//! SPDX-License-Identifier: GPL-3.0-or-later
//! S2/S3 Task 2: independent reference histories for the pure object model.
//!
//! Every expectation below is handwritten from the contract notes (model,
//! close-scope and revised origin design). The harness only plays the role
//! of a correct reference producer: it allocates explicit ordinal cuts,
//! remembers which calls it began/completed and lists the open calls in each
//! prefix. It never computes an expected transition with the model's own
//! helpers and never hands the model an oracle identity/sharing fact.

use crate::semantics_edge::{EdgeSemantics, SemanticCall};
use crate::semantics_objects::{
    AffectedScope, AttrObservation, AttributeList, Attribution, Birth, CallKey, CallToken,
    CompleteInputPrefix, CompletedFact, CreationFamily, FieldState, FieldValue, FindResult,
    HandleInput, KeyLabel, Lifetime, LostOutcome, MAX_ACCESS_RELATIONS, MechanismEvidence,
    ObjectDomain, ObjectEffect, ObjectEffects, ObjectGap, ObjectHandle, ObjectId, ObjectLimits,
    ObjectProjection, ObjectSemantics, ObjectView, OriginFact, QueryStatus, RefCut, ResultSlot,
    SessionEnd, SessionHandle, SessionIncarnation, SessionOrigin, SessionState, SlotScope,
    ViewOrigin,
};
use p11scope_ebpf_common::LinuxLayout;
use p11scope_ebpf_common::capture;
use p11scope_ebpf_common::object_policy::{SafeAttributeKind, SafeCurve};
use pkcs11_types::CkRv;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Reference vocabulary
// ---------------------------------------------------------------------------

/// Sentinel-shaped private words: any leak into formatted output is visible.
const SA: u64 = 0x5A5A_0A01;
const SB: u64 = 0x5A5A_0B02;
const SC: u64 = 0x5A5A_0C03;
const SD: u64 = 0x5A5A_0D04;
const H1: u64 = 0x7E57_0001;
const H2: u64 = 0x7E57_0002;
const H3: u64 = 0x7E57_0003;
const H4: u64 = 0x7E57_0004;
const H5: u64 = 0x7E57_0005;
const H6: u64 = 0x7E57_0006;
const H7: u64 = 0x7E57_0007;
const H8: u64 = 0x7E57_0008;
const H9: u64 = 0x7E57_0009;
/// The v3 ignored-`phKey` sentinel.
const PHKEY_SENTINEL: u64 = 0x5152_5354;
const SLOT1: u64 = 1;
const SLOT2: u64 = 2;

const ECDH1: u64 = 0x1050;
const SHA256_DERIVE: u64 = 0x393;
const SSL3_KEY_MATERIAL: u64 = 0x372;
const ECDSA: u64 = 0x1041;

const CKA_CLASS: u64 = 0x0000;
const CKA_TOKEN: u64 = 0x0001;
const CKA_KEY_TYPE: u64 = 0x0100;
const CKA_MODULUS_BITS: u64 = 0x0121;
const CKA_VALUE_LEN: u64 = 0x0161;
const CKA_EC_PARAMS: u64 = 0x0180;
const CKA_ID: u64 = 0x0102;
const SECP256R1: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

fn sess(raw: u64) -> SessionHandle {
    SessionHandle::new(raw).expect("nonzero session handle")
}

fn obj(raw: u64) -> ObjectHandle {
    ObjectHandle::new(raw).expect("nonzero object handle")
}

fn base_domain() -> ObjectDomain {
    ObjectDomain::reference(1, 1, 1, 1, 1)
}

fn slot(slot: u64) -> SlotScope {
    SlotScope::reference_known(slot, 1)
}

fn fid(name: &str) -> u32 {
    crate::kinds::function_id(name).expect("catalog function")
}

fn scalar(selector: u64, value: u64) -> AttrObservation {
    let len = if selector == CKA_TOKEN { 1 } else { 8 };
    AttrObservation::scalar(selector, len, value, LinuxLayout::Lp64)
}

fn attrs(items: &[AttrObservation]) -> AttributeList {
    AttributeList::new(items)
}

fn token_attr(value: u64) -> AttributeList {
    attrs(&[scalar(CKA_TOKEN, value)])
}

/// One call's entry evidence, by name.
#[derive(Clone)]
struct Call {
    function: &'static str,
    session: HandleInput<SessionHandle>,
    inputs: [HandleInput<ObjectHandle>; 2],
    requested: [Option<AttributeList>; 2],
    mechanism: MechanismEvidence,
    scope: SlotScope,
}

fn call(function: &'static str) -> Call {
    Call {
        function,
        session: HandleInput::Absent,
        inputs: [HandleInput::Absent, HandleInput::Absent],
        requested: [None, None],
        mechanism: MechanismEvidence::NotCaptured,
        scope: SlotScope::Unknown,
    }
}

impl Call {
    fn on(mut self, raw: u64) -> Self {
        self.session = HandleInput::Value(sess(raw));
        self
    }
    fn input(mut self, index: usize, raw: u64) -> Self {
        self.inputs[index] = HandleInput::Value(obj(raw));
        self
    }
    fn input_unreadable(mut self, index: usize) -> Self {
        self.inputs[index] = HandleInput::Unreadable;
        self
    }
    fn request(mut self, index: usize, list: AttributeList) -> Self {
        self.requested[index] = Some(list);
        self
    }
    fn mech(mut self, evidence: MechanismEvidence) -> Self {
        self.mechanism = evidence;
        self
    }
    fn scope(mut self, scope: SlotScope) -> Self {
        self.scope = scope;
        self
    }
}

fn open_in(slot_scope: SlotScope) -> Call {
    call("C_OpenSession").scope(slot_scope)
}

fn create(on: u64) -> Call {
    call("C_CreateObject").on(on)
}

fn get_size(on: u64, handle: u64) -> Call {
    call("C_GetObjectSize").on(on).input(0, handle)
}

fn get_attrs(on: u64, handle: u64) -> Call {
    call("C_GetAttributeValue").on(on).input(0, handle)
}

fn sign_init(on: u64, handle: u64) -> Call {
    call("C_SignInit").on(on).input(0, handle)
}

fn destroy(on: u64, handle: u64) -> Call {
    call("C_DestroyObject").on(on).input(0, handle)
}

fn close(on: u64) -> Call {
    call("C_CloseSession").on(on)
}

/// One call's matched completion evidence.
#[derive(Clone)]
struct Done {
    rv: u64,
    mechanism: MechanismEvidence,
    results: [ResultSlot; 2],
    session_out: HandleInput<SessionHandle>,
    found: FindResult,
    attributes: Option<AttributeList>,
}

fn rv(value: CkRv) -> Done {
    Done {
        rv: value.0,
        mechanism: MechanismEvidence::NotCaptured,
        results: [ResultSlot::NotCaptured, ResultSlot::NotCaptured],
        session_out: HandleInput::Absent,
        found: FindResult::NotCaptured,
        attributes: None,
    }
}

fn ok() -> Done {
    rv(CkRv::OK)
}

impl Done {
    fn result(mut self, slot: usize, raw: u64) -> Self {
        self.results[slot] = ResultSlot::Handle(obj(raw));
        self
    }
    fn unreadable(mut self, slot: usize) -> Self {
        self.results[slot] = ResultSlot::Unreadable;
        self
    }
    fn session_out(mut self, raw: u64) -> Self {
        self.session_out = HandleInput::Value(sess(raw));
        self
    }
    fn mech(mut self, evidence: MechanismEvidence) -> Self {
        self.mechanism = evidence;
        self
    }
    fn found(mut self, raws: &[u64]) -> Self {
        let handles: Vec<ObjectHandle> = raws.iter().map(|raw| obj(*raw)).collect();
        self.found = FindResult::handles(&handles);
        self
    }
    fn attrs(mut self, list: AttributeList) -> Self {
        self.attributes = Some(list);
        self
    }
}

/// The reference producer's bookkeeping for one domain: begin cut and
/// delivered completion cut per logical call (key = begin cut).
#[derive(Default)]
struct Book {
    calls: BTreeMap<u64, (CallToken, Option<u64>)>,
    bootstrap: Option<u64>,
}

/// A reference history driving one shared model across explicit domains.
struct Hist {
    model: ObjectSemantics,
    domains: Vec<(ObjectDomain, Book)>,
}

impl Hist {
    /// One qualified domain (bootstrap at cut 0) with policy limits.
    fn qualified() -> Self {
        Self::with_limits(ObjectLimits::policy())
    }

    fn with_limits(limits: ObjectLimits) -> Self {
        let mut hist = Self {
            model: ObjectSemantics::with_limits(limits),
            domains: Vec::new(),
        };
        hist.add_domain(base_domain(), true);
        hist
    }

    fn unqualified() -> Self {
        let mut hist = Self {
            model: ObjectSemantics::new(),
            domains: Vec::new(),
        };
        hist.add_domain(base_domain(), false);
        hist
    }

    /// Register a domain; a qualified one carries bootstrap at cut 0.
    fn add_domain(&mut self, domain: ObjectDomain, qualified: bool) -> usize {
        // Registration may be refused (capacity); facts then stay refused.
        let _ = self.model.register_domain(domain);
        let book = Book {
            calls: BTreeMap::new(),
            bootstrap: qualified.then_some(0),
        };
        self.domains.push((domain, book));
        self.domains.len() - 1
    }

    fn origin(&self, dom: usize, cut: u64, call: &Call) -> OriginFact {
        OriginFact {
            domain: self.domains[dom].0,
            cut: RefCut::reference(cut),
            key: CallKey::reference(cut),
            entry_ns: cut.saturating_mul(100),
            function: fid(call.function),
            session: call.session,
            inputs: call.inputs,
            requested: call.requested,
            entry_mechanism: call.mechanism,
            scope: call.scope,
        }
    }

    fn try_begin_in(&mut self, dom: usize, cut: u64, call: Call) -> Result<CallToken, ObjectGap> {
        let origin = self.origin(dom, cut, &call);
        let token = self.model.begin(origin)?;
        self.domains[dom].1.calls.insert(cut, (token, None));
        Ok(token)
    }

    fn begin_in(&mut self, dom: usize, cut: u64, call: Call) -> CallToken {
        match self.try_begin_in(dom, cut, call) {
            Ok(token) => token,
            Err(gap) => panic!("reference begin refused: {gap:?}"),
        }
    }

    fn begin(&mut self, cut: u64, call: Call) -> CallToken {
        self.begin_in(0, cut, call)
    }

    fn done_in(&mut self, dom: usize, token: CallToken, cut: u64, done: Done) -> ObjectEffects {
        for (known, completion) in self.domains[dom].1.calls.values_mut() {
            if *known == token && completion.is_none() {
                *completion = Some(cut);
            }
        }
        let fact = CompletedFact {
            cut: RefCut::reference(cut),
            end_ns: cut.saturating_mul(100),
            rv: done.rv,
            return_mechanism: done.mechanism,
            results: done.results,
            session_out: done.session_out,
            found: done.found,
            attributes: done.attributes,
        };
        self.model.complete(token, fact)
    }

    fn done(&mut self, token: CallToken, cut: u64, done: Done) -> ObjectEffects {
        self.done_in(0, token, cut, done)
    }

    /// Begin and complete in one step (strictly ordered calls).
    fn run_in(&mut self, dom: usize, begin: u64, call: Call, end: u64, done: Done) -> CallToken {
        let token = self.begin_in(dom, begin, call);
        self.done_in(dom, token, end, done);
        token
    }

    fn run(&mut self, begin: u64, call: Call, end: u64, done: Done) -> CallToken {
        self.run_in(0, begin, call, end, done)
    }

    /// A correct reference prefix: every call begun through `frontier` is
    /// either completed through it or explicitly listed open.
    fn prefix(&self, dom: usize, frontier: u64) -> CompleteInputPrefix {
        let book = &self.domains[dom].1;
        let open: Vec<CallKey> = book
            .calls
            .iter()
            .filter(|(begin, (_, completion))| {
                **begin <= frontier && completion.is_none_or(|end| end > frontier)
            })
            .map(|(begin, _)| CallKey::reference(*begin))
            .collect();
        CompleteInputPrefix::reference(
            self.domains[dom].0,
            RefCut::reference(frontier),
            &open,
            book.bootstrap.map(RefCut::reference),
        )
    }

    fn settle_in(&mut self, dom: usize, frontier: u64) -> ObjectEffects {
        let prefix = self.prefix(dom, frontier);
        let effects = self.model.settle(prefix);
        // A bootstrap is a one-time reference statement.
        self.domains[dom].1.bootstrap = None;
        effects
    }

    fn settle(&mut self, frontier: u64) -> ObjectEffects {
        self.settle_in(0, frontier)
    }

    /// Supply a fresh bootstrap statement with the next prefix.
    fn rebootstrap(&mut self, dom: usize, cut: u64) {
        self.domains[dom].1.bootstrap = Some(cut);
    }

    fn project(&self) -> ObjectProjection {
        self.model.project()
    }
}

// ---------------------------------------------------------------------------
// Effect/projection readers (lookups only, no transition logic)
// ---------------------------------------------------------------------------

fn created(effects: &ObjectEffects, call: CallToken, slot: u8) -> Option<ObjectId> {
    effects.effects.iter().find_map(|effect| match effect {
        ObjectEffect::Created {
            call: c,
            slot: s,
            object,
            ..
        } if *c == call && *s == slot => Some(*object),
        _ => None,
    })
}

fn first_observed(effects: &ObjectEffects, call: CallToken) -> Vec<ObjectId> {
    effects
        .effects
        .iter()
        .filter_map(|effect| match effect {
            ObjectEffect::FirstObserved {
                call: c, object, ..
            } if *c == call => Some(*object),
            _ => None,
        })
        .collect()
}

fn opened(effects: &ObjectEffects, call: CallToken) -> Option<SessionIncarnation> {
    effects.effects.iter().find_map(|effect| match effect {
        ObjectEffect::SessionOpened { call: c, session } if *c == call => Some(*session),
        _ => None,
    })
}

fn unresolved(effects: &ObjectEffects, call: CallToken) -> Option<ObjectGap> {
    effects.effects.iter().find_map(|effect| match effect {
        ObjectEffect::Unresolved { call: c, reason } if *c == call => Some(*reason),
        _ => None,
    })
}

fn has_created(effects: &ObjectEffects) -> bool {
    effects
        .effects
        .iter()
        .any(|effect| matches!(effect, ObjectEffect::Created { .. }))
}

fn view(projection: &ObjectProjection, id: ObjectId) -> &ObjectView {
    projection.object(id).expect("projected object view")
}

fn sole(ids: Vec<ObjectId>) -> ObjectId {
    assert_eq!(ids.len(), 1, "exactly one observed view");
    ids[0]
}

fn scalar_field(value: u16) -> FieldState {
    FieldState::Value(FieldValue::Scalar(value))
}

// ---------------------------------------------------------------------------
// creation_protocols
// ---------------------------------------------------------------------------

#[test]
fn s2s3_creation_protocols_all_six_families_mint_fresh_results() {
    let mut h = Hist::qualified();
    let open = h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let secret_aes = attrs(&[
        scalar(CKA_CLASS, 4),
        scalar(CKA_KEY_TYPE, 0x1f),
        scalar(CKA_VALUE_LEN, 32),
    ]);
    let c_create = h.run(3, create(SA).request(0, secret_aes), 4, ok().result(0, H1));
    let c_copy = h.run(
        5,
        call("C_CopyObject").on(SA).input(0, H1),
        6,
        ok().result(0, H2),
    );
    let c_gen = h.run(7, call("C_GenerateKey").on(SA), 8, ok().result(0, H3));
    let c_pair = h.run(
        9,
        call("C_GenerateKeyPair").on(SA),
        10,
        ok().result(0, H4).result(1, H5),
    );
    let c_derive = h.run(
        11,
        call("C_DeriveKey")
            .on(SA)
            .input(0, H3)
            .mech(MechanismEvidence::Value(ECDH1)),
        12,
        ok().mech(MechanismEvidence::Value(ECDH1)).result(0, H6),
    );
    let c_unwrap = h.run(
        13,
        call("C_UnwrapKey").on(SA).input(0, H3),
        14,
        ok().result(0, H7),
    );
    let effects = h.settle(14);
    let p = h.project();

    let session = opened(&effects, open).expect("opened session");
    let expected = [
        (c_create, 0, CreationFamily::Create, 3, 4),
        (c_copy, 0, CreationFamily::Copy, 5, 6),
        (c_gen, 0, CreationFamily::Generate, 7, 8),
        (c_pair, 0, CreationFamily::GeneratePair, 9, 10),
        (c_pair, 1, CreationFamily::GeneratePair, 9, 10),
        (c_derive, 0, CreationFamily::Derive, 11, 12),
        (c_unwrap, 0, CreationFamily::Unwrap, 13, 14),
    ];
    let mut ids = Vec::new();
    for (token, slot, family, begin, end) in expected {
        let id = created(&effects, token, slot).expect("fresh accepted result view");
        let v = view(&p, id);
        assert_eq!(v.origin, ViewOrigin::Created(family));
        assert_eq!(v.session, session);
        assert_eq!(v.creator, Some(session));
        assert_eq!(v.lifetime, Lifetime::Live);
        assert_eq!(
            v.birth,
            Birth::Observed {
                start_ns: begin * 100,
                end_ns: end * 100
            }
        );
        assert_eq!(v.accessing_sessions, 1);
        ids.push(id);
    }
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 7, "every creation result is a fresh view");
    assert_eq!(p.objects.len(), 7, "copy/derive never merge with inputs");

    let source = view(&p, ids[0]);
    assert_eq!(source.references, 1, "copy reads its source once");
    assert_eq!(source.key_uses, 0, "copy is not a key use");
    assert_eq!(
        source.requested.field(SafeAttributeKind::Class),
        scalar_field(4)
    );
    assert_eq!(
        source.requested.field(SafeAttributeKind::KeyType),
        scalar_field(0x1f)
    );
    assert_eq!(
        source.established.field(SafeAttributeKind::Class),
        FieldState::Unknown
    );
    assert_eq!(source.label, None, "requested metadata never labels");
    let copy = view(&p, ids[1]);
    assert_eq!(
        copy.requested.field(SafeAttributeKind::Class),
        FieldState::Unknown
    );
    let base = view(&p, ids[2]);
    assert_eq!(base.key_uses, 2, "derive base and unwrapping key uses");
}

#[test]
fn s2s3_creation_protocols_pair_distinct_duplicate_and_partial() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let dup = h.run(
        3,
        call("C_GenerateKeyPair").on(SA),
        4,
        ok().result(0, H4).result(1, H4),
    );
    let partial = h.run(
        5,
        call("C_GenerateKeyPair").on(SA),
        6,
        ok().result(0, H8).unreadable(1),
    );
    let pair = h.run(
        7,
        call("C_GenerateKeyPair").on(SA),
        8,
        ok().result(0, H1).result(1, H2),
    );
    let dependent = h.run(
        9,
        sign_init(SA, H4),
        10,
        ok().mech(MechanismEvidence::Value(ECDSA)),
    );
    let effects = h.settle(10);
    let p = h.project();

    assert_eq!(
        created(&effects, dup, 0),
        None,
        "duplicate pair invalidates the pair"
    );
    assert_eq!(created(&effects, dup, 1), None);
    assert!(
        created(&effects, partial, 0).is_some(),
        "independent member survives"
    );
    assert_eq!(created(&effects, partial, 1), None, "no invented sibling");
    let public = created(&effects, pair, 0).expect("public member");
    let private = created(&effects, pair, 1).expect("private member");
    assert_ne!(public, private);
    assert_eq!(p.objects.len(), 3);
    assert!(p.gap(ObjectGap::PairDuplicate) >= 1);
    assert!(p.gap(ObjectGap::OutputUnreadable) >= 1);
    assert_eq!(
        unresolved(&effects, dependent),
        Some(ObjectGap::DependencyBroken),
        "a dependent of the rejected pair stays unknown"
    );
    assert!(first_observed(&effects, dependent).is_empty());
}

#[test]
fn s2s3_creation_protocols_normal_failures_create_nothing() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let observe = h.run(3, get_size(SA, H1), 4, ok());
    let failed = h.run(
        5,
        create(SA).request(0, attrs(&[scalar(CKA_CLASS, 3)])),
        6,
        rv(CkRv::FUNCTION_FAILED).result(0, H1),
    );
    let failed_gen = h.run(
        7,
        call("C_GenerateKey").on(SA),
        8,
        rv(CkRv::FUNCTION_FAILED),
    );
    let pending = h.run(9, create(SA), 10, rv(CkRv::PENDING).result(0, H2));
    let effects = h.settle(10);
    let p = h.project();

    let first = sole(first_observed(&effects, observe));
    assert!(
        !has_created(&effects),
        "no failed/pending creation is accepted"
    );
    assert_eq!(created(&effects, failed, 0), None);
    assert_eq!(created(&effects, failed_gen, 0), None);
    assert_eq!(created(&effects, pending, 0), None);
    assert_eq!(p.objects.len(), 1);
    let v = view(&p, first);
    assert_eq!(v.origin, ViewOrigin::FirstObserved);
    assert_eq!(v.birth, Birth::Unknown);
    assert_eq!(
        v.requested.field(SafeAttributeKind::Class),
        FieldState::Unknown,
        "a failed creation lends no request metadata"
    );
    assert!(p.gap(ObjectGap::PendingResultUnavailable) >= 1);
}

#[test]
fn s2s3_creation_protocols_derive_result_protocol_is_guarded() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let base_call = h.run(3, call("C_GenerateKey").on(SA), 4, ok().result(0, H1));
    let derive = |m: MechanismEvidence| call("C_DeriveKey").on(SA).input(0, H1).mech(m);
    let v = MechanismEvidence::Value;
    let unavailable = h.run(
        5,
        derive(v(SSL3_KEY_MATERIAL)),
        6,
        ok().mech(v(SSL3_KEY_MATERIAL)).result(0, PHKEY_SENTINEL),
    );
    let vendor = h.run(
        7,
        derive(v(0x8000_0001)),
        8,
        ok().mech(v(0x8000_0001)).result(0, H2),
    );
    let unreadable_entry = h.run(
        9,
        derive(MechanismEvidence::Unreadable),
        10,
        ok().mech(v(ECDH1)).result(0, H3),
    );
    let qualified = h.run(11, derive(v(ECDH1)), 12, ok().mech(v(ECDH1)).result(0, H4));
    let missing_return = h.run(
        13,
        derive(v(ECDH1)),
        14,
        ok().mech(MechanismEvidence::Unreadable).result(0, H5),
    );
    let changed_return = h.run(
        15,
        derive(v(ECDH1)),
        16,
        ok().mech(v(SHA256_DERIVE)).result(0, H6),
    );
    let absent_return = h.run(17, derive(v(ECDH1)), 18, ok().result(0, H7));
    let effects = h.settle(18);
    let p = h.project();

    let base = created(&effects, base_call, 0).expect("base key");
    let derived = created(&effects, qualified, 0).expect("qualified scalar result");
    for token in [
        unavailable,
        vendor,
        unreadable_entry,
        missing_return,
        changed_return,
        absent_return,
    ] {
        assert_eq!(created(&effects, token, 0), None);
        assert!(first_observed(&effects, token).iter().all(|id| *id == base));
    }
    assert_eq!(p.objects.len(), 2, "only base and the qualified derive");
    assert_eq!(p.gap(ObjectGap::ResultProtocolUnavailable), 6);
    assert_eq!(view(&p, base).key_uses, 7, "base key observations remain");
    assert_eq!(
        view(&p, derived).origin,
        ViewOrigin::Created(CreationFamily::Derive)
    );
    assert_eq!(view(&p, derived).label, None, "no mechanism-inferred label");
}

// ---------------------------------------------------------------------------
// domain_session_isolation
// ---------------------------------------------------------------------------

#[test]
fn s2s3_domain_session_isolation_equal_handles_across_domains() {
    let mut h = Hist::qualified();
    let others = [
        ObjectDomain::reference(2, 1, 1, 1, 1),
        ObjectDomain::reference(1, 2, 1, 1, 1),
        ObjectDomain::reference(1, 1, 2, 1, 1),
        ObjectDomain::reference(1, 1, 1, 2, 1),
        ObjectDomain::reference(1, 1, 1, 1, 2),
    ];
    for domain in others {
        h.add_domain(domain, true);
    }
    let mut ids = Vec::new();
    let mut sessions = Vec::new();
    for dom in 0..6 {
        let open = h.run_in(dom, 1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
        let made = h.run_in(dom, 3, create(SA), 4, ok().result(0, H1));
        let effects = h.settle_in(dom, 4);
        sessions.push(opened(&effects, open).expect("session"));
        ids.push(created(&effects, made, 0).expect("object"));
    }
    let mut unique_ids = ids.clone();
    unique_ids.sort();
    unique_ids.dedup();
    let mut unique_sessions = sessions.clone();
    unique_sessions.sort();
    unique_sessions.dedup();
    assert_eq!(
        unique_ids.len(),
        6,
        "native-source/image/instance/era never merge"
    );
    assert_eq!(unique_sessions.len(), 6);

    h.run_in(0, 5, destroy(SA, H1), 6, ok());
    h.settle_in(0, 6);
    let p = h.project();
    assert_eq!(view(&p, ids[0]).lifetime, Lifetime::Destroyed);
    for id in &ids[1..] {
        assert_eq!(
            view(&p, *id).lifetime,
            Lifetime::Live,
            "no cross-domain effect"
        );
    }
}

#[test]
fn s2s3_domain_session_isolation_slots_epochs_and_sessions() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT2)), 4, ok().session_out(SB));
    h.run(
        5,
        open_in(SlotScope::reference_known(SLOT1, 2)),
        6,
        ok().session_out(SC),
    );
    h.run(7, open_in(slot(SLOT1)), 8, ok().session_out(SD));
    let a = h.run(9, create(SA), 10, ok().result(0, H1));
    let b = h.run(11, create(SB), 12, ok().result(0, H1));
    let c = h.run(13, create(SC), 14, ok().result(0, H1));
    let d = h.run(15, create(SD), 16, ok().result(0, H1));
    let effects = h.settle(16);
    let ids: Vec<ObjectId> = [a, b, c, d]
        .iter()
        .map(|t| created(&effects, *t, 0).expect("created"))
        .collect();
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        4,
        "equal handles in four sessions stay four views"
    );

    h.run(17, destroy(SA, H1), 18, ok());
    h.settle(18);
    let p = h.project();
    assert_eq!(view(&p, ids[0]).lifetime, Lifetime::Destroyed);
    assert_eq!(
        view(&p, ids[1]).lifetime,
        Lifetime::Live,
        "proven other slot"
    );
    assert_eq!(
        view(&p, ids[2]).lifetime,
        Lifetime::Live,
        "proven other token epoch"
    );
    assert_eq!(
        view(&p, ids[3]).lifetime,
        Lifetime::Live,
        "independently distinct continuous creation"
    );
}

#[test]
fn s2s3_domain_session_isolation_find_use_and_equal_metadata() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    let fa = h.run(5, call("C_FindObjects").on(SA), 6, ok().found(&[H1]));
    let fb = h.run(7, call("C_FindObjects").on(SB), 8, ok().found(&[H1]));
    let ec = attrs(&[scalar(CKA_CLASS, 3), scalar(CKA_KEY_TYPE, 3)]);
    h.run(9, get_attrs(SA, H1), 10, ok().attrs(ec));
    h.run(11, get_attrs(SB, H1), 12, ok().attrs(ec));
    let effects = h.settle(12);
    let p = h.project();
    let va = sole(first_observed(&effects, fa));
    let vb = sole(first_observed(&effects, fb));
    assert_ne!(va, vb, "equal handle and equal metadata supply no alias");
    for id in [va, vb] {
        let v = view(&p, id);
        assert_eq!(v.origin, ViewOrigin::FirstObserved);
        assert_eq!(v.birth, Birth::Unknown);
        assert_eq!(v.creator, None);
        assert_eq!(v.accessing_sessions, 1);
        assert_eq!(
            v.established.field(SafeAttributeKind::Class),
            scalar_field(3)
        );
        assert_eq!(v.references, 2, "find plus attribute query");
    }
    assert_eq!(p.objects.len(), 2);
}

#[test]
fn s2s3_domain_session_isolation_unknown_scope_is_not_slot_zero() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SB));
    let unknown = h.run(3, get_size(SA, H1), 4, ok());
    let known = h.run(5, get_size(SB, H2), 6, ok());
    h.run(7, destroy(SA, H1), 8, ok());
    let effects = h.settle(8);
    let p = h.project();
    let vu = sole(first_observed(&effects, unknown));
    let vk = sole(first_observed(&effects, known));
    assert_eq!(view(&p, vu).lifetime, Lifetime::Destroyed);
    assert_eq!(
        view(&p, vk).lifetime,
        Lifetime::Retired(ObjectGap::DestroyAlias),
        "an unknown-scope destroy is compatible with slot 1, unlike slot 0"
    );
    let su = view(&p, vu).session;
    let session = p.session(su).expect("first-observed session");
    assert_eq!(session.origin, SessionOrigin::FirstObserved);
    assert!(!session.scope_known);
}

// ---------------------------------------------------------------------------
// null_mechanism_init_cancel_does_not_use_supplied_key
// ---------------------------------------------------------------------------

fn s1_call(
    function: &str,
    session: u64,
    mechanism: u64,
    capture_bits: u32,
    rv: CkRv,
) -> SemanticCall {
    SemanticCall {
        function: function.to_string(),
        rv: rv.0,
        session,
        mechanism,
        capture: capture_bits | capture::OUTPUT_NONE,
        ..SemanticCall::default()
    }
}

#[test]
fn s2s3_null_mechanism_init_cancel_does_not_use_supplied_key() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let key_a = h.run(3, call("C_GenerateKey").on(SA), 4, ok().result(0, H1));
    h.run(
        5,
        sign_init(SA, H1),
        6,
        ok().mech(MechanismEvidence::Value(ECDSA)),
    );
    let cancel = h.run(7, sign_init(SA, H2), 8, ok().mech(MechanismEvidence::Null));
    let effects = h.settle(8);
    let p = h.project();
    let a = created(&effects, key_a, 0).expect("key A");
    assert_eq!(view(&p, a).key_uses, 1, "only the real Init uses A");
    assert!(
        first_observed(&effects, cancel).is_empty(),
        "no key-B identity"
    );
    assert_eq!(p.objects.len(), 1, "no key-B view, access or use");
    assert_eq!(p.gap(ObjectGap::NullMechanismCancel), 1);

    // S1 keeps ordinary call accounting and cancels once.
    let mut edge = EdgeSemantics::default();
    edge.observe(&s1_call(
        "C_SignInit",
        SA,
        ECDSA,
        capture::MECHANISM_VALUE,
        CkRv::OK,
    ));
    edge.observe(&s1_call(
        "C_SignInit",
        SA,
        0,
        capture::MECHANISM_NULL,
        CkRv::OK,
    ));
    assert_eq!(edge.calls(), 2);
    assert_eq!(edge.started(), 1);
    assert_eq!(edge.cancelled(), 1);
    assert!(!edge.has_live_operations());
}

#[test]
fn s2s3_null_mechanism_init_cancel_controls_keep_distinct_behavior() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    h.run(5, open_in(slot(SLOT1)), 6, ok().session_out(SC));
    let value = h.run(
        7,
        sign_init(SA, H1),
        8,
        ok().mech(MechanismEvidence::Value(ECDSA)),
    );
    let unreadable = h.run(
        9,
        sign_init(SB, H2),
        10,
        ok().mech(MechanismEvidence::Unreadable),
    );
    let no_flag = h.run(
        11,
        call("C_MessageDecryptInit").on(SC).input(0, H3),
        12,
        ok().mech(MechanismEvidence::Null),
    );
    let failed = h.run(
        13,
        sign_init(SA, H4),
        14,
        rv(CkRv::FUNCTION_FAILED).mech(MechanismEvidence::Value(ECDSA)),
    );
    let effects = h.settle(14);
    let p = h.project();
    for token in [value, unreadable, no_flag] {
        let id = sole(first_observed(&effects, token));
        assert_eq!(view(&p, id).key_uses, 1);
        assert_eq!(view(&p, id).birth, Birth::Unknown);
    }
    assert!(
        first_observed(&effects, failed).is_empty(),
        "failed Init is no access"
    );
    assert_eq!(p.objects.len(), 3);
    assert_eq!(p.gap(ObjectGap::NullMechanismCancel), 0);

    let mut edge = EdgeSemantics::default();
    edge.observe(&s1_call(
        "C_SignInit",
        SA,
        ECDSA,
        capture::MECHANISM_VALUE,
        CkRv::OK,
    ));
    edge.observe(&s1_call(
        "C_SignInit",
        SB,
        0,
        capture::MECHANISM_UNREADABLE,
        CkRv::OK,
    ));
    edge.observe(&s1_call(
        "C_MessageDecryptInit",
        SC,
        0,
        capture::MECHANISM_NULL,
        CkRv::OK,
    ));
    assert_eq!(edge.started(), 3);
    assert_eq!(edge.cancelled(), 0);
    assert_eq!(edge.evidence().semantic_capture_failures, 1);
}

// ---------------------------------------------------------------------------
// deferred_chain_one_prefix (O1)
// ---------------------------------------------------------------------------

fn o1_open_create_use(intermediate: bool, early_dependent_begin: bool) -> ObjectProjection {
    let mut h = Hist::qualified();
    let open = h.begin(1, open_in(slot(SLOT1)));
    h.done(open, 2, ok().session_out(SA));
    if intermediate {
        h.settle(2);
    }
    let made = h.begin(3, create(SA));
    let used = if early_dependent_begin {
        // The dependent's begin is delivered before the predecessor's
        // completion; its reference cut still follows that completion.
        let used = h.begin(5, sign_init(SA, H1));
        h.done(made, 4, ok().result(0, H1));
        used
    } else {
        h.done(made, 4, ok().result(0, H1));
        if intermediate {
            h.settle(4);
        }
        h.begin(5, sign_init(SA, H1))
    };
    h.done(used, 6, ok().mech(MechanismEvidence::Value(ECDSA)));
    h.settle(6);
    h.project()
}

fn o1_shape(p: &ObjectProjection) {
    assert_eq!(p.sessions.len(), 1);
    assert_eq!(p.sessions[0].origin, SessionOrigin::Opened);
    assert_eq!(p.objects.len(), 1);
    let v = &p.objects[0];
    assert_eq!(v.session, p.sessions[0].id);
    assert_eq!(v.creator, Some(p.sessions[0].id));
    assert_eq!(v.origin, ViewOrigin::Created(CreationFamily::Create));
    assert_eq!(v.key_uses, 1);
}

#[test]
fn s2s3_deferred_chain_one_prefix_open_create_use() {
    let stepwise = o1_open_create_use(true, false);
    let delayed = o1_open_create_use(false, false);
    let early = o1_open_create_use(false, true);
    o1_shape(&stepwise);
    o1_shape(&delayed);
    o1_shape(&early);
    assert_eq!(stepwise.objects, delayed.objects);
    assert_eq!(stepwise.sessions, delayed.sessions);
    assert_eq!(delayed.objects, early.objects);
}

#[test]
fn s2s3_deferred_chain_one_prefix_create_use_without_open() {
    let run = |intermediate: bool| {
        let mut h = Hist::qualified();
        h.run(1, create(SA), 2, ok().result(0, H1));
        if intermediate {
            h.settle(2);
        }
        h.run(
            3,
            sign_init(SA, H1),
            4,
            ok().mech(MechanismEvidence::Value(ECDSA)),
        );
        h.settle(4);
        h.project()
    };
    let stepwise = run(true);
    let delayed = run(false);
    assert_eq!(stepwise.objects, delayed.objects);
    assert_eq!(stepwise.sessions, delayed.sessions);
    assert_eq!(delayed.sessions.len(), 1);
    assert_eq!(delayed.sessions[0].origin, SessionOrigin::FirstObserved);
    assert_eq!(delayed.objects.len(), 1);
    assert_eq!(
        delayed.objects[0].origin,
        ViewOrigin::Created(CreationFamily::Create)
    );
    assert_eq!(delayed.objects[0].key_uses, 1);
}

// ---------------------------------------------------------------------------
// stale_origin_and_dependency_fences (O2/O3)
// ---------------------------------------------------------------------------

fn o2_reuse(reverse_delivery: bool) -> (ObjectProjection, Vec<ObjectEffects>) {
    let mut h = Hist::qualified();
    let plan = [
        (1, open_in(slot(SLOT1)), 2, ok().session_out(SA)),
        (3, create(SA), 4, ok().result(0, H1)),
        (
            5,
            sign_init(SA, H1),
            6,
            ok().mech(MechanismEvidence::Value(ECDSA)),
        ),
        (7, destroy(SA, H1), 8, ok()),
        (9, create(SA), 10, ok().result(0, H1)),
        (
            11,
            sign_init(SA, H1),
            12,
            ok().mech(MechanismEvidence::Value(ECDSA)),
        ),
    ];
    let tokens: Vec<CallToken> = plan
        .iter()
        .map(|(begin, c, _, _)| h.begin(*begin, c.clone()))
        .collect();
    let mut order: Vec<usize> = (0..plan.len()).collect();
    if reverse_delivery {
        order.reverse();
    }
    for index in order {
        let (_, _, end, done) = &plan[index];
        h.done(tokens[index], *end, done.clone());
    }
    let effects = h.settle(12);
    let first = created(&effects, tokens[1], 0).expect("first lifetime");
    let second = created(&effects, tokens[4], 0).expect("replacement lifetime");
    assert_ne!(first, second);
    let p = h.project();
    assert_eq!(view(&p, first).lifetime, Lifetime::Destroyed);
    assert_eq!(
        view(&p, first).key_uses,
        1,
        "old use joins only the old lifetime"
    );
    assert_eq!(view(&p, second).lifetime, Lifetime::Live);
    assert_eq!(view(&p, second).key_uses, 1);
    (p, vec![effects])
}

#[test]
fn s2s3_stale_origin_and_dependency_fences_destroy_reuse_both_orders() {
    let (forward, _) = o2_reuse(false);
    let (reverse, _) = o2_reuse(true);
    assert_eq!(forward.objects, reverse.objects);
}

fn o2_overlapping_collision(cross_last: bool) -> ObjectProjection {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    let long_b = h.begin(5, create(SB));
    if !cross_last {
        h.done(long_b, 12, ok().result(0, H1));
    }
    h.run(6, create(SA), 7, ok().result(0, H1));
    h.run(8, destroy(SA, H1), 9, ok());
    h.run(10, create(SA), 11, ok().result(0, H1));
    if cross_last {
        h.done(long_b, 12, ok().result(0, H1));
    }
    h.settle(12);
    let repair = h.run(13, get_size(SA, H1), 14, ok());
    let effects = h.settle(14);
    assert_eq!(
        unresolved(&effects, repair),
        Some(ObjectGap::DependencyBroken),
        "a later equal handle is no repair proof"
    );
    h.project()
}

#[test]
fn s2s3_stale_origin_and_dependency_fences_unresolved_overlap_never_joins() {
    let a = o2_overlapping_collision(false);
    let b = o2_overlapping_collision(true);
    assert!(
        a.objects.is_empty(),
        "overlapping equal outputs stay unknown"
    );
    assert_eq!(a.objects, b.objects);
    assert!(a.gap(ObjectGap::OutputCollision) >= 2);
}

#[test]
fn s2s3_stale_origin_and_dependency_fences_predecessor_loss() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, create(SA), 4, ok().result(0, H1));
    let lost_use = h.run(
        5,
        sign_init(SA, H1),
        6,
        ok().mech(MechanismEvidence::Value(ECDSA)),
    );
    let lost = h.model.invalidate(
        AffectedScope::Session(base_domain(), sess(SA)),
        ObjectGap::Loss,
    );
    assert!(!has_created(&lost));
    let settled = h.settle(6);
    assert!(!has_created(&settled), "lost tickets never publish");
    assert!(first_observed(&settled, lost_use).is_empty());
    assert!(h.project().objects.is_empty());

    h.rebootstrap(0, 7);
    let fresh = h.run(8, create(SA), 9, ok().result(0, H1));
    let used = h.run(
        10,
        sign_init(SA, H1),
        11,
        ok().mech(MechanismEvidence::Value(ECDSA)),
    );
    let effects = h.settle(11);
    let p = h.project();
    let id = created(&effects, fresh, 0).expect("fresh post-boundary creation");
    assert!(first_observed(&effects, used).is_empty());
    assert_eq!(p.objects.len(), 1);
    assert_eq!(view(&p, id).key_uses, 1);
    assert!(p.gap(ObjectGap::Loss) >= 1);
}

#[test]
fn s2s3_stale_origin_and_dependency_fences_capacity_keeps_fences() {
    let limits = ObjectLimits {
        pending_calls: 3,
        ..ObjectLimits::policy()
    };
    let mut h = Hist::with_limits(limits);
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, create(SA), 4, ok().result(0, H1));
    let waiting = h.begin(5, sign_init(SA, H1));
    assert_eq!(
        h.project().usage.pending_calls,
        3,
        "N pending calls admitted"
    );
    let refused = h.try_begin_in(0, 7, get_size(SA, H2));
    assert_eq!(refused, Err(ObjectGap::PendingCapacity), "N+1 refuses");
    assert_eq!(
        h.project().usage.pending_calls,
        3,
        "fences retained after refusal"
    );
    let late = h.done(waiting, 6, ok().mech(MechanismEvidence::Value(ECDSA)));
    assert!(!has_created(&late));
    let effects = h.settle(6);
    assert!(!has_created(&effects), "an unrepresented call blocks proof");
    let p = h.project();
    assert!(p.objects.is_empty());
    assert_eq!(p.gap(ObjectGap::PendingCapacity), 1);
}

#[test]
fn s2s3_stale_origin_and_dependency_fences_duplicates() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let made = h.begin(3, create(SA));
    assert_eq!(
        h.try_begin_in(0, 3, create(SA)),
        Err(ObjectGap::DuplicateCall),
        "an active logical call is admitted once"
    );
    h.done(made, 4, ok().result(0, H1));
    let again = h.done(made, 4, ok().result(0, H1));
    assert!(again.effects.contains(&ObjectEffect::Gap {
        reason: ObjectGap::DuplicateCompletion
    }));
    let first = h.settle(4);
    assert!(created(&first, made, 0).is_some());
    let second = h.settle(4);
    assert!(
        !has_created(&second),
        "repeated settlement applies nothing twice"
    );
    assert_eq!(h.project().objects.len(), 1);
    assert_eq!(
        h.try_begin_in(0, 3, create(SA)),
        Err(ObjectGap::ClosedFrontier),
        "the closed frontier rejects re-entry after retirement"
    );
    let stale = h.done(made, 5, ok().result(0, H2));
    assert!(stale.effects.contains(&ObjectEffect::Gap {
        reason: ObjectGap::StaleToken
    }));
    assert_eq!(h.project().objects.len(), 1);
}

fn unknown_output_collision(first_outcome: Done) -> (ObjectEffects, CallToken) {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    let a = h.begin(5, create(SA));
    let b = h.run(6, create(SB), 7, ok().result(0, H2));
    h.done(a, 8, first_outcome);
    (h.settle(8), b)
}

#[test]
fn s2s3_stale_origin_and_dependency_fences_unreadable_success_is_not_no_effect() {
    let (effects, b) = unknown_output_collision(ok().unreadable(0));
    assert_eq!(created(&effects, b, 0), None, "unknown output may collide");
    assert_eq!(unresolved(&effects, b), Some(ObjectGap::OutputCollision));
    let (control, b) = unknown_output_collision(rv(CkRv::FUNCTION_FAILED));
    assert!(
        created(&control, b, 0).is_some(),
        "ordinary failure has no output"
    );
}

#[test]
fn s2s3_stale_origin_and_dependency_fences_pending_is_not_replayed() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let pending = h.run(3, create(SA), 4, rv(CkRv::PENDING).result(0, H1));
    let later = h.run(
        5,
        sign_init(SA, H1),
        6,
        ok().mech(MechanismEvidence::Value(ECDSA)),
    );
    let effects = h.settle(6);
    assert_eq!(created(&effects, pending, 0), None);
    let id = sole(first_observed(&effects, later));
    let p = h.project();
    assert_eq!(
        view(&p, id).origin,
        ViewOrigin::FirstObserved,
        "no async replay"
    );
    assert_eq!(view(&p, id).birth, Birth::Unknown);
}

#[test]
fn s2s3_stale_origin_and_dependency_fences_timeout_mints_no_proof() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT2)), 4, ok().session_out(SB));
    let _stuck = h.begin(5, create(SA));
    let other = h.run(6, create(SB), 7, ok().result(0, H2));
    let held = h.settle(7);
    assert_eq!(
        created(&held, other, 0),
        None,
        "a prefix does not settle past an open call"
    );
    assert_eq!(h.project().usage.pending_calls, 2);
    h.model.invalidate(
        AffectedScope::Session(base_domain(), sess(SA)),
        ObjectGap::Loss,
    );
    let after = h.settle(8);
    assert!(!has_created(&after), "timeout/loss mints no proof");
    assert!(h.project().objects.is_empty());
}

#[test]
fn s2s3_stale_origin_and_dependency_fences_unreadable_inputs_stay_unknown() {
    let mut h = Hist::qualified();
    let open = h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let unreadable_key = h.run(
        3,
        call("C_SignInit").on(SA).input_unreadable(0),
        4,
        ok().mech(MechanismEvidence::Value(ECDSA)),
    );
    let mut unreadable_session = sign_init(SB, H1);
    unreadable_session.session = HandleInput::Unreadable;
    let no_session = h.run(
        5,
        unreadable_session,
        6,
        ok().mech(MechanismEvidence::Value(ECDSA)),
    );
    let unreadable_find = h.begin(7, call("C_FindObjects").on(SA));
    let mut done = ok();
    done.found = FindResult::Unreadable;
    h.done(unreadable_find, 8, done);
    let many = [H1, H2, H3, H4, H5, H6, H7, H8, H9];
    let truncated = h.run(9, call("C_FindObjects").on(SA), 10, ok().found(&many));
    let closed = h.run(11, close(SA), 12, ok());
    let effects = h.settle(12);
    assert_eq!(
        unresolved(&effects, unreadable_key),
        Some(ObjectGap::UnprovenInput)
    );
    assert_eq!(
        unresolved(&effects, no_session),
        Some(ObjectGap::UnprovenSession)
    );
    assert!(first_observed(&effects, unreadable_find).is_empty());
    assert_eq!(
        first_observed(&effects, truncated).len(),
        8,
        "at most eight find handles"
    );
    let session = opened(&effects, open).unwrap();
    assert!(effects.effects.contains(&ObjectEffect::SessionEnded {
        session,
        end: SessionEnd::Closed
    }));
    let _ = closed;
    let p = h.project();
    assert_eq!(p.objects.len(), 8);
    assert_eq!(
        p.sessions.len(),
        1,
        "an unreadable selector mints no session"
    );
}

// ---------------------------------------------------------------------------
// destroy_other_session_scope (D1/D2)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Persist {
    Unknown,
    False,
    True,
}

fn d1_case(equal: bool, b_persist: Persist, a_first_observed: bool, reverse: bool) {
    let mut h = Hist::qualified();
    let hb = if equal { H1 } else { H2 };
    let mut plan: Vec<(u64, Call, u64, Done)> = vec![
        (1, open_in(slot(SLOT1)), 2, ok().session_out(SA)),
        (3, open_in(slot(SLOT1)), 4, ok().session_out(SB)),
    ];
    if a_first_observed {
        plan.push((5, get_size(SA, H1), 6, ok()));
    } else {
        plan.push((5, create(SA), 6, ok().result(0, H1)));
    }
    plan.push((7, get_size(SB, hb), 8, ok()));
    match b_persist {
        Persist::Unknown => {}
        Persist::False => plan.push((9, get_attrs(SB, hb), 10, ok().attrs(token_attr(0)))),
        Persist::True => plan.push((9, get_attrs(SB, hb), 10, ok().attrs(token_attr(1)))),
    }
    plan.push((11, destroy(SA, H1), 12, ok()));
    plan.push((13, get_size(SB, hb), 14, ok()));
    let tokens: Vec<CallToken> = plan
        .iter()
        .map(|(b, c, _, _)| h.begin(*b, c.clone()))
        .collect();
    let mut order: Vec<usize> = (0..plan.len()).collect();
    if reverse {
        order.reverse();
    }
    for i in order {
        h.done(tokens[i], plan[i].2, plan[i].3.clone());
    }
    let effects = h.settle(14);
    let p = h.project();
    let target = if a_first_observed {
        sole(first_observed(&effects, tokens[2]))
    } else {
        created(&effects, tokens[2], 0).expect("A's created target")
    };
    let b_old = sole(first_observed(&effects, tokens[3]));
    let b_new = sole(first_observed(&effects, *tokens.last().unwrap()));
    assert_eq!(view(&p, target).lifetime, Lifetime::Destroyed);
    assert_eq!(
        view(&p, b_old).lifetime,
        Lifetime::Retired(ObjectGap::DestroyAlias),
        "B's possibly shared view retires uncertain, never destroyed"
    );
    assert_ne!(
        b_new, b_old,
        "B's reused handle gets a new first-observed ID"
    );
    let fresh = view(&p, b_new);
    assert_eq!(fresh.origin, ViewOrigin::FirstObserved);
    assert_eq!(fresh.birth, Birth::Unknown);
    assert_eq!(
        fresh.established.field(SafeAttributeKind::Token),
        FieldState::Unknown
    );
    assert_eq!(fresh.references, 1);
}

#[test]
fn s2s3_destroy_other_session_scope_d1_matrix() {
    for equal in [true, false] {
        for persist in [Persist::Unknown, Persist::False, Persist::True] {
            for first in [false, true] {
                for reverse in [false, true] {
                    d1_case(equal, persist, first, reverse);
                }
            }
        }
    }
}

/// A creates H1 in slot1; B's view of H2 comes from `b_view`; A destroys.
fn d2_case(b_scope: SlotScope, b_creates: bool, destroy_rv: CkRv) -> (Lifetime, Lifetime) {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(b_scope), 4, ok().session_out(SB));
    let a = h.run(5, create(SA), 6, ok().result(0, H1));
    let b = if b_creates {
        h.run(7, create(SB), 8, ok().result(0, H1))
    } else {
        h.run(7, get_size(SB, H2), 8, ok())
    };
    h.run(9, destroy(SA, H1), 10, rv(destroy_rv));
    let effects = h.settle(10);
    let p = h.project();
    let a_id = created(&effects, a, 0).expect("A view");
    let b_id = if b_creates {
        created(&effects, b, 0).expect("B created view")
    } else {
        sole(first_observed(&effects, b))
    };
    (view(&p, a_id).lifetime, view(&p, b_id).lifetime)
}

#[test]
fn s2s3_destroy_other_session_scope_d2_controls() {
    // Proven different slot: disjoint.
    assert_eq!(
        d2_case(slot(SLOT2), false, CkRv::OK),
        (Lifetime::Destroyed, Lifetime::Live)
    );
    // Distinct continuous creations survive even with equal handles.
    assert_eq!(
        d2_case(slot(SLOT1), true, CkRv::OK),
        (Lifetime::Destroyed, Lifetime::Live)
    );
    // Unknown B scope is compatible.
    assert_eq!(
        d2_case(SlotScope::Unknown, false, CkRv::OK),
        (
            Lifetime::Destroyed,
            Lifetime::Retired(ObjectGap::DestroyAlias)
        )
    );
    // Ordinary failed destroy: no transition at all.
    assert_eq!(
        d2_case(slot(SLOT1), false, CkRv::FUNCTION_FAILED),
        (Lifetime::Live, Lifetime::Live)
    );
    // Invalid handle ends A's access only.
    assert_eq!(
        d2_case(slot(SLOT1), false, CkRv::OBJECT_HANDLE_INVALID),
        (
            Lifetime::AccessEnded(ObjectGap::InvalidHandle),
            Lifetime::Live
        )
    );
    // Ambiguous failure: uncertainty, never destruction.
    assert_eq!(
        d2_case(slot(SLOT1), false, CkRv::GENERAL_ERROR),
        (
            Lifetime::Retired(ObjectGap::AmbiguousOutcome),
            Lifetime::Retired(ObjectGap::DestroyAlias)
        )
    );
}

#[test]
fn s2s3_destroy_other_session_scope_first_observed_target_may_be_b_creation() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    let b = h.run(5, create(SB), 6, ok().result(0, H2));
    let a = h.run(7, get_size(SA, H1), 8, ok());
    h.run(9, destroy(SA, H1), 10, ok());
    let effects = h.settle(10);
    let p = h.project();
    let b_id = created(&effects, b, 0).unwrap();
    let a_id = sole(first_observed(&effects, a));
    assert_eq!(view(&p, a_id).lifetime, Lifetime::Destroyed);
    assert_eq!(
        view(&p, b_id).lifetime,
        Lifetime::Retired(ObjectGap::DestroyAlias)
    );
}

#[test]
fn s2s3_destroy_other_session_scope_disjoint_domain_survives() {
    let mut h = Hist::qualified();
    let other = h.add_domain(ObjectDomain::reference(9, 1, 1, 1, 1), true);
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, create(SA), 4, ok().result(0, H1));
    let b = h.run_in(other, 1, get_size(SA, H1), 2, ok());
    let b_effects = h.settle_in(other, 2);
    h.run(5, destroy(SA, H1), 6, ok());
    h.settle(6);
    let p = h.project();
    let b_id = sole(first_observed(&b_effects, b));
    assert_eq!(
        view(&p, b_id).lifetime,
        Lifetime::Live,
        "other authority domain"
    );
}

#[test]
fn s2s3_destroy_other_session_scope_overlapping_b_result_is_refused() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    h.run(5, create(SA), 6, ok().result(0, H1));
    let b_seen = h.run(7, get_size(SB, H2), 8, ok());
    let overlapping = h.begin(9, get_size(SB, H2));
    h.run(10, destroy(SA, H1), 11, ok());
    h.done(overlapping, 12, ok());
    let effects = h.settle(12);
    let p = h.project();
    let b_id = sole(first_observed(&effects, b_seen));
    assert_eq!(
        unresolved(&effects, overlapping),
        Some(ObjectGap::OverlapUncertain)
    );
    assert_eq!(
        view(&p, b_id).references,
        1,
        "overlapping result does not join"
    );
    assert_eq!(
        view(&p, b_id).lifetime,
        Lifetime::Retired(ObjectGap::DestroyAlias)
    );
}

// ---------------------------------------------------------------------------
// creator_close_scope
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Debug)]
enum BEvidence {
    Unknown,
    False,
    Conflicted,
    TrueThenSet,
    True,
    CreatedByB,
}

struct CloseOutcome {
    p: ObjectProjection,
    x: ObjectId,
    b_old: ObjectId,
    b_new: Option<ObjectId>,
    a_session: SessionIncarnation,
    b_session: SessionIncarnation,
}

fn close_case(
    b_evidence: BEvidence,
    equal: bool,
    b_scope: SlotScope,
    close_rv: CkRv,
) -> CloseOutcome {
    let mut h = Hist::qualified();
    let hb = if equal { H1 } else { H2 };
    let oa = h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let ob = h.run(3, open_in(b_scope), 4, ok().session_out(SB));
    let x = h.run(5, create(SA), 6, ok().result(0, H1));
    h.run(7, get_attrs(SA, H1), 8, ok().attrs(token_attr(0)));
    let b = if b_evidence == BEvidence::CreatedByB {
        h.run(9, create(SB), 10, ok().result(0, hb))
    } else {
        h.run(9, get_size(SB, hb), 10, ok())
    };
    match b_evidence {
        BEvidence::Unknown | BEvidence::CreatedByB => {}
        BEvidence::False => {
            h.run(11, get_attrs(SB, hb), 12, ok().attrs(token_attr(0)));
        }
        BEvidence::True => {
            h.run(11, get_attrs(SB, hb), 12, ok().attrs(token_attr(1)));
        }
        BEvidence::Conflicted => {
            h.run(11, get_attrs(SB, hb), 12, ok().attrs(token_attr(0)));
            h.run(13, get_attrs(SB, hb), 14, ok().attrs(token_attr(1)));
        }
        BEvidence::TrueThenSet => {
            h.run(11, get_attrs(SB, hb), 12, ok().attrs(token_attr(1)));
            h.run(
                13,
                call("C_SetAttributeValue").on(SB).input(0, hb),
                14,
                ok(),
            );
        }
    }
    h.run(15, close(SA), 16, rv(close_rv));
    let fresh = h.run(17, get_size(SB, hb), 18, ok());
    let effects = h.settle(18);
    let p = h.project();
    let b_old = if b_evidence == BEvidence::CreatedByB {
        created(&effects, b, 0).unwrap()
    } else {
        sole(first_observed(&effects, b))
    };
    let b_new = first_observed(&effects, fresh).first().copied();
    CloseOutcome {
        x: created(&effects, x, 0).unwrap(),
        b_old,
        b_new,
        a_session: opened(&effects, oa).unwrap(),
        b_session: opened(&effects, ob).unwrap(),
        p,
    }
}

#[test]
fn s2s3_creator_close_scope_unknown_creator_views_retire_uncertain() {
    for evidence in [
        BEvidence::Unknown,
        BEvidence::False,
        BEvidence::Conflicted,
        BEvidence::TrueThenSet,
    ] {
        for equal in [true, false] {
            let o = close_case(evidence, equal, slot(SLOT1), CkRv::OK);
            // B's successful mutation may have reached A's object through an
            // alias, so A's token=false claim is no longer current.
            let x_expected = if evidence == BEvidence::TrueThenSet {
                Lifetime::AccessEnded(ObjectGap::SessionClosed)
            } else {
                Lifetime::Destroyed
            };
            assert_eq!(view(&o.p, o.x).lifetime, x_expected, "{evidence:?}");
            assert_eq!(
                view(&o.p, o.b_old).lifetime,
                Lifetime::Retired(ObjectGap::CloseUncertain),
                "{evidence:?}: B is never declared destroyed"
            );
            let b_new = o.b_new.expect("fresh B observation");
            assert_ne!(b_new, o.b_old);
            assert_eq!(
                view(&o.p, b_new)
                    .established
                    .field(SafeAttributeKind::Token),
                FieldState::Unknown,
                "no metadata carries to the reused handle"
            );
            assert_eq!(
                o.p.session(o.a_session).unwrap().state,
                SessionState::Closed
            );
            assert_eq!(o.p.session(o.b_session).unwrap().state, SessionState::Live);
        }
    }
}

#[test]
fn s2s3_creator_close_scope_exemptions_preserve_b() {
    for evidence in [BEvidence::True, BEvidence::CreatedByB] {
        let o = close_case(evidence, true, slot(SLOT1), CkRv::OK);
        assert_eq!(view(&o.p, o.x).lifetime, Lifetime::Destroyed);
        assert_eq!(view(&o.p, o.b_old).lifetime, Lifetime::Live, "{evidence:?}");
        assert_eq!(o.b_new, None, "B's continuous view is reused, no new ID");
        let expected_refs = if evidence == BEvidence::True { 3 } else { 1 };
        assert_eq!(view(&o.p, o.b_old).references, expected_refs);
    }
    let disjoint = close_case(BEvidence::Unknown, true, slot(SLOT2), CkRv::OK);
    assert_eq!(view(&disjoint.p, disjoint.b_old).lifetime, Lifetime::Live);
    let unknown = close_case(BEvidence::Unknown, true, SlotScope::Unknown, CkRv::OK);
    assert_eq!(
        view(&unknown.p, unknown.b_old).lifetime,
        Lifetime::Retired(ObjectGap::CloseUncertain),
        "unknown slot is compatible, not slot zero"
    );
}

#[test]
fn s2s3_creator_close_scope_failed_and_ambiguous_close() {
    let failed = close_case(BEvidence::Unknown, true, slot(SLOT1), CkRv::FUNCTION_FAILED);
    assert_eq!(view(&failed.p, failed.x).lifetime, Lifetime::Live);
    assert_eq!(view(&failed.p, failed.b_old).lifetime, Lifetime::Live);
    assert_eq!(
        failed.p.session(failed.a_session).unwrap().state,
        SessionState::Live
    );
    for ambiguous in [
        CkRv::GENERAL_ERROR,
        CkRv::SESSION_CLOSED,
        CkRv::DEVICE_REMOVED,
    ] {
        let o = close_case(BEvidence::False, true, slot(SLOT1), ambiguous);
        assert!(
            matches!(view(&o.p, o.x).lifetime, Lifetime::Retired(_)),
            "never synthesize destruction from failure"
        );
        assert!(matches!(view(&o.p, o.b_old).lifetime, Lifetime::Retired(_)));
        assert!(matches!(
            o.p.session(o.a_session).unwrap().state,
            SessionState::Ended(_)
        ));
    }
}

#[test]
fn s2s3_creator_close_scope_own_view_persistence_unknown_ends_observation() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let requested_only = h.run(
        3,
        create(SA).request(0, token_attr(0)),
        4,
        ok().result(0, H1),
    );
    let conflicted = h.run(5, create(SA), 6, ok().result(0, H2));
    h.run(7, get_attrs(SA, H2), 8, ok().attrs(token_attr(0)));
    h.run(9, get_attrs(SA, H2), 10, ok().attrs(token_attr(1)));
    let token = h.run(11, create(SA), 12, ok().result(0, H3));
    h.run(13, get_attrs(SA, H3), 14, ok().attrs(token_attr(1)));
    h.run(15, close(SA), 16, ok());
    let effects = h.settle(16);
    let p = h.project();
    for t in [requested_only, conflicted, token] {
        let id = created(&effects, t, 0).unwrap();
        assert_eq!(
            view(&p, id).lifetime,
            Lifetime::AccessEnded(ObjectGap::SessionClosed),
            "requested/conflicted/token persistence ends observation only"
        );
    }
}

#[test]
fn s2s3_creator_close_scope_other_domain_unknown_slot_survives() {
    let mut h = Hist::qualified();
    let other = h.add_domain(ObjectDomain::reference(1, 1, 1, 7, 1), true);
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, create(SA), 4, ok().result(0, H1));
    let b = h.run_in(other, 1, get_size(SB, H1), 2, ok());
    let b_effects = h.settle_in(other, 2);
    h.run(5, close(SA), 6, ok());
    h.settle(6);
    let p = h.project();
    let b_id = sole(first_observed(&b_effects, b));
    assert_eq!(view(&p, b_id).lifetime, Lifetime::Live);
}

#[test]
fn s2s3_creator_close_scope_close_all_logout_and_reopen() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    h.run(5, open_in(slot(SLOT2)), 6, ok().session_out(SC));
    let x = h.run(7, create(SA), 8, ok().result(0, H1));
    h.run(9, get_attrs(SA, H1), 10, ok().attrs(token_attr(0)));
    let b = h.run(11, get_size(SB, H2), 12, ok());
    h.run(13, get_attrs(SB, H2), 14, ok().attrs(token_attr(1)));
    let c = h.run(15, get_size(SC, H3), 16, ok());
    h.run(17, call("C_CloseAllSessions").scope(slot(SLOT1)), 18, ok());
    let reopen = h.run(19, open_in(slot(SLOT1)), 20, ok().session_out(SA));
    let found = h.run(21, call("C_FindObjects").on(SA), 22, ok().found(&[H1]));
    let effects = h.settle(22);
    let p = h.project();
    let x_id = created(&effects, x, 0).unwrap();
    let b_id = sole(first_observed(&effects, b));
    let c_id = sole(first_observed(&effects, c));
    assert_eq!(
        view(&p, x_id).lifetime,
        Lifetime::Destroyed,
        "creator closed, token=false"
    );
    assert_eq!(
        view(&p, b_id).lifetime,
        Lifetime::AccessEnded(ObjectGap::SessionClosed),
        "token view access ends without destruction"
    );
    assert_eq!(view(&p, c_id).lifetime, Lifetime::Live, "other slot");
    let new_session = opened(&effects, reopen).unwrap();
    assert_ne!(new_session, view(&p, x_id).session);
    let refound = sole(first_observed(&effects, found));
    assert_ne!(refound, x_id, "equal handles never recover old IDs");

    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    h.run(5, open_in(slot(SLOT2)), 6, ok().session_out(SC));
    let x = h.run(7, create(SA), 8, ok().result(0, H1));
    let b = h.run(9, get_size(SB, H2), 10, ok());
    h.run(11, get_attrs(SB, H2), 12, ok().attrs(token_attr(1)));
    let c = h.run(13, get_size(SC, H3), 14, ok());
    h.run(15, call("C_Logout").on(SA), 16, ok());
    let effects = h.settle(16);
    let p = h.project();
    for id in [
        created(&effects, x, 0).unwrap(),
        sole(first_observed(&effects, b)),
    ] {
        assert_eq!(
            view(&p, id).lifetime,
            Lifetime::Retired(ObjectGap::LogoutUncertain),
            "logout ends accessibility, including token views"
        );
    }
    assert_eq!(
        view(&p, sole(first_observed(&effects, c))).lifetime,
        Lifetime::Live
    );
    assert!(p.sessions.iter().all(|s| s.state == SessionState::Live));
}

#[test]
fn s2s3_creator_close_scope_last_session_close_then_reopen() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    let b = h.run(5, get_size(SB, H1), 6, ok());
    h.run(7, get_attrs(SB, H1), 8, ok().attrs(token_attr(1)));
    h.run(9, close(SA), 10, ok());
    h.run(11, close(SB), 12, ok());
    h.run(13, open_in(slot(SLOT1)), 14, ok().session_out(SB));
    let again = h.run(15, get_size(SB, H1), 16, ok());
    let effects = h.settle(16);
    let p = h.project();
    let old = sole(first_observed(&effects, b));
    assert_eq!(
        view(&p, old).lifetime,
        Lifetime::AccessEnded(ObjectGap::SessionClosed)
    );
    let new = sole(first_observed(&effects, again));
    assert_ne!(new, old, "token history is not a surviving session binding");
}

#[test]
fn s2s3_creator_close_scope_overlapping_b_result() {
    let run = |b_token: bool| {
        let mut h = Hist::qualified();
        h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
        h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
        let seen = h.run(5, get_size(SB, H2), 6, ok());
        if b_token {
            h.run(7, get_attrs(SB, H2), 8, ok().attrs(token_attr(1)));
        }
        let overlap = h.begin(9, get_size(SB, H2));
        h.run(10, close(SA), 11, ok());
        h.done(overlap, 12, ok());
        let effects = h.settle(12);
        let p = h.project();
        let id = sole(first_observed(&effects, seen));
        (unresolved(&effects, overlap), view(&p, id).clone())
    };
    let (gap, v) = run(false);
    assert_eq!(gap, Some(ObjectGap::OverlapUncertain));
    assert_eq!(v.lifetime, Lifetime::Retired(ObjectGap::CloseUncertain));
    assert_eq!(v.references, 1);
    let (gap, v) = run(true);
    assert_eq!(gap, None, "token-view control stays useful");
    assert_eq!(v.lifetime, Lifetime::Live);
    assert_eq!(v.references, 3);
}

// ---------------------------------------------------------------------------
// concurrent_session_contract (C1)
// ---------------------------------------------------------------------------

#[test]
fn s2s3_concurrent_session_contract_separate_sessions_settle() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    let before = h.run(5, create(SC), 6, ok().result(0, H9));
    let first = h.settle(6);
    let prior = created(&first, before, 0).unwrap();
    let snapshot = view(&h.project(), prior).clone();
    let a = h.begin(7, create(SA));
    let b = h.run(8, create(SB), 9, ok().result(0, H2));
    h.done(a, 10, ok().result(0, H1));
    let ua = h.run(
        11,
        sign_init(SA, H1),
        12,
        ok().mech(MechanismEvidence::Value(ECDSA)),
    );
    let ub = h.run(
        13,
        sign_init(SB, H2),
        14,
        ok().mech(MechanismEvidence::Value(ECDSA)),
    );
    let effects = h.settle(14);
    let p = h.project();
    let ia = created(&effects, a, 0).expect("A creation");
    let ib = created(&effects, b, 0).expect("B creation");
    assert_ne!(ia, ib);
    assert_eq!(view(&p, ia).key_uses, 1);
    assert_eq!(view(&p, ib).key_uses, 1);
    assert!(first_observed(&effects, ua).is_empty() && first_observed(&effects, ub).is_empty());
    assert_eq!(
        view(&p, prior),
        &snapshot,
        "one creation does not advance all objects"
    );
}

#[test]
fn s2s3_concurrent_session_contract_same_session_overlap_is_uncertain() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let a = h.begin(3, create(SA));
    let b = h.run(4, call("C_GenerateKey").on(SA), 5, ok().result(0, H2));
    h.done(a, 6, ok().result(0, H1));
    let effects = h.settle(6);
    assert_eq!(
        created(&effects, a, 0),
        None,
        "disjoint handles supply no exemption"
    );
    assert_eq!(created(&effects, b, 0), None);
    assert_eq!(unresolved(&effects, a), Some(ObjectGap::SameSessionOverlap));
    assert_eq!(unresolved(&effects, b), Some(ObjectGap::SameSessionOverlap));
    assert!(h.project().objects.is_empty());
}

#[test]
fn s2s3_concurrent_session_contract_cross_session_equal_outputs_collide() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    let a = h.begin(5, create(SA));
    let b = h.run(6, create(SB), 7, ok().result(0, H1));
    h.done(a, 8, ok().result(0, H1));
    let effects = h.settle(8);
    assert_eq!(unresolved(&effects, a), Some(ObjectGap::OutputCollision));
    assert_eq!(unresolved(&effects, b), Some(ObjectGap::OutputCollision));
    // Strictly ordered equal outputs in separate sessions stay two views.
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    let a = h.run(5, create(SA), 6, ok().result(0, H1));
    let b = h.run(7, create(SB), 8, ok().result(0, H1));
    let effects = h.settle(8);
    assert_ne!(
        created(&effects, a, 0).unwrap(),
        created(&effects, b, 0).unwrap()
    );
}

#[test]
fn s2s3_concurrent_session_contract_open_call_holds_then_releases() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    let a = h.begin(5, create(SA));
    let b = h.run(6, create(SB), 7, ok().result(0, H2));
    let held = h.settle(7);
    assert_eq!(
        created(&held, b, 0),
        None,
        "held while the overlapping output is unknown"
    );
    assert!(h.project().objects.is_empty());
    h.done(a, 8, ok().result(0, H1));
    let released = h.settle(8);
    assert!(created(&released, a, 0).is_some());
    assert!(
        created(&released, b, 0).is_some(),
        "distinct outcome proves separation"
    );
}

// ---------------------------------------------------------------------------
// lifecycle_loss_and_prefix_contradiction (H1)
// ---------------------------------------------------------------------------

#[test]
fn s2s3_lifecycle_loss_and_prefix_contradiction_finalize_and_new_era() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let x = h.run(3, create(SA), 4, ok().result(0, H1));
    h.run(5, call("C_Finalize"), 6, ok());
    let effects = h.settle(6);
    let p = h.project();
    let id = created(&effects, x, 0).unwrap();
    assert_eq!(
        view(&p, id).lifetime,
        Lifetime::AccessEnded(ObjectGap::Finalize)
    );
    assert!(p.sessions.iter().all(|s| s.state != SessionState::Live));
    assert_eq!(
        h.try_begin_in(0, 7, create(SA)),
        Err(ObjectGap::DomainEnded),
        "finalize ends the initialization era"
    );
    let era = h.add_domain(ObjectDomain::reference(1, 1, 1, 1, 2), true);
    h.run_in(era, 1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let seen = h.run_in(era, 3, get_size(SA, H1), 4, ok());
    let e2 = h.settle_in(era, 4);
    assert_ne!(sole(first_observed(&e2, seen)), id, "no old ID recovery");
}

#[test]
fn s2s3_lifecycle_loss_and_prefix_contradiction_failed_finalize_keeps_state() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let x = h.run(3, create(SA), 4, ok().result(0, H1));
    h.run(5, call("C_Finalize"), 6, rv(CkRv::FUNCTION_FAILED));
    let effects = h.settle(6);
    let id = created(&effects, x, 0).unwrap();
    assert_eq!(
        view(&h.project(), id).lifetime,
        Lifetime::Live,
        "no automatic epoch"
    );
    assert!(h.try_begin_in(0, 7, get_size(SA, H1)).is_ok());
}

#[test]
fn s2s3_lifecycle_loss_and_prefix_contradiction_reference_boundaries() {
    for reason in [
        ObjectGap::Exec,
        ObjectGap::Unload,
        ObjectGap::Fork,
        ObjectGap::Loss,
    ] {
        let mut h = Hist::qualified();
        h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
        let x = h.run(3, create(SA), 4, ok().result(0, H1));
        let effects = h.settle(4);
        let id = created(&effects, x, 0).unwrap();
        h.model
            .invalidate(AffectedScope::Domain(base_domain()), reason);
        let p = h.project();
        assert_eq!(view(&p, id).lifetime, Lifetime::Retired(reason));
        assert_eq!(
            view(&p, id).origin,
            ViewOrigin::Created(CreationFamily::Create)
        );
        assert!(p.sessions.iter().all(|s| s.state != SessionState::Live));
    }
    // A forked child is a separate domain and inherits nothing.
    let mut h = Hist::qualified();
    let child = h.add_domain(ObjectDomain::reference(2, 1, 1, 1, 1), true);
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let parent = h.run(3, create(SA), 4, ok().result(0, H1));
    let pe = h.settle(4);
    let seen = h.run_in(child, 1, get_size(SA, H1), 2, ok());
    let ce = h.settle_in(child, 2);
    let p = h.project();
    let child_view = view(&p, sole(first_observed(&ce, seen)));
    assert_ne!(child_view.id, created(&pe, parent, 0).unwrap());
    assert_eq!(child_view.creator, None);
    assert_eq!(child_view.origin, ViewOrigin::FirstObserved);
}

#[test]
fn s2s3_lifecycle_loss_and_prefix_contradiction_ended_domain_releases_tickets() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.settle(2);
    let in_flight = h.begin(3, create(SA));
    assert_eq!(h.project().usage.pending_calls, 1);
    h.model
        .invalidate(AffectedScope::Domain(base_domain()), ObjectGap::Unload);
    assert_eq!(
        h.project().usage.pending_calls,
        0,
        "no fence outlives an ended domain"
    );
    let late = h.done(in_flight, 4, ok().result(0, H1));
    assert!(late.effects.contains(&ObjectEffect::Gap {
        reason: ObjectGap::StaleToken
    }));
    assert!(h.project().objects.is_empty());
}

#[test]
fn s2s3_lifecycle_loss_and_prefix_contradiction_token_reset_and_local_loss() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT2)), 4, ok().session_out(SB));
    h.run(5, open_in(slot(SLOT1)), 6, ok().session_out(SC));
    let a = h.run(7, create(SA), 8, ok().result(0, H1));
    let b = h.run(9, create(SB), 10, ok().result(0, H1));
    let c = h.run(11, create(SC), 12, ok().result(0, H3));
    let effects = h.settle(12);
    let (ia, ib, ic) = (
        created(&effects, a, 0).unwrap(),
        created(&effects, b, 0).unwrap(),
        created(&effects, c, 0).unwrap(),
    );
    h.model.invalidate(
        AffectedScope::Session(base_domain(), sess(SC)),
        ObjectGap::Loss,
    );
    let p = h.project();
    assert_eq!(view(&p, ic).lifetime, Lifetime::Retired(ObjectGap::Loss));
    assert_eq!(
        view(&p, ia).lifetime,
        Lifetime::Retired(ObjectGap::Loss),
        "a session loss is an uncertain close+destroy over its compatible scope"
    );
    assert_eq!(view(&p, ib).lifetime, Lifetime::Live, "proven other slot");
    let a_session = view(&p, ia).session;
    assert_eq!(p.session(a_session).unwrap().state, SessionState::Live);
    // SA stays open and proof continues (no pending tickets were lost).
    let d = h.run(15, create(SA), 16, ok().result(0, H4));
    let e = h.settle(16);
    let id = created(&e, d, 0).expect("proof continues after a ticketless loss");
    h.model.invalidate(
        AffectedScope::Slot(base_domain(), slot(SLOT1)),
        ObjectGap::TokenReset,
    );
    let p = h.project();
    assert_eq!(
        view(&p, id).lifetime,
        Lifetime::Retired(ObjectGap::TokenReset)
    );
    assert_eq!(view(&p, ib).lifetime, Lifetime::Live, "other slot survives");
    h.model.invalidate(AffectedScope::Capture, ObjectGap::Loss);
    let p = h.project();
    assert_eq!(view(&p, ib).lifetime, Lifetime::Retired(ObjectGap::Loss));
    // Global loss voids bootstrap: later success publishes nothing.
    let later = h.run(17, create(SB), 18, ok().result(0, H2));
    let e = h.settle(18);
    assert_eq!(created(&e, later, 0), None);
    assert!(p.gap(ObjectGap::Loss) >= 2);
}

#[test]
fn s2s3_lifecycle_loss_and_prefix_contradiction_ordinary_vs_ambiguous_failure() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let x = h.run(3, create(SA), 4, ok().result(0, H1));
    h.run(
        5,
        call("C_SetAttributeValue").on(SA).input(0, H1),
        6,
        rv(CkRv::FUNCTION_FAILED),
    );
    h.run(7, destroy(SA, H1), 8, rv(CkRv::FUNCTION_FAILED));
    let effects = h.settle(8);
    let id = created(&effects, x, 0).unwrap();
    assert_eq!(view(&h.project(), id).lifetime, Lifetime::Live);
    h.run(9, destroy(SA, H1), 10, rv(CkRv::GENERAL_ERROR));
    h.settle(10);
    assert_eq!(
        view(&h.project(), id).lifetime,
        Lifetime::Retired(ObjectGap::AmbiguousOutcome)
    );
}

#[test]
fn s2s3_lifecycle_loss_and_prefix_contradiction_downgrades_published_join() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let x = h.run(3, create(SA), 4, ok().result(0, H1));
    let open_call = h.begin(5, sign_init(SA, H1));
    let effects = h.settle(6);
    let id = created(&effects, x, 0).unwrap();
    assert_eq!(view(&h.project(), id).attribution, Attribution::Valid);
    // The completion contradicts the prefix that declared it open through 6.
    let contradiction = h.done(open_call, 5, ok().mech(MechanismEvidence::Value(ECDSA)));
    assert!(contradiction.effects.contains(&ObjectEffect::Downgraded {
        object: id,
        reason: ObjectGap::PrefixContradiction
    }));
    let p = h.project();
    let v = view(&p, id);
    assert_eq!(
        v.attribution,
        Attribution::Downgraded(ObjectGap::PrefixContradiction)
    );
    assert_eq!(
        v.origin,
        ViewOrigin::Created(CreationFamily::Create),
        "observation retained"
    );
    assert_eq!(
        v.lifetime,
        Lifetime::Retired(ObjectGap::PrefixContradiction)
    );
    assert_eq!(v.key_uses, 0);
    // Dependents cannot use the downgraded join afterwards.
    let later = h.run(
        7,
        sign_init(SA, H1),
        8,
        ok().mech(MechanismEvidence::Value(ECDSA)),
    );
    let e = h.settle(8);
    assert!(
        first_observed(&e, later).is_empty(),
        "no proof until a new bootstrap"
    );
    assert_eq!(view(&h.project(), id).key_uses, 0);
}

#[test]
fn s2s3_lifecycle_loss_and_prefix_contradiction_open_set_mismatch() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let x = h.run(3, create(SA), 4, ok().result(0, H1));
    let effects = h.settle(4);
    let id = created(&effects, x, 0).unwrap();
    let _open = h.begin(5, sign_init(SA, H1));
    // A prefix through 6 that omits the registered open call.
    let bad = CompleteInputPrefix::reference(base_domain(), RefCut::reference(6), &[], None);
    h.model.settle(bad);
    assert_eq!(
        view(&h.project(), id).attribution,
        Attribution::Downgraded(ObjectGap::PrefixContradiction)
    );
    // A prefix naming an unregistered call is equally contradictory.
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let x = h.run(3, create(SA), 4, ok().result(0, H1));
    let id = created(&h.settle(4), x, 0).unwrap();
    let phantom = CompleteInputPrefix::reference(
        base_domain(),
        RefCut::reference(6),
        &[CallKey::reference(5)],
        None,
    );
    h.model.settle(phantom);
    assert_eq!(
        view(&h.project(), id).attribution,
        Attribution::Downgraded(ObjectGap::PrefixContradiction)
    );
}

// ---------------------------------------------------------------------------
// reference_bootstrap_and_unsealed_output
// ---------------------------------------------------------------------------

#[test]
fn s2s3_reference_bootstrap_and_unsealed_output_requires_bootstrap() {
    let mut h = Hist::unqualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let x = h.run(3, create(SA), 4, ok().result(0, H1));
    let e = h.settle(4);
    assert_eq!(
        created(&e, x, 0),
        None,
        "an unknown earlier call could affect it"
    );
    for frontier in [5, 6, 7] {
        h.settle(frontier);
    }
    let y = h.run(8, create(SA), 9, ok().result(0, H2));
    let e = h.settle(9);
    assert_eq!(
        created(&e, y, 0),
        None,
        "empty prefixes/timeouts mint no proof"
    );
    let p = h.project();
    assert!(p.objects.is_empty());
    assert!(p.gap(ObjectGap::BootstrapUnproven) >= 2);

    h.rebootstrap(0, 10);
    h.run(11, open_in(slot(SLOT1)), 12, ok().session_out(SB));
    let z = h.run(13, create(SB), 14, ok().result(0, H3));
    let pre = h.run(15, get_size(SB, H4), 16, ok());
    let e = h.settle(16);
    assert!(
        created(&e, z, 0).is_some(),
        "constructed bootstrap permits settlement"
    );
    let preexisting = sole(first_observed(&e, pre));
    assert_eq!(view(&h.project(), preexisting).birth, Birth::Unknown);
}

#[test]
fn s2s3_reference_bootstrap_and_unsealed_output_represented_old_call_still_affects() {
    let mut h = Hist::unqualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    h.settle(4);
    // A call already in progress at the bootstrap boundary is represented.
    let old = h.begin(5, destroy(SB, H1));
    h.rebootstrap(0, 6);
    let x = h.run(7, create(SA), 8, ok().result(0, H1));
    h.done(old, 9, ok());
    let e = h.settle(9);
    assert_eq!(
        created(&e, x, 0),
        None,
        "the represented old destroy overlaps"
    );
    assert_eq!(unresolved(&e, x), Some(ObjectGap::OverlapUncertain));
}

#[test]
fn s2s3_reference_bootstrap_and_unsealed_output_nothing_before_settlement() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let x = h.begin(3, create(SA));
    let done = h.done(x, 4, ok().result(0, H1));
    assert!(!has_created(&done), "completion stages privately");
    let p = h.project();
    assert!(
        p.objects.is_empty(),
        "no unsettled object ID, birth or metadata"
    );
    assert!(p.sessions.is_empty(), "no unsettled session ID");
    assert_eq!(p.usage.pending_calls, 2);
    let e = h.settle(4);
    assert!(created(&e, x, 0).is_some());
    assert_eq!(
        h.project().usage.pending_calls,
        0,
        "settled tickets are pruned"
    );
}

// ---------------------------------------------------------------------------
// metadata_provenance
// ---------------------------------------------------------------------------

#[test]
fn s2s3_metadata_provenance_requested_and_established_are_separate() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let req = attrs(&[
        scalar(CKA_CLASS, 4),
        scalar(CKA_KEY_TYPE, 0x1f),
        scalar(CKA_VALUE_LEN, 32),
        scalar(CKA_TOKEN, 0),
    ]);
    let x = h.run(
        3,
        call("C_GenerateKey").on(SA).request(0, req),
        4,
        ok().result(0, H1),
    );
    let partial = attrs(&[
        scalar(CKA_CLASS, 4),
        AttrObservation::unavailable(CKA_KEY_TYPE),
        AttrObservation::size_only(CKA_VALUE_LEN),
    ]);
    h.run(
        5,
        get_attrs(SA, H1),
        6,
        rv(CkRv::ATTRIBUTE_SENSITIVE).attrs(partial),
    );
    let e = h.settle(6);
    let id = created(&e, x, 0).unwrap();
    let p = h.project();
    let v = view(&p, id);
    assert_eq!(
        v.requested.field(SafeAttributeKind::KeyType),
        scalar_field(0x1f)
    );
    assert_eq!(
        v.established.field(SafeAttributeKind::Class),
        scalar_field(4)
    );
    assert_eq!(
        v.established.field(SafeAttributeKind::KeyType),
        FieldState::Unknown
    );
    assert_eq!(
        v.established.field(SafeAttributeKind::ValueLen),
        FieldState::Unknown
    );
    assert_eq!(
        v.established.field(SafeAttributeKind::Token),
        FieldState::Unknown
    );
    assert_eq!(
        v.queries[1],
        QueryStatus::Unavailable,
        "KeyType query recorded"
    );
    assert_eq!(
        v.queries[3],
        QueryStatus::SizeOnly,
        "ValueLen query recorded"
    );
    assert_eq!(v.label, None, "size/type unknown: no label");

    // Retry is a new call; it establishes the remaining fields.
    let retry = attrs(&[scalar(CKA_KEY_TYPE, 0x1f), scalar(CKA_VALUE_LEN, 32)]);
    h.run(7, get_attrs(SA, H1), 8, ok().attrs(retry));
    // Unavailable alone does not erase intact previous evidence.
    h.run(
        9,
        get_attrs(SA, H1),
        10,
        ok().attrs(attrs(&[AttrObservation::unavailable(CKA_CLASS)])),
    );
    h.settle(10);
    let p = h.project();
    let v = view(&p, id);
    assert_eq!(
        v.established.field(SafeAttributeKind::Class),
        scalar_field(4)
    );
    assert_eq!(v.queries[0], QueryStatus::Unavailable);
    assert_eq!(v.label, Some(KeyLabel::Aes { value_len: 32 }));

    // Conflict, not last-writer-wins.
    h.run(
        11,
        get_attrs(SA, H1),
        12,
        ok().attrs(attrs(&[scalar(CKA_CLASS, 3)])),
    );
    h.settle(12);
    let p = h.project();
    let v = view(&p, id);
    assert_eq!(
        v.established.field(SafeAttributeKind::Class),
        FieldState::Conflict(Some(FieldValue::Scalar(4))),
        "the earlier value's provenance is retained as history"
    );
    assert_eq!(
        v.label, None,
        "class conflict invalidates the combined label"
    );
}

#[test]
fn s2s3_metadata_provenance_set_attribute_invalidates_current_claims() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let x = h.run(
        3,
        call("C_GenerateKeyPair").on(SA),
        4,
        ok().result(0, H1).result(1, H2),
    );
    let rsa = attrs(&[
        scalar(CKA_CLASS, 2),
        scalar(CKA_KEY_TYPE, 0),
        scalar(CKA_MODULUS_BITS, 2048),
    ]);
    h.run(5, get_attrs(SA, H1), 6, ok().attrs(rsa));
    h.run(
        7,
        call("C_SetAttributeValue").on(SA).input(0, H1),
        8,
        rv(CkRv::FUNCTION_FAILED),
    );
    let e = h.settle(8);
    let id = created(&e, x, 0).unwrap();
    assert_eq!(
        view(&h.project(), id).label,
        Some(KeyLabel::Rsa { modulus_bits: 2048 })
    );
    h.run(9, call("C_SetAttributeValue").on(SA).input(0, H1), 10, ok());
    h.settle(10);
    let p = h.project();
    let v = view(&p, id);
    assert_eq!(
        v.established.field(SafeAttributeKind::ModulusBits),
        FieldState::Invalidated(Some(FieldValue::Scalar(2048))),
        "history retained, current claim invalidated"
    );
    assert_eq!(v.label, None);
    assert_eq!(v.lifetime, Lifetime::Live);
}

#[test]
fn s2s3_metadata_provenance_curve_and_type_labels() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let x = h.run(
        3,
        call("C_GenerateKeyPair").on(SA),
        4,
        ok().result(0, H1).result(1, H2),
    );
    let curve = AttrObservation::curve(CKA_EC_PARAMS, &SECP256R1, LinuxLayout::Lp64);
    h.run(5, get_attrs(SA, H1), 6, ok().attrs(attrs(&[curve])));
    let e = h.settle(6);
    let id = created(&e, x, 0).unwrap();
    let other = created(&e, x, 1).unwrap();
    assert_eq!(
        view(&h.project(), id)
            .established
            .field(SafeAttributeKind::EcParams),
        FieldState::Value(FieldValue::Curve(SafeCurve::Secp256r1))
    );
    assert_eq!(
        view(&h.project(), id).label,
        None,
        "curve without key type: no label"
    );
    h.run(
        7,
        get_attrs(SA, H1),
        8,
        ok().attrs(attrs(&[scalar(CKA_KEY_TYPE, 3)])),
    );
    h.settle(8);
    assert_eq!(
        view(&h.project(), id).label,
        Some(KeyLabel::Ec {
            curve: SafeCurve::Secp256r1
        })
    );
    // Mismatched type: an AES key type with a curve yields no label.
    let mismatched = attrs(&[
        scalar(CKA_KEY_TYPE, 0x1f),
        AttrObservation::curve(CKA_EC_PARAMS, &SECP256R1, LinuxLayout::Lp64),
    ]);
    h.run(9, get_attrs(SA, H2), 10, ok().attrs(mismatched));
    h.settle(10);
    assert_eq!(view(&h.project(), other).label, None);
}

#[test]
fn s2s3_metadata_provenance_classifiers_reject_unsupported_values() {
    let l = LinuxLayout::Lp64;
    let i = LinuxLayout::Ilp32;
    assert_eq!(
        AttrObservation::scalar(CKA_CLASS, 8, 4, l).status(),
        QueryStatus::Established
    );
    assert_eq!(
        AttrObservation::scalar(CKA_CLASS, 4, 4, i).status(),
        QueryStatus::Established
    );
    assert_eq!(
        AttrObservation::scalar(CKA_CLASS, 4, 4, l).status(),
        QueryStatus::Malformed
    );
    assert_eq!(
        AttrObservation::scalar(CKA_CLASS, 8, 0x8000_0000, l).status(),
        QueryStatus::Unsupported
    );
    assert_eq!(
        AttrObservation::scalar(CKA_CLASS, 8, 4 | (1 << 32), l).status(),
        QueryStatus::Unsupported
    );
    assert_eq!(
        AttrObservation::scalar(CKA_CLASS | (1 << 32), 8, 4, l).status(),
        QueryStatus::Excluded
    );
    assert_eq!(
        AttrObservation::scalar(CKA_ID, 8, 4, l).status(),
        QueryStatus::Excluded
    );
    assert_eq!(
        AttrObservation::scalar(CKA_TOKEN, 1, 2, l).status(),
        QueryStatus::Unsupported
    );
    assert_eq!(
        AttrObservation::scalar(CKA_EC_PARAMS, 8, 1, l).status(),
        QueryStatus::Malformed
    );
    let mut altered = SECP256R1;
    altered[9] = 0x08;
    assert_eq!(
        AttrObservation::curve(CKA_EC_PARAMS, &altered, l).status(),
        QueryStatus::Unsupported
    );
    assert_eq!(
        AttrObservation::curve(CKA_EC_PARAMS, &SECP256R1[..9], l).status(),
        QueryStatus::Malformed
    );
    // Unsupported results establish nothing on a view.
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let seen = h.run(
        3,
        get_attrs(SA, H1),
        4,
        ok().attrs(attrs(&[
            AttrObservation::scalar(CKA_CLASS, 8, 0x8000_0000, l),
            AttrObservation::scalar(CKA_ID, 8, 4, l),
        ])),
    );
    let e = h.settle(4);
    let v = view(&h.project(), sole(first_observed(&e, seen))).clone();
    assert_eq!(
        v.established.field(SafeAttributeKind::Class),
        FieldState::Unknown
    );
    assert_eq!(v.queries[0], QueryStatus::Unsupported);
}

// ---------------------------------------------------------------------------
// bounded_state_and_redaction
// ---------------------------------------------------------------------------

#[test]
fn s2s3_bounded_state_and_redaction_policy_limits() {
    let l = ObjectLimits::policy();
    assert_eq!(l.live_sessions_per_instance, 1_024);
    assert_eq!(l.views_per_instance, 4_096);
    assert_eq!(l.instances, 4_096);
    assert_eq!(l.session_records, 16_384);
    assert_eq!(l.object_records, 65_536);
    assert_eq!(l.pending_calls, 1_024);
    assert_eq!(MAX_ACCESS_RELATIONS, 32, "v3 relation ceiling preserved");
}

#[test]
fn s2s3_bounded_state_and_redaction_one_session_relation_invariant() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    h.run(5, create(SA), 6, ok().result(0, H1));
    h.run(7, get_size(SB, H1), 8, ok());
    h.run(9, get_size(SA, H1), 10, ok());
    h.run(11, call("C_FindObjects").on(SB), 12, ok().found(&[H1, H2]));
    h.run(13, destroy(SB, H2), 14, ok());
    h.settle(14);
    let p = h.project();
    assert_eq!(p.objects.len(), 3, "equal handles stay per-session views");
    for v in &p.objects {
        let expected = usize::from(v.lifetime == Lifetime::Live);
        assert_eq!(
            v.accessing_sessions, expected,
            "relations are counted from live bindings: one proven session, none once ended"
        );
        assert!(v.accessing_sessions <= MAX_ACCESS_RELATIONS);
    }
    assert!(p.objects.iter().any(|v| v.accessing_sessions == 0));
}

fn small_limits() -> ObjectLimits {
    ObjectLimits {
        live_sessions_per_instance: 2,
        views_per_instance: 3,
        instances: 2,
        session_records: 3,
        object_records: 4,
        pending_calls: 8,
        ..ObjectLimits::policy()
    }
}

#[test]
fn s2s3_bounded_state_and_redaction_live_sessions_n_and_n_plus_one() {
    let mut h = Hist::with_limits(small_limits());
    let a = h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let b = h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    let c = h.run(5, open_in(slot(SLOT1)), 6, ok().session_out(SC));
    let x = h.run(7, create(SC), 8, ok().result(0, H1));
    let e = h.settle(8);
    assert!(
        opened(&e, a).is_some() && opened(&e, b).is_some(),
        "N sessions admitted"
    );
    assert_eq!(opened(&e, c), None, "N+1 live session refused");
    assert_eq!(
        created(&e, x, 0),
        None,
        "calls on a refused session cannot join"
    );
    assert!(h.project().gap(ObjectGap::SessionCapacity) >= 1);
    // Closing one releases live occupancy; records stay counted.
    h.run(9, close(SA), 10, ok());
    let d = h.run(11, open_in(slot(SLOT1)), 12, ok().session_out(SD));
    let e = h.settle(12);
    assert!(
        opened(&e, d).is_some(),
        "third record fits the record budget"
    );
    let d_id = opened(&e, d).unwrap();
    // Ended, settled, unreferenced records are pruned under record pressure
    // (the caps bound occupancy, not lifetime); IDs are never reused.
    h.run(13, close(SB), 14, ok());
    let f = h.run(15, open_in(slot(SLOT1)), 16, ok().session_out(SA));
    let e = h.settle(16);
    let fresh = opened(&e, f).expect("a pruned ended record releases the budget");
    assert!(fresh > d_id, "session IDs are never reused after pruning");
    assert!(h.project().usage.session_records <= 3);
    assert!(h.project().usage.pruned_sessions >= 1);
    // With every record live, capture-wide N+1 is still refused.
    let other = h.add_domain(ObjectDomain::reference(1, 1, 1, 2, 1), true);
    h.run_in(other, 1, open_in(slot(SLOT1)), 2, ok().session_out(SB));
    let g = h.run_in(other, 3, open_in(slot(SLOT1)), 4, ok().session_out(SC));
    let e = h.settle_in(other, 4);
    assert_eq!(
        opened(&e, g),
        None,
        "capture-wide session records at N=3 refuse N+1"
    );
    assert_eq!(h.project().usage.session_records, 3);
}

#[test]
fn s2s3_bounded_state_and_redaction_object_views_and_records() {
    let mut h = Hist::with_limits(small_limits());
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let made: Vec<CallToken> = [H1, H2, H3, H4]
        .iter()
        .enumerate()
        .map(|(i, raw)| {
            let b = 3 + 2 * i as u64;
            h.run(b, create(SA), b + 1, ok().result(0, *raw))
        })
        .collect();
    let e = h.settle(10);
    let ids: Vec<Option<ObjectId>> = made.iter().map(|t| created(&e, *t, 0)).collect();
    assert!(ids[..3].iter().all(Option::is_some), "N views per instance");
    assert_eq!(ids[3], None, "N+1 view refused, not evicted");
    assert_eq!(h.project().gap(ObjectGap::ObjectCapacity), 1);
    assert_eq!(h.project().objects.len(), 3);

    // A second instance shares the capture-wide record budget (4).
    let other = h.add_domain(ObjectDomain::reference(1, 1, 1, 2, 1), true);
    h.run_in(other, 1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let x = h.run_in(other, 3, create(SA), 4, ok().result(0, H5));
    let y = h.run_in(other, 5, create(SA), 6, ok().result(0, H6));
    let e = h.settle_in(other, 6);
    assert!(created(&e, x, 0).is_some());
    assert_eq!(created(&e, y, 0), None, "capture-wide N+1 refused");
    assert_eq!(h.project().usage.object_records, 4);
    // Positive history survived every refusal.
    let p = h.project();
    for id in ids[..3].iter().flatten() {
        assert_eq!(view(&p, *id).lifetime, Lifetime::Live);
    }
}

#[test]
fn s2s3_bounded_state_and_redaction_instances_and_ids() {
    let mut h = Hist::with_limits(small_limits());
    let second = h.add_domain(ObjectDomain::reference(1, 1, 1, 2, 1), true);
    let third = h.add_domain(ObjectDomain::reference(1, 1, 1, 3, 1), true);
    assert!(h.try_begin_in(0, 1, get_size(SA, H1)).is_ok());
    assert!(h.try_begin_in(second, 1, get_size(SA, H1)).is_ok());
    assert_eq!(
        h.try_begin_in(third, 1, get_size(SA, H1)),
        Err(ObjectGap::UnknownDomain),
        "an unregistered (refused) domain admits no fact"
    );
    assert!(h.project().gap(ObjectGap::InstanceCapacity) >= 1);
    assert_eq!(h.project().usage.domains, 2);

    let limits = ObjectLimits {
        max_object_id: 2,
        max_call_token: 4,
        ..ObjectLimits::policy()
    };
    let mut h = Hist::with_limits(limits);
    let a = h.run(1, create(SA), 2, ok().result(0, H1));
    let b = h.run(3, create(SA), 4, ok().result(0, H2));
    let c = h.run(5, create(SA), 6, ok().result(0, H3));
    let e = h.settle(6);
    assert!(created(&e, a, 0).is_some() && created(&e, b, 0).is_some());
    assert_eq!(
        created(&e, c, 0),
        None,
        "object ID exhaustion refuses, never wraps"
    );
    assert!(h.project().gap(ObjectGap::IdExhausted) >= 1);
    assert!(h.try_begin_in(0, 7, get_size(SA, H1)).is_ok());
    assert_eq!(
        h.try_begin_in(0, 9, get_size(SA, H1)),
        Err(ObjectGap::IdExhausted),
        "call tokens are checked and never recycled"
    );
}

#[test]
fn s2s3_bounded_state_and_redaction_cut_exhaustion() {
    let mut h = Hist::qualified();
    let x = h.run(1, create(SA), 2, ok().result(0, H1));
    let top = CompleteInputPrefix::reference(
        base_domain(),
        RefCut::reference(u64::MAX),
        &[],
        Some(RefCut::reference(0)),
    );
    let effects = h.model.settle(top);
    let id = created(&effects, x, 0).expect("published before exhaustion");
    assert_eq!(
        h.try_begin_in(0, u64::MAX, get_size(SA, H1)),
        Err(ObjectGap::ClosedFrontier),
        "no cut follows the maximum frontier"
    );
    assert_eq!(
        view(&h.project(), id).attribution,
        Attribution::Downgraded(ObjectGap::ClosedFrontier),
        "an unrepresentable call costs coverage"
    );
}

fn scale_origin(
    domain: ObjectDomain,
    cut: u64,
    function: &str,
    session: u64,
    input: Option<u64>,
) -> OriginFact {
    OriginFact {
        domain,
        cut: RefCut::reference(cut),
        key: CallKey::reference(cut),
        entry_ns: cut,
        function: fid(function),
        session: HandleInput::Value(sess(session)),
        inputs: [
            input.map_or(HandleInput::Absent, |raw| HandleInput::Value(obj(raw))),
            HandleInput::Absent,
        ],
        requested: [None, None],
        entry_mechanism: MechanismEvidence::NotCaptured,
        scope: SlotScope::Unknown,
    }
}

fn scale_created(cut: u64, raw: u64) -> CompletedFact {
    CompletedFact {
        cut: RefCut::reference(cut),
        end_ns: cut,
        rv: CkRv::OK.0,
        return_mechanism: MechanismEvidence::NotCaptured,
        results: [ResultSlot::Handle(obj(raw)), ResultSlot::NotCaptured],
        session_out: HandleInput::Absent,
        found: FindResult::NotCaptured,
        attributes: None,
    }
}

fn count_created(effects: &ObjectEffects) -> usize {
    effects
        .effects
        .iter()
        .filter(|e| matches!(e, ObjectEffect::Created { .. }))
        .count()
}

#[test]
fn s2s3_bounded_state_and_redaction_policy_scale_n_and_n_plus_one() {
    // Policy-scale bounds: 4,096 views per instance across 16 instances
    // reach the capture-wide 65,536 object records; then N+1 per instance,
    // capture-wide and for the 1,024-call pending budget.
    let mut model = ObjectSemantics::new();
    let rss_before = crate::discovery::inventory_workload::rss_bytes();
    let mut created_total = 0usize;
    let mut last_cut = BTreeMap::new();
    for instance in 0..16u64 {
        let domain = ObjectDomain::reference(1, 1, 1, 100 + instance, 1);
        model.register_domain(domain).unwrap();
        let mut cut = 0u64;
        let mut bootstrap = Some(RefCut::reference(0));
        let mut raw = 0u64;
        for session in 0..4u64 {
            for _ in 0..1_024 {
                raw += 1;
                cut += 1;
                let token = model
                    .begin(scale_origin(
                        domain,
                        cut,
                        "C_CreateObject",
                        0x6600 + session,
                        None,
                    ))
                    .expect("within pending budget");
                cut += 1;
                model.complete(token, scale_created(cut, 0x9000_0000 + raw));
                if raw.is_multiple_of(64) {
                    let prefix = CompleteInputPrefix::reference(
                        domain,
                        RefCut::reference(cut),
                        &[],
                        bootstrap.take(),
                    );
                    created_total += count_created(&model.settle(prefix));
                }
            }
        }
        last_cut.insert(instance, cut);
        let usage = model.project().usage;
        assert_eq!(usage.pending_calls, 0);
        assert_eq!(usage.object_records, ((instance + 1) * 4_096) as usize);
    }
    assert_eq!(created_total, 65_536, "N capture-wide object records");
    let usage = model.project().usage;
    assert_eq!(usage.object_records, 65_536);
    assert_eq!(usage.live_sessions, 64);
    let rss_full = crate::discovery::inventory_workload::rss_bytes();

    // Per-instance N+1 (instance 0 already holds 4,096 views).
    let domain = ObjectDomain::reference(1, 1, 1, 100, 1);
    let cut = last_cut[&0];
    let token = model
        .begin(scale_origin(
            domain,
            cut + 1,
            "C_CreateObject",
            0x6600,
            None,
        ))
        .unwrap();
    model.complete(token, scale_created(cut + 2, 0x9100_0001));
    let effects = model.settle(CompleteInputPrefix::reference(
        domain,
        RefCut::reference(cut + 2),
        &[],
        None,
    ));
    assert_eq!(count_created(&effects), 0, "per-instance N+1 refused");

    // Capture-wide N+1 in a fresh instance.
    let domain = ObjectDomain::reference(1, 1, 1, 999, 1);
    model.register_domain(domain).unwrap();
    let token = model
        .begin(scale_origin(domain, 1, "C_CreateObject", 0x6600, None))
        .unwrap();
    model.complete(token, scale_created(2, 0x9999_0001));
    let effects = model.settle(CompleteInputPrefix::reference(
        domain,
        RefCut::reference(2),
        &[],
        Some(RefCut::reference(0)),
    ));
    assert_eq!(count_created(&effects), 0, "capture-wide N+1 refused");
    assert_eq!(model.project().usage.object_records, 65_536);
    assert!(model.project().gap(ObjectGap::ObjectCapacity) >= 2);

    // Pending N/N+1 at policy scale.
    let domain = ObjectDomain::reference(1, 1, 1, 998, 1);
    model.register_domain(domain).unwrap();
    for cut in 1..=1_024u64 {
        model
            .begin(scale_origin(
                domain,
                cut,
                "C_GetObjectSize",
                0x6600,
                Some(0x9000_0001),
            ))
            .expect("N pending");
    }
    assert_eq!(model.project().usage.pending_calls, 1_024);
    assert_eq!(
        model.begin(scale_origin(
            domain,
            1_025,
            "C_GetObjectSize",
            0x6600,
            Some(0x9000_0001)
        )),
        Err(ObjectGap::PendingCapacity)
    );
    let rss_after = crate::discovery::inventory_workload::rss_bytes();
    let estimate = model.state_estimate();
    eprintln!(
        "s2s3 policy-scale state: measured RSS delta {} bytes after 65,536 records \
         ({} bytes after +1,024 pending); estimated occupied {} bytes \
         (object records {}, session records {}, bindings {}, pending {}); \
         the estimate is size_of*len, not allocator evidence",
        rss_full.saturating_sub(rss_before),
        rss_after.saturating_sub(rss_before),
        estimate.occupied_bytes,
        estimate.object_records,
        estimate.session_records,
        estimate.live_bindings,
        estimate.pending_calls,
    );
}

/// Every textual form that would reveal one private word.
fn leaked_forms(word: u64) -> Vec<String> {
    vec![
        format!("{word}"),
        format!("{word:x}"),
        format!("{word:X}"),
        format!("{word:#x}"),
    ]
}

fn assert_no_leak(text: &str, words: &[u64]) {
    for word in words {
        for form in leaked_forms(*word) {
            assert!(
                !text.contains(&form),
                "private word leaked into formatted output"
            );
        }
    }
}

#[test]
fn s2s3_bounded_state_and_redaction_sentinel_canaries() {
    let private = [
        SA,
        SB,
        H1,
        H2,
        PHKEY_SENTINEL,
        0xC0FF_EE01,
        0xC0FF_EE02,
        0xC0FF_EE03,
    ];
    let domain = ObjectDomain::reference(0xC0FF_EE01, 0xC0FF_EE02, 0xC0FF_EE03, 1, 1);
    let mut h = Hist::qualified();
    let dom = h.add_domain(domain, true);
    h.run_in(
        dom,
        1,
        open_in(SlotScope::reference_known(0xC0FF_EE02, 7)),
        2,
        ok().session_out(SA),
    );
    h.run_in(dom, 3, create(SA), 4, ok().result(0, H1));
    h.run_in(
        dom,
        5,
        call("C_DeriveKey")
            .on(SA)
            .input(0, H1)
            .mech(MechanismEvidence::Value(SSL3_KEY_MATERIAL)),
        6,
        ok().result(0, PHKEY_SENTINEL),
    );
    h.run_in(
        dom,
        7,
        call("C_GenerateKeyPair").on(SA),
        8,
        ok().result(0, H2).result(1, H2),
    );
    h.run_in(
        dom,
        9,
        get_size(SB, H2),
        10,
        rv(CkRv::SESSION_HANDLE_INVALID),
    );
    let dup = h.try_begin_in(dom, 9, get_size(SB, H2));
    let mut text = String::new();
    text.push_str(&format!("{dup:?}"));
    let effects = h.settle_in(dom, 10);
    let invalidated = h
        .model
        .invalidate(AffectedScope::Session(domain, sess(SA)), ObjectGap::Loss);
    let projection = h.project();
    let origin = h.origin(dom, 11, &get_size(SA, H1).input(1, H2));
    let fact = CompletedFact {
        cut: RefCut::reference(12),
        end_ns: 1,
        rv: 0,
        return_mechanism: MechanismEvidence::NotCaptured,
        results: [
            ResultSlot::Handle(obj(H1)),
            ResultSlot::Handle(obj(PHKEY_SENTINEL)),
        ],
        session_out: HandleInput::Value(sess(SB)),
        found: FindResult::handles(&[obj(H1), obj(H2)]),
        attributes: None,
    };
    for form in [
        format!("{effects:?}"),
        format!("{effects:#?}"),
        format!("{invalidated:?}"),
        format!("{projection:?}"),
        format!("{projection:#?}"),
        format!("{projection:x?}"),
        format!("{:?}", h.model),
        format!("{:#?}", h.model),
        format!("{origin:?}"),
        format!("{fact:?}"),
        format!("{:?}", AffectedScope::Session(domain, sess(SB))),
        format!(
            "{:?}",
            CompleteInputPrefix::reference(
                domain,
                RefCut::reference(0xC0FF_EE03),
                &[CallKey::reference(0xC0FF_EE03)],
                None
            )
        ),
    ] {
        text.push_str(&form);
    }
    assert_no_leak(&text, &private);
    assert!(text.contains("object#"), "public IDs remain visible");
}

// ---------------------------------------------------------------------------
// Review regressions (Task 2 review round 1). Each trace is the reviewer's.
// ---------------------------------------------------------------------------

/// C1: a proof void must reject snapshots whose begin was already applied.
#[test]
fn s2s3_lifecycle_loss_and_prefix_contradiction_void_rejects_applied_snapshots() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let c1 = h.begin(3, call("C_FindObjects").on(SB));
    let c0 = h.begin(4, create(SA));
    h.done(c1, 5, ok().found(&[H1]));
    h.settle(5);
    h.model.invalidate(
        AffectedScope::Session(base_domain(), sess(SA)),
        ObjectGap::Loss,
    );
    h.run(6, close(SB), 7, ok());
    h.done(c0, 8, ok().result(0, H2));
    let e8 = h.settle(8);
    assert!(
        first_observed(&e8, c1).is_empty(),
        "a snapshot taken before the void cannot publish"
    );
    let p = h.project();
    assert!(p.objects.is_empty());
    assert!(p.sessions.iter().all(|s| s.state != SessionState::Live));
    h.rebootstrap(0, 9);
    let g = h.run(10, get_size(SB, H1), 11, ok());
    let e11 = h.settle(11);
    let v = sole(first_observed(&e11, g));
    let p = h.project();
    assert_eq!(p.objects.len(), 1, "no view survives from the voided era");
    assert_eq!(view(&p, v).references, 1);
    assert_eq!(
        p.session(view(&p, v).session).unwrap().origin,
        SessionOrigin::FirstObserved
    );
}

/// C2: boundary calls on an unknown/unreadable session widen uncertainty.
fn unknown_session_boundary(boundary: Call, done: Done) -> Lifetime {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let seen = h.run(3, get_size(SA, H1), 4, ok());
    h.run(5, boundary, 6, done);
    let e = h.settle(6);
    let id = sole(first_observed(&e, seen));
    view(&h.project(), id).lifetime
}

#[test]
fn s2s3_destroy_other_session_scope_unknown_session_boundaries_widen() {
    let unreadable = |c: Call| {
        let mut c = c;
        c.session = HandleInput::Unreadable;
        c
    };
    for (label, boundary, done) in [
        (
            "destroy GENERAL_ERROR",
            destroy(SB, H1),
            rv(CkRv::GENERAL_ERROR),
        ),
        (
            "destroy DEVICE_REMOVED",
            destroy(SB, H1),
            rv(CkRv::DEVICE_REMOVED),
        ),
        ("destroy PENDING", destroy(SB, H1), rv(CkRv::PENDING)),
        ("close GENERAL_ERROR", close(SB), rv(CkRv::GENERAL_ERROR)),
        ("close DEVICE_REMOVED", close(SB), rv(CkRv::DEVICE_REMOVED)),
        ("logout PENDING", call("C_Logout").on(SB), rv(CkRv::PENDING)),
        ("unreadable-session close", unreadable(close(SB)), ok()),
        (
            "unreadable-session destroy",
            unreadable(destroy(SB, H1)),
            ok(),
        ),
    ] {
        assert!(
            matches!(
                unknown_session_boundary(boundary, done),
                Lifetime::Retired(_)
            ),
            "{label}: possibly affected compatible views become uncertain"
        );
    }
    assert_eq!(
        unknown_session_boundary(destroy(SB, H1), rv(CkRv::FUNCTION_FAILED)),
        Lifetime::Live,
        "an ordinary failure stays a no-effect control"
    );
}

/// I1: removal/corruption return values on ordinary calls.
fn i1_case(code: CkRv) -> (ObjectProjection, ObjectId, ObjectId, ObjectId) {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    h.run(5, open_in(slot(SLOT2)), 6, ok().session_out(SC));
    let a = h.run(7, get_size(SA, H1), 8, ok());
    let b = h.run(9, get_size(SB, H2), 10, ok());
    let c = h.run(11, get_size(SC, H3), 12, ok());
    h.run(13, sign_init(SA, H1), 14, rv(code));
    let e = h.settle(14);
    let ids = (
        sole(first_observed(&e, a)),
        sole(first_observed(&e, b)),
        sole(first_observed(&e, c)),
    );
    (h.project(), ids.0, ids.1, ids.2)
}

#[test]
fn s2s3_lifecycle_loss_and_prefix_contradiction_removal_return_values() {
    for code in [
        CkRv::DEVICE_REMOVED,
        CkRv::TOKEN_NOT_PRESENT,
        CkRv::DEVICE_ERROR,
    ] {
        let (p, a, b, c) = i1_case(code);
        assert_eq!(
            view(&p, a).lifetime,
            Lifetime::Retired(ObjectGap::DeviceLoss)
        );
        assert_eq!(
            view(&p, b).lifetime,
            Lifetime::Retired(ObjectGap::DeviceLoss)
        );
        assert_eq!(view(&p, c).lifetime, Lifetime::Live, "proven other slot");
        assert_eq!(
            p.session(view(&p, a).session).unwrap().state,
            SessionState::Ended(ObjectGap::DeviceLoss)
        );
        assert_eq!(
            p.session(view(&p, c).session).unwrap().state,
            SessionState::Live
        );
    }
    let (p, a, b, c) = i1_case(CkRv::GENERAL_ERROR);
    assert_eq!(
        view(&p, a).lifetime,
        Lifetime::Retired(ObjectGap::AmbiguousOutcome)
    );
    assert_eq!(
        view(&p, b).lifetime,
        Lifetime::Retired(ObjectGap::AmbiguousOutcome)
    );
    assert_eq!(view(&p, c).lifetime, Lifetime::Live);
    let (p, a, _, c) = i1_case(CkRv::CRYPTOKI_NOT_INITIALIZED);
    assert_eq!(
        view(&p, a).attribution,
        Attribution::Downgraded(ObjectGap::UnseenFinalize),
        "an unseen finalize contradicts the domain's proof"
    );
    assert!(matches!(view(&p, c).lifetime, Lifetime::Retired(_)));
}

/// I3: unrepresentable begins void proof; exact duplicates stay no-ops.
#[test]
fn s2s3_stale_origin_and_dependency_fences_unrepresentable_begin_voids_proof() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let x = h.run(3, create(SA), 4, ok().result(0, H1));
    let id = created(&h.settle(4), x, 0).unwrap();
    let _pending = h.begin(5, get_size(SA, H1));
    assert_eq!(
        h.try_begin_in(0, 5, get_size(SA, H1)),
        Err(ObjectGap::DuplicateCall)
    );
    assert_eq!(
        view(&h.project(), id).attribution,
        Attribution::Valid,
        "an exact duplicate of an admitted key is a no-op"
    );
    let mut colliding = h.origin(0, 5, &get_size(SA, H1));
    colliding.key = CallKey::reference(99);
    assert_eq!(h.model.begin(colliding), Err(ObjectGap::MalformedFact));
    assert_eq!(
        view(&h.project(), id).attribution,
        Attribution::Downgraded(ObjectGap::MalformedFact)
    );

    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let x = h.run(3, create(SA), 4, ok().result(0, H1));
    let id = created(&h.settle(4), x, 0).unwrap();
    let mut late = h.origin(0, 2, &get_size(SA, H1));
    late.key = CallKey::reference(77);
    assert_eq!(h.model.begin(late), Err(ObjectGap::ClosedFrontier));
    let p = h.project();
    assert_eq!(
        view(&p, id).attribution,
        Attribution::Downgraded(ObjectGap::ClosedFrontier)
    );
    assert_eq!(
        view(&p, id).lifetime,
        Lifetime::Retired(ObjectGap::ClosedFrontier)
    );
}

/// I4: a tombstone that cannot be stored ends the session; a cleared
/// tombstone's charge is not refunded before its clearing settles.
#[test]
fn s2s3_bounded_state_and_redaction_tombstone_capacity() {
    let full = ObjectLimits {
        views_per_instance: 1,
        ..ObjectLimits::policy()
    };
    let mut h = Hist::with_limits(full);
    let open = h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, create(SA), 4, ok().result(0, H1));
    h.run(
        5,
        call("C_GenerateKeyPair").on(SA),
        6,
        ok().result(0, H3).result(1, H3),
    );
    let e = h.settle(6);
    let session = opened(&e, open).unwrap();
    assert_eq!(
        h.project().session(session).unwrap().state,
        SessionState::Ended(ObjectGap::ObjectCapacity),
        "an unstorable fence ends the affected session"
    );

    let two = ObjectLimits {
        views_per_instance: 2,
        ..ObjectLimits::policy()
    };
    let mut h = Hist::with_limits(two);
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, create(SA), 4, ok().result(0, H1));
    h.run(
        5,
        call("C_GenerateKeyPair").on(SA),
        6,
        ok().result(0, H3).result(1, H3),
    );
    h.run(7, destroy(SA, H3), 8, ok());
    let found = h.run(9, call("C_FindObjects").on(SA), 10, ok().found(&[H4]));
    let e = h.settle(10);
    assert!(
        first_observed(&e, found).is_empty(),
        "a tombstone cleared in this replay is not refunded before its clearing settles"
    );
    assert_eq!(unresolved(&e, found), Some(ObjectGap::ObjectCapacity));
}

/// I5: an invalid-handle return ends only the argument it names.
#[test]
fn s2s3_destroy_other_session_scope_invalid_handle_names_its_argument() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let mut k = Vec::new();
    for (b, raw) in [(3, H1), (5, H2), (7, H3), (9, H4), (11, H5), (13, H6)] {
        k.push(h.run(b, call("C_GenerateKey").on(SA), b + 1, ok().result(0, raw)));
    }
    let wrap = |w: u64, key: u64| call("C_WrapKey").on(SA).input(0, w).input(1, key);
    h.run(15, wrap(H1, H2), 16, rv(CkRv::KEY_HANDLE_INVALID));
    h.run(
        17,
        call("C_SetOperationState").on(SA).input(0, H3).input(1, H4),
        18,
        rv(CkRv::KEY_HANDLE_INVALID),
    );
    h.run(19, wrap(H5, H6), 20, rv(CkRv::WRAPPING_KEY_HANDLE_INVALID));
    let e = h.settle(20);
    let p = h.project();
    let life = |i: usize| view(&p, created(&e, k[i], 0).unwrap()).lifetime;
    assert_eq!(
        life(0),
        Lifetime::Live,
        "the valid wrapping key keeps access"
    );
    assert_eq!(life(1), Lifetime::AccessEnded(ObjectGap::InvalidHandle));
    assert_eq!(
        life(2),
        Lifetime::Retired(ObjectGap::InvalidHandle),
        "ambiguous input"
    );
    assert_eq!(
        life(3),
        Lifetime::Retired(ObjectGap::InvalidHandle),
        "ambiguous input"
    );
    assert_eq!(life(4), Lifetime::AccessEnded(ObjectGap::InvalidHandle));
    assert_eq!(life(5), Lifetime::Live);
}

/// M5: session-ID exhaustion refuses, never wraps.
#[test]
fn s2s3_bounded_state_and_redaction_session_id_exhaustion() {
    let limits = ObjectLimits {
        max_session_id: 1,
        ..ObjectLimits::policy()
    };
    let mut h = Hist::with_limits(limits);
    let a = h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let b = h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    let e = h.settle(4);
    assert!(opened(&e, a).is_some());
    assert_eq!(opened(&e, b), None);
    assert_eq!(unresolved(&e, b), Some(ObjectGap::IdExhausted));
    assert_eq!(h.project().sessions.len(), 1);
}

/// M6: null-mechanism cancellation from entry evidence; inconsistent
/// entry/return evidence makes no key association.
#[test]
fn s2s3_null_mechanism_init_cancel_entry_evidence_and_inconsistency() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let entry_only = h.run(3, sign_init(SA, H2).mech(MechanismEvidence::Null), 4, ok());
    let null_then_value = h.run(
        5,
        sign_init(SA, H3).mech(MechanismEvidence::Null),
        6,
        ok().mech(MechanismEvidence::Value(ECDSA)),
    );
    let value_then_null = h.run(
        7,
        sign_init(SA, H4).mech(MechanismEvidence::Value(ECDSA)),
        8,
        ok().mech(MechanismEvidence::Null),
    );
    let e = h.settle(8);
    for t in [entry_only, null_then_value, value_then_null] {
        assert!(first_observed(&e, t).is_empty(), "no key-B association");
    }
    let p = h.project();
    assert!(p.objects.is_empty());
    assert_eq!(p.gap(ObjectGap::NullMechanismCancel), 1);
    assert_eq!(p.gap(ObjectGap::InconsistentMechanism), 2);
}

/// M7: a refused begin is an in-flight fence; a lost terminal outcome with
/// an upper-bound cut releases fences so proof can resume.
#[test]
fn s2s3_stale_origin_and_dependency_fences_refused_begin_blocks_bootstrap() {
    let limits = ObjectLimits {
        pending_calls: 2,
        ..ObjectLimits::policy()
    };
    let mut h = Hist::with_limits(limits);
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let c = h.begin(3, create(SA));
    assert_eq!(
        h.try_begin_in(0, 5, get_size(SA, H9)),
        Err(ObjectGap::PendingCapacity)
    );
    h.done(c, 4, ok().result(0, H1));
    h.settle(4);
    h.rebootstrap(0, 6);
    h.settle(6);
    let early = h.run(7, create(SA), 8, ok().result(0, H2));
    let e = h.settle(8);
    assert_eq!(
        created(&e, early, 0),
        None,
        "the refused call may still be running"
    );
    h.model
        .outcome_lost(LostOutcome::Refused(base_domain(), RefCut::reference(9)));
    h.rebootstrap(0, 10);
    h.settle(10);
    let later = h.run(11, create(SA), 12, ok().result(0, H3));
    let e = h.settle(12);
    assert!(
        created(&e, later, 0).is_some(),
        "proof resumes above the bound"
    );

    // A begin refused by contradiction is also a real call that may still
    // be running: ClosedFrontier (a new key at or below the frontier).
    let mut late = h.origin(0, 3, &get_size(SA, H9));
    late.key = CallKey::reference(1_003);
    assert_eq!(h.model.begin(late), Err(ObjectGap::ClosedFrontier));
    h.rebootstrap(0, 13);
    h.settle(13);
    let blocked = h.run(14, create(SA), 15, ok().result(0, H4));
    let e = h.settle(15);
    assert_eq!(
        created(&e, blocked, 0),
        None,
        "a ClosedFrontier begin may still be running"
    );
    h.model
        .outcome_lost(LostOutcome::Refused(base_domain(), RefCut::reference(16)));
    h.rebootstrap(0, 17);
    h.settle(17);
    let resumed = h.run(18, create(SA), 19, ok().result(0, H5));
    let e = h.settle(19);
    assert!(created(&e, resumed, 0).is_some(), "bounded, proof resumes");

    // MalformedFact: a new key colliding with an occupied cut.
    let occupant = h.begin(20, get_size(SA, H9));
    let mut clash = h.origin(0, 20, &get_size(SA, H9));
    clash.key = CallKey::reference(1_020);
    assert_eq!(h.model.begin(clash), Err(ObjectGap::MalformedFact));
    h.done(occupant, 21, ok());
    h.rebootstrap(0, 22);
    h.settle(22);
    let blocked = h.run(23, create(SA), 24, ok().result(0, H6));
    let e = h.settle(24);
    assert_eq!(
        created(&e, blocked, 0),
        None,
        "a colliding begin may still be running"
    );
    h.model
        .outcome_lost(LostOutcome::Refused(base_domain(), RefCut::reference(25)));
    h.rebootstrap(0, 26);
    h.settle(26);
    let resumed = h.run(27, create(SA), 28, ok().result(0, H7));
    let e = h.settle(28);
    assert!(created(&e, resumed, 0).is_some(), "bounded, proof resumes");
}

#[test]
fn s2s3_stale_origin_and_dependency_fences_lost_outcome_releases_ticket() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let stuck = h.begin(3, create(SA));
    h.model.invalidate(
        AffectedScope::Session(base_domain(), sess(SA)),
        ObjectGap::Loss,
    );
    h.rebootstrap(0, 4);
    let refused = h.settle(4);
    assert!(refused.effects.contains(&ObjectEffect::Gap {
        reason: ObjectGap::BootstrapRefused
    }));
    h.model
        .outcome_lost(LostOutcome::Ticket(stuck, RefCut::reference(5)));
    for (_, completion) in h.domains[0].1.calls.values_mut() {
        if completion.is_none() {
            *completion = Some(5);
        }
    }
    assert_eq!(
        h.project().usage.pending_calls,
        0,
        "the pending slot is freed"
    );
    h.rebootstrap(0, 6);
    let x = h.run(7, create(SA), 8, ok().result(0, H1));
    let e = h.settle(8);
    assert!(created(&e, x, 0).is_some());
    assert!(h.project().gap(ObjectGap::OutcomeLost) >= 1);
}

// ---------------------------------------------------------------------------
// Review round 2 regressions.
// ---------------------------------------------------------------------------

/// Minor 1: the proof generation never wraps; exhaustion ends the domain.
#[test]
fn s2s3_bounded_state_and_redaction_proof_generation_never_wraps() {
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.settle(2);
    h.model.exhaust_generation(base_domain());
    h.model
        .invalidate(AffectedScope::Domain(base_domain()), ObjectGap::Loss);
    assert_eq!(
        h.try_begin_in(0, 3, create(SA)),
        Err(ObjectGap::DomainEnded),
        "an exhausted proof generation ends the domain instead of wrapping"
    );
    assert!(h.project().gap(ObjectGap::IdExhausted) >= 1);
}

/// Minor 2: a lost-outcome bound below the ticket's own cuts is malformed.
#[test]
fn s2s3_stale_origin_and_dependency_fences_lost_outcome_bound_is_validated() {
    let malformed = |e: &ObjectEffects| {
        e.effects.contains(&ObjectEffect::Gap {
            reason: ObjectGap::MalformedFact,
        })
    };
    let mut h = Hist::qualified();
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let open = h.begin(5, create(SA));
    let before = h.project().usage.pending_calls;
    let e = h
        .model
        .outcome_lost(LostOutcome::Ticket(open, RefCut::reference(4)));
    assert!(malformed(&e), "a bound below the begin is rejected");
    assert_eq!(h.project().usage.pending_calls, before, "ticket kept");
    let done = h.begin(7, create(SA));
    h.done(done, 9, ok().result(0, H2));
    let e = h
        .model
        .outcome_lost(LostOutcome::Ticket(done, RefCut::reference(8)));
    assert!(malformed(&e), "a bound below the completion is rejected");
    assert_eq!(h.project().usage.pending_calls, before + 1, "ticket kept");
    let e = h
        .model
        .outcome_lost(LostOutcome::Ticket(open, RefCut::reference(10)));
    assert!(!malformed(&e));
    assert_eq!(h.project().usage.pending_calls, before, "released");
}

/// Minor 4: conservative return-value escalation applies even to an end
/// whose begin was unqualified (it straddles the bootstrap).
fn straddle(code: CkRv) -> (ObjectProjection, ObjectId) {
    let mut h = Hist::unqualified();
    let straddler = h.begin(1, sign_init(SB, H9));
    h.rebootstrap(0, 2);
    let seen = h.run(3, get_size(SA, H1), 4, ok());
    h.done(straddler, 5, rv(code));
    let e = h.settle(5);
    let id = sole(first_observed(&e, seen));
    (h.project(), id)
}

#[test]
fn s2s3_lifecycle_loss_and_prefix_contradiction_straddling_end_escalates() {
    let (p, id) = straddle(CkRv::DEVICE_REMOVED);
    assert_eq!(
        view(&p, id).lifetime,
        Lifetime::Retired(ObjectGap::DeviceLoss),
        "a straddling removal still ends the compatible scope"
    );
    assert_eq!(
        p.session(view(&p, id).session).unwrap().state,
        SessionState::Ended(ObjectGap::DeviceLoss)
    );
    let (p, id) = straddle(CkRv::GENERAL_ERROR);
    assert_eq!(
        view(&p, id).lifetime,
        Lifetime::Retired(ObjectGap::AmbiguousOutcome)
    );
    let (p, id) = straddle(CkRv::CRYPTOKI_NOT_INITIALIZED);
    assert_eq!(
        view(&p, id).attribution,
        Attribution::Downgraded(ObjectGap::UnseenFinalize)
    );
    let (p, id) = straddle(CkRv::FUNCTION_FAILED);
    assert_eq!(view(&p, id).lifetime, Lifetime::Live, "ordinary control");
}

/// Minor 3 / lifetime caps: create->destroy churn far beyond the caps keeps
/// publishing; occupancy stays bounded and IDs are never reused.
fn churn(limits: ObjectLimits, cycles: u64) -> (ObjectSemantics, Vec<ObjectId>, usize) {
    let domain = base_domain();
    let origin = |cut: u64,
                  function: &str,
                  session: HandleInput<SessionHandle>,
                  input: HandleInput<ObjectHandle>,
                  scope: SlotScope| OriginFact {
        domain,
        cut: RefCut::reference(cut),
        key: CallKey::reference(cut),
        entry_ns: cut,
        function: fid(function),
        session,
        inputs: [input, HandleInput::Absent],
        requested: [None, None],
        entry_mechanism: MechanismEvidence::NotCaptured,
        scope,
    };
    let completed =
        |cut: u64, result: ResultSlot, session_out: HandleInput<SessionHandle>| CompletedFact {
            cut: RefCut::reference(cut),
            end_ns: cut,
            rv: CkRv::OK.0,
            return_mechanism: MechanismEvidence::NotCaptured,
            results: [result, ResultSlot::NotCaptured],
            session_out,
            found: FindResult::NotCaptured,
            attributes: None,
        };
    let prefix = |cut: u64, bootstrap: Option<u64>| {
        CompleteInputPrefix::reference(
            domain,
            RefCut::reference(cut),
            &[],
            bootstrap.map(RefCut::reference),
        )
    };
    let sa = HandleInput::Value(sess(SA));
    let mut model = ObjectSemantics::with_limits(limits);
    model.register_domain(domain).unwrap();
    let open = model
        .begin(origin(
            1,
            "C_OpenSession",
            HandleInput::Absent,
            HandleInput::Absent,
            slot(SLOT1),
        ))
        .unwrap();
    model.complete(open, completed(2, ResultSlot::NotCaptured, sa));
    model.settle(prefix(2, Some(0)));
    let mut ids = Vec::new();
    let mut peak = 0;
    for i in 0..cycles {
        let b = 3 + 4 * i;
        let c = model
            .begin(origin(
                b,
                "C_CreateObject",
                sa,
                HandleInput::Absent,
                SlotScope::Unknown,
            ))
            .unwrap();
        model.complete(
            c,
            completed(b + 1, ResultSlot::Handle(obj(H1)), HandleInput::Absent),
        );
        let d = model
            .begin(origin(
                b + 2,
                "C_DestroyObject",
                sa,
                HandleInput::Value(obj(H1)),
                SlotScope::Unknown,
            ))
            .unwrap();
        model.complete(
            d,
            completed(b + 3, ResultSlot::NotCaptured, HandleInput::Absent),
        );
        let e = model.settle(prefix(b + 3, None));
        ids.push(created(&e, c, 0).expect("churn keeps publishing new IDs"));
        if i % 64 == 0 || i + 1 == cycles {
            let usage = model.project().usage;
            assert!(usage.object_records <= limits.views_per_instance);
            assert!(usage.object_records <= limits.object_records);
            peak = peak.max(usage.object_records);
        }
    }
    (model, ids, peak)
}

#[test]
fn s2s3_bounded_state_and_redaction_churn_prunes_settled_records() {
    let limits = ObjectLimits {
        views_per_instance: 4,
        object_records: 6,
        ..ObjectLimits::policy()
    };
    let (model, ids, peak) = churn(limits, 200);
    assert!(
        ids.windows(2).all(|w| w[0] < w[1]),
        "IDs never reused after pruning"
    );
    let usage = model.project().usage;
    assert_eq!(usage.lifetime_objects, 200);
    assert!(usage.pruned_objects >= 196);
    assert!(peak <= 4);
}

#[test]
fn s2s3_bounded_state_and_redaction_churn_at_policy_caps() {
    let (model, ids, peak) = churn(ObjectLimits::policy(), 10_000);
    assert!(ids.windows(2).all(|w| w[0] < w[1]));
    let usage = model.project().usage;
    assert_eq!(usage.lifetime_objects, 10_000);
    assert!(usage.object_records <= 4_096 && peak <= 4_096);
    assert!(usage.pruned_objects >= 10_000 - 4_096);
}

/// Pruning never removes a fence that can still be needed.
#[test]
fn s2s3_bounded_state_and_redaction_pruning_keeps_needed_fences() {
    // A live tombstone survives churn-driven pruning; its dependent still
    // gets DependencyBroken.
    let limits = ObjectLimits {
        views_per_instance: 4,
        object_records: 6,
        ..ObjectLimits::policy()
    };
    let mut h = Hist::with_limits(limits);
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(
        3,
        call("C_GenerateKeyPair").on(SA),
        4,
        ok().result(0, H3).result(1, H3),
    );
    h.settle(4);
    for i in 0..20 {
        let b = 5 + 4 * i;
        let c = h.run(b, create(SA), b + 1, ok().result(0, H1));
        h.run(b + 2, destroy(SA, H1), b + 3, ok());
        let e = h.settle(b + 3);
        assert!(created(&e, c, 0).is_some(), "churn keeps publishing");
    }
    let dep = h.run(85, get_size(SA, H3), 86, ok());
    let e = h.settle(86);
    assert!(first_observed(&e, dep).is_empty());
    assert_eq!(unresolved(&e, dep), Some(ObjectGap::DependencyBroken));
    assert_eq!(h.project().usage.tombstones, 1);

    // A retired view whose straddling ticket has not settled is not pruned,
    // even under capture-wide pressure from another domain.
    let limits = ObjectLimits {
        object_records: 2,
        ..ObjectLimits::policy()
    };
    let mut h = Hist::with_limits(limits);
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    h.run(3, open_in(slot(SLOT1)), 4, ok().session_out(SB));
    let a = h.run(5, create(SA), 6, ok().result(0, H1));
    let id1 = created(&h.settle(6), a, 0).unwrap();
    let x = h.begin(7, get_size(SA, H1));
    h.run(8, destroy(SB, H5), 9, ok());
    let y = h.begin(10, call("C_FindObjects").on(SB));
    h.done(x, 11, ok());
    h.settle(11);
    assert_eq!(
        view(&h.project(), id1).lifetime,
        Lifetime::Retired(ObjectGap::DestroyAlias)
    );
    let other = h.add_domain(ObjectDomain::reference(1, 1, 1, 2, 1), true);
    h.run_in(other, 1, open_in(slot(SLOT1)), 2, ok().session_out(SC));
    let p1 = h.run_in(other, 3, create(SC), 4, ok().result(0, H2));
    let e = h.settle_in(other, 4);
    assert_eq!(created(&e, p1, 0), None, "nothing prunable yet");
    assert!(
        h.project().objects.iter().any(|v| v.id == id1),
        "an unsettled straddler keeps the retired view"
    );
    h.done(y, 12, ok().found(&[]));
    let e = h.settle(12);
    assert!(unresolved(&e, x).is_some(), "the dependent never joins");
    let p2 = h.run_in(other, 5, create(SC), 6, ok().result(0, H2));
    let e = h.settle_in(other, 6);
    let fresh = created(&e, p2, 0).expect("settled records are now prunable");
    assert!(fresh > id1, "IDs never reused");
    assert!(h.project().objects.iter().all(|v| v.id != id1));
}

// ---------------------------------------------------------------------------
// Domain-record pruning (controller ruling: no lifetime domain cap).
// ---------------------------------------------------------------------------

fn churn_domain(n: u64) -> ObjectDomain {
    ObjectDomain::reference(1, 1, 1, 10_000 + n, 1)
}

/// One short-lived process: open, create, settle, then an exec boundary
/// ends the domain. Returns the created view.
fn short_lived(model: &mut ObjectSemantics, domain: ObjectDomain) -> Option<ObjectId> {
    let origin =
        |cut: u64, function: &str, session: HandleInput<SessionHandle>, scope| OriginFact {
            domain,
            cut: RefCut::reference(cut),
            key: CallKey::reference(cut),
            entry_ns: cut,
            function: fid(function),
            session,
            inputs: [HandleInput::Absent, HandleInput::Absent],
            requested: [None, None],
            entry_mechanism: MechanismEvidence::NotCaptured,
            scope,
        };
    let completed = |cut: u64, result: ResultSlot, session_out| CompletedFact {
        cut: RefCut::reference(cut),
        end_ns: cut,
        rv: CkRv::OK.0,
        return_mechanism: MechanismEvidence::NotCaptured,
        results: [result, ResultSlot::NotCaptured],
        session_out,
        found: FindResult::NotCaptured,
        attributes: None,
    };
    let sa = HandleInput::Value(sess(SA));
    let open = model
        .begin(origin(1, "C_OpenSession", HandleInput::Absent, slot(SLOT1)))
        .ok()?;
    model.complete(open, completed(2, ResultSlot::NotCaptured, sa));
    let create = model
        .begin(origin(3, "C_CreateObject", sa, SlotScope::Unknown))
        .ok()?;
    model.complete(
        create,
        completed(4, ResultSlot::Handle(obj(H1)), HandleInput::Absent),
    );
    let effects = model.settle(CompleteInputPrefix::reference(
        domain,
        RefCut::reference(4),
        &[],
        Some(RefCut::reference(0)),
    ));
    model.invalidate(AffectedScope::Domain(domain), ObjectGap::Exec);
    created(&effects, create, 0)
}

fn domain_churn(limits: ObjectLimits, domains: u64) -> (ObjectSemantics, Vec<ObjectId>) {
    let mut model = ObjectSemantics::with_limits(limits);
    let mut ids = Vec::new();
    for n in 0..domains {
        let domain = churn_domain(n);
        model
            .register_domain(domain)
            .expect("ended domains are reclaimed under the cap");
        ids.push(short_lived(&mut model, domain).expect("new domains keep working"));
        if n % 256 == 0 || n + 1 == domains {
            assert!(model.project().usage.domains <= limits.instances);
        }
    }
    (model, ids)
}

#[test]
fn s2s3_bounded_state_and_redaction_domain_churn_small_caps() {
    let limits = ObjectLimits {
        instances: 4,
        ..ObjectLimits::policy()
    };
    let (model, ids) = domain_churn(limits, 100);
    assert!(ids.windows(2).all(|w| w[0] < w[1]), "IDs never reused");
    let usage = model.project().usage;
    assert!(usage.domains <= 4);
    assert!(usage.pruned_domains >= 96);
    assert!(usage.object_records <= 4 && usage.session_records <= 4);
}

#[test]
fn s2s3_bounded_state_and_redaction_domain_churn_at_policy_caps() {
    let (model, ids) = domain_churn(ObjectLimits::policy(), 10_000);
    assert!(ids.windows(2).all(|w| w[0] < w[1]));
    let usage = model.project().usage;
    assert!(usage.domains <= 4_096);
    assert!(usage.pruned_domains >= 10_000 - 4_096);
}

#[test]
fn s2s3_bounded_state_and_redaction_unknown_and_pruned_domains_fail_closed() {
    let limits = ObjectLimits {
        instances: 2,
        ..ObjectLimits::policy()
    };
    let mut model = ObjectSemantics::with_limits(limits);
    let refused_begin = |model: &mut ObjectSemantics, domain: ObjectDomain| {
        model.begin(OriginFact {
            domain,
            cut: RefCut::reference(50),
            key: CallKey::reference(50),
            entry_ns: 50,
            function: fid("C_GetObjectSize"),
            session: HandleInput::Value(sess(SA)),
            inputs: [HandleInput::Value(obj(H1)), HandleInput::Absent],
            requested: [None, None],
            entry_mechanism: MechanismEvidence::NotCaptured,
            scope: SlotScope::Unknown,
        })
    };
    // A never-registered domain is never created implicitly.
    let stranger = churn_domain(77);
    assert_eq!(
        refused_begin(&mut model, stranger),
        Err(ObjectGap::UnknownDomain)
    );
    let e = model.settle(CompleteInputPrefix::reference(
        stranger,
        RefCut::reference(60),
        &[],
        Some(RefCut::reference(0)),
    ));
    assert!(e.effects.contains(&ObjectEffect::Gap {
        reason: ObjectGap::UnknownDomain
    }));
    assert_eq!(model.project().usage.domains, 0, "no fresh domain");

    // Two short-lived domains end; a third registration prunes them.
    let (a, b, c) = (churn_domain(1), churn_domain(2), churn_domain(3));
    for d in [a, b] {
        model.register_domain(d).unwrap();
        short_lived(&mut model, d).unwrap();
    }
    model.register_domain(c).unwrap();
    let live = short_lived(&mut model, c);
    assert!(live.is_some());
    let before = model.project();
    assert_eq!(before.usage.pruned_domains, 2);

    // Late facts for a pruned domain: refused, counted, no state, no join.
    assert_eq!(refused_begin(&mut model, a), Err(ObjectGap::DomainPruned));
    let e = model.settle(CompleteInputPrefix::reference(
        a,
        RefCut::reference(60),
        &[],
        Some(RefCut::reference(55)),
    ));
    assert!(e.effects.contains(&ObjectEffect::Gap {
        reason: ObjectGap::DomainPruned
    }));
    assert!(!e.effects.iter().any(|x| matches!(
        x,
        ObjectEffect::Created { .. } | ObjectEffect::FirstObserved { .. }
    )));
    model.invalidate(AffectedScope::Domain(a), ObjectGap::Loss);
    model.invalidate(AffectedScope::Session(a, sess(SA)), ObjectGap::Loss);
    let e = model.outcome_lost(LostOutcome::Refused(a, RefCut::reference(70)));
    assert!(e.effects.contains(&ObjectEffect::Gap {
        reason: ObjectGap::DomainPruned
    }));
    assert_eq!(model.register_domain(a), Err(ObjectGap::DomainPruned));
    let after = model.project();
    assert_eq!(after.usage.domains, before.usage.domains);
    assert_eq!(after.objects.len(), before.objects.len());
    assert_eq!(after.sessions.len(), before.sessions.len());
    assert!(after.gap(ObjectGap::DomainPruned) >= 4);
}

#[test]
fn s2s3_bounded_state_and_redaction_domain_with_pending_ticket_is_kept() {
    let limits = ObjectLimits {
        instances: 2,
        ..ObjectLimits::policy()
    };
    let mut h = Hist::with_limits(limits);
    h.run(1, open_in(slot(SLOT1)), 2, ok().session_out(SA));
    let pending = h.begin(3, create(SA));
    // An ended domain is reclaimed; the held domain with a ticket is not.
    let ended = churn_domain(1);
    h.model.register_domain(ended).unwrap();
    short_lived(&mut h.model, ended).unwrap();
    let next = churn_domain(2);
    assert_eq!(h.model.register_domain(next), Ok(()));
    assert_eq!(
        h.model.register_domain(churn_domain(3)),
        Err(ObjectGap::InstanceCapacity),
        "a domain with a pending ticket is never pruned"
    );
    h.done(pending, 4, ok().result(0, H1));
    let e = h.settle(4);
    assert!(
        created(&e, pending, 0).is_some(),
        "the held domain still joins"
    );
}
