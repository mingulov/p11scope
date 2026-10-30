//! SPDX-License-Identifier: GPL-3.0-or-later
//! H9 key-operation acceptance tests: operation effects, the single S1
//! feed, positional key roles, metadata timing, bounded projection and
//! output-schema agreement. Reducer/feed/projection behavior is tested
//! through production authority only (real `EdgeSemantics` reducer, real
//! H8 seal ingress, real `Presentation`); reference model constructors
//! appear only where the brief's algorithm twins require them.

use crate::semantics_edge::{
    EdgeSemantics, EffectOrigin, OpState, OperationEffect, OperationOutcome, SemanticCall,
};
use p11scope_ebpf_common::{FUNCTION_NONE, capture};
use pkcs11_types::CkRv;

const RSA_PKCS: u64 = 0x0001;
const AES_GCM: u64 = 0x1087;

fn call(function: &str, session: u64, rv: u64, ts_ns: u64) -> SemanticCall {
    SemanticCall {
        function: function.into(),
        rv,
        session,
        ts_ns,
        ..SemanticCall::default()
    }
}

fn init(function: &str, session: u64, mechanism: u64, ts_ns: u64) -> SemanticCall {
    SemanticCall {
        function: function.into(),
        session,
        mechanism,
        capture: capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL,
        ts_ns,
        ..SemanticCall::default()
    }
}

fn op(function: &str, session: u64, ts_ns: u64) -> SemanticCall {
    SemanticCall {
        function: function.into(),
        session,
        capture: capture::MECHANISM_NONE | capture::OUTPUT_NON_NULL,
        ts_ns,
        ..SemanticCall::default()
    }
}

/// Feed one call with its registry-supplied origin; returns this call's
/// freshly emitted effects only.
fn feed(
    edge: &mut EdgeSemantics,
    sink: &mut Vec<OperationEffect>,
    call: &SemanticCall,
) -> Vec<OperationEffect> {
    let origin = EffectOrigin::from(call);
    let before = sink.len();
    let refused = edge.observe_with_effects(call, &origin, sink);
    assert_eq!(refused, 0, "no bound refusal in {:?}", call.function);
    sink[before..].to_vec()
}

fn started(effect: &OperationEffect) -> (u64, &'static str, Option<u64>, &EffectOrigin) {
    match effect {
        OperationEffect::Started {
            id,
            category,
            mechanism,
            origin,
            ..
        } => (id.ordinal_for_test(), category, *mechanism, origin),
        other => panic!("expected Started, got {other:?}"),
    }
}

fn ended(effect: &OperationEffect) -> (u64, &'static str, OperationOutcome, &EffectOrigin) {
    match effect {
        OperationEffect::Ended {
            id,
            category,
            outcome,
            origin,
        } => (id.ordinal_for_test(), category, *outcome, origin),
        other => panic!("expected Ended, got {other:?}"),
    }
}

fn direct(effect: &OperationEffect) -> (u64, &'static str, Option<u64>, &EffectOrigin) {
    match effect {
        OperationEffect::DirectCompleted {
            id,
            category,
            mechanism,
            origin,
            ..
        } => (id.ordinal_for_test(), category, *mechanism, origin),
        other => panic!("expected DirectCompleted, got {other:?}"),
    }
}

/// Strip positional key receipts for S1-shape comparison: Joint
/// effects carry sealed receipts the S1Only twin never has; every
/// other field must match exactly.
fn strip_receipts(stream: &[OperationEffect]) -> Vec<OperationEffect> {
    stream
        .iter()
        .map(|effect| match effect {
            OperationEffect::Started {
                id,
                category,
                mechanism,
                origin,
                ..
            } => OperationEffect::Started {
                id: *id,
                category,
                mechanism: *mechanism,
                key_receipt: None,
                origin: origin.clone(),
            },
            OperationEffect::Ended {
                id,
                category,
                outcome,
                origin,
            } => OperationEffect::Ended {
                id: *id,
                category,
                outcome: *outcome,
                origin: origin.clone(),
            },
            OperationEffect::DirectCompleted {
                id,
                category,
                mechanism,
                origin,
                ..
            } => OperationEffect::DirectCompleted {
                id: *id,
                category,
                mechanism: *mechanism,
                key_receipts: Vec::new(),
                origin: origin.clone(),
            },
        })
        .collect()
}

/// G11/H9-§2: started/ended/direct effects exactly match the existing
/// counters across every mutation site.
#[test]
fn key_operation_transition_conservation() {
    // --- One-shot sign: Started then Ended(Completed), nothing else. ---
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    let effects = feed(&mut edge, &mut sink, &c);
    assert_eq!(effects.len(), 1);
    let (id, category, mechanism, origin) = started(&effects[0]);
    assert_eq!((category, mechanism), ("sign", Some(RSA_PKCS)));
    assert_eq!(origin.function, "C_SignInit");
    assert_eq!(origin.session, 7);
    assert_eq!(edge.started(), 1);
    let c = op("C_Sign", 7, 200);
    let effects = feed(&mut edge, &mut sink, &c);
    assert_eq!(effects.len(), 1);
    let (end_id, category, outcome, origin) = ended(&effects[0]);
    assert_eq!(end_id, id, "end carries the start's identity");
    assert_eq!((category, outcome), ("sign", OperationOutcome::Completed));
    assert_eq!(origin.function, "C_Sign");
    assert_eq!((edge.started(), edge.completed()), (1, 1));

    // --- Failed Init starts nothing and emits nothing. ---
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    let c = SemanticCall {
        rv: CkRv::OPERATION_ACTIVE.0,
        ..init("C_SignInit", 7, RSA_PKCS, 100)
    };
    assert!(feed(&mut edge, &mut sink, &c).is_empty());
    assert_eq!(edge.started(), 0);

    // --- Replacement: old terminal BEFORE new start, same call. ---
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    let first = feed(&mut edge, &mut sink, &c);
    let (first_id, _, _, _) = started(&first[0]);
    let c = init("C_SignInit", 7, AES_GCM, 200);
    let effects = feed(&mut edge, &mut sink, &c);
    assert_eq!(effects.len(), 2);
    let (end_id, _, outcome, _) = ended(&effects[0]);
    assert_eq!((end_id, outcome), (first_id, OperationOutcome::Cancelled));
    let (second_id, _, mechanism, _) = started(&effects[1]);
    assert_ne!(second_id, first_id);
    assert_eq!(mechanism, Some(AES_GCM));
    assert_eq!((edge.started(), edge.cancelled()), (2, 1));

    // --- Two-operation update touches both machines, retains both. ---
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    let c = init("C_DecryptInit", 7, AES_GCM, 100);
    assert_eq!(feed(&mut edge, &mut sink, &c).len(), 1);
    let c = init("C_VerifyInit", 7, RSA_PKCS, 150);
    assert_eq!(feed(&mut edge, &mut sink, &c).len(), 1);
    let c = op("C_DecryptVerifyUpdate", 7, 200);
    assert!(
        feed(&mut edge, &mut sink, &c).is_empty(),
        "RETAIN_ALWAYS emits no terminal"
    );
    assert!(edge.has_live_operations());
    assert_eq!(edge.started(), 2);

    // --- Size query and too-small retry retain; only real output ends. ---
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    assert_eq!(feed(&mut edge, &mut sink, &c).len(), 1);
    let query = SemanticCall {
        capture: capture::MECHANISM_NONE | capture::OUTPUT_NULL,
        ..op("C_Sign", 7, 200)
    };
    assert!(
        feed(&mut edge, &mut sink, &query).is_empty(),
        "size query retains"
    );
    let retry = SemanticCall {
        rv: CkRv::BUFFER_TOO_SMALL.0,
        ..op("C_Sign", 7, 300)
    };
    assert!(
        feed(&mut edge, &mut sink, &retry).is_empty(),
        "too-small retry retains"
    );
    let c = op("C_Sign", 7, 400);
    let effects = feed(&mut edge, &mut sink, &c);
    assert_eq!(effects.len(), 1);
    assert_eq!(ended(&effects[0]).2, OperationOutcome::Completed);
    assert_eq!((edge.started(), edge.completed()), (1, 1));

    // --- Multipart: updates retain, Final completes exactly once. ---
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    let first = feed(&mut edge, &mut sink, &c);
    let (id, _, _, _) = started(&first[0]);
    for ts in [200, 300, 400] {
        let c = op("C_SignUpdate", 7, ts);
        assert!(feed(&mut edge, &mut sink, &c).is_empty());
    }
    let c = op("C_SignFinal", 7, 500);
    let effects = feed(&mut edge, &mut sink, &c);
    assert_eq!(effects.len(), 1);
    let (end_id, _, outcome, _) = ended(&effects[0]);
    assert_eq!((end_id, outcome), (id, OperationOutcome::Completed));
    assert_eq!((edge.started(), edge.completed()), (1, 1));

    // --- Failed terminal ends Failed, not Completed. ---
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    let c = init("C_VerifyInit", 7, RSA_PKCS, 100);
    let first = feed(&mut edge, &mut sink, &c);
    let (id, _, _, _) = started(&first[0]);
    let c = SemanticCall {
        rv: CkRv::SIGNATURE_INVALID.0,
        ..op("C_Verify", 7, 200)
    };
    let effects = feed(&mut edge, &mut sink, &c);
    assert_eq!(effects.len(), 1);
    let (end_id, category, outcome, _) = ended(&effects[0]);
    assert_eq!(
        (end_id, category, outcome),
        (id, "verify", OperationOutcome::Failed)
    );
    assert_eq!((edge.started(), edge.failed()), (1, 1));

    // --- C_SessionCancel OK ends the selected machine Cancelled. ---
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    let first = feed(&mut edge, &mut sink, &c);
    let (id, _, _, _) = started(&first[0]);
    let mut c = call("C_SessionCancel", 7, CkRv::OK.0, 200);
    c.flags = 0x0000_0800; // CKF_SIGN
    let effects = feed(&mut edge, &mut sink, &c);
    assert_eq!(effects.len(), 1);
    let (end_id, _, outcome, _) = ended(&effects[0]);
    assert_eq!((end_id, outcome), (id, OperationOutcome::Cancelled));
    assert_eq!((edge.started(), edge.cancelled()), (2 - 1, 1));

    // --- Close/logout/finalize cancel through the same end sites. ---
    for (lifecycle, session) in [("C_CloseSession", 7), ("C_Logout", 7), ("C_Finalize", 7)] {
        let mut edge = EdgeSemantics::default();
        let mut sink = Vec::new();
        if lifecycle != "C_Finalize" {
            let c = call("C_OpenSession", session, CkRv::OK.0, 50);
            feed(&mut edge, &mut sink, &c);
        }
        let c = init("C_SignInit", session, RSA_PKCS, 100);
        let first = feed(&mut edge, &mut sink, &c);
        let (id, _, _, _) = started(&first[0]);
        let c = call(lifecycle, session, CkRv::OK.0, 200);
        let effects = feed(&mut edge, &mut sink, &c);
        assert_eq!(effects.len(), 1, "{lifecycle} ends the machine");
        let (end_id, _, outcome, _) = ended(&effects[0]);
        assert_eq!((end_id, outcome), (id, OperationOutcome::Cancelled));
        assert_eq!((edge.started(), edge.cancelled()), (1, 1));
    }

    // --- Loss invalidates live authority as Unknown. ---
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    let first = feed(&mut edge, &mut sink, &c);
    let (id, _, _, _) = started(&first[0]);
    edge.invalidate_with_effects(&mut sink);
    assert_eq!(sink.len(), 2);
    let (end_id, _, outcome, _) = ended(&sink[1]);
    assert_eq!((end_id, outcome), (id, OperationOutcome::Unknown));
    assert_eq!((edge.started(), edge.unknown()), (1, 1));

    // --- Direct success: exactly ONE atomic DirectCompleted. ---
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    let c = op("C_GenerateKey", 7, 100);
    let effects = feed(&mut edge, &mut sink, &c);
    assert_eq!(effects.len(), 1);
    let (_, category, _, origin) = direct(&effects[0]);
    assert_eq!(category, "generate_key");
    assert_eq!(origin.function, "C_GenerateKey");
    assert_eq!((edge.started(), edge.completed()), (1, 1));

    // --- Direct failure: no effect, no operation. ---
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    let c = SemanticCall {
        rv: CkRv::TEMPLATE_INCOMPLETE.0,
        ..op("C_GenerateKey", 7, 100)
    };
    assert!(feed(&mut edge, &mut sink, &c).is_empty());
    assert_eq!((edge.started(), edge.completed()), (0, 0));

    // --- Message units are explicit message contexts, never signatures. ---
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    let c = init("C_MessageSignInit", 7, RSA_PKCS, 100);
    let first = feed(&mut edge, &mut sink, &c);
    let (id, category, _, _) = started(&first[0]);
    assert_eq!(category, "message_sign");
    let c = op("C_SignMessage", 7, 200);
    assert!(feed(&mut edge, &mut sink, &c).is_empty());
    let c = op("C_MessageSignFinal", 7, 300);
    let effects = feed(&mut edge, &mut sink, &c);
    assert_eq!(effects.len(), 1);
    let (end_id, category, outcome, _) = ended(&effects[0]);
    assert_eq!(
        (end_id, category, outcome),
        (id, "message_sign", OperationOutcome::Completed)
    );
}

/// G11/H9-§2: operation identity never wraps or recycles, across
/// machines, direct operations and stale async completions.
#[test]
fn key_operation_identity_never_wraps() {
    // --- Checked N/N+1: last identity allocates, next refuses. ---
    let mut edge = EdgeSemantics::default();
    edge.seed_machine_seq_for_test(u64::MAX - 1);
    let mut sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    let effects = feed(&mut edge, &mut sink, &c);
    assert_eq!(effects.len(), 1, "N allocates the final identity");
    assert_eq!(started(&effects[0]).0, u64::MAX);
    let c = init("C_EncryptInit", 7, AES_GCM, 200);
    let before = sink.len();
    let origin = EffectOrigin::from(&c);
    edge.observe_with_effects(&c, &origin, &mut sink);
    assert_eq!(sink.len(), before, "N+1 mints no recycled identity");
    assert_eq!(edge.id_exhaustions(), 1);
    // The refused Init still started per S1 (OK return) but its end is
    // honestly unknown: no machine, no invented completion.
    assert_eq!((edge.started(), edge.unknown()), (2, 1));
    assert_eq!(edge.completed(), 0);

    // --- Direct operations draw from the same checked source. ---
    let mut edge = EdgeSemantics::default();
    edge.seed_machine_seq_for_test(u64::MAX - 1);
    let mut sink = Vec::new();
    let c = op("C_GenerateKey", 7, 100);
    let effects = feed(&mut edge, &mut sink, &c);
    assert_eq!(effects.len(), 1);
    assert_eq!(direct(&effects[0]).0, u64::MAX);
    let c = op("C_WrapKey", 7, 200);
    let before = sink.len();
    let origin = EffectOrigin::from(&c);
    edge.observe_with_effects(&c, &origin, &mut sink);
    assert_eq!(sink.len(), before, "exhausted direct mints nothing");
    assert_eq!(edge.id_exhaustions(), 1);
    // A direct call completes inside its own call: no tracking is
    // needed, so the definite S1 completion stands without an effect.
    assert_eq!((edge.started(), edge.completed()), (2, 2));

    // --- Machine and direct identities never collide. ---
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    feed(&mut edge, &mut sink, &c);
    let c = op("C_GenerateKey", 7, 200);
    feed(&mut edge, &mut sink, &c);
    let c = init("C_SignInit", 7, RSA_PKCS, 300);
    feed(&mut edge, &mut sink, &c);
    assert_eq!(sink.len(), 4); // Started, Direct, Ended(old), Started
    let ids: Vec<u64> = sink
        .iter()
        .map(|effect| match effect {
            OperationEffect::Started { id, .. }
            | OperationEffect::Ended { id, .. }
            | OperationEffect::DirectCompleted { id, .. } => id.ordinal_for_test(),
        })
        .collect();
    assert_eq!(ids, vec![1, 2, 1, 3]);

    // --- A delayed async completion cannot reuse a dead identity. ---
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    feed(&mut edge, &mut sink, &c);
    // Queue a PENDING C_Sign against the live machine.
    let mut pending = op("C_Sign", 7, 200);
    pending.rv = CkRv::PENDING.0;
    feed(&mut edge, &mut sink, &pending);
    // Replace the machine before the completion lands.
    let c = init("C_SignInit", 7, AES_GCM, 300);
    feed(&mut edge, &mut sink, &c);
    let target = crate::kinds::function_id("C_Sign").unwrap();
    let mut complete = call("C_AsyncComplete", 7, CkRv::OK.0, 400);
    complete.target_function = target;
    let effects = feed(&mut edge, &mut sink, &complete);
    assert!(
        effects.is_empty(),
        "stale completion orphans; no effect reuses the dead identity"
    );
    assert_eq!(edge.orphans(), 1);
    assert_eq!(edge.completed(), 0);
    assert_eq!(sink.len(), 3); // Started, Ended(old), Started(new)

    // --- Async completion of the ORIGINATING machine ends its identity. ---
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    let first = feed(&mut edge, &mut sink, &c);
    let (id, _, _, _) = started(&first[0]);
    let mut pending = op("C_Sign", 7, 200);
    pending.rv = CkRv::PENDING.0;
    feed(&mut edge, &mut sink, &pending);
    let target = crate::kinds::function_id("C_Sign").unwrap();
    let mut complete = call("C_AsyncComplete", 7, CkRv::OK.0, 300);
    complete.target_function = target;
    let effects = feed(&mut edge, &mut sink, &complete);
    assert_eq!(effects.len(), 1);
    let (end_id, _, outcome, origin) = ended(&effects[0]);
    assert_eq!((end_id, outcome), (id, OperationOutcome::Completed));
    assert_eq!(
        (origin.function.as_str(), origin.session, origin.ts_ns),
        ("C_Sign", 7, 200),
        "completion carries the FULL original call identity, not the completion's time"
    );
    assert_eq!(edge.completed(), 1);
    assert_eq!(FUNCTION_NONE, p11scope_ebpf_common::FUNCTION_NONE);
}

/// N8: a joined async completion preserves the ORIGINAL consumed
/// call identity in its effects — the completion's session and time
/// are receiver custody, never the origin.
#[test]
fn key_operation_async_completion_preserves_origin_identity() {
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    feed(
        &mut edge,
        &mut sink,
        &call("C_OpenSession", 7, CkRv::OK.0, 90),
    );
    feed(
        &mut edge,
        &mut sink,
        &call("C_OpenSession", 8, CkRv::OK.0, 95),
    );
    // The original call is consumed on session 7 at ts 100, then
    // detached and joined by session 8.
    let mut pending = op("C_GenerateKey", 7, 100);
    pending.rv = CkRv::PENDING.0;
    feed(&mut edge, &mut sink, &pending);
    let target = crate::kinds::function_id("C_GenerateKey").unwrap();
    let mut get_id = call("C_AsyncGetID", 7, CkRv::OK.0, 120);
    get_id.target_function = target;
    get_id.async_value = 42;
    feed(&mut edge, &mut sink, &get_id);
    let mut join = call("C_AsyncJoin", 8, CkRv::OK.0, 170);
    join.target_function = target;
    join.async_value = 42;
    feed(&mut edge, &mut sink, &join);
    // Session 8 completes at ts 400: the replayed completion still
    // names the original (7, 100) call.
    let mut complete = call("C_AsyncComplete", 8, CkRv::OK.0, 400);
    complete.target_function = target;
    let effects = feed(&mut edge, &mut sink, &complete);
    assert_eq!(effects.len(), 1, "the joined completion replays its call");
    let (_, _, _, origin) = direct(&effects[0]);
    assert_eq!(
        (origin.function.as_str(), origin.session, origin.ts_ns),
        ("C_GenerateKey", 7, 100),
        "the replayed effect carries the original call identity"
    );
}

// ==================== Checkbox 1B: the single S1 feed ====================

use crate::semantics_key_use::{
    FailureApplyOutcome, FeedMode, JointStaging, SealApplyOutcome, StagingRefusal,
};
use crate::semantics_objects::ObjectSemantics;
use crate::semantics_objects::journal::tests::{
    AttestationFixture, COOKIE, ENTRY_NS, EXEC, FLAGS, NativeBirthRows, NativePublisher, SESSION,
    abandon_bytes, begin_bytes, begin_bytes_shaped, end_bytes, end_bytes_absent, end_bytes_getattr,
    end_bytes_result, function_id, ordinary_for,
};
use crate::semantics_objects::journal::{
    BirthKind, BootstrapReceipt, FaultEpoch, FaultReadError, H3DispositionEvidence, JournalAdapter,
    JournalAuditReceipt, JournalDisposition, JournalDomainProof, JournalGap, JournalIngestItem,
    JournalLimits, ScriptedBirthSource, ScriptedH3Source, SealFailure, SealSuccess,
    SessionBirthEvidence, SessionBirthGrant, SessionClosureGrant, StagingLedger,
};
use p11scope_ebpf_common::object_journal::{
    JOURNAL_REASON_SYNC_RETURN_RESULT_LOST, decode_journal_record,
};
use p11scope_ebpf_common::object_wire::{
    OBJECT_ACTION_ACCESS, OBJECT_ACTION_COPY, OBJECT_ACTION_CREATE,
    OBJECT_ACTION_DECAPSULATE, OBJECT_ACTION_DESTROY, OBJECT_ACTION_ENCAPSULATE,
    OBJECT_ACTION_FIND, ObjectDescriptorWire, publish_object_descriptors,
    verify_object_descriptors,
};
use p11scope_ebpf_common::{Event, ImageIdentity, InstanceStamp, MAX_DESCRIPTORS};

/// The H7 fixture's created key word (mirrors the journal's own
/// neutral-history grounding).
const CREATED_KEY: u64 = 0x9090_9090_9090_9090;

/// The KEM fixture's minted output word: distinct from the created
/// input word so healthy KEM outputs never collide with their input.
const KEM_OUTPUT_KEY: u64 = 0xB0B0_B0B0_B0B0_B0B0;

struct SteadyFaultCell(u64);

impl FaultEpoch for SteadyFaultCell {
    fn fault_epoch(&self) -> Result<u64, FaultReadError> {
        Ok(self.0)
    }
}

/// One Joint scene: real H3 admissions, real H8 attest/ingest/seal,
/// H9 staging plus the one reducer, and an S1Only direct twin. The
/// shared staging ledger sits H8-side (next to the adapter/model),
/// borrowed by every staging call.
struct JointScene {
    adapter: JournalAdapter,
    model: ObjectSemantics,
    descriptors: [ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
    fixture: AttestationFixture,
    proof: JournalDomainProof,
    thread: u64,
    sequence: u64,
    admission_sequence: u64,
    /// Exact pre-admission wire input indexed by its returned H0 identity.
    paired_begins: BTreeMap<u64, [u8; 224]>,
}

impl JointScene {
    fn new() -> Self {
        let descriptors = publish_object_descriptors();
        assert!(verify_object_descriptors(&descriptors));
        let mut adapter = JournalAdapter::new(JournalLimits::policy());
        let mut fixture = AttestationFixture::new(ImageIdentity {
            task_cookie: COOKIE,
            exec_id: EXEC,
        });
        let grant = SessionClosureGrant::observe(fixture.attachment());
        let _ = adapter.install_closure_grant(&grant);
        let admitted = fixture.admit_function("C_SignInit");
        let proof = adapter.attest_key(&admitted).expect("key attests");
        Self {
            adapter,
            model: ObjectSemantics::new(),
            descriptors,
            fixture,
            proof,
            thread: 1,
            sequence: 0,
            admission_sequence: 0,
            paired_begins: BTreeMap::new(),
        }
    }

    fn install_closure(&mut self) {
        let grant = SessionClosureGrant::observe(self.fixture.attachment());
        let _ = self.adapter.install_closure_grant(&grant);
    }

    fn bootstrap(&self) -> BootstrapReceipt {
        BootstrapReceipt::scripted(
            self.proof,
            BirthKind::ExecMarker,
            0,
            self.fixture.attachment().generation(),
        )
    }

    fn ingest(&mut self, bytes: &[u8]) -> JournalDisposition {
        let record = decode_journal_record(bytes, &self.descriptors).expect("test bytes decode");
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

    fn seal(&mut self) -> Result<SealSuccess, SealFailure> {
        self.seal_with_fault(7, 7)
    }

    /// One seal with explicit audit/cell epochs: equal for healthy
    /// seals, moved for the native-fault loss twin.
    fn seal_with_fault(
        &mut self,
        audit_epoch: u64,
        cell_epoch: u64,
    ) -> Result<SealSuccess, SealFailure> {
        self.install_closure();
        let bootstrap = self.bootstrap();
        let frontier = self.adapter.consumed_frontier();
        let audit = JournalAuditReceipt::scripted(
            audit_epoch,
            audit_epoch,
            None,
            0,
            H3DispositionEvidence::scripted_clean(self.fixture.h0_allocated_below() - 1),
            self.fixture.attachment().generation(),
        );
        let fresh = SessionBirthEvidence::scripted_for_receipt(&bootstrap);
        let cell = SteadyFaultCell(cell_epoch);
        let mut births = ScriptedBirthSource::once(fresh);
        self.adapter.seal(
            &mut self.model,
            &audit,
            &bootstrap,
            frontier,
            &mut births,
            &cell,
        )
    }

    /// One seal over a genuinely observed birth (N1a): the caller
    /// supplies the attested receipt plus FRESH re-observed birth
    /// evidence (a second producer run, never the first run's
    /// words), mirroring T3's re-observation at seal. The audit/H3
    /// receipts stay the scene's scripted ones (H8 seal machinery,
    /// T3-pinned); the birth side is fully observed.
    fn seal_with_birth(
        &mut self,
        bootstrap: &BootstrapReceipt,
        fresh: SessionBirthEvidence,
    ) -> Result<SealSuccess, SealFailure> {
        self.install_closure();
        let frontier = self.adapter.consumed_frontier();
        let audit = JournalAuditReceipt::scripted(
            7,
            7,
            None,
            0,
            H3DispositionEvidence::scripted_clean(self.fixture.h0_allocated_below() - 1),
            self.fixture.attachment().generation(),
        );
        let cell = SteadyFaultCell(7);
        let mut births = ScriptedBirthSource::once(fresh);
        self.adapter.seal(
            &mut self.model,
            &audit,
            bootstrap,
            frontier,
            &mut births,
            &cell,
        )
    }
}

/// One S1-shaped call: admission facts plus matching journal record
/// shape. The journal BEGIN carries the same fingerprint fields as
/// the admission, so H8 attribution is genuine, not staged.
struct ShapedS1 {
    name: &'static str,
    rv: u64,
    mechanism: u64,
    capture: u32,
    flags: u64,
    /// Session word override (`None` = the shared fixture session).
    session: Option<u64>,
    /// Input words as (word, status): `Some` overrides the
    /// per-function default (`None` = absent).
    input0: Option<(u64, u8)>,
    input1: Option<(u64, u8)>,
    /// CREATE result word override (`None` = the default key word).
    result: Option<u64>,
    /// COPY result word override (`None` = unknown output, status 7;
    /// `Some(word)` = valid VALUE result slot 0).
    copy_result: Option<u64>,
    /// FIND handles override (`None` = unknown output; `Some((words,
    /// truncated))` = valid Find section with the given handle words).
    find_handles: Option<(Vec<u64>, bool)>,
    /// GET attribute cells as (kind, status, value).
    getattr_cells: Vec<(u8, u8, u16)>,
    /// KEM result (word, status) override (`None` = the healthy
    /// minted-output default).
    kem_result: Option<(u64, u8)>,
}

impl ShapedS1 {
    fn shaped(name: &'static str, rv: u64, mechanism: u64, capture: u32) -> Self {
        let input0 = match name {
            "C_SignInit"
            | "C_VerifyInit"
            | "C_MessageSignInit"
            | "C_DestroyObject"
            | "C_GetAttributeValue"
            | "C_EncapsulateKey"
            | "C_DecapsulateKey" => Some((CREATED_KEY, 1)),
            _ => None,
        };
        Self {
            name,
            rv,
            mechanism,
            capture,
            flags: FLAGS,
            session: None,
            input0,
            input1: None,
            result: None,
            copy_result: None,
            find_handles: None,
            getattr_cells: Vec::new(),
            kem_result: None,
        }
    }
}

fn init_capture() -> u32 {
    capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL
}

fn op_capture() -> u32 {
    capture::MECHANISM_NONE | capture::OUTPUT_NON_NULL
}

fn query_capture() -> u32 {
    capture::MECHANISM_NONE | capture::OUTPUT_NULL
}

/// Attest + stage one call (no ingest): for correlation twins that
/// stage and ingest different calls. Returns the payload and its H0
/// position.
fn attest_and_stage(
    scene: &mut JointScene,
    staging: &mut JointStaging,
    call: &ShapedS1,
) -> (SemanticCall, u64) {
    let admitted = admit_call_input(scene, call);
    scene.adapter.attest_key(&admitted).expect("call attests");
    let facts = admitted.s1_facts().clone();
    let origin = EffectOrigin::from(&facts);
    let position = admitted.h0_ordinal();
    staging
        .stage(facts.clone(), origin, position, scene.adapter.ledger_mut())
        .expect("call stages");
    (facts, position)
}

/// Attest (no stage) + ingest one call: the seal settles a call H9
/// never staged.
fn attest_and_ingest(scene: &mut JointScene, call: &ShapedS1) {
    let admitted = admit_call_input(scene, call);
    scene.adapter.attest_key(&admitted).expect("call attests");
    ingest_call(scene, call, admitted.h0_ordinal());
}

/// One explicit paired native/Event input before routed admission.
fn admit_call_input(scene: &mut JointScene, call: &ShapedS1) -> AdmittedInstanceCall {
    scene.admission_sequence = scene.admission_sequence.max(scene.sequence) + 1;
    let begin = begin_for_call(scene, call, scene.admission_sequence);
    let end = end_for_call(&begin, call);
    let record = decode_journal_record(&end, &scene.descriptors).expect("paired END decodes");
    let p11scope_ebpf_common::object_journal::JournalRecord::End(end) = record else {
        panic!("END input")
    };
    let admitted = scene
        .fixture
        .admit_original_event(call.name, end.payload_base().event);
    scene.paired_begins.insert(admitted.h0_ordinal(), begin);
    admitted
}

fn begin_for_call(scene: &JointScene, call: &ShapedS1, sequence: u64) -> [u8; 224] {
    let fid = crate::kinds::function_id(call.name).unwrap();
    begin_bytes_shaped(
        scene.thread,
        sequence,
        fid,
        0,
        (COOKIE, EXEC),
        call.session.unwrap_or(SESSION),
        call.mechanism,
        call.capture,
        call.input0,
        call.input1,
        call.flags,
    )
}

fn end_for_call(begin: &[u8; 224], call: &ShapedS1) -> [u8; 632] {
    match call.name {
        "C_CreateObject" => match call.result {
            Some(result) => {
                end_bytes_result(begin, OBJECT_ACTION_CREATE, call.rv, ENTRY_NS + 50, result)
            }
            None => end_bytes(begin, OBJECT_ACTION_CREATE, call.rv, ENTRY_NS + 50),
        },
        "C_SignInit" | "C_VerifyInit" | "C_MessageSignInit" | "C_WrapKey" => {
            end_bytes(begin, OBJECT_ACTION_ACCESS, call.rv, ENTRY_NS + 50)
        }
        "C_DestroyObject" => end_bytes(begin, OBJECT_ACTION_DESTROY, call.rv, ENTRY_NS + 50),
        // Copy/Find carry result protocols, so their tails stay present.
        // Unknown outputs (`None`) read explicit unknown
        // (NotCaptured/Unreadable), never an absent row. Both authorize
        // result slot 0, which the validator requires non-absent:
        // status 7 marks it never captured. Valid overrides emit real
        // VALUE / Find-section bytes through the same conversion seam.
        "C_CopyObject" => {
            let mut end = end_bytes(begin, OBJECT_ACTION_COPY, call.rv, ENTRY_NS + 50);
            // Tail result slot 0: record[392 + 114]; word at +32.
            match call.copy_result {
                Some(word) => {
                    assert_ne!(word, 0, "valid COPY result is nonzero");
                    end[506] = 1;
                    end[424..432].copy_from_slice(&word.to_le_bytes());
                }
                None => {
                    end[506] = 7;
                }
            }
            end
        }
        "C_FindObjects" => {
            let mut end = end_bytes(begin, OBJECT_ACTION_FIND, call.rv, ENTRY_NS + 50);
            // Tail result slot 0: record[392 + 114].
            end[506] = 7;
            if let Some((handles, truncated)) = &call.find_handles {
                assert!(
                    handles.len() <= 8,
                    "at most eight find handles, got {}",
                    handles.len()
                );
                assert!(
                    !truncated || handles.len() == 8,
                    "truncation implies eight cells"
                );
                // Find section: len at +124, flags at +125, valid at
                // +126; cell statuses at +116..+124, words at
                // +48+8*i. Record base is 392.
                end[516] = handles.len() as u8;
                end[517] = u8::from(*truncated);
                end[518] = 1;
                for (i, word) in handles.iter().enumerate() {
                    assert_ne!(*word, 0, "valid FIND handle is nonzero");
                    end[508 + i] = 1;
                    let base = 440 + 8 * i;
                    end[base..base + 8].copy_from_slice(&word.to_le_bytes());
                }
            }
            end
        }
        "C_GetAttributeValue" => {
            end_bytes_getattr(begin, call.rv, ENTRY_NS + 50, &call.getattr_cells)
        }
        "C_EncapsulateKey" => end_bytes_kem(begin, OBJECT_ACTION_ENCAPSULATE, call),
        "C_DecapsulateKey" => end_bytes_kem(begin, OBJECT_ACTION_DECAPSULATE, call),
        _ => end_bytes_absent(begin, call.rv, ENTRY_NS + 50),
    }
}

/// KEM END with an explicit result (word, status): the default is the
/// healthy minted output; tests override for zero/unreadable/
/// unavailable cells. Tail result word at record[424..432], status at
/// record[506].
fn end_bytes_kem(begin: &[u8; 224], action: u8, call: &ShapedS1) -> [u8; 632] {
    let mut end = end_bytes(begin, action, call.rv, ENTRY_NS + 50);
    let (word, status) = call.kem_result.unwrap_or((KEM_OUTPUT_KEY, 1));
    end[424..432].copy_from_slice(&word.to_le_bytes());
    end[506] = status;
    end
}

/// Ingest the paired call's native records in their original order.
fn ingest_call(scene: &mut JointScene, call: &ShapedS1, position: u64) {
    let begin = scene
        .paired_begins
        .remove(&position)
        .expect("original paired BEGIN for this exact H0 admission");
    let p11scope_ebpf_common::object_journal::JournalRecord::Begin(native) =
        decode_journal_record(&begin, &scene.descriptors).expect("paired BEGIN")
    else {
        panic!("BEGIN input")
    };
    assert_eq!(
        native.descriptor() - 1,
        crate::kinds::function_id(call.name).unwrap()
    );
    scene.sequence = scene.sequence.max(native.sequence());
    assert_eq!(
        scene.ingest(&begin),
        JournalDisposition::BeginAdmitted,
        "{} begin admits",
        call.name
    );
    let end = end_for_call(&begin, call);
    assert_eq!(
        scene.ingest(&end),
        JournalDisposition::EndStaged,
        "{} end stages",
        call.name
    );
}

/// Attest + stage + ingest one call's quantum; seal separately so
/// tests drive success and failure arms explicitly. Returns the
/// admitted S1 payload for the direct twin plus its H0 position.
fn prepare_call(
    scene: &mut JointScene,
    staging: &mut JointStaging,
    call: &ShapedS1,
) -> (SemanticCall, u64) {
    let (facts, position) = attest_and_stage(scene, staging, call);
    ingest_call(scene, call, position);
    (facts, position)
}

fn sign_flow() -> Vec<ShapedS1> {
    vec![
        ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
        ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
        ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
        ShapedS1::shaped("C_VerifyInit", CkRv::OK.0, RSA_PKCS, init_capture()),
        ShapedS1::shaped("C_Verify", CkRv::SIGNATURE_INVALID.0, 0, op_capture()),
        ShapedS1::shaped("C_SignMessage", CkRv::OK.0, 0, op_capture()),
    ]
}

fn assert_s1_equal(joint: &EdgeSemantics, direct: &EdgeSemantics) {
    assert_eq!(
        (
            joint.calls(),
            joint.started(),
            joint.completed(),
            joint.cancelled(),
            joint.failed(),
            joint.unknown(),
            joint.orphans(),
            joint.dropped(),
            joint.id_exhaustions(),
        ),
        (
            direct.calls(),
            direct.started(),
            direct.completed(),
            direct.cancelled(),
            direct.failed(),
            direct.unknown(),
            direct.orphans(),
            direct.dropped(),
            direct.id_exhaustions(),
        ),
        "S1 counters match"
    );
    assert_eq!(joint.mechanisms().len(), direct.mechanisms().len());
    for (id, a) in joint.mechanisms() {
        let b = direct.mechanisms().get(id).expect("same mechanism row");
        assert_eq!((a.calls, a.errors), (b.calls, b.errors));
        assert_eq!(a.ops, b.ops);
        assert_eq!(a.last_seen_ns, b.last_seen_ns);
        assert_eq!(a.functions, b.functions);
        assert_eq!(a.returns, b.returns);
        assert_eq!(a.truncated, b.truncated);
    }
    assert_eq!(joint.evidence(), direct.evidence());
    assert_eq!(joint.active_summary(), direct.active_summary());
    assert_eq!(joint.label(), direct.label());
}

/// G11/H9-§1: one S1 feed — Joint replay through sealed H8 authority
/// reduces each authorized payload exactly once with S1 totals
/// identical to direct reduction; model facts appear only in Joint.
#[test]
fn key_operation_single_feed_exactly_once() {
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    assert_eq!(staging.mode(), FeedMode::Joint);
    let mut joint = EdgeSemantics::default();
    let mut joint_sink = Vec::new();
    let mut keyuse = KeyUseReducer::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();

    for call in sign_flow() {
        let (facts, _) = prepare_call(&mut scene, &mut staging, &call);
        let success = scene.seal().expect("single-call quantum seals");
        assert_eq!(success.prefix.settled().len(), 1);
        let (outcome, refused) = staging.apply_seal(
            &success,
            &scene.model,
            scene.adapter.ledger_mut(),
            &mut joint,
            &mut keyuse,
            instance,
            &mut joint_sink,
            None,
        );
        assert_eq!(
            outcome,
            SealApplyOutcome::ReplayedOne,
            "{} replays once",
            call.name
        );
        assert_eq!(refused, 0, "no bound refusal in the quantum");
        // The direct twin reduces the same proved payload once.
        let origin = EffectOrigin::from(&facts);
        direct.observe_with_effects(&facts, &origin, &mut direct_sink);
        // One visit per accepted completed call on both feeds: equal
        // effects, equal counters, after every call.
        assert_eq!(strip_receipts(&joint_sink), direct_sink, "S1 shapes match");
        assert_s1_equal(&joint, &direct);
    }
    assert_eq!(
        (joint.started(), joint.completed(), joint.failed()),
        (2, 1, 1)
    );
    assert_eq!(joint.orphans(), 1, "uninitialized C_SignMessage orphans");
    assert_eq!(joint.calls(), 6);
    assert_eq!(staging.reduced(), 6);

    // --- S1Only is permanent: no receipt upgrades it, no replay. ---
    let mut s1only = JointStaging::select_s1_only();
    assert_eq!(s1only.mode(), FeedMode::S1Only);
    let facts = SemanticCall {
        function: "C_Sign".into(),
        ..SemanticCall::default()
    };
    let origin = EffectOrigin::from(&facts);
    assert_eq!(
        s1only.stage(facts.clone(), origin.clone(), 1, scene.adapter.ledger_mut()),
        Err(StagingRefusal::NotJoint)
    );
    // A receipt arriving after S1Only selection changes nothing: no
    // upgrade path exists, and staging still refuses.
    let _late_receipt = scene.bootstrap();
    assert_eq!(s1only.mode(), FeedMode::S1Only);
    assert_eq!(
        s1only.stage(facts, origin, 2, scene.adapter.ledger_mut()),
        Err(StagingRefusal::NotJoint)
    );

    // --- An already-reduced call is never replayed. ---
    let mut scene2 = JointScene::new();
    let bootstrap2 = scene2.bootstrap();
    let mut staging2 = JointStaging::select_joint(Some(&bootstrap2));
    let mut edge2 = EdgeSemantics::default();
    let mut sink2 = Vec::new();
    let mut keyuse = KeyUseReducer::new();
    let (facts, _) = prepare_call(
        &mut scene2,
        &mut staging2,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let success = scene2.seal().expect("quantum seals");
    let (outcome, refused) = staging2.apply_seal(
        &success,
        &scene2.model,
        scene2.adapter.ledger_mut(),
        &mut edge2,
        &mut keyuse,
        instance,
        &mut sink2,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    assert_eq!(refused, 0);
    // Restaging the same H0 position after reduction refuses.
    let origin = EffectOrigin::from(&facts);
    assert_eq!(
        staging2.stage(facts.clone(), origin.clone(), 1, scene.adapter.ledger_mut()),
        Err(StagingRefusal::ReplayRefused)
    );
    // Staging at or below the consumed frontier refuses even with
    // fresh facts.
    let mut older = facts.clone();
    older.ts_ns += 1;
    assert_eq!(
        staging2.stage(older, origin, 1, scene.adapter.ledger_mut()),
        Err(StagingRefusal::ReplayRefused)
    );
}

/// G11/H9-§1: proof-only refusal falls back once through ordinary S1
/// with an explicit complete H3 stream; real loss invalidates before
/// history-only disposal and starts no old machine.
#[test]
fn key_operation_fallback_and_history_loss() {
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    // --- Proof-only refusal: the own birth proof mismatches, H3 is clean. ---
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut joint_sink = Vec::new();
    let mut keyuse = KeyUseReducer::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();
    let mut staged_facts = Vec::new();
    for call in sign_flow().into_iter().take(3) {
        staged_facts.push(prepare_call(&mut scene, &mut staging, &call).0);
    }
    // Seal under an invalid own birth proof: no loss is fenced.
    scene.install_closure();
    // Own established domain, deliberately invalid birth cut: a proof
    // refusal scopes fallback here; a foreign request must remain inert.
    let refused_bootstrap = BootstrapReceipt::scripted(
        scene.proof,
        BirthKind::ExecMarker,
        u64::MAX,
        scene.fixture.attachment().generation(),
    );
    let frontier = scene.adapter.consumed_frontier();
    let audit = JournalAuditReceipt::scripted(
        7,
        7,
        None,
        0,
        H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through_for_test()),
        scene.fixture.attachment().generation(),
    );
    let fresh = SessionBirthEvidence::scripted_for_receipt(&refused_bootstrap);
    let cell = SteadyFaultCell(7);
    let mut births = ScriptedBirthSource::once(fresh);
    let failure = scene
        .adapter
        .seal(
            &mut scene.model,
            &audit,
            &refused_bootstrap,
            frontier,
            &mut births,
            &cell,
        )
        .expect_err("own birth proof mismatches");
    assert_eq!(failure.gap, JournalGap::BootstrapMismatch);

    // Without a complete H3 stream the fallback holds: pending work
    // below the watermark is journal silence, not completeness.
    let mut pending_source = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean_pending(
        u64::MAX,
        Some(1),
    ));
    let (outcome, refused) = staging.apply_algorithm_failure_for_test(
        &failure,
        &mut pending_source,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
        None,
    );
    assert_eq!(outcome, FailureApplyOutcome::HeldForCompleteness);
    assert_eq!(refused, 0);
    assert_eq!(staging.mode(), FeedMode::Joint);
    assert_eq!(joint.calls(), 0, "nothing reduced before completeness");

    // With the explicit complete stream, retained calls replay once
    // in original order through ordinary S1, then S1Only forever.
    let mut clean_source = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    let (outcome, refused) = staging.apply_algorithm_failure_for_test(
        &failure,
        &mut clean_source,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
        None,
    );
    assert_eq!(outcome, FailureApplyOutcome::FellBack { replayed: 3 });
    assert_eq!(refused, 0);
    assert_eq!(staging.mode(), FeedMode::S1Only);
    for facts in &staged_facts {
        let origin = EffectOrigin::from(facts);
        direct.observe_with_effects(facts, &origin, &mut direct_sink);
    }
    assert_eq!(
        strip_receipts(&joint_sink),
        direct_sink,
        "fallback equals direct S1"
    );
    assert_s1_equal(&joint, &direct);
    assert_eq!((joint.started(), joint.completed()), (1, 1));
    // Fresh calls after fallback reduce directly, never stage.
    let fresh = SemanticCall {
        function: "C_Sign".into(),
        ..SemanticCall::default()
    };
    let origin = EffectOrigin::from(&fresh);
    assert_eq!(
        staging.stage(fresh, origin, 99, scene.adapter.ledger_mut()),
        Err(StagingRefusal::NotJoint)
    );

    // --- Real loss: the seal-time fault cell moved (native fault). ---
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut joint_sink = Vec::new();
    let mut keyuse = KeyUseReducer::new();
    // One live machine before the loss.
    let (live, _) = prepare_call(
        &mut scene,
        &mut staging,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    assert!(live.function == "C_SignInit");
    let success = scene.seal().expect("first quantum seals");
    let (outcome, refused) = staging.apply_seal(
        &success,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    assert_eq!(refused, 0);
    assert_eq!(joint.started(), 1);
    assert!(joint.has_live_operations());
    // Two more staged, then the fault moves under the seal.
    for call in [
        ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
        ShapedS1::shaped("C_VerifyInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    ] {
        prepare_call(&mut scene, &mut staging, &call);
    }
    let failure = scene
        .seal_with_fault(7, 8)
        .expect_err("moved fault voids the seal");
    assert_eq!(failure.gap, JournalGap::FaultChanged);
    let mut h3 = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    let (outcome, refused) = staging.apply_algorithm_failure_for_test(
        &failure,
        &mut h3,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
        None,
    );
    assert_eq!(outcome, FailureApplyOutcome::Degraded { disposed: 2 });
    assert_eq!(refused, 0);
    // Live authority invalidated first: the machine ends Unknown in
    // the sink before any disposal accounting.
    assert_eq!(joint_sink.len(), 2);
    assert_eq!(ended(&joint_sink[1]).2, OperationOutcome::Unknown);
    assert_eq!((joint.started(), joint.unknown()), (1, 1));
    assert_eq!(joint.calls(), 1, "disposal reduces nothing");
    assert_eq!(staging.history_disposed(), 2);
    assert_eq!(staging.mode(), FeedMode::S1Only);
    // The same incarnation continues S1Only: fresh H3 calls reduce
    // directly through ordinary S1.
    let mut fresh = SemanticCall {
        function: "C_SignInit".into(),
        session: 7,
        mechanism: RSA_PKCS,
        capture: init_capture(),
        ..SemanticCall::default()
    };
    fresh.ts_ns = 999;
    let origin = EffectOrigin::from(&fresh);
    joint.observe_with_effects(&fresh, &origin, &mut joint_sink);
    assert_eq!(joint.started(), 2);
    assert_eq!(joint_sink.len(), 3);
}

/// G11/H9-§1: staging is bounded (N/N+1 backpressures), open
/// terminals hold without replay, and correlation breaks refuse
/// loudly with staging intact.
#[test]
fn key_operation_joint_staging_bounds() {
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    use crate::semantics_key_use::JOINT_STAGING_CAPACITY;

    // --- N/N+1: 1,024 stage, the 1,025th backpressures. ---
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    for position in 1..=JOINT_STAGING_CAPACITY as u64 {
        let facts = SemanticCall {
            function: "C_Sign".into(),
            ts_ns: position,
            ..SemanticCall::default()
        };
        let origin = EffectOrigin::from(&facts);
        staging
            .stage(facts, origin, position, scene.adapter.ledger_mut())
            .expect("N stages");
    }
    assert_eq!(staging.staged_len(), JOINT_STAGING_CAPACITY);
    let facts = SemanticCall {
        function: "C_Sign".into(),
        ..SemanticCall::default()
    };
    let origin = EffectOrigin::from(&facts);
    assert_eq!(
        staging.stage(
            facts,
            origin,
            JOINT_STAGING_CAPACITY as u64 + 1,
            scene.adapter.ledger_mut()
        ),
        Err(StagingRefusal::Full)
    );
    assert_eq!(staging.staged_len(), JOINT_STAGING_CAPACITY);

    // --- An open terminal holds: begin-only seals settle the call
    // without its END, and nothing replays until the END seals. ---
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut sink = Vec::new();
    let mut keyuse = KeyUseReducer::new();
    let call = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    attest_and_stage(&mut scene, &mut staging, &call);
    scene.sequence += 1;
    let fid = crate::kinds::function_id(call.name).unwrap();
    let begin = begin_bytes_shaped(
        scene.thread,
        scene.sequence,
        fid,
        0,
        (COOKIE, EXEC),
        SESSION,
        call.mechanism,
        call.capture,
        None,
        None,
        call.flags,
    );
    assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
    let success = scene.seal().expect("begin-only quantum seals");
    assert_eq!(success.prefix.settled().len(), 1);
    assert!(success.prefix.settled()[0].end_cut.is_none());
    let (outcome, refused) = staging.apply_seal(
        &success,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::Held);
    assert_eq!(refused, 0);
    assert_eq!(joint.calls(), 0, "open terminal reduces nothing");
    assert_eq!(staging.staged_len(), 1);
    assert_eq!(staging.correlation_refusals(), 0, "a hold is not a refusal");
    // The END lands: the same head replays exactly once.
    assert_eq!(
        scene.ingest(&end_bytes_absent(&begin, CkRv::OK.0, ENTRY_NS + 60)),
        JournalDisposition::EndStaged
    );
    let success = scene.seal().expect("terminal quantum seals");
    let (outcome, _) = staging.apply_seal(
        &success,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    assert_eq!(joint.calls(), 1);
    assert_eq!(staging.reduced(), 1);

    // Legacy scalar algorithm input refuses multicall. The genuine frame
    // key_operation_joint_batch_replays_exact_order covers production batching
    // with its original actual-End steps and shared bounded work cursor.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut sink = Vec::new();
    let mut keyuse = KeyUseReducer::new();
    for call in sign_flow().into_iter().take(2) {
        prepare_call(&mut scene, &mut staging, &call);
    }
    let success = scene.seal().expect("two-call quantum seals");
    assert_eq!(success.prefix.settled().len(), 2);
    let (outcome, refused) = staging.apply_seal(
        &success,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::Held);
    assert_eq!(refused, 0);
    assert_eq!(staging.correlation_refusals(), 1);
    assert_eq!(staging.staged_len(), 2, "refusal keeps staging");
    assert_eq!(joint.calls(), 0);

    // --- A settled-but-never-staged call refuses on function. ---
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut sink = Vec::new();
    let mut keyuse = KeyUseReducer::new();
    attest_and_stage(
        &mut scene,
        &mut staging,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    attest_and_ingest(
        &mut scene,
        &ShapedS1::shaped("C_VerifyInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    let success = scene.seal().expect("quantum seals");
    assert_eq!(success.prefix.settled().len(), 1);
    let (outcome, _) = staging.apply_seal(
        &success,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::Held);
    assert_eq!(staging.correlation_refusals(), 1);
    assert_eq!(staging.staged_len(), 1);
    assert_eq!(joint.calls(), 0);
}

/// G11/H9-§1: transient seal failures retry untouched, H3's own loss
/// degrades, and post-degradation seal outcomes are inert.
#[test]
fn key_operation_joint_retry_and_degraded_inert() {
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    // --- H3Pending retries: staging and reducer untouched. ---
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut sink = Vec::new();
    let mut keyuse = KeyUseReducer::new();
    prepare_call(
        &mut scene,
        &mut staging,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    scene.install_closure();
    let frontier = scene.adapter.consumed_frontier();
    let consumed = scene.adapter.consumed_through_for_test();
    let audit = JournalAuditReceipt::scripted_h0(
        7,
        7,
        None,
        0,
        H3DispositionEvidence::scripted_clean(consumed),
        scene.fixture.attachment().generation(),
        consumed + 10,
    );
    let fresh = SessionBirthEvidence::scripted_for_receipt(&bootstrap);
    let cell = SteadyFaultCell(7);
    let mut births = ScriptedBirthSource::once(fresh);
    let failure = scene
        .adapter
        .seal(
            &mut scene.model,
            &audit,
            &bootstrap,
            frontier,
            &mut births,
            &cell,
        )
        .expect_err("short H3 coverage pends");
    assert_eq!(failure.gap, JournalGap::H3Pending);
    let mut h3 = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    let (outcome, refused) = staging.apply_algorithm_failure_for_test(
        &failure,
        &mut h3,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, FailureApplyOutcome::Retried);
    assert_eq!(refused, 0);
    assert_eq!(staging.mode(), FeedMode::Joint);
    assert_eq!(staging.staged_len(), 1);
    assert_eq!(joint.calls(), 0);

    // --- H3's own loss barrier degrades through the fallback gap. ---
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut sink = Vec::new();
    let mut keyuse = KeyUseReducer::new();
    for call in sign_flow().into_iter().take(2) {
        prepare_call(&mut scene, &mut staging, &call);
    }
    scene.install_closure();
    // Own established domain, deliberately invalid birth cut: a proof
    // refusal scopes fallback here; a foreign request must remain inert.
    let refused_bootstrap = BootstrapReceipt::scripted(
        scene.proof,
        BirthKind::ExecMarker,
        u64::MAX,
        scene.fixture.attachment().generation(),
    );
    let frontier = scene.adapter.consumed_frontier();
    let audit = JournalAuditReceipt::scripted(
        7,
        7,
        None,
        0,
        H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through_for_test()),
        scene.fixture.attachment().generation(),
    );
    let fresh = SessionBirthEvidence::scripted_for_receipt(&refused_bootstrap);
    let cell = SteadyFaultCell(7);
    let mut births = ScriptedBirthSource::once(fresh);
    let failure = scene
        .adapter
        .seal(
            &mut scene.model,
            &audit,
            &refused_bootstrap,
            frontier,
            &mut births,
            &cell,
        )
        .expect_err("own birth proof mismatches");
    assert_eq!(failure.gap, JournalGap::BootstrapMismatch);
    let mut loss_source = ScriptedH3Source::once(H3DispositionEvidence::scripted_loss(5));
    let (outcome, refused) = staging.apply_algorithm_failure_for_test(
        &failure,
        &mut loss_source,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, FailureApplyOutcome::Degraded { disposed: 2 });
    assert_eq!(refused, 0);
    assert_eq!(staging.history_disposed(), 2);
    assert_eq!(staging.mode(), FeedMode::S1Only);
    assert_eq!(joint.calls(), 0, "loss disposes without reducing");

    // --- Post-degradation outcomes are inert, never touching S1Only. ---
    let calls_before = joint.calls();
    let (outcome, refused) = staging.apply_algorithm_failure_for_test(
        &failure,
        &mut loss_source,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, FailureApplyOutcome::Ignored);
    assert_eq!(refused, 0);
    assert_eq!(joint.calls(), calls_before);
    // A stray seal settling a real call still holds via the mode
    // guard without counting a correlation refusal.
    attest_and_ingest(
        &mut scene,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let stray = scene.seal().expect("H8 still seals; H9 no longer consumes");
    assert!(
        !stray.prefix.settled().is_empty(),
        "stray seal settles real calls the degraded feed ignores"
    );
    let (outcome, refused) = staging.apply_seal(
        &stray,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::Held);
    assert_eq!(refused, 0);
    assert_eq!(staging.correlation_refusals(), 0);
    assert_eq!(joint.calls(), calls_before);
}

/// G11/H9-§1: a bounded-abandonment quantum replays its definite S1
/// payload (the abandonment bounds only the object outcome, never
/// the completed H3 observation).
#[test]
fn key_operation_abandoned_quantum_replays_s1() {
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut joint_sink = Vec::new();
    let mut keyuse = KeyUseReducer::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();
    let call = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let (facts, _) = attest_and_stage(&mut scene, &mut staging, &call);
    scene.sequence += 1;
    let fid = crate::kinds::function_id(call.name).unwrap();
    let begin = begin_bytes_shaped(
        scene.thread,
        scene.sequence,
        fid,
        0,
        (COOKIE, EXEC),
        SESSION,
        call.mechanism,
        call.capture,
        None,
        None,
        call.flags,
    );
    assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
    assert_eq!(
        scene.ingest_ordinary(ordinary_for(&begin, CkRv::OK.0)),
        JournalDisposition::ReturnObserved
    );
    assert_eq!(
        scene.ingest(&abandon_bytes(
            scene.thread,
            scene.sequence,
            JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
            (COOKIE, EXEC)
        )),
        JournalDisposition::AbandonStaged
    );
    let success = scene.seal().expect("bounded-abandon quantum seals");
    assert_eq!(success.prefix.settled().len(), 1);
    assert!(success.prefix.settled()[0].abandoned);
    let (outcome, refused) = staging.apply_seal(
        &success,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    assert_eq!(refused, 0);
    let origin = EffectOrigin::from(&facts);
    direct.observe_with_effects(&facts, &origin, &mut direct_sink);
    assert_eq!(strip_receipts(&joint_sink), direct_sink);
    assert_s1_equal(&joint, &direct);
    assert_eq!((joint.started(), joint.completed()), (1, 0));
}

/// G29/H9-§2: the S1 matrix (failed Init, size query, too-small
/// retry, multipart, message context, cancellation) holds
/// N3: proof-only fallback invalidates before it replays: the
/// seal failure's retirement effects close the open key association
/// first, so the replayed S1 terminal cannot complete a now-unproved
/// binding — earlier completed history stands, and the primary S1
/// outcome routes once to the unknown-key summary.
#[test]
fn key_operation_fallback_invalidates_before_replay() {
    use crate::discovery::caller_registry::instance_input::RegistryInstanceId;

    let instance = RegistryInstanceId::from_raw(3);
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    // The terminal stages; then proof fails while the model retires
    // the key (loss): the fallback must invalidate first.
    let terminal = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    attest_and_stage(&mut scene, &mut staging, &terminal);
    let effects = scene.model.invalidate(
        crate::semantics_objects::AffectedScope::Capture,
        crate::semantics_objects::ObjectGap::Loss,
        scene.adapter.ledger_mut(),
    );
    assert!(
        effects.effects.iter().any(|effect| matches!(
            effect,
            crate::semantics_objects::ObjectEffect::Retired { .. }
        )),
        "non-vacuous: invalidation retires the key"
    );
    let failure = scene
        .adapter
        .scripted_failure(JournalGap::ClosureStale, &bootstrap, effects);
    let mut clean = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    let (outcome, _) = staging.apply_algorithm_failure_for_test(
        &failure,
        &mut clean,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, FailureApplyOutcome::FellBack { replayed: 1 });
    assert_eq!(joint.completed(), 1, "proof-only loss preserves S1");
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert!(
        committed
            .key_operations
            .iter()
            .all(|row| row.completed == 0),
        "fallback must not complete a now-unproved key binding: {:?}",
        committed.key_operations
    );
    let lost = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("earlier association history stands");
    assert_eq!((lost.started, lost.key_join_lost), (1, 1));
    let terminal = committed
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "key_join_lost")
        .expect("the primary S1 outcome routes once to unknown-key");
    assert_eq!(terminal.completed, 1);
}

/// N3 remainder (fix round 2): a held multi-call quantum still
/// applies its qualified invalidations. The two-call seal (terminal
/// and destroy) holds S1 replay — H9 runs no batching — but the
/// destroyed key's open association closes at invalidation time
/// (active 0, lost 1), never held with the replay. The eventual
/// fallback terminal then routes once to unknown-key.
#[test]
fn key_operation_n3_held_multicall_applies_invalidations() {
    use crate::discovery::caller_registry::instance_input::RegistryInstanceId;

    let instance = RegistryInstanceId::from_raw(3);
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    // Ground the key with its label, then open one proved use.
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    let calls_before = joint.calls();
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("one open proved use");
    assert_eq!(
        (row.active, row.key_join_lost),
        (1, 0),
        "precondition: the Init association is live"
    );

    // The terminal plus the destroy settle in one quantum: replay
    // holds, the invalidation must not.
    prepare_call(
        &mut scene,
        &mut staging,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    prepare_call(
        &mut scene,
        &mut staging,
        &ShapedS1::shaped("C_DestroyObject", CkRv::OK.0, 0, 0),
    );
    let success = scene.seal().expect("two-call quantum seals");
    assert_eq!(success.prefix.settled().len(), 2);
    let (outcome, refused) = staging.apply_seal(
        &success,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::Held);
    assert_eq!(refused, 0);
    assert_eq!(staging.staged_len(), 2, "the held quantum keeps staging");
    assert_eq!(
        joint.calls(),
        calls_before,
        "the held quantum replays nothing"
    );
    let committed = commit(2, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("earlier association history stands");
    assert_eq!(
        (row.active, row.key_join_lost),
        (0, 1),
        "invalidation closes authority when it occurs"
    );

    // The eventual primary outcome still routes once (fallback).
    let failure = scene.adapter.scripted_failure(
        JournalGap::ClosureStale,
        &bootstrap,
        crate::semantics_objects::ObjectEffects::default(),
    );
    let mut clean = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    let (outcome, _) = staging.apply_algorithm_failure_for_test(
        &failure,
        &mut clean,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, FailureApplyOutcome::FellBack { replayed: 2 });
    let committed = commit(3, &[&staging], &scene.model.project(), &keyuse);
    let proved = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("earlier association history stands");
    assert_eq!((proved.completed, proved.key_join_lost), (0, 1));
    let terminal = committed
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "key_join_lost")
        .expect("the eventual primary outcome routes once to unknown-key");
    assert_eq!(terminal.completed, 1);
}

/// N3 remainder (fix round 2): failure-completeness holds still
/// apply their qualified invalidations. HeldForCompleteness and
/// Retried keep staging and S1 intact while the retired association
/// closes immediately; the later fallback still routes once.
#[test]
fn key_operation_n3_held_failure_paths_apply_invalidations() {
    use crate::discovery::caller_registry::instance_input::RegistryInstanceId;

    let instance = RegistryInstanceId::from_raw(3);
    // --- HeldForCompleteness: proof-only gap, incomplete H3. ---
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    let terminal = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    attest_and_stage(&mut scene, &mut staging, &terminal);
    let calls_before = joint.calls();
    let effects = scene.model.invalidate(
        crate::semantics_objects::AffectedScope::Capture,
        crate::semantics_objects::ObjectGap::Loss,
        scene.adapter.ledger_mut(),
    );
    assert!(
        effects.effects.iter().any(|effect| matches!(
            effect,
            crate::semantics_objects::ObjectEffect::Retired { .. }
        )),
        "non-vacuous: invalidation retires the key"
    );
    let failure = scene
        .adapter
        .scripted_failure(JournalGap::ClosureStale, &bootstrap, effects);
    let mut pending = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean_pending(
        u64::MAX,
        Some(1),
    ));
    let (outcome, refused) = staging.apply_algorithm_failure_for_test(
        &failure,
        &mut pending,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, FailureApplyOutcome::HeldForCompleteness);
    assert_eq!(refused, 0);
    assert_eq!(staging.staged_len(), 1, "completeness holds keep staging");
    assert_eq!(
        joint.calls(),
        calls_before,
        "completeness holds reduce nothing"
    );
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("earlier association history stands");
    assert_eq!(
        (row.active, row.key_join_lost),
        (0, 1),
        "invalidation closes authority when it occurs"
    );
    // The later fallback still routes the primary outcome once.
    let mut clean = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    let failure = scene.adapter.scripted_failure(
        JournalGap::ClosureStale,
        &bootstrap,
        crate::semantics_objects::ObjectEffects::default(),
    );
    let (outcome, _) = staging.apply_algorithm_failure_for_test(
        &failure,
        &mut clean,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, FailureApplyOutcome::FellBack { replayed: 1 });
    let committed = commit(2, &[&staging], &scene.model.project(), &keyuse);
    let terminal = committed
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "key_join_lost")
        .expect("the eventual primary outcome routes once to unknown-key");
    assert_eq!(terminal.completed, 1);

    // --- Retried: transient gaps wait, but never swallow the
    // refusal's own invalidations. ---
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    let terminal = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    attest_and_stage(&mut scene, &mut staging, &terminal);
    let calls_before = joint.calls();
    let effects = scene.model.invalidate(
        crate::semantics_objects::AffectedScope::Capture,
        crate::semantics_objects::ObjectGap::Loss,
        scene.adapter.ledger_mut(),
    );
    let failure = scene
        .adapter
        .scripted_failure(JournalGap::H3Pending, &bootstrap, effects);
    let mut h3 = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    let (outcome, refused) = staging.apply_algorithm_failure_for_test(
        &failure,
        &mut h3,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, FailureApplyOutcome::Retried);
    assert_eq!(refused, 0);
    assert_eq!(staging.staged_len(), 1, "retries keep staging");
    assert_eq!(joint.calls(), calls_before, "retries reduce nothing");
    let committed = commit(3, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("earlier association history stands");
    assert_eq!(
        (row.active, row.key_join_lost),
        (0, 1),
        "retries never swallow invalidations"
    );
}

/// N3: object retirement closes the live association at invalidation
/// time: the committed row shows no active association and one lost
/// join immediately — never a still-active row awaiting its S1
/// terminal — and the eventual terminal routes once to unknown-key
/// without double-closing.
#[test]
fn key_operation_retirement_closes_association_before_terminal() {
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    let key = sink
        .iter()
        .find_map(|effect| match effect {
            OperationEffect::Started { key_receipt, .. } => *key_receipt,
            _ => None,
        })
        .expect("init start carries its receipt")
        .key;
    keyuse.retire_object(key);
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("the live association publishes");
    assert_eq!(
        (row.active, row.key_join_lost),
        (0, 1),
        "retirement ends key authority immediately"
    );
    // The eventual S1 terminal routes once to unknown-key; the
    // proved bucket never double-closes.
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let committed = commit(2, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("history stands");
    assert_eq!((row.started, row.completed, row.key_join_lost), (1, 0, 1));
    let terminal = committed
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "key_join_lost")
        .expect("the S1 terminal routes once to unknown-key");
    assert_eq!(terminal.completed, 1);
}

/// N3: the success path retires before it replays: a session close
/// whose seal ends the session retires the open key association
/// first, so the close's own S1 terminal cannot complete a binding
/// the same seal just unproved.
#[test]
fn key_operation_success_path_retires_before_replay() {
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CloseSession", CkRv::OK.0, 0, 0),
    );
    assert_eq!(joint.started(), 1);
    assert_eq!(joint.cancelled(), 1, "the close cancels the live machine");
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("the association publishes");
    assert_eq!(
        (row.completed, row.cancelled, row.failed, row.unknown),
        (0, 0, 0, 0),
        "no proved outcome past retirement"
    );
    assert_eq!(row.key_join_lost, 1);
    let terminal = committed
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "key_join_lost")
        .expect("the close terminal routes once to unknown-key");
    assert_eq!(terminal.cancelled, 1);
}

/// C2: a seal binds its EXACT staged call and consumes the claim
/// once. Re-applying the same single-call seal refuses (Held) even
/// when another same-function call stages; foreign, delayed,
/// reordered and differently-shaped applications refuse without
/// replaying or consuming anything.
#[test]
fn key_operation_seal_binds_exact_call_once() {
    use crate::discovery::caller_registry::instance_input::RegistryInstanceId;

    let instance = RegistryInstanceId::from_raw(3);
    // Repeated seal: the same seal applied to a second same-function
    // staged call refuses — the first replay consumed the claim.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let shaped = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    prepare_call(&mut scene, &mut staging, &shaped);
    let seal = scene.seal().expect("init quantum seals");
    let (outcome, _) = staging.apply_seal(
        &seal,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    let staged_before = joint.started();
    prepare_call(&mut scene, &mut staging, &shaped);
    let (outcome, _) = staging.apply_seal(
        &seal,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(
        outcome,
        SealApplyOutcome::Held,
        "a consumed seal never replays"
    );
    assert_eq!(joint.started(), staged_before, "nothing replays on refusal");
    assert_eq!(staging.correlation_refusals(), 1);

    // Foreign session: the staged head and the sealed call name
    // different sessions — refusal leaves staging intact.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let foreign_staged = ShapedS1 {
        session: Some(SESSION + 100),
        ..ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture())
    };
    attest_and_stage(&mut scene, &mut staging, &foreign_staged);
    let foreign_sealed = ShapedS1 {
        session: Some(SESSION + 200),
        ..ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture())
    };
    attest_and_ingest(&mut scene, &foreign_sealed);
    let seal = scene.seal().expect("foreign quantum seals");
    let (outcome, _) = staging.apply_seal(
        &seal,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(
        outcome,
        SealApplyOutcome::Held,
        "foreign seals never replay"
    );
    assert_eq!(staging.staged_len(), 1, "the head stays staged");
    assert_eq!(joint.started(), 0);

    // Differently-shaped mechanism: VALUE staged, NULL sealed.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let shaped_value = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    attest_and_stage(&mut scene, &mut staging, &shaped_value);
    let shaped_null = ShapedS1 {
        mechanism: 0,
        capture: capture::MECHANISM_NULL | capture::OUTPUT_NON_NULL,
        ..ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture())
    };
    attest_and_ingest(&mut scene, &shaped_null);
    let seal = scene.seal().expect("reshaped quantum seals");
    let (outcome, _) = staging.apply_seal(
        &seal,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(
        outcome,
        SealApplyOutcome::Held,
        "reshaped seals never replay"
    );
    assert_eq!(staging.staged_len(), 1);

    // Delayed/reordered: the seal names the second staged call while
    // the head is a different call — refusal, no skip-ahead.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let first = ShapedS1 {
        session: Some(SESSION + 300),
        ..ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture())
    };
    let second = ShapedS1 {
        session: Some(SESSION + 400),
        ..ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture())
    };
    attest_and_stage(&mut scene, &mut staging, &first);
    attest_and_stage(&mut scene, &mut staging, &second);
    attest_and_ingest(&mut scene, &second);
    let seal = scene.seal().expect("reordered quantum seals");
    let (outcome, _) = staging.apply_seal(
        &seal,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::Held, "seals never skip the head");
    assert_eq!(staging.staged_len(), 2);
}

/// identically through S1Only-direct and Joint replay; S2/S3
/// close/destroy/session scope appears only in Joint; fallback
/// preserves S1 without inventing object facts.
#[test]
fn key_operation_s1_matrix_through_both_feeds() {
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    use crate::semantics_objects::Lifetime;

    const CKF_SIGN: u64 = 0x0000_0800;
    let matrix = vec![
        ShapedS1::shaped("C_OpenSession", CkRv::OK.0, 0, 0),
        ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
        ShapedS1::shaped(
            "C_SignInit",
            CkRv::OPERATION_ACTIVE.0,
            RSA_PKCS,
            init_capture(),
        ),
        ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
        ShapedS1::shaped("C_Sign", CkRv::BUFFER_TOO_SMALL.0, 0, op_capture()),
        ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, query_capture()),
        ShapedS1::shaped("C_SignUpdate", CkRv::OK.0, 0, op_capture()),
        ShapedS1::shaped("C_SignUpdate", CkRv::OK.0, 0, op_capture()),
        ShapedS1::shaped("C_SignUpdate", CkRv::OK.0, 0, op_capture()),
        ShapedS1::shaped("C_SignFinal", CkRv::OK.0, 0, op_capture()),
        ShapedS1::shaped("C_MessageSignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
        ShapedS1::shaped("C_SignMessage", CkRv::OK.0, 0, op_capture()),
        ShapedS1::shaped("C_MessageSignFinal", CkRv::OK.0, 0, op_capture()),
        ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
        ShapedS1 {
            flags: CKF_SIGN,
            ..ShapedS1::shaped("C_SessionCancel", CkRv::OK.0, 0, 0)
        },
        ShapedS1::shaped("C_DestroyObject", CkRv::OK.0, 0, 0),
        ShapedS1::shaped("C_CloseSession", CkRv::OK.0, 0, 0),
    ];

    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut joint_sink = Vec::new();
    let mut keyuse = KeyUseReducer::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();
    for call in &matrix {
        let (facts, _) = prepare_call(&mut scene, &mut staging, call);
        let success = scene.seal().expect("matrix quantum seals");
        assert_eq!(success.prefix.settled().len(), 1, "{}", call.name);
        let (outcome, refused) = staging.apply_seal(
            &success,
            &scene.model,
            scene.adapter.ledger_mut(),
            &mut joint,
            &mut keyuse,
            instance,
            &mut joint_sink,
            None,
        );
        assert_eq!(outcome, SealApplyOutcome::ReplayedOne, "{}", call.name);
        assert_eq!(refused, 0);
        let origin = EffectOrigin::from(&facts);
        direct.observe_with_effects(&facts, &origin, &mut direct_sink);
        assert_eq!(strip_receipts(&joint_sink), direct_sink, "{}", call.name);
        assert_s1_equal(&joint, &direct);
    }
    assert_eq!(joint.calls(), 17);
    assert_eq!(
        (joint.started(), joint.completed(), joint.cancelled()),
        (3, 2, 1)
    );
    assert_eq!(
        (joint.failed(), joint.unknown(), joint.orphans()),
        (0, 0, 0)
    );

    // S2/S3 scope belongs to Joint: the model proves the destroy and
    // the session; the S1Only twin is a bare reducer (no objects).
    let projection = scene.model.project();
    assert_eq!(projection.objects.len(), 1);
    assert_eq!(projection.objects[0].lifetime, Lifetime::Destroyed);
    assert!(!projection.sessions.is_empty(), "Joint proves the session");

    // Fallback preserves S1 without inventing object facts: the
    // model snapshot is identical across the fallback replay.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut joint_sink = Vec::new();
    let mut keyuse = KeyUseReducer::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();
    for call in matrix.iter().take(2) {
        let (facts, _) = prepare_call(&mut scene, &mut staging, call);
        let success = scene.seal().expect("grounding quantum seals");
        let (outcome, _) = staging.apply_seal(
            &success,
            &scene.model,
            scene.adapter.ledger_mut(),
            &mut joint,
            &mut keyuse,
            instance,
            &mut joint_sink,
            None,
        );
        assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
        let origin = EffectOrigin::from(&facts);
        direct.observe_with_effects(&facts, &origin, &mut direct_sink);
    }
    let before = scene.model.project();
    assert_eq!(before.objects.len(), 1, "grounding created the key");
    let mut staged_facts = Vec::new();
    for call in matrix.iter().skip(2).take(3) {
        staged_facts.push(attest_and_stage(&mut scene, &mut staging, call).0);
    }
    scene.install_closure();
    // Own established domain, deliberately invalid birth cut: a proof
    // refusal scopes fallback here; a foreign request must remain inert.
    let refused_bootstrap = BootstrapReceipt::scripted(
        scene.proof,
        BirthKind::ExecMarker,
        u64::MAX,
        scene.fixture.attachment().generation(),
    );
    let frontier = scene.adapter.consumed_frontier();
    let audit = JournalAuditReceipt::scripted(
        7,
        7,
        None,
        0,
        H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through_for_test()),
        scene.fixture.attachment().generation(),
    );
    let fresh = SessionBirthEvidence::scripted_for_receipt(&refused_bootstrap);
    let cell = SteadyFaultCell(7);
    let mut births = ScriptedBirthSource::once(fresh);
    let failure = scene
        .adapter
        .seal(
            &mut scene.model,
            &audit,
            &refused_bootstrap,
            frontier,
            &mut births,
            &cell,
        )
        .expect_err("own birth proof mismatches");
    let mut clean = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    let (outcome, _) = staging.apply_algorithm_failure_for_test(
        &failure,
        &mut clean,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
        None,
    );
    assert_eq!(outcome, FailureApplyOutcome::FellBack { replayed: 3 });
    for facts in &staged_facts {
        let origin = EffectOrigin::from(facts);
        direct.observe_with_effects(facts, &origin, &mut direct_sink);
    }
    assert_eq!(strip_receipts(&joint_sink), direct_sink);
    assert_s1_equal(&joint, &direct);
    assert_eq!(
        scene.model.project(),
        before,
        "fallback invents no object facts"
    );
}

// ==================== Message units: contexts, never signatures ====================

/// Drive one Joint quantum plus the S1Only-direct twin: the twin
/// reduces the same proved payload, and effects (sans receipts)
/// plus S1 counters agree after every call.
#[allow(clippy::too_many_arguments)] // One explicit quantum per axis: scene, staging, both reducers, both sinks, call.
fn drive_message_quantum(
    scene: &mut JointScene,
    staging: &mut JointStaging,
    joint: &mut EdgeSemantics,
    keyuse: &mut KeyUseReducer,
    joint_sink: &mut Vec<OperationEffect>,
    direct: &mut EdgeSemantics,
    direct_sink: &mut Vec<OperationEffect>,
    call: &ShapedS1,
) -> (SemanticCall, u64) {
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    let (facts, position) = prepare_call(scene, staging, call);
    let success = scene.seal().expect("message quantum seals");
    assert_eq!(success.prefix.settled().len(), 1, "{}", call.name);
    let (outcome, refused) = staging.apply_seal(
        &success,
        &scene.model,
        scene.adapter.ledger_mut(),
        joint,
        keyuse,
        instance,
        joint_sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne, "{}", call.name);
    assert_eq!(refused, 0, "{}", call.name);
    let origin = EffectOrigin::from(&facts);
    direct.observe_with_effects(&facts, &origin, direct_sink);
    assert_eq!(strip_receipts(joint_sink), *direct_sink, "{}", call.name);
    assert_s1_equal(joint, direct);
    (facts, position)
}

/// Ground one labelled RSA key: create plus the Class/KeyType/
/// ModulusBits GET the role tests pin to `rsa_2048`.
fn drive_message_grounding(
    scene: &mut JointScene,
    staging: &mut JointStaging,
    joint: &mut EdgeSemantics,
    keyuse: &mut KeyUseReducer,
    joint_sink: &mut Vec<OperationEffect>,
    direct: &mut EdgeSemantics,
    direct_sink: &mut Vec<OperationEffect>,
) {
    let create = ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0);
    drive_message_quantum(
        scene,
        staging,
        joint,
        keyuse,
        joint_sink,
        direct,
        direct_sink,
        &create,
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_message_quantum(
        scene,
        staging,
        joint,
        keyuse,
        joint_sink,
        direct,
        direct_sink,
        &get,
    );
}

/// Message units: one init/update/final lifetime is ONE message
/// context, however many per-message calls it carries. Five updates
/// retain the context without effects; the final completes exactly
/// one context; the proved row counts `message_contexts`, never
/// signatures — through seal, reducer and projection.
#[test]
fn key_operation_message_context_counts_contexts_not_signatures() {
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut joint_sink = Vec::new();
    let mut keyuse = KeyUseReducer::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();

    drive_message_grounding(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
    );
    let init = ShapedS1::shaped("C_MessageSignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    drive_message_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
        &init,
    );
    // Non-vacuous: the context bound the labelled key as its
    // operation key.
    let (id, category, _, _) = started(joint_sink.last().expect("init starts the context"));
    assert_eq!(category, "message_sign");
    let receipt = match joint_sink.last() {
        Some(OperationEffect::Started {
            key_receipt: Some(receipt),
            ..
        }) => *receipt,
        other => panic!("init binds a receipt, got {other:?}"),
    };
    assert_eq!(receipt.role, KeyRole::OperationKey);
    assert_eq!(
        receipt.label,
        Some(crate::semantics_objects::KeyLabel::Rsa { modulus_bits: 2048 })
    );

    // Five per-message updates retain the one context: no new effects.
    // (The Joint attestation fixture admits only the `C_SignMessage`
    // spelling; the Begin/Next spellings share its RETAIN_ALWAYS
    // descriptor arm and pin at the S1Only-direct seam below.)
    for name in [
        "C_SignMessage",
        "C_SignMessage",
        "C_SignMessage",
        "C_SignMessage",
        "C_SignMessage",
    ] {
        let update = ShapedS1::shaped(name, CkRv::OK.0, 0, op_capture());
        let before = joint_sink.len();
        drive_message_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut joint_sink,
            &mut direct,
            &mut direct_sink,
            &update,
        );
        assert_eq!(joint_sink.len(), before, "{name} retains the context");
    }
    assert_eq!(
        joint.active_summary(),
        vec![("message_sign".to_string(), OpState::InProgress, 1)]
    );
    assert_eq!(
        (joint.started(), joint.completed(), joint.orphans()),
        (1, 0, 0)
    );

    // Mid-flow link: one open context, unit `message_contexts`.
    let mid = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!((mid.status, mid.reason), (ObsStatus::Populated, "none"));
    let row = mid
        .key_operations
        .iter()
        .find(|row| row.category == "message_sign")
        .expect("one open proved context");
    assert_eq!(row.unit, "message_contexts");
    assert_eq!((row.started, row.completed, row.active), (1, 0, 1));
    assert!(
        mid.unknown_key_operations
            .iter()
            .all(|row| row.category != "message_sign"),
        "the bound context rows proved, never unknown: {:?}",
        mid.unknown_key_operations
    );

    // The final completes exactly one context — not five signatures.
    let terminal = ShapedS1::shaped("C_MessageSignFinal", CkRv::OK.0, 0, op_capture());
    drive_message_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
        &terminal,
    );
    let (end_id, category, outcome, _) = ended(joint_sink.last().expect("final ends the context"));
    assert_eq!(
        (end_id, category, outcome),
        (id, "message_sign", OperationOutcome::Completed)
    );
    assert!(
        joint_sink
            .iter()
            .all(|effect| !matches!(effect, OperationEffect::DirectCompleted { .. })),
        "message flows never complete direct"
    );
    assert_eq!((joint.started(), joint.completed()), (1, 1));

    let committed = commit(2, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(
        (committed.status, committed.reason),
        (ObsStatus::Populated, "none")
    );
    assert_eq!(committed.revision, 2);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "message_sign")
        .expect("the completed proved context");
    assert_eq!(row.unit, "message_contexts");
    assert_eq!(
        (
            row.started,
            row.completed,
            row.failed,
            row.cancelled,
            row.active
        ),
        (1, 1, 0, 0, 0),
        "one context completed, however many messages it carried"
    );
    assert_eq!((row.role, row.metadata_at_use), ("key", "rsa_2048"));
    assert_eq!(committed.budgets.key_occupied, 1);
    assert!(
        committed.unknown_key_operations.is_empty(),
        "no unknown rows: {:?}",
        committed.unknown_key_operations
    );
}

/// Message units: a failed final retains the context without a
/// terminal — the attempt invents no keys and moves no rows — and
/// the retained context still completes exactly once.
#[test]
fn key_operation_message_failed_final_retains_context_without_terminal() {
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut joint_sink = Vec::new();
    let mut keyuse = KeyUseReducer::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();

    drive_message_grounding(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
    );
    let init = ShapedS1::shaped("C_MessageSignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    drive_message_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
        &init,
    );
    let (id, _, _, _) = started(joint_sink.last().expect("init starts the context"));

    let failed = ShapedS1::shaped(
        "C_MessageSignFinal",
        CkRv::FUNCTION_FAILED.0,
        0,
        op_capture(),
    );
    let before = joint_sink.len();
    drive_message_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
        &failed,
    );
    assert_eq!(joint_sink.len(), before, "a failed final emits no terminal");
    assert_eq!(
        (
            joint.started(),
            joint.completed(),
            joint.failed(),
            joint.unknown()
        ),
        (1, 0, 0, 0)
    );
    assert!(joint.has_live_operations());
    assert_eq!(
        joint.active_summary(),
        vec![("message_sign".to_string(), OpState::InProgress, 1)]
    );
    // The failed terminal attempt invents no keys and moves no rows.
    let mid = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(keyuse.aggregates().len(), 1);
    let row = mid
        .key_operations
        .iter()
        .find(|row| row.category == "message_sign")
        .expect("the retained proved context");
    assert_eq!(
        (row.started, row.completed, row.failed, row.active),
        (1, 0, 0, 1)
    );
    assert!(
        mid.unknown_key_operations.is_empty(),
        "no unknown rows: {:?}",
        mid.unknown_key_operations
    );

    // The retained context still completes exactly once.
    let terminal = ShapedS1::shaped("C_MessageSignFinal", CkRv::OK.0, 0, op_capture());
    drive_message_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
        &terminal,
    );
    let (end_id, category, outcome, _) = ended(joint_sink.last().expect("final ends the context"));
    assert_eq!(
        (end_id, category, outcome),
        (id, "message_sign", OperationOutcome::Completed)
    );
    let committed = commit(2, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "message_sign")
        .expect("the completed proved context");
    assert_eq!(
        (row.completed, row.failed, row.active),
        (1, 0, 0),
        "the failed attempt left no failed terminal behind"
    );
    assert!(
        committed.unknown_key_operations.is_empty(),
        "no unknown rows: {:?}",
        committed.unknown_key_operations
    );
}

/// Message units: updates, finals and cross-session calls with no
/// live context orphan — even though a labelled key exists, nothing
/// binds it, and neither proved nor unknown rows appear.
#[test]
fn key_operation_message_missing_context_invents_no_keys() {
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut joint_sink = Vec::new();
    let mut keyuse = KeyUseReducer::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();

    drive_message_grounding(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
    );
    assert_eq!(
        scene.model.project().objects.len(),
        1,
        "non-vacuous: a key exists that nothing may bind"
    );

    let wrong_session = ShapedS1 {
        session: Some(SESSION + 100),
        ..ShapedS1::shaped("C_SignMessage", CkRv::OK.0, 0, op_capture())
    };
    // Only spellings the Joint attestation fixture admits; sibling
    // categories pin at the S1Only-direct seam below.
    let missing = [
        ShapedS1::shaped("C_SignMessage", CkRv::OK.0, 0, op_capture()),
        ShapedS1::shaped("C_SignMessage", CkRv::OK.0, 0, op_capture()),
        ShapedS1::shaped("C_MessageSignFinal", CkRv::OK.0, 0, op_capture()),
        ShapedS1::shaped(
            "C_MessageSignFinal",
            CkRv::FUNCTION_FAILED.0,
            0,
            op_capture(),
        ),
        ShapedS1::shaped("C_SignMessage", CkRv::OK.0, 0, op_capture()),
        wrong_session,
    ];
    for call in &missing {
        let before = joint_sink.len();
        drive_message_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut joint_sink,
            &mut direct,
            &mut direct_sink,
            call,
        );
        assert_eq!(joint_sink.len(), before, "{} joins no context", call.name);
    }
    // A cancel naming the message operation is inert with no live
    // context: no terminal, no orphan, no row.
    let cancel = ShapedS1 {
        flags: 0x0000_0008,
        ..ShapedS1::shaped("C_SessionCancel", CkRv::OK.0, 0, 0)
    };
    let before = joint_sink.len();
    drive_message_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
        &cancel,
    );
    assert_eq!(
        joint_sink.len(),
        before,
        "cancel on a missing context is inert"
    );
    assert_eq!(
        (joint.started(), joint.completed(), joint.orphans()),
        (0, 0, 6)
    );
    assert!(keyuse.aggregates().is_empty());
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(
        (committed.status, committed.reason),
        (ObsStatus::Populated, "none")
    );
    assert!(
        committed.key_operations.is_empty(),
        "no context started, no proved rows: {:?}",
        committed.key_operations
    );
    assert!(
        committed.unknown_key_operations.is_empty(),
        "no context started, no unknown rows either: {:?}",
        committed.unknown_key_operations
    );
}

/// Message units: a competing init replaces the shared context —
/// the old terminal emits before the new start, both bind the same
/// qualified key, and no third key is invented. A context is
/// per-session: another session's update joins nothing.
#[test]
fn key_operation_message_competing_init_replaces_without_new_keys() {
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut joint_sink = Vec::new();
    let mut keyuse = KeyUseReducer::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();

    drive_message_grounding(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
    );
    let first = ShapedS1::shaped("C_MessageSignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    drive_message_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
        &first,
    );
    let (id1, _, _, _) = started(joint_sink.last().expect("first init starts"));
    let key1 = match joint_sink.last() {
        Some(OperationEffect::Started {
            key_receipt: Some(receipt),
            ..
        }) => receipt.key,
        other => panic!("first init binds a receipt, got {other:?}"),
    };

    // The competing init ends the shared context cancelled, then
    // starts its own — in that order, on the same key.
    let second = ShapedS1::shaped("C_MessageSignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    drive_message_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
        &second,
    );
    let tail = &joint_sink[joint_sink.len() - 2..];
    let (end_id, end_category, end_outcome, _) = ended(&tail[0]);
    assert_eq!(
        (end_id, end_category, end_outcome),
        (id1, "message_sign", OperationOutcome::Cancelled)
    );
    let (id2, start_category, _, _) = started(&tail[1]);
    assert_eq!(start_category, "message_sign");
    assert_ne!(id1, id2, "the replacement is a new context");
    let receipt2 = match &tail[1] {
        OperationEffect::Started {
            key_receipt: Some(receipt),
            ..
        } => *receipt,
        other => panic!("replacement binds its own receipt, got {other:?}"),
    };
    assert_eq!(receipt2.role, KeyRole::OperationKey);
    assert_eq!(receipt2.key, key1, "same qualified key, no third key");

    // Another session's update joins nothing: contexts are per-session.
    let foreign = ShapedS1 {
        session: Some(SESSION + 100),
        ..ShapedS1::shaped("C_SignMessage", CkRv::OK.0, 0, op_capture())
    };
    let before = joint_sink.len();
    drive_message_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
        &foreign,
    );
    assert_eq!(
        joint_sink.len(),
        before,
        "a foreign-session update joins nothing"
    );

    let terminal = ShapedS1::shaped("C_MessageSignFinal", CkRv::OK.0, 0, op_capture());
    drive_message_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
        &terminal,
    );
    let (end_id, _, outcome, _) = ended(joint_sink.last().expect("final ends the context"));
    assert_eq!((end_id, outcome), (id2, OperationOutcome::Completed));
    assert_eq!(
        (
            joint.started(),
            joint.completed(),
            joint.cancelled(),
            joint.orphans()
        ),
        (2, 1, 1, 1)
    );

    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(keyuse.aggregates().len(), 1, "one shared-key bucket");
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "message_sign")
        .expect("the shared-key bucket");
    assert_eq!(row.unit, "message_contexts");
    assert_eq!(
        (row.started, row.completed, row.cancelled, row.active),
        (2, 1, 1, 0)
    );
    assert!(
        committed.unknown_key_operations.is_empty(),
        "no unknown rows: {:?}",
        committed.unknown_key_operations
    );
}

/// Message units: a cancel naming another operation leaves the
/// context live; a cancel naming the message operation ends it
/// cancelled — and the cancel itself invents no keys.
#[test]
fn key_operation_message_cancel_ends_context_without_new_keys() {
    // Mirrors src/semantics.rs (its CKF_* vocabulary is private there).
    const CKF_SIGN: u64 = 0x0000_0800;
    const CKF_MESSAGE_SIGN: u64 = 0x0000_0008;

    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut joint_sink = Vec::new();
    let mut keyuse = KeyUseReducer::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();

    drive_message_grounding(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
    );
    let init = ShapedS1::shaped("C_MessageSignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    drive_message_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
        &init,
    );
    let (id, _, _, _) = started(joint_sink.last().expect("init starts the context"));

    // A cancel naming another operation leaves the context live.
    let wrong = ShapedS1 {
        flags: CKF_SIGN,
        ..ShapedS1::shaped("C_SessionCancel", CkRv::OK.0, 0, 0)
    };
    let before = joint_sink.len();
    drive_message_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
        &wrong,
    );
    assert_eq!(
        joint_sink.len(),
        before,
        "a foreign-flag cancel ends nothing"
    );
    assert!(joint.has_live_operations());

    // A cancel naming the message operation ends it cancelled.
    let cancel = ShapedS1 {
        flags: CKF_MESSAGE_SIGN,
        ..ShapedS1::shaped("C_SessionCancel", CkRv::OK.0, 0, 0)
    };
    drive_message_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
        &cancel,
    );
    let (end_id, category, outcome, _) = ended(joint_sink.last().expect("cancel ends the context"));
    assert_eq!(
        (end_id, category, outcome),
        (id, "message_sign", OperationOutcome::Cancelled)
    );
    assert_eq!((joint.started(), joint.cancelled()), (1, 1));

    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(keyuse.aggregates().len(), 1);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "message_sign")
        .expect("the cancelled proved context");
    assert_eq!(row.unit, "message_contexts");
    assert_eq!((row.cancelled, row.completed, row.active), (1, 0, 0));
    assert!(
        committed.unknown_key_operations.is_empty(),
        "the cancel invents no keys: {:?}",
        committed.unknown_key_operations
    );
}

/// Message units: a context the model cannot bind rows unknown-key
/// with reason `unbound` — and the unknown row still counts
/// `message_contexts`, one completion per context. The S1Only-direct
/// twin rows the same unknown unit without object proof.
#[test]
fn key_operation_message_unbound_context_rows_message_contexts() {
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut joint_sink = Vec::new();
    let mut keyuse = KeyUseReducer::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();

    // Unreadable input: the model explicitly leaves the join
    // unresolved, so the context starts receipt-less.
    let unreadable = ShapedS1 {
        input0: Some((0, 2)),
        ..ShapedS1::shaped("C_MessageSignInit", CkRv::OK.0, RSA_PKCS, init_capture())
    };
    let (facts, _) = prepare_call(&mut scene, &mut staging, &unreadable);
    let success = scene.seal().expect("quantum seals");
    assert!(
        success.effects.effects.iter().any(|effect| matches!(
            effect,
            crate::semantics_objects::ObjectEffect::Unresolved { .. }
        )),
        "the model explicitly leaves the join unresolved"
    );
    assert!(
        success.effects.effects.iter().all(|effect| !matches!(
            effect,
            crate::semantics_objects::ObjectEffect::Referenced { .. }
        )),
        "no reference to associate"
    );
    let (outcome, _) = staging.apply_seal(
        &success,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    let origin = EffectOrigin::from(&facts);
    direct.observe_with_effects(&facts, &origin, &mut direct_sink);
    assert_eq!(strip_receipts(&joint_sink), direct_sink);
    assert_s1_equal(&joint, &direct);
    let (id, category, _, _) = started(joint_sink.last().expect("init starts the context"));
    assert_eq!(category, "message_sign");
    assert!(
        matches!(
            joint_sink.last(),
            Some(OperationEffect::Started {
                key_receipt: None,
                ..
            })
        ),
        "the context started receipt-less"
    );

    // Updates retain and the final completes — all without a key.
    for name in ["C_SignMessage", "C_SignMessage"] {
        let update = ShapedS1::shaped(name, CkRv::OK.0, 0, op_capture());
        let before = joint_sink.len();
        drive_message_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut joint_sink,
            &mut direct,
            &mut direct_sink,
            &update,
        );
        assert_eq!(joint_sink.len(), before, "{name} retains the context");
    }
    let terminal = ShapedS1::shaped("C_MessageSignFinal", CkRv::OK.0, 0, op_capture());
    drive_message_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut joint_sink,
        &mut direct,
        &mut direct_sink,
        &terminal,
    );
    let (end_id, _, outcome, _) = ended(joint_sink.last().expect("final ends the context"));
    assert_eq!((end_id, outcome), (id, OperationOutcome::Completed));

    assert!(keyuse.aggregates().is_empty(), "no key bound");
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "message_sign" && row.reason == "unbound")
        .expect("the keyless context rows unknown-key");
    assert_eq!(row.unit, "message_contexts");
    assert_eq!((row.completed, row.active), (1, 0));

    // S1Only-direct twin: no object proof, same unknown row and unit.
    let mut s1only = EdgeSemantics::default();
    let mut s1only_sink = Vec::new();
    let mut s1only_keyuse = KeyUseReducer::new();
    let mut assoc_ledger = StagingLedger::new();
    let c = init("C_MessageSignInit", 7, RSA_PKCS, 100);
    feed(&mut s1only, &mut s1only_sink, &c);
    let c = op("C_SignMessage", 7, 200);
    feed(&mut s1only, &mut s1only_sink, &c);
    let c = op("C_MessageSignFinal", 7, 300);
    feed(&mut s1only, &mut s1only_sink, &c);
    for effect in &s1only_sink {
        s1only_keyuse.observe_effect(instance, effect, Some(&mut assoc_ledger), None);
    }
    assert!(s1only_keyuse.aggregates().is_empty());
    let s1only_staging = JointStaging::select_s1_only();
    let twin = crate::key_operation_projection::producer::commit_with_journal_linked(
        1,
        &[&s1only_staging],
        &scene.model.project(),
        &s1only_keyuse,
        true,
    );
    assert_eq!(
        (twin.status, twin.reason),
        (ObsStatus::Unavailable, "bootstrap_unavailable")
    );
    let row = twin
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "message_sign" && row.reason == "unbound")
        .expect("the S1Only twin rows the same unknown unit");
    assert_eq!(row.unit, "message_contexts");
    assert_eq!((row.completed, row.active), (1, 0));
}

/// Message units at the S1Only-direct seam: every message category's
/// init/update/cancel flow counts `message_contexts` through the real
/// reducer and projection, and each category's cancel flag selects
/// exactly its own context. (The Joint attestation fixture admits
/// only the message_sign spellings, so the sibling categories and
/// update spellings pin here, where no H3 admission is needed — the
/// same S1Only path fallback feeds reduce.)
#[test]
fn key_operation_message_all_categories_count_contexts_direct() {
    // Mirrors src/semantics.rs (its CKF_* vocabulary is private there).
    let matrix = [
        (
            "C_MessageEncryptInit",
            "C_EncryptMessage",
            0x0000_0002u64,
            AES_GCM,
            "message_encrypt",
        ),
        (
            "C_MessageDecryptInit",
            "C_DecryptMessage",
            0x0000_0004u64,
            AES_GCM,
            "message_decrypt",
        ),
        (
            "C_MessageSignInit",
            "C_SignMessageBegin",
            0x0000_0008u64,
            RSA_PKCS,
            "message_sign",
        ),
        (
            "C_MessageVerifyInit",
            "C_VerifyMessageNext",
            0x0000_0010u64,
            RSA_PKCS,
            "message_verify",
        ),
    ];
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    let mut assoc_ledger = StagingLedger::new();
    let mut s1only = EdgeSemantics::default();
    let mut sink = Vec::new();
    let mut keyuse = KeyUseReducer::new();

    let mut ts = 100u64;
    for (init_fn, update_fn, flag, mechanism, category) in &matrix {
        let c = init(init_fn, 7, *mechanism, ts);
        ts += 100;
        let effects = feed(&mut s1only, &mut sink, &c);
        assert_eq!(effects.len(), 1, "{init_fn} starts its context");
        let (id, started_category, _, _) = started(&effects[0]);
        assert_eq!(started_category, *category);

        let c = op(update_fn, 7, ts);
        ts += 100;
        let effects = feed(&mut s1only, &mut sink, &c);
        assert!(effects.is_empty(), "{update_fn} retains the context");

        let mut c = call("C_SessionCancel", 7, CkRv::OK.0, ts);
        ts += 100;
        c.flags = *flag;
        let effects = feed(&mut s1only, &mut sink, &c);
        assert_eq!(effects.len(), 1, "the matching flag ends the context");
        let (end_id, end_category, outcome, _) = ended(&effects[0]);
        assert_eq!(
            (end_id, end_category, outcome),
            (id, *category, OperationOutcome::Cancelled)
        );
    }
    // One sibling completion, so `completed` units pin beyond cancel.
    let c = init("C_MessageVerifyInit", 7, RSA_PKCS, ts);
    let effects = feed(&mut s1only, &mut sink, &c);
    assert_eq!(effects.len(), 1);
    let c = op("C_VerifyMessage", 7, ts + 100);
    assert!(feed(&mut s1only, &mut sink, &c).is_empty());
    let c = op("C_MessageVerifyFinal", 7, ts + 200);
    let effects = feed(&mut s1only, &mut sink, &c);
    assert_eq!(effects.len(), 1);
    assert_eq!(ended(&effects[0]).2, OperationOutcome::Completed);

    assert!(
        sink.iter()
            .all(|effect| !matches!(effect, OperationEffect::DirectCompleted { .. })),
        "message flows never complete direct"
    );
    for effect in &sink {
        keyuse.observe_effect(instance, effect, Some(&mut assoc_ledger), None);
    }
    assert!(keyuse.aggregates().is_empty(), "no key bound");
    let scene = JointScene::new();
    let s1only_staging = JointStaging::select_s1_only();
    let committed = crate::key_operation_projection::producer::commit_with_journal_linked(
        1,
        &[&s1only_staging],
        &scene.model.project(),
        &keyuse,
        true,
    );
    assert_eq!(
        (committed.status, committed.reason),
        (ObsStatus::Unavailable, "bootstrap_unavailable")
    );
    for (_, _, _, _, category) in &matrix {
        let row = committed
            .unknown_key_operations
            .iter()
            .find(|row| row.category == *category && row.reason == "unbound")
            .expect("every message category rows its unit");
        assert_eq!(row.unit, "message_contexts");
        let completed = u64::from(*category == "message_verify");
        assert_eq!(
            (row.completed, row.cancelled, row.active),
            (completed, 1, 0),
            "{category}: one terminal per context"
        );
    }
}

// ==================== Checkbox 3: key receipts and rows ====================

use crate::semantics_edge::KeyRole;
use crate::semantics_key_use::KeyUseReducer;

/// Drive one Joint quantum to completion: prepare + seal + apply.
/// Returns the admitted payload, its H0 position and the seal.
fn drive_quantum(
    scene: &mut JointScene,
    staging: &mut JointStaging,
    reducer: &mut EdgeSemantics,
    keyuse: &mut KeyUseReducer,
    sink: &mut Vec<OperationEffect>,
    call: &ShapedS1,
) -> (SemanticCall, u64) {
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    let (facts, position) = prepare_call(scene, staging, call);
    let success = scene.seal().expect("quantum seals");
    assert_eq!(success.prefix.settled().len(), 1, "{}", call.name);
    let (outcome, refused) = staging.apply_seal(
        &success,
        &scene.model,
        scene.adapter.ledger_mut(),
        reducer,
        keyuse,
        instance,
        sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne, "{}", call.name);
    assert_eq!(refused, 0);
    (facts, position)
}

/// Feed one admitted call to the S1Only direct twin.
fn observe_direct(
    direct: &mut EdgeSemantics,
    sink: &mut Vec<OperationEffect>,
    facts: &SemanticCall,
) {
    let origin = EffectOrigin::from(facts);
    direct.observe_with_effects(facts, &origin, sink);
}

/// G11/H9-§1: Joint async flows through the carve-out: the PENDING
/// Init stages and seals (queuing S1-side), while the completion —
/// H8-negative-only, un-ingestable without tainting the image —
/// refuses staging and reduces S1Only-direct. Both feeds agree on
/// S1; the async-started machine rows unknown-key (its inputs never
/// join in the model), with explicit evidence.
#[test]
fn key_operation_joint_async_pending_then_direct_completion() {
    let mut assoc_ledger = StagingLedger::new();
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut joint_sink = Vec::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();

    // The PENDING Init is modelable: attest, stage, seal, replay,
    // queue — on both feeds.
    let pending = ShapedS1::shaped("C_SignInit", CkRv::PENDING.0, RSA_PKCS, init_capture());
    let (facts, _) = prepare_call(&mut scene, &mut staging, &pending);
    let success = scene.seal().expect("pending quantum seals");
    assert_eq!(success.prefix.settled().len(), 1);
    let (outcome, _) = staging.apply_seal(
        &success,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    let origin = EffectOrigin::from(&facts);
    direct.observe_with_effects(&facts, &origin, &mut direct_sink);
    assert_eq!(strip_receipts(&joint_sink), direct_sink);
    assert_s1_equal(&joint, &direct);
    assert_eq!(
        (joint.started(), joint.completed()),
        (0, 0),
        "queued, not started"
    );

    // The completion cannot stage (frozen negative-only table), so
    // the driver reduces it S1Only-direct on both feeds.
    let target = crate::kinds::function_id("C_SignInit").unwrap();
    let mut complete = SemanticCall {
        function: "C_AsyncComplete".into(),
        session: SESSION,
        target_function: target,
        capture: op_capture(),
        ts_ns: 999,
        ..SemanticCall::default()
    };
    complete.rv = CkRv::OK.0;
    let origin = EffectOrigin::from(&complete);
    assert_eq!(
        staging.stage(
            complete.clone(),
            origin.clone(),
            999,
            scene.adapter.ledger_mut()
        ),
        Err(StagingRefusal::Unsealable)
    );
    let effects_before = joint_sink.len();
    joint.observe_with_effects(&complete, &origin, &mut joint_sink);
    // The direct carve-out has no tee: the driver feeds the new
    // effects to the key-use reducer itself.
    for effect in &joint_sink[effects_before..] {
        keyuse.observe_effect(instance, effect, Some(&mut assoc_ledger), None);
    }
    direct.observe_with_effects(&complete, &origin, &mut direct_sink);
    assert_eq!(strip_receipts(&joint_sink), direct_sink);
    assert_s1_equal(&joint, &direct);
    assert_eq!(joint.started(), 1, "the completion starts the machine");
    let (_, _, _, corigin) = started(joint_sink.last().unwrap());
    assert_eq!(corigin.function, "C_SignInit", "original call identity");

    // The Sign completes the async-started machine on both feeds;
    // its row is unknown-key with explicit evidence.
    let sign = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    let (facts, _) = prepare_call(&mut scene, &mut staging, &sign);
    let success = scene.seal().expect("terminal quantum seals");
    let (outcome, _) = staging.apply_seal(
        &success,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    let origin = EffectOrigin::from(&facts);
    direct.observe_with_effects(&facts, &origin, &mut direct_sink);
    assert_eq!(strip_receipts(&joint_sink), direct_sink);
    assert_eq!((joint.started(), joint.completed()), (1, 1));
    assert!(
        keyuse.aggregates().is_empty(),
        "async start binds no receipt"
    );
    assert_eq!(keyuse.evidence().unknown_key_rows, 1);
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "unbound")
        .expect("async completion rows unknown-key");
    assert_eq!((row.completed, row.active), (1, 0));
}

/// G11/H9-§3: positional key receipts bind operation transitions
/// from the qualified positional join: colliding lifetimes qualify
/// distinct keys, and Wrap binds two distinct roles in input order.
#[test]
fn key_operation_key_roles_bind_transitions() {
    use crate::semantics_objects::Lifetime;

    const WRAP_KEY: u64 = 0xA1A1_A1A1_A1A1_A1A1;
    const DATA_KEY: u64 = 0xA2A2_A2A2_A2A2_A2A2;

    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    // Receipt detail rides the typed effects; aggregate buckets
    // retain the proved associations.
    fn start_receipts(sink: &[OperationEffect]) -> Vec<crate::semantics_edge::KeyReceipt> {
        sink.iter()
            .filter_map(|effect| match effect {
                OperationEffect::Started { key_receipt, .. } => *key_receipt,
                _ => None,
            })
            .collect()
    }
    let rsa_get = |word: u64| ShapedS1 {
        input0: Some((word, 1)),
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };

    // Lifetime 1: create, label, use, destroy.
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &rsa_get(CREATED_KEY),
    );
    let (_, pos_init1) = drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_DestroyObject", CkRv::OK.0, 0, 0),
    );
    // Lifetime 2: the same handle word, a new qualified key.
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &rsa_get(CREATED_KEY),
    );
    let (_, pos_init2) = drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );

    assert!(pos_init1 < pos_init2);
    // The Started effects carry the bound receipts: distinct keys,
    // roles and H0 positions per lifetime.
    let starts = start_receipts(&sink);
    assert_eq!(starts.len(), 2, "two completed sign operations");
    assert_ne!(
        starts[0].key, starts[1].key,
        "colliding lifetimes qualify distinct keys"
    );
    assert_eq!(starts[0].role, KeyRole::OperationKey);
    assert_eq!(starts[1].role, KeyRole::OperationKey);
    assert_eq!(starts[0].position, pos_init1);
    assert_eq!(starts[1].position, pos_init2);
    // The proved associations aggregate per lifetime key.
    let buckets: Vec<_> = keyuse.aggregates().iter().collect();
    assert_eq!(buckets.len(), 2);
    assert_ne!(buckets[0].0.object, buckets[1].0.object);
    for (bucket, counters) in &buckets {
        assert_eq!(
            (bucket.category, bucket.role, bucket.metadata),
            ("sign", "key", "rsa_2048")
        );
        assert_eq!(
            (counters.started, counters.completed, counters.active),
            (1, 1, 0)
        );
    }
    // Cross-check against the model's own qualified observations.
    let objects = &scene.model.project().objects;
    assert_eq!(objects.len(), 2);
    assert_eq!(objects[0].lifetime, Lifetime::Destroyed);
    assert_eq!(objects[1].lifetime, Lifetime::Live);
    assert_eq!(objects[0].id.as_u64(), buckets[0].0.object);
    assert_eq!(objects[1].id.as_u64(), buckets[1].0.object);
    assert_eq!(keyuse.evidence().unknown_key_rows, 0);

    // Wrap dual-reference: two keys, two distinct roles, input order.
    let create_wrap = ShapedS1 {
        result: Some(WRAP_KEY),
        ..ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &create_wrap,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &rsa_get(WRAP_KEY),
    );
    let create_data = ShapedS1 {
        result: Some(DATA_KEY),
        ..ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &create_data,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &rsa_get(DATA_KEY),
    );
    let wrap = ShapedS1 {
        input0: Some((WRAP_KEY, 1)),
        input1: Some((DATA_KEY, 1)),
        ..ShapedS1::shaped("C_WrapKey", CkRv::OK.0, RSA_PKCS, init_capture())
    };
    let (_, pos_wrap) = drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &wrap,
    );
    let direct = sink
        .iter()
        .filter_map(|effect| match effect {
            OperationEffect::DirectCompleted { key_receipts, .. } => Some(key_receipts.clone()),
            _ => None,
        })
        .find(|receipts| receipts.len() == 2)
        .expect("wrap direct effect");
    assert_eq!(direct.len(), 2);
    assert_eq!(direct[0].role, KeyRole::WrappingKey);
    assert_eq!(direct[1].role, KeyRole::WrappedKey);
    assert_eq!(direct[0].input, 0);
    assert_eq!(direct[1].input, 1);
    assert_ne!(direct[0].key, direct[1].key);
    assert_eq!(direct[0].position, pos_wrap);
    assert_eq!(direct[1].position, pos_wrap);
    // The receipts name the two created keys in input order: the
    // join minted both positions, and each role aggregates.
    let objects = &scene.model.project().objects;
    assert_eq!(objects.len(), 4);
    assert_eq!(direct[0].key, objects[2].id);
    assert_eq!(direct[1].key, objects[3].id);
    let buckets: Vec<_> = keyuse.aggregates().iter().collect();
    assert_eq!(buckets.len(), 4, "two signs plus two wrap roles");
    let wrapping = buckets
        .iter()
        .find(|(bucket, _)| bucket.role == "wrapping_key")
        .expect("wrapping role bucket");
    let wrapped = buckets
        .iter()
        .find(|(bucket, _)| bucket.role == "wrapped_object")
        .expect("wrapped role bucket");
    assert_eq!(wrapping.0.object, objects[2].id.as_u64());
    assert_eq!(wrapped.0.object, objects[3].id.as_u64());
    assert_eq!((wrapping.1.started, wrapping.1.completed), (1, 1));
    assert_eq!((wrapped.1.started, wrapped.1.completed), (1, 1));
}

/// C3: a proved later Wrap input keeps its true input position and
/// role when the earlier input is unprovable (positions come from the
/// qualified model join, never from successful-reference order); the
/// missing primary yields an unknown-key terminal while the proved
/// secondary association is retained (never promoted to primary).
/// Equal-handle inputs keep both positions with distinct roles.
#[test]
fn key_operation_partial_wrap_preserves_input_position() {
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    // Establish an RSA label so the proved secondary is usable.
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    // Wrap with input 0 unreadable and input 1 the proved key.
    let wrap = ShapedS1 {
        input0: Some((0, 2)),
        input1: Some((CREATED_KEY, 1)),
        ..ShapedS1::shaped("C_WrapKey", CkRv::OK.0, RSA_PKCS, init_capture())
    };
    let (_, position) = prepare_call(&mut scene, &mut staging, &wrap);
    let seal = scene.seal().expect("partial wrap quantum seals");
    assert_eq!(seal.prefix.settled().len(), 1);
    let receipts =
        keyuse.receipts_for_call(&seal, &seal.prefix.settled()[0], &scene.model, position);
    assert_eq!(receipts.len(), 1, "only input 1 proved");
    assert_eq!(
        receipts[0].input, 1,
        "position is the joined input, not reference order"
    );
    assert_eq!(receipts[0].role, KeyRole::WrappedKey);
    let (outcome, _) = staging.apply_seal(
        &seal,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let secondary = committed
        .key_operations
        .iter()
        .find(|row| row.role == "wrapped_object")
        .expect("proved secondary association retained");
    assert_eq!((secondary.started, secondary.completed), (1, 1));
    assert!(
        committed
            .key_operations
            .iter()
            .all(|row| row.role != "wrapping_key"),
        "no invented primary association: {:?}",
        committed.key_operations
    );
    let missing_primary = committed
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "wrap" && row.reason == "unbound")
        .expect("missing primary yields an unknown-key terminal");
    assert_eq!(missing_primary.completed, 1);

    // Equal handles: both positions prove with distinct roles.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let wrap = ShapedS1 {
        input0: Some((CREATED_KEY, 1)),
        input1: Some((CREATED_KEY, 1)),
        ..ShapedS1::shaped("C_WrapKey", CkRv::OK.0, RSA_PKCS, init_capture())
    };
    let (_, position) = prepare_call(&mut scene, &mut staging, &wrap);
    let seal = scene.seal().expect("equal-handle wrap quantum seals");
    let receipts =
        keyuse.receipts_for_call(&seal, &seal.prefix.settled()[0], &scene.model, position);
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].input, 0);
    assert_eq!(receipts[0].role, KeyRole::WrappingKey);
    assert_eq!(receipts[1].input, 1);
    assert_eq!(receipts[1].role, KeyRole::WrappedKey);
    assert_eq!(
        receipts[0].key, receipts[1].key,
        "same object, both positions"
    );
}

/// G11/H9-§3: association failure on effect-neutral calls records
/// unknown-key S1 with explicit evidence (never loss), and
/// requested-only metadata keeps definite operations without values.
#[test]
fn key_operation_unknown_key_and_requested_only() {
    let mut assoc_ledger = StagingLedger::new();
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    // Unreadable Init input: the model explicitly leaves the join
    // unresolved, so no reference exists to associate. (Absent
    // inputs are wire-malformed for ACCESS — present positions
    // carry non-absent statuses — so unreadable is the only
    // unassociated shape.)
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    let unreadable_init = ShapedS1 {
        input0: Some((0, 2)),
        ..ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture())
    };
    let (facts, _) = prepare_call(&mut scene, &mut staging, &unreadable_init);
    assert_eq!(facts.function, "C_SignInit");
    let success = scene.seal().expect("quantum seals");
    assert!(
        success.effects.effects.iter().any(|effect| matches!(
            effect,
            crate::semantics_objects::ObjectEffect::Unresolved { .. }
        )),
        "the model explicitly leaves the join unresolved"
    );
    assert!(
        success.effects.effects.iter().all(|effect| !matches!(
            effect,
            crate::semantics_objects::ObjectEffect::Referenced { .. }
        )),
        "no reference to associate"
    );
    let (outcome, _) = staging.apply_seal(
        &success,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    // Definite S1, unknown key, explicit evidence.
    assert_eq!((joint.started(), joint.completed()), (1, 1));
    assert!(keyuse.aggregates().is_empty(), "no key bound");
    assert_eq!(keyuse.evidence().unknown_key_rows, 1);
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "unbound")
        .expect("the operation still rows unknown-key");
    assert_eq!((row.completed, row.active), (1, 0));

    // S1Only-direct: no object proof, same unknown-key row.
    let mut direct = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    feed(&mut direct, &mut sink, &c);
    let c = op("C_Sign", 7, 200);
    feed(&mut direct, &mut sink, &c);
    for effect in &sink {
        keyuse.observe_effect(instance, effect, Some(&mut assoc_ledger), None);
    }
    assert!(keyuse.aggregates().is_empty());
    assert_eq!(keyuse.evidence().unknown_key_rows, 1);

    // Requested-only: the GET requests Class without values; the
    // later sign operation stays definite and its row shows
    // requested-but-unestablished metadata (presence only).
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 3u8, 0u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    assert_eq!((joint.started(), joint.completed()), (1, 1));
    // The Started effect carries the requested-only receipt (presence
    // only); the unusable association counts unknown-key.
    let receipt = sink
        .iter()
        .find_map(|effect| match effect {
            OperationEffect::Started { key_receipt, .. } => *key_receipt,
            _ => None,
        })
        .expect("init start carries its receipt");
    assert_eq!(receipt.metadata.requested_count(), 1, "Class was requested");
    assert!(receipt.metadata.is_requested(0), "field 0 is Class");
    assert_eq!(
        receipt.metadata.established_count(),
        0,
        "no value ever arrived"
    );
    assert!(
        keyuse.aggregates().is_empty(),
        "requested-only proves no bucket"
    );
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "metadata_unknown")
        .expect("requested-only rows metadata-unknown");
    assert_eq!((row.completed, row.active), (1, 0));
}

/// N2: metadata freezes in the positional model receipt at the
/// join: a receipt assembled after routing delay (the model learned
/// an RSA label after the Init settled) carries no label — delay
/// cannot backfill an earlier use. Conflict/attribution state
/// freezes the same way.
#[test]
fn key_operation_delayed_receipt_does_not_backfill_metadata() {
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    // The Init settles with no metadata established.
    let (_, pos_init) = prepare_call(
        &mut scene,
        &mut staging,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    let earlier = scene.seal().expect("init quantum seals");
    assert_eq!(earlier.prefix.settled().len(), 1);
    let (outcome, _) = staging.apply_seal(
        &earlier,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    // Routing delay: the model learns a full RSA label afterwards.
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    let objects = &scene.model.project().objects;
    assert_eq!(objects.len(), 1);
    assert!(objects[0].label.is_some(), "non-vacuous: the GET landed");
    // The delayed receipt for the earlier Init carries no label.
    let receipts = keyuse.receipts_for_call(
        &earlier,
        &earlier.prefix.settled()[0],
        &scene.model,
        pos_init,
    );
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].label, None,
        "delay cannot backfill the earlier use"
    );
    assert_eq!(receipts[0].metadata.established_count(), 0);
    assert_eq!(receipts[0].input, 0);
}

/// G11/H9-§3: later-learned key metadata never rewrites S1 rows: the
/// completed row is byte-identical before and after the GET that
/// establishes values the row predates.
#[test]
fn key_operation_later_metadata_never_rewrites_rows() {
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let before = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(before.unknown_key_operations.len(), 1);
    // The GET establishes Class=3 after the operation completed.
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    // The model's view learned the value (non-vacuous: the GET
    // landed), but completed history is untouched.
    let key = scene.model.project().objects[0].id;
    let flags = scene
        .model
        .key_metadata_flags(key)
        .expect("key view exists");
    assert_eq!(flags.established_count(), 1, "the GET established Class");
    assert!(flags.is_established(0), "field 0 is Class");
    let after = commit(2, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(after.key_operations, before.key_operations);
    assert_eq!(
        after.unknown_key_operations, before.unknown_key_operations,
        "completed history never rewrites"
    );
}

/// G11/H9-§3: conflicting key metadata never last-writer-wins:
/// two GETs establishing different Class values keep the earlier
/// value as history (established stays) and raise the conflict
/// bit; untouched fields and out-of-range indexes stay clear.
#[test]
fn key_operation_conflicting_metadata_keeps_earlier_value() {
    use crate::semantics_objects::METADATA_FIELDS;

    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let before = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(before.unknown_key_operations.len(), 1);
    // Two GETs disagree on Class: 3 first, then 4.
    for value in [3u16, 4u16] {
        let get = ShapedS1 {
            getattr_cells: vec![(1u8, 1u8, value)],
            ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
        };
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &get,
        );
    }
    let key = scene.model.project().objects[0].id;
    let flags = scene
        .model
        .key_metadata_flags(key)
        .expect("key view exists");
    assert!(flags.is_requested(0), "Class was asked");
    assert!(
        flags.is_established(0),
        "the earlier value stays as history"
    );
    assert!(
        flags.is_conflicted(0),
        "the second value conflicts, never overwrites"
    );
    for field in 1..METADATA_FIELDS {
        assert!(
            !flags.is_requested(field)
                && !flags.is_established(field)
                && !flags.is_conflicted(field),
            "field {field} untouched"
        );
    }
    assert!(
        !flags.is_conflicted(METADATA_FIELDS),
        "out of range stays clear"
    );
    let after = commit(2, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(after.key_operations, before.key_operations);
    assert_eq!(
        after.unknown_key_operations, before.unknown_key_operations,
        "completed history never rewrites"
    );
}

/// N4: the retained-row budget counts aggregate keys, not
/// operations: one two-role Wrap reserves two aggregate slots, so a
/// one-slot budget refuses it atomically (S1 preserved, PARTIAL).
#[test]
fn key_operation_wrap_reserves_two_aggregate_rows() {
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::with_capacity(1);
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    // Equal-handle Wrap: two usable roles, two aggregate slots.
    let wrap = ShapedS1 {
        input0: Some((CREATED_KEY, 1)),
        input1: Some((CREATED_KEY, 1)),
        ..ShapedS1::shaped("C_WrapKey", CkRv::OK.0, RSA_PKCS, init_capture())
    };
    let (_, position) = prepare_call(&mut scene, &mut staging, &wrap);
    let seal = scene.seal().expect("wrap quantum seals");
    let receipts =
        keyuse.receipts_for_call(&seal, &seal.prefix.settled()[0], &scene.model, position);
    assert_eq!(receipts.len(), 2, "both roles prove");
    let (outcome, _) = staging.apply_seal(
        &seal,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    assert_eq!((joint.started(), joint.completed()), (1, 1), "S1 preserved");
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert!(
        committed.key_operations.len() <= keyuse.capacity(),
        "a two-role Wrap consumes two aggregate slots: {:?}",
        committed.key_operations
    );
    assert!(
        committed.key_operations.is_empty(),
        "atomic refusal rows nothing"
    );
    assert_eq!(committed.budgets.key_refused, 1);
    assert!(keyuse.evidence().partial, "refusal makes coverage PARTIAL");
}

/// N4: repeated uses of one aggregate update its counters without
/// consuming new slots: two identical proved Signs share one bucket.
#[test]
fn key_operation_repeated_use_updates_one_aggregate() {
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::with_capacity(1);
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    for _ in 0..2 {
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
        );
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
        );
    }
    assert_eq!((joint.started(), joint.completed()), (2, 2));
    assert!(!keyuse.evidence().partial, "one bucket suffices");
    assert_eq!(keyuse.evidence().rows_refused, 0);
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(committed.key_operations.len(), 1);
    let row = &committed.key_operations[0];
    assert_eq!(
        (row.category, row.role, row.metadata_at_use),
        ("sign", "key", "rsa_2048")
    );
    assert_eq!((row.started, row.completed), (2, 2));
    assert_eq!(committed.budgets.key_occupied, 1);
}

/// N5: refused associations preserve their terminal outcomes in
/// fixed unknown summaries (Completed/Failed/Cancelled/Unknown per
/// category/reason) without allocating a positive row: one proved
/// bucket, one admitted and four refused instances, one terminal
/// per outcome.
#[test]
fn key_operation_refused_terminals_preserve_outcomes() {
    let mut assoc_ledger = StagingLedger::new();
    use crate::discovery::caller_registry::instance_input::RegistryInstanceId;
    use crate::semantics_edge::OperationOutcome;

    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut probe = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut probe,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut probe,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut probe,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    let start = sink
        .iter()
        .find(|effect| matches!(effect, OperationEffect::Started { .. }))
        .cloned()
        .expect("proved start");
    let mut end_sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut KeyUseReducer::new(),
        &mut end_sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let completed = end_sink
        .iter()
        .find(|effect| matches!(effect, OperationEffect::Ended { .. }))
        .cloned()
        .expect("completed terminal");
    // One bucket: instance 0 admits, instances 1..=4 refuse.
    let mut keyuse = KeyUseReducer::with_capacity(1);
    for n in 0..=4u32 {
        keyuse.observe_effect(
            RegistryInstanceId::from_raw(n),
            &start,
            Some(&mut assoc_ledger),
            None,
        );
    }
    assert_eq!(keyuse.aggregates().len(), 1);
    assert_eq!(keyuse.refused_opens().len(), 4);
    // The admitted terminal closes its bucket; each refused
    // terminal preserves its outcome in the fixed summary.
    keyuse.observe_effect(
        RegistryInstanceId::from_raw(0),
        &completed,
        Some(&mut assoc_ledger),
        None,
    );
    keyuse.observe_effect(
        RegistryInstanceId::from_raw(1),
        &completed,
        Some(&mut assoc_ledger),
        None,
    );
    // Failed: a bad-rv terminal on the same ordinal.
    let mut edge = EdgeSemantics::default();
    let mut failed_sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    feed(&mut edge, &mut failed_sink, &c);
    let c = call("C_Sign", 7, 0x30, 200);
    let failed = feed(&mut edge, &mut failed_sink, &c);
    assert!(matches!(
        failed[0],
        OperationEffect::Ended {
            outcome: OperationOutcome::Failed,
            ..
        }
    ));
    keyuse.observe_effect(
        RegistryInstanceId::from_raw(2),
        &failed[0],
        Some(&mut assoc_ledger),
        None,
    );
    // Cancelled: a competing Init ends the old machine.
    let mut edge = EdgeSemantics::default();
    let mut cancelled_sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    feed(&mut edge, &mut cancelled_sink, &c);
    let c = init("C_SignInit", 7, RSA_PKCS, 200);
    let cancelled = feed(&mut edge, &mut cancelled_sink, &c);
    let cancelled_end = cancelled
        .iter()
        .find(|effect| matches!(effect, OperationEffect::Ended { .. }))
        .expect("replacement terminal");
    assert!(matches!(
        cancelled_end,
        OperationEffect::Ended {
            outcome: OperationOutcome::Cancelled,
            ..
        }
    ));
    keyuse.observe_effect(
        RegistryInstanceId::from_raw(3),
        cancelled_end,
        Some(&mut assoc_ledger),
        None,
    );
    // Unknown: loss disposal ends the live machine.
    let mut edge = EdgeSemantics::default();
    let mut unknown_sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    feed(&mut edge, &mut unknown_sink, &c);
    let mut lost_sink = Vec::new();
    edge.invalidate_with_effects(&mut lost_sink);
    let unknown = lost_sink
        .iter()
        .find(|effect| matches!(effect, OperationEffect::Ended { .. }))
        .expect("loss terminal");
    assert!(matches!(
        unknown,
        OperationEffect::Ended {
            outcome: OperationOutcome::Unknown,
            ..
        }
    ));
    keyuse.observe_effect(
        RegistryInstanceId::from_raw(4),
        unknown,
        Some(&mut assoc_ledger),
        None,
    );

    assert!(keyuse.refused_opens().is_empty());
    assert_eq!(keyuse.aggregates().len(), 1, "no positive row for refusals");
    assert_eq!(keyuse.evidence().refused_terminals, 4);
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let summary = committed
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "unbound")
        .expect("refused terminals summarize per outcome");
    assert_eq!(
        (
            summary.completed,
            summary.failed,
            summary.cancelled,
            summary.unknown
        ),
        (1, 1, 1, 1)
    );
    assert_eq!(summary.active, 0);
    let admitted = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("admitted bucket stands");
    assert_eq!((admitted.started, admitted.completed), (1, 1));
}

/// G11/H9-§3/§91: key-operation rows are bounded (65,536):
/// history is never evicted for a new row. At N+1 the new
/// association is refused — S1 preserved, old rows intact — with
/// explicit PARTIAL evidence, and terminals of refused
/// associations land in fixed counters without allocating rows.
#[test]
fn key_operation_row_retention_bounds() {
    let mut assoc_ledger = StagingLedger::new();
    use crate::key_operation_projection::KEY_OP_ROW_CAPACITY;

    use crate::discovery::caller_registry::instance_input::RegistryInstanceId;

    let instance = RegistryInstanceId::from_raw(3);
    let mut edge = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    assert_eq!(KEY_OP_ROW_CAPACITY, 65_536);
    // Receipt-less operations never consume aggregate slots: they
    // count in fixed unknown summaries, however many arrive.
    for n in 0..65_546u64 {
        let mut sink = Vec::new();
        let c = op("C_GenerateKey", 7, 1_000 + n);
        let origin = EffectOrigin::from(&c);
        edge.observe_with_effects(&c, &origin, &mut sink);
        assert_eq!(sink.len(), 1);
        keyuse.observe_effect(instance, &sink[0], Some(&mut assoc_ledger), None);
    }
    assert!(keyuse.aggregates().is_empty(), "no bucket without a key");
    assert!(!keyuse.evidence().partial, "fixed summaries never refuse");
    assert_eq!(keyuse.evidence().rows_refused, 0);
    let marker = JointStaging::select_s1_only();
    let model = ObjectSemantics::new().project();
    let committed = commit(1, &[&marker], &model, &keyuse);
    let row = committed
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "generate_key" && row.reason == "not_applicable")
        .expect("receipt-less directs summarize");
    assert_eq!(row.completed, 65_546);

    // One real proved start, fanned out over distinct instances:
    // each instance is its own aggregate bucket.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    let start = sink
        .iter()
        .find(|effect| matches!(effect, OperationEffect::Started { .. }))
        .cloned()
        .expect("proved start");
    // The sign terminal, fanned out with the start below.
    let mut end_sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut KeyUseReducer::new(),
        &mut end_sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let end = end_sink
        .iter()
        .rev()
        .find(|effect| matches!(effect, OperationEffect::Ended { .. }))
        .cloned()
        .expect("sign terminal");
    // Fill exactly to capacity across instances, in waves of 1,024
    // live opens (N1c): the unified census caps simultaneous opens
    // while the 65,536 aggregate buckets retain closed history.
    let mut keyuse = KeyUseReducer::new();
    for wave in 0..64u32 {
        for n in 0..1_024u32 {
            let instance = RegistryInstanceId::from_raw(wave * 1_024 + n);
            keyuse.observe_effect(instance, &start, Some(&mut assoc_ledger), None);
        }
        for n in 0..1_024u32 {
            let instance = RegistryInstanceId::from_raw(wave * 1_024 + n);
            keyuse.observe_effect(instance, &end, Some(&mut assoc_ledger), None);
        }
    }
    assert_eq!(keyuse.aggregates().len(), KEY_OP_ROW_CAPACITY);
    assert!(keyuse.open().is_empty(), "waves close their opens");
    assert!(!keyuse.evidence().partial, "exact fit is not partial");
    // N+1 refuses: S1 still completes, old buckets intact, PARTIAL.
    keyuse.observe_effect(
        RegistryInstanceId::from_raw(65_536),
        &start,
        Some(&mut assoc_ledger),
        None,
    );
    assert_eq!(keyuse.aggregates().len(), KEY_OP_ROW_CAPACITY);
    let evidence = keyuse.evidence();
    assert!(evidence.partial, "refusal makes coverage PARTIAL");
    assert_eq!(evidence.rows_refused, 1);
    assert_eq!(keyuse.refused_opens().len(), 1);
    let first = keyuse
        .aggregates()
        .values()
        .next()
        .expect("history never evicted");
    assert_eq!((first.started, first.active), (1, 0));
    // The refused start's terminal lands counted without a bucket.
    keyuse.observe_effect(
        RegistryInstanceId::from_raw(65_536),
        &end,
        Some(&mut assoc_ledger),
        None,
    );
    assert_eq!(keyuse.aggregates().len(), KEY_OP_ROW_CAPACITY);
    assert_eq!(keyuse.evidence().refused_terminals, 1);
    assert!(keyuse.refused_opens().is_empty());
    let closed = keyuse.aggregates().values().next().expect("first bucket");
    assert_eq!((closed.completed, closed.active), (1, 0));

    // Small-N twin: reservation at start, reserved closes reuse
    // their bucket allocation-free, N+1 refuses starts and directs.
    let mut keyuse = KeyUseReducer::with_capacity(2);
    assert_eq!(keyuse.capacity(), 2, "injected bound");
    keyuse.observe_effect(
        RegistryInstanceId::from_raw(0),
        &start,
        Some(&mut assoc_ledger),
        None,
    );
    keyuse.observe_effect(
        RegistryInstanceId::from_raw(1),
        &start,
        Some(&mut assoc_ledger),
        None,
    );
    assert_eq!(keyuse.open().len(), 2, "both starts reserved");
    assert!(!keyuse.evidence().partial);
    keyuse.observe_effect(
        RegistryInstanceId::from_raw(0),
        &end,
        Some(&mut assoc_ledger),
        None,
    );
    assert_eq!(keyuse.aggregates().len(), 2, "the end reused its bucket");
    assert!(!keyuse.evidence().partial, "reserved closes never refuse");
    // N+1: a proved start refuses, while receipt-less operations
    // still count in fixed summaries at full budget.
    keyuse.observe_effect(
        RegistryInstanceId::from_raw(2),
        &start,
        Some(&mut assoc_ledger),
        None,
    );
    assert_eq!(keyuse.evidence().rows_refused, 1);
    assert!(keyuse.evidence().partial);
    assert_eq!(keyuse.refused_opens().len(), 1);
    let mut sink = Vec::new();
    let c = op("C_GenerateKey", 7, 500_000);
    let origin = EffectOrigin::from(&c);
    edge.observe_with_effects(&c, &origin, &mut sink);
    keyuse.observe_effect(instance, &sink[0], Some(&mut assoc_ledger), None);
    assert_eq!(
        keyuse.evidence().rows_refused,
        1,
        "fixed summaries never refuse"
    );
    keyuse.observe_effect(
        RegistryInstanceId::from_raw(2),
        &end,
        Some(&mut assoc_ledger),
        None,
    );
    assert_eq!(
        keyuse.aggregates().len(),
        2,
        "refused terminals row nothing"
    );
    assert_eq!(keyuse.evidence().refused_terminals, 1);
    assert!(keyuse.refused_opens().is_empty());
}

/// C1: the key-use join namespaces reducer-local operation IDs by
/// exact instance: concurrent equal-ordinal starts on two instances
/// stay partitioned, reversed terminals close their own custody
/// (never a sibling's), refused starts are namespaced too, and an
/// exact duplicate start refuses loudly instead of overwriting
/// unrelated custody.
#[test]
fn key_operation_cross_instance_operation_identity() {
    let mut assoc_ledger = StagingLedger::new();
    use crate::discovery::caller_registry::instance_input::RegistryInstanceId;
    let a = RegistryInstanceId::from_raw(10);
    let b = RegistryInstanceId::from_raw(11);
    let mut ea = EdgeSemantics::default();
    let mut eb = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    // Concurrent equal-ordinal starts: Sign on i10, Verify on i11.
    let mut sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    let origin = EffectOrigin::from(&c);
    ea.observe_joint(&c, &origin, &[], &mut sink);
    let start_a = sink.last().cloned().unwrap();
    let c = init("C_VerifyInit", 7, AES_GCM, 100);
    let origin = EffectOrigin::from(&c);
    eb.observe_joint(&c, &origin, &[], &mut sink);
    let start_b = sink.last().cloned().unwrap();
    assert_eq!(
        started(&start_a).0,
        started(&start_b).0,
        "equal ordinals collide"
    );
    keyuse.observe_effect(a, &start_a, Some(&mut assoc_ledger), None);
    keyuse.observe_effect(b, &start_b, Some(&mut assoc_ledger), None);
    assert_eq!((ea.started(), eb.started()), (1, 1));
    assert_eq!(keyuse.open().len(), 2, "both custodies retained");
    // Reversed terminals: i11's Verify first, then i10's Sign.
    let c = op("C_Verify", 7, 200);
    let origin = EffectOrigin::from(&c);
    eb.observe_with_effects(&c, &origin, &mut sink);
    keyuse.observe_effect(b, sink.last().unwrap(), Some(&mut assoc_ledger), None);
    let c = op("C_Sign", 7, 300);
    let origin = EffectOrigin::from(&c);
    ea.observe_with_effects(&c, &origin, &mut sink);
    keyuse.observe_effect(a, sink.last().unwrap(), Some(&mut assoc_ledger), None);
    assert!(keyuse.open().is_empty());
    // Each terminal closed its own custody: both categories counted,
    // nothing orphaned (a cross-close would orphan one terminal).
    assert_eq!(keyuse.evidence().orphan_ends, 0);
    let marker = JointStaging::select_s1_only();
    let model = ObjectSemantics::new().project();
    let committed = commit(1, &[&marker], &model, &keyuse);
    for category in ["sign", "verify"] {
        let row = committed
            .unknown_key_operations
            .iter()
            .find(|row| row.category == category && row.reason == "unbound")
            .expect("terminal counted");
        assert_eq!((row.completed, row.active), (1, 0));
    }
    assert!(
        committed
            .unknown_key_operations
            .iter()
            .all(|row| row.category != "unknown"),
        "no orphaned terminal"
    );

    // Refused starts are namespaced: with one proved bucket, i10's
    // start admits, i11's equal-ordinal start refuses without
    // touching i10's open, and each terminal lands in its place.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut probe = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut probe,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut probe,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut probe,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    let start = sink
        .iter()
        .find(|effect| matches!(effect, OperationEffect::Started { .. }))
        .cloned()
        .expect("proved start");
    let mut terminator = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut KeyUseReducer::new(),
        &mut terminator,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let end = terminator
        .iter()
        .find(|effect| matches!(effect, OperationEffect::Ended { .. }))
        .cloned()
        .expect("sign terminal");
    let mut keyuse = KeyUseReducer::with_capacity(1);
    keyuse.observe_effect(a, &start, Some(&mut assoc_ledger), None);
    keyuse.observe_effect(b, &start, Some(&mut assoc_ledger), None);
    assert_eq!(keyuse.open().len(), 1);
    assert_eq!(keyuse.refused_opens().len(), 1);
    keyuse.observe_effect(a, &end, Some(&mut assoc_ledger), None);
    let buckets: Vec<_> = keyuse.aggregates().iter().collect();
    assert_eq!(buckets.len(), 1);
    assert_eq!((buckets[0].0.instance, buckets[0].0.category), (a, "sign"));
    assert_eq!((buckets[0].1.started, buckets[0].1.completed), (1, 1));
    keyuse.observe_effect(b, &end, Some(&mut assoc_ledger), None);
    assert_eq!(
        keyuse.aggregates().len(),
        1,
        "refused terminals row nothing"
    );
    assert_eq!(keyuse.evidence().refused_terminals, 1);

    // An exact duplicate start refuses loudly; the original custody
    // stands, never overwritten.
    let mut edge = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    let origin = EffectOrigin::from(&c);
    edge.observe_joint(&c, &origin, &[], &mut sink);
    let start = sink.last().cloned().unwrap();
    keyuse.observe_effect(a, &start, Some(&mut assoc_ledger), None);
    keyuse.observe_effect(a, &start, Some(&mut assoc_ledger), None);
    assert_eq!(keyuse.open().len(), 1);
    assert_eq!(keyuse.evidence().duplicate_starts, 1);
    assert!(keyuse.aggregates().is_empty());
}

// ==================== Checkbox 4: one projection, three consumers ====================

use crate::discovery::caller_registry::RegistryLimits;
use crate::discovery::inventory_workload::{Harness, ScaleSpec};
use crate::inventory::render_json_from_presentation;
use crate::inventory_dashboard::{DashboardState, DisplayFrame, LogTail, Viewport, render_frame};
use crate::inventory_events::{EventWriter, KeyOperationEmitter};
use crate::inventory_present::Presentation;
use crate::key_operation_projection::{
    ObjectObservations, ObsStatus, ObservationPublisher, object_observations_json, producer::commit,
};
use std::collections::BTreeMap;

/// A private scratch dir for stream files (0700, TMPDIR-backed).
fn private_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    dir
}

/// Read every stream file (rotations oldest-first, live last) into
/// parsed lines.
fn read_stream(dir: &std::path::Path, live: &str) -> Vec<serde_json::Value> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name == live || name.starts_with(&format!("{live}.")))
        .collect();
    let sequence = |name: &String| -> (bool, u64) {
        if name == live {
            return (true, u64::MAX);
        }
        let suffix = name.strip_prefix(&format!("{live}.")).unwrap_or("");
        (false, suffix.parse().unwrap_or(u64::MAX))
    };
    files.sort_by_key(sequence);
    let mut lines = Vec::new();
    for name in files {
        let body = std::fs::read_to_string(dir.join(&name)).unwrap();
        for line in body.lines() {
            lines.push(
                serde_json::from_str(line)
                    .unwrap_or_else(|_| panic!("{name}: unparsable line: {line:?}")),
            );
        }
    }
    lines
}

/// The test consumer: replays `object_observed` /
/// `key_operations_observed` lines into row maps by (bucket, row
/// key), replacing by revision. Same-revision repeats must be
/// identical (rotation re-emission); older revisions never replace.
fn reconstruct(lines: &[serde_json::Value]) -> Reconstructed {
    let mut objects = BTreeMap::new();
    let mut known = BTreeMap::new();
    let mut unknown = BTreeMap::new();
    for line in lines {
        let kind = line["kind"].as_str().unwrap_or("");
        let event = &line["event"];
        let revision = event["revision"].as_u64().unwrap_or(u64::MAX);
        let (map, key) = match kind {
            "object_observed" => (&mut objects, format!("o:{}", event["row"]["object"])),
            "key_operations_observed" if event["bucket"] == "known" => {
                let row = &event["row"];
                (
                    &mut known,
                    format!(
                        "k:{}:{}:{}:{}:{}",
                        row["instance"].as_str().unwrap_or("?"),
                        row["object"],
                        row["category"].as_str().unwrap_or("?"),
                        row["role"].as_str().unwrap_or("?"),
                        row["metadata_at_use"].as_str().unwrap_or("?"),
                    ),
                )
            }
            "key_operations_observed" => {
                let row = &event["row"];
                (
                    &mut unknown,
                    format!(
                        "u:{}:{}",
                        row["category"].as_str().unwrap_or("?"),
                        row["reason"].as_str().unwrap_or("?"),
                    ),
                )
            }
            _ => continue,
        };
        match map.get(&key) {
            Some((stored_revision, stored_row)) => {
                assert!(
                    revision >= *stored_revision,
                    "revisions never move backwards for {key}"
                );
                if revision == *stored_revision {
                    assert_eq!(
                        &event["row"], stored_row,
                        "same-revision repeats are identical for {key}"
                    );
                } else {
                    map.insert(key, (revision, event["row"].clone()));
                }
            }
            None => {
                map.insert(key, (revision, event["row"].clone()));
            }
        }
    }
    Reconstructed {
        objects,
        known,
        unknown,
    }
}

#[derive(Debug, Default)]
struct Reconstructed {
    objects: BTreeMap<String, (u64, serde_json::Value)>,
    known: BTreeMap<String, (u64, serde_json::Value)>,
    unknown: BTreeMap<String, (u64, serde_json::Value)>,
}

/// The same rows keyed the same way, from the JSON section.
fn section_rows(section: &serde_json::Value) -> Reconstructed {
    let revision = section["revision"].as_u64().unwrap();
    let mut out = Reconstructed::default();
    for row in section["objects"].as_array().unwrap() {
        out.objects
            .insert(format!("o:{}", row["object"]), (revision, row.clone()));
    }
    for row in section["key_operations"].as_array().unwrap() {
        out.known.insert(
            format!(
                "k:{}:{}:{}:{}:{}",
                row["instance"].as_str().unwrap(),
                row["object"],
                row["category"].as_str().unwrap(),
                row["role"].as_str().unwrap(),
                row["metadata_at_use"].as_str().unwrap(),
            ),
            (revision, row.clone()),
        );
    }
    for row in section["unknown_key_operations"].as_array().unwrap() {
        out.unknown.insert(
            format!(
                "u:{}:{}",
                row["category"].as_str().unwrap(),
                row["reason"].as_str().unwrap(),
            ),
            (revision, row.clone()),
        );
    }
    out
}

/// Rows agree exactly; revisions agree exactly on fresh emission,
/// or persist below the section revision after delta emission (a
/// row event's revision is its last change).
fn assert_reconstructed_eq_json(
    reconstructed: &Reconstructed,
    section: &serde_json::Value,
    exact_revision: bool,
) {
    let expected = section_rows(section);
    let section_revision = section["revision"].as_u64().unwrap();
    for (name, got, want) in [
        ("object", &reconstructed.objects, &expected.objects),
        ("key", &reconstructed.known, &expected.known),
        ("unknown", &reconstructed.unknown, &expected.unknown),
    ] {
        assert_eq!(got.len(), want.len(), "{name} row count agrees");
        for (key, (want_revision, want_row)) in want {
            let (got_revision, got_row) = got
                .get(key)
                .unwrap_or_else(|| panic!("{name} row {key} reconstructed"));
            assert_eq!(got_row, want_row, "{name} row {key} agrees");
            if exact_revision {
                assert_eq!(
                    got_revision, want_revision,
                    "{name} row {key} revision agrees"
                );
            } else {
                assert!(
                    *got_revision <= section_revision,
                    "{name} row {key} persists below the section revision"
                );
            }
        }
    }
}

/// A captured harness presentation to embed committed projections
/// into (the future live loop publishes atomically; tests embed the
/// committed revision the same way).
fn harness_presentation() -> Presentation {
    let mut harness = Harness::new(RegistryLimits::default_limits()).unwrap();
    harness.stage_scale(&ScaleSpec {
        name: "projection-consumers",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 91_000,
    });
    harness.commit();
    Presentation::capture(harness.coordinator(), "workload", 1, 2, 1)
}

fn dashboard_text(presentation: &Presentation, width: usize, height: usize) -> Vec<String> {
    let mut tail = LogTail::bounded();
    tail.push("p11scope: pass 1: projection consumers");
    let frame = DisplayFrame {
        presentation: std::sync::Arc::new(presentation.clone()),
        log: tail.snapshot(),
    };
    let bytes = render_frame(&frame, Viewport { width, height }, &DashboardState::new());
    let text = String::from_utf8(bytes).expect("frames are valid UTF-8");
    assert!(text.starts_with("\x1b[H"), "frames home first");
    text.replace("\x1b[H", "")
        .replace("\x1b[K", "")
        .split('\n')
        .map(str::to_string)
        .collect()
}

/// H9-§3: one immutable projection, three consumers. A populated
/// Joint scene (RSA-2048 label established before use, sign, verify,
/// failed verify, two-role wrap, an open proved association and an
/// open unbound S1Only association, KEM and generation activity)
/// commits revision 1; JSON, JSONL reconstruction and the dashboard
/// agree on revision, status, IDs, units and counters. Revision 2
/// retires the key (destroy before the open sign's terminal):
/// changed rows re-emit, unchanged rows persist client-side, and
/// reconstruction still equals JSON with no double counting.
/// Rotation preserves the same final facts across files.
#[test]
fn key_operation_one_projection_three_consumers() {
    let mut assoc_ledger = StagingLedger::new();
    const WRAP_KEY: u64 = 0xA1A1_A1A1_A1A1_A1A1;
    const DATA_KEY: u64 = 0xA2A2_A2A2_A2A2_A2A2;
    let s1_instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(4);

    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let s1_marker = JointStaging::select_s1_only();
    let mut joint = EdgeSemantics::default();
    let mut s1_edge = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();

    // The sign key exists, then its RSA-2048 label is established
    // before use.
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    // Sign, verify, one failed verify.
    for call in [
        ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
        ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
        ShapedS1::shaped("C_VerifyInit", CkRv::OK.0, RSA_PKCS, init_capture()),
        ShapedS1::shaped("C_Verify", CkRv::OK.0, 0, op_capture()),
        ShapedS1::shaped("C_VerifyInit", CkRv::OK.0, RSA_PKCS, init_capture()),
        ShapedS1::shaped("C_Verify", CkRv::SIGNATURE_INVALID.0, 0, op_capture()),
    ] {
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &call,
        );
    }
    // Two-role wrap over two created keys, both RSA-labeled like
    // the sign key (the GET queries its input0 override).
    for result in [WRAP_KEY, DATA_KEY] {
        let create = ShapedS1 {
            result: Some(result),
            ..ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0)
        };
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &create,
        );
        let label = ShapedS1 {
            input0: Some((result, 1)),
            getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
            ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
        };
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &label,
        );
    }
    let wrap = ShapedS1 {
        input0: Some((WRAP_KEY, 1)),
        input1: Some((DATA_KEY, 1)),
        ..ShapedS1::shaped("C_WrapKey", CkRv::OK.0, RSA_PKCS, init_capture())
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &wrap,
    );
    // One proved association stays open at revision 1.
    let open_sign = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &open_sign,
    );
    assert_eq!(keyuse.open().len(), 1);

    // The S1Only sibling instance (separate reducer, shared
    // capture-wide key-use): KEM + generation activity plus one open
    // unbound association. No staging: S1Only reduces directly.
    for (name, ts) in [("C_EncapsulateKey", 900_000u64), ("C_GenerateKey", 900_001)] {
        let mut direct_sink = Vec::new();
        let c = op(name, 9, ts);
        let origin = EffectOrigin::from(&c);
        s1_edge.observe_with_effects(&c, &origin, &mut direct_sink);
        assert!(!direct_sink.is_empty(), "{name} emits its S1 effect");
        for effect in &direct_sink {
            keyuse.observe_effect(s1_instance, effect, Some(&mut assoc_ledger), None);
        }
    }
    let mut direct_sink = Vec::new();
    let c = init("C_SignInit", 9, RSA_PKCS, 900_002);
    let origin = EffectOrigin::from(&c);
    s1_edge.observe_with_effects(&c, &origin, &mut direct_sink);
    assert!(!direct_sink.is_empty(), "the unbound start emits");
    for effect in &direct_sink {
        keyuse.observe_effect(s1_instance, effect, Some(&mut assoc_ledger), None);
    }
    assert_eq!(keyuse.open().len(), 2);

    // Revision 1 commits populated: the Joint feed carries object
    // authority; the S1Only sibling contributes unknown-key S1 facts.
    let r1 = commit(1, &[&staging, &s1_marker], &scene.model.project(), &keyuse);
    assert_eq!(r1.status, ObsStatus::Populated);
    assert_eq!(r1.reason, "none");
    assert_eq!(r1.sessions.len(), 1);
    assert_eq!(r1.objects.len(), 3, "sign key + wrap key + data key");
    assert!(
        r1.key_operations
            .iter()
            .all(|row| row.metadata_at_use == "rsa_2048"),
        "established labels bind at use"
    );
    assert!(
        r1.key_operations.iter().all(|row| row.instance == "i3"),
        "proved rows carry the Joint instance; the S1Only sibling stays unknown-key"
    );
    let sign_rows: Vec<_> = r1
        .key_operations
        .iter()
        .filter(|row| row.category == "sign")
        .collect();
    assert_eq!(sign_rows.len(), 1);
    assert_eq!((sign_rows[0].completed, sign_rows[0].active), (1, 1));
    let verify_row = r1
        .key_operations
        .iter()
        .find(|row| row.category == "verify")
        .expect("proved verify row");
    assert_eq!((verify_row.completed, verify_row.failed), (1, 1));
    let mut wrap_roles: Vec<_> = r1
        .key_operations
        .iter()
        .filter(|row| row.category == "wrap")
        .map(|row| row.role)
        .collect();
    wrap_roles.sort_unstable();
    assert_eq!(
        wrap_roles,
        vec!["wrapped_object", "wrapping_key"],
        "both wrap roles"
    );
    let wrap_keys: Vec<_> = r1
        .key_operations
        .iter()
        .filter(|row| row.category == "wrap")
        .map(|row| (row.instance.clone(), row.object, row.role))
        .collect();
    assert_eq!(wrap_keys.len(), 2);
    assert!(wrap_keys[0] < wrap_keys[1], "rows sort by full key tuple");
    let unknown_sign = r1
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "unbound")
        .expect("open unbound sign");
    assert_eq!(unknown_sign.active, 1);
    assert!(
        r1.unknown_key_operations
            .iter()
            .any(|row| row.category == "encapsulate" && row.reason == "role_unavailable"),
        "KEM reports role unavailable, S1 intact"
    );
    assert!(
        r1.unknown_key_operations
            .iter()
            .any(|row| row.category == "generate_key" && row.reason == "not_applicable"),
        "generation stays not-applicable"
    );
    assert_eq!(s1_edge.completed(), 2, "KEM + generation S1 totals");

    // Consumer 1 (JSON) and consumer 3 (dashboard) read the shared
    // presentation; consumer 2 (JSONL) reconstructs from the stream.
    let mut presentation = harness_presentation();
    presentation.object_observations = r1.clone();
    let document = render_json_from_presentation(&presentation);
    let section = &document["object_observations"];
    assert_eq!(section["version"], 1);
    assert_eq!(section["revision"], 1);
    assert_eq!(section["status"], "populated");

    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 5).unwrap();
    let mut emitter = KeyOperationEmitter::new();
    let first = emitter.emit(&mut writer, &r1, 1_000).unwrap();
    assert_eq!(first.deferred, 0);
    assert_eq!(
        first.emitted,
        r1.objects.len() + r1.key_operations.len() + r1.unknown_key_operations.len(),
        "first emission carries every row"
    );
    drop(writer);
    let lines = read_stream(dir.path(), "events.jsonl");
    assert_reconstructed_eq_json(&reconstruct(&lines), section, true);

    let wide = dashboard_text(&presentation, 300, 24);
    assert_eq!(wide.len(), 24, "frames fill the viewport");
    let line = wide
        .iter()
        .find(|line| line.starts_with("objects/keys"))
        .expect("projection line");
    assert_eq!(
        line,
        &format!(
            "objects/keys rev 1 populated | sess 1 obj 3 krows {} urows {} refused 0+0 | {}",
            r1.key_operations.len(),
            r1.unknown_key_operations.len(),
            "encapsulate 1/0/0 operations, generate_key 1/0/0 operations, sign 1/0/2 operations, verify 1/1/0 operations, wrap 1/0/0 operations",
        ),
        "dashboard agrees on revision, status, counts, units and tallies"
    );
    assert!(
        wide.last().unwrap().contains("scroll 0/"),
        "footer pinned: {}",
        wide.last().unwrap()
    );
    let narrow = dashboard_text(&presentation, 80, 24);
    let short = narrow
        .iter()
        .find(|line| line.starts_with("objects/keys"))
        .expect("narrow line");
    assert!(
        short.starts_with("objects/keys rev 1 populated | sess 1 obj 3 krows "),
        "{short}"
    );

    // Revision 2: destroy retires the open sign association before
    // its terminal; the terminal closes key_join_lost and lands
    // unknown-key, with no second start anywhere.
    let destroy = ShapedS1::shaped("C_DestroyObject", CkRv::OK.0, 0, 0);
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &destroy,
    );
    assert_eq!(
        keyuse.evidence().join_lost,
        1,
        "the open sign lost its join"
    );
    let close = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &close,
    );
    let r2 = commit(2, &[&staging, &s1_marker], &scene.model.project(), &keyuse);
    assert_eq!(r2.status, ObsStatus::Populated);
    let sign_row = r2
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("proved sign row");
    assert_eq!(
        (
            sign_row.started,
            sign_row.completed,
            sign_row.active,
            sign_row.key_join_lost
        ),
        (2, 1, 0, 1),
        "started = completed + key_join_lost across the retirement"
    );
    let lost_terminal = r2
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "key_join_lost")
        .expect("retired terminal lands unknown-key");
    assert_eq!(lost_terminal.completed, 1);
    assert!(
        !r2.unknown_key_operations
            .iter()
            .any(|row| row.category == "sign" && row.reason == "key_join_lost" && row.active > 0),
        "no fabricated unknown starts"
    );
    presentation.object_observations = r2.clone();
    let document = render_json_from_presentation(&presentation);
    let section = &document["object_observations"];

    // Changed rows re-emit; unchanged rows persist client-side.
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 5).unwrap();
    let mut emitter = KeyOperationEmitter::new();
    emitter.emit(&mut writer, &r1, 1_000).unwrap();
    let before = emitter.tracked();
    let delta = emitter.emit(&mut writer, &r2, 2_000).unwrap();
    assert_eq!(delta.deferred, 0);
    assert_eq!(
        delta.emitted, 3,
        "only the sign row, the new lost summary and the destroyed object row re-emit"
    );
    assert_eq!(
        emitter.tracked(),
        before + 1,
        "one row is new, two changed in place"
    );
    drop(writer);
    let lines = read_stream(dir.path(), "events.jsonl");
    assert_reconstructed_eq_json(&reconstruct(&lines), section, false);

    // Rotation preserves the same final facts across files.
    let spin = dir.path().join("spin.jsonl");
    let mut writer = EventWriter::create(&spin, 1024, 16).unwrap();
    let mut emitter = KeyOperationEmitter::new();
    emitter.emit(&mut writer, &r1, 1_000).unwrap();
    emitter.emit(&mut writer, &r2, 2_000).unwrap();
    assert!(writer.rotations() > 0, "rotation exercised");
    drop(writer);
    let lines = read_stream(dir.path(), "spin.jsonl");
    assert!(
        lines.iter().any(|line| line["kind"] == "rotated"),
        "rotation marker present"
    );
    assert_reconstructed_eq_json(&reconstruct(&lines), section, false);
}

/// N9: key-row terminals replace, never silently drop: a refused
/// active unknown row's terminal re-emits under the same row key
/// (the digest changes), so JSONL reconstruction matches the JSON
/// section — no stale active row, no silent vanishing.
#[test]
fn key_operation_refused_row_terminal_replaces_in_stream() {
    let mut assoc_ledger = StagingLedger::new();
    use crate::discovery::caller_registry::instance_input::RegistryInstanceId;

    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut probe = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut probe,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut probe,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut probe,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    let start = sink
        .iter()
        .find(|effect| matches!(effect, OperationEffect::Started { .. }))
        .cloned()
        .expect("proved start");
    let mut end_sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut KeyUseReducer::new(),
        &mut end_sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let end = end_sink
        .iter()
        .find(|effect| matches!(effect, OperationEffect::Ended { .. }))
        .cloned()
        .expect("sign terminal");
    // One bucket: instance 0 admits, instance 1 refuses (active).
    let mut keyuse = KeyUseReducer::with_capacity(1);
    keyuse.observe_effect(
        RegistryInstanceId::from_raw(0),
        &start,
        Some(&mut assoc_ledger),
        None,
    );
    keyuse.observe_effect(
        RegistryInstanceId::from_raw(1),
        &start,
        Some(&mut assoc_ledger),
        None,
    );
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 5).unwrap();
    let mut emitter = KeyOperationEmitter::new();
    let r1 = commit(1, &[&staging], &scene.model.project(), &keyuse);
    emitter.emit(&mut writer, &r1, 1_000).unwrap();
    // The refused terminal lands under the same row key: the
    // zero-active terminal row replaces the active row.
    keyuse.observe_effect(
        RegistryInstanceId::from_raw(1),
        &end,
        Some(&mut assoc_ledger),
        None,
    );
    let r2 = commit(2, &[&staging], &scene.model.project(), &keyuse);
    emitter.emit(&mut writer, &r2, 2_000).unwrap();
    drop(writer);
    let lines = read_stream(dir.path(), "events.jsonl");
    let rebuilt = reconstruct(&lines);
    let row = rebuilt
        .unknown
        .get("u:sign:unbound")
        .expect("the refused row reaches the stream");
    assert_eq!(row.0, 2, "the terminal replacement carries revision 2");
    assert_eq!(row.1["completed"], 1);
    assert_eq!(row.1["active"], 0, "never the stale active row");
    let live = r2
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "unbound")
        .expect("live section row");
    assert_eq!(row.1["completed"], live.completed);
    assert_eq!(row.1["active"], live.active, "JSONL matches JSON");
}

/// N9 remainder (fix round 2): a lost join before the terminal keeps
/// the old unknown row's zero-active replacement. The
/// metadata_unknown summary drains to all zeros (its outcome routes
/// to key_join_lost) but must still emit — else the cumulative
/// consumer keeps stale activity the JSON section no longer shows.
#[test]
fn key_operation_n9_lost_unknown_metadata_keeps_zero_replacement() {
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    // Known object, unknown metadata (no getattr): the use aggregates
    // metadata_unknown.
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    let key = sink
        .iter()
        .find_map(|effect| match effect {
            OperationEffect::Started { key_receipt, .. } => *key_receipt,
            _ => None,
        })
        .expect("init start carries its receipt")
        .key;
    let before = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let live = before
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "metadata_unknown")
        .expect("live unknown row");
    assert_eq!(live.active, 1, "precondition: the use is live");
    // Lost join before the terminal, then the S1 terminal routes to
    // key_join_lost while the old summary drains to zeros.
    keyuse.retire_object(key);
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let after = commit(2, &[&staging], &scene.model.project(), &keyuse);
    let zero = after
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "metadata_unknown")
        .expect("zero-active replacement");
    assert_eq!(
        (
            zero.active,
            zero.completed,
            zero.failed,
            zero.cancelled,
            zero.unknown
        ),
        (0, 0, 0, 0, 0),
        "drained but still emitted"
    );
    let lost = after
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "key_join_lost")
        .expect("the routed outcome");
    assert_eq!(lost.completed, 1);
    // The stream replaces the stale row: reconstruction matches JSON.
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 5).unwrap();
    let mut emitter = KeyOperationEmitter::new();
    emitter.emit(&mut writer, &before, 1_000).unwrap();
    emitter.emit(&mut writer, &after, 2_000).unwrap();
    drop(writer);
    let lines = read_stream(dir.path(), "events.jsonl");
    let rebuilt = reconstruct(&lines);
    assert_eq!(
        rebuilt.unknown.len(),
        after.unknown_key_operations.len(),
        "no stale rows, none missing"
    );
    let replaced = rebuilt
        .unknown
        .get("u:sign:metadata_unknown")
        .expect("the replacement reaches the stream");
    assert_eq!(replaced.0, 2, "the terminal replacement carries revision 2");
    assert_eq!(replaced.1["active"], 0, "never the stale active row");
}

/// C2 remainder (fix round 2): a seal binds its ACTUAL ADMITTED
/// INVOCATION (identity), not a value-equal shape. Two same-shaped
/// Inits stage; delivering the second seal first holds (its key
/// names the second invocation, not the head) with staging and S1
/// untouched — then in-order delivery replays each exactly once.
#[test]
fn key_operation_c2_foreign_namespace_seal_never_replays() {
    let mut own = JointScene::new();
    let receipt = own.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&receipt));
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let (_, own_position) = prepare_call(&mut own, &mut staging, &init);
    let mut foreign = JointScene::new();
    let foreign_receipt = foreign.bootstrap();
    let mut foreign_staging = JointStaging::select_joint(Some(&foreign_receipt));
    let (_, foreign_position) = prepare_call(&mut foreign, &mut foreign_staging, &init);
    assert_eq!(
        own_position, foreign_position,
        "independent H0 namespaces restart their ordinals"
    );
    let foreign_seal = foreign
        .seal()
        .expect("the foreign Session legitimately seals its own call");
    let mut reducer = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    let (outcome, _) = staging.apply_seal(
        &foreign_seal,
        &foreign.model,
        own.adapter.ledger_mut(),
        &mut reducer,
        &mut keyuse,
        RegistryInstanceId::from_raw(3),
        &mut sink,
        None,
    );
    assert_eq!(
        outcome,
        SealApplyOutcome::Held,
        "numeric H0 equality cannot substitute for the selected namespace"
    );
    assert_eq!(staging.staged_len(), 1);
    assert_eq!(reducer.calls(), 0);
    assert!(keyuse.open().is_empty());
}

#[test]
fn key_operation_c2_foreign_namespace_failure_preserves_live_history() {
    let mut own = JointScene::new();
    let receipt = own.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&receipt));
    let mut reducer = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    drive_quantum(
        &mut own,
        &mut staging,
        &mut reducer,
        &mut keyuse,
        &mut sink,
        &init,
    );
    let sign = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    prepare_call(&mut own, &mut staging, &sign);
    let before = (
        reducer.calls(),
        reducer.started(),
        reducer.completed(),
        reducer.unknown(),
        sink.len(),
    );
    assert!(reducer.has_live_operations());
    let mut foreign = JointScene::new();
    let receipt = foreign.bootstrap();
    let mut foreign_staging = JointStaging::select_joint(Some(&receipt));
    prepare_call(&mut foreign, &mut foreign_staging, &init);
    let failure = foreign
        .seal_with_fault(7, 8)
        .expect_err("the foreign adapter really observes native loss");
    assert_eq!(failure.gap, JournalGap::FaultChanged);
    let mut finalizer = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    let (outcome, _) = staging.apply_algorithm_failure_for_test(
        &failure,
        &mut finalizer,
        &foreign.model,
        own.adapter.ledger_mut(),
        &mut reducer,
        &mut keyuse,
        RegistryInstanceId::from_raw(3),
        &mut sink,
        None,
    );
    assert_eq!(outcome, FailureApplyOutcome::Ignored);
    assert_eq!(staging.mode(), FeedMode::Joint);
    assert_eq!(staging.staged_len(), 1);
    assert!(matches!(
        crate::semantics_objects::journal::H3EvidenceSource::take_h3_disposition(&mut finalizer),
        H3DispositionEvidence::Clean {
            staged_max: u64::MAX,
            pending_floor: None
        }
    ));
    assert_eq!(
        (
            reducer.calls(),
            reducer.started(),
            reducer.completed(),
            reducer.unknown(),
            sink.len()
        ),
        before
    );
    assert!(
        reducer.has_live_operations(),
        "foreign loss has no authority over the selected feed"
    );
    let seal = own.seal().expect("the selected namespace still seals");
    assert_eq!(
        staging
            .apply_seal(
                &seal,
                &own.model,
                own.adapter.ledger_mut(),
                &mut reducer,
                &mut keyuse,
                RegistryInstanceId::from_raw(3),
                &mut sink,
                None
            )
            .0,
        SealApplyOutcome::ReplayedOne
    );
    assert_eq!(reducer.completed(), 1);
}

#[test]
fn key_operation_c2_foreign_namespace_registry_delivery_keeps_projection() {
    for loss in [false, true] {
        let mut own = GuardedScene::new();
        let receipt = own.scene.bootstrap();
        let key = own.key(1);
        own.registry.install_joint_receipt(key.clone(), receipt);
        let (_, id) = own.register(1);
        let create = ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0);
        let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
        for shape in [&create, &init] {
            assert_eq!(
                own.drive_joint(&key, id, shape),
                SealApplyOutcome::ReplayedOne
            );
        }
        let sign = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
        let (facts, position) = own.admit_shape(&sign);
        own.observe(&key, position, facts);
        own.registry
            .publish_with_ledger(own.scene.adapter.ledger_mut());
        ingest_call(&mut own.scene, &sign, position);
        let before = own.registry.joint_observations(9);
        let staged = own.scene.adapter.ledger().staged();
        let mut foreign = JointScene::new();
        let receipt = foreign.bootstrap();
        let mut foreign_staging = JointStaging::select_joint(Some(&receipt));
        prepare_call(&mut foreign, &mut foreign_staging, &init);
        let mut finalizer = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
        if loss {
            let failure = foreign
                .seal_with_fault(7, 8)
                .expect_err("genuine foreign loss");
            assert_eq!(
                own.registry.deliver_joint_algorithm_failure_for_test(
                    id,
                    &failure,
                    &mut finalizer,
                    &foreign.model,
                    own.scene.adapter.ledger_mut()
                ),
                FailureApplyOutcome::Ignored
            );
        } else {
            let seal = foreign.seal().expect("foreign call seals");
            assert_eq!(
                own.registry.deliver_joint_algorithm_seal_for_test(
                    id,
                    &seal,
                    &foreign.model,
                    own.scene.adapter.ledger_mut()
                ),
                SealApplyOutcome::Held
            );
        }
        assert_eq!(
            own.registry.joint_observations(9),
            before,
            "foreign delivery cannot replace a retained object projection or S1 history"
        );
        assert_eq!(own.scene.adapter.ledger().staged(), staged);
        assert!(
            matches!(
                crate::semantics_objects::journal::H3EvidenceSource::take_h3_disposition(
                    &mut finalizer
                ),
                H3DispositionEvidence::Clean {
                    staged_max: u64::MAX,
                    pending_floor: None
                }
            ),
            "foreign delivery never takes completeness"
        );
        let seal = own
            .scene
            .seal()
            .expect("own queued terminal remains healthy");
        assert_eq!(
            own.registry.deliver_joint_algorithm_seal_for_test(
                id,
                &seal,
                &own.scene.model,
                own.scene.adapter.ledger_mut()
            ),
            SealApplyOutcome::ReplayedOne
        );
        assert_eq!(own.edge_calls(id), 3);
        let observations = own.registry.joint_observations(10);
        assert_eq!(
            observations
                .unknown_key_operations
                .iter()
                .map(|row| row.completed)
                .sum::<u64>(),
            1
        );
    }
}

#[test]
fn key_operation_c2_early_loss_scope_comes_from_adapter_not_request() {
    let mut own = JointScene::new();
    let receipt = own.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&receipt));
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    prepare_call(&mut own, &mut staging, &init);
    let mut foreign = JointScene::new();
    let foreign_receipt = foreign.bootstrap();
    let mut foreign_staging = JointStaging::select_joint(Some(&foreign_receipt));
    prepare_call(&mut foreign, &mut foreign_staging, &init);
    let audit = JournalAuditReceipt::scripted(
        7,
        8,
        None,
        0,
        H3DispositionEvidence::scripted_clean(u64::MAX),
        own.fixture.attachment().generation(),
    );
    let frontier = own.adapter.consumed_frontier();
    let mut births =
        ScriptedBirthSource::once(SessionBirthEvidence::scripted_for_receipt(&foreign_receipt));
    let failure = own
        .adapter
        .seal(
            &mut own.model,
            &audit,
            &foreign_receipt,
            frontier,
            &mut births,
            &SteadyFaultCell(8),
        )
        .expect_err("real loss precedes the wrong bootstrap check");
    assert_eq!(failure.gap, JournalGap::FaultChanged);
    assert!(
        failure.affects_domain(receipt.domain()),
        "an admitted, not-yet-model-registered key is affected"
    );
    assert!(
        !failure.affects_domain(foreign_receipt.domain()),
        "the request cannot retarget an adapter loss"
    );
    let mut reducer = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    let mut finalizer = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    assert_eq!(
        foreign_staging
            .apply_algorithm_failure_for_test(
                &failure,
                &mut finalizer,
                &own.model,
                foreign.adapter.ledger_mut(),
                &mut reducer,
                &mut keyuse,
                RegistryInstanceId::from_raw(4),
                &mut sink,
                None
            )
            .0,
        FailureApplyOutcome::Ignored
    );
    assert_eq!(foreign_staging.staged_len(), 1);
    assert_eq!(
        staging
            .apply_algorithm_failure_for_test(
                &failure,
                &mut finalizer,
                &own.model,
                own.adapter.ledger_mut(),
                &mut reducer,
                &mut keyuse,
                RegistryInstanceId::from_raw(3),
                &mut sink,
                None
            )
            .0,
        FailureApplyOutcome::Degraded { disposed: 1 }
    );
    assert_eq!(staging.history_disposed(), 1);
    assert_eq!(
        staging
            .apply_algorithm_failure_for_test(
                &failure,
                &mut finalizer,
                &own.model,
                own.adapter.ledger_mut(),
                &mut reducer,
                &mut keyuse,
                RegistryInstanceId::from_raw(3),
                &mut sink,
                None
            )
            .0,
        FailureApplyOutcome::Ignored,
        "the same scoped loss disposes once"
    );
}

#[test]
fn key_operation_c2_unknown_request_is_inert_and_own_receipt_refresh_keeps_frontier() {
    let mut own = JointScene::new();
    let receipt = own.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&receipt));
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    prepare_call(&mut own, &mut staging, &init);
    let foreign = JointScene::new();
    let foreign_receipt = foreign.bootstrap();
    let audit = JournalAuditReceipt::scripted(
        7,
        7,
        None,
        0,
        H3DispositionEvidence::scripted_clean(u64::MAX),
        own.fixture.attachment().generation(),
    );
    let frontier = own.adapter.consumed_frontier();
    let mut births =
        ScriptedBirthSource::once(SessionBirthEvidence::scripted_for_receipt(&foreign_receipt));
    let failure = own
        .adapter
        .seal(
            &mut own.model,
            &audit,
            &foreign_receipt,
            frontier,
            &mut births,
            &SteadyFaultCell(7),
        )
        .expect_err("unknown key never selects this adapter's domain");
    assert_eq!(failure.gap, JournalGap::BootstrapMismatch);
    assert!(!failure.affects_domain(receipt.domain()));
    let mut reducer = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    let mut finalizer = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    assert_eq!(
        staging
            .apply_algorithm_failure_for_test(
                &failure,
                &mut finalizer,
                &own.model,
                own.adapter.ledger_mut(),
                &mut reducer,
                &mut keyuse,
                RegistryInstanceId::from_raw(3),
                &mut sink,
                None
            )
            .0,
        FailureApplyOutcome::Ignored
    );
    assert_eq!(staging.staged_len(), 1);
    let refreshed = own.bootstrap();
    assert_eq!(refreshed.domain(), receipt.domain());
    let seal = own
        .seal()
        .expect("same-domain refreshed birth seals existing input");
    assert_eq!(
        staging
            .apply_seal(
                &seal,
                &own.model,
                own.adapter.ledger_mut(),
                &mut reducer,
                &mut keyuse,
                RegistryInstanceId::from_raw(3),
                &mut sink,
                None
            )
            .0,
        SealApplyOutcome::ReplayedOne
    );
    let count = reducer.calls();
    let refreshed = own.bootstrap();
    assert_eq!(refreshed.domain(), receipt.domain());
    assert_eq!(
        staging
            .apply_seal(
                &seal,
                &own.model,
                own.adapter.ledger_mut(),
                &mut reducer,
                &mut keyuse,
                RegistryInstanceId::from_raw(3),
                &mut sink,
                None
            )
            .0,
        SealApplyOutcome::Held
    );
    assert_eq!(
        reducer.calls(),
        count,
        "refresh cannot reset consumed identity or replay history"
    );
}

#[test]
fn key_operation_c2_reordered_seal_refuses_then_recovers_in_order() {
    use crate::discovery::caller_registry::instance_input::RegistryInstanceId;

    let instance = RegistryInstanceId::from_raw(3);
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    // Two same-shaped Inits (same session): only invocation identity
    // distinguishes them.
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let (_, first_pos) = prepare_call(&mut scene, &mut staging, &init);
    let first = scene.seal().expect("first quantum seals");
    assert_eq!(first.prefix.settled().len(), 1);
    let (_, second_pos) = prepare_call(&mut scene, &mut staging, &init);
    let second = scene.seal().expect("second quantum seals");
    assert_eq!(second.prefix.settled().len(), 1);
    assert!(first_pos < second_pos, "non-vacuous order");
    assert_eq!(staging.staged_len(), 2);

    // The second seal first: held — its invocation is not the head.
    let (outcome, _) = staging.apply_seal(
        &second,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(
        outcome,
        SealApplyOutcome::Held,
        "a matching shape is not exact call identity"
    );
    assert_eq!(staging.staged_len(), 2, "held seals keep staging");
    assert_eq!(joint.calls(), 0, "held seals reduce nothing");
    // In-order delivery replays each exactly once.
    let (outcome, _) = staging.apply_seal(
        &first,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    let (outcome, _) = staging.apply_seal(
        &second,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    assert_eq!(staging.staged_len(), 0);
    assert_eq!(joint.calls(), 2, "each invocation replays exactly once");
    assert_eq!(staging.reduced(), 2, "the held quantum never replayed");
}

/// C2 remainder (fix round 2): consumption is irreversible — no
/// bounded forget window for live claims. 1,025 same-shaped seals
/// consume (historically evicting the first ticket from the 1,024-slot dedup);
/// reapplying the first seal against a new head still holds: its
/// invocation lies below the staging frontier and can never match
/// again. The selector retains its historical name; frontier now enforces
/// the same permanent refusal without allocating the redundant dedup storage.
#[test]
fn key_operation_c2_consumption_survives_fifo_eviction() {
    use crate::discovery::caller_registry::instance_input::RegistryInstanceId;

    let instance = RegistryInstanceId::from_raw(3);
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let mut first_seal = None;
    for n in 0..=1024u64 {
        let (_, position) = prepare_call(&mut scene, &mut staging, &init);
        let seal = scene.seal().expect("quantum seals");
        assert_eq!(seal.prefix.settled().len(), 1, "iteration {n}");
        let (outcome, _) = staging.apply_seal(
            &seal,
            &scene.model,
            scene.adapter.ledger_mut(),
            &mut joint,
            &mut keyuse,
            instance,
            &mut sink,
            None,
        );
        assert_eq!(outcome, SealApplyOutcome::ReplayedOne, "iteration {n}");
        if n == 0 {
            assert_eq!(position, first_pos_of(&seal), "seal binds its admission");
            first_seal = Some(seal);
        }
    }
    assert_eq!(staging.reduced(), 1025);
    // One new head, then the first seal again: held forever.
    let (_, _) = prepare_call(&mut scene, &mut staging, &init);
    let first = first_seal.expect("kept the first seal");
    let (outcome, _) = staging.apply_seal(
        &first,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(
        outcome,
        SealApplyOutcome::Held,
        "bounded dedup eviction cannot re-authorize an old seal"
    );
    assert_eq!(staging.reduced(), 1025, "the old seal replays nothing");
}

#[test]
fn key_operation_c2_frontier_disposed_and_resource_refused_heads_never_replay() {
    use crate::semantics_edge::resources::{SEMANTIC_RESOURCE_LIMIT, SemanticResourcePool};
    for resource_refusal in [false, true] {
        let mut scene = JointScene::new();
        let receipt = scene.bootstrap();
        let mut staging = JointStaging::select_joint(Some(&receipt));
        let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
        let (_, first_position) = prepare_call(&mut scene, &mut staging, &init);
        let first = scene.seal().expect("actual own call seals");
        let pool = SemanticResourcePool::default();
        let mut reducer = EdgeSemantics::with_resources(&pool).unwrap();
        let mut keyuse = KeyUseReducer::new();
        let mut sink = Vec::new();
        if resource_refusal {
            pool.reference_set_limit(pool.snapshot().charged_bytes);
            assert_eq!(
                staging
                    .apply_seal(
                        &first,
                        &scene.model,
                        scene.adapter.ledger_mut(),
                        &mut reducer,
                        &mut keyuse,
                        RegistryInstanceId::from_raw(3),
                        &mut sink,
                        None,
                    )
                    .0,
                SealApplyOutcome::ResourceRefused
            );
            pool.reference_set_limit(SEMANTIC_RESOURCE_LIMIT);
        } else {
            // The H9 loss/timeout disposal entry point consumes a head as
            // history. No successful semantic replay or H0 report is scripted.
            assert_eq!(
                staging
                    .dispose_below_barrier(Some(first_position), Some(scene.adapter.ledger_mut())),
                1
            );
        }
        assert_eq!(staging.staged_len(), 0);
        assert_eq!(staging.history_disposed(), 1);
        let (_, next_position) = prepare_call(&mut scene, &mut staging, &init);
        assert!(next_position > first_position);
        let before = reducer.calls();
        assert_eq!(
            staging
                .apply_seal(
                    &first,
                    &scene.model,
                    scene.adapter.ledger_mut(),
                    &mut reducer,
                    &mut keyuse,
                    RegistryInstanceId::from_raw(3),
                    &mut sink,
                    None,
                )
                .0,
            SealApplyOutcome::Held
        );
        assert_eq!(staging.staged_len(), 1);
        assert_eq!(reducer.calls(), before);
        let next = scene.seal().expect("new own invocation seals");
        assert_eq!(
            staging
                .apply_seal(
                    &next,
                    &scene.model,
                    scene.adapter.ledger_mut(),
                    &mut reducer,
                    &mut keyuse,
                    RegistryInstanceId::from_raw(3),
                    &mut sink,
                    None,
                )
                .0,
            SealApplyOutcome::ReplayedOne
        );
    }
}

#[test]
fn key_operation_c2_frontier_new_session_reuses_positions_with_foreign_seals_inert() {
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let mut old = JointScene::new();
    let receipt = old.bootstrap();
    let mut old_staging = JointStaging::select_joint(Some(&receipt));
    let (_, old_position) = prepare_call(&mut old, &mut old_staging, &init);
    let old_seal = old.seal().expect("old namespace seals its own input");
    let mut old_reducer = EdgeSemantics::default();
    let mut old_keyuse = KeyUseReducer::new();
    let mut old_sink = Vec::new();
    assert_eq!(
        old_staging
            .apply_seal(
                &old_seal,
                &old.model,
                old.adapter.ledger_mut(),
                &mut old_reducer,
                &mut old_keyuse,
                RegistryInstanceId::from_raw(3),
                &mut old_sink,
                None,
            )
            .0,
        SealApplyOutcome::ReplayedOne
    );

    let mut new = JointScene::new();
    let receipt = new.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&receipt));
    let (_, position) = prepare_call(&mut new, &mut staging, &init);
    assert_eq!(old_position, position);
    let own = new.seal().expect("new namespace seals its own input");
    let mut reducer = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    assert_eq!(
        staging
            .apply_seal(
                &old_seal,
                &old.model,
                new.adapter.ledger_mut(),
                &mut reducer,
                &mut keyuse,
                RegistryInstanceId::from_raw(3),
                &mut sink,
                None,
            )
            .0,
        SealApplyOutcome::Held
    );
    assert_eq!(staging.staged_len(), 1);
    assert_eq!(reducer.calls(), 0);
    assert_eq!(
        staging
            .apply_seal(
                &own,
                &new.model,
                new.adapter.ledger_mut(),
                &mut reducer,
                &mut keyuse,
                RegistryInstanceId::from_raw(3),
                &mut sink,
                None,
            )
            .0,
        SealApplyOutcome::ReplayedOne
    );
    assert_eq!(
        staging
            .apply_seal(
                &old_seal,
                &old.model,
                new.adapter.ledger_mut(),
                &mut reducer,
                &mut keyuse,
                RegistryInstanceId::from_raw(3),
                &mut sink,
                None,
            )
            .0,
        SealApplyOutcome::Held
    );
    assert_eq!(staging.reduced(), 1);
    // This uses the established H8/H9 algorithm scenes. It does not claim
    // actual native cleanup or capture-owned A→B Session transfer acceptance.
}

#[test]
fn key_operation_c2_frontier_max_disposal_cannot_wrap_or_reset() {
    let mut scene = JointScene::new();
    let receipt = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&receipt));
    let facts = SemanticCall {
        function: "C_Sign".into(),
        ..SemanticCall::default()
    };
    staging
        .stage(
            facts.clone(),
            EffectOrigin::from(&facts),
            u64::MAX,
            scene.adapter.ledger_mut(),
        )
        .unwrap();
    assert_eq!(
        staging.dispose_below_barrier(None, Some(scene.adapter.ledger_mut())),
        1
    );
    for position in [0, 1, u64::MAX - 1, u64::MAX] {
        assert_eq!(
            staging.stage(
                facts.clone(),
                EffectOrigin::from(&facts),
                position,
                scene.adapter.ledger_mut()
            ),
            Err(StagingRefusal::ReplayRefused)
        );
    }
    assert_eq!(staging.history_disposed(), 1);
    assert_eq!(staging.reduced(), 0);
    assert_eq!(staging.staged_len(), 0);
}

/// The admission ordinal one single-call seal binds (C2 test helper):
/// the settled call's key.
fn first_pos_of(seal: &SealSuccess) -> u64 {
    seal.prefix.settled()[0].key.admission()
}

/// G29 (N1b): cross-session destroy through Joint. A live use from
/// session 7 destroyed from session 8 loses its join (session never
/// gates retirement); a completed use's definite history stands
/// while the object row shows destroyed. S1 records the destroy
/// without inventing an operation.
#[test]
fn key_operation_n1c_shared_owner_unsettled_census() {
    // N1(c): H8 open begins, staged H9 payloads, model pending calls
    // and prospective key associations share ONE reservation owner:
    // 1,020 opens + 1 staged + 3 assocs fill the 1,024 census, and
    // the next charge in ANY population refuses even though no
    // per-population cap is reached.
    let mut scene = JointScene::new();
    let create = function_id("C_CreateObject");
    for sequence in 1..=1_020u64 {
        let begin = begin_bytes(1, sequence, create, 0);
        assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
    }
    assert_eq!(scene.adapter.ledger().census(), 1_020);
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let call = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let admitted = scene.fixture.admit_shaped(
        call.session.unwrap_or(SESSION),
        call.name,
        call.rv,
        call.mechanism,
        call.capture,
        call.flags,
    );
    scene.adapter.attest_key(&admitted).expect("call attests");
    let facts = admitted.s1_facts().clone();
    let origin = EffectOrigin::from(&facts);
    let position = admitted.h0_ordinal();
    staging
        .stage(facts, origin, position, scene.adapter.ledger_mut())
        .expect("stages at census 1,020");
    assert_eq!(scene.adapter.ledger().census(), 1_021);
    // Three prospective associations against the same owner: one
    // S1Only-direct start fanned over distinct instances.
    let mut edge = EdgeSemantics::default();
    let mut start_sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    let start_origin = EffectOrigin::from(&c);
    edge.observe_with_effects(&c, &start_origin, &mut start_sink);
    let start = start_sink
        .iter()
        .find(|effect| matches!(effect, OperationEffect::Started { .. }))
        .cloned()
        .expect("proved start");
    let mut keyuse = KeyUseReducer::new();
    for n in 0..3u32 {
        keyuse.observe_effect(
            RegistryInstanceId::from_raw(n),
            &start,
            Some(scene.adapter.ledger_mut()),
            None,
        );
    }
    assert_eq!(keyuse.open().len(), 3);
    assert_eq!(scene.adapter.ledger().census(), 1_024);
    // The next charge in every population refuses: the shared
    // ceiling binds, not the per-population caps.
    assert_eq!(
        scene.ingest(&begin_bytes(1, 1_021, create, 0)),
        JournalDisposition::BeginRefusedCapacity
    );
    let call2 = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    let admitted2 = scene.fixture.admit_shaped(
        call2.session.unwrap_or(SESSION),
        call2.name,
        call2.rv,
        call2.mechanism,
        call2.capture,
        call2.flags,
    );
    scene.adapter.attest_key(&admitted2).expect("call attests");
    let facts2 = admitted2.s1_facts().clone();
    let origin2 = EffectOrigin::from(&facts2);
    assert_eq!(
        staging.stage(
            facts2,
            origin2,
            admitted2.h0_ordinal(),
            scene.adapter.ledger_mut()
        ),
        Err(StagingRefusal::Full)
    );
    keyuse.observe_effect(
        RegistryInstanceId::from_raw(3),
        &start,
        Some(scene.adapter.ledger_mut()),
        None,
    );
    assert_eq!(keyuse.open().len(), 3, "fourth assoc refuses");
    assert_eq!(keyuse.refused_opens().len(), 1);
    let domain = crate::semantics_objects::ObjectDomain::reference(9, 9, 9, 9, 1);
    scene
        .model
        .register_domain(domain)
        .expect("reference domain registers");
    let model_origin = crate::semantics_objects::OriginFact {
        domain,
        cut: crate::semantics_objects::RefCut::reference(1),
        key: crate::semantics_objects::CallKey::reference(1),
        entry_ns: 100,
        function: crate::kinds::function_id("C_CreateObject").expect("known function"),
        session: crate::semantics_objects::HandleInput::Absent,
        inputs: [
            crate::semantics_objects::HandleInput::Absent,
            crate::semantics_objects::HandleInput::Absent,
        ],
        requested: [None, None],
        entry_mechanism: crate::semantics_objects::MechanismEvidence::NotCaptured,
        scope: crate::semantics_objects::SlotScope::Unknown,
        entry_output: crate::semantics_objects::OutputEvidence::NotCaptured,
    };
    assert_eq!(
        scene.model.begin(model_origin, scene.adapter.ledger_mut()),
        Err(crate::semantics_objects::ObjectGap::PendingCapacity)
    );
}

#[test]
fn key_operation_n1_genuine_birth_bootstrap() {
    // N1(a): H9 Joint bootstrap needs no scripted birth receipt. The
    // same genuine-producer chain T3 pins (a natively published READY
    // marker naming the admitted exec, a real admission control row,
    // live held custody) observes, the issued grant attests, and the
    // Joint path replays on top of the observed receipt.
    use crate::attach::observe_exec_birth;
    use p11scope_ebpf_common::journal_marker::ready_word;

    let publisher = NativePublisher::build();
    let mut scene = JointScene::new();
    let create = function_id("C_CreateObject");
    let begin = begin_bytes(9, 1, create, 0);
    let paired_end = end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
    let p11scope_ebpf_common::object_journal::JournalRecord::End(paired_end) =
        decode_journal_record(&paired_end, &scene.descriptors).expect("paired sighting END")
    else {
        panic!("END input")
    };
    let admitted = scene
        .fixture
        .admit_original_event("C_CreateObject", paired_end.payload_base().event);
    let proof = scene
        .adapter
        .attest_key(&admitted)
        .expect("sighting call attests");
    let generation = scene.fixture.attachment().generation();
    let (row, control, wins) = publisher.publish_stamped(&["0", "1"], generation);
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
    let grant = SessionBirthGrant::issue_for_native_row_test(
        &token,
        proof,
        BirthKind::ExecMarker,
        0,
        generation,
        evidence,
    );
    // The sighting ingest T3 runs before attesting, on a spare
    // thread so the Joint flow's own sequencing stays untouched.
    scene.ingest(&begin);
    scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
    let birth = BootstrapReceipt::attest(&scene.adapter, &grant).expect("observed grant attests");
    // Fresh native words at seal: a second publisher run, pulled
    // through a new reader — never the first run's words (T3's
    // re-observation at seal, mirrored for the Joint bootstrap).
    let (fresh_row, fresh_control, _) = publisher.publish_stamped(&["0", "1"], generation);
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
    // Settle the sighting pair on its own seal so each Joint
    // quantum below settles exactly its own call.
    let pre = scene
        .seal_with_birth(&birth, fresh)
        .expect("sighting pair seals");
    assert_eq!(pre.prefix.settled().len(), 1, "sighting pair settles alone");
    let mut staging = JointStaging::select_joint(Some(&birth));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    assert_eq!(joint.started(), 1, "joint replays on observed birth");
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("the open use stands");
    assert_eq!((row.active, row.key_join_lost), (1, 0));
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    assert_eq!((joint.started(), joint.completed()), (1, 1));
}

#[test]
fn key_operation_g29_cross_session_destroy() {
    // --- Open use + cross-session destroy: the join is lost. ---
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    let (started, completed) = (joint.started(), joint.completed());
    let mut destroy = ShapedS1::shaped("C_DestroyObject", CkRv::OK.0, 0, 0);
    destroy.session = Some(8);
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &destroy,
    );
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("the live use stands");
    assert_eq!(
        (row.active, row.key_join_lost),
        (0, 1),
        "cross-session destroy loses the open join"
    );
    let key = sink
        .iter()
        .find_map(|effect| match effect {
            OperationEffect::Started { key_receipt, .. } => *key_receipt,
            _ => None,
        })
        .expect("init start carries its receipt")
        .key;
    let object = committed
        .objects
        .iter()
        .find(|row| row.object == key.as_u64())
        .expect("the use's object row stands");
    assert_eq!(
        object.lifetime, "retired",
        "S3 d1: the possibly-shared view retires uncertain, never destroyed"
    );
    assert!(
        committed
            .objects
            .iter()
            .any(|row| row.lifetime == "destroyed"),
        "the cross-session destroy takes effect"
    );
    assert_eq!(
        (joint.started(), joint.completed()),
        (started, completed),
        "S1 records the destroy without inventing an operation"
    );

    // --- Completed history + cross-session destroy: history stands. ---
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let mut destroy = ShapedS1::shaped("C_DestroyObject", CkRv::OK.0, 0, 0);
    destroy.session = Some(8);
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &destroy,
    );
    let committed = commit(2, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("definite history stands");
    assert_eq!(
        (row.started, row.completed, row.active, row.key_join_lost),
        (1, 1, 0, 0),
        "a later destroy never rewrites a completed use"
    );
    let key = sink
        .iter()
        .find_map(|effect| match effect {
            OperationEffect::Started { key_receipt, .. } => *key_receipt,
            _ => None,
        })
        .expect("init start carries its receipt")
        .key;
    let object = committed
        .objects
        .iter()
        .find(|row| row.object == key.as_u64())
        .expect("the use's object row stands");
    assert_eq!(
        object.lifetime, "retired",
        "S3 d1: the possibly-shared view retires uncertain, never destroyed"
    );
    assert!(
        committed
            .objects
            .iter()
            .any(|row| row.lifetime == "destroyed"),
        "the cross-session destroy takes effect"
    );
}

/// G29 (N1b): a failed close changes nothing through Joint. The
/// FUNCTION_FAILED close leaves the session live (S3), its machines
/// live (S1), its key use live (H9) and its object live.
#[test]
fn key_operation_g29_failed_close_changes_nothing() {
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    assert!(joint.has_live_operations(), "precondition: live machine");
    let close = ShapedS1::shaped("C_CloseSession", CkRv::FUNCTION_FAILED.0, 0, 0);
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &close,
    );
    assert!(joint.has_live_operations(), "failed close ends no machine");
    assert_eq!(
        (joint.cancelled(), joint.completed()),
        (0, 0),
        "failed close routes no terminal"
    );
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("the live use stands");
    assert_eq!(
        (row.active, row.key_join_lost),
        (1, 0),
        "failed close retires no binding"
    );
    let key = sink
        .iter()
        .find_map(|effect| match effect {
            OperationEffect::Started { key_receipt, .. } => *key_receipt,
            _ => None,
        })
        .expect("init start carries its receipt")
        .key;
    let object = committed
        .objects
        .iter()
        .find(|row| row.object == key.as_u64())
        .expect("the object row stands");
    assert_eq!(object.lifetime, "live", "failed close destroys nothing");
}

/// G29 (N1b): uncertain concurrent same-session overlap through
/// Joint matches the S1Only twin exactly. Whatever S1 decides for
/// the overlapping second Init, Joint replays it identically —
/// equivalence, never invented S1.
#[test]
fn key_operation_g29_concurrent_overlap_matches_s1only_twin() {
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    let mut twin = EdgeSemantics::default();
    let mut twin_sink = Vec::new();
    // Two overlapping Inits on one session, same key and mechanism.
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    for _ in 0..2 {
        let (facts, position) = prepare_call(&mut scene, &mut staging, &init);
        let _ = position;
        let origin = EffectOrigin::from(&facts);
        twin.observe_with_effects(&facts, &origin, &mut twin_sink);
        let seal = scene.seal().expect("quantum seals");
        assert_eq!(seal.prefix.settled().len(), 1);
        use crate::discovery::caller_registry::instance_input::RegistryInstanceId;
        let (outcome, _) = staging.apply_seal(
            &seal,
            &scene.model,
            scene.adapter.ledger_mut(),
            &mut joint,
            &mut keyuse,
            RegistryInstanceId::from_raw(3),
            &mut sink,
            None,
        );
        assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    }
    assert_s1_equal(&joint, &twin);
    assert_eq!(joint.calls(), 2, "both overlapping calls reduce once");
}

/// G29 (N1b): ambiguous destroy widens uncertainty without inventing
/// destruction. The GENERAL_ERROR cross-session destroy retires
/// (never destroys); definite completed history stands; S1 records
/// the call without inventing an operation.
#[test]
fn key_operation_g29_unknown_scope_widens_without_inventing() {
    // G29 (N1b): unknown token/scope widening through Joint. H8
    // emits SlotScope::Unknown for these shapes; the model must
    // never invent known scope, and an ambiguous cross-session
    // destroy widens the object lifetime (retired) instead of
    // destroying it, while the completed sign history stands.
    use crate::semantics_objects::Lifetime;

    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let mut destroy = ShapedS1::shaped("C_DestroyObject", CkRv::GENERAL_ERROR.0, 0, 0);
    destroy.session = Some(8);
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &destroy,
    );
    let projection = scene.model.project();
    assert!(!projection.sessions.is_empty(), "sessions observed");
    assert!(
        projection.sessions.iter().all(|view| !view.scope_known),
        "unknown scope is never invented known"
    );
    assert!(
        projection
            .objects
            .iter()
            .any(|view| matches!(view.lifetime, Lifetime::Retired(_))),
        "ambiguity widens lifetime to retired"
    );
    assert!(
        projection
            .objects
            .iter()
            .all(|view| !matches!(view.lifetime, Lifetime::Destroyed)),
        "never synthesize destruction from failure"
    );
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("definite history stands");
    assert_eq!(
        (row.started, row.completed, row.active, row.key_join_lost),
        (1, 1, 0, 0),
        "ambiguity never rewrites a completed use"
    );
}

#[test]
fn key_operation_g29_ambiguous_close_sweeps_retire_without_destroying() {
    // G29 (N1b): ambiguous creator-close sweeps through Joint. S3
    // (s2s3_creator_close_scope_failed_and_ambiguous_close) pins:
    // GENERAL_ERROR/SESSION_CLOSED/DEVICE_REMOVED closes retire
    // object views and end the session — never destroy. H9 ends the
    // live binding (key_join_lost) without rewriting S1.
    use crate::semantics_objects::{Lifetime, SessionState};

    for rv in [
        CkRv::GENERAL_ERROR.0,
        CkRv::SESSION_CLOSED.0,
        CkRv::DEVICE_REMOVED.0,
    ] {
        let mut scene = JointScene::new();
        let bootstrap = scene.bootstrap();
        let mut staging = JointStaging::select_joint(Some(&bootstrap));
        let mut joint = EdgeSemantics::default();
        let mut keyuse = KeyUseReducer::new();
        let mut sink = Vec::new();
        for session in [7u64, 8u64] {
            let mut open = ShapedS1::shaped("C_OpenSession", CkRv::OK.0, 0, 0);
            open.session = Some(session);
            drive_quantum(
                &mut scene,
                &mut staging,
                &mut joint,
                &mut keyuse,
                &mut sink,
                &open,
            );
        }
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
        );
        let get = ShapedS1 {
            getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
            ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
        };
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &get,
        );
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
        );
        assert!(joint.has_live_operations(), "rv {rv:#x}: live machine");
        let close = ShapedS1::shaped("C_CloseSession", rv, 0, 0);
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &close,
        );
        let projection = scene.model.project();
        assert!(
            projection
                .objects
                .iter()
                .any(|view| matches!(view.lifetime, Lifetime::Retired(_))),
            "rv {rv:#x}: ambiguity widens lifetime to retired"
        );
        assert!(
            projection
                .objects
                .iter()
                .all(|view| !matches!(view.lifetime, Lifetime::Destroyed)),
            "rv {rv:#x}: never synthesize destruction from failure"
        );
        assert!(
            projection
                .sessions
                .iter()
                .any(|view| matches!(view.state, SessionState::Ended(_))),
            "rv {rv:#x}: the closed session ends"
        );
        let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
        let row = committed
            .key_operations
            .iter()
            .find(|row| row.category == "sign")
            .expect("rv {rv:#x}: the use row stands");
        assert_eq!(
            (row.active, row.key_join_lost),
            (0, 1),
            "rv {rv:#x}: the ended session ends its binding"
        );
    }
}

#[test]
fn key_operation_g29_ambiguous_destroy_widens_without_destroying() {
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let (started, completed) = (joint.started(), joint.completed());
    let mut destroy = ShapedS1::shaped("C_DestroyObject", CkRv::GENERAL_ERROR.0, 0, 0);
    destroy.session = Some(8);
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &destroy,
    );
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("definite history stands");
    assert_eq!(
        (row.started, row.completed, row.active, row.key_join_lost),
        (1, 1, 0, 0),
        "ambiguity never rewrites a completed use"
    );
    assert!(
        committed
            .objects
            .iter()
            .all(|row| row.lifetime != "destroyed"),
        "never synthesize destruction from failure (S3)"
    );
    assert_eq!(
        (joint.started(), joint.completed()),
        (started, completed),
        "S1 records the call without inventing an operation"
    );
}

/// G29 (N1b): creator close versus accessor view through Joint. The
/// creator session's close destroys its objects (S3) and cancels its
/// live S1 machines; the accessor session's machines stay live and
/// its views retire uncertain (never destroyed).
#[test]
fn key_operation_g29_creator_close_vs_accessor_view() {
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    // Open both sessions first (S3 close needs opened sessions).
    for session in [7u64, 8u64] {
        let mut open = ShapedS1::shaped("C_OpenSession", CkRv::OK.0, 0, 0);
        open.session = Some(session);
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &open,
        );
    }
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    // Creator use on session 7, accessor use of the same key on 8.
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    let mut accessor = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    accessor.session = Some(8);
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &accessor,
    );
    assert_eq!(joint.started(), 2, "precondition: both machines live");
    let close = ShapedS1::shaped("C_CloseSession", CkRv::OK.0, 0, 0);
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &close,
    );
    // S1: the creator session's machine cancels; the accessor's stays
    // live.
    assert_eq!(joint.cancelled(), 1, "creator close cancels its machine");
    assert!(joint.has_live_operations(), "accessor machine stays live");
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    // H9: the creator's proved use loses its join (session retired)
    // and its cancelled terminal routes to key_join_lost; the
    // accessor's use stays live on its own live session.
    let creator = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("the creator use stands");
    assert_eq!(
        (creator.active, creator.key_join_lost),
        (0, 1),
        "creator close retires its session's joins"
    );
    let routed = committed
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "key_join_lost")
        .expect("the cancelled terminal routes once");
    assert_eq!(routed.cancelled, 1);
    let accessor = committed
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "metadata_unknown")
        .expect("the accessor use stands");
    assert_eq!(accessor.active, 1, "accessor session stays live");
}

/// G29 (N1b): delivery/equivalence matrix through the registry.
/// Seal delivery replays S1-identical to the direct twin; proof-only
/// fallback preserves S1 while exposing no invented object/key facts
/// (unknown rows only, never proved); real loss preserves definite
/// completed history.
#[test]
fn key_operation_g29_delivery_equivalence_matrix() {
    // --- Seal delivery == direct twin. ---
    let mut guarded = GuardedScene::new();
    let bootstrap = guarded.scene.bootstrap();
    let joint_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(joint_key.clone(), bootstrap);
    let (_, joint_id) = guarded.register(1);
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let sign = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    let mut twin = EdgeSemantics::default();
    let mut twin_sink = Vec::new();
    for shape in [&init, &sign] {
        let (facts, position) = guarded.admit_shape(shape);
        let origin = EffectOrigin::from(&facts);
        twin.observe_with_effects(&facts, &origin, &mut twin_sink);
        guarded.observe(&joint_key, position, facts);
        guarded
            .registry
            .publish_with_ledger(guarded.scene.adapter.ledger_mut());
        ingest_call(&mut guarded.scene, shape, position);
        let seal = guarded.scene.seal().expect("quantum seals");
        assert_eq!(
            guarded.registry.deliver_joint_algorithm_seal_for_test(
                joint_id,
                &seal,
                &guarded.scene.model,
                guarded.scene.adapter.ledger_mut(),
            ),
            SealApplyOutcome::ReplayedOne
        );
    }
    let edge = guarded
        .registry
        .instance_semantic_edges()
        .find(|record| record.id == joint_id)
        .expect("edge retained")
        .semantics
        .as_ref()
        .expect("materialized");
    assert_s1_equal(edge, &twin);

    // --- Proof-only fallback: S1 preserved, nothing invented. ---
    let mut guarded = GuardedScene::new();
    let bootstrap = guarded.scene.bootstrap();
    let joint_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(joint_key.clone(), bootstrap);
    let (_, joint_id) = guarded.register(1);
    let (facts, position) = guarded.admit_shape(&init);
    let mut twin = EdgeSemantics::default();
    let mut twin_sink = Vec::new();
    let origin = EffectOrigin::from(&facts);
    twin.observe_with_effects(&facts, &origin, &mut twin_sink);
    guarded.observe(&joint_key, position, facts);
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    let failure = guarded.scene.adapter.scripted_failure(
        JournalGap::ClosureStale,
        &bootstrap,
        crate::semantics_objects::ObjectEffects::default(),
    );
    let mut clean = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    assert_eq!(
        guarded.registry.deliver_joint_algorithm_failure_for_test(
            joint_id,
            &failure,
            &mut clean,
            &guarded.scene.model,
            guarded.scene.adapter.ledger_mut(),
        ),
        FailureApplyOutcome::FellBack { replayed: 1 }
    );
    let edge = guarded
        .registry
        .instance_semantic_edges()
        .find(|record| record.id == joint_id)
        .expect("edge retained")
        .semantics
        .as_ref()
        .expect("materialized");
    assert_s1_equal(edge, &twin);
    let observations = guarded.registry.joint_observations(16);
    assert!(
        observations.key_operations.is_empty(),
        "fallback exposes no invented object/key facts"
    );
    assert!(
        !observations.unknown_key_operations.is_empty(),
        "definite S1 still accounts unknown-key"
    );

    // --- Real loss: definite completed history stands. ---
    let mut guarded = GuardedScene::new();
    let bootstrap = guarded.scene.bootstrap();
    let joint_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(joint_key.clone(), bootstrap);
    let (_, joint_id) = guarded.register(1);
    assert_eq!(
        guarded.drive_joint(&joint_key, joint_id, &init),
        SealApplyOutcome::ReplayedOne
    );
    assert_eq!(
        guarded.drive_joint(&joint_key, joint_id, &sign),
        SealApplyOutcome::ReplayedOne
    );
    let failure = guarded.scene.adapter.scripted_failure(
        JournalGap::FaultChanged,
        &bootstrap,
        crate::semantics_objects::ObjectEffects::default(),
    );
    let mut h3 = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    assert_eq!(
        guarded.registry.deliver_joint_algorithm_failure_for_test(
            joint_id,
            &failure,
            &mut h3,
            &guarded.scene.model,
            guarded.scene.adapter.ledger_mut(),
        ),
        FailureApplyOutcome::Degraded { disposed: 0 }
    );
    assert_eq!(
        (
            guarded.edge_calls(joint_id),
            guarded.edge_started(joint_id),
            guarded.edge_completed(joint_id)
        ),
        (2, 1, 1),
        "real loss preserves definite completed S1 history"
    );
}

/// N9: emitter digest tracking is bounded by the current
/// publication: churning single-object publications (each object
/// pruned before the next arrives) never accumulates tracking for
/// absent rows.
#[test]
fn key_operation_emitter_tracking_bounded_across_object_churn() {
    use crate::key_operation_projection::{
        MetadataBlock, MetadataField, ObjectObservations, ObjectRow, ObsStatus, QueriesBlock,
    };

    fn churned(revision: u64, object: u64) -> ObjectObservations {
        let mut observations = ObjectObservations::unavailable(revision, "bootstrap_unavailable");
        observations.status = ObsStatus::Populated;
        observations.reason = "none";
        let blank = MetadataField {
            status: "absent",
            scalar: None,
            curve: None,
        };
        let block = MetadataBlock {
            class: blank,
            key_type: blank,
            token: blank,
            value_len: blank,
            modulus_bits: blank,
            ec_params: blank,
        };
        observations.objects.push(ObjectRow {
            object,
            session: 7,
            origin: "observed",
            creation: None,
            birth: None,
            lifetime: "destroyed",
            lifetime_reason: None,
            attribution: "valid",
            attribution_reason: None,
            requested: block,
            established: block,
            queries: QueriesBlock {
                class: "not_queried",
                key_type: "not_queried",
                token: "not_queried",
                value_len: "not_queried",
                modulus_bits: "not_queried",
                ec_params: "not_queried",
            },
            label: None,
            successful_references: 1,
            successful_key_references: 0,
            accessing_sessions: 1,
        });
        observations
    }

    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 8 << 20, 5).unwrap();
    let mut emitter = KeyOperationEmitter::new();
    let mut peak = 0usize;
    for id in 1..=2_000u64 {
        let observations = churned(id, id);
        emitter
            .emit(&mut writer, &observations, id * 1_000)
            .unwrap();
        peak = peak.max(emitter.tracked());
    }
    assert_eq!(emitter.tracked(), 1, "only the current row stays tracked");
    assert!(peak <= 2, "tracking never accumulates churn: peak {peak}");
}

/// N6: key history pins its object records inline. Under a
/// 1-object cap, retiring the key-used object then admitting a
/// newcomer must REFUSE the newcomer visibly (ObjectCapacity) while
/// the proved row still names the original — never prune the
/// referent and paper over it with a gap entry.
#[test]
fn key_operation_pinned_key_object_refuses_newcomer() {
    use crate::semantics_objects::{ObjectGap, ObjectLimits};

    const OTHER_KEY: u64 = 0xB3B3_B3B3_B3B3_B3B3;
    let mut scene = JointScene::new();
    scene.model = ObjectSemantics::with_limits(ObjectLimits {
        views_per_instance: 1,
        object_records: 1,
        ..ObjectLimits::policy()
    });
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();

    // Lifetime 1: create, label, key-use (pins the record),
    // destroy (retires it but the proved row still names it).
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1 {
            input0: Some((CREATED_KEY, 1)),
            getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
            ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
        },
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let id1 = scene.model.project().objects[0].id;
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_DestroyObject", CkRv::OK.0, 0, 0),
    );
    // Lifetime 2: the newcomer must refuse, visibly.
    let mut second = ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0);
    second.result = Some(OTHER_KEY);
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &second,
    );
    let projected = scene.model.project();
    assert!(
        projected.gap(ObjectGap::ObjectCapacity) >= 1,
        "the newcomer refuses visibly while the pin holds"
    );
    assert!(
        projected.object(id1).is_some(),
        "the pinned original stays retained"
    );
    assert_eq!(projected.objects.len(), 1);
    let committed = commit(11, &[&staging], &projected, &keyuse);
    assert!(
        committed
            .key_operations
            .iter()
            .any(|row| row.object == id1.as_u64()),
        "the proved row still names its retained referent"
    );
    assert!(
        !committed
            .gaps
            .iter()
            .any(|gap| gap.reason == "pruned_object_referenced"),
        "a retained referent never dangles"
    );
}

/// H9-§3: the frozen contract. Rendered sections carry exactly the
/// frozen keys and enums (pinned key-for-key against the schema file
/// and the golden); row equations, sort orders and the no-started
/// unknown rule hold; every vocabulary map is exhaustive; the
/// status matrix, stale publication, sink failure, full-budget
/// terminals and deferred delivery behave exactly.
#[test]
fn key_operation_schema_contract() {
    let mut assoc_ledger = StagingLedger::new();
    use crate::key_operation_projection::contract::*;
    use crate::key_operation_projection::producer::{gap_label, metadata_field, query_label};
    use crate::semantics_edge::KeyRole;
    use crate::semantics_key_use::{
        UNKNOWN_BUCKETS, UNKNOWN_CATEGORIES, UNKNOWN_REASONS as REDUCER_REASONS, metadata_label,
        role_label,
    };
    use crate::semantics_key_use::{binds_keys, unbound_reason_for, unit_for};
    use crate::semantics_objects::{FieldState, FieldValue, KeyLabel, QueryStatus};

    // ---- Frozen tables mirror the schema file key-for-key. ----
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            root.join("docs/schema/inventory-v1-object-observations.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let defs = &schema["$defs"];
    let required = |pointer: &str| -> Vec<String> {
        let mut keys: Vec<String> = schema
            .pointer(pointer)
            .unwrap_or(&serde_json::Value::Null)
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|key| key.as_str().unwrap().to_string())
            .collect();
        keys.sort();
        keys
    };
    let table = |keys: &[&str]| -> Vec<String> {
        let mut owned: Vec<String> = keys.iter().map(|key| key.to_string()).collect();
        owned.sort();
        owned
    };
    assert_eq!(required("/required"), table(&SECTION_KEYS), "section keys");
    assert_eq!(
        required("/$defs/session_row/required"),
        table(&SESSION_ROW_KEYS)
    );
    assert_eq!(
        required("/$defs/object_row/required"),
        table(&OBJECT_ROW_KEYS)
    );
    assert_eq!(required("/$defs/key_row/required"), table(&KEY_ROW_KEYS));
    assert_eq!(
        required("/$defs/unknown_row/required"),
        table(&UNKNOWN_ROW_KEYS)
    );
    assert_eq!(required("/$defs/gap_row/required"), table(&GAP_ROW_KEYS));
    assert_eq!(
        required("/properties/budgets/required"),
        table(&BUDGET_KEYS)
    );
    assert_eq!(required("/properties/gaps/required"), table(&GAP_KEYS));
    assert_eq!(
        required("/$defs/row_budget/required"),
        table(&ROW_BUDGET_KEYS)
    );
    assert_eq!(
        required("/$defs/metadata_block/required"),
        table(&METADATA_KEYS)
    );
    let enums = |pointer: &str| -> Vec<String> {
        let mut values: Vec<String> = schema
            .pointer(pointer)
            .unwrap_or(&serde_json::Value::Null)
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect();
        values.sort();
        values
    };
    assert_eq!(enums("/properties/status/enum"), table(&STATUS_LABELS));
    assert_eq!(
        enums("/properties/reason/enum"),
        table(&crate::key_operation_projection::REASON_LABELS)
    );
    assert_eq!(enums("/$defs/category/enum"), table(&CATEGORY_LABELS));
    // The reducer's fixed-summary vocabulary mirrors the frozen
    // contract tables exactly (same sets, same order): admission
    // and publication index the same buckets.
    assert_eq!(UNKNOWN_CATEGORIES.as_slice(), CATEGORY_LABELS.as_slice());
    assert_eq!(REDUCER_REASONS.as_slice(), UNKNOWN_REASONS.as_slice());
    assert_eq!(UNKNOWN_BUCKETS, 23 * 6);
    assert_eq!(enums("/$defs/role/enum"), table(&ROLE_LABELS));
    assert!(
        ROLE_LABELS.contains(&crate::key_operation_projection::SECONDARY_ROLE),
        "the secondary tally exclusion stays frozen vocabulary"
    );
    assert_eq!(enums("/$defs/unit/enum"), table(&UNIT_LABELS));
    assert_eq!(enums("/$defs/metadata_label/enum"), table(&METADATA_LABELS));
    assert_eq!(enums("/$defs/unknown_reason/enum"), table(&UNKNOWN_REASONS));
    assert_eq!(enums("/$defs/gap_reason/enum"), table(&GAP_REASONS));
    assert_eq!(enums("/$defs/query_status/enum"), table(&QUERY_STATUSES));
    assert_eq!(
        defs["row_budget"]["properties"]["limit"],
        serde_json::json!({"const": 65536})
    );
    assert_eq!(
        enums("/$defs/session_row/properties/origin/enum"),
        table(&SESSION_ORIGINS)
    );
    assert_eq!(
        enums("/$defs/session_row/properties/status/enum"),
        table(&SESSION_STATUSES)
    );
    assert_eq!(
        enums("/$defs/object_row/properties/origin/enum"),
        table(&OBJECT_ORIGINS)
    );
    assert_eq!(
        enums("/$defs/object_row/properties/creation/enum"),
        table(&CREATION_LABELS)
    );

    // ---- The golden carries exactly the frozen keys. ----
    let golden: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            root.join("tests/fixtures/key-operations/object-observations.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let keys_of = |value: &serde_json::Value| -> Vec<String> {
        let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        keys
    };
    assert_eq!(
        keys_of(&golden),
        table(&SECTION_KEYS),
        "golden section keys"
    );
    for row in golden["sessions"].as_array().unwrap() {
        assert_eq!(keys_of(row), table(&SESSION_ROW_KEYS));
    }
    for row in golden["objects"].as_array().unwrap() {
        assert_eq!(keys_of(row), table(&OBJECT_ROW_KEYS));
        assert_eq!(keys_of(&row["requested"]), table(&METADATA_KEYS));
        assert_eq!(keys_of(&row["established"]), table(&METADATA_KEYS));
        for field in [
            "class",
            "key_type",
            "token",
            "value_len",
            "modulus_bits",
            "ec_params",
        ] {
            assert_eq!(keys_of(&row["requested"][field]), table(&FIELD_KEYS));
            assert_eq!(keys_of(&row["established"][field]), table(&FIELD_KEYS));
        }
        assert_eq!(keys_of(&row["queries"]), table(&METADATA_KEYS));
        if !row["birth"].is_null() {
            assert_eq!(keys_of(&row["birth"]), table(&BIRTH_KEYS));
        }
    }
    for row in golden["key_operations"].as_array().unwrap() {
        assert_eq!(keys_of(row), table(&KEY_ROW_KEYS));
    }
    for row in golden["unknown_key_operations"].as_array().unwrap() {
        assert_eq!(keys_of(row), table(&UNKNOWN_ROW_KEYS));
    }
    assert_eq!(keys_of(&golden["gaps"]), table(&GAP_KEYS));
    for row in golden["gaps"]["rows"].as_array().unwrap() {
        assert_eq!(keys_of(row), table(&GAP_ROW_KEYS));
    }
    assert_eq!(keys_of(&golden["budgets"]), table(&BUDGET_KEYS));
    assert_eq!(
        keys_of(&golden["budgets"]["key_rows"]),
        table(&ROW_BUDGET_KEYS)
    );
    assert_eq!(
        keys_of(&golden["budgets"]["object_rows"]),
        table(&ROW_BUDGET_KEYS)
    );
    assert_eq!(
        keys_of(&golden["budgets"]["unknown_rows"]),
        table(&UNKNOWN_BUDGET_KEYS)
    );

    // ---- Every vocabulary map is exhaustive over its source. ----
    let gaps = [
        crate::semantics_objects::ObjectGap::BootstrapUnproven,
        crate::semantics_objects::ObjectGap::BootstrapRefused,
        crate::semantics_objects::ObjectGap::PrefixContradiction,
        crate::semantics_objects::ObjectGap::StalePrefix,
        crate::semantics_objects::ObjectGap::ClosedFrontier,
        crate::semantics_objects::ObjectGap::DuplicateCall,
        crate::semantics_objects::ObjectGap::DuplicateCompletion,
        crate::semantics_objects::ObjectGap::StaleToken,
        crate::semantics_objects::ObjectGap::FencedCompletion,
        crate::semantics_objects::ObjectGap::MalformedFact,
        crate::semantics_objects::ObjectGap::UnsupportedFunction,
        crate::semantics_objects::ObjectGap::DomainEnded,
        crate::semantics_objects::ObjectGap::ResultProtocolUnavailable,
        crate::semantics_objects::ObjectGap::PendingResultUnavailable,
        crate::semantics_objects::ObjectGap::OutputUnreadable,
        crate::semantics_objects::ObjectGap::PairDuplicate,
        crate::semantics_objects::ObjectGap::NullMechanismCancel,
        crate::semantics_objects::ObjectGap::SameSessionOverlap,
        crate::semantics_objects::ObjectGap::OverlapUncertain,
        crate::semantics_objects::ObjectGap::OutputCollision,
        crate::semantics_objects::ObjectGap::StaleOrigin,
        crate::semantics_objects::ObjectGap::DependencyBroken,
        crate::semantics_objects::ObjectGap::UnprovenInput,
        crate::semantics_objects::ObjectGap::UnprovenSession,
        crate::semantics_objects::ObjectGap::MetadataUncertain,
        crate::semantics_objects::ObjectGap::DestroyAlias,
        crate::semantics_objects::ObjectGap::CloseUncertain,
        crate::semantics_objects::ObjectGap::CloseAllUncertain,
        crate::semantics_objects::ObjectGap::LogoutUncertain,
        crate::semantics_objects::ObjectGap::SessionClosed,
        crate::semantics_objects::ObjectGap::InvalidHandle,
        crate::semantics_objects::ObjectGap::AmbiguousOutcome,
        crate::semantics_objects::ObjectGap::SessionContradiction,
        crate::semantics_objects::ObjectGap::HandleReuse,
        crate::semantics_objects::ObjectGap::Finalize,
        crate::semantics_objects::ObjectGap::TokenReset,
        crate::semantics_objects::ObjectGap::Exec,
        crate::semantics_objects::ObjectGap::Fork,
        crate::semantics_objects::ObjectGap::Unload,
        crate::semantics_objects::ObjectGap::Loss,
        crate::semantics_objects::ObjectGap::PendingCapacity,
        crate::semantics_objects::ObjectGap::SessionCapacity,
        crate::semantics_objects::ObjectGap::ObjectCapacity,
        crate::semantics_objects::ObjectGap::InstanceCapacity,
        crate::semantics_objects::ObjectGap::IdExhausted,
        crate::semantics_objects::ObjectGap::DeviceLoss,
        crate::semantics_objects::ObjectGap::UnseenFinalize,
        crate::semantics_objects::ObjectGap::InconsistentMechanism,
        crate::semantics_objects::ObjectGap::OutcomeLost,
        crate::semantics_objects::ObjectGap::UnknownDomain,
        crate::semantics_objects::ObjectGap::DomainPruned,
    ];
    assert_eq!(gaps.len(), 51, "every model gap enumerated");
    let mut mapped: Vec<&str> = gaps.iter().map(|gap| gap_label(*gap)).collect();
    mapped.sort_unstable();
    mapped.dedup();
    assert_eq!(mapped.len(), 51, "gap labels are distinct");
    assert!(mapped.iter().all(|label| GAP_REASONS.contains(label)));
    assert!(GAP_REASONS.contains(&"pruned_object_referenced"));
    assert_eq!(GAP_REASONS.len(), 52);

    let roles = [
        (KeyRole::OperationKey, "key"),
        (KeyRole::WrappingKey, "wrapping_key"),
        (KeyRole::WrappedKey, "wrapped_object"),
        (KeyRole::BaseKey, "base_key"),
        (KeyRole::UnwrappingKey, "unwrapping_key"),
        (KeyRole::Other, "other"),
    ];
    for (role, expected) in roles {
        assert_eq!(role_label(role), expected);
        assert!(ROLE_LABELS.contains(&expected));
    }
    let labels = [
        (KeyLabel::Rsa { modulus_bits: 1024 }, "rsa_1024"),
        (KeyLabel::Rsa { modulus_bits: 2048 }, "rsa_2048"),
        (KeyLabel::Rsa { modulus_bits: 3072 }, "rsa_3072"),
        (KeyLabel::Rsa { modulus_bits: 4096 }, "rsa_4096"),
        (KeyLabel::Rsa { modulus_bits: 512 }, "rsa_other"),
        (KeyLabel::Aes { value_len: 16 }, "aes_128"),
        (KeyLabel::Aes { value_len: 24 }, "aes_192"),
        (KeyLabel::Aes { value_len: 32 }, "aes_256"),
        (KeyLabel::Aes { value_len: 8 }, "aes_other"),
        (
            KeyLabel::Ec {
                curve: p11scope_ebpf_common::object_policy::SafeCurve::Secp256r1,
            },
            "ec_p256",
        ),
        (
            KeyLabel::Ec {
                curve: p11scope_ebpf_common::object_policy::SafeCurve::Secp384r1,
            },
            "ec_p384",
        ),
        (
            KeyLabel::Ec {
                curve: p11scope_ebpf_common::object_policy::SafeCurve::Secp521r1,
            },
            "ec_p521",
        ),
    ];
    for (label, expected) in labels {
        assert_eq!(metadata_label(label), expected);
        assert!(METADATA_LABELS.contains(&expected));
    }
    for category in CATEGORY_LABELS {
        assert!(UNIT_LABELS.contains(&unit_for(category)), "{category}");
        assert!(
            UNKNOWN_REASONS.contains(&unbound_reason_for(category)),
            "{category}"
        );
        let applicable = ![
            "generate_key",
            "generate_key_pair",
            "digest",
            "direct",
            "encapsulate",
            "decapsulate",
        ]
        .contains(&category);
        assert_eq!(binds_keys(category), applicable, "{category}");
        let message = matches!(
            category,
            "message_encrypt" | "message_decrypt" | "message_sign" | "message_verify"
        );
        assert_eq!(
            unit_for(category),
            if message {
                "message_contexts"
            } else {
                "operations"
            }
        );
    }
    let queries = [
        (QueryStatus::NotQueried, "not_queried"),
        (QueryStatus::Established, "established"),
        (QueryStatus::Unavailable, "unavailable"),
        (QueryStatus::SizeOnly, "size_only"),
        (QueryStatus::Unsupported, "unsupported"),
        (QueryStatus::Malformed, "malformed"),
        (QueryStatus::Excluded, "excluded"),
    ];
    for (status, expected) in queries {
        assert_eq!(query_label(status), expected);
        assert!(QUERY_STATUSES.contains(&expected));
    }
    let curve = p11scope_ebpf_common::object_policy::SafeCurve::Secp384r1;
    let fields = [
        (FieldState::Unknown, "unknown", None, None),
        (
            FieldState::Value(FieldValue::Scalar(2048)),
            "value",
            Some(2048u16),
            None,
        ),
        (
            FieldState::Value(FieldValue::Curve(curve)),
            "value",
            None,
            Some("secp384r1"),
        ),
        (
            FieldState::Conflict(Some(FieldValue::Scalar(7))),
            "conflict",
            Some(7),
            None,
        ),
        (FieldState::Conflict(None), "conflict", None, None),
        (
            FieldState::Invalidated(Some(FieldValue::Scalar(9))),
            "invalidated",
            Some(9),
            None,
        ),
        (FieldState::Invalidated(None), "invalidated", None, None),
    ];
    for (state, status, scalar, curve_name) in fields {
        let field = metadata_field(state);
        assert_eq!(field.status, status);
        assert!(FIELD_STATUSES.contains(&status));
        assert_eq!(field.scalar, scalar);
        assert_eq!(field.curve, curve_name);
        if let Some(name) = curve_name {
            assert!(CURVE_LABELS.contains(&name));
        }
    }

    // ---- Rendered output carries exactly the frozen keys/enums. ----
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    for call in [
        ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
        ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
        ShapedS1::shaped("C_VerifyInit", CkRv::OK.0, RSA_PKCS, init_capture()),
        ShapedS1::shaped("C_Verify", CkRv::SIGNATURE_INVALID.0, 0, op_capture()),
        ShapedS1::shaped("C_DestroyObject", CkRv::OK.0, 0, 0),
    ] {
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &call,
        );
    }
    let r1 = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(r1.status, ObsStatus::Populated);
    let section = object_observations_json(&r1);
    assert_eq!(
        keys_of(&section),
        table(&SECTION_KEYS),
        "rendered section keys"
    );
    assert_eq!(section["version"], 1);
    assert_eq!(section["revision"], 1);
    assert!(STATUS_LABELS.contains(&section["status"].as_str().unwrap()));
    assert_eq!(section["reason"], "none");
    for row in section["sessions"].as_array().unwrap() {
        assert_eq!(keys_of(row), table(&SESSION_ROW_KEYS));
        assert!(row["session"].as_u64().is_some());
    }
    assert!(!section["sessions"].as_array().unwrap().is_empty());
    for row in section["objects"].as_array().unwrap() {
        assert_eq!(keys_of(row), table(&OBJECT_ROW_KEYS));
        assert_eq!(keys_of(&row["requested"]), table(&METADATA_KEYS));
        assert_eq!(keys_of(&row["established"]), table(&METADATA_KEYS));
        for field in [
            "class",
            "key_type",
            "token",
            "value_len",
            "modulus_bits",
            "ec_params",
        ] {
            assert_eq!(keys_of(&row["requested"][field]), table(&FIELD_KEYS));
            assert_eq!(keys_of(&row["established"][field]), table(&FIELD_KEYS));
            assert!(
                FIELD_STATUSES.contains(&row["established"][field]["status"].as_str().unwrap())
            );
            assert!(QUERY_STATUSES.contains(&row["queries"][field].as_str().unwrap()));
        }
        assert_eq!(keys_of(&row["queries"]), table(&METADATA_KEYS));
        if !row["birth"].is_null() {
            assert_eq!(keys_of(&row["birth"]), table(&BIRTH_KEYS));
        }
        if let Some(label) = row["label"].as_str() {
            assert!(METADATA_LABELS.contains(&label));
        }
        assert!(LIFETIME_LABELS.contains(&row["lifetime"].as_str().unwrap()));
        assert!(ATTRIBUTION_LABELS.contains(&row["attribution"].as_str().unwrap()));
    }
    assert_eq!(section["objects"][0]["lifetime"], "destroyed");
    assert_eq!(section["objects"][0]["label"], "rsa_2048");
    for row in section["key_operations"].as_array().unwrap() {
        assert_eq!(keys_of(row), table(&KEY_ROW_KEYS));
        assert!(CATEGORY_LABELS.contains(&row["category"].as_str().unwrap()));
        assert!(ROLE_LABELS.contains(&row["role"].as_str().unwrap()));
        assert!(METADATA_LABELS.contains(&row["metadata_at_use"].as_str().unwrap()));
        assert!(UNIT_LABELS.contains(&row["unit"].as_str().unwrap()));
        let total = row["completed"].as_u64().unwrap()
            + row["failed"].as_u64().unwrap()
            + row["cancelled"].as_u64().unwrap()
            + row["unknown"].as_u64().unwrap()
            + row["active"].as_u64().unwrap()
            + row["key_join_lost"].as_u64().unwrap();
        assert_eq!(row["started"], total, "row equation holds for {row}");
        assert!(row["instance"].as_str().unwrap().starts_with('i'));
    }
    for row in section["unknown_key_operations"].as_array().unwrap() {
        assert_eq!(keys_of(row), table(&UNKNOWN_ROW_KEYS));
        assert!(
            row.get("started").is_none(),
            "unknown rows never carry started"
        );
    }
    assert_eq!(keys_of(&section["gaps"]), table(&GAP_KEYS));
    for row in section["gaps"]["rows"].as_array().unwrap() {
        assert_eq!(keys_of(row), table(&GAP_ROW_KEYS));
        assert!(GAP_SUBJECTS.contains(&row["subject"].as_str().unwrap()));
        assert!(GAP_REASONS.contains(&row["reason"].as_str().unwrap()));
    }
    assert_eq!(keys_of(&section["budgets"]), table(&BUDGET_KEYS));
    assert_eq!(section["budgets"]["key_rows"]["limit"], 65536);
    assert_eq!(section["budgets"]["object_rows"]["limit"], 65536);
    assert_eq!(section["budgets"]["allocation_refused"], false);
    assert_eq!(section["budgets"]["refusal_reason"], "none");
    let measured = serde_json::to_vec(&section).unwrap().len();
    assert_eq!(
        section["budgets"]["encoded_bytes"], measured,
        "bytes measured, not estimated"
    );
    let order: Vec<_> = section["key_operations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["instance"].as_str().unwrap().to_string(),
                row["object"].as_u64().unwrap(),
                row["category"].as_str().unwrap().to_string(),
                row["role"].as_str().unwrap().to_string(),
                row["metadata_at_use"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let mut sorted = order.clone();
    sorted.sort();
    assert_eq!(order, sorted, "key rows sort by full key tuple");

    // ---- Receipt metadata shapes aggregate exactly. ----
    // Hand-built receipts over a REAL object id through the real
    // edge reducer: usable labels prove rows; conflicting, unknown
    // and requested-only metadata partition unknown with exact
    // reasons (requested-only RSA2048 stays untyped).
    let mut tiny = JointScene::new();
    let tiny_bootstrap = tiny.bootstrap();
    let mut tiny_staging = JointStaging::select_joint(Some(&tiny_bootstrap));
    let mut tiny_edge = EdgeSemantics::default();
    let mut tiny_keyuse = KeyUseReducer::new();
    let mut tiny_sink = Vec::new();
    drive_quantum(
        &mut tiny,
        &mut tiny_staging,
        &mut tiny_edge,
        &mut tiny_keyuse,
        &mut tiny_sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let real_id = tiny.model.project().objects[0].id;
    let sign_fn = crate::kinds::function_id("C_SignInit").unwrap();
    let rsa = KeyLabel::Rsa { modulus_bits: 2048 };
    // (label, attribution_valid, requested, established, conflicted)
    let shapes = [
        (Some(rsa), true, 0x1Fu8, 0x1Fu8, 0u8),
        (Some(rsa), true, 0x1F, 0x1F, 1u8 << 4),
        (None, true, 0u8, 0u8, 0u8),
        (None, true, 0x13u8, 0u8, 0u8),
    ];
    let mut shape_edge = EdgeSemantics::default();
    let mut shape_keyuse = KeyUseReducer::new();
    for (n, (label, attribution_valid, requested, established, conflicted)) in
        shapes.into_iter().enumerate()
    {
        let receipt = crate::semantics_edge::KeyReceipt {
            key: real_id,
            function: sign_fn,
            input: 0,
            role: KeyRole::OperationKey,
            position: 700 + n as u64,
            metadata: crate::semantics_objects::KeyMetadataFlags {
                requested,
                established,
                conflicted,
            },
            label,
            attribution_valid,
            lost: false,
        };
        let mut start_sink = Vec::new();
        let c = init("C_SignInit", 7, RSA_PKCS, 800_000 + n as u64 * 10);
        let origin = EffectOrigin::from(&c);
        shape_edge.observe_joint(&c, &origin, std::slice::from_ref(&receipt), &mut start_sink);
        assert_eq!(start_sink.len(), 1);
        for effect in &start_sink {
            shape_keyuse.observe_effect(instance, effect, Some(&mut assoc_ledger), None);
        }
        let mut end_sink = Vec::new();
        let c = op("C_Sign", 7, 800_005 + n as u64 * 10);
        let origin = EffectOrigin::from(&c);
        shape_edge.observe_with_effects(&c, &origin, &mut end_sink);
        assert_eq!(end_sink.len(), 1);
        for effect in &end_sink {
            shape_keyuse.observe_effect(instance, effect, Some(&mut assoc_ledger), None);
        }
    }
    let shaped_commit = commit(9, &[&tiny_staging], &tiny.model.project(), &shape_keyuse);
    assert_eq!(shaped_commit.status, ObsStatus::Populated);
    let proved = shaped_commit
        .key_operations
        .iter()
        .find(|row| row.metadata_at_use == "rsa_2048")
        .expect("the usable label proves its row");
    assert_eq!((proved.started, proved.completed), (1, 1));
    assert_eq!(
        shaped_commit.key_operations.len(),
        1,
        "only the usable label proves"
    );
    let conflicting = shaped_commit
        .unknown_key_operations
        .iter()
        .find(|row| row.reason == "metadata_conflicting")
        .expect("required-field conflict partitions unknown");
    assert_eq!(conflicting.completed, 1);
    let unknown = shaped_commit
        .unknown_key_operations
        .iter()
        .find(|row| row.reason == "metadata_unknown")
        .expect("unknown and requested-only partition unknown");
    assert_eq!(unknown.completed, 2, "requested-only RSA2048 stays untyped");
    assert!(
        !shaped_commit
            .gaps
            .iter()
            .any(|gap| gap.reason == "pruned_object_referenced"),
        "live objects never dangle"
    );
    // The pruned-reference tripwire is defensive-only: through the
    // model a proved bucket's referent is pinned (N6), so a real
    // commit never dangles — but an inconsistent embedding that
    // commits proved history against a model missing the referent
    // still renders the row (history is immutable) and fires the
    // tripwire loudly, never silently.
    let pruned_model = JointScene::new().model.project();
    assert!(pruned_model.objects.is_empty());
    let pruned_commit = commit(10, &[&tiny_staging], &pruned_model, &shape_keyuse);
    assert_eq!(
        pruned_commit.key_operations.len(),
        1,
        "the proved row stays"
    );
    let tripwire = pruned_commit
        .gaps
        .iter()
        .find(|gap| gap.reason == "pruned_object_referenced")
        .expect("the inconsistent embedding trips the wire");
    assert_eq!(tripwire.subject, "key_operation");
    assert_eq!(
        tripwire.repeats, 1,
        "only proved buckets retain object references; unknown summaries count outcomes"
    );

    // ---- The status matrix: every feed census maps exactly. ----
    let fresh = JointStaging::select_s1_only();
    let empty_model = JointScene::new().model.project();
    let empty_keyuse = KeyUseReducer::new();
    let never_joint = commit(1, &[&fresh], &empty_model, &empty_keyuse);
    assert_eq!(never_joint.status, ObsStatus::Unavailable);
    assert_eq!(never_joint.reason, "bootstrap_unavailable");
    assert!(never_joint.key_operations.is_empty());
    assert!(never_joint.unknown_key_operations.is_empty());

    // Proof-only refusal: the replayed S1 is preserved (unknown-key
    // rows exist) while no object facts are invented.
    let mut fall_scene = JointScene::new();
    let fall_bootstrap = fall_scene.bootstrap();
    let mut fall_staging = JointStaging::select_joint(Some(&fall_bootstrap));
    let mut fall_edge = EdgeSemantics::default();
    let mut fall_keyuse = KeyUseReducer::new();
    let mut fall_sink = Vec::new();
    for call in sign_flow()[0..3].iter() {
        prepare_call(&mut fall_scene, &mut fall_staging, call);
    }
    let failure = fall_scene.adapter.scripted_failure(
        JournalGap::BootstrapMismatch,
        &fall_bootstrap,
        crate::semantics_objects::ObjectEffects::default(),
    );
    let clean = H3DispositionEvidence::scripted_clean(u64::MAX);
    let mut h3 = ScriptedH3Source::once(clean);
    let (outcome, _) = fall_staging.apply_algorithm_failure_for_test(
        &failure,
        &mut h3,
        &fall_scene.model,
        fall_scene.adapter.ledger_mut(),
        &mut fall_edge,
        &mut fall_keyuse,
        instance,
        &mut fall_sink,
        None,
    );
    assert!(matches!(
        outcome,
        crate::semantics_key_use::FailureApplyOutcome::FellBack { replayed: 3 }
    ));
    assert!(fall_staging.fell_back());
    let fell = commit(
        2,
        &[&fall_staging],
        &fall_scene.model.project(),
        &fall_keyuse,
    );
    assert_eq!(fell.status, ObsStatus::Unavailable);
    assert_eq!(fell.reason, "proof_refused_fallback");
    assert!(fell.objects.is_empty(), "fallback invents no object facts");
    assert!(
        !fell.unknown_key_operations.is_empty(),
        "fallback preserves replayed S1"
    );

    // Real loss degrades louder than proof-only refusal.
    let mut loss_scene = JointScene::new();
    let loss_bootstrap = loss_scene.bootstrap();
    let mut loss_staging = JointStaging::select_joint(Some(&loss_bootstrap));
    let mut loss_edge = EdgeSemantics::default();
    let mut loss_keyuse = KeyUseReducer::new();
    let mut loss_sink = Vec::new();
    prepare_call(
        &mut loss_scene,
        &mut loss_staging,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let loss_failure = loss_scene.adapter.scripted_failure(
        JournalGap::H3Loss,
        &loss_bootstrap,
        crate::semantics_objects::ObjectEffects::default(),
    );
    // HistoryLoss never consults the finalizer: any scripted source will do.
    let mut loss_h3 = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    let (outcome, _) = loss_staging.apply_algorithm_failure_for_test(
        &loss_failure,
        &mut loss_h3,
        &loss_scene.model,
        loss_scene.adapter.ledger_mut(),
        &mut loss_edge,
        &mut loss_keyuse,
        instance,
        &mut loss_sink,
        None,
    );
    assert!(matches!(
        outcome,
        crate::semantics_key_use::FailureApplyOutcome::Degraded { disposed: 1 }
    ));
    assert!(loss_staging.degraded_loss());
    let lost = commit(
        3,
        &[&loss_staging],
        &loss_scene.model.project(),
        &loss_keyuse,
    );
    assert_eq!(lost.status, ObsStatus::Unavailable);
    assert_eq!(lost.reason, "authority_lost");

    // Full budget: the commit surface reports PARTIAL with exact
    // budgets; refused terminals land counted without buckets.
    let mut full_scene = JointScene::new();
    let full_bootstrap = full_scene.bootstrap();
    let mut full_staging = JointStaging::select_joint(Some(&full_bootstrap));
    let mut full_edge = EdgeSemantics::default();
    let mut full_probe = KeyUseReducer::new();
    let mut full_sink = Vec::new();
    drive_quantum(
        &mut full_scene,
        &mut full_staging,
        &mut full_edge,
        &mut full_probe,
        &mut full_sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let full_get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut full_scene,
        &mut full_staging,
        &mut full_edge,
        &mut full_probe,
        &mut full_sink,
        &full_get,
    );
    drive_quantum(
        &mut full_scene,
        &mut full_staging,
        &mut full_edge,
        &mut full_probe,
        &mut full_sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    let full_start = full_sink
        .iter()
        .find(|effect| matches!(effect, OperationEffect::Started { .. }))
        .cloned()
        .expect("proved start");
    use crate::discovery::caller_registry::instance_input::RegistryInstanceId;
    let mut full_keyuse = KeyUseReducer::with_capacity(2);
    full_keyuse.observe_effect(
        RegistryInstanceId::from_raw(0),
        &full_start,
        Some(&mut assoc_ledger),
        None,
    );
    full_keyuse.observe_effect(
        RegistryInstanceId::from_raw(1),
        &full_start,
        Some(&mut assoc_ledger),
        None,
    );
    full_keyuse.observe_effect(
        RegistryInstanceId::from_raw(2),
        &full_start,
        Some(&mut assoc_ledger),
        None,
    );
    assert!(full_keyuse.evidence().partial);
    let partial = commit(
        4,
        &[&full_staging],
        &full_scene.model.project(),
        &full_keyuse,
    );
    assert_eq!(partial.status, ObsStatus::Partial);
    assert_eq!(partial.reason, "row_budget_exhausted");
    assert_eq!(partial.budgets.key_occupied, 2);
    assert_eq!(partial.budgets.key_refused, 1);
    // The refused start's terminal lands counted without a bucket.
    let mut full_end_sink = Vec::new();
    drive_quantum(
        &mut full_scene,
        &mut full_staging,
        &mut full_edge,
        &mut KeyUseReducer::new(),
        &mut full_end_sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let full_end = full_end_sink
        .iter()
        .find(|effect| matches!(effect, OperationEffect::Ended { .. }))
        .cloned()
        .expect("sign terminal");
    full_keyuse.observe_effect(
        RegistryInstanceId::from_raw(2),
        &full_end,
        Some(&mut assoc_ledger),
        None,
    );
    assert_eq!(full_keyuse.evidence().refused_terminals, 1);

    // The producer emits only feed/budget reasons: publisher reasons
    // (publication/sink/serialization) never come from a commit.
    for reason in [
        r1.reason,
        never_joint.reason,
        fell.reason,
        lost.reason,
        partial.reason,
    ] {
        assert!(
            [
                "none",
                "bootstrap_unavailable",
                "proof_refused_fallback",
                "authority_lost",
                "row_budget_exhausted"
            ]
            .contains(&reason),
            "producer-only reason: {reason}"
        );
    }

    // ---- Stale publication: the last complete revision survives with
    // its rows and budgets intact, relabeled in place. ----
    let mut small_scene = JointScene::new();
    let small_bootstrap = small_scene.bootstrap();
    let mut small_staging = JointStaging::select_joint(Some(&small_bootstrap));
    let mut small_edge = EdgeSemantics::default();
    let mut small_keyuse = KeyUseReducer::new();
    let mut small_sink = Vec::new();
    for call in [
        ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
        ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
        ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    ] {
        drive_quantum(
            &mut small_scene,
            &mut small_staging,
            &mut small_edge,
            &mut small_keyuse,
            &mut small_sink,
            &call,
        );
    }
    let small_r1 = commit(
        1,
        &[&small_staging],
        &small_scene.model.project(),
        &small_keyuse,
    );
    for call in [
        ShapedS1::shaped("C_VerifyInit", CkRv::OK.0, RSA_PKCS, init_capture()),
        ShapedS1::shaped("C_Verify", CkRv::OK.0, 0, op_capture()),
    ] {
        drive_quantum(
            &mut small_scene,
            &mut small_staging,
            &mut small_edge,
            &mut small_keyuse,
            &mut small_sink,
            &call,
        );
    }
    let small_r2 = commit(
        2,
        &[&small_staging],
        &small_scene.model.project(),
        &small_keyuse,
    );
    assert!(
        small_r2.budgets.encoded_bytes > small_r1.budgets.encoded_bytes,
        "the second revision is genuinely bigger"
    );
    let mut publisher = ObservationPublisher::new();
    assert_eq!(publisher.publish(small_r1.clone()).revision, 1);
    assert_eq!(
        publisher.publication().unwrap().status,
        ObsStatus::Populated
    );
    let mut limited = ObservationPublisher::with_byte_limit(small_r1.budgets.encoded_bytes);
    assert_eq!(limited.publish(small_r1.clone()).revision, 1);
    let stale = limited.publish(small_r2.clone());
    assert_eq!(stale.status, ObsStatus::Stale);
    assert_eq!(stale.reason, "publication_budget_exhausted");
    assert_eq!(
        stale.revision, 1,
        "the retained revision, not the refused one"
    );
    assert_eq!(
        stale.key_operations, small_r1.key_operations,
        "rows survive intact"
    );
    assert_eq!(stale.objects, small_r1.objects);
    assert_eq!(
        stale.budgets, small_r1.budgets,
        "budgets keep content state"
    );
    // An over-budget first publication yields the pre-reserved
    // negative: unavailable + cause, no rows, no big allocation.
    let mut starved = ObservationPublisher::with_byte_limit(10);
    let negative = starved.publish(small_r1.clone());
    assert_eq!(negative.status, ObsStatus::Unavailable);
    assert_eq!(negative.reason, "publication_budget_exhausted");
    assert_eq!(negative.revision, 1);
    assert!(negative.key_operations.is_empty() && negative.objects.is_empty());
    assert!(negative.budgets.encoded_bytes < small_r1.budgets.encoded_bytes);

    // ---- Failed sinks stale the retained publication without a new
    // snapshot; unavailable publications have nothing to stale. ----
    let attempts = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let fault = crate::inventory_events::EventFault {
        kind: "key_operations_observed",
        final_pass_only: false,
        after_ended: false,
        attempts: attempts.clone(),
    };
    let anon = tempfile::tempfile().unwrap();
    let mut failing = EventWriter::anonymous_test_sink(anon);
    failing.fault = Some(fault);
    let mut failing_emitter = KeyOperationEmitter::new();
    let error = failing_emitter
        .emit(&mut failing, &small_r1, 1_000)
        .unwrap_err();
    assert!(error.contains("key_operations_observed"), "{error}");
    let tried: Vec<String> = attempts.borrow().clone();
    assert!(
        tried.contains(&"object_observed".to_string()),
        "objects went first: {tried:?}"
    );
    assert!(tried.contains(&"key_operations_observed".to_string()));
    let before_rows = publisher.publication().unwrap().key_operations.clone();
    publisher.note_sink_failed();
    let staled = publisher.publication().unwrap();
    assert_eq!(staled.status, ObsStatus::Stale);
    assert_eq!(staled.reason, "sink_failed");
    assert_eq!(staled.revision, 1, "same revision, no new snapshot");
    assert_eq!(
        staled.key_operations, before_rows,
        "history, not fresh authority"
    );
    let mut no_rows = ObservationPublisher::new();
    no_rows.publish(ObjectObservations::unavailable(5, "bootstrap_unavailable"));
    no_rows.note_sink_failed();
    assert_eq!(
        no_rows.publication().unwrap().status,
        ObsStatus::Unavailable
    );
    assert_eq!(
        no_rows.publication().unwrap().reason,
        "bootstrap_unavailable"
    );

    // ---- Deferred delivery: the per-pass cap spreads rows across
    // passes without loss; the full stream reconstructs exactly. ----
    let dir = private_tempdir();
    let path = dir.path().join("slow.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 5).unwrap();
    let mut slow = KeyOperationEmitter::with_cap(2);
    let total_rows = small_r2.objects.len()
        + small_r2.key_operations.len()
        + small_r2.unknown_key_operations.len();
    assert!(total_rows > 2, "the cap binds");
    let mut delivered = 0usize;
    for _ in 0..total_rows + 1 {
        let out = slow.emit(&mut writer, &small_r2, 1_000).unwrap();
        delivered += out.emitted;
        if out.emitted == 0 {
            break;
        }
    }
    assert_eq!(delivered, total_rows, "every row eventually delivers");
    assert_eq!(slow.tracked(), total_rows);
    assert!(slow.deferred_total() > 0, "deferrals counted, not silent");
    drop(writer);
    let lines = read_stream(dir.path(), "slow.jsonl");
    let mut presentation = harness_presentation();
    presentation.object_observations = small_r2.clone();
    let document = render_json_from_presentation(&presentation);
    assert_reconstructed_eq_json(&reconstruct(&lines), &document["object_observations"], true);

    // ---- The snapshot path carries the same section and rows. ----
    let snap_path = dir.path().join("snap.jsonl");
    let mut snap_writer = EventWriter::create(&snap_path, 1 << 20, 5).unwrap();
    crate::inventory_events::emit_snapshot_as_events(&mut snap_writer, &presentation, 3_000)
        .unwrap();
    drop(snap_writer);
    let snap_lines = read_stream(dir.path(), "snap.jsonl");
    let snapshot = snap_lines
        .iter()
        .find(|line| line["kind"] == "snapshot")
        .expect("snapshot marker present");
    assert_eq!(
        snapshot["event"]["object_observations"],
        document["object_observations"]
    );
    assert_reconstructed_eq_json(
        &reconstruct(&snap_lines),
        &document["object_observations"],
        true,
    );
}

// ==================== 6.07c: KEM roles, creation, guards ====================
//
// Corrected-contract battery (§10 items 1-20 as replaced by the
// agreement review): independent encapsulate/decapsulate ledgers
// through the real seal/reducer/projection seam. ShapedS1 injects
// already-captured facts; the adapter read-spies (object_flow KEM
// tests) prove forbidden addresses are avoided.

/// Healthy encapsulate S1 capture: mechanism plus a non-null
/// ciphertext-output pointer.
fn kem_encap_capture() -> u32 {
    capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL
}

/// Healthy decapsulate S1 capture: mechanism only (arg 6 is a scalar
/// length value, never an output marker).
fn kem_decap_capture() -> u32 {
    capture::MECHANISM_VALUE
}

/// Encapsulation query S1 capture: null ciphertext-output pointer.
fn kem_query_capture() -> u32 {
    capture::MECHANISM_VALUE | capture::OUTPUT_NULL
}

/// Drive one KEM-shaped quantum and return the seal: like
/// `drive_quantum`, but the seal's model effects stay available for
/// exact Referenced/Created/gap assertions.
fn drive_kem_quantum(
    scene: &mut JointScene,
    staging: &mut JointStaging,
    reducer: &mut EdgeSemantics,
    keyuse: &mut KeyUseReducer,
    sink: &mut Vec<OperationEffect>,
    call: &ShapedS1,
) -> (SemanticCall, u64, SealSuccess) {
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    let (facts, position) = prepare_call(scene, staging, call);
    let success = scene.seal().expect("quantum seals");
    assert_eq!(success.prefix.settled().len(), 1, "{}", call.name);
    let (outcome, refused) = staging.apply_seal(
        &success,
        &scene.model,
        scene.adapter.ledger_mut(),
        reducer,
        keyuse,
        instance,
        sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne, "{}", call.name);
    assert_eq!(refused, 0);
    (facts, position, success)
}

fn direct_receipts(sink: &[OperationEffect]) -> Vec<crate::semantics_edge::KeyReceipt> {
    sink.iter()
        .filter_map(|effect| match effect {
            OperationEffect::DirectCompleted { key_receipts, .. } => Some(key_receipts.clone()),
            _ => None,
        })
        .flatten()
        .collect()
}

fn referenced_effects(
    success: &SealSuccess,
) -> Vec<crate::semantics_objects::ObjectEffect> {
    success
        .effects
        .effects
        .iter()
        .filter(|effect| {
            matches!(
                effect,
                crate::semantics_objects::ObjectEffect::Referenced { .. }
            )
        })
        .cloned()
        .collect()
}

/// Genuine ML-KEM input establishment: class plus an unclassifiable
/// ML-KEM key type (73). The GET lands (non-vacuous) but no usable
/// label can form under the frozen vocabulary.
fn kem_mlkem_get(word: u64) -> ShapedS1 {
    ShapedS1 {
        input0: Some((word, 1)),
        getattr_cells: vec![(1u8, 1u8, 2u16), (2u8, 1u8, 73u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    }
}

/// Item 1: encapsulation binds its input role. One qualified
/// Referenced effect (key_use, ordinal 0); the receipt carries the
/// encapsulation role; the genuine ML-KEM input partitions
/// metadata-unknown; the decapsulate ledger stays empty.
#[test]
fn key_operation_kem_encapsulate_binds_input_role() {
    use crate::semantics_objects::ObjectEffect;
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &kem_mlkem_get(CREATED_KEY),
    );
    let key = scene.model.project().objects[0].id;
    let flags = scene
        .model
        .key_metadata_flags(key)
        .expect("key view exists");
    assert!(flags.is_established(0), "the GET established Class");
    assert!(!flags.is_established(1), "ML-KEM key type stays untyped");
    let (_, _, success) = drive_kem_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped(
            "C_EncapsulateKey",
            CkRv::OK.0,
            0x17,
            kem_encap_capture(),
        ),
    );
    let referenced = referenced_effects(&success);
    assert_eq!(referenced.len(), 1, "one qualified input reference");
    match &referenced[0] {
        ObjectEffect::Referenced {
            key_use,
            input,
            label,
            attribution_valid,
            ..
        } => {
            assert!(key_use, "encapsulation input is a key use");
            assert_eq!(*input, Some(0));
            assert_eq!(*label, None, "no fabricated established label");
            assert!(attribution_valid);
        }
        other => panic!("expected Referenced, got {other:?}"),
    }
    let receipts = direct_receipts(&sink);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].role, KeyRole::EncapsulationKey);
    assert_eq!(receipts[0].input, 0);
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert!(
        committed
            .key_operations
            .iter()
            .all(|row| row.category != "encapsulate"),
        "no proved row for the genuine ML-KEM input"
    );
    let unknown: Vec<_> = committed
        .unknown_key_operations
        .iter()
        .map(|row| (row.category, row.reason, row.completed))
        .collect();
    assert_eq!(unknown, vec![("encapsulate", "metadata_unknown", 1)]);
    assert!(
        !committed.unknown_key_operations.iter().any(|row| row.category == "decapsulate")
            && !committed
                .key_operations
                .iter()
                .any(|row| row.category == "decapsulate"),
        "decapsulate ledger untouched"
    );
    // The key use counted on the input object row exactly once.
    let input_row = committed
        .objects
        .iter()
        .find(|row| row.successful_key_references == 1)
        .expect("one key use on the input");
    assert_eq!(input_row.successful_references, 1);
}

/// Item 1 twins: receipt-less and unproved encapsulation stays
/// `role_unavailable` — S1Only, zero and unreadable inputs bind no
/// receipt and prove nothing.
#[test]
fn key_operation_kem_encapsulate_unproved_twins() {
    // S1Only direct: no receipt exists, so the terminal partitions
    // role_unavailable while S1 completes.
    let mut assoc_ledger = StagingLedger::new();
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(4);
    let mut edge = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    let mut call = op("C_EncapsulateKey", 9, 700_000);
    call.mechanism = 0x17;
    for effect in feed(&mut edge, &mut sink, &call) {
        keyuse.observe_effect(instance, &effect, Some(&mut assoc_ledger), None);
    }
    assert_eq!((edge.started(), edge.completed()), (1, 1));
    assert!(keyuse.aggregates().is_empty());
    let s1only = JointStaging::select_s1_only();
    let scene = JointScene::new();
    let committed = commit(1, &[&s1only], &scene.model.project(), &keyuse);
    let unknown: Vec<_> = committed
        .unknown_key_operations
        .iter()
        .map(|row| (row.category, row.reason, row.completed))
        .collect();
    assert_eq!(unknown, vec![("encapsulate", "role_unavailable", 1)]);
    // Zero and unreadable Joint inputs join nothing: the completed
    // S1 operation partitions role_unavailable with an unproven-input
    // gap. The independently observed output still mints (the tuple
    // stays incomplete: no input is invented for it).
    for (word, status) in [(0u64, 3u8), (0u64, 2u8)] {
        let mut scene = JointScene::new();
        let bootstrap = scene.bootstrap();
        let mut staging = JointStaging::select_joint(Some(&bootstrap));
        let mut joint = EdgeSemantics::default();
        let mut keyuse = KeyUseReducer::new();
        let mut sink = Vec::new();
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
        );
        let kem = ShapedS1 {
            input0: Some((word, status)),
            ..ShapedS1::shaped("C_EncapsulateKey", CkRv::OK.0, 0x17, kem_encap_capture())
        };
        let (_, _, success) = drive_kem_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &kem,
        );
        assert!(
            referenced_effects(&success).is_empty(),
            "status {status}: no input reference"
        );
        assert!(direct_receipts(&sink).is_empty());
        let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
        let unknown: Vec<_> = committed
            .unknown_key_operations
            .iter()
            .map(|row| (row.category, row.reason, row.completed))
            .collect();
        assert_eq!(
            unknown,
            vec![("encapsulate", "role_unavailable", 1)],
            "status {status}"
        );
        assert!(
            committed.gaps.iter().any(|row| row.reason == "unproven_input"),
            "status {status}: the failed join names its gap"
        );
        assert!(
            committed
                .objects
                .iter()
                .any(|row| row.creation == Some("encapsulate")),
            "status {status}: the observed output still mints"
        );
    }
}

/// Item 1 twins: conflicting metadata partitions
/// `metadata_conflicting`; a bound receipt with invalid attribution
/// can never prove a row.
#[test]
fn key_operation_kem_conflict_and_attribution_twins() {
    // Conflicting Class across two GETs: the bound encapsulation
    // receipt partitions metadata_conflicting.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    for value in [3u16, 4u16] {
        let get = ShapedS1 {
            getattr_cells: vec![(1u8, 1u8, value)],
            ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
        };
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &get,
        );
    }
    let (_, _, success) = drive_kem_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_EncapsulateKey", CkRv::OK.0, 0x17, kem_encap_capture()),
    );
    assert_eq!(referenced_effects(&success).len(), 1);
    let receipts = direct_receipts(&sink);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].role, KeyRole::EncapsulationKey);
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert!(committed.key_operations.is_empty());
    let unknown: Vec<_> = committed
        .unknown_key_operations
        .iter()
        .map(|row| (row.category, row.reason, row.completed))
        .collect();
    assert_eq!(unknown, vec![("encapsulate", "metadata_conflicting", 1)]);
    // Invalid attribution never proves: a bound KEM receipt with a
    // usable label but invalid attribution partitions unknown.
    let mut tiny = JointScene::new();
    let tiny_bootstrap = tiny.bootstrap();
    let mut tiny_staging = JointStaging::select_joint(Some(&tiny_bootstrap));
    let mut tiny_edge = EdgeSemantics::default();
    let mut tiny_keyuse = KeyUseReducer::new();
    let mut tiny_sink = Vec::new();
    drive_quantum(
        &mut tiny,
        &mut tiny_staging,
        &mut tiny_edge,
        &mut tiny_keyuse,
        &mut tiny_sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let real_id = tiny.model.project().objects[0].id;
    let encap_fn = crate::kinds::function_id("C_EncapsulateKey").unwrap();
    let receipt = crate::semantics_edge::KeyReceipt {
        key: real_id,
        function: encap_fn,
        input: 0,
        role: KeyRole::EncapsulationKey,
        position: 700,
        metadata: crate::semantics_objects::KeyMetadataFlags {
            requested: 0x1F,
            established: 0x1F,
            conflicted: 0,
        },
        label: Some(crate::semantics_objects::KeyLabel::Aes { value_len: 32 }),
        attribution_valid: false,
        lost: false,
    };
    let call = op("C_EncapsulateKey", 7, 800_000);
    let origin = EffectOrigin::from(&call);
    let effect = OperationEffect::DirectCompleted {
        id: crate::semantics_edge::OperationId(1),
        category: "encapsulate",
        mechanism: Some(0x17),
        key_receipts: vec![receipt],
        origin,
    };
    let mut assoc_ledger = StagingLedger::new();
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    tiny_keyuse.observe_effect(instance, &effect, Some(&mut assoc_ledger), None);
    let committed = commit(2, &[&tiny_staging], &tiny.model.project(), &tiny_keyuse);
    assert!(
        committed.key_operations.is_empty(),
        "invalid attribution proves no row"
    );
    let unknown: Vec<_> = committed
        .unknown_key_operations
        .iter()
        .map(|row| (row.category, row.reason, row.completed))
        .collect();
    assert_eq!(unknown, vec![("encapsulate", "metadata_unknown", 1)]);
}

/// Item 2: decapsulation binds its input role (mirror of item 1);
/// the encapsulate ledger stays empty.
#[test]
fn key_operation_kem_decapsulate_binds_input_role() {
    use crate::semantics_objects::ObjectEffect;
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &kem_mlkem_get(CREATED_KEY),
    );
    let (_, _, success) = drive_kem_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped(
            "C_DecapsulateKey",
            CkRv::OK.0,
            0x17,
            kem_decap_capture(),
        ),
    );
    let referenced = referenced_effects(&success);
    assert_eq!(referenced.len(), 1, "one qualified input reference");
    match &referenced[0] {
        ObjectEffect::Referenced {
            key_use,
            input,
            label,
            ..
        } => {
            assert!(key_use, "decapsulation input is a key use");
            assert_eq!(*input, Some(0));
            assert_eq!(*label, None, "no fabricated established label");
        }
        other => panic!("expected Referenced, got {other:?}"),
    }
    let receipts = direct_receipts(&sink);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].role, KeyRole::DecapsulationKey);
    assert_eq!(receipts[0].input, 0);
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let unknown: Vec<_> = committed
        .unknown_key_operations
        .iter()
        .map(|row| (row.category, row.reason, row.completed))
        .collect();
    assert_eq!(unknown, vec![("decapsulate", "metadata_unknown", 1)]);
    assert!(
        !committed.unknown_key_operations.iter().any(|row| row.category == "encapsulate")
            && !committed
                .key_operations
                .iter()
                .any(|row| row.category == "encapsulate"),
        "encapsulate ledger untouched"
    );
}

/// Item 3: encapsulation mints its output object with the
/// encapsulate creation family; the output carries no role and
/// starts a second operation. Twins: unrelated old-handle reuse
/// retires and mints; result==input collision refuses without
/// merging; unavailable output preserves the proved input.
#[test]
fn key_operation_kem_encapsulate_mints_output_object() {
    use crate::semantics_objects::ObjectEffect;
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let (_, _, success) = drive_kem_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_EncapsulateKey", CkRv::OK.0, 0x17, kem_encap_capture()),
    );
    let created: Vec<_> = success
        .effects
        .effects
        .iter()
        .filter_map(|effect| match effect {
            ObjectEffect::Created { slot, object, .. } => Some((*slot, *object)),
            _ => None,
        })
        .collect();
    assert_eq!(created.len(), 1, "one output object minted");
    assert_eq!(created[0].0, 0, "slot 0 only; no pair sibling");
    // No receipt names the output: receipts carry input ordinals only.
    for receipt in direct_receipts(&sink) {
        assert_eq!(receipt.input, 0, "output carries no role");
    }
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let output_row = committed
        .objects
        .iter()
        .find(|row| row.creation == Some("encapsulate"))
        .expect("encapsulate creation family published");
    assert_eq!(output_row.origin, "created");
    assert_eq!(output_row.successful_key_references, 0);
    // Exactly one terminal for the call: the input use and the
    // creation share one DirectCompleted, never two operations.
    let directs = sink
        .iter()
        .filter(|effect| {
            matches!(
                effect,
                OperationEffect::DirectCompleted { category, .. }
                    if *category == "encapsulate"
            )
        })
        .count();
    assert_eq!(directs, 1);
}

/// Item 3 twins: unrelated reuse retires and mints; collision
/// refuses; unavailable output preserves the input.
#[test]
fn key_operation_kem_encapsulate_output_twins() {
    // Unrelated old-handle reuse: the output word names a prior
    // view that is NOT this call's input. The prior view retires
    // with HandleReuse and the output mints fresh (ordinary reuse,
    // not the input==output collision).
    const OTHER_KEY: u64 = 0xC0C0_C0C0_C0C0_C0C0;
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let other = ShapedS1 {
        result: Some(OTHER_KEY),
        ..ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &other,
    );
    assert_eq!(scene.model.project().objects.len(), 2);
    let reuse = ShapedS1 {
        kem_result: Some((OTHER_KEY, 1)),
        ..ShapedS1::shaped("C_EncapsulateKey", CkRv::OK.0, 0x17, kem_encap_capture())
    };
    let (_, _, success) = drive_kem_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &reuse,
    );
    assert_eq!(referenced_effects(&success).len(), 1, "input use stands");
    let views = scene.model.project().objects;
    assert_eq!(views.len(), 3, "retired view kept plus the fresh mint");
    let retired = views
        .iter()
        .filter(|view| {
            matches!(
                view.lifetime,
                crate::semantics_objects::Lifetime::Retired(
                    crate::semantics_objects::ObjectGap::HandleReuse
                )
            )
        })
        .count();
    assert_eq!(retired, 1, "the unrelated prior view retired by reuse");
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert!(
        committed
            .objects
            .iter()
            .any(|row| row.creation == Some("encapsulate")),
        "unrelated reuse still mints"
    );
    // Collision: result word equals this call's input word. No output
    // object is created, no identities merge, the input use stands.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let before = scene.model.project().objects.len();
    let collision = ShapedS1 {
        kem_result: Some((CREATED_KEY, 1)),
        ..ShapedS1::shaped("C_EncapsulateKey", CkRv::OK.0, 0x17, kem_encap_capture())
    };
    let (_, _, success) = drive_kem_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &collision,
    );
    assert_eq!(referenced_effects(&success).len(), 1, "input use stands");
    assert_eq!(
        scene.model.project().objects.len(),
        before,
        "collision creates no output object"
    );
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert!(
        !committed
            .objects
            .iter()
            .any(|row| row.creation == Some("encapsulate")),
        "no encapsulate creation published"
    );
    assert!(
        committed
            .gaps
            .iter()
            .any(|row| row.reason == "output_collision"),
        "the collision names its gap"
    );
    // The input binding still names its original view: no merge.
    assert_eq!(scene.model.project().objects.len(), before);
    // Unavailable output preserves the independently proved input:
    // the receipt binds and the unknown summary lands while the
    // output side reports unreadable.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let lost = ShapedS1 {
        kem_result: Some((0, 2)),
        ..ShapedS1::shaped("C_EncapsulateKey", CkRv::OK.0, 0x17, kem_encap_capture())
    };
    let (_, _, success) = drive_kem_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &lost,
    );
    assert_eq!(referenced_effects(&success).len(), 1, "input use stands");
    let receipts = direct_receipts(&sink);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].role, KeyRole::EncapsulationKey);
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert!(
        !committed
            .objects
            .iter()
            .any(|row| row.creation == Some("encapsulate")),
        "unreadable output mints nothing"
    );
    assert!(
        committed
            .gaps
            .iter()
            .any(|row| row.reason == "output_unreadable"),
        "the lost output names its gap"
    );
}

/// Item 4: decapsulation mints its output object with the
/// decapsulate creation family (mirror of item 3).
#[test]
fn key_operation_kem_decapsulate_mints_output_object() {
    use crate::semantics_objects::ObjectEffect;
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let (_, _, success) = drive_kem_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped(
            "C_DecapsulateKey",
            CkRv::OK.0,
            0x17,
            kem_decap_capture(),
        ),
    );
    let created: Vec<_> = success
        .effects
        .effects
        .iter()
        .filter_map(|effect| match effect {
            ObjectEffect::Created { slot, object, .. } => Some((*slot, *object)),
            _ => None,
        })
        .collect();
    assert_eq!(created.len(), 1, "one output object minted");
    assert_eq!(created[0].0, 0, "slot 0 only; no pair sibling");
    for receipt in direct_receipts(&sink) {
        assert_eq!(receipt.input, 0, "output carries no role");
    }
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let output_row = committed
        .objects
        .iter()
        .find(|row| row.creation == Some("decapsulate"))
        .expect("decapsulate creation family published");
    assert_eq!(output_row.origin, "created");
    // Collision refusal mirrors encapsulation.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let before = scene.model.project().objects.len();
    let collision = ShapedS1 {
        kem_result: Some((CREATED_KEY, 1)),
        ..ShapedS1::shaped(
            "C_DecapsulateKey",
            CkRv::OK.0,
            0x17,
            kem_decap_capture(),
        )
    };
    let (_, _, success) = drive_kem_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &collision,
    );
    assert_eq!(referenced_effects(&success).len(), 1, "input use stands");
    assert_eq!(
        scene.model.project().objects.len(),
        before,
        "collision creates no output object"
    );
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert!(
        committed
            .gaps
            .iter()
            .any(|row| row.reason == "output_collision"),
        "the collision names its gap"
    );
}

/// Item 5 (M2): a proved ML-KEM key_operations row is NOT
/// deliverable without a separately approved M1a contract. The
/// genuine ML-KEM input completes into the unknown summary; no
/// proved row appears for either KEM category.
#[test]
fn key_operation_kem_proved_row_needs_m1a() {
    for name in ["C_EncapsulateKey", "C_DecapsulateKey"] {
        let mut scene = JointScene::new();
        let bootstrap = scene.bootstrap();
        let mut staging = JointStaging::select_joint(Some(&bootstrap));
        let mut joint = EdgeSemantics::default();
        let mut keyuse = KeyUseReducer::new();
        let mut sink = Vec::new();
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
        );
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &kem_mlkem_get(CREATED_KEY),
        );
        let capture = if name == "C_EncapsulateKey" {
            kem_encap_capture()
        } else {
            kem_decap_capture()
        };
        drive_kem_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped(name, CkRv::OK.0, 0x17, capture),
        );
        let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
        assert!(
            committed.key_operations.is_empty(),
            "{name}: M2 proves no ML-KEM row"
        );
        assert_eq!(
            committed.unknown_key_operations.len(),
            1,
            "{name}: the terminal partitions unknown exactly once"
        );
        // Unknown metadata is not a proved row by another name: the
        // metadata vocabulary stays at 12 labels.
        assert_eq!(
            crate::key_operation_projection::contract::METADATA_LABELS.len(),
            12
        );
    }
}

/// Item 6: the M2 positive. Each function completes one
/// metadata_unknown summary and no proved KEM row; the conflict
/// twin uses metadata_conflicting; the receipt-less twin retains
/// role_unavailable.
#[test]
fn key_operation_kem_metadata_unknown_terminal() {
    for (name, category, capture) in [
        ("C_EncapsulateKey", "encapsulate", kem_encap_capture()),
        ("C_DecapsulateKey", "decapsulate", kem_decap_capture()),
    ] {
        let mut scene = JointScene::new();
        let bootstrap = scene.bootstrap();
        let mut staging = JointStaging::select_joint(Some(&bootstrap));
        let mut joint = EdgeSemantics::default();
        let mut keyuse = KeyUseReducer::new();
        let mut sink = Vec::new();
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
        );
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &kem_mlkem_get(CREATED_KEY),
        );
        drive_kem_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped(name, CkRv::OK.0, 0x17, capture),
        );
        let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
        assert!(
            committed.key_operations.is_empty(),
            "{name}: no proved KEM row"
        );
        let unknown: Vec<_> = committed
            .unknown_key_operations
            .iter()
            .map(|row| (row.category, row.reason, row.completed))
            .collect();
        assert_eq!(unknown, vec![(category, "metadata_unknown", 1)], "{name}");
        // Parsed keys and counters, not JSON byte order: the row
        // equation holds on the typed row.
        let row = &committed.unknown_key_operations[0];
        assert_eq!(row.unit, "operations");
        assert_eq!((row.failed, row.cancelled, row.unknown, row.active), (0, 0, 0, 0));
    }
}

/// Item 7: BUFFER_TOO_SMALL invents nothing on either function: no
/// input use, no output creation, no DirectCompleted. S1 observes
/// the failed API call without completing an operation.
#[test]
fn key_operation_kem_buffer_too_small_invents_nothing() {
    for (name, category, capture) in [
        ("C_EncapsulateKey", "encapsulate", kem_encap_capture()),
        ("C_DecapsulateKey", "decapsulate", kem_decap_capture()),
    ] {
        let mut scene = JointScene::new();
        let bootstrap = scene.bootstrap();
        let mut staging = JointStaging::select_joint(Some(&bootstrap));
        let mut joint = EdgeSemantics::default();
        let mut keyuse = KeyUseReducer::new();
        let mut sink = Vec::new();
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
        );
        let (started, completed) = (joint.started(), joint.completed());
        let failed = ShapedS1 {
            kem_result: Some((0, 7)),
            ..ShapedS1::shaped(name, CkRv::BUFFER_TOO_SMALL.0, 0x17, capture)
        };
        let (_, _, success) = drive_kem_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &failed,
        );
        assert!(
            referenced_effects(&success).is_empty(),
            "{name}: no input use"
        );
        assert!(
            success.effects.effects.iter().all(|effect| !matches!(
                effect,
                crate::semantics_objects::ObjectEffect::Created { .. }
            )),
            "{name}: no output creation"
        );
        assert!(
            !sink.iter().any(|effect| matches!(
                effect,
                OperationEffect::DirectCompleted { category: direct, .. }
                    if *direct == category
            )),
            "{name}: failed directs emit no DirectCompleted"
        );
        // S1 accounting: the failed call completes no operation.
        assert_eq!((joint.started(), joint.completed()), (started, completed));
        let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
        assert!(
            !committed.key_operations.iter().any(|row| row.category == category)
                && !committed
                    .unknown_key_operations
                    .iter()
                    .any(|row| row.category == category),
            "{name}: no terminal, no row"
        );
        assert!(
            !committed
                .objects
                .iter()
                .any(|row| row.creation == Some(category)),
            "{name}: no creation published"
        );
    }
}

/// Item 8: invalid-handle returns end exactly the one established
/// input's access on both functions and both RVs; unrelated views
/// stay live; nothing is first-observed or created.
#[test]
fn key_operation_kem_bad_handle_ends_input_access() {
    use crate::semantics_objects::Lifetime;
    for (name, capture) in [
        ("C_EncapsulateKey", kem_encap_capture()),
        ("C_DecapsulateKey", kem_decap_capture()),
    ] {
        for rv in [CkRv::KEY_HANDLE_INVALID.0, CkRv::OBJECT_HANDLE_INVALID.0] {
            let mut scene = JointScene::new();
            let bootstrap = scene.bootstrap();
            let mut staging = JointStaging::select_joint(Some(&bootstrap));
            let mut joint = EdgeSemantics::default();
            let mut keyuse = KeyUseReducer::new();
            let mut sink = Vec::new();
            drive_quantum(
                &mut scene,
                &mut staging,
                &mut joint,
                &mut keyuse,
                &mut sink,
                &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
            );
            const OTHER_KEY: u64 = 0xC0C0_C0C0_C0C0_C0C0;
            let other = ShapedS1 {
                result: Some(OTHER_KEY),
                ..ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0)
            };
            drive_quantum(
                &mut scene,
                &mut staging,
                &mut joint,
                &mut keyuse,
                &mut sink,
                &other,
            );
            let bad = ShapedS1 {
                kem_result: Some((0, 7)),
                ..ShapedS1::shaped(name, rv, 0x17, capture)
            };
            let (_, _, success) = drive_kem_quantum(
                &mut scene,
                &mut staging,
                &mut joint,
                &mut keyuse,
                &mut sink,
                &bad,
            );
            assert!(
                referenced_effects(&success).is_empty(),
                "{name} {rv:#x}: no input use"
            );
            let views = scene.model.project().objects;
            assert_eq!(views.len(), 2, "{name} {rv:#x}: nothing minted");
            let ended = views
                .iter()
                .filter(|view| matches!(view.lifetime, Lifetime::AccessEnded(_)))
                .count();
            assert_eq!(ended, 1, "{name} {rv:#x}: exactly one access ended");
            let live = views
                .iter()
                .filter(|view| matches!(view.lifetime, Lifetime::Live))
                .count();
            assert_eq!(live, 1, "{name} {rv:#x}: unrelated view stays live");
        }
    }
}

/// Item 9: PENDING freezes no KEM use and creates nothing; each
/// named ambiguous RV lands its gap; session-invalid closes the
/// proven session with SessionContradiction. No result-cell read
/// happens on any of these paths (adapter pins).
#[test]
fn key_operation_kem_pending_and_ambiguous_gaps() {
    use crate::semantics_objects::ObjectEffect;
    for (name, capture) in [
        ("C_EncapsulateKey", kem_encap_capture()),
        ("C_DecapsulateKey", kem_decap_capture()),
    ] {
        // PENDING: uncertainty preserved (DeferredMinted), no use, no
        // creation, no receipt.
        let mut scene = JointScene::new();
        let bootstrap = scene.bootstrap();
        let mut staging = JointStaging::select_joint(Some(&bootstrap));
        let mut joint = EdgeSemantics::default();
        let mut keyuse = KeyUseReducer::new();
        let mut sink = Vec::new();
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
        );
        let pending = ShapedS1 {
            kem_result: Some((0, 7)),
            ..ShapedS1::shaped(name, CkRv::PENDING.0, 0x17, capture)
        };
        let (_, _, success) = drive_kem_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &pending,
        );
        assert!(
            success.effects.effects.iter().any(|effect| matches!(
                effect,
                ObjectEffect::DeferredMinted { .. }
            )),
            "{name}: pending uncertainty preserved"
        );
        assert!(
            referenced_effects(&success).is_empty(),
            "{name}: PENDING freezes no use"
        );
        assert!(
            success.effects.effects.iter().all(|effect| !matches!(
                effect,
                ObjectEffect::Created { .. }
            )),
            "{name}: PENDING creates nothing"
        );
        assert!(direct_receipts(&sink).is_empty());
        let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
        assert!(
            committed.gaps.iter().any(|row| row.reason == "pending_result_unavailable"),
            "{name}: the pending gap lands"
        );
        // Each named ambiguous RV: nothing but its gap.
        for rv in [
            CkRv::GENERAL_ERROR.0,
            CkRv::DEVICE_ERROR.0,
            CkRv::DEVICE_MEMORY.0,
            CkRv::DEVICE_REMOVED.0,
            CkRv::TOKEN_NOT_PRESENT.0,
            CkRv::CRYPTOKI_NOT_INITIALIZED.0,
        ] {
            let mut scene = JointScene::new();
            let bootstrap = scene.bootstrap();
            let mut staging = JointStaging::select_joint(Some(&bootstrap));
            let mut joint = EdgeSemantics::default();
            let mut keyuse = KeyUseReducer::new();
            let mut sink = Vec::new();
            drive_quantum(
                &mut scene,
                &mut staging,
                &mut joint,
                &mut keyuse,
                &mut sink,
                &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
            );
            let ambiguous = ShapedS1 {
                kem_result: Some((0, 7)),
                ..ShapedS1::shaped(name, rv, 0x17, capture)
            };
            let (_, _, success) = drive_kem_quantum(
                &mut scene,
                &mut staging,
                &mut joint,
                &mut keyuse,
                &mut sink,
                &ambiguous,
            );
            assert!(
                referenced_effects(&success).is_empty(),
                "{name} {rv:#x}: no input use"
            );
            assert!(direct_receipts(&sink).is_empty());
            let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
            assert!(
                committed.gaps.iter().any(|row| row.reason == "ambiguous_outcome"),
                "{name} {rv:#x}: the ambiguity gap lands"
            );
            assert!(
                !committed.objects.iter().any(|row| row.creation.is_some()
                    && row.creation != Some("create")),
                "{name} {rv:#x}: no creation published"
            );
        }
    }
}

/// Item 9 twin: session-invalid KEM returns close the proven live
/// session with SessionContradiction before the creation arm runs;
/// the call uses and creates nothing.
#[test]
fn key_operation_kem_session_invalid_contradicts_session() {
    for (name, capture) in [
        ("C_EncapsulateKey", kem_encap_capture()),
        ("C_DecapsulateKey", kem_decap_capture()),
    ] {
        for rv in [CkRv::SESSION_CLOSED.0, CkRv::SESSION_HANDLE_INVALID.0] {
            let mut scene = JointScene::new();
            let bootstrap = scene.bootstrap();
            let mut staging = JointStaging::select_joint(Some(&bootstrap));
            let mut joint = EdgeSemantics::default();
            let mut keyuse = KeyUseReducer::new();
            let mut sink = Vec::new();
            drive_quantum(
                &mut scene,
                &mut staging,
                &mut joint,
                &mut keyuse,
                &mut sink,
                &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
            );
            assert_eq!(scene.model.project().sessions.len(), 1);
            let invalid = ShapedS1 {
                kem_result: Some((0, 7)),
                ..ShapedS1::shaped(name, rv, 0x17, capture)
            };
            let (_, _, success) = drive_kem_quantum(
                &mut scene,
                &mut staging,
                &mut joint,
                &mut keyuse,
                &mut sink,
                &invalid,
            );
            assert!(
                referenced_effects(&success).is_empty(),
                "{name} {rv:#x}: no input use"
            );
            let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
            assert!(
                committed.gaps.iter().any(|row| row.reason == "session_contradiction"),
                "{name} {rv:#x}: the contradiction gap lands"
            );
            assert_eq!(
                committed.sessions.len(),
                1,
                "{name} {rv:#x}: the session row survives"
            );
            assert_eq!(
                committed.sessions[0].status, "lost",
                "{name} {rv:#x}: the proven session closed"
            );
        }
    }
}

/// Item 9 twin: no KEM deferred positive. A PENDING KEM origin
/// mints its uncertainty record, but completion redeems no
/// reference and reuses no pointer: the frozen inputs are unproven,
/// never positive.
#[test]
fn key_operation_kem_no_deferred_positive() {
    use crate::semantics_objects::ObjectEffect;
    for (name, capture) in [
        ("C_EncapsulateKey", kem_encap_capture()),
        ("C_DecapsulateKey", kem_decap_capture()),
    ] {
        let mut scene = JointScene::new();
        let bootstrap = scene.bootstrap();
        let mut staging = JointStaging::select_joint(Some(&bootstrap));
        let mut joint = EdgeSemantics::default();
        let mut keyuse = KeyUseReducer::new();
        let mut sink = Vec::new();
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
        );
        let (_, _) = prepare_call(
            &mut scene,
            &mut staging,
            &ShapedS1 {
                kem_result: Some((0, 7)),
                ..ShapedS1::shaped(name, CkRv::PENDING.0, 0x17, capture)
            },
        );
        let success = scene.seal().expect("pending quantum seals");
        let ticket = success
            .effects
            .effects
            .iter()
            .find_map(|effect| match effect {
                ObjectEffect::DeferredMinted { call } => Some(*call),
                _ => None,
            })
            .expect("PENDING KEM mints its uncertainty record");
        assert_eq!(scene.model.project().usage.deferred_origins, 1);
        let redeemed = scene
            .model
            .redeem_deferred(ticket)
            .expect("live record redeems once");
        assert!(
            !redeemed.effects.iter().any(|effect| matches!(
                effect,
                ObjectEffect::Referenced { .. }
            )),
            "{name}: completion redeems no reference"
        );
        assert_eq!(scene.model.project().usage.deferred_origins, 0);
        assert!(
            scene.model.redeem_deferred(ticket).is_none(),
            "{name}: removal is the once-token; no pointer reuse"
        );
    }
}

/// Item 10: the encapsulation query corner. A null or unavailable
/// entry ciphertext-pointer decision refuses input-use inference
/// and new object authority even for CKR_OK with a readable nonzero
/// sentinel; the healthy non-null owned call is the twin; S1
/// accounting matches its existing control.
#[test]
fn key_operation_kem_query_corner_refuses_use_and_output() {
    // Null and unreadable OUTPUT decisions (plus a missing marker)
    // all refuse: no reference, no creation, no receipt.
    for capture in [
        kem_query_capture(),
        capture::MECHANISM_VALUE | capture::OUTPUT_UNREADABLE,
        capture::MECHANISM_VALUE,
    ] {
        let mut scene = JointScene::new();
        let bootstrap = scene.bootstrap();
        let mut staging = JointStaging::select_joint(Some(&bootstrap));
        let mut joint = EdgeSemantics::default();
        let mut keyuse = KeyUseReducer::new();
        let mut sink = Vec::new();
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
        );
        let before = scene.model.project().objects.len();
        let query = ShapedS1::shaped("C_EncapsulateKey", CkRv::OK.0, 0x17, capture);
        let (_, _, success) = drive_kem_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &query,
        );
        assert!(
            referenced_effects(&success).is_empty(),
            "capture {capture:#x}: no input-use inference"
        );
        assert_eq!(
            scene.model.project().objects.len(),
            before,
            "capture {capture:#x}: the nonzero sentinel mints nothing"
        );
        assert!(direct_receipts(&sink).is_empty());
        let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
        assert!(
            committed.gaps.iter().any(|row| row.reason == "result_protocol_unavailable"),
            "capture {capture:#x}: the refused protocol names its gap"
        );
        // The completed S1 terminal still partitions role_unavailable:
        // observed but unbound, never a key use.
        let unknown: Vec<_> = committed
            .unknown_key_operations
            .iter()
            .map(|row| (row.category, row.reason, row.completed))
            .collect();
        assert_eq!(
            unknown,
            vec![("encapsulate", "role_unavailable", 1)],
            "capture {capture:#x}"
        );
        // S1 still completes the observed successful call: S1
        // accounting is unchanged by the object refusal.
        assert_eq!((joint.started(), joint.completed()), (2, 2));
    }
    // Healthy twin: the non-null owned call uses and creates.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let (_, _, success) = drive_kem_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_EncapsulateKey", CkRv::OK.0, 0x17, kem_encap_capture()),
    );
    assert_eq!(referenced_effects(&success).len(), 1);
    assert_eq!(scene.model.project().objects.len(), 2);
    assert_eq!((joint.started(), joint.completed()), (2, 2));
}

/// Item 11 (model leg): hostile input scalars never establish use.
/// Unreadable/zero/width-invalid entry words join nothing and mint
/// no input view; the narrowed width range binds no second slot.
/// (Adapter read discipline is pinned by the entry-spy tests.)
#[test]
fn key_operation_kem_hostile_input_establishes_no_use() {
    // (word, status): unreadable, zero, width-invalid. Each
    // refuses the join; no input view is first-observed. Nonzero
    // words with non-VALUE statuses never reach the model: BEGIN
    // validation refuses them first (asserted below).
    for (word, status) in [(0u64, 2u8), (0u64, 3u8), (0u64, 4u8)] {
        for (name, capture) in [
            ("C_EncapsulateKey", kem_encap_capture()),
            ("C_DecapsulateKey", kem_decap_capture()),
        ] {
            let mut scene = JointScene::new();
            let bootstrap = scene.bootstrap();
            let mut staging = JointStaging::select_joint(Some(&bootstrap));
            let mut joint = EdgeSemantics::default();
            let mut keyuse = KeyUseReducer::new();
            let mut sink = Vec::new();
            drive_quantum(
                &mut scene,
                &mut staging,
                &mut joint,
                &mut keyuse,
                &mut sink,
                &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
            );
            let before = scene.model.project().objects.len();
            let hostile = ShapedS1 {
                input0: Some((word, status)),
                ..ShapedS1::shaped(name, CkRv::OK.0, 0x17, capture)
            };
            let (_, _, success) = drive_kem_quantum(
                &mut scene,
                &mut staging,
                &mut joint,
                &mut keyuse,
                &mut sink,
                &hostile,
            );
            assert!(
                referenced_effects(&success).is_empty(),
                "{name} status {status}: no input reference"
            );
            // Only the independently observed output may mint: the
            // hostile input word first-observes no view.
            let views = scene.model.project().objects;
            assert!(
                views.len() <= before + 1,
                "{name} status {status}: no input view invented"
            );
            assert!(
                !views.iter().any(|view| {
                    view.origin == crate::semantics_objects::ViewOrigin::FirstObserved
                }),
                "{name} status {status}: hostile input claims no identity"
            );
            let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
            assert!(
                committed
                    .gaps
                    .iter()
                    .any(|row| row.reason == "unproven_input"),
                "{name} status {status}: the failed join names its gap"
            );
        }
    }
    // A nonzero word with a non-VALUE status refuses BEGIN decode:
    // hostile scalars never reach the join.
    use crate::semantics_objects::journal::decode_journal_record;
    let descriptors = publish_object_descriptors();
    let probe = JointScene::new();
    for (index, name) in ["C_EncapsulateKey", "C_DecapsulateKey"]
        .into_iter()
        .enumerate()
    {
        for status in [2u8, 3u8, 4u8] {
            let call = ShapedS1 {
                input0: Some((0x1234, status)),
                ..ShapedS1::shaped(name, CkRv::OK.0, 0x17, kem_encap_capture())
            };
            let begin = begin_for_call(&probe, &call, index as u64 * 10 + status as u64);
            assert!(
                decode_journal_record(&begin, &descriptors).is_err(),
                "{name} status {status}: nonzero hostile word refuses"
            );
        }
    }
}

/// Item 12 (model leg): hostile result cells mint nothing. Null,
/// zero and unreadable cells (and a half-open tail) create no
/// output while the proved input use stands.
#[test]
fn key_operation_kem_hostile_result_mints_nothing() {
    // (word, status, gap): unreadable and zero cells report
    // output_unreadable; protocol-unavailable stays uncaptured.
    for (word, status, gap) in [
        (0u64, 2u8, "output_unreadable"),
        (0u64, 3u8, "output_unreadable"),
        (0u64, 7u8, "unexpected_output"),
    ] {
        for (name, capture) in [
            ("C_EncapsulateKey", kem_encap_capture()),
            ("C_DecapsulateKey", kem_decap_capture()),
        ] {
            let mut scene = JointScene::new();
            let bootstrap = scene.bootstrap();
            let mut staging = JointStaging::select_joint(Some(&bootstrap));
            let mut joint = EdgeSemantics::default();
            let mut keyuse = KeyUseReducer::new();
            let mut sink = Vec::new();
            drive_quantum(
                &mut scene,
                &mut staging,
                &mut joint,
                &mut keyuse,
                &mut sink,
                &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
            );
            let before = scene.model.project().objects.len();
            let hostile = ShapedS1 {
                kem_result: Some((word, status)),
                ..ShapedS1::shaped(name, CkRv::OK.0, 0x17, capture)
            };
            let (_, _, success) = drive_kem_quantum(
                &mut scene,
                &mut staging,
                &mut joint,
                &mut keyuse,
                &mut sink,
                &hostile,
            );
            assert_eq!(
                referenced_effects(&success).len(),
                1,
                "{name} status {status}: the proved input use stands"
            );
            assert_eq!(
                scene.model.project().objects.len(),
                before,
                "{name} status {status}: hostile cell mints nothing"
            );
            let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
            assert!(
                committed.gaps.iter().any(|row| row.reason == gap),
                "{name} status {status}: the lost output names {gap}"
            );
        }
    }
}

/// Item 13 (journal leg): under T0 the KEM journal record carries
/// no template authorization. A KEM BEGIN with a nonzero requested
/// list refuses decode; absent pairs stay all-zero on the wire.
#[test]
fn key_operation_kem_t0_rejects_templated_begin() {
    use crate::semantics_objects::journal::{decode_journal_record, ValidatedJournalBegin};
    let descriptors = publish_object_descriptors();
    verify_object_descriptors(&descriptors);
    let scene = JointScene::new();
    for (index, name) in ["C_EncapsulateKey", "C_DecapsulateKey"]
        .into_iter()
        .enumerate()
    {
        let call = ShapedS1::shaped(name, CkRv::OK.0, 0x17, kem_encap_capture());
        let begin = begin_for_call(&scene, &call, index as u64 + 1);
        // Healthy KEM BEGIN decodes with absent template pairs.
        let record = decode_journal_record(&begin, &descriptors).expect("healthy KEM BEGIN");
        let validated = ValidatedJournalBegin::validate(record).expect("validates");
        assert_eq!(validated.requested(), [[0u8; 36]; 2]);
        // Any nonzero requested byte refuses: no KEM template read
        // exists to authorize it.
        for offset in [128usize, 160, 164, 196] {
            let mut bad = begin;
            bad[offset] = 1;
            assert!(
                decode_journal_record(&bad, &descriptors).is_err(),
                "{name} offset {offset}: templated BEGIN refuses"
            );
        }
    }
}

/// Item 14: one KEM result is never a pair. Sequential KEM outputs
/// mint independently; no pair_duplicate rule fires with slot 1
/// absent (the capture-side partial flag is pinned by the KEM
/// return-spy test).
#[test]
fn key_operation_kem_single_result_is_never_a_pair() {
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    // Two sequential encapsulations with distinct outputs: each
    // mints; neither completion sees a pair sibling.
    const SECOND_KEY: u64 = 0xD0D0_D0D0_D0D0_D0D0;
    for output in [KEM_OUTPUT_KEY, SECOND_KEY] {
        let kem = ShapedS1 {
            kem_result: Some((output, 1)),
            ..ShapedS1::shaped("C_EncapsulateKey", CkRv::OK.0, 0x17, kem_encap_capture())
        };
        drive_kem_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &kem,
        );
    }
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let minted = committed
        .objects
        .iter()
        .filter(|row| row.creation == Some("encapsulate"))
        .count();
    assert_eq!(minted, 2, "both sequential outputs mint");
    assert!(
        !committed
            .gaps
            .iter()
            .any(|row| row.reason == "pair_duplicate"),
        "no pair rule fires with slot 1 absent"
    );
    // One receipt per call, each bound to its own input.
    assert_eq!(direct_receipts(&sink).len(), 2);
}

/// Item 17: retirement. A KEM input retired between the call's
/// begin snapshot and its completion never joins: the stale
/// original is not replaced by the current equal handle, no
/// reference binds, and the successful S1 operation stays in the
/// role_unavailable unknown summary.
#[test]
fn key_operation_kem_stale_input_is_never_replaced() {
    use crate::semantics_objects::{
        CallKey, CompletedFact, HandleInput, MechanismEvidence, ObjectDomain, ObjectEffect,
        ObjectHandle, ObjectSemantics, OriginFact, RefCut, ResultSlot, SessionHandle, SlotScope,
    };
    use crate::semantics_objects::journal::{CompleteInputPrefix, StagingLedger};
    let domain = ObjectDomain::reference(1, 1, 1, 1, 1);
    let mut model = ObjectSemantics::new();
    model.register_domain(domain).expect("domain registers");
    let mut ledger = StagingLedger::new();
    let session = SessionHandle::new(7).unwrap();
    let input = ObjectHandle::new(0xA11CE).unwrap();
    let output = ObjectHandle::new(0xB0B).unwrap();
    let scope = SlotScope::reference_known(3, 1);
    let origin = |cut: u64, key: u64, function: u32, inputs| OriginFact {
        domain,
        cut: RefCut::reference(cut),
        key: CallKey::reference(key),
        entry_ns: 100 + cut,
        function,
        session: HandleInput::Value(session),
        inputs,
        requested: [None, None],
        entry_mechanism: MechanismEvidence::Value(0x17),
        scope,
        entry_output: crate::semantics_objects::OutputEvidence::NonNull,
    };
    let completed = |cut: u64, results| CompletedFact {
        cut: RefCut::reference(cut),
        end_ns: 200 + cut,
        rv: CkRv::OK.0,
        return_mechanism: MechanismEvidence::Value(0x17),
        results,
        session_out: HandleInput::Value(session),
        found: crate::semantics_objects::FindResult::NotCaptured,
        attributes: None,
    };
    let create = crate::kinds::function_id("C_CreateObject").unwrap();
    let destroy = crate::kinds::function_id("C_DestroyObject").unwrap();
    let encap = crate::kinds::function_id("C_EncapsulateKey").unwrap();
    // Create the input and settle it.
    let token = model
        .begin(
            origin(1, 11, create, [HandleInput::Absent, HandleInput::Absent]),
            &mut ledger,
        )
        .expect("create begins");
    model.complete(
        token,
        completed(2, [ResultSlot::Handle(input), ResultSlot::NotCaptured]),
        &mut ledger,
    );
    model.settle(
        CompleteInputPrefix::reference(domain, RefCut::reference(2), &[], Some(RefCut::reference(0))),
        &mut ledger,
    );
    // KEM begins (snapshot binds the live input), then the input is
    // destroyed, then the KEM call completes: the completion replays
    // after the retirement.
    let kem = model
        .begin(
            origin(
                3,
                13,
                encap,
                [HandleInput::Value(input), HandleInput::Absent],
            ),
            &mut ledger,
        )
        .expect("KEM begins");
    let goodbye = model
        .begin(
            origin(
                4,
                14,
                destroy,
                [HandleInput::Value(input), HandleInput::Absent],
            ),
            &mut ledger,
        )
        .expect("destroy begins");
    model.complete(
        goodbye,
        completed(5, [ResultSlot::NotCaptured, ResultSlot::NotCaptured]),
        &mut ledger,
    );
    model.complete(
        kem,
        completed(6, [ResultSlot::Handle(output), ResultSlot::NotCaptured]),
        &mut ledger,
    );
    let effects = model.settle(
        CompleteInputPrefix::reference(domain, RefCut::reference(6), &[], Some(RefCut::reference(0))),
        &mut ledger,
    );
    assert!(
        !effects.effects.iter().any(|effect| matches!(
            effect,
            ObjectEffect::Referenced { .. }
        )),
        "the stale input binds no reference"
    );
    assert!(
        !effects.effects.iter().any(|effect| matches!(
            effect,
            ObjectEffect::Rebound { .. }
        )),
        "the stale original is not replaced"
    );
    // The retired input's access stays ended; the independently
    // observed output still mints.
    let views = model.project().objects;
    assert_eq!(views.len(), 2);
    assert!(
        views.iter().any(|view| view.handle == input
            && !matches!(
                view.lifetime,
                crate::semantics_objects::Lifetime::Live
            )),
        "the input view stays retired"
    );
}

/// Item 17 (Joint leg): a KEM call against an already-retired
/// input completes its S1 operation into the role_unavailable
/// summary; no receipt binds.
#[test]
fn key_operation_kem_retired_input_stays_unavailable() {
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_DestroyObject", CkRv::OK.0, 0, 0),
    );
    let (_, _, success) = drive_kem_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_EncapsulateKey", CkRv::OK.0, 0x17, kem_encap_capture()),
    );
    assert!(referenced_effects(&success).is_empty());
    assert!(direct_receipts(&sink).is_empty());
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let unknown: Vec<_> = committed
        .unknown_key_operations
        .iter()
        .map(|row| (row.category, row.reason, row.completed))
        .collect();
    assert_eq!(unknown, vec![("encapsulate", "role_unavailable", 1)]);
}

/// Item 18: later qualification is forward-only. A KEM output's
/// untyped summary never backfills; a later GET qualifies only
/// later uses; an AES-established output qualifies its later use
/// normally.
#[test]
fn key_operation_kem_later_use_qualifies_forward_only() {
    // First use partitions unknown; a later GET establishes AES
    // metadata; the second use proves a row. The first summary is
    // never rewritten.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    drive_kem_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_EncapsulateKey", CkRv::OK.0, 0x17, kem_encap_capture()),
    );
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert!(committed.key_operations.is_empty());
    assert_eq!(committed.unknown_key_operations.len(), 1);
    // Establish AES metadata on the KEM *input* (the created key):
    // the next KEM use of that input proves its row.
    let aes = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 4u16), (2u8, 1u8, 0x1Fu16), (4u8, 1u8, 32u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &aes,
    );
    drive_kem_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_DecapsulateKey", CkRv::OK.0, 0x17, kem_decap_capture()),
    );
    let committed = commit(2, &[&staging], &scene.model.project(), &keyuse);
    // The earlier unknown summary stands untouched (no backfill);
    // the later qualified use proves exactly one row.
    let unknown: Vec<_> = committed
        .unknown_key_operations
        .iter()
        .map(|row| (row.category, row.reason, row.completed))
        .collect();
    assert_eq!(unknown, vec![("encapsulate", "metadata_unknown", 1)]);
    assert_eq!(committed.key_operations.len(), 1);
    let row = &committed.key_operations[0];
    assert_eq!(row.category, "decapsulate");
    assert_eq!(row.role, "decapsulation_key");
    assert_eq!(row.metadata_at_use, "aes_256");
    assert_eq!(row.completed, 1);
}

/// Item 19: the KEM link proof. Wire bytes drive the real
/// BEGIN/END→seal→reducer→commit chain: references equal receipts
/// (positive observation only), receipts bind to their own call,
/// repeated terminals contradict without double count, and row
/// pressure stays bounded with no invented keys.
#[test]
fn key_operation_kem_wire_to_commit_link() {
    // Mixed scene: two qualified uses, one query, one failure.
    // References and receipts agree exactly; every terminal lands
    // in its own summary.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let mut referenced_total = 0;
    for call in [
        ShapedS1::shaped("C_EncapsulateKey", CkRv::OK.0, 0x17, kem_encap_capture()),
        ShapedS1::shaped("C_DecapsulateKey", CkRv::OK.0, 0x17, kem_decap_capture()),
        ShapedS1::shaped("C_EncapsulateKey", CkRv::OK.0, 0x17, kem_query_capture()),
        ShapedS1 {
            kem_result: Some((0, 7)),
            ..ShapedS1::shaped(
                "C_EncapsulateKey",
                CkRv::BUFFER_TOO_SMALL.0,
                0x17,
                kem_encap_capture(),
            )
        },
    ] {
        let (_, _, success) = drive_kem_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &call,
        );
        referenced_total += referenced_effects(&success).len();
    }
    // Positive observation only: two references, two receipts, no
    // receipt for the query or the failure.
    assert_eq!(referenced_total, 2);
    assert_eq!(direct_receipts(&sink).len(), 2);
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert!(committed.key_operations.is_empty());
    let mut unknown: Vec<_> = committed
        .unknown_key_operations
        .iter()
        .map(|row| (row.category, row.reason, row.completed))
        .collect();
    unknown.sort();
    assert_eq!(
        unknown,
        vec![
            ("decapsulate", "metadata_unknown", 1),
            ("encapsulate", "metadata_unknown", 1),
            ("encapsulate", "role_unavailable", 1),
        ]
    );
    let creations: Vec<_> = committed
        .objects
        .iter()
        .filter_map(|row| row.creation)
        .collect();
    assert_eq!(creations.len(), 3, "create plus two KEM outputs");
    // Receipts bind to their own call only: distinct inputs stay
    // distinct across sequential terminals.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    const OTHER_KEY: u64 = 0xC0C0_C0C0_C0C0_C0C0;
    let other = ShapedS1 {
        result: Some(OTHER_KEY),
        ..ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &other,
    );
    for input in [CREATED_KEY, OTHER_KEY] {
        let kem = ShapedS1 {
            input0: Some((input, 1)),
            ..ShapedS1::shaped("C_EncapsulateKey", CkRv::OK.0, 0x17, kem_encap_capture())
        };
        drive_kem_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &kem,
        );
    }
    let directs: Vec<_> = sink
        .iter()
        .filter_map(|effect| match effect {
            OperationEffect::DirectCompleted { key_receipts, .. } => Some(key_receipts.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(directs.len(), 2, "one terminal per call");
    assert_eq!(directs[0].len(), 1);
    assert_eq!(directs[1].len(), 1);
    assert_ne!(
        directs[0][0].key, directs[1][0].key,
        "each receipt names its own call's input"
    );
    // Repeated terminals contradict: no double count is possible.
    let mut scene = JointScene::new();
    let kem = ShapedS1::shaped("C_EncapsulateKey", CkRv::OK.0, 0x17, kem_encap_capture());
    let admitted = admit_call_input(&mut scene, &kem);
    let begin = scene.paired_begins[&admitted.h0_ordinal()];
    assert_eq!(
        scene.ingest(&begin),
        crate::semantics_objects::journal::JournalDisposition::BeginAdmitted
    );
    let end = end_for_call(&begin, &kem);
    assert_eq!(
        scene.ingest(&end),
        crate::semantics_objects::journal::JournalDisposition::EndStaged
    );
    assert_eq!(
        scene.ingest(&end),
        crate::semantics_objects::journal::JournalDisposition::Contradiction(
            crate::semantics_objects::journal::JournalContradiction::DuplicateTerminal
        )
    );
    // Row pressure: thirty alternating KEM operations stay bounded
    // with exact aggregates and no invented keys.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    for round in 0..30u64 {
        let output = 0xE000_0000_0000_0000u64 | (round + 1);
        let (name, capture) = if round % 2 == 0 {
            ("C_EncapsulateKey", kem_encap_capture())
        } else {
            ("C_DecapsulateKey", kem_decap_capture())
        };
        let kem = ShapedS1 {
            kem_result: Some((output, 1)),
            ..ShapedS1::shaped(name, CkRv::OK.0, 0x17, capture)
        };
        drive_kem_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &kem,
        );
    }
    assert_eq!(direct_receipts(&sink).len(), 30);
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let mut unknown: Vec<_> = committed
        .unknown_key_operations
        .iter()
        .map(|row| (row.category, row.reason, row.completed))
        .collect();
    unknown.sort();
    assert_eq!(
        unknown,
        vec![
            ("decapsulate", "metadata_unknown", 15),
            ("encapsulate", "metadata_unknown", 15),
        ]
    );
    assert_eq!(committed.objects.len(), 31, "create plus thirty outputs");
    assert!(
        committed.objects.len()
            <= crate::semantics_objects::ObjectLimits::policy().object_records,
        "bounded object rows"
    );
}

/// Clearing twin: an abandoned KEM call disposes its staged entry
/// without proof. No reference binds, no output mints, no receipt
/// flows; the S1 observation still replays its definite payload.
#[test]
fn key_operation_kem_abandoned_call_clears_without_proof() {
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let call = ShapedS1::shaped("C_EncapsulateKey", CkRv::OK.0, 0x17, kem_encap_capture());
    let (facts, _) = attest_and_stage(&mut scene, &mut staging, &call);
    scene.sequence += 1;
    let fid = crate::kinds::function_id(call.name).unwrap();
    let begin = begin_bytes_shaped(
        scene.thread,
        scene.sequence,
        fid,
        0,
        (COOKIE, EXEC),
        SESSION,
        call.mechanism,
        call.capture,
        call.input0,
        call.input1,
        call.flags,
    );
    assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
    assert_eq!(
        scene.ingest(&abandon_bytes(
            scene.thread,
            scene.sequence,
            JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
            (COOKIE, EXEC)
        )),
        JournalDisposition::AbandonStaged
    );
    let success = scene.seal().expect("abandoned quantum seals");
    assert_eq!(success.prefix.settled().len(), 1);
    assert!(success.prefix.settled()[0].abandoned);
    assert!(referenced_effects(&success).is_empty());
    let (outcome, refused) = staging.apply_seal(
        &success,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    assert_eq!(refused, 0);
    assert!(direct_receipts(&sink).is_empty());
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert!(
        !committed
            .objects
            .iter()
            .any(|row| row.creation == Some("encapsulate")),
        "abandoned KEM mints nothing"
    );
    assert_eq!(facts.function.as_ref(), "C_EncapsulateKey");
}

/// Item 20 (H9 dispatch): the section version follows its content.
/// KEM creation or role labels publish version 2; KEM-free content
/// keeps byte-stable version 1. The JSONL stream reconstructs the
/// versioned section exactly, and dashboard tallies carry the KEM
/// categories.
#[test]
fn key_operation_h9_v2_dispatches_on_kem_content() {
    use crate::key_operation_projection::{
        OBSERVATIONS_VERSION, OBSERVATIONS_VERSION_V2, object_observations_json,
    };
    assert_eq!(OBSERVATIONS_VERSION, 1);
    assert_eq!(OBSERVATIONS_VERSION_V2, 2);
    // KEM-bearing commit renders version 2 with the new labels.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let aes = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 4u16), (2u8, 1u8, 0x1Fu16), (4u8, 1u8, 32u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &aes,
    );
    drive_kem_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_DecapsulateKey", CkRv::OK.0, 0x17, kem_decap_capture()),
    );
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let section = object_observations_json(&committed);
    assert_eq!(section["version"], 2);
    let rendered = serde_json::to_string(&section).unwrap();
    assert!(rendered.contains("\"decapsulation_key\""), "{rendered}");
    assert!(rendered.contains("\"decapsulate\""), "{rendered}");
    // The JSONL stream reconstructs the versioned section exactly.
    let dir = private_tempdir();
    let path = dir.path().join("kem.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 5).unwrap();
    let mut emitter = KeyOperationEmitter::new();
    loop {
        let out = emitter.emit(&mut writer, &committed, 1_000).unwrap();
        if out.emitted == 0 {
            break;
        }
    }
    drop(writer);
    let lines = read_stream(dir.path(), "kem.jsonl");
    assert_reconstructed_eq_json(&reconstruct(&lines), &section, true);
    // Dashboard tallies (what the keys line renders) carry the KEM
    // category with its exact counters.
    let tallies = crate::inventory_present::key_operation_tallies(&committed);
    let decap = tallies
        .iter()
        .find(|tally| tally.category == "decapsulate")
        .expect("decapsulate tally");
    assert_eq!((decap.completed, decap.failed, decap.active), (1, 0, 0));
    // KEM-free content keeps version 1: proved rows and all.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let aes = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 4u16), (2u8, 1u8, 0x1Fu16), (4u8, 1u8, 32u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &aes,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, AES_GCM, init_capture()),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert!(!committed.key_operations.is_empty(), "a proved v1 row");
    let section = object_observations_json(&committed);
    assert_eq!(section["version"], 1);
    let rendered = serde_json::to_string(&section).unwrap();
    assert!(!rendered.contains("encapsulat"), "{rendered}");
    assert!(!rendered.contains("decapsulat"), "{rendered}");
}

/// Item 20 (contracts audit): v1 tables and the v1 schema stay
/// frozen; v2 adds exactly the KEM role/creation labels; metadata
/// stays at 12; the native and canary action ranges match the wire.
#[test]
fn key_operation_kem_contracts_audit() {
    use crate::key_operation_projection::contract::*;
    // Roles 6→8, creations 6→8, metadata pinned at 12 under M2.
    assert_eq!(ROLE_LABELS.len(), 6);
    assert_eq!(ROLE_LABELS_V2.len(), 8);
    assert_eq!(
        ROLE_LABELS_V2,
        [
            "key",
            "wrapping_key",
            "wrapped_object",
            "base_key",
            "unwrapping_key",
            "encapsulation_key",
            "decapsulation_key",
            "other",
        ]
    );
    assert_eq!(CREATION_LABELS.len(), 6);
    assert_eq!(CREATION_LABELS_V2.len(), 8);
    assert_eq!(
        CREATION_LABELS_V2,
        [
            "create",
            "copy",
            "generate",
            "generate_pair",
            "derive",
            "unwrap",
            "encapsulate",
            "decapsulate",
        ]
    );
    assert_eq!(METADATA_LABELS.len(), 12);
    // v1 schema: frozen, no KEM labels, version 1.
    let v1: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string("docs/schema/inventory-v1-object-observations.schema.json")
            .expect("v1 schema reads"),
    )
    .expect("v1 schema parses");
    assert_eq!(v1["properties"]["version"]["const"], 1);
    let v1_roles = v1["properties"]["key_operations"]["items"]["properties"]["role"]["enum"]
        .as_array()
        .expect("v1 role enum");
    assert_eq!(v1_roles.len(), 6);
    assert!(
        !v1_roles.iter().any(|label| label
            .as_str()
            .is_some_and(|label| label.contains("capsulat"))),
        "v1 roles exclude KEM"
    );
    // v2 schema: version 2, v1 plus exactly the KEM labels.
    let v2: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string("docs/schema/inventory-v1-object-observations-v2.schema.json")
            .expect("v2 schema reads"),
    )
    .expect("v2 schema parses");
    assert_eq!(v2["properties"]["version"]["const"], 2);
    let v2_roles = v2["properties"]["key_operations"]["items"]["properties"]["role"]["enum"]
        .as_array()
        .expect("v2 role enum");
    assert_eq!(
        v2_roles
            .iter()
            .filter_map(|label| label.as_str())
            .collect::<Vec<_>>(),
        ROLE_LABELS_V2,
    );
    let v2_creations = v2["properties"]["objects"]["items"]["properties"]["creation"]["enum"]
        .as_array()
        .expect("v2 creation enum");
    assert_eq!(v2_creations.len(), 9, "8 creations plus null");
    // Native and canary action ranges match the wire exactly.
    let header =
        std::fs::read_to_string("crates/ebpf/native/task_owner.h").expect("native header reads");
    let define = "#define OBJECT_ACTION_MAX";
    let line = header
        .lines()
        .find(|line| line.starts_with(define))
        .expect("native action max");
    let native: u8 = line[define.len()..]
        .trim()
        .trim_end_matches('U')
        .trim()
        .parse()
        .expect("native max parses");
    assert_eq!(
        native,
        p11scope_ebpf_common::object_wire::OBJECT_ACTION_MAX
    );
    assert_eq!(
        p11scope_ebpf_common::object_wire::OBJECT_ACTION_MAX,
        14
    );
    let canary = std::fs::read_to_string("scripts/check-canary-evidence.py")
        .expect("canary script reads");
    let binding = "OBJECT_ACTION_MAX = ";
    let line = canary
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(binding))
        .expect("canary action max");
    let script: u8 = line[binding.len()..].trim().parse().expect("canary parses");
    assert_eq!(script, 14);
}

// ==================== Checkbox 5: ledger, PQC, measurement ====================

/// H9-§4: KEM endpoints are modeled (packet 6.07c stages and joins
/// them), while receipt-less S1Only-direct execution with real PQC
/// mechanism ids still partitions `role_unavailable` with S1
/// mechanism activity qualified separately: S1 mechanism counters
/// and outcomes advance unchanged, and the projection carries no
/// proved rows and no invented object facts.
#[test]
fn key_operation_pqc_matrix_negative() {
    let mut assoc_ledger = StagingLedger::new();
    use crate::semantics_key_use::StagingRefusal;

    // KEM stages now that object descriptors exist; the still-negative
    // authenticated wrap keeps the explicit Unsealable control.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    for (n, name) in ["C_EncapsulateKey", "C_DecapsulateKey"]
        .into_iter()
        .enumerate()
    {
        let fid = crate::kinds::function_id(name).unwrap();
        assert_eq!(
            crate::semantics_objects::journal::endpoint_class(fid),
            Some(crate::semantics_objects::journal::EndpointClass::ModeledAffecting),
            "{name} is modeled"
        );
        let facts = op(name, 9, 700_000 + n as u64);
        let origin = EffectOrigin::from(&facts);
        assert_eq!(
            staging.stage(facts, origin, 100 + n as u64, scene.adapter.ledger_mut()),
            Ok(()),
            "{name} stages"
        );
    }
    let auth_wrap = crate::kinds::function_id("C_WrapKeyAuthenticated").unwrap();
    assert_eq!(
        crate::semantics_objects::journal::endpoint_class(auth_wrap),
        Some(crate::semantics_objects::journal::EndpointClass::NegativeOnlyAffecting),
        "authenticated wrap withholds proof: absent prerequisite, explicit"
    );
    let facts = op("C_WrapKeyAuthenticated", 9, 700_010);
    let origin = EffectOrigin::from(&facts);
    assert_eq!(
        staging.stage(facts, origin, 110, scene.adapter.ledger_mut()),
        Err(StagingRefusal::Unsealable),
        "authenticated wrap is explicitly unstageable"
    );

    // S1Only-direct execution with real PQC mechanism ids: S1
    // mechanism activity advances; the key side reports role
    // unavailable (KEM) and not-applicable (PQC key generation).
    const CKM_ML_KEM: u64 = 0x17;
    const CKM_ML_KEM_KEY_PAIR_GEN: u64 = 0x0F;
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(4);
    let mut edge = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    for (name, mechanism, ts) in [
        ("C_EncapsulateKey", CKM_ML_KEM, 700_000u64),
        ("C_DecapsulateKey", CKM_ML_KEM, 700_001),
        ("C_GenerateKeyPair", CKM_ML_KEM_KEY_PAIR_GEN, 700_002),
    ] {
        let mut call = op(name, 9, ts);
        call.mechanism = mechanism;
        call.capture = capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL;
        for effect in feed(&mut edge, &mut sink, &call) {
            keyuse.observe_effect(instance, &effect, Some(&mut assoc_ledger), None);
        }
    }
    assert_eq!(
        (edge.started(), edge.completed()),
        (3, 3),
        "S1 outcomes unchanged"
    );
    assert_eq!(edge.failed(), 0);
    // S1 mechanism activity is qualified separately at the effect
    // level (direct calls attribute no machine-bound mechanism row):
    // the PQC ids flow through S1 effects into key-use rows, while
    // the projection contract stays mechanism-free.
    let mut direct_mechs: Vec<_> = sink
        .iter()
        .filter_map(|effect| match effect {
            OperationEffect::DirectCompleted { mechanism, .. } => Some(*mechanism),
            _ => None,
        })
        .collect();
    direct_mechs.sort();
    assert_eq!(
        direct_mechs,
        vec![
            Some(CKM_ML_KEM_KEY_PAIR_GEN),
            Some(CKM_ML_KEM),
            Some(CKM_ML_KEM)
        ]
    );
    // Aggregates carry no mechanism dimension (H9 §81: mechanism
    // stays S1 provenance): KEM activity rows unknown-key with the
    // role-unavailable reason, generation without a key role.
    assert!(keyuse.aggregates().is_empty(), "no KEM proved bucket");
    let s1only = JointStaging::select_s1_only();
    let committed = commit(1, &[&s1only], &scene.model.project(), &keyuse);
    assert_eq!(committed.status, ObsStatus::Unavailable);
    assert_eq!(committed.reason, "bootstrap_unavailable");
    assert!(committed.key_operations.is_empty(), "no KEM proved rows");
    assert!(committed.objects.is_empty(), "no KEM object read invented");
    let mut reasons: Vec<_> = committed
        .unknown_key_operations
        .iter()
        .map(|row| (row.category, row.reason, row.completed))
        .collect();
    reasons.sort();
    assert_eq!(
        reasons,
        vec![
            ("decapsulate", "role_unavailable", 1),
            ("encapsulate", "role_unavailable", 1),
            ("generate_key_pair", "not_applicable", 1),
        ]
    );
}

/// Unique scratch roots for fixture processes (parallel-safe).
static SCRATCH_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Probe the RSA ledger prerequisites: gcc, SoftHSM tool + module,
/// and a real `pkcs11.h` (system/`PKCS11_HEADER_DIR`/cryptoki-sys
/// vendor). Returns the missing pieces (empty = runnable).
fn ledger_prerequisites() -> Vec<String> {
    let mut missing = Vec::new();
    for tool in ["gcc", "softhsm2-util"] {
        let found = std::env::var_os("PATH")
            .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(tool).is_file()));
        if !found {
            missing.push(tool.to_string());
        }
    }
    let module = [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    ]
    .into_iter()
    .find(|path| std::path::Path::new(path).is_file());
    if module.is_none() {
        missing.push("libsofthsm2.so".to_string());
    }
    if pkcs11_header_dir().is_none() {
        missing.push("pkcs11.h".to_string());
    }
    missing
}

/// The directory containing a real `pkcs11.h`, mirroring the Python
/// driver's discovery (explicit env wins, cryptoki-sys vendor
/// header is the sanctioned fallback).
fn pkcs11_header_dir() -> Option<std::path::PathBuf> {
    if let Some(dir) = std::env::var_os("PKCS11_HEADER_DIR") {
        let dir = std::path::PathBuf::from(dir);
        if dir.join("pkcs11.h").is_file() {
            return Some(dir);
        }
    }
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from)?;
    let registry = home.join(".cargo/registry/src");
    let mut vendors: Vec<_> = std::fs::read_dir(&registry)
        .ok()?
        .flatten()
        .flat_map(|index| {
            std::fs::read_dir(index.path())
                .into_iter()
                .flatten()
                .flatten()
        })
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("cryptoki-sys-") {
                return None;
            }
            let dir = entry.path().join("vendor");
            dir.join("pkcs11.h").is_file().then_some(dir)
        })
        .collect();
    vendors.sort();
    vendors.into_iter().next()
}

/// Build, run (disposable token) and oracle-attest the current RSA
/// ledger fixture from build/runtime truth: the C source and oracle
/// are read from the tree, binaries/tokens/ledgers live in a private
/// scratch dir and are deleted afterwards. Returns the parsed ledger
/// rows. A missing prerequisite is the caller's skip decision (see
/// [`ledger_prerequisites`]); anything failing afterwards fails the
/// lane — a real boot/loader/run failure is never a skip.
fn run_rsa_ledger() -> Vec<serde_json::Value> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let header = pkcs11_header_dir().expect("pkcs11.h probed present");
    let module = [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    ]
    .into_iter()
    .find(|path| std::path::Path::new(path).is_file())
    .expect("SoftHSM module probed present");
    let scratch = std::env::temp_dir().join(format!(
        "p11scope-rsa-ledger-{}-{}",
        std::process::id(),
        SCRATCH_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(scratch.join("tokens")).expect("scratch tokens dir");
    std::fs::set_permissions(
        &scratch,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("scratch 0700");
    let keep_on_failure = |scratch: &std::path::Path, what: &str| -> ! {
        eprintln!("RSA ledger {what}; scratch kept at {}", scratch.display());
        panic!("RSA ledger {what}");
    };
    let conf = format!(
        "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
        scratch.join("tokens").display()
    );
    std::fs::write(scratch.join("softhsm2.conf"), conf).expect("softhsm conf");
    std::fs::set_permissions(
        scratch.join("softhsm2.conf"),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("conf 0600");
    let init = std::process::Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            "key-ledger",
            "--so-pin",
            "5678",
            "--pin",
            "1234",
        ])
        .env("SOFTHSM2_CONF", scratch.join("softhsm2.conf"))
        .output()
        .expect("spawn softhsm2-util");
    if !init.status.success() {
        keep_on_failure(&scratch, "token init failed");
    }
    let binary = scratch.join("rsa-ledger");
    let build = std::process::Command::new("gcc")
        .args([
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            header.to_str().unwrap(),
        ])
        .arg(root.join("tests/fixtures/key-operations/rsa-ledger.c"))
        .arg("-ldl")
        .arg("-o")
        .arg(&binary)
        .output()
        .expect("spawn gcc");
    if !build.status.success() {
        eprintln!("gcc stderr: {}", String::from_utf8_lossy(&build.stderr));
        keep_on_failure(&scratch, "fixture build failed");
    }
    // The fixture's absolute deadline bounds the run; the controller
    // owns/reaps the child and requires successful exit.
    let mut child = std::process::Command::new(&binary)
        .arg(module)
        .env("SOFTHSM2_CONF", scratch.join("softhsm2.conf"))
        .env("P11SCOPE_KEY_FIXTURE_PIN", "1234")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn rsa-ledger");
    use std::io::Write as _;
    child
        .stdin
        .as_mut()
        .expect("fixture stdin")
        .write_all(b"GF")
        .expect("control barriers");
    let run = child.wait_with_output().expect("reap rsa-ledger");
    if !run.status.success() {
        eprintln!("fixture stderr: {}", String::from_utf8_lossy(&run.stderr));
        keep_on_failure(&scratch, "fixture run failed");
    }
    let ledger_path = scratch.join("application.jsonl");
    std::fs::write(&ledger_path, &run.stdout).expect("write ledger");
    let oracle = std::process::Command::new("python3")
        .arg(root.join("scripts/key-operation-ledger.py"))
        .arg(&ledger_path)
        .output()
        .expect("spawn ledger oracle");
    if !oracle.status.success() {
        eprintln!("oracle stderr: {}", String::from_utf8_lossy(&oracle.stderr));
        keep_on_failure(&scratch, "oracle refused the ledger");
    }
    let mut rows = Vec::new();
    for line in String::from_utf8(run.stdout)
        .expect("ledger is UTF-8")
        .lines()
    {
        rows.push(serde_json::from_str(line).expect("ledger line parses"));
    }
    std::fs::remove_dir_all(&scratch).ok();
    rows
}

/// Replay one ledger call through the edge in ledger order:
/// mechanisms from the fixture's fixed SHA256-RSA header shape,
/// returns verbatim, the null-output size query with OUTPUT_NULL
/// (phase-known) so it retains its machine. Returns the call's
/// fresh S1 effects.
fn replay_ledger_call(
    edge: &mut EdgeSemantics,
    sink: &mut Vec<OperationEffect>,
    call: &serde_json::Value,
) -> Vec<OperationEffect> {
    const CKM_SHA256_RSA_PKCS: u64 = 0x40;
    let name = call["fn"].as_str().unwrap();
    let rv = call["rv"].as_u64().unwrap();
    let ts = call["start_ns"].as_u64().unwrap();
    let phase = call["phase"].as_str().unwrap();
    let facts = if name.ends_with("Init") {
        assert_eq!(rv, 0, "{name} inits return OK");
        let mut facts = init(name, 7, CKM_SHA256_RSA_PKCS, ts);
        facts.rv = rv;
        facts
    } else {
        let mut facts = op(name, 7, ts);
        facts.rv = rv;
        facts.mechanism = 0;
        if phase == "query" {
            // The null-output size query: OUTPUT_NULL retains the
            // machine (a bare MECHANISM_NONE clears the output field
            // and falsely completes on the query).
            facts.capture = capture::MECHANISM_NONE | capture::OUTPUT_NULL;
        }
        facts
    };
    feed(edge, sink, &facts)
}

/// N12: the null-output size query retains its machine — no
/// completion on the query; the later real terminal completes it.
#[test]
fn key_operation_size_query_stays_active() {
    let init_call =
        serde_json::json!({"fn": "C_SignInit", "rv": 0, "start_ns": 100, "phase": "init"});
    let query = serde_json::json!({"fn": "C_Sign", "rv": 0, "start_ns": 200, "phase": "query"});
    let terminal =
        serde_json::json!({"fn": "C_Sign", "rv": 0, "start_ns": 300, "phase": "terminal"});
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    assert_eq!(
        replay_ledger_call(&mut edge, &mut sink, &init_call).len(),
        1
    );
    assert!(
        replay_ledger_call(&mut edge, &mut sink, &query).is_empty(),
        "no completion on the size query"
    );
    assert_eq!((edge.started(), edge.completed(), edge.failed()), (1, 0, 0));
    assert_eq!(
        replay_ledger_call(&mut edge, &mut sink, &terminal).len(),
        1,
        "the one real terminal lands"
    );
    assert_eq!((edge.started(), edge.completed(), edge.failed()), (1, 1, 0));
    assert_eq!(edge.orphans(), 0);
}

/// H9-§4: the installed RSA ledger is the reference population. The
/// current fixture builds, runs against a disposable SoftHSM token
/// and attests clean; its 68 API calls partition 31 sign / 24 verify
/// / 13 other with 10 sign complete, 10 verify complete and 2 verify
/// failed. Replaying every real call through S1Only reduction
/// preserves those outcomes exactly into unknown-key summaries (no
/// Joint evidence exists here, so no object facts are invented).
/// Absent build/run prerequisites skip explicitly; anything failing
/// afterwards fails the lane.
#[test]
fn key_operation_rsa_ledger_reference() {
    let mut assoc_ledger = StagingLedger::new();
    let missing = ledger_prerequisites();
    if !missing.is_empty() {
        eprintln!(
            "SKIP key_operation_rsa_ledger_reference: missing {}",
            missing.join(", ")
        );
        return;
    }
    let rows = run_rsa_ledger();
    let calls: Vec<_> = rows.iter().filter(|row| row["kind"] == "call").collect();
    assert_eq!(calls.len(), 68, "the fixture's exact API population");
    let mut sign = 0usize;
    let mut verify = 0usize;
    let mut other = 0usize;
    for call in &calls {
        let name = call["fn"].as_str().unwrap();
        if name.starts_with("C_Sign") {
            sign += 1;
        } else if name.starts_with("C_Verify") {
            verify += 1;
        } else {
            other += 1;
        }
    }
    assert_eq!((sign, verify, other), (31, 24, 13), "API family partition");
    let mut categories: std::collections::BTreeMap<u64, &str> = std::collections::BTreeMap::new();
    for row in rows
        .iter()
        .filter(|row| row["kind"] == "operation" && row["event"] == "begin")
    {
        categories.insert(
            row["operation"].as_u64().unwrap(),
            row["category"].as_str().unwrap(),
        );
    }
    let mut outcomes: std::collections::BTreeMap<(&str, &str), u64> =
        std::collections::BTreeMap::new();
    for row in rows
        .iter()
        .filter(|row| row["kind"] == "operation" && row["event"] == "end")
    {
        let number = row["operation"].as_u64().unwrap();
        let key = (categories[&number], row["outcome"].as_str().unwrap());
        *outcomes.entry(key).or_default() += 1;
    }
    assert_eq!(outcomes.get(&("sign", "completed")), Some(&10));
    assert_eq!(outcomes.get(&("verify", "completed")), Some(&10));
    assert_eq!(outcomes.get(&("verify", "failed")), Some(&2));
    assert_eq!(outcomes.len(), 3, "no other operation outcomes exist");
    let done = rows
        .iter()
        .find(|row| row["kind"] == "done")
        .expect("done row");
    assert_eq!(done["api_calls"], 68);
    assert_eq!(done["operations"]["sign"]["completed"], 10);
    assert_eq!(done["operations"]["verify"]["completed"], 10);
    assert_eq!(done["operations"]["verify"]["failed"], 2);

    // Every real call replays through S1Only reduction in ledger
    // order: mechanisms from the ledger's fixed SHA256-RSA header
    // shape, returns verbatim, the null-output size query with
    // OUTPUT_NULL (phase-known). Non-operation calls must emit
    // nothing: any S1 misclassification fails here, not silently.
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(7);
    let mut edge = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    for call in &calls {
        let name = call["fn"].as_str().unwrap();
        let phase = call["phase"].as_str().unwrap();
        let fresh = replay_ledger_call(&mut edge, &mut sink, call);
        // Exact S1 emission per phase: inits start; the first OK
        // sign/verify/final after its init ends the machine;
        // queries, retries, updates and too-small replies retain
        // the machine and emit nothing; every terminal lands once.
        let expected = if name == "C_GenerateKeyPair" {
            1
        } else if !name.starts_with("C_Sign") && !name.starts_with("C_Verify") {
            0
        } else {
            match phase {
                "init" | "terminal" => 1,
                "query" | "update" | "too_small" => 0,
                other => panic!("unknown ledger phase {other}"),
            }
        };
        assert_eq!(fresh.len(), expected, "{name} ({phase}) S1 emission");
        for effect in &fresh {
            keyuse.observe_effect(instance, effect, Some(&mut assoc_ledger), None);
        }
    }
    assert_eq!(
        (edge.started(), edge.completed(), edge.failed()),
        (23, 21, 2)
    );
    assert_eq!(
        edge.orphans(),
        0,
        "no false completion strands the retry or the terminal"
    );

    let s1only = JointStaging::select_s1_only();
    let model = JointScene::new().model.project();
    let committed = commit(1, &[&s1only], &model, &keyuse);
    assert_eq!(committed.status, ObsStatus::Unavailable);
    assert_eq!(committed.reason, "bootstrap_unavailable");
    assert!(committed.key_operations.is_empty(), "S1Only proves no rows");
    assert!(committed.objects.is_empty() && committed.sessions.is_empty());
    let mut summaries: Vec<_> = committed
        .unknown_key_operations
        .iter()
        .map(|row| (row.category, row.reason, row.completed, row.failed))
        .collect();
    summaries.sort();
    assert_eq!(
        summaries,
        vec![
            ("generate_key_pair", "not_applicable", 1, 0),
            ("sign", "unbound", 10, 0),
            ("verify", "unbound", 10, 2),
        ],
        "the fixture's exact outcomes survive S1Only reduction"
    );
}

/// N7: every terminal uses pre-reserved storage: closes of
/// admitted, receipt-less and refused associations, orphan ends and
/// refused directs allocate nothing (starts reserve; terminals
/// move within reserved buckets and fixed summaries).
#[test]
fn key_operation_terminals_allocate_nothing() {
    let mut assoc_ledger = StagingLedger::new();
    use crate::discovery::caller_registry::instance_input::RegistryInstanceId;
    use crate::test_alloc::count_allocs_during;

    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut probe = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut probe,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut probe,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut probe,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    let start = sink
        .iter()
        .find(|effect| matches!(effect, OperationEffect::Started { .. }))
        .cloned()
        .expect("proved start");
    let mut end_sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut KeyUseReducer::new(),
        &mut end_sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let end = end_sink
        .iter()
        .find(|effect| matches!(effect, OperationEffect::Ended { .. }))
        .cloned()
        .expect("sign terminal");

    // Proved close: reserved bucket, fixed outcome.
    let mut keyuse = KeyUseReducer::with_capacity(1);
    keyuse.observe_effect(
        RegistryInstanceId::from_raw(0),
        &start,
        Some(&mut assoc_ledger),
        None,
    );
    let ((), blocks, bytes) = count_allocs_during(|| {
        keyuse.observe_effect(
            RegistryInstanceId::from_raw(0),
            &end,
            Some(&mut assoc_ledger),
            None,
        );
    });
    assert_eq!((blocks, bytes), (0, 0), "proved close allocates nothing");
    // Refused close: fixed summary, counted scalar.
    keyuse.observe_effect(
        RegistryInstanceId::from_raw(1),
        &start,
        Some(&mut assoc_ledger),
        None,
    );
    let ((), blocks, bytes) = count_allocs_during(|| {
        keyuse.observe_effect(
            RegistryInstanceId::from_raw(1),
            &end,
            Some(&mut assoc_ledger),
            None,
        );
    });
    assert_eq!((blocks, bytes), (0, 0), "refused close allocates nothing");
    // Receipt-less close: fixed summary, explicit evidence.
    let mut edge = EdgeSemantics::default();
    let mut bare = KeyUseReducer::with_capacity(1);
    let mut bare_sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    feed(&mut edge, &mut bare_sink, &c);
    for effect in bare_sink.clone() {
        bare.observe_effect(
            RegistryInstanceId::from_raw(0),
            &effect,
            Some(&mut assoc_ledger),
            None,
        );
    }
    let c = op("C_Sign", 7, 200);
    let terms = feed(&mut edge, &mut bare_sink, &c);
    let ((), blocks, bytes) = count_allocs_during(|| {
        bare.observe_effect(
            RegistryInstanceId::from_raw(0),
            &terms[0],
            Some(&mut assoc_ledger),
            None,
        );
    });
    assert_eq!(
        (blocks, bytes),
        (0, 0),
        "receipt-less close allocates nothing"
    );
    // Orphan end and refused direct: fixed summaries only.
    let mut orphan = KeyUseReducer::with_capacity(1);
    let ((), blocks, bytes) = count_allocs_during(|| {
        orphan.observe_effect(
            RegistryInstanceId::from_raw(9),
            &end,
            Some(&mut assoc_ledger),
            None,
        );
    });
    assert_eq!((blocks, bytes), (0, 0), "orphan end allocates nothing");
    let wrap = ShapedS1 {
        input0: Some((CREATED_KEY, 1)),
        input1: Some((CREATED_KEY, 1)),
        ..ShapedS1::shaped("C_WrapKey", CkRv::OK.0, RSA_PKCS, init_capture())
    };
    let mut wrap_sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut KeyUseReducer::new(),
        &mut wrap_sink,
        &wrap,
    );
    let direct = wrap_sink
        .iter()
        .find(|effect| matches!(effect, OperationEffect::DirectCompleted { .. }))
        .cloned()
        .expect("wrap direct");
    let mut full = KeyUseReducer::with_capacity(0);
    let ((), blocks, bytes) = count_allocs_during(|| {
        full.observe_effect(
            RegistryInstanceId::from_raw(0),
            &direct,
            Some(&mut assoc_ledger),
            None,
        );
    });
    assert_eq!((blocks, bytes), (0, 0), "refused direct allocates nothing");
    assert_eq!(full.evidence().rows_refused, 1);
}

/// N7/H9-§91/§93: retained/live/peak memory stays bounded across
/// useful updates and churn. One pipeline (model, staging, S1 join,
/// key-use reducer, publisher, emitter) serves an updates phase on a
/// working key set and a churn phase on fresh keys; per-component
/// structural occupancy plus allocator live/peak prove the envelope:
/// fixed structures stay flat, history grows only per retained
/// bucket, steady-state emission retains nothing.
#[test]
fn key_operation_allocation_pressure_is_bounded_across_passes() {
    use crate::test_alloc::{armed_requested_snapshot, requested_peak_during};

    const WORKING_KEYS: u64 = 4;
    const UPDATE_USES: u64 = 4;
    const CHURN_KEYS: u64 = 24;

    fn word_quantum(name: &'static str, word: u64) -> ShapedS1 {
        let (mechanism, capture) = match name {
            "C_SignInit" => (RSA_PKCS, init_capture()),
            "C_Sign" => (0, op_capture()),
            _ => (0, 0),
        };
        let mut shaped = ShapedS1::shaped(name, CkRv::OK.0, mechanism, capture);
        match name {
            "C_CreateObject" => shaped.result = Some(word),
            "C_SignInit" | "C_Sign" | "C_DestroyObject" | "C_GetAttributeValue" => {
                shaped.input0 = Some((word, 1));
            }
            other => panic!("unexpected quantum {other}"),
        }
        shaped
    }
    fn label_quantum(word: u64) -> ShapedS1 {
        ShapedS1 {
            getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
            ..word_quantum("C_GetAttributeValue", word)
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn drive_cycle(
        scene: &mut JointScene,
        staging: &mut JointStaging,
        joint: &mut EdgeSemantics,
        keyuse: &mut KeyUseReducer,
        quanta: &[ShapedS1],
    ) {
        let mut sink = Vec::new();
        for quantum in quanta {
            drive_quantum(scene, staging, joint, keyuse, &mut sink, quantum);
        }
    }

    #[derive(Debug)]
    struct PhaseFootprint {
        model_objects: usize,
        model_pending: usize,
        staged: usize,
        joint_started: u64,
        joint_completed: u64,
        aggregates: usize,
        open: usize,
        refused: usize,
        unknown_live: usize,
        emitter_tracked: usize,
        published_rows: usize,
    }
    impl PhaseFootprint {
        #[allow(clippy::too_many_arguments)]
        fn capture(
            scene: &JointScene,
            staging: &JointStaging,
            joint: &EdgeSemantics,
            keyuse: &KeyUseReducer,
            emitter: &KeyOperationEmitter,
            committed: &crate::key_operation_projection::ObjectObservations,
        ) -> Self {
            Self {
                model_objects: scene.model.project().objects.len(),
                model_pending: scene.model.project().usage.pending_calls,
                staged: staging.staged_len(),
                joint_started: joint.started(),
                joint_completed: joint.completed(),
                aggregates: keyuse.aggregates().len(),
                open: keyuse.open().len(),
                refused: keyuse.refused_opens().len(),
                unknown_live: committed.unknown_key_operations.len(),
                emitter_tracked: emitter.tracked(),
                published_rows: committed.objects.len()
                    + committed.key_operations.len()
                    + committed.unknown_key_operations.len(),
            }
        }
    }

    let dir = private_tempdir();
    let (pipeline, peak) = requested_peak_during(|| {
        let mut scene = JointScene::new();
        let bootstrap = scene.bootstrap();
        let mut staging = JointStaging::select_joint(Some(&bootstrap));
        let mut joint = EdgeSemantics::default();
        let mut keyuse = KeyUseReducer::new();
        let path = dir.path().join("events.jsonl");
        let mut writer = EventWriter::create(&path, 8 << 20, 10).unwrap();
        let mut emitter = KeyOperationEmitter::new();
        let mut revision = 0u64;
        // Phase A: useful updates on a working set — repeated uses
        // share eight buckets.
        for key in 0..WORKING_KEYS {
            let word = 0xB000_0000_0000_0000 + key;
            drive_cycle(
                &mut scene,
                &mut staging,
                &mut joint,
                &mut keyuse,
                &[word_quantum("C_CreateObject", word), label_quantum(word)],
            );
        }
        for use_number in 0..UPDATE_USES {
            let word = 0xB000_0000_0000_0000 + (use_number % WORKING_KEYS);
            drive_cycle(
                &mut scene,
                &mut staging,
                &mut joint,
                &mut keyuse,
                &[
                    word_quantum("C_SignInit", word),
                    word_quantum("C_Sign", word),
                ],
            );
        }
        revision += 1;
        let committed = commit(revision, &[&staging], &scene.model.project(), &keyuse);
        emitter
            .emit(&mut writer, &committed, revision * 1_000)
            .unwrap();
        let phase_a =
            PhaseFootprint::capture(&scene, &staging, &joint, &keyuse, &emitter, &committed);
        let live_a = armed_requested_snapshot();
        drop(committed);
        // Phase B: churn — every cycle mints, labels, uses and
        // retires a fresh key.
        for key in 0..CHURN_KEYS {
            let word = 0xC000_0000_0000_0000 + key;
            drive_cycle(
                &mut scene,
                &mut staging,
                &mut joint,
                &mut keyuse,
                &[
                    word_quantum("C_CreateObject", word),
                    label_quantum(word),
                    word_quantum("C_SignInit", word),
                    word_quantum("C_Sign", word),
                    word_quantum("C_DestroyObject", word),
                ],
            );
        }
        revision += 1;
        let committed = commit(revision, &[&staging], &scene.model.project(), &keyuse);
        emitter
            .emit(&mut writer, &committed, revision * 1_000)
            .unwrap();
        let phase_b =
            PhaseFootprint::capture(&scene, &staging, &joint, &keyuse, &emitter, &committed);
        let live_b = armed_requested_snapshot();
        drop(committed);
        (
            (phase_a, live_a, phase_b, live_b),
            scene,
            staging,
            keyuse,
            emitter,
            writer,
        )
    });
    let ((phase_a, live_a, phase_b, live_b), scene, staging, keyuse, mut emitter, mut writer) =
        pipeline;
    eprintln!("phase A: {phase_a:?} live {live_a:?}");
    eprintln!("phase B: {phase_b:?} live {live_b:?}");
    eprintln!("pipeline peak: {peak:?}");

    // The tracker saw everything (no overflow, no failure).
    assert!(!peak.incomplete, "complete allocation report");
    assert_eq!(peak.failed_requests, 0);
    assert!(!live_a.incomplete && !live_b.incomplete);

    // Structural occupancy: exact per-component retention.
    assert_eq!(phase_a.aggregates, WORKING_KEYS as usize);
    assert_eq!(phase_a.model_objects, WORKING_KEYS as usize);
    let buckets = WORKING_KEYS as usize + CHURN_KEYS as usize;
    assert_eq!(phase_b.aggregates, buckets, "one bucket per churned key");
    assert_eq!(
        phase_b.model_objects, buckets,
        "retired views retained under cap"
    );
    assert_eq!(phase_b.staged, 0, "every quantum replayed");
    assert!(phase_b.model_pending <= 2, "settled calls prune");
    assert_eq!(phase_b.open, 0);
    assert_eq!(phase_b.refused, 0);
    assert_eq!(phase_b.joint_started, UPDATE_USES + CHURN_KEYS);
    assert_eq!(phase_b.joint_completed, UPDATE_USES + CHURN_KEYS);
    assert_eq!(
        phase_b.emitter_tracked, phase_b.published_rows,
        "tracking bounded by the live publication"
    );
    assert!(phase_b.unknown_live <= 138, "fixed summaries stay fixed");

    // Live/peak envelope: churn grows only per retained bucket.
    assert!(
        live_b.live_bytes >= live_a.live_bytes,
        "history accumulates"
    );
    let growth = live_b.live_bytes - live_a.live_bytes;
    assert!(
        growth <= CHURN_KEYS as usize * 4096,
        "churn growth {growth} within per-bucket envelope"
    );
    assert!(peak.peak_bytes <= 8 << 20, "pipeline peak {:?}", peak);

    // Publisher isolation: one retained commit of churned state.
    let (committed, published) =
        requested_peak_during(|| commit(9_999, &[&staging], &scene.model.project(), &keyuse));
    eprintln!("publisher retained: {published:?}");
    assert!(!published.incomplete);
    assert!(
        published.live_bytes <= 256 << 10,
        "commit retains {:?}",
        published
    );
    // Emitter isolation: a steady-state pass retains nothing; a
    // changed row retains only its digest.
    let steady = requested_peak_during(|| {
        emitter.emit(&mut writer, &committed, 9_999_000).unwrap();
    })
    .1;
    assert_eq!(
        (steady.live_blocks, steady.live_bytes),
        (0, 0),
        "steady-state emission retains nothing"
    );
}

// ==================== N1: guarded Joint delivery ====================

use crate::attach::capture::NativeDomainId;
use crate::discovery::caller_registry::instance_input::{
    AdmittedInstance, AdmittedInstanceCall, InstanceKey, RegistryInstanceId,
};
use crate::discovery::caller_registry::{CallerId, CallerRegistry, ModuleKey};
use crate::discovery::instances::InstanceId;

/// One guarded-path scene: a real H8 joint scene plus a standalone
/// registry with one scripted module edge. Registrations take ids
/// 0, 1, ... in order.
struct GuardedScene {
    scene: JointScene,
    registry: CallerRegistry,
    domain: NativeDomainId,
    caller: CallerId,
    module: ModuleKey,
    next_id: u32,
}

impl GuardedScene {
    fn new() -> Self {
        let scene = JointScene::new();
        let mut registry =
            CallerRegistry::new(RegistryLimits::new(8, 8, 8, 8, 8, 8).expect("generous limits"));
        let domain = NativeDomainId::try_mint().expect("fresh domain");
        let caller = CallerId(7);
        let module = ModuleKey::Physical {
            dev_major: 1,
            dev_minor: 2,
            ino: 3,
            sha256: None,
        };
        registry.scripted_module_edge(module.clone(), caller);
        Self {
            scene,
            registry,
            domain,
            caller,
            module,
            next_id: 0,
        }
    }

    fn key(&self, router: u64) -> InstanceKey {
        InstanceKey::scripted(
            self.domain,
            ImageIdentity {
                task_cookie: 100 + router,
                exec_id: 1,
            },
            InstanceId::from_raw(router),
            self.module.clone(),
        )
    }

    fn register(&mut self, router: u64) -> (InstanceKey, RegistryInstanceId) {
        let key = self.key(router);
        let id = RegistryInstanceId::from_raw(self.next_id);
        self.next_id += 1;
        self.registry
            .note_instance(AdmittedInstance::scripted(key.clone(), self.caller));
        self.registry.publish();
        assert!(
            self.registry.feed_mode_for_test(id).is_some(),
            "registration retains the instance"
        );
        (key, id)
    }

    fn observe(&mut self, key: &InstanceKey, ordinal: u64, facts: SemanticCall) {
        self.registry
            .observe_instance_semantic(AdmittedInstanceCall::scripted(
                key.clone(),
                self.caller,
                ordinal,
                facts,
            ));
    }

    /// Attest one shaped call and return registry-ready facts
    /// (admission flags set — they never participate in the C2
    /// fingerprint) and its H0 position.
    fn admit_shape(&mut self, call: &ShapedS1) -> (SemanticCall, u64) {
        let admitted = admit_call_input(&mut self.scene, call);
        self.scene
            .adapter
            .attest_key(&admitted)
            .expect("call attests");
        (admitted.s1_facts().clone(), admitted.h0_ordinal())
    }

    fn edge_calls(&self, id: RegistryInstanceId) -> u64 {
        self.registry
            .instance_semantic_edges()
            .find(|record| record.id == id)
            .expect("edge retained")
            .semantics
            .as_ref()
            .expect("materialized")
            .calls()
    }

    fn edge_started(&self, id: RegistryInstanceId) -> u64 {
        self.registry
            .instance_semantic_edges()
            .find(|record| record.id == id)
            .expect("edge retained")
            .semantics
            .as_ref()
            .expect("materialized")
            .started()
    }

    fn edge_completed(&self, id: RegistryInstanceId) -> u64 {
        self.registry
            .instance_semantic_edges()
            .find(|record| record.id == id)
            .expect("edge retained")
            .semantics
            .as_ref()
            .expect("materialized")
            .completed()
    }

    /// Drive one Joint quantum for `key`/`id`: admit, stage, seal,
    /// deliver. Returns the seal outcome.
    fn drive_joint(
        &mut self,
        key: &InstanceKey,
        id: RegistryInstanceId,
        shape: &ShapedS1,
    ) -> SealApplyOutcome {
        let (facts, position) = self.admit_shape(shape);
        self.observe(key, position, facts);
        self.registry
            .publish_with_ledger(self.scene.adapter.ledger_mut());
        ingest_call(&mut self.scene, shape, position);
        let seal = self.scene.seal().expect("quantum seals");
        assert_eq!(seal.prefix.settled().len(), 1, "{}", shape.name);
        self.registry.deliver_joint_algorithm_seal_for_test(
            id,
            &seal,
            &self.scene.model,
            self.scene.adapter.ledger_mut(),
        )
    }

    /// Drive one S1Only-direct call for `key`: admit, observe,
    /// publish (no ledger). Effects tee while Joint evidence exists.
    fn drive_s1only(&mut self, key: &InstanceKey, shape: &ShapedS1) {
        let admitted = self.scene.fixture.admit_shaped(
            shape.session.unwrap_or(SESSION),
            shape.name,
            shape.rv,
            shape.mechanism,
            shape.capture,
            shape.flags,
        );
        self.observe(key, admitted.h0_ordinal(), admitted.s1_facts().clone());
        self.registry.publish();
    }
}

/// N1: an installed receipt selects Joint exactly once; without one
/// the feed stays S1Only (the production default).
#[test]
fn key_operation_joint_install_selects_joint_default_s1only() {
    let mut guarded = GuardedScene::new();
    let bootstrap = guarded.scene.bootstrap();
    let joint_key = guarded.key(1);
    assert!(
        guarded
            .registry
            .install_joint_receipt(joint_key.clone(), bootstrap),
        "install fits the instance bound"
    );
    let (_, joint_id) = guarded.register(1);
    assert_eq!(
        guarded.registry.feed_mode_for_test(joint_id),
        Some(FeedMode::Joint),
        "the installed receipt selects Joint"
    );
    assert_eq!(guarded.registry.joint_feeds(), 1);
    let (_, s1_id) = guarded.register(2);
    assert_eq!(
        guarded.registry.feed_mode_for_test(s1_id),
        Some(FeedMode::S1Only),
        "no receipt, no Joint: the default stays S1Only"
    );
    assert_eq!(guarded.registry.joint_feeds(), 1);
}

/// N1: Joint staging charges the shared H8 ledger (tickets and
/// bytes); S1Only siblings never stage; Joint calls without a
/// ledger (or past a frozen byte pool) reduce S1-direct and count
/// the fallback — S1 is always preserved.
#[test]
fn key_operation_joint_staging_charges_shared_ledger() {
    let mut guarded = GuardedScene::new();
    let bootstrap = guarded.scene.bootstrap();
    let joint_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(joint_key.clone(), bootstrap);
    let (_, joint_id) = guarded.register(1);

    let shape = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let (facts, init_position) = guarded.admit_shape(&shape);
    guarded.observe(&joint_key, init_position, facts);
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        1,
        "one ticket charged"
    );
    assert!(
        guarded.scene.adapter.ledger().charged_bytes() > 0,
        "duplicate bytes charged"
    );
    assert_eq!(guarded.registry.joint_direct_fallback(), 0);
    assert_eq!(
        guarded.edge_calls(joint_id),
        0,
        "staged calls reduce only at the seal"
    );

    // An S1Only sibling reduces direct through the shared pass and
    // never touches the ledger.
    let (sibling_key, sibling_id) = guarded.register(2);
    let shape = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let (facts, position) = guarded.admit_shape(&shape);
    guarded.observe(&sibling_key, position, facts);
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        1,
        "siblings never stage"
    );
    assert_eq!(guarded.edge_calls(sibling_id), 1, "S1 preserved direct");
    assert_eq!(guarded.registry.joint_direct_fallback(), 0);

    // No ledger with a queued call: ordered fallback replays the
    // queued Init first (C4) — the Sign must not overtake it — then
    // the Sign reduces direct. Releases pend without a ledger.
    let shape = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    let (facts, position) = guarded.admit_shape(&shape);
    guarded.observe(&joint_key, position, facts);
    guarded.registry.publish();
    assert_eq!(guarded.registry.joint_direct_fallback(), 1);
    assert_eq!(
        guarded.registry.feed_mode_for_test(joint_id),
        Some(FeedMode::S1Only),
        "capacity fallback degrades the feed"
    );
    assert_eq!(
        (
            guarded.edge_calls(joint_id),
            guarded.edge_started(joint_id),
            guarded.edge_completed(joint_id)
        ),
        (2, 1, 1),
        "one completed Sign in original order"
    );
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        1,
        "ledger-less releases pend, never leak silently"
    );
    // The next ledger contact flushes the pended release.
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    ingest_call(&mut guarded.scene, &init, init_position);
    let seal = guarded.scene.seal().expect("init quantum seals");
    assert_eq!(
        guarded.registry.deliver_joint_algorithm_seal_for_test(
            joint_id,
            &seal,
            &guarded.scene.model,
            guarded.scene.adapter.ledger_mut(),
        ),
        SealApplyOutcome::Held,
        "late seals never re-replay a fallback"
    );
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        0,
        "ledger contact flushes"
    );

    // A frozen byte pool refuses staging the same ordered way, on a
    // fresh Joint feed (the first already fell back above).
    let bootstrap = guarded.scene.bootstrap();
    let full_key = guarded.key(3);
    guarded
        .registry
        .install_joint_receipt(full_key.clone(), bootstrap);
    let (_, full_id) = guarded.register(3);
    let (facts, position) = guarded.admit_shape(&init);
    guarded.observe(&full_key, position, facts);
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        1,
        "one ticket charged"
    );
    guarded.scene.adapter.ledger_mut().set_byte_limit(0);
    let shape = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    let (facts, position) = guarded.admit_shape(&shape);
    guarded.observe(&full_key, position, facts);
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    assert_eq!(guarded.registry.joint_direct_fallback(), 2);
    assert_eq!(
        guarded.registry.feed_mode_for_test(full_id),
        Some(FeedMode::S1Only),
        "capacity fallback degrades the feed"
    );
    assert_eq!(
        (
            guarded.edge_calls(full_id),
            guarded.edge_started(full_id),
            guarded.edge_completed(full_id)
        ),
        (2, 1, 1),
        "one completed Sign in original order"
    );
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        0,
        "fallback with a ledger releases tickets"
    );
    guarded.scene.adapter.ledger_mut().set_byte_limit(u64::MAX);
}

/// N1: seal delivery replays the staged head through the shared
/// reducer, releases the ledger, and capture commits Populated from
/// the retained projection.
#[test]
fn key_operation_joint_seal_delivery_replays_and_populates_capture() {
    let mut guarded = GuardedScene::new();
    let bootstrap = guarded.scene.bootstrap();
    let joint_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(joint_key.clone(), bootstrap);
    let (_, joint_id) = guarded.register(1);

    // The create grounds the key and the getattr establishes its
    // label (as every proved-key flow does); the sign then
    // aggregates against it.
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    let flow = [
        ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
        get,
        ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
        ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    ];
    let mut last_seal = None;
    for shape in &flow {
        let (facts, position) = guarded.admit_shape(shape);
        guarded.observe(&joint_key, position, facts);
        guarded
            .registry
            .publish_with_ledger(guarded.scene.adapter.ledger_mut());
        ingest_call(&mut guarded.scene, shape, position);
        let seal = guarded.scene.seal().expect("single-call quantum seals");
        let outcome = guarded.registry.deliver_joint_algorithm_seal_for_test(
            joint_id,
            &seal,
            &guarded.scene.model,
            guarded.scene.adapter.ledger_mut(),
        );
        assert_eq!(
            outcome,
            SealApplyOutcome::ReplayedOne,
            "{} replays once",
            shape.name
        );
        last_seal = Some(seal);
    }
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        0,
        "replay releases tickets"
    );
    assert_eq!(guarded.registry.joint_direct_fallback(), 0);
    assert_eq!(
        guarded.edge_calls(joint_id),
        4,
        "each quantum reduced exactly once"
    );
    assert_eq!(guarded.edge_started(joint_id), 1);

    let observations = guarded.registry.joint_observations(41);
    assert_eq!(observations.revision, 41);
    assert_eq!(observations.status, ObsStatus::Populated);
    assert_eq!(observations.reason, "none");
    assert_eq!(observations.key_operations.len(), 1);
    let row = &observations.key_operations[0];
    assert_eq!(
        (row.category, row.role, row.metadata_at_use),
        ("sign", "key", "rsa_2048"),
        "the proved key joins its label"
    );
    assert_eq!(
        (row.started, row.completed),
        (1, 1),
        "the sign operation aggregates once"
    );

    // Unknown instances hold without effect.
    let last_seal = last_seal.expect("four quanta sealed");
    assert_eq!(
        guarded.registry.deliver_joint_algorithm_seal_for_test(
            RegistryInstanceId::from_raw(99),
            &last_seal,
            &guarded.scene.model,
            guarded.scene.adapter.ledger_mut(),
        ),
        SealApplyOutcome::Held,
    );
}

/// N1: failure delivery disposes retained staging, degrades the feed
/// to S1Only, releases the guard — and still retains the H8
/// projection for capture.
#[test]
fn key_operation_joint_failure_delivery_retains_projection() {
    let mut guarded = GuardedScene::new();
    let bootstrap = guarded.scene.bootstrap();
    let joint_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(joint_key.clone(), bootstrap);
    let (_, joint_id) = guarded.register(1);

    let shape = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let (facts, position) = guarded.admit_shape(&shape);
    guarded.observe(&joint_key, position, facts);
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    ingest_call(&mut guarded.scene, &shape, position);
    let failure = guarded
        .scene
        .seal_with_fault(7, 8)
        .expect_err("moved fault voids the seal");
    assert_eq!(failure.gap, JournalGap::FaultChanged);
    let mut h3 = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    let outcome = guarded.registry.deliver_joint_algorithm_failure_for_test(
        joint_id,
        &failure,
        &mut h3,
        &guarded.scene.model,
        guarded.scene.adapter.ledger_mut(),
    );
    assert_eq!(outcome, FailureApplyOutcome::Degraded { disposed: 1 });
    assert_eq!(
        guarded.registry.feed_mode_for_test(joint_id),
        Some(FeedMode::S1Only),
        "loss degrades the feed"
    );
    assert_eq!(guarded.registry.joint_feeds(), 0, "the guard releases");
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        0,
        "disposal releases tickets"
    );

    // Capture still commits from the retained projection: the
    // section names the loss, never bootstrap silence.
    let observations = guarded.registry.joint_observations(42);
    assert_eq!(observations.revision, 42);
    assert_eq!(observations.status, ObsStatus::Unavailable);
    assert_eq!(observations.reason, "authority_lost");

    // Unknown instances ignore without effect.
    let mut h3 = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    assert_eq!(
        guarded.registry.deliver_joint_algorithm_failure_for_test(
            RegistryInstanceId::from_raw(99),
            &failure,
            &mut h3,
            &guarded.scene.model,
            guarded.scene.adapter.ledger_mut(),
        ),
        FailureApplyOutcome::Ignored,
    );
}

/// N1 guard: with no install anywhere the registry reduces S1Only
/// and capture stays unavailable exactly as before — the N1 path
/// cuts no production scope.
#[test]
fn key_operation_s1only_capture_stays_unavailable() {
    let mut guarded = GuardedScene::new();
    let (key, id) = guarded.register(1);
    assert_eq!(
        guarded.registry.feed_mode_for_test(id),
        Some(FeedMode::S1Only)
    );
    let shape = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let (facts, position) = guarded.admit_shape(&shape);
    guarded.observe(&key, position, facts);
    guarded.registry.publish();
    assert_eq!(guarded.edge_calls(id), 1, "plain S1Only reduction");
    assert_eq!(guarded.registry.joint_feeds(), 0);
    let observations = guarded.registry.joint_observations(7);
    assert_eq!(observations.revision, 7);
    assert_eq!(observations.status, ObsStatus::Unavailable);
    assert_eq!(observations.reason, "bootstrap_unavailable");
    assert!(observations.key_operations.is_empty());
    assert!(guarded.registry.keyuse_for_test().open().is_empty());
    assert!(
        guarded
            .registry
            .keyuse_for_test()
            .unknown_counters()
            .iter()
            .all(|r| r.active == 0 && r.completed == 0)
    );
}

/// N14: Joint seal replay reserves H3 resources: the shared charge
/// grows when the replay adds machine/mechanism/provenance state.
#[test]
fn key_operation_n14_joint_replay_reserves_resources() {
    let mut guarded = GuardedScene::new();
    let bootstrap = guarded.scene.bootstrap();
    let joint_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(joint_key.clone(), bootstrap);
    let (_, joint_id) = guarded.register(1);

    // Grounding quanta (create + label) first, like every proved flow.
    let create = ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0);
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    for shape in [&create, &get] {
        assert_eq!(
            guarded.drive_joint(&joint_key, joint_id, shape),
            SealApplyOutcome::ReplayedOne
        );
    }
    // The Init replay adds a live machine plus mechanism/provenance
    // rows: the shared H3 charge must grow.
    let shape = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let (facts, position) = guarded.admit_shape(&shape);
    guarded.observe(&joint_key, position, facts);
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    ingest_call(&mut guarded.scene, &shape, position);
    let seal = guarded.scene.seal().expect("init quantum seals");
    let before = guarded.registry.semantic_resource_snapshot().charged_bytes;
    let outcome = guarded.registry.deliver_joint_algorithm_seal_for_test(
        joint_id,
        &seal,
        &guarded.scene.model,
        guarded.scene.adapter.ledger_mut(),
    );
    let after = guarded.registry.semantic_resource_snapshot().charged_bytes;
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    eprintln!("Joint Init replay charge: {before} -> {after}");
    assert!(
        after > before,
        "a new machine/mechanism/provenance must reserve its H3 charge"
    );
}

/// N14: small-budget N/N+1 refusal with a useful sibling and eligible
/// release. A fits; B's identical replay refuses (claim consumed,
/// head disposed as history, feed stays Joint); A's live machine
/// stays useful and completes; its release makes room for B's retry.
#[test]
fn key_operation_n14_small_budget_refuses_n_plus_one() {
    use crate::semantics_edge::resources::{REDUCER_BASE_CHARGE, SEMANTIC_TRANSITION_SCRATCH};

    // The consumed receipt leaves its grant table allocated and charged.
    // Measure that retained prepayment separately from one Init's growth.
    let (registration_prepay, growth) = {
        let mut probe = GuardedScene::new();
        let baseline = probe.registry.semantic_resource_snapshot().charged_bytes;
        let bootstrap = probe.scene.bootstrap();
        let key = probe.key(1);
        assert!(probe.registry.install_joint_receipt(key.clone(), bootstrap));
        let (_, id) = probe.register(1);
        let prepay = probe.registry.semantic_resource_snapshot().charged_bytes - baseline;
        assert!(prepay > 0, "the consumed grant retains its paid table");
        let shape = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
        let (facts, position) = probe.admit_shape(&shape);
        probe.observe(&key, position, facts);
        probe
            .registry
            .publish_with_ledger(probe.scene.adapter.ledger_mut());
        ingest_call(&mut probe.scene, &shape, position);
        let seal = probe.scene.seal().expect("probe quantum seals");
        let before = probe.registry.semantic_resource_snapshot().charged_bytes;
        assert_eq!(
            probe.registry.deliver_joint_algorithm_seal_for_test(
                id,
                &seal,
                &probe.scene.model,
                probe.scene.adapter.ledger_mut()
            ),
            SealApplyOutcome::ReplayedOne
        );
        let after = probe.registry.semantic_resource_snapshot().charged_bytes;
        assert!(after > before, "probe: replay reserves");
        (prepay, after - before)
    };
    eprintln!("calibrated Init growth: {growth}");

    let mut guarded = GuardedScene::new();
    // Room for the retained grant table, both reducers, A's full Init and
    // all but 100 bytes of B's. A's net release makes room for B's retry.
    guarded.registry.reference_semantic_resource_limit(
        SEMANTIC_TRANSITION_SCRATCH + registration_prepay + 2 * REDUCER_BASE_CHARGE + 2 * growth
            - 100,
    );
    let bootstrap = guarded.scene.bootstrap();
    let a_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(a_key.clone(), bootstrap);
    let (_, a_id) = guarded.register(1);
    let bootstrap = guarded.scene.bootstrap();
    let b_key = guarded.key(2);
    guarded
        .registry
        .install_joint_receipt(b_key.clone(), bootstrap);
    let (_, b_id) = guarded.register(2);
    assert_eq!(
        guarded.registry.semantic_resource_snapshot().charged_bytes,
        SEMANTIC_TRANSITION_SCRATCH + registration_prepay,
        "both consumed grants reuse one retained allocation, before either reducer exists"
    );

    // A fits.
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    assert_eq!(
        guarded.drive_joint(&a_key, a_id, &init),
        SealApplyOutcome::ReplayedOne
    );
    // B's identical replay refuses: same shape, no room.
    assert_eq!(
        guarded.drive_joint(&b_key, b_id, &init),
        SealApplyOutcome::ResourceRefused
    );
    assert_eq!(
        guarded.registry.semantic_resource_snapshot().refused,
        1,
        "the pool counts the refusal"
    );
    assert_eq!(
        guarded.registry.feed_mode_for_test(b_id),
        Some(FeedMode::Joint),
        "refusal keeps the feed Joint"
    );
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        0,
        "the refused head releases its ticket"
    );
    // A's live machine stays useful (refusal is instance-local).
    let before_completion = guarded.registry.semantic_resource_snapshot().charged_bytes;
    let sign = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    assert_eq!(
        guarded.drive_joint(&a_key, a_id, &sign),
        SealApplyOutcome::ReplayedOne
    );
    assert!(
        guarded.registry.semantic_resource_snapshot().charged_bytes < before_completion,
        "completing A releases live machine storage"
    );
    // Eligible release made room: B's retry fits.
    assert_eq!(
        guarded.drive_joint(&b_key, b_id, &init),
        SealApplyOutcome::ReplayedOne
    );
    let pool = guarded.registry.semantic_resource_snapshot();
    let reserve = guarded.registry.semantic_storage_reserver();
    assert_semantic_pool_refunded_after_drop(guarded, reserve, pool.limit_bytes);
}

/// N14: fallback replay reserves too, and mid-fallback refusal
/// preserves invalidation: the first call replays, the second
/// refuses, live S1 ends Unknown with terminals teed (no leaked
/// opens), the rest disposes as history.
#[test]
fn key_operation_n14_fallback_replay_reserves_and_disposes_on_refusal() {
    use crate::semantics_edge::resources::{REDUCER_BASE_CHARGE, SEMANTIC_TRANSITION_SCRATCH};

    // --- Default pool: fallback replay reserves. ---
    let mut guarded = GuardedScene::new();
    let bootstrap = guarded.scene.bootstrap();
    let joint_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(joint_key.clone(), bootstrap);
    let (_, joint_id) = guarded.register(1);
    let init7 = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let mut init8 = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    init8.session = Some(8);
    for shape in [&init7, &init8] {
        let (facts, position) = guarded.admit_shape(shape);
        guarded.observe(&joint_key, position, facts);
        guarded
            .registry
            .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    }
    assert_eq!(guarded.scene.adapter.ledger().staged(), 2);
    let failure = guarded.scene.adapter.scripted_failure(
        JournalGap::ClosureStale,
        &bootstrap,
        crate::semantics_objects::ObjectEffects::default(),
    );
    let mut clean = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    let before = guarded.registry.semantic_resource_snapshot().charged_bytes;
    let outcome = guarded.registry.deliver_joint_algorithm_failure_for_test(
        joint_id,
        &failure,
        &mut clean,
        &guarded.scene.model,
        guarded.scene.adapter.ledger_mut(),
    );
    let after = guarded.registry.semantic_resource_snapshot().charged_bytes;
    assert_eq!(outcome, FailureApplyOutcome::FellBack { replayed: 2 });
    eprintln!("fallback replay charge: {before} -> {after}");
    assert!(after > before, "fallback replay must reserve its H3 charge");

    // --- Small budget: the second replay refuses; live S1 ends
    // Unknown with terminals teed, the rest disposes as history. ---
    let (registration_prepay, growth) = {
        let mut probe = GuardedScene::new();
        let baseline = probe.registry.semantic_resource_snapshot().charged_bytes;
        let bootstrap = probe.scene.bootstrap();
        let key = probe.key(1);
        assert!(probe.registry.install_joint_receipt(key.clone(), bootstrap));
        let (_, id) = probe.register(1);
        let prepay = probe.registry.semantic_resource_snapshot().charged_bytes - baseline;
        assert!(prepay > 0, "the consumed grant retains its paid table");
        let shape = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
        let (facts, position) = probe.admit_shape(&shape);
        probe.observe(&key, position, facts);
        probe
            .registry
            .publish_with_ledger(probe.scene.adapter.ledger_mut());
        ingest_call(&mut probe.scene, &shape, position);
        let seal = probe.scene.seal().expect("probe quantum seals");
        let before = probe.registry.semantic_resource_snapshot().charged_bytes;
        assert_eq!(
            probe.registry.deliver_joint_algorithm_seal_for_test(
                id,
                &seal,
                &probe.scene.model,
                probe.scene.adapter.ledger_mut()
            ),
            SealApplyOutcome::ReplayedOne
        );
        let after = probe.registry.semantic_resource_snapshot().charged_bytes;
        assert!(after > before, "probe: replay reserves");
        (prepay, after - before)
    };
    let mut guarded = GuardedScene::new();
    // Keep the grant table paid, then allow one Init plus 512 bytes of
    // the second machine-only growth (1024): replay two must refuse.
    guarded.registry.reference_semantic_resource_limit(
        SEMANTIC_TRANSITION_SCRATCH + registration_prepay + REDUCER_BASE_CHARGE + growth + 512,
    );
    let bootstrap = guarded.scene.bootstrap();
    let joint_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(joint_key.clone(), bootstrap);
    let (_, joint_id) = guarded.register(1);
    assert_eq!(
        guarded.registry.semantic_resource_snapshot().charged_bytes,
        SEMANTIC_TRANSITION_SCRATCH + registration_prepay,
        "registration retains only the calibrated grant table"
    );
    for shape in [&init7, &init8] {
        let (facts, position) = guarded.admit_shape(shape);
        guarded.observe(&joint_key, position, facts);
        guarded
            .registry
            .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    }
    let failure = guarded.scene.adapter.scripted_failure(
        JournalGap::ClosureStale,
        &bootstrap,
        crate::semantics_objects::ObjectEffects::default(),
    );
    let mut clean = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    let outcome = guarded.registry.deliver_joint_algorithm_failure_for_test(
        joint_id,
        &failure,
        &mut clean,
        &guarded.scene.model,
        guarded.scene.adapter.ledger_mut(),
    );
    assert_eq!(outcome, FailureApplyOutcome::FellBack { replayed: 1 });
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        0,
        "refusal disposes the rest as history"
    );
    assert_eq!(
        guarded.registry.feed_mode_for_test(joint_id),
        Some(FeedMode::S1Only),
        "fallback still degrades the feed"
    );
    // Live S1 ended Unknown with terminals teed: no leaked opens.
    let observations = guarded.registry.joint_observations(9);
    let row = observations
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "unbound")
        .expect("the replayed start's terminal routes to unknown-key");
    assert_eq!((row.unknown, row.active), (1, 0));
    assert_eq!(guarded.registry.semantic_resource_snapshot().refused, 1);
    assert_eq!(guarded.scene.adapter.ledger().charged_bytes(), 0);
    let pool = guarded.registry.semantic_resource_snapshot();
    let reserve = guarded.registry.semantic_storage_reserver();
    assert_semantic_pool_refunded_after_drop(guarded, reserve, pool.limit_bytes);
}

/// Keep a handle to the original pool after all its owners are gone. Filling
/// exactly the non-scratch headroom detects both leaked and over-refunded leases.
fn assert_semantic_pool_refunded_after_drop(
    owner: impl Sized,
    reserve: crate::semantics_edge::resources::SemanticResourceReserver,
    limit: usize,
) {
    use crate::semantics_edge::resources::SEMANTIC_TRANSITION_SCRATCH;

    drop(owner);
    let repaid = reserve
        .reserve(limit - SEMANTIC_TRANSITION_SCRATCH)
        .expect("every persistent lease returns its exact charge on owner drop");
    assert!(
        reserve.reserve(1).is_err(),
        "the permanently reserved scratch was not over-refunded"
    );
    drop(repaid);
}

#[test]
fn key_operation_n1_ledger_contact_releases_before_new_staging() {
    use crate::semantics_objects::journal::MAX_UNSETTLED_STAGED;
    let mut g = GuardedScene::new();
    let bootstrap = g.scene.bootstrap();
    let key = g.key(1);
    g.registry.install_joint_receipt(key.clone(), bootstrap);
    let (_, id) = g.register(1);
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    assert_eq!(
        g.drive_joint(&key, id, &init),
        SealApplyOutcome::ReplayedOne
    );
    let sign = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    g.drive_s1only(&key, &sign);
    assert!(g.registry.keyuse_for_test().open().is_empty());
    assert_eq!(
        g.scene.adapter.ledger().census(),
        1,
        "the ended shared ticket awaits contact"
    );
    for token in 0..MAX_UNSETTLED_STAGED - 1 {
        g.scene
            .adapter
            .ledger_mut()
            .charge_model(10_000 + token as u64, 1)
            .unwrap();
    }
    let (facts, pos) = g.admit_shape(&init);
    g.observe(&key, pos, facts);
    g.registry.publish_with_ledger(g.scene.adapter.ledger_mut());
    assert_eq!(
        g.registry.feed_mode_for_test(id),
        Some(FeedMode::Joint),
        "an already-ended association cannot force a false capacity fallback"
    );
    assert_eq!(g.scene.adapter.ledger().staged(), 1);
    assert_eq!(g.scene.adapter.ledger().census(), MAX_UNSETTLED_STAGED);
}

#[test]
fn key_operation_n1_empty_ledger_publish_releases_ended_association() {
    let mut g = GuardedScene::new();
    let bootstrap = g.scene.bootstrap();
    let key = g.key(1);
    g.registry.install_joint_receipt(key.clone(), bootstrap);
    let (_, id) = g.register(1);
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    assert_eq!(
        g.drive_joint(&key, id, &init),
        SealApplyOutcome::ReplayedOne
    );
    assert_eq!(g.scene.adapter.ledger().census(), 1);
    // Without a ledger, a proof fallback followed by Sign ends the
    // shared association and defers its release until ledger contact.
    let update = ShapedS1::shaped("C_SignUpdate", CkRv::OK.0, 0, op_capture());
    let (facts, pos) = g.admit_shape(&update);
    g.observe(&key, pos, facts);
    g.registry.publish_with_ledger(g.scene.adapter.ledger_mut());
    let sign = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    g.drive_s1only(&key, &sign);
    assert!(g.registry.keyuse_for_test().open().is_empty());
    assert_eq!(
        g.scene.adapter.ledger().census(),
        2,
        "staging and association releases pend"
    );
    g.registry.publish_with_ledger(g.scene.adapter.ledger_mut());
    assert_eq!(
        g.scene.adapter.ledger().census(),
        0,
        "an empty ledger-bearing publish must release all eligible tickets"
    );
    assert_eq!(g.scene.adapter.ledger().charged_bytes(), 0);
}

/// Ordered fallback precedes all seal/failure delivery: accounting must
/// survive independently of the still-missing object publication proof.
fn first_fallback_accounting(capacity: bool, invalidate: bool, retire: bool) {
    use crate::discovery::caller_registry::instance_input::{
        InstanceReason, Retirement, Scope, loss, position, retirement,
    };
    let mut g = GuardedScene::new();
    let bootstrap = g.scene.bootstrap();
    let key = g.key(1);
    g.registry.install_joint_receipt(key.clone(), bootstrap);
    let (_, id) = g.register(1);
    let (sibling, sibling_id) = g.register(2);
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let update = ShapedS1::shaped("C_SignUpdate", CkRv::OK.0, 0, op_capture());
    let sign = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    g.drive_s1only(&sibling, &init);
    let (facts, pos) = g.admit_shape(&init);
    g.observe(&key, pos, facts);
    let init_position = pos;
    g.registry.publish_with_ledger(g.scene.adapter.ledger_mut());
    assert_eq!(g.scene.adapter.ledger().staged(), 1);
    if capacity {
        let limit = g.scene.adapter.ledger().charged_bytes();
        g.scene.adapter.ledger_mut().set_byte_limit(limit);
    }
    let (facts, pos) = g.admit_shape(&update);
    g.observe(&key, pos, facts);
    if capacity {
        g.registry.publish_with_ledger(g.scene.adapter.ledger_mut());
        g.scene.adapter.ledger_mut().set_byte_limit(u64::MAX);
    } else {
        g.registry.publish();
    }
    assert_eq!(g.registry.joint_feeds(), 0);
    assert_eq!(g.registry.feed_mode_for_test(id), Some(FeedMode::S1Only));
    assert_eq!(g.registry.keyuse_for_test().open().len(), 2);
    assert_eq!(
        g.registry.joint_observations(1).reason,
        "bootstrap_unavailable"
    );
    if invalidate {
        let barrier = g.scene.fixture.admit_function("C_Sign").h0_ordinal();
        if retire {
            g.registry.retire_instance(retirement(
                Retirement::Exact(key.clone()),
                position(g.domain, barrier),
                InstanceReason::InstanceRetired,
            ));
        } else {
            g.registry.note_instance_semantic_loss(loss(
                Scope::Exact(key.clone()),
                position(g.domain, barrier),
                InstanceReason::SemanticLoss,
            ));
        }
        g.registry.publish_with_ledger(g.scene.adapter.ledger_mut());
        // The healthy sibling still owns its open.
        assert_eq!(g.registry.keyuse_for_test().open().len(), 1);
    } else {
        let (facts, pos) = g.admit_shape(&sign);
        g.observe(&key, pos, facts);
        g.registry.publish_with_ledger(g.scene.adapter.ledger_mut());
        assert_eq!(g.edge_completed(id), 1);
        assert_eq!(
            g.registry.keyuse_for_test().open().len(),
            1,
            "the ordinary terminal closes the fallback open"
        );
    }
    g.drive_s1only(&sibling, &sign);
    assert_eq!(g.edge_completed(sibling_id), 1);
    // A repeated pair (or a new sibling after retirement) still accounts once.
    let repeat_key = if retire { g.register(3).0 } else { key.clone() };
    g.drive_s1only(&repeat_key, &init);
    g.drive_s1only(&repeat_key, &sign);
    assert_eq!(g.registry.keyuse_for_test().open().len(), 0);
    assert!(g.registry.keyuse_for_test().refused_opens().is_empty());
    let counters = g.registry.keyuse_for_test().unknown_counters();
    assert_eq!(
        counters.iter().map(|r| r.completed).sum::<u64>(),
        if invalidate { 2 } else { 3 }
    );
    assert_eq!(
        counters.iter().map(|r| r.unknown).sum::<u64>(),
        u64::from(invalidate)
    );
    assert_eq!(counters.iter().map(|r| r.active).sum::<u64>(), 0);
    assert!(
        g.registry.keyuse_for_test().aggregates().is_empty(),
        "no object authority invented"
    );
    assert_eq!(
        g.registry.joint_observations(2).reason,
        "bootstrap_unavailable"
    );
    assert_eq!(
        g.scene.adapter.ledger().census(),
        0,
        "eligible shared charges returned"
    );
    if !invalidate {
        ingest_call(&mut g.scene, &init, init_position);
        let seal = g.scene.seal().expect("the delayed original Init seals");
        assert_eq!(
            g.registry.deliver_joint_algorithm_seal_for_test(
                id,
                &seal,
                &g.scene.model,
                g.scene.adapter.ledger_mut()
            ),
            SealApplyOutcome::Held
        );
        assert!(g.registry.keyuse_for_test().open().is_empty());
        assert_eq!(
            g.registry.joint_observations(3).reason,
            "bootstrap_unavailable",
            "inert late delivery creates no object authority"
        );
    }
}

#[test]
fn key_operation_n15_first_unsealable_fallback_keeps_accounting() {
    let mut g = GuardedScene::new();
    let bootstrap = g.scene.bootstrap();
    let key = g.key(1);
    g.registry.install_joint_receipt(key.clone(), bootstrap);
    let (_, id) = g.register(1);
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let (facts, pos) = g.admit_shape(&init);
    g.observe(&key, pos, facts.clone());
    g.registry.publish_with_ledger(g.scene.adapter.ledger_mut());
    // S1's synthetic async completion is outside H8's sealable table.
    // It cannot overtake the queued Init and it cannot end that Init.
    let minted = g.scene.fixture.admit_function("C_SignInit");
    g.observe(
        &key,
        minted.h0_ordinal(),
        SemanticCall {
            function: "C_AsyncComplete".into(),
            session: facts.session,
            target_function: crate::kinds::function_id("C_Sign").unwrap(),
            capture: op_capture(),
            ts_ns: facts.ts_ns + 100,
            authorized: true,
            unambiguous: true,
            attributable: true,
            ..SemanticCall::default()
        },
    );
    g.registry.publish_with_ledger(g.scene.adapter.ledger_mut());
    assert_eq!(g.registry.joint_feeds(), 0);
    assert_eq!(g.registry.keyuse_for_test().open().len(), 1);
    let sign = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    let (facts, pos) = g.admit_shape(&sign);
    g.observe(&key, pos, facts);
    g.registry.publish_with_ledger(g.scene.adapter.ledger_mut());
    assert_eq!(g.edge_completed(id), 1);
    assert!(g.registry.keyuse_for_test().open().is_empty());
    assert_eq!(
        g.scene.adapter.ledger().census(),
        0,
        "the eligible association charge returns"
    );
    assert_eq!(
        g.registry.joint_observations(1).reason,
        "bootstrap_unavailable"
    );
}

#[test]
fn key_operation_n15_first_capacity_fallback_keeps_accounting() {
    first_fallback_accounting(true, false, false);
}

#[test]
fn key_operation_n15_first_missing_ledger_fallback_keeps_accounting() {
    first_fallback_accounting(false, false, false);
}

#[test]
fn key_operation_n15_first_fallback_loss_keeps_accounting() {
    first_fallback_accounting(false, true, false);
}

#[test]
fn key_operation_n15_first_fallback_retirement_keeps_accounting() {
    first_fallback_accounting(false, true, true);
}

/// N15: capture-wide effect accounting continues after the final
/// Joint-feed exit. Fallback replays A's Init (open) while B's S1Only
/// Init tees alongside; after the transition both terminals plus a
/// repeated fresh pair still account (completed, none stuck).
#[test]
fn key_operation_n15_post_fallback_terminals_still_accounted() {
    let mut guarded = GuardedScene::new();
    let bootstrap = guarded.scene.bootstrap();
    let a_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(a_key.clone(), bootstrap);
    let (_, a_id) = guarded.register(1);
    let (b_key, _) = guarded.register(2);

    // B's S1Only Init tees while Joint exists (open).
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    guarded.drive_s1only(&b_key, &init);
    // A's Init stages, then fallback replays it (open).
    let (facts, position) = guarded.admit_shape(&init);
    guarded.observe(&a_key, position, facts);
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    let failure = guarded.scene.adapter.scripted_failure(
        JournalGap::ClosureStale,
        &bootstrap,
        crate::semantics_objects::ObjectEffects::default(),
    );
    let mut clean = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    assert_eq!(
        guarded.registry.deliver_joint_algorithm_failure_for_test(
            a_id,
            &failure,
            &mut clean,
            &guarded.scene.model,
            guarded.scene.adapter.ledger_mut(),
        ),
        FailureApplyOutcome::FellBack { replayed: 1 }
    );
    assert_eq!(
        guarded.registry.joint_feeds(),
        0,
        "the final feed fell back"
    );

    // After the transition: both terminals plus a repeated fresh pair.
    let sign = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    guarded.drive_s1only(&a_key, &sign);
    guarded.drive_s1only(&b_key, &sign);
    guarded.drive_s1only(&a_key, &init);
    guarded.drive_s1only(&a_key, &sign);

    let observations = guarded.registry.joint_observations(11);
    let row = observations
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "unbound")
        .expect("S1 accounting continues after the transition");
    assert_eq!((row.completed, row.active), (3, 0));
}

/// N15: the same accounting continues after a real-loss transition:
/// fresh S1Only calls reduce definite outcomes into the retained
/// capture (no object authority invented).
#[test]
fn key_operation_n15_post_loss_s1_still_accounted() {
    let mut guarded = GuardedScene::new();
    let bootstrap = guarded.scene.bootstrap();
    let a_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(a_key.clone(), bootstrap);
    let (_, a_id) = guarded.register(1);

    // One staged call, then real loss disposes it.
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let (facts, position) = guarded.admit_shape(&init);
    guarded.observe(&a_key, position, facts);
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    let failure = guarded.scene.adapter.scripted_failure(
        JournalGap::FaultChanged,
        &bootstrap,
        crate::semantics_objects::ObjectEffects::default(),
    );
    let mut h3 = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    assert_eq!(
        guarded.registry.deliver_joint_algorithm_failure_for_test(
            a_id,
            &failure,
            &mut h3,
            &guarded.scene.model,
            guarded.scene.adapter.ledger_mut(),
        ),
        FailureApplyOutcome::Degraded { disposed: 1 }
    );
    assert_eq!(guarded.registry.joint_feeds(), 0, "the final feed degraded");

    // A fresh S1Only pair after the loss still accounts.
    let sign = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    guarded.drive_s1only(&a_key, &init);
    guarded.drive_s1only(&a_key, &sign);
    let observations = guarded.registry.joint_observations(12);
    let row = observations
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "unbound")
        .expect("S1 accounting continues after the loss");
    assert_eq!((row.completed, row.active), (1, 0));
}

/// C4: capacity fallback preserves original order. The staged Init
/// plus the capacity-refused Sign replay in order (one completed
/// Sign, nothing live) — never the direct terminal overtaking the
/// queued Init. The late Init seal then holds: no double-replay.
/// S1 matches the direct twin exactly.
#[test]
fn key_operation_c4_full_fallback_preserves_order() {
    let mut guarded = GuardedScene::new();
    let bootstrap = guarded.scene.bootstrap();
    let joint_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(joint_key.clone(), bootstrap);
    let (_, joint_id) = guarded.register(1);

    // Stage the Init, then freeze the pool: the terminal refuses.
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let sign = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    let (init_facts, init_pos) = guarded.admit_shape(&init);
    guarded.observe(&joint_key, init_pos, init_facts.clone());
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    assert_eq!(guarded.scene.adapter.ledger().staged(), 1);
    guarded.scene.adapter.ledger_mut().set_byte_limit(0);
    let (sign_facts, sign_pos) = guarded.admit_shape(&sign);
    guarded.observe(&joint_key, sign_pos, sign_facts.clone());
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    // The late Init seal must not re-replay the fallback. Unfreeze
    // first: the byte pool is shared (N1c), so the freeze that forced
    // staging refusal would also refuse the late begin.
    guarded.scene.adapter.ledger_mut().set_byte_limit(u64::MAX);
    ingest_call(&mut guarded.scene, &init, init_pos);
    let seal = guarded.scene.seal().expect("init quantum seals");
    assert_eq!(
        guarded.registry.deliver_joint_algorithm_seal_for_test(
            joint_id,
            &seal,
            &guarded.scene.model,
            guarded.scene.adapter.ledger_mut(),
        ),
        SealApplyOutcome::Held,
        "the late seal never re-replays"
    );
    {
        let edge = guarded
            .registry
            .instance_semantic_edges()
            .find(|record| record.id == joint_id)
            .expect("edge retained")
            .semantics
            .as_ref()
            .expect("materialized");
        assert_eq!(
            (edge.calls(), edge.started(), edge.completed()),
            (2, 1, 1),
            "one completed Sign in original order"
        );
        assert!(!edge.has_live_operations(), "nothing left live");
        let mut twin = EdgeSemantics::default();
        let mut twin_sink = Vec::new();
        for facts in [&init_facts, &sign_facts] {
            let origin = EffectOrigin::from(facts);
            twin.observe_with_effects(facts, &origin, &mut twin_sink);
        }
        assert_s1_equal(edge, &twin);
    }
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        0,
        "fallback releases tickets"
    );
}

/// A resource-backed legacy head keeps staged custody through replay: its
/// staged charge holds a real lease, so the byte limit still sees it while
/// the replayed open mints its association as a separate reservation
/// (source `None`, zero credit). At staged + assoc − 1 the mint refuses —
/// the open lands refused while S1 still replays the head. Releasing the
/// staged charge before replay would free the allowance and let the mint
/// succeed, refunding a live reservation early.
#[test]
fn key_operation_resource_backed_legacy_replay_holds_staged_custody() {
    use crate::semantics_edge::resources::SemanticResourcePool;

    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    let mut scene = JointScene::new();
    let receipt = scene.bootstrap();
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let admitted = admit_call_input(&mut scene, &init);
    scene.adapter.attest_key(&admitted).expect("call attests");
    let facts = admitted.s1_facts().clone();
    let origin = EffectOrigin::from(&facts);
    let position = admitted.h0_ordinal();

    // Calibrate the replayed association bytes on a scratch reserver-less
    // ledger at full limit: the scratch mint always succeeds, so the
    // leftover charge is exactly one association.
    let assoc = {
        let mut scratch = StagingLedger::new();
        let mut staging = JointStaging::select_joint(Some(&receipt));
        staging
            .stage(facts.clone(), origin.clone(), position, &mut scratch)
            .expect("scratch stages");
        let mut reducer = EdgeSemantics::default();
        let mut keyuse = KeyUseReducer::new();
        let mut sink = Vec::new();
        let (replayed, _) = staging.ordered_fallback(
            &mut reducer,
            &mut keyuse,
            instance,
            &mut sink,
            Some(&mut scratch),
            None,
        );
        assert_eq!(replayed, 1, "scratch replays the head");
        assert_eq!(
            keyuse.open().len(),
            1,
            "scratch mint succeeds at full limit"
        );
        scratch.charged_bytes()
    };
    assert!(assoc > 0, "the replayed association charges bytes");

    // The same legacy payload (no collection provenance) on a
    // resource-backed ledger: its staged charge holds a real lease.
    let pool = SemanticResourcePool::default();
    let mut ledger = StagingLedger::with_resources(pool.reserver());
    let mut staging = JointStaging::select_joint(Some(&receipt));
    staging
        .stage(facts.clone(), origin.clone(), position, &mut ledger)
        .expect("resource-backed head stages");
    let staged = ledger.charged_bytes();
    assert!(staged > 0, "the staged head charges bytes");
    ledger.set_byte_limit(staged + assoc - 1);

    let mut reducer = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    let (replayed, _) = staging.ordered_fallback(
        &mut reducer,
        &mut keyuse,
        instance,
        &mut sink,
        Some(&mut ledger),
        None,
    );
    assert_eq!(replayed, 1, "the head still replays through S1");
    assert_eq!(reducer.started(), 1, "S1 owns the replayed start");
    assert!(
        keyuse.open().is_empty(),
        "custody held: staged + assoc exceeds the limit, so the replayed mint refuses"
    );
    assert_eq!(
        keyuse.refused_opens().len(),
        1,
        "the refused open stays tracked for its terminal"
    );
}

/// C4: staging N/N+1 falls back in order. 1,024 Creates stage; the
/// 1,025th refuses Full, replaying all 1,024 in order before its own
/// direct reduction. S1 matches the direct twin exactly.
#[test]
fn key_operation_c4_staging_n_plus_one_falls_back_in_order() {
    use crate::semantics_key_use::JOINT_STAGING_CAPACITY;

    let mut guarded = GuardedScene::new();
    let bootstrap = guarded.scene.bootstrap();
    let joint_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(joint_key.clone(), bootstrap);
    let (_, joint_id) = guarded.register(1);

    let create = ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0);
    let mut twin = EdgeSemantics::default();
    let mut twin_sink = Vec::new();
    for _ in 0..JOINT_STAGING_CAPACITY {
        let (facts, position) = guarded.admit_shape(&create);
        let origin = EffectOrigin::from(&facts);
        twin.observe_with_effects(&facts, &origin, &mut twin_sink);
        guarded.observe(&joint_key, position, facts);
        guarded
            .registry
            .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    }
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        JOINT_STAGING_CAPACITY,
        "N stage"
    );
    // N+1 refuses Full: ordered fallback replays N in order, then N+1
    // reduces direct.
    let (facts, position) = guarded.admit_shape(&create);
    let origin = EffectOrigin::from(&facts);
    twin.observe_with_effects(&facts, &origin, &mut twin_sink);
    guarded.observe(&joint_key, position, facts);
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    assert_eq!(
        guarded.registry.feed_mode_for_test(joint_id),
        Some(FeedMode::S1Only),
        "capacity fallback degrades the feed"
    );
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        0,
        "fallback releases tickets"
    );
    let edge = guarded
        .registry
        .instance_semantic_edges()
        .find(|record| record.id == joint_id)
        .expect("edge retained")
        .semantics
        .as_ref()
        .expect("materialized");
    assert_eq!(
        edge.calls(),
        JOINT_STAGING_CAPACITY as u64 + 1,
        "every call reduced exactly once"
    );
    assert_s1_equal(edge, &twin);
}

/// C4: missing-ledger fallback preserves order with pended releases.
/// The staged Init plus the ledger-less Sign replay in order (one
/// completed Sign); the ticket releases pend until the next ledger
/// contact, when a seal delivery flushes them. S1 matches the twin.
#[test]
fn key_operation_c4_missing_ledger_falls_back_in_order() {
    let mut guarded = GuardedScene::new();
    let bootstrap = guarded.scene.bootstrap();
    let joint_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(joint_key.clone(), bootstrap);
    let (_, joint_id) = guarded.register(1);

    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let sign = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    let (init_facts, init_pos) = guarded.admit_shape(&init);
    guarded.observe(&joint_key, init_pos, init_facts.clone());
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    assert_eq!(guarded.scene.adapter.ledger().staged(), 1);
    // No ledger: the Sign cannot stage, but must not overtake.
    let (sign_facts, sign_pos) = guarded.admit_shape(&sign);
    guarded.observe(&joint_key, sign_pos, sign_facts.clone());
    guarded.registry.publish();
    {
        let edge = guarded
            .registry
            .instance_semantic_edges()
            .find(|record| record.id == joint_id)
            .expect("edge retained")
            .semantics
            .as_ref()
            .expect("materialized");
        assert_eq!(
            (edge.calls(), edge.started(), edge.completed()),
            (2, 1, 1),
            "one completed Sign in original order"
        );
        let mut twin = EdgeSemantics::default();
        let mut twin_sink = Vec::new();
        for facts in [&init_facts, &sign_facts] {
            let origin = EffectOrigin::from(facts);
            twin.observe_with_effects(facts, &origin, &mut twin_sink);
        }
        assert_s1_equal(edge, &twin);
    }
    // The ticket release pended (no ledger supplied); the next ledger
    // contact — here a late seal delivery — flushes it.
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        1,
        "ledger-less releases pend, never leak silently"
    );
    let before = guarded.registry.joint_observations(7);
    let mut foreign = JointScene::new();
    let foreign_receipt = foreign.bootstrap();
    let mut foreign_staging = JointStaging::select_joint(Some(&foreign_receipt));
    prepare_call(&mut foreign, &mut foreign_staging, &init);
    let foreign_seal = foreign
        .seal()
        .expect("foreign namespace seals its own input");
    assert_eq!(
        guarded.registry.deliver_joint_algorithm_seal_for_test(
            joint_id,
            &foreign_seal,
            &foreign.model,
            guarded.scene.adapter.ledger_mut()
        ),
        SealApplyOutcome::Held
    );
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        1,
        "foreign success cannot release owned deferred charges"
    );
    let failure = foreign
        .seal_with_fault(7, 8)
        .expect_err("foreign loss is adapter-minted");
    let mut finalizer = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    assert_eq!(
        guarded.registry.deliver_joint_algorithm_failure_for_test(
            joint_id,
            &failure,
            &mut finalizer,
            &foreign.model,
            guarded.scene.adapter.ledger_mut()
        ),
        FailureApplyOutcome::Ignored
    );
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        1,
        "foreign failure cannot release owned deferred charges"
    );
    assert_eq!(guarded.registry.joint_observations(7), before);
    assert!(matches!(
        crate::semantics_objects::journal::H3EvidenceSource::take_h3_disposition(&mut finalizer),
        H3DispositionEvidence::Clean {
            staged_max: u64::MAX,
            pending_floor: None
        }
    ));
    ingest_call(&mut guarded.scene, &init, init_pos);
    let seal = guarded.scene.seal().expect("init quantum seals");
    assert_eq!(
        guarded.registry.deliver_joint_algorithm_seal_for_test(
            joint_id,
            &seal,
            &guarded.scene.model,
            guarded.scene.adapter.ledger_mut(),
        ),
        SealApplyOutcome::Held
    );
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        0,
        "ledger contact flushes"
    );
    assert_eq!(
        guarded.registry.joint_observations(7),
        before,
        "reclamation never re-enables semantic consumption or projection"
    );
}

/// C4: an unsealable completion with queued calls falls back in
/// order first. The staged PENDING Init replays (queuing S1-side)
/// before the completion reduces direct, so the completion routes to
/// its original instead of orphaning. S1 matches the direct twin.
#[test]
fn key_operation_c4_unsealable_with_queued_calls_falls_back_in_order() {
    let mut guarded = GuardedScene::new();
    let bootstrap = guarded.scene.bootstrap();
    let joint_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(joint_key.clone(), bootstrap);
    let (_, joint_id) = guarded.register(1);

    // The PENDING Init stages and stays queued (no seal yet).
    let pending = ShapedS1::shaped("C_SignInit", CkRv::PENDING.0, RSA_PKCS, init_capture());
    let (pending_facts, pending_pos) = guarded.admit_shape(&pending);
    guarded.observe(&joint_key, pending_pos, pending_facts.clone());
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    assert_eq!(guarded.scene.adapter.ledger().staged(), 1);
    // The completion is unsealable (frozen negative-only table) but
    // must not overtake the queued original. It rides a
    // fixture-minted H0 ordinal: the async completion is
    // p11scope-synthesized, not a PKCS#11 table function, so the
    // fixture cannot admit its shape; the S1 facts mirror the unit
    // carve-out exactly.
    let minted = guarded.scene.fixture.admit_function("C_SignInit");
    let complete_pos = minted.h0_ordinal();
    let target = crate::kinds::function_id("C_SignInit").unwrap();
    let complete_facts = SemanticCall {
        function: "C_AsyncComplete".into(),
        session: pending_facts.session,
        target_function: target,
        capture: op_capture(),
        ts_ns: pending_facts.ts_ns.saturating_add(100),
        rv: CkRv::OK.0,
        authorized: true,
        unambiguous: true,
        attributable: true,
        ..SemanticCall::default()
    };
    guarded.observe(&joint_key, complete_pos, complete_facts.clone());
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    {
        let edge = guarded
            .registry
            .instance_semantic_edges()
            .find(|record| record.id == joint_id)
            .expect("edge retained")
            .semantics
            .as_ref()
            .expect("materialized");
        assert_eq!(
            (edge.calls(), edge.started(), edge.orphans()),
            (2, 1, 0),
            "the completion routes to its queued original"
        );
        let mut twin = EdgeSemantics::default();
        let mut twin_sink = Vec::new();
        for facts in [&pending_facts, &complete_facts] {
            let origin = EffectOrigin::from(facts);
            twin.observe_with_effects(facts, &origin, &mut twin_sink);
        }
        assert_s1_equal(edge, &twin);
    }
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        0,
        "fallback releases tickets"
    );
}

/// C5: registry loss disposes staged Joint custody and bars late
/// delivery. The queued Init disposes as history (shared tickets
/// released before publication); its late seal holds — no live
/// machine below the barrier. Definite completed history stands.
#[test]
fn key_operation_c5_loss_disposes_staged_and_bars_late_delivery() {
    use crate::discovery::caller_registry::instance_input::{
        InstanceReason, Scope, loss, position,
    };

    let mut guarded = GuardedScene::new();
    let bootstrap = guarded.scene.bootstrap();
    let joint_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(joint_key.clone(), bootstrap);
    let (_, joint_id) = guarded.register(1);

    // Definite history: one completed Sign through Joint seals.
    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let sign = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    assert_eq!(
        guarded.drive_joint(&joint_key, joint_id, &init),
        SealApplyOutcome::ReplayedOne
    );
    assert_eq!(
        guarded.drive_joint(&joint_key, joint_id, &sign),
        SealApplyOutcome::ReplayedOne
    );
    // One more Init staged and queued below the coming barrier.
    let (facts, staged_at) = guarded.admit_shape(&init);
    guarded.observe(&joint_key, staged_at, facts);
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        1,
        "one queued call charged"
    );
    // The loss barrier sits above the queued call.
    let barrier = guarded
        .scene
        .fixture
        .admit_function("C_SignInit")
        .h0_ordinal();
    assert!(barrier > staged_at, "non-vacuous: barrier above the queue");
    guarded.registry.note_instance_semantic_loss(loss(
        Scope::Exact(joint_key.clone()),
        position(guarded.domain, barrier),
        InstanceReason::SemanticLoss,
    ));
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        0,
        "loss disposes and releases shared custody"
    );
    // Late seal for the disposed call: inert, no live machine below
    // the barrier.
    ingest_call(&mut guarded.scene, &init, staged_at);
    let seal = guarded.scene.seal().expect("init quantum seals");
    assert_eq!(
        guarded.registry.deliver_joint_algorithm_seal_for_test(
            joint_id,
            &seal,
            &guarded.scene.model,
            guarded.scene.adapter.ledger_mut(),
        ),
        SealApplyOutcome::Held,
        "calls below the loss barrier are disposed history"
    );
    assert_eq!(
        (
            guarded.edge_calls(joint_id),
            guarded.edge_started(joint_id),
            guarded.edge_completed(joint_id)
        ),
        (2, 1, 1),
        "definite completed history stands; nothing replayed below the barrier"
    );
}

/// C5: registry loss tees invalidation terminals and spares healthy
/// siblings. A's live machine ends Unknown with its key-use open
/// closed (never stuck active); completed history stands; B's live
/// machine continues and completes afterwards.
#[test]
fn key_operation_c5_loss_tees_terminals_and_spares_siblings() {
    use crate::discovery::caller_registry::instance_input::{
        InstanceReason, Scope, loss, position,
    };

    let mut guarded = GuardedScene::new();
    let bootstrap = guarded.scene.bootstrap();
    let a_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(a_key.clone(), bootstrap);
    let (_, a_id) = guarded.register(1);
    let (b_key, _) = guarded.register(2);

    let init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let sign = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    // A's definite history plus one live machine; B live alongside.
    assert_eq!(
        guarded.drive_joint(&a_key, a_id, &init),
        SealApplyOutcome::ReplayedOne
    );
    assert_eq!(
        guarded.drive_joint(&a_key, a_id, &sign),
        SealApplyOutcome::ReplayedOne
    );
    assert_eq!(
        guarded.drive_joint(&a_key, a_id, &init),
        SealApplyOutcome::ReplayedOne
    );
    guarded.drive_s1only(&b_key, &init);
    let barrier = guarded
        .scene
        .fixture
        .admit_function("C_SignInit")
        .h0_ordinal();
    guarded.registry.note_instance_semantic_loss(loss(
        Scope::Exact(a_key.clone()),
        position(guarded.domain, barrier),
        InstanceReason::SemanticLoss,
    ));
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    // A's live machine ended Unknown; its open closed (teed); B live.
    // (A's Joint uses carry receipts without established metadata, so
    // they aggregate metadata_unknown; B's receipt-less direct use is
    // unbound.)
    let observations = guarded.registry.joint_observations(13);
    let proved = observations
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "metadata_unknown")
        .expect("Joint evidence retained");
    assert_eq!(
        (proved.completed, proved.unknown, proved.active),
        (1, 1, 0),
        "history stands and loss closes its open (teed)"
    );
    let sibling = observations
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "unbound")
        .expect("sibling S1 accounted");
    assert_eq!(
        (sibling.completed, sibling.active),
        (0, 1),
        "sibling stays live"
    );
    // The healthy sibling continues and completes afterwards.
    guarded.drive_s1only(&b_key, &sign);
    let observations = guarded.registry.joint_observations(14);
    let row = observations
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "unbound")
        .expect("Joint evidence retained");
    assert_eq!((row.completed, row.active), (1, 0));
}

/// C5: above-barrier staging survives loss; retirement disposes the
/// rest. A (below) disposes while B (above) stays queued for its
/// seal; A's seal mismatches B's head and holds. Retirement then
/// disposes the new queue and ends live S1 with terminals teed.
#[test]
fn key_operation_c5_above_barrier_survives_and_retirement_disposes() {
    use crate::discovery::caller_registry::instance_input::{
        InstanceReason, Retirement, Scope, loss, position, retirement,
    };

    let mut guarded = GuardedScene::new();
    let bootstrap = guarded.scene.bootstrap();
    let joint_key = guarded.key(1);
    guarded
        .registry
        .install_joint_receipt(joint_key.clone(), bootstrap);
    let (_, joint_id) = guarded.register(1);

    // Two queued Inits on distinct sessions with an ordinal gap.
    let mut init_a = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    init_a.session = Some(7);
    let mut init_b = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    init_b.session = Some(8);
    let (facts_a, pos_a) = guarded.admit_shape(&init_a);
    guarded.observe(&joint_key, pos_a, facts_a);
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    let gap = guarded
        .scene
        .fixture
        .admit_function("C_SignInit")
        .h0_ordinal();
    let (facts_b, pos_b) = guarded.admit_shape(&init_b);
    guarded.observe(&joint_key, pos_b, facts_b);
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    assert!(pos_a < gap && gap < pos_b, "non-vacuous ordinal gap");
    assert_eq!(guarded.scene.adapter.ledger().staged(), 2);
    // Loss at the gap: A disposes, B stays queued.
    guarded.registry.note_instance_semantic_loss(loss(
        Scope::Exact(joint_key.clone()),
        position(guarded.domain, gap),
        InstanceReason::SemanticLoss,
    ));
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        1,
        "below-barrier disposes; above-barrier stays queued"
    );
    // A's seal mismatches B's head (distinct sessions) and holds;
    // B's seal replays its own head.
    ingest_call(&mut guarded.scene, &init_a, pos_a);
    let seal_a = guarded.scene.seal().expect("A quantum seals");
    assert_eq!(
        guarded.registry.deliver_joint_algorithm_seal_for_test(
            joint_id,
            &seal_a,
            &guarded.scene.model,
            guarded.scene.adapter.ledger_mut(),
        ),
        SealApplyOutcome::Held,
        "disposed calls never replay against later heads"
    );
    ingest_call(&mut guarded.scene, &init_b, pos_b);
    let seal_b = guarded.scene.seal().expect("B quantum seals");
    assert_eq!(
        guarded.registry.deliver_joint_algorithm_seal_for_test(
            joint_id,
            &seal_b,
            &guarded.scene.model,
            guarded.scene.adapter.ledger_mut(),
        ),
        SealApplyOutcome::ReplayedOne,
        "above-barrier calls keep their seals"
    );
    assert_eq!(guarded.edge_started(joint_id), 1, "B's machine live");
    // Retirement disposes a fresh queue and ends live S1 teed.
    let (facts_c, pos_c) = guarded.admit_shape(&init_a);
    guarded.observe(&joint_key, pos_c, facts_c);
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    assert_eq!(guarded.scene.adapter.ledger().staged(), 1, "C queued");
    let retire_at = guarded
        .scene
        .fixture
        .admit_function("C_SignInit")
        .h0_ordinal();
    assert!(retire_at > pos_c, "non-vacuous: retirement above the queue");
    guarded.registry.retire_instance(retirement(
        Retirement::Exact(joint_key.clone()),
        position(guarded.domain, retire_at),
        InstanceReason::InstanceRetired,
    ));
    guarded
        .registry
        .publish_with_ledger(guarded.scene.adapter.ledger_mut());
    assert_eq!(
        guarded.scene.adapter.ledger().staged(),
        0,
        "retirement disposes the owned queue"
    );
    ingest_call(&mut guarded.scene, &init_a, pos_c);
    let seal_c = guarded.scene.seal().expect("C quantum seals");
    assert_eq!(
        guarded.registry.deliver_joint_algorithm_seal_for_test(
            joint_id,
            &seal_c,
            &guarded.scene.model,
            guarded.scene.adapter.ledger_mut(),
        ),
        SealApplyOutcome::Held,
        "retired queues never replay"
    );
    let observations = guarded.registry.joint_observations(15);
    let row = observations
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "metadata_unknown")
        .expect("Joint evidence retained");
    assert_eq!(
        (row.unknown, row.active),
        (1, 0),
        "retirement ends live S1 with terminals teed"
    );
}

/// The capture owner holds ONE ledger: a staged H9 charge plus its
/// association mint account together in one census/total, so either
/// release frees allowance for the other role. Scalar-role charges
/// stay distinct operations; only the same-wire bridge joins roles.
#[test]
fn joint_capture_owner_single_ledger_accounts_staged_and_assoc() {
    use crate::semantics_edge::resources::SemanticResourcePool;
    use crate::semantics_objects::journal::joint_driver::JointCaptureOwner;

    let pool = SemanticResourcePool::default();
    let mut owner = JointCaptureOwner::new(JournalLimits::policy(), pool.reserver());
    assert_eq!(owner.ledger().census(), 0);
    assert_eq!(owner.ledger().charged_bytes(), 0);
    owner.ledger_mut().charge(7, 40).expect("staged charges");
    assert_eq!(owner.ledger().staged(), 1);
    assert_eq!(owner.ledger().charged_bytes(), 40);
    let ticket = owner.ledger_mut().mint_keyassoc(24).expect("assoc mints");
    assert_eq!(owner.ledger().census(), 2);
    assert_eq!(owner.ledger().charged_bytes(), 64);
    owner.ledger_mut().release_keyassoc(ticket);
    assert_eq!(owner.ledger().charged_bytes(), 40);
    owner.ledger_mut().release(7, 40);
    assert_eq!(owner.ledger().staged(), 0);
    assert_eq!(owner.ledger().charged_bytes(), 0);
    assert_eq!(owner.ledger().census(), 0);
}

/// A coordinator commit borrows the capture owner's ledger: a Joint
/// call observed then committed stages its H9 charge into the owner's
/// ledger through the real commit path, not the fallback.
#[test]
fn joint_capture_owner_commit_batch_stages_into_owned_ledger() {
    use crate::discovery::engine::inventory_coordinator::InventoryCoordinator;

    let mut coordinator = InventoryCoordinator::new(
        crate::attach::Scope::Pid(std::process::id()),
        crate::discovery::hooks::HookRegistry::builtin(),
        Vec::new(),
        crate::discovery::caller_registry::OsProcessSource,
        RegistryLimits::new(8, 8, 8, 8, 8, 8).expect("generous limits"),
    )
    .expect("coordinator builds");
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let module = ModuleKey::Physical {
        dev_major: 1,
        dev_minor: 2,
        ino: 3,
        sha256: None,
    };
    let caller = CallerId(7);
    let domain = NativeDomainId::try_mint().expect("fresh domain");
    let key = InstanceKey::scripted(
        domain,
        ImageIdentity {
            task_cookie: 101,
            exec_id: 1,
        },
        InstanceId::from_raw(1),
        module.clone(),
    );
    {
        let registry = coordinator.registry_mut();
        registry.scripted_module_edge(module, caller);
        assert!(
            registry.install_joint_receipt(key.clone(), bootstrap),
            "the receipt install fits the instance bound"
        );
        registry.note_instance(AdmittedInstance::scripted(key.clone(), caller));
    }
    coordinator
        .commit_batch(false)
        .expect("registration commits");
    let id = RegistryInstanceId::from_raw(0);
    assert_eq!(
        coordinator.registry().feed_mode_for_test(id),
        Some(FeedMode::Joint),
        "the installed receipt selects Joint through the commit"
    );
    assert_eq!(coordinator.joint_capture().ledger().staged(), 0);
    let shape = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let admitted = admit_call_input(&mut scene, &shape);
    scene.adapter.attest_key(&admitted).expect("call attests");
    let (facts, position) = (admitted.s1_facts().clone(), admitted.h0_ordinal());
    coordinator
        .registry_mut()
        .observe_instance_semantic(AdmittedInstanceCall::scripted(
            key.clone(),
            caller,
            position,
            facts,
        ));
    coordinator
        .commit_batch(false)
        .expect("observation commits");
    assert_eq!(
        coordinator.joint_capture().ledger().staged(),
        1,
        "the commit stages the Joint call into the owner's ledger"
    );
    assert!(
        coordinator.joint_capture().ledger().charged_bytes() > 0,
        "the staged call charges the owner's bytes"
    );
}

/// The owner holds ONE ledger behind its adapter: a genuine origin
/// minted by raw collection through the owner's adapter survives the
/// bridge into a publication-side charge, and the adapter observes the
/// publication's census. The failure twin charges the same genuine
/// origin against a second owner's ledger — seeded with a live
/// same-ID reservation so only the generation check can refuse — and
/// must refuse, proving the generation check is real and the pass is
/// not vacuous.
#[test]
fn joint_capture_owner_adapter_origins_survive_the_owner_bridge() {
    use crate::attach::SessionDrainProducers;
    use crate::attach::capture::NativeDomainId;
    use crate::events::{EventDrain, EventsDomain, ScriptedRecords};
    use crate::semantics_edge::resources::SemanticResourcePool;
    use crate::semantics_objects::journal::LedgerRefusal;
    use crate::semantics_objects::journal::joint_driver::{JointCaptureOwner, RawJointQuantum};

    let rows = publish_object_descriptors();
    assert!(verify_object_descriptors(&rows));
    let begin = begin_bytes(1, 1, function_id("C_Sign"), 0);
    let end = end_bytes_absent(&begin, 0, ENTRY_NS + 100);
    let events = EventsDomain::test_standin(0xf201);
    let producers = SessionDrainProducers::test_pair(NativeDomainId::mint(), events.clone());
    let mut drain = EventDrain::over_domain(
        ScriptedRecords::records([begin.to_vec(), end.to_vec()], 2),
        events,
    );
    let pool = SemanticResourcePool::default();
    let mut owner = JointCaptureOwner::new(JournalLimits::policy(), pool.reserver());
    let fault = SteadyFaultCell(7);
    let quantum = RawJointQuantum::collect_with_adapter(
        &mut drain,
        &rows,
        2,
        &fault,
        &producers,
        |bytes| pool.reserve(bytes),
        owner.adapter_mut(),
    )
    .expect("a genuine BEGIN+END quantum collects through the owner's adapter");
    let (h0, _) = quantum
        .h0_input(producers.native_domain(), 2)
        .expect("the completed quantum lends its H0 input");
    let origin = h0
        .iter()
        .find_map(|record| record.joint_resource.as_ref())
        .expect("the completed END projects a genuine adapter origin");
    assert!(
        origin.matches_native(producers.native_domain()),
        "the origin names its actual native domain"
    );
    owner
        .ledger_mut()
        .charge_collected(producers.native_domain(), 1, 300, Some(origin))
        .expect("the owner's ledger honors its own adapter's origins");
    assert_eq!(
        owner.adapter().ledger().staged(),
        1,
        "one ledger: the adapter observes the publication-side charge"
    );
    assert_eq!(
        owner.ledger().census(),
        1,
        "one census across the bridge: the staged payload joins the raw operation"
    );
    assert_eq!(
        owner.adapter().ledger().census(),
        1,
        "the adapter observes the same absolute census"
    );
    let mut foreign = JointCaptureOwner::new(JournalLimits::policy(), pool.reserver());
    // Seed the foreign ledger with a live first reservation: both tables
    // mint sequentially from one, so the foreign operation carries the
    // same numeric reservation ID as the local raw operation, under a
    // different role (H8Open leaves the H9Staged role free and its key
    // unused). Without generation validation the bridged charge would
    // join that operation; only the generation check refuses it.
    foreign
        .ledger_mut()
        .charge_h8open(9, 10)
        .expect("the foreign ledger holds a live reservation");
    assert!(
        matches!(
            foreign
                .ledger_mut()
                .charge_collected(producers.native_domain(), 1, 300, Some(origin)),
            Err(LedgerRefusal::ReplayRefused)
        ),
        "a foreign ledger still refuses the genuine origin"
    );
    assert_eq!(
        foreign.ledger().census(),
        1,
        "the refused charge leaves the foreign census unchanged"
    );
    assert_eq!(
        foreign.ledger().staged(),
        0,
        "the refused charge stages nothing foreign"
    );
    assert_eq!(
        foreign.ledger().charged_bytes(),
        10,
        "the refused charge adds no foreign bytes"
    );
}

/// Real-pipeline 1024/1025 through the owner's ledger: 1024 Joint calls
/// observed and committed stage into the capture owner's ledger (census
/// 1024, bytes exact, pool delta exact); the 1025th refuses Full and the
/// feed falls back in order (C4) — replayed S1-direct, staged charges
/// released exactly, no residue from the refused call. An S1Only-direct
/// twin (same facts, same order, teed under the same capture-wide latch)
/// proves S1 facts intact: identical reducers, identical pool deltas,
/// identical key-use rows, and joint observations still unavailable
/// (no invented object facts) before and after the fallback.
#[test]
fn joint_capture_owner_pipeline_stages_1024_then_full_falls_back_exact() {
    use crate::discovery::caller_registry::OsProcessSource;
    use crate::discovery::engine::inventory_coordinator::InventoryCoordinator;
    use crate::semantics_edge::resources::{OWNED_ALLOCATION_PADDING, REDUCER_BASE_CHARGE};

    struct Pipeline {
        coordinator: InventoryCoordinator<OsProcessSource>,
        scene: JointScene,
        caller: CallerId,
        domain: NativeDomainId,
        module: ModuleKey,
    }

    impl Pipeline {
        fn coordinator() -> InventoryCoordinator<OsProcessSource> {
            InventoryCoordinator::new(
                crate::attach::Scope::Pid(std::process::id()),
                crate::discovery::hooks::HookRegistry::builtin(),
                Vec::new(),
                OsProcessSource,
                RegistryLimits::new(16, 16, 16, 1024, 1024, 16).expect("generous limits"),
            )
            .expect("coordinator builds")
        }

        fn new() -> Self {
            let mut coordinator = Self::coordinator();
            let scene = JointScene::new();
            let module = ModuleKey::Physical {
                dev_major: 1,
                dev_minor: 2,
                ino: 3,
                sha256: None,
            };
            let caller = CallerId(7);
            let domain = NativeDomainId::try_mint().expect("fresh domain");
            coordinator
                .registry_mut()
                .scripted_module_edge(module.clone(), caller);
            Self {
                coordinator,
                scene,
                caller,
                domain,
                module,
            }
        }

        /// Register `key` (Joint iff `joint`) and return its instance id.
        /// One registration commit per instance keeps ids ordered.
        fn register(
            &mut self,
            joint: bool,
            cookie: u64,
            router: u64,
            id: RegistryInstanceId,
        ) -> InstanceKey {
            let key = InstanceKey::scripted(
                self.domain,
                ImageIdentity {
                    task_cookie: cookie,
                    exec_id: 1,
                },
                InstanceId::from_raw(router),
                self.module.clone(),
            );
            {
                let registry = self.coordinator.registry_mut();
                if joint {
                    let bootstrap = self.scene.bootstrap();
                    assert!(
                        registry.install_joint_receipt(key.clone(), bootstrap),
                        "the receipt install fits the instance bound"
                    );
                }
                registry.note_instance(AdmittedInstance::scripted(key.clone(), self.caller));
            }
            self.coordinator
                .commit_batch(false)
                .expect("registration commits");
            assert_eq!(
                self.coordinator.registry().feed_mode_for_test(id),
                Some(if joint {
                    FeedMode::Joint
                } else {
                    FeedMode::S1Only
                }),
                "registration selects the intended feed"
            );
            key
        }

        fn admit(&mut self, session: Option<u64>) -> (SemanticCall, u64) {
            let mut shape = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
            shape.session = session;
            let admitted = admit_call_input(&mut self.scene, &shape);
            self.scene
                .adapter
                .attest_key(&admitted)
                .expect("call attests");
            (admitted.s1_facts().clone(), admitted.h0_ordinal())
        }

        fn observe(&mut self, key: &InstanceKey, facts: SemanticCall, position: u64) {
            self.coordinator.registry_mut().observe_instance_semantic(
                AdmittedInstanceCall::scripted(key.clone(), self.caller, position, facts),
            );
        }

        fn commit(&mut self) {
            self.coordinator
                .commit_batch(false)
                .expect("observation commits");
        }

        fn reducer(&self, id: RegistryInstanceId) -> &EdgeSemantics {
            self.coordinator
                .registry()
                .instance_semantic_edges()
                .find(|record| record.id == id)
                .expect("edge retained")
                .semantics
                .as_ref()
                .expect("reducer materialized")
        }
    }

    // Main: one Joint feed. Twin: a silent Joint latch (id 0, never
    // called — it only activates capture-wide accounting) plus the
    // S1Only-direct twin feed (id 1) under the same teed path.
    let mut main = Pipeline::new();
    let main_id = RegistryInstanceId::from_raw(0);
    let main_key = main.register(true, 101, 1, main_id);
    let mut twin = Pipeline::new();
    let latch_id = RegistryInstanceId::from_raw(0);
    twin.register(true, 201, 11, latch_id);
    let twin_id = RegistryInstanceId::from_raw(1);
    let twin_key = twin.register(false, 102, 2, twin_id);
    assert_eq!(twin.coordinator.joint_capture().ledger().census(), 0);

    let main_base = main
        .coordinator
        .registry()
        .semantic_resource_snapshot()
        .charged_bytes;
    let twin_base = twin
        .coordinator
        .registry()
        .semantic_resource_snapshot()
        .charged_bytes;

    // Round 0 pins the per-call staged bytes; the remaining 1023
    // observations batch into one commit (loop shape is free; the
    // refusal-twin exactness below is not). Each round runs its own
    // session, so every replayed init opens genuinely (same-session
    // inits would dedupe to one live open, hiding the assoc load).
    let (facts, position) = main.admit(Some(SESSION));
    let (twin_facts, twin_position) = twin.admit(Some(SESSION));
    assert_eq!(position, twin_position, "lockstep admissions agree");
    assert_eq!(
        (
            facts.function.as_str(),
            facts.rv,
            facts.session,
            facts.mechanism,
            facts.capture,
            facts.ts_ns
        ),
        (
            twin_facts.function.as_str(),
            twin_facts.rv,
            twin_facts.session,
            twin_facts.mechanism,
            twin_facts.capture,
            twin_facts.ts_ns
        ),
        "lockstep facts agree"
    );
    main.observe(&main_key, facts, position);
    twin.observe(&twin_key, twin_facts, twin_position);
    main.commit();
    twin.commit();
    assert_eq!(main.coordinator.joint_capture().ledger().staged(), 1);
    assert_eq!(main.coordinator.joint_capture().ledger().census(), 1);
    let bytes_one = main.coordinator.joint_capture().ledger().charged_bytes();
    assert!(bytes_one > 0, "the staged call charges owner bytes");
    assert_eq!(twin.coordinator.joint_capture().ledger().staged(), 0);
    assert_eq!(
        main.reducer(main_id).calls(),
        0,
        "staged calls await seal replay"
    );
    assert_eq!(twin.reducer(twin_id).calls(), 1);
    // Round 0 also prepays the owner's fixed table once; measured,
    // never hardcoded (see the ledger twin).
    let main_round0_pool = main
        .coordinator
        .registry()
        .semantic_resource_snapshot()
        .charged_bytes;
    let main_table_prepay = main_round0_pool
        - main_base
        - REDUCER_BASE_CHARGE
        - (bytes_one as usize + OWNED_ALLOCATION_PADDING);
    assert!(main_table_prepay > 0, "round 0 prepays the owner table");

    for round in 1..1024 {
        let (facts, position) = main.admit(Some(SESSION + round));
        let (twin_facts, twin_position) = twin.admit(Some(SESSION + round));
        assert_eq!(position, twin_position, "lockstep admissions agree");
        main.observe(&main_key, facts, position);
        twin.observe(&twin_key, twin_facts, twin_position);
    }
    main.commit();
    twin.commit();
    assert_eq!(
        main.coordinator.joint_capture().ledger().census(),
        1024,
        "1024 staged calls share one owner census"
    );
    assert_eq!(main.coordinator.joint_capture().ledger().staged(), 1024);
    let bytes_1024 = main.coordinator.joint_capture().ledger().charged_bytes();
    assert_eq!(
        bytes_1024,
        1024 * bytes_one,
        "uniform shapes charge uniform bytes"
    );
    assert_eq!(
        main.coordinator.registry().feed_mode_for_test(main_id),
        Some(FeedMode::Joint),
        "the full feed stays Joint: Full only fires on the next stage"
    );
    // Pool delta: round 0 paid the reducer base plus the one table
    // prepay; the remaining 1023 staged roles add exactly one pool
    // lease (bytes + 32) each — the exact S1/shared-pool interplay.
    let main_staged_pool = main
        .coordinator
        .registry()
        .semantic_resource_snapshot()
        .charged_bytes;
    assert_eq!(
        main_staged_pool - main_round0_pool,
        1023 * (bytes_one as usize + OWNED_ALLOCATION_PADDING),
        "each further staged role adds exactly its pool lease"
    );
    assert_eq!(main.reducer(main_id).calls(), 0);
    assert_eq!(twin.reducer(twin_id).calls(), 1024);
    assert_eq!(twin.coordinator.joint_capture().ledger().staged(), 0);

    // The 1025th reuses round 0's session (a duplicate init: no new
    // open, nothing held): Full refuses the stage, and the feed falls
    // back in order — the old publication below must survive that.
    let (facts, position) = main.admit(Some(SESSION));
    let (twin_facts, twin_position) = twin.admit(Some(SESSION));
    assert_eq!(position, twin_position, "lockstep admissions agree");
    main.observe(&main_key, facts, position);
    twin.observe(&twin_key, twin_facts, twin_position);
    let main_pool_before = main.coordinator.registry().semantic_resource_snapshot();
    let observations_before = main.coordinator.registry().joint_observations(7);
    assert_eq!(
        observations_before,
        crate::key_operation_projection::ObjectObservations::unavailable(
            7,
            "bootstrap_unavailable"
        ),
        "no seal delivered: the publication is unavailable, never invented"
    );
    twin.commit();
    let ((), fallback_peak, fallback_allocs, fallback_requested) =
        crate::test_alloc::counted_peak_during(|| {
            main.coordinator
                .commit_batch(false)
                .expect("the 1025th commits through ordered fallback");
        });
    assert!(
        !fallback_peak.incomplete,
        "the fallback commit stays within the peak tracker"
    );
    // Full fired exactly once and drained the staged queue in order.
    assert_eq!(
        main.coordinator.registry().joint_direct_fallback(),
        1,
        "the 1025th stage refused Full exactly once"
    );
    assert_eq!(
        main.coordinator.registry().feed_mode_for_test(main_id),
        Some(FeedMode::S1Only),
        "ordered fallback degrades the feed to S1Only"
    );
    assert_eq!(
        main.reducer(main_id).calls(),
        1025,
        "every staged call replays S1-direct in order, then the 1025th reduces"
    );
    // The refused stage allocates nothing: every staged charge
    // released exactly once, no orphan bytes, no partial lease.
    assert_eq!(main.coordinator.joint_capture().ledger().staged(), 0);
    assert_eq!(
        main.coordinator.joint_capture().ledger().census(),
        twin.coordinator.joint_capture().ledger().census(),
        "fallback joins leave the same live operations as direct mints"
    );
    assert_eq!(
        main.coordinator.joint_capture().ledger().charged_bytes(),
        twin.coordinator.joint_capture().ledger().charged_bytes(),
        "fallback joins charge the same live bytes as direct mints"
    );
    assert_eq!(
        main.coordinator.joint_capture().ledger().census(),
        1024,
        "1024 live associations hold the census; the refused 1025th holds nothing"
    );
    // Twin equality: S1 facts, pool, and key-use rows match the
    // never-staged direct reduction exactly.
    assert_s1_equal(main.reducer(main_id), twin.reducer(twin_id));
    let main_pool_after = main
        .coordinator
        .registry()
        .semantic_resource_snapshot()
        .charged_bytes;
    let twin_pool_after = twin
        .coordinator
        .registry()
        .semantic_resource_snapshot()
        .charged_bytes;
    assert_eq!(
        main_pool_after - main_base,
        twin_pool_after - twin_base,
        "staged charges refund exactly: the fallback pool equals the direct pool"
    );
    assert_eq!(
        main_pool_after,
        main_pool_before.charged_bytes + (twin_pool_after - twin_base)
            - (main_staged_pool - main_base),
        "pool snapshot delta exact across the fallback commit"
    );
    let main_keyuse = main.coordinator.registry().keyuse_for_test();
    let twin_keyuse = twin.coordinator.registry().keyuse_for_test();
    assert_eq!(main_keyuse.open().len(), twin_keyuse.open().len());
    assert_eq!(main_keyuse.open().len(), 1024, "every replayed open mints");
    assert_eq!(
        main_keyuse.refused_opens().len(),
        twin_keyuse.refused_opens().len()
    );
    assert_eq!(
        main_keyuse.refused_opens().len(),
        0,
        "the duplicate 1025th init opens nothing and refuses nothing"
    );
    assert_eq!(
        main.coordinator.registry().joint_observations(7),
        observations_before,
        "the old publication survives the fallback intact"
    );
    assert_eq!(
        twin.coordinator.registry().joint_observations(7),
        observations_before,
        "the twin never invents object facts either"
    );
    println!(
        "H3_MEM_1024_1025 {{\"staged_bytes_1024\": {bytes_1024}, \
         \"fallback_live_bytes\": {}, \"fallback_peak_bytes\": {}, \
         \"fallback_cumulative_requested_bytes\": {fallback_requested}, \
         \"fallback_allocation_requests\": {fallback_allocs}, \
         \"main_pool_delta\": {}, \"twin_pool_delta\": {}}}",
        fallback_peak.live_bytes,
        fallback_peak.peak_bytes,
        main_pool_after - main_base,
        twin_pool_after - twin_base,
    );
}

/// Ledger-level 1024/1025: 1024 staged charges fill the owner's census;
/// the 1025th refuses Full allocating nothing — census, bytes and the
/// shared pool stay exactly put (preflight fails before the pool lease
/// and the table insert, per H9 charge-before-allocation).
#[test]
fn joint_capture_owner_ledger_1025th_charge_refuses_without_allocating() {
    use crate::semantics_edge::resources::{OWNED_ALLOCATION_PADDING, SemanticResourcePool};
    use crate::semantics_objects::journal::LedgerRefusal;
    use crate::semantics_objects::journal::joint_driver::JointCaptureOwner;

    let pool = SemanticResourcePool::default();
    let base = pool.snapshot().charged_bytes;
    let mut owner = JointCaptureOwner::new(JournalLimits::policy(), pool.reserver());
    owner.ledger_mut().charge(0, 40).expect("staged charges");
    // The first charge prepays the fixed 1024-slot table once (H9
    // charge-before-allocation); every later charge adds exactly its
    // own pool lease. Measured, never hardcoded: the table size is a
    // layout fact, the once-only prepay is the invariant.
    let pool_after_first = pool.snapshot().charged_bytes;
    let table_prepay = pool_after_first - base - (40 + OWNED_ALLOCATION_PADDING);
    assert!(table_prepay > 0, "the first charge prepays the table");
    for ticket in 1..1024 {
        owner
            .ledger_mut()
            .charge(ticket, 40)
            .expect("staged charges");
    }
    assert_eq!(owner.ledger().census(), 1024);
    assert_eq!(owner.ledger().staged(), 1024);
    assert_eq!(owner.ledger().charged_bytes(), 1024 * 40);
    let pool_full = pool.snapshot().charged_bytes;
    assert_eq!(
        pool_full - pool_after_first,
        1023 * (40 + OWNED_ALLOCATION_PADDING),
        "one pool lease per further live role, no second table prepay"
    );
    let (result, peak, allocs, requested) =
        crate::test_alloc::counted_peak_during(|| owner.ledger_mut().charge(1024, 40));
    assert!(
        matches!(result, Err(LedgerRefusal::Full)),
        "the 1025th charge refuses Full"
    );
    assert!(!peak.incomplete);
    assert_eq!(
        (peak.live_bytes, peak.peak_bytes),
        (0, 0),
        "the refused charge retains nothing"
    );
    assert_eq!(
        (allocs, requested),
        (0, 0),
        "the refused charge requests nothing"
    );
    assert_eq!(owner.ledger().census(), 1024);
    assert_eq!(owner.ledger().staged(), 1024);
    assert_eq!(owner.ledger().charged_bytes(), 1024 * 40);
    assert_eq!(
        pool.snapshot().charged_bytes,
        pool_full,
        "the refused charge moves no pool bytes"
    );
}

/// Below-prepay Joint staging refusal through the owner commit path:
/// a generous twin stages one Joint observation (measuring the
/// staged bytes and the once-only table prepay), an S1Only twin
/// under capture-wide accounting measures the direct-commit pool
/// delta and its owner-ledger assoc bytes, and the refusal twin —
/// pool pinned pre-registration to exactly the direct commit's
/// non-prepay need, provably below the table prepay — commits the
/// same observation gracefully through `commit_batch`: Full fires
/// exactly once at the stage, ordered fallback reduces S1-direct,
/// and the assoc mint refuses into a refused key-use row. The
/// owner ledger bears no trace (census, staged and charged bytes
/// all zero), the pool moves exactly the non-prepay delta (both
/// refused ledger contacts moved zero pool bytes), and S1 reduces
/// identically to the direct twin.
#[test]
fn joint_capture_owner_commit_batch_below_prepay_refuses_full_gracefully() {
    use crate::discovery::caller_registry::OsProcessSource;
    use crate::discovery::engine::inventory_coordinator::InventoryCoordinator;
    use crate::semantics_edge::resources::{OWNED_ALLOCATION_PADDING, REDUCER_BASE_CHARGE};

    struct Pipeline {
        coordinator: InventoryCoordinator<OsProcessSource>,
        scene: JointScene,
        caller: CallerId,
        domain: NativeDomainId,
        module: ModuleKey,
    }

    impl Pipeline {
        fn new() -> Self {
            let mut coordinator = InventoryCoordinator::new(
                crate::attach::Scope::Pid(std::process::id()),
                crate::discovery::hooks::HookRegistry::builtin(),
                Vec::new(),
                OsProcessSource,
                RegistryLimits::new(16, 16, 16, 1024, 1024, 16).expect("generous limits"),
            )
            .expect("coordinator builds");
            let scene = JointScene::new();
            let module = ModuleKey::Physical {
                dev_major: 1,
                dev_minor: 2,
                ino: 3,
                sha256: None,
            };
            let caller = CallerId(7);
            let domain = NativeDomainId::try_mint().expect("fresh domain");
            coordinator
                .registry_mut()
                .scripted_module_edge(module.clone(), caller);
            Self {
                coordinator,
                scene,
                caller,
                domain,
                module,
            }
        }

        fn register(
            &mut self,
            joint: bool,
            cookie: u64,
            router: u64,
            id: RegistryInstanceId,
        ) -> InstanceKey {
            let key = InstanceKey::scripted(
                self.domain,
                ImageIdentity {
                    task_cookie: cookie,
                    exec_id: 1,
                },
                InstanceId::from_raw(router),
                self.module.clone(),
            );
            {
                let registry = self.coordinator.registry_mut();
                if joint {
                    let bootstrap = self.scene.bootstrap();
                    assert!(
                        registry.install_joint_receipt(key.clone(), bootstrap),
                        "the receipt install fits the instance bound"
                    );
                }
                registry.note_instance(AdmittedInstance::scripted(key.clone(), self.caller));
            }
            self.coordinator
                .commit_batch(false)
                .expect("registration commits");
            assert_eq!(
                self.coordinator.registry().feed_mode_for_test(id),
                Some(if joint {
                    FeedMode::Joint
                } else {
                    FeedMode::S1Only
                }),
                "registration selects the intended feed"
            );
            key
        }

        fn admit(&mut self, session: Option<u64>) -> (SemanticCall, u64) {
            let mut shape = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
            shape.session = session;
            let admitted = admit_call_input(&mut self.scene, &shape);
            self.scene
                .adapter
                .attest_key(&admitted)
                .expect("call attests");
            (admitted.s1_facts().clone(), admitted.h0_ordinal())
        }

        fn observe(&mut self, key: &InstanceKey, facts: SemanticCall, position: u64) {
            self.coordinator.registry_mut().observe_instance_semantic(
                AdmittedInstanceCall::scripted(key.clone(), self.caller, position, facts),
            );
        }

        fn reducer(&self, id: RegistryInstanceId) -> &EdgeSemantics {
            self.coordinator
                .registry()
                .instance_semantic_edges()
                .find(|record| record.id == id)
                .expect("edge retained")
                .semantics
                .as_ref()
                .expect("reducer materialized")
        }

        fn pool_charged(&self) -> usize {
            self.coordinator
                .registry()
                .semantic_resource_snapshot()
                .charged_bytes
        }
    }

    fn shape_of(facts: &SemanticCall) -> (String, u64, u64, u64, u32, u64) {
        (
            facts.function.clone(),
            facts.rv,
            facts.session,
            facts.mechanism,
            facts.capture,
            facts.ts_ns,
        )
    }

    // Healthy twin: generous pool; the observation stages.
    let mut healthy = Pipeline::new();
    let healthy_id = RegistryInstanceId::from_raw(0);
    let healthy_base = healthy.pool_charged();
    let healthy_key = healthy.register(true, 101, 1, healthy_id);
    let healthy_reg = healthy.pool_charged();
    let registration_delta = healthy_reg - healthy_base;
    assert!(
        registration_delta > 0,
        "the consumed receipt retains its paid grant-table allocation"
    );
    assert!(
        healthy
            .coordinator
            .registry()
            .instance_semantic_edges()
            .all(|record| record.semantics.is_none()),
        "the reducer base still lands only at first reduction"
    );
    let (h_facts, h_pos) = healthy.admit(Some(SESSION));
    // S1Only twin under capture-wide accounting: a silent Joint
    // latch plus the direct feed.
    let mut s1 = Pipeline::new();
    s1.register(true, 201, 11, RegistryInstanceId::from_raw(0));
    let s1_id = RegistryInstanceId::from_raw(1);
    let s1_key = s1.register(false, 102, 2, s1_id);
    let (s1_facts, s1_pos) = s1.admit(Some(SESSION));
    // Refusal twin: admitted early for lockstep; pinned and
    // registered after the twins measure its headroom.
    let mut refusal = Pipeline::new();
    let (r_facts, r_pos) = refusal.admit(Some(SESSION));
    assert_eq!(s1_pos, h_pos, "lockstep admissions agree");
    assert_eq!(r_pos, h_pos, "lockstep admissions agree");
    assert_eq!(
        shape_of(&h_facts),
        shape_of(&s1_facts),
        "lockstep facts agree"
    );
    assert_eq!(
        shape_of(&h_facts),
        shape_of(&r_facts),
        "lockstep facts agree"
    );
    healthy.observe(&healthy_key, h_facts, h_pos);
    healthy
        .coordinator
        .commit_batch(false)
        .expect("healthy observation commits");
    assert_eq!(healthy.coordinator.joint_capture().ledger().staged(), 1);
    assert_eq!(healthy.coordinator.joint_capture().ledger().census(), 1);
    let staged_bytes = healthy.coordinator.joint_capture().ledger().charged_bytes();
    assert!(staged_bytes > 0, "the staged call charges owner bytes");
    let staged_delta = healthy.pool_charged() - healthy_reg;
    let table_prepay =
        staged_delta - REDUCER_BASE_CHARGE - (staged_bytes as usize + OWNED_ALLOCATION_PADDING);
    assert!(table_prepay > 0, "the first stage prepays the owner table");
    s1.observe(&s1_key, s1_facts, s1_pos);
    let s1_pre = s1.pool_charged();
    let s1_observations_before = s1.coordinator.registry().joint_observations(7);
    let ((), s1_peak, s1_allocs, s1_requested) = crate::test_alloc::counted_peak_during(|| {
        s1.coordinator
            .commit_batch(false)
            .expect("direct observation commits");
    });
    assert!(!s1_peak.incomplete);
    let s1_pool_delta = s1.pool_charged() - s1_pre;
    // The direct commit mints its key-use assoc into the shared
    // owner ledger, prepaying the same table the stage would: the
    // refusal pin must clear the reducer base plus transition
    // growth while sitting below the prepay the assoc took here.
    let s1_assoc_bytes = s1.coordinator.joint_capture().ledger().charged_bytes();
    assert!(s1_assoc_bytes > 0, "the direct commit mints its assoc");
    assert_eq!(s1.coordinator.joint_capture().ledger().census(), 1);
    let s1_keyuse = s1.coordinator.registry().keyuse_for_test();
    assert_eq!(s1_keyuse.open().len(), 1, "the assoc opens live");
    assert_eq!(s1_keyuse.refused_opens().len(), 0);
    let headroom =
        s1_pool_delta - table_prepay - (s1_assoc_bytes as usize + OWNED_ALLOCATION_PADDING);
    assert!(headroom > 0, "the direct commit needs non-prepay pool");
    assert!(
        headroom < table_prepay,
        "the pinned headroom sits below the table prepay"
    );
    let refusal_base = refusal.pool_charged();
    refusal
        .coordinator
        .registry_mut()
        .reference_semantic_resource_limit(refusal_base + registration_delta + headroom);
    let refusal_id = RegistryInstanceId::from_raw(0);
    let refusal_key = refusal.register(true, 101, 1, refusal_id);
    let refusal_reg = refusal.pool_charged();
    assert_eq!(
        refusal_reg - refusal_base,
        registration_delta,
        "twin registration replays exactly"
    );
    refusal.observe(&refusal_key, r_facts, r_pos);
    let r_pre = refusal.pool_charged();
    assert_eq!(
        r_pre, refusal_reg,
        "observe stages no pool bytes before the commit"
    );
    let r_observations_before = refusal.coordinator.registry().joint_observations(7);
    assert_eq!(
        r_observations_before, s1_observations_before,
        "no seal delivered: both twins start unavailable, never invented"
    );
    let refused_before = refusal
        .coordinator
        .registry()
        .semantic_resource_snapshot()
        .refused;
    let ((), r_peak, r_allocs, r_requested) = crate::test_alloc::counted_peak_during(|| {
        refusal
            .coordinator
            .commit_batch(false)
            .expect("the refused stage commits gracefully");
    });
    assert!(!r_peak.incomplete);
    let r_post = refusal.pool_charged();
    let refused_after = refusal
        .coordinator
        .registry()
        .semantic_resource_snapshot()
        .refused;
    println!(
        "H3_MEM_BELOW_PREPAY {{\"registration_delta\": {registration_delta}, \
         \"staged_bytes\": {staged_bytes}, \"table_prepay\": {table_prepay}, \
         \"s1_pool_delta\": {s1_pool_delta}, \"s1_assoc_bytes\": {s1_assoc_bytes}, \
         \"s1_allocs\": {s1_allocs}, \"s1_requested\": {s1_requested}, \
         \"s1_live\": {}, \"headroom\": {headroom}, \
         \"r_pool_delta\": {}, \"r_allocs\": {r_allocs}, \
         \"r_requested\": {r_requested}, \"r_live\": {}, \
         \"refused_delta\": {}, \"fallback\": {}, \"census\": {}, \
         \"staged\": {}, \"charged\": {}}}",
        s1_peak.live_bytes,
        r_post - r_pre,
        r_peak.live_bytes,
        refused_after - refused_before,
        refusal.coordinator.registry().joint_direct_fallback(),
        refusal.coordinator.joint_capture().ledger().census(),
        refusal.coordinator.joint_capture().ledger().staged(),
        refusal.coordinator.joint_capture().ledger().charged_bytes(),
    );
    assert_eq!(
        refusal.coordinator.registry().joint_direct_fallback(),
        1,
        "Full fires exactly once at the staging refusal point"
    );
    assert_eq!(
        refusal
            .coordinator
            .registry()
            .feed_mode_for_test(refusal_id),
        Some(FeedMode::S1Only),
        "ordered fallback degrades the feed to S1Only"
    );
    assert_eq!(
        refusal.coordinator.joint_capture().ledger().census(),
        0,
        "the refused stage holds no census"
    );
    assert_eq!(
        refusal.coordinator.joint_capture().ledger().staged(),
        0,
        "the refused stage holds no staged roles"
    );
    assert_eq!(
        refusal.coordinator.joint_capture().ledger().charged_bytes(),
        0,
        "the refused ledger contacts charge no bytes"
    );
    assert_eq!(
        r_post - r_pre,
        headroom,
        "the refused commit moves exactly the non-prepay delta"
    );
    assert_eq!(
        refused_after - refused_before,
        2,
        "the stage and the assoc mint each refuse the prepay once"
    );
    assert_s1_equal(refusal.reducer(refusal_id), s1.reducer(s1_id));
    assert_eq!(
        refusal.reducer(refusal_id).calls(),
        1,
        "the fallback reduces the refused call S1-direct"
    );
    let r_keyuse = refusal.coordinator.registry().keyuse_for_test();
    assert_eq!(
        r_keyuse.open().len(),
        0,
        "the refused assoc opens nothing live"
    );
    assert_eq!(
        r_keyuse.refused_opens().len(),
        1,
        "the refused assoc lands exactly one refused row"
    );
    assert_eq!(
        refusal.coordinator.registry().joint_observations(7),
        r_observations_before,
        "the fallback invents no object facts"
    );
    assert_eq!(
        s1.coordinator.registry().joint_observations(7),
        s1_observations_before,
        "the direct twin invents no object facts either"
    );
    for pipeline in [healthy, s1, refusal] {
        let registry = pipeline.coordinator.registry();
        let reserve = registry.semantic_storage_reserver();
        let limit = registry.semantic_resource_snapshot().limit_bytes;
        assert_semantic_pool_refunded_after_drop(pipeline, reserve, limit);
    }
}

/// Mixed H8-open census via adapter ingest, with N15 at capacity: 1000
/// H8Open charges plus 24 genuine adapter-collected raw quants (each
/// joined by its staged payload) fill the owner's 1024 census with
/// mixed roles. At capacity, an N15 sourced mint still accounts through
/// the owner (the assoc joins its staged operation, census flat), while
/// a sourceless mint refuses Full allocating nothing.
#[test]
fn joint_capture_owner_mixed_census_with_n15_at_capacity() {
    use crate::attach::SessionDrainProducers;
    use crate::attach::capture::NativeDomainId;
    use crate::events::{EventDrain, EventsDomain, ScriptedRecords};
    use crate::semantics_edge::resources::{OWNED_ALLOCATION_PADDING, SemanticResourcePool};
    use crate::semantics_objects::journal::LedgerRefusal;
    use crate::semantics_objects::journal::joint_driver::{JointCaptureOwner, RawJointQuantum};

    let rows = publish_object_descriptors();
    assert!(verify_object_descriptors(&rows));
    let domain = NativeDomainId::mint();
    let events = EventsDomain::test_standin(0xf202);
    let producers = SessionDrainProducers::test_pair(domain, events.clone());
    let pool = SemanticResourcePool::default();
    let base = pool.snapshot().charged_bytes;
    let mut owner = JointCaptureOwner::new(JournalLimits::policy(), pool.reserver());
    let fault = SteadyFaultCell(7);
    owner
        .ledger_mut()
        .charge_h8open(0, 8)
        .expect("H8Open charges");
    // First charge prepays the fixed table once (measured, never
    // hardcoded); the rest add exactly their own leases.
    let pool_after_first = pool.snapshot().charged_bytes;
    let table_prepay = pool_after_first - base - (8 + OWNED_ALLOCATION_PADDING);
    assert!(table_prepay > 0, "the first charge prepays the table");
    for ordinal in 1..1000 {
        owner
            .ledger_mut()
            .charge_h8open(ordinal, 8)
            .expect("H8Open charges");
    }
    assert_eq!(owner.ledger().census(), 1000);
    let pool_after_h8 = pool.snapshot().charged_bytes;
    assert_eq!(
        pool_after_h8 - pool_after_first,
        999 * (8 + OWNED_ALLOCATION_PADDING),
        "each further H8Open adds exactly its pool lease"
    );
    let mut staged_origins = Vec::new();
    for sequence in 1..=24u64 {
        let pool_before_quantum = pool.snapshot().charged_bytes;
        let begin = begin_bytes(1, sequence, function_id("C_Sign"), 0);
        let end = end_bytes_absent(&begin, 0, ENTRY_NS + 100 + sequence);
        let mut drain = EventDrain::over_domain(
            ScriptedRecords::records([begin.to_vec(), end.to_vec()], 2),
            events.clone(),
        );
        // The quantum drops (refunding its collection scratch)
        // before the staged charge lands: retained per quantum is
        // exactly the raw lease plus the staged lease.
        let origin = {
            let quantum = RawJointQuantum::collect_with_adapter(
                &mut drain,
                &rows,
                2,
                &fault,
                &producers,
                |bytes| pool.reserve(bytes),
                owner.adapter_mut(),
            )
            .expect("a genuine quantum collects through the owner's adapter");
            let (h0, _) = quantum
                .h0_input(producers.native_domain(), 2)
                .expect("the completed quantum lends its H0 input");
            h0.iter()
                .find_map(|record| record.joint_resource)
                .expect("the completed END projects a genuine adapter origin")
        };
        let staged = owner
            .ledger_mut()
            .charge_collected(producers.native_domain(), sequence, 300, Some(&origin))
            .expect("the staged payload joins its raw operation");
        staged_origins.push((sequence, staged));
        assert_eq!(
            pool.snapshot().charged_bytes - pool_before_quantum,
            OWNED_ALLOCATION_PADDING + (300 + OWNED_ALLOCATION_PADDING),
            "quantum {sequence} retains exactly its raw plus staged leases"
        );
    }
    // Each quantum above retained exactly its raw plus staged
    // leases (collection scratch refunded at quantum drop): the
    // total carries exactly the 24 uniform quants over H8Open.
    let mixed_pool = pool.snapshot().charged_bytes;
    assert_eq!(
        mixed_pool - pool_after_h8,
        24 * (OWNED_ALLOCATION_PADDING + (300 + OWNED_ALLOCATION_PADDING)),
        "the pool carries exactly the 24 quantum roles over the H8Open base"
    );
    assert_eq!(
        owner.ledger().census(),
        1024,
        "1000 H8Open plus 24 joined raw operations fill the census"
    );
    assert_eq!(owner.ledger().staged(), 24);
    let mixed_bytes = 1000 * 8 + 24 * 300;
    assert_eq!(owner.ledger().charged_bytes(), mixed_bytes);
    // N15 at capacity: the sourced assoc mint joins its staged
    // operation (no new slot), crediting the staged bytes it will
    // release right after — at-capacity replay still accounts.
    let (ticket, source) = &staged_origins[0];
    let assoc = owner
        .ledger_mut()
        .mint_keyassoc_from_stage(24, Some(source))
        .expect("at-capacity N15 mint joins through the owner");
    assert_eq!(owner.ledger().census(), 1024, "the join keeps census flat");
    assert_eq!(
        pool.snapshot().charged_bytes - mixed_pool,
        24 + OWNED_ALLOCATION_PADDING,
        "the joined assoc takes exactly its own pool lease"
    );
    owner
        .ledger_mut()
        .release_collected(producers.native_domain(), *ticket);
    assert_eq!(owner.ledger().staged(), 23);
    assert_eq!(
        owner.ledger().census(),
        1024,
        "the assoc holds its operation"
    );
    owner.ledger_mut().release_keyassoc(assoc);
    assert_eq!(
        owner.ledger().census(),
        1024,
        "the raw role still holds its operation"
    );
    // Sourceless mint at capacity refuses Full allocating nothing.
    let pool_before_refusal = pool.snapshot().charged_bytes;
    let bytes_before_refusal = owner.ledger().charged_bytes();
    let (result, peak, allocs, requested) =
        crate::test_alloc::counted_peak_during(|| owner.ledger_mut().mint_keyassoc(24));
    assert!(
        matches!(result, Err(LedgerRefusal::Full)),
        "a sourceless mint at capacity refuses Full"
    );
    assert!(!peak.incomplete);
    assert_eq!((peak.live_bytes, peak.peak_bytes), (0, 0));
    assert_eq!((allocs, requested), (0, 0));
    assert_eq!(owner.ledger().census(), 1024);
    assert_eq!(owner.ledger().charged_bytes(), bytes_before_refusal);
    assert_eq!(
        pool.snapshot().charged_bytes,
        pool_before_refusal,
        "the refused mint moves no pool bytes"
    );
}

/// Pipeline S1-precharge refusal through the owner: two staged heads,
/// one seal each. The calibration scene (default pool limit) replays
/// both seals green and measures the pool right after the first
/// replay; the tight scene pins the pool limit exactly there. Its
/// first seal replays identically (healthy twin); its second seal's
/// S1 growth (an open-binding charge over a full pool) refuses — the
/// head disposes as history, the feed stays Joint, live S1
/// invalidates with its terminals teed (the open row closes instead
/// of sticking), and the staged charge releases to the owner.
#[test]
fn joint_capture_owner_seal_replay_resource_refusal_disposes_head_keeps_joint() {
    use crate::discovery::caller_registry::OsProcessSource;
    use crate::discovery::engine::inventory_coordinator::InventoryCoordinator;

    struct Scene {
        coordinator: InventoryCoordinator<OsProcessSource>,
        scene: JointScene,
        caller: CallerId,
        key: InstanceKey,
        id: RegistryInstanceId,
        positions: Vec<u64>,
    }

    impl Scene {
        fn joint() -> Self {
            let mut coordinator = InventoryCoordinator::new(
                crate::attach::Scope::Pid(std::process::id()),
                crate::discovery::hooks::HookRegistry::builtin(),
                Vec::new(),
                OsProcessSource,
                RegistryLimits::new(16, 16, 16, 1024, 1024, 16).expect("generous limits"),
            )
            .expect("coordinator builds");
            let scene = JointScene::new();
            let bootstrap = scene.bootstrap();
            let module = ModuleKey::Physical {
                dev_major: 1,
                dev_minor: 2,
                ino: 3,
                sha256: None,
            };
            let caller = CallerId(7);
            let domain = NativeDomainId::try_mint().expect("fresh domain");
            let key = InstanceKey::scripted(
                domain,
                ImageIdentity {
                    task_cookie: 101,
                    exec_id: 1,
                },
                InstanceId::from_raw(1),
                module.clone(),
            );
            {
                let registry = coordinator.registry_mut();
                registry.scripted_module_edge(module, caller);
                assert!(
                    registry.install_joint_receipt(key.clone(), bootstrap),
                    "the receipt install fits the instance bound"
                );
                registry.note_instance(AdmittedInstance::scripted(key.clone(), caller));
            }
            coordinator
                .commit_batch(false)
                .expect("registration commits");
            let id = RegistryInstanceId::from_raw(0);
            assert_eq!(
                coordinator.registry().feed_mode_for_test(id),
                Some(FeedMode::Joint),
                "registration selects Joint"
            );
            Self {
                coordinator,
                scene,
                caller,
                key,
                id,
                positions: Vec::new(),
            }
        }

        fn pool(&self) -> crate::semantics_edge::resources::SemanticResourceSnapshot {
            self.coordinator.registry().semantic_resource_snapshot()
        }

        fn stage_shape(&mut self, shape: &ShapedS1) {
            let admitted = admit_call_input(&mut self.scene, shape);
            self.scene
                .adapter
                .attest_key(&admitted)
                .expect("call attests");
            let (facts, position) = (admitted.s1_facts().clone(), admitted.h0_ordinal());
            self.coordinator.registry_mut().observe_instance_semantic(
                AdmittedInstanceCall::scripted(self.key.clone(), self.caller, position, facts),
            );
            self.coordinator.commit_batch(false).expect("stage commits");
            self.positions.push(position);
        }

        fn seal_staged(&mut self, shape: &ShapedS1, position: u64) -> SealSuccess {
            ingest_call(&mut self.scene, shape, position);
            let seal = self.scene.seal().expect("quantum seals");
            assert_eq!(seal.prefix.settled().len(), 1, "one call settles");
            seal
        }

        fn deliver(&mut self, seal: &SealSuccess) -> SealApplyOutcome {
            let model = &self.scene.model;
            self.coordinator
                .deliver_joint_seal_through_owner(self.id, seal, model)
        }
    }

    let shape = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    let mut shape2 = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    shape2.session = Some(SESSION + 100);
    // Calibration (default limit): both seals replay green; measure
    // the pool AND its transient peak right after the first replay.
    // The pinned limit is the first replay's own peak: head 1 fits
    // exactly (healthy twin), while head 2 — a fresh session needing
    // a new open binding plus active machine — cannot.
    let mut healthy = Scene::joint();
    healthy.stage_shape(&shape);
    healthy.stage_shape(&shape2);
    assert_eq!(healthy.coordinator.joint_capture().ledger().staged(), 2);
    let seal1 = healthy.seal_staged(&shape, healthy.positions[0]);
    assert_eq!(
        healthy.deliver(&seal1),
        SealApplyOutcome::ReplayedOne,
        "calibration replays head 1"
    );
    let tight_limit = healthy.pool().peak_charged_bytes;
    let after_head1 = healthy.pool().charged_bytes;
    println!(
        "H3_MEM_S1_REFUSAL_CALIBRATION {{\"after_head1\": {after_head1}, \
         \"peak_head1\": {tight_limit}, \
         \"transient_conservatism\": {}}}",
        tight_limit - after_head1
    );
    assert_eq!(healthy.coordinator.joint_capture().ledger().staged(), 1);
    let seal2 = healthy.seal_staged(&shape2, healthy.positions[1]);
    assert_eq!(
        healthy.deliver(&seal2),
        SealApplyOutcome::ReplayedOne,
        "calibration replays head 2: the tight refusal is pool-caused"
    );
    assert_eq!(healthy.coordinator.joint_capture().ledger().staged(), 0);
    // Tight scene: same two heads, pool pinned at head 1's own peak.
    let mut tight = Scene::joint();
    tight
        .coordinator
        .registry_mut()
        .reference_semantic_resource_limit(tight_limit);
    tight.stage_shape(&shape);
    tight.stage_shape(&shape2);
    assert_eq!(tight.coordinator.joint_capture().ledger().staged(), 2);
    let seal1 = tight.seal_staged(&shape, tight.positions[0]);
    assert_eq!(
        tight.deliver(&seal1),
        SealApplyOutcome::ReplayedOne,
        "the first seal replays under the pinned limit (healthy twin)"
    );
    assert_eq!(tight.pool().charged_bytes, after_head1);
    assert_eq!(tight.coordinator.joint_capture().ledger().staged(), 1);
    assert_eq!(
        tight.coordinator.registry().keyuse_for_test().open().len(),
        1,
        "head 1's open is live when head 2 replays"
    );
    let refused_before = tight.pool().refused;
    let seal2 = tight.seal_staged(&shape2, tight.positions[1]);
    assert_eq!(
        tight.deliver(&seal2),
        SealApplyOutcome::ResourceRefused,
        "head 2's S1 growth over a full pool refuses"
    );
    assert_eq!(tight.pool().refused, refused_before + 1);
    assert_eq!(
        tight.coordinator.registry().feed_mode_for_test(tight.id),
        Some(FeedMode::Joint),
        "refusal keeps the feed Joint for later seals"
    );
    let record = tight
        .coordinator
        .registry()
        .instance_semantic_edges()
        .find(|record| record.id == tight.id)
        .expect("edge retained");
    assert_eq!(record.feed.staged_len(), 0, "the head disposed");
    assert_eq!(record.feed.history_disposed(), 1);
    assert_eq!(
        record.semantics.as_ref().expect("reducer kept").calls(),
        1,
        "only head 1 reduced"
    );
    assert!(
        !record
            .semantics
            .as_ref()
            .expect("reducer kept")
            .has_live_operations(),
        "refusal invalidates live S1"
    );
    assert!(
        tight
            .coordinator
            .registry()
            .keyuse_for_test()
            .open()
            .is_empty(),
        "the invalidated open's terminal teed through: no stuck open"
    );
    assert_eq!(tight.coordinator.joint_capture().ledger().staged(), 0);
    assert!(
        tight.pool().charged_bytes <= tight_limit,
        "the refused replay grows nothing"
    );
}

/// OD33/R-50: `object_observations` on an attachment with no linked
/// journal producer reports `unavailable` with the frozen reason
/// `journal_unavailable`. The Rust table and the frozen schema enum
/// carry it together (`key_operation_schema_contract` pins the sets
/// equal); `bootstrap_unavailable` keeps its 0.6.0 meaning (journal
/// linked, no birth yet).
#[test]
fn reason_enum_pins_journal_unavailable() {
    assert!(
        crate::key_operation_projection::REASON_LABELS.contains(&"journal_unavailable"),
        "REASON_LABELS must carry journal_unavailable"
    );
    assert!(
        crate::key_operation_projection::REASON_LABELS.contains(&"bootstrap_unavailable"),
        "bootstrap_unavailable keeps its 0.6.0 meaning"
    );
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            root.join("docs/schema/inventory-v1-object-observations.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let reasons: Vec<&str> = schema["properties"]["reason"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert!(
        reasons.contains(&"journal_unavailable"),
        "frozen schema enum must carry journal_unavailable"
    );
    assert!(
        reasons.contains(&"bootstrap_unavailable"),
        "frozen schema enum keeps bootstrap_unavailable"
    );
}

/// OD33/R-50: with no Joint feed and no linked journal producer, the
/// producer mapping reports `unavailable` with `journal_unavailable`;
/// linked without births keeps `bootstrap_unavailable`. Status stays
/// unavailable either way; rows stay empty.
#[test]
fn producer_commit_without_linked_journal_reports_journal_unavailable() {
    use crate::key_operation_projection::producer::commit_with_journal_linked;
    let fresh = JointStaging::select_s1_only();
    let empty_model = JointScene::new().model.project();
    let empty_keyuse = KeyUseReducer::new();
    let unlinked = commit_with_journal_linked(1, &[&fresh], &empty_model, &empty_keyuse, false);
    assert_eq!(unlinked.status, ObsStatus::Unavailable);
    assert_eq!(unlinked.reason, "journal_unavailable");
    assert!(unlinked.key_operations.is_empty());
    assert!(unlinked.unknown_key_operations.is_empty());
    let linked = commit_with_journal_linked(2, &[&fresh], &empty_model, &empty_keyuse, true);
    assert_eq!(linked.status, ObsStatus::Unavailable);
    assert_eq!(
        linked.reason, "bootstrap_unavailable",
        "linked without births keeps its 0.6.0 meaning"
    );
}

// ==================== 6.07b async userspace contract ====================
// S1: GetID mint (§3.1), Join transfer (§3.2), Complete-once (§3.3),
// duplicate (§3.5), stale (§3.6), failed (§3.7). Model redeem + seal
// path follow later (journal frozen; U-5 open: no proved async rows).

/// One PENDING C_SignInit on a session: queues S1-side, completes by
/// starting the machine (the :3618 carve-out shape).
fn pending_init(session: u64, ts_ns: u64) -> SemanticCall {
    let mut pending = init("C_SignInit", session, RSA_PKCS, ts_ns);
    pending.rv = CkRv::PENDING.0;
    pending
}

fn async_control(
    function: &str,
    session: u64,
    target: u32,
    value: u64,
    ts_ns: u64,
) -> SemanticCall {
    let mut control = call(function, session, CkRv::OK.0, ts_ns);
    control.target_function = target;
    control.async_value = value;
    control
}

fn sign_init_target() -> u32 {
    crate::kinds::function_id("C_SignInit").unwrap()
}

/// R2-D3-5: ≥2 eligible records ⇒ ambiguous: orphan with evidence,
/// consume none. Pending-first and BTree-first are withdrawn as proof.
#[test]
fn key_operation_async_complete_ambiguous_orphans_without_consuming() {
    let target = sign_init_target();
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    feed(
        &mut edge,
        &mut sink,
        &call("C_OpenSession", 7, CkRv::OK.0, 90),
    );
    feed(
        &mut edge,
        &mut sink,
        &call("C_OpenSession", 8, CkRv::OK.0, 95),
    );
    feed(&mut edge, &mut sink, &pending_init(7, 100));
    feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncGetID", 7, target, 42, 110),
    );
    feed(&mut edge, &mut sink, &pending_init(8, 120));
    feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncGetID", 8, target, 43, 130),
    );
    feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncJoin", 7, target, 43, 140),
    );
    // Session 7 now owns two detached ids for one target: the
    // completion is ambiguous and consumes neither.
    let effects = feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncComplete", 7, target, 0, 150),
    );
    assert!(effects.is_empty(), "ambiguous completion replays nothing");
    assert_eq!(edge.started(), 0);
    assert_eq!(edge.orphans(), 1);
    assert_eq!(edge.evidence().async_duplicates, 1);
    // Non-vacuity: both records are still live. Moving one id away
    // leaves exactly one eligible record, which completes.
    feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncJoin", 8, target, 42, 160),
    );
    let effects = feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncComplete", 7, target, 0, 170),
    );
    assert_eq!(effects.len(), 1);
    assert_eq!(edge.started(), 1);
    let (_, _, _, origin) = started(&effects[0]);
    assert_eq!(
        (origin.function.as_str(), origin.session, origin.ts_ns),
        ("C_SignInit", 8, 120),
        "the surviving record keeps its first origin"
    );
}

/// R2-D3-3: same-key remint over a live origin refuses (orphan +
/// ambiguity evidence); the first origin and the refused mint's
/// pending both stay intact.
#[test]
fn key_operation_async_getid_remint_refuses_first_origin_intact() {
    let target = sign_init_target();
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    feed(
        &mut edge,
        &mut sink,
        &call("C_OpenSession", 7, CkRv::OK.0, 90),
    );
    feed(
        &mut edge,
        &mut sink,
        &call("C_OpenSession", 8, CkRv::OK.0, 95),
    );
    feed(&mut edge, &mut sink, &pending_init(7, 100));
    feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncGetID", 7, target, 42, 110),
    );
    feed(&mut edge, &mut sink, &pending_init(8, 120));
    feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncGetID", 8, target, 42, 130),
    );
    assert_eq!(edge.orphans(), 1, "the second mint orphans");
    assert_eq!(edge.evidence().async_duplicates, 1);
    assert_eq!(edge.started(), 0);
    // The first origin is intact: session 7 completes its own call.
    let effects = feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncComplete", 7, target, 0, 140),
    );
    assert_eq!(effects.len(), 1);
    let (_, _, _, origin) = started(&effects[0]);
    assert_eq!(
        (origin.function.as_str(), origin.session, origin.ts_ns),
        ("C_SignInit", 7, 100),
        "first origin never overwritten"
    );
    // The refused mint's pending survived: session 8 completes direct.
    let effects = feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncComplete", 8, target, 0, 150),
    );
    assert_eq!(effects.len(), 1);
    let (_, _, _, origin) = started(&effects[0]);
    assert_eq!(
        (origin.function.as_str(), origin.session, origin.ts_ns),
        ("C_SignInit", 8, 120)
    );
    assert_eq!(edge.started(), 2);
}

/// R2-D3-5 (§3.5): duplicate PENDING queue for a live
/// (session, target) refuses; the first record completes.
#[test]
fn key_operation_async_duplicate_pending_refuses_first_intact() {
    let target = sign_init_target();
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    feed(
        &mut edge,
        &mut sink,
        &call("C_OpenSession", 7, CkRv::OK.0, 90),
    );
    feed(&mut edge, &mut sink, &pending_init(7, 100));
    feed(&mut edge, &mut sink, &pending_init(7, 200));
    assert_eq!(edge.evidence().async_duplicates, 1);
    assert_eq!(edge.orphans(), 1, "the refused queue orphans");
    let effects = feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncComplete", 7, target, 0, 300),
    );
    assert_eq!(effects.len(), 1);
    let (_, _, _, origin) = started(&effects[0]);
    assert_eq!(
        (origin.function.as_str(), origin.session, origin.ts_ns),
        ("C_SignInit", 7, 100),
        "first pending intact"
    );
    assert_eq!(edge.started(), 1);
}

/// R2-D3-5 zero arm: a completion with no eligible record orphans and
/// consumes nothing.
#[test]
fn key_operation_async_complete_zero_eligible_orphans() {
    let target = sign_init_target();
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    feed(
        &mut edge,
        &mut sink,
        &call("C_OpenSession", 7, CkRv::OK.0, 90),
    );
    let effects = feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncComplete", 7, target, 0, 100),
    );
    assert!(effects.is_empty());
    assert_eq!(edge.started(), 0);
    assert_eq!(edge.orphans(), 1);
    assert_eq!(edge.evidence().async_duplicates, 0);
}

/// R2-D3-5 once-token: a pending-only completion consumes exactly
/// once; redelivery finds no record and orphans.
#[test]
fn key_operation_async_complete_pending_only_consumes_once() {
    let target = sign_init_target();
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    feed(
        &mut edge,
        &mut sink,
        &call("C_OpenSession", 7, CkRv::OK.0, 90),
    );
    feed(&mut edge, &mut sink, &pending_init(7, 100));
    let effects = feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncComplete", 7, target, 0, 200),
    );
    assert_eq!(effects.len(), 1);
    let (_, _, _, origin) = started(&effects[0]);
    assert_eq!(
        (origin.function.as_str(), origin.session, origin.ts_ns),
        ("C_SignInit", 7, 100)
    );
    assert_eq!(edge.started(), 1);
    let effects = feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncComplete", 7, target, 0, 300),
    );
    assert!(effects.is_empty(), "redelivery replays nothing");
    assert_eq!(edge.started(), 1);
    assert_eq!(edge.orphans(), 1);
}

/// R2-D3-4: Join moves whole custody to the joiner (origin, receipts,
/// position unchanged); floating ids stay joinable; failed Join and
/// unknown keys mutate nothing / orphan.
#[test]
fn key_operation_async_join_moves_whole_custody() {
    let target = sign_init_target();
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    feed(
        &mut edge,
        &mut sink,
        &call("C_OpenSession", 7, CkRv::OK.0, 90),
    );
    feed(
        &mut edge,
        &mut sink,
        &call("C_OpenSession", 8, CkRv::OK.0, 95),
    );
    feed(&mut edge, &mut sink, &pending_init(7, 100));
    feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncGetID", 7, target, 42, 110),
    );
    // A failed Join mutates nothing: no custody move, no evidence.
    let mut failed = async_control("C_AsyncJoin", 8, target, 42, 120);
    failed.rv = CkRv::GENERAL_ERROR.0;
    feed(&mut edge, &mut sink, &failed);
    assert_eq!(edge.orphans(), 0);
    // An unknown-key Join orphans.
    feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncJoin", 8, target, 999, 125),
    );
    assert_eq!(edge.orphans(), 1);
    // The successful Join moves whole custody; the completion keeps
    // the original (7, 100) identity.
    feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncJoin", 8, target, 42, 130),
    );
    let effects = feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncComplete", 8, target, 0, 140),
    );
    assert_eq!(effects.len(), 1);
    let (_, _, _, origin) = started(&effects[0]);
    assert_eq!(
        (origin.function.as_str(), origin.session, origin.ts_ns),
        ("C_SignInit", 7, 100)
    );
    // Floating ids (owner None after close) stay joinable in-edge.
    feed(&mut edge, &mut sink, &pending_init(7, 200));
    feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncGetID", 7, target, 43, 210),
    );
    feed(
        &mut edge,
        &mut sink,
        &call("C_CloseSession", 7, CkRv::OK.0, 220),
    );
    // Fresh joiner: session 8 owns a live machine from the first
    // half's replay, so a completion by 8 would stale-orphan (F2).
    feed(
        &mut edge,
        &mut sink,
        &call("C_OpenSession", 9, CkRv::OK.0, 225),
    );
    feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncJoin", 9, target, 43, 230),
    );
    let effects = feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncComplete", 9, target, 0, 240),
    );
    assert_eq!(effects.len(), 1);
    let (_, _, _, origin) = started(&effects[0]);
    assert_eq!(
        (origin.function.as_str(), origin.session, origin.ts_ns),
        ("C_SignInit", 7, 200)
    );
    assert_eq!(edge.started(), 2);
}

/// R2-D3-7 (§3.7): failed controls and CKR_PENDING completions mutate
/// nothing and dispose nothing; the pending stays completable.
#[test]
fn key_operation_async_failed_controls_mutate_nothing() {
    let target = sign_init_target();
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    feed(
        &mut edge,
        &mut sink,
        &call("C_OpenSession", 7, CkRv::OK.0, 90),
    );
    feed(&mut edge, &mut sink, &pending_init(7, 100));
    let mut pending_complete = async_control("C_AsyncComplete", 7, target, 0, 110);
    pending_complete.rv = CkRv::PENDING.0;
    feed(&mut edge, &mut sink, &pending_complete);
    assert_eq!(edge.started(), 0);
    assert_eq!(edge.orphans(), 0);
    let mut failed_get = async_control("C_AsyncGetID", 7, target, 42, 120);
    failed_get.rv = CkRv::GENERAL_ERROR.0;
    feed(&mut edge, &mut sink, &failed_get);
    assert_eq!(edge.started(), 0);
    assert_eq!(edge.orphans(), 0);
    let effects = feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncComplete", 7, target, 0, 130),
    );
    assert_eq!(effects.len(), 1, "pending survived both failures");
    let (_, _, _, origin) = started(&effects[0]);
    assert_eq!(
        (origin.function.as_str(), origin.session, origin.ts_ns),
        ("C_SignInit", 7, 100)
    );
}

/// R2-D3-5/§3.6: a joined completion landing on the receiver's own
/// newer machine is stale and orphans instead of joining.
#[test]
fn key_operation_async_stale_completion_orphans() {
    let mut edge = EdgeSemantics::default();
    let mut sink = Vec::new();
    feed(
        &mut edge,
        &mut sink,
        &call("C_OpenSession", 7, CkRv::OK.0, 90),
    );
    feed(
        &mut edge,
        &mut sink,
        &call("C_OpenSession", 8, CkRv::OK.0, 95),
    );
    feed(&mut edge, &mut sink, &init("C_SignInit", 7, RSA_PKCS, 100));
    let mut pending = op("C_Sign", 7, 110);
    pending.rv = CkRv::PENDING.0;
    feed(&mut edge, &mut sink, &pending);
    let sign = crate::kinds::function_id("C_Sign").unwrap();
    feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncGetID", 7, sign, 42, 120),
    );
    // The receiver holds its own newer sign machine before joining.
    feed(&mut edge, &mut sink, &init("C_SignInit", 8, RSA_PKCS, 130));
    feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncJoin", 8, sign, 42, 140),
    );
    let effects = feed(
        &mut edge,
        &mut sink,
        &async_control("C_AsyncComplete", 8, sign, 0, 150),
    );
    assert!(effects.is_empty(), "stale completion replays nothing");
    assert_eq!(edge.started(), 2, "only the two Inits started");
    assert_eq!(edge.completed(), 0);
    assert_eq!(edge.orphans(), 1);
}

/// 6.07b Q1: a qualified PENDING origin END mints a deferred origin
/// (DeferredMinted + stored record); the Q2 primitive redeems it once
/// with the origin ticket and frozen inputs.
#[test]
fn key_operation_joint_async_pending_mints_deferred_origin() {
    use crate::semantics_objects::{KeyLabel, ObjectEffect};

    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    // Create + label a key so the PENDING Init freezes a settled input.
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1 {
            input0: Some((CREATED_KEY, 1)),
            getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
            ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
        },
    );
    assert!(
        !scene.model.project().objects.is_empty(),
        "the key exists before the PENDING origin"
    );
    let (_, _) = prepare_call(
        &mut scene,
        &mut staging,
        &ShapedS1::shaped("C_SignInit", CkRv::PENDING.0, RSA_PKCS, init_capture()),
    );
    let success = scene.seal().expect("pending quantum seals");
    assert_eq!(success.prefix.settled().len(), 1);
    let ticket = success
        .effects
        .effects
        .iter()
        .find_map(|effect| match effect {
            ObjectEffect::DeferredMinted { call } => Some(*call),
            _ => None,
        })
        .expect("origin PENDING END mints a deferred origin");
    assert_eq!(scene.model.project().usage.deferred_origins, 1);
    let redeemed = scene
        .model
        .redeem_deferred(ticket)
        .expect("live record redeems once");
    let refs: Vec<_> = redeemed
        .effects
        .iter()
        .filter_map(|effect| match effect {
            ObjectEffect::Referenced {
                call,
                object: _,
                key_use,
                input,
                metadata: _,
                label,
                attribution_valid,
            } => Some((*call, *key_use, *input, *label, *attribution_valid)),
            _ => None,
        })
        .collect();
    assert_eq!(refs.len(), 1, "one frozen input redeems one reference");
    assert_eq!(refs[0].0, ticket, "origin ticket");
    assert!(refs[0].1, "access input is a key use");
    assert_eq!(refs[0].2, Some(0));
    assert_eq!(refs[0].3, Some(KeyLabel::Rsa { modulus_bits: 2048 }));
    assert!(refs[0].4);
    assert_eq!(scene.model.project().usage.deferred_origins, 0);
    assert!(
        scene.model.redeem_deferred(ticket).is_none(),
        "removal is the once-token"
    );
}

/// 6.07b F3: a PENDING origin with an unknown session mints the
/// effect but stores no record: permanently unknown, never repaired.
#[test]
fn key_operation_joint_async_deferred_unknown_session_stays_unknown() {
    use crate::semantics_objects::ObjectEffect;

    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut shape = ShapedS1::shaped("C_SignInit", CkRv::PENDING.0, RSA_PKCS, init_capture());
    shape.session = Some(0x0BEEF);
    let (_, _) = prepare_call(&mut scene, &mut staging, &shape);
    let success = scene.seal().expect("pending quantum seals");
    let ticket = success
        .effects
        .effects
        .iter()
        .find_map(|effect| match effect {
            ObjectEffect::DeferredMinted { call } => Some(*call),
            _ => None,
        })
        .expect("unknown-session origin still mints the effect");
    assert_eq!(
        scene.model.project().usage.deferred_origins,
        0,
        "no incarnation, no record"
    );
    assert!(
        scene.model.redeem_deferred(ticket).is_none(),
        "nothing to redeem"
    );
}

/// 6.07b carve-out replacement (userspace): Q1 mints the deferred
/// origin; the completion still reduces S1Only-direct (journal frozen,
/// so `Unsealable` stays); the S1 machine starts once; the row stays
/// unknown-key `unbound` (U-5 open: no proved async rows); S1 twins agree.
#[test]
fn key_operation_joint_async_pending_mint_then_unbound_completion() {
    use crate::semantics_objects::ObjectEffect;

    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut joint_sink = Vec::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    let mut assoc_ledger = StagingLedger::new();

    // Q0: create + label a key so Q1 freezes a settled input.
    for shape in [
        ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
        ShapedS1 {
            input0: Some((CREATED_KEY, 1)),
            getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
            ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
        },
    ] {
        let (facts, _) = prepare_call(&mut scene, &mut staging, &shape);
        let success = scene.seal().expect("setup quantum seals");
        let (outcome, _) = staging.apply_seal(
            &success,
            &scene.model,
            scene.adapter.ledger_mut(),
            &mut joint,
            &mut keyuse,
            instance,
            &mut joint_sink,
            None,
        );
        assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
        let origin = EffectOrigin::from(&facts);
        direct.observe_with_effects(&facts, &origin, &mut direct_sink);
    }

    // Q1: the PENDING Init stages, seals, replays and queues — and now
    // mints a deferred origin.
    let pending = ShapedS1::shaped("C_SignInit", CkRv::PENDING.0, RSA_PKCS, init_capture());
    let (facts, _) = prepare_call(&mut scene, &mut staging, &pending);
    let success = scene.seal().expect("pending quantum seals");
    assert_eq!(success.prefix.settled().len(), 1);
    assert!(
        success
            .effects
            .effects
            .iter()
            .any(|effect| matches!(effect, ObjectEffect::DeferredMinted { .. })),
        "Q1 mints the deferred origin"
    );
    assert_eq!(scene.model.project().usage.deferred_origins, 1);
    let (outcome, _) = staging.apply_seal(
        &success,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    let origin = EffectOrigin::from(&facts);
    direct.observe_with_effects(&facts, &origin, &mut direct_sink);
    assert_eq!(strip_receipts(&joint_sink), direct_sink);
    assert_s1_equal(&joint, &direct);
    assert_eq!(
        (joint.started(), joint.completed()),
        (0, 0),
        "queued, not started"
    );

    // Q2: the completion still cannot stage (journal frozen), so the
    // driver reduces it S1Only-direct on both feeds; the S1 machine
    // starts once with the original identity.
    let target = crate::kinds::function_id("C_SignInit").unwrap();
    let mut complete = SemanticCall {
        function: "C_AsyncComplete".into(),
        session: SESSION,
        target_function: target,
        capture: op_capture(),
        ts_ns: 999,
        ..SemanticCall::default()
    };
    complete.rv = CkRv::OK.0;
    let origin = EffectOrigin::from(&complete);
    assert_eq!(
        staging.stage(
            complete.clone(),
            origin.clone(),
            999,
            scene.adapter.ledger_mut()
        ),
        Err(StagingRefusal::Unsealable)
    );
    let effects_before = joint_sink.len();
    joint.observe_with_effects(&complete, &origin, &mut joint_sink);
    for effect in &joint_sink[effects_before..] {
        keyuse.observe_effect(instance, effect, Some(&mut assoc_ledger), None);
    }
    direct.observe_with_effects(&complete, &origin, &mut direct_sink);
    assert_eq!(strip_receipts(&joint_sink), direct_sink);
    assert_s1_equal(&joint, &direct);
    assert_eq!(joint.started(), 1, "the completion starts the machine");
    let (_, _, _, corigin) = started(joint_sink.last().unwrap());
    assert_eq!(corigin.function, "C_SignInit", "original call identity");

    // The Sign completes the async-started machine on both feeds; its
    // row stays unknown-key `unbound` (U-5 open: no proved async rows).
    let sign = ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture());
    let (facts, _) = prepare_call(&mut scene, &mut staging, &sign);
    let success = scene.seal().expect("terminal quantum seals");
    let (outcome, _) = staging.apply_seal(
        &success,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    let origin = EffectOrigin::from(&facts);
    direct.observe_with_effects(&facts, &origin, &mut direct_sink);
    assert_eq!(strip_receipts(&joint_sink), direct_sink);
    assert_eq!((joint.started(), joint.completed()), (1, 1));
    assert!(
        keyuse.aggregates().is_empty(),
        "async start binds no receipt"
    );
    assert_eq!(keyuse.evidence().unknown_key_rows, 1);
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .unknown_key_operations
        .iter()
        .find(|row| row.category == "sign" && row.reason == "unbound")
        .expect("async completion rows unknown-key");
    assert_eq!((row.completed, row.active), (1, 0));
}

// ==================== 6.07a object/session lifecycles ====================
// P4 Initialize era rule (owner-approved 2026-10-29) plus lifecycle
// close-all/finalize/copy/find coverage, each ending in a
// producer→seal→reducer→projection link proof. Model-only green is
// not delivery: every test below commits.

/// P4-M5 through producer→seal→reducer→projection: a genuine second
/// qualified C_Initialize OK on the live (already-initialized) era
/// contradicts — Downgraded joins, UnseenFinalize gap — while the
/// seal itself succeeds and the commit stays honest. A birth bootstrap
/// alone is not a live era: the first success mints.
#[test]
fn key_operation_lifecycle_initialize_ok_contradicts_live_era() {
    use crate::semantics_objects::{Attribution, Lifetime, ObjectGap, SessionState};
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Initialize", CkRv::OK.0, 0, 0),
    );
    assert_eq!(
        scene.model.project().gap(ObjectGap::UnseenFinalize),
        0,
        "the first success mints"
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    assert!(
        joint.has_live_operations(),
        "the use is live before duplicate"
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Initialize", CkRv::OK.0, 0, 0),
    );
    let projection = scene.model.project();
    assert_eq!(projection.objects.len(), 1);
    let view = &projection.objects[0];
    assert_eq!(
        view.attribution,
        Attribution::Downgraded(ObjectGap::UnseenFinalize),
        "duplicate OK downgrades the published join"
    );
    assert_eq!(
        view.lifetime,
        Lifetime::Retired(ObjectGap::UnseenFinalize),
        "contradiction retires live continuity"
    );
    assert!(
        projection
            .sessions
            .iter()
            .all(|s| matches!(s.state, SessionState::Ended(ObjectGap::UnseenFinalize))),
        "live sessions end uncertain"
    );
    assert!(
        projection.gap(ObjectGap::UnseenFinalize) >= 1,
        "the contradiction is counted"
    );
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(committed.status, ObsStatus::Populated);
    assert_eq!(committed.reason, "none");
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("the use row stands");
    assert_eq!(
        (row.started, row.active, row.key_join_lost),
        (1, 0, 1),
        "the ended binding closes to key_join_lost"
    );
    let object = &committed.objects[0];
    assert_eq!(object.lifetime, "retired");
    assert_eq!(object.lifetime_reason, Some("unseen_finalize"));
    assert_eq!(object.attribution, "downgraded");
    assert_eq!(object.attribution_reason, Some("unseen_finalize"));
    assert!(
        committed
            .gaps
            .iter()
            .any(|gap| gap.subject == "model" && gap.reason == "unseen_finalize"),
        "the gap row survives to the projection"
    );
}

/// P4-M4 through the link: ALREADY_INITIALIZED is a benign no-op —
/// no mint, no end, no void, no contradiction — and P4-M2 argument 0
/// is never a session: two session words behave identically.
#[test]
fn key_operation_lifecycle_initialize_already_is_benign_noop() {
    use crate::semantics_objects::{Lifetime, ObjectGap, SessionState};
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();
    let (facts, _) = drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    observe_direct(&mut direct, &mut direct_sink, &facts);
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    let (facts, _) = drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    observe_direct(&mut direct, &mut direct_sink, &facts);
    let (facts, _) = drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    observe_direct(&mut direct, &mut direct_sink, &facts);
    let sessions_before = scene.model.project().sessions.len();
    for word in [7u64, 8u64] {
        let mut already =
            ShapedS1::shaped("C_Initialize", CkRv::CRYPTOKI_ALREADY_INITIALIZED.0, 0, 0);
        already.session = Some(word);
        let (facts, _) = drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &already,
        );
        observe_direct(&mut direct, &mut direct_sink, &facts);
    }
    let projection = scene.model.project();
    assert_eq!(
        projection.sessions.len(),
        sessions_before,
        "argument 0 never names a session"
    );
    assert!(
        projection
            .objects
            .iter()
            .all(|view| matches!(view.lifetime, Lifetime::Live)),
        "ALREADY ends nothing"
    );
    assert!(
        projection
            .sessions
            .iter()
            .all(|s| matches!(s.state, SessionState::Live)),
        "ALREADY closes nothing"
    );
    assert_eq!(projection.gap(ObjectGap::UnseenFinalize), 0);
    assert_s1_equal(&joint, &direct);
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(committed.status, ObsStatus::Populated);
    assert_eq!(committed.reason, "none");
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("the live use stands");
    assert_eq!(
        (row.started, row.active, row.key_join_lost),
        (1, 1, 0),
        "the use stays live across benign ALREADYs"
    );
}

/// Unknown-output copy/find invent nothing: copy reports its
/// unreadable output, the find sequence stays silent, and a later use
/// still populates proved rows through the commit.
#[test]
fn key_operation_lifecycle_copy_find_unknown_output_invents_nothing() {
    use crate::semantics_objects::ObjectGap;
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    let mut copy = ShapedS1::shaped("C_CopyObject", CkRv::OK.0, 0, 0);
    copy.input0 = Some((CREATED_KEY, 1));
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &copy,
    );
    assert_eq!(
        scene.model.project().objects.len(),
        1,
        "an unreadable copy output mints no view"
    );
    assert!(
        scene.model.project().gap(ObjectGap::OutputUnreadable) >= 1,
        "the missing output is counted, never guessed"
    );
    for name in ["C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal"] {
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped(name, CkRv::OK.0, 0, 0),
        );
    }
    assert_eq!(
        scene.model.project().objects.len(),
        1,
        "an absent find tail invents no views"
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(committed.status, ObsStatus::Populated);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("the completed use rows proved");
    assert_eq!(
        (row.started, row.completed, row.active, row.key_join_lost),
        (1, 1, 0, 0)
    );
    assert!(
        committed
            .gaps
            .iter()
            .any(|gap| gap.reason == "output_unreadable"),
        "the copy gap survives to the projection"
    );
}

/// 6.07a delivery gate: close-all retires uncertain, a successful
/// finalize ends the era inside its seal, a later quantum on the
/// ended domain is refused at conversion, a failed finalize keeps
/// state, and the unlinked lane twin reports journal_unavailable —
/// with status/reason/row/bucket behavior committed at every stage.
#[test]
fn key_operation_lifecycle_close_all_finalize_commit_link() {
    use crate::key_operation_projection::producer::commit_with_journal_linked;
    use crate::semantics_objects::{Lifetime, ObjectGap, SessionState};
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();
    // Stage 1: a healthy use populates proved rows.
    let (facts, _) = drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    observe_direct(&mut direct, &mut direct_sink, &facts);
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    let (facts, _) = drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    observe_direct(&mut direct, &mut direct_sink, &facts);
    let (facts, _) = drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    observe_direct(&mut direct, &mut direct_sink, &facts);
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(
        (committed.status, committed.reason),
        (ObsStatus::Populated, "none")
    );
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("stage 1 rows the live use");
    assert_eq!((row.started, row.active), (1, 1));
    assert_eq!(committed.budgets.key_occupied, 1);
    assert_eq!(committed.objects.len(), 1);
    assert_eq!(committed.objects[0].lifetime, "live");
    // Stage 2: close-all over unknown seal scopes retires uncertain.
    let (facts, _) = drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CloseAllSessions", CkRv::OK.0, 0, 0),
    );
    observe_direct(&mut direct, &mut direct_sink, &facts);
    assert_s1_equal(&joint, &direct);
    let projection = scene.model.project();
    assert!(
        projection.objects.iter().all(|view| matches!(
            view.lifetime,
            Lifetime::Retired(ObjectGap::CloseAllUncertain)
        )),
        "uncertain close-all retires, never destroys"
    );
    assert!(
        projection
            .sessions
            .iter()
            .all(|s| matches!(s.state, SessionState::Ended(ObjectGap::CloseAllUncertain)))
    );
    let committed = commit(2, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(
        (committed.status, committed.reason),
        (ObsStatus::Populated, "none")
    );
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("stage 2 keeps the use row");
    assert_eq!((row.active, row.key_join_lost), (0, 1));
    assert_eq!(committed.objects[0].lifetime, "retired");
    assert_eq!(
        committed.objects[0].lifetime_reason,
        Some("close_all_uncertain")
    );
    // Stage 3: a successful finalize ends a live era inside its
    // seal (fresh scene: finalize retires live views, and stage 2
    // already retired this scene's). The commit shows the ended era
    // honestly; a later quantum on the ended domain is refused at
    // conversion — nothing joins across the split.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();
    let (facts, _) = drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    observe_direct(&mut direct, &mut direct_sink, &facts);
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    let (facts, _) = drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    observe_direct(&mut direct, &mut direct_sink, &facts);
    let (facts, _) = drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    observe_direct(&mut direct, &mut direct_sink, &facts);
    let (facts, _) = drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Finalize", CkRv::OK.0, 0, 0),
    );
    observe_direct(&mut direct, &mut direct_sink, &facts);
    assert_s1_equal(&joint, &direct);
    let projection = scene.model.project();
    assert!(
        projection
            .objects
            .iter()
            .all(|view| matches!(view.lifetime, Lifetime::AccessEnded(ObjectGap::Finalize))),
        "finalize ends every view with its own reason"
    );
    assert!(
        projection
            .sessions
            .iter()
            .all(|s| !matches!(s.state, SessionState::Live)),
        "finalize ends every session"
    );
    let committed = commit(3, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(
        (committed.status, committed.reason),
        (ObsStatus::Populated, "none"),
        "the Joint feed commits the ended era honestly"
    );
    assert_eq!(committed.objects[0].lifetime, "access_ended");
    assert_eq!(committed.objects[0].lifetime_reason, Some("finalize"));
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("stage 3 keeps the use row");
    assert_eq!(
        (row.started, row.completed, row.active, row.key_join_lost),
        (1, 0, 0, 1),
        "the live binding closes to key_join_lost exactly once"
    );
    prepare_call(
        &mut scene,
        &mut staging,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let failure = scene.seal().expect_err("nothing joins across the split");
    assert_eq!(failure.gap, JournalGap::ModelRefused);
    assert!(
        scene
            .model
            .project()
            .objects
            .iter()
            .all(|view| matches!(view.lifetime, Lifetime::AccessEnded(ObjectGap::Finalize))),
        "the refused quantum changes nothing"
    );
    // Stage 4: a failed finalize keeps state (twin scene).
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Finalize", CkRv::FUNCTION_FAILED.0, 0, 0),
    );
    assert!(joint.has_live_operations(), "failed finalize keeps S1 live");
    let committed = commit(4, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(
        (committed.status, committed.reason),
        (ObsStatus::Populated, "none")
    );
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("failed finalize keeps the live use");
    assert_eq!((row.started, row.active, row.key_join_lost), (1, 1, 0));
    assert_eq!(committed.objects[0].lifetime, "live");
    // Stage 5: the same populated model through an unlinked lane
    // reports journal_unavailable — rows in memory are not delivery.
    let s1only = JointStaging::select_s1_only();
    let unlinked =
        commit_with_journal_linked(5, &[&s1only], &scene.model.project(), &keyuse, false);
    assert_eq!(unlinked.status, ObsStatus::Unavailable);
    assert_eq!(unlinked.reason, "journal_unavailable");
    assert_eq!(unlinked.objects.len(), 1, "rows stay while status refuses");
}

/// Object handle reuse retires the old view and mints the new one,
/// and inaccessible attribute reads establish nothing: a SENSITIVE
/// GetAttributeValue records its unavailable queries without
/// inventing values. The commit carries both rows honestly.
#[test]
fn key_operation_lifecycle_handle_reuse_and_inaccessible_attributes() {
    use crate::semantics_objects::{FieldState, Lifetime, ObjectGap, QueryStatus, field_index};
    use p11scope_ebpf_common::object_policy::SafeAttributeKind;
    const H1: u64 = 0xA1A1_0001;
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    let mut create = ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0);
    create.result = Some(H1);
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &create,
    );
    let mut reuse = ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0);
    reuse.result = Some(H1);
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &reuse,
    );
    let mut get = ShapedS1::shaped("C_GetAttributeValue", CkRv::ATTRIBUTE_SENSITIVE.0, 0, 0);
    get.input0 = Some((H1, 1));
    get.getattr_cells = vec![(1u8, 3u8, 0u16), (2u8, 3u8, 0u16)];
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    let projection = scene.model.project();
    assert_eq!(projection.objects.len(), 2);
    assert!(
        projection
            .objects
            .iter()
            .any(|view| matches!(view.lifetime, Lifetime::Retired(ObjectGap::HandleReuse))),
        "the reused old view retires"
    );
    let live = projection
        .objects
        .iter()
        .find(|view| matches!(view.lifetime, Lifetime::Live))
        .expect("the reuse mints a live view");
    for kind in [SafeAttributeKind::Class, SafeAttributeKind::KeyType] {
        assert_eq!(
            live.established.field(kind),
            FieldState::Unknown,
            "inaccessible reads establish nothing"
        );
        assert_eq!(
            live.queries[field_index(kind)],
            QueryStatus::Unavailable,
            "the unavailable query is recorded"
        );
    }
    assert_eq!(live.label, None, "no label without values");
    let mut destroy = ShapedS1::shaped("C_DestroyObject", CkRv::OK.0, 0, 0);
    destroy.input0 = Some((H1, 1));
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &destroy,
    );
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(
        (committed.status, committed.reason),
        (ObsStatus::Populated, "none")
    );
    assert_eq!(committed.objects.len(), 2);
    assert!(
        committed
            .objects
            .iter()
            .any(|row| row.lifetime == "retired" && row.lifetime_reason == Some("handle_reuse")),
        "the retired row keeps its reason"
    );
    let destroyed = committed
        .objects
        .iter()
        .find(|row| row.lifetime == "destroyed")
        .expect("the reuse target destroys");
    assert_eq!(destroyed.queries.class, "unavailable");
    assert_eq!(destroyed.queries.key_type, "unavailable");
    assert_eq!(destroyed.label, None);
}

/// P4 first-initialize through seal (finding 1): fresh independently
/// attested birth, Initialize OK first (no prior create/open), then
/// create/getattr/SignInit/Sign. No unseen_finalize, populated rows.
/// Includes one batched seal plus a duplicate-success twin.
#[test]
fn key_operation_lifecycle_first_initialize_through_seal() {
    use crate::semantics_objects::{Attribution, Lifetime, ObjectGap, SessionState};
    // Part A: separate seals, full link proof.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Initialize", CkRv::OK.0, 0, 0),
    );
    assert_eq!(
        scene.model.project().gap(ObjectGap::UnseenFinalize),
        0,
        "first Initialize mints, never contradicts"
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let projection = scene.model.project();
    assert_eq!(
        projection.gap(ObjectGap::UnseenFinalize),
        0,
        "no unseen_finalize across the first era"
    );
    assert_eq!(projection.objects.len(), 1, "real populated rows");
    assert!(
        matches!(projection.objects[0].lifetime, Lifetime::Live),
        "the created view stays live"
    );
    assert!(
        projection
            .sessions
            .iter()
            .any(|s| matches!(s.state, SessionState::Live)),
        "sessions stay live"
    );
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(
        (committed.status, committed.reason),
        (ObsStatus::Populated, "none")
    );
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("the completed use rows proved");
    assert_eq!(
        (row.started, row.completed, row.active, row.key_join_lost),
        (1, 1, 0, 0),
        "one started/completed keyed operation, no fallback/double replay"
    );
    // Part B: one batched seal (Initialize + create share a seal).
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    prepare_call(
        &mut scene,
        &mut staging,
        &ShapedS1::shaped("C_Initialize", CkRv::OK.0, 0, 0),
    );
    prepare_call(
        &mut scene,
        &mut staging,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let success = scene.seal().expect("batched quantum seals");
    assert_eq!(success.prefix.settled().len(), 2);
    let (outcome, refused) = staging.apply_seal(
        &success,
        &scene.model,
        scene.adapter.ledger_mut(),
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
        None,
    );
    assert_eq!(outcome, SealApplyOutcome::Held, "multicall holds S1");
    assert_eq!(refused, 0);
    let projection = scene.model.project();
    assert_eq!(
        projection.gap(ObjectGap::UnseenFinalize),
        0,
        "batched first Initialize mints"
    );
    assert_eq!(
        projection.objects.len(),
        1,
        "batched follow-on qualifies on the minted era"
    );
    // Part C: duplicate-success twin downgrades prior joins; ALREADY and
    // FUNCTION_FAILED mint nothing and contradict nothing.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Initialize", CkRv::OK.0, 0, 0),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    assert!(
        joint.has_live_operations(),
        "the use is live before duplicate"
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Initialize", CkRv::OK.0, 0, 0),
    );
    let projection = scene.model.project();
    assert_eq!(projection.objects.len(), 1);
    let view = &projection.objects[0];
    assert_eq!(
        view.attribution,
        Attribution::Downgraded(ObjectGap::UnseenFinalize),
        "duplicate OK downgrades the published join"
    );
    assert_eq!(
        view.lifetime,
        Lifetime::Retired(ObjectGap::UnseenFinalize),
        "contradiction retires live continuity"
    );
    assert!(
        projection.gap(ObjectGap::UnseenFinalize) >= 1,
        "the duplicate contradiction is counted"
    );
    let committed = commit(2, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("the use row stands");
    assert_eq!(
        (row.started, row.active, row.key_join_lost),
        (1, 0, 1),
        "the ended binding closes to key_join_lost"
    );
    // ALREADY and FUNCTION_FAILED after a proved first success are benign
    // no-mint no-contradiction twins (fresh scenes to avoid the voided domain).
    for rv in [
        CkRv::CRYPTOKI_ALREADY_INITIALIZED.0,
        CkRv::FUNCTION_FAILED.0,
    ] {
        let mut scene = JointScene::new();
        let bootstrap = scene.bootstrap();
        let mut staging = JointStaging::select_joint(Some(&bootstrap));
        let mut joint = EdgeSemantics::default();
        let mut keyuse = KeyUseReducer::new();
        let mut sink = Vec::new();
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped("C_Initialize", CkRv::OK.0, 0, 0),
        );
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
        );
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
        );
        let gaps_before = scene.model.project().gap(ObjectGap::UnseenFinalize);
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped("C_Initialize", rv, 0, 0),
        );
        let projection = scene.model.project();
        assert_eq!(
            projection.gap(ObjectGap::UnseenFinalize),
            gaps_before,
            "rv {rv:#x} contradicts nothing"
        );
        assert!(
            projection
                .objects
                .iter()
                .all(|view| matches!(view.lifetime, Lifetime::Live)),
            "rv {rv:#x} ends nothing"
        );
        assert!(joint.has_live_operations(), "rv {rv:#x} keeps S1 live");
    }
}

/// Valid copy/find outputs through seal (finding 3): a valid COPY
/// result mints a distinct incarnation with source-reference (not
/// key-use) accounting; valid FIND lists first-observe unseen keys
/// with unknown birth; established metadata and subsequent keyed uses
/// of each returned object commit. Twins prove removing the output
/// removes the rows. M6/M7 (dropping conversion) must fail here.
#[test]
fn key_operation_lifecycle_copy_find_outputs_through_seal() {
    use crate::semantics_objects::{Birth, CreationFamily, Lifetime, ObjectGap, ViewOrigin};
    const COPY_KEY: u64 = 0xB1B1_B1B1_B1B1_B1B1;
    const FIND_A: u64 = 0xC1C1_C1C1_C1C1_C1C1;
    const FIND_B: u64 = 0xC2C2_C2C2_C2C2_C2C2;
    // Part A: valid COPY through the conversion seam.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Initialize", CkRv::OK.0, 0, 0),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let mut copy = ShapedS1::shaped("C_CopyObject", CkRv::OK.0, 0, 0);
    copy.input0 = Some((CREATED_KEY, 1));
    copy.copy_result = Some(COPY_KEY);
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &copy,
    );
    let projection = scene.model.project();
    assert_eq!(projection.objects.len(), 2, "copy mints a second view");
    let source = projection
        .objects
        .iter()
        .find(|view| matches!(view.origin, ViewOrigin::Created(CreationFamily::Create)))
        .expect("source view stands");
    let copied = projection
        .objects
        .iter()
        .find(|view| matches!(view.origin, ViewOrigin::Created(CreationFamily::Copy)))
        .expect("copy view mints through conversion");
    assert_ne!(source.id, copied.id, "distinct incarnations");
    assert_eq!(source.references, 1, "copy reads its source once");
    assert_eq!(source.key_uses, 0, "copy is not a key use");
    assert!(
        matches!(copied.birth, Birth::Observed { .. }),
        "copy birth is observed"
    );
    assert!(matches!(copied.lifetime, Lifetime::Live));
    // Established metadata on the returned copy, then a keyed use.
    let mut get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    get.input0 = Some((COPY_KEY, 1));
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    // Subsequent keyed use of the returned copy object.
    let mut sign_init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    sign_init.input0 = Some((COPY_KEY, 1));
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &sign_init,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(
        (committed.status, committed.reason),
        (ObsStatus::Populated, "none")
    );
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("copy-key use rows proved");
    assert_eq!((row.started, row.completed), (1, 1));
    assert_eq!(committed.objects.len(), 2);
    // Part B: valid FIND through the seam, then use of a found key.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Initialize", CkRv::OK.0, 0, 0),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_FindObjectsInit", CkRv::OK.0, 0, 0),
    );
    let mut find = ShapedS1::shaped("C_FindObjects", CkRv::OK.0, 0, 0);
    find.find_handles = Some((vec![FIND_A, FIND_B], false));
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &find,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_FindObjectsFinal", CkRv::OK.0, 0, 0),
    );
    let projection = scene.model.project();
    assert_eq!(
        projection.objects.len(),
        3,
        "two found keys first-observe alongside the created one"
    );
    let found: Vec<_> = projection
        .objects
        .iter()
        .filter(|view| matches!(view.origin, ViewOrigin::FirstObserved))
        .collect();
    assert_eq!(found.len(), 2, "both handles first-observe");
    for view in &found {
        assert_eq!(view.birth, Birth::Unknown, "found birth is unknown");
        assert!(matches!(view.lifetime, Lifetime::Live));
    }
    let mut get = ShapedS1 {
        getattr_cells: vec![(1u8, 1u8, 3u16), (2u8, 1u8, 0u16), (5u8, 1u8, 2048u16)],
        ..ShapedS1::shaped("C_GetAttributeValue", CkRv::OK.0, 0, 0)
    };
    get.input0 = Some((FIND_A, 1));
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &get,
    );
    let mut sign_init = ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture());
    sign_init.input0 = Some((FIND_A, 1));
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &sign_init,
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Sign", CkRv::OK.0, 0, op_capture()),
    );
    let committed = commit(2, &[&staging], &scene.model.project(), &keyuse);
    let row = committed
        .key_operations
        .iter()
        .find(|row| row.category == "sign")
        .expect("found-key use rows proved");
    assert_eq!((row.started, row.completed), (1, 1));
    // Part C: find counts 0, 8 and truncated-8 through the seam.
    for (handles, truncated, expect_new, expect_gap) in [
        (vec![], false, 0usize, false),
        (
            vec![
                0xD1D1_D1D1_D1D1_D1D1,
                0xD2D2_D2D2_D2D2_D2D2,
                0xD3D3_D3D3_D3D3_D3D3,
                0xD4D4_D4D4_D4D4_D4D4,
                0xD5D5_D5D5_D5D5_D5D5,
                0xD6D6_D6D6_D6D6_D6D6,
                0xD7D7_D7D7_D7D7_D7D7,
                0xD8D8_D8D8_D8D8_D8D8,
            ],
            false,
            8usize,
            false,
        ),
        (
            vec![
                0xE1E1_E1E1_E1E1_E1E1,
                0xE2E2_E2E2_E2E2_E2E2,
                0xE3E3_E3E3_E3E3_E3E3,
                0xE4E4_E4E4_E4E4_E4E4,
                0xE5E5_E5E5_E5E5_E5E5,
                0xE6E6_E6E6_E6E6_E6E6,
                0xE7E7_E7E7_E7E7_E7E7,
                0xE8E8_E8E8_E8E8_E8E8,
            ],
            true,
            8usize,
            true,
        ),
    ] {
        let mut scene = JointScene::new();
        let bootstrap = scene.bootstrap();
        let mut staging = JointStaging::select_joint(Some(&bootstrap));
        let mut joint = EdgeSemantics::default();
        let mut keyuse = KeyUseReducer::new();
        let mut sink = Vec::new();
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped("C_Initialize", CkRv::OK.0, 0, 0),
        );
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
        );
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &ShapedS1::shaped("C_FindObjectsInit", CkRv::OK.0, 0, 0),
        );
        let gaps_before = scene.model.project().gap(ObjectGap::OutputUnreadable);
        let mut find = ShapedS1::shaped("C_FindObjects", CkRv::OK.0, 0, 0);
        find.find_handles = Some((handles.clone(), truncated));
        drive_quantum(
            &mut scene,
            &mut staging,
            &mut joint,
            &mut keyuse,
            &mut sink,
            &find,
        );
        let projection = scene.model.project();
        assert_eq!(
            projection.objects.len(),
            1 + expect_new,
            "find with {} handles (truncated={truncated})",
            handles.len()
        );
        assert_eq!(
            projection.gap(ObjectGap::OutputUnreadable) > gaps_before,
            expect_gap,
            "truncation gap iff truncated"
        );
    }
    // Part D: unreadable/absent/failed twins invent nothing.
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Initialize", CkRv::OK.0, 0, 0),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    // Unknown copy output.
    let mut copy = ShapedS1::shaped("C_CopyObject", CkRv::OK.0, 0, 0);
    copy.input0 = Some((CREATED_KEY, 1));
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &copy,
    );
    assert_eq!(
        scene.model.project().objects.len(),
        1,
        "unknown copy output mints nothing"
    );
    // Failed copy with a valid result word still mints nothing.
    let mut copy = ShapedS1::shaped("C_CopyObject", CkRv::FUNCTION_FAILED.0, 0, 0);
    copy.input0 = Some((CREATED_KEY, 1));
    copy.copy_result = Some(COPY_KEY);
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &copy,
    );
    assert_eq!(
        scene.model.project().objects.len(),
        1,
        "failed copy mints nothing"
    );
    // Unknown find output.
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_FindObjectsInit", CkRv::OK.0, 0, 0),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_FindObjects", CkRv::OK.0, 0, 0),
    );
    assert_eq!(
        scene.model.project().objects.len(),
        1,
        "unknown find invents nothing"
    );
    // Failed find with valid handles still invents nothing.
    let mut find = ShapedS1::shaped("C_FindObjects", CkRv::FUNCTION_FAILED.0, 0, 0);
    find.find_handles = Some((vec![FIND_A], false));
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &find,
    );
    assert_eq!(
        scene.model.project().objects.len(),
        1,
        "failed find invents nothing"
    );
}

/// Finding 2 — INCOMPLETE (pending 6.04 sealed era issuance):
/// successful finalize ends the old era through its seal; a successor
/// Initialize on the ended domain is refused at conversion — no fresh
/// sealed `init_era` is constructed or propagated here. The old rows
/// stay access-ended, the refused quantum changes nothing, and the
/// commit stays honest. Successful reinitialize through the owning
/// journal/seal is NOT delivered by 607a; see `docs/schema/inventory-v1.md`.
#[test]
fn key_operation_lifecycle_reinitialize_successor_blocked_pending_sealed_era() {
    use crate::semantics_objects::{Lifetime, ObjectGap};
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Initialize", CkRv::OK.0, 0, 0),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_SignInit", CkRv::OK.0, RSA_PKCS, init_capture()),
    );
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_Finalize", CkRv::OK.0, 0, 0),
    );
    let projection = scene.model.project();
    assert!(
        projection
            .objects
            .iter()
            .all(|view| matches!(view.lifetime, Lifetime::AccessEnded(ObjectGap::Finalize))),
        "old era access-ended"
    );
    assert_eq!(projection.objects.len(), 1, "only the old row exists");
    let committed = commit(1, &[&staging], &scene.model.project(), &keyuse);
    assert_eq!(
        (committed.status, committed.reason),
        (ObsStatus::Populated, "none")
    );
    assert_eq!(committed.objects[0].lifetime, "access_ended");
    assert_eq!(committed.objects[0].lifetime_reason, Some("finalize"));
    // A successor Initialize admitted against the ended domain is
    // refused at conversion: nothing joins across the split, and no
    // successor domain is minted here.
    prepare_call(
        &mut scene,
        &mut staging,
        &ShapedS1::shaped("C_Initialize", CkRv::OK.0, 0, 0),
    );
    let failure = scene
        .seal()
        .expect_err("no successor joins across the split");
    assert_eq!(failure.gap, JournalGap::ModelRefused);
    let projection = scene.model.project();
    assert_eq!(
        projection.objects.len(),
        1,
        "the refused quantum mints no successor"
    );
    assert!(
        projection
            .objects
            .iter()
            .all(|view| matches!(view.lifetime, Lifetime::AccessEnded(ObjectGap::Finalize))),
        "the refused quantum changes nothing"
    );
    // Same raw words in a later quantum are likewise refused (the
    // first refusal taints the key, so the second reports taint):
    // old tickets stay stale, never resurrected.
    prepare_call(
        &mut scene,
        &mut staging,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
    );
    let failure = scene.seal().expect_err("old-domain calls stay refused");
    assert_eq!(failure.gap, JournalGap::DomainTainted);
    assert_eq!(
        scene.model.project().objects.len(),
        1,
        "no resurrection under reused words"
    );
}
