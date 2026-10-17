//! SPDX-License-Identifier: GPL-3.0-or-later
//! H9 key-operation acceptance tests: operation effects, the single S1
//! feed, positional key roles, metadata timing, bounded projection and
//! output-schema agreement. Reducer/feed/projection behavior is tested
//! through production authority only (real `EdgeSemantics` reducer, real
//! H8 seal ingress, real `Presentation`); reference model constructors
//! appear only where the brief's algorithm twins require them.

use crate::semantics_edge::{
    EdgeSemantics, EffectOrigin, OperationEffect, OperationOutcome, SemanticCall,
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
        } => (id.ordinal_for_test(), category, *mechanism, origin),
        other => panic!("expected DirectCompleted, got {other:?}"),
    }
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
        origin.function, "C_Sign",
        "completion carries the ORIGINAL call identity"
    );
    assert_eq!(edge.completed(), 1);
    assert_eq!(FUNCTION_NONE, p11scope_ebpf_common::FUNCTION_NONE);
}

// ==================== Checkbox 1B: the single S1 feed ====================

use crate::semantics_key_use::{
    FailureApplyOutcome, FeedMode, JointStaging, SealApplyOutcome, StagingRefusal,
};
use crate::semantics_objects::ObjectSemantics;
use crate::semantics_objects::journal::tests::{
    AttestationFixture, COOKIE, ENTRY_NS, EXEC, SESSION, abandon_bytes, begin_bytes_shaped,
    end_bytes, end_bytes_absent, ordinary_for,
};
use crate::semantics_objects::journal::{
    BirthKind, BootstrapReceipt, FaultEpoch, FaultReadError, H3DispositionEvidence, JournalAdapter,
    JournalAuditReceipt, JournalDisposition, JournalDomainProof, JournalGap, JournalIngestItem,
    JournalLimits, ScriptedBirthSource, ScriptedH3Source, SealFailure, SealSuccess,
    SessionBirthEvidence, SessionClosureGrant,
};
use p11scope_ebpf_common::object_journal::{
    JOURNAL_REASON_SYNC_RETURN_RESULT_LOST, decode_journal_record,
};
use p11scope_ebpf_common::object_wire::{
    OBJECT_ACTION_ACCESS, OBJECT_ACTION_CREATE, ObjectDescriptorWire, publish_object_descriptors,
    verify_object_descriptors,
};
use p11scope_ebpf_common::{Event, ImageIdentity, InstanceStamp, MAX_DESCRIPTORS};

/// The H7 fixture's created key word (mirrors the journal's own
/// neutral-history grounding).
const CREATED_KEY: u64 = 0x9090_9090_9090_9090;

struct SteadyFaultCell(u64);

impl FaultEpoch for SteadyFaultCell {
    fn fault_epoch(&self) -> Result<u64, FaultReadError> {
        Ok(self.0)
    }
}

/// One Joint scene: real H3 admissions, real H8 attest/ingest/seal,
/// H9 staging plus the one reducer, and an S1Only direct twin.
struct JointScene {
    adapter: JournalAdapter,
    model: ObjectSemantics,
    descriptors: [ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
    fixture: AttestationFixture,
    proof: JournalDomainProof,
    thread: u64,
    sequence: u64,
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
            H3DispositionEvidence::scripted_clean(self.adapter.consumed_through_for_test()),
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
}

/// One S1-shaped call: admission facts plus matching journal record
/// shape. The journal BEGIN carries the same fingerprint fields as
/// the admission, so H8 attribution is genuine, not staged.
struct ShapedS1 {
    name: &'static str,
    rv: u64,
    mechanism: u64,
    capture: u32,
}

fn init_capture() -> u32 {
    capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL
}

fn op_capture() -> u32 {
    capture::MECHANISM_NONE | capture::OUTPUT_NON_NULL
}

/// Attest + stage one call (no ingest): for correlation twins that
/// stage and ingest different calls.
fn attest_and_stage(
    scene: &mut JointScene,
    staging: &mut JointStaging,
    call: &ShapedS1,
) -> SemanticCall {
    let admitted =
        scene
            .fixture
            .admit_shaped(SESSION, call.name, call.rv, call.mechanism, call.capture);
    scene.adapter.attest_key(&admitted).expect("call attests");
    let facts = admitted.s1_facts().clone();
    let origin = EffectOrigin::from(&facts);
    staging
        .stage(facts.clone(), origin, admitted.h0_ordinal())
        .expect("call stages");
    facts
}

/// Attest (no stage) + ingest one call: the seal settles a call H9
/// never staged.
fn attest_and_ingest(scene: &mut JointScene, call: &ShapedS1) {
    let admitted =
        scene
            .fixture
            .admit_shaped(SESSION, call.name, call.rv, call.mechanism, call.capture);
    scene.adapter.attest_key(&admitted).expect("call attests");
    ingest_call(scene, call);
}

/// Ingest one call's begin/end records.
fn ingest_call(scene: &mut JointScene, call: &ShapedS1) {
    scene.sequence += 1;
    let fid = crate::kinds::function_id(call.name).unwrap();
    let input0 = match call.name {
        "C_SignInit" | "C_VerifyInit" => Some(CREATED_KEY),
        _ => None,
    };
    let begin = begin_bytes_shaped(
        scene.thread,
        scene.sequence,
        fid,
        0,
        (COOKIE, EXEC),
        SESSION,
        call.mechanism,
        call.capture,
        input0,
    );
    assert_eq!(
        scene.ingest(&begin),
        JournalDisposition::BeginAdmitted,
        "{} begin admits",
        call.name
    );
    let end = match call.name {
        "C_CreateObject" => end_bytes(&begin, OBJECT_ACTION_CREATE, call.rv, ENTRY_NS + 50),
        "C_SignInit" | "C_VerifyInit" => {
            end_bytes(&begin, OBJECT_ACTION_ACCESS, call.rv, ENTRY_NS + 50)
        }
        _ => end_bytes_absent(&begin, call.rv, ENTRY_NS + 50),
    };
    assert_eq!(
        scene.ingest(&end),
        JournalDisposition::EndStaged,
        "{} end stages",
        call.name
    );
}

/// Attest + stage + ingest one call's quantum; seal separately so
/// tests drive success and failure arms explicitly. Returns the
/// admitted S1 payload for the direct twin.
fn prepare_call(
    scene: &mut JointScene,
    staging: &mut JointStaging,
    call: &ShapedS1,
) -> SemanticCall {
    let facts = attest_and_stage(scene, staging, call);
    ingest_call(scene, call);
    facts
}

fn sign_flow() -> Vec<ShapedS1> {
    vec![
        ShapedS1 {
            name: "C_CreateObject",
            rv: CkRv::OK.0,
            mechanism: 0,
            capture: 0,
        },
        ShapedS1 {
            name: "C_SignInit",
            rv: CkRv::OK.0,
            mechanism: RSA_PKCS,
            capture: init_capture(),
        },
        ShapedS1 {
            name: "C_Sign",
            rv: CkRv::OK.0,
            mechanism: 0,
            capture: op_capture(),
        },
        ShapedS1 {
            name: "C_VerifyInit",
            rv: CkRv::OK.0,
            mechanism: RSA_PKCS,
            capture: init_capture(),
        },
        ShapedS1 {
            name: "C_Verify",
            rv: CkRv::SIGNATURE_INVALID.0,
            mechanism: 0,
            capture: op_capture(),
        },
        ShapedS1 {
            name: "C_SignMessage",
            rv: CkRv::OK.0,
            mechanism: 0,
            capture: op_capture(),
        },
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
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    assert_eq!(staging.mode(), FeedMode::Joint);
    let mut joint = EdgeSemantics::default();
    let mut joint_sink = Vec::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();

    for call in sign_flow() {
        let facts = prepare_call(&mut scene, &mut staging, &call);
        let success = scene.seal().expect("single-call quantum seals");
        assert_eq!(success.prefix.settled().len(), 1);
        let (outcome, refused) = staging.apply_seal(&success, &mut joint, &mut joint_sink);
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
        assert_eq!(joint_sink, direct_sink, "effect streams match");
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
        s1only.stage(facts.clone(), origin.clone(), 1),
        Err(StagingRefusal::NotJoint)
    );
    // A receipt arriving after S1Only selection changes nothing: no
    // upgrade path exists, and staging still refuses.
    let _late_receipt = scene.bootstrap();
    assert_eq!(s1only.mode(), FeedMode::S1Only);
    assert_eq!(
        s1only.stage(facts, origin, 2),
        Err(StagingRefusal::NotJoint)
    );

    // --- An already-reduced call is never replayed. ---
    let mut scene2 = JointScene::new();
    let bootstrap2 = scene2.bootstrap();
    let mut staging2 = JointStaging::select_joint(Some(&bootstrap2));
    let mut edge2 = EdgeSemantics::default();
    let mut sink2 = Vec::new();
    let facts = prepare_call(
        &mut scene2,
        &mut staging2,
        &ShapedS1 {
            name: "C_CreateObject",
            rv: CkRv::OK.0,
            mechanism: 0,
            capture: 0,
        },
    );
    let success = scene2.seal().expect("quantum seals");
    let (outcome, refused) = staging2.apply_seal(&success, &mut edge2, &mut sink2);
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    assert_eq!(refused, 0);
    // Restaging the same H0 position after reduction refuses.
    let origin = EffectOrigin::from(&facts);
    assert_eq!(
        staging2.stage(facts.clone(), origin.clone(), 1),
        Err(StagingRefusal::ReplayRefused)
    );
    // Staging at or below the consumed frontier refuses even with
    // fresh facts.
    let mut older = facts.clone();
    older.ts_ns += 1;
    assert_eq!(
        staging2.stage(older, origin, 1),
        Err(StagingRefusal::ReplayRefused)
    );
}

/// G11/H9-§1: proof-only refusal falls back once through ordinary S1
/// with an explicit complete H3 stream; real loss invalidates before
/// history-only disposal and starts no old machine.
#[test]
fn key_operation_fallback_and_history_loss() {
    // --- Proof-only refusal: a foreign proof mismatches, H3 is clean. ---
    let mut scene = JointScene::new();
    let mut foreign = JointScene::new();
    let foreign_admitted = foreign.fixture.admit_function("C_SignInit");
    let foreign_proof = foreign
        .adapter
        .attest_key(&foreign_admitted)
        .expect("foreign key attests");
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut joint_sink = Vec::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();
    let mut staged_facts = Vec::new();
    for call in sign_flow().into_iter().take(3) {
        staged_facts.push(prepare_call(&mut scene, &mut staging, &call));
    }
    // Seal under the foreign proof: genuine mismatch, no loss fenced.
    scene.install_closure();
    let foreign_bootstrap = BootstrapReceipt::scripted(
        foreign_proof,
        BirthKind::ExecMarker,
        0,
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
    let fresh = SessionBirthEvidence::scripted_for_receipt(&foreign_bootstrap);
    let cell = SteadyFaultCell(7);
    let mut births = ScriptedBirthSource::once(fresh);
    let failure = scene
        .adapter
        .seal(
            &mut scene.model,
            &audit,
            &foreign_bootstrap,
            frontier,
            &mut births,
            &cell,
        )
        .expect_err("foreign proof mismatches");
    assert_eq!(failure.gap, JournalGap::BootstrapMismatch);

    // Without a complete H3 stream the fallback holds: pending work
    // below the watermark is journal silence, not completeness.
    let mut pending_source = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean_pending(
        u64::MAX,
        Some(1),
    ));
    let (outcome, refused) =
        staging.apply_failure(&failure, &mut pending_source, &mut joint, &mut joint_sink);
    assert_eq!(outcome, FailureApplyOutcome::HeldForCompleteness);
    assert_eq!(refused, 0);
    assert_eq!(staging.mode(), FeedMode::Joint);
    assert_eq!(joint.calls(), 0, "nothing reduced before completeness");

    // With the explicit complete stream, retained calls replay once
    // in original order through ordinary S1, then S1Only forever.
    let mut clean_source = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    let (outcome, refused) =
        staging.apply_failure(&failure, &mut clean_source, &mut joint, &mut joint_sink);
    assert_eq!(outcome, FailureApplyOutcome::FellBack { replayed: 3 });
    assert_eq!(refused, 0);
    assert_eq!(staging.mode(), FeedMode::S1Only);
    for facts in &staged_facts {
        let origin = EffectOrigin::from(facts);
        direct.observe_with_effects(facts, &origin, &mut direct_sink);
    }
    assert_eq!(joint_sink, direct_sink, "fallback equals direct S1");
    assert_s1_equal(&joint, &direct);
    assert_eq!((joint.started(), joint.completed()), (1, 1));
    // Fresh calls after fallback reduce directly, never stage.
    let fresh = SemanticCall {
        function: "C_Sign".into(),
        ..SemanticCall::default()
    };
    let origin = EffectOrigin::from(&fresh);
    assert_eq!(
        staging.stage(fresh, origin, 99),
        Err(StagingRefusal::NotJoint)
    );

    // --- Real loss: the seal-time fault cell moved (native fault). ---
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut joint_sink = Vec::new();
    // One live machine before the loss.
    let live = prepare_call(
        &mut scene,
        &mut staging,
        &ShapedS1 {
            name: "C_SignInit",
            rv: CkRv::OK.0,
            mechanism: RSA_PKCS,
            capture: init_capture(),
        },
    );
    assert!(live.function == "C_SignInit");
    let success = scene.seal().expect("first quantum seals");
    let (outcome, refused) = staging.apply_seal(&success, &mut joint, &mut joint_sink);
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    assert_eq!(refused, 0);
    assert_eq!(joint.started(), 1);
    assert!(joint.has_live_operations());
    // Two more staged, then the fault moves under the seal.
    for call in [
        ShapedS1 {
            name: "C_Sign",
            rv: CkRv::OK.0,
            mechanism: 0,
            capture: op_capture(),
        },
        ShapedS1 {
            name: "C_VerifyInit",
            rv: CkRv::OK.0,
            mechanism: RSA_PKCS,
            capture: init_capture(),
        },
    ] {
        prepare_call(&mut scene, &mut staging, &call);
    }
    let failure = scene
        .seal_with_fault(7, 8)
        .expect_err("moved fault voids the seal");
    assert_eq!(failure.gap, JournalGap::FaultChanged);
    let mut h3 = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    let (outcome, refused) = staging.apply_failure(&failure, &mut h3, &mut joint, &mut joint_sink);
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
    use crate::semantics_key_use::JOINT_STAGING_CAPACITY;

    // --- N/N+1: 1,024 stage, the 1,025th backpressures. ---
    let scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    for position in 1..=JOINT_STAGING_CAPACITY as u64 {
        let facts = SemanticCall {
            function: "C_Sign".into(),
            ts_ns: position,
            ..SemanticCall::default()
        };
        let origin = EffectOrigin::from(&facts);
        staging.stage(facts, origin, position).expect("N stages");
    }
    assert_eq!(staging.staged_len(), JOINT_STAGING_CAPACITY);
    let facts = SemanticCall {
        function: "C_Sign".into(),
        ..SemanticCall::default()
    };
    let origin = EffectOrigin::from(&facts);
    assert_eq!(
        staging.stage(facts, origin, JOINT_STAGING_CAPACITY as u64 + 1),
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
    let call = ShapedS1 {
        name: "C_Sign",
        rv: CkRv::OK.0,
        mechanism: 0,
        capture: op_capture(),
    };
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
    );
    assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
    let success = scene.seal().expect("begin-only quantum seals");
    assert_eq!(success.prefix.settled().len(), 1);
    assert!(success.prefix.settled()[0].end_cut.is_none());
    let (outcome, refused) = staging.apply_seal(&success, &mut joint, &mut sink);
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
    let (outcome, _) = staging.apply_seal(&success, &mut joint, &mut sink);
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    assert_eq!(joint.calls(), 1);
    assert_eq!(staging.reduced(), 1);

    // --- A multi-call seal refuses loudly; staging stays intact. ---
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut sink = Vec::new();
    for call in sign_flow().into_iter().take(2) {
        prepare_call(&mut scene, &mut staging, &call);
    }
    let success = scene.seal().expect("two-call quantum seals");
    assert_eq!(success.prefix.settled().len(), 2);
    let (outcome, refused) = staging.apply_seal(&success, &mut joint, &mut sink);
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
    attest_and_stage(
        &mut scene,
        &mut staging,
        &ShapedS1 {
            name: "C_SignInit",
            rv: CkRv::OK.0,
            mechanism: RSA_PKCS,
            capture: init_capture(),
        },
    );
    attest_and_ingest(
        &mut scene,
        &ShapedS1 {
            name: "C_VerifyInit",
            rv: CkRv::OK.0,
            mechanism: RSA_PKCS,
            capture: init_capture(),
        },
    );
    let success = scene.seal().expect("quantum seals");
    assert_eq!(success.prefix.settled().len(), 1);
    let (outcome, _) = staging.apply_seal(&success, &mut joint, &mut sink);
    assert_eq!(outcome, SealApplyOutcome::Held);
    assert_eq!(staging.correlation_refusals(), 1);
    assert_eq!(staging.staged_len(), 1);
    assert_eq!(joint.calls(), 0);
}

/// G11/H9-§1: transient seal failures retry untouched, H3's own loss
/// degrades, and post-degradation seal outcomes are inert.
#[test]
fn key_operation_joint_retry_and_degraded_inert() {
    // --- H3Pending retries: staging and reducer untouched. ---
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut sink = Vec::new();
    prepare_call(
        &mut scene,
        &mut staging,
        &ShapedS1 {
            name: "C_CreateObject",
            rv: CkRv::OK.0,
            mechanism: 0,
            capture: 0,
        },
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
    let (outcome, refused) = staging.apply_failure(&failure, &mut h3, &mut joint, &mut sink);
    assert_eq!(outcome, FailureApplyOutcome::Retried);
    assert_eq!(refused, 0);
    assert_eq!(staging.mode(), FeedMode::Joint);
    assert_eq!(staging.staged_len(), 1);
    assert_eq!(joint.calls(), 0);

    // --- H3's own loss barrier degrades through the fallback gap. ---
    let mut scene = JointScene::new();
    let mut foreign = JointScene::new();
    let foreign_admitted = foreign.fixture.admit_function("C_SignInit");
    let foreign_proof = foreign
        .adapter
        .attest_key(&foreign_admitted)
        .expect("foreign key attests");
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut sink = Vec::new();
    for call in sign_flow().into_iter().take(2) {
        prepare_call(&mut scene, &mut staging, &call);
    }
    scene.install_closure();
    let foreign_bootstrap = BootstrapReceipt::scripted(
        foreign_proof,
        BirthKind::ExecMarker,
        0,
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
    let fresh = SessionBirthEvidence::scripted_for_receipt(&foreign_bootstrap);
    let cell = SteadyFaultCell(7);
    let mut births = ScriptedBirthSource::once(fresh);
    let failure = scene
        .adapter
        .seal(
            &mut scene.model,
            &audit,
            &foreign_bootstrap,
            frontier,
            &mut births,
            &cell,
        )
        .expect_err("foreign proof mismatches");
    assert_eq!(failure.gap, JournalGap::BootstrapMismatch);
    let mut loss_source = ScriptedH3Source::once(H3DispositionEvidence::scripted_loss(5));
    let (outcome, refused) =
        staging.apply_failure(&failure, &mut loss_source, &mut joint, &mut sink);
    assert_eq!(outcome, FailureApplyOutcome::Degraded { disposed: 2 });
    assert_eq!(refused, 0);
    assert_eq!(staging.history_disposed(), 2);
    assert_eq!(staging.mode(), FeedMode::S1Only);
    assert_eq!(joint.calls(), 0, "loss disposes without reducing");

    // --- Post-degradation outcomes are inert, never touching S1Only. ---
    let calls_before = joint.calls();
    let (outcome, refused) =
        staging.apply_failure(&failure, &mut loss_source, &mut joint, &mut sink);
    assert_eq!(outcome, FailureApplyOutcome::Ignored);
    assert_eq!(refused, 0);
    assert_eq!(joint.calls(), calls_before);
    // A stray seal settling a real call still holds via the mode
    // guard without counting a correlation refusal.
    attest_and_ingest(
        &mut scene,
        &ShapedS1 {
            name: "C_Sign",
            rv: CkRv::OK.0,
            mechanism: 0,
            capture: op_capture(),
        },
    );
    let stray = scene.seal().expect("H8 still seals; H9 no longer consumes");
    assert!(
        !stray.prefix.settled().is_empty(),
        "stray seal settles real calls the degraded feed ignores"
    );
    let (outcome, refused) = staging.apply_seal(&stray, &mut joint, &mut sink);
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
    let mut scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    let mut joint = EdgeSemantics::default();
    let mut joint_sink = Vec::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();
    let call = ShapedS1 {
        name: "C_SignInit",
        rv: CkRv::OK.0,
        mechanism: RSA_PKCS,
        capture: init_capture(),
    };
    let facts = attest_and_stage(&mut scene, &mut staging, &call);
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
    let (outcome, refused) = staging.apply_seal(&success, &mut joint, &mut joint_sink);
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    assert_eq!(refused, 0);
    let origin = EffectOrigin::from(&facts);
    direct.observe_with_effects(&facts, &origin, &mut direct_sink);
    assert_eq!(joint_sink, direct_sink);
    assert_s1_equal(&joint, &direct);
    assert_eq!((joint.started(), joint.completed()), (1, 0));
}
