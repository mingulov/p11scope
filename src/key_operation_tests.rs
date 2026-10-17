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
    AttestationFixture, COOKIE, ENTRY_NS, EXEC, FLAGS, SESSION, abandon_bytes, begin_bytes_shaped,
    end_bytes, end_bytes_absent, end_bytes_getattr, end_bytes_result, ordinary_for,
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
    OBJECT_ACTION_ACCESS, OBJECT_ACTION_CREATE, OBJECT_ACTION_DESTROY, ObjectDescriptorWire,
    publish_object_descriptors, verify_object_descriptors,
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
    flags: u64,
    /// Input words as (word, status): `Some` overrides the
    /// per-function default (`None` = absent).
    input0: Option<(u64, u8)>,
    input1: Option<(u64, u8)>,
    /// CREATE result word override (`None` = the default key word).
    result: Option<u64>,
    /// GET attribute cells as (kind, status, value).
    getattr_cells: Vec<(u8, u8, u16)>,
}

impl ShapedS1 {
    fn shaped(name: &'static str, rv: u64, mechanism: u64, capture: u32) -> Self {
        let input0 = match name {
            "C_SignInit"
            | "C_VerifyInit"
            | "C_MessageSignInit"
            | "C_DestroyObject"
            | "C_GetAttributeValue" => Some((CREATED_KEY, 1)),
            _ => None,
        };
        Self {
            name,
            rv,
            mechanism,
            capture,
            flags: FLAGS,
            input0,
            input1: None,
            result: None,
            getattr_cells: Vec::new(),
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
    let admitted = scene.fixture.admit_shaped(
        SESSION,
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
        .stage(facts.clone(), origin, position)
        .expect("call stages");
    (facts, position)
}

/// Attest (no stage) + ingest one call: the seal settles a call H9
/// never staged.
fn attest_and_ingest(scene: &mut JointScene, call: &ShapedS1) {
    let admitted = scene.fixture.admit_shaped(
        SESSION,
        call.name,
        call.rv,
        call.mechanism,
        call.capture,
        call.flags,
    );
    scene.adapter.attest_key(&admitted).expect("call attests");
    ingest_call(scene, call);
}

/// Ingest one call's begin/end records.
fn ingest_call(scene: &mut JointScene, call: &ShapedS1) {
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
    assert_eq!(
        scene.ingest(&begin),
        JournalDisposition::BeginAdmitted,
        "{} begin admits",
        call.name
    );
    let end = match call.name {
        "C_CreateObject" => match call.result {
            Some(result) => {
                end_bytes_result(&begin, OBJECT_ACTION_CREATE, call.rv, ENTRY_NS + 50, result)
            }
            None => end_bytes(&begin, OBJECT_ACTION_CREATE, call.rv, ENTRY_NS + 50),
        },
        "C_SignInit" | "C_VerifyInit" | "C_MessageSignInit" | "C_WrapKey" => {
            end_bytes(&begin, OBJECT_ACTION_ACCESS, call.rv, ENTRY_NS + 50)
        }
        "C_DestroyObject" => end_bytes(&begin, OBJECT_ACTION_DESTROY, call.rv, ENTRY_NS + 50),
        "C_GetAttributeValue" => {
            end_bytes_getattr(&begin, call.rv, ENTRY_NS + 50, &call.getattr_cells)
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
/// admitted S1 payload for the direct twin plus its H0 position.
fn prepare_call(
    scene: &mut JointScene,
    staging: &mut JointStaging,
    call: &ShapedS1,
) -> (SemanticCall, u64) {
    let (facts, position) = attest_and_stage(scene, staging, call);
    ingest_call(scene, call);
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
            &mut joint,
            &mut keyuse,
            instance,
            &mut joint_sink,
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
        &mut edge2,
        &mut keyuse,
        instance,
        &mut sink2,
    );
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
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
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
    let mut keyuse = KeyUseReducer::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();
    let mut staged_facts = Vec::new();
    for call in sign_flow().into_iter().take(3) {
        staged_facts.push(prepare_call(&mut scene, &mut staging, &call).0);
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
    let (outcome, refused) = staging.apply_failure(
        &failure,
        &mut pending_source,
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
    );
    assert_eq!(outcome, FailureApplyOutcome::HeldForCompleteness);
    assert_eq!(refused, 0);
    assert_eq!(staging.mode(), FeedMode::Joint);
    assert_eq!(joint.calls(), 0, "nothing reduced before completeness");

    // With the explicit complete stream, retained calls replay once
    // in original order through ordinary S1, then S1Only forever.
    let mut clean_source = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    let (outcome, refused) = staging.apply_failure(
        &failure,
        &mut clean_source,
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
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
        staging.stage(fresh, origin, 99),
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
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
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
    let (outcome, refused) = staging.apply_failure(
        &failure,
        &mut h3,
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
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
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
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
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    assert_eq!(joint.calls(), 1);
    assert_eq!(staging.reduced(), 1);

    // --- A multi-call seal refuses loudly; staging stays intact. ---
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
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
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
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
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
    let (outcome, refused) = staging.apply_failure(
        &failure,
        &mut h3,
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
    );
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
    let mut keyuse = KeyUseReducer::new();
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
    let (outcome, refused) = staging.apply_failure(
        &failure,
        &mut loss_source,
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
    );
    assert_eq!(outcome, FailureApplyOutcome::Degraded { disposed: 2 });
    assert_eq!(refused, 0);
    assert_eq!(staging.history_disposed(), 2);
    assert_eq!(staging.mode(), FeedMode::S1Only);
    assert_eq!(joint.calls(), 0, "loss disposes without reducing");

    // --- Post-degradation outcomes are inert, never touching S1Only. ---
    let calls_before = joint.calls();
    let (outcome, refused) = staging.apply_failure(
        &failure,
        &mut loss_source,
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
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
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
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
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
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
            &mut joint,
            &mut keyuse,
            instance,
            &mut joint_sink,
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
    let mut keyuse = KeyUseReducer::new();
    let mut direct = EdgeSemantics::default();
    let mut direct_sink = Vec::new();
    for call in matrix.iter().take(2) {
        let (facts, _) = prepare_call(&mut scene, &mut staging, call);
        let success = scene.seal().expect("grounding quantum seals");
        let (outcome, _) = staging.apply_seal(
            &success,
            &scene.model,
            &mut joint,
            &mut keyuse,
            instance,
            &mut joint_sink,
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
    let mut clean = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    let (outcome, _) = staging.apply_failure(
        &failure,
        &mut clean,
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
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

// ==================== Checkbox 3: key receipts and rows ====================

use crate::semantics_edge::KeyRole;
use crate::semantics_key_use::{KeyOpRow, KeyUseReducer};

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
    let (outcome, refused) =
        staging.apply_seal(&success, &scene.model, reducer, keyuse, instance, sink);
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne, "{}", call.name);
    assert_eq!(refused, 0);
    (facts, position)
}

/// G11/H9-§1: Joint async flows through the carve-out: the PENDING
/// Init stages and seals (queuing S1-side), while the completion —
/// H8-negative-only, un-ingestable without tainting the image —
/// refuses staging and reduces S1Only-direct. Both feeds agree on
/// S1; the async-started machine rows unknown-key (its inputs never
/// join in the model), with explicit evidence.
#[test]
fn key_operation_joint_async_pending_then_direct_completion() {
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
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
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
        staging.stage(complete.clone(), origin.clone(), 999),
        Err(StagingRefusal::Unsealable)
    );
    let effects_before = joint_sink.len();
    joint.observe_with_effects(&complete, &origin, &mut joint_sink);
    // The direct carve-out has no tee: the driver feeds the new
    // effects to the key-use reducer itself.
    for effect in &joint_sink[effects_before..] {
        keyuse.observe_effect(instance, effect);
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
        &mut joint,
        &mut keyuse,
        instance,
        &mut joint_sink,
    );
    assert_eq!(outcome, SealApplyOutcome::ReplayedOne);
    let origin = EffectOrigin::from(&facts);
    direct.observe_with_effects(&facts, &origin, &mut direct_sink);
    assert_eq!(strip_receipts(&joint_sink), direct_sink);
    assert_eq!((joint.started(), joint.completed()), (1, 1));
    let rows = keyuse.rows();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].keys.is_empty(), "async start binds no receipt");
    assert_eq!(rows[0].outcome, OperationOutcome::Completed);
    assert_eq!(keyuse.evidence().unknown_key_rows, 1);
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

    // Lifetime 1: create, use, destroy.
    drive_quantum(
        &mut scene,
        &mut staging,
        &mut joint,
        &mut keyuse,
        &mut sink,
        &ShapedS1::shaped("C_CreateObject", CkRv::OK.0, 0, 0),
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
    let rows = keyuse.rows();
    assert_eq!(rows.len(), 2, "two completed sign operations");
    assert_eq!(rows[0].keys.len(), 1);
    assert_eq!(rows[1].keys.len(), 1);
    let (key1, key2) = (rows[0].keys[0].key, rows[1].keys[0].key);
    assert_ne!(key1, key2, "colliding lifetimes qualify distinct keys");
    assert_eq!(rows[0].keys[0].role, KeyRole::OperationKey);
    assert_eq!(rows[1].keys[0].role, KeyRole::OperationKey);
    assert_eq!(rows[0].keys[0].position, pos_init1);
    assert_eq!(rows[1].keys[0].position, pos_init2);
    assert_eq!(rows[0].keys[0].metadata.requested_count(), 0);
    assert_eq!(rows[0].outcome, OperationOutcome::Completed);
    assert_eq!(rows[1].outcome, OperationOutcome::Completed);
    // Cross-check against the model's own qualified observations.
    let objects = &scene.model.project().objects;
    assert_eq!(objects.len(), 2);
    assert_eq!(objects[0].lifetime, Lifetime::Destroyed);
    assert_eq!(objects[1].lifetime, Lifetime::Live);
    assert_eq!((objects[0].id, objects[1].id), (key1, key2));
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
    let rows = keyuse.rows();
    assert_eq!(rows.len(), 3);
    let wrap_row = &rows[2];
    assert_eq!(wrap_row.keys.len(), 2);
    assert_eq!(wrap_row.keys[0].role, KeyRole::WrappingKey);
    assert_eq!(wrap_row.keys[1].role, KeyRole::WrappedKey);
    assert_eq!(wrap_row.keys[0].input, 0);
    assert_eq!(wrap_row.keys[1].input, 1);
    assert_ne!(wrap_row.keys[0].key, wrap_row.keys[1].key);
    assert_eq!(wrap_row.keys[0].position, pos_wrap);
    assert_eq!(wrap_row.keys[1].position, pos_wrap);
    assert_eq!(wrap_row.outcome, OperationOutcome::Completed);
    // The receipts name the two created keys in input order (this
    // pins the model's index-order reference emission H9 relies on).
    let objects = &scene.model.project().objects;
    assert_eq!(objects.len(), 4);
    assert_eq!(wrap_row.keys[0].key, objects[2].id);
    assert_eq!(wrap_row.keys[1].key, objects[3].id);
}

/// G11/H9-§3: association failure on effect-neutral calls records
/// unknown-key S1 with explicit evidence (never loss), and
/// requested-only metadata keeps definite operations without values.
#[test]
fn key_operation_unknown_key_and_requested_only() {
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
        &mut joint,
        &mut keyuse,
        instance,
        &mut sink,
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
    let rows = keyuse.rows();
    assert_eq!(rows.len(), 1, "the operation still rows");
    assert!(rows[0].keys.is_empty(), "no key bound");
    assert_eq!(rows[0].outcome, OperationOutcome::Completed);
    assert_eq!(keyuse.evidence().unknown_key_rows, 1);

    // S1Only-direct: no object proof, same unknown-key row.
    let mut direct = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    let mut sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 100);
    feed(&mut direct, &mut sink, &c);
    let c = op("C_Sign", 7, 200);
    feed(&mut direct, &mut sink, &c);
    for effect in &sink {
        keyuse.observe_effect(instance, effect);
    }
    assert_eq!(keyuse.rows().len(), 1);
    assert!(keyuse.rows()[0].keys.is_empty());
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
    let rows = keyuse.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].keys.len(), 1);
    let metadata = rows[0].keys[0].metadata;
    assert_eq!(metadata.requested_count(), 1, "Class was requested");
    assert!(metadata.is_requested(0), "field 0 is Class");
    assert_eq!(metadata.established_count(), 0, "no value ever arrived");
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
    assert_eq!(keyuse.rows().len(), 1);
    let frozen: KeyOpRow = keyuse.rows()[0].clone();
    assert_eq!(frozen.keys.len(), 1);
    // The GET establishes Class=3 after the row completed.
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
    // landed), but the completed row is untouched.
    let key = frozen.keys[0].key;
    let flags = scene
        .model
        .key_metadata_flags(key)
        .expect("key view exists");
    assert_eq!(flags.established_count(), 1, "the GET established Class");
    assert!(flags.is_established(0), "field 0 is Class");
    assert_eq!(keyuse.rows().len(), 1, "the GET rows no operation");
    assert_eq!(keyuse.rows()[0], frozen, "completed rows never rewrite");
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
    assert_eq!(keyuse.rows().len(), 1);
    let frozen: KeyOpRow = keyuse.rows()[0].clone();
    assert_eq!(frozen.keys.len(), 1);
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
    let key = frozen.keys[0].key;
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
    assert_eq!(keyuse.rows().len(), 1, "GETs row no operation");
    assert_eq!(keyuse.rows()[0], frozen, "completed rows never rewrite");
}

/// G11/H9-§3/§91: key-operation rows are bounded (65,536):
/// history is never evicted for a new row. At N+1 the new
/// association is refused — S1 preserved, old rows intact — with
/// explicit PARTIAL evidence, and terminals of refused
/// associations land in fixed counters without allocating rows.
#[test]
fn key_operation_row_retention_bounds() {
    use crate::key_operation_projection::KEY_OP_ROW_CAPACITY;

    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(3);
    let mut edge = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::new();
    assert_eq!(KEY_OP_ROW_CAPACITY, 65_536);
    // Fill exactly to capacity with real direct operations: real
    // identities, real effects, receipt-less rows.
    for n in 0..65_536u64 {
        let mut sink = Vec::new();
        let c = op("C_GenerateKey", 7, 1_000 + n);
        let origin = EffectOrigin::from(&c);
        edge.observe_with_effects(&c, &origin, &mut sink);
        assert_eq!(sink.len(), 1);
        keyuse.observe_effect(instance, &sink[0]);
    }
    assert_eq!(keyuse.rows().len(), KEY_OP_ROW_CAPACITY);
    assert!(!keyuse.evidence().partial, "exact fit is not partial");
    // N+1 refuses: S1 still completes, old rows intact, PARTIAL.
    let completed_before = edge.completed();
    for n in 0..10u64 {
        let mut sink = Vec::new();
        let c = op("C_GenerateKey", 7, 200_000 + n);
        let origin = EffectOrigin::from(&c);
        edge.observe_with_effects(&c, &origin, &mut sink);
        assert_eq!(sink.len(), 1);
        keyuse.observe_effect(instance, &sink[0]);
    }
    assert_eq!(edge.completed(), completed_before + 10, "S1 preserved");
    assert_eq!(keyuse.rows().len(), KEY_OP_ROW_CAPACITY);
    assert_eq!(keyuse.rows()[0].seq, 0, "history never evicted");
    assert_eq!(keyuse.rows().back().unwrap().seq, 65_535);
    let evidence = keyuse.evidence();
    assert!(evidence.partial, "refusal makes coverage PARTIAL");
    assert_eq!(evidence.rows_refused, 10);
    assert_eq!(
        evidence.refused_terminals, 10,
        "refused directs land counted, never rowed"
    );

    // Small-N twin: reservation at start, reserved closes reuse
    // their slot allocation-free, N+1 refuses starts and directs.
    let mut edge = EdgeSemantics::default();
    let mut keyuse = KeyUseReducer::with_capacity(4);
    assert_eq!(keyuse.capacity(), 4, "injected bound");
    for n in 0..3u64 {
        let mut sink = Vec::new();
        let c = op("C_GenerateKey", 7, 300_000 + n);
        let origin = EffectOrigin::from(&c);
        edge.observe_with_effects(&c, &origin, &mut sink);
        keyuse.observe_effect(instance, &sink[0]);
    }
    let mut sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 400_000);
    let origin = EffectOrigin::from(&c);
    edge.observe_joint(&c, &origin, &[], &mut sink);
    for effect in &sink {
        keyuse.observe_effect(instance, effect);
    }
    assert_eq!(keyuse.open().len(), 1, "the start reserved its slot");
    assert!(!keyuse.evidence().partial);
    let mut sink = Vec::new();
    let c = op("C_Sign", 7, 400_001);
    let origin = EffectOrigin::from(&c);
    edge.observe_with_effects(&c, &origin, &mut sink);
    for effect in &sink {
        keyuse.observe_effect(instance, effect);
    }
    assert_eq!(keyuse.rows().len(), 4, "the end reused its slot");
    assert!(keyuse.open().is_empty());
    assert!(!keyuse.evidence().partial, "reserved closes never refuse");
    assert_eq!(keyuse.rows()[3].category, "sign");
    assert_eq!(keyuse.rows()[3].outcome, OperationOutcome::Completed);
    // N+1 from here on: a direct refuses atomically, a refused
    // start's terminal lands counted without a row.
    let mut sink = Vec::new();
    let c = op("C_GenerateKey", 7, 500_000);
    let origin = EffectOrigin::from(&c);
    edge.observe_with_effects(&c, &origin, &mut sink);
    keyuse.observe_effect(instance, &sink[0]);
    assert_eq!(keyuse.evidence().rows_refused, 1);
    assert!(keyuse.evidence().partial);
    let started_before = edge.started();
    let mut sink = Vec::new();
    let c = init("C_SignInit", 7, RSA_PKCS, 500_001);
    let origin = EffectOrigin::from(&c);
    edge.observe_joint(&c, &origin, &[], &mut sink);
    for effect in &sink {
        keyuse.observe_effect(instance, effect);
    }
    assert_eq!(keyuse.evidence().rows_refused, 2);
    assert_eq!(keyuse.refused_opens().len(), 1);
    assert_eq!(
        edge.started(),
        started_before + 1,
        "refused S1 machines still run"
    );
    let completed_before = edge.completed();
    let mut sink = Vec::new();
    let c = op("C_Sign", 7, 500_002);
    let origin = EffectOrigin::from(&c);
    edge.observe_with_effects(&c, &origin, &mut sink);
    for effect in &sink {
        keyuse.observe_effect(instance, effect);
    }
    assert_eq!(keyuse.rows().len(), 4, "refused terminals row nothing");
    assert_eq!(keyuse.evidence().refused_terminals, 2);
    assert!(keyuse.refused_opens().is_empty());
    assert_eq!(
        edge.completed(),
        completed_before + 1,
        "S1 outcomes preserved"
    );
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
            keyuse.observe_effect(s1_instance, effect);
        }
    }
    let mut direct_sink = Vec::new();
    let c = init("C_SignInit", 9, RSA_PKCS, 900_002);
    let origin = EffectOrigin::from(&c);
    s1_edge.observe_with_effects(&c, &origin, &mut direct_sink);
    assert!(!direct_sink.is_empty(), "the unbound start emits");
    for effect in &direct_sink {
        keyuse.observe_effect(s1_instance, effect);
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
            "encapsulate 1/0/0 operations, generate_key 1/0/0 operations, sign 1/0/2 operations, verify 1/1/0 operations, wrap 2/0/0 operations",
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

/// H9-§3: the frozen contract. Rendered sections carry exactly the
/// frozen keys and enums (pinned key-for-key against the schema file
/// and the golden); row equations, sort orders and the no-started
/// unknown rule hold; every vocabulary map is exhaustive; the
/// status matrix, stale publication, sink failure, full-budget
/// terminals and deferred delivery behave exactly.
#[test]
fn key_operation_schema_contract() {
    use crate::key_operation_projection::contract::*;
    use crate::key_operation_projection::producer::{
        gap_label, metadata_field, metadata_label, query_label, role_label,
    };
    use crate::semantics_edge::KeyRole;
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
    assert_eq!(enums("/$defs/role/enum"), table(&ROLE_LABELS));
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
            shape_keyuse.observe_effect(instance, effect);
        }
        let mut end_sink = Vec::new();
        let c = op("C_Sign", 7, 800_005 + n as u64 * 10);
        let origin = EffectOrigin::from(&c);
        shape_edge.observe_with_effects(&c, &origin, &mut end_sink);
        assert_eq!(end_sink.len(), 1);
        for effect in &end_sink {
            shape_keyuse.observe_effect(instance, effect);
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
    // History is immutable: against a model that pruned the object
    // the proved row stays and the dangle is explicit, never silent.
    let pruned_model = JointScene::new().model.project();
    assert!(pruned_model.objects.is_empty());
    let pruned_commit = commit(10, &[&tiny_staging], &pruned_model, &shape_keyuse);
    assert_eq!(
        pruned_commit.key_operations.len(),
        1,
        "the proved row stays"
    );
    let dangle = pruned_commit
        .gaps
        .iter()
        .find(|gap| gap.reason == "pruned_object_referenced")
        .expect("the dangle is explicit");
    assert_eq!(dangle.subject, "key_operation");
    assert_eq!(dangle.repeats, 4);

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
    let failure = SealFailure {
        gap: JournalGap::BootstrapMismatch,
        effects: crate::semantics_objects::ObjectEffects::default(),
        h3_voided: None,
    };
    let clean = H3DispositionEvidence::scripted_clean(u64::MAX);
    let mut h3 = ScriptedH3Source::once(clean);
    let (outcome, _) = fall_staging.apply_failure(
        &failure,
        &mut h3,
        &mut fall_edge,
        &mut fall_keyuse,
        instance,
        &mut fall_sink,
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
    let loss_failure = SealFailure {
        gap: JournalGap::H3Loss,
        effects: crate::semantics_objects::ObjectEffects::default(),
        h3_voided: None,
    };
    // HistoryLoss never consults the finalizer: any scripted source will do.
    let mut loss_h3 = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(u64::MAX));
    let (outcome, _) = loss_staging.apply_failure(
        &loss_failure,
        &mut loss_h3,
        &mut loss_edge,
        &mut loss_keyuse,
        instance,
        &mut loss_sink,
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
    // budgets; refused terminals land counted without rows.
    let mut full_edge = EdgeSemantics::default();
    let mut full_keyuse = KeyUseReducer::with_capacity(2);
    for n in 0..2u64 {
        let mut direct_sink = Vec::new();
        let c = op("C_GenerateKey", 7, 600_000 + n);
        let origin = EffectOrigin::from(&c);
        full_edge.observe_with_effects(&c, &origin, &mut direct_sink);
        full_keyuse.observe_effect(instance, &direct_sink[0]);
    }
    let mut direct_sink = Vec::new();
    let c = op("C_GenerateKey", 7, 600_002);
    let origin = EffectOrigin::from(&c);
    full_edge.observe_with_effects(&c, &origin, &mut direct_sink);
    full_keyuse.observe_effect(instance, &direct_sink[0]);
    assert!(full_keyuse.evidence().partial);
    let partial = commit(4, &[&staging], &scene.model.project(), &full_keyuse);
    assert_eq!(partial.status, ObsStatus::Partial);
    assert_eq!(partial.reason, "row_budget_exhausted");
    assert_eq!(partial.budgets.key_occupied, 2);
    assert_eq!(partial.budgets.key_refused, 1);
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

// ==================== Checkbox 5: ledger, PQC, measurement ====================

/// H9-§4: executed KEM operations stay `role_unavailable` with S1
/// mechanism activity qualified separately: KEM endpoints are
/// negative-only (staging refuses them explicitly — no KEM object
/// read exists to join), while S1Only-direct execution with real PQC
/// mechanism ids advances S1 mechanism counters and outcomes
/// unchanged, and the projection carries no proved rows and no
/// invented object facts.
#[test]
fn key_operation_pqc_matrix_negative() {
    use crate::semantics_key_use::StagingRefusal;

    // KEM never stages: no KEM object descriptor exists, so the
    // frozen endpoint table leaves KEM negative-only (KEM is not
    // even fixture-admittable), and the feed refuses KEM-shaped
    // facts loudly instead of joining thin air.
    let scene = JointScene::new();
    let bootstrap = scene.bootstrap();
    let mut staging = JointStaging::select_joint(Some(&bootstrap));
    for (n, name) in ["C_EncapsulateKey", "C_DecapsulateKey"]
        .into_iter()
        .enumerate()
    {
        let fid = crate::kinds::function_id(name).unwrap();
        assert_eq!(
            crate::semantics_objects::journal::endpoint_class(fid),
            Some(crate::semantics_objects::journal::EndpointClass::NegativeOnlyAffecting),
            "{name} withholds proof: absent prerequisite, explicit"
        );
        let facts = op(name, 9, 700_000 + n as u64);
        let origin = EffectOrigin::from(&facts);
        assert_eq!(
            staging.stage(facts, origin, 100 + n as u64),
            Err(StagingRefusal::Unsealable),
            "{name} is explicitly unstageable"
        );
    }

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
            keyuse.observe_effect(instance, &effect);
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
    let mut row_mechs: Vec<_> = keyuse.rows().iter().map(|row| row.mechanism).collect();
    row_mechs.sort();
    assert_eq!(
        row_mechs,
        vec![
            Some(CKM_ML_KEM_KEY_PAIR_GEN),
            Some(CKM_ML_KEM),
            Some(CKM_ML_KEM)
        ]
    );
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
/// returns verbatim, the null-output size query without its output
/// bit (phase-known). Returns the call's fresh S1 effects.
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
            facts.capture = capture::MECHANISM_NONE;
        }
        facts
    };
    feed(edge, sink, &facts)
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
    // shape, returns verbatim, the null-output size query without
    // its output bit (phase-known). Non-operation calls must emit
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
        // continuations emit nothing; the size-query completion
        // orphans op 1's retry + terminal (counted, never joined).
        let number = call["operation"].as_u64().unwrap();
        let expected = if name == "C_GenerateKeyPair" {
            1
        } else if !name.starts_with("C_Sign") && !name.starts_with("C_Verify") {
            0
        } else {
            match phase {
                "init" | "query" => 1,
                "update" | "too_small" => 0,
                "terminal" if number == 1 => 0,
                "terminal" => 1,
                other => panic!("unknown ledger phase {other}"),
            }
        };
        assert_eq!(fresh.len(), expected, "{name} ({phase}) S1 emission");
        for effect in &fresh {
            keyuse.observe_effect(instance, effect);
        }
    }
    assert_eq!(
        (edge.started(), edge.completed(), edge.failed()),
        (23, 21, 2)
    );
    assert_eq!(
        edge.orphans(),
        2,
        "query completion orphans the retry + terminal"
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

/// H9-§91/§93: retained rows never outgrow the bound, so repeat
/// publication costs identical bytes on every pass: refused input
/// accumulates in scalar counters only, never in rows or render
/// buffers. Three ledger passes share one reducer sized to the
/// first pass (a probe pass learns the exact retained
/// population): later passes refuse everything, the committed
/// summaries stay put, and commit+render allocates exactly the
/// same blocks and bytes on the two refused passes (same status,
/// same digit widths, zero growth).
#[test]
fn key_operation_allocation_pressure_is_bounded_across_passes() {
    let missing = ledger_prerequisites();
    if !missing.is_empty() {
        eprintln!(
            "SKIP key_operation_allocation_pressure_is_bounded_across_passes: missing {}",
            missing.join(", ")
        );
        return;
    }
    let rows = run_rsa_ledger();
    let calls: Vec<_> = rows.iter().filter(|row| row["kind"] == "call").collect();
    assert_eq!(calls.len(), 68, "the fixture's exact API population");
    let instance =
        crate::discovery::caller_registry::instance_input::RegistryInstanceId::from_raw(7);
    let mut probe_edge = EdgeSemantics::default();
    let mut probe_sink = Vec::new();
    let mut probe = KeyUseReducer::new();
    for call in &calls {
        for effect in &replay_ledger_call(&mut probe_edge, &mut probe_sink, call) {
            probe.observe_effect(instance, effect);
        }
    }
    let retained = probe.rows().len();
    assert!(retained > 0, "the ledger retains rows to bound");
    assert_eq!(
        probe.evidence().rows_refused,
        0,
        "the default bound fits one ledger"
    );

    let mut keyuse = KeyUseReducer::with_capacity(retained);
    let mut passes = Vec::new();
    for revision in 1..=3u64 {
        let mut edge = EdgeSemantics::default();
        let mut sink = Vec::new();
        for call in &calls {
            for effect in &replay_ledger_call(&mut edge, &mut sink, call) {
                keyuse.observe_effect(instance, effect);
            }
        }
        assert_eq!(
            keyuse.rows().len(),
            retained,
            "pass {revision}: rows never grow past the bound"
        );
        let model = JointScene::new().model.project();
        let s1only = JointStaging::select_s1_only();
        let ((committed, rendered), blocks, bytes) = crate::test_alloc::count_allocs_during(|| {
            let committed = commit(revision, &[&s1only], &model, &keyuse);
            let rendered =
                serde_json::to_string(&object_observations_json(&committed)).expect("render");
            (committed, rendered)
        });
        assert_eq!(committed.status, ObsStatus::Unavailable);
        assert_eq!(committed.reason, "bootstrap_unavailable");
        assert!(
            blocks > 0 && bytes > 0,
            "pass {revision}: measured, not empty"
        );
        passes.push((committed, rendered, blocks, bytes));
    }
    assert_eq!(
        passes[0].0.budgets.key_refused, 0,
        "the sized bound fits pass one"
    );
    assert!(
        passes[1].0.budgets.key_refused > 0,
        "pass two refuses into scalar counters"
    );
    assert!(
        passes[2].0.budgets.key_refused > passes[1].0.budgets.key_refused,
        "pass three refuses more, still scalar"
    );
    assert_eq!(
        passes[1].0.unknown_key_operations, passes[0].0.unknown_key_operations,
        "refused passes keep the committed summaries"
    );
    assert_eq!(
        passes[2].0.unknown_key_operations, passes[1].0.unknown_key_operations,
        "refused passes keep the committed summaries"
    );
    assert_eq!(
        passes[2].1.len(),
        passes[1].1.len(),
        "refused passes render the same bytes wide"
    );
    assert_eq!(
        (passes[2].2, passes[2].3),
        (passes[1].2, passes[1].3),
        "commit+render allocates identically on refused passes: zero growth"
    );
}
