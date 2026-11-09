//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Actual collected H0, current validation and original prepared admissions.
//! No object bootstrap or ordinary Joint activation is supplied by this seam.

use super::*;
use crate::attach::SessionDrainProducers;
use crate::events::{EventDrain, EventsDomain, ScriptedRecords, record_bytes};
use crate::semantics_objects::journal::joint_driver::{
    IngestedRaw, RawJointQuantum, RawQuantumRefusal,
};
use crate::semantics_objects::journal::tests::{
    ENTRY_NS, KeepupRng, begin_bytes_shaped, end_bytes, end_bytes_absent, function_id,
};
use crate::semantics_objects::journal::{
    AttestationRefusal, H3DispositionEvidence, JournalDomainProof, SessionDrainGrant,
};
use p11scope_ebpf_common::object_journal::{JournalRecord, decode_journal_record};
use p11scope_ebpf_common::object_wire::{OBJECT_ACTION_ACCESS, publish_object_descriptors};

#[path = "joint_audit_handoff.rs"]
mod audit_handoff;
#[path = "joint_audit_fanout.rs"]
mod fanout;

struct JointScene {
    real: RealScene,
    producers: SessionDrainProducers,
    drain: EventDrain<ScriptedRecords>,
    attached: Option<crate::attach::AttachedSemanticSet>,
}

/// Preserve the existing refusal/retry selector and its assertions, now with
/// the original collected ingestion rather than an independent stopped adapter.
pub(super) fn claim_refusal_and_staging_regression() {
    let mut fixture = JointScene::new(1);
    let pid = std::process::id();
    fixture.bind(pid, image(7), &[0]);
    fixture.push(pid, 0, "C_SignInit", 1);
    fixture.push(pid, 0, "C_SignInit", 2);
    let raw = fixture.prepare(2);
    fixture.assert_claims(&[]);
    let (ingested, _) = fixture.ingest(raw);
    let (adapter, model) = fixture.real.scene.coordinator.joint_capture_mut().parts();
    let _ = adapter.stop(model);
    let coordinator = &mut fixture.real.scene.coordinator;
    for ordinal in [1, 2] {
        assert_eq!(
            coordinator
                .claim_next_prepared_admission(&fixture.producers, &ingested)
                .unwrap(),
            Some((ordinal, Err(AttestationRefusal::Stopped)))
        );
        assert_eq!(
            coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test(),
            (0, vec![])
        );
        if ordinal == 1 {
            assert!(
                !coordinator.stage_next_prepared_admission(false, true),
                "all sibling claim decisions precede any original staging move"
            );
        }
    }
    for _ in 0..2 {
        assert!(
            coordinator
                .claim_next_prepared_admission(&fixture.producers, &ingested)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test(),
            (0, vec![])
        );
    }
    assert!(!coordinator.finish_prepared_semantic_batch(&fixture.real.lane));
    assert!(coordinator.stage_next_prepared_admission(false, true));
    assert!(!coordinator.finish_prepared_semantic_batch(&fixture.real.lane));
    assert!(coordinator.stage_next_prepared_admission(false, true));
    assert!(!coordinator.stage_next_prepared_admission(false, true));
    assert!(coordinator.finish_prepared_semantic_batch(&fixture.real.lane));
    coordinator
        .commit_batch_with_semantics(false, Some(&mut fixture.real.lane))
        .unwrap();
    assert_eq!(operation_edge_rows(&fixture.real.scene)[0].0, Some(2));
}

/// Ordinary rows without journal rows: the strict driver still refuses
/// `Admission` (no H8 subject exists for the admission), but staging
/// skips the disposition and stages S1 directly.
#[test]
fn joint_h8_absent_s1only_stages_without_disposition() {
    let mut fixture = JointScene::new(1);
    let pid = std::process::id();
    fixture.bind(pid, image(7), &[0]);
    let descriptors = publish_object_descriptors();
    for sequence in 1..=2u64 {
        let (_, end) = fixture.encoded(pid, 0, "C_SignInit", sequence);
        let payload = match decode_journal_record(&end, &descriptors) {
            Some(JournalRecord::End(end)) => end.payload_base(),
            other => panic!("the shaped END decodes: {other:?}"),
        };
        fixture
            .drain
            .source_mut()
            .push_record(record_bytes(&payload));
    }
    let raw = fixture.prepare(2);
    let (mut ingested, _) = fixture.ingest(raw);
    let coordinator = &mut fixture.real.scene.coordinator;
    while coordinator
        .claim_next_prepared_admission(&fixture.producers, &ingested)
        .unwrap()
        .is_some()
    {}
    let input = {
        let (prepared, _) = coordinator.prepared_joint_parts().unwrap();
        assert!(
            prepared
                .admissions()
                .next()
                .unwrap()
                .joint_resource_origin()
                .is_none(),
            "bare ordinary rows carry no H8 association"
        );
        prepared.admissions().next().unwrap().clone()
    };
    {
        let (_, owner) = coordinator.prepared_joint_parts().unwrap();
        let refusal = match ingested.disposition_s1only_original(
            owner.adapter_mut(),
            &fixture.producers,
            &input,
        ) {
            Ok(_) => panic!("no H8 subject exists for a bare ordinary row"),
            Err(refusal) => refusal,
        };
        assert_eq!(refusal, RawQuantumRefusal::Admission);
        assert_eq!(refusal.code(), "Admission");
    }
    let mut staged = 0;
    while coordinator
        .stage_next_prepared_admission_with_disposition(&fixture.producers, &mut ingested)
        .unwrap()
    {
        staged += 1;
    }
    assert_eq!(staged, 2);
    assert!(coordinator.finish_prepared_semantic_batch(&fixture.real.lane));
}

impl JointScene {
    fn new(providers: usize) -> Self {
        Self::from_held(
            HeldProviders::with_functions(
                providers,
                &["C_SignInit", "C_SignUpdate", "C_SignFinal"],
            ),
            None,
        )
    }

    fn for_audit(providers: usize) -> Self {
        let (held, attached) = HeldProviders::with_attachment(
            providers,
            &["C_SignInit", "C_SignUpdate", "C_SignFinal"],
        );
        Self::from_held(held, Some(attached))
    }

    fn from_held(held: HeldProviders, attach: Option<AttestedSubset>) -> Self {
        let real = RealScene::from_held(held);
        let attached = attach.map(|subset| {
            crate::attach::seal_test_attachment(
                subset,
                real.lane.domain(),
                real.lane.subset().pins(),
            )
        });
        let events = EventsDomain::test_standin(0xb301);
        let producers = SessionDrainProducers::test_pair(real.lane.domain(), events.clone());
        Self {
            real,
            producers,
            // Test-only wire: 8,192 records, so saturation tests can
            // stage multi-quantum backlogs (matches the ScriptedRecords
            // ring window; production EVENTS is 16 MiB).
            drain: EventDrain::over_domain(ScriptedRecords::records([], 8192), events),
            attached,
        }
    }

    fn bind(&mut self, pid: u32, image: ImageIdentity, files: &[u32]) -> CallerId {
        let caller = self.real.bind(pid, image, files[0] as usize);
        self.admit_providers(pid, caller, files);
        caller
    }

    fn admit_providers(&mut self, pid: u32, caller: CallerId, files: &[u32]) {
        for file in files {
            let candidate = self
                .real
                .scene
                .coordinator
                .prepare_legacy_semantic_candidate(caller, self.real.lane.domain())
                .expect("the actual caller retains its original custody");
            assert!(Arc::ptr_eq(
                &candidate.pin(),
                &self.real.h0.0.borrow().io.targets[&pid].0,
            ));
            let slot = self.real.h0.0.borrow().io.slot(*file, "C_SignInit");
            let prepared = self
                .real
                .lane
                .prepare_caller_admission(
                    candidate.pin(),
                    slot,
                    &self.real.modules[*file as usize].0,
                    |bytes| {
                        self.real
                            .scene
                            .coordinator
                            .registry()
                            .reserve_semantic_storage(bytes)
                    },
                )
                .expect("actual H0 receipt and retained provider validate");
            let (receipt, result) = self
                .real
                .scene
                .coordinator
                .consume_semantic_admission(candidate, prepared, None);
            self.real.lane.deliver_admission_receipt(receipt);
            result.expect("the real provider admission consumer accepts this exact file");
            let endpoint = self.real.h0.0.borrow().io.endpoint(slot).unwrap();
            assert!(
                self.real
                    .scene
                    .coordinator
                    .semantic_bindings()
                    .get(caller)
                    .unwrap()
                    .provider_for_endpoint(endpoint)
                    .is_some(),
                "the positive uses actual provider authority, not the legacy reference fallback"
            );
        }
    }

    fn push(&mut self, pid: u32, file: u32, name: &str, sequence: u64) {
        let (begin, end) = self.encoded(pid, file, name, sequence);
        self.drain.source_mut().push_record(begin.to_vec());
        self.drain.source_mut().push_record(end.to_vec());
    }

    /// One original physical pair; future-END tests retain these bytes only
    /// on the fixture stack until the same cursor actually receives END.
    ///
    /// The BEGIN carries the production entry-time words: the safe entry
    /// leaves a mechanism-bearing call at `MECH_NONE` with no mechanism
    /// capture state, and a call with no session argument
    /// (`C_Initialize`, `C_OpenSession`, `C_CloseAllSessions`,
    /// `C_Finalize`) at the absent word 0 with status 0. The END (and
    /// the H0 original decoded from it) carries the return rewrites of
    /// `capture_return_facts`: the mechanism VALUE, `SESSION_NONE` for a
    /// sessionless call and the returned `C_OpenSession` handle.
    fn encoded(&self, pid: u32, file: u32, name: &str, sequence: u64) -> ([u8; 224], [u8; 632]) {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_PAIR;
        use p11scope_ebpf_common::{MECH_NONE, SESSION_NONE};
        let held = self.real.h0.0.borrow();
        let io = &held.io;
        let image = io.targets[&pid].1;
        let slot = io.slot(file, name);
        let endpoint = io.endpoint(slot).unwrap();
        let (base, epoch, _) = io.scan_input(file);
        let init = name == "C_SignInit";
        let pair = name == "C_GenerateKeyPair";
        // The mechanism read at return (CKM_RSA_PKCS_KEY_PAIR_GEN is 0).
        let returned_mechanism = match name {
            "C_SignInit" => Some(0x000d_u64),
            "C_GenerateKeyPair" => Some(0),
            _ => None,
        };
        let sessionless = matches!(
            name,
            "C_Initialize" | "C_OpenSession" | "C_CloseAllSessions" | "C_Finalize"
        );
        let mut begin = begin_bytes_shaped(
            u64::from(pid),
            sequence,
            function_id(name),
            0,
            (image.task_cookie, image.exec_id),
            if sessionless { 0 } else { 7 },
            if returned_mechanism.is_some() {
                MECH_NONE
            } else {
                0
            },
            capture::OUTPUT_NON_NULL | capture::MECHANISM_NONE,
            init.then_some((9, 1)),
            None,
            0,
        );
        if sessionless {
            // H7 absent session: word 0, status 0.
            begin[125] = 0;
        }
        begin[24..32].copy_from_slice(&((u64::from(pid) << 32) | u64::from(pid)).to_le_bytes());
        begin[48..56].copy_from_slice(&(sequence * 1_000).to_le_bytes());
        begin[56..64].copy_from_slice(&(base + endpoint.offset).to_le_bytes());
        begin[64..68].copy_from_slice(&epoch.to_le_bytes());
        begin[68..72].fill(0);
        begin[72..76].copy_from_slice(&(io.script.last_health.fault as u32).to_le_bytes());
        begin[76..78].copy_from_slice(&((file + 1) as u16).to_le_bytes());
        begin[104..108].copy_from_slice(&slot.to_le_bytes());
        // The original END retains this START's exact physical interval.
        let end = if name == "C_CreateObject" {
            end_bytes(
                &begin,
                p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE,
                0,
                ENTRY_NS + 10,
            )
        } else if init {
            end_bytes(&begin, OBJECT_ACTION_ACCESS, 0, ENTRY_NS + 10)
        } else if pair {
            let mut end = end_bytes(&begin, OBJECT_ACTION_PAIR, 0, ENTRY_NS + 10);
            // Two VALUE result handles (public, private), distinct per call.
            end[424..432].copy_from_slice(&(0x9100 + 2 * sequence).to_le_bytes());
            end[432..440].copy_from_slice(&(0x9101 + 2 * sequence).to_le_bytes());
            end[506] = 1;
            end[507] = 1;
            end
        } else {
            end_bytes_absent(&begin, 0, ENTRY_NS + 10)
        };
        // The return rewrites at the END event's session (24 + 32),
        // mechanism (24 + 48) and capture (24 + 280) offsets.
        let mut end = end;
        if let Some(mechanism) = returned_mechanism {
            end[72..80].copy_from_slice(&mechanism.to_le_bytes());
            end[304..308].copy_from_slice(
                &(capture::OUTPUT_NON_NULL | capture::MECHANISM_VALUE).to_le_bytes(),
            );
        }
        if sessionless {
            let returned = if name == "C_OpenSession" {
                7
            } else {
                SESSION_NONE
            };
            end[56..64].copy_from_slice(&returned.to_le_bytes());
        }
        (begin, end)
    }

    fn prepare(&mut self, count: usize) -> RawJointQuantum {
        self.prepare_with_fault(count, &BirthFault)
    }

    fn prepare_with_fault(
        &mut self,
        count: usize,
        fault: &impl crate::semantics_objects::journal::FaultEpoch,
    ) -> RawJointQuantum {
        let raw = self.collect_with_fault(fault);
        assert_eq!(
            raw.h0_input(self.real.lane.domain(), 64).unwrap().0.len(),
            count
        );
        self.real.h0.0.borrow_mut().collected = Some(raw);
        let batch = self.real.tick();
        self.prepare_batch(batch, count);
        self.real.h0.0.borrow_mut().collected.take().unwrap()
    }

    fn collect_with_fault(
        &mut self,
        fault: &impl crate::semantics_objects::journal::FaultEpoch,
    ) -> RawJointQuantum {
        let reserve = self
            .real
            .scene
            .coordinator
            .registry()
            .semantic_storage_reserver();
        RawJointQuantum::collect_bounded_with_adapter(
            &mut self.drain,
            &publish_object_descriptors(),
            64,
            None,
            fault,
            &self.producers,
            |bytes| reserve.reserve(bytes),
            self.real
                .scene
                .coordinator
                .joint_capture_mut()
                .adapter_mut(),
        )
        .expect("actual persistent cursor collection")
    }

    fn prepare_batch(&mut self, batch: SemanticBatch, count: usize) {
        assert_eq!(self.real.h0.0.borrow().last_calls.len(), count);
        self.real.scene.coordinator.stage_semantic_batch(batch);
        self.real
            .scene
            .coordinator
            .prepare_staged_semantic_batch(&mut self.real.lane, None)
            .unwrap();
        assert_eq!(
            self.real
                .scene
                .coordinator
                .prepared_semantic_batch()
                .unwrap()
                .admissions()
                .count(),
            count,
            "every physical original survived actual H0 and current receipt validation"
        );
    }

    fn ingest(&mut self, raw: RawJointQuantum) -> (IngestedRaw, JournalDomainProof) {
        let (ingested, proof, _) = self.ingest_with_grant(raw);
        (ingested, proof)
    }

    fn ingest_with_grant(
        &mut self,
        raw: RawJointQuantum,
    ) -> (IngestedRaw, JournalDomainProof, SessionDrainGrant) {
        let (prepared, owner) = self.real.scene.coordinator.prepared_joint_parts().unwrap();
        let before = owner.adapter().invocation_claims_for_test();
        let input = prepared.next_admission().unwrap();
        let proof = owner.adapter_mut().bind_admitted_key(input).unwrap();
        let grant = SessionDrainGrant::observe(&self.producers, input).unwrap();
        owner.adapter_mut().bind_session_drain(&grant).unwrap();
        let ingested = raw
            .ingest(owner.adapter_mut(), &self.producers, &grant)
            .unwrap_or_else(|(_, reason)| panic!("original ingestion: {reason:?}"));
        assert_eq!(
            owner.adapter().invocation_claims_for_test(),
            before,
            "initial key binding and original raw ingestion grant no invocation claims"
        );
        (ingested, proof, grant)
    }

    fn assert_claims(&self, expected: &[(u64, JournalDomainProof)]) {
        let (count, originals) = self
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test();
        assert_eq!(count, expected.len(), "canonical adapter claim census");
        assert_eq!(
            originals.as_slice(),
            expected,
            "actual stored original ordinals and keys"
        );
    }

    fn finish(&mut self, count: usize, maximum: u64) {
        for _ in 0..count {
            assert!(
                self.real
                    .scene
                    .coordinator
                    .stage_next_prepared_admission(false, true)
            );
        }
        assert!(
            !self
                .real
                .scene
                .coordinator
                .stage_next_prepared_admission(false, true)
        );
        assert!(
            self.real
                .scene
                .coordinator
                .finish_prepared_semantic_batch(&self.real.lane)
        );
        assert!(
            !self
                .real
                .scene
                .coordinator
                .finish_prepared_semantic_batch(&self.real.lane)
        );
        assert!(matches!(
            self.real.scene.coordinator.take_h3_disposition(),
            H3DispositionEvidence::Clean { staged_max, pending_floor: None } if staged_max == maximum
        ));
        self.real
            .scene
            .coordinator
            .commit_batch_with_semantics(false, Some(&mut self.real.lane))
            .unwrap();
    }
}

#[test]
fn joint_prepared_all_originals_claim_after_actual_ingest_once() {
    let mut fixture = JointScene::new(1);
    let pid = std::process::id();
    fixture.bind(pid, image(7), &[0]);
    for (sequence, function) in ["C_SignInit", "C_SignUpdate", "C_SignUpdate", "C_SignFinal"]
        .into_iter()
        .enumerate()
    {
        fixture.push(pid, 0, function, sequence as u64 + 1);
    }
    let raw = fixture.prepare(4);
    fixture.assert_claims(&[]);
    let originals: Vec<_> = fixture
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap()
        .admissions()
        .map(|input| (input.h0_ordinal(), input.s1_facts().function.clone()))
        .collect();
    assert_eq!(
        originals,
        [
            (1, "C_SignInit"),
            (2, "C_SignUpdate"),
            (3, "C_SignUpdate"),
            (4, "C_SignFinal")
        ]
        .map(|(at, name)| (at, name.to_owned()))
    );
    assert!(
        !fixture
            .real
            .scene
            .coordinator
            .stage_next_prepared_admission(false, true)
    );
    assert!(
        !fixture
            .real
            .scene
            .coordinator
            .finish_prepared_semantic_batch(&fixture.real.lane)
    );
    assert!(matches!(
        fixture.real.scene.coordinator.take_h3_disposition(),
        H3DispositionEvidence::Clean {
            staged_max: 0,
            pending_floor: None
        }
    ));
    let (ingested, proof) = fixture.ingest(raw);
    fixture.assert_claims(&[]);
    for ordinal in 1..=4 {
        let (actual, claim) = fixture
            .real
            .scene
            .coordinator
            .claim_next_prepared_admission(&fixture.producers, &ingested)
            .unwrap()
            .expect("one original claim");
        assert_eq!(actual, ordinal);
        assert_eq!(claim, Ok(proof));
        fixture.assert_claims(
            &(1..=ordinal)
                .map(|original| (original, proof))
                .collect::<Vec<_>>(),
        );
        assert!(
            !fixture
                .real
                .scene
                .coordinator
                .finish_prepared_semantic_batch(&fixture.real.lane)
        );
        if ordinal != 4 {
            assert!(
                !fixture
                    .real
                    .scene
                    .coordinator
                    .stage_next_prepared_admission(false, true),
                "no original stages before all sibling claim decisions"
            );
        }
    }
    for _ in 0..2 {
        assert!(
            fixture
                .real
                .scene
                .coordinator
                .claim_next_prepared_admission(&fixture.producers, &ingested)
                .unwrap()
                .is_none()
        );
        fixture.assert_claims(
            &(1..=4)
                .map(|original| (original, proof))
                .collect::<Vec<_>>(),
        );
    }
    fixture.finish(4, 4);
    assert_eq!(
        operation_edge_rows(&fixture.real.scene),
        vec![(Some(4), 0, false, 1, 1)]
    );
}

#[test]
fn joint_prepared_foreign_or_old_raw_proof_never_advances_claim_cursor() {
    let mut fixture = JointScene::new(1);
    let pid = std::process::id();
    fixture.bind(pid, image(7), &[0]);
    fixture.push(pid, 0, "C_SignInit", 1);
    let raw = fixture.prepare(1);
    fixture.assert_claims(&[]);
    let (first, proof) = fixture.ingest(raw);
    fixture.assert_claims(&[]);
    let foreign = SessionDrainProducers::test_pair(
        fixture.producers.native_domain(),
        EventsDomain::test_standin(fixture.producers.events_id()),
    );
    for _ in 0..2 {
        assert_eq!(
            fixture
                .real
                .scene
                .coordinator
                .claim_next_prepared_admission(&foreign, &first),
            Err(RawQuantumRefusal::ForeignCapture)
        );
        fixture.assert_claims(&[]);
    }
    assert_eq!(
        fixture
            .real
            .scene
            .coordinator
            .prepared_semantic_batch()
            .unwrap()
            .next_admission()
            .unwrap()
            .h0_ordinal(),
        1
    );
    assert!(
        !fixture
            .real
            .scene
            .coordinator
            .stage_next_prepared_admission(false, true)
    );
    assert_eq!(
        fixture
            .real
            .scene
            .coordinator
            .claim_next_prepared_admission(&fixture.producers, &first)
            .unwrap(),
        Some((1, Ok(proof)))
    );
    fixture.assert_claims(&[(1, proof)]);
    fixture.finish(1, 1);

    fixture.push(pid, 0, "C_SignUpdate", 2);
    let next_raw = fixture.prepare(1);
    // The old proof still has the adapter's current frontier here. Only its
    // actual original allocation distinguishes this later prepared sibling.
    assert_eq!(
        first.validate_owner(
            fixture.real.scene.coordinator.joint_capture().adapter(),
            &fixture.producers
        ),
        Ok(())
    );
    for _ in 0..2 {
        assert_eq!(
            fixture
                .real
                .scene
                .coordinator
                .claim_next_prepared_admission(&fixture.producers, &first),
            Err(RawQuantumRefusal::Admission)
        );
        fixture.assert_claims(&[(1, proof)]);
    }
    let (next, next_proof) = fixture.ingest(next_raw);
    for _ in 0..2 {
        assert_eq!(
            fixture
                .real
                .scene
                .coordinator
                .claim_next_prepared_admission(&fixture.producers, &first),
            Err(RawQuantumRefusal::StaleFrontier)
        );
        fixture.assert_claims(&[(1, proof)]);
    }
    assert_eq!(
        fixture
            .real
            .scene
            .coordinator
            .prepared_semantic_batch()
            .unwrap()
            .next_admission()
            .unwrap()
            .h0_ordinal(),
        2
    );
    assert!(
        !fixture
            .real
            .scene
            .coordinator
            .stage_next_prepared_admission(false, true)
    );
    assert_eq!(
        fixture
            .real
            .scene
            .coordinator
            .claim_next_prepared_admission(&fixture.producers, &next)
            .unwrap(),
        Some((2, Ok(next_proof)))
    );
    fixture.assert_claims(&[(1, proof), (2, next_proof)]);
    for _ in 0..2 {
        assert!(
            fixture
                .real
                .scene
                .coordinator
                .claim_next_prepared_admission(&fixture.producers, &next)
                .unwrap()
                .is_none()
        );
        fixture.assert_claims(&[(1, proof), (2, next_proof)]);
    }
    fixture.finish(1, 2);
    assert_eq!(
        operation_edge_rows(&fixture.real.scene),
        vec![(Some(2), 0, false, 1, 0)]
    );
}

#[test]
fn joint_prepared_claims_every_adjacent_provider_and_caller_original() {
    use crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild;
    let child = OwnedStoppedChild::new();
    let pid = std::process::id();
    let mut fixture = JointScene::new(2);
    fixture.bind(pid, image(7), &[0, 1]);
    fixture.bind(child.id(), image(8), &[1]);
    fixture.push(pid, 0, "C_SignInit", 1);
    fixture.push(pid, 1, "C_SignInit", 2);
    fixture.push(child.id(), 1, "C_SignInit", 1);
    let raw = fixture.prepare(3);
    fixture.assert_claims(&[]);
    let (ingested, first_proof) = fixture.ingest(raw);
    fixture.assert_claims(&[]);
    let mut proofs = Vec::new();
    for ordinal in 1..=3 {
        let (actual, proof) = fixture
            .real
            .scene
            .coordinator
            .claim_next_prepared_admission(&fixture.producers, &ingested)
            .unwrap()
            .expect("actual provider/caller admission");
        assert_eq!(actual, ordinal);
        proofs.push(proof.unwrap());
        fixture.assert_claims(
            &proofs
                .iter()
                .enumerate()
                .map(|(at, proof)| (at as u64 + 1, *proof))
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(proofs[0], first_proof);
    assert_ne!(
        proofs[0], proofs[1],
        "adjacent provider keeps its actual router key"
    );
    assert_ne!(proofs[1], proofs[2], "the next actual caller keeps its key");
    assert!(
        fixture
            .real
            .scene
            .coordinator
            .claim_next_prepared_admission(&fixture.producers, &ingested)
            .unwrap()
            .is_none()
    );
    fixture.assert_claims(&[(1, proofs[0]), (2, proofs[1]), (3, proofs[2])]);
    fixture.finish(3, 3);
    let rows = operation_edge_rows(&fixture.real.scene);
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|row| *row == (Some(1), 0, false, 1, 0)));
}

#[test]
fn joint_prepared_key_binding_alone_does_not_claim_original() {
    let mut fixture = JointScene::new(1);
    let pid = std::process::id();
    fixture.bind(pid, image(7), &[0]);
    fixture.push(pid, 0, "C_SignInit", 1);
    let raw = fixture.prepare(1);
    fixture.assert_claims(&[]);
    let (ingested, bound) = fixture.ingest(raw);
    for _ in 0..2 {
        let (prepared, owner) = fixture
            .real
            .scene
            .coordinator
            .prepared_joint_parts()
            .unwrap();
        assert_eq!(
            owner
                .adapter_mut()
                .bind_admitted_key(prepared.next_admission().unwrap()),
            Ok(bound),
            "the actual key-only port returns the same proof without claiming"
        );
        fixture.assert_claims(&[]);
        assert!(
            !fixture
                .real
                .scene
                .coordinator
                .stage_next_prepared_admission(false, true)
        );
        assert!(
            !fixture
                .real
                .scene
                .coordinator
                .finish_prepared_semantic_batch(&fixture.real.lane)
        );
    }
    assert_eq!(
        fixture
            .real
            .scene
            .coordinator
            .claim_next_prepared_admission(&fixture.producers, &ingested)
            .unwrap(),
        Some((1, Ok(bound)))
    );
    fixture.assert_claims(&[(1, bound)]);
    for _ in 0..2 {
        assert!(
            fixture
                .real
                .scene
                .coordinator
                .claim_next_prepared_admission(&fixture.producers, &ingested)
                .unwrap()
                .is_none()
        );
        fixture.assert_claims(&[(1, bound)]);
    }
    fixture.finish(1, 1);
    assert_eq!(operation_edge_rows(&fixture.real.scene)[0].0, Some(1));
}

/// One modeled call as a bare ordinary row: the END payload of a
/// shaped pair, without its journal BEGIN. A drain fed only these
/// rows stages no journal opens: the feed-less session shape.
fn push_bare_sign_init(fixture: &mut JointScene, pid: u32, sequence: u64) {
    push_bare_call(fixture, pid, "C_SignInit", sequence);
}

/// One modeled call as a bare ordinary row for any held function.
fn push_bare_call(fixture: &mut JointScene, pid: u32, name: &str, sequence: u64) {
    let (_, end) = fixture.encoded(pid, 0, name, sequence);
    let payload = match decode_journal_record(&end, &publish_object_descriptors()) {
        Some(JournalRecord::End(end)) => end.payload_base(),
        other => panic!("the shaped END decodes: {other:?}"),
    };
    fixture
        .drain
        .source_mut()
        .push_record(record_bytes(&payload));
}

/// Feed-less bench: an unlinked session (no journal BEGIN feed) over
/// bare ordinary rows. Past the 2048-entry claim store the per-claim
/// cost must stay flat: no prune work is billed and no claim is
/// refused, because a session that can never stage a BEGIN can never
/// consume a fingerprint claim.
#[test]
fn joint_keepup_feedless_claim_cost_flat_past_cap() {
    const PER_QUANTUM: usize = 64;
    const QUANTA: usize = 33;
    const TOTAL: usize = PER_QUANTUM * QUANTA;
    const {
        assert!(TOTAL > 2_048, "the bench must cross the claim cap");
    }
    let mut fixture = JointScene::new(1);
    let events = fixture.drain.consumption_cut().unwrap().events().clone();
    fixture.producers =
        SessionDrainProducers::test_pair_unlinked(fixture.real.lane.domain(), events);
    assert!(
        !fixture.producers.journal_linked(),
        "the bench session links no journal producer"
    );
    let pid = std::process::id();
    fixture.bind(pid, image(7), &[0]);
    let mut sequence = 0u64;
    let mut total_ok = 0usize;
    let mut total_err = 0usize;
    for _ in 0..QUANTA {
        // The scripted drain counts takes against its bound for the
        // whole scene, not per quantum: cover this quantum's rows.
        fixture.drain.source_mut().bound += PER_QUANTUM;
        for _ in 0..PER_QUANTUM {
            sequence += 1;
            push_bare_sign_init(&mut fixture, pid, sequence);
        }
        let raw = fixture.prepare(PER_QUANTUM);
        let (ingested, _) = fixture.ingest(raw);
        {
            let coordinator = &mut fixture.real.scene.coordinator;
            while let Some((_, claim)) = coordinator
                .claim_next_prepared_admission(&fixture.producers, &ingested)
                .unwrap()
            {
                if claim.is_ok() {
                    total_ok += 1;
                } else {
                    total_err += 1;
                }
            }
        }
        fixture.finish(PER_QUANTUM, sequence);
    }
    assert_eq!(total_ok + total_err, TOTAL, "every modeled call is claimed");
    assert_eq!(
        total_err, 0,
        "feed-less claims are never billed past the cap"
    );
    assert_eq!(total_ok, TOTAL);
    let adapter = fixture.real.scene.coordinator.joint_capture().adapter();
    assert!(
        adapter.retained_starts_for_test().is_empty(),
        "bare rows stage no journal BEGINs"
    );
    assert_eq!(
        adapter.invocation_claims_for_test().0,
        0,
        "no claim-store growth without a feed"
    );
    assert_eq!(
        adapter.test_claim_costs_for_test(),
        (0, 0, 0),
        "no fingerprint-claim work without a feed"
    );
}

/// One unlinked joint scene: the session links no journal producer,
/// so its drain can never carry a journal BEGIN feed.
fn unlinked_feedless_scene() -> JointScene {
    let mut fixture = JointScene::new(1);
    let events = fixture.drain.consumption_cut().unwrap().events().clone();
    fixture.producers =
        SessionDrainProducers::test_pair_unlinked(fixture.real.lane.domain(), events);
    assert!(
        !fixture.producers.journal_linked(),
        "the differential session links no journal producer"
    );
    fixture
}

/// Public outputs of one feed-less quantum: joins, gaps, counts and
/// staged edges. Claim results ride along for the below-cap exact
/// comparison; the claim store itself is excluded by design.
struct FeedlessQuantumView {
    admissions: Vec<(u64, String)>,
    claims: Vec<(u64, Result<JournalDomainProof, AttestationRefusal>)>,
    births_installed: usize,
    staged: usize,
    h3_max: u64,
    h3_floor: Option<u64>,
    revision: u64,
    gaps: Vec<crate::discovery::caller_registry::RegistryGap>,
    repeats: Vec<u64>,
    feeds: usize,
    edges: Vec<(Option<u64>, u64, bool, u64, u64)>,
}

/// Run one feed-less quantum on one arm through the production
/// phase order (claim, births, staging with disposition, finish,
/// commit) and snapshot its public outputs.
fn run_feedless_quantum(
    arm: &mut JointScene,
    calls: &[(&str, u64)],
    legacy_claims: bool,
) -> FeedlessQuantumView {
    use crate::inventory_semantics::RetainedJointBirths;

    arm.drain.source_mut().bound += calls.len();
    let pid = std::process::id();
    for (name, sequence) in calls {
        push_bare_call(arm, pid, name, *sequence);
    }
    let raw = arm.prepare(calls.len());
    if legacy_claims {
        arm.real
            .scene
            .coordinator
            .set_prepared_legacy_claims_for_test(true);
    }
    let (mut ingested, _) = arm.ingest(raw);
    let admissions: Vec<(u64, String)> = arm
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap()
        .admissions()
        .map(|input| (input.h0_ordinal(), input.s1_facts().function.clone()))
        .collect();
    let mut claims = Vec::new();
    {
        let coordinator = &mut arm.real.scene.coordinator;
        while let Some((ordinal, claim)) = coordinator
            .claim_next_prepared_admission(&arm.producers, &ingested)
            .unwrap()
        {
            claims.push((ordinal, claim));
        }
    }
    {
        // Every recorded Ok proof binds its exact admission: the
        // skip arm's bind-only proof is genuine, not manufactured.
        let prepared = arm
            .real
            .scene
            .coordinator
            .prepared_semantic_batch()
            .unwrap();
        for (ordinal, result) in &claims {
            if let Ok(proof) = result {
                let input = prepared
                    .admissions()
                    .find(|input| input.h0_ordinal() == *ordinal)
                    .expect("a claimed ordinal was admitted");
                assert!(
                    proof.matches_admitted(input),
                    "the recorded proof binds its exact admission"
                );
            }
        }
    }
    let mut births = RetainedJointBirths::new();
    let disposition = arm
        .real
        .scene
        .coordinator
        .prepare_joint_births(
            &ingested,
            &arm.producers,
            &mut births,
            |_, _, _, _, _, _| panic!("unlinked births never reach native consume"),
        )
        .unwrap();
    let mut staged = 0usize;
    {
        let coordinator = &mut arm.real.scene.coordinator;
        while coordinator
            .stage_next_prepared_admission_with_disposition(&arm.producers, &mut ingested)
            .unwrap()
        {
            staged += 1;
        }
    }
    assert!(
        arm.real
            .scene
            .coordinator
            .finish_prepared_semantic_batch(&arm.real.lane)
    );
    let (h3_max, h3_floor) = match arm.real.scene.coordinator.take_h3_disposition() {
        H3DispositionEvidence::Clean {
            staged_max,
            pending_floor,
        } => (staged_max, pending_floor),
        other => panic!("the feed-less quantum stages clean H3, not {other:?}"),
    };
    arm.real
        .scene
        .coordinator
        .commit_batch_with_semantics(false, Some(&mut arm.real.lane))
        .unwrap();
    let registry = arm.real.scene.coordinator.registry();
    FeedlessQuantumView {
        admissions,
        claims,
        births_installed: disposition.installed,
        staged,
        h3_max,
        h3_floor,
        revision: registry.published_revision(),
        gaps: registry.gaps().to_vec(),
        repeats: registry.gap_repeats().to_vec(),
        feeds: registry.joint_feeds(),
        edges: operation_edge_rows(&arm.real.scene),
    }
}

/// Differential over randomized feed-less sequences: the legacy arm
/// files fingerprint claims (the old path, forced per batch) while
/// the skip arm binds keys only. Joins, gaps, counts and staged
/// edges must match every quantum; only the claim store diverges.
/// `fixed_count` pins the quantum size for the past-cap leg.
fn feedless_differential_sequences(seed: u64, quanta: usize, fixed_count: Option<usize>) {
    let mut legacy = unlinked_feedless_scene();
    let mut skipped = unlinked_feedless_scene();
    let pid = std::process::id();
    legacy.bind(pid, image(7), &[0]);
    skipped.bind(pid, image(7), &[0]);
    let mut rng = KeepupRng::new(seed);
    let mut sequence = 0u64;
    let mut total = 0usize;
    for quantum in 0..quanta {
        let count = fixed_count.unwrap_or_else(|| 1 + rng.below(64) as usize);
        let mut calls = Vec::with_capacity(count);
        for _ in 0..count {
            sequence += 1;
            let name = match rng.below(3) {
                0 => "C_SignInit",
                1 => "C_SignUpdate",
                _ => "C_SignFinal",
            };
            calls.push((name, sequence));
        }
        let old = run_feedless_quantum(&mut legacy, &calls, true);
        let new = run_feedless_quantum(&mut skipped, &calls, false);
        assert_eq!(
            new.admissions, old.admissions,
            "seed {seed} quantum {quantum}: identical admissions"
        );
        assert_eq!(
            new.claims.len(),
            old.claims.len(),
            "seed {seed} quantum {quantum}: every admission is claimed on both arms"
        );
        for (index, ((at_old, res_old), (at_new, res_new))) in
            old.claims.iter().zip(new.claims.iter()).enumerate()
        {
            assert_eq!(
                at_new, at_old,
                "seed {seed} quantum {quantum}: identical claim ordinals"
            );
            // Proofs bind their own session's domain, so only the
            // result shapes compare across arms; within-arm proof
            // genuineness is pinned at claim time above.
            if total + index < 5_120 {
                assert!(
                    res_old.is_ok() && res_new.is_ok(),
                    "seed {seed} quantum {quantum}: below-cap claims succeed on both arms"
                );
            } else {
                assert_eq!(
                    *res_old,
                    Err(AttestationRefusal::ClaimsExhausted),
                    "seed {seed} quantum {quantum}: the legacy arm bills past the cap"
                );
                assert!(
                    res_new.is_ok(),
                    "seed {seed} quantum {quantum}: the skip arm never bills"
                );
            }
        }
        total += count;
        assert_eq!(
            new.births_installed, 0,
            "seed {seed} quantum {quantum}: the skip arm installs no births"
        );
        assert_eq!(
            new.births_installed, old.births_installed,
            "seed {seed} quantum {quantum}: identical joins"
        );
        assert_eq!(
            new.staged, count,
            "seed {seed} quantum {quantum}: the skip arm stages every call"
        );
        assert_eq!(
            new.staged, old.staged,
            "seed {seed} quantum {quantum}: identical staged counts"
        );
        assert_eq!(
            (new.h3_max, new.h3_floor),
            (old.h3_max, old.h3_floor),
            "seed {seed} quantum {quantum}: identical H3 disposition"
        );
        assert_eq!(
            new.h3_max, sequence,
            "seed {seed} quantum {quantum}: H3 covers every staged position"
        );
        assert_eq!(
            new.revision, old.revision,
            "seed {seed} quantum {quantum}: identical published revisions"
        );
        assert_eq!(
            new.gaps, old.gaps,
            "seed {seed} quantum {quantum}: identical gaps"
        );
        assert!(
            new.gaps
                .iter()
                .any(|gap| gap.reason == "joint_journal_unavailable"),
            "seed {seed} quantum {quantum}: the unlinked disclosure is present, so the gap comparison is non-vacuous"
        );
        assert_eq!(
            new.repeats, old.repeats,
            "seed {seed} quantum {quantum}: identical gap repeats"
        );
        assert_eq!(
            new.feeds, old.feeds,
            "seed {seed} quantum {quantum}: identical joint feeds"
        );
        assert_eq!(
            new.edges, old.edges,
            "seed {seed} quantum {quantum}: identical staged edges"
        );
        assert!(
            !new.edges.is_empty(),
            "seed {seed} quantum {quantum}: staged edges exist, so the edge comparison is non-vacuous"
        );
    }
    if fixed_count.is_some() {
        assert!(total > 5_120, "the past-cap leg must cross the claim cap");
    }
    // Both arms staged no journal BEGINs (genuinely feed-less) while
    // only the legacy arm filled the claim store: this pins the
    // switch live on both sides.
    for (label, arm, expect_stored) in
        [("legacy", &legacy, total.min(5_120)), ("skip", &skipped, 0)]
    {
        let adapter = arm.real.scene.coordinator.joint_capture().adapter();
        assert!(
            adapter.retained_starts_for_test().is_empty(),
            "{label} arm: bare rows stage no journal BEGINs"
        );
        assert_eq!(
            adapter.invocation_claims_for_test().0,
            expect_stored,
            "{label} arm: claim-store census"
        );
    }
    assert_eq!(
        legacy
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .test_claim_costs_for_test(),
        (total as u64, total, 0),
        "the legacy arm bills fingerprint work per claim, with no prune while keys live"
    );
    assert_eq!(
        skipped
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .test_claim_costs_for_test(),
        (0, 0, 0),
        "the skip arm files no fingerprint claims"
    );
}

/// Feed-less skip differential: randomized bare-row sequences give
/// identical public outputs on the legacy and skip arms, including
/// one leg past the 2048-entry claim cap. Claim-store internals are
/// the only allowed divergence.
#[test]
fn joint_keepup_feedless_skip_matches_legacy_public_outputs() {
    for seed in [
        0x1234_5678_9abc_def1,
        0xdead_beef_cafe_f00d,
        0x0bad_f00d_5eed_1234,
    ] {
        feedless_differential_sequences(seed, 5, None);
    }
    feedless_differential_sequences(0xfeed_1e55_ca1c_u64, 81, Some(64));
}
