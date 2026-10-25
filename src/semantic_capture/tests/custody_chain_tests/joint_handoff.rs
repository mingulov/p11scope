//! SPDX-License-Identifier: GPL-3.0-or-later
//! Actual collected H0, current validation and original prepared admissions.
//! No object bootstrap or ordinary Joint activation is supplied by this seam.

use super::*;
use crate::attach::SessionDrainProducers;
use crate::events::{EventDrain, EventsDomain, ScriptedRecords, record_bytes};
use crate::semantics_objects::journal::joint_driver::{
    IngestedRaw, RawJointQuantum, RawQuantumRefusal,
};
use crate::semantics_objects::journal::tests::{
    ENTRY_NS, begin_bytes_shaped, end_bytes, end_bytes_absent, function_id,
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
                !coordinator.stage_next_prepared_admission(),
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
    assert!(coordinator.stage_next_prepared_admission());
    assert!(!coordinator.finish_prepared_semantic_batch(&fixture.real.lane));
    assert!(coordinator.stage_next_prepared_admission());
    assert!(!coordinator.stage_next_prepared_admission());
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
            drain: EventDrain::over_domain(ScriptedRecords::records([], 64), events),
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
    fn encoded(&self, pid: u32, file: u32, name: &str, sequence: u64) -> ([u8; 224], [u8; 632]) {
        let held = self.real.h0.0.borrow();
        let io = &held.io;
        let image = io.targets[&pid].1;
        let slot = io.slot(file, name);
        let endpoint = io.endpoint(slot).unwrap();
        let (base, epoch, _) = io.scan_input(file);
        let init = name == "C_SignInit";
        let mut begin = begin_bytes_shaped(
            u64::from(pid),
            sequence,
            function_id(name),
            0,
            (image.task_cookie, image.exec_id),
            7,
            if init { 0x000d } else { 0 },
            capture::OUTPUT_NON_NULL
                | if init {
                    capture::MECHANISM_VALUE
                } else {
                    capture::MECHANISM_NONE
                },
            init.then_some((9, 1)),
            None,
            0,
        );
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
        } else {
            end_bytes_absent(&begin, 0, ENTRY_NS + 10)
        };
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
            assert!(self.real.scene.coordinator.stage_next_prepared_admission());
        }
        assert!(!self.real.scene.coordinator.stage_next_prepared_admission());
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
            .stage_next_prepared_admission()
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
                    .stage_next_prepared_admission(),
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
            .stage_next_prepared_admission()
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
            .stage_next_prepared_admission()
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
                .stage_next_prepared_admission()
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
