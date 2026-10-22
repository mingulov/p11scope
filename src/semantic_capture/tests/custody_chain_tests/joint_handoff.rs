//! SPDX-License-Identifier: GPL-3.0-or-later
//! Actual collected H0, current validation and original prepared admissions.
//! No object bootstrap or ordinary Joint activation is supplied by this seam.

use super::*;
use crate::attach::SessionDrainProducers;
use crate::events::{EventDrain, EventsDomain, ScriptedRecords};
use crate::semantics_objects::journal::joint_driver::{
    IngestedRaw, RawJointQuantum, RawQuantumRefusal,
};
use crate::semantics_objects::journal::tests::{
    ENTRY_NS, begin_bytes_shaped, end_bytes, end_bytes_absent, function_id,
};
use crate::semantics_objects::journal::{
    AttestationRefusal, H3DispositionEvidence, JournalDomainProof, SessionDrainGrant,
};
use p11scope_ebpf_common::object_wire::{OBJECT_ACTION_ACCESS, publish_object_descriptors};

struct JointScene {
    real: RealScene,
    producers: SessionDrainProducers,
    drain: EventDrain<ScriptedRecords>,
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

impl JointScene {
    fn new(providers: usize) -> Self {
        let real = RealScene::from_held(HeldProviders::with_functions(
            providers,
            &["C_SignInit", "C_SignUpdate", "C_SignFinal"],
        ));
        let events = EventsDomain::test_standin(0xb301);
        let producers = SessionDrainProducers::test_pair(real.lane.domain(), events.clone());
        Self {
            real,
            producers,
            drain: EventDrain::over_domain(ScriptedRecords::records([], 64), events),
        }
    }

    fn bind(&mut self, pid: u32, image: ImageIdentity, files: &[u32]) -> CallerId {
        let caller = self.real.bind(pid, image, files[0] as usize);
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
        caller
    }

    fn push(&mut self, pid: u32, file: u32, name: &str, sequence: u64) {
        let held = self.real.h0.0.borrow();
        let io = &held.io;
        let image = io.targets[&pid].1;
        let slot = io.slot(file, name);
        let endpoint = io.endpoint(slot).unwrap();
        let (base, epoch) = io.scan_input(file);
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
        let end = if init {
            end_bytes(&begin, OBJECT_ACTION_ACCESS, 0, ENTRY_NS + 10)
        } else {
            end_bytes_absent(&begin, 0, ENTRY_NS + 10)
        };
        self.drain.source_mut().push_record(begin.to_vec());
        self.drain.source_mut().push_record(end.to_vec());
    }

    fn prepare(&mut self, count: usize) -> RawJointQuantum {
        let reserve = self
            .real
            .scene
            .coordinator
            .registry()
            .semantic_storage_reserver();
        let raw = RawJointQuantum::collect_bounded_with_adapter(
            &mut self.drain,
            &publish_object_descriptors(),
            64,
            None,
            &BirthFault,
            &self.producers,
            |bytes| reserve.reserve(bytes),
            self.real
                .scene
                .coordinator
                .joint_capture_mut()
                .adapter_mut(),
        )
        .expect("actual persistent cursor collection");
        assert_eq!(
            raw.h0_input(self.real.lane.domain(), 64).unwrap().0.len(),
            count
        );
        self.real.h0.0.borrow_mut().collected = Some(raw);
        let batch = self.real.tick();
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
        self.real.h0.0.borrow_mut().collected.take().unwrap()
    }

    fn ingest(&mut self, raw: RawJointQuantum) -> (IngestedRaw, JournalDomainProof) {
        let (prepared, owner) = self.real.scene.coordinator.prepared_joint_parts().unwrap();
        let input = prepared.next_admission().unwrap();
        let proof = owner.adapter_mut().bind_admitted_key(input).unwrap();
        let grant = SessionDrainGrant::observe(&self.producers, input).unwrap();
        owner.adapter_mut().bind_session_drain(&grant).unwrap();
        let ingested = raw
            .ingest(owner.adapter_mut(), &self.producers, &grant)
            .unwrap_or_else(|(_, reason)| panic!("original ingestion: {reason:?}"));
        (ingested, proof)
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
    let (first, proof) = fixture.ingest(raw);
    let foreign = SessionDrainProducers::test_pair(
        fixture.producers.native_domain(),
        EventsDomain::test_standin(fixture.producers.events_id()),
    );
    assert_eq!(
        fixture
            .real
            .scene
            .coordinator
            .claim_next_prepared_admission(&foreign, &first),
        Err(RawQuantumRefusal::ForeignCapture)
    );
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
    assert_eq!(
        fixture
            .real
            .scene
            .coordinator
            .claim_next_prepared_admission(&fixture.producers, &first),
        Err(RawQuantumRefusal::Admission)
    );
    let (next, next_proof) = fixture.ingest(next_raw);
    assert_eq!(
        fixture
            .real
            .scene
            .coordinator
            .claim_next_prepared_admission(&fixture.producers, &first),
        Err(RawQuantumRefusal::StaleFrontier)
    );
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
    assert!(
        fixture
            .real
            .scene
            .coordinator
            .claim_next_prepared_admission(&fixture.producers, &next)
            .unwrap()
            .is_none()
    );
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
    let (ingested, first_proof) = fixture.ingest(raw);
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
    fixture.finish(3, 3);
    let rows = operation_edge_rows(&fixture.real.scene);
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|row| *row == (Some(1), 0, false, 1, 0)));
}
