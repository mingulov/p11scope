//! SPDX-License-Identifier: GPL-3.0-or-later
//! Actual H0/admission/ingestion and the canonical Session audit owner.

use super::*;
use crate::attach::AttachedSemanticSet;
use crate::semantics_objects::journal::joint_audit::IngestedJointQuantum;
use crate::semantics_objects::journal::{FaultEpoch, FaultReadError, JournalGap};
use std::cell::Cell;

struct ReadFault {
    epoch: u64,
    reads: Cell<usize>,
}

impl ReadFault {
    fn new(epoch: u64) -> Self {
        Self {
            epoch,
            reads: Cell::new(0),
        }
    }
}

impl FaultEpoch for ReadFault {
    fn fault_epoch(&self) -> Result<u64, FaultReadError> {
        self.reads.set(self.reads.get() + 1);
        Ok(self.epoch)
    }
}

fn attachment(fixture: &mut JointScene) -> AttachedSemanticSet {
    fixture
        .attached
        .take()
        .expect("the actual separately minted attachment was sealed once")
}

fn claim_and_finish(
    fixture: &mut JointScene,
    ingested: &IngestedRaw,
) -> Vec<(u64, JournalDomainProof)> {
    let originals: Vec<_> = fixture
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap()
        .admissions()
        .map(|input| input.h0_ordinal())
        .collect();
    let mut claimed = Vec::new();
    for original in &originals {
        let (ordinal, proof) = fixture
            .real
            .scene
            .coordinator
            .claim_next_prepared_admission(&fixture.producers, ingested)
            .unwrap()
            .unwrap();
        assert_eq!(ordinal, *original);
        claimed.push((ordinal, proof.unwrap()));
    }
    assert!(
        fixture
            .real
            .scene
            .coordinator
            .claim_next_prepared_admission(&fixture.producers, ingested)
            .unwrap()
            .is_none()
    );
    for _ in &originals {
        assert!(
            fixture
                .real
                .scene
                .coordinator
                .stage_next_prepared_admission()
        );
    }
    assert!(
        !fixture
            .real
            .scene
            .coordinator
            .stage_next_prepared_admission()
    );
    assert!(
        fixture
            .real
            .scene
            .coordinator
            .finish_prepared_semantic_batch(&fixture.real.lane)
    );
    claimed
}

fn acquire(
    fixture: &mut JointScene,
    ingested: IngestedRaw,
    attached: &AttachedSemanticSet,
    fault: &impl FaultEpoch,
) -> IngestedJointQuantum {
    fixture
        .real
        .scene
        .coordinator
        .audit_ingested_quantum(ingested, &fixture.producers, attached, fault)
        .unwrap_or_else(|(_, reason)| panic!("actual finished audit: {reason:?}"))
}

#[test]
fn joint_audit_requires_every_original_disposed_before_one_h3_take() {
    let mut fixture = JointScene::for_audit(1);
    let pid = std::process::id();
    fixture.bind(pid, image(7), &[0]);
    fixture.push(pid, 0, "C_SignInit", 1);
    let raw = fixture.prepare(1);
    let identity = raw.h0_identity();
    let (mut ingested, proof) = fixture.ingest(raw);
    let frontier = ingested.frontier();
    let attached = attachment(&mut fixture);
    let fault = ReadFault::new(0);
    for phase in 0..3 {
        let refusal = fixture.real.scene.coordinator.audit_ingested_quantum(
            ingested,
            &fixture.producers,
            &attached,
            &fault,
        );
        let (original, reason) = match refusal {
            Err(refusal) => refusal,
            Ok(_) => panic!("unfinished original phase {phase} acquired an audit"),
        };
        assert_eq!(reason, RawQuantumRefusal::H3Undisposed);
        assert_eq!(original.frontier(), frontier);
        assert_eq!(
            fixture.real.scene.coordinator.reference_h3_audit_state(),
            (0, false)
        );
        assert_eq!(fault.reads.get(), 0, "preflight performs no audit mutation");
        ingested = original;
        match phase {
            0 => {
                fixture.assert_claims(&[]);
                assert_eq!(
                    fixture
                        .real
                        .scene
                        .coordinator
                        .claim_next_prepared_admission(&fixture.producers, &ingested,)
                        .unwrap(),
                    Some((1, Ok(proof)))
                );
            }
            1 => assert!(
                fixture
                    .real
                    .scene
                    .coordinator
                    .stage_next_prepared_admission()
            ),
            2 => assert!(
                fixture
                    .real
                    .scene
                    .coordinator
                    .finish_prepared_semantic_batch(&fixture.real.lane)
            ),
            _ => unreachable!(),
        }
    }
    fixture.assert_claims(&[(1, proof)]);
    assert_eq!(
        fixture.real.scene.coordinator.reference_h3_audit_state(),
        (0, true)
    );
    let before = fixture
        .real
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    let frame = acquire(&mut fixture, ingested, &attached, &fault);
    assert!(frame.identity() == identity);
    assert_eq!(frame.frontier(), frontier);
    assert!(frame.failure_for_test().is_none());
    assert_eq!(
        frame.validate_owner(
            fixture.real.scene.coordinator.joint_capture(),
            &fixture.producers
        ),
        Ok(())
    );
    assert!(matches!(
        frame.audit_for_test().h3_for_test(),
        crate::semantics_objects::journal::H3DispositionEvidence::Clean {
            staged_max: 1,
            pending_floor: None
        }
    ));
    assert!(std::ptr::eq(frame.audit_for_test(), frame.audit_for_test()));
    assert_eq!(
        fixture.real.scene.coordinator.reference_h3_audit_state(),
        (1, false)
    );
    assert_eq!(
        fault.reads.get(),
        1,
        "collection-wide audit runs even with no eligible head"
    );
    fixture.assert_claims(&[(1, proof)]);
    let during = fixture
        .real
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    assert!(during.charged_bytes >= before.charged_bytes + frame.retained_storage_bytes_for_test());
    drop(frame);
    assert_eq!(
        fixture
            .real
            .scene
            .coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes,
        before.charged_bytes
    );
}

#[test]
fn joint_audit_foreign_and_stale_raw_preserve_pending_h3_and_original() {
    let mut fixture = JointScene::for_audit(1);
    let pid = std::process::id();
    fixture.bind(pid, image(7), &[0]);
    fixture.push(pid, 0, "C_SignInit", 1);
    let raw = fixture.prepare(1);
    let (mut first, proof) = fixture.ingest(raw);
    claim_and_finish(&mut fixture, &first);
    let attached = attachment(&mut fixture);
    let fault = ReadFault::new(0);
    let foreign = SessionDrainProducers::test_pair(
        fixture.producers.native_domain(),
        EventsDomain::test_standin(fixture.producers.events_id()),
    );
    for _ in 0..2 {
        let (original, reason) = match fixture
            .real
            .scene
            .coordinator
            .audit_ingested_quantum(first, &foreign, &attached, &fault)
        {
            Err(refusal) => refusal,
            Ok(_) => panic!("equal numeric map id replaced the actual producer allocation"),
        };
        assert_eq!(reason, RawQuantumRefusal::ForeignCapture);
        assert_eq!(
            fixture.real.scene.coordinator.reference_h3_audit_state(),
            (0, true)
        );
        assert_eq!(fault.reads.get(), 0);
        fixture.assert_claims(&[(1, proof)]);
        first = original;
    }
    fixture.push(pid, 0, "C_SignUpdate", 2);
    let next_raw = fixture.prepare(1);
    let identity = next_raw.h0_identity();
    let (next, next_proof) = fixture.ingest(next_raw);
    claim_and_finish(&mut fixture, &next);
    for _ in 0..2 {
        let (original, reason) = match fixture.real.scene.coordinator.audit_ingested_quantum(
            first,
            &fixture.producers,
            &attached,
            &fault,
        ) {
            Err(refusal) => refusal,
            Ok(_) => panic!("old quantum acquired the later original frontier"),
        };
        assert_eq!(reason, RawQuantumRefusal::StaleFrontier);
        assert_eq!(
            fixture.real.scene.coordinator.reference_h3_audit_state(),
            (0, true)
        );
        assert_eq!(fault.reads.get(), 0);
        fixture.assert_claims(&[(1, proof), (2, next_proof)]);
        first = original;
    }
    let frame = acquire(&mut fixture, next, &attached, &fault);
    assert!(frame.identity() == identity);
    assert!(frame.frontier() > first.frontier());
    assert_eq!(
        fixture.real.scene.coordinator.reference_h3_audit_state(),
        (1, false)
    );
    assert_eq!(
        frame.validate_owner(fixture.real.scene.coordinator.joint_capture(), &foreign),
        Err(RawQuantumRefusal::ForeignCapture)
    );
    assert!(matches!(
        frame.audit_for_test().h3_for_test(),
        crate::semantics_objects::journal::H3DispositionEvidence::Clean {
            staged_max: 2,
            pending_floor: None
        }
    ));
}

#[test]
fn joint_audit_storage_refusal_precedes_take_and_global_mutation() {
    let mut fixture = JointScene::for_audit(1);
    let pid = std::process::id();
    fixture.bind(pid, image(7), &[0]);
    fixture.push(pid, 0, "C_SignInit", 1);
    let raw = fixture.prepare(1);
    let (ingested, proof) = fixture.ingest(raw);
    claim_and_finish(&mut fixture, &ingested);
    let attached = attachment(&mut fixture);
    let fault = ReadFault::new(1);
    let before = fixture
        .real
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    fixture
        .real
        .scene
        .coordinator
        .registry_mut()
        .reference_semantic_resource_limit(
            before.charged_bytes + std::mem::size_of::<IngestedJointQuantum>(),
        );
    let (ingested, reason) = match fixture.real.scene.coordinator.audit_ingested_quantum(
        ingested,
        &fixture.producers,
        &attached,
        &fault,
    ) {
        Err(refusal) => refusal,
        Ok(_) => {
            panic!("inline ownership fits, but the original affected-domain allocation does not")
        }
    };
    assert!(matches!(reason, RawQuantumRefusal::Resource(_)));
    assert_eq!(
        fixture.real.scene.coordinator.reference_h3_audit_state(),
        (0, true)
    );
    assert_eq!(fault.reads.get(), 0);
    fixture.assert_claims(&[(1, proof)]);
    assert_eq!(
        fixture
            .real
            .scene
            .coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes,
        before.charged_bytes
    );
    fixture
        .real
        .scene
        .coordinator
        .registry_mut()
        .reference_semantic_resource_limit(before.limit_bytes);
    let frame = acquire(&mut fixture, ingested, &attached, &fault);
    let failure = frame
        .failure_for_test()
        .expect("actual seal-time fault changed");
    assert_eq!(failure.gap, JournalGap::FaultChanged);
    assert!(failure.affects_proof_for_test(&proof));
    fixture.assert_claims(&[]);
    assert_eq!(
        fixture.real.scene.coordinator.reference_h3_audit_state(),
        (1, false)
    );
}

#[test]
fn joint_audit_no_head_fault_or_malformed_keeps_original_affected_domains() {
    for malformed in [false, true] {
        let mut fixture = JointScene::for_audit(2);
        let pid = std::process::id();
        fixture.bind(pid, image(7), &[0, 1]);
        fixture.push(pid, 0, "C_SignInit", 1);
        fixture.push(pid, 1, "C_SignInit", 2);
        if malformed {
            fixture.drain.source_mut().push_record(vec![0; 3]);
        }
        let raw = fixture.prepare(2);
        let (ingested, _) = fixture.ingest(raw);
        let claims = claim_and_finish(&mut fixture, &ingested);
        assert_eq!(claims.len(), 2);
        assert_ne!(claims[0].1, claims[1].1);
        fixture.assert_claims(&claims);
        let attached = attachment(&mut fixture);
        let fault = ReadFault::new(u64::from(!malformed));
        let frame = acquire(&mut fixture, ingested, &attached, &fault);
        let failure = frame
            .failure_for_test()
            .expect("owned collection-wide loss");
        assert_eq!(
            failure.gap,
            if malformed {
                JournalGap::Malformed
            } else {
                JournalGap::FaultChanged
            }
        );
        assert!(
            claims
                .iter()
                .all(|(_, proof)| failure.affects_proof_for_test(proof))
        );
        assert_eq!(failure.h3_voided, None);
        assert!(
            std::ptr::eq(failure, frame.failure_for_test().unwrap()),
            "re-observation borrows the original failure, never re-runs the void"
        );
        fixture.assert_claims(&[]);
        assert_eq!(
            fixture.real.scene.coordinator.reference_h3_audit_state(),
            (1, false)
        );
        assert_eq!(
            fixture
                .real
                .scene
                .coordinator
                .reference_h3_acknowledged_below(),
            0
        );
        assert_eq!(fault.reads.get(), 1);
    }
}

#[test]
fn joint_audit_no_head_clean_frame_establishes_cumulative_fault_baseline() {
    let mut fixture = JointScene::for_audit(1);
    let pid = std::process::id();
    fixture.bind(pid, image(7), &[0]);
    fixture.push(pid, 0, "C_SignInit", 1);
    let raw = fixture.prepare(1);
    let (first, _) = fixture.ingest(raw);
    claim_and_finish(&mut fixture, &first);
    let attached = attachment(&mut fixture);
    let frame = acquire(&mut fixture, first, &attached, &ReadFault::new(0));
    assert!(frame.failure_for_test().is_none());
    drop(frame);
    fixture.real.h0.0.borrow_mut().io.script.last_health.fault = 1;
    fixture.push(pid, 0, "C_SignInit", 2);
    let fault = ReadFault::new(1);
    let raw = fixture.prepare_with_fault(1, &fault);
    let (next, _) = fixture.ingest(raw);
    claim_and_finish(&mut fixture, &next);
    let reads_before = fault.reads.get();
    let frame = acquire(&mut fixture, next, &attached, &fault);
    assert_eq!(
        frame.failure_for_test().unwrap().gap,
        JournalGap::FaultChanged,
        "both q2 reads and seal-time fault agree; only q1's actual baseline detects the between-frame move"
    );
    assert_eq!(fault.reads.get(), reads_before + 1);
    assert_eq!(
        fixture.real.scene.coordinator.reference_h3_audit_state(),
        (2, false)
    );
}
