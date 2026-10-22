//! SPDX-License-Identifier: GPL-3.0-or-later
//! Genuine prior sealed history, retained by the canonical owner and pool.

use super::audit_handoff::{acquire, attachment, claim_and_finish};
use super::*;
use crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild;
use crate::semantics_objects::journal::tests::{NativeBirthRows, NativePublisher};
use crate::semantics_objects::journal::{BootstrapReceipt, ScriptedBirthSource};
use crate::semantics_objects::{Lifetime, ObjectEffect, ObjectGap};

struct CanonicalFanoutScene {
    scene: JointScene,
    attached: crate::attach::AttachedSemanticSet,
    births: Vec<(CallerId, RetainedBirthWitness, NativeBirthRows)>,
    grant: SessionDrainGrant,
    _child: OwnedStoppedChild,
}

impl CanonicalFanoutScene {
    fn prior_sealed() -> Self {
        let (held, attached) = HeldProviders::with_attachment(
            1,
            &[
                "C_CreateObject",
                "C_SignInit",
                "C_SignUpdate",
                "C_SignFinal",
            ],
        );
        let mut scene = JointScene::from_held(held, Some(attached));
        scene.real.h0.0.borrow_mut().io.script.local = 1;
        let child = OwnedStoppedChild::new();
        let first = scene.real.bind(
            std::process::id(),
            ImageIdentity {
                task_cookie: 71,
                exec_id: 0,
            },
            0,
        );
        let second = scene.real.bind(
            child.id(),
            ImageIdentity {
                task_cookie: 72,
                exec_id: 0,
            },
            0,
        );
        // The first accepted H0 scan happens through the actual collected
        // quantum. A preliminary provider refresh would spend New too early.
        scene.push(std::process::id(), 0, "C_CreateObject", 1);
        scene.push(child.id(), 0, "C_CreateObject", 1);
        let raw = scene.collect_with_fault(&BirthFault);
        scene.real.h0.0.borrow_mut().collected = Some(raw);
        let batch = scene.real.tick();
        scene.admit_providers(std::process::id(), first, &[0]);
        scene.admit_providers(child.id(), second, &[0]);
        scene.prepare_batch(batch, 2);
        let raw = scene.real.h0.0.borrow_mut().collected.take().unwrap();
        let (ingested, _, grant) = scene.ingest_with_grant(raw);
        let (admitted, current) = {
            let (prepared, _) = scene.real.scene.coordinator.prepared_joint_parts().unwrap();
            (
                prepared.admissions().cloned().collect::<Vec<_>>(),
                prepared.take_current_for_birth_test(),
            )
        };
        assert_eq!(admitted.len(), 2);
        assert_eq!(current.len(), 2, "two actual collected New receipts");
        let claims = claim_and_finish(&mut scene, &ingested);
        let attached = attachment(&mut scene);
        let publisher = NativePublisher::build();
        let mut births = Vec::new();
        for receipt in current {
            let candidate = receipt.into_birth_candidate().unwrap_or_else(|_| {
                panic!("provider admission must preserve the original collected New")
            });
            let input = admitted
                .iter()
                .find(|input| input.journal_binding().1 == candidate.receipt.image())
                .unwrap();
            let proof = claims
                .iter()
                .find(|(ordinal, _)| *ordinal == input.h0_ordinal())
                .unwrap()
                .1;
            let caller = input.journal_binding().3;
            let (row, control, _) = publisher.publish_stamped(&["0", "0"], attached.generation());
            let mut rows = NativeBirthRows { row, control };
            let mut h0 = scene.real.h0.0.borrow_mut();
            let HeldH0 { capture, io, .. } = &mut *h0;
            capture
                .validate_birth_candidate(io, &candidate, false)
                .unwrap();
            let witness = capture
                .finish_birth(
                    candidate,
                    None,
                    input,
                    scene
                        .real
                        .scene
                        .coordinator
                        .semantic_bindings()
                        .get(caller)
                        .unwrap(),
                    &attached,
                    &proof,
                    scene.real.scene.coordinator.joint_capture().adapter(),
                    &mut rows,
                )
                .expect("the original actual New and native marker authorize this subject");
            births.push((caller, witness, rows));
        }
        assert_ne!(
            births[0].1.receipt().domain(),
            births[1].1.receipt().domain()
        );
        for (caller, witness, _) in &births {
            let input = admitted
                .iter()
                .find(|input| input.journal_binding().3 == *caller)
                .unwrap();
            assert!(
                scene
                    .real
                    .scene
                    .coordinator
                    .registry_mut()
                    .install_joint_receipt(input.instance_key_for_test(), *witness.receipt(),)
            );
        }
        let frame = acquire(&mut scene, ingested, &attached, &BirthFault);
        assert!(frame.failure_for_test().is_none());
        scene
            .real
            .scene
            .coordinator
            .commit_batch_with_semantics(false, Some(&mut scene.real.lane))
            .unwrap();
        assert_eq!(scene.real.scene.coordinator.registry().joint_feeds(), 2);
        // Bootstrap the fixture with actual native rechecks and the SAME
        // acquired audit/model/ledger. Tests below exercise new frame delivery.
        for (caller, witness, rows) in &mut births {
            let fresh = {
                let mut h0 = scene.real.h0.0.borrow_mut();
                let HeldH0 { capture, io, .. } = &mut *h0;
                witness
                    .fresh_evidence_with(
                        io,
                        rows,
                        capture,
                        &attached,
                        scene
                            .real
                            .scene
                            .coordinator
                            .semantic_bindings()
                            .get(*caller)
                            .unwrap(),
                    )
                    .unwrap()
            };
            let (adapter, model) = scene.real.scene.coordinator.joint_capture_mut().parts();
            let sealed = adapter
                .seal(
                    model,
                    frame.audit_for_test(),
                    witness.receipt(),
                    frame.frontier(),
                    &mut ScriptedBirthSource::once(fresh),
                    &BirthFault,
                )
                .expect("actual native birth seals original history on canonical owner");
            assert_eq!(sealed.prefix.settled().len(), 1);
            let id = scene
                .real
                .scene
                .coordinator
                .registry()
                .instance_semantic_edges()
                .find(|record| record.caller == *caller)
                .unwrap()
                .id;
            assert_eq!(
                scene
                    .real
                    .scene
                    .coordinator
                    .deliver_canonical_joint_seal_for_test(id, &sealed),
                crate::semantics_key_use::SealApplyOutcome::ReplayedOne
            );
        }
        drop(frame);
        let history = scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .model()
            .project();
        assert_eq!(history.objects.len(), 2);
        assert!(
            history
                .objects
                .iter()
                .all(|object| object.lifetime == Lifetime::Live)
        );
        Self {
            scene,
            attached,
            births,
            grant,
            _child: child,
        }
    }

    fn receipts(&self) -> Vec<BootstrapReceipt> {
        self.births
            .iter()
            .map(|(_, witness, _)| *witness.receipt())
            .collect()
    }
}

#[test]
fn joint_prior_sealed_fixture_keeps_nonempty_original_two_domain_effects() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    let before = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    let receipts = fixture.receipts();
    fixture.scene.drain.source_mut().push_record(vec![1, 2, 3]);
    let raw = fixture.scene.prepare(0);
    let ingested = raw
        .ingest(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture_mut()
                .adapter_mut(),
            &fixture.scene.producers,
            &fixture.grant,
        )
        .unwrap_or_else(|(_, reason)| panic!("original malformed collection: {reason:?}"));
    assert!(claim_and_finish(&mut fixture.scene, &ingested).is_empty());
    let frame = acquire(&mut fixture.scene, ingested, &fixture.attached, &BirthFault);
    let failure = frame
        .failure_for_test()
        .expect("actual original broad loss");
    assert_eq!(
        failure.gap,
        crate::semantics_objects::journal::JournalGap::Malformed
    );
    assert!(
        receipts
            .iter()
            .all(|receipt| failure.affects_domain(receipt.domain()))
    );
    for object in &before.objects {
        assert!(
            failure.effects.effects.iter().any(|effect| matches!(
                effect,
                ObjectEffect::Retired { object: affected, reason: ObjectGap::Loss }
                    if *affected == object.id
            )),
            "both original registered domains retain their actual retirement effects"
        );
    }
    assert!(!failure.effects.effects.is_empty());
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        0
    );
}
