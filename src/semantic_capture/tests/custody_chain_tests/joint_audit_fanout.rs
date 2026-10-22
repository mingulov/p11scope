//! SPDX-License-Identifier: GPL-3.0-or-later
//! Genuine prior sealed history, retained by the canonical owner and pool.

use super::audit_handoff::{acquire, attachment, claim_and_finish};
use super::*;
use crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild;
use crate::semantics_objects::journal::tests::{NativeBirthRows, NativePublisher};
use crate::semantics_objects::journal::{
    BootstrapReceipt, ScriptedBirthSource, SessionClosureGrant,
};
use crate::semantics_objects::{Lifetime, ObjectEffect, ObjectGap};

struct CanonicalFanoutScene {
    scene: JointScene,
    attached: crate::attach::AttachedSemanticSet,
    births: Vec<(CallerId, RetainedBirthWitness, NativeBirthRows)>,
    grant: SessionDrainGrant,
    _child: OwnedStoppedChild,
}

impl CanonicalFanoutScene {
    /// Retain the actual collected New carried by a later stash merge. Its
    /// original cut/subject, not the current quantum number, authorizes birth.
    fn retain_collected_birth(
        &mut self,
        input: &crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
        current: crate::semantic_capture::CurrentPartitionReceipt,
        proof: crate::semantics_objects::journal::JournalDomainProof,
    ) {
        let candidate = current.into_birth_candidate().unwrap_or_else(|_| {
            panic!("the original pending job must retain its actual collected New")
        });
        assert_eq!(candidate.receipt.image(), input.journal_binding().1);
        let publisher = NativePublisher::build();
        let (row, control, _) = publisher.publish_stamped(&["0", "0"], self.attached.generation());
        let mut rows = NativeBirthRows { row, control };
        let caller = input.journal_binding().3;
        let witness = {
            let mut h0 = self.scene.real.h0.0.borrow_mut();
            let HeldH0 { capture, io, .. } = &mut *h0;
            capture
                .validate_birth_candidate(io, &candidate, false)
                .unwrap();
            capture
                .finish_birth(
                    candidate,
                    None,
                    input,
                    self.scene
                        .real
                        .scene
                        .coordinator
                        .semantic_bindings()
                        .get(caller)
                        .unwrap(),
                    &self.attached,
                    &proof,
                    self.scene.real.scene.coordinator.joint_capture().adapter(),
                    &mut rows,
                )
                .expect("the retained actual New and original subject authorize birth")
        };
        assert!(
            self.scene
                .real
                .scene
                .coordinator
                .registry_mut()
                .install_joint_receipt(input.instance_key_for_test(), *witness.receipt(),)
        );
        self.births.push((caller, witness, rows));
    }

    fn prior_sealed() -> Self {
        Self::prior_sealed_with_providers(1)
    }

    fn prior_sealed_with_providers(providers: usize) -> Self {
        let (held, attached) = HeldProviders::with_attachment(
            providers,
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
        let admitted = {
            let (prepared, _) = scene.real.scene.coordinator.prepared_joint_parts().unwrap();
            prepared.admissions().cloned().collect::<Vec<_>>()
        };
        let current = scene
            .real
            .scene
            .coordinator
            .take_prepared_current_for_birth_test()
            .unwrap();
        assert_eq!(admitted.len(), 2);
        assert_eq!(current.len(), 2, "two actual collected New receipts");
        let claims = claim_and_finish(&mut scene, &ingested);
        let attached = attachment(&mut scene);
        assert!(
            scene
                .real
                .scene
                .coordinator
                .joint_capture_mut()
                .adapter_mut()
                .install_closure_grant(&SessionClosureGrant::observe(&attached)),
            "install the genuine current attachment before any birth attestation"
        );
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
            assert_eq!(
                witness.receipt().closure_generation(),
                attached.generation()
            );
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
    let before_audit = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    for object in &before.objects {
        assert_eq!(
            before_audit.object(object.id).unwrap().lifetime,
            Lifetime::Live
        );
    }
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (1, true)
    );
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
                ObjectEffect::Retired { object: affected, reason: ObjectGap::OutcomeLost }
                    if *affected == object.id
            )),
            "audit Voided must retain each original OutcomeLost retirement: {:?}",
            failure.effects
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .model()
                .project()
                .object(object.id)
                .unwrap()
                .lifetime,
            Lifetime::Retired(ObjectGap::OutcomeLost)
        );
    }
    assert!(!failure.effects.effects.is_empty());
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (2, false)
    );
    let original_effects = failure.effects.clone();
    fixture
        .scene
        .push(std::process::id(), 0, "C_CreateObject", 2);
    let cut = fixture.scene.drain.consumption_cut().unwrap();
    let reserve = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_storage_reserver();
    let next = RawJointQuantum::collect_bounded_with_adapter(
        &mut fixture.scene.drain,
        &publish_object_descriptors(),
        64,
        None,
        &BirthFault,
        &fixture.scene.producers,
        |bytes| reserve.reserve(bytes),
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture_mut()
            .adapter_mut(),
    );
    assert!(matches!(
        next,
        Err(RawQuantumRefusal::Cut(
            crate::semantics_objects::journal::BirthCutRefusal::Gap
        ))
    ));
    assert!(
        fixture
            .scene
            .drain
            .consumption_cut()
            .unwrap()
            .same_boundary(&cut)
    );
    assert!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .consumed_frontier()
            == frame.frontier()
    );
    assert_eq!(failure.effects, original_effects);
    assert!(
        receipts
            .iter()
            .all(|receipt| failure.affects_domain(receipt.domain()))
    );
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

use crate::attach::{BirthObservationRefusal, BirthRowError, BirthRowReader};
use crate::discovery::caller_registry::instance_input::{JointFeedTarget, RegistryInstanceId};
use crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding;
use crate::semantics_objects::journal::SessionBirthEvidence;
use crate::semantics_objects::journal::joint_audit::{
    IngestedJointQuantum, JointBirthEvidenceSource, QuantumSealProgress,
};
use std::cell::Cell;

/// Reads the genuine retained native row through the same verifier. Refusal
/// substitutes only the row I/O leaf, never a birth value or target counter.
struct NativeFrameBirths<'a> {
    h0: &'a SharedH0,
    attached: &'a crate::attach::AttachedSemanticSet,
    retained: &'a mut [(CallerId, RetainedBirthWitness, NativeBirthRows)],
    seen: Vec<(
        RegistryInstanceId,
        CallerId,
        ImageIdentity,
        crate::semantics_objects::ObjectDomain,
    )>,
    unreadable: bool,
}

struct UnreadableRows<'a>(&'a mut NativeBirthRows);
impl BirthRowReader for UnreadableRows<'_> {
    fn read_marker_row(&mut self) -> Result<p11scope_ebpf_common::InstanceRecord, BirthRowError> {
        Err(BirthRowError::Unreadable)
    }
    fn read_admission_control(
        &mut self,
    ) -> Result<p11scope_ebpf_common::JournalAdmissionControl, BirthRowError> {
        self.0.read_admission_control()
    }
}

impl JointBirthEvidenceSource for NativeFrameBirths<'_> {
    fn take_for(
        &mut self,
        target: &JointFeedTarget,
        binding: &SemanticCallerBinding,
    ) -> Result<SessionBirthEvidence, BirthObservationRefusal> {
        assert_eq!(target.caller(), binding.caller());
        let (_, witness, rows) = self
            .retained
            .iter_mut()
            .find(|(caller, witness, _)| {
                *caller == binding.caller()
                    && witness.receipt().domain() == target.bootstrap().domain()
            })
            .expect("the selected typed target names its own original binding/witness");
        self.seen.push((
            target.id(),
            binding.caller(),
            binding.image(),
            target.bootstrap().domain(),
        ));
        let mut h0 = self.h0.0.borrow_mut();
        let HeldH0 { capture, io, .. } = &mut *h0;
        if self.unreadable {
            witness.fresh_evidence_with(
                io,
                &mut UnreadableRows(rows),
                capture,
                self.attached,
                binding,
            )
        } else {
            witness.fresh_evidence_with(io, rows, capture, self.attached, binding)
        }
    }
}

struct RefuseOneBirth<'a> {
    inner: NativeFrameBirths<'a>,
    refused: Option<CallerId>,
}
impl JointBirthEvidenceSource for RefuseOneBirth<'_> {
    fn take_for(
        &mut self,
        target: &JointFeedTarget,
        binding: &SemanticCallerBinding,
    ) -> Result<SessionBirthEvidence, BirthObservationRefusal> {
        self.inner.unreadable = self.refused == Some(target.caller());
        self.inner.take_for(target, binding)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FeedState {
    id: RegistryInstanceId,
    caller: CallerId,
    reduced: u64,
    staged: usize,
    disposed: u64,
    degraded: bool,
    fallback: bool,
}

struct FrameFault {
    epoch: Cell<u64>,
    reads: Cell<usize>,
}
impl FrameFault {
    fn clean() -> Self {
        Self {
            epoch: Cell::new(0),
            reads: Cell::new(0),
        }
    }
}
impl crate::semantics_objects::journal::FaultEpoch for FrameFault {
    fn fault_epoch(&self) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
        self.reads.set(self.reads.get() + 1);
        Ok(self.epoch.get())
    }
}

impl CanonicalFanoutScene {
    fn feeds(&self) -> Vec<FeedState> {
        self.scene
            .real
            .scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .map(|record| FeedState {
                id: record.id,
                caller: record.caller,
                reduced: record.feed.reduced(),
                staged: record.feed.staged_len(),
                disposed: record.feed.history_disposed(),
                degraded: record.feed.degraded_loss(),
                fallback: record.feed.fell_back(),
            })
            .collect()
    }

    fn push_two(&mut self, name: &str, sequence: u64) {
        for pid in [std::process::id(), self._child.id()] {
            self.scene.push(pid, 0, name, sequence);
        }
    }

    fn push_distinct_create(&mut self, pid: u32, sequence: u64, result: u64) {
        let (begin, _) = self.scene.encoded(pid, 0, "C_CreateObject", sequence);
        let end = crate::semantics_objects::journal::tests::end_bytes_result(
            &begin,
            p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE,
            0,
            ENTRY_NS + 10,
            result,
        );
        self.scene.drain.source_mut().push_record(begin.to_vec());
        self.scene.drain.source_mut().push_record(end.to_vec());
    }

    fn audited(
        &mut self,
        physical: usize,
        admissions: usize,
        fault: &impl crate::semantics_objects::journal::FaultEpoch,
    ) -> IngestedJointQuantum {
        let raw = self.scene.collect_with_fault(fault);
        assert_eq!(
            raw.h0_input(self.scene.real.lane.domain(), 64)
                .unwrap()
                .0
                .len(),
            physical
        );
        self.scene.real.h0.0.borrow_mut().collected = Some(raw);
        let batch = self.scene.real.tick();
        assert_eq!(self.scene.real.h0.0.borrow().last_calls.len(), physical);
        let coordinator = &mut self.scene.real.scene.coordinator;
        coordinator.stage_semantic_batch(batch);
        coordinator
            .prepare_staged_semantic_batch(&mut self.scene.real.lane, None)
            .unwrap();
        assert_eq!(
            coordinator
                .prepared_semantic_batch()
                .unwrap()
                .admissions()
                .count(),
            admissions
        );
        let raw = self.scene.real.h0.0.borrow_mut().collected.take().unwrap();
        let ingested = raw
            .ingest(
                coordinator.joint_capture_mut().adapter_mut(),
                &self.scene.producers,
                &self.grant,
            )
            .unwrap_or_else(|(_, reason)| panic!("same original ingestion: {reason:?}"));
        assert_eq!(
            claim_and_finish(&mut self.scene, &ingested).len(),
            admissions
        );
        // Existing commit applies actual staged payloads to the selected feeds.
        // Atomic publication/revision wiring is explicitly the later Task5 gate.
        self.scene
            .real
            .scene
            .coordinator
            .commit_batch_with_semantics(false, Some(&mut self.scene.real.lane))
            .unwrap();
        acquire(&mut self.scene, ingested, &self.attached, fault)
    }
}

#[test]
fn joint_one_audit_fans_out_two_domains() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    fixture.push_two("C_SignInit", 2);
    let mut frame = fixture.audited(2, 2, &BirthFault);
    let identity = frame.identity();
    let frontier = frame.frontier();
    assert_eq!(
        fixture
            .feeds()
            .iter()
            .map(|feed| (feed.reduced, feed.staged))
            .collect::<Vec<_>>(),
        [(1, 1), (1, 1)]
    );
    let targets = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .joint_feed_targets()
        .collect::<Vec<_>>();
    assert_eq!(targets.len(), 2);
    for target in &targets {
        assert!(
            fixture
                .births
                .iter()
                .any(|(caller, witness, _)| *caller == target.caller()
                    && witness.receipt().domain() == target.bootstrap().domain())
        );
    }
    let h0 = fixture.scene.real.h0.clone();
    let mut births = NativeFrameBirths {
        h0: &h0,
        attached: &fixture.attached,
        retained: &mut fixture.births,
        seen: Vec::new(),
        unreadable: false,
    };
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
        assert_eq!(
            frame.bind_targets(&ports),
            Err(RawQuantumRefusal::DispositionMismatch)
        );
        for index in 0..2 {
            assert_eq!(
                frame.seal_next(&mut ports, &mut births, &BirthFault),
                Ok(QuantumSealProgress::DeliveryReady)
            );
            assert_eq!(births.seen.len(), index + 1);
            assert_eq!(
                frame.seal_next(&mut ports, &mut births, &BirthFault),
                Ok(QuantumSealProgress::DeliveryReady)
            );
            assert_eq!(
                births.seen.len(),
                index + 1,
                "retry never seals or reads birth twice"
            );
            assert_eq!(
                frame.deliver_next(&mut ports),
                Ok(if index == 0 {
                    QuantumSealProgress::LocalPending
                } else {
                    QuantumSealProgress::Complete
                })
            );
        }
        assert_eq!(
            frame.seal_next(&mut ports, &mut births, &BirthFault),
            Ok(QuantumSealProgress::Complete)
        );
        assert_eq!(
            frame.deliver_next(&mut ports),
            Ok(QuantumSealProgress::Complete)
        );
        let disposed = frame
            .finish_frame(&mut ports)
            .unwrap_or_else(|(_, reason)| panic!("all consumers disposed: {reason:?}"));
        assert!(disposed.identity() == identity);
        assert_eq!(disposed.frontier(), frontier);
    }
    assert_ne!(
        births.seen[0].2, births.seen[1].2,
        "different original images/bindings"
    );
    assert_eq!(
        births.seen.iter().map(|seen| seen.0).collect::<Vec<_>>(),
        targets.iter().map(JointFeedTarget::id).collect::<Vec<_>>()
    );
    drop(births);
    assert!(
        fixture
            .feeds()
            .iter()
            .all(|feed| feed.reduced == 2 && feed.staged == 0 && !feed.degraded && !feed.fallback)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (2, false)
    );
    fixture.scene.assert_claims(&[]);
}

#[test]
fn joint_two_feeds_share_nonzero_audited_fallback_once() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    fixture.push_two("C_SignInit", 2);
    let mut frame = fixture.audited(2, 2, &BirthFault);
    assert!(matches!(
        frame.audit_for_test().h3_for_test(),
        H3DispositionEvidence::Clean {
            staged_max: 4,
            pending_floor: None
        }
    ));
    let h0 = fixture.scene.real.h0.clone();
    let mut births = NativeFrameBirths {
        h0: &h0,
        attached: &fixture.attached,
        retained: &mut fixture.births,
        seen: Vec::new(),
        unreadable: true,
    };
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
        for index in 0..2 {
            assert_eq!(
                frame.seal_next(&mut ports, &mut births, &BirthFault),
                Ok(QuantumSealProgress::DeliveryReady)
            );
            assert_eq!(
                frame.deliver_next(&mut ports),
                Ok(if index == 0 {
                    QuantumSealProgress::LocalPending
                } else {
                    QuantumSealProgress::Complete
                })
            );
        }
        assert_eq!(
            frame.deliver_next(&mut ports),
            Ok(QuantumSealProgress::Complete)
        );
        frame
            .finish_frame(&mut ports)
            .unwrap_or_else(|(_, reason)| panic!("audited fallback disposed both: {reason:?}"));
    }
    assert_eq!(births.seen.len(), 2);
    assert_ne!(
        births.seen[0].2, births.seen[1].2,
        "first refusal does not choose the next witness by guessed ordinal"
    );
    drop(births);
    assert!(
        fixture
            .feeds()
            .iter()
            .all(|feed| feed.reduced == 2 && feed.staged == 0 && feed.fallback && !feed.degraded)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (2, false),
        "both feeds borrow the same nonzero taken H3, no genesis second take"
    );
    fixture.scene.assert_claims(&[]);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test()[..4],
        [0, 0, 0, 0],
        "completed originals release Raw/H8/Model/H9 after once-only fallback; legitimate live S1 associations keep their own roles"
    );
}

#[test]
fn joint_fallback_preflight_preserves_incomplete_admitted_original() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    let first = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .joint_feed_targets()
        .next()
        .unwrap();
    let pid = fixture
        .scene
        .real
        .scene
        .coordinator
        .semantic_bindings()
        .get(first.caller())
        .unwrap()
        .pin()
        .pid();
    let (begin, end) = fixture.scene.encoded(pid, 0, "C_SignInit", 2);
    fixture.scene.drain.source_mut().push_record(begin.to_vec());
    // H0 genuinely admits the ordinary physical return, while the journal
    // retains START without its END. Completeness of H3 cannot invent END.
    fixture
        .scene
        .drain
        .source_mut()
        .push_record(end[24..392].to_vec());
    let mut frame = fixture.audited(1, 1, &BirthFault);
    let before = fixture.feeds();
    let owner = fixture.scene.real.scene.coordinator.joint_capture();
    let claims = owner.adapter().invocation_claims_for_test();
    let starts = owner.adapter().retained_starts_for_test();
    let roles = owner.ledger().roles_for_test();
    assert_eq!(claims.0, 1);
    assert_eq!(roles[..4], [0, 1, 0, 1]);
    assert_eq!(
        owner
            .adapter()
            .retained_start_bytes_for_test((u64::from(pid), 2)),
        Some(begin)
    );
    let h0 = fixture.scene.real.h0.clone();
    let mut births = NativeFrameBirths {
        h0: &h0,
        attached: &fixture.attached,
        retained: &mut fixture.births,
        seen: Vec::new(),
        unreadable: true,
    };
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
        assert_eq!(
            frame.seal_next(&mut ports, &mut births, &BirthFault),
            Ok(QuantumSealProgress::DeliveryReady)
        );
        assert_eq!(
            frame.deliver_next(&mut ports),
            Err(RawQuantumRefusal::DispositionMismatch),
            "completed-original preflight precedes any H9 fallback mutation"
        );
    }
    drop(births);
    assert_eq!(fixture.feeds(), before);
    let owner = fixture.scene.real.scene.coordinator.joint_capture();
    assert_eq!(owner.adapter().invocation_claims_for_test(), claims);
    assert_eq!(owner.adapter().retained_starts_for_test(), starts);
    assert_eq!(owner.ledger().roles_for_test(), roles);
    assert_eq!(
        owner
            .adapter()
            .retained_start_bytes_for_test((u64::from(pid), 2)),
        Some(begin)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (2, false),
        "refusal neither retakes H3 nor acknowledges a loss"
    );
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

struct NoFrameBirths;
impl JointBirthEvidenceSource for NoFrameBirths {
    fn take_for(
        &mut self,
        _: &JointFeedTarget,
        _: &SemanticCallerBinding,
    ) -> Result<SessionBirthEvidence, BirthObservationRefusal> {
        panic!("collection-wide loss must fan out before any fresh per-domain birth");
    }
}

#[test]
fn joint_original_loss_fans_out_before_ack() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    let original = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project()
        .objects;
    fixture.push_two("C_SignInit", 2);
    // Genuine H0 no-file refusal: ordinary bytes from the native END recipe,
    // with its actual descriptor removed only at the injected H0 I/O leaf.
    // H3 itself must produce the loss barrier; no scripted disposition/cut.
    let (_, ordinary) = fixture
        .scene
        .encoded(std::process::id(), 0, "C_SignFinal", 3);
    let slot = fixture.scene.real.h0.0.borrow().io.slot(0, "C_SignFinal");
    fixture
        .scene
        .real
        .h0
        .0
        .borrow_mut()
        .io
        .endpoints
        .retain(|(index, _, _)| *index != slot);
    fixture
        .scene
        .drain
        .source_mut()
        .push_record(ordinary[24..392].to_vec());
    let mut frame = fixture.audited(3, 2, &BirthFault);
    let failure = frame
        .failure_for_test()
        .expect("actual finalizer loss is adjudicated once");
    assert_eq!(
        failure.gap,
        crate::semantics_objects::journal::JournalGap::H3Loss
    );
    let voided = failure
        .h3_voided
        .expect("the original H3 barrier needs acknowledgement");
    for object in &original {
        assert!(failure.effects.effects.iter().any(|effect| matches!(effect, ObjectEffect::Retired { object: id, reason: ObjectGap::OutcomeLost } if *id == object.id)));
    }
    let effects = failure.effects.clone();
    let receipts = fixture.receipts();
    {
        let a = frame
            .audited_failure_for_test(receipts[0].domain())
            .unwrap();
        let b = frame
            .audited_failure_for_test(receipts[1].domain())
            .unwrap();
        assert!(
            std::ptr::eq(a.failure(), b.failure()),
            "both domains borrow the original failure, never recomputed scope/effects"
        );
        assert!(std::ptr::eq(a.h3(), b.h3()), "same original audit H3");
        assert!(a.identity() == frame.identity());
        assert_eq!(a.frontier(), frame.frontier());
    }
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
        assert_eq!(
            frame.seal_next(&mut ports, &mut NoFrameBirths, &BirthFault),
            Ok(QuantumSealProgress::DeliveryReady)
        );
        assert_eq!(
            frame.deliver_next(&mut ports),
            Ok(QuantumSealProgress::LocalPending)
        );
        frame = match frame.finish_frame(&mut ports) {
            Err((original, reason)) => {
                assert_eq!(reason, RawQuantumRefusal::DispositionMismatch);
                original
            }
            Ok(_) => panic!("one consumer cannot acknowledge a collection-wide void"),
        };
    }
    assert_eq!(
        fixture.feeds().iter().filter(|feed| feed.degraded).count(),
        1
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        0
    );
    assert_eq!(frame.failure_for_test().unwrap().effects, effects);
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        assert_eq!(
            frame.seal_next(&mut ports, &mut NoFrameBirths, &BirthFault),
            Ok(QuantumSealProgress::DeliveryReady)
        );
        assert_eq!(
            frame.deliver_next(&mut ports),
            Ok(QuantumSealProgress::Complete)
        );
        assert_eq!(
            frame.deliver_next(&mut ports),
            Ok(QuantumSealProgress::Complete)
        );
    }
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        0,
        "delivery is not acknowledgement"
    );
    assert!(fixture.feeds().iter().all(|feed| feed.degraded
        && !feed.fallback
        && feed.reduced == 1
        && feed.staged == 0
        && feed.disposed == 1));
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame
            .finish_frame(&mut ports)
            .unwrap_or_else(|(_, reason)| {
                panic!("both original loss deliveries complete: {reason:?}")
            });
    }
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        voided
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (2, false)
    );
}

#[test]
fn joint_later_loss_precharges_newly_sealed_objects_before_mutation() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    let before = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    let targets = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .joint_feed_targets()
        .collect::<Vec<_>>();
    assert_eq!(targets.len(), 2);
    for (index, target) in targets.iter().enumerate() {
        let pid = fixture
            .scene
            .real
            .scene
            .coordinator
            .semantic_bindings()
            .get(target.caller())
            .unwrap()
            .pin()
            .pid();
        fixture.push_distinct_create(pid, 2, 0x5000 + index as u64);
    }
    let fault = FrameFault::clean();
    let mut frame = fixture.audited(2, 2, &fault);
    let h0 = fixture.scene.real.h0.clone();
    let mut births = NativeFrameBirths {
        h0: &h0,
        attached: &fixture.attached,
        retained: &mut fixture.births,
        seen: Vec::new(),
        unreadable: false,
    };
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
        assert_eq!(
            frame.seal_next(&mut ports, &mut births, &fault),
            Ok(QuantumSealProgress::DeliveryReady)
        );
        assert_eq!(
            frame.deliver_next(&mut ports),
            Ok(QuantumSealProgress::LocalPending)
        );
    }
    let grown = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    assert_eq!(
        grown.objects.len(),
        before.objects.len() + 1,
        "first seal genuinely creates a new retained view"
    );
    let new_id = grown
        .objects
        .iter()
        .find(|object| !before.objects.iter().any(|old| old.id == object.id))
        .unwrap()
        .id;
    assert_eq!(grown.object(new_id).unwrap().lifetime, Lifetime::Live);
    let snapshot = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    let hold = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .reserve_semantic_storage(snapshot.limit_bytes - snapshot.charged_bytes)
        .unwrap();
    let reads = fault.reads.get();
    fault.epoch.set(1);
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        assert!(matches!(
            frame.seal_next(&mut ports, &mut births, &fault),
            Err(RawQuantumRefusal::Resource(_))
        ));
    }
    assert_eq!(
        fault.reads.get(),
        reads,
        "post-growth retained failure capacity is prepaid before audit/fault mutation"
    );
    assert_eq!(
        births.seen.len(),
        1,
        "capacity refusal does not select or reread a birth"
    );
    assert!(frame.failure_for_test().is_none());
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .model()
            .project()
            .object(new_id)
            .unwrap()
            .lifetime,
        Lifetime::Live
    );
    drop(hold);
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        assert_eq!(
            frame.seal_next(&mut ports, &mut births, &fault),
            Ok(QuantumSealProgress::DeliveryReady)
        );
    }
    let failure = frame.failure_for_test().unwrap();
    assert_eq!(
        failure.gap,
        crate::semantics_objects::journal::JournalGap::FaultChanged
    );
    for object in &grown.objects {
        assert!(failure.effects.effects.iter().any(|effect| matches!(effect, ObjectEffect::Retired { object: id, reason: ObjectGap::OutcomeLost } if *id == object.id)), "late failure includes original and newly-created live views");
    }
    let effects = failure.effects.clone();
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        assert_eq!(
            frame.deliver_next(&mut ports),
            Ok(QuantumSealProgress::LocalPending)
        );
        assert_eq!(
            frame.seal_next(&mut ports, &mut NoFrameBirths, &fault),
            Ok(QuantumSealProgress::DeliveryReady)
        );
        assert_eq!(
            frame.deliver_next(&mut ports),
            Ok(QuantumSealProgress::Complete)
        );
    }
    assert_eq!(frame.failure_for_test().unwrap().effects, effects);
    drop(births);
    let feeds = fixture.feeds();
    assert!(feeds.iter().all(|feed| feed.degraded && feed.staged == 0));
    assert_eq!(
        feeds
            .iter()
            .find(|feed| feed.id == targets[0].id())
            .unwrap()
            .reduced,
        2,
        "already delivered success is not replayed while its original loss fans out"
    );
    assert_eq!(
        feeds
            .iter()
            .find(|feed| feed.id == targets[1].id())
            .unwrap()
            .disposed,
        1
    );
    let mut ports = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_frame_ports(&fixture.scene.producers)
        .unwrap();
    frame
        .finish_frame(&mut ports)
        .unwrap_or_else(|(_, reason)| panic!("original later loss delivered to both: {reason:?}"));
}

#[test]
fn joint_frame_preflight_keeps_targets_and_birth_selection_on_retry() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    fixture.push_two("C_SignInit", 2);
    let fault = FrameFault::clean();
    let mut frame = fixture.audited(2, 2, &fault);
    let identity = frame.identity();
    let frontier = frame.frontier();
    let before = fixture.feeds();
    let foreign = SessionDrainProducers::test_pair(
        fixture.scene.producers.native_domain(),
        EventsDomain::test_standin(fixture.scene.producers.events_id()),
    );
    assert!(
        matches!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&foreign),
            Err(RawQuantumRefusal::ForeignCapture)
        ),
        "equal numeric map id cannot lend the retained Session port"
    );
    let snapshot = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    let hold = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .reserve_semantic_storage(snapshot.limit_bytes - snapshot.charged_bytes)
        .unwrap();
    {
        let ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        assert!(matches!(
            frame.bind_targets(&ports),
            Err(RawQuantumRefusal::Resource(_))
        ));
    }
    assert_eq!(fixture.feeds(), before);
    assert!(frame.identity() == identity);
    assert_eq!(frame.frontier(), frontier);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes,
        snapshot.limit_bytes,
        "refused target acquisition refunds its own attempt"
    );
    drop(hold);
    {
        let ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
    }
    let targets = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .joint_feed_targets()
        .collect::<Vec<_>>();
    let h0 = fixture.scene.real.h0.clone();
    let mut births = NativeFrameBirths {
        h0: &h0,
        attached: &fixture.attached,
        retained: &mut fixture.births,
        seen: Vec::new(),
        unreadable: false,
    };
    let snapshot = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    let hold = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .reserve_semantic_storage(snapshot.limit_bytes - snapshot.charged_bytes)
        .unwrap();
    let reads = fault.reads.get();
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        assert!(matches!(
            frame.seal_next(&mut ports, &mut births, &fault),
            Err(RawQuantumRefusal::Resource(_))
        ));
    }
    assert_eq!(fault.reads.get(), reads);
    assert!(births.seen.is_empty());
    drop(hold);
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        for index in 0..2 {
            assert_eq!(
                frame.seal_next(&mut ports, &mut births, &fault),
                Ok(QuantumSealProgress::DeliveryReady)
            );
            assert_eq!(
                births.seen[index].0,
                targets[index].id(),
                "a refused attempt cannot advance the typed subject"
            );
            assert_eq!(
                frame.deliver_next(&mut ports),
                Ok(if index == 0 {
                    QuantumSealProgress::LocalPending
                } else {
                    QuantumSealProgress::Complete
                })
            );
        }
        frame
            .finish_frame(&mut ports)
            .unwrap_or_else(|(_, reason)| panic!("same originals retry after refund: {reason:?}"));
    }
    drop(births);
    assert!(
        fixture
            .feeds()
            .iter()
            .all(|feed| feed.reduced == 2 && feed.staged == 0 && !feed.fallback && !feed.degraded)
    );
}

#[test]
fn joint_future_end_disposes_frame_without_disposing_call() {
    let mut previous_generation = None;
    for (b_begin_first, fallback_b) in [(false, false), (true, false), (false, true), (true, true)]
    {
        eprintln!("future-END arm: b_begin_first={b_begin_first}, fallback_b={fallback_b}");
        let mut fixture = CanonicalFanoutScene::prior_sealed();
        let generation = fixture.attached.generation();
        assert!(previous_generation.is_none_or(|previous| generation > previous));
        previous_generation = Some(generation);
        let a = std::process::id();
        let b = fixture._child.id();
        let (begin_a, end_a) = fixture.scene.encoded(a, 0, "C_SignInit", 2);
        let (begin_b, end_b) = fixture.scene.encoded(b, 0, "C_SignInit", 2);
        for begin in if b_begin_first {
            [begin_b, begin_a]
        } else {
            [begin_a, begin_b]
        } {
            fixture.scene.drain.source_mut().push_record(begin.to_vec());
        }
        fixture.scene.drain.source_mut().push_record(end_b.to_vec());
        let mut q1 = fixture.audited(1, 1, &BirthFault);
        assert!(q1.failure_for_test().is_none());
        let h0 = fixture.scene.real.h0.clone();
        let b_caller = fixture
            .feeds()
            .iter()
            .find(|feed| {
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .semantic_bindings()
                    .get(feed.caller)
                    .unwrap()
                    .pin()
                    .pid()
                    == b
            })
            .unwrap()
            .caller;
        let mut births = RefuseOneBirth {
            inner: NativeFrameBirths {
                h0: &h0,
                attached: &fixture.attached,
                retained: &mut fixture.births,
                seen: Vec::new(),
                unreadable: false,
            },
            refused: fallback_b.then_some(b_caller),
        };
        {
            let mut ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            q1.bind_targets(&ports).unwrap();
            let mut future = 0;
            let mut delivered = 0;
            for _ in 0..2 {
                match q1.seal_next(&mut ports, &mut births, &BirthFault).unwrap() {
                    QuantumSealProgress::AwaitFutureInput => future += 1,
                    QuantumSealProgress::DeliveryReady => {
                        delivered += 1;
                        assert!(matches!(
                            q1.deliver_next(&mut ports).unwrap(),
                            QuantumSealProgress::LocalPending
                                | QuantumSealProgress::AwaitFutureInput
                        ));
                    }
                    progress => panic!("unexpected q1 progress: {progress:?}"),
                }
            }
            assert_eq!((future, delivered), (1, 1));
            assert_eq!(
                q1.seal_next(&mut ports, &mut births, &BirthFault),
                Ok(QuantumSealProgress::AwaitFutureInput)
            );
        }
        drop(births);
        let starts = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test();
        assert_eq!(starts.len(), 1);
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
                .retained_start_bytes_for_test((u64::from(a), 2)),
            Some(begin_a),
            "fallback retains the exact original incomplete START bytes"
        );
        assert_eq!(
            (starts[0].0, starts[0].1),
            (u64::from(a), 2),
            "the original actual A START remains unconverted"
        );
        fixture.scene.assert_claims(&[]);
        let roles = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test();
        assert_eq!(
            roles[..4],
            [0, 1, 0, 0],
            "q1 releases physical raw/H9 and keeps only original A H8 custody; associations have their own owners"
        );
        {
            let mut ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            q1.finish_frame(&mut ports).unwrap_or_else(|(_, reason)| {
                panic!("future genuine END releases only the completed frame: {reason:?}")
            });
        }
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
                .retained_starts_for_test(),
            starts
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .ledger()
                .roles_for_test(),
            roles
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
                .retained_start_bytes_for_test((u64::from(a), 2)),
            Some(begin_a)
        );
        let before_b = fixture
            .feeds()
            .into_iter()
            .find(|feed| {
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .semantic_bindings()
                    .get(feed.caller)
                    .unwrap()
                    .pin()
                    .pid()
                    == b
            })
            .unwrap();
        assert_eq!((before_b.reduced, before_b.staged), (2, 0));
        assert_eq!(before_b.fallback, fallback_b);
        // The SAME original END arrives through the SAME actual consumer later.
        fixture.scene.drain.source_mut().push_record(end_a.to_vec());
        let mut q2 = fixture.audited(1, 1, &BirthFault);
        assert!(q2.failure_for_test().is_none());
        let mut births = NativeFrameBirths {
            h0: &h0,
            attached: &fixture.attached,
            retained: &mut fixture.births,
            seen: Vec::new(),
            unreadable: false,
        };
        {
            let mut ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            q2.bind_targets(&ports).unwrap();
            let target_count = if fallback_b { 1 } else { 2 };
            for index in 0..target_count {
                assert_eq!(
                    q2.seal_next(&mut ports, &mut births, &BirthFault),
                    Ok(QuantumSealProgress::DeliveryReady)
                );
                assert_eq!(
                    q2.deliver_next(&mut ports),
                    Ok(if index + 1 < target_count {
                        QuantumSealProgress::LocalPending
                    } else {
                        QuantumSealProgress::Complete
                    })
                );
            }
            q2.finish_frame(&mut ports)
                .unwrap_or_else(|(_, reason)| panic!("actual later END settles once: {reason:?}"));
        }
        drop(births);
        assert!(fixture.feeds().iter().all(|feed| {
            feed.reduced == 2
                && feed.staged == 0
                && !feed.degraded
                && feed.fallback == (fallback_b && feed.id == before_b.id)
        }));
        assert_eq!(
            fixture
                .feeds()
                .into_iter()
                .find(|feed| feed.id == before_b.id)
                .unwrap(),
            before_b,
            "empty later work cannot replay or erase B"
        );
        assert!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
                .retained_starts_for_test()
                .is_empty()
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .ledger()
                .roles_for_test()[..4],
            [0, 0, 0, 0]
        );
        fixture.scene.assert_claims(&[]);
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_h3_audit_state(),
            (3, false)
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_h3_acknowledged_below(),
            0,
            "a future terminal wait never invents a loss void"
        );
    }
}

struct PendingH3Scene {
    fixture: CanonicalFanoutScene,
    frame: IngestedJointQuantum,
    child_c: OwnedStoppedChild,
    c_caller: CallerId,
    c_image: ImageIdentity,
    end_b: [u8; 632],
}

fn pending_h3_from_stash(
    unmatched_complete: bool,
    audit_fault: &impl crate::semantics_objects::journal::FaultEpoch,
) -> PendingH3Scene {
    let mut fixture =
        CanonicalFanoutScene::prior_sealed_with_providers(if unmatched_complete { 2 } else { 1 });
    let a = std::process::id();
    let b = fixture._child.id();
    let child_c = OwnedStoppedChild::new();
    let c = child_c.id();
    let c_image = ImageIdentity {
        task_cookie: 73,
        exec_id: 0,
    };
    let c_caller = fixture.scene.real.bind(c, c_image, 0);
    let (begin_b, end_b) = fixture.scene.encoded(b, 0, "C_SignInit", 2);
    fixture.scene.push(a, 0, "C_SignInit", 2);
    fixture.scene.push(c, 0, "C_SignInit", 1);
    fixture
        .scene
        .drain
        .source_mut()
        .push_record(begin_b.to_vec());
    if unmatched_complete {
        let caller = fixture
            .births
            .iter()
            .find(|(caller, _, _)| {
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .semantic_bindings()
                    .get(*caller)
                    .unwrap()
                    .pin()
                    .pid()
                    == a
            })
            .unwrap()
            .0;
        fixture.scene.admit_providers(a, caller, &[1]);
        fixture.scene.push(a, 1, "C_SignInit", 3);
    }
    let mut raw = fixture.scene.collect_with_fault(&BirthFault);
    let first = {
        let mut h0 = fixture.scene.real.h0.0.borrow_mut();
        let HeldH0 { capture, io, .. } = &mut *h0;
        io.script.fail_cookie = Some(c_image.task_cookie);
        let first = capture.tick_collected_with(io, &mut raw).unwrap();
        assert_eq!(first.calls().count(), 1 + usize::from(unmatched_complete));
        assert_eq!(first.awaiting_floor(), Some(4));
        first
    };
    let first = SemanticBatch::from_tick_report(
        fixture.scene.real.lane.domain(),
        first,
        Vec::new(),
        now_ns(),
    )
    .unwrap();
    {
        let mut h0 = fixture.scene.real.h0.0.borrow_mut();
        let HeldH0 {
            capture, io, stash, ..
        } = &mut *h0;
        io.script.fail_cookie = None;
        // The actual original scan job owns the q1 birth cut. An empty
        // service of the SAME raw clears its actual pending disposition;
        // every resulting call/receipt moves into the existing lane stash.
        let mut completed = capture.tick_collected_with(io, &mut raw).unwrap();
        assert_eq!(completed.calls().count(), 1);
        assert_eq!(completed.awaiting_floor(), None);
        assert_eq!(
            completed.allocated_below(),
            5 + u64::from(unmatched_complete)
        );
        assert_eq!(completed.calls().next().unwrap().position(), Some(4));
        assert_eq!(stash_refresh_report(stash, &mut completed).1, 0);
        assert_eq!(stash.min_outcome_position(), Some(4));
    }
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    coordinator.stage_semantic_batch(first);
    coordinator
        .prepare_staged_semantic_batch(&mut fixture.scene.real.lane, None)
        .unwrap();
    assert_eq!(
        coordinator
            .prepared_semantic_batch()
            .unwrap()
            .admissions()
            .count(),
        1 + usize::from(unmatched_complete)
    );
    let ingested = raw
        .ingest(
            coordinator.joint_capture_mut().adapter_mut(),
            &fixture.scene.producers,
            &fixture.grant,
        )
        .unwrap_or_else(|(_, reason)| {
            panic!("the genuine same raw is now H0 disposed: {reason:?}")
        });
    let first_claim = coordinator
        .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
        .unwrap()
        .unwrap();
    assert_eq!(first_claim.0, 3);
    assert!(first_claim.1.is_ok());
    if unmatched_complete {
        assert_eq!(
            coordinator
                .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
                .unwrap(),
            Some((
                5,
                Err(crate::semantics_objects::journal::AttestationRefusal::ImageSealed)
            )),
            "late provider is genuinely admitted but cannot replace the already-sealed image key"
        );
    }
    assert!(
        coordinator
            .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
            .unwrap()
            .is_none()
    );
    let mut staged = 0;
    while coordinator.stage_next_prepared_admission() {
        staged += 1;
    }
    assert_eq!(staged, 1 + usize::from(unmatched_complete));
    assert!(coordinator.finish_prepared_semantic_batch(&fixture.scene.real.lane));
    fixture
        .scene
        .real
        .scene
        .coordinator
        .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
        .unwrap();
    let q1 = acquire(&mut fixture.scene, ingested, &fixture.attached, audit_fault);

    PendingH3Scene {
        fixture,
        frame: q1,
        child_c,
        c_caller,
        c_image,
        end_b,
    }
}

/// Catches treating truthful acquired H3Pending as a permanent local retry.
/// The deferred call is an original collected END, resolved by its existing
/// H0 scan job and retained in the real lane stash; B also keeps a real START.
#[test]
fn joint_pending_h3_stash_disposes_frame_and_claims_original_in_next_quantum() {
    let PendingH3Scene {
        mut fixture,
        frame: mut q1,
        child_c,
        c_caller,
        c_image,
        end_b,
    } = pending_h3_from_stash(false, &BirthFault);
    let c = child_c.id();
    let b = fixture._child.id();
    assert_eq!(
        q1.failure_for_test().unwrap().gap,
        crate::semantics_objects::journal::JournalGap::H3Pending
    );
    assert!(matches!(
        q1.audit_for_test().h3_for_test(),
        H3DispositionEvidence::Clean {
            staged_max: 3,
            pending_floor: Some(4),
        }
    ));
    let before_feeds = fixture.feeds();
    let before_claims = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .adapter()
        .invocation_claims_for_test();
    assert_eq!(before_claims.0, 1);
    assert_eq!(
        before_claims
            .1
            .iter()
            .map(|(at, _)| *at)
            .collect::<Vec<_>>(),
        [3]
    );
    let before_roles = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .ledger()
        .roles_for_test();
    assert_eq!(before_roles[..4], [0, 3, 0, 1]);
    assert_eq!(
        crate::semantics_objects::journal::JournalAdapter::open_entry_size_for_test(),
        1160
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .retained_open_charges_for_test(),
        [1160; 3]
    );
    let before_starts = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .adapter()
        .retained_starts_for_test();
    assert_eq!(before_starts.len(), 3);
    let start_b = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .adapter()
        .retained_start_bytes_for_test((u64::from(b), 2))
        .unwrap();
    let h0 = fixture.scene.real.h0.clone();
    let mut births = NativeFrameBirths {
        h0: &h0,
        attached: &fixture.attached,
        retained: &mut fixture.births,
        seen: Vec::new(),
        unreadable: false,
    };
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        q1.bind_targets(&ports).unwrap();
        let real_producers = h0.0.borrow().collected_producers.clone().unwrap();
        h0.0.borrow_mut().collected_producers = Some(SessionDrainProducers::test_pair(
            real_producers.native_domain(),
            crate::events::EventsDomain::test_standin(real_producers.events_id()),
        ));
        assert_eq!(
            q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
            Ok(QuantumSealProgress::LocalPending),
            "equal numeric EVENTS identity cannot grant a foreign allocation continuation"
        );
        h0.0.borrow_mut().collected_producers = Some(real_producers);
        let retained_outcomes = h0.0.borrow_mut().stash.take_outcomes();
        assert_eq!(
            q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
            Ok(QuantumSealProgress::LocalPending),
            "the old floor grants nothing after actual stash ownership moved"
        );
        assert_eq!(
            h0.0.borrow_mut()
                .stash
                .push_all(Vec::new(), retained_outcomes),
            0
        );
        for _ in 0..2 {
            assert_eq!(
                q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
                Ok(QuantumSealProgress::AwaitFutureInput)
            );
        }
        assert_eq!(
            q1.seal_next(&mut ports, &mut births, &BirthFault),
            Ok(QuantumSealProgress::AwaitFutureInput)
        );
        let (retained, reason) = q1
            .finish_frame(&mut ports)
            .err()
            .expect("generic finish has no continuation authority");
        assert_eq!(reason, RawQuantumRefusal::H3Undisposed);
        q1 = retained;
        q1.finish_pending_h3(&mut ports, &fixture.scene.real.lane)
            .unwrap_or_else(|(_, reason)| {
                panic!("truthful producer-owned pending evidence must allow q2: {reason:?}")
            });
    }
    drop(births);
    assert_eq!(fixture.feeds(), before_feeds);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test(),
        before_claims
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test(),
        before_roles
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test(),
        before_starts
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .retained_start_bytes_for_test((u64::from(b), 2)),
        Some(start_b)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        0
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (2, false)
    );

    // q2 receives B's exact END and merges C's original Call/New. H0 ordinal
    // order is C=4, then B=5 even though the ring returns B before the merge.
    fixture.scene.drain.source_mut().push_record(end_b.to_vec());
    let raw = fixture.scene.collect_with_fault(&BirthFault);
    fixture.scene.real.h0.0.borrow_mut().collected = Some(raw);
    let batch = fixture.scene.real.tick();
    fixture.scene.admit_providers(c, c_caller, &[0]);
    fixture.scene.prepare_batch(batch, 2);
    let admitted = fixture
        .scene
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap()
        .admissions()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        admitted
            .iter()
            .map(|input| input.h0_ordinal())
            .collect::<Vec<_>>(),
        [4, 5]
    );
    let current = fixture
        .scene
        .real
        .scene
        .coordinator
        .take_prepared_current_for_birth_test()
        .unwrap();
    let current_c = current
        .into_iter()
        .find(|receipt| receipt.image() == c_image)
        .unwrap();
    let raw = fixture
        .scene
        .real
        .h0
        .0
        .borrow_mut()
        .collected
        .take()
        .unwrap();
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
        .unwrap_or_else(|(_, reason)| panic!("actual next raw: {reason:?}"));
    assert!(
        !ingested.matches_admission(&admitted[0]),
        "C is still the actual q1 allocation"
    );
    assert!(
        ingested.matches_retained_admission(
            &admitted[0],
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
        )
    );
    let claims = claim_and_finish(&mut fixture.scene, &ingested);
    assert!(
        !ingested.matches_retained_admission(
            &admitted[0],
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
        ),
        "the original is claimed at most once"
    );
    assert_eq!(claims.iter().map(|(at, _)| *at).collect::<Vec<_>>(), [4, 5]);
    let actual_claims = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .adapter()
        .invocation_claims_for_test();
    assert_eq!(actual_claims.0, 3);
    assert_eq!(
        actual_claims
            .1
            .iter()
            .map(|(at, _)| *at)
            .collect::<Vec<_>>(),
        [3, 4, 5]
    );
    fixture.retain_collected_birth(&admitted[0], current_c, claims[0].1);
    fixture
        .scene
        .real
        .scene
        .coordinator
        .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
        .unwrap();
    let mut q2 = acquire(&mut fixture.scene, ingested, &fixture.attached, &BirthFault);
    assert!(q2.failure_for_test().is_none());
    let h0 = fixture.scene.real.h0.clone();
    let mut births = NativeFrameBirths {
        h0: &h0,
        attached: &fixture.attached,
        retained: &mut fixture.births,
        seen: Vec::new(),
        unreadable: false,
    };
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        q2.bind_targets(&ports).unwrap();
        for remaining in [2, 1, 0] {
            assert_eq!(
                q2.seal_next(&mut ports, &mut births, &BirthFault),
                Ok(QuantumSealProgress::DeliveryReady)
            );
            assert_eq!(
                q2.deliver_next(&mut ports),
                Ok(if remaining == 0 {
                    QuantumSealProgress::Complete
                } else {
                    QuantumSealProgress::LocalPending
                })
            );
        }
        q2.finish_frame(&mut ports)
            .unwrap_or_else(|(_, reason)| panic!("originals settle once: {reason:?}"));
    }
    drop(births);
    assert_eq!(
        fixture.feeds().iter().map(|feed| feed.reduced).sum::<u64>(),
        5
    );
    assert!(
        fixture
            .feeds()
            .iter()
            .all(|feed| feed.staged == 0 && !feed.degraded && !feed.fallback)
    );
    fixture.scene.assert_claims(&[]);
    assert!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test()
            .is_empty()
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test()[..4],
        [0, 0, 0, 0]
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        0
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (3, false)
    );
}

#[test]
fn joint_pending_h3_keeps_unmatched_complete_original_local() {
    let PendingH3Scene {
        mut fixture,
        frame: mut q1,
        child_c: _child_c,
        c_caller: _,
        c_image: _,
        end_b: _,
    } = pending_h3_from_stash(true, &BirthFault);
    assert_eq!(
        q1.failure_for_test().unwrap().gap,
        crate::semantics_objects::journal::JournalGap::H3Pending
    );
    assert!(matches!(
        q1.audit_for_test().h3_for_test(),
        H3DispositionEvidence::Clean {
            staged_max: 5,
            pending_floor: Some(4),
        }
    ));
    let before_feeds = fixture.feeds();
    let owner = fixture.scene.real.scene.coordinator.joint_capture();
    let claims = owner.adapter().invocation_claims_for_test();
    let starts = owner.adapter().retained_starts_for_test();
    let roles = owner.ledger().roles_for_test();
    assert_eq!(starts.len(), 4);
    assert_eq!(claims.0, 1);
    assert_eq!(roles[..4], [0, 4, 0, 1]);
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        q1.bind_targets(&ports).unwrap();
        for _ in 0..2 {
            assert_eq!(
                q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
                Ok(QuantumSealProgress::LocalPending)
            );
        }
        let (same, reason) = q1
            .finish_pending_h3(&mut ports, &fixture.scene.real.lane)
            .err()
            .expect("a truthful floor cannot forgive an unrelated completed original");
        assert_eq!(reason, RawQuantumRefusal::H3Undisposed);
        q1 = same;
        assert!(q1.finish_frame(&mut ports).is_err());
    }
    assert_eq!(fixture.feeds(), before_feeds);
    let owner = fixture.scene.real.scene.coordinator.joint_capture();
    assert_eq!(owner.adapter().invocation_claims_for_test(), claims);
    assert_eq!(owner.adapter().retained_starts_for_test(), starts);
    assert_eq!(owner.ledger().roles_for_test(), roles);
    assert_eq!(
        fixture
            .scene
            .real
            .h0
            .0
            .borrow()
            .stash
            .min_outcome_position(),
        Some(4)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (2, false)
    );
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

#[test]
fn joint_pending_h3_continuation_cannot_forgive_native_fault() {
    struct ChangedFault;
    impl crate::semantics_objects::journal::FaultEpoch for ChangedFault {
        fn fault_epoch(&self) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
            Ok(1)
        }
    }
    let PendingH3Scene {
        mut fixture,
        frame: mut q1,
        child_c: _child_c,
        c_caller: _,
        c_image: _,
        end_b: _,
    } = pending_h3_from_stash(false, &ChangedFault);
    let original = q1.failure_for_test().unwrap();
    assert_eq!(
        original.gap,
        crate::semantics_objects::journal::JournalGap::FaultChanged
    );
    assert!(
        !original.effects.effects.is_empty(),
        "the same two original live objects must produce actual loss effects"
    );
    let effects = original.effects.clone();
    let roles = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .ledger()
        .roles_for_test();
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        q1.bind_targets(&ports).unwrap();
        assert_eq!(
            q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
            Ok(QuantumSealProgress::LocalPending)
        );
        assert_eq!(q1.failure_for_test().unwrap().effects, effects);
        let (same, reason) = q1
            .finish_pending_h3(&mut ports, &fixture.scene.real.lane)
            .err()
            .expect("a real pending owner never changes an original fault into Future");
        assert_eq!(reason, RawQuantumRefusal::H3Undisposed);
        q1 = same;
    }
    assert_eq!(q1.failure_for_test().unwrap().effects, effects);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test(),
        roles
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (2, false)
    );
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

#[test]
fn joint_first_pending_h3_pins_native_baseline_before_next_fault() {
    // This owner has never acquired a healthy audit or sealed a model call.
    // A's genuine New still registers one Joint consumer before its first
    // pending audit; C's original remains in the same real lane stash.
    let mut scene = JointScene::for_audit(1);
    scene.real.h0.0.borrow_mut().io.script.local = 1;
    let a = std::process::id();
    let child_b = OwnedStoppedChild::new();
    let child_c = OwnedStoppedChild::new();
    let a_caller = scene.real.bind(
        a,
        ImageIdentity {
            task_cookie: 71,
            exec_id: 0,
        },
        0,
    );
    scene.real.bind(
        child_b.id(),
        ImageIdentity {
            task_cookie: 72,
            exec_id: 0,
        },
        0,
    );
    let c_image = ImageIdentity {
        task_cookie: 73,
        exec_id: 0,
    };
    scene.real.bind(child_c.id(), c_image, 0);
    scene.push(a, 0, "C_SignInit", 1);
    scene.push(child_c.id(), 0, "C_SignInit", 1);
    let begin_b = scene.encoded(child_b.id(), 0, "C_SignInit", 1).0;
    scene.drain.source_mut().push_record(begin_b.to_vec());
    let mut raw = scene.collect_with_fault(&BirthFault);
    let first = {
        let mut h0 = scene.real.h0.0.borrow_mut();
        let HeldH0 { capture, io, .. } = &mut *h0;
        io.script.fail_cookie = Some(c_image.task_cookie);
        let first = capture.tick_collected_with(io, &mut raw).unwrap();
        assert_eq!(first.calls().count(), 1);
        assert_eq!(first.awaiting_floor(), Some(2));
        first
    };
    let batch =
        SemanticBatch::from_tick_report(scene.real.lane.domain(), first, Vec::new(), now_ns())
            .unwrap();
    scene.admit_providers(a, a_caller, &[0]);
    {
        let mut h0 = scene.real.h0.0.borrow_mut();
        let HeldH0 {
            capture,
            io,
            stash,
            collected_producers,
            ..
        } = &mut *h0;
        *collected_producers = Some(raw.producers_for_test().clone());
        io.script.fail_cookie = None;
        let mut completed = capture.tick_collected_with(io, &mut raw).unwrap();
        assert_eq!(completed.calls().next().unwrap().position(), Some(2));
        assert_eq!(completed.awaiting_floor(), None);
        assert_eq!(stash_refresh_report(stash, &mut completed).1, 0);
    }
    scene.real.scene.coordinator.stage_semantic_batch(batch);
    scene
        .real
        .scene
        .coordinator
        .prepare_staged_semantic_batch(&mut scene.real.lane, None)
        .unwrap();
    let admitted = scene
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap()
        .admissions()
        .next()
        .unwrap()
        .clone();
    let current = scene
        .real
        .scene
        .coordinator
        .take_prepared_current_for_birth_test()
        .unwrap()
        .into_iter()
        .find(|receipt| receipt.image() == admitted.journal_binding().1)
        .unwrap();
    let (ingested, proof, grant) = scene.ingest_with_grant(raw);
    assert_eq!(claim_and_finish(&mut scene, &ingested).len(), 1);
    let attached = attachment(&mut scene);
    assert!(
        scene
            .real
            .scene
            .coordinator
            .joint_capture_mut()
            .adapter_mut()
            .install_closure_grant(&SessionClosureGrant::observe(&attached))
    );
    let mut fixture = CanonicalFanoutScene {
        scene,
        attached,
        births: Vec::new(),
        grant,
        _child: child_b,
    };
    fixture.retain_collected_birth(&admitted, current, proof);
    fixture
        .scene
        .real
        .scene
        .coordinator
        .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
        .unwrap();
    let mut q1 = acquire(&mut fixture.scene, ingested, &fixture.attached, &BirthFault);
    assert_eq!(
        q1.failure_for_test().unwrap().gap,
        crate::semantics_objects::journal::JournalGap::H3Pending
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .fault_baseline_for_test(),
        None
    );
    let roles = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .ledger()
        .roles_for_test();
    let claims = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .adapter()
        .invocation_claims_for_test();
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        q1.bind_targets(&ports).unwrap();
        assert_eq!(
            q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
            Ok(QuantumSealProgress::AwaitFutureInput)
        );
        q1.finish_pending_h3(&mut ports, &fixture.scene.real.lane)
            .unwrap_or_else(|(_, reason)| panic!("actual first pending frame: {reason:?}"));
    }
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .fault_baseline_for_test(),
        Some(0)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test(),
        roles
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test(),
        claims
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        0
    );
    struct ChangedFault;
    impl crate::semantics_objects::journal::FaultEpoch for ChangedFault {
        fn fault_epoch(&self) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
            Ok(1)
        }
    }
    fixture
        .scene
        .real
        .h0
        .0
        .borrow_mut()
        .io
        .script
        .last_health
        .fault = 1;
    let raw = fixture.scene.collect_with_fault(&ChangedFault);
    fixture.scene.real.h0.0.borrow_mut().collected = Some(raw);
    let batch = fixture.scene.real.tick();
    fixture
        .scene
        .real
        .scene
        .coordinator
        .stage_semantic_batch(batch);
    fixture
        .scene
        .real
        .scene
        .coordinator
        .prepare_staged_semantic_batch(&mut fixture.scene.real.lane, None)
        .unwrap();
    let raw = fixture
        .scene
        .real
        .h0
        .0
        .borrow_mut()
        .collected
        .take()
        .unwrap();
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
        .unwrap_or_else(|(_, reason)| panic!("genuine q2 fault collection: {reason:?}"));
    while fixture
        .scene
        .real
        .scene
        .coordinator
        .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
        .unwrap()
        .is_some()
    {}
    while fixture
        .scene
        .real
        .scene
        .coordinator
        .stage_next_prepared_admission()
    {}
    assert!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .finish_prepared_semantic_batch(&fixture.scene.real.lane)
    );
    fixture
        .scene
        .real
        .scene
        .coordinator
        .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
        .unwrap();
    let q2 = acquire(
        &mut fixture.scene,
        ingested,
        &fixture.attached,
        &ChangedFault,
    );
    assert_eq!(
        q2.failure_for_test().unwrap().gap,
        crate::semantics_objects::journal::JournalGap::FaultChanged
    );
}

struct ZeroHeadPendingScene {
    fixture: CanonicalFanoutScene,
    frame: IngestedJointQuantum,
    caller: CallerId,
    image: ImageIdentity,
}

fn first_pending_h3_without_joint_head() -> ZeroHeadPendingScene {
    let (held, subset) = HeldProviders::with_attachment(
        1,
        &[
            "C_GetSessionInfo",
            "C_SignInit",
            "C_SignUpdate",
            "C_SignFinal",
        ],
    );
    let mut scene = JointScene::from_held(held, Some(subset));
    scene.real.h0.0.borrow_mut().io.script.local = 1;
    let a = std::process::id();
    scene.bind(
        a,
        ImageIdentity {
            task_cookie: 71,
            exec_id: 0,
        },
        &[0],
    );
    // The actual ordinary allowlisted GetSessionInfo establishes the native
    // Session association on direct S1. It has no journal invocation, grants
    // no birth, and is proved irrelevant before its original raw is disposed.
    let mut quiet = scene.encoded(a, 0, "C_GetSessionInfo", 1).1;
    // Ordinary synchronous CALL uses the real producer's no-async-target
    // sentinel. Canonical admission, never this scalar, proves irrelevance.
    quiet[24 + 108..24 + 112].copy_from_slice(&u32::MAX.to_le_bytes());
    scene
        .drain
        .source_mut()
        .push_record(quiet[24..392].to_vec());
    let mut raw = scene.prepare(1);
    let input = scene
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap()
        .admissions()
        .next()
        .unwrap()
        .clone();
    assert_eq!(input.s1_facts().function, "C_GetSessionInfo");
    raw.classify_ordinary(&input).unwrap();
    let grant = SessionDrainGrant::observe(&scene.producers, &input).unwrap();
    let owner = scene.real.scene.coordinator.joint_capture_mut();
    owner.adapter_mut().bind_admitted_key(&input).unwrap();
    owner.adapter_mut().bind_session_drain(&grant).unwrap();
    let disposed = raw
        .dispose_without_ingest(
            owner,
            &scene.producers,
            crate::semantics_objects::journal::joint_driver::RawDisposeReason::NoAdmission,
        )
        .unwrap_or_else(|(_, reason)| panic!("actual quiet direct-S1 raw: {reason:?}"));
    assert!(disposed.failure().is_none());
    scene.real.scene.coordinator.dispose_prepared_claims_s1();
    assert!(scene.real.scene.coordinator.stage_next_prepared_admission());
    assert!(!scene.real.scene.coordinator.stage_next_prepared_admission());
    assert!(
        scene
            .real
            .scene
            .coordinator
            .finish_prepared_semantic_batch(&scene.real.lane)
    );
    scene
        .real
        .scene
        .coordinator
        .commit_batch_with_semantics(false, Some(&mut scene.real.lane))
        .unwrap();
    assert_eq!(
        scene
            .real
            .scene
            .coordinator
            .registry()
            .joint_feed_targets()
            .count(),
        0
    );
    assert_eq!(scene.real.scene.coordinator.reference_h3_audit_state().0, 0);
    assert_eq!(
        scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .fault_baseline_for_test(),
        None
    );
    drop(disposed);

    let child = OwnedStoppedChild::new();
    let image = ImageIdentity {
        task_cookie: 73,
        exec_id: 0,
    };
    let caller = scene.real.bind(child.id(), image, 0);
    scene.push(child.id(), 0, "C_SignInit", 1);
    let mut raw = scene.collect_with_fault(&BirthFault);
    let first = {
        let mut h0 = scene.real.h0.0.borrow_mut();
        let HeldH0 { capture, io, .. } = &mut *h0;
        io.script.fail_cookie = Some(image.task_cookie);
        let first = capture.tick_collected_with(io, &mut raw).unwrap();
        assert_eq!(first.calls().count(), 0);
        assert_eq!(first.awaiting_floor(), Some(2));
        first
    };
    let batch =
        SemanticBatch::from_tick_report(scene.real.lane.domain(), first, Vec::new(), now_ns())
            .unwrap();
    {
        let mut h0 = scene.real.h0.0.borrow_mut();
        let HeldH0 {
            capture, io, stash, ..
        } = &mut *h0;
        io.script.fail_cookie = None;
        let mut completed = capture.tick_collected_with(io, &mut raw).unwrap();
        assert_eq!(completed.calls().next().unwrap().position(), Some(2));
        assert_eq!(completed.awaiting_floor(), None);
        assert_eq!(stash_refresh_report(stash, &mut completed).1, 0);
    }
    let coordinator = &mut scene.real.scene.coordinator;
    coordinator.stage_semantic_batch(batch);
    coordinator
        .prepare_staged_semantic_batch(&mut scene.real.lane, None)
        .unwrap();
    assert_eq!(
        coordinator
            .prepared_semantic_batch()
            .unwrap()
            .admissions()
            .count(),
        0
    );
    let ingested = raw
        .ingest(
            coordinator.joint_capture_mut().adapter_mut(),
            &scene.producers,
            &grant,
        )
        .unwrap_or_else(|(_, reason)| panic!("actual no-head pending original: {reason:?}"));
    assert!(
        coordinator
            .claim_next_prepared_admission(&scene.producers, &ingested)
            .unwrap()
            .is_none()
    );
    assert!(!coordinator.stage_next_prepared_admission());
    assert!(coordinator.finish_prepared_semantic_batch(&scene.real.lane));
    coordinator
        .commit_batch_with_semantics(false, Some(&mut scene.real.lane))
        .unwrap();
    let attached = attachment(&mut scene);
    let mut fixture = CanonicalFanoutScene {
        scene,
        attached,
        births: Vec::new(),
        grant,
        _child: child,
    };
    let frame = acquire(&mut fixture.scene, ingested, &fixture.attached, &BirthFault);
    assert_eq!(
        frame.failure_for_test().unwrap().gap,
        crate::semantics_objects::journal::JournalGap::H3Pending
    );
    assert!(matches!(
        frame.audit_for_test().h3_for_test(),
        H3DispositionEvidence::Clean {
            staged_max: 1,
            pending_floor: Some(2),
        }
    ));
    ZeroHeadPendingScene {
        fixture,
        frame,
        caller,
        image,
    }
}

#[test]
fn joint_zero_head_pending_h3_requires_original_continuation_and_keeps_fault_prefix() {
    for changed_fault in [false, true] {
        let ZeroHeadPendingScene {
            mut fixture,
            mut frame,
            caller,
            image,
        } = first_pending_h3_without_joint_head();
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .joint_feed_targets()
                .count(),
            0
        );
        let owner = fixture.scene.real.scene.coordinator.joint_capture();
        let starts = owner.adapter().retained_starts_for_test();
        let claims = owner.adapter().invocation_claims_for_test();
        let roles = owner.ledger().roles_for_test();
        assert_eq!(starts.len(), 1);
        assert_eq!(claims.0, 0);
        assert_eq!(roles[..4], [0, 1, 0, 0]);
        assert_eq!(owner.adapter().fault_baseline_for_test(), None);
        {
            let mut ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            frame.bind_targets(&ports).unwrap();
            let (same, reason) = frame.finish_frame(&mut ports).err().expect(
                "zero eligible heads do not forgive actual pending H3 or its native prefix",
            );
            assert_eq!(reason, RawQuantumRefusal::H3Undisposed);
            frame = same;
        }
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
                .fault_baseline_for_test(),
            None,
            "generic refusal preserves the first native baseline"
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .ledger()
                .roles_for_test(),
            roles
        );
        let retained_outcomes = fixture.scene.real.h0.0.borrow_mut().stash.take_outcomes();
        {
            let mut ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            let (same, reason) = frame
                .finish_pending_h3(&mut ports, &fixture.scene.real.lane)
                .err()
                .expect("a zero-head finish still needs actual stash ownership");
            assert_eq!(reason, RawQuantumRefusal::H3Undisposed);
            frame = same;
        }
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
                .fault_baseline_for_test(),
            None
        );
        assert_eq!(
            fixture
                .scene
                .real
                .h0
                .0
                .borrow_mut()
                .stash
                .push_all(Vec::new(), retained_outcomes),
            0
        );
        {
            let mut ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            // Explicit disposal must revalidate the actual owner even when
            // no domain consumer needed a separate defer operation.
            frame
                .finish_pending_h3(&mut ports, &fixture.scene.real.lane)
                .unwrap_or_else(|(_, reason)| {
                    panic!("actual zero-head continuation progresses: {reason:?}")
                });
        }
        let owner = fixture.scene.real.scene.coordinator.joint_capture();
        assert_eq!(owner.adapter().retained_starts_for_test(), starts);
        assert_eq!(owner.adapter().invocation_claims_for_test(), claims);
        assert_eq!(owner.ledger().roles_for_test(), roles);
        assert_eq!(owner.adapter().fault_baseline_for_test(), Some(0));
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_h3_audit_state(),
            (1, false)
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_h3_acknowledged_below(),
            0
        );
        struct NextFault(bool);
        impl crate::semantics_objects::journal::FaultEpoch for NextFault {
            fn fault_epoch(
                &self,
            ) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
                Ok(u64::from(self.0))
            }
        }
        fixture
            .scene
            .real
            .h0
            .0
            .borrow_mut()
            .io
            .script
            .last_health
            .fault = u64::from(changed_fault);
        let fault = NextFault(changed_fault);
        let raw = fixture.scene.collect_with_fault(&fault);
        fixture.scene.real.h0.0.borrow_mut().collected = Some(raw);
        let batch = fixture.scene.real.tick();
        if !changed_fault {
            fixture
                .scene
                .admit_providers(fixture._child.id(), caller, &[0]);
        }
        let coordinator = &mut fixture.scene.real.scene.coordinator;
        coordinator.stage_semantic_batch(batch);
        coordinator
            .prepare_staged_semantic_batch(&mut fixture.scene.real.lane, None)
            .unwrap();
        let admitted = coordinator
            .prepared_semantic_batch()
            .unwrap()
            .admissions()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].h0_ordinal(), 2);
        let current = coordinator.take_prepared_current_for_birth_test().unwrap();
        let raw = fixture
            .scene
            .real
            .h0
            .0
            .borrow_mut()
            .collected
            .take()
            .unwrap();
        let ingested = raw
            .ingest(
                coordinator.joint_capture_mut().adapter_mut(),
                &fixture.scene.producers,
                &fixture.grant,
            )
            .unwrap_or_else(|(_, reason)| panic!("actual zero-head q2: {reason:?}"));
        let mut q2_proof = None;
        while let Some((ordinal, proof)) = coordinator
            .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
            .unwrap()
        {
            let owner = coordinator.joint_capture();
            assert_eq!(owner.adapter().retained_starts_for_test(), starts);
            assert_eq!(ordinal, 2);
            let proof = proof.expect("the same retained original claims before audit");
            assert_eq!(
                owner.adapter().invocation_claims_for_test(),
                (1, vec![(2, proof)])
            );
            assert_eq!(owner.ledger().roles_for_test()[..4], [0, 1, 0, 0]);
            assert!(q2_proof.replace(proof).is_none());
        }
        let proof = q2_proof.expect("the original is claimed exactly once in either arm");
        while coordinator.stage_next_prepared_admission() {}
        assert!(coordinator.finish_prepared_semantic_batch(&fixture.scene.real.lane));
        // A retained claim corroborates the original before the collection
        // audit. Only the healthy arm may establish birth and a Joint feed.
        if !changed_fault {
            let original_new = current
                .into_iter()
                .find(|receipt| receipt.image() == image)
                .unwrap();
            fixture.retain_collected_birth(&admitted[0], original_new, proof);
        }
        fixture
            .scene
            .real
            .scene
            .coordinator
            .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
            .unwrap();
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
                .fault_baseline_for_test(),
            Some(0),
            "claiming and staging never forgive the original native prefix"
        );
        let before_audit = fixture.feeds();
        let mut q2 = acquire(&mut fixture.scene, ingested, &fixture.attached, &fault);
        if changed_fault {
            assert_eq!(
                q2.failure_for_test().unwrap().gap,
                crate::semantics_objects::journal::JournalGap::FaultChanged
            );
            assert!(fixture.births.is_empty());
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .registry()
                    .joint_feed_targets()
                    .count(),
                0
            );
            assert_eq!(fixture.feeds(), before_audit);
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .reference_h3_audit_state(),
                (2, false)
            );
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .reference_h3_acknowledged_below(),
                0
            );
            continue;
        }
        assert!(q2.failure_for_test().is_none());
        let h0 = fixture.scene.real.h0.clone();
        let mut births = NativeFrameBirths {
            h0: &h0,
            attached: &fixture.attached,
            retained: &mut fixture.births,
            seen: Vec::new(),
            unreadable: false,
        };
        {
            let mut ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            q2.bind_targets(&ports).unwrap();
            assert_eq!(
                q2.seal_next(&mut ports, &mut births, &fault),
                Ok(QuantumSealProgress::DeliveryReady)
            );
            assert_eq!(
                q2.deliver_next(&mut ports),
                Ok(QuantumSealProgress::Complete)
            );
            q2.finish_frame(&mut ports).unwrap_or_else(|(_, reason)| {
                panic!("actual first useful domain settles: {reason:?}")
            });
        }
        drop(births);
        let target = fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .joint_feed_targets()
            .next()
            .unwrap();
        assert_eq!(target.caller(), caller);
        assert!(fixture.feeds().iter().any(|feed| feed.caller == caller
            && !feed.fallback
            && feed.reduced == 1
            && feed.staged == 0));
        fixture.scene.assert_claims(&[]);
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .ledger()
                .roles_for_test()[..4],
            [0, 0, 0, 0]
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_h3_audit_state(),
            (2, false)
        );
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
}
