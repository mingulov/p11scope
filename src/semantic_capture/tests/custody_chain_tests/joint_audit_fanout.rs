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

#[derive(Clone, Copy)]
enum PublicationReceipts {
    All,
    Missing,
    Capacity(usize),
}

/// The real binder must not spend New before the same collected H0 can carry
/// its birth. Only the native I/O is substituted; no semantic binding exists
/// before this production refresh/admission path runs.
#[test]
fn joint_real_bind_refresh_preserves_collected_first_new() {
    for (tick_first, refuse_first) in [(true, false), (true, true), (false, false), (false, true)] {
        let (held, attached) = HeldProviders::with_attachment(1, &["C_CreateObject", "C_SignInit"]);
        let mut scene = JointScene::from_held(held, Some(attached));
        let pid = std::process::id();
        let image = ImageIdentity {
            task_cookie: 71,
            exec_id: 0,
        };
        SIGHT_NS.with(|clock| clock.set(1_005));
        scene.real.h0.0.borrow_mut().io.script.local = 1;
        let caller = scene.real.scene.admit(pid, 50);
        let (module, path) = &scene.real.modules[0];
        scene.real.scene.coordinator.registry_mut().note_mapping(
            caller,
            pid,
            ModuleInfo {
                path: path.clone(),
                key: module.clone(),
                double_loaded: false,
                build_id: None,
                identity_source: Some("held-provider".into()),
                admission: AdmissionState::Admitted,
                admission_class: Some("exact".into()),
                admission_endpoints: Some(2),
                admission_reasons: Vec::new(),
            },
            60,
        );
        scene.real.scene.coordinator.commit_batch(false).unwrap();
        let candidate = scene
            .real
            .scene
            .coordinator
            .prepare_legacy_semantic_candidate(caller, scene.real.lane.domain())
            .expect("the actual Detailed caller retains its first custody allocation");
        let original_pin = candidate.pin();
        drop(candidate);
        scene
            .real
            .h0
            .0
            .borrow_mut()
            .io
            .targets
            .insert(pid, (original_pin.clone(), image));
        assert_eq!(scene.real.scene.coordinator.semantic_bindings().len(), 0);
        scene.push(pid, 0, "C_CreateObject", 1);
        let raw = scene.collect_with_fault(&BirthFault);
        let original_quantum = raw.h0_identity();
        assert_eq!(raw.pending_h0_records(), 1);
        let original_boundary = scene.drain.consumption_cut().unwrap();
        scene.real.h0.0.borrow_mut().collected = Some(raw);
        let early_batch = tick_first.then(|| scene.real.tick());
        let retained_records = scene
            .real
            .h0
            .0
            .borrow()
            .collected
            .as_ref()
            .unwrap()
            .pending_h0_records();
        let roles = scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test();
        let hold = refuse_first.then(|| {
            let registry = scene.real.scene.coordinator.registry();
            let snapshot = registry.semantic_resource_snapshot();
            registry
                .reserve_semantic_storage(snapshot.limit_bytes - snapshot.charged_bytes)
                .unwrap()
        });
        crate::inventory::bind_semantic_callers_for_test(
            &mut scene.real.scene.coordinator,
            &mut scene.real.lane,
        );
        {
            let owned = scene.real.h0.0.borrow();
            assert_eq!(
                owned.last_refresh_observation,
                Some(if tick_first {
                    ObserveOutcome::Continued
                } else {
                    ObserveOutcome::New
                }),
                "real refresh observation: tick_first={tick_first}, refuse_first={refuse_first}"
            );
            let raw = owned.collected.as_ref().unwrap();
            assert!(raw.h0_identity() == original_quantum);
            assert_eq!(raw.pending_h0_records(), retained_records);
        }
        assert_eq!(
            scene.real.scene.coordinator.semantic_bindings().len(),
            usize::from(!refuse_first),
            "the storage refusal exercises the actual admission consumer"
        );
        drop(hold);
        // The newest matching receipt on retry is Continued. It may support
        // admission, but cannot replace or recreate the original New.
        crate::inventory::bind_semantic_callers_for_test(
            &mut scene.real.scene.coordinator,
            &mut scene.real.lane,
        );
        {
            let owned = scene.real.h0.0.borrow();
            assert_eq!(
                owned.last_refresh_observation,
                Some(ObserveOutcome::Continued)
            );
            assert!(owned.last_refresh_birth.is_none());
            let raw = owned.collected.as_ref().unwrap();
            assert!(raw.h0_identity() == original_quantum);
            assert_eq!(raw.pending_h0_records(), retained_records);
        }
        assert!(
            scene
                .drain
                .consumption_cut()
                .unwrap()
                .same_boundary(&original_boundary),
            "refresh/retry must not poll or replace the collected cursor"
        );
        assert_eq!(
            scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .ledger()
                .roles_for_test(),
            roles,
            "refresh must not acknowledge or release any original raw role"
        );
        let binding = scene
            .real
            .scene
            .coordinator
            .semantic_bindings()
            .get(caller)
            .expect("the retry admits through the original current receipt");
        assert!(Arc::ptr_eq(&binding.pin(), &original_pin));
        let endpoint = scene.real.h0.0.borrow().io.endpoint(0).unwrap();
        assert!(binding.provider_for_endpoint(endpoint).is_some());
        let batch = early_batch.unwrap_or_else(|| scene.real.tick());
        scene.prepare_batch(batch, 1);
        let current = scene
            .real
            .scene
            .coordinator
            .take_prepared_current_for_birth_test()
            .unwrap();
        let births = current
            .into_iter()
            .filter_map(|receipt| receipt.into_birth_candidate().ok())
            .collect::<Vec<_>>();
        assert_eq!(
            births.len(),
            1,
            "same original New must survive real bind/refresh/retry, stash merge and prepared move: tick_first={tick_first}, refuse_first={refuse_first}"
        );
        assert!(births[0].quantum == original_quantum);
        assert!(Arc::ptr_eq(births[0].receipt.original_pin(), &original_pin));
        assert_eq!(births[0].receipt.image(), image);
    }
}

impl CanonicalFanoutScene {
    fn publication_step(
        &mut self,
        frame: &mut Option<IngestedJointQuantum>,
        fault: &impl crate::semantics_objects::journal::FaultEpoch,
        remaining: &mut usize,
    ) -> anyhow::Result<Option<crate::discovery::engine::inventory_coordinator::BatchReceipt>> {
        use crate::discovery::engine::inventory_coordinator::JointCommitProgress;
        let h0 = self.scene.real.h0.clone();
        let mut births = NativeFrameBirths {
            h0: &h0,
            attached: &self.attached,
            retained: &mut self.births,
            seen: Vec::new(),
            unreadable: false,
        };
        let progress = self.scene.real.scene.coordinator.commit_joint_batch(
            &mut self.scene.real.lane,
            &self.scene.producers,
            frame,
            &mut births,
            fault,
            remaining,
        )?;
        Ok(match progress {
            JointCommitProgress::Pending => None,
            JointCommitProgress::Published(receipt) => Some(receipt),
        })
    }

    fn assert_publication_hidden(&self, old_revision: u64) {
        use crate::inventory_present::Presentation;
        let coordinator = &self.scene.real.scene.coordinator;
        assert!(coordinator.publication_pending());
        assert_eq!(coordinator.registry().published_revision(), old_revision);
        assert!(Presentation::try_capture(coordinator, "system", 1, 2, 1).is_err());
        assert!(Presentation::try_capture_dashboard(coordinator, "system", 1, 2, 1, 2, 1).is_err());
        // Legacy entrypoints share the pre-read guard while the ordinary
        // lane remains inactive. They cannot construct a partial snapshot.
        for dashboard in [false, true] {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if dashboard {
                        Presentation::capture_dashboard(coordinator, "system", 1, 2, 1, 2, 1)
                    } else {
                        Presentation::capture(coordinator, "system", 1, 2, 1)
                    }
                }))
                .is_err()
            );
        }
    }

    fn complete_publication(
        &mut self,
        frame: &mut Option<IngestedJointQuantum>,
        fault: &impl crate::semantics_objects::journal::FaultEpoch,
        old_revision: u64,
    ) -> crate::discovery::engine::inventory_coordinator::BatchReceipt {
        // Every slice shares one unit across all actual feeds/effects. The
        // fixture has <128 transitions, so this also detects stranded heads.
        for _ in 0..256 {
            let mut remaining = 1;
            if let Some(receipt) = self
                .publication_step(frame, fault, &mut remaining)
                .expect("same original publication remains runnable")
            {
                assert!(frame.is_none(), "only actual disposal consumes the frame");
                assert!(!self.scene.real.scene.coordinator.publication_pending());
                assert_eq!(receipt.registry_published, old_revision + 1);
                return receipt;
            }
            self.assert_publication_hidden(old_revision);
        }
        panic!("same original publication must reach its real finished boundary")
    }
}

/// Catches registration selecting permanent S1Only before a genuine receipt
/// arrives, publishing an empty first head, or exposing an applied partial view.
#[test]
fn joint_first_real_birth_publishes_one_revision() {
    use crate::inventory_present::Presentation;
    for (policy, joint) in [
        (PublicationReceipts::All, 2),
        (PublicationReceipts::Missing, 0),
        (PublicationReceipts::Capacity(1), 1),
    ] {
        let (mut fixture, original) = CanonicalFanoutScene::first_publication_with_functions(
            1,
            &["C_CreateObject", "C_SignInit"],
            policy,
        );
        let coordinator = &fixture.scene.real.scene.coordinator;
        assert_eq!(coordinator.registry().joint_feeds(), 0);
        let old_revision = coordinator.registry().published_revision();
        let old_text = format!("{:?}", fixture.published_before);
        assert!(fixture.published_before.instances.is_empty());
        let claims = coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test();
        assert_eq!(
            claims.0, joint,
            "selected originals stay claimed; actual S1Only negatives already dispose their own"
        );
        let mut frame = Some(original);
        let receipt = fixture.complete_publication(&mut frame, &BirthFault, old_revision);
        assert!(receipt.registry_applied > 0);
        assert_eq!(format!("{:?}", fixture.published_before), old_text);
        let coordinator = &fixture.scene.real.scene.coordinator;
        assert_eq!(coordinator.registry().joint_feeds(), joint);
        let feeds = fixture.feeds();
        assert_eq!(feeds.len(), 2, "denied receipt does not drop an admission");
        assert_eq!(
            feeds.iter().map(|feed| feed.reduced).sum::<u64>(),
            joint as u64
        );
        assert!(feeds.iter().all(|feed| feed.staged == 0));
        for feed in feeds {
            assert_eq!(fixture.s1_counts(feed.id), (1, 0, 0, 0, 0));
        }
        let published = Presentation::try_capture(coordinator, "system", 1, 3, 1).unwrap();
        assert_eq!(published.instances.len(), 2);
        assert_eq!(published.semantic_edges.len(), 2);
        assert!(
            published
                .semantic_edges
                .iter()
                .all(|edge| edge.api_returns == Some(1))
        );
        assert_eq!(coordinator.reference_h3_audit_state(), (1, false));
        fixture.scene.assert_claims(&[]);
        assert_eq!(
            coordinator.joint_capture().ledger().roles_for_test()[..4],
            [0, 0, 0, 0]
        );
    }
}

/// A real physical tail must join the one original H3/audit before any
/// claim/stage decision. A new tail minted at commit cannot replace it later.
#[test]
fn joint_physical_tail_precedes_claims_and_one_audit() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    struct NativeFault(SharedH0);
    impl crate::semantics_objects::journal::FaultEpoch for NativeFault {
        fn fault_epoch(&self) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
            let value = self.0.0.borrow().io.script.last_health.fault;
            if value > u64::from(u32::MAX) {
                Err(crate::semantics_objects::journal::FaultReadError::Saturated)
            } else {
                Ok(value)
            }
        }
    }
    let native = NativeFault(fixture.scene.real.h0.clone());
    let caller = fixture.births[0].0;
    let before = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    assert_eq!(before.objects.len(), 2);
    fixture
        .scene
        .real
        .scene
        .coordinator
        .reference_mark_tail(caller);
    fixture.push_two("C_SignInit", 2);
    let raw = fixture.scene.collect_with_fault(&native);
    fixture.scene.real.h0.0.borrow_mut().collected = Some(raw);
    let batch = fixture.scene.real.tick();
    let mut raw = fixture
        .scene
        .real
        .h0
        .0
        .borrow_mut()
        .collected
        .take()
        .unwrap();
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    coordinator.stage_semantic_batch(batch);
    coordinator
        .prepare_joint_publication(
            false,
            &mut fixture.scene.real.lane,
            &mut raw,
            &fixture.scene.producers,
        )
        .unwrap();
    coordinator
        .prepare_staged_semantic_batch(&mut fixture.scene.real.lane, None)
        .unwrap();
    let mut ingested = raw
        .ingest(
            coordinator.joint_capture_mut().adapter_mut(),
            &fixture.scene.producers,
            &fixture.grant,
        )
        .unwrap_or_else(|(_, reason)| panic!("original physical-tail collection: {reason:?}"));
    while coordinator
        .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
        .unwrap()
        .is_some()
    {}
    while coordinator
        .stage_next_prepared_admission_with_disposition(&fixture.scene.producers, &mut ingested)
        .unwrap()
    {}
    assert!(coordinator.finish_prepared_semantic_batch(&fixture.scene.real.lane));
    let frame = acquire(&mut fixture.scene, ingested, &fixture.attached, &native);
    assert!(
        matches!(
            frame.audit_for_test().h3_for_test(),
            H3DispositionEvidence::StagedLoss { .. }
        ),
        "the original audit must own the real physical cut, not a later replacement H3"
    );
    let failure = frame
        .failure_for_test()
        .expect("actual original physical loss");
    assert_eq!(
        failure.gap,
        crate::semantics_objects::journal::JournalGap::FaultChanged,
        "the physical cut raised the same actual native fault cell after raw collection"
    );
    for object in &before.objects {
        assert!(failure.effects.effects.iter().any(|effect| matches!(effect,
            ObjectEffect::Retired { object: id, reason: ObjectGap::OutcomeLost } if *id == object.id)));
    }
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(coordinator.reference_h3_audit_state(), (2, false));
    let revision = coordinator.registry().published_revision();
    let before_feeds = fixture.feeds();
    fixture.complete_publication(&mut Some(frame), &native, revision);
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(
        coordinator.reference_h3_audit_state(),
        (2, false),
        "no second H3 take or stranded replacement"
    );
    let after = coordinator.joint_capture().model().project();
    for object in &before.objects {
        assert_eq!(
            after.object(object.id).unwrap().lifetime,
            Lifetime::Retired(ObjectGap::OutcomeLost)
        );
    }
    assert_eq!(
        fixture.feeds().iter().map(|feed| feed.reduced).sum::<u64>(),
        before_feeds.iter().map(|feed| feed.reduced).sum::<u64>()
    );
    fixture.scene.assert_claims(&[]);
    assert_eq!(
        coordinator.joint_capture().ledger().roles_for_test()[..4],
        [0, 0, 0, 0]
    );
}

/// Catches a retry repeating original admission, physical publication,
/// diagnostics, H9 reduction, or silently applying a later staged batch.
#[test]
fn joint_publication_retry_does_not_repeat_admission_or_reducer() {
    use crate::inventory_diagnostics::{
        CaptureOutcome, CaptureSettlement, DiagnosticConfig, DiagnosticOutcome,
        RetainedIdentityView,
    };
    let (mut fixture, original) = CanonicalFanoutScene::first_publication_inputs(
        1,
        &["C_CreateObject", "C_SignInit"],
        PublicationReceipts::All,
        true,
        true,
    );
    let caller = fixture.births[0].0;
    let module_key = fixture.scene.real.modules[0].0.clone();
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    let module = coordinator.registry().module_id_for(&module_key).unwrap();
    coordinator
        .enable_diagnostics(DiagnosticConfig::default())
        .unwrap();
    coordinator
        .registry_mut()
        .note_counted_use(caller, &module_key, 7, 1, 2, 0);
    let old_revision = coordinator.registry().published_revision();
    let claims = coordinator
        .joint_capture()
        .adapter()
        .invocation_claims_for_test();
    assert_eq!(claims.0, 2);
    let mut frame = Some(original);
    let mut remaining = 1;
    let mut zero = 0;
    assert!(
        fixture
            .publication_step(&mut frame, &BirthFault, &mut zero)
            .unwrap()
            .is_none()
    );
    fixture.assert_publication_hidden(old_revision);
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(
        coordinator
            .registry()
            .edge(caller, module)
            .unwrap()
            .entry_count,
        7
    );
    assert!(
        fixture
            .feeds()
            .iter()
            .all(|feed| feed.reduced == 0 && feed.staged == 1)
    );
    // The next batch stays in the original staging Vec, without being folded
    // into the already-applied phase by either the Joint or legacy paths.
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    coordinator
        .registry_mut()
        .note_counted_use(caller, &module_key, 4, 3, 4, 7);
    assert!(coordinator.commit_batch(true).is_err());
    assert!(
        coordinator
            .commit_batch_with_semantics(true, Some(&mut fixture.scene.real.lane))
            .is_err()
    );
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| coordinator
            .registry_mut()
            .publish()))
        .is_err()
    );
    for _ in 0..3 {
        let feeds = fixture.feeds();
        let claims = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test();
        assert!(
            fixture
                .publication_step(&mut frame, &BirthFault, &mut zero)
                .unwrap()
                .is_none()
        );
        fixture.assert_publication_hidden(old_revision);
        assert_eq!(fixture.feeds(), feeds);
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
                .registry()
                .edge(caller, module)
                .unwrap()
                .entry_count,
            7
        );
    }
    let (mut foreign, foreign_frame) = CanonicalFanoutScene::first_publication_with_functions(
        1,
        &["C_CreateObject", "C_SignInit"],
        PublicationReceipts::All,
    );
    let mut foreign_frame = Some(foreign_frame);
    let foreign_id = foreign_frame.as_ref().unwrap().identity();
    assert!(
        fixture
            .publication_step(&mut foreign_frame, &BirthFault, &mut remaining)
            .is_err()
    );
    assert!(foreign_frame.as_ref().unwrap().identity() == foreign_id);
    fixture.assert_publication_hidden(old_revision);
    let first = fixture.complete_publication(&mut frame, &BirthFault, old_revision);
    let feeds = fixture.feeds();
    assert!(
        feeds
            .iter()
            .all(|feed| feed.reduced == 1 && feed.staged == 0)
    );
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    assert_eq!(
        coordinator
            .registry()
            .edge(caller, module)
            .unwrap()
            .entry_count,
        7
    );
    let next = coordinator.commit_batch(false).unwrap();
    assert_eq!(next.registry_published, first.registry_published + 1);
    assert_eq!(
        coordinator
            .registry()
            .edge(caller, module)
            .unwrap()
            .entry_count,
        11
    );
    assert_eq!(fixture.feeds(), feeds);
    let finished = fixture
        .scene
        .real
        .scene
        .coordinator
        .take_diagnostics(DiagnosticOutcome {
            capture_outcome: CaptureOutcome::Completed,
            capture_settlement: CaptureSettlement::Settled,
        })
        .unwrap();
    struct Identities<'a, S: crate::discovery::caller_registry::ProcessSource>(
        &'a crate::discovery::engine::inventory_coordinator::InventoryCoordinator<S>,
    );
    impl<S: crate::discovery::caller_registry::ProcessSource> RetainedIdentityView
        for Identities<'_, S>
    {
        fn application(&self, caller: u32) -> Option<&str> {
            self.0
                .adapter()
                .record(CallerId(caller))?
                .exe
                .as_ref()?
                .path
                .as_deref()
        }
        fn module(&self, module: u32) -> Option<&str> {
            self.0
                .registry()
                .module(crate::discovery::caller_registry::ModuleId(module))?
                .paths
                .first()
                .map(String::as_str)
        }
    }
    let mut bytes = Vec::new();
    finished
        .write_jsonl(
            &mut bytes,
            &Identities(&fixture.scene.real.scene.coordinator),
            || false,
        )
        .unwrap();
    let rows = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|row| row["kind"] == "publication")
        .collect::<Vec<_>>();
    assert_eq!(
        rows.len(),
        2,
        "one observer call for each original mutation, never each retry"
    );
    assert_eq!(
        (
            rows[0]["staged"].as_u64(),
            rows[0]["base"].as_u64(),
            rows[0]["edge_total"].as_u64()
        ),
        (Some(7), Some(0), Some(7))
    );
    assert_eq!(
        (
            rows[1]["staged"].as_u64(),
            rows[1]["base"].as_u64(),
            rows[1]["edge_total"].as_u64()
        ),
        (Some(4), Some(7), Some(11))
    );
    let foreign_revision = foreign
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .published_revision();
    foreign.complete_publication(&mut foreign_frame, &BirthFault, foreign_revision);
}

/// Catches a second domain's real late broad loss becoming visible after an
/// intermediate positive revision, or skipping earlier already-delivered heads.
#[test]
fn joint_second_domain_fault_is_invisible_until_fanout() {
    use crate::inventory_present::Presentation;
    let (mut fixture, original) = CanonicalFanoutScene::first_publication_with_functions(
        1,
        &["C_CreateObject", "C_SignInit"],
        PublicationReceipts::All,
    );
    let old_revision = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .published_revision();
    let old_text = format!("{:?}", fixture.published_before);
    let fault = FrameFault::clean();
    let mut frame = Some(original);
    let mut first_reduced = false;
    for _ in 0..64 {
        let mut remaining = 1;
        assert!(
            fixture
                .publication_step(&mut frame, &fault, &mut remaining)
                .unwrap()
                .is_none()
        );
        fixture.assert_publication_hidden(old_revision);
        let reduced = fixture.feeds().iter().map(|feed| feed.reduced).sum::<u64>();
        assert!(
            reduced <= 1,
            "one service slice cannot silently replay the next domain"
        );
        if reduced == 1 {
            first_reduced = true;
            break;
        }
    }
    assert!(first_reduced);
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
        1,
        "the first actual seal creates live history"
    );
    assert_eq!(grown.objects[0].lifetime, Lifetime::Live);
    fault.epoch.set(1);
    let receipt = fixture.complete_publication(&mut frame, &fault, old_revision);
    assert_eq!(receipt.registry_published, old_revision + 1);
    assert_eq!(format!("{:?}", fixture.published_before), old_text);
    let coordinator = &fixture.scene.real.scene.coordinator;
    let history = coordinator.joint_capture().model().project();
    assert_eq!(
        history.object(grown.objects[0].id).unwrap().lifetime,
        Lifetime::Retired(ObjectGap::OutcomeLost)
    );
    let feeds = fixture.feeds();
    assert_eq!(feeds.iter().map(|feed| feed.reduced).sum::<u64>(), 1);
    assert_eq!(feeds.iter().map(|feed| feed.disposed).sum::<u64>(), 1);
    assert!(feeds.iter().all(|feed| feed.degraded && feed.staged == 0));
    assert!(Presentation::try_capture(coordinator, "system", 1, 3, 1).is_ok());
    fixture.scene.assert_claims(&[]);
    assert_eq!(
        coordinator.joint_capture().ledger().roles_for_test()[..4],
        [0, 0, 0, 0]
    );
    assert_eq!(coordinator.reference_h3_audit_state(), (1, false));

    // A global FrameFault truthfully affects every retained key. A separate
    // genuine localized negative proves that disjoint proved domains survive.
    let (mut fixture, first) = CanonicalFanoutScene::first_publication_with_functions(
        1,
        &["C_CreateObject", "C_SignInit"],
        PublicationReceipts::All,
    );
    let first_revision = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .published_revision();
    fixture.complete_publication(&mut Some(first), &BirthFault, first_revision);
    let before = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    assert_eq!(before.objects.len(), 2);
    let raw_children = [OwnedStoppedChild::new(), OwnedStoppedChild::new()];
    let mut callers = Vec::new();
    for (offset, child) in raw_children.iter().enumerate() {
        let caller = fixture.scene.real.bind(
            child.id(),
            ImageIdentity {
                task_cookie: 73 + offset as u64,
                exec_id: 0,
            },
            0,
        );
        fixture.scene.push(child.id(), 0, "C_CreateObject", 1);
        callers.push(caller);
    }
    let raw = fixture.scene.collect_with_fault(&BirthFault);
    fixture.scene.real.h0.0.borrow_mut().collected = Some(raw);
    let batch = fixture.scene.real.tick();
    for (child, caller) in raw_children.iter().zip(&callers) {
        fixture.scene.admit_providers(child.id(), *caller, &[0]);
    }
    let mut raw = fixture
        .scene
        .real
        .h0
        .0
        .borrow_mut()
        .collected
        .take()
        .unwrap();
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    coordinator.stage_semantic_batch(batch);
    coordinator
        .prepare_joint_publication(
            false,
            &mut fixture.scene.real.lane,
            &mut raw,
            &fixture.scene.producers,
        )
        .unwrap();
    coordinator
        .prepare_staged_semantic_batch(&mut fixture.scene.real.lane, None)
        .unwrap();
    let mut ingested = raw
        .ingest(
            coordinator.joint_capture_mut().adapter_mut(),
            &fixture.scene.producers,
            &fixture.grant,
        )
        .unwrap_or_else(|(_, reason)| panic!("original localized C/D input: {reason:?}"));
    let mut claims = Vec::new();
    while let Some((position, proof)) = coordinator
        .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
        .unwrap()
    {
        claims.push((position, proof.expect("genuine localized C/D claim")));
    }
    assert_eq!(
        claims
            .iter()
            .map(|(position, _)| *position)
            .collect::<Vec<_>>(),
        [3, 4]
    );
    let roles = coordinator.joint_capture().ledger().roles_for_test();
    assert_eq!(roles[..4], [0, 2, 0, 0]);
    while coordinator
        .stage_next_prepared_admission_with_disposition(&fixture.scene.producers, &mut ingested)
        .unwrap()
    {}
    assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
    assert!(coordinator.finish_prepared_semantic_batch(&fixture.scene.real.lane));
    let localized = acquire(&mut fixture.scene, ingested, &fixture.attached, &BirthFault);
    let failure = localized.failure_for_test().unwrap();
    assert_eq!(
        failure.gap,
        crate::semantics_objects::journal::JournalGap::ImageTainted
    );
    assert!(
        claims
            .iter()
            .all(|(_, proof)| failure.affects_proof_for_test(proof))
    );
    assert!(
        fixture
            .receipts()
            .iter()
            .all(|receipt| !failure.affects_domain(receipt.domain()))
    );
    let revision = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .published_revision();
    fixture.complete_publication(&mut Some(localized), &BirthFault, revision);
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(coordinator.registry().joint_feeds(), 2);
    for caller in callers {
        let direct = coordinator
            .registry()
            .instance_semantic_edges()
            .find(|record| record.caller == caller)
            .unwrap();
        assert_eq!(
            coordinator.registry().feed_mode_for_test(direct.id),
            Some(crate::semantics_key_use::FeedMode::S1Only)
        );
        assert_eq!(fixture.s1_counts(direct.id), (1, 0, 0, 0, 0));
    }
    let after = coordinator.joint_capture().model().project();
    for object in &before.objects {
        assert_eq!(after.object(object.id).unwrap().lifetime, Lifetime::Live);
    }
    assert!(
        fixture
            .feeds()
            .iter()
            .all(|feed| !feed.degraded && !feed.fallback && feed.staged == 0)
    );
    assert!(Presentation::try_capture(coordinator, "system", 1, 4, 1).is_ok());
    fixture.scene.assert_claims(&[]);
    assert_eq!(
        coordinator.joint_capture().ledger().roles_for_test()[..4],
        [0, 0, 0, 0]
    );
}

struct CanonicalFanoutScene {
    scene: JointScene,
    attached: crate::attach::AttachedSemanticSet,
    births: Vec<(CallerId, RetainedBirthWitness, NativeBirthRows)>,
    grant: SessionDrainGrant,
    published_before: crate::inventory_present::Presentation,
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
        Self::prior_sealed_with_functions(
            providers,
            &[
                "C_CreateObject",
                "C_SignInit",
                "C_SignUpdate",
                "C_SignFinal",
            ],
        )
    }

    fn first_publication_with_functions(
        providers: usize,
        functions: &[&str],
        receipt_policy: PublicationReceipts,
    ) -> (Self, IngestedJointQuantum) {
        Self::first_publication_inputs(providers, functions, receipt_policy, true, false)
    }

    fn first_publication_inputs(
        providers: usize,
        functions: &[&str],
        receipt_policy: PublicationReceipts,
        joint_preparation: bool,
        probe_preparation_refusal: bool,
    ) -> (Self, IngestedJointQuantum) {
        let (held, attached) = HeldProviders::with_attachment(providers, functions);
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
        let published_before = crate::inventory_present::Presentation::capture(
            &scene.real.scene.coordinator,
            "system",
            1,
            2,
            1,
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
        let mut raw = scene.real.h0.0.borrow_mut().collected.take().unwrap();
        let coordinator = &mut scene.real.scene.coordinator;
        coordinator.stage_semantic_batch(batch);
        if joint_preparation {
            if probe_preparation_refusal {
                // Equal native IDs do not let another real Capture route or
                // restamp this already-collected original, even for a no-op.
                let mut owned = scene.real.h0.0.borrow_mut();
                let HeldH0 { capture, io, .. } = &mut *owned;
                let mut foreign = SemanticCapture::in_domain(
                    scene.producers.native_domain(),
                    TickLimits::default(),
                )
                .unwrap();
                let before = (
                    capture.next_token,
                    io.script.now,
                    io.script.raises,
                    io.script.health.len(),
                    raw.pending_h0_records(),
                );
                assert!(foreign.tick_collected_with(io, &mut raw).is_err());
                assert!(
                    foreign
                        .apply_physical_gaps_collected_with(io, Vec::new(), &mut raw)
                        .is_err()
                );
                assert_eq!(
                    (
                        capture.next_token,
                        io.script.now,
                        io.script.raises,
                        io.script.health.len(),
                        raw.pending_h0_records(),
                    ),
                    before,
                    "foreign Capture refuses before routing or native audit"
                );
                capture.validate_collected_preparation(&raw).unwrap();
                drop(owned);
                let revision = coordinator.registry().published_revision();
                let roles = coordinator.joint_capture().ledger().roles_for_test();
                let snapshot = coordinator.registry().semantic_resource_snapshot();
                let hold = coordinator
                    .registry()
                    .reserve_semantic_storage(snapshot.limit_bytes - snapshot.charged_bytes)
                    .unwrap();
                assert!(
                    coordinator
                        .prepare_joint_publication(
                            false,
                            &mut scene.real.lane,
                            &mut raw,
                            &scene.producers
                        )
                        .is_err()
                );
                assert!(!coordinator.publication_pending());
                assert_eq!(coordinator.registry().published_revision(), revision);
                assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
                assert!(
                    coordinator.prepared_semantic_batch().is_none(),
                    "no admission was prepared on refusal"
                );
                drop(hold);
            }
            coordinator
                .prepare_joint_publication(false, &mut scene.real.lane, &mut raw, &scene.producers)
                .unwrap();
            let charged = coordinator
                .registry()
                .semantic_resource_snapshot()
                .charged_bytes;
            coordinator
                .prepare_joint_publication(false, &mut scene.real.lane, &mut raw, &scene.producers)
                .unwrap();
            assert_eq!(
                coordinator
                    .registry()
                    .semantic_resource_snapshot()
                    .charged_bytes,
                charged,
                "same original preparation does not charge/repeat"
            );
        }
        coordinator
            .prepare_staged_semantic_batch(&mut scene.real.lane, None)
            .unwrap();
        assert_eq!(
            coordinator
                .prepared_semantic_batch()
                .unwrap()
                .admissions()
                .count(),
            2
        );
        let (mut ingested, _, grant) = scene.ingest_with_grant(raw);
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
        let mut claims = Vec::new();
        while let Some((position, proof)) = scene
            .real
            .scene
            .coordinator
            .claim_next_prepared_admission(&scene.producers, &ingested)
            .unwrap()
        {
            claims.push((position, proof.expect("actual first key claim")));
        }
        assert_eq!(claims.len(), 2);
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
        if let PublicationReceipts::Capacity(limit) = receipt_policy {
            scene
                .real
                .scene
                .coordinator
                .registry_mut()
                .reference_instance_limit(limit);
        }
        let mut installed = 0;
        for (caller, witness, _) in &births {
            let input = admitted
                .iter()
                .find(|input| input.journal_binding().3 == *caller)
                .unwrap();
            if matches!(receipt_policy, PublicationReceipts::Missing) {
                continue;
            }
            let accepted = scene
                .real
                .scene
                .coordinator
                .registry_mut()
                .install_joint_receipt(input.instance_key_for_test(), *witness.receipt());
            let expected = match receipt_policy {
                PublicationReceipts::All => true,
                PublicationReceipts::Capacity(limit) => installed < limit,
                PublicationReceipts::Missing => unreachable!(),
            };
            assert_eq!(accepted, expected, "actual grant capacity is respected");
            installed += usize::from(accepted);
        }
        if matches!(receipt_policy, PublicationReceipts::Capacity(_)) {
            // The exercised refusal is receipt installation. Restore the
            // ordinary instance cap so both genuine admissions still publish.
            scene
                .real
                .scene
                .coordinator
                .registry_mut()
                .reference_instance_limit(usize::MAX);
        }
        // Selection is settled before the actual disposition port: missing
        // grants must become S1Only negatives, never hidden by old staging.
        while scene
            .real
            .scene
            .coordinator
            .stage_next_prepared_admission_with_disposition(&scene.producers, &mut ingested)
            .unwrap()
        {}
        assert!(
            scene
                .real
                .scene
                .coordinator
                .finish_prepared_semantic_batch(&scene.real.lane)
        );
        let frame = acquire(&mut scene, ingested, &attached, &BirthFault);
        if matches!(receipt_policy, PublicationReceipts::All) {
            assert!(frame.failure_for_test().is_none());
        } else {
            assert_eq!(
                frame.failure_for_test().unwrap().gap,
                crate::semantics_objects::journal::JournalGap::ImageTainted
            );
        }
        (
            Self {
                scene,
                attached,
                births,
                grant,
                published_before,
                _child: child,
            },
            frame,
        )
    }

    fn prior_sealed_with_functions(providers: usize, functions: &[&str]) -> Self {
        let (mut fixture, frame) = Self::first_publication_inputs(
            providers,
            functions,
            PublicationReceipts::All,
            false,
            false,
        );
        let Self {
            scene,
            attached,
            births,
            ..
        } = &mut fixture;
        scene
            .real
            .scene
            .coordinator
            .commit_batch_with_semantics(false, Some(&mut scene.real.lane))
            .unwrap();
        assert_eq!(scene.real.scene.coordinator.registry().joint_feeds(), 2);
        // Bootstrap the fixture with actual native rechecks and the SAME
        // acquired audit/model/ledger. Tests below exercise new frame delivery.
        for (caller, witness, rows) in births.iter_mut() {
            let fresh = {
                let mut h0 = scene.real.h0.0.borrow_mut();
                let HeldH0 { capture, io, .. } = &mut *h0;
                witness
                    .fresh_evidence_with(
                        io,
                        rows,
                        capture,
                        attached,
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
        fixture
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
        assert_eq!(targets.len(), 2);
        for (index, target) in targets.iter().enumerate() {
            assert_eq!(
                frame.seal_next(&mut ports, &mut births, &fault),
                Ok(QuantumSealProgress::DeliveryReady)
            );
            assert_eq!(
                births.seen[index].0,
                target.id(),
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
    pending_h3_with_sibling(unmatched_complete, false, audit_fault)
}

fn pending_h3_with_sibling(
    unmatched_complete: bool,
    dispose_sibling: bool,
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
    let mut ingested = raw
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
    while if dispose_sibling {
        coordinator
            .stage_next_prepared_admission_with_disposition(&fixture.scene.producers, &mut ingested)
            .unwrap()
    } else {
        coordinator.stage_next_prepared_admission()
    } {
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
        1208
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
        [1208; 3]
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
    let published_before = crate::inventory_present::Presentation::capture(
        &scene.real.scene.coordinator,
        "system",
        1,
        2,
        1,
    );
    let mut fixture = CanonicalFanoutScene {
        scene,
        attached,
        births: Vec::new(),
        grant,
        published_before,
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
    let published_before = crate::inventory_present::Presentation::capture(
        &scene.real.scene.coordinator,
        "system",
        1,
        2,
        1,
    );
    let mut fixture = CanonicalFanoutScene {
        scene,
        attached,
        births: Vec::new(),
        grant,
        published_before,
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

/// The same actual collector, owner, model and frame used above; this gate
/// observes conversion only. Multi-call H9 delivery deliberately stays held.
struct ObservationWire {
    label: &'static str,
    begin: [u8; 224],
    end: [u8; 632],
}

/// An omitted empty transition, a guessed call index, or a reordered effect
/// range must fail at the same original seal H9 will eventually borrow.
fn assert_original_replay_partition(seal: &crate::semantics_objects::journal::SealSuccess) {
    use crate::semantics_objects::journal::SealReplayPhase;
    let mut next = 0;
    for step in seal.prefix.replay_steps() {
        let range = step.effect_range();
        assert_eq!(range.start, next, "steps partition the original buffer");
        assert!(range.end >= range.start && range.end <= seal.effects.effects.len());
        let original = &seal.effects.effects[range.clone()];
        let borrowed = seal.effects_for_step(step).unwrap();
        assert_eq!(borrowed, original);
        assert_eq!(borrowed.as_ptr(), original.as_ptr(), "no cloned facts");
        if matches!(
            step.phase(),
            SealReplayPhase::Begin | SealReplayPhase::End | SealReplayPhase::BoundedLoss
        ) {
            let call = seal
                .prefix
                .call_for_step(step)
                .expect("original call index");
            assert!(seal.prefix.replay_calls().contains(call));
            if step.phase() == SealReplayPhase::BoundedLoss {
                assert!(call.abandoned && call.end_cut.is_none());
                assert!(step.cut().is_some(), "actual corroborated loss bound");
            } else {
                assert_eq!(
                    step.cut(),
                    if step.phase() == SealReplayPhase::End {
                        call.end_cut
                    } else {
                        Some(call.begin_cut)
                    }
                );
            }
        } else {
            assert!(seal.prefix.call_for_step(step).is_none());
        }
        next = range.end;
    }
    assert_eq!(next, seal.effects.effects.len());
}

fn observation_wire(
    fixture: &CanonicalFanoutScene,
    pid: u32,
    label: &'static str,
    function: &'static str,
    sequence: u64,
) -> ObservationWire {
    use crate::semantics_objects::journal::tests::{end_bytes_getattr, end_bytes_result};
    use p11scope_ebpf_common::object_wire::{
        OBJECT_ACTION_CREATE, OBJECT_ACTION_DESTROY, OBJECT_ACTION_SET,
    };
    let (mut begin, _) = fixture.scene.encoded(pid, 0, function, sequence);
    // A fresh handle, distinct from both prior-sealed fixture objects. The
    // END builders copy this exact original argument/status into their tails.
    if matches!(
        function,
        "C_SignInit" | "C_GetAttributeValue" | "C_SetAttributeValue" | "C_DestroyObject"
    ) {
        begin[88..96].copy_from_slice(&0x5151u64.to_le_bytes());
        begin[126] = 1;
    }
    let end = match function {
        "C_CreateObject" => {
            end_bytes_result(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 10, 0x5151)
        }
        "C_GetAttributeValue" => end_bytes_getattr(
            &begin,
            0,
            ENTRY_NS + 10,
            &[
                (1, 1, 3),
                (2, 1, 0),
                (5, 1, if label == "metadata" { 2048 } else { 4096 }),
            ],
        ),
        "C_SetAttributeValue" => end_bytes(&begin, OBJECT_ACTION_SET, 0, ENTRY_NS + 10),
        "C_DestroyObject" => end_bytes(&begin, OBJECT_ACTION_DESTROY, 0, ENTRY_NS + 10),
        "C_SignInit" => end_bytes(&begin, OBJECT_ACTION_ACCESS, 0, ENTRY_NS + 10),
        _ => end_bytes_absent(&begin, 0, ENTRY_NS + 10),
    };
    ObservationWire { label, begin, end }
}

/// Route these exact physical originals through the existing H0 validator,
/// sorted admission handoff, raw owner, claims and one real collection audit.
fn prepare_wire_frame(
    fixture: &mut CanonicalFanoutScene,
    wires: &[ObservationWire],
    physical: &[(usize, bool)],
    reverse_delivery: bool,
) -> (IngestedJointQuantum, Vec<(u64, u64)>, u64) {
    for (index, terminal) in physical {
        fixture.scene.drain.source_mut().push_record(if *terminal {
            wires[*index].end.to_vec()
        } else {
            wires[*index].begin.to_vec()
        });
    }
    let mut raw = fixture.scene.collect_with_fault(&BirthFault);
    let mut report = {
        let mut h0 = fixture.scene.real.h0.0.borrow_mut();
        let HeldH0 { capture, io, .. } = &mut *h0;
        capture.tick_collected_with(io, &mut raw).unwrap()
    };
    assert_eq!(report.calls().count(), wires.len());
    assert_eq!(report.awaiting_floor(), None);
    assert_eq!(report.shed_floor(), None);
    let originals: Vec<_> = report
        .calls()
        .map(|call| {
            (
                call.position().unwrap(),
                call.collected_origin().unwrap(),
                call.record().event.ts_ns,
            )
        })
        .collect();
    let base_admission = originals.iter().map(|entry| entry.0).min().unwrap();
    let watermark = report.allocated_below();
    if reverse_delivery {
        let mut original_outcomes = report.take_outcomes();
        original_outcomes.reverse();
        assert_eq!(report.merge_stashed_outcomes(original_outcomes), 0);
    }
    let mut after: Vec<_> = report
        .calls()
        .map(|call| {
            (
                call.position().unwrap(),
                call.collected_origin().unwrap(),
                call.record().event.ts_ns,
            )
        })
        .collect();
    after.sort_by_key(|entry| entry.0);
    let mut before = originals;
    before.sort_by_key(|entry| entry.0);
    assert_eq!(after, before, "delivery never remints original H0 identity");
    assert_eq!(report.allocated_below(), watermark);
    let batch = SemanticBatch::from_tick_report(
        fixture.scene.real.lane.domain(),
        report,
        Vec::new(),
        now_ns(),
    )
    .unwrap();
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    coordinator.stage_semantic_batch(batch);
    coordinator
        .prepare_staged_semantic_batch(&mut fixture.scene.real.lane, None)
        .unwrap();
    let admissions: Vec<_> = coordinator
        .prepared_semantic_batch()
        .unwrap()
        .admissions()
        .map(|input| (input.h0_ordinal(), input.s1_facts().ts_ns))
        .collect();
    assert_eq!(
        admissions.iter().map(|entry| entry.0).collect::<Vec<_>>(),
        (base_admission..watermark).collect::<Vec<_>>()
    );
    let ingested = raw
        .ingest(
            coordinator.joint_capture_mut().adapter_mut(),
            &fixture.scene.producers,
            &fixture.grant,
        )
        .unwrap_or_else(|(_, reason)| panic!("original observation raw: {reason:?}"));
    assert_eq!(
        claim_and_finish(&mut fixture.scene, &ingested).len(),
        wires.len()
    );
    fixture
        .scene
        .real
        .scene
        .coordinator
        .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
        .unwrap();
    let frame = acquire(&mut fixture.scene, ingested, &fixture.attached, &BirthFault);
    assert!(frame.failure_for_test().is_none());
    (frame, admissions, base_admission)
}

fn with_genuine_settlement_order(
    late_metadata: bool,
    mut after_observation: impl FnMut(
        &mut CanonicalFanoutScene,
        &mut IngestedJointQuantum,
        JointFeedTarget,
    ) -> bool,
) {
    use crate::semantics_key_use::KeyUseReducer;
    use crate::semantics_objects::{KeyLabel, trace_settlement_for_test};
    use pkcs11_types::CkRv;
    let mut completion_tuples = Vec::new();
    for reverse_end in [false, true] {
        let mut delivery_tuple = None;
        for reverse_delivery in [false, true] {
            let mut fixture = CanonicalFanoutScene::prior_sealed_with_functions(
                1,
                &[
                    "C_CreateObject",
                    "C_GetAttributeValue",
                    "C_SetAttributeValue",
                    "C_DestroyObject",
                    "C_SignInit",
                    "C_SignUpdate",
                    "C_SignFinal",
                ],
            );
            let target = fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .joint_feed_targets()
                .min_by_key(JointFeedTarget::id)
                .unwrap();
            let primary = if fixture.births[0].0 == target.caller() {
                std::process::id()
            } else {
                fixture._child.id()
            };
            let peer = if primary == std::process::id() {
                fixture._child.id()
            } else {
                std::process::id()
            };
            let mut wires = Vec::new();
            let mut physical = Vec::new();
            let init_sequence = if late_metadata { 3 } else { 4 };
            {
                let mut pair = |wire: ObservationWire| {
                    let index = wires.len();
                    physical.push((index, false));
                    physical.push((index, true));
                    wires.push(wire);
                };
                pair(observation_wire(
                    &fixture,
                    primary,
                    "create",
                    "C_CreateObject",
                    2,
                ));
                if !late_metadata {
                    pair(observation_wire(
                        &fixture,
                        primary,
                        "metadata",
                        "C_GetAttributeValue",
                        3,
                    ));
                }
            }
            let init_index = wires.len();
            let mut init = observation_wire(&fixture, primary, "init", "C_SignInit", init_sequence);
            let mut independent =
                observation_wire(&fixture, peer, "independent", "C_SignUpdate", 2);
            // Two different retained physical threads/images overlap, while
            // Init still finishes before any dependent metadata mutation.
            let entry = u64::from_le_bytes(init.begin[48..56].try_into().unwrap());
            independent.begin[48..56].copy_from_slice(&(entry + 1).to_le_bytes());
            init.end = end_bytes(
                &init.begin,
                OBJECT_ACTION_ACCESS,
                CkRv::OK.0,
                ENTRY_NS + if reverse_end { 20 } else { 10 },
            );
            independent.end = end_bytes_absent(
                &independent.begin,
                CkRv::OK.0,
                ENTRY_NS + if reverse_end { 9 } else { 19 },
            );
            assert_ne!(&init.begin[8..24], &independent.begin[8..24]);
            wires.push(init);
            wires.push(independent);
            physical.extend([(init_index, false), (init_index + 1, false)]);
            if reverse_end {
                physical.extend([(init_index + 1, true), (init_index, true)]);
            } else {
                physical.extend([(init_index, true), (init_index + 1, true)]);
            }
            let mut sequence = init_sequence + 1;
            if late_metadata {
                let index = wires.len();
                wires.push(observation_wire(
                    &fixture,
                    primary,
                    "metadata",
                    "C_GetAttributeValue",
                    sequence,
                ));
                physical.extend([(index, false), (index, true)]);
                sequence += 1;
            }
            for (label, name) in [
                ("conflict", "C_GetAttributeValue"),
                ("invalidate", "C_SetAttributeValue"),
                ("destroy", "C_DestroyObject"),
                ("reuse", "C_CreateObject"),
                ("replacement_metadata", "C_GetAttributeValue"),
                ("final", "C_SignFinal"),
            ] {
                let index = wires.len();
                wires.push(observation_wire(&fixture, primary, label, name, sequence));
                physical.extend([(index, false), (index, true)]);
                sequence += 1;
            }
            assert_eq!(wires.len(), 10);
            let (mut frame, admissions, base_admission) =
                prepare_wire_frame(&mut fixture, &wires, &physical, reverse_delivery);
            let feeds_before = fixture.feeds();
            let h0 = fixture.scene.real.h0.clone();
            let mut births = NativeFrameBirths {
                h0: &h0,
                attached: &fixture.attached,
                retained: &mut fixture.births,
                seen: Vec::new(),
                unreadable: false,
            };
            let trace = {
                let mut ports = fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_frame_ports(&fixture.scene.producers)
                    .unwrap();
                frame.bind_targets(&ports).unwrap();
                let (progress, trace) =
                    trace_settlement_for_test(target.bootstrap().domain(), || {
                        frame.seal_next(&mut ports, &mut births, &BirthFault)
                    });
                assert_eq!(progress, Ok(QuantumSealProgress::DeliveryReady));
                trace
            };
            assert_eq!(births.seen.len(), 1);
            drop(births);
            let seal = frame
                .active_seal_for_test()
                .expect("borrow the actual retained seal");
            assert_eq!(seal.prefix.domain(), target.bootstrap().domain());
            assert_eq!(seal.prefix.settled().len(), 9);
            assert_eq!(trace.settlements, 1);
            assert_eq!(
                trace.steps.len(),
                18,
                "every real BEGIN and END, including empty effects"
            );
            let conversion_len = seal
                .effects
                .effects
                .len()
                .checked_sub(trace.effects.len())
                .unwrap();
            assert_eq!(&seal.effects.effects[conversion_len..], trace.effects);
            assert_eq!(
                conversion_len, 0,
                "healthy conversion emitted no pre-settlement effects"
            );
            assert_original_replay_partition(seal);
            use crate::semantics_objects::journal::SealReplayPhase;
            assert_eq!(seal.prefix.replay_calls(), seal.prefix.settled());
            assert_eq!(seal.prefix.replay_steps().len(), 38);
            let actual_steps: Vec<_> = seal
                .prefix
                .replay_steps()
                .iter()
                .filter(|step| {
                    matches!(step.phase(), SealReplayPhase::Begin | SealReplayPhase::End)
                })
                .collect();
            assert_eq!(actual_steps.len(), trace.steps.len());
            for (actual, observed) in actual_steps.iter().zip(&trace.steps) {
                let original = seal.prefix.call_for_step(actual).unwrap();
                assert_eq!(original.ticket, observed.call);
                assert_eq!(actual.cut(), Some(observed.cut));
                assert_eq!(actual.phase() == SealReplayPhase::End, observed.terminal);
                assert_eq!(actual.effect_range(), observed.effects.clone());
            }
            assert_eq!(
                seal.prefix
                    .replay_steps()
                    .iter()
                    .filter(|step| step.phase() == SealReplayPhase::Conversion)
                    .count(),
                18,
                "each real conversion stays distinct even when it emits no effects"
            );
            let prefix_base = seal.prefix.frontier_cut() - physical.len() as u64;
            let mut keyuse = KeyUseReducer::new();
            let mut selected = Vec::new();
            for (index, wire) in wires
                .iter()
                .enumerate()
                .filter(|(_, wire)| wire.label != "independent")
            {
                let begin_index = physical
                    .iter()
                    .position(|item| *item == (index, false))
                    .unwrap();
                let end_index = physical
                    .iter()
                    .position(|item| *item == (index, true))
                    .unwrap();
                let begin_cut = prefix_base + begin_index as u64 + 1;
                let end_cut = prefix_base + end_index as u64 + 1;
                let settled = seal
                    .prefix
                    .settled()
                    .iter()
                    .find(|call| call.begin_cut == begin_cut)
                    .unwrap();
                let ts = u64::from_le_bytes(wire.end[24..32].try_into().unwrap());
                let admission = admissions.iter().find(|entry| entry.1 == ts).unwrap().0;
                assert_eq!(settled.key.admission(), admission);
                assert_eq!(settled.end_cut, Some(end_cut));
                let steps: Vec<_> = trace
                    .steps
                    .iter()
                    .filter(|step| step.call == settled.ticket)
                    .collect();
                assert_eq!(steps.len(), 2);
                assert_eq!((steps[0].cut, steps[0].terminal), (begin_cut, false));
                assert_eq!((steps[1].cut, steps[1].terminal), (end_cut, true));
                assert!(steps[0].effects.is_empty());
                let receipts = keyuse.receipts_for_call(
                    seal,
                    settled,
                    fixture.scene.real.scene.coordinator.joint_capture().model(),
                    admission,
                );
                selected.push((wire.label, *settled, steps[1], receipts));
            }
            assert!(trace.steps.windows(2).all(|pair| pair[0].cut < pair[1].cut));
            let find = |label| selected.iter().find(|entry| entry.0 == label).unwrap();
            let create = find("create");
            let old = trace.effects[create.2.effects.clone()]
                .iter()
                .find_map(|effect| match effect {
                    ObjectEffect::Created { call, object, .. } if *call == create.1.ticket => {
                        Some(*object)
                    }
                    _ => None,
                })
                .unwrap();
            let reuse = find("reuse");
            let replacement = trace.effects[reuse.2.effects.clone()]
                .iter()
                .find_map(|effect| match effect {
                    ObjectEffect::Created { call, object, .. } if *call == reuse.1.ticket => {
                        Some(*object)
                    }
                    _ => None,
                })
                .unwrap();
            assert_ne!(old, replacement);
            let init = find("init");
            assert_eq!(init.3.len(), 1);
            let receipt = init.3[0];
            assert_eq!(
                (receipt.key, receipt.input, receipt.position),
                (old, 0, init.1.key.admission())
            );
            assert!(receipt.attribution_valid);
            assert_eq!(
                receipt.label,
                if late_metadata {
                    None
                } else {
                    Some(KeyLabel::Rsa { modulus_bits: 2048 })
                }
            );
            assert_eq!(
                receipt.metadata.established_count(),
                if late_metadata { 0 } else { 3 }
            );
            let conflict = find("conflict");
            assert!(trace.effects[conflict.2.effects.clone()].iter().any(|effect| matches!(effect,
                ObjectEffect::MetadataConflict { call, object, .. } if *call == conflict.1.ticket && *object == old)));
            let invalidation = find("invalidate");
            assert!(
                trace.effects[invalidation.2.effects.clone()]
                    .iter()
                    .any(|effect| matches!(effect,
                ObjectEffect::MetadataInvalidated { object, .. } if *object == old))
            );
            let destroy = find("destroy");
            assert!(trace.effects[destroy.2.effects.clone()].iter().any(|effect| matches!(effect,
                ObjectEffect::Destroyed { call, object } if *call == destroy.1.ticket && *object == old)));
            let final_call = find("final");
            assert!(
                final_call.2.effects.is_empty(),
                "Final still needs its actual empty transition boundary"
            );
            assert!(final_call.3.is_empty());
            assert!(
                init.2.cut < conflict.2.cut
                    && conflict.2.cut < invalidation.2.cut
                    && invalidation.2.cut < destroy.2.cut
                    && destroy.2.cut < reuse.2.cut
                    && reuse.2.cut < final_call.2.cut
            );
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_capture()
                    .model()
                    .receipt_snapshot(replacement)
                    .unwrap()
                    .label,
                Some(KeyLabel::Rsa { modulus_bits: 4096 })
            );
            let tuple = (
                init.1.key.admission(),
                init.1.begin_cut,
                init.1.end_cut.unwrap(),
            );
            eprintln!(
                "observation late={late_metadata} reverse_end={reverse_end} reverse_delivery={reverse_delivery}: init={tuple:?}, frozen={:?}, conflict={}, invalidation={} {:?}, destroy={}, reuse={}, final={} {:?}, pre_settlement_effects={conversion_len}",
                receipt.label,
                conflict.2.cut,
                invalidation.2.cut,
                invalidation.2.effects,
                destroy.2.cut,
                reuse.2.cut,
                final_call.2.cut,
                final_call.2.effects,
            );
            let offset = if late_metadata { 1 } else { 2 };
            assert_eq!(tuple.0, base_admission + offset + u64::from(reverse_end));
            if let Some(previous) = delivery_tuple {
                assert_eq!(tuple, previous);
            }
            delivery_tuple = Some(tuple);
            assert_eq!(
                fixture.feeds(),
                feeds_before,
                "observation performs no H9 replay"
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
            if after_observation(&mut fixture, &mut frame, target) {
                fixture.finish_bounded_batch(frame, false);
            }
        }
        completion_tuples.push(delivery_tuple.unwrap());
    }
    assert_eq!(completion_tuples[0].1, completion_tuples[1].1);
    assert_eq!(completion_tuples[0].0 + 1, completion_tuples[1].0);
    assert_eq!(completion_tuples[0].2 + 1, completion_tuples[1].2);
}

fn observe_genuine_settlement_order(late_metadata: bool) {
    with_genuine_settlement_order(late_metadata, |_, _, _| false);
}

#[test]
fn joint_seal_observation_trace_keeps_call_positions() {
    observe_genuine_settlement_order(false);
}

#[test]
fn joint_seal_observation_trace_never_backfills_init() {
    observe_genuine_settlement_order(true);
}

impl CanonicalFanoutScene {
    fn replay_target(&self) -> (JointFeedTarget, u32) {
        let target = self
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .joint_feed_targets()
            .min_by_key(JointFeedTarget::id)
            .unwrap();
        let pid = self
            .scene
            .real
            .scene
            .coordinator
            .semantic_bindings()
            .get(target.caller())
            .unwrap()
            .pin()
            .pid();
        (target, pid)
    }

    fn seal_replay_head(
        &mut self,
        frame: &mut IngestedJointQuantum,
        fault: &impl crate::semantics_objects::journal::FaultEpoch,
    ) {
        {
            let ports = self
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&self.scene.producers)
                .unwrap();
            frame.bind_targets(&ports).unwrap();
        }
        self.seal_replay_bound_head(frame, fault);
    }

    fn seal_replay_bound_head(
        &mut self,
        frame: &mut IngestedJointQuantum,
        fault: &impl crate::semantics_objects::journal::FaultEpoch,
    ) {
        let h0 = self.scene.real.h0.clone();
        let mut births = NativeFrameBirths {
            h0: &h0,
            attached: &self.attached,
            retained: &mut self.births,
            seen: Vec::new(),
            unreadable: false,
        };
        let mut ports = self
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&self.scene.producers)
            .unwrap();
        assert_eq!(
            frame.seal_next(&mut ports, &mut births, fault),
            Ok(QuantumSealProgress::DeliveryReady)
        );
        assert_eq!(births.seen.len(), 1);
        assert!(
            frame.active_seal_for_test().is_some(),
            "genuine frame must retain the positive"
        );
    }
}

fn with_genuine_prior_terminal(
    reverse_head: bool,
    drive_h9: bool,
    after_seal: impl FnOnce(
        &mut CanonicalFanoutScene,
        &mut IngestedJointQuantum,
        JointFeedTarget,
        crate::semantics_objects::journal::SealedCall,
        crate::semantics_objects::journal::SealedCall,
    ) -> bool,
) {
    use crate::semantics_objects::journal::SealReplayPhase;
    use crate::semantics_objects::journal::tests::abandon_bytes;
    use p11scope_ebpf_common::object_journal::JOURNAL_REASON_SYNC_RETURN_RESULT_LOST;
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    let (target, pid) = fixture.replay_target();
    let (open, ordinary) = fixture.scene.encoded(
        pid,
        0,
        if drive_h9 {
            "C_SignInit"
        } else {
            "C_SignUpdate"
        },
        2,
    );
    let (held, complete) = fixture.scene.encoded(pid, 0, "C_SignInit", 3);
    let ordinary = if reverse_head {
        // B began first but returns after A. H0 therefore admits A before B,
        // while q2 still emits B's loss span before A's actual settlement END.
        end_bytes_absent(&open, 0, ENTRY_NS + 2_010)
    } else {
        ordinary
    };
    fixture.scene.drain.source_mut().push_record(open.to_vec());
    if !reverse_head {
        fixture
            .scene
            .drain
            .source_mut()
            .push_record(ordinary[24..392].to_vec());
    }
    fixture.scene.drain.source_mut().push_record(held.to_vec());
    fixture
        .scene
        .drain
        .source_mut()
        .push_record(complete.to_vec());
    if reverse_head {
        fixture
            .scene
            .drain
            .source_mut()
            .push_record(ordinary[24..392].to_vec());
    }
    let mut q1 = fixture.audited(2, 2, &BirthFault);
    assert!(
        q1.failure_for_test().is_none(),
        "q1 must have an actual clean audit: {:?}",
        q1.failure_for_test()
    );
    fixture.seal_replay_head(&mut q1, &BirthFault);
    let first = q1.active_seal_for_test().unwrap();
    assert_eq!(first.prefix.domain(), target.bootstrap().domain());
    assert_eq!(first.prefix.settled().len(), 2);
    let old = *first
        .prefix
        .settled()
        .iter()
        .find(|call| call.end_cut.is_some())
        .unwrap();
    let lost = *first
        .prefix
        .settled()
        .iter()
        .find(|call| call.end_cut.is_none())
        .unwrap();
    let loss_bound = first.prefix.frontier_cut() - 4 + if reverse_head { 4 } else { 2 };
    assert_eq!(old.key.admission() < lost.key.admission(), reverse_head);
    assert!(
        first.effects.effects.is_empty(),
        "the real open holds the watermark"
    );
    assert_original_replay_partition(first);
    assert!(
        !first
            .prefix
            .replay_steps()
            .iter()
            .any(|step| step.phase() == SealReplayPhase::End)
    );
    if drive_h9 {
        let feeds = fixture.feeds();
        let roles = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test();
        for _ in 0..8 {
            assert_ne!(
                fixture.deliver_one_work(&mut q1),
                QuantumSealProgress::Complete
            );
        }
        assert_eq!(
            fixture.feeds(),
            feeds,
            "no actual End or subject-bound loss yet"
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
    }
    fixture.scene.assert_claims(&[]);
    let before_feeds = fixture.feeds();
    let before_roles = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .ledger()
        .roles_for_test();
    assert_eq!(before_roles[..4], [0, 2, 2, 2]);

    let image = fixture
        .scene
        .real
        .scene
        .coordinator
        .semantic_bindings()
        .get(target.caller())
        .unwrap()
        .image();
    let mut abandon = abandon_bytes(
        u64::from(pid),
        2,
        JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
        (image.task_cookie, image.exec_id),
    );
    abandon[24..32].copy_from_slice(&open[24..32]);
    abandon[48..52].copy_from_slice(&open[104..108]);
    abandon[56..64].copy_from_slice(&open[48..56]);
    fixture
        .scene
        .drain
        .source_mut()
        .push_record(abandon.to_vec());
    let mut q2 = fixture.audited(0, 0, &BirthFault);
    assert!(
        q2.failure_for_test().is_none(),
        "q2 bounded ABANDON must preserve resource custody: {:?}",
        q2.failure_for_test()
    );
    fixture.seal_replay_head(&mut q2, &BirthFault);
    let second = q2.active_seal_for_test().unwrap();
    assert_eq!(
        second.prefix.settled().len(),
        1,
        "legacy delta stays unchanged"
    );
    assert!(second.prefix.settled()[0].abandoned);
    assert_eq!(second.prefix.replay_calls().len(), 2);
    assert_eq!(
        second.prefix.replay_calls()[1],
        old,
        "capture the retained original before prune"
    );
    assert_original_replay_partition(second);
    for foreign in q1.active_seal_for_test().unwrap().prefix.replay_steps() {
        assert!(second.prefix.call_for_step(foreign).is_none());
        assert!(second.effects_for_step(foreign).is_none());
    }
    let conversion = second
        .prefix
        .replay_steps()
        .iter()
        .find(|step| step.phase() == SealReplayPhase::BoundedLoss)
        .unwrap();
    assert!(!conversion.effect_range().is_empty());
    let loss_call = second.prefix.call_for_step(conversion).unwrap();
    assert_eq!((loss_call.key, loss_call.ticket), (lost.key, lost.ticket));
    assert!(loss_call.abandoned && loss_call.end_cut.is_none());
    assert_eq!(conversion.cut(), Some(loss_bound));
    assert!(
        second
            .effects_for_step(conversion)
            .unwrap()
            .iter()
            .any(|effect| matches!(
                effect,
                ObjectEffect::Retired {
                    reason: ObjectGap::OutcomeLost,
                    ..
                }
            ))
    );
    let terminal: Vec<_> = second
        .prefix
        .replay_steps()
        .iter()
        .filter(|step| step.phase() == SealReplayPhase::End)
        .collect();
    assert_eq!(
        terminal.len(),
        1,
        "only the different complete original actually settles"
    );
    assert_eq!(second.prefix.call_for_step(terminal[0]), Some(&old));
    assert_eq!(terminal[0].cut(), old.end_cut);
    assert!(
        second
            .effects_for_step(terminal[0])
            .unwrap()
            .iter()
            .any(|effect| matches!(
                effect,
                ObjectEffect::Gap {
                    reason: ObjectGap::BootstrapUnproven
                }
            ))
    );
    assert!(
        !second.effects.effects.iter().any(|effect| matches!(effect,
        ObjectEffect::Referenced { call, .. } if *call == old.ticket)),
        "conversion loss cannot fabricate a qualified receipt"
    );
    assert_eq!(
        fixture.feeds(),
        before_feeds,
        "representation activates no H9 replay"
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
        [0, 0, 0, 2]
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
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        0
    );
    if after_seal(&mut fixture, &mut q2, target, old, lost) {
        fixture.finish_bounded_batch(q2, false);
    }
}

#[test]
fn joint_replay_steps_keep_prior_terminal_after_conversion_loss() {
    with_genuine_prior_terminal(false, false, |_, _, _, _, _| false);
}

#[test]
fn joint_replay_step_capacity_refusal_preserves_original() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    let (_, pid) = fixture.replay_target();
    fixture.scene.push(pid, 0, "C_SignInit", 2);
    let fault = FrameFault::clean();
    let mut frame = fixture.audited(1, 1, &fault);
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
    let (legacy, retained, temporary) = {
        let ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.replay_reservation_for_test(&ports).unwrap()
    };
    assert!(retained > 0 && temporary > 0);
    let available = legacy
        .checked_add(retained)
        .unwrap()
        .checked_add(temporary)
        .unwrap()
        .checked_sub(1)
        .unwrap();
    let coordinator = &fixture.scene.real.scene.coordinator;
    let claims = coordinator
        .joint_capture()
        .adapter()
        .invocation_claims_for_test();
    let starts = coordinator
        .joint_capture()
        .adapter()
        .retained_starts_for_test();
    let roles = coordinator.joint_capture().ledger().roles_for_test();
    let model = coordinator.joint_capture().model().project();
    let cursor = (frame.identity(), frame.frontier());
    let feeds = fixture.feeds();
    let snapshot = coordinator.registry().semantic_resource_snapshot();
    let hold = coordinator
        .registry()
        .reserve_semantic_storage(snapshot.limit_bytes - snapshot.charged_bytes - available)
        .unwrap();
    let h0 = fixture.scene.real.h0.clone();
    let mut births = NativeFrameBirths {
        h0: &h0,
        attached: &fixture.attached,
        retained: &mut fixture.births,
        seen: Vec::new(),
        unreadable: false,
    };
    let reads = fault.reads.get();
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        assert!(
            matches!(
                frame.seal_next(&mut ports, &mut births, &fault),
                Err(RawQuantumRefusal::Resource(_))
            ),
            "the old result charge alone cannot pay for steps and the temporary locator"
        );
    }
    assert_eq!(fault.reads.get(), reads);
    assert!(births.seen.is_empty());
    drop(births);
    assert_eq!(fixture.feeds(), feeds);
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test(),
        claims
    );
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test(),
        starts
    );
    assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
    assert_eq!(coordinator.joint_capture().model().project(), model);
    assert!(frame.identity() == cursor.0);
    assert_eq!(frame.frontier(), cursor.1);
    assert_eq!(
        coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes,
        snapshot.limit_bytes - available,
        "the whole failed preflight is refunded"
    );
    drop(hold);
    fixture.seal_replay_bound_head(&mut frame, &fault);
    assert_original_replay_partition(frame.active_seal_for_test().unwrap());
    assert_eq!(
        fixture.feeds(),
        feeds,
        "retry still does not publish or replay"
    );
}

impl CanonicalFanoutScene {
    fn s1_counts(&self, id: RegistryInstanceId) -> (u64, u64, u64, u64, usize) {
        let s1 = self
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .find(|record| record.id == id)
            .unwrap()
            .semantics
            .as_ref()
            .unwrap();
        (
            s1.calls(),
            s1.started(),
            s1.completed(),
            s1.unknown(),
            s1.active_summary()
                .iter()
                .map(|entry| entry.2 as usize)
                .sum(),
        )
    }

    /// A service slice has ONE work unit shared by every selected consumer.
    /// Reductions/disposals cannot each receive a fresh per-feed allowance.
    fn deliver_one_work(&mut self, frame: &mut IngestedJointQuantum) -> QuantumSealProgress {
        let before: u64 = self
            .feeds()
            .iter()
            .map(|feed| feed.reduced + feed.disposed)
            .sum();
        let audit = self.scene.real.scene.coordinator.reference_h3_audit_state();
        let ack = self
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below();
        let mut remaining = 1;
        let progress = {
            let mut ports = self
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&self.scene.producers)
                .unwrap();
            frame
                .deliver_next_bounded(&mut ports, &mut remaining)
                .unwrap()
        };
        let after: u64 = self
            .feeds()
            .iter()
            .map(|feed| feed.reduced + feed.disposed)
            .sum();
        assert!(
            after >= before && after - before <= 1,
            "one shared service unit"
        );
        if after != before {
            assert_eq!(remaining, 0, "a terminal disposition is charged work");
        }
        assert!(remaining <= 1);
        assert_eq!(
            self.scene.real.scene.coordinator.reference_h3_audit_state(),
            audit,
            "a yielded/retried delivery never takes H3 again"
        );
        assert_eq!(
            self.scene
                .real
                .scene
                .coordinator
                .reference_h3_acknowledged_below(),
            ack,
            "no acknowledgement while an original result is retained"
        );
        progress
    }

    fn seal_selected_for_batch(&mut self, frame: &mut IngestedJointQuantum, unreadable: bool) {
        let h0 = self.scene.real.h0.clone();
        let mut births = NativeFrameBirths {
            h0: &h0,
            attached: &self.attached,
            retained: &mut self.births,
            seen: Vec::new(),
            unreadable,
        };
        let mut ports = self
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&self.scene.producers)
            .unwrap();
        assert!(matches!(
            frame
                .seal_next(&mut ports, &mut births, &BirthFault)
                .unwrap(),
            QuantumSealProgress::DeliveryReady | QuantumSealProgress::Complete
        ));
        assert!(births.seen.len() <= 1);
    }

    fn finish_bounded_batch(&mut self, mut frame: IngestedJointQuantum, unreadable: bool) {
        let mut complete = false;
        // This fixture has fewer than 128 original transitions/effects. The
        // finite guard catches a hidden head/cursor deadlock, not slow I/O.
        for _ in 0..256 {
            self.seal_selected_for_batch(&mut frame, unreadable);
            if self.deliver_one_work(&mut frame) == QuantumSealProgress::Complete {
                complete = true;
                break;
            }
        }
        assert!(
            complete,
            "every exact original must reach a terminal disposition"
        );
        let feeds = self.feeds();
        assert_eq!(
            self.deliver_one_work(&mut frame),
            QuantumSealProgress::Complete
        );
        assert_eq!(
            self.feeds(),
            feeds,
            "a completed frame never replays/disposes twice"
        );
        let mut ports = self
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&self.scene.producers)
            .unwrap();
        frame
            .finish_frame(&mut ports)
            .unwrap_or_else(|(_, reason)| panic!("bounded consumers remain: {reason:?}"));
        self.scene.assert_claims(&[]);
        assert_eq!(
            self.scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .ledger()
                .roles_for_test()[..4],
            [0, 0, 0, 0]
        );
    }
}

/// Catches the old multi-call hold, prefix-only redemption, unbounded per-feed
/// work, and replacing an original admission with an equal-shaped Update.
#[test]
fn key_operation_joint_batch_replays_exact_order() {
    for reverse_end in [false, true] {
        for reverse_delivery in [false, true] {
            let mut fixture = CanonicalFanoutScene::prior_sealed();
            let (target, primary) = fixture.replay_target();
            let peer = if primary == std::process::id() {
                fixture._child.id()
            } else {
                std::process::id()
            };
            let before = fixture.feeds();
            let before_s1 = fixture.s1_counts(target.id());
            let mut wires = Vec::new();
            let mut physical = Vec::new();
            for (offset, function) in [
                "C_CreateObject",
                "C_SignInit",
                "C_SignUpdate",
                "C_SignUpdate",
                "C_SignFinal",
            ]
            .into_iter()
            .enumerate()
            {
                let first = wires.len();
                for pid in [primary, peer] {
                    wires.push(observation_wire(
                        &fixture,
                        pid,
                        "batch",
                        function,
                        offset as u64 + 2,
                    ));
                }
                physical.extend([(first, false), (first + 1, false)]);
                physical.extend(if reverse_end {
                    [(first + 1, true), (first, true)]
                } else {
                    [(first, true), (first + 1, true)]
                });
            }
            let (mut frame, admissions, _) =
                prepare_wire_frame(&mut fixture, &wires, &physical, reverse_delivery);
            assert_eq!(admissions.len(), 10);
            fixture.seal_replay_head(&mut frame, &BirthFault);
            let seal = frame.active_seal_for_test().unwrap();
            assert_original_replay_partition(seal);
            assert_eq!(seal.prefix.replay_calls().len(), 5);
            assert_eq!(
                seal.prefix
                    .replay_steps()
                    .iter()
                    .filter(|step| step.phase()
                        == crate::semantics_objects::journal::SealReplayPhase::End)
                    .count(),
                5
            );
            let mut original = seal
                .prefix
                .replay_calls()
                .iter()
                .map(|call| (call.key.admission(), call.function))
                .collect::<Vec<_>>();
            original.sort_unstable_by_key(|call| call.0);
            assert_eq!(
                original.iter().map(|call| call.1).collect::<Vec<_>>(),
                [
                    "C_CreateObject",
                    "C_SignInit",
                    "C_SignUpdate",
                    "C_SignUpdate",
                    "C_SignFinal"
                ]
                .map(function_id)
            );
            assert!(original.windows(2).all(|pair| pair[0].0 < pair[1].0));
            let base = before
                .iter()
                .find(|feed| feed.id == target.id())
                .unwrap()
                .reduced;
            let mut done = false;
            for _ in 0..128 {
                fixture.deliver_one_work(&mut frame);
                let feed = fixture
                    .feeds()
                    .into_iter()
                    .find(|feed| feed.id == target.id())
                    .unwrap();
                let n = feed.reduced - base;
                let counts = fixture.s1_counts(target.id());
                assert_eq!(
                    counts.0 - before_s1.0,
                    n,
                    "only the next original enters S1"
                );
                assert_eq!(counts.1 - before_s1.1, u64::from(n >= 2));
                assert_eq!(counts.2 - before_s1.2, u64::from(n == 5));
                assert_eq!(counts.3, before_s1.3);
                assert_eq!(counts.4, usize::from((2..5).contains(&n)));
                assert_eq!(feed.disposed, 0);
                if n == 5 {
                    assert_eq!(feed.staged, 0);
                    done = true;
                    break;
                }
            }
            assert!(
                done,
                "the genuine five-call prefix must progress with budget one"
            );
            let delivered = fixture.feeds();
            fixture.deliver_one_work(&mut frame);
            assert_eq!(
                fixture.feeds(),
                delivered,
                "retry of consumed original table is inert"
            );
            fixture.finish_bounded_batch(frame, false);
            for feed in fixture.feeds() {
                let original = before.iter().find(|old| old.id == feed.id).unwrap();
                assert_eq!(
                    (feed.reduced - original.reduced, feed.disposed, feed.staged),
                    (5, 0, 0)
                );
                assert!(!feed.fallback && !feed.degraded);
            }
        }
    }
}

/// Catches applying the batch's final invalidations before Init, relabeling
/// from the current replacement object, or losing an empty Final boundary.
#[test]
fn key_operation_joint_batch_receipts_keep_observation_time() {
    for late_metadata in [false, true] {
        with_genuine_settlement_order(late_metadata, |fixture, frame, target| {
            let seal = frame.active_seal_for_test().unwrap();
            let mut calls = seal.prefix.replay_calls().to_vec();
            calls.sort_unstable_by_key(|call| call.key.admission());
            let init_rank = calls
                .iter()
                .position(|call| call.function == function_id("C_SignInit"))
                .unwrap() as u64
                + 1;
            let before = fixture
                .feeds()
                .into_iter()
                .find(|feed| feed.id == target.id())
                .unwrap()
                .reduced;
            let mut saw_init = false;
            let mut saw_retirement = false;
            let mut done = false;
            for _ in 0..192 {
                fixture.deliver_one_work(frame);
                let feed = fixture
                    .feeds()
                    .into_iter()
                    .find(|feed| feed.id == target.id())
                    .unwrap();
                let keyuse = fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .registry()
                    .keyuse_for_test();
                let buckets: Vec<_> = keyuse
                    .aggregates()
                    .iter()
                    .filter(|(key, _)| key.instance == target.id())
                    .collect();
                assert!(
                    buckets.iter().all(|(key, _)| key.metadata != "rsa_4096"),
                    "later replacement metadata cannot label the original use"
                );
                if !saw_init && feed.reduced - before == init_rank {
                    saw_init = true;
                    if late_metadata {
                        assert!(
                            buckets.is_empty(),
                            "metadata learned later never backfills Init"
                        );
                    } else {
                        assert_eq!(buckets.len(), 1);
                        assert_eq!(buckets[0].0.metadata, "rsa_2048");
                        assert_eq!(
                            (
                                buckets[0].1.started,
                                buckets[0].1.active,
                                buckets[0].1.key_join_lost
                            ),
                            (1, 1, 0)
                        );
                    }
                }
                if buckets
                    .iter()
                    .any(|(_, counters)| counters.key_join_lost != 0)
                {
                    assert!(saw_init, "the original Init must precede its invalidation");
                    saw_retirement = true;
                    assert_eq!((buckets[0].1.active, buckets[0].1.key_join_lost), (0, 1));
                }
                if feed.reduced - before == 9 {
                    assert_eq!(feed.staged, 0);
                    assert_eq!(
                        keyuse
                            .open()
                            .keys()
                            .filter(|(instance, _)| *instance == target.id())
                            .count(),
                        0
                    );
                    done = true;
                    break;
                }
            }
            assert!(done && saw_init);
            assert_eq!(saw_retirement, !late_metadata);
            // The oracle above already checked the actual object is now
            // RSA4096; replay must retain the earlier frozen label instead.
            true
        });
    }
}

/// Catches spending a fresh H3 for feed two, switching to S1Only before its
/// suffix is disposed, or replaying the same retained head on budget retry.
#[test]
fn key_operation_two_feeds_share_audited_fallback_once() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    for (offset, function) in ["C_SignInit", "C_SignUpdate", "C_SignFinal"]
        .into_iter()
        .enumerate()
    {
        fixture.push_two(function, offset as u64 + 2);
    }
    let mut frame = fixture.audited(6, 6, &BirthFault);
    assert!(matches!(
        frame.audit_for_test().h3_for_test(),
        H3DispositionEvidence::Clean {
            staged_max: 8,
            pending_floor: None
        }
    ));
    let before = fixture.feeds();
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
    for _ in 0..128 {
        fixture.seal_selected_for_batch(&mut frame, true);
        let progress = fixture.deliver_one_work(&mut frame);
        for feed in fixture.feeds() {
            let start = before.iter().find(|old| old.id == feed.id).unwrap();
            assert_eq!(feed.reduced - start.reduced + feed.staged as u64, 3);
            assert_eq!(feed.disposed, 0);
            assert_eq!(
                feed.fallback,
                feed.staged == 0,
                "mode changes only after that feed's entire original suffix"
            );
            assert!(!feed.degraded);
        }
        if progress == QuantumSealProgress::Complete {
            break;
        }
    }
    assert!(
        fixture
            .feeds()
            .iter()
            .all(|feed| feed.staged == 0 && feed.fallback)
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
    fixture.finish_bounded_batch(frame, true);
    for feed in fixture.feeds() {
        assert_eq!(fixture.s1_counts(feed.id), (4, 1, 1, 0, 0));
    }
}

/// Catches inferring a terminal from table.abandoned, disposing an equal-shaped
/// sibling, or blocking A forever behind the earlier-emitted loss span of B.
#[test]
fn key_operation_joint_batch_bounded_loss_keeps_exact_admission_head() {
    for reverse_head in [false, true] {
        with_genuine_prior_terminal(
            reverse_head,
            true,
            |fixture, frame, target, complete, lost| {
                assert_eq!(
                    complete.function, lost.function,
                    "same-shaped distinct originals"
                );
                assert_ne!(complete.key, lost.key);
                assert_ne!(complete.ticket, lost.ticket);
                let seal = frame.active_seal_for_test().unwrap();
                use crate::semantics_objects::journal::SealReplayPhase;
                let loss_index = seal
                    .prefix
                    .replay_steps()
                    .iter()
                    .position(|step| step.phase() == SealReplayPhase::BoundedLoss)
                    .unwrap();
                let end_index = seal
                    .prefix
                    .replay_steps()
                    .iter()
                    .position(|step| step.phase() == SealReplayPhase::End)
                    .unwrap();
                assert!(loss_index < end_index);
                assert_eq!(
                    complete.key.admission() < lost.key.admission(),
                    reverse_head
                );
                assert!(!seal.effects.effects.iter().any(|effect| matches!(effect,
                ObjectEffect::Referenced { call, .. } if *call == complete.ticket || *call == lost.ticket)));
                let before = fixture.feeds();
                let target_before = before.iter().find(|feed| feed.id == target.id()).unwrap();
                let base = (target_before.reduced, target_before.disposed);
                let counts = fixture.s1_counts(target.id());
                let roles = fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_capture()
                    .ledger()
                    .roles_for_test();
                assert_eq!(roles[..4], [0, 0, 0, 2]);
                // The same-shaped originals of a different producer allocation
                // cannot authorize either loss disposal or actual-End replay.
                let mut foreign = CanonicalFanoutScene::prior_sealed();
                let mut remaining = 1;
                {
                    let mut ports = foreign
                        .scene
                        .real
                        .scene
                        .coordinator
                        .joint_frame_ports(&foreign.scene.producers)
                        .unwrap();
                    assert_eq!(
                        frame.deliver_next_bounded(&mut ports, &mut remaining),
                        Err(RawQuantumRefusal::ForeignCapture)
                    );
                }
                assert_eq!(remaining, 1);
                assert_eq!(fixture.feeds(), before);
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
                let mut done = false;
                for _ in 0..64 {
                    let progress = fixture.deliver_one_work(frame);
                    let feed = fixture
                        .feeds()
                        .into_iter()
                        .find(|feed| feed.id == target.id())
                        .unwrap();
                    let (replayed, disposed) = (feed.reduced - base.0, feed.disposed - base.1);
                    assert_eq!(
                        replayed + disposed + feed.staged as u64,
                        2,
                        "every original is replayed, explicitly disposed, or still owned"
                    );
                    assert!(replayed <= 1 && disposed <= 1);
                    if reverse_head && disposed != 0 {
                        assert_eq!(
                            replayed, 1,
                            "B cannot discard the earlier equal-shaped A head"
                        );
                    }
                    if !reverse_head && replayed != 0 {
                        assert_eq!(disposed, 1, "A cannot skip the earlier B head");
                    }
                    let current = fixture.s1_counts(target.id());
                    assert_eq!(
                        current.0 - counts.0,
                        replayed,
                        "bounded loss is history disposal, never S1-positive replay"
                    );
                    assert!(
                        fixture
                            .scene
                            .real
                            .scene
                            .coordinator
                            .registry()
                            .keyuse_for_test()
                            .aggregates()
                            .iter()
                            .all(|(key, counters)| key.instance != target.id()
                                || counters.active == 0)
                    );
                    if feed.staged != 0 {
                        assert_ne!(progress, QuantumSealProgress::Complete);
                    } else {
                        assert_eq!((replayed, disposed), (1, 1));
                        assert_eq!(
                            current.4,
                            usize::from(!reverse_head),
                            "B's later loss must close A's earlier Init, never resurrect it"
                        );
                        assert_eq!(current.3 - counts.3, u64::from(reverse_head));
                        done = true;
                        break;
                    }
                }
                assert!(
                    done,
                    "independent span and exact-head cursors must both progress"
                );
                let feeds = fixture.feeds();
                let s1 = fixture.s1_counts(target.id());
                let evidence = fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .registry()
                    .keyuse_for_test()
                    .evidence();
                for _ in 0..3 {
                    fixture.deliver_one_work(frame);
                }
                assert_eq!(fixture.feeds(), feeds);
                assert_eq!(fixture.s1_counts(target.id()), s1);
                assert_eq!(
                    fixture
                        .scene
                        .real
                        .scene
                        .coordinator
                        .registry()
                        .keyuse_for_test()
                        .evidence(),
                    evidence,
                    "consumed loss neither invalidates nor disposes twice"
                );
                true
            },
        );
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SiblingLossMoment {
    None,
    BeforeProofRefusal,
    AfterProofRefusal,
}

fn exercise_s1only_sibling_raw(sibling_first: bool, loss_moment: SiblingLossMoment) {
    use crate::semantics_key_use::FeedMode;
    let fault = FrameFault::clean();
    let mut fixture = CanonicalFanoutScene::prior_sealed_with_providers(2);
    if loss_moment != SiblingLossMoment::None {
        fixture.push_two("C_SignInit", 2);
        let mut prior = fixture.audited(2, 2, &BirthFault);
        {
            let ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            prior.bind_targets(&ports).unwrap();
        }
        fixture.finish_bounded_batch(prior, false);
        for feed in fixture.feeds() {
            assert_eq!(
                fixture.s1_counts(feed.id),
                (2, 1, 0, 0, 1),
                "retain one genuine live S1 operation before overlapping original loss effects"
            );
        }
    }
    let targets = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .joint_feed_targets()
        .collect::<Vec<_>>();
    assert_eq!(targets.len(), 2);
    let before = fixture.feeds();
    let before_model = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    let mut subjects = Vec::new();
    for target in &targets {
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
        fixture.scene.admit_providers(pid, target.caller(), &[1]);
        subjects.push((target.caller(), pid));
    }
    let mut b_returns = Vec::new();
    for (offset, function) in ["C_SignInit", "C_SignUpdate", "C_SignFinal"]
        .into_iter()
        .enumerate()
    {
        for (caller, pid) in &subjects {
            for (within, file) in if sibling_first { [1, 0] } else { [0, 1] }
                .into_iter()
                .enumerate()
            {
                let (begin, end) = fixture.scene.encoded(
                    *pid,
                    file,
                    function,
                    (if loss_moment == SiblingLossMoment::None {
                        2
                    } else {
                        4
                    }) + offset as u64 * 2
                        + within as u64,
                );
                // Same image/session/mechanism and input handle; only
                // actual provider/slot and original invocation differ.
                if file == 1 {
                    b_returns.push((*caller, u64::from_le_bytes(end[24..32].try_into().unwrap())));
                }
                fixture.scene.drain.source_mut().push_record(begin.to_vec());
                fixture.scene.drain.source_mut().push_record(end.to_vec());
            }
        }
    }
    if loss_moment == SiblingLossMoment::BeforeProofRefusal {
        fault.epoch.set(1);
    }
    let raw = fixture.scene.prepare_with_fault(12, &fault);
    let inputs: Vec<_> = fixture
        .scene
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap()
        .admissions()
        .map(|input| {
            (
                input.h0_ordinal(),
                input.journal_binding().3,
                input.s1_facts().ts_ns,
                input.collected_origin().unwrap(),
            )
        })
        .collect();
    assert_eq!(inputs.len(), 12);
    let b_ordinals = inputs
        .iter()
        .filter(|input| b_returns.contains(&(input.1, input.2)))
        .map(|input| input.0)
        .collect::<Vec<_>>();
    assert_eq!(b_ordinals.len(), 6);
    let b_originals = subjects
        .iter()
        .map(|(caller, _)| {
            fixture
                .scene
                .real
                .scene
                .coordinator
                .prepared_semantic_batch()
                .unwrap()
                .admissions()
                .find(|input| {
                    input.journal_binding().3 == *caller && b_ordinals.contains(&input.h0_ordinal())
                })
                .unwrap()
                .clone()
        })
        .collect::<Vec<_>>();
    let mut ingested = raw
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
        .unwrap_or_else(|(_, reason)| panic!("original sibling raw: {reason:?}"));
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    let mut claims = Vec::new();
    while let Some((ordinal, result)) = coordinator
        .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
        .unwrap()
    {
        if b_ordinals.contains(&ordinal) {
            assert_eq!(
                result,
                Err(crate::semantics_objects::journal::AttestationRefusal::ImageSealed),
                "a genuinely late provider never upgrades the already-sealed image"
            );
        } else {
            assert!(result.is_ok());
        }
        claims.push(ordinal);
    }
    assert_eq!(
        claims,
        inputs.iter().map(|input| input.0).collect::<Vec<_>>()
    );
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test()
            .0,
        6
    );
    if loss_moment == SiblingLossMoment::AfterProofRefusal {
        fault.epoch.set(1);
    }
    let starts = coordinator
        .joint_capture()
        .adapter()
        .retained_starts_for_test();
    let exact_claims = coordinator
        .joint_capture()
        .adapter()
        .invocation_claims_for_test();
    let exact_roles = coordinator.joint_capture().ledger().roles_for_test();
    let foreign = SessionDrainProducers::test_pair(
        fixture.scene.producers.native_domain(),
        EventsDomain::test_standin(fixture.scene.producers.events_id()),
    );
    assert_eq!(
        coordinator.stage_next_prepared_admission_with_disposition(&foreign, &mut ingested),
        Err(RawQuantumRefusal::ForeignCapture)
    );
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test(),
        starts
    );
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test(),
        exact_claims
    );
    assert_eq!(
        coordinator.joint_capture().ledger().roles_for_test(),
        exact_roles
    );
    assert_eq!(
        coordinator
            .prepared_semantic_batch()
            .unwrap()
            .admissions()
            .map(|input| (
                input.h0_ordinal(),
                input.journal_binding().3,
                input.s1_facts().ts_ns,
                input.collected_origin().unwrap()
            ))
            .collect::<Vec<_>>(),
        inputs,
        "foreign allocation cannot mark, stage or substitute any original"
    );
    let mut staged = 0;
    while coordinator
        .stage_next_prepared_admission_with_disposition(&fixture.scene.producers, &mut ingested)
        .unwrap()
    {
        staged += 1;
    }
    assert_eq!(staged, 12);
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test(),
        starts,
        "negative association is retained before physical disposal"
    );
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test(),
        exact_claims
    );
    assert_eq!(coordinator.joint_capture().model().project(), before_model);
    assert_eq!(
        coordinator
            .prepared_semantic_batch()
            .unwrap()
            .admissions()
            .count(),
        0
    );
    assert!(coordinator.finish_prepared_semantic_batch(&fixture.scene.real.lane));
    coordinator
        .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
        .unwrap();
    assert_eq!(
        coordinator.joint_capture().ledger().roles_for_test()[..4],
        [0, 12, 0, 6],
        "marking negative originals must not erase A's source reservation before H9 joins it"
    );
    for target in &targets {
        let a = coordinator
            .registry()
            .instance_semantic_edges()
            .find(|record| record.id == target.id())
            .unwrap();
        let prior = before
            .iter()
            .find(|feed| feed.id == target.id())
            .unwrap()
            .reduced;
        assert_eq!((a.feed.staged_len(), a.feed.reduced()), (3, prior));
        assert_eq!(
            a.semantics.as_ref().unwrap().calls(),
            prior,
            "A has not escaped through direct fallback"
        );
    }
    let b_ids = coordinator
        .registry()
        .instance_semantic_edges()
        .filter(|record| {
            subjects.iter().any(|subject| subject.0 == record.caller)
                && !targets.iter().any(|target| target.id() == record.id)
        })
        .map(|record| record.id)
        .collect::<Vec<_>>();
    assert_eq!(b_ids.len(), 2);
    for id in &b_ids {
        assert_eq!(
            coordinator.registry().feed_mode_for_test(*id),
            Some(FeedMode::S1Only)
        );
    }
    for id in &b_ids {
        assert_eq!(fixture.s1_counts(*id), (3, 1, 1, 0, 0));
    }
    let mut frame = acquire(&mut fixture.scene, ingested, &fixture.attached, &fault);
    use crate::semantics_objects::journal::JournalGap;
    let failures = frame.original_failures_for_test().collect::<Vec<_>>();
    assert!(
        failures
            .iter()
            .any(|failure| failure.gap == JournalGap::ImageTainted),
        "retain the original bulk sibling refusal, including its own scope/effects"
    );
    let failure = frame
        .failure_for_test()
        .expect("the original unowned sibling effects must be disclosed");
    if loss_moment != SiblingLossMoment::None {
        assert_eq!(
            failures.len(),
            2,
            "one bulk sibling result and the actual audit result"
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.gap == JournalGap::FaultChanged)
        );
        assert_eq!(
            failure.gap,
            JournalGap::FaultChanged,
            "a proof-only first reason cannot certify clean fallback across actual loss"
        );
    }
    assert!(
        targets
            .iter()
            .all(|target| failure.affects_domain(target.bootstrap().domain())),
        "the second image's original negative cannot be lost behind the first"
    );
    for object in &before_model.objects {
        assert!(failures.iter().any(|failure| {
            failure.effects.effects.iter().any(|effect| {
                matches!(effect,
            ObjectEffect::Retired { object: retired, .. } if *retired == object.id)
            })
        }));
        assert_ne!(
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
            Lifetime::Live
        );
    }
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
    fixture.finish_bounded_batch(frame, false);
    for target in &targets {
        let feed = fixture
            .feeds()
            .into_iter()
            .find(|feed| feed.id == target.id())
            .unwrap();
        let original = before.iter().find(|feed| feed.id == target.id()).unwrap();
        assert_eq!(
            feed.reduced - original.reduced + feed.disposed - original.disposed,
            3
        );
        assert_eq!(feed.staged, 0);
        assert!(
            feed.fallback || feed.degraded,
            "loss/refusal remains explicit"
        );
        if loss_moment != SiblingLossMoment::None {
            assert!(
                feed.degraded && !feed.fallback,
                "actual loss dominates proof refusal in either order"
            );
            assert_eq!(
                feed.reduced, original.reduced,
                "no clean S1 fallback after native loss"
            );
            assert_eq!(feed.disposed - original.disposed, 3);
            assert_eq!(
                fixture.s1_counts(target.id()),
                (2, 1, 0, 1, 0),
                "both original loss buffers end the one existing operation exactly once"
            );
        }
    }
    for id in &b_ids {
        assert_eq!(
            fixture.s1_counts(*id),
            (3, 1, 1, 0, 0),
            "direct S1 cannot replay during negative disposal"
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .feed_mode_for_test(*id),
            Some(FeedMode::S1Only)
        );
    }
    assert!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .keyuse_for_test()
            .aggregates()
            .is_empty(),
        "neither colliding provider receives object proof after disclosed loss"
    );
    let roles = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .ledger()
        .roles_for_test();
    for original in &b_originals {
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture_mut()
                .adapter_mut()
                .bind_admitted_key(original),
            Err(crate::semantics_objects::journal::AttestationRefusal::ImageTainted),
            "a later original/quiet cut cannot heal the unowned affecting image"
        );
    }
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
        (
            if loss_moment == SiblingLossMoment::None {
                2
            } else {
                3
            },
            false
        )
    );
}

/// Catches a late S1Only provider pinning a Joint sibling's raw head forever,
/// tainting only the first image, or erasing A's reservation before H9 joins it.
#[test]
fn key_operation_s1only_sibling_raw_reaches_terminal() {
    for sibling_first in [false, true] {
        exercise_s1only_sibling_raw(sibling_first, SiblingLossMoment::None);
    }
}

/// A real moved native prefix is loss regardless of whether its collection
/// predates the ImageSealed refusal or it moves after that genuine refusal.
/// Both original causes/effect buffers remain owned; neither manufactures H3.
#[test]
fn key_operation_s1only_sibling_mixed_loss_overrides_proof_refusal() {
    for sibling_first in [false, true] {
        for moment in [
            SiblingLossMoment::BeforeProofRefusal,
            SiblingLossMoment::AfterProofRefusal,
        ] {
            exercise_s1only_sibling_raw(sibling_first, moment);
        }
    }
}

/// A delivered negative span is not fallback or released history. The real
/// producer's refresh-stashed C original must allow the next quantum while
/// A's exact START/claim/H9 remains owned, even though A's key is tainted.
#[test]
fn key_operation_s1only_sibling_pending_h3_reaches_next_frame() {
    // Healthy progress, native loss in q2, and a damaged original H9 role.
    for arm in 0..3 {
        let PendingH3Scene {
            mut fixture,
            frame: mut q1,
            child_c,
            c_caller,
            c_image,
            end_b,
        } = pending_h3_with_sibling(true, true, &BirthFault);
        use crate::semantics_objects::journal::JournalGap;
        let gaps = q1
            .original_failures_for_test()
            .map(|failure| failure.gap)
            .collect::<Vec<_>>();
        assert_eq!(gaps, [JournalGap::ImageTainted, JournalGap::H3Pending]);
        let effects = q1
            .original_failures_for_test()
            .next()
            .unwrap()
            .effects
            .effects
            .len();
        assert!(
            effects != 0,
            "genuine prior live object produces original loss effects"
        );
        assert!(matches!(
            q1.audit_for_test().h3_for_test(),
            H3DispositionEvidence::Clean {
                staged_max: 5,
                pending_floor: Some(4),
            }
        ));
        let coordinator = &fixture.scene.real.scene.coordinator;
        let a = coordinator
            .registry()
            .joint_feed_targets()
            .find(|target| {
                q1.failure_for_test()
                    .unwrap()
                    .affects_domain(target.bootstrap().domain())
            })
            .unwrap();
        let direct = coordinator
            .registry()
            .instance_semantic_edges()
            .find(|record| record.caller == a.caller() && record.id != a.id())
            .unwrap()
            .id;
        let direct_before = fixture.s1_counts(direct);
        assert_eq!(direct_before, (1, 1, 0, 0, 1));
        let feeds = fixture.feeds();
        let claims = coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test();
        assert_eq!(claims.0, 1);
        assert_eq!(
            claims
                .1
                .iter()
                .map(|(ordinal, _)| *ordinal)
                .collect::<Vec<_>>(),
            [3]
        );
        let starts = coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test();
        let roles = coordinator.joint_capture().ledger().roles_for_test();
        assert_eq!(roles[..4], [0, 3, 0, 1]);
        let audit = coordinator.reference_h3_audit_state();
        assert_eq!(audit, (2, false));
        let h0 = fixture.scene.real.h0.clone();
        let stash_originals = fixture
            .scene
            .real
            .lane
            .with_pending_h3_continuation(|pending| {
                pending
                    .originals()
                    .map(|(position, origin, record, resource)| {
                        (
                            position,
                            origin,
                            record.event.ts_ns,
                            resource.map(|resource| resource.invocation()),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap();
        assert_eq!(stash_originals.len(), 1);
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
                Ok(QuantumSealProgress::LocalPending),
                "the original negative has not reached its consumer"
            );
            let (retained, reason) = q1
                .finish_frame(&mut ports)
                .err()
                .expect("generic finish cannot consume pending H3");
            assert_eq!(reason, RawQuantumRefusal::H3Undisposed);
            q1 = retained;
        }
        // Work includes a visit to an earlier nonaffecting target. Read the
        // SAME original cursor; no assumed one-call/one-effect mapping or
        // unbounded retry can hide a stranded negative consumer.
        let bound = effects
            + fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .joint_feed_targets()
                .count();
        for _ in 0..bound {
            if q1.negative_effects_complete_for_test(a.bootstrap().domain()) == Some(true) {
                break;
            }
            {
                let mut ports = fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_frame_ports(&fixture.scene.producers)
                    .unwrap();
                assert_eq!(
                    q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
                    Ok(QuantumSealProgress::LocalPending),
                    "every incomplete original span refuses Future"
                );
            }
            fixture.deliver_one_work(&mut q1);
        }
        assert_eq!(
            q1.negative_effects_complete_for_test(a.bootstrap().domain()),
            Some(true),
            "a nonaffecting target cannot starve the later original negative span"
        );
        assert_eq!(
            fixture.feeds(),
            feeds,
            "q1 delivers negative effects without replay/disposal"
        );
        let coordinator = &fixture.scene.real.scene.coordinator;
        assert_eq!(
            coordinator
                .joint_capture()
                .adapter()
                .retained_starts_for_test(),
            starts
        );
        assert_eq!(
            coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test(),
            claims
        );
        assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
        assert_eq!(coordinator.reference_h3_audit_state(), audit);
        assert_eq!(coordinator.reference_h3_acknowledged_below(), 0);
        if arm == 2 {
            // An actual lost membership is not excused by an effects cursor
            // or a numeric position. No repair/mint is supplied by this test.
            let coordinator = &mut fixture.scene.real.scene.coordinator;
            coordinator
                .joint_capture_mut()
                .ledger_mut()
                .release_collected(fixture.scene.producers.native_domain(), 3);
            let damaged_roles = coordinator.joint_capture().ledger().roles_for_test();
            assert_eq!(damaged_roles[3], 0);
            let mut ports = coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            assert_eq!(
                q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
                Ok(QuantumSealProgress::LocalPending)
            );
            let (retained, reason) = q1
                .finish_pending_h3(&mut ports, &fixture.scene.real.lane)
                .err()
                .expect("missing original H9 role refuses");
            assert_eq!(reason, RawQuantumRefusal::H3Undisposed);
            drop(retained);
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_capture()
                    .ledger()
                    .roles_for_test(),
                damaged_roles
            );
            continue;
        }
        {
            let mut ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            let real = h0.0.borrow().collected_producers.clone().unwrap();
            h0.0.borrow_mut().collected_producers = Some(SessionDrainProducers::test_pair(
                real.native_domain(),
                EventsDomain::test_standin(real.events_id()),
            ));
            assert_eq!(
                q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
                Ok(QuantumSealProgress::LocalPending)
            );
            h0.0.borrow_mut().collected_producers = Some(real);
            let original_stash = h0.0.borrow_mut().stash.take_outcomes();
            assert_eq!(
                q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
                Ok(QuantumSealProgress::LocalPending)
            );
            assert_eq!(
                h0.0.borrow_mut().stash.push_all(Vec::new(), original_stash),
                0
            );
            assert_eq!(
                q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
                Ok(QuantumSealProgress::AwaitFutureInput),
                "delivered original negative plus exact producer continuation must allow q2"
            );
            let (retained, reason) = q1
                .finish_frame(&mut ports)
                .err()
                .expect("Future still grants no generic finish");
            assert_eq!(reason, RawQuantumRefusal::H3Undisposed);
            q1 = retained;
            q1.finish_pending_h3(&mut ports, &fixture.scene.real.lane)
                .unwrap_or_else(|(_, reason)| {
                    panic!("original pending sibling continuation arm{arm}: {reason:?}")
                });
        }
        assert_eq!(fixture.feeds(), feeds);
        let coordinator = &fixture.scene.real.scene.coordinator;
        assert_eq!(
            coordinator
                .joint_capture()
                .adapter()
                .retained_starts_for_test(),
            starts
        );
        assert_eq!(
            coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test(),
            claims
        );
        assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
        assert_eq!(coordinator.reference_h3_audit_state(), audit);
        assert_eq!(coordinator.reference_h3_acknowledged_below(), 0);
        assert_eq!(
            fixture
                .scene
                .real
                .lane
                .with_pending_h3_continuation(|pending| {
                    pending
                        .originals()
                        .map(|(position, origin, record, resource)| {
                            (
                                position,
                                origin,
                                record.event.ts_ns,
                                resource.map(|resource| resource.invocation()),
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap(),
            stash_originals
        );

        // The next actual collection merges C's retained q1 original and B's
        // real END; it cannot replay the already-direct S1Only sibling.
        let fault = FrameFault::clean();
        if arm == 1 {
            fault.epoch.set(1);
        }
        fixture.scene.drain.source_mut().push_record(end_b.to_vec());
        let raw = fixture.scene.collect_with_fault(&fault);
        fixture.scene.real.h0.0.borrow_mut().collected = Some(raw);
        let batch = fixture.scene.real.tick();
        fixture.scene.admit_providers(child_c.id(), c_caller, &[0]);
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
            [4, 6]
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
        let raw = h0.0.borrow_mut().collected.take().unwrap();
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
            .unwrap_or_else(|(_, reason)| panic!("actual pending sibling q2: {reason:?}"));
        let mut claims_q2 = Vec::new();
        while let Some((position, proof)) = fixture
            .scene
            .real
            .scene
            .coordinator
            .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
            .unwrap()
        {
            claims_q2.push((position, proof.expect("genuine C/B original admissions")));
        }
        assert_eq!(
            claims_q2
                .iter()
                .map(|(position, _)| *position)
                .collect::<Vec<_>>(),
            [4, 6]
        );
        if arm == 0 {
            fixture.retain_collected_birth(&admitted[0], current_c, claims_q2[0].1);
        }
        // On actual native loss no C birth/Joint grant is minted from claims.
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
        let mut q2 = acquire(&mut fixture.scene, ingested, &fixture.attached, &fault);
        if arm == 1 {
            assert_eq!(q2.failure_for_test().unwrap().gap, JournalGap::FaultChanged);
        } else {
            assert!(q2.failure_for_test().is_none());
        }
        {
            let ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            q2.bind_targets(&ports).unwrap();
        }
        fixture.finish_bounded_batch(q2, false);
        let a_after = fixture
            .feeds()
            .into_iter()
            .find(|feed| feed.id == a.id())
            .unwrap();
        let a_before = feeds.iter().find(|feed| feed.id == a.id()).unwrap();
        assert_eq!(a_after.staged, 0);
        if arm == 0 {
            assert!(a_after.fallback && !a_after.degraded);
            assert_eq!(a_after.reduced - a_before.reduced, 1);
            assert_eq!(a_after.disposed, a_before.disposed);
            assert_eq!(fixture.s1_counts(a.id()), (2, 1, 0, 0, 1));
        } else {
            assert!(a_after.degraded && !a_after.fallback);
            assert_eq!(a_after.reduced, a_before.reduced);
            assert_eq!(a_after.disposed - a_before.disposed, 1);
            assert_eq!(fixture.s1_counts(a.id()), (1, 0, 0, 0, 0));
        }
        assert_eq!(fixture.s1_counts(direct), direct_before);
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
            0
        );
    }
}

fn fallback_history_then_later_loss(next_frame: bool) {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    fixture.push_two("C_SignInit", 2);
    let fault = FrameFault::clean();
    let mut frame = fixture.audited(2, 2, &fault);
    let first = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .joint_feed_targets()
        .next()
        .unwrap();
    let initial = fixture.feeds();
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
    fixture.seal_selected_for_batch(&mut frame, true);
    for _ in 0..32 {
        fixture.deliver_one_work(&mut frame);
        if fixture
            .feeds()
            .iter()
            .find(|feed| feed.id == first.id())
            .unwrap()
            .fallback
        {
            break;
        }
    }
    let fallback = fixture
        .feeds()
        .into_iter()
        .find(|feed| feed.id == first.id())
        .unwrap();
    assert!(fallback.fallback && !fallback.degraded);
    assert_eq!(
        (fallback.staged, fixture.s1_counts(first.id())),
        (0, (2, 1, 0, 0, 1))
    );
    if next_frame {
        fixture.finish_bounded_batch(frame, false);
        fault.epoch.set(1);
        frame = fixture.audited(0, 0, &fault);
        let ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
    } else {
        fault.epoch.set(1);
        let h0 = fixture.scene.real.h0.clone();
        let mut births = NativeFrameBirths {
            h0: &h0,
            attached: &fixture.attached,
            retained: &mut fixture.births,
            seen: Vec::new(),
            unreadable: false,
        };
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
        assert!(
            births.seen.is_empty(),
            "actual moved fault refuses before birth"
        );
    }
    let failure = frame.failure_for_test().unwrap();
    assert_eq!(
        failure.gap,
        crate::semantics_objects::journal::JournalGap::FaultChanged
    );
    assert!(failure.affects_domain(first.bootstrap().domain()));
    assert!(!failure.effects.effects.is_empty());
    let mut foreign = CanonicalFanoutScene::prior_sealed();
    let before = fixture.feeds();
    let mut remaining = 1;
    {
        let mut ports = foreign
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&foreign.scene.producers)
            .unwrap();
        assert_eq!(
            frame.deliver_next_bounded(&mut ports, &mut remaining),
            Err(RawQuantumRefusal::ForeignCapture)
        );
    }
    assert_eq!(remaining, 1);
    assert_eq!(fixture.feeds(), before);
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        let (retained, _) = frame
            .finish_frame(&mut ports)
            .err()
            .expect("no early finish before actual affecting negative delivery");
        frame = retained;
    }
    for _ in 0..128 {
        if fixture.deliver_one_work(&mut frame) == QuantumSealProgress::Complete {
            break;
        }
    }
    assert_eq!(
        fixture.s1_counts(first.id()),
        (2, 1, 0, 1, 0),
        "S1Only gates positive replay, never authenticated affecting loss"
    );
    let after = fixture
        .feeds()
        .into_iter()
        .find(|feed| feed.id == first.id())
        .unwrap();
    assert!(after.degraded);
    assert_eq!(
        (after.reduced, after.disposed, after.staged),
        (fallback.reduced, fallback.disposed, 0)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .feed_mode_for_test(first.id()),
        Some(crate::semantics_key_use::FeedMode::S1Only)
    );
    assert!(
        !fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .keyuse_for_test()
            .open()
            .keys()
            .any(|(id, _)| *id == first.id())
    );
    for feed in fixture.feeds() {
        let prior = initial.iter().find(|old| old.id == feed.id).unwrap();
        if feed.id != first.id() {
            assert!(feed.degraded);
            assert_eq!(
                feed.reduced - prior.reduced + feed.disposed - prior.disposed,
                1
            );
        }
    }
    let counts = fixture.s1_counts(first.id());
    let evidence = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .keyuse_for_test()
        .evidence();
    for _ in 0..3 {
        fixture.deliver_one_work(&mut frame);
    }
    assert_eq!(fixture.s1_counts(first.id()), counts);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .keyuse_for_test()
            .evidence(),
        evidence
    );
    fixture.finish_bounded_batch(frame, false);
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
fn key_operation_joint_fallback_then_same_frame_loss_invalidates_once() {
    fallback_history_then_later_loss(false);
}

#[test]
fn key_operation_s1only_history_next_frame_loss_invalidates_once() {
    fallback_history_then_later_loss(true);
}

/// A genuine S1Only C may have an exact successful key claim without a Joint
/// birth grant. Its negative must consume only that original and must not
/// strand the healthy, disjoint A/B targets or retire their live objects.
#[test]
fn key_operation_s1only_own_claim_disposes_disjoint_raw() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    let before_model = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    let child_c = OwnedStoppedChild::new();
    let caller = fixture.scene.real.bind(
        child_c.id(),
        ImageIdentity {
            task_cookie: 73,
            exec_id: 0,
        },
        0,
    );
    for (sequence, name) in ["C_SignInit", "C_SignUpdate", "C_SignFinal"]
        .into_iter()
        .enumerate()
    {
        fixture
            .scene
            .push(child_c.id(), 0, name, sequence as u64 + 1);
    }
    let raw = fixture.scene.collect_with_fault(&BirthFault);
    fixture.scene.real.h0.0.borrow_mut().collected = Some(raw);
    let batch = fixture.scene.real.tick();
    fixture.scene.admit_providers(child_c.id(), caller, &[0]);
    fixture.scene.prepare_batch(batch, 3);
    let raw = fixture
        .scene
        .real
        .h0
        .0
        .borrow_mut()
        .collected
        .take()
        .unwrap();
    let mut ingested = raw
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
        .unwrap_or_else(|(_, reason)| panic!("original C raw: {reason:?}"));
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    let mut claims = Vec::new();
    while let Some((position, proof)) = coordinator
        .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
        .unwrap()
    {
        assert!(
            proof.is_ok(),
            "successful real C claims are not a Joint feed grant"
        );
        claims.push(position);
    }
    assert_eq!(claims, [3, 4, 5]);
    let original_claims = coordinator
        .joint_capture()
        .adapter()
        .invocation_claims_for_test();
    let starts = coordinator
        .joint_capture()
        .adapter()
        .retained_starts_for_test();
    let roles = coordinator.joint_capture().ledger().roles_for_test();
    assert_eq!(roles[..4], [0, 3, 0, 0]);
    let mut staged = 0;
    while coordinator
        .stage_next_prepared_admission_with_disposition(&fixture.scene.producers, &mut ingested)
        .unwrap_or_else(|reason| {
            panic!("exact own S1Only claim must retain negative disposition, not stall: {reason:?}")
        })
    {
        staged += 1;
    }
    assert_eq!(staged, 3);
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test(),
        original_claims
    );
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test(),
        starts
    );
    assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
    assert!(coordinator.finish_prepared_semantic_batch(&fixture.scene.real.lane));
    coordinator
        .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
        .unwrap();
    let c = coordinator
        .registry()
        .instance_semantic_edges()
        .find(|record| record.caller == caller)
        .unwrap()
        .id;
    assert_eq!(
        coordinator.registry().feed_mode_for_test(c),
        Some(crate::semantics_key_use::FeedMode::S1Only)
    );
    assert_eq!(fixture.s1_counts(c), (3, 1, 1, 0, 0));
    let mut frame = acquire(&mut fixture.scene, ingested, &fixture.attached, &BirthFault);
    assert_eq!(
        frame.failure_for_test().unwrap().gap,
        crate::semantics_objects::journal::JournalGap::ImageTainted
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
    fixture.finish_bounded_batch(frame, false);
    assert_eq!(fixture.s1_counts(c), (3, 1, 1, 0, 0));
    let after_model = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    for object in &before_model.objects {
        assert_eq!(
            after_model.object(object.id).unwrap().lifetime,
            Lifetime::Live
        );
    }
    assert!(
        fixture
            .feeds()
            .iter()
            .all(|feed| feed.staged == 0 && !feed.degraded && !feed.fallback)
    );
}
