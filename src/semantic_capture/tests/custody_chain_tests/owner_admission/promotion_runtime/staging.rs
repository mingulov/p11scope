//! SPDX-License-Identifier: GPL-3.0-or-later
//! Pre-activation visibility at the genuine owner-consumption boundary.
//! Ordinary and private consumers share the same real evidence validator;
//! only the destination of its history/binding effects differs.

use super::*;
use crate::discovery::engine::inventory_coordinator::semantics::{
    PromotionAdmissionReservation, SemanticAdmissionCandidate, SemanticBindingRefusal,
};
use crate::inventory_semantics::{PreparedSemanticAdmission, SemanticRefusal};

fn prepare_owner(
    scene: &mut AdmissionScene,
    refuse_provider_storage: bool,
) -> (
    SemanticAdmissionCandidate,
    PreparedSemanticAdmission,
    PromotionAdmissionReservation,
) {
    scene.prepare_without_cookie();
    scene.observe_entry();
    prepare_owner_after_catalog(scene, refuse_provider_storage)
}

fn prepare_owner_after_catalog(
    scene: &mut AdmissionScene,
    refuse_provider_storage: bool,
) -> (
    SemanticAdmissionCandidate,
    PreparedSemanticAdmission,
    PromotionAdmissionReservation,
) {
    let caller = scene.caller();
    let lane = scene.lane.as_mut().unwrap();
    let candidate = scene
        .coordinator
        .prepare_legacy_semantic_candidate(caller, lane.domain())
        .expect("the actual catalog retains the original eligible caller");
    let reservation = scene
        .coordinator
        .reserve_promotion_admission(&candidate)
        .unwrap();
    let pin = lane.subset().pins().pinned().next().unwrap();
    let module = ModuleKey::physical(
        pin.key.device.major,
        pin.key.device.minor,
        pin.key.inode,
        Some(pin.sha256.to_owned()),
        pin.path,
    );
    let slot = scene.h0.0.borrow().io.held.slot(0, "C_SignInit");
    if refuse_provider_storage {
        // The same real pool already holds original-custody allocations.
        // Setting its ceiling at that live baseline refuses the next copy.
        let baseline = scene
            .coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes;
        scene
            .coordinator
            .registry_mut()
            .reference_semantic_resource_limit(baseline);
    }
    let prepared = lane
        .prepare_caller_admission(candidate.pin(), slot, &module, |bytes| {
            scene.coordinator.registry().reserve_semantic_storage(bytes)
        })
        .expect("real H0 accepts the exact original-custody provider scan");
    assert!(scene.h0.0.borrow().accepted > 0);
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
    assert_eq!(scene.coordinator.registry().instances().count(), 0);
    (candidate, prepared, reservation)
}

#[test]
fn promotion_stage_first_candidate_rejects_divergent_h0_original_arc() {
    let mut scene = AdmissionScene::new(Selection::Pid);
    scene.prepare_without_cookie();
    scene.observe_entry();
    let (images, divergent) = scene.refresh_direct();
    assert_eq!(images, vec![image(7)]);
    let original = scene
        .coordinator
        .adapter()
        .shared_semantic_custody(scene.caller())
        .unwrap();
    assert!(!Arc::ptr_eq(&original, &divergent));
    let (candidate, prepared, _reservation) = prepare_owner_after_catalog(&mut scene, false);
    assert!(Arc::ptr_eq(&candidate.pin(), &original));
    let (receipt, result) = scene
        .coordinator
        .consume_semantic_admission(candidate, prepared, None);
    assert!(
        Arc::ptr_eq(receipt.original_pin(), &divergent),
        "the real H0 refresh retains its already accepted allocation"
    );
    assert_eq!(
        result,
        Err(SemanticBindingRefusal::ImageUnproven(
            crate::discovery::native_binding::UnboundReason::ExecAmbiguous
        )),
        "an independently accepted same-PID H0 allocation cannot replace Inventory's original Arc"
    );
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
}

#[test]
fn promotion_stage_immediate_consumer_healthy_control() {
    let mut scene = AdmissionScene::new(Selection::Pid);
    let (candidate, prepared, _reservation) = prepare_owner(&mut scene, false);
    let (receipt, result) = scene
        .coordinator
        .consume_semantic_admission(candidate, prepared, None);
    assert_eq!(result, Ok(()));
    let binding = scene
        .coordinator
        .semantic_bindings()
        .get(scene.caller())
        .expect("the ordinary immediate path must still install its binding");
    assert!(Arc::ptr_eq(&binding.pin(), receipt.original_pin()));
    assert_eq!(binding.domain(), receipt.domain());
    assert_eq!(binding.image(), receipt.image());
    scene
        .lane
        .as_mut()
        .unwrap()
        .deliver_admission_receipt(receipt);
}

#[test]
fn promotion_stage_accepted_evidence_is_private_before_activation() {
    let mut scene = AdmissionScene::new(Selection::Pid);
    let (candidate, prepared, reservation) = prepare_owner(&mut scene, false);
    let staged =
        scene
            .coordinator
            .stage_promotion_admission(reservation, candidate, prepared, None);
    let result = staged.result();
    assert_eq!(result, Ok(()));
    assert_eq!(
        scene.coordinator.semantic_bindings().len(),
        0,
        "a prepared owner receipt cannot publish a binding before native activation"
    );
    assert_eq!(scene.coordinator.registry().instances().count(), 0);
    drop(staged);
    assert!(
        scene
            .coordinator
            .prepare_legacy_semantic_candidate(scene.caller(), NativeDomainId::mint())
            .is_some(),
        "disposing a provisional stage leaves no current-domain admission history"
    );
}

#[test]
fn promotion_stage_refused_provider_leaves_no_global_admission_history() {
    let mut scene = AdmissionScene::new(Selection::Pid);
    let (candidate, prepared, reservation) = prepare_owner(&mut scene, true);
    let staged =
        scene
            .coordinator
            .stage_promotion_admission(reservation, candidate, prepared, None);
    let result = staged.result();
    assert_eq!(
        result,
        Err(SemanticBindingRefusal::OwnerRefused(
            SemanticRefusal::ProviderStorage
        ))
    );
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
    assert_eq!(scene.coordinator.registry().instances().count(), 0);
    drop(staged);
    assert!(
        scene
            .coordinator
            .prepare_legacy_semantic_candidate(scene.caller(), NativeDomainId::mint())
            .is_some(),
        "a provisional provider refusal cannot install negative history in the live coordinator"
    );
}

#[test]
fn promotion_stage_budget_refuses_before_copy_or_owner_scan() {
    let mut scene = AdmissionScene::new(Selection::Pid);
    scene.prepare_without_cookie();
    let candidate = scene
        .coordinator
        .prepare_legacy_semantic_candidate(scene.caller(), scene.lane.as_ref().unwrap().domain())
        .unwrap();
    let baseline = scene.coordinator.registry().semantic_resource_snapshot();
    scene
        .coordinator
        .registry_mut()
        .reference_semantic_resource_limit(baseline.charged_bytes);
    let (result, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
        scene.coordinator.reserve_promotion_admission(&candidate)
    });
    assert!(matches!(result, Err(SemanticBindingRefusal::Capacity)));
    assert_eq!((allocations, bytes), (0, 0));
    assert_eq!(scene.h0.0.borrow().accepted, 0);
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
    assert_eq!(scene.coordinator.registry().instances().count(), 0);
    let after = scene.coordinator.registry().semantic_resource_snapshot();
    assert_eq!(after.charged_bytes, baseline.charged_bytes);
    assert_eq!(after.peak_charged_bytes, baseline.peak_charged_bytes);
    assert_eq!(after.refused, baseline.refused + 1);
}
