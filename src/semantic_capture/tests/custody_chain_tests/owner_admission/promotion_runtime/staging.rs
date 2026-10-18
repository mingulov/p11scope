//! SPDX-License-Identifier: GPL-3.0-or-later
//! Pre-activation visibility at the genuine owner-consumption boundary.
//! Until the private stage exists, these diagnostics exercise the current
//! immediate consumer and expose exactly why it cannot serve as that stage.

use super::*;
use crate::discovery::engine::inventory_coordinator::semantics::{
    SemanticAdmissionCandidate, SemanticBindingRefusal,
};
use crate::inventory_semantics::{PreparedSemanticAdmission, SemanticRefusal};

fn prepare_owner(
    scene: &mut AdmissionScene,
    refuse_provider_storage: bool,
) -> (SemanticAdmissionCandidate, PreparedSemanticAdmission) {
    scene.prepare_without_cookie();
    scene.observe_entry();
    let caller = scene.caller();
    let lane = scene.lane.as_mut().unwrap();
    let candidate = scene
        .coordinator
        .prepare_legacy_semantic_candidate(caller, lane.domain())
        .expect("the actual catalog retains the original eligible caller");
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
    (candidate, prepared)
}

#[test]
fn promotion_stage_immediate_consumer_healthy_control() {
    let mut scene = AdmissionScene::new(Selection::Pid);
    let (candidate, prepared) = prepare_owner(&mut scene, false);
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
    let (candidate, prepared) = prepare_owner(&mut scene, false);
    // RED diagnostic: the old immediate consumer is deliberately used here.
    // The implementation replaces this call with the genuine private stage;
    // no native success or activation receipt is manufactured by the fixture.
    let (receipt, result) = scene
        .coordinator
        .consume_semantic_admission(candidate, prepared, None);
    assert_eq!(result, Ok(()));
    assert_eq!(
        scene.coordinator.semantic_bindings().len(),
        0,
        "a prepared owner receipt cannot publish a binding before native activation"
    );
    assert_eq!(scene.coordinator.registry().instances().count(), 0);
    drop(receipt);
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
    let (candidate, prepared) = prepare_owner(&mut scene, true);
    let (receipt, result) = scene
        .coordinator
        .consume_semantic_admission(candidate, prepared, None);
    assert_eq!(
        result,
        Err(SemanticBindingRefusal::OwnerRefused(
            SemanticRefusal::ProviderStorage
        ))
    );
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
    assert_eq!(scene.coordinator.registry().instances().count(), 0);
    drop(receipt);
    assert!(
        scene
            .coordinator
            .prepare_legacy_semantic_candidate(scene.caller(), NativeDomainId::mint())
            .is_some(),
        "a provisional provider refusal cannot install negative history in the live coordinator"
    );
}
