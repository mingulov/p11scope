//! SPDX-License-Identifier: GPL-3.0-or-later
//! Original process custody at the real Inventory-to-Detailed admission seam.
//! Native I/O uses the existing parent fixture; no receipt is constructed here.

use super::*;

#[path = "promotion_runtime/staging.rs"]
mod staging;

#[test]
fn promotion_runtime_scoped_preparation_reuses_original_inventory_pin() {
    let mut scene = AdmissionScene::new(Selection::Cgroup);
    scene.prepare_without_cookie();
    let caller = scene.caller();
    let mut collection = scene
        .coordinator
        .cgroup_collector(
            std::mem::take(&mut scene.continuation),
            CgroupWalkLimits::default(),
            scene.control.clone(),
            None,
        )
        .unwrap()();
    let preparation = collection.preparation(scene.child.id()).unwrap();
    let prepared = scene
        .coordinator
        .adapter_mut()
        .prepare_scoped_caller(&preparation)
        .map_err(|failure| failure.reason)
        .unwrap();
    let candidate = scene
        .coordinator
        .prepare_scoped_semantic_candidate(&prepared, scene.lane.as_ref().unwrap().domain())
        .unwrap();
    assert!(std::ptr::eq(
        candidate.pin().as_ref(),
        scene
            .coordinator
            .adapter()
            .semantic_custody_ref(caller)
            .unwrap()
    ));
    let mut requested = BTreeSet::new();
    requested.insert(scene.child.id());
    collection.sample_end(&requested);
    let permit = collection.permit(scene.child.id()).unwrap();
    scene.control.cancel();
    assert!(
        scene
            .coordinator
            .adapter_mut()
            .commit_scoped_caller(prepared, permit, 20, &mut || Some(21))
            .is_err(),
        "an expired real scope permit cannot commit even with the original shared Arc"
    );
    assert_eq!(
        scene.coordinator.adapter().live_id(scene.child.id()),
        Some(caller)
    );
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
}

#[test]
fn promotion_runtime_new_scoped_caller_moves_prepared_original_pin() {
    let mut scene = AdmissionScene::new(Selection::Cgroup);
    let mut collection = scene
        .coordinator
        .cgroup_collector(
            CgroupWalkState::default(),
            CgroupWalkLimits::default(),
            scene.control.clone(),
            None,
        )
        .unwrap()();
    let preparation = collection.preparation(scene.child.id()).unwrap();
    let prepared = scene
        .coordinator
        .adapter_mut()
        .prepare_scoped_caller(&preparation)
        .map_err(|failure| failure.reason)
        .unwrap();
    assert!(prepared.existing().is_none());
    let original = scene
        .coordinator
        .adapter()
        .scoped_shared_semantic_custody(&prepared)
        .unwrap();
    let weak = PidPin::downgrade_shared(&original).unwrap();
    let mut requested = BTreeSet::new();
    requested.insert(scene.child.id());
    collection.sample_end(&requested);
    let permit = collection.permit(scene.child.id()).unwrap();
    let (caller, admitted) = scene
        .coordinator
        .adapter_mut()
        .commit_scoped_caller(prepared, permit, 20, &mut || Some(21))
        .map_err(|failure| failure.reason)
        .unwrap();
    assert!(admitted);
    let tracked = scene
        .coordinator
        .adapter()
        .shared_semantic_custody(caller)
        .unwrap();
    assert!(Arc::ptr_eq(&original, &tracked));
    assert!(weak.matches_original(&tracked));
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
    assert_eq!(scene.h0.0.borrow().accepted, 0);
}

#[test]
fn promotion_runtime_pid_candidate_shares_original_inventory_pin() {
    assert_first_candidate_shares_original(Selection::Pid);
}

#[test]
fn promotion_runtime_system_candidate_shares_original_inventory_pin() {
    assert_first_candidate_shares_original(Selection::System);
}

fn assert_first_candidate_shares_original(selection: Selection) {
    let mut scene = AdmissionScene::new(selection);
    scene.prepare_without_cookie();
    let caller = scene.caller();
    let candidate = scene
        .coordinator
        .prepare_legacy_semantic_candidate(caller, scene.lane.as_ref().unwrap().domain())
        .expect("actual mapped caller is eligible for first owner preparation");
    let pin = candidate.pin();
    let original = scene
        .coordinator
        .adapter()
        .semantic_custody_ref(caller)
        .expect("Inventory retains its original process pin");
    assert_eq!(pin.pid(), original.pid());
    assert_eq!(pin.start_time(), original.start_time());
    assert!(pin.still_the_same() && original.still_the_same());
    assert!(
        std::ptr::eq(pin.as_ref(), original),
        "{selection:?}: first Detailed candidate must share Inventory's original allocation, not a duplicated pidfd or replacement Arc"
    );
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
    assert_eq!(scene.coordinator.registry().instances().count(), 0);
    assert_eq!(scene.h0.0.borrow().accepted, 0);
}

#[test]
fn promotion_runtime_weak_candidate_cannot_keep_process_custody_alive() {
    let weak = {
        let mut scene = AdmissionScene::new(Selection::Pid);
        scene.prepare_without_cookie();
        let caller = scene.caller();
        let candidate = scene
            .coordinator
            .prepare_legacy_semantic_candidate(caller, scene.lane.as_ref().unwrap().domain())
            .expect("healthy actual admission candidate");
        let pin = candidate.pin();
        let weak = Arc::downgrade(&pin);
        drop(candidate);
        assert!(
            weak.upgrade().is_some(),
            "owned strong candidate remains live"
        );
        drop(pin);
        assert!(
            weak.upgrade().is_some(),
            "Inventory must remain the original strong owner after a candidate is dropped"
        );
        weak
    };
    assert!(
        weak.upgrade().is_none(),
        "dropping the capture and its actual lane releases custody; a view's Weak cannot keep the pidfd alive"
    );
}
