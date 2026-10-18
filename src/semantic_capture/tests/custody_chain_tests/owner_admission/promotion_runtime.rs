//! SPDX-License-Identifier: GPL-3.0-or-later
//! Original process custody at the real Inventory-to-Detailed admission seam.
//! Native I/O uses the existing parent fixture; no receipt is constructed here.

use super::*;

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
