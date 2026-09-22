// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::discovery::scan::{InventoryRetainedLimits, InventoryWindowLimits};

fn config(owners: usize, leases: usize) -> InventoryDiscoveryConfig {
    InventoryDiscoveryConfig::new(
        InventoryDiscoveryLimits::new(
            8 << 20,
            InventoryWindowLimits::new(16 << 20, 1 << 20, 1024, 8192, 1024).unwrap(),
            InventoryRetainedLimits::new(1024, 8192, 1024, 64, 64, 8 << 20).unwrap(),
        )
        .unwrap(),
        InventoryOwnerLimits::new(owners, leases, 8192).unwrap(),
        InventoryBudget::new(2048, 2048 * 8).unwrap(),
    )
}

fn engine(owners: usize, leases: usize) -> Engine {
    Engine::inventory(
        config(owners, leases),
        Scope::Pid(std::process::id()),
        HookRegistry::builtin(),
        Vec::new(),
    )
    .unwrap()
}

// Only the native query is scripted. This never purports to read the host's
// task-storage identity map or qualify a running Inventory capture.
struct ScriptedImage(ImageCheck);
impl ImageGuard for ScriptedImage {
    fn check(&mut self, view: &ProcessView, image: ImageIdentity) -> ImageCheck {
        assert!(view.still_the_same());
        assert_eq!(image, expected());
        self.0
    }
}

fn expected() -> ImageIdentity {
    ImageIdentity {
        task_cookie: 42,
        exec_id: 0,
    }
}

fn open(engine: &mut Engine) -> ProcessViewId {
    engine
        .open_inventory_owner(
            std::process::id(),
            expected(),
            &mut ScriptedImage(ImageCheck::Exact),
        )
        .unwrap()
}

#[test]
fn checked_owner_limits_reject_empty_or_impossible_envelopes() {
    for (owners, leases, refs) in [(0, 1, 1), (1, 0, 1), (1, 1, 0), (1, 2, 1)] {
        assert!(InventoryOwnerLimits::new(owners, leases, refs).is_err());
    }
    assert!(InventoryOwnerLimits::new(u32::MAX as usize + 1, 1, 1).is_err());
}

#[test]
fn explicit_constructor_sets_both_policies_before_any_owner_or_io() {
    let engine = engine(512, 2);
    let cfg = config(512, 2);
    assert_eq!(engine.budget.policy(), DiscoveryPolicy::Inventory(cfg.work));
    assert_eq!(
        engine.plan.admission_policy(),
        plan::AdmissionPolicy::Inventory(cfg.admission)
    );
    assert!(engine.views.is_empty() && engine.modules.is_empty());
    assert!(engine.plan.slots.is_empty());
    let detailed = Engine::empty();
    assert_eq!(detailed.budget.policy(), DiscoveryPolicy::DetailedLegacy);
    assert_eq!(
        detailed.plan.admission_policy(),
        plan::AdmissionPolicy::Detailed
    );
    assert!(detailed.inventory.is_none());
}

#[test]
fn unavailable_image_guard_releases_reservation_but_never_reuses_id() {
    let mut engine = engine(1, 1);
    assert!(
        engine
            .open_inventory_owner(std::process::id(), expected(), &mut UnavailableImageGuard)
            .is_err()
    );
    assert!(engine.views.is_empty());
    assert!(engine.inventory_state().unwrap().reservations.is_empty());
    assert_eq!(open(&mut engine), ProcessViewId(1));
    assert!(
        engine.allocate_view_id().is_err(),
        "retained owner occupies the sole reservation"
    );
}

#[test]
fn absent_cookie_or_wrong_pid_scope_cannot_admit_an_owner() {
    let mut engine = engine(2, 1);
    assert!(
        engine
            .open_inventory_owner(
                std::process::id(),
                ImageIdentity::default(),
                &mut ScriptedImage(ImageCheck::Exact)
            )
            .is_err()
    );
    assert!(
        engine
            .open_inventory_owner(
                std::process::id() + 1,
                expected(),
                &mut ScriptedImage(ImageCheck::Exact)
            )
            .is_err()
    );
    assert!(engine.views.is_empty());
    assert_eq!(engine.next_view_id, 0);
}

#[test]
fn leases_are_unique_nonreplayable_and_capture_local() {
    let mut first = engine(2, 1);
    let mut second = engine(2, 1);
    let a = first.allocate_view_id().unwrap();
    let b = second.allocate_view_id().unwrap();
    assert_eq!(a, b);
    let lease = first.acquire_inventory_scan(a).unwrap();
    assert!(first.acquire_inventory_scan(a).is_err());
    assert!(second.release_inventory_scan(&lease).is_err());
    first.release_inventory_scan(&lease).unwrap();
    let replacement = first.acquire_inventory_scan(a).unwrap();
    assert!(first.release_inventory_scan(&lease).is_err());
    first.release_inventory_scan(&replacement).unwrap();
}

#[test]
fn policy_mismatch_refuses_before_work_or_owner_mutation() {
    let mut engine = engine(2, 1);
    let owner = open(&mut engine);
    engine.plan = plan::AttachPlan::from_slots(Vec::new());
    assert!(engine.acquire_inventory_scan(owner).is_err());
    assert!(
        engine
            .request_inventory_refresh(owner, RefreshCause::Periodic)
            .is_err()
    );
    assert!(engine.inventory.as_ref().unwrap().leases.is_empty());
    assert_eq!(
        engine.inventory.as_ref().unwrap().owners[&owner].requested_epoch,
        0
    );
}

#[test]
fn owner_id_exhaustion_does_not_wrap_or_create_reservation() {
    let mut engine = engine(2, 1);
    engine.next_view_id = u32::MAX;
    assert!(engine.allocate_view_id().is_err());
    assert_eq!(engine.next_view_id, u32::MAX);
    assert!(engine.inventory_state().unwrap().reservations.is_empty());
}

#[test]
fn unavailable_image_refuses_before_scanner_is_called() {
    let mut engine = engine(2, 1);
    let owner = open(&mut engine);
    let lease = engine.acquire_inventory_scan(owner).unwrap();
    assert!(
        engine
            .scan_inventory_owner_with(&lease, &mut UnavailableImageGuard, |_, _, _| panic!(
                "unavailable image authority must prevent scanning"
            ))
            .is_err()
    );
    assert_eq!(
        engine.inventory_state().unwrap().owners[&owner].image_state,
        ImageCheck::Unavailable
    );
    assert_eq!(engine.views.len(), 1);
    assert!(engine.retirement_intents.is_empty());
    engine.release_inventory_scan(&lease).unwrap();
}

#[test]
fn stale_claim_revision_and_foreign_capture_receipts_are_refused() {
    let mut first = engine(2, 1);
    let owner = open(&mut first);
    let identity = first.inventory_receipt_identity(owner).unwrap();
    first
        .inventory
        .as_mut()
        .unwrap()
        .owners
        .get_mut(&owner)
        .unwrap()
        .revision += 1;
    assert!(
        first
            .check_inventory_image(&identity, &mut ScriptedImage(ImageCheck::Exact))
            .is_err()
    );
    let mut second = engine(2, 1);
    assert_eq!(open(&mut second), owner);
    assert!(
        second
            .check_inventory_image(&identity, &mut ScriptedImage(ImageCheck::Exact))
            .is_err()
    );
}

#[test]
fn proved_image_change_cannot_be_revived_by_a_later_stale_exact_reply() {
    let mut engine = engine(2, 1);
    let owner = open(&mut engine);
    let identity = engine.inventory_receipt_identity(owner).unwrap();
    assert!(
        engine
            .check_inventory_image(&identity, &mut ScriptedImage(ImageCheck::Changed))
            .is_err()
    );
    assert!(
        engine
            .check_inventory_image(&identity, &mut ScriptedImage(ImageCheck::Exact))
            .is_err()
    );
    assert_eq!(
        engine.inventory_state().unwrap().owners[&owner].image_state,
        ImageCheck::Changed
    );
    assert_eq!(engine.views.len(), 1);
    assert!(engine.retirement_intents.is_empty());
}

#[test]
fn generic_refreshes_keep_distinct_dirty_causes_without_retirement() {
    let mut engine = engine(2, 1);
    let owner = open(&mut engine);
    for cause in [
        RefreshCause::LoaderHint,
        RefreshCause::Periodic,
        RefreshCause::TransportRecovery(7),
        RefreshCause::TransportRecovery(3),
        RefreshCause::ScopeRecheck,
    ] {
        engine.request_inventory_refresh(owner, cause).unwrap();
    }
    let record = &engine.inventory_state().unwrap().owners[&owner];
    assert_eq!(
        (record.dirty, record.requested_epoch, record.recovery_epoch),
        (15, 5, 7)
    );
    assert_eq!(record.serviced_epoch, 0);
    assert_eq!(record.last_complete_revision, None);
    assert!(engine.retirement_intents.is_empty());
}
