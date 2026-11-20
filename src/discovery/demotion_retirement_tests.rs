//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Behavioral retirement tests over retained real file identities.
use super::tests::{CaptureScene, NativeScene, capture_catalog};
use super::*;
use crate::discovery::engine::inventory::UnavailableImageGuard;
use crate::discovery::inventory_attach_set::tests as fx;
thread_local! { static QUERY_CLOCK: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
thread_local! {
    static WORK_RECEIPTS: std::cell::RefCell<Option<Vec<(usize, usize)>>> = const { std::cell::RefCell::new(None) };
    static RECEIPT_WORK_RECEIPTS: std::cell::RefCell<Option<Vec<usize>>> = const { std::cell::RefCell::new(None) };
}
// Test-side observation of the actual budget consumed by each production slice.
// This adds no production callback or alternate service path.
impl Drop for RecoveryWorkBudget {
    fn drop(&mut self) {
        WORK_RECEIPTS.with(|receipts| {
            if let Some(receipts) = receipts.borrow_mut().as_mut() {
                receipts.push((self.visited, self.queries));
            }
        });
    }
}
impl Drop for ReceiptWork {
    fn drop(&mut self) {
        RECEIPT_WORK_RECEIPTS.with(|receipts| {
            if let Some(receipts) = receipts.borrow_mut().as_mut() {
                receipts.push(self.visits);
            }
        });
    }
}
struct WorkReceipts;
impl WorkReceipts {
    fn begin() -> Self {
        WORK_RECEIPTS.with(|receipts| *receipts.borrow_mut() = Some(Vec::new()));
        RECEIPT_WORK_RECEIPTS.with(|receipts| *receipts.borrow_mut() = Some(Vec::new()));
        Self
    }
    fn assert_bounded(&self) {
        WORK_RECEIPTS.with(|receipts| {
            let mut receipts = receipts.borrow_mut();
            let receipts = receipts.as_mut().unwrap();
            assert!(
                !receipts.is_empty(),
                "actual production recovery slices ran"
            );
            for (visits, queries) in receipts.drain(..) {
                assert!(visits <= 128, "actual slice spent {visits} visits");
                assert!(queries <= 4, "actual slice attempted {queries} queries");
            }
        });
        RECEIPT_WORK_RECEIPTS.with(|receipts| {
            for visits in receipts.borrow_mut().as_mut().unwrap().drain(..) {
                assert!(
                    visits <= 32,
                    "actual fixed receipt resolution spent {visits} visits"
                );
            }
        });
    }
}
impl Drop for WorkReceipts {
    fn drop(&mut self) {
        WORK_RECEIPTS.with(|receipts| *receipts.borrow_mut() = None);
        RECEIPT_WORK_RECEIPTS.with(|receipts| *receipts.borrow_mut() = None);
    }
}
fn query_clock() -> Option<u64> {
    QUERY_CLOCK.with(|clock| Some(clock.get()))
}

fn members_catalog(
    scene: &Scene,
    members: &[(u32, CallerId, u64)],
    a_present: bool,
    at: u64,
) -> crate::inspect_system::Catalog {
    let paths: Vec<&std::path::Path> = if a_present {
        vec![&scene.a, &scene.b]
    } else {
        vec![&scene.b]
    };
    members_catalog_paths(scene, members, &paths, at)
}

fn members_catalog_paths(
    scene: &Scene,
    members: &[(u32, CallerId, u64)],
    paths: &[&std::path::Path],
    at: u64,
) -> crate::inspect_system::Catalog {
    let mut catalog = scene.catalog(true, true, at);
    catalog.processes.clear();
    catalog.objects.clear();
    for &(pid, caller, _) in members {
        let record = scene
            .native
            .scene
            .coordinator
            .adapter
            .record(caller)
            .unwrap();
        let generation = crate::inspect_system::MemberGeneration {
            start_time: record.start_time,
            exe: record.exe.clone(),
        };
        let mut member = capture_catalog(&scene.pins, paths, pid, Some(generation.clone()));
        member.processes[0].complete_scan = Some(
            crate::inspect_system::CompleteMemberScan::scripted(generation, at, at + 1),
        );
        let offset = catalog.objects.len();
        for index in &mut member.processes[0].objects {
            *index += offset;
        }
        catalog.objects.extend(member.objects);
        catalog.processes.extend(member.processes);
    }
    catalog.enumerated = members.len();
    catalog.selected = members.len();
    catalog.scanned = members.len();
    catalog.cap = members.len();
    catalog.lowering = Some(crate::inspect_system::CatalogLowering {
        plan: fx::lower_named(
            &paths
                .iter()
                .map(|path| fx::module_with_targets(&scene.pins, path, &[(&scene.a, 0x1000)]))
                .collect::<Vec<_>>(),
            &scene.pins,
            crate::plan::AdmissionPolicy::Inventory(
                scene.native.scene.coordinator.attach_set.budget(),
            ),
        ),
        pins: fx::pass_pins(&[(&scene.a, "sha-a"), (&scene.b, "sha-b")]),
        modules: Vec::new(),
    });
    catalog
}

fn round2_bound_members() -> (Scene, Vec<(u32, CallerId, u64)>) {
    let mut scene = Scene::placed();
    let mut members = vec![(7, scene.caller, 41)];
    for pid in 8..24 {
        let start = 500 + u64::from(pid);
        scene.native.scene.source.spawn(pid, start);
        let caller = scene
            .native
            .scene
            .coordinator
            .adapter
            .admit(pid, ImageAuthority::ScanPinned, 80)
            .unwrap();
        scene.native.scene.project_paths(pid, &[&scene.a], 90);
        scene.native.scene.coordinator.commit_batch(false).unwrap();
        let ticket = 100 + u64::from(pid);
        scene.native.answer(pid, start, ticket);
        let mut row = scene.native.row(ticket, 1, pid, 100, 0);
        row.entry_count = 5;
        scene.native.witness(vec![row]);
        members.push((pid, caller, ticket));
    }
    (scene, members)
}

fn round2_quiet_ownership(scene: &mut Scene) {
    for _ in 0..40 {
        QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
        scene
            .native
            .scene
            .coordinator
            .reconcile_count_eligibility(&mut scene.native.cookies, &mut RecoveryWorkBudget::new());
    }
}

#[test]
fn demotion_retirement_round2_direct_bound_transition_keeps_first_advance() {
    let receipts = WorkReceipts::begin();
    let (mut scene, members) = round2_bound_members();
    scene.apply(members_catalog(&scene, &members, true, 200), 200);
    // Current A+B is observed, but there is no shared advancing read. The
    // successfully placed pairs remain ordinary Bound A5 with no armed epoch.
    round2_quiet_ownership(&mut scene);
    assert!(
        scene
            .native
            .scene
            .coordinator
            .recoveries
            .values()
            .all(|recovery| !recovery.blocked
                && recovery.epoch.is_none()
                && recovery.watermark == 5)
    );
    for &(_, caller, _) in &members {
        assert_eq!(edge_count(&scene.native, caller, "a.so"), 5);
    }
    receipts.assert_bounded();
    scene.apply(members_catalog(&scene, &members, false, 300), 300);
    let unarmed: Vec<_> = scene
        .native
        .scene
        .coordinator
        .recoveries
        .iter()
        .filter(|(_, recovery)| !recovery.blocked)
        .map(|(&key, recovery)| (key, recovery.caller))
        .collect();
    assert!(
        !unarmed.is_empty(),
        "bounded service has not armed every changed pair"
    );
    receipts.assert_bounded();
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 8))
            .collect(),
    );
    let original_eights = scene.native.scene.coordinator.pair_counts.clone();
    receipts.assert_bounded();
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 10))
            .collect(),
    );
    receipts.assert_bounded();
    scene.apply(members_catalog(&scene, &members, false, 400), 400);
    receipts.assert_bounded();
    for _ in 0..40 {
        scene.horizons();
        receipts.assert_bounded();
    }
    for &(key, caller) in &unarmed {
        assert_eq!(
            (
                edge_count(&scene.native, caller, "a.so"),
                edge_count(&scene.native, caller, "b.so")
            ),
            (5, 2),
            "the actual transition must retain first8 before generic pending accounting can erase it"
        );
        let recovery = scene.native.scene.coordinator.recoveries.get(&key).unwrap();
        let fence = recovery.fence.expect("original advancing fence");
        let original = original_eights.get(&key).unwrap();
        assert_eq!(fence.count, 8);
        assert_eq!(
            (fence.anchor_ns, fence.last_ns),
            (original.anchor_ns, original.last_ns)
        );
        assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), 300);
    }
    for &(_, caller, _) in &members {
        assert_eq!(
            (
                edge_count(&scene.native, caller, "a.so"),
                edge_count(&scene.native, caller, "b.so")
            ),
            (5, 2)
        );
    }
}

#[test]
fn demotion_retirement_round2_membership_change_with_present_owner_keeps_fence() {
    let receipts = WorkReceipts::begin();
    let (mut scene, members) = round2_bound_members();
    scene.apply(members_catalog(&scene, &members, true, 200), 200);
    round2_quiet_ownership(&mut scene);
    assert!(
        scene
            .native
            .scene
            .coordinator
            .recoveries
            .values()
            .all(|recovery| !recovery.blocked
                && recovery.epoch.is_none()
                && recovery.watermark == 5)
    );
    let original_revision = scene.native.scene.coordinator.attach_set.count_revision();
    let retarget = |at| {
        let mut catalog = members_catalog(&scene, &members, true, at);
        // A remains present, but its real retained target membership moves to
        // another object. B keeps the original physical count object.
        catalog.lowering = Some(crate::inspect_system::CatalogLowering {
            plan: fx::lower_named(
                &[
                    fx::module_with_targets(&scene.pins, &scene.a, &[(&scene.b, 0x1000)]),
                    fx::module_with_targets(&scene.pins, &scene.b, &[(&scene.a, 0x1000)]),
                ],
                &scene.pins,
                crate::plan::AdmissionPolicy::Inventory(
                    scene.native.scene.coordinator.attach_set.budget(),
                ),
            ),
            pins: fx::pass_pins(&[(&scene.a, "sha-a"), (&scene.b, "sha-b")]),
            modules: Vec::new(),
        });
        catalog
    };
    let changed = retarget(300);
    let equivalent = retarget(400);
    scene.apply(changed, 300);
    assert!(scene.native.scene.coordinator.attach_set.count_revision() != original_revision);
    assert!(
        scene
            .native
            .scene
            .coordinator
            .recoveries
            .values()
            .any(|recovery| !recovery.blocked)
    );
    receipts.assert_bounded();
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 8))
            .collect(),
    );
    let original_eights = scene.native.scene.coordinator.pair_counts.clone();
    receipts.assert_bounded();
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 10))
            .collect(),
    );
    receipts.assert_bounded();
    scene.apply(equivalent, 400);
    receipts.assert_bounded();
    for _ in 0..40 {
        scene.horizons();
        receipts.assert_bounded();
    }
    for &(_, caller, _) in &members {
        assert_eq!(
            (
                edge_count(&scene.native, caller, "a.so"),
                edge_count(&scene.native, caller, "b.so")
            ),
            (5, 2),
            "membership-only carrier change must not publish unfenced generic growth"
        );
    }
    for (key, recovery) in &scene.native.scene.coordinator.recoveries {
        let fence = recovery.fence.expect("original actual first advance");
        let original = original_eights.get(key).unwrap();
        assert_eq!(fence.count, 8);
        assert_eq!(
            (fence.anchor_ns, fence.last_ns),
            (original.anchor_ns, original.last_ns)
        );
        assert_eq!(
            recovery.scan.as_ref().unwrap().started_ns(),
            300,
            "the new membership revision requires its original supporting scan"
        );
    }
}

#[test]
fn demotion_retirement_round2_deferred_same_carrier_keeps_all_ordinary_growth() {
    let receipts = WorkReceipts::begin();
    let (mut scene, members) = round2_bound_members();
    let initial = members_catalog_paths(&scene, &members, &[&scene.a], 200);
    scene.apply(initial, 200);
    round2_quiet_ownership(&mut scene);
    let equivalent = members_catalog_paths(&scene, &members, &[&scene.a], 300);
    scene.apply(equivalent, 300);
    let object = scene.native.scene.delta.endpoints[0].object.index();
    assert!(
        members.iter().any(|&(_, caller, _)| scene
            .native
            .scene
            .coordinator
            .count_ownership
            .deferred(caller, object)),
        "actual bounded comparison leaves at least one same-carrier observation pending"
    );
    let queries = scene.native.cookies.queries;
    receipts.assert_bounded();
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 8))
            .collect(),
    );
    receipts.assert_bounded();
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 10))
            .collect(),
    );
    receipts.assert_bounded();
    scene.apply(
        members_catalog_paths(&scene, &members, &[&scene.a], 400),
        400,
    );
    for _ in 0..40 {
        scene.horizons();
        receipts.assert_bounded();
    }
    for &(_, caller, _) in &members {
        assert_eq!(
            edge_count(&scene.native, caller, "a.so"),
            10,
            "an unresolved equivalent observation must defer, then retain all ordinary same-owner growth"
        );
    }
    assert_eq!(
        scene.native.cookies.queries, queries,
        "same-carrier continuation needs no new binding query"
    );
}

#[test]
fn demotion_retirement_round2_settled_fence_survives_unrelated_revision() {
    println!(
        "round2 fixed layout: pair_recovery={} ownership_scan={} complete_scan={} shared_wrapper_metadata={}",
        std::mem::size_of::<PairRecovery>(),
        std::mem::size_of::<OwnershipScan>(),
        std::mem::size_of::<crate::inspect_system::CompleteMemberScan>(),
        std::mem::size_of::<OwnershipScan>()
            - std::mem::size_of::<crate::inspect_system::CompleteMemberScan>()
    );
    let receipts = WorkReceipts::begin();
    let mut scene = Scene::shared();
    scene.observe(false, true, 300);
    scene.count(8);
    let recovery = scene
        .native
        .scene
        .coordinator
        .recoveries
        .values()
        .next()
        .unwrap();
    let original_epoch = recovery.epoch.expect("original Sole epoch was selected");
    let original_fence = recovery
        .fence
        .expect("first advancing read selected before proof settles");
    assert_eq!(original_fence.count, 8);
    assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), 300);
    assert!(matches!(
        scene
            .native
            .scene
            .coordinator
            .binder
            .check_current_binding(recovery.sighting.as_ref().unwrap()),
        CurrentBindingCheck::Pending
    ));
    scene.count(10);
    let queries = scene.native.cookies.queries;
    let original_revision = scene.native.scene.coordinator.attach_set.count_revision();
    let mut catalog = scene.catalog(false, true, 400);
    // B adds an endpoint on a different physical object. The original common
    // object and this caller's Sole B membership stay unchanged.
    catalog.lowering = Some(crate::inspect_system::CatalogLowering {
        plan: fx::lower_named(
            &[fx::module_with_targets(
                &scene.pins,
                &scene.b,
                &[(&scene.a, 0x1000), (&scene.b, 0x2000)],
            )],
            &scene.pins,
            crate::plan::AdmissionPolicy::Inventory(
                scene.native.scene.coordinator.attach_set.budget(),
            ),
        ),
        pins: fx::pass_pins(&[(&scene.a, "sha-a"), (&scene.b, "sha-b")]),
        modules: Vec::new(),
    });
    scene.apply(catalog, 400);
    assert!(scene.native.scene.coordinator.attach_set.count_revision() != original_revision);
    round2_quiet_ownership(&mut scene);
    let recovery = scene
        .native
        .scene
        .coordinator
        .recoveries
        .values()
        .next()
        .unwrap();
    let fence = recovery
        .fence
        .expect("settled fence survives unrelated index reconstruction");
    assert!(
        recovery.epoch == Some(original_epoch),
        "logical Sole epoch is unchanged"
    );
    assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), 300);
    assert_eq!(
        (fence.count, fence.anchor_ns, fence.last_ns),
        (8, original_fence.anchor_ns, original_fence.last_ns)
    );
    assert_eq!(
        scene.native.cookies.queries, queries,
        "unchanged epoch retains its sighting"
    );
    assert_eq!(
        scene.counts(),
        (5, 0),
        "later proof horizons still have not arrived"
    );
    receipts.assert_bounded();
    for _ in 0..40 {
        scene.horizons();
        receipts.assert_bounded();
    }
    assert_eq!(
        scene.counts(),
        (5, 2),
        "settling proof consumes the original fence8"
    );
}

#[test]
fn demotion_retirement_fix_many_pairs_keep_the_actual_first_advance() {
    let receipts = WorkReceipts::begin();
    let mut scene = Scene::shared();
    let mut members = vec![(7, scene.caller, 41)];
    // Seventeen pairs exceed even two entire eight-pair service slices.
    for pid in 8..24 {
        let start = 500 + u64::from(pid);
        scene.native.scene.source.spawn(pid, start);
        let caller = scene
            .native
            .scene
            .coordinator
            .adapter
            .admit(pid, ImageAuthority::ScanPinned, 80)
            .unwrap();
        scene.native.scene.project_paths(pid, &[&scene.a], 90);
        scene.native.scene.coordinator.commit_batch(false).unwrap();
        let ticket = 100 + u64::from(pid);
        scene.native.answer(pid, start, ticket);
        let mut row = scene.native.row(ticket, 1, pid, 100, 0);
        row.entry_count = 5;
        scene.native.witness(vec![row]);
        members.push((pid, caller, ticket));
    }
    scene.apply(members_catalog(&scene, &members, true, 200), 200);
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 7))
            .collect(),
    );
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    scene.apply(members_catalog(&scene, &members, false, 300), 300);
    // Build the stable index, Sole summaries and fresh sightings while lifecycle
    // horizons remain before those sightings. No advance or new witness occurs.
    for _ in 0..40 {
        QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
        scene
            .native
            .scene
            .coordinator
            .reconcile_count_eligibility(&mut scene.native.cookies, &mut RecoveryWorkBudget::new());
    }
    assert_eq!(
        scene.native.scene.coordinator.recoveries.len(),
        members.len()
    );
    for recovery in scene.native.scene.coordinator.recoveries.values() {
        assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), 300);
        assert!(recovery.sighting.is_some() && recovery.fence.is_none());
    }
    receipts.assert_bounded();
    let queries = scene.native.cookies.queries;
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 8))
            .collect(),
    );
    let original_eights = scene.native.scene.coordinator.pair_counts.clone();
    assert!(
        scene
            .native
            .scene
            .coordinator
            .recoveries
            .values()
            .any(|recovery| recovery.fence.is_none()),
        "the actual bounded service leaves at least one pair unvisited"
    );
    receipts.assert_bounded();
    // Production merges this second batch before the missed pairs are serviced.
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 10))
            .collect(),
    );
    receipts.assert_bounded();
    scene.apply(members_catalog(&scene, &members, false, 400), 400);
    receipts.assert_bounded();
    for _ in 0..40 {
        scene.horizons();
        receipts.assert_bounded();
    }
    for &(_, caller, _) in &members {
        assert_eq!(
            (
                edge_count(&scene.native, caller, "a.so"),
                edge_count(&scene.native, caller, "b.so")
            ),
            (5, 2),
            "every eligible pair retains A5 and allocates only post-eight B2"
        );
        let gaps = scene.native.scene.coordinator.registry.gaps();
        assert!(gaps.iter().any(|gap| gap.caller == Some(caller)
            && gap.reason.contains("(7, 8]")
            && gap.reason.contains("1 unattributed calls")));
        assert!(
            !gaps
                .iter()
                .any(|gap| gap.caller == Some(caller) && gap.reason.contains("(7, 10]"))
        );
    }
    for (key, recovery) in &scene.native.scene.coordinator.recoveries {
        let fence = recovery.fence.unwrap();
        let original = original_eights.get(key).unwrap();
        assert_eq!(fence.count, 8);
        assert_eq!(
            (fence.anchor_ns, fence.last_ns),
            (original.anchor_ns, original.last_ns)
        );
        assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), 300);
    }
    assert_eq!(
        scene.native.cookies.queries, queries,
        "equivalent scans reuse each saved sighting"
    );
}

#[test]
fn demotion_retirement_fix_one_edge_multiple_objects_keep_ordinary_growth() {
    use super::tests::CaptureScene;
    let mut capture = CaptureScene::new(1);
    let common = fx::provider(&capture._dir, "common.so", "common-code");
    let pins = fx::pass_pins(&[(&capture.path, "sha-a"), (&common, "sha-common")]);
    let mut limits = RegistryLimits::default_limits();
    limits.max_edges = 1;
    capture.coordinator = InventoryCoordinator::new(
        Scope::Pid(std::process::id()),
        HookRegistry::builtin(),
        Vec::new(),
        vec![],
        capture.source.clone(),
        limits,
    )
    .unwrap();
    let a = fx::module_with_targets(
        &pins,
        &capture.path,
        &[(&capture.path, 0x1000), (&common, 0x1000)],
    );
    let policy = crate::plan::AdmissionPolicy::Inventory(capture.coordinator.attach_set.budget());
    let absorbed = capture
        .coordinator
        .attach_set
        .absorb(&fx::lower_named(&[a], &pins, policy), &pins);
    capture.delta = absorbed.delta;
    capture.verdicts = absorbed.verdicts;
    capture.pins = pins;
    assert_eq!(capture.delta.endpoints.len(), 2);
    assert_ne!(
        capture.delta.endpoints[0].object,
        capture.delta.endpoints[1].object
    );
    capture.source.spawn(7, 500);
    let caller = capture
        .coordinator
        .adapter
        .admit(7, ImageAuthority::ScanPinned, 50)
        .unwrap();
    capture.project(7, 60);
    capture.coordinator.commit_batch(false).unwrap();
    let mut native = NativeScene::over(capture, 0);
    native.answer(7, 500, 41);
    for member in 0..2 {
        let mut row = native.row(41, 1, 7, 100, member);
        row.entry_count = 5;
        native.witness(vec![row]); // each placement publishes separately
    }
    assert_eq!(native.scene.coordinator.registry.edges().count(), 1);
    let initial = edge_count(&native, caller, "a.so");
    native.counts_read(Vec::new(), vec![(41, 1, 0, 7)]);
    native.scene.coordinator.commit_batch(false).unwrap();
    assert_eq!(
        edge_count(&native, caller, "a.so"),
        initial + 2,
        "startup index refusal must also preserve the first physical pair's ordinary growth"
    );
    let before = edge_count(&native, caller, "a.so");
    native.counts_read(Vec::new(), vec![(41, 1, 1, 7)]);
    native.scene.coordinator.commit_batch(false).unwrap();
    assert_eq!(
        edge_count(&native, caller, "a.so"),
        before + 2,
        "optional retirement metadata must not drop the already placed physical pair"
    );
    native.counts_read(Vec::new(), vec![(41, 1, 1, 9)]);
    native.scene.coordinator.commit_batch(false).unwrap();
    assert_eq!(edge_count(&native, caller, "a.so"), before + 4);
    let key = PairKey::of(&native.row(41, 1, 7, 100, 1));
    assert!(matches!(
        native.scene.coordinator.pair_targets.get(&key),
        Some(PairTarget::Bound { .. })
    ));
    assert!(!native.scene.coordinator.recoveries.contains_key(&key));
    assert_eq!(native.scene.coordinator.recoveries.len(), 0);
    assert_eq!(
        native.scene.coordinator.count_ownership.retained_cells().2,
        1
    );
    assert!(
        native
            .scene
            .coordinator
            .registry
            .gaps()
            .iter()
            .any(|gap| gap.caller == Some(caller)
                && gap
                    .budget
                    .as_ref()
                    .is_some_and(|budget| budget.resource == "inventory_count_retirements"
                        && budget.limit == 1
                        && budget.requested == 2)),
        "the smaller optional retirement envelope is explicitly disclosed"
    );
    // Add a real second root sharing both physical count objects. The one
    // existing registry edge remains history; capacity cannot confer recovery.
    let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
    let pins = fx::pass_pins(&[
        (&native.scene.path, "sha-a"),
        (&common, "sha-common"),
        (&b, "sha-b"),
    ]);
    let modules = [
        fx::module_with_targets(
            &pins,
            &native.scene.path,
            &[(&native.scene.path, 0x1000), (&common, 0x1000)],
        ),
        fx::module_with_targets(
            &pins,
            &b,
            &[(&native.scene.path, 0x1000), (&common, 0x1000)],
        ),
    ];
    let policy =
        crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
    native
        .scene
        .coordinator
        .attach_set
        .absorb(&fx::lower_named(&modules, &pins, policy), &pins);
    native.counts_read(Vec::new(), vec![(41, 1, 0, 9), (41, 1, 1, 10)]);
    native.scene.coordinator.commit_batch(false).unwrap();
    native.counts_read(Vec::new(), vec![(41, 1, 0, 12), (41, 1, 1, 12)]);
    native.scene.coordinator.commit_batch(false).unwrap();
    assert_eq!(
        edge_count(&native, caller, "a.so"),
        before + 4,
        "a pair without retirement metadata cannot continue through ownership ambiguity"
    );
    assert_eq!(native.scene.coordinator.recoveries.len(), 0);
    assert_eq!(
        native.scene.coordinator.count_ownership.retained_cells().2,
        1
    );
}

fn edge_count(native: &NativeScene, caller: CallerId, name: &str) -> u64 {
    let registry = &native.scene.coordinator.registry;
    registry
        .edges()
        .find(|edge| {
            edge.caller == caller
                && registry
                    .module(edge.module)
                    .is_some_and(|module| module.paths.iter().any(|path| path.ends_with(name)))
        })
        .expect("retained edge")
        .entry_count
}

pub(super) struct Scene {
    pub(super) native: NativeScene,
    pub(super) caller: CallerId,
    a: PathBuf,
    b: PathBuf,
    pins: crate::discovery::identity::PinnedObjects,
    generation: crate::inspect_system::MemberGeneration,
}

impl Scene {
    fn shared() -> Self {
        let mut scene = Self::placed();
        scene.observe(true, true, 200);
        scene.count(7);
        assert_eq!(edge_count(&scene.native, scene.caller, "a.so"), 5);
        scene
    }

    pub(super) fn placed() -> Self {
        Self::placed_with_diagnostics(None)
    }

    pub(super) fn placed_with_diagnostics(
        config: Option<crate::inventory_diagnostics::DiagnosticConfig>,
    ) -> Self {
        let (mut native, caller) = NativeScene::new();
        if let Some(config) = config {
            native.scene.coordinator.enable_diagnostics(config).unwrap();
        }
        native
            .scene
            .coordinator
            .binder
            .set_current_binding_clock(query_clock);
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row]);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 5)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let a = native.scene.path.clone();
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let pins = fx::pass_pins(&[(&a, "sha-a"), (&b, "sha-b")]);
        let generation = crate::inspect_system::MemberGeneration {
            start_time: Some(500),
            exe: native
                .scene
                .coordinator
                .adapter
                .record(caller)
                .unwrap()
                .exe
                .clone(),
        };
        Self {
            native,
            caller,
            a,
            b,
            pins,
            generation,
        }
    }

    fn catalog(&self, a_present: bool, complete: bool, at: u64) -> crate::inspect_system::Catalog {
        let paths: Vec<&std::path::Path> = if a_present {
            vec![&self.a, &self.b]
        } else {
            vec![&self.b]
        };
        let mut catalog = capture_catalog(&self.pins, &paths, 7, Some(self.generation.clone()));
        if complete {
            catalog.processes[0].complete_scan =
                Some(crate::inspect_system::CompleteMemberScan::scripted(
                    self.generation.clone(),
                    at,
                    at + 1,
                ));
        }
        let modules: Vec<_> = paths
            .iter()
            .map(|path| fx::module_with_targets(&self.pins, path, &[(&self.a, 0x1000)]))
            .collect();
        catalog.lowering = Some(crate::inspect_system::CatalogLowering {
            plan: fx::lower_named(
                &modules,
                &self.pins,
                crate::plan::AdmissionPolicy::Inventory(
                    self.native.scene.coordinator.attach_set.budget(),
                ),
            ),
            pins: fx::pass_pins(&[(&self.a, "sha-a"), (&self.b, "sha-b")]),
            modules: Vec::new(),
        });
        catalog
    }

    fn apply(&mut self, catalog: crate::inspect_system::Catalog, at: u64) {
        QUERY_CLOCK.with(|clock| clock.set(self.native.stamps.tick()));
        self.native.scene.coordinator.apply_catalog(
            catalog,
            &mut crate::discovery::engine::inventory::UnavailableImageGuard,
            &mut self.native.cookies,
            at + 100,
            at,
        );
        self.native.scene.coordinator.commit_batch(false).unwrap();
    }

    pub(super) fn observe(&mut self, a_present: bool, complete: bool, at: u64) {
        self.apply(self.catalog(a_present, complete, at), at);
    }

    pub(super) fn count(&mut self, absolute: u64) {
        QUERY_CLOCK.with(|clock| clock.set(self.native.stamps.tick()));
        self.native
            .counts_read(Vec::new(), vec![(41, 1, 0, absolute)]);
        self.native.scene.coordinator.commit_batch(false).unwrap();
    }

    pub(super) fn horizons(&mut self) {
        QUERY_CLOCK.with(|clock| clock.set(self.native.stamps.tick()));
        self.native.drain();
        self.native.read(Vec::new());
        self.native.scene.coordinator.commit_batch(false).unwrap();
    }

    pub(super) fn bracketed_count(&mut self, absolute: u64, pre: u64, post: u64, failed: bool) {
        QUERY_CLOCK.with(|clock| clock.set(self.native.stamps.tick()));
        let NativeBatch::Witness(mut batch) =
            self.native.stamps.read(self.native.domain, Vec::new())
        else {
            unreachable!()
        };
        batch.counts = vec![CallerCountUpdate {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: self.native.scene.delta.endpoints[0].object,
            count: absolute,
        }];
        batch.counts_read_ns = pre;
        batch.rows_read_ns = post;
        if failed {
            batch.refresh_sweep_gaps = true;
        }
        self.native.stage(NativeBatch::Witness(batch));
        self.native.scene.coordinator.commit_batch(false).unwrap();
    }

    pub(super) fn counts(&self) -> (u64, u64) {
        (
            edge_count(&self.native, self.caller, "a.so"),
            edge_count(&self.native, self.caller, "b.so"),
        )
    }
}

#[test]
fn demotion_retirement_invalid_original_bracket_and_refresh_never_fence() {
    for (pre, post, failed) in [
        (301, 302, false),
        (0, 400, false),
        (400, 399, false),
        (400, u64::MAX, false),
        (400, 401, true),
    ] {
        let mut scene = Scene::shared();
        scene.observe(false, true, 300);
        scene.bracketed_count(8, pre, post, failed);
        scene.horizons();
        scene.count(8); // An equal read cannot replace the bad original bracket.
        scene.horizons();
        assert_eq!(scene.counts(), (5, 0));
        scene.count(10);
        scene.horizons();
        assert_eq!(
            scene.counts(),
            (5, 0),
            "the first healthy advance is the fence"
        );
        scene.count(12);
        scene.horizons();
        assert_eq!(
            scene.counts(),
            (5, 2),
            "healthy input must recover after its own fence"
        );
    }
    let mut saturated = Scene::shared();
    saturated.observe(false, true, 300);
    saturated.count(u64::MAX);
    saturated.horizons();
    assert_eq!(
        saturated.counts(),
        (5, 0),
        "a saturated absolute cannot fence or allocate"
    );
}

#[test]
fn demotion_retirement_another_endpoint_of_same_object_keeps_ownership_shared() {
    let mut scene = Scene::shared();
    let c = fx::provider(&scene.native.scene._dir, "c.so", "provider-c");
    scene.pins = fx::pass_pins(&[(&scene.a, "sha-a"), (&scene.b, "sha-b"), (&c, "sha-c")]);
    for at in [300, 350] {
        let mut catalog = capture_catalog(
            &scene.pins,
            &[&scene.b, &c],
            7,
            Some(scene.generation.clone()),
        );
        catalog.processes[0].complete_scan =
            Some(crate::inspect_system::CompleteMemberScan::scripted(
                scene.generation.clone(),
                at,
                at + 1,
            ));
        let modules = [
            fx::module_with_targets(&scene.pins, &scene.b, &[(&scene.a, 0x1000)]),
            fx::module_with_targets(&scene.pins, &c, &[(&scene.a, 0x2000)]),
        ];
        catalog.lowering = Some(crate::inspect_system::CatalogLowering {
            plan: fx::lower_named(
                &modules,
                &scene.pins,
                crate::plan::AdmissionPolicy::Inventory(
                    scene.native.scene.coordinator.attach_set.budget(),
                ),
            ),
            pins: fx::pass_pins(&[(&scene.a, "sha-a"), (&scene.b, "sha-b"), (&c, "sha-c")]),
            modules: Vec::new(),
        });
        scene.apply(catalog, at);
    }
    scene.count(8);
    scene.horizons();
    scene.count(10);
    scene.horizons();
    assert_eq!(
        scene.counts(),
        (5, 0),
        "all retained endpoints of the physical object participate"
    );
    assert!(matches!(
        scene.native.scene.coordinator.count_ownership.candidates(
            scene.caller,
            scene.native.scene.delta.endpoints[0].object.index()
        ),
        CurrentCandidates::Shared
    ));
    scene.observe(false, true, 500);
    scene.count(11);
    scene.horizons();
    scene.count(13);
    scene.horizons();
    assert_eq!(
        scene.counts(),
        (5, 2),
        "removing the other current root eventually permits its own fence"
    );
}

#[test]
fn demotion_retirement_pending_handles_and_epochs_are_checked() {
    let mut scene = Scene::shared();
    scene.observe(false, true, 300);
    scene.count(8);
    scene.horizons();
    scene.native.scene.coordinator.next_pending_id = u64::MAX;
    scene.count(10);
    scene.horizons();
    scene.count(12);
    scene.horizons();
    assert_eq!(
        scene.counts(),
        (5, 0),
        "handle exhaustion is sticky and never aliases an older decision"
    );
    let mut scene = Scene::shared();
    scene
        .native
        .scene
        .coordinator
        .count_ownership
        .exhaust_epochs();
    scene.observe(false, true, 300);
    scene.count(8);
    scene.horizons();
    scene.count(10);
    scene.horizons();
    assert_eq!(
        scene.counts(),
        (5, 0),
        "catalog/eligibility exhaustion refuses recovery permanently"
    );
}

// This uses catalog absence, never fabricated empty-A relowering or a second witness.
#[test]
fn demotion_retirement_absent_owner_resumes_after_real_advance_fence() {
    let mut scene = Scene::shared();
    scene.observe(false, true, 300);
    scene.count(8);
    scene.horizons();
    assert_eq!(scene.counts(), (5, 0), "fence growth stays unallocated");
    scene.count(10);
    scene.horizons();
    assert_eq!(
        scene.counts(),
        (5, 2),
        "only growth beyond the advancing fence resumes"
    );
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .attach_set
            .modules_with_member(scene.native.scene.delta.endpoints[0].id)
            .count(),
        2,
        "historical membership remains"
    );
}

#[test]
fn demotion_retirement_fence_gap_does_not_double_disclose_shared_history() {
    let mut scene = Scene::shared();
    let before = scene.native.scene.coordinator.registry.gaps().len();
    scene.observe(false, true, 300);
    scene.count(8);
    scene.horizons();
    let gaps: Vec<_> = scene
        .native
        .scene
        .coordinator
        .registry
        .gaps()
        .iter()
        .skip(before)
        .filter(|gap| gap.subject == crate::discovery::caller_registry::DEMOTED_COUNT_REJECTED)
        .collect();
    assert_eq!(gaps.len(), 1, "the fence has one new gap-only disposition");
    assert!(gaps[0].reason.contains("(7, 8]") && gaps[0].reason.contains("1 unattributed calls"));
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .registry
            .witness_placement()
            .total(),
        1,
        "the boundary never invents a witness"
    );
    scene.count(10);
    scene.horizons();
    assert_eq!(scene.counts(), (5, 2));
}

#[test]
fn demotion_retirement_pending_observations_and_historical_range_union_are_immutable() {
    let mut scene = Scene::shared();
    scene.observe(false, true, 300);
    scene.count(8);
    scene.horizons();
    scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 10)]);
    scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 12)]);
    let mut observations: Vec<_> = scene
        .native
        .scene
        .coordinator
        .pending_ids
        .values()
        .map(|pending| pending.observation.count)
        .collect();
    observations.sort_unstable();
    assert_eq!(
        observations,
        vec![10, 12],
        "each handle keeps the exact read that staged its range"
    );
    scene.native.scene.source.kill(7);
    scene.native.scene.coordinator.observe_empty_pass(
        &mut crate::discovery::engine::inventory::UnavailableImageGuard,
        &mut scene.native.cookies,
        "owned caller ended before publication",
        350,
    );
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    assert_eq!(
        scene.counts(),
        (5, 4),
        "already staged historical ranges publish once despite current cancellation"
    );
    for _ in 0..3 {
        scene.native.scene.coordinator.commit_batch(false).unwrap();
    }
    assert_eq!(
        scene.counts(),
        (5, 4),
        "repeated publication cannot duplicate either range"
    );
    scene.count(14);
    scene.horizons();
    assert_eq!(
        scene.counts(),
        (5, 4),
        "stale decisions cannot authorize newer growth"
    );
}

#[test]
fn demotion_retirement_incomplete_observation_never_shrinks_candidates() {
    for mutation in 0..6 {
        let mut scene = Scene::shared();
        let mut catalog = scene.catalog(false, true, 300);
        match mutation {
            0 => catalog.processes[0].complete_scan = None,
            1 => catalog.processes[0].status = crate::inspect_system::MemberStatus::MapsMatched,
            2 => catalog.processes[0].generation = None,
            3 => catalog.processes[0].generation.as_mut().unwrap().start_time = Some(501),
            4 => {
                catalog.processes[0].status =
                    crate::inspect_system::MemberStatus::MemoryUnavailable {
                        reason: "unavailable",
                    }
            }
            _ => catalog.processes.clear(),
        }
        scene.apply(catalog, 300);
        scene.count(8);
        scene.horizons();
        scene.count(10);
        scene.horizons();
        assert_eq!(
            scene.counts(),
            (5, 0),
            "incomplete or missing observation {mutation} retains ambiguity"
        );
    }
}

#[test]
fn demotion_retirement_pending_proof_reuses_first_fence_and_supporting_scan() {
    let mut scene = Scene::shared();
    scene.observe(false, true, 300);
    scene.count(8);
    let queries = scene.native.cookies.queries;
    scene.observe(false, true, 400);
    scene.count(10);
    scene.observe(false, true, 500);
    assert_eq!(
        scene.native.cookies.queries, queries,
        "equivalent scans reuse the fresh sighting"
    );
    let recovery = scene
        .native
        .scene
        .coordinator
        .recoveries
        .values()
        .next()
        .unwrap();
    assert_eq!(recovery.fence.unwrap().count, 8);
    assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), 300);
    assert_eq!(scene.counts(), (5, 0), "horizons still pending");
    scene.horizons();
    assert_eq!(
        scene.counts(),
        (5, 2),
        "settling without a further increase must keep the fence at eight"
    );
}

#[test]
fn demotion_retirement_adapter_retirement_and_finish_cancel_saved_sightings() {
    for finish in [false, true] {
        let mut scene = Scene::shared();
        scene.observe(false, true, 300);
        scene.count(8);
        if finish {
            scene.native.stage(NativeBatch::Finish {
                domain: scene.native.domain,
            });
            scene.native.stage(NativeBatch::Finish {
                domain: scene.native.domain,
            });
        } else {
            scene.native.scene.source.kill(7);
            scene.native.scene.coordinator.observe_empty_pass(
                &mut crate::discovery::engine::inventory::UnavailableImageGuard,
                &mut scene.native.cookies,
                "owned process exited",
                350,
            );
            assert!(
                scene
                    .native
                    .scene
                    .coordinator
                    .adapter
                    .record(scene.caller)
                    .unwrap()
                    .retired
            );
        }
        scene.horizons();
        scene.count(10);
        scene.horizons();
        assert_eq!(
            scene.counts(),
            (5, 0),
            "explicit cancellation blocks a saved proof"
        );
    }
}

#[test]
fn demotion_retirement_stale_or_equal_read_cannot_fence() {
    let mut scene = Scene::shared();
    scene.observe(false, true, 300);
    scene.count(7);
    scene.horizons();
    scene.count(6);
    scene.horizons();
    assert_eq!(scene.counts(), (5, 0));
    scene.count(8);
    scene.horizons();
    scene.count(10);
    scene.horizons();
    assert_eq!(
        scene.counts(),
        (5, 2),
        "only a later actual strict advance establishes a fence"
    );
}

#[test]
fn demotion_retirement_membership_pages_and_recovery_work_are_resumable() {
    let dir = tempfile::tempdir().unwrap();
    let a = fx::provider(&dir, "a.so", "provider-a");
    let pins = fx::pass_pins(&[(&a, "sha-a")]);
    let budget = InventoryBudget::new(4096, 32768).unwrap();
    let mut attach = InventoryAttachSet::new(budget);
    let plan = fx::lower_named(
        &[fx::module(&pins, &a, &fx::offsets(300))],
        &pins,
        crate::plan::AdmissionPolicy::Inventory(budget),
    );
    attach.absorb(&plan, &pins);
    let revision = attach.count_revision();
    let mut cursor = None;
    let mut total_visits = 0;
    let mut members = 0;
    loop {
        let page = match attach.count_membership_page(cursor, revision, 128) {
            Ok(page) => page,
            Err(_) => panic!("healthy indexed traversal must progress"),
        };
        assert!(page.visited <= 128);
        assert_eq!(
            page.visited,
            page.items.len(),
            "headers, skipped and unknown entries are charged"
        );
        members += page
            .items
            .iter()
            .filter(|item| {
                matches!(
                    item,
                    crate::discovery::inventory_attach_set::CountMembershipItem::Module { .. }
                )
            })
            .count();
        total_visits += page.visited;
        cursor = page.cursor;
        if cursor.is_none() {
            break;
        }
        assert!(total_visits < 2000, "cursor cannot rescan a prefix");
    }
    assert_eq!(members, 300, "every membership examined exactly once");
    assert!(
        total_visits >= 600,
        "endpoint headers and members both cost visits"
    );
    let first = match attach.count_membership_page(None, revision, 1) {
        Ok(page) => page,
        Err(_) => panic!("first page"),
    };
    attach.absorb(&plan, &pins);
    let next = match attach.count_membership_page(first.cursor, revision, 128) {
        Ok(page) => page,
        Err(_) => panic!("equivalent scans must not restart a long index"),
    };
    let smaller = fx::lower_named(
        &[fx::module(&pins, &a, &fx::offsets(299))],
        &pins,
        crate::plan::AdmissionPolicy::Inventory(budget),
    );
    attach.absorb(&smaller, &pins);
    assert!(
        attach
            .count_membership_page(next.cursor, revision, 128)
            .is_err(),
        "an actual membership change invalidates a saved prefix"
    );
}

#[test]
fn demotion_retirement_current_owners_require_latest_complete_pass() {
    use super::count_eligibility::{CountOwnership, CurrentCandidates, RecoveryWorkBudget};
    let scene = Scene::shared();
    let coordinator = &scene.native.scene.coordinator;
    let object = coordinator
        .attach_set
        .endpoints()
        .next()
        .unwrap()
        .object
        .index();
    let b = coordinator
        .registry
        .modules()
        .find(|module| module.paths.iter().any(|path| path.ends_with("b.so")))
        .unwrap()
        .key
        .clone();
    let mut ownership = CountOwnership::new(coordinator.registry.limits());
    ownership.register_pair(scene.caller, object);
    ownership.invalidate_memberships(coordinator.attach_set.count_revision());
    ownership.begin_catalog_pass();
    ownership.queue_observation(
        scene.caller,
        vec![b.clone()],
        Some(crate::inspect_system::CompleteMemberScan::scripted(
            scene.generation.clone(),
            300,
            301,
        )),
    );
    for _ in 0..20 {
        let mut budget = RecoveryWorkBudget::new();
        ownership.advance(&coordinator.attach_set, &coordinator.registry, &mut budget);
        assert!(budget.visited <= 128);
        assert!(budget.queries <= 4);
    }
    assert!(
        matches!(ownership.candidates(scene.caller, object), CurrentCandidates::Sole { module, .. } if module == b),
        "bounded healthy input must reach B-only eligibility"
    );
    ownership.begin_catalog_pass();
    assert!(
        matches!(
            ownership.candidates(scene.caller, object),
            CurrentCandidates::Unknown
        ),
        "omission cannot retain an earlier Sole result"
    );
    ownership.queue_observation(scene.caller, vec![b], None);
    for _ in 0..20 {
        ownership.advance(
            &coordinator.attach_set,
            &coordinator.registry,
            &mut RecoveryWorkBudget::new(),
        );
    }
    assert!(
        matches!(
            ownership.candidates(scene.caller, object),
            CurrentCandidates::Unknown
        ),
        "failed absence authority stays unknown"
    );
}

#[test]
fn demotion_retirement_long_stable_index_and_repeated_observations_keep_first_fence() {
    let mut scene = Scene::shared();
    let plan = fx::lower_named(
        &[fx::module(&scene.pins, &scene.a, &fx::offsets(300))],
        &scene.pins,
        crate::plan::AdmissionPolicy::Inventory(scene.native.scene.coordinator.attach_set.budget()),
    );
    scene
        .native
        .scene
        .coordinator
        .attach_set
        .absorb(&plan, &scene.pins);
    scene.observe(false, true, 300);
    scene.count(8);
    scene.count(10);
    let before = scene.native.cookies.queries;
    for at in 400..560 {
        scene.observe(false, true, at);
        let mut budget = RecoveryWorkBudget::new();
        scene
            .native
            .scene
            .coordinator
            .reconcile_count_eligibility(&mut scene.native.cookies, &mut budget);
        assert!(
            budget.visited <= 128,
            "inner/cleanup work shares the invocation bound"
        );
        assert!(
            budget.queries <= 4,
            "failed queries consume the same allowance"
        );
        scene.horizons();
        let (observations, index, pairs) = scene
            .native
            .scene
            .coordinator
            .count_ownership
            .retained_cells();
        let max = scene.native.scene.coordinator.registry.limits().max_edges;
        assert!(observations <= max && index <= max && pairs <= max);
    }
    assert_eq!(
        scene.counts(),
        (5, 2),
        "bounded stable work eventually recovers without another count increase"
    );
    assert_eq!(
        scene.native.cookies.queries - before,
        1,
        "one fresh query survives equivalent observations"
    );
    let recovery = scene
        .native
        .scene
        .coordinator
        .recoveries
        .values()
        .next()
        .unwrap();
    assert_eq!(recovery.fence.unwrap().count, 8);
    assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), 300);
}

#[test]
fn demotion_retirement_observation_capacity_plateaus_and_healthy_input_recovers() {
    let scene = Scene::shared();
    let coordinator = &scene.native.scene.coordinator;
    let b = coordinator
        .registry
        .modules()
        .find(|module| module.paths.iter().any(|path| path.ends_with("b.so")))
        .unwrap()
        .key
        .clone();
    let object = coordinator
        .attach_set
        .endpoints()
        .next()
        .unwrap()
        .object
        .index();
    let mut limits = coordinator.registry.limits();
    limits.max_edges = 8;
    let mut ownership = CountOwnership::new(limits);
    ownership.register_pair(scene.caller, object);
    ownership.invalidate_memberships(coordinator.attach_set.count_revision());
    for at in 300..360 {
        ownership.begin_catalog_pass();
        assert!(!ownership.queue_observation(
            scene.caller,
            vec![b.clone(); 9],
            Some(crate::inspect_system::CompleteMemberScan::scripted(
                scene.generation.clone(),
                at,
                at + 1
            ))
        ));
        let mut budget = RecoveryWorkBudget::new();
        ownership.advance(&coordinator.attach_set, &coordinator.registry, &mut budget);
        let (observations, index, pairs) = ownership.retained_cells();
        assert!(observations <= 8 && index <= 8 && pairs <= 8);
        assert!(matches!(
            ownership.candidates(scene.caller, object),
            CurrentCandidates::Unknown
        ));
    }
    ownership.begin_catalog_pass();
    assert!(ownership.queue_observation(
        scene.caller,
        vec![b.clone()],
        Some(crate::inspect_system::CompleteMemberScan::scripted(
            scene.generation.clone(),
            400,
            401
        ))
    ));
    for _ in 0..30 {
        ownership.advance(
            &coordinator.attach_set,
            &coordinator.registry,
            &mut RecoveryWorkBudget::new(),
        );
    }
    assert!(
        matches!(ownership.candidates(scene.caller,object),CurrentCandidates::Sole { module, .. } if module==b),
        "healthy bounded input is not permanently poisoned by observation refusal"
    );
    let mut budget = RecoveryWorkBudget::new();
    for _ in 0..4 {
        assert!(budget.query());
    }
    assert!(
        !budget.query(),
        "the fifth attempt is refused even when earlier attempts failed"
    );
}

#[test]
fn demotion_retirement_aba_uses_a_new_fence_and_retains_both_histories() {
    let mut scene = Scene::shared();
    scene.observe(false, true, 300);
    scene.count(8);
    scene.horizons();
    scene.count(10);
    scene.horizons();
    assert_eq!(scene.counts(), (5, 2));
    let at = scene.native.stamps.tick();
    let mut catalog = capture_catalog(&scene.pins, &[&scene.a], 7, Some(scene.generation.clone()));
    catalog.processes[0].complete_scan = Some(crate::inspect_system::CompleteMemberScan::scripted(
        scene.generation.clone(),
        at,
        at + 1,
    ));
    catalog.lowering = Some(crate::inspect_system::CatalogLowering {
        plan: fx::lower_named(
            &[fx::module_with_targets(
                &scene.pins,
                &scene.a,
                &[(&scene.a, 0x1000)],
            )],
            &scene.pins,
            crate::plan::AdmissionPolicy::Inventory(
                scene.native.scene.coordinator.attach_set.budget(),
            ),
        ),
        pins: fx::pass_pins(&[(&scene.a, "sha-a"), (&scene.b, "sha-b")]),
        modules: Vec::new(),
    });
    scene.apply(catalog, at);
    scene.count(11);
    scene.horizons();
    assert_eq!(
        scene.counts(),
        (5, 2),
        "returning A must cross its own new fence"
    );
    scene.count(13);
    scene.horizons();
    assert_eq!(
        scene.counts(),
        (7, 2),
        "A accumulates only its new segment onto retained history"
    );
    let at = scene.native.stamps.tick();
    scene.observe(false, true, at);
    scene.count(14);
    scene.horizons();
    scene.count(16);
    scene.horizons();
    assert_eq!(
        scene.counts(),
        (7, 4),
        "a third epoch cannot reuse either older boundary"
    );
}

#[test]
fn demotion_retirement_historical_and_current_owners_are_separate_per_caller() {
    let mut scene = Scene::shared();
    scene.native.scene.source.spawn(8, 600);
    let y = scene
        .native
        .scene
        .coordinator
        .adapter
        .admit(8, ImageAuthority::ScanPinned, 80)
        .unwrap();
    scene.native.scene.project_paths(8, &[&scene.a], 90);
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    scene.native.answer(8, 600, 51);
    let mut row = scene.native.row(51, 1, 8, 100, 0);
    row.entry_count = 5;
    scene.native.witness(vec![row]);
    let generation = crate::inspect_system::MemberGeneration {
        start_time: Some(600),
        exe: scene
            .native
            .scene
            .coordinator
            .adapter
            .record(y)
            .unwrap()
            .exe
            .clone(),
    };
    let mut catalog = scene.catalog(false, true, 300);
    let mut y_catalog = capture_catalog(
        &scene.pins,
        &[&scene.a, &scene.b],
        8,
        Some(generation.clone()),
    );
    y_catalog.processes[0].complete_scan = Some(
        crate::inspect_system::CompleteMemberScan::scripted(generation, 300, 301),
    );
    let offset = catalog.objects.len();
    for index in &mut y_catalog.processes[0].objects {
        *index += offset;
    }
    catalog.objects.extend(y_catalog.objects);
    catalog.processes.extend(y_catalog.processes);
    catalog.lowering = Some(crate::inspect_system::CatalogLowering {
        plan: fx::lower_named(
            &[
                fx::module_with_targets(&scene.pins, &scene.a, &[(&scene.a, 0x1000)]),
                fx::module_with_targets(&scene.pins, &scene.b, &[(&scene.a, 0x1000)]),
            ],
            &scene.pins,
            crate::plan::AdmissionPolicy::Inventory(
                scene.native.scene.coordinator.attach_set.budget(),
            ),
        ),
        pins: fx::pass_pins(&[(&scene.a, "sha-a"), (&scene.b, "sha-b")]),
        modules: Vec::new(),
    });
    scene.apply(catalog, 300);
    scene.native.counts_read(Vec::new(), vec![(51, 1, 0, 7)]);
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    scene.count(8);
    scene.horizons();
    scene.count(10);
    scene.horizons();
    scene.native.counts_read(Vec::new(), vec![(51, 1, 0, 10)]);
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    assert_eq!(scene.counts(), (5, 2));
    assert_eq!(
        (
            edge_count(&scene.native, y, "a.so"),
            edge_count(&scene.native, y, "b.so")
        ),
        (5, 0),
        "Y still maps both roots and remains ambiguous"
    );
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .attach_set
            .modules_with_member(scene.native.scene.delta.endpoints[0].id)
            .count(),
        2
    );
}

#[test]
fn demotion_retirement_round3_queued_new_scan_keeps_first_advance_without_flush() {
    let receipts = WorkReceipts::begin();
    let (mut scene, members) = round2_bound_members();
    scene.apply(members_catalog(&scene, &members, true, 200), 200);
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 7))
            .collect(),
    );
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    scene.apply(members_catalog(&scene, &members, false, 300), 300);
    // No service flush: the original shared receipt/read is still unresolved
    // for some pairs while the genuinely new complete scan is queued.
    assert!(
        scene
            .native
            .scene
            .coordinator
            .recoveries
            .values()
            .any(|recovery| recovery
                .pending_reads
                .iter()
                .flatten()
                .any(|tag| tag.read.count == 7 && tag.scan.started_ns() == 200))
    );
    receipts.assert_bounded();
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 8))
            .collect(),
    );
    let original_eights = scene.native.scene.coordinator.pair_counts.clone();
    receipts.assert_bounded();
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 10))
            .collect(),
    );
    receipts.assert_bounded();
    for _ in 0..40 {
        scene.horizons();
        receipts.assert_bounded();
    }
    for &(_, caller, _) in &members {
        assert_eq!(
            (
                edge_count(&scene.native, caller, "a.so"),
                edge_count(&scene.native, caller, "b.so")
            ),
            (5, 2),
            "the queued new authority must retain actual8 while older shared7 still waits"
        );
        assert!(
            scene
                .native
                .scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .any(|gap| gap.caller == Some(caller)
                    && gap.reason.contains("(7, 8]")
                    && gap.reason.contains("1 unattributed calls"))
        );
    }
    for (key, recovery) in &scene.native.scene.coordinator.recoveries {
        let fence = recovery.fence.expect("first current-authority advance");
        let original = original_eights.get(key).unwrap();
        assert_eq!(
            (fence.count, fence.anchor_ns, fence.last_ns),
            (8, original.anchor_ns, original.last_ns)
        );
        assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), 300);
    }
}

#[test]
fn demotion_retirement_round3_pending_predecessor_cannot_consume_new_scan_reads() {
    let receipts = WorkReceipts::begin();
    let mut scene = Scene::placed();
    // Publish both admissions without a private complete-scan receipt. The
    // shared7 request then follows the existing generic path and stays in flight.
    scene.observe(true, false, 200);
    scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 7)]);
    let key = *scene
        .native
        .scene
        .coordinator
        .recoveries
        .keys()
        .next()
        .unwrap();
    assert!(matches!(
        scene.native.scene.coordinator.pair_targets.get(&key),
        Some(PairTarget::Pending {
            base: 5,
            staged: 7,
            ..
        })
    ));
    let recovery = scene.native.scene.coordinator.recoveries.get(&key).unwrap();
    assert!(recovery.blocked && recovery.epoch.is_none() && recovery.watermark == 5);
    let catalog = scene.catalog(false, true, 300);
    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene.native.scene.coordinator.apply_catalog(
        catalog,
        &mut crate::discovery::engine::inventory::UnavailableImageGuard,
        &mut scene.native.cookies,
        400,
        300,
    );
    // apply_catalog returns without publication; no artificial service precedes8.
    scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 8)]);
    let original_eight = scene.native.scene.coordinator.pair_counts[&key];
    scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 10)]);
    let mut generic_reads: Vec<_> = scene
        .native
        .scene
        .coordinator
        .pending_ids
        .values()
        .filter(|pending| {
            pending.key == key && !matches!(pending.origin, PendingCountOrigin::Recovered(_))
        })
        .map(|pending| pending.observation.count)
        .collect();
    generic_reads.sort_unstable();
    println!("generic predecessor observations before publication: {generic_reads:?}");
    receipts.assert_bounded();
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    for _ in 0..40 {
        scene.horizons();
        receipts.assert_bounded();
    }
    assert_eq!(
        scene.counts(),
        (5, 2),
        "original Pending7 must finalize without consuming source-authorized8/10"
    );
    assert_eq!(
        generic_reads,
        vec![7],
        "only the original generic request may stay in flight"
    );
    round3_debug(&scene);
    let recovery = scene.native.scene.coordinator.recoveries.get(&key).unwrap();
    let fence = recovery.fence.expect("original actual first8");
    assert_eq!(
        (fence.count, fence.anchor_ns, fence.last_ns),
        (8, original_eight.anchor_ns, original_eight.last_ns)
    );
    assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), 300);
    assert!(
        scene
            .native
            .scene
            .coordinator
            .registry
            .gaps()
            .iter()
            .any(|gap| gap.caller == Some(scene.caller) && gap.reason.contains("(7, 8]"))
    );
}

fn round3_more_members() -> (Scene, Vec<(u32, CallerId, u64)>) {
    let (mut scene, mut members) = round2_bound_members();
    for pid in 24..40 {
        let start = 500 + u64::from(pid);
        scene.native.scene.source.spawn(pid, start);
        let caller = scene
            .native
            .scene
            .coordinator
            .adapter
            .admit(pid, ImageAuthority::ScanPinned, 80)
            .unwrap();
        scene.native.scene.project_paths(pid, &[&scene.a], 90);
        scene.native.scene.coordinator.commit_batch(false).unwrap();
        let ticket = 100 + u64::from(pid);
        scene.native.answer(pid, start, ticket);
        let mut row = scene.native.row(ticket, 1, pid, 100, 0);
        row.entry_count = 5;
        scene.native.witness(vec![row]);
        members.push((pid, caller, ticket));
    }
    (scene, members)
}

fn round3_apply_unpublished(scene: &mut Scene, catalog: crate::inspect_system::Catalog, at: u64) {
    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene.native.scene.coordinator.apply_catalog(
        catalog,
        &mut crate::discovery::engine::inventory::UnavailableImageGuard,
        &mut scene.native.cookies,
        at + 100,
        at,
    );
}

fn round3_assert_slots(scene: &Scene) {
    for recovery in scene.native.scene.coordinator.recoveries.values() {
        assert!(recovery.pending_reads.iter().flatten().count() <= 3);
        assert!(
            !recovery.receipt_refused,
            "normal current receipt positions must not exhaust fixed slots"
        );
    }
}

fn round3_receipts(scene: &Scene) -> Vec<std::sync::Weak<OwnershipScan>> {
    let coordinator = &scene.native.scene.coordinator;
    let mut refs = Vec::new();
    for recovery in coordinator.recoveries.values() {
        refs.extend(
            coordinator
                .count_ownership
                .receipt_view(recovery.caller)
                .receipts()
                .map(Arc::downgrade),
        );
        refs.extend(recovery.scan.as_ref().map(Arc::downgrade));
        refs.extend(
            recovery
                .pending_reads
                .iter()
                .flatten()
                .map(|tag| Arc::downgrade(&tag.scan)),
        );
    }
    refs.sort_by_key(std::sync::Weak::as_ptr);
    refs.dedup_by_key(|reference| reference.as_ptr());
    refs
}

#[test]
fn demotion_retirement_round3_early_candidate_waits_for_real_binding_and_keeps_epoch() {
    let receipts = WorkReceipts::begin();
    let mut scene = Scene::shared();
    scene.native.unavailable_answer(7, 500);
    scene.observe(false, true, 300);
    scene.count(8);
    let key = *scene
        .native
        .scene
        .coordinator
        .recoveries
        .keys()
        .next()
        .unwrap();
    let recovery = &scene.native.scene.coordinator.recoveries[&key];
    let original = recovery.fence.expect("ownership-selected unproven read");
    let epoch = recovery.epoch.unwrap();
    assert_eq!(original.count, 8);
    assert_eq!(
        recovery.watermark, 7,
        "selection alone must not account first8"
    );
    assert!(recovery.sighting.is_none() && !recovery.recovered);
    assert_eq!(scene.counts(), (5, 0));
    scene.count(10);
    scene.observe(false, true, 350);
    let revision = scene.native.scene.coordinator.attach_set.count_revision();
    let mut catalog = scene.catalog(false, true, 400);
    catalog.lowering = Some(crate::inspect_system::CatalogLowering {
        plan: fx::lower_named(
            &[fx::module_with_targets(
                &scene.pins,
                &scene.b,
                &[(&scene.a, 0x1000), (&scene.b, 0x2000)],
            )],
            &scene.pins,
            crate::plan::AdmissionPolicy::Inventory(
                scene.native.scene.coordinator.attach_set.budget(),
            ),
        ),
        pins: fx::pass_pins(&[(&scene.a, "sha-a"), (&scene.b, "sha-b")]),
        modules: Vec::new(),
    });
    scene.apply(catalog, 400);
    assert!(scene.native.scene.coordinator.attach_set.count_revision() != revision);
    for _ in 0..20 {
        scene.horizons();
        receipts.assert_bounded();
    }
    let recovery = &scene.native.scene.coordinator.recoveries[&key];
    assert!(recovery.epoch == Some(epoch) && recovery.sighting.is_none());
    assert_eq!(recovery.watermark, 7);
    assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), 300);
    assert_eq!(recovery.fence.unwrap().anchor_ns, original.anchor_ns);
    assert_eq!(scene.counts(), (5, 0));
    scene.native.answer(7, 500, 41);
    for _ in 0..20 {
        scene.horizons();
        receipts.assert_bounded();
    }
    assert_eq!(
        scene.counts(),
        (5, 2),
        "real binding/proof later settles without another count"
    );
    let recovery = &scene.native.scene.coordinator.recoveries[&key];
    assert_eq!(
        (
            recovery.fence.unwrap().count,
            recovery.fence.unwrap().anchor_ns,
            recovery.fence.unwrap().last_ns
        ),
        (8, original.anchor_ns, original.last_ns)
    );
    assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), 300);
}

enum Round4FreshRejection {
    NoCookie,
    DifferentCookie,
    Exited,
}

fn round4_fresh_rejection_revokes_original_read(rejection: Round4FreshRejection) {
    use crate::attach::capture::{CookieQuery, DomainCookie};

    let receipts = WorkReceipts::begin();
    let mut scene = Scene::shared();
    scene.native.unavailable_answer(7, 500);
    scene.observe(false, true, 300);
    scene.count(8);
    let key = *scene
        .native
        .scene
        .coordinator
        .recoveries
        .keys()
        .next()
        .unwrap();
    let original = scene.native.scene.coordinator.recoveries[&key]
        .fence
        .expect("first actual8 retained under explicit Unavailable");
    scene.count(10);
    for _ in 0..4 {
        scene.horizons();
        receipts.assert_bounded();
    }
    let recovery = &scene.native.scene.coordinator.recoveries[&key];
    let selected = recovery.fence.expect("unavailability preserves actual8");
    assert_eq!(
        (selected.count, selected.anchor_ns, selected.last_ns),
        (8, original.anchor_ns, original.last_ns)
    );
    assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), 300);
    assert!(recovery.sighting.is_none());
    assert_eq!(recovery.watermark, 7);
    assert_eq!(scene.counts(), (5, 0));

    match rejection {
        Round4FreshRejection::NoCookie => scene.native.forget_answer(7, 500),
        Round4FreshRejection::DifferentCookie => scene.native.query_answer(
            7,
            500,
            CookieQuery::Cookie(DomainCookie::scripted(scene.native.domain, 999)),
        ),
        Round4FreshRejection::Exited => scene.native.query_answer(7, 500, CookieQuery::Exited),
    }
    let queries = scene.native.cookies.queries;
    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene.native.read(Vec::new());
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    assert!(
        scene.native.cookies.queries > queries,
        "real fresh query was attempted"
    );
    let recovery = &scene.native.scene.coordinator.recoveries[&key];
    assert!(
        recovery.epoch.is_none()
            && recovery.scan.is_none()
            && recovery.fence.is_none()
            && recovery.sighting.is_none(),
        "fresh identity rejection must revoke the original S300/read8 authority immediately"
    );
    assert_eq!(scene.counts(), (5, 0));
    receipts.assert_bounded();

    scene.native.answer(7, 500, 41);
    for _ in 0..8 {
        scene.horizons();
        receipts.assert_bounded();
    }
    scene.count(10);
    assert_eq!(
        scene.counts(),
        (5, 0),
        "restoration and equal held10 cannot reuse read8"
    );
    assert!(
        scene.native.scene.coordinator.recoveries[&key]
            .fence
            .is_none()
    );

    scene.count(12);
    for _ in 0..8 {
        scene.horizons();
        receipts.assert_bounded();
    }
    let replacement = scene.native.scene.coordinator.recoveries[&key]
        .fence
        .expect("new strict actual12 supplies a new boundary");
    assert_eq!(replacement.count, 12);
    assert!(replacement.anchor_ns > original.last_ns);
    assert_eq!(scene.counts(), (5, 0));
    scene.count(14);
    for _ in 0..4 {
        scene.horizons();
        receipts.assert_bounded();
    }
    assert_eq!(
        scene.counts(),
        (5, 2),
        "only growth after the new actual12 may recover"
    );
}

#[test]
fn demotion_retirement_round4_no_cookie_revokes_original_read() {
    round4_fresh_rejection_revokes_original_read(Round4FreshRejection::NoCookie);
}

#[test]
fn demotion_retirement_round4_different_cookie_revokes_original_read() {
    round4_fresh_rejection_revokes_original_read(Round4FreshRejection::DifferentCookie);
}

#[test]
fn demotion_retirement_round4_exited_query_revokes_original_read() {
    round4_fresh_rejection_revokes_original_read(Round4FreshRejection::Exited);
}

#[test]
fn demotion_retirement_round4_missing_completion_clock_revokes_original_read() {
    let clocks: [fn() -> Option<u64>; 2] = [|| None, || Some(0)];
    for unavailable_clock in clocks {
        let receipts = WorkReceipts::begin();
        let mut scene = Scene::shared();
        scene.native.unavailable_answer(7, 500);
        scene.observe(false, true, 300);
        scene.count(8);
        scene.count(10);
        let key = *scene
            .native
            .scene
            .coordinator
            .recoveries
            .keys()
            .next()
            .unwrap();
        assert_eq!(
            scene.native.scene.coordinator.recoveries[&key]
                .fence
                .unwrap()
                .count,
            8
        );
        scene.native.answer(7, 500, 41);
        scene
            .native
            .scene
            .coordinator
            .binder
            .set_current_binding_clock(unavailable_clock);
        scene.native.read(Vec::new());
        scene.native.scene.coordinator.commit_batch(false).unwrap();
        let recovery = &scene.native.scene.coordinator.recoveries[&key];
        assert!(
            recovery.epoch.is_none() && recovery.fence.is_none() && recovery.sighting.is_none(),
            "missing completion time revokes usable authority without asserting a cookie mismatch"
        );
        scene
            .native
            .scene
            .coordinator
            .binder
            .set_current_binding_clock(query_clock);
        for _ in 0..8 {
            scene.horizons();
            receipts.assert_bounded();
        }
        assert_eq!(
            scene.counts(),
            (5, 0),
            "restoring a clock cannot reuse actual8"
        );
        assert!(
            scene.native.scene.coordinator.recoveries[&key]
                .fence
                .is_none()
        );
        scene.count(12);
        for _ in 0..8 {
            scene.horizons();
        }
        assert_eq!(
            scene.native.scene.coordinator.recoveries[&key]
                .fence
                .unwrap()
                .count,
            12
        );
        scene.count(14);
        for _ in 0..4 {
            scene.horizons();
        }
        assert_eq!(scene.counts(), (5, 2));
        receipts.assert_bounded();
    }
}

fn round4_native_service(scene: &mut Scene) {
    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene.native.read(Vec::new());
    scene.native.scene.coordinator.commit_batch(false).unwrap();
}

fn round4_sole_is(scene: &Scene, caller: CallerId, object: u32, name: &str) -> bool {
    let coordinator = &scene.native.scene.coordinator;
    coordinator
        .count_ownership
        .sole(caller, object)
        .is_some_and(|(module, _)| {
            coordinator
                .registry
                .module_id_for(module)
                .and_then(|id| coordinator.registry.module(id))
                .is_some_and(|record| record.paths.iter().any(|path| path.ends_with(name)))
        })
}

fn round4_many_bound_members() -> (Scene, Vec<(u32, CallerId, u64)>) {
    let (mut scene, mut members) = round3_more_members();
    // Leave a substantial real scheduling distance between the ownership
    // summary cursor and the single-pair recovery service. No cursor is edited.
    for pid in 40..136 {
        let start = 500 + u64::from(pid);
        scene.native.scene.source.spawn(pid, start);
        let caller = scene
            .native
            .scene
            .coordinator
            .adapter
            .admit(pid, ImageAuthority::ScanPinned, 80)
            .unwrap();
        scene.native.scene.project_paths(pid, &[&scene.a], 90);
        scene.native.scene.coordinator.commit_batch(false).unwrap();
        let ticket = 100 + u64::from(pid);
        scene.native.answer(pid, start, ticket);
        let mut row = scene.native.row(ticket, 1, pid, 100, 0);
        row.entry_count = 5;
        scene.native.witness(vec![row]);
        members.push((pid, caller, ticket));
    }
    (scene, members)
}

fn round4_late_ordinary_keys(scene: &Scene, owner: &str) -> Vec<PairKey> {
    let coordinator = &scene.native.scene.coordinator;
    coordinator
        .recoveries
        .iter()
        .filter_map(|(&key, recovery)| {
            (!recovery.blocked
                && recovery.epoch.is_none()
                && recovery.watermark == 5
                && matches!(
                    coordinator.pair_targets.get(&key),
                    Some(PairTarget::Bound { staged: 5, .. })
                )
                && round4_sole_is(scene, recovery.caller, key.object, owner))
            .then_some(key)
        })
        .collect()
}

fn round4_processed_return_requires_fence(intermediate_read: bool) {
    let receipts = WorkReceipts::begin();
    let (mut scene, members) = round4_many_bound_members();
    let object = scene.native.scene.delta.endpoints[0].object.index();
    scene.apply(
        members_catalog_paths(&scene, &members, &[&scene.a], 200),
        200,
    );
    for _ in 0..512 {
        if members
            .iter()
            .all(|&(_, caller, _)| round4_sole_is(&scene, caller, object, "a.so"))
        {
            break;
        }
        round4_native_service(&mut scene);
    }
    assert!(
        members
            .iter()
            .all(|&(_, caller, _)| round4_sole_is(&scene, caller, object, "a.so"))
    );
    for &(pid, _, _) in &members {
        scene
            .native
            .unavailable_answer(pid, if pid == 7 { 500 } else { 500 + u64::from(pid) });
    }
    scene.apply(members_catalog(&scene, &members, false, 300), 300);
    let mut late_b = Vec::new();
    for _ in 0..512 {
        late_b = round4_late_ordinary_keys(&scene, "b.so");
        if late_b.len() >= members.len() / 2 {
            break;
        }
        round4_native_service(&mut scene);
    }
    assert!(
        late_b.len() >= members.len() / 2,
        "fixture must positively finish B for many still-unserviced Bound A5 pairs"
    );
    if intermediate_read {
        let updates = late_b
            .iter()
            .map(|key| {
                let caller = scene.native.scene.coordinator.recoveries[key].caller;
                let ticket = members.iter().find(|member| member.1 == caller).unwrap().2;
                (ticket, 1, 0, 7)
            })
            .collect();
        QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
        scene.native.counts_read(Vec::new(), updates);
        let coordinator = &scene.native.scene.coordinator;
        late_b.retain(|key| {
            let recovery = &coordinator.recoveries[key];
            recovery.epoch.is_none()
                && !recovery.blocked
                && recovery.deferred_count
                && recovery
                    .pending_reads
                    .iter()
                    .flatten()
                    .any(|tag| tag.scan.started_ns() == 300 && tag.read.count == 7)
                && !coordinator
                    .pending_ids
                    .values()
                    .any(|pending| pending.key == *key)
        });
        assert!(
            !late_b.is_empty(),
            "actual B7 was retained before this pair's service turn"
        );
    }
    receipts.assert_bounded();
    scene.apply(
        members_catalog_paths(&scene, &members, &[&scene.a], 400),
        400,
    );
    let mut returning = None;
    for _ in 0..512 {
        returning = late_b.iter().copied().find(|key| {
            let coordinator = &scene.native.scene.coordinator;
            let recovery = &coordinator.recoveries[key];
            recovery.epoch.is_none()
                && !recovery.blocked
                && recovery.watermark == 5
                && matches!(
                    coordinator.pair_targets.get(key),
                    Some(PairTarget::Bound { staged: 5, .. })
                )
                && round4_sole_is(&scene, recovery.caller, key.object, "a.so")
                && (!intermediate_read
                    || recovery
                        .pending_reads
                        .iter()
                        .flatten()
                        .any(|tag| tag.scan.started_ns() == 300 && tag.read.count == 7))
        });
        if returning.is_some() {
            break;
        }
        round4_native_service(&mut scene);
    }
    let key = returning.expect(
        "fixture must finish A while the same positively processed B transition is unserviced",
    );
    let caller = scene.native.scene.coordinator.recoveries[&key].caller;
    let &(pid, _, ticket) = members.iter().find(|member| member.1 == caller).unwrap();
    assert_eq!(edge_count(&scene.native, caller, "a.so"), 5);
    assert_eq!(edge_count(&scene.native, caller, "b.so"), 0);
    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene
        .native
        .counts_read(Vec::new(), vec![(ticket, 1, 0, 10)]);
    let actual_ten = scene.native.scene.coordinator.pair_counts[&key];
    assert!(
        !scene
            .native
            .scene
            .coordinator
            .pending_ids
            .values()
            .any(|pending| pending.key == key && pending.observation.count == 10),
        "returning A's first read10 must enter the recovery interlock before generic staging"
    );
    scene.native.answer(
        pid,
        if pid == 7 { 500 } else { 500 + u64::from(pid) },
        ticket,
    );
    for _ in 0..(members.len() * 2) {
        scene.horizons();
        receipts.assert_bounded();
    }
    assert_eq!(
        (
            edge_count(&scene.native, caller, "a.so"),
            edge_count(&scene.native, caller, "b.so")
        ),
        (5, 0),
        "a positively processed B interval must not become full ordinary A growth"
    );
    let recovery = &scene.native.scene.coordinator.recoveries[&key];
    let fence = recovery
        .fence
        .expect("returning A needs its actual first10 as a new fence");
    assert_eq!(
        (fence.count, fence.anchor_ns, fence.last_ns),
        (10, actual_ten.anchor_ns, actual_ten.last_ns)
    );
    assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), 400);
    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene
        .native
        .counts_read(Vec::new(), vec![(ticket, 1, 0, 12)]);
    for _ in 0..(members.len() * 2) {
        scene.horizons();
        receipts.assert_bounded();
    }
    assert_eq!(
        (
            edge_count(&scene.native, caller, "a.so"),
            edge_count(&scene.native, caller, "b.so")
        ),
        (7, 0),
        "only actual12 after the new10 fence contributes a returned-A segment"
    );
}

#[test]
fn demotion_retirement_round4_processed_b_then_a_before_service_keeps_fence() {
    round4_processed_return_requires_fence(true);
}

#[test]
fn demotion_retirement_round4_processed_b_then_a_without_read_keeps_fence() {
    round4_processed_return_requires_fence(false);
}

fn round4_noncompeting_b_catalog(scene: &Scene, at: u64) -> crate::inspect_system::Catalog {
    let mut catalog =
        members_catalog_paths(scene, &[(7, scene.caller, 41)], &[&scene.a, &scene.b], at);
    catalog.lowering = Some(crate::inspect_system::CatalogLowering {
        plan: fx::lower_named(
            &[
                fx::module_with_targets(&scene.pins, &scene.a, &[(&scene.a, 0x1000)]),
                fx::module_with_targets(&scene.pins, &scene.b, &[(&scene.b, 0x1000)]),
            ],
            &scene.pins,
            crate::plan::AdmissionPolicy::Inventory(
                scene.native.scene.coordinator.attach_set.budget(),
            ),
        ),
        pins: fx::pass_pins(&[(&scene.a, "sha-a"), (&scene.b, "sha-b")]),
        modules: Vec::new(),
    });
    catalog
}

fn round4_finish_sole(scene: &mut Scene, name: &str) {
    let object = scene.native.scene.delta.endpoints[0].object.index();
    for _ in 0..128 {
        if round4_sole_is(scene, scene.caller, object, name) {
            break;
        }
        round4_native_service(scene);
    }
    assert!(
        round4_sole_is(scene, scene.caller, object, name),
        "the real bounded summary must positively finish {name}; scan={:?}, deferred={}, cells={:?}",
        scene
            .native
            .scene
            .coordinator
            .count_ownership
            .supporting_scan(scene.caller)
            .map(|scan| (scan.started_ns(), scan.finished_ns())),
        scene
            .native
            .scene
            .coordinator
            .count_ownership
            .deferred(scene.caller, object),
        scene
            .native
            .scene
            .coordinator
            .count_ownership
            .retained_cells()
    );
}

fn round4_placed_with_known_b() -> Scene {
    let (mut native, caller) = NativeScene::new();
    native
        .scene
        .coordinator
        .binder
        .set_current_binding_clock(query_clock);
    let a = native.scene.path.clone();
    let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
    let pins = fx::pass_pins(&[(&a, "sha-a"), (&b, "sha-b")]);
    let generation = crate::inspect_system::MemberGeneration {
        start_time: Some(500),
        exe: native
            .scene
            .coordinator
            .adapter
            .record(caller)
            .unwrap()
            .exe
            .clone(),
    };
    let mut scene = Scene {
        native,
        caller,
        a,
        b,
        pins,
        generation,
    };
    // Publish both admissions before the baseline. A single-caller ownership
    // slice can finish before the same pass publishes a new module's admission.
    let mut admission = round4_noncompeting_b_catalog(&scene, 80);
    admission.processes[0].complete_scan = None;
    scene.apply(admission, 80);
    scene.apply(
        members_catalog_paths(&scene, &[(7, caller, 41)], &[&scene.a], 100),
        100,
    );
    scene.native.answer(7, 500, 41);
    let row = scene.native.row(41, 1, 7, 100, 0);
    scene.native.witness(vec![row]);
    scene.count(5);
    scene
}

#[test]
fn demotion_retirement_round4_noncompeting_module_keeps_ordinary_growth() {
    let receipts = WorkReceipts::begin();
    let mut scene = round4_placed_with_known_b();
    scene.apply(
        members_catalog_paths(&scene, &[(7, scene.caller, 41)], &[&scene.a], 200),
        200,
    );
    round4_finish_sole(&mut scene, "a.so");
    let queries = scene.native.cookies.queries;
    scene.apply(round4_noncompeting_b_catalog(&scene, 300), 300);
    round4_finish_sole(&mut scene, "a.so");
    scene.apply(
        members_catalog_paths(&scene, &[(7, scene.caller, 41)], &[&scene.a], 400),
        400,
    );
    round4_finish_sole(&mut scene, "a.so");
    scene.count(8);
    scene.count(10);
    for _ in 0..8 {
        scene.horizons();
    }
    assert_eq!(scene.counts(), (10, 0));
    assert_eq!(
        scene.native.cookies.queries, queries,
        "a positively processed unrelated provider cannot revoke ordinary physical A continuity"
    );
    receipts.assert_bounded();
}

/// Mapping learned late, then a revision churns the epoch scan:
/// the seed places, one flap runs the ownership sequence past the
/// recovery's checkpoint, and growth addressed to the resolving scan
/// must stage instead of gap-flushing. Fenced growth whose proof
/// never completes still discloses (binder-proof domain); unfenced
/// post-scan growth stages at the first same-carrier resolution and
/// later revisions must neither double-stage nor re-gap it. (Live
/// the whole window gaps and the edge freezes: the churned tags
/// never match the resolving scan, so no fence ever sets.)
#[test]
fn demotion_retirement_late_mapping_stages_withheld_growth() {
    let receipts = WorkReceipts::begin();
    let (mut native, caller) = NativeScene::new();
    native
        .scene
        .coordinator
        .binder
        .set_current_binding_clock(query_clock);
    let a = native.scene.path.clone();
    let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
    let pins = fx::pass_pins(&[(&a, "sha-a"), (&b, "sha-b")]);
    let generation = crate::inspect_system::MemberGeneration {
        start_time: Some(500),
        exe: native
            .scene
            .coordinator
            .adapter
            .record(caller)
            .unwrap()
            .exe
            .clone(),
    };
    let mut scene = Scene {
        native,
        caller,
        a,
        b,
        pins,
        generation,
    };
    let object = scene.native.scene.delta.endpoints[0].object.index();
    let victim = &[(7, caller, 41)];
    let mut admission = round4_noncompeting_b_catalog(&scene, 80);
    admission.processes[0].complete_scan = None;
    scene.apply(admission, 80);
    scene.apply(members_catalog_paths(&scene, victim, &[&scene.a], 100), 100);
    scene.native.answer(7, 500, 41);
    let row = scene.native.row(41, 1, 7, 100, 0);
    scene.native.witness(vec![row]);
    scene.count(1);
    assert_eq!(edge_count(&scene.native, caller, "a.so"), 1);
    round4_finish_sole(&mut scene, "a.so");
    let checkpoint = scene
        .native
        .scene
        .coordinator
        .recoveries
        .values()
        .next()
        .map(|recovery| recovery.ordinary_checkpoint)
        .unwrap();
    // First flap stales the checkpoint; incomplete scans keep
    // absences uncertain so the edge survives the Unknown phase.
    let mut unmapped = members_catalog_paths(&scene, victim, &[], 200);
    unmapped.processes[0].complete_scan = None;
    scene.apply(unmapped, 200);
    for _ in 0..128 {
        let coordinator = &scene.native.scene.coordinator;
        if !coordinator.count_ownership.deferred(caller, object)
            && coordinator.count_ownership.sole(caller, object).is_none()
        {
            break;
        }
        round4_native_service(&mut scene);
    }
    scene.apply(members_catalog_paths(&scene, victim, &[&scene.a], 250), 250);
    round4_finish_sole(&mut scene, "a.so");
    let sequence = scene
        .native
        .scene
        .coordinator
        .count_ownership
        .ordinary_view(caller, object)
        .sequence;
    assert_ne!(
        sequence, checkpoint,
        "flapping must stale the checkpoint for the wedge shape"
    );
    // Withheld growth absorbed (not yet reconciled) under the old
    // epoch. Absorb without committing so no reconcile fences the
    // reads against the stale scan first.
    for (absolute, pre, post) in [(7, 500, 501), (12, 3000, 3001)] {
        QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
        let NativeBatch::Witness(mut batch) =
            scene.native.stamps.read(scene.native.domain, Vec::new())
        else {
            unreachable!()
        };
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: scene.native.scene.delta.endpoints[0].object,
            count: absolute,
        }];
        batch.counts_read_ns = pre;
        batch.rows_read_ns = post;
        scene.native.stage(NativeBatch::Witness(batch));
    }
    assert_eq!(edge_count(&scene.native, caller, "a.so"), 1);
    let mut unmapped = members_catalog_paths(&scene, victim, &[], 2400);
    unmapped.processes[0].complete_scan = None;
    scene.apply(unmapped, 2400);
    for _ in 0..128 {
        let coordinator = &scene.native.scene.coordinator;
        if !coordinator.count_ownership.deferred(caller, object)
            && coordinator.count_ownership.sole(caller, object).is_none()
        {
            break;
        }
        round4_native_service(&mut scene);
    }
    scene.apply(
        members_catalog_paths(&scene, victim, &[&scene.a], 2000),
        2000,
    );
    round4_finish_sole(&mut scene, "a.so");
    for _ in 0..64 {
        scene.horizons();
    }
    assert_eq!(edge_count(&scene.native, caller, "a.so"), 6);
    let gaps: Vec<String> = scene
        .native
        .scene
        .coordinator
        .registry
        .gaps()
        .iter()
        .filter(|gap| gap.subject == crate::discovery::caller_registry::DEMOTED_COUNT_REJECTED)
        .map(|gap| gap.reason.clone())
        .collect();
    assert!(
        gaps.iter().any(|reason| reason.contains("(1, 7]")),
        "predating growth discloses, got: {gaps:?}"
    );
    assert!(
        gaps.iter().all(|reason| !reason.contains("(1, 12]")),
        "eligible growth must stage, not gap, got: {gaps:?}"
    );
    receipts.assert_bounded();
}

fn round4_queued_catalog(
    scene: &Scene,
    extras: &[PathBuf],
    observed: &[&std::path::Path],
    at: u64,
    complete: bool,
    b_competes: bool,
) -> crate::inspect_system::Catalog {
    let mut catalog = capture_catalog(&scene.pins, observed, 7, Some(scene.generation.clone()));
    if complete {
        catalog.processes[0].complete_scan =
            Some(crate::inspect_system::CompleteMemberScan::scripted(
                scene.generation.clone(),
                at,
                at + 1,
            ));
    }
    let mut inputs = vec![(scene.a.as_path(), "sha-a"), (scene.b.as_path(), "sha-b")];
    inputs.extend(extras.iter().map(|path| (path.as_path(), "sha-extra")));
    let mut modules = vec![
        fx::module_with_targets(&scene.pins, &scene.a, &[(&scene.a, 0x1000)]),
        fx::module_with_targets(
            &scene.pins,
            &scene.b,
            &[(if b_competes { &scene.a } else { &scene.b }, 0x1000)],
        ),
    ];
    modules.extend(
        extras
            .iter()
            .map(|path| fx::module(&scene.pins, path, &[0x1000])),
    );
    catalog.lowering = Some(crate::inspect_system::CatalogLowering {
        plan: fx::lower_named(
            &modules,
            &scene.pins,
            crate::plan::AdmissionPolicy::Inventory(
                scene.native.scene.coordinator.attach_set.budget(),
            ),
        ),
        pins: fx::pass_pins(&inputs),
        modules: Vec::new(),
    });
    catalog
}

fn round4_queued_accepted_interval(shared: bool, noncompeting: bool) {
    let receipts = WorkReceipts::begin();
    let (mut native, caller) = NativeScene::new();
    native
        .scene
        .coordinator
        .binder
        .set_current_binding_clock(query_clock);
    let a = native.scene.path.clone();
    let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
    let extras = (0..5)
        .map(|index| fx::provider(&native.scene._dir, &format!("n{index}.so"), "noncompeting"))
        .collect::<Vec<_>>();
    let mut inputs = vec![(a.as_path(), "sha-a"), (b.as_path(), "sha-b")];
    inputs.extend(extras.iter().map(|path| (path.as_path(), "sha-extra")));
    let pins = fx::pass_pins(&inputs);
    let generation = crate::inspect_system::MemberGeneration {
        start_time: Some(500),
        exe: native
            .scene
            .coordinator
            .adapter
            .record(caller)
            .unwrap()
            .exe
            .clone(),
    };
    let mut scene = Scene {
        native,
        caller,
        a,
        b,
        pins,
        generation,
    };
    let all = std::iter::once(scene.a.as_path())
        .chain(std::iter::once(scene.b.as_path()))
        .chain(extras.iter().map(PathBuf::as_path))
        .collect::<Vec<_>>();
    scene.apply(
        round4_queued_catalog(&scene, &extras, &all, 80, false, false),
        80,
    );
    assert_eq!(scene.native.scene.coordinator.registry.modules().count(), 7);
    assert!(
        scene
            .native
            .scene
            .coordinator
            .registry
            .modules()
            .all(|module| {
                module.admission == crate::discovery::caller_registry::AdmissionState::Admitted
            })
    );
    // Original generic A5 is published before B first shares its endpoint.
    // Neither optional incomplete admission nor this count fabricates a proof.
    scene.native.answer(7, 500, 41);
    let row = scene.native.row(41, 1, 7, 100, 0);
    let key = PairKey::of(&row);
    scene.native.witness(vec![row]);
    scene.count(5);
    assert_eq!(scene.counts(), (5, 0));
    let a_paths = std::iter::once(scene.a.as_path())
        .chain(extras.iter().map(PathBuf::as_path))
        .collect::<Vec<_>>();
    scene.apply(
        round4_queued_catalog(&scene, &extras, &a_paths, 100, true, !noncompeting),
        100,
    );
    let object = scene.native.scene.delta.endpoints[0].object.index();
    for _ in 0..128 {
        if scene
            .native
            .scene
            .coordinator
            .count_ownership
            .newest_accepted_post(caller)
            == 101
            && !scene
                .native
                .scene
                .coordinator
                .count_ownership
                .deferred(caller, object)
        {
            break;
        }
        round4_native_service(&mut scene);
    }
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .count_ownership
            .newest_accepted_post(caller),
        101
    );
    round4_finish_sole(&mut scene, "a.so");
    assert_eq!(scene.counts(), (5, 0));
    let checkpoint = scene.native.scene.coordinator.recoveries[&key].ordinary_checkpoint;
    assert_ne!(checkpoint, 0);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .count_ownership
            .ordinary_sequence(caller, object),
        checkpoint
    );
    let queries = scene.native.cookies.queries;

    let mut middle = if noncompeting {
        vec![scene.a.as_path()]
    } else if shared {
        vec![scene.a.as_path(), scene.b.as_path()]
    } else {
        vec![scene.b.as_path()]
    };
    middle.extend(
        extras
            .iter()
            .take(if noncompeting { 4 } else { 5 })
            .map(PathBuf::as_path),
    );
    scene.apply(
        round4_queued_catalog(&scene, &extras, &middle, 300, true, !noncompeting),
        300,
    );
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .count_ownership
            .newest_accepted_post(caller),
        101,
        "five three-visit comparisons leave the middle receipt processing"
    );
    let a_paths = std::iter::once(scene.a.as_path())
        .chain(extras.iter().map(PathBuf::as_path))
        .collect::<Vec<_>>();
    scene.apply(
        round4_queued_catalog(&scene, &extras, &a_paths, 400, true, !noncompeting),
        400,
    );
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .count_ownership
            .newest_accepted_post(caller),
        301,
        "the competing/noncompeting middle observation actually completed acceptance"
    );
    assert!(
        scene
            .native
            .scene
            .coordinator
            .count_ownership
            .deferred(caller, object)
    );
    let retained = scene
        .native
        .scene
        .coordinator
        .count_ownership
        .receipt_view(caller)
        .receipts()
        .map(|scan| scan.started_ns())
        .collect::<Vec<_>>();
    assert_eq!(
        retained,
        vec![300, 400],
        "accepted middle receipt and processing return coexist"
    );
    eprintln!(
        "accepted middle POST301 while return400 is queued: checkpoint={checkpoint}, ordinary_sequence={}",
        scene
            .native
            .scene
            .coordinator
            .count_ownership
            .ordinary_sequence(caller, object)
    );
    scene.count(10);
    let actual_ten = scene.native.scene.coordinator.pair_counts[&key];
    for _ in 0..128 {
        scene.horizons();
        receipts.assert_bounded();
    }
    assert_eq!(
        scene.counts(),
        (if noncompeting { 10 } else { 5 }, 0),
        "every accepted intervening observation must affect ordinary continuity"
    );
    if noncompeting {
        assert_eq!(
            scene.native.cookies.queries, queries,
            "proved noncompeting queued changes keep ordinary growth without a fresh query"
        );
    } else {
        let fence = scene.native.scene.coordinator.recoveries[&key]
            .fence
            .expect("actual returning-A boundary");
        assert_eq!(
            (fence.count, fence.anchor_ns, fence.last_ns),
            (10, actual_ten.anchor_ns, actual_ten.last_ns)
        );
    }
    scene.count(12);
    for _ in 0..16 {
        scene.horizons();
    }
    assert_eq!(scene.counts(), (if noncompeting { 12 } else { 7 }, 0));
    receipts.assert_bounded();
}

#[test]
fn demotion_retirement_round4_accepted_b_return_before_summary_requires_fence() {
    round4_queued_accepted_interval(false, false);
}

#[test]
fn demotion_retirement_round4_accepted_shared_return_before_summary_requires_fence() {
    round4_queued_accepted_interval(true, false);
}

#[test]
fn demotion_retirement_round4_accepted_noncompeting_queue_keeps_ordinary_growth() {
    round4_queued_accepted_interval(false, true);
}

fn round4_late_initial_handle_requires_new_fence(delayed_staging: bool, competing: bool) {
    use crate::attach::capture::ExecCoverage;

    let receipts = WorkReceipts::begin();
    let mut scene = round4_placed_with_known_b();
    scene.apply(
        members_catalog_paths(&scene, &[(7, scene.caller, 41)], &[&scene.a], 200),
        200,
    );
    round4_finish_sole(&mut scene, "a.so");
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .count_ownership
            .retained_cells()
            .2,
        1,
        "another exact native pair already owns the caller/object summary"
    );

    let first_domain = scene.native.domain;
    let second_domain = NativeDomainId::mint();
    scene
        .native
        .scene
        .coordinator
        .note_extend_receipt(&ExtendReceipt {
            activated_roots: true,
            exec_coverage: Some(ExecCoverage::scripted(second_domain, 0)),
            ..ExtendReceipt::default()
        });
    scene.native.domain = second_domain;
    scene.native.answer(7, 500, 99);
    let row = scene.native.row(99, 1, 7, 100, 0);
    let key = PairKey::of(&row);
    scene.native.read(vec![row]);
    scene.native.counts_read(Vec::new(), vec![(99, 1, 0, 5)]);
    let original = scene.native.scene.coordinator.pair_counts[&key];
    assert_eq!(original.count, 5);
    assert!(!scene.native.scene.coordinator.recoveries.contains_key(&key));
    let mut original_decisions = Vec::new();
    if delayed_staging {
        assert!(
            !scene
                .native
                .scene
                .coordinator
                .pair_targets
                .contains_key(&key),
            "the second domain's real binder must still await its horizons"
        );
    } else {
        scene.native.drain();
        scene.native.read(Vec::new());
        let pending = scene
            .native
            .scene
            .coordinator
            .pending_ids
            .values()
            .find(|pending| pending.key == key)
            .expect("actual original generic5 handle");
        assert_eq!(
            (
                pending.observation.count,
                pending.observation.anchor_ns,
                pending.observation.last_ns
            ),
            (5, original.anchor_ns, original.last_ns)
        );
        scene.native.scene.coordinator.registry.publish();
        original_decisions = scene
            .native
            .scene
            .coordinator
            .registry
            .take_pending_count_decisions();
        assert_eq!(original_decisions.len(), 1);
        assert!(
            matches!(
                &original_decisions[0].outcome,
                PendingCountOutcome::Placed { .. }
            ),
            "hold a real successful historical5 decision, never manufacture one"
        );
        assert!(!scene.native.scene.coordinator.recoveries.contains_key(&key));
    }

    // Only first-domain services run while the second-domain original5 waits.
    // Scan PRE/POST now truly follow that saved count, not just call order.
    scene.native.domain = first_domain;
    if competing {
        let b_at = scene.native.stamps.tick();
        scene.observe(false, true, b_at);
        round4_finish_sole(&mut scene, "b.so");
    }
    let a_at = scene.native.stamps.tick();
    let returning = if competing {
        round4_noncompeting_b_catalog(&scene, a_at)
    } else {
        members_catalog_paths(&scene, &[(7, scene.caller, 41)], &[&scene.a], a_at)
    };
    scene.apply(returning, a_at);
    round4_finish_sole(&mut scene, "a.so");
    let CurrentCandidates::Sole { scan, .. } = scene
        .native
        .scene
        .coordinator
        .count_ownership
        .candidates(scene.caller, key.object)
    else {
        unreachable!()
    };
    assert!(
        scene
            .native
            .scene
            .coordinator
            .count_ownership
            .newest_accepted_post(scene.caller)
            > original.last_ns,
        "first staging/publication happens after a newer accepted return-to-A scan"
    );
    if !competing {
        assert!(
            scan.finished_ns() < original.anchor_ns,
            "the original equivalent receipt remains separate from the newest accepted POST"
        );
    }
    assert!(!scene.native.scene.coordinator.recoveries.contains_key(&key));

    scene.native.domain = second_domain;
    if delayed_staging {
        scene.native.drain();
        scene.native.read(Vec::new());
        let pending = scene
            .native
            .scene
            .coordinator
            .pending_ids
            .values()
            .find(|pending| pending.key == key)
            .expect("late first stage preserves actual old5");
        assert_eq!(
            (
                pending.observation.count,
                pending.observation.anchor_ns,
                pending.observation.last_ns
            ),
            (5, original.anchor_ns, original.last_ns)
        );
    } else {
        crate::discovery::caller_registry::tests::deliver_pending_decisions(
            &mut scene.native.scene.coordinator.registry,
            &original_decisions,
        );
        scene.native.scene.coordinator.finalize_pending_counts();
    }
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    assert!(scene.native.scene.coordinator.recoveries.contains_key(&key));
    assert_eq!(
        scene.counts(),
        (5, 0),
        "generic initial absolutes preserve the original historical five"
    );

    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene.native.counts_read(Vec::new(), vec![(99, 1, 0, 10)]);
    let actual_ten = scene.native.scene.coordinator.pair_counts[&key];
    for _ in 0..16 {
        scene.horizons();
        receipts.assert_bounded();
    }
    assert_eq!(
        scene.counts(),
        (5, 0),
        "an old first read cannot acquire ordinary authority from current summary state at staging/publication"
    );
    let fence = scene.native.scene.coordinator.recoveries[&key]
        .fence
        .expect("the second exact pair needs its own new actual10 boundary");
    assert_eq!(
        (fence.count, fence.anchor_ns, fence.last_ns),
        (10, actual_ten.anchor_ns, actual_ten.last_ns)
    );
    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene.native.counts_read(Vec::new(), vec![(99, 1, 0, 12)]);
    for _ in 0..8 {
        scene.horizons();
    }
    assert_eq!(scene.counts(), (7, 0));
    if !delayed_staging {
        crate::discovery::caller_registry::tests::deliver_pending_decisions(
            &mut scene.native.scene.coordinator.registry,
            &original_decisions,
        );
        scene.native.scene.coordinator.finalize_pending_counts();
        scene.native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            scene.counts(),
            (7, 0),
            "old decision replay cannot reset the checkpoint or history"
        );
    }
    receipts.assert_bounded();
}

#[test]
fn demotion_retirement_round4_delayed_first_publication_keeps_original_checkpoint() {
    round4_late_initial_handle_requires_new_fence(false, true);
}

#[test]
fn demotion_retirement_round4_delayed_first_stage_cannot_borrow_other_pair_summary() {
    round4_late_initial_handle_requires_new_fence(true, true);
}

#[test]
fn demotion_retirement_round4_delayed_first_stage_uses_newest_equivalent_post() {
    round4_late_initial_handle_requires_new_fence(true, false);
}

#[test]
fn demotion_retirement_round4_fixed_state_layouts() {
    let (summary, caller, index) = CountOwnership::state_layouts();
    println!(
        "round4 layouts: PairRecovery={} CandidateSummary={summary} CallerObservation={caller} MembershipIndex={index} PendingCountObservation={} PendingCountOrigin={}",
        std::mem::size_of::<PairRecovery>(),
        std::mem::size_of::<PendingCountObservation>(),
        std::mem::size_of::<PendingCountOrigin>()
    );
    // Original R1 payload320, four immutable reads gain16 bytes of refs each,
    // and the fixed diagnostic transition/suppression projection adds104 bytes.
    assert_eq!(std::mem::size_of::<PairRecovery>(), 488);
    assert_eq!(std::mem::size_of::<PendingCountOrigin>(), 16);
}

fn round4_queue_ownership(
    ownership: &mut CountOwnership,
    scene: &Scene,
    mut modules: Vec<ModuleKey>,
    at: u64,
) {
    modules.sort();
    ownership.invalidate_memberships(scene.native.scene.coordinator.attach_set.count_revision());
    ownership.begin_catalog_pass();
    assert!(ownership.queue_observation(
        scene.caller,
        modules,
        Some(crate::inspect_system::CompleteMemberScan::scripted(
            scene.generation.clone(),
            at,
            at + 1
        ))
    ));
}

fn round4_settle_ownership(ownership: &mut CountOwnership, scene: &Scene) {
    for _ in 0..128 {
        let mut budget = RecoveryWorkBudget::new();
        ownership.advance(
            &scene.native.scene.coordinator.attach_set,
            &scene.native.scene.coordinator.registry,
            &mut budget,
        );
        assert!(budget.visited <= 128 && budget.queries <= 4);
    }
}

fn round4_b_key(scene: &Scene) -> ModuleKey {
    scene
        .native
        .scene
        .coordinator
        .registry
        .modules()
        .find(|module| module.paths.iter().any(|path| path.ends_with("b.so")))
        .unwrap()
        .key
        .clone()
}

fn round4_a_key(scene: &Scene) -> ModuleKey {
    scene
        .native
        .scene
        .coordinator
        .registry
        .modules()
        .find(|module| module.paths.iter().any(|path| path.ends_with("a.so")))
        .unwrap()
        .key
        .clone()
}

#[test]
fn demotion_retirement_round4_first_shared_or_unknown_cannot_keep_initial_checkpoint() {
    for shared in [false, true] {
        let scene = Scene::shared();
        let coordinator = &scene.native.scene.coordinator;
        let object = scene.native.scene.delta.endpoints[0].object.index();
        let mut ownership = CountOwnership::new(coordinator.registry.limits());
        assert!(ownership.register_pair(scene.caller, object));
        let original = ownership
            .ordinary_view(scene.caller, object)
            .checkpoint(1_000);
        assert_ne!(original, 0);
        let modules = if shared {
            coordinator
                .registry
                .modules()
                .map(|module| module.key.clone())
                .collect()
        } else {
            Vec::new()
        };
        round4_queue_ownership(&mut ownership, &scene, modules, 300);
        // Unknown is reconsidered on later summary visits. End at an actual
        // completed intersection instead of at an arbitrary full-budget turn.
        for _ in 0..128 {
            let mut budget = RecoveryWorkBudget::new();
            budget.limit_visits(5);
            ownership.advance(&coordinator.attach_set, &coordinator.registry, &mut budget);
            assert!(budget.visited <= 5 && budget.queries == 0);
            if ownership.newest_accepted_post(scene.caller) == 301
                && !ownership.deferred(scene.caller, object)
            {
                break;
            }
        }
        assert_eq!(ownership.newest_accepted_post(scene.caller), 301);
        assert!(!ownership.deferred(scene.caller, object));
        assert!(if shared {
            matches!(
                ownership.candidates(scene.caller, object),
                CurrentCandidates::Shared
            )
        } else {
            matches!(
                ownership.candidates(scene.caller, object),
                CurrentCandidates::Unknown
            )
        });
        assert_ne!(
            ownership.ordinary_sequence(scene.caller, object),
            original,
            "the first completed non-sole result must revoke startup continuity"
        );
        round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 400);
        round4_settle_ownership(&mut ownership, &scene);
        assert!(ownership.sole(scene.caller, object).is_some());
        assert_ne!(
            ownership.ordinary_view(scene.caller, object).sequence,
            original
        );
    }
}

#[test]
fn demotion_retirement_revision_skew_unknown_keeps_ordinary_checkpoint() {
    let mut scene = round4_placed_with_known_b();
    let object = scene.native.scene.delta.endpoints[0].object.index();
    let mut ownership = CountOwnership::new(scene.native.scene.coordinator.registry.limits());
    assert!(ownership.register_pair(scene.caller, object));
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 200);
    round4_settle_ownership(&mut ownership, &scene);
    assert!(ownership.sole(scene.caller, object).is_some());
    let original = ownership
        .ordinary_view(scene.caller, object)
        .checkpoint(1_000);
    assert_ne!(original, 0);
    assert_eq!(ownership.ordinary_sequence(scene.caller, object), original);
    // A new endpoint on another object bumps the attach count revision, so
    // the membership index rebuilds under a revision the active scan does
    // not carry: the summary can only finish an unproven Unknown (the
    // revision-skew classification the joint lane hits during attach drain).
    let grown = fx::lower_named(
        &[fx::module_with_targets(
            &scene.pins,
            &scene.b,
            &[(&scene.a, 0x1000), (&scene.b, 0x2000)],
        )],
        &scene.pins,
        crate::plan::AdmissionPolicy::Inventory(scene.native.scene.coordinator.attach_set.budget()),
    );
    scene
        .native
        .scene
        .coordinator
        .attach_set
        .absorb(&grown, &scene.pins);
    round4_settle_ownership(&mut ownership, &scene);
    assert!(
        matches!(
            ownership.candidates(scene.caller, object),
            CurrentCandidates::Unknown
        ),
        "the stale-revision scan serves no current candidate"
    );
    assert_eq!(
        ownership.ordinary_sequence(scene.caller, object),
        original,
        "an unproven revision-skew Unknown must not revoke ordinary continuity"
    );
    assert_eq!(
        ownership.last_cause(scene.caller, object),
        RevocationCause::MembersFilter,
        "the retained finish still names its leg for diagnostics"
    );
    assert_eq!(
        ownership.revocation_cause(scene.caller, object),
        RevocationCause::None,
        "a retained finish records no revocation"
    );
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 400);
    round4_settle_ownership(&mut ownership, &scene);
    assert!(ownership.sole(scene.caller, object).is_some());
    assert_eq!(
        ownership.ordinary_view(scene.caller, object).sequence,
        original,
        "the returning same-carrier Sole resumes on the original checkpoint"
    );
}

#[test]
fn demotion_retirement_module_change_across_skew_revokes_checkpoint() {
    let mut scene = Scene::shared();
    let object = scene.native.scene.delta.endpoints[0].object.index();
    let mut ownership = round4_ownership_with_sole(&scene, object);
    let original = ownership
        .ordinary_view(scene.caller, object)
        .checkpoint(1_000);
    assert_ne!(original, 0);
    assert_eq!(ownership.ordinary_sequence(scene.caller, object), original);
    // Probe the premise on a twin slice: the [A,B] window below must
    // genuinely share the counted object, or this twin pins a
    // module-set change rather than the sharing window it claims.
    let mut probe = CountOwnership::new(scene.native.scene.coordinator.registry.limits());
    assert!(probe.register_pair(scene.caller, object));
    round4_queue_ownership(
        &mut probe,
        &scene,
        vec![round4_a_key(&scene), round4_b_key(&scene)],
        100,
    );
    round4_settle_ownership(&mut probe, &scene);
    assert_eq!(probe.newest_accepted_post(scene.caller), 101);
    assert!(
        matches!(
            probe.candidates(scene.caller, object),
            CurrentCandidates::Shared
        ),
        "the [A,B] window must share the counted object"
    );
    // A second module sharing the counted object arrives, but its [A,B]
    // scan is queued under a membership revision the attach set outgrows
    // before classification runs: the [A,B] window is never classified,
    // so the unproven members-filter finish must revoke instead of
    // retaining the proven sole-owner checkpoint across a module-set
    // change it never examined.
    round4_queue_ownership(
        &mut ownership,
        &scene,
        vec![round4_a_key(&scene), round4_b_key(&scene)],
        300,
    );
    round4_grow_attach_revision(&mut scene);
    round4_settle_ownership(&mut ownership, &scene);
    assert_eq!(
        ownership.newest_accepted_post(scene.caller),
        301,
        "the [A,B] observation is accepted and moves the caller epoch"
    );
    assert_eq!(
        ownership.last_cause(scene.caller, object),
        RevocationCause::MembersFilter,
        "the [A,B] scan finishes on the revision-skew leg"
    );
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 400);
    round4_settle_ownership(&mut ownership, &scene);
    assert!(ownership.sole(scene.caller, object).is_some());
    assert_ne!(
        ownership.ordinary_view(scene.caller, object).sequence,
        original,
        "growth across an unclassified module-set change needs a new fence, not the old checkpoint"
    );
}

#[test]
fn demotion_retirement_module_swap_across_skew_revokes_checkpoint() {
    let mut scene = round4_placed_with_known_b();
    let object = scene.native.scene.delta.endpoints[0].object.index();
    let mut ownership = round4_ownership_with_sole(&scene, object);
    let original = ownership
        .ordinary_view(scene.caller, object)
        .checkpoint(1_000);
    assert_ne!(original, 0);
    assert_eq!(ownership.ordinary_sequence(scene.caller, object), original);
    // A same-length module swap ([A] -> [B]) is a different module
    // list even though the length and the process generation match:
    // the swapped scan moves the caller epoch. Queued under a
    // membership revision the attach set outgrows before
    // classification runs, the [B] window is never classified, so the
    // unproven members-filter finish must revoke instead of retaining
    // the proven sole-owner checkpoint across a module-set change it
    // never examined.
    round4_queue_ownership(&mut ownership, &scene, vec![round4_b_key(&scene)], 300);
    round4_grow_attach_revision(&mut scene);
    round4_settle_ownership(&mut ownership, &scene);
    assert_eq!(
        ownership.newest_accepted_post(scene.caller),
        301,
        "the [B] observation is accepted and moves the caller epoch"
    );
    assert_eq!(
        ownership.last_cause(scene.caller, object),
        RevocationCause::MembersFilter,
        "the [B] scan finishes on the revision-skew leg"
    );
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 400);
    round4_settle_ownership(&mut ownership, &scene);
    assert!(ownership.sole(scene.caller, object).is_some());
    assert_ne!(
        ownership.ordinary_view(scene.caller, object).sequence,
        original,
        "growth across an unclassified same-length swap needs a new fence, not the old checkpoint"
    );
}

#[test]
fn demotion_retirement_in_place_rewrite_unknown_revokes_checkpoint() {
    let mut scene = round4_placed_with_known_b();
    let object = scene.native.scene.delta.endpoints[0].object.index();
    let mut ownership = round4_ownership_with_sole(&scene, object);
    let original = ownership
        .ordinary_view(scene.caller, object)
        .checkpoint(1_000);
    assert_ne!(original, 0);
    assert_eq!(ownership.ordinary_sequence(scene.caller, object), original);
    // The provider file is rewritten in place: same inode, new bytes and
    // digest. The attach set marks the retained object changed, so its
    // membership entry reads unknown — a proven revocation, never a
    // retained checkpoint.
    std::fs::write(&scene.a, "provider-a-v2-longer").unwrap();
    let repinned = fx::pass_pins(&[(&scene.a, "sha-a2")]);
    let rewritten = fx::lower_named(
        std::slice::from_ref(&fx::module_with_targets(
            &repinned,
            &scene.a,
            &[(&scene.a, 0x1000)],
        )),
        &repinned,
        crate::plan::AdmissionPolicy::Inventory(scene.native.scene.coordinator.attach_set.budget()),
    );
    let outcome = scene
        .native
        .scene
        .coordinator
        .attach_set
        .absorb(&rewritten, &repinned);
    assert!(
        outcome
            .gaps
            .iter()
            .any(|gap| gap.subject == crate::discovery::inventory_attach_set::CHANGED_SUBJECT),
        "the rewritten provider must mark its object changed: {:?}",
        outcome.gaps
    );
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 400);
    round4_settle_ownership(&mut ownership, &scene);
    assert_eq!(
        ownership.last_cause(scene.caller, object),
        RevocationCause::MembersFilter,
        "the unknown members entry finishes on the members-filter leg"
    );
    assert_eq!(
        ownership.revocation_cause(scene.caller, object),
        RevocationCause::MembersFilter,
        "an unknown members entry revokes ordinary continuity"
    );
    assert_ne!(
        ownership.ordinary_sequence(scene.caller, object),
        original,
        "growth across a changed provider file needs a new fence, not the old checkpoint"
    );
}

#[test]
fn demotion_retirement_proven_absence_revokes_ordinary_checkpoint() {
    let scene = round4_placed_with_known_b();
    let object = scene.native.scene.delta.endpoints[0].object.index();
    let mut ownership = CountOwnership::new(scene.native.scene.coordinator.registry.limits());
    assert!(ownership.register_pair(scene.caller, object));
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 200);
    round4_settle_ownership(&mut ownership, &scene);
    assert!(ownership.sole(scene.caller, object).is_some());
    let original = ownership
        .ordinary_view(scene.caller, object)
        .checkpoint(1_000);
    assert_ne!(original, 0);
    // A complete observation whose modules intersect no member of the
    // object proves the carrier absent: continuity must still revoke.
    round4_queue_ownership(&mut ownership, &scene, Vec::new(), 300);
    round4_settle_ownership(&mut ownership, &scene);
    assert_ne!(
        ownership.ordinary_sequence(scene.caller, object),
        original,
        "a proven absence must revoke ordinary continuity"
    );
    assert_eq!(
        ownership.revocation_cause(scene.caller, object),
        RevocationCause::ProvenAbsence,
        "the revocation names the proven-absence leg for diagnostics"
    );
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 400);
    round4_settle_ownership(&mut ownership, &scene);
    assert!(ownership.sole(scene.caller, object).is_some());
    assert_ne!(
        ownership.ordinary_view(scene.caller, object).sequence,
        original,
        "growth across a proven absence needs a new fence, not the old checkpoint"
    );
}

fn round4_queue_ownership_same_pass(
    ownership: &mut CountOwnership,
    scene: &Scene,
    mut modules: Vec<ModuleKey>,
    at: u64,
) {
    modules.sort();
    ownership.invalidate_memberships(scene.native.scene.coordinator.attach_set.count_revision());
    assert!(ownership.queue_observation(
        scene.caller,
        modules,
        Some(crate::inspect_system::CompleteMemberScan::scripted(
            scene.generation.clone(),
            at,
            at + 1
        ))
    ));
}

fn round4_ownership_with_sole(scene: &Scene, object: u32) -> CountOwnership {
    let mut ownership = CountOwnership::new(scene.native.scene.coordinator.registry.limits());
    assert!(ownership.register_pair(scene.caller, object));
    round4_queue_ownership(&mut ownership, scene, vec![round4_a_key(scene)], 200);
    round4_settle_ownership(&mut ownership, scene);
    assert!(ownership.sole(scene.caller, object).is_some());
    ownership
}

#[test]
fn demotion_retirement_missing_pass_unknown_keeps_ordinary_checkpoint() {
    let scene = round4_placed_with_known_b();
    let object = scene.native.scene.delta.endpoints[0].object.index();
    let mut ownership = round4_ownership_with_sole(&scene, object);
    let original = ownership
        .ordinary_view(scene.caller, object)
        .checkpoint(1_000);
    assert_ne!(original, 0);
    // The caller misses one catalog pass entirely: no observation, no
    // failure recorded. The summary can only finish an unproven Unknown
    // on the invalid-slot leg, which retains ordinary continuity while
    // serving no current candidate.
    ownership.begin_catalog_pass();
    round4_settle_ownership(&mut ownership, &scene);
    assert!(matches!(
        ownership.candidates(scene.caller, object),
        CurrentCandidates::Unknown
    ));
    assert_eq!(
        ownership.ordinary_sequence(scene.caller, object),
        original,
        "a missing pass with no failure must not revoke ordinary continuity"
    );
    assert_eq!(
        ownership.last_cause(scene.caller, object),
        RevocationCause::InvalidSlot,
        "the retained finish still names its leg for diagnostics"
    );
    assert_eq!(
        ownership.revocation_cause(scene.caller, object),
        RevocationCause::None,
        "a retained finish records no revocation"
    );
    // Returning in the same pass resumes on the original checkpoint.
    round4_queue_ownership_same_pass(&mut ownership, &scene, vec![round4_a_key(&scene)], 400);
    round4_settle_ownership(&mut ownership, &scene);
    assert!(ownership.sole(scene.caller, object).is_some());
    assert_eq!(
        ownership.ordinary_view(scene.caller, object).sequence,
        original,
        "the returning same-carrier Sole resumes on the original checkpoint"
    );
}

#[test]
fn demotion_retirement_missing_pass_then_proven_absence_revokes_checkpoint() {
    let scene = round4_placed_with_known_b();
    let object = scene.native.scene.delta.endpoints[0].object.index();
    let mut ownership = round4_ownership_with_sole(&scene, object);
    let original = ownership
        .ordinary_view(scene.caller, object)
        .checkpoint(1_000);
    assert_ne!(original, 0);
    ownership.begin_catalog_pass();
    round4_settle_ownership(&mut ownership, &scene);
    assert_eq!(
        ownership.ordinary_sequence(scene.caller, object),
        original,
        "the missing pass itself retains ordinary continuity"
    );
    assert_eq!(
        ownership.last_cause(scene.caller, object),
        RevocationCause::InvalidSlot
    );
    // A later complete observation without the carrier proves absence:
    // the retained checkpoint must still revoke rather than resume.
    round4_queue_ownership_same_pass(&mut ownership, &scene, Vec::new(), 300);
    round4_settle_ownership(&mut ownership, &scene);
    assert_ne!(
        ownership.ordinary_sequence(scene.caller, object),
        original,
        "a proven absence after a retained missing pass must revoke continuity"
    );
    assert_eq!(
        ownership.revocation_cause(scene.caller, object),
        RevocationCause::ProvenAbsence
    );
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 400);
    round4_settle_ownership(&mut ownership, &scene);
    assert!(ownership.sole(scene.caller, object).is_some());
    assert_ne!(
        ownership.ordinary_view(scene.caller, object).sequence,
        original,
        "growth across the proven absence needs a new fence, not the old checkpoint"
    );
}

fn round4_note_a_double_loaded(scene: &mut Scene, double_loaded: bool) {
    use crate::discovery::caller_registry::{AdmissionState, ModuleInfo};
    let key = round4_a_key(scene);
    scene.native.scene.coordinator.registry.note_mapping(
        scene.caller,
        7,
        ModuleInfo {
            path: scene.a.to_string_lossy().into_owned(),
            key: key.clone(),
            double_loaded,
            build_id: None,
            identity_source: Some("mountinfo".into()),
            admission: AdmissionState::Admitted,
            admission_class: Some("exact".into()),
            admission_endpoints: Some(1),
            admission_reasons: Vec::new(),
        },
        400,
    );
    scene.native.scene.coordinator.registry.publish();
    let id = scene
        .native
        .scene
        .coordinator
        .registry
        .module_id_for(&key)
        .expect("published carrier module");
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .registry
            .edge(scene.caller, id)
            .expect("carrier edge")
            .double_loaded,
        double_loaded,
        "the mapping note deterministically sets the carrier edge latch"
    );
}

fn round4_grow_attach_revision(scene: &mut Scene) {
    let grown = fx::lower_named(
        &[fx::module_with_targets(
            &scene.pins,
            &scene.b,
            &[(&scene.a, 0x1000), (&scene.b, 0x2000)],
        )],
        &scene.pins,
        crate::plan::AdmissionPolicy::Inventory(scene.native.scene.coordinator.attach_set.budget()),
    );
    scene
        .native
        .scene
        .coordinator
        .attach_set
        .absorb(&grown, &scene.pins);
}

#[test]
fn demotion_retirement_double_loaded_edge_unknown_keeps_ordinary_checkpoint() {
    let mut scene = round4_placed_with_known_b();
    let object = scene.native.scene.delta.endpoints[0].object.index();
    let mut ownership = round4_ownership_with_sole(&scene, object);
    let original = ownership
        .ordinary_view(scene.caller, object)
        .checkpoint(1_000);
    assert_ne!(original, 0);
    // A new membership revision forces reclassification, and the carrier
    // edge is double-loaded: the summary can only finish an unproven
    // Unknown on the invalid-edge leg, which retains ordinary
    // continuity while serving no current candidate.
    round4_grow_attach_revision(&mut scene);
    round4_note_a_double_loaded(&mut scene, true);
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 300);
    round4_settle_ownership(&mut ownership, &scene);
    assert!(matches!(
        ownership.candidates(scene.caller, object),
        CurrentCandidates::Unknown
    ));
    assert_eq!(
        ownership.last_cause(scene.caller, object),
        RevocationCause::InvalidEdge,
        "the retained finish names the invalid-edge leg for diagnostics"
    );
    assert_eq!(
        ownership.ordinary_sequence(scene.caller, object),
        original,
        "an unproven invalid-edge Unknown must not revoke ordinary continuity"
    );
    assert_eq!(
        ownership.revocation_cause(scene.caller, object),
        RevocationCause::None
    );
    // Unlatching the edge resumes the same carrier on the checkpoint.
    round4_note_a_double_loaded(&mut scene, false);
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 400);
    round4_settle_ownership(&mut ownership, &scene);
    assert!(ownership.sole(scene.caller, object).is_some());
    assert_eq!(
        ownership.ordinary_view(scene.caller, object).sequence,
        original,
        "the returning same-carrier Sole resumes on the original checkpoint"
    );
}

#[test]
fn demotion_retirement_double_loaded_edge_then_proven_absence_revokes_checkpoint() {
    let mut scene = round4_placed_with_known_b();
    let object = scene.native.scene.delta.endpoints[0].object.index();
    let mut ownership = round4_ownership_with_sole(&scene, object);
    let original = ownership
        .ordinary_view(scene.caller, object)
        .checkpoint(1_000);
    assert_ne!(original, 0);
    round4_grow_attach_revision(&mut scene);
    round4_note_a_double_loaded(&mut scene, true);
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 300);
    round4_settle_ownership(&mut ownership, &scene);
    assert_eq!(
        ownership.last_cause(scene.caller, object),
        RevocationCause::InvalidEdge
    );
    assert_eq!(
        ownership.ordinary_sequence(scene.caller, object),
        original,
        "the invalid-edge finish itself retains ordinary continuity"
    );
    // A later complete observation without the carrier proves absence:
    // the retained checkpoint must still revoke rather than resume.
    round4_note_a_double_loaded(&mut scene, false);
    round4_queue_ownership(&mut ownership, &scene, Vec::new(), 400);
    round4_settle_ownership(&mut ownership, &scene);
    assert_ne!(
        ownership.ordinary_sequence(scene.caller, object),
        original,
        "a proven absence after a retained invalid-edge finish must revoke continuity"
    );
    assert_eq!(
        ownership.revocation_cause(scene.caller, object),
        RevocationCause::ProvenAbsence
    );
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 500);
    round4_settle_ownership(&mut ownership, &scene);
    assert!(ownership.sole(scene.caller, object).is_some());
    assert_ne!(
        ownership.ordinary_view(scene.caller, object).sequence,
        original,
        "growth across the proven absence needs a new fence, not the old checkpoint"
    );
}

#[test]
fn demotion_retirement_fresh_first_finish_skew_revokes_initial_checkpoint() {
    let mut scene = round4_placed_with_known_b();
    let object = scene.native.scene.delta.endpoints[0].object.index();
    let mut ownership = CountOwnership::new(scene.native.scene.coordinator.registry.limits());
    assert!(ownership.register_pair(scene.caller, object));
    let original = ownership
        .ordinary_view(scene.caller, object)
        .checkpoint(1_000);
    assert_ne!(original, 0);
    // The pair's first scan is queued under the current membership
    // revision, but the attach set grows before any classification
    // runs, so the first finish is an unproven revision-skew Unknown.
    // A fresh summary has no proven Sole to retain: the initial
    // checkpoint revokes (fail-closed), and growth fences into exact
    // named gaps at first Sole service instead of resuming ordinary.
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 200);
    round4_grow_attach_revision(&mut scene);
    round4_settle_ownership(&mut ownership, &scene);
    assert!(matches!(
        ownership.candidates(scene.caller, object),
        CurrentCandidates::Unknown
    ));
    assert_eq!(
        ownership.last_cause(scene.caller, object),
        RevocationCause::MembersFilter,
        "the first finish is the revision-skew leg"
    );
    assert_ne!(
        ownership.ordinary_sequence(scene.caller, object),
        original,
        "a fresh pair's first unproven finish still revokes the initial checkpoint"
    );
    assert_eq!(
        ownership.revocation_cause(scene.caller, object),
        RevocationCause::MembersFilter
    );
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 400);
    round4_settle_ownership(&mut ownership, &scene);
    assert!(ownership.sole(scene.caller, object).is_some());
    assert_ne!(
        ownership.ordinary_view(scene.caller, object).sequence,
        original,
        "growth across the first-finish skew fences instead of resuming ordinary"
    );
}

#[test]
fn demotion_retirement_fresh_summary_staging_after_accepted_scan_keeps_checkpoint() {
    let scene = round4_placed_with_known_b();
    let object = scene.native.scene.delta.endpoints[0].object.index();
    let mut ownership = CountOwnership::new(scene.native.scene.coordinator.registry.limits());
    // A catalog scan for this caller is accepted (POST 201) before the
    // pair's first count stages: no summary exists yet, so no completed
    // classification can have revoked continuity. Live joint cells stage
    // the driver's setup count exactly here; taking checkpoint 0 fences
    // all later steady sole growth at the first Sole service.
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 200);
    round4_settle_ownership(&mut ownership, &scene);
    assert_eq!(ownership.newest_accepted_post(scene.caller), 201);
    assert!(ownership.register_pair(scene.caller, object));
    let checkpoint = ownership
        .ordinary_view(scene.caller, object)
        .checkpoint(150);
    assert_eq!(
        checkpoint, 1,
        "a fresh summary with no completed classification keeps the initial checkpoint"
    );
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 400);
    round4_settle_ownership(&mut ownership, &scene);
    assert!(ownership.sole(scene.caller, object).is_some());
    assert_eq!(
        ownership.ordinary_view(scene.caller, object).sequence,
        checkpoint,
        "the returning same-carrier Sole resumes on the fresh checkpoint"
    );
    assert_eq!(
        ownership.revocation_cause(scene.caller, object),
        RevocationCause::None
    );
}

#[test]
fn demotion_retirement_fresh_summary_after_replaced_scan_takes_no_checkpoint() {
    let scene = Scene::shared();
    let object = scene.native.scene.delta.endpoints[0].object.index();
    // Probe the premise on a twin slice: both modules target (A,0x1000)
    // in this scene, so [A,B] is truly Shared for endpoints[0]. The
    // replaced pre-registration scan below therefore stages a real
    // transient-Shared window, not a Sole-to-Sole swap.
    let mut probe = CountOwnership::new(scene.native.scene.coordinator.registry.limits());
    assert!(probe.register_pair(scene.caller, object));
    round4_queue_ownership(
        &mut probe,
        &scene,
        vec![round4_a_key(&scene), round4_b_key(&scene)],
        100,
    );
    round4_settle_ownership(&mut probe, &scene);
    assert_eq!(probe.newest_accepted_post(scene.caller), 101);
    assert!(matches!(
        probe.candidates(scene.caller, object),
        CurrentCandidates::Shared
    ));
    let mut ownership = CountOwnership::new(scene.native.scene.coordinator.registry.limits());
    // Before the pair registers, an accepted scan proving both carriers
    // (Shared for this object, pinned by the probe above) is replaced by
    // an accepted Sole scan. The fresh summary will only ever classify
    // the Sole scan; the replaced Shared scan is gone, so growth whose
    // read predates it crosses a proven-transient Shared window and must
    // fence into exact named gaps, not resume ordinary on the initial
    // checkpoint.
    round4_queue_ownership(
        &mut ownership,
        &scene,
        vec![round4_a_key(&scene), round4_b_key(&scene)],
        100,
    );
    round4_settle_ownership(&mut ownership, &scene);
    assert_eq!(ownership.newest_accepted_post(scene.caller), 101);
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 200);
    round4_settle_ownership(&mut ownership, &scene);
    assert_eq!(ownership.newest_accepted_post(scene.caller), 201);
    assert!(ownership.register_pair(scene.caller, object));
    let view = ownership.ordinary_view(scene.caller, object);
    assert_eq!(
        view.checkpoint(50),
        0,
        "a replaced pre-registration scan cannot be skipped by the fresh-summary bypass"
    );
    assert_eq!(
        view.checkpoint(250),
        view.sequence,
        "a read after the newest accepted POST still keeps the sequence"
    );
    assert_ne!(view.sequence, 0);
}

#[test]
fn demotion_retirement_equal_replacement_before_registration_keeps_fresh_bypass() {
    let mut scene = round4_placed_with_known_b();
    let object = scene.native.scene.delta.endpoints[0].object.index();
    let mut ownership = CountOwnership::new(scene.native.scene.coordinator.registry.limits());
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 100);
    round4_settle_ownership(&mut ownership, &scene);
    assert_eq!(ownership.newest_accepted_post(scene.caller), 101);
    // A new endpoint on another object bumps the attach count revision,
    // so the second [A] scan arrives under a new membership revision. It
    // carries the same modules and generation, so the equal branch swaps
    // the receipt without replacing ownership evidence or counting.
    let grown = fx::lower_named(
        &[fx::module_with_targets(
            &scene.pins,
            &scene.b,
            &[(&scene.b, 0x1000), (&scene.b, 0x2000)],
        )],
        &scene.pins,
        crate::plan::AdmissionPolicy::Inventory(scene.native.scene.coordinator.attach_set.budget()),
    );
    scene
        .native
        .scene
        .coordinator
        .attach_set
        .absorb(&grown, &scene.pins);
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 200);
    round4_settle_ownership(&mut ownership, &scene);
    assert_eq!(
        ownership.newest_accepted_post(scene.caller),
        201,
        "the equal scan is accepted under the new revision"
    );
    assert_eq!(
        ownership
            .supporting_scan(scene.caller)
            .map(|scan| scan.finished_ns()),
        Some(201),
        "the equal branch swaps the active receipt to the new scan"
    );
    assert!(ownership.register_pair(scene.caller, object));
    let view = ownership.ordinary_view(scene.caller, object);
    assert_eq!(
        view.checkpoint(50),
        view.sequence,
        "an equal pre-registration replacement keeps the fresh-summary bypass"
    );
    assert_ne!(view.sequence, 0);
}

#[test]
fn demotion_retirement_finished_summary_old_read_cannot_borrow_current_sequence() {
    let scene = round4_placed_with_known_b();
    let object = scene.native.scene.delta.endpoints[0].object.index();
    let mut ownership = CountOwnership::new(scene.native.scene.coordinator.registry.limits());
    assert!(ownership.register_pair(scene.caller, object));
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 200);
    round4_settle_ownership(&mut ownership, &scene);
    assert!(ownership.sole(scene.caller, object).is_some());
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 400);
    round4_settle_ownership(&mut ownership, &scene);
    assert_eq!(ownership.newest_accepted_post(scene.caller), 401);
    let view = ownership.ordinary_view(scene.caller, object);
    assert_eq!(
        view.checkpoint(300),
        0,
        "a finished summary's old read still cannot borrow the current sequence"
    );
    assert_eq!(
        view.checkpoint(500),
        view.sequence,
        "a read after the newest accepted POST keeps the sequence"
    );
    assert_ne!(view.sequence, 0);
}

#[test]
fn demotion_retirement_round4_failed_caller_source_survives_lagging_summary() {
    let scene = round4_placed_with_known_b();
    let object = scene.native.scene.delta.endpoints[0].object.index();
    let mut ownership = CountOwnership::new(scene.native.scene.coordinator.registry.limits());
    assert!(ownership.register_pair(scene.caller, object));
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 200);
    round4_settle_ownership(&mut ownership, &scene);
    let original = ownership
        .ordinary_view(scene.caller, object)
        .checkpoint(1_000);
    assert_ne!(original, 0);
    ownership.begin_catalog_pass();
    assert!(ownership.queue_observation(scene.caller, Vec::new(), None));
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 400);
    assert_eq!(
        ownership.ordinary_sequence(scene.caller, object),
        original,
        "no summary service occurred during the source failure"
    );
    assert_eq!(ownership.ordinary_view(scene.caller, object).sequence, 0);
    round4_settle_ownership(&mut ownership, &scene);
    assert!(ownership.sole(scene.caller, object).is_some());
    assert_ne!(
        ownership.ordinary_view(scene.caller, object).sequence,
        original,
        "returning A must consume the sticky failure before replacing its old provenance"
    );
}

#[test]
fn demotion_retirement_round4_index_refusal_survives_rebuild_before_summary_service() {
    let mut scene = round4_placed_with_known_b();
    let object = scene.native.scene.delta.endpoints[0].object.index();
    let mut limits = scene.native.scene.coordinator.registry.limits();
    limits.max_edges = 12;
    let mut ownership = CountOwnership::new(limits);
    assert!(ownership.register_pair(scene.caller, object));
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 200);
    round4_settle_ownership(&mut ownership, &scene);
    let original = ownership
        .ordinary_view(scene.caller, object)
        .checkpoint(1_000);
    assert_ne!(original, 0);

    let extras = (0..8)
        .map(|index| {
            fx::provider(
                &scene.native.scene._dir,
                &format!("extra-{index}.so"),
                "additional provider",
            )
        })
        .collect::<Vec<_>>();
    let mut inputs = vec![(scene.a.as_path(), "sha-a"), (scene.b.as_path(), "sha-b")];
    inputs.extend(extras.iter().map(|path| (path.as_path(), "sha-extra")));
    let pins = fx::pass_pins(&inputs);
    let policy =
        crate::plan::AdmissionPolicy::Inventory(scene.native.scene.coordinator.attach_set.budget());
    let grown = fx::lower_named(
        &extras
            .iter()
            .map(|path| fx::module_with_targets(&pins, path, &[(&scene.a, 0x1000)]))
            .collect::<Vec<_>>(),
        &pins,
        policy,
    );
    scene
        .native
        .scene
        .coordinator
        .attach_set
        .absorb(&grown, &pins);
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 300);
    // Real bounded page processing can encounter the cap before any summary
    // turn. Four visits are too few to enter summary service, not a cursor edit.
    for _ in 0..128 {
        let mut budget = RecoveryWorkBudget::new();
        budget.limit_visits(4);
        ownership.advance(
            &scene.native.scene.coordinator.attach_set,
            &scene.native.scene.coordinator.registry,
            &mut budget,
        );
        assert!(budget.visited <= 4);
        if ownership.index_failure() != 0 {
            break;
        }
    }
    assert_ne!(
        ownership.index_failure(),
        0,
        "real membership capacity refusal"
    );
    assert_eq!(
        ownership.ordinary_sequence(scene.caller, object),
        original,
        "the old Sole summary must still be unserviced at the failure"
    );
    let shrunk = fx::lower_named(
        &extras
            .iter()
            .map(|path| fx::module(&pins, path, &[]))
            .collect::<Vec<_>>(),
        &pins,
        policy,
    );
    scene
        .native
        .scene
        .coordinator
        .attach_set
        .absorb(&shrunk, &pins);
    round4_queue_ownership(&mut ownership, &scene, vec![round4_a_key(&scene)], 400);
    round4_settle_ownership(&mut ownership, &scene);
    assert!(
        ownership.sole(scene.caller, object).is_some(),
        "a healthy smaller index must recover"
    );
    assert_ne!(
        ownership.ordinary_view(scene.caller, object).sequence,
        original,
        "the replaced refused index cannot restore the original ordinary checkpoint"
    );
}

#[test]
fn demotion_retirement_round4_rejected_first_placement_retains_bounded_summary() {
    let mut scene = Scene::shared();
    scene.native.scene.source.spawn(8, 508);
    let caller = scene
        .native
        .scene
        .coordinator
        .adapter
        .admit(8, ImageAuthority::ScanPinned, 80)
        .unwrap();
    let mut catalog = members_catalog(
        &scene,
        &[(7, scene.caller, 41), (8, caller, 108)],
        true,
        250,
    );
    for process in &mut catalog.processes {
        process.complete_scan = None;
    }
    scene.apply(catalog, 250);
    let before = scene
        .native
        .scene
        .coordinator
        .count_ownership
        .retained_cells()
        .2;
    scene.native.answer(8, 508, 108);
    let mut row = scene.native.row(108, 1, 8, 300, 0);
    row.entry_count = 5;
    let key = PairKey::of(&row);
    scene.native.witness(vec![row]);
    assert!(
        matches!(
            scene.native.scene.coordinator.pair_targets.get(&key),
            Some(PairTarget::Dropped { base: 5, .. })
        ),
        "the real shared first request must reject"
    );
    assert!(!scene.native.scene.coordinator.recoveries.contains_key(&key));
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .count_ownership
            .retained_cells()
            .2,
        before + 1,
        "registration/tombstones count even when the first historical placement rejects"
    );
    for _ in 0..16 {
        scene.horizons();
    }
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .count_ownership
            .retained_cells()
            .2,
        before + 1
    );
}

#[test]
fn demotion_retirement_round3_three_slot_movement_and_mixed_revocation_are_bounded() {
    let receipts = WorkReceipts::begin();
    let (mut scene, members) = round3_more_members();
    for &(pid, _, _) in &members {
        scene.native.unavailable_answer(pid, 500 + u64::from(pid));
    }
    // pid7's fixture start is500, not507.
    scene.native.unavailable_answer(7, 500);
    scene.apply(members_catalog(&scene, &members, true, 200), 200);
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 7))
            .collect(),
    );
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    scene.apply(members_catalog(&scene, &members, false, 300), 300);
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 8))
            .collect(),
    );
    scene.apply(members_catalog(&scene, &members, true, 350), 350);
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 9))
            .collect(),
    );
    assert!(
        scene
            .native
            .scene
            .coordinator
            .recoveries
            .values()
            .any(|recovery| recovery
                .pending_reads
                .iter()
                .flatten()
                .any(|tag| tag.read.count == 9 && tag.scan.started_ns() == 350)),
        "actual new waiting receipt retains its original read during movement"
    );
    let old_receipts = round3_receipts(&scene);
    round3_assert_slots(&scene);
    receipts.assert_bounded();
    // Replace a genuinely different waiting observation, before pair service
    // can settle every original S300. This is the separately classified mixed
    // interval case, not a rescue rescan of either original isolated RED.
    scene.apply(members_catalog(&scene, &members, false, 400), 400);
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 10))
            .collect(),
    );
    for _ in 0..80 {
        scene.horizons();
        round3_assert_slots(&scene);
        receipts.assert_bounded();
    }
    // Dropping an unexamined waiting scan does not prove a competing epoch.
    // Depending on actual bounded comparison order, a retained S300/read8 or
    // the new S400/read10 may qualify; detached9 supplies neither boundary.
    for recovery in scene.native.scene.coordinator.recoveries.values() {
        let read = recovery
            .fence
            .expect("actual full source/read survives classification");
        assert!(
            matches!(read.count, 8 | 10),
            "discarded scalar9 cannot supply a fence"
        );
        assert_eq!(
            recovery.scan.as_ref().unwrap().started_ns(),
            if read.count == 8 { 300 } else { 400 }
        );
        assert!(recovery.sighting.is_none());
    }
    for &(pid, _, ticket) in &members {
        scene.native.answer(
            pid,
            if pid == 7 { 500 } else { 500 + u64::from(pid) },
            ticket,
        );
    }
    for _ in 0..40 {
        scene.horizons();
        receipts.assert_bounded();
    }
    for recovery in scene.native.scene.coordinator.recoveries.values() {
        assert_eq!(edge_count(&scene.native, recovery.caller, "a.so"), 5);
        assert_eq!(
            edge_count(&scene.native, recovery.caller, "b.so"),
            10 - recovery.fence.unwrap().count
        );
    }
    assert!(
        old_receipts
            .iter()
            .any(|reference| reference.upgrade().is_none()),
        "obsolete receipt allocations release"
    );
}

#[test]
fn demotion_retirement_round3_later_obsolete_read_keeps_selected_continuation() {
    let receipts = WorkReceipts::begin();
    let (mut scene, members) = round3_more_members();
    scene.apply(members_catalog(&scene, &members, true, 200), 200);
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 7))
            .collect(),
    );
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    scene.apply(members_catalog(&scene, &members, false, 300), 300);
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 8))
            .collect(),
    );
    for _ in 0..80 {
        scene.horizons();
        receipts.assert_bounded();
    }
    assert!(
        scene
            .native
            .scene
            .coordinator
            .recoveries
            .values()
            .all(|recovery| recovery.fence.is_some_and(|read| read.count == 8))
    );
    let original: HashMap<_, _> = scene
        .native
        .scene
        .coordinator
        .recoveries
        .iter()
        .map(|(&key, recovery)| {
            (
                key,
                (
                    recovery.epoch,
                    recovery.fence.unwrap(),
                    recovery.scan.as_ref().unwrap().started_ns(),
                ),
            )
        })
        .collect();
    // Keep B-only processing ahead of an unexamined A+B waiting receipt;
    // replace that waiting receipt after its actual9, preserving validated S300.
    scene.apply(members_catalog(&scene, &members, false, 400), 400);
    scene.apply(members_catalog(&scene, &members, true, 450), 450);
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 9))
            .collect(),
    );
    let waiting_reads = scene
        .native
        .scene
        .coordinator
        .recoveries
        .iter()
        .filter(|(_, recovery)| {
            recovery
                .pending_reads
                .iter()
                .flatten()
                .any(|tag| tag.read.count == 9 && tag.scan.started_ns() == 450)
        })
        .map(|(&key, _)| key)
        .collect::<Vec<_>>();
    assert!(
        !waiting_reads.is_empty(),
        "real unresolved later receipt retains actual9"
    );
    scene.apply(members_catalog(&scene, &members, false, 500), 500);
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 10))
            .collect(),
    );
    for _ in 0..80 {
        scene.horizons();
        round3_assert_slots(&scene);
        receipts.assert_bounded();
    }
    let mut preserved = 0;
    for key in waiting_reads {
        let recovery = &scene.native.scene.coordinator.recoveries[&key];
        let (epoch, fence, started) = original[&key];
        if recovery.epoch != epoch {
            continue;
        } // A actually completed: a genuine new epoch.
        preserved += 1;
        assert_eq!(
            (
                edge_count(&scene.native, recovery.caller, "a.so"),
                edge_count(&scene.native, recovery.caller, "b.so")
            ),
            (5, 2)
        );
        assert_eq!(
            (
                recovery.fence.unwrap().count,
                recovery.fence.unwrap().anchor_ns,
                recovery.fence.unwrap().last_ns
            ),
            (8, fence.anchor_ns, fence.last_ns)
        );
        assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), started);
        assert!(
            !scene
                .native
                .scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .any(|gap| gap.caller == Some(recovery.caller) && gap.reason.contains("(8, 9]")),
            "unexamined obsolete9 cannot consume the surviving valid continuation"
        );
    }
    assert!(
        preserved > 0,
        "an actual dropped waiting receipt must leave a continuing selected epoch"
    );
}

#[test]
fn demotion_retirement_round3_cancellation_preserves_historical_predecessor() {
    for cancellation in 0..3 {
        let receipts = WorkReceipts::begin();
        let mut scene = Scene::placed();
        scene.observe(true, false, 200);
        scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 7)]);
        let key = *scene
            .native
            .scene
            .coordinator
            .recoveries
            .keys()
            .next()
            .unwrap();
        let history = scene
            .native
            .scene
            .coordinator
            .pending_ids
            .iter()
            .map(|(&id, pending)| (id, (pending.observation.count, pending.generation)))
            .collect::<HashMap<_, _>>();
        let catalog = scene.catalog(false, true, 300);
        round3_apply_unpublished(&mut scene, catalog, 300);
        scene.native.unavailable_answer(7, 500);
        scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 8)]);
        scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 10)]);
        match cancellation {
            0 => {
                scene.native.scene.source.kill(7);
                scene.native.scene.coordinator.observe_empty_pass(
                    &mut crate::discovery::engine::inventory::UnavailableImageGuard,
                    &mut scene.native.cookies,
                    "owned exact caller canceled before proof",
                    350,
                );
            }
            1 => {
                scene.native.stage(NativeBatch::Finish {
                    domain: scene.native.domain,
                });
            }
            _ => {
                let catalog = scene.catalog(false, false, 350);
                round3_apply_unpublished(&mut scene, catalog, 350);
            }
        }
        for (&id, &(count, generation)) in &history {
            let pending = scene
                .native
                .scene
                .coordinator
                .pending_ids
                .get(&id)
                .expect("historical handle survives cancellation");
            assert_eq!(
                (pending.observation.count, pending.generation),
                (count, generation)
            );
        }
        scene.native.scene.coordinator.commit_batch(false).unwrap();
        for _ in 0..20 {
            scene.horizons();
            receipts.assert_bounded();
        }
        assert_eq!(scene.counts(), (5, 0));
        let recovery = &scene.native.scene.coordinator.recoveries[&key];
        assert!(
            recovery.fence.is_none()
                && recovery.sighting.is_none()
                && recovery.pending_reads.iter().all(Option::is_none)
        );
        assert!(!recovery.recovered);
        let gaps = scene.native.scene.coordinator.registry.gaps().len();
        scene.native.scene.coordinator.commit_batch(false).unwrap();
        scene.horizons();
        assert_eq!(
            scene.native.scene.coordinator.registry.gaps().len(),
            gaps,
            "no duplicate historical disclosure"
        );
    }
}

#[test]
fn demotion_retirement_round3_predecessor_decision_order_and_replay_are_immutable() {
    for reverse in [false, true] {
        let receipts = WorkReceipts::begin();
        let mut scene = Scene::placed();
        scene.observe(true, false, 200);
        scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 6)]);
        scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 7)]);
        let key = *scene
            .native
            .scene
            .coordinator
            .recoveries
            .keys()
            .next()
            .unwrap();
        let mut old = scene
            .native
            .scene
            .coordinator
            .pending_ids
            .values()
            .map(|pending| pending.observation.count)
            .collect::<Vec<_>>();
        old.sort_unstable();
        assert_eq!(old, vec![6, 7]);
        let catalog = scene.catalog(false, true, 300);
        round3_apply_unpublished(&mut scene, catalog, 300);
        scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 8)]);
        let eight = scene.native.scene.coordinator.pair_counts[&key];
        scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 10)]);
        assert_eq!(scene.native.scene.coordinator.pending_ids.len(), 2);
        scene.native.scene.coordinator.registry.publish();
        let mut decisions = scene
            .native
            .scene
            .coordinator
            .registry
            .take_pending_count_decisions();
        assert_eq!(decisions.len(), 2);
        if reverse {
            decisions.reverse();
        }
        crate::discovery::caller_registry::tests::deliver_pending_decisions(
            &mut scene.native.scene.coordinator.registry,
            &decisions,
        );
        scene.native.scene.coordinator.finalize_pending_counts();
        for _ in 0..20 {
            scene.horizons();
            receipts.assert_bounded();
        }
        assert_eq!(scene.counts(), (5, 2));
        let recovery = &scene.native.scene.coordinator.recoveries[&key];
        assert_eq!(
            (
                recovery.fence.unwrap().count,
                recovery.fence.unwrap().anchor_ns
            ),
            (8, eight.anchor_ns)
        );
        assert_eq!(recovery.watermark, 10);
        let gaps = scene.native.scene.coordinator.registry.gaps().len();
        // Replay actual historical decisions after placement generation changed.
        crate::discovery::caller_registry::tests::deliver_pending_decisions(
            &mut scene.native.scene.coordinator.registry,
            &decisions,
        );
        scene.native.scene.coordinator.finalize_pending_counts();
        scene.native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(scene.counts(), (5, 2));
        assert_eq!(
            scene.native.scene.coordinator.recoveries[&key].watermark,
            10
        );
        assert_eq!(scene.native.scene.coordinator.registry.gaps().len(), gaps);
    }
}

#[test]
fn demotion_retirement_round3_placed_predecessor_resumes_unchanged_carrier_growth() {
    let receipts = WorkReceipts::begin();
    let mut scene = Scene::placed();
    // Admit the common B endpoint without a B mapping edge. Generic Pending7
    // is real, but its eventual publication has exactly one eligible A edge.
    let mut catalog = members_catalog_paths(&scene, &[(7, scene.caller, 41)], &[&scene.a], 200);
    catalog.processes[0].complete_scan = None;
    catalog.lowering = Some(crate::inspect_system::CatalogLowering {
        plan: fx::lower_named(
            &[
                fx::module_with_targets(&scene.pins, &scene.a, &[(&scene.a, 0x1000)]),
                fx::module_with_targets(&scene.pins, &scene.b, &[(&scene.a, 0x1000)]),
            ],
            &scene.pins,
            crate::plan::AdmissionPolicy::Inventory(
                scene.native.scene.coordinator.attach_set.budget(),
            ),
        ),
        pins: fx::pass_pins(&[(&scene.a, "sha-a"), (&scene.b, "sha-b")]),
        modules: Vec::new(),
    });
    scene.apply(catalog, 200);
    scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 7)]);
    assert!(
        scene
            .native
            .scene
            .coordinator
            .pending_ids
            .values()
            .any(|pending| pending.observation.count == 7)
    );
    let before_gaps = scene.native.scene.coordinator.registry.gaps().len();
    let catalog = members_catalog_paths(&scene, &[(7, scene.caller, 41)], &[&scene.a], 300);
    round3_apply_unpublished(&mut scene, catalog, 300);
    scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 8)]);
    scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 10)]);
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    for _ in 0..20 {
        scene.horizons();
        receipts.assert_bounded();
    }
    assert_eq!(edge_count(&scene.native, scene.caller, "a.so"), 10);
    assert!(
        scene
            .native
            .scene
            .coordinator
            .registry
            .edges()
            .filter(|edge| edge.caller == scene.caller)
            .all(|edge| edge.entry_count == 0
                || scene
                    .native
                    .scene
                    .coordinator
                    .registry
                    .module(edge.module)
                    .is_some_and(|module| module.paths.iter().any(|path| path.ends_with("a.so"))))
    );
    assert!(
        !scene
            .native
            .scene
            .coordinator
            .registry
            .gaps()
            .iter()
            .skip(before_gaps)
            .any(|gap| gap.subject == crate::discovery::caller_registry::DEMOTED_COUNT_REJECTED)
    );
}

#[test]
fn demotion_retirement_round3_receipt_allocations_plateau_and_release() {
    let receipts = WorkReceipts::begin();
    let mut scene = Scene::shared();
    scene.native.unavailable_answer(7, 500);
    scene.observe(false, true, 300);
    scene.count(8);
    scene.count(10);
    let mut weak = round3_receipts(&scene);
    let mut max_alive = 0;
    let mut max_path_capacity = 0;
    for at in 400..480 {
        scene.observe(false, true, at);
        weak.extend(round3_receipts(&scene));
        weak.sort_by_key(std::sync::Weak::as_ptr);
        weak.dedup_by_key(|reference| reference.as_ptr());
        let alive = weak
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .collect::<Vec<_>>();
        max_alive = max_alive.max(alive.len());
        for scan in &alive {
            let capacity = scan
                .generation()
                .exe
                .as_ref()
                .and_then(|exe| exe.path.as_ref())
                .map_or(0, String::capacity);
            max_path_capacity = max_path_capacity.max(capacity);
        }
        assert!(alive.len() <= 8, "4R + 3C + P bound for R=C=P=1");
        round3_assert_slots(&scene);
        scene.horizons();
        receipts.assert_bounded();
    }
    println!(
        "round3 PairRecovery offsets caller={} endpoint={} carrier={} epoch={} scan={} sighting={} fence={} tags={} H={} D={} watermark={} blocked={} recovered={} deferred={} refused={} epoch_pending={}",
        std::mem::offset_of!(PairRecovery, caller),
        std::mem::offset_of!(PairRecovery, endpoint),
        std::mem::offset_of!(PairRecovery, carrier),
        std::mem::offset_of!(PairRecovery, epoch),
        std::mem::offset_of!(PairRecovery, scan),
        std::mem::offset_of!(PairRecovery, sighting),
        std::mem::offset_of!(PairRecovery, fence),
        std::mem::offset_of!(PairRecovery, pending_reads),
        std::mem::offset_of!(PairRecovery, withheld_through),
        std::mem::offset_of!(PairRecovery, discarded_through),
        std::mem::offset_of!(PairRecovery, watermark),
        std::mem::offset_of!(PairRecovery, blocked),
        std::mem::offset_of!(PairRecovery, recovered),
        std::mem::offset_of!(PairRecovery, deferred_count),
        std::mem::offset_of!(PairRecovery, receipt_refused),
        std::mem::offset_of!(PairRecovery, epoch_pending)
    );
    println!(
        "round3 actual layouts: PairRecovery={} TaggedCountRead={} OwnershipScan={} CompleteMemberScan={} ArcStrong={} ArcWeak={} retained_receipt_peak={} max_exe_path_capacity={} conservative_allocations=4R+3C+P",
        std::mem::size_of::<PairRecovery>(),
        std::mem::size_of::<TaggedCountRead>(),
        std::mem::size_of::<OwnershipScan>(),
        std::mem::size_of::<crate::inspect_system::CompleteMemberScan>(),
        std::mem::size_of::<std::sync::atomic::AtomicUsize>(),
        std::mem::size_of::<std::sync::atomic::AtomicUsize>(),
        max_alive,
        max_path_capacity
    );
    let catalog = scene.catalog(false, false, 500);
    scene.apply(catalog, 500);
    for _ in 0..20 {
        scene.horizons();
        receipts.assert_bounded();
    }
    assert!(
        weak.iter().all(|reference| reference.upgrade().is_none()),
        "failed source releases caller, pair and stale summary receipt ownership"
    );
    assert_eq!(scene.counts(), (5, 0));
}

#[test]
fn demotion_retirement_round3_old_prefix_finishes_before_unproven_first_read() {
    let receipts = WorkReceipts::begin();
    let (mut scene, members) = round3_more_members();
    for &(pid, _, _) in &members {
        scene
            .native
            .unavailable_answer(pid, if pid == 7 { 500 } else { 500 + u64::from(pid) });
    }
    scene.apply(members_catalog(&scene, &members, true, 200), 200);
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 7))
            .collect(),
    );
    let generic_callers = scene
        .native
        .scene
        .coordinator
        .pending_ids
        .values()
        .filter(|pending| pending.observation.count == 7)
        .map(|pending| pending.caller)
        .collect::<std::collections::HashSet<_>>();
    let catalog = members_catalog(&scene, &members, false, 300);
    round3_apply_unpublished(&mut scene, catalog, 300);
    for _ in 0..80 {
        scene.horizons();
        receipts.assert_bounded();
    }
    for &(_, caller, _) in &members {
        let recovery = scene
            .native
            .scene
            .coordinator
            .recoveries
            .values()
            .find(|recovery| recovery.caller == caller)
            .unwrap();
        assert_eq!(
            recovery.watermark, 7,
            "old saved7 has independent historical disposition"
        );
        assert!(recovery.fence.is_none() && recovery.sighting.is_none());
        assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), 300);
        if generic_callers.contains(&caller) {
            assert!(
                scene
                    .native
                    .scene
                    .coordinator
                    .registry
                    .gaps()
                    .iter()
                    .any(|gap| gap.subject
                        == crate::discovery::caller_registry::DEMOTED_COUNT_REJECTED
                        && gap.reason.contains("2 unattributed calls")),
                "original generic rejection keeps its inherited module-scoped disclosure"
            );
        } else {
            assert!(
                scene
                    .native
                    .scene
                    .coordinator
                    .registry
                    .gaps()
                    .iter()
                    .any(|gap| gap.caller == Some(caller)
                        && gap.reason.contains("(5, 7]")
                        && gap.reason.contains("2 unattributed calls"))
            );
        }
    }
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 8))
            .collect(),
    );
    let original = scene.native.scene.coordinator.pair_counts.clone();
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 10))
            .collect(),
    );
    for _ in 0..80 {
        scene.horizons();
        receipts.assert_bounded();
    }
    for recovery in scene.native.scene.coordinator.recoveries.values() {
        assert_eq!(
            recovery.watermark, 7,
            "selection/failing fresh query cannot authenticate8"
        );
        assert!(recovery.fence.is_some_and(|read| read.count == 8));
    }
    for &(pid, _, ticket) in &members {
        scene.native.answer(
            pid,
            if pid == 7 { 500 } else { 500 + u64::from(pid) },
            ticket,
        );
    }
    for _ in 0..80 {
        scene.horizons();
        receipts.assert_bounded();
    }
    for (key, recovery) in &scene.native.scene.coordinator.recoveries {
        assert_eq!(
            (
                edge_count(&scene.native, recovery.caller, "a.so"),
                edge_count(&scene.native, recovery.caller, "b.so")
            ),
            (5, 2)
        );
        assert_eq!(
            (
                recovery.fence.unwrap().count,
                recovery.fence.unwrap().anchor_ns,
                recovery.fence.unwrap().last_ns
            ),
            (8, original[key].anchor_ns, original[key].last_ns)
        );
        assert!(
            scene
                .native
                .scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .any(|gap| gap.caller == Some(recovery.caller)
                    && gap.reason.contains("(7, 8]")
                    && gap.reason.contains("1 unattributed calls"))
        );
    }
}

#[test]
fn demotion_retirement_round3_delayed_predecessor_and_later_discard_keep_original_fence() {
    let receipts = WorkReceipts::begin();
    let (mut scene, members) = round3_more_members();
    let mut historical = members_catalog(&scene, &members, true, 200);
    for process in &mut historical.processes {
        process.complete_scan = None;
    }
    scene.apply(historical, 200);
    // Establish the original shared catalog before7, as the real generic
    // predecessor branch requires. No service flush precedes8 in either of the
    // two isolated RED controls; this separate delayed-publication control
    // explicitly tests selected state while that historical decision remains held.
    for _ in 0..80 {
        scene.horizons();
        receipts.assert_bounded();
    }
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 7))
            .collect(),
    );
    let history = scene
        .native
        .scene
        .coordinator
        .pending_ids
        .iter()
        .map(|(&id, pending)| (id, (pending.observation.count, pending.generation)))
        .collect::<HashMap<_, _>>();
    assert_eq!(history.len(), members.len());
    for &(pid, _, _) in &members {
        scene
            .native
            .unavailable_answer(pid, if pid == 7 { 500 } else { 500 + u64::from(pid) });
    }
    let catalog = members_catalog(&scene, &members, false, 300);
    round3_apply_unpublished(&mut scene, catalog, 300);
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 8))
            .collect(),
    );
    let original = scene.native.scene.coordinator.pair_counts.clone();
    // Real lifecycle/read service with publication withheld; historical7 keeps
    // its original handle/generation while source ownership selects8.
    for _ in 0..80 {
        scene.native.drain();
        scene.native.read(Vec::new());
        receipts.assert_bounded();
    }
    assert!(
        scene
            .native
            .scene
            .coordinator
            .recoveries
            .values()
            .all(
                |recovery| recovery.fence.is_some_and(|read| read.count == 8)
                    && recovery.watermark == 5
                    && recovery.sighting.is_none()
            )
    );
    let epochs = scene
        .native
        .scene
        .coordinator
        .recoveries
        .iter()
        .map(|(&key, recovery)| (key, recovery.epoch))
        .collect::<HashMap<_, _>>();
    for (a_present, at) in [(false, 400), (true, 450)] {
        let catalog = members_catalog(&scene, &members, a_present, at);
        round3_apply_unpublished(&mut scene, catalog, at);
    }
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 9))
            .collect(),
    );
    let waiting = scene
        .native
        .scene
        .coordinator
        .recoveries
        .iter()
        .filter(|(_, recovery)| {
            recovery
                .pending_reads
                .iter()
                .flatten()
                .any(|tag| tag.read.count == 9 && tag.scan.started_ns() == 450)
        })
        .map(|(&key, _)| key)
        .collect::<Vec<_>>();
    assert!(!waiting.is_empty());
    let catalog = members_catalog(&scene, &members, false, 500);
    round3_apply_unpublished(&mut scene, catalog, 500);
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, 10))
            .collect(),
    );
    for (&id, &(count, generation)) in &history {
        let pending = &scene.native.scene.coordinator.pending_ids[&id];
        assert_eq!(
            (pending.observation.count, pending.generation),
            (count, generation)
        );
    }
    assert_eq!(
        scene.native.scene.coordinator.pending_ids.len(),
        history.len()
    );
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    for &(pid, _, ticket) in &members {
        scene.native.answer(
            pid,
            if pid == 7 { 500 } else { 500 + u64::from(pid) },
            ticket,
        );
    }
    for _ in 0..100 {
        scene.horizons();
        round3_assert_slots(&scene);
        receipts.assert_bounded();
    }
    let mut continued = 0;
    for key in waiting {
        let recovery = &scene.native.scene.coordinator.recoveries[&key];
        if recovery.epoch != epochs[&key] {
            continue;
        }
        continued += 1;
        assert_eq!(
            (
                edge_count(&scene.native, recovery.caller, "a.so"),
                edge_count(&scene.native, recovery.caller, "b.so")
            ),
            (5, 2)
        );
        assert_eq!(
            (
                recovery.fence.unwrap().count,
                recovery.fence.unwrap().anchor_ns
            ),
            (8, original[&key].anchor_ns)
        );
        assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), 300);
        assert!(
            scene
                .native
                .scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .any(|gap| gap.caller == Some(recovery.caller) && gap.reason.contains("(7, 8]"))
        );
        assert!(
            !scene
                .native
                .scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .any(|gap| gap.caller == Some(recovery.caller) && gap.reason.contains("(8, 9]"))
        );
    }
    assert!(
        continued > 0,
        "the actual dropped waiting9 must preserve at least one settled S300 epoch"
    );
}

fn round3_missing_bindings(scene: &mut Scene, members: &[(u32, CallerId, u64)]) {
    for &(pid, _, _) in members {
        scene
            .native
            .unavailable_answer(pid, if pid == 7 { 500 } else { 500 + u64::from(pid) });
    }
}
fn round3_restore_bindings(scene: &mut Scene, members: &[(u32, CallerId, u64)]) {
    for &(pid, _, ticket) in members {
        scene.native.answer(
            pid,
            if pid == 7 { 500 } else { 500 + u64::from(pid) },
            ticket,
        );
    }
}
fn round3_member_read(scene: &mut Scene, members: &[(u32, CallerId, u64)], count: u64) {
    scene.native.counts_read(
        Vec::new(),
        members
            .iter()
            .map(|&(_, _, ticket)| (ticket, 1, 0, count))
            .collect(),
    );
}

#[test]
fn demotion_retirement_round3_rollover_classifies_new_candidate_before_later_discard() {
    let receipts = WorkReceipts::begin();
    let (mut scene, members) = round3_more_members();
    scene.apply(members_catalog(&scene, &members, true, 200), 200);
    round3_member_read(&mut scene, &members, 7);
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    round3_missing_bindings(&mut scene, &members);
    scene.apply(members_catalog(&scene, &members, false, 300), 300);
    round3_member_read(&mut scene, &members, 8);
    for _ in 0..80 {
        scene.horizons();
        receipts.assert_bounded();
    }
    let old_epochs = scene
        .native
        .scene
        .coordinator
        .recoveries
        .iter()
        .map(|(&key, recovery)| (key, recovery.epoch))
        .collect::<HashMap<_, _>>();
    assert!(
        scene
            .native
            .scene
            .coordinator
            .recoveries
            .values()
            .all(
                |recovery| recovery.fence.is_some_and(|read| read.count == 8)
                    && recovery.sighting.is_none()
            )
    );
    // A-only is positively processed, so the B epoch genuinely ends. Its new
    // full10 must survive later conditional11; matching module names alone
    // are never used to transport the old8 authority.
    let catalog = members_catalog_paths(&scene, &members, &[&scene.a], 400);
    scene.apply(catalog, 400);
    round3_member_read(&mut scene, &members, 10);
    for _ in 0..80 {
        scene.horizons();
        receipts.assert_bounded();
    }
    let original = scene
        .native
        .scene
        .coordinator
        .recoveries
        .iter()
        .map(|(&key, recovery)| {
            assert!(recovery.epoch != old_epochs[&key]);
            assert_eq!(recovery.fence.unwrap().count, 10);
            assert_eq!(
                recovery.watermark, 8,
                "only the actually revoked old8 is unknown history"
            );
            (
                key,
                (
                    recovery.epoch,
                    recovery.fence.unwrap(),
                    recovery.scan.as_ref().unwrap().started_ns(),
                ),
            )
        })
        .collect::<HashMap<_, _>>();
    let catalog = members_catalog_paths(&scene, &members, &[&scene.a], 500);
    scene.apply(catalog, 500);
    scene.apply(members_catalog(&scene, &members, false, 550), 550);
    round3_member_read(&mut scene, &members, 11);
    let waiting = scene
        .native
        .scene
        .coordinator
        .recoveries
        .iter()
        .filter(|(_, recovery)| {
            recovery
                .pending_reads
                .iter()
                .flatten()
                .any(|tag| tag.read.count == 11 && tag.scan.started_ns() == 550)
        })
        .map(|(&key, _)| key)
        .collect::<Vec<_>>();
    assert!(!waiting.is_empty(), "actual unexamined waiting11 exists");
    let catalog = members_catalog_paths(&scene, &members, &[&scene.a], 600);
    scene.apply(catalog, 600);
    round3_member_read(&mut scene, &members, 12);
    for _ in 0..80 {
        scene.horizons();
        round3_assert_slots(&scene);
        receipts.assert_bounded();
    }
    let continuing = waiting
        .into_iter()
        .filter(|key| scene.native.scene.coordinator.recoveries[key].epoch == original[key].0)
        .collect::<Vec<_>>();
    assert!(
        !continuing.is_empty(),
        "sampled new-epoch continuation must actually occur"
    );
    for key in &continuing {
        let recovery = &scene.native.scene.coordinator.recoveries[key];
        let (_, full_read, started) = original[key];
        assert_eq!(
            recovery.watermark, 8,
            "conditional11 cannot account through valid new-epoch10"
        );
        assert_eq!(
            (
                recovery.fence.unwrap().count,
                recovery.fence.unwrap().anchor_ns,
                recovery.fence.unwrap().last_ns
            ),
            (10, full_read.anchor_ns, full_read.last_ns)
        );
        assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), started);
    }
    round3_restore_bindings(&mut scene, &members);
    for _ in 0..80 {
        scene.horizons();
        receipts.assert_bounded();
    }
    for key in continuing {
        let recovery = &scene.native.scene.coordinator.recoveries[&key];
        assert_eq!(
            (
                edge_count(&scene.native, recovery.caller, "a.so"),
                edge_count(&scene.native, recovery.caller, "b.so")
            ),
            (7, 0)
        );
        assert_eq!(recovery.fence.unwrap().count, 10);
        assert!(
            !scene
                .native
                .scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .any(|gap| gap.caller == Some(recovery.caller) && gap.reason.contains("(10, 11]"))
        );
    }
}

#[test]
fn demotion_retirement_round3_failed_authority_invalidates_then_requires_actual_advance() {
    let receipts = WorkReceipts::begin();
    let mut scene = Scene::shared();
    scene.native.unavailable_answer(7, 500);
    scene.observe(false, true, 300);
    scene.count(8);
    scene.count(10);
    for _ in 0..20 {
        scene.horizons();
        receipts.assert_bounded();
    }
    let key = *scene
        .native
        .scene
        .coordinator
        .recoveries
        .keys()
        .next()
        .unwrap();
    assert_eq!(
        scene.native.scene.coordinator.recoveries[&key]
            .fence
            .unwrap()
            .count,
        8
    );
    assert_eq!(scene.native.scene.coordinator.recoveries[&key].watermark, 7);
    scene.observe(false, false, 400);
    for _ in 0..20 {
        scene.horizons();
        receipts.assert_bounded();
    }
    let recovery = &scene.native.scene.coordinator.recoveries[&key];
    assert!(recovery.fence.is_none() && recovery.sighting.is_none() && recovery.epoch.is_none());
    assert_eq!(recovery.watermark, 10);
    assert_eq!(scene.counts(), (5, 0));
    scene.observe(false, true, 450);
    scene.count(10);
    for _ in 0..20 {
        scene.horizons();
        receipts.assert_bounded();
    }
    assert!(
        scene.native.scene.coordinator.recoveries[&key]
            .fence
            .is_none(),
        "equal held maximum is not a new fence"
    );
    scene.count(12);
    let actual = scene.native.scene.coordinator.pair_counts[&key];
    scene.native.answer(7, 500, 41);
    for _ in 0..20 {
        scene.horizons();
        receipts.assert_bounded();
    }
    assert_eq!(scene.counts(), (5, 0));
    let recovery = &scene.native.scene.coordinator.recoveries[&key];
    assert_eq!(
        (
            recovery.fence.unwrap().count,
            recovery.fence.unwrap().anchor_ns,
            recovery.fence.unwrap().last_ns
        ),
        (12, actual.anchor_ns, actual.last_ns)
    );
    assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), 450);
    scene.count(14);
    for _ in 0..20 {
        scene.horizons();
        receipts.assert_bounded();
    }
    assert_eq!(scene.counts(), (5, 2));
}

fn round3_long_unrelated_catalog(
    scene: &Scene,
    members: &[(u32, CallerId, u64)],
    at: u64,
) -> crate::inspect_system::Catalog {
    let mut catalog = members_catalog(scene, members, false, at);
    let offsets = fx::offsets(300);
    let mut targets = vec![(scene.a.as_path(), 0x1000)];
    targets.extend(
        offsets
            .iter()
            .map(|offset| (scene.b.as_path(), offset + 0x2000)),
    );
    catalog.lowering = Some(crate::inspect_system::CatalogLowering {
        plan: fx::lower_named(
            &[fx::module_with_targets(&scene.pins, &scene.b, &targets)],
            &scene.pins,
            crate::plan::AdmissionPolicy::Inventory(
                scene.native.scene.coordinator.attach_set.budget(),
            ),
        ),
        pins: fx::pass_pins(&[(&scene.a, "sha-a"), (&scene.b, "sha-b")]),
        modules: Vec::new(),
    });
    catalog
}

#[test]
fn demotion_retirement_round3_historical7_selected8_discard9_and_three_live_tags() {
    let receipts = WorkReceipts::begin();
    let (mut scene, members) = round3_more_members();
    let mut historical = members_catalog(&scene, &members, true, 200);
    for process in &mut historical.processes {
        process.complete_scan = None;
    }
    scene.apply(historical, 200);
    for _ in 0..80 {
        scene.horizons();
        receipts.assert_bounded();
    }
    round3_member_read(&mut scene, &members, 7);
    assert_eq!(
        scene.native.scene.coordinator.pending_ids.len(),
        members.len()
    );
    let history = scene
        .native
        .scene
        .coordinator
        .pending_ids
        .iter()
        .map(|(&id, pending)| (id, (pending.observation.count, pending.generation)))
        .collect::<HashMap<_, _>>();
    round3_missing_bindings(&mut scene, &members);
    let catalog = members_catalog(&scene, &members, false, 300);
    round3_apply_unpublished(&mut scene, catalog, 300);
    round3_member_read(&mut scene, &members, 8);
    for _ in 0..80 {
        scene.native.drain();
        scene.native.read(Vec::new());
        receipts.assert_bounded();
    }
    let original = scene
        .native
        .scene
        .coordinator
        .recoveries
        .iter()
        .map(|(&key, recovery)| {
            assert_eq!(recovery.fence.unwrap().count, 8);
            assert_eq!(recovery.watermark, 5);
            assert!(recovery.sighting.is_none());
            (key, (recovery.epoch, recovery.fence.unwrap()))
        })
        .collect::<HashMap<_, _>>();
    let catalog = members_catalog(&scene, &members, false, 400);
    round3_apply_unpublished(&mut scene, catalog, 400);
    let catalog = members_catalog(&scene, &members, true, 450);
    round3_apply_unpublished(&mut scene, catalog, 450);
    round3_member_read(&mut scene, &members, 9);
    let obsolete = round3_receipts(&scene);
    let revision = scene.native.scene.coordinator.attach_set.count_revision();
    let catalog = round3_long_unrelated_catalog(&scene, &members, 500);
    round3_apply_unpublished(&mut scene, catalog, 500);
    assert!(scene.native.scene.coordinator.attach_set.count_revision() != revision);
    round3_member_read(&mut scene, &members, 10);
    for _ in 0..80 {
        if members
            .iter()
            .filter(|(_, caller, _)| {
                scene
                    .native
                    .scene
                    .coordinator
                    .count_ownership
                    .newest_accepted_post(*caller)
                    >= 501
            })
            .count()
            >= members.len() / 2
        {
            break;
        }
        scene.native.drain();
        scene.native.read(Vec::new());
        receipts.assert_bounded();
    }
    assert!(
        members
            .iter()
            .filter(|(_, caller, _)| scene
                .native
                .scene
                .coordinator
                .count_ownership
                .newest_accepted_post(*caller)
                >= 501)
            .count()
            >= members.len() / 2,
        "bounded comparison must really accept enough scan500 receipts before filling processing/waiting"
    );
    let catalog = round3_long_unrelated_catalog(&scene, &members, 600);
    round3_apply_unpublished(&mut scene, catalog, 600);
    round3_member_read(&mut scene, &members, 11);
    let catalog = round3_long_unrelated_catalog(&scene, &members, 700);
    round3_apply_unpublished(&mut scene, catalog, 700);
    round3_member_read(&mut scene, &members, 12);
    let collisions = scene
        .native
        .scene
        .coordinator
        .recoveries
        .iter()
        .filter(|(_, recovery)| {
            let mut counts = recovery
                .pending_reads
                .iter()
                .flatten()
                .map(|tag| tag.read.count)
                .collect::<Vec<_>>();
            counts.sort_unstable();
            counts == [10, 11, 12]
        })
        .map(|(&key, _)| key)
        .collect::<Vec<_>>();
    assert!(
        !collisions.is_empty(),
        "actual active/processing/waiting tags10/11/12 exercise the reported collision"
    );
    for key in &collisions {
        let recovery = &scene.native.scene.coordinator.recoveries[key];
        assert_eq!((recovery.fence.unwrap().count, recovery.watermark), (8, 5));
        assert!(recovery.discarded_through >= 9 && recovery.sighting.is_none());
        assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), 300);
    }
    for (&id, &(count, generation)) in &history {
        let pending = scene.native.scene.coordinator.pending_ids.get(&id).unwrap();
        assert_eq!(
            (pending.observation.count, pending.generation),
            (count, generation)
        );
    }
    assert_eq!(
        scene.native.scene.coordinator.pending_ids.len(),
        history.len()
    );
    round3_assert_slots(&scene);
    assert!(
        obsolete
            .iter()
            .any(|reference| reference.upgrade().is_none()),
        "detached receipt Arc releases before predecessor publication"
    );
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    round3_restore_bindings(&mut scene, &members);
    for _ in 0..180 {
        scene.horizons();
        round3_assert_slots(&scene);
        receipts.assert_bounded();
    }
    let mut preserved = 0;
    for key in collisions {
        let recovery = &scene.native.scene.coordinator.recoveries[&key];
        if recovery.epoch != original[&key].0 {
            continue;
        }
        preserved += 1;
        assert_eq!(
            (
                edge_count(&scene.native, recovery.caller, "a.so"),
                edge_count(&scene.native, recovery.caller, "b.so")
            ),
            (5, 4)
        );
        assert_eq!(
            (
                recovery.fence.unwrap().count,
                recovery.fence.unwrap().anchor_ns,
                recovery.fence.unwrap().last_ns
            ),
            (8, original[&key].1.anchor_ns, original[&key].1.last_ns)
        );
        assert_eq!(recovery.scan.as_ref().unwrap().started_ns(), 300);
        assert!(
            !scene
                .native
                .scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .any(|gap| gap.caller == Some(recovery.caller) && gap.reason.contains("(8, 9]"))
        );
    }
    assert!(
        preserved > 0,
        "unrelated global revision establishes bounded original-epoch continuation"
    );
}

fn round3_debug(scene: &Scene) {
    for recovery in scene.native.scene.coordinator.recoveries.values().take(4) {
        println!(
            "state epoch={:?} scan={:?} fence={:?} wm={} H={} D={} blocked={} defer={} refused={} epoch_pending={} recovered={} sighting={}",
            recovery.epoch.map(|epoch| epoch.0),
            recovery.scan.as_ref().map(|scan| scan.started_ns()),
            recovery.fence.map(|read| read.count),
            recovery.watermark,
            recovery.withheld_through,
            recovery.discarded_through,
            recovery.blocked,
            recovery.deferred_count,
            recovery.receipt_refused,
            recovery.epoch_pending,
            recovery.recovered,
            recovery.sighting.is_some()
        );
        println!(
            "tags {:?}",
            recovery
                .pending_reads
                .iter()
                .flatten()
                .map(|tag| (tag.read.count, tag.scan.started_ns()))
                .collect::<Vec<_>>()
        );
    }
    for gap in scene.native.scene.coordinator.registry.gaps() {
        if gap.subject.starts_with("count retirement") || gap.subject.starts_with("demoted") {
            println!("gap {} {}", gap.subject, gap.reason);
        }
    }
}

#[test]
fn demotion_retirement_round3_staged_growth_keeps_original_fence_until_publication() {
    let receipts = WorkReceipts::begin();
    let mut scene = Scene::shared();
    scene.observe(false, true, 300);
    scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 8)]);
    let key = *scene
        .native
        .scene
        .coordinator
        .recoveries
        .keys()
        .next()
        .unwrap();
    let eight = scene.native.scene.coordinator.pair_counts[&key];
    scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 10)]);
    for _ in 0..20 {
        QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
        scene.native.drain();
        scene.native.read(Vec::new());
        receipts.assert_bounded();
    }
    let pending = scene
        .native
        .scene
        .coordinator
        .pending_ids
        .iter()
        .filter(|(_, pending)| {
            pending.key == key && matches!(pending.origin, PendingCountOrigin::Recovered(_))
        })
        .map(|(&id, pending)| (id, pending.observation.count, pending.generation))
        .collect::<Vec<_>>();
    assert_eq!(
        pending.len(),
        1,
        "only the immutable actual10 recovery request is staged"
    );
    assert_eq!(pending[0].1, 10);
    let recovery = &scene.native.scene.coordinator.recoveries[&key];
    assert_eq!(
        recovery.watermark, 10,
        "watermark includes the immutable publication reservation"
    );
    assert_eq!(
        (
            recovery.fence.unwrap().count,
            recovery.fence.unwrap().anchor_ns,
            recovery.fence.unwrap().last_ns
        ),
        (8, eight.anchor_ns, eight.last_ns)
    );
    assert!(!recovery.recovered, "staging is not successful placement");
    let epoch = recovery.epoch;
    for _ in 0..20 {
        QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
        scene.native.drain();
        scene.native.read(Vec::new());
        receipts.assert_bounded();
    }
    assert!(scene.native.scene.coordinator.recoveries[&key].epoch == epoch);
    let original = scene
        .native
        .scene
        .coordinator
        .pending_ids
        .get(&pending[0].0)
        .unwrap();
    assert_eq!(
        (original.observation.count, original.generation),
        (10, pending[0].2)
    );
    assert_eq!(
        scene.native.scene.coordinator.recoveries[&key]
            .fence
            .unwrap()
            .count,
        8
    );
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    assert_eq!(scene.counts(), (5, 2));
    assert!(scene.native.scene.coordinator.recoveries[&key].recovered);
    assert_eq!(
        scene.native.scene.coordinator.recoveries[&key]
            .fence
            .unwrap()
            .count,
        8
    );
}

/// cnt-1 steady sole pair: one caller, one 68-endpoint module, production
/// pass order (apply the catalog, stage a lifecycle drain, stage one
/// witness read, then a single commit). Catalog scans run before the
/// native stamps, the way a live observer scans before first use.
struct Cnt1Steady {
    native: NativeScene,
    caller: CallerId,
    a: std::path::PathBuf,
    pins: crate::discovery::identity::PinnedObjects,
    offsets: Vec<u64>,
    generation: crate::inspect_system::MemberGeneration,
    row_at: u64,
}

impl Cnt1Steady {
    fn new() -> Self {
        let mut scene = CaptureScene::new(68);
        scene.source.spawn(7, 500);
        let caller = scene
            .coordinator
            .adapter
            .admit(7, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene.project(7, 60);
        scene.coordinator.commit_batch(false).unwrap();
        let mut native = NativeScene::over(scene, 0);
        native
            .scene
            .coordinator
            .binder
            .set_current_binding_clock(query_clock);
        native.answer(7, 500, 41);
        let a = native.scene.path.clone();
        let pins = fx::pass_pins(&[(&a, "sha-a")]);
        let offsets = fx::offsets(68);
        let generation = crate::inspect_system::MemberGeneration {
            start_time: Some(500),
            exe: native
                .scene
                .coordinator
                .adapter
                .record(caller)
                .unwrap()
                .exe
                .clone(),
        };
        Self {
            native,
            caller,
            a,
            pins,
            offsets,
            generation,
            row_at: 0,
        }
    }

    fn catalog(&self, at: u64) -> crate::inspect_system::Catalog {
        let mut catalog = capture_catalog(&self.pins, &[&self.a], 7, Some(self.generation.clone()));
        catalog.processes[0].complete_scan =
            Some(crate::inspect_system::CompleteMemberScan::scripted(
                self.generation.clone(),
                at,
                at + 1,
            ));
        let targets: Vec<(&std::path::Path, u64)> = self
            .offsets
            .iter()
            .map(|offset| (self.a.as_path(), *offset))
            .collect();
        let modules = vec![fx::module_with_targets(&self.pins, &self.a, &targets)];
        catalog.lowering = Some(crate::inspect_system::CatalogLowering {
            plan: fx::lower_named(
                &modules,
                &self.pins,
                crate::plan::AdmissionPolicy::Inventory(
                    self.native.scene.coordinator.attach_set.budget(),
                ),
            ),
            pins: fx::pass_pins(&[(&self.a, "sha-a")]),
            modules: Vec::new(),
        });
        catalog
    }

    fn apply(&mut self, at: u64) {
        QUERY_CLOCK.with(|clock| clock.set(self.native.stamps.tick()));
        self.native.scene.coordinator.apply_catalog(
            self.catalog(at),
            &mut crate::discovery::engine::inventory::UnavailableImageGuard,
            &mut self.native.cookies,
            at + 100,
            at,
        );
    }

    fn drain(&mut self) {
        QUERY_CLOCK.with(|clock| clock.set(self.native.stamps.tick()));
        self.native.drain();
    }

    fn commit(&mut self) {
        self.native.scene.coordinator.commit_batch(false).unwrap();
    }

    /// A quiet pass: catalog, drain, empty witness read, commit.
    fn pass(&mut self, at: u64) {
        self.apply(at);
        self.drain();
        self.native.read(Vec::new());
        self.commit();
    }

    /// The first-use pass: the row arrives with no advanced count yet.
    fn pass_row(&mut self, at: u64) {
        QUERY_CLOCK.with(|clock| clock.set(self.native.stamps.tick()));
        self.row_at = self.native.stamps.tick();
        self.apply(at);
        self.drain();
        let row = self.native.row(41, 1, 7, self.row_at, 0);
        self.native.read(vec![row]);
        self.commit();
    }

    /// A counted pass: the refresh carries only the advanced absolute.
    /// Live reports each witness row exactly once (the witness sweep
    /// reports the unseen and skips the seen); steady passes re-read
    /// counts, never rows.
    fn pass_count(&mut self, at: u64, absolute: u64) {
        self.apply(at);
        self.drain();
        QUERY_CLOCK.with(|clock| clock.set(self.native.stamps.tick()));
        self.native
            .counts_read(Vec::new(), vec![(41, 1, 0, absolute)]);
        self.commit();
    }

    fn edge_count(&self) -> u64 {
        self.native
            .scene
            .coordinator
            .registry()
            .edges_of(self.caller)
            .next()
            .map(|edge| edge.entry_count)
            .unwrap()
    }

    fn owner_unproven_gaps(&self) -> Vec<String> {
        self.native
            .scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .filter(|gap| gap.reason.contains("physical owner is not proven"))
            .map(|gap| format!("{}: {}", gap.subject, gap.reason))
            .collect()
    }
}

#[test]
fn cnt1_steady_sole_pair_attributes_every_refresh() {
    let mut scene = Cnt1Steady::new();
    scene.pass(100);
    scene.pass(200);
    scene.pass_row(220);
    assert_eq!(scene.edge_count(), 0);
    assert!(scene.owner_unproven_gaps().is_empty());
    // The live absolute sequence, extended: every refresh must land on the
    // sole edge with no "owner not proven" gap once the index finishes.
    for (step, absolute) in [
        270106, 413539, 531131, 629874, 700000, 750000, 800000, 850000, 900000, 950000,
    ]
    .into_iter()
    .enumerate()
    {
        scene.pass_count(230 + step as u64 * 10, absolute);
        assert_eq!(
            scene.edge_count(),
            absolute,
            "steady refresh {absolute} attributes exactly"
        );
        assert!(
            scene.owner_unproven_gaps().is_empty(),
            "steady refresh {absolute} leaves no owner-unproven gap: {:?}",
            scene.owner_unproven_gaps()
        );
    }
}

/// cnt-1 disclosure guard: an exit that is not clean (the pair was
/// refused or a transition is armed) keeps today's cancel-and-disclose
/// path. Only a clean exit attributes terminal growth.
#[test]
fn cnt1_blocked_exit_still_discloses_owner_unproven_gap() {
    let mut scene = Scene::shared();
    let before = scene.counts();
    scene.native.scene.source.kill(7);
    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene.native.scene.coordinator.observe_empty_pass(
        &mut crate::discovery::engine::inventory::UnavailableImageGuard,
        &mut scene.native.cookies,
        "cannot inventory pid 7: the process could not be read",
        2000,
    );
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 12)]);
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    assert_eq!(
        scene.counts(),
        before,
        "a blocked exit attributes no terminal growth"
    );
    assert!(
        scene
            .native
            .scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .any(|gap| gap.reason.contains("physical owner is not proven")),
        "a blocked exit discloses the owner-unproven range"
    );
}

#[test]
fn cnt1_terminal_growth_of_exited_sole_owner_attributes() {
    let mut scene = Cnt1Steady::new();
    scene.pass(100);
    scene.pass(200);
    scene.pass_row(220);
    for (step, absolute) in [270106, 413539, 531131].into_iter().enumerate() {
        scene.pass_count(230 + step as u64 * 10, absolute);
    }
    assert_eq!(scene.edge_count(), 531131);
    // The process exits; an empty pass retires the caller with proven exit,
    // then the terminal count arrives late.
    scene.native.scene.source.kill(7);
    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene.native.scene.coordinator.observe_empty_pass(
        &mut crate::discovery::engine::inventory::UnavailableImageGuard,
        &mut scene.native.cookies,
        "cannot inventory pid 7: the process could not be read",
        2000,
    );
    scene.commit();
    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene
        .native
        .counts_read(Vec::new(), vec![(41, 1, 0, 629874)]);
    scene.commit();
    assert_eq!(
        scene.edge_count(),
        629874,
        "terminal growth of the proven-exited sole owner attributes"
    );
    assert!(
        scene.owner_unproven_gaps().is_empty(),
        "terminal growth leaves no owner-unproven gap: {:?}",
        scene.owner_unproven_gaps()
    );
}

fn dead_pin_tick_then_terminal_count(abandon_pending: bool) {
    let mut scene = Cnt1Steady::new();
    scene.pass(100);
    scene.pass(200);
    scene.pass_row(220);
    scene.pass_count(230, 161950);
    assert_eq!(scene.edge_count(), 161950);

    // Between catalog passes the native lane services lifecycle quanta. The
    // original pin may already prove death, while reconcile has not yet
    // changed the retained caller's lifecycle to Exited.
    scene.native.scene.source.kill(7);
    scene.drain();
    assert!(
        !scene
            .native
            .scene
            .coordinator
            .adapter
            .record(scene.caller)
            .unwrap()
            .retired,
        "the service tick precedes catalog exit classification"
    );
    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene.native.scene.coordinator.observe_empty_pass(
        &mut crate::discovery::engine::inventory::UnavailableImageGuard,
        &mut scene.native.cookies,
        "cannot inventory pid 7: the process could not be read",
        2000,
    );
    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene
        .native
        .counts_read(Vec::new(), vec![(41, 1, 0, 162003)]);

    if abandon_pending {
        // Exercise the real abandonment entrypoint over the coordinator's
        // retained-publication seam. This pose supplies no semantic frame or
        // new authority; the ordinary physical count must survive it.
        let lowering = scene.catalog(2100).lowering.unwrap();
        let subset =
            semantics::AttestedSubset::scripted(lowering.plan, lowering.pins, BTreeMap::new());
        let mut lane = AttestedSemanticLane::start(
            subset,
            &crate::attach::Scope::System,
            crate::attach::BackendSelection::Auto,
        )
        .unwrap();
        let coordinator = &mut scene.native.scene.coordinator;
        coordinator.pose_pending_joint_publication_for_test();
        assert!(coordinator.publication_pending());
        coordinator.abandon_unfinished_joint_publication(
            &mut lane,
            None,
            "test publication stopped after caller exit".into(),
        );
        assert!(!coordinator.publication_pending());
    }
    scene.commit();
    assert_eq!(
        scene.edge_count(),
        162003,
        "the final absolute read retains the complete proven-exited sole owner history; gaps={:?}",
        scene.owner_unproven_gaps(),
    );
    assert!(scene.owner_unproven_gaps().is_empty());
}

#[test]
fn cnt1_dead_pin_tick_before_exit_classification_retains_terminal_count() {
    dead_pin_tick_then_terminal_count(false);
}

#[test]
fn cnt1_dead_pin_tick_and_publication_abandon_retain_terminal_count() {
    dead_pin_tick_then_terminal_count(true);
}

fn pid_tail_read(scene: &mut Cnt1Steady, count: u64, custody: ScopeCustody) {
    let NativeBatch::Witness(mut batch) = scene.native.stamps.read(scene.native.domain, Vec::new())
    else {
        unreachable!()
    };
    batch.custody = custody;
    batch.counts = vec![CallerCountUpdate {
        image: p11scope_ebpf_common::ImageIdentity {
            task_cookie: 41,
            exec_id: 1,
        },
        object: scene.native.scene.delta.endpoints[0].object,
        count,
    }];
    scene.native.stage(NativeBatch::Witness(batch));
}

fn capture_tail_scene(scope: CaptureScopeCoverage) -> Cnt1Steady {
    let mut scene = Cnt1Steady::new();
    scene.native.scene.coordinator.begin_capture_coverage(scope);
    let custody = match scope {
        CaptureScopeCoverage::System => ScopeCustody::System,
        CaptureScopeCoverage::Pid(_) => ScopeCustody::PidHeld,
        CaptureScopeCoverage::Cgroup => unreachable!(),
    };
    scene.native.scene.attach_all(70, custody);
    scene.pass(100);
    scene.pass(200);
    scene.pass_row(220);
    scene.pass_count(230, 1894);
    assert_eq!(scene.edge_count(), 1894);
    scene
}

fn original_exit_custody(scene: &Cnt1Steady) -> ScopeCustody {
    ScopeCustody::PidExited {
        at_ns: 230,
        proof: crate::attach::capture::OriginalPidExit::scripted(
            scene.native.domain,
            crate::attach::capture::ScopeIncarnation {
                pid: 7,
                start_time: Some(500),
            },
        ),
    }
}

fn classify_exit_and_read_tail(scene: &mut Cnt1Steady, custody: ScopeCustody) {
    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene.native.scene.coordinator.observe_empty_pass(
        &mut crate::discovery::engine::inventory::UnavailableImageGuard,
        &mut scene.native.cookies,
        "cannot inventory pid 7: the process could not be read",
        2000,
    );
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .adapter
            .record(scene.caller)
            .unwrap()
            .lifecycle,
        crate::discovery::caller_registry::CallerLifecycle::Exited
    );
    pid_tail_read(scene, 2002, custody);
    scene.commit();
}

fn pid_tail_scene() -> Cnt1Steady {
    capture_tail_scene(CaptureScopeCoverage::Pid(
        crate::attach::capture::ScopeIncarnation {
            pid: 7,
            start_time: Some(500),
        },
    ))
}

#[test]
fn cnt1_pid_exit_custody_before_classification_preserves_terminal_count() {
    let mut scene = pid_tail_scene();
    scene.native.scene.source.kill(7);
    let custody = original_exit_custody(&scene);
    // Actual PID capture ordering: custody is lost before the adapter has
    // classified the dead original, and before its last absolute read.
    pid_tail_read(&mut scene, 1894, custody.clone());
    assert_eq!(scene.edge_count(), 1894, "no early count credit");
    assert!(
        !scene
            .native
            .scene
            .coordinator
            .adapter
            .record(scene.caller)
            .unwrap()
            .retired
    );
    classify_exit_and_read_tail(&mut scene, custody);
    assert_eq!(
        scene.edge_count(),
        2002,
        "original PID history retains the final 108-call tail"
    );
    assert!(scene.owner_unproven_gaps().is_empty());
    let (module, verdict) = scene.native.scene.verdicts.iter().next().unwrap();
    assert!(
        matches!(
            scene.native.scene.coordinator.capture_coverage_note(
                ScopeVerdict::Inside,
                module,
                Some(verdict),
            ),
            Some(CoverageNote::Unknown(UnknownReason::Loss(_)))
        ),
        "historical count credit must not restore a watched interval"
    );
}

#[test]
fn cnt1_pid_exit_custody_waits_for_classification_before_publishing_advance() {
    let mut scene = pid_tail_scene();
    scene.native.scene.source.kill(7);
    let custody = original_exit_custody(&scene);
    pid_tail_read(&mut scene, 2002, custody.clone());
    scene.commit();
    assert!(
        !scene
            .native
            .scene
            .coordinator
            .adapter
            .record(scene.caller)
            .unwrap()
            .retired
    );
    assert_eq!(
        scene.edge_count(),
        1894,
        "an unclassified original exit stays pending even at publication"
    );
    classify_exit_and_read_tail(&mut scene, custody);
    assert_eq!(scene.edge_count(), 2002);
    assert!(scene.owner_unproven_gaps().is_empty());
}

#[test]
fn cnt1_pid_uncertainty_with_an_advancing_read_never_publishes_the_tail() {
    for custody in [
        ScopeCustody::PidLost {
            at_ns: 230,
            reason: "owned pidfd poll failed".into(),
        },
        ScopeCustody::PidUnproven {
            at_ns: 230,
            reason: "an earlier exec was unproven".into(),
        },
    ] {
        let mut scene = pid_tail_scene();
        scene.native.scene.source.kill(7);
        pid_tail_read(&mut scene, 2002, custody.clone());
        scene.commit();
        assert_eq!(scene.edge_count(), 1894);
        classify_exit_and_read_tail(&mut scene, custody);
        assert_eq!(scene.edge_count(), 1894);
        assert_eq!(scene.owner_unproven_gaps().len(), 1);
    }
}

#[test]
fn cnt1_system_capture_coverage_preserves_terminal_count() {
    let mut scene = capture_tail_scene(CaptureScopeCoverage::System);
    scene.native.scene.source.kill(7);
    scene.drain();
    classify_exit_and_read_tail(&mut scene, ScopeCustody::System);
    assert_eq!(scene.edge_count(), 2002);
    assert!(scene.owner_unproven_gaps().is_empty());
}

#[test]
fn cnt1_pid_exit_custody_never_upgrades_prior_uncertainty() {
    for prior in [
        ScopeCustody::PidLost {
            at_ns: 230,
            reason: "owned pidfd poll failed".into(),
        },
        ScopeCustody::PidUnproven {
            at_ns: 230,
            reason: "an earlier exec was unproven".into(),
        },
    ] {
        let mut scene = pid_tail_scene();
        scene.native.scene.source.kill(7);
        pid_tail_read(&mut scene, 1894, prior);
        let custody = original_exit_custody(&scene);
        classify_exit_and_read_tail(&mut scene, custody);
        assert_eq!(scene.edge_count(), 1894);
        assert_eq!(scene.owner_unproven_gaps().len(), 1);
    }
}

#[test]
fn cnt1_pid_exit_custody_is_revoked_by_later_uncertainty() {
    for later in [
        ScopeCustody::PidLost {
            at_ns: 240,
            reason: "owned pidfd poll failed".into(),
        },
        ScopeCustody::PidUnproven {
            at_ns: 220,
            reason: "an earlier exec arrived late".into(),
        },
    ] {
        let mut scene = pid_tail_scene();
        scene.native.scene.source.kill(7);
        let custody = original_exit_custody(&scene);
        pid_tail_read(&mut scene, 1894, custody.clone());
        pid_tail_read(&mut scene, 1894, later);
        classify_exit_and_read_tail(&mut scene, custody);
        assert_eq!(scene.edge_count(), 1894);
        assert_eq!(scene.owner_unproven_gaps().len(), 1);
    }
}

#[test]
fn cnt1_pid_exit_custody_does_not_survive_lifecycle_loss_object_drift_or_stop() {
    for cause in 0..3 {
        let mut scene = pid_tail_scene();
        scene.native.scene.source.kill(7);
        let custody = original_exit_custody(&scene);
        pid_tail_read(&mut scene, 1894, custody.clone());
        match cause {
            0 => scene.native.scene.coordinator.note_lifecycle_loss(
                &crate::attach::capture::LifecycleLoss {
                    at_ns: 220,
                    reason: "lifecycle loss arrived after the exit poll".into(),
                },
            ),
            1 => scene.native.scene.coordinator.end_capture_coverage(240),
            _ => {
                let NativeBatch::Witness(mut batch) =
                    scene.native.stamps.read(scene.native.domain, Vec::new())
                else {
                    unreachable!()
                };
                batch.custody = custody.clone();
                batch
                    .changed_objects
                    .push(scene.native.scene.delta.endpoints[0].object);
                scene.native.stage(NativeBatch::Witness(batch));
            }
        }
        classify_exit_and_read_tail(&mut scene, custody);
        assert_eq!(scene.edge_count(), 1894);
        assert_eq!(scene.owner_unproven_gaps().len(), 1);
    }
}

#[test]
fn cnt1_pid_exit_custody_requires_the_original_scope_and_domain() {
    for wrong_domain in [false, true] {
        let mut scene = pid_tail_scene();
        scene.native.scene.source.kill(7);
        let custody = ScopeCustody::PidExited {
            at_ns: 230,
            proof: crate::attach::capture::OriginalPidExit::scripted(
                if wrong_domain {
                    NativeDomainId::mint()
                } else {
                    scene.native.domain
                },
                crate::attach::capture::ScopeIncarnation {
                    pid: 7,
                    start_time: Some(if wrong_domain { 500 } else { 501 }),
                },
            ),
        };
        pid_tail_read(&mut scene, 1894, custody.clone());
        classify_exit_and_read_tail(&mut scene, custody);
        assert_eq!(scene.edge_count(), 1894);
        assert_eq!(scene.owner_unproven_gaps().len(), 1);
    }
}

#[test]
fn cnt1_exec_transition_does_not_authorize_late_old_image_count() {
    let mut scene = Cnt1Steady::new();
    scene.pass(100);
    scene.pass(200);
    scene.pass_row(220);
    scene.pass_count(230, 161950);
    // An executable change retires the old image, rather than proving a
    // continuous sole-owner exit. Its late count cannot borrow the new
    // image's still-live process custody.
    scene.native.scene.source.exec(7, 600, "/bin/new-image");
    scene.drain();
    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene.native.scene.coordinator.observe_empty_pass(
        &mut crate::discovery::engine::inventory::UnavailableImageGuard,
        &mut scene.native.cookies,
        "the original executable image is no longer current",
        2000,
    );
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .adapter
            .record(scene.caller)
            .unwrap()
            .lifecycle,
        crate::discovery::caller_registry::CallerLifecycle::ExecRetired,
    );
    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene
        .native
        .counts_read(Vec::new(), vec![(41, 1, 0, 162003)]);
    scene.commit();
    assert_eq!(scene.edge_count(), 161950);
    assert_eq!(scene.owner_unproven_gaps().len(), 1);
    assert!(scene.owner_unproven_gaps()[0].contains("(161950, 162003]"));
}

#[test]
fn cnt1_dead_pin_tick_keeps_capture_loss_cancellation() {
    let mut scene = Cnt1Steady::new();
    scene.pass(100);
    scene.pass(200);
    scene.pass_row(220);
    scene.pass_count(230, 161950);
    let coordinator = &mut scene.native.scene.coordinator;
    coordinator.begin_capture_coverage(CaptureScopeCoverage::System);
    coordinator.note_lifecycle_loss(&crate::attach::capture::LifecycleLoss {
        at_ns: 1800,
        reason: "fixture: lifecycle evidence was lost before exit".into(),
    });
    scene.native.scene.source.kill(7);
    scene.drain();
    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene.native.scene.coordinator.observe_empty_pass(
        &mut crate::discovery::engine::inventory::UnavailableImageGuard,
        &mut scene.native.cookies,
        "cannot inventory pid 7: the process could not be read",
        2000,
    );
    QUERY_CLOCK.with(|clock| clock.set(scene.native.stamps.tick()));
    scene
        .native
        .counts_read(Vec::new(), vec![(41, 1, 0, 162003)]);
    scene.commit();
    assert_eq!(scene.edge_count(), 161950);
    assert_eq!(scene.owner_unproven_gaps().len(), 1);
    assert!(scene.owner_unproven_gaps()[0].contains("(161950, 162003]"));
}

/// The production pass order for one steady `--pid` caller
/// (`inventory/capture.rs`, `run_classic_finalizing`): read the pass
/// clock, collect (the deep scan, while collection ticks drain and hold
/// lifecycle quanta), apply the catalog, stage the held quanta, one
/// service quantum and the witness read, commit, then service ticks
/// between passes. Unlike the scenes above, nothing is admitted,
/// projected or committed before the first pass: the first pass itself
/// detects the caller and first projects its provider, and its
/// reconcile runs before that pass commits. Every stamp comes from one
/// clock, so a later pass's scan follows the earlier pass's reads.
struct LiveOrder {
    native: NativeScene,
    a: std::path::PathBuf,
    pins: crate::discovery::identity::PinnedObjects,
    offsets: Vec<u64>,
    generation: crate::inspect_system::MemberGeneration,
    caller: Option<CallerId>,
    /// After each pass: the edge count and the owner-unproven and
    /// demoted-placement gaps recorded so far.
    observed: Vec<(u64, Vec<String>)>,
}

impl LiveOrder {
    /// Service ticks between passes (live runs about ten per second).
    const TICKS: usize = 3;

    fn new() -> Self {
        use crate::discovery::caller_registry::ProcessSource;
        let scene = CaptureScene::new(68);
        scene.source.spawn(7, 500);
        let generation = crate::inspect_system::MemberGeneration {
            start_time: scene.source.start_time(7),
            exe: scene.source.exe_identity(7),
        };
        let mut native = NativeScene::over(scene, 0);
        native
            .scene
            .coordinator
            .binder
            .set_current_binding_clock(query_clock);
        native.answer(7, 500, 41);
        let a = native.scene.path.clone();
        let pins = fx::pass_pins(&[(&a, "sha-a")]);
        Self {
            native,
            a,
            pins,
            offsets: fx::offsets(68),
            generation,
            caller: None,
            observed: Vec::new(),
        }
    }

    fn catalog(&self, started: u64, finished: u64) -> crate::inspect_system::Catalog {
        let mut catalog = capture_catalog(&self.pins, &[&self.a], 7, Some(self.generation.clone()));
        catalog.processes[0].complete_scan =
            Some(crate::inspect_system::CompleteMemberScan::scripted(
                self.generation.clone(),
                started,
                finished,
            ));
        let targets: Vec<(&std::path::Path, u64)> = self
            .offsets
            .iter()
            .map(|offset| (self.a.as_path(), *offset))
            .collect();
        let modules = vec![fx::module_with_targets(&self.pins, &self.a, &targets)];
        catalog.lowering = Some(crate::inspect_system::CatalogLowering {
            plan: fx::lower_named(
                &modules,
                &self.pins,
                crate::plan::AdmissionPolicy::Inventory(
                    self.native.scene.coordinator.attach_set.budget(),
                ),
            ),
            pins: fx::pass_pins(&[(&self.a, "sha-a")]),
            modules: Vec::new(),
        });
        catalog
    }

    fn drain(&mut self) {
        QUERY_CLOCK.with(|clock| clock.set(self.native.stamps.tick()));
        self.native.drain();
    }

    fn read(&mut self, rows: Vec<WitnessRow>, counts: Vec<(u64, u64, usize, u64)>) {
        QUERY_CLOCK.with(|clock| clock.set(self.native.stamps.tick()));
        self.native.counts_read(rows, counts);
    }

    fn commit(&mut self) {
        self.native.scene.coordinator.commit_batch(false).unwrap();
    }

    /// One pass. `row` delivers the first-use witness row (read once,
    /// like live); `count` is the refreshed absolute count, if any.
    fn pass(&mut self, row: bool, count: Option<u64>) {
        let now = self.native.stamps.tick();
        let started = self.native.stamps.tick();
        let finished = self.native.stamps.tick();
        let held = self.native.stamps.drain(self.native.domain);
        QUERY_CLOCK.with(|clock| clock.set(self.native.stamps.tick()));
        let catalog = self.catalog(started, finished);
        self.native.scene.coordinator.apply_catalog(
            catalog,
            &mut crate::discovery::engine::inventory::UnavailableImageGuard,
            &mut self.native.cookies,
            now + 1_000_000,
            now,
        );
        self.caller = self.native.scene.coordinator.adapter.live_id(7);
        self.native.stage(held);
        self.drain();
        let rows = if row {
            let t0 = self.native.stamps.tick();
            let mut row = self.native.row(41, 1, 7, t0, 0);
            row.entry_count = 2_000;
            vec![row]
        } else {
            Vec::new()
        };
        let counts = count.map_or_else(Vec::new, |count| vec![(41, 1, 0, count)]);
        self.read(rows, counts);
        self.commit();
        self.note();
        for _ in 0..Self::TICKS {
            self.drain();
        }
    }

    /// The finite stop after the target exited (the live runner's order:
    /// the workload ends, then the observer is interrupted, with no pass
    /// between): the stop drain, the terminal read (before coverage
    /// ends), the post-stop refresh read and the domain's finish, then
    /// the final commit.
    fn stop_after_exit(&mut self, terminal: u64) {
        self.native.scene.source.kill(7);
        self.stop(terminal);
    }

    /// The same finite stop while the target still runs.
    fn stop(&mut self, terminal: u64) {
        self.native.scene.coordinator.stop();
        self.drain();
        self.read(Vec::new(), vec![(41, 1, 0, terminal)]);
        let at = self.native.stamps.tick();
        self.native.scene.coordinator.end_capture_coverage(at);
        self.drain();
        self.read(Vec::new(), vec![(41, 1, 0, terminal)]);
        let domain = self.native.domain;
        self.native.stage(NativeBatch::Finish { domain });
        self.commit();
        self.note();
    }

    fn note(&mut self) {
        let edge = self.caller.map_or(0, |caller| {
            self.native
                .scene
                .coordinator
                .registry()
                .edges_of(caller)
                .next()
                .map_or(0, |edge| edge.entry_count)
        });
        let gaps = self
            .native
            .scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .filter(|gap| {
                gap.reason.contains("physical owner is not proven")
                    || gap.subject == crate::discovery::caller_registry::DEMOTED_COUNT_PLACED
            })
            .map(|gap| format!("{}: {}", gap.subject, gap.reason))
            .collect();
        self.observed.push((edge, gaps));
    }
}

/// The live quiet, first-use and counted passes before the stop.
fn live_steady_passes() -> LiveOrder {
    let mut scene = LiveOrder::new();
    scene.pass(false, None);
    scene.pass(false, None);
    scene.pass(true, None);
    for count in [427_579, 608_121, 815_289] {
        scene.pass(false, Some(count));
    }
    scene
}

/// A steady single caller whose provider is first projected by the same
/// pass that detects the caller: after first use every refresh lands
/// exactly on its sole edge, and so does the terminal read at a stop
/// while the target runs. Live passes, in order: two quiet passes (the
/// gate is closed), the first-use row, then counted refreshes. No
/// owner-unproven range and no demoted placement may appear anywhere.
#[test]
fn steady_caller_first_projected_with_its_provider_attributes_every_count() {
    let mut scene = live_steady_passes();
    scene.stop(1_027_812);
    let expected: Vec<(u64, Vec<String>)> = [0, 0, 0, 427_579, 608_121, 815_289, 1_027_812]
        .into_iter()
        .map(|edge| (edge, Vec::new()))
        .collect();
    assert_eq!(
        scene.observed, expected,
        "per pass (edge count, owner-unproven and demoted-placement gaps)"
    );
}

/// The same caller exits after its last counted pass and the capture
/// stops before any pass classifies that exit. Every count up to the
/// last pass lands exactly; the tail read after the death stays
/// disclosed, never placed: no pass proved the exit, so the liveness
/// cancel holds (under `--pid` the lost scope custody cancels as well).
#[test]
fn steady_caller_exit_before_any_pass_classifies_it_discloses_only_the_tail() {
    let mut scene = live_steady_passes();
    scene.stop_after_exit(1_027_812);
    let (last, rest) = scene.observed.split_last().expect("stop observed");
    let expected: Vec<(u64, Vec<String>)> = [0, 0, 0, 427_579, 608_121, 815_289]
        .into_iter()
        .map(|edge| (edge, Vec::new()))
        .collect();
    assert_eq!(rest, expected.as_slice(), "every pass before the stop");
    assert_eq!(last.0, 815_289, "nothing past the last proven read lands");
    assert_eq!(last.1.len(), 1, "one disclosed tail: {:?}", last.1);
    assert!(
        last.1[0].contains("physical owner is not proven")
            && last.1[0].contains("(815289, 1027812]"),
        "the tail is disclosed exactly: {:?}",
        last.1
    );
}

/// The wait that keeps commit lag from failing count authority waits
/// only for the queuing projection's own publication. A module the
/// committed registry knows is judged at once; one it still does not
/// know after a later publication fails authority, and so does one
/// queued outside a projection.
#[test]
fn demotion_retirement_projected_observation_waits_only_for_its_own_publication() {
    use super::count_eligibility::CountOwnership;
    let mut scene = Scene::shared();
    let caller = scene.caller;
    let object = scene.native.scene.delta.endpoints[0].object.index();
    let known = scene
        .native
        .scene
        .coordinator
        .registry
        .modules()
        .find(|module| module.paths.iter().any(|path| path.ends_with("b.so")))
        .unwrap()
        .key
        .clone();
    let unknown = ModuleKey::physical(253, 7, 999_999, Some("sha-unstaged".into()), "");
    assert!(
        scene
            .native
            .scene
            .coordinator
            .registry
            .module_id_for(&unknown)
            .is_none()
    );
    let fresh = |scene: &Scene| {
        let coordinator = &scene.native.scene.coordinator;
        let mut ownership = CountOwnership::new(coordinator.registry.limits());
        assert!(ownership.register_pair(caller, object));
        ownership.invalidate_memberships(coordinator.attach_set.count_revision());
        ownership.begin_catalog_pass();
        ownership
    };
    let complete = |scene: &Scene| {
        Some(crate::inspect_system::CompleteMemberScan::scripted(
            scene.generation.clone(),
            300,
            301,
        ))
    };

    let mut ownership = fresh(&scene);
    let published = scene.native.scene.coordinator.registry.published_revision();
    assert!(ownership.queue_projected_observation(
        caller,
        vec![known],
        complete(&scene),
        published
    ));
    round4_settle_ownership(&mut ownership, &scene);
    assert_eq!(
        ownership.newest_accepted_post(caller),
        301,
        "known: judged at once"
    );
    assert_eq!(ownership.caller_authority_failure(caller), 0);

    let mut ownership = fresh(&scene);
    assert!(ownership.queue_projected_observation(
        caller,
        vec![unknown.clone()],
        complete(&scene),
        published
    ));
    round4_settle_ownership(&mut ownership, &scene);
    assert_eq!(
        ownership.newest_accepted_post(caller),
        0,
        "nothing accepted while waiting"
    );
    assert_eq!(
        ownership.caller_authority_failure(caller),
        0,
        "the projection's own commit lag is not failed authority"
    );
    scene.native.scene.coordinator.registry.publish();
    assert!(scene.native.scene.coordinator.registry.published_revision() > published);
    round4_settle_ownership(&mut ownership, &scene);
    assert_eq!(ownership.newest_accepted_post(caller), 0);
    assert_ne!(
        ownership.caller_authority_failure(caller),
        0,
        "still unknown after a later publication: authority fails"
    );

    let mut ownership = fresh(&scene);
    assert!(ownership.queue_observation(caller, vec![unknown], complete(&scene)));
    round4_settle_ownership(&mut ownership, &scene);
    assert_eq!(ownership.newest_accepted_post(caller), 0);
    assert_ne!(
        ownership.caller_authority_failure(caller),
        0,
        "unknown outside a projection: authority fails at once"
    );
}

/// The same wait covers an admission upgrade: a module the committed
/// registry knows but has not admitted is judged only after the
/// publication that carries the upgrade, not against the stale
/// pre-upgrade verdict. Staging Admitted over a published Refused,
/// then judging before the publish, must wait (nothing accepted, no
/// failure); after the publish the caller is judged with Admitted.
#[test]
fn demotion_retirement_projected_observation_waits_for_admission_upgrade() {
    use super::count_eligibility::CountOwnership;
    use crate::discovery::caller_registry::{AdmissionState, ModuleInfo};
    let mut scene = Scene::shared();
    let caller = scene.caller;
    let object = scene.native.scene.delta.endpoints[0].object.index();
    let key = ModuleKey::physical(253, 7, 999_998, Some("sha-flip".into()), "");
    let info = |admission: AdmissionState| ModuleInfo {
        path: "/lib/flip.so".into(),
        key: key.clone(),
        double_loaded: false,
        build_id: None,
        identity_source: Some("mountinfo".into()),
        admission,
        admission_class: Some("exact".into()),
        admission_endpoints: match admission {
            AdmissionState::Admitted => Some(1),
            AdmissionState::Refused | AdmissionState::Unresolved => None,
        },
        admission_reasons: match admission {
            AdmissionState::Admitted => Vec::new(),
            AdmissionState::Refused | AdmissionState::Unresolved => {
                vec!["attach-budget churn".into()]
            }
        },
    };
    scene.native.scene.coordinator.registry.note_mapping(
        caller,
        7,
        info(AdmissionState::Refused),
        400,
    );
    scene.native.scene.coordinator.registry.publish();
    let id = scene
        .native
        .scene
        .coordinator
        .registry
        .module_id_for(&key)
        .expect("published module is known");
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .registry
            .module(id)
            .expect("published module record")
            .admission,
        AdmissionState::Refused
    );
    let fresh = |scene: &Scene| {
        let coordinator = &scene.native.scene.coordinator;
        let mut ownership = CountOwnership::new(coordinator.registry.limits());
        assert!(ownership.register_pair(caller, object));
        ownership.invalidate_memberships(coordinator.attach_set.count_revision());
        ownership.begin_catalog_pass();
        ownership
    };
    let complete = |scene: &Scene| {
        Some(crate::inspect_system::CompleteMemberScan::scripted(
            scene.generation.clone(),
            300,
            301,
        ))
    };
    let mut ownership = fresh(&scene);
    let published = scene.native.scene.coordinator.registry.published_revision();
    scene.native.scene.coordinator.registry.note_mapping(
        caller,
        7,
        info(AdmissionState::Admitted),
        500,
    );
    assert!(ownership.queue_projected_observation(
        caller,
        vec![key.clone()],
        complete(&scene),
        published
    ));
    round4_settle_ownership(&mut ownership, &scene);
    assert_eq!(
        ownership.newest_accepted_post(caller),
        0,
        "nothing accepted while the upgrade is unpublished"
    );
    assert_eq!(
        ownership.caller_authority_failure(caller),
        0,
        "an unpublished admission upgrade is not failed authority"
    );
    scene.native.scene.coordinator.registry.publish();
    assert!(scene.native.scene.coordinator.registry.published_revision() > published);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .registry
            .module(id)
            .expect("upgraded module record")
            .admission,
        AdmissionState::Admitted
    );
    round4_settle_ownership(&mut ownership, &scene);
    assert_eq!(
        ownership.newest_accepted_post(caller),
        301,
        "after its publication the caller is judged with the Admitted admission"
    );
    assert_eq!(ownership.caller_authority_failure(caller), 0);
}

/// A forgotten caller releases its count-ownership header and summaries;
/// lifetime caller IDs may exceed the caller budget without a storage
/// refusal, and a later caller takes the freed slot.
#[test]
fn demotion_retirement_round4_forgotten_caller_releases_count_ownership() {
    let mut limits = RegistryLimits::default_limits();
    limits.max_callers = 2;
    let mut ownership = CountOwnership::new(limits);
    ownership.begin_catalog_pass();
    assert!(ownership.queue_projected_observation(CallerId(1), Vec::new(), None, 0));
    assert!(ownership.queue_projected_observation(CallerId(2), Vec::new(), None, 0));
    assert!(ownership.register_pair(CallerId(2), 7));
    assert_eq!(
        (ownership.caller_headers(), ownership.summary_rows()),
        (2, 1)
    );
    assert!(
        !ownership.queue_projected_observation(CallerId(3), Vec::new(), None, 0),
        "the live-retained budget still refuses a third caller"
    );
    ownership.forget_caller(CallerId(1));
    assert_eq!(ownership.caller_headers(), 1);
    assert!(
        ownership.queue_projected_observation(CallerId(3), Vec::new(), None, 0),
        "a forgotten caller's header is reusable"
    );
    ownership.forget_caller(CallerId(2));
    assert_eq!(ownership.summary_rows(), 0, "its pair summaries are gone");
    ownership.forget_caller(CallerId(3));
    assert_eq!(ownership.caller_headers(), 0);
}

fn round4_empty_catalog(
    native: &NativeScene,
    caller: CallerId,
    pid: u32,
    at: u64,
) -> crate::inspect_system::Catalog {
    let record = native.scene.coordinator.adapter.record(caller).unwrap();
    let generation = crate::inspect_system::MemberGeneration {
        start_time: record.start_time,
        exe: record.exe.clone(),
    };
    let mut catalog = capture_catalog(&native.scene.pins, &[], pid, Some(generation.clone()));
    catalog.processes[0].complete_scan = Some(crate::inspect_system::CompleteMemberScan::scripted(
        generation,
        at,
        at + 1,
    ));
    catalog
}

/// Lifecycle caller IDs can exceed `max_callers` once retired rows are
/// forgotten: the third lifetime caller is projected, does not read the
/// current-count-ownership refusal, and gets its metadata row.
#[test]
fn demotion_retirement_round4_lifetime_callers_exceed_the_retained_budget() {
    // The metadata worker slot is process-global: serialize with the
    // stop twins so neither side observes an unavailable lane.
    let _serial = crate::caller_metadata::runtime::job::test_support::worker_lock();
    let mut limits = RegistryLimits::default_limits();
    limits.max_callers = 2;
    let base = CaptureScene::with_limits(2, limits);
    let mut native = NativeScene::over(base, 0);
    native
        .scene
        .coordinator
        .binder
        .set_current_binding_clock(query_clock);
    native.scene.coordinator.enable_caller_metadata(1).unwrap();
    let mut ids = Vec::new();
    for (index, pid) in [7u32, 8, 9, 10].into_iter().enumerate() {
        let at = 100 + index as u64 * 100;
        native.scene.source.spawn(pid, 500 + u64::from(pid));
        let id = native
            .scene
            .coordinator
            .adapter
            .admit(pid, ImageAuthority::ScanPinned, at)
            .unwrap();
        ids.push(id);
        QUERY_CLOCK.with(|clock| clock.set(native.stamps.tick()));
        let catalog = round4_empty_catalog(&native, id, pid, at);
        native.scene.coordinator.apply_catalog(
            catalog,
            &mut UnavailableImageGuard,
            &mut native.cookies,
            at + 100,
            at,
        );
        native.scene.coordinator.commit_batch(false).unwrap();
        native.scene.coordinator.synchronize_caller_metadata(at + 1);
        let frame = native.scene.coordinator.metadata_frame();
        assert!(
            frame.contains(id),
            "caller {id:?} (lifetime {index}) has a metadata row"
        );
        assert_eq!(
            frame.summary.budget_refusals, 0,
            "no lifetime caller is refused metadata storage"
        );
        assert!(
            !native
                .scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .any(|gap| gap.subject == "current count ownership storage refused"),
            "no current count ownership storage refusal for a lifetime caller"
        );
        let events = native
            .scene
            .coordinator
            .adapter
            .exec_transition_scoped(id, at + 2);
        native
            .scene
            .coordinator
            .apply_reconcile_events(&events, at + 2);
        native.scene.coordinator.commit_batch(false).unwrap();
        native.scene.coordinator.note_rendered_callers(&[id]);
        assert_eq!(
            native
                .scene
                .coordinator
                .retire_rendered_callers(at + 3, None)
                .retired,
            1,
            "the proven-exited rendered caller retires"
        );
        assert!(
            native.scene.coordinator.adapter.record(id).is_none(),
            "the retired caller row is forgotten"
        );
        // M2: retirement releases the metadata slot too; without the
        // coordinator's `metadata.forget(id)` the lifetime table fills
        // and later callers read a storage refusal.
        let frame = native.scene.coordinator.metadata_frame();
        assert!(
            !frame.contains(id),
            "caller {id:?} (lifetime {index}) released its metadata row"
        );
        assert_eq!(
            frame.summary.budget_refusals, 0,
            "no lifetime caller is refused metadata storage after a retirement"
        );
    }
    assert_eq!(
        ids.len(),
        4,
        "more lifetime callers than the retained budget"
    );
    assert_eq!(
        native.scene.coordinator.count_ownership.caller_headers(),
        0,
        "each forgotten caller released its ownership header"
    );
}

/// Item 1: exited callers WITH attributed calls fold into the exact
/// per-module departed aggregate instead of holding caller slots: 5000
/// lifetime callers (past the 4096 budget) retire with zero refusals,
/// exact totals, a flat retained census, and gaps that keep naming the
/// folded callers.
#[test]
fn demotion_retirement_round5_lifetime_callers_with_calls_fold_past_the_budget() {
    // The metadata worker slot is process-global: serialize with the
    // stop twins so neither side observes an unavailable lane.
    let _serial = crate::caller_metadata::runtime::job::test_support::worker_lock();
    const LIFETIME: usize = 5000;
    const BATCH: usize = 16;
    const ENTRIES: [u64; 4] = [0, 1, 5, 100];
    let mut scene = Scene::placed();
    scene
        .native
        .scene
        .coordinator
        .enable_caller_metadata(1)
        .unwrap();
    let live_caller = scene.caller;
    let live_edges = scene.native.scene.coordinator.registry.edge_count();
    let charges_before = scene
        .native
        .scene
        .coordinator
        .registry
        .semantic_resource_snapshot();
    let mut expected_entries = 0u64;
    let mut expected_with_calls = 0u64;
    let mut rounds = 0u64;
    for base in (0..LIFETIME).step_by(BATCH) {
        // Small clocks like the other multi-round scenes: rows,
        // anchors and catalogs stay mutually fresh.
        let at = 2000 + rounds * 10;
        rounds += 1;
        let width = BATCH.min(LIFETIME - base);
        let mut members = Vec::new();
        let mut ids = Vec::new();
        for offset in 0..width {
            let index = base + offset;
            let pid = 50_000 + index as u32;
            // Match the catalog generation the members catalog claims
            // for every member (like pid 7's own spawn).
            let start = 500;
            let ticket = 100_000 + index as u64;
            let entries = ENTRIES[index % ENTRIES.len()];
            expected_entries = expected_entries.saturating_add(entries);
            if entries > 0 {
                expected_with_calls += 1;
            }
            scene.native.scene.source.spawn(pid, start);
            let id = scene
                .native
                .scene
                .coordinator
                .adapter
                .admit(pid, ImageAuthority::ScanPinned, at)
                .expect("a churn caller is never refused while folds recycle slots");
            ids.push(id);
            scene.native.scene.project_paths(pid, &[&scene.a], at);
            scene.native.scene.coordinator.commit_batch(false).unwrap();
            scene.native.answer(pid, start, ticket);
            // Rows must postdate admission (like round-2's t0=100 past
            // admit 80): a row predating admission never binds.
            let mut row = scene.native.row(ticket, 1, pid, at + 1, 0);
            row.entry_count = entries;
            scene.native.witness(vec![row]);
            members.push((pid, id, ticket));
            scene.native.scene.coordinator.registry.record_gap(
                crate::discovery::caller_registry::RegistryGap {
                    caller: Some(id),
                    module: None,
                    pid: Some(pid),
                    subject: "test fold gap".into(),
                    reason: "names a caller the fold retires".into(),
                    budget: None,
                },
            );
        }
        scene.apply(members_catalog(&scene, &members, true, at + 2), at + 2);
        // Recovery arming needs repeated reconciliation (bounded
        // service per round); mirror the round-2 quiet pattern.
        round2_quiet_ownership(&mut scene);
        for (k, &(_, id, _)) in members.iter().enumerate() {
            assert!(
                scene
                    .native
                    .scene
                    .coordinator
                    .registry
                    .edges_of(id)
                    .next()
                    .is_some(),
                "batch caller {id:?} holds a mapping edge before it exits"
            );
            assert_eq!(
                edge_count(&scene.native, id, "a.so"),
                ENTRIES[(base + k) % ENTRIES.len()],
                "batch caller {id:?} places its staged absolute"
            );
        }
        scene
            .native
            .scene
            .coordinator
            .synchronize_caller_metadata(at + 3);
        let frame = scene.native.scene.coordinator.metadata_frame();
        for id in &ids {
            assert!(
                frame.contains(*id),
                "live batch caller {id:?} has a metadata row"
            );
        }
        assert_eq!(
            frame.summary.budget_refusals, 0,
            "no batch caller is refused metadata storage"
        );
        for (pid, _, _) in &members {
            scene.native.scene.source.kill(*pid);
        }
        scene.native.scene.coordinator.observe_empty_pass(
            &mut UnavailableImageGuard,
            &mut scene.native.cookies,
            "test batch exit",
            at + 4,
        );
        scene.native.scene.coordinator.commit_batch(false).unwrap();
        scene.native.scene.coordinator.note_rendered_callers(&ids);
        assert_eq!(
            scene
                .native
                .scene
                .coordinator
                .retire_rendered_callers(at + 5, None)
                .retired,
            width as u64,
            "every proven-exited batch caller retires"
        );
        // The retained census plateaus: only the never-exiting scene
        // caller and its edges stay; churn leaves no slot behind.
        assert_eq!(
            scene.native.scene.coordinator.adapter().len(),
            1,
            "only the live scene caller stays admitted"
        );
        assert_eq!(
            scene.native.scene.coordinator.registry.edge_count(),
            live_edges,
            "only the live scene caller's edges stay"
        );
        let frame = scene.native.scene.coordinator.metadata_frame();
        for id in &ids {
            assert!(
                scene.native.scene.coordinator.adapter.record(*id).is_none(),
                "folded caller {id:?} holds no adapter row"
            );
            assert!(
                !frame.contains(*id),
                "folded caller {id:?} holds no metadata row"
            );
        }
    }
    let coordinator = &scene.native.scene.coordinator;
    assert_eq!(
        coordinator.retired_callers(),
        LIFETIME as u64,
        "every lifetime caller folded exactly once"
    );
    assert_eq!(
        coordinator.adapter().admit_refused() + coordinator.registry.callers_refused(),
        0,
        "no lifetime caller was refused a caller slot"
    );
    assert_eq!(
        coordinator.metadata_frame().summary.budget_refusals,
        0,
        "no lifetime caller was refused metadata storage"
    );
    // Four setup gaps exist beside the batch gaps (the placed row
    // predating admission, the empty-pass notice, two early ambiguous
    // endpoints); the batch gaps are counted by subject.
    assert_eq!(
        coordinator
            .registry
            .gaps()
            .iter()
            .filter(|gap| gap.subject == "test fold gap")
            .count(),
        LIFETIME,
        "every batch gap is retained"
    );
    // Gaps keep naming the folded callers by label; the rows are gone
    // but the evidence still resolves through the stream and the
    // departed aggregate.
    for gap in coordinator
        .registry
        .gaps()
        .iter()
        .filter(|gap| gap.subject == "test fold gap")
    {
        assert!(
            gap.caller
                .is_some_and(|caller| coordinator.adapter.record(caller).is_none()),
            "a retained gap names its folded caller"
        );
    }
    let charges_after = coordinator.registry.semantic_resource_snapshot();
    assert_eq!(
        charges_after.charged_bytes, charges_before.charged_bytes,
        "folds without semantic state charge nothing"
    );
    assert!(
        charges_after.peak_charged_bytes < charges_before.charged_bytes + 65_536,
        "peak stays transient (per-batch staging, never per-lifetime growth)"
    );
    let document = crate::inventory::render_json(coordinator, "test", 0, rounds * 10_000, rounds);
    assert_eq!(
        document["budgets"]["callers"]["retired"], LIFETIME as u64,
        "the report counts every folded caller"
    );
    assert_eq!(
        document["budgets"]["callers"]["retired_with_calls"], expected_with_calls,
        "the report counts the folded callers that carried calls"
    );
    // Two edges per caller (the counted a.so edge plus the watched
    // b.so catalog edge): both fold.
    assert_eq!(
        document["budgets"]["edges"]["folded"],
        2 * LIFETIME as u64,
        "the report counts every folded edge"
    );
    assert_eq!(
        document["budgets"]["edges"]["folded_entries"], expected_entries,
        "the report counts every folded entry"
    );
    // The logical total is folded entries plus the live scene
    // caller's own edge (the only row left in `edges[]`).
    let live_entries: u64 = document["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .map(|edge| edge["entries"]["count"].as_u64().expect("count"))
        .sum();
    assert_eq!(live_entries, 5, "the live scene caller keeps its 5");
    assert_eq!(
        document["layer_totals"]["logical_entries"]
            .as_u64()
            .expect("total"),
        expected_entries + live_entries,
        "folded entries stay in the logical total"
    );
    assert_eq!(
        document["layer_totals"]["forwarding_entries"], 0,
        "no forwarding layer observed these calls"
    );
    // Past the 4096-per-module identity bound the aggregate saturates
    // honestly: first rows named, the rest counted as dropped.
    for leaf in ["a.so", "b.so"] {
        let module = document["modules"]
            .as_array()
            .expect("modules array")
            .iter()
            .find(|module| {
                module["paths"].as_array().is_some_and(|paths| {
                    paths
                        .iter()
                        .any(|path| path.as_str().is_some_and(|path| path.ends_with(leaf)))
                })
            })
            .unwrap_or_else(|| panic!("the {leaf} module renders"));
        assert_eq!(module["departed_use"]["callers"], LIFETIME as u64);
        assert_eq!(module["departed_use"]["edges"], LIFETIME as u64);
        assert_eq!(
            module["departed_use"]["identities"]
                .as_array()
                .expect("identity rows")
                .len(),
            4096
        );
        assert_eq!(module["departed_use"]["identities_saturated"], true);
        assert_eq!(
            module["departed_use"]["identities_dropped"],
            LIFETIME as u64 - 4096
        );
    }
    assert_eq!(
        document["budgets"]["departed_use"]["identities_dropped"],
        2 * (LIFETIME as u64 - 4096)
    );
    // The never-exiting scene caller keeps its live row and edge: the
    // fold only retires proven-ended callers.
    let live = coordinator
        .adapter
        .record(live_caller)
        .expect("the live scene caller stays admitted");
    assert_eq!(live.lifecycle, CallerLifecycle::Mapped);
    assert!(
        coordinator.registry.edges_of(live_caller).next().is_some(),
        "the live scene caller keeps its edge"
    );
}

/// Item 1: a folded edge's counts, function/rv breakdown and identity
/// survive in the departed aggregate row-for-row: the module's
/// `departed_use` carries exactly what the edge showed before the fold.
#[test]
fn demotion_retirement_round5_folded_edge_semantics_stay_exact() {
    use crate::semantics_edge::SemanticCall;
    use p11scope_ebpf_common::capture;
    use pkcs11_types::CkRv;
    const MECH_SIGN: u64 = 0x0d;
    const MECH_DIGEST: u64 = 0x250;
    fn init(function: &str, session: u64, mechanism: u64, ts_ns: u64) -> SemanticCall {
        SemanticCall {
            function: function.into(),
            session,
            mechanism,
            capture: capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL,
            ts_ns,
            ..SemanticCall::default()
        }
    }
    fn op(function: &str, session: u64, ts_ns: u64) -> SemanticCall {
        SemanticCall {
            function: function.into(),
            session,
            capture: capture::MECHANISM_NONE | capture::OUTPUT_NON_NULL,
            ts_ns,
            ..SemanticCall::default()
        }
    }
    let mut scene = Scene::shared();
    let caller = scene.caller;
    let coordinator = &mut scene.native.scene.coordinator;
    let module_key = {
        let edge = coordinator
            .registry
            .edges_of(caller)
            .next()
            .expect("the shared scene stages one edge");
        coordinator
            .registry
            .module(edge.module)
            .expect("the edge module is retained")
            .key
            .clone()
    };
    // One completed sign, one failed digest, one still-live operation.
    coordinator.registry_mut().observe_semantic(
        caller,
        &module_key,
        init("C_SignInit", 7, MECH_SIGN, 300),
    );
    coordinator
        .registry_mut()
        .observe_semantic(caller, &module_key, op("C_Sign", 7, 310));
    coordinator.registry_mut().observe_semantic(
        caller,
        &module_key,
        init("C_DigestInit", 9, MECH_DIGEST, 320),
    );
    let mut failing = op("C_Digest", 9, 330);
    failing.rv = CkRv::GENERAL_ERROR.0;
    coordinator
        .registry_mut()
        .observe_semantic(caller, &module_key, failing);
    coordinator.registry_mut().observe_semantic(
        caller,
        &module_key,
        init("C_EncryptInit", 11, MECH_SIGN, 340),
    );
    coordinator.commit_batch(false).unwrap();
    // The fold input: the retired edge row, rendered after the exit.
    scene.native.scene.source.kill(7);
    scene.native.scene.coordinator.observe_empty_pass(
        &mut UnavailableImageGuard,
        &mut scene.native.cookies,
        "test s1 exit",
        1000,
    );
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    let coordinator = &scene.native.scene.coordinator;
    let retired = crate::inventory::render_json(coordinator, "test", 0, 1000, 1);
    let edge = retired["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .find(|edge| edge["caller"] == caller.label())
        .expect("the retired edge still renders before the fold")
        .clone();
    let caller_row = retired["callers"]
        .as_array()
        .expect("callers array")
        .iter()
        .find(|row| row["id"] == caller.label())
        .expect("the retired caller still renders before the fold")
        .clone();
    assert_eq!(edge["semantics"], "observed");
    assert_eq!(
        edge["mechanisms"].as_array().expect("mechanism rows").len(),
        2,
        "both mechanisms are claimed before the fold"
    );
    assert_eq!(caller_row["retired"], true);
    assert_eq!(caller_row["lifecycle"], "exited");
    let pre_entries = edge["entries"]["count"].as_u64().expect("entry count");
    scene
        .native
        .scene
        .coordinator
        .note_rendered_callers(&[caller]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(1001, None)
            .retired,
        1,
        "the proven-exited caller with calls retires"
    );
    // The suspended pair drops with its staged absolute into the
    // existing Dropped machinery (revival intact); its held read and
    // stalled recovery leave with it instead of pinning the caller.
    // Past the grace the staged absolute reaches the counted totals.
    assert!(
        scene.native.scene.coordinator.pair_counts.is_empty(),
        "no held read survives the fold"
    );
    assert!(
        scene.native.scene.coordinator.recoveries.is_empty(),
        "no stalled recovery survives the fold"
    );
    scene
        .native
        .scene
        .coordinator
        .prune_departed_native_state(1_000_000_000_000);
    assert_eq!(
        scene.native.scene.coordinator.pruned_pair_totals(),
        (1, 7),
        "the staged absolute reaches the counted totals"
    );
    assert!(
        scene.native.scene.coordinator.pair_targets.is_empty(),
        "the dropped pair prunes on schedule"
    );
    let coordinator = &scene.native.scene.coordinator;
    assert!(
        coordinator.adapter.record(caller).is_none(),
        "the folded caller holds no adapter row"
    );
    assert!(
        coordinator.registry.edges_of(caller).next().is_none(),
        "the folded edge leaves the registry"
    );
    assert_eq!(
        coordinator.registry.semantic_occupied(),
        0,
        "the fold releases the edge's semantic occupancy"
    );
    // The fold refunds the edge's semantic charges exactly: a control
    // scene folded without any S1 claims ends on the identical charge.
    // (More would leak; less would refund foreign charges.)
    let mut control = Scene::shared();
    let control_caller = control.caller;
    control.native.scene.source.kill(7);
    control.native.scene.coordinator.observe_empty_pass(
        &mut UnavailableImageGuard,
        &mut control.native.cookies,
        "test control exit",
        1000,
    );
    control
        .native
        .scene
        .coordinator
        .commit_batch(false)
        .unwrap();
    control
        .native
        .scene
        .coordinator
        .note_rendered_callers(&[control_caller]);
    assert_eq!(
        control
            .native
            .scene
            .coordinator
            .retire_rendered_callers(1001, None)
            .retired,
        1,
        "the control caller retires"
    );
    let charges_after = coordinator.registry.semantic_resource_snapshot();
    let charges_control = control
        .native
        .scene
        .coordinator
        .registry
        .semantic_resource_snapshot();
    assert_eq!(
        charges_after.charged_bytes, charges_control.charged_bytes,
        "the fold refunds the edge's semantic charges"
    );
    let folded = crate::inventory::render_json(coordinator, "test", 0, 1001, 2);
    assert!(
        folded["edges"].as_array().expect("edges array").is_empty(),
        "no edge row survives the fold"
    );
    assert!(
        folded["callers"]
            .as_array()
            .expect("callers array")
            .is_empty(),
        "no caller row survives the fold"
    );
    assert_eq!(folded["budgets"]["callers"]["retired"], 1);
    assert_eq!(folded["budgets"]["callers"]["retired_with_calls"], 1);
    // Two edges: the counted a.so edge and the watched b.so edge.
    assert_eq!(folded["budgets"]["edges"]["folded"], 2);
    assert_eq!(folded["budgets"]["edges"]["folded_entries"], pre_entries);
    assert_eq!(folded["layer_totals"]["logical_entries"], pre_entries);
    let module = folded["modules"]
        .as_array()
        .expect("modules array")
        .iter()
        .find(|module| {
            module["paths"].as_array().is_some_and(|paths| {
                paths
                    .iter()
                    .any(|path| path.as_str().is_some_and(|path| path.ends_with("a.so")))
            })
        })
        .expect("the provider module renders")
        .clone();
    // One folded edge: every distribution holds exactly the edge row's
    // own values, so the aggregate row reads identically in meaning.
    let departed = &module["departed_use"];
    assert_eq!(departed["callers"], 1);
    assert_eq!(departed["edges"], 1);
    assert_eq!(departed["entries"]["count"], pre_entries);
    assert_eq!(
        departed["entries"]["saturated"],
        u64::from(edge["entries"]["saturated"].as_bool().expect("saturated")),
    );
    assert_eq!(
        departed["entries"]["first_min_ns"],
        edge["entries"]["first_seen_ns"],
    );
    assert_eq!(
        departed["entries"]["last_max_ns"],
        edge["entries"]["last_seen_ns"]
    );
    assert_eq!(departed["entries"]["in_flight"], 0);
    assert_eq!(departed["entries"]["logical"], pre_entries);
    assert_eq!(departed["entries"]["forwarding"], 0);
    let observation = edge["entries"]["observation"]
        .as_str()
        .expect("observation");
    assert_eq!(departed["entries"]["observation"][observation], 1);
    let coverage = &edge["entries"]["coverage"];
    let state = coverage["state"].as_str().expect("coverage state");
    for (key, want) in [
        ("counted", u64::from(state == "counted")),
        ("witnessed", u64::from(state == "witnessed")),
        ("watched_no_use", u64::from(state == "watched_no_use")),
    ] {
        assert_eq!(departed["entries"]["coverage"][key], want, "coverage {key}");
    }
    assert_eq!(
        departed["entries"]["coverage"]["since_min_ns"],
        coverage["since_ns"],
    );
    assert_eq!(
        departed["entries"]["coverage"]["until_max_ns"],
        coverage["until_ns"],
    );
    assert_eq!(
        departed["entries"]["coverage"]["first_min_ns"],
        coverage["first_ns"],
    );
    let mapping = &edge["mapping"];
    for (key, want) in [
        ("mapped", u64::from(mapping["state"] == "mapped")),
        ("ended", u64::from(mapping["state"] == "ended")),
        ("uncertain", u64::from(mapping["state"] == "uncertain")),
    ] {
        assert_eq!(departed["mapping"]["state"][key], want, "mapping {key}");
    }
    let evidence = mapping["evidence"].as_str().expect("mapping evidence");
    assert_eq!(departed["mapping"]["evidence"][evidence], 1);
    assert_eq!(
        departed["mapping"]["interruptions"],
        mapping["interruptions"]
    );
    assert_eq!(
        departed["mapping"]["first_min_ns"],
        mapping["first_seen_ns"]
    );
    assert_eq!(departed["mapping"]["last_max_ns"], mapping["last_seen_ns"]);
    assert_eq!(departed["mapping"]["reasons_overflow"], 0);
    if let Some(reason) = mapping["reason"].as_str() {
        assert_eq!(departed["mapping"]["reasons"][reason], 1);
    }
    let label = edge["semantics"].as_str().expect("semantic label");
    assert_eq!(departed["semantics"]["labels"][label], 1);
    assert_eq!(
        departed["mechanisms"], edge["mechanisms"],
        "every mechanism row survives with its function/rv breakdown"
    );
    assert_eq!(departed["mechanisms_overflow"]["mechs"], 0);
    assert_eq!(departed["mechanisms_overflow"]["calls"], 0);
    assert_eq!(departed["mechanisms_overflow"]["errors"], 0);
    let operations = &edge["operations"];
    for key in [
        "calls",
        "started",
        "completed",
        "cancelled",
        "failed",
        "unknown",
        "orphans",
        "dropped",
        "last_seen_ns",
    ] {
        assert_eq!(
            departed["operations"][key], operations[key],
            "operations {key}"
        );
    }
    assert_eq!(departed["operations"]["evidence"], operations["evidence"]);
    assert!(
        departed["operations"]["active"]
            .as_array()
            .expect("active array")
            .is_empty(),
        "no live machine survives the fold"
    );
    // The exit retired the edge before the fold, so its live operation
    // already ended unknown there: the fold itself settles nothing.
    assert_eq!(departed["operations"]["settled_machines"], 0);
    assert_eq!(departed["operations"]["settled_pending"], 0);
    assert_eq!(departed["operations"]["settled_detached"], 0);
    assert_eq!(departed["operations"]["settled_open"], 0);
    assert!(
        departed["operations"]["settled_active"]
            .as_array()
            .expect("settled array")
            .is_empty()
    );
    assert_eq!(departed["operations"]["settled_active_overflow"], 0);
    assert_eq!(departed["instances"]["folded"], 0);
    let identities = departed["identities"].as_array().expect("identity rows");
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0]["caller"], caller_row["id"]);
    assert_eq!(identities[0]["pid"], caller_row["pid"]);
    assert_eq!(identities[0]["start_time"], caller_row["start_time"]);
    assert_eq!(identities[0]["incarnation"], caller_row["incarnation"]);
    assert_eq!(identities[0]["exe"], caller_row["image"]["exe"]);
    assert_eq!(identities[0]["authority"], caller_row["image"]["authority"]);
    assert_eq!(identities[0]["lifecycle"], caller_row["lifecycle"]);
    assert_eq!(
        identities[0]["lifecycle_reason"],
        caller_row["lifecycle_reason"]
    );
    assert_eq!(
        identities[0]["exec_observed"],
        caller_row["image"]["exec_observed"]
    );
    assert_eq!(departed["identities_saturated"], false);
    assert_eq!(departed["identities_dropped"], 0);
    // The watched b.so edge folds into its own module row with zero
    // entries; the caller is named under both modules it touched.
    let other = folded["modules"]
        .as_array()
        .expect("modules array")
        .iter()
        .find(|module| {
            module["paths"].as_array().is_some_and(|paths| {
                paths
                    .iter()
                    .any(|path| path.as_str().is_some_and(|path| path.ends_with("b.so")))
            })
        })
        .expect("the b.so module renders");
    assert_eq!(other["departed_use"]["callers"], 1);
    assert_eq!(other["departed_use"]["edges"], 1);
    assert_eq!(other["departed_use"]["entries"]["count"], 0);
}

/// Item 1: a folded load lifetime survives in the departed aggregate:
/// the instance row's state and reason, its API returns, and its S1
/// rows fold exactly, including a lossy history.
#[test]
fn demotion_retirement_round5_folded_instances_stay_exact() {
    use crate::discovery::caller_registry::instance_input::{
        AdmittedInstance, AdmittedInstanceCall, InstanceKey,
    };
    use crate::semantics_edge::SemanticCall;
    use p11scope_ebpf_common::{ImageIdentity, capture};
    let mut scene = Scene::shared();
    let caller = scene.caller;
    let coordinator = &mut scene.native.scene.coordinator;
    let module_key = {
        let edge = coordinator
            .registry
            .edges_of(caller)
            .next()
            .expect("the shared scene stages one edge");
        coordinator
            .registry
            .module(edge.module)
            .expect("the edge module is retained")
            .key
            .clone()
    };
    let key = InstanceKey::scripted(
        scene.native.domain,
        ImageIdentity {
            task_cookie: 41,
            exec_id: 1,
        },
        crate::discovery::instances::InstanceId::from_raw(3),
        module_key,
    );
    coordinator
        .registry_mut()
        .note_instance(AdmittedInstance::scripted(key.clone(), caller));
    coordinator.commit_batch(false).unwrap();
    let facts = |function: &str, ts_ns: u64| SemanticCall {
        function: function.into(),
        session: 7,
        mechanism: 0x40,
        capture: capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL,
        ts_ns,
        ..SemanticCall::default()
    };
    coordinator
        .registry_mut()
        .observe_instance_semantic(AdmittedInstanceCall::scripted(
            key.clone(),
            caller,
            1,
            facts("C_SignInit", 300),
        ));
    coordinator
        .registry_mut()
        .observe_instance_semantic(AdmittedInstanceCall::scripted(
            key.clone(),
            caller,
            2,
            facts("C_Sign", 310),
        ));
    coordinator.commit_batch(false).unwrap();
    // One more call under an unproven mapping: the history goes lossy
    // with its reason kept.
    coordinator.registry_mut().note_member_unscanned(caller);
    coordinator.commit_batch(false).unwrap();
    coordinator
        .registry_mut()
        .observe_instance_semantic(AdmittedInstanceCall::scripted(
            key.clone(),
            caller,
            3,
            facts("C_Sign", 320),
        ));
    coordinator.commit_batch(false).unwrap();
    scene.native.scene.source.kill(7);
    scene.native.scene.coordinator.observe_empty_pass(
        &mut UnavailableImageGuard,
        &mut scene.native.cookies,
        "test instance exit",
        1000,
    );
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    let coordinator = &scene.native.scene.coordinator;
    let retired = crate::inventory::render_json(coordinator, "test", 0, 1000, 1);
    let instance = retired["instances"]
        .as_array()
        .expect("instances array")
        .iter()
        .find(|row| row["caller"] == caller.label())
        .expect("the retired instance still renders before the fold")
        .clone();
    assert_eq!(instance["state"], "retired");
    let child = retired["semantic_edges"]
        .as_array()
        .expect("semantic edges array")
        .iter()
        .find(|row| row["caller"] == caller.label())
        .expect("the retired semantic row still renders before the fold")
        .clone();
    assert_eq!(child["api_returns"]["count"], 3);
    assert!(child["coverage"]["lossy"].as_bool().expect("lossy"));
    scene
        .native
        .scene
        .coordinator
        .note_rendered_callers(&[caller]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(1001, None)
            .retired,
        1,
        "the proven-exited caller with an instance retires"
    );
    let coordinator = &scene.native.scene.coordinator;
    assert!(
        coordinator
            .registry
            .instances()
            .all(|row| row.caller != caller),
        "the folded instance leaves the registry"
    );
    let folded = crate::inventory::render_json(coordinator, "test", 0, 1001, 2);
    assert!(
        folded["instances"]
            .as_array()
            .expect("instances array")
            .is_empty(),
        "no instance row survives the fold"
    );
    assert!(
        folded["semantic_edges"]
            .as_array()
            .expect("semantic edges array")
            .is_empty(),
        "no semantic row survives the fold"
    );
    assert_eq!(folded["budgets"]["instances"]["folded"], 1);
    let module = folded["modules"]
        .as_array()
        .expect("modules array")
        .iter()
        .find(|module| {
            module["paths"].as_array().is_some_and(|paths| {
                paths
                    .iter()
                    .any(|path| path.as_str().is_some_and(|path| path.ends_with("a.so")))
            })
        })
        .expect("the provider module renders")
        .clone();
    let departed = &module["departed_use"];
    let folded_instances = &departed["instances"];
    assert_eq!(folded_instances["folded"], 1);
    assert_eq!(folded_instances["retired"], 1);
    assert_eq!(folded_instances["observed"], 0);
    assert_eq!(folded_instances["uncertain"], 0);
    assert_eq!(folded_instances["settled_live"], 0);
    let reason = instance["reason"].as_str().expect("instance reason");
    assert_eq!(folded_instances["reasons"][reason], 1);
    assert_eq!(folded_instances["first_min_ns"], instance["first_seen_ns"]);
    assert_eq!(folded_instances["last_max_ns"], instance["last_seen_ns"]);
    assert_eq!(
        folded_instances["api_returns"],
        child["api_returns"]["count"]
    );
    assert_eq!(
        folded_instances["api_returns_saturated_rows"],
        u64::from(
            child["api_returns"]["saturated"]
                .as_bool()
                .expect("saturated")
        ),
    );
    assert_eq!(
        folded_instances["historical_only_returns"],
        child["api_returns"]["historical_only_returns"]
    );
    assert_eq!(
        folded_instances["lossy_rows"],
        u64::from(child["coverage"]["lossy"].as_bool().expect("lossy")),
    );
    for reason in child["coverage"]["reasons"]
        .as_array()
        .expect("loss reasons")
    {
        let reason = reason.as_str().expect("reason code");
        assert_eq!(
            folded_instances["loss_reasons"][reason], 1,
            "loss reason {reason}"
        );
    }
    // The instance's own S1 rows fold through the same aggregate as
    // the edge's: mechanisms identical, operations identical.
    assert_eq!(departed["mechanisms"], child["mechanisms"]);
    let operations = child["operations"].as_object().expect("operations");
    for (key, value) in operations {
        if key == "active" {
            continue;
        }
        assert_eq!(
            departed["operations"][key.as_str()],
            *value,
            "instance operations {key}"
        );
    }
    assert_eq!(departed["operations"]["settled_machines"], 0);
    assert_eq!(departed["operations"]["settled_pending"], 0);
    assert_eq!(departed["operations"]["settled_detached"], 0);
    assert_eq!(departed["operations"]["settled_open"], 0);
}

/// Item 1: an exec-retired caller with calls folds exactly, and live
/// operations still open at the fold end unknown with explicit
/// accounting — never silently completed, never silently dropped.
#[test]
fn demotion_retirement_round5_exec_retired_live_operations_settle_at_fold() {
    use crate::semantics_edge::SemanticCall;
    use p11scope_ebpf_common::capture;
    let mut scene = Scene::shared();
    let old = scene.caller;
    let coordinator = &mut scene.native.scene.coordinator;
    let module_key = {
        let edge = coordinator
            .registry
            .edges_of(old)
            .next()
            .expect("the shared scene stages one edge");
        coordinator
            .registry
            .module(edge.module)
            .expect("the edge module is retained")
            .key
            .clone()
    };
    coordinator.registry_mut().observe_semantic(
        old,
        &module_key,
        SemanticCall {
            function: "C_SignInit".into(),
            session: 7,
            mechanism: 0x0d,
            capture: capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL,
            ts_ns: 300,
            ..SemanticCall::default()
        },
    );
    coordinator.registry_mut().observe_semantic(
        old,
        &module_key,
        SemanticCall {
            function: "C_Sign".into(),
            session: 7,
            capture: capture::MECHANISM_NONE | capture::OUTPUT_NON_NULL,
            ts_ns: 310,
            ..SemanticCall::default()
        },
    );
    // Still open when the image execs away: no completion can follow.
    coordinator.registry_mut().observe_semantic(
        old,
        &module_key,
        SemanticCall {
            function: "C_DigestInit".into(),
            session: 9,
            mechanism: 0x250,
            capture: capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL,
            ts_ns: 320,
            ..SemanticCall::default()
        },
    );
    coordinator.commit_batch(false).unwrap();
    let live = crate::inventory::render_json(coordinator, "test", 0, 400, 1);
    let live_edge = live["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .find(|edge| edge["caller"] == old.label())
        .expect("the live edge renders")
        .clone();
    assert_eq!(
        live_edge["operations"]["active"]
            .as_array()
            .expect("active machines")
            .len(),
        1,
        "one operation is still open before the exec"
    );
    let events = scene
        .native
        .scene
        .coordinator
        .adapter
        .exec_transition_scoped(old, 500);
    scene
        .native
        .scene
        .coordinator
        .apply_reconcile_events(&events, 500);
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    let coordinator = &scene.native.scene.coordinator;
    let retired = crate::inventory::render_json(coordinator, "test", 0, 500, 2);
    let edge = retired["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .find(|edge| edge["caller"] == old.label())
        .expect("the exec-retired edge still renders before the fold")
        .clone();
    let live_at_fold: u64 = edge["operations"]["active"]
        .as_array()
        .expect("active machines")
        .iter()
        .map(|machine| machine["count"].as_u64().expect("machine count"))
        .sum();
    scene.native.scene.coordinator.note_rendered_callers(&[old]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(501, None)
            .retired,
        1,
        "the proven exec-retired caller with calls retires"
    );
    // ScopedDenied admits no successor (the next catalog admits the
    // pid afresh); the fold only needs the retired old caller.
    let coordinator = &scene.native.scene.coordinator;
    assert!(
        coordinator.adapter.live_id(7).is_none(),
        "no successor in the scoped-denied scope"
    );
    let folded = crate::inventory::render_json(coordinator, "test", 0, 501, 3);
    assert_eq!(folded["budgets"]["callers"]["retired"], 1);
    assert_eq!(folded["budgets"]["callers"]["retired_with_calls"], 1);
    let module = folded["modules"]
        .as_array()
        .expect("modules array")
        .iter()
        .find(|module| {
            module["paths"].as_array().is_some_and(|paths| {
                paths
                    .iter()
                    .any(|path| path.as_str().is_some_and(|path| path.ends_with("a.so")))
            })
        })
        .expect("the provider module renders")
        .clone();
    let departed = &module["departed_use"];
    assert_eq!(departed["callers"], 1);
    assert_eq!(departed["edges"], 1);
    // Exactly the machines still open at the fold end unknown there;
    // their category/state distribution is preserved, not dropped.
    assert_eq!(departed["operations"]["settled_machines"], live_at_fold);
    assert_eq!(
        departed["operations"]["unknown"].as_u64().expect("unknown"),
        edge["operations"]["unknown"].as_u64().expect("unknown") + live_at_fold,
    );
    let mut settled: Vec<(String, String, u64)> = departed["operations"]["settled_active"]
        .as_array()
        .expect("settled array")
        .iter()
        .map(|machine| {
            (
                machine["category"].as_str().expect("category").to_string(),
                machine["state"].as_str().expect("state").to_string(),
                machine["count"].as_u64().expect("count"),
            )
        })
        .collect();
    settled.sort();
    let mut open: Vec<(String, String, u64)> = edge["operations"]["active"]
        .as_array()
        .expect("active array")
        .iter()
        .map(|machine| {
            (
                machine["category"].as_str().expect("category").to_string(),
                machine["state"].as_str().expect("state").to_string(),
                machine["count"].as_u64().expect("count"),
            )
        })
        .collect();
    open.sort();
    assert_eq!(settled, open);
    for key in [
        "calls",
        "started",
        "completed",
        "cancelled",
        "failed",
        "orphans",
        "dropped",
        "last_seen_ns",
    ] {
        assert_eq!(
            departed["operations"][key], edge["operations"][key],
            "operations {key}"
        );
    }
}

/// Item 1: the `-v` memory line attributes the departed aggregate to
/// its own rows, so folded state never reads as unattributed growth.
#[test]
fn demotion_retirement_round5_folded_state_has_memory_rows() {
    let mut scene = Scene::shared();
    let caller = scene.caller;
    scene.native.scene.source.kill(7);
    scene.native.scene.coordinator.observe_empty_pass(
        &mut UnavailableImageGuard,
        &mut scene.native.cookies,
        "test memory exit",
        1000,
    );
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    scene
        .native
        .scene
        .coordinator
        .note_rendered_callers(&[caller]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(1001, None)
            .retired,
        1,
        "the proven-exited caller retires"
    );
    let lens = scene.native.scene.coordinator.registry.memory_lens();
    assert_eq!(
        lens.departed_identities.len, 2,
        "the caller is named under both modules it touched"
    );
    assert!(
        lens.departed_identities.bytes > 0,
        "the identity row estimates bytes"
    );
    assert_eq!(
        lens.departed_mechs.len, 0,
        "no mechanism rows folded without claims"
    );
}

/// Fix round 6, blocking 1: a Dropped pair with a live recovery naming
/// the folded caller must settle at the fold (gap + remove), never
/// suspend into a live target naming the folded caller. Place, drop
/// via the rejected-row path (which leaves the recovery, like
/// production), fold, service: no Suspended names the folded caller,
/// the dropped base prunes into the exact totals, and a revival
/// attributes exactly new minus base.
#[test]
fn demotion_retirement_round6_dropped_pair_recovery_settles_at_fold() {
    use crate::discovery::caller_registry::DEMOTED_COUNT_REJECTED;
    let mut scene = Scene::shared();
    let folded = scene.caller;
    let coordinator = &mut scene.native.scene.coordinator;
    let key = coordinator
        .recoveries
        .keys()
        .next()
        .copied()
        .expect("the shared scene places one pair with a recovery");
    assert!(
        matches!(
            coordinator.pair_targets.get(&key),
            Some(
                PairTarget::Bound { caller, .. }
                    | PairTarget::Pending { caller, .. }
                    | PairTarget::Suspended { caller, .. }
            ) if *caller == folded
        ),
        "the placed pair targets the caller before the drop"
    );
    let watermark = coordinator.recoveries[&key].watermark;
    // A newer held absolute the recovery has not yet accounted: staged
    // only (no commit), so the watermark stays behind and the drop
    // base diverges from it — the realistic distinct-quantity case.
    scene
        .native
        .counts_read(Vec::new(), vec![(41, 1, 0, watermark.saturating_add(3))]);
    // A later rejected row for the same pair drops through the
    // production drop path, which preserves the recovery (the
    // precondition the fold must settle).
    let row = scene.native.row(41, 1, 7, 300, 0);
    assert_eq!(
        PairKey::of(&row),
        key,
        "the rejected row names the placed pair"
    );
    let base = scene.native.scene.coordinator.drop_pair_count(
        &row,
        crate::inventory_diagnostics::DiagnosticReason::NotAdmitted,
    );
    let coordinator = &scene.native.scene.coordinator;
    assert!(
        matches!(
            coordinator.pair_targets.get(&key),
            Some(PairTarget::Dropped { base: dropped, .. }) if *dropped == base
        ),
        "the rejected row drops the pair with its staged absolute"
    );
    assert!(
        coordinator
            .recoveries
            .get(&key)
            .is_some_and(|recovery| recovery.caller == folded),
        "the drop leaves the live recovery naming the caller"
    );
    assert_ne!(
        base, watermark,
        "the test needs distinct base and watermark to catch a rebase past the watermark"
    );
    // A withheld range the fold must disclose, not silence.
    let withheld = watermark.saturating_add(5);
    scene
        .native
        .scene
        .coordinator
        .recoveries
        .get_mut(&key)
        .expect("live recovery")
        .withheld_through = withheld.max(base);
    let gaps_before = scene
        .native
        .scene
        .coordinator
        .registry
        .gaps()
        .iter()
        .filter(|gap| gap.subject == DEMOTED_COUNT_REJECTED)
        .count();
    scene.native.scene.source.kill(7);
    scene.native.scene.coordinator.observe_empty_pass(
        &mut UnavailableImageGuard,
        &mut scene.native.cookies,
        "test dropped-recovery exit",
        1000,
    );
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    scene
        .native
        .scene
        .coordinator
        .note_rendered_callers(&[folded]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(1001, None)
            .retired,
        1,
        "the proven-exited caller folds"
    );
    assert!(
        scene
            .native
            .scene
            .coordinator
            .adapter
            .record(folded)
            .is_none(),
        "the folded caller holds no adapter row"
    );
    // Per-pass servicing must not resurrect a live target naming the
    // folded caller.
    round2_quiet_ownership(&mut scene);
    // Servicing stages gap mutations; commit applies them so the
    // disclosure is visible in gaps().
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    let coordinator = &scene.native.scene.coordinator;
    assert!(
        coordinator
            .recoveries
            .values()
            .all(|recovery| recovery.caller != folded),
        "no stranded recovery names the folded caller"
    );
    assert!(
        coordinator
            .pair_targets
            .values()
            .all(|target| match target {
                PairTarget::Suspended { caller, .. } => *caller != folded,
                PairTarget::Bound { caller, .. } | PairTarget::Pending { caller, .. } =>
                    *caller != folded,
                PairTarget::Dropped { .. } => true,
            }),
        "servicing never suspends a live target naming the folded caller"
    );
    assert!(
        matches!(
            coordinator.pair_targets.get(&key),
            Some(PairTarget::Dropped { base: dropped, .. }) if *dropped == base
        ),
        "the dropped base survives the fold and servicing unchanged"
    );
    let gaps_after = coordinator
        .registry
        .gaps()
        .iter()
        .filter(|gap| gap.subject == DEMOTED_COUNT_REJECTED)
        .count();
    assert!(
        gaps_after > gaps_before,
        "the withheld range is disclosed as a retirement-count gap, never silent"
    );
    // The dropped base prunes into the exact totals on schedule.
    scene
        .native
        .scene
        .coordinator
        .prune_departed_native_state(1_000_000_000_000);
    assert_eq!(
        scene.native.scene.coordinator.pruned_pair_totals(),
        (1, base),
        "the staged absolute reaches the counted totals exactly once"
    );
    assert!(
        !scene
            .native
            .scene
            .coordinator
            .pair_targets
            .contains_key(&key),
        "the dropped pair prunes on schedule"
    );
    // A revival past the pruned base (cookie reuse by a new process)
    // attributes exactly new minus base, never past a watermark.
    let growth = 3u64;
    let revived_absolute = base.saturating_add(growth);
    scene.native.scene.source.spawn(8, 800);
    let revived = scene
        .native
        .scene
        .coordinator
        .adapter
        .admit(8, ImageAuthority::ScanPinned, 2000)
        .expect("the reviving caller admits");
    scene.native.scene.project_paths(8, &[&scene.a], 2001);
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    scene.native.answer(8, 800, 41);
    let repeat = scene.native.row(41, 1, 8, 2002, 0);
    assert_eq!(
        PairKey::of(&repeat),
        key,
        "the reviving row names the pruned pair"
    );
    scene.native.witness(vec![repeat]);
    scene
        .native
        .counts_read(Vec::new(), vec![(41, 1, 0, revived_absolute)]);
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    assert_eq!(
        edge_count(&scene.native, revived, "a.so"),
        growth,
        "a revival past the pruned base stages post-drop growth only"
    );
}

/// Fix round 6, blocking 1 (servicing choke point): a recovery whose
/// caller record is gone — a stranded entry from before the fold fix,
/// or any future forget path — must settle (gap + remove) when
/// serviced, never suspend into a live target naming the gone caller
/// or clobber a revived pair. Dropped base preserved, prunes exact.
#[test]
fn demotion_retirement_round6_gone_caller_recovery_settles_without_suspend() {
    use crate::discovery::caller_registry::DEMOTED_COUNT_REJECTED;
    let mut scene = Scene::shared();
    let gone = scene.caller;
    let coordinator = &mut scene.native.scene.coordinator;
    let key = coordinator
        .recoveries
        .keys()
        .next()
        .copied()
        .expect("the shared scene places one pair with a recovery");
    let watermark = coordinator.recoveries[&key].watermark;
    let endpoint = coordinator.recoveries[&key].endpoint;
    let carrier = coordinator.recoveries[&key].carrier;
    let checkpoint = coordinator.recoveries[&key].ordinary_checkpoint;
    scene
        .native
        .counts_read(Vec::new(), vec![(41, 1, 0, watermark.saturating_add(3))]);
    let row = scene.native.row(41, 1, 7, 300, 0);
    assert_eq!(PairKey::of(&row), key, "the drop names the placed pair");
    let base = scene.native.scene.coordinator.drop_pair_count(
        &row,
        crate::inventory_diagnostics::DiagnosticReason::NotAdmitted,
    );
    assert_ne!(
        base, watermark,
        "the test needs distinct base and watermark"
    );
    scene.native.scene.source.kill(7);
    scene.native.scene.coordinator.observe_empty_pass(
        &mut UnavailableImageGuard,
        &mut scene.native.cookies,
        "test choke exit",
        1000,
    );
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    scene
        .native
        .scene
        .coordinator
        .note_rendered_callers(&[gone]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(1001, None)
            .retired,
        1,
        "the proven-exited caller folds"
    );
    assert!(
        scene
            .native
            .scene
            .coordinator
            .adapter
            .record(gone)
            .is_none(),
        "the folded caller holds no adapter row"
    );
    // Simulate a stranded pre-fix entry: a live recovery naming the
    // gone caller over a Dropped target (or a pruned pair). Servicing
    // must settle it, never suspend.
    let gaps_before = scene
        .native
        .scene
        .coordinator
        .registry
        .gaps()
        .iter()
        .filter(|gap| gap.subject == DEMOTED_COUNT_REJECTED)
        .count();
    // Ensure a Dropped target with the original base (fold may have
    // left Suspended→Dropped with a rewritten base pre-fix; restore
    // the exact base to isolate the choke point from the fold fix).
    scene.native.scene.coordinator.pair_targets.insert(
        key,
        PairTarget::Dropped {
            base,
            base_since: 300,
        },
    );
    scene.native.scene.coordinator.pair_counts.remove(&key);
    scene.native.scene.coordinator.recoveries.remove(&key);
    scene
        .native
        .scene
        .coordinator
        .recovery_order
        .retain(|ordered| *ordered != key);
    scene.native.scene.coordinator.recoveries.insert(
        key,
        PairRecovery {
            caller: gone,
            endpoint,
            carrier,
            ordinary_checkpoint: checkpoint,
            epoch: None,
            scan: None,
            sighting: None,
            fence: None,
            pending_reads: [None, None, None],
            withheld_through: base.saturating_add(2),
            discarded_through: watermark,
            watermark,
            blocked: false,
            recovered: false,
            deferred_count: false,
            receipt_refused: false,
            epoch_pending: false,
            diagnostic: RecoveryDiagnostics::default(),
        },
    );
    scene.native.scene.coordinator.recovery_order.push(key);
    round2_quiet_ownership(&mut scene);
    // Servicing stages gap mutations; commit applies them so the
    // disclosure is visible in gaps().
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    let coordinator = &scene.native.scene.coordinator;
    assert!(
        !coordinator.recoveries.contains_key(&key),
        "a gone caller's recovery is settled and removed, never retained"
    );
    assert!(
        coordinator
            .pair_targets
            .values()
            .all(|target| match target {
                PairTarget::Suspended { caller, .. } => *caller != gone,
                PairTarget::Bound { caller, .. } | PairTarget::Pending { caller, .. } =>
                    *caller != gone,
                PairTarget::Dropped { .. } => true,
            }),
        "servicing never suspends a live target naming the gone caller"
    );
    assert!(
        matches!(
            coordinator.pair_targets.get(&key),
            Some(PairTarget::Dropped { base: dropped, .. }) if *dropped == base
        ),
        "the dropped base survives choke-point servicing unchanged"
    );
    let gaps_after = coordinator
        .registry
        .gaps()
        .iter()
        .filter(|gap| gap.subject == DEMOTED_COUNT_REJECTED)
        .count();
    assert!(
        gaps_after > gaps_before,
        "the withheld range is disclosed as a retirement-count gap, never silent"
    );
    scene
        .native
        .scene
        .coordinator
        .prune_departed_native_state(1_000_000_000_000);
    assert_eq!(
        scene.native.scene.coordinator.pruned_pair_totals(),
        (1, base),
        "the staged absolute reaches the counted totals exactly once"
    );
}

/// Fix round 6, fold gate: an exec-retired caller with a pending
/// successor keeps its facts until the handoff releases, then folds
/// with exact totals.
#[test]
fn demotion_retirement_round6_fold_gate_pending_successor_blocks_fold() {
    let mut scene = Scene::shared();
    let old = scene.caller;
    let live_edges: Vec<(ModuleId, u64)> = scene
        .native
        .scene
        .coordinator
        .registry
        .edges_of(old)
        .map(|edge| (edge.module, edge.entry_count))
        .collect();
    assert!(!live_edges.is_empty(), "the scene stages an edge");
    let before = scene.native.scene.coordinator.registry.departed_totals();
    scene
        .native
        .scene
        .coordinator
        .mint_pending_successor(ExecTransition::unheld_predecessor(old, 7), 2000)
        .expect("a live caller mints its exec handoff");
    assert!(
        scene
            .native
            .scene
            .coordinator
            .pending_successors
            .contains_key(&old),
        "the handoff pins the exec-retired caller"
    );
    scene.native.scene.coordinator.note_rendered_callers(&[old]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(2001, None)
            .retired,
        0,
        "a caller with a pending successor keeps its facts"
    );
    assert!(
        scene.native.scene.coordinator.adapter.record(old).is_some(),
        "the pinned row stays"
    );
    scene
        .native
        .scene
        .coordinator
        .pending_successors
        .remove(&old);
    scene.native.scene.coordinator.note_rendered_callers(&[old]);
    let receipt = scene
        .native
        .scene
        .coordinator
        .retire_rendered_callers(2002, None);
    assert_eq!(
        receipt.retired, 1,
        "the caller folds after the pin releases"
    );
    assert!(
        scene.native.scene.coordinator.adapter.record(old).is_none(),
        "the folded row leaves the adapter"
    );
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .registry
            .edges_of(old)
            .count(),
        0,
        "no edge row survives its caller's fold"
    );
    let after = scene.native.scene.coordinator.registry.departed_totals();
    assert_eq!(
        after.edges - before.edges,
        live_edges.len() as u64,
        "the folded edges land in the departed aggregate"
    );
    assert_eq!(
        after.entries - before.entries,
        live_edges.iter().map(|(_, entries)| entries).sum::<u64>(),
        "the folded entries land in the departed aggregate"
    );
}

/// Fix round 6, fold gate: a caller with a pending count keeps its
/// facts until the count resolves, then folds with exact totals.
#[test]
fn demotion_retirement_round6_fold_gate_pending_count_blocks_fold() {
    let mut scene = Scene::shared();
    let caller = scene.caller;
    scene.native.scene.source.kill(7);
    scene.native.scene.coordinator.observe_empty_pass(
        &mut UnavailableImageGuard,
        &mut scene.native.cookies,
        "test pending-count exit",
        1000,
    );
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    let live_edges: Vec<(ModuleId, u64)> = scene
        .native
        .scene
        .coordinator
        .registry
        .edges_of(caller)
        .map(|edge| (edge.module, edge.entry_count))
        .collect();
    assert!(!live_edges.is_empty(), "the scene stages an edge");
    let before = scene.native.scene.coordinator.registry.departed_totals();
    let domain = scene.native.domain;
    scene.native.scene.coordinator.pending_ids.insert(
        999_999,
        PendingCountObservation {
            key: PairKey {
                image: DomainCookie::new(domain, 999),
                exec: 1,
                object: 0,
            },
            caller,
            endpoint: EndpointId(0),
            observation: PairCount {
                count: 1,
                first_ns: 0,
                anchor_ns: 0,
                last_ns: 0,
                retirement_usable: false,
                diagnostic_observation: 0,
                diagnostic_transition: 0,
            },
            generation: Some(0),
            origin: PendingCountOrigin::Untracked,
            diagnostic: None,
        },
    );
    scene
        .native
        .scene
        .coordinator
        .note_rendered_callers(&[caller]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(1001, None)
            .retired,
        0,
        "a caller with a pending count keeps its facts"
    );
    assert!(
        scene
            .native
            .scene
            .coordinator
            .adapter
            .record(caller)
            .is_some(),
        "the pinned row stays"
    );
    scene.native.scene.coordinator.pending_ids.remove(&999_999);
    scene
        .native
        .scene
        .coordinator
        .note_rendered_callers(&[caller]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(1002, None)
            .retired,
        1,
        "the caller folds after the pin releases"
    );
    assert!(
        scene
            .native
            .scene
            .coordinator
            .adapter
            .record(caller)
            .is_none(),
        "the folded row leaves the adapter"
    );
    let after = scene.native.scene.coordinator.registry.departed_totals();
    assert_eq!(
        after.edges - before.edges,
        live_edges.len() as u64,
        "the folded edges land in the departed aggregate"
    );
    assert_eq!(
        after.entries - before.entries,
        live_edges.iter().map(|(_, entries)| entries).sum::<u64>(),
        "the folded entries land in the departed aggregate"
    );
}

/// Fix round 6, fold gate: a caller with a pending binder row keeps
/// its facts until that row decides, then folds with exact totals.
#[test]
fn demotion_retirement_round6_fold_gate_pending_binder_row_blocks_fold() {
    let mut scene = Scene::shared();
    let caller = scene.caller;
    let live_edges: Vec<(ModuleId, u64)> = scene
        .native
        .scene
        .coordinator
        .registry
        .edges_of(caller)
        .map(|edge| (edge.module, edge.entry_count))
        .collect();
    assert!(!live_edges.is_empty(), "the scene stages an edge");
    let before = scene.native.scene.coordinator.registry.departed_totals();
    // One witness read without its horizons for the live caller, with
    // a new ticket the binder has never bound: the row stays pending
    // with its sighting, pinning the caller through its incarnation
    // snapshot. (A repeat of the bound ticket would decide at once.)
    let pending = scene.native.row(42, 1, 7, 300, 0);
    scene.native.read(vec![pending]);
    // Exec-retire (not kill): foldable, but the binder row still pends.
    scene
        .native
        .scene
        .coordinator
        .adapter
        .exec_transition_scoped(caller, 500);
    scene
        .native
        .scene
        .coordinator
        .note_rendered_callers(&[caller]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(2001, None)
            .retired,
        0,
        "a caller with a pending binder row keeps its facts"
    );
    assert!(
        scene
            .native
            .scene
            .coordinator
            .adapter
            .record(caller)
            .is_some(),
        "the pinned row stays"
    );
    scene.native.drain();
    scene.native.read(Vec::new());
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    scene
        .native
        .scene
        .coordinator
        .note_rendered_callers(&[caller]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(2002, None)
            .retired,
        1,
        "the caller folds after the binder row decides"
    );
    let after = scene.native.scene.coordinator.registry.departed_totals();
    assert_eq!(
        after.edges - before.edges,
        live_edges.len() as u64,
        "the folded edges land in the departed aggregate"
    );
    assert_eq!(
        after.entries - before.entries,
        live_edges.iter().map(|(_, entries)| entries).sum::<u64>(),
        "the folded entries land in the departed aggregate"
    );
}

/// Fix round 6, fold gate: the capture-bound caller keeps its facts
/// until the binding releases, then folds with exact totals.
#[test]
fn demotion_retirement_round6_fold_gate_capture_bound_blocks_fold() {
    let mut scene = Scene::shared();
    let caller = scene.caller;
    scene.native.scene.source.kill(7);
    scene.native.scene.coordinator.observe_empty_pass(
        &mut UnavailableImageGuard,
        &mut scene.native.cookies,
        "test capture exit",
        1000,
    );
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    let live_edges: Vec<(ModuleId, u64)> = scene
        .native
        .scene
        .coordinator
        .registry
        .edges_of(caller)
        .map(|edge| (edge.module, edge.entry_count))
        .collect();
    assert!(!live_edges.is_empty(), "the scene stages an edge");
    let before = scene.native.scene.coordinator.registry.departed_totals();
    scene
        .native
        .scene
        .coordinator
        .begin_capture_coverage(CaptureScopeCoverage::System);
    scene
        .native
        .scene
        .coordinator
        .capture
        .as_mut()
        .expect("capture coverage")
        .bound = Some(caller);
    scene
        .native
        .scene
        .coordinator
        .note_rendered_callers(&[caller]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(1001, None)
            .retired,
        0,
        "the capture-bound caller keeps its facts"
    );
    scene
        .native
        .scene
        .coordinator
        .capture
        .as_mut()
        .expect("capture coverage")
        .bound = None;
    scene
        .native
        .scene
        .coordinator
        .note_rendered_callers(&[caller]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(1002, None)
            .retired,
        1,
        "the caller folds after the binding releases"
    );
    let after = scene.native.scene.coordinator.registry.departed_totals();
    assert_eq!(
        after.edges - before.edges,
        live_edges.len() as u64,
        "the folded edges land in the departed aggregate"
    );
    assert_eq!(
        after.entries - before.entries,
        live_edges.iter().map(|(_, entries)| entries).sum::<u64>(),
        "the folded entries land in the departed aggregate"
    );
}

/// Fix round 6, fold gate: a caller holding an owner keeps its facts
/// until the owner releases, then folds with exact totals.
#[test]
fn demotion_retirement_round6_fold_gate_owner_blocks_fold() {
    let mut scene = Scene::shared();
    let caller = scene.caller;
    scene.native.scene.source.kill(7);
    scene.native.scene.coordinator.observe_empty_pass(
        &mut UnavailableImageGuard,
        &mut scene.native.cookies,
        "test owner exit",
        1000,
    );
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    let before = scene.native.scene.coordinator.registry.departed_totals();
    scene
        .native
        .scene
        .coordinator
        .owners
        .insert(caller, crate::process::ProcessViewId(1));
    scene
        .native
        .scene
        .coordinator
        .note_rendered_callers(&[caller]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(1001, None)
            .retired,
        0,
        "a caller holding an owner keeps its facts"
    );
    scene.native.scene.coordinator.owners.remove(&caller);
    scene
        .native
        .scene
        .coordinator
        .note_rendered_callers(&[caller]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(1002, None)
            .retired,
        1,
        "the caller folds after the owner releases"
    );
    let after = scene.native.scene.coordinator.registry.departed_totals();
    assert!(
        after.edges > before.edges,
        "the folded edges land in the departed aggregate"
    );
}

/// Fix round 6, fold gate: a caller with a pending leader exit keeps
/// its facts until the exit resolves, then folds with exact totals.
#[test]
fn demotion_retirement_round6_fold_gate_pending_leader_exit_blocks_fold() {
    let mut scene = Scene::shared();
    let caller = scene.caller;
    let domain = scene.native.domain;
    // Defer while live (the retirement clears the map), then
    // exec-retire (which does not): foldable but pinned.
    scene
        .native
        .scene
        .coordinator
        .defer_leader_exit(caller, 7, 2000, domain);
    assert!(
        scene
            .native
            .scene
            .coordinator
            .pending_leader_exits
            .contains_key(&caller),
        "the leader exit pins the caller"
    );
    scene
        .native
        .scene
        .coordinator
        .adapter
        .exec_transition_scoped(caller, 500);
    let before = scene.native.scene.coordinator.registry.departed_totals();
    scene
        .native
        .scene
        .coordinator
        .note_rendered_callers(&[caller]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(1001, None)
            .retired,
        0,
        "a caller with a pending leader exit keeps its facts"
    );
    scene
        .native
        .scene
        .coordinator
        .pending_leader_exits
        .remove(&caller);
    scene
        .native
        .scene
        .coordinator
        .note_rendered_callers(&[caller]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(1002, None)
            .retired,
        1,
        "the caller folds after the exit resolves"
    );
    let after = scene.native.scene.coordinator.registry.departed_totals();
    assert!(
        after.edges > before.edges,
        "the folded edges land in the departed aggregate"
    );
}

/// Fix round 6, fold gate: a caller with a pending adjudication keeps
/// its facts until the tail adjudicates, then folds with exact totals.
#[test]
fn demotion_retirement_round6_fold_gate_pending_adjudication_blocks_fold() {
    let mut scene = Scene::shared();
    let caller = scene.caller;
    scene.native.scene.source.kill(7);
    scene.native.scene.coordinator.observe_empty_pass(
        &mut UnavailableImageGuard,
        &mut scene.native.cookies,
        "test adjudication exit",
        1000,
    );
    scene.native.scene.coordinator.commit_batch(false).unwrap();
    let before = scene.native.scene.coordinator.registry.departed_totals();
    scene
        .native
        .scene
        .coordinator
        .reference_stage_adjudication(caller, 7);
    scene
        .native
        .scene
        .coordinator
        .note_rendered_callers(&[caller]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(1001, None)
            .retired,
        0,
        "a caller with a pending adjudication keeps its facts"
    );
    scene
        .native
        .scene
        .coordinator
        .pending_adjudication
        .remove(&caller);
    scene
        .native
        .scene
        .coordinator
        .note_rendered_callers(&[caller]);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .retire_rendered_callers(1002, None)
            .retired,
        1,
        "the caller folds after the adjudication releases"
    );
    let after = scene.native.scene.coordinator.registry.departed_totals();
    assert!(
        after.edges > before.edges,
        "the folded edges land in the departed aggregate"
    );
}
