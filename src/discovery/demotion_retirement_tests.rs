//! SPDX-License-Identifier: GPL-3.0-or-later
//! Behavioral retirement tests over retained real file identities.
use super::tests::{NativeScene, capture_catalog};
use super::*;
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

struct Scene {
    native: NativeScene,
    caller: CallerId,
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

    fn placed() -> Self {
        let (mut native, caller) = NativeScene::new();
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

    fn observe(&mut self, a_present: bool, complete: bool, at: u64) {
        self.apply(self.catalog(a_present, complete, at), at);
    }

    fn count(&mut self, absolute: u64) {
        QUERY_CLOCK.with(|clock| clock.set(self.native.stamps.tick()));
        self.native
            .counts_read(Vec::new(), vec![(41, 1, 0, absolute)]);
        self.native.scene.coordinator.commit_batch(false).unwrap();
    }

    fn horizons(&mut self) {
        QUERY_CLOCK.with(|clock| clock.set(self.native.stamps.tick()));
        self.native.drain();
        self.native.read(Vec::new());
        self.native.scene.coordinator.commit_batch(false).unwrap();
    }

    fn bracketed_count(&mut self, absolute: u64, pre: u64, post: u64, failed: bool) {
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

    fn counts(&self) -> (u64, u64) {
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
    assert_eq!(std::mem::size_of::<PairRecovery>(), 320);
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
