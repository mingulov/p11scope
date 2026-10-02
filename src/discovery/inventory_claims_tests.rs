//! SPDX-License-Identifier: GPL-3.0-or-later

//! I4b Slice 1 regressions through the existing owner and candidate paths.
//! Scan results and native-image replies are scripted at those dependency
//! boundaries. Pinning, candidate construction, and claim ownership are real.

use super::super::inventory::{
    ImageCheck, ImageGuard, InventoryDiscoveryConfig, InventoryOwnerLimits, RefreshCause,
    ScanReceipt, UnavailableImageGuard,
};
use super::*;
use crate::capacity::InventoryBudget;
use crate::discovery::scan::{
    InventoryDiscoveryLimits, InventoryRetainedLimits, InventoryWindowLimits, WindowId,
};
use p11scope_ebpf_common::ImageIdentity;

fn inventory_engine(scan_capacity: usize) -> Engine {
    inventory_engine_with_claim_capacity(scan_capacity, 32768)
}

fn inventory_engine_with_claim_capacity(scan_capacity: usize, claim_capacity: usize) -> Engine {
    let window = InventoryWindowLimits::new(16 << 20, 1 << 20, 4096, 32768, 4096).unwrap();
    let retained = InventoryRetainedLimits::new(8192, 32768, 8192, 128, 128, 16 << 20).unwrap();
    let limits = InventoryDiscoveryLimits::new(8 << 20, window, retained).unwrap();
    Engine::inventory(
        InventoryDiscoveryConfig::new(
            limits,
            InventoryOwnerLimits::new(1024, scan_capacity, claim_capacity).unwrap(),
            InventoryBudget::new(4096, 4096 * 8).unwrap(),
        ),
        Scope::System,
        HookRegistry::builtin(),
        Vec::new(),
    )
    .unwrap()
}

// This is explicitly a scripted native-query dependency, not live image proof.
struct FixtureImages;

fn fixture_image(pid: u32) -> ImageIdentity {
    ImageIdentity {
        task_cookie: u64::from(pid) + 1,
        exec_id: 7,
    }
}

impl ImageGuard for FixtureImages {
    fn check(&mut self, view: &ProcessView, expected: ImageIdentity) -> ImageCheck {
        assert_eq!(expected, fixture_image(view.pid()));
        ImageCheck::Exact
    }
}

fn open_owner(engine: &mut Engine, pid: u32) -> ProcessViewId {
    engine
        .open_inventory_owner(pid, fixture_image(pid), &mut FixtureImages)
        .unwrap()
}

fn receipt(
    engine: &mut Engine,
    owner: ProcessViewId,
    modules: Vec<ScannedModule>,
    partial: bool,
) -> ScanReceipt {
    receipt_at(engine, owner, modules, partial, 1)
}

fn receipt_at(
    engine: &mut Engine,
    owner: ProcessViewId,
    modules: Vec<ScannedModule>,
    partial: bool,
    window_id: u64,
) -> ScanReceipt {
    let lease = engine.acquire_inventory_scan(owner).unwrap();
    let window = engine
        .budget
        .begin_window(WindowId::new(window_id), u64::MAX)
        .unwrap();
    let checkpoint = engine.budget.checkpoint(window.clone()).unwrap();
    let result = engine
        .scan_inventory_owner_with(&lease, &mut FixtureImages, |_, _, _| {
            Ok(ScanOutcome::Scanned {
                modules,
                skipped: if partial {
                    vec![Skipped {
                        subject: "inventory scan".into(),
                        reason: "continuation remains pending".into(),
                    }]
                } else {
                    Vec::new()
                },
                scan_ms: 0,
            })
        })
        .unwrap();
    engine.budget.finish_scan(checkpoint).unwrap();
    engine.budget.finish_window(window).unwrap();
    engine.release_inventory_scan(&lease).unwrap();
    result
}

/// Tables are synthetic. Process pins, executable mappings, open file identity,
/// reconciliation, deduplication, and plan construction are the production path.
fn mapped_providers(owner: &OwnedMapper, view: &ProcessView, count: usize) -> Vec<ScannedModule> {
    let modules: Vec<_> = mapped_provider_candidates(owner, view)
        .into_iter()
        .take(count)
        .map(|(mapping, path)| provider_module(view, &mapping, &path, mapping.file_offset))
        .collect();
    assert_eq!(modules.len(), count, "enough distinct executable mappings");
    modules
}

fn mapped_provider_candidates(owner: &OwnedMapper, view: &ProcessView) -> Vec<(MapEntry, PathBuf)> {
    assert_eq!(
        view.pid(),
        owner.pid(),
        "mapping view must belong to the owned fixture"
    );
    let bytes = std::fs::read(format!("/proc/{}/maps", view.pid())).unwrap();
    let maps = parse_maps(&bytes).unwrap();
    let index = MapIndex::new(&maps).unwrap();
    let mut seen = BTreeSet::new();
    maps.iter()
        .filter(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
        .filter_map(|mapping| {
            let Resolved::File {
                path: MappedPath::Usable(path),
                ..
            } = index.resolve(mapping.start)
            else {
                return None;
            };
            if !seen.insert(ObjectKey::of(mapping)) {
                return None;
            }
            Some((mapping.clone(), path))
        })
        .collect()
}

fn shared_mapping_indices(own: &[ObjectKey], peer: &[ObjectKey]) -> Option<(usize, usize)> {
    own.iter().enumerate().find_map(|(own_index, key)| {
        peer.iter()
            .position(|peer_key| peer_key == key)
            .map(|peer_index| (own_index, peer_index))
    })
}

#[test]
fn shared_pair_selector_searches_past_unrelated_prefix_by_exact_object_key() {
    let key = |minor, inode| ObjectKey {
        device: Device { major: 8, minor },
        inode,
    };
    let shared = key(1, 77);
    let own = [
        key(1, 10),
        key(1, 11),
        key(2, 77), // Same inode on another device is a different object.
        shared,
    ];
    let peer = [shared];

    assert_eq!(shared_mapping_indices(&own, &peer), Some((3, 0)));
}

fn shared_provider_pair(
    own_subject: &OwnedMapper,
    own_view: &ProcessView,
    peer_subject: &OwnedMapper,
    peer_view: &ProcessView,
) -> Option<(ScannedModule, ScannedModule)> {
    let own = mapped_provider_candidates(own_subject, own_view);
    let peer = mapped_provider_candidates(peer_subject, peer_view);
    let own_keys: Vec<_> = own
        .iter()
        .map(|(mapping, _)| ObjectKey::of(mapping))
        .collect();
    let peer_keys: Vec<_> = peer
        .iter()
        .map(|(mapping, _)| ObjectKey::of(mapping))
        .collect();
    let (own_index, peer_index) = shared_mapping_indices(&own_keys, &peer_keys)?;
    let (own_mapping, own_path) = &own[own_index];
    let (peer_mapping, peer_path) = &peer[peer_index];
    Some((
        provider_module(own_view, own_mapping, own_path, own_mapping.file_offset),
        provider_module(peer_view, peer_mapping, peer_path, 0x1000),
    ))
}

/// Seed an already accepted snapshot without simulating an Inventory BPF
/// session. All assertions exercise subsequent candidate construction, not
/// kernel attachment or the unavailable live image-query capability.
fn seed_claims(engine: &mut Engine, owner: ProcessViewId, modules: &[ScannedModule]) {
    engine.retain_view_id(owner).unwrap();
    let view = engine.views.iter().find(|view| view.id() == owner).unwrap();
    let mut pins = engine.pinned.clone();
    assert!(pins.absorb(pin_test_modules(view, modules)).is_empty());
    let mut raw: Vec<_> = engine
        .modules
        .iter()
        .map(|module| module.scanned.clone())
        .collect();
    for module in modules {
        merge_scanned_module(&mut raw, module.clone());
    }
    let candidate = engine.live_candidate(pins, raw, Vec::new()).unwrap();
    assert!(
        engine.counters.object_skips.is_empty(),
        "{:?}",
        engine.counters.object_skips
    );
    engine.plan = candidate.plan;
    engine.pinned = candidate.pinned;
    engine.modules = candidate.modules;
}

#[test]
fn inventory_partial_third_provider_keeps_both_existing_claims() {
    let subject = OwnedMapper::ready();
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, subject.pid());
    let providers = mapped_providers(&subject, &engine.views[0], 3);
    seed_claims(&mut engine, owner, &providers[..2]);
    let retained_slots = engine.plan.slots.clone();
    let scanned = receipt(&mut engine, owner, providers[2..].to_vec(), true);
    assert!(matches!(scanned, ScanReceipt::AdditionsOnly(_)));
    let prepared = engine
        .prepare_inventory_reconciliation(scanned, &mut FixtureImages)
        .unwrap();
    let candidate = prepared.candidate();

    assert_eq!(
        candidate.modules.len(),
        3,
        "partial refresh only adds claims"
    );
    assert!(
        candidate.delta.retire.is_empty(),
        "no old endpoint may retire"
    );
    assert_eq!(candidate.delta.new.len(), 1);
    for old in retained_slots {
        assert_eq!(candidate.plan.slots[old.index as usize], old);
    }
    let claims = candidate.pinned.view_claims(ProcessViewId(0)).unwrap();
    assert_eq!(
        claims.pins.iter().collect::<BTreeSet<_>>().len(),
        3,
        "all three exact physical pins survive"
    );
    assert_eq!(
        engine.modules.len(),
        2,
        "candidate preparation is not commit"
    );
}

#[test]
fn inventory_owner_ids_do_not_treat_scan_capacity_as_lifetime_ceiling() {
    let mut engine = inventory_engine(2);
    let mut owners = Vec::new();
    for expected in 0..300 {
        let owner = engine
            .allocate_view_id()
            .unwrap_or_else(|error| panic!("owner {expected}: {error:#}"));
        assert_eq!(owner, ProcessViewId(expected));
        owners.push(owner);
    }
    let first = engine.acquire_inventory_scan(owners[0]).unwrap();
    let second = engine.acquire_inventory_scan(owners[1]).unwrap();
    assert!(engine.acquire_inventory_scan(owners[299]).is_err());
    engine.release_inventory_scan(&first).unwrap();
    let last = engine.acquire_inventory_scan(owners[299]).unwrap();
    engine.release_inventory_scan(&second).unwrap();
    engine.release_inventory_scan(&last).unwrap();
}

#[test]
fn retired_inventory_owner_ids_never_reappear() {
    let mut engine = inventory_engine(2);
    let first = engine.allocate_view_id().unwrap();
    let second = engine.allocate_view_id().unwrap();
    engine.release_view_id(first);
    engine.release_view_id(first);
    let next = engine.allocate_view_id().unwrap();
    assert!(
        next.0 > second.0,
        "retirement cannot recycle an owner identity"
    );
}

#[test]
fn inventory_generic_refresh_is_not_exec_authority() {
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, std::process::id());
    for cause in [
        RefreshCause::Periodic,
        RefreshCause::LoaderHint,
        RefreshCause::TransportRecovery(9),
        RefreshCause::ScopeRecheck,
    ] {
        engine.request_inventory_refresh(owner, cause).unwrap();
    }
    assert!(engine.retirement_intents.is_empty());
    assert!(engine.pending_retirements.is_empty());
    assert!(
        engine.refresh_requested.is_empty(),
        "never enters legacy exec refresh queue"
    );
}

#[test]
fn owned_mapper_waits_for_a_stopped_image_and_reaps_on_drop() {
    let child = OwnedMapper::ready();
    let pid = child.0.id();
    let view = ProcessView::open(ProcessViewId(0), pid).unwrap();
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let state = status
        .lines()
        .find(|line| line.starts_with("State:"))
        .unwrap()
        .split_whitespace()
        .nth(1);
    assert_eq!(state, Some("T"), "the fixture must acknowledge its stop");
    let before = std::fs::read(format!("/proc/{pid}/maps")).unwrap();
    let foreign = E07Provider::dlopen();
    assert_eq!(std::fs::read(format!("/proc/{pid}/maps")).unwrap(), before);
    drop(foreign);
    assert_eq!(std::fs::read(format!("/proc/{pid}/maps")).unwrap(), before);
    drop(child);
    assert_owned_child_reaped(&view);
}

#[test]
#[should_panic(expected = "mapping view must belong to the owned fixture")]
fn owned_mapper_rejects_an_unowned_mapping_view() {
    let child = OwnedMapper::ready();
    let parent = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let _ = mapped_provider_candidates(&child, &parent);
}

#[test]
fn inventory_fixture_keeps_real_claims_after_foreign_parent_provider_removal() {
    let subject = OwnedMapper::ready();
    let foreign = E07Provider::dlopen();
    let foreign_path = foreign.path.clone();
    let parent_maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
    let parent_index = MapIndex::new(&parent_maps).unwrap();
    let foreign_key = parent_maps
        .iter()
        .find_map(|mapping| match parent_index.resolve(mapping.start) {
            Resolved::File {
                path: MappedPath::Usable(path),
                ..
            } if path == foreign_path => Some(ObjectKey::of(mapping)),
            _ => None,
        })
        .expect("the control provider really belongs to the parent maps");
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, subject.pid());
    let modules = mapped_providers(&subject, &engine.views[0], 3);
    let child_exe = std::fs::read_link(format!("/proc/{}/exe", subject.pid())).unwrap();
    assert!(
        modules
            .iter()
            .any(|module| Path::new(&module.path) == child_exe)
    );
    assert!(modules.iter().all(|module| module.key != foreign_key));
    let selected: BTreeSet<_> = modules.iter().map(|module| module.key).collect();
    drop(foreign);
    assert_eq!(
        std::fs::metadata(foreign_path).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );

    seed_claims(&mut engine, owner, &modules);
    assert_eq!(engine.pinned.pinned().count(), 3);
    assert_eq!(
        engine
            .pinned
            .view_claims(owner)
            .unwrap()
            .pins
            .iter()
            .collect::<BTreeSet<_>>()
            .len(),
        3,
        "raw, module and entry references retain three distinct physical pins"
    );
    assert_eq!(engine.plan.slots.len(), 3);
    assert_eq!(
        engine
            .modules
            .iter()
            .map(|module| module.scanned.key)
            .collect::<BTreeSet<_>>(),
        selected
    );
}

#[test]
fn inventory_one_mapper_removal_preserves_other_mapper_and_physical_slot() {
    let subject = OwnedMapper::ready();
    let child = OwnedMapper::ready();
    let mut engine = inventory_engine(2);
    let own = open_owner(&mut engine, subject.pid());
    let peer = open_owner(&mut engine, child.pid());
    let (own_module, peer_module) =
        shared_provider_pair(&subject, &engine.views[0], &child, &engine.views[1])
            .expect("the two real processes share an executable ELF object");
    let mut peer_module = peer_module;
    peer_module.tables[0].entries[0].file_offset = own_module.tables[0].entries[0].file_offset;
    seed_claims(&mut engine, own, &[own_module]);
    seed_claims(&mut engine, peer, &[peer_module]);
    assert_eq!(engine.plan.slots.len(), 1, "one shared physical attachment");
    let endpoint = engine.plan.slots[0].index;
    // The scanner's complete absence result is scripted; no live unload is
    // claimed. Both image brackets and the resulting physical claim path run.
    let scanned = receipt(&mut engine, own, Vec::new(), false);
    assert!(matches!(scanned, ScanReceipt::Complete(_)));
    let prepared = engine
        .prepare_inventory_reconciliation(scanned, &mut FixtureImages)
        .unwrap();
    let candidate = prepared.candidate();
    assert_eq!(candidate.modules.len(), 1);
    assert_eq!(candidate.modules[0].scanned.view, ProcessViewId(1));
    assert!(
        candidate
            .pinned
            .view_claims(ProcessViewId(0))
            .is_none_or(|claims| claims.pins.is_empty()
                && claims.tables.is_empty()
                && claims.targets.is_empty())
    );
    assert!(candidate.pinned.view_claims(ProcessViewId(1)).is_some());
    assert!(candidate.delta.retire.is_empty());
    assert_eq!(candidate.plan.slots[endpoint as usize].index, endpoint);
}

#[test]
fn inventory_unavailable_image_cannot_retire_committed_claims() {
    let subject = OwnedMapper::ready();
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, subject.pid());
    let modules = mapped_providers(&subject, &engine.views[0], 2);
    seed_claims(&mut engine, owner, &modules);
    let scanned = receipt(&mut engine, owner, Vec::new(), false);
    let plan = engine.plan.clone();
    let claims = engine.pinned.view_claims(owner).unwrap().clone();
    assert!(
        engine
            .prepare_inventory_reconciliation(scanned, &mut UnavailableImageGuard)
            .is_err()
    );
    assert_eq!(engine.plan, plan);
    assert_eq!(engine.pinned.view_claims(owner), Some(&claims));
    assert_eq!(engine.modules.len(), 2);
    assert!(engine.retirement_intents.is_empty());
}

#[test]
fn inventory_changed_image_after_candidate_build_cannot_publish_absence() {
    struct ChangesAfterFirstCheck(bool);
    impl ImageGuard for ChangesAfterFirstCheck {
        fn check(&mut self, _: &ProcessView, _: ImageIdentity) -> ImageCheck {
            if std::mem::replace(&mut self.0, true) {
                ImageCheck::Changed
            } else {
                ImageCheck::Exact
            }
        }
    }
    let subject = OwnedMapper::ready();
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, subject.pid());
    let modules = mapped_providers(&subject, &engine.views[0], 2);
    seed_claims(&mut engine, owner, &modules);
    let scanned = receipt(&mut engine, owner, Vec::new(), false);
    let plan = engine.plan.clone();
    let claims = engine.pinned.view_claims(owner).unwrap().clone();
    assert!(
        engine
            .prepare_inventory_reconciliation(scanned, &mut ChangesAfterFirstCheck(false))
            .is_err()
    );
    assert_eq!(engine.plan, plan);
    assert_eq!(engine.modules.len(), 2);
    assert_eq!(engine.pinned.view_claims(owner), Some(&claims));
}

#[test]
fn inventory_unavailable_scan_keeps_old_claims_and_is_not_empty_complete() {
    let subject = OwnedMapper::ready();
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, subject.pid());
    let modules = mapped_providers(&subject, &engine.views[0], 2);
    seed_claims(&mut engine, owner, &modules);
    let lease = engine.acquire_inventory_scan(owner).unwrap();
    let scanned = engine
        .scan_inventory_owner_with(&lease, &mut FixtureImages, |_, _, _| {
            Err("scripted read failure".into())
        })
        .unwrap();
    assert!(matches!(scanned, ScanReceipt::Unavailable { .. }));
    let plan = engine.plan.clone();
    assert!(
        engine
            .prepare_inventory_reconciliation(scanned, &mut FixtureImages)
            .is_err()
    );
    assert_eq!(engine.plan, plan);
    assert_eq!(engine.modules.len(), 2);
    engine.release_inventory_scan(&lease).unwrap();
}

#[test]
fn inventory_lease_release_changes_no_claims_history_contexts_or_plan() {
    let subject = OwnedMapper::ready();
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, subject.pid());
    let modules = mapped_providers(&subject, &engine.views[0], 2);
    seed_claims(&mut engine, owner, &modules);
    engine.publish_current_capture_facts().unwrap();
    engine.exploratory_dirty.insert(owner);
    engine.loader_contexts.insert(
        (owner, LoaderAggregateKey::Unbound, false),
        LoaderContextClass {
            bound: false,
            initial_set: false,
        },
    );
    let plan = engine.plan.clone();
    let claims = engine.pinned.view_claims(owner).unwrap().clone();
    let facts = format!("{:?}", engine.capture_facts);
    let contexts = engine.loader_contexts.clone();
    let lease = engine.acquire_inventory_scan(owner).unwrap();
    engine.release_inventory_scan(&lease).unwrap();
    // Even a legacy cancellation call cannot retire a retained Inventory owner.
    engine.release_view_id(owner);
    assert_eq!(engine.plan, plan);
    assert_eq!(engine.pinned.view_claims(owner), Some(&claims));
    assert_eq!(format!("{:?}", engine.capture_facts), facts);
    assert_eq!(engine.loader_contexts, contexts);
    assert!(engine.exploratory_dirty.contains(&owner));
    assert!(engine.retired_view_ids.is_empty());
    assert_eq!(engine.views.len(), 1);
    assert_eq!(engine.modules.len(), 2);
    assert!(engine.retirement_intents.is_empty());
}

#[test]
fn inventory_publication_revalidation_rejects_late_image_uncertainty() {
    let subject = OwnedMapper::ready();
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, subject.pid());
    let modules = mapped_providers(&subject, &engine.views[0], 2);
    seed_claims(&mut engine, owner, &modules);
    let scanned = receipt(&mut engine, owner, Vec::new(), false);
    let prepared = engine
        .prepare_inventory_reconciliation(scanned, &mut FixtureImages)
        .unwrap();
    let plan = engine.plan.clone();
    assert!(
        engine
            .revalidate_inventory_reconciliation(&prepared, &mut UnavailableImageGuard)
            .is_err()
    );
    assert_eq!(engine.plan, plan);
    assert_eq!(engine.modules.len(), 2);
}

#[test]
fn inventory_clock_uncertainty_produces_additions_only_and_preserves_claims() {
    let subject = OwnedMapper::ready();
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, subject.pid());
    let modules = mapped_providers(&subject, &engine.views[0], 2);
    seed_claims(&mut engine, owner, &modules);
    let lease = engine.acquire_inventory_scan(owner).unwrap();
    let window = engine
        .budget
        .begin_window(WindowId::new(1), u64::MAX)
        .unwrap();
    let checkpoint = engine.budget.checkpoint(window.clone()).unwrap();
    let scanned = engine
        .scan_inventory_owner_with(&lease, &mut FixtureImages, |_, _, _| {
            Ok(ScanOutcome::Scanned {
                modules: Vec::new(),
                skipped: vec![Skipped {
                    subject: "inventory scan clock".into(),
                    reason: crate::discovery::scan::SCAN_CLOCK_REASON.into(),
                }],
                scan_ms: 0,
            })
        })
        .unwrap();
    assert!(matches!(scanned, ScanReceipt::AdditionsOnly(_)));
    engine.budget.finish_scan(checkpoint).unwrap();
    engine.budget.finish_window(window).unwrap();
    engine.release_inventory_scan(&lease).unwrap();
    let prepared = engine
        .prepare_inventory_reconciliation(scanned, &mut FixtureImages)
        .unwrap();
    assert_eq!(prepared.candidate().modules.len(), 2);
    assert!(prepared.candidate().delta.retire.is_empty());
}

#[test]
fn inventory_pinning_loss_cannot_turn_complete_scan_into_absence_authority() {
    let subject = OwnedMapper::ready();
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, subject.pid());
    let modules = mapped_providers(&subject, &engine.views[0], 3);
    seed_claims(&mut engine, owner, &modules[..2]);
    let mut unreadable = modules[2].clone();
    unreadable.key.inode = u64::MAX;
    let scanned = receipt(&mut engine, owner, vec![unreadable], false);
    assert!(matches!(scanned, ScanReceipt::AdditionsOnly(_)));
    let prepared = engine
        .prepare_inventory_reconciliation(scanned, &mut FixtureImages)
        .unwrap();
    assert_eq!(prepared.candidate().modules.len(), 2);
    assert!(prepared.candidate().delta.retire.is_empty());
}

#[test]
fn inventory_repeated_partial_receipts_do_not_accumulate_identical_pin_claims() {
    let subject = OwnedMapper::ready();
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, subject.pid());
    let modules = mapped_providers(&subject, &engine.views[0], 1);
    seed_claims(&mut engine, owner, &modules);
    let mut first_count = None;
    for window in 1..=4 {
        let scanned = receipt_at(&mut engine, owner, modules.clone(), true, window);
        let prepared = engine
            .prepare_inventory_reconciliation(scanned, &mut FixtureImages)
            .unwrap();
        let candidate = prepared.candidate();
        let claims = candidate.pinned.view_claims(owner).unwrap();
        let count = claims.pins.len() + claims.tables.len() + claims.targets.len();
        assert_eq!(
            *first_count.get_or_insert(count),
            count,
            "identical partial observations must not consume new retained claim capacity"
        );
        assert!(candidate.delta.new.is_empty() && candidate.delta.retire.is_empty());
        // Seed the next accepted userspace snapshot only. This is not a fake
        // BPF activation or a production publication adapter.
        engine.plan = candidate.plan.clone();
        engine.pinned = candidate.pinned.clone();
        engine.modules = candidate.modules.clone();
    }
}

/// Seed both real process views in one binding pass. Repeatedly using the
/// legacy seed helper would already add stale derived refs before the test.
fn two_owner_claim_fixture(
    claim_capacity: usize,
) -> (
    Engine,
    [OwnedMapper; 2],
    [ProcessViewId; 2],
    [ScannedModule; 2],
) {
    let subject = OwnedMapper::ready();
    let child = OwnedMapper::ready();
    let mut engine = inventory_engine_with_claim_capacity(2, claim_capacity);
    let own = open_owner(&mut engine, subject.pid());
    let peer = open_owner(&mut engine, child.pid());
    let (own_module, mut peer_module) =
        shared_provider_pair(&subject, &engine.views[0], &child, &engine.views[1])
            .expect("the two real processes share an executable ELF object");
    peer_module.tables[0].entries[0].file_offset = own_module.tables[0].entries[0].file_offset;
    let modules = [own_module, peer_module];
    let mut pins = engine.pinned.clone();
    for (owner, module) in [own, peer].into_iter().zip(&modules) {
        engine.retain_view_id(owner).unwrap();
        let view = engine.views.iter().find(|view| view.id() == owner).unwrap();
        assert!(
            pins.absorb(pin_test_modules(view, std::slice::from_ref(module)))
                .is_empty()
        );
    }
    let candidate = engine
        .live_candidate(pins, modules.to_vec(), Vec::new())
        .unwrap();
    assert!(engine.counters.object_skips.is_empty());
    engine.plan = candidate.plan;
    engine.pinned = candidate.pinned;
    engine.modules = candidate.modules;
    assert_eq!(engine.plan.slots.len(), 1, "one shared physical endpoint");
    (engine, [subject, child], [own, peer], modules)
}

#[test]
fn inventory_two_owner_refresh_keeps_each_independent_claim_exactly_once() {
    let (mut engine, _child, owners, modules) = two_owner_claim_fixture(32768);
    let before = owners.map(|owner| engine.pinned.view_claims(owner).unwrap().clone());
    for window in 1..=12 {
        let which = usize::from(window % 3 == 0);
        let scanned = receipt_at(
            &mut engine,
            owners[which],
            vec![modules[which].clone()],
            window % 2 == 0,
            window,
        );
        let prepared = engine
            .prepare_inventory_reconciliation(scanned, &mut FixtureImages)
            .unwrap();
        let candidate = prepared.candidate();
        for (owner, expected) in owners.into_iter().zip(&before) {
            assert_eq!(
                candidate.pinned.view_claims(owner),
                Some(expected),
                "identical facts must retain exactly the same independent claims, window {window} owner {owner:?}"
            );
        }
        assert!(candidate.delta.new.is_empty() && candidate.delta.retire.is_empty());
        engine.plan = candidate.plan.clone();
        engine.pinned = candidate.pinned.clone();
        engine.modules = candidate.modules.clone();
    }
}

#[test]
fn inventory_two_owner_noop_refresh_fits_the_existing_exact_reference_budget() {
    // Per owner: one raw pin, one module pin, one entry pin, one table and
    // one target. Shared physical storage must still retain both owners.
    let (mut engine, _child, owners, modules) = two_owner_claim_fixture(10);
    let count: usize = owners
        .iter()
        .map(|owner| {
            let claims = engine.pinned.view_claims(*owner).unwrap();
            claims.pins.len() + claims.tables.len() + claims.targets.len()
        })
        .sum();
    assert_eq!(count, 10);
    for partial in [false, true] {
        let scanned = receipt_at(
            &mut engine,
            owners[0],
            vec![modules[0].clone()],
            partial,
            if partial { 2 } else { 1 },
        );
        let prepared = engine
            .prepare_inventory_reconciliation(scanned, &mut FixtureImages)
            .expect("unchanged two-owner claims fit the accepted reference budget");
        assert_eq!(prepared.candidate().modules.len(), 2);
    }
}
