// SPDX-License-Identifier: GPL-3.0-or-later

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
fn mapped_providers(view: &ProcessView, count: usize) -> Vec<ScannedModule> {
    let bytes = std::fs::read(format!("/proc/{}/maps", view.pid())).unwrap();
    let maps = parse_maps(&bytes).unwrap();
    let index = MapIndex::new(&maps).unwrap();
    let executable = std::env::current_exe().unwrap();
    let mut seen = BTreeSet::new();
    let modules: Vec<_> = maps
        .iter()
        .filter(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
        .filter_map(|mapping| {
            let Resolved::File {
                path: MappedPath::Usable(path),
                ..
            } = index.resolve(mapping.start)
            else {
                return None;
            };
            // Avoid hashing the large Rust test executable when shared ELF
            // objects provide the same physical-identity fixture.
            if path == executable || !seen.insert(ObjectKey::of(mapping)) {
                return None;
            }
            Some(provider_module(view, mapping, &path, mapping.file_offset))
        })
        .take(count)
        .collect();
    assert_eq!(modules.len(), count, "enough distinct executable mappings");
    modules
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
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, std::process::id());
    let providers = mapped_providers(&engine.views[0], 3);
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

struct OwnedMapper(std::process::Child);

impl OwnedMapper {
    fn ready() -> Self {
        use std::io::Read as _;
        use std::os::fd::AsRawFd as _;
        use std::process::{Command, Stdio};

        // Spawn returns at exec, before the dynamic loader necessarily maps
        // libc. A userspace handshake makes the shared mapping deterministic.
        // The shell blocks in its read builtin; it creates no descendant.
        let mut child = Self(
            Command::new("sh")
                .args(["-c", "printf 'ready\\n'; read -r ignored"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut stdout = child.0.stdout.take().unwrap();
        let mut poll = libc::pollfd {
            fd: stdout.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd is valid for the bounded poll call.
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 5000) }, 1);
        let mut ready = [0; 6];
        stdout.read_exact(&mut ready).unwrap();
        assert_eq!(&ready, b"ready\n");
        child
    }
}

impl Drop for OwnedMapper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn inventory_one_mapper_removal_preserves_other_mapper_and_physical_slot() {
    let child = OwnedMapper::ready();
    let mut engine = inventory_engine(2);
    let own = open_owner(&mut engine, std::process::id());
    let peer = open_owner(&mut engine, child.0.id());
    let own_modules = mapped_providers(&engine.views[0], 3);
    let peer_modules = child_provider_modules(&engine.views[1]);
    let (own_module, peer_module) = own_modules
        .iter()
        .find_map(|own_module| {
            peer_modules
                .iter()
                .find(|peer_module| peer_module.key == own_module.key)
                .map(|peer_module| (own_module.clone(), peer_module.clone()))
        })
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
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, std::process::id());
    let modules = mapped_providers(&engine.views[0], 2);
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
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, std::process::id());
    let modules = mapped_providers(&engine.views[0], 2);
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
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, std::process::id());
    let modules = mapped_providers(&engine.views[0], 2);
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
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, std::process::id());
    let modules = mapped_providers(&engine.views[0], 2);
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
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, std::process::id());
    let modules = mapped_providers(&engine.views[0], 2);
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
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, std::process::id());
    let modules = mapped_providers(&engine.views[0], 2);
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
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, std::process::id());
    let modules = mapped_providers(&engine.views[0], 3);
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
    let mut engine = inventory_engine(2);
    let owner = open_owner(&mut engine, std::process::id());
    let modules = mapped_providers(&engine.views[0], 1);
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
) -> (Engine, OwnedMapper, [ProcessViewId; 2], [ScannedModule; 2]) {
    let child = OwnedMapper::ready();
    let mut engine = inventory_engine_with_claim_capacity(2, claim_capacity);
    let own = open_owner(&mut engine, std::process::id());
    let peer = open_owner(&mut engine, child.0.id());
    let own_modules = mapped_providers(&engine.views[0], 3);
    let peer_modules = child_provider_modules(&engine.views[1]);
    let (own_module, mut peer_module) = own_modules
        .iter()
        .find_map(|own_module| {
            peer_modules
                .iter()
                .find(|peer_module| peer_module.key == own_module.key)
                .map(|peer_module| (own_module.clone(), peer_module.clone()))
        })
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
    (engine, child, [own, peer], modules)
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
