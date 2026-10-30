//! SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::attach::capture::{ExecCoverage, NativeDomainId, ReadWindow};
use crate::discovery::engine::inventory::image_guard::ScriptedAcquisition;
use crate::discovery::engine::tests::DiscoveryLifecycleFixture;
use crate::discovery::native_binding::{BinderLimits, NativeBinder};
use crate::discovery::scan::{InventoryRetainedLimits, InventoryWindowLimits, WindowId};
use crate::process::PidPin;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    fn check(&mut self, view: &ProcessView, image: BoundImage) -> ImageCheck {
        assert!(view.still_the_same());
        assert_eq!(image, expected());
        self.0
    }
}

/// One stable scripted domain for this module's expected images; a fresh
/// domain per call would break equality for the wrong reason.
fn expected_domain() -> NativeDomainId {
    static DOMAIN: std::sync::OnceLock<NativeDomainId> = std::sync::OnceLock::new();
    *DOMAIN.get_or_init(NativeDomainId::mint)
}

fn expected() -> BoundImage {
    BoundImage::scripted(expected_domain(), 42, 0).unwrap()
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
fn pre_window_owner_refuses_a_cold_group_without_reading_a_default_census() {
    use crate::process::cold_view_tests::ColdLeaderSubject;

    let mut group = ColdLeaderSubject::spawn(1);
    group.leave_leader();
    let mut engine = Engine::inventory(
        config(2, 1),
        Scope::Pid(group.pid()),
        HookRegistry::builtin(),
        vec![group.program.clone()],
    )
    .unwrap();
    let error = engine
        .open_inventory_owner(
            group.pid(),
            expected(),
            &mut ScriptedImage(ImageCheck::Exact),
        )
        .expect_err("a pre-window owner cannot buy cold metadata with a new default budget");
    assert!(error.to_string().contains("warm-only"), "{error:#}");
    assert!(engine.views.is_empty());
    assert!(engine.inventory_state().unwrap().owners.is_empty());
    assert!(engine.inventory_state().unwrap().reservations.is_empty());
    assert_eq!(engine.budget.attempted_io_bytes(), 0);
    assert_eq!(engine.next_view_id, 1, "the refused ID is still burned");
    group.call_three();
}

#[test]
fn pre_window_warm_owner_keeps_original_inactive_inventory_operation() {
    let mut engine = engine(2, 1);
    let owner = open(&mut engine);
    assert_eq!(engine.views.len(), 1);
    assert_eq!(engine.views[0].id(), owner);
    assert!(engine.views[0].still_the_same());
    assert_eq!(engine.budget.attempted_io_bytes(), 0);
    assert!(engine.budget.remaining_window_io().is_err());
    assert!(
        engine
            .inventory_state()
            .unwrap()
            .owners
            .contains_key(&owner)
    );
}

#[test]
fn absent_cookie_or_wrong_pid_scope_cannot_admit_an_owner() {
    // A zero ticket is unavailable: it cannot even construct an expected
    // image, so the growth path never sees it.
    assert!(BoundImage::scripted(expected_domain(), 0, 0).is_none());
    let mut engine = engine(2, 1);
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

fn pid_scoped_engine(pid: u32) -> Engine {
    Engine::inventory(
        config(2, 1),
        Scope::Pid(pid),
        HookRegistry::builtin(),
        Vec::new(),
    )
    .unwrap()
}

fn open_pid_owner(engine: &mut Engine, pid: u32, guard: &mut dyn ImageGuard) -> ProcessViewId {
    engine.open_inventory_owner(pid, expected(), guard).unwrap()
}

/// Call-counting scripted guard: proves whether the engine consulted the
/// guard at all (a refusal before invocation leaves `calls` at zero).
struct CountingGuard {
    reply: ImageCheck,
    calls: usize,
}

impl ImageGuard for CountingGuard {
    fn check(&mut self, _: &ProcessView, _: BoundImage) -> ImageCheck {
        self.calls += 1;
        self.reply
    }
}

/// Fresh-guard owner scene: a self-scoped engine, an active but rowless
/// binder domain, and the expected image for one scripted ticket/exec.
fn guard_owner_scene(ticket: u64, exec: u64) -> (Engine, NativeBinder, NativeDomainId, BoundImage) {
    let domain = NativeDomainId::mint();
    let mut binder = NativeBinder::new(BinderLimits::default());
    binder.note_exec_coverage(ExecCoverage::scripted(domain, 0));
    let expected = BoundImage::scripted(domain, ticket, exec).unwrap();
    (engine(2, 1), binder, domain, expected)
}

fn guard_window() -> ReadWindow {
    ReadWindow::new(1, Instant::now() + Duration::from_secs(30)).unwrap()
}

fn expired_window() -> ReadWindow {
    ReadWindow::new(1, Instant::now() - Duration::from_secs(1)).unwrap()
}

fn assert_no_owner(engine: &Engine) {
    assert!(engine.views.is_empty());
    let state = engine.inventory_state().unwrap();
    assert!(state.owners.is_empty());
    assert!(state.reservations.is_empty());
}

/// One scripted empty-module scan through the production scan path.
fn scan_empty(
    engine: &mut Engine,
    owner: ProcessViewId,
    guard: &mut dyn ImageGuard,
    id: u64,
) -> anyhow::Result<ScanReceipt> {
    let lease = engine.acquire_inventory_scan(owner).unwrap();
    let window = engine
        .budget
        .begin_window(WindowId::new(id), u64::MAX)
        .unwrap();
    let checkpoint = engine.budget.checkpoint(window.clone()).unwrap();
    let result = engine.scan_inventory_owner_with(&lease, guard, |_, _, _| {
        Ok(ScanOutcome::Scanned {
            modules: Vec::new(),
            skipped: Vec::new(),
            scan_ms: 0,
        })
    });
    engine.budget.finish_scan(checkpoint).unwrap();
    engine.budget.finish_window(window).unwrap();
    engine.release_inventory_scan(&lease).unwrap();
    result
}

#[test]
fn foreign_native_image_receipt_is_rejected_before_query() {
    let mut engine = engine(2, 1);
    let owner = open(&mut engine);
    // The exact same opaque image proceeds (control).
    let identity = engine.inventory_receipt_identity(owner).unwrap();
    let mut control = CountingGuard {
        reply: ImageCheck::Exact,
        calls: 0,
    };
    engine
        .check_inventory_image(&identity, &mut control)
        .unwrap();
    assert_eq!(control.calls, 1);
    // An equal-number foreign-domain value (the same 42/0 `expected`
    // carries, tagged elsewhere) rejects before guard invocation.
    let mut foreign = engine.inventory_receipt_identity(owner).unwrap();
    foreign.image = BoundImage::scripted(NativeDomainId::mint(), 42, 0).unwrap();
    let mut probe = CountingGuard {
        reply: ImageCheck::Exact,
        calls: 0,
    };
    assert!(engine.check_inventory_image(&foreign, &mut probe).is_err());
    assert_eq!(probe.calls, 0, "the receipt refuses before any guard query");
}

#[test]
fn same_binary_exec_without_lifecycle_row_refuses_complete() {
    const TICKET: u64 = 41;
    const E: u64 = 9;
    let pid = std::process::id();

    // Only the fresh post-scan exec advances; the scan refuses with
    // Changed and commits nothing, although PID, pin, domain, and ticket
    // are unchanged and no lifecycle row was delivered.
    let (mut engine, binder, domain, expected) = guard_owner_scene(TICKET, E);
    let mut source = ScriptedAcquisition::new(domain);
    source.script_observe(1, TICKET, E);
    source.script_observe(2, TICKET, E);
    source.script_observe(3, TICKET, E + 1);
    let mut guard = FreshImageGuard::new(&mut source, &binder, guard_window());
    let owner = engine
        .open_inventory_owner(pid, expected, &mut guard)
        .unwrap();
    let error = scan_empty(&mut engine, owner, &mut guard, 0)
        .err()
        .expect("the post-scan exec advance must refuse the scan");
    assert!(
        format!("{error:#}").contains("Changed"),
        "the refusal names the changed image: {error:#}"
    );
    assert_eq!(
        engine.inventory_owner_epochs(owner).unwrap().image_state,
        ImageCheck::Changed
    );
    assert_eq!(engine.inventory_last_complete(owner).unwrap(), None);
    assert!(
        engine.acquire_inventory_scan(owner).is_err(),
        "an ended image scans nothing new"
    );
    guard.release();
    assert_eq!(source.calls(), 3);
    assert_eq!(source.generations(), &[1, 2, 3]);
    assert_eq!(binder.census().rows, 0);
    assert_eq!(binder.census().pending, 0);

    // Control: a stable direct exec before and after the scan commits
    // complete.
    let (mut engine, binder, domain, expected) = guard_owner_scene(TICKET, E);
    let mut source = ScriptedAcquisition::new(domain);
    for generation in 1..=6 {
        source.script_observe(generation, TICKET, E);
    }
    let mut guard = FreshImageGuard::new(&mut source, &binder, guard_window());
    let owner = engine
        .open_inventory_owner(pid, expected, &mut guard)
        .unwrap();
    let receipt = scan_empty(&mut engine, owner, &mut guard, 0).unwrap();
    assert!(receipt_is_complete(&receipt, "stable post-scan exec"));
    let prepared = engine
        .prepare_inventory_reconciliation(receipt, &mut guard)
        .unwrap();
    let commit = engine
        .commit_inventory_reconciliation(prepared, &mut guard)
        .unwrap();
    assert!(commit.complete);
    assert_eq!(engine.inventory_last_complete(owner).unwrap(), Some(0));
    guard.release();
    assert_eq!(source.calls(), 6);
    assert_eq!(source.generations(), &[1, 2, 3, 4, 5, 6]);
    assert_eq!(binder.census().rows, 0, "no use row reached the binder");
}

#[test]
fn fresh_guard_unavailable_never_scans_or_consumes_owner_capacity() {
    const TICKET: u64 = 41;
    const E: u64 = 9;
    let pid = std::process::id();

    // A failed pre-scan query refuses before the scanner runs.
    {
        let (mut engine, binder, domain, expected) = guard_owner_scene(TICKET, E);
        let mut source = ScriptedAcquisition::new(domain);
        source.script_observe(1, TICKET, E);
        source.script_fail("query failed");
        let mut guard = FreshImageGuard::new(&mut source, &binder, guard_window());
        let owner = engine
            .open_inventory_owner(pid, expected, &mut guard)
            .unwrap();
        let lease = engine.acquire_inventory_scan(owner).unwrap();
        assert!(
            engine
                .scan_inventory_owner_with(&lease, &mut guard, |_, _, _| panic!(
                    "unavailable image authority must prevent scanning"
                ))
                .is_err()
        );
        assert_eq!(
            engine.inventory_owner_epochs(owner).unwrap().image_state,
            ImageCheck::Unavailable
        );
        assert_eq!(engine.views.len(), 1);
        assert!(engine.retirement_intents.is_empty());
        engine.release_inventory_scan(&lease).unwrap();
        guard.release();
        assert_eq!(source.calls(), 2);
        assert_eq!(binder.census().rows, 0);
    }

    // A stopped source fails the open and retains nothing.
    {
        let (mut engine, binder, domain, expected) = guard_owner_scene(TICKET, E);
        let mut source = ScriptedAcquisition::new(domain);
        source.script_fail("Inventory is stopping");
        let mut guard = FreshImageGuard::new(&mut source, &binder, guard_window());
        assert!(
            engine
                .open_inventory_owner(pid, expected, &mut guard)
                .is_err()
        );
        guard.release();
        assert_no_owner(&engine);
        assert_eq!(source.calls(), 1);
    }

    // An expired window fails the open before any scripted answer.
    {
        let (mut engine, binder, domain, expected) = guard_owner_scene(TICKET, E);
        let mut source = ScriptedAcquisition::new(domain);
        source.script_observe(1, TICKET, E);
        let mut guard = FreshImageGuard::new(&mut source, &binder, expired_window());
        assert!(
            engine
                .open_inventory_owner(pid, expected, &mut guard)
                .is_err()
        );
        guard.release();
        assert_no_owner(&engine);
        assert_eq!(source.calls(), 1);
    }

    // A stale (zero-generation) answer fails decoding and the open.
    {
        let (mut engine, binder, domain, expected) = guard_owner_scene(TICKET, E);
        let mut source = ScriptedAcquisition::new(domain);
        source.script_observe(0, TICKET, E);
        let mut guard = FreshImageGuard::new(&mut source, &binder, guard_window());
        assert!(
            engine
                .open_inventory_owner(pid, expected, &mut guard)
                .is_err()
        );
        guard.release();
        assert_no_owner(&engine);
        assert_eq!(source.calls(), 1);
        assert!(source.generations().is_empty());
    }

    // An answer built on a replacement original fails the open.
    {
        let (mut engine, binder, domain, expected) = guard_owner_scene(TICKET, E);
        let replacement = Arc::new(PidPin::open(pid).unwrap());
        let mut source = ScriptedAcquisition::new(domain);
        source.script_observe_on(1, TICKET, E, replacement);
        let mut guard = FreshImageGuard::new(&mut source, &binder, guard_window());
        assert!(
            engine
                .open_inventory_owner(pid, expected, &mut guard)
                .is_err()
        );
        guard.release();
        assert_no_owner(&engine);
        assert_eq!(source.calls(), 1);
    }

    // A post-scan failure preserves the prior complete commit.
    {
        let (mut engine, binder, domain, expected) = guard_owner_scene(TICKET, E);
        let mut source = ScriptedAcquisition::new(domain);
        for generation in 1..=7 {
            source.script_observe(generation, TICKET, E);
        }
        source.script_fail("post-scan query failed");
        let mut guard = FreshImageGuard::new(&mut source, &binder, guard_window());
        let owner = engine
            .open_inventory_owner(pid, expected, &mut guard)
            .unwrap();
        let first = scan_empty(&mut engine, owner, &mut guard, 0).unwrap();
        assert!(receipt_is_complete(&first, "first"));
        let prepared = engine
            .prepare_inventory_reconciliation(first, &mut guard)
            .unwrap();
        let commit = engine
            .commit_inventory_reconciliation(prepared, &mut guard)
            .unwrap();
        assert!(commit.complete);
        assert_eq!(engine.inventory_last_complete(owner).unwrap(), Some(0));
        let modules_before = engine.modules.clone();
        engine
            .request_inventory_refresh(owner, RefreshCause::Periodic)
            .unwrap();
        assert!(scan_empty(&mut engine, owner, &mut guard, 1).is_err());
        assert_eq!(engine.inventory_last_complete(owner).unwrap(), Some(0));
        assert_eq!(engine.modules, modules_before);
        assert_eq!(
            engine.inventory_owner_epochs(owner).unwrap().image_state,
            ImageCheck::Unavailable
        );
        guard.release();
        assert_eq!(source.calls(), 8);
    }

    // A prepare failure preserves the prior complete commit.
    {
        let (mut engine, binder, domain, expected) = guard_owner_scene(TICKET, E);
        let mut source = ScriptedAcquisition::new(domain);
        for generation in 1..=8 {
            source.script_observe(generation, TICKET, E);
        }
        source.script_fail("prepare query failed");
        let mut guard = FreshImageGuard::new(&mut source, &binder, guard_window());
        let owner = engine
            .open_inventory_owner(pid, expected, &mut guard)
            .unwrap();
        let first = scan_empty(&mut engine, owner, &mut guard, 0).unwrap();
        let prepared = engine
            .prepare_inventory_reconciliation(first, &mut guard)
            .unwrap();
        let commit = engine
            .commit_inventory_reconciliation(prepared, &mut guard)
            .unwrap();
        assert!(commit.complete);
        let modules_before = engine.modules.clone();
        engine
            .request_inventory_refresh(owner, RefreshCause::Periodic)
            .unwrap();
        let second = scan_empty(&mut engine, owner, &mut guard, 1).unwrap();
        assert!(
            engine
                .prepare_inventory_reconciliation(second, &mut guard)
                .is_err()
        );
        assert_eq!(engine.inventory_last_complete(owner).unwrap(), Some(0));
        assert_eq!(engine.modules, modules_before);
        assert_eq!(
            engine.inventory_owner_epochs(owner).unwrap().image_state,
            ImageCheck::Unavailable
        );
        guard.release();
        assert_eq!(source.calls(), 9);
    }

    // A publication (commit revalidation) failure preserves the commit.
    {
        let (mut engine, binder, domain, expected) = guard_owner_scene(TICKET, E);
        let mut source = ScriptedAcquisition::new(domain);
        for generation in 1..=10 {
            source.script_observe(generation, TICKET, E);
        }
        source.script_fail("publication query failed");
        let mut guard = FreshImageGuard::new(&mut source, &binder, guard_window());
        let owner = engine
            .open_inventory_owner(pid, expected, &mut guard)
            .unwrap();
        let first = scan_empty(&mut engine, owner, &mut guard, 0).unwrap();
        let prepared = engine
            .prepare_inventory_reconciliation(first, &mut guard)
            .unwrap();
        let commit = engine
            .commit_inventory_reconciliation(prepared, &mut guard)
            .unwrap();
        assert!(commit.complete);
        let modules_before = engine.modules.clone();
        engine
            .request_inventory_refresh(owner, RefreshCause::Periodic)
            .unwrap();
        let second = scan_empty(&mut engine, owner, &mut guard, 1).unwrap();
        let prepared = engine
            .prepare_inventory_reconciliation(second, &mut guard)
            .unwrap();
        assert!(
            engine
                .commit_inventory_reconciliation(prepared, &mut guard)
                .is_err()
        );
        assert_eq!(engine.inventory_last_complete(owner).unwrap(), Some(0));
        assert_eq!(engine.modules, modules_before);
        assert_eq!(
            engine.inventory_owner_epochs(owner).unwrap().image_state,
            ImageCheck::Unavailable
        );
        guard.release();
        assert_eq!(source.calls(), 11);
    }

    // Control, last: a genuine match admits and scans.
    {
        let (mut engine, binder, domain, expected) = guard_owner_scene(TICKET, E);
        let mut source = ScriptedAcquisition::new(domain);
        for generation in 1..=3 {
            source.script_observe(generation, TICKET, E);
        }
        let mut guard = FreshImageGuard::new(&mut source, &binder, guard_window());
        let owner = engine
            .open_inventory_owner(pid, expected, &mut guard)
            .unwrap();
        let receipt = scan_empty(&mut engine, owner, &mut guard, 0).unwrap();
        assert!(receipt_is_complete(&receipt, "genuine match"));
        guard.release();
        assert_eq!(source.calls(), 3);
        assert_eq!(binder.census().rows, 0);
    }
}

/// Real receipts only: a deferred or unavailable scan is a failed
/// prerequisite, never a reconciliation input. Returns whether complete.
fn receipt_is_complete(receipt: &ScanReceipt, label: &str) -> bool {
    match receipt {
        ScanReceipt::Complete(_) => true,
        ScanReceipt::AdditionsOnly(_) => false,
        ScanReceipt::Deferred { reason, .. } => {
            panic!("{label} scan deferred, cannot stage the reconciliation: {reason}")
        }
        ScanReceipt::Unavailable { reason, .. } => {
            panic!("{label} scan unavailable, cannot stage the reconciliation: {reason}")
        }
    }
}

fn assert_actual_provider_facts(
    modules: &[crate::discovery::identity::ReconciledModule],
    provider: &std::path::Path,
    label: &str,
) {
    assert!(
        !modules.is_empty(),
        "{label} must carry nonempty actual provider facts"
    );
    assert!(
        modules.iter().any(|module| {
            std::path::Path::new(&module.scanned.path) == provider
                && !module.scanned.tables.is_empty()
                && module
                    .scanned
                    .exports
                    .iter()
                    .any(|export| export == "C_GetFunctionList")
        }),
        "{label} must name the owned provider with decoded tables: {modules:?}",
    );
}

#[test]
fn stale_reconciliation_refusal_preserves_newer_committed_facts() {
    let mut fixture = DiscoveryLifecycleFixture::start();
    let pid = fixture.pid();
    let mut engine = pid_scoped_engine(pid);
    let mut guard = ScriptedImage(ImageCheck::Exact);
    let owner = open_pid_owner(&mut engine, pid, &mut guard);

    // Epoch 1: the owned child has not mapped its provider yet.
    engine
        .request_inventory_refresh(owner, RefreshCause::Periodic)
        .unwrap();
    let lease_a = engine.acquire_inventory_scan(owner).unwrap();
    let window_a = engine
        .budget
        .begin_window(WindowId::new(0), u64::MAX)
        .unwrap();
    let checkpoint_a = engine.budget.checkpoint(window_a.clone()).unwrap();
    let old_receipt = engine.scan_inventory_owner(&lease_a, &mut guard).unwrap();
    engine.budget.finish_scan(checkpoint_a).unwrap();
    engine.budget.finish_window(window_a).unwrap();
    let old_complete = receipt_is_complete(&old_receipt, "pre-load");
    assert!(
        old_complete,
        "pre-load receipt must be Complete; an AdditionsOnly receipt here requires test redesign"
    );
    let old_prepared = engine
        .prepare_inventory_reconciliation(old_receipt, &mut guard)
        .unwrap();
    assert!(
        old_prepared.candidate().modules.is_empty(),
        "the pre-load reconciliation must stage no provider facts"
    );
    engine.release_inventory_scan(&lease_a).unwrap();

    // The owned child really loads its provider behind the acknowledged barrier.
    fixture.load();

    // Epoch 2: the provider is mapped; the newer reconciliation commits.
    engine
        .request_inventory_refresh(owner, RefreshCause::LoaderHint)
        .unwrap();
    let lease_b = engine.acquire_inventory_scan(owner).unwrap();
    let window_b = engine
        .budget
        .begin_window(WindowId::new(1), u64::MAX)
        .unwrap();
    let checkpoint_b = engine.budget.checkpoint(window_b.clone()).unwrap();
    let new_receipt = engine.scan_inventory_owner(&lease_b, &mut guard).unwrap();
    engine.budget.finish_scan(checkpoint_b).unwrap();
    engine.budget.finish_window(window_b).unwrap();
    let new_complete = receipt_is_complete(&new_receipt, "post-load");
    assert!(
        new_complete,
        "post-load receipt must be Complete; an AdditionsOnly receipt here requires test redesign"
    );
    let new_prepared = engine
        .prepare_inventory_reconciliation(new_receipt, &mut guard)
        .unwrap();
    assert_actual_provider_facts(
        &new_prepared.candidate().modules,
        fixture.provider_path(),
        "post-load prepared",
    );
    let new_commit = engine
        .commit_inventory_reconciliation(new_prepared, &mut guard)
        .unwrap();
    engine.release_inventory_scan(&lease_b).unwrap();

    // Prerequisites: the newer commit is real, same-epoch, and complete
    // exactly when its receipt was.
    assert_eq!(new_commit.owner, owner);
    assert_eq!(new_commit.complete, new_complete);
    assert_eq!(new_commit.serviced_epoch, 2);
    assert!(!new_commit.refresh_pending);
    assert_actual_provider_facts(&engine.modules, fixture.provider_path(), "newer committed");
    let committed_epochs = engine.inventory_owner_epochs(owner).unwrap();
    assert_eq!(committed_epochs.requested, 2);
    assert_eq!(committed_epochs.serviced, 2);
    assert_eq!(committed_epochs.dirty, 0);
    assert_eq!(
        engine.inventory_last_complete(owner).unwrap(),
        if new_complete { Some(0) } else { None }
    );

    // Snapshot every committed fact the stale refusal must preserve.
    let pins = engine.pinned.view_claims(owner).unwrap().clone();
    let pin_revision = engine.pinned.revision();
    let pin_debug = format!("{:?}", engine.pinned);
    let modules = engine.modules.clone();
    let plan = engine.plan.clone();
    let bindings = engine.selection_bindings.clone();
    let claims = engine.selection_claims.clone();
    let tables = engine.selection_tables.clone();
    let facts_revision = engine.facts_revision;

    // The stale epoch-1 commit refuses: a newer refresh was serviced.
    let error = engine
        .commit_inventory_reconciliation(old_prepared, &mut guard)
        .expect_err("the stale commit must refuse after a newer commit");
    assert!(
        error
            .to_string()
            .contains("serviced a refresh newer than the committed receipt"),
        "{error:#}"
    );

    // The refusal preserves every newer committed fact.
    assert_eq!(engine.pinned.view_claims(owner), Some(&pins));
    assert_eq!(engine.pinned.revision(), pin_revision);
    assert_eq!(format!("{:?}", engine.pinned), pin_debug);
    assert_eq!(engine.modules, modules);
    assert_eq!(engine.plan, plan);
    assert_eq!(engine.selection_bindings, bindings);
    assert_eq!(engine.selection_claims, claims);
    assert_eq!(engine.selection_tables, tables);
    assert_eq!(engine.facts_revision, facts_revision);
    assert_eq!(
        engine.inventory_owner_epochs(owner).unwrap(),
        committed_epochs
    );
    assert_eq!(
        engine.inventory_last_complete(owner).unwrap(),
        committed_epochs.complete
    );
}

#[test]
fn reconciliation_commit_keeps_a_newer_requested_refresh_pending() {
    let mut fixture = DiscoveryLifecycleFixture::start();
    let pid = fixture.pid();
    let mut engine = pid_scoped_engine(pid);
    let mut guard = ScriptedImage(ImageCheck::Exact);
    let owner = open_pid_owner(&mut engine, pid, &mut guard);

    // Epoch 1: prepared before the provider is mapped.
    engine
        .request_inventory_refresh(owner, RefreshCause::Periodic)
        .unwrap();
    let lease_one = engine.acquire_inventory_scan(owner).unwrap();
    let window_one = engine
        .budget
        .begin_window(WindowId::new(0), u64::MAX)
        .unwrap();
    let checkpoint_one = engine.budget.checkpoint(window_one.clone()).unwrap();
    let first_receipt = engine.scan_inventory_owner(&lease_one, &mut guard).unwrap();
    engine.budget.finish_scan(checkpoint_one).unwrap();
    engine.budget.finish_window(window_one).unwrap();
    let first_complete = receipt_is_complete(&first_receipt, "epoch-1");
    assert!(
        first_complete,
        "epoch-1 receipt must be Complete; an AdditionsOnly receipt here requires test redesign"
    );
    let first_prepared = engine
        .prepare_inventory_reconciliation(first_receipt, &mut guard)
        .unwrap();
    assert!(
        first_prepared.candidate().modules.is_empty(),
        "the epoch-1 reconciliation must stage no provider facts"
    );
    engine.release_inventory_scan(&lease_one).unwrap();

    // The provider really loads; epoch 2 is requested but not serviced yet.
    fixture.load();
    engine
        .request_inventory_refresh(owner, RefreshCause::LoaderHint)
        .unwrap();

    // Committing epoch 1 with a newer request outstanding succeeds and
    // keeps the newer refresh pending with its dirty causes.
    let first_commit = engine
        .commit_inventory_reconciliation(first_prepared, &mut guard)
        .unwrap();
    assert_eq!(first_commit.owner, owner);
    assert_eq!(first_commit.complete, first_complete);
    assert_eq!(first_commit.serviced_epoch, 1);
    assert!(first_commit.refresh_pending);
    let pending_epochs = engine.inventory_owner_epochs(owner).unwrap();
    assert_eq!(pending_epochs.requested, 2);
    assert_eq!(pending_epochs.serviced, 1);
    assert_eq!(
        pending_epochs.dirty, 3,
        "Periodic and LoaderHint causes stay dirty"
    );
    assert_eq!(
        engine.inventory_last_complete(owner).unwrap(),
        if first_complete { Some(0) } else { None }
    );

    // The later epoch-2 scan really runs and commits: same-epoch success
    // retains the new provider facts and clears only serviced work.
    let lease_two = engine.acquire_inventory_scan(owner).unwrap();
    let window_two = engine
        .budget
        .begin_window(WindowId::new(1), u64::MAX)
        .unwrap();
    let checkpoint_two = engine.budget.checkpoint(window_two.clone()).unwrap();
    let second_receipt = engine.scan_inventory_owner(&lease_two, &mut guard).unwrap();
    engine.budget.finish_scan(checkpoint_two).unwrap();
    engine.budget.finish_window(window_two).unwrap();
    let second_complete = receipt_is_complete(&second_receipt, "epoch-2");
    assert!(
        second_complete,
        "epoch-2 receipt must be Complete; an AdditionsOnly receipt here requires test redesign"
    );
    let second_prepared = engine
        .prepare_inventory_reconciliation(second_receipt, &mut guard)
        .unwrap();
    let second_commit = engine
        .commit_inventory_reconciliation(second_prepared, &mut guard)
        .unwrap();
    engine.release_inventory_scan(&lease_two).unwrap();

    assert_eq!(second_commit.owner, owner);
    assert_eq!(second_commit.complete, second_complete);
    assert_eq!(second_commit.serviced_epoch, 2);
    assert!(!second_commit.refresh_pending);
    assert_actual_provider_facts(
        &engine.modules,
        fixture.provider_path(),
        "epoch-2 committed",
    );
    let settled_epochs = engine.inventory_owner_epochs(owner).unwrap();
    assert_eq!(settled_epochs.requested, 2);
    assert_eq!(settled_epochs.serviced, 2);
    assert_eq!(settled_epochs.dirty, 0);
    assert_eq!(
        engine.inventory_last_complete(owner).unwrap(),
        if first_complete || second_complete {
            Some(0)
        } else {
            None
        }
    );
}
