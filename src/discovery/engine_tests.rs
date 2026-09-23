//! SPDX-License-Identifier: GPL-3.0-or-later
use super::session_fixture::ScriptedSession;
use super::*;

#[path = "inventory_claims_tests.rs"]
mod inventory_claims;
use crate::discovery::identity::test_fixture::{
    SHA as OVERLAY_SHA, backing_file as overlay_backing_file, module as overlay_module,
    overlay as overlay_key, pins as overlay_pins, reback as overlay_reback,
    view_pin as overlay_view_pin,
};
use crate::discovery::identity::{
    ManifestPinError, ManifestStaleReason, PinnedObjectId, ReconciledModule, open_view_object,
    pin_manifest_objects, pin_manifest_objects_deferred, pin_scanned_objects,
    reconcile_scanned_modules,
};
use crate::discovery::loader::LoaderContextSpec;
use crate::discovery::scan::{
    IO_CEILING_REASON, SCAN_DEADLINE_REASON, ScanLimits, ScannedEntry, ScannedTable,
    WORK_CEILING_REASON, order_tables_by_evidence,
};
use crate::discovery::scheduler::MAX_PENDING_REFRESH;
use crate::{semantics, trace};
use p11scope_manifest::manifest::{
    Acquisition, AliasEntry, AliasGroup, FunctionRecord, InterfaceClassification, SurfaceRecord,
    SurfaceSource, Version, WalkOutcome,
};
use p11scope_manifest::maps::parse_maps;
use std::cell::Cell;
use std::io::Write as _;
use std::path::PathBuf;

/// Task 11 fix round 2 (csf_ce5962b root closure): the live per-record
/// snapshot read charges the capture budget and honors the installed
/// batch deadline on the real `/proc` path, refusing before a byte is read.
#[test]
fn live_maps_snapshot_charges_the_budget_and_honors_the_installed_deadline() {
    use crate::discovery::scan::SCAN_DEADLINE_REASON;

    let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let mut budget = CaptureWorkBudget::default();
    assert!(!Engine::read_maps(&view, &mut budget).unwrap().is_empty());
    assert!(
        budget.attempted_io_bytes() > 0,
        "the snapshot read is charged to the capture budget"
    );

    let mut budget = CaptureWorkBudget::default();
    budget.set_deadline(Some(0));
    let error = Engine::read_maps(&view, &mut budget)
        .err()
        .map(|error| error.to_string());
    assert_eq!(error.as_deref(), Some(SCAN_DEADLINE_REASON));
    assert_eq!(
        budget.attempted_io_bytes(),
        0,
        "an expired deadline refuses before a byte is read"
    );
}

#[test]
fn lifecycle_tier_gap_uses_existing_public_discovery_evidence() {
    let mut engine = Engine::empty();
    let mut session = ScriptedSession::default();
    session.lifecycle_tracking_unavailable =
        Some("live lifecycle tracking unavailable: tracefs not found");
    engine.record_session_lifecycle_tracking(&session);
    record_object_skips(&mut engine.plan, &engine.counters.object_skips);
    engine.publish_current_capture_facts().unwrap();

    assert_eq!(engine.plan.skipped.len(), 1);
    assert_eq!(
        render::capture_skipped_out(&engine.plan.skipped[0]),
        render::SkippedOut {
            name: "discovery subject".into(),
            reason: "discovery unavailable".into(),
        }
    );
    assert!(
        !engine.plan.skipped.is_empty(),
        "the final engine plan supplies the existing public PARTIAL projection"
    );
}

#[test]
fn unvalidated_discovery_accounting_changes_only_bounded_loss_evidence() {
    let (mut engine, owner) = Engine::retiring_loader_context(std::process::id());
    let view = ProcessViewId(0);
    let timing = timing_key(0);
    engine.timings.observe(&timing, 1_000_000);
    engine.timings.complete(&timing, 2_000_000);
    engine.discovery_truncated = 1;
    engine.refresh_requested.insert(std::process::id());
    engine.pending_retirements.insert(view);
    engine.ready_expected_removals.insert(view);
    engine.expected_target_exit_pending = Some(view);
    engine.loader_records_accepted = 7;
    engine.counter_snapshot.loader_hits = 11;
    engine.terminal_journal = Some(TerminalJournal {
        owner,
        dispatch_started: true,
        retry_used: false,
    });
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_LOADER;
    engine
        .pending_discovery_records
        .push(QueuedDiscoveryRecord {
            record,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        });
    let confirmation = PauseClosure::new(true);

    let before_plan = engine.plan.clone();
    let before_discovery = engine.discovery.clone();
    let before_views: Vec<_> = engine.views.iter().map(ProcessView::id).collect();
    let before_refresh = engine.refresh_requested.clone();
    let before_retirements = engine.pending_retirements.clone();
    let before_ready = engine.ready_expected_removals.clone();
    let before_facts = engine.capture_facts();
    let before_journal = engine.terminal_journal_for_test();

    engine.account_unvalidated_discovery(0);
    assert_eq!(engine.timings.gap_ns(&timing), Some(1_000_000));
    engine.account_unvalidated_discovery(u64::MAX);
    engine.account_unvalidated_discovery(1);

    assert_eq!(engine.discovery_truncated, u64::MAX);
    assert_eq!(engine.capture_facts().discovery_truncated, u64::MAX);
    assert_eq!(engine.capture_facts().attach_gap_ms(), None);
    assert_eq!(engine.plan, before_plan);
    assert_eq!(engine.discovery, before_discovery);
    assert_eq!(
        engine.views.iter().map(ProcessView::id).collect::<Vec<_>>(),
        before_views
    );
    assert_eq!(engine.refresh_requested, before_refresh);
    assert_eq!(engine.loader_records_accepted, 7);
    assert_eq!(engine.counter_snapshot.loader_hits, 11);
    assert_eq!(engine.loader_context_state_for_test(owner), Some("live"));
    assert_eq!(engine.pending_retirements, before_retirements);
    assert_eq!(engine.ready_expected_removals, before_ready);
    assert_eq!(engine.expected_target_exit_pending, Some(view));
    assert_eq!(engine.terminal_journal_for_test(), before_journal);
    assert!(engine.terminal_batch_for_test().is_none());
    assert_eq!(engine.pending_discovery_records.len(), 1);
    assert!(confirmation.required_complete());
    assert_eq!(
        engine.capture_facts().table_entries,
        before_facts.table_entries
    );
    assert_eq!(engine.capture_facts().slots, before_facts.slots);
}

fn dynamic_export_work(module: PinnedTimingKey, already_attached: bool) -> DynamicExportWork {
    DynamicExportWork {
        context: LoaderContextId::from_case_id(0),
        module: Some(module),
        object: PinnedObjectId(7),
        file_offset: 0x10,
        cookie: 1,
        abi: HookAbi::FunctionList,
        already_attached,
        selection_binding: None,
    }
}

fn timing_key(index: usize) -> PinnedTimingKey {
    static KEYS: std::sync::OnceLock<Vec<PinnedTimingKey>> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        let view = ProcessView::open(ProcessViewId(99), std::process::id()).unwrap();
        let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
        let map_index = MapIndex::new(&maps).expect("the self maps snapshot is valid");
        let mut keys = Vec::new();
        for mapping in maps
            .iter()
            .filter(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
        {
            let Resolved::File {
                path: MappedPath::Usable(path),
                ..
            } = map_index.resolve(mapping.start)
            else {
                continue;
            };
            let module = mapped_object(&view, mapping, &path);
            let pins = pin_test_module(&view, &module);
            let object = pins
                .id_for_scanned(&module, module.key, &module.path)
                .unwrap();
            let key = pins.owned_timing_key(object).unwrap();
            if !keys.contains(&key) {
                keys.push(key);
            }
            if keys.len() == 3 {
                break;
            }
        }
        assert_eq!(
            keys.len(),
            3,
            "the test process has three executable objects"
        );
        keys
    })[index]
        .clone()
}

#[test]
fn pause_closure_preserves_real_required_attachment_failure() {
    let failed = timing_key(0);
    let outcome = ApplyOutcome {
        disposition: ApplyDisposition::Accepted,
        static_failures: [failed].into_iter().collect(),
        ..ApplyOutcome::default()
    };
    let mut closure = PauseClosure::new(true);

    closure.observe_apply(&outcome);

    assert!(!closure.required_complete());
}

#[test]
fn unattributed_selection_rejection_marks_loss_and_invalidates_coverage() {
    // WINS: the seven unattributed-selection rejections share one
    // helper — loss marker, coverage invalidation, Rejected outcome.
    let mut engine = Engine::empty();
    let outcome = engine.reject_unattributed_selection(7, "a test selection record");
    assert!(matches!(
        outcome,
        DiscoveryRecordOutcome::Rejected(RecordRejection::SelectionUnattributed)
    ));
    assert_eq!(engine.counters.object_skips.len(), 1);
    let skipped = &engine.counters.object_skips[0];
    assert_eq!(skipped.subject, "live interface selection");
    assert_eq!(skipped.reason, "a test selection record");
}

#[test]
fn pinned_unchanged_check_refreshes_the_sticky_flag() {
    // The bool stays discarded here — evidence reads the sticky flag.
    let engine = Engine::empty();
    engine.pinned().check_unchanged().map(|_| ()).unwrap();
    assert!(!engine.pinned().provider_changed());
}

#[test]
fn every_rejected_discovery_record_fails_the_pause_closure() {
    let rejections = [
        RecordRejection::ExportNoRetainedView,
        RecordRejection::ExportNoLowerableOwner,
        RecordRejection::SelectionUnattributed,
        RecordRejection::LoaderMissingCounterAuthority,
        RecordRejection::LoaderInvalidContext,
        RecordRejection::LoaderNoRetainedView,
        RecordRejection::LoaderUnknownContext,
        RecordRejection::LoaderMissingMapping,
        RecordRejection::LoaderMismatchedMapping,
        RecordRejection::LoaderPinnedIdentityMismatch,
        RecordRejection::LoaderValidationFailure,
        RecordRejection::UnknownKind,
    ];

    for rejection in rejections {
        let outcome = DiscoveryRecordOutcome::Rejected(rejection);
        assert!(
            !outcome.required_complete(),
            "{rejection:?} must make a pause batch non-confirmable"
        );
    }
}

#[test]
fn loader_retirement_never_owns_an_untimed_session_dequeue() {
    let source = include_str!("engine.rs");
    let retirement = source
        .split_once("    fn retire_loader_contexts(")
        .unwrap()
        .1
        .split_once("    fn queue_stale_views(")
        .unwrap()
        .0;
    assert!(!retirement.contains("Self::collect_discovery_records(session)"));
    assert!(retirement.contains("collect(session)"));
}

/// The generic (non-terminal) drain never retries: `drain_discovery_tick`
/// aborts the run on `?` (src/run.rs) instead of retaining and replaying
/// anything. Its error text must not claim retention the terminal routes
/// actually perform.
#[test]
fn generic_drain_failure_states_no_retention_claim() {
    let record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    let retained =
        IncompleteTerminalDrain::new(vec![record], 0, 0, anyhow!("scripted ring read failed"));

    let error = Engine::generic_drain_error(retained.into());

    assert_eq!(error.to_string(), "scripted ring read failed");
    assert!(
        !error.to_string().contains("retained"),
        "the generic drain retains nothing across ticks: {error:#}"
    );
}

fn malformed_dequeues(count: usize) -> Vec<Result<Option<crate::events::DiscoveryItem>>> {
    (0..count)
        .map(|_| Ok(Some(crate::events::DiscoveryItem::Malformed)))
        .collect()
}

/// One record past the quantum, then a dequeue that must never be reached:
/// a producer that keeps the live ring nonempty must not keep the shared
/// collector from returning to its caller's deadline and signal checks.
#[test]
fn live_collector_stops_at_its_quantum_with_the_backlog_still_queued() {
    let record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    let mut session = ScriptedSession::default();
    session.dequeues.extend(
        (0..=LIVE_DISCOVERY_DRAIN_QUANTUM)
            .map(|_| Ok(Some(crate::events::DiscoveryItem::Record(record)))),
    );
    session
        .dequeues
        .push_back(Err(anyhow!("dequeued past the quantum")));

    let incomplete = match Engine::collect_discovery_records(&mut session) {
        Ok((records, malformed)) => panic!(
            "a quantum stop is an incomplete drain, never an empty ring: {} records, {malformed} malformed",
            records.len()
        ),
        Err(error) => error
            .downcast::<IncompleteTerminalDrain>()
            .expect("the exact prefix travels with the stop"),
    };

    assert!(incomplete.backlog, "{incomplete:?}");
    assert_eq!(incomplete.records.len(), LIVE_DISCOVERY_DRAIN_QUANTUM);
    assert_eq!(incomplete.malformed, 0);
    assert_eq!(
        session.dequeues.len(),
        2,
        "the record past the quantum and the sentinel stay queued"
    );
}

/// The generic tick route applies a quantum's exact prefix and returns;
/// the backlog waits on the ring for the next tick, behind the run loop's
/// duration/signal checks, and is never a batch error.
#[test]
fn the_live_drain_applies_the_quantum_prefix_and_leaves_the_backlog_queued() {
    let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
    let mut session = ScriptedSession::default();
    session
        .dequeues
        .extend(malformed_dequeues(LIVE_DISCOVERY_DRAIN_QUANTUM + 1));
    session
        .dequeues
        .push_back(Err(anyhow!("dequeued past the quantum")));

    engine
        .drain_discovery_from(&mut session)
        .expect("a backlog is not a drain failure");

    assert_eq!(
        engine.malformed_discovery,
        LIVE_DISCOVERY_DRAIN_QUANTUM as u64
    );
    assert_eq!(session.dequeues.len(), 2);

    session.dequeues.pop_back();
    engine.drain_discovery_from(&mut session).unwrap();

    assert_eq!(
        engine.malformed_discovery,
        LIVE_DISCOVERY_DRAIN_QUANTUM as u64 + 1
    );
    assert!(session.dequeues.is_empty());
}

/// The shallow predicate is the exact deferral contract: a quiet
/// non-pid engine may skip the inventory sweep, while pending work, a
/// refresh request, staged facts, or pid scope always forces the full
/// pass. Pid scope never defers: its per-tick sweep is the generation
/// authority and already cheap.
#[test]
fn shallow_idle_predicate_covers_pending_refresh_staged_and_scope() {
    let (mut engine, _dir) = engine_over_cgroup_naming(&[]);
    assert!(engine.discovery_shallow_idle());

    engine.pending_retirements.insert(ProcessViewId(7));
    assert!(!engine.discovery_shallow_idle());
    engine.pending_retirements.clear();

    engine.refresh_requested.insert(std::process::id());
    assert!(!engine.discovery_shallow_idle());
    engine.refresh_requested.clear();

    engine.capture_facts.staged = Some(engine.capture_facts.history.clone());
    assert!(!engine.discovery_shallow_idle());
    engine.capture_facts.staged = None;

    engine.scope = Scope::Pid(std::process::id());
    assert!(!engine.discovery_shallow_idle());

    assert!(engine.pending_loader_scans.is_empty());
    assert!(engine.pending_rejected_keys.is_empty());
    assert!(engine.pending_leader_exit_views.is_empty());
    assert!(engine.expected_target_exit_pending.is_none());
    assert!(engine.ready_expected_removals.is_empty());
    assert!(engine.pending_discovery_records.is_empty());
}

/// Loader events are never delayed by shallow frames: a ring with
/// records upgrades to the full pass and applies them same-frame.
#[test]
fn shallow_drain_applies_ring_records_like_a_full_pass() {
    let (mut engine, _dir) = engine_over_cgroup_naming(&[]);
    let mut session = ScriptedSession::default();
    session.dequeues.extend(malformed_dequeues(3));

    assert!(
        !engine
            .drain_discovery_shallow_from(&mut session, false)
            .expect("records upgrade, never fail")
    );

    assert_eq!(engine.malformed_discovery, 3);
    assert!(session.dequeues.is_empty());
}

/// A quiet frame applies nothing and changes nothing: no plan change,
/// no counter movement, no queued work.
#[test]
fn shallow_drain_skips_quiet_frames_without_side_effects() {
    let (mut engine, _dir) = engine_over_cgroup_naming(&[]);
    let mut session = ScriptedSession::default();

    assert!(
        !engine
            .drain_discovery_shallow_from(&mut session, false)
            .unwrap()
    );
    assert!(
        !engine
            .drain_discovery_shallow_from(&mut session, true)
            .expect("a forced full pass over quiet state still applies nothing")
    );

    assert_eq!(engine.malformed_discovery, 0);
    assert!(engine.pending_discovery_records.is_empty());
    assert!(engine.pending_retirements.is_empty());
}

#[test]
fn terminal_drain_consumes_all_discovery_quanta_and_refreshes_counters() {
    let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
    let mut session = ScriptedSession::default();
    session.counters.loader_hits = 7;
    session.dequeues.extend(
        (0..=LIVE_DISCOVERY_DRAIN_QUANTUM)
            .map(|_| Ok(Some(crate::events::DiscoveryItem::Malformed))),
    );
    session.dequeues.push_back(Ok(None));

    assert!(!engine.drain_discovery_terminal_from(&mut session).unwrap());
    assert_eq!(
        engine.malformed_discovery_for_test(),
        LIVE_DISCOVERY_DRAIN_QUANTUM as u64 + 1
    );
    assert_eq!(
        engine.capture_facts().discovery_truncated,
        LIVE_DISCOVERY_DRAIN_QUANTUM as u64 + 1
    );
    assert_eq!(engine.loader_discovery().hits, 7);
    assert_eq!(
        session.counter_reads(),
        2,
        "each applied quantum refreshes counters"
    );
    assert!(
        session.dequeues.is_empty(),
        "the terminating empty read is consumed"
    );
}

#[test]
fn terminal_drain_never_attaches_a_late_valid_export() {
    let (view, _maps, record) = self_export_fixture(ProcessViewId(0));
    let mut engine = Engine::empty();
    engine.next_view_id = 1;
    engine.views.push(view);
    engine.budget = CaptureWorkBudget::new(ScanLimits {
        per_object_bytes: u64::MAX,
        total_bytes: u64::MAX,
    });
    let mut session = ScriptedSession::default();
    session.dequeues.extend([
        Ok(Some(crate::events::DiscoveryItem::Record(record))),
        Ok(None),
    ]);

    engine
        .drain_discovery_terminal_from(&mut session)
        .expect("a valid late record is accounted without post-detach attach");

    assert!(session.attached_slots.is_empty());
    assert!(session.dynamic_attach_calls.is_empty());
    assert!(
        engine
            .plan
            .slots
            .iter()
            .all(|slot| !engine.plan.is_active(slot.index)),
        "terminal discovery must not admit active targets"
    );
    assert!(session.dequeues.is_empty());
}

#[test]
fn bounded_terminal_drain_rejects_late_export_and_leaves_one_quantum_backlog() {
    let (view, _maps, record) = self_export_fixture(ProcessViewId(0));
    let mut engine = Engine::empty();
    engine.next_view_id = 1;
    engine.views.push(view);
    engine.budget = CaptureWorkBudget::new(ScanLimits {
        per_object_bytes: u64::MAX,
        total_bytes: u64::MAX,
    });
    let mut session = ScriptedSession::default();
    session
        .dequeues
        .push_back(Ok(Some(crate::events::DiscoveryItem::Record(record))));
    session.dequeues.extend(
        (0..LIVE_DISCOVERY_DRAIN_QUANTUM)
            .map(|_| Ok(Some(crate::events::DiscoveryItem::Malformed))),
    );

    engine
        .drain_discovery_terminal_bounded_from(&mut session)
        .expect("a bounded terminal drain keeps its unread backlog");

    assert!(session.attached_slots.is_empty());
    assert!(session.dynamic_attach_calls.is_empty());
    assert!(
        engine
            .plan
            .slots
            .iter()
            .all(|slot| !engine.plan.is_active(slot.index)),
        "detach-failure discovery must not admit active targets"
    );
    assert_eq!(
        session.dequeues.len(),
        1,
        "only the record beyond the bounded quantum remains queued"
    );
    assert_eq!(
        engine.malformed_discovery_for_test(),
        (LIVE_DISCOVERY_DRAIN_QUANTUM - 1) as u64
    );
}

#[test]
fn terminal_drain_applies_a_consumed_prefix_before_reporting_dequeue_failure() {
    let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
    let mut session = ScriptedSession::default();
    session.dequeues.extend([
        Ok(Some(crate::events::DiscoveryItem::Malformed)),
        Ok(Some(crate::events::DiscoveryItem::Malformed)),
        Err(anyhow!("scripted terminal dequeue failed")),
    ]);

    let error = engine
        .drain_discovery_terminal_from(&mut session)
        .unwrap_err();

    assert_eq!(error.to_string(), "scripted terminal dequeue failed");
    assert_eq!(engine.malformed_discovery_for_test(), 2);
    assert_eq!(engine.capture_facts().discovery_truncated, 2);
    assert!(session.dequeues.is_empty());
}

#[test]
fn bounded_terminal_drain_applies_a_consumed_prefix_before_dequeue_failure() {
    let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
    let mut session = ScriptedSession::default();
    session.dequeues.extend([
        Ok(Some(crate::events::DiscoveryItem::Malformed)),
        Err(anyhow!("scripted bounded terminal dequeue failed")),
    ]);

    let error = engine
        .drain_discovery_terminal_bounded_from(&mut session)
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "scripted bounded terminal dequeue failed"
    );
    assert_eq!(engine.malformed_discovery_for_test(), 1);
    assert_eq!(engine.capture_facts().discovery_truncated, 1);
    assert!(session.dequeues.is_empty());
}

#[test]
fn a_real_dequeue_failure_still_aborts_the_generic_route() {
    let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
    let mut session = ScriptedSession::default();
    session
        .dequeues
        .push_back(Err(anyhow!("scripted ring read failed")));

    let error = engine.drain_discovery_from(&mut session).unwrap_err();

    assert_eq!(error.to_string(), "scripted ring read failed");
}

/// Every dequeue is capture-wide work, charged at the sink the records
/// enter so the one work ceiling counts ring traffic too. The budget has
/// no unit accessor and `DEFAULT_WORK_CEILING` is private to scan.rs, so
/// the charge is observed exactly through the ceiling itself.
#[test]
fn dequeued_discovery_work_is_charged_to_the_capture_budget() {
    const WORK_CEILING: u64 = 16 * 1024 * 1024;
    let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
    assert!(engine.budget.charge(WORK_CEILING - 3));
    let mut session = ScriptedSession::default();
    session.dequeues.extend(malformed_dequeues(3));
    engine.drain_discovery_from(&mut session).unwrap();
    assert!(
        !engine.budget.charge(1),
        "three dequeues must have consumed the last three work units"
    );

    let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
    assert!(engine.budget.charge(WORK_CEILING - 4));
    let mut session = ScriptedSession::default();
    session.dequeues.extend(malformed_dequeues(3));
    engine.drain_discovery_from(&mut session).unwrap();
    assert!(engine.budget.charge(1), "exactly one unit per dequeue");
    assert!(!engine.budget.charge(1));
}

/// Past the ceiling the records are already off the ring, so they are
/// still applied — dropping them would be silent loss — and the sticky
/// stop the refused charge leaves is what the lowering and the next scan
/// refuse on and publish.
#[test]
fn a_drain_past_the_work_ceiling_still_applies_the_dequeued_records() {
    let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
    assert!(engine.budget.charge(16 * 1024 * 1024));
    let mut session = ScriptedSession::default();
    session.dequeues.extend(malformed_dequeues(2));
    engine.drain_discovery_from(&mut session).unwrap();
    session.dequeues.extend(malformed_dequeues(1));
    engine.drain_discovery_from(&mut session).unwrap();

    assert_eq!(
        engine.malformed_discovery, 3,
        "dequeued records are never dropped"
    );
    assert!(!engine.budget.charge(1), "the ceiling stays sticky");
}

/// Task 11 fix round 3 (writer A1 follow-ups 1 and 2). A1's drain quantum
/// returns to the caller at this sink, so the sink is where the live
/// collector path polls the clock: a batch deadline that expired during the
/// drain stops the capture at the quantum boundary instead of one whole
/// batch later. A refused charge is published there exactly once, under
/// whichever ceiling actually stopped it — the work ceiling and the
/// deadline are never labelled as each other.
#[test]
fn a_drained_quantum_polls_the_batch_deadline_and_publishes_its_own_stop() {
    let drain_skip = |engine: &Engine| -> Vec<Skipped> {
        engine
            .counters
            .object_skips
            .iter()
            .filter(|skip| skip.subject == "live discovery drain")
            .cloned()
            .collect()
    };

    let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
    let mut session = ScriptedSession::default();
    let mut collect = Engine::collect_discovery_records;
    engine
        .apply_discovery_batch_with(
            &mut session,
            Vec::new(),
            2,
            true,
            false,
            &mut collect,
            Some(0),
        )
        .unwrap();
    assert_eq!(
        drain_skip(&engine),
        vec![Skipped {
            subject: "live discovery drain".into(),
            reason: SCAN_DEADLINE_REASON.into(),
        }],
        "an expired batch deadline stops the drain at its quantum, once"
    );

    let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
    assert!(engine.budget.charge(16 * 1024 * 1024));
    let mut session = ScriptedSession::default();
    let mut collect = Engine::collect_discovery_records;
    engine
        .apply_discovery_batch_with(&mut session, Vec::new(), 2, true, false, &mut collect, None)
        .unwrap();
    assert_eq!(
        drain_skip(&engine),
        vec![Skipped {
            subject: "live discovery drain".into(),
            reason: WORK_CEILING_REASON.into(),
        }],
        "a refused charge is the work ceiling, never mislabelled as the deadline"
    );

    // An ordinary drain inside its deadline publishes nothing at all.
    let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
    let mut session = ScriptedSession::default();
    let mut collect = Engine::collect_discovery_records;
    engine
        .apply_discovery_batch_with(
            &mut session,
            Vec::new(),
            2,
            true,
            false,
            &mut collect,
            Some(u64::MAX),
        )
        .unwrap();
    assert!(drain_skip(&engine).is_empty());
}

#[test]
fn owned_session_prearms_while_exclusively_borrowing_the_unreleased_child() {
    let source = include_str!("engine.rs");
    let owned_entry = source
        .split_once("    pub(crate) fn start_owned_session(")
        .unwrap()
        .1
        .split_once("    pub(crate) fn revalidate_owned_session_with(")
        .unwrap()
        .0;
    assert!(owned_entry.contains("child: &mut OwnedChild"));
    let route = source
        .split_once("    fn start_session_with(")
        .unwrap()
        .1
        .split_once("\n    }\n}")
        .unwrap()
        .0;
    assert!(route.contains("arm_owned_loader_before_release("));
    assert!(!route.contains("child.release()"));
    assert!(source.contains("child.revalidate_after_exec()"));
    let prearm = route.find("self.arm_owned_loader_before_release(").unwrap();
    let exports = route.find("self.attach_initial_exports(").unwrap();
    let coverage = route.find("self.mark_owned_selection_pending(").unwrap();
    let ready = route.rfind("Ok(session)").unwrap();
    assert!(prearm < exports && exports < coverage && coverage < ready);
    assert!(route.contains("if owned_prearmed && let Some(generation)"));

    let run = include_str!("../run.rs");
    let owned_run = run
        .split_once("fn run_owned_inner(")
        .unwrap()
        .1
        .split_once("\nfn no_modules_hint(")
        .unwrap()
        .0;
    assert!(
        owned_run.find(".start_owned_session(").unwrap()
            < owned_run.find(".release_until(").unwrap()
    );
    assert!(!owned_entry.contains("child.release_until("));
    let finish = run
        .split_once("    fn finish(\n")
        .unwrap()
        .1
        .split_once("\n    }\n}")
        .unwrap()
        .0;
    assert!(
        finish.find("finish_owned_selection_coverage(").unwrap()
            < finish.find("self.coordinator.cleanup(").unwrap()
    );
}

#[test]
fn initial_provider_exports_are_attached_before_session_readiness() {
    let source = include_str!("engine.rs");
    let route = source
        .split_once("    fn start_session_with(")
        .unwrap()
        .1
        .split_once("\n    }\n}")
        .unwrap()
        .0;
    let external_loader = route.find("self.arm_loader_or_partial(").unwrap();
    let exports = route.find("self.attach_initial_exports(").unwrap();
    let drain = route
        .find("let cleanup = self.process_discovery_records(")
        .unwrap();
    let ready = route.rfind("Ok(session)").unwrap();

    assert!(external_loader < exports);
    assert!(exports < drain);
    assert!(drain < ready);
}

fn prepared_loader_registry() -> (LoaderRegistry, LoaderContextId) {
    use p11scope_manifest::elf::SymbolFact;

    let mut registry = LoaderRegistry::default();
    let prepared = registry
        .preflight(LoaderContextSpec {
            view: ProcessViewId(3),
            loader: PinnedObjectId(9),
            mapping: None,
            hook: SymbolFact {
                virtual_address: 0x2100,
                file_offset: 0x2100,
            },
            state_address: None,
        })
        .unwrap();
    let context = registry.prepare(prepared).unwrap();
    (registry, context)
}

#[test]
fn prearm_mark_attached_failure_retires_and_drains_before_reporting() {
    let (mut registry, context) = prepared_loader_registry();
    let order = std::cell::RefCell::new(vec!["detach"]);
    let mut errors = vec!["loader registry mark-attached failed".to_string()];

    let drained =
        begin_owned_prearm_retirement_with(&mut registry, context, false, &mut errors, || {
            order.borrow_mut().push("drain");
            Ok("accounted")
        });

    assert_eq!(*order.borrow(), ["detach", "drain"]);
    assert_eq!(drained, Some("accounted"));
    assert!(registry.is_tombstoned(context));
    assert!(errors.iter().any(|error| error.contains("mark-attached")));
}

#[test]
fn prearm_detach_failure_still_drains_and_remains_lifecycle_fatal() {
    let (mut registry, context) = prepared_loader_registry();
    registry.mark_attached(context).unwrap();
    let mut errors = vec!["dynamic loader detach failed".to_string()];

    let drained =
        begin_owned_prearm_retirement_with(&mut registry, context, true, &mut errors, || {
            Ok("accounted")
        });

    assert_eq!(drained, Some("accounted"));
    assert!(registry.is_tombstoned(context));
    assert!(errors.iter().any(|error| error.contains("detach failed")));
}

#[test]
fn typed_prearm_attach_unavailability_is_the_only_fallback() {
    use crate::attach::DynamicLoaderAttachFailure;

    assert!(matches!(
        classify_owned_prearm_attach(GenerationMutation::Committed(Err(
            DynamicLoaderAttachFailure::KernelUnavailable(anyhow!(
                "kernel loader attach unavailable"
            ))
        ))),
        OwnedPrearmAttachDisposition::Unavailable { .. }
    ));
    for failure in [
        DynamicLoaderAttachFailure::Provenance(anyhow!("pinned identity changed")),
        DynamicLoaderAttachFailure::Registry(anyhow!("attach path unavailable")),
        DynamicLoaderAttachFailure::ProgramMissing,
        DynamicLoaderAttachFailure::ProgramType(anyhow!("wrong Aya program type")),
        DynamicLoaderAttachFailure::InvalidPid,
    ] {
        assert!(matches!(
            classify_owned_prearm_attach(GenerationMutation::Committed(Err(failure))),
            OwnedPrearmAttachDisposition::Lifecycle {
                producer_exists: false,
                ..
            }
        ));
    }
    assert!(matches!(
        classify_owned_prearm_attach(GenerationMutation::PrecheckFailed),
        OwnedPrearmAttachDisposition::Lifecycle {
            producer_exists: false,
            ..
        }
    ));
    assert!(matches!(
        classify_owned_prearm_attach(GenerationMutation::PostcheckFailed(Ok(true))),
        OwnedPrearmAttachDisposition::Lifecycle {
            producer_exists: true,
            ..
        }
    ));
}

fn engine_with_overlay(minor: u64) -> (Engine, ScannedModule, PinnedObjectId, PinnedTimingKey) {
    let module = overlay_module(overlay_key(minor));
    let mut pins = overlay_pins(&[(module.key, OVERLAY_SHA, 1)]);
    let object = pins
        .id_for_scanned(&module, module.key, &module.path)
        .unwrap();
    let timing = pins.owned_timing_key(object).unwrap();
    let (modules, skipped) = bind_scanned_modules(std::slice::from_ref(&module), &mut pins);
    assert!(skipped.is_empty(), "{skipped:?}");
    let mut engine = Engine::empty();
    engine.plan = plan::build_from_reconciled_modules(&modules);
    engine.pinned = pins;
    engine.modules = modules;
    (engine, module, object, timing)
}

#[test]
fn capture_facts_reuses_only_the_same_exact_module_id() {
    let first = timing_key(0);
    let second = timing_key(1);
    let mut facts = CaptureFacts::default();

    assert_eq!(facts.resolve_module_id(&first).unwrap(), plan::ModuleId(0));
    assert_eq!(facts.resolve_module_id(&first).unwrap(), plan::ModuleId(0));
    assert_eq!(facts.resolve_module_id(&second).unwrap(), plan::ModuleId(1));
    assert_eq!(facts.module_key(plan::ModuleId(0)), Some(&first));
    assert_eq!(facts.module_key(plan::ModuleId(1)), Some(&second));
}

#[test]
fn capture_facts_bind_candidate_plan_ids_before_extension() {
    let (first, _, _, first_key) = engine_with_overlay(20);
    let mut facts = CaptureFacts::default();
    let mut initial = first.plan.clone();
    facts
        .bind_plan_module_ids(&mut initial, &first.modules, &[], &first.pinned)
        .unwrap();
    let stable = initial.modules[0].id;
    assert_eq!(stable, plan::ModuleId(0));
    assert_eq!(initial.slots[0].module_ids, [stable]);

    let mut reload = first.plan.clone();
    facts
        .bind_plan_module_ids(&mut reload, &first.modules, &[], &first.pinned)
        .unwrap();
    assert_eq!(reload.modules[0].id, stable);
    assert_eq!(facts.module_key(stable), Some(&first_key));

    let (different, _, _, different_key) = engine_with_overlay(21);
    let mut different_plan = different.plan.clone();
    facts
        .bind_plan_module_ids(
            &mut different_plan,
            &different.modules,
            &[],
            &different.pinned,
        )
        .unwrap();
    assert_eq!(different_plan.modules[0].id, plan::ModuleId(1));
    assert_eq!(different_plan.slots[0].module_ids, [plan::ModuleId(1)]);
    assert_eq!(facts.module_key(plan::ModuleId(1)), Some(&different_key));
}

/// Task 9.2b defect F. A capture-stable module ID is not the plan-local
/// one: any provider discovered ahead of this one takes the lower ID — a
/// capacity-*refused* provider included, since it is still a discovered
/// module with an exact identity. Binding renames the plan's modules and
/// its slots' owners; the aggregate cells name the same modules and must be
/// renamed with them. Leaving them on the pre-bind ID makes the next
/// extension read one provider under two IDs as two rivals and latch
/// `module_ambiguous` on every one of its cells — lane 03's 68 ambiguous
/// slots with no competing co-owner anywhere.
#[test]
fn rebinding_a_provider_to_its_stable_id_is_not_a_second_rival_owner() {
    let (engine, _, _, _) = engine_with_overlay(50);
    let mut facts = CaptureFacts::default();
    // Another provider this capture discovered first holds ModuleId(0).
    facts.resolve_module_id(&timing_key(0)).unwrap();

    let mut committed = engine.plan.clone();
    assert_eq!(committed.modules[0].id, plan::ModuleId(0));
    facts
        .bind_plan_module_ids(&mut committed, &engine.modules, &[], &engine.pinned)
        .unwrap();
    assert_eq!(committed.modules[0].id, plan::ModuleId(1));

    let mut rebuilt = engine.plan.clone();
    facts
        .bind_plan_module_ids(&mut rebuilt, &engine.modules, &[], &engine.pinned)
        .unwrap();
    committed
        .extend_exact_with_stable_module_ids(rebuilt)
        .unwrap();

    assert_eq!(
        committed.module_ambiguous, 0,
        "one provider under one stable ID is one owner, not two rivals"
    );
}

#[test]
fn live_candidate_reuses_an_exact_provider_id_after_an_empty_interval() {
    let (mut engine, first_raw, _, _) = engine_with_overlay(30);
    engine
        .capture_facts
        .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
        .unwrap();
    let first_pins = engine.pinned.clone();

    let empty = engine
        .live_candidate(PinnedObjects::empty(), Vec::new(), Vec::new())
        .unwrap();
    engine.plan = empty.plan;
    engine.pinned = empty.pinned;
    engine.modules = empty.modules;

    let reload = engine
        .live_candidate(first_pins, vec![first_raw], Vec::new())
        .unwrap();
    assert_eq!(reload.plan.modules[0].id, plan::ModuleId(0));

    let (different, different_raw, _, _) = engine_with_overlay(31);
    let new_identity = engine
        .live_candidate(different.pinned, vec![different_raw], Vec::new())
        .unwrap();
    assert_eq!(new_identity.plan.modules[0].id, plan::ModuleId(1));
}

#[test]
fn accepted_capture_facts_survive_empty_and_deduplicate_exact_reload() {
    let (mut engine, _, _, _) = engine_with_overlay(40);
    engine
        .capture_facts
        .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
        .unwrap();
    let first_plan = engine.plan.clone();
    let first_pins = engine.pinned.clone();
    let first_modules = engine.modules.clone();

    engine.publish_current_capture_facts().unwrap();
    assert_eq!(engine.plan.entries_seen, 1);
    assert_eq!(engine.plan.surfaces.len(), 1);
    assert_eq!(engine.discovery.modules.len(), 1);

    let empty = engine
        .live_candidate(PinnedObjects::empty(), Vec::new(), Vec::new())
        .unwrap();
    engine.plan = empty.plan;
    engine.pinned = empty.pinned;
    engine.modules = empty.modules;
    engine.publish_current_capture_facts().unwrap();
    assert_eq!(engine.plan.entries_seen, 1);
    assert_eq!(engine.plan.surfaces.len(), 1);
    assert_eq!(engine.discovery.modules.len(), 1);

    engine.plan = first_plan;
    engine.pinned = first_pins;
    engine.modules = first_modules;
    engine.publish_current_capture_facts().unwrap();
    assert_eq!(engine.plan.entries_seen, 1, "exact reload is not recounted");
    assert_eq!(engine.plan.surfaces.len(), 1, "surface is not duplicated");
    assert_eq!(engine.discovery.modules.len(), 1);

    let (different, _, _, _) = engine_with_overlay(41);
    engine.plan = different.plan;
    engine.pinned = different.pinned;
    engine.modules = different.modules;
    engine
        .capture_facts
        .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
        .unwrap();
    engine.publish_current_capture_facts().unwrap();
    assert_eq!(engine.plan.entries_seen, 2);
    assert_eq!(engine.plan.surfaces.len(), 2);
    assert_eq!(engine.discovery.modules.len(), 2);
}

#[test]
fn accepted_capture_facts_publish_scanned_interface_surfaces() {
    let (mut engine, _, _, _) = engine_with_overlay(45);
    engine.modules[0].scanned.interfaces.push(ScannedInterface {
        index: 0,
        name_class: "exact_standard",
        name_lossy: None,
        name_private: None,
        flags: 0,
        table: Some(0),
    });
    engine.plan = plan::build_from_reconciled_modules(&engine.modules);
    engine
        .capture_facts
        .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
        .unwrap();

    engine.publish_current_capture_facts().unwrap();

    assert_eq!(engine.plan.surfaces.len(), 2);
    assert_eq!(
        engine.plan.surfaces[1].source,
        "interface[0] exact_standard"
    );

    engine.publish_current_capture_facts().unwrap();
    assert_eq!(engine.plan.surfaces.len(), 2, "surface is not duplicated");
}

#[test]
fn accepted_capture_facts_retain_a_changed_table_at_the_same_position() {
    let (mut engine, _, _, _) = engine_with_overlay(42);
    engine
        .capture_facts
        .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
        .unwrap();
    engine.publish_current_capture_facts().unwrap();

    engine.modules[0].scanned.tables[0].version = (3, 0);
    engine.plan.modules[0].tables[0].version = (3, 0);
    engine.publish_current_capture_facts().unwrap();

    assert_eq!(
        engine.discovery.modules[0]
            .tables
            .iter()
            .map(|table| table.version)
            .collect::<Vec<_>>(),
        [(2, 40), (3, 0)]
    );

    engine.publish_current_capture_facts().unwrap();
    assert_eq!(engine.discovery.modules[0].tables.len(), 2);
}

#[test]
fn later_same_path_table_retires_pre_attachment_scan_losses() {
    let (mut engine, _, _, _) = engine_with_overlay(43);
    engine
        .capture_facts
        .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
        .unwrap();
    let attached_plan = engine.plan.clone();
    let attached_pinned = engine.pinned.clone();
    let attached_modules = engine.modules.clone();
    let path = attached_modules[0].scanned.path.clone();
    let not_mapped = Skipped {
        subject: path.clone(),
        reason: "not mapped in the target".into(),
    };
    let empty_scan = Skipped {
        subject: path,
        reason: "no function table was found in its file-backed data".into(),
    };
    let same_path_other = Skipped {
        subject: attached_modules[0].scanned.path.clone(),
        reason: "provider identity changed".into(),
    };
    let initial_set_timing = Skipped {
        subject: "owned initial-set discovery".into(),
        reason: "the empty timing catalog leaves initial-set capture unproven".into(),
    };
    let unmatched = Skipped {
        subject: "/opt/other-p11.so".into(),
        reason: "not mapped in the target".into(),
    };
    engine.counters.object_skips = vec![
        not_mapped.clone(),
        empty_scan.clone(),
        same_path_other.clone(),
        initial_set_timing.clone(),
        unmatched.clone(),
    ];
    engine.plan = plan::build_from_reconciled_modules(&[]);
    engine.pinned = PinnedObjects::empty();
    engine.modules.clear();
    engine.publish_current_capture_facts().unwrap();

    engine.plan = attached_plan;
    engine.pinned = attached_pinned;
    engine.modules = attached_modules;
    engine.publish_current_capture_facts().unwrap();

    assert_eq!(
        engine.plan.skipped,
        vec![
            unmatched.clone(),
            same_path_other.clone(),
            initial_set_timing.clone()
        ],
        "only non-scan-gap losses remain"
    );
    assert!(!engine.plan.skipped.contains(&not_mapped));
    assert!(!engine.plan.skipped.contains(&empty_scan));

    engine.plan = plan::build_from_reconciled_modules(&[]);
    engine.pinned = PinnedObjects::empty();
    engine.modules.clear();
    engine.publish_current_capture_facts().unwrap();
    assert_eq!(
        engine.plan.skipped,
        vec![unmatched, same_path_other, initial_set_timing],
        "a later empty publication does not resurrect retired scan gaps"
    );
    let rendered = engine
        .plan
        .skipped
        .iter()
        .map(render::capture_skipped_out)
        .collect::<Vec<_>>();
    assert_eq!(rendered.len(), 3);
    assert!(rendered.iter().all(|skip| {
        skip.name == "discovery subject" && skip.reason == "discovery unavailable"
    }));
}

#[test]
fn capture_fact_stage_publishes_once_or_rolls_back_whole() {
    let (mut engine, _, _, _) = engine_with_overlay(50);
    engine
        .capture_facts
        .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
        .unwrap();
    engine.publish_current_capture_facts().unwrap();
    assert_eq!(engine.discovery.modules.len(), 1);

    let (different, _, _, _) = engine_with_overlay(51);
    engine.capture_facts.begin_stage().unwrap();
    engine.plan = different.plan.clone();
    engine.pinned = different.pinned.clone();
    engine.modules = different.modules.clone();
    engine
        .capture_facts
        .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
        .unwrap();
    engine.publish_current_capture_facts().unwrap();
    assert_eq!(
        engine.discovery.modules.len(),
        1,
        "the stage is not published before successful return"
    );
    engine.capture_facts.rollback_stage();
    engine.capture_facts.apply_to_plan(&mut engine.plan);
    engine.discovery = engine.capture_facts.discovery(&engine.plan);
    assert_eq!(
        engine.discovery.modules.len(),
        1,
        "late failure publishes nothing"
    );
    assert_eq!(engine.plan.entries_seen, 1);

    engine.capture_facts.begin_stage().unwrap();
    engine.publish_current_capture_facts().unwrap();
    engine.capture_facts.commit_stage().unwrap();
    engine.project_capture_facts();
    assert_eq!(engine.discovery.modules.len(), 2);
    assert_eq!(engine.plan.entries_seen, 2);
}

/// `table_entries` counts an exact target occurrence once however many
/// sources decoded it (`docs/schema/observed-profile-v2.md`: "A `--manifest`
/// overlapping a scanned module does not add a second count for the same
/// exact target occurrence; distinct claims and true repeated occurrences
/// remain separate"). The planner already merges that way; publication must
/// not undo it by counting the scan's target and the manifest's function as
/// two entries.
#[test]
fn capture_facts_count_a_corroborated_entry_once_across_both_surfaces() {
    let (view, modules, pins, input) = same_object_scan_and_manifest(0x40);
    let mut engine = discovered_from_inputs(vec![view], modules, pins, vec![input]);
    assert_eq!(engine.plan.entries_seen, 1, "the planner counts it once");
    assert_eq!(engine.plan.surfaces.len(), 2, "one scan and one manifest");

    engine.publish_current_capture_facts().unwrap();

    assert_eq!(
        engine.plan.entries_seen, 1,
        "the corroborating manifest must not add a second count"
    );
    assert_eq!(
        engine.plan.surfaces.len(),
        2,
        "each source keeps its own surface record"
    );

    // The other direction: a manifest claim the scan did not decode is a
    // distinct entry, not a duplicate of the one it did.
    let (view, modules, pins, input) = same_object_scan_and_manifest(0x80);
    let mut engine = discovered_from_inputs(vec![view], modules, pins, vec![input]);
    assert_eq!(engine.plan.entries_seen, 2);
    engine.publish_current_capture_facts().unwrap();
    assert_eq!(
        engine.plan.entries_seen, 2,
        "a distinct claim stays a distinct entry"
    );
}

/// The attach-time reconciliation is the only thing that ever derives a
/// §4.12 outcome, and on a target held on a barrier it runs before the
/// provider is mapped: it sees no scan, records `uncorroborated`, and the
/// live path never revisits it. Rewinds the recorded counters to exactly
/// that blind state and leaves the scan facts the capture ended up with.
fn blinded_attach_time_corroboration(engine: &mut Engine) {
    engine.counters.conflicts = 0;
    engine.counters.uncorroborated = 1;
    engine.counters.corroboration = vec![(
        engine.plan.modules.iter().map(|m| m.object).collect(),
        "uncorroborated",
    )];
    for module in &mut engine.plan.modules {
        module.corroborated = false;
    }
}

/// §4.12 is judged by capture end, not by what the attach-time scan
/// happened to see (design §4.12: corroboration happens "whenever the
/// object is mapped in scope — scan **or a live export record**"; schema:
/// `uncorroborated` means "not mapped in scope, or no scan"). A provider
/// the target only maps after the observer attached is corroborated by the
/// end, and the blind attach-time outcome is stale.
#[test]
fn a_manifest_the_scan_only_reaches_later_is_corroborated_by_capture_end() {
    // Differing targets: the manifest records 0x40, the scan decodes 0x80.
    let (view, modules, pins, input) = same_object_scan_and_manifest(0x80);
    let mut engine = discovered_from_inputs(vec![view], modules, pins, vec![input]);
    blinded_attach_time_corroboration(&mut engine);

    engine.publish_current_capture_facts().unwrap();

    assert_eq!(
        engine.discovery.conflicts, 1,
        "both sources decoded targets in one object and they differ"
    );
    assert_eq!(
        engine.discovery.uncorroborated, 0,
        "nothing is uncorroborated: the scan reached this object by capture end"
    );
    let module = &engine.discovery.modules[0];
    assert!(module.corroborated, "{module:?}");
    assert_eq!(module.corroboration, vec!["conflict"], "{module:?}");
}

/// Same seam, agreeing sources: the re-derivation must report the outcome
/// it actually derives, not "corroborated somehow".
#[test]
fn a_late_scan_that_agrees_is_recorded_as_agreed_not_as_a_conflict() {
    let (view, modules, pins, input) = same_object_scan_and_manifest(0x40);
    let mut engine = discovered_from_inputs(vec![view], modules, pins, vec![input]);
    blinded_attach_time_corroboration(&mut engine);

    engine.publish_current_capture_facts().unwrap();

    assert_eq!(engine.discovery.conflicts, 0);
    assert_eq!(engine.discovery.uncorroborated, 0);
    let module = &engine.discovery.modules[0];
    assert!(module.corroborated, "{module:?}");
    assert_eq!(module.corroboration, vec!["agreed"], "{module:?}");
}

/// Corroboration is a capture-*lifetime* fact, so it survives the ordinary
/// churn of a `--cgroup` capture: `pkcs11-check --isolation file` retires a
/// view per exiting subprocess, and a publication whose pin set no longer
/// holds the scan's decoded tables is less informed, not newer evidence
/// that nothing corroborated the manifest. Observed live before this was
/// held: `corroboration: ["agreed", "uncorroborated"]` beside
/// `corroborated: true` and `discovery_uncorroborated: 1`.
#[test]
fn a_derived_corroboration_survives_a_later_less_informed_publication() {
    let (view, modules, pins, input) = same_object_scan_and_manifest(0x80);
    let mut engine = discovered_from_inputs(vec![view], modules, pins, vec![input]);
    blinded_attach_time_corroboration(&mut engine);
    engine.publish_current_capture_facts().unwrap();
    assert_eq!(engine.discovery.modules[0].corroboration, vec!["conflict"]);

    // The scan's view is gone; the manifest still describes the object.
    engine.modules.clear();
    engine.publish_current_capture_facts().unwrap();

    let module = &engine.discovery.modules[0];
    assert_eq!(module.corroboration, vec!["conflict"], "{module:?}");
    assert!(module.corroborated, "{module:?}");
    assert_eq!(engine.discovery.conflicts, 1);
    assert_eq!(engine.discovery.uncorroborated, 0);
}

/// A corroboration tombstone is a gap of its own, and it must survive every
/// later publication however many *other* modules hold a derived
/// corroboration. Also the only cover for the tombstone-revokes-derived
/// path: a derived corroboration is already inside the blind attach-time
/// count, so revoking it restores that contribution rather than adding a
/// second one.
#[test]
fn a_tombstone_gap_survives_another_modules_derived_corroboration() {
    let (view, modules, pins, input) = same_object_scan_and_manifest(0x80);
    let mut engine = discovered_from_inputs(vec![view], modules, pins, vec![input]);
    blinded_attach_time_corroboration(&mut engine);
    engine.publish_current_capture_facts().unwrap();
    let derived = engine.discovery.modules[0].id;
    assert_eq!(
        engine.discovery.uncorroborated, 0,
        "the blind attach-time outcome is re-derived at capture end"
    );
    assert_eq!(
        engine.discovery.conflicts, 1,
        "the two sources decoded different targets in one object"
    );

    // A second provider, corroborated when the plan was built: it is not in
    // the blind attach-time count, so revoking its proof is a new gap.
    let second = plan::ModuleId(derived.0 + 1);
    let mut attach_corroborated = merged_module(vec!["scan", "manifest"]);
    attach_corroborated.id = second;
    attach_corroborated.corroborated = true;
    attach_corroborated.corroboration = vec!["agreed"];
    engine
        .capture_facts
        .history
        .modules
        .insert(second, attach_corroborated);

    engine
        .capture_facts
        .invalidate_discovery_proofs([second], []);
    engine.publish_current_capture_facts().unwrap();
    assert_eq!(
        engine.discovery.uncorroborated, 1,
        "the revoked proof is a gap the document must report"
    );
    engine.publish_current_capture_facts().unwrap();
    assert_eq!(
        engine.discovery.uncorroborated, 1,
        "a tombstone gap is not absorbed by another module's re-derivation"
    );

    // Revoking the derived module's own proof restores exactly its blind
    // attach-time contribution — it must not be counted twice.
    engine
        .capture_facts
        .invalidate_discovery_proofs([derived], []);
    engine.publish_current_capture_facts().unwrap();
    assert_eq!(
        engine.discovery.uncorroborated, 2,
        "both providers are uncorroborated now, and neither is double-counted"
    );
    // Corroboration is revocable; a disagreement is not. The two sources
    // did decode different targets, and no later retirement unsays it —
    // an attach-derived conflict survives its module's tombstone through
    // the high-water base, and a capture-end-derived one must too.
    assert_eq!(
        engine.discovery.conflicts, 1,
        "a derived conflict is sticky: revoking the proof cannot lower it"
    );
}

/// The other way a derived conflict can be replaced rather than revoked.
/// Only three of the version-matrix provider's thirteen tables live in
/// file-backed data; the other ten are built at run time in `.bss`, so a
/// scan that differs early and agrees once more of the object is decoded
/// is reachable. The later agreement is the better reading of the module,
/// but it does not unsay that the two sources once decoded different
/// targets.
#[test]
fn a_derived_conflict_stays_counted_when_a_later_scan_agrees() {
    let (view, modules, pins, input) = same_object_scan_and_manifest(0x80);
    let mut engine = discovered_from_inputs(vec![view], modules, pins, vec![input]);
    blinded_attach_time_corroboration(&mut engine);
    engine.publish_current_capture_facts().unwrap();
    assert_eq!(engine.discovery.conflicts, 1);
    assert_eq!(engine.discovery.modules[0].corroboration, vec!["conflict"]);

    // The same object, decoded again with the targets now agreeing.
    let (_, agreeing, agreeing_pins, agreeing_input) = same_object_scan_and_manifest(0x40);
    let agreed = discovered_from_inputs(
        vec![ProcessView::open(ProcessViewId(0), std::process::id()).unwrap()],
        agreeing,
        agreeing_pins,
        vec![agreeing_input],
    );
    engine.plan = agreed.plan;
    engine.pinned = agreed.pinned;
    engine.modules = agreed.modules;
    engine.manifests = agreed.manifests;
    engine.manifest_ordinals = agreed.manifest_ordinals;
    blinded_attach_time_corroboration(&mut engine);
    engine
        .capture_facts
        .bind_plan_module_ids(
            &mut engine.plan,
            &engine.modules,
            &engine.manifests,
            &engine.pinned,
        )
        .unwrap();
    engine.publish_current_capture_facts().unwrap();

    assert_eq!(
        engine.discovery.modules[0].corroboration,
        vec!["agreed"],
        "the better-informed reading wins the module's own record"
    );
    assert_eq!(
        engine.discovery.conflicts, 1,
        "a disagreement the capture really observed is never decremented"
    );
    assert_eq!(engine.discovery.uncorroborated, 0);
}

/// The guard the re-derivation turns on: a provider the scan never reached
/// — the only source that ever described it is the manifest — is still
/// uncorroborated at capture end, and must stay that way.
#[test]
fn a_provider_the_scan_never_reached_stays_uncorroborated() {
    let (_, modules, pins, input) = same_object_scan_and_manifest(0x80);
    let object = pins.pinned().next().unwrap();
    let manifest_only = pin_as_manifest_object(object.path);
    let owned = manifest_only.pinned().next().unwrap().id;
    assert_eq!(
        manifest_only.sources(owned),
        ["manifest"],
        "the fixture must have no scan alias"
    );

    let counters = DiscoveryCounters {
        uncorroborated: 1,
        corroboration: vec![([owned].into_iter().collect(), "uncorroborated")],
        ..DiscoveryCounters::default()
    };
    let reconciled = bind_scanned_modules(&modules, &mut pins.clone()).0;
    assert!(
        recorroborate_at_capture_end(
            &manifest_only,
            &reconciled,
            std::slice::from_ref(&input.manifest),
            &counters,
        )
        .is_empty(),
        "nothing is mapped in scope to corroborate against"
    );
}

#[test]
fn capture_facts_keep_each_accepted_manifest_ordinal_once() {
    let (_, pins) = pinned_self();
    let summary = pins.pinned().next().unwrap();
    let path = summary.path.to_string();
    let sha256 = summary.sha256.to_string();
    let input = |name| ManifestInput {
        path: PathBuf::from(name),
        manifest: manifest_naming(&path, Some(sha256.clone())),
        pins: pin_as_manifest_object(&path),
        stale: Vec::new(),
    };
    let mut engine = lifecycle_discovered(Vec::new());
    engine.manifest_inputs = vec![input("first.json"), input("second.json")];
    rebuild_discovered(&mut engine).unwrap();

    engine.publish_current_capture_facts().unwrap();
    assert_eq!(engine.plan.entries_seen, 2);
    assert_eq!(engine.plan.surfaces.len(), 2);

    engine.publish_current_capture_facts().unwrap();
    assert_eq!(engine.plan.entries_seen, 2, "one refresh does not recount");
    assert_eq!(
        engine.plan.surfaces.len(),
        2,
        "one refresh does not duplicate"
    );
}

#[test]
fn capture_fact_proof_tombstones_block_later_positive_refresh() {
    let (mut engine, _, object, _) = engine_with_overlay(52);
    engine
        .capture_facts
        .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
        .unwrap();
    let module = engine.plan.modules[0].id;
    engine.plan.modules[0].corroborated = true;
    engine.counters.corroboration = vec![([object].into_iter().collect(), "agreed")];
    engine.counters.manifest_fallbacks.push(ManifestFallback {
        manifest: 0,
        object: 0,
        reason: ManifestStaleReason::IdentityMismatch,
        replacement: object,
        proof: BoundFallbackProof {
            module: object,
            tables: Vec::new(),
            required_targets: BTreeMap::new(),
        },
    });
    engine.publish_current_capture_facts().unwrap();
    assert!(engine.discovery.modules[0].corroborated);
    assert_eq!(engine.discovery.manifest_object_fallbacks.len(), 1);

    engine
        .capture_facts
        .invalidate_discovery_proofs([module], [(0, 0)]);
    engine.publish_current_capture_facts().unwrap();

    assert!(!engine.discovery.modules[0].corroborated);
    assert_eq!(
        engine.discovery.modules[0].corroboration,
        ["uncorroborated"]
    );
    assert!(engine.discovery.manifest_object_fallbacks.is_empty());
}

#[test]
fn current_discovery_never_reads_an_inactive_slots_retired_pin() {
    let (mut plan, pins) = plan_with_pins(2, 0);
    plan.slots[1].object = PinnedObjectId(u32::MAX);
    plan.deactivate(1);

    let evidence = discovery_evidence(&plan, &pins, &DiscoveryCounters::default());

    assert_eq!(evidence.modules[0].objects.len(), 1);
}

#[test]
fn capture_facts_keep_all_decoded_occurrences_for_a_capacity_refusal() {
    let mut raw = overlay_module(overlay_key(53));
    raw.tables[0].entries = (0..=p11scope_ebpf_common::MAX_SLOTS)
        .map(|index| ScannedEntry {
            name: "C_Sign",
            object: raw.key,
            object_path: raw.path.clone(),
            file_offset: 8 * u64::from(index),
        })
        .collect();
    let mut pins = overlay_pins(&[(raw.key, OVERLAY_SHA, 1)]);
    let (modules, skipped) = bind_scanned_modules(std::slice::from_ref(&raw), &mut pins);
    assert!(skipped.is_empty(), "{skipped:?}");
    let mut engine = Engine::empty();
    engine.plan = plan::build_from_reconciled_modules(&modules);
    engine.pinned = pins;
    engine.modules = modules;
    engine
        .capture_facts
        .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
        .unwrap();

    engine.publish_current_capture_facts().unwrap();

    assert_eq!(
        engine.plan.entries_seen,
        p11scope_ebpf_common::MAX_SLOTS as usize + 1
    );
    assert!(engine.plan.slots.is_empty());
    assert_eq!(engine.plan.modules_skipped.len(), 1);
    assert!(engine.discovery.modules.is_empty());
    assert_eq!(engine.discovery.modules_skipped.len(), 1);

    engine.plan = plan::build_from_reconciled_modules(&[]);
    engine.pinned = PinnedObjects::empty();
    engine.modules.clear();
    engine.publish_current_capture_facts().unwrap();
    assert_eq!(
        engine.plan.entries_seen,
        p11scope_ebpf_common::MAX_SLOTS as usize + 1
    );
    assert_eq!(engine.discovery.modules_skipped.len(), 1);
}

#[test]
fn capture_facts_keep_a_manifest_only_capacity_refusal() {
    let (_, pins) = pinned_self();
    let summary = pins.pinned().next().unwrap();
    let path = summary.path.to_string();
    let mut manifest = manifest_naming(&path, Some(summary.sha256.to_string()));
    let function = manifest.surfaces[0].functions[0].clone();
    manifest.surfaces[0].functions = (0..=p11scope_ebpf_common::MAX_SLOTS)
        .map(|index| {
            let mut function = function.clone();
            function.resolution = Resolution::Resolved {
                object: 0,
                file_offset: 8 * u64::from(index),
            };
            function
        })
        .collect();
    let manifest_pins = pin_as_manifest_object(&path);
    retarget_to_pins(&mut manifest, &[], &PinnedObjects::empty(), &manifest_pins);
    let (mut engine, _, _, _) = engine_with_overlay(55);
    assert!(engine.pinned.absorb(manifest_pins).is_empty());
    engine.manifests = vec![manifest];
    engine.manifest_ordinals = vec![0];
    let mut counters = DiscoveryCounters::default();
    engine.plan = build_current_plan(
        &engine.modules,
        &engine.manifests,
        &engine.pinned,
        &mut counters,
        &BTreeSet::new(),
        0,
        0,
        false,
    )
    .unwrap();
    engine.counters = counters;
    engine
        .capture_facts
        .bind_plan_module_ids(
            &mut engine.plan,
            &engine.modules,
            &engine.manifests,
            &engine.pinned,
        )
        .unwrap();
    assert_eq!(engine.plan.modules_skipped.len(), 1);

    engine.publish_current_capture_facts().unwrap();

    assert_eq!(
        engine.plan.entries_seen,
        p11scope_ebpf_common::MAX_SLOTS as usize + 2
    );
    assert_eq!(engine.plan.slots.len(), 1);
    assert_eq!(engine.plan.modules_skipped.len(), 1);
    assert_eq!(engine.discovery.modules_skipped.len(), 1);
    assert_eq!(engine.discovery.modules.len(), 1);
}

#[test]
fn start_attempt_stages_initial_facts_before_active_cleanup() {
    let (mut engine, _, _, _) = engine_with_overlay(56);
    engine
        .capture_facts
        .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
        .unwrap();
    assert!(engine.capture_facts.history.modules.is_empty());
    let snapshot = engine.begin_start_capture_attempt().unwrap();

    engine.plan = plan::build_from_reconciled_modules(&[]);
    engine.pinned = PinnedObjects::empty();
    engine.modules.clear();
    engine.publish_current_capture_facts().unwrap();
    engine
        .finish_start_capture_attempt(snapshot, Ok(()))
        .unwrap();

    assert_eq!(engine.discovery.modules.len(), 1);
    assert_eq!(engine.plan.entries_seen, 1);
}

#[test]
fn failed_start_restores_prior_aggregate_owner_after_cleanup() {
    let (mut engine, _, _, _) = engine_with_overlay(54);
    engine
        .capture_facts
        .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
        .unwrap();
    engine.publish_current_capture_facts().unwrap();
    let owner = engine.plan.module_of_slot(0);
    let snapshot = engine.begin_start_capture_attempt().unwrap();

    let mut shared = engine.plan.slots[0].clone();
    shared.module_ids.push(plan::ModuleId(99));
    let candidate = plan::AttachPlan::from_slots(vec![shared]);
    assert!(engine.latch_candidate_ambiguity(&candidate));
    assert_eq!(engine.plan.module_of_slot(0), None);
    let cleanup_ran = Cell::new(false);
    cleanup_ran.set(true);

    let result: Result<()> =
        engine.finish_start_capture_attempt(snapshot, Err(anyhow!("late loader failure")));

    assert!(result.is_err());
    assert!(cleanup_ran.get());
    assert_eq!(engine.plan.module_of_slot(0), owner);
    assert_eq!(engine.plan.module_ambiguous, 0);
    assert_eq!(engine.discovery.modules.len(), 1);
}

#[test]
fn interface_truncation_is_recorded_once_for_a_17_entry_invocation() {
    use p11scope_ebpf_common::DISCOVERY_INTERFACES;

    let records: Vec<DiscoveryRecord> = (0..DISCOVERY_INTERFACES)
        .map(|index| {
            let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
            record.kind = DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN;
            record.interface_index = index;
            record.announced_count = u32::from(DISCOVERY_INTERFACES) + 1;
            record
        })
        .collect();

    assert_eq!(
        records
            .iter()
            .filter(|record| interface_list_is_truncated(record))
            .count(),
        1,
        "only index zero owns the finite userspace truncation contribution"
    );
}

#[test]
fn causal_gap_stays_none_after_loss_then_later_record() {
    let module = timing_key(0);
    let mut timings = CausalTimings::default();
    timings.invalidate();
    timings.observe(&module, 20);
    timings.complete(&module, 50);
    assert_eq!(timings.gap_ns(&module), None);

    let mut intact = CausalTimings::default();
    intact.observe(&module, 20);
    intact.observe(&module, 40);
    intact.complete(&module, 50);
    assert_eq!(
        intact.gap_ns(&module),
        Some(30),
        "a later hit cannot replace the first accepted causal timestamp"
    );
}

#[test]
fn causal_timing_does_not_follow_a_reused_candidate_module_id() {
    let first = timing_key(0);
    let second = timing_key(1);
    assert_ne!(first, second);

    let mut timings = CausalTimings::default();
    timings.observe(&first, 10);
    timings.lose(&first);
    timings.observe(&second, 20);
    timings.complete(&second, 30);
    timings.observe(&first, 40);
    timings.complete(&first, 50);

    assert_eq!(timings.gap_ns(&second), Some(10));
    assert_eq!(
        timings.gap_ns(&first),
        None,
        "the refused physical module keeps its loss after reappearance"
    );
}

#[test]
fn live_overlay_peer_keeps_one_stable_slot_without_new_attach_work() {
    let (mut engine, first, original, _) = engine_with_overlay(104);
    let second = overlay_module(overlay_key(102));
    let mut candidate_pins = engine.pinned.clone();
    let skipped = candidate_pins.absorb(overlay_pins(&[(second.key, OVERLAY_SHA, 1)]));

    let candidate = engine
        .live_candidate(candidate_pins, vec![first.clone(), second.clone()], skipped)
        .unwrap();

    assert_eq!(
        candidate
            .pinned
            .id_for_scanned(&first, first.key, &first.path),
        Some(original)
    );
    assert_eq!(
        candidate
            .pinned
            .id_for_scanned(&second, second.key, &second.path),
        Some(original),
        "the later overlay peer must use the already committed canonical ID"
    );
    assert_eq!(candidate.plan.modules.len(), 1);
    assert_eq!(candidate.plan.slots.len(), 1);
    assert!(candidate.delta.new.is_empty());
    assert_eq!(engine.counters.object_skips.len(), 1);
}

#[test]
fn same_key_overlay_uncertainty_keeps_causal_timing_null() {
    let (mut engine, module, _, kept_timing) = engine_with_overlay(102);
    engine.timings.observe(&kept_timing, 10);
    engine.timings.complete(&kept_timing, 20);
    assert_eq!(engine.timings.gap_ns(&kept_timing), Some(10));

    // The peer from another mount table is another overlay instance (another
    // file); the same file would take the same-open-file path with no skip.
    let dir = tempfile::tempdir().unwrap();
    let mut incoming = overlay_view_pin(&module, 999, OVERLAY_SHA, 1, true);
    overlay_reback(&mut incoming, &overlay_backing_file(&dir, "peer.so"));
    let incoming_object = incoming
        .id_for_scanned(&module, module.key, &module.path)
        .unwrap();
    let incoming_timing = incoming.owned_timing_key(incoming_object).unwrap();
    assert_ne!(kept_timing, incoming_timing);
    let mut candidate_pins = engine.pinned.clone();
    let skipped = candidate_pins.absorb(incoming);
    assert_eq!(skipped.len(), 1, "the accepted heuristic stays explicit");

    let candidate = engine
        .live_candidate(candidate_pins, vec![module.clone()], skipped)
        .unwrap();
    let observed = candidate_timing_keys(&candidate, std::slice::from_ref(&module));
    engine.observe_causal_timing(&observed, 30);
    engine.complete_causal_timing(&observed, Some(40));
    engine.timings.observe(&incoming_timing, 35);
    engine.timings.complete(&incoming_timing, 45);

    assert_eq!(engine.timings.gap_ns(&kept_timing), None);
    assert_eq!(engine.timings.gap_ns(&incoming_timing), None);
}

#[test]
fn causal_completion_tracks_the_last_new_required_attachment() {
    let module = timing_key(0);
    let mut timings = CausalTimings::default();
    timings.observe(&module, 10);
    timings.complete(&module, 12);
    timings.observe(&module, 20);
    timings.complete(&module, 25);

    assert_eq!(
        timings.gap_ns(&module),
        Some(15),
        "completion advances after later genuinely new required work"
    );
}

#[test]
fn accepted_causal_observation_is_independent_from_candidate_work() {
    let (raw_modules, mut pinned) = pinned_self();
    let modules = reconcile_for_test(&raw_modules, &mut pinned);
    let mut engine = Engine::empty();
    engine.plan = plan::build_from_reconciled_modules(&modules);
    engine.pinned = pinned;
    engine.modules = modules;
    let candidate = engine
        .live_candidate(engine.pinned.clone(), raw_modules.clone(), Vec::new())
        .unwrap();

    assert!(candidate.delta.new.is_empty());
    assert!(candidate.delta.replace.is_empty());
    let observed = candidate_timing_keys(&candidate, &raw_modules);
    assert_eq!(observed.len(), 1, "the stable duplicate still has an owner");
    engine.observe_causal_timing(&observed, 10);
    assert_eq!(engine.timings.gap_ns(observed.first().unwrap()), None);

    engine.observe_causal_timing(&observed, 30);
    engine.record_apply_timing(&ApplyOutcome {
        static_completions: vec![(observed.clone(), Some(40))],
        ..ApplyOutcome::default()
    });
    assert_eq!(
        engine.timings.gap_ns(observed.first().unwrap()),
        Some(30),
        "later work keeps the earlier accepted observation"
    );
    engine.observe_causal_timing(&observed, 50);
    assert_eq!(engine.timings.gap_ns(observed.first().unwrap()), Some(30));
    engine.invalidate_causal_timing();
    engine.observe_causal_timing(&observed, 60);
    engine.complete_causal_timing(&observed, Some(70));
    assert_eq!(engine.timings.gap_ns(observed.first().unwrap()), None);
}

#[test]
fn each_module_uses_its_own_immediate_attach_completion() {
    let first = timing_key(0);
    let second = timing_key(1);
    let mut engine = Engine::empty();
    engine.timings.observe(&first, 10);
    engine.timings.observe(&second, 10);
    engine.complete_causal_timing(&[first.clone()].into_iter().collect(), Some(20));
    engine.complete_causal_timing(&[second.clone()].into_iter().collect(), Some(35));

    assert_eq!(engine.timings.gap_ns(&first), Some(10));
    assert_eq!(engine.timings.gap_ns(&second), Some(25));
}

#[test]
fn generation_precheck_reports_exact_missing_view_ids() {
    let current = ProcessView::open(ProcessViewId(2), std::process::id()).unwrap();
    let expected: BTreeSet<_> = [ProcessViewId(9)].into_iter().collect();
    let requested: BTreeSet<_> = [current.id(), ProcessViewId(9)].into_iter().collect();

    assert_eq!(
        stale_process_views(&[current], &[], &requested),
        expected,
        "callers need the exact stale identity for terminal cleanup and refresh"
    );
}

#[test]
fn lifecycle_records_bind_once_to_the_admitted_process_view() {
    let view = ProcessView::open(ProcessViewId(12), std::process::id()).unwrap();
    let admitted = view.admitted_ns();
    let pid = view.pid();

    assert_eq!(
        lifecycle_retirement(
            &[view],
            pid,
            admitted.saturating_sub(1),
            DISCOVERY_KIND_LEADER_EXIT,
        ),
        None,
        "a delayed record from before this retained generation cannot retire it"
    );

    let view = ProcessView::open(ProcessViewId(13), std::process::id()).unwrap();
    assert_eq!(
        lifecycle_retirement(&[view], pid, u64::MAX, DISCOVERY_KIND_EXEC),
        Some((ProcessViewId(13), RetirementCause::ExecRefresh))
    );
    let view = ProcessView::open(ProcessViewId(14), std::process::id()).unwrap();
    assert_eq!(
        lifecycle_retirement(&[view], pid, u64::MAX, DISCOVERY_KIND_LEADER_EXIT),
        Some((ProcessViewId(14), RetirementCause::ExpectedRemoval))
    );
}

#[test]
fn leader_exit_assessment_settles_once_and_terminalizes_pending_views() {
    let view = ProcessViewId(22);
    let mut pending = [view].into_iter().collect();
    let mut counted = BTreeSet::new();
    let mut losses = 0;

    assert_eq!(
        settle_leader_exit_view(&mut pending, &mut counted, &mut losses, view, Ok(false),),
        LeaderExitAssessment::LinkLoss
    );
    assert_eq!(losses, 1);
    assert_eq!(
        settle_leader_exit_view(&mut pending, &mut counted, &mut losses, view, Ok(false),),
        LeaderExitAssessment::AlreadySettled
    );
    assert_eq!(losses, 1, "repeated leader records cannot double count");

    let clean = ProcessViewId(23);
    pending.insert(clean);
    assert_eq!(
        settle_leader_exit_view(&mut pending, &mut counted, &mut losses, clean, Ok(true),),
        LeaderExitAssessment::WholeGroupExit
    );
    assert_eq!(losses, 1, "ordinary whole-group exit is not a link loss");

    pending.insert(view);
    assert_eq!(
        settle_leader_exit_view(&mut pending, &mut counted, &mut losses, view, Ok(true),),
        LeaderExitAssessment::WholeGroupExit,
        "a later definitive whole-group exit remains ordinary retirement"
    );
    assert_eq!(losses, 1);

    let unresolved = ProcessViewId(24);
    pending.insert(unresolved);
    assert_eq!(
        settle_leader_exit_view(
            &mut pending,
            &mut counted,
            &mut losses,
            unresolved,
            Err("pidfd poll failed".into()),
        ),
        LeaderExitAssessment::Pending
    );
    assert!(pending.contains(&unresolved));
    finalize_pending_leader_exit_views(&mut pending, &mut counted, &mut losses);
    assert_eq!(
        losses, 2,
        "terminalization promotes unresolved evidence once"
    );
    finalize_pending_leader_exit_views(&mut pending, &mut counted, &mut losses);
    assert_eq!(losses, 2, "terminalization is sticky");
}

#[test]
fn leader_exit_dispatch_is_two_phase_and_uses_the_admitted_view() {
    let view = ProcessView::open(ProcessViewId(26), std::process::id()).unwrap();
    let pid = view.pid();
    let admitted = view.admitted_ns();
    let mut engine = Engine::empty();
    engine.views.push(view);
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_LEADER_EXIT;
    record.pid_tgid = u64::from(pid) << 32;
    record.hook_ts_ns = admitted;
    let mut pending_views = PendingViewRetirements::new();

    assert_eq!(
        engine.dispatch_lifecycle_record(&record, &mut pending_views),
        None
    );
    assert!(pending_views.is_empty(), "dispatch does not retire yet");
    assert!(
        engine
            .pending_leader_exit_views
            .contains(&ProcessViewId(26)),
        "the matched event is assessed at the next settlement point"
    );
    assert_eq!(engine.task_uprobe_link_losses, 0);
    assert_eq!(
        settle_leader_exit_view(
            &mut engine.pending_leader_exit_views,
            &mut engine.counted_leader_exit_views,
            &mut engine.task_uprobe_link_losses,
            ProcessViewId(26),
            engine.views[0].original_exited(),
        ),
        LeaderExitAssessment::LinkLoss
    );
    assert_eq!(engine.task_uprobe_link_losses, 1);
}

#[test]
fn cgroup_ingress_admission_and_delayed_exit_are_generation_bounded() {
    let first = ProcessView::open(ProcessViewId(31), std::process::id()).unwrap();
    let pid = first.pid();
    let admitted = first.admitted_ns();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 1,
        path: PathBuf::from("/sys/fs/cgroup/test"),
        dir: Arc::new(File::open("/dev/null").unwrap()),
    };
    engine.views.push(first);
    engine.seed_initial_cgroup_views();
    assert_eq!(engine.pid_descendant_gaps(), 0);

    let second = ProcessView::open(ProcessViewId(32), pid).unwrap();
    engine.views.push(second);
    engine.record_cgroup_view_admissions([ProcessViewId(32)]);
    assert_eq!(engine.pid_descendant_gaps(), 1);

    // A delayed exit for the first generation arrives after that view was
    // retired; its admission timestamp still authenticates it exactly once.
    engine.views.retain(|view| view.id() != ProcessViewId(31));
    let mut delayed: DiscoveryRecord = unsafe { std::mem::zeroed() };
    delayed.kind = DISCOVERY_KIND_LEADER_EXIT;
    delayed.pid_tgid = u64::from(pid) << 32;
    delayed.hook_ts_ns = admitted;
    let mut pending = PendingViewRetirements::new();
    engine.dispatch_lifecycle_record(&delayed, &mut pending);
    assert_eq!(engine.pid_descendant_gaps(), 1);

    let mut short_lived: DiscoveryRecord = unsafe { std::mem::zeroed() };
    short_lived.kind = DISCOVERY_KIND_LEADER_EXIT;
    short_lived.pid_tgid = u64::from(pid.saturating_add(1)) << 32;
    short_lived.hook_ts_ns = admitted;
    engine.dispatch_lifecycle_record(&short_lived, &mut pending);
    engine.dispatch_lifecycle_record(&short_lived, &mut pending);
    assert_eq!(engine.pid_descendant_gaps(), 2);
}

#[test]
fn cgroup_boundary_unavailability_latches_one_ingress_sentinel() {
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 1,
        path: PathBuf::from("/sys/fs/cgroup/test"),
        dir: Arc::new(File::open("/dev/null").unwrap()),
    };
    let mut session = ScriptedSession::default();
    session.process_creation_tracking_unavailable = Some("creation unavailable");
    engine.record_session_lifecycle_tracking(&session);
    engine.record_session_lifecycle_tracking(&session);
    assert_eq!(engine.pid_descendant_gaps(), 1);
    session.process_creation_tracking_unavailable = None;
    engine.record_session_lifecycle_tracking(&session);
    assert_eq!(engine.pid_descendant_gaps(), 1);
}

#[test]
fn cgroup_same_pid_unseen_generation_after_closed_interval_counts_once() {
    let first = ProcessView::open(ProcessViewId(33), std::process::id()).unwrap();
    let pid = first.pid();
    let admitted = first.admitted_ns();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 1,
        path: PathBuf::from("/sys/fs/cgroup/test"),
        dir: Arc::new(File::open("/dev/null").unwrap()),
    };
    engine.views.push(first);
    engine.seed_initial_cgroup_views();
    let mut exit: DiscoveryRecord = unsafe { std::mem::zeroed() };
    exit.kind = DISCOVERY_KIND_LEADER_EXIT;
    exit.pid_tgid = u64::from(pid) << 32;
    exit.hook_ts_ns = admitted;
    let mut pending = PendingViewRetirements::new();
    engine.dispatch_lifecycle_record(&exit, &mut pending);
    assert_eq!(engine.pid_descendant_gaps(), 0);

    exit.hook_ts_ns = admitted.saturating_add(1);
    engine.dispatch_lifecycle_record(&exit, &mut pending);
    assert_eq!(engine.pid_descendant_gaps(), 1);
    engine.dispatch_lifecycle_record(&exit, &mut pending);
    assert_eq!(engine.pid_descendant_gaps(), 1);
}

/// Mutation caught: applying the leader-exit interval predicate to EXEC
/// suppresses the required refresh of the still-current selected view.
#[test]
fn cgroup_live_sibling_exec_refreshes_after_leader_interval_closed() {
    let view = ProcessView::open(ProcessViewId(34), std::process::id()).unwrap();
    let pid = view.pid();
    let admitted = view.admitted_ns();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 1,
        path: PathBuf::from("/sys/fs/cgroup/test"),
        dir: Arc::new(File::open("/dev/null").unwrap()),
    };
    engine.views.push(view);
    engine.seed_initial_cgroup_views();
    engine.close_cgroup_admission(ProcessViewId(34), admitted);
    let mut exec: DiscoveryRecord = unsafe { std::mem::zeroed() };
    exec.kind = DISCOVERY_KIND_EXEC;
    exec.pid_tgid = u64::from(pid) << 32;
    exec.hook_ts_ns = admitted.saturating_add(1);
    let mut pending = PendingViewRetirements::new();

    engine.dispatch_lifecycle_record(&exec, &mut pending);

    assert_eq!(
        pending.get(&ProcessViewId(34)),
        Some(&RetirementCause::ExecRefresh)
    );
}

/// Mutation caught: reopening only after inventory lets the next record in
/// one outer batch misclassify the exact live generation as unseen.
#[test]
fn cgroup_exec_reopens_before_same_batch_leader_exit() {
    let pid = std::process::id();
    let view = ProcessView::open(ProcessViewId(38), pid).unwrap();
    let admitted = view.admitted_ns();
    let (mut engine, _dir) = engine_over_cgroup_naming(&[pid]);
    engine.views.push(view);
    engine.seed_initial_cgroup_views();
    engine.close_cgroup_admission(ProcessViewId(38), admitted);
    let mut exec: DiscoveryRecord = unsafe { std::mem::zeroed() };
    exec.kind = DISCOVERY_KIND_EXEC;
    exec.pid_tgid = u64::from(pid) << 32;
    exec.hook_ts_ns = admitted.saturating_add(1);
    let mut session = ScriptedSession::default();

    let mut exit = exec;
    exit.kind = DISCOVERY_KIND_LEADER_EXIT;
    exit.hook_ts_ns = admitted.saturating_add(2);
    apply_ordinary_batch(&mut engine, &mut session, vec![exec, exit])
        .expect("same-batch exec and exit remain processable");

    assert_eq!(
        engine.admitted_cgroup_views[&ProcessViewId(38)].closed_ns,
        Some(admitted.saturating_add(2))
    );
    assert_eq!(engine.pid_descendant_gaps(), 0);
    assert!(
        engine
            .pending_leader_exit_views
            .contains(&ProcessViewId(38))
    );
}

/// Mutation caught: accepting an EXEC from a retained but stale process pin
/// binds a later same-PID generation to historical admission evidence.
#[test]
fn a_view_retired_after_its_group_exited_is_not_a_link_loss() {
    // A leader-exit assessment is answered from the view's own pidfd.
    // Retiring the view without settling leaves it pending forever, and
    // capture end counts every still-pending assessment as a lost uprobe
    // link -- so an ordinary target exit was published as a capture gap
    // that never happened.
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let view = ProcessView::open(ProcessViewId(40), child.id()).unwrap();
    let mut engine = Engine::empty();
    engine.views.push(view);
    engine.queue_leader_exit_assessment(ProcessViewId(40));
    child.kill().unwrap();
    child.wait().unwrap();

    engine.settle_leader_exits_at_removal([ProcessViewId(40)]);

    assert!(
        engine.pending_leader_exit_views.is_empty(),
        "retirement must settle the assessment while the pidfd can still answer it"
    );
    assert_eq!(
        engine.task_uprobe_link_losses, 0,
        "a whole-group exit is the ordinary end of a capture, not a lost link"
    );

    // The fail-closed path is untouched: an assessment that never became
    // answerable is still counted at capture end.
    engine.queue_leader_exit_assessment(ProcessViewId(41));
    finalize_pending_leader_exit_views(
        &mut engine.pending_leader_exit_views,
        &mut engine.counted_leader_exit_views,
        &mut engine.task_uprobe_link_losses,
    );
    assert_eq!(engine.task_uprobe_link_losses, 1);
}

#[test]
fn a_view_retired_while_its_group_lives_is_still_a_link_loss() {
    // The other direction, so the fix cannot be "stop counting". The
    // leader exited and the thread group did not: the link that probe
    // held is genuinely gone and the gap is real.
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let view = ProcessView::open(ProcessViewId(42), child.id()).unwrap();
    let mut engine = Engine::empty();
    engine.views.push(view);
    engine.queue_leader_exit_assessment(ProcessViewId(42));

    engine.settle_leader_exits_at_removal([ProcessViewId(42)]);

    assert!(engine.pending_leader_exit_views.is_empty());
    assert_eq!(engine.task_uprobe_link_losses, 1);
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn cgroup_exec_rejects_a_stale_retained_generation() {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let view = ProcessView::open(ProcessViewId(35), child.id()).unwrap();
    let admitted = view.admitted_ns();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 1,
        path: PathBuf::from("/sys/fs/cgroup/test"),
        dir: Arc::new(File::open("/dev/null").unwrap()),
    };
    engine.views.push(view);
    engine.seed_initial_cgroup_views();
    engine.close_cgroup_admission(ProcessViewId(35), admitted);
    child.kill().unwrap();
    child.wait().unwrap();
    let mut exec: DiscoveryRecord = unsafe { std::mem::zeroed() };
    exec.kind = DISCOVERY_KIND_EXEC;
    exec.pid_tgid = u64::from(child.id()) << 32;
    exec.hook_ts_ns = admitted.saturating_add(1);
    let mut pending = PendingViewRetirements::new();

    engine.dispatch_lifecycle_record(&exec, &mut pending);

    assert!(pending.is_empty());
    assert!(!engine.refresh_requested.contains(&child.id()));
    assert!(
        engine.admitted_cgroup_views[&ProcessViewId(35)]
            .closed_ns
            .is_some(),
        "a stale reused generation cannot reopen historical admission"
    );
}

/// Mutation caught: returning early when the removal clock is unavailable
/// retains an unauthenticated open interval and rebuild erases its PARTIAL.
#[test]
fn missing_removal_clock_drops_open_admission_and_latches_one_gap() {
    let view = ProcessView::open(ProcessViewId(36), std::process::id()).unwrap();
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 1,
        path: PathBuf::from("/sys/fs/cgroup/test"),
        dir: Arc::new(File::open("/dev/null").unwrap()),
    };
    engine.views.push(view);
    engine.seed_initial_cgroup_views();
    let removed = [ProcessViewId(36)].into_iter().collect();

    engine.update_cgroup_admissions_at_removal(&removed, None);
    engine.update_cgroup_admissions_at_removal(&removed, None);

    assert!(
        !engine
            .admitted_cgroup_views
            .contains_key(&ProcessViewId(36))
    );
    assert_eq!(engine.pid_descendant_gaps(), 1);
    assert_eq!(
        engine
            .base_counters
            .object_skips
            .iter()
            .filter(|skip| skip.subject == "cgroup admission removal")
            .count(),
        1
    );
    rebuild_discovered(&mut engine).unwrap();
    assert_eq!(
        engine
            .counters
            .object_skips
            .iter()
            .filter(|skip| skip.subject == "cgroup admission removal")
            .count(),
        1
    );
    assert_eq!(
        evidence_verdict(&engine.plan, &engine.pinned, &engine.counters).completeness,
        "PARTIAL"
    );
}

/// Mutation caught: deleting a pre-attach stale view before closing its
/// admission makes delayed exits indistinguishable from post-close exits.
#[test]
fn preattach_stale_removal_closes_admission_before_view_deletion() {
    let view = ProcessView::open(ProcessViewId(37), std::process::id()).unwrap();
    let pid = view.pid();
    let admitted = view.admitted_ns();
    let mut engine = lifecycle_discovered(vec![view]);
    engine.scope = Scope::Cgroup {
        id: 1,
        path: PathBuf::from("/sys/fs/cgroup/test"),
        dir: Arc::new(File::open("/dev/null").unwrap()),
    };
    engine.seed_initial_cgroup_views();

    remove_stale_views(&mut engine, &[ProcessViewId(37)]).unwrap();

    let closed = engine.admitted_cgroup_views[&ProcessViewId(37)]
        .closed_ns
        .unwrap();
    let mut exit: DiscoveryRecord = unsafe { std::mem::zeroed() };
    exit.kind = DISCOVERY_KIND_LEADER_EXIT;
    exit.pid_tgid = u64::from(pid) << 32;
    exit.hook_ts_ns = admitted;
    let mut pending = PendingViewRetirements::new();
    engine.dispatch_lifecycle_record(&exit, &mut pending);
    assert_eq!(engine.pid_descendant_gaps(), 0);

    exit.hook_ts_ns = closed.saturating_add(1);
    engine.dispatch_lifecycle_record(&exit, &mut pending);
    assert_eq!(engine.pid_descendant_gaps(), 1);
}

#[test]
fn outer_batch_coalesces_pre_admission_exit_into_the_admission_gap() {
    let pid = std::process::id();
    let (mut engine, _dir) = engine_over_cgroup_naming(&[pid]);
    let mut exit: DiscoveryRecord = unsafe { std::mem::zeroed() };
    exit.kind = DISCOVERY_KIND_LEADER_EXIT;
    exit.pid_tgid = u64::from(pid) << 32;
    exit.hook_ts_ns = 0;
    let mut session = ScriptedSession::with_records([], 0);

    apply_ordinary_batch(&mut engine, &mut session, vec![exit])
        .expect("accepted admission and deferred exit remain processable");

    assert_eq!(engine.pid_descendant_gaps(), 1);
    assert!(engine.unmatched_leader_exit_events.contains(&(pid, 0)));
}

#[test]
fn outer_batch_counts_deferred_exit_once_when_no_view_is_admitted() {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let pid = child.id();
    child.kill().unwrap();
    child.wait().unwrap();
    let (mut engine, _dir) = engine_over_cgroup_naming(&[pid]);
    let mut exit: DiscoveryRecord = unsafe { std::mem::zeroed() };
    exit.kind = DISCOVERY_KIND_LEADER_EXIT;
    exit.pid_tgid = u64::from(pid) << 32;
    exit.hook_ts_ns = 1;
    let mut session = ScriptedSession::with_records([], 0);

    apply_ordinary_batch(&mut engine, &mut session, vec![exit])
        .expect("a vanished candidate leaves its deferred exit processable");

    assert_eq!(engine.pid_descendant_gaps(), 1);
    assert!(engine.unmatched_leader_exit_events.contains(&(pid, 1)));
}

/// Mutation caught: treating coalescing-ledger overflow as a novel unseen
/// exit adds a second gap after the accepted admission already counted one.
#[test]
fn coalesced_exit_ledger_overflow_marks_partial_without_a_second_gap() {
    let pid = std::process::id();
    let (mut engine, _dir) = engine_over_cgroup_naming(&[pid]);
    engine.unmatched_leader_exit_events = (0..MAX_SCAN_PIDS)
        .map(|index| (index as u32 + 1, index as u64 + 1))
        .collect();
    let mut exit: DiscoveryRecord = unsafe { std::mem::zeroed() };
    exit.kind = DISCOVERY_KIND_LEADER_EXIT;
    exit.pid_tgid = u64::from(pid) << 32;
    exit.hook_ts_ns = 0;
    let mut session = ScriptedSession::default();

    apply_ordinary_batch(&mut engine, &mut session, vec![exit])
        .expect("the accepted admission coalesces despite a full replay ledger");

    assert_eq!(engine.pid_descendant_gaps(), 1);
    assert!(engine.cgroup_ingress_overflow);
    assert_eq!(
        engine
            .counters
            .object_skips
            .iter()
            .filter(|skip| skip.subject == "cgroup ingress tracking")
            .count(),
        1
    );
}

#[test]
fn cgroup_unmatched_exit_overflow_latches_one_lower_bound() {
    let mut engine = Engine::empty();
    engine.scope = Scope::Cgroup {
        id: 1,
        path: PathBuf::from("/sys/fs/cgroup/test"),
        dir: Arc::new(File::open("/dev/null").unwrap()),
    };
    let mut pending = PendingViewRetirements::new();
    for index in 0..=MAX_SCAN_PIDS {
        let mut exit: DiscoveryRecord = unsafe { std::mem::zeroed() };
        exit.kind = DISCOVERY_KIND_LEADER_EXIT;
        exit.pid_tgid = (index as u64 + 1) << 32;
        exit.hook_ts_ns = index as u64 + 1;
        engine.dispatch_lifecycle_record(&exit, &mut pending);
    }
    let after_overflow = engine.pid_descendant_gaps();
    let mut replay: DiscoveryRecord = unsafe { std::mem::zeroed() };
    replay.kind = DISCOVERY_KIND_LEADER_EXIT;
    replay.pid_tgid = (MAX_SCAN_PIDS as u64 + 1) << 32;
    replay.hook_ts_ns = MAX_SCAN_PIDS as u64 + 1;
    engine.dispatch_lifecycle_record(&replay, &mut pending);
    let mut further: DiscoveryRecord = unsafe { std::mem::zeroed() };
    further.kind = DISCOVERY_KIND_LEADER_EXIT;
    further.pid_tgid = (MAX_SCAN_PIDS as u64 + 2) << 32;
    further.hook_ts_ns = MAX_SCAN_PIDS as u64 + 2;
    engine.dispatch_lifecycle_record(&further, &mut pending);
    assert_eq!(after_overflow, MAX_SCAN_PIDS as u64 + 1);
    assert_eq!(engine.pid_descendant_gaps(), after_overflow);
    assert_eq!(
        engine
            .counters
            .object_skips
            .iter()
            .filter(|skip| skip.subject == "cgroup ingress tracking")
            .count(),
        1
    );
}

#[test]
fn system_scope_admits_new_generations_and_counts_unmatched_exits() {
    let first = ProcessView::open(ProcessViewId(41), std::process::id()).unwrap();
    let pid = first.pid();
    let admitted = first.admitted_ns();
    let mut engine = Engine::empty();
    engine.scope = Scope::System;
    engine.views.push(first);
    engine.seed_initial_cgroup_views();
    assert_eq!(engine.pid_descendant_gaps(), 0);

    // A newly admitted generation counts exactly once, as in cgroup scope.
    let second = ProcessView::open(ProcessViewId(42), pid).unwrap();
    engine.views.push(second);
    engine.record_cgroup_view_admissions([ProcessViewId(42)]);
    assert_eq!(engine.pid_descendant_gaps(), 1);

    // An exit that matches no admitted generation counts once however often
    // it is replayed; admission needs no cgroup check in system scope.
    let mut short_lived: DiscoveryRecord = unsafe { std::mem::zeroed() };
    short_lived.kind = DISCOVERY_KIND_LEADER_EXIT;
    short_lived.pid_tgid = u64::from(pid.saturating_add(1)) << 32;
    short_lived.hook_ts_ns = admitted;
    let mut pending = PendingViewRetirements::new();
    engine.dispatch_lifecycle_record(&short_lived, &mut pending);
    engine.dispatch_lifecycle_record(&short_lived, &mut pending);
    assert_eq!(engine.pid_descendant_gaps(), 2);
}

#[test]
fn system_scope_ledger_overflow_latches_partial_with_system_subject() {
    let mut engine = Engine::empty();
    engine.scope = Scope::System;
    let mut pending = PendingViewRetirements::new();
    for index in 0..=MAX_SCAN_PIDS {
        let mut exit: DiscoveryRecord = unsafe { std::mem::zeroed() };
        exit.kind = DISCOVERY_KIND_LEADER_EXIT;
        exit.pid_tgid = (index as u64 + 1) << 32;
        exit.hook_ts_ns = index as u64 + 1;
        engine.dispatch_lifecycle_record(&exit, &mut pending);
    }
    let after_overflow = engine.pid_descendant_gaps();
    let mut further: DiscoveryRecord = unsafe { std::mem::zeroed() };
    further.kind = DISCOVERY_KIND_LEADER_EXIT;
    further.pid_tgid = (MAX_SCAN_PIDS as u64 + 2) << 32;
    further.hook_ts_ns = MAX_SCAN_PIDS as u64 + 2;
    engine.dispatch_lifecycle_record(&further, &mut pending);
    assert_eq!(after_overflow, MAX_SCAN_PIDS as u64 + 1);
    assert_eq!(engine.pid_descendant_gaps(), after_overflow);
    assert!(engine.cgroup_ingress_overflow);
    assert_eq!(
        engine
            .counters
            .object_skips
            .iter()
            .filter(|skip| skip.subject == "system ingress tracking")
            .count(),
        1
    );
}

#[test]
fn leader_exit_loss_closes_only_the_owned_selection_view() {
    let view = ProcessView::open(ProcessViewId(25), std::process::id()).unwrap();
    let mut engine = Engine::empty();
    engine.views.push(view);
    let generation = NonZeroU64::new(1).unwrap();
    engine.selection_bindings.insert(
        1,
        SelectionBindingFact {
            id: 1,
            context: LoaderContextId::from_case_id(1),
            view: ProcessViewId(25),
            object: PinnedObjectId(1),
            file_offset: 0,
            hook_id: 0,
            abi: HookAbi::Interface,
            attached: true,
            retired: false,
            provider: plan::ModuleId(0),
            observed: false,
            coverage: SelectionCoverageState::OwnedOpen(generation),
        },
    );
    engine.pending_leader_exit_views.insert(ProcessViewId(25));
    engine.refresh_requested.insert(std::process::id());
    let mut pending_views = PendingViewRetirements::new();
    let mut additions_allowed = true;
    let mut closure = PauseClosure::new(true);
    let assessments = engine.pending_leader_exit_views.clone();
    engine.settle_leader_exit_assessments(
        &assessments,
        &mut pending_views,
        &mut additions_allowed,
        &mut closure,
    );
    assert_eq!(engine.task_uprobe_link_losses, 1);
    assert!(!additions_allowed);
    assert!(!closure.required_complete());
    assert!(
        pending_views.is_empty(),
        "link loss does not retire the live view"
    );
    assert!(
        engine
            .views
            .iter()
            .any(|candidate| candidate.id() == ProcessViewId(25)),
        "the live ProcessView remains available for later whole-group exit evidence"
    );
    assert_eq!(
        engine.selection_bindings[&1].coverage,
        SelectionCoverageState::OwnedClosed(generation)
    );
    assert!(
        !engine.refresh_requested.contains(&std::process::id()),
        "link loss does not re-arm the same live view"
    );
}

#[test]
fn leader_exit_batch_n_queues_and_batch_n_plus_1_settles() {
    let view = ProcessView::open(ProcessViewId(27), std::process::id()).unwrap();
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_LEADER_EXIT;
    record.pid_tgid = u64::from(view.pid()) << 32;
    record.hook_ts_ns = view.admitted_ns();
    let mut engine = Engine::empty();
    engine.views.push(view);
    let mut session = ScriptedSession::default();

    let first = apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();
    assert!(first.required_complete, "batch N has no settled loss yet");
    assert_eq!(engine.task_uprobe_link_losses, 0);
    assert!(
        engine
            .pending_leader_exit_views
            .contains(&ProcessViewId(27))
    );

    let second = apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();
    assert!(
        !second.required_complete,
        "batch N+1 publishes the link loss"
    );
    assert_eq!(engine.task_uprobe_link_losses, 1);
    assert!(engine.pending_leader_exit_views.is_empty());
    assert!(
        engine
            .views
            .iter()
            .any(|candidate| candidate.id() == ProcessViewId(27))
    );
}

/// HI-1: a refresh set naming a view retired after the set was built
/// (stale loader context) skips that view and discloses PARTIAL
/// instead of panicking the whole capture.
#[test]
fn inventory_scan_skips_views_retired_before_their_refresh() {
    let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let mut engine = lifecycle_discovered(vec![view]);
    let views = BTreeSet::from([ProcessViewId(0), ProcessViewId(7)]);
    let (scans, _, skipped) = engine.scan_inventory_views(&views, "test refresh");
    let scanned: Vec<u32> = scans.iter().map(|(view, _, _)| view.0).collect();
    assert!(
        scanned.iter().all(|id| *id == 0),
        "only the retained view is scanned: {scanned:?}"
    );
    assert!(
        skipped
            .iter()
            .any(|skip| skip.reason.contains("no longer retained")),
        "the retired view is a disclosed skip: {skipped:?}"
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject.contains("process view 7") && skip.reason.contains("no longer retained")
        }),
        "the retired view forces PARTIAL: {:?}",
        engine.counters.object_skips
    );
}

#[test]
fn mixed_refresh_batch_does_not_settle_new_leader_until_next_outer_batch() {
    let view = ProcessView::open(ProcessViewId(30), std::process::id()).unwrap();
    let mut leader: DiscoveryRecord = unsafe { std::mem::zeroed() };
    leader.kind = DISCOVERY_KIND_LEADER_EXIT;
    leader.pid_tgid = u64::from(view.pid()) << 32;
    leader.hook_ts_ns = view.admitted_ns();
    let mut exec = leader;
    exec.kind = DISCOVERY_KIND_EXEC;
    let mut engine = Engine::empty();
    engine.views.push(view);
    let mut session = ScriptedSession::default();

    apply_ordinary_batch(&mut engine, &mut session, vec![leader, exec])
        .expect("mixed refresh batch remains processable");
    assert_eq!(engine.task_uprobe_link_losses, 0);
    assert!(
        engine
            .pending_leader_exit_views
            .contains(&ProcessViewId(30))
    );

    apply_ordinary_batch(&mut engine, &mut session, Vec::new())
        .expect("the next outer batch settles the retained assessment");
    assert_eq!(engine.task_uprobe_link_losses, 1);
    assert!(engine.pending_leader_exit_views.is_empty());
}

#[test]
fn named_pid_link_loss_continues_with_retained_view_and_partial_evidence() {
    let view = ProcessView::open(ProcessViewId(28), std::process::id()).unwrap();
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_LEADER_EXIT;
    record.pid_tgid = u64::from(view.pid()) << 32;
    record.hook_ts_ns = view.admitted_ns();
    let mut engine = Engine::empty();
    engine.scope = Scope::Pid(view.pid());
    engine.views.push(view);
    let mut session = ScriptedSession::default();

    apply_ordinary_batch(&mut engine, &mut session, vec![record])
        .expect("a named PID link loss remains a successful batch");
    let outcome = apply_ordinary_batch(&mut engine, &mut session, Vec::new())
        .expect("confirmed link loss does not produce a named-PID fatal error");

    assert!(!outcome.required_complete);
    assert_eq!(engine.capture_facts().task_uprobe_link_losses(), 1);
    assert!(
        engine
            .views
            .iter()
            .any(|candidate| candidate.id() == ProcessViewId(28))
    );
    assert!(engine.pending_leader_exit_views.is_empty());
}

#[test]
fn retirement_cause_merge_never_downgrades_real_loss() {
    assert_eq!(
        RetirementCause::ExecRefresh.merge(RetirementCause::ExpectedRemoval),
        RetirementCause::ExpectedRemoval
    );
    assert_eq!(
        RetirementCause::ExpectedRemoval.merge(RetirementCause::GenerationLost),
        RetirementCause::GenerationLost
    );
    assert_eq!(
        RetirementCause::GenerationLost.merge(RetirementCause::ExecRefresh),
        RetirementCause::GenerationLost
    );
}

#[test]
fn batch_exit_dominates_exec_before_dead_pin_promotion() {
    let record = |kind, pid, hook_ts_ns| {
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = kind;
        record.pid_tgid = u64::from(pid) << 32;
        record.hook_ts_ns = hook_ts_ns;
        record
    };
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let view = ProcessView::open(ProcessViewId(18), child.id()).unwrap();
    let hook_ts_ns = view.admitted_ns();
    let mut engine = Engine::empty();
    engine.views.push(view);
    child.kill().unwrap();
    child.wait().unwrap();
    let mut pending = PendingViewRetirements::new();

    for record in [
        record(DISCOVERY_KIND_EXEC, child.id(), hook_ts_ns),
        record(DISCOVERY_KIND_LEADER_EXIT, child.id(), hook_ts_ns),
    ] {
        engine.dispatch_lifecycle_record(&record, &mut pending);
    }
    engine.promote_stale_execs(&mut pending);

    assert_eq!(
        pending.get(&ProcessViewId(18)),
        Some(&RetirementCause::ExpectedRemoval)
    );
    assert!(!engine.refresh_requested.contains(&child.id()));
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .all(|skip| skip.subject != "live discovery generation")
    );

    // An exec with no exit *record* still gets its matching exit from the
    // stronger authority: the retained original pin. Task 9.2 defect B —
    // the exit record is still in the ring while the pidfd is already
    // readable, and calling that proven exit a lost generation failed
    // `p11scope run` on every short-lived child.
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let view = ProcessView::open(ProcessViewId(19), child.id()).unwrap();
    let exec = record(DISCOVERY_KIND_EXEC, child.id(), view.admitted_ns());
    let mut engine = Engine::empty();
    engine.views.push(view);
    child.kill().unwrap();
    child.wait().unwrap();
    let mut pending = PendingViewRetirements::new();
    engine.dispatch_lifecycle_record(&exec, &mut pending);
    engine.promote_stale_execs(&mut pending);
    assert_eq!(
        pending.get(&ProcessViewId(19)),
        Some(&RetirementCause::ExpectedRemoval),
        "a pin that proves the original exited names the leader-exit transition"
    );
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .all(|skip| skip.subject != "live discovery generation"),
        "a proven exit is not a loss"
    );

    // Loss that cannot be proven an exit stays loss: the live-loader attach
    // postcheck route on a generation that is still running.
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let view = ProcessView::open(ProcessViewId(20), child.id()).unwrap();
    let mut engine = Engine::empty();
    engine.views.push(view);
    let mut pending = PendingViewRetirements::new();
    engine.queue_stale_views(&[ProcessViewId(20)].into_iter().collect(), &mut pending);
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(
        pending.get(&ProcessViewId(20)),
        Some(&RetirementCause::GenerationLost),
        "a live generation that changed under us is genuine loss"
    );
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .any(|skip| skip.subject == "live discovery generation"),
        "genuine loss stays sticky and PARTIAL"
    );
}

/// Task 9.2 defect B, through the real batch route. A named target that
/// exits while live discovery is working on it is an expected removal —
/// the retained pin proves it — and the capture ends the ordinary way.
/// Only the `LEADER_EXIT` record used to say so, and it is still in the
/// ring when the pidfd is already readable, so `p11scope run` on a
/// short-lived child failed with a false `the named process generation
/// changed during live discovery` and discarded the whole capture.
#[test]
fn a_named_target_that_provably_exited_ends_the_capture_rather_than_failing_it() {
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let view = ProcessView::open(ProcessViewId(0), child.id()).unwrap();
    record.kind = DISCOVERY_KIND_EXEC;
    record.pid_tgid = u64::from(child.id()) << 32;
    record.hook_ts_ns = view.admitted_ns();
    let mut engine = Engine::empty();
    engine.scope = Scope::Pid(child.id());
    engine.views.push(view);
    child.kill().unwrap();
    child.wait().unwrap();

    let mut session = ScriptedSession::default();
    apply_ordinary_batch(&mut engine, &mut session, vec![record])
        .expect("a named target's provable exit is not a live-discovery failure");

    assert!(
        engine.expected_target_exit(),
        "the capture ends the ordinary way: {:?}",
        engine.counters.object_skips
    );
    assert!(engine.views.is_empty());
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .all(|skip| skip.subject != "live discovery generation"),
        "a proven exit is not a lost generation: {:?}",
        engine.counters.object_skips
    );
}

#[test]
fn expected_exit_requires_a_definitive_original_pin_result() {
    assert!(!retirement_ready_with(RetirementCause::ExpectedRemoval, || Ok(false)).unwrap());
    assert!(retirement_ready_with(RetirementCause::ExpectedRemoval, || Ok(true)).unwrap());
    assert!(
        retirement_ready_with(RetirementCause::ExpectedRemoval, || {
            Err("original pidfd poll failed".to_string())
        })
        .is_err(),
        "a transport error is loss, never exit evidence"
    );
    assert!(
        retirement_ready_with(RetirementCause::ExecRefresh, || {
            Err("must not poll".to_string())
        })
        .unwrap()
    );
}

/// Task 9.2 defect A. An ordinary dynamically linked target binds its live
/// loader context through the real arming path, so no capture publishes a
/// `discovery unavailable` skip for a loader that is plainly there. The
/// loader is located by reading only the retained executable's bounded
/// PT_INTERP metadata and matching `/proc/<pid>/maps`; `stat`'s `st_dev` is not
/// that representation: on a btrfs rootfs it is the subvolume's anonymous device,
/// so every comparison failed and every capture on such a host reported unavailable.
#[test]
fn an_ordinary_dynamic_target_binds_its_live_loader_context() {
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let mut child = ChildGuard(
        std::process::Command::new("sh")
            .args(["-c", "printf R; kill -STOP $$"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut ready = [0_u8; 1];
    std::io::Read::read_exact(child.0.stdout.as_mut().unwrap(), &mut ready).unwrap();
    assert_eq!(ready, *b"R");
    let view = ProcessView::open(ProcessViewId(0), child.0.id()).unwrap();
    let mut engine = Engine::empty();
    engine.scope = Scope::Pid(child.0.id());
    engine.views.push(view);

    let mut session = ScriptedSession::default();
    let armed = engine.arm_loader_or_partial(
        0,
        &mut session,
        &mut true,
        &mut PendingViewRetirements::new(),
    );
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    armed.expect("arming an ordinary dynamic target is not a failure");

    let skips = engine.counters.object_skips.clone();
    let aggregate = engine.loader_discovery();
    assert_eq!(
        aggregate.strategies.debug_state_every_hit, 1,
        "the loader context must bind: {skips:?}"
    );
    assert_eq!(aggregate.strategies.unavailable, 0, "{skips:?}");
    assert_eq!(aggregate.dlopen_timing.none, 0, "{skips:?}");
    assert!(
        skips
            .iter()
            .all(|skip| render::capture_skipped_out(skip).reason != "discovery unavailable"),
        "an available loader never publishes a refused discovery skip: {skips:?}"
    );
}

/// Task E1: a view whose `/proc/PID/exe` readlinks ENOENT (the kthread
/// shape — a live generation with no executable) is NotArmable, not
/// partial: silent `Ok(false)`, no mark, no loader record. The zombie
/// child below is that shape without needing a kernel thread; the
/// start-time pin keeps `still_the_same()` true across the kill.
#[test]
fn arming_a_view_without_an_executable_is_not_armable_not_partial() {
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let mut child = ChildGuard(
        std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap(),
    );
    let pid = child.0.id();
    let view =
        crate::process::start_time_pinned_process_view_for_test(ProcessViewId(0), pid).unwrap();
    child.0.kill().unwrap();
    // The unwaited child is now a zombie: its exe link is gone while its
    // start time still matches the retained pin. Never `wait` here — that
    // would reap it and change the fixture.
    let exe = format!("/proc/{pid}/exe");
    let mut spins = 0;
    while std::fs::read_link(&exe).is_ok() {
        std::thread::sleep(std::time::Duration::from_millis(1));
        spins += 1;
        assert!(spins < 10_000, "SIGKILLed child never became a zombie");
    }
    assert_eq!(
        std::fs::read_link(&exe).map_err(|error| error.kind()),
        Err(std::io::ErrorKind::NotFound),
        "the zombie fixture must present exe-ENOENT"
    );
    assert!(
        view.still_the_same(),
        "the zombie keeps its start-time generation"
    );

    let mut engine = Engine::empty();
    engine.views.push(view);
    let mut session = ScriptedSession::default();
    let armed = engine.arm_loader_or_partial(
        0,
        &mut session,
        &mut true,
        &mut PendingViewRetirements::new(),
    );
    assert!(!armed.unwrap(), "a view without an executable never arms");

    assert!(
        engine.counters.object_skips.is_empty(),
        "NotArmable marks nothing: {:?}",
        engine.counters.object_skips
    );
    assert!(
        engine.loader_contexts.is_empty(),
        "NotArmable records no loader context"
    );
    assert!(
        engine
            .loader_registry
            .ids_for_view(ProcessViewId(0))
            .is_empty()
    );
    assert_eq!(engine.loader_discovery().strategies.unavailable, 0);
}

/// True when `/proc/<pid>/maps` text has an executable mapping of exactly
/// `image`. The kernel switches `/proc/<pid>/exe` in `begin_new_exec()`, before
/// `load_elf_binary()` maps the new image, so an exe link alone is not readiness.
fn maps_have_executable_image(maps: &str, image: &std::path::Path) -> bool {
    maps.lines().any(|line| {
        let mut fields = line.splitn(6, ' ');
        let _range = fields.next();
        let executable = fields
            .next()
            .is_some_and(|perms| perms.as_bytes().get(2) == Some(&b'x'));
        let path = fields.nth(3).map(str::trim_start);
        executable && path.is_some_and(|path| std::path::Path::new(path) == image)
    })
}

#[test]
fn exec_readiness_needs_the_new_images_executable_mapping() {
    let image = std::path::Path::new("/usr/bin/busybox");
    // The begin_new_exec() window: the exe link already names the image but
    // none of its segments are mapped yet.
    assert!(!maps_have_executable_image("", image));
    assert!(!maps_have_executable_image(
        "7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0                          [stack]\n",
        image
    ));
    // A read-only first segment is not yet an executable mapping.
    assert!(!maps_have_executable_image(
        "560000000000-560000001000 r--p 00000000 00:23 42                         /usr/bin/busybox\n",
        image
    ));
    // Another file whose path merely ends like the image does not count.
    assert!(!maps_have_executable_image(
        "560000001000-560000002000 r-xp 00001000 00:23 43                         /opt/usr/bin/busybox\n",
        image
    ));
    assert!(maps_have_executable_image(
        "560000000000-560000001000 r--p 00000000 00:23 42                         /usr/bin/busybox\n\
         560000001000-560000090000 r-xp 00001000 00:23 42                         /usr/bin/busybox\n",
        image
    ));
}

/// Task E1: a static executable (no PT_INTERP, so the locator returns
/// `None`) is NotArmable, not partial: silent `Ok(false)`, no mark, no
/// loader record, no `unavailable` growth.
#[test]
fn arming_a_static_executable_is_not_armable_not_partial() {
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    // Canonicalized: the kernel may report the exe link through a
    // merged-/usr alias (e.g. /usr/bin/busybox for /bin/busybox).
    let busybox = std::fs::canonicalize("/bin/busybox").unwrap();
    let mut child = ChildGuard(
        std::process::Command::new(&busybox)
            .args(["sleep", "60"])
            .spawn()
            .unwrap(),
    );
    let pid = child.0.id();
    // Readiness: pre-exec the child is a fork of this dynamic test binary,
    // so only open the view once its exe link is the static busybox image.
    // The kernel switches that link in begin_new_exec(), before the new
    // image's segments are mapped, so also wait for its executable mapping.
    let exe = format!("/proc/{pid}/exe");
    let maps = format!("/proc/{pid}/maps");
    let mut spins = 0;
    let execed = || {
        std::fs::read_link(&exe).is_ok_and(|target| target == busybox)
            && std::fs::read_to_string(&maps)
                .is_ok_and(|maps| maps_have_executable_image(&maps, &busybox))
    };
    while !execed() {
        std::thread::sleep(std::time::Duration::from_millis(1));
        spins += 1;
        assert!(spins < 10_000, "busybox child never execed");
    }
    let view = ProcessView::open(ProcessViewId(0), pid).unwrap();

    let mut engine = Engine::empty();
    engine.views.push(view);
    let mut session = ScriptedSession::default();
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "the static child is alive entering the arm"
    );
    let armed = engine.arm_loader_or_partial(
        0,
        &mut session,
        &mut true,
        &mut PendingViewRetirements::new(),
    );
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "a NotArmable arm leaves the child alive"
    );
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert!(!armed.unwrap(), "a static executable never arms");

    assert!(
        engine.counters.object_skips.is_empty(),
        "NotArmable marks nothing: {:?}",
        engine.counters.object_skips
    );
    assert!(
        engine.loader_contexts.is_empty(),
        "NotArmable records no loader context"
    );
    assert!(
        engine
            .loader_registry
            .ids_for_view(ProcessViewId(0))
            .is_empty()
    );
    let aggregate = engine.loader_discovery();
    assert_eq!(aggregate.strategies.unavailable, 0);
    assert_eq!(aggregate.dlopen_timing.none, 0);
}

/// Task E1 pin: a genuine arm failure on a dynamic executable keeps
/// today's mark text byte-for-byte AND still records (unlike NotArmable).
/// The starved capture budget refuses the very first maps read.
#[test]
fn genuine_arm_failures_still_mark_partial() {
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let mut child = ChildGuard(
        std::process::Command::new("sh")
            .args(["-c", "printf R; kill -STOP $$"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut ready = [0_u8; 1];
    std::io::Read::read_exact(child.0.stdout.as_mut().unwrap(), &mut ready).unwrap();
    assert_eq!(ready, *b"R");
    let pid = child.0.id();
    let view = ProcessView::open(ProcessViewId(0), pid).unwrap();
    let mut engine = Engine::empty();
    engine.views.push(view);
    engine.budget = CaptureWorkBudget::new(ScanLimits {
        per_object_bytes: ScanLimits::default().per_object_bytes,
        total_bytes: 0,
    });

    let mut session = ScriptedSession::default();
    let armed = engine.arm_loader_or_partial(
        0,
        &mut session,
        &mut true,
        &mut PendingViewRetirements::new(),
    );
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert!(!armed.unwrap(), "a refused arm reports no change");

    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == "live loader arming"
                && skip.reason
                    == "capture attempted-I/O ceiling reached; remaining provider bytes were not read"
        }),
        "today's mark text is kept byte-for-byte: {:?}",
        engine.counters.object_skips
    );
    assert_eq!(
        engine.loader_discovery().strategies.unavailable,
        1,
        "a genuine failure still records its context"
    );
}

#[test]
fn loader_budget_refusals_keep_named_causes_and_fail_closed_cleanup() {
    let (fixture, view, _module, _pins) = loaded_seed_provider();
    let pid = fixture.child.id();
    let per_object_bytes = ScanLimits::default().per_object_bytes;
    let mut sizing_budget = CaptureWorkBudget::new(ScanLimits {
        per_object_bytes,
        total_bytes: u64::MAX,
    });
    let locator = Engine::loader_locator(&view, &mut sizing_budget)
        .unwrap()
        .unwrap();
    let loader_subject = locator.authority.loader_path.display().to_string();
    let locator_bytes = sizing_budget.attempted_io_bytes();
    let loader_target_path = PathBuf::from(format!(
        "/proc/{pid}/root{}",
        locator.authority.loader_path.display()
    ));
    let mut mount_budget = CaptureWorkBudget::new(ScanLimits {
        per_object_bytes,
        total_bytes: u64::MAX,
    });
    open_view_object(&view, &loader_target_path, &mut mount_budget).unwrap();
    let hash_start = locator_bytes
        .checked_add(mount_budget.attempted_io_bytes())
        .unwrap();
    let loader_module = mapped_object(
        &view,
        &locator.authority.loader_maps[0],
        &locator.authority.loader_path,
    );
    let (loader_pins, calibration_skips) = pin_scanned_view_objects(
        &view,
        std::slice::from_ref(&loader_module),
        &mut sizing_budget,
    )
    .unwrap();
    assert!(calibration_skips.is_empty(), "{calibration_skips:?}");
    let loader_id = loader_pins
        .id_for_scanned(&loader_module, loader_module.key, &loader_module.path)
        .expect("calibration must pin the exact mapped loader");
    let loader_snapshot = read_elf_snapshot(
        loader_pins
            .file_for(loader_id)
            .expect("the calibration pin retains its loader file"),
        &mut sizing_budget,
    )
    .unwrap();
    let hook = loader_snapshot
        .defined_symbol("_dl_debug_state")
        .unwrap()
        .filter(|hook| loader_snapshot.is_executable_offset(hook.file_offset))
        .expect("the calibration loader must expose its executable hook");
    assert!(unique_mapping_for_offset(&locator.authority.loader_maps, hook.file_offset).is_ok());
    let candidate_bytes = sizing_budget.attempted_io_bytes();
    let revalidated = Engine::loader_locator(&view, &mut sizing_budget)
        .unwrap()
        .unwrap();
    assert_eq!(revalidated.authority, locator.authority);
    assert!(revalidated.maps.contains(&locator.authority.loader_maps[0]));
    let revalidation_bytes = sizing_budget.attempted_io_bytes();
    assert!(
        locator_bytes < candidate_bytes && candidate_bytes < revalidation_bytes,
        "L={locator_bytes} C={candidate_bytes} R={revalidation_bytes}"
    );
    assert!(
        locator_bytes < hash_start && hash_start < candidate_bytes,
        "the calibration must place the hash between L={locator_bytes} and C={candidate_bytes}; H={hash_start}"
    );

    let arm = |total_bytes| {
        let view = ProcessView::open(ProcessViewId(0), pid).unwrap();
        let mut engine = Engine::empty();
        engine.scope = Scope::Pid(pid);
        engine.views.push(view);
        engine.budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes,
            total_bytes,
        });
        let mut session = ScriptedSession::default();
        let mut pending = PendingViewRetirements::new();
        let result = engine.arm_loader_or_partial(0, &mut session, &mut true, &mut pending);
        (engine, pending, session, result)
    };
    let assert_named_io_cause = |engine: &Engine| {
        assert!(
            engine
                .counters
                .object_skips
                .iter()
                .any(|skip| skip.reason.contains(IO_CEILING_REASON)),
            "{:?}",
            engine.counters.object_skips
        );
        assert!(engine.counters.object_skips.iter().all(|skip| {
            !skip.reason.contains("process generation changed")
                && !skip.reason.contains("named process generation changed")
        }));
    };

    let pin_cut = locator_bytes.checked_add(1).unwrap();
    let (pin_engine, pin_pending, pin_session, pin_result) = arm(pin_cut);
    assert!(!pin_result.unwrap());
    assert_eq!(pin_session.dynamic_loader_attach_calls, 0);
    assert_eq!(pin_engine.budget.attempted_io_bytes(), pin_cut);
    assert_eq!(pin_pending.get(&ProcessViewId(0)), None);
    assert!(
        pin_engine
            .loader_registry
            .ids_for_view(ProcessViewId(0))
            .is_empty()
    );
    let exact_pin_reason = format!("cannot read pid {pid}'s mount table: {IO_CEILING_REASON}");
    assert!(
        pin_engine
            .counters
            .object_skips
            .iter()
            .any(|skip| { skip.subject == loader_subject && skip.reason == exact_pin_reason })
    );
    assert_named_io_cause(&pin_engine);

    let snapshot_cut = candidate_bytes.checked_sub(1).unwrap();
    let (snapshot_engine, snapshot_pending, snapshot_session, snapshot_result) = arm(snapshot_cut);
    assert!(!snapshot_result.unwrap());
    assert_eq!(snapshot_session.dynamic_loader_attach_calls, 0);
    assert_eq!(snapshot_engine.budget.attempted_io_bytes(), snapshot_cut);
    assert_eq!(snapshot_pending.get(&ProcessViewId(0)), None);
    assert!(
        snapshot_engine
            .loader_registry
            .ids_for_view(ProcessViewId(0))
            .is_empty()
    );
    assert_named_io_cause(&snapshot_engine);

    let hash_cut = hash_start.checked_add(1).unwrap();
    let (hash_engine, hash_pending, hash_session, hash_result) = arm(hash_cut);
    assert!(!hash_result.unwrap());
    assert_eq!(hash_session.dynamic_loader_attach_calls, 0);
    assert_eq!(hash_engine.budget.attempted_io_bytes(), hash_cut);
    assert_eq!(hash_pending.get(&ProcessViewId(0)), None);
    assert!(
        hash_engine
            .loader_registry
            .ids_for_view(ProcessViewId(0))
            .is_empty()
    );
    assert_named_io_cause(&hash_engine);

    let (pre_engine, pre_pending, pre_session, pre_result) = arm(candidate_bytes);
    assert!(!pre_result.unwrap());
    assert_eq!(pre_session.dynamic_loader_attach_calls, 0);
    assert_eq!(pre_engine.budget.attempted_io_bytes(), candidate_bytes);
    assert_named_io_cause(&pre_engine);
    assert_eq!(
        pre_pending.get(&ProcessViewId(0)),
        Some(&RetirementCause::ExecRefresh)
    );
    assert!(
        pre_engine
            .loader_registry
            .ids_for_view(ProcessViewId(0))
            .is_empty()
    );

    // One byte beyond the calibrated precheck admits one byte of the repeated
    // postcheck snapshot, then refuses it whole after the loader link was added.
    let postcheck_cut = revalidation_bytes.checked_add(1).unwrap();
    let (mut post_engine, mut post_pending, mut post_session, post_result) = arm(postcheck_cut);
    assert!(!post_result.unwrap());
    assert_eq!(post_session.dynamic_loader_attach_calls, 1);
    assert_eq!(post_engine.budget.attempted_io_bytes(), postcheck_cut);
    assert_named_io_cause(&post_engine);
    assert_eq!(
        post_pending.get(&ProcessViewId(0)),
        Some(&RetirementCause::ExecRefresh)
    );
    let contexts = post_engine.loader_registry.ids_for_view(ProcessViewId(0));
    assert_eq!(
        contexts.len(),
        1,
        "L={locator_bytes} C={candidate_bytes} R={revalidation_bytes} attempted={} skips={:?}",
        post_engine.budget.attempted_io_bytes(),
        post_engine.counters.object_skips
    );
    let context = contexts[0];
    assert!(
        post_engine
            .loader_registry
            .context(context)
            .unwrap()
            .was_attached
    );
    let mut additions_allowed = true;
    let mut collect = Engine::collect_discovery_records;
    let mut closure = PauseClosure::new(true);
    let mut no_terminal_selection_handoffs = TerminalSelectionHandoffs::new();
    let (_, complete) = post_engine
        .retire_loader_contexts(
            ProcessViewId(0),
            &mut no_terminal_selection_handoffs,
            &mut post_session,
            &mut additions_allowed,
            &mut post_pending,
            &mut collect,
            &mut closure,
        )
        .unwrap();
    assert!(complete);
    assert_eq!(post_session.detached, [context]);
    assert!(post_session.dynamic_loader_links.is_empty());
    assert!(post_engine.loader_registry.context(context).is_none());
}

#[test]
fn two_gib_dynamic_executable_arms_without_hashing_the_executable() {
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let source_path = std::path::Path::new("/bin/sh");
    let source_file = std::fs::File::open(source_path).unwrap();
    let source_size = source_file.metadata().unwrap().len();
    assert!(
        read_bounded_interpreter(&source_file, source_size)
            .unwrap()
            .0
            .is_some(),
        "the copied source must be a dynamic executable with one PT_INTERP"
    );

    let dir = tempfile::tempdir().unwrap();
    let executable = dir.path().join("large-sh");
    std::fs::copy(source_path, &executable).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&executable)
        .unwrap()
        .set_len(2 * 1024 * 1024 * 1024 + 11 * 1024 * 1024)
        .unwrap();
    assert_eq!(
        std::fs::metadata(&executable).unwrap().len(),
        2 * 1024 * 1024 * 1024 + 11 * 1024 * 1024
    );
    let mut child = ChildGuard(
        std::process::Command::new(&executable)
            .args(["-c", "printf R; kill -STOP $$"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut ready = [0_u8; 1];
    std::io::Read::read_exact(child.0.stdout.as_mut().unwrap(), &mut ready).unwrap();
    assert_eq!(ready, *b"R");
    let pid = child.0.id() as libc::pid_t;
    let mut status = 0;
    // SAFETY: this process is the parent of the exact unreaped child.
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) },
        pid
    );
    assert!(libc::WIFSTOPPED(status));
    assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
    let process_executable = std::fs::metadata(format!("/proc/{}/exe", child.0.id())).unwrap();
    let fixture_executable = std::fs::metadata(&executable).unwrap();
    assert_eq!(
        (process_executable.dev(), process_executable.ino()),
        (fixture_executable.dev(), fixture_executable.ino()),
        "the stopped child must execute the enlarged fixture"
    );
    let view = ProcessView::open(ProcessViewId(0), child.0.id()).unwrap();
    let mut engine = Engine::empty();
    engine.scope = Scope::Pid(child.0.id());
    engine.views.push(view);

    let mut session = ScriptedSession::default();
    let armed = engine.arm_loader_or_partial(
        0,
        &mut session,
        &mut true,
        &mut PendingViewRetirements::new(),
    );
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    armed.expect("a large dynamic executable locates its separately bounded loader");

    let skips = engine.counters.object_skips.clone();
    let aggregate = engine.loader_discovery();
    assert_eq!(aggregate.strategies.debug_state_every_hit, 1, "{skips:?}");
    assert_eq!(aggregate.strategies.unavailable, 0, "{skips:?}");
    assert!(
        skips.iter().all(|skip| !skip.reason.contains("too_large")),
        "the executable itself is never hashed: {skips:?}"
    );
}

/// Task 9.2 defect A, second half, through the real batch route. A loader
/// context that retires cleanly publishes nothing. Its terminal dispatch
/// removes the context it retired, so the view retirement that follows must
/// not report that same context as one it could not remove — a second
/// false `discovery unavailable`, reachable only once a loader actually
/// binds, which is why the broken binding hid it.
#[test]
fn a_cleanly_retired_loader_context_publishes_no_skip() {
    let (mut engine, owner) = Engine::retiring_loader_context(std::process::id());
    let mut session = ScriptedSession::with_records([], 0);
    apply_ordinary_batch(&mut engine, &mut session, Vec::new())
        .expect("an ordinary retirement batch");

    assert!(engine.loader_registry.context(owner).is_none());
    let skips = engine.counters.object_skips.clone();
    assert!(
        skips
            .iter()
            .all(|skip| skip.subject != "live loader retirement"),
        "a context removed exactly once is not a removal failure: {skips:?}"
    );
    assert!(
        skips
            .iter()
            .all(|skip| render::capture_skipped_out(skip).reason != "discovery unavailable"),
        "{skips:?}"
    );
}

/// One retained live view for this process, one *attached* loader context
/// frozen on `mapping`, and an `ExecRefresh` already queued for that view:
/// the state every capture whose target execs passes through between the
/// exec record and the refresh it queues.
fn engine_with_exec_refreshed_loader(
    mapping: MapEntry,
) -> (Engine, LoaderContextId, ProcessViewId) {
    use p11scope_manifest::elf::SymbolFact;

    let pid = std::process::id();
    let view = ProcessView::open(ProcessViewId(0), pid).expect("a live process view");
    let view_id = view.id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Pid(pid);
    engine.views.push(view);
    engine.next_view_id = 1;
    let prepared = engine
        .loader_registry
        .preflight(LoaderContextSpec {
            view: view_id,
            loader: PinnedObjectId(9),
            hook: SymbolFact {
                virtual_address: mapping.file_offset + 0x10,
                file_offset: mapping.file_offset + 0x10,
            },
            mapping: Some(mapping),
            state_address: None,
        })
        .expect("a preflighted loader context");
    let context = engine
        .loader_registry
        .prepare(prepared)
        .expect("a prepared loader context");
    engine
        .loader_registry
        .mark_attached(context)
        .expect("an attached loader context");
    engine
        .retirement_intents
        .insert(view_id, RetirementCause::ExecRefresh);
    (engine, context, view_id)
}

/// A pending retirement intent is not evidence that this dispatched batch
/// contains the matching exec record.
#[test]
fn a_loader_hit_remapped_by_a_preexisting_exec_refresh_is_a_discovery_loss() {
    let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
    let observed = maps
        .iter()
        .find(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
        .expect("this process maps its own executable text")
        .clone();
    // The same object at the load base it had before the exec: identity,
    // file offset and protection unchanged, only the address moved.
    let mut armed = observed.clone();
    armed.start -= 0x1000_0000;
    armed.end -= 0x1000_0000;

    let (mut engine, context, _) = engine_with_exec_refreshed_loader(armed);
    let mut record = loader_record_for(context, std::process::id());
    record.table_ptr = observed.start + 0x10;
    let mut session = ScriptedSession::with_records([], 1);
    apply_ordinary_batch(&mut engine, &mut session, vec![record])
        .expect("an ordinary batch carrying one remapped loader hit");

    let skips = engine.counters.object_skips.clone();
    assert!(
        skips
            .iter()
            .any(|skip| skip.subject == "live loader discovery"),
        "an intent without an actual same-batch exec cannot explain the moved \
             mapping: {skips:?}"
    );
    // ...and "not a loss" has to mean the loss-class counter too. It is the
    // one contributor that publishes no skip, so a nonzero value here is a
    // gap no reader can attribute to anything.
    let [_, _, _, truncated] = engine.capture_facts().discovery_losses();
    assert_eq!(
        truncated, 1,
        "without an actual same-batch exec, the rejected hit remains one loss"
    );
}

/// A loader hit may precede its matching EXEC record in one dispatched
/// batch. The hit remains rejected and fails pause completeness, but the
/// exact same-batch lifecycle match explains its moved mapping.
#[test]
fn a_loader_hit_remapped_by_a_same_batch_exec_is_not_a_discovery_loss() {
    let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
    let observed = maps
        .iter()
        .find(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
        .expect("this process maps its own executable text")
        .clone();
    let mut armed = observed.clone();
    armed.start -= 0x1000_0000;
    armed.end -= 0x1000_0000;

    let (mut engine, context, _) = engine_with_exec_refreshed_loader(armed);
    engine.retirement_intents.clear();
    engine.refresh_requested.clear();
    let mut loader = loader_record_for(context, std::process::id());
    loader.table_ptr = observed.start + 0x10;
    let mut exec: DiscoveryRecord = unsafe { std::mem::zeroed() };
    exec.kind = DISCOVERY_KIND_EXEC;
    exec.pid_tgid = u64::from(std::process::id()) << 32;
    exec.hook_ts_ns = engine.views[0].admitted_ns();
    let mut session = ScriptedSession::with_records([], 1);
    let outcome = apply_ordinary_batch(&mut engine, &mut session, vec![loader, exec])
        .expect("an ordinary batch carrying a remapped hit before its exec");

    assert!(
        !outcome.required_complete,
        "the loader hit remains rejected even when its loss is explained"
    );
    let skips = engine.counters.object_skips.clone();
    assert!(
        skips
            .iter()
            .all(|skip| skip.subject != "live loader discovery"),
        "the exact same-batch exec explains the moved mapping: {skips:?}"
    );
    let [_, _, _, truncated] = engine.capture_facts().discovery_losses();
    assert_eq!(
        truncated, 0,
        "the explained rejection is counted by nothing"
    );
}

/// Task 9.2-fix5 item A. A retained generation that changes under an
/// operation needing it is loss — unless the retained original pin proves
/// the process simply ended. Arming a loader context for one of
/// pkcs11-check's per-file subprocesses loses the generation every time
/// one finishes, and that is the ordinary end of a process, on the same
/// authority `queue_retirement` already uses.
#[test]
fn a_generation_change_a_pin_proves_was_an_exit_is_not_a_loss() {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let mut engine = Engine::empty();
    engine
        .views
        .push(ProcessView::open(ProcessViewId(0), child.id()).unwrap());
    engine.next_view_id = 1;

    engine.mark_generation_change(ProcessViewId(0), "live loader arming", "scripted");
    assert_eq!(
        engine.counters.object_skips.len(),
        1,
        "a live generation that changed under an arm is a real loss"
    );

    child.kill().unwrap();
    child.wait().unwrap();
    engine.counters.object_skips.clear();
    engine.mark_generation_change(ProcessViewId(0), "live loader arming", "scripted");
    assert!(
        engine.counters.object_skips.is_empty(),
        "a generation the retained pin proves ended is not a lost one: {:?}",
        engine.counters.object_skips
    );
}

/// Task 9.2-fix5 item C. The scan owes an empty module an answer, but by
/// capture end the same object can have a full table: SoftHSM2 builds its
/// `CK_FUNCTION_LIST` at run time, and whether one scan pass of a live
/// target sees it is a race. Measured on the healthy lane-16 shape
/// (`run --pause auto -- hammer`): one run in eight published a second
/// record, `function table unavailable in file-backed data`, beside 68
/// table entries, 68 slots and 136/136 probes for that very object — every
/// other counter identical to the seven clean runs.
#[test]
fn an_empty_scan_pass_is_not_a_loss_once_the_capture_attaches_that_table() {
    let mut plan = plan::build_from_reconciled_modules(&[]);
    plan.modules = vec![plan::ModuleSummary {
        id: plan::ModuleId(0),
        object: PinnedObjectId(42),
        key: ObjectKey {
            device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
            inode: 42,
        },
        path: "/opt/p11.so".into(),
        tables: vec![plan::TableSummary {
            version: (2, 40),
            entries: 68,
            source: "scan",
            file_offset: None,
            linkage: "heuristic",
        }],
        interfaces: 0,
        source: "scan",
        corroborated: false,
        skipped: vec![],
    }];
    let empty_scan = |path: &str| Skipped {
        subject: path.into(),
        reason: "no function table was found in its file-backed data; a table built at \
                     run time in .bss or on the heap is outside the memory scan's reach"
            .into(),
    };
    let attached = empty_scan("/opt/p11.so");
    let never_attached = empty_scan("/opt/other.so");

    record_object_skips(&mut plan, &[attached.clone(), never_attached.clone()]);
    assert_eq!(
        plan.skipped,
        vec![never_attached.clone()],
        "a module this capture attached a table in has no empty scan to show; \
             one it never attached still does"
    );

    // …and the plan's skip list is only rebuilt when its sources are, so a
    // record an earlier batch made while the module was still empty has to
    // be re-judged, not just kept out.
    plan.skipped = vec![attached, never_attached.clone()];
    record_object_skips(&mut plan, &[]);
    assert_eq!(plan.skipped, vec![never_attached]);
}

/// A cgroup whose `cgroup.procs` names one process that no longer exists —
/// what every inventory tick of a workload that forks per unit of work
/// sees. `scope_pids` only reads the file, so a plain directory holding one
/// is the whole scope.
fn engine_over_cgroup_naming(pids: &[u32]) -> (Engine, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("a scope directory");
    let listing: String = pids.iter().map(|pid| format!("{pid}\n")).collect();
    std::fs::write(dir.path().join("cgroup.procs"), listing).expect("a cgroup.procs");
    let mut engine = Engine::empty();
    engine.scope = crate::scope::cgroup(dir.path()).expect("open scope directory");
    (engine, dir)
}

fn refresh_inventory_once(engine: &mut Engine) {
    refresh_inventory_with(engine, &mut ScriptedSession::with_records([], 0));
}

fn refresh_inventory_with(engine: &mut Engine, session: &mut ScriptedSession) {
    let mut collect: Box<DiscoveryCollector<'_>> = Box::new(Engine::collect_discovery_records);
    engine
        .refresh_inventory(
            session,
            &mut true,
            &mut Vec::new(),
            &mut PendingViewRetirements::new(),
            &mut *collect,
            &mut PauseClosure::new(true),
        )
        .expect("an inventory refresh over a cgroup scope");
}

/// Task 9.2-fix5 item A. A `--cgroup` capture re-enumerates its members
/// every tick, and a workload that forks one short-lived subprocess per
/// unit of work leaves some of them gone before discovery can open or scan
/// them. That is the ordinary end of a process, on the same authority
/// `queue_retirement` and the fix4 record rule already use — not a
/// discovery loss. Measured on the pkcs11-check `--isolation file` shape:
/// five public `discovery unavailable` records, one per vanished pid.
#[test]
fn a_scope_member_that_ended_before_discovery_reached_it_is_not_a_loss() {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let pid = child.id();
    child.kill().unwrap();
    child.wait().unwrap();

    let (mut engine, _dir) = engine_over_cgroup_naming(&[pid]);
    refresh_inventory_once(&mut engine);

    let skips = engine.counters.object_skips.clone();
    assert!(
        skips.is_empty(),
        "a generation that is provably gone is not a discovery loss: {skips:?}"
    );
}

/// …and when its fate is *not* proven the loss stays loud — but as one
/// record for the whole capture, not one per pid. The pid, the view and the
/// error belong in the diagnostic; carrying them in the deduplicated
/// `(subject, reason)` pair defeated `record_object_skips`'s own stated
/// deduplication and made the published count track the workload's fork
/// rate. Lane 11 published eleven of these on a capture an independent
/// oracle proved complete.
#[test]
fn unreadable_scope_members_stay_loud_as_one_deduplicated_record() {
    let mut noise = crate::discovery::noise::DiscoveryNoiseAggregator::default();
    let published: Vec<_> = [7u32, 9, 4242]
        .into_iter()
        .filter_map(|pid| unreadable_member_skip(pid, false, "scripted, unproven", &mut noise))
        .collect();
    assert_eq!(published.len(), 3, "an unproven fate is never silent");

    let mut engine = Engine::empty();
    for skip in &published {
        engine.mark_partial(&skip.subject, &skip.reason);
    }
    assert_eq!(
        engine.counters.object_skips.len(),
        1,
        "three unreadable members are one loss, not three: {:?}",
        engine.counters.object_skips
    );
    assert_eq!(
        render::capture_skipped_out(&engine.counters.object_skips[0]).reason,
        "discovery unavailable"
    );
    assert!(
        unreadable_member_skip(11, true, "scripted, proven gone", &mut noise).is_none(),
        "a generation that is provably gone is the ordinary end of a process"
    );
}

#[test]
fn scan_pin_diagnostics_escape_target_controls() {
    let message =
        format_discovery_skip("/opt/p\u{1b}[2Jevil\r.so", "scan failed: \u{1b}[31mboom\r");
    assert_eq!(
        message,
        r"p11scope: discovery skipped /opt/p\u{1b}[2Jevil\r.so — scan failed: \u{1b}[31mboom\r"
    );
    assert!(!message.contains('\u{1b}') && !message.contains('\r'));
}

#[test]
fn unreadable_member_diagnostics_escape_target_controls() {
    let message = format_unreadable_member(4242, "detail: \u{1b}[2Jevil\r");
    assert_eq!(
        message,
        r"p11scope: discovery skipped pid 4242: detail: \u{1b}[2Jevil\r"
    );
    assert!(!message.contains('\u{1b}') && !message.contains('\r'));
}

#[test]
fn module_refusal_diagnostics_escape_target_controls() {
    let message = format_module_refusal("/opt/p\u{1b}[2Jevil\r.so", "capacity: \u{1b}[31mboom\r");
    assert_eq!(
        message,
        r"p11scope: module refused: /opt/p\u{1b}[2Jevil\r.so — capacity: \u{1b}[31mboom\r"
    );
    assert!(!message.contains('\u{1b}') && !message.contains('\r'));
}

/// Task 9.2-fix5 item B, first half. The same `exec` transition, one step
/// earlier: when the whole image is replaced the moved hook address often
/// resolves to *no* mapping at all rather than to a moved one, so the
/// record is rejected here instead of at the identity check — and this
/// branch never learned what the identity branch already knows. Measured
/// on `run --pause never -- env LD_PRELOAD=<provider> harness`: a second
/// public `discovery unavailable` on a capture with 136/136 probes, 68
/// slots and every counter clean, attributed to this exact site.
#[test]
fn a_loader_hit_unmapped_by_a_queued_exec_refresh_is_not_a_discovery_loss() {
    let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
    let armed = maps
        .iter()
        .find(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
        .expect("this process maps its own executable text")
        .clone();
    // Below `mmap_min_addr`: never mapped, so the hook address resolves to
    // nothing at all rather than to a moved mapping.
    let unmapped = 0x1000;
    assert!(
        !maps
            .iter()
            .any(|mapping| (mapping.start..mapping.end).contains(&unmapped)),
        "the null page is not mapped"
    );

    let (mut engine, context, _) = engine_with_exec_refreshed_loader(armed);
    let mut record = loader_record_for(context, std::process::id());
    record.table_ptr = unmapped;
    let mut session = ScriptedSession::with_records([], 1);
    apply_ordinary_batch(&mut engine, &mut session, vec![record])
        .expect("an ordinary batch carrying one unmapped loader hit");

    let skips = engine.counters.object_skips.clone();
    assert!(
        skips
            .iter()
            .all(|skip| skip.subject != "live loader discovery"),
        "an exec this capture already queued a refresh for explains the vanished \
             mapping; the hit is rejected, not lost: {skips:?}"
    );
    let [_, _, _, truncated] = engine.capture_facts().discovery_losses();
    assert_eq!(
        truncated, 0,
        "the queued refresh rescans the view whole, so this rejection is \
             counted by nothing"
    );
}

/// …and the exec record does not have to have been *seen* yet. Measured on
/// `run --pause auto -- env LD_PRELOAD=<provider> harness`: two loader hits
/// sit ahead of the exec record in the same ring batch, so neither
/// `pending_views` nor `refresh_requested` knows about the exec when they
/// are resolved. The armed mapping being gone from a live image is proof
/// enough on its own — only `exec` replaces an address space wholesale,
/// and `sched_process_exec` is attached unconditionally.
#[test]
fn a_loader_hit_whose_armed_image_is_gone_is_not_a_discovery_loss() {
    let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
    let observed = maps
        .iter()
        .find(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
        .expect("this process maps its own executable text")
        .clone();
    let mut armed = observed.clone();
    armed.start -= 0x1000_0000;
    armed.end -= 0x1000_0000;

    let (mut engine, context, _) = engine_with_exec_refreshed_loader(armed);
    // Neither channel knows about the exec yet: the record is still behind
    // this hit in the ring.
    engine.retirement_intents.clear();
    engine.refresh_requested.clear();
    let mut record = loader_record_for(context, std::process::id());
    record.table_ptr = 0x1000;
    let mut session = ScriptedSession::with_records([], 1);
    apply_ordinary_batch(&mut engine, &mut session, vec![record])
        .expect("an ordinary batch carrying one hit from a replaced image");

    let skips = engine.counters.object_skips.clone();
    assert!(
        skips
            .iter()
            .all(|skip| skip.subject != "live loader discovery"),
        "the armed mapping is gone from a live image, which only exec does: {skips:?}"
    );
}

/// fix5 review, finding 1. `refresh_requested` is not exec evidence: it is
/// also filled by `GenerationLost`, and `refresh_inventory` *retains* it
/// for every pid whose refresh failed, so on a live target whose refresh
/// keeps failing it is sticky for the rest of the capture. Silencing a
/// hit on it claims "the refresh rescans that view whole and re-arms it",
/// which is exactly what did not happen. Only a context armed before its
/// child exec'd has no mapping of its own to judge by.
#[test]
fn a_sticky_refresh_request_does_not_excuse_a_live_armed_mapping() {
    let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
    // Armed on a mapping this live image still holds: nothing about it says
    // `exec`.
    let armed = maps
        .iter()
        .find(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
        .expect("this process maps its own executable text")
        .clone();
    let pid = std::process::id();

    let (mut engine, context, _) = engine_with_exec_refreshed_loader(armed);
    engine.retirement_intents.clear();
    engine.refresh_requested.insert(pid);
    let mut record = loader_record_for(context, pid);
    record.table_ptr = 0x1000;
    let mut session = ScriptedSession::with_records([], 1);
    apply_ordinary_batch(&mut engine, &mut session, vec![record])
        .expect("an ordinary batch carrying one unresolvable hit");

    let skips = engine.counters.object_skips.clone();
    assert!(
        skips
            .iter()
            .any(|skip| skip.subject == "live loader discovery"),
        "a stale refresh request is not proof that an exec replaced this image: {skips:?}"
    );
}

/// fix5 review, finding 2. fix4's identity branch excuses a moved mapping
/// only while the exec that moved it is queued as this view's
/// `ExecRefresh`. `same_object_remapped` already requires the mapping to
/// have moved, so "the armed mapping is absent from the live image" is
/// implied there and must not stand in for the queued refresh — that would
/// make fix4's precondition vacuous. The controller's ruling is that fix4's
/// decision stands.
#[test]
fn the_identity_branch_still_requires_a_queued_exec_refresh() {
    let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
    let observed = maps
        .iter()
        .find(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
        .expect("this process maps its own executable text")
        .clone();
    let mut armed = observed.clone();
    armed.start -= 0x1000_0000;
    armed.end -= 0x1000_0000;

    let (mut engine, context, _) = engine_with_exec_refreshed_loader(armed);
    // No exec queued and no request outstanding: the mapping moved for a
    // reason this capture cannot name.
    engine.retirement_intents.clear();
    engine.refresh_requested.clear();
    let mut record = loader_record_for(context, std::process::id());
    record.table_ptr = observed.start + 0x10;
    let mut session = ScriptedSession::with_records([], 1);
    apply_ordinary_batch(&mut engine, &mut session, vec![record])
        .expect("an ordinary batch carrying one remapped hit");

    let skips = engine.counters.object_skips.clone();
    assert!(
        skips
            .iter()
            .any(|skip| skip.subject == "live loader discovery"),
        "without a queued exec refresh a moved mapping is loss, as fix4 left it: {skips:?}"
    );
}

/// fix5 review, finding 3. The initial discovery pass has the same two
/// producers `refresh_inventory` does, and they were left carrying the pid
/// in their deduplication key and consulting no exit proof — so a
/// `--cgroup` capture attached to an already-churning workload reproduces
/// lane 11's multiplicity at capture start, before the live path ever runs.
#[test]
fn capture_start_members_that_ended_are_not_losses() {
    let pids: Vec<_> = (0..3)
        .map(|_| {
            let mut child = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap();
            let pid = child.id();
            child.kill().unwrap();
            child.wait().unwrap();
            pid
        })
        .collect();
    let dir = tempfile::tempdir().expect("a scope directory");
    let listing: String = pids.iter().map(|pid| format!("{pid}\n")).collect();
    std::fs::write(dir.path().join("cgroup.procs"), listing).expect("a cgroup.procs");
    let args = CaptureArgs {
        kind: crate::cli::Kind::Profile,
        modules: vec![],
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: crate::cli::ScopeArg::Cgroup(dir.path().to_path_buf()),
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        ring_bytes: None,
        drain_interval: None,
        max_scan_pids: None,
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    };
    let scope = crate::scope::cgroup(dir.path()).expect("open scope directory");

    let engine = Engine::discover(&args, &scope, None).expect("an empty cgroup still captures");

    assert!(
        engine.plan().skipped.is_empty(),
        "three members that ended before capture start are not three losses: {:?}",
        engine.plan().skipped
    );
}

/// Task 2 (cgroup-256 B1): the multi-process scan cap is a CLI-settable Engine
/// field, not a hardcoded constant. Five live members with the cap at two: the
/// initial pass scans at most two and publishes a skip naming the effective
/// value, ordinary refresh ticks keep the retained set (filling a free slot
/// by rotation, never past the cap) and republish the bound as a deferral
/// gap, and the reconciliation pass republishes it as a rarity selection.
/// (Task 4: identical members share one provider group, so five `sleep`s
/// deep-scan as one representative — the bound is an upper bound now, not a
/// pid-order head-take.)
#[test]
fn max_scan_pids_bounds_initial_scan_and_refresh() {
    struct ChildrenGuard(Vec<std::process::Child>);
    impl Drop for ChildrenGuard {
        fn drop(&mut self) {
            for child in &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    let mut children = ChildrenGuard(
        (0..5)
            .map(|_| {
                std::process::Command::new("sleep")
                    .arg("30")
                    .spawn()
                    .unwrap()
            })
            .collect(),
    );
    let pids: Vec<_> = children.0.iter().map(|child| child.id()).collect();
    let dir = tempfile::tempdir().expect("a scope directory");
    let listing: String = pids.iter().map(|pid| format!("{pid}\n")).collect();
    std::fs::write(dir.path().join("cgroup.procs"), listing).expect("a cgroup.procs");
    let mut args = CaptureArgs {
        kind: crate::cli::Kind::Profile,
        modules: vec![],
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: crate::cli::ScopeArg::Cgroup(dir.path().to_path_buf()),
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        ring_bytes: None,
        drain_interval: None,
        max_scan_pids: Some(2),
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    };
    let scope = crate::scope::cgroup(dir.path()).expect("open scope directory");

    // Readiness (same idiom as the id-exhaustion sibling): a pre-exec child
    // still maps this test binary, which would split the provider groups and
    // move the representatives. Discover only once every child execed sleep.
    let self_exe = std::env::current_exe().unwrap();
    for child in &children.0 {
        let pid = child.id();
        let exe = format!("/proc/{pid}/exe");
        let mut execed = false;
        for _ in 0..500 {
            if std::fs::read_link(&exe).is_ok_and(|target| target != self_exe) {
                execed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(execed, "sleep child {pid} never execed");
    }

    // The sweep can transiently degrade under parallel load (one maps read
    // fails, that pid trails as an individual, and the representatives move),
    // so retry for an agreeing discovery. A deterministically broken selection
    // never agrees and still fails on the last attempt (Task-2 retry idiom).
    let mut lowest_first = pids.clone();
    lowest_first.sort_unstable();
    let mut agreed = None;
    for _ in 0..50 {
        let candidate =
            Engine::discover(&args, &scope, None).expect("a capped cgroup still captures");
        let view_pids: Vec<u32> = candidate.views.iter().map(|view| view.pid()).collect();
        let agrees = view_pids.as_slice() == &lowest_first[..view_pids.len()];
        agreed = Some(candidate);
        if agrees {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let mut engine = agreed.unwrap();
    assert_eq!(engine.max_scan_pids, 2);
    assert!(
        (1..=2).contains(&engine.views.len()),
        "the initial scan covers at most the capped count (identical members share one representative): {}",
        engine.views.len()
    );
    assert!(
        engine.base_counters.object_skips.iter().any(|skip| {
            skip.reason.contains("; discovery selected")
                && skip.reason.contains("for deep scanning by provider rarity")
        }),
        "the initial skip names the actual selected set: {:?}",
        engine.base_counters.object_skips
    );

    let initial: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    assert_eq!(
        initial.as_slice(),
        &lowest_first[..initial.len()],
        "the retained views are the lowest-pid members (one representative per provider group, lowest pid first, in every environment)"
    );
    refresh_inventory_once(&mut engine);
    let kept: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    assert!(
        initial.iter().all(|pid| kept.contains(pid)),
        "an ordinary tick displaces nothing: {initial:?} -> {kept:?}"
    );
    assert!(
        kept.len() <= 2,
        "rotation never admits past the cap: {kept:?}"
    );
    if initial.len() == 1 {
        assert_eq!(
            kept.len(),
            2,
            "one free slot admits exactly one rotation candidate"
        );
    }
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.reason.contains("live discovery deferred")
                && skip.reason.contains("to the periodic reconciliation sweep")
        }),
        "the ordinary refresh skip names the deferral gap: {:?}",
        engine.counters.object_skips
    );
    // The reconciliation pass republishes the bound as a rarity selection.
    refresh_inventory_once(&mut engine);
    refresh_inventory_once(&mut engine);
    refresh_inventory_once(&mut engine);
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.reason.contains("live discovery selected")
                && skip.reason.contains("for deep scanning by provider rarity")
        }),
        "the reconcile skip names the actual selected set: {:?}",
        engine.counters.object_skips
    );

    // ABC-T4 coverage: at every cap the selected set is minimal — exactly
    // min(cap, available candidates), never a redundant member more. The
    // discovery's internal sweep and this probe sweep are independent samples
    // that can disagree transiently under parallel load, so retry for an
    // agreeing pair and fail on the last attempt (same idiom as above).
    for cap in 1..=4usize {
        args.max_scan_pids = Some(cap);
        let mut attempt = None;
        for _ in 0..50 {
            let capped =
                Engine::discover(&args, &scope, None).expect("a capped cgroup still captures");
            let mut sweep_budget = CaptureWorkBudget::default();
            let sweep = sweep_process_maps(&pids, &mut sweep_budget);
            // Probe one below the sweep length so selection takes the grouped
            // path: `usize::MAX` would return the under-cap identity (all pids),
            // not the representative-plus-individual candidate count.
            let candidates =
                select_deep_scan_candidates(&sweep, sweep.len().saturating_sub(1)).len();
            let agrees = capped.views.len() == cap.min(candidates);
            attempt = Some((capped, candidates));
            if agrees {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let (capped, candidates) = attempt.unwrap();
        assert!(
            (1..=4).contains(&capped.views.len()),
            "cap {cap} covers at most the capped count: {}",
            capped.views.len()
        );
        assert_eq!(
            capped.views.len(),
            cap.min(candidates),
            "cap {cap} selects exactly the minimal set"
        );
    }

    for child in &mut children.0 {
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

/// ABC-T2 hardening: `Some(0)` via direct `CaptureArgs` construction clamps
/// to the default, exactly like `None` — `take(0)` is unreachable. An empty
/// cgroup needs no live members, so the clamp pins down without fixtures.
#[test]
fn some_zero_max_scan_pids_clamps_to_default_like_none() {
    let dir = tempfile::tempdir().expect("a scope directory");
    std::fs::write(dir.path().join("cgroup.procs"), "").expect("a cgroup.procs");
    let scope = crate::scope::cgroup(dir.path()).expect("open scope directory");
    let args_with = |max_scan_pids| CaptureArgs {
        kind: crate::cli::Kind::Profile,
        modules: vec![],
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: crate::cli::ScopeArg::Cgroup(dir.path().to_path_buf()),
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        ring_bytes: None,
        drain_interval: None,
        max_scan_pids,
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    };
    let zero = Engine::discover(&args_with(Some(0)), &scope, None)
        .expect("a zero-capped cgroup still captures");
    let unset = Engine::discover(&args_with(None), &scope, None)
        .expect("an uncapped cgroup still captures");
    assert_eq!(
        zero.max_scan_pids, unset.max_scan_pids,
        "`Some(0)` behaves identically to `None`"
    );
    assert_eq!(
        zero.max_scan_pids, MAX_SCAN_PIDS,
        "`Some(0)` clamps to the default"
    );
    assert!(
        zero.views.is_empty() && unset.views.is_empty(),
        "an empty cgroup admits no views either way"
    );
}

/// ABC-T4 hardening: a zero cap short-circuits the refresh sweep to empty —
/// no maps reads, zero budget charge — while the bound skip still publishes.
/// (`discover_plan` can no longer see a zero cap after the `Some(0)` clamp,
/// so the refresh tick is the live carrier of this edge.)
#[test]
fn zero_cap_refresh_short_circuits_the_sweep_to_empty() {
    struct ChildrenGuard(Vec<std::process::Child>);
    impl Drop for ChildrenGuard {
        fn drop(&mut self) {
            for child in &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    let mut children = ChildrenGuard(
        (0..5)
            .map(|_| {
                std::process::Command::new("sleep")
                    .arg("30")
                    .spawn()
                    .unwrap()
            })
            .collect(),
    );
    let pids: Vec<_> = children.0.iter().map(|child| child.id()).collect();
    let dir = tempfile::tempdir().expect("a scope directory");
    let listing: String = pids.iter().map(|pid| format!("{pid}\n")).collect();
    std::fs::write(dir.path().join("cgroup.procs"), listing).expect("a cgroup.procs");
    let args = CaptureArgs {
        kind: crate::cli::Kind::Profile,
        modules: vec![],
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: crate::cli::ScopeArg::Cgroup(dir.path().to_path_buf()),
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        ring_bytes: None,
        drain_interval: None,
        max_scan_pids: None,
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    };
    let scope = crate::scope::cgroup(dir.path()).expect("open scope directory");

    // Readiness (same idiom as the cap sibling): discover only once every
    // child execed sleep, so no maps read races a fork-exec transition.
    let self_exe = std::env::current_exe().unwrap();
    for child in &children.0 {
        let pid = child.id();
        let exe = format!("/proc/{pid}/exe");
        let mut execed = false;
        for _ in 0..500 {
            if std::fs::read_link(&exe).is_ok_and(|target| target != self_exe) {
                execed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(execed, "sleep child {pid} never execed");
    }

    let mut engine = Engine::discover(&args, &scope, None).expect("an uncapped cgroup captures");
    let before: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();

    engine.max_scan_pids = 0;
    let budget_before = engine.budget.attempted_io_bytes();
    refresh_inventory_once(&mut engine);
    let budget_after = engine.budget.attempted_io_bytes();

    assert_eq!(
        budget_after - budget_before,
        0,
        "a zero cap performs no scan reads on refresh"
    );
    let kept: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    assert_eq!(
        kept, before,
        "the tick selects nothing new and retires nothing"
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.reason
                .contains("live discovery selected 0 new candidates")
                && skip.reason.contains("for deep scanning by provider rarity")
        }),
        "the refresh skip still names the effective value: {:?}",
        engine.counters.object_skips
    );

    for child in &mut children.0 {
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

/// Task 3.1b: an ordinary over-cap refresh tick performs no maps sweep.
/// Five retained views under a cap of two leave nothing to select, so the
/// tick must charge zero budget bytes and publish no rarity selection —
/// the full sweep belongs to the slower reconciliation pass, not to every
/// tick against the lifetime budget.
#[test]
fn ordinary_over_cap_refresh_performs_no_maps_sweep() {
    struct ChildrenGuard(Vec<std::process::Child>);
    impl Drop for ChildrenGuard {
        fn drop(&mut self) {
            for child in &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    let mut children = ChildrenGuard(
        (0..5)
            .map(|_| {
                std::process::Command::new("sleep")
                    .arg("30")
                    .spawn()
                    .unwrap()
            })
            .collect(),
    );
    let pids: Vec<_> = children.0.iter().map(|child| child.id()).collect();
    let dir = tempfile::tempdir().expect("a scope directory");
    let listing: String = pids.iter().map(|pid| format!("{pid}\n")).collect();
    std::fs::write(dir.path().join("cgroup.procs"), listing).expect("a cgroup.procs");
    let args = CaptureArgs {
        kind: crate::cli::Kind::Profile,
        modules: vec![],
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: crate::cli::ScopeArg::Cgroup(dir.path().to_path_buf()),
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        ring_bytes: None,
        drain_interval: None,
        max_scan_pids: None,
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    };
    let scope = crate::scope::cgroup(dir.path()).expect("open scope directory");

    let self_exe = std::env::current_exe().unwrap();
    for child in &children.0 {
        let pid = child.id();
        let exe = format!("/proc/{pid}/exe");
        let mut execed = false;
        for _ in 0..500 {
            if std::fs::read_link(&exe).is_ok_and(|target| target != self_exe) {
                execed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(execed, "sleep child {pid} never execed");
    }

    let mut engine = Engine::discover(&args, &scope, None).expect("an uncapped cgroup captures");
    assert_eq!(engine.views.len(), 5, "all five members are retained");
    engine.max_scan_pids = 2;

    let budget_before = engine.budget.attempted_io_bytes();
    refresh_inventory_once(&mut engine);
    let budget_after = engine.budget.attempted_io_bytes();

    assert_eq!(
        budget_after - budget_before,
        0,
        "an ordinary over-cap tick reads no maps"
    );
    assert!(
        !engine.counters.object_skips.iter().any(|skip| {
            skip.reason.contains("live discovery selected")
                && skip.reason.contains("for deep scanning by provider rarity")
        }),
        "no rarity selection runs on an ordinary tick: {:?}",
        engine.counters.object_skips
    );
    let kept: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    assert_eq!(kept.len(), 5, "the tick retires nothing");

    for child in &mut children.0 {
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

/// Task 3.1b: lifecycle/loader refresh requests enqueue bounded work. Past
/// the cap, excess requests are dropped with explicit truncation evidence —
/// never an unbounded userspace queue — while a re-request for an already
/// queued pid stays free.
#[test]
fn refresh_request_queue_is_bounded_with_explicit_overflow() {
    let (mut engine, _dir) = engine_over_cgroup_naming(&[]);
    for pid in 1..=(MAX_PENDING_REFRESH as u32 + 44) {
        engine.request_refresh(pid);
    }
    assert_eq!(engine.refresh_requested.len(), MAX_PENDING_REFRESH);
    assert_eq!(engine.discovery_truncated, 44);
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .any(|skip| skip.subject == "live discovery refresh"
                && skip
                    .reason
                    .contains("refresh requests exceeded the bounded pending queue")),
        "overflow publishes explicit loss: {:?}",
        engine.counters.object_skips
    );
    // Re-requesting a queued pid is a no-op, not more overflow.
    engine.request_refresh(1);
    assert_eq!(engine.refresh_requested.len(), MAX_PENDING_REFRESH);
    assert_eq!(engine.discovery_truncated, 44);
}

/// Task 3.1b: the loader half of the bounded-work contract. Deferred loader
/// memory scans already cap at the loader-context ledger; past it, the
/// excess scan is dropped with the same explicit truncation evidence.
#[test]
fn loader_deferral_bound_drops_with_explicit_loss() {
    let (mut engine, _dir) = engine_over_cgroup_naming(&[]);
    let context = crate::discovery::loader::LoaderContextId::from_case_id(0);
    for index in 0..=(crate::discovery::loader::MAX_LOADER_CONTEXTS as u32) {
        engine.defer_loader_memory_scan(
            PendingLoaderScanKey {
                view: ProcessViewId(index),
                context,
            },
            7,
        );
    }
    assert_eq!(
        engine.pending_loader_scans.len(),
        crate::discovery::loader::MAX_LOADER_CONTEXTS
    );
    assert_eq!(engine.discovery_truncated, 1);
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == "live loader memory discovery"
                && skip
                    .reason
                    .contains("exceeded the bounded loader-context ledger")
        }),
        "loader overflow publishes explicit loss: {:?}",
        engine.counters.object_skips
    );
}

/// Task 3.1b: ordinary rotation admits unscanned views into free slots and
/// never displaces a retained view. Five members under a cap of two: the
/// first ordinary pass fills the free slot (if any) with the lowest
/// unscanned pid, later passes keep the admitted set, and the deferral gap
/// names exact counts without naming any pid.
#[test]
fn retained_views_survive_ordinary_rotation_passes() {
    struct ChildrenGuard(Vec<std::process::Child>);
    impl Drop for ChildrenGuard {
        fn drop(&mut self) {
            for child in &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    let mut children = ChildrenGuard(
        (0..5)
            .map(|_| {
                std::process::Command::new("sleep")
                    .arg("30")
                    .spawn()
                    .unwrap()
            })
            .collect(),
    );
    let mut pids: Vec<_> = children.0.iter().map(|child| child.id()).collect();
    pids.sort_unstable();
    let dir = tempfile::tempdir().expect("a scope directory");
    let listing: String = pids.iter().map(|pid| format!("{pid}\n")).collect();
    std::fs::write(dir.path().join("cgroup.procs"), listing).expect("a cgroup.procs");
    let args = CaptureArgs {
        kind: crate::cli::Kind::Profile,
        modules: vec![],
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: crate::cli::ScopeArg::Cgroup(dir.path().to_path_buf()),
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        ring_bytes: None,
        drain_interval: None,
        max_scan_pids: Some(2),
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    };
    let scope = crate::scope::cgroup(dir.path()).expect("open scope directory");

    let self_exe = std::env::current_exe().unwrap();
    for child in &children.0 {
        let pid = child.id();
        let exe = format!("/proc/{pid}/exe");
        let mut execed = false;
        for _ in 0..500 {
            if std::fs::read_link(&exe).is_ok_and(|target| target != self_exe) {
                execed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(execed, "sleep child {pid} never execed");
    }

    let mut engine = Engine::discover(&args, &scope, None).expect("a capped cgroup still captures");
    let initial: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    assert!(
        (1..=2).contains(&initial.len()),
        "identical members share representatives: {}",
        initial.len()
    );

    refresh_inventory_once(&mut engine);
    let after_first: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    assert!(
        initial.iter().all(|pid| after_first.contains(pid)),
        "rotation displaces nothing: {initial:?} -> {after_first:?}"
    );
    if initial.len() == 1 {
        // One free slot: rotation admits the lowest unscanned pid.
        let lowest_unknown = pids.iter().find(|pid| !initial.contains(pid)).unwrap();
        assert_eq!(after_first.len(), 2);
        assert!(
            after_first.contains(lowest_unknown),
            "rotation admits the lowest unscanned pid: {after_first:?}"
        );
    } else {
        assert_eq!(after_first, initial, "a full cap admits nothing");
    }
    // The deferral gap is exact and categorical: counts only, no pids.
    let deferred = engine
        .counters
        .object_skips
        .iter()
        .find(|skip| skip.reason.contains("periodic reconciliation sweep"));
    assert_eq!(
        deferred.map(|skip| skip.reason.as_str()),
        Some(
            "5 processes in scope; live discovery deferred 3 unscanned processes to the periodic reconciliation sweep (limit 2)"
        ),
        "deferral gap names exact counts: {:?}",
        engine.counters.object_skips
    );

    refresh_inventory_once(&mut engine);
    refresh_inventory_once(&mut engine);
    let kept: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    assert!(
        after_first.iter().all(|pid| kept.contains(pid)),
        "later ordinary passes displace nothing: {after_first:?} -> {kept:?}"
    );
    assert_eq!(kept.len(), 2, "the cap stays full without churn");

    for child in &mut children.0 {
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

/// Task 3.1b: the reconciliation pass re-reads maps (never from a cache),
/// keeps rarity-ordered admission for what its slice covers, and parks the
/// cursor at the last pid read. Ordinary passes around it charge nothing.
/// Package C: with the cap full of exploratory views, the reconcile pass
/// rotates one out for the rarity-selected newcomer (ordinary passes still
/// displace nothing); the second reconcile admits forward, never churning
/// the cooling evictee back in.
/// (Mandated semantic change: pass 4 used to select 0 into zero free slots.)
#[test]
fn reconcile_pass_rereads_maps_rarity_selects_and_advances_cursor() {
    struct ChildrenGuard(Vec<std::process::Child>);
    impl Drop for ChildrenGuard {
        fn drop(&mut self) {
            for child in &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    let mut children = ChildrenGuard(
        (0..5)
            .map(|_| {
                std::process::Command::new("sleep")
                    .arg("30")
                    .spawn()
                    .unwrap()
            })
            .collect(),
    );
    let mut pids: Vec<_> = children.0.iter().map(|child| child.id()).collect();
    pids.sort_unstable();
    let dir = tempfile::tempdir().expect("a scope directory");
    let listing: String = pids.iter().map(|pid| format!("{pid}\n")).collect();
    std::fs::write(dir.path().join("cgroup.procs"), listing).expect("a cgroup.procs");
    let args = CaptureArgs {
        kind: crate::cli::Kind::Profile,
        modules: vec![],
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: crate::cli::ScopeArg::Cgroup(dir.path().to_path_buf()),
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        ring_bytes: None,
        drain_interval: None,
        max_scan_pids: Some(2),
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    };
    let scope = crate::scope::cgroup(dir.path()).expect("open scope directory");

    let self_exe = std::env::current_exe().unwrap();
    for child in &children.0 {
        let pid = child.id();
        let exe = format!("/proc/{pid}/exe");
        let mut execed = false;
        for _ in 0..500 {
            if std::fs::read_link(&exe).is_ok_and(|target| target != self_exe) {
                execed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(execed, "sleep child {pid} never execed");
    }

    // The initial sweep can transiently degrade under parallel load (one maps
    // read fails or races a fork-exec transition, that pid trails as an
    // individual, and the representatives move), so retry for an agreeing
    // lowest-first discovery. A deterministically broken selection never
    // agrees and still fails on the last attempt (Task-2 retry idiom).
    // Refresh-time reads are safe: the children settled long before pass 4.
    let mut agreed = None;
    for _ in 0..50 {
        let candidate =
            Engine::discover(&args, &scope, None).expect("a capped cgroup still captures");
        let view_pids: Vec<u32> = candidate.views.iter().map(|view| view.pid()).collect();
        let agrees = view_pids.as_slice() == [pids[0]];
        agreed = Some(candidate);
        if agrees {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let mut engine = agreed.unwrap();
    assert_eq!(
        engine
            .views
            .iter()
            .map(|view| view.pid())
            .collect::<Vec<_>>(),
        vec![pids[0]],
        "the retained view is the lowest-pid member"
    );
    engine.scheduler.set_quantum_ns_for_test(u64::MAX);

    // Passes 1-3 are ordinary: only the pass-1 rotation admission charges
    // (initial discovery agreed on exactly the lowest rep, so one free slot
    // rotates exactly the lowest unknown in).
    let before = engine.budget.attempted_io_bytes();
    refresh_inventory_once(&mut engine);
    let pass1 = engine.budget.attempted_io_bytes() - before;
    assert!(pass1 > 0, "the rotation admission deep-scans its one view");
    assert_eq!(engine.views.len(), 2);
    let mut pass1_views: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    pass1_views.sort_unstable();
    assert_eq!(pass1_views, pids[..2]);
    for pass in 2..=3 {
        let before = engine.budget.attempted_io_bytes();
        refresh_inventory_once(&mut engine);
        assert_eq!(
            engine.budget.attempted_io_bytes() - before,
            0,
            "ordinary pass {pass} charges nothing"
        );
    }

    // Pass 4 reconciles: the slice re-reads every enumerated maps file,
    // rarity selection runs over the slice, and the cursor parks at the end.
    let before = engine.budget.attempted_io_bytes();
    refresh_inventory_once(&mut engine);
    let pass4 = engine.budget.attempted_io_bytes() - before;
    assert!(pass4 > 0, "the reconcile slice reads maps, never cached");
    assert_eq!(engine.scheduler.cursor_for_test(), Some(pids[4]));
    let rarity = engine
        .counters
        .object_skips
        .iter()
        .find(|skip| skip.reason.contains("live discovery selected"));
    assert_eq!(
        rarity.map(|skip| skip.reason.as_str()),
        Some(
            "5 processes in scope; live discovery selected 1 new candidate for deep scanning by provider rarity (limit 2)"
        ),
        "reconcile keeps rarity admission: {:?}",
        engine.counters.object_skips
    );
    // Package C: the three unknowns share one provider group and exceed the
    // two slots, so the grouped path takes the group representative (lowest
    // pid) and rotation evicts the lowest retained pid for it. Both evidence
    // records are categorical counts.
    let mut pass4_views: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    pass4_views.sort_unstable();
    assert_eq!(
        pass4_views,
        vec![pids[1], pids[2]],
        "pass 4 rotates the lowest retained pid out for the group representative"
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == "live discovery rotation"
                && skip.reason
                    == "exploratory rotation evicted 1 provider-free process view to reach unscanned processes (limit 2)"
        }),
        "rotation publishes its exact evidence: {:?}",
        engine.counters.object_skips
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == "live discovery rotation"
                && skip.reason == "1 unscanned process is cooling down after exploratory rotation"
        }),
        "the cooldown publishes its exact evidence: {:?}",
        engine.counters.object_skips
    );
    // The surviving retained exploratory view was covered too, so it polls
    // same-tick (a rescan, not a displacement — the view set above proves it).
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == "live discovery rotation"
                && skip.reason == "queued 1 retained exploratory view for polling rescan"
        }),
        "the surviving retained view polls: {:?}",
        engine.counters.object_skips
    );

    // Passes 5-7 are ordinary again: they charge nothing and displace
    // nothing; pass 8 reconciles and re-reads — maps bytes are never
    // served from a cache.
    for pass in 5..=7 {
        let before = engine.budget.attempted_io_bytes();
        refresh_inventory_once(&mut engine);
        assert_eq!(
            engine.budget.attempted_io_bytes() - before,
            0,
            "ordinary pass {pass} charges nothing"
        );
        let mut kept: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
        kept.sort_unstable();
        assert_eq!(kept, pass4_views, "ordinary pass {pass} displaces nothing");
    }
    let before = engine.budget.attempted_io_bytes();
    refresh_inventory_once(&mut engine);
    assert!(
        engine.budget.attempted_io_bytes() - before > 0,
        "the next reconcile re-reads maps too"
    );
    // The second sweep admits forward: the cooled-out evictee sits out, so
    // the remaining two unknowns fit the two slots exactly (identity, not
    // grouping) and both rotate in — neither is the just-evicted lowest pid.
    let mut pass8_views: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    pass8_views.sort_unstable();
    assert_eq!(
        pass8_views,
        vec![pids[3], pids[4]],
        "pass 8 walks forward past the cooling evictee"
    );

    for child in &mut children.0 {
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

/// Task 3.1b: the reconcile cursor is incremental — each sweep covers the
/// next slice and wraps — and each incomplete slice publishes its exact
/// coverage plus its generation-revalidation count as a categorical gap.
/// Package C: sweeps covering only retained pids rotate nothing; the first
/// sweep reaching unknowns rotates one exploratory view out per selected
/// newcomer, and the wrapped sweep revalidates only what is still retained.
/// (Mandated semantic change: the wrapped slice used to revalidate a view
/// that rotation has since moved on from.)
#[test]
fn reconcile_cursor_advances_incrementally_and_wraps() {
    struct ChildrenGuard(Vec<std::process::Child>);
    impl Drop for ChildrenGuard {
        fn drop(&mut self) {
            for child in &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    let mut children = ChildrenGuard(
        (0..5)
            .map(|_| {
                std::process::Command::new("sleep")
                    .arg("30")
                    .spawn()
                    .unwrap()
            })
            .collect(),
    );
    let mut pids: Vec<_> = children.0.iter().map(|child| child.id()).collect();
    pids.sort_unstable();
    let dir = tempfile::tempdir().expect("a scope directory");
    let listing: String = pids.iter().map(|pid| format!("{pid}\n")).collect();
    std::fs::write(dir.path().join("cgroup.procs"), listing).expect("a cgroup.procs");
    let args = CaptureArgs {
        kind: crate::cli::Kind::Profile,
        modules: vec![],
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: crate::cli::ScopeArg::Cgroup(dir.path().to_path_buf()),
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        ring_bytes: None,
        drain_interval: None,
        max_scan_pids: Some(2),
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    };
    let scope = crate::scope::cgroup(dir.path()).expect("open scope directory");

    let self_exe = std::env::current_exe().unwrap();
    for child in &children.0 {
        let pid = child.id();
        let exe = format!("/proc/{pid}/exe");
        let mut execed = false;
        for _ in 0..500 {
            if std::fs::read_link(&exe).is_ok_and(|target| target != self_exe) {
                execed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(execed, "sleep child {pid} never execed");
    }

    // The initial sweep can transiently degrade under parallel load (one maps
    // read fails, that pid trails as an individual, and the representatives
    // move), so retry for an agreeing lowest-first discovery. A
    // deterministically broken selection never agrees and still fails on the
    // last attempt (Task-2 retry idiom).
    let mut agreed = None;
    for _ in 0..50 {
        let candidate =
            Engine::discover(&args, &scope, None).expect("a capped cgroup still captures");
        let view_pids: Vec<u32> = candidate.views.iter().map(|view| view.pid()).collect();
        let agrees = view_pids.as_slice() == &pids[..view_pids.len()];
        agreed = Some(candidate);
        if agrees {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let mut engine = agreed.unwrap();
    let initial: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    assert_eq!(
        initial.as_slice(),
        &pids[..initial.len()],
        "the retained views are the lowest-pid members"
    );
    engine.scheduler.set_quantum_ns_for_test(u64::MAX);
    engine.scheduler.set_slice_pids_for_test(2);

    for _ in 0..3 {
        refresh_inventory_once(&mut engine);
    }
    // The cap is full with the two lowest pids after the ordinary passes.
    let mut kept: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    kept.sort_unstable();
    assert_eq!(kept, pids[..2]);

    // Pass 4: first slice covers the two lowest pids, both retained.
    refresh_inventory_once(&mut engine);
    assert_eq!(engine.scheduler.cursor_for_test(), Some(pids[1]));
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.reason
                == "reconciliation sweep covered 2 of 5 observed processes and revalidated 2 retained generations; 3 deferred to the next sweep"
        }),
        "first slice gap is exact: {:?}",
        engine.counters.object_skips
    );
    // Nothing unknown in the slice, so nothing rotates — but both covered
    // retained exploratory views are queued for a polling rescan, since
    // unarmed views otherwise never re-examine their process.
    let mut kept: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    kept.sort_unstable();
    assert_eq!(kept, pids[..2]);
    assert!(
        !engine
            .counters
            .object_skips
            .iter()
            .any(|skip| skip.reason.contains("evicted")),
        "a slice over retained pids only evicts nothing"
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == "live discovery rotation"
                && skip.reason == "queued 2 retained exploratory views for polling rescan"
        }),
        "covered retained exploratory views poll: {:?}",
        engine.counters.object_skips
    );

    // Pass 8: next slice covers the following two pids, neither retained.
    for _ in 0..3 {
        refresh_inventory_once(&mut engine);
    }
    refresh_inventory_once(&mut engine);
    assert_eq!(engine.scheduler.cursor_for_test(), Some(pids[3]));
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.reason
                == "reconciliation sweep covered 2 of 5 observed processes and revalidated 0 retained generations; 3 deferred to the next sweep"
        }),
        "second slice gap is exact: {:?}",
        engine.counters.object_skips
    );
    // The two unknowns fit the two slots exactly (identity, not grouping),
    // so both rotate in and both lowest retained pids rotate out.
    let mut kept: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    kept.sort_unstable();
    assert_eq!(
        kept,
        vec![pids[2], pids[3]],
        "pass 8 rotates both unknowns in for both lowest retained pids"
    );

    // Pass 12: the slice wraps past the end to the lowest pid — which
    // rotation moved on from at pass 8, so nothing there revalidates.
    for _ in 0..3 {
        refresh_inventory_once(&mut engine);
    }
    refresh_inventory_once(&mut engine);
    assert_eq!(engine.scheduler.cursor_for_test(), Some(pids[0]));
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.reason
                == "reconciliation sweep covered 2 of 5 observed processes and revalidated 0 retained generations; 3 deferred to the next sweep"
        }),
        "wrapped slice gap is exact: {:?}",
        engine.counters.object_skips
    );

    for child in &mut children.0 {
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

/// Task 3.1b: a zero wall-time quantum stops the reconcile slice before its
/// first read — the whole slice defers explicitly and the cursor holds.
/// Package C: the polling rescan still runs on under its own tick quantum;
/// the reconcile quantum bounds maps reads, not deep scans.
#[test]
fn reconcile_quantum_zero_defers_the_whole_slice() {
    struct ChildrenGuard(Vec<std::process::Child>);
    impl Drop for ChildrenGuard {
        fn drop(&mut self) {
            for child in &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    let mut children = ChildrenGuard(
        (0..3)
            .map(|_| {
                std::process::Command::new("sleep")
                    .arg("30")
                    .spawn()
                    .unwrap()
            })
            .collect(),
    );
    let pids: Vec<_> = children.0.iter().map(|child| child.id()).collect();
    let dir = tempfile::tempdir().expect("a scope directory");
    let listing: String = pids.iter().map(|pid| format!("{pid}\n")).collect();
    std::fs::write(dir.path().join("cgroup.procs"), listing).expect("a cgroup.procs");
    let args = CaptureArgs {
        kind: crate::cli::Kind::Profile,
        modules: vec![],
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: crate::cli::ScopeArg::Cgroup(dir.path().to_path_buf()),
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        ring_bytes: None,
        drain_interval: None,
        max_scan_pids: Some(1),
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    };
    let scope = crate::scope::cgroup(dir.path()).expect("open scope directory");

    let self_exe = std::env::current_exe().unwrap();
    for child in &children.0 {
        let pid = child.id();
        let exe = format!("/proc/{pid}/exe");
        let mut execed = false;
        for _ in 0..500 {
            if std::fs::read_link(&exe).is_ok_and(|target| target != self_exe) {
                execed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(execed, "sleep child {pid} never execed");
    }

    let mut engine = Engine::discover(&args, &scope, None).expect("a capped cgroup still captures");
    engine.scheduler.set_quantum_ns_for_test(0);

    for _ in 0..3 {
        refresh_inventory_once(&mut engine);
    }
    assert_eq!(engine.scheduler.cursor_for_test(), None);
    // Package C: the maps slice defers (cursor holds, gap exact), but the
    // polling rescan runs on under its own tick quantum — the reconcile
    // quantum bounds maps reads, not deep scans. The one retained
    // exploratory view polls its standard pre- plus post-retirement pair.
    // (Mandated semantic change: the reconcile tick used to charge nothing
    // at all under a zero quantum.)
    let scans_before = engine.deep_scans;
    refresh_inventory_once(&mut engine);
    assert_eq!(
        engine.deep_scans - scans_before,
        2,
        "polling rescans proceed under the tick quantum"
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == "live discovery rotation"
                && skip.reason == "queued 1 retained exploratory view for polling rescan"
        }),
        "the polling round is explicit: {:?}",
        engine.counters.object_skips
    );
    assert_eq!(
        engine.scheduler.cursor_for_test(),
        None,
        "an unread slice advances nothing"
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.reason.contains("covered 0 of 3 observed processes")
                && skip.reason.contains("deferred to the next sweep")
        }),
        "the deferred slice is explicit: {:?}",
        engine.counters.object_skips
    );

    for child in &mut children.0 {
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

/// Task 3.1b: event-driven refresh requests survive allocation exhaustion.
/// Three retained views under a cap of two leave no free slot, and two
/// further members arrive with queued lifecycle refreshes: an ordinary pass
/// admits nothing, keeps both queued requests for a later pass, and
/// publishes the standard capacity skip instead of dropping the work.
#[test]
fn refresh_requests_survive_allocation_exhaustion() {
    struct ChildrenGuard(Vec<std::process::Child>);
    impl Drop for ChildrenGuard {
        fn drop(&mut self) {
            for child in &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    let mut children = ChildrenGuard(
        (0..5)
            .map(|_| {
                std::process::Command::new("sleep")
                    .arg("30")
                    .spawn()
                    .unwrap()
            })
            .collect(),
    );
    let mut pids: Vec<_> = children.0.iter().map(|child| child.id()).collect();
    pids.sort_unstable();
    let dir = tempfile::tempdir().expect("a scope directory");
    let listing: String = pids[..3].iter().map(|pid| format!("{pid}\n")).collect();
    std::fs::write(dir.path().join("cgroup.procs"), listing).expect("a cgroup.procs");
    let args = CaptureArgs {
        kind: crate::cli::Kind::Profile,
        modules: vec![],
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: crate::cli::ScopeArg::Cgroup(dir.path().to_path_buf()),
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        ring_bytes: None,
        drain_interval: None,
        max_scan_pids: None,
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    };
    let scope = crate::scope::cgroup(dir.path()).expect("open scope directory");

    let self_exe = std::env::current_exe().unwrap();
    for child in &children.0 {
        let pid = child.id();
        let exe = format!("/proc/{pid}/exe");
        let mut execed = false;
        for _ in 0..500 {
            if std::fs::read_link(&exe).is_ok_and(|target| target != self_exe) {
                execed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(execed, "sleep child {pid} never execed");
    }

    let mut engine = Engine::discover(&args, &scope, None).expect("an uncapped cgroup captures");
    assert_eq!(engine.views.len(), 3, "three members are retained");
    // Two further members arrive; the cap drops below the retained count.
    let listing: String = pids.iter().map(|pid| format!("{pid}\n")).collect();
    std::fs::write(dir.path().join("cgroup.procs"), listing).expect("a cgroup.procs");
    engine.max_scan_pids = 2;
    // Queue event-driven refreshes for the two unknown members.
    engine.refresh_requested.insert(pids[3]);
    engine.refresh_requested.insert(pids[4]);

    refresh_inventory_once(&mut engine);

    assert!(
        engine.refresh_requested.contains(&pids[3]) && engine.refresh_requested.contains(&pids[4]),
        "exhaustion retains the queued work: {:?}",
        engine.refresh_requested
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.reason
                .contains("capture process-view capacity 2 was exhausted")
        }),
        "exhaustion publishes the standard skip: {:?}",
        engine.counters.object_skips
    );

    for child in &mut children.0 {
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

/// Task 3 (cgroup-256 A2): with an exhausted view-ID space, allocation
/// failure degrades to evidence, never fatal. Two members admitted at cap
/// two, then a third member arrives: the ordinary tick returns `Ok`, keeps
/// the admitted views, and defers the newcomer with an exact gap (rotation
/// only fills free slots, so no allocation is attempted); a queued
/// lifecycle refresh for the newcomer then attempts admission, exhausts,
/// and publishes the standard skip naming the effective value. (The
/// initial-scan path is unreachable post-Task-2 — fresh engine plus a
/// matching ceiling — so the refresh tick carries the behavioral coverage;
/// the shape test below pins the defensive initial-scan sites.)
#[test]
fn id_exhaustion_publishes_skip_instead_of_failing() {
    let mut children: Vec<_> = (0..2)
        .map(|_| {
            std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap()
        })
        .collect();
    let mut pids: Vec<_> = children.iter().map(|child| child.id()).collect();
    let dir = tempfile::tempdir().expect("a scope directory");
    let listing: String = pids.iter().map(|pid| format!("{pid}\n")).collect();
    std::fs::write(dir.path().join("cgroup.procs"), listing).expect("a cgroup.procs");
    let args = CaptureArgs {
        kind: crate::cli::Kind::Profile,
        modules: vec![],
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: crate::cli::ScopeArg::Cgroup(dir.path().to_path_buf()),
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        ring_bytes: None,
        drain_interval: None,
        max_scan_pids: Some(2),
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    };
    let scope = crate::scope::cgroup(dir.path()).expect("open scope directory");

    // Readiness (flake hardening): pre-exec a child is a fork of this
    // dynamic test binary, and its exe link already resolves then (to our
    // own image) — so only discover once no child's exe link still points
    // at us. Identical sleep groups keep selection deterministic.
    let self_exe = std::env::current_exe().unwrap();
    for child in &children {
        let pid = child.id();
        let exe = format!("/proc/{pid}/exe");
        let mut execed = false;
        for _ in 0..500 {
            if std::fs::read_link(&exe).is_ok_and(|target| target != self_exe) {
                execed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(execed, "sleep child {pid} never execed");
    }

    let mut engine = Engine::discover(&args, &scope, None).expect("a capped cgroup still captures");
    assert_eq!(engine.views.len(), 2, "both members admitted at cap two");
    let admitted: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();

    // A third member arrives after admission with no lifecycle event: the
    // ordinary tick keeps the admitted views and defers the newcomer with
    // an exact gap instead of attempting an allocation it cannot fill.
    let newcomer = std::process::id();
    pids.push(newcomer);
    let listing: String = pids.iter().map(|pid| format!("{pid}\n")).collect();
    std::fs::write(dir.path().join("cgroup.procs"), listing).expect("a cgroup.procs");
    refresh_inventory_once(&mut engine);

    let kept: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    assert_eq!(kept, admitted, "deferral keeps the admitted views");
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.reason
                == "3 processes in scope; live discovery deferred 1 unscanned processes to the periodic reconciliation sweep (limit 2)"
        }),
        "arrival without an event publishes the exact deferral gap: {:?}",
        engine.counters.object_skips
    );

    // A queued lifecycle refresh for the newcomer attempts admission and
    // exhausts: the standard skip names the effective value, the request
    // stays queued for a later pass, and nothing is displaced.
    engine.request_refresh(newcomer);
    refresh_inventory_once(&mut engine);

    let kept: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    assert_eq!(kept, admitted, "exhaustion keeps the admitted views");
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == "process view"
                && skip.reason
                    == "capture process-view capacity 2 was exhausted; remaining generations were not scanned"
        }),
        "exhaustion publishes the standard skip with the effective value: {:?}",
        engine.counters.object_skips
    );
    assert!(
        engine.refresh_requested.contains(&newcomer),
        "exhaustion retains the queued refresh: {:?}",
        engine.refresh_requested
    );

    for child in &mut children {
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

/// Task 3 (cgroup-256 A2): `discover_plan` must not fatally propagate
/// view-ID allocation failure. The two `?` sites are defensive (unreachable
/// post-Task-2: fresh engine, matching ceiling); this pins them as
/// skip+break so a future ceiling drift degrades instead of killing the
/// capture.
#[test]
fn discover_plan_has_no_fatal_allocation() {
    let source = include_str!("engine.rs");
    let plan = source
        .split_once("fn discover_plan(")
        .unwrap()
        .1
        .split_once("fn build_current_plan(")
        .unwrap()
        .0;
    assert!(
        !plan.contains("allocate_view_id()?"),
        "discover_plan must degrade allocation failure to a skip, not `?`"
    );
    assert!(
        !plan.contains("retain_view_id(view.id())?"),
        "discover_plan must degrade retain failure to a skip, not `?`"
    );
}

/// Task 9.2b defect D, second half. A discovery record can only be resolved
/// against the address space it came from, and a `--cgroup` capture's
/// forked children make their calls and exit while their records are still
/// queued. Every one of those then fails resolution with "process
/// generation changed before target access" and publishes one public
/// `discovery unavailable` — for the ordinary end of a process whose calls
/// the attached probes already counted exactly.
#[test]
fn a_record_from_a_proven_exited_generation_is_not_a_discovery_loss() {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let pid = child.id();
    let (mut engine, context) = Engine::retiring_loader_context(pid);
    // A cgroup capture continues when one member exits; the record its
    // exited member already queued is what this is about.
    let scope_dir = tempfile::tempdir().expect("a scope directory");
    engine.scope = crate::scope::cgroup(scope_dir.path()).expect("open scope directory");
    engine.retirement_intents.clear();
    child.kill().unwrap();
    child.wait().unwrap();

    // A loader record whose context is fine but whose address space is
    // gone: resolution reads `/proc/<pid>/maps` behind the retained pin.
    let mut session = ScriptedSession::with_records([], 1);
    apply_ordinary_batch(
        &mut engine,
        &mut session,
        vec![loader_record_for(context, pid)],
    )
    .expect("an ordinary batch carrying one unresolvable record");

    let skips = engine.counters.object_skips.clone();
    assert!(
        skips
            .iter()
            .all(|skip| skip.subject != "live discovery record"),
        "a generation the retained pin proves ended is not a lost one: {skips:?}"
    );
}

/// Task 9.2b defect E, first half. An `ExecRefresh` *keeps* its view: the
/// refresh rescans that same live generation. Queuing it for the
/// conservative retirement replay drops the view's pins, so the same
/// provider is re-pinned under a fresh `PinnedObjectId`, a second full slot
/// set is allocated for targets that already have one, and `additions
/// allowed` is cleared so the replacement never attaches — 136 slots for a
/// 68-entry table, and probes that count nothing.
#[test]
fn an_exec_refresh_never_queues_its_live_view_for_conservative_retirement() {
    let (mut engine, module, object, _) = engine_with_overlay(7);
    let pid = std::process::id();
    engine.scope = Scope::Pid(pid);
    engine
        .views
        .push(ProcessView::open(module.view, pid).unwrap());
    engine.next_view_id = module.view.0 + 1;
    engine
        .retirement_intents
        .insert(module.view, RetirementCause::ExecRefresh);
    assert_eq!(engine.plan.slots.len(), 1);
    engine
        .capture_facts
        .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
        .unwrap();
    let mut session = ScriptedSession::with_records([], 0);

    apply_ordinary_batch(&mut engine, &mut session, Vec::new())
        .expect("an ordinary retirement batch");

    assert!(
        engine
            .views
            .iter()
            .any(|retained| retained.id() == module.view),
        "an exec refresh keeps its process view"
    );
    assert!(
        engine.pinned.summary(object).is_some(),
        "a retained view keeps its pins; re-pinning the same object under a \
             fresh ID allocates a second slot set for targets that already have one"
    );
    assert_eq!(engine.plan.modules.len(), 1);
}

/// Task 9.2b defect E, second half, in the *capture* path this time.
/// `fix1` taught `queue_retirement` that the retained original pin, not
/// `still_the_same()`, decides whether a generation was lost or merely
/// ended. `refresh_inventory` asks a weaker question — whether an
/// `ExpectedRemoval` intent was already *recorded* — so a `run` child that
/// exits before its `LEADER_EXIT` record is drained fails the whole
/// capture with "the named process generation changed during capture".
#[test]
fn a_capture_refresh_ends_on_a_proven_exit_instead_of_failing() {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let pid = child.id();
    let view = ProcessView::open(ProcessViewId(0), pid).unwrap();
    let mut engine = Engine::empty();
    engine.scope = Scope::Pid(pid);
    engine.views.push(view);
    engine.next_view_id = 1;
    child.kill().unwrap();
    child.wait().unwrap();

    let mut session = ScriptedSession::with_records([], 0);
    let mut collect: Box<DiscoveryCollector<'_>> = Box::new(Engine::collect_discovery_records);
    let outcome = engine.refresh_inventory(
        &mut session,
        &mut true,
        &mut Vec::new(),
        &mut PendingViewRetirements::new(),
        &mut *collect,
        &mut PauseClosure::new(true),
    );

    assert!(
        outcome.is_ok(),
        "a proven exit ends the capture, it does not discard it: {:?}",
        outcome.err()
    );
    assert!(engine.expected_target_exit());
}

/// Real child, /proc reads, offline table acquisition, inventory reconciliation,
/// and publication. Only the BPF/link adapter is substituted. The child cannot
/// load or exit until the test acknowledges the preceding engine operation.
struct DiscoveryLifecycleFixture {
    _dir: tempfile::TempDir,
    provider: PathBuf,
    manifest: PathBuf,
    child: SystemScopeChildGuard,
    output: std::process::ChildStdout,
    pidfd: std::os::fd::OwnedFd,
}

// An explicit ignored entrypoint keeps the offline helper in a fresh exec image
// even when only `cargo test --lib` was built. It is not a separate passing test.
#[test]
#[ignore = "private manifest helper; invoked by DiscoveryLifecycleFixture"]
fn lifecycle_manifest_helper_entrypoint() {
    let provider = std::env::var_os("P11SCOPE_TEST_DISCOVERY_PROVIDER")
        .expect("the fixture supplies its owned provider");
    let output = std::env::var_os("P11SCOPE_TEST_DISCOVERY_MANIFEST")
        .expect("the fixture supplies its manifest output");
    let manifest = p11scope_discover::discover::discover(Path::new(&provider))
        .expect("the real offline helper acquires the fixture's table");
    std::fs::write(output, serde_json::to_vec(&manifest).unwrap()).unwrap();
}

impl DiscoveryLifecycleFixture {
    fn child_pidfd(child: &SystemScopeChildGuard) -> std::os::fd::OwnedFd {
        use std::os::fd::FromRawFd as _;

        // SAFETY: pidfd_open takes a live owned child's PID and flags zero,
        // returning a new descriptor owned exclusively by this fixture.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, child.pid(), 0) };
        assert!(
            descriptor >= 0,
            "retain child exit readiness: {}",
            std::io::Error::last_os_error()
        );
        unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptor as i32) }
    }

    fn acquire_manifest(provider: &Path, manifest: &Path, log: &Path) {
        use std::os::fd::AsRawFd as _;

        let output = std::fs::File::create(log).unwrap();
        let mut helper = SystemScopeChildGuard::new(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "discovery::engine::tests::lifecycle_manifest_helper_entrypoint",
                    "--ignored",
                    "--nocapture",
                ])
                .env_clear()
                .env("P11SCOPE_TEST_DISCOVERY_PROVIDER", provider)
                .env("P11SCOPE_TEST_DISCOVERY_MANIFEST", manifest)
                .stdin(std::process::Stdio::null())
                .stdout(output.try_clone().unwrap())
                .stderr(output)
                .spawn()
                .expect("exec an isolated offline manifest helper"),
        );
        let pidfd = Self::child_pidfd(&helper);
        assert!(
            system_scope_poll_fd(pidfd.as_raw_fd(), std::time::Duration::from_secs(60)).unwrap(),
            "manifest helper must finish within its owned-process deadline"
        );
        let status = helper.child.wait().expect("reap the exact manifest helper");
        helper.live = false;
        assert!(
            status.success(),
            "isolated manifest helper failed: {status}\n{}",
            std::fs::read_to_string(log).unwrap()
        );
    }

    fn start() -> Self {
        let dir = tempfile::tempdir().expect("a discovery lifecycle fixture directory");
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/discovery-lifecycle.c");
        let provider = dir.path().join("lifecycle-provider.so");
        let driver = dir.path().join("lifecycle-driver");
        for (output, extra) in [
            (
                &provider,
                &["-shared", "-fPIC", "-DDISCOVERY_LIFECYCLE_PROVIDER"][..],
            ),
            (&driver, &[][..]),
        ] {
            assert!(
                std::process::Command::new("gcc")
                    .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
                    .args(extra)
                    .arg(&source)
                    .arg("-o")
                    .arg(output)
                    .arg("-ldl")
                    .status()
                    .expect("compile the owned discovery fixture")
                    .success()
            );
        }
        let manifest = dir.path().join("provider.json");
        Self::acquire_manifest(
            &provider,
            &manifest,
            &dir.path().join("manifest-helper.log"),
        );

        let mut child = SystemScopeChildGuard::new(
            std::process::Command::new(&driver)
                .arg(&provider)
                .env_clear()
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the owned loader behind its pre-load barrier"),
        );
        let output = child.child.stdout.take().unwrap();
        let pidfd = Self::child_pidfd(&child);
        let mut fixture = Self {
            _dir: dir,
            provider,
            manifest,
            child,
            output,
            pidfd,
        };
        assert_eq!(
            fixture.read_ack(),
            format!("READY {}\n", fixture.child.pid())
        );
        fixture
    }

    fn read_ack(&mut self) -> String {
        use std::io::Read as _;
        use std::os::fd::AsRawFd as _;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut ack = Vec::new();
        while !ack.ends_with(b"\n") {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(
                !remaining.is_zero() && ack.len() < 256,
                "bounded fixture acknowledgement: {ack:?}"
            );
            assert!(system_scope_poll_fd(self.output.as_raw_fd(), remaining).unwrap());
            let mut byte = [0];
            assert_eq!(
                self.output.read(&mut byte).unwrap(),
                1,
                "fixture exited before acknowledgement: {ack:?}"
            );
            ack.push(byte[0]);
        }
        String::from_utf8(ack).unwrap()
    }

    fn discover_before_load(&self) -> Engine {
        let pid = self.child.pid();
        let mut args = system_args(vec![self.provider.clone()], None);
        args.scope = crate::cli::ScopeArg::Pid(pid);
        args.manifests = vec![self.manifest.clone()];
        let view = ProcessView::open(ProcessViewId(0), pid).expect("retain the owned generation");
        let engine = Engine::discover(&args, &Scope::Pid(pid), Some(view))
            .expect("manifest-backed discovery before dlopen");
        assert_eq!(engine.discovery.uncorroborated, 1);
        assert_eq!(engine.discovery.modules.len(), 1);
        assert!(!engine.discovery.modules[0].corroborated);
        assert_eq!(
            engine.discovery.modules[0].corroboration,
            ["uncorroborated"]
        );
        assert!(
            engine.modules.is_empty(),
            "the child has not mapped the provider"
        );
        engine
    }

    fn load(&mut self) {
        use std::os::unix::fs::MetadataExt as _;

        self.child
            .child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"L")
            .unwrap();
        let identity = std::fs::metadata(&self.provider).unwrap();
        assert_eq!(
            self.read_ack(),
            format!(
                "LOADED {} {} {} 68\n",
                self.child.pid(),
                identity.dev(),
                identity.ino()
            )
        );
    }

    fn exit_and_reap(&mut self) {
        use std::os::fd::AsRawFd as _;

        self.child
            .child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"X")
            .unwrap();
        assert!(
            system_scope_poll_fd(self.pidfd.as_raw_fd(), std::time::Duration::from_secs(10))
                .unwrap(),
            "owned fixture must exit after release"
        );
        let status = self.child.child.wait().expect("reap the exact owned child");
        self.child.live = false;
        assert!(status.success(), "fixture exit: {status}");
    }
}

/// Unlike the synthetic corroboration unit tests, these regressions acquire
/// their manifest and scanned table independently from a real shared object.
/// Calling refresh requests service; only accepted tables plus publication
/// establish agreement. No loader event or elapsed delay is an acknowledgement.
#[test]
fn lifecycle_completed_discovery_agreement_survives_real_child_exit() {
    let mut fixture = DiscoveryLifecycleFixture::start();
    let mut engine = fixture.discover_before_load();
    let generation = engine.views[0].id();
    fixture.load();
    engine.request_refresh(fixture.child.pid());
    refresh_inventory_once(&mut engine);
    engine.publish_current_capture_facts().unwrap();

    assert_eq!(engine.views.len(), 1);
    assert_eq!(engine.views[0].id(), generation);
    assert!(
        engine.views[0].still_the_same(),
        "agreement is acknowledged while the child is alive"
    );
    assert!(
        engine
            .modules
            .iter()
            .any(|module| module.scanned.view == generation
                && module
                    .scanned
                    .tables
                    .iter()
                    .any(|table| table.entries.len() == 68)),
        "a real complete table must have been acquired: {:?}",
        engine.modules
    );
    assert_eq!(engine.discovery.uncorroborated, 0, "{:?}", engine.discovery);
    assert_eq!(engine.discovery.conflicts, 0);
    assert_eq!(engine.discovery.modules.len(), 1);
    assert!(engine.discovery.modules[0].corroborated);
    assert_eq!(engine.discovery.modules[0].corroboration, ["agreed"]);
    let identity = (
        engine.discovery.modules[0].dev,
        engine.discovery.modules[0].ino,
        engine.discovery.modules[0].sha256.clone(),
    );

    fixture.exit_and_reap();
    refresh_inventory_once(&mut engine);
    engine.publish_current_capture_facts().unwrap();

    assert!(engine.expected_target_exit());
    assert!(engine.views.is_empty());
    assert!(
        engine.modules.is_empty(),
        "the live scan view really retired"
    );
    assert_eq!(engine.discovery.uncorroborated, 0, "{:?}", engine.discovery);
    assert_eq!(engine.discovery.conflicts, 0);
    assert_eq!(
        engine.discovery.modules.len(),
        1,
        "the historical provider survives retirement"
    );
    let module = &engine.discovery.modules[0];
    assert_eq!((module.dev, module.ino, module.sha256.clone()), identity);
    assert!(module.corroborated);
    assert_eq!(module.corroboration, ["agreed"]);
    assert!(engine.plan.skipped.is_empty(), "{:?}", engine.plan.skipped);
}

#[test]
fn lifecycle_exit_before_discovery_service_stays_explicitly_uncorroborated() {
    let mut fixture = DiscoveryLifecycleFixture::start();
    let mut engine = fixture.discover_before_load();
    fixture.load();
    engine.request_refresh(fixture.child.pid());
    // The workload did load and acquire its provider, but the observer has
    // deliberately not serviced the request when this exact generation exits.
    fixture.exit_and_reap();
    refresh_inventory_once(&mut engine);
    engine.publish_current_capture_facts().unwrap();

    assert!(engine.expected_target_exit());
    assert!(engine.views.is_empty());
    assert!(engine.modules.is_empty());
    assert_eq!(engine.discovery.uncorroborated, 1, "{:?}", engine.discovery);
    assert_eq!(engine.discovery.conflicts, 0);
    assert_eq!(engine.discovery.modules.len(), 1);
    assert!(!engine.discovery.modules[0].corroborated);
    assert_eq!(
        engine.discovery.modules[0].corroboration,
        ["uncorroborated"]
    );
    assert!(
        engine.plan.skipped.is_empty(),
        "a proven owned exit is not discovery loss: {:?}",
        engine.plan.skipped
    );
}

/// Other parallel tests legitimately keep a provider mapped after unlinking its
/// pathname. Manifest acquisition must not inspect that test worker's maps.
#[test]
fn lifecycle_manifest_acquisition_ignores_an_unrelated_deleted_mapping() {
    let unrelated = E07Provider::dlopen();
    std::fs::remove_file(&unrelated.path).unwrap();
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    assert!(
        maps.lines()
            .any(|line| line.contains(unrelated.path.to_str().unwrap())
                && line.ends_with(" (deleted)")),
        "the interfering mapping must actually remain present"
    );

    let fixture = DiscoveryLifecycleFixture::start();
    let manifest: Manifest =
        serde_json::from_slice(&std::fs::read(&fixture.manifest).unwrap()).unwrap();
    assert_eq!(manifest.module_path, fixture.provider.to_str().unwrap());
    assert!(
        manifest
            .provenance_objects
            .iter()
            .all(|object| object.path != unrelated.path.to_str().unwrap()),
        "a foreign test worker's mapping is not fixture provenance"
    );
}

/// Plan Task 8 Step 1 checkbox 8, deferred to Step 2 because it needs the
/// crate-private `DiscoveryItem`/record path: strategy, timing, and
/// capture counts deduplicate the exact internal
/// `{process generation, optional bound tuple}` once, while `hits` and
/// `state_read_failures` come only from their BPF counters and never from
/// received-record counts.
#[test]
fn loader_counts_deduplicate_one_context_and_take_hits_only_from_bpf_counters() {
    let view = ProcessViewId(3);
    let mut engine = Engine::empty();

    // Same context, recorded on every tick of a live capture: one context,
    // one strategy count, one timing count, one capture count.
    for _ in 0..5 {
        engine.record_loader_arm(view, true);
    }
    let aggregate = engine.loader_discovery();
    assert_eq!(aggregate.strategies.unavailable, 1);
    assert_eq!(aggregate.initial_set_timing.none, 1);
    assert_eq!(aggregate.initial_set_capture.none, 1);
    assert_eq!(aggregate.initial_set_capture.eligible, 0);
    assert_eq!(aggregate.dlopen_timing, render::LoaderTiming::default());

    // A second exact process generation is a second context.
    engine.record_loader_arm(ProcessViewId(4), false);
    let aggregate = engine.loader_discovery();
    assert_eq!(aggregate.strategies.unavailable, 2);
    assert_eq!(aggregate.dlopen_timing.none, 1);
    assert_eq!(
        aggregate.initial_set_capture.none, 1,
        "an ordinary dlopen context is not a second initial-set capture"
    );

    // Records are not counts. Dispatching loader records moves neither
    // `hits` nor `state_read_failures`; only the BPF producer counters do.
    engine.loader_records_accepted = 9;
    assert_eq!(engine.loader_discovery().hits, 0);
    assert_eq!(engine.loader_discovery().state_read_failures, 0);
    engine.counter_snapshot.loader_hits = 7;
    engine.counter_snapshot.loader_state_read_failures = 2;
    let aggregate = engine.loader_discovery();
    assert_eq!(aggregate.hits, 7);
    assert_eq!(aggregate.state_read_failures, 2);
    assert_eq!(
        aggregate.strategies.unavailable, 2,
        "a producer counter is not a classification"
    );

    // `capture_facts()` publishes the BPF-owned discovery losses verbatim
    // and derives the truncation accumulator, never a second copy of the
    // loader state-read counter.
    engine.counter_snapshot.ring_loss = 4;
    engine.counter_snapshot.export_state_failures = 5;
    engine.counter_snapshot.export_bounded_read_failures = 6;
    engine.discovery_truncated = 1;
    engine.malformed_discovery = 2;
    let facts = engine.capture_facts();
    assert_eq!(facts.discovery_losses(), [4, 5, 6, 3]);
    assert_eq!(
        facts.attach_gap_ms(),
        None,
        "an unmeasured gap is never zero"
    );
}

#[test]
fn loader_counts_deduplicate_replaced_context_by_stable_bound_tuple() {
    use p11scope_manifest::elf::SymbolFact;

    let view = ProcessViewId(5);
    let module = overlay_module(overlay_key(105));
    let pins = overlay_pins(&[(module.key, OVERLAY_SHA, 1)]);
    let loader = pins
        .id_for_scanned(&module, module.key, &module.path)
        .unwrap();
    let mut engine = Engine::empty();
    engine.pinned = pins;
    let spec = LoaderContextSpec {
        view,
        loader,
        mapping: Some(MapEntry {
            start: 0x4000,
            end: 0x5000,
            file_offset: 0x2000,
            permissions: *b"r-xp",
            device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
            inode: 7,
            raw_path: Some(b"/lib/ld.so".to_vec()),
        }),
        hook: SymbolFact {
            virtual_address: 0x2100,
            file_offset: 0x2100,
        },
        state_address: None,
    };

    let first = engine.loader_registry.preflight(spec.clone()).unwrap();
    let first = engine.loader_registry.prepare(first).unwrap();
    engine.loader_registry.mark_attached(first).unwrap();
    engine.record_loader_arm(view, false);
    engine.loader_registry.tombstone(first).unwrap();
    engine.loader_registry.remove(first).unwrap();

    let replacement = engine.loader_registry.preflight(spec.clone()).unwrap();
    let replacement = engine.loader_registry.prepare(replacement).unwrap();
    engine.loader_registry.mark_attached(replacement).unwrap();
    engine.record_loader_arm(view, false);

    let aggregate = engine.loader_discovery();
    assert_eq!(aggregate.strategies.debug_state_every_hit, 1);
    assert_eq!(aggregate.dlopen_timing.unproven, 1);
    assert_eq!(
        aggregate.initial_set_timing,
        render::LoaderTiming::default()
    );
    assert_eq!(
        aggregate.initial_set_capture,
        render::InitialSetCapture::default()
    );

    engine.loader_registry.tombstone(replacement).unwrap();
    engine.loader_registry.remove(replacement).unwrap();
    let initial_set = engine.loader_registry.preflight(spec).unwrap();
    let initial_set = engine.loader_registry.prepare(initial_set).unwrap();
    engine.loader_registry.mark_attached(initial_set).unwrap();
    engine.record_loader_arm(view, true);

    let aggregate = engine.loader_discovery();
    assert_eq!(aggregate.strategies.debug_state_every_hit, 2);
    assert_eq!(aggregate.dlopen_timing.unproven, 1);
    assert_eq!(aggregate.initial_set_timing.unproven, 1);
    assert_eq!(aggregate.initial_set_capture.none, 1);
}

#[test]
fn loader_counts_distinguish_unbound_and_unkeyed_contexts() {
    use p11scope_manifest::elf::SymbolFact;

    let view = ProcessViewId(6);
    let mut engine = Engine::empty();
    engine.record_loader_arm(view, false);
    let spec = LoaderContextSpec {
        view,
        loader: PinnedObjectId(9),
        mapping: Some(MapEntry {
            start: 0x4000,
            end: 0x5000,
            file_offset: 0x2000,
            permissions: *b"r-xp",
            device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
            inode: 7,
            raw_path: Some(b"/lib/ld.so".to_vec()),
        }),
        hook: SymbolFact {
            virtual_address: 0x2100,
            file_offset: 0x2100,
        },
        state_address: None,
    };
    let first = engine.loader_registry.preflight(spec.clone()).unwrap();
    let first = engine.loader_registry.prepare(first).unwrap();
    engine.loader_registry.mark_attached(first).unwrap();
    engine.record_loader_arm(view, false);
    engine.record_loader_arm(view, false);

    let aggregate = engine.loader_discovery();
    assert_eq!(aggregate.strategies.unavailable, 1);
    assert_eq!(aggregate.strategies.debug_state_every_hit, 1);
    assert_eq!(aggregate.dlopen_timing.unproven, 1);
    assert_eq!(engine.counters.object_skips.len(), 1);
    assert_eq!(
        render::capture_skipped_out(&engine.counters.object_skips[0]).reason,
        "discovery unavailable"
    );

    engine.loader_registry.tombstone(first).unwrap();
    engine.loader_registry.remove(first).unwrap();
    let replacement = engine.loader_registry.preflight(spec).unwrap();
    let replacement = engine.loader_registry.prepare(replacement).unwrap();
    engine.loader_registry.mark_attached(replacement).unwrap();
    engine.record_loader_arm(view, false);

    let aggregate = engine.loader_discovery();
    assert_eq!(aggregate.strategies.unavailable, 1);
    assert_eq!(aggregate.strategies.debug_state_every_hit, 2);
    assert_eq!(aggregate.dlopen_timing.unproven, 2);
    assert_eq!(engine.counters.object_skips.len(), 1);
}

/// Plan Task 8 Step 2: a named target's expected exit is what ends the
/// capture the ordinary way, with no interrupt and no `--duration`. A
/// cgroup capture never reaches that state when one member exits — it
/// stops only by its normal capture policy — and the asymmetry lives in
/// exactly one place: only `Scope::Pid` arms the pending marker.
#[test]
fn only_a_named_targets_expected_exit_finishes_the_capture() {
    let view = ProcessViewId(21);

    let mut named = Engine::empty();
    named.scope = Scope::Pid(1);
    assert!(!named.expected_target_exit(), "nothing has exited yet");
    named.arm_expected_target_exit(view);
    named.finalize_expected_target_exit();
    assert!(
        named.expected_target_exit(),
        "a named target's expected exit must end the capture"
    );

    let mut cgroup = Engine::empty();
    let cgroup_dir = tempfile::tempdir().expect("a scope directory");
    cgroup.scope = crate::scope::cgroup(cgroup_dir.path()).expect("open scope directory");
    cgroup.arm_expected_target_exit(view);
    cgroup.finalize_expected_target_exit();
    assert!(
        !cgroup.expected_target_exit(),
        "one cgroup member exiting must not end a cgroup capture"
    );
}

#[test]
fn expected_target_exit_completes_only_after_conservative_cleanup() {
    let view = ProcessViewId(17);
    let mut engine = Engine::empty();
    engine.scope = Scope::Pid(1);
    engine.expected_target_exit_pending = Some(view);
    engine.pending_retirements.insert(view);

    engine.finalize_expected_target_exit();
    assert!(!engine.expected_target_exit);
    assert_eq!(engine.expected_target_exit_pending, Some(view));

    engine.pending_retirements.clear();
    let owner = LoaderContextId::from_case_id(1);
    let journal = TerminalJournal {
        owner,
        dispatch_started: false,
        retry_used: false,
    };
    let batch = TerminalBatch::empty(TerminalAuthority {
        owner,
        exports: Vec::new(),
    });

    // Every terminal-journal state blocks finalization on its own: an
    // undispatched batch, a started journal with no batch, and both.
    for (pending_journal, pending_batch) in [
        (Some(journal), None),
        (
            None,
            Some(TerminalBatch::empty(TerminalAuthority {
                owner,
                exports: Vec::new(),
            })),
        ),
        (Some(journal), Some(batch)),
        (
            Some(TerminalJournal {
                dispatch_started: true,
                ..journal
            }),
            None,
        ),
    ] {
        engine.terminal_journal = pending_journal;
        engine.terminal_batch = pending_batch;
        engine.finalize_expected_target_exit();
        assert!(
            !engine.expected_target_exit,
            "a pending terminal lifecycle state cannot prove expected exit"
        );
        assert_eq!(engine.expected_target_exit_pending, Some(view));
    }

    engine.terminal_batch = None;
    engine.terminal_journal = None;
    engine.finalize_expected_target_exit();
    assert!(engine.expected_target_exit);
    assert_eq!(engine.expected_target_exit_pending, None);
}

/// The tombstoned registry context a real terminal drain leaves behind is
/// carried through detach and return: finalization stays blocked until the
/// continuation removes it.
#[test]
fn a_real_terminal_drain_blocks_expected_exit_until_its_journal_clears() {
    let pid = std::process::id();
    let (mut engine, owner) = Engine::retiring_loader_context(pid);
    let view = engine.views[0].id();
    let mut session = ScriptedSession::with_records([], 16);
    session.detach_exports = vec![terminal_export()];
    start_failed_terminal_drain(&mut engine, &mut session, owner);

    let retained = std::mem::take(&mut engine.views);
    let intents = std::mem::take(&mut engine.retirement_intents);
    engine.expected_target_exit_pending = Some(view);
    engine.finalize_expected_target_exit();

    assert!(
        !engine.expected_target_exit,
        "a tombstoned context with an undispatched batch is not a clean exit"
    );
    assert_eq!(
        engine.loader_context_state_for_test(owner),
        Some("tombstoned")
    );

    engine.views = retained;
    engine.retirement_intents = intents;
    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

    assert!(engine.terminal_journal.is_none());
    assert!(engine.loader_registry.context(owner).is_none());
    engine.views.clear();
    engine.retirement_intents.clear();
    engine.pending_retirements.clear();
    engine.finalize_expected_target_exit();
    assert!(engine.expected_target_exit);
}

#[test]
fn delayed_pre_admission_exec_cannot_refresh_a_reused_pid() {
    let view = ProcessView::open(ProcessViewId(16), std::process::id()).unwrap();
    let mut delayed: DiscoveryRecord = unsafe { std::mem::zeroed() };
    delayed.kind = DISCOVERY_KIND_EXEC;
    delayed.pid_tgid = u64::from(view.pid()) << 32;
    delayed.hook_ts_ns = view.admitted_ns().saturating_sub(1);
    let mut engine = Engine::empty();
    engine.views.push(view);
    let mut pending = PendingViewRetirements::new();

    engine.dispatch_lifecycle_record(&delayed, &mut pending);

    assert!(pending.is_empty());
    assert!(!engine.refresh_requested.contains(&std::process::id()));
}

#[test]
fn only_complete_cgroup_enumeration_authorizes_absence() {
    assert_eq!(
        inventory_retirement_cause(true, true, false, false),
        Some((RetirementCause::ExpectedRemoval, true))
    );
    assert_eq!(
        inventory_retirement_cause(false, true, false, false),
        Some((RetirementCause::ExpectedRemoval, true)),
        "authoritative absence proves clean departure even after the process exited"
    );
    assert_eq!(
        inventory_retirement_cause(true, false, false, false),
        None,
        "unreadable or truncated membership cannot prove departure"
    );
    assert_eq!(
        inventory_retirement_cause(false, false, false, false),
        Some((RetirementCause::GenerationLost, false)),
        "an independently stale retained pin remains genuine loss"
    );
    assert_eq!(
        inventory_retirement_cause(true, false, true, true),
        Some((RetirementCause::ExecRefresh, false))
    );
}

#[test]
fn cgroup_departure_is_journaled_before_fallible_retirement() {
    let view = ProcessView::open(ProcessViewId(20), std::process::id()).unwrap();
    let mut engine = Engine::empty();
    engine.views.push(view);
    let retirement_views = [ProcessViewId(20)].into_iter().collect();
    let departed = [ProcessViewId(20)].into_iter().collect();
    let mut pending = PendingViewRetirements::new();

    engine.queue_inventory_retirements(
        &retirement_views,
        &BTreeSet::new(),
        &departed,
        &mut pending,
    );

    assert_eq!(
        engine.retirement_intents.get(&ProcessViewId(20)),
        Some(&RetirementCause::ExpectedRemoval)
    );
    assert!(engine.ready_expected_removals.contains(&ProcessViewId(20)));
    assert!(!engine.refresh_requested.contains(&std::process::id()));
    pending.clear();
    assert_eq!(
        engine.retirement_intents.get(&ProcessViewId(20)),
        Some(&RetirementCause::ExpectedRemoval),
        "an unconsumed drain retry keeps the selected exact view"
    );

    let source = include_str!("engine.rs");
    let refresh = source
        .split_once("    fn refresh_inventory(")
        .unwrap()
        .1
        .split_once("    /// Drains private discovery records")
        .unwrap()
        .0;
    assert!(
        refresh.find("self.queue_inventory_retirements(").unwrap()
            < refresh.find("self.retire_loader_contexts(").unwrap()
    );
}

#[test]
fn cgroup_walk_does_not_silently_drop_directory_entry_errors() {
    let source = include_str!("engine.rs");
    let walk = source
        .split_once("fn scope_pids(")
        .unwrap()
        .1
        .split_once("fn scope_label(")
        .unwrap()
        .0;

    assert!(!walk.contains("entries.flatten()"));
    assert!(!walk.contains("file_type().is_ok_and"));
    assert!(walk.contains("membership absence is not authoritative"));
}

#[test]
fn retirement_intent_is_persistent_and_generation_loss_is_sticky() {
    let view = ProcessView::open(ProcessViewId(15), std::process::id()).unwrap();
    let mut engine = lifecycle_discovered(vec![view]);
    let mut pending = PendingViewRetirements::new();

    engine.queue_retirement(
        ProcessViewId(15),
        RetirementCause::ExecRefresh,
        &mut pending,
    );
    engine.queue_retirement(
        ProcessViewId(15),
        RetirementCause::ExpectedRemoval,
        &mut pending,
    );
    engine.queue_retirement(
        ProcessViewId(15),
        RetirementCause::GenerationLost,
        &mut pending,
    );

    assert_eq!(
        engine.retirement_intents.get(&ProcessViewId(15)),
        Some(&RetirementCause::GenerationLost)
    );
    assert_eq!(
        pending.get(&ProcessViewId(15)),
        Some(&RetirementCause::GenerationLost)
    );
    assert!(engine.refresh_requested.contains(&std::process::id()));
    assert_eq!(
        engine
            .counters
            .object_skips
            .iter()
            .filter(|skip| skip.subject == "live discovery generation")
            .count(),
        1,
        "the sticky loss is published once"
    );
}

#[test]
fn expected_exit_waits_for_the_original_process_pin() {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let view = ProcessView::open(ProcessViewId(16), child.id()).unwrap();
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_LEADER_EXIT;
    record.pid_tgid = u64::from(child.id()) << 32;
    record.hook_ts_ns = view.admitted_ns();
    let mut engine = Engine::empty();
    engine.views.push(view);
    let mut pending = PendingViewRetirements::new();
    engine.dispatch_lifecycle_record(&record, &mut pending);

    assert!(
        pending.is_empty(),
        "leader exit awaits generation settlement"
    );
    assert!(
        engine
            .pending_leader_exit_views
            .contains(&ProcessViewId(16))
    );
    assert_eq!(engine.task_uprobe_link_losses, 0);

    child.kill().unwrap();
    child.wait().unwrap();
    let mut additions_allowed = true;
    let mut closure = PauseClosure::new(true);
    let assessments = engine.pending_leader_exit_views.clone();
    engine.settle_leader_exit_assessments(
        &assessments,
        &mut pending,
        &mut additions_allowed,
        &mut closure,
    );
    assert_eq!(
        pending.get(&ProcessViewId(16)),
        Some(&RetirementCause::ExpectedRemoval)
    );
    assert_eq!(engine.task_uprobe_link_losses, 0);
    assert!(retirement_ready(RetirementCause::ExpectedRemoval, &engine.views[0]).unwrap());
}

#[test]
fn apply_outcome_keeps_static_timing_and_generation_loss_ownership() {
    let completed = timing_key(0);
    let failed = timing_key(1);
    let stale = ProcessViewId(9);
    let mut engine = Engine::empty();
    engine.timings.observe(&completed, 10);
    engine.timings.observe(&failed, 10);
    let outcome = ApplyOutcome {
        disposition: ApplyDisposition::Accepted,
        changed: true,
        stale_views: [stale].into_iter().collect(),
        missing_contexts: Vec::new(),
        static_completions: vec![([completed.clone()].into_iter().collect(), Some(20))],
        static_failures: [failed.clone()].into_iter().collect(),
        newly_rejected_keys: BTreeSet::new(),
        selection_authorized: false,
        unpublished_views: BTreeSet::new(),
    };

    engine.record_apply_timing(&outcome);

    assert_eq!(engine.timings.gap_ns(&completed), Some(10));
    assert_eq!(engine.timings.gap_ns(&failed), None);
    assert_eq!(outcome.stale_views, [stale].into_iter().collect());
    assert!(outcome.accepted() && outcome.changed);
}

/// One provider module over a real file-backed mapping of `view`. The
/// table is synthetic; the identity, the pin, and the process view are all
/// real, which is what the transaction path is about.
fn provider_module(
    view: &ProcessView,
    mapping: &MapEntry,
    path: &Path,
    offset: u64,
) -> ScannedModule {
    let mut module = mapped_object(view, mapping, path);
    module.decoder_abi = Some(ElfAbi::Lp64);
    module.exports = vec!["C_GetFunctionList".into()];
    module.tables = vec![ScannedTable {
        version: (2, 40),
        walk: "full",
        entries: vec![ScannedEntry {
            name: "C_Initialize",
            object: module.key,
            object_path: module.path.clone(),
            file_offset: offset,
        }],
        null_entries: vec![],
        unpinned: vec![],
        address: 0x7000,
        file_offset: Some(0),
        live_return: false,
        manifest_supported: false,
    }];
    module
}

struct LoadedSeedProvider {
    child: std::process::Child,
    peers: Vec<std::process::Child>,
    _dir: tempfile::TempDir,
}

impl Drop for LoadedSeedProvider {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for peer in &mut self.peers {
            let _ = peer.kill();
            let _ = peer.wait();
        }
    }
}

impl LoadedSeedProvider {
    fn spawn_peer(&mut self) -> u32 {
        let child = std::process::Command::new(self._dir.path().join("seed-runner"))
            .arg(self._dir.path().join("seed-provider.so"))
            .spawn()
            .unwrap();
        let pid = child.id();
        self.peers.push(child);
        pid
    }
}

fn loaded_seed_provider() -> (
    LoadedSeedProvider,
    ProcessView,
    ScannedModule,
    PinnedObjects,
) {
    let dir = tempfile::tempdir().unwrap();
    let library = dir.path().join("seed-provider.so");
    let source = dir.path().join("seed-provider.c");
    let runner_source = dir.path().join("seed-runner.c");
    let runner = dir.path().join("seed-runner");
    std::fs::write(
        &source,
        r#"
#include <stddef.h>
__attribute__((visibility("default"), noinline))
int C_GetFunctionList(void **out) {
    if (out != NULL) *out = NULL;
    return 0;
}
__attribute__((visibility("default"), noinline))
int C_GetInterfaceList(void *out, unsigned long *count) {
    if (out != NULL) *(void **)out = NULL;
    if (count != NULL) *count = 0;
    return 0;
}
__attribute__((visibility("default"), noinline))
int C_GetInterface(const char *name, void *version, void **out, unsigned long flags) {
    (void)name;
    (void)version;
    (void)flags;
    if (out != NULL) *out = NULL;
    return 0;
}
"#,
    )
    .unwrap();
    assert!(
        std::process::Command::new("gcc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&library)
            .arg(&source)
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(
        &runner_source,
        r#"
#include <dlfcn.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) return 3;
    sleep(30);
    dlclose(handle);
    return 0;
}
"#,
    )
    .unwrap();
    assert!(
        std::process::Command::new("gcc")
            .args(["-o"])
            .arg(&runner)
            .arg(&runner_source)
            .arg("-ldl")
            .status()
            .unwrap()
            .success()
    );
    let child = std::process::Command::new(&runner)
        .arg(&library)
        .spawn()
        .unwrap();
    let fixture = LoadedSeedProvider {
        child,
        peers: Vec::new(),
        _dir: dir,
    };
    let view = ProcessView::open(ProcessViewId(0), fixture.child.id()).unwrap();
    let mut mapped = None;
    for _ in 0..200 {
        let maps =
            parse_maps(&std::fs::read(format!("/proc/{}/maps", fixture.child.id())).unwrap())
                .unwrap();
        let map_index = MapIndex::new(&maps).expect("the loaded child maps snapshot is valid");
        mapped = maps
            .iter()
            .find_map(|mapping| match map_index.resolve(mapping.start) {
                Resolved::File {
                    path: MappedPath::Usable(path),
                    ..
                } if path == library => Some((mapping.clone(), path)),
                _ => None,
            });
        if mapped.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let (mapping, mapped_path) = mapped.expect("the loaded seed provider is mapped");
    let mut module = mapped_object(&view, &mapping, &mapped_path);
    module.exports = vec!["C_GetFunctionList".into()];
    let pins = pin_test_module(&view, &module);
    (fixture, view, module, pins)
}

fn initial_export_route() -> (LoadedSeedProvider, Engine, ScriptedSession) {
    let (fixture, view, mut module, pins) = loaded_seed_provider();
    let pid = view.pid();
    module.exports = vec![
        "C_GetFunctionList".into(),
        "C_GetInterfaceList".into(),
        "C_GetInterface".into(),
    ];
    let mut engine = Engine::empty();
    engine.scope = Scope::Pid(pid);
    engine.next_view_id = 1;
    engine.views.push(view);
    let candidate = engine
        .live_candidate(pins, vec![module], Vec::new())
        .unwrap();
    let mut session = ScriptedSession::default();
    let mut additions_allowed = true;
    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions_allowed, false, &[])
        .unwrap();
    assert!(outcome.accepted());
    engine
        .arm_loader_or_partial(
            0,
            &mut session,
            &mut additions_allowed,
            &mut PendingViewRetirements::new(),
        )
        .unwrap();
    assert!(additions_allowed);
    (fixture, engine, session)
}

fn attached_selection_route() -> (
    LoadedSeedProvider,
    Engine,
    ScriptedSession,
    SelectionBindingFact,
) {
    let (fixture, mut engine, mut session) = initial_export_route();
    session.dynamic_attach_reports_added = true;
    engine.attach_initial_exports(
        &mut session,
        &mut true,
        &mut PendingViewRetirements::new(),
        &mut PauseClosure::new(true),
    );
    let binding = *engine.selection_bindings.values().next().unwrap();
    (fixture, engine, session, binding)
}

pub(crate) fn selection_output_engines() -> (Engine, Engine) {
    let (_fixture, mut clean, _session, binding) = attached_selection_route();
    clean
        .selection_bindings
        .get_mut(&binding.id)
        .unwrap()
        .coverage = SelectionCoverageState::OwnedClosed(NonZeroU64::new(1).unwrap());
    let (_fixture, mut truncated, _session, binding) = attached_selection_route();
    for flags in 0..=MAX_LIVE_SELECTION_TUPLES {
        truncated.capture_facts.record_selection(
            LiveSelectionTuple {
                module: binding.provider,
                request: SelectionRequest {
                    name: SelectionNameClass::Null,
                    version: SelectionVersionClass::Null,
                    flags: flags as u64,
                },
                rv: 1,
                result: None,
                inventory_matches: vec![],
                authority: SelectionAuthority::None,
                count: 1,
            },
            false,
        );
    }
    (clean, truncated)
}

fn selection_only_table(
    engine: &Engine,
    binding: SelectionBindingFact,
    table_file_offset: u64,
    entries: &[(&'static str, u64)],
    null_entries: Vec<&'static str>,
) -> ScannedTable {
    let summary = engine.pinned.summary(binding.object).unwrap();
    let path = engine
        .modules
        .iter()
        .find(|module| module.object == binding.object)
        .unwrap()
        .scanned
        .path
        .clone();
    ScannedTable {
        version: (3, 0),
        walk: "full",
        entries: entries
            .iter()
            .map(|(name, file_offset)| ScannedEntry {
                name,
                object: summary.key,
                object_path: path.clone(),
                file_offset: *file_offset,
            })
            .collect(),
        null_entries,
        unpinned: Vec::new(),
        address: 0,
        file_offset: Some(table_file_offset),
        live_return: false,
        manifest_supported: false,
    }
}

fn manifest_selection_evidence(
    version: Version,
    resolved: &[(&str, u64)],
) -> p11scope_manifest::manifest::SelectionEvidence {
    use p11scope_manifest::manifest::{
        SelectionAcquisition, SelectionAuthority, SelectionEvidence, SelectionNameClass,
        SelectionQuery, SelectionRequest, SelectionTable, SelectionVersionClass,
    };

    let functions = pkcs11_module::FUNCTION_LIST_FIELDS
        .iter()
        .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
        .chain(
            (version.minor == 2)
                .then_some(pkcs11_module::FUNCTION_LIST_3_2_EXTRA_FIELDS)
                .into_iter()
                .flatten(),
        )
        .map(|field| FunctionRecord {
            name: field.name.into(),
            resolution: resolved
                .iter()
                .find(|(name, _)| *name == field.name)
                .map_or(Resolution::NullPointer, |(_, file_offset)| {
                    Resolution::Resolved {
                        object: 0,
                        file_offset: *file_offset,
                    }
                }),
        })
        .collect();
    let mut queries = Vec::new();
    for selector in 0..5 {
        for flags in 0..=1 {
            let (name, result_version) = match selector {
                0 => (SelectionNameClass::Null, SelectionVersionClass::Null),
                1 => (
                    SelectionNameClass::ExactStandard,
                    SelectionVersionClass::Null,
                ),
                2 => (
                    SelectionNameClass::ExactStandard,
                    SelectionVersionClass::V3_0,
                ),
                3 => (
                    SelectionNameClass::ExactStandard,
                    SelectionVersionClass::V3_1,
                ),
                _ => (
                    SelectionNameClass::ExactStandard,
                    SelectionVersionClass::V3_2,
                ),
            };
            let request = SelectionRequest {
                name,
                version: result_version,
                flags,
            };
            queries.push(
                if selector == version.minor.saturating_add(2) && flags == 0 {
                    SelectionQuery {
                        selector,
                        request,
                        rv: 0,
                        result: Some(request),
                        inventory_matches: Vec::new(),
                        selection_table: Some(0),
                        authority: SelectionAuthority::SelectionCountOnly,
                        helper_failure: None,
                    }
                } else {
                    SelectionQuery {
                        selector,
                        request,
                        rv: 1,
                        result: None,
                        inventory_matches: Vec::new(),
                        selection_table: None,
                        authority: SelectionAuthority::None,
                        helper_failure: None,
                    }
                },
            );
        }
    }
    SelectionEvidence {
        acquisition: SelectionAcquisition::Queried,
        queries,
        tables: vec![SelectionTable {
            id: 0,
            version,
            walk: WalkOutcome::Full,
            functions,
            semantic_authorized: false,
        }],
        selection_truncated: false,
    }
}

fn evidence_verdict(
    plan: &plan::AttachPlan,
    pinned: &PinnedObjects,
    counters: &DiscoveryCounters,
) -> render::Evidence {
    let mut evidence = render::Evidence {
        table_entries: plan.entries_seen,
        slots: plan.slots.len(),
        active_slots: plan
            .slots
            .iter()
            .filter(|slot| plan.is_active(slot.index))
            .count(),
        attached_probes: 0,
        attach_failures: Vec::new(),
        aliased: plan
            .slots
            .iter()
            .filter(|slot| slot.aliased)
            .map(|slot| slot.names.clone())
            .collect(),
        skipped: plan
            .skipped
            .iter()
            .map(render::capture_skipped_out)
            .collect(),
        semantic_unverified_slots: plan
            .slots
            .iter()
            .filter(|slot| !slot.semantic_authorized)
            .count(),
        in_flight_at_end: 0,
        surfaces: plan.surfaces.clone(),
        vendor_interfaces: plan.vendor_interfaces,
        interface_list: plan.interface_list.clone(),
        event_loss: 0,
        start_insert_failures: 0,
        unmatched_returns: 0,
        rv_update_failures: 0,
        abi_refusals: 0,
        cgroup_scope_failures: 0,
        semantic_capture_failures: 0,
        unregistered_mechanisms: 0,
        template_tail_failures: 0,
        process_tracking_fallbacks: 0,
        process_tracking_failures: 0,
        process_tracking_evictions: 0,
        state_reconciliations: 0,
        session_cancel_ambiguities: 0,
        session_cancel_unknown_flags: 0,
        operation_state_imports: 0,
        auth_state_ambiguities: 0,
        async_target_failures: 0,
        async_orphans: 0,
        async_duplicates: 0,
        async_evictions: 0,
        fork_state_ambiguities: 0,
        semantic_state_drops: 0,
        semantic_history_drops: 0,
        pending_at_end: 0,
        malformed_records: 0,
        orphan_ops: 0,
        unmatched_closes: 0,
        shape_decode_failures: 0,
        shape_decode_total_failures: 0,
        templates_truncated: false,
        attach_gap_ms: None,
        pause: "none",
        pause_attempts: 0,
        pause_confirmed: 0,
        pause_partial: 0,
        child_still_running: None,
        discovery_ring_loss: 0,
        discovery_state_failures: 0,
        discovery_read_failures: 0,
        discovery_truncated: 0,
        task_uprobe_link_losses: 0,
        loader_discovery: render::LoaderDiscovery::default(),
        interface_selection: render::InterfaceSelection::default(),
        attach_mechanisms: vec![],
        pid_descendant_gaps: 0,
        multi_rebuild_gaps: 0,
        unprotected_live_windows: 0,
        module_unresolved_slots: 0,
        provider_changed: false,
        discovery: discovery_evidence(plan, pinned, counters),
        scheduling: render::SchedulingEvidence::default(),
        drain_proven: false,
        verdict_detail: render::VERDICT_CONCRETE_GAP,
        uretprobe_override: None,
        handoff_child_pid: None,
        p11scope_env: vec![],
        completeness: "UNKNOWN",
    };
    evidence.verdict();
    evidence
}

/// U-14 (owner decision 2026-09-23): churn from provider restarts must not
/// hide the currently-attached count behind the ever-growing allocation
/// count. `slots` keeps counting every endpoint the capture ever allocated,
/// retired ones included — the append-only plan never reuses a slot within a
/// capture — while `active_slots` must report only what the plan still has
/// attached when the report is written, mirroring `plan.is_active`.
#[test]
fn capture_facts_reports_active_slots_separately_from_churned_allocations() {
    let mut engine = Engine::empty();
    // Generation 1: a provider with three probed endpoints.
    engine.plan = plan_with(3, 0);
    // It exits: nothing pins its object any longer, so `retire_unpinned_targets`
    // retires its three slots — they stay allocated, per the append-only plan.
    engine
        .plan
        .retire_unpinned_targets(&PinnedObjects::empty(), 0);
    assert!(
        (0..3).all(|slot| !engine.plan.is_active(slot)),
        "generation 1's slots must retire, not disappear"
    );

    // Generation 2 replaces it: two fresh endpoints at new indices, never
    // reusing the three retired ones.
    for offset in 0..2u64 {
        let index = engine.plan.slots.len() as u32;
        engine.plan.slots.push(plan::Slot {
            index,
            descriptor_index: 0,
            object: PinnedObjectId(43),
            object_path: "/opt/p11-v2.so".into(),
            file_offset: offset * 8,
            names: vec!["C_Sign".into()],
            aliased: false,
            semantics: p11scope_ebpf_common::SlotSemantics::COUNT_ONLY,
            semantic_authorized: true,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![plan::ModuleId(1)],
        });
    }

    let facts = engine.capture_facts();
    assert_eq!(
        facts.slots, 5,
        "allocated slots must include generation 1's three retired endpoints"
    );
    assert_eq!(
        facts.active_slots, 2,
        "active_slots must count only generation 2's still-attached endpoints"
    );
}

#[test]
fn manifest_selection_tables_enter_the_attach_transaction() {
    let (_fixture, view, mut module, mut pins) = loaded_seed_provider();
    let provider = pins.pinned().next().unwrap();
    let path = provider.path.to_string();
    let base = object_facts(Path::new(&path)).2;
    module.tables.push(ScannedTable {
        version: (2, 40),
        walk: "full",
        entries: vec![ScannedEntry {
            name: "C_Initialize",
            object: provider.key,
            object_path: path.clone(),
            file_offset: base,
        }],
        null_entries: Vec::new(),
        unpinned: Vec::new(),
        address: 0,
        file_offset: Some(base),
        live_return: false,
        manifest_supported: false,
    });

    let mut manifest = valid_manifest_for(&[PathBuf::from(&path)], &[0; 67]);
    for (index, function) in manifest.surfaces[0].functions.iter_mut().enumerate() {
        function.resolution = Resolution::Resolved {
            object: 0,
            file_offset: base + index as u64,
        };
    }
    let manifest_pins = pin_manifest_objects(&manifest).unwrap();
    assert!(pins.absorb(manifest_pins).is_empty());

    let mut engine = Engine::empty();
    engine.scope = Scope::Pid(view.pid());
    engine.next_view_id = 1;
    engine.views.push(view);
    engine.manifests.push(manifest.clone());
    engine.manifest_ordinals.push(0);
    let mut session = ScriptedSession::default();
    let initial = engine
        .live_candidate(pins, vec![module.clone()], Vec::new())
        .unwrap();
    engine
        .apply_candidate(&mut session, initial, &mut true, false, &[])
        .unwrap();
    let shared_inventory = base + 10;
    let inventory = engine
        .plan
        .slots
        .iter_mut()
        .find(|slot| slot.file_offset == shared_inventory)
        .unwrap();
    assert_ne!(inventory.index, 0);
    inventory.descriptor_index = 0;
    inventory.semantics = p11scope_ebpf_common::SlotSemantics::COUNT_ONLY;
    let inventory = inventory.clone();
    let inventory_tables = engine.plan.modules[0].tables.clone();
    let extra = base + 80;
    let removed_inventory = base + 1;
    manifest.surfaces[0]
        .functions
        .iter_mut()
        .find(|function| {
            matches!(
                function.resolution,
                Resolution::Resolved { file_offset, .. } if file_offset == removed_inventory
            )
        })
        .unwrap()
        .resolution = Resolution::NullPointer;

    let mut selection = manifest_selection_evidence(
        Version { major: 3, minor: 0 },
        &[
            ("C_Finalize", shared_inventory),
            ("C_GetInfo", extra),
            ("C_GetSlotList", extra + 1),
            ("C_GetMechanismList", extra + 2),
        ],
    );
    let mut survivor = manifest_selection_evidence(
        Version { major: 3, minor: 1 },
        &[("C_GetInfo", shared_inventory), ("C_GetSlotList", extra)],
    );
    survivor.tables[0].id = 1;
    for query in &mut survivor.queries {
        if query.selection_table.is_some() {
            query.selection_table = Some(1);
        }
    }
    let survivor_query = survivor
        .queries
        .into_iter()
        .find(|query| query.selection_table == Some(1))
        .unwrap();
    let survivor_key = (survivor_query.selector, survivor_query.request.flags);
    *selection
        .queries
        .iter_mut()
        .find(|query| (query.selector, query.request.flags) == survivor_key)
        .unwrap() = survivor_query;
    selection.tables.push(survivor.tables.pop().unwrap());
    manifest.selection_evidence = selection;
    let problems = crate::manifest_input::validate_structure(&manifest);
    assert!(problems.is_empty(), "{problems:?}");
    engine.manifests[0] = manifest;
    let candidate = engine
        .live_candidate(engine.pinned.clone(), vec![module], Vec::new())
        .unwrap();

    assert_eq!(candidate.delta.new.len(), 3, "null entries do not attach");
    assert_eq!(
        candidate
            .plan
            .slots
            .iter()
            .filter(|slot| slot.file_offset == shared_inventory)
            .count(),
        1,
        "inventory and selection share one physical slot"
    );
    for slot in
        candidate.plan.slots.iter().filter(
            |slot| matches!(slot.file_offset, offset if offset >= extra && offset <= extra + 2),
        )
    {
        assert_eq!(
            slot.semantics,
            p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
        );
        assert!(!slot.semantic_authorized);
    }
    assert_eq!(candidate.plan.modules[0].tables, inventory_tables);
    let inventory_key = plan::AttachKey {
        object: inventory.object,
        file_offset: inventory.file_offset,
    };
    let rebuilt_inventory = candidate
        .manifest_inventory_slots
        .get(&inventory_key)
        .unwrap();
    assert_ne!(
        rebuilt_inventory.index, inventory.index,
        "removing an earlier target must compact the pre-reconciliation snapshot"
    );
    assert!(
        candidate
            .delta
            .retire
            .iter()
            .any(|slot| slot.file_offset == removed_inventory)
    );
    let committed_inventory = candidate
        .plan
        .slots
        .iter()
        .find(|slot| slot.file_offset == shared_inventory)
        .unwrap()
        .clone();
    assert_eq!(committed_inventory.index, inventory.index);
    assert_eq!(committed_inventory.descriptor_index, 0);
    assert_eq!(
        committed_inventory.semantics,
        p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
    );
    let evidence = evidence_verdict(&candidate.plan, &candidate.pinned, &engine.counters);
    assert!(evidence.semantic_unverified_slots > 0);
    assert_eq!(
        serde_json::to_value(&evidence).unwrap()["completeness"],
        "PARTIAL"
    );

    let earlier = candidate
        .delta
        .new
        .iter()
        .find(|slot| slot.file_offset == extra + 1)
        .unwrap()
        .index;
    let later = candidate
        .delta
        .new
        .iter()
        .find(|slot| slot.file_offset == extra + 2)
        .unwrap()
        .index;
    assert_ne!(earlier, later);
    session.fail_target_slots([later]);
    engine
        .apply_candidate(&mut session, candidate, &mut true, false, &[])
        .unwrap();

    let mut expected_inventory = committed_inventory;
    expected_inventory.names.clone_from(&inventory.names);
    expected_inventory.names.push("C_GetInfo".into());
    expected_inventory.names.sort();
    expected_inventory.names.dedup();
    expected_inventory.aliased = expected_inventory.names.len() >= 2;
    assert_eq!(
        engine
            .plan
            .slots
            .iter()
            .find(|slot| slot.file_offset == shared_inventory)
            .unwrap(),
        &expected_inventory,
        "rollback removes only the failed manifest alias from inventory"
    );
    let shared = engine
        .plan
        .slots
        .iter()
        .find(|slot| slot.file_offset == extra)
        .unwrap();
    assert!(engine.plan.is_active(shared.index));
    assert_eq!(shared.names, ["C_GetSlotList"]);
    assert!(
            engine
                .plan
                .slots
                .iter()
                .filter(|slot| matches!(slot.file_offset, offset if offset == extra + 1 || offset == extra + 2))
                .all(|slot| !engine.plan.is_active(slot.index)),
            "a later failure rolls back the successful selection-only prefix"
        );
    assert_eq!(session.detached_slots.last(), Some(&1));
    assert_eq!(session.detached_slot_indices.last(), Some(&vec![earlier]));
    assert_eq!(session.attached_slots.last(), Some(&3));
    let evidence = evidence_verdict(&engine.plan, &engine.pinned, &engine.counters);
    assert_eq!(
        serde_json::to_value(&evidence).unwrap()["completeness"],
        "PARTIAL"
    );
    assert!(
        engine
            .plan
            .skipped
            .iter()
            .any(|skip| skip.subject == "offline interface selection")
    );
}

#[test]
fn manifest_selection_tables_lower_during_initial_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let provider = dir.path().join("provider.so");
    std::fs::copy("/bin/sh", &provider).unwrap();
    let base = object_facts(&provider).2;
    let mut manifest = valid_manifest_for(std::slice::from_ref(&provider), &[0; 67]);
    manifest.selection_evidence =
        manifest_selection_evidence(Version { major: 3, minor: 0 }, &[("C_GetInfo", base + 80)]);
    let problems = crate::manifest_input::validate_structure(&manifest);
    assert!(problems.is_empty(), "{problems:?}");

    let mut discovered = lifecycle_discovered(Vec::new());
    discovered
        .manifest_inputs
        .push(manifest_input_from_pinning("initial.json", manifest));
    rebuild_discovered(&mut discovered).unwrap();

    let slot = discovered
        .plan
        .slots
        .iter()
        .find(|slot| slot.file_offset == base + 80)
        .expect("initial manifest selection target enters the starting plan");
    assert_eq!(
        slot.semantics,
        p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
    );
    assert!(!slot.semantic_authorized);
    assert_eq!(discovered.plan.modules[0].tables.len(), 1);
}

#[test]
fn manifest_selection_table_without_a_candidate_provider_adds_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let provider = dir.path().join("provider.so");
    std::fs::copy("/bin/sh", &provider).unwrap();
    let base = object_facts(&provider).2;
    let mut manifest = valid_manifest_for(std::slice::from_ref(&provider), &[0; 67]);
    manifest.selection_evidence =
        manifest_selection_evidence(Version { major: 3, minor: 0 }, &[("C_GetInfo", base + 80)]);
    let problems = crate::manifest_input::validate_structure(&manifest);
    assert!(problems.is_empty(), "{problems:?}");
    let pins = pin_manifest_objects(&manifest).unwrap();
    let mut plan = plan::build_from_reconciled_modules(&[]);
    let allocated = plan.clone();

    let (admissions, refused) = lower_manifest_selection_tables(
        &mut plan,
        &allocated,
        std::slice::from_ref(&manifest),
        &[0],
        &pins,
    );

    assert!(admissions.is_empty());
    assert!(refused.is_empty());
    assert!(plan.slots.is_empty());
}

#[test]
fn structurally_valid_orphan_table_record_is_rejected_and_never_lowered() {
    let dir = tempfile::tempdir().unwrap();
    let provider = dir.path().join("provider.so");
    std::fs::copy("/bin/sh", &provider).unwrap();
    let base = object_facts(&provider).2;
    let mut manifest = valid_manifest_for(std::slice::from_ref(&provider), &[0; 67]);
    manifest.selection_evidence =
        manifest_selection_evidence(Version { major: 3, minor: 0 }, &[("C_GetInfo", base + 80)]);
    let pins = pin_manifest_objects(&manifest).unwrap();
    let mut orphan = manifest.selection_evidence.tables[0].clone();
    orphan.id = 1;
    orphan
        .functions
        .iter_mut()
        .find(|function| function.name == "C_GetInfo")
        .unwrap()
        .resolution = Resolution::Resolved {
        object: 0,
        file_offset: base + 90,
    };
    manifest.selection_evidence.tables.push(orphan);
    // The table record itself is fully valid. Schema v5 deliberately makes
    // the containing document invalid solely because no authoritative
    // query references it, so no valid orphan document exists to accept.
    assert_eq!(
        crate::manifest_input::validate_structure(&manifest),
        ["selection table 1 is orphaned"]
    );
    let mut plan = plan::build_from_sources(&[], std::slice::from_ref(&manifest), &pins);
    let allocated = plan.clone();

    let (admissions, refused) = lower_manifest_selection_tables(
        &mut plan,
        &allocated,
        std::slice::from_ref(&manifest),
        &[7],
        &pins,
    );

    assert_eq!(
        admissions
            .iter()
            .map(|admission| admission.source)
            .collect::<Vec<_>>(),
        [(7, 0)]
    );
    assert!(refused.is_empty());
    assert!(plan.slots.iter().all(|slot| slot.file_offset != base + 90));
}

#[test]
fn stale_manifest_selection_does_not_transfer_to_scan_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let provider = dir.path().join("provider.so");
    std::fs::copy("/bin/sh", &provider).unwrap();
    let base = object_facts(&provider).2;
    let paths = vec![provider.clone()];
    let targets = vec![0; 67];
    let mut manifest = valid_manifest_for(&paths, &targets);
    manifest.selection_evidence =
        manifest_selection_evidence(Version { major: 3, minor: 0 }, &[("C_GetInfo", base + 80)]);
    let problems = crate::manifest_input::validate_structure(&manifest);
    assert!(problems.is_empty(), "{problems:?}");
    let scan = scanned_manifest_replacement(&paths, &targets);
    let scan_pins = pin_scan(&scan);
    std::fs::remove_file(&provider).unwrap();
    let input = manifest_input_from_pinning("stale-selection.json", manifest);
    assert_eq!(input.stale[0].reason, ManifestStaleReason::OpenStale);
    let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let mut discovered = lifecycle_discovered(vec![view]);
    discovered.scan_inputs.insert(
        ProcessViewId(0),
        ScanInput {
            modules: vec![scan],
            pins: scan_pins,
            counters: DiscoveryCounters::default(),
        },
    );
    discovered.manifest_inputs.push(input);

    rebuild_discovered(&mut discovered).unwrap();

    assert!(discovered.manifests.is_empty());
    assert_eq!(discovered.plan.modules.len(), 1);
    assert_eq!(discovered.plan.modules[0].source, "scan");
    assert!(
        discovered
            .plan
            .slots
            .iter()
            .any(|slot| slot.file_offset == base),
        "the exact scan replacement was accepted"
    );
    assert!(
        discovered
            .plan
            .slots
            .iter()
            .all(|slot| slot.file_offset != base + 80),
        "the scan replacement cannot inherit stale offline selection authority"
    );
}

fn selection_provider_address(engine: &Engine, binding: SelectionBindingFact) -> u64 {
    let provider = engine.pinned.summary(binding.object).unwrap().key;
    parse_maps(&std::fs::read(format!("/proc/{}/maps", engine.views[0].pid())).unwrap())
        .unwrap()
        .into_iter()
        .find(|mapping| ObjectKey::of(mapping) == provider)
        .unwrap()
        .start
}

fn armed_seed_route(
    loader_hits: u64,
) -> (
    LoadedSeedProvider,
    Engine,
    LoaderContextId,
    DiscoveryRecord,
    ScriptedSession,
) {
    let (fixture, view, _module, _pins) = loaded_seed_provider();
    let pid = view.pid();
    let mut engine = Engine::empty();
    engine.scope = Scope::Pid(pid);
    engine.next_view_id = 1;
    engine.views.push(view);
    let mut session = ScriptedSession::default();
    session.counters.loader_hits = loader_hits;
    engine
        .arm_loader_or_partial(
            0,
            &mut session,
            &mut true,
            &mut PendingViewRetirements::new(),
        )
        .unwrap();
    let context = engine.loader_registry.ids_for_view(ProcessViewId(0))[0];
    let spec = engine
        .loader_registry
        .context(context)
        .unwrap()
        .spec
        .clone();
    let mapping = spec.mapping.as_ref().unwrap();
    let mut record = loader_record_for(context, pid);
    record.table_ptr = mapping.start + (spec.hook.file_offset - mapping.file_offset);
    record.hook_ts_ns = engine.views[0].admitted_ns();
    (fixture, engine, context, record, session)
}

#[test]
fn exec_refresh_attaches_provider_exports_before_readiness() {
    let (fixture, view, _module, _pins) = loaded_seed_provider();
    let pid = view.pid();
    let view_id = view.id();
    let mut engine = Engine::empty();
    engine.scope = Scope::Pid(pid);
    engine.next_view_id = 1;
    engine.module_hints = vec![fixture._dir.path().join("seed-provider.so")];
    engine.views.push(view);
    let mut session = ScriptedSession::default();
    engine
        .arm_loader_or_partial(
            0,
            &mut session,
            &mut true,
            &mut PendingViewRetirements::new(),
        )
        .unwrap();
    let retired = engine.loader_registry.ids_for_view(view_id)[0];
    let mut exec: DiscoveryRecord = unsafe { std::mem::zeroed() };
    exec.kind = DISCOVERY_KIND_EXEC;
    exec.pid_tgid = u64::from(pid) << 32;
    exec.hook_ts_ns = engine.views[0].admitted_ns();

    let outcome = apply_ordinary_batch(&mut engine, &mut session, vec![exec]).unwrap();

    assert!(outcome.required_complete);
    let contexts = engine.loader_registry.ids_for_view(view_id);
    assert_eq!(contexts.len(), 1);
    assert_ne!(contexts[0], retired);
    assert_eq!(session.dynamic_attach_calls.len(), 3);
    let context_case_id = (contexts[0].get() - 1) as u8;
    assert_eq!(
        session
            .dynamic_attach_calls
            .iter()
            .filter(|export| export.abi != HookAbi::Interface)
            .map(|export| export.cookie)
            .collect::<BTreeSet<_>>(),
        [
            export_attach_cookie(
                session.dynamic_attach_calls[0].object.0,
                context_case_id,
                engine.hooks.id("C_GetFunctionList").unwrap(),
            )
            .unwrap(),
            export_attach_cookie(
                session.dynamic_attach_calls[0].object.0,
                context_case_id,
                engine.hooks.id("C_GetInterfaceList").unwrap(),
            )
            .unwrap(),
        ]
        .into_iter()
        .collect(),
        "readiness requires all configured exports from the refreshed provider"
    );
}

#[test]
fn selection_bindings_reuse_existing_physical_attachments() {
    let (_fixture, mut engine, mut session) = initial_export_route();
    engine.modules[0]
        .scanned
        .exports
        .push("C_GetInterface".into());
    session.dynamic_attach_reports_added = true;
    let mut additions_allowed = true;
    let mut pending = PendingViewRetirements::new();
    let mut closure = PauseClosure::new(true);

    engine.attach_initial_exports(
        &mut session,
        &mut additions_allowed,
        &mut pending,
        &mut closure,
    );
    assert_eq!(session.dynamic_attach_calls.len(), 3);
    assert_eq!(
        session
            .dynamic_attach_calls
            .iter()
            .filter(|export| export.abi != HookAbi::Interface)
            .map(|export| export.cookie)
            .collect::<BTreeSet<_>>()
            .len(),
        2
    );
    assert_eq!(engine.selection_bindings.len(), 1);
    assert!(engine.selection_bindings[&1].attached);
    let context_case_id = (engine.selection_bindings[&1].context.get() - 1) as u8;
    assert_eq!(
        session
            .dynamic_attach_calls
            .iter()
            .find(|export| export.abi == HookAbi::FunctionList)
            .unwrap()
            .cookie,
        export_attach_cookie(
            engine.selection_bindings[&1].object.0,
            context_case_id,
            engine.hooks.id("C_GetFunctionList").unwrap(),
        )
        .unwrap()
    );
    assert_eq!(
        session
            .dynamic_attach_calls
            .iter()
            .find(|export| export.abi == HookAbi::InterfaceList)
            .unwrap()
            .cookie,
        export_attach_cookie(
            engine.selection_bindings[&1].object.0,
            context_case_id,
            engine.hooks.id("C_GetInterfaceList").unwrap(),
        )
        .unwrap()
    );
    assert_eq!(
        session
            .dynamic_attach_calls
            .iter()
            .find(|export| export.abi == HookAbi::Interface)
            .unwrap()
            .cookie,
        engine.selection_bindings[&1].id
    );
    assert!(additions_allowed && pending.is_empty() && closure.required_complete());

    engine.attach_initial_exports(
        &mut session,
        &mut additions_allowed,
        &mut pending,
        &mut closure,
    );
    assert_eq!(session.dynamic_attach_calls.len(), 3);
    assert_eq!(engine.selection_bindings.len(), 1);
}

#[test]
fn two_view_selection_claims_retire_independently() {
    let (mut fixture, mut engine, mut session, first_binding) = attached_selection_route();
    let provider_path = PathBuf::from(&engine.modules[0].scanned.path);
    let peer_pid = fixture.spawn_peer();
    let second_view = ProcessView::open(ProcessViewId(1), peer_pid).unwrap();
    let second_view_id = second_view.id();
    let (cgroup_engine, _scope_dir) = engine_over_cgroup_naming(&[engine.views[0].pid(), peer_pid]);
    engine.scope = cgroup_engine.scope;
    let provider = engine
        .pinned
        .owned_timing_key(first_binding.object)
        .unwrap();
    let first_table = selection_only_table(
        &engine,
        first_binding,
        0x20,
        &[("C_Initialize", 0x100)],
        Vec::new(),
    );
    let result = SelectionRequest {
        name: SelectionNameClass::ExactStandard,
        version: SelectionVersionClass::V3_0,
        flags: 0,
    };
    let (claims, tables, pending) = engine
        .propose_selection_claim(&first_binding, provider, &first_table, &result)
        .unwrap();
    let candidate = engine
        .live_candidate_with_selection(
            engine.pinned.clone(),
            engine
                .modules
                .iter()
                .map(|module| module.scanned.clone())
                .collect(),
            claims,
            tables,
            pending,
        )
        .unwrap();
    engine
        .apply_candidate(&mut session, candidate, &mut true, false, &[])
        .unwrap();

    let mut mapped = None;
    for _ in 0..200 {
        let maps = parse_maps(&std::fs::read(format!("/proc/{peer_pid}/maps")).unwrap()).unwrap();
        let map_index = MapIndex::new(&maps).expect("the peer maps snapshot is valid");
        mapped = maps.iter().find_map(|mapping| {
            matches!(
                map_index.resolve(mapping.start),
                Resolved::File {
                    path: MappedPath::Usable(ref path),
                    ..
                } if path == &provider_path
            )
            .then(|| mapping.clone())
        });
        if mapped.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let mut second_module = mapped_object(
        &second_view,
        &mapped.expect("the peer seed provider is mapped"),
        &provider_path,
    );
    second_module.exports = vec![
        "C_GetFunctionList".into(),
        "C_GetInterfaceList".into(),
        "C_GetInterface".into(),
    ];
    let mut candidate_pinned = engine.pinned.clone();
    assert!(
        candidate_pinned
            .absorb(pin_test_module(&second_view, &second_module))
            .is_empty()
    );
    engine.next_view_id = 2;
    let raw_modules = engine
        .modules
        .iter()
        .map(|module| module.scanned.clone())
        .chain([second_module.clone()])
        .collect();
    let candidate = engine
        .live_candidate(candidate_pinned, raw_modules, Vec::new())
        .unwrap();
    assert!(
        engine
            .apply_candidate(&mut session, candidate, &mut true, false, &[&second_view],)
            .unwrap()
            .accepted()
    );
    engine.views.push(second_view);
    engine
        .arm_loader_or_partial(
            1,
            &mut session,
            &mut true,
            &mut PendingViewRetirements::new(),
        )
        .unwrap();
    let (retire, complete) =
        engine.attach_refreshed_exports(second_view_id, &mut session, &mut true);
    assert!(!retire && complete);
    let second_binding = *engine
        .selection_bindings
        .values()
        .find(|binding| binding.view == second_view_id)
        .unwrap();
    let second_table = selection_only_table(
        &engine,
        second_binding,
        0x20,
        &[("C_Initialize", 0x100)],
        Vec::new(),
    );
    let (claims, tables, pending) = engine
        .propose_selection_claim(
            &second_binding,
            engine
                .pinned
                .owned_timing_key(second_binding.object)
                .unwrap(),
            &second_table,
            &result,
        )
        .unwrap();
    let raw_modules = engine
        .modules
        .iter()
        .map(|module| module.scanned.clone())
        .collect();
    let candidate = engine
        .live_candidate_with_selection(engine.pinned.clone(), raw_modules, claims, tables, pending)
        .unwrap();
    assert!(
        engine
            .apply_candidate(&mut session, candidate, &mut true, false, &[])
            .unwrap()
            .accepted()
    );

    let selection_slot = engine
        .plan
        .slots
        .iter()
        .find(|slot| slot.file_offset == 0x100)
        .map(|slot| slot.index)
        .unwrap();
    assert_eq!(engine.selection_claims.len(), 2);
    assert_eq!(
        engine
            .plan
            .slots
            .iter()
            .filter(|slot| slot.file_offset == 0x100 && engine.plan.is_active(slot.index))
            .count(),
        1
    );
    let raw_modules = engine
        .modules
        .iter()
        .map(|module| module.scanned.clone())
        .collect();
    let candidate = engine
        .live_candidate(engine.pinned.clone(), raw_modules, Vec::new())
        .unwrap();
    let mut first_retirement = ScriptedSession::losing_generation_at_attach(engine.views[0].pid());
    let first_outcome = engine
        .apply_candidate(&mut first_retirement, candidate, &mut true, false, &[])
        .unwrap();

    assert!(!first_outcome.accepted());
    assert!(
        engine.selection_bindings[&first_binding.id].retired,
        "retiring the first view must retire its binding ID"
    );
    assert!(!engine.selection_bindings[&second_binding.id].retired);
    assert_eq!(engine.selection_claims.len(), 1);
    assert_eq!(
        engine.selection_claims.keys().next().unwrap().binding_id,
        second_binding.id
    );
    assert!(engine.plan.is_active(selection_slot));
    assert_eq!(first_retirement.detached_slots.iter().sum::<usize>(), 0);

    let mut delayed: DiscoveryRecord = unsafe { std::mem::zeroed() };
    delayed.kind = DISCOVERY_KIND_INTERFACE_RETURN;
    delayed.pid_tgid = u64::from(engine.views[0].pid()) << 32;
    delayed.case_id = DISCOVERY_NAME_EXACT_STANDARD;
    delayed.interface_index = DISCOVERY_VERSION_V3_0;
    delayed.name_class = DISCOVERY_NAME_EXACT_STANDARD;
    delayed.selection_version_class = DISCOVERY_VERSION_V3_0;
    delayed.binding_id = first_binding.id;
    assert_eq!(
        engine.process_selection_record(&QueuedDiscoveryRecord {
            record: delayed,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        }),
        DiscoveryRecordOutcome::Rejected(RecordRejection::SelectionUnattributed)
    );

    let mut usable: DiscoveryRecord = unsafe { std::mem::zeroed() };
    usable.kind = DISCOVERY_KIND_INTERFACE_RETURN;
    usable.pid_tgid = u64::from(engine.views[1].pid()) << 32;
    usable.case_id = DISCOVERY_NAME_EXACT_STANDARD;
    usable.interface_index = DISCOVERY_VERSION_V3_0;
    usable.name_class = DISCOVERY_NAME_EXACT_STANDARD;
    usable.selection_version_class = DISCOVERY_VERSION_V3_0;
    usable.return_rv = 1;
    usable.binding_id = second_binding.id;
    assert_eq!(
        engine.process_selection_record(&QueuedDiscoveryRecord {
            record: usable,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        }),
        DiscoveryRecordOutcome::applied(false, true)
    );

    let raw_modules = engine
        .modules
        .iter()
        .map(|module| module.scanned.clone())
        .collect();
    let candidate = engine
        .live_candidate(engine.pinned.clone(), raw_modules, Vec::new())
        .unwrap();
    let mut second_retirement = ScriptedSession::losing_generation_at_attach(peer_pid);
    let second_outcome = engine
        .apply_candidate(&mut second_retirement, candidate, &mut true, false, &[])
        .unwrap();
    assert!(!second_outcome.accepted());
    assert_eq!(second_retirement.detached_slots.iter().sum::<usize>(), 1);
    assert!(!engine.plan.is_active(selection_slot));
    assert!(engine.selection_bindings[&second_binding.id].retired);
    assert!(engine.selection_claims.is_empty());
    assert!(engine.selection_tables.is_empty());
}

#[test]
fn aggregate_policy_creates_no_selection_bindings() {
    let (_fixture, mut engine, mut session) = initial_export_route();
    engine.modules[0].scanned.exports = vec!["C_GetInterface".into()];
    session.capture_policy = Some(CapturePolicy::AggregateOnly);
    session.dynamic_attach_reports_added = true;
    let mut additions_allowed = true;
    let mut pending = PendingViewRetirements::new();
    let mut closure = PauseClosure::new(true);

    engine.attach_initial_exports(
        &mut session,
        &mut additions_allowed,
        &mut pending,
        &mut closure,
    );

    assert!(session.dynamic_attach_calls.is_empty());
    assert!(engine.selection_bindings.is_empty());
    assert_eq!(engine.next_selection_binding_id, Some(1));
    assert!(closure.required_complete());
    assert!(
        !engine.counters.object_skips.iter().any(|skip| {
            skip.subject.contains("selection") || skip.reason.contains("selection")
        })
    );
}

#[test]
fn selection_binding_ids_never_reuse() {
    let mut engine = Engine::empty();
    let context = LoaderContextId::from_case_id(0);

    let ordinary = engine
        .selection_binding_candidate(
            context,
            ProcessViewId(1),
            PinnedObjectId(2),
            0x10,
            3,
            plan::ModuleId(0),
        )
        .unwrap();
    assert_eq!(ordinary.id, 1);
    engine.selection_bindings.insert(ordinary.id, ordinary);
    engine
        .selection_bindings
        .get_mut(&ordinary.id)
        .unwrap()
        .retired = true;
    assert!(engine.selection_bindings.remove(&ordinary.id).is_some());

    let replacement = engine
        .selection_binding_candidate(
            context,
            ProcessViewId(1),
            PinnedObjectId(3),
            0x20,
            3,
            plan::ModuleId(0),
        )
        .unwrap();
    assert!(replacement.id > ordinary.id);
    engine
        .selection_bindings
        .insert(replacement.id, replacement);

    engine.next_selection_binding_id = Some(u64::MAX);

    let last = engine
        .selection_binding_candidate(
            context,
            ProcessViewId(1),
            PinnedObjectId(2),
            0x10,
            3,
            plan::ModuleId(0),
        )
        .unwrap();
    assert_eq!(last.id, u64::MAX);
    engine.selection_bindings.insert(last.id, last);
    assert_eq!(
        engine
            .selection_binding_candidate(
                context,
                ProcessViewId(1),
                PinnedObjectId(2),
                0x10,
                3,
                plan::ModuleId(0),
            )
            .unwrap()
            .id,
        u64::MAX,
        "the same physical attachment reuses its retained ID"
    );
    assert!(
        engine
            .selection_binding_candidate(
                context,
                ProcessViewId(1),
                PinnedObjectId(2),
                0x20,
                3,
                plan::ModuleId(0),
            )
            .is_none(),
        "exhaustion refuses rather than wrapping to zero"
    );
    assert_eq!(engine.next_selection_binding_id, None);
}

#[test]
fn selection_binding_start_failure_restores_capture_state() {
    let mut engine = Engine::empty();
    let binding = engine
        .selection_binding_candidate(
            LoaderContextId::from_case_id(0),
            ProcessViewId(1),
            PinnedObjectId(2),
            0x10,
            3,
            plan::ModuleId(0),
        )
        .unwrap();
    engine.selection_bindings.insert(binding.id, binding);
    let snapshot = engine.begin_start_capture_attempt().unwrap();
    assert!(engine.selection_bindings.is_empty());
    assert_eq!(engine.next_selection_binding_id, Some(1));
    let attempted = engine
        .selection_binding_candidate(
            LoaderContextId::from_case_id(1),
            ProcessViewId(4),
            PinnedObjectId(5),
            0x20,
            3,
            plan::ModuleId(0),
        )
        .unwrap();
    engine.selection_bindings.insert(attempted.id, attempted);

    let error = engine
        .finish_start_capture_attempt::<()>(snapshot, Err(anyhow!("late start failure")))
        .unwrap_err();

    assert_eq!(error.to_string(), "late start failure");
    assert_eq!(
        engine.selection_bindings,
        [(1, binding)].into_iter().collect()
    );
    assert_eq!(engine.next_selection_binding_id, Some(2));
}

#[test]
fn selection_postcheck_failure_retains_attached_binding() {
    let (_fixture, mut engine, mut session) = initial_export_route();
    engine.modules[0].scanned.exports = vec!["C_GetInterface".into()];
    let view = engine.views[0].id();
    session.dynamic_attach_reports_added = true;
    session.lose_generation_at_dynamic_attach(engine.views[0].pid());
    let mut additions_allowed = true;
    let mut pending = PendingViewRetirements::new();
    let mut closure = PauseClosure::new(true);

    engine.attach_initial_exports(
        &mut session,
        &mut additions_allowed,
        &mut pending,
        &mut closure,
    );

    assert_eq!(engine.selection_bindings.len(), 1);
    let binding = *engine.selection_bindings.values().next().unwrap();
    assert!(binding.attached);
    assert_eq!(binding.coverage, SelectionCoverageState::Uncovered);
    assert!(
        session
            .dynamic_attach_calls
            .contains(&DynamicExportIdentity {
                object: binding.object,
                file_offset: binding.file_offset,
                cookie: binding.id,
                abi: binding.abi,
            })
    );
    assert!(!additions_allowed);
    assert!(pending.contains_key(&view));
    assert!(!closure.required_complete());
}

#[test]
fn owned_run_selection_coverage() {
    let (_fixture, mut engine, _session, binding) = attached_selection_route();
    let provider = binding.provider;
    assert_eq!(binding.coverage, SelectionCoverageState::Uncovered);
    assert_eq!(engine.selection_coverage(plan::ModuleId(u32::MAX)), None);
    assert_eq!(
        engine.selection_coverage(provider),
        Some(SelectionCoverageVerdict::AbsentUncovered)
    );
    engine
        .selection_bindings
        .get_mut(&binding.id)
        .unwrap()
        .observed = true;
    assert_eq!(
        engine.selection_coverage(provider),
        Some(SelectionCoverageVerdict::Observed)
    );
    engine
        .selection_bindings
        .get_mut(&binding.id)
        .unwrap()
        .observed = false;

    let generation = std::num::NonZeroU64::new(7).unwrap();
    engine.mark_owned_selection_pending(generation);
    assert_eq!(
        engine.selection_bindings[&binding.id].coverage,
        SelectionCoverageState::OwnedPending(generation)
    );
    assert_eq!(
        engine.selection_coverage(provider),
        Some(SelectionCoverageVerdict::AbsentUncovered)
    );
    engine.open_owned_selection(binding.id);
    assert_eq!(
        engine.selection_bindings[&binding.id].coverage,
        SelectionCoverageState::OwnedOpen(generation)
    );

    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
    record.pid_tgid = u64::from(engine.views[0].pid()) << 32;
    record.case_id = DISCOVERY_NAME_EXACT_STANDARD;
    record.interface_index = DISCOVERY_VERSION_V3_0;
    record.return_rv = 7;
    record.binding_id = binding.id;
    assert_eq!(
        engine.process_selection_record(&QueuedDiscoveryRecord {
            record,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        }),
        DiscoveryRecordOutcome::applied(false, true)
    );
    assert!(engine.selection_bindings[&binding.id].observed);
    assert_eq!(
        engine.selection_coverage(provider),
        Some(SelectionCoverageVerdict::Observed)
    );
    let uncovered = SelectionBindingFact {
        id: binding.id + 1,
        observed: false,
        coverage: SelectionCoverageState::Uncovered,
        ..binding
    };
    engine.selection_bindings.insert(uncovered.id, uncovered);
    assert_eq!(
        engine.selection_coverage(provider),
        Some(SelectionCoverageVerdict::ObservedUncovered)
    );
    engine.selection_bindings.remove(&uncovered.id);

    engine.close_owned_selection(binding.id);
    assert_eq!(
        engine.selection_bindings[&binding.id].coverage,
        SelectionCoverageState::OwnedClosed(generation)
    );

    engine
        .selection_bindings
        .get_mut(&binding.id)
        .unwrap()
        .observed = false;
    engine
        .selection_bindings
        .get_mut(&binding.id)
        .unwrap()
        .coverage = SelectionCoverageState::OwnedOpen(generation);
    engine.finish_owned_selection_coverage(true);
    assert_eq!(
        engine.selection_bindings[&binding.id].coverage,
        SelectionCoverageState::OwnedClosed(generation)
    );
    assert_eq!(
        engine.selection_coverage(provider),
        Some(SelectionCoverageVerdict::AbsentCovered)
    );

    engine
        .selection_bindings
        .get_mut(&binding.id)
        .unwrap()
        .coverage = SelectionCoverageState::OwnedOpen(generation);
    engine.finish_owned_selection_coverage(false);
    assert_eq!(
        engine.selection_bindings[&binding.id].coverage,
        SelectionCoverageState::Uncovered
    );
    assert_eq!(
        engine.selection_coverage(provider),
        Some(SelectionCoverageVerdict::AbsentUncovered)
    );
}

#[test]
fn public_selection_coverage_uses_the_private_four_state_reducer() {
    let (_fixture, mut engine, _session, binding) = attached_selection_route();
    let generation = NonZeroU64::new(1).unwrap();
    let cases = [
        (false, SelectionCoverageState::Uncovered, "absent_uncovered"),
        (
            false,
            SelectionCoverageState::OwnedClosed(generation),
            "absent_covered",
        ),
        (
            true,
            SelectionCoverageState::OwnedClosed(generation),
            "observed",
        ),
    ];
    for (observed, coverage, expected) in cases {
        let retained = engine.selection_bindings.get_mut(&binding.id).unwrap();
        retained.observed = observed;
        retained.coverage = coverage;
        let public = engine.interface_selection();
        assert_eq!(public.providers[0].coverage, expected);
    }
    let mut silent = binding;
    silent.id = binding.id + 1;
    silent.observed = false;
    silent.coverage = SelectionCoverageState::Uncovered;
    engine.selection_bindings.insert(silent.id, silent);
    engine
        .selection_bindings
        .get_mut(&binding.id)
        .unwrap()
        .observed = true;
    assert_eq!(
        engine.interface_selection().providers[0].coverage,
        "observed_uncovered"
    );
}

#[test]
fn selection_ring_loss_invalidates_silent_coverage() {
    let (_fixture, mut engine, mut session, binding) = attached_selection_route();
    let generation = std::num::NonZeroU64::new(9).unwrap();
    engine.mark_owned_selection_pending(generation);
    engine.open_owned_selection(binding.id);
    assert_eq!(
        engine.selection_bindings[&binding.id].coverage,
        SelectionCoverageState::OwnedOpen(generation)
    );

    session.counters.ring_loss = 1;
    engine.update_counter_snapshot(&session).unwrap();
    assert_eq!(
        engine.selection_bindings[&binding.id].coverage,
        SelectionCoverageState::Uncovered
    );
    assert_eq!(
        engine.selection_coverage(binding.provider),
        Some(SelectionCoverageVerdict::AbsentUncovered)
    );

    engine.mark_owned_selection_pending(generation);
    assert_eq!(
        engine.selection_bindings[&binding.id].coverage,
        SelectionCoverageState::Uncovered,
        "a loss known before prearm cannot mint covered silence"
    );

    engine.counter_snapshot.ring_loss = 0;
    session.counters.ring_loss = 0;
    engine.mark_owned_selection_pending(generation);
    engine.open_owned_selection(binding.id);
    engine.finish_owned_selection_coverage(true);
    assert_eq!(
        engine.selection_bindings[&binding.id].coverage,
        SelectionCoverageState::OwnedClosed(generation)
    );
    session.counters.ring_loss = 1;
    engine.update_counter_snapshot(&session).unwrap();
    assert_eq!(
        engine.selection_bindings[&binding.id].coverage,
        SelectionCoverageState::Uncovered,
        "loss discovered after closure invalidates the historical proof"
    );
}

#[test]
fn selection_abi_refusal_invalidates_silent_coverage() {
    let (_fixture, mut engine, mut session, binding) = attached_selection_route();
    let generation = NonZeroU64::new(10).unwrap();
    engine.mark_owned_selection_pending(generation);
    engine.open_owned_selection(binding.id);

    session.counters.abi_refusals = 1;
    engine.update_counter_snapshot(&session).unwrap();
    assert_eq!(
        engine.selection_bindings[&binding.id].coverage,
        SelectionCoverageState::Uncovered
    );

    engine.mark_owned_selection_pending(generation);
    assert_eq!(
        engine.selection_bindings[&binding.id].coverage,
        SelectionCoverageState::Uncovered,
        "an unsupported target ABI cannot mint covered silence"
    );
}

#[test]
fn selection_counter_regression_invalidates_silent_coverage() {
    let (_fixture, mut engine, mut session, binding) = attached_selection_route();
    let generation = NonZeroU64::new(13).unwrap();
    engine.mark_owned_selection_pending(generation);
    engine.open_owned_selection(binding.id);
    engine.counter_snapshot.loader_hits = 2;
    session.counters.loader_hits = 1;
    session.counters.ring_loss = 1;

    engine.update_counter_snapshot(&session).unwrap();

    assert_eq!(
        engine.selection_bindings[&binding.id].coverage,
        SelectionCoverageState::Uncovered
    );
}

#[test]
fn selection_bindings_isolate_provider_attribution_and_refusal() {
    let (child, mut engine, modules) = engine_with_one_accepted_provider();
    let mut session = ScriptedSession::default();
    let mut additions_allowed = true;
    engine
        .arm_loader_or_partial(
            0,
            &mut session,
            &mut additions_allowed,
            &mut PendingViewRetirements::new(),
        )
        .unwrap();
    let context = engine.loader_registry.ids_for_view(engine.views[0].id())[0];
    let candidate = peer_candidate(&mut engine, &modules);
    assert!(
        engine
            .apply_candidate(&mut session, candidate, &mut additions_allowed, false, &[])
            .unwrap()
            .accepted()
    );
    let first = engine
        .modules
        .iter()
        .find(|module| module.object == engine.plan.modules[0].object)
        .unwrap()
        .object;
    let second = engine
        .modules
        .iter()
        .find(|module| module.object != first)
        .unwrap()
        .object;
    let first_provider = engine.pinned.owned_timing_key(first).unwrap();
    let first_id = engine
        .plan
        .modules
        .iter()
        .find(|module| module.object == first)
        .unwrap()
        .id;
    let second_id = engine
        .plan
        .modules
        .iter()
        .find(|module| module.object == second)
        .unwrap()
        .id;
    let generation = NonZeroU64::new(17).unwrap();
    let interface_hook = engine.hooks.id("C_GetInterface").unwrap();
    let first_binding = SelectionBindingFact {
        id: 1,
        context,
        view: engine.views[0].id(),
        object: first,
        file_offset: 0x10,
        hook_id: interface_hook,
        abi: HookAbi::Interface,
        attached: true,
        retired: false,
        provider: first_id,
        observed: false,
        coverage: SelectionCoverageState::OwnedOpen(generation),
    };
    let second_binding = SelectionBindingFact {
        id: 2,
        object: second,
        provider: second_id,
        coverage: SelectionCoverageState::OwnedOpen(generation),
        ..first_binding
    };
    engine
        .selection_bindings
        .extend([(1, first_binding), (2, second_binding)]);

    for (binding_id, module) in [(1, first_id), (2, second_id)] {
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
        record.pid_tgid = u64::from(engine.views[0].pid()) << 32;
        record.case_id = DISCOVERY_NAME_EXACT_STANDARD;
        record.interface_index = DISCOVERY_VERSION_V3_0;
        record.return_rv = 1;
        record.binding_id = binding_id;
        assert_eq!(
            engine.process_selection_record(&QueuedDiscoveryRecord {
                record,
                terminal_owner: None,
                terminal_exports: Vec::new(),
            }),
            DiscoveryRecordOutcome::applied(false, true)
        );
        assert_eq!(
            engine
                .capture_facts
                .history
                .selections
                .last()
                .unwrap()
                .module,
            module
        );
    }

    let table_key = SelectionTableKey {
        view: engine.views[0].id(),
        provider: first_provider.clone(),
        version: SelectionVersionClass::V3_0,
        flags: 0,
    };
    let claim = SelectionClaim {
        target: plan::AttachKey {
            object: first,
            file_offset: 0x100,
        },
        object_path: String::new(),
    };
    let mut key = SelectionClaimKey {
        binding_id: 1,
        view: table_key.view,
        context: context.get(),
        hook_owner: first,
        provider: first_provider,
        selected_object: first,
        table_file_offset: 0x20,
        version: table_key.version,
        flags: table_key.flags,
        name: "C_Initialize",
        file_offset: 0x100,
    };
    let mut claims: BTreeMap<SelectionClaimKey, SelectionClaim> =
        [(key.clone(), claim.clone())].into_iter().collect();
    key.table_file_offset = 0x28;
    claims.insert(key, claim);
    let table = SelectionTableFact {
        object: first,
        file_offset: 0x20,
        targets: vec![plan::SelectionTableTarget {
            object: first,
            object_path: String::new(),
            file_offset: 0x100,
            name: "C_Initialize",
        }],
    };
    let pending = PendingSelectionAdmission {
        key: table_key.clone(),
        table: table.clone(),
        previous_claims: BTreeMap::new(),
        previous_tables: BTreeMap::new(),
    };
    let candidate = engine
        .live_candidate_with_selection(
            engine.pinned.clone(),
            engine
                .modules
                .iter()
                .map(|module| module.scanned.clone())
                .collect(),
            claims,
            [(table_key, table)].into_iter().collect(),
            pending,
        )
        .unwrap();
    assert!(candidate.plan.slots.len() >= engine.plan.slots.len());
    assert_eq!(
        engine.selection_bindings[&1].coverage,
        SelectionCoverageState::Uncovered
    );
    assert_eq!(
        engine.selection_bindings[&2].coverage,
        SelectionCoverageState::OwnedOpen(generation)
    );
    let mut child = child;
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn interface_list_truncation_preserves_selection_coverage() {
    let (_fixture, mut engine, mut session, binding) = attached_selection_route();
    let generation = NonZeroU64::new(19).unwrap();
    engine.mark_owned_selection_pending(generation);
    engine.open_owned_selection(binding.id);
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN;
    record.pid_tgid = u64::from(engine.views[0].pid()) << 32;
    record.interface_index = 0;
    record.announced_count = u32::from(DISCOVERY_INTERFACES) + 1;
    let mut additions_allowed = true;
    let mut pending = PendingViewRetirements::new();
    let _ =
        engine.process_export_record(&record, &mut session, &mut additions_allowed, &mut pending);

    assert_eq!(engine.discovery_truncated, 1);
    assert_eq!(
        engine.selection_bindings[&binding.id].coverage,
        SelectionCoverageState::OwnedOpen(generation)
    );
}

#[test]
fn attributed_selection_loss_does_not_poison_another_provider() {
    let (_fixture, mut engine, _session, binding) = attached_selection_route();
    let generation = NonZeroU64::new(11).unwrap();
    engine.mark_owned_selection_pending(generation);
    engine.open_owned_selection(binding.id);
    let unrelated = SelectionBindingFact {
        id: binding.id + 1,
        provider: plan::ModuleId(binding.provider.0 + 1),
        coverage: SelectionCoverageState::OwnedOpen(generation),
        ..binding
    };
    engine.selection_bindings.insert(unrelated.id, unrelated);

    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
    record.pid_tgid = u64::from(engine.views[0].pid()) << 32;
    record.case_id = u8::MAX;
    record.binding_id = binding.id;
    assert_eq!(
        engine.process_selection_record(&QueuedDiscoveryRecord {
            record,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        }),
        DiscoveryRecordOutcome::Rejected(RecordRejection::SelectionUnattributed)
    );
    assert_eq!(
        engine.selection_bindings[&binding.id].coverage,
        SelectionCoverageState::Uncovered
    );
    assert_eq!(
        engine.selection_bindings[&unrelated.id].coverage,
        SelectionCoverageState::OwnedOpen(generation)
    );
}

#[test]
fn c_get_interface_selection_never_mutates_inventory() {
    let (_fixture, mut engine, mut session) = initial_export_route();
    session.dynamic_attach_reports_added = true;
    let mut additions_allowed = true;
    let mut pending = PendingViewRetirements::new();
    let mut closure = PauseClosure::new(true);
    engine.attach_initial_exports(
        &mut session,
        &mut additions_allowed,
        &mut pending,
        &mut closure,
    );
    let binding = *engine.selection_bindings.values().next().unwrap();
    let before_plan = engine.plan.clone();
    let before_modules = engine.modules.clone();
    let before_discovery = engine.discovery.clone();
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
    record.pid_tgid = u64::from(engine.views[0].pid()) << 32;
    record.case_id = DISCOVERY_NAME_NULL;
    record.return_rv = 1;
    record.binding_id = binding.id;
    assert!(valid_discovery_record(&record));

    let outcome = engine
        .dispatch_discovery_record(
            QueuedDiscoveryRecord {
                record,
                terminal_owner: None,
                terminal_exports: Vec::new(),
            },
            &mut session,
            &mut additions_allowed,
            &mut pending,
            &mut BTreeSet::new(),
            &mut Vec::new(),
        )
        .unwrap();

    assert_eq!(outcome, DiscoveryRecordOutcome::applied(false, true));
    assert_eq!(engine.plan, before_plan);
    assert_eq!(engine.modules, before_modules);
    assert_eq!(engine.discovery, before_discovery);

    engine
        .selection_bindings
        .get_mut(&binding.id)
        .unwrap()
        .retired = true;
    engine.loader_registry.tombstone(binding.context).unwrap();
    let identity = DynamicExportIdentity {
        object: binding.object,
        file_offset: binding.file_offset,
        cookie: binding.id,
        abi: binding.abi,
    };
    assert_eq!(
        engine
            .process_selection_record(&tagged_by_authority(binding.context, &[identity], record,)),
        DiscoveryRecordOutcome::applied(false, true),
        "the exact terminal export snapshot remains historical authority"
    );
    let skips = engine.counters.object_skips.len();
    let ordinary = engine.process_selection_record(&QueuedDiscoveryRecord {
        record,
        terminal_owner: None,
        terminal_exports: Vec::new(),
    });
    assert_eq!(
        ordinary,
        DiscoveryRecordOutcome::Rejected(RecordRejection::SelectionUnattributed),
        "a delayed ordinary record fails closed after retirement"
    );
    assert_eq!(engine.counters.object_skips.len(), skips + 1);
}

#[test]
fn c_get_interface_selection_tuples_are_capture_bounded_and_counted() {
    let (_fixture, mut engine, _session, binding) = attached_selection_route();
    let before_plan = engine.plan.clone();
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
    record.pid_tgid = u64::from(engine.views[0].pid()) << 32;
    record.case_id = DISCOVERY_NAME_EXACT_STANDARD;
    record.interface_index = DISCOVERY_VERSION_V3_0;
    record.name_class = DISCOVERY_NAME_EXACT_STANDARD;
    record.selection_version_class = DISCOVERY_VERSION_V3_0;
    record.table_ptr = selection_provider_address(&engine, binding);
    record.binding_id = binding.id;
    let queued = |record| QueuedDiscoveryRecord {
        record,
        terminal_owner: None,
        terminal_exports: Vec::new(),
    };

    for flags in 0..16 {
        record.request_flags = flags;
        assert_eq!(
            engine.process_selection_record(&queued(record)),
            DiscoveryRecordOutcome::applied(false, true)
        );
    }
    assert_eq!(engine.capture_facts.history.selections.len(), 16);
    assert!(engine.capture_facts.history.selections[0].result.is_some());
    assert!(
        engine.capture_facts.history.selections[0]
            .inventory_matches
            .is_empty()
    );
    record.request_flags = 0;
    engine.process_selection_record(&queued(record));
    assert_eq!(engine.capture_facts.history.selections[0].count, 2);
    engine.capture_facts.history.selections[0].count = u64::MAX;
    engine.process_selection_record(&queued(record));
    assert_eq!(engine.capture_facts.history.selections[0].count, u64::MAX);

    record.request_flags = 16;
    engine.process_selection_record(&queued(record));
    assert_eq!(engine.capture_facts.history.selections.len(), 16);
    assert!(engine.capture_facts.history.selection_truncated);
    assert_eq!(
        engine.plan, before_plan,
        "selection tuples never mutate inventory"
    );
    assert!(engine.selection_claims.is_empty());
    assert!(engine.selection_tables.is_empty());
}

#[test]
fn selection_tuple_bound_is_global_across_modules() {
    let mut facts = CaptureFacts::default();
    for index in 0..=MAX_LIVE_SELECTION_TUPLES {
        facts.record_selection(
            LiveSelectionTuple {
                module: plan::ModuleId(index as u32),
                request: SelectionRequest {
                    name: SelectionNameClass::Null,
                    version: SelectionVersionClass::Null,
                    flags: index as u64,
                },
                rv: 1,
                result: None,
                inventory_matches: vec![],
                authority: SelectionAuthority::None,
                count: 1,
            },
            false,
        );
    }
    assert_eq!(facts.history.selections.len(), MAX_LIVE_SELECTION_TUPLES);
    assert!(facts.history.selection_truncated);
}

#[test]
fn task_8d_selection_authority_is_part_of_exact_tuple_identity_and_bound() {
    let tuple = LiveSelectionTuple {
        module: plan::ModuleId(1),
        request: SelectionRequest {
            name: SelectionNameClass::ExactStandard,
            version: SelectionVersionClass::V3_0,
            flags: 0,
        },
        rv: 0,
        result: None,
        inventory_matches: Vec::new(),
        authority: SelectionAuthority::SelectionCountOnly,
        count: 1,
    };
    let mut facts = CaptureFacts::default();
    facts.record_selection(tuple.clone(), false);
    facts.record_selection(
        LiveSelectionTuple {
            authority: SelectionAuthority::None,
            ..tuple.clone()
        },
        false,
    );
    assert_eq!(facts.history.selections.len(), 2);
    assert_eq!(
        facts
            .history
            .selections
            .iter()
            .map(|tuple| (tuple.authority, tuple.count))
            .collect::<Vec<_>>(),
        [
            (SelectionAuthority::SelectionCountOnly, 1),
            (SelectionAuthority::None, 1),
        ]
    );

    let mut bounded = CaptureFacts::default();
    for flags in 0..MAX_LIVE_SELECTION_TUPLES {
        bounded.record_selection(
            LiveSelectionTuple {
                request: SelectionRequest {
                    flags: flags as u64,
                    ..tuple.request
                },
                authority: SelectionAuthority::None,
                ..tuple.clone()
            },
            false,
        );
    }
    assert!(bounded.can_record_selection(&LiveSelectionTuple {
        authority: SelectionAuthority::None,
        ..tuple.clone()
    }));
    assert!(
        !bounded.can_record_selection_claim(&LiveSelectionTuple {
            authority: SelectionAuthority::None,
            ..tuple.clone()
        }),
        "authority-distinct tuple is the seventeenth identity"
    );
    bounded.record_selection(tuple, false);
    assert_eq!(bounded.history.selections.len(), MAX_LIVE_SELECTION_TUPLES);
    assert!(bounded.history.selection_truncated);
}

#[test]
fn task_8d_public_selection_projection_preserves_authority_distinct_tuples() {
    let mut engine = Engine::empty();
    let stable = plan::ModuleId(0);
    let mut module = merged_module(vec!["scan"]);
    module.id = stable;
    engine.capture_facts.history.modules.insert(stable, module);
    let tuple = LiveSelectionTuple {
        module: stable,
        request: SelectionRequest {
            name: SelectionNameClass::ExactStandard,
            version: SelectionVersionClass::V3_0,
            flags: 0,
        },
        rv: 0,
        result: None,
        inventory_matches: Vec::new(),
        authority: SelectionAuthority::None,
        count: 2,
    };
    engine.capture_facts.history.selections.extend([
        tuple.clone(),
        LiveSelectionTuple {
            authority: SelectionAuthority::SelectionCountOnly,
            ..tuple
        },
    ]);

    let tuples = engine.interface_selection().tuples;
    assert_eq!(tuples.len(), 2);
    assert!(
        tuples
            .iter()
            .any(|tuple| { tuple.authority == SelectionAuthority::None && tuple.count == 2 })
    );
    assert!(tuples.iter().any(|tuple| {
        tuple.authority == SelectionAuthority::SelectionCountOnly && tuple.count == 2
    }));
}

#[test]
fn selection_claim_cap_is_checked_before_production_candidate_application() {
    let (_fixture, mut engine, mut session, binding) = attached_selection_route();
    let provider = engine.pinned.summary(binding.object).unwrap().key;
    let mapping =
        parse_maps(&std::fs::read(format!("/proc/{}/maps", engine.views[0].pid())).unwrap())
            .unwrap()
            .into_iter()
            .find(|mapping| ObjectKey::of(mapping) == provider)
            .unwrap();
    session.selection_table_read = Some((
        mapping,
        selection_only_table(
            &engine,
            binding,
            0x20,
            &[("C_Initialize", 0x100)],
            Vec::new(),
        ),
    ));
    let tuple = LiveSelectionTuple {
        module: binding.provider,
        request: SelectionRequest {
            name: SelectionNameClass::ExactStandard,
            version: SelectionVersionClass::V3_0,
            flags: 0,
        },
        rv: 0,
        result: Some(SelectionRequest {
            name: SelectionNameClass::ExactStandard,
            version: SelectionVersionClass::V3_0,
            flags: 0,
        }),
        inventory_matches: Vec::new(),
        authority: SelectionAuthority::None,
        count: 1,
    };
    engine.capture_facts.history.selections.push(tuple.clone());
    for flags in 1..MAX_LIVE_SELECTION_TUPLES {
        engine
            .capture_facts
            .history
            .selections
            .push(LiveSelectionTuple {
                request: SelectionRequest {
                    flags: flags as u64,
                    ..tuple.request
                },
                ..tuple.clone()
            });
    }
    let before_calls = session.attached_slots.len();
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
    record.pid_tgid = u64::from(engine.views[0].pid()) << 32;
    record.case_id = DISCOVERY_NAME_EXACT_STANDARD;
    record.interface_index = DISCOVERY_VERSION_V3_0;
    record.name_class = DISCOVERY_NAME_EXACT_STANDARD;
    record.selection_version_class = DISCOVERY_VERSION_V3_0;
    record.table_ptr = 1;
    record.binding_id = binding.id;
    let outcome = engine
        .dispatch_discovery_record(
            QueuedDiscoveryRecord {
                record,
                terminal_owner: None,
                terminal_exports: Vec::new(),
            },
            &mut session,
            &mut true,
            &mut PendingViewRetirements::new(),
            &mut BTreeSet::new(),
            &mut Vec::new(),
        )
        .unwrap();

    assert_eq!(outcome, DiscoveryRecordOutcome::applied(false, true));
    assert_eq!(session.attached_slots.len(), before_calls);
    assert!(engine.selection_claims.is_empty());
    assert!(engine.selection_tables.is_empty());
    assert_eq!(engine.capture_facts.history.selections.len(), 16);
    assert_eq!(engine.capture_facts.history.selections[0].count, 2);
    assert!(
        !engine.capture_facts.history.selections.iter().any(|known| {
            known.authority == SelectionAuthority::SelectionCountOnly
                && known.request == tuple.request
        })
    );
}

#[test]
fn public_selection_projection_is_sorted_bounded_and_address_free() {
    let mut engine = Engine::empty();
    let first = timing_key(1);
    let second = timing_key(2);
    engine
        .capture_facts
        .module_ids
        .insert(first.clone(), plan::ModuleId(0));
    engine
        .capture_facts
        .module_ids
        .insert(second.clone(), plan::ModuleId(1));
    for id in [plan::ModuleId(0), plan::ModuleId(1)] {
        let mut module = merged_module(vec!["scan"]);
        module.id = id;
        engine.capture_facts.history.modules.insert(id, module);
    }
    let surface = |provider, offset, name| InventorySurfaceKey {
        base: InventorySurfaceBase {
            provider,
            table_file_offset: offset,
            kind: InventorySurfaceKind::Interface,
            name,
            version: SelectionVersionClass::V3_0,
            flags: 0,
            manifest_identity: None,
        },
        duplicate: 0,
    };
    let first_surface = surface(
        first.clone(),
        10,
        PrivateSelectionName::Other(b"private-name-canary".to_vec()),
    );
    let later_surface = surface(first, 20, PrivateSelectionName::ExactStandard);
    engine
        .capture_facts
        .history
        .selection_surfaces
        .insert(surface(second, 1, PrivateSelectionName::ExactStandard));
    engine
        .capture_facts
        .history
        .selection_surfaces
        .insert(first_surface.clone());
    engine
        .capture_facts
        .history
        .selection_surfaces
        .insert(later_surface.clone());
    let tuple = LiveSelectionTuple {
        module: plan::ModuleId(0),
        request: SelectionRequest {
            name: SelectionNameClass::ExactStandard,
            version: SelectionVersionClass::V3_0,
            flags: 0,
        },
        rv: 0,
        result: Some(SelectionRequest {
            name: SelectionNameClass::ExactStandard,
            version: SelectionVersionClass::V3_0,
            flags: 0,
        }),
        inventory_matches: vec![
            LiveInventoryMatch {
                surface: later_surface.clone(),
                name_agrees: true,
                version_agrees: false,
            },
            LiveInventoryMatch {
                surface: first_surface.clone(),
                name_agrees: true,
                version_agrees: true,
            },
            LiveInventoryMatch {
                surface: later_surface,
                name_agrees: false,
                version_agrees: true,
            },
            LiveInventoryMatch {
                surface: first_surface,
                name_agrees: true,
                version_agrees: true,
            },
        ],
        authority: SelectionAuthority::Inventory,
        count: u64::MAX,
    };
    engine.capture_facts.history.selections.push(tuple.clone());
    engine.capture_facts.history.selections.push(tuple);

    let selection = engine.interface_selection();
    assert_eq!(
        selection
            .inventory_surfaces
            .iter()
            .map(|row| row.module)
            .collect::<Vec<_>>(),
        [0, 0, 1]
    );
    assert_eq!(
        selection.tuples[0]
            .inventory_matches
            .iter()
            .map(|matched| (matched.surface, matched.name_agrees, matched.version_agrees))
            .collect::<Vec<_>>(),
        [(0, true, true), (1, false, false)]
    );
    assert!(selection.selection_truncated);
    assert_eq!(selection.tuples[0].authority, SelectionAuthority::None);
    assert_eq!(selection.tuples[0].count, u64::MAX);
    assert_eq!(selection.tuples.len(), 1);
    let value = serde_json::to_value(&selection).unwrap();
    assert_eq!(
        value["tuples"][0]["inventory_matches"],
        serde_json::json!([
            {"surface": 0, "name_agrees": true, "version_agrees": true},
            {"surface": 1, "name_agrees": false, "version_agrees": false},
        ])
    );
    let json = serde_json::to_string(&value).unwrap();
    assert!(!json.contains("private-name-canary"));
    assert!(!json.contains("feed"));
}

#[test]
fn public_selection_module_rows_stop_at_exactly_512_dense_indices() {
    let (_fixture, _source, _session, binding) = attached_selection_route();
    for (count, truncated) in [(512, false), (513, true)] {
        let mut engine = Engine::empty();
        for index in 0..count {
            let stable = plan::ModuleId(index as u32);
            let mut module = merged_module(vec!["scan"]);
            module.id = stable;
            engine.capture_facts.history.modules.insert(stable, module);
            engine
                .capture_facts
                .history
                .standard_exports
                .insert(stable, BTreeSet::from([StandardExportFact::Present]));
            let mut retained = binding;
            retained.id = index as u64 + 1;
            retained.provider = stable;
            retained.observed = true;
            engine.selection_bindings.insert(retained.id, retained);
        }

        let selection = engine.interface_selection();
        let expected = (0..512.min(count as u32)).collect::<Vec<_>>();
        assert_eq!(
            selection
                .providers
                .iter()
                .map(|row| row.module)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            selection
                .standard_exports
                .iter()
                .map(|row| row.module)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(selection.selection_truncated, truncated);
    }
}

#[test]
fn public_module_indices_are_dense_after_stable_id_zero_is_refused() {
    let (_fixture, _source, _session, binding) = attached_selection_route();
    let mut engine = Engine::empty();
    let refused = timing_key(0);
    let first = timing_key(1);
    let second = timing_key(2);
    assert_eq!(
        engine.capture_facts.resolve_module_id(&refused).unwrap(),
        plan::ModuleId(0)
    );
    assert_eq!(
        engine.capture_facts.resolve_module_id(&first).unwrap(),
        plan::ModuleId(1)
    );
    assert_eq!(
        engine.capture_facts.resolve_module_id(&second).unwrap(),
        plan::ModuleId(2)
    );

    for (stable, public, key) in [
        (plan::ModuleId(1), 0, first),
        (plan::ModuleId(2), 1, second),
    ] {
        let mut module = merged_module(vec!["scan"]);
        module.id = stable;
        engine.capture_facts.history.modules.insert(stable, module);
        assert_eq!(engine.capture_facts.module_ids[&key], stable);
        engine
            .capture_facts
            .history
            .standard_exports
            .insert(stable, BTreeSet::from([StandardExportFact::Present]));
        let mut retained = binding;
        retained.id = u64::from(stable.0) + 10;
        retained.provider = stable;
        retained.observed = true;
        engine.selection_bindings.insert(retained.id, retained);
        assert_eq!(
            engine.selection_coverage(stable),
            Some(SelectionCoverageVerdict::Observed)
        );
        assert_eq!(public, usize::try_from(stable.0 - 1).unwrap());
    }
    engine
        .capture_facts
        .history
        .selections
        .push(LiveSelectionTuple {
            module: plan::ModuleId(2),
            request: SelectionRequest {
                name: SelectionNameClass::Null,
                version: SelectionVersionClass::Null,
                flags: 0,
            },
            rv: 1,
            result: None,
            inventory_matches: vec![],
            authority: SelectionAuthority::None,
            count: 1,
        });

    let selection = engine.interface_selection();
    assert_eq!(
        selection
            .providers
            .iter()
            .map(|row| row.module)
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert_eq!(
        selection
            .standard_exports
            .iter()
            .map(|row| row.module)
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert!(
        selection
            .standard_exports
            .iter()
            .all(|row| row.status == "present")
    );
    assert_eq!(selection.tuples[0].module, 1);
}

#[test]
fn invalid_selection_cross_reference_is_dropped_and_truncated() {
    let mut engine = Engine::empty();
    let provider = timing_key(1);
    let foreign = timing_key(2);
    engine
        .capture_facts
        .module_ids
        .insert(provider.clone(), plan::ModuleId(1));
    engine
        .capture_facts
        .module_ids
        .insert(foreign.clone(), plan::ModuleId(2));
    let mut module = merged_module(vec!["scan"]);
    module.id = plan::ModuleId(1);
    engine
        .capture_facts
        .history
        .modules
        .insert(module.id, module);
    let mut second_module = merged_module(vec!["scan"]);
    second_module.id = plan::ModuleId(2);
    engine
        .capture_facts
        .history
        .modules
        .insert(second_module.id, second_module);
    let foreign_surface = InventorySurfaceKey {
        base: InventorySurfaceBase {
            provider: foreign,
            table_file_offset: 1,
            kind: InventorySurfaceKind::Interface,
            name: PrivateSelectionName::ExactStandard,
            version: SelectionVersionClass::V3_0,
            flags: 0,
            manifest_identity: None,
        },
        duplicate: 0,
    };
    engine
        .capture_facts
        .history
        .selection_surfaces
        .insert(foreign_surface.clone());
    engine
        .capture_facts
        .history
        .selection_surfaces
        .insert(InventorySurfaceKey {
            base: InventorySurfaceBase {
                provider: timing_key(0),
                table_file_offset: 2,
                kind: InventorySurfaceKind::Legacy,
                name: PrivateSelectionName::Legacy,
                version: SelectionVersionClass::V2_40,
                flags: 0,
                manifest_identity: None,
            },
            duplicate: 0,
        });
    engine
        .capture_facts
        .history
        .selections
        .push(LiveSelectionTuple {
            module: plan::ModuleId(1),
            request: SelectionRequest {
                name: SelectionNameClass::ExactStandard,
                version: SelectionVersionClass::V3_0,
                flags: 0,
            },
            rv: 0,
            result: Some(SelectionRequest {
                name: SelectionNameClass::ExactStandard,
                version: SelectionVersionClass::V3_0,
                flags: 0,
            }),
            inventory_matches: vec![LiveInventoryMatch {
                surface: foreign_surface,
                name_agrees: true,
                version_agrees: true,
            }],
            authority: SelectionAuthority::Inventory,
            count: 1,
        });
    engine
        .capture_facts
        .history
        .selections
        .push(LiveSelectionTuple {
            module: plan::ModuleId(0),
            request: SelectionRequest {
                name: SelectionNameClass::Null,
                version: SelectionVersionClass::Null,
                flags: 0,
            },
            rv: 1,
            result: None,
            inventory_matches: vec![],
            authority: SelectionAuthority::None,
            count: 1,
        });

    let selection = engine.interface_selection();
    assert_eq!(selection.inventory_surfaces.len(), 1);
    assert_eq!(selection.inventory_surfaces[0].module, 1);
    assert_eq!(selection.tuples.len(), 1);
    assert!(selection.tuples[0].inventory_matches.is_empty());
    assert_eq!(selection.tuples[0].authority, SelectionAuthority::None);
    assert!(selection.selection_truncated);
}

#[test]
fn retained_standard_export_facts_project_through_public_selection() {
    let (_fixture, mut engine, _session, _binding) = attached_selection_route();
    engine.capture_facts.history.standard_exports.clear();
    engine.capture_facts.history.standard_requirements.clear();
    for id in 1..5 {
        let id = plan::ModuleId(id);
        let mut module = merged_module(vec!["manifest", "scan"]);
        module.id = id;
        engine.capture_facts.history.modules.insert(id, module);
    }
    let history = &mut engine.capture_facts.history;
    history.standard_exports.insert(
        plan::ModuleId(0),
        BTreeSet::from([StandardExportFact::Present]),
    );
    history.standard_requirements.insert(
        plan::ModuleId(1),
        BTreeSet::from([StandardRequirementFact::Legacy]),
    );
    history.standard_exports.insert(
        plan::ModuleId(1),
        BTreeSet::from([StandardExportFact::Absent]),
    );
    history.standard_exports.insert(
        plan::ModuleId(2),
        BTreeSet::from([StandardExportFact::Absent]),
    );
    history.standard_requirements.insert(
        plan::ModuleId(2),
        BTreeSet::from([StandardRequirementFact::V3]),
    );
    history.standard_exports.insert(
        plan::ModuleId(3),
        BTreeSet::from([StandardExportFact::Outside]),
    );
    history.standard_exports.insert(
        plan::ModuleId(4),
        BTreeSet::from([StandardExportFact::Absent, StandardExportFact::Present]),
    );

    let selection = engine.interface_selection();
    assert_eq!(
        selection
            .standard_exports
            .iter()
            .map(|export| (export.module, export.status))
            .collect::<Vec<_>>(),
        [
            (0, "present"),
            (1, "legacy_absent"),
            (2, "required_absent"),
            (3, "outside_module"),
            (4, "unresolved"),
        ]
    );
    let mut evidence = evidence_verdict(engine.plan(), engine.pinned(), &engine.counters);
    evidence.slots = 1;
    evidence.verdict();
    assert_eq!(evidence.completeness, "COMPLETE");
    evidence.interface_selection = selection;
    evidence.verdict();
    assert_eq!(evidence.completeness, "PARTIAL");
}

#[test]
fn standard_export_reducer_is_order_independent_and_fail_closed() {
    let present = BTreeSet::from([StandardExportFact::Present]);
    let absent = BTreeSet::from([StandardExportFact::Absent]);
    let outside = BTreeSet::from([StandardExportFact::Outside]);
    let conflicting = BTreeSet::from([StandardExportFact::Present, StandardExportFact::Absent]);
    let legacy = BTreeSet::from([StandardRequirementFact::Legacy]);
    let v3 = BTreeSet::from([StandardRequirementFact::V3]);
    let mixed = BTreeSet::from([StandardRequirementFact::Legacy, StandardRequirementFact::V3]);

    assert_eq!(standard_export_status(Some(&present), None), "present");
    assert_eq!(
        standard_export_status(Some(&outside), None),
        "outside_module"
    );
    assert_eq!(
        standard_export_status(Some(&absent), Some(&legacy)),
        "legacy_absent"
    );
    assert_eq!(
        standard_export_status(Some(&absent), Some(&v3)),
        "required_absent"
    );
    assert_eq!(standard_export_status(Some(&absent), None), "unresolved");
    assert_eq!(
        standard_export_status(Some(&absent), Some(&mixed)),
        "unresolved"
    );
    assert_eq!(
        standard_export_status(Some(&conflicting), Some(&v3)),
        "unresolved"
    );
}

#[test]
fn selection_unknown_result_flags_remain_factual_without_authority() {
    let (_fixture, mut engine, _session, binding) = attached_selection_route();
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
    record.pid_tgid = u64::from(engine.views[0].pid()) << 32;
    record.case_id = DISCOVERY_NAME_EXACT_STANDARD;
    record.interface_index = DISCOVERY_VERSION_V3_0;
    record.name_class = DISCOVERY_NAME_EXACT_STANDARD;
    record.selection_version_class = DISCOVERY_VERSION_V3_0;
    record.interface_flags = 1 << 63;
    record.table_ptr = selection_provider_address(&engine, binding);
    record.binding_id = binding.id;

    assert_eq!(
        engine.process_selection_record(&QueuedDiscoveryRecord {
            record,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        }),
        DiscoveryRecordOutcome::applied(false, true)
    );
    assert_eq!(
        engine.capture_facts.history.selections[0]
            .result
            .as_ref()
            .unwrap()
            .flags,
        1 << 63
    );
    assert!(engine.selection_claims.is_empty());
    assert!(engine.selection_tables.is_empty());
    assert!(!engine.capture_facts.history.selection_truncated);
}

#[test]
fn c_get_interface_selection_exact_match_keeps_inventory_aliases() {
    let (_fixture, mut engine, _session, binding) = attached_selection_route();
    let pid = engine.views[0].pid();
    let provider = engine.pinned.summary(binding.object).unwrap().key;
    let maps = parse_maps(&std::fs::read(format!("/proc/{pid}/maps")).unwrap()).unwrap();
    let map_index = MapIndex::new(&maps).expect("the target maps snapshot is valid");
    let address = maps
        .iter()
        .find(|mapping| ObjectKey::of(mapping) == provider)
        .unwrap()
        .start;
    let table_file_offset = match map_index.resolve(address) {
        Resolved::File { file_offset, .. } => file_offset,
        _ => unreachable!(),
    };
    engine.modules[0].scanned.tables.push(ScannedTable {
        version: (3, 0),
        walk: "full",
        entries: Vec::new(),
        null_entries: vec!["C_Initialize"],
        unpinned: Vec::new(),
        address,
        file_offset: Some(table_file_offset),
        live_return: false,
        manifest_supported: false,
    });
    engine.modules[0].entry_objects.push(Vec::new());
    engine.modules[0].scanned.interfaces.extend([
        ScannedInterface {
            index: 0,
            name_class: "exact_standard",
            name_lossy: None,
            name_private: Some(b"PKCS 11".to_vec()),
            flags: 0,
            table: Some(0),
        },
        ScannedInterface {
            index: 1,
            name_class: "exact_standard",
            name_lossy: None,
            name_private: Some(b"PKCS 11".to_vec()),
            flags: 1,
            table: Some(0),
        },
    ]);
    engine.publish_current_capture_facts().unwrap();
    let before_plan = engine.plan.clone();

    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
    record.pid_tgid = u64::from(pid) << 32;
    record.case_id = DISCOVERY_NAME_EXACT_STANDARD;
    record.interface_index = DISCOVERY_VERSION_V3_0;
    record.request_flags = 1;
    record.name_class = DISCOVERY_NAME_EXACT_STANDARD;
    record.selection_version_class = DISCOVERY_VERSION_V3_0;
    record.interface_flags = 1;
    record.table_ptr = address;
    record.binding_id = binding.id;
    assert_eq!(
        engine.process_selection_record(&QueuedDiscoveryRecord {
            record,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        }),
        DiscoveryRecordOutcome::applied(false, true)
    );

    let tuple = engine.capture_facts.history.selections.last().unwrap();
    assert_eq!(tuple.inventory_matches.len(), 3);
    assert_eq!(
        tuple
            .inventory_matches
            .iter()
            .filter(|matched| matched.name_agrees)
            .count(),
        2,
        "legacy has no name while both interface aliases remain distinct"
    );
    assert!(
        tuple
            .inventory_matches
            .iter()
            .all(|matched| matched.version_agrees)
    );
    let provider_module = tuple.module;
    assert_eq!(engine.plan, before_plan);

    record.name_class = DISCOVERY_NAME_UNREADABLE;
    engine.process_selection_record(&QueuedDiscoveryRecord {
        record,
        terminal_owner: None,
        terminal_exports: Vec::new(),
    });
    assert!(
        engine.capture_facts.history.selections[1]
            .inventory_matches
            .iter()
            .all(|matched| !matched.name_agrees),
        "unreadable classifications never agree"
    );

    record.name_class = DISCOVERY_NAME_EXACT_STANDARD;
    let losses = engine.capture_facts.history.losses.len();
    record.table_ptr = maps
        .iter()
        .find(|mapping| ObjectKey::of(mapping) != provider)
        .unwrap()
        .start;
    engine.process_selection_record(&QueuedDiscoveryRecord {
        record,
        terminal_owner: None,
        terminal_exports: Vec::new(),
    });
    let foreign = engine.capture_facts.history.selections.last().unwrap();
    assert_eq!(
        foreign.module, provider_module,
        "the hook owner stays the provider"
    );
    assert!(
        foreign.inventory_matches.is_empty(),
        "a returned pointer in another object never becomes an inventory match"
    );
    assert_eq!(engine.capture_facts.history.losses.len(), losses + 1);
    assert!(
        engine.capture_facts.history.losses.values().any(|loss| {
            loss.reason == "a successful selection result matched no inventory table"
        })
    );

    record.table_ptr = address;
    let original_key = engine
        .capture_facts
        .history
        .selection_inventory
        .keys()
        .next()
        .unwrap()
        .clone();
    let surfaces = engine
        .capture_facts
        .history
        .selection_inventory
        .remove(&original_key)
        .unwrap();
    let mut wrong_offset = original_key;
    wrong_offset.file_offset = wrong_offset.file_offset.saturating_add(1);
    engine
        .capture_facts
        .history
        .selection_inventory
        .insert(wrong_offset, surfaces);
    engine.process_selection_record(&QueuedDiscoveryRecord {
        record,
        terminal_owner: None,
        terminal_exports: Vec::new(),
    });
    let unmatched = engine
        .capture_facts
        .history
        .selections
        .iter()
        .find(|tuple| {
            tuple.result.is_some()
                && tuple.inventory_matches.is_empty()
                && tuple.request.flags == record.request_flags
        })
        .unwrap();
    assert_eq!(
        unmatched.count, 2,
        "the same inode and address cannot recover a stale table offset"
    );
}

#[test]
fn selection_facts_follow_capture_stage_commit_and_rollback() {
    let tuple = LiveSelectionTuple {
        module: plan::ModuleId(7),
        request: SelectionRequest {
            name: SelectionNameClass::Null,
            version: SelectionVersionClass::Null,
            flags: 0,
        },
        rv: 1,
        result: None,
        inventory_matches: Vec::new(),
        authority: SelectionAuthority::None,
        count: 1,
    };
    let mut facts = CaptureFacts::default();
    let provider = timing_key(0);
    let selection_surfaces = |start: usize, count: usize| {
        canonical_inventory_keys(
            (start..start + count)
                .map(|offset| InventorySurfaceBase {
                    provider: provider.clone(),
                    table_file_offset: offset as u64,
                    kind: InventorySurfaceKind::Interface,
                    name: PrivateSelectionName::ExactStandard,
                    version: SelectionVersionClass::V3_0,
                    flags: 0,
                    manifest_identity: None,
                })
                .collect(),
        )
    };
    let baseline_surfaces = facts.history.selection_surfaces.clone();
    let baseline_inventory = facts.history.selection_inventory.clone();
    let baseline_losses = facts.history.losses.clone();
    facts.begin_stage().unwrap();
    assert_eq!(
        admit_inventory_keys(
            facts.visible_history_mut(),
            selection_surfaces(0, MAX_LIVE_SELECTION_SURFACES),
        )
        .len(),
        MAX_LIVE_SELECTION_SURFACES
    );
    assert!(
        admit_inventory_keys(
            facts.visible_history_mut(),
            selection_surfaces(MAX_LIVE_SELECTION_SURFACES, 1),
        )
        .is_empty()
    );
    for flags in 0..17 {
        let mut distinct = tuple.clone();
        distinct.request.flags = flags;
        facts.record_selection(distinct, false);
    }
    let mut other_provider = tuple.clone();
    other_provider.module = plan::ModuleId(8);
    facts.record_selection(other_provider, false);
    assert_eq!(facts.visible_history().selections.len(), 16);
    assert!(facts.visible_history().selection_truncated);
    assert_eq!(facts.visible_history().losses.len(), 1);
    facts.rollback_stage();
    assert!(facts.history.selections.is_empty());
    assert_eq!(facts.history.selection_surfaces, baseline_surfaces);
    assert_eq!(facts.history.selection_inventory, baseline_inventory);
    assert_eq!(facts.history.losses, baseline_losses);
    assert!(!facts.history.selection_truncated);

    facts.begin_stage().unwrap();
    assert_eq!(
        admit_inventory_keys(
            facts.visible_history_mut(),
            selection_surfaces(0, MAX_LIVE_SELECTION_SURFACES),
        )
        .len(),
        MAX_LIVE_SELECTION_SURFACES
    );
    assert!(
        admit_inventory_keys(
            facts.visible_history_mut(),
            selection_surfaces(MAX_LIVE_SELECTION_SURFACES, 1),
        )
        .is_empty()
    );
    for flags in 0..17 {
        let mut distinct = tuple.clone();
        distinct.request.flags = flags;
        facts.record_selection(distinct, false);
    }
    let mut other_provider = tuple;
    other_provider.module = plan::ModuleId(8);
    facts.record_selection(other_provider, false);
    facts.commit_stage().unwrap();
    assert_eq!(
        facts.history.selection_surfaces.len(),
        MAX_LIVE_SELECTION_SURFACES
    );
    assert_eq!(facts.history.selections.len(), 16);
    assert!(facts.history.selection_truncated);
    assert_eq!(facts.history.losses.len(), 1);
}

#[test]
fn terminal_selection_success_survives_view_loss_as_unmatched_fact() {
    let (_fixture, mut engine, _session, binding) = attached_selection_route();
    engine
        .selection_bindings
        .get_mut(&binding.id)
        .unwrap()
        .retired = true;
    engine.loader_registry.tombstone(binding.context).unwrap();
    engine.views.clear();
    let identity = DynamicExportIdentity {
        object: binding.object,
        file_offset: binding.file_offset,
        cookie: binding.id,
        abi: binding.abi,
    };
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
    record.case_id = DISCOVERY_NAME_EXACT_STANDARD;
    record.interface_index = DISCOVERY_VERSION_V3_0;
    record.name_class = DISCOVERY_NAME_EXACT_STANDARD;
    record.selection_version_class = DISCOVERY_VERSION_V3_0;
    record.table_ptr = 0x1000;
    record.binding_id = binding.id;

    assert_eq!(
        engine
            .process_selection_record(&tagged_by_authority(binding.context, &[identity], record,)),
        DiscoveryRecordOutcome::applied(false, true)
    );
    let tuple = engine.capture_facts.history.selections.last().unwrap();
    assert!(tuple.result.is_some());
    assert!(tuple.inventory_matches.is_empty());
    assert!(engine.capture_facts.history.losses.values().any(|loss| {
        loss.reason == "a terminal selection result had no stable live table assessment"
    }));
    assert!(engine.selection_claims.is_empty());
    assert!(engine.selection_tables.is_empty());
}

#[test]
fn selection_occurrences_keep_canonical_null_and_alias_ordinals() {
    let mut engine = Engine::empty();
    let provider = timing_key(0);
    let table = ScannedTable {
        version: (3, 0),
        walk: "full",
        entries: vec![
            ScannedEntry {
                name: "C_Finalize",
                object: plan::TEST_OBJECT,
                object_path: "/provider.so".into(),
                file_offset: 0x40,
            },
            ScannedEntry {
                name: "C_GetInfo",
                object: plan::TEST_OBJECT,
                object_path: "/provider.so".into(),
                file_offset: 0x40,
            },
        ],
        null_entries: vec!["C_Initialize"],
        unpinned: Vec::new(),
        address: 0,
        file_offset: Some(0x20),
        live_return: false,
        manifest_supported: false,
    };

    engine.record_selection_occurrences(plan::ModuleId(7), provider, &table);

    let occurrences: Vec<_> = engine
        .capture_facts
        .history
        .decoded
        .iter()
        .filter_map(|occurrence| match occurrence {
            DecodedOccurrence::Selection {
                ordinal,
                name,
                object,
                ..
            } => Some((*ordinal, *name, object.is_some())),
            _ => None,
        })
        .collect();
    assert_eq!(occurrences.len(), 3);
    assert!(occurrences.contains(&(
        crate::kinds::function_id("C_Initialize").unwrap() as u16,
        "C_Initialize",
        false,
    )));
    assert!(occurrences.contains(&(
        crate::kinds::function_id("C_Finalize").unwrap() as u16,
        "C_Finalize",
        true,
    )));
    assert!(occurrences.contains(&(
        crate::kinds::function_id("C_GetInfo").unwrap() as u16,
        "C_GetInfo",
        true,
    )));
}

#[test]
fn selection_semantic_key_reuses_same_table_and_refuses_changed_targets() {
    let (_fixture, mut engine, _session, binding) = attached_selection_route();
    let provider = engine.pinned.owned_timing_key(binding.object).unwrap();
    let result = SelectionRequest {
        name: SelectionNameClass::ExactStandard,
        version: SelectionVersionClass::V3_0,
        flags: 0,
    };
    let first = selection_only_table(
        &engine,
        binding,
        0x20,
        &[("C_Initialize", 0x100), ("C_Finalize", 0x108)],
        Vec::new(),
    );
    let (claims, tables, _) = engine
        .propose_selection_claim(&binding, provider.clone(), &first, &result)
        .unwrap();
    engine.selection_claims = claims.clone();
    engine.selection_tables = tables.clone();

    let (same_claims, same_tables, _) = engine
        .propose_selection_claim(&binding, provider.clone(), &first, &result)
        .unwrap();
    assert_eq!(same_claims, claims);
    assert_eq!(same_tables, tables);

    engine.selection_claims.clear();
    assert_eq!(engine.selection_tables, tables);

    let changed = selection_only_table(
        &engine,
        binding,
        0x20,
        &[("C_Initialize", 0x100), ("C_Finalize", 0x110)],
        Vec::new(),
    );
    assert!(
        engine
            .propose_selection_claim(&binding, provider, &changed, &result)
            .is_none()
    );
    assert!(engine.selection_claims.is_empty());
    assert_eq!(engine.selection_tables, tables);
    assert!(engine.capture_facts.history.selection_truncated);
}

#[test]
fn selection_table_partial_attach_rolls_back_the_successful_prefix() {
    let (_fixture, mut engine, mut session, binding) = attached_selection_route();
    let provider = engine.pinned.owned_timing_key(binding.object).unwrap();
    let table = selection_only_table(
        &engine,
        binding,
        0x20,
        &[("C_Initialize", 0x100), ("C_Finalize", 0x108)],
        Vec::new(),
    );
    let result = SelectionRequest {
        name: SelectionNameClass::ExactStandard,
        version: SelectionVersionClass::V3_0,
        flags: 0,
    };
    let (claims, tables, pending) = engine
        .propose_selection_claim(&binding, provider, &table, &result)
        .unwrap();
    let raw_modules = engine
        .modules
        .iter()
        .map(|module| module.scanned.clone())
        .collect();
    let candidate = engine
        .live_candidate_with_selection(engine.pinned.clone(), raw_modules, claims, tables, pending)
        .unwrap();
    assert_eq!(candidate.delta.new.len(), 2);
    session.fail_target_slots([candidate.delta.new[1].index]);

    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut true, false, &[])
        .unwrap();

    assert!(!outcome.selection_authorized);
    assert!(engine.selection_claims.is_empty());
    assert!(engine.selection_tables.is_empty());
    assert!(
        engine
            .plan
            .slots
            .iter()
            .filter(|slot| matches!(slot.file_offset, 0x100 | 0x108))
            .all(|slot| !engine.plan.is_active(slot.index))
    );
    assert_eq!(session.attached_slots.last(), Some(&2));
    assert_eq!(
        session.detached_slots.iter().rev().take(2).sum::<usize>(),
        2
    );
}

#[test]
fn selection_candidate_preflight_refusal_keeps_claims_and_latch_unchanged() {
    let (_fixture, mut engine, _session, binding) = attached_selection_route();
    let table = selection_only_table(
        &engine,
        binding,
        0x20,
        &[("C_Initialize", 0x100)],
        Vec::new(),
    );
    let result = SelectionRequest {
        name: SelectionNameClass::ExactStandard,
        version: SelectionVersionClass::V3_0,
        flags: 0,
    };
    let (claims, tables, pending) = engine
        .propose_selection_claim(
            &binding,
            engine.pinned.owned_timing_key(binding.object).unwrap(),
            &table,
            &result,
        )
        .unwrap();
    let candidate = engine
        .live_candidate_with_selection(
            engine.pinned.clone(),
            engine
                .modules
                .iter()
                .map(|module| module.scanned.clone())
                .collect(),
            claims,
            tables,
            pending,
        )
        .unwrap();
    let before_plan = engine.plan.clone();
    let mut session = ScriptedSession::refusing_preflight();

    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut true, false, &[])
        .unwrap();

    assert!(!outcome.selection_authorized);
    assert_eq!(engine.plan, before_plan);
    assert!(engine.selection_claims.is_empty());
    assert!(engine.selection_tables.is_empty());
    assert!(session.attached_slots.is_empty());
}

#[test]
fn selection_rollback_does_not_restore_a_latch_after_generation_loss() {
    let (_fixture, mut engine, _session, binding) = attached_selection_route();
    let table = selection_only_table(
        &engine,
        binding,
        0x20,
        &[("C_Initialize", 0x100)],
        Vec::new(),
    );
    let result = SelectionRequest {
        name: SelectionNameClass::ExactStandard,
        version: SelectionVersionClass::V3_0,
        flags: 0,
    };
    let provider = engine.pinned.owned_timing_key(binding.object).unwrap();
    let (_, latched, _) = engine
        .propose_selection_claim(&binding, provider.clone(), &table, &result)
        .unwrap();
    engine.selection_tables = latched;
    let (claims, tables, pending) = engine
        .propose_selection_claim(&binding, provider, &table, &result)
        .unwrap();
    let candidate = engine
        .live_candidate_with_selection(
            engine.pinned.clone(),
            engine
                .modules
                .iter()
                .map(|module| module.scanned.clone())
                .collect(),
            claims,
            tables,
            pending,
        )
        .unwrap();
    let mut session = ScriptedSession::losing_generation_at_attach(engine.views[0].pid());

    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut true, false, &[])
        .unwrap();

    assert!(!outcome.selection_authorized);
    assert!(engine.selection_claims.is_empty());
    assert!(engine.selection_tables.is_empty());
}

#[test]
fn selection_inventory_keys_are_canonical_bounded_and_pruned() {
    let (_fixture, engine, _session, binding) = attached_selection_route();
    let provider = engine.pinned.owned_timing_key(binding.object).unwrap();
    let base = |table_file_offset, name, flags| InventorySurfaceBase {
        provider: provider.clone(),
        table_file_offset,
        kind: InventorySurfaceKind::Interface,
        name,
        version: SelectionVersionClass::V3_0,
        flags,
        manifest_identity: None,
    };
    let first = base(0x20, PrivateSelectionName::Other(b"alpha".to_vec()), 0);
    let second = base(0x20, PrivateSelectionName::Other(b"beta".to_vec()), 1);
    assert_eq!(
        canonical_inventory_keys(vec![first.clone(), second.clone()]),
        canonical_inventory_keys(vec![second.clone(), first.clone()]),
        "enumeration order does not change canonical aliases"
    );
    assert_ne!(
        canonical_inventory_keys(vec![first.clone()]),
        canonical_inventory_keys(vec![second.clone()]),
        "private names and flags remain part of alias identity"
    );
    assert_ne!(
        canonical_inventory_keys(vec![first.clone()]),
        canonical_inventory_keys(vec![base(
            0x28,
            PrivateSelectionName::Other(b"alpha".to_vec()),
            0,
        )]),
        "the same apparent alias at another table offset stays distinct"
    );
    let duplicates = canonical_inventory_keys(vec![first.clone(), first]);
    assert_eq!(duplicates[0].duplicate, 0);
    assert_eq!(duplicates[1].duplicate, 1);

    let mut history = CaptureHistory::default();
    let first_512 = (0..MAX_LIVE_SELECTION_SURFACES)
        .map(|offset| base(offset as u64, PrivateSelectionName::ExactStandard, 0))
        .collect();
    assert_eq!(
        admit_inventory_keys(&mut history, canonical_inventory_keys(first_512)).len(),
        MAX_LIVE_SELECTION_SURFACES
    );
    let overflow = canonical_inventory_keys(vec![base(
        MAX_LIVE_SELECTION_SURFACES as u64,
        PrivateSelectionName::ExactStandard,
        0,
    )]);
    assert!(admit_inventory_keys(&mut history, overflow).is_empty());
    assert_eq!(
        history.selection_surfaces.len(),
        MAX_LIVE_SELECTION_SURFACES
    );
    assert!(history.selection_truncated);
    assert_eq!(history.losses.len(), 1);

    let surface = history.selection_surfaces.iter().next().unwrap().clone();
    for view in [ProcessViewId(1), ProcessViewId(2)] {
        history.selection_inventory.insert(
            ExactSelectionTable {
                view,
                provider: provider.clone(),
                address: 0x1000,
                file_offset: 0,
            },
            vec![surface.clone()],
        );
    }
    prune_selection_inventory(&mut history, &[ProcessViewId(2)].into_iter().collect());
    assert_eq!(history.selection_inventory.len(), 1);
    assert!(
        history
            .selection_inventory
            .keys()
            .all(|table| table.view == ProcessViewId(2))
    );

    let before = parse_maps(b"00001000-00002000 r--p 00000000 08:01 9 /opt/provider.so\n").unwrap();
    let remapped =
        parse_maps(b"00001000-00002000 r--p 00001000 08:01 9 /opt/provider.so\n").unwrap();
    assert!(!stable_selection_mapping(before.first(), remapped.first()));
}

#[test]
fn selection_assessment_rejects_remap_view_loss_and_pin_change() {
    // The bracket's verdict paired with the call order it took: the events
    // are the point of this test, since a bracket that reaches the right
    // answer without reading maps twice is not the bracket.
    type AssessOutcome = (Result<(Option<MapEntry>, Resolved), ()>, Vec<&'static str>);
    fn assess(
        table_ptr: u64,
        before: Vec<MapEntry>,
        after: Vec<MapEntry>,
        view_same: bool,
        pin_same: bool,
    ) -> AssessOutcome {
        let mut snapshots = [before, after].into_iter();
        let events = std::cell::RefCell::new(Vec::new());
        let result = selection_mapping_bracket(
            table_ptr,
            || {
                events.borrow_mut().push("maps");
                snapshots.next().ok_or(())
            },
            || {
                events.borrow_mut().push("view");
                view_same
            },
            || {
                events.borrow_mut().push("pin");
                pin_same
            },
        );
        (result, events.into_inner())
    }

    let stable = parse_maps(b"00001000-00002000 r--p 00000000 08:01 9 /opt/provider.so\n").unwrap();
    let remapped =
        parse_maps(b"00001000-00002000 r--p 00001000 08:01 9 /opt/provider.so\n").unwrap();
    let (result, events) = assess(0x1000, stable.clone(), remapped, true, true);
    assert!(result.is_err());
    assert_eq!(events, ["maps", "maps", "view", "pin"]);
    assert!(
        assess(0x1000, stable.clone(), stable.clone(), false, true)
            .0
            .is_err()
    );
    assert!(
        assess(0x1000, stable.clone(), stable.clone(), true, false)
            .0
            .is_err()
    );

    let (absent, events) = assess(0x3000, stable.clone(), stable.clone(), true, true);
    assert_eq!(absent, Ok((None, Resolved::Unmapped)));
    assert_eq!(events, ["maps", "maps", "view", "pin"]);

    let invalid = vec![
        MapEntry {
            start: 0x1000,
            end: 0x3000,
            file_offset: 0,
            permissions: *b"r--p",
            device: Device { major: 8, minor: 1 },
            inode: 9,
            raw_path: Some(b"/opt/provider.so".to_vec()),
        },
        MapEntry {
            start: 0x2000,
            end: 0x4000,
            file_offset: 0,
            permissions: *b"rw-p",
            device: Device { major: 0, minor: 0 },
            inode: 0,
            raw_path: None,
        },
    ];
    let (invalid_a, events) = assess(0x1000, invalid.clone(), stable.clone(), true, true);
    assert!(invalid_a.is_err());
    assert_eq!(events, ["maps"]);

    let (invalid_b, events) = assess(0x1000, stable, invalid, true, true);
    assert!(invalid_b.is_err());
    assert_eq!(events, ["maps", "maps"]);
}

#[test]
fn initial_export_generation_loss_queues_retirement_before_readiness() {
    let (_fixture, mut engine, mut session) = initial_export_route();
    let view = engine.views[0].id();
    session.lose_generation_at_dynamic_attach(engine.views[0].pid());
    let mut additions_allowed = true;
    let mut pending = PendingViewRetirements::new();
    let mut closure = PauseClosure::new(true);

    engine.attach_initial_exports(
        &mut session,
        &mut additions_allowed,
        &mut pending,
        &mut closure,
    );

    assert!(!additions_allowed);
    assert!(pending.contains_key(&view));
    assert!(!closure.required_complete());
}

#[test]
fn rt_add_deferral_state_table_keeps_zero_ambiguous_and_defers_add_delete() {
    for (state, read_failures, expected_pending, expected_memory_scans) in
        [(0, 0, 0, 1), (0, 1, 0, 1), (1, 0, 1, 0), (2, 0, 1, 0)]
    {
        let (_fixture, mut engine, _context, mut record, mut session) = armed_seed_route(1);
        record.announced_count = state;
        session.counters.loader_state_read_failures = read_failures;

        apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();

        assert_eq!(
            engine.pending_loader_scans.len(),
            expected_pending,
            "r_state={state}, read_failures={read_failures}"
        );
        assert_eq!(
            engine.loader_memory_scan_attempts, expected_memory_scans,
            "r_state={state}, read_failures={read_failures}"
        );
        if state == 0 {
            let aggregate = engine.loader_discovery();
            assert_eq!(aggregate.dlopen_timing.qualified_pre_constructor, 0);
            assert_eq!(aggregate.dlopen_timing.known_pre_relocation, 0);
            assert_eq!(aggregate.dlopen_timing.unproven, 1);
            assert_eq!(aggregate.state_read_failures, read_failures);
        }
    }
}

/// Mutation caught: scanning before queuing `RT_ADD` races the loader, and
/// returning before the rest of the handler fails to arm standard exports.
#[test]
fn rt_add_deferral_authenticated_add_accounts_and_arms_without_memory_scan() {
    let (_fixture, mut engine, context, mut record, mut session) = armed_seed_route(1);
    record.announced_count = 1;

    let outcome = apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();

    assert!(outcome.required_complete);
    assert_eq!(engine.loader_records_accepted, 1);
    assert_eq!(engine.loader_memory_scan_attempts, 0);
    assert_eq!(session.dynamic_attach_calls.len(), 3);
    assert_eq!(
        engine
            .pending_loader_scans
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        [PendingLoaderScanKey {
            view: ProcessViewId(0),
            context,
        }]
    );
    assert!(engine.pending_loader_scans.len() <= crate::discovery::loader::MAX_LOADER_CONTEXTS);
}

/// Mutation caught: replaying the original ADD consumes producer authority
/// twice; omitting the independent-tick fallback leaves work pending forever.
#[test]
fn rt_add_deferral_next_tick_falls_back_once_without_record_replay() {
    let (_fixture, mut engine, _context, mut record, mut session) = armed_seed_route(1);
    record.announced_count = 1;
    apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();
    assert_eq!(engine.pending_loader_scans.len(), 1);
    assert_eq!(engine.loader_memory_scan_attempts, 0);

    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

    assert!(engine.pending_loader_scans.is_empty());
    assert_eq!(engine.loader_memory_scan_attempts, 1);
    assert_eq!(engine.loader_records_accepted, 1);
}

/// Mutation caught: keying pending work by event occurrence instead of the
/// exact view/context lets duplicate ADDs grow the bounded ledger.
#[test]
fn rt_add_deferral_duplicate_adds_coalesce_and_settle_once() {
    let (_fixture, mut engine, _context, mut record, mut session) = armed_seed_route(2);
    record.announced_count = 1;

    apply_ordinary_batch(&mut engine, &mut session, vec![record, record]).unwrap();

    assert_eq!(engine.pending_loader_scans.len(), 1);
    assert_eq!(engine.loader_memory_scan_attempts, 0);
    assert_eq!(engine.loader_records_accepted, 2);
    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();
    assert!(engine.pending_loader_scans.is_empty());
    assert_eq!(engine.loader_memory_scan_attempts, 1);
    assert_eq!(engine.loader_records_accepted, 2);
}

/// Mutation caught: an expected process exit cannot silently discard a
/// deferred memory acquisition that never ran.
#[test]
fn rt_add_deferral_expected_exit_settles_pending_as_loss() {
    let (_fixture, mut engine, _context, mut record, mut session) = armed_seed_route(1);
    record.announced_count = 1;
    apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();
    let mut pending_views = PendingViewRetirements::new();

    engine.queue_retirement(
        ProcessViewId(0),
        RetirementCause::ExpectedRemoval,
        &mut pending_views,
    );

    assert!(engine.pending_loader_scans.is_empty());
    assert!(engine.counters.object_skips.iter().any(|skip| {
        skip.subject == "live loader memory discovery"
            && skip.reason.contains("expected process exit")
    }));
}

/// Mutation caught: replacing a loader context cannot transfer its pending
/// scan authority to the replacement context.
#[test]
fn rt_add_deferral_context_retirement_settles_pending_as_loss() {
    let (_fixture, mut engine, _context, mut record, mut session) = armed_seed_route(1);
    record.announced_count = 2;
    apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();
    let mut pending_views = PendingViewRetirements::new();

    engine.queue_retirement(
        ProcessViewId(0),
        RetirementCause::ExecRefresh,
        &mut pending_views,
    );

    assert!(engine.pending_loader_scans.is_empty());
    assert!(engine.counters.object_skips.iter().any(|skip| {
        skip.subject == "live loader memory discovery"
            && skip.reason.contains("loader context retirement")
    }));
}

/// Mutation caught: a sticky work-ceiling stop must resolve the pending
/// ledger to loss instead of preserving an impossible fallback.
#[test]
fn rt_add_deferral_budget_exhaustion_settles_pending_as_loss() {
    let (_fixture, mut engine, _context, mut record, mut session) = armed_seed_route(1);
    record.announced_count = 1;
    apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();
    assert!(!engine.budget.charge(u64::MAX));

    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

    assert!(engine.pending_loader_scans.is_empty());
    assert_eq!(engine.loader_memory_scan_attempts, 0);
    assert!(engine.counters.object_skips.iter().any(|skip| {
        skip.subject == "live loader memory discovery" && skip.reason.contains("budget exhaustion")
    }));
}

/// Mutation caught: cancellation/shutdown finalization must turn every
/// still-pending scan into published loss evidence.
#[test]
fn rt_add_deferral_cancellation_or_shutdown_settles_pending_as_loss() {
    let (_fixture, mut engine, _context, mut record, mut session) = armed_seed_route(1);
    record.announced_count = 1;
    apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();

    engine.settle_terminal_drain();

    assert!(engine.pending_loader_scans.is_empty());
    assert!(engine.plan.skipped.iter().any(|skip| {
        skip.subject == "live loader memory discovery"
            && skip.reason.contains("capture cancellation or shutdown")
    }));
}

#[test]
fn loader_batch_route_adds_one_count_only_seed_without_table_surface() {
    let (_dir, mut engine, _context, record, mut session) = armed_seed_route(2);
    engine.capture_facts.next_module_id = 7;
    let first = apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();

    assert!(first.required_complete);
    assert_eq!(
        session
            .attached_slots
            .iter()
            .filter(|count| **count > 0)
            .count(),
        1
    );
    assert_eq!(engine.plan.entries_seen, 0);
    assert!(engine.plan.surfaces.is_empty());
    let binding = engine
        .selection_bindings
        .values()
        .next()
        .expect("the newly loader-discovered provider has a selection binding");
    let provider = engine
        .plan
        .modules
        .iter()
        .find(|module| module.object == binding.object)
        .expect("the selection hook owner has a committed provider module");
    assert_eq!(binding.provider, provider.id);
    assert_eq!(binding.provider, plan::ModuleId(7));
    assert_eq!(
        engine
            .plan
            .slots
            .iter()
            .filter(|slot| engine.plan.is_active(slot.index))
            .count(),
        1
    );
    assert_eq!(
        engine.plan.slots[0].names,
        ["C_GetFunctionList"],
        "the seed owns descriptor zero"
    );

    let second = apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();
    assert!(second.required_complete);
    assert_eq!(
        session
            .attached_slots
            .iter()
            .filter(|count| **count > 0)
            .count(),
        1,
        "an exact repeated loader record does not reattach the seed"
    );
    assert_eq!(
        session.dynamic_attach_calls.len(),
        3,
        "an exact repeated loader record does not reattach the exports"
    );
    assert_eq!(
        engine
            .plan
            .slots
            .iter()
            .filter(|slot| engine.plan.is_active(slot.index))
            .count(),
        1
    );
}

#[test]
fn terminal_loader_batch_route_seeds_without_dynamic_attach() {
    let (_fixture, mut engine, context, record, mut session) = armed_seed_route(1);
    engine
        .begin_terminal_drain(context, Vec::new(), || Ok::<(), anyhow::Error>(()))
        .unwrap()
        .unwrap();
    engine.retain_terminal_batch([record], true, 0).unwrap();
    let mut collect = Engine::collect_discovery_records;
    let terminal = engine
        .apply_discovery_batch_with(&mut session, Vec::new(), 0, true, true, &mut collect, None)
        .unwrap();

    assert!(terminal.required_complete);
    assert!(engine.loader_registry.context(context).is_none());
    assert!(session.dynamic_attach_calls.is_empty());
    assert_eq!(
        session
            .attached_slots
            .iter()
            .filter(|count| **count > 0)
            .count(),
        1,
        "the terminal replay does not attach a duplicate static seed"
    );
    assert_eq!(
        engine
            .plan
            .slots
            .iter()
            .filter(|slot| engine.plan.is_active(slot.index))
            .count(),
        1
    );
}

#[test]
fn loader_batch_route_seed_target_failure_deactivates_slot() {
    let (_fixture, mut engine, _context, record, mut session) = armed_seed_route(1);
    session.fail_target_slots([0]);

    let outcome = apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();

    assert!(!outcome.required_complete);
    assert!(!engine.plan.is_active(0));
    assert_eq!(engine.plan.slots[0].descriptor_index, 0);
    assert_eq!(engine.plan.slots[0].names, ["C_GetFunctionList"]);
    assert_eq!(engine.plan.entries_seen, 0);
    assert!(engine.plan.surfaces.is_empty());
    assert_eq!(
        session
            .attached_slots
            .iter()
            .filter(|count| **count > 0)
            .count(),
        1
    );
    assert!(session.detached_slots.contains(&1));
}

#[test]
fn failed_detach_blocks_fresh_attachment_in_a_later_loader_batch() {
    let (_fixture, mut engine, context, record, mut session) = armed_seed_route(2);
    let loader_identity = *session
        .dynamic_loader_links
        .first()
        .expect("the loader route owns its initial dynamic link");
    let export_target = (loader_identity.1, loader_identity.2);
    let export_cookie = u64::MAX;
    assert!(
        !session
            .attach_dynamic_export(
                context,
                engine.views[0].pid(),
                export_target,
                export_cookie,
                HookAbi::FunctionList,
                &engine.pinned,
            )
            .unwrap()
            .0
    );
    let detach_calls_before = session.detached_slot_indices.len();
    session.fail_target_slots([0]);
    session.fail_slot_detaches([false, true]);

    let first = apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();
    assert!(!first.required_complete);
    assert_eq!(
        session.detach_failures(),
        ["scripted one-shot slot detach failed"]
    );
    assert!(!engine.plan.is_active(0));
    let first_target = session
        .preflight_targets
        .borrow()
        .iter()
        .flatten()
        .copied()
        .find(|(slot, _, _)| *slot == 0)
        .expect("the first batch proposed slot 0");
    let static_attempts = session
        .attached_slots
        .iter()
        .filter(|count| **count > 0)
        .count();
    assert_eq!(
        static_attempts, 1,
        "the first batch attempted one nonempty static attachment"
    );
    let dynamic_attempts = session.dynamic_attach_calls.len();
    let cleanup_attempts = session.detached_slot_indices.clone();
    assert_eq!(
        cleanup_attempts[detach_calls_before..],
        [Vec::new(), vec![0]],
        "the failed detach was the exact cleanup of failed slot 0"
    );

    let second = apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();

    assert!(!second.required_complete);
    let later_target = session
        .preflight_targets
        .borrow()
        .iter()
        .flatten()
        .copied()
        .find(|(slot, _, _)| *slot == 1)
        .expect("the later batch proposed a fresh slot ID");
    assert_eq!(
        (later_target.1, later_target.2),
        (first_target.1, first_target.2),
        "the later batch rediscovered the same object and offset"
    );
    assert_eq!(
        session
            .attached_slots
            .iter()
            .filter(|count| **count > 0)
            .count(),
        static_attempts,
        "the persistent failed-detach evidence blocks a later static attach"
    );
    assert_eq!(session.dynamic_attach_calls.len(), dynamic_attempts);
    assert_eq!(session.detached_slot_indices, cleanup_attempts);
    assert_eq!(
        session.detach_failures(),
        ["scripted one-shot slot detach failed"]
    );

    session.preflight_targets(&[], &engine.pinned).unwrap();
    session.attach_targets(&[], &engine.pinned).unwrap();
    assert_eq!(session.attached_slots.last(), Some(&0));
    assert_eq!(
        session
            .attach_dynamic_export(
                context,
                engine.views[0].pid(),
                export_target,
                export_cookie,
                HookAbi::FunctionList,
                &engine.pinned,
            )
            .unwrap(),
        (false, None),
        "an existing dynamic export remains a no-op after admission closes"
    );
    assert!(
        !session
            .attach_dynamic_loader(
                loader_identity.0,
                engine.views[0].pid(),
                loader_identity.1,
                loader_identity.2,
                loader_identity.3,
                &engine.pinned,
            )
            .unwrap(),
        "an existing loader link remains a no-op after admission closes"
    );
    session.detach_slots(&[]).unwrap();
    assert_eq!(session.detached_slot_indices.last(), Some(&Vec::new()));
}

#[test]
fn scripted_dynamic_retirement_removes_only_the_selected_context_ownership() {
    let (_fixture, engine, context, _record, mut session) = armed_seed_route(2);
    let loader_identity = session.dynamic_loader_links[0];
    let export_target = (loader_identity.1, loader_identity.2);
    let export_cookie = u64::MAX;
    let other_context = LoaderContextId::from_case_id(7);

    for owner in [context, other_context] {
        session
            .attach_dynamic_export(
                owner,
                engine.views[0].pid(),
                export_target,
                export_cookie,
                HookAbi::FunctionList,
                &engine.pinned,
            )
            .unwrap();
        session
            .attach_dynamic_loader(
                owner,
                engine.views[0].pid(),
                loader_identity.1,
                loader_identity.2,
                loader_identity.3,
                &engine.pinned,
            )
            .unwrap();
    }
    let export_attempts = session.dynamic_attach_calls.len();
    let loader_attempts = session.dynamic_loader_attach_calls;

    assert!(!session.detach_dynamic_context(context).1);
    assert_eq!(
        session
            .attach_dynamic_export(
                other_context,
                engine.views[0].pid(),
                export_target,
                export_cookie,
                HookAbi::FunctionList,
                &engine.pinned,
            )
            .unwrap(),
        (false, None),
        "another context retains its valid export-link no-op"
    );
    assert!(
        !session
            .attach_dynamic_loader(
                other_context,
                engine.views[0].pid(),
                loader_identity.1,
                loader_identity.2,
                loader_identity.3,
                &engine.pinned,
            )
            .unwrap(),
        "another context retains its valid loader-link no-op"
    );
    assert_eq!(session.dynamic_attach_calls.len(), export_attempts);
    assert_eq!(session.dynamic_loader_attach_calls, loader_attempts);

    session
        .attach_dynamic_export(
            context,
            engine.views[0].pid(),
            export_target,
            export_cookie,
            HookAbi::FunctionList,
            &engine.pinned,
        )
        .unwrap();
    session
        .attach_dynamic_loader(
            context,
            engine.views[0].pid(),
            loader_identity.1,
            loader_identity.2,
            loader_identity.3,
            &engine.pinned,
        )
        .unwrap();
    assert_eq!(session.dynamic_attach_calls.len(), export_attempts + 1);
    assert_eq!(session.dynamic_loader_attach_calls, loader_attempts + 1);
}

#[test]
fn scripted_failed_dynamic_retirement_refuses_retired_identity_but_keeps_other_context() {
    let (_fixture, engine, context, _record, mut session) = armed_seed_route(2);
    let loader_identity = session.dynamic_loader_links[0];
    let export_target = (loader_identity.1, loader_identity.2);
    let export_cookie = u64::MAX;
    let other_context = LoaderContextId::from_case_id(7);

    for owner in [context, other_context] {
        session
            .attach_dynamic_export(
                owner,
                engine.views[0].pid(),
                export_target,
                export_cookie,
                HookAbi::FunctionList,
                &engine.pinned,
            )
            .unwrap();
        session
            .attach_dynamic_loader(
                owner,
                engine.views[0].pid(),
                loader_identity.1,
                loader_identity.2,
                loader_identity.3,
                &engine.pinned,
            )
            .unwrap();
    }
    let export_attempts = session.dynamic_attach_calls.len();
    let loader_attempts = session.dynamic_loader_attach_calls;
    session.detach_failed = true;

    assert!(session.detach_dynamic_context(context).1);
    assert_eq!(
        session
            .attach_dynamic_export(
                context,
                engine.views[0].pid(),
                export_target,
                export_cookie,
                HookAbi::FunctionList,
                &engine.pinned,
            )
            .unwrap_err()
            .to_string(),
        "new producer attachment is refused after a detach bookkeeping failure; start a new session"
    );
    match session
        .attach_dynamic_loader(
            context,
            engine.views[0].pid(),
            loader_identity.1,
            loader_identity.2,
            loader_identity.3,
            &engine.pinned,
        )
        .unwrap_err()
    {
        DynamicLoaderAttachFailure::Registry(error) => assert_eq!(
            error.to_string(),
            "new producer attachment is refused after a detach bookkeeping failure; start a new session"
        ),
        error => panic!("retired loader identity had the wrong refusal cause: {error}"),
    }
    assert_eq!(
        session
            .attach_dynamic_export(
                other_context,
                engine.views[0].pid(),
                export_target,
                export_cookie,
                HookAbi::FunctionList,
                &engine.pinned,
            )
            .unwrap(),
        (false, None)
    );
    assert!(
        !session
            .attach_dynamic_loader(
                other_context,
                engine.views[0].pid(),
                loader_identity.1,
                loader_identity.2,
                loader_identity.3,
                &engine.pinned,
            )
            .unwrap()
    );
    assert_eq!(session.dynamic_attach_calls.len(), export_attempts);
    assert_eq!(session.dynamic_loader_attach_calls, loader_attempts);
}

#[test]
fn exact_pinned_executable_export_collects_one_count_only_seed() {
    let (_fixture, view, module, pins) = loaded_seed_provider();
    let mut engine = Engine::empty();
    let candidate = engine
        .live_candidate(pins, vec![module.clone()], Vec::new())
        .unwrap();
    let object = candidate
        .pinned
        .id_for_scanned(&module, module.key, &module.path)
        .unwrap();
    let collected = engine.collect_dynamic_export_work(
        LoaderContextId::from_case_id(0),
        std::slice::from_ref(&module),
        &candidate.pinned,
        &ScriptedSession::default(),
        false,
        &[],
    );

    assert!(collected.required_seed_complete);
    assert_eq!(collected.count_only_seeds.len(), 1);
    assert_eq!(collected.count_only_seeds[0].object, object);
    assert_eq!(collected.count_only_seeds[0].object_path, module.path);
    assert_eq!(collected.dynamic.len(), 1);
    assert_eq!(collected.dynamic[0].object, object);
    let cookie = collected.dynamic[0].cookie;
    assert_eq!(cookie >> 32, u64::from(object.0));
    assert_eq!((cookie >> 24) as u8, 0);
    assert_eq!(
        cookie as u32 & 0x00ff_ffff,
        engine.hooks.id("C_GetFunctionList").unwrap()
    );
    let other_context = engine.collect_dynamic_export_work(
        LoaderContextId::from_case_id(1),
        std::slice::from_ref(&module),
        &candidate.pinned,
        &ScriptedSession::default(),
        false,
        &[],
    );
    assert_eq!((other_context.dynamic[0].cookie >> 24) as u8, 1);
    assert_ne!(other_context.dynamic[0].cookie, cookie);
    assert!(
        candidate
            .plan
            .modules
            .iter()
            .any(|summary| summary.object == object)
    );
    assert_eq!(view.id(), module.view);
}

#[test]
fn overflowing_export_cookie_id_refuses_dynamic_work_with_partial_evidence() {
    let (_fixture, _view, module, pins) = loaded_seed_provider();
    let mut engine = Engine::empty();
    engine.hooks = HookRegistry::with_overflowing_export_cookie_id();
    assert_eq!(engine.hooks.id("C_GetFunctionList"), Some(0x0100_0000));
    let candidate = engine
        .live_candidate(pins, vec![module.clone()], Vec::new())
        .unwrap();
    let object = candidate
        .pinned
        .id_for_scanned(&module, module.key, &module.path)
        .unwrap();
    let overflow_subject = "live export hook";
    let overflow_reason = "an export hook identity did not fit the checked attachment cookie";
    assert!(
        !engine
            .counters
            .object_skips
            .iter()
            .any(|skip| { skip.subject == overflow_subject && skip.reason == overflow_reason })
    );

    let collected = engine.collect_dynamic_export_work(
        LoaderContextId::from_case_id(0),
        std::slice::from_ref(&module),
        &candidate.pinned,
        &ScriptedSession::default(),
        false,
        &[],
    );

    assert!(collected.dynamic.is_empty());
    assert!(!collected.required_seed_complete);
    assert_eq!(collected.count_only_seeds.len(), 1);
    assert_eq!(collected.count_only_seeds[0].object, object);
    assert_eq!(collected.count_only_seeds[0].object_path, module.path);
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .any(|skip| { skip.subject == overflow_subject && skip.reason == overflow_reason })
    );
}

#[test]
fn expired_deadline_names_live_export_snapshot_refusal() {
    let (_fixture, _view, module, pins) = loaded_seed_provider();
    let mut engine = Engine::empty();
    let candidate = engine
        .live_candidate(pins, vec![module.clone()], Vec::new())
        .unwrap();
    engine.budget.set_deadline(Some(0));
    let collected = engine.collect_dynamic_export_work(
        LoaderContextId::from_case_id(0),
        std::slice::from_ref(&module),
        &candidate.pinned,
        &ScriptedSession::default(),
        false,
        &[],
    );

    assert!(!collected.required_seed_complete);
    assert!(collected.count_only_seeds.is_empty());
    assert!(collected.dynamic.is_empty());
    assert_eq!(engine.budget.attempted_io_bytes(), 0);
    assert!(engine.counters.object_skips.iter().any(|skip| {
        skip.subject == "live export hook" && skip.reason.contains(SCAN_DEADLINE_REASON)
    }));
}

#[test]
fn absent_pinned_export_marks_seed_incomplete_without_allocating_a_slot() {
    let (mut modules, pins) = pinned_self();
    let mut module = modules.pop().unwrap();
    module.exports = vec!["C_GetFunctionList".into()];
    let mut engine = Engine::empty();
    let candidate = engine
        .live_candidate(pins, vec![module.clone()], Vec::new())
        .unwrap();
    let collected = engine.collect_dynamic_export_work(
        LoaderContextId::from_case_id(0),
        std::slice::from_ref(&module),
        &candidate.pinned,
        &ScriptedSession::default(),
        false,
        &[],
    );

    assert!(!collected.required_seed_complete);
    assert!(collected.count_only_seeds.is_empty());
    assert!(collected.dynamic.is_empty());
    assert!(engine.counters.object_skips.iter().any(|skip| {
        skip.subject == "live export hook"
            && !skip.reason.contains(&module.path)
            && !skip.reason.contains("offset")
    }));
}

#[test]
fn static_seed_attach_failure_detaches_and_deactivates_seed_slot() {
    let (_fixture, view, module, pins) = loaded_seed_provider();
    let mut engine = Engine::empty();
    engine.views.push(view);
    let mut candidate = engine
        .live_candidate(pins, vec![module.clone()], Vec::new())
        .unwrap();
    let object = candidate
        .pinned
        .id_for_scanned(&module, module.key, &module.path)
        .unwrap();
    let collected = engine.collect_dynamic_export_work(
        LoaderContextId::from_case_id(0),
        std::slice::from_ref(&module),
        &candidate.pinned,
        &ScriptedSession::default(),
        false,
        &[],
    );
    let seed = &collected.count_only_seeds[0];
    let owner = candidate
        .plan
        .modules
        .iter()
        .find(|summary| summary.object == object)
        .unwrap()
        .id;
    let slot = candidate
        .plan
        .add_provisional_get_function_list(plan::ProvisionalGetFunctionList {
            module: owner,
            object: seed.object,
            object_path: seed.object_path.clone(),
            file_offset: seed.file_offset,
        })
        .unwrap()
        .unwrap();
    candidate.delta.new.push(slot.clone());

    let mut session = ScriptedSession::default();
    session.fail_target_slots([slot.index]);
    let mut additions_allowed = true;
    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions_allowed, false, &[])
        .unwrap();

    assert!(!outcome.required_complete());
    assert_eq!(session.attached_slots, [1]);
    assert_eq!(session.detached_slots, [0, 1]);
    assert!(!engine.plan.is_active(slot.index));
    assert_eq!(engine.plan.slots[slot.index as usize].descriptor_index, 0);
    assert_eq!(
        engine.plan.slots[slot.index as usize].names,
        ["C_GetFunctionList"]
    );
    assert_eq!(engine.plan.entries_seen, 0);
    assert!(engine.plan.surfaces.is_empty());
}

#[test]
fn static_seed_preflight_refusal_keeps_accepted_plan_and_links_unchanged() {
    let (_fixture, view, module, pins) = loaded_seed_provider();
    let mut engine = Engine::empty();
    engine.views.push(view);
    let mut candidate = engine
        .live_candidate(pins, vec![module.clone()], Vec::new())
        .unwrap();
    let object = candidate
        .pinned
        .id_for_scanned(&module, module.key, &module.path)
        .unwrap();
    let owner = candidate
        .plan
        .modules
        .iter()
        .find(|summary| summary.object == object)
        .unwrap()
        .id;
    let seed = CountOnlySeedWork {
        object,
        object_path: module.path.clone(),
        file_offset: ElfSnapshot::read(candidate.pinned.file_for(object).unwrap())
            .unwrap()
            .defined_symbol("C_GetFunctionList")
            .unwrap()
            .unwrap()
            .file_offset,
    };
    let slot = candidate
        .plan
        .add_provisional_get_function_list(plan::ProvisionalGetFunctionList {
            module: owner,
            object: seed.object,
            object_path: seed.object_path,
            file_offset: seed.file_offset,
        })
        .unwrap()
        .unwrap();
    candidate.delta.new.push(slot);
    let accepted_plan = engine.plan.clone();
    let mut session = ScriptedSession::refusing_preflight();
    let mut additions_allowed = true;
    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions_allowed, false, &[])
        .unwrap();

    assert!(outcome.refused());
    assert!(!outcome.required_complete());
    assert_eq!(engine.plan, accepted_plan);
    assert!(session.attached_slots.is_empty());
    assert!(session.detached_slots.is_empty());
}

/// Two provider modules over two distinct executable objects the live
/// child really mapped.
fn child_provider_modules(view: &ProcessView) -> Vec<ScannedModule> {
    for _ in 0..200 {
        let bytes = std::fs::read(format!("/proc/{}/maps", view.pid())).unwrap();
        let maps = parse_maps(&bytes).unwrap();
        let map_index = MapIndex::new(&maps).expect("the live child maps snapshot is valid");
        let mut keys = BTreeSet::new();
        let mut modules = Vec::new();
        for mapping in maps
            .iter()
            .filter(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
        {
            let Resolved::File {
                path: MappedPath::Usable(path),
                ..
            } = map_index.resolve(mapping.start)
            else {
                continue;
            };
            if !keys.insert(ObjectKey::of(mapping)) {
                continue;
            }
            modules.push(provider_module(view, mapping, &path, 0x1000));
            if modules.len() == 2 {
                return modules;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("the live child never mapped two distinct file-backed objects");
}

fn pin_test_modules(view: &ProcessView, modules: &[ScannedModule]) -> PinnedObjects {
    let mut budget = CaptureWorkBudget::new(ScanLimits {
        per_object_bytes: u64::MAX,
        total_bytes: u64::MAX,
    });
    let (pins, skipped) = pin_scanned_view_objects(view, modules, &mut budget).unwrap();
    assert!(skipped.is_empty(), "{skipped:?}");
    pins
}

/// A live child, an Engine that retains one process view on it, and one
/// accepted provider already attached in slot 0. The returned modules are
/// `[accepted, peer]`; the peer is what a later candidate allocates.
fn engine_with_one_accepted_provider() -> (std::process::Child, Engine, Vec<ScannedModule>) {
    let child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let view = ProcessView::open(ProcessViewId(3), child.id()).unwrap();
    let modules = child_provider_modules(&view);
    let mut engine = Engine::empty();
    engine.scope = Scope::Pid(child.id());
    engine.next_view_id = 4;
    engine.views.push(view);
    let pins = pin_test_modules(&engine.views[0], &modules[..1]);
    let candidate = engine
        .live_candidate(pins, vec![modules[0].clone()], Vec::new())
        .unwrap();
    assert_eq!(candidate.delta.new.len(), 1);
    let mut session = ScriptedSession::default();
    let mut additions = true;
    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions, false, &[])
        .unwrap();
    assert!(outcome.accepted(), "the first candidate is accepted whole");
    assert_eq!(engine.plan.slots.len(), 1);
    assert!(engine.plan.module_of_slot(0).is_some());
    (child, engine, modules)
}

/// The candidate that allocates one more cell for the peer provider.
fn peer_candidate(engine: &mut Engine, modules: &[ScannedModule]) -> LiveCandidate {
    let mut pins = engine.pinned.clone();
    let skipped = pins.absorb(pin_test_modules(&engine.views[0], &modules[1..2]));
    let candidate = engine
        .live_candidate(pins, modules.to_vec(), skipped)
        .unwrap();
    assert_eq!(
        candidate.delta.new.len(),
        1,
        "only the peer provider is newly allocated"
    );
    assert_eq!(candidate.plan.slots.len(), 2);
    candidate
}

#[test]
fn post_mutation_generation_loss_never_owns_the_cell_it_allocated() {
    let (child, mut engine, modules) = engine_with_one_accepted_provider();
    let accepted_owner = engine.plan.module_of_slot(0);
    let candidate = peer_candidate(&mut engine, &modules);
    let mut session = ScriptedSession::losing_generation_at_attach(child.id());
    let mut additions = true;

    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions, false, &[])
        .unwrap();

    assert!(!outcome.stale_views.is_empty(), "the generation was lost");
    assert_eq!(
        engine.plan.slots.len(),
        2,
        "an allocated endpoint is never given back"
    );
    assert!(!engine.plan.is_active(0));
    assert!(!engine.plan.is_active(1));
    assert_eq!(
        engine.plan.module_of_slot(1),
        None,
        "a cell this candidate allocated but never got accepted owns nothing"
    );
    assert_eq!(
        engine.plan.module_of_slot(0),
        accepted_owner,
        "an owner already accepted before the candidate stays valid"
    );
    assert_eq!(engine.plan.module_ambiguous, 0);
    assert_eq!(
        engine.pinned.pinned().count(),
        0,
        "the stale view's live pins are cleaned"
    );
    assert!(engine.modules.is_empty());
    assert!(!additions);
    assert!(!outcome.required_complete());
}

fn rebuild_timing_owners(
    pins: &PinnedObjects,
    plan: &plan::AttachPlan,
) -> BTreeMap<plan::ModuleId, PinnedTimingKey> {
    plan.modules
        .iter()
        .filter_map(|module| {
            pins.owned_timing_key(module.object)
                .map(|key| (module.id, key))
        })
        .collect()
}

#[test]
fn rebuild_report_recompletions_record_reactivation_for_siblings() {
    let (mut plan, pins) = plan_with_pins(2, 0);
    let owners = rebuild_timing_owners(&pins, &plan);
    let key = owners.get(&plan::ModuleId(0)).cloned().unwrap();
    let mut engine = Engine::empty();
    let mut outcome = ApplyOutcome::default();

    engine.apply_group_rebuild(
        &mut plan,
        &owners,
        DetachOutcome {
            recompleted: vec![(1, Some(50))],
            rebuild_failures: Vec::new(),
            rebuilt_groups: 1,
        },
        &mut outcome,
    );

    assert!(plan.is_active(0));
    assert!(plan.is_active(1));
    assert_eq!(outcome.static_completions.len(), 1);
    assert_eq!(
        outcome.static_completions[0],
        (BTreeSet::from([key]), Some(50))
    );
    assert!(outcome.static_failures.is_empty());
    assert_eq!(engine.multi_rebuild_gaps(), 1);
    assert!(
        engine.counters.object_skips.iter().any(|skip| skip.subject
            == "multi group rebuild"
            && skip.reason
                == "one or more groups rebuilt; calls in flight across the rebuild window may pair entry and return across attachment generations"),
        "the rebuild window publishes pairing uncertainty: {:?}",
        engine.counters.object_skips
    );
}

#[test]
fn rebuild_report_failures_deactivate_and_record_loss() {
    let (mut plan, pins) = plan_with_pins(2, 0);
    let owners = rebuild_timing_owners(&pins, &plan);
    let key = owners.get(&plan::ModuleId(0)).cloned().unwrap();
    let mut engine = Engine::empty();
    let mut outcome = ApplyOutcome::default();

    engine.apply_group_rebuild(
        &mut plan,
        &owners,
        DetachOutcome {
            recompleted: Vec::new(),
            rebuild_failures: vec![(1, "p11_return refused".into())],
            rebuilt_groups: 1,
        },
        &mut outcome,
    );

    assert!(plan.is_active(0));
    assert!(!plan.is_active(1));
    assert!(outcome.static_completions.is_empty());
    assert_eq!(outcome.static_failures, BTreeSet::from([key]));
    assert_eq!(engine.multi_rebuild_gaps(), 1);
    assert!(
        engine.counters.object_skips.iter().any(
            |skip| skip.subject == "multi group rebuild" && skip.reason.contains("deactivated")
        ),
        "failed survivors deactivate with a published reason: {:?}",
        engine.counters.object_skips
    );
}

#[test]
fn rebuild_report_for_unknown_slot_publishes_defensive_partial() {
    let (mut plan, pins) = plan_with_pins(2, 0);
    let owners = rebuild_timing_owners(&pins, &plan);
    let mut engine = Engine::empty();
    let mut outcome = ApplyOutcome::default();

    engine.apply_group_rebuild(
        &mut plan,
        &owners,
        DetachOutcome {
            recompleted: vec![(99, Some(7))],
            rebuild_failures: vec![(98, "gone".into())],
            rebuilt_groups: 1,
        },
        &mut outcome,
    );

    assert!(plan.is_active(0));
    assert!(plan.is_active(1));
    assert!(outcome.static_completions.is_empty());
    assert!(outcome.static_failures.is_empty());
    assert_eq!(engine.multi_rebuild_gaps(), 1);
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .any(|skip| skip.reason.contains("no plan entry")),
        "an unrecordable reactivation is never silent: {:?}",
        engine.counters.object_skips
    );
}

#[test]
fn empty_rebuild_report_is_a_no_op() {
    let (mut plan, pins) = plan_with_pins(2, 0);
    let owners = rebuild_timing_owners(&pins, &plan);
    let mut engine = Engine::empty();
    let mut outcome = ApplyOutcome::default();

    engine.apply_group_rebuild(&mut plan, &owners, DetachOutcome::default(), &mut outcome);

    assert!(outcome.static_completions.is_empty());
    assert!(outcome.static_failures.is_empty());
    assert_eq!(engine.multi_rebuild_gaps(), 0);
    assert!(engine.counters.object_skips.is_empty());
    assert!(plan.is_active(0) && plan.is_active(1));
}

#[test]
fn failed_attach_rebuild_report_reactivates_surviving_sibling() {
    let (_child, mut engine, modules) = engine_with_one_accepted_provider();
    let candidate = peer_candidate(&mut engine, &modules);
    let sibling = candidate.plan.slots[0].index;
    let failing = candidate.delta.new[0].index;
    let mut session = ScriptedSession::default();
    session.fail_target_slots([failing]);
    session.report_slot_rebuilds([
        DetachOutcome::default(),
        DetachOutcome {
            recompleted: vec![(sibling, Some(77))],
            rebuild_failures: Vec::new(),
            rebuilt_groups: 1,
        },
    ]);
    let mut additions = true;

    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions, false, &[])
        .unwrap();

    assert_eq!(session.detached_slots, vec![0, 1]);
    assert!(engine.plan.is_active(sibling));
    assert!(!engine.plan.is_active(failing));
    assert!(
        outcome
            .static_completions
            .iter()
            .any(|(_, at)| *at == Some(77)),
        "the sibling reactivation time is recorded"
    );
    assert_eq!(engine.multi_rebuild_gaps(), 1);
    assert!(additions, "a clean rebuild blocks no additions");
}

#[test]
fn retired_slot_rebuild_report_reactivates_surviving_sibling() {
    let (_child, mut engine, modules) = engine_with_one_accepted_provider();
    let peer = peer_candidate(&mut engine, &modules);
    let mut session = ScriptedSession::default();
    let mut additions = true;
    engine
        .apply_candidate(&mut session, peer, &mut additions, false, &[])
        .unwrap();
    assert!(engine.plan.is_active(0));
    assert!(engine.plan.is_active(1));
    // A candidate without the peer retires slot 1; the detach reports the
    // group rebuild that reattached slot 0.
    let candidate = engine
        .live_candidate(engine.pinned.clone(), modules[..1].to_vec(), Vec::new())
        .unwrap();
    assert_eq!(candidate.delta.retire.len(), 1);
    let mut session = ScriptedSession::default();
    session.report_slot_rebuilds([DetachOutcome {
        recompleted: vec![(0, Some(88))],
        rebuild_failures: Vec::new(),
        rebuilt_groups: 1,
    }]);
    let mut additions = true;
    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions, false, &[])
        .unwrap();

    assert!(engine.plan.is_active(0));
    assert!(!engine.plan.is_active(1));
    assert!(
        outcome
            .static_completions
            .iter()
            .any(|(_, at)| *at == Some(88)),
        "the sibling reactivation time is recorded"
    );
    assert_eq!(engine.multi_rebuild_gaps(), 1);
}

#[test]
fn generation_loss_cleanup_finishes_after_one_failed_detach() {
    let (child, mut engine, modules) = engine_with_one_accepted_provider();
    let accepted_owner = engine.plan.module_of_slot(0);
    let candidate = peer_candidate(&mut engine, &modules);
    let mut session = ScriptedSession::losing_generation_at_attach(child.id());
    session.fail_slot_detaches([false, false, true]);
    let mut additions = true;

    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions, false, &[])
        .unwrap();

    assert_eq!(
        session.detached_slots.len(),
        3,
        "the failed one-shot cleanup detach was not retried"
    );
    assert_eq!(session.detached_slots[2], 2, "both endpoints were retired");
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .any(|skip| skip.subject == "live discovery detach"),
        "{:?}",
        engine.counters.object_skips
    );
    assert_eq!(engine.plan.module_of_slot(1), None);
    assert_eq!(engine.plan.module_of_slot(0), accepted_owner);
    assert_eq!(
        engine.pinned.pinned().count(),
        0,
        "cleanup finished past the detach failure"
    );
    assert!(engine.modules.is_empty());
    assert!(!additions);
    assert!(!outcome.required_complete());
}

#[test]
fn a_history_preparation_failure_never_enters_the_link_mutation() {
    let (mut child, mut engine, modules) = engine_with_one_accepted_provider();
    let candidate = peer_candidate(&mut engine, &modules);
    let plan = engine.plan.clone();
    let pins = engine.pinned.pinned().count();
    // The accepted manifest history lost its source ordinals, so no
    // candidate of this Engine can publish provider history.
    engine.manifest_ordinals.push(0);
    let mut session = ScriptedSession::default();
    let mut additions = true;

    let error = engine
        .apply_candidate(&mut session, candidate, &mut additions, false, &[])
        .err()
        .expect("history preparation refuses the candidate");

    assert!(
        format!("{error:#}").contains("source ordinals"),
        "{error:#}"
    );
    assert!(
        session.detached_slots.is_empty() && session.attached_slots.is_empty(),
        "the link-mutation closure was never entered"
    );
    assert_eq!(engine.plan, plan, "the accepted plan is unchanged");
    assert_eq!(engine.pinned.pinned().count(), pins);
    assert!(additions, "a pre-mutation refusal keeps the additions gate");
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn a_post_mutation_retirement_is_not_an_accepted_candidate() {
    let (child, mut engine, modules) = engine_with_one_accepted_provider();
    let view = engine.views[0].id();
    let candidate = peer_candidate(&mut engine, &modules);
    let mut session = ScriptedSession::losing_generation_at_attach(child.id());
    let mut additions = true;

    let retired = engine
        .apply_candidate(&mut session, candidate, &mut additions, false, &[])
        .unwrap();

    assert_eq!(
        retired.disposition,
        ApplyDisposition::ConservativeRetirement,
        "a conservative post-mutation retirement is not an accepted candidate"
    );
    assert!(!retired.accepted());
    let mut closure = PauseClosure::new(true);
    closure.observe_apply(&retired);
    assert!(
        !closure.required_complete(),
        "a retired candidate cannot confirm pause completeness"
    );
    let mut pending = PendingViewRetirements::new();
    engine.pending_retirements.insert(view);
    engine.queue_conservative_outcome(
        &retired,
        &[view].into_iter().collect(),
        &BTreeSet::new(),
        &mut pending,
    );
    assert!(
        engine.pending_retirements.is_empty(),
        "conservative cleanup clears the retry intent it consumed"
    );

    let refused_candidate = engine
        .live_candidate(engine.pinned.clone(), Vec::new(), Vec::new())
        .unwrap();
    let mut refusing = ScriptedSession::refusing_preflight();
    let refused = engine
        .apply_candidate(&mut refusing, refused_candidate, &mut additions, false, &[])
        .unwrap();

    assert!(refused.refused());
    engine.pending_retirements.insert(view);
    engine.queue_conservative_outcome(
        &refused,
        &[view].into_iter().collect(),
        &BTreeSet::new(),
        &mut pending,
    );
    assert_eq!(
        engine.pending_retirements,
        [view].into_iter().collect(),
        "a refusal retains the retry intent it never consumed"
    );
}

#[test]
fn a_failed_start_returns_its_own_error_after_restoring_publication() {
    let (mut engine, _, _, _) = engine_with_overlay(58);
    engine
        .capture_facts
        .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
        .unwrap();
    engine.publish_current_capture_facts().unwrap();
    let owner = engine.plan.module_of_slot(0);
    let snapshot = engine.begin_start_capture_attempt().unwrap();

    // A post-link rebuild has to re-derive this registry; restoration must
    // not depend on it, and must never speak over the original failure.
    engine
        .capture_facts
        .module_keys
        .insert(plan::ModuleId(0), timing_key(0));

    let result: Result<()> =
        engine.finish_start_capture_attempt(snapshot, Err(anyhow!("late loader failure")));

    assert_eq!(
        format!("{}", result.unwrap_err()),
        "late loader failure",
        "restoration must not obscure the original start failure"
    );
    assert_eq!(engine.plan.module_of_slot(0), owner);
    assert!(engine.capture_facts.staged.is_none());
    assert_eq!(engine.discovery.modules.len(), 1);
}

#[test]
fn closed_additions_gate_loses_every_unperformed_exact_owner() {
    let first_id = plan::ModuleId(3);
    let second_id = plan::ModuleId(4);
    let first = timing_key(0);
    let second = timing_key(1);
    let duplicate = timing_key(2);
    let slots = vec![
        plan::Slot {
            index: 0,
            descriptor_index: 0,
            object: PinnedObjectId(7),
            object_path: "/opt/first.so".into(),
            file_offset: 0x10,
            names: vec!["C_Sign".into()],
            aliased: false,
            semantics: p11scope_ebpf_common::SlotSemantics::COUNT_ONLY,
            semantic_authorized: false,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![first_id],
        },
        plan::Slot {
            index: 1,
            descriptor_index: 0,
            object: PinnedObjectId(8),
            object_path: "/opt/second.so".into(),
            file_offset: 0x20,
            names: vec!["C_Verify".into()],
            aliased: false,
            semantics: p11scope_ebpf_common::SlotSemantics::COUNT_ONLY,
            semantic_authorized: false,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![second_id],
        },
    ];
    let delta = plan::AttachDelta {
        new: vec![slots[0].clone()],
        replace: vec![slots[1].clone()],
        retire: Vec::new(),
    };
    let mut candidate_plan = plan::AttachPlan::from_slots(slots);
    let mut outcome = ApplyOutcome::default();
    let owners = [(first_id, first.clone()), (second_id, second.clone())]
        .into_iter()
        .collect();
    block_unperformed_static(&mut candidate_plan, &delta, &owners, &mut outcome);

    assert_eq!(
        outcome.static_failures,
        [first.clone(), second.clone()].into_iter().collect(),
        "an already-closed gate owns every skipped new/replacement slot"
    );
    assert!(!candidate_plan.is_active(0));
    assert!(!candidate_plan.is_active(1));

    let mut timings = CausalTimings::default();
    for module in [&first, &second, &duplicate] {
        timings.observe(module, 10);
    }
    timings.complete(&duplicate, 15);
    lose_unperformed_dynamic_work(
        &mut timings,
        &[
            dynamic_export_work(first.clone(), false),
            dynamic_export_work(second.clone(), false),
            dynamic_export_work(duplicate.clone(), true),
        ],
    );
    for module in [&first, &second] {
        timings.complete(module, 30);
        assert_eq!(
            timings.gap_ns(module),
            None,
            "later work cannot substitute for required work skipped by the closed gate"
        );
    }
    assert_eq!(
        timings.gap_ns(&duplicate),
        Some(5),
        "an already-attached dynamic pair is not unperformed work"
    );
}

#[test]
fn refused_dynamic_only_candidate_loses_its_exact_owner() {
    let module = timing_key(0);
    let mut timings = CausalTimings::default();
    timings.observe(&module, 10);
    let refused = ApplyOutcome {
        missing_contexts: vec![LoaderContextId::from_case_id(0)],
        ..ApplyOutcome::default()
    };
    let work = [dynamic_export_work(module.clone(), false)];

    if refused.accepted() {
        timings.complete(&module, 20);
    } else {
        lose_unperformed_dynamic_work(&mut timings, &work);
    }
    timings.complete(&module, 30);

    assert_eq!(
        timings.gap_ns(&module),
        None,
        "a later attach cannot substitute for dynamic work skipped by candidate refusal"
    );
}

#[test]
fn tagged_terminal_export_snapshot_preserves_only_the_exact_duplicate() {
    let object = PinnedObjectId(7);
    let module = timing_key(0);
    let context = LoaderContextId::from_case_id(0);
    let exact = crate::attach::DynamicExportIdentity {
        object,
        file_offset: 0x10,
        cookie: export_attach_cookie(object.0, (context.get() - 1) as u8, 1).unwrap(),
        abi: HookAbi::FunctionList,
    };
    let snapshot = vec![exact];
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_LOADER;
    record.case_id = 0;
    let queued = tagged_by_authority(context, &snapshot, record);
    assert_eq!(queued.terminal_owner, Some(context));
    assert_eq!(queued.terminal_exports, snapshot);

    let mut timings = CausalTimings::default();
    timings.observe(&module, 10);
    timings.complete(&module, 20);
    let duplicate = DynamicExportWork {
        context,
        module: Some(module.clone()),
        object,
        file_offset: exact.file_offset,
        cookie: exact.cookie,
        abi: exact.abi,
        already_attached: queued.terminal_exports.contains(&exact),
        selection_binding: None,
    };
    lose_unperformed_dynamic_work(&mut timings, std::slice::from_ref(&duplicate));
    assert_eq!(timings.gap_ns(&module), Some(10));

    let absent = DynamicExportWork {
        file_offset: 0x20,
        already_attached: queued
            .terminal_exports
            .contains(&crate::attach::DynamicExportIdentity {
                file_offset: 0x20,
                ..exact
            }),
        ..duplicate.clone()
    };
    lose_unperformed_dynamic_work(&mut timings, std::slice::from_ref(&absent));
    assert_eq!(timings.gap_ns(&module), None);

    record.case_id = 1;
    let other = tagged_by_authority(context, &snapshot, record);
    assert_eq!(other.terminal_owner, None);
    assert!(other.terminal_exports.is_empty());
}

#[test]
fn terminal_authority_tags_every_matching_record_in_the_owned_batch() {
    let owner = LoaderContextId::from_case_id(2);
    let export = DynamicExportIdentity {
        object: PinnedObjectId(7),
        file_offset: 0x10,
        cookie: 1,
        abi: HookAbi::FunctionList,
    };
    let mut matching: DiscoveryRecord = unsafe { std::mem::zeroed() };
    matching.kind = DISCOVERY_KIND_LOADER;
    matching.case_id = (owner.get() - 1) as u8;
    let mut unrelated = matching;
    unrelated.case_id = unrelated.case_id.wrapping_add(1);
    let mut records = [matching, matching, unrelated].map(|record| QueuedDiscoveryRecord {
        record,
        terminal_owner: None,
        terminal_exports: Vec::new(),
    });
    let authority = TerminalAuthority {
        owner,
        exports: vec![export],
    };

    assert!(authority.tag_matching(&mut records));
    assert_eq!(
        records
            .iter()
            .map(|record| record.terminal_owner)
            .collect::<Vec<_>>(),
        [Some(owner), Some(owner), None]
    );
    assert_eq!(records[0].terminal_exports, [export]);
    assert_eq!(records[1].terminal_exports, [export]);
    assert!(records[2].terminal_exports.is_empty());
}

#[test]
fn terminal_authority_tags_selection_by_binding_not_request_class() {
    let owner = LoaderContextId::from_case_id(2);
    let export = DynamicExportIdentity {
        object: PinnedObjectId(7),
        file_offset: 0x10,
        cookie: 41,
        abi: HookAbi::Interface,
    };
    let mut matching: DiscoveryRecord = unsafe { std::mem::zeroed() };
    matching.kind = DISCOVERY_KIND_INTERFACE_RETURN;
    matching.case_id = DISCOVERY_NAME_NULL;
    matching.binding_id = export.cookie;
    let mut wrong_binding = matching;
    wrong_binding.binding_id += 1;
    let mut records = [matching, wrong_binding].map(|record| QueuedDiscoveryRecord {
        record,
        terminal_owner: None,
        terminal_exports: Vec::new(),
    });

    assert!(
        (TerminalAuthority {
            owner,
            exports: vec![export],
        })
        .tag_matching(&mut records)
    );
    assert_eq!(records[0].terminal_owner, Some(owner));
    assert_eq!(records[0].terminal_exports, [export]);
    assert_eq!(records[1].terminal_owner, None);
    assert!(records[1].terminal_exports.is_empty());
}

#[test]
fn predispatch_failure_returns_the_exact_batch_for_one_retry() {
    let record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    let records = vec![QueuedDiscoveryRecord {
        record,
        terminal_owner: None,
        terminal_exports: Vec::new(),
    }];

    let (error, retained) = match begin_discovery_batch(records, Err(anyhow!("counter read"))) {
        Err(retained) => retained,
        Ok(_) => panic!("predispatch failure must keep ownership unconsumed"),
    };
    assert!(error.to_string().contains("counter read"));
    assert_eq!(retained.len(), 1);

    let dispatching = match begin_discovery_batch(retained, Ok(())) {
        Ok(dispatching) => dispatching,
        Err(_) => panic!("the retained batch must begin exactly once"),
    };
    assert_eq!(dispatching.len(), 1);
}

#[test]
fn generic_batches_cannot_consume_or_tag_terminal_authority() {
    let owner = LoaderContextId::from_case_id(2);
    let authority = TerminalAuthority {
        owner,
        exports: Vec::new(),
    };
    let mut engine = Engine::empty();
    engine.terminal_journal = Some(TerminalJournal {
        owner,
        dispatch_started: false,
        retry_used: false,
    });
    engine.terminal_batch = Some(TerminalBatch::empty(authority));
    let queued = |case_id| {
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_LOADER;
        record.case_id = case_id;
        QueuedDiscoveryRecord {
            record,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        }
    };
    let unrelated = [queued(((owner.get() - 1) as u8).wrapping_add(1))];
    let matching = queued((owner.get() - 1) as u8);

    assert_eq!(unrelated[0].terminal_owner, None);
    engine
        .retain_terminal_batch([matching.record, matching.record], true, 0)
        .unwrap();
    assert!(
        engine
            .terminal_batch
            .as_ref()
            .unwrap()
            .records
            .iter()
            .all(|record| record.terminal_owner == Some(owner))
    );
    assert!(engine.terminal_journal.is_some());
}

#[test]
fn a_second_terminal_authority_is_rejected_without_replacing_the_first() {
    let (registry, first) = prepared_loader_registry();
    let second = LoaderContextId::from_case_id(2);
    let mut engine = Engine::empty();
    engine.loader_registry = registry;
    engine.loader_registry.mark_attached(first).unwrap();
    let deferred = engine
        .begin_terminal_drain(first, Vec::new(), || Err::<(), _>(anyhow!("deferred")))
        .unwrap();
    assert!(deferred.is_err());

    let error = engine
        .begin_terminal_drain(second, Vec::new(), || Ok(()))
        .unwrap_err();

    assert!(error.to_string().contains("already pending"), "{error:#}");
    assert_eq!(
        engine
            .terminal_journal
            .as_ref()
            .map(|journal| journal.owner),
        Some(first)
    );
}

#[test]
fn fallible_terminal_drain_keeps_tombstoned_authority_for_retry() {
    let (registry, context) = prepared_loader_registry();
    let export = DynamicExportIdentity {
        object: PinnedObjectId(7),
        file_offset: 0x10,
        cookie: 1,
        abi: HookAbi::FunctionList,
    };
    let mut engine = Engine::empty();
    engine.loader_registry = registry;
    engine.loader_registry.mark_attached(context).unwrap();

    let drained = engine
        .begin_terminal_drain(context, vec![export], || Err::<(), _>(anyhow!("deferred")))
        .unwrap();

    assert!(drained.is_err());
    assert!(engine.loader_registry.is_tombstoned(context));
    let batch = engine.terminal_batch.as_ref().unwrap();
    assert_eq!(batch.authority.owner, context);
    assert_eq!(batch.authority.exports, [export]);
    assert!(!batch.complete());

    assert!(engine.terminal_batch.is_some());
    assert!(engine.terminal_journal.is_some());
    engine.loader_registry.remove(context).unwrap();
}

#[test]
fn terminal_predispatch_counter_failure_uses_one_retry_before_cleanup() {
    let (registry, context) = prepared_loader_registry();
    let mut engine = Engine::empty();
    engine.loader_registry = registry;
    engine.loader_registry.mark_attached(context).unwrap();
    engine
        .begin_terminal_drain(context, Vec::new(), || Err::<(), _>(anyhow!("deferred")))
        .unwrap()
        .unwrap_err();
    let mut additions_allowed = true;
    let mut closure = PauseClosure::new(true);

    engine.retry_terminal_predispatch_failure(&mut additions_allowed, &mut closure);

    assert!(engine.terminal_journal.as_ref().unwrap().retry_used);
    assert!(engine.loader_registry.is_tombstoned(context));
    assert!(engine.terminal_batch.is_some());

    engine.retry_terminal_predispatch_failure(&mut additions_allowed, &mut closure);

    assert!(engine.terminal_journal.is_none());
    assert!(engine.terminal_batch.is_none());
    assert!(engine.loader_registry.context(context).is_none());
    assert!(!additions_allowed);
    assert!(!closure.required_complete());
}

/// One record put through the real production authority-tagging path.
fn tagged_by_authority(
    owner: LoaderContextId,
    exports: &[DynamicExportIdentity],
    record: DiscoveryRecord,
) -> QueuedDiscoveryRecord {
    let mut batch = TerminalBatch::empty(TerminalAuthority {
        owner,
        exports: exports.to_vec(),
    });
    batch.extend([record]);
    batch
        .records
        .into_iter()
        .next()
        .expect("the authority batch holds the extended record")
}

fn terminal_export() -> DynamicExportIdentity {
    DynamicExportIdentity {
        object: PinnedObjectId(7),
        file_offset: 0x10,
        cookie: 1,
        abi: HookAbi::FunctionList,
    }
}

fn closed_terminal_selection(
    engine: &mut Engine,
    owner: LoaderContextId,
    pid: u32,
) -> (DynamicExportIdentity, DiscoveryRecord) {
    let identity = DynamicExportIdentity {
        object: PinnedObjectId(7),
        file_offset: 0x20,
        cookie: 2,
        abi: HookAbi::Interface,
    };
    engine.selection_bindings.insert(
        identity.cookie,
        SelectionBindingFact {
            id: identity.cookie,
            context: owner,
            view: ProcessViewId(0),
            object: identity.object,
            file_offset: identity.file_offset,
            hook_id: HookRegistry::builtin().id("C_GetInterface").unwrap(),
            abi: identity.abi,
            attached: true,
            retired: false,
            provider: plan::ModuleId(0),
            observed: false,
            coverage: SelectionCoverageState::OwnedClosed(NonZeroU64::new(1).unwrap()),
        },
    );
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
    record.pid_tgid = u64::from(pid) << 32;
    record.binding_id = identity.cookie;
    (identity, record)
}

fn loader_record_for(context: LoaderContextId, pid: u32) -> DiscoveryRecord {
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_LOADER;
    record.case_id = (context.get() - 1) as u8;
    record.pid_tgid = u64::from(pid) << 32;
    record
}

fn successful_selection_record(pid: u32, binding_id: u64, request_flags: u64) -> DiscoveryRecord {
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
    record.pid_tgid = u64::from(pid) << 32;
    record.case_id = DISCOVERY_NAME_EXACT_STANDARD;
    record.interface_index = DISCOVERY_VERSION_V3_0;
    record.request_flags = request_flags;
    record.name_class = DISCOVERY_NAME_EXACT_STANDARD;
    record.selection_version_class = DISCOVERY_VERSION_V3_0;
    record.table_ptr = 0x1000;
    record.binding_id = binding_id;
    assert!(valid_discovery_record(&record));
    record
}

/// One ordinary non-terminal Engine batch through the real application
/// route, with the real generic collector.
fn apply_ordinary_batch(
    engine: &mut Engine,
    session: &mut ScriptedSession,
    records: Vec<DiscoveryRecord>,
) -> Result<DiscoveryBatchOutcome> {
    let mut collect = Engine::collect_discovery_records;
    engine.apply_discovery_batch_with(session, records, 0, true, false, &mut collect, None)
}

/// Mutation caught: rejecting an already-dequeued return solely because
/// its original process exited drops a factual interface-selection tuple.
#[test]
fn ordinary_selection_records_survive_honest_exit_through_exact_terminal_handoff() {
    const WORK_CEILING: u64 = 16 * 1024 * 1024;
    let (mut fixture, mut engine, mut session, binding) = attached_selection_route();
    let identity = DynamicExportIdentity {
        object: binding.object,
        file_offset: binding.file_offset,
        cookie: binding.id,
        abi: binding.abi,
    };
    session.detach_exports = vec![identity];
    let records = (0..3)
        .map(|flags| successful_selection_record(fixture.child.id(), binding.id, flags))
        .collect();
    engine.budget = CaptureWorkBudget::default();
    assert!(engine.budget.charge(WORK_CEILING - 3));

    fixture.child.kill().unwrap();
    fixture.child.wait().unwrap();
    let outcome = apply_ordinary_batch(&mut engine, &mut session, records).unwrap();

    assert_eq!(engine.capture_facts.history.selections.len(), 3);
    assert!(engine.capture_facts.history.selections.iter().all(|tuple| {
        tuple.result.is_some()
            && tuple.inventory_matches.is_empty()
            && tuple.authority == SelectionAuthority::None
            && tuple.count == 1
    }));
    assert!(engine.capture_facts.history.losses.values().any(|loss| {
        loss.reason == "a terminal selection result had no stable live table assessment"
    }));
    assert!(engine.selection_claims.is_empty());
    assert!(engine.selection_tables.is_empty());
    assert_eq!(session.detached, [binding.context]);
    assert!(engine.views.is_empty());
    assert!(engine.terminal_batch.is_none());
    assert!(engine.terminal_journal.is_none());
    assert!(
        engine.budget.charge(0),
        "the terminal handoff must not charge the three records again"
    );
    assert!(
        !engine.budget.charge(1),
        "the ordinary dequeue consumed exactly the last three work units"
    );
    assert!(!outcome.required_complete);
}

/// Mutation caught: treating a changed retained `/proc` start time as an
/// exit would transfer a different process's record into terminal authority.
#[test]
fn ordinary_selection_record_refuses_pid_reuse_without_terminal_handoff() {
    let (_fixture, mut engine, mut session, binding) = attached_selection_route();
    let pid = std::process::id();
    engine.scope = Scope::Pid(pid);
    engine.views = vec![
        crate::process::reused_process_view_for_test(binding.view, pid)
            .expect("a deterministic reused-pid view"),
    ];
    assert!(
        !engine.views[0].still_the_same(),
        "the fixture independently retains a different /proc start time"
    );
    engine
        .selection_bindings
        .get_mut(&binding.id)
        .unwrap()
        .coverage = SelectionCoverageState::OwnedOpen(NonZeroU64::new(41).unwrap());
    let identity = DynamicExportIdentity {
        object: binding.object,
        file_offset: binding.file_offset,
        cookie: binding.id,
        abi: binding.abi,
    };
    session.detach_exports = vec![identity];

    let outcome = apply_ordinary_batch(
        &mut engine,
        &mut session,
        vec![successful_selection_record(pid, binding.id, 0)],
    )
    .unwrap();

    assert!(engine.capture_facts.history.selections.is_empty());
    assert!(engine.terminal_batch.is_none());
    assert!(engine.terminal_journal.is_none());
    assert_eq!(
        engine.selection_bindings[&binding.id].coverage,
        SelectionCoverageState::Uncovered
    );
    assert!(engine.counters.object_skips.iter().any(|skip| {
        skip.reason
            == "a selection record failed binding, context, or process-generation attribution"
    }));
    assert!(!outcome.required_complete);
}

/// Mutation caught: terminal tagging nominates by cookie and ABI, but the
/// reducer must still require the detached snapshot's full exact identity.
#[test]
fn exited_selection_handoff_refuses_mismatched_detached_identity() {
    for case in ["object", "file offset", "cookie", "abi"] {
        let (mut fixture, mut engine, mut session, binding) = attached_selection_route();
        let mut detached = DynamicExportIdentity {
            object: binding.object,
            file_offset: binding.file_offset,
            cookie: binding.id,
            abi: binding.abi,
        };
        match case {
            "object" => detached.object = PinnedObjectId(binding.object.0 + 1),
            "file offset" => detached.file_offset += 1,
            "cookie" => detached.cookie += 1,
            "abi" => detached.abi = HookAbi::FunctionList,
            _ => unreachable!(),
        }
        session.detach_exports = vec![detached];
        let record = successful_selection_record(fixture.child.id(), binding.id, 0);

        fixture.child.kill().unwrap();
        fixture.child.wait().unwrap();
        let outcome = apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();

        assert!(engine.capture_facts.history.selections.is_empty(), "{case}");
        assert_eq!(session.detached, [binding.context], "{case}");
        assert!(engine.terminal_batch.is_none(), "{case}");
        assert!(engine.terminal_journal.is_none(), "{case}");
        assert!(
            engine.counters.object_skips.iter().any(|skip| {
                skip.reason
                    == "a selection record failed binding, context, or process-generation attribution"
            }),
            "{case}"
        );
        assert!(!outcome.required_complete, "{case}");
    }
}

#[test]
fn exited_selection_handoff_requires_every_ordinary_attribution_guard() {
    for case in [
        "unknown binding",
        "unattached binding",
        "retired binding",
        "tombstoned context",
        "context view disagreement",
        "missing retained view",
        "wrong record pid",
        "hook abi mismatch",
    ] {
        let (mut fixture, mut engine, _session, binding) = attached_selection_route();
        let pid = fixture.child.id();
        let mut record = successful_selection_record(pid, binding.id, 0);
        match case {
            "unknown binding" => record.binding_id = binding.id + 1000,
            "unattached binding" => {
                engine
                    .selection_bindings
                    .get_mut(&binding.id)
                    .unwrap()
                    .attached = false;
            }
            "retired binding" => {
                engine
                    .selection_bindings
                    .get_mut(&binding.id)
                    .unwrap()
                    .retired = true;
            }
            "tombstoned context" => {
                engine.loader_registry.tombstone(binding.context).unwrap();
            }
            "context view disagreement" => {
                let other = ProcessView::open(ProcessViewId(77), pid).unwrap();
                engine.views.push(other);
                engine.selection_bindings.get_mut(&binding.id).unwrap().view = ProcessViewId(77);
            }
            "missing retained view" => engine.views.clear(),
            "wrong record pid" => record.pid_tgid = u64::from(std::process::id()) << 32,
            "hook abi mismatch" => {
                engine.selection_bindings.get_mut(&binding.id).unwrap().abi = HookAbi::FunctionList;
            }
            _ => unreachable!(),
        }

        fixture.child.kill().unwrap();
        fixture.child.wait().unwrap();
        assert_eq!(
            engine.process_selection_record(&QueuedDiscoveryRecord {
                record,
                terminal_owner: None,
                terminal_exports: Vec::new(),
            }),
            DiscoveryRecordOutcome::Rejected(RecordRejection::SelectionUnattributed),
            "{case}"
        );
        assert!(engine.capture_facts.history.selections.is_empty(), "{case}");
    }
}

#[test]
fn terminal_selection_authority_refuses_the_wrong_owner() {
    let (_fixture, mut engine, _session, binding) = attached_selection_route();
    let identity = DynamicExportIdentity {
        object: binding.object,
        file_offset: binding.file_offset,
        cookie: binding.id,
        abi: binding.abi,
    };
    let wrong_owner = LoaderContextId::from_case_id(200);
    assert_ne!(wrong_owner, binding.context);
    let record = successful_selection_record(engine.views[0].pid(), binding.id, 0);

    assert_eq!(
        engine.process_selection_record(&tagged_by_authority(wrong_owner, &[identity], record,)),
        DiscoveryRecordOutcome::Rejected(RecordRejection::SelectionUnattributed)
    );
    assert!(engine.capture_facts.history.selections.is_empty());
}

#[test]
fn ordinary_selection_record_refuses_an_unprovable_generation() {
    let (_fixture, mut engine, _session, binding) = attached_selection_route();
    let pid = std::process::id();
    engine.views = vec![
        crate::process::unprovable_process_view_for_test(binding.view, pid)
            .expect("a view with no retained start time or pidfd"),
    ];
    let record = successful_selection_record(pid, binding.id, 0);

    assert_eq!(
        engine.process_selection_record(&QueuedDiscoveryRecord {
            record,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        }),
        DiscoveryRecordOutcome::Rejected(RecordRejection::SelectionUnattributed)
    );
    assert!(engine.capture_facts.history.selections.is_empty());
    assert!(engine.counters.object_skips.iter().any(|skip| {
        skip.reason
            == "a selection record failed binding, context, or process-generation attribution"
    }));
}

#[test]
fn exited_selection_handoff_survives_predispatch_retry_without_recharge() {
    const WORK_CEILING: u64 = 16 * 1024 * 1024;
    let (mut fixture, mut engine, mut session, binding) = attached_selection_route();
    let generation = NonZeroU64::new(43).unwrap();
    engine
        .selection_bindings
        .get_mut(&binding.id)
        .unwrap()
        .coverage = SelectionCoverageState::OwnedOpen(generation);
    let identity = DynamicExportIdentity {
        object: binding.object,
        file_offset: binding.file_offset,
        cookie: binding.id,
        abi: binding.abi,
    };
    session.detach_exports = vec![identity];
    session.fail_counter_reads([false, true]);
    engine.budget = CaptureWorkBudget::default();
    assert!(engine.budget.charge(WORK_CEILING - 1));
    let record = successful_selection_record(fixture.child.id(), binding.id, 0);

    fixture.child.kill().unwrap();
    fixture.child.wait().unwrap();
    apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();

    assert_eq!(session.counter_reads(), 3);
    assert_eq!(engine.capture_facts.history.selections.len(), 1);
    assert_eq!(engine.capture_facts.history.selections[0].count, 1);
    assert!(engine.capture_facts.history.losses.values().any(|loss| {
        loss.reason == "a terminal selection result had no stable live table assessment"
    }));
    assert!(engine.counters.object_skips.iter().any(|skip| {
        skip.reason
            == "the post-detach producer snapshot could not be read; the exact terminal batch remains queued"
    }));
    assert!(engine.terminal_batch.is_none());
    assert!(engine.terminal_journal.is_none());
    assert!(engine.loader_registry.context(binding.context).is_none());
    assert_eq!(
        engine.selection_bindings[&binding.id].coverage,
        SelectionCoverageState::Uncovered
    );
    assert!(
        engine.budget.charge(0),
        "handoff and retry must not recharge the precharged record"
    );
    assert!(!engine.budget.charge(1));
}

#[test]
fn discovery_batch_deadline_is_cleared_after_success_and_error() {
    let (_fixture, mut engine, _context, _record, mut session) = armed_seed_route(0);
    let mut collect = Engine::collect_discovery_records;
    engine
        .apply_discovery_batch_with(
            &mut session,
            Vec::new(),
            0,
            true,
            false,
            &mut collect,
            Some(1),
        )
        .unwrap();
    assert_eq!(engine.budget.deadline_for_test(), None);

    session.fail_counter_reads([true]);
    let mut collect = Engine::collect_discovery_records;
    assert!(
        engine
            .apply_discovery_batch_with(
                &mut session,
                Vec::new(),
                0,
                true,
                false,
                &mut collect,
                Some(1),
            )
            .is_err()
    );
    assert_eq!(engine.budget.deadline_for_test(), None);
}

/// A real failed post-detach drain: the retirement route detaches,
/// tombstones, and keeps an undispatched authority-bearing batch.
fn start_failed_terminal_drain(
    engine: &mut Engine,
    session: &mut ScriptedSession,
    owner: LoaderContextId,
) {
    session
        .dequeues
        .push_back(Err(anyhow!("scripted ring read failed")));
    apply_ordinary_batch(engine, session, Vec::new())
        .expect("a failed terminal drain is loss, never a batch error");
    assert_eq!(
        engine.terminal_journal.map(|journal| journal.owner),
        Some(owner)
    );
    assert!(engine.loader_registry.is_tombstoned(owner));
}

#[test]
fn terminal_drain_promotes_pending_leader_loss_with_retained_journal() {
    let view = ProcessView::open(ProcessViewId(29), std::process::id()).unwrap();
    let mut engine = Engine::empty();
    engine.views.push(view);
    let generation = NonZeroU64::new(1).unwrap();
    engine.selection_bindings.insert(
        1,
        SelectionBindingFact {
            id: 1,
            context: LoaderContextId::from_case_id(1),
            view: ProcessViewId(29),
            object: PinnedObjectId(1),
            file_offset: 0,
            hook_id: 0,
            abi: HookAbi::Interface,
            attached: true,
            retired: false,
            provider: plan::ModuleId(0),
            observed: false,
            coverage: SelectionCoverageState::OwnedOpen(generation),
        },
    );
    engine.pending_leader_exit_views.insert(ProcessViewId(29));
    let owner = LoaderContextId::from_case_id(1);
    engine.terminal_journal = Some(TerminalJournal {
        owner,
        dispatch_started: false,
        retry_used: false,
    });

    engine.settle_terminal_drain();

    assert_eq!(engine.task_uprobe_link_losses, 1);
    assert!(engine.pending_leader_exit_views.is_empty());
    assert!(
        engine
            .views
            .iter()
            .any(|candidate| candidate.id() == ProcessViewId(29))
    );
    assert_eq!(
        engine.selection_bindings[&1].coverage,
        SelectionCoverageState::OwnedClosed(generation)
    );
    assert_eq!(engine.terminal_owner(), Some(owner));
}

#[test]
fn rejected_terminal_cleanup_leaves_both_batch_owners_unchanged() {
    let pid = std::process::id();
    for case in [
        "missing journal",
        "mismatched journal owner",
        "dispatch started",
        "competing engine batch",
    ] {
        let (mut engine, owner) = Engine::retiring_loader_context(pid);
        let other = LoaderContextId::from_case_id(9);
        let export = terminal_export();
        let mut first = loader_record_for(owner, pid);
        first.hook_ts_ns = 11;
        let mut second = loader_record_for(other, pid);
        second.hook_ts_ns = 22;
        let mut returned = TerminalBatch::empty(TerminalAuthority {
            owner,
            exports: vec![export],
        });
        returned.extend([first, second]);
        returned.complete = true;
        let mut returned = Some(returned);

        match case {
            "missing journal" => {}
            "mismatched journal owner" => {
                engine.terminal_journal = Some(TerminalJournal {
                    owner: other,
                    dispatch_started: false,
                    retry_used: true,
                });
            }
            "dispatch started" => {
                engine.terminal_journal = Some(TerminalJournal {
                    owner,
                    dispatch_started: true,
                    retry_used: true,
                });
            }
            "competing engine batch" => {
                engine.terminal_journal = Some(TerminalJournal {
                    owner,
                    dispatch_started: false,
                    retry_used: true,
                });
                engine.terminal_batch = Some(TerminalBatch::empty(TerminalAuthority {
                    owner: other,
                    exports: Vec::new(),
                }));
            }
            _ => unreachable!(),
        }

        let batch_state = |batch: Option<&TerminalBatch>| {
            batch.map(|batch| {
                (
                    batch.authority.owner,
                    batch.authority.exports.clone(),
                    batch.record_count(),
                    batch.complete(),
                    batch.tagged_owners(),
                )
            })
        };
        let journal = engine.terminal_journal_for_test();
        let engine_batch = batch_state(engine.terminal_batch.as_ref());
        let registry = engine.loader_context_state_for_test(owner);
        let skips = engine.counters.object_skips.clone();
        let plan = engine.plan.clone();
        let truncated = engine.capture_facts().discovery_truncated;
        let dispatched = engine.dispatched_loader_records();

        let error = engine
            .cleanup_terminal_batch_without_replay(&mut returned)
            .unwrap_err();

        assert!(!error.to_string().is_empty(), "{case}");
        let returned = returned.as_ref().expect("coordinator keeps its batch");
        assert_eq!(returned.authority.owner, owner, "{case}");
        assert_eq!(returned.authority.exports, [export], "{case}");
        assert_eq!(returned.record_count(), 2, "{case}");
        assert!(returned.complete(), "{case}");
        assert_eq!(returned.tagged_owners(), [Some(owner), None], "{case}");
        assert_eq!(returned.records[0].record.hook_ts_ns, 11, "{case}");
        assert_eq!(
            returned.records[0].record.pid_tgid,
            u64::from(pid) << 32,
            "{case}"
        );
        assert_eq!(returned.records[1].record.hook_ts_ns, 22, "{case}");
        assert_eq!(
            returned.records[1].record.pid_tgid,
            u64::from(pid) << 32,
            "{case}"
        );
        assert_eq!(engine.terminal_journal_for_test(), journal, "{case}");
        assert_eq!(
            batch_state(engine.terminal_batch.as_ref()),
            engine_batch,
            "{case}"
        );
        assert_eq!(
            engine.loader_context_state_for_test(owner),
            registry,
            "{case}"
        );
        assert_eq!(engine.counters.object_skips, skips, "{case}");
        assert_eq!(engine.plan, plan, "{case}");
        assert_eq!(
            engine.capture_facts().discovery_truncated,
            truncated,
            "{case}"
        );
        assert_eq!(engine.dispatched_loader_records(), dispatched, "{case}");
    }
}

#[test]
fn terminal_cleanup_consumes_once_then_retries_only_registry_removal() {
    let pid = std::process::id();
    let (mut engine, owner) = Engine::retiring_loader_context(pid);
    let other = LoaderContextId::from_case_id(9);
    let export = terminal_export();
    let (selection_export, selection_record) = closed_terminal_selection(&mut engine, owner, pid);
    let mut returned = TerminalBatch::empty(TerminalAuthority {
        owner,
        exports: vec![export, selection_export],
    });
    returned.extend([
        loader_record_for(owner, pid),
        loader_record_for(other, pid),
        selection_record,
    ]);
    returned.complete = true;
    let mut returned = Some(returned);
    engine.terminal_journal = Some(TerminalJournal {
        owner,
        dispatch_started: false,
        retry_used: true,
    });
    let plan = engine.plan.clone();
    let truncated = engine.capture_facts().discovery_truncated;
    let malformed = engine.malformed_discovery_for_test();
    let pending = engine.pending_discovery_records_for_test();

    let error = engine
        .cleanup_terminal_batch_without_replay(&mut returned)
        .unwrap_err();

    assert!(error.to_string().contains("not tombstoned"), "{error:#}");
    assert!(returned.is_none(), "the coordinator batch was consumed");
    assert_eq!(
        engine.selection_bindings[&selection_export.cookie].coverage,
        SelectionCoverageState::Uncovered
    );
    assert!(engine.terminal_batch_for_test().is_none());
    assert_eq!(
        engine.terminal_journal_for_test(),
        Some((owner, true, true))
    );
    assert_eq!(engine.loader_context_state_for_test(owner), Some("live"));
    assert_eq!(engine.dispatched_loader_records(), 0);
    assert_eq!(engine.counters.object_skips.len(), 1);
    assert_eq!(
        engine.counters.object_skips[0].subject,
        TERMINAL_DRAIN_SUBJECT
    );
    assert_eq!(
        engine.counters.object_skips[0].reason,
        "the bounded terminal cleanup retry failed; its undispatched batch was discarded without replay"
    );
    assert_eq!(engine.plan, plan);
    assert_eq!(engine.capture_facts().discovery_truncated, truncated);
    assert_eq!(engine.malformed_discovery_for_test(), malformed);
    assert_eq!(engine.pending_discovery_records_for_test(), pending);

    engine.tombstone_loader_context_for_test(owner);
    let skips = engine.counters.object_skips.clone();
    engine.cleanup_started_terminal_journal().unwrap();

    assert_eq!(engine.terminal_journal_for_test(), None);
    assert!(engine.terminal_batch_for_test().is_none());
    assert_eq!(engine.loader_context_state_for_test(owner), None);
    assert_eq!(engine.dispatched_loader_records(), 0);
    assert_eq!(engine.counters.object_skips, skips);
    assert_eq!(engine.plan, plan);
    assert_eq!(engine.capture_facts().discovery_truncated, truncated);
    assert_eq!(engine.malformed_discovery_for_test(), malformed);
    assert_eq!(engine.pending_discovery_records_for_test(), pending);
}

#[test]
fn generic_apply_and_replay_never_consume_the_retained_terminal_authority() {
    let pid = std::process::id();
    let (mut engine, owner) = Engine::retiring_loader_context(pid);
    let view = engine.views[0].id();
    let unrelated = LoaderContextId::from_case_id(9);
    let mut session = ScriptedSession::with_records([], 16);
    session.detach_exports = vec![terminal_export()];
    start_failed_terminal_drain(&mut engine, &mut session, owner);

    // No retirement is due, so an ordinary batch cannot reach the authority.
    engine.retirement_intents.remove(&view);
    apply_ordinary_batch(
        &mut engine,
        &mut session,
        vec![loader_record_for(unrelated, pid)],
    )
    .unwrap();

    assert_eq!(engine.loader_records_accepted, 1);
    let batch = engine.terminal_batch.as_ref().unwrap();
    assert_eq!(
        batch.record_count(),
        0,
        "a generic batch cannot enter the authority batch"
    );
    assert!(!batch.complete());
    assert_eq!(batch.authority.exports, [terminal_export()]);
    assert!(!engine.terminal_journal.unwrap().dispatch_started);

    // The coordinator now owns the exact batch; a retirement replay may
    // neither reconstruct nor dispatch it behind the coordinator's back.
    let carried = engine.take_terminal_batch_for_deferred().unwrap();
    engine
        .retirement_intents
        .insert(view, RetirementCause::ExecRefresh);
    apply_ordinary_batch(
        &mut engine,
        &mut session,
        vec![loader_record_for(unrelated, pid)],
    )
    .unwrap();

    assert_eq!(
        engine.loader_records_accepted, 2,
        "only the two generic records were dispatched"
    );
    assert!(engine.terminal_batch.is_none());
    assert_eq!(
        engine
            .terminal_journal
            .map(|journal| (journal.owner, journal.dispatch_started)),
        Some((owner, false))
    );
    assert!(engine.loader_registry.is_tombstoned(owner));
    assert_eq!(carried.authority.owner, owner);
}

/// The failed-drain record announces a *retry*: "the exact terminal batch
/// remains tombstoned for retry". While the journal is pending that is
/// true. Once the retry lands and the journal clears, nothing remains
/// tombstoned and the announcement is contradicted by the same document
/// that carries it — so capture end judges it, like the empty-scan rule.
#[test]
fn a_terminal_drain_the_capture_retried_is_not_a_published_loss() {
    let pid = std::process::id();
    let (mut engine, owner) = Engine::retiring_loader_context(pid);
    let unrelated = LoaderContextId::from_case_id(9);
    let mut session = ScriptedSession::with_records([], 16);
    session.detach_exports = vec![terminal_export()];
    start_failed_terminal_drain(&mut engine, &mut session, owner);

    let announced = Skipped {
        subject: TERMINAL_DRAIN_SUBJECT.into(),
        reason: TERMINAL_DRAIN_RETRY_REASON.into(),
    };
    assert_eq!(
        announced.reason,
        "the post-detach private discovery drain failed; the exact terminal batch remains \
             tombstoned for retry",
        "the published reason is unchanged"
    );
    assert!(
        engine.plan.skipped.contains(&announced),
        "a failed drain announces its retry: {:?}",
        engine.plan.skipped
    );

    // Still owed at capture end: the announcement is true and stands.
    engine.settle_terminal_drain();
    assert!(engine.plan.skipped.contains(&announced));

    session.dequeues.extend(
        [
            loader_record_for(owner, pid),
            loader_record_for(unrelated, pid),
        ]
        .map(|record| Ok(Some(crate::events::DiscoveryItem::Record(record)))),
    );
    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();
    assert!(engine.terminal_journal.is_none(), "the retry landed");

    engine.settle_terminal_drain();
    assert!(
        !engine.plan.skipped.contains(&announced),
        "a retry the capture proved leaves nothing tombstoned: {:?}",
        engine.plan.skipped
    );
    assert!(
        !engine.counters.object_skips.contains(&announced),
        "and nothing to rebuild the record from"
    );
}

#[test]
fn an_incomplete_terminal_drain_is_continued_and_dispatched_exactly_once() {
    let pid = std::process::id();
    let (mut engine, owner) = Engine::retiring_loader_context(pid);
    let unrelated = LoaderContextId::from_case_id(9);
    let mut session = ScriptedSession::with_records([], 16);
    session.detach_exports = vec![terminal_export()];
    start_failed_terminal_drain(&mut engine, &mut session, owner);

    session.dequeues.extend(
        [
            loader_record_for(owner, pid),
            loader_record_for(owner, pid),
            loader_record_for(unrelated, pid),
        ]
        .map(|record| Ok(Some(crate::events::DiscoveryItem::Record(record)))),
    );
    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

    assert_eq!(
        engine.loader_records_accepted, 3,
        "the continued batch dispatched every collected record once"
    );
    assert!(engine.terminal_batch.is_none());
    assert!(engine.terminal_journal.is_none());
    assert!(engine.loader_registry.context(owner).is_none());

    engine
        .retirement_intents
        .insert(engine.views[0].id(), RetirementCause::ExecRefresh);
    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

    assert_eq!(
        engine.loader_records_accepted, 3,
        "a consumed terminal batch is never collected or dispatched again"
    );
}

#[test]
fn a_mid_drain_ring_failure_retains_the_already_dequeued_prefix() {
    let pid = std::process::id();
    let (mut engine, owner) = Engine::retiring_loader_context(pid);
    let unrelated = LoaderContextId::from_case_id(9);
    let mut session = ScriptedSession::with_records([], 16);
    session.detach_exports = vec![terminal_export()];
    // The post-detach drain takes two records off the ring, then fails.
    session.dequeues.extend([
        Ok(Some(crate::events::DiscoveryItem::Record(
            loader_record_for(owner, pid),
        ))),
        Ok(Some(crate::events::DiscoveryItem::Record(
            loader_record_for(unrelated, pid),
        ))),
        Err(anyhow!("scripted ring read failed")),
    ]);

    apply_ordinary_batch(&mut engine, &mut session, Vec::new())
        .expect("a failed terminal drain is loss, never a batch error");

    assert_eq!(
        engine.loader_records_accepted, 0,
        "an incomplete batch dispatches nothing"
    );
    let batch = engine.terminal_batch.as_ref().unwrap();
    assert_eq!(
        batch.record_count(),
        2,
        "the records already off the ring stay in the retained prefix"
    );
    assert!(!batch.complete());
    assert_eq!(
        batch.tagged_owners(),
        [Some(owner), None],
        "only the owned record of the retained prefix carries authority"
    );
    let journal = engine.terminal_journal.unwrap();
    assert!(!journal.dispatch_started && !journal.retry_used);

    // The one shared continuation finishes the drain and dispatches once.
    session
        .dequeues
        .push_back(Ok(Some(crate::events::DiscoveryItem::Record(
            loader_record_for(owner, pid),
        ))));
    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

    assert_eq!(
        engine.loader_records_accepted, 3,
        "every dequeued record reached dispatch exactly once"
    );
    assert!(engine.terminal_batch.is_none());
    assert!(engine.terminal_journal.is_none());
    assert!(engine.loader_registry.context(owner).is_none());
}

/// The post-detach collector shares the quantum. A stop there is retained
/// as an explicitly incomplete batch — never claimed complete, nothing
/// dispatched — and the one shared continuation finishes it once the ring
/// reads empty, dispatching every dequeued record exactly once.
#[test]
fn a_quantum_stop_after_detach_retains_an_incomplete_batch_until_the_ring_reads_empty() {
    let pid = std::process::id();
    let (mut engine, owner) = Engine::retiring_loader_context(pid);
    let unrelated = LoaderContextId::from_case_id(9);
    let mut session = ScriptedSession::with_records([], 1024);
    session.detach_exports = vec![terminal_export()];
    session
        .dequeues
        .push_back(Ok(Some(crate::events::DiscoveryItem::Record(
            loader_record_for(owner, pid),
        ))));
    session
        .dequeues
        .extend((1..=LIVE_DISCOVERY_DRAIN_QUANTUM).map(|_| {
            Ok(Some(crate::events::DiscoveryItem::Record(
                loader_record_for(unrelated, pid),
            )))
        }));
    session
        .dequeues
        .push_back(Err(anyhow!("dequeued past the quantum")));

    apply_ordinary_batch(&mut engine, &mut session, Vec::new())
        .expect("a quantum stop is backlog, never a batch error");

    assert_eq!(
        engine.loader_records_accepted, 0,
        "an incomplete batch dispatches nothing"
    );
    let batch = engine.terminal_batch.as_ref().unwrap();
    assert_eq!(batch.record_count(), LIVE_DISCOVERY_DRAIN_QUANTUM);
    assert!(
        !batch.complete(),
        "a quantum stop never claims a complete drain"
    );
    assert_eq!(
        session.dequeues.len(),
        2,
        "the record past the quantum and the sentinel stay queued"
    );
    assert!(engine.terminal_journal.is_some());

    session.dequeues.pop_back();
    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

    assert_eq!(
        engine.loader_records_accepted as usize,
        LIVE_DISCOVERY_DRAIN_QUANTUM + 1,
        "every dequeued record reached dispatch exactly once"
    );
    assert!(engine.terminal_batch.is_none());
    assert!(engine.terminal_journal.is_none());
    assert!(engine.loader_registry.context(owner).is_none());
}

/// The terminal sink charges too: a retained prefix is dequeued work even
/// while nothing has been dispatched yet.
#[test]
fn a_retained_terminal_prefix_is_charged_as_capture_work() {
    const WORK_CEILING: u64 = 16 * 1024 * 1024;
    let pid = std::process::id();
    let (mut engine, owner) = Engine::retiring_loader_context(pid);
    assert!(
        engine
            .budget
            .charge(WORK_CEILING - LIVE_DISCOVERY_DRAIN_QUANTUM as u64)
    );
    let mut session = ScriptedSession::with_records([], 1024);
    session.detach_exports = vec![terminal_export()];
    session
        .dequeues
        .extend((0..=LIVE_DISCOVERY_DRAIN_QUANTUM).map(|_| {
            Ok(Some(crate::events::DiscoveryItem::Record(
                loader_record_for(owner, pid),
            )))
        }));

    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

    assert_eq!(engine.loader_records_accepted, 0);
    assert!(!engine.terminal_batch.as_ref().unwrap().complete());
    assert!(
        !engine.budget.charge(1),
        "the retained quantum consumed the last work units"
    );
}

#[test]
fn terminal_predispatch_counter_failure_retains_the_exact_batch_for_one_retry() {
    let pid = std::process::id();
    let (mut engine, owner) = Engine::retiring_loader_context(pid);
    let unrelated = LoaderContextId::from_case_id(9);
    let (selection_export, selection_record) = closed_terminal_selection(&mut engine, owner, pid);
    let mut session = ScriptedSession::with_records(
        [
            loader_record_for(owner, pid),
            loader_record_for(owner, pid),
            loader_record_for(unrelated, pid),
            selection_record,
        ],
        16,
    );
    session.detach_exports = vec![terminal_export(), selection_export];
    session.fail_counter_reads([false, true]);

    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

    assert_eq!(
        engine.loader_records_accepted, 0,
        "a predispatch counter failure dispatches nothing"
    );
    let batch = engine.terminal_batch.as_ref().unwrap();
    assert_eq!(batch.record_count(), 4);
    assert!(batch.complete());
    assert_eq!(batch.authority.owner, owner);
    assert_eq!(
        batch.authority.exports,
        [terminal_export(), selection_export]
    );
    assert_eq!(
        batch.tagged_owners(),
        [Some(owner), Some(owner), None, Some(owner)],
        "only the owned records carry terminal authority"
    );
    let journal = engine.terminal_journal.unwrap();
    assert!(journal.retry_used && !journal.dispatch_started);
    assert_eq!(
        engine.selection_bindings[&selection_export.cookie].coverage,
        SelectionCoverageState::OwnedClosed(NonZeroU64::new(1).unwrap()),
        "a retained retry does not invalidate the closed proof"
    );

    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

    assert_eq!(
        engine.loader_records_accepted, 3,
        "the one retry dispatches the exact retained batch once"
    );
    assert!(engine.terminal_batch.is_none());
    assert!(engine.terminal_journal.is_none());
    assert!(engine.loader_registry.context(owner).is_none());
}

#[test]
fn an_exhausted_terminal_predispatch_retry_cleans_up_without_dispatching() {
    let pid = std::process::id();
    let (mut engine, owner) = Engine::retiring_loader_context(pid);
    let (selection_export, selection_record) = closed_terminal_selection(&mut engine, owner, pid);
    let mut session =
        ScriptedSession::with_records([loader_record_for(owner, pid), selection_record], 16);
    session.detach_exports = vec![selection_export];
    session.fail_counter_reads([false, true]);

    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();
    assert!(engine.terminal_journal.unwrap().retry_used);
    assert_eq!(
        engine.selection_bindings[&selection_export.cookie].coverage,
        SelectionCoverageState::OwnedClosed(NonZeroU64::new(1).unwrap())
    );

    session.fail_counter_reads([false, true]);
    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

    assert_eq!(
        engine.loader_records_accepted, 0,
        "an exhausted retry never replays the records it dropped"
    );
    assert!(engine.terminal_batch.is_none());
    assert!(engine.terminal_journal.is_none());
    assert!(engine.loader_registry.context(owner).is_none());
    assert_eq!(
        engine.selection_bindings[&selection_export.cookie].coverage,
        SelectionCoverageState::Uncovered
    );
}

#[test]
fn a_failed_owned_prearm_cleanup_uses_the_shared_predispatch_journal() {
    let pid = std::process::id();
    let (mut engine, owner) = Engine::retiring_loader_context(pid);
    let unrelated = LoaderContextId::from_case_id(9);
    let mut session = ScriptedSession::with_records(
        [
            loader_record_for(owner, pid),
            loader_record_for(unrelated, pid),
        ],
        16,
    );
    session.detach_exports = vec![terminal_export()];
    session.fail_counter_reads([true]);
    // A prior snapshot already authorized these hits, so only the routing
    // of the failed post-detach read is under test.
    engine.counter_snapshot = session.counters;
    let mut pending_views = PendingViewRetirements::new();

    let error = engine
        .fail_owned_prearm_attachment(
            owner,
            true,
            &mut session,
            &mut pending_views,
            "loader registry mark-attached failed".into(),
        )
        .unwrap_err();

    assert!(error.to_string().contains("mark-attached"), "{error:#}");
    assert_eq!(
        engine.loader_records_accepted, 0,
        "a failed post-detach counter snapshot dispatches nothing"
    );
    let batch = engine.terminal_batch.as_ref().unwrap();
    assert_eq!(batch.record_count(), 2);
    assert!(batch.complete());
    assert_eq!(batch.authority.exports, [terminal_export()]);
    assert_eq!(batch.tagged_owners(), [Some(owner), None]);
    let journal = engine.terminal_journal.unwrap();
    assert!(journal.retry_used && !journal.dispatch_started);
    assert!(
        engine.loader_registry.is_tombstoned(owner),
        "the tombstone survives the shared one retry"
    );

    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

    assert_eq!(
        engine.loader_records_accepted, 2,
        "the shared retry dispatches the exact batch once"
    );
    assert!(engine.terminal_batch.is_none());
    assert!(engine.terminal_journal.is_none());
    assert!(engine.loader_registry.context(owner).is_none());
}

#[test]
fn a_failed_owned_prearm_drain_retains_its_dequeued_prefix() {
    let pid = std::process::id();
    let (mut engine, owner) = Engine::retiring_loader_context(pid);
    let mut session = ScriptedSession::with_records([], 16);
    session.detach_exports = vec![terminal_export()];
    // The pre-arm drain takes one record off the ring, then the ring fails.
    session.dequeues.extend([
        Ok(Some(crate::events::DiscoveryItem::Record(
            loader_record_for(owner, pid),
        ))),
        Err(anyhow!("scripted ring read failed")),
    ]);
    let mut pending_views = PendingViewRetirements::new();

    let error = engine
        .fail_owned_prearm_attachment(
            owner,
            true,
            &mut session,
            &mut pending_views,
            "loader registry mark-attached failed".into(),
        )
        .unwrap_err();

    assert!(error.to_string().contains("mark-attached"), "{error:#}");
    assert_eq!(
        engine.loader_records_accepted, 0,
        "an incomplete batch dispatches nothing"
    );
    let batch = engine.terminal_batch.as_ref().unwrap();
    assert_eq!(
        batch.record_count(),
        1,
        "the record already off the ring stays in the retained prefix"
    );
    assert!(!batch.complete());
    assert_eq!(batch.tagged_owners(), [Some(owner)]);
    assert!(engine.loader_registry.is_tombstoned(owner));

    // The one shared continuation finishes the drain and dispatches once.
    session
        .dequeues
        .push_back(Ok(Some(crate::events::DiscoveryItem::Record(
            loader_record_for(owner, pid),
        ))));
    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

    assert_eq!(
        engine.loader_records_accepted, 2,
        "every dequeued record reached dispatch exactly once"
    );
    assert!(engine.terminal_batch.is_none());
    assert!(engine.terminal_journal.is_none());
    assert!(engine.loader_registry.context(owner).is_none());
}

#[test]
fn a_started_terminal_journal_retries_registry_cleanup_without_replaying_records() {
    let pid = std::process::id();
    let (mut engine, owner) = Engine::retiring_loader_context(pid);
    let unrelated = LoaderContextId::from_case_id(9);
    let mut session = ScriptedSession::with_records(
        [
            loader_record_for(owner, pid),
            loader_record_for(unrelated, pid),
        ],
        16,
    );
    session.fail_counter_reads([false, true]);
    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();
    assert_eq!(engine.loader_records_accepted, 0);

    // The tombstoned entry is gone before the retry, so the started journal
    // can never finish its cleanup.
    engine.loader_registry.remove(owner).unwrap();
    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

    assert_eq!(
        engine.loader_records_accepted, 2,
        "the retry dispatched the exact batch once"
    );
    assert!(engine.terminal_batch.is_none());
    assert!(
        engine.terminal_journal.unwrap().dispatch_started,
        "a failed registry removal keeps the started journal pending"
    );

    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

    assert_eq!(
        engine.loader_records_accepted, 2,
        "a started journal repeats only its registry removal"
    );
    assert!(engine.terminal_batch.is_none());
    assert!(engine.terminal_journal.unwrap().dispatch_started);
}

#[test]
fn pt_interp_alias_binds_the_mapped_dev_inode_and_mapping_path() {
    use p11scope_manifest::maps::Device;

    let interpreter = PathBuf::from("/lib64/ld-linux-x86-64.so.2");
    let mapped = PathBuf::from("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");
    let key = ObjectKey {
        device: Device {
            major: 0,
            minor: 32,
        },
        inode: 35_110_329,
    };
    let maps = vec![
        MapEntry {
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            permissions: *b"r-xp",
            device: Device {
                major: 8,
                minor: 32,
            },
            inode: key.inode,
            raw_path: Some(interpreter.as_os_str().as_encoded_bytes().to_vec()),
        },
        MapEntry {
            start: 0x3000,
            end: 0x4000,
            file_offset: 0,
            permissions: *b"r-xp",
            device: key.device,
            inode: key.inode,
            raw_path: Some(mapped.as_os_str().as_encoded_bytes().to_vec()),
        },
    ];

    let index = MapIndex::new(&maps).unwrap();
    let (mapping, path) = exact_executable_mapping(&index, key).unwrap();
    assert_eq!(mapping.start, 0x3000, "inode alone is not full identity");
    assert_eq!(path, mapped, "pin through the mapping's usable alias");
    assert_ne!(path, interpreter, "PT_INTERP spelling is not map authority");
}

fn bounded_elf(interpreters: &[&[u8]]) -> Vec<u8> {
    let count = interpreters.len().max(1);
    let table_len = count * ELF_PROGRAM_HEADER_BYTES;
    let mut bytes = vec![0u8; ELF_HEADER_BYTES + table_len];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&(ELF_HEADER_BYTES as u64).to_le_bytes());
    bytes[52..54].copy_from_slice(&(ELF_HEADER_BYTES as u16).to_le_bytes());
    bytes[54..56].copy_from_slice(&(ELF_PROGRAM_HEADER_BYTES as u16).to_le_bytes());
    bytes[56..58].copy_from_slice(&(count as u16).to_le_bytes());
    if interpreters.is_empty() {
        bytes[ELF_HEADER_BYTES..ELF_HEADER_BYTES + 4].copy_from_slice(&1u32.to_le_bytes());
        return bytes;
    }
    for (index, interpreter) in interpreters.iter().enumerate() {
        let program = ELF_HEADER_BYTES + index * ELF_PROGRAM_HEADER_BYTES;
        let offset = bytes.len() as u64;
        bytes[program..program + 4].copy_from_slice(&3u32.to_le_bytes());
        bytes[program + 8..program + 16].copy_from_slice(&offset.to_le_bytes());
        bytes[program + 32..program + 40]
            .copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
        bytes.extend_from_slice(interpreter);
    }
    bytes
}

fn bounded_interpreter(bytes: &[u8]) -> std::result::Result<Option<PathBuf>, String> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("executable");
    std::fs::write(&path, bytes).unwrap();
    let file = std::fs::File::open(path).unwrap();
    read_bounded_interpreter(&file, bytes.len() as u64).map(|(path, _)| path)
}

fn bounded_elf32(interpreter: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 52 + 32 + interpreter.len()];
    bytes[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
    bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&3u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&52u32.to_le_bytes());
    bytes[40..42].copy_from_slice(&52u16.to_le_bytes());
    bytes[42..44].copy_from_slice(&32u16.to_le_bytes());
    bytes[44..46].copy_from_slice(&1u16.to_le_bytes());
    bytes[52..56].copy_from_slice(&3u32.to_le_bytes());
    bytes[56..60].copy_from_slice(&84u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&(interpreter.len() as u32).to_le_bytes());
    bytes[84..].copy_from_slice(interpreter);
    bytes
}

#[test]
fn bounded_pt_interp_reader_rejects_malformed_or_unbounded_elf() {
    assert_eq!(
        bounded_interpreter(&bounded_elf(&[b"/lib/ld.so\0"])),
        Ok(Some(PathBuf::from("/lib/ld.so")))
    );
    assert_eq!(bounded_interpreter(&bounded_elf(&[])), Ok(None));
    assert_eq!(
        bounded_interpreter(&bounded_elf32(b"/lib/ld-linux.so.2\0")),
        Ok(Some(PathBuf::from("/lib/ld-linux.so.2")))
    );
    for interpreter in [
        &b"relative\0"[..],
        &b"/lib/ld.so"[..],
        &b"/lib/ld\0.so\0"[..],
        &b"\0"[..],
    ] {
        assert!(bounded_interpreter(&bounded_elf(&[interpreter])).is_err());
    }
    assert!(bounded_interpreter(&bounded_elf(&[b"/a\0", b"/b\0"])).is_err());
    let oversized = vec![b'a'; MAX_INTERPRETER_BYTES + 1];
    assert!(bounded_interpreter(&bounded_elf(&[&oversized])).is_err());

    let mut malformed = bounded_elf(&[b"/lib/ld.so\0"]);
    for index in [4usize, 5, 18, 52, 54] {
        let saved = malformed[index];
        malformed[index] = 0;
        assert!(
            bounded_interpreter(&malformed).is_err(),
            "accepted byte {index}"
        );
        malformed[index] = saved;
    }
    malformed[56..58].copy_from_slice(&0xffffu16.to_le_bytes());
    assert!(bounded_interpreter(&malformed).is_err());

    let mut out_of_bounds = bounded_elf(&[b"/lib/ld.so\0"]);
    out_of_bounds[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(bounded_interpreter(&out_of_bounds).is_err());
    let mut overflowing_interp = bounded_elf(&[b"/lib/ld.so\0"]);
    overflowing_interp[ELF_HEADER_BYTES + 8..ELF_HEADER_BYTES + 16]
        .copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(bounded_interpreter(&overflowing_interp).is_err());
}

/// Task 11 fix round 3 (shadow finding 5). The live consumers used the
/// compatibility `maps::resolve(&[MapEntry], addr)`, which rebuilds — and
/// so revalidates, O(entries) — the whole index for every lookup: the
/// loader snapshot loops were quadratic in a target-controlled entry count
/// and none of it was charged. One validated index is now built per
/// accepted snapshot and every examined entry and lookup is charged, so
/// this exact unit arithmetic is what a regression to that wrapper breaks.
#[test]
fn one_charged_index_serves_every_live_lookup_in_one_snapshot() {
    const WORK_CEILING: u64 = 16 * 1024 * 1024;
    let key = ObjectKey {
        device: Device { major: 8, minor: 1 },
        inode: 20,
    };
    // The shape a target creates to make a per-lookup index rebuild
    // quadratic: many executable mappings of one identity and one path.
    let entries: Vec<MapEntry> = (0..128u64)
        .map(|index| MapEntry {
            start: 0x700000 + index * 0x2000,
            end: 0x700000 + index * 0x2000 + 0x1000,
            file_offset: index * 0x1000,
            permissions: if index % 2 == 0 { *b"r-xp" } else { *b"rw-p" },
            device: key.device,
            inode: if index % 2 == 0 { key.inode } else { 0 },
            raw_path: (index % 2 == 0).then(|| b"/lib/ld.so".to_vec()),
        })
        .collect();
    let matching = 64u64;

    // One validation pass per snapshot, then one unit per entry examined
    // and one per index lookup in each of the two snapshot loops.
    let expected = entries.len() as u64 * 3 + matching * 2;
    let snapshots = |budget: &mut CaptureWorkBudget| {
        let index = index_maps_or_refuse(&entries, budget).expect("a kernel-ordered snapshot");
        let executable =
            executable_map_snapshot(&index, key, budget).expect("the executable mappings");
        assert_eq!(executable.len() as u64, matching);
        let (path, loader) = loader_map_snapshot(&index, key, budget).expect("the loader mappings");
        assert_eq!(path, PathBuf::from("/lib/ld.so"));
        assert_eq!(loader.len() as u64, matching);
    };

    let mut budget = CaptureWorkBudget::default();
    assert!(budget.charge(WORK_CEILING - expected));
    snapshots(&mut budget);
    assert!(
        !budget.charge(1),
        "one index and two charged passes cost exactly {expected} units"
    );

    let mut budget = CaptureWorkBudget::default();
    assert!(budget.charge(WORK_CEILING - expected - 1));
    snapshots(&mut budget);
    assert!(budget.charge(1), "and never fewer");
    assert!(!budget.charge(1));

    // A stopped capture refuses the snapshot under its own reason, not as
    // "no usable executable mapping".
    let mut budget = CaptureWorkBudget::default();
    assert!(!budget.charge(u64::MAX));
    assert_eq!(
        index_maps_or_refuse(&entries, &mut budget).unwrap_err(),
        WORK_CEILING_REASON
    );
    let index = MapIndex::new(&entries).unwrap();
    assert_eq!(
        executable_map_snapshot(&index, key, &mut budget).unwrap_err(),
        WORK_CEILING_REASON
    );
    assert_eq!(
        loader_map_snapshot(&index, key, &mut budget).unwrap_err(),
        WORK_CEILING_REASON
    );
}

#[test]
fn loader_mapping_selection_is_path_qualified_and_offset_exact() {
    let key = ObjectKey {
        device: Device { major: 8, minor: 1 },
        inode: 20,
    };
    let mapping = |start, offset, path: &[u8]| MapEntry {
        start,
        end: start + 0x1000,
        file_offset: offset,
        permissions: *b"r-xp",
        device: key.device,
        inode: key.inode,
        raw_path: Some(path.to_vec()),
    };
    let maps = vec![
        mapping(0x700000, 0, b"/lib/ld.so"),
        mapping(0x702000, 0x2000, b"/lib/ld.so"),
    ];
    let mut budget = CaptureWorkBudget::default();
    let index = MapIndex::new(&maps).unwrap();
    let (path, executable) = loader_map_snapshot(&index, key, &mut budget).unwrap();
    assert_eq!(path, PathBuf::from("/lib/ld.so"));
    assert_eq!(
        unique_mapping_for_offset(&executable, 0x2100).unwrap(),
        maps[1]
    );

    let mut collision = maps.clone();
    collision.push(mapping(0x800000, 0, b"/other/ld.so"));
    let collision_index = MapIndex::new(&collision).unwrap();
    assert!(loader_map_snapshot(&collision_index, key, &mut budget).is_err());
    assert!(unique_mapping_for_offset(&executable, 0x5000).is_err());
}

#[test]
fn loader_pin_collision_cannot_commit_a_plan_with_missing_pin_id() {
    let (plan, pins) = plan_with_pins(1, 0);
    assert!(candidate_identity_is_complete(&plan, &[], &pins));
    assert!(
        !candidate_identity_is_complete(&plan, &[], &PinnedObjects::empty()),
        "a collision-rejected ID cannot remain in an active plan"
    );
}

fn pin_test_module(view: &ProcessView, module: &ScannedModule) -> PinnedObjects {
    let mut budget = CaptureWorkBudget::new(ScanLimits {
        per_object_bytes: u64::MAX,
        total_bytes: u64::MAX,
    });
    let (pins, skipped) =
        pin_scanned_view_objects(view, std::slice::from_ref(module), &mut budget).unwrap();
    assert!(skipped.is_empty(), "{skipped:?}");
    pins
}

#[test]
fn exact_loader_pin_is_view_owned_but_not_a_provider_module() {
    let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let (raw_modules, mut provider_pins) = pinned_self();
    let provider_modules = reconcile_for_test(&raw_modules, &mut provider_pins);
    let mut engine = Engine::empty();
    engine.plan = plan::build_from_reconciled_modules(&provider_modules);
    engine.pinned = provider_pins;
    engine.modules = provider_modules;

    let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
    let map_index = MapIndex::new(&maps).expect("the self maps snapshot is valid");
    let executable = std::env::current_exe().unwrap();
    let (loader_mapping, loader_path) = maps
        .iter()
        .filter(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
        .find_map(|mapping| match map_index.resolve(mapping.start) {
            Resolved::File {
                path: MappedPath::Usable(path),
                ..
            } if path != executable => Some((mapping, path)),
            _ => None,
        })
        .expect("the test process has a mapped executable dependency");
    let loader_module = mapped_object(&view, loader_mapping, &loader_path);
    let loader_pins = pin_test_module(&view, &loader_module);
    let local_loader = loader_pins
        .id_for_scanned(&loader_module, loader_module.key, &loader_module.path)
        .unwrap();
    let (candidate, loader) = engine
        .loader_candidate(
            view.id(),
            &loader_module,
            &loader_pins,
            local_loader,
            Vec::new(),
        )
        .unwrap();
    let loader = loader.expect("the exact loader pin survives reconciliation");

    assert!(candidate.pinned.summary(loader).is_some());
    assert!(
        candidate
            .plan
            .modules
            .iter()
            .all(|module| module.object != loader),
        "a loader-only pin is not a provider module"
    );
    let evidence = discovery_evidence(
        &candidate.plan,
        &candidate.pinned,
        &DiscoveryCounters::default(),
    );
    assert!(
        evidence
            .modules
            .iter()
            .all(|module| module.path != loader_module.path),
        "public discovery has no linker-only module"
    );
}

#[test]
fn exact_loader_pin_survives_cross_overlay_canonicalization() {
    let (mut engine, _, provider, _) = engine_with_overlay(104);
    let loader_module = overlay_module(overlay_key(102));
    let mut loader_pins = overlay_view_pin(&loader_module, 999, OVERLAY_SHA, 1, true);
    let (_, bind_skips) =
        bind_scanned_modules(std::slice::from_ref(&loader_module), &mut loader_pins);
    assert!(bind_skips.is_empty(), "{bind_skips:?}");
    let local_loader = loader_pins
        .id_for_scanned(&loader_module, loader_module.key, &loader_module.path)
        .unwrap();

    let (candidate, loader) = engine
        .loader_candidate(
            loader_module.view,
            &loader_module,
            &loader_pins,
            local_loader,
            Vec::new(),
        )
        .unwrap();
    let loader = loader.expect("the exact local loader pin survives reconciliation");

    assert_ne!(loader, provider);
    assert!(loader_pins.exactly_matches(local_loader, &candidate.pinned, loader));
    assert_eq!(
        candidate
            .pinned
            .id_for_scanned(&loader_module, loader_module.key, &loader_module.path),
        Some(loader)
    );
    assert!(
        candidate
            .pinned
            .view_claims(loader_module.view)
            .is_some_and(|claims| claims.pins.contains(&loader))
    );
    assert!(candidate.pinned.has_overlay_uncertainty());
    assert!(candidate_identity_is_complete(
        &candidate.plan,
        &candidate.modules,
        &candidate.pinned
    ));
    assert_eq!(candidate.plan.modules.len(), 1);
    assert_eq!(candidate.plan.modules[0].object, provider);
    assert!(
        candidate
            .plan
            .slots
            .iter()
            .all(|slot| slot.object != loader)
    );
    let evidence = discovery_evidence(
        &candidate.plan,
        &candidate.pinned,
        &DiscoveryCounters::default(),
    );
    assert_eq!(evidence.modules.len(), 1);

    let mut retired = candidate.pinned;
    let claims = retired.remove_view(loader_module.view).unwrap();
    assert!(claims.pins.contains(&loader));
    assert!(retired.summary(loader).is_none());
    assert_eq!(
        retired.id_for_scanned(&loader_module, loader_module.key, &loader_module.path),
        None,
        "retiring the loader view removes its raw ownership"
    );
}

#[test]
fn loader_collision_candidate_keeps_provider_retirement_without_loader_id() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("provider-and-loader.so");
    std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
    let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let len = file.metadata().unwrap().len() as usize;
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    assert_ne!(address, libc::MAP_FAILED);
    let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
    let mapping = maps
        .iter()
        .find(|mapping| (mapping.start..mapping.end).contains(&(address as u64)))
        .unwrap();
    let mut provider = mapped_object(&view, mapping, &path);
    provider.tables.push(ScannedTable {
        version: (2, 40),
        walk: "full",
        entries: vec![ScannedEntry {
            name: "C_Sign",
            object: provider.key,
            object_path: provider.path.clone(),
            file_offset: 0x10,
        }],
        null_entries: Vec::new(),
        unpinned: Vec::new(),
        address: 0x7000,
        file_offset: Some(0),
        live_return: false,
        manifest_supported: false,
    });
    let mut provider_pins = pin_test_module(&view, &provider);
    let provider_modules = reconcile_for_test(std::slice::from_ref(&provider), &mut provider_pins);
    let mut engine = Engine::empty();
    engine.plan = plan::build_from_reconciled_modules(&provider_modules);
    engine.pinned = provider_pins;
    engine.modules = provider_modules;
    let rejected_loader = engine.plan.modules[0].object;

    let context_spec = |view| LoaderContextSpec {
        view,
        loader: rejected_loader,
        mapping: Some(MapEntry {
            start: 0x4000,
            end: 0x5000,
            file_offset: 0x2000,
            permissions: *b"r-xp",
            device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
            inode: 7,
            raw_path: Some(b"/lib/ld.so".to_vec()),
        }),
        hook: p11scope_manifest::elf::SymbolFact {
            virtual_address: 0x2100,
            file_offset: 0x2100,
        },
        state_address: None,
    };
    let prepared = engine
        .loader_registry
        .preflight(context_spec(ProcessViewId(80)))
        .unwrap();
    let prepared = engine.loader_registry.prepare(prepared).unwrap();
    let attached = engine
        .loader_registry
        .preflight(context_spec(ProcessViewId(81)))
        .unwrap();
    let attached = engine.loader_registry.prepare(attached).unwrap();
    engine.loader_registry.mark_attached(attached).unwrap();
    let tombstoned = engine
        .loader_registry
        .preflight(context_spec(ProcessViewId(82)))
        .unwrap();
    let tombstoned = engine.loader_registry.prepare(tombstoned).unwrap();
    engine.loader_registry.mark_attached(tombstoned).unwrap();
    engine.loader_registry.tombstone(tombstoned).unwrap();

    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&[0])
        .unwrap();
    let loader_module = mapped_object(&view, mapping, &path);
    let loader_pins = pin_test_module(&view, &loader_module);
    let local_loader = loader_pins
        .id_for_scanned(&loader_module, loader_module.key, &loader_module.path)
        .unwrap();
    let (candidate, loader) = engine
        .loader_candidate(
            view.id(),
            &loader_module,
            &loader_pins,
            local_loader,
            Vec::new(),
        )
        .unwrap();

    assert!(loader.is_none(), "the conflicting loader has no authority");
    assert_eq!(candidate.delta.retire.len(), 1);
    assert!(
        candidate
            .plan
            .slots
            .iter()
            .all(|slot| !candidate.plan.is_active(slot.index))
    );
    assert!(candidate_identity_is_complete(
        &candidate.plan,
        &candidate.modules,
        &candidate.pinned
    ));
    let admission = candidate_admission(
        &engine.views,
        &[],
        &candidate.views,
        &engine.loader_registry,
        &candidate.pinned,
        &engine.pinned,
        true,
    );
    assert_eq!(
        admission.missing_contexts,
        vec![prepared, attached, tombstoned],
        "Prepared, Attached, and Tombstoned loader pins are all candidate evidence"
    );

    assert!(candidate.pinned.rejects(loader_module.key));
    let rejected_keys = candidate.pinned.newly_rejected_keys(&engine.pinned);
    let outcome = ApplyOutcome {
        missing_contexts: admission.missing_contexts.clone(),
        newly_rejected_keys: rejected_keys.clone(),
        ..ApplyOutcome::default()
    };
    let mut pending_views = PendingViewRetirements::new();
    engine.queue_apply_outcome(&outcome, &mut pending_views);
    assert_eq!(engine.pending_rejected_keys, rejected_keys);
    drop(candidate);
    engine.loader_registry.cancel_prepared(prepared).unwrap();
    engine.loader_registry.remove(prepared).unwrap();
    engine.loader_registry.tombstone(attached).unwrap();
    engine.loader_registry.remove(attached).unwrap();
    engine.loader_registry.remove(tombstoned).unwrap();
    let keys = engine.pending_rejected_keys.clone();
    let replay = engine
        .conservative_candidate(&BTreeSet::new(), &keys)
        .unwrap();
    assert!(
        replay.pinned.rejects(loader_module.key),
        "serial context cleanup cannot discard the collision that selected it"
    );
    assert_eq!(
        replay.delta.retire.len(),
        1,
        "the fresh post-cleanup candidate must retain the affected provider retirement"
    );
    assert_eq!(unsafe { libc::munmap(address, len) }, 0);
}

#[test]
fn live_candidate_captures_rejected_keys_before_fallible_plan_extension() {
    let (_, raw_modules, mut pins, _) = same_object_scan_and_manifest(0x10);
    let modules = reconcile_for_test(&raw_modules, &mut pins);
    let mut engine = Engine::empty();
    engine.plan = plan::build_from_reconciled_modules(&modules);
    assert_eq!(engine.plan.slots.len(), 1);
    engine.plan.slots[0].descriptor_index += 1;
    engine.plan.slots[0].semantics = p11scope_ebpf_common::SlotSemantics::COUNT_ONLY;
    engine.plan.slots[0].semantic_ambiguous = true;
    engine.pinned = pins;
    engine.modules = modules;

    let rejected = ObjectKey {
        device: p11scope_manifest::maps::Device {
            major: 254,
            minor: 1,
        },
        inode: u64::MAX - 1,
    };
    let mut candidate_pins = engine.pinned.clone();
    assert!(
        candidate_pins
            .reapply_rejected_keys(&[rejected].into_iter().collect())
            .is_empty()
    );

    assert!(
        engine
            .live_candidate(candidate_pins, raw_modules, Vec::new())
            .is_err(),
        "the fixture reaches the fallible plan-extension boundary"
    );

    assert_eq!(
        engine.pending_rejected_keys,
        [rejected].into_iter().collect(),
        "later plan construction cannot erase the already-proved rejection"
    );
}

#[test]
fn conservative_intent_survives_refusal_until_current_candidate_commits() {
    let (_, raw_modules, mut pins, _) = same_object_scan_and_manifest(0x10);
    let modules = reconcile_for_test(&raw_modules, &mut pins);
    let retired = raw_modules[0].view;
    let rejected = pins.pinned().next().unwrap().key;
    let mut engine = Engine::empty();
    engine.plan = plan::build_from_reconciled_modules(&modules);
    engine.pinned = pins;
    engine.modules = modules;
    engine.pending_retirements.insert(retired);
    engine.pending_rejected_keys.insert(rejected);

    let retirements = engine.pending_retirements.clone();
    let rejected_keys = engine.pending_rejected_keys.clone();
    let candidate = engine
        .conservative_candidate(&retirements, &rejected_keys)
        .unwrap();
    assert!(candidate.delta.new.is_empty());
    assert!(candidate.delta.replace.is_empty());
    assert!(candidate.plan.modules.is_empty());
    assert!(candidate.pinned.rejects(rejected));

    let mut pending_views = PendingViewRetirements::new();
    let refused = ApplyOutcome {
        stale_views: [ProcessViewId(91)].into_iter().collect(),
        newly_rejected_keys: rejected_keys.clone(),
        ..ApplyOutcome::default()
    };
    assert!(!engine.queue_conservative_outcome(
        &refused,
        &retirements,
        &rejected_keys,
        &mut pending_views,
    ));
    assert_eq!(engine.pending_retirements, retirements);
    assert_eq!(engine.pending_rejected_keys, rejected_keys);

    let committed = ApplyOutcome {
        disposition: ApplyDisposition::Accepted,
        changed: true,
        newly_rejected_keys: rejected_keys.clone(),
        ..ApplyOutcome::default()
    };
    assert!(engine.queue_conservative_outcome(
        &committed,
        &retirements,
        &rejected_keys,
        &mut pending_views,
    ));
    assert!(engine.pending_retirements.is_empty());
    assert!(engine.pending_rejected_keys.is_empty());
}

#[test]
fn candidate_admission_keeps_exact_retained_and_local_stale_view_ids() {
    fn exited_view(id: ProcessViewId) -> ProcessView {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let view = ProcessView::open(id, child.id()).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!view.still_the_same());
        view
    }

    let retained = exited_view(ProcessViewId(90));
    let local_new = exited_view(ProcessViewId(91));
    let candidate_views = [retained.id(), local_new.id()].into_iter().collect();
    let admission = candidate_admission(
        std::slice::from_ref(&retained),
        &[&local_new],
        &candidate_views,
        &LoaderRegistry::default(),
        &PinnedObjects::empty(),
        &PinnedObjects::empty(),
        false,
    );

    assert_eq!(admission.stale_views, candidate_views);
    assert!(!admission.targets_ok);
}

#[test]
fn post_retirement_target_failure_requires_conservative_apply() {
    let failed = CandidateAdmission {
        targets_ok: false,
        ..CandidateAdmission::default()
    };

    assert!(
        !failed.requires_conservative_apply(false),
        "a pure preflight failure leaves the transaction unchanged"
    );
    assert!(
        failed.requires_conservative_apply(true),
        "after dynamic retirement the same failure must commit conservative subtraction"
    );
}

#[test]
fn every_pre_mutation_refusal_latches_shared_active_slot_provenance() {
    fn plans() -> (plan::AttachPlan, plan::AttachPlan, u32) {
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let mut current = plan_with(1, 0);
        current.slots[0].descriptor_index = descriptor;
        current.slots[0].semantics = crate::kinds::DESCRIPTORS[descriptor as usize];
        let mut rebuilt = current.clone();
        let mut second = rebuilt.modules[0].clone();
        second.id = plan::ModuleId(1);
        second.object = PinnedObjectId(43);
        second.key.inode = 43;
        second.path = "/opt/peer.so".into();
        rebuilt.modules.push(second);
        rebuilt.slots[0].descriptor_index = 0;
        rebuilt.slots[0].semantics = p11scope_ebpf_common::SlotSemantics::COUNT_ONLY;
        rebuilt.slots[0].semantic_ambiguous = true;
        rebuilt.slots[0].module_ids.push(plan::ModuleId(1));
        let mut candidate = current.clone();
        let delta = candidate.extend_exact(rebuilt).unwrap();
        assert_eq!(delta.replace.len(), 1);
        (current, candidate, descriptor)
    }

    let refusals = [
        (
            "target preflight",
            CandidateAdmission {
                targets_ok: false,
                ..CandidateAdmission::default()
            },
        ),
        (
            "stale generation",
            CandidateAdmission {
                stale_views: [ProcessViewId(91)].into_iter().collect(),
                targets_ok: true,
                ..CandidateAdmission::default()
            },
        ),
        (
            "missing loader context",
            CandidateAdmission {
                missing_contexts: vec![LoaderContextId::from_case_id(7)],
                targets_ok: true,
                ..CandidateAdmission::default()
            },
        ),
    ];

    for (label, admission) in refusals {
        let (current, candidate, descriptor) = plans();
        let mut engine = Engine::empty();
        engine.plan = current;

        assert!(admission.refuses_candidate(), "{label}");
        assert!(
            engine.latch_candidate_ambiguity(&candidate),
            "{label} must report a canonical semantic change"
        );
        assert_eq!(engine.plan.slots[0].descriptor_index, descriptor, "{label}");
        assert_eq!(
            engine.plan.slots[0].module_ids,
            [plan::ModuleId(0)],
            "{label}"
        );
        assert_eq!(engine.plan.module_of_slot(0), None, "{label}");
        assert_eq!(engine.plan.module_ambiguous, 1, "{label}");
        assert_eq!(engine.discovery.module_ambiguous, 1, "{label}");
        assert!(
            !engine.latch_candidate_ambiguity(&candidate),
            "{label} must be idempotent"
        );
    }
}

#[test]
fn context_free_refresh_does_not_create_retirement_intent() {
    let removed = [ProcessViewId(1)].into_iter().collect();
    let context_views = [ProcessViewId(2)].into_iter().collect();
    let failed = [ProcessViewId(3)].into_iter().collect();

    assert_eq!(
        completed_retirement_intent(&removed, &context_views, &failed),
        [ProcessViewId(1), ProcessViewId(2)].into_iter().collect(),
        "removed views and successful context retirements persist; a context-free refresh does not"
    );
}

#[test]
fn post_retirement_local_new_stale_requires_conservative_apply() {
    let stale = CandidateAdmission {
        stale_views: [ProcessViewId(91)].into_iter().collect(),
        targets_ok: true,
        ..CandidateAdmission::default()
    };

    assert!(
        !stale.requires_conservative_apply(false),
        "a pre-mutation local generation loss leaves canonical topology unchanged"
    );
    assert!(
        stale.requires_conservative_apply(true),
        "after dynamic retirement local-only staleness still requires static subtraction"
    );
}

#[test]
fn post_attach_generation_loss_detaches_and_cannot_commit_stale_candidate() {
    let view = ProcessView::open(ProcessViewId(91), std::process::id()).unwrap();
    let checks = Cell::new(0usize);
    let outcome = generation_checked_mutation(
        || {
            let call = checks.get();
            checks.set(call + 1);
            view.still_the_same() && call == 0
        },
        || "attached",
    );
    let mut detached = 0;
    let mut retired_views = 0;
    let mut committed = false;
    match outcome {
        GenerationMutation::PostcheckFailed(value) => {
            assert_eq!(value, "attached");
            detached += 1;
            retired_views += 1;
        }
        GenerationMutation::Committed(_) => committed = true,
        GenerationMutation::PrecheckFailed => {}
    }

    assert_eq!(checks.get(), 2, "generation is checked on both sides");
    assert_eq!(detached, 1, "post-attach loss triggers one cleanup");
    assert_eq!(retired_views, 1, "the stale candidate view is retired now");
    assert!(!committed, "stale ownership is never committed");

    let (raw_modules, mut pins) = pinned_self();
    let stale = raw_modules[0].view;
    let (modules, skipped) = bind_scanned_modules(&raw_modules, &mut pins);
    assert!(skipped.is_empty());
    let (remaining_pins, remaining_modules) =
        candidate_sources_without_view(&pins, &modules, stale);
    assert!(
        remaining_modules.is_empty(),
        "stale module ownership is removed"
    );
    assert_eq!(
        remaining_pins.pinned().count(),
        0,
        "stale pins are removed before the candidate can commit"
    );
    let remaining_reconciled: Vec<_> = modules
        .iter()
        .filter(|module| module.scanned.view != stale)
        .cloned()
        .collect();

    let mut candidate = LiveCandidate {
        pinned: pins,
        modules,
        plan: plan::build_from_reconciled_modules(&[]),
        delta: plan::AttachDelta {
            new: Vec::new(),
            replace: Vec::new(),
            retire: Vec::new(),
        },
        views: [stale].into_iter().collect(),
        corroboration: Vec::new(),
        manifest_fallbacks: Vec::new(),
        selection_claims: BTreeMap::new(),
        selection_tables: BTreeMap::new(),
        selection_admission: None,
        manifest_selection_admissions: Vec::new(),
        manifest_inventory_slots: BTreeMap::new(),
    };
    commit_cleaned_candidate_identity(
        &mut candidate,
        remaining_pins,
        remaining_reconciled,
        &[stale].into_iter().collect(),
    );
    assert!(candidate.modules.is_empty());
    assert!(candidate.pinned.pinned().next().is_none());
    assert!(candidate.views.is_empty());
}

#[test]
fn attached_context_is_processed_and_removed_before_same_view_rearm() {
    use p11scope_manifest::elf::SymbolFact;
    use p11scope_manifest::maps::Device;

    let mapping = MapEntry {
        start: 0x4000,
        end: 0x5000,
        file_offset: 0x2000,
        permissions: *b"r-xp",
        device: Device { major: 8, minor: 1 },
        inode: 7,
        raw_path: Some(b"/lib/ld.so".to_vec()),
    };
    let mut registry = LoaderRegistry::default();
    let prepared = registry
        .preflight(LoaderContextSpec {
            view: ProcessViewId(3),
            loader: PinnedObjectId(9),
            mapping: Some(mapping.clone()),
            hook: SymbolFact {
                virtual_address: 0x2100,
                file_offset: 0x2100,
            },
            state_address: None,
        })
        .unwrap();
    let context = registry.prepare(prepared).unwrap();
    registry.mark_attached(context).unwrap();
    let mut queued: DiscoveryRecord = unsafe { std::mem::zeroed() };
    queued.kind = DISCOVERY_KIND_LOADER;
    queued.case_id = (context.get() - 1) as u8;
    queued.table_ptr = 0x4100;
    queued.hook_ts_ns = 10;
    let order = std::cell::RefCell::new(Vec::new());

    order.borrow_mut().push("detach");
    let drained = begin_attached_retirement_with(&mut registry, context, || {
        order.borrow_mut().push("drain");
        Ok((
            vec![queued],
            CounterSnapshot {
                loader_hits: 1,
                ..CounterSnapshot::default()
            },
        ))
    })
    .unwrap();
    let (drained, post_drain_snapshot) = drained.unwrap();
    let mut authority = CounterSnapshot::default();
    assert!(authority.replace_with(post_drain_snapshot));

    assert_eq!(*order.borrow(), ["detach", "drain"]);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].case_id, queued.case_id);
    assert_eq!(drained[0].hook_ts_ns, queued.hook_ts_ns);
    assert_eq!(
        authority.loader_hits, 1,
        "the owned hit has fresh authority"
    );
    let ordinary = QueuedDiscoveryRecord {
        record: queued,
        terminal_owner: None,
        terminal_exports: Vec::new(),
    };
    assert!(
        validate_loader_record_context(
            &mut registry,
            ordinary.terminal_owner,
            &ordinary.record,
            ProcessViewId(3),
            PinnedObjectId(9),
            &mapping,
        )
        .is_err(),
        "ordinary dispatch cannot revive a tombstone"
    );
    let wrong_owner = Some(LoaderContextId::from_case_id(
        queued.case_id.wrapping_add(1),
    ));
    assert!(
        validate_loader_record_context(
            &mut registry,
            wrong_owner,
            &queued,
            ProcessViewId(3),
            PinnedObjectId(9),
            &mapping,
        )
        .is_err(),
        "another drain's tag cannot authorize this tombstone"
    );
    let failures = registry.context_failures();
    let terminal = QueuedDiscoveryRecord {
        record: queued,
        terminal_owner: Some(context),
        terminal_exports: Vec::new(),
    };
    validate_loader_record_context(
        &mut registry,
        terminal.terminal_owner,
        &terminal.record,
        ProcessViewId(3),
        PinnedObjectId(9),
        &mapping,
    )
    .expect("the exact owned terminal drain can resolve its live tombstone");
    assert_eq!(
        registry.context_failures(),
        failures,
        "the tagged terminal hit adds no context failure"
    );
    order.borrow_mut().push("process");
    let mut engine = Engine::empty();
    engine.loader_registry = registry;
    engine.loader_registry.remove(context).unwrap();
    order.borrow_mut().push("remove");
    assert!(
        engine
            .loader_registry
            .ids_for_view(ProcessViewId(3))
            .is_empty(),
        "the tombstone cannot block same-view replacement arming"
    );
    let prepared = engine
        .loader_registry
        .preflight(LoaderContextSpec {
            view: ProcessViewId(3),
            loader: PinnedObjectId(9),
            mapping: Some(mapping),
            hook: SymbolFact {
                virtual_address: 0x2100,
                file_offset: 0x2100,
            },
            state_address: None,
        })
        .unwrap();
    let replacement = engine.loader_registry.prepare(prepared).unwrap();
    order.borrow_mut().push("arm");
    assert_ne!(replacement, context, "context IDs are never reused");
    assert_eq!(
        *order.borrow(),
        ["detach", "drain", "process", "remove", "arm"]
    );
}

#[test]
fn serial_terminal_drain_never_claims_another_attached_context() {
    use p11scope_manifest::elf::SymbolFact;
    use p11scope_manifest::maps::Device;

    let mapping = MapEntry {
        start: 0x4000,
        end: 0x5000,
        file_offset: 0x2000,
        permissions: *b"r-xp",
        device: Device { major: 8, minor: 1 },
        inode: 7,
        raw_path: Some(b"/lib/ld.so".to_vec()),
    };
    let mut registry = LoaderRegistry::default();
    let mut prepare = |view, loader| {
        let prepared = registry
            .preflight(LoaderContextSpec {
                view,
                loader,
                mapping: Some(mapping.clone()),
                hook: SymbolFact {
                    virtual_address: 0x2100,
                    file_offset: 0x2100,
                },
                state_address: None,
            })
            .unwrap();
        let context = registry.prepare(prepared).unwrap();
        registry.mark_attached(context).unwrap();
        context
    };
    let first = prepare(ProcessViewId(3), PinnedObjectId(9));
    let second = prepare(ProcessViewId(4), PinnedObjectId(10));

    registry.tombstone(first).unwrap();
    let mut second_hit: DiscoveryRecord = unsafe { std::mem::zeroed() };
    second_hit.kind = DISCOVERY_KIND_LOADER;
    second_hit.case_id = (second.get() - 1) as u8;
    second_hit.table_ptr = 0x4100;
    second_hit.hook_ts_ns = 10;
    let queued = tagged_by_authority(first, &[], second_hit);
    assert_eq!(
        queued.terminal_owner, None,
        "A's global drain cannot grant terminal authority to B's record"
    );
    let failures = registry.context_failures();
    validate_loader_record_context(
        &mut registry,
        queued.terminal_owner,
        &queued.record,
        ProcessViewId(4),
        PinnedObjectId(10),
        &mapping,
    )
    .expect("B remains Attached while A's drained batch is dispatched");
    assert_eq!(registry.context_failures(), failures);
    registry.remove(first).unwrap();

    registry.tombstone(second).unwrap();
    let queued = tagged_by_authority(second, &[], second_hit);
    assert_eq!(queued.terminal_owner, Some(second));
    validate_loader_record_context(
        &mut registry,
        queued.terminal_owner,
        &queued.record,
        ProcessViewId(4),
        PinnedObjectId(10),
        &mapping,
    )
    .expect("B receives terminal authority only from B's own drain");
    registry.remove(second).unwrap();
    assert!(registry.ids_for_view(ProcessViewId(3)).is_empty());
    assert!(registry.ids_for_view(ProcessViewId(4)).is_empty());
}

#[test]
fn refresh_preserves_a_loader_arm_plan_change() {
    let mut attempted = Vec::new();
    let changed = arm_refreshed_views_with(&[4, 7], |position| {
        attempted.push(position);
        Ok(position == 7)
    })
    .unwrap();

    assert_eq!(attempted, [4, 7]);
    assert!(changed, "refresh must report a loader-arm plan mutation");
}

#[test]
fn refresh_continues_second_view_after_first_loader_arm_error() {
    let mut attempted = Vec::new();
    let mut partial = 0;
    let changed = arm_refreshed_views_with(&[0, 1], |position| {
        attempted.push(position);
        let result = if position == 0 {
            Err(LoaderArmFailure::ordinary(anyhow!(
                "ordinary per-view map failure"
            )))
        } else {
            Ok(false)
        };
        match loader_arm_outcome(true, result) {
            LoaderArmOutcome::OrdinaryFailure(_) => {
                partial += 1;
                Ok(false)
            }
            LoaderArmOutcome::Changed(changed) => Ok(changed),
            _ => unreachable!(),
        }
    })
    .unwrap();

    assert_eq!(attempted, [0, 1]);
    assert_eq!(partial, 1);
    assert!(!changed);
    assert!(
        matches!(
            loader_arm_outcome(
                true,
                Err(LoaderArmFailure::invariant(anyhow!(
                    "registry state transition failed"
                )))
            ),
            LoaderArmOutcome::Invariant(_)
        ),
        "a true loader-arm invariant remains capture-fatal"
    );

    for changed in [false, true] {
        assert!(
            matches!(
                loader_arm_outcome(false, Ok(changed)),
                LoaderArmOutcome::GenerationLost {
                    changed: retained,
                    failure: None,
                } if retained == changed
            ),
            "a successful or early-return arm must enter cleanup and retain its change bit"
        );
    }
}

#[test]
fn merge_scanned_modules_retains_names_and_exact_decoder_provenance() {
    let module = |name_lossy, decoder_abi| ScannedModule {
        view: ProcessViewId(0),
        mount_namespace: crate::process::MountNamespaceId {
            device: 1,
            inode: 2,
        },
        key: ObjectKey {
            device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
            inode: 42,
        },
        path: "/opt/p.so".into(),
        decoder_abi,
        exports: vec![],
        tables: vec![ScannedTable {
            version: (3, 0),
            walk: "full",
            entries: vec![],
            null_entries: vec![],
            unpinned: vec![],
            address: 0x1000,
            file_offset: Some(0),
            live_return: false,
            manifest_supported: false,
        }],
        interfaces: vec![ScannedInterface {
            index: 0,
            name_class: "exact_standard",
            name_lossy,
            name_private: Some(b"PKCS 11".to_vec()),
            flags: 7,
            table: Some(0),
        }],
    };

    let mut merged = vec![module(Some("PKCS 11".into()), Some(ElfAbi::Ilp32))];
    merge_scanned_module(&mut merged, module(None, None));

    assert_eq!(merged[0].interfaces.len(), 1);
    assert_eq!(merged[0].decoder_abi, Some(ElfAbi::Ilp32));
    assert_eq!(
        merged[0].interfaces[0].name_lossy.as_deref(),
        Some("PKCS 11")
    );

    let mut mapping_first = vec![module(None, None)];
    merge_scanned_module(&mut mapping_first, module(None, Some(ElfAbi::Ilp32)));
    assert_eq!(mapping_first[0].decoder_abi, Some(ElfAbi::Ilp32));

    merge_scanned_module(&mut mapping_first, module(None, Some(ElfAbi::Lp64)));
    assert_eq!(
        mapping_first.len(),
        2,
        "conflicting exact decoder provenance is never merged away"
    );
}

/// The valid self-export fixture: a retained view of this process, its own
/// `/proc/self/maps`, and one structurally valid FUNCTION_LIST record whose
/// table owner is a file-backed readable data mapping of the test
/// executable and whose single pointer is the matching code mapping —
/// exactly the shape `engine_lowers_export_table_owner_and_prefix` proves
/// lowers whole.
fn self_export_fixture(id: ProcessViewId) -> (ProcessView, Vec<MapEntry>, DiscoveryRecord) {
    use p11scope_ebpf_common::DISCOVERY_KIND_FUNCTION_LIST_RETURN;

    let pid = std::process::id();
    let view = ProcessView::open(id, pid).unwrap();
    let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
    let map_index = MapIndex::new(&maps).expect("the self maps snapshot is valid");
    let executable = std::env::current_exe().unwrap();
    let executable = executable.canonicalize().unwrap_or(executable);
    let owner = maps
        .iter()
        .find(|mapping| {
            mapping.inode != 0
                && mapping.permissions[0] == b'r'
                && mapping.permissions[2] != b'x'
                && matches!(
                    map_index.resolve(mapping.start),
                    Resolved::File {
                        path: MappedPath::Usable(ref path),
                        ..
                    } if path == &executable
                )
        })
        .expect("the test executable has a file-backed data mapping")
        .clone();
    let code = maps
        .iter()
        .find(|mapping| {
            mapping.inode == owner.inode
                && mapping.device == owner.device
                && mapping.permissions[2] == b'x'
        })
        .expect("the test executable has a matching code mapping")
        .clone();

    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_FUNCTION_LIST_RETURN;
    record.symbol_id = 1;
    record.pid_tgid = u64::from(pid) << 32;
    record.table_ptr = owner.start;
    record.version_major = 2;
    record.version_minor = 40;
    record.pointers[0] = code.start;
    record.pointers_attempted = 1;
    record.completed_prefix = 1;
    record.usable_n = 1;
    (view, maps, record)
}

/// Task 11 fix round 3 (shadow finding 5): live admission is stop-aware.
/// A structurally valid record used to lower whole through a capture that
/// had already stopped — `admit_table`/`admit_interface` looked only at
/// their own cardinality counters, so a sticky work stop refused nothing
/// and an expired batch deadline was never polled between the snapshot and
/// the decode.
#[test]
fn a_stopped_capture_refuses_a_valid_live_export_record() {
    let (view, maps, record) = self_export_fixture(ProcessViewId(42));
    let hooks = HookRegistry::builtin();
    let index = MapIndex::new(&maps).expect("a kernel-ordered self snapshot");

    // An expired batch deadline, nothing sticky yet: only an admission
    // clock poll can catch it.
    let mut budget = CaptureWorkBudget::default();
    budget.set_deadline(Some(0));
    assert_eq!(
        lower_export_record(&view, &index, &hooks, &record, &mut budget).unwrap_err(),
        SCAN_DEADLINE_REASON
    );

    // A sticky work stop left by any other consumer of the one budget.
    let mut budget = CaptureWorkBudget::default();
    assert!(
        !budget.charge(u64::MAX),
        "the work ceiling refuses and sticks"
    );
    assert_eq!(
        lower_export_record(&view, &index, &hooks, &record, &mut budget).unwrap_err(),
        WORK_CEILING_REASON
    );

    // The same record still lowers when neither ceiling was reached: the
    // refusals above are the capture's stop, not the fixture's shape.
    let mut budget = CaptureWorkBudget::default();
    assert!(
        lower_export_record(&view, &index, &hooks, &record, &mut budget)
            .unwrap()
            .is_some()
    );

    // And the admission functions refuse the stop themselves, so no caller
    // of theirs can decode new work past the capture's ceiling.
    let mut budget = CaptureWorkBudget::default();
    assert!(budget.admit_table(1) && budget.admit_interface());
    assert!(!budget.charge(u64::MAX));
    assert!(!budget.admit_table(1), "a stopped capture admits no table");
    assert!(
        !budget.admit_interface(),
        "a stopped capture admits no interface"
    );
}

/// Task 11 fix round 3 (shadow-review test blocker 1): the production call
/// site. An ordinary batch carrying the valid self-export record under an
/// expired batch deadline admits no candidate and no slot, and publishes
/// the exact live loss — and the refusal lands before one byte of the
/// target's maps is read.
#[test]
fn an_expired_batch_deadline_admits_no_live_export_record() {
    let refused = {
        let (view, _maps, record) = self_export_fixture(ProcessViewId(0));
        let mut engine = Engine::empty();
        engine.next_view_id = 1;
        engine.views.push(view);
        let mut session = ScriptedSession::default();
        let mut collect = Engine::collect_discovery_records;
        let outcome = engine
            .apply_discovery_batch_with(
                &mut session,
                vec![record],
                0,
                true,
                false,
                &mut collect,
                Some(0),
            )
            .expect("a refused live snapshot is loss, never a batch error");
        assert!(!outcome.required_complete, "the batch is incomplete");
        assert!(engine.plan.slots.is_empty(), "no slot is admitted");
        assert!(engine.modules.is_empty(), "no candidate is admitted");
        assert!(
            engine.counters.object_skips.contains(&Skipped {
                subject: "live discovery record".into(),
                reason: "a structurally valid private record failed exact live resolution".into(),
            }),
            "{:?}",
            engine.counters.object_skips
        );
        assert_eq!(
            engine.budget.attempted_io_bytes(),
            0,
            "the expired deadline refuses the snapshot before a byte is read"
        );
        engine.counters.object_skips.clone()
    };

    // The positive control: the same fixture through the same route with no
    // deadline is admitted, so the refusal above is the deadline's.
    let (view, _maps, record) = self_export_fixture(ProcessViewId(0));
    let mut engine = Engine::empty();
    engine.next_view_id = 1;
    engine.views.push(view);
    // This test binary is larger than the default per-object cap, which
    // would skip its own pin for an unrelated reason.
    engine.budget = CaptureWorkBudget::new(ScanLimits {
        per_object_bytes: u64::MAX,
        total_bytes: u64::MAX,
    });
    let mut session = ScriptedSession::default();
    let mut collect = Engine::collect_discovery_records;
    engine
        .apply_discovery_batch_with(
            &mut session,
            vec![record],
            0,
            true,
            false,
            &mut collect,
            None,
        )
        .expect("an ordinary batch");
    assert_eq!(
        engine.plan.slots.len(),
        1,
        "{:?}",
        engine.counters.object_skips
    );
    assert!(
        engine.budget.attempted_io_bytes() > 0,
        "the snapshot was read"
    );
    assert!(
        !engine
            .counters
            .object_skips
            .iter()
            .any(|skip| refused.contains(skip)),
        "{:?}",
        engine.counters.object_skips
    );
}

#[test]
fn engine_lowers_export_table_owner_and_prefix() {
    use p11scope_ebpf_common::{
        DISCOVERY_KIND_FUNCTION_LIST_RETURN, DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN,
        DISCOVERY_STATUS_READ_FAILURE, DiscoveryRecord,
    };

    let view = ProcessView::open(ProcessViewId(41), std::process::id()).unwrap();
    let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
    let map_index = MapIndex::new(&maps).expect("the self maps snapshot is valid");
    let executable = std::env::current_exe().unwrap();
    let executable = executable.canonicalize().unwrap_or(executable);
    let owner = maps
        .iter()
        .find(|mapping| {
            mapping.inode != 0
                && mapping.permissions[0] == b'r'
                && mapping.permissions[2] != b'x'
                && matches!(
                    map_index.resolve(mapping.start),
                    Resolved::File {
                        path: MappedPath::Usable(ref path),
                        ..
                    } if path == &executable
                )
        })
        .expect("the test executable has a file-backed data mapping");
    let code = maps
        .iter()
        .find(|mapping| {
            mapping.inode == owner.inode
                && mapping.device == owner.device
                && mapping.permissions[2] == b'x'
        })
        .expect("the test executable has a matching code mapping");

    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_FUNCTION_LIST_RETURN;
    record.symbol_id = 1;
    record.table_ptr = owner.start;
    record.version_major = 2;
    record.version_minor = 40;
    record.pointers[0] = code.start;
    record.pointers_attempted = 1;
    record.completed_prefix = 1;
    record.usable_n = 1;

    let hooks = crate::discovery::hooks::HookRegistry::builtin();
    let limits = ScanLimits {
        per_object_bytes: u64::MAX,
        total_bytes: u64::MAX,
    };
    let mut budget = CaptureWorkBudget::new(limits);
    let index = MapIndex::new(&maps).expect("a kernel-ordered self snapshot");
    let lowered = lower_export_record(&view, &index, &hooks, &record, &mut budget)
        .expect("the structurally valid record lowers")
        .expect("one usable pointer gives one table");
    assert_eq!(
        lowered.decoder_abi, None,
        "a kernel export record does not claim userspace decoder provenance"
    );
    assert_eq!(lowered.view, view.id());
    assert_eq!(lowered.key, ObjectKey::of(owner));
    assert_eq!(lowered.tables.len(), 1);
    assert_eq!(lowered.tables[0].entries.len(), 1);
    assert_eq!(lowered.tables[0].entries[0].object, ObjectKey::of(code));

    let mut interface_record = record;
    interface_record.kind = DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN;
    interface_record.symbol_id = 2;
    interface_record.table_ptr += 8;
    interface_record.interface_index = 3;
    interface_record.announced_count = 4;
    interface_record.name_class = DISCOVERY_NAME_EXACT_STANDARD;
    let interface = lower_export_record(&view, &index, &hooks, &interface_record, &mut budget)
        .unwrap()
        .unwrap();
    assert_eq!(interface.decoder_abi, None);
    let mut merged = vec![lowered.clone()];
    merge_scanned_module(&mut merged, interface);
    assert_eq!(merged[0].interfaces[0].table, Some(1));

    let mut wrong_hook = record;
    wrong_hook.symbol_id = 2;
    assert!(
        lower_export_record(&view, &index, &hooks, &wrong_hook, &mut budget).is_err(),
        "the retained symbol ABI must agree with the record kind"
    );
    wrong_hook.symbol_id = u32::MAX;
    assert!(
        lower_export_record(&view, &index, &hooks, &wrong_hook, &mut budget).is_err(),
        "unknown private symbol IDs have no hook authority"
    );

    let (mut pins, skipped) =
        pin_scanned_objects(view.pid(), std::slice::from_ref(&lowered), &mut budget).unwrap();
    assert!(skipped.is_empty(), "{skipped:?}");
    let reconciled = reconcile_for_test(&[lowered], &mut pins);
    assert_eq!(
        plan::build_from_reconciled_modules(&reconciled).slots.len(),
        1
    );

    record.status_flags = DISCOVERY_STATUS_READ_FAILURE;
    record.usable_n = 0;
    assert!(
        lower_export_record(&view, &index, &hooks, &record, &mut budget)
            .expect("the completed raw prefix is structurally valid")
            .is_none(),
        "a read-failed completed prefix is not target authority"
    );

    record.status_flags = 0;
    record.usable_n = 1;
    record.table_ptr = maps
        .iter()
        .find(|mapping| mapping.inode == 0 && mapping.permissions[0] == b'r')
        .expect("this process has an anonymous readable mapping")
        .start;
    assert!(
        lower_export_record(&view, &index, &hooks, &record, &mut budget)
            .expect("an anonymous table owner is a count-only outcome")
            .is_none(),
        "an anonymous mapping cannot own a live table"
    );
}

#[test]
fn post_session_rebuild_preserves_canonical_ids() {
    let (modules, canonical) = pinned_self();
    let original = canonical
        .id_for_scanned(&modules[0], modules[0].key, &modules[0].path)
        .unwrap();
    let (_, incoming) = pinned_self();
    let mut engine = Engine::empty();
    engine.pinned = canonical;
    let mut candidate_pins = engine.pinned.clone();
    let skipped = candidate_pins.absorb(incoming);
    assert!(skipped.is_empty(), "{skipped:?}");
    let candidate = engine
        .live_candidate(candidate_pins, modules.clone(), skipped)
        .unwrap();
    assert_eq!(
        candidate
            .pinned
            .id_for_scanned(&modules[0], modules[0].key, &modules[0].path)
            .unwrap(),
        original,
        "an exact post-session observation reuses the canonical object ID"
    );
    assert_eq!(
        engine.pinned.pinned().count(),
        candidate.pinned.pinned().count()
    );

    let mut preserved = engine.pinned.clone();
    assert!(
        preserved
            .replace_view_pins(modules[0].view, PinnedObjects::empty(), &[original])
            .is_empty()
    );
    assert_eq!(
        preserved.id_for_scanned(&modules[0], modules[0].key, &modules[0].path),
        Some(original),
        "an active loader context can retain its exact pin across a view rescan"
    );
}

#[test]
fn manifest_pins_are_not_rehashed_by_event() {
    use std::io::{Read as _, Seek as _, SeekFrom};
    use std::os::fd::AsRawFd as _;

    let exe = std::env::current_exe().unwrap();
    let pins = pin_as_manifest_object(exe.to_str().unwrap());
    let id = pins.pinned().next().unwrap().id;
    let file = pins
        .file_for(id)
        .expect("the manifest pin retains its opened file");
    let before = file.metadata().unwrap().ino();
    let mut borrowed = file;
    borrowed.seek(SeekFrom::Start(0)).unwrap();
    let mut magic = [0; 4];
    borrowed.read_exact(&mut magic).unwrap();
    assert_eq!(&magic, b"\x7fELF");
    assert_eq!(file.metadata().unwrap().ino(), before);
    let retained_fd = file.as_raw_fd();
    assert!(pins.check_unchanged().unwrap());

    let mut engine = Engine::empty();
    engine.pinned = pins;
    let candidate = engine
        .live_candidate(engine.pinned.clone(), Vec::new(), Vec::new())
        .unwrap();
    assert_eq!(
        candidate.pinned.file_for(id).unwrap().as_raw_fd(),
        retained_fd,
        "an event candidate shares the retained manifest descriptor"
    );
}

#[test]
fn scope_refresh_uses_engine_owned_scope_and_monotonic_view_ids() {
    let mut engine = Engine::empty();
    engine.scope = Scope::Pid(std::process::id());
    let first = engine.allocate_view_id().unwrap();
    let second = engine.allocate_view_id().unwrap();
    assert_eq!((first, second), (ProcessViewId(0), ProcessViewId(1)));
    assert_eq!(scope_pids(&engine.scope).0, vec![std::process::id()]);

    engine.next_view_id = MAX_SCAN_PIDS as u32;
    assert!(engine.allocate_view_id().is_err());
    assert_eq!(engine.next_view_id, MAX_SCAN_PIDS as u32);
}

#[test]
fn retired_view_ids_are_reused_for_new_generations() {
    let mut engine = Engine::empty();
    engine.next_view_id = MAX_SCAN_PIDS as u32;
    assert!(engine.allocate_view_id().is_err());
    engine.release_view_id(ProcessViewId(7));
    let reused = engine.allocate_view_id().unwrap();
    assert_eq!(reused, ProcessViewId(7));
    assert!(engine.allocate_view_id().is_err());
}

/// ABC-T3 hardening: a double release is a silent no-op — the retired pool
/// holds the ID once, so the next admissions reuse it exactly once and the
/// ID sequence stays consistent after.
#[test]
fn release_view_id_double_release_is_a_silent_noop() {
    let mut engine = Engine::empty();
    let first = engine.allocate_view_id().unwrap();
    let second = engine.allocate_view_id().unwrap();
    assert_eq!((first, second), (ProcessViewId(0), ProcessViewId(1)));
    engine.release_view_id(first);
    engine.release_view_id(first);
    assert_eq!(
        engine.allocate_view_id().unwrap(),
        first,
        "the released ID is reused exactly once"
    );
    assert_eq!(
        engine.allocate_view_id().unwrap(),
        ProcessViewId(2),
        "no duplicate retired entry mints the ID to a second live view"
    );
}

/// ABC-T3 coverage: removal-to-reuse end to end. Two views are admitted
/// through the real ID lifecycle, one is released via `release_view_id`,
/// and the next admission reuses the exact released ID value — not just a
/// count, the value itself.
#[test]
fn released_view_ids_are_reused_end_to_end() {
    let mut engine = Engine::empty();
    let first = engine.allocate_view_id().unwrap();
    engine.retain_view_id(first).unwrap();
    engine
        .views
        .push(ProcessView::open(first, std::process::id()).unwrap());
    let second = engine.allocate_view_id().unwrap();
    engine.retain_view_id(second).unwrap();
    engine
        .views
        .push(ProcessView::open(second, std::process::id()).unwrap());
    assert_eq!((first, second), (ProcessViewId(0), ProcessViewId(1)));

    engine.release_view_id(first);
    engine.views.retain(|view| view.id() != first);

    let reused = engine.allocate_view_id().unwrap();
    assert_eq!(reused, first);
}

/// Task 5 (ABC carry-forward), initial pass. Members that ended before
/// capture start are each allocated a view ID whose open then fails; the
/// ID was dropped without release — one burn per dead member, so a
/// churning cgroup could still exhaust the pool. The drop returns the ID
/// to the retired pool: minted == admitted + retired balances, and the
/// next allocation reuses a released value.
#[test]
fn capture_start_releases_view_ids_for_members_that_ended_before_scan() {
    let pids: Vec<_> = (0..3)
        .map(|_| {
            let mut child = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap();
            let pid = child.id();
            child.kill().unwrap();
            child.wait().unwrap();
            pid
        })
        .collect();
    let dir = tempfile::tempdir().expect("a scope directory");
    let listing: String = pids.iter().map(|pid| format!("{pid}\n")).collect();
    std::fs::write(dir.path().join("cgroup.procs"), listing).expect("a cgroup.procs");
    let args = CaptureArgs {
        kind: crate::cli::Kind::Profile,
        modules: vec![],
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: crate::cli::ScopeArg::Cgroup(dir.path().to_path_buf()),
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        ring_bytes: None,
        drain_interval: None,
        max_scan_pids: None,
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    };
    let scope = crate::scope::cgroup(dir.path()).expect("open scope directory");

    let mut engine = Engine::discover(&args, &scope, None).expect("an empty cgroup still captures");

    assert!(
        engine.views.is_empty(),
        "no ended member is admitted: {:?}",
        engine
            .views
            .iter()
            .map(ProcessView::pid)
            .collect::<Vec<_>>()
    );
    // Pop-before-mint reuses the released ID within the pass, so three
    // ended members burn exactly one mint between them.
    assert_eq!(
        engine.retired_view_ids,
        vec![0],
        "each allocated-but-never-admitted ID returns to the pool"
    );
    assert_eq!(
        engine.next_view_id, 1,
        "ended members do not advance the mint counter past the recycled ID"
    );
    assert_eq!(
        engine.next_view_id as usize,
        engine.views.len() + engine.retired_view_ids.len(),
        "minted IDs balance: admitted + retired"
    );
    assert_eq!(
        engine.allocate_view_id().unwrap(),
        ProcessViewId(0),
        "the next allocation reuses the released ID"
    );
}

/// Task 5 (ABC carry-forward), live tick. Same drop as the initial pass
/// but in the refresh `new_views` loop; a second tick pins the churn
/// steady state — re-allocated from the pool and released again, the
/// pool neither grows (duplicates) nor drains.
#[test]
fn refresh_releases_view_ids_for_members_that_ended_before_scan() {
    let pids: Vec<_> = (0..3)
        .map(|_| {
            let mut child = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap();
            let pid = child.id();
            child.kill().unwrap();
            child.wait().unwrap();
            pid
        })
        .collect();
    let (mut engine, _dir) = engine_over_cgroup_naming(&pids);

    // Pop-before-mint reuses the released ID within the pass, so three
    // ended members burn exactly one mint between them.
    refresh_inventory_once(&mut engine);
    assert_eq!(
        engine.retired_view_ids,
        vec![0],
        "tick 1: each allocated-but-never-admitted ID returns to the pool"
    );
    assert_eq!(
        engine.next_view_id, 1,
        "tick 1: ended members do not advance the mint counter"
    );
    assert_eq!(
        engine.next_view_id as usize,
        engine.views.len() + engine.retired_view_ids.len(),
        "tick 1: minted IDs balance: admitted + retired"
    );

    refresh_inventory_once(&mut engine);
    assert_eq!(
        engine.retired_view_ids,
        vec![0],
        "tick 2: re-allocated from the pool and released again, no duplicates"
    );
    assert_eq!(
        engine.next_view_id, 1,
        "tick 2: churn steady state holds the mint counter at one"
    );
    assert_eq!(
        engine.next_view_id as usize,
        engine.views.len() + engine.retired_view_ids.len(),
        "tick 2: minted IDs balance: admitted + retired"
    );
}

/// A live `sleep` child whose own image is already mapped. Until its exec
/// completes the child is a fork of this test binary, and a scan racing that
/// exec is not what the U-11 ticks below are about.
fn spawn_execed_sleep() -> std::process::Child {
    let child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let pid = child.id();
    let this_image = std::env::current_exe().unwrap();
    let execed = || {
        std::fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|image| {
            image != this_image
                && std::fs::read_to_string(format!("/proc/{pid}/maps"))
                    .is_ok_and(|maps| maps_have_executable_image(&maps, &image))
        })
    };
    let mut spins = 0;
    while !execed() {
        std::thread::sleep(std::time::Duration::from_millis(1));
        spins += 1;
        assert!(spins < 10_000, "sleep child {pid} never execed");
    }
    child
}

fn capacity_exhausted(engine: &Engine) -> bool {
    engine
        .counters
        .object_skips
        .iter()
        .any(|skip| skip.reason.starts_with("capture process-view capacity"))
}

/// U-11, the `!targets_ok` exit. A candidate its target preflight refuses
/// returns before any mutation and drops every view the tick just opened,
/// and those IDs were never returned: a member held at that exit burned one
/// ID per tick until the capture's process-view capacity was exhausted and
/// the member was not scanned any more. Ticks well past the capacity now
/// recycle one ID.
#[test]
fn refresh_releases_view_ids_when_the_target_preflight_refuses() {
    let mut child = spawn_execed_sleep();
    let (mut engine, _dir) = engine_over_cgroup_naming(&[child.id()]);
    engine.max_scan_pids = 2;
    engine.scheduler.set_tick_quantum_ns_for_test(u64::MAX);
    let mut session = ScriptedSession::refusing_preflight();

    let ticks = 4;
    for tick in 1..=ticks {
        refresh_inventory_with(&mut engine, &mut session);
        assert!(
            engine.views.is_empty(),
            "tick {tick}: a refused candidate admits nothing"
        );
    }

    assert!(
        !capacity_exhausted(&engine),
        "ticks past the capacity never exhaust it: {:?}",
        engine.counters.object_skips
    );
    assert_eq!(
        engine.deep_scans, ticks as u64,
        "every tick opened and scanned the member"
    );
    assert_eq!(
        session.preflight_targets.borrow().len(),
        ticks,
        "every tick returned at its first preflight"
    );
    assert!(
        engine.counters.object_skips.contains(&Skipped {
            subject: "live inventory transaction".into(),
            reason:
                "candidate preflight failed; canonical identity, plan, and links were unchanged"
                    .into(),
        }),
        "the refusal exit published its gap: {:?}",
        engine.counters.object_skips
    );
    assert_eq!(
        engine.retired_view_ids,
        vec![0],
        "the one ID returns to the pool at every refusal"
    );
    assert_eq!(engine.next_view_id, 1, "no tick mints a second ID");

    child.kill().unwrap();
    child.wait().unwrap();
}

/// U-11, the stale-generation exit. A process admitted this tick that ends
/// before the inventory preflight reads the views makes the candidate stale:
/// the tick re-requests the pid and returns, dropping the new view. The
/// request is keyed by pid, and a later tick opens a fresh view under a fresh
/// ID, so the dropped view's ID has to come back even though its pid is
/// queued again. Every tick loses its newcomer exactly inside that preflight,
/// well past the capacity.
#[test]
fn refresh_releases_view_ids_when_a_new_generation_ends_before_admission() {
    let (mut engine, dir) = engine_over_cgroup_naming(&[]);
    engine.max_scan_pids = 2;
    engine.scheduler.set_tick_quantum_ns_for_test(u64::MAX);
    let mut session = ScriptedSession::default();

    let ticks = 4;
    let mut lost = Vec::new();
    for tick in 1..=ticks {
        // The preflight kills and reaps this child; the test never waits on it.
        let pid = spawn_execed_sleep().id();
        std::fs::write(dir.path().join("cgroup.procs"), format!("{pid}\n")).unwrap();
        session.lose_generations_at_preflight([Some(pid)]);
        refresh_inventory_with(&mut engine, &mut session);
        assert!(
            engine.views.is_empty(),
            "tick {tick}: a generation lost before admission is not admitted"
        );
        lost.push(pid);
    }

    assert!(
        !capacity_exhausted(&engine),
        "ticks past the capacity never exhaust it: {:?}",
        engine.counters.object_skips
    );
    assert_eq!(
        engine.deep_scans, ticks as u64,
        "every tick opened and scanned its newcomer"
    );
    assert_eq!(
        session.preflight_targets.borrow().len(),
        ticks,
        "every tick returned at its first preflight"
    );
    assert!(
        engine.counters.object_skips.contains(&Skipped {
            subject: "live inventory generation".into(),
            reason: "an exact retained or newly opened process generation changed during inventory preflight"
                .into(),
        }),
        "the stale exit published its loss: {:?}",
        engine.counters.object_skips
    );
    assert!(
        lost.iter()
            .all(|pid| engine.refresh_requested.contains(pid)),
        "every lost newcomer's pid is queued again: {:?}",
        engine.refresh_requested
    );
    assert_eq!(
        engine.retired_view_ids,
        vec![0],
        "the dropped view's ID returns although its pid is queued again"
    );
    assert_eq!(engine.next_view_id, 1, "no tick mints a second ID");
}

/// U-11, the post-retirement preflight exits. A candidate that passed its
/// first preflight is checked again after conservative retirements, and both
/// the refusal and the stale-generation return there dropped the tick's new
/// views without their IDs. Tick 1 refuses the second preflight; tick 2
/// loses the newcomer inside it.
#[test]
fn refresh_releases_view_ids_at_the_post_retirement_preflight_exits() {
    // Tick 2's preflight kills and reaps this child; the test never waits on it.
    let pid = spawn_execed_sleep().id();
    let (mut engine, _dir) = engine_over_cgroup_naming(&[pid]);
    engine.scheduler.set_tick_quantum_ns_for_test(u64::MAX);
    let mut session = ScriptedSession::default();

    session.refuse_preflights([false, true]);
    refresh_inventory_with(&mut engine, &mut session);
    assert!(engine.views.is_empty(), "tick 1: nothing is admitted");
    assert_eq!(
        session.preflight_targets.borrow().len(),
        2,
        "tick 1 returned at its second preflight"
    );
    assert!(
        engine.counters.object_skips.contains(&Skipped {
            subject: "live inventory transaction".into(),
            reason: "post-retirement candidate preflight failed; conservative retirements were committed and additions were blocked"
                .into(),
        }),
        "tick 1: the post-retirement refusal published its gap: {:?}",
        engine.counters.object_skips
    );
    assert_eq!(
        engine.retired_view_ids,
        vec![0],
        "tick 1: the refused newcomer's ID returns to the pool"
    );
    assert_eq!(engine.next_view_id, 1, "tick 1: one ID was minted");

    session.lose_generations_at_preflight([None, Some(pid)]);
    refresh_inventory_with(&mut engine, &mut session);
    assert!(engine.views.is_empty(), "tick 2: nothing is admitted");
    assert_eq!(
        session.preflight_targets.borrow().len(),
        4,
        "tick 2 returned at its second preflight"
    );
    assert!(
        engine.counters.object_skips.contains(&Skipped {
            subject: "live inventory generation".into(),
            reason: "an exact retained or newly opened process generation changed during post-retirement preflight"
                .into(),
        }),
        "tick 2: the post-retirement stale exit published its loss: {:?}",
        engine.counters.object_skips
    );
    assert!(
        engine.refresh_requested.contains(&pid),
        "tick 2: the lost newcomer's pid is queued again"
    );
    assert_eq!(
        engine.retired_view_ids,
        vec![0],
        "tick 2: the lost newcomer's ID returns to the pool"
    );
    assert_eq!(engine.next_view_id, 1, "tick 2: no second ID was minted");
}

/// U-11: a view the tick never admitted returns its ID only when nothing
/// still names it: a committed module, a pin claim, or a retirement intent
/// (a record pass that fails after `queue_apply_outcome` can leave one
/// behind; U-07 stopped a conservative retirement from committing the
/// modules and claims of a newcomer it does not retain). A later generation
/// reusing such an ID would inherit the old one's modules, claims, or
/// retirement. Each leftover here is named by exactly one of those, and only
/// the unnamed one is released.
#[test]
fn unadmitted_view_ids_stay_allocated_while_engine_state_names_them() {
    let (mut engine, module, _, _) = engine_with_overlay(7);
    let claimed = module.view;
    let listed = ProcessViewId(claimed.0 + 1);
    let intended = ProcessViewId(claimed.0 + 2);
    let free = ProcessViewId(claimed.0 + 3);
    // The committed module moves to `listed`; its pin claims stay on `claimed`.
    engine.modules[0].scanned.view = listed;
    engine
        .retirement_intents
        .insert(intended, RetirementCause::GenerationLost);
    engine.next_view_id = free.0 + 1;
    assert!(engine.pinned.view_claims(claimed).is_some());
    assert!(engine.pinned.view_claims(listed).is_none());

    let pid = std::process::id();
    let leftovers = [claimed, listed, intended, free]
        .into_iter()
        .map(|id| {
            (
                ProcessView::open(id, pid).unwrap(),
                Vec::new(),
                PinnedObjects::empty(),
            )
        })
        .collect();
    engine.release_unadmitted_views(leftovers);

    assert_eq!(
        engine.retired_view_ids,
        vec![free.0],
        "only the ID nothing names returns to the pool"
    );
}

/// U-07 fixture: a cgroup-scope engine whose membership is exactly what the
/// test writes to `cgroup.procs`, so no process outside the test is ever in
/// scope. The providers are the module hints, and the tick quantum is lifted
/// so wall time never defers an admission.
fn u07_engine(members: &[u32], providers: &[PathBuf]) -> (Engine, tempfile::TempDir) {
    let (mut engine, scope) = engine_over_cgroup_naming(members);
    engine.module_hints = providers.to_vec();
    engine.scheduler.set_tick_quantum_ns_for_test(u64::MAX);
    (engine, scope)
}

fn u07_name_members(scope: &Path, members: &[u32]) {
    let listing: String = members.iter().map(|pid| format!("{pid}\n")).collect();
    std::fs::write(scope.join("cgroup.procs"), listing).expect("rewrite cgroup.procs");
}

/// One inventory tick that hands the tick's additions frame to the caller.
fn u07_tick(engine: &mut Engine, session: &mut ScriptedSession, additions: &mut bool) {
    let mut collect: Box<DiscoveryCollector<'_>> = Box::new(Engine::collect_discovery_records);
    engine
        .refresh_inventory(
            session,
            additions,
            &mut Vec::new(),
            &mut PendingViewRetirements::new(),
            &mut *collect,
            &mut PauseClosure::new(true),
        )
        .expect("an inventory refresh over a cgroup scope");
}

/// The plan's slots on the provider with this file name, as (active,
/// inactive) slot indices.
fn u07_provider_slots(engine: &Engine, provider: &str) -> (Vec<u32>, Vec<u32>) {
    engine
        .plan
        .slots
        .iter()
        .filter(|slot| slot.object_path.ends_with(provider))
        .map(|slot| slot.index)
        .partition(|index| engine.plan.is_active(*index))
}

/// U-07. A foreign member that ends is an ordinary retirement, and the
/// conservative replay that retires it only removes. That replay used to
/// close the whole tick's additions frame, so a newcomer admitted in the same
/// tick was published with every slot deactivated, never attached and never
/// armed. As a known view it was never retried afterwards. Here the foreign
/// member's retirement and the newcomer's admission share one tick, and the
/// newcomer must leave that tick attached and armed.
#[test]
fn a_foreign_exit_retired_in_the_same_tick_does_not_strand_a_newcomer() {
    let dir = tempfile::tempdir().expect("a fixture directory");
    let provider = system_scope_build_fixture(dir.path(), "u07-newcomer");
    let driver = system_scope_build_driver(dir.path());
    let mut foreign = spawn_execed_sleep();
    let (mut engine, scope) = u07_engine(&[foreign.id()], std::slice::from_ref(&provider));
    let mut session = ScriptedSession::default();
    u07_tick(&mut engine, &mut session, &mut true);
    let foreign_view = engine
        .views
        .iter()
        .find(|view| view.pid() == foreign.id())
        .map(ProcessView::id)
        .expect("tick 1 admits the foreign member");

    // Between the ticks the foreign member ends and leaves the scope, and the
    // newcomer joins it: tick 2 retires the one and admits the other.
    foreign.kill().unwrap();
    foreign.wait().unwrap();
    let newcomer = system_scope_spawn_loaded(&driver, &provider);
    u07_name_members(scope.path(), &[newcomer.pid()]);
    let attached_before = session.attached_slots.len();
    let mut additions = true;
    u07_tick(&mut engine, &mut session, &mut additions);

    assert!(
        engine.views.iter().all(|view| view.id() != foreign_view),
        "tick 2 retires the ended foreign member"
    );
    let newcomer_view = engine
        .views
        .iter()
        .find(|view| view.pid() == newcomer.pid())
        .map(ProcessView::id)
        .expect("tick 2 admits the fully verified newcomer");
    let (active, inactive) = u07_provider_slots(&engine, "u07-newcomer.so");
    let attached = &session.attached_slots[attached_before..];
    assert!(
        !active.is_empty() && inactive.is_empty(),
        "the newcomer was published without its links: active {active:?}, inactive {inactive:?}, attach calls {attached:?}"
    );
    assert_eq!(
        attached.iter().sum::<usize>(),
        active.len(),
        "the same tick attaches exactly the newcomer's slots"
    );
    assert!(
        !engine
            .loader_registry
            .ids_for_view(newcomer_view)
            .is_empty(),
        "the same tick arms the newcomer's loader"
    );
    assert!(
        additions,
        "retiring an ended member leaves the tick open for additions"
    );
}

/// U-07. The conservative replay never attaches: that is a property of its
/// own candidate, not of the tick, so a clean replay leaves the tick's
/// additions frame open. Ownership uncertainty still closes it: a replay
/// whose detach fails blocks additions for the rest of the tick, exactly as
/// its PARTIAL reason says.
#[test]
fn a_conservative_replay_closes_the_tick_only_on_ownership_uncertainty() {
    for detach_fails in [false, true] {
        let (mut child, mut engine, _) = engine_with_one_accepted_provider();
        let slots = engine.plan.slots.len();
        assert_eq!(slots, 1, "the retired view owns one attached slot");
        engine.pending_retirements.insert(engine.views[0].id());
        let mut session = ScriptedSession::default();
        session.fail_slot_detaches([detach_fails]);
        let mut additions = true;
        let mut pending = PendingViewRetirements::new();

        let outcome =
            engine.replay_pending_conservative(&mut session, &mut additions, &mut pending);

        assert!(
            !outcome.refused(),
            "detach failed: {detach_fails}; the replay applied"
        );
        assert!(
            engine.pending_retirements.is_empty(),
            "detach failed: {detach_fails}; the replay consumed its retirement"
        );
        assert_eq!(
            session.detached_slots.first(),
            Some(&slots),
            "detach failed: {detach_fails}; the replay detached the retired view's slots"
        );
        assert!(
            session.attached_slots.is_empty(),
            "detach failed: {detach_fails}; a conservative replay attaches nothing"
        );
        assert_eq!(
            additions, !detach_fails,
            "detach failed: {detach_fails}; only ownership uncertainty closes the tick"
        );
        let blocked = Skipped {
            subject: "live discovery detach".into(),
            reason:
                "a one-shot detach failed; additions and replacements were blocked for this cycle"
                    .into(),
        };
        assert_eq!(
            engine.counters.object_skips.contains(&blocked),
            detach_fails,
            "detach failed: {detach_fails}; {:?}",
            engine.counters.object_skips
        );
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

/// U-07. A tick whose additions are already closed (by its caller or by an
/// earlier failure in the batch) cannot attach a newcomer, so it must not
/// publish one: no view, module, pin claim or active slot of the newcomer is
/// committed, its view ID returns to the pool, and its pid is requested
/// again. The next open tick then admits it whole.
#[test]
fn a_closed_tick_leaves_a_newcomer_unpublished_and_requested() {
    let dir = tempfile::tempdir().expect("a fixture directory");
    let provider = system_scope_build_fixture(dir.path(), "u07-closed");
    let driver = system_scope_build_driver(dir.path());
    let newcomer = system_scope_spawn_loaded(&driver, &provider);
    let (mut engine, _scope) = u07_engine(&[newcomer.pid()], std::slice::from_ref(&provider));
    let mut session = ScriptedSession::default();

    let mut additions = false;
    u07_tick(&mut engine, &mut session, &mut additions);
    assert!(
        engine.views.is_empty(),
        "a closed tick publishes no newcomer: {:?}",
        engine
            .views
            .iter()
            .map(|view| (view.id(), view.pid()))
            .collect::<Vec<_>>()
    );
    assert!(
        engine.modules.is_empty(),
        "a closed tick commits no newcomer module: {:?}",
        engine
            .modules
            .iter()
            .map(|module| (module.scanned.view, &module.scanned.path))
            .collect::<Vec<_>>()
    );
    assert!(
        engine.pinned.view_claims(ProcessViewId(0)).is_none(),
        "a closed tick commits no newcomer pin claim"
    );
    let (active, _) = u07_provider_slots(&engine, "u07-closed.so");
    assert!(active.is_empty(), "no newcomer slot is active: {active:?}");
    assert!(
        engine
            .plan
            .modules
            .iter()
            .all(|module| !module.path.ends_with("u07-closed.so")),
        "the plan names no newcomer provider"
    );
    assert!(
        session.attached_slots.is_empty(),
        "a closed tick attaches nothing"
    );
    assert_eq!(
        engine.retired_view_ids,
        vec![0],
        "the unpublished newcomer's view ID returns to the pool"
    );
    assert!(
        engine.refresh_requested.contains(&newcomer.pid()),
        "the unpublished newcomer is requested again"
    );

    let mut additions = true;
    u07_tick(&mut engine, &mut session, &mut additions);
    let view = engine
        .views
        .iter()
        .find(|view| view.pid() == newcomer.pid())
        .map(ProcessView::id)
        .expect("the next open tick admits the newcomer");
    let (active, inactive) = u07_provider_slots(&engine, "u07-closed.so");
    assert!(
        !active.is_empty(),
        "the next open tick activates the newcomer's slots: inactive {inactive:?}"
    );
    assert_eq!(
        session.attached_slots.iter().sum::<usize>(),
        active.len(),
        "the next open tick attaches exactly the newcomer's slots"
    );
    assert!(
        !engine.loader_registry.ids_for_view(view).is_empty(),
        "the next open tick arms the newcomer's loader"
    );
    assert!(
        !engine.refresh_requested.contains(&newcomer.pid()),
        "the admission consumes the retry request"
    );
}

/// Task 1's carried concern, on the U-07 chain. Every newcomer is part of
/// the tick's candidate, so a generation that ends while a newcomer's links
/// are attached downgrades the whole candidate to a conservative
/// retirement. That committed the surviving newcomer's modules, pin claims
/// and attached slots but dropped its view. The orphaned module then named a
/// view nothing retained, every later candidate read as stale, and discovery
/// never admitted anything again. The survivor must stay unpublished, its
/// links rolled back and its pid requested, and the next tick must admit it
/// whole.
#[test]
fn a_generation_lost_during_a_newcomers_attach_leaves_no_orphaned_publication() {
    let dir = tempfile::tempdir().expect("a fixture directory");
    let provider = system_scope_build_fixture(dir.path(), "u07-survivor");
    let driver = system_scope_build_driver(dir.path());
    let survivor = system_scope_spawn_loaded(&driver, &provider);
    // Killed and reaped inside `attach_targets`, between the link mutation's
    // generation precheck and its postcheck; the test never waits on it.
    let lost = spawn_execed_sleep().id();
    let (mut engine, scope) = u07_engine(&[survivor.pid(), lost], std::slice::from_ref(&provider));
    let mut session = ScriptedSession::losing_generation_at_attach(lost);

    u07_tick(&mut engine, &mut session, &mut true);
    let attached = session.attached_slots.iter().sum::<usize>();
    assert!(attached > 0, "tick 1 attached the survivor's slots");
    let retained: BTreeSet<_> = engine.views.iter().map(ProcessView::id).collect();
    let orphaned: Vec<_> = engine
        .modules
        .iter()
        .filter(|module| !retained.contains(&module.scanned.view))
        .map(|module| (module.scanned.view, module.scanned.path.clone()))
        .collect();
    assert!(
        orphaned.is_empty(),
        "no committed module may name a view the engine does not retain: {orphaned:?}, retained {retained:?}"
    );
    assert!(
        engine.views.iter().all(|view| view.pid() != survivor.pid()),
        "a downgraded candidate retains no newcomer"
    );
    let (active, _) = u07_provider_slots(&engine, "u07-survivor.so");
    assert!(
        active.is_empty(),
        "an unpublished survivor keeps no active link: {active:?}"
    );
    assert_eq!(
        session
            .detached_slot_indices
            .iter()
            .map(Vec::len)
            .sum::<usize>(),
        attached,
        "the survivor's attached links were rolled back"
    );
    assert!(
        engine.refresh_requested.contains(&survivor.pid()),
        "the unpublished survivor is requested again"
    );

    u07_name_members(scope.path(), &[survivor.pid()]);
    u07_tick(&mut engine, &mut session, &mut true);
    let view = engine
        .views
        .iter()
        .find(|view| view.pid() == survivor.pid())
        .map(ProcessView::id)
        .expect("the next tick admits the survivor");
    let (active, _) = u07_provider_slots(&engine, "u07-survivor.so");
    assert!(
        !active.is_empty(),
        "the next tick activates the survivor's slots"
    );
    assert!(
        engine
            .modules
            .iter()
            .all(|module| module.scanned.view == view),
        "every committed module names the retained survivor"
    );
    assert!(
        !engine.loader_registry.ids_for_view(view).is_empty(),
        "the next tick arms the survivor's loader"
    );
}

fn u07_partial(subject: &str, reason: &str) -> Skipped {
    Skipped {
        subject: subject.into(),
        reason: reason.into(),
    }
}

/// U-07 fix round 1 (Important 1). A retained member's refresh finds a
/// provider it dlopened after admission, so the tick's candidate allocates
/// new slots for a view that stays current. A newcomer in the same
/// candidate ends during the serialized detach, before the attach
/// precheck, so the precheck fails and `attach_targets` never runs. Those
/// new slots used to be committed active with no link. They stayed keyed,
/// so no later candidate re-added them, and every rescan saw them as
/// attached. They must be left inactive with an explicit failure, and the
/// member's surviving refresh request must re-add and attach them on the
/// next tick.
#[test]
fn a_generation_lost_before_attach_leaves_a_refreshed_views_new_targets_retryable() {
    let dir = tempfile::tempdir().expect("a fixture directory");
    let provider = system_scope_build_fixture(dir.path(), "u07-refreshed");
    let mut member = LazyLoader::spawn(dir.path(), &provider);
    let (mut engine, scope) = u07_engine(&[member.pid()], std::slice::from_ref(&provider));
    let mut session = ScriptedSession::default();
    u07_tick(&mut engine, &mut session, &mut true);
    let view = engine
        .views
        .iter()
        .find(|view| view.pid() == member.pid())
        .map(ProcessView::id)
        .expect("tick 1 admits the module-free member");
    assert!(engine.modules.is_empty(), "tick 1 finds no provider");

    // The member dlopens its provider; the request models the refresh event.
    member.send(b'L');
    member.wait_for(b"P11SCOPE_LAZY loaded\n");
    engine.request_refresh(member.pid());
    // Killed and reaped inside the candidate's detach, before its attach
    // precheck; the test never waits on it.
    let lost = spawn_execed_sleep().id();
    u07_name_members(scope.path(), &[member.pid(), lost]);
    session.lose_generations_at_detach([Some(lost)]);
    let attach_calls = session.attached_slots.len();
    u07_tick(&mut engine, &mut session, &mut true);

    assert!(
        engine.views.iter().any(|retained| retained.id() == view),
        "the refreshed member stays retained"
    );
    let (active, inactive) = u07_provider_slots(&engine, "u07-refreshed.so");
    assert!(
        active.is_empty() && !inactive.is_empty(),
        "new targets that were never attached must not stay active: active {active:?}, inactive {inactive:?}, attach calls {:?}",
        &session.attached_slots[attach_calls..]
    );
    assert_eq!(
        session.attached_slots.len(),
        attach_calls,
        "the failed precheck attached nothing"
    );
    assert!(
        engine.counters.object_skips.contains(&u07_partial(
            "live discovery attach",
            "a process generation changed before new exact targets were attached; they were deactivated for a later attempt",
        )),
        "the unattached targets are an explicit failure: {:?}",
        engine.counters.object_skips
    );
    assert!(
        engine.refresh_requested.contains(&member.pid()),
        "the member's refresh request survives for the retry"
    );

    u07_name_members(scope.path(), &[member.pid()]);
    let attach_calls = session.attached_slots.len();
    u07_tick(&mut engine, &mut session, &mut true);
    let (active, _) = u07_provider_slots(&engine, "u07-refreshed.so");
    assert!(
        !active.is_empty(),
        "the next tick re-adds the member's targets"
    );
    assert_eq!(
        session.attached_slots[attach_calls..].iter().sum::<usize>(),
        active.len(),
        "the next tick attaches exactly the re-added targets"
    );
    assert!(
        !engine.loader_registry.ids_for_view(view).is_empty(),
        "the next tick arms the member's loader"
    );
    assert!(
        !engine.refresh_requested.contains(&member.pid()),
        "the retry consumes the refresh request"
    );
}

/// U-07 fix round 1 (Minor 1). A closure raised in the record pass that
/// follows a successful apply lands after the tick has already retained its
/// newcomer. The arm phase is then skipped, and the retain there keeps only
/// requests that already exist; a first-time newcomer has none. Its static
/// links are attached, but its loader was never armed, so its dynamic
/// coverage was silently lost for its lifetime. Here a module-free member
/// whose leader exit is already recorded finishes exiting during the attach,
/// and the post-apply pass retires it. That replay's preflight is refused,
/// an unclean replay, so it closes the tick. The newcomer must be requested,
/// and the next tick must arm it.
#[test]
fn a_closure_after_admission_requests_the_newcomer_it_left_unarmed() {
    let dir = tempfile::tempdir().expect("a fixture directory");
    let provider = system_scope_build_fixture(dir.path(), "u07-unarmed");
    let driver = system_scope_build_driver(dir.path());
    let exiting = spawn_execed_sleep();
    let exiting_pid = exiting.id();
    let (mut engine, scope) = u07_engine(&[exiting_pid], std::slice::from_ref(&provider));
    u07_tick(&mut engine, &mut ScriptedSession::default(), &mut true);
    let exiting_view = engine
        .views
        .iter()
        .find(|view| view.pid() == exiting_pid)
        .map(ProcessView::id)
        .expect("tick 1 admits the module-free member");
    // Its leader exit is recorded, but its pin does not prove the exit yet,
    // so each record pass leaves the retirement queued until it does.
    engine.queue_retirement(
        exiting_view,
        RetirementCause::ExpectedRemoval,
        &mut PendingViewRetirements::new(),
    );

    let newcomer = system_scope_spawn_loaded(&driver, &provider);
    u07_name_members(scope.path(), &[exiting_pid, newcomer.pid()]);
    // The member finishes exiting inside the newcomer's attach; it is not a
    // candidate view, so the newcomer's apply is accepted. Preflights 1 and 2
    // are the tick's own; 3 is the post-apply replay that retires the member.
    let mut session = ScriptedSession::losing_generation_at_attach(exiting_pid);
    session.refuse_preflights([false, false, true]);
    let mut additions = true;
    u07_tick(&mut engine, &mut session, &mut additions);
    drop(exiting);

    let view = engine
        .views
        .iter()
        .find(|view| view.pid() == newcomer.pid())
        .map(ProcessView::id)
        .expect("the newcomer is admitted");
    let (active, _) = u07_provider_slots(&engine, "u07-unarmed.so");
    assert!(!active.is_empty(), "the newcomer's slots are active");
    assert_eq!(
        session.attached_slots.iter().sum::<usize>(),
        active.len(),
        "the newcomer's static links are attached"
    );
    assert!(
        !additions,
        "the unclean replay after the apply closes the tick"
    );
    assert!(
        engine.loader_registry.ids_for_view(view).is_empty(),
        "the closed tick skips arming"
    );
    assert!(
        engine.refresh_requested.contains(&newcomer.pid()),
        "the newcomer the closed tick left unarmed is requested again"
    );

    u07_name_members(scope.path(), &[newcomer.pid()]);
    u07_tick(&mut engine, &mut session, &mut true);
    assert!(
        !engine.loader_registry.ids_for_view(view).is_empty(),
        "the next tick arms the newcomer"
    );
    assert!(
        !engine.refresh_requested.contains(&newcomer.pid()),
        "arming consumes the refresh request"
    );
}

/// U-07 fix round 1 (Minor 1). A closure can also land inside the arm phase:
/// a foreign generation that ends while the first newcomer's loader
/// candidate is being admitted closes the tick. That skips every newcomer
/// armed after it, and the first one is not armed either. Each owned
/// newcomer left unarmed must be requested, and the next tick must arm it.
#[test]
fn a_foreign_exit_during_arming_requests_the_newcomer_it_left_unarmed() {
    let dir = tempfile::tempdir().expect("a fixture directory");
    let first = system_scope_build_fixture(dir.path(), "u07-arm-first");
    let second = system_scope_build_fixture(dir.path(), "u07-arm-second");
    let driver = system_scope_build_driver(dir.path());
    let mut survivor = system_scope_spawn_loaded(&driver, &first);
    let mut lost = system_scope_spawn_loaded(&driver, &second);
    // Newcomers are admitted and armed in pid order: the lower pid survives
    // and is armed first, and the higher pid is the foreign generation that
    // ends inside that arm.
    if lost.pid() < survivor.pid() {
        std::mem::swap(&mut survivor, &mut lost);
    }
    let (mut engine, scope) = u07_engine(
        &[survivor.pid(), lost.pid()],
        &[first.clone(), second.clone()],
    );
    let mut session = ScriptedSession::default();
    // Preflights 1 and 2 are the tick's own; 3 is the survivor's loader
    // candidate, where the other newcomer ends.
    session.lose_generations_at_preflight([None, None, Some(lost.pid())]);
    let mut additions = true;
    u07_tick(&mut engine, &mut session, &mut additions);
    // The seam killed and reaped it: its guard must not signal the pid again.
    // SAFETY: signal 0 only probes whether the pid still exists.
    lost.live = unsafe { libc::kill(lost.pid() as libc::pid_t, 0) } == 0;

    let view = engine
        .views
        .iter()
        .find(|view| view.pid() == survivor.pid())
        .map(ProcessView::id)
        .expect("the surviving newcomer is admitted");
    assert!(!additions, "the foreign exit inside arming closes the tick");
    assert!(
        engine.loader_registry.ids_for_view(view).is_empty(),
        "the closed tick leaves the surviving newcomer unarmed"
    );
    assert!(
        engine.refresh_requested.contains(&survivor.pid()),
        "the newcomer the closed tick left unarmed is requested again"
    );

    u07_name_members(scope.path(), &[survivor.pid()]);
    u07_tick(&mut engine, &mut session, &mut true);
    assert!(
        !engine.loader_registry.ids_for_view(view).is_empty(),
        "the next tick arms the surviving newcomer"
    );
    assert!(
        !engine.refresh_requested.contains(&survivor.pid()),
        "arming consumes the refresh request"
    );
}

/// U-07 fix round 2 (C2). While the tick is still open, the retain before the
/// arm phase drops the refresh request of every view it refreshed. A
/// module-owning foreign view that ends while a refreshed view's loader
/// candidate is admitted closes the tick inside the arm phase, so that view
/// was left unarmed with no request. That is the main dlopen path: an
/// exploratory member that gains a provider is armed as a refreshed view,
/// and once it owns modules polling never rescans it. It must be requested,
/// and the next tick must arm it.
#[test]
fn a_foreign_exit_during_arming_requests_the_refreshed_view_it_left_unarmed() {
    let dir = tempfile::tempdir().expect("a fixture directory");
    let provider = system_scope_build_fixture(dir.path(), "u07-rearm");
    let foreign_provider = system_scope_build_fixture(dir.path(), "u07-rearm-foreign");
    let driver = system_scope_build_driver(dir.path());
    let mut member = LazyLoader::spawn(dir.path(), &provider);
    let mut foreign = system_scope_spawn_loaded(&driver, &foreign_provider);
    let (mut engine, scope) = u07_engine(
        &[member.pid(), foreign.pid()],
        &[provider.clone(), foreign_provider.clone()],
    );
    let mut session = ScriptedSession::default();
    u07_tick(&mut engine, &mut session, &mut true);
    let view_of = |engine: &Engine, pid: u32| {
        engine
            .views
            .iter()
            .find(|view| view.pid() == pid)
            .map(ProcessView::id)
    };
    let view = view_of(&engine, member.pid()).expect("tick 1 admits the member");
    let foreign_view = view_of(&engine, foreign.pid()).expect("tick 1 admits the foreign view");
    assert!(
        engine.loader_registry.ids_for_view(view).is_empty(),
        "the module-free member stays exploratory"
    );
    assert!(
        !engine.loader_registry.ids_for_view(foreign_view).is_empty(),
        "tick 1 arms the module-owning foreign view"
    );

    // The member dlopens its provider; the request models the refresh event.
    member.send(b'L');
    member.wait_for(b"P11SCOPE_LAZY loaded\n");
    engine.request_refresh(member.pid());
    // Preflights 1 and 2 are the tick's own; 3 is the member's loader
    // candidate, where the foreign view ends.
    session.lose_generations_at_preflight([None, None, Some(foreign.pid())]);
    let mut additions = true;
    u07_tick(&mut engine, &mut session, &mut additions);
    // The seam killed and reaped it: its guard must not signal the pid again.
    // SAFETY: signal 0 only probes whether the pid still exists.
    foreign.live = unsafe { libc::kill(foreign.pid() as libc::pid_t, 0) } == 0;

    let (active, _) = u07_provider_slots(&engine, "u07-rearm.so");
    assert!(
        !active.is_empty(),
        "the refresh attaches the member's new provider"
    );
    assert!(!additions, "the foreign exit inside arming closes the tick");
    assert!(
        engine.loader_registry.ids_for_view(view).is_empty(),
        "the closed tick leaves the refreshed member unarmed"
    );
    assert!(
        engine.refresh_requested.contains(&member.pid()),
        "the refreshed view the closed tick left unarmed is requested again"
    );

    u07_name_members(scope.path(), &[member.pid()]);
    u07_tick(&mut engine, &mut session, &mut true);
    assert!(
        !engine.loader_registry.ids_for_view(view).is_empty(),
        "the next tick arms the member"
    );
    assert!(
        !engine.refresh_requested.contains(&member.pid()),
        "arming consumes the refresh request"
    );
}

/// U-07 fix round 2 (C1). A downgraded exact target is replaced by detaching
/// its old link with the retirements and attaching the replacement last. A
/// candidate view that ends between the new-target attach and the
/// replacement's generation precheck (here inside the failed-slot detach,
/// the only session call in that window) fails that precheck. The
/// replacement then did nothing: its target stayed active with no link, and
/// only session start would ever link it again. The target must be left
/// inactive with an explicit failure. Slot 0's exact descriptor is set on
/// the plan directly, standing in for the authorized identity that
/// corroboration would supply; the rebuilt candidate downgrades it.
#[test]
fn a_generation_lost_before_replacement_leaves_the_detached_targets_inactive() {
    let (mut kept, mut engine, modules) = engine_with_one_accepted_provider();
    let descriptor = crate::kinds::function_id("C_Initialize").unwrap() + 1;
    let accepted = &mut engine.plan.slots[0];
    accepted.descriptor_index = descriptor;
    accepted.semantics = crate::kinds::DESCRIPTORS[descriptor as usize];
    accepted.semantic_authorized = true;
    accepted.semantic_ambiguous = false;
    engine.plan.validate_slot_index().unwrap();

    // A second candidate view, whose own provider is new; it is killed and
    // reaped inside the apply's second detach. The test never waits on it.
    let lost = spawn_execed_sleep().id();
    let lost_view = ProcessView::open(ProcessViewId(4), lost).unwrap();
    engine.next_view_id = 5;
    let lost_module = child_provider_modules(&lost_view)[1].clone();
    let lost_pins = pin_test_modules(&lost_view, std::slice::from_ref(&lost_module));
    engine.views.push(lost_view);
    let mut pins = engine.pinned.clone();
    let skipped = pins.absorb(lost_pins);
    let candidate = engine
        .live_candidate(pins, vec![modules[0].clone(), lost_module], skipped)
        .unwrap();
    assert_eq!(
        candidate.delta.replace.len(),
        1,
        "the candidate downgrades slot 0"
    );
    assert_eq!(
        candidate.delta.new.len(),
        1,
        "the second view's provider is new"
    );
    let replaced = candidate.delta.replace[0].index;
    let mut session = ScriptedSession::default();
    session.lose_generations_at_detach([None, Some(lost)]);
    let mut additions = true;

    engine
        .apply_candidate(&mut session, candidate, &mut additions, false, &[])
        .unwrap();

    assert_eq!(
        session.detached_slot_indices.first(),
        Some(&vec![replaced]),
        "the replaced target's old link was detached first"
    );
    assert_eq!(
        session.attached_slots,
        [1],
        "the new target attached before the generation was lost"
    );
    assert!(
        !engine.plan.is_active(replaced),
        "a target whose old link was detached and never replaced must not stay active"
    );
    assert!(
        engine.counters.object_skips.contains(&u07_partial(
            "live discovery replacement",
            "a process generation changed before downgraded exact targets were replaced; they were deactivated",
        )),
        "the unreplaced target is an explicit failure: {:?}",
        engine.counters.object_skips
    );
    assert!(!additions, "the lost generation closes the tick");
    kept.kill().unwrap();
    kept.wait().unwrap();
}

/// Replays one queued retirement through `replay_pending_conservative` on
/// `engine_with_one_accepted_provider`, whose accepted provider stays in the
/// replay's candidate: the retired view is `retired`, not the provider's.
fn u07_replay(
    engine: &mut Engine,
    session: &mut ScriptedSession,
    retired: ProcessViewId,
) -> (ApplyOutcome, bool) {
    engine.pending_retirements.insert(retired);
    let mut additions = true;
    let outcome = engine.replay_pending_conservative(
        session,
        &mut additions,
        &mut PendingViewRetirements::new(),
    );
    (outcome, additions)
}

/// U-07 fix round 1 (Minor 3a). A clean replay leaves the tick open, but a
/// replay whose preflight refuses it committed nothing and still closes the
/// tick; its retirement stays queued.
#[test]
fn a_refused_conservative_replay_closes_the_tick() {
    let (mut child, mut engine, _) = engine_with_one_accepted_provider();
    let retired = ProcessViewId(9);
    let mut session = ScriptedSession::default();
    session.refuse_preflights([true]);

    let (outcome, additions) = u07_replay(&mut engine, &mut session, retired);

    assert!(outcome.refused(), "the preflight refused the replay");
    assert!(!additions, "a refused replay closes the tick");
    assert_eq!(
        engine.pending_retirements,
        [retired].into_iter().collect(),
        "the refused retirement stays queued"
    );
    assert!(
        session.attached_slots.is_empty(),
        "the replay attached nothing"
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

/// U-07 fix round 1 (Minor 3a). A replay whose candidate loses a generation
/// during its detach commits only a conservative retirement, and still
/// closes the tick.
#[test]
fn a_retired_conservative_replay_closes_the_tick() {
    let (child, mut engine, _) = engine_with_one_accepted_provider();
    let mut session = ScriptedSession::default();
    // The accepted provider's process ends inside the replay's detach; the
    // seam kills and reaps it.
    session.lose_generations_at_detach([Some(child.id())]);

    let (outcome, additions) = u07_replay(&mut engine, &mut session, ProcessViewId(9));

    assert_eq!(
        outcome.disposition,
        ApplyDisposition::ConservativeRetirement,
        "the lost generation retired the replay's candidate"
    );
    assert!(!additions, "a retired replay closes the tick");
    assert!(
        engine.counters.object_skips.contains(&u07_partial(
            "live discovery generation",
            "a process generation changed after link mutation; its targets were retired before context cleanup",
        )),
        "{:?}",
        engine.counters.object_skips
    );
    assert!(
        session.attached_slots.is_empty(),
        "the replay attached nothing"
    );
}

/// U-07 fix round 1 (Minor 3b). A replay whose conservative candidate cannot
/// be rebuilt closes the tick and keeps its retirement queued.
#[test]
fn a_conservative_replay_that_cannot_be_rebuilt_closes_the_tick() {
    let (mut child, mut engine, _) = engine_with_one_accepted_provider();
    let retired = ProcessViewId(9);
    // The capture-lifetime module registry no longer maps the accepted
    // provider bijectively, so no candidate over it can be rebuilt.
    engine
        .capture_facts
        .module_keys
        .insert(plan::ModuleId(0), timing_key(0));
    let mut session = ScriptedSession::default();

    let (outcome, additions) = u07_replay(&mut engine, &mut session, retired);

    assert!(outcome.refused(), "nothing was applied");
    assert!(!additions, "an unrebuildable replay closes the tick");
    assert_eq!(
        engine.pending_retirements,
        [retired].into_iter().collect(),
        "the retirement stays queued"
    );
    assert!(
        engine.counters.object_skips.contains(&u07_partial(
            "live discovery transaction",
            "a pending conservative candidate could not be rebuilt and remains queued",
        )),
        "{:?}",
        engine.counters.object_skips
    );
    assert!(
        session.detached_slots.is_empty() && session.attached_slots.is_empty(),
        "no link was touched"
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

/// U-07 fix round 1 (Minor 3b). A replay whose conservative candidate cannot
/// be applied closes the tick and keeps its retirement queued.
#[test]
fn a_conservative_replay_that_cannot_be_applied_closes_the_tick() {
    let (mut child, mut engine, _) = engine_with_one_accepted_provider();
    let retired = ProcessViewId(9);
    // The accepted manifest history lost its source ordinals, so the replay's
    // publication preflight refuses before any link mutation.
    engine.manifest_ordinals.push(0);
    let mut session = ScriptedSession::default();

    let (outcome, additions) = u07_replay(&mut engine, &mut session, retired);

    assert!(outcome.refused(), "nothing was applied");
    assert!(!additions, "an inapplicable replay closes the tick");
    assert_eq!(
        engine.pending_retirements,
        [retired].into_iter().collect(),
        "the retirement stays queued"
    );
    assert!(
        engine.counters.object_skips.contains(&u07_partial(
            "live discovery transaction",
            "a pending conservative candidate could not be applied and remains queued",
        )),
        "{:?}",
        engine.counters.object_skips
    );
    assert!(
        session.detached_slots.is_empty() && session.attached_slots.is_empty(),
        "no link was touched"
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn view_id_ceiling_follows_max_scan_pids() {
    let mut engine = Engine::empty();
    engine.max_scan_pids = 300;
    engine.next_view_id = 256;
    assert!(engine.allocate_view_id().is_ok());
    engine.max_scan_pids = 256;
    assert!(engine.allocate_view_id().is_err());
}

/// A2-T2 coverage: the `retain_view_id` path pins the retained ID value
/// (the allocator floor advances past it) and the interpolated ceiling
/// message names the effective value byte-exactly.
#[test]
fn retain_view_id_advances_the_floor_and_names_the_ceiling() {
    let mut engine = Engine::empty();
    engine.max_scan_pids = 2;
    engine.retain_view_id(ProcessViewId(1)).unwrap();
    assert_eq!(engine.next_view_id, 2);
    assert!(engine.allocate_view_id().is_err());
    let error = engine.retain_view_id(ProcessViewId(2)).unwrap_err();
    assert_eq!(
        error.to_string(),
        "capture process-view capacity 2 is exhausted"
    );
}

fn current_mount_namespace() -> crate::process::MountNamespaceId {
    let metadata = std::fs::metadata("/proc/self/ns/mnt").unwrap();
    crate::process::MountNamespaceId {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn reconcile_for_test(
    modules: &[ScannedModule],
    pinned: &mut PinnedObjects,
) -> Vec<ReconciledModule> {
    let (modules, _, skipped) = reconcile_scanned_modules(modules, pinned);
    assert!(skipped.is_empty(), "{skipped:?}");
    modules
}

fn lifecycle_discovered(views: Vec<ProcessView>) -> Engine {
    let mut discovered = Engine::empty();
    for view in &views {
        discovered.retain_view_id(view.id()).unwrap();
    }
    discovered.views = views;
    discovered
}

fn discovered_from_inputs(
    views: Vec<ProcessView>,
    scan_modules: Vec<ScannedModule>,
    scan_pins: PinnedObjects,
    manifest_inputs: Vec<ManifestInput>,
) -> Engine {
    let mut discovered = lifecycle_discovered(views);
    let view = scan_modules
        .first()
        .expect("test scan input has one process view")
        .view;
    discovered.scan_inputs.insert(
        view,
        ScanInput {
            modules: scan_modules,
            pins: scan_pins,
            counters: DiscoveryCounters::default(),
        },
    );
    discovered.manifest_inputs = manifest_inputs;
    rebuild_discovered(&mut discovered).unwrap();
    discovered
}

fn same_object_scan_and_manifest(
    scan_offset: u64,
) -> (
    ProcessView,
    Vec<ScannedModule>,
    PinnedObjects,
    ManifestInput,
) {
    let (mut modules, pins) = pinned_self();
    assert_eq!(modules.len(), 1);
    let summary = pins.pinned().next().unwrap();
    let (path, key, sha256) = (
        summary.path.to_string(),
        summary.key,
        summary.sha256.to_string(),
    );
    modules[0].tables.push(ScannedTable {
        version: (2, 40),
        walk: "full",
        entries: vec![ScannedEntry {
            name: "C_Sign",
            object: key,
            object_path: path.clone(),
            file_offset: scan_offset,
        }],
        null_entries: vec![],
        unpinned: vec![],
        address: 0x7000,
        file_offset: Some(0),
        live_return: false,
        manifest_supported: false,
    });
    let manifest = manifest_naming(&path, Some(sha256));
    let input = ManifestInput {
        path: PathBuf::from("manifest.json"),
        pins: pin_as_manifest_object(&path),
        manifest,
        stale: Vec::new(),
    };
    (
        ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
        modules,
        pins,
        input,
    )
}

/// Hermetic stand-in for the old `/bin/sh` + `/bin/ls` copies: host shell
/// layouts drift (this host's dash has TEXT at file 0x4000, outside the
/// replacement's X ranges), which broke the stale tests' assumption that
/// manifest-time offsets stay valid under the replacement file. The marker
/// yields the standard `gcc -shared` layout (R-X at file 0x1000); staleness
/// triggers by identity change (appended byte), never by host layout.
const FIXTURE_ORIGINAL: &str = "ORIGINAL-0001";

fn build_fixture_so(path: &Path, marker: &str) {
    let source = path.with_extension("c");
    std::fs::write(
            &source,
            format!(
                "const char p11scope_fixture_marker[] = \"{marker}\";\nint p11scope_fixture_entry(void) {{ return 0; }}\n"
            ),
        )
        .unwrap();
    // Compile aside, then copy over the target: like the old
    // `std::fs::copy("/bin/ls", …)` replacement, this truncates in place
    // and keeps the inode stable, which the stale tests' key matching
    // requires (`gcc -o` would unlink and recreate with a new inode).
    let built = path.with_extension("build.so");
    assert!(
        std::process::Command::new("gcc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&built)
            .arg(&source)
            .status()
            .unwrap()
            .success()
    );
    std::fs::copy(&built, path).unwrap();
}

fn object_facts(path: &Path) -> (ObjectKey, p11scope_manifest::identity::ObjectIdentity, u64) {
    let file = p11scope_manifest::identity::open_object(path).unwrap();
    let mapping = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
    let inspected = p11scope_manifest::identity::inspect_file(&file).unwrap();
    (
        ObjectKey {
            device: p11scope_manifest::maps::Device {
                major: mapping.device_major,
                minor: mapping.device_minor,
            },
            inode: mapping.inode,
        },
        inspected.identity,
        inspected.executable_ranges[0].0,
    )
}

fn replace_fixture_with_changed_elf(path: &Path) {
    let before = object_facts(path);
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(&[0]).unwrap();
    let after = object_facts(path);
    assert_eq!(before.2, after.2, "fixture executable layout changed");
    assert_ne!(before.1, after.1, "fixture identity did not change");
}

fn valid_manifest_for(paths: &[PathBuf], targets: &[u32]) -> Manifest {
    use p11scope_manifest::manifest::*;

    assert_eq!(targets.len(), 67);
    let facts: Vec<_> = paths.iter().map(|path| object_facts(path)).collect();
    Manifest {
        schema: SCHEMA.to_string(),
        module_path: paths[0].display().to_string(),
        objects: paths
            .iter()
            .zip(&facts)
            .enumerate()
            .map(|(id, (path, (_, identity, _)))| ObjectRecord {
                id: id as u32,
                path: path.display().to_string(),
                identity: identity.clone(),
            })
            .collect(),
        provenance_objects: paths
            .iter()
            .zip(&facts)
            .map(|(path, (key, identity, _))| ProvenanceObject {
                path: path.display().to_string(),
                device_major: key.device.major,
                device_minor: key.device.minor,
                inode: key.inode,
                identity: identity.clone(),
            })
            .collect(),
        interface_list: Acquisition::Absent,
        surfaces: vec![SurfaceRecord {
            source: SurfaceSource::LegacyFunctionList,
            acquisition: Acquisition::Ok,
            version: Some(Version { major: 2, minor: 0 }),
            walk: WalkOutcome::Full,
            functions: pkcs11_module::FUNCTION_LIST_FIELDS[..67]
                .iter()
                .zip(targets)
                .map(|(field, object)| FunctionRecord {
                    name: field.name.into(),
                    resolution: Resolution::Resolved {
                        object: *object,
                        file_offset: facts[*object as usize].2,
                    },
                })
                .collect(),
        }],
        vendor_interfaces: vec![],
        alias_groups: vec![],
        selection_evidence: Default::default(),
    }
}

fn scanned_manifest_replacement(paths: &[PathBuf], targets: &[u32]) -> ScannedModule {
    let facts: Vec<_> = paths.iter().map(|path| object_facts(path)).collect();
    ScannedModule {
        view: ProcessViewId(0),
        mount_namespace: current_mount_namespace(),
        key: facts[0].0,
        path: paths[0].display().to_string(),
        decoder_abi: Some(ElfAbi::Lp64),
        exports: vec!["C_GetFunctionList".into()],
        tables: vec![ScannedTable {
            version: (2, 0),
            walk: "full",
            entries: pkcs11_module::FUNCTION_LIST_FIELDS[..67]
                .iter()
                .zip(targets)
                .map(|(field, object)| ScannedEntry {
                    name: field.name,
                    object: facts[*object as usize].0,
                    object_path: paths[*object as usize].display().to_string(),
                    file_offset: facts[*object as usize].2,
                })
                .collect(),
            null_entries: vec![],
            unpinned: vec![],
            address: 0x7000,
            file_offset: Some(0),
            live_return: false,
            manifest_supported: false,
        }],
        interfaces: vec![],
    }
}

fn manifest_input_from_pinning(path: &str, manifest: Manifest) -> ManifestInput {
    let pinning = pin_manifest_objects_deferred(&manifest).unwrap();
    ManifestInput {
        path: PathBuf::from(path),
        manifest,
        pins: pinning.pins,
        stale: pinning.stale,
    }
}

fn pin_scan(module: &ScannedModule) -> PinnedObjects {
    let (pins, skipped) = pin_scanned_objects(
        std::process::id(),
        std::slice::from_ref(module),
        &mut CaptureWorkBudget::default(),
    )
    .unwrap();
    assert!(skipped.is_empty(), "{skipped:?}");
    pins
}

#[test]
fn discovery_open_stale_manifest_object_uses_only_the_exact_scanned_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let provider = dir.path().join("provider.so");
    std::fs::copy("/bin/sh", &provider).unwrap();
    let paths = vec![provider.clone()];
    let targets = vec![0; 67];
    let manifest = valid_manifest_for(&paths, &targets);
    let scan = scanned_manifest_replacement(&paths, &targets);
    let scan_offset = scan.tables[0].entries[0].file_offset;
    let scan_pins = pin_scan(&scan);
    std::fs::remove_file(&provider).unwrap();
    let input = manifest_input_from_pinning("open-stale.json", manifest);
    assert_eq!(input.stale[0].reason, ManifestStaleReason::OpenStale);

    let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let stale_view = view.id();
    let mut discovered = discovered_from_inputs(vec![view], vec![scan], scan_pins, vec![input]);

    assert_eq!(discovered.plan.modules[0].source, "scan");
    assert_eq!(discovered.plan.slots.len(), 1);
    assert_eq!(discovered.plan.slots[0].file_offset, scan_offset);
    assert!(!discovered.plan.slots[0].semantic_authorized);
    assert_eq!(
        discovered.plan.slots[0].semantics,
        p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
    );
    assert_eq!(discovered.counters.manifest_fallbacks.len(), 1);
    assert_eq!(discovered.counters.uncorroborated, 1);
    assert_eq!(discovered.discovery.manifest_object_fallbacks.len(), 1);

    let error = remove_stale_views(&mut discovered, &[stale_view])
        .expect_err("fallback must be recomputed from the surviving pristine views");
    assert!(
        error.to_string().contains("stale manifest object"),
        "{error:#}"
    );
}

#[test]
fn discovery_identity_stale_object_with_invalid_offset_is_fatal_before_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let provider = dir.path().join("provider.so");
    std::fs::copy("/bin/sh", &provider).unwrap();
    let paths = vec![provider.clone()];
    let targets = vec![0; 67];
    let mut manifest = valid_manifest_for(&paths, &targets);
    for function in &mut manifest.surfaces[0].functions {
        let Resolution::Resolved { file_offset, .. } = &mut function.resolution else {
            unreachable!()
        };
        *file_offset = 0xdead_beef;
    }
    std::fs::copy("/bin/true", &provider).unwrap();
    let error = pin_manifest_objects_deferred(&manifest)
        .expect_err("invalid executable offsets stay fatal before stale fallback");
    assert!(
        matches!(
            &error,
            ManifestPinError::Fatal(problems)
                if problems.iter().any(|problem| problem.contains("outside every executable"))
        ),
        "{error:?}"
    );
}

#[test]
fn discovery_complementary_partial_tables_do_not_cover_one_stale_surface() {
    let dir = tempfile::tempdir().unwrap();
    let provider = dir.path().join("provider.so");
    build_fixture_so(&provider, FIXTURE_ORIGINAL);
    let paths = vec![provider.clone()];
    let targets = vec![0; 67];
    let manifest = valid_manifest_for(&paths, &targets);
    replace_fixture_with_changed_elf(&provider);
    let mut scan = scanned_manifest_replacement(&paths, &targets);
    let mut second = scan.tables[0].clone();
    let midpoint = scan.tables[0].entries.len() / 2;
    second.entries = scan.tables[0].entries.split_off(midpoint);
    second.address += 0x1000;
    scan.tables.push(second);
    let pins = pin_scan(&scan);
    let input = manifest_input_from_pinning("partial-tables.json", manifest);
    let mut discovered = lifecycle_discovered(vec![
        ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
    ]);
    discovered.scan_inputs.insert(
        ProcessViewId(0),
        ScanInput {
            modules: vec![scan],
            pins,
            counters: DiscoveryCounters::default(),
        },
    );
    discovered.manifest_inputs.push(input);

    let error = rebuild_discovered(&mut discovered)
        .expect_err("two partial tables cannot manufacture one complete proof");
    assert!(error.to_string().contains("object 0"), "{error:#}");
}

#[test]
fn discovery_one_duplicate_table_cannot_prove_two_manifest_surfaces() {
    let dir = tempfile::tempdir().unwrap();
    let provider = dir.path().join("provider.so");
    build_fixture_so(&provider, FIXTURE_ORIGINAL);
    let paths = vec![provider.clone()];
    let targets = vec![0; 67];
    let mut manifest = valid_manifest_for(&paths, &targets);
    manifest.interface_list = Acquisition::Ok;
    manifest.surfaces[0] = SurfaceRecord {
        source: SurfaceSource::LegacyFunctionList,
        acquisition: Acquisition::Absent,
        version: None,
        walk: WalkOutcome::NotWalked,
        functions: vec![],
    };
    let functions: Vec<_> = pkcs11_module::FUNCTION_LIST_FIELDS
        .iter()
        .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
        .map(|field| FunctionRecord {
            name: field.name.into(),
            resolution: Resolution::Resolved {
                object: 0,
                file_offset: object_facts(&provider).2,
            },
        })
        .collect();
    let interface = |index| SurfaceRecord {
        source: SurfaceSource::Interface {
            index,
            raw_name_hex: Some("504b4353203131".into()),
            name_lossy: Some("PKCS 11".into()),
            name_error: None,
            flags: 0,
            classification: InterfaceClassification::ExactStandard,
        },
        acquisition: Acquisition::Ok,
        version: Some(Version { major: 3, minor: 0 }),
        walk: WalkOutcome::Full,
        functions: functions.clone(),
    };
    manifest.surfaces.extend([interface(0), interface(1)]);
    replace_fixture_with_changed_elf(&provider);
    let mut scan = scanned_manifest_replacement(&paths, &targets);
    let (key, _, offset) = object_facts(&provider);
    scan.tables[0].version = (3, 0);
    scan.tables[0].entries = pkcs11_module::FUNCTION_LIST_FIELDS
        .iter()
        .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
        .flat_map(|field| {
            std::iter::repeat_n(
                ScannedEntry {
                    name: field.name,
                    object: key,
                    object_path: provider.display().to_string(),
                    file_offset: offset,
                },
                2,
            )
        })
        .collect();
    let pins = pin_scan(&scan);
    let input = manifest_input_from_pinning("duplicate-table.json", manifest);
    let mut discovered = lifecycle_discovered(vec![
        ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
    ]);
    discovered.scan_inputs.insert(
        ProcessViewId(0),
        ScanInput {
            modules: vec![scan],
            pins,
            counters: DiscoveryCounters::default(),
        },
    );
    discovered.manifest_inputs.push(input);

    let error = rebuild_discovered(&mut discovered)
        .expect_err("one table cannot be reused for two manifest surfaces");
    assert!(error.to_string().contains("object 0"), "{error:#}");
}

#[test]
fn discovery_stale_module_requires_coverage_for_unresolved_claims() {
    let dir = tempfile::tempdir().unwrap();
    let provider = dir.path().join("provider.so");
    build_fixture_so(&provider, FIXTURE_ORIGINAL);
    let paths = vec![provider.clone()];
    let targets = vec![0; 67];
    let mut manifest = valid_manifest_for(&paths, &targets);
    manifest.surfaces[0].functions[66].resolution = Resolution::NullPointer;
    replace_fixture_with_changed_elf(&provider);
    let mut scan = scanned_manifest_replacement(&paths, &targets);
    scan.tables[0].entries.pop();
    let pins = pin_scan(&scan);
    let input = manifest_input_from_pinning("unresolved-claim.json", manifest);
    let mut discovered = lifecycle_discovered(vec![
        ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
    ]);
    discovered.scan_inputs.insert(
        ProcessViewId(0),
        ScanInput {
            modules: vec![scan],
            pins,
            counters: DiscoveryCounters::default(),
        },
    );
    discovered.manifest_inputs.push(input);

    let error = rebuild_discovered(&mut discovered)
        .expect_err("discarded unresolved records still require table coverage");
    assert!(error.to_string().contains("object 0"), "{error:#}");
}

#[test]
fn discovery_mixed_manifest_drops_only_the_stale_dependency_claims() {
    let dir = tempfile::tempdir().unwrap();
    let provider = dir.path().join("provider.so");
    let replaced = dir.path().join("replaced.so");
    let fresh = dir.path().join("fresh.so");
    for path in [&provider, &replaced, &fresh] {
        build_fixture_so(path, FIXTURE_ORIGINAL);
    }
    let paths = vec![provider.clone(), replaced.clone(), fresh.clone()];
    let mut targets = vec![0; 67];
    targets[0] = 1;
    targets[1] = 2;
    targets[2] = 2;
    targets[3] = 1;
    let mut manifest = valid_manifest_for(&paths, &targets);
    let stale_offset = object_facts(&replaced).2;
    let fresh_offset = object_facts(&fresh).2;
    manifest.alias_groups = vec![
        AliasGroup {
            object: 1,
            file_offset: stale_offset,
            entries: vec![
                AliasEntry {
                    surface: 0,
                    name: manifest.surfaces[0].functions[0].name.clone(),
                },
                AliasEntry {
                    surface: 0,
                    name: manifest.surfaces[0].functions[3].name.clone(),
                },
            ],
        },
        AliasGroup {
            object: 2,
            file_offset: fresh_offset,
            entries: vec![
                AliasEntry {
                    surface: 0,
                    name: manifest.surfaces[0].functions[1].name.clone(),
                },
                AliasEntry {
                    surface: 0,
                    name: manifest.surfaces[0].functions[2].name.clone(),
                },
            ],
        },
    ];

    replace_fixture_with_changed_elf(&replaced);
    let mut scan_targets = targets.clone();
    scan_targets[1] = 0;
    scan_targets[2] = 0;
    let mut scan = scanned_manifest_replacement(&paths, &scan_targets);
    scan.tables[0].entries[4].file_offset += 1;
    let scan_pins = pin_scan(&scan);
    let input = manifest_input_from_pinning("mixed-valid.json", manifest);
    assert_eq!(input.stale.len(), 1);
    assert_eq!(input.stale[0].object, 1);

    let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let discovered = discovered_from_inputs(vec![view], vec![scan], scan_pins, vec![input]);

    assert_eq!(discovered.counters.manifest_fallbacks.len(), 1);
    assert_eq!(discovered.discovery.manifest_object_fallbacks.len(), 1);
    assert_eq!(discovered.manifests.len(), 1);
    let filtered = &discovered.manifests[0];
    assert_eq!(filtered.surfaces.len(), 1);
    assert_eq!(filtered.surfaces[0].walk, WalkOutcome::Full);
    assert_eq!(filtered.surfaces[0].functions.len(), 67);
    for index in [0, 3] {
        assert!(matches!(
            &filtered.surfaces[0].functions[index].resolution,
            Resolution::UnusableFile { reason, path_hex }
                if reason == "superseded by exact scan fallback" && path_hex.is_empty()
        ));
    }
    for index in [1, 2] {
        assert!(matches!(
            filtered.surfaces[0].functions[index].resolution,
            Resolution::Resolved { object: 1, file_offset } if file_offset == fresh_offset
        ));
    }
    assert_eq!(
        filtered
            .objects
            .iter()
            .map(|object| (object.id, object.path.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (0, provider.to_str().unwrap()),
            (1, fresh.to_str().unwrap())
        ]
    );
    assert_eq!(
        filtered
            .provenance_objects
            .iter()
            .map(|object| object.path.as_str())
            .collect::<Vec<_>>(),
        vec![provider.to_str().unwrap(), fresh.to_str().unwrap()]
    );
    assert_eq!(filtered.alias_groups.len(), 1);
    assert_eq!(filtered.alias_groups[0].object, 1);
    assert_eq!(filtered.alias_groups[0].entries.len(), 2);
    let module_objects = &discovered.discovery.modules[0].objects;
    let sources_for = |path: &Path| {
        let key = object_facts(path).0;
        module_objects
            .iter()
            .find(|object| {
                object.dev == (key.device.major, key.device.minor) && object.ino == key.inode
            })
            .map(|object| object.sources.as_slice())
    };
    assert_eq!(
        sources_for(&provider),
        Some(["scan", "manifest"].as_slice())
    );
    assert_eq!(sources_for(&replaced), Some(["scan"].as_slice()));
    assert_eq!(sources_for(&fresh), Some(["manifest"].as_slice()));
    assert_eq!(
        discovered.plan.entries_seen, 72,
        "62 exact scan/manifest claims count once; distinct claims remain"
    );
    assert_eq!(discovered.plan.surfaces.len(), 2);
    assert_eq!(
        discovered.plan.modules[0]
            .tables
            .iter()
            .map(|table| (table.source, table.entries))
            .collect::<Vec<_>>(),
        vec![("scan", 67), ("manifest", 67)]
    );
    assert_eq!(
        discovered
            .plan
            .skipped
            .iter()
            .filter(|skip| skip.reason == "superseded by exact scan fallback")
            .count(),
        2
    );
}

#[test]
fn discovery_dependency_fallback_rejects_an_unrelated_modules_table() {
    let dir = tempfile::tempdir().unwrap();
    let provider = dir.path().join("provider.so");
    let replaced = dir.path().join("replaced.so");
    let unrelated = dir.path().join("unrelated.so");
    for path in [&provider, &replaced, &unrelated] {
        build_fixture_so(path, FIXTURE_ORIGINAL);
    }
    let paths = vec![provider.clone(), replaced.clone()];
    let mut manifest_targets = vec![0; 67];
    manifest_targets[0] = 1;
    let manifest = valid_manifest_for(&paths, &manifest_targets);

    replace_fixture_with_changed_elf(&replaced);
    let owner_scan = scanned_manifest_replacement(&paths, &vec![0; 67]);
    let unrelated_scan = scanned_manifest_replacement(&[unrelated, replaced], &manifest_targets);
    let modules = vec![owner_scan, unrelated_scan];
    let (pins, skipped) = pin_scanned_objects(
        std::process::id(),
        &modules,
        &mut CaptureWorkBudget::default(),
    )
    .unwrap();
    assert!(skipped.is_empty(), "{skipped:?}");
    let input = manifest_input_from_pinning("unrelated.json", manifest);
    assert_eq!(input.stale.len(), 1);

    let mut discovered = lifecycle_discovered(vec![
        ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
    ]);
    discovered.scan_inputs.insert(
        ProcessViewId(0),
        ScanInput {
            modules,
            pins,
            counters: DiscoveryCounters::default(),
        },
    );
    discovered.manifest_inputs.push(input);

    let error = rebuild_discovered(&mut discovered)
        .expect_err("only the exact manifest module's scan view may replace its dependency");
    assert!(error.to_string().contains("object 1"), "{error:#}");
}

#[test]
fn discovery_fallback_fails_when_the_proof_module_is_refused_at_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let provider = dir.path().join("provider.so");
    let replaced = dir.path().join("replaced.so");
    let unrelated = dir.path().join("unrelated.so");
    for path in [&provider, &replaced, &unrelated] {
        build_fixture_so(path, FIXTURE_ORIGINAL);
    }
    let paths = vec![provider.clone(), replaced.clone()];
    let mut targets = vec![0; 67];
    targets[0] = 1;
    let manifest = valid_manifest_for(&paths, &targets);
    replace_fixture_with_changed_elf(&replaced);

    let mut proof_module = scanned_manifest_replacement(&paths, &targets);
    let (provider_key, _, _) = object_facts(&provider);
    proof_module.tables[0]
        .entries
        .extend(
            (0..p11scope_ebpf_common::MAX_SLOTS).map(|index| ScannedEntry {
                name: "C_Initialize",
                object: provider_key,
                object_path: provider.display().to_string(),
                file_offset: 0x1000_0000 + u64::from(index),
            }),
        );
    let unrelated_module = scanned_manifest_replacement(&[unrelated, replaced], &targets);
    let modules = vec![proof_module, unrelated_module];
    let (pins, skipped) = pin_scanned_objects(
        std::process::id(),
        &modules,
        &mut CaptureWorkBudget::default(),
    )
    .unwrap();
    assert!(skipped.is_empty(), "{skipped:?}");
    let input = manifest_input_from_pinning("capacity-proof.json", manifest);
    let mut discovered = lifecycle_discovered(vec![
        ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
    ]);
    discovered.scan_inputs.insert(
        ProcessViewId(0),
        ScanInput {
            modules,
            pins,
            counters: DiscoveryCounters::default(),
        },
    );
    discovered.manifest_inputs.push(input);

    let error = rebuild_discovered(&mut discovered)
        .expect_err("an unrelated admitted module using the dependency cannot preserve the proof");
    assert!(error.to_string().contains("proof"), "{error:#}");
}

#[test]
fn discovery_fallback_binding_rejects_a_proof_table_lost_during_reconciliation() {
    let dir = tempfile::tempdir().unwrap();
    let provider = dir.path().join("provider.so");
    build_fixture_so(&provider, FIXTURE_ORIGINAL);
    let paths = vec![provider.clone()];
    let targets = vec![0; 67];
    let manifest = valid_manifest_for(&paths, &targets);
    replace_fixture_with_changed_elf(&provider);
    let scan = scanned_manifest_replacement(&paths, &targets);
    let mut pins = pin_scan(&scan);
    let input = manifest_input_from_pinning("reconciliation-loss.json", manifest);
    let proof = scanned_replacement(
        &input.manifest,
        &input.stale[0],
        std::slice::from_ref(&scan),
        &pins,
        &input.pins,
    )
    .expect("the pristine scan table proves the pending fallback");
    let (mut reconciled, _, _) = reconcile_scanned_modules(std::slice::from_ref(&scan), &mut pins);
    reconciled[0].scanned.tables.clear();
    reconciled[0].entry_objects.clear();

    assert!(
        bind_fallback_proof(&proof, &reconciled).is_none(),
        "a candidate locator is not proof after its exact table is gone"
    );
}

#[test]
fn discovery_open_stale_sole_source_is_fatal_after_scan_availability_is_known() {
    let dir = tempfile::tempdir().unwrap();
    let provider = dir.path().join("provider.so");
    std::fs::copy("/bin/sh", &provider).unwrap();
    let manifest = valid_manifest_for(&[provider.clone()], &vec![0; 67]);
    std::fs::remove_file(&provider).unwrap();
    let input = manifest_input_from_pinning("sole-source.json", manifest);
    let mut discovered = lifecycle_discovered(Vec::new());
    discovered.manifest_inputs.push(input);

    let error = rebuild_discovered(&mut discovered).expect_err("no scan replacement is fatal");
    assert!(
        error.to_string().contains("stale manifest object"),
        "{error:#}"
    );
}

#[test]
fn discovery_mixed_manifest_cannot_hide_a_stale_sole_source_object() {
    let dir = tempfile::tempdir().unwrap();
    let provider = dir.path().join("provider.so");
    let replaced = dir.path().join("replaced.so");
    let sole = dir.path().join("sole.so");
    for path in [&provider, &replaced, &sole] {
        build_fixture_so(path, FIXTURE_ORIGINAL);
    }
    let mut targets = vec![0; 67];
    targets[0] = 1;
    targets[1] = 2;
    let manifest = valid_manifest_for(
        &[provider.clone(), replaced.clone(), sole.clone()],
        &targets,
    );
    replace_fixture_with_changed_elf(&replaced);
    std::fs::remove_file(&sole).unwrap();

    let mut scan_targets = targets.clone();
    scan_targets[1] = 0;
    let scan = scanned_manifest_replacement(&[provider, replaced], &scan_targets);
    let scan_pins = pin_scan(&scan);
    let input = manifest_input_from_pinning("mixed.json", manifest);
    assert_eq!(input.stale.len(), 2);
    let mut discovered = lifecycle_discovered(vec![
        ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
    ]);
    discovered.scan_inputs.insert(
        ProcessViewId(0),
        ScanInput {
            modules: vec![scan],
            pins: scan_pins,
            counters: DiscoveryCounters::default(),
        },
    );
    discovered.manifest_inputs.push(input);

    let error = rebuild_discovered(&mut discovered)
        .expect_err("the second stale object has no scanned replacement");
    assert!(error.to_string().contains("object 2"), "{error:#}");
}

#[derive(Debug)]
struct FakeSession(std::rc::Rc<std::cell::RefCell<Vec<&'static str>>>);

impl Drop for FakeSession {
    fn drop(&mut self) {
        self.0.borrow_mut().push("drop");
    }
}

/// Mutation caught: starting before the precheck would attach against a raw,
/// potentially recycled named PID.
#[test]
fn named_generation_change_before_attach_never_starts_a_session() {
    let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let stale = view.id();
    let mut discovered = lifecycle_discovered(vec![view]);
    let starts = Cell::new(0);
    let error = start_retained_with(
        &mut discovered,
        true,
        |_| vec![stale],
        |_, _| {
            starts.set(starts.get() + 1);
            Ok(FakeSession(Default::default()))
        },
    )
    .expect_err("a named generation change is fatal");

    assert!(error.to_string().contains("before attach"), "{error:#}");
    assert_eq!(starts.get(), 0, "no attach action may follow the mismatch");
}

/// Mutation caught: returning the new session before the postcheck would make its
/// ring/maps consumable; failing without dropping it would leave its links live.
#[test]
fn named_generation_change_during_attach_drops_before_event_consumption() {
    let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let stale = view.id();
    let mut discovered = lifecycle_discovered(vec![view]);
    let checks = Cell::new(0);
    let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let error = start_retained_with(
        &mut discovered,
        true,
        |_| {
            checks.set(checks.get() + 1);
            (checks.get() == 2).then_some(stale).into_iter().collect()
        },
        |_, _| {
            log.borrow_mut().push("start");
            Ok(FakeSession(std::rc::Rc::clone(&log)))
        },
    )
    .expect_err("a named generation change is fatal");

    assert!(error.to_string().contains("while attaching"), "{error:#}");
    assert_eq!(*log.borrow(), ["start", "drop"]);
    assert!(!log.borrow().contains(&"consume"));
}

/// Mutation caught: retrying without subtracting an originally accepted stale
/// view can spin forever under cgroup churn. Three accepted views permit only
/// three stale-session retries, followed by the final stable start.
#[test]
fn cgroup_retries_retire_one_original_view_each_time_and_publish_partial() {
    let views: Vec<_> = (0..3)
        .map(|id| ProcessView::open(ProcessViewId(id), std::process::id()).unwrap())
        .collect();
    let original: Vec<_> = views.iter().map(ProcessView::id).collect();
    let mut discovered = lifecycle_discovered(views);
    let checks = Cell::new(0usize);
    let starts = Cell::new(0usize);
    let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let session = start_retained_with(
        &mut discovered,
        false,
        |_| {
            checks.set(checks.get() + 1);
            if checks.get() % 2 == 0 {
                original
                    .get(checks.get() / 2 - 1)
                    .copied()
                    .into_iter()
                    .collect()
            } else {
                Vec::new()
            }
        },
        |_, _| {
            starts.set(starts.get() + 1);
            log.borrow_mut().push("start");
            Ok(FakeSession(std::rc::Rc::clone(&log)))
        },
    )
    .unwrap();

    assert_eq!(starts.get(), original.len() + 1);
    assert!(discovered.views.is_empty());
    assert_eq!(
        discovered
            .counters
            .object_skips
            .iter()
            .filter(|skip| skip.reason == STALE_VIEW_REASON)
            .count(),
        original.len(),
        "each retired accepted view remains accounted internally"
    );
    assert_eq!(
        discovered.plan.skipped.len(),
        1,
        "identical public cgroup losses use the existing bounded deduplication"
    );
    assert!(
        discovered
            .plan
            .skipped
            .iter()
            .map(render::capture_skipped_out)
            .all(|skip| skip.name == "discovery subject" && skip.reason == "discovery unavailable")
    );
    assert_eq!(
        log.borrow()
            .iter()
            .filter(|event| **event == "drop")
            .count(),
        original.len(),
        "every stale post-start pass tears down its whole session"
    );
    drop(session);
}

/// Mutation caught: retaining only the initial `Agreed` outcome drops the
/// manifest's valid offsets when its sole agreeing scan owner is retired.
#[test]
fn stale_sole_owner_agreement_falls_back_to_the_retained_manifest() {
    let (view, modules, pins, input) = same_object_scan_and_manifest(0x40);
    let stale = view.id();
    let mut discovered = discovered_from_inputs(vec![view], modules, pins, vec![input]);
    assert_eq!(discovered.plan.slots.len(), 1);
    assert_eq!(discovered.plan.modules[0].source, "scan+manifest");
    assert!(
        discovered.plan.slots[0].semantic_authorized,
        "an agreed explicit manifest remains an exact plan claim"
    );
    assert_eq!(
        discovered.plan.slots[0].semantics,
        crate::kinds::descriptor("C_Sign").unwrap()
    );
    assert_eq!(discovered.plan.entries_seen, 1);

    remove_stale_views(&mut discovered, &[stale]).unwrap();

    assert_eq!(discovered.plan.slots.len(), 1);
    assert_eq!(discovered.plan.slots[0].names, ["C_Sign"]);
    assert_eq!(discovered.plan.slots[0].file_offset, 0x40);
    assert!(discovered.plan.slots[0].semantic_authorized);
    assert_eq!(discovered.plan.modules[0].source, "manifest");
    assert_eq!(discovered.counters.uncorroborated, 1);
    assert_eq!(discovered.identity_mismatches, 0);
}

/// Mutation caught: a stale path-matching view's mismatch must not remain
/// latched and abort the rebuild after that view's scan slot is subtracted.
#[test]
fn stale_only_identity_mismatch_becomes_manifest_fallback_for_stable_scope() {
    let dir = tempfile::tempdir().unwrap();
    let provider = dir.path().join("provider.so");
    std::fs::copy("/bin/sh", &provider).unwrap();
    let path = provider.display().to_string();
    let own = pin_as_manifest_object(&path);
    let old_sha = own.pinned().next().unwrap().sha256.to_string();
    let manifest = manifest_naming(&path, Some(old_sha));

    let replacement = dir.path().join("replacement.so");
    std::fs::copy("/bin/true", &replacement).unwrap();
    std::fs::rename(&replacement, &provider).unwrap();
    let file = p11scope_manifest::identity::open_object(&provider).unwrap();
    let mapping = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
    let key = ObjectKey {
        device: p11scope_manifest::maps::Device {
            major: mapping.device_major,
            minor: mapping.device_minor,
        },
        inode: mapping.inode,
    };
    let module = ScannedModule {
        view: ProcessViewId(0),
        mount_namespace: current_mount_namespace(),
        key,
        path: path.clone(),
        decoder_abi: Some(ElfAbi::Lp64),
        exports: vec!["C_GetFunctionList".into()],
        tables: vec![ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: vec![ScannedEntry {
                name: "C_Sign",
                object: key,
                object_path: path.clone(),
                file_offset: 0x80,
            }],
            null_entries: vec![],
            unpinned: vec![],
            address: 0x7000,
            file_offset: Some(0),
            live_return: false,
            manifest_supported: false,
        }],
        interfaces: vec![],
    };
    let (scan_pins, skipped) = pin_scanned_objects(
        std::process::id(),
        std::slice::from_ref(&module),
        &mut CaptureWorkBudget::default(),
    )
    .unwrap();
    assert!(skipped.is_empty(), "{skipped:?}");
    let stale = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let stable = ProcessView::open(ProcessViewId(1), std::process::id()).unwrap();
    let stale_id = stale.id();
    let input = ManifestInput {
        path: PathBuf::from("stale-manifest.json"),
        manifest,
        pins: own,
        stale: Vec::new(),
    };
    let mut discovered =
        discovered_from_inputs(vec![stale, stable], vec![module], scan_pins, vec![input]);
    assert_eq!(discovered.identity_mismatches, 1);
    assert_eq!(
        discovered.plan.slots.len(),
        1,
        "the scan initially keeps capture viable"
    );

    remove_stale_views(&mut discovered, &[stale_id]).unwrap();

    assert_eq!(
        discovered.views.len(),
        1,
        "the unrelated stable view remains"
    );
    assert_eq!(discovered.identity_mismatches, 0);
    assert_eq!(discovered.plan.modules[0].source, "manifest");
    assert_eq!(discovered.plan.slots[0].names, ["C_Sign"]);
}

/// Mutation caught: subtracting the only conflicting scan owner must recompute
/// the manifest as uncorroborated instead of preserving stale conflict evidence.
#[test]
fn stale_conflict_owner_is_removed_from_final_counter_and_corroboration() {
    let (view, modules, pins, input) = same_object_scan_and_manifest(0x80);
    let stale = view.id();
    let mut discovered = discovered_from_inputs(vec![view], modules, pins, vec![input]);
    assert_eq!(discovered.counters.conflicts, 1);
    assert_eq!(discovered.plan.slots.len(), 2);

    remove_stale_views(&mut discovered, &[stale]).unwrap();

    assert_eq!(discovered.counters.conflicts, 0);
    assert_eq!(discovered.plan.slots.len(), 1);
    assert_eq!(discovered.plan.modules[0].source, "manifest");
    assert_eq!(
        discovered.discovery.modules[0].corroboration,
        ["uncorroborated"]
    );
}

#[test]
fn repeated_manifest_only_outcomes_preserve_order_and_multiplicity() {
    let (_, pins) = pinned_self();
    let summary = pins.pinned().next().unwrap();
    let path = summary.path.to_string();
    let sha256 = summary.sha256.to_string();
    let input = |name| ManifestInput {
        path: PathBuf::from(name),
        manifest: manifest_naming(&path, Some(sha256.clone())),
        pins: pin_as_manifest_object(&path),
        stale: Vec::new(),
    };
    let mut discovered = lifecycle_discovered(Vec::new());
    discovered.manifest_inputs = vec![input("first.json"), input("second.json")];

    rebuild_discovered(&mut discovered).unwrap();

    assert_eq!(discovered.plan.modules.len(), 1);
    assert_eq!(
        discovered.discovery.modules[0].corroboration,
        ["uncorroborated", "uncorroborated"],
        "one accepted outcome must remain visible for each repeated --manifest input"
    );
}

#[test]
fn repeated_manifest_outcomes_recompute_after_the_scan_owner_is_removed() {
    let (view, modules, pins, input) = same_object_scan_and_manifest(0x40);
    let stale = view.id();
    let mut duplicate = ManifestInput {
        path: PathBuf::from("duplicate-manifest.json"),
        manifest: input.manifest.clone(),
        pins: pin_as_manifest_object(&input.manifest.module_path),
        stale: Vec::new(),
    };
    let Resolution::Resolved { file_offset, .. } =
        &mut duplicate.manifest.surfaces[0].functions[0].resolution
    else {
        unreachable!()
    };
    *file_offset = 0x80;
    let mut discovered = discovered_from_inputs(vec![view], modules, pins, vec![input, duplicate]);

    assert_eq!(
        discovered.discovery.modules[0].corroboration,
        ["agreed", "conflict"],
        "outcomes retain repeated manifest input order"
    );

    remove_stale_views(&mut discovered, &[stale]).unwrap();

    assert_eq!(discovered.plan.modules.len(), 1);
    assert_eq!(
        discovered.discovery.modules[0].corroboration,
        ["uncorroborated", "uncorroborated"],
        "rebuilds must retain each accepted manifest outcome, not synthesize one"
    );
}

#[test]
fn later_manifest_identity_collision_drops_stale_scan_ids_before_planning() {
    let dir = tempfile::tempdir().unwrap();
    let provider = dir.path().join("provider.so");
    let dependency = dir.path().join("dependency.so");
    std::fs::copy("/bin/sh", &provider).unwrap();
    std::fs::copy("/bin/sh", &dependency).unwrap();
    let paths = vec![provider.clone(), dependency.clone()];
    let targets = vec![1; 67];
    let scan = scanned_manifest_replacement(&paths, &targets);
    let dependency_key = scan.tables[0].entries[0].object;
    let scan_pins = pin_scan(&scan);

    // `copy` truncates the existing file: its raw map key remains the same,
    // while its opened pin and hash become incomparable to the scan's pin.
    std::fs::copy("/bin/true", &dependency).unwrap();
    let input =
        manifest_input_from_pinning("later-collision.json", valid_manifest_for(&paths, &targets));
    let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let stale = view.id();
    let mut discovered = lifecycle_discovered(vec![view]);
    discovered.scan_inputs.insert(
        stale,
        ScanInput {
            modules: vec![scan],
            pins: scan_pins,
            counters: DiscoveryCounters::default(),
        },
    );
    discovered.manifest_inputs.push(input);

    rebuild_discovered(&mut discovered).unwrap();

    assert!(
        discovered
            .plan
            .modules
            .iter()
            .all(|module| discovered.pinned.summary(module.object).is_some()),
        "no pre-absorption module ID may reach the final plan"
    );
    assert!(
        discovered
            .plan
            .slots
            .iter()
            .all(|slot| discovered.pinned.summary(slot.object).is_some()),
        "no pre-absorption dependency ID may reach the final plan"
    );
    assert!(
        discovered.plan.slots.iter().all(|slot| {
            discovered
                .pinned
                .summary(slot.object)
                .is_none_or(|summary| summary.key != dependency_key)
        }),
        "the rejected collision group cannot lend its old dependency offsets"
    );
    assert_eq!(
        discovered.discovery.modules[0].corroboration,
        ["conflict"],
        "the surviving exact provider owns the conflict outcome"
    );

    remove_stale_views(&mut discovered, &[stale]).unwrap();
    assert!(
        discovered
            .plan
            .slots
            .iter()
            .all(|slot| discovered.pinned.summary(slot.object).is_some()),
        "a stable-view rebuild resolves fresh final IDs from pristine inputs"
    );
}

#[test]
fn corroboration_marks_the_exact_reconciled_object_not_the_raw_key_peer() {
    let key = ObjectKey {
        device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
        inode: 42,
    };
    let module = |view, object, path: &str, offset| ReconciledModule {
        object,
        entry_objects: vec![vec![object]],
        scanned: ScannedModule {
            view,
            mount_namespace: current_mount_namespace(),
            key,
            path: path.into(),
            decoder_abi: Some(ElfAbi::Lp64),
            exports: vec!["C_GetFunctionList".into()],
            tables: vec![ScannedTable {
                version: (2, 40),
                walk: "full",
                entries: vec![ScannedEntry {
                    name: "C_Sign",
                    object: key,
                    object_path: path.into(),
                    file_offset: offset,
                }],
                null_entries: vec![],
                unpinned: vec![],
                address: 0x7000 + offset,
                file_offset: Some(offset),
                live_return: false,
                manifest_supported: false,
            }],
            interfaces: vec![],
        },
    };
    let first = module(ProcessViewId(0), PinnedObjectId(100), "/first.so", 0x10);
    let second = module(ProcessViewId(0), PinnedObjectId(200), "/second.so", 0x20);
    let mut counters = DiscoveryCounters::default();
    let plan = build_current_plan(
        &[first, second],
        &[],
        &PinnedObjects::empty(),
        &mut counters,
        // The exact final object, not its equal-key peer, owns the outcome.
        &[PinnedObjectId(200)].into_iter().collect(),
        0,
        0,
        false,
    )
    .unwrap();

    let first = plan
        .modules
        .iter()
        .find(|module| module.object == PinnedObjectId(100))
        .unwrap();
    let second = plan
        .modules
        .iter()
        .find(|module| module.object == PinnedObjectId(200))
        .unwrap();
    assert!(!first.corroborated);
    assert_eq!(first.source, "scan");
    assert!(second.corroborated);
    assert_eq!(second.source, "scan+manifest");

    counters
        .corroboration
        .push(([PinnedObjectId(200)].into_iter().collect(), "conflict"));
    assert_eq!(
        corroboration_of(&counters, first),
        ["single_source"],
        "a raw-key peer must not contribute public outcome evidence"
    );
    assert_eq!(
        corroboration_of(&counters, second),
        ["conflict"],
        "the exact reconciled module retains its outcome array"
    );
}

#[test]
fn pending_fallback_outcome_follows_the_final_overlay_canonical_id_without_authority() {
    let key = ObjectKey {
        device: p11scope_manifest::maps::Device {
            major: 0,
            minor: 102,
        },
        inode: 42,
    };
    let module = |view: ProcessViewId, path: &str| ReconciledModule {
        object: PinnedObjectId(200),
        entry_objects: vec![vec![PinnedObjectId(200)]],
        scanned: ScannedModule {
            view,
            mount_namespace: current_mount_namespace(),
            key,
            path: path.into(),
            decoder_abi: Some(ElfAbi::Lp64),
            exports: vec!["C_GetFunctionList".into()],
            tables: vec![ScannedTable {
                version: (2, 40),
                walk: "full",
                entries: vec![ScannedEntry {
                    name: "C_Sign",
                    object: key,
                    object_path: path.into(),
                    file_offset: 0x10,
                }],
                null_entries: vec![],
                unpinned: vec![],
                address: 0x7000,
                file_offset: Some(0),
                live_return: false,
                manifest_supported: false,
            }],
            interfaces: vec![],
        },
    };
    let first = module(ProcessViewId(0), "/overlay/first.so");
    let second = module(ProcessViewId(1), "/overlay/second.so");
    let mut counters = DiscoveryCounters::default();
    let corroborated = bind_pending_corroboration(
        vec![PendingCorroboration {
            owners: vec![OutcomeOwner::Scan(ScanOutcomeLocator::module(
                &second.scanned,
            ))],
            label: "object_fallback",
        }],
        &[first, second],
        &PinnedObjects::empty(),
        &mut counters,
    )
    .unwrap();

    assert!(
        corroborated.is_empty(),
        "a scan-only overlay collapse can bind fallback evidence but never semantic authority"
    );
    assert_eq!(
        counters.corroboration,
        vec![(
            [PinnedObjectId(200)].into_iter().collect(),
            "object_fallback"
        )],
        "the overlay peer's fallback locator binds to its final canonical ID, never a stale pre-remap ID"
    );
}

#[test]
fn pending_corroboration_rebuild_resolves_the_current_final_id() {
    let key = ObjectKey {
        device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
        inode: 42,
    };
    let module = |object| ReconciledModule {
        object,
        entry_objects: vec![vec![object]],
        scanned: ScannedModule {
            view: ProcessViewId(0),
            mount_namespace: current_mount_namespace(),
            key,
            path: "/stable-view.so".into(),
            decoder_abi: Some(ElfAbi::Lp64),
            exports: vec!["C_GetFunctionList".into()],
            tables: vec![ScannedTable {
                version: (2, 40),
                walk: "full",
                entries: vec![ScannedEntry {
                    name: "C_Sign",
                    object: key,
                    object_path: "/stable-view.so".into(),
                    file_offset: 0x10,
                }],
                null_entries: vec![],
                unpinned: vec![],
                address: 0x7000,
                file_offset: Some(0),
                live_return: false,
                manifest_supported: false,
            }],
            interfaces: vec![],
        },
    };
    let first = module(PinnedObjectId(10));
    let owner = OutcomeOwner::Scan(ScanOutcomeLocator::module(&first.scanned));
    let second = module(PinnedObjectId(20));
    let mut counters = DiscoveryCounters::default();
    let corroborated = bind_pending_corroboration(
        vec![PendingCorroboration {
            owners: vec![owner],
            label: "conflict",
        }],
        &[second],
        &PinnedObjects::empty(),
        &mut counters,
    )
    .unwrap();

    assert_eq!(corroborated, [PinnedObjectId(20)].into_iter().collect());
    assert_eq!(
        counters.corroboration,
        vec![([PinnedObjectId(20)].into_iter().collect(), "conflict")],
        "a rebuild cannot retain an earlier capture-local numeric ID"
    );
}

#[test]
fn legacy_manifest_schemas_are_rejected_with_rediscovery_instruction() {
    for schema in [
        "p11scope-manifest/1",
        "p11scope-manifest/2",
        "p11scope-manifest/3",
        "p11scope-manifest/4",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.json");
        std::fs::write(
                &path,
                format!(
                    r#"{{"schema":"{schema}","module_path":"/opt/p.so","objects":[],"interface_list":{{"status":"absent"}},"surfaces":[],"vendor_interfaces":[],"alias_groups":[]}}"#
                ),
            )
            .unwrap();
        let err = read_manifest_file(&path).unwrap_err().to_string();
        assert!(err.contains("rediscover"), "{err}");
    }
}

/// Our own executable, represented by empty scan facts and pinned the way a
/// capture pins a provider: one real `PinnedObjects` key, with no privileges.
fn pinned_self() -> (Vec<ScannedModule>, PinnedObjects) {
    let exe = std::env::current_exe().unwrap();
    let key = object_facts(&exe).0;
    let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let modules = vec![ScannedModule {
        view: view.id(),
        mount_namespace: view.mount_namespace(),
        key,
        path: exe.display().to_string(),
        decoder_abi: Some(if usize::BITS == 64 {
            ElfAbi::Lp64
        } else {
            ElfAbi::Ilp32
        }),
        exports: vec![],
        tables: vec![],
        interfaces: vec![],
    }];
    // Unbounded on purpose: `pin_scanned_object` caps on the whole file size, and
    // this test binary is already past 60% of the 256 MiB default. The byte caps are
    // not what these tests are about, and a silent skip would fail them with
    // "the hinted executable is pinned", which names the symptom, not the cause.
    let limits = ScanLimits {
        per_object_bytes: u64::MAX,
        total_bytes: u64::MAX,
    };
    let mut budget = CaptureWorkBudget::new(limits);
    let (pinned, skipped) = pin_scanned_view_objects(&view, &modules, &mut budget).unwrap();
    assert!(
        skipped.is_empty(),
        "the executable has no pinning loss: {skipped:?}"
    );
    assert_eq!(
        pinned.pinned().count(),
        1,
        "the hinted executable is pinned"
    );
    (modules, pinned)
}

#[test]
fn coordinator_reuses_one_budget_across_process_scans_and_hashes() {
    use std::os::unix::fs::MetadataExt as _;

    let exe = std::env::current_exe().unwrap();
    let inode = std::fs::metadata(&exe).unwrap().ino();
    let maps_bytes = std::fs::read("/proc/self/maps").unwrap();
    let maps = p11scope_manifest::maps::parse_maps(&maps_bytes).unwrap();
    let scan_bytes: u64 = maps
        .iter()
        .filter(|m| m.inode == inode && m.permissions[0] == b'r' && m.permissions[2] != b'x')
        .map(|m| m.end - m.start)
        .sum();
    let hash_bytes = std::fs::metadata(&exe).unwrap().len();
    // The scan path charges only the ELF tables it queries, not the whole file.
    let elf_snapshot_bytes = {
        let file = std::fs::File::open(&exe).unwrap();
        let hooks = HookRegistry::builtin();
        let wanted = hooks.names();
        let tables = p11scope_manifest::elf::read_export_facts(&file, &wanted)
            .unwrap()
            .2;
        assert!(
            tables < hash_bytes,
            "the tables must cost less than the {hash_bytes}-byte executable: {tables}"
        );
        tables
    };
    // Both complete maps snapshots belong to each scan operation.
    let scan_pass = maps_bytes.len() as u64 * 2 + scan_bytes;
    // The ELF snapshot is read once per capture: the second scan reuses the first
    // scan's cached export facts, so only one copy is budgeted here.
    let mut budget = CaptureWorkBudget::new(ScanLimits {
        per_object_bytes: scan_bytes.max(hash_bytes),
        total_bytes: scan_pass * 2 + elf_snapshot_bytes + hash_bytes,
    });
    let hints = vec![exe];
    let hooks = HookRegistry::builtin();
    let mut counters = DiscoveryCounters::default();
    let first_view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let (_, first) = scan_and_pin(
        &first_view,
        &hints,
        &hooks,
        &mut budget,
        &mut counters,
        false,
    )
    .unwrap();
    let second_view = ProcessView::open(ProcessViewId(1), std::process::id()).unwrap();
    let (_, second) = scan_and_pin(
        &second_view,
        &hints,
        &hooks,
        &mut budget,
        &mut counters,
        false,
    )
    .unwrap();
    assert_eq!(first.pinned().count(), 1);
    assert_eq!(
        second.pinned().count(),
        0,
        "the later scan cannot renew bytes"
    );
    assert!(
        counters
            .object_skips
            .iter()
            .any(|skip| skip.reason.contains("capture attempted-I/O ceiling")),
        "budget exhaustion must remain explicit: {:?}",
        counters.object_skips
    );
}

/// The pin `pin_manifest_objects` produces for one manifest object: filed under
/// the path the manifest names (`ObjectRecord.path`, which it opens), keyed by the
/// identity that path resolves to right now.
fn pin_as_manifest_object(object_path: &str) -> PinnedObjects {
    let file = p11scope_manifest::identity::open_object(Path::new(object_path)).unwrap();
    let found = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
    let identity = p11scope_manifest::identity::inspect_file(&file)
        .unwrap()
        .identity;
    let mut manifest = manifest_naming(object_path, identity.sha256.clone());
    manifest.objects[0].identity = identity.clone();
    manifest.provenance_objects[0] = p11scope_manifest::manifest::ProvenanceObject {
        path: object_path.to_string(),
        device_major: found.device_major,
        device_minor: found.device_minor,
        inode: found.inode,
        identity,
    };
    manifest.surfaces[0].acquisition = p11scope_manifest::manifest::Acquisition::Absent;
    manifest.surfaces[0].walk = p11scope_manifest::manifest::WalkOutcome::NotWalked;
    manifest.surfaces[0].functions.clear();
    pin_manifest_objects(&manifest).unwrap()
}

fn entry(name: &'static str, object: ObjectKey, file_offset: u64) -> ScannedEntry {
    ScannedEntry {
        name,
        object,
        object_path: format!("/opt/{}.so", object.inode),
        file_offset,
    }
}

/// An entry whose object could not be pinned has no attach path of its own. Left
/// in the plan it either kills the whole capture (§4.10 says one unusable
/// dependency must not) or, once a manifest is in the same plan, falls back to
/// the *observer's* file at the target's pathname — a different file, silently
/// probed at scan-derived offsets.
#[test]
fn a_table_entry_whose_object_was_not_pinned_never_becomes_a_slot() {
    let (mut modules, mut pinned) = pinned_self();
    let pinned_key = pinned.pinned().next().unwrap().key;
    let unpinned_key = ObjectKey {
        device: p11scope_manifest::maps::Device {
            major: 0xffff,
            minor: 0xffff,
        },
        inode: u64::MAX,
    };
    modules[0]
        .tables
        .push(crate::discovery::scan::ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: vec![
                entry("C_Sign", pinned_key, 0x10),
                entry("C_Verify", unpinned_key, 0x20),
            ],
            null_entries: vec![],
            unpinned: vec![],
            address: 0x7000,
            file_offset: Some(0),
            live_return: false,
            manifest_supported: false,
        });
    modules[0].tables.last_mut().unwrap().entries[0].object_path = modules[0].path.clone();

    let (reconciled, _, dropped) = reconcile_scanned_modules(&modules, &mut pinned);
    assert_eq!(dropped.len(), 1, "{dropped:?}");
    assert_eq!(dropped[0].subject, "C_Verify");
    assert!(
        dropped[0]
            .reason
            .contains("could not be reconciled to a comparable pinned object"),
        "{dropped:?}"
    );

    let plan = plan::build_from_reconciled_modules(&reconciled);
    assert_eq!(plan.slots.len(), 1, "only the pinned target attaches");
    for slot in &plan.slots {
        assert!(
            pinned.attach_path_for(slot.object).is_ok(),
            "every scanned slot must have a pinned object of its own: {slot:?}"
        );
    }
    // A record the scan decoded and could not use is still a record it saw:
    // dropping it from `entries_seen` would make `slots` vs `table_entries`
    // read as "everything seen was attached". It is reported as a skip too,
    // the same way a NULL entry is, and attributed to its own module.
    assert_eq!(plan.entries_seen, 2, "the dropped entry stays counted");
    assert_eq!(plan.skipped.len(), 1, "{:?}", plan.skipped);
    // Task 1.3: reconciliation keeps the ordinal label internally (above),
    // but the plan presents the unlinked table's entry as `unknown`.
    assert_eq!(plan.skipped[0].subject, "unknown");
    assert_eq!(plan.modules[0].skipped, plan.skipped);
    // The reason the drop is recorded on the table rather than added to the
    // total afterwards: per-surface counts and the total stay one number.
    assert_eq!(
        plan.surfaces.iter().map(|s| s.functions).sum::<usize>(),
        plan.entries_seen,
        "every record counted in table_entries belongs to a surface"
    );
}

#[test]
fn an_unpinned_entry_skip_is_bounded_in_every_capture_output() {
    let raw = Skipped {
        subject: "C_Sign".into(),
        reason: "/private/ROUND4_OBJECT_PATH_SENTINEL.so was not pinned: \
                     ROUND4_ERROR_CHAIN_SENTINEL"
            .into(),
    };
    let (mut modules, mut pinned) = pinned_self();
    modules[0]
        .tables
        .push(crate::discovery::scan::ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: vec![],
            null_entries: vec![],
            unpinned: vec![raw.clone()],
            address: 0x7000,
            file_offset: Some(0),
            live_return: false,
            manifest_supported: false,
        });
    let reconciled = reconcile_for_test(&modules, &mut pinned);
    let plan = plan::build_from_reconciled_modules(&reconciled);
    // Task 1.3: the injected table is unlinked, so its ordinal subject is
    // gated to `unknown` at plan lowering; the bounded reason is unchanged.
    let gated = Skipped {
        subject: "unknown".into(),
        reason: raw.reason.clone(),
    };
    assert_eq!(plan.skipped, vec![gated.clone()]);
    assert_eq!(plan.modules[0].skipped, vec![gated]);

    let discovery = discovery_evidence(&plan, &pinned, &DiscoveryCounters::default());
    let mut evidence = render::Evidence {
        table_entries: plan.entries_seen,
        slots: plan.slots.len(),
        active_slots: plan
            .slots
            .iter()
            .filter(|slot| plan.is_active(slot.index))
            .count(),
        attached_probes: 0,
        attach_failures: vec![],
        aliased: vec![],
        skipped: plan
            .skipped
            .iter()
            .map(render::capture_skipped_out)
            .collect(),
        semantic_unverified_slots: 0,
        in_flight_at_end: 0,
        surfaces: plan.surfaces.clone(),
        vendor_interfaces: 0,
        interface_list: "absent".into(),
        event_loss: 0,
        start_insert_failures: 0,
        unmatched_returns: 0,
        rv_update_failures: 0,
        abi_refusals: 0,
        cgroup_scope_failures: 0,
        semantic_capture_failures: 0,
        unregistered_mechanisms: 0,
        template_tail_failures: 0,
        process_tracking_fallbacks: 0,
        process_tracking_failures: 0,
        process_tracking_evictions: 0,
        state_reconciliations: 0,
        session_cancel_ambiguities: 0,
        session_cancel_unknown_flags: 0,
        operation_state_imports: 0,
        auth_state_ambiguities: 0,
        async_target_failures: 0,
        async_orphans: 0,
        async_duplicates: 0,
        async_evictions: 0,
        fork_state_ambiguities: 0,
        semantic_state_drops: 0,
        semantic_history_drops: 0,
        pending_at_end: 0,
        malformed_records: 0,
        orphan_ops: 0,
        unmatched_closes: 0,
        shape_decode_failures: 0,
        shape_decode_total_failures: 0,
        templates_truncated: false,
        attach_gap_ms: None,
        pause: "none",
        pause_attempts: 0,
        pause_confirmed: 0,
        pause_partial: 0,
        child_still_running: None,
        discovery_ring_loss: 0,
        discovery_state_failures: 0,
        discovery_read_failures: 0,
        discovery_truncated: 0,
        task_uprobe_link_losses: 0,
        loader_discovery: render::LoaderDiscovery::default(),
        interface_selection: render::InterfaceSelection::default(),
        attach_mechanisms: vec![],
        pid_descendant_gaps: 0,
        multi_rebuild_gaps: 0,
        unprotected_live_windows: 0,
        module_unresolved_slots: 0,
        provider_changed: false,
        discovery,
        scheduling: render::SchedulingEvidence::default(),
        drain_proven: false,
        verdict_detail: render::VERDICT_CONCRETE_GAP,
        uretprobe_override: None,
        handoff_child_pid: None,
        p11scope_env: vec![],
        completeness: "UNKNOWN",
    };
    evidence.verdict();
    let profile_capture = render::CaptureMeta {
        started: "t0",
        ended: "t1",
        kernel: "test",
        policy: CapturePolicy::Allowlisted,
        scope: "pid",
        ring_bytes: p11scope_ebpf_common::RING_BYTES,
        drain_interval_ms: 1000,
    };
    let state = semantics::State::with_policy(&plan, CapturePolicy::Allowlisted);
    let profile = render::profile_json(
        &[],
        render::VersionedEvidence::wrap(&evidence),
        &state,
        &profile_capture,
    );
    let metrics_capture = render::CaptureMeta {
        policy: CapturePolicy::AggregateOnly,
        ..profile_capture
    };
    let metrics = render::json(&[], &evidence, &metrics_capture);
    let trace = trace::evidence_line(&evidence, CapturePolicy::Allowlisted, false);

    for rendered in [
        serde_json::to_string(&profile).unwrap(),
        serde_json::to_string(&metrics).unwrap(),
        trace,
    ] {
        for sentinel in ["ROUND4_OBJECT_PATH_SENTINEL", "ROUND4_ERROR_CHAIN_SENTINEL"] {
            assert!(
                !rendered.contains(sentinel),
                "leaked {sentinel}: {rendered}"
            );
        }
    }
    for document in [profile, metrics] {
        assert_eq!(document["evidence"]["completeness"], "PARTIAL");
        assert_eq!(document["evidence"]["skipped"].as_array().unwrap().len(), 1);
        assert_eq!(
            document["evidence"]["discovery"][0]["skipped"],
            document["evidence"]["skipped"]
        );
        assert_eq!(
            document["evidence"]["skipped"][0],
            serde_json::json!({
                "name": "discovery subject",
                "reason": "discovery unavailable",
            })
        );
    }
}

/// An object the scan could not identify at all is the loss `discovery[]` cannot
/// show: the module it belonged to contributes no table, so it produces no
/// entry to skip, no attach to fail and no counter to raise. Printed and
/// dropped, it leaves a document whose every field says the capture was
/// clean while a provider went unobserved.
fn p2_refuse_then_exit(
    counters: &mut DiscoveryCounters,
) -> Result<(Vec<ScannedModule>, PinnedObjects, bool)> {
    let mut child = std::process::Command::new("/bin/cat")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let view = ProcessView::open(ProcessViewId(711), child.id()).unwrap();
    let result = scan_and_pin_with(
        &view,
        &[],
        &HookRegistry::builtin(),
        &mut CaptureWorkBudget::default(),
        counters,
        false,
        |_, view, budget| {
            let outcome = crate::discovery::scan::bracket_refusal_for_test(view, budget);
            assert!(outcome.modules().is_empty());
            assert!(
                outcome
                    .skipped()
                    .iter()
                    .any(|skip| skip.reason == crate::discovery::scan::MAPPING_CHANGED_REASON)
            );
            drop(child.stdin.take());
            assert!(child.wait().unwrap().success());
            assert_eq!(view.original_exited(), Ok(true));
            Ok(outcome)
        },
    );
    assert!(
        result
            .as_ref()
            .unwrap_err()
            .to_string()
            .contains("pinning process view")
    );
    result
}

#[test]
fn p2_refusal_occurrences_survive_history_and_sanitized_duplicates() {
    let (result, mut counters) = Engine::scan_retained_view_with(p2_refuse_then_exit);
    assert!(result.is_err());
    let mut distinct = counters.object_skips[0].clone();
    distinct.reason = "memory scan refused: final mapping validation unavailable".into();
    counters.object_skips.push(distinct);
    assert_eq!(counters.object_skips.len(), 2);
    let mut facts = CaptureFacts::default();
    let mut plan = plan::build_from_reconciled_modules(&[]);
    facts
        .merge_current(&plan, &PinnedObjects::empty(), &[], &[], &[], &counters)
        .unwrap();
    facts
        .merge_current(
            &plan,
            &PinnedObjects::empty(),
            &[],
            &[],
            &[],
            &DiscoveryCounters::default(),
        )
        .unwrap();
    facts.apply_to_plan(&mut plan);
    assert_eq!(
        plan.skipped.len(),
        2,
        "retirement must retain both distinct acquisition losses"
    );
    let public: Vec<_> = plan
        .skipped
        .iter()
        .map(render::capture_skipped_out)
        .collect();
    assert_eq!(
        serde_json::to_value(public).unwrap(),
        serde_json::json!([
            {"name":"discovery subject","reason":"discovery unavailable"},
            {"name":"discovery subject","reason":"discovery unavailable"}
        ])
    );
}

#[test]
fn p2_absorbed_refusal_survives_later_inventory_failure() {
    let (result, counters) = Engine::scan_retained_view_with(p2_refuse_then_exit);
    assert!(result.is_err());
    let expected = counters.object_skips[0].clone();
    let mut engine = Engine::empty();
    let pending_skips = engine.absorb_scan_counters(counters);
    assert!(pending_skips.contains(&expected));
    // Subsequent candidate construction may fail; publishing retained
    // capture facts must still include the already incurred acquisition loss.
    engine.publish_current_capture_facts().unwrap();
    assert!(
        engine.plan.skipped.contains(&expected),
        "absorbed acquisition loss depended on candidate success"
    );
}

#[test]
fn p2_refusal_saved_before_pinning_failure() {
    let mut counters = DiscoveryCounters::default();
    assert!(p2_refuse_then_exit(&mut counters).is_err());
    assert!(
        counters
            .object_skips
            .iter()
            .any(|skip| skip.reason == crate::discovery::scan::MAPPING_CHANGED_REASON),
        "pinning error lost bracket refusal: {:?}",
        counters.object_skips
    );
}

#[test]
fn p2_retained_scan_error_keeps_counters_and_survives_attachment() {
    let (result, counters) = Engine::scan_retained_view_with(p2_refuse_then_exit);
    assert!(result.is_err());
    let refusal = counters
        .object_skips
        .iter()
        .find(|skip| skip.reason == crate::discovery::scan::MAPPING_CHANGED_REASON)
        .expect("retained scan error discarded bracket refusal")
        .clone();
    // Normal-exit bookkeeping suppresses only the generic unreadable member.
    let mut noise = crate::discovery::noise::DiscoveryNoiseAggregator::default();
    assert!(unreadable_member_skip(711, true, "pin failure", &mut noise).is_none());
    for source in ["manifest", "scan"] {
        let mut plan = plan_with(1, 0);
        plan.modules[0].path = refusal.subject.clone();
        plan.modules[0].source = source;
        plan.modules[0].tables.push(plan::TableSummary {
            version: (2, 40),
            entries: 68,
            source,
            file_offset: None,
            linkage: if source == "manifest" {
                "manifest"
            } else {
                "heuristic"
            },
        });
        record_object_skips(&mut plan, std::slice::from_ref(&refusal));
        record_object_skips(&mut plan, &[]);
        assert_eq!(
            plan.skipped,
            [refusal.clone()],
            "later {source} erased acquisition loss"
        );
        let public = render::capture_skipped_out(&plan.skipped[0]);
        assert_eq!(
            serde_json::to_value(public).unwrap(),
            serde_json::json!({"name":"discovery subject","reason":"discovery unavailable"})
        );
    }
}

#[test]
fn an_object_the_scan_could_not_read_is_published_not_only_printed() {
    let (modules, _) = pinned_self();
    // Refuse before the first mount-table read while leaving the per-object
    // allowance generous: this specifically exercises capture-wide admission.
    let tiny = ScanLimits {
        per_object_bytes: ScanLimits::default().per_object_bytes,
        total_bytes: 0,
    };
    let (mut pinned, skips) = pin_scanned_objects(
        std::process::id(),
        &modules,
        &mut CaptureWorkBudget::new(tiny),
    )
    .unwrap();
    assert_eq!(pinned.pinned().count(), 0, "nothing could be pinned");
    let expected = Skipped {
        subject: modules[0].path.clone(),
        reason: format!(
            "cannot read pid {}'s mount table: {IO_CEILING_REASON}",
            std::process::id()
        ),
    };
    assert_eq!(skips, [expected.clone()], "the scan reports the exact loss");

    let (reconciled, _, _) = reconcile_scanned_modules(&modules, &mut pinned);
    let mut plan = plan::build_from_reconciled_modules(&reconciled);
    assert!(
        plan.skipped.is_empty(),
        "the module published no table, so nothing else records the loss: {:?}",
        plan.skipped
    );

    record_object_skips(&mut plan, &skips);
    assert_eq!(
        plan.skipped, skips,
        "the actual skip is transferred exactly"
    );

    // A cgroup scans many processes mapping the same provider; one loss is
    // one line however many processes hit it — and two *different* losses
    // are still two, which a dedupe that collapsed by subject would lose.
    let other = Skipped {
        subject: skips[0].subject.clone(),
        reason: "a second, different loss of the same object".into(),
    };
    let mixed: Vec<Skipped> = skips
        .iter()
        .chain(skips.iter())
        .cloned()
        .chain([other.clone()])
        .collect();
    let mut plan = plan::build_from_reconciled_modules(&reconciled);
    record_object_skips(&mut plan, &mixed);
    assert_eq!(plan.skipped, [expected, other]);
}

fn plan_with(slots: usize, refused: usize) -> plan::AttachPlan {
    let mut plan = plan::AttachPlan::from_slots(
        (0..slots)
            .map(|index| plan::Slot {
                index: index as u32,
                descriptor_index: 0,
                object: PinnedObjectId(42),
                object_path: "/opt/p11.so".into(),
                file_offset: index as u64 * 8,
                names: vec!["C_Sign".into()],
                aliased: false,
                semantics: p11scope_ebpf_common::SlotSemantics::COUNT_ONLY,
                semantic_authorized: true,
                semantic_ambiguous: false,
                fork_safe: false,
                module_ids: vec![plan::ModuleId(0)],
            })
            .collect(),
    );
    plan.modules = vec![plan::ModuleSummary {
        id: plan::ModuleId(0),
        object: PinnedObjectId(42),
        key: ObjectKey {
            device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
            inode: 42,
        },
        path: "/opt/p11.so".into(),
        tables: vec![],
        interfaces: 0,
        source: "scan",
        corroborated: false,
        skipped: vec![],
    }];
    plan.modules_skipped = (0..refused)
        .map(|i| Skipped {
            subject: format!("/opt/big{i}.so"),
            reason: "module needs 600 more of the 512 attach slots".into(),
        })
        .collect();
    plan.entries_seen = slots;
    plan
}

fn plan_with_pins(slots: usize, refused: usize) -> (plan::AttachPlan, PinnedObjects) {
    let (_, pins) = pinned_self();
    let pin = pins.pinned().next().unwrap();
    let mut plan = plan_with(slots, refused);
    for slot in &mut plan.slots {
        slot.object = pin.id;
        slot.object_path = pin.path.to_string();
    }
    plan.modules[0].object = pin.id;
    plan.modules[0].key = pin.key;
    plan.modules[0].path = pin.path.to_string();
    (plan, pins)
}

/// One provider over the slot ceiling must not cost the capture the other
/// providers could still have shared: the refusal is evidence (and forces
/// PARTIAL), not an abort. It stays an error only when nothing is left.
#[test]
fn a_partial_capacity_refusal_is_reported_and_only_an_empty_one_is_fatal() {
    assert_eq!(refusal_error(&plan_with(4, 0)), None, "nothing refused");
    assert_eq!(
        refusal_error(&plan_with(4, 1)),
        None,
        "one refused module must not lose the four slots that fit"
    );
    assert_eq!(refusal_error(&plan_with(0, 0)), None, "§4.10: not an error");
    let error = refusal_error(&plan_with(0, 1)).expect("a refusal with nothing left is fatal");
    assert!(error.contains("nothing to attach"), "{error}");
    assert!(error.contains("/opt/big0.so"), "{error}");

    // …and the refusal reaches evidence, which is what makes reporting it
    // instead of aborting honest: `render::Evidence::verdict` turns a
    // non-empty `modules_skipped` into PARTIAL (see `render`'s own tests).
    let (plan, pins) = plan_with_pins(4, 1);
    let evidence = discovery_evidence(&plan, &pins, &DiscoveryCounters::default());
    assert_eq!(evidence.modules_skipped.len(), 1);
    assert_eq!(evidence.modules_skipped[0].name, "/opt/big0.so");
    assert!(
        evidence.modules_skipped[0].reason.contains("attach slots"),
        "{:?}",
        evidence.modules_skipped[0]
    );
}

/// A manifest ignored as stale is the one §4.12 outcome with no module of
/// its own in the plan — and the one most likely to be covering a provider
/// the scan cannot read, which is then observed by nobody.
#[test]
fn an_ignored_stale_manifest_is_counted_as_uncorroborated() {
    let mut plan = plan_with(1, 0);
    assert_eq!(
        uncorroborated_count(&plan, 0, 0),
        0,
        "a scanned module is not"
    );
    assert_eq!(
        uncorroborated_count(&plan, 1, 0),
        1,
        "an ignored manifest must reach a counter, or it reaches none"
    );
    plan.modules[0].source = "manifest";
    assert_eq!(uncorroborated_count(&plan, 1, 0), 2, "both are counted");
    plan.modules[0].corroborated = true;
    assert_eq!(uncorroborated_count(&plan, 0, 0), 0);
    assert_eq!(uncorroborated_count(&plan, 0, 1), 1);
}

/// Both §4.12 outcomes that attach a union mark the module corroborated, so
/// without the outcome itself an agreement and a conflict are the same
/// record — and `discovery_conflicts` would have nothing explaining it.
#[test]
fn the_module_record_says_which_corroboration_outcome_it_got() {
    let (plan, pins) = plan_with_pins(1, 0);
    let object = plan.modules[0].object;
    for (outcome, label) in [
        (Corroboration::Agreed, "agreed"),
        (Corroboration::Conflict, "conflict"),
        (Corroboration::ScanEmpty, "scan_empty"),
        (Corroboration::IdentityMismatch, "identity_mismatch"),
    ] {
        let counters = DiscoveryCounters {
            corroboration: vec![([object].into_iter().collect(), corroboration_label(outcome))],
            ..DiscoveryCounters::default()
        };
        let evidence = discovery_evidence(&plan, &pins, &counters);
        assert_eq!(evidence.modules[0].corroboration, vec![label]);
    }
    // Nothing recorded: one source described it, and the record says so
    // rather than implying a second source failed to.
    let evidence = discovery_evidence(&plan, &pins, &DiscoveryCounters::default());
    assert_eq!(evidence.modules[0].corroboration, vec!["single_source"]);
    assert_eq!(evidence.modules[0].sources, vec!["scan"]);
}

#[test]
fn late_collision_invalidates_fallback_evidence_without_discovery_evidence_panic() {
    let (plan, pins) = plan_with_pins(1, 0);
    let mut counters = DiscoveryCounters::default();
    counters.manifest_fallbacks.push(ManifestFallback {
        manifest: 0,
        object: 0,
        reason: ManifestStaleReason::IdentityMismatch,
        replacement: PinnedObjectId(u32::MAX),
        proof: BoundFallbackProof {
            module: PinnedObjectId(u32::MAX),
            tables: vec![],
            required_targets: BTreeMap::new(),
        },
    });

    let evidence = discovery_evidence(&plan, &pins, &counters);

    assert!(
        evidence.manifest_object_fallbacks.is_empty(),
        "a fallback whose exact replacement was rejected must not survive"
    );
}

/// A manifest records the `{device, inode}` its provider had on the host it was
/// made on. Inode reuse after a rebuild is enough for that pair to collide with a
/// *live* pin of an unrelated file — and the by-key lookup in `Session::start` is
/// consulted first, so the collision wins and the manifest's offsets are applied
/// to the wrong file. The mirror of the unpinned-entry hazard above.
#[test]
fn a_stale_recorded_identity_never_resolves_to_another_objects_pin() {
    let (_, mut pins) = pinned_self();
    let collision = pins.pinned().next().unwrap().key;

    // A second, unrelated file.
    let dir = tempfile::tempdir().unwrap();
    let provider = dir.path().join("provider.so");
    std::fs::copy("/bin/sh", &provider).unwrap();
    let path = provider.display().to_string();
    let own = pin_as_manifest_object(&path);

    let mut m = manifest_naming(&path, Some("11".repeat(32)));
    // The stale pair, here colliding with the live pin of a different file.
    m.provenance_objects[0].device_major = collision.device.major;
    m.provenance_objects[0].device_minor = collision.device.minor;
    m.provenance_objects[0].inode = collision.inode;

    retarget_to_pins(&mut m, &[], &pins, &own);
    pins.absorb(own);

    let plan = plan::build_from_sources(&[], std::slice::from_ref(&m), &pins);
    let attach = pins.attach_path_for(plan.slots[0].object).unwrap();
    assert_eq!(
        std::fs::metadata(&attach).unwrap().ino(),
        std::fs::metadata(&provider).unwrap().ino(),
        "a manifest slot must attach into its own object, never into whatever \
             live pin happens to share the identity it recorded"
    );
}

/// `p11scope-discover` writes `objects[].path` as the `--module` argument was
/// spelled and `provenance_objects[].path` as `/proc/self/maps` renders it — the
/// resolved target. Any provider named through a symlink (`libykcs11.so` →
/// `.so.2.x`, usrmerge `/lib` → `/usr/lib`) therefore has two different pathnames
/// in one manifest, and a retarget that looked the pin up by the provenance path
/// would find none: the recorded pair would survive into the plan, which either
/// resolves to an unrelated file that shares it or fails to resolve at all.
#[test]
fn a_manifest_naming_its_object_and_its_provenance_differently_is_still_retargeted() {
    let (_, mut pins) = pinned_self();
    let collision = pins.pinned().next().unwrap().key;

    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("provider.so.2.4");
    std::fs::copy("/bin/sh", &real).unwrap();
    let link = dir.path().join("provider.so");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let (link_path, real_path) = (link.display().to_string(), real.display().to_string());

    let own = pin_as_manifest_object(&link_path);
    pins.absorb(pin_as_manifest_object(&link_path));

    // A pair nothing pins (a manifest reused after a rebuild — the case pinning
    // exists to support), then one colliding with a live pin of another file.
    for recorded in [
        ObjectKey {
            device: p11scope_manifest::maps::Device {
                major: 0xffff,
                minor: 0xffff,
            },
            inode: u64::MAX,
        },
        collision,
    ] {
        let mut m = manifest_naming(&link_path, Some("11".repeat(32)));
        m.provenance_objects[0].path = real_path.clone();
        m.provenance_objects[0].device_major = recorded.device.major;
        m.provenance_objects[0].device_minor = recorded.device.minor;
        m.provenance_objects[0].inode = recorded.inode;

        retarget_to_pins(&mut m, &[], &pins, &own);

        let plan = plan::build_from_sources(&[], std::slice::from_ref(&m), &pins);
        let attach = pins.attach_path_for(plan.slots[0].object).expect(
            "a manifest whose recorded identity is not the live one must still \
                 resolve — that reuse is what pinning by build-id and sha256 is for",
        );
        assert_eq!(
            std::fs::metadata(&attach).unwrap().ino(),
            std::fs::metadata(&real).unwrap().ino(),
            "recorded {recorded:?} must not decide what gets attached"
        );
    }
}

/// The glue that picks among the four §4.12 outcomes: which scanned module a
/// manifest is talking about, and whether the bytes agree.
#[test]
fn scan_view_matches_by_hash_then_path_and_needs_a_pin() {
    let (modules, pinned) = pinned_self();
    let summary = pinned.pinned().next().unwrap();
    let (path, sha) = (summary.path.to_string(), summary.sha256.to_string());

    let m = manifest_naming(&path, Some(sha.clone()));
    let own = pin_as_manifest_object(&path);
    let view = scan_view(&m, &modules, &pinned, &own).expect("mapped and pinned");
    assert_eq!(view.modules[0].key, summary.key);
    assert!(view.agrees, "the recorded sha256 is the pinned one");
    let manifest_target = manifest_targets(&m, &own).unwrap();
    assert_eq!(manifest_target.len(), 1);
    let (manifest_target, manifest_offset) = manifest_target.iter().next().unwrap();
    assert_eq!(*manifest_offset, 0x40);
    assert_eq!(
        own.summary(*manifest_target).unwrap().path,
        path,
        "manifest targets resolve through their exact opened pin"
    );
    assert_eq!(
        scanned_targets(&view.modules, &pinned),
        Some(BTreeSet::new()),
        "our own executable publishes no PKCS#11 table"
    );

    // Same path, different bytes: §4.12's identity mismatch.
    let stale = manifest_naming(&path, Some("22".repeat(32)));
    assert_eq!(
        scan_view(&stale, &modules, &pinned, &own).map(|view| view.agrees),
        Some(false)
    );

    // Mapped but never pinned: nothing to compare against, so nothing corroborates
    // it — the trigger condition for the unpinned-slot bug above.
    let unpinned = manifest_naming(&path, Some(sha));
    assert!(
        scan_view(&unpinned, &modules, &PinnedObjects::empty(), &own).is_none(),
        "a module with no pin has no hash to agree or disagree with"
    );

    // A manifest for something the target does not map at all.
    let elsewhere = manifest_naming("/opt/not-mapped.so", Some("33".repeat(32)));
    assert!(scan_view(&elsewhere, &modules, &pinned, &PinnedObjects::empty()).is_none());
}

#[test]
fn scan_view_does_not_choose_the_first_byte_identical_ordinary_file() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first.so");
    let intended = dir.path().join("intended.so");
    std::fs::copy("/bin/sh", &first).unwrap();
    std::fs::copy("/bin/sh", &intended).unwrap();
    let as_module = |path: &Path| {
        let file = p11scope_manifest::identity::open_object(path).unwrap();
        let key = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
        ScannedModule {
            view: ProcessViewId(0),
            mount_namespace: current_mount_namespace(),
            key: ObjectKey {
                device: p11scope_manifest::maps::Device {
                    major: key.device_major,
                    minor: key.device_minor,
                },
                inode: key.inode,
            },
            path: path.display().to_string(),
            decoder_abi: None,
            exports: vec![],
            tables: vec![],
            interfaces: vec![],
        }
    };
    let modules = vec![as_module(&first), as_module(&intended)];
    let (pinned, skipped) = pin_scanned_objects(
        std::process::id(),
        &modules,
        &mut CaptureWorkBudget::default(),
    )
    .unwrap();
    assert!(skipped.is_empty(), "{skipped:?}");
    let intended_sha = pinned
        .pinned()
        .find(|pin| pin.key == modules[1].key)
        .unwrap()
        .sha256
        .to_string();
    let intended_path = intended.display().to_string();
    let manifest = manifest_naming(&intended_path, Some(intended_sha));
    let own = pin_as_manifest_object(&intended_path);

    let view = scan_view(&manifest, &modules, &pinned, &own).expect("mapped object");
    assert!(view.agrees);
    assert_eq!(
        view.modules[0].path, modules[1].path,
        "digest equality selected the first distinct ordinary file"
    );
}

#[test]
fn byte_identical_distinct_entry_objects_conflict_and_attach_the_union() {
    use crate::discovery::scan::ScannedTable;
    use p11scope_manifest::manifest::{
        Acquisition, FunctionRecord, ObjectRecord, ProvenanceObject, SurfaceRecord, SurfaceSource,
        Version, WalkOutcome,
    };

    let dir = tempfile::tempdir().unwrap();
    let module_path = dir.path().join("module.so");
    let scanned_target_path = dir.path().join("scanned-target.so");
    let manifest_target_path = dir.path().join("manifest-target.so");
    for path in [&module_path, &scanned_target_path, &manifest_target_path] {
        std::fs::copy("/bin/sh", path).unwrap();
    }

    let opened = |path: &Path| {
        let file = p11scope_manifest::identity::open_object(path).unwrap();
        let mapping = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
        let inspected = p11scope_manifest::identity::inspect_file(&file).unwrap();
        (mapping, inspected)
    };
    let (module_mapping, module_inspected) = opened(&module_path);
    let (scanned_mapping, scanned_inspected) = opened(&scanned_target_path);
    let (manifest_mapping, manifest_inspected) = opened(&manifest_target_path);
    assert_eq!(
        scanned_inspected.identity.sha256, manifest_inspected.identity.sha256,
        "the witness requires equal bytes"
    );
    assert_ne!(
        scanned_mapping.inode, manifest_mapping.inode,
        "the witness requires distinct opened objects"
    );
    let offset = scanned_inspected.executable_ranges[0].0;
    let key = |mapping: p11scope_manifest::identity::MappingFileKey| ObjectKey {
        device: p11scope_manifest::maps::Device {
            major: mapping.device_major,
            minor: mapping.device_minor,
        },
        inode: mapping.inode,
    };
    let module = ScannedModule {
        view: ProcessViewId(0),
        mount_namespace: current_mount_namespace(),
        key: key(module_mapping),
        path: module_path.display().to_string(),
        decoder_abi: Some(ElfAbi::Lp64),
        exports: vec!["C_GetFunctionList".into()],
        tables: vec![ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: vec![ScannedEntry {
                name: "C_Initialize",
                object: key(scanned_mapping),
                object_path: scanned_target_path.display().to_string(),
                file_offset: offset,
            }],
            null_entries: vec![],
            unpinned: vec![],
            address: 0x7000,
            file_offset: Some(0),
            live_return: false,
            manifest_supported: false,
        }],
        interfaces: vec![],
    };
    let mut budget = CaptureWorkBudget::new(ScanLimits {
        per_object_bytes: u64::MAX,
        total_bytes: u64::MAX,
    });
    let (mut scan_pins, skipped) = pin_scanned_objects(
        std::process::id(),
        std::slice::from_ref(&module),
        &mut budget,
    )
    .unwrap();
    assert!(skipped.is_empty(), "{skipped:?}");

    let object = |id, path: &Path, identity| ObjectRecord {
        id,
        path: path.display().to_string(),
        identity,
    };
    let provenance = |path: &Path,
                      mapping: p11scope_manifest::identity::MappingFileKey,
                      identity| ProvenanceObject {
        path: path.display().to_string(),
        device_major: mapping.device_major,
        device_minor: mapping.device_minor,
        inode: mapping.inode,
        identity,
    };
    let mut manifest = Manifest {
        schema: SCHEMA.into(),
        module_path: module_path.display().to_string(),
        objects: vec![
            object(0, &module_path, module_inspected.identity.clone()),
            object(
                1,
                &manifest_target_path,
                manifest_inspected.identity.clone(),
            ),
        ],
        provenance_objects: vec![
            provenance(&module_path, module_mapping, module_inspected.identity),
            provenance(
                &manifest_target_path,
                manifest_mapping,
                manifest_inspected.identity,
            ),
        ],
        interface_list: Acquisition::Absent,
        surfaces: vec![SurfaceRecord {
            source: SurfaceSource::LegacyFunctionList,
            acquisition: Acquisition::Ok,
            version: Some(Version {
                major: 2,
                minor: 40,
            }),
            walk: WalkOutcome::Full,
            functions: pkcs11_module::FUNCTION_LIST_FIELDS
                .iter()
                .map(|field| FunctionRecord {
                    name: field.name.into(),
                    resolution: Resolution::Resolved {
                        object: 1,
                        file_offset: offset,
                    },
                })
                .collect(),
        }],
        vendor_interfaces: vec![],
        alias_groups: vec![],
        selection_evidence: Default::default(),
    };
    let manifest_pins = pin_manifest_objects(&manifest).unwrap();
    let view = scan_view(
        &manifest,
        std::slice::from_ref(&module),
        &scan_pins,
        &manifest_pins,
    )
    .expect("the module itself exact-matches");
    let scanned_targets = scanned_targets(&view.modules, &scan_pins).unwrap();
    let manifest_targets = manifest_targets(&manifest, &manifest_pins).unwrap();
    let outcome = corroborate(
        false,
        Some(view.agrees),
        scan_pins.exactly_same_targets(&scanned_targets, &manifest_pins, &manifest_targets),
        scanned_targets.is_empty(),
    );
    assert_eq!(
        outcome,
        Corroboration::Conflict,
        "equal digest/offset must not suppress a distinct opened target"
    );

    retarget_to_pins(&mut manifest, &view.modules, &scan_pins, &manifest_pins);
    assert!(scan_pins.absorb(manifest_pins).is_empty());
    let (modules, _, uncertainty) =
        reconcile_scanned_modules(std::slice::from_ref(&module), &mut scan_pins);
    assert!(uncertainty.is_empty(), "{uncertainty:?}");
    let plan = plan::build_from_sources(&modules, &[manifest], &scan_pins);
    assert_eq!(plan.slots.len(), 2, "both exact opened targets must attach");
    assert_eq!(
        plan.slots
            .iter()
            .map(|slot| slot.object)
            .collect::<BTreeSet<_>>()
            .len(),
        2,
        "the union must retain two distinct capture-local identities"
    );
    let mut counters = DiscoveryCounters {
        conflicts: 1,
        ..DiscoveryCounters::default()
    };
    counters
        .corroboration
        .push(([modules[0].object].into_iter().collect(), "conflict"));
    assert_eq!(
        discovery_evidence(&plan, &scan_pins, &counters).conflicts,
        1,
        "the conflict is the bounded evidence that forces PARTIAL"
    );
}

/// Retargeting adopts the identity of the object the scan matched — never some
/// other pin that happens to hash the same (an earlier manifest's copy of the
/// same bytes, which the target may not map at all).
#[test]
fn retargeting_only_adopts_the_matched_scanned_object() {
    let (modules, pinned) = pinned_self();
    let summary = pinned.pinned().next().unwrap();
    let (path, sha) = (summary.path.to_string(), summary.sha256.to_string());
    let mut m = manifest_naming(&path, Some(sha.clone()));
    m.provenance_objects[0].inode = 1;
    m.provenance_objects[0].device_major = 99;

    let own = pin_as_manifest_object(&path);
    retarget_to_pins(&mut m, &[&modules[0]], &pinned, &own);
    assert_eq!(m.provenance_objects[0].inode, summary.key.inode);
    assert_eq!(
        m.provenance_objects[0].device_major,
        summary.key.device.major
    );

    // The same bytes pinned under an identity the scan did not see must not be
    // adopted: a decoy module the matched scan never named.
    let decoy = ScannedModule {
        view: ProcessViewId(0),
        mount_namespace: current_mount_namespace(),
        key: ObjectKey {
            device: p11scope_manifest::maps::Device { major: 0, minor: 0 },
            inode: 7,
        },
        path: "/opt/decoy.so".into(),
        decoder_abi: None,
        exports: vec![],
        tables: vec![],
        interfaces: vec![],
    };
    let mut m = manifest_naming(&path, Some(sha));
    m.provenance_objects[0].inode = 1;
    retarget_to_pins(&mut m, &[&decoy], &pinned, &own);
    assert_eq!(
        m.provenance_objects[0].inode, summary.key.inode,
        "no pin of the decoy exists, so the manifest's own exact pin is retained"
    );
}

/// A minimal schema-current manifest naming one object with one resolved function.
fn manifest_naming(path: &str, sha256: Option<String>) -> Manifest {
    use p11scope_manifest::identity::{IdentityKind, ObjectIdentity};
    use p11scope_manifest::manifest::*;
    let identity = ObjectIdentity {
        kind: IdentityKind::GnuBuildId,
        value: Some("aa".into()),
        sha256,
        reusable: true,
        note: None,
    };
    Manifest {
        schema: SCHEMA.to_string(),
        module_path: path.to_string(),
        objects: vec![ObjectRecord {
            id: 0,
            path: path.to_string(),
            identity: identity.clone(),
        }],
        provenance_objects: vec![ProvenanceObject {
            path: path.to_string(),
            device_major: 8,
            device_minor: 1,
            inode: 42,
            identity,
        }],
        interface_list: Acquisition::Absent,
        surfaces: vec![SurfaceRecord {
            source: SurfaceSource::LegacyFunctionList,
            acquisition: Acquisition::Ok,
            version: None,
            walk: WalkOutcome::Full,
            functions: vec![FunctionRecord {
                name: "C_Sign".into(),
                resolution: Resolution::Resolved {
                    object: 0,
                    file_offset: 0x40,
                },
            }],
        }],
        vendor_interfaces: vec![],
        alias_groups: vec![],
        selection_evidence: Default::default(),
    }
}

/// The outcomes of spec §4.12, which decide whether `--manifest` is a safe
/// fallback or a trapdoor. Each one changes what is attached and what the
/// capture claims about it.
#[test]
fn the_corroboration_outcomes() {
    // 1. Not mapped in scope: the manifest stands on its own.
    assert_eq!(
        corroborate(false, None, false, true),
        Corroboration::Uncorroborated
    );
    // 2. Mapped, same {object, offset} set: corroborated.
    assert_eq!(
        corroborate(false, Some(true), true, false),
        Corroboration::Agreed
    );
    // 3. Mapped, the sets differ: a conflict (the caller attaches the union).
    assert_eq!(
        corroborate(false, Some(true), false, false),
        Corroboration::Conflict
    );
    // 3b. Mapped and identity-matched, but the scan decoded no table at all:
    // the documented use of `--manifest`, not two sources contradicting each
    // other. Reported as uncorroborated, never as a disagreement.
    assert_eq!(
        corroborate(false, Some(true), false, true),
        Corroboration::ScanEmpty
    );
    // Two empty sets are not a scan-empty case: nothing was recorded either.
    assert_eq!(
        corroborate(false, Some(true), true, true),
        Corroboration::Agreed
    );
    // 4. Mapped, but the bytes are not the ones the manifest recorded.
    assert_eq!(
        corroborate(false, Some(false), true, false),
        Corroboration::IdentityMismatch
    );
    // A scan that could not read memory found no tables to disagree with, so it
    // never turns a usable manifest into a conflict or a mismatch.
    for identity in [None, Some(true), Some(false)] {
        assert_eq!(
            corroborate(true, identity, false, true),
            Corroboration::Uncorroborated,
            "{identity:?}"
        );
    }
}

/// A pod's processes live in the container cgroups below the pod directory;
/// capture scope already includes every descendant, so discovery must too.
#[test]
fn cgroup_walk_follows_the_retained_directory_not_a_replaced_path() {
    let root = tempfile::tempdir().unwrap();
    let real = root.path().join("target.scope");
    let impostor = root.path().join("impostor.scope");
    std::fs::create_dir_all(real.join("leaf.scope")).unwrap();
    std::fs::create_dir(&impostor).unwrap();
    std::fs::write(real.join("cgroup.procs"), "11\n").unwrap();
    std::fs::write(real.join("leaf.scope/cgroup.procs"), "22\n").unwrap();
    std::fs::write(impostor.join("cgroup.procs"), "99\n").unwrap();
    let scope = crate::scope::cgroup(&real).unwrap();
    let stash = root.path().join("moved.scope");
    std::fs::rename(&real, &stash).unwrap();
    std::fs::rename(&impostor, &real).unwrap();

    let (pids, lost) = scope_pids(&scope);

    assert_eq!(pids, vec![11, 22], "the retained fd's descendants, not 99");
    assert!(!pids.contains(&99));
    assert_eq!(lost, vec![]);
}

#[test]
fn cgroup_walk_reports_losses_under_the_operator_path_not_a_proc_fd_path() {
    let root = tempfile::tempdir().unwrap();
    let real = root.path().join("target.scope");
    let leaf = real.join("leaf.scope");
    std::fs::create_dir_all(&leaf).unwrap();
    std::fs::write(real.join("cgroup.procs"), "11\n").unwrap();
    std::fs::create_dir(leaf.join("cgroup.procs")).unwrap();
    let scope = crate::scope::cgroup(&real).unwrap();

    let (pids, lost) = scope_pids(&scope);

    assert_eq!(pids, vec![11]);
    assert_eq!(
        lost.len(),
        1,
        "the directory cannot be read as text: {lost:?}"
    );
    assert_eq!(lost[0].subject, leaf.display().to_string());
    assert!(!format!("{lost:?}").contains("/proc/self/fd"));
}

#[test]
fn cgroup_scope_collects_pids_from_every_descendant() {
    let root = tempfile::tempdir().unwrap();
    let leaf = root.path().join("kubepods.slice").join("container.scope");
    std::fs::create_dir_all(&leaf).unwrap();
    std::fs::write(root.path().join("cgroup.procs"), "11\n").unwrap();
    std::fs::write(leaf.join("cgroup.procs"), "22\n33\n\n22\n").unwrap();
    let scope = crate::scope::cgroup(root.path()).unwrap();
    let (pids, lost) = scope_pids(&scope);
    assert_eq!(pids, vec![11, 22, 33], "deduplicated, descendants included");
    assert_eq!(lost, vec![], "every directory was readable");
    assert_eq!(scope_pids(&Scope::Pid(7)).0, vec![7]);

    // A cgroup that is gone by the time the walk reaches it — container
    // cgroups churn constantly, and one is removable only when empty — held
    // no process to lose, on either read. Claiming otherwise would publish a
    // false loss and force PARTIAL on ordinary pod turnover.
    let vanished = tempfile::tempdir().unwrap();
    let vanished_scope = crate::scope::cgroup(vanished.path()).unwrap();
    std::fs::remove_dir(vanished.path()).unwrap();
    let (pids, lost) = scope_pids(&vanished_scope);
    assert_eq!(pids, Vec::<u32>::new());
    assert_eq!(lost, vec![], "a cgroup that no longer exists is not a loss");

    // A subtree the observer cannot read is not an empty subtree: the
    // processes in it were never listed, so their providers were never
    // discovered, and nothing else in the document would say so. An *absent*
    // cgroup.procs (the intermediate directory above) is not a loss — it is
    // not a cgroup — which is why the first assertion above sees none.
    //
    // Root reads a mode-000 directory, so the denial is not reproducible
    // there. Both configurations assert — a test that steps aside under the
    // very privilege level the gates run at is a green that proves nothing.
    // Which claim applies is decided by what this process can actually do
    // rather than by its uid: root with CAP_DAC_OVERRIDE dropped is denied
    // like anyone else, and would fail a uid-based branch for the wrong
    // reason.
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = std::fs::metadata(&leaf).unwrap().permissions();
    permissions.set_mode(0o000);
    std::fs::set_permissions(&leaf, permissions).unwrap();
    let denied = std::fs::read_dir(&leaf).is_err();
    let (pids, lost) = scope_pids(&scope);
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o755)).unwrap();
    if !denied {
        assert_eq!(
            pids,
            vec![11, 22, 33],
            "the mode change denied this observer nothing, so nothing is missed"
        );
        assert_eq!(lost, vec![], "nothing was denied, so nothing is a loss");
        return;
    }
    assert_eq!(pids, vec![11], "only the readable cgroup's process");
    assert_eq!(
        lost.len(),
        2,
        "the file and the listing both failed: {lost:?}"
    );
    assert!(
        lost.iter().all(|s| s.subject.ends_with("container.scope")),
        "{lost:?}"
    );
    assert!(
        lost.iter().any(|s| s.reason.contains("cgroup.procs"))
            && lost.iter().any(|s| s.reason.contains("never discovered")),
        "{lost:?}"
    );
}

#[test]
fn system_scope_sweeps_proc_for_sorted_unique_tgids() {
    // No cgroup path is consulted: the whole machine is the membership.
    let (pids, lost) = scope_pids(&Scope::System);
    assert_eq!(lost, vec![], "a listable /proc loses nothing: {lost:?}");
    assert!(
        pids.contains(&std::process::id()),
        "the sweep must see its own observer"
    );
    assert!(pids.contains(&1), "pid 1 always exists");
    let mut sorted = pids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(pids, sorted, "sorted and deduplicated");
    assert_eq!(scope_label(&Scope::System), "system");
}

fn merged_object(sources: Vec<&'static str>) -> render::ObjectSummary {
    render::ObjectSummary {
        dev: (0, 30),
        ino: 12_043_768,
        sha256: Some("5f48fcc1".into()),
        path: "/tmp/freeze-provider.so".into(),
        build_id: Some("23a2c057".into()),
        identity_source: "mountinfo",
        note: None,
        sources,
    }
}

fn merged_module(sources: Vec<&'static str>) -> render::DiscoveredModule {
    render::DiscoveredModule {
        id: plan::ModuleId(0),
        dev: (0, 30),
        ino: 12_043_768,
        sha256: Some("5f48fcc1".into()),
        path: "/tmp/freeze-provider.so".into(),
        build_id: Some("23a2c057".into()),
        objects: vec![merged_object(sources.clone())],
        sources,
        corroborated: false,
        corroboration: vec!["uncorroborated"],
        tables: Vec::new(),
        interfaces: 0,
        skipped: Vec::new(),
    }
}

/// A manifest-first module that the scan only reaches later is the one
/// arrival order an append-union renders as `["manifest", "scan"]`, which
/// is outside the schema's three legal arrays
/// (docs/schema/observed-profile-v2.md: "in that canonical order").
#[test]
fn a_later_scan_merges_into_a_manifest_module_in_canonical_source_order() {
    let mut retained = merged_module(vec!["manifest"]);
    merge_discovered_module(&mut retained, merged_module(vec!["scan", "manifest"]));
    assert_eq!(retained.sources, vec!["scan", "manifest"]);
}

/// `objects[]` is "every object this module's planned slots attach into" —
/// one entry per object. A source set that grows between snapshots is the
/// same physical object described better, not a second one.
#[test]
fn one_physical_object_keeps_one_objects_entry_across_a_source_change() {
    let mut retained = merged_module(vec!["manifest"]);
    merge_discovered_module(&mut retained, merged_module(vec!["scan", "manifest"]));
    assert_eq!(
        retained.objects,
        vec![merged_object(vec!["scan", "manifest"])]
    );
}

/// Two genuinely different objects still both appear.
#[test]
fn distinct_objects_are_never_coalesced_by_the_source_union() {
    let mut retained = merged_module(vec!["scan"]);
    let mut incoming = merged_module(vec!["manifest"]);
    incoming.objects[0].ino = 999;
    merge_discovered_module(&mut retained, incoming);
    assert_eq!(retained.objects.len(), 2);
    assert_eq!(retained.sources, vec!["scan", "manifest"]);
}

#[test]
fn manifest_selection_queries_merge_once_and_preserve_manifest_loss() {
    let (_fixture, mut engine, _session) = initial_export_route();
    let path = engine.modules[0].scanned.path.clone();
    let function_offset = object_facts(Path::new(&path)).2;
    let mut manifest = valid_manifest_for(&[PathBuf::from(&path)], &[0; 67]);
    manifest.interface_list = Acquisition::Ok;
    manifest.surfaces[0].acquisition = Acquisition::Absent;
    manifest.surfaces[0].walk = WalkOutcome::NotWalked;
    manifest.surfaces[0].functions.clear();
    let interface_functions: Vec<_> = pkcs11_module::FUNCTION_LIST_FIELDS
        .iter()
        .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS.iter())
        .map(|field| FunctionRecord {
            name: field.name.into(),
            resolution: Resolution::NullPointer,
        })
        .collect();
    for index in 0..16 {
        manifest.surfaces.push(SurfaceRecord {
            source: SurfaceSource::Interface {
                index,
                raw_name_hex: Some("504b4353203131".into()),
                name_lossy: Some("PKCS 11".into()),
                name_error: None,
                flags: 0,
                classification: InterfaceClassification::ExactStandard,
            },
            acquisition: Acquisition::Ok,
            version: Some(Version { major: 3, minor: 0 }),
            walk: WalkOutcome::Full,
            functions: interface_functions.clone(),
        });
    }
    manifest.selection_evidence = manifest_selection_evidence(
        Version { major: 3, minor: 0 },
        &[("C_Initialize", function_offset)],
    );
    {
        let query = &mut manifest.selection_evidence.queries[4];
        query.result = Some(SelectionRequest {
            name: SelectionNameClass::ExactStandard,
            version: SelectionVersionClass::V3_0,
            flags: 0,
        });
        query.selection_table = None;
        query.inventory_matches = (1..=16)
            .map(
                |surface| p11scope_manifest::manifest::SelectionInventoryMatch {
                    surface,
                    name_agrees: true,
                    version_agrees: true,
                },
            )
            .collect();
        query.authority = SelectionAuthority::Inventory;
    }
    manifest.selection_evidence.tables.clear();
    manifest.selection_evidence.queries[5].rv = 0;
    manifest.selection_evidence.queries[5].helper_failure =
        Some(p11scope_manifest::manifest::SelectionFailure::NullOutput);
    manifest.selection_evidence.selection_truncated = true;
    let expected_queries: Vec<_> = manifest
        .selection_evidence
        .queries
        .iter()
        .map(|query| (query.request, query.rv, query.result, query.authority))
        .collect();
    let manifest_pins = pin_manifest_objects(&manifest).unwrap();
    assert!(engine.pinned.absorb(manifest_pins.clone()).is_empty());
    engine.manifests.push(manifest.clone());
    engine.manifest_ordinals.push(17);

    engine.publish_current_capture_facts().unwrap();
    let first = engine.capture_facts.history.selections.clone();
    let first_surfaces = engine.capture_facts.history.selection_surfaces.clone();
    engine.publish_current_capture_facts().unwrap();

    assert_eq!(engine.capture_facts.history.selections, first);
    assert_eq!(first.len(), 10, "all ten fixed manifest rows are imported");
    assert!(first.iter().all(|tuple| tuple.count == 1));
    assert_eq!(
        first
            .iter()
            .map(|tuple| (tuple.request, tuple.rv, tuple.result, tuple.authority))
            .collect::<Vec<_>>(),
        expected_queries,
        "every fixed query, including the helper-failure row, is imported exactly"
    );
    let inventory_tuple = first
        .iter()
        .find(|tuple| tuple.authority == SelectionAuthority::Inventory)
        .expect("the inventory-backed row is retained");
    assert_eq!(inventory_tuple.inventory_matches.len(), 16);
    assert!(
        inventory_tuple
            .inventory_matches
            .iter()
            .enumerate()
            .all(|(index, matched)| {
                matched.surface.base.manifest_identity == Some((17, index as u32 + 1))
            })
    );
    assert_eq!(
        engine.capture_facts.history.selection_surfaces,
        first_surfaces
    );
    assert!(engine.capture_facts.history.selection_truncated);
    let manifest_identities: BTreeSet<_> = first_surfaces
        .iter()
        .filter_map(|surface| surface.base.manifest_identity)
        .collect();
    assert_eq!(
        manifest_identities,
        (1..=16).map(|index| (17, index)).collect()
    );

    let projected = engine.interface_selection();
    assert_eq!(projected.inventory_surfaces.len(), 16);
    assert!(
        projected
            .inventory_surfaces
            .iter()
            .all(|surface| surface.module == 0)
    );
    assert!(projected.tuples.iter().all(|tuple| {
        tuple.module == 0
            && tuple
                .inventory_matches
                .iter()
                .all(|matched| matched.surface < projected.inventory_surfaces.len() as u16)
    }));
    assert!(
        !serde_json::to_string(&projected)
            .unwrap()
            .contains("manifest_identity")
    );

    let mut rendered = evidence_verdict(&engine.plan, &engine.pinned, &engine.counters);
    rendered.interface_selection = projected;
    rendered.verdict_with_selection(true);
    assert_eq!(rendered.completeness, "PARTIAL");

    // A second accepted manifest gets a distinct private ordinal, but a
    // repeated publication must not duplicate either its rows or matches.
    engine.pinned.absorb(manifest_pins);
    engine.manifests.push(manifest);
    engine.manifest_ordinals.push(18);
    engine.publish_current_capture_facts().unwrap();
    let twice = engine.capture_facts.history.selections.clone();
    assert_eq!(twice.len(), 11);
    assert!(twice.iter().all(|tuple| {
        if tuple.authority == SelectionAuthority::Inventory {
            tuple.count == 1
        } else {
            tuple.count == 2
        }
    }));
    let inventory_matches: BTreeSet<_> = twice
        .iter()
        .filter(|tuple| tuple.authority == SelectionAuthority::Inventory)
        .flat_map(|tuple| {
            tuple
                .inventory_matches
                .iter()
                .map(|matched| matched.surface.base.manifest_identity)
        })
        .collect();
    assert_eq!(inventory_matches.len(), 32);
    assert!(inventory_matches.contains(&Some((17, 1))));
    assert!(inventory_matches.contains(&Some((18, 16))));
    let reprojected = engine.interface_selection();
    engine.publish_current_capture_facts().unwrap();
    assert_eq!(engine.capture_facts.history.selections, twice);
    assert_eq!(
        engine.interface_selection(),
        reprojected,
        "the second manifest ordinal reprojects identically after republication"
    );

    // The tuple budget is capture-wide: seven live tuples plus the ten
    // offline rows leave only nine offline rows admitted.
    let (_bound_fixture, mut bound, _bound_session) = initial_export_route();
    for flags in 0..7 {
        bound.capture_facts.record_selection(
            LiveSelectionTuple {
                module: plan::ModuleId(0),
                request: SelectionRequest {
                    name: SelectionNameClass::Null,
                    version: SelectionVersionClass::Null,
                    flags,
                },
                rv: 99,
                result: None,
                inventory_matches: Vec::new(),
                authority: SelectionAuthority::None,
                count: 1,
            },
            false,
        );
    }
    let bound_path = bound.modules[0].scanned.path.clone();
    let bound_offset = object_facts(Path::new(&bound_path)).2;
    let mut bound_manifest = valid_manifest_for(&[PathBuf::from(&bound_path)], &[0; 67]);
    bound_manifest.selection_evidence = manifest_selection_evidence(
        Version { major: 3, minor: 0 },
        &[("C_Initialize", bound_offset)],
    );
    let bound_pins = pin_manifest_objects(&bound_manifest).unwrap();
    assert!(bound.pinned.absorb(bound_pins).is_empty());
    bound.manifests.push(bound_manifest);
    bound.manifest_ordinals.push(19);
    bound.publish_current_capture_facts().unwrap();
    assert_eq!(bound.capture_facts.history.selections.len(), 16);
    assert!(bound.capture_facts.history.selection_truncated);
}

#[test]
fn offline_helper_failure_alone_marks_exact_loss_and_partial() {
    let (_fixture, mut engine, _session) = initial_export_route();
    let path = engine.modules[0].scanned.path.clone();
    let offset = object_facts(Path::new(&path)).2;
    let mut manifest = valid_manifest_for(&[PathBuf::from(&path)], &[0; 67]);
    manifest.selection_evidence =
        manifest_selection_evidence(Version { major: 3, minor: 0 }, &[("C_Initialize", offset)]);
    manifest.selection_evidence.selection_truncated = false;
    manifest.selection_evidence.queries[5].rv = 0;
    manifest.selection_evidence.queries[5].helper_failure =
        Some(p11scope_manifest::manifest::SelectionFailure::NullOutput);
    let pins = pin_manifest_objects(&manifest).unwrap();
    assert!(engine.pinned.absorb(pins).is_empty());
    engine.manifests.push(manifest);
    engine.manifest_ordinals.push(20);

    engine.publish_current_capture_facts().unwrap();

    let loss = Skipped {
        subject: "offline interface selection".into(),
        reason: OFFLINE_SELECTION_LOSS_REASON.into(),
    };
    assert_eq!(
        engine
            .capture_facts
            .history
            .losses
            .get(&(loss.subject.clone(), loss.reason.clone())),
        Some(&loss)
    );
    let mut evidence = evidence_verdict(&engine.plan, &engine.pinned, &engine.counters);
    evidence.interface_selection = engine.interface_selection();
    evidence.verdict_with_selection(true);
    assert_eq!(evidence.completeness, "PARTIAL");
}

/// Fix A, engine leg: the same export table in two ordinary batches burns one
/// candidate. This drives the export-record admit site (engine.rs); the
/// scan-level test covers the memory-scan site, and both share the budget.
/// (The loader-route shape from the first draft is vacuous here: probing
/// showed the seed fixture's memory scan admits zero tables, so 0→0 passes
/// with or without the fix. The export fixture below admits a real table.)
#[test]
fn identical_table_in_two_batches_burns_one_candidate() {
    let (view, _maps, record) = self_export_fixture(ProcessViewId(0));
    let mut engine = Engine::empty();
    engine.next_view_id = 1;
    engine.views.push(view);
    // This test binary is larger than the default per-object cap, which
    // would skip its own pin for an unrelated reason.
    engine.budget = CaptureWorkBudget::new(ScanLimits {
        per_object_bytes: u64::MAX,
        total_bytes: u64::MAX,
    });
    let mut session = ScriptedSession::default();
    let first = apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();
    let candidates_after_first = engine.budget.table_candidates_count();
    assert_eq!(candidates_after_first, 1);
    let second = apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();
    assert!(first.required_complete);
    assert!(second.required_complete);
    assert_eq!(
        engine.budget.table_candidates_count(),
        candidates_after_first,
        "the second identical table must not burn another candidate"
    );
}

/// Fix C: phase-1 selection prefers rare providers over pid order, so a
/// just-started high-pid provider is deep-scanned instead of truncated away.
/// Under the cap the selection is the identity (today's exact order).
#[test]
fn candidate_selection_prefers_rare_providers_over_pid_order() {
    fn map_entry(path: &str, inode: u64) -> MapEntry {
        MapEntry {
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            permissions: *b"r-xp",
            device: Device { major: 8, minor: 1 },
            inode,
            raw_path: Some(path.as_bytes().to_vec()),
        }
    }
    let sweep: Vec<(u32, Vec<MapEntry>)> = vec![
        (7, vec![map_entry("/usr/lib/libp11-kit.so", 9)]),
        (8, vec![map_entry("/usr/lib/libp11-kit.so", 9)]),
        (9001, vec![map_entry("/tmp/uniq-p11.so", 10)]),
    ];
    assert_eq!(select_deep_scan_candidates(&sweep, 1), vec![9001]);
    assert_eq!(select_deep_scan_candidates(&sweep, 2), vec![9001, 7]);
    assert_eq!(select_deep_scan_candidates(&sweep, 3), vec![7, 8, 9001]);
}

/// F2: the published over-cap diagnostic agrees with the actual selected
/// set — real counts, the cap, and the rarity method, never a "first N"
/// prefix claim and never a pid. Refresh counts new candidates only.
#[test]
fn scan_cap_diagnostic_reports_actual_selection() {
    // Rare provider lives at the highest pid: selection is [9001], not [7].
    assert_eq!(
        scan_cap_reason(3, 1, 1, false),
        "3 processes in scope; discovery selected 1 for deep scanning by provider rarity (limit 1); unselected processes may contain undiscovered providers"
    );
    // Grouped case: cap 2 yields one representative.
    assert_eq!(
        scan_cap_reason(4, 1, 2, false),
        "4 processes in scope; discovery selected 1 for deep scanning by provider rarity (limit 2); unselected processes may contain undiscovered providers"
    );
    assert_eq!(
        scan_cap_reason(3, 1, 2, true),
        "3 processes in scope; live discovery selected 1 new candidate for deep scanning by provider rarity (limit 2)"
    );
    assert_eq!(
        scan_cap_reason(5, 0, 0, true),
        "5 processes in scope; live discovery selected 0 new candidates for deep scanning by provider rarity (limit 0)"
    );
    for reason in [
        scan_cap_reason(3, 1, 1, false),
        scan_cap_reason(3, 1, 2, true),
    ] {
        assert!(!reason.contains("first"), "no prefix claim: {reason}");
        assert!(!reason.contains("9001"), "no pid leaks: {reason}");
    }
}

/// ABC-T4 coverage: the pure selection edges — equal-rarity tie-break goes
/// to the lowest pid, pids with no provider mapping trail as individuals,
/// and an under-cap sweep keeps today's ascending identity order.
#[test]
fn selection_edges_tie_break_empty_key_under_cap() {
    fn map_entry(path: &str, inode: u64) -> MapEntry {
        MapEntry {
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            permissions: *b"r-xp",
            device: Device { major: 8, minor: 1 },
            inode,
            raw_path: Some(path.as_bytes().to_vec()),
        }
    }
    // Tie-break: both files are mapped by exactly 2 pids and both groups
    // have 2 members, so the order falls through to lowest pid.
    let tied: Vec<(u32, Vec<MapEntry>)> = vec![
        (30, vec![map_entry("/usr/lib/liba.so", 11)]),
        (31, vec![map_entry("/usr/lib/liba.so", 11)]),
        (40, vec![map_entry("/usr/lib/libb.so", 12)]),
        (41, vec![map_entry("/usr/lib/libb.so", 12)]),
    ];
    assert_eq!(select_deep_scan_candidates(&tied, 2), vec![30, 40]);
    // Empty key: pids with no provider mapping (no entries at all, or an
    // anonymous mapping) trail as individuals behind the representatives.
    let keyed: Vec<(u32, Vec<MapEntry>)> = vec![
        (7, vec![map_entry("/tmp/uniq-p11.so", 10)]),
        (100, vec![]),
        (101, vec![map_entry("/usr/lib/liba.so", 0)]),
    ];
    assert_eq!(select_deep_scan_candidates(&keyed, 2), vec![7, 100]);
    assert_eq!(select_deep_scan_candidates(&keyed, 3), vec![7, 100, 101]);
    // Under cap: the sweep length fits, so the selection is the identity —
    // all pids ascending however unsorted the input.
    let under: Vec<(u32, Vec<MapEntry>)> = vec![
        (50, vec![map_entry("/usr/lib/liba.so", 11)]),
        (9, vec![]),
        (30, vec![map_entry("/tmp/uniq-p11.so", 10)]),
    ];
    assert_eq!(select_deep_scan_candidates(&under, 3), vec![9, 30, 50]);
}

/// Package C: rotation's fairness tier agrees with plain selection when
/// nothing is stale, prefers never-evicted members within each rarity
/// class, and still lets global rarity beat pid order across groups.
#[test]
fn rotation_selection_tiers_fresh_before_stale_within_rarity() {
    fn map_entry(path: &str, inode: u64) -> MapEntry {
        MapEntry {
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            permissions: *b"r-xp",
            device: Device { major: 8, minor: 1 },
            inode,
            raw_path: Some(path.as_bytes().to_vec()),
        }
    }
    let sweep: Vec<(u32, Vec<MapEntry>)> = vec![
        (30, vec![map_entry("/usr/lib/liba.so", 11)]),
        (31, vec![map_entry("/usr/lib/liba.so", 11)]),
        (32, vec![map_entry("/usr/lib/liba.so", 11)]),
        (40, vec![map_entry("/usr/lib/libb.so", 12)]),
        (41, vec![map_entry("/usr/lib/libb.so", 12)]),
        (90, vec![]),
        (91, vec![]),
    ];
    let empty: BTreeSet<u32> = BTreeSet::new();
    // No stale pids: exact agreement with plain selection.
    assert_eq!(
        select_rotation_candidates(&sweep, 3, &empty),
        select_deep_scan_candidates(&sweep, 3),
        "fresh-only rotation matches plain rarity selection"
    );
    // One class's lowest member is stale: the representative moves to the
    // lowest fresh member, and unmapped staleness sorts behind fresh. The
    // rarer libb group still leads liba: rarity orders groups, freshness
    // only members.
    let stale: BTreeSet<u32> = [30, 40, 90].into_iter().collect();
    assert_eq!(
        select_rotation_candidates(&sweep, 2, &stale),
        vec![41, 31],
        "group representatives skip stale members for fresh ones"
    );
    assert_eq!(
        select_rotation_candidates(&sweep, 4, &stale),
        vec![41, 31, 91, 90],
        "unmapped pids trail fresh-first, then stale"
    );
    // A stale rare singleton still beats fresh commons: rarity is global,
    // freshness only orders within a class.
    let rare: Vec<(u32, Vec<MapEntry>)> = vec![
        (7, vec![map_entry("/tmp/uniq-p11.so", 10)]),
        (100, vec![map_entry("/usr/lib/liba.so", 11)]),
        (101, vec![map_entry("/usr/lib/liba.so", 11)]),
        (102, vec![map_entry("/usr/lib/liba.so", 11)]),
    ];
    let stale_rare: BTreeSet<u32> = [7].into_iter().collect();
    assert_eq!(
        select_rotation_candidates(&rare, 1, &stale_rare),
        vec![7],
        "global rarity beats freshness across groups"
    );
}

/// A4 Task 1: file-level rarity beats pid order — a high-pid singleton mapping
/// a globally-unique file sorts before a low-pid singleton whose files are all
/// widely mapped. (Set-level rarity ties both at len 1 and the low pid wins.)
#[test]
fn globally_rare_file_sorts_before_common_singletons() {
    fn map_entry(path: &str, inode: u64) -> MapEntry {
        MapEntry {
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            permissions: *b"r-xp",
            device: Device { major: 8, minor: 1 },
            inode,
            raw_path: Some(path.as_bytes().to_vec()),
        }
    }
    let mut sweep: Vec<(u32, Vec<MapEntry>)> = Vec::new();
    // 200 pids mapping only the widely-shared provider A.
    for pid in 100..300u32 {
        sweep.push((pid, vec![map_entry("/usr/lib/common-a.so", 1)]));
    }
    // 55 pids mapping only the widely-shared provider B.
    for pid in 300..355u32 {
        sweep.push((pid, vec![map_entry("/usr/lib/common-b.so", 2)]));
    }
    // Low-pid singleton whose set is unique but every file is widely mapped
    // (A: 201 pids, B: 56 pids).
    sweep.push((
        7,
        vec![
            map_entry("/usr/lib/common-a.so", 1),
            map_entry("/usr/lib/common-b.so", 2),
        ],
    ));
    // High-pid singleton mapping one globally-unique file.
    sweep.push((9001, vec![map_entry("/tmp/uniq-p11.so", 3)]));
    assert_eq!(sweep.len(), 257);
    let selected = select_deep_scan_candidates(&sweep, 256);
    assert_eq!(&selected[..2], &[9001, 7]);
}

/// A4 Task 1: equal file-rarity keeps today's (group len, lowest pid) order.
#[test]
fn tie_break_stays_len_then_lowest_pid() {
    fn map_entry(path: &str, inode: u64) -> MapEntry {
        MapEntry {
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            permissions: *b"r-xp",
            device: Device { major: 8, minor: 1 },
            inode,
            raw_path: Some(path.as_bytes().to_vec()),
        }
    }
    // Every file is mapped by exactly 2 pids, so every group has
    // min-global-count 2 and the order falls through to (len, lowest pid).
    let sweep: Vec<(u32, Vec<MapEntry>)> = vec![
        (30, vec![map_entry("/usr/lib/liba.so", 11)]),
        (31, vec![map_entry("/usr/lib/liba.so", 11)]),
        (40, vec![map_entry("/usr/lib/libb.so", 12)]),
        (
            41,
            vec![
                map_entry("/usr/lib/libb.so", 12),
                map_entry("/usr/lib/libc.so", 13),
            ],
        ),
        (42, vec![map_entry("/usr/lib/libc.so", 13)]),
    ];
    assert_eq!(select_deep_scan_candidates(&sweep, 4), vec![40, 41, 42, 30]);
}

/// A4 Task 1: the under-cap identity path is untouched — pids ascending.
#[test]
fn under_cap_order_unchanged() {
    fn map_entry(path: &str, inode: u64) -> MapEntry {
        MapEntry {
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            permissions: *b"r-xp",
            device: Device { major: 8, minor: 1 },
            inode,
            raw_path: Some(path.as_bytes().to_vec()),
        }
    }
    let sweep: Vec<(u32, Vec<MapEntry>)> = vec![
        (9001, vec![map_entry("/tmp/uniq-p11.so", 10)]),
        (7, vec![map_entry("/usr/lib/libp11-kit.so", 9)]),
    ];
    assert_eq!(select_deep_scan_candidates(&sweep, 2), vec![7, 9001]);
    assert_eq!(select_deep_scan_candidates(&sweep, 256), vec![7, 9001]);
}

/// Task 3 (F3) helpers: the same C-fixture bodies as `tests/system_scope.rs`
/// (`build_fixture`, `build_driver`, `spawn_loaded`), duplicated here
/// because a `--lib` unit test cannot import `tests/support`. Two owned
/// children load distinct `.so` files, so each provider keeps its own
/// identity and slots.
fn system_scope_build_fixture(dir: &Path, name: &str) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/discover/tests/fixture/version_matrix.c");
    let library = dir.join(format!("{name}.so"));
    assert!(
        std::process::Command::new("gcc")
            .args(["-shared", "-fPIC", "-DMATRIX_INTERFACES=0", "-o"])
            .arg(&library)
            .arg(source)
            .status()
            .unwrap()
            .success()
    );
    library
}

fn system_scope_build_driver(dir: &Path) -> PathBuf {
    let driver = dir.join("driver");
    assert!(
        std::process::Command::new("gcc")
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-o"])
            .arg(&driver)
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/live-discovery-driver.c")
            )
            .args(["-ldl", "-pthread"])
            .status()
            .unwrap()
            .success()
    );
    driver
}

/// A native child with one provider dlopened, held until the guard drops.
/// `reap` kills and blocks in `wait`: the returned status — never PID
/// disappearance alone — proves this owned generation ended.
struct SystemScopeChildGuard {
    child: std::process::Child,
    live: bool,
}

impl SystemScopeChildGuard {
    fn new(child: std::process::Child) -> Self {
        Self { child, live: true }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn reap(&mut self) -> std::io::Result<std::process::ExitStatus> {
        let _ = self.child.kill();
        let status = self.child.wait()?;
        self.live = false;
        Ok(status)
    }
}

impl Drop for SystemScopeChildGuard {
    fn drop(&mut self) {
        if self.live {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn system_scope_poll_fd(fd: i32, timeout: std::time::Duration) -> std::io::Result<bool> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let timeout_ms = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pollfd names one initialized descriptor for this process.
        let result = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
        if result > 0 {
            return Ok(true);
        }
        if result == 0 {
            return Ok(false);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
    }
}

fn system_scope_spawn_loaded(driver: &Path, provider: &Path) -> SystemScopeChildGuard {
    system_scope_spawn_loaded_multi(driver, &[provider.to_path_buf()])
}

/// Package C variant mapping several providers in one process: the driver
/// loops `drive_dlopened` over every argument and prints one `done`.
fn system_scope_spawn_loaded_multi(driver: &Path, providers: &[PathBuf]) -> SystemScopeChildGuard {
    use std::io::Read as _;
    use std::os::fd::AsRawFd as _;
    let mut child = SystemScopeChildGuard::new(
        std::process::Command::new(driver)
            .arg("dlopen")
            .args(providers)
            .env_clear()
            .env("P11SCOPE_FIXTURE_INTERFACES", "0")
            .env("P11SCOPE_FIXTURE_POST_GATE", "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut stderr = child.child.stderr.take().unwrap();
    let mut readiness = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !readiness.ends_with(b"P11SCOPE_FIXTURE driver done\n") {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        assert!(!remaining.is_zero() && readiness.len() < 4096);
        assert!(system_scope_poll_fd(stderr.as_raw_fd(), remaining).unwrap());
        let mut byte = [0];
        assert_eq!(
            stderr.read(&mut byte).unwrap(),
            1,
            "fixture exited before ready"
        );
        readiness.extend_from_slice(&byte);
    }
    child
}

fn system_args(hints: Vec<PathBuf>, max_scan_pids: Option<usize>) -> CaptureArgs {
    CaptureArgs {
        kind: crate::cli::Kind::Profile,
        modules: hints,
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: crate::cli::ScopeArg::System,
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        max_scan_pids,
        ring_bytes: None,
        drain_interval: None,
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    }
}

/// Slots solely attributed to the plan module with this path suffix, as
/// stable `(path, offset, names)` keys. The module ID is re-resolved by
/// path on every call because a plan rebuild may reassign IDs; the keys
/// themselves survive rebuilds, so tick-to-tick comparison is exact.
fn system_scope_slots_for(
    engine: &Engine,
    provider_suffix: &str,
) -> Vec<(String, u64, Vec<String>)> {
    let module_id = engine
        .plan()
        .modules
        .iter()
        .find(|module| module.path.ends_with(provider_suffix))
        .unwrap_or_else(|| panic!("the plan names {provider_suffix}"))
        .id;
    let mut slots: Vec<(String, u64, Vec<String>)> = engine
        .plan()
        .slots
        .iter()
        .filter(|slot| slot.module_ids.as_slice() == [module_id])
        .map(|slot| {
            (
                slot.object_path.clone(),
                slot.file_offset,
                slot.names.clone(),
            )
        })
        .collect();
    slots.sort();
    slots
}

fn system_scope_live_process_count() -> usize {
    std::fs::read_dir("/proc")
        .expect("enumerate /proc for the under-cap ceiling")
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry.file_name().to_str().is_some_and(|name| {
                !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit())
            })
        })
        .count()
}

/// Task 3 (F3): one system-scope engine admits a later process generation
/// on refresh. Child A is discovered by the single `Engine::discover`
/// pass; child B spawns afterward and must enter the SAME engine through
/// the real `refresh_inventory` reconciliation — a new view ID, its own
/// provider/slot attribution, pinned claims, and a requested attachment —
/// while A keeps its view ID and ownership and the capture-wide budget
/// never resets. A quiet tick then holds every ID and slot steady, and
/// reaping B through its owned guard retires B while A remains.
#[test]
fn system_scope_refresh_admits_later_generation_in_same_engine() {
    let dir = tempfile::tempdir().expect("a fixture directory");
    let first = system_scope_build_fixture(dir.path(), "refresh-first");
    let second = system_scope_build_fixture(dir.path(), "refresh-second");
    let driver = system_scope_build_driver(dir.path());
    // Under-cap ceiling with headroom: selection is the identity, so the
    // one discover pass admits every live process and the refresh still
    // has view-ID room for the later child.
    let cap = system_scope_live_process_count() + 256;

    let child_a = system_scope_spawn_loaded(&driver, &first);
    let pid_a = child_a.pid();
    let mut engine = Engine::discover(
        &system_args(vec![first.clone(), second.clone()], Some(cap)),
        &Scope::System,
        None,
    )
    .expect("system scope discovers the first child");

    let views_a: Vec<_> = engine
        .views
        .iter()
        .filter(|view| view.pid() == pid_a)
        .collect();
    assert_eq!(views_a.len(), 1, "the first child is admitted exactly once");
    let id_a = views_a[0].id();
    assert!(
        views_a[0].still_the_same(),
        "the first child's retained generation is current"
    );
    let scan_a = engine
        .scan_inputs
        .get(&id_a)
        .expect("the first child's scan input is retained");
    assert!(
        scan_a
            .modules
            .iter()
            .any(|module| module.path.ends_with("refresh-first.so")),
        "the first child's scan names its provider: {:?}",
        scan_a
            .modules
            .iter()
            .map(|module| &module.path)
            .collect::<Vec<_>>()
    );
    let claims_a = engine
        .pinned()
        .view_claims(id_a)
        .expect("the first child owns pinned claims");
    assert!(
        !claims_a.pins.is_empty(),
        "the first child's claims pin objects"
    );
    assert!(
        engine.modules.iter().any(|module| {
            module.scanned.view == id_a && module.scanned.path.ends_with("refresh-first.so")
        }),
        "the first child's provider is attributed to its view"
    );
    let module_a_id = engine
        .plan()
        .modules
        .iter()
        .find(|module| module.path.ends_with("refresh-first.so"))
        .expect("the plan names the first child's provider")
        .id;
    let slots_a = system_scope_slots_for(&engine, "refresh-first.so");
    assert!(
        !slots_a.is_empty(),
        "the first child's provider contributes attachable slots"
    );
    assert!(
        engine
            .plan()
            .modules
            .iter()
            .all(|module| !module.path.ends_with("refresh-second.so")),
        "nothing maps the second provider before the later child spawns"
    );
    let budget_before = engine.budget.attempted_io_bytes();

    // The later child spawns after the one discover pass; the same engine
    // must pick it up through real reconciliation, copying the exact
    // `refresh_inventory_once` argument pattern with a retained session.
    let mut child_b = system_scope_spawn_loaded(&driver, &second);
    let pid_b = child_b.pid();
    let mut session = ScriptedSession::with_records([], 0);
    let attached_before = session.attached_slots.len();
    // A foreign provider-mapping process that exits mid-preflight makes
    // this tick report `Ok` without admitting anything (generation-stale
    // preflight), so retry for the agreeing tick like the capped-selection
    // sibling does. A deterministically broken admission never agrees and
    // still fails the assertions below.
    for _ in 0..25 {
        let mut collect: Box<DiscoveryCollector<'_>> = Box::new(Engine::collect_discovery_records);
        engine
            .refresh_inventory(
                &mut session,
                &mut true,
                &mut Vec::new(),
                &mut PendingViewRetirements::new(),
                &mut *collect,
                &mut PauseClosure::new(true),
            )
            .expect("the refresh tick applies");
        if engine.views.iter().any(|view| view.pid() == pid_b) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let views_a: Vec<_> = engine
        .views
        .iter()
        .filter(|view| view.pid() == pid_a)
        .collect();
    assert_eq!(
        views_a.len(),
        1,
        "the refresh retires nothing of the first child"
    );
    assert_eq!(
        views_a[0].id(),
        id_a,
        "the first child retains its original view ID"
    );
    assert!(
        views_a[0].still_the_same(),
        "the first child's retained generation is still current"
    );
    assert!(
        engine.scan_inputs.get(&id_a).is_some_and(|scan| {
            scan.modules
                .iter()
                .any(|module| module.path.ends_with("refresh-first.so"))
        }),
        "the first child's scan input survives the refresh"
    );
    assert!(
        engine
            .pinned()
            .view_claims(id_a)
            .is_some_and(|claims| !claims.pins.is_empty()),
        "the first child retains its ownership and pinned claims"
    );
    assert_eq!(
        system_scope_slots_for(&engine, "refresh-first.so"),
        slots_a,
        "the refresh keeps the first child's attributed slots"
    );
    let views_b: Vec<_> = engine
        .views
        .iter()
        .filter(|view| view.pid() == pid_b)
        .collect();
    assert_eq!(
        views_b.len(),
        1,
        "the refresh admits exactly one view for the later child"
    );
    let id_b = views_b[0].id();
    assert_ne!(
        id_b, id_a,
        "the later child gets a distinct view ID, not the first child's"
    );
    assert!(
        views_b[0].still_the_same(),
        "the later child's retained generation is current"
    );
    assert!(
        engine.modules.iter().any(|module| {
            module.scanned.view == id_b && module.scanned.path.ends_with("refresh-second.so")
        }),
        "the later child's provider is attributed to its own view"
    );
    let claims_b = engine
        .pinned()
        .view_claims(id_b)
        .expect("the later child owns pinned claims");
    assert!(
        !claims_b.pins.is_empty(),
        "the later child's claims pin objects"
    );
    let module_b_id = engine
        .plan()
        .modules
        .iter()
        .find(|module| module.path.ends_with("refresh-second.so"))
        .expect("the plan names the later child's provider")
        .id;
    assert_ne!(
        module_b_id, module_a_id,
        "each provider keeps its own plan identity"
    );
    let slots_b = system_scope_slots_for(&engine, "refresh-second.so");
    assert!(
        !slots_b.is_empty(),
        "the later child's provider contributes its own attachable slots"
    );
    assert!(
        session.attached_slots.len() > attached_before,
        "admitting the later generation requests attachment: {:?}",
        session.attached_slots
    );
    let budget_after = engine.budget.attempted_io_bytes();
    assert!(
        budget_after >= budget_before,
        "capture-wide attempted I/O is monotonic across the refresh: {budget_before} -> {budget_after}"
    );

    // A quiet tick: no child changed, so every view ID and every
    // attributed slot holds steady and the later child is not attached
    // a second time.
    let mut collect: Box<DiscoveryCollector<'_>> = Box::new(Engine::collect_discovery_records);
    engine
        .refresh_inventory(
            &mut session,
            &mut true,
            &mut Vec::new(),
            &mut PendingViewRetirements::new(),
            &mut *collect,
            &mut PauseClosure::new(true),
        )
        .expect("a quiet refresh tick applies");
    let views_a: Vec<_> = engine
        .views
        .iter()
        .filter(|view| view.pid() == pid_a)
        .collect();
    assert_eq!(views_a.len(), 1, "the quiet tick keeps the first child");
    assert_eq!(
        views_a[0].id(),
        id_a,
        "the quiet tick holds the first child's view ID steady"
    );
    let views_b: Vec<_> = engine
        .views
        .iter()
        .filter(|view| view.pid() == pid_b)
        .collect();
    assert_eq!(views_b.len(), 1, "the quiet tick keeps the later child");
    assert_eq!(
        views_b[0].id(),
        id_b,
        "the quiet tick holds the later child's view ID steady"
    );
    assert_eq!(
        system_scope_slots_for(&engine, "refresh-second.so"),
        slots_b,
        "the quiet tick attaches no duplicate later-child slot"
    );
    assert_eq!(
        system_scope_slots_for(&engine, "refresh-first.so"),
        slots_a,
        "the quiet tick keeps the first child's attributed slots"
    );

    // Reap the later child through its owned guard — `wait` proves the
    // owned generation ended — then the next refresh retires B while A
    // remains fully intact.
    let status_b = child_b
        .reap()
        .expect("reap the later child through its owned guard");
    assert!(
        !status_b.success(),
        "the owned later generation ended by signal, not by silent exit: {status_b:?}"
    );
    // Same transient-preflight retry as the admission tick: repeat the
    // refresh until the reaped generation's view is gone.
    for _ in 0..25 {
        let mut collect: Box<DiscoveryCollector<'_>> = Box::new(Engine::collect_discovery_records);
        engine
            .refresh_inventory(
                &mut session,
                &mut true,
                &mut Vec::new(),
                &mut PendingViewRetirements::new(),
                &mut *collect,
                &mut PauseClosure::new(true),
            )
            .expect("the refresh after the owned reap applies");
        if engine.views.iter().all(|view| view.id() != id_b) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        engine.views.iter().all(|view| view.id() != id_b),
        "the reaped generation's view is retired, not retained"
    );
    let views_a: Vec<_> = engine
        .views
        .iter()
        .filter(|view| view.pid() == pid_a)
        .collect();
    assert_eq!(views_a.len(), 1, "the first child remains after the reap");
    assert_eq!(
        views_a[0].id(),
        id_a,
        "the first child keeps its view ID after the reap"
    );
    assert!(
        views_a[0].still_the_same(),
        "the first child's generation is still current after the reap"
    );
    assert!(
        engine.scan_inputs.get(&id_a).is_some_and(|scan| {
            scan.modules
                .iter()
                .any(|module| module.path.ends_with("refresh-first.so"))
        }),
        "the first child's scan input remains after the reap"
    );
    assert!(
        engine
            .pinned()
            .view_claims(id_a)
            .is_some_and(|claims| !claims.pins.is_empty()),
        "the first child keeps its ownership and pinned claims after the reap"
    );
    assert_eq!(
        system_scope_slots_for(&engine, "refresh-first.so"),
        slots_a,
        "the first child's attributed slots remain after the reap"
    );
}

/// Task 1.1: publication evidence orders candidate tables — a table named by
/// an interface triple sorts before an unlinked lookalike, even when the
/// lookalike was discovered first. Synthetic tables only; no live processes.
#[test]
fn linked_candidate_table_sorts_before_unlinked_lookalike() {
    let tables = [
        ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: Vec::new(),
            null_entries: Vec::new(),
            unpinned: Vec::new(),
            address: 0x7000,
            file_offset: Some(0x1000),
            live_return: false,
            manifest_supported: false,
        },
        ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: Vec::new(),
            null_entries: Vec::new(),
            unpinned: Vec::new(),
            address: 0x7800,
            file_offset: Some(0x1800),
            live_return: false,
            manifest_supported: false,
        },
    ];
    let interfaces = [ScannedInterface {
        index: 0,
        name_class: "exact_standard",
        name_lossy: None,
        name_private: Some(b"PKCS 11".to_vec()),
        flags: 0,
        table: Some(1),
    }];

    let order = order_tables_by_evidence(&tables, &interfaces, &[], &[]);

    assert_eq!(
        order,
        vec![1, 0],
        "the interface-linked table sorts before the unlinked lookalike"
    );
}

/// Task 1.2 fixture: the sysprobe 64-table replica as a checked-in synthetic
/// module for the resource-bound test. `docs/sysprobe-2026-09-19/replicate_scan.py`
/// proved one `libp11-kit.so.0.4.8` instance decodes as 64 consecutive 840-byte
/// 3.2 closure templates (file `0x1caf20 + k*840`), each with 104 non-null
/// pointers into `.text` — 6656 entry records that refuse the whole module at
/// the 512 ceiling today. Entry offsets are all distinct (the replica's real
/// duplicates are pointer-value accidents, not structure), so the pre-fix
/// wanted set is 6656 and the module refuses; the resource bound must admit 4
/// tables' worth of slots and spill 60 candidates as evidence instead.
///
/// The single interface triple links the LAST table (index 63): evidence
/// order must admit it despite discovery-last position, while the other
/// three admitted tables stay unlinked — linkage is preferred, never gated,
/// so scan-only capture of never-called legacy providers keeps working. The
/// linked table bypasses the per-object heuristic cap; the global resource
/// bound still limits the total to 4 tables (416 slots).
fn p11kit_like_64_table_module() -> ScannedModule {
    const TABLES: u64 = 64;
    const ENTRIES: u64 = 104;
    const NAMES: [&str; 8] = [
        "C_Initialize",
        "C_Finalize",
        "C_GetInfo",
        "C_GetFunctionList",
        "C_GetSlotList",
        "C_GetSlotInfo",
        "C_GetTokenInfo",
        "C_Sign",
    ];
    let mut raw = overlay_module(overlay_key(57));
    raw.tables = (0..TABLES)
        .map(|table| ScannedTable {
            version: (3, 2),
            walk: "full",
            entries: (0..ENTRIES)
                .map(|entry| {
                    let ordinal = table * ENTRIES + entry;
                    ScannedEntry {
                        name: NAMES[(ordinal % NAMES.len() as u64) as usize],
                        object: raw.key,
                        object_path: raw.path.clone(),
                        file_offset: 0x10000 + ordinal * 8,
                    }
                })
                .collect(),
            null_entries: vec![],
            unpinned: vec![],
            address: 0x7f00_0000 + table * 840,
            file_offset: Some(0x1caf20 + table * 840),
            live_return: false,
            manifest_supported: false,
        })
        .collect();
    raw.interfaces = vec![ScannedInterface {
        index: 0,
        name_class: "exact_standard",
        name_lossy: None,
        name_private: Some(b"PKCS 11".to_vec()),
        flags: 0,
        table: Some(63),
    }];
    raw
}

/// Task 1.2 resource-bound test: ordered admission with a per-object cap.
/// The 64-table replica must NOT refuse the module. The linked table bypasses
/// the independent K=4 heuristic cap; the global slot bound admits three
/// heuristic tables at 512 or all four at 2112. Every spill stays explicit.
#[test]
fn ordered_admission_resource_bound_caps_heuristic_tables_per_object() {
    let admitted_heuristics = if cfg!(feature = "wide-detailed-2112") {
        4u64
    } else {
        3u64
    };
    let expected_slots = ((admitted_heuristics + 1) * 104) as usize;
    let expected_spill = 63 - admitted_heuristics;
    let raw = p11kit_like_64_table_module();
    let mut pins = overlay_pins(&[(raw.key, OVERLAY_SHA, 1)]);
    let (modules, skipped) = bind_scanned_modules(std::slice::from_ref(&raw), &mut pins);
    assert!(skipped.is_empty(), "{skipped:?}");
    let plan = plan::build_from_reconciled_modules(&modules);

    assert!(
        plan.modules_skipped.is_empty(),
        "the 64-table module stays admitted under the resource bound, not refused: {:?}",
        plan.modules_skipped
    );
    assert_eq!(
        plan.slots.len(),
        expected_slots,
        "linked plus admitted heuristic tables become slots under the selected resource bound"
    );
    assert_eq!(
        plan.uncorroborated_candidates, expected_spill,
        "resource-bound spill is counted, never slotted"
    );
    assert_eq!(
        plan.entries_seen, 6656,
        "seen counts every decoded record under the resource bound, admitted or spilled"
    );

    // Evidence order, not discovery order: the linked table (index 63,
    // decoded last) is admitted via the published bypass; the unlinked
    // tables fill the selected bound and the remainder spills.
    let attached: BTreeSet<u64> = plan.slots.iter().map(|slot| slot.file_offset).collect();
    for table in 0..64u64 {
        let first_entry = 0x10000 + table * 104 * 8;
        assert_eq!(
            attached.contains(&first_entry),
            table < admitted_heuristics || table == 63,
            "table {table} admission follows evidence order under the resource bound"
        );
    }

    // The spill reaches discovery evidence through the publish path, beside
    // the admitted module — never silence, never a refusal.
    let mut engine = Engine::empty();
    engine.plan = plan;
    engine.pinned = pins;
    engine.modules = modules;
    engine
        .capture_facts
        .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
        .unwrap();
    engine.publish_current_capture_facts().unwrap();
    assert_eq!(engine.discovery.modules.len(), 1);
    assert!(engine.discovery.modules_skipped.is_empty());
    assert_eq!(
        engine.discovery.uncorroborated_candidates, expected_spill,
        "published evidence carries the resource-bound spill count"
    );
}

/// Task 1.3 mislabel guard on the 64-table replica: every admitted
/// unlinked tables' slots are named `unknown` — never the ordinal PKCS#11
/// labels — while the linked table keeps its names. Every table carries
/// (file_offset, entry count, linkage kind) into published evidence.
#[test]
fn admitted_heuristic_tables_are_unknown_with_provenance() {
    let admitted_heuristics = if cfg!(feature = "wide-detailed-2112") {
        4u64
    } else {
        3u64
    };
    let raw = p11kit_like_64_table_module();
    let mut pins = overlay_pins(&[(raw.key, OVERLAY_SHA, 1)]);
    let (modules, skipped) = bind_scanned_modules(std::slice::from_ref(&raw), &mut pins);
    assert!(skipped.is_empty(), "{skipped:?}");
    let plan = plan::build_from_reconciled_modules(&modules);

    // All admitted unlinked slots, not just the
    // first entries: no ordinal label may survive on an unlinked table.
    let unknown: BTreeSet<u64> = plan
        .slots
        .iter()
        .filter(|slot| slot.names == ["unknown"])
        .map(|slot| slot.file_offset)
        .collect();
    for table in 0..admitted_heuristics {
        for entry in 0..104u64 {
            let offset = 0x10000 + (table * 104 + entry) * 8;
            assert!(
                unknown.contains(&offset),
                "table {table} entry {entry} must be unknown, never an ordinal label"
            );
        }
    }
    assert_eq!(unknown.len(), (admitted_heuristics * 104) as usize);
    assert_eq!(plan.slots.len(), ((admitted_heuristics + 1) * 104) as usize);

    // Table 63 is interface-linked: ordinal 63*104 % 8 == 0 keeps C_Initialize.
    let linked = plan
        .slots
        .iter()
        .find(|slot| slot.file_offset == 0x10000 + 63 * 104 * 8)
        .unwrap();
    assert_eq!(linked.names, ["C_Initialize"]);

    let tables = &plan.modules[0].tables;
    assert_eq!(tables.len(), 64);
    for (index, table) in tables.iter().enumerate() {
        assert_eq!(
            table.file_offset,
            Some(0x1caf20 + index as u64 * 840),
            "table {index} carries its version-word file offset"
        );
        assert_eq!(table.entries, 104);
        assert_eq!(
            table.linkage,
            if index == 63 {
                "interface"
            } else {
                "heuristic"
            },
            "table {index} carries its linkage kind"
        );
    }

    // The provenance reaches discovery evidence through the publish path.
    let mut engine = Engine::empty();
    engine.plan = plan;
    engine.pinned = pins;
    engine.modules = modules;
    engine
        .capture_facts
        .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
        .unwrap();
    engine.publish_current_capture_facts().unwrap();
    let published = &engine.discovery.modules[0].tables;
    assert_eq!(published.len(), 64);
    for (index, table) in published.iter().enumerate() {
        assert_eq!(table.file_offset, Some(0x1caf20 + index as u64 * 840));
        assert_eq!(
            table.linkage,
            if index == 63 {
                "interface"
            } else {
                "heuristic"
            }
        );
    }
}

/// Task 1.3: a table returned by a live provider export carries publication
/// evidence — it keeps its ordinal names and bypasses the unresolved-heuristic
/// cap exactly like an interface-linked table.
#[test]
fn live_return_tables_keep_names_and_bypass_the_heuristic_cap() {
    const TABLES: usize = 6;
    const ENTRIES: usize = 4;
    let mut raw = overlay_module(overlay_key(61));
    raw.tables = (0..TABLES)
        .map(|table| ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: (0..ENTRIES)
                .map(|entry| {
                    let ordinal = (table * ENTRIES + entry) as u64;
                    ScannedEntry {
                        name: "C_Sign",
                        object: raw.key,
                        object_path: raw.path.clone(),
                        file_offset: 0x40000 + ordinal * 8,
                    }
                })
                .collect(),
            null_entries: vec![],
            unpinned: vec![],
            address: 0x7f00_1000 + table as u64 * 0x1000,
            file_offset: Some(0x90000 + table as u64 * 0x1000),
            live_return: table == 5,
            manifest_supported: false,
        })
        .collect();
    raw.interfaces = vec![];
    let mut pins = overlay_pins(&[(raw.key, OVERLAY_SHA, 1)]);
    let (modules, skipped) = bind_scanned_modules(std::slice::from_ref(&raw), &mut pins);
    assert!(skipped.is_empty(), "{skipped:?}");
    let plan = plan::build_from_reconciled_modules(&modules);

    // Four heuristic tables fill K=4, the live-return table bypasses it, and
    // the fifth heuristic table spills as evidence.
    assert!(
        plan.modules_skipped.is_empty(),
        "{:?}",
        plan.modules_skipped
    );
    assert_eq!(plan.slots.len(), 5 * ENTRIES);
    assert_eq!(plan.uncorroborated_candidates, 1);
    let names_of = |table: usize| {
        plan.slots
            .iter()
            .find(|slot| slot.file_offset == 0x40000 + (table * ENTRIES) as u64 * 8)
            .unwrap()
            .names
            .clone()
    };
    for table in 0..4 {
        assert_eq!(names_of(table), ["unknown"]);
    }
    assert_eq!(names_of(5), ["C_Sign"]);
    let tables = &plan.modules[0].tables;
    assert_eq!(tables.len(), 6);
    assert_eq!(tables[5].linkage, "live_return");
    assert!(
        tables[..5].iter().all(|table| table.linkage == "heuristic"),
        "{tables:?}"
    );
}

/// Task 1.2 (a): five disjoint published 2.40 tables bypass the per-object
/// heuristic cap. Each table is interface-linked (published), so K=4 does not
/// apply; with sufficient global budget all 340 slots admit and nothing spills.
#[test]
fn published_tables_bypass_heuristic_cap_with_sufficient_budget() {
    const TABLES: u64 = 5;
    const ENTRIES: u64 = 68;
    const NAMES: [&str; 8] = [
        "C_Initialize",
        "C_Finalize",
        "C_GetInfo",
        "C_GetFunctionList",
        "C_GetSlotList",
        "C_GetSlotInfo",
        "C_GetTokenInfo",
        "C_Sign",
    ];
    let mut raw = overlay_module(overlay_key(57));
    raw.tables = (0..TABLES)
        .map(|table| ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: (0..ENTRIES)
                .map(|entry| {
                    let ordinal = table * ENTRIES + entry;
                    ScannedEntry {
                        name: NAMES[(ordinal % NAMES.len() as u64) as usize],
                        object: raw.key,
                        object_path: raw.path.clone(),
                        file_offset: 0x30000 + ordinal * 8,
                    }
                })
                .collect(),
            null_entries: vec![],
            unpinned: vec![],
            address: 0x7f10_0000 + table * 0x1000,
            file_offset: Some(0x20000 + table * 0x1000),
            live_return: false,
            manifest_supported: false,
        })
        .collect();
    raw.interfaces = (0..TABLES as usize)
        .map(|index| ScannedInterface {
            index,
            name_class: "exact_standard",
            name_lossy: None,
            name_private: Some(b"PKCS 11".to_vec()),
            flags: 0,
            table: Some(index),
        })
        .collect();

    let mut pins = overlay_pins(&[(raw.key, OVERLAY_SHA, 1)]);
    let (modules, skipped) = bind_scanned_modules(std::slice::from_ref(&raw), &mut pins);
    assert!(skipped.is_empty(), "{skipped:?}");
    let plan = plan::build_from_reconciled_modules(&modules);

    assert!(
        plan.modules_skipped.is_empty(),
        "five published tables fit the global budget and must admit: {:?}",
        plan.modules_skipped
    );
    assert_eq!(
        plan.slots.len(),
        340,
        "5 published tables x 68 entries all admit past the heuristic cap"
    );
    assert_eq!(
        plan.uncorroborated_candidates, 0,
        "published tables never spill as uncorroborated"
    );
    assert_eq!(plan.entries_seen, 340, "seen counts every published record");
    assert_eq!(plan.modules.len(), 1);
    assert_eq!(
        plan.modules[0].interfaces, 5,
        "all five published interfaces stay visible"
    );

    // Every table admitted: the first entry of each is slotted.
    let attached: BTreeSet<u64> = plan.slots.iter().map(|slot| slot.file_offset).collect();
    for table in 0..TABLES {
        let first_entry = 0x30000 + table * ENTRIES * 8;
        assert!(
            attached.contains(&first_entry),
            "published table {table} admits despite the heuristic cap"
        );
    }
}

/// Task 1.2 (b): the global budget still refuses atomically. With
/// MAX_SLOTS-112 already admitted, a module needing 136 new targets is
/// refused whole; a later small module still fits in the remaining budget.
#[test]
fn global_budget_refuses_oversized_module_atomically_and_admits_later_small_module() {
    fn heuristic_module(
        minor: u64,
        tables: usize,
        entries_per_table: usize,
        entry_base: u64,
    ) -> ScannedModule {
        const NAMES: [&str; 8] = [
            "C_Initialize",
            "C_Finalize",
            "C_GetInfo",
            "C_GetFunctionList",
            "C_GetSlotList",
            "C_GetSlotInfo",
            "C_GetTokenInfo",
            "C_Sign",
        ];
        let mut raw = overlay_module(overlay_key(minor));
        raw.tables = (0..tables)
            .map(|table| ScannedTable {
                version: (3, 2),
                walk: "full",
                entries: (0..entries_per_table)
                    .map(|entry| {
                        let ordinal = (table * entries_per_table + entry) as u64;
                        ScannedEntry {
                            name: NAMES[(ordinal % NAMES.len() as u64) as usize],
                            object: raw.key,
                            object_path: raw.path.clone(),
                            file_offset: entry_base + ordinal * 8,
                        }
                    })
                    .collect(),
                null_entries: vec![],
                unpinned: vec![],
                address: 0x7f00_0000 + minor * 0x100000 + table as u64 * 0x1000,
                file_offset: Some(0x50000 + minor * 0x10000 + table as u64 * 0x1000),
                live_return: false,
                manifest_supported: false,
            })
            .collect();
        raw.interfaces = vec![];
        raw
    }

    // Four heuristic tables fill all but 112 slots in either profile.
    let filler_per_table = (p11scope_ebpf_common::MAX_SLOTS as usize - 112) / 4;
    let filler_slots = 4 * filler_per_table;
    assert_eq!(filler_slots + 112, p11scope_ebpf_common::MAX_SLOTS as usize);
    let filler = heuristic_module(57, 4, filler_per_table, 0x100000);
    // Oversized: 1 heuristic table x 136 entries; 136 > 112 remaining.
    let oversized = heuristic_module(58, 1, 136, 0x200000);
    // Small: 1 heuristic table x 2 entries; fits after the refusal.
    let small = heuristic_module(59, 1, 2, 0x300000);

    let mut pins = overlay_pins(&[
        (filler.key, OVERLAY_SHA, 1),
        (oversized.key, OVERLAY_SHA, 1),
        (small.key, OVERLAY_SHA, 1),
    ]);
    let raws = [filler, oversized, small];
    let (modules, skipped) = bind_scanned_modules(&raws, &mut pins);
    assert!(skipped.is_empty(), "{skipped:?}");
    assert_eq!(modules.len(), 3);
    let plan = plan::build_from_reconciled_modules(&modules);

    assert_eq!(
        plan.slots.len(),
        filler_slots + 2,
        "filler plus small admit; the oversized 136 leave no prefix"
    );
    assert_eq!(
        plan.modules.len(),
        2,
        "only the filler and the small module admit"
    );
    assert_eq!(
        plan.modules_skipped.len(),
        1,
        "the oversized module is refused whole: {:?}",
        plan.modules_skipped
    );
    assert!(
        plan.modules_skipped[0].reason.contains("136")
            && plan.modules_skipped[0]
                .reason
                .contains(&format!("{filler_slots} are in use")),
        "refusal names the need and the budget: {:?}",
        plan.modules_skipped[0]
    );
    assert_eq!(
        plan.uncorroborated_candidates, 0,
        "refusal is atomic, not a spill"
    );
    assert_eq!(
        plan.entries_seen,
        filler_slots + 138,
        "seen counts filler + oversized 136 + small 2 despite refusal"
    );

    let attached: BTreeSet<u64> = plan.slots.iter().map(|slot| slot.file_offset).collect();
    assert!(
        attached.contains(&0x100000),
        "filler admits its first entry"
    );
    assert!(
        attached.contains(&0x300000),
        "the later small module still fits after the refusal"
    );
    for offset in (0..136u64).map(|i| 0x200000 + i * 8) {
        assert!(
            !attached.contains(&offset),
            "refused module leaves no prefix at offset {offset:#x}"
        );
    }
}

/// Task 1.2 (c): two ASLR/process views of one provider share ONE per-object
/// cap. Both views decode the same 6 tables (same file offsets, different
/// runtime addresses); distinct tables admit once, scored by the strongest
/// instance, so linkage seen in any view counts. Entry bindings, interface
/// indexes, and exact target pins are preserved per view.
#[test]
fn two_views_share_one_per_object_cap_preserving_pins_and_interfaces() {
    const TABLES: u64 = 6;
    const ENTRIES: u64 = 10;
    const NAMES: [&str; 8] = [
        "C_Initialize",
        "C_Finalize",
        "C_GetInfo",
        "C_GetFunctionList",
        "C_GetSlotList",
        "C_GetSlotInfo",
        "C_GetTokenInfo",
        "C_Sign",
    ];
    let key = overlay_key(57);
    let template = overlay_module(key);

    // View 1 links the last table; view 2 links nothing, proving linkage
    // observed from any view corroborates the distinct table.
    let mut view1 = template.clone();
    view1.view = ProcessViewId(100);
    view1.tables = (0..TABLES)
        .map(|table| ScannedTable {
            version: (3, 2),
            walk: "full",
            entries: (0..ENTRIES)
                .map(|entry| {
                    let ordinal = table * ENTRIES + entry;
                    ScannedEntry {
                        name: NAMES[(ordinal % NAMES.len() as u64) as usize],
                        object: key,
                        object_path: view1.path.clone(),
                        file_offset: 0x20000 + ordinal * 8,
                    }
                })
                .collect(),
            null_entries: vec![],
            unpinned: vec![],
            address: 0x7f00_0000 + table * 840,
            file_offset: Some(0x1caf20 + table * 840),
            live_return: false,
            manifest_supported: false,
        })
        .collect();
    view1.interfaces = vec![ScannedInterface {
        index: 0,
        name_class: "exact_standard",
        name_lossy: None,
        name_private: Some(b"PKCS 11".to_vec()),
        flags: 0,
        table: Some(5),
    }];

    let mut view2 = template.clone();
    view2.view = ProcessViewId(101);
    view2.tables = (0..TABLES)
        .map(|table| ScannedTable {
            version: (3, 2),
            walk: "full",
            entries: (0..ENTRIES)
                .map(|entry| {
                    let ordinal = table * ENTRIES + entry;
                    ScannedEntry {
                        name: NAMES[(ordinal % NAMES.len() as u64) as usize],
                        object: key,
                        object_path: view2.path.clone(),
                        file_offset: 0x20000 + ordinal * 8,
                    }
                })
                .collect(),
            null_entries: vec![],
            unpinned: vec![],
            address: 0x7f80_0000 + table * 840,
            file_offset: Some(0x1caf20 + table * 840),
            live_return: false,
            manifest_supported: false,
        })
        .collect();
    view2.interfaces = vec![];

    let mut pins = overlay_pins(&[(key, OVERLAY_SHA, 1)]);
    let (modules, skipped) = bind_scanned_modules(&[view1, view2], &mut pins);
    assert!(skipped.is_empty(), "{skipped:?}");
    assert_eq!(modules.len(), 2);
    assert_eq!(
        modules[0].object, modules[1].object,
        "two views of one provider bind one pinned object"
    );
    let object = modules[0].object;

    // Entry bindings preserved per view: 6 tables x 10 entries, same object.
    for (view, module) in modules.iter().enumerate() {
        assert_eq!(
            module.entry_objects.len(),
            6,
            "view {view} keeps 6 tables of entry bindings"
        );
        for (table, ids) in module.entry_objects.iter().enumerate() {
            assert_eq!(ids.len(), 10, "view {view} table {table} keeps 10 bindings");
            for id in ids {
                assert_eq!(*id, object, "view {view} table {table} pins the provider");
            }
        }
    }
    // Interface indexes preserved: view 1 links table 5 at index 0.
    assert_eq!(modules[0].scanned.interfaces.len(), 1);
    assert_eq!(modules[0].scanned.interfaces[0].index, 0);
    assert_eq!(modules[0].scanned.interfaces[0].table, Some(5));
    assert!(modules[1].scanned.interfaces.is_empty());
    // ASLR: same file offsets, different runtime addresses.
    assert_eq!(
        modules[0].scanned.tables[0].file_offset, modules[1].scanned.tables[0].file_offset,
        "same provider, same table file offsets"
    );
    assert_ne!(
        modules[0].scanned.tables[0].address, modules[1].scanned.tables[0].address,
        "ASLR remaps runtime addresses across views"
    );

    let plan = plan::build_from_reconciled_modules(&modules);

    assert_eq!(plan.modules.len(), 1, "one object is one module");
    assert!(
        plan.modules_skipped.is_empty(),
        "shared cap admits, never refuses: {:?}",
        plan.modules_skipped
    );
    assert_eq!(
        plan.slots.len(),
        50,
        "1 published x 10 + 4 heuristic x 10 admit under the shared cap"
    );
    assert_eq!(
        plan.uncorroborated_candidates, 1,
        "6 distinct tables (1 published + 5 heuristic) spill 1 under one shared cap, not per-view"
    );
    assert_eq!(
        plan.entries_seen, 60,
        "seen counts distinct records once across views"
    );
    assert_eq!(
        plan.modules[0].interfaces, 1,
        "interfaces take the max across views, never the sum"
    );
    assert!(
        plan.surfaces
            .iter()
            .any(|surface| surface.source == "interface[0] exact_standard"),
        "interface index 0 survives the shared-cap admission: {:?}",
        plan.surfaces
    );

    // Admitted: tables 0,1,2,3 (heuristic prefix) + 5 (published via any-view
    // linkage). Spilled: table 4.
    let attached: BTreeSet<u64> = plan.slots.iter().map(|slot| slot.file_offset).collect();
    for table in 0..TABLES {
        let first_entry = 0x20000 + table * ENTRIES * 8;
        assert_eq!(
            attached.contains(&first_entry),
            table != 4,
            "table {table} admission follows the shared evidence order"
        );
    }
    for slot in &plan.slots {
        assert_eq!(
            slot.object, object,
            "every slot pins the exact provider object"
        );
    }
}

// Audit F5/F7 spill-then-settle publication pair: five distinct one-target
// heuristic tables, four admitted under K=4, one omitted; the second
// publication corroborates the fifth table with a live return and rebuilds
// through the same stable-ID extension path the engine uses.
fn spill_history_engine() -> (Engine, ScannedModule) {
    let mut raw = p11kit_like_64_table_module();
    raw.tables.truncate(5);
    for table in &mut raw.tables {
        table.entries.truncate(1);
    }
    raw.interfaces.clear();
    let mut engine = Engine::empty();
    engine.pinned = overlay_pins(&[(raw.key, OVERLAY_SHA, 1)]);
    let (modules, skipped) = bind_scanned_modules(std::slice::from_ref(&raw), &mut engine.pinned);
    assert!(skipped.is_empty());
    engine.plan = plan::build_from_reconciled_modules(&modules);
    engine.modules = modules;
    engine
        .capture_facts
        .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
        .unwrap();
    engine.publish_current_capture_facts().unwrap();
    (engine, raw)
}

fn publish_fifth_table_live(engine: &mut Engine, mut raw: ScannedModule) {
    raw.tables[4].live_return = true;
    let (modules, skipped) = bind_scanned_modules(&[raw], &mut engine.pinned);
    assert!(skipped.is_empty());
    let mut rebuilt = plan::build_from_reconciled_modules(&modules);
    engine
        .capture_facts
        .bind_plan_module_ids(&mut rebuilt, &modules, &[], &engine.pinned)
        .unwrap();
    engine
        .plan
        .extend_exact_with_stable_module_ids(rebuilt)
        .unwrap();
    engine.modules = modules;
    engine.publish_current_capture_facts().unwrap();
}

/// Audit F5: published spill evidence is capture-lifetime, the plan counter
/// stays current-state. The fifth table spills past K=4, then a live return
/// bypasses it and the rebuild settles: the plan resolves to 0 while the
/// published evidence still reports the earlier omission.
#[test]
fn spill_history_retains_earlier_omission_after_live_merge() {
    let (mut engine, raw) = spill_history_engine();
    assert_eq!(engine.plan.uncorroborated_candidates, 1);
    assert_eq!(engine.discovery.uncorroborated_candidates, 1);
    assert_eq!(engine.plan.slots.len(), 4);
    publish_fifth_table_live(&mut engine, raw);
    assert_eq!(engine.plan.slots.len(), 5);
    assert_eq!(
        engine.plan.uncorroborated_candidates, 0,
        "the live merge resolves the current-inventory spill"
    );
    assert_eq!(
        engine.discovery.uncorroborated_candidates, 1,
        "earlier omitted table disappeared from lifetime evidence"
    );
}

/// Audit F7: public table provenance follows a later live publication. The
/// fifth table is first seen heuristic, then corroborated by a live return:
/// the published history must upgrade to `live_return`, not keep whichever
/// linkage was inserted first.
#[test]
fn public_linkage_reflects_later_live_publication() {
    let (mut engine, raw) = spill_history_engine();
    let offset = raw.tables[4].file_offset;
    publish_fifth_table_live(&mut engine, raw);
    let current = engine.plan.modules[0]
        .tables
        .iter()
        .find(|table| table.file_offset == offset)
        .unwrap();
    let public = engine.discovery.modules[0]
        .tables
        .iter()
        .find(|table| table.file_offset == offset)
        .unwrap();
    assert_eq!(current.linkage, "live_return");
    assert_eq!(
        public.linkage, "live_return",
        "current publication proof is hidden by initial heuristic history"
    );
}

/// Audit F7 converse: provenance never downgrades. A third publication that
/// no longer carries the live proof (a view retired with it) leaves the
/// corroborated public linkage in place.
#[test]
fn public_linkage_never_downgrades_after_proof_retires() {
    let (mut engine, raw) = spill_history_engine();
    let offset = raw.tables[4].file_offset;
    publish_fifth_table_live(&mut engine, raw.clone());
    let public = engine.discovery.modules[0]
        .tables
        .iter()
        .find(|table| table.file_offset == offset)
        .unwrap();
    assert_eq!(public.linkage, "live_return");
    republish_all_heuristic(&mut engine, raw);
    let public = engine.discovery.modules[0]
        .tables
        .iter()
        .find(|table| table.file_offset == offset)
        .unwrap();
    assert_eq!(
        public.linkage, "live_return",
        "a less-informed later reading revoked observed publication proof"
    );
}

fn republish_all_heuristic(engine: &mut Engine, raw: ScannedModule) {
    let (modules, skipped) = bind_scanned_modules(&[raw], &mut engine.pinned);
    assert!(skipped.is_empty());
    let mut rebuilt = plan::build_from_reconciled_modules(&modules);
    engine
        .capture_facts
        .bind_plan_module_ids(&mut rebuilt, &modules, &[], &engine.pinned)
        .unwrap();
    engine
        .plan
        .extend_exact_with_stable_module_ids(rebuilt)
        .unwrap();
    engine.modules = modules;
    engine.publish_current_capture_facts().unwrap();
}

// SYSPLAN Package B (E07/E09): preserve coverage through incomplete scans.
//
// The fixture below is a gcc-built provider look-alike with one planted
// function table and NO hook exports: hint-scoped scans of this process see
// it, while hintless full scans skip it for lack of exports — so it is
// invisible to every other test scanning this process.
const E07_TABLE_WORDS: usize = 105;

extern "C" fn e07_anchor() {}

struct E07Provider {
    _dir: tempfile::TempDir,
    path: PathBuf,
    handle: *mut std::ffi::c_void,
    table: *mut u64,
}

impl E07Provider {
    fn dlopen() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let c = dir.path().join("provider.c");
        let path = dir.path().join("provider.so");
        std::fs::write(
            &c,
            "unsigned long p11scope_e07_table[105] = { 1 };\n\
             unsigned long p11scope_e07_iface[3] = { 4, 5, 6 };\n\
             char p11scope_e07_name[8] = \"PKCS 11\";\n",
        )
        .unwrap();
        let status = std::process::Command::new("gcc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&path)
            .arg(&c)
            .status()
            .unwrap();
        assert!(status.success(), "the fixture provider must compile");
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: an owned file just written by this test; RTLD_LOCAL keeps
        // its symbols out of every other test in this process.
        let handle = unsafe { libc::dlopen(cpath.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        assert!(!handle.is_null(), "the fixture provider must load");
        let symbol = |name: &str| {
            let name = std::ffi::CString::new(name).unwrap();
            // SAFETY: the symbols are the arrays above; the handle stays
            // open until Drop, and only this thread writes through them.
            (unsafe { libc::dlsym(handle, name.as_ptr()) }) as *mut u64
        };
        let table = symbol("p11scope_e07_table");
        let iface = symbol("p11scope_e07_iface");
        let name = symbol("p11scope_e07_name");
        assert!(
            !table.is_null() && !iface.is_null() && !name.is_null(),
            "the planted records must resolve"
        );
        let words = unsafe { std::slice::from_raw_parts_mut(table, E07_TABLE_WORDS) };
        words[0] = 0x2802; // CK_VERSION { major 2, minor 40 }.
        for word in &mut words[1..] {
            *word = e07_anchor as usize as u64;
        }
        // The interface triple linking the table: publication evidence, so
        // the plan authorizes the table's endpoints.
        let triple = unsafe { std::slice::from_raw_parts_mut(iface, 3) };
        triple[0] = name as u64;
        triple[1] = table as u64;
        triple[2] = 0;
        Self {
            _dir: dir,
            path,
            handle,
            table,
        }
    }

    /// Zero the version word: the next scan finds the module with no table.
    fn zero_version(&self) {
        unsafe { self.table.write(0) };
    }
}

impl Drop for E07Provider {
    fn drop(&mut self) {
        unsafe { libc::dlclose(self.handle) };
    }
}

fn e07_engine() -> Engine {
    let pid = std::process::id();
    let view = ProcessView::open(ProcessViewId(0), pid).unwrap();
    let mut engine = Engine::empty();
    engine.scope = Scope::Pid(pid);
    engine.views.push(view);
    engine.next_view_id = 1;
    engine.budget = CaptureWorkBudget::new(ScanLimits {
        per_object_bytes: u64::MAX,
        total_bytes: u64::MAX,
    });
    engine
}

/// A loader context over a stably pinned loader object (this test
/// binary): the loader id must resolve in every candidate's pins, so it is
/// pinned once here and never rescanned.
fn e07_loader_context(engine: &mut Engine, view: ProcessViewId) -> LoaderContextId {
    use p11scope_manifest::elf::SymbolFact;

    let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
    let map_index = MapIndex::new(&maps).expect("the self maps snapshot is valid");
    let executable = std::env::current_exe().unwrap();
    let (loader_mapping, loader_path) = maps
        .iter()
        .filter(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
        .find_map(|mapping| match map_index.resolve(mapping.start) {
            Resolved::File {
                path: MappedPath::Usable(path),
                ..
            } if path == executable => Some((mapping, path)),
            _ => None,
        })
        .expect("the test process maps its own executable");
    let view_ref = engine
        .views
        .iter()
        .find(|retained| retained.id() == view)
        .expect("the engine retains the view");
    let loader_module = mapped_object(view_ref, loader_mapping, &loader_path);
    let loader_pins = pin_test_module(view_ref, &loader_module);
    let absorb_skips = engine.pinned.absorb(loader_pins);
    assert!(absorb_skips.is_empty(), "{absorb_skips:?}");
    let loader = engine
        .pinned
        .id_for_scanned(&loader_module, loader_module.key, &loader_module.path)
        .expect("the loader pin resolves");
    let prepared = engine
        .loader_registry
        .preflight(LoaderContextSpec {
            view,
            loader,
            mapping: None,
            hook: SymbolFact {
                virtual_address: 0x2100,
                file_offset: 0x2100,
            },
            state_address: None,
        })
        .expect("a preflighted loader context");
    let context = engine
        .loader_registry
        .prepare(prepared)
        .expect("a prepared loader context");
    engine
        .loader_registry
        .mark_attached(context)
        .expect("an attached loader context");
    context
}

fn e07_rescan(
    engine: &mut Engine,
    session: &mut ScriptedSession,
    context: LoaderContextId,
    additions: &mut bool,
    pending: &mut PendingViewRetirements,
) -> DiscoveryRecordOutcome {
    engine
        .process_validated_loader_scan(
            0,
            context,
            1_000_000,
            None,
            &[],
            LoaderScanMode::Memory,
            session,
            additions,
            pending,
        )
        .expect("a live loader rescan applies")
}

/// Active (object, file offset) targets: the covered-endpoint set.
fn e07_active_targets(engine: &Engine) -> BTreeSet<(PinnedObjectId, u64)> {
    engine
        .plan
        .slots
        .iter()
        .filter(|slot| engine.plan.is_active(slot.index))
        .map(|slot| (slot.object, slot.file_offset))
        .collect()
}

/// E07: an unchanged complete loader rescan retires nothing. The direct scan
/// reports complete, and the rescan is a no-op: same tables, same slots,
/// no detaches.
#[test]
fn e07_unchanged_complete_loader_rescan_retires_nothing() {
    let provider = E07Provider::dlopen();
    let mut engine = e07_engine();
    engine.module_hints = vec![provider.path.clone()];
    let view_id = engine.views[0].id();
    let context = e07_loader_context(&mut engine, view_id);
    let mut session = ScriptedSession::default();
    let mut additions = true;
    let mut pending = PendingViewRetirements::new();

    let outcome = e07_rescan(
        &mut engine,
        &mut session,
        context,
        &mut additions,
        &mut pending,
    );
    assert!(outcome.changed(), "the first scan attaches its tables");
    let attached = e07_active_targets(&engine);
    assert!(!attached.is_empty(), "the planted table is covered");
    assert_eq!(session.attached_slots.len(), 1);

    // A direct scan of the unchanged view is complete: verified absence.
    let (scan_result, _) = Engine::scan_retained_view(
        &engine.views[0],
        &engine.module_hints,
        &engine.hooks,
        &mut engine.budget,
        false,
    );
    let (found, _, complete) = scan_result.expect("the view still scans");
    assert!(complete, "an unchanged full scan is complete");
    assert_eq!(found.len(), 1);
    assert!(!found[0].tables.is_empty());

    // And the loader rescan through the engine is a no-op.
    let outcome = e07_rescan(
        &mut engine,
        &mut session,
        context,
        &mut additions,
        &mut pending,
    );
    assert!(!outcome.changed(), "an unchanged rescan changes nothing");
    assert_eq!(e07_active_targets(&engine), attached);
    assert_eq!(
        session.detached_slots.iter().sum::<usize>(),
        0,
        "an unchanged rescan detaches nothing"
    );
    assert_eq!(
        session.attached_slots.iter().sum::<usize>(),
        1,
        "nothing re-attaches"
    );
}

/// E07: a saturated table cap still recognizes the unchanged rescan, so no
/// spurious retirement follows. 511 further distinct tables fill the 512
/// budget on top of the planted one; the rescan decodes its repeat free.
#[test]
fn e07_saturated_table_cap_unchanged_rescan_retires_nothing() {
    let provider = E07Provider::dlopen();
    let mut engine = e07_engine();
    engine.module_hints = vec![provider.path.clone()];
    let view_id = engine.views[0].id();
    let context = e07_loader_context(&mut engine, view_id);
    let mut session = ScriptedSession::default();
    let mut additions = true;
    let mut pending = PendingViewRetirements::new();

    e07_rescan(
        &mut engine,
        &mut session,
        context,
        &mut additions,
        &mut pending,
    );
    let attached = e07_active_targets(&engine);
    assert!(!attached.is_empty(), "the planted table is covered");

    // Saturate the candidate ceiling with distinct tables decoded from
    // crafted snapshots inside this binary's own data mapping.
    let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
    let map_index = MapIndex::new(&maps).expect("the self maps snapshot is valid");
    let data = maps
        .iter()
        .find(|mapping| {
            mapping.permissions.starts_with(b"rw-") && mapping.end - mapping.start >= 4096
        })
        .expect("the test process has a writable data mapping");
    let mut snapshot = vec![0u8; 2048];
    snapshot[..8].copy_from_slice(&0x2802u64.to_le_bytes());
    for slot in 0..255 {
        let at = 8 + slot * 8;
        snapshot[at..at + 8].copy_from_slice(&(e07_anchor as usize as u64).to_le_bytes());
    }
    for table in 0..511 {
        let address = data.start + table as u64 * 8;
        let decoded = decode_exact_table(
            &snapshot,
            address,
            LinuxLayout::Lp64,
            &map_index,
            &mut engine.budget,
            None,
        )
        .expect("a valid table decodes")
        .expect("all slots walkable");
        assert!(!decoded.entries.is_empty());
    }
    assert_eq!(
        engine.budget.table_candidates_count(),
        512,
        "the ceiling is saturated"
    );

    let outcome = e07_rescan(
        &mut engine,
        &mut session,
        context,
        &mut additions,
        &mut pending,
    );
    assert!(
        !outcome.changed(),
        "an unchanged rescan under a saturated cap changes nothing"
    );
    assert_eq!(e07_active_targets(&engine), attached);
    assert_eq!(
        session.detached_slots.iter().sum::<usize>(),
        0,
        "no spurious retirement under a saturated cap"
    );
    assert!(
        !engine
            .counters
            .object_skips
            .iter()
            .any(|skip| skip.reason.contains("table decode ceiling")),
        "repeats are recognized, never refused: {:?}",
        engine.counters.object_skips
    );
}

/// E07: an incomplete loader rescan (here: a stopped capture budget) must
/// not retire still-validated endpoints. The old tables are retained after
/// their pins revalidate; the stop stays explicit evidence.
#[test]
fn e07_incomplete_loader_rescan_retains_validated_endpoints() {
    let provider = E07Provider::dlopen();
    let mut engine = e07_engine();
    engine.module_hints = vec![provider.path.clone()];
    let view_id = engine.views[0].id();
    let context = e07_loader_context(&mut engine, view_id);
    let mut session = ScriptedSession::default();
    let mut additions = true;
    let mut pending = PendingViewRetirements::new();

    e07_rescan(
        &mut engine,
        &mut session,
        context,
        &mut additions,
        &mut pending,
    );
    let attached = e07_active_targets(&engine);
    assert!(!attached.is_empty(), "the planted table is covered");

    assert!(!engine.budget.charge(u64::MAX), "the budget stops");
    let outcome = e07_rescan(
        &mut engine,
        &mut session,
        context,
        &mut additions,
        &mut pending,
    );
    assert!(
        outcome.changed(),
        "the stop is published as new plan evidence"
    );
    assert_eq!(
        e07_active_targets(&engine),
        attached,
        "budget-limited absence must not retire validated endpoints"
    );
    assert_eq!(
        session.detached_slots.iter().sum::<usize>(),
        0,
        "retention detaches nothing"
    );
    assert_eq!(
        session.attached_slots.iter().sum::<usize>(),
        1,
        "retention attaches nothing new"
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| skip
            .reason
            .contains("capture discovery work ceiling reached")),
        "the stop stays explicit evidence: {:?}",
        engine.counters.object_skips
    );
}

/// E07 negative control: a genuine unmap still retires on a complete
/// rescan. After dlclose the loader scan verifies absence and detaches.
#[test]
fn e07_genuine_unmap_retires_on_a_complete_rescan() {
    let provider = E07Provider::dlopen();
    let mut engine = e07_engine();
    engine.module_hints = vec![provider.path.clone()];
    let view_id = engine.views[0].id();
    let context = e07_loader_context(&mut engine, view_id);
    let mut session = ScriptedSession::default();
    let mut additions = true;
    let mut pending = PendingViewRetirements::new();

    e07_rescan(
        &mut engine,
        &mut session,
        context,
        &mut additions,
        &mut pending,
    );
    assert!(!e07_active_targets(&engine).is_empty());

    drop(provider);
    let outcome = e07_rescan(
        &mut engine,
        &mut session,
        context,
        &mut additions,
        &mut pending,
    );
    assert!(outcome.changed(), "the unmap detaches its targets");
    assert!(
        e07_active_targets(&engine).is_empty(),
        "a genuine unmap retires"
    );
    assert_eq!(
        session.detached_slots.iter().sum::<usize>(),
        1,
        "the unmap detaches exactly its slot: {:?}",
        session.detached_slots
    );
}

/// E07 negative control: changed table bytes still retire stale targets.
/// Zeroing the version word makes the next complete scan verify absence.
#[test]
fn e07_changed_table_bytes_retire_stale_targets() {
    let provider = E07Provider::dlopen();
    let mut engine = e07_engine();
    engine.module_hints = vec![provider.path.clone()];
    let view_id = engine.views[0].id();
    let context = e07_loader_context(&mut engine, view_id);
    let mut session = ScriptedSession::default();
    let mut additions = true;
    let mut pending = PendingViewRetirements::new();

    e07_rescan(
        &mut engine,
        &mut session,
        context,
        &mut additions,
        &mut pending,
    );
    assert!(!e07_active_targets(&engine).is_empty());

    provider.zero_version();
    let outcome = e07_rescan(
        &mut engine,
        &mut session,
        context,
        &mut additions,
        &mut pending,
    );
    assert!(outcome.changed(), "changed bytes detach stale targets");
    assert!(
        e07_active_targets(&engine).is_empty(),
        "changed bytes retire stale targets"
    );
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .any(|skip| skip.reason.contains("no function table was found")),
        "verified absence stays explicit: {:?}",
        engine.counters.object_skips
    );
}

/// E07 negative control: a deleted provider file retires safely. The mapping
/// is gone from the namespace, the scan verifies absence, the targets
/// detach with the refusal as evidence.
#[test]
fn e07_deleted_provider_file_retires_safely_with_evidence() {
    let provider = E07Provider::dlopen();
    let mut engine = e07_engine();
    engine.module_hints = vec![provider.path.clone()];
    let view_id = engine.views[0].id();
    let context = e07_loader_context(&mut engine, view_id);
    let mut session = ScriptedSession::default();
    let mut additions = true;
    let mut pending = PendingViewRetirements::new();

    e07_rescan(
        &mut engine,
        &mut session,
        context,
        &mut additions,
        &mut pending,
    );
    assert!(!e07_active_targets(&engine).is_empty());

    std::fs::remove_file(&provider.path).unwrap();
    let outcome = e07_rescan(
        &mut engine,
        &mut session,
        context,
        &mut additions,
        &mut pending,
    );
    assert!(outcome.changed(), "the deleted file detaches its targets");
    assert!(
        e07_active_targets(&engine).is_empty(),
        "unavailable identity retires"
    );
    assert!(
        !engine.counters.object_skips.is_empty(),
        "the refusal stays explicit evidence"
    );
}

/// E07 negative control: retention requires revalidation. An incomplete
/// rescan over a replaced (deleted) file must NOT retain: the pins no
/// longer validate, so the stale targets retire.
#[test]
fn e07_incomplete_rescan_over_replaced_files_does_not_retain() {
    let provider = E07Provider::dlopen();
    let mut engine = e07_engine();
    engine.module_hints = vec![provider.path.clone()];
    let view_id = engine.views[0].id();
    let context = e07_loader_context(&mut engine, view_id);
    let mut session = ScriptedSession::default();
    let mut additions = true;
    let mut pending = PendingViewRetirements::new();

    e07_rescan(
        &mut engine,
        &mut session,
        context,
        &mut additions,
        &mut pending,
    );
    assert!(!e07_active_targets(&engine).is_empty());

    std::fs::remove_file(&provider.path).unwrap();
    assert!(!engine.budget.charge(u64::MAX), "the budget stops");
    assert!(
        !engine.view_pins_unchanged(view_id),
        "the deleted file fails revalidation"
    );
    let outcome = e07_rescan(
        &mut engine,
        &mut session,
        context,
        &mut additions,
        &mut pending,
    );
    assert!(
        e07_active_targets(&engine).is_empty(),
        "failed revalidation must not retain stale targets"
    );
    assert!(outcome.changed());
}

/// A loader rescan against a stale process generation is an error, never a
/// retirement: the engine's modules, pins and plan are untouched.
#[test]
fn loader_rescan_with_a_stale_generation_refuses_without_mutation() {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("an owned sleeper");
    let pid = child.id();
    let view = ProcessView::open(ProcessViewId(0), pid).unwrap();
    let view_id = view.id();
    let mount_namespace = view.mount_namespace();
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    child.wait().expect("the sleeper is reaped");
    assert!(!view.still_the_same(), "the generation is stale");

    let mut engine = Engine::empty();
    engine.views.push(view);
    engine.next_view_id = 1;
    engine.modules = vec![ReconciledModule {
        object: PinnedObjectId(7),
        scanned: ScannedModule {
            view: view_id,
            mount_namespace,
            key: ObjectKey {
                device: Device { major: 8, minor: 1 },
                inode: 7,
            },
            path: "/lib/provider.so".to_string(),
            decoder_abi: None,
            exports: Vec::new(),
            tables: Vec::new(),
            interfaces: Vec::new(),
        },
        entry_objects: Vec::new(),
    }];
    let before = engine.modules.clone();
    // A fake loader id is fine here: the stale scan errors before any
    // candidate admission could consult it.
    let context = {
        use p11scope_manifest::elf::SymbolFact;

        let prepared = engine
            .loader_registry
            .preflight(LoaderContextSpec {
                view: view_id,
                loader: PinnedObjectId(9),
                mapping: None,
                hook: SymbolFact {
                    virtual_address: 0x2100,
                    file_offset: 0x2100,
                },
                state_address: None,
            })
            .expect("a preflighted loader context");
        let context = engine
            .loader_registry
            .prepare(prepared)
            .expect("a prepared loader context");
        engine
            .loader_registry
            .mark_attached(context)
            .expect("an attached loader context");
        context
    };
    let mut session = ScriptedSession::default();
    let mut additions = true;
    let mut pending = PendingViewRetirements::new();

    let error = engine
        .process_validated_loader_scan(
            0,
            context,
            1_000_000,
            None,
            &[],
            LoaderScanMode::Memory,
            &mut session,
            &mut additions,
            &mut pending,
        )
        .expect_err("a stale generation refuses");
    assert!(
        format!("{error:#}").contains("exited"),
        "the refusal names the exited generation: {error:#}"
    );
    assert_eq!(engine.modules, before, "nothing is retired on refusal");
    assert_eq!(engine.views.len(), 1, "the view itself is untouched");
    assert!(engine.plan.slots.is_empty());
}

/// Retention revalidation is per view and pin-exact: an untouched view
/// revalidates, and replacing one of its files fails it.
#[test]
fn view_pin_revalidation_detects_replaced_files() {
    let pid = std::process::id();
    let view = ProcessView::open(ProcessViewId(0), pid).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("provider.so");
    std::fs::copy("/bin/sh", &path).unwrap();
    let mut budget = CaptureWorkBudget::new(ScanLimits {
        per_object_bytes: u64::MAX,
        total_bytes: u64::MAX,
    });
    let rooted = PathBuf::from(format!("/proc/{pid}/root{}", path.display()));
    let (_, key) = open_view_object(&view, &rooted, &mut budget).unwrap();
    let module = ScannedModule {
        view: view.id(),
        mount_namespace: view.mount_namespace(),
        key,
        path: path.display().to_string(),
        decoder_abi: None,
        exports: Vec::new(),
        tables: Vec::new(),
        interfaces: Vec::new(),
    };
    let (pins, skipped) =
        pin_scanned_view_objects(&view, std::slice::from_ref(&module), &mut budget).unwrap();
    assert!(skipped.is_empty(), "{skipped:?}");
    let mut engine = Engine::empty();
    engine.views.push(view);
    engine.pinned = pins;
    let view_id = engine.views[0].id();

    assert!(
        engine.view_pins_unchanged(view_id),
        "an untouched view revalidates"
    );
    std::fs::write(&path, b"replaced").unwrap();
    assert!(
        !engine.view_pins_unchanged(view_id),
        "a replaced file fails revalidation"
    );
}

/// E25: the preflight walk proves exactly what the merge would fail on.
/// Every failure mode below must fail identically (same message) in both,
/// and a failed merge must leave the facts usable — the merge is atomic.
#[test]
fn merge_preflight_agrees_with_merge_on_failure_modes() {
    let provider = E07Provider::dlopen();
    let mut engine = e07_engine();
    engine.module_hints = vec![provider.path.clone()];
    let view_id = engine.views[0].id();
    let context = e07_loader_context(&mut engine, view_id);
    let mut session = ScriptedSession::default();
    let mut additions = true;
    let mut pending = PendingViewRetirements::new();
    e07_rescan(
        &mut engine,
        &mut session,
        context,
        &mut additions,
        &mut pending,
    );
    assert!(!engine.modules.is_empty());
    let reconciled = engine.modules[0].clone();
    let object = reconciled.object;
    let so_id = object;
    let plan = plan::build_from_reconciled_modules(&[]);
    let counters = DiscoveryCounters::default();
    let manifest = valid_manifest_for(std::slice::from_ref(&provider.path), &[0u32; 67]);

    // One failing input set per mode. Refused-module resolution shares
    // `module_id_for_object` with the covered modes; refused plans only
    // arise from ceiling rebuilds, which the suite covers elsewhere.
    struct FailureMode {
        name: &'static str,
        modules: Vec<ReconciledModule>,
        manifests: Vec<Manifest>,
        ordinals: Vec<u32>,
        pins: PinnedObjects,
        facts: CaptureFacts,
    }
    let object_without_identity = PinnedObjectId(999);
    let modes = vec![
        FailureMode {
            name: "ordinal mismatch",
            modules: Vec::new(),
            manifests: vec![manifest.clone()],
            ordinals: Vec::new(),
            pins: engine.pinned.clone(),
            facts: engine.capture_facts.clone(),
        },
        FailureMode {
            name: "module without opened identity",
            modules: vec![ReconciledModule {
                object: object_without_identity,
                scanned: reconciled.scanned.clone(),
                entry_objects: Vec::new(),
            }],
            manifests: Vec::new(),
            ordinals: Vec::new(),
            pins: engine.pinned.clone(),
            facts: engine.capture_facts.clone(),
        },
        FailureMode {
            name: "module without stable ID",
            modules: vec![reconciled.clone()],
            manifests: Vec::new(),
            ordinals: Vec::new(),
            pins: engine.pinned.clone(),
            facts: CaptureFacts::default(),
        },
        FailureMode {
            name: "table without parallel identities",
            modules: vec![ReconciledModule {
                object: so_id,
                scanned: reconciled.scanned.clone(),
                entry_objects: Vec::new(),
            }],
            manifests: Vec::new(),
            ordinals: Vec::new(),
            pins: engine.pinned.clone(),
            facts: engine.capture_facts.clone(),
        },
        FailureMode {
            name: "entry target without identity",
            modules: vec![ReconciledModule {
                object: so_id,
                scanned: reconciled.scanned.clone(),
                entry_objects: vec![vec![
                    object_without_identity;
                    reconciled.scanned.tables[0].entries.len()
                ]],
            }],
            manifests: Vec::new(),
            ordinals: Vec::new(),
            pins: engine.pinned.clone(),
            facts: engine.capture_facts.clone(),
        },
        FailureMode {
            name: "manifest without pinned identity",
            modules: Vec::new(),
            manifests: vec![manifest],
            ordinals: vec![0],
            pins: engine.pinned.clone(),
            facts: engine.capture_facts.clone(),
        },
    ];
    for mode in modes {
        let preflight = match mode.facts.resolve_merge_inputs(
            &plan,
            &mode.pins,
            &mode.modules,
            &mode.manifests,
            &mode.ordinals,
        ) {
            Ok(()) => panic!("{}: the preflight must fail", mode.name),
            Err(error) => error.to_string(),
        };
        let mut attempted = mode.facts.clone();
        let merge = match attempted.merge_current(
            &plan,
            &mode.pins,
            &mode.modules,
            &mode.manifests,
            &mode.ordinals,
            &counters,
        ) {
            Ok(()) => panic!("{}: the merge must fail", mode.name),
            Err(error) => error.to_string(),
        };
        assert_eq!(
            preflight, merge,
            "{}: proof and merge must agree",
            mode.name
        );
        // The failed merge changed nothing observable: valid inputs still
        // merge cleanly into the same facts.
        if let Err(error) = attempted.merge_current(&plan, &mode.pins, &[], &[], &[], &counters) {
            panic!("{}: facts stay usable after failure: {error:#}", mode.name);
        }
    }
}

/// E25: preflight success implies merge success with identical results.
/// Two merges of real candidate inputs produce byte-identical histories
/// and public projections.
#[test]
fn merge_preflight_success_implies_identical_merge_results() {
    let provider = E07Provider::dlopen();
    let mut engine = e07_engine();
    engine.module_hints = vec![provider.path.clone()];
    let view_id = engine.views[0].id();
    let context = e07_loader_context(&mut engine, view_id);
    let mut session = ScriptedSession::default();
    let mut additions = true;
    let mut pending = PendingViewRetirements::new();
    e07_rescan(
        &mut engine,
        &mut session,
        context,
        &mut additions,
        &mut pending,
    );

    let inputs = (
        engine.plan.clone(),
        engine.pinned.clone(),
        engine.modules.clone(),
        engine.manifests.clone(),
        engine.manifest_ordinals.clone(),
        engine.counters.clone(),
    );
    engine
        .capture_facts
        .resolve_merge_inputs(&inputs.0, &inputs.1, &inputs.2, &inputs.3, &inputs.4)
        .expect("the preflight proves real candidate inputs");
    let mut first = engine.capture_facts.clone();
    first
        .merge_current(
            &inputs.0, &inputs.1, &inputs.2, &inputs.3, &inputs.4, &inputs.5,
        )
        .expect("the merge accepts real candidate inputs");
    let mut second = engine.capture_facts.clone();
    second
        .merge_current(
            &inputs.0, &inputs.1, &inputs.2, &inputs.3, &inputs.4, &inputs.5,
        )
        .expect("the merge is repeatable");
    assert_eq!(
        format!("{:?}", first.visible_history()),
        format!("{:?}", second.visible_history()),
        "merges produce identical histories"
    );
    let mut plan_a = inputs.0.clone();
    let mut plan_b = inputs.0.clone();
    first.apply_to_plan(&mut plan_a);
    second.apply_to_plan(&mut plan_b);
    assert_eq!(plan_a.skipped, plan_b.skipped);
    assert_eq!(plan_a.entries_seen, plan_b.entries_seen);
    assert_eq!(
        format!("{:?}", first.discovery(&plan_a)),
        format!("{:?}", second.discovery(&plan_b)),
        "merges publish identical discovery"
    );
}

/// The scan-to-live-candidate completeness contract: a clean scan over a
/// live budget is complete; stops, refusals and truncating skips are not,
/// while verified-absence skips keep a scan complete.
#[test]
fn scan_and_pin_reports_completeness_for_the_candidate_boundary() {
    let pid = std::process::id();
    let view = ProcessView::open(ProcessViewId(0), pid).unwrap();
    let hooks = HookRegistry::builtin();
    fn clean(
        _: &ScanRequest<'_>,
        _: &ProcessView,
        _: &mut CaptureWorkBudget,
    ) -> Result<ScanOutcome, String> {
        Ok(ScanOutcome::Scanned {
            modules: Vec::new(),
            skipped: Vec::new(),
            scan_ms: 0,
        })
    }

    // A clean scan over a live budget is complete.
    let mut budget = CaptureWorkBudget::default();
    let mut counters = DiscoveryCounters::default();
    let (_, _, complete) =
        scan_and_pin_with(&view, &[], &hooks, &mut budget, &mut counters, false, clean).unwrap();
    assert!(complete);

    // Verified absence keeps a scan complete.
    let mut budget = CaptureWorkBudget::default();
    let mut counters = DiscoveryCounters::default();
    let (_, _, complete) = scan_and_pin_with(
        &view,
        &[],
        &hooks,
        &mut budget,
        &mut counters,
        false,
        |_, _, _| {
            Ok::<_, String>(ScanOutcome::Scanned {
                modules: Vec::new(),
                skipped: vec![Skipped {
                    subject: "/lib/provider.so".into(),
                    reason: "not mapped in the target".into(),
                }],
                scan_ms: 0,
            })
        },
    )
    .unwrap();
    assert!(complete, "verified absence is complete");

    // A truncating skip marks the scan incomplete.
    let mut budget = CaptureWorkBudget::default();
    let mut counters = DiscoveryCounters::default();
    let (_, _, complete) = scan_and_pin_with(
        &view,
        &[],
        &hooks,
        &mut budget,
        &mut counters,
        false,
        |_, _, _| {
            Ok::<_, String>(ScanOutcome::Scanned {
                modules: Vec::new(),
                skipped: vec![Skipped {
                    subject: "/lib/provider.so".into(),
                    reason: IO_CEILING_REASON.into(),
                }],
                scan_ms: 0,
            })
        },
    )
    .unwrap();
    assert!(!complete, "a truncating skip is incomplete");

    // An unavailable memory scan is incomplete: nothing was examined.
    let mut budget = CaptureWorkBudget::default();
    let mut counters = DiscoveryCounters::default();
    let (_, _, complete) = scan_and_pin_with(
        &view,
        &[],
        &hooks,
        &mut budget,
        &mut counters,
        false,
        |_, _, _| {
            Ok::<_, String>(ScanOutcome::Unavailable {
                reason: "ptrace",
                modules: Vec::new(),
                skipped: Vec::new(),
            })
        },
    )
    .unwrap();
    assert!(!complete, "an unavailable scan is incomplete");

    // A stopped budget marks the scan incomplete even with clean output.
    let mut budget = CaptureWorkBudget::default();
    assert!(!budget.charge(u64::MAX), "the budget stops");
    let mut counters = DiscoveryCounters::default();
    let (_, _, complete) =
        scan_and_pin_with(&view, &[], &hooks, &mut budget, &mut counters, false, clean).unwrap();
    assert!(!complete, "a stopped scan is incomplete");

    // A refused new candidate marks the scan incomplete.
    let mut budget = CaptureWorkBudget::default();
    for _ in 0..512 {
        assert!(budget.admit_table(1));
    }
    let mut counters = DiscoveryCounters::default();
    let (_, _, complete) = scan_and_pin_with(
        &view,
        &[],
        &hooks,
        &mut budget,
        &mut counters,
        false,
        |_, _, budget| {
            assert!(!budget.admit_table(1), "the 513th candidate refuses");
            Ok::<_, String>(ScanOutcome::Scanned {
                modules: Vec::new(),
                skipped: Vec::new(),
                scan_ms: 0,
            })
        },
    )
    .unwrap();
    assert!(!complete, "a refused candidate is incomplete");
}

// SYSPLAN Package C (E06): fair bounded system exploration.
//
// The RED pair below pins the experiment before the fix: with the scan cap
// full of long-lived provider-free views, a later process carrying a unique
// provider is never reached — ordinary ticks have no free slot and the
// reconcile slice selects into zero free slots, so the newcomer starves
// forever. The shared-inode twin is the countercontrol: the starvation is
// generic, not specific to unique providers, so the fix must cover both.
fn e06_cgroup_args(
    scope_dir: &Path,
    hints: Vec<PathBuf>,
    max_scan_pids: Option<usize>,
) -> CaptureArgs {
    CaptureArgs {
        kind: crate::cli::Kind::Profile,
        modules: hints,
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: crate::cli::ScopeArg::Cgroup(scope_dir.to_path_buf()),
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        ring_bytes: None,
        drain_interval: None,
        max_scan_pids,
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    }
}

fn e06_spawn_sleeps(count: usize) -> Vec<SystemScopeChildGuard> {
    let guards: Vec<SystemScopeChildGuard> = (0..count)
        .map(|_| {
            SystemScopeChildGuard::new(
                std::process::Command::new("sleep")
                    .arg("30")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap(),
            )
        })
        .collect();
    // Readiness (same idiom as the cap siblings): discover only once every
    // child execed sleep, so no maps read races a fork-exec transition.
    let self_exe = std::env::current_exe().unwrap();
    for guard in &guards {
        let pid = guard.pid();
        let exe = format!("/proc/{pid}/exe");
        let mut execed = false;
        for _ in 0..500 {
            if std::fs::read_link(&exe).is_ok_and(|target| target != self_exe) {
                execed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(execed, "sleep child {pid} never execed");
    }
    guards
}

fn e06_write_listing(scope_dir: &Path, pids: &[u32]) {
    let listing: String = pids.iter().map(|pid| format!("{pid}\n")).collect();
    std::fs::write(scope_dir.join("cgroup.procs"), listing).expect("a cgroup.procs");
}

/// E06 RED: `max_scan_pids=2` retains two long-lived provider-free views;
/// a third process with a unique provider arrives later. At least eight
/// reconciliation frames must reach it. The oracle is actual deep-scan and
/// admission evidence (plan module, attachable slots, refresh-phase
/// `scan_ms`), never `/proc/maps` visits.
#[test]
fn e06_unique_provider_reached_within_bounded_frames() {
    let sleeps = e06_spawn_sleeps(2);
    let sleep_pids: Vec<u32> = sleeps.iter().map(|guard| guard.pid()).collect();
    let dir = tempfile::tempdir().expect("a fixture directory");
    let provider = system_scope_build_fixture(dir.path(), "e06-unique");
    let driver = system_scope_build_driver(dir.path());
    let scope_dir = tempfile::tempdir().expect("a scope directory");
    e06_write_listing(scope_dir.path(), &sleep_pids);
    let scope = crate::scope::cgroup(scope_dir.path()).expect("open scope directory");
    let args = e06_cgroup_args(scope_dir.path(), vec![provider.clone()], Some(2));

    let mut engine = Engine::discover(&args, &scope, None).expect("a capped cgroup still captures");
    assert_eq!(
        engine.views.len(),
        2,
        "both provider-free views are retained"
    );
    assert!(
        engine.plan.modules.is_empty(),
        "no provider is mapped yet: {:?}",
        engine.plan.modules
    );

    let child = system_scope_spawn_loaded(&driver, &provider);
    let newcomer = child.pid();
    let mut pids = sleep_pids.clone();
    pids.push(newcomer);
    e06_write_listing(scope_dir.path(), &pids);

    let mut first_seen = None;
    for frame in 1..=8 {
        refresh_inventory_once(&mut engine);
        assert!(
            engine.views.len() <= 2,
            "frame {frame}: the cap still binds: {}",
            engine.views.len()
        );
        if first_seen.is_none()
            && engine
                .plan
                .modules
                .iter()
                .any(|module| module.path.ends_with("e06-unique.so"))
        {
            first_seen = Some(frame);
        }
    }
    let first_seen =
        first_seen.expect("the unique provider is discovered within eight reconciliation frames");
    assert!(
        first_seen <= 4,
        "one reconcile reaches it: first seen at frame {first_seen}"
    );
    assert!(
        engine.views.iter().any(|view| view.pid() == newcomer),
        "the newcomer generation is retained: {:?}",
        engine
            .views
            .iter()
            .map(|view| view.pid())
            .collect::<Vec<_>>()
    );
    assert!(
        !system_scope_slots_for(&engine, "e06-unique.so").is_empty(),
        "admission produced attachable slots, not just a maps visit"
    );
    assert!(
        engine.counters.scan_ms > 0,
        "the refresh phase ran actual deep scans"
    );
}

/// E06 countercontrol: the same starvation setup with shared-inode
/// endpoints. Both children map the one provider file; rotation must cover
/// both generations while keeping the shared file pinned once (union
/// indices, no duplicate provider).
#[test]
fn e06_shared_inode_control_stays_covered_across_rotation() {
    let sleeps = e06_spawn_sleeps(2);
    let sleep_pids: Vec<u32> = sleeps.iter().map(|guard| guard.pid()).collect();
    let dir = tempfile::tempdir().expect("a fixture directory");
    let provider = system_scope_build_fixture(dir.path(), "e06-shared");
    let driver = system_scope_build_driver(dir.path());
    let scope_dir = tempfile::tempdir().expect("a scope directory");
    e06_write_listing(scope_dir.path(), &sleep_pids);
    let scope = crate::scope::cgroup(scope_dir.path()).expect("open scope directory");
    let args = e06_cgroup_args(scope_dir.path(), vec![provider.clone()], Some(2));

    let mut engine = Engine::discover(&args, &scope, None).expect("a capped cgroup still captures");
    assert_eq!(engine.views.len(), 2);

    let child_a = system_scope_spawn_loaded(&driver, &provider);
    let child_b = system_scope_spawn_loaded(&driver, &provider);
    let mut pids = sleep_pids.clone();
    pids.push(child_a.pid());
    pids.push(child_b.pid());
    e06_write_listing(scope_dir.path(), &pids);

    for frame in 1..=8 {
        refresh_inventory_once(&mut engine);
        assert!(
            engine.views.len() <= 2,
            "frame {frame}: the cap still binds: {}",
            engine.views.len()
        );
    }
    let kept: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    assert!(
        kept.contains(&child_a.pid()) && kept.contains(&child_b.pid()),
        "both shared-inode generations are retained: {kept:?}"
    );
    let provider_modules: Vec<_> = engine
        .modules
        .iter()
        .filter(|module| module.scanned.path.ends_with("e06-shared.so"))
        .collect();
    assert_eq!(
        provider_modules.len(),
        2,
        "both generations contribute their scanned module"
    );
    assert_eq!(
        provider_modules[0].object, provider_modules[1].object,
        "the shared file is pinned once across both views"
    );
    assert!(
        !system_scope_slots_for(&engine, "e06-shared.so").is_empty(),
        "the shared provider admits attachable slots"
    );
}

/// Package C: rotation never evicts owned views. A provider view and a
/// sleep share the cap; a newcomer sleep arrives and the provider view
/// takes a refresh (same image) mid-rotation. The provider's pid is
/// retained on every frame — evicted pids always leave the view set for at
/// least one frame (cooldown), so every-frame retention proves non-eviction.
/// Pins stay authoritative: the same capture-local object IDs, the same
/// slots, the same view ID throughout, while the sleeps cycle.
#[test]
fn exploratory_rotation_never_evicts_owned_views() {
    let dir = tempfile::tempdir().expect("a fixture directory");
    let provider = system_scope_build_fixture(dir.path(), "owned-never");
    let driver = system_scope_build_driver(dir.path());
    let provider_child = system_scope_spawn_loaded(&driver, &provider);
    let provider_pid = provider_child.pid();
    let sleeps = e06_spawn_sleeps(1);
    let sleep_a = sleeps[0].pid();
    let scope_dir = tempfile::tempdir().expect("a scope directory");
    e06_write_listing(scope_dir.path(), &[provider_pid, sleep_a]);
    let scope = crate::scope::cgroup(scope_dir.path()).expect("open scope directory");
    let args = e06_cgroup_args(scope_dir.path(), vec![provider.clone()], Some(2));

    let mut engine = Engine::discover(&args, &scope, None).expect("a capped cgroup still captures");
    assert_eq!(engine.views.len(), 2);
    let provider_view = engine
        .views
        .iter()
        .find(|view| view.pid() == provider_pid)
        .unwrap()
        .id();
    let slots_before = system_scope_slots_for(&engine, "owned-never.so");
    assert!(!slots_before.is_empty());
    let objects_before: BTreeSet<PinnedObjectId> = engine
        .modules
        .iter()
        .filter(|module| module.scanned.path.ends_with("owned-never.so"))
        .map(|module| module.object)
        .collect();
    assert!(!objects_before.is_empty());

    let newcomer = e06_spawn_sleeps(1);
    let sleep_b = newcomer[0].pid();
    e06_write_listing(scope_dir.path(), &[provider_pid, sleep_a, sleep_b]);
    // A same-image refresh mid-rotation: the rescan must run (deep-scan
    // delta below) and replace with identical content, and the view must
    // arm (it owns a provider, so the ownership gate passes).
    engine.request_refresh(provider_pid);
    let scans_before = engine.deep_scans;

    let mut sleep_a_seen = false;
    let mut sleep_b_seen = false;
    for frame in 1..=8 {
        refresh_inventory_once(&mut engine);
        let kept: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
        assert!(
            kept.contains(&provider_pid),
            "frame {frame}: the owned view is always retained: {kept:?}"
        );
        sleep_a_seen |= kept.contains(&sleep_a);
        sleep_b_seen |= kept.contains(&sleep_b);
    }
    assert!(
        engine.deep_scans > scans_before,
        "the refresh rescan actually ran"
    );
    assert!(
        !engine
            .loader_registry
            .ids_for_view(provider_view)
            .is_empty(),
        "the refreshed provider view armed its loader context"
    );
    assert!(
        engine.loader_arms >= 1,
        "arming was attempted for the owned view"
    );
    assert_eq!(
        system_scope_slots_for(&engine, "owned-never.so"),
        slots_before,
        "owned slots are stable across refresh and rotation"
    );
    let objects_after: BTreeSet<PinnedObjectId> = engine
        .modules
        .iter()
        .filter(|module| module.scanned.path.ends_with("owned-never.so"))
        .map(|module| module.object)
        .collect();
    assert_eq!(
        objects_after, objects_before,
        "the provider was never re-pinned under a fresh ID"
    );
    assert!(
        engine
            .views
            .iter()
            .any(|view| view.pid() == provider_pid && view.id() == provider_view),
        "the owned view ID is stable"
    );
    assert!(
        engine.exploratory_evictions >= 1,
        "the sleeps cycled while the provider held its slot"
    );
    assert!(
        sleep_a_seen && sleep_b_seen,
        "rotation reached both sleeps around the owned view"
    );
}

/// Package C: the dirty history pins retired provider evidence. A view ID
/// that ever observed modules is never rotatable — even when it is
/// currently empty — because the capture budget still keys that ID's old
/// runtime evidence and offers no per-view scrub. Marking is proven on a
/// real scan; exclusion is proven by a simulated dirtied sleep (standing in
/// for an emptied provider view, covered behaviorally by the unload test),
/// which rotation must never touch even though it is otherwise evictable.
/// With nothing evictable the newcomer honestly starves with explicit
/// selected-0 evidence: rotation capacity requires evictable views.
#[test]
fn exploratory_eviction_never_recycles_dirty_identities() {
    let dir = tempfile::tempdir().expect("a fixture directory");
    let provider = system_scope_build_fixture(dir.path(), "dirty-never");
    let driver = system_scope_build_driver(dir.path());
    let provider_child = system_scope_spawn_loaded(&driver, &provider);
    let provider_pid = provider_child.pid();
    let sleeps = e06_spawn_sleeps(1);
    let sleep_a = sleeps[0].pid();
    let scope_dir = tempfile::tempdir().expect("a scope directory");
    e06_write_listing(scope_dir.path(), &[provider_pid, sleep_a]);
    let scope = crate::scope::cgroup(scope_dir.path()).expect("open scope directory");
    let args = e06_cgroup_args(scope_dir.path(), vec![provider.clone()], Some(2));

    let mut engine = Engine::discover(&args, &scope, None).expect("a capped cgroup still captures");
    let provider_view = engine
        .views
        .iter()
        .find(|view| view.pid() == provider_pid)
        .unwrap()
        .id();
    let sleep_view = engine
        .views
        .iter()
        .find(|view| view.pid() == sleep_a)
        .unwrap()
        .id();
    assert!(
        engine.exploratory_dirty.contains(&provider_view),
        "a real scan marks the provider view dirty"
    );
    assert!(
        !engine.exploratory_evictable(provider_view),
        "the owned view is not evictable"
    );
    assert!(
        engine.exploratory_evictable(sleep_view),
        "the clean sleep is evictable"
    );

    // Simulate a view that once held runtime evidence and has since gone
    // empty: dirty history alone must block its rotation.
    engine.exploratory_dirty.insert(sleep_view);
    assert!(
        !engine.exploratory_evictable(sleep_view),
        "dirty history alone blocks eviction"
    );

    let newcomer = e06_spawn_sleeps(1);
    let sleep_b = newcomer[0].pid();
    e06_write_listing(scope_dir.path(), &[provider_pid, sleep_a, sleep_b]);
    for frame in 1..=8 {
        refresh_inventory_once(&mut engine);
        let kept: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
        assert!(
            kept.contains(&provider_pid) && kept.contains(&sleep_a),
            "frame {frame}: nothing rotates without an evictable view: {kept:?}"
        );
        assert!(
            !kept.contains(&sleep_b),
            "frame {frame}: the newcomer honestly waits: {kept:?}"
        );
    }
    assert_eq!(
        engine.exploratory_evictions, 0,
        "no evictable view means no eviction"
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.reason
                .contains("live discovery selected 0 new candidates")
        }),
        "starvation stays explicit: {:?}",
        engine.counters.object_skips
    );
}

/// Package C: one tick admits at most the configured new views, under or
/// over the cap; the rest defer with exact evidence and their queued
/// event-driven requests are retained until served. Five newcomers with a
/// tick limit of two drain over three ticks in pid order.
#[test]
fn refresh_tick_bounds_new_admissions_with_explicit_deferral() {
    let first = e06_spawn_sleeps(1);
    let mut pids: Vec<u32> = first.iter().map(|guard| guard.pid()).collect();
    let scope_dir = tempfile::tempdir().expect("a scope directory");
    e06_write_listing(scope_dir.path(), &pids);
    let scope = crate::scope::cgroup(scope_dir.path()).expect("open scope directory");
    let args = e06_cgroup_args(scope_dir.path(), vec![], None);

    let mut engine = Engine::discover(&args, &scope, None).expect("an uncapped cgroup captures");
    assert_eq!(engine.views.len(), 1);
    engine.scheduler.set_max_new_views_for_test(2);

    let rest = e06_spawn_sleeps(5);
    let mut more: Vec<u32> = rest.iter().map(|guard| guard.pid()).collect();
    more.sort_unstable();
    pids.extend(more.iter().copied());
    e06_write_listing(scope_dir.path(), &pids);
    // The highest pid defers twice; its queued request must survive both.
    engine.request_refresh(more[4]);

    refresh_inventory_once(&mut engine);
    assert_eq!(engine.views.len(), 3, "two of five newcomers drain first");
    assert!(
        engine.refresh_requested.contains(&more[4]),
        "the deferred request is retained, not dropped"
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == "live discovery tick"
                && skip.reason
                    == "5 new processes pending; tick admitted 2 for deep scanning (tick limit 2)"
        }),
        "the deferral is exact: {:?}",
        engine.counters.object_skips
    );

    refresh_inventory_once(&mut engine);
    assert_eq!(engine.views.len(), 5, "two more drain next");
    assert!(
        engine.refresh_requested.contains(&more[4]),
        "still retained after the second deferral"
    );

    refresh_inventory_once(&mut engine);
    assert_eq!(engine.views.len(), 6, "the last newcomer drains third");
    assert!(
        !engine.refresh_requested.contains(&more[4]),
        "the served request clears"
    );
    let mut kept: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    kept.sort_unstable();
    let mut expected = pids.clone();
    expected.sort_unstable();
    assert_eq!(kept, expected, "every newcomer is eventually admitted");
}

/// Package C: a zero deep-scan quantum defers the whole phase — refreshed
/// views and new admissions alike — with exact evidence and zero scans;
/// restoring the quantum serves everything next tick. Extremes only, so no
/// wall-time flakes: the quantum is either already expired or unreachable.
#[test]
fn refresh_tick_deep_scan_quantum_defers_with_evidence() {
    let first = e06_spawn_sleeps(1);
    let kept_pid = first[0].pid();
    let scope_dir = tempfile::tempdir().expect("a scope directory");
    e06_write_listing(scope_dir.path(), &[kept_pid]);
    let scope = crate::scope::cgroup(scope_dir.path()).expect("open scope directory");
    let args = e06_cgroup_args(scope_dir.path(), vec![], None);

    let mut engine = Engine::discover(&args, &scope, None).expect("an uncapped cgroup captures");
    let rest = e06_spawn_sleeps(2);
    let more: Vec<u32> = rest.iter().map(|guard| guard.pid()).collect();
    e06_write_listing(scope_dir.path(), &[kept_pid, more[0], more[1]]);
    engine.request_refresh(kept_pid);
    engine.scheduler.set_tick_quantum_ns_for_test(0);
    let scans_before = engine.deep_scans;

    refresh_inventory_once(&mut engine);
    assert_eq!(
        engine.deep_scans, scans_before,
        "an expired quantum scans nothing"
    );
    assert_eq!(engine.views.len(), 1, "no admission runs past the quantum");
    assert!(
        engine.refresh_requested.contains(&kept_pid),
        "the refreshed request is retained"
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == "live discovery tick"
                && skip.reason
                    == "tick deep-scan quantum exhausted; 1 refreshed view deferred to the next tick"
        }),
        "the refreshed deferral is exact: {:?}",
        engine.counters.object_skips
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == "live discovery tick"
                && skip.reason
                    == "tick deep-scan quantum exhausted; remaining new processes deferred to the next tick"
        }),
        "the admission deferral is exact: {:?}",
        engine.counters.object_skips
    );

    engine.scheduler.set_tick_quantum_ns_for_test(u64::MAX);
    refresh_inventory_once(&mut engine);
    assert_eq!(engine.views.len(), 3, "everything drains once unblocked");
    assert!(
        engine.refresh_requested.is_empty(),
        "served requests clear: {:?}",
        engine.refresh_requested
    );
}

/// Package C: cancellation is the capture budget's deadline, and it
/// cancels work — not admission. An expired deadline refuses a newcomer
/// provider's scan, which is then admitted empty (Package B's partial-first-
/// scan semantic) with the deadline named in evidence and no bytes charged;
/// crucially the refused scan dirties nothing, so clearing the deadline lets
/// the next reconcile's polling rescan find the provider and upgrade the
/// view to owned and armed. The tick quantum is untouched throughout:
/// budget cancellation and the time quantum are independent mechanisms.
#[test]
fn refresh_tick_cancellation_defers_new_work_with_evidence() {
    let sleeps = e06_spawn_sleeps(2);
    let sleep_pids: Vec<u32> = sleeps.iter().map(|guard| guard.pid()).collect();
    let dir = tempfile::tempdir().expect("a fixture directory");
    let provider = system_scope_build_fixture(dir.path(), "cancel-unique");
    let driver = system_scope_build_driver(dir.path());
    let scope_dir = tempfile::tempdir().expect("a scope directory");
    e06_write_listing(scope_dir.path(), &sleep_pids);
    let scope = crate::scope::cgroup(scope_dir.path()).expect("open scope directory");
    let args = e06_cgroup_args(scope_dir.path(), vec![provider.clone()], Some(2));

    let mut engine = Engine::discover(&args, &scope, None).expect("a capped cgroup still captures");
    let child = system_scope_spawn_loaded(&driver, &provider);
    let newcomer = child.pid();
    let mut pids = sleep_pids.clone();
    pids.push(newcomer);
    e06_write_listing(scope_dir.path(), &pids);
    engine.request_refresh(newcomer);
    engine.budget.set_deadline(Some(0));

    // Ordinary frames cannot reach the newcomer (no free slots); the queued
    // request survives them.
    for frame in 1..=3 {
        refresh_inventory_once(&mut engine);
        assert!(
            !engine.views.iter().any(|view| view.pid() == newcomer),
            "frame {frame}: no slot means no attempt yet"
        );
    }
    assert!(
        engine.refresh_requested.contains(&newcomer),
        "the queued request survives the ordinary frames"
    );

    // The reconcile admits the newcomer, but the expired deadline refuses
    // its scan: an empty view with deadline evidence and no work charged.
    let bytes_before = engine.budget.attempted_io_bytes();
    refresh_inventory_once(&mut engine);
    assert!(
        engine.views.iter().any(|view| view.pid() == newcomer),
        "the refused newcomer is admitted empty, not dropped"
    );
    assert!(
        engine.plan.modules.is_empty(),
        "nothing was verified, so nothing is published"
    );
    assert_eq!(
        engine.budget.attempted_io_bytes() - bytes_before,
        0,
        "cancellation charges no bytes"
    );
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .any(|skip| { skip.reason.contains("deadline") }),
        "the deadline is named in evidence: {:?}",
        engine.counters.object_skips
    );
    let newcomer_view = engine
        .views
        .iter()
        .find(|view| view.pid() == newcomer)
        .unwrap()
        .id();
    assert!(
        !engine.exploratory_dirty.contains(&newcomer_view),
        "a refused scan dirties nothing, so recovery stays possible"
    );

    // Clearing the deadline recovers through the polling rescan: the next
    // reconcile re-examines the clean empty view, finds the provider, and
    // upgrades it to owned and armed.
    engine.budget.set_deadline(None);
    for _ in 5..=8 {
        refresh_inventory_once(&mut engine);
    }
    assert!(
        engine
            .plan
            .modules
            .iter()
            .any(|module| module.path.ends_with("cancel-unique.so")),
        "the polling rescan recovers the provider after cancellation"
    );
    assert!(
        engine.exploratory_dirty.contains(&newcomer_view),
        "the verifying scan marks the view dirty"
    );
    assert!(
        !engine
            .loader_registry
            .ids_for_view(newcomer_view)
            .is_empty(),
        "the upgraded view arms its loader context"
    );
    assert!(
        !system_scope_slots_for(&engine, "cancel-unique.so").is_empty(),
        "recovery admits attachable slots"
    );
}

/// Package C: the per-tick oracle measures actual deep scans and hook arms,
/// never `/proc/maps` visits. On the E06 shape (cap 2, two sleeps, one
/// newcomer provider): ordinary full ticks move nothing (no maps sweep, no
/// scans, no arms); the reconcile tick deep-scans exactly the newcomer
/// admission plus the survivor's polling rescan, attempts exactly the
/// newcomer's loader arm (the gate skips the provider-free survivor), and
/// re-reads maps; later reconciles rescan only the polling survivor while
/// the owned newcomer is never re-polled.
#[test]
fn per_tick_accounting_measures_deep_scans_hooks_and_maps_separately() {
    let sleeps = e06_spawn_sleeps(2);
    let sleep_pids: Vec<u32> = sleeps.iter().map(|guard| guard.pid()).collect();
    let dir = tempfile::tempdir().expect("a fixture directory");
    let provider = system_scope_build_fixture(dir.path(), "acct-unique");
    let driver = system_scope_build_driver(dir.path());
    let scope_dir = tempfile::tempdir().expect("a scope directory");
    e06_write_listing(scope_dir.path(), &sleep_pids);
    let scope = crate::scope::cgroup(scope_dir.path()).expect("open scope directory");
    let args = e06_cgroup_args(scope_dir.path(), vec![provider.clone()], Some(2));

    let mut engine = Engine::discover(&args, &scope, None).expect("a capped cgroup still captures");
    // Discovery scans but never arms: arming needs the session/refresh path.
    assert_eq!(engine.deep_scans, 2, "both initial views were deep-scanned");
    assert_eq!(engine.loader_arms, 0, "discovery alone arms nothing");

    let child = system_scope_spawn_loaded(&driver, &provider);
    let newcomer = child.pid();
    let mut pids = sleep_pids.clone();
    pids.push(newcomer);
    e06_write_listing(scope_dir.path(), &pids);

    for frame in 1..=3 {
        let (scans, arms, bytes) = (
            engine.deep_scans,
            engine.loader_arms,
            engine.budget.attempted_io_bytes(),
        );
        refresh_inventory_once(&mut engine);
        assert_eq!(
            (engine.deep_scans - scans, engine.loader_arms - arms),
            (0, 0),
            "ordinary full frame {frame} scans and arms nothing"
        );
        assert_eq!(
            engine.budget.attempted_io_bytes() - bytes,
            0,
            "ordinary full frame {frame} reads no maps either"
        );
    }

    let (scans, arms, bytes) = (
        engine.deep_scans,
        engine.loader_arms,
        engine.budget.attempted_io_bytes(),
    );
    refresh_inventory_once(&mut engine);
    // The newcomer admission scans once; the survivor's polling rescan runs
    // the standard pre- plus post-retirement pair.
    assert_eq!(
        engine.deep_scans - scans,
        3,
        "the reconcile tick scans the newcomer plus the survivor's polling rescan pair"
    );
    assert_eq!(
        engine.loader_arms - arms,
        1,
        "only the provider newcomer is armed; the gate skips the survivor"
    );
    assert!(
        engine.budget.attempted_io_bytes() - bytes > 0,
        "the reconcile slice re-read maps"
    );
    assert!(
        engine
            .plan
            .modules
            .iter()
            .any(|module| module.path.ends_with("acct-unique.so")),
        "the newcomer provider is admitted on the reconcile"
    );

    for frame in 5..=7 {
        let (scans, arms, bytes) = (
            engine.deep_scans,
            engine.loader_arms,
            engine.budget.attempted_io_bytes(),
        );
        refresh_inventory_once(&mut engine);
        assert_eq!(
            (
                engine.deep_scans - scans,
                engine.loader_arms - arms,
                engine.budget.attempted_io_bytes() - bytes
            ),
            (0, 0, 0),
            "ordinary frame {frame} is quiet again"
        );
    }

    let (scans, arms, bytes) = (
        engine.deep_scans,
        engine.loader_arms,
        engine.budget.attempted_io_bytes(),
    );
    refresh_inventory_once(&mut engine);
    assert_eq!(
        engine.deep_scans - scans,
        2,
        "the next reconcile runs only the survivor's polling rescan pair"
    );
    assert_eq!(
        engine.loader_arms - arms,
        0,
        "nothing newly armable appears"
    );
    assert!(
        engine.budget.attempted_io_bytes() - bytes > 0,
        "maps are re-read every reconcile"
    );
    assert!(
        engine.views.iter().any(|view| view.pid() == newcomer),
        "the owned newcomer stays retained throughout"
    );
}

/// Package C lazy loader: a child that starts provider-free and dlopens or
/// dlcloses its provider on stdin commands, so one retained generation can
/// gain and lose a provider mid-capture (the polling-upgrade and unload
/// paths). Protocol on stderr, one line each: `ready` at start, `loaded`
/// after `L`, `unloaded` after `U`; `Q` quits.
const LAZY_LOADER_C: &str = r#"
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
typedef unsigned long (*get_list_fn)(void **);
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    setvbuf(stderr, NULL, _IONBF, 0);
    fprintf(stderr, "P11SCOPE_LAZY ready\n");
    void *handle = NULL;
    for (;;) {
        char cmd = 0;
        if (read(STDIN_FILENO, &cmd, 1) != 1) return 3;
        if (cmd == 'Q') break;
        if (cmd == 'L') {
            if (handle == NULL) {
                handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
                if (handle == NULL) {
                    fprintf(stderr, "P11SCOPE_LAZY dlopen-failed\n");
                    return 4;
                }
                get_list_fn fn_ = (get_list_fn)dlsym(handle, "C_GetFunctionList");
                void *table = NULL;
                if (fn_ == NULL || fn_(&table) != 0 || table == NULL) {
                    fprintf(stderr, "P11SCOPE_LAZY surface-failed\n");
                    return 5;
                }
            }
            fprintf(stderr, "P11SCOPE_LAZY loaded\n");
        } else if (cmd == 'U') {
            if (handle != NULL) {
                dlclose(handle);
                handle = NULL;
            }
            fprintf(stderr, "P11SCOPE_LAZY unloaded\n");
        }
    }
    return 0;
}
"#;

struct LazyLoader {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stderr: std::process::ChildStderr,
}

impl LazyLoader {
    fn spawn(dir: &Path, provider: &Path) -> Self {
        let source = dir.join("lazy_loader.c");
        let binary = dir.join("lazy_loader");
        std::fs::write(&source, LAZY_LOADER_C).expect("the lazy loader source");
        assert!(
            std::process::Command::new("gcc")
                .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-o"])
                .arg(&binary)
                .arg(&source)
                .args(["-ldl"])
                .status()
                .unwrap()
                .success()
        );
        let mut child = std::process::Command::new(&binary)
            .arg(provider)
            .env_clear()
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let mut loader = Self {
            child,
            stdin,
            stderr,
        };
        loader.wait_for(b"P11SCOPE_LAZY ready\n");
        loader
    }

    fn wait_for(&mut self, marker: &[u8]) {
        use std::os::fd::AsRawFd as _;
        let mut seen = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !seen.ends_with(marker) {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(!remaining.is_zero() && seen.len() < 4096);
            assert!(system_scope_poll_fd(self.stderr.as_raw_fd(), remaining).unwrap());
            let mut byte = [0];
            assert_eq!(
                std::io::Read::read(&mut self.stderr, &mut byte).unwrap(),
                1,
                "lazy loader exited before {marker:?}"
            );
            seen.extend_from_slice(&byte);
        }
    }

    fn send(&mut self, byte: u8) {
        use std::io::Write as _;
        self.stdin.write_all(&[byte]).unwrap();
        self.stdin.flush().unwrap();
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for LazyLoader {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Package C: a retained exploratory view whose process gains a provider is
/// upgraded by the polling rescan — no loader event exists (the view was
/// never armed and the session carries no records), so the reconcile's
/// polling queue is the only path. The upgrade marks the view dirty, arms
/// its loader context, and admits slots.
#[test]
fn polling_rescan_upgrades_retained_view_that_gains_a_provider() {
    let dir = tempfile::tempdir().expect("a fixture directory");
    let provider = system_scope_build_fixture(dir.path(), "upgrade-lazy");
    let mut loader = LazyLoader::spawn(dir.path(), &provider);
    let loader_pid = loader.pid();
    let sleeps = e06_spawn_sleeps(1);
    let sleep_a = sleeps[0].pid();
    let scope_dir = tempfile::tempdir().expect("a scope directory");
    e06_write_listing(scope_dir.path(), &[loader_pid, sleep_a]);
    let scope = crate::scope::cgroup(scope_dir.path()).expect("open scope directory");
    let args = e06_cgroup_args(scope_dir.path(), vec![provider.clone()], Some(2));

    let mut engine = Engine::discover(&args, &scope, None).expect("a capped cgroup still captures");
    assert_eq!(engine.views.len(), 2);
    assert!(engine.plan.modules.is_empty());
    let loader_view = engine
        .views
        .iter()
        .find(|view| view.pid() == loader_pid)
        .unwrap()
        .id();
    assert!(engine.exploratory_evictable(loader_view));

    loader.send(b'L');
    loader.wait_for(b"P11SCOPE_LAZY loaded\n");

    let mut upgraded = None;
    for frame in 1..=8 {
        refresh_inventory_once(&mut engine);
        if upgraded.is_none()
            && engine
                .plan
                .modules
                .iter()
                .any(|module| module.path.ends_with("upgrade-lazy.so"))
        {
            upgraded = Some(frame);
        }
    }
    let upgraded = upgraded.expect("polling finds the gained provider");
    assert!(
        upgraded <= 4,
        "the first reconcile upgrades it: frame {upgraded}"
    );
    assert!(
        engine.exploratory_dirty.contains(&loader_view),
        "the verifying rescan marks the view dirty"
    );
    assert!(
        !engine.exploratory_evictable(loader_view),
        "the upgraded view is owned, no longer exploratory"
    );
    assert!(
        !engine.loader_registry.ids_for_view(loader_view).is_empty(),
        "the upgrade arms loader tracking"
    );
    assert!(
        !system_scope_slots_for(&engine, "upgrade-lazy.so").is_empty(),
        "the upgrade admits attachable slots"
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == "live discovery rotation" && skip.reason.contains("for polling rescan")
        }),
        "polling evidence is published: {:?}",
        engine.counters.object_skips
    );
}

/// Package C: the full dirty lifecycle. A retained view upgraded by polling
/// (dirty, owned, armed) then unloads its provider: the next polling rescan
/// replaces its modules with verified emptiness (replace-always), retires
/// its loader context, and drops its slots — but the dirty history pins the
/// ID forever, so rotation cycles newcomers around it without ever evicting
/// it into its own old runtime-table evidence.
#[test]
fn unloaded_provider_view_stays_pinned_by_dirty_history() {
    let dir = tempfile::tempdir().expect("a fixture directory");
    let provider = system_scope_build_fixture(dir.path(), "unload-lazy");
    let mut loader = LazyLoader::spawn(dir.path(), &provider);
    let loader_pid = loader.pid();
    let sleeps = e06_spawn_sleeps(1);
    let sleep_a = sleeps[0].pid();
    let scope_dir = tempfile::tempdir().expect("a scope directory");
    e06_write_listing(scope_dir.path(), &[loader_pid, sleep_a]);
    let scope = crate::scope::cgroup(scope_dir.path()).expect("open scope directory");
    let args = e06_cgroup_args(scope_dir.path(), vec![provider.clone()], Some(2));

    let mut engine = Engine::discover(&args, &scope, None).expect("a capped cgroup still captures");
    let loader_view = engine
        .views
        .iter()
        .find(|view| view.pid() == loader_pid)
        .unwrap()
        .id();

    // Phase 1: gain the provider through the polling upgrade.
    loader.send(b'L');
    loader.wait_for(b"P11SCOPE_LAZY loaded\n");
    for _ in 1..=8 {
        refresh_inventory_once(&mut engine);
    }
    assert!(
        engine
            .plan
            .modules
            .iter()
            .any(|module| module.path.ends_with("unload-lazy.so")),
        "phase 1 upgrades the loader view"
    );
    assert!(engine.exploratory_dirty.contains(&loader_view));
    assert!(
        !engine.loader_registry.ids_for_view(loader_view).is_empty(),
        "phase 1 arms the upgraded view"
    );
    assert_eq!(engine.loader_arms, 1, "exactly one arm attempt so far");

    // Phase 2: unload it. Owned views rely on event-driven refresh (in
    // production the armed loader context fires; here the request models
    // that event, since polling deliberately covers only exploratory views
    // and can therefore only add coverage, never flap owned modules).
    loader.send(b'U');
    loader.wait_for(b"P11SCOPE_LAZY unloaded\n");
    engine.request_refresh(loader_pid);
    for _ in 1..=8 {
        refresh_inventory_once(&mut engine);
    }
    assert!(
        engine.plan.modules.is_empty(),
        "phase 2 replaces the modules with verified emptiness"
    );
    assert!(
        engine.exploratory_dirty.contains(&loader_view),
        "dirty history survives the unload"
    );
    assert!(
        !engine.exploratory_evictable(loader_view),
        "the emptied dirty view never rotates"
    );
    let unloaded_contexts = engine.loader_registry.ids_for_view(loader_view);
    assert!(
        unloaded_contexts
            .iter()
            .all(|id| engine.loader_registry.is_tombstoned(*id)),
        "no live loader context remains after the unload"
    );
    assert_eq!(
        engine.loader_arms, 1,
        "the emptied view never re-arms: the ownership gate holds"
    );

    // Phase 3: newcomers cycle around the pinned view for twelve frames.
    let newcomers = e06_spawn_sleeps(2);
    let sleep_b = newcomers[0].pid();
    let sleep_c = newcomers[1].pid();
    e06_write_listing(scope_dir.path(), &[loader_pid, sleep_a, sleep_b, sleep_c]);
    let evictions_before = engine.exploratory_evictions;
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    for frame in 1..=12 {
        refresh_inventory_once(&mut engine);
        let kept: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
        assert!(
            kept.contains(&loader_pid),
            "frame {frame}: the pinned view is always retained: {kept:?}"
        );
        seen.extend(kept);
    }
    assert!(
        engine.exploratory_evictions > evictions_before,
        "rotation cycled the sleep slot around the pinned view"
    );
    assert!(
        seen.contains(&sleep_b) && seen.contains(&sleep_c),
        "both newcomers were covered around the pinned view: {seen:?}"
    );
    assert!(
        engine.exploratory_dirty.contains(&loader_view),
        "still pinned at the end"
    );
}

/// Package C fixture variant with distinct bytes but the identical driven
/// surface: `-O2` codegen instead of the default flags, same
/// `MATRIX_INTERFACES=0` (a nonzero interface count is undrivable — the
/// matrix reports 13, which matches no driver expectation — so byte
/// variance, not surface variance, distinguishes the build).
fn system_scope_build_fixture_variant(dir: &Path, name: &str) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/discover/tests/fixture/version_matrix.c");
    let library = dir.join(format!("{name}.so"));
    assert!(
        std::process::Command::new("gcc")
            .args(["-shared", "-fPIC", "-O2", "-DMATRIX_INTERFACES=0", "-o"])
            .arg(&library)
            .arg(source)
            .status()
            .unwrap()
            .success()
    );
    library
}

/// Package C: rotation evicts at most the per-pass bound however many
/// newcomers wait, and still converges — three unknowns behind a bound of
/// one drain over three sweeps while no single reconcile evicts twice.
#[test]
fn exploratory_rotation_respects_per_pass_eviction_bound() {
    let sleeps = e06_spawn_sleeps(3);
    let sleep_pids: Vec<u32> = sleeps.iter().map(|guard| guard.pid()).collect();
    let scope_dir = tempfile::tempdir().expect("a scope directory");
    e06_write_listing(scope_dir.path(), &sleep_pids);
    let scope = crate::scope::cgroup(scope_dir.path()).expect("open scope directory");
    let args = e06_cgroup_args(scope_dir.path(), vec![], Some(3));

    let mut engine = Engine::discover(&args, &scope, None).expect("a capped cgroup still captures");
    assert_eq!(engine.views.len(), 3);
    engine.scheduler.set_max_evictions_for_test(1);

    let newcomers = e06_spawn_sleeps(3);
    let fresh: Vec<u32> = newcomers.iter().map(|guard| guard.pid()).collect();
    let mut pids = sleep_pids.clone();
    pids.extend(fresh.iter().copied());
    e06_write_listing(scope_dir.path(), &pids);

    let mut seen: BTreeSet<u32> = BTreeSet::new();
    for _ in 1..=16 {
        let evictions_before = engine.exploratory_evictions;
        refresh_inventory_once(&mut engine);
        assert!(
            engine.exploratory_evictions - evictions_before <= 1,
            "no tick evicts past the bound of one"
        );
        assert_eq!(engine.views.len(), 3, "the cap binds throughout");
        seen.extend(engine.views.iter().map(|view| view.pid()));
    }
    for pid in &fresh {
        assert!(
            seen.contains(pid),
            "newcomer {pid} is covered within three sweeps: {seen:?}"
        );
    }
}

/// Package C: same-rarity rotation covers every pid within a finite bound —
/// six identical sleeps behind a cap of two, no providers anywhere. The
/// fairness tier keeps cooled evictees behind never-scanned pids, so each
/// sweep admits forward and the whole set is covered within six sweeps
/// (one representative per sweep for a single group).
#[test]
fn rotation_covers_every_pid_within_a_finite_bound() {
    let sleeps = e06_spawn_sleeps(6);
    let mut pids: Vec<u32> = sleeps.iter().map(|guard| guard.pid()).collect();
    pids.sort_unstable();
    let scope_dir = tempfile::tempdir().expect("a scope directory");
    e06_write_listing(scope_dir.path(), &pids);
    let scope = crate::scope::cgroup(scope_dir.path()).expect("open scope directory");
    let args = e06_cgroup_args(scope_dir.path(), vec![], Some(2));

    let mut engine = Engine::discover(&args, &scope, None).expect("a capped cgroup still captures");
    let mut seen: BTreeSet<u32> = engine.views.iter().map(|view| view.pid()).collect();
    for _ in 1..=24 {
        refresh_inventory_once(&mut engine);
        assert_eq!(engine.views.len(), 2, "the cap binds throughout");
        seen.extend(engine.views.iter().map(|view| view.pid()));
    }
    for pid in &pids {
        assert!(
            seen.contains(pid),
            "pid {pid} is covered within six sweeps: {seen:?}"
        );
    }
    assert!(
        engine.exploratory_evictions >= 4,
        "rotation walked the whole set: {}",
        engine.exploratory_evictions
    );
}

/// Package C, E05 at 256 and above the cap: 251 sleeps plus five provider
/// children (two sharing file A, one with B = A's equal bytes on a distinct
/// inode, one with C = distinct bytes on a distinct inode, one multi child
/// mapping A and C together) discover at the cap — every member
/// deep-scanned exactly once, the three physical providers distinct, each
/// shared file pinned once across all its generations. Then nine more
/// members (eight sleeps, one unique provider D) push past the cap:
/// rotation reaches D within the slice-coverage bound while the owned
/// providers never drop.
#[test]
fn e05_cross_module_admission_at_256_and_above_cap() {
    let dir = tempfile::tempdir().expect("a fixture directory");
    let provider_a = system_scope_build_fixture(dir.path(), "scale-a");
    let provider_b = dir.path().join("scale-b.so");
    std::fs::copy(&provider_a, &provider_b).expect("an equal-bytes copy");
    let provider_c = system_scope_build_fixture_variant(dir.path(), "scale-c");
    let provider_d = system_scope_build_fixture(dir.path(), "scale-d");
    let driver = system_scope_build_driver(dir.path());
    let hints = vec![
        provider_a.clone(),
        provider_b.clone(),
        provider_c.clone(),
        provider_d.clone(),
    ];

    let mut provider_children: Vec<SystemScopeChildGuard> = [
        provider_a.clone(),
        provider_a.clone(),
        provider_b.clone(),
        provider_c.clone(),
    ]
    .into_iter()
    .map(|provider| system_scope_spawn_loaded(&driver, &provider))
    .collect();
    provider_children.push(system_scope_spawn_loaded_multi(
        &driver,
        &[provider_a.clone(), provider_c.clone()],
    ));
    let guards = e06_spawn_sleeps(251);
    let mut pids: Vec<u32> = provider_children.iter().map(|guard| guard.pid()).collect();
    pids.extend(guards.iter().map(|guard| guard.pid()));
    assert_eq!(pids.len(), 256);
    let scope_dir = tempfile::tempdir().expect("a scope directory");
    e06_write_listing(scope_dir.path(), &pids);
    let scope = crate::scope::cgroup(scope_dir.path()).expect("open scope directory");
    let args = e06_cgroup_args(scope_dir.path(), hints, None);

    let mut engine = Engine::discover(&args, &scope, None).expect("the at-cap capture succeeds");
    // Deterministic paging: the wall-time quanta are covered by their own
    // tests, so pin them here — the five-sweep bound below measures
    // rotation/paging arithmetic, not scheduler wall time under parallel
    // load (a quantum-cut slice or deferred admission scan otherwise slips
    // late-pid coverage a sweep with correct explicit evidence).
    engine.scheduler.set_quantum_ns_for_test(u64::MAX);
    engine.scheduler.set_tick_quantum_ns_for_test(u64::MAX);
    assert_eq!(
        engine.views.len(),
        256,
        "every member is admitted at the cap"
    );
    assert_eq!(
        engine.deep_scans, 256,
        "every member is deep-scanned exactly once"
    );
    assert_eq!(engine.loader_arms, 0, "discovery alone arms nothing");
    let mut objects = BTreeMap::new();
    for name in ["scale-a.so", "scale-b.so", "scale-c.so"] {
        let modules: Vec<_> = engine
            .modules
            .iter()
            .filter(|module| module.scanned.path.ends_with(name))
            .collect();
        // A: two single children plus the multi child; C: one single plus
        // the multi child; B: its one copy child.
        let expected = if name == "scale-a.so" {
            3
        } else if name == "scale-c.so" {
            2
        } else {
            1
        };
        assert_eq!(
            modules.len(),
            expected,
            "{name}: one scanned module per mapping generation"
        );
        let object = modules[0].object;
        assert!(
            modules.iter().all(|module| module.object == object),
            "{name}: its generations share one pin"
        );
        objects.insert(name, object);
        assert!(
            !system_scope_slots_for(&engine, name).is_empty(),
            "{name} admits attachable slots"
        );
    }
    assert_ne!(
        objects["scale-a.so"], objects["scale-b.so"],
        "equal bytes on distinct inodes are distinct providers, never merged"
    );
    assert_ne!(
        objects["scale-a.so"], objects["scale-c.so"],
        "distinct bytes on distinct inodes are distinct providers"
    );
    assert_ne!(
        objects["scale-b.so"], objects["scale-c.so"],
        "the copy and the variant are distinct from each other"
    );

    // Above the cap: eight more sleeps and one unique provider. D has the
    // highest pid, so slice paging covers it no later than the fifth sweep.
    let extra_sleeps = e06_spawn_sleeps(8);
    let child_d = system_scope_spawn_loaded(&driver, &provider_d);
    pids.extend(extra_sleeps.iter().map(|guard| guard.pid()));
    pids.push(child_d.pid());
    assert_eq!(pids.len(), 265);
    e06_write_listing(scope_dir.path(), &pids);

    let mut first_seen = None;
    for frame in 1..=24 {
        refresh_inventory_once(&mut engine);
        assert_eq!(engine.views.len(), 256, "frame {frame}: the cap binds");
        if first_seen.is_none()
            && engine
                .plan
                .modules
                .iter()
                .any(|module| module.path.ends_with("scale-d.so"))
        {
            first_seen = Some(frame);
        }
    }
    let first_seen = first_seen.expect("rotation reaches D above the cap");
    assert!(
        first_seen <= 20,
        "slice paging covers D within five sweeps: frame {first_seen}"
    );
    assert!(
        !system_scope_slots_for(&engine, "scale-d.so").is_empty(),
        "D admits attachable slots"
    );
    for name in ["scale-a.so", "scale-b.so", "scale-c.so"] {
        assert!(
            engine
                .plan
                .modules
                .iter()
                .any(|module| module.path.ends_with(name)),
            "{name} survives above-cap rotation"
        );
    }
    assert!(
        engine.exploratory_evictions > 0,
        "rotation evicted to make room"
    );
    assert!(
        engine.deep_scans > 256,
        "rotation deep-scanned past discovery"
    );
    drop(provider_children);
    drop(child_d);
    drop(guards);
    drop(extra_sleeps);
}

/// Package C, E06 plus E14 at scale: 256 provider-free views at the cap, a
/// unique provider arriving later, then lifecycle churn (ten exits, ten
/// replacements with a second provider). Rotation reaches each provider
/// within the slice-coverage bound; exits settle within one reconcile;
/// reused view IDs always map to live generations with their providers
/// intact.
#[test]
fn e06_e14_rotation_and_lifecycle_recovery_at_scale() {
    let dir = tempfile::tempdir().expect("a fixture directory");
    let provider_e = system_scope_build_fixture(dir.path(), "scale-e");
    let provider_f = system_scope_build_fixture_variant(dir.path(), "scale-f");
    let driver = system_scope_build_driver(dir.path());
    let hints = vec![provider_e.clone(), provider_f.clone()];

    let mut guards = e06_spawn_sleeps(256);
    let mut pids: Vec<u32> = guards.iter().map(|guard| guard.pid()).collect();
    let scope_dir = tempfile::tempdir().expect("a scope directory");
    e06_write_listing(scope_dir.path(), &pids);
    let scope = crate::scope::cgroup(scope_dir.path()).expect("open scope directory");
    let args = e06_cgroup_args(scope_dir.path(), hints, None);

    let mut engine = Engine::discover(&args, &scope, None).expect("the at-cap capture succeeds");
    // Deterministic paging (same confound as the E05 scale twin): the
    // wall-time quanta are covered by their own tests, so pin them — the
    // five-sweep bound measures rotation/paging arithmetic, not scheduler
    // wall time under parallel load.
    engine.scheduler.set_quantum_ns_for_test(u64::MAX);
    engine.scheduler.set_tick_quantum_ns_for_test(u64::MAX);
    assert_eq!(engine.views.len(), 256);

    // E06 at scale: the unique provider has the highest pid, so slice
    // paging covers it no later than the fifth sweep.
    let child_e = system_scope_spawn_loaded(&driver, &provider_e);
    pids.push(child_e.pid());
    e06_write_listing(scope_dir.path(), &pids);
    let mut first_seen = None;
    for frame in 1..=24 {
        refresh_inventory_once(&mut engine);
        assert_eq!(engine.views.len(), 256, "frame {frame}: the cap binds");
        if first_seen.is_none()
            && engine
                .plan
                .modules
                .iter()
                .any(|module| module.path.ends_with("scale-e.so"))
        {
            first_seen = Some(frame);
        }
    }
    let first_seen = first_seen.expect("rotation reaches E at scale");
    assert!(
        first_seen <= 20,
        "slice paging covers E within five sweeps: frame {first_seen}"
    );

    // E14 at scale: ten exits plus ten replacements (one with provider F).
    // Back at 256 enumerated the capture is under-cap again, so departures
    // are authoritative immediately and F admits on the first tick.
    let dead: Vec<u32> = guards.drain(0..10).map(|guard| guard.pid()).collect();
    let replacements = e06_spawn_sleeps(9);
    let child_f = system_scope_spawn_loaded(&driver, &provider_f);
    pids.retain(|pid| !dead.contains(pid));
    pids.extend(replacements.iter().map(|guard| guard.pid()));
    pids.push(child_f.pid());
    e06_write_listing(scope_dir.path(), &pids);
    let mut f_seen = None;
    for frame in 1..=24 {
        refresh_inventory_once(&mut engine);
        let kept: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
        if frame >= 4 {
            for pid in &dead {
                assert!(
                    !kept.contains(pid),
                    "frame {frame}: exited pid {pid} settled"
                );
            }
        }
        if f_seen.is_none()
            && engine
                .plan
                .modules
                .iter()
                .any(|module| module.path.ends_with("scale-f.so"))
        {
            f_seen = Some(frame);
        }
    }
    let live: BTreeSet<u32> = pids.iter().copied().collect();
    for view in &engine.views {
        assert!(
            live.contains(&view.pid()),
            "every retained view maps a live generation: {}",
            view.pid()
        );
        assert!(view.still_the_same(), "no stale generation is retained");
    }
    for name in ["scale-e.so", "scale-f.so"] {
        assert!(
            engine
                .plan
                .modules
                .iter()
                .any(|module| module.path.ends_with(name)),
            "{name} is covered after churn"
        );
    }
    let f_seen = f_seen.expect("rotation reaches F after churn");
    assert!(
        f_seen <= 20,
        "under-cap admission covers F at once: frame {f_seen}"
    );
}
