//! SPDX-License-Identifier: GPL-3.0-or-later
//! Future R56: cold snapshots are hints; deep scans retain actual group custody.

use super::*;
use crate::process::cold_view_tests::ColdLeaderSubject;

#[test]
fn cold_group_sweep_reads_live_member_maps_as_advisory_hints() {
    let mut group = ColdLeaderSubject::spawn(1);
    group.leave_leader();
    let mut budget = CaptureWorkBudget::default();

    let sweep = sweep_process_maps(&[group.pid()], &mut budget);
    eprintln!(
        "R56 live-survivor sweep: leader_maps_bytes={:?}, snapshots={:?}, io={}, stop={:?}",
        std::fs::read(format!("/proc/{}/maps", group.pid())).map(|bytes| bytes.len()),
        sweep
            .snapshots
            .iter()
            .map(|(_, snapshot)| match snapshot {
                MapsSnapshot::Read(maps) => Some(maps.len()),
                MapsSnapshot::Unavailable => None,
            })
            .collect::<Vec<_>>(),
        budget.attempted_io_bytes(),
        budget.stopped_reason(),
    );
    let (snapshots, unavailable, skipped) = sweep.into_selection_with_unavailable();

    assert!(unavailable.is_empty(), "{skipped:?}");
    let maps = &snapshots
        .iter()
        .find(|(pid, _)| *pid == group.pid())
        .expect("the TGID keeps its row")
        .1;
    let index = MapIndex::new(maps).unwrap();
    assert!(
        maps.iter()
            .any(|mapping| matches!(index.resolve(mapping.start),
            Resolved::File { path: MappedPath::Usable(path), .. } if path == group.program)),
        "the actual exported provider's executable is present in the cold snapshot"
    );
    // The snapshot never promotes a numeric survivor TID into a scope member.
    assert!(
        group
            .tids
            .iter()
            .all(|tid| snapshots.iter().all(|(pid, _)| pid != tid))
    );
    group.call_three();
}

#[test]
fn cold_group_deep_scan_keeps_sparse_provider_targets_useful() {
    for workers in [1, 2] {
        let mut group = ColdLeaderSubject::spawn(workers);
        group.leave_leader();
        let view = ProcessView::open(ProcessViewId(81), group.pid())
            .expect("the first deep-scan view opens after leader exit");
        let mut budget = CaptureWorkBudget::default();
        let mut timings = crate::timing::StageTimings::new();

        let (scan, counters) = Engine::scan_retained_view(
            &view,
            std::slice::from_ref(&group.program),
            &HookRegistry::builtin(),
            &mut budget,
            false,
            &mut timings,
        );

        let (modules, pins, _) =
            scan.expect("cold discovery scans the actual member address space");
        let module = modules
            .iter()
            .find(|module| Path::new(&module.path) == group.program)
            .expect("the mapped sparse provider remains discoverable");
        assert_eq!(module.view, view.id());
        assert_eq!(module.mount_namespace, view.mount_namespace());
        assert!(
            module
                .exports
                .iter()
                .any(|name| name == "C_GetFunctionList")
        );
        assert!(
            module.tables.iter().any(|table| table.version == (3, 2)
                && table
                    .entries
                    .iter()
                    .any(|entry| entry.name == "C_Initialize")
                && table.null_entries.len() >= 67),
            "a successful empty scan is not enough: {module:?}; skips={:?}",
            counters.object_skips,
        );
        assert!(
            pins.pinned().next().is_some(),
            "targets retain actual file pins"
        );
        group.call_three();
    }
}

#[test]
fn cold_group_discovery_keeps_tgid_scope_and_actual_callback_target() {
    for workers in [1, 2] {
        let mut group = ColdLeaderSubject::spawn(workers);
        group.leave_leader();
        let maps = parse_maps(
            &std::fs::read(format!("/proc/{}/task/{}/maps", group.pid(), group.tids[0])).unwrap(),
        )
        .unwrap();
        let index = MapIndex::new(&maps).unwrap();
        let mapping = index.containing(group.callback_address).unwrap();
        let expected_offset = mapping.file_offset + group.callback_address - mapping.start;
        let args = CaptureArgs {
            kind: crate::cli::Kind::Profile,
            modules: vec![group.program.clone()],
            manifests: vec![],
            prearm_modules: vec![],
            hooks: HookRegistry::builtin(),
            scope: crate::cli::ScopeArg::Pid(group.pid()),
            metrics: false,
            counter_mode: None,
            duration: None,
            out: None,
            max_events: None,
            max_scan_pids: None,
            ring_bytes: None,
            drain_interval: None,
            unsafe_requested: false,
            allow_confined_uretprobe: false,
            attach_backend: BackendSelection::default(),
        };
        let view = ProcessView::open(ProcessViewId(0), group.pid()).unwrap();
        let engine = Engine::discover(&args, &Scope::Pid(group.pid()), Some(view)).unwrap();
        assert!(engine.views.iter().any(|view| view.pid() == group.pid()));
        assert!(
            group
                .tids
                .iter()
                .all(|tid| engine.views.iter().all(|view| view.pid() != *tid))
        );
        assert!(
            engine
                .plan()
                .slots
                .iter()
                .any(|slot| slot.file_offset == expected_offset
                    && Path::new(&slot.object_path) == group.program),
            "cold discovery needs the actual callable target: {:?}",
            engine.plan()
        );
        group.call_three();
    }
}

#[test]
fn cold_group_sweep_does_not_classify_ended_metadata_as_empty_success() {
    let mut group = ColdLeaderSubject::spawn(0);
    group.leave_leader();
    let mut budget = CaptureWorkBudget::default();

    let sweep = sweep_process_maps(&[group.pid()], &mut budget);
    eprintln!(
        "R56 ended-group sweep: leader_maps_bytes={:?}, snapshots={:?}, io={}, stop={:?}",
        std::fs::read(format!("/proc/{}/maps", group.pid())).map(|bytes| bytes.len()),
        sweep
            .snapshots
            .iter()
            .map(|(_, snapshot)| match snapshot {
                MapsSnapshot::Read(maps) => Some(maps.len()),
                MapsSnapshot::Unavailable => None,
            })
            .collect::<Vec<_>>(),
        budget.attempted_io_bytes(),
        budget.stopped_reason(),
    );
    let (_, unavailable, skipped) = sweep.into_selection_with_unavailable();

    assert!(unavailable.contains(&group.pid()));
    assert!(
        skipped.is_some(),
        "an unresolved empty map snapshot stays unavailable"
    );
}

#[test]
fn cold_scan_and_pin_entrypoints_use_the_passed_capture_budget() {
    let mut group = ColdLeaderSubject::spawn(1);
    group.leave_leader();
    let hooks = HookRegistry::builtin();
    let hints = [group.program.clone()];
    let request = crate::discovery::scan::ScanRequest {
        pid: group.pid(),
        hints: &hints,
        hooks: &hooks,
    };
    let mut scan_budget = CaptureWorkBudget::with_work_ceiling(0);
    let stopped = crate::discovery::scan::scan_pid(&request, &mut scan_budget).unwrap();
    assert!(stopped.modules().is_empty());
    assert!(!stopped.mapping_scan_completed());
    assert!(
        stopped
            .skipped()
            .iter()
            .any(|skip| skip.subject == "capture discovery"
                && skip.reason == crate::discovery::scan::WORK_CEILING_REASON)
    );
    assert_eq!(scan_budget.attempted_io_bytes(), 0);
    let mut pin_budget = CaptureWorkBudget::with_work_ceiling(0);
    assert!(
        crate::discovery::identity::pin_scanned_objects(group.pid(), &[], &mut pin_budget).is_err()
    );
    assert_eq!(pin_budget.attempted_io_bytes(), 0);
    let mut healthy = CaptureWorkBudget::default();
    let scan = crate::discovery::scan::scan_pid(&request, &mut healthy).unwrap();
    assert!(
        scan.modules()
            .iter()
            .any(|module| Path::new(&module.path) == group.program)
    );
    group.call_three();
}

#[test]
fn cold_reconcile_uses_survivor_hints_and_keeps_ended_metadata_unknown() {
    let mut ended = ColdLeaderSubject::spawn(0);
    ended.leave_leader();
    let mut live = ColdLeaderSubject::spawn(1);
    live.leave_leader();
    let mut pids = vec![ended.pid(), live.pid()];
    pids.sort_unstable();
    let mut engine = Engine::empty();
    engine.scope = Scope::System;
    engine.scheduler.set_quantum_ns_for_test(u64::MAX);
    let selected = engine.reconcile_slice(&pids, &BTreeSet::new(), 1);
    assert_eq!(
        selected,
        vec![live.pid()],
        "actual survivor shared-object mappings must beat the unknown row"
    );
    assert!(engine.budget.attempted_io_bytes() > 0);
    assert!(engine.counters.object_skips.iter().any(|skip| {
        skip.subject == "process maps sweep" && skip.reason.contains("1 of 2 attempted")
    }));
    live.call_three();
}

fn stop_after_initial_empty_maps_read(pid: u32) -> CaptureWorkBudget {
    use crate::discovery::scan::CollectionWork;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Calibrate the real primary maps reader, without a cold completion.
    // The next checkpoint belongs to the serial cold stage in both callers.
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let mut calibration = CaptureWorkBudget::default();
    calibration.set_collection_work(CollectionWork::new(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
        true
    }));
    let primary = sweep_process_maps_with(
        &[pid],
        &mut calibration,
        1,
        MapsReadLimits::LIVE,
        &|pid| std::fs::File::open(format!("/proc/{pid}/maps")),
        &crate::attach::monotonic_ns,
    );
    assert!(matches!(&primary.snapshots[0].1, MapsSnapshot::Read(maps) if maps.is_empty()));
    let primary_calls = calls.load(Ordering::SeqCst);
    assert!(primary_calls > 0);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut budget = CaptureWorkBudget::default();
    budget.set_collection_work(CollectionWork::new(move |_| {
        calls.fetch_add(1, Ordering::SeqCst) < primary_calls
    }));
    budget
}

#[test]
fn cold_initial_stop_after_empty_read_keeps_unknown_without_metadata_io() {
    let mut group = ColdLeaderSubject::spawn(1);
    group.leave_leader();
    let mut budget = stop_after_initial_empty_maps_read(group.pid());
    let sweep = sweep_process_maps(&[group.pid()], &mut budget);
    assert!(budget.stopped_reason().is_some());
    assert_eq!(budget.attempted_io_bytes(), 0);
    let (_, unavailable, skipped) = sweep.into_selection_with_unavailable();
    assert!(unavailable.contains(&group.pid()));
    assert!(skipped.is_some());
    group.call_three();
}

#[test]
fn cold_reconcile_stop_after_empty_read_keeps_unknown_without_metadata_io() {
    let mut group = ColdLeaderSubject::spawn(1);
    group.leave_leader();
    let mut engine = Engine::empty();
    engine.scope = Scope::System;
    engine.scheduler.set_quantum_ns_for_test(u64::MAX);
    engine.budget = stop_after_initial_empty_maps_read(group.pid());
    let selected = engine.reconcile_slice(&[group.pid()], &BTreeSet::new(), 1);
    assert_eq!(selected, vec![group.pid()], "unknown stays eligible");
    assert!(engine.budget.stopped_reason().is_some());
    assert_eq!(engine.budget.attempted_io_bytes(), 0);
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .any(|skip| skip.subject == "process maps sweep")
    );
    group.call_three();
}

#[test]
fn cold_initial_and_reconcile_expiry_preserve_unknown_without_metadata_io() {
    for workers in [0, 1] {
        let mut group = ColdLeaderSubject::spawn(workers);
        group.leave_leader();
        let mut budget = CaptureWorkBudget::default();
        budget.set_deadline(Some(0));
        let (_, unavailable, skipped) =
            sweep_process_maps(&[group.pid()], &mut budget).into_selection_with_unavailable();
        assert!(unavailable.contains(&group.pid()));
        assert!(skipped.is_some());
        assert_eq!(budget.attempted_io_bytes(), 0);

        let mut engine = Engine::empty();
        engine.scope = Scope::System;
        engine.scheduler.set_quantum_ns_for_test(u64::MAX);
        engine.budget.set_deadline(Some(0));
        assert_eq!(
            engine.reconcile_slice(&[group.pid()], &BTreeSet::new(), 1),
            vec![group.pid()]
        );
        assert_eq!(engine.budget.attempted_io_bytes(), 0);
        assert!(
            engine
                .counters
                .object_skips
                .iter()
                .any(|skip| skip.subject == "process maps sweep")
        );
        if workers != 0 {
            group.call_three();
        }
    }
}

#[test]
fn generic_maps_sweep_record_preserves_successful_empty_without_cold_classification() {
    let mut sweep = MapsSweep::default();
    sweep.record(7, Ok(Vec::new()));
    assert_eq!(sweep.read(), 1);
    let (hints, unavailable, skipped) = sweep.into_selection_with_unavailable();
    assert_eq!(hints, vec![(7, Vec::new())]);
    assert!(unavailable.is_empty());
    assert!(skipped.is_none());
}
