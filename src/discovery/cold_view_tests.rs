//! SPDX-License-Identifier: GPL-3.0-or-later
//! Future R56: cold snapshots are hints; deep scans retain actual group custody.

use super::*;
use crate::process::cold_view_tests::ColdLeaderSubject;

#[test]
fn cold_group_sweep_reads_live_member_maps_as_advisory_hints() {
    let mut group = ColdLeaderSubject::spawn(1);
    group.leave_leader();
    let mut budget = CaptureWorkBudget::default();

    let (snapshots, unavailable, skipped) =
        sweep_process_maps(&[group.pid()], &mut budget).into_selection_with_unavailable();

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

    let (_, unavailable, skipped) =
        sweep_process_maps(&[group.pid()], &mut budget).into_selection_with_unavailable();

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
    assert!(crate::discovery::scan::scan_pid(&request, &mut scan_budget).is_err());
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
