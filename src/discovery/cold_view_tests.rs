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
    let mut group = ColdLeaderSubject::spawn(1);
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

    let (modules, pins, _) = scan.expect("cold discovery scans the actual member address space");
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
