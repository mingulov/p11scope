//! SPDX-License-Identifier: GPL-3.0-or-later
//! Cgroup capture facade controls; filesystem and scripted IO only.

use super::super::activation::validate_capture_activation;
use super::*;
use std::sync::{Arc, Weak};

fn accepts_cgroup(backend: AttachBackend) {
    let root = tempfile::tempdir().unwrap();
    let scope = crate::scope::cgroup(root.path()).unwrap();
    let budget = InventoryBudget::new(1, 8).unwrap();
    let targets = InventoryTargets::for_capture(budget);
    validate_capture_activation(&scope, None, backend, budget, &targets)
        .expect("the facade must activate the retained cgroup with all-process entry links");
}

#[test]
fn cgroup_capture_activation_accepts_singles_without_pid_custody() {
    accepts_cgroup(AttachBackend::Singles);
}

#[test]
fn cgroup_capture_activation_accepts_multi_without_pid_custody() {
    accepts_cgroup(AttachBackend::Multi);
}

#[test]
fn cgroup_constructor_refuses_system_and_pid_scopes() {
    for scope in [Scope::System, Scope::Pid(7)] {
        let error = CaptureScope::cgroup(scope)
            .err()
            .expect("wrong scope refused");
        assert!(format!("{error:#}").contains("retained cgroup scope"));
    }
}

#[test]
fn cgroup_entry_scope_is_all_processes_for_both_link_backends() {
    let root = tempfile::tempdir().unwrap();
    let scope = crate::scope::cgroup(root.path()).unwrap();
    let entry_scope = super::super::activation::capture_entry_scope(&scope);
    assert!(matches!(
        entry_scope,
        aya::programs::uprobe::UProbeScope::AllProcesses
    ));
    assert_eq!(crate::attach::multi_link_pid(entry_scope), 0);
}

fn cgroup_book() -> (tempfile::TempDir, CaptureBook, Weak<std::fs::File>) {
    let root = tempfile::tempdir().unwrap();
    let scope = crate::scope::cgroup(root.path()).unwrap();
    let capture = CaptureScope::cgroup(scope).unwrap();
    assert_eq!(capture.scope_coverage(), CaptureScopeCoverage::Cgroup);
    let CaptureScope::Cgroup(cgroup) = &capture else {
        unreachable!()
    };
    let weak = Arc::downgrade(cgroup.root());
    let prepared = capture.into_prepared_scope().unwrap();
    let book = CaptureBook::new_scoped(
        InventoryBudget::new(1, 8).unwrap(),
        8,
        prepared.held_scope,
        100,
    );
    drop(prepared.scope);
    (root, book, weak)
}

#[test]
fn cgroup_filter_custody_is_distinct_and_lifecycle_loss_does_not_fake_pid_loss() {
    let (_root, mut book, _) = cgroup_book();
    assert_eq!(book.scope_coverage(), CaptureScopeCoverage::Cgroup);
    assert_eq!(book.custody(), ScopeCustody::CgroupHeld);
    book.mark_lifecycle_loss(150, "ring loss".into());
    assert_eq!(book.custody(), ScopeCustody::CgroupHeld);
    assert_eq!(book.lifecycle_loss().unwrap().at_ns, 150);
}

#[test]
fn unactivated_stop_keeps_root_through_terminal_reads_until_drop() {
    let (_root, book, weak) = cgroup_book();
    let capture = InventoryCapture {
        state: CaptureState::Moving,
        book,
    };
    let mut retiring = capture.begin_stop();
    assert!(weak.upgrade().is_some());
    let read = retiring
        .read_witnesses(ReadWindow::new(1, Instant::now() + Duration::from_secs(1)).unwrap());
    assert_eq!(read.custody, ScopeCustody::CgroupHeld);
    let mut retired = retiring
        .try_finish()
        .ok()
        .expect("no producers need detaching");
    assert!(weak.upgrade().is_some());
    let read = retired
        .read_witnesses(ReadWindow::new(1, Instant::now() + Duration::from_secs(1)).unwrap());
    assert_eq!(read.custody, ScopeCustody::CgroupHeld);
    drop(retired);
    assert!(weak.upgrade().is_none());
}

#[test]
fn active_and_failed_branches_share_the_root_preserving_retirement_transfer() {
    // The same unconditional assembly called after Active/Failed detach
    // transitions; kernel link IO is outside this ownership control.
    let (_root, mut book, weak) = cgroup_book();
    book.stopping = true;
    book.attached.insert(0);
    let mut retiring = retiring_capture(
        RetiringInner::Unactivated(None),
        book,
        Some("failed after activation".into()),
    );
    assert!(weak.upgrade().is_some());
    assert_eq!(
        retiring
            .read_witnesses(ReadWindow::new(1, Instant::now() + Duration::from_secs(1)).unwrap())
            .custody,
        ScopeCustody::CgroupHeld
    );
    let mut retired = retiring
        .try_finish()
        .ok()
        .expect("no kernel IO in this control");
    assert!(weak.upgrade().is_some());
    assert_eq!(
        retired
            .read_witnesses(ReadWindow::new(1, Instant::now() + Duration::from_secs(1)).unwrap())
            .custody,
        ScopeCustody::CgroupHeld
    );
    drop(retired);
    assert!(weak.upgrade().is_none());
}
