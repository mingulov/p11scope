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

// RED-only forwarders for the approved consume-self signatures. These are
// compiled solely inside this cfg(test) child and invoke the existing owning
// destructor, including the real RetirementJob join. No production retention
// API exists yet. GREEN removes these forwarding implementations.
impl RetiringCapture {
    pub(crate) fn abandon_for_process_exit(self) {
        drop(self);
    }
}

impl RetiredCapture {
    pub(crate) fn abandon_for_process_exit(self) {
        drop(self);
    }
}

pub(crate) struct HostCaptureExitCase {
    pub(crate) capture: RetiringCapture,
    pub(crate) gate: Arc<crate::attach::cleanup_worker::concurrency_tests::CloseGate>,
    pub(crate) root: Weak<std::fs::File>,
    pub(crate) pin: Weak<std::fs::File>,
    pub(crate) raw_fd: std::os::fd::RawFd,
    pub(crate) calls: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) counts: (usize, usize, usize),
    _directory: tempfile::TempDir,
}

pub(crate) struct HostExitObservation {
    pub(crate) gate: Arc<crate::attach::cleanup_worker::concurrency_tests::CloseGate>,
    pub(crate) root: Weak<std::fs::File>,
    pub(crate) pin: Weak<std::fs::File>,
    pub(crate) raw_fd: std::os::fd::RawFd,
    pub(crate) calls: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) counts: (usize, usize, usize),
}

impl HostCaptureExitCase {
    pub(crate) fn release_on_unwind(&self) -> impl Drop + use<> {
        crate::attach::cleanup_worker::concurrency_tests::ReleaseGuard(Arc::clone(&self.gate))
    }

    pub(crate) fn observation(&self) -> HostExitObservation {
        HostExitObservation {
            gate: Arc::clone(&self.gate),
            root: self.root.clone(),
            pin: self.pin.clone(),
            raw_fd: self.raw_fd,
            calls: Arc::clone(&self.calls),
            counts: self.counts,
        }
    }
}

impl RetiringCapture {
    pub(crate) fn host_exit_case(mode: &str) -> HostCaptureExitCase {
        let owner = RetiringInventory::host_exit_owner(mode);
        let (directory, mut book, root) = cgroup_book();
        book.stopping = true;
        let capture = retiring_capture(
            RetiringInner::Retiring(Box::new(owner.retiring)),
            book,
            (mode != "pending").then(|| format!("host owned {mode} failure")),
        );
        HostCaptureExitCase {
            capture,
            gate: owner.gate,
            root,
            pin: owner.pin,
            raw_fd: owner.raw_fd,
            calls: owner.calls,
            counts: owner.counts,
            _directory: directory,
        }
    }

    /// Run intentional process-exit retention in one owned, bounded child.
    /// Every gated worker is released before assertions, including RED.
    pub(crate) fn run_host_exit_child(test_name: &str, body: impl FnOnce()) {
        const CHILD: &str = "P11SCOPE_INVENTORY_EXIT_RETENTION_CHILD";
        if std::env::var(CHILD).as_deref() == Ok(test_name) {
            body();
            return;
        }
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
            .env(CHILD, test_name)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut expired = false;
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                expired = true;
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !expired
                && output.status.success()
                && stdout.contains("running 1 test")
                && stdout.contains("1 passed"),
            "owned retention child failed (expired={expired}): {}{}",
            stdout,
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

fn capture_exit_control(mode: &'static str, retain: bool) {
    use crate::attach::cleanup_worker::concurrency_tests::ReleaseGuard;
    use std::sync::atomic::Ordering;

    let (made, case_receiver) = std::sync::mpsc::sync_channel(1);
    let (returned, observed) = std::sync::mpsc::sync_channel(1);
    // Construct the capture on its caller thread: process-exit retention
    // needs no Send assumption for the complete native state envelope.
    let caller = std::thread::Builder::new()
        .spawn(move || {
            let case = RetiringCapture::host_exit_case(mode);
            let _release = case.release_on_unwind();
            made.send(case.observation()).unwrap();
            let root_after = case.root.clone();
            let pin_after = case.pin.clone();
            let raw_fd = case.raw_fd;
            if retain {
                case.capture.abandon_for_process_exit();
            } else {
                drop(case.capture);
            }
            // SAFETY: inspect only this control's original descriptor. No
            // descriptor is opened/reused between destruction and this read.
            let open = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } >= 0;
            returned
                .send((
                    root_after.upgrade().is_some(),
                    pin_after.upgrade().is_some(),
                    open,
                ))
                .unwrap();
        })
        .unwrap();
    let case = case_receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    let release = ReleaseGuard(Arc::clone(&case.gate));
    let pending = match mode {
        "pending" => case
            .gate
            .wait_for(Duration::from_secs(1), |state| state.started.contains(&0)),
        "handoff" => case
            .gate
            .wait_for(Duration::from_secs(1), |state| state.started.contains(&9)),
        _ => true,
    };
    let early = observed.recv_timeout(Duration::from_millis(100)).ok();
    let root_during_gate = case.root.upgrade().is_some();
    let pin_during_gate = case.pin.upgrade().is_some();
    case.gate.release_all();
    caller.join().unwrap();
    let after = early.unwrap_or_else(|| observed.recv_timeout(Duration::from_secs(1)).unwrap());
    let finished = match mode {
        "pending" => case
            .gate
            .wait_for(Duration::from_secs(1), |state| state.completed.contains(&0)),
        "handoff" => case
            .gate
            .wait_for(Duration::from_secs(1), |state| state.completed.contains(&9)),
        _ => true,
    };
    drop(release);
    let snapshot = case.gate.snapshot();
    assert!(pending && finished, "actual worker gate: {snapshot:?}");
    assert!(snapshot.failures.is_empty(), "{snapshot:?}");
    assert_eq!(
        case.calls.load(Ordering::SeqCst),
        usize::from(mode == "pending" || mode == "residual")
    );
    assert_eq!(
        case.counts,
        if mode == "residual" {
            (1, 0, 1)
        } else {
            (0, 0, 0)
        }
    );
    if retain {
        assert!(
            early.is_some(),
            "full capture drop waited for the actual job"
        );
        assert_eq!(
            after,
            (true, true, true),
            "some original owner dropped on exit retention"
        );
        assert!(root_during_gate && pin_during_gate);
    } else {
        assert!(
            early.is_none(),
            "ordinary reclaim bypassed the actual job gate"
        );
        assert!(root_during_gate && pin_during_gate);
        assert_eq!(after, (false, false, false));
    }
}

#[test]
fn inventory_exit_retention_pending_capture_returns_before_actual_job_close() {
    RetiringCapture::run_host_exit_child(
        "attach::inventory::capture::cgroup_tests::inventory_exit_retention_pending_capture_returns_before_actual_job_close",
        || capture_exit_control("pending", true),
    );
}

#[test]
fn inventory_exit_retention_unstarted_work_keeps_its_original_fd_and_files() {
    RetiringCapture::run_host_exit_child(
        "attach::inventory::capture::cgroup_tests::inventory_exit_retention_unstarted_work_keeps_its_original_fd_and_files",
        || capture_exit_control("unstarted", true),
    );
}

#[test]
fn inventory_exit_retention_failed_handoff_keeps_work_and_empty_worker_owner() {
    RetiringCapture::run_host_exit_child(
        "attach::inventory::capture::cgroup_tests::inventory_exit_retention_failed_handoff_keeps_work_and_empty_worker_owner",
        || capture_exit_control("handoff", true),
    );
}

#[test]
fn inventory_exit_retention_failed_residual_is_held_without_closed_credit() {
    RetiringCapture::run_host_exit_child(
        "attach::inventory::capture::cgroup_tests::inventory_exit_retention_failed_residual_is_held_without_closed_credit",
        || capture_exit_control("residual", true),
    );
}

#[test]
fn inventory_exit_retention_ordinary_reclaim_still_waits_for_actual_close() {
    RetiringCapture::run_host_exit_child(
        "attach::inventory::capture::cgroup_tests::inventory_exit_retention_ordinary_reclaim_still_waits_for_actual_close",
        || capture_exit_control("pending", false),
    );
}

#[test]
fn inventory_exit_retention_retired_capture_keeps_the_original_book_root() {
    RetiringCapture::run_host_exit_child(
        "attach::inventory::capture::cgroup_tests::inventory_exit_retention_retired_capture_keeps_the_original_book_root",
        || {
            let (_directory, book, root) = cgroup_book();
            let retired = retiring_capture(RetiringInner::Unactivated(None), book, None)
                .try_finish()
                .ok()
                .unwrap();
            retired.abandon_for_process_exit();
            assert!(
                root.upgrade().is_some(),
                "inner-only retention lost CaptureBook root"
            );
        },
    );
}
