//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Runtime controls use real scoped collection/commit over an owned provider.
//! Scripted capture service does not qualify a kernel capture or public cgroupfs.

use super::*;
use crate::discovery::engine::inventory_coordinator::tests::cgroup_provider_scene;
use crate::inventory_capture::{CgroupCollectJob, worker_spawn_test};
use crate::scope::inventory_cgroup::{
    CgroupWalkLimits, CgroupWalkState, CollectionControl, CollectionStop,
};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;

type JobWrapper = Box<dyn FnOnce(CgroupCollectJob) -> CgroupCollectJob>;

struct ObservedDriver<'a> {
    inner: ClassicDriver<'a>,
    wrapper: Option<JobWrapper>,
    tick: Option<Box<dyn FnMut()>>,
    collections: Arc<AtomicUsize>,
    log: Rc<RefCell<Vec<String>>>,
}

impl<'a> ObservedDriver<'a> {
    fn new(
        coordinator: &'a mut InventoryCoordinator<OsProcessSource>,
        control: CollectionControl,
    ) -> Self {
        let seal_scope = coordinator.engine_scope_for_test();
        Self {
            inner: ClassicDriver {
                coordinator,
                inventory_scope: None,
                scope: InventoryRunScope::Cgroup,
                seal_scope,
                cgroup: Some(CgroupDriverState {
                    observer: None,
                    continuation: Some(CgroupWalkState::default()),
                    limits: CgroupWalkLimits::default(),
                    control,
                    deadline: None,
                    last_outcome: None,
                    resume: SnapshotResumeLedger::default(),
                }),
                max_scan_pids: None,
                guard: UnavailableImageGuard,
                deadline: None,
                attach_backend: crate::attach::BackendSelection::Auto,
                display: None,
                semantic: None,
                scan_seal_pending: false,
                scan_seal_last_sets: None,
                scan_seal_stable_runs: 0,
                scan_seal_waited: 0,
                scan_seal_changed: false,
                semantic_staged: false,
                seated_summary: None,
                second_signal: None,
                lifecycle: crate::inventory_promotion::lifecycle::SelectedLifecycleService::new(),
                completion_source: None,
                pending_install: None,
                installed_promotion: None,
                retiring: None,
                identity: None,
                joint_finish: JointFinishDriver::NotBegun,
                stop_requested: false,
                prearm_stop_probe: None,
                prearm_probe_stop: None,
                joint_first_error: None,
                suspended: false,
                joint_commit_pending: false,
                joint_tick_refusal: None,
                joint_commit_retries: 0,
                #[cfg(test)]
                terminal_seq_calls: 0,
                #[cfg(test)]
                reclaim_calls: Vec::new(),
                #[cfg(test)]
                joint_begin_calls: 0,
                #[cfg(test)]
                joint_step_calls: 0,
                #[cfg(test)]
                joint_commit_polls: 0,
                #[cfg(test)]
                take_promotion_work_calls: 0,
                #[cfg(test)]
                drive_pending_install_calls: 0,
                #[cfg(test)]
                service_caller_metadata_calls: 0,
                #[cfg(test)]
                commit_calls: 0,
            },
            wrapper: None,
            tick: None,
            collections: Arc::new(AtomicUsize::new(0)),
            log: Rc::default(),
        }
    }
}

impl PassDriver<PidPin> for ObservedDriver<'_> {
    type Host = InventoryCoordinator<OsProcessSource>;
    fn host(&mut self) -> &mut Self::Host {
        self.inner.host()
    }
    fn collector(&mut self) -> CollectJob {
        self.collections.fetch_add(1, Ordering::SeqCst);
        let job = self.inner.collector();
        match (job, self.wrapper.take()) {
            (
                CollectJob::Cgroup {
                    control,
                    task: Ok(task),
                },
                Some(wrapper),
            ) => CollectJob::Cgroup {
                control,
                task: Ok(wrapper(task)),
            },
            (job, _) => job,
        }
    }
    fn collection_control(&self) -> Option<CollectionControl> {
        self.inner.collection_control()
    }
    fn apply(
        &mut self,
        collected: CollectedPass,
        identity: &mut dyn NativeIdentity<PidPin>,
        now: u64,
    ) -> Result<PassReport> {
        self.log.borrow_mut().push("apply".into());
        self.inner.apply(collected, identity, now)
    }
    fn commit(&mut self, changed: bool) -> Result<()> {
        self.log.borrow_mut().push("commit".into());
        self.inner.commit(changed)
    }
    fn finish_pass(&mut self, report: &mut PassReport) -> Result<()> {
        self.log.borrow_mut().push("completion".into());
        self.inner.finish_pass(report)
    }
    fn snapshot_resume_pending(&mut self) -> bool {
        self.inner.snapshot_resume_pending()
    }
    fn on_tick(&mut self) {
        self.inner.on_tick();
        if let Some(tick) = &mut self.tick {
            tick();
        }
    }
}

fn clock(stop: &dyn Fn() -> bool) -> LoopClock<'_> {
    LoopClock {
        deadline: None,
        stop,
        now: &Instant::now,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: Duration::from_millis(1),
    }
}

#[test]
fn cgroup_runtime_stopped_startup_performs_no_collection() {
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let control = CollectionControl::new(None);
    let mut driver = ObservedDriver::new(&mut coordinator, control.clone());
    let calls = driver.collections.clone();
    let mut publications = 0;
    let result = run_classic_finalizing::<PidPin, _, FacadeLane>(
        &mut driver,
        None,
        &clock(&|| true),
        None,
        &mut |_, publication| {
            if matches!(publication, Publish::Pass { .. }) {
                publications += 1;
            }
            Ok(())
        },
    );
    assert!(result.error.is_none());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "startup stop precedes the first collection operation"
    );
    assert_eq!(publications, 0);
    assert_eq!(control.check(), Err(CollectionStop::OperatorStop));
    assert_eq!(driver.inner.coordinator.registry().caller_count(), 0);
}

/// The main tick acts only after an actual positive /proc maps read returned.
fn returning_read_gate(stop_on_tick: bool) {
    returning_read_control_gate(
        if stop_on_tick {
            GateStop::Operator
        } else {
            GateStop::Healthy
        },
        false,
    );
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GateStop {
    Healthy,
    Operator,
    Deadline,
}

fn returning_read_control_gate(reason: GateStop, native: bool) {
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let expired = Arc::new(AtomicBool::new(false));
    let clock_expired = expired.clone();
    let base = Instant::now();
    let deadline = (reason == GateStop::Deadline).then_some(base + Duration::from_secs(1));
    let control = CollectionControl::with_clock(deadline, move || {
        if clock_expired.load(Ordering::SeqCst) {
            base + Duration::from_secs(1)
        } else {
            base
        }
    });
    let (capture, native_log) = crate::inventory_capture::tests::cgroup_runtime_lane();
    let lane = native.then(|| {
        NativeLane::start(capture, &mut coordinator, LaneWindows::PROVISIONAL, None)
            .map_err(|(_, reason)| reason)
            .unwrap()
    });
    let initial_services = native_log
        .borrow()
        .iter()
        .filter(|entry| *entry == "service")
        .count();
    let serviced_while_held = Rc::new(std::cell::Cell::new(false));
    let tick_service = serviced_while_held.clone();
    let tick_native_log = native_log.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicUsize::new(0));
    let returned = Arc::new(AtomicBool::new(false));
    let ticks = Arc::new(AtomicUsize::new(0));
    let (read_sender, read_receiver) = mpsc::sync_channel(1);
    let (release_sender, release_receiver) = mpsc::sync_channel(1);
    let mut driver = ObservedDriver::new(&mut coordinator, control.clone());
    let calls = driver.collections.clone();
    let worker_reads = reads.clone();
    let worker_returned = returned.clone();
    driver.wrapper = Some(Box::new(move |job| {
        Box::new(move || {
            let mut first = true;
            let collection = crate::discovery::scan::maps_read_test::observe(
                move |bytes| {
                    if bytes > 0 {
                        worker_reads.fetch_add(1, Ordering::SeqCst);
                        if first {
                            first = false;
                            read_sender.send(()).unwrap();
                            release_receiver
                                .recv_timeout(Duration::from_secs(5))
                                .expect("main service tick must release the returning read");
                        }
                    }
                },
                job,
            );
            worker_returned.store(true, Ordering::SeqCst);
            collection
        })
    }));
    let tick_stop = stop.clone();
    let tick_count = ticks.clone();
    driver.tick = Some(Box::new(move || {
        if read_receiver.try_recv().is_ok() {
            // Mirrors dashboard quit: drawing sets stop; cancellation must
            // be latched after on_tick returns, before the next worker unit.
            tick_stop.store(reason == GateStop::Operator, Ordering::SeqCst);
            expired.store(reason == GateStop::Deadline, Ordering::SeqCst);
            if native {
                tick_service.set(
                    tick_native_log
                        .borrow()
                        .iter()
                        .filter(|entry| *entry == "service")
                        .count()
                        > initial_services,
                );
            }
            tick_count.fetch_add(1, Ordering::SeqCst);
            release_sender.send(()).unwrap();
        }
    }));
    let stop_requested = || stop.load(Ordering::SeqCst);
    let mut loop_clock = clock(&stop_requested);
    loop_clock.deadline = deadline;
    let mut terminal_publications = 0;
    let result = run_classic_finalizing(&mut driver, lane, &loop_clock, None, &mut |_, point| {
        if matches!(point, Publish::Stop { .. }) {
            terminal_publications += 1;
        }
        Ok(())
    });
    assert!(result.error.is_none(), "{:?}", result.error);
    assert!(
        reads.load(Ordering::SeqCst) > 0,
        "actual scanner I/O reached the returning-read gate"
    );
    assert_eq!(ticks.load(Ordering::SeqCst), 1);
    assert!(
        returned.load(Ordering::SeqCst),
        "the owned worker returned before finalization"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "no next or recovery collection after stop"
    );
    if reason == GateStop::Healthy {
        assert_eq!(control.check(), Ok(()));
        assert_eq!(driver.inner.coordinator.registry().caller_count(), 1);
        assert!(driver.inner.coordinator.registry().edges().next().is_some());
    } else if reason == GateStop::Deadline {
        // Owner rule 2026-11-09: pass 0 completes past the deadline,
        // so the run publishes the scanned caller like the healthy
        // twin instead of discarding into 0 callers. The run control
        // still latches, and the staged delta is never taken past
        // the stop.
        assert_eq!(control.check(), Err(CollectionStop::Deadline));
        assert_eq!(driver.inner.coordinator.registry().caller_count(), 1);
        assert!(driver.inner.coordinator.registry().edges().next().is_some());
        assert!(
            !driver
                .inner
                .coordinator
                .take_target_delta()
                .endpoints
                .is_empty(),
            "the completed commit stages its delta; the stopped run takes nothing"
        );
    } else {
        assert_eq!(control.check(), Err(CollectionStop::OperatorStop));
        assert_eq!(
            driver.inner.coordinator.registry().caller_count(),
            0,
            "an operator stop still cancels the worker promptly"
        );
        assert!(
            driver
                .inner
                .coordinator
                .take_target_delta()
                .endpoints
                .is_empty()
        );
    }
    if native {
        assert!(
            serviced_while_held.get(),
            "native lifecycle service continues while the returning read is held"
        );
        let stopped = result
            .stopped
            .as_ref()
            .expect("active native lane finalizes");
        assert_eq!(stopped.summary.passes, 1);
        assert!(matches!(
            stopped.summary.retirement,
            crate::inventory_capture::Retirement::Closed(_)
        ));
        assert_eq!(terminal_publications, 1);
        let log = native_log.borrow();
        let begin_stop = log.iter().position(|entry| entry == "begin_stop").unwrap();
        assert!(log[..begin_stop].iter().any(|entry| entry == "read"));
        assert!(log[begin_stop + 1..].iter().any(|entry| entry == "read"));
    }
}

#[test]
fn cgroup_runtime_explicit_deadline_during_returning_worker_stops_owned_job() {
    returning_read_control_gate(GateStop::Deadline, false);
}

#[test]
fn cgroup_runtime_cancelled_worker_keeps_native_service_join_and_finalization() {
    returning_read_control_gate(GateStop::Operator, true);
}

/// Owner rule 2026-11-09: a timed `--cgroup` run shorter than the
/// first full pass publishes the members its pass-0 collection saw
/// instead of discarding into 0 callers. The deadline expires
/// mid-collection (after the first scanner read returns, like the
/// busy-host shape); the scanned provider caller must still publish.
#[test]
fn cgroup_short_timed_run_publishes_scanned_pass0() {
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let base = Instant::now();
    let deadline = base + Duration::from_millis(200);
    let control = CollectionControl::new(Some(deadline));
    let mut driver = ObservedDriver::new(&mut coordinator, control.clone());
    let calls = driver.collections.clone();
    let reads = Arc::new(AtomicUsize::new(0));
    let worker_reads = reads.clone();
    driver.wrapper = Some(Box::new(move |job| {
        Box::new(move || {
            let mut first = true;
            crate::discovery::scan::maps_read_test::observe(
                move |bytes| {
                    if bytes > 0 {
                        worker_reads.fetch_add(1, Ordering::SeqCst);
                        if first {
                            first = false;
                            let bound = Instant::now() + Duration::from_secs(10);
                            while Instant::now() < deadline {
                                assert!(
                                    Instant::now() < bound,
                                    "the held read must see the deadline pass"
                                );
                                std::thread::yield_now();
                            }
                        }
                    }
                },
                job,
            )
        })
    }));
    let stop_requested = || false;
    let mut loop_clock = clock(&stop_requested);
    loop_clock.deadline = Some(deadline);
    let mut pass_publications = 0;
    let result = run_classic_finalizing::<PidPin, _, FacadeLane>(
        &mut driver,
        None,
        &loop_clock,
        None,
        &mut |_, point| {
            if matches!(point, Publish::Pass { .. }) {
                pass_publications += 1;
            }
            Ok(())
        },
    );
    assert!(result.error.is_none(), "{:?}", result.error);
    assert!(
        reads.load(Ordering::SeqCst) > 0,
        "actual scanner I/O reached the held read"
    );
    assert_eq!(
        control.check(),
        Err(CollectionStop::Deadline),
        "the deadline latched during the held collection"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "no next or recovery collection after the stop"
    );
    assert_eq!(pass_publications, 1, "pass 0 still publishes");
    assert!(
        result.zero_pass.is_none(),
        "a publishing pass is not a zero-pass run"
    );
    assert_eq!(
        driver.inner.coordinator.registry().caller_count(),
        1,
        "the scanned caller publishes instead of discarding to 0"
    );
    assert!(
        driver.inner.coordinator.registry().edges().next().is_some(),
        "the scanned caller's module edge publishes"
    );
}

/// Live twin of the kept pass: with a native lane the completed
/// pass-0 collection publishes its caller beside the
/// `stopped before attach` scope gap (counts never attached; no
/// attach starts after the stop), and the owned stop still drains.
#[test]
fn cgroup_short_timed_run_keeps_live_pass_with_attach_gap() {
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let (capture, _native_log) = crate::inventory_capture::tests::cgroup_runtime_lane();
    let lane = NativeLane::start(capture, &mut coordinator, LaneWindows::PROVISIONAL, None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let base = Instant::now();
    let deadline = base + Duration::from_millis(200);
    let control = CollectionControl::new(Some(deadline));
    let mut driver = ObservedDriver::new(&mut coordinator, control.clone());
    let reads = Arc::new(AtomicUsize::new(0));
    let worker_reads = reads.clone();
    driver.wrapper = Some(Box::new(move |job| {
        Box::new(move || {
            let mut first = true;
            crate::discovery::scan::maps_read_test::observe(
                move |bytes| {
                    if bytes > 0 {
                        worker_reads.fetch_add(1, Ordering::SeqCst);
                        if first {
                            first = false;
                            let bound = Instant::now() + Duration::from_secs(10);
                            while Instant::now() < deadline {
                                assert!(
                                    Instant::now() < bound,
                                    "the held read must see the deadline pass"
                                );
                                std::thread::yield_now();
                            }
                        }
                    }
                },
                job,
            )
        })
    }));
    let stop_requested = || false;
    let mut loop_clock = clock(&stop_requested);
    loop_clock.deadline = Some(deadline);
    let result = run_classic_finalizing(&mut driver, Some(lane), &loop_clock, None, &mut |_, _| {
        Ok(())
    });
    assert!(result.error.is_none(), "{:?}", result.error);
    assert!(
        reads.load(Ordering::SeqCst) > 0,
        "actual scanner I/O reached the held read"
    );
    assert_eq!(
        control.check(),
        Err(CollectionStop::Deadline),
        "the deadline latched during the held collection"
    );
    let stopped = result.stopped.as_ref().expect("the owned stop drains");
    assert_eq!(stopped.summary.passes, 1, "the kept pass is the run");
    assert!(
        result.zero_pass.is_none(),
        "a kept pass is not a zero-pass run"
    );
    assert_eq!(
        driver.inner.coordinator.registry().caller_count(),
        1,
        "the scanned caller publishes instead of discarding to 0"
    );
    assert!(
        driver.inner.coordinator.registry().edges().next().is_some(),
        "the scanned caller's module edge publishes"
    );
    let gaps = driver.inner.coordinator.registry().gaps();
    assert!(
        gaps.iter()
            .any(|gap| gap.subject == crate::inventory_capture::STOPPED_BEFORE_ATTACH_SUBJECT),
        "the live kept pass names stopped-before-attach: {:?}",
        gaps.iter().map(|gap| &gap.subject).collect::<Vec<_>>()
    );
}

/// Twin: a run whose deadline already passed before pass 0 starts
/// collected nothing, so it stays an honest empty: 0 callers with
/// the cancelled-before-launch gap and the zero-pass diagnostic.
#[test]
fn cgroup_preexpired_deadline_stays_honest_empty() {
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let deadline = Instant::now();
    let control = CollectionControl::new(Some(deadline));
    let mut driver = ObservedDriver::new(&mut coordinator, control.clone());
    let calls = driver.collections.clone();
    let stop_requested = || false;
    let mut loop_clock = clock(&stop_requested);
    loop_clock.deadline = Some(deadline);
    let mut pass_publications = 0;
    let result = run_classic_finalizing::<PidPin, _, FacadeLane>(
        &mut driver,
        None,
        &loop_clock,
        None,
        &mut |_, point| {
            if matches!(point, Publish::Pass { .. }) {
                pass_publications += 1;
            }
            Ok(())
        },
    );
    assert!(result.error.is_none(), "{:?}", result.error);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "no collection starts past the deadline"
    );
    assert_eq!(pass_publications, 0, "no pass publishes");
    assert_eq!(
        driver.inner.coordinator.registry().caller_count(),
        0,
        "nothing was seen, so 0 callers is honest"
    );
    let zero = result.zero_pass.expect("the honest empty stays zero-pass");
    assert_eq!(
        zero.cause,
        crate::inventory_capture::ZeroPassCause::Deadline
    );
    assert_eq!(zero.discarded, 0, "no collection ran to discard");
    let gaps = driver.inner.coordinator.registry().gaps();
    assert!(
        gaps.iter()
            .any(|gap| gap.subject == "cgroup collection cancelled before launch"),
        "the before-launch stop is named: {:?}",
        gaps.iter().map(|gap| &gap.subject).collect::<Vec<_>>()
    );
    assert!(
        gaps.iter()
            .any(|gap| gap.subject == crate::inventory_capture::ZERO_PASS_GAP_SUBJECT),
        "the zero-pass diagnostic is staged: {:?}",
        gaps.iter().map(|gap| &gap.subject).collect::<Vec<_>>()
    );
}

#[test]
fn cgroup_runtime_stopped_native_startup_finalizes_without_fabricating_pass() {
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let (capture, log) = crate::inventory_capture::tests::cgroup_runtime_lane();
    let lane = NativeLane::start(capture, &mut coordinator, LaneWindows::PROVISIONAL, None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let control = CollectionControl::new(None);
    let mut driver = ObservedDriver::new(&mut coordinator, control.clone());
    let mut pass_publications = 0;
    let mut stop_publications = 0;
    let result = run_classic_finalizing(
        &mut driver,
        Some(lane),
        &clock(&|| true),
        None,
        &mut |_, point| {
            match point {
                Publish::Pass { .. } => pass_publications += 1,
                Publish::Stop { events, .. } => {
                    stop_publications += 1;
                    assert!(
                        !events
                            .iter()
                            .any(|event| matches!(event, CallerEvent::Admitted { .. }))
                    );
                }
                Publish::Retiring { .. } => {}
            }
            Ok(())
        },
    );
    assert!(result.error.is_none(), "{:?}", result.error);
    assert_eq!(driver.collections.load(Ordering::SeqCst), 0);
    assert_eq!(driver.inner.coordinator.passes(), 0);
    assert_eq!(pass_publications, 0);
    assert_eq!(stop_publications, 1);
    assert_eq!(control.check(), Err(CollectionStop::OperatorStop));
    let stopped = result
        .stopped
        .as_ref()
        .expect("zero-pass active capture retires");
    assert_eq!(stopped.summary.passes, 0);
    assert!(matches!(
        stopped.summary.retirement,
        crate::inventory_capture::Retirement::Closed(_)
    ));
    let log = log.borrow();
    let begin_stop = log.iter().position(|entry| entry == "begin_stop").unwrap();
    assert!(log[..begin_stop].iter().any(|entry| entry == "read"));
    assert!(log[begin_stop + 1..].iter().any(|entry| entry == "read"));
}

#[test]
fn cgroup_runtime_wait_tick_after_draw_latches_operator_stop() {
    returning_read_gate(true);
}

#[test]
fn cgroup_runtime_returning_read_healthy_keeps_useful_snapshot() {
    returning_read_gate(false);
}

#[test]
fn cgroup_runtime_fast_result_stop_is_checked_before_apply_commit() {
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let stop = Arc::new(AtomicBool::new(false));
    let control = CollectionControl::new(None);
    let mut driver = ObservedDriver::new(&mut coordinator, control.clone());
    let worker_stop = stop.clone();
    driver.wrapper = Some(Box::new(move |job| {
        Box::new(move || {
            let collection = job();
            worker_stop.store(true, Ordering::SeqCst);
            collection
        })
    }));
    let result = run_classic_finalizing::<PidPin, _, FacadeLane>(
        &mut driver,
        None,
        &clock(&|| stop.load(Ordering::SeqCst)),
        None,
        &mut |_, _| Ok(()),
    );
    assert!(result.error.is_none());
    assert_eq!(driver.collections.load(Ordering::SeqCst), 1);
    assert_eq!(control.check(), Err(CollectionStop::OperatorStop));
    // Owner rule 2026-11-09: the stop landed after the collection
    // completed, so the completed collection still applies instead
    // of discarding into 0 callers (the cgroup twin of the kept
    // pass-0). The run control still latches, and no second
    // collection starts.
    assert_eq!(driver.inner.coordinator.registry().caller_count(), 1);
    assert!(
        !driver
            .inner
            .coordinator
            .take_target_delta()
            .endpoints
            .is_empty(),
        "the completed commit stages its delta; the stopped run takes nothing"
    );
}

/// Twin with a wide return window: the stop lands after the collection
/// completed but before the loop receives it, and several collection
/// ticks run in between. A tick must not reach back into the returned
/// worker's control and cancel the completed pass 0 (the race CI hit
/// under coverage), so the scanned caller still publishes.
#[test]
fn cgroup_runtime_stop_after_return_survives_collection_ticks() {
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let stop = Arc::new(AtomicBool::new(false));
    let control = CollectionControl::new(None);
    let mut driver = ObservedDriver::new(&mut coordinator, control.clone());
    let worker_stop = stop.clone();
    driver.wrapper = Some(Box::new(move |job| {
        Box::new(move || {
            let collection = job();
            worker_stop.store(true, Ordering::SeqCst);
            // The test clock ticks every millisecond: hold the result
            // long enough that ticks always run inside the window.
            std::thread::sleep(Duration::from_millis(30));
            collection
        })
    }));
    let window_ticks = Arc::new(AtomicUsize::new(0));
    let (tick_stop, tick_count) = (stop.clone(), Arc::clone(&window_ticks));
    driver.tick = Some(Box::new(move || {
        if tick_stop.load(Ordering::SeqCst) {
            tick_count.fetch_add(1, Ordering::SeqCst);
        }
    }));
    let result = run_classic_finalizing::<PidPin, _, FacadeLane>(
        &mut driver,
        None,
        &clock(&|| stop.load(Ordering::SeqCst)),
        None,
        &mut |_, _| Ok(()),
    );
    assert!(result.error.is_none());
    assert_eq!(driver.collections.load(Ordering::SeqCst), 1);
    assert!(
        window_ticks.load(Ordering::SeqCst) > 0,
        "collection ticks must run inside the return window"
    );
    assert_eq!(control.check(), Err(CollectionStop::OperatorStop));
    assert_kept_completed_pass0(&mut driver);
}

/// The completed pass-0 collection published: its caller is present, no
/// incomplete-transaction gap was recorded, and the stopped run never
/// took the staged delta.
fn assert_kept_completed_pass0(driver: &mut ObservedDriver<'_>) {
    assert_eq!(driver.inner.coordinator.registry().caller_count(), 1);
    assert!(
        !driver
            .inner
            .coordinator
            .registry()
            .gaps()
            .iter()
            .any(|gap| gap.subject == "cgroup scope transaction incomplete"),
        "a completed pass 0 records no incomplete-transaction gap"
    );
    assert!(
        !driver
            .inner
            .coordinator
            .take_target_delta()
            .endpoints
            .is_empty(),
        "the completed commit stages its delta; the stopped run takes nothing"
    );
}

/// Ctrl-C twin of the return window: the operator stop arrives through
/// the shared signal source (which reaches the forked worker control
/// directly, without any tick) after pass 0's collection returned. The
/// completed collection's outcome is frozen at return, so apply still
/// publishes the scanned caller and the run still ends on the stop.
#[test]
fn cgroup_runtime_operator_stop_after_return_keeps_completed_pass0() {
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let source = Arc::new(AtomicUsize::new(0));
    let control = CollectionControl::new(None).with_operator_stop_source(Arc::clone(&source));
    let mut driver = ObservedDriver::new(&mut coordinator, control.clone());
    let worker_source = Arc::clone(&source);
    driver.wrapper = Some(Box::new(move |job| {
        Box::new(move || {
            let collection = job();
            worker_source.store(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(30));
            collection
        })
    }));
    let window_ticks = Arc::new(AtomicUsize::new(0));
    let (tick_source, tick_count) = (Arc::clone(&source), Arc::clone(&window_ticks));
    driver.tick = Some(Box::new(move || {
        if tick_source.load(Ordering::SeqCst) != 0 {
            tick_count.fetch_add(1, Ordering::SeqCst);
        }
    }));
    let result = run_classic_finalizing::<PidPin, _, FacadeLane>(
        &mut driver,
        None,
        &clock(&|| source.load(Ordering::SeqCst) != 0),
        None,
        &mut |_, _| Ok(()),
    );
    assert!(result.error.is_none());
    assert_eq!(driver.collections.load(Ordering::SeqCst), 1);
    assert!(
        window_ticks.load(Ordering::SeqCst) > 0,
        "collection ticks must run inside the return window"
    );
    assert_eq!(control.check(), Err(CollectionStop::OperatorStop));
    assert_kept_completed_pass0(&mut driver);
}

/// Stop-boundary twin of the operator-stop-after-return scenario,
/// through the real collector, apply, commit, operator-stop source
/// and finalizing loop: the completed pass-0 collection still
/// publishes its caller, but the terminal finish must not start a
/// new seal — the eighth stable peek arrives after the operator
/// stop latched. Refusal verdicts stand in at the BPF-start
/// boundary, so no BPF is loaded either way.
#[test]
fn cgroup_runtime_operator_stop_drain_attempts_no_new_seal() {
    use crate::discovery::engine::inventory_coordinator::semantics::{
        AttestedSubset, SubsetPreparation,
    };
    use crate::discovery::identity::PinnedObjectId;
    use crate::inventory_semantics::SemanticRefusal;
    use std::collections::{BTreeMap, BTreeSet};
    fn scripted_preparation() -> SubsetPreparation {
        let slot = crate::plan::Slot {
            index: 0,
            descriptor_index: crate::kinds::function_id("C_SignInit").unwrap() + 1,
            object: PinnedObjectId(0),
            object_path: "/stub-provider.so".into(),
            file_offset: 0x1200,
            names: vec!["C_SignInit".into()],
            aliased: false,
            semantics: crate::kinds::descriptor("C_SignInit").unwrap(),
            semantic_authorized: true,
            semantic_ambiguous: false,
            fork_safe: true,
            module_ids: vec![crate::plan::ModuleId(0)],
        };
        SubsetPreparation {
            subset: Some(AttestedSubset::scripted(
                crate::plan::AttachPlan::from_slots(vec![slot]),
                crate::discovery::identity::PinnedObjects::empty(),
                BTreeMap::from([(PinnedObjectId(0), BTreeSet::from([0]))]),
            )),
            refusals: Vec::new(),
        }
    }
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let source = Arc::new(AtomicUsize::new(0));
    let control = CollectionControl::new(None).with_operator_stop_source(Arc::clone(&source));
    let mut driver = ObservedDriver::new(&mut coordinator, control.clone());
    // One more stable peek seats: the settle state is primed, the
    // start itself must never run past the stop.
    driver.inner.scan_seal_pending = true;
    let one: BTreeSet<PinnedObjectId> = BTreeSet::from([PinnedObjectId(0)]);
    driver.inner.scan_seal_last_sets = Some(one.clone());
    driver.inner.scan_seal_stable_runs = super::SCAN_SEAL_STABLE_PEEKS - 1;
    let worker_source = Arc::clone(&source);
    driver.wrapper = Some(Box::new(move |job| {
        Box::new(move || {
            let collection = job();
            worker_source.store(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(30));
            collection
        })
    }));
    let preparations = (0..8).map(|_| scripted_preparation()).collect::<Vec<_>>();
    let verdicts = (0..4)
        .map(|_| Err(SemanticRefusal::Unavailable))
        .collect::<Vec<_>>();
    let (result, start_scopes) =
        super::seal_startup_test::with_peek_queue(vec![Some(one)], preparations, verdicts, || {
            let result = run_classic_finalizing::<PidPin, _, FacadeLane>(
                &mut driver,
                None,
                &clock(&|| source.load(Ordering::SeqCst) != 0),
                None,
                &mut |_, _| Ok(()),
            );
            (result, super::seal_startup_test::take_start_scopes())
        });
    assert!(result.error.is_none());
    assert_eq!(driver.collections.load(Ordering::SeqCst), 1);
    assert_eq!(control.check(), Err(CollectionStop::OperatorStop));
    assert_kept_completed_pass0(&mut driver);
    assert!(
        driver.inner.semantic.is_none(),
        "the stop drain seats no lane"
    );
    assert!(
        start_scopes.is_empty(),
        "the stop drain attempts no new seal: {start_scopes:?}"
    );
}

#[test]
fn cgroup_runtime_spawn_failure_never_runs_collection_inline() {
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let executed = Arc::new(AtomicUsize::new(0));
    let mut driver = ObservedDriver::new(&mut coordinator, CollectionControl::new(None));
    let worker_executed = executed.clone();
    driver.wrapper = Some(Box::new(move |job| {
        Box::new(move || {
            worker_executed.fetch_add(1, Ordering::SeqCst);
            job()
        })
    }));
    let result = worker_spawn_test::fail_next(|| {
        run_classic_finalizing::<PidPin, _, FacadeLane>(
            &mut driver,
            None,
            &clock(&|| false),
            None,
            &mut |_, _| Ok(()),
        )
    });
    assert_eq!(
        executed.load(Ordering::SeqCst),
        0,
        "a failed scoped worker never executes inline"
    );
    assert!(
        result
            .error
            .is_some_and(|error| error.to_string() == CgroupJobFailure::Spawn.reason())
    );
    assert_eq!(driver.inner.coordinator.registry().caller_count(), 0);
    assert!(
        driver
            .inner
            .coordinator
            .registry()
            .gaps()
            .iter()
            .any(|gap| gap.reason == CgroupJobFailure::Spawn.reason())
    );
}

#[test]
fn cgroup_runtime_no_duration_consumes_delayed_events_and_continuation_once() {
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let mut driver = ObservedDriver::new(&mut coordinator, CollectionControl::new(None));
    let mut published = Vec::new();
    let result = run_classic_finalizing::<PidPin, _, FacadeLane>(
        &mut driver,
        None,
        &clock(&|| false),
        None,
        &mut |driver, publication| {
            if let Publish::Pass { report, .. } = publication {
                assert!(driver.inner.coordinator.registry().edges().next().is_some());
                published.push((
                    report.scan_callers,
                    report
                        .events
                        .iter()
                        .filter(|event| matches!(event, CallerEvent::Admitted { .. }))
                        .count(),
                ));
            }
            Ok(())
        },
    );
    assert!(result.error.is_none());
    assert_eq!(
        driver.collections.load(Ordering::SeqCst),
        1,
        "None deadline means one useful snapshot"
    );
    assert_eq!(
        published,
        vec![(1, 1)],
        "report uses validated callers and delayed admission events"
    );
    assert!(driver.inner.cgroup.as_ref().unwrap().continuation.is_some());
    assert!(
        driver.inner.coordinator.take_cgroup_completion().is_none(),
        "original completion was consumed exactly once"
    );
}

/// Compile C sources with gcc into the test tmp dir.
fn gcc_fixture(
    dir: &std::path::Path,
    out: &str,
    sources: &[&std::path::Path],
    args: &[&str],
    libs: &[&str],
) -> PathBuf {
    let bin = dir.join(out);
    let mut cmd = std::process::Command::new("gcc");
    cmd.args(args).arg("-o").arg(&bin).args(sources).args(libs);
    assert!(
        cmd.status().unwrap().success(),
        "gcc failed for {out}: {cmd:?}"
    );
    bin
}

/// A cgroup scene whose single provider carries `bytes` of
/// file-backed data plus one hook export: past any single 1M-unit
/// pass allowance, so a snapshot must resume across passes to find
/// it. Mirrors the small provider scene with a haskoki-class object.
fn big_data_cgroup_scene(
    bytes: usize,
) -> (
    tempfile::TempDir,
    crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild,
    InventoryCoordinator<OsProcessSource>,
) {
    use crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild;
    let dir = tempfile::tempdir().unwrap();
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = dir.path().join("big-data.c");
    std::fs::write(
        &source,
        format!(
            "/* {bytes} bytes of file-backed data. */\n\
             __attribute__((used)) static const unsigned char fixture_blob[{bytes}] = {{1}};\n"
        ),
    )
    .unwrap();
    // The blob rides with a real hook implementation, so the driver's
    // `--call` surface succeeds exactly as on the small provider.
    let matrix = manifest.join("crates/discover/tests/fixture/version_matrix.c");
    let provider = gcc_fixture(
        dir.path(),
        "big-data.so",
        &[source.as_path(), matrix.as_path()],
        &["-shared", "-fPIC", "-DLEGACY_MINOR=40"],
        &[],
    );
    gcc_fixture(
        dir.path(),
        "scoped-driver",
        &[manifest.join("tests/fixtures/catalog-driver.c").as_path()],
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    let ready = dir.path().join("ready");
    let child = OwnedStoppedChild::spawn_stopped(
        std::process::Command::new(dir.path().join("scoped-driver"))
            .arg("--ready")
            .arg(&ready)
            .arg("--call")
            .arg(&provider)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
        |pid| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !ready.exists() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "owned provider child did not finish startup"
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            // SAFETY: pid names the child retained by spawn_stopped.
            assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) }, 0);
        },
    );
    std::fs::write(dir.path().join("cgroup.procs"), format!("{}\n", child.id())).unwrap();
    let mut coordinator = InventoryCoordinator::new(
        crate::scope::cgroup(dir.path()).unwrap(),
        HookRegistry::builtin(),
        vec![provider],
        vec![],
        OsProcessSource,
        crate::discovery::caller_registry::RegistryLimits::default_limits(),
    )
    .unwrap();
    coordinator.begin_capture_coverage(crate::attach::capture::CaptureScopeCoverage::Cgroup);
    (dir, child, coordinator)
}

/// A snapshot (no deadline) over a haskoki-class member runs follow-up
/// passes while decode progress is unfinished, then converges: the
/// provider is found, no stale exhaustion verdict survives, and the
/// terminal shows no in-progress gap. This pins resume, not fit: a
/// single-pass snapshot fails the collection count.
#[test]
fn cgroup_runtime_snapshot_resumes_across_passes_until_converged() {
    const BIG_DATA_BYTES: usize = 12 << 20;
    const PASS_CAP: usize = 10;
    let (_fixture, _child, mut coordinator) = big_data_cgroup_scene(BIG_DATA_BYTES);
    let mut driver = ObservedDriver::new(&mut coordinator, CollectionControl::new(None));
    let mut publications = 0;
    let result = run_classic_finalizing::<PidPin, _, FacadeLane>(
        &mut driver,
        None,
        &clock(&|| false),
        None,
        &mut |_, publication| {
            if matches!(publication, Publish::Pass { .. }) {
                publications += 1;
            }
            Ok(())
        },
    );
    assert!(result.error.is_none(), "{:?}", result.error);
    let collections = driver.collections.load(Ordering::SeqCst);
    assert!(
        collections >= 2,
        "a haskoki-class member cannot fit one 1M pass: {collections} collection ran"
    );
    assert!(
        collections <= PASS_CAP,
        "the resumed snapshot must terminate: {collections} collections ran"
    );
    assert_eq!(
        publications, collections,
        "every resumed pass publishes: {publications} of {collections}"
    );
    assert!(
        driver.inner.coordinator.registry().edges().next().is_some(),
        "the resumed snapshot must find the provider"
    );
    assert!(
        !driver
            .inner
            .coordinator
            .registry()
            .gaps()
            .iter()
            .any(|gap| gap.subject == "cgroup scope transaction incomplete"
                && gap.reason.contains("shared work allowance exhausted")),
        "no stale exhaustion verdict survives the converged snapshot: {:?}",
        driver.inner.coordinator.registry().gaps()
    );
    assert!(
        !driver
            .inner
            .coordinator
            .registry()
            .gaps()
            .iter()
            .any(|gap| gap.subject == "scan_in_progress"),
        "no stale in-progress row survives in terminal history: {:?}",
        driver.inner.coordinator.registry().gaps()
    );
    assert!(
        driver.inner.coordinator.live_scan_progress_gap().is_none(),
        "the converged snapshot shows no in-progress gap"
    );
}

/// One posed cursor key for the snapshot resume rule: identity only.
fn resume_key(
    pid: u32,
    start_time: u64,
    inode: u64,
) -> crate::discovery::scan_pass::DecodeCursorKey {
    let file = std::fs::File::open("/bin/sh").unwrap();
    crate::discovery::scan_pass::DecodeCursorKey {
        pid,
        start_time,
        file: crate::discovery::scan::InspectedFileKey {
            device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
            inode,
            pin: crate::discovery::identity::pin_of(&file).unwrap(),
            fd_dev: 7,
        },
        exec: None,
    }
}

/// One posed committed progress: layout hash plus frontiers, decoded
/// count and completion.
fn resume_progress(
    layout: u64,
    tables: (usize, u64),
    interfaces: (usize, u64),
    tables_decoded: usize,
    complete: bool,
) -> crate::discovery::scan_pass::CommittedCursorProgress {
    crate::discovery::scan_pass::CommittedCursorProgress {
        layout,
        tables: crate::discovery::scan_pass::SweepFrontier {
            snapshot: tables.0,
            word: tables.1,
        },
        interfaces: crate::discovery::scan_pass::SweepFrontier {
            snapshot: interfaces.0,
            word: interfaces.1,
        },
        tables_decoded,
        complete,
    }
}

/// One posed resume position, mirroring production: every carried
/// cursor, completed ones included.
type PosedResumePosition = std::collections::BTreeMap<
    crate::discovery::scan_pass::DecodeCursorKey,
    crate::discovery::scan_pass::CommittedCursorProgress,
>;

/// Pose one resume position from cursor entries.
fn resume_position(
    entries: Vec<(
        crate::discovery::scan_pass::DecodeCursorKey,
        crate::discovery::scan_pass::CommittedCursorProgress,
    )>,
) -> PosedResumePosition {
    entries.into_iter().collect()
}

/// Pose one decision on a driver: a fresh ledger whose whole decided
/// history is `prev`, then the real observation of `last`, so
/// single-step poses read like an adjacent rule while the decision
/// runs the real ledger. The spent settle grant carries over.
fn pose_resume(
    driver: &mut ClassicDriver<'_>,
    last: PosedResumePosition,
    prev: PosedResumePosition,
) {
    let cgroup = driver.cgroup.as_mut().unwrap();
    let settle_granted = cgroup.resume.settle_granted;
    cgroup.resume = SnapshotResumeLedger {
        settle_granted,
        ..SnapshotResumeLedger::default()
    };
    cgroup.resume.observe(&prev);
    cgroup.resume.observe(&last);
}

/// Observe one pass position exactly like `finish_pass`, then decide:
/// the multi-pass twins drive sequences through this so every
/// decision reads the real retained history.
fn pass_resume(driver: &mut ClassicDriver<'_>, last: PosedResumePosition) -> bool {
    driver.cgroup.as_mut().unwrap().resume.observe(&last);
    driver.snapshot_resume_pending()
}

/// The snapshot settle grant is single-use across churn: a convergence
/// after unfinished work grants the one settle pass; unfinished work
/// that returns afterwards resumes once more through the
/// first-unfinished rule; the next convergence ends the snapshot
/// instead of settling again.
#[test]
fn cgroup_snapshot_settle_grant_is_single_use_across_churn() {
    use crate::inspect_system::inventory_cgroup::{ScopedCollectionGap, ScopedCollectionOutcome};
    use crate::scope::inventory_cgroup::CgroupIncomplete;
    let work_limit = ScopedCollectionOutcome::Incomplete(ScopedCollectionGap::Membership(
        CgroupIncomplete::WorkLimit,
    ));
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let mut driver = ObservedDriver::new(&mut coordinator, CollectionControl::new(None));
    driver.inner.cgroup.as_mut().unwrap().last_outcome = Some(work_limit);
    let some = || {
        resume_position(vec![(
            resume_key(7, 9, 11),
            resume_progress(100, (0, 360), (0, 0), 4, false),
        )])
    };
    let none = || resume_position(vec![]);
    pose_resume(&mut driver.inner, none(), some());
    assert!(
        driver.inner.snapshot_resume_pending(),
        "the first convergence grants the settle pass"
    );
    pose_resume(&mut driver.inner, some(), none());
    assert!(
        driver.inner.snapshot_resume_pending(),
        "returned unfinished work resumes once more"
    );
    pose_resume(&mut driver.inner, none(), some());
    assert!(
        !driver.inner.snapshot_resume_pending(),
        "the spent grant denies a second settle"
    );
}

/// The snapshot resume rule, posed state by state: only a work stop
/// resumes; unfinished same-cursor progress continues the scan
/// (completion, decoded tables or lexicographic sweep frontiers under
/// the same layout — never churn: new, removed or relaid-out cursors,
/// and never a cycle through disjoint positions); a converged scan
/// with no bind budget gets exactly one settle pass; duration runs,
/// stops and every other outcome keep the single snapshot.
#[test]
fn cgroup_snapshot_resume_rule_answers_posed_states() {
    use crate::inspect_system::inventory_cgroup::{ScopedCollectionGap, ScopedCollectionOutcome};
    use crate::scope::inventory_cgroup::CgroupIncomplete;
    let work_limit = || {
        ScopedCollectionOutcome::Incomplete(ScopedCollectionGap::Membership(
            CgroupIncomplete::WorkLimit,
        ))
    };
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let mut driver = ObservedDriver::new(&mut coordinator, CollectionControl::new(None));
    driver.inner.cgroup.as_mut().unwrap().last_outcome = Some(work_limit());
    let k1 = resume_key(7, 9, 11);
    let k2 = resume_key(7, 9, 12);
    let base = resume_progress(100, (0, 360), (0, 0), 4, false);
    // Nothing unfinished never resumes.
    pose_resume(
        &mut driver.inner,
        resume_position(vec![]),
        resume_position(vec![]),
    );
    assert!(!driver.inner.snapshot_resume_pending());
    // The first unfinished pass always resumes.
    pose_resume(
        &mut driver.inner,
        resume_position(vec![(k1.clone(), base)]),
        resume_position(vec![]),
    );
    assert!(driver.inner.snapshot_resume_pending());
    // Each same-cursor advance resumes on its own: decoded tables,
    // table snapshots, table words, interface words.
    let prev = resume_position(vec![(k1.clone(), base)]);
    for (progress, what) in [
        (
            resume_progress(100, (0, 360), (0, 0), 5, false),
            "decoded tables",
        ),
        (
            resume_progress(100, (1, 360), (0, 0), 4, false),
            "table snapshots",
        ),
        (
            resume_progress(100, (0, 361), (0, 0), 4, false),
            "table words",
        ),
        (
            resume_progress(100, (0, 360), (0, 1), 4, false),
            "interface words",
        ),
    ] {
        pose_resume(
            &mut driver.inner,
            resume_position(vec![(k1.clone(), progress)]),
            prev.clone(),
        );
        assert!(driver.inner.snapshot_resume_pending(), "{what} must resume");
    }
    // Completion resumes while other work stays unfinished.
    pose_resume(
        &mut driver.inner,
        resume_position(vec![
            (k1.clone(), resume_progress(100, (0, 360), (0, 0), 4, true)),
            (k2.clone(), base),
        ]),
        resume_position(vec![(k1.clone(), base), (k2.clone(), base)]),
    );
    assert!(driver.inner.snapshot_resume_pending());
    // An unchanged position stalls: a full fresh allowance moved
    // nothing, so the snapshot ends honestly.
    pose_resume(
        &mut driver.inner,
        resume_position(vec![(k1.clone(), base)]),
        resume_position(vec![(k1.clone(), base)]),
    );
    assert!(!driver.inner.snapshot_resume_pending());
    // Churn never resumes: new cursors ...
    pose_resume(
        &mut driver.inner,
        resume_position(vec![(k1.clone(), base), (k2.clone(), base)]),
        resume_position(vec![(k1.clone(), base)]),
    );
    assert!(
        !driver.inner.snapshot_resume_pending(),
        "new cursors are churn, not progress"
    );
    // ... removed cursors ...
    pose_resume(
        &mut driver.inner,
        resume_position(vec![(k1.clone(), base)]),
        resume_position(vec![(k1.clone(), base), (k2.clone(), base)]),
    );
    assert!(
        !driver.inner.snapshot_resume_pending(),
        "removed cursors are churn, not progress"
    );
    // ... relaid-out cursors, even at further frontiers ...
    pose_resume(
        &mut driver.inner,
        resume_position(vec![(
            k1.clone(),
            resume_progress(200, (9, 999), (9, 999), 99, false),
        )]),
        resume_position(vec![(k1.clone(), base)]),
    );
    assert!(
        !driver.inner.snapshot_resume_pending(),
        "a relaid-out cursor never resumes"
    );
    // ... and disjoint bounded positions never cycle either way.
    let a = resume_position(vec![(
        k1.clone(),
        resume_progress(100, (0, 900), (0, 0), 1, false),
    )]);
    let b = resume_position(vec![(
        k2.clone(),
        resume_progress(100, (0, 950), (0, 0), 1, false),
    )]);
    pose_resume(&mut driver.inner, b.clone(), a.clone());
    assert!(
        !driver.inner.snapshot_resume_pending(),
        "disjoint positions must not cycle"
    );
    pose_resume(&mut driver.inner, a, b);
    assert!(
        !driver.inner.snapshot_resume_pending(),
        "disjoint positions must not cycle back"
    );
    // A regressed frontier (a fresh restart behind the old frontier)
    // never resumes either.
    pose_resume(
        &mut driver.inner,
        resume_position(vec![(
            k1.clone(),
            resume_progress(100, (0, 359), (0, 0), 4, false),
        )]),
        resume_position(vec![(k1.clone(), base)]),
    );
    assert!(!driver.inner.snapshot_resume_pending());
    // A converged scan with no bind budget gets one settle pass.
    pose_resume(
        &mut driver.inner,
        resume_position(vec![]),
        resume_position(vec![(k1.clone(), base)]),
    );
    assert!(driver.inner.snapshot_resume_pending());
    // Two consecutive no-progress passes end the snapshot: the grant
    // is spent.
    pose_resume(
        &mut driver.inner,
        resume_position(vec![]),
        resume_position(vec![]),
    );
    assert!(!driver.inner.snapshot_resume_pending());
    // A scan that fits pass zero with no bind budget left still
    // settles once (no previous position to compare against).
    driver.inner.cgroup.as_mut().unwrap().resume.settle_granted = false;
    let cgroup = driver.inner.cgroup.as_ref().unwrap();
    assert!(cgroup.resume.settle_pending(1));
    assert!(!cgroup.resume.settle_pending(2));
    // Only a work stop resumes: a complete transaction and any
    // other incomplete outcome keep the single snapshot, even
    // with unfinished progress posed.
    pose_resume(
        &mut driver.inner,
        resume_position(vec![(
            k1.clone(),
            resume_progress(100, (0, 361), (0, 0), 4, false),
        )]),
        resume_position(vec![(k1.clone(), base)]),
    );
    driver.inner.cgroup.as_mut().unwrap().last_outcome = Some(ScopedCollectionOutcome::Complete);
    assert!(!driver.inner.snapshot_resume_pending());
    driver.inner.cgroup.as_mut().unwrap().last_outcome = Some(ScopedCollectionOutcome::Incomplete(
        ScopedCollectionGap::ScanIncomplete,
    ));
    assert!(!driver.inner.snapshot_resume_pending());
    // Duration runs, stops and a latched control never resume.
    driver.inner.cgroup.as_mut().unwrap().last_outcome = Some(work_limit());
    assert!(driver.inner.snapshot_resume_pending());
    driver.inner.deadline = Some(std::time::Instant::now() + std::time::Duration::from_secs(60));
    assert!(!driver.inner.snapshot_resume_pending());
    driver.inner.deadline = None;
    driver.inner.stop_requested = true;
    assert!(!driver.inner.snapshot_resume_pending());
    driver.inner.stop_requested = false;
    assert!(driver.inner.snapshot_resume_pending());
    driver.inner.cgroup.as_ref().unwrap().control.cancel();
    assert!(!driver.inner.snapshot_resume_pending());
}

/// Overlapping same-key cursor cycles stall: two cursors alternating
/// table frontiers (900,950) and (950,900) grant while ground is
/// uncovered, then stall in both directions once the high-water covers
/// every frontier. An adjacent comparison grants all 32 transitions.
#[test]
fn cgroup_snapshot_resume_refuses_overlapping_cursor_cycles() {
    use crate::inspect_system::inventory_cgroup::{ScopedCollectionGap, ScopedCollectionOutcome};
    use crate::scope::inventory_cgroup::CgroupIncomplete;
    let work_limit = ScopedCollectionOutcome::Incomplete(ScopedCollectionGap::Membership(
        CgroupIncomplete::WorkLimit,
    ));
    for swapped in [false, true] {
        let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
        let mut driver = ObservedDriver::new(&mut coordinator, CollectionControl::new(None));
        driver.inner.cgroup.as_mut().unwrap().last_outcome = Some(work_limit);
        let k1 = resume_key(7, 9, 11);
        let k2 = resume_key(7, 9, 12);
        let at = |w1: u64, w2: u64| {
            let (w1, w2) = if swapped { (w2, w1) } else { (w1, w2) };
            resume_position(vec![
                (k1.clone(), resume_progress(100, (0, w1), (0, 0), 4, false)),
                (k2.clone(), resume_progress(100, (0, w2), (0, 0), 4, false)),
            ])
        };
        let s1 = at(900, 950);
        let s2 = at(950, 900);
        assert!(
            pass_resume(&mut driver.inner, s1.clone()),
            "swapped={swapped}: the first unfinished pass resumes"
        );
        assert!(
            pass_resume(&mut driver.inner, s2.clone()),
            "swapped={swapped}: the first uncovered advance grants once"
        );
        for round in 0..16 {
            assert!(
                !pass_resume(&mut driver.inner, s1.clone()),
                "swapped={swapped} round {round}: covered ground stalls"
            );
            assert!(
                !pass_resume(&mut driver.inner, s2.clone()),
                "swapped={swapped} round {round}: the cycle never re-admits"
            );
        }
    }
}

/// The high-water survives temporary disappearance: a cursor that
/// leaves for a pass and returns to covered ground stalls, while a
/// return past the retained high-water resumes.
#[test]
fn cgroup_snapshot_resume_retains_high_water_across_disappearance() {
    use crate::inspect_system::inventory_cgroup::{ScopedCollectionGap, ScopedCollectionOutcome};
    use crate::scope::inventory_cgroup::CgroupIncomplete;
    let work_limit = ScopedCollectionOutcome::Incomplete(ScopedCollectionGap::Membership(
        CgroupIncomplete::WorkLimit,
    ));
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let mut driver = ObservedDriver::new(&mut coordinator, CollectionControl::new(None));
    driver.inner.cgroup.as_mut().unwrap().last_outcome = Some(work_limit);
    let k1 = resume_key(7, 9, 11);
    let k2 = resume_key(7, 9, 12);
    let at = |w1: Option<u64>, w2: u64| {
        let mut entries = Vec::new();
        if let Some(w1) = w1 {
            entries.push((k1.clone(), resume_progress(100, (0, w1), (0, 0), 4, false)));
        }
        entries.push((k2.clone(), resume_progress(100, (0, w2), (0, 0), 4, false)));
        resume_position(entries)
    };
    assert!(pass_resume(&mut driver.inner, at(Some(900), 500)));
    assert!(
        pass_resume(&mut driver.inner, at(None, 600)),
        "the remaining cursor still advances while its sibling is gone"
    );
    assert!(
        !pass_resume(&mut driver.inner, at(Some(900), 600)),
        "a return to covered ground stalls even after a disappearance"
    );
    assert!(
        pass_resume(&mut driver.inner, at(Some(950), 600)),
        "a return past the retained high-water resumes"
    );
}

/// Healthy multi-pass convergence still resumes: same identities,
/// same layouts, advancing sweep frontiers, decoded tables and
/// completion grant pass after pass until the scan converges; the
/// converged scan settles exactly once and then ends.
#[test]
fn cgroup_snapshot_resume_converges_across_healthy_multi_pass_advance() {
    use crate::inspect_system::inventory_cgroup::{ScopedCollectionGap, ScopedCollectionOutcome};
    use crate::scope::inventory_cgroup::CgroupIncomplete;
    let work_limit = ScopedCollectionOutcome::Incomplete(ScopedCollectionGap::Membership(
        CgroupIncomplete::WorkLimit,
    ));
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let mut driver = ObservedDriver::new(&mut coordinator, CollectionControl::new(None));
    driver.inner.cgroup.as_mut().unwrap().last_outcome = Some(work_limit);
    let k1 = resume_key(7, 9, 11);
    let k2 = resume_key(7, 9, 12);
    assert!(pass_resume(
        &mut driver.inner,
        resume_position(vec![
            (k1.clone(), resume_progress(100, (0, 100), (0, 0), 0, false)),
            (k2.clone(), resume_progress(100, (0, 100), (0, 0), 0, false)),
        ]),
    ));
    assert!(
        pass_resume(
            &mut driver.inner,
            resume_position(vec![
                (k1.clone(), resume_progress(100, (0, 200), (0, 0), 1, false)),
                (k2.clone(), resume_progress(100, (0, 100), (0, 0), 0, false)),
            ]),
        ),
        "a further table frontier with a new decoded table resumes"
    );
    assert!(
        pass_resume(
            &mut driver.inner,
            resume_position(vec![
                (
                    k1.clone(),
                    resume_progress(100, (0, 200), (0, 50), 1, false),
                ),
                (k2.clone(), resume_progress(100, (1, 0), (0, 0), 0, false)),
            ]),
        ),
        "interface and snapshot advances resume"
    );
    assert!(
        pass_resume(
            &mut driver.inner,
            resume_position(vec![
                (k1.clone(), resume_progress(100, (0, 200), (0, 50), 1, true)),
                (k2.clone(), resume_progress(100, (1, 0), (0, 0), 0, false)),
            ]),
        ),
        "completion resumes"
    );
    assert!(
        pass_resume(
            &mut driver.inner,
            resume_position(vec![(
                k2.clone(),
                resume_progress(100, (9, 999), (9, 999), 9, false)
            )]),
        ),
        "a lone remaining cursor resumes on its own advance"
    );
    assert!(
        pass_resume(&mut driver.inner, resume_position(vec![])),
        "the converged scan gets its one settle pass"
    );
    assert!(
        !pass_resume(&mut driver.inner, resume_position(vec![])),
        "the spent settle grant ends the snapshot"
    );
}

/// Recurring layouts under fixed keys stall: two cursors whose layouts
/// change and later recur (bounds, offsets or permissions remapped
/// under the same generation, pin and image) keep the covered ground of
/// every layout they visited. The first circuit grants while each
/// (identity, layout) pair still has uncovered ground; every later
/// circuit revisits covered frontiers only and stalls in both
/// directions, so one cursor's restart never pays for another's.
#[test]
fn cgroup_snapshot_resume_refuses_recurring_layout_cycles() {
    use crate::inspect_system::inventory_cgroup::{ScopedCollectionGap, ScopedCollectionOutcome};
    use crate::scope::inventory_cgroup::CgroupIncomplete;
    let work_limit = ScopedCollectionOutcome::Incomplete(ScopedCollectionGap::Membership(
        CgroupIncomplete::WorkLimit,
    ));
    for swapped in [false, true] {
        let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
        let mut driver = ObservedDriver::new(&mut coordinator, CollectionControl::new(None));
        driver.inner.cgroup.as_mut().unwrap().last_outcome = Some(work_limit);
        let k1 = resume_key(7, 9, 11);
        let k2 = resume_key(7, 9, 12);
        let at = |a: (u64, u64), b: (u64, u64)| {
            let (a, b) = if swapped { (b, a) } else { (a, b) };
            resume_position(vec![
                (k1.clone(), resume_progress(a.0, (0, a.1), (0, 0), 4, false)),
                (k2.clone(), resume_progress(b.0, (0, b.1), (0, 0), 4, false)),
            ])
        };
        let circuit = [
            at((100, 900), (100, 950)),
            at((100, 950), (200, 900)),
            at((200, 900), (200, 950)),
            at((200, 950), (100, 900)),
        ];
        let first: Vec<bool> = circuit
            .iter()
            .map(|position| pass_resume(&mut driver.inner, position.clone()))
            .collect();
        assert_eq!(
            first,
            [true, true, true, true],
            "swapped={swapped}: the first circuit grants uncovered ground only"
        );
        for round in 0..8 {
            for (step, position) in circuit.iter().enumerate() {
                assert!(
                    !pass_resume(&mut driver.inner, position.clone()),
                    "swapped={swapped} round {round} step {step}: a recurring layout \
                     revisits covered ground and must stall"
                );
            }
        }
    }
}

/// Completed-only history never starves live work: completed objects
/// that arrive complete under fresh layouts (they never needed a
/// continuation) fill the history for 64 passes while one cursor
/// advances; a newcomer then joins with only 130 cursors carried and
/// advances under a stable layout and identity, so its rise must earn
/// the next pass. The all-complete control fills the history in one
/// converged pass (its settle), then a newcomer resumes through the
/// initial grant and its strict rise still resumes.
#[test]
fn cgroup_snapshot_resume_admits_advancing_work_past_completed_history() {
    use crate::inspect_system::inventory_cgroup::{ScopedCollectionGap, ScopedCollectionOutcome};
    use crate::scope::inventory_cgroup::CgroupIncomplete;
    let work_limit = ScopedCollectionOutcome::Incomplete(ScopedCollectionGap::Membership(
        CgroupIncomplete::WorkLimit,
    ));
    // Layout churn of completed-only objects over 64 passes.
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let mut driver = ObservedDriver::new(&mut coordinator, CollectionControl::new(None));
    driver.inner.cgroup.as_mut().unwrap().last_outcome = Some(work_limit);
    let fixed = resume_key(7, 9, 11);
    let newcomer = resume_key(7, 9, 12);
    let completed: Vec<_> = (0..128u64).map(|index| resume_key(8, 9, 1000 + index)).collect();
    let mut last_completed = Vec::new();
    for round in 0..64u64 {
        let mut entries = vec![(
            fixed.clone(),
            resume_progress(100, (0, 100 + round), (0, 0), 4, false),
        )];
        last_completed = completed
            .iter()
            .map(|key| (key.clone(), resume_progress(5000 + round, (2, 0), (2, 0), 1, true)))
            .collect();
        entries.extend(last_completed.iter().cloned());
        assert!(
            pass_resume(&mut driver.inner, resume_position(entries)),
            "round {round}: the fixed cursor's advance resumes"
        );
    }
    let with = |word: u64| {
        let mut entries = vec![
            (
                fixed.clone(),
                resume_progress(100, (0, 163), (0, 0), 4, false),
            ),
            (
                newcomer.clone(),
                resume_progress(100, (0, word), (0, 0), 4, false),
            ),
        ];
        entries.extend(last_completed.iter().cloned());
        resume_position(entries)
    };
    assert!(
        !pass_resume(&mut driver.inner, with(900)),
        "the newcomer's arrival is not an advance"
    );
    assert!(
        pass_resume(&mut driver.inner, with(950)),
        "the newcomer's strict rise earns the next pass despite the full history"
    );
    // All-complete control: one converged pass fills the history.
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let mut driver = ObservedDriver::new(&mut coordinator, CollectionControl::new(None));
    driver.inner.cgroup.as_mut().unwrap().last_outcome = Some(work_limit);
    let full: Vec<_> = (0..crate::discovery::scan_pass::MAX_DECODE_CURSORS as u64)
        .map(|index| {
            (
                resume_key(9, 9, 100_000 + index),
                resume_progress(100, (2, 0), (2, 0), 1, true),
            )
        })
        .collect();
    let _ = pass_resume(&mut driver.inner, resume_position(full));
    let fresh = |word: u64| {
        resume_position(vec![(
            newcomer.clone(),
            resume_progress(100, (0, word), (0, 0), 4, false),
        )])
    };
    assert!(
        pass_resume(&mut driver.inner, fresh(900)),
        "the first unfinished pass resumes"
    );
    assert!(
        pass_resume(&mut driver.inner, fresh(950)),
        "the newcomer's strict rise resumes after the all-complete history"
    );
}

/// A completed sweep stays covered across the settle pass: a cursor
/// that completes (granting the one settle pass) and then restarts
/// under the same identity and layout — a re-proof invalidation —
/// re-scans ground an earlier pass already finished, so neither the
/// restart nor its later frontiers grant another pass.
#[test]
fn cgroup_snapshot_resume_keeps_completed_sweeps_covered_across_settle() {
    use crate::inspect_system::inventory_cgroup::{ScopedCollectionGap, ScopedCollectionOutcome};
    use crate::scope::inventory_cgroup::CgroupIncomplete;
    let work_limit = ScopedCollectionOutcome::Incomplete(ScopedCollectionGap::Membership(
        CgroupIncomplete::WorkLimit,
    ));
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let mut driver = ObservedDriver::new(&mut coordinator, CollectionControl::new(None));
    driver.inner.cgroup.as_mut().unwrap().last_outcome = Some(work_limit);
    let k1 = resume_key(7, 9, 11);
    assert!(
        pass_resume(
            &mut driver.inner,
            resume_position(vec![(
                k1.clone(),
                resume_progress(100, (0, 900), (0, 0), 4, false)
            )]),
        ),
        "the first unfinished pass resumes"
    );
    assert!(
        pass_resume(
            &mut driver.inner,
            resume_position(vec![(
                k1.clone(),
                resume_progress(100, (0, 900), (0, 0), 4, true)
            )]),
        ),
        "the completed scan gets its one settle pass"
    );
    for word in [950, 960, 5000] {
        assert!(
            !pass_resume(
                &mut driver.inner,
                resume_position(vec![(
                    k1.clone(),
                    resume_progress(100, (0, word), (0, 0), 4, false)
                )]),
            ),
            "a restart over a completed sweep (word {word}) must not grant"
        );
    }
}

#[test]
fn cgroup_runtime_published_targets_extend_after_scoped_commit_then_receipt_commit() {
    let (_fixture, _child, mut coordinator) = cgroup_provider_scene();
    let (capture, log) = crate::inventory_capture::tests::cgroup_runtime_lane();
    let lane = NativeLane::start(capture, &mut coordinator, LaneWindows::PROVISIONAL, None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let mut driver = ObservedDriver::new(&mut coordinator, CollectionControl::new(None));
    driver.log = log.clone();
    let mut published = 0;
    let result = run_classic_finalizing(
        &mut driver,
        Some(lane),
        &clock(&|| false),
        None,
        &mut |driver, publication| {
            if let Publish::Pass { .. } = publication {
                log.borrow_mut().push("publish".into());
                assert!(driver.inner.coordinator.registry().edges().next().is_some());
                published += 1;
            }
            Ok(())
        },
    );
    assert!(result.error.is_none(), "{:?}", result.error);
    assert_eq!(published, 1);
    let entries = log.borrow();
    let extend = entries
        .iter()
        .position(|entry| entry.starts_with("extend[") && entry != "extend[]")
        .expect("a real nonempty scoped provider delta must reach native extend");
    let first_commit = entries.iter().position(|entry| entry == "commit").unwrap();
    let completion = entries
        .iter()
        .position(|entry| entry == "completion")
        .unwrap();
    let publication = entries.iter().position(|entry| entry == "publish").unwrap();
    assert!(
        first_commit < completion && completion < extend && extend < publication,
        "{entries:?}"
    );
    assert!(
        entries[extend + 1..publication]
            .iter()
            .any(|entry| entry == "commit"),
        "native receipt/facts publish after extend and before output: {entries:?}"
    );
    assert_eq!(
        entries[..publication]
            .iter()
            .filter(|entry| *entry == "completion")
            .count(),
        1
    );
}

#[test]
fn cgroup_runtime_same_image_reentry_reports_validated_callers_without_new_ids() {
    let (_fixture, child, mut coordinator) = cgroup_provider_scene();
    let mut driver = ObservedDriver::new(&mut coordinator, CollectionControl::new(None));
    let collect = |job| match job {
        CollectJob::Cgroup { task: Ok(job), .. } => CollectedPass::Cgroup(Ok(Box::new(job()))),
        _ => panic!("the real scoped driver must prepare its original scoped job"),
    };
    let first = collect(driver.collector());
    let mut first = driver
        .apply(
            first,
            &mut crate::discovery::native_binding::ScanOnlyIdentity,
            now_ns(),
        )
        .unwrap();
    driver.commit(false).unwrap();
    driver.finish_pass(&mut first).unwrap();
    assert_eq!(driver.inner.coordinator.registry().caller_count(), 1);
    assert!(driver.inner.coordinator.registry().edges().next().is_some());
    let original = driver
        .inner
        .coordinator
        .adapter()
        .live_id(child.id())
        .unwrap();

    let second = collect(driver.collector());
    let mut second = driver
        .apply(
            second,
            &mut crate::discovery::native_binding::ScanOnlyIdentity,
            now_ns(),
        )
        .unwrap();
    driver.commit(false).unwrap();
    driver.finish_pass(&mut second).unwrap();
    assert_eq!(
        driver.inner.coordinator.adapter().live_id(child.id()),
        Some(original)
    );
    assert!(
        !second
            .events
            .iter()
            .any(|event| matches!(event, CallerEvent::Admitted { .. })),
        "same-image reentry has no newly minted caller ID"
    );
    assert_eq!(
        second.scan_callers, 1,
        "validated same-image caller remains useful in this pass's report"
    );
    assert!(driver.inner.coordinator.take_cgroup_completion().is_none());
}

fn run_public_selection(
    selection: impl Into<InventorySelection>,
    modules: &[PathBuf],
    report: Option<&Path>,
    events: Option<&Path>,
    diagnostics: Option<&Path>,
    stdout: &mut Vec<u8>,
) -> Result<i32> {
    run_with_terminal_budget(
        selection,
        modules,
        &[],
        &[],
        &[],
        &[],
        &HookRegistry::builtin(),
        true,
        Some(2),
        None,
        inventory_endpoint_budget(None).map_err(anyhow::Error::msg)?,
        None,
        report,
        false,
        events,
        None,
        None,
        None,
        if diagnostics.is_some() {
            CaptureMode::Auto
        } else {
            CaptureMode::Scan
        },
        crate::attach::BackendSelection::Auto,
        None,
        false,
        &|| false,
        &|| {},
        false,
        &mut WriterStdout(stdout),
        &DashboardIo::stdio(),
        DiagnosticRequest {
            path: diagnostics,
            pid_filter: None,
            second_signal: &|| false,
        },
        None,
        &|| Ok(crate::attach::MultiCapableHost::for_test()),
        None,
        None,
        false,
        false,
    )
}

fn retained(scope: Scope) -> InventorySelection {
    InventorySelection::Retained {
        scope,
        numbering: crate::pidns::PidNumbering::agreeing(),
    }
}

#[test]
fn native_semantic_no_manifests_means_no_lane_and_no_gap() {
    // H3 Task5: without --manifest the run starts no Detailed lane and
    // records no semantic gap at all; the summary reports disabled.
    let mut stdout = Vec::new();
    let result = run_public_selection(
        crate::cli::ScopeArg::Pid(std::process::id()),
        &[],
        None,
        None,
        None,
        &mut stdout,
    );
    assert_eq!(result.unwrap(), 0);
    let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(
        document["observation"]["semantic_capture"]["status"],
        "disabled"
    );
    let gaps = document["gaps"].as_array().unwrap();
    assert!(
        gaps.iter().all(|gap| {
            !gap["subject"]
                .as_str()
                .unwrap_or_default()
                .contains("semantic")
        }),
        "a manifest-less run carries no semantic gaps, got {gaps:?}"
    );
}

#[test]
fn cgroup_public_plain_directory_refusal_precedes_all_sinks() {
    let fixture = tempfile::tempdir().unwrap();
    let report = fixture.path().join("report.json");
    let events = fixture.path().join("events.jsonl");
    let diagnostics = fixture.path().join("diagnostics.jsonl");
    let mut stdout = Vec::new();
    let result = run_public_selection(
        crate::cli::ScopeArg::Cgroup(fixture.path().into()),
        &[],
        Some(&report),
        Some(&events),
        Some(&diagnostics),
        &mut stdout,
    );
    assert!(result.is_err());
    assert!(stdout.is_empty());
    assert!(!report.exists() && !events.exists() && !diagnostics.exists());
    let error = format!("{:#}", result.unwrap_err());
    assert!(error.contains("not a cgroup v2 directory"), "{error}");
}

#[test]
fn cgroup_public_namespace_refusal_is_specific_and_precedes_all_sinks() {
    use crate::pidns::{ObserverPidNs, PidNumbering, ProcView};
    for numbering in [
        PidNumbering {
            observer: ObserverPidNs::Nested,
            proc_view: ProcView::Own,
        },
        PidNumbering {
            observer: ObserverPidNs::Initial,
            proc_view: ProcView::Foreign("fixture foreign procfs".into()),
        },
        PidNumbering {
            observer: ObserverPidNs::Unknown("fixture unknown namespace".into()),
            proc_view: ProcView::Own,
        },
    ] {
        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(fixture.path().join("cgroup.procs"), "").unwrap();
        let report = fixture.path().join("report.json");
        let events = fixture.path().join("events.jsonl");
        let diagnostics = fixture.path().join("diagnostics.jsonl");
        let selection = InventorySelection::Retained {
            scope: crate::scope::cgroup(fixture.path()).unwrap(),
            numbering,
        };
        let mut stdout = Vec::new();
        let result = run_public_selection(
            selection,
            &[],
            Some(&report),
            Some(&events),
            Some(&diagnostics),
            &mut stdout,
        );
        assert!(result.is_err());
        assert!(stdout.is_empty());
        assert!(!report.exists() && !events.exists() && !diagnostics.exists());
        let error = format!("{:#}", result.unwrap_err());
        assert!(
            error.contains(crate::pidns::MISMATCH_CODE) && error.contains("cgroup inventory"),
            "{error}"
        );
        assert!(
            !error.contains("or use --cgroup"),
            "the cgroup refusal must not recommend its own selector: {error}"
        );
    }
}

#[test]
fn cgroup_public_scan_produces_nonempty_json_events_and_finite_scope_label() {
    let (fixture, child, old_coordinator) = cgroup_provider_scene();
    drop(old_coordinator);
    let selected = fixture.path().join("owned-scope");
    std::fs::create_dir(&selected).unwrap();
    std::fs::write(selected.join("cgroup.procs"), format!("{}\n", child.id())).unwrap();
    let report = fixture.path().join("report.json");
    let events = fixture.path().join("events.jsonl");
    let mut stdout = Vec::new();
    let result = run_public_selection(
        retained(crate::scope::cgroup(&selected).unwrap()),
        &[fixture.path().join("scoped-provider.so")],
        Some(&report),
        Some(&events),
        None,
        &mut stdout,
    );
    assert_eq!(result.unwrap(), 0);
    let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    assert_eq!(document, saved);
    assert_eq!(document["scope"], "cgroup");
    assert_eq!(document["callers"].as_array().unwrap().len(), 1);
    assert!(!document["modules"].as_array().unwrap().is_empty());
    assert!(!document["edges"].as_array().unwrap().is_empty());
    let mut diff_bytes = Vec::new();
    let diff = crate::inventory_diff::run_with_writer(
        &crate::cli::InventoryDiffArgs {
            before: report.clone(),
            after: report,
            json: true,
            out: None,
            output_owner: None,
            verbose: false,
            quiet: false,
        },
        &mut diff_bytes,
    );
    assert_eq!(diff.unwrap(), 0);
    assert!(String::from_utf8_lossy(&diff_bytes).contains("scope_completeness_unknown"));
    let stream = std::fs::read_to_string(events).unwrap();
    assert!(
        stream
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .any(|event| event["kind"] == "caller_event" && event["event"]["event"] == "admitted"),
        "{stream}"
    );
    assert!(!String::from_utf8_lossy(&stdout).contains(&selected.to_string_lossy().to_string()));
    assert!(!stream.contains(&selected.to_string_lossy().to_string()));
}

#[test]
fn cgroup_public_empty_valid_scope_is_empty_scoped_output() {
    let fixture = tempfile::tempdir().unwrap();
    let selected = fixture.path().join("owned-empty-scope");
    std::fs::create_dir(&selected).unwrap();
    std::fs::write(selected.join("cgroup.procs"), "").unwrap();
    let mut stdout = Vec::new();
    let result = run_public_selection(
        retained(crate::scope::cgroup(&selected).unwrap()),
        &[],
        None,
        None,
        None,
        &mut stdout,
    );
    assert_eq!(result.unwrap(), 0);
    let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(document["scope"], "cgroup");
    assert!(document["callers"].as_array().unwrap().is_empty());
    assert!(document["edges"].as_array().unwrap().is_empty());
}

#[test]
fn cgroup_public_retained_root_survives_operator_path_replacement() {
    let (fixture, child, old_coordinator) = cgroup_provider_scene();
    drop(old_coordinator);
    let selected = fixture.path().join("owned-scope");
    std::fs::create_dir(&selected).unwrap();
    std::fs::write(selected.join("cgroup.procs"), format!("{}\n", child.id())).unwrap();
    let original = crate::scope::cgroup(&selected).unwrap();
    std::fs::rename(&selected, fixture.path().join("retained-original")).unwrap();
    std::fs::create_dir(&selected).unwrap();
    std::fs::write(selected.join("cgroup.procs"), "").unwrap();
    let mut stdout = Vec::new();
    let result = run_public_selection(
        retained(original),
        &[fixture.path().join("scoped-provider.so")],
        None,
        None,
        None,
        &mut stdout,
    );
    assert_eq!(result.unwrap(), 0);
    let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(document["scope"], "cgroup");
    assert_eq!(document["callers"].as_array().unwrap().len(), 1);
    assert_eq!(document["callers"][0]["pid"], child.id());
    assert!(!document["edges"].as_array().unwrap().is_empty());
}

#[test]
fn cgroup_public_auto_fallback_keeps_retained_root_and_diagnostic_scope() {
    let (fixture, child, old_coordinator) = cgroup_provider_scene();
    drop(old_coordinator);
    let selected = fixture.path().join("owned-scope");
    std::fs::create_dir(&selected).unwrap();
    std::fs::write(selected.join("cgroup.procs"), format!("{}\n", child.id())).unwrap();
    let scope = crate::scope::cgroup(&selected).unwrap();
    let Scope::Cgroup {
        dir: expected_root, ..
    } = &scope
    else {
        unreachable!()
    };
    let expected_root = expected_root.clone();
    let prepared = Rc::new(std::cell::Cell::new(0));
    let prepare_calls = prepared.clone();
    let report = fixture.path().join("report.json");
    let events = fixture.path().join("events.jsonl");
    let diagnostic_directory = fixture.path().join("diagnostic-output");
    std::fs::create_dir(&diagnostic_directory).unwrap();
    let diagnostics = diagnostic_directory.join("diagnostics.jsonl");
    let mut stdout = Vec::new();
    let result = native_preparation_test::with(
        move |scope, _, _| {
            let crate::attach::capture::CaptureScope::Cgroup(scope) = scope else {
                panic!("native preparation requires the typed cgroup input");
            };
            assert!(
                Arc::ptr_eq(scope.root(), &expected_root),
                "same original root reaches native preparation"
            );
            prepare_calls.set(prepare_calls.get() + 1);
            anyhow::bail!("fixture native preparation unavailable")
        },
        || {
            run_public_selection(
                retained(scope),
                &[fixture.path().join("scoped-provider.so")],
                Some(&report),
                Some(&events),
                Some(&diagnostics),
                &mut stdout,
            )
        },
    );
    assert_eq!(result.unwrap(), 0);
    assert_eq!(prepared.get(), 1);
    let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(document["scope"], "cgroup");
    assert_eq!(document["callers"].as_array().unwrap().len(), 1);
    assert!(!document["edges"].as_array().unwrap().is_empty());
    assert!(
        document["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap["subject"] == "native usage feed unavailable"
                && gap["reason"] == "fixture native preparation unavailable")
    );
    let diagnostics = std::fs::read_to_string(diagnostics).unwrap();
    let records: Vec<serde_json::Value> = diagnostics
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records[0]["kind"], "header");
    assert_eq!(records[0]["scope"], "cgroup");
    assert_eq!(
        records.last().unwrap()["capture_outcome"],
        "native_unavailable"
    );
    assert!(!diagnostics.contains(&selected.to_string_lossy().to_string()));
}

#[test]
fn cgroup_runtime_precommit_exec_witness_invalidates_original_job_and_retires_old_only() {
    let (_fixture, child, mut coordinator) = cgroup_provider_scene();
    // Public startup activates exec coverage before the scoped admission.
    let (capture, log) = crate::inventory_capture::tests::cgroup_runtime_exec_lane(child.id());
    let mut lane = NativeLane::start(capture, &mut coordinator, LaneWindows::PROVISIONAL, None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let initial = coordinator
        .cgroup_collector(
            CgroupWalkState::default(),
            CgroupWalkLimits::default(),
            CollectionControl::new(None),
            None,
        )
        .unwrap()();
    coordinator
        .apply_cgroup_collection(initial, now_ns())
        .unwrap();
    coordinator.commit_batch(false).unwrap();
    let initial = coordinator.take_cgroup_completion().unwrap();
    assert_eq!(initial.admitted, 1);
    let original = coordinator.adapter().live_id(child.id()).unwrap();
    assert!(coordinator.registry().edges().next().is_some());

    // The old witness binds only after a later lifecycle and health read.
    lane.after_cgroup_commit(&mut coordinator);
    coordinator.commit_batch(false).unwrap();
    assert_eq!(coordinator.registry().witness_census().pending, 1);
    lane.after_cgroup_commit(&mut coordinator);
    coordinator.commit_batch(false).unwrap();
    assert_eq!(coordinator.registry().witness_census().bound, 1);
    assert_eq!(coordinator.registry().witness_census().pending, 0);
    assert_eq!(
        coordinator.registry().edges().next().unwrap().entry_count,
        1
    );
    assert_eq!(coordinator.adapter().live_id(child.id()), Some(original));
    assert!(!coordinator.adapter().record(original).unwrap().retired);

    // The next image's actual row is pending when the next scoped job is
    // issued. Its later horizons arrive through production precommit service.
    lane.after_cgroup_commit(&mut coordinator);
    coordinator.commit_batch(false).unwrap();
    assert_eq!(coordinator.registry().witness_census().pending, 1);
    assert_eq!(coordinator.adapter().live_id(child.id()), Some(original));
    log.borrow_mut().clear();
    let mut driver = ObservedDriver::new(&mut coordinator, CollectionControl::new(None));
    driver.inner.cgroup.as_mut().unwrap().continuation = Some(initial.state);
    driver.log = log.clone();
    let mut publications = 0;
    let result = run_classic_finalizing(
        &mut driver,
        Some(lane),
        &clock(&|| false),
        None,
        &mut |_, publication| {
            if let Publish::Pass { report, .. } = publication {
                publications += 1;
                assert_eq!(
                    report.scan_callers, 0,
                    "a precommit EXEC invalidates the original job's permit"
                );
                assert!(
                    !report
                        .events
                        .iter()
                        .any(|event| matches!(event, CallerEvent::Admitted { .. }))
                );
                assert!(report.events.iter().any(
                    |event| matches!(event, CallerEvent::Retired { id, .. } if *id == original)
                ));
            }
            Ok(())
        },
    );
    assert!(result.error.is_none(), "{:?}", result.error);
    assert_eq!(publications, 1);
    assert_eq!(driver.inner.coordinator.adapter().live_id(child.id()), None);
    assert!(
        driver
            .inner
            .coordinator
            .adapter()
            .record(original)
            .unwrap()
            .retired
    );
    assert_eq!(
        driver.inner.coordinator.registry().caller_count(),
        1,
        "old history is retained without a successor"
    );
    let entries = log.borrow();
    let apply = entries.iter().position(|entry| entry == "apply").unwrap();
    let commit = entries.iter().position(|entry| entry == "commit").unwrap();
    assert!(
        entries[apply + 1..commit]
            .iter()
            .any(|entry| entry == "read"),
        "witness staging precedes scoped final commit: {entries:?}"
    );
}
