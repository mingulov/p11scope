//! SPDX-License-Identifier: GPL-3.0-or-later
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
        Self {
            inner: ClassicDriver {
                coordinator,
                inventory_scope: None,
                scope: InventoryRunScope::Cgroup,
                cgroup: Some(CgroupDriverState {
                    continuation: Some(CgroupWalkState::default()),
                    limits: CgroupWalkLimits::default(),
                    control,
                    deadline: None,
                }),
                max_scan_pids: None,
                guard: UnavailableImageGuard,
                deadline: None,
                display: None,
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
    if reason != GateStop::Healthy {
        assert_eq!(
            control.check(),
            Err(if reason == GateStop::Operator {
                CollectionStop::OperatorStop
            } else {
                CollectionStop::Deadline
            })
        );
        assert_eq!(driver.inner.coordinator.registry().caller_count(), 0);
        assert!(
            driver
                .inner
                .coordinator
                .take_target_delta()
                .endpoints
                .is_empty()
        );
    } else {
        assert_eq!(control.check(), Ok(()));
        assert_eq!(driver.inner.coordinator.registry().caller_count(), 1);
        assert!(driver.inner.coordinator.registry().edges().next().is_some());
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
    assert_eq!(driver.inner.coordinator.registry().caller_count(), 0);
    assert!(
        driver
            .inner
            .coordinator
            .take_target_delta()
            .endpoints
            .is_empty()
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
        if diagnostics.is_some() {
            CaptureMode::Auto
        } else {
            CaptureMode::Scan
        },
        crate::attach::BackendSelection::Auto,
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
        None,
    )
}

fn retained(scope: Scope) -> InventorySelection {
    InventorySelection::Retained {
        scope,
        numbering: crate::pidns::PidNumbering::agreeing(),
    }
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
