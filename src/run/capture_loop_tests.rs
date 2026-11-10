//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
use super::*;
use crate::events::{EventDrain, LIVE_POLL_QUANTUM, ScriptedRecords};
use p11scope_ebpf_common::{Event, capture, event_type};

#[test]
fn profile_counter_consumers_share_collection_at_both_terminal_paths() {
    let source = include_str!("../run.rs");
    let profile = source
        .split_once("fn capture_profile(")
        .unwrap()
        .1
        .split_once("fn write_json_report")
        .unwrap()
        .0;
    assert_eq!(
        profile
            .matches("metrics::CaptureCollection::new(counter_inputs)")
            .count(),
        1
    );
    assert_eq!(profile.matches("collection.fresh(").count(), 1);
    let compact: String = profile.chars().filter(|ch| !ch.is_whitespace()).collect();
    assert_eq!(compact.matches("context.6.terminal(").count(), 1);
    assert_eq!(
        profile.matches("&mut collection,").count(),
        2,
        "both normal and quiesce-error finalizers retain the actual live collector"
    );
    let terminal = profile.split_once("fn run_terminal(").unwrap().1;
    assert!(!terminal.contains("last_snapshot"));
    assert!(!terminal.contains("profile_tick_snapshot("));
}

#[test]
fn profile_counter_modes_share_the_live_and_terminal_collection() {
    use p11scope_ebpf_common::CounterMode;
    for mode in [
        CounterMode::Counts,
        CounterMode::Timestamps,
        CounterMode::Latency,
    ] {
        let mut fixture = metrics::ConsumerFixture::new();
        let mut cache = None;
        let live = profile_tick_snapshot(
            ProfileFrame {
                since_frame: Duration::ZERO,
                fresh_snapshot: true,
                render: true,
            },
            &mut cache,
            || fixture.fresh(mode, 1, 5, None),
        )
        .unwrap();
        assert_eq!(live.reports()[0].calls, 5);
        assert_eq!(live.reports()[0].mode, mode);
        assert_eq!(live.reports()[0].rv_counts[&0x1_0000_0001], 2);
        let terminal = fixture.terminal(mode, 1, 8, None).unwrap();
        assert_eq!(terminal.reports()[0].calls, 8);
        assert_eq!(metrics::ConsumerFixture::delta(&terminal), Some(3));
        assert!(metrics::ConsumerFixture::terminal_eligible(&terminal));
        assert_eq!(fixture.reads(), (2, 0));
    }
}

#[test]
fn profile_counter_cached_ticks_make_zero_native_calls() {
    use p11scope_ebpf_common::CounterMode;
    let mut fixture = metrics::ConsumerFixture::new();
    let mut cache = None;
    let first = profile_tick_snapshot(
        ProfileFrame {
            since_frame: Duration::ZERO,
            fresh_snapshot: true,
            render: true,
        },
        &mut cache,
        || fixture.fresh(CounterMode::Counts, 1, 5, None),
    )
    .unwrap();
    for _ in 0..4 {
        let cached = profile_tick_snapshot(
            ProfileFrame {
                since_frame: Duration::ZERO,
                fresh_snapshot: false,
                render: false,
            },
            &mut cache,
            || panic!("a cached tick cannot acquire another native read"),
        )
        .unwrap();
        assert_eq!(cached.counter_collection(), first.counter_collection());
        assert_eq!(cached.reports(), first.reports());
        assert!(!metrics::ConsumerFixture::terminal_eligible(&cached));
    }
    assert_eq!(fixture.reads(), (1, 0));
    let next = fixture.terminal(CounterMode::Counts, 1, 9, None).unwrap();
    assert_eq!(metrics::ConsumerFixture::delta(&next), Some(4));
    assert_eq!(fixture.reads(), (2, 0));
}

#[test]
fn profile_counter_terminal_publishes_last_good_on_failure() {
    use metrics::ConsumerFault;
    use p11scope_ebpf_common::CounterMode;
    for (fault, cause) in [
        (ConsumerFault::ReadRvs, "read_rvs"),
        (ConsumerFault::RowTopology, "topology"),
        (ConsumerFault::Saturated, "saturated"),
        (ConsumerFault::Contended, "contended"),
    ] {
        let mut fixture = metrics::ConsumerFixture::new();
        let live = fixture.fresh(CounterMode::Counts, 1, 5, None).unwrap();
        assert!(!metrics::ConsumerFixture::terminal_eligible(&live.clone()));
        let stale = profile_tick_snapshot(
            ProfileFrame {
                since_frame: Duration::ZERO,
                fresh_snapshot: true,
                render: true,
            },
            &mut None,
            || fixture.fresh(CounterMode::Counts, 1, 8, Some(fault)),
        )
        .unwrap();
        assert_eq!(stale.reports()[0].calls, 5);
        let metadata = stale.counter_collection().unwrap();
        assert_eq!(metadata["status"], "stale");
        assert_eq!(metadata["failure"], cause);
        assert!(metadata["health"].is_null());
        assert!(!metrics::ConsumerFixture::terminal_eligible(&stale));
        let terminal = fixture
            .terminal(CounterMode::Counts, 1, 9, Some(fault))
            .expect("terminal publishes the last good snapshot as stale");
        assert_eq!(terminal.reports()[0].calls, 5);
        assert!(terminal.has_counter_gap());
        let metadata = terminal.counter_collection().unwrap();
        assert_eq!(metadata["status"], "stale");
        assert_eq!(metadata["failure"], cause);
        assert!(!metrics::ConsumerFixture::terminal_eligible(&terminal));
        assert_eq!(fixture.reads(), (3, 0));
    }
}

#[test]
fn profile_counter_initial_unavailability_cannot_fabricate_zero_measurements() {
    use metrics::ConsumerFault;
    use p11scope_ebpf_common::CounterMode;
    for fault in [
        ConsumerFault::ReadRvs,
        ConsumerFault::RowTopology,
        ConsumerFault::Saturated,
        ConsumerFault::Contended,
    ] {
        let mut fixture = metrics::ConsumerFixture::new();
        let mut cache = None;
        let result = profile_tick_snapshot(
            ProfileFrame {
                since_frame: Duration::ZERO,
                fresh_snapshot: true,
                render: true,
            },
            &mut cache,
            || fixture.fresh(CounterMode::Counts, 1, 5, Some(fault)),
        );
        assert!(result.is_err());
        assert!(
            cache.is_none(),
            "no initial unavailable result may become a report"
        );
        assert_eq!(fixture.reads(), (1, 0));
    }
}

#[test]
fn profile_counter_captures_keep_independent_collection_baselines() {
    use p11scope_ebpf_common::CounterMode;
    let mut a = metrics::ConsumerFixture::new();
    let mut b = metrics::ConsumerFixture::new();
    a.fresh(CounterMode::Counts, 1, 5, None).unwrap();
    b.fresh(CounterMode::Counts, 1, 9, None).unwrap();
    let a = a.terminal(CounterMode::Counts, 1, 8, None).unwrap();
    let b = b.terminal(CounterMode::Counts, 1, 14, None).unwrap();
    assert_eq!(a.reports()[0].calls, 8);
    assert_eq!(b.reports()[0].calls, 14);
    assert_eq!(metrics::ConsumerFixture::delta(&a), Some(3));
    assert_eq!(metrics::ConsumerFixture::delta(&b), Some(5));
}

#[test]
fn profile_counter_generation_and_stale_status_keep_accepted_identity() {
    use p11scope_ebpf_common::CounterMode;
    let mut fixture = metrics::ConsumerFixture::new();
    fixture.fresh(CounterMode::Counts, 1, 5, None).unwrap();
    let changed = fixture.fresh(CounterMode::Timestamps, 2, 7, None).unwrap();
    let metadata = changed.counter_collection().unwrap();
    assert_eq!(metadata["mode"], "timestamps");
    assert_eq!(metadata["generation"], 2);
    assert_eq!(metadata["status"], "fresh");
    assert_eq!(metadata["discontinuity"], true);
    let stale = fixture
        .fresh(
            CounterMode::Latency,
            3,
            10,
            Some(metrics::ConsumerFault::ReadRvs),
        )
        .unwrap();
    let metadata = stale.counter_collection().unwrap();
    assert_eq!(metadata["mode"], "timestamps");
    assert_eq!(metadata["generation"], 2);
    assert_eq!(
        metadata["read_window"],
        changed.counter_collection().unwrap()["read_window"]
    );
    assert_eq!(metadata["status"], "stale");
    assert_eq!(stale.reports()[0].mode, CounterMode::Timestamps);
    assert_eq!(stale.reports()[0].calls, 7);
}

#[test]
fn profile_counter_failed_read_preserves_additional_native_kernel_evidence() {
    use p11scope_ebpf_common::CounterMode;
    let mut fixture = metrics::ConsumerFixture::new();
    fixture.fresh(CounterMode::Counts, 1, 5, None).unwrap();
    let stale = fixture
        .fresh(
            CounterMode::Timestamps,
            2,
            8,
            Some(metrics::ConsumerFault::KernelLoss),
        )
        .unwrap();
    assert_eq!(
        stale.kernel_evidence().ring_loss,
        7,
        "counter evidence is never metrics-masked"
    );
    assert_eq!(stale.kernel_evidence().start_insert_failures, 3);
    assert_eq!(
        stale.counter_collection().unwrap()["failure"],
        "kernel_evidence"
    );
    assert_eq!(stale.counter_collection().unwrap()["mode"], "counts");
    assert_eq!(stale.counter_collection().unwrap()["generation"], 1);
    assert_eq!(stale.reports()[0].calls, 5);
    assert_eq!(fixture.reads(), (2, 0));
}

fn open_plan() -> crate::plan::AttachPlan {
    crate::plan::AttachPlan::from_slots(vec![crate::plan::Slot {
        index: 0,
        descriptor_index: crate::kinds::function_id("C_OpenSession").unwrap() + 1,
        object: crate::plan::TEST_PINNED_OBJECT,
        object_path: "/opt/p11.so".into(),
        file_offset: 0x10,
        names: vec!["C_OpenSession".into()],
        aliased: false,
        semantics: crate::kinds::descriptor("C_OpenSession").unwrap(),
        semantic_authorized: true,
        semantic_ambiguous: false,
        fork_safe: true,
        module_ids: vec![crate::plan::ModuleId(0)],
    }])
}

fn open_event(session: u64) -> Event {
    Event {
        ts_ns: session * 100,
        duration_ns: 10,
        event_type: event_type::CALL,
        image: p11scope_ebpf_common::ImageIdentity {
            task_cookie: 77,
            exec_id: 0,
        },
        pid_tgid: u64::from(std::process::id()) << 32,
        session,
        slot_id: 3,
        slot: 0,
        capture: capture::MECHANISM_NONE | capture::OUTPUT_NON_NULL,
        rv: pkcs11_types::CkRv::OK.0,
        ..Event::default()
    }
}

fn tracker() -> process::Tracker {
    process::Tracker::for_producer(crate::events::EventsDomain::test_standin(1), 16)
}

fn terminal_plan() -> crate::plan::AttachPlan {
    let mut plan = open_plan();
    plan.slots.push(crate::plan::Slot {
        index: 1,
        descriptor_index: crate::kinds::function_id("C_Sign").unwrap() + 1,
        object: crate::plan::TEST_PINNED_OBJECT,
        object_path: "/opt/p11.so".into(),
        file_offset: 0x20,
        names: vec!["C_Sign".into()],
        aliased: false,
        semantics: crate::kinds::descriptor("C_Sign").unwrap(),
        semantic_authorized: true,
        semantic_ambiguous: false,
        fork_safe: true,
        module_ids: vec![crate::plan::ModuleId(0)],
    });
    plan
}

fn root_event(slot: u32, rv: u64) -> Event {
    Event {
        slot,
        rv,
        root_affiliation: 1,
        ..open_event(11)
    }
}

struct TerminalWriter {
    fail: bool,
    bytes: Vec<u8>,
}

impl Write for TerminalWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.fail {
            Err(std::io::Error::other("deferred trace writer failure"))
        } else {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct TerminalContext {
    plan: crate::plan::AttachPlan,
    root: Option<(
        EventDrain<crate::events::root_fence_tests::Source>,
        crate::events::OwnedRootTail,
    )>,
    ordinary: EventDrain<ScriptedRecords>,
    remaining: Option<u64>,
    writer: TerminalWriter,
    stdout_open: bool,
    phases: Vec<&'static str>,
}

fn terminal_context(
    plan: crate::plan::AttachPlan,
    domain: crate::events::EventsDomain,
    root_events: impl IntoIterator<Item = Event>,
) -> TerminalContext {
    let tail = crate::events::OwnedRootTail::new(
        OriginalRootExit::test_reaped(domain.clone()),
        Instant::now() + Duration::from_secs(1),
    );
    TerminalContext {
        plan,
        root: Some((
            EventDrain::over_domain(crate::events::root_fence_tests::source(root_events), domain),
            tail,
        )),
        ordinary: EventDrain::over_test_domain(ScriptedRecords::events([], usize::MAX), 1),
        remaining: None,
        writer: TerminalWriter {
            fail: false,
            bytes: Vec::new(),
        },
        stdout_open: true,
        phases: Vec::new(),
    }
}

#[test]
fn finish_capture_preserves_settlement_detach_and_terminal_attempt_boundaries() {
    #[derive(Clone, Copy)]
    enum Case {
        LoopError,
        LoopErrorSettleFails,
        FinishError,
        ErrorEnd,
        Success,
        DetachError,
    }

    for case in [
        Case::LoopError,
        Case::LoopErrorSettleFails,
        Case::FinishError,
        Case::ErrorEnd,
        Case::Success,
        Case::DetachError,
    ] {
        let mut phases = Vec::new();
        let mut observed = None;
        let loop_result = match case {
            Case::LoopError | Case::LoopErrorSettleFails => Err(anyhow::anyhow!("loop failure")),
            Case::ErrorEnd => Ok(CaptureEnd::Error),
            _ => Ok(CaptureEnd::DurationExpired),
        };
        let result = finish_capture_with(
            &mut phases,
            loop_result,
            |phases| phases.push("gap"),
            |phases, result| {
                phases.push("finish");
                let end = result?;
                if matches!(case, Case::FinishError | Case::LoopErrorSettleFails) {
                    anyhow::bail!("finish failure");
                }
                Ok(end)
            },
            |phases| {
                phases.push("detach");
                if matches!(case, Case::DetachError) {
                    anyhow::bail!("detach failure");
                }
                Ok(())
            },
            |phases, end, detached| {
                phases.push("terminal");
                observed = Some((end, detached));
                Ok(17)
            },
        );

        match case {
            Case::LoopError => {
                // A failed capture loop still seals the report from
                // what was captured: settle as an error end, publish,
                // then detach. The loop error stays the outer error.
                let message = format!("{:#}", result.unwrap_err());
                assert!(message.contains("loop failure"), "{message}");
                assert_eq!(observed, Some((CaptureEnd::Error, false)));
                assert_eq!(phases, ["gap", "finish", "terminal", "detach"]);
            }
            Case::LoopErrorSettleFails => {
                // A failed settlement seals with child status unknown
                // instead of suppressing the report, and both errors are
                // kept.
                let message = format!("{:#}", result.unwrap_err());
                assert!(
                    message.contains("loop failure") && message.contains("finish failure"),
                    "{message}"
                );
                assert_eq!(observed, Some((CaptureEnd::Error, false)));
                assert_eq!(phases, ["gap", "finish", "terminal", "detach"]);
            }
            Case::FinishError => {
                // The terminal still seals (with unknown child status) and
                // detach still runs; the finish error stays the error,
                // exactly (a succeeding terminal and detach add no layer).
                assert_eq!(result.unwrap_err().to_string(), "finish failure");
                assert_eq!(observed, Some((CaptureEnd::DurationExpired, false)));
                assert_eq!(phases, ["finish", "terminal", "detach"]);
            }
            Case::ErrorEnd => {
                assert_eq!(result.unwrap(), 17);
                assert_eq!(observed, Some((CaptureEnd::Error, false)));
                assert_eq!(phases, ["finish", "terminal", "detach"]);
            }
            Case::Success => {
                assert_eq!(result.unwrap(), 17);
                assert_eq!(observed, Some((CaptureEnd::DurationExpired, false)));
                assert_eq!(phases, ["finish", "terminal", "detach"]);
            }
            Case::DetachError => {
                assert!(result.unwrap_err().to_string().contains("detach failure"));
                assert_eq!(observed, Some((CaptureEnd::DurationExpired, false)));
                assert_eq!(phases, ["finish", "terminal", "detach"]);
            }
        }
    }
}

/// I1: a quiesce-block failure settles like a capture-loop failure.
/// Settlement (pause cleanup plus policy settlement in production) runs
/// with the loop's real end, then publication seals the report from
/// partial state, then detach runs. Every error — quiesce, settlement,
/// publication, detach — is retained in the returned error. A settlement
/// failure seals with child status unknown instead of skipping
/// publication.
#[test]
fn quiesce_error_runs_settlement_with_the_loop_end_then_detaches() {
    #[derive(Clone, Copy)]
    enum Case {
        Clean,
        SettleError,
        DetachError,
        BothError,
    }

    for case in [
        Case::Clean,
        Case::SettleError,
        Case::DetachError,
        Case::BothError,
    ] {
        let mut phases = Vec::new();
        let mut settled_end = None;
        let error = finish_quiesce_error(
            anyhow::anyhow!("quiesce failure"),
            Ok(CaptureEnd::DurationExpired),
            &mut phases,
            |phases| phases.push("gap"),
            |phases, end| {
                phases.push("settle");
                settled_end = Some(end);
                if matches!(case, Case::SettleError | Case::BothError) {
                    anyhow::bail!("settle failure");
                }
                Ok(())
            },
            |phases| {
                phases.push("publish");
                Ok(())
            },
            |phases| {
                phases.push("detach");
                if matches!(case, Case::DetachError | Case::BothError) {
                    anyhow::bail!("detach failure");
                }
                Ok(())
            },
        );
        // Settlement runs (not skipped) with the loop's real end, before
        // detach — the `--duration` handoff end survives a quiesce failure.
        // Publication runs between them even when settlement failed (with
        // unknown child status).
        assert_eq!(settled_end, Some(CaptureEnd::DurationExpired));
        assert_eq!(phases, ["settle", "publish", "detach"]);
        let message = format!("{error:#}");
        assert!(
            message.contains("quiesce failure"),
            "quiesce error dropped: {message}"
        );
        match case {
            Case::Clean => assert_eq!(message, "quiesce failure"),
            Case::SettleError => {
                assert!(
                    message.contains("settle failure")
                        && message.contains("owned cleanup/settlement"),
                    "settlement error lost or mislabeled: {message}"
                );
            }
            Case::DetachError => {
                assert!(
                    message.contains("detach failure")
                        && message.contains("detaching capture producers"),
                    "detach error lost or mislabeled: {message}"
                );
            }
            Case::BothError => {
                assert!(
                    message.contains("settle failure") && message.contains("detach failure"),
                    "cleanup errors lost: {message}"
                );
            }
        }
    }
}

/// I1: a publication failure behind a quiesce failure keeps its own
/// layer, and detach still runs behind both.
#[test]
fn quiesce_error_with_publish_failure_labels_publication_and_still_detaches() {
    let mut phases = Vec::new();
    let error = finish_quiesce_error(
        anyhow::anyhow!("quiesce failure"),
        Ok(CaptureEnd::Signal),
        &mut phases,
        |phases| phases.push("gap"),
        |phases, _| {
            phases.push("settle");
            Ok(())
        },
        |phases| {
            phases.push("publish");
            anyhow::bail!("seal failure");
        },
        |phases| {
            phases.push("detach");
            Ok(())
        },
    );
    assert_eq!(phases, ["settle", "publish", "detach"]);
    let message = format!("{error:#}");
    assert!(
        message.contains("quiesce failure")
            && message.contains("seal failure")
            && message.contains("terminal publication"),
        "publication error lost or mislabeled: {message}"
    );
}

/// I1: a loop failure plus a quiesce failure keeps both errors (the loop
/// error is the capture failure, the quiesce error attaches to it), and
/// settlement runs with `Error` — a failed loop never hands a child back.
#[test]
fn quiesce_error_after_loop_failure_keeps_both_errors_and_settles_as_error() {
    let mut phases = Vec::new();
    let mut settled_end = None;
    let error = finish_quiesce_error(
        anyhow::anyhow!("quiesce failure"),
        Err(anyhow::anyhow!("loop failure")),
        &mut phases,
        |phases| phases.push("gap"),
        |phases, end| {
            phases.push("settle");
            settled_end = Some(end);
            Ok(())
        },
        |phases| {
            phases.push("publish");
            Ok(())
        },
        |phases| {
            phases.push("detach");
            Ok(())
        },
    );
    assert_eq!(settled_end, Some(CaptureEnd::Error));
    // A failed loop still seals what was captured, unsignalled too,
    // and files its named gap before the seal.
    assert_eq!(phases, ["gap", "settle", "publish", "detach"]);
    let message = format!("{error:#}");
    assert!(
        message.contains("loop failure"),
        "loop error dropped: {message}"
    );
    assert!(
        message.contains("quiesce failure"),
        "quiesce error dropped: {message}"
    );
    assert!(
        message.contains("terminal quiescence"),
        "quiesce phase unlabeled: {message}"
    );
}

#[test]
fn terminal_completed_root_reduces_and_retires_before_ordinary_drain_in_both_modes() {
    for trace_mode in [false, true] {
        let domain = crate::events::EventsDomain::test_standin(41 + u64::from(trace_mode));
        let plan = terminal_plan();
        let mut state = semantics::State::for_capture(
            &plan,
            crate::attach::CapturePolicy::Allowlisted,
            domain.clone(),
        );
        let mut tracker = process::Tracker::for_producer(domain.clone(), 16);
        let mut tracer = trace::Tracer::new(&plan);
        let mut malformed_records = 0;
        let mut context = terminal_context(
            plan,
            domain.clone(),
            [
                root_event(0, pkcs11_types::CkRv::OK.0),
                root_event(1, pkcs11_types::CkRv::PENDING.0),
            ],
        );
        context.ordinary = EventDrain::over_domain(
            ScriptedRecords::events([open_event(12)], usize::MAX),
            domain,
        );
        let mut diagnostics = Vec::new();

        let snapshot = {
            let mut scheduling = SchedulingAccumulator::default();
            let mut consumers = CaptureConsumers {
                state: &mut state,
                tracker: &mut tracker,
                tracer: trace_mode.then_some(&mut tracer),
                malformed_records: &mut malformed_records,
                scheduling: &mut scheduling,
                stop_quiescence: Default::default(),
            };
            drain_capture_terminal_with(
                &mut context,
                &mut consumers,
                None,
                &mut diagnostics,
                |context: &mut TerminalContext, _, quiesced| {
                    assert_eq!(quiesced, None);
                    context.phases.push("discovery");
                    Ok((false, &context.plan))
                },
                |context, consumers| {
                    context.phases.push("root");
                    let (mut drain, tail) = context.root.take().unwrap();
                    if let Some(tracer) = consumers.tracer.as_deref_mut() {
                        let mut write_error = None;
                        let mut out_file: Option<Vec<u8>> = None;
                        let result = drain_original_root_events_from(
                            &mut drain,
                            tail,
                            &SignalState::new(),
                            |domain, event| {
                                reduce_trace_event(
                                    domain,
                                    &mut context.remaining,
                                    consumers.state,
                                    consumers.tracker,
                                    &Scope::Pid(std::process::id()),
                                    tracer,
                                    &mut context.writer,
                                    &mut context.stdout_open,
                                    &mut out_file,
                                    &mut write_error,
                                    event,
                                )
                            },
                        );
                        (result, write_error)
                    } else {
                        (
                            drain_original_root_events_from(
                                &mut drain,
                                tail,
                                &SignalState::new(),
                                |domain, event| {
                                    reduce_profile_event(
                                        domain,
                                        consumers.tracker,
                                        consumers.state,
                                        &Scope::Pid(std::process::id()),
                                        event,
                                    )
                                },
                            ),
                            None,
                        )
                    }
                },
                |_| {},
                |context, consumers| {
                    context.phases.push("drain");
                    let sessions = consumers.state.sessions();
                    assert_eq!(sessions.closed, 1);
                    assert_eq!(consumers.state.pending_at_end(), 0);
                    if let Some(tracer) = consumers.tracer.as_deref_mut() {
                        let mut out_file: Option<Vec<u8>> = None;
                        let (malformed, _) = drain_trace_events_from(
                            &mut context.ordinary,
                            &mut context.remaining,
                            consumers.state,
                            consumers.tracker,
                            &Scope::Pid(std::process::id()),
                            tracer,
                            &mut context.writer,
                            &mut context.stdout_open,
                            &mut out_file,
                            None,
                        )?;
                        *consumers.malformed_records += malformed;
                    } else {
                        let (malformed, _) = drain_profile_events(
                            &mut context.ordinary,
                            consumers.state,
                            consumers.tracker,
                            &Scope::Pid(std::process::id()),
                            None,
                        )?;
                        *consumers.malformed_records += malformed;
                    }
                    Ok(())
                },
                |_| {},
                |context, consumers| {
                    context.phases.push("snapshot");
                    let sessions = consumers.state.sessions();
                    Ok((
                        sessions.opened,
                        sessions.closed,
                        consumers.state.pending_at_end(),
                    ))
                },
            )
            .unwrap()
        };

        assert_eq!(snapshot, (1, 1, 0));
        assert_eq!(context.ordinary.source().remaining(), 0);
        assert_eq!(malformed_records, 0);
        assert_eq!(context.phases, ["discovery", "root", "drain", "snapshot"]);
        assert!(diagnostics.is_empty());
        if trace_mode {
            assert_eq!(tracer.raw_calls(), 3);
            assert!(!context.writer.bytes.is_empty());
        }
    }
}

fn pending_state(
    plan: &crate::plan::AttachPlan,
    domain: crate::events::EventsDomain,
) -> (semantics::State, process::Tracker) {
    let mut state = semantics::State::for_capture(
        plan,
        crate::attach::CapturePolicy::Allowlisted,
        domain.clone(),
    );
    let mut tracker = process::Tracker::for_producer(domain.clone(), 16);
    let mut drain = EventDrain::over_domain(
        ScriptedRecords::events(
            [
                root_event(0, pkcs11_types::CkRv::OK.0),
                root_event(1, pkcs11_types::CkRv::PENDING.0),
            ],
            usize::MAX,
        ),
        domain,
    );
    drain_profile_events(
        &mut drain,
        &mut state,
        &mut tracker,
        &Scope::Pid(std::process::id()),
        None,
    )
    .unwrap();
    (state, tracker)
}

#[test]
fn terminal_absent_and_cancelled_roots_retain_pending_state() {
    for cancelled in [false, true] {
        let domain = crate::events::EventsDomain::test_standin(51 + u64::from(cancelled));
        let plan = terminal_plan();
        let (mut state, mut tracker) = pending_state(&plan, domain);
        let mut malformed_records = 0;
        let mut context = context(plan, []);
        let mut diagnostics = Vec::new();
        let snapshot = {
            let mut scheduling = SchedulingAccumulator::default();
            let mut consumers = CaptureConsumers {
                state: &mut state,
                tracker: &mut tracker,
                tracer: None,
                malformed_records: &mut malformed_records,
                scheduling: &mut scheduling,
                stop_quiescence: Default::default(),
            };
            drain_capture_terminal_with(
                &mut context,
                &mut consumers,
                None,
                &mut diagnostics,
                |context: &mut TickContext, _, _| Ok((false, &context.plan)),
                |_, _| {
                    (
                        Ok(if cancelled {
                            OriginalRootDrain::Cancelled {
                                malformed: 3,
                                remaining: 2,
                            }
                        } else {
                            OriginalRootDrain::Absent
                        }),
                        None,
                    )
                },
                |_| {},
                |_, _| Ok(()),
                |_| {},
                |_, consumers| {
                    let sessions = consumers.state.sessions();
                    Ok((
                        sessions.opened,
                        sessions.closed,
                        consumers.state.pending_at_end(),
                    ))
                },
            )
            .unwrap()
        };
        assert_eq!(snapshot, (1, 0, 1));
        assert_eq!(malformed_records, if cancelled { 3 } else { 0 });
        assert_eq!(
            String::from_utf8_lossy(&diagnostics).contains("cancelled; remaining=2"),
            cancelled
        );
    }
}

#[test]
fn terminal_deferred_trace_writer_error_retires_then_skips_later_phases() {
    let domain = crate::events::EventsDomain::test_standin(61);
    let plan = terminal_plan();
    let mut state = semantics::State::for_capture(
        &plan,
        crate::attach::CapturePolicy::Allowlisted,
        domain.clone(),
    );
    let mut tracker = process::Tracker::for_producer(domain.clone(), 16);
    let mut tracer = trace::Tracer::new(&plan);
    let mut malformed_records = 0;
    let mut context = terminal_context(
        plan,
        domain,
        [
            root_event(0, pkcs11_types::CkRv::OK.0),
            root_event(1, pkcs11_types::CkRv::PENDING.0),
        ],
    );
    context.writer.fail = true;
    let mut diagnostics = Vec::new();
    let result = {
        let mut scheduling = SchedulingAccumulator::default();
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: Some(&mut tracer),
            malformed_records: &mut malformed_records,
            scheduling: &mut scheduling,
            stop_quiescence: Default::default(),
        };
        drain_capture_terminal_with(
            &mut context,
            &mut consumers,
            None,
            &mut diagnostics,
            |context: &mut TerminalContext, _, _| {
                context.phases.push("discovery");
                Ok((false, &context.plan))
            },
            |context, consumers| {
                context.phases.push("root");
                let (mut drain, tail) = context.root.take().unwrap();
                let mut write_error = None;
                let mut out_file: Option<Vec<u8>> = None;
                let result = drain_original_root_events_from(
                    &mut drain,
                    tail,
                    &SignalState::new(),
                    |domain, event| {
                        reduce_trace_event(
                            domain,
                            &mut context.remaining,
                            consumers.state,
                            consumers.tracker,
                            &Scope::Pid(std::process::id()),
                            consumers.tracer.as_deref_mut().unwrap(),
                            &mut context.writer,
                            &mut context.stdout_open,
                            &mut out_file,
                            &mut write_error,
                            event,
                        )
                    },
                );
                (result, write_error)
            },
            |_| {},
            |context, _| {
                context.phases.push("drain");
                Ok(())
            },
            |_| {},
            |context, _| {
                context.phases.push("snapshot");
                Ok(())
            },
        )
    };
    let error = format!("{:#}", result.unwrap_err());
    assert!(error.contains("deferred trace writer failure"), "{error}");
    assert_eq!(context.phases, ["discovery", "root"]);
    assert_eq!(state.sessions().opened, 1);
    assert_eq!(state.sessions().closed, 1);
    assert_eq!(state.pending_at_end(), 0);
}

#[test]
fn terminal_discovery_error_stops_but_root_and_drain_errors_still_seal() {
    for failure in ["discovery", "root", "drain"] {
        let plan = terminal_plan();
        let mut state = semantics::State::new(&plan);
        let mut tracker = tracker();
        let mut malformed_records = 0;
        let mut context = context(plan, []);
        let phases = std::cell::RefCell::new(Vec::new());
        let mut diagnostics = Vec::new();
        let result = {
            let mut scheduling = SchedulingAccumulator::default();
            let mut consumers = CaptureConsumers {
                state: &mut state,
                tracker: &mut tracker,
                tracer: None,
                malformed_records: &mut malformed_records,
                scheduling: &mut scheduling,
                stop_quiescence: Default::default(),
            };
            drain_capture_terminal_with(
                &mut context,
                &mut consumers,
                None,
                &mut diagnostics,
                |context: &mut TickContext, _, quiesced| {
                    phases.borrow_mut().push("discovery");
                    assert_eq!(quiesced, None);
                    if failure == "discovery" {
                        anyhow::bail!("discovery failure");
                    }
                    Ok((false, &context.plan))
                },
                |_, _| {
                    phases.borrow_mut().push("root");
                    if failure == "root" {
                        (
                            Err(anyhow::anyhow!("root failure")),
                            Some(anyhow::anyhow!("root writer failure")),
                        )
                    } else {
                        (Ok(OriginalRootDrain::Absent), None)
                    }
                },
                |_| {},
                |_, _| {
                    phases.borrow_mut().push("drain");
                    if failure == "drain" {
                        anyhow::bail!("drain failure");
                    }
                    Ok(())
                },
                |_| {},
                |_, _| {
                    phases.borrow_mut().push("snapshot");
                    Ok(())
                },
            )
        };
        let error = format!("{:#}", result.unwrap_err());
        assert!(error.contains(failure), "{error}");
        if failure == "root" {
            assert!(error.contains("root writer failure"), "{error}");
        }
        // Data-always (owner, binding, 2026-11-09): a run that collected
        // data seals its report even when a terminal drain fails. Root
        // and drain failures file a named gap, run the remaining phases,
        // and fail after publication; only a discovery failure still
        // stops the terminal.
        let expected = match failure {
            "discovery" => vec!["discovery"],
            "root" => vec!["discovery", "root", "drain", "snapshot"],
            _ => vec!["discovery", "root", "drain", "snapshot"],
        };
        assert_eq!(*phases.borrow(), expected);
    }

    let plan = terminal_plan();
    let mut state = semantics::State::new(&plan);
    let mut tracker = tracker();
    let mut malformed_records = 0;
    let mut context = context(plan, []);
    let mut diagnostics = TerminalWriter {
        fail: true,
        bytes: Vec::new(),
    };
    let error = {
        let mut scheduling = SchedulingAccumulator::default();
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: None,
            malformed_records: &mut malformed_records,
            scheduling: &mut scheduling,
            stop_quiescence: Default::default(),
        };
        drain_capture_terminal_with(
            &mut context,
            &mut consumers,
            None,
            &mut diagnostics,
            |context: &mut TickContext, _, _| Ok((false, &context.plan)),
            |_, _| {
                (
                    Ok(OriginalRootDrain::Cancelled {
                        malformed: 0,
                        remaining: 4,
                    }),
                    None,
                )
            },
            |_| {},
            |_, _| Ok(()),
            |_| {},
            |_, _| Err::<(), _>(anyhow::anyhow!("publication failure")),
        )
        .unwrap_err()
    };
    let error = format!("{error:#}");
    assert!(error.contains("publication failure"), "{error}");
    assert!(
        error.contains("root-tail diagnostic also failed"),
        "{error}"
    );
    assert!(error.contains("deferred trace writer failure"), "{error}");
}

#[test]
fn terminal_discovery_syncs_new_and_downgraded_slots_for_both_consumers() {
    let empty = crate::plan::AttachPlan::from_slots(vec![]);
    let mut state = semantics::State::new(&empty);
    let mut tracker = tracker();
    let mut tracer = trace::Tracer::new(&empty);
    let mut malformed_records = 0;
    let mut context = context(open_plan(), [open_event(11)]);
    let mut diagnostics = Vec::new();
    {
        let mut scheduling = SchedulingAccumulator::default();
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: Some(&mut tracer),
            malformed_records: &mut malformed_records,
            scheduling: &mut scheduling,
            stop_quiescence: Default::default(),
        };
        let snapshot = drain_capture_terminal_with(
            &mut context,
            &mut consumers,
            None,
            &mut diagnostics,
            |context: &mut TickContext, _, _| Ok((true, &context.plan)),
            |_, _| (Ok(OriginalRootDrain::Absent), None),
            |_| {},
            |context, consumers| drain_tick(context, consumers),
            |_| {},
            |_, consumers| Ok(consumers.state.sessions().opened),
        )
        .unwrap();
        assert_eq!(snapshot, 1);
    }
    assert!(String::from_utf8_lossy(&context.stdout).contains(" C_OpenSession "));

    context.plan.slots[0].descriptor_index = 0;
    context.plan.slots[0].semantics = p11scope_ebpf_common::SlotSemantics::COUNT_ONLY;
    context.plan.slots[0].semantic_authorized = false;
    context.drain =
        EventDrain::over_test_domain(ScriptedRecords::events([open_event(12)], usize::MAX), 1);
    context.stdout.clear();
    {
        let mut scheduling = SchedulingAccumulator::default();
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: Some(&mut tracer),
            malformed_records: &mut malformed_records,
            scheduling: &mut scheduling,
            stop_quiescence: Default::default(),
        };
        let snapshot = drain_capture_terminal_with(
            &mut context,
            &mut consumers,
            None,
            &mut diagnostics,
            |context: &mut TickContext, _, _| Ok((true, &context.plan)),
            |_, _| (Ok(OriginalRootDrain::Absent), None),
            |_| {},
            |context, consumers| drain_tick(context, consumers),
            |_| {},
            |_, consumers| Ok(consumers.state.sessions().opened),
        )
        .unwrap();
        assert_eq!(snapshot, 0);
    }
    // The downgraded slot's line names the function with no per-line
    // marker; the header note covers unverified slots once.
    let stdout = String::from_utf8_lossy(&context.stdout);
    assert!(stdout.contains(" C_OpenSession "), "{stdout}");
    assert!(!stdout.contains("[semantics unverified]"), "{stdout}");
}

struct TickContext {
    plan: crate::plan::AttachPlan,
    drain: EventDrain<ScriptedRecords>,
    remaining: Option<u64>,
    stdout: Vec<u8>,
    stdout_open: bool,
    out_file: Option<Vec<u8>>,
}

fn context(plan: crate::plan::AttachPlan, events: impl IntoIterator<Item = Event>) -> TickContext {
    TickContext {
        plan,
        drain: EventDrain::over_test_domain(ScriptedRecords::events(events, usize::MAX), 1),
        remaining: None,
        stdout: Vec::new(),
        stdout_open: true,
        out_file: None,
    }
}

fn drain_tick(context: &mut TickContext, consumers: &mut CaptureConsumers<'_>) -> Result<()> {
    let (malformed, _) = if let Some(tracer) = consumers.tracer.as_deref_mut() {
        drain_trace_events_from(
            &mut context.drain,
            &mut context.remaining,
            consumers.state,
            consumers.tracker,
            &Scope::Pid(std::process::id()),
            tracer,
            &mut context.stdout,
            &mut context.stdout_open,
            &mut context.out_file,
            Some(LIVE_POLL_QUANTUM),
        )?
    } else {
        drain_profile_events(
            &mut context.drain,
            consumers.state,
            consumers.tracker,
            &Scope::Pid(std::process::id()),
            Some(LIVE_POLL_QUANTUM),
        )?
    };
    *consumers.malformed_records += malformed;
    Ok(())
}

#[test]
fn capture_tick_syncs_new_and_downgraded_slots_before_reduction() {
    for trace_mode in [false, true] {
        let empty = crate::plan::AttachPlan::from_slots(vec![]);
        let mut state = semantics::State::new(&empty);
        let mut tracker = tracker();
        let mut tracer = trace::Tracer::new(&empty);
        let mut malformed_records = 0;
        let mut context = context(open_plan(), [open_event(11)]);

        {
            let mut scheduling = SchedulingAccumulator::default();
            let mut consumers = CaptureConsumers {
                state: &mut state,
                tracker: &mut tracker,
                tracer: trace_mode.then_some(&mut tracer),
                malformed_records: &mut malformed_records,
                scheduling: &mut scheduling,
                stop_quiescence: Default::default(),
            };
            let tick = capture_tick_with(
                &mut context,
                &mut consumers,
                |context: &mut TickContext, _| Ok((true, true, &context.plan)),
                |_| Ok(None),
                |context, consumers| {
                    drain_tick(context, consumers)?;
                    Ok(None)
                },
                |_, consumers| Ok(consumers.state.sessions().opened),
                |_| Ok(()),
            )
            .unwrap();
            assert!(matches!(tick, CaptureTick::Continue { snapshot: 1, .. }));
        }
        assert_eq!(state.sessions().opened, 1);
        if trace_mode {
            let stdout = String::from_utf8_lossy(&context.stdout);
            assert!(stdout.contains(" C_OpenSession "), "{stdout}");
            assert!(stdout.contains("sess#"), "{stdout}");
        }

        context.plan.slots[0].descriptor_index = 0;
        context.plan.slots[0].semantics = p11scope_ebpf_common::SlotSemantics::COUNT_ONLY;
        context.plan.slots[0].semantic_authorized = false;
        context.drain =
            EventDrain::over_test_domain(ScriptedRecords::events([open_event(12)], usize::MAX), 1);
        context.stdout.clear();
        {
            let mut scheduling = SchedulingAccumulator::default();
            let mut consumers = CaptureConsumers {
                state: &mut state,
                tracker: &mut tracker,
                tracer: trace_mode.then_some(&mut tracer),
                malformed_records: &mut malformed_records,
                scheduling: &mut scheduling,
                stop_quiescence: Default::default(),
            };
            let tick = capture_tick_with(
                &mut context,
                &mut consumers,
                |context: &mut TickContext, _| Ok((true, true, &context.plan)),
                |_| Ok(None),
                |context, consumers| {
                    drain_tick(context, consumers)?;
                    Ok(None)
                },
                |_, consumers| Ok(consumers.state.sessions().opened),
                |_| Ok(()),
            )
            .unwrap();
            assert!(matches!(
                tick,
                CaptureTick::Continue {
                    paused: true,
                    snapshot: 0
                }
            ));
        }

        assert_eq!(
            state.sessions().opened,
            0,
            "COUNT_ONLY must not add a semantic open"
        );
        if trace_mode {
            // No per-line marker anymore: a downgraded (COUNT_ONLY) slot
            // renders the bare name with no session pseudonym, so the
            // missing `sess#` proves the tracer synced the downgrade.
            let stdout = String::from_utf8_lossy(&context.stdout);
            assert!(stdout.contains(" C_OpenSession "), "{stdout}");
            assert!(
                !stdout.contains("sess#"),
                "trace metadata must be synchronized with the downgrade: {stdout}"
            );
        }
    }
}

#[test]
fn capture_tick_limit_skips_live_snapshot_and_check_but_terminal_reduces_remainder() {
    let plan = open_plan();
    let mut state = semantics::State::new(&plan);
    let mut tracker = tracker();
    let mut tracer = trace::Tracer::new(&plan);
    let mut malformed_records = 0;
    let mut context = context(plan, [open_event(11), open_event(12)]);
    context.remaining = Some(1);
    let snapshot_called = std::cell::Cell::new(false);
    let check_called = std::cell::Cell::new(false);

    let tick = {
        let mut scheduling = SchedulingAccumulator::default();
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: Some(&mut tracer),
            malformed_records: &mut malformed_records,
            scheduling: &mut scheduling,
            stop_quiescence: Default::default(),
        };
        capture_tick_with(
            &mut context,
            &mut consumers,
            |context: &mut TickContext, _| Ok((false, false, &context.plan)),
            |_| Ok(None),
            |context, consumers| {
                drain_tick(context, consumers)?;
                Ok((context.remaining == Some(0)).then_some(CaptureEnd::LimitReached))
            },
            |_, _| {
                snapshot_called.set(true);
                Ok(())
            },
            |_| {
                check_called.set(true);
                Ok(())
            },
        )
        .unwrap()
    };

    assert!(matches!(tick, CaptureTick::End(CaptureEnd::LimitReached)));
    assert!(!snapshot_called.get());
    assert!(!check_called.get());
    assert_eq!(state.sessions().opened, 1);
    assert_eq!(context.drain.source().remaining(), 1);
    let emitted = context.stdout.len();

    let mut diagnostics = Vec::new();
    let terminal_opened = {
        let mut scheduling = SchedulingAccumulator::default();
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: Some(&mut tracer),
            malformed_records: &mut malformed_records,
            scheduling: &mut scheduling,
            stop_quiescence: Default::default(),
        };
        drain_capture_terminal_with(
            &mut context,
            &mut consumers,
            None,
            &mut diagnostics,
            |context: &mut TickContext, _, quiesced| {
                assert_eq!(quiesced, None);
                Ok((false, &context.plan))
            },
            |_, _| (Ok(OriginalRootDrain::Absent), None),
            |_| {},
            |context, consumers| {
                let (malformed, _) = drain_trace_events_from(
                    &mut context.drain,
                    &mut context.remaining,
                    consumers.state,
                    consumers.tracker,
                    &Scope::Pid(std::process::id()),
                    consumers.tracer.as_deref_mut().expect("trace consumer"),
                    &mut context.stdout,
                    &mut context.stdout_open,
                    &mut context.out_file,
                    None,
                )?;
                *consumers.malformed_records += malformed;
                Ok(())
            },
            |_| {},
            |_, consumers| Ok(consumers.state.sessions().opened),
        )
        .unwrap()
    };
    assert_eq!(terminal_opened, 2);
    assert_eq!(state.sessions().opened, 2);
    assert_eq!(context.drain.source().remaining(), 0);
    assert!(diagnostics.is_empty());
    assert_eq!(
        context.stdout.len(),
        emitted,
        "terminal remainder is not output past the limit"
    );
}

#[test]
fn capture_tick_snapshots_reduced_state_before_retained_check_failure() {
    let plan = open_plan();
    let mut state = semantics::State::new(&plan);
    let mut tracker = tracker();
    let mut malformed_records = 0;
    let mut context = context(plan, [open_event(11)]);
    let observed_opened = std::cell::Cell::new(0);
    let error = {
        let mut scheduling = SchedulingAccumulator::default();
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: None,
            malformed_records: &mut malformed_records,
            scheduling: &mut scheduling,
            stop_quiescence: Default::default(),
        };
        capture_tick_with(
            &mut context,
            &mut consumers,
            |context: &mut TickContext, _| Ok((false, false, &context.plan)),
            |_| Ok(None),
            |context, consumers| {
                drain_tick(context, consumers)?;
                Ok(None)
            },
            |_, consumers| {
                observed_opened.set(consumers.state.sessions().opened);
                Ok(())
            },
            |_| Err(anyhow::anyhow!("distinct retained check failure")),
        )
        .unwrap_err()
    };

    assert_eq!(observed_opened.get(), 1);
    assert_eq!(error.to_string(), "distinct retained check failure");
}

#[test]
fn capture_tick_short_circuits_end_and_errors_after_required_sync() {
    let empty = crate::plan::AttachPlan::from_slots(vec![]);
    let plan = open_plan();
    let event = open_event(11);

    for (failure, expected) in [
        ("discovery", vec!["discovery"]),
        ("end", vec!["discovery", "end"]),
        ("drain", vec!["discovery", "end", "drain"]),
    ] {
        let mut state = semantics::State::new(&empty);
        let mut tracker = tracker();
        let mut tracer = trace::Tracer::new(&empty);
        let mut malformed_records = 0;
        let mut context = context(plan.clone(), [event]);
        let phases = std::cell::RefCell::new(Vec::new());
        let result = {
            let mut scheduling = SchedulingAccumulator::default();
            let mut consumers = CaptureConsumers {
                state: &mut state,
                tracker: &mut tracker,
                tracer: Some(&mut tracer),
                malformed_records: &mut malformed_records,
                scheduling: &mut scheduling,
                stop_quiescence: Default::default(),
            };
            capture_tick_with(
                &mut context,
                &mut consumers,
                |context: &mut TickContext, _| {
                    phases.borrow_mut().push("discovery");
                    if failure == "discovery" {
                        Err(anyhow::anyhow!("discovery failure"))
                    } else {
                        Ok((true, false, &context.plan))
                    }
                },
                |_| {
                    phases.borrow_mut().push("end");
                    if failure == "end" {
                        Err(anyhow::anyhow!("end failure"))
                    } else {
                        Ok(None)
                    }
                },
                |_, _| {
                    phases.borrow_mut().push("drain");
                    Err(anyhow::anyhow!("drain failure"))
                },
                |_, _| {
                    phases.borrow_mut().push("snapshot");
                    Ok(())
                },
                |_| {
                    phases.borrow_mut().push("check");
                    Ok(())
                },
            )
        };
        assert!(result.is_err());
        assert_eq!(*phases.borrow(), expected);
        if failure != "discovery" {
            let line = tracer.on_event(&event, &mut state);
            assert!(
                line.contains(" C_OpenSession "),
                "consumer sync must precede {failure}"
            );
            assert_eq!(state.sessions().opened, 1);
        }
    }

    let mut state = semantics::State::new(&empty);
    let mut tracker = tracker();
    let mut tracer = trace::Tracer::new(&empty);
    let mut malformed_records = 0;
    let mut context = context(plan, []);
    let later_phase = std::cell::Cell::new(false);
    let result = {
        let mut scheduling = SchedulingAccumulator::default();
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: Some(&mut tracer),
            malformed_records: &mut malformed_records,
            scheduling: &mut scheduling,
            stop_quiescence: Default::default(),
        };
        capture_tick_with(
            &mut context,
            &mut consumers,
            |context: &mut TickContext, _| Ok((true, true, &context.plan)),
            |_| Ok(Some(CaptureEnd::Signal)),
            |_, _| {
                later_phase.set(true);
                Ok(None)
            },
            |_, _| {
                later_phase.set(true);
                Ok(())
            },
            |_| {
                later_phase.set(true);
                Ok(())
            },
        )
        .unwrap()
    };
    assert!(matches!(result, CaptureTick::End(CaptureEnd::Signal)));
    assert!(!later_phase.get());
    let line = tracer.on_event(&event, &mut state);
    assert!(line.contains(" C_OpenSession "));
    assert_eq!(state.sessions().opened, 1);
}

/// E04 correctness gate: a cancelled root tail abandons only the optional
/// retirement, carrying the exact unconsumed backlog and the per-poll
/// malformed delta — no retirement token, no silent loss.
#[test]
fn root_tail_cancellation_abandons_backlog_with_exact_malformed_delta() {
    let domain = crate::events::EventsDomain::test_standin(71);
    let tail = crate::events::OwnedRootTail::new(
        OriginalRootExit::test_reaped(domain.clone()),
        Instant::now() + Duration::from_secs(1),
    );
    let mut drain = EventDrain::over_domain(
        crate::events::root_fence_tests::source([root_event(0, pkcs11_types::CkRv::OK.0)]),
        domain,
    );
    let signals = SignalState::new();
    signals.observe(libc::SIGTERM);
    let reduced = std::cell::Cell::new(0);
    let outcome = drain_original_root_events_from(&mut drain, tail, &signals, |_, _| {
        reduced.set(reduced.get() + 1);
        Ok(())
    })
    .unwrap();
    match outcome {
        OriginalRootDrain::Cancelled {
            malformed,
            remaining,
        } => {
            assert_eq!(reduced.get(), 0);
            assert_eq!(malformed, 0);
            assert_eq!(remaining, 8, "the one snapshot record stays backlog");
            assert_eq!(drain.take_malformed_delta(), 0);
        }
        _ => panic!("a pre-cancelled tail must abandon, not complete or vanish"),
    }
}

#[test]
fn stop_requests_the_gate_before_any_detach() {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    struct FakeGate {
        phases: Rc<RefCell<Vec<&'static str>>>,
        polls: Cell<u32>,
    }

    impl StopGateLike for FakeGate {
        fn request_stop(&self) {
            self.phases.borrow_mut().push("request_stop");
        }
        fn quiescent(&self) -> bool {
            self.phases.borrow_mut().push("quiesce_poll");
            self.polls.set(self.polls.get() + 1);
            true
        }
    }

    let shared = Rc::new(RefCell::new(Vec::new()));
    let gate = FakeGate {
        phases: Rc::clone(&shared),
        polls: Cell::new(0),
    };
    // The production terminal wiring: request the stop and poll for
    // quiescence first, servicing drains between polls ...
    let at = Instant::now();
    let state = quiesce_with(
        &gate,
        Duration::from_secs(5),
        || shared.borrow_mut().push("service"),
        || at,
    );
    // ... then settle, drain, snapshot, publish, and only then detach.
    let mut phases = shared.take();
    let result = finish_capture_with(
        &mut phases,
        Ok(CaptureEnd::DurationExpired),
        |phases| phases.push("gap"),
        |phases, result| {
            phases.push("settle");
            result
        },
        |phases| {
            phases.push("detach");
            Ok(())
        },
        |phases, _end, _detached| {
            phases.push("drain");
            phases.push("snapshot");
            phases.push("publish");
            Ok(7)
        },
    );
    assert_eq!(result.unwrap(), 7);
    assert_eq!(
        phases,
        [
            "request_stop",
            "quiesce_poll",
            "settle",
            "drain",
            "snapshot",
            "publish",
            "detach"
        ]
    );
    assert!(matches!(state, StopState::Quiesced { at: q } if q == at));
    assert_eq!(gate.polls.get(), 1);
}

#[test]
fn quiesce_reports_unproven_when_in_flight_never_drains() {
    use std::cell::Cell;

    struct NeverQuiescent {
        polls: Cell<u32>,
    }

    impl StopGateLike for NeverQuiescent {
        fn request_stop(&self) {}
        fn quiescent(&self) -> bool {
            self.polls.set(self.polls.get() + 1);
            false
        }
    }

    let gate = NeverQuiescent {
        polls: Cell::new(0),
    };
    let t0 = Instant::now();
    let mut tick = 0u32;
    let mut services = 0u32;
    let state = quiesce_with(
        &gate,
        Duration::from_secs(5),
        || services += 1,
        || {
            let now = t0 + Duration::from_secs(u64::from(tick));
            tick += 1;
            now
        },
    );
    match state {
        StopState::QuiescenceUnproven { waited } => {
            assert!(waited >= Duration::from_secs(5), "waited {waited:?}")
        }
        other => panic!("expected QuiescenceUnproven, got {other:?}"),
    }
    assert!(
        services >= 1,
        "the budget window must service drains, got {services}"
    );
    assert!(gate.polls.get() >= 1);
    // The unproven report keeps today's unproven marker, split by story.
    let mut clean = crate::render::tests::evidence();
    clean.completeness = "COMPLETE";
    clean.mark_terminal_drain_unproven();
    assert_eq!(clean.completeness, "PARTIAL");
    assert_eq!(
        clean.verdict_detail,
        crate::render::VERDICT_CLEAN_BUT_UNPROVEN
    );
    let mut gap = crate::render::tests::evidence();
    gap.mark_terminal_drain_unproven();
    assert_eq!(gap.completeness, "PARTIAL");
    assert_eq!(gap.verdict_detail, crate::render::VERDICT_CONCRETE_GAP);
}

#[test]
fn quiesced_drain_reads_to_the_positions_observed_at_q() {
    use crate::events::{BoundedRecordSource as _, ScriptedRecords};
    use std::ops::ControlFlow;

    for post_q_write in [false, true] {
        let mut script = ScriptedRecords::events([open_event(1), open_event(2)], usize::MAX);
        let q = script.positions().producer;
        if post_q_write {
            script.push_event(&open_event(3));
        }
        let mut drain = EventDrain::over_test_domain(script, 1);
        let mut seen = 0;
        let (post_q_record, backlog) = crate::events::poll_events_to_position(
            &mut drain,
            q,
            Some(crate::events::TERMINAL_DRAIN_BOUND),
            |_| {
                seen += 1;
                ControlFlow::Continue(())
            },
        )
        .unwrap();
        assert_eq!(seen, 2, "post_q_write={post_q_write}");
        assert_eq!(post_q_record, post_q_write, "post_q_write={post_q_write}");
        assert!(!backlog, "post_q_write={post_q_write}");
        assert_eq!(
            drain.source().remaining(),
            usize::from(post_q_write),
            "post_q_write={post_q_write}"
        );
    }
}

fn discovery_bytes(pid: u32) -> Vec<u8> {
    // SAFETY: repr(C) integer-only wire record, including zeroed reserved bytes.
    let mut record: p11scope_ebpf_common::DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = p11scope_ebpf_common::DISCOVERY_KIND_LEADER_EXIT;
    record.pid_tgid = u64::from(pid) << 32;
    unsafe {
        std::slice::from_raw_parts(
            (&record as *const p11scope_ebpf_common::DiscoveryRecord).cast::<u8>(),
            std::mem::size_of::<p11scope_ebpf_common::DiscoveryRecord>(),
        )
        .to_vec()
    }
}

#[test]
fn quiesced_discovery_drain_reads_to_the_positions_observed_at_q() {
    use crate::events::{BoundedRecordSource as _, DiscoveryDrain, DiscoveryItem};
    use std::ops::ControlFlow;

    for post_q_write in [false, true] {
        let mut script =
            ScriptedRecords::records([discovery_bytes(11), discovery_bytes(12)], usize::MAX);
        let q = script.positions().producer;
        if post_q_write {
            // Content is unread: the drain stops at Q with this still
            // queued, and only the moved producer position matters.
            script.push_event(&open_event(3));
        }
        let mut drain = DiscoveryDrain::over(script);
        let mut seen = 0;
        let (post_q_record, backlog) = crate::events::poll_discovery_to_position(
            &mut drain,
            q,
            Some(crate::events::TERMINAL_DRAIN_BOUND),
            |item| {
                assert!(matches!(item, DiscoveryItem::Record(_)));
                seen += 1;
                ControlFlow::Continue(())
            },
        )
        .unwrap();
        assert_eq!(seen, 2, "post_q_write={post_q_write}");
        assert_eq!(post_q_record, post_q_write, "post_q_write={post_q_write}");
        assert!(!backlog, "post_q_write={post_q_write}");
        assert_eq!(
            drain.source().remaining(),
            usize::from(post_q_write),
            "post_q_write={post_q_write}"
        );
    }
}

/// A bounded source past its stop: every read fails the way Aya fails
/// when the consumer already stands past the boundary (`crossed`) or the
/// boundary itself is unusable (`!crossed`, a genuine bug).
struct FailingBoundedSource {
    crossed: bool,
}

impl crate::events::RecordSource for FailingBoundedSource {
    fn next_record(&mut self) -> Option<impl std::ops::Deref<Target = [u8]> + '_> {
        None::<&[u8]>
    }
}

impl crate::events::BoundedRecordSource for FailingBoundedSource {
    fn positions(&self) -> aya::maps::ring_buf::RingBufPositions {
        aya::maps::ring_buf::RingBufPositions {
            consumer: 16,
            producer: 16,
            capacity: 4096,
        }
    }
    fn consumer(&self) -> usize {
        16
    }
    fn bounded_record(
        &mut self,
        stop: usize,
    ) -> Result<crate::events::BoundedRecord<impl std::ops::Deref<Target = [u8]> + '_>> {
        if stop == usize::MAX {
            // Unreachable: names the hidden item type for the always-failing body.
            return Ok(crate::events::BoundedRecord::Item(&[][..]));
        }
        Err(if self.crossed {
            aya::maps::ring_buf::RingBufBoundaryError::BoundaryOutOfRange {
                consumer: 16,
                stop: 8,
                capacity: 4096,
                distance: usize::MAX - 7,
            }
        } else {
            aya::maps::ring_buf::RingBufBoundaryError::InvalidBoundary {
                consumer: 16,
                stop: 9,
                capacity: 4096,
            }
        }
        .into())
    }
}

#[test]
fn bounded_drain_maps_a_crossed_stop_to_post_q_record() {
    use std::ops::ControlFlow;

    for crossed in [true, false] {
        let source = FailingBoundedSource { crossed };
        let mut events_drain = EventDrain::over_test_domain(source, 1);
        let events = crate::events::poll_events_to_position(&mut events_drain, 8, Some(64), |_| {
            ControlFlow::Continue(())
        });
        let source = FailingBoundedSource { crossed };
        let mut discovery_drain = crate::events::DiscoveryDrain::over(source);
        let discovery =
            crate::events::poll_discovery_to_position(&mut discovery_drain, 8, Some(64), |_| {
                ControlFlow::Continue(())
            });
        if crossed {
            // The consumer stands past the stop, so records past Q existed:
            // the post-Q violation, not a drain failure.
            assert_eq!(events.unwrap(), (true, false));
            assert_eq!(discovery.unwrap(), (true, false));
        } else {
            // A misaligned boundary is a bug, never a post-Q write.
            assert!(
                events
                    .unwrap_err()
                    .to_string()
                    .contains("invalid ring buffer boundary")
            );
            assert!(
                discovery
                    .unwrap_err()
                    .to_string()
                    .contains("invalid ring buffer boundary")
            );
        }
    }
}

/// I2: a BUSY (uncommitted) record below the Q stop is the ungated-writer
/// signature: the proven-Q drains must surface it as a named violation,
/// not report clean. The scripted source yields Pending exactly when its
/// queue runs dry below stop, like the ring reader facing BUSY; the stop
/// one record past the script is the producer position Q recorded. The
/// committed record ahead of BUSY still reaches the callback, and the
/// error carries the unread span so nothing is silently lost.
#[test]
fn quiesced_drain_names_a_busy_record_below_q() {
    use crate::events::{BoundedRecordSource as _, DiscoveryDrain, DiscoveryItem};
    use std::ops::ControlFlow;

    let events_script = ScriptedRecords::events([open_event(1)], usize::MAX);
    let events_q = events_script.positions().producer + 8;
    let mut events_drain = EventDrain::over_test_domain(events_script, 1);
    let mut events_seen = 0;
    let events = crate::events::poll_events_to_position(
        &mut events_drain,
        events_q,
        Some(crate::events::TERMINAL_DRAIN_BOUND),
        |_| {
            events_seen += 1;
            ControlFlow::Continue(())
        },
    );
    let discovery_script = ScriptedRecords::records([discovery_bytes(11)], usize::MAX);
    let discovery_q = discovery_script.positions().producer + 8;
    let mut discovery_drain = DiscoveryDrain::over(discovery_script);
    let mut discovery_seen = 0;
    let discovery = crate::events::poll_discovery_to_position(
        &mut discovery_drain,
        discovery_q,
        Some(crate::events::TERMINAL_DRAIN_BOUND),
        |item| {
            assert!(matches!(item, DiscoveryItem::Record(_)));
            discovery_seen += 1;
            ControlFlow::Continue(())
        },
    );
    for (site, result) in [("events", events), ("discovery", discovery)] {
        let message = result.unwrap_err().to_string();
        assert!(
            message.contains("ungated writer before Q"),
            "{site}: expected the named violation, got: {message}"
        );
        assert!(
            message.contains("consumer 8") && message.contains("stop 16"),
            "{site}: the unread span must be accounted, got: {message}"
        );
    }
    assert_eq!(
        events_seen, 1,
        "the committed record ahead of BUSY is still delivered"
    );
    assert_eq!(
        discovery_seen, 1,
        "the committed record ahead of BUSY is still delivered"
    );
}

/// A bounded source standing exactly at its stop that still reports
/// Pending: impossible from the ring reader (it reports Reached first),
/// pinned here so the at-Q boundary keeps its clean meaning.
struct PendingAtStop;

impl crate::events::RecordSource for PendingAtStop {
    fn next_record(&mut self) -> Option<impl std::ops::Deref<Target = [u8]> + '_> {
        None::<&[u8]>
    }
}

impl crate::events::BoundedRecordSource for PendingAtStop {
    fn positions(&self) -> aya::maps::ring_buf::RingBufPositions {
        aya::maps::ring_buf::RingBufPositions {
            consumer: 16,
            producer: 16,
            capacity: 4096,
        }
    }
    fn consumer(&self) -> usize {
        16
    }
    fn bounded_record(
        &mut self,
        stop: usize,
    ) -> Result<crate::events::BoundedRecord<impl std::ops::Deref<Target = [u8]> + '_>> {
        if stop == usize::MAX {
            // Unreachable: names the hidden item type for the always-pending body.
            return Ok(crate::events::BoundedRecord::Item(&[][..]));
        }
        assert_eq!(stop, 16);
        Ok(crate::events::BoundedRecord::Pending)
    }
}

#[test]
fn quiesced_drain_at_q_pending_stays_clean() {
    use std::ops::ControlFlow;

    let mut events_drain = EventDrain::over_test_domain(PendingAtStop, 1);
    assert_eq!(
        crate::events::poll_events_to_position(&mut events_drain, 16, Some(64), |_| {
            ControlFlow::Continue(())
        })
        .unwrap(),
        (false, false)
    );
    let mut discovery_drain = crate::events::DiscoveryDrain::over(PendingAtStop);
    assert_eq!(
        crate::events::poll_discovery_to_position(&mut discovery_drain, 16, Some(64), |_| {
            ControlFlow::Continue(())
        })
        .unwrap(),
        (false, false)
    );
}

#[test]
fn quiesced_profile_drain_reduces_pre_q_events_and_excludes_post_q_writes() {
    use crate::events::BoundedRecordSource as _;

    let domain = crate::events::EventsDomain::test_standin(7);
    let plan = open_plan();
    let fresh = || {
        (
            semantics::State::for_capture(
                &plan,
                crate::attach::CapturePolicy::Allowlisted,
                domain.clone(),
            ),
            process::Tracker::for_producer(domain.clone(), 16),
        )
    };
    // Baseline: the unbounded drain of the two pre-Q events.
    let (mut base_state, mut base_tracker) = fresh();
    let mut base_drain = EventDrain::over_test_domain(
        ScriptedRecords::events([open_event(1), open_event(2)], usize::MAX),
        1,
    );
    drain_profile_events(
        &mut base_drain,
        &mut base_state,
        &mut base_tracker,
        &Scope::Pid(7),
        None,
    )
    .unwrap();
    let baseline = (
        base_state.sessions().opened,
        base_state.sessions().closed,
        base_state.pending_at_end(),
    );
    for post_q_write in [false, true] {
        let (mut state, mut tracker) = fresh();
        let mut script = ScriptedRecords::events([open_event(1), open_event(2)], usize::MAX);
        let q = script.positions().producer;
        if post_q_write {
            script.push_event(&open_event(3));
        }
        let mut drain = EventDrain::over_test_domain(script, 1);
        let (malformed, post_q_record) = drain_profile_events_to_position(
            &mut drain,
            q,
            &mut state,
            &mut tracker,
            &Scope::Pid(7),
        )
        .unwrap();
        assert_eq!(malformed, 0, "post_q_write={post_q_write}");
        assert_eq!(post_q_record, post_q_write, "post_q_write={post_q_write}");
        // Exactly the pre-Q reduction, with the post-Q write excluded from
        // semantics and left queued.
        assert_eq!(
            (
                state.sessions().opened,
                state.sessions().closed,
                state.pending_at_end()
            ),
            baseline,
            "post_q_write={post_q_write}"
        );
        assert_eq!(
            drain.source().remaining(),
            usize::from(post_q_write),
            "post_q_write={post_q_write}"
        );
    }
}

/// SG-T7B (owner ruling B) regression: an injected post-Q write on either
/// ring, routed exactly as the terminal drains route it, keeps a clean
/// terminal document PARTIAL; the same drain without the write proves
/// the drain and the document is COMPLETE.
#[test]
#[cfg(target_arch = "x86_64")] // the drain proof applies on x86_64 only
fn an_injected_post_q_write_keeps_the_terminal_document_partial() {
    use crate::events::{BoundedRecordSource as _, DiscoveryDrain};
    use std::ops::ControlFlow;

    let domain = crate::events::EventsDomain::test_standin(7);
    let plan = open_plan();
    for (ring, post_q_write) in [
        ("EVENTS", false),
        ("EVENTS", true),
        ("DISCOVERY", false),
        ("DISCOVERY", true),
    ] {
        let mut stop = stop_quiescence_for(StopState::Quiesced { at: Instant::now() });
        if ring == "EVENTS" {
            let mut state = semantics::State::for_capture(
                &plan,
                crate::attach::CapturePolicy::Allowlisted,
                domain.clone(),
            );
            let mut tracker = process::Tracker::for_producer(domain.clone(), 16);
            let mut script = ScriptedRecords::events([open_event(1)], usize::MAX);
            let q = script.positions().producer;
            if post_q_write {
                script.push_event(&open_event(2));
            }
            let mut drain = EventDrain::over_test_domain(script, 1);
            let (_, post_q) = drain_profile_events_to_position(
                &mut drain,
                q,
                &mut state,
                &mut tracker,
                &Scope::Pid(7),
            )
            .unwrap();
            note_post_q_record(&mut stop.post_q_events, ring, post_q);
        } else {
            let mut script = ScriptedRecords::records([discovery_bytes(11)], usize::MAX);
            let q = script.positions().producer;
            if post_q_write {
                // Only the moved producer position matters past Q.
                script.push_event(&open_event(2));
            }
            let mut drain = DiscoveryDrain::over(script);
            let (post_q, backlog) = crate::events::poll_discovery_to_position(
                &mut drain,
                q,
                Some(crate::events::TERMINAL_DRAIN_BOUND),
                |_| ControlFlow::Continue(()),
            )
            .unwrap();
            assert!(!backlog);
            note_post_q_record(&mut stop.post_q_discovery, ring, post_q);
        }
        let mut ev = crate::render::tests::evidence();
        ev.apply_stop_quiescence(stop);
        ev.settle_terminal(true);
        let case = format!("{ring} post_q_write={post_q_write}");
        assert_eq!(ev.drain_proven, !post_q_write, "{case}");
        assert_eq!(
            ev.completeness,
            if post_q_write { "PARTIAL" } else { "COMPLETE" },
            "{case}"
        );
        let value = crate::render::versioned_evidence(&ev);
        let flag = if ring == "EVENTS" {
            "post_q_events"
        } else {
            "post_q_discovery"
        };
        assert_eq!(value["stop_quiescence"][flag], post_q_write, "{case}");
    }
}

/// Only a proven Q starts a terminal drain proof; the post-Q flags are
/// sticky once a ring crossed.
#[test]
fn stop_quiescence_maps_only_a_proven_q_and_keeps_post_q_flags_sticky() {
    use crate::render::QuiescenceState;
    assert_eq!(
        stop_quiescence_for(StopState::Quiesced { at: Instant::now() }).state,
        QuiescenceState::Proven
    );
    assert_eq!(
        stop_quiescence_for(StopState::QuiescenceUnproven {
            waited: Duration::from_secs(5)
        })
        .state,
        QuiescenceState::Unproven
    );
    for state in [StopState::Running, StopState::StopRequested] {
        assert_eq!(
            stop_quiescence_for(state).state,
            QuiescenceState::NotReached
        );
    }
    let mut flag = false;
    note_post_q_record(&mut flag, "EVENTS", true);
    note_post_q_record(&mut flag, "EVENTS", false);
    assert!(flag, "a later clean quantum must not clear the flag");
}
/// Task 3 Stage A privacy: the private entry IP and the continuity stamps
/// travel in every `EVENTS` record but must never reach any rendered output.
/// The tail is dropped at decode; this pins that the trace path, fed whole
/// records with sentinel continuity, renders none of it.
#[test]
fn instance_entry_ip_and_stamps_never_reach_trace_rendering() {
    const IP: u64 = 0x7E5C_A1AB_1E5E_C0DE;
    const EPOCH: u32 = 0x5EC1_7A11;
    const GLOBAL: u32 = 0x6A0B_A15E;
    const FAULT: u32 = 0x7AFF_0FF1;
    let stamp = p11scope_ebpf_common::InstanceStamp {
        epoch: EPOCH,
        global: GLOBAL,
        fault: FAULT,
        file_slot_plus1: 0x3A5D,
        flags: p11scope_ebpf_common::instance::STAMP_VALID,
    };
    let record = p11scope_ebpf_common::EventRecord {
        event: canary_event(),
        continuity: p11scope_ebpf_common::InstanceContinuity {
            entry_ip: IP,
            entry_stamp: stamp,
            return_stamp: stamp,
        },
    };
    let plan = open_plan();
    let mut state = semantics::State::new(&plan);
    let mut tracker = tracker();
    let mut tracer = canary_tracer(&plan);
    let mut malformed_records = 0;
    let mut context = context(plan, []);
    context.out_file = Some(Vec::new());
    context.drain = EventDrain::over_test_domain(
        ScriptedRecords::records([crate::events::record_bytes(&record)], usize::MAX),
        1,
    );
    {
        let mut scheduling = SchedulingAccumulator::default();
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: Some(&mut tracer),
            malformed_records: &mut malformed_records,
            scheduling: &mut scheduling,
            stop_quiescence: Default::default(),
        };
        capture_tick_with(
            &mut context,
            &mut consumers,
            |context: &mut TickContext, _| Ok((true, true, &context.plan)),
            |_| Ok(None),
            |context, consumers| {
                drain_tick(context, consumers)?;
                Ok(None)
            },
            |_, consumers| Ok(consumers.state.sessions().opened),
            |_| Ok(()),
        )
        .unwrap();
    }
    assert_eq!(malformed_records, 0);
    assert_eq!(state.sessions().opened, 1, "the record was reduced");
    let rendered = String::from_utf8_lossy(&context.stdout);
    assert!(
        rendered.to_ascii_lowercase().contains(" c_opensession "),
        "the call was rendered"
    );
    // Task 1c: the shared exact-offset canary replaces the ad-hoc word
    // loop, and the mirrored trace file is scanned as its own surface.
    let canary = continuity_canary::ContinuityCanary::from_continuity(&record.continuity);
    canary.assert_clean(&context.stdout, "trace stdout");
    canary.assert_clean(
        context.out_file.as_deref().unwrap_or_default(),
        "trace file",
    );
}

// --- Task 1c Stage A privacy evidence -----------------------------------
// The addendum requires, before activation: (1) an exact-offset canary
// scanner for the entry IP and stamps in the EVENTS tail and
// INSTANCE_START, with must-detect positive controls in public outputs;
// (2) a sentinel regression proving renderers never receive the tail.
// The scanner is the nested `continuity_canary` module below; these tests plant
// recognizable sentinel continuity values through the real capture ->
// reduce -> render path and scan every public surface.
/// The Task 1c exact-offset canary scanner, nested here (rather than in
/// its own file) so the `instance_entry_ip_and_stamps_have_no_rendering_`
/// `consumers` contract keeps its exact four-file user list: this test
/// module is already an allowed reader of the private continuity fields,
/// and no new file gains that power.
///
/// The reusable check behind the Stage A privacy evidence: it takes the
/// ACTUAL private continuity bytes — the `u64` entry IP plus the 16-byte
/// `{epoch, global, fault, file slot, flags}` stamps exactly as laid out
/// in the `EventRecord` tail (`InstanceContinuity`) and in
/// `INSTANCE_START` (`InstanceEntry`) — and searches any public output
/// surface for them.
///
/// Every form a renderer could emit is covered, for full words and for
/// 32-bit halves of the `u64` entry IP:
///
/// - raw bytes: the exact laid-out little-endian sequences — the whole
///   40-byte tail / 24-byte entry, each 16-byte stamp, the 8-byte IP and
///   every 4-byte word;
/// - hex, upper/lower/mixed case (matched case-insensitively), with and
///   without a `0x` prefix (zero-padded forms contain the unpadded
///   needle, so they match too);
/// - decimal.
///
/// The two `u16` stamp fields (file slot, flags) are covered by their
/// rendered forms plus the enclosing 16-byte stamp raw sequence; their
/// bare 2-byte sequences are NOT matched standalone because any two text
/// bytes would match them (a bare `u16` raw match cannot tell a leak
/// from prose).
mod continuity_canary {
    use p11scope_ebpf_common::{InstanceContinuity, InstanceEntry, InstanceStamp};

    const _: () = assert!(size_of::<InstanceContinuity>() == 40);
    const _: () = assert!(size_of::<InstanceEntry>() == 24);
    const _: () = assert!(size_of::<InstanceStamp>() == 16);

    /// The raw bytes of one `repr(C)` Pod value, exactly as laid out.
    pub(crate) fn struct_bytes<T>(value: &T) -> Vec<u8> {
        // SAFETY: the caller passes `repr(C)` Pod shared-transport
        // values only (the same contract `crate::events::record_bytes`
        // relies on); this reads exactly the value's bytes.
        unsafe {
            std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()).to_vec()
        }
    }

    /// One searchable form of one private word: what to look for, and
    /// how to describe a hit. `is_text` needles match
    /// case-insensitively (their bytes are stored lowercase); raw
    /// needles match byte-exact.
    pub(crate) struct Needle {
        pub description: String,
        pub bytes: Vec<u8>,
        pub is_text: bool,
    }

    /// The reusable Stage A continuity check, built from the actual
    /// private tail/entry structs fed to the capture path under test.
    pub(crate) struct ContinuityCanary {
        needles: Vec<Needle>,
    }

    impl ContinuityCanary {
        /// The scanner for an `EVENTS`-tail layout: entry IP plus the
        /// entry and return stamps.
        pub(crate) fn from_continuity(continuity: &InstanceContinuity) -> Self {
            let mut words: Vec<(String, u64, usize)> = Vec::new();
            push_u64(&mut words, "entry_ip", continuity.entry_ip);
            push_stamp(&mut words, "entry_stamp", &continuity.entry_stamp);
            push_stamp(&mut words, "return_stamp", &continuity.return_stamp);
            let mut raw: Vec<(String, Vec<u8>)> = vec![
                (
                    "the 40-byte EVENTS tail as laid out".to_string(),
                    struct_bytes(continuity),
                ),
                (
                    "the 16-byte entry stamp as laid out".to_string(),
                    struct_bytes(&continuity.entry_stamp),
                ),
                (
                    "the 16-byte return stamp as laid out".to_string(),
                    struct_bytes(&continuity.return_stamp),
                ),
            ];
            raw.push((
                "the 8-byte entry IP as laid out".to_string(),
                continuity.entry_ip.to_le_bytes().to_vec(),
            ));
            Self::build(words, raw)
        }

        /// The scanner for an `INSTANCE_START`-value layout: entry IP
        /// plus the single entry stamp.
        pub(crate) fn from_entry(entry: &InstanceEntry) -> Self {
            let mut words: Vec<(String, u64, usize)> = Vec::new();
            push_u64(&mut words, "entry_ip", entry.entry_ip);
            push_stamp(&mut words, "entry_stamp", &entry.entry_stamp);
            let raw: Vec<(String, Vec<u8>)> = vec![
                (
                    "the 24-byte INSTANCE_START value as laid out".to_string(),
                    struct_bytes(entry),
                ),
                (
                    "the 16-byte entry stamp as laid out".to_string(),
                    struct_bytes(&entry.entry_stamp),
                ),
                (
                    "the 8-byte entry IP as laid out".to_string(),
                    entry.entry_ip.to_le_bytes().to_vec(),
                ),
            ];
            Self::build(words, raw)
        }

        fn build(words: Vec<(String, u64, usize)>, raw: Vec<(String, Vec<u8>)>) -> Self {
            let mut needles: Vec<Needle> = Vec::new();
            for (name, value, width) in &words {
                // Rendered forms for every word, whatever its width.
                for (form, text) in [
                    ("hex", format!("{value:x}")),
                    ("0x-prefixed hex", format!("0x{value:x}")),
                    ("decimal", value.to_string()),
                ] {
                    push_needle(
                        &mut needles,
                        format!("{name} {form} {text}"),
                        text.into_bytes(),
                        true,
                    );
                }
                // Raw little-endian bytes for 4- and 8-byte words only;
                // see the module docs for why bare 2-byte matches are
                // excluded.
                if *width == 8 {
                    push_needle(
                        &mut needles,
                        format!("{name} raw LE bytes"),
                        value.to_le_bytes().to_vec(),
                        false,
                    );
                } else if *width == 4 {
                    push_needle(
                        &mut needles,
                        format!("{name} raw LE bytes"),
                        (*value as u32).to_le_bytes().to_vec(),
                        false,
                    );
                }
            }
            for (description, bytes) in raw {
                push_needle(&mut needles, description, bytes, false);
            }
            Self { needles }
        }

        /// Every searchable form, for must-detect positive controls:
        /// plant each into a public output and assert [`Self::hits_in`]
        /// flags it. Text needles are stored lowercase; uppercasing them
        /// before planting must still flag (case-insensitive match).
        pub(crate) fn needles(&self) -> &[Needle] {
            &self.needles
        }

        /// Descriptions of every canary form found in `output`; empty
        /// when the surface is clean.
        pub(crate) fn hits_in(&self, output: &[u8]) -> Vec<String> {
            let lowered = output.to_ascii_lowercase();
            let mut hits = Vec::new();
            for needle in &self.needles {
                let haystack = if needle.is_text { &lowered } else { output };
                if haystack
                    .windows(needle.bytes.len())
                    .any(|window| window == needle.bytes.as_slice())
                {
                    hits.push(needle.description.clone());
                }
            }
            hits
        }

        /// Panics when `output` carries any canary form, naming the
        /// surface and the first hits; passes silently when clean.
        pub(crate) fn assert_clean(&self, output: &[u8], surface: &str) {
            let hits = self.hits_in(output);
            assert!(
                hits.is_empty(),
                "Stage A privacy: {surface} leaked {} continuity canary form(s): {}",
                hits.len(),
                hits.iter().take(5).cloned().collect::<Vec<_>>().join("; "),
            );
        }
    }

    /// One `u64` word plus its 32-bit halves.
    fn push_u64(words: &mut Vec<(String, u64, usize)>, name: &str, value: u64) {
        words.push((name.to_string(), value, 8));
        words.push((format!("{name} high half"), value >> 32, 4));
        words.push((format!("{name} low half"), value & 0xffff_ffff, 4));
    }

    /// One 16-byte `{epoch, global, fault, file slot, flags}` stamp.
    fn push_stamp(words: &mut Vec<(String, u64, usize)>, name: &str, stamp: &InstanceStamp) {
        words.push((format!("{name} epoch"), u64::from(stamp.epoch), 4));
        words.push((format!("{name} global"), u64::from(stamp.global), 4));
        words.push((format!("{name} fault"), u64::from(stamp.fault), 4));
        words.push((
            format!("{name} file slot"),
            u64::from(stamp.file_slot_plus1),
            2,
        ));
        words.push((format!("{name} flags"), u64::from(stamp.flags), 2));
    }

    /// Adds a needle unless an identical one is already present (the
    /// entry and return stamps share flag values, for example).
    fn push_needle(needles: &mut Vec<Needle>, description: String, bytes: Vec<u8>, is_text: bool) {
        if needles
            .iter()
            .any(|needle| needle.bytes == bytes && needle.is_text == is_text)
        {
            return;
        }
        needles.push(Needle {
            description,
            bytes,
            is_text,
        });
    }
}

use continuity_canary::{ContinuityCanary, struct_bytes};

// Public canary input is fixed, independently of the observer's clock/PID.
// The scripted EVENTS domain supplies CALL history, not native PID authority.
const CANARY_PID: u32 = 4242;
const CANARY_MONO_NS: u64 = 1100;

fn canary_event() -> Event {
    Event {
        ts_ns: CANARY_MONO_NS,
        pid_tgid: u64::from(CANARY_PID) << 32,
        ..open_event(11)
    }
}

fn canary_tracer(plan: &crate::plan::AttachPlan) -> trace::Tracer {
    trace::tracer_with_test_wall_anchor(plan, CANARY_MONO_NS, 0)
}

/// Sentinel entry IP, shared with the trace-only test above.
const CANARY_IP: u64 = 0x7E5C_A1AB_1E5E_C0DE;

fn canary_entry_stamp() -> p11scope_ebpf_common::InstanceStamp {
    p11scope_ebpf_common::InstanceStamp {
        epoch: 0x5EC1_7A11,
        global: 0x6A0B_A15E,
        fault: 0x7AFF_0FF1,
        file_slot_plus1: 0x3A5D,
        flags: p11scope_ebpf_common::instance::STAMP_VALID,
    }
}

/// A deliberately DIFFERENT return stamp (a mid-call mutation is
/// realistic) so the scanner's return-stamp forms get distinct values.
fn canary_return_stamp() -> p11scope_ebpf_common::InstanceStamp {
    p11scope_ebpf_common::InstanceStamp {
        epoch: 0x9A2B_44D1,
        global: 0xB3C5_55E2,
        fault: 0xC4D6_66F3,
        file_slot_plus1: 0x5B7E,
        flags: p11scope_ebpf_common::instance::STAMP_VALID,
    }
}

fn canary_continuity() -> p11scope_ebpf_common::InstanceContinuity {
    p11scope_ebpf_common::InstanceContinuity {
        entry_ip: CANARY_IP,
        entry_stamp: canary_entry_stamp(),
        return_stamp: canary_return_stamp(),
    }
}

fn canary_record() -> p11scope_ebpf_common::EventRecord {
    p11scope_ebpf_common::EventRecord {
        event: canary_event(),
        continuity: canary_continuity(),
    }
}

struct TraceDrive {
    state: semantics::State,
    stdout: Vec<u8>,
    out_file: Vec<u8>,
    malformed: u64,
    scheduling: SchedulingAccumulator,
    raw_calls: u64,
}

/// The real trace capture -> reduce path, fed whole sentinel records.
fn drive_trace_capture(record: &[u8]) -> TraceDrive {
    let plan = open_plan();
    let mut state = semantics::State::new(&plan);
    let mut tracker = tracker();
    let mut tracer = canary_tracer(&plan);
    let mut malformed_records = 0;
    let mut context = context(plan, []);
    context.out_file = Some(Vec::new());
    context.drain =
        EventDrain::over_test_domain(ScriptedRecords::records([record.to_vec()], usize::MAX), 1);
    let mut scheduling = SchedulingAccumulator::default();
    {
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: Some(&mut tracer),
            malformed_records: &mut malformed_records,
            scheduling: &mut scheduling,
            stop_quiescence: Default::default(),
        };
        capture_tick_with(
            &mut context,
            &mut consumers,
            |context: &mut TickContext, _| Ok((true, true, &context.plan)),
            |_| Ok(None),
            |context, consumers| {
                drain_tick(context, consumers)?;
                Ok(None)
            },
            |_, consumers| Ok(consumers.state.sessions().opened),
            |_| Ok(()),
        )
        .unwrap();
    }
    let raw_calls = tracer.raw_calls();
    TraceDrive {
        state,
        stdout: context.stdout,
        out_file: context.out_file.unwrap_or_default(),
        malformed: malformed_records,
        scheduling,
        raw_calls,
    }
}

struct ProfileDrive {
    state: semantics::State,
    malformed: u64,
}

/// The real profile capture -> reduce path, fed whole sentinel records.
fn drive_profile_capture(record: &[u8]) -> ProfileDrive {
    let plan = open_plan();
    let mut state = semantics::State::new(&plan);
    let mut tracker = tracker();
    let mut malformed_records = 0;
    let mut context = context(plan, []);
    context.drain =
        EventDrain::over_test_domain(ScriptedRecords::records([record.to_vec()], usize::MAX), 1);
    let mut scheduling = SchedulingAccumulator::default();
    {
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: None,
            malformed_records: &mut malformed_records,
            scheduling: &mut scheduling,
            stop_quiescence: Default::default(),
        };
        capture_tick_with(
            &mut context,
            &mut consumers,
            |context: &mut TickContext, _| Ok((true, true, &context.plan)),
            |_| Ok(None),
            |context, consumers| {
                drain_tick(context, consumers)?;
                Ok(None)
            },
            |_, consumers| Ok(consumers.state.sessions().opened),
            |_| Ok(()),
        )
        .unwrap();
    }
    ProfileDrive {
        state,
        malformed: malformed_records,
    }
}

/// One aggregate row matching the reduced call, so the JSON/profile/live
/// renderers emit a non-trivial `functions` section. Aggregate rows come
/// from the BPF count maps, not from EVENTS records, so this fixture only
/// supplies output shape; the reduced semantic state is the real input
/// under test.
fn canary_reports() -> Vec<crate::metrics::SlotReport> {
    vec![crate::metrics::SlotReport {
        names: vec!["C_OpenSession".into()],
        aliased: false,
        semantic_authorized: true,
        module: Some(crate::plan::ModuleId(0)),
        module_ambiguous: false,
        module_unresolved: false,
        mode: p11scope_ebpf_common::CounterMode::Latency,
        calls: 1,
        errors: 0,
        in_flight: 0,
        total_ns: 10,
        max_ns: 10,
        buckets: [0; p11scope_ebpf_common::LATENCY_BUCKETS],
        rv_counts: std::collections::BTreeMap::from([(0u64, 1u64)]),
        file_offset: 0x10,
        target_object: None,
        ordinals: Vec::new(),
    }]
}

fn canary_capture() -> crate::render::CaptureMeta<'static> {
    crate::render::CaptureMeta {
        started: "t0",
        ended: "t1",
        kernel: "6.8.0",
        policy: crate::attach::CapturePolicy::Allowlisted,
        scope: "pid",
        caller: None,
        ring_bytes: p11scope_ebpf_common::RING_BYTES,
        drain_interval_ms: 1000,
    }
}

/// A small but non-trivial inventory presentation: one caller, one
/// module, one counted edge and one gap. Inventory renderers consume
/// `Presentation`, which carries no continuity field — the EVENTS tail
/// cannot reach them by construction — and these surfaces are scanned to
/// prove the fact on representative bytes.
fn canary_presentation() -> crate::inventory_present::Presentation {
    use crate::discovery::caller_registry::{
        AdmissionState, CallerId, CallerLifecycle, ExeIdentity, ImageAuthority, LauncherOrigin,
        MappingEvidence, MappingState, ModuleId, ModuleLifecycle, UseCoverage,
    };
    use crate::inventory_present::{
        Activity, BudgetView, CallerView, Capture, EdgeSemanticsView, EdgeView, GapView,
        ModuleView, Presence, Presentation,
    };
    Presentation {
        caller_metadata: crate::caller_metadata::runtime::MetadataFrame::default(),
        scope_label: "pid 4242".into(),
        started_ns: 1_000,
        ended_ns: 2_000,
        passes: 1,
        usage_feed: true,
        semantic_capture: crate::inventory_semantics::SemanticCaptureSummary::default(),
        native_witnesses: crate::discovery::native_binding::BindingCensus {
            rows: 0,
            bound: 0,
            unbound: std::collections::BTreeMap::new(),
            pending: 0,
            integrity: 0,
        },
        witness_placement: crate::discovery::caller_registry::WitnessPlacement {
            edge: 0,
            module: 0,
            ambiguous: 0,
            unresolved: 0,
        },
        unbound_images: 0,
        unbound_images_saturated: false,
        identity_unavailable_refused: 0,
        identity_budget_exhausted: false,
        unbound_pids: Vec::new(),
        unbound_pids_dropped: 0,
        callers: vec![CallerView {
            id: CallerId(0),
            pid: 4242,
            start_time: Some(700),
            incarnation: 0,
            exe: Some(ExeIdentity {
                dev: 8,
                ino: 90_001,
                mtime_secs: 11,
                mtime_nanos: 22,
                path: Some("/usr/bin/canary-app".into()),
            }),
            app_hint: None,
            launched_by: Vec::new(),
            launcher_gap: None,
            launched_by_origin: LauncherOrigin::Chain,
            launched_by_unit: None,
            exec_observed: false,
            authority: ImageAuthority::ScanPinned,
            lifecycle: CallerLifecycle::Mapped,
            lifecycle_reason: None,
            first_seen_ns: 1000,
            last_seen_ns: 2000,
            retired: false,
        }],
        modules: vec![ModuleView {
            id: ModuleId(0),
            paths: vec!["/opt/canary-provider.so".into()],
            device_major: 8,
            device_minor: 1,
            inode: 100_001,
            sha256: Some("ab".repeat(32)),
            build_id: Some("ccdd".into()),
            identity_source: Some("scan".into()),
            admission: AdmissionState::Admitted,
            admission_class: None,
            admission_endpoints: Some(2),
            admission_reasons: Vec::new(),
            admission_history: Vec::new(),
            lifecycle: ModuleLifecycle::Mapped,
            unloaded_observed: false,
            unbound_use: None,
            init: crate::inventory_present::ModuleInitView {
                calls: 0,
                ok: 0,
                already_initialized: 0,
                last_error_rv: None,
                status: "unknown",
                detail: "semantic lane unavailable".into(),
            },
            operator_forwarding: false,
        }],
        edges: vec![EdgeView {
            caller: CallerId(0),
            module: ModuleId(0),
            mapping: MappingState::Mapped,
            mapping_reason: None,
            mapping_evidence: MappingEvidence::DeepScan,
            mapping_first_seen_ns: 1000,
            mapping_last_seen_ns: 2000,
            mapping_interruptions: 0,
            entry_count: 4,
            entry_saturated: false,
            entry_first_seen_ns: Some(1100),
            entry_last_seen_ns: Some(1900),
            entry_in_flight: false,
            entry_observation: "observed",
            coverage: UseCoverage::Counted {
                since_ns: 1000,
                lossy: false,
                pid_exit: false,
            },
            presence: Presence::Mapped,
            capture: Capture::Armed,
            activity: Activity::RecentlyObserved,
            semantics: EdgeSemanticsView {
                label: crate::discovery::caller_registry::SEMANTIC_UNKNOWN,
                mechanisms: Vec::new(),
                operations: None,
            },
        }],
        gaps: vec![GapView {
            caller: Some(CallerId(0)),
            module: None,
            pid: Some(4242),
            subject: "canary gap".into(),
            reason: "coverage demonstration gap".into(),
            budget: None,
            repeats: 1,
        }],
        instances: Vec::new(),
        semantic_edges: Vec::new(),
        instance_reload_not_excluded: None,
        render_index: Default::default(),
        gaps_suppressed: 0,
        excluded_modules: Vec::new(),
        unmatched_excludes: Vec::new(),
        unmatched_forwarding: Vec::new(),
        object_observations: crate::key_operation_projection::ObjectObservations::unavailable(
            1,
            "bootstrap_unavailable",
        ),
        prearm: Vec::new(),
        key_operations_requested: false,
        manifests_present: false,
        budgets: BudgetView {
            callers_limit: 8,
            callers_occupied: 1,
            callers_refused: 0,
            modules_limit: 8,
            modules_occupied: 1,
            modules_refused: 0,
            edges_limit: 16,
            edges_occupied: 1,
            edges_refused: 0,
            endpoints_limit: 32,
            endpoints_occupied: 2,
            endpoints_refused: 0,
            inventory_endpoints_limit: 32,
            inventory_endpoints_occupied: 2,
            inventory_endpoints_refused: 0,
            inventory_modules_limit: 8,
            inventory_modules_occupied: 1,
            inventory_modules_refused: 0,
            counters_observed: 1,
            counters_saturated: 0,
            semantic_limit: 4,
            semantic_occupied: 0,
            semantic_unknown_edges: 1,
            semantic_refused: 0,
            instances_limit: 4096,
            instances_occupied: 0,
            instances_refused: 0,
            instance_semantic_occupied: 0,
            instance_semantic_unknown_edges: 0,
            instance_semantic_refused: 0,
            instance_negative_limit: 4096,
            instance_negative_occupied: 0,
            instance_negative_refused: 0,
            instance_negative_exhausted: false,
            instance_semantic_resources: Default::default(),
            retained_limit: 16,
            retained: 1,
            retained_suppressed: 0,
            preadmission: None,
        },
    }
}

struct RenderedSurfaces {
    surfaces: Vec<(String, Vec<u8>)>,
    trace_sessions_opened: u64,
    trace_rendered_call: bool,
    profile_sessions_opened: u64,
}

/// Renders every public output surface the addendum names — JSON, JSONL,
/// trace, profile, dashboard, logs, errors — from state reduced from
/// whole sentinel records through the real capture path.
fn render_all_surfaces() -> RenderedSurfaces {
    let record = crate::events::record_bytes(&canary_record());
    let trace = drive_trace_capture(&record);
    let profile = drive_profile_capture(&record);
    assert_eq!(trace.malformed, 0, "sentinel records decode");
    assert_eq!(profile.malformed, 0, "sentinel records decode");

    let reports = canary_reports();
    let capture = canary_capture();
    let mut evidence = crate::render::tests::evidence();
    evidence.verdict();
    let policy = crate::attach::CapturePolicy::Allowlisted;

    let mut surfaces: Vec<(String, Vec<u8>)> = Vec::new();
    let mut push = |surface: &str, output: Vec<u8>| {
        surfaces.push((surface.to_string(), output));
    };

    // Trace surfaces, straight from the driven capture.
    let trace_rendered_call = String::from_utf8_lossy(&trace.stdout)
        .to_ascii_lowercase()
        .contains(" c_opensession ");
    push("trace stdout", trace.stdout.clone());
    push("trace file", trace.out_file.clone());

    // Profile/metrics JSON and the live display, rendered from the
    // reduced semantic state.
    let profile_doc = crate::render::profile_json(
        &reports,
        crate::render::VersionedEvidence::wrap(&evidence),
        &profile.state,
        &capture,
    );
    push(
        "profile json",
        serde_json::to_string(&profile_doc).unwrap().into_bytes(),
    );
    let metrics_doc = crate::render::json(&reports, &evidence, &capture);
    push(
        "metrics json",
        serde_json::to_string(&metrics_doc).unwrap().into_bytes(),
    );
    push(
        "profile live display",
        crate::render::live(
            &reports,
            &evidence,
            std::time::Duration::from_secs(3),
            "canary-provider",
            "profile",
            policy,
        )
        .into_bytes(),
    );

    // Trace terminal/log lines.
    push(
        "trace evidence line",
        crate::trace::evidence_line(&evidence, policy).into_bytes(),
    );
    push(
        "trace count line",
        crate::trace::count_evidence_line(&reports, trace.raw_calls).into_bytes(),
    );
    push(
        "trace capture line",
        crate::trace::capture_line(policy).into_bytes(),
    );
    push(
        "trace truncated line",
        crate::trace::truncated_line(1000, true).into_bytes(),
    );
    push(
        "longrun log line",
        trace.scheduling.longrun_line(false).into_bytes(),
    );

    // Inventory surfaces: JSON, JSONL, dashboard frame, pager snapshot.
    let presentation = canary_presentation();
    let inventory_doc = crate::inventory::render_json_from_presentation(&presentation);
    push(
        "inventory json",
        serde_json::to_string(&inventory_doc).unwrap().into_bytes(),
    );
    let dir = tempfile::tempdir().unwrap();
    // The event writer only publishes under owner-writable ancestors;
    // `tempfile` honors the process umask, so pin the mode explicitly
    // and pass under any umask the gates run with.
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let path = dir.path().join("events.jsonl");
    let mut writer = crate::inventory_events::EventWriter::create(&path, 1 << 20, 5).unwrap();
    crate::inventory_events::emit_snapshot_as_events(&mut writer, &presentation, 1).unwrap();
    drop(writer);
    push("inventory jsonl", std::fs::read(&path).unwrap());
    let frame = crate::inventory_dashboard::DisplayFrame {
        presentation: std::sync::Arc::new(presentation.clone()),
        log: crate::inventory_dashboard::LogTail::bounded().snapshot(),
    };
    push(
        "inventory dashboard frame",
        crate::inventory_dashboard::render_frame(
            &frame,
            crate::inventory_dashboard::Viewport {
                width: 100,
                height: 30,
            },
            &crate::inventory_dashboard::DashboardState::new(),
        ),
    );
    push(
        "inventory pager snapshot",
        crate::inventory_present::render_snapshot(&presentation).into_bytes(),
    );

    // Error surfaces, produced with sentinel records in flight.
    push(
        "drain write error",
        failing_drain_error(&record).into_bytes(),
    );
    push(
        "bounded-drain error",
        crate::events::BoundedDrainError::UngatedWriterBeforeQ {
            consumer: 8,
            stop: 16,
        }
        .to_string()
        .into_bytes(),
    );
    push(
        "malformed lost line",
        malformed_lost_line(&record).into_bytes(),
    );

    RenderedSurfaces {
        surfaces,
        trace_sessions_opened: trace.state.sessions().opened,
        trace_rendered_call,
        profile_sessions_opened: profile.state.sessions().opened,
    }
}

/// A REAL error from the trace drain path with a sentinel record in
/// flight: the stdout writer fails, so the drain returns the write
/// error instead of rendering.
fn failing_drain_error(record: &[u8]) -> String {
    let mut drain =
        EventDrain::over_test_domain(ScriptedRecords::records([record.to_vec()], usize::MAX), 1);
    let plan = open_plan();
    let mut state = semantics::State::new(&plan);
    let mut tracker = tracker();
    let mut tracer = canary_tracer(&plan);
    let mut writer = TerminalWriter {
        fail: true,
        bytes: Vec::new(),
    };
    let mut open = true;
    let mut remaining: Option<u64> = None;
    let mut out_file: Option<TerminalWriter> = None;
    let error = drain_trace_events_from(
        &mut drain,
        &mut remaining,
        &mut state,
        &mut tracker,
        &Scope::Pid(std::process::id()),
        &mut tracer,
        &mut writer,
        &mut open,
        &mut out_file,
        Some(LIVE_POLL_QUANTUM),
    )
    .unwrap_err();
    let rendered = format!("{error:?}");
    assert!(
        rendered.contains("writing stdout"),
        "the error is the real write path: {rendered}"
    );
    rendered
}

/// A truncated sentinel record (its tail cut short) decodes to nothing:
/// the malformed path emits a count, never bytes. Returns the resulting
/// `LOST` line.
fn malformed_lost_line(record: &[u8]) -> String {
    let truncated = record[..record.len() - 8].to_vec();
    assert!(
        crate::events::decode(&truncated).is_none(),
        "a cut tail never decodes"
    );
    let mut drain =
        EventDrain::over_test_domain(ScriptedRecords::records([truncated], usize::MAX), 1);
    let plan = open_plan();
    let mut state = semantics::State::new(&plan);
    let mut tracker = tracker();
    let (malformed, _) = drain_profile_events(
        &mut drain,
        &mut state,
        &mut tracker,
        &Scope::Pid(std::process::id()),
        Some(LIVE_POLL_QUANTUM),
    )
    .unwrap();
    assert_eq!(malformed, 1, "the cut record counts as malformed");
    crate::trace::lost_line(malformed).expect("loss always gets a line")
}

/// Must-detect positive controls (R2): every surface is clean first (so
/// the controls are non-vacuous), then every needle — plus its
/// uppercase form for text needles — is planted into every surface and
/// must flag. The planted path is test-only string/byte splicing.
fn assert_must_detect(canary: &ContinuityCanary, surfaces: &[(String, Vec<u8>)]) {
    for (surface, output) in surfaces {
        assert!(
            canary.hits_in(output).is_empty(),
            "clean {surface} must pass before planting"
        );
        for needle in canary.needles() {
            let mut forms = vec![needle.bytes.clone()];
            if needle.is_text {
                let upper = needle.bytes.to_ascii_uppercase();
                if upper != needle.bytes {
                    forms.push(upper);
                }
            }
            for form in forms {
                let mut dirty = output.clone();
                let at = dirty.len() / 2;
                dirty.splice(at..at, form.iter().cloned());
                let hits = canary.hits_in(&dirty);
                assert!(
                    hits.contains(&needle.description),
                    "planted {} in {surface} was NOT flagged",
                    needle.description
                );
            }
        }
    }
}

#[test]
fn continuity_canary_public_metadata_is_deterministic() {
    let record = canary_record();
    assert_eq!(
        record.event.pid_tgid,
        4242u64 << 32,
        "a canary fixture must not depend on the ambient observer PID"
    );
    assert_eq!(record.event.ts_ns, 1100);
    let driven = drive_trace_capture(&crate::events::record_bytes(&record));
    assert!(
        driven.stdout.starts_with(
            b"00:00:00.000000 Unknown executable (PID 4242, TID 0) sess#1 C_OpenSession "
        ),
        "the actual capture/render path must use fixed canary clock and PID metadata: {}",
        String::from_utf8_lossy(&driven.stdout),
    );
    assert_eq!(driven.stdout, driven.out_file);
    let repeated = drive_trace_capture(&crate::events::record_bytes(&record));
    assert_eq!(driven.stdout, repeated.stdout, "fresh canary drives agree");
}

/// R1+R2, EVENTS-tail layout: the scanner covers every needle form, and
/// every planted control flags on every public surface.
#[test]
fn continuity_canary_flags_every_planted_form_on_every_surface() {
    let canary = ContinuityCanary::from_continuity(&canary_continuity());
    assert_eq!(
        canary.needles().len(),
        48,
        "needle coverage contract: 13 words x 3 rendered forms (minus 3 \
         flag-value dedups) + 12 raw sequences"
    );
    let rendered = render_all_surfaces();
    assert_eq!(
        rendered.surfaces.len(),
        17,
        "surface coverage contract: trace stdout/file, profile/metrics \
         json, live display, 5 trace/log lines, inventory json/jsonl/\
         dashboard/pager, 3 error surfaces"
    );
    assert_must_detect(&canary, &rendered.surfaces);
}

/// R1+R2, INSTANCE_START layout: the entry IP plus its single stamp get
/// the same must-detect treatment on every surface.
#[test]
fn instance_start_entry_canary_flags_planted_controls() {
    let entry = p11scope_ebpf_common::InstanceEntry {
        entry_ip: CANARY_IP,
        entry_stamp: canary_entry_stamp(),
    };
    let canary = ContinuityCanary::from_entry(&entry);
    assert_eq!(
        canary.needles().len(),
        32,
        "needle coverage contract: 8 words x 3 rendered forms + 8 raw sequences"
    );
    let rendered = render_all_surfaces();
    assert_must_detect(&canary, &rendered.surfaces);
}

/// R3 sentinel regression: recognizable sentinel continuity through the
/// real capture -> reduce -> render path reaches NO renderer. The
/// decoder proof pins the drop point (`decode` hands renderers a bare
/// `Event`); the end-to-end proof scans every rendered surface.
#[test]
fn instance_continuity_tail_never_reaches_any_renderer() {
    let continuity = canary_continuity();
    let canary = ContinuityCanary::from_continuity(&continuity);
    let record = p11scope_ebpf_common::EventRecord {
        event: canary_event(),
        continuity,
    };
    let bytes = crate::events::record_bytes(&record);

    // The drop point: what renderers decode carries no tail bytes.
    let event = crate::events::decode(&bytes).expect("sentinel record decodes");
    canary.assert_clean(&struct_bytes(&event), "renderer-facing bare Event");
    // Non-vacuous: the router-facing decoder sees the planted tail.
    let whole = crate::events::decode_record(&bytes).expect("whole record decodes");
    assert_eq!(whole.continuity.entry_ip, CANARY_IP, "the tail was planted");
    assert_eq!(
        whole.continuity.entry_stamp.epoch,
        canary_entry_stamp().epoch
    );
    assert_eq!(
        whole.continuity.return_stamp.epoch,
        canary_return_stamp().epoch
    );

    // End-to-end: the call was reduced and rendered, and every surface
    // rendered from it is clean.
    let rendered = render_all_surfaces();
    assert_eq!(
        rendered.trace_sessions_opened, 1,
        "trace reduced the sentinel call"
    );
    assert!(
        rendered.trace_rendered_call,
        "trace rendered the sentinel call"
    );
    assert_eq!(
        rendered.profile_sessions_opened, 1,
        "profile reduced the sentinel call"
    );
    for (surface, output) in &rendered.surfaces {
        canary.assert_clean(output, surface);
    }
}

/// Data always, generic seal order: a capture loop failure still seals
/// the report (gap, settle as an error end, publish, then detach) and the
/// error stays the outer error. `finish_capture_with` takes no pause
/// policy, so this pins the order once; the real pause paths behind the
/// loop error — the `auto` hand-back and the `always` refusal — are pinned
/// by the held-child tests in `run.rs`, and both `always_wrap` texts by
/// its wrap unit tests. The signalled wrap is asserted here once to pin
/// the seal-plus-wrap composition: the interruption is named rather than
/// claimed as a success.
#[test]
fn failed_capture_loop_still_seals_the_report_in_order() {
    let mut phases = Vec::new();
    let result = finish_capture_with(
        &mut phases,
        Err(anyhow::anyhow!("pause: pause coordination cancelled")),
        |phases| phases.push("gap"),
        |phases, result| {
            phases.push("finish");
            assert_eq!(result.as_ref().ok(), Some(&CaptureEnd::Error));
            result
        },
        |phases| {
            phases.push("detach");
            Ok(())
        },
        |phases, end, _detached| {
            assert_eq!(end, CaptureEnd::Error);
            phases.push("terminal");
            Ok(())
        },
    );
    assert_eq!(phases, ["gap", "finish", "terminal", "detach"]);
    let error = result.expect_err("the failed run still fails");
    let signals = SignalState::new();
    signals.observe(libc::SIGINT);
    let text = format!("{:#}", always_wrap(&signals, error));
    assert!(
        text.contains("pause coordination cancelled"),
        "the sealed error still names the cancellation: {text}"
    );
    assert!(
        text.contains("interrupted by SIGINT"),
        "a signalled run names the interruption, never a refusal: {text}"
    );
}

/// v070: a settled finish still seals (healthy twin for the settlement-
/// unknown path). The terminal runs before detach and the evidence is
/// returned.
#[test]
fn settlement_success_still_seals_the_report() {
    let mut phases = Vec::new();
    let mut observed = None;
    let result = finish_capture_with(
        &mut phases,
        Ok(CaptureEnd::DurationExpired),
        |phases| phases.push("gap"),
        |phases, result| {
            phases.push("finish");
            result
        },
        |phases| {
            phases.push("detach");
            Ok(())
        },
        |phases, end, detached| {
            phases.push("terminal");
            observed = Some((end, detached));
            Ok(17)
        },
    );
    assert_eq!(result.unwrap(), 17);
    assert_eq!(observed, Some((CaptureEnd::DurationExpired, false)));
    assert_eq!(phases, ["finish", "terminal", "detach"]);
}

/// v070 RED: a finish (settlement) failure after capture must still seal
/// the report with child status unknown, then detach, then return the
/// error. The terminal runs even though the child disposition is unknown.
#[test]
fn settlement_failure_still_seals_the_report_with_unknown_child() {
    for loop_failed in [false, true] {
        let mut phases = Vec::new();
        let mut observed = None;
        let loop_result: Result<CaptureEnd> = if loop_failed {
            Err(anyhow::anyhow!("loop failure"))
        } else {
            Ok(CaptureEnd::DurationExpired)
        };
        let result = finish_capture_with(
            &mut phases,
            loop_result,
            |phases| phases.push("gap"),
            |phases, result| {
                phases.push("finish");
                let _ = result?;
                anyhow::bail!("finish failure");
            },
            |phases| {
                phases.push("detach");
                Ok(())
            },
            |phases, end, detached| {
                phases.push("terminal");
                observed = Some((end, detached));
                Ok(17)
            },
        );
        let message = format!("{:#}", result.unwrap_err());
        assert!(
            message.contains("finish failure"),
            "loop_failed={loop_failed}: settlement error dropped: {message}"
        );
        if loop_failed {
            assert!(
                message.contains("loop failure"),
                "loop error dropped: {message}"
            );
            assert_eq!(observed, Some((CaptureEnd::Error, false)));
            assert_eq!(phases, ["gap", "finish", "terminal", "detach"]);
        } else {
            assert_eq!(observed, Some((CaptureEnd::DurationExpired, false)));
            assert_eq!(phases, ["finish", "terminal", "detach"]);
        }
    }
}

/// v070 RED: a quiesce-block settlement failure must still publish (with
/// unknown child) before detach, keeping every error.
#[test]
fn quiesce_settlement_failure_still_publishes_with_unknown_child() {
    let mut phases = Vec::new();
    let error = finish_quiesce_error(
        anyhow::anyhow!("quiesce failure"),
        Ok(CaptureEnd::DurationExpired),
        &mut phases,
        |phases| phases.push("gap"),
        |phases, _| {
            phases.push("settle");
            anyhow::bail!("settle failure");
        },
        |phases| {
            phases.push("publish");
            Ok(())
        },
        |phases| {
            phases.push("detach");
            Ok(())
        },
    );
    assert_eq!(phases, ["settle", "publish", "detach"]);
    let message = format!("{error:#}");
    assert!(
        message.contains("quiesce failure") && message.contains("settle failure"),
        "an error was dropped: {message}"
    );
}

/// v070: a clean terminal read seals fresh (healthy twin for the snapshot
/// fallback). No diagnostic, no error.
#[test]
fn terminal_snapshot_success_seals_fresh_with_no_gap() {
    let diagnosed = std::cell::Cell::new(false);
    let (value, error) = seal_terminal_or_last_good(Some(&5u64), Ok(8u64), |_| diagnosed.set(true))
        .expect("a clean read seals");
    assert_eq!(value, 8);
    assert!(error.is_none());
    assert!(!diagnosed.get(), "a clean read names no failure");
}

/// v070: a failed terminal read with a last good value seals from it with
/// a diagnostic and the error, so the caller files its named gap and
/// still exits nonzero.
#[test]
fn terminal_snapshot_failure_seals_from_last_good_with_gap() {
    let diagnosed = std::cell::Cell::new(false);
    let (value, error) =
        seal_terminal_or_last_good(Some(&5u64), Err(anyhow::anyhow!("STATS map gone")), |_| {
            diagnosed.set(true)
        })
        .expect("a last good value always seals");
    assert_eq!(value, 5);
    let message = format!("{:#}", error.expect("the failure stays an error"));
    assert!(message.contains("STATS map gone"), "{message}");
    assert!(diagnosed.get(), "the fallback must name the failure");
}

/// v070: a failed terminal read with no last good value has nothing to
/// seal from and returns the error.
#[test]
fn terminal_snapshot_failure_without_last_good_returns_the_error() {
    let diagnosed = std::cell::Cell::new(false);
    let result: Result<(u64, Option<anyhow::Error>)> =
        seal_terminal_or_last_good(None, Err(anyhow::anyhow!("STATS map gone")), |_| {
            diagnosed.set(true)
        });
    let message = format!("{:#}", result.unwrap_err());
    assert!(message.contains("STATS map gone"), "{message}");
    assert!(
        !diagnosed.get(),
        "with nothing to seal from there is no fallback to name"
    );
}

/// Data always, degraded terminal order: `run_terminal` publishes the `-o`
/// report before failing with the terminal read error, so a degraded
/// snapshot still seals its report and the run exits nonzero. The degraded
/// read error joins the stored seal union (never a second tail that a
/// pinned failure would shadow), and that union's return follows the
/// commit. Deleting the union member or the return must fail this test.
#[test]
fn degraded_terminal_publishes_before_failing_with_terminal_error() {
    let source = include_str!("../run.rs");
    let production = source.split_once("#[cfg(test)]\nmod tests").unwrap().0;
    let terminal = production
        .split_once("fn run_terminal(")
        .unwrap()
        .1
        .split_once("\nfn write_json_report")
        .unwrap()
        .0;
    assert_eq!(
        terminal
            .matches("terminal_seal_errors(snapshot_error, &snapshot, pinned_error)")
            .count(),
        1,
        "run_terminal stores the degraded read error with the other seal errors"
    );
    assert!(
        !terminal.contains("snapshot.terminal_error()"),
        "no separate degraded tail that a coincident pinned failure would shadow"
    );
    let union = terminal
        .find("terminal_seal_errors(")
        .expect("run_terminal builds the seal union");
    let commit = terminal
        .find("out_file.commit()")
        .expect("run_terminal publishes the -o report");
    let failure = terminal
        .rfind("if let Some(error) = terminal_error {\n            return Err(error);")
        .expect("run_terminal fails with the stored seal errors");
    assert!(
        union < commit && commit < failure,
        "the union is stored before publication and fails the run after the commit"
    );
    let helper = production
        .split_once("fn terminal_seal_errors(")
        .expect("the seal-union helper exists")
        .1
        .split_once("\n}\n")
        .unwrap()
        .0;
    assert!(
        helper.contains("snapshot\n        .terminal_error()")
            && helper.contains(
                "combine_terminal_errors([snapshot_error, degraded_error, pinned_error])"
            ),
        "the helper folds the degraded read error between the fallback and pinned errors"
    );
}

/// F1 twin, coincident double fault: a degraded terminal snapshot (never
/// acquired) and a failed pinned-identity check both survive in the
/// returned chain, and a later publication failure keeps both too.
#[test]
fn degraded_snapshot_and_pinned_failure_both_survive_the_seal() {
    let degraded = metrics::CaptureSnapshot::degraded_legacy(
        "stats_unread",
        "reading STATS map: map gone".into(),
    );
    let stored = terminal_seal_errors(
        None,
        &degraded,
        Some(
            anyhow::anyhow!("pinned provider fstat failed")
                .context("revalidating pinned provider identity"),
        ),
    )
    .expect("both failures are kept");
    let message = format!("{stored:#}");
    assert!(message.contains("reading STATS map: map gone"), "{message}");
    assert!(
        message.contains("pinned provider fstat failed"),
        "{message}"
    );
    assert!(
        message.contains("revalidating pinned provider identity"),
        "{message}"
    );
    let published = terminal_publication_error(Some(stored), anyhow::anyhow!("writing -o failed"));
    let message = format!("{published:#}");
    assert!(message.contains("reading STATS map: map gone"), "{message}");
    assert!(
        message.contains("pinned provider fstat failed"),
        "{message}"
    );
    assert!(message.contains("writing -o failed"), "{message}");
}

/// Healthy twin: a clean snapshot with no fallback and no pinned failure
/// stores nothing, and a degraded snapshot alone is kept on its own.
#[test]
fn clean_terminal_stores_no_seal_error_and_degraded_alone_is_kept() {
    let clean = metrics::CaptureSnapshot::empty();
    assert!(terminal_seal_errors(None, &clean, None).is_none());
    let degraded = metrics::CaptureSnapshot::degraded_legacy(
        "stats_unread",
        "reading STATS map: map gone".into(),
    );
    let alone = terminal_seal_errors(None, &degraded, None).expect("the read error is kept");
    assert_eq!(format!("{alone:#}"), "reading STATS map: map gone");
}

/// The terminal-seal test context: a plan the discovery closure hands
/// back, one gap flag per terminal drain, and a publication flag.
struct TerminalSealContext {
    plan: crate::plan::AttachPlan,
    drain_gap: bool,
    root_gap: bool,
    published: bool,
}

impl TerminalSealContext {
    fn new() -> Self {
        Self {
            plan: crate::plan::AttachPlan::from_slots(vec![]),
            drain_gap: false,
            root_gap: false,
            published: false,
        }
    }
}

/// Owned terminal consumers: the state keeps no borrow on the plan it
/// was built from, so the fixture owns the live consumers only.
struct TerminalSealSetup {
    state: semantics::State,
    tracker: process::Tracker,
    malformed: u64,
    scheduling: SchedulingAccumulator,
}

impl TerminalSealSetup {
    fn new() -> Self {
        let plan = crate::plan::AttachPlan::from_slots(vec![]);
        let state = semantics::State::new(&plan);
        let tracker =
            process::Tracker::for_producer(crate::events::EventsDomain::test_standin(7), 16);
        Self {
            state,
            tracker,
            malformed: 0,
            scheduling: SchedulingAccumulator::default(),
        }
    }

    fn consumers(&mut self) -> CaptureConsumers<'_> {
        CaptureConsumers {
            state: &mut self.state,
            tracker: &mut self.tracker,
            tracer: None,
            malformed_records: &mut self.malformed,
            scheduling: &mut self.scheduling,
            stop_quiescence: crate::render::StopQuiescence {
                state: crate::render::QuiescenceState::NotReached,
                post_q_events: false,
                post_q_discovery: false,
            },
        }
    }
}

/// A failed terminal events drain still seals: the named gap is filed,
/// publication runs from partial state, and the drain error returns so
/// the run exits nonzero.
#[test]
fn terminal_events_drain_failure_still_seals_with_a_named_gap() {
    let mut setup = TerminalSealSetup::new();
    let mut consumers = setup.consumers();
    let mut context = TerminalSealContext::new();
    let mut diagnostics = Vec::new();
    let result: Result<()> = drain_capture_terminal_with(
        &mut context,
        &mut consumers,
        None,
        &mut diagnostics,
        |context, _, _| Ok((false, &context.plan)),
        |_, _| (Ok(OriginalRootDrain::Absent), None),
        |context| context.root_gap = true,
        |_, _| Err(anyhow::anyhow!("ring read failed")),
        |context| context.drain_gap = true,
        |context, _| {
            context.published = true;
            Ok(())
        },
    );
    let error = result.expect_err("a failed terminal drain must fail the run");
    assert!(
        format!("{error:#}").contains("ring read failed"),
        "the drain error must survive the seal: {error:#}"
    );
    assert!(
        context.drain_gap,
        "the drain failure must file its named gap"
    );
    assert!(!context.root_gap, "no root failure happened");
    assert!(
        context.published,
        "a failed terminal drain must still publish"
    );
}

/// Healthy twin: a healthy terminal events drain seals cleanly with no
/// gap and no error.
#[test]
fn terminal_events_drain_success_seals_without_a_gap() {
    let mut setup = TerminalSealSetup::new();
    let mut consumers = setup.consumers();
    let mut context = TerminalSealContext::new();
    let mut diagnostics = Vec::new();
    let result: Result<()> = drain_capture_terminal_with(
        &mut context,
        &mut consumers,
        None,
        &mut diagnostics,
        |context, _, _| Ok((false, &context.plan)),
        |_, _| (Ok(OriginalRootDrain::Absent), None),
        |context| context.root_gap = true,
        |_, _| Ok(()),
        |context| context.drain_gap = true,
        |context, _| {
            context.published = true;
            Ok(())
        },
    );
    result.expect("a healthy terminal drain must seal cleanly");
    assert!(
        !context.drain_gap && !context.root_gap,
        "a healthy seal files no gap"
    );
    assert!(context.published, "a healthy seal publishes");
}

/// A failed terminal original-root tail drain still seals: the named
/// gap is filed, publication runs with no completed tail, and the root
/// error returns so the run exits nonzero.
#[test]
fn terminal_root_drain_failure_still_seals_with_a_named_gap() {
    let mut setup = TerminalSealSetup::new();
    let mut consumers = setup.consumers();
    let mut context = TerminalSealContext::new();
    let mut diagnostics = Vec::new();
    let result: Result<()> = drain_capture_terminal_with(
        &mut context,
        &mut consumers,
        None,
        &mut diagnostics,
        |context, _, _| Ok((false, &context.plan)),
        |_, _| (Err(anyhow::anyhow!("root ring read failed")), None),
        |context| context.root_gap = true,
        |_, _| Ok(()),
        |context| context.drain_gap = true,
        |context, _| {
            context.published = true;
            Ok(())
        },
    );
    let error = result.expect_err("a failed root drain must fail the run");
    assert!(
        format!("{error:#}").contains("root ring read failed"),
        "the root error must survive the seal: {error:#}"
    );
    assert!(context.root_gap, "the root failure must file its named gap");
    assert!(!context.drain_gap, "no events-drain failure happened");
    assert!(context.published, "a failed root drain must still publish");
}

/// Healthy twin: a healthy terminal root drain seals cleanly with no
/// gap and no error.
#[test]
fn terminal_root_drain_success_seals_without_a_gap() {
    let mut setup = TerminalSealSetup::new();
    let mut consumers = setup.consumers();
    let mut context = TerminalSealContext::new();
    let mut diagnostics = Vec::new();
    let result: Result<()> = drain_capture_terminal_with(
        &mut context,
        &mut consumers,
        None,
        &mut diagnostics,
        |context, _, _| Ok((false, &context.plan)),
        |_, _| (Ok(OriginalRootDrain::Absent), None),
        |context| context.root_gap = true,
        |_, _| Ok(()),
        |context| context.drain_gap = true,
        |context, _| {
            context.published = true;
            Ok(())
        },
    );
    result.expect("a healthy root drain must seal cleanly");
    assert!(
        !context.drain_gap && !context.root_gap,
        "a healthy seal files no gap"
    );
    assert!(context.published, "a healthy seal publishes");
}

/// An unusable capture stdout degrades to a closed sink: the named gap
/// is filed, the run starts closed, and the deferred failure fails the
/// run after publication.
#[test]
fn unavailable_capture_stdout_degrades_to_a_closed_sink_with_a_gap() {
    let gap = std::cell::Cell::new(false);
    let opened = open_capture_stdout(
        || gap.set(true),
        || {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "fd 1 closed",
            ))
        },
    )
    .expect("a degraded open must still hand back a sink");
    assert!(gap.get(), "the failure must file its named gap");
    assert!(!opened.open, "a degraded run starts with stdout closed");
    let deferred = opened
        .deferred
        .expect("a degraded run must fail after publication");
    assert!(
        format!("{deferred:#}").contains("opening capture stdout"),
        "the deferred failure must name the open: {deferred:#}"
    );
    // The degraded sink is safe to hold: nothing is written through it
    // (callers start closed), but a write would reach /dev/null.
    let mut sink = opened.sink;
    use std::io::Write as _;
    sink.write_all(b"x")
        .expect("a degraded sink stays writable");
}

/// Healthy twin: a live stdout opens live with no gap and nothing
/// deferred.
#[test]
fn available_capture_stdout_opens_live_with_no_gap() {
    let gap = std::cell::Cell::new(false);
    let opened = open_capture_stdout(|| gap.set(true), crate::sink::stdout_sink)
        .expect("a live stdout must open");
    assert!(!gap.get(), "a live open files no gap");
    assert!(opened.open, "a live open stays open");
    assert!(opened.deferred.is_none(), "a live open defers nothing");
}

/// A terminal identity revalidation whose `fstat` itself failed
/// degrades to a named gap and fails after publication; the caller
/// latches fail-closed identity beside it.
#[test]
fn failed_identity_revalidation_degrades_to_a_gap_and_fails() {
    let gap = std::cell::Cell::new(false);
    let error = terminal_identity_or_gap(
        || gap.set(true),
        Err("/prov/p11.so: Bad file descriptor".to_string()),
    )
    .expect_err("a failed revalidation must fail the run");
    assert!(gap.get(), "the failure must file its named gap");
    assert!(
        format!("{error:#}").contains("revalidating pinned provider identity"),
        "the failure must name the revalidation: {error:#}"
    );
}

/// Healthy twins: a proven identity check — changed or not — passes
/// through with no gap.
#[test]
fn proven_identity_checks_pass_through_without_a_gap() {
    for changed in [false, true] {
        let gap = std::cell::Cell::new(false);
        terminal_identity_or_gap(|| gap.set(true), Ok(!changed))
            .expect("a proven check must pass through");
        assert!(!gap.get(), "a proven check files no gap");
    }
}

/// A failure deferred past publication still fails the run: a sealed
/// document keeps its error, and a failed seal keeps both errors.
#[test]
fn deferred_failure_fails_after_publication() {
    assert!(
        combine_deferred_failure::<()>(Ok(()), None).is_ok(),
        "no deferral leaves a sealed result standing"
    );
    assert!(
        combine_deferred_failure::<()>(Err(anyhow::anyhow!("seal failed")), None).is_err(),
        "no deferral leaves a failed seal failing"
    );
    let error = combine_deferred_failure::<()>(Ok(()), Some(anyhow::anyhow!("stdout failed")))
        .expect_err("a deferred failure must fail a sealed run");
    assert!(
        error.to_string().contains("stdout failed"),
        "the deferred failure must survive: {error:#}"
    );
    let error = combine_deferred_failure::<()>(
        Err(anyhow::anyhow!("seal failed")),
        Some(anyhow::anyhow!("stdout failed")),
    )
    .expect_err("a deferred failure must fail a failed seal");
    let message = format!("{error:#}");
    assert!(
        message.contains("stdout failed") && message.contains("seal failed"),
        "either error dropped: {message}"
    );
}

/// A degraded-stdout trace that then hits a quiesce failure keeps both
/// errors: the deferred stdout failure joins the quiesce error union at
/// the quiesce-error terminal exactly as at the normal terminals, so
/// the report names it and the run exits nonzero.
#[test]
fn trace_quiesce_error_with_degraded_stdout_names_both_failures() {
    let mut deferred: Option<anyhow::Error> = Some(
        anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "fd 1 closed",
        ))
        .context("opening capture stdout"),
    );
    let error = finish_quiesce_error(
        anyhow::anyhow!("quiesce failure"),
        Ok(CaptureEnd::DurationExpired),
        &mut (),
        |_| {},
        |_, _| Ok(()),
        |_| combine_deferred_failure(Ok(()), deferred.take()),
        |_| Ok(()),
    );
    let message = format!("{error:#}");
    assert!(
        message.contains("quiesce failure") && message.contains("opening capture stdout"),
        "either error dropped: {message}"
    );
}

/// Both capture paths file the terminal-drain gaps, open stdout
/// through the degrading opener, and report the deferred failure after
/// publication at both terminals (quiesce-error and normal): a
/// degraded-stdout run that then hits a quiesce failure still names
/// the deferred failure and exits nonzero.
#[test]
fn terminal_drain_and_stdout_degradations_are_wired_at_both_capture_paths() {
    let source = include_str!("../run.rs");
    let profile = source
        .split_once("fn capture_profile(")
        .unwrap()
        .1
        .split_once("fn capture_trace(")
        .unwrap()
        .0;
    let trace = source
        .split_once("fn capture_trace(")
        .unwrap()
        .1
        .split_once("fn terminal_trace_count_line")
        .unwrap()
        .0;
    for (function, body, deferred) in [("capture_profile", profile, 2), ("capture_trace", trace, 2)]
    {
        for site in [
            "note_terminal_events_drain_failure()",
            "note_terminal_original_root_drain_failure()",
            "open_capture_stdout(",
        ] {
            assert!(body.contains(site), "{function} must wire {site}");
        }
        assert_eq!(
            body.matches("combine_deferred_failure(").count(),
            deferred,
            "{function} must fail the deferred stdout error after publication"
        );
    }
}

/// Every terminal identity revalidation — one in the profile seal, two
/// bracketing the trace map read — degrades through the shared helper.
#[test]
fn terminal_identity_degradation_is_wired_at_every_revalidation_site() {
    let source = include_str!("../run.rs");
    let profile = source
        .split_once("fn capture_profile(")
        .unwrap()
        .1
        .split_once("fn capture_trace(")
        .unwrap()
        .0;
    let trace = source
        .split_once("fn capture_trace(")
        .unwrap()
        .1
        .split_once("fn terminal_trace_count_line")
        .unwrap()
        .0;
    assert_eq!(
        profile.matches("terminal_identity_or_gap(").count(),
        1,
        "the profile seal must degrade its revalidation"
    );
    assert_eq!(
        trace.matches("terminal_identity_or_gap(").count(),
        2,
        "the trace seal must degrade both revalidations"
    );
}

/// v070r2 RED: a pinned-object revalidation failure after the profile
/// snapshot sealed must degrade to a gap plus a combined error, never an
/// early return that discards the sealed report (data-always).
#[test]
fn terminal_pinned_check_degrades_to_a_gap_in_profile() {
    let source = include_str!("../run.rs");
    let profile = source
        .split_once("fn capture_profile(")
        .unwrap()
        .1
        .split_once("fn write_json_report")
        .unwrap()
        .0;
    let terminal = profile.split_once("fn run_terminal(").unwrap().1;
    assert_eq!(
        terminal.matches("terminal_identity_or_gap(").count(),
        1,
        "run_terminal must degrade the pinned check instead of an early `?`"
    );
    assert!(
        terminal.contains("pinned_error"),
        "run_terminal must keep the pinned failure for its gap and error"
    );
    assert!(
        !terminal.contains(".check_unchanged()?")
            && !terminal.contains(".check_unchanged().map_err("),
        "run_terminal must not revalidate pins directly with an early return"
    );
}

/// v070r2 RED: trace pinned/prearm failures must degrade like the aggregate
/// reads (gap plus combined error), never discard the sealed EVIDENCE.
/// Scoped to the terminal drain region: the live tick loop keeps its own
/// pin sweep, which fails the tick (sealed with a loop gap), not the seal.
#[test]
fn terminal_pinned_and_prearm_checks_degrade_to_gaps_in_trace() {
    let source = include_str!("../run.rs");
    let trace = source
        .split_once("fn capture_trace(")
        .unwrap()
        .1
        .split_once("fn terminal_trace_count_line")
        .unwrap()
        .0;
    let terminal = trace.split_once("drain_capture_terminal_with(").unwrap().1;
    assert_eq!(
        terminal.matches("terminal_identity_or_gap(").count(),
        2,
        "both trace pinned checks must degrade instead of an early `?`"
    );
    assert!(
        terminal.contains("watch_error"),
        "the trace watch-kernel read must seal from a default with its error kept"
    );
    assert!(
        !terminal.contains(".check_unchanged()?")
            && !terminal.contains(".check_unchanged().map_err("),
        "trace terminal must not revalidate pins directly with an early return"
    );
    assert!(
        !terminal.contains("prearm_terminal_kernel(context.1)?"),
        "the watch-kernel read must not discard the sealed reports with `?`"
    );
}

/// v070r2: the settlement-unknown terminal mapping through the real
/// evidence wiring: absent child and handoff, one gap, present run tree,
/// PARTIAL with a concrete gap. The healthy twin keeps the child with no
/// settlement gap and no `skipped` verdict cause.
#[test]
fn settlement_unknown_maps_to_absent_child_with_gap_and_partial() {
    let (engine, _) = crate::discovery::engine::tests::selection_output_engines();
    let state = semantics::State::new(engine.plan());
    let build = |child: Option<bool>, handoff: Option<u32>| {
        evidence_for(
            &engine,
            engine.capture_facts(),
            0,
            false,
            false,
            Default::default(),
            crate::render::ObjectCaptureEvidence::for_build(cfg!(
                feature = "stub-object-attributes"
            )),
            &[],
            &[],
            crate::metrics::KernelEvidence::default(),
            crate::process::TrackingEvidence::default(),
            0,
            &state,
            false,
            true,
            Default::default(),
            0,
            None,
            child,
            false,
            crate::render::SchedulingEvidence::default(),
            None,
            handoff,
            None,
            0,
        )
    };
    // Healthy twin: a settled running child handed back, no settlement gap.
    let mut healthy = build(Some(true), Some(1234));
    assert_eq!(healthy.child_still_running, Some(true));
    assert_eq!(healthy.handoff_child_pid, Some(1234));
    assert_eq!(
        healthy.run_tree_handed_back,
        Some(engine.run_tree_handed_back())
    );
    healthy.apply_stop_quiescence(crate::render::StopQuiescence::default());
    healthy.settle_terminal(true);
    assert!(healthy.skipped.is_empty());
    assert_eq!(healthy.completeness, "PARTIAL");
    assert!(
        !healthy.gap_classes.observation.causes.contains(&"skipped"),
        "no settlement gap without an unsettled child: {:?}",
        healthy.gap_classes.observation.causes
    );

    // Failure twin: the terminal mapping for an unsettled child.
    let mut unknown = build(None, None);
    // `evidence_for` derives no run tree from an absent child; the terminal
    // restores the count measured before settlement.
    assert_eq!(unknown.run_tree_handed_back, None);
    unknown.skipped.push(crate::render::SkippedOut {
        name: "discovery subject".into(),
        reason: "discovery unavailable".into(),
    });
    unknown.run_tree_handed_back = Some(engine.run_tree_handed_back());
    unknown.apply_stop_quiescence(crate::render::StopQuiescence::default());
    unknown.settle_terminal(true);
    assert_eq!(unknown.child_still_running, None);
    assert_eq!(unknown.handoff_child_pid, None);
    assert_eq!(
        unknown.run_tree_handed_back,
        Some(engine.run_tree_handed_back())
    );
    assert_eq!(unknown.skipped.len(), 1);
    assert_eq!(unknown.completeness, "PARTIAL");
    assert_eq!(unknown.verdict_detail, crate::render::VERDICT_CONCRETE_GAP);
    assert!(
        unknown.gap_classes.observation.causes.contains(&"skipped"),
        "the settlement gap must land as a verdict cause: {:?}",
        unknown.gap_classes.observation.causes
    );
    let json = serde_json::to_value(&unknown).expect("evidence serializes");
    assert!(json.get("child_still_running").is_none());
    assert_eq!(
        json["run_tree_handed_back"],
        serde_json::json!(engine.run_tree_handed_back())
    );
    assert_eq!(json["completeness"], "PARTIAL");
}

/// v070r2: the snapshot fallbacks through the real seal-plus-gap wiring:
/// profile seals stale from the last good snapshot, trace seals unknown
/// from empty reports and default kernel evidence, each with a gap and a
/// concrete PARTIAL.
#[test]
fn snapshot_fallback_seals_with_gap_and_partial() {
    use p11scope_ebpf_common::CounterMode;
    // Profile: a failed terminal read seals from the last good snapshot.
    let mut fixture = crate::metrics::ConsumerFixture::new();
    let last_good = fixture.fresh(CounterMode::Counts, 1, 5, None).unwrap();
    let diagnosed = std::cell::Cell::new(false);
    let (snapshot, error) = seal_terminal_or_last_good(
        Some(&last_good),
        Err(anyhow::anyhow!("STATS map gone")),
        |_| diagnosed.set(true),
    )
    .expect("a last good value always seals");
    assert_eq!(snapshot.reports()[0].calls, 5);
    assert!(error.is_some());
    assert!(diagnosed.get());
    let (engine, _) = crate::discovery::engine::tests::selection_output_engines();
    let state = semantics::State::new(engine.plan());
    let mut ev = evidence_for(
        &engine,
        engine.capture_facts(),
        0,
        false,
        false,
        Default::default(),
        crate::render::ObjectCaptureEvidence::for_build(cfg!(feature = "stub-object-attributes")),
        &[],
        &[],
        crate::metrics::KernelEvidence::default(),
        crate::process::TrackingEvidence::default(),
        0,
        &state,
        false,
        true,
        Default::default(),
        0,
        None,
        None,
        false,
        crate::render::SchedulingEvidence::default(),
        None,
        None,
        None,
        0,
    );
    ev.skipped.push(crate::render::SkippedOut {
        name: "discovery subject".into(),
        reason: "discovery unavailable".into(),
    });
    ev.apply_stop_quiescence(crate::render::StopQuiescence::default());
    ev.settle_terminal(true);
    assert_eq!(ev.completeness, "PARTIAL");
    assert_eq!(ev.verdict_detail, crate::render::VERDICT_CONCRETE_GAP);

    // Trace: failed aggregate reads seal unknown with a gap.
    let empty_reports: Vec<crate::metrics::SlotReport> = Vec::new();
    let (reports, reports_error) = seal_terminal_or_last_good(
        Some(&empty_reports),
        Err(anyhow::anyhow!("STATS map gone")),
        |_| {},
    )
    .expect("a synthetic empty fallback always seals");
    assert!(reports.is_empty());
    assert!(reports_error.is_some());
    let default_kernel = crate::metrics::KernelEvidence::default();
    let (kernel, kernel_error) = seal_terminal_or_last_good(
        Some(&default_kernel),
        Err(anyhow::anyhow!("kernel evidence gone")),
        |_| {},
    )
    .expect("a synthetic default fallback always seals");
    assert_eq!(kernel.ring_loss, 0);
    assert!(kernel_error.is_some());
}

/// v070r2: a terminal pinned-object revalidation still seals whether the
/// pins are unchanged or changed: the bool stays discarded (the sticky
/// `provider_changed` flag carries the evidence), only an I/O failure
/// becomes a stored error (and a latched gap) for the caller.
#[test]
fn terminal_pinned_check_still_seals_across_unchanged_and_changed_pins() {
    use crate::discovery::identity::test_fixture::real_scan_pin;
    let degraded = |pins: &crate::discovery::identity::PinnedObjects| {
        let noted = std::cell::Cell::new(false);
        let result = terminal_identity_or_gap(|| noted.set(true), pins.check_unchanged());
        assert_eq!(
            result.is_err(),
            noted.get(),
            "a gap is filed exactly on failure"
        );
        result.err()
    };
    let empty = crate::discovery::identity::PinnedObjects::empty();
    assert!(degraded(&empty).is_none());
    assert!(!empty.provider_changed());

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("provider.so");
    std::fs::write(&path, b"original bytes").unwrap();
    let pins = real_scan_pin(&path, None, 1, &"ab".repeat(32));
    assert!(degraded(&pins).is_none());
    assert!(!pins.provider_changed());

    // A changed provider still seals (None): the report keeps the sealed
    // snapshot with a gap, and the sticky flag names the change.
    std::fs::write(&path, b"original bytes plus a mutation").unwrap();
    assert!(degraded(&pins).is_none());
    assert!(pins.provider_changed());
}

/// v070r2: terminal errors combine keeping every layer: nothing when all
/// succeeded, the single failure otherwise, an `also failed` chain when
/// several failed (with `None` entries skipped).
#[test]
fn terminal_errors_combine_keeping_every_layer() {
    assert!(combine_terminal_errors([None, None]).is_none());
    let single = combine_terminal_errors([None, Some(anyhow::anyhow!("pinned failed"))])
        .expect("a single failure is kept");
    assert_eq!(format!("{single:#}"), "pinned failed");
    let both = combine_terminal_errors([
        Some(anyhow::anyhow!("snapshot failed")),
        None,
        Some(anyhow::anyhow!("pinned failed")),
    ])
    .expect("failures combine");
    let message = format!("{both:#}");
    assert!(message.contains("snapshot failed"), "{message}");
    assert!(message.contains("pinned failed"), "{message}");
    assert!(message.contains("also failed"), "{message}");
}

/// v070r3 RED: run_terminal must seal events-only when no snapshot was
/// ever acquired, never return early without a report (data-always).
#[test]
fn terminal_without_last_good_seals_events_only_in_profile() {
    let source = include_str!("../run.rs");
    let profile = source
        .split_once("fn capture_profile(")
        .unwrap()
        .1
        .split_once("fn write_json_report")
        .unwrap()
        .0;
    let terminal = profile.split_once("fn run_terminal(").unwrap().1;
    assert!(
        terminal.contains("seal_terminal_snapshot(last_good, acquired)"),
        "run_terminal must seal through the events-only fallback instead of an early `?`"
    );
    assert!(
        !terminal.contains("seal_terminal_or_last_good"),
        "run_terminal must not return the unsealable error early without a report"
    );
}

/// v070r3 RED: a failed terminal trace-loss report must degrade like the
/// reads (named gap plus combined error), never return early without
/// EVIDENCE (data-always). Scoped to the terminal drain region like the
/// pinned/prearm pins.
#[test]
fn terminal_trace_loss_degrades_to_a_gap_in_trace() {
    let source = include_str!("../run.rs");
    let trace = source
        .split_once("fn capture_trace(")
        .unwrap()
        .1
        .split_once("fn terminal_trace_count_line")
        .unwrap()
        .0;
    let terminal = trace.split_once("drain_capture_terminal_with(").unwrap().1;
    assert!(
        terminal.contains("loss_error"),
        "the trace terminal must keep the loss failure for its gap and error"
    );
    assert!(
        !terminal
            .contains("report_trace_loss(context.1, context.4, context.5, context.6, context.7)?"),
        "the loss report must not discard the seal with an early `?`"
    );
}

/// v070r3: a failed terminal snapshot with no last good value seals
/// events-only (empty reports, default kernel evidence) with the failure
/// kept for the nonzero exit, landing PARTIAL through the terminal gap;
/// a clean read seals fresh with no error; the last-good fallback is
/// unchanged.
#[test]
fn terminal_snapshot_without_last_good_seals_events_only() {
    use p11scope_ebpf_common::CounterMode;
    // Failure twin: no last good value, failed read.
    let (snapshot, error) = seal_terminal_snapshot(None, Err(anyhow::anyhow!("STATS map gone")));
    assert!(snapshot.reports().is_empty());
    assert_eq!(
        snapshot.kernel_evidence(),
        crate::metrics::KernelEvidence::default()
    );
    let message = format!("{:#}", error.expect("the failure stays an error"));
    assert!(message.contains("STATS map gone"), "{message}");
    // The events-only seal still lands PARTIAL through the terminal gap.
    let (engine, _) = crate::discovery::engine::tests::selection_output_engines();
    let state = semantics::State::new(engine.plan());
    let mut ev = evidence_for(
        &engine,
        engine.capture_facts(),
        0,
        false,
        false,
        Default::default(),
        crate::render::ObjectCaptureEvidence::for_build(cfg!(feature = "stub-object-attributes")),
        &[],
        snapshot.reports(),
        snapshot.kernel_evidence(),
        crate::process::TrackingEvidence::default(),
        0,
        &state,
        false,
        true,
        Default::default(),
        0,
        None,
        None,
        false,
        crate::render::SchedulingEvidence::default(),
        None,
        None,
        None,
        0,
    );
    ev.skipped.push(crate::render::SkippedOut {
        name: "discovery subject".into(),
        reason: "discovery unavailable".into(),
    });
    ev.apply_stop_quiescence(crate::render::StopQuiescence::default());
    ev.settle_terminal(true);
    assert_eq!(ev.completeness, "PARTIAL");
    assert_eq!(ev.verdict_detail, crate::render::VERDICT_CONCRETE_GAP);
    // Healthy twin: a clean read seals fresh with no error.
    let (snapshot, error) = seal_terminal_snapshot(None, Ok(metrics::CaptureSnapshot::empty()));
    assert!(snapshot.reports().is_empty());
    assert!(error.is_none());
    // Stale twin: the last-good fallback is unchanged.
    let mut fixture = crate::metrics::ConsumerFixture::new();
    let last_good = fixture.fresh(CounterMode::Counts, 1, 5, None).unwrap();
    let (snapshot, error) =
        seal_terminal_snapshot(Some(&last_good), Err(anyhow::anyhow!("STATS map gone")));
    assert_eq!(snapshot.reports()[0].calls, 5);
    assert!(error.is_some());
}

/// v070r2: a publication failure after the seal keeps the stored seal
/// errors instead of dropping them: alone it passes through, beside a
/// stored failure both layers survive.
#[test]
fn terminal_publication_failure_keeps_the_stored_seal_errors() {
    let alone = terminal_publication_error(None, anyhow::anyhow!("writing stdout"));
    assert_eq!(format!("{alone:#}"), "writing stdout");
    let both = terminal_publication_error(
        Some(anyhow::anyhow!("snapshot failed")),
        anyhow::anyhow!("writing stdout"),
    );
    let message = format!("{both:#}");
    assert!(message.contains("snapshot failed"), "{message}");
    assert!(message.contains("writing stdout"), "{message}");
    assert!(
        message.contains("terminal publication also failed"),
        "{message}"
    );
}
