use super::*;
use crate::events::{EventDrain, LIVE_POLL_QUANTUM, ScriptedRecords};
use p11scope_ebpf_common::{Event, capture, event_type};

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
        rv: pkcs11_proxy_ng_types::CkRv::OK.0,
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
        FinishError,
        ErrorEnd,
        Success,
        DetachError,
    }

    for case in [
        Case::LoopError,
        Case::FinishError,
        Case::ErrorEnd,
        Case::Success,
        Case::DetachError,
    ] {
        let mut phases = Vec::new();
        let mut observed = None;
        let loop_result = match case {
            Case::LoopError => Err(anyhow::anyhow!("loop failure")),
            Case::ErrorEnd => Ok(CaptureEnd::Error),
            _ => Ok(CaptureEnd::DurationExpired),
        };
        let result = finish_capture_with(
            &mut phases,
            loop_result,
            |phases, result| {
                phases.push("finish");
                let end = result?;
                if matches!(case, Case::FinishError) {
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
                assert_eq!(result.unwrap_err().to_string(), "loop failure");
                assert_eq!(phases, ["finish"]);
            }
            Case::FinishError => {
                assert_eq!(result.unwrap_err().to_string(), "finish failure");
                assert_eq!(phases, ["finish"]);
            }
            Case::ErrorEnd => {
                assert_eq!(result.unwrap(), 17);
                assert_eq!(observed, Some((CaptureEnd::Error, true)));
                assert_eq!(phases, ["finish", "detach", "terminal"]);
            }
            Case::Success => {
                assert_eq!(result.unwrap(), 17);
                assert_eq!(observed, Some((CaptureEnd::DurationExpired, true)));
                assert_eq!(phases, ["finish", "detach", "terminal"]);
            }
            Case::DetachError => {
                assert!(result.unwrap_err().to_string().contains("detach failure"));
                assert_eq!(observed, Some((CaptureEnd::DurationExpired, false)));
                assert_eq!(phases, ["finish", "detach", "terminal"]);
            }
        }
    }
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
                root_event(0, pkcs11_proxy_ng_types::CkRv::OK.0),
                root_event(1, pkcs11_proxy_ng_types::CkRv::PENDING.0),
            ],
        );
        context.ordinary = EventDrain::over_domain(
            ScriptedRecords::events([open_event(12)], usize::MAX),
            domain,
        );
        let mut diagnostics = Vec::new();

        let snapshot = {
            let mut consumers = CaptureConsumers {
                state: &mut state,
                tracker: &mut tracker,
                tracer: trace_mode.then_some(&mut tracer),
                malformed_records: &mut malformed_records,
            };
            drain_capture_terminal_with(
                &mut context,
                &mut consumers,
                true,
                &mut diagnostics,
                |context: &mut TerminalContext, detached| {
                    assert!(detached);
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
                |context, consumers| {
                    context.phases.push("drain");
                    let sessions = consumers.state.sessions();
                    assert_eq!(sessions.closed, 1);
                    assert_eq!(consumers.state.pending_at_end(), 0);
                    if let Some(tracer) = consumers.tracer.as_deref_mut() {
                        let mut out_file: Option<Vec<u8>> = None;
                        *consumers.malformed_records += drain_trace_events_from(
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
                    } else {
                        *consumers.malformed_records += drain_profile_events(
                            &mut context.ordinary,
                            consumers.state,
                            consumers.tracker,
                            &Scope::Pid(std::process::id()),
                            None,
                        )?;
                    }
                    Ok(())
                },
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
                root_event(0, pkcs11_proxy_ng_types::CkRv::OK.0),
                root_event(1, pkcs11_proxy_ng_types::CkRv::PENDING.0),
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
            let mut consumers = CaptureConsumers {
                state: &mut state,
                tracker: &mut tracker,
                tracer: None,
                malformed_records: &mut malformed_records,
            };
            drain_capture_terminal_with(
                &mut context,
                &mut consumers,
                true,
                &mut diagnostics,
                |context: &mut TickContext, _| Ok((false, &context.plan)),
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
                |_, _| Ok(()),
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
            root_event(0, pkcs11_proxy_ng_types::CkRv::OK.0),
            root_event(1, pkcs11_proxy_ng_types::CkRv::PENDING.0),
        ],
    );
    context.writer.fail = true;
    let mut diagnostics = Vec::new();
    let result = {
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: Some(&mut tracer),
            malformed_records: &mut malformed_records,
        };
        drain_capture_terminal_with(
            &mut context,
            &mut consumers,
            true,
            &mut diagnostics,
            |context: &mut TerminalContext, _| {
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
            |context, _| {
                context.phases.push("drain");
                Ok(())
            },
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
fn terminal_errors_stop_at_the_current_attempt_boundary() {
    for failure in ["discovery", "root", "drain"] {
        let plan = terminal_plan();
        let mut state = semantics::State::new(&plan);
        let mut tracker = tracker();
        let mut malformed_records = 0;
        let mut context = context(plan, []);
        let phases = std::cell::RefCell::new(Vec::new());
        let mut diagnostics = Vec::new();
        let result = {
            let mut consumers = CaptureConsumers {
                state: &mut state,
                tracker: &mut tracker,
                tracer: None,
                malformed_records: &mut malformed_records,
            };
            drain_capture_terminal_with(
                &mut context,
                &mut consumers,
                false,
                &mut diagnostics,
                |context: &mut TickContext, detached| {
                    phases.borrow_mut().push("discovery");
                    assert!(!detached);
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
                |_, _| {
                    phases.borrow_mut().push("drain");
                    if failure == "drain" {
                        anyhow::bail!("drain failure");
                    }
                    Ok(())
                },
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
        let expected = match failure {
            "discovery" => vec!["discovery"],
            "root" => vec!["discovery", "root"],
            _ => vec!["discovery", "root", "drain"],
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
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: None,
            malformed_records: &mut malformed_records,
        };
        drain_capture_terminal_with(
            &mut context,
            &mut consumers,
            true,
            &mut diagnostics,
            |context: &mut TickContext, _| Ok((false, &context.plan)),
            |_, _| {
                (
                    Ok(OriginalRootDrain::Cancelled {
                        malformed: 0,
                        remaining: 4,
                    }),
                    None,
                )
            },
            |_, _| Ok(()),
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
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: Some(&mut tracer),
            malformed_records: &mut malformed_records,
        };
        let snapshot = drain_capture_terminal_with(
            &mut context,
            &mut consumers,
            true,
            &mut diagnostics,
            |context: &mut TickContext, _| Ok((true, &context.plan)),
            |_, _| (Ok(OriginalRootDrain::Absent), None),
            |context, consumers| drain_tick(context, consumers),
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
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: Some(&mut tracer),
            malformed_records: &mut malformed_records,
        };
        let snapshot = drain_capture_terminal_with(
            &mut context,
            &mut consumers,
            true,
            &mut diagnostics,
            |context: &mut TickContext, _| Ok((true, &context.plan)),
            |_, _| (Ok(OriginalRootDrain::Absent), None),
            |context, consumers| drain_tick(context, consumers),
            |_, consumers| Ok(consumers.state.sessions().opened),
        )
        .unwrap();
        assert_eq!(snapshot, 0);
    }
    assert!(String::from_utf8_lossy(&context.stdout).contains("[semantics unverified]"));
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
    let malformed = if let Some(tracer) = consumers.tracer.as_deref_mut() {
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
            let mut consumers = CaptureConsumers {
                state: &mut state,
                tracker: &mut tracker,
                tracer: trace_mode.then_some(&mut tracer),
                malformed_records: &mut malformed_records,
            };
            let tick = capture_tick_with(
                &mut context,
                &mut consumers,
                |context: &mut TickContext| Ok((true, true, &context.plan)),
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
            assert!(String::from_utf8_lossy(&context.stdout).contains(" C_OpenSession "));
        }

        context.plan.slots[0].descriptor_index = 0;
        context.plan.slots[0].semantics = p11scope_ebpf_common::SlotSemantics::COUNT_ONLY;
        context.plan.slots[0].semantic_authorized = false;
        context.drain =
            EventDrain::over_test_domain(ScriptedRecords::events([open_event(12)], usize::MAX), 1);
        context.stdout.clear();
        {
            let mut consumers = CaptureConsumers {
                state: &mut state,
                tracker: &mut tracker,
                tracer: trace_mode.then_some(&mut tracer),
                malformed_records: &mut malformed_records,
            };
            let tick = capture_tick_with(
                &mut context,
                &mut consumers,
                |context: &mut TickContext| Ok((true, true, &context.plan)),
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
            assert!(
                String::from_utf8_lossy(&context.stdout).contains("[semantics unverified]"),
                "trace metadata must be synchronized with the downgrade"
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
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: Some(&mut tracer),
            malformed_records: &mut malformed_records,
        };
        capture_tick_with(
            &mut context,
            &mut consumers,
            |context: &mut TickContext| Ok((false, false, &context.plan)),
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
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: Some(&mut tracer),
            malformed_records: &mut malformed_records,
        };
        drain_capture_terminal_with(
            &mut context,
            &mut consumers,
            true,
            &mut diagnostics,
            |context: &mut TickContext, detached| {
                assert!(detached);
                Ok((false, &context.plan))
            },
            |_, _| (Ok(OriginalRootDrain::Absent), None),
            |context, consumers| {
                *consumers.malformed_records += drain_trace_events_from(
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
                Ok(())
            },
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
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: None,
            malformed_records: &mut malformed_records,
        };
        capture_tick_with(
            &mut context,
            &mut consumers,
            |context: &mut TickContext| Ok((false, false, &context.plan)),
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
            let mut consumers = CaptureConsumers {
                state: &mut state,
                tracker: &mut tracker,
                tracer: Some(&mut tracer),
                malformed_records: &mut malformed_records,
            };
            capture_tick_with(
                &mut context,
                &mut consumers,
                |context: &mut TickContext| {
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
        let mut consumers = CaptureConsumers {
            state: &mut state,
            tracker: &mut tracker,
            tracer: Some(&mut tracer),
            malformed_records: &mut malformed_records,
        };
        capture_tick_with(
            &mut context,
            &mut consumers,
            |context: &mut TickContext| Ok((true, true, &context.plan)),
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
