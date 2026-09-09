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

    drain_trace_events_from(
        &mut context.drain,
        &mut context.remaining,
        &mut state,
        &mut tracker,
        &Scope::Pid(std::process::id()),
        &mut tracer,
        &mut context.stdout,
        &mut context.stdout_open,
        &mut context.out_file,
        None,
    )
    .unwrap();
    assert_eq!(state.sessions().opened, 2);
    assert_eq!(context.drain.source().remaining(), 0);
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
