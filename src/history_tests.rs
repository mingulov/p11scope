//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Private acceptance tests: actual reducers/drains, only task membership injected.
use super::*;
use crate::events::{EventDrain, ScriptedRecords};
use crate::history::{Membership, TaskMembership};
use p11scope_ebpf_common::{Event, ImageIdentity, capture, event_type};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    os::fd::{AsRawFd, OwnedFd},
    rc::Rc,
    sync::Arc,
};

type MembershipBindings = BTreeMap<u32, (Arc<OwnedFd>, Membership)>;

#[derive(Clone)]
pub(super) struct Adapter(Rc<RefCell<MembershipBindings>>);
impl TaskMembership for Adapter {
    fn candidate(&mut self, pid: u32) -> Option<Arc<OwnedFd>> {
        self.0.borrow().get(&pid).map(|(fd, _)| fd.clone())
    }
    fn sample(&mut self, original: &OwnedFd) -> Membership {
        self.0
            .borrow()
            .values()
            .find(|(fd, _)| fd.as_raw_fd() == original.as_raw_fd())
            .map_or(Membership::Unavailable, |(_, m)| *m)
    }
}
impl Adapter {
    pub(super) fn new() -> Self {
        Self(Rc::new(RefCell::new(BTreeMap::new())))
    }
    pub(super) fn bind(&self, pid: u32, cookie: u64) {
        let fd: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        self.0
            .borrow_mut()
            .insert(pid, (Arc::new(fd), Membership::Live { domain: 1, cookie }));
    }
    fn sample(&self, pid: u32, sample: Membership) {
        self.0.borrow_mut().get_mut(&pid).unwrap().1 = sample;
    }
}
fn plan() -> crate::plan::AttachPlan {
    crate::plan::AttachPlan::from_slots(
        [
            "C_OpenSession",
            "C_SignInit",
            "C_Sign",
            "C_Finalize",
            "C_AsyncGetID",
            "C_AsyncJoin",
            "C_AsyncComplete",
            "C_GetInfo",
            "C_CloseSession",
            "C_CloseAllSessions",
            // H9 E20: appended, so slots 0-9 never shift.
            "C_Initialize",
        ]
        .into_iter()
        .enumerate()
        .map(|(index, name)| crate::plan::Slot {
            index: index as u32,
            descriptor_index: crate::kinds::function_id(name).unwrap() + 1,
            object: crate::plan::TEST_PINNED_OBJECT,
            object_path: "/opt/p11.so".into(),
            file_offset: index as u64 * 16,
            names: vec![name.into()],
            aliased: false,
            semantics: crate::kinds::descriptor(name).unwrap(),
            semantic_authorized: true,
            semantic_ambiguous: false,
            fork_safe: true,
            module_ids: vec![crate::plan::ModuleId(0)],
        })
        .collect(),
    )
}
fn ev(pid: u32, cookie: u64, exec_id: u64, slot: u32) -> Event {
    Event {
        image: ImageIdentity {
            task_cookie: cookie,
            exec_id,
        },
        event_type: event_type::CALL,
        pid_tgid: u64::from(pid) << 32,
        session: 7,
        slot_id: 3,
        slot,
        capture: capture::OUTPUT_NON_NULL,
        ..Event::default()
    }
}
fn setup(limit: usize) -> (semantics::State, process::Tracker, Adapter) {
    let adapter = Adapter::new();
    adapter.bind(100, 90);
    adapter.bind(200, 20);
    let tracker = process::Tracker::with_membership(1, limit, limit, Box::new(adapter.clone()));
    (semantics::State::new(&plan()), tracker, adapter)
}
fn feed(
    state: &mut semantics::State,
    tracker: &mut process::Tracker,
    events: impl IntoIterator<Item = Event>,
) {
    let mut drain = EventDrain::over_test_domain(ScriptedRecords::events(events, usize::MAX), 1);
    drain_profile_events(&mut drain, state, tracker, &scope(), None).unwrap();
    assert_eq!(drain.source().remaining(), 0);
}
fn scope() -> Scope {
    Scope::Cgroup {
        id: 0,
        path: "/".into(),
        dir: Arc::new(std::fs::File::open("/").unwrap()),
    }
}
fn vector(s: &semantics::State) -> (u64, u64, u64, u64, u64, u64) {
    let v = s.sessions();
    (
        v.opened,
        v.inherited,
        v.closed,
        v.opened
            .saturating_add(v.inherited)
            .saturating_sub(v.closed),
        v.peak_concurrent,
        s.pending_at_end(),
    )
}
fn key(cookie: u64, exec_id: u64) -> semantics::ProcessKey {
    semantics::ProcessKey::history(1, cookie, exec_id, 100)
}

#[test]
fn history_first_call_exec_zero_finalize_reinitialize_and_empty_watermark() {
    let (mut s, mut t, _) = setup(16);
    feed(&mut s, &mut t, [ev(100, 90, 0, 0)]);
    assert_eq!(vector(&s), (1, 0, 0, 1, 1, 0));
    let mut init = ev(100, 90, 0, 1);
    init.capture = capture::MECHANISM_VALUE;
    init.mechanism = 1;
    feed(&mut s, &mut t, [init, ev(100, 90, 0, 2)]);
    assert_eq!(s.mechanisms()[&1].calls, 2);
    feed(&mut s, &mut t, [ev(100, 90, 0, 3)]);
    assert!(!s.has_process_state(key(90, 0)));
    feed(&mut s, &mut t, [ev(100, 90, 1, 7), ev(100, 90, 0, 0)]);
    assert_eq!(vector(&s), (1, 0, 1, 0, 1, 0));
    assert_eq!(s.semantic_evidence().semantic_history_drops, 1);
    feed(
        &mut s,
        &mut t,
        [ev(100, 90, 1, 0), ev(100, 90, 1, 3), ev(100, 90, 1, 0)],
    );
    assert_eq!(vector(&s), (3, 0, 2, 1, 1, 0));
}

#[test]
fn history_birth_fork_once_before_child_call_and_exact_death() {
    let (mut s, mut t, a) = setup(16);
    feed(&mut s, &mut t, [ev(100, 90, 0, 0)]);
    let mut birth = ev(100, 90, 0, 0);
    birth.event_type = event_type::FORK;
    birth.session = 200;
    birth.child_image = ImageIdentity {
        task_cookie: 20,
        exec_id: 0,
    };
    feed(&mut s, &mut t, [birth]);
    assert_eq!(vector(&s), (1, 1, 0, 2, 2, 0));
    assert!(
        s.session_pseudonym_process(semantics::ProcessKey::history(1, 20, 0, 200), 0, 7)
            .is_some()
    );
    feed(&mut s, &mut t, [birth]);
    assert_eq!(vector(&s), (1, 1, 0, 2, 2, 0));
    feed(&mut s, &mut t, [ev(200, 20, 0, 2), birth]);
    assert_eq!(vector(&s), (1, 1, 0, 2, 2, 0));
    assert_eq!(s.semantic_evidence().semantic_history_drops, 2);
    a.sample(100, Membership::Exited);
    assert!(t.poll_exited().is_empty());
    apply_confirmed_retirement(&mut t, &mut s, key(90, 0));
    assert_eq!(vector(&s), (1, 1, 1, 1, 2, 0));
    assert!(t.poll_exited().is_empty());
    assert_eq!(s.sessions().closed, 1);
    a.sample(200, Membership::Exited);
    assert!(t.poll_exited().is_empty());
    apply_confirmed_retirement(
        &mut t,
        &mut s,
        semantics::ProcessKey::history(1, 20, 0, 200),
    );
    assert_eq!(vector(&s), (1, 1, 2, 0, 2, 0));
}

#[test]
fn history_registry_exec_bump_clears_forked_latch() {
    // Internal state-contract test: an exec-id bump clears the current
    // image's inherited-fork latch; this is not a second authentic birth.
    let domain = crate::events::EventsDomain::test_standin(1);
    let mut registry = crate::history::Registry::new(domain, 4);
    let parent = key(90, 0);
    let child = semantics::ProcessKey::history(1, 20, 0, 200);
    let child_image = ImageIdentity {
        task_cookie: 20,
        exec_id: 0,
    };
    assert_eq!(
        registry
            .admit(
                1,
                100,
                ImageIdentity {
                    task_cookie: 90,
                    exec_id: 0,
                },
                0,
            )
            .0,
        Some(parent)
    );
    assert_eq!(registry.admit(1, 200, child_image, 0).0, Some(child));
    assert!(registry.birth(parent, child));

    let current = semantics::ProcessKey::history(1, 20, 1, 200);
    assert_eq!(
        registry
            .admit(
                1,
                200,
                ImageIdentity {
                    task_cookie: 20,
                    exec_id: 1,
                },
                0,
            )
            .0,
        Some(current)
    );
    assert!(
        registry.birth(parent, current),
        "current image's forked latch must clear after exec-id bump"
    );
}

#[test]
fn history_same_cookie_exec_closes_before_open_and_late_old_never_reduces() {
    let (mut s, mut t, _) = setup(16);
    feed(&mut s, &mut t, [ev(100, 90, 0, 0)]);
    let mut pending = ev(100, 90, 0, 2);
    pending.rv = pkcs11_types::CkRv::PENDING.0;
    feed(&mut s, &mut t, [pending]);
    assert_eq!(vector(&s), (1, 0, 0, 1, 1, 1));
    feed(&mut s, &mut t, [ev(100, 90, 1, 0)]);
    assert_eq!(vector(&s), (2, 0, 1, 1, 1, 0));
    feed(
        &mut s,
        &mut t,
        [ev(100, 90, 0, 1), pending, ev(100, 90, 0, 0)],
    );
    assert_eq!(vector(&s), (2, 0, 1, 1, 1, 0));
    assert_eq!(s.semantic_evidence().semantic_history_drops, 3);
    assert!(s.session_pseudonym_process(key(90, 1), 0, 7).is_some());
    feed(&mut s, &mut t, [ev(100, 90, 1, 3), ev(100, 90, 1, 0)]);
    assert_eq!(vector(&s), (3, 0, 2, 1, 1, 0));
}

#[test]
fn exit_tap_retires_by_kernel_time_and_spares_reuse_successor() {
    // B1 step-1 twin: a tapped exit retires the old generation's
    // maps by kernel time (`first_ts_ns` strictly before the hook),
    // frees its R10 entry with keys refunded, and spares a reused
    // pid's successor admitted after the exit; a `first_ts_ns ==
    // hook_ts_ns` tie retires nothing and counts the skip. Fails
    // while exit matching is unwired: nothing is due.
    let (mut s, mut t, _) = setup(64);
    let mut first = ev(100, 90, 0, 0);
    first.ts_ns = 100;
    let mut init = ev(100, 90, 0, 1);
    init.ts_ns = 101;
    init.capture = capture::MECHANISM_VALUE;
    init.mechanism = 1;
    feed(&mut s, &mut t, [first, init]);
    assert_eq!(vector(&s), (1, 0, 0, 1, 1, 0));
    let old = key(90, 0);
    assert!(s.has_process_state(old));
    assert_eq!(s.memory_lens().reduced.len, 1);
    // The old generation exits at hook 200; the transfer stamps a
    // future EVENTS producer position, so this twin drives the retire
    // mechanism directly (drain-driven retire is the step-3 twin).
    t.note_exit_taps(
        vec![crate::history::ExitTap {
            pid: 100,
            hook_ts_ns: 200,
        }],
        1000,
    );
    assert_eq!(t.pending_exit_taps_for_test(), 1);
    // The pid is reused before the exit retires: the successor's
    // first CALL (ts 300, after the old exit) admits a new generation.
    let mut reborn = ev(100, 91, 0, 0);
    reborn.ts_ns = 300;
    let mut reborn_init = ev(100, 91, 0, 1);
    reborn_init.ts_ns = 301;
    reborn_init.capture = capture::MECHANISM_VALUE;
    reborn_init.mechanism = 1;
    feed(&mut s, &mut t, [reborn, reborn_init]);
    let successor = semantics::ProcessKey::history(1, 91, 0, 100);
    assert!(s.has_process_state(successor));
    assert_eq!(vector(&s), (2, 0, 0, 2, 2, 0));
    assert_eq!(s.memory_lens().active_ops.len, 2);
    // The drain reads past the tap position: the old generation's
    // maps are freed and its R10 entry is gone, while the successor's
    // rows are intact.
    let due = t.retire_exits_due(1000, 1000, EXIT_RETIRE_PER_DRAIN_BUDGET);
    assert_eq!(due, std::collections::BTreeSet::from([old]));
    s.retire_processes(&due);
    assert!(!s.has_process_state(old));
    assert!(s.has_process_state(successor));
    assert_eq!(vector(&s), (2, 0, 1, 1, 2, 0));
    let lens = s.memory_lens();
    assert_eq!(lens.reduced.len, 1, "only the successor keeps R10");
    assert_eq!(lens.open.len, 1, "only the successor keeps a session");
    assert_eq!(lens.active_ops.len, 1, "only the successor keeps an op");
    assert_eq!(t.exit_counters_for_test(), (0, 0, 0, 0));
    assert_eq!(t.pending_exit_taps_for_test(), 0);
    // A first_ts_ns == hook_ts_ns tie retires neither generation and
    // counts the skip instead.
    let mut tied = ev(101, 92, 0, 0);
    tied.ts_ns = 200;
    feed(&mut s, &mut t, [tied]);
    let tied_key = semantics::ProcessKey::history(1, 92, 0, 101);
    t.note_exit_taps(
        vec![crate::history::ExitTap {
            pid: 101,
            hook_ts_ns: 200,
        }],
        1000,
    );
    let due = t.retire_exits_due(1000, 1000, EXIT_RETIRE_PER_DRAIN_BUDGET);
    assert!(due.is_empty(), "ties never retire");
    assert!(s.has_process_state(tied_key));
    assert_eq!(t.exit_counters_for_test(), (1, 0, 0, 0));
    // Repeating a retire is safe: a duplicate tap for the same exit
    // re-collects the same key and the batch frees nothing twice.
    t.note_exit_taps(
        vec![crate::history::ExitTap {
            pid: 100,
            hook_ts_ns: 200,
        }],
        1000,
    );
    let due = t.retire_exits_due(1000, 1000, EXIT_RETIRE_PER_DRAIN_BUDGET);
    assert_eq!(due, std::collections::BTreeSet::from([old]));
    let closed = s.sessions().closed;
    s.retire_processes(&due);
    assert_eq!(s.sessions().closed, closed, "no double close");
    assert!(s.has_process_state(successor));
    assert_eq!(t.exit_counters_for_test(), (2, 0, 0, 0));
}

#[test]
fn tie_exit_drops_immediately_with_single_count() {
    // F2 twin: a `first_ts_ns == hook_ts_ns` tie can never match on
    // retry, so the exit drops on the first position-passing drain
    // with its own named outcome (one tie count, no requeue, never
    // unmatched). Fails while ties retry: pending stays 1 and the tie
    // recounts, then miscounts as unmatched.
    let (mut s, mut t, _) = setup(64);
    let mut tied = ev(101, 92, 0, 0);
    tied.ts_ns = 200;
    feed(&mut s, &mut t, [tied]);
    let tied_key = semantics::ProcessKey::history(1, 92, 0, 101);
    t.note_exit_taps(
        vec![crate::history::ExitTap {
            pid: 101,
            hook_ts_ns: 200,
        }],
        1000,
    );
    assert_eq!(t.pending_exit_taps_for_test(), 1);
    for drain in 1..=3 {
        let due = t.retire_exits_due(1000, 1000, EXIT_RETIRE_PER_DRAIN_BUDGET);
        assert!(due.is_empty(), "ties never retire (drain {drain})");
        assert_eq!(
            t.pending_exit_taps_for_test(),
            0,
            "tie drops on the first drain (drain {drain})"
        );
        assert_eq!(
            t.exit_counters_for_test(),
            (1, 0, 0, 0),
            "one tie, never unmatched (drain {drain})"
        );
    }
    assert!(
        s.has_process_state(tied_key),
        "tied rows are retained, never freed"
    );
}

#[test]
fn retire_waits_for_drain_past_tap_position() {
    // B1 step-3 twin: an exit tapped while a late CALL is still in
    // staging retires only after the drain reads past the tap-time
    // producer position — the CALL is admitted first, never
    // `reject_unadmitted` — and an unmatched exit retries two
    // position-passing drains, then drops with a counted gap. Fails
    // while the drains consume no exits: nothing ever retires.
    use crate::discovery::engine::Engine;
    let (mut s, mut t, _) = setup(64);
    let mut first = ev(100, 90, 0, 0);
    first.ts_ns = 100;
    let mut drain = EventDrain::over_test_domain(
        crate::events::StagedEvents::with_caps(
            ScriptedRecords::events([first], usize::MAX),
            1024,
            1024 * 1024,
        ),
        1,
    );
    drain_profile_events(&mut drain, &mut s, &mut t, &scope(), None).unwrap();
    assert_eq!(vector(&s), (1, 0, 0, 1, 1, 0));
    let old = key(90, 0);
    // A late CALL from the same process is staged but not yet
    // reduced when the exit is captured and transferred.
    let mut late = ev(100, 90, 0, 2);
    late.ts_ns = 150;
    drain.source_mut().inner_mut().push_event(&late);
    drain.source_mut().stage(1, None);
    let mut engine = Engine::empty_for_test();
    engine.note_exit_tap(100, 200);
    let stamp = crate::events::event_drain_positions(&drain).producer;
    transfer_exit_taps(&mut engine, &mut t, stamp);
    assert_eq!(t.pending_exit_taps_for_test(), 1);
    // A drain that reads nothing does not pass the tap position:
    // nothing retires.
    drain_profile_events(&mut drain, &mut s, &mut t, &scope(), Some(0)).unwrap();
    assert!(s.has_process_state(old));
    assert_eq!(t.pending_exit_taps_for_test(), 1);
    // The full drain reduces the staged CALL first — admitted, never
    // refused — and only then, past the tap position, retires.
    drain_profile_events(&mut drain, &mut s, &mut t, &scope(), None).unwrap();
    assert_eq!(s.semantic_evidence().semantic_history_drops, 0);
    assert!(!s.has_process_state(old));
    assert_eq!(vector(&s), (1, 0, 1, 0, 1, 0));
    assert_eq!(t.pending_exit_taps_for_test(), 0);
    // An exit with no matching task retries two position-passing
    // drains, then drops with the counted gap.
    engine.note_exit_tap(999, 300);
    let stamp = crate::events::event_drain_positions(&drain).producer;
    transfer_exit_taps(&mut engine, &mut t, stamp);
    for _ in 0..2 {
        drain_profile_events(&mut drain, &mut s, &mut t, &scope(), None).unwrap();
        assert_eq!(t.pending_exit_taps_for_test(), 1);
        assert_eq!(t.exit_counters_for_test(), (0, 0, 0, 0));
    }
    drain_profile_events(&mut drain, &mut s, &mut t, &scope(), None).unwrap();
    assert_eq!(t.pending_exit_taps_for_test(), 0);
    assert_eq!(t.exit_counters_for_test(), (0, 1, 0, 0));
    // Strictly-past retire: the drain reads beyond the stamp while new
    // records keep arriving — due without waiting for quiet.
    let mut fresh = ev(200, 93, 0, 0);
    fresh.ts_ns = 100;
    drain.source_mut().inner_mut().push_event(&fresh);
    drain_profile_events(&mut drain, &mut s, &mut t, &scope(), None).unwrap();
    let fresh_key = semantics::ProcessKey::history(1, 93, 0, 200);
    assert!(s.has_process_state(fresh_key));
    engine.note_exit_tap(200, 200);
    let stamp = crate::events::event_drain_positions(&drain).producer;
    transfer_exit_taps(&mut engine, &mut t, stamp);
    let mut next = ev(200, 93, 0, 7);
    next.ts_ns = 150;
    let mut later = ev(200, 93, 0, 7);
    later.ts_ns = 151;
    drain.source_mut().inner_mut().push_event(&next);
    drain.source_mut().inner_mut().push_event(&later);
    drain_profile_events(&mut drain, &mut s, &mut t, &scope(), Some(1)).unwrap();
    assert!(!s.has_process_state(fresh_key));
    assert_eq!(t.pending_exit_taps_for_test(), 0);
    assert_eq!(t.exit_counters_for_test(), (0, 1, 0, 0));
}

#[test]
fn exec_bump_resets_exit_matching_generation() {
    // Exit-matching generation twin: an exec-id bump resets the task's
    // first_ts_ns, so an exit older than the exec never retires the new
    // generation. Direct registry drive: admission plus matching only.
    let domain = crate::events::EventsDomain::test_standin(1);
    let mut registry = crate::history::Registry::new(domain, 16);
    let image0 = ImageIdentity {
        task_cookie: 90,
        exec_id: 0,
    };
    assert!(registry.admit(1, 100, image0, 100).0.is_some());
    let image1 = ImageIdentity {
        task_cookie: 90,
        exec_id: 1,
    };
    let (current, retired) = registry.admit(1, 100, image1, 250);
    assert!(current.is_some());
    assert_eq!(retired.len(), 1);
    // An exit hooked between the original admit and the exec matches
    // nothing: the live generation started after it.
    registry.note_exit_taps(
        vec![crate::history::ExitTap {
            pid: 100,
            hook_ts_ns: 200,
        }],
        8,
    );
    let due = registry.retire_exits_due(8, 8, EXIT_RETIRE_PER_DRAIN_BUDGET);
    assert!(due.is_empty(), "the post-exec generation is spared");
}

#[test]
fn retired_cookie_reopens_and_clears_exit_timestamp() {
    // B1 step-4 twin: exit-retire never sets `closed`; an event on a
    // retired cookie with a timestamp after the exit reopens the task,
    // clears the exit timestamp, counts `exit_retire_reopened`, and is
    // never refused; an event timestamped at or before the exit counts
    // `exit_retire_late` and is still admitted. Fails while admission
    // ignores the exit timestamp: nothing reopens or counts late.
    let (mut s, mut t, _) = setup(64);
    let mut first = ev(100, 90, 0, 0);
    first.ts_ns = 100;
    feed(&mut s, &mut t, [first]);
    let cookie = key(90, 0);
    // Exit at hook 200, retired past a future stamp.
    t.note_exit_taps(
        vec![crate::history::ExitTap {
            pid: 100,
            hook_ts_ns: 200,
        }],
        1000,
    );
    let due = t.retire_exits_due(1000, 1000, EXIT_RETIRE_PER_DRAIN_BUDGET);
    assert_eq!(due, std::collections::BTreeSet::from([cookie]));
    s.retire_processes(&due);
    assert!(!s.has_process_state(cookie));
    // A thread CALL after the exit reopens: admitted, never refused,
    // and the exit timestamp clears.
    let mut thread = ev(100, 90, 0, 0);
    thread.ts_ns = 250;
    feed(&mut s, &mut t, [thread]);
    assert_eq!(s.semantic_evidence().semantic_history_drops, 0);
    assert!(s.has_process_state(cookie));
    assert_eq!(t.exit_counters_for_test(), (0, 0, 1, 0));
    // With the timestamp cleared, an older event counts nothing late.
    let mut older = ev(100, 90, 0, 2);
    older.ts_ns = 150;
    feed(&mut s, &mut t, [older]);
    assert_eq!(s.semantic_evidence().semantic_history_drops, 0);
    assert_eq!(t.exit_counters_for_test(), (0, 0, 1, 0));
    // A second exit retires again; events at or before its hook count
    // late — twice proves the timestamp stays set — yet still admit.
    t.note_exit_taps(
        vec![crate::history::ExitTap {
            pid: 100,
            hook_ts_ns: 300,
        }],
        1000,
    );
    let due = t.retire_exits_due(1000, 1000, EXIT_RETIRE_PER_DRAIN_BUDGET);
    assert_eq!(due, std::collections::BTreeSet::from([cookie]));
    s.retire_processes(&due);
    assert!(!s.has_process_state(cookie));
    for ts in [250, 260] {
        let mut late = ev(100, 90, 0, 0);
        late.ts_ns = ts;
        feed(&mut s, &mut t, [late]);
    }
    assert_eq!(s.semantic_evidence().semantic_history_drops, 0);
    assert!(s.has_process_state(cookie), "late events still admit");
    assert_eq!(t.exit_counters_for_test(), (0, 0, 1, 2));
}

#[test]
fn trace_drain_retires_exits_like_profile() {
    // B1 step-5 twin: an exit tapped on the trace path retires through
    // the trace drain once past the tap position — State rows freed,
    // the exit timestamp set, `closed` never set. Fails while the trace
    // drain consumes no exits: nothing ever retires.
    use crate::discovery::engine::Engine;
    let (mut s, mut t, _) = setup(64);
    let mut first = ev(100, 90, 0, 0);
    first.ts_ns = 100;
    let mut drain = EventDrain::over_test_domain(ScriptedRecords::events([first], usize::MAX), 1);
    let mut tracer = trace::Tracer::new(&plan());
    let mut output = Vec::new();
    drain_trace_events_from(
        &mut drain,
        &mut None,
        &mut s,
        &mut t,
        &scope(),
        &mut tracer,
        &mut output,
        &mut true,
        &mut None::<Vec<u8>>,
        None,
    )
    .unwrap();
    assert_eq!(vector(&s), (1, 0, 0, 1, 1, 0));
    let old = key(90, 0);
    let mut engine = Engine::empty_for_test();
    engine.note_exit_tap(100, 200);
    let stamp = crate::events::event_drain_positions(&drain).producer;
    transfer_exit_taps(&mut engine, &mut t, stamp);
    drain_trace_events_from(
        &mut drain,
        &mut None,
        &mut s,
        &mut t,
        &scope(),
        &mut tracer,
        &mut output,
        &mut true,
        &mut None::<Vec<u8>>,
        None,
    )
    .unwrap();
    assert!(!s.has_process_state(old));
    assert_eq!(vector(&s), (1, 0, 1, 0, 1, 0));
    assert_eq!(t.pending_exit_taps_for_test(), 0);
    // `closed` was never set: a post-exit event reopens the task
    // instead of being refused.
    let image = ImageIdentity {
        task_cookie: 90,
        exec_id: 0,
    };
    assert!(t.admit_history(1, 100, image, 250).0.is_some());
    assert_eq!(t.exit_counters_for_test(), (0, 0, 1, 0));
}

#[test]
fn token_gated_root_completion_still_retires_exactly_once() {
    // B1 step-6 twin: a root-completed (closed) task is excluded from
    // exit matching, so an exit plus a token-gated root completion of
    // the same key retires exactly once — sessions.closed moves once,
    // rows are freed once, and the unmatched exit drops with its gap.
    // The history path keeps the R10 entry (only the exit path frees
    // it), so no second refund exists to double-spend.
    let plan = plan();
    let domain = crate::events::EventsDomain::test_standin(1);
    let mut state =
        semantics::State::for_capture(&plan, CapturePolicy::Allowlisted, domain.clone());
    let mut tracker = process::Tracker::for_producer(domain.clone(), 64);
    let mut positive = ev(100, 90, 0, 0);
    positive.root_affiliation = 1;
    positive.ts_ns = 100;
    feed(&mut state, &mut tracker, [positive]);
    let completed = key(90, 0);
    assert!(state.has_process_state(completed));
    // Token-gated root completion closes the task and retires it. The
    // tail reduces a rowless call, not a second open of the same handle
    // (re-observing an open supersede-closes it by existing semantics).
    let mut tail_call = ev(100, 90, 0, 2);
    tail_call.ts_ns = 150;
    let mut drain = EventDrain::over_domain(
        crate::events::root_fence_tests::source([tail_call]),
        domain.clone(),
    );
    let mut tail = crate::events::OwnedRootTail::new(
        OriginalRootExit::test_reaped(domain),
        Instant::now() + Duration::from_secs(1),
    );
    drain.begin_root_tail(&mut tail).unwrap();
    let domain_id = drain.domain_id();
    assert_eq!(
        drain
            .poll_root_tail(&mut tail, 8, |event| reduce_profile_event(
                domain_id,
                &mut tracker,
                &mut state,
                &scope(),
                event
            ))
            .unwrap(),
        crate::events::RootTailProgress::Reached
    );
    apply_original_root_retirement(&mut tracker, &mut state, tail.complete().unwrap()).unwrap();
    assert!(!state.has_process_state(completed));
    assert_eq!(state.sessions().closed, 1);
    assert_eq!(
        state.memory_lens().reduced.len,
        1,
        "the history path keeps the R10 entry"
    );
    // A later exit for the pid matches no open task: the closed task
    // is excluded, so the exit retries, then drops unmatched — and
    // sessions.closed still counts the single retirement.
    tracker.note_exit_taps(
        vec![crate::history::ExitTap {
            pid: 100,
            hook_ts_ns: 200,
        }],
        1000,
    );
    for _ in 0..2 {
        let due = tracker.retire_exits_due(1000, 1000, EXIT_RETIRE_PER_DRAIN_BUDGET);
        assert!(due.is_empty(), "closed tasks never match an exit");
    }
    assert_eq!(tracker.pending_exit_taps_for_test(), 1);
    let due = tracker.retire_exits_due(1000, 1000, EXIT_RETIRE_PER_DRAIN_BUDGET);
    assert!(due.is_empty());
    assert_eq!(tracker.pending_exit_taps_for_test(), 0);
    assert_eq!(tracker.exit_counters_for_test(), (0, 1, 0, 0));
    assert_eq!(state.sessions().closed, 1, "retired exactly once");
}

#[test]
fn exit_retire_budget_carries_unexamined_exits_to_the_next_drain() {
    // Budget twin: one retire call examines at most `budget` exits in
    // tap order; due-but-unexamined exits carry over to the next drain
    // instead of dropping.
    let (mut s, mut t, _) = setup(64);
    for (pid, cookie) in [(100u32, 90u64), (101, 91), (102, 92)] {
        let mut first = ev(pid, cookie, 0, 0);
        first.ts_ns = 100;
        feed(&mut s, &mut t, [first]);
    }
    t.note_exit_taps(
        (100u32..=102).map(|pid| crate::history::ExitTap {
            pid,
            hook_ts_ns: 200,
        }),
        1000,
    );
    let first = semantics::ProcessKey::history(1, 90, 0, 100);
    let second = semantics::ProcessKey::history(1, 91, 0, 101);
    let third = semantics::ProcessKey::history(1, 92, 0, 102);
    let due = t.retire_exits_due(1000, 1000, 2);
    assert_eq!(due, std::collections::BTreeSet::from([first, second]));
    assert_eq!(t.pending_exit_taps_for_test(), 1);
    s.retire_processes(&due);
    let due = t.retire_exits_due(1000, 1000, 2);
    assert_eq!(due, std::collections::BTreeSet::from([third]));
    assert_eq!(t.pending_exit_taps_for_test(), 0);
    s.retire_processes(&due);
    assert_eq!(s.sessions().closed, 3);
}

/// Collects `(json path, before, after)` for every value that differs
/// between two rendered documents.
fn json_diffs(
    before: &serde_json::Value,
    after: &serde_json::Value,
    path: String,
    out: &mut Vec<(String, serde_json::Value, serde_json::Value)>,
) {
    if before == after {
        return;
    }
    match (before, after) {
        (serde_json::Value::Object(a), serde_json::Value::Object(b)) => {
            let mut keys = std::collections::BTreeSet::new();
            keys.extend(a.keys());
            keys.extend(b.keys());
            for key in keys {
                let child = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                let left = a.get(key).unwrap_or(&serde_json::Value::Null);
                let right = b.get(key).unwrap_or(&serde_json::Value::Null);
                json_diffs(left, right, child, out);
            }
        }
        (serde_json::Value::Array(a), serde_json::Value::Array(b)) => {
            for (index, (left, right)) in a.iter().zip(b.iter()).enumerate() {
                json_diffs(left, right, format!("{path}[{index}]"), out);
            }
            if a.len() != b.len() {
                out.push((path, before.clone(), after.clone()));
            }
        }
        _ => out.push((path, before.clone(), after.clone())),
    }
}

#[test]
fn retired_sessions_count_as_closed_declared_diff() {
    // B1 step-7 twin (declared correction): exit-retired sessions count
    // as closed, so `sessions.closed`, the session balance, and "N still
    // open" move — by exactly the retired sessions, and nothing else in
    // either the profile JSON or the text moves. Byte-diffs both renders
    // of the same capture with and without the exit retire.
    let (mut s, mut t, _) = setup(64);
    let mut first = ev(100, 90, 0, 0);
    first.ts_ns = 100;
    let mut second = ev(101, 91, 0, 0);
    second.ts_ns = 100;
    feed(&mut s, &mut t, [first, second]);
    let render_json = |state: &semantics::State| {
        let mut ev = crate::render::tests::evidence();
        ev.verdict();
        crate::render::profile_json(
            &[],
            crate::render::VersionedEvidence::wrap(&ev),
            state,
            &crate::render::CaptureMeta {
                started: "t0",
                ended: "t1",
                kernel: "6.8.0",
                policy: CapturePolicy::Allowlisted,
                scope: "system",
                caller: None,
                ring_bytes: p11scope_ebpf_common::RING_BYTES,
                drain_interval_ms: 1000,
            },
        )
    };
    let render_text = |state: &semantics::State| {
        let mut ev = crate::render::tests::evidence();
        ev.verdict();
        crate::render::live_scoped_with_verbosity_and_sessions(
            &[],
            &ev,
            std::time::Duration::from_secs(60),
            "provider",
            "profile",
            CapturePolicy::Allowlisted,
            "system",
            state.mechanisms(),
            crate::cli::TextVerbosity::Concise,
            &state.sessions(),
            state.logins(),
        )
    };
    let json_before = render_json(&s);
    let text_before = render_text(&s);
    // Exit-retire the first process past a future stamp.
    t.note_exit_taps(
        vec![crate::history::ExitTap {
            pid: 100,
            hook_ts_ns: 200,
        }],
        1000,
    );
    let due = t.retire_exits_due(1000, 1000, EXIT_RETIRE_PER_DRAIN_BUDGET);
    s.retire_processes(&due);
    let json_after = render_json(&s);
    let text_after = render_text(&s);
    // The JSON moves in exactly the two session-balance fields, by
    // exactly the one retired session.
    let mut diffs = Vec::new();
    json_diffs(&json_before, &json_after, String::new(), &mut diffs);
    diffs.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(
        diffs,
        vec![
            (
                "sessions.balance".to_string(),
                serde_json::json!(2),
                serde_json::json!(1),
            ),
            (
                "sessions.closed".to_string(),
                serde_json::json!(0),
                serde_json::json!(1),
            ),
        ]
    );
    // The text moves in exactly the sessions line, by the same session.
    let before_lines: Vec<&str> = text_before.lines().collect();
    let after_lines: Vec<&str> = text_after.lines().collect();
    assert_eq!(before_lines.len(), after_lines.len());
    let line_diffs: Vec<(usize, &str, &str)> = before_lines
        .iter()
        .zip(after_lines.iter())
        .enumerate()
        .filter(|(_, (left, right))| left != right)
        .map(|(index, (left, right))| (index, *left, *right))
        .collect();
    assert_eq!(line_diffs.len(), 1, "only the sessions line moves");
    let (_, left, right) = line_diffs[0];
    assert!(
        left.contains("2 still open"),
        "before names two open sessions: {left}"
    );
    assert!(
        right.contains("1 still open"),
        "after names one open session: {right}"
    );
}

#[test]
fn churned_processes_free_all_dead_owned_rows_on_exit() {
    // B1 step-8 fixture: eight short-lived processes churn through one
    // drain — each opening a session, starting an op, and leaving a
    // pending call — then all exit. The A0 dead-owned lens proves the
    // effect: before the exits drain, every R12 row reads dead-owned;
    // after, no process owns rows and every dead count returns to zero.
    let (mut s, mut t, _) = setup(64);
    let mut events = Vec::new();
    for i in 0..8u32 {
        let pid = 1000 + i;
        let cookie = u64::from(100 + i);
        let mut open = ev(pid, cookie, 0, 0);
        open.ts_ns = 100;
        let mut init = ev(pid, cookie, 0, 1);
        init.ts_ns = 101;
        init.capture = capture::MECHANISM_VALUE;
        init.mechanism = 1;
        let mut pending = ev(pid, cookie, 0, 2);
        pending.ts_ns = 102;
        pending.rv = pkcs11_types::CkRv::PENDING.0;
        events.extend([open, init, pending]);
    }
    let mut drain = EventDrain::over_test_domain(ScriptedRecords::events(events, usize::MAX), 1);
    drain_profile_events(&mut drain, &mut s, &mut t, &scope(), None).unwrap();
    assert_eq!(vector(&s), (8, 0, 0, 8, 8, 8));
    // Every test pid reads dead: all rows are dead-owned before retire.
    let all_dead = |_: u32| false;
    let (live, dead, dead_rows, _) = s.memory_sample(&all_dead);
    assert_eq!((live, dead), (0, 8));
    assert_eq!(dead_rows.reduced_dead.len, 8);
    assert_eq!(dead_rows.open_dead.len, 8);
    assert_eq!(dead_rows.active_ops_dead.len, 8);
    assert_eq!(dead_rows.next_pseudonym_dead.len, 8);
    assert_eq!(dead_rows.pending_dead.len, 8);
    // All eight exit; the transfer stamps the producer, and one more
    // drain past the stamp retires every generation.
    t.note_exit_taps(
        (0..8u32).map(|i| crate::history::ExitTap {
            pid: 1000 + i,
            hook_ts_ns: 200,
        }),
        crate::events::event_drain_positions(&drain).producer,
    );
    let mut trigger = ev(1000, 100, 0, 7);
    trigger.ts_ns = 150;
    drain.source_mut().push_event(&trigger);
    drain_profile_events(&mut drain, &mut s, &mut t, &scope(), None).unwrap();
    // Everything freed: no owners remain, every dead count is zero,
    // every session counted closed, no exit gap fired.
    let (live, dead, dead_rows, _) = s.memory_sample(&all_dead);
    assert_eq!((live, dead), (0, 0));
    for (name, len) in [
        ("R10", dead_rows.reduced_dead.len),
        ("open", dead_rows.open_dead.len),
        ("active_ops", dead_rows.active_ops_dead.len),
        ("next_pseudonym", dead_rows.next_pseudonym_dead.len),
        ("find_active", dead_rows.find_active_dead.len),
        ("pending", dead_rows.pending_dead.len),
        ("detached", dead_rows.detached_dead.len),
        (
            "inherited_ambiguous",
            dead_rows.inherited_ambiguous_dead.len,
        ),
    ] {
        assert_eq!(len, 0, "no dead-owned {name} rows remain");
    }
    let lens = s.memory_lens();
    for (name, len) in [
        ("R10", lens.reduced.len),
        ("open", lens.open.len),
        ("active_ops", lens.active_ops.len),
        ("next_pseudonym", lens.next_pseudonym.len),
        ("pending", lens.pending.len),
    ] {
        assert_eq!(len, 0, "no {name} rows remain at all");
    }
    assert_eq!(s.sessions().closed, 8);
    assert_eq!(t.exit_counters_for_test(), (0, 0, 0, 0));
    assert_eq!(t.pending_exit_taps_for_test(), 0);
}

#[test]
fn history_cookie_fd_and_pid_changes_never_order_independent_producer_histories() {
    let (mut s, mut t, a) = setup(16);
    feed(&mut s, &mut t, [ev(100, 90, 0, 0)]);
    a.sample(100, Membership::Unavailable);
    feed(&mut s, &mut t, [ev(100, 91, 0, 0)]);
    assert_eq!(vector(&s), (2, 0, 0, 2, 2, 0));
    a.sample(
        100,
        Membership::Live {
            domain: 2,
            cookie: 90,
        },
    );
    feed(&mut s, &mut t, [ev(100, 90, 0, 7)]);
    a.sample(
        100,
        Membership::Live {
            domain: 1,
            cookie: 4,
        },
    );
    feed(&mut s, &mut t, [ev(100, 4, 9, 0)]);
    assert_eq!(vector(&s), (3, 0, 0, 3, 3, 0));
    a.bind(100, 900);
    feed(&mut s, &mut t, [ev(100, 900, 0, 0)]);
    assert_eq!(vector(&s), (4, 0, 0, 4, 4, 0));
    assert_eq!(s.semantic_evidence().semantic_history_drops, 0);
    apply_confirmed_retirement(&mut t, &mut s, key(90, 0));
    apply_confirmed_retirement(&mut t, &mut s, key(90, 0));
    assert_eq!(vector(&s), (4, 0, 1, 3, 4, 0));
    assert!(s.session_pseudonym_process(key(4, 9), 0, 7).is_some());
}

#[test]
fn history_nonactivating_state_and_tuple_domains_do_not_alias() {
    let mut s = semantics::State::new(&plan());
    let a = key(90, 0);
    let b = semantics::ProcessKey::history(2, 90, 0, 100);
    s.observe_process(a, &ev(100, 90, 0, 0));
    s.observe_process(b, &ev(100, 90, 0, 0));
    s.observe_process(a, &ev(100, 90, 0, 7));
    assert_eq!(vector(&s), (2, 0, 0, 2, 2, 0));
    s.retire_process(a);
    assert!(s.session_pseudonym_process(b, 0, 7).is_some());
    assert_eq!(vector(&s), (2, 0, 1, 1, 2, 0));
    assert_eq!(key(90, 0), semantics::ProcessKey::history(1, 90, 0, 999));
    // Direct reducer isolation is independent of the registry's exec sweep.
    // Removing the exec component of equality must fail this real-map oracle.
    let mut isolated = semantics::State::new(&plan());
    isolated.observe_process(key(90, 0), &ev(100, 90, 0, 0));
    isolated.observe_process(key(90, 1), &ev(100, 90, 1, 0));
    assert_eq!(vector(&isolated), (2, 0, 0, 2, 2, 0));
    isolated.retire_process(key(90, 0));
    assert!(
        isolated
            .session_pseudonym_process(key(90, 1), 0, 7)
            .is_some()
    );
}

#[test]
fn history_old_init_and_detached_state_cannot_enrich_successor_or_late_fork() {
    let (mut s, mut t, _) = setup(16);
    let mut init = ev(100, 90, 0, 1);
    init.capture = capture::MECHANISM_VALUE;
    init.mechanism = 1;
    let mut pending = ev(100, 90, 0, 2);
    pending.rv = pkcs11_types::CkRv::PENDING.0;
    let mut get = ev(100, 90, 0, 4);
    get.target_function = crate::kinds::function_id("C_Sign").unwrap();
    get.async_value = 123;
    feed(&mut s, &mut t, [ev(100, 90, 0, 0), init, pending, get]);
    assert_eq!(s.pending_at_end(), 1);
    assert_eq!(s.mechanisms()[&1].calls, 1);
    feed(&mut s, &mut t, [ev(100, 90, 1, 0), ev(100, 90, 1, 2)]);
    assert_eq!(vector(&s), (2, 0, 1, 1, 1, 0));
    assert_eq!(s.mechanisms()[&1].calls, 1);
    feed(&mut s, &mut t, [init]);
    assert_eq!(s.mechanisms()[&1].calls, 1);
    // Birth after the child's own CALL cannot retroactively inherit.
    feed(&mut s, &mut t, [ev(200, 20, 0, 7)]);
    let mut birth = ev(100, 90, 1, 0);
    birth.event_type = event_type::FORK;
    birth.session = 200;
    birth.child_image = ImageIdentity {
        task_cookie: 20,
        exec_id: 0,
    };
    feed(&mut s, &mut t, [birth]);
    assert_eq!(s.sessions().inherited, 0);
    assert_eq!(s.semantic_evidence().semantic_history_drops, 2);
    birth.image.exec_id = 0;
    feed(&mut s, &mut t, [birth]);
    assert_eq!(s.sessions().inherited, 0);
    assert_eq!(s.semantic_evidence().semantic_history_drops, 3);
}

/// AR-13 / AC-01. Old INIT/FORK records arriving after a replacement process
/// generation reach the real profile consumers (`observe_fork` and
/// `identify_tracked`, through `drain_profile_events`) and are refused on the
/// producer-authenticated `(domain, task_cookie, exec_id)` identity alone:
/// only count-only evidence is retained and no semantic state crosses the
/// generation boundary. Two replacements are exercised: the same task after
/// exec (cookie 90, exec 1) and a different task reusing pid 100 (cookie 91).
/// The pid-keyed stat/pidfd acquisition table (`Tracker::identify`) is never
/// consulted, and FORK `ts_ns`, which the producer leaves at zero, plays no
/// part in admission.
#[test]
fn ar13_delayed_init_and_fork_admit_only_to_the_authenticated_generation() {
    let (mut s, mut t, _) = setup(16);
    let mut init = ev(100, 90, 0, 1);
    init.capture = capture::MECHANISM_VALUE;
    init.mechanism = 1;
    feed(&mut s, &mut t, [ev(100, 90, 0, 0), init]);
    assert_eq!(vector(&s), (1, 0, 0, 1, 1, 0));
    assert_eq!(s.mechanisms()[&1].calls, 1);
    assert!(s.has_process_state(key(90, 0)));

    // Replacement 1: the same task after exec. The old generation is retired
    // in band; nothing is carried into exec 1.
    feed(&mut s, &mut t, [ev(100, 90, 1, 0)]);
    assert!(!s.has_process_state(key(90, 0)));
    assert!(s.has_process_state(key(90, 1)));
    // Replacement 2: a different task reusing pid 100.
    feed(&mut s, &mut t, [ev(100, 91, 0, 0)]);
    assert_eq!(vector(&s), (3, 0, 1, 2, 2, 0));
    assert_eq!(s.semantic_evidence().semantic_history_drops, 0);
    let counted = s.cgroups()[&0].calls;

    // Delayed old INIT and delayed old FORK, both stamped with the retired
    // generation (cookie 90, exec 0). A fresh-looking timestamp cannot rescue
    // an old generation: identity decides, not time.
    let child = semantics::ProcessKey::history(1, 20, 0, 200);
    let mut old_fork = ev(100, 90, 0, 0);
    old_fork.event_type = event_type::FORK;
    old_fork.session = 200;
    old_fork.child_image = ImageIdentity {
        task_cookie: 20,
        exec_id: 0,
    };
    old_fork.ts_ns = u64::MAX;
    feed(&mut s, &mut t, [init, old_fork]);
    assert_eq!(s.mechanisms()[&1].calls, 1, "old INIT enriched a successor");
    assert_eq!(
        s.sessions().inherited,
        0,
        "old FORK inherited into a successor"
    );
    assert!(s.session_pseudonym_process(child, 0, 7).is_none());
    assert_eq!(s.semantic_evidence().semantic_history_drops, 2);
    assert_eq!(
        s.cgroups()[&0].calls,
        counted + 1,
        "rejected CALL not counted"
    );
    assert_eq!(s.semantic_evidence().fork_state_ambiguities, 0);
    assert_eq!(vector(&s), (3, 0, 1, 2, 2, 0));
    assert!(s.has_process_state(key(90, 1)));
    assert!(s.has_process_state(key(91, 0)));

    // A FORK naming a child that already made its own CALL is refused too:
    // birth is one-shot and precedes every child CALL.
    feed(&mut s, &mut t, [ev(201, 21, 0, 7)]);
    let mut late_fork = ev(100, 90, 1, 0);
    late_fork.event_type = event_type::FORK;
    late_fork.session = 201;
    late_fork.child_image = ImageIdentity {
        task_cookie: 21,
        exec_id: 0,
    };
    feed(&mut s, &mut t, [late_fork]);
    assert_eq!(s.sessions().inherited, 0);
    assert_eq!(s.semantic_evidence().semantic_history_drops, 3);

    // The consumers never touched the pid-keyed acquisition table. The
    // tripwire holds because production trackers use `for_producer` with
    // pidfd_limit == 0, so any nonzero evidence means the pid table has
    // been re-wired. Positive control: one direct acquisition for the
    // same pid is visible there.
    assert_eq!(t.evidence(), process::TrackingEvidence::default());
    t.identify(100);
    assert_ne!(t.evidence(), process::TrackingEvidence::default());

    // FORK ts_ns is never written by the producer; an authentic first FORK is
    // admitted identically at zero, at the maximum, and older than the
    // parent's own CALL.
    for ts_ns in [0, u64::MAX, 1] {
        let (mut s, mut t, _) = setup(16);
        let mut opened = ev(100, 90, 0, 0);
        opened.ts_ns = 1_000;
        let mut birth = old_fork;
        birth.ts_ns = ts_ns;
        feed(&mut s, &mut t, [opened, birth]);
        assert_eq!(s.sessions().inherited, 1, "ts_ns={ts_ns}");
        assert!(s.session_pseudonym_process(child, 0, 7).is_some());
        assert_eq!(
            s.semantic_evidence().semantic_history_drops,
            0,
            "ts_ns={ts_ns}"
        );
    }
}

/// AR-13 defense in depth. `Registry::mark_call` was the one mutator that did
/// not authenticate its key. Its sole production caller (`identify_tracked`)
/// passes the key `admit` returned two statements earlier, so the gap is not
/// reachable through the consumers; the registry API is closed regardless, so
/// a CALL mark stamped with a retired generation can never suppress the
/// successor generation's authentic first FORK.
#[test]
fn ar13_stale_generation_call_mark_cannot_suppress_successor_first_fork() {
    let child = |exec_id| semantics::ProcessKey::history(1, 20, exec_id, 200);
    let mut birth = ev(100, 90, 0, 0);
    birth.event_type = event_type::FORK;
    birth.session = 200;
    birth.child_image = ImageIdentity {
        task_cookie: 20,
        exec_id: 1,
    };
    for (mark, inherited) in [(None, 1), (Some(child(0)), 1), (Some(child(1)), 0)] {
        let (mut s, mut t, _) = setup(16);
        feed(&mut s, &mut t, [ev(100, 90, 0, 0), ev(200, 20, 0, 7)]);
        // Task 20 execs: generation 1 is admitted with no CALL of its own.
        assert_eq!(
            t.admit_history(1, 200, birth.child_image, birth.ts_ns).0,
            Some(child(1))
        );
        if let Some(key) = mark {
            t.history_call(key);
        }
        feed(&mut s, &mut t, [birth]);
        assert_eq!(s.sessions().inherited, inherited, "mark={mark:?}");
    }
}

#[test]
fn history_authentic_reaped_first_trace_has_semantics_without_raw_identity_output() {
    let (mut s, mut t, a) = setup(16);
    a.sample(100, Membership::Exited);
    let mut event = ev(100, 90, 0, 0);
    event.capture |= capture::MECHANISM_VALUE;
    event.mechanism = 1;
    let mut drain = EventDrain::over_test_domain(ScriptedRecords::events([event], 1), 1);
    let mut tracer = trace::Tracer::new(&plan());
    let mut out = Vec::new();
    let mut file = None::<Vec<u8>>;
    drain_trace_events_from(
        &mut drain,
        &mut None,
        &mut s,
        &mut t,
        &scope(),
        &mut tracer,
        &mut out,
        &mut true,
        &mut file,
        None,
    )
    .unwrap();
    assert_eq!(tracer.raw_calls(), 1);
    assert_eq!(vector(&s), (1, 0, 0, 1, 1, 0));
    assert_eq!(s.semantic_evidence().semantic_history_drops, 0);
    let line = String::from_utf8(out).unwrap();
    assert!(line.contains("C_OpenSession"));
    assert!(line.contains("sess#"));
    // Admitted metadata is allowed; raw identity remains private.
    assert!(!line.contains("task_cookie"));
    assert!(!line.contains("exec_id"));
}

#[test]
fn history_terminal_tail_precedes_confirmation_and_late_closed_record_is_loss() {
    let (mut s, mut t, a) = setup(16);
    let mut pending = ev(200, 20, 0, 2);
    pending.rv = pkcs11_types::CkRv::PENDING.0;
    feed(
        &mut s,
        &mut t,
        [ev(100, 90, 0, 0), ev(200, 20, 0, 0), pending],
    );
    assert_eq!(vector(&s), (2, 0, 0, 2, 2, 1));
    feed(&mut s, &mut t, []);
    assert!(t.poll_exited().is_empty());
    assert_eq!(vector(&s), (2, 0, 0, 2, 2, 1));
    let mut drain = EventDrain::over_test_domain(
        ScriptedRecords::events([ev(100, 90, 0, 7), ev(100, 90, 0, 0)], 2),
        1,
    );
    drain_profile_events(&mut drain, &mut s, &mut t, &scope(), Some(1)).unwrap();
    assert_eq!(drain.source().remaining(), 1);
    a.sample(100, Membership::Exited);
    assert!(t.poll_exited().is_empty());
    drain_profile_events(&mut drain, &mut s, &mut t, &scope(), None).unwrap();
    assert_eq!(vector(&s), (3, 0, 1, 2, 2, 1));
    assert_eq!(s.semantic_evidence().semantic_history_drops, 0);
    // Only now inject explicit confirmation. No real cursor is claimed here.
    apply_confirmed_retirement(&mut t, &mut s, key(90, 0));
    assert_eq!(vector(&s), (3, 0, 2, 1, 2, 1));
    feed(&mut s, &mut t, [ev(100, 90, 0, 0)]);
    assert_eq!(vector(&s), (3, 0, 2, 1, 2, 1));
    assert_eq!(s.semantic_evidence().semantic_history_drops, 1);
}

#[test]
fn history_trace_max_events_and_output_failure_still_reduce_finite_tail() {
    for fail in [false, true] {
        let (mut s, mut t, _) = setup(16);
        let mut tracer = trace::Tracer::new(&plan());
        let mut drain = EventDrain::over_test_domain(
            ScriptedRecords::events([ev(100, 90, 0, 0), ev(100, 90, 1, 0), ev(100, 90, 0, 0)], 3),
            1,
        );
        let mut remaining = Some(1);
        let mut out = Vec::new();
        let mut file = fail.then_some(Fails);
        let result = drain_trace_events_from(
            &mut drain,
            &mut remaining,
            &mut s,
            &mut t,
            &scope(),
            &mut tracer,
            &mut out,
            &mut true,
            &mut file,
            Some(1),
        );
        assert_eq!(result.is_err(), fail);
        let result = drain_trace_events_from(
            &mut drain,
            &mut remaining,
            &mut s,
            &mut t,
            &scope(),
            &mut tracer,
            &mut out,
            &mut true,
            &mut file,
            None,
        );
        assert_eq!(result.is_err(), fail);
        assert_eq!(vector(&s), (2, 0, 1, 1, 1, 0));
        assert_eq!(tracer.raw_calls(), 3);
        assert_eq!(s.semantic_evidence().semantic_history_drops, 1);
    }
}
struct Fails;
impl std::io::Write for Fails {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("history output failure"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn history_detached_join_cannot_cross_loaded_object_domains() {
    let mut s = semantics::State::new(&plan());
    let a = key(90, 0);
    let b = semantics::ProcessKey::history(2, 90, 0, 100);
    let opened = ev(100, 90, 0, 0);
    s.observe_process(a, &opened);
    s.observe_process(b, &opened);
    let mut pending = ev(100, 90, 0, 2);
    pending.rv = pkcs11_types::CkRv::PENDING.0;
    let mut get = ev(100, 90, 0, 4);
    get.target_function = crate::kinds::function_id("C_Sign").unwrap();
    get.async_value = 123;
    let mut join = get;
    join.slot = 5;
    s.observe_process(a, &pending);
    s.observe_process(a, &get);
    s.observe_process(b, &join);
    s.retire_process(a);
    assert_eq!(
        s.pending_at_end(),
        0,
        "foreign domain must not adopt custody"
    );
    assert_eq!(s.semantic_evidence().async_orphans, 1);
    // Equal IDs can coexist too; publishing B's ID cannot overwrite A's.
    let mut separate = semantics::State::new(&plan());
    for process in [a, b] {
        separate.observe_process(process, &opened);
        separate.observe_process(process, &pending);
        separate.observe_process(process, &get);
    }
    assert_eq!(separate.pending_at_end(), 2);
    separate.retire_process(a);
    assert_eq!(separate.pending_at_end(), 1);
}

#[test]
fn history_finite_membership_refuses_new_tasks_but_never_forgets_empty_known_task() {
    let (mut s, mut t, a) = setup(1);
    feed(
        &mut s,
        &mut t,
        [ev(100, 90, 0, 7), ev(200, 20, 0, 0), ev(100, 90, 0, 0)],
    );
    assert_eq!(vector(&s), (1, 0, 0, 1, 1, 0));
    assert_eq!(s.semantic_evidence().semantic_history_drops, 1);
    a.sample(100, Membership::Exited);
    assert!(t.poll_exited().is_empty());
    apply_confirmed_retirement(&mut t, &mut s, key(90, 0));
    a.sample(
        100,
        Membership::Live {
            domain: 1,
            cookie: 90,
        },
    );
    feed(&mut s, &mut t, [ev(100, 90, 0, 0), ev(200, 20, 0, 0)]);
    assert_eq!(vector(&s), (1, 0, 1, 0, 1, 0));
    assert_eq!(s.semantic_evidence().semantic_history_drops, 3);
}

#[test]
fn history_detached_join_changes_exact_custody_before_retirement() {
    let (mut s, mut t, a) = setup(16);
    feed(&mut s, &mut t, [ev(100, 90, 0, 0), ev(200, 20, 0, 0)]);
    let mut pending = ev(100, 90, 0, 2);
    pending.rv = pkcs11_types::CkRv::PENDING.0;
    let target = crate::kinds::function_id("C_Sign").unwrap();
    let mut get = ev(100, 90, 0, 4);
    get.target_function = target;
    get.async_value = 123;
    let mut join = ev(200, 20, 0, 5);
    join.target_function = target;
    join.async_value = 123;
    feed(&mut s, &mut t, [pending, get, join]);
    assert_eq!(s.pending_at_end(), 1);
    a.sample(100, Membership::Exited);
    assert!(t.poll_exited().is_empty());
    apply_confirmed_retirement(&mut t, &mut s, key(90, 0));
    assert_eq!(s.pending_at_end(), 1);
    a.sample(200, Membership::Exited);
    assert!(t.poll_exited().is_empty());
    apply_confirmed_retirement(
        &mut t,
        &mut s,
        semantics::ProcessKey::history(1, 20, 0, 200),
    );
    assert_eq!(s.pending_at_end(), 0);
    assert_eq!(s.sessions().closed, 2);
}

#[test]
fn domain_boundary_unbound_drain_has_no_history_authority() {
    let (mut s, mut t, _) = setup(16);
    let mut drain = EventDrain::over(ScriptedRecords::events([ev(100, 90, 0, 0)], 1));
    drain_profile_events(&mut drain, &mut s, &mut t, &scope(), None).unwrap();
    assert_eq!(s.sessions().opened, 0);
    assert_eq!(s.semantic_evidence().semantic_history_drops, 1);
}

#[test]
fn domain_boundary_malformed_affiliation_has_no_reducer_effects() {
    let (mut s, mut t, _) = setup(16);
    let mut records = vec![vec![0; 320]];
    for affiliation in [2, u64::MAX] {
        let mut event = ev(100, 90, 0, 0);
        event.root_affiliation = affiliation;
        records.push(crate::events::event_bytes(&event));
    }
    let mut drain = EventDrain::over_test_domain(ScriptedRecords::records(records, 3), 1);
    assert_eq!(
        drain_profile_events(&mut drain, &mut s, &mut t, &scope(), None).unwrap(),
        (3, false)
    );
    assert_eq!(s.sessions().opened, 0);
    assert_eq!(s.semantic_evidence().semantic_history_drops, 0);
    assert!(s.mechanisms().is_empty());
}

#[test]
fn domain_boundary_state_refuses_foreign_history_and_fork_custody() {
    let domain = crate::events::EventsDomain::test_standin(1);
    let mut s = semantics::State::for_capture(&plan(), CapturePolicy::Allowlisted, domain);
    let foreign = semantics::ProcessKey::history(2, 90, 0, 100);
    s.observe_process(foreign, &ev(100, 90, 0, 0));
    assert_eq!(s.sessions().opened, 0);
    s.observe_process(key(90, 0), &ev(100, 90, 0, 0));
    s.fork_process(key(90, 0), foreign);
    assert_eq!(s.sessions().inherited, 0);
    assert!(!s.has_process_state(foreign));
    assert_eq!(s.sessions().opened, 1);
}

#[test]
fn domain_boundary_valid_affiliations_preserve_history_without_root_retirement() {
    for tag in [0, 1] {
        let (mut s, mut t, _) = setup(16);
        let mut parent = ev(100, 90, 0, 0);
        parent.root_affiliation = tag;
        feed(&mut s, &mut t, [parent]);
        let mut birth = parent;
        birth.event_type = event_type::FORK;
        birth.session = 200;
        birth.child_image = ImageIdentity {
            task_cookie: 20,
            exec_id: 0,
        };
        feed(&mut s, &mut t, [birth]);
        // The FORK tag describes only the parent; neither history gains a
        // retirement witness. An Unknown child still has ordinary authority.
        feed(&mut s, &mut t, [ev(200, 20, 0, 7)]);
        assert_eq!(vector(&s), (1, 1, 0, 2, 2, 0));
        assert_eq!(s.semantic_evidence().semantic_history_drops, 0);
        assert!(t.poll_exited().is_empty());
    }
}

#[test]
fn domain_boundary_malformed_trace_never_counts_or_emits_or_reduces() {
    let (mut s, mut t, _) = setup(16);
    let records = [2, u64::MAX].map(|tag| {
        let mut event = ev(100, 90, 0, 0);
        event.root_affiliation = tag;
        crate::events::event_bytes(&event)
    });
    let mut drain = EventDrain::over_test_domain(ScriptedRecords::records(records, 2), 1);
    let mut tracer = trace::Tracer::new(&plan());
    let mut output = Vec::new();
    assert_eq!(
        drain_trace_events_from(
            &mut drain,
            &mut None,
            &mut s,
            &mut t,
            &scope(),
            &mut tracer,
            &mut output,
            &mut true,
            &mut None::<Vec<u8>>,
            None
        )
        .unwrap(),
        (2, false)
    );
    assert_eq!(tracer.raw_calls(), 0);
    assert!(output.is_empty());
    assert_eq!(vector(&s), (0, 0, 0, 0, 0, 0));
    assert_eq!(s.semantic_evidence().semantic_history_drops, 0);
}

#[test]
fn root_fence_retires_delayed_positive_and_exec_but_preserves_unknown() {
    let plan = plan();
    let domain = crate::events::EventsDomain::test_standin(1);
    let mut state =
        semantics::State::for_capture(&plan, CapturePolicy::Allowlisted, domain.clone());
    let mut tracker = process::Tracker::for_producer(domain.clone(), 64);
    let mut first = ev(100, 10, 0, 0);
    first.root_affiliation = 1;
    let unknown = ev(100, 20, 0, 0);
    let mut delayed = ev(200, 30, 0, 0);
    delayed.root_affiliation = 1;
    feed(&mut state, &mut tracker, [first, unknown]);
    let mut exec = first;
    exec.image.exec_id = 1;
    let mut drain = EventDrain::over_domain(
        crate::events::root_fence_tests::source([exec, delayed]),
        domain.clone(),
    );
    let mut tail = crate::events::OwnedRootTail::new(
        OriginalRootExit::test_reaped(domain),
        Instant::now() + Duration::from_secs(1),
    );
    drain.begin_root_tail(&mut tail).unwrap();
    let domain = drain.domain_id();
    assert_eq!(
        drain
            .poll_root_tail(&mut tail, 8, |event| reduce_profile_event(
                domain,
                &mut tracker,
                &mut state,
                &scope(),
                event
            ))
            .unwrap(),
        crate::events::RootTailProgress::Reached
    );
    apply_original_root_retirement(&mut tracker, &mut state, tail.complete().unwrap()).unwrap();
    assert!(
        tracker
            .admit_history(1, 100, first.image, first.ts_ns)
            .0
            .is_none()
    );
    assert!(
        tracker
            .admit_history(1, 100, exec.image, exec.ts_ns)
            .0
            .is_none()
    );
    assert!(
        tracker
            .admit_history(1, 200, delayed.image, delayed.ts_ns)
            .0
            .is_none()
    );
    assert!(
        tracker
            .admit_history(1, 100, unknown.image, unknown.ts_ns)
            .0
            .is_some()
    );
    assert!(reduce_profile_event(1, &mut tracker, &mut state, &scope(), delayed).is_err());
}

#[test]
fn root_fence_trace_reduces_parent_only_and_preserves_unknown_pending_and_write_error() {
    for fail in [false, true] {
        let domain = crate::events::EventsDomain::test_standin(1);
        let mut state =
            semantics::State::for_capture(&plan(), CapturePolicy::Allowlisted, domain.clone());
        let mut tracker = process::Tracker::for_producer(domain.clone(), 64);
        let mut tracer = trace::Tracer::new(&plan());
        let mut positive = ev(100, 10, 0, 0);
        positive.root_affiliation = 1;
        let unknown = ev(200, 20, 0, 0);
        let mut pending = ev(200, 20, 0, 2);
        pending.rv = pkcs11_types::CkRv::PENDING.0;
        let mut fork = ev(100, 10, 0, 0);
        fork.root_affiliation = 1;
        fork.event_type = event_type::FORK;
        fork.session = 300;
        fork.child_image = ImageIdentity {
            task_cookie: 30,
            exec_id: 0,
        };
        let mut source =
            crate::events::root_fence_tests::source([positive, unknown, pending, fork]);
        source.records.push_front(Some(vec![0]));
        source.producer += 8;
        let mut drain = EventDrain::over_domain(source, domain.clone());
        let mut tail = crate::events::OwnedRootTail::new(
            OriginalRootExit::test_reaped(domain),
            Instant::now() + Duration::from_secs(1),
        );
        drain.begin_root_tail(&mut tail).unwrap();
        let mut out = Vec::new();
        let mut file = fail.then_some(Fails);
        let mut write_error = None;
        let mut remaining = Some(1);
        loop {
            let progress = drain
                .poll_root_tail(&mut tail, 1, |event| {
                    reduce_trace_event(
                        1,
                        &mut remaining,
                        &mut state,
                        &mut tracker,
                        &scope(),
                        &mut tracer,
                        &mut out,
                        &mut true,
                        &mut file,
                        &mut write_error,
                        event,
                    )
                })
                .unwrap();
            if progress == crate::events::RootTailProgress::Reached {
                break;
            }
        }
        assert_eq!(drain.malformed(), 1);
        assert_eq!(write_error.is_some(), fail);
        assert_eq!(tracer.raw_calls(), 3);
        apply_original_root_retirement(&mut tracker, &mut state, tail.complete().unwrap()).unwrap();
        assert_eq!(state.pending_at_end(), 1);
        assert!(
            tracker
                .admit_history(1, 100, positive.image, positive.ts_ns)
                .0
                .is_none()
        );
        assert!(
            tracker
                .admit_history(1, 200, unknown.image, unknown.ts_ns)
                .0
                .is_some()
        );
        assert!(
            tracker
                .admit_history(1, 300, fork.child_image, fork.ts_ns)
                .0
                .is_some()
        );
        assert!(out.iter().filter(|&&b| b == b'\n').count() <= 1);
        if let Some(error) = write_error {
            assert!(format!("{error:#}").contains("history output failure"));
        }
    }
}

#[test]
fn root_fence_unknown_after_positive_stays_bound_and_incomplete_keeps_state() {
    for cancelled in [false, true] {
        let domain = crate::events::EventsDomain::test_standin(1);
        let mut state =
            semantics::State::for_capture(&plan(), CapturePolicy::Allowlisted, domain.clone());
        let mut tracker = process::Tracker::for_producer(domain.clone(), 64);
        let mut positive = ev(100, 10, 0, 0);
        positive.root_affiliation = 1;
        let unknown = ev(100, 10, 0, 7);
        feed(&mut state, &mut tracker, [positive, unknown]);
        let mut drain = EventDrain::over_domain(
            crate::events::root_fence_tests::source([unknown]),
            domain.clone(),
        );
        let mut tail = crate::events::OwnedRootTail::new(
            OriginalRootExit::test_reaped(domain),
            Instant::now() + Duration::from_secs(1),
        );
        drain.begin_root_tail(&mut tail).unwrap();
        if cancelled {
            assert!(tail.check(true, Instant::now()).is_err());
            assert!(tail.complete().is_err());
            assert_eq!(state.sessions().closed, 0);
            assert!(
                tracker
                    .admit_history(1, 100, positive.image, positive.ts_ns)
                    .0
                    .is_some()
            );
        } else {
            drain
                .poll_root_tail(&mut tail, 8, |event| {
                    reduce_profile_event(1, &mut tracker, &mut state, &scope(), event)
                })
                .unwrap();
            apply_original_root_retirement(&mut tracker, &mut state, tail.complete().unwrap())
                .unwrap();
            assert_eq!(state.sessions().closed, 1);
        }
    }
}

#[test]
fn root_fence_trace_preserves_both_errors_without_claiming_settlement_failure() {
    let domain = crate::events::EventsDomain::test_standin(1);
    let mut state =
        semantics::State::for_capture(&plan(), CapturePolicy::Allowlisted, domain.clone());
    let mut tracker = process::Tracker::for_producer(domain.clone(), 64);
    let mut drain =
        EventDrain::over_domain(crate::events::root_fence_tests::source([]), domain.clone());
    let mut tail = crate::events::OwnedRootTail::new(
        OriginalRootExit::test_reaped(domain),
        Instant::now() + Duration::from_secs(1),
    );
    drain.begin_root_tail(&mut tail).unwrap();
    drain.poll_root_tail(&mut tail, 1, |_| Ok(())).unwrap();
    apply_original_root_retirement(&mut tracker, &mut state, tail.complete().unwrap()).unwrap();
    let unknown = ev(100, 10, 0, 0);
    let mut positive = ev(200, 20, 0, 0);
    positive.root_affiliation = 1;
    let mut drain =
        EventDrain::over_test_domain(ScriptedRecords::events([unknown, positive], 2), 1);
    let error = drain_trace_events_from(
        &mut drain,
        &mut None,
        &mut state,
        &mut tracker,
        &scope(),
        &mut trace::Tracer::new(&plan()),
        &mut Vec::new(),
        &mut true,
        &mut Some(Fails),
        None,
    )
    .unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("positive root event after completed fixed EVENTS tail"));
    assert!(message.contains("history output failure"));
    assert!(!message.contains("owned child settlement"), "{message}");
}

fn root_cancel_output_case(is_trace: bool, partial: bool) {
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let domain = crate::events::EventsDomain::test_standin(1);
        let mut state =
            semantics::State::for_capture(&plan(), CapturePolicy::Allowlisted, domain.clone());
        let mut tracker = process::Tracker::for_producer(domain.clone(), 64);
        let mut positive = ev(100, 10, 0, 0);
        positive.root_affiliation = 1;
        let unknown = ev(200, 20, 0, 0);
        let mut pending_positive = ev(100, 10, 0, 2);
        pending_positive.rv = pkcs11_types::CkRv::PENDING.0;
        let mut pending_unknown = ev(200, 20, 0, 2);
        pending_unknown.rv = pkcs11_types::CkRv::PENDING.0;
        feed(
            &mut state,
            &mut tracker,
            [positive, unknown, pending_positive, pending_unknown],
        );
        let before = vector(&state);
        assert_eq!(before, (2, 0, 0, 2, 2, 2));
        let signals = SignalState::new();
        let exit = OriginalRootExit::test_reaped(domain.clone());
        let mut source = crate::events::root_fence_tests::source([]);
        if partial {
            let mut event = ev(100, 10, 0, 7);
            event.root_affiliation = 1;
            source = crate::events::root_fence_tests::source(std::iter::repeat_n(
                event,
                crate::events::LIVE_POLL_QUANTUM,
            ));
            source.records.push_front(Some(vec![0]));
            source.producer += 8;
            source.capacity = 65536;
        } else {
            signals.observe(signal);
        }
        let mut drain = EventDrain::over_domain(source, domain);
        let mut tracer = trace::Tracer::new(&plan());
        let mut root_write_error = None;
        let scope = scope();
        let tail =
            crate::events::OwnedRootTail::new(exit, Instant::now() + Duration::from_secs(30));
        let root = drain_original_root_events_from(&mut drain, tail, &signals, |domain, event| {
            if is_trace {
                reduce_trace_event(
                    domain,
                    &mut Some(0),
                    &mut state,
                    &mut tracker,
                    &scope,
                    &mut tracer,
                    &mut Vec::new(),
                    &mut true,
                    &mut None::<Vec<u8>>,
                    &mut root_write_error,
                    event,
                )?;
            } else {
                reduce_profile_event(domain, &mut tracker, &mut state, &scope, event)?;
            }
            if !signals.interrupted() {
                signals.observe(signal);
            }
            Ok(())
        });
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            temp.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        let path = temp.path().join("profile.json");
        let mut stdout = Vec::new();
        let mut file = None::<Vec<u8>>;
        let mut diagnostic = Vec::new();
        let mut malformed = 0;
        let result = terminal_after_root(root, &mut diagnostic, |(count, completed)| {
            malformed += count;
            if let Some(completed) = completed {
                apply_original_root_retirement(&mut tracker, &mut state, completed)?;
            }
            combine_trace_errors(Ok(()), root_write_error)?;
            if is_trace {
                emit_trace_terminal(
                    &[],
                    &tracer,
                    "EVIDENCE {}",
                    &mut stdout,
                    &mut true,
                    &mut file,
                )?;
            } else {
                let mut output = AtomicFile::create(&path).map_err(anyhow::Error::msg)?;
                write_json_report(
                    output.file(),
                    &serde_json::json!({"malformed":malformed,"signal":signals.first_signal(),"pending":state.pending_at_end()}),
                )?;
                output.commit().map_err(anyhow::Error::msg)?;
            }
            Ok(())
        });
        assert!(
            if is_trace {
                stdout.windows(9).any(|b| b == b"EVIDENCE ")
            } else {
                path.exists()
            },
            "normal terminal output was suppressed: {result:?}"
        );
        result.unwrap();
        assert_eq!(malformed, u64::from(partial));
        assert_eq!(drain.source().records.len(), usize::from(partial));
        if is_trace {
            assert_eq!(tracer.raw_calls(), if partial { 4095 } else { 0 });
        }
        let diagnostic = String::from_utf8(diagnostic).unwrap();
        assert!(
            diagnostic.contains("root_tail_incomplete: cancelled"),
            "{diagnostic}"
        );
        assert!(
            diagnostic.contains(if partial {
                "remaining=8"
            } else {
                "remaining=0"
            }),
            "{diagnostic}"
        );
        assert_eq!(signals.first_signal(), Some(signal));
        assert!(signals.interrupted());
        assert_eq!(vector(&state), before);
        assert!(
            tracker
                .admit_history(1, 100, positive.image, positive.ts_ns)
                .0
                .is_some()
        );
        assert!(
            tracker
                .admit_history(1, 200, unknown.image, unknown.ts_ns)
                .0
                .is_some()
        );
        if !is_trace {
            let json: serde_json::Value =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert_eq!(json["malformed"], u64::from(partial));
            assert_eq!(json["signal"], signal);
        }
    }
}
#[test]
fn root_cancel_profile_preset_keeps_atomic_final_output() {
    root_cancel_output_case(false, false);
}
#[test]
fn root_cancel_profile_partial_keeps_atomic_final_output() {
    root_cancel_output_case(false, true);
}
#[test]
fn root_cancel_trace_preset_keeps_terminal_evidence() {
    root_cancel_output_case(true, false);
}
#[test]
fn root_cancel_trace_partial_keeps_terminal_evidence() {
    root_cancel_output_case(true, true);
}

#[test]
fn root_cancel_keeps_real_write_and_settlement_failures() {
    let domain = crate::events::EventsDomain::test_standin(1);
    let mut state =
        semantics::State::for_capture(&plan(), CapturePolicy::Allowlisted, domain.clone());
    let mut tracker = process::Tracker::for_producer(domain.clone(), 64);
    let mut positive = ev(100, 10, 0, 0);
    positive.root_affiliation = 1;
    let mut drain = EventDrain::over_domain(
        crate::events::root_fence_tests::source([positive]),
        domain.clone(),
    );
    let tail = crate::events::OwnedRootTail::new(
        OriginalRootExit::test_reaped(domain.clone()),
        Instant::now() + Duration::from_secs(1),
    );
    let signals = SignalState::new();
    let mut write_error = None;
    let mut tracer = trace::Tracer::new(&plan());
    let root = drain_original_root_events_from(&mut drain, tail, &signals, |domain, event| {
        reduce_trace_event(
            domain,
            &mut None,
            &mut state,
            &mut tracker,
            &scope(),
            &mut tracer,
            &mut Vec::new(),
            &mut true,
            &mut Some(Fails),
            &mut write_error,
            event,
        )?;
        signals.observe(libc::SIGTERM);
        Ok(())
    });
    let root =
        root.map_err(|error| combine_trace_errors(Err(error), write_error.take()).unwrap_err());
    let mut diagnostic = Vec::new();
    let mut output = Vec::new();
    let error = terminal_after_root(root, &mut diagnostic, |(_, completed)| {
        assert!(completed.is_none());
        combine_trace_errors(Ok(()), write_error)?;
        emit_trace_terminal(
            &[],
            &tracer,
            "EVIDENCE {}",
            &mut output,
            &mut true,
            &mut None::<Vec<u8>>,
        )
    })
    .unwrap_err();
    assert!(format!("{error:#}").contains("history output failure"));
    assert!(output.is_empty());
    assert!(
        String::from_utf8(diagnostic)
            .unwrap()
            .contains("root_tail_incomplete: cancelled")
    );
    assert_eq!(state.sessions().closed, 0);
    assert_eq!(signals.first_signal(), Some(libc::SIGTERM));
    let exit = OriginalRootExit::test_reaped(domain);
    let mut code = None;
    let mut running = true;
    let settlement = record_settlement_result(
        &exit._child,
        Err(anyhow!("settlement cleanup failed")),
        &mut code,
        &mut running,
    )
    .unwrap_err();
    let error = terminal_after_root::<()>(Err(settlement), &mut Vec::new(), |_| {
        panic!("settlement failure became successful output")
    })
    .unwrap_err();
    assert!(error.to_string().contains("settlement cleanup failed"));
    assert!(code.is_some());
    assert!(!running);
    assert_eq!(signals.first_signal(), Some(libc::SIGTERM));
}

/// I1: a passed root-tail deadline (here with a signal pending as well)
/// still finalizes and publishes the report. It abandons only the optional
/// retirement, names the deadline (never "cancelled"), and leaves the
/// snapshot record to the ordinary terminal drain. Before I1 this was a
/// hard error and the report was dropped.
#[test]
fn root_tail_deadline_publishes_the_report_with_a_named_diagnostic() {
    // Without a signal is the real full-ring-at-exit case; with one, the
    // deadline still wins and is never relabeled as a cancellation.
    for signal_pending in [false, true] {
        root_tail_deadline_case(signal_pending);
    }
}

fn root_tail_deadline_case(signal_pending: bool) {
    let domain = crate::events::EventsDomain::test_standin(1);
    let tail = crate::events::OwnedRootTail::new(
        OriginalRootExit::test_reaped(domain.clone()),
        Instant::now() - Duration::from_secs(1),
    );
    let mut drain = EventDrain::over_domain(
        crate::events::root_fence_tests::source([ev(100, 10, 0, 7)]),
        domain,
    );
    let signals = SignalState::new();
    if signal_pending {
        signals.observe(libc::SIGINT);
    }
    let root = drain_original_root_events_from(&mut drain, tail, &signals, |_, _| {
        panic!("an expired tail reduced a record")
    });
    let mut diagnostic = Vec::new();
    let mut finalized = None;
    terminal_after_root(root, &mut diagnostic, |(malformed, completed)| {
        finalized = Some((malformed, completed.is_some()));
        Ok(())
    })
    .unwrap();
    assert_eq!(finalized, Some((0, false)), "published without retirement");
    let diagnostic = String::from_utf8(diagnostic).unwrap();
    assert!(
        diagnostic.contains("root_tail_incomplete: deadline; remaining=8"),
        "{diagnostic}"
    );
    assert!(!diagnostic.contains("cancelled"), "{diagnostic}");
    assert_eq!(
        drain.source().records.len(),
        1,
        "left to the terminal drain"
    );
}

/// I1 healthy twin: with the deadline met and no signal, the same tail
/// completes, retirement is handed to the finalizer and no root-tail
/// diagnostic is written, so the report is unchanged.
#[test]
fn root_tail_met_deadline_publishes_the_report_unchanged() {
    let domain = crate::events::EventsDomain::test_standin(1);
    let tail = crate::events::OwnedRootTail::new(
        OriginalRootExit::test_reaped(domain.clone()),
        Instant::now() + Duration::from_secs(60 * 60),
    );
    let mut drain = EventDrain::over_domain(
        crate::events::root_fence_tests::source([ev(100, 10, 0, 7)]),
        domain,
    );
    let signals = SignalState::new();
    let mut reduced = 0;
    let root = drain_original_root_events_from(&mut drain, tail, &signals, |_, _| {
        reduced += 1;
        Ok(())
    });
    let mut diagnostic = Vec::new();
    let mut finalized = None;
    terminal_after_root(root, &mut diagnostic, |(malformed, completed)| {
        finalized = Some((malformed, completed.is_some()));
        Ok(())
    })
    .unwrap();
    assert_eq!(reduced, 1);
    assert_eq!(finalized, Some((0, true)), "published with retirement");
    assert!(
        diagnostic.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&diagnostic)
    );
    assert!(drain.source().records.is_empty());
}

#[test]
fn root_cancel_never_relabels_domain_reducer_or_crossing_failures() {
    for failure in 1..4 {
        let domain = crate::events::EventsDomain::test_standin(1);
        // These cases assert domain, reducer, and cursor-crossing
        // failures. Keep the wall clock from becoming a competing
        // failure source when the full suite deschedules this test.
        let deadline = Instant::now() + Duration::from_secs(60 * 60);
        let tail = crate::events::OwnedRootTail::new(
            OriginalRootExit::test_reaped(domain.clone()),
            deadline,
        );
        let source = crate::events::root_fence_tests::source([ev(100, 10, 0, 7)]);
        let cursor = source.cursor.clone();
        let mut drain = EventDrain::over_domain(
            source,
            if failure == 1 {
                crate::events::EventsDomain::test_standin(2)
            } else {
                domain
            },
        );
        let signals = SignalState::new();
        if failure < 2 {
            signals.observe(libc::SIGINT);
        }
        let root = drain_original_root_events_from(&mut drain, tail, &signals, |_, _| {
            signals.observe(libc::SIGINT);
            if failure == 2 {
                anyhow::bail!("genuine reducer failure");
            }
            cursor.set(8);
            Ok(())
        });
        let mut diagnostic = Vec::new();
        let error = terminal_after_root::<()>(root, &mut diagnostic, |_| {
            panic!("genuine failure became cancellation success")
        })
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains(
                [
                    "deadline",
                    "foreign EVENTS domain",
                    "genuine reducer failure",
                    "crossed root tail boundary"
                ][failure]
            ),
            "{message}"
        );
        assert!(!message.contains("cancelled"));
        assert!(diagnostic.is_empty());
        assert!(signals.interrupted());
    }
}

/// E20 / F-75 first regression. Same EVENTS domain (1), distinct task
/// cookies (90 vs 20), equal module/slot/target-function/async ID, different
/// pending mechanisms (0x101 vs 0x250). The second `C_AsyncGetID` is a proven
/// independent-owner collision: the key is tombstoned, the first owner's join
/// and every completion on it are refused, and no mechanism is published under
/// either process — while PARTIAL-implying evidence (`async_duplicates`,
/// `async_orphans`) stays explicit. The other owner's finalize retires only
/// its own scope; a late completion after retirement is a history drop, never
/// a binding.
#[test]
fn e20_f75_same_domain_collision_refuses_join_and_completion_without_wrong_binding() {
    let target = crate::kinds::function_id("C_SignInit").unwrap();
    let pending_init = |pid: u32, cookie: u64, mechanism: u64| {
        let mut init = ev(pid, cookie, 0, 1);
        init.rv = pkcs11_types::CkRv::PENDING.0;
        init.capture = capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL;
        init.mechanism = mechanism;
        init
    };
    let get_id = |pid: u32, cookie: u64| {
        let mut get = ev(pid, cookie, 0, 4);
        get.target_function = target;
        get.async_value = 42;
        get
    };
    let join = |pid: u32, cookie: u64, session: u64| {
        let mut join = ev(pid, cookie, 0, 5);
        join.session = session;
        join.target_function = target;
        join.async_value = 42;
        join
    };
    let complete = |pid: u32, cookie: u64, session: u64| {
        let mut complete = ev(pid, cookie, 0, 6);
        complete.session = session;
        complete.target_function = target;
        complete
    };

    let (mut s, mut t, _) = setup(16);
    let a = key(90, 0);
    let b = semantics::ProcessKey::history(1, 20, 0, 200);
    let mut open_a8 = ev(100, 90, 0, 0);
    open_a8.session = 8;
    feed(
        &mut s,
        &mut t,
        [ev(100, 90, 0, 0), open_a8, ev(200, 20, 0, 0)],
    );
    assert_eq!(vector(&s), (3, 0, 0, 3, 3, 0));

    // Opposite pending mechanisms, one shared (module, slot, function, id).
    feed(
        &mut s,
        &mut t,
        [pending_init(100, 90, 0x101), pending_init(200, 20, 0x250)],
    );
    assert_eq!(s.pending_at_end(), 2);
    feed(&mut s, &mut t, [get_id(100, 90)]);
    assert_eq!(s.pending_at_end(), 2);
    assert_eq!(s.semantic_evidence().async_duplicates, 0);

    // The second GetID proves the collision: one tombstoned key, no new key,
    // explicit duplicate evidence (PARTIAL-implying downstream).
    feed(&mut s, &mut t, [get_id(200, 20)]);
    assert_eq!(s.pending_at_end(), 1);
    assert_eq!(s.semantic_evidence().async_duplicates, 1);

    // The first owner's join is refused: custody cannot move off an
    // ambiguous key.
    feed(&mut s, &mut t, [join(100, 90, 8)]);
    assert_eq!(s.semantic_evidence().async_orphans, 1);
    assert_eq!(s.pending_at_end(), 1);

    // Opposite completion order (B first) plus both of A's sessions: every
    // completion on the collided key is refused and publishes nothing.
    feed(&mut s, &mut t, [complete(200, 20, 7)]);
    assert_eq!(s.semantic_evidence().async_orphans, 2);
    feed(&mut s, &mut t, [complete(100, 90, 8)]);
    assert_eq!(s.semantic_evidence().async_orphans, 3);
    feed(&mut s, &mut t, [complete(100, 90, 7)]);
    assert_eq!(s.semantic_evidence().async_orphans, 4);
    assert!(
        s.mechanisms().get(&0x101).is_none(),
        "loser's mechanism must not publish"
    );
    assert!(
        s.mechanisms().get(&0x250).is_none(),
        "winner's mechanism must not publish under the other owner"
    );
    assert_eq!(s.pending_at_end(), 1);
    assert!(s.has_process_state(a));
    assert!(s.has_process_state(b));

    // A later ordinary call on either session finds no smuggled binding.
    let mut sign_a = ev(100, 90, 0, 2);
    sign_a.session = 8;
    feed(&mut s, &mut t, [sign_a, ev(200, 20, 0, 2)]);
    assert!(s.mechanisms().get(&0x101).is_none());
    assert!(s.mechanisms().get(&0x250).is_none());

    // The other owner's finalize retires only its own scope: the tombstone
    // (first inserter's Cryptoki) survives, B's session is settled.
    feed(&mut s, &mut t, [ev(200, 20, 0, 3)]);
    assert_eq!(vector(&s), (3, 0, 1, 2, 3, 1));
    assert!(!s.has_process_state(b));
    assert!(s.has_process_state(a));

    // The first owner's finalize drops the tombstone with its Cryptoki.
    feed(&mut s, &mut t, [ev(100, 90, 0, 3)]);
    assert_eq!(vector(&s), (3, 0, 3, 0, 3, 0));
    assert!(!s.has_process_state(a));

    // Late completion after the collision settled: refused, still nothing
    // published even though PARTIAL-implying evidence is set.
    feed(&mut s, &mut t, [complete(100, 90, 7)]);
    assert_eq!(s.semantic_evidence().async_orphans, 5);
    assert!(s.mechanisms().is_empty());
    assert_eq!(s.semantic_evidence().async_duplicates, 1);

    // Exits retire both histories; anything later is a history drop.
    apply_confirmed_retirement(&mut t, &mut s, a);
    apply_confirmed_retirement(&mut t, &mut s, b);
    assert_eq!(vector(&s), (3, 0, 3, 0, 3, 0));
    feed(&mut s, &mut t, [complete(200, 20, 7)]);
    assert_eq!(s.semantic_evidence().semantic_history_drops, 1);
    assert_eq!(s.semantic_evidence().async_orphans, 5);
    assert!(s.mechanisms().is_empty());
}

/// E20 countercontrol: one `C_AsyncGetID` followed by a genuine cross-process
/// join still transfers custody and completes with the originator's own
/// mechanism. The collision tombstone must never fire without a proven second
/// owner; this test pins that valid transfers survive the gate.
#[test]
fn e20_valid_cross_process_transfer_still_completes_with_own_mechanism() {
    let target = crate::kinds::function_id("C_SignInit").unwrap();
    let (mut s, mut t, _) = setup(16);
    feed(&mut s, &mut t, [ev(100, 90, 0, 0), ev(200, 20, 0, 0)]);
    let mut init = ev(100, 90, 0, 1);
    init.rv = pkcs11_types::CkRv::PENDING.0;
    init.capture = capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL;
    init.mechanism = 0x101;
    let mut get = ev(100, 90, 0, 4);
    get.target_function = target;
    get.async_value = 42;
    feed(&mut s, &mut t, [init, get]);
    assert_eq!(s.pending_at_end(), 1);

    let mut join = ev(200, 20, 0, 5);
    join.target_function = target;
    join.async_value = 42;
    feed(&mut s, &mut t, [join]);
    assert_eq!(s.semantic_evidence().async_orphans, 0);
    assert_eq!(s.pending_at_end(), 1);

    let mut complete = ev(200, 20, 0, 6);
    complete.target_function = target;
    feed(&mut s, &mut t, [complete]);
    assert_eq!(s.semantic_evidence().async_orphans, 0);
    assert_eq!(s.semantic_evidence().async_duplicates, 0);
    assert_eq!(s.mechanisms()[&0x101].calls, 1);
    assert_eq!(s.pending_at_end(), 0);
    assert_eq!(vector(&s), (2, 0, 0, 2, 2, 0));
}

/// FU-1 via the real history drain (Package E): after the E20 same-domain
/// collision, the first owner mints a fresh PENDING GetID on the collided
/// key. Duplicates +1, exactly one record, joins/completions refused, and
/// neither the original nor the fresh mechanism publishes.
#[test]
fn e20_fu1_history_remint_on_live_tombstone_refuses_without_binding() {
    let target = crate::kinds::function_id("C_SignInit").unwrap();
    let pending_init = |pid: u32, cookie: u64, mechanism: u64| {
        let mut init = ev(pid, cookie, 0, 1);
        init.rv = pkcs11_types::CkRv::PENDING.0;
        init.capture = capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL;
        init.mechanism = mechanism;
        init
    };
    let get_id = |pid: u32, cookie: u64| {
        let mut get = ev(pid, cookie, 0, 4);
        get.target_function = target;
        get.async_value = 42;
        get
    };
    let join = |pid: u32, cookie: u64| {
        let mut join = ev(pid, cookie, 0, 5);
        join.target_function = target;
        join.async_value = 42;
        join
    };
    let complete = |pid: u32, cookie: u64| {
        let mut complete = ev(pid, cookie, 0, 6);
        complete.target_function = target;
        complete
    };

    let (mut s, mut t, _) = setup(16);
    feed(&mut s, &mut t, [ev(100, 90, 0, 0), ev(200, 20, 0, 0)]);
    feed(
        &mut s,
        &mut t,
        [pending_init(100, 90, 0x101), pending_init(200, 20, 0x250)],
    );
    feed(&mut s, &mut t, [get_id(100, 90), get_id(200, 20)]);
    assert_eq!(s.semantic_evidence().async_duplicates, 1);
    assert_eq!(s.pending_at_end(), 1);

    // First owner mints a fresh PENDING operation and re-issues GetID.
    feed(&mut s, &mut t, [pending_init(100, 90, 0x103)]);
    assert_eq!(s.pending_at_end(), 2);
    feed(&mut s, &mut t, [get_id(100, 90)]);
    assert_eq!(
        s.semantic_evidence().async_duplicates,
        2,
        "re-mint on a live tombstone counts one more duplicate"
    );
    assert_eq!(s.pending_at_end(), 1, "the tombstone adds zero keys");

    feed(&mut s, &mut t, [join(100, 90)]);
    assert_eq!(s.semantic_evidence().async_orphans, 1);
    feed(&mut s, &mut t, [join(200, 20)]);
    assert_eq!(s.semantic_evidence().async_orphans, 2);
    feed(&mut s, &mut t, [complete(200, 20)]);
    assert_eq!(s.semantic_evidence().async_orphans, 3);
    feed(&mut s, &mut t, [complete(100, 90)]);
    assert_eq!(s.semantic_evidence().async_orphans, 4);
    assert!(s.mechanisms().get(&0x101).is_none());
    assert!(s.mechanisms().get(&0x103).is_none());
    assert!(s.mechanisms().get(&0x250).is_none());
    assert_eq!(s.pending_at_end(), 1);
}

/// FU-2 via the real history drain (Package E): `C_CloseSession` (slot 8)
/// and `C_CloseAllSessions` (slot 9) by each owner on a collided key leave
/// the tombstone live: one record, joins/completions still refused.
#[test]
fn e20_fu2_history_close_on_live_tombstone_preserves_refusal() {
    let target = crate::kinds::function_id("C_SignInit").unwrap();
    let pending_init = |pid: u32, cookie: u64, mechanism: u64| {
        let mut init = ev(pid, cookie, 0, 1);
        init.rv = pkcs11_types::CkRv::PENDING.0;
        init.capture = capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL;
        init.mechanism = mechanism;
        init
    };
    let get_id = |pid: u32, cookie: u64| {
        let mut get = ev(pid, cookie, 0, 4);
        get.target_function = target;
        get.async_value = 42;
        get
    };

    // --- C_CloseSession by each owner. ---
    let (mut s, mut t, _) = setup(16);
    feed(&mut s, &mut t, [ev(100, 90, 0, 0), ev(200, 20, 0, 0)]);
    feed(
        &mut s,
        &mut t,
        [pending_init(100, 90, 0x101), pending_init(200, 20, 0x250)],
    );
    feed(&mut s, &mut t, [get_id(100, 90), get_id(200, 20)]);
    assert_eq!(s.semantic_evidence().async_duplicates, 1);
    feed(&mut s, &mut t, [ev(200, 20, 0, 8)]);
    assert_eq!(s.pending_at_end(), 1);
    feed(&mut s, &mut t, [ev(100, 90, 0, 8)]);
    assert_eq!(s.pending_at_end(), 1, "close detaches but never drops");
    assert_eq!(vector(&s), (2, 0, 2, 0, 2, 1));
    // Re-open both, joins/completions still refuse.
    feed(&mut s, &mut t, [ev(100, 90, 0, 0), ev(200, 20, 0, 0)]);
    let mut join = ev(100, 90, 0, 5);
    join.target_function = target;
    join.async_value = 42;
    feed(&mut s, &mut t, [join]);
    assert_eq!(s.semantic_evidence().async_orphans, 1);
    let mut complete = ev(200, 20, 0, 6);
    complete.target_function = target;
    feed(&mut s, &mut t, [complete]);
    assert_eq!(s.semantic_evidence().async_orphans, 2);
    assert_eq!(s.pending_at_end(), 1);

    // --- C_CloseAllSessions by each owner (fresh collision). ---
    let (mut s, mut t, _) = setup(16);
    feed(&mut s, &mut t, [ev(100, 90, 0, 0), ev(200, 20, 0, 0)]);
    feed(
        &mut s,
        &mut t,
        [pending_init(100, 90, 0x101), pending_init(200, 20, 0x250)],
    );
    feed(&mut s, &mut t, [get_id(100, 90), get_id(200, 20)]);
    let mut close_all_b = ev(200, 20, 0, 9);
    close_all_b.session = p11scope_ebpf_common::SESSION_NONE;
    feed(&mut s, &mut t, [close_all_b]);
    assert_eq!(s.pending_at_end(), 1);
    let mut close_all_a = ev(100, 90, 0, 9);
    close_all_a.session = p11scope_ebpf_common::SESSION_NONE;
    feed(&mut s, &mut t, [close_all_a]);
    assert_eq!(
        s.pending_at_end(),
        1,
        "close-all detaches but never drops a live tombstone"
    );
    feed(&mut s, &mut t, [ev(100, 90, 0, 0)]);
    let mut join = ev(100, 90, 0, 5);
    join.target_function = target;
    join.async_value = 42;
    feed(&mut s, &mut t, [join]);
    assert_eq!(s.semantic_evidence().async_orphans, 1);
    assert!(s.mechanisms().is_empty());
}

/// E20/H9-§2, exec reuse through the actual capture-wide
/// profile/trace reducer: an exec retires the old generation, so a
/// post-exec completion cannot adopt the pre-exec async record; a
/// post-exec re-issue of the same id value starts clean (no
/// tombstone from the dead record).
#[test]
fn e20_exec_reuse_cannot_adopt_pre_exec_async() {
    let target = crate::kinds::function_id("C_SignInit").unwrap();
    let (mut s, mut t, _) = setup(16);
    let old = key(90, 0);
    feed(&mut s, &mut t, [ev(100, 90, 0, 0)]);
    let mut init = ev(100, 90, 0, 1);
    init.rv = pkcs11_types::CkRv::PENDING.0;
    init.capture = capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL;
    init.mechanism = 0x101;
    feed(&mut s, &mut t, [init]);
    let mut get = ev(100, 90, 0, 4);
    get.target_function = target;
    get.async_value = 42;
    feed(&mut s, &mut t, [get]);
    assert_eq!(s.pending_at_end(), 1);
    assert!(s.has_process_state(old));

    // Same cookie, new exec: the tracker retires the old generation
    // (its open session closes with it).
    let mut complete = ev(100, 90, 1, 6);
    complete.target_function = target;
    complete.async_value = pkcs11_types::CkRv::OK.0;
    feed(&mut s, &mut t, [complete]);
    assert_eq!(
        s.semantic_evidence().async_orphans,
        1,
        "post-exec completion cannot adopt the retired record"
    );
    assert_eq!(s.pending_at_end(), 0);
    assert!(!s.has_process_state(old), "exec retired the old key");
    assert_eq!(s.sessions().closed, 1, "the old open retired with it");
    assert!(s.mechanisms().is_empty(), "nothing published");

    // Re-issue under the new generation: the same id value starts a
    // clean record (the dead one left no tombstone).
    let new = semantics::ProcessKey::history(1, 90, 1, 100);
    feed(&mut s, &mut t, [ev(100, 90, 1, 0)]);
    let mut init = ev(100, 90, 1, 1);
    init.rv = pkcs11_types::CkRv::PENDING.0;
    init.capture = capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL;
    init.mechanism = 0x101;
    feed(&mut s, &mut t, [init]);
    let mut get = ev(100, 90, 1, 4);
    get.target_function = target;
    get.async_value = 42;
    feed(&mut s, &mut t, [get]);
    assert_eq!(s.pending_at_end(), 1);
    assert_eq!(s.semantic_evidence().async_duplicates, 0);
    let mut join = ev(100, 90, 1, 5);
    join.target_function = target;
    join.async_value = 42;
    feed(&mut s, &mut t, [join]);
    let mut complete = ev(100, 90, 1, 6);
    complete.target_function = target;
    complete.async_value = pkcs11_types::CkRv::OK.0;
    feed(&mut s, &mut t, [complete]);
    assert_eq!(s.pending_at_end(), 0);
    assert_eq!(
        s.semantic_evidence().async_orphans,
        1,
        "only the pre-exec completion orphaned"
    );
    assert!(s.has_process_state(new));
}

/// E20/H9-§2, persisted async through the actual capture-wide
/// reducer: GetID → Finalize → Initialize → Join → Complete. The
/// process's own finalize kills its detached ids; Initialize
/// resurrects nothing, so joining the old value orphans without
/// adopting a dead operation — while re-issuing the same value
/// fresh works cleanly.
#[test]
fn e20_persisted_async_value_reuse_after_finalize() {
    let target = crate::kinds::function_id("C_SignInit").unwrap();
    let (mut s, mut t, _) = setup(16);
    let a = key(90, 0);
    feed(&mut s, &mut t, [ev(100, 90, 0, 0)]);
    let mut init = ev(100, 90, 0, 1);
    init.rv = pkcs11_types::CkRv::PENDING.0;
    init.capture = capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL;
    init.mechanism = 0x101;
    feed(&mut s, &mut t, [init]);
    let mut get = ev(100, 90, 0, 4);
    get.target_function = target;
    get.async_value = 42;
    feed(&mut s, &mut t, [get]);
    assert_eq!(s.pending_at_end(), 1);

    // The process's own finalize kills its detached ids.
    let mut finalize = ev(100, 90, 0, 3);
    finalize.session = p11scope_ebpf_common::SESSION_NONE;
    feed(&mut s, &mut t, [finalize]);
    assert_eq!(s.pending_at_end(), 0);
    assert!(!s.has_process_state(a));

    // Re-initialize: rouses nothing.
    let initialize = ev(100, 90, 0, 10);
    feed(&mut s, &mut t, [initialize]);
    assert_eq!(s.pending_at_end(), 0);
    assert_eq!(
        s.cgroups()[&0].calls,
        5,
        "Initialize routed and counted, not dropped"
    );

    // Joining the old value orphans: no adoption of a dead operation.
    let mut open = ev(100, 90, 0, 0);
    open.session = 9;
    feed(&mut s, &mut t, [open]);
    let mut join = ev(100, 90, 0, 5);
    join.session = 9;
    join.target_function = target;
    join.async_value = 42;
    feed(&mut s, &mut t, [join]);
    assert_eq!(s.semantic_evidence().async_orphans, 1);
    let mut complete = ev(100, 90, 0, 6);
    complete.session = 9;
    complete.target_function = target;
    feed(&mut s, &mut t, [complete]);
    assert_eq!(s.semantic_evidence().async_orphans, 2);
    assert!(s.mechanisms().is_empty(), "the dead id published nothing");

    // Re-issuing the same value fresh works cleanly.
    let mut init = ev(100, 90, 0, 1);
    init.session = 9;
    init.rv = pkcs11_types::CkRv::PENDING.0;
    init.capture = capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL;
    init.mechanism = 0x101;
    feed(&mut s, &mut t, [init]);
    let mut get = ev(100, 90, 0, 4);
    get.session = 9;
    get.target_function = target;
    get.async_value = 42;
    feed(&mut s, &mut t, [get]);
    assert_eq!(s.semantic_evidence().async_duplicates, 0);
    let mut join = ev(100, 90, 0, 5);
    join.session = 9;
    join.target_function = target;
    join.async_value = 42;
    feed(&mut s, &mut t, [join]);
    let mut complete = ev(100, 90, 0, 6);
    complete.session = 9;
    complete.target_function = target;
    complete.async_value = pkcs11_types::CkRv::OK.0;
    feed(&mut s, &mut t, [complete]);
    assert_eq!(s.pending_at_end(), 0);
    assert_eq!(
        s.semantic_evidence().async_orphans,
        2,
        "only the dead-id join and completion orphaned"
    );
}

/// E20/H9-§2, the independently proven legitimate transfer: a join
/// from a process with no open session refuses (target failure, not
/// adoption), which is what makes the receiver's own open the
/// transfer's legitimacy proof.
#[test]
fn e20_transfer_without_receiver_open_refuses_without_adoption() {
    let target = crate::kinds::function_id("C_SignInit").unwrap();
    let (mut s, mut t, _) = setup(16);
    let a = key(90, 0);
    feed(&mut s, &mut t, [ev(100, 90, 0, 0), ev(200, 20, 0, 0)]);
    let mut init = ev(100, 90, 0, 1);
    init.rv = pkcs11_types::CkRv::PENDING.0;
    init.capture = capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL;
    init.mechanism = 0x101;
    feed(&mut s, &mut t, [init]);
    let mut get = ev(100, 90, 0, 4);
    get.target_function = target;
    get.async_value = 42;
    feed(&mut s, &mut t, [get]);
    // B closes its only session: the join below arrives with no
    // open session to prove the receiver.
    feed(&mut s, &mut t, [ev(200, 20, 0, 8)]);
    let mut join = ev(200, 20, 0, 5);
    join.target_function = target;
    join.async_value = 42;
    feed(&mut s, &mut t, [join]);
    assert_eq!(s.semantic_evidence().async_target_failures, 1);
    assert_eq!(s.semantic_evidence().async_orphans, 0);
    assert_eq!(s.pending_at_end(), 1, "custody never moved");
    assert!(s.has_process_state(a));
    // The owner still completes its own operation cleanly.
    let mut complete = ev(100, 90, 0, 6);
    complete.target_function = target;
    complete.async_value = pkcs11_types::CkRv::OK.0;
    feed(&mut s, &mut t, [complete]);
    assert_eq!(s.pending_at_end(), 0);
    assert_eq!(s.semantic_evidence().async_orphans, 0);
}

/// Wide producer history (ADR identity-design P1.5): a producer tracker at
/// the ticket budget admits the 16,385th distinct task, fills to 262,144
/// with an exact admitted count, and refuses the 262,145th.
#[test]
fn producer_tracker_admits_past_16384_to_the_wide_budget() {
    let limit = p11scope_ebpf_common::IMAGE_IDENTITY_TICKET_LIMIT as usize;
    let domain = crate::events::EventsDomain::test_standin(1);
    let mut tracker = process::Tracker::for_producer(domain, limit);
    let mut admitted = 0usize;
    for cookie in 1..=262_145u64 {
        let image = ImageIdentity {
            task_cookie: cookie,
            exec_id: 0,
        };
        #[allow(clippy::cast_possible_truncation)]
        let pid = cookie as u32;
        let (key, retired) = tracker.admit_history(1, pid, image, 0);
        assert!(retired.is_empty(), "cookie={cookie}");
        if key.is_some() {
            admitted += 1;
            assert_eq!(admitted as u64, cookie, "cookie={cookie}");
        } else {
            assert_eq!(cookie, 262_145, "first refusal must be past the budget");
        }
    }
    assert_eq!(admitted, 262_144);
}

/// The producer history bound is the ticket budget (ADR identity-design
/// Decision 4): one history slot per lifetime ticket, never less.
#[test]
fn producer_history_limit_is_the_ticket_budget() {
    assert_eq!(process::PRODUCER_HISTORY_LIMIT, 262_144);
    assert_eq!(
        process::PRODUCER_HISTORY_LIMIT,
        p11scope_ebpf_common::IMAGE_IDENTITY_TICKET_LIMIT as usize
    );
}

// ---- Reviewer probes: failing-first exit-retire twins ----
// Each asserts the correct behaviour: a FORK-admitted reuse successor is
// spared (probe 1), a post-exec generation first admitted by a FORK is
// spared (probe 2), a leader exit with live threads keeps session
// continuity (probe 3), a fork+exec child frees every R10 entry on exit
// (probe 4), and an exit retire keeps naming pending gaps (probe 5).

#[test]
fn probe_fork_admitted_reuse_successor_is_spared() {
    // Real reducer seam: FORK records carry ts_ns 0 from BPF
    // (p11_link_emit_fork builds `..Event::default()`).
    let (mut s, mut t, _) = setup(64);
    let mut popen = ev(50, 80, 0, 0);
    popen.ts_ns = 10;
    let mut ocall = ev(100, 90, 0, 0);
    ocall.ts_ns = 100;
    feed(&mut s, &mut t, [popen, ocall]);
    let old = key(90, 0);
    assert!(s.has_process_state(old));
    t.note_exit_taps(
        vec![crate::history::ExitTap {
            pid: 100,
            hook_ts_ns: 200,
        }],
        1000,
    );
    let mut birth = ev(50, 80, 0, 0);
    birth.event_type = event_type::FORK;
    birth.session = 100;
    birth.child_image = ImageIdentity {
        task_cookie: 91,
        exec_id: 0,
    };
    birth.ts_ns = 0;
    feed(&mut s, &mut t, [birth]);
    let child = semantics::ProcessKey::history(1, 91, 0, 100);
    assert!(s.has_process_state(child), "child inherited the session");
    let closed_before = s.sessions().closed;
    let due = t.retire_exits_due(1000, 1000, EXIT_RETIRE_PER_DRAIN_BUDGET);
    s.retire_processes(&due);
    eprintln!(
        "PROBE1 due={due:?} closed {closed_before}->{} child_state={}",
        s.sessions().closed,
        s.has_process_state(child)
    );
    assert!(
        !due.contains(&child),
        "FORK-admitted reuse successor (live) was retired with the old generation"
    );
}

#[test]
fn probe_exec_bump_via_fork_spares_post_exec_generation() {
    let (mut s, mut t, _) = setup(64);
    let mut pre = ev(100, 90, 0, 0);
    pre.ts_ns = 100;
    feed(&mut s, &mut t, [pre]);
    // de_thread: the old leader exits at 200 while a non-leader execs.
    t.note_exit_taps(
        vec![crate::history::ExitTap {
            pid: 100,
            hook_ts_ns: 200,
        }],
        1000,
    );
    // First post-exec event is a FORK (ts 0), then a CALL opening session 8.
    let mut birth = ev(100, 90, 1, 0);
    birth.event_type = event_type::FORK;
    birth.session = 300;
    birth.child_image = ImageIdentity {
        task_cookie: 95,
        exec_id: 0,
    };
    birth.ts_ns = 0;
    let mut open8 = ev(100, 90, 1, 0);
    open8.session = 8;
    open8.ts_ns = 300;
    feed(&mut s, &mut t, [birth, open8]);
    let live = key(90, 1);
    assert!(s.has_process_state(live));
    let closed_before = s.sessions().closed;
    let due = t.retire_exits_due(1000, 1000, EXIT_RETIRE_PER_DRAIN_BUDGET);
    s.retire_processes(&due);
    eprintln!(
        "PROBE2 due={due:?} closed {closed_before}->{} live_state={}",
        s.sessions().closed,
        s.has_process_state(live)
    );
    assert!(
        !due.contains(&live),
        "post-exec live generation (first admitted by a ts-0 FORK) was retired by the pre-exec leader exit"
    );
}

#[test]
fn probe_leader_exit_with_live_threads_session_continuity() {
    let (mut s, mut t, _) = setup(64);
    let mut open7 = ev(100, 90, 0, 0);
    open7.ts_ns = 100;
    feed(&mut s, &mut t, [open7]);
    let k = key(90, 0);
    let p7 = s.session_pseudonym_process(k, 0, 7);
    // Leader thread exits (pthread_exit) at 200; workers keep running.
    t.note_exit_taps(
        vec![crate::history::ExitTap {
            pid: 100,
            hook_ts_ns: 200,
        }],
        1000,
    );
    let due = t.retire_exits_due(1000, 1000, EXIT_RETIRE_PER_DRAIN_BUDGET);
    s.retire_processes(&due);
    // A worker opens session 8 at 300, then closes session 7 at 310.
    let mut open8 = ev(100, 90, 0, 0);
    open8.session = 8;
    open8.ts_ns = 300;
    let mut close7 = ev(100, 90, 0, 8);
    close7.ts_ns = 310;
    feed(&mut s, &mut t, [open8, close7]);
    let p8 = s.session_pseudonym_process(k, 0, 8);
    let v = s.sessions();
    eprintln!(
        "PROBE3 p7={p7:?} p8={p8:?} opened={} closed={} unmatched_closes={} counters={:?}",
        v.opened,
        v.closed,
        s.unmatched_closes(),
        t.exit_counters_for_test()
    );
    assert_ne!(
        p7, p8,
        "a reopened live process reuses a retired session's pseudonym"
    );
    assert_eq!(
        s.unmatched_closes(),
        0,
        "closing the retired session counts unmatched"
    );
}

#[test]
fn probe_fork_exec_child_exit_frees_every_r10_entry() {
    let (mut s, mut t, _) = setup(64);
    let mut popen = ev(50, 80, 0, 0);
    popen.ts_ns = 10;
    feed(&mut s, &mut t, [popen]);
    let mut birth = ev(50, 80, 0, 0);
    birth.event_type = event_type::FORK;
    birth.session = 300;
    birth.child_image = ImageIdentity {
        task_cookie: 95,
        exec_id: 0,
    };
    feed(&mut s, &mut t, [birth]);
    // The child execs and calls under the new image (exec bump).
    let mut ccall = ev(300, 95, 1, 0);
    ccall.session = 9;
    ccall.ts_ns = 100;
    feed(&mut s, &mut t, [ccall]);
    let r10_before = s.memory_lens().reduced.len;
    t.note_exit_taps(
        vec![crate::history::ExitTap {
            pid: 300,
            hook_ts_ns: 200,
        }],
        1000,
    );
    let due = t.retire_exits_due(1000, 1000, EXIT_RETIRE_PER_DRAIN_BUDGET);
    s.retire_processes(&due);
    let parent_alive = |pid: u32| pid == 50;
    let (_, dead, dead_rows, _) = s.memory_sample(&parent_alive);
    eprintln!(
        "PROBE4 r10 before={r10_before} after={} dead_procs={dead} r10_dead={}",
        s.memory_lens().reduced.len,
        dead_rows.reduced_dead.len
    );
    assert_eq!(
        dead_rows.reduced_dead.len, 0,
        "the exec-superseded generation's R10 entry stays dead-owned after the exit"
    );
}

#[test]
fn probe_exit_retire_keeps_pending_at_end() {
    let (mut s, mut t, _) = setup(64);
    let mut open = ev(100, 90, 0, 0);
    open.ts_ns = 100;
    let mut pending = ev(100, 90, 0, 2);
    pending.ts_ns = 101;
    pending.rv = pkcs11_types::CkRv::PENDING.0;
    feed(&mut s, &mut t, [open, pending]);
    let before = s.pending_at_end();
    t.note_exit_taps(
        vec![crate::history::ExitTap {
            pid: 100,
            hook_ts_ns: 200,
        }],
        1000,
    );
    let due = t.retire_exits_due(1000, 1000, EXIT_RETIRE_PER_DRAIN_BUDGET);
    s.retire_processes(&due);
    eprintln!(
        "PROBE5 pending_at_end before={before} after={}",
        s.pending_at_end()
    );
    assert_eq!(
        s.pending_at_end(),
        before,
        "exit retire silently removes an unresolved async call from the rendered pending_at_end gap"
    );
}
