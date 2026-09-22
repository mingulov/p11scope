//! SPDX-License-Identifier: GPL-3.0-or-later
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
            )
            .0,
        Some(parent)
    );
    assert_eq!(registry.admit(1, 200, child_image).0, Some(child));
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
        assert_eq!(t.admit_history(1, 200, birth.child_image).0, Some(child(1)));
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
    assert!(tracker.admit_history(1, 100, first.image).0.is_none());
    assert!(tracker.admit_history(1, 100, exec.image).0.is_none());
    assert!(tracker.admit_history(1, 200, delayed.image).0.is_none());
    assert!(tracker.admit_history(1, 100, unknown.image).0.is_some());
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
        assert!(tracker.admit_history(1, 100, positive.image).0.is_none());
        assert!(tracker.admit_history(1, 200, unknown.image).0.is_some());
        assert!(tracker.admit_history(1, 300, fork.child_image).0.is_some());
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
            assert!(tracker.admit_history(1, 100, positive.image).0.is_some());
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
        assert!(tracker.admit_history(1, 100, positive.image).0.is_some());
        assert!(tracker.admit_history(1, 200, unknown.image).0.is_some());
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

#[test]
fn root_cancel_never_relabels_timeout_domain_reducer_or_crossing_failures() {
    for failure in 0..4 {
        let domain = crate::events::EventsDomain::test_standin(1);
        let deadline = if failure == 0 {
            Instant::now() - Duration::from_secs(1)
        } else {
            // These cases assert domain, reducer, and cursor-crossing
            // failures. Keep the wall clock from becoming a competing
            // failure source when the full suite deschedules this test.
            Instant::now() + Duration::from_secs(60 * 60)
        };
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
