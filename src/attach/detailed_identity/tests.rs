//! SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn cgroup_ready_fixture() -> (ProofSession, crate::process::ProcessView, CgroupCandidate) {
    let scope = Scope::Cgroup {
        id: 1,
        path: "/retained-only".into(),
        dir: Arc::new(std::fs::File::open("/dev/null").unwrap()),
    };
    let proof = ProofSession::test_scope(&scope, true);
    proof.test_set_time(100);
    let view = crate::process::ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let mut work = TraceWorkTicket::test_new(proof.clone(), 100, 5_000_100);
    let candidate = proof.register_cgroup(&view, &mut work).unwrap();
    proof.test_set_time(200);
    let event = Event {
        pid_tgid: u64::from(view.pid()) << 32,
        ts_ns: 101,
        image: p11scope_ebpf_common::ImageIdentity {
            task_cookie: 11,
            exec_id: 0,
        },
        ..Event::default()
    };
    let mut drain = crate::events::EventDrain::over_domain(
        crate::events::ScriptedRecords::events([event], 1),
        proof.test_events_domain(),
    );
    drain.attach_trace_tap(proof.test_events_tap()).unwrap();
    drain.poll(None, |_| std::ops::ControlFlow::Continue(()));
    (proof, view, candidate)
}
#[test]
fn cgroup_trace_bracket_reader_first_permit_and_cookie_sandwich() {
    let (proof, view, mut candidate) = cgroup_ready_fixture();
    let mut spent = TraceWorkTicket::test_new(proof.clone(), 200, 5_000_200);
    proof.test_health(Ok(0), 7, 8).unwrap();
    for _ in 0..32 {
        spent.external_read(&proof).unwrap();
    }
    assert_eq!(
        proof.test_sample_cgroup(
            &mut candidate,
            &view,
            &mut spent,
            (b"/owned/fixture", None),
            || panic!("no cookie after read allowance exhausted"),
            |_| panic!("baseline already exists")
        ),
        Err(TraceWorkError::Deferred)
    );
    let before = proof.test_cgroup_snapshot(candidate.id()).unwrap();
    assert_eq!(before.starts, 0);
    assert!(before.first_start.is_none());
    assert_eq!(proof.usage(), (1, 0));
    let cookies = std::cell::Cell::new(0);
    let mut after = || {
        assert_eq!(
            cookies.get(),
            1,
            "original cookie precedes executable reads"
        )
    };
    let mut work = TraceWorkTicket::test_new(
        proof.clone(),
        proof.test_time(),
        proof.test_time() + 5_000_000,
    );
    proof
        .test_sample_cgroup(
            &mut candidate,
            &view,
            &mut work,
            (b"/owned/fixture", Some(&mut after)),
            || {
                cookies.set(cookies.get() + 1);
                Ok(Some(11))
            },
            |_| panic!("no redundant baseline"),
        )
        .unwrap();
    assert_eq!(
        cookies.get(),
        2,
        "same original cookie is read again after all executable validation"
    );
    let after = proof.test_cgroup_snapshot(candidate.id()).unwrap();
    assert_eq!(after.starts, 1);
    assert!(after.completed.unwrap() >= after.first_start.unwrap());
    assert_eq!(proof.usage(), (1, 14));
}
#[test]
fn cgroup_trace_bracket_nonbudget_failures_cannot_restart_or_keep_path() {
    for fault in 0..4 {
        let (proof, view, mut candidate) = cgroup_ready_fixture();
        let mut work = TraceWorkTicket::test_new(proof.clone(), 200, 5_000_200);
        let cookies = std::cell::Cell::new(0);
        let mut after = || match fault {
            0 => proof.test_set_time(u64::MAX),
            1 => proof.test_set_time(1),
            2 => proof.test_events_tap().observe_failure(),
            _ => proof.test_set_time(60_000_000_500),
        };
        let result = proof.test_sample_cgroup(
            &mut candidate,
            &view,
            &mut work,
            (b"/owned/fixture", Some(&mut after)),
            || {
                cookies.set(cookies.get() + 1);
                Ok(Some(11))
            },
            |work| proof.test_refresh_read(work, Ok(0)),
        );
        assert!(matches!(result, Err(TraceWorkError::Unknown(_))));
        assert_eq!(
            cookies.get(),
            1,
            "a read-observed failure stops before the post-executable cookie read"
        );
        assert_eq!(proof.usage(), (1, 0));
        let snapshot = proof.test_cgroup_snapshot(candidate.id()).unwrap();
        assert!(snapshot.parked && snapshot.completed.is_none());
        assert_eq!(snapshot.starts, 1);
        proof.test_set_time(1_000);
        let mut fresh = TraceWorkTicket::test_new(proof.clone(), 1_000, 5_001_000);
        assert!(
            proof
                .test_sample_cgroup(
                    &mut candidate,
                    &view,
                    &mut fresh,
                    (b"/owned/fixture", None),
                    || panic!("actual failure cannot restart"),
                    |_| panic!("no health after parked failure")
                )
                .is_err()
        );
        assert_eq!(
            proof.test_cgroup_snapshot(candidate.id()).unwrap().starts,
            1
        );
    }
}
#[test]
fn cgroup_trace_bracket_utf8_and_path_caps_remain_shared() {
    for (link, fits) in [
        (vec![b'a'; 4096], true),
        (vec![b'a'; 4097], false),
        (vec![0xff; 1365], true),
        (vec![0xff; 1366], false),
    ] {
        let (proof, view, mut candidate) = cgroup_ready_fixture();
        let mut work = TraceWorkTicket::test_new(proof.clone(), 200, 5_000_200);
        let result = proof.test_sample_cgroup(
            &mut candidate,
            &view,
            &mut work,
            (&link, None),
            || Ok(Some(11)),
            |work| proof.test_refresh_read(work, Ok(0)),
        );
        assert_eq!(result.is_ok(), fits);
        assert_eq!(
            proof.usage(),
            (
                1,
                if fits {
                    String::from_utf8_lossy(&link).len()
                } else {
                    0
                }
            )
        );
    }
}
#[test]
fn cgroup_trace_bracket_baseline_loss_forbids_the_first_cookie_read() {
    let (proof, view, candidate) = cgroup_ready_fixture();
    let mut baseline = TraceWorkTicket::test_new(proof.clone(), 200, 5_000_200);
    proof.test_refresh_read(&mut baseline, Ok(0)).unwrap();
    let mut malformed = crate::events::DiscoveryDrain::over_domain(
        crate::events::ScriptedRecords::records([vec![0]], 1),
        proof.test_discovery_domain(),
    );
    malformed
        .attach_trace_tap(proof.test_discovery_tap())
        .unwrap();
    assert!(matches!(
        malformed.dequeue(),
        Some(crate::events::DiscoveryItem::Malformed)
    ));
    drop(candidate);
    proof.test_set_time(300);
    let mut work = TraceWorkTicket::test_new(proof.clone(), 300, 5_000_300);
    let mut candidate = proof.register_cgroup(&view, &mut work).unwrap();
    proof.test_set_time(400);
    let event = Event {
        pid_tgid: u64::from(view.pid()) << 32,
        ts_ns: 301,
        image: p11scope_ebpf_common::ImageIdentity {
            task_cookie: 11,
            exec_id: 0,
        },
        ..Event::default()
    };
    let mut events = crate::events::EventDrain::over_domain(
        crate::events::ScriptedRecords::events([event], 1),
        proof.test_events_domain(),
    );
    events.attach_trace_tap(proof.test_events_tap()).unwrap();
    events.poll(None, |_| std::ops::ControlFlow::Continue(()));
    let mut work = TraceWorkTicket::test_new(proof.clone(), 400, 5_000_400);
    let cookies = std::cell::Cell::new(0);
    let result = proof.test_sample_cgroup(
        &mut candidate,
        &view,
        &mut work,
        (b"/owned/fixture", None),
        || {
            cookies.set(cookies.get() + 1);
            Ok(Some(11))
        },
        |work| proof.test_refresh_read(work, Ok(1)),
    );
    assert_eq!(
        result,
        Err(TraceWorkError::Unknown(TraceProofUnknown::LifecycleLoss))
    );
    assert_eq!(
        cookies.get(),
        0,
        "loss observed by the baseline refuses sample I/O immediately"
    );
    assert_eq!(
        proof.test_cgroup_snapshot(candidate.id()).unwrap().starts,
        0
    );
    assert_eq!(proof.usage(), (1, 0));
}
#[test]
fn cgroup_trace_bracket_poisoned_accepted_drop_cleans_all_nonowning_indexes() {
    let (proof, receipt) =
        crate::discovery::engine::tests::detailed_proof_driver::cgroup_verified_fixture();
    assert_eq!(proof.usage(), (1, 14));
    let authority = proof.authority.clone();
    let _ = std::panic::catch_unwind(|| {
        let _guard = authority.ledger.lock().unwrap();
        panic!("poison genuine accepted authority");
    });
    drop(receipt);
    assert_eq!(proof.usage(), (0, 0));
    let ledger = authority
        .ledger
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    assert!(
        ledger.pending.is_empty() && ledger.accepted.is_empty() && ledger.accepted_keys.is_empty()
    );
    assert!(ledger.pids.is_empty() && ledger.cgroup_views.is_empty());
}
#[test]
fn cgroup_trace_bracket_exit_inside_sample_stops_all_later_reads() {
    let (proof, view, mut candidate) = cgroup_ready_fixture();
    let mut work = TraceWorkTicket::test_new(proof.clone(), 200, 5_000_200);
    let cookies = std::cell::Cell::new(0);
    let mut after = || {
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.pid_tgid = u64::from(view.pid()) << 32;
        record.kind = p11scope_ebpf_common::DISCOVERY_KIND_LEADER_EXIT;
        record.hook_ts_ns = proof.test_time();
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&record as *const DiscoveryRecord).cast::<u8>(),
                std::mem::size_of::<DiscoveryRecord>(),
            )
        }
        .to_vec();
        let mut drain = crate::events::DiscoveryDrain::over_domain(
            crate::events::ScriptedRecords::records([bytes], 1),
            proof.test_discovery_domain(),
        );
        drain.attach_trace_tap(proof.test_discovery_tap()).unwrap();
        assert!(matches!(
            drain.dequeue(),
            Some(crate::events::DiscoveryItem::Record(_))
        ));
    };
    let result = proof.test_sample_cgroup(
        &mut candidate,
        &view,
        &mut work,
        (b"/owned/fixture", Some(&mut after)),
        || {
            cookies.set(cookies.get() + 1);
            Ok(Some(11))
        },
        |work| proof.test_refresh_read(work, Ok(0)),
    );
    assert_eq!(
        result,
        Err(TraceWorkError::Unknown(TraceProofUnknown::TargetGone))
    );
    assert_eq!(
        cookies.get(),
        1,
        "actual retained lifecycle cancellation stops before the second cookie read"
    );
    assert_eq!(proof.usage(), (1, 0));
}

#[derive(Clone, Copy, Debug)]
enum Exhaustion {
    Reads,
    Frame,
}
fn exhaust_ticket(
    proof: &ProofSession,
    work: &mut TraceWorkTicket,
    exhaustion: Exhaustion,
    deadline: u64,
) {
    match exhaustion {
        Exhaustion::Reads => while work.external_read(proof).is_ok() {},
        Exhaustion::Frame => proof.test_set_time(deadline),
    }
}
#[test]
fn cgroup_trace_bracket_post_cookie_failure_wins_over_exhausted_allowance() {
    for exhaustion in [Exhaustion::Reads, Exhaustion::Frame] {
        for (bad_cookie, reason) in [
            (None, TraceProofUnknown::Unreadable),
            (Some(0), TraceProofUnknown::Unreadable),
            (Some(12), TraceProofUnknown::TargetGone),
        ] {
            let (proof, view, mut candidate) = cgroup_ready_fixture();
            proof.test_health(Ok(0), 7, 8).unwrap();
            let deadline = 5_000_200;
            let mut work = TraceWorkTicket::test_new(proof.clone(), 200, deadline);
            let mut shared = work.clone();
            let mut cookies = 0;
            let result = proof.test_sample_cgroup(
                &mut candidate,
                &view,
                &mut work,
                (b"/owned/fixture", None),
                || {
                    cookies += 1;
                    if cookies == 1 {
                        Ok(Some(11))
                    } else {
                        exhaust_ticket(&proof, &mut shared, exhaustion, deadline);
                        Ok(bad_cookie)
                    }
                },
                |_| panic!("baseline already exists"),
            );
            assert_eq!(
                result,
                Err(TraceWorkError::Unknown(reason)),
                "{exhaustion:?} {bad_cookie:?}"
            );
            assert_eq!(cookies, 2);
            assert_eq!(proof.usage(), (1, 0));
            let snapshot = proof.test_cgroup_snapshot(candidate.id()).unwrap();
            assert!(snapshot.parked && snapshot.completed.is_none());
            proof.test_tick();
            let now = proof.test_time();
            let mut fresh = TraceWorkTicket::test_new(proof.clone(), now, now + 5_000_000);
            assert!(
                proof
                    .test_sample_cgroup(
                        &mut candidate,
                        &view,
                        &mut fresh,
                        (b"/owned/fixture", None),
                        || panic!("failed cookie cannot restart"),
                        |_| panic!("parked sample cannot read health")
                    )
                    .is_err()
            );
            assert_eq!(
                proof.test_cgroup_snapshot(candidate.id()).unwrap().starts,
                1
            );
        }
    }
}
#[test]
fn cgroup_trace_bracket_confirmation_cookie_failure_wins_over_exhausted_allowance() {
    for exhaustion in [Exhaustion::Reads, Exhaustion::Frame] {
        for (bad_cookie, reason) in [
            (None, TraceProofUnknown::Unreadable),
            (Some(0), TraceProofUnknown::Unreadable),
            (Some(12), TraceProofUnknown::TargetGone),
        ] {
            let (proof, view, mut candidate) = cgroup_ready_fixture();
            proof.test_health(Ok(0), 7, 8).unwrap();
            let mut sample = TraceWorkTicket::test_new(proof.clone(), 200, 5_000_200);
            proof
                .test_sample_cgroup(
                    &mut candidate,
                    &view,
                    &mut sample,
                    (b"/owned/fixture", None),
                    || Ok(Some(11)),
                    |_| panic!("baseline already exists"),
                )
                .unwrap();
            let upper = proof.test_time() + 1;
            proof.test_set_time(upper + 1);
            let event = Event {
                pid_tgid: u64::from(view.pid()) << 32,
                ts_ns: upper,
                image: p11scope_ebpf_common::ImageIdentity {
                    task_cookie: 11,
                    exec_id: 0,
                },
                ..Event::default()
            };
            let mut drain = crate::events::EventDrain::over_domain(
                crate::events::ScriptedRecords::events([event], 1),
                proof.test_events_domain(),
            );
            drain.attach_trace_tap(proof.test_events_tap()).unwrap();
            drain.poll(None, |_| std::ops::ControlFlow::Continue(()));
            let now = proof.test_time();
            let deadline = now + 5_000_000;
            let mut work = TraceWorkTicket::test_new(proof.clone(), now, deadline);
            let mut shared = work.clone();
            let mut cookies = 0;
            let result = proof.test_confirm_cgroup(&mut candidate, &view, &mut work, || {
                cookies += 1;
                exhaust_ticket(&proof, &mut shared, exhaustion, deadline);
                Ok(bad_cookie)
            });
            assert_eq!(
                result,
                Err(TraceWorkError::Unknown(reason)),
                "{exhaustion:?} {bad_cookie:?}"
            );
            assert_eq!(cookies, 1);
            assert_eq!(proof.usage(), (1, 0));
            let snapshot = proof.test_cgroup_snapshot(candidate.id()).unwrap();
            assert!(snapshot.parked && snapshot.arm.is_none());
            proof.test_tick();
            let now = proof.test_time();
            let mut fresh = TraceWorkTicket::test_new(proof.clone(), now, now + 5_000_000);
            assert!(
                proof
                    .test_confirm_cgroup(&mut candidate, &view, &mut fresh, || panic!(
                        "failed confirmation cannot retry"
                    ))
                    .is_err()
            );
        }
    }
}
struct ChangedLinkSample<'a> {
    inner: FixtureSample<'a>,
    links: usize,
    stats: usize,
    after_second_link: &'a mut dyn FnMut(),
}
impl SampleSource for ChangedLinkSample<'_> {
    fn exited(&mut self) -> Result<bool, TraceProofUnknown> {
        self.inner.exited()
    }
    fn stat(&mut self) -> Result<ExeStat, TraceProofUnknown> {
        self.stats += 1;
        self.inner.stat()
    }
    fn link(&mut self, buf: &mut [u8; IMAGE_PATH_CAP + 1]) -> Result<usize, TraceProofUnknown> {
        let n = self.inner.link(buf)?;
        self.links += 1;
        if self.links == 2 {
            buf[0] = b'!';
            (self.after_second_link)();
        }
        Ok(n)
    }
    fn birth(
        &mut self,
        proof: &ProofSession,
        work: &mut TraceWorkTicket,
    ) -> Result<u64, TraceWorkError> {
        self.inner.birth(proof, work)
    }
    fn namespace(&mut self) -> Result<crate::process::MountNamespaceId, TraceProofUnknown> {
        self.inner.namespace()
    }
}
#[test]
fn cgroup_trace_bracket_completed_path_change_wins_over_exhausted_allowance() {
    for exhaustion in [Exhaustion::Reads, Exhaustion::Frame] {
        let (proof, view, mut candidate) = cgroup_ready_fixture();
        proof.test_health(Ok(0), 7, 8).unwrap();
        let deadline = 5_000_200;
        let mut work = TraceWorkTicket::test_new(proof.clone(), 200, deadline);
        let mut shared = work.clone();
        let mut boundary = || exhaust_ticket(&proof, &mut shared, exhaustion, deadline);
        let mut source = ChangedLinkSample {
            inner: FixtureSample {
                view: &view,
                proof: &proof,
                link: b"/owned/fixture",
                after_first_link: None,
            },
            links: 0,
            stats: 0,
            after_second_link: &mut boundary,
        };
        let mut cookies = 0;
        let result = proof.sample_cgroup_from(
            &mut candidate,
            &view,
            &mut work,
            &mut source,
            || {
                cookies += 1;
                Ok(Some(11))
            },
            |_| panic!("baseline already exists"),
        );
        assert_eq!(
            result,
            Err(TraceWorkError::Unknown(TraceProofUnknown::ExecChanged)),
            "{exhaustion:?}"
        );
        assert_eq!(
            (source.links, source.stats, cookies),
            (2, 1, 1),
            "completed differing paths stop before any later read"
        );
        assert_eq!(proof.usage(), (1, 0));
        assert!(proof.test_cgroup_snapshot(candidate.id()).unwrap().parked);
        proof.test_tick();
        let now = proof.test_time();
        let mut fresh = TraceWorkTicket::test_new(proof.clone(), now, now + 5_000_000);
        assert!(
            proof
                .test_sample_cgroup(
                    &mut candidate,
                    &view,
                    &mut fresh,
                    (b"/owned/fixture", None),
                    || panic!("completed path failure cannot restart"),
                    |_| panic!("parked sample cannot read health")
                )
                .is_err()
        );
        assert_eq!(
            proof.test_cgroup_snapshot(candidate.id()).unwrap().starts,
            1
        );
    }
}

#[test]
fn detailed_proof_foreign_session_equal_cookie_refused() {
    let a = ProofSession::test_session();
    let b = ProofSession::test_session();
    let held = a.reserve(4).expect("stable same-Session reservation");
    assert!(a.owns(&held));
    assert!(
        !b.owns(&held),
        "equal domain integers cannot authenticate another allocation"
    );
    let mut cursor = crate::events::EventDrain::over_domain(
        crate::events::ScriptedRecords::events([], 0),
        a.test_events_domain(),
    );
    assert_eq!(
        cursor.attach_trace_tap(b.test_events_tap()),
        Err(TraceProofUnknown::DomainMismatch)
    );
    assert!(cursor.attach_trace_tap(a.test_events_tap()).is_ok());
}

#[test]
fn detailed_proof_reservation_transfer_keeps_charge() {
    let proof = ProofSession::test_session();
    let held = proof
        .reserve(16384)
        .expect("reserve bounded sampling scratch");
    assert_eq!(proof.usage(), (1, 16384));
    let mut transferred = held;
    transferred.shrink(7).unwrap();
    assert_eq!(proof.usage(), (1, 7));
    drop(transferred);
    assert_eq!(proof.usage(), (0, 0));
}

#[test]
fn detailed_proof_total_entry_and_path_caps() {
    let proof = ProofSession::test_session();
    let mut held = Vec::new();
    for _ in 0..16384 {
        held.push(proof.reserve(0).expect("each charged metadata entry fits"));
    }
    assert!(matches!(proof.reserve(0), Err(TraceProofUnknown::Budget)));
    drop(held);
    assert_eq!(proof.usage(), (0, 0));
    let mut held = Vec::new();
    for _ in 0..2048 {
        held.push(
            proof
                .reserve(4096)
                .expect("retained path pool fits exact edge"),
        );
    }
    assert_eq!(proof.usage(), (2048, 8388608));
    assert!(matches!(proof.reserve(1), Err(TraceProofUnknown::Budget)));
    drop(held);
    assert!(proof.reserve(8388609).is_err());
    assert_eq!(proof.usage(), (0, 0));
}

#[test]
fn detailed_proof_cookie_requires_original_live_pidfd() {
    let mut checks = 0;
    let cookie = checked_cookie(
        true,
        || {
            checks += 1;
            Ok(false)
        },
        || Ok(Some(11)),
    );
    assert_eq!(cookie, Ok(11));
    assert_eq!(
        checks, 2,
        "original descriptor is live before and after lookup"
    );
    assert_eq!(
        checked_cookie(false, || Ok(false), || Ok(Some(11))),
        Err(TraceProofUnknown::Unreadable)
    );
    assert_eq!(
        checked_cookie(true, || Ok(true), || Ok(Some(11))),
        Err(TraceProofUnknown::TargetGone)
    );
    assert_eq!(
        checked_cookie(true, || Err(()), || Ok(Some(11))),
        Err(TraceProofUnknown::Unreadable)
    );
    for value in [None, Some(0)] {
        assert_eq!(
            checked_cookie(true, || Ok(false), || Ok(value)),
            Err(TraceProofUnknown::Unreadable)
        );
    }
    let mut calls = 0;
    assert_eq!(
        checked_cookie(
            true,
            || {
                calls += 1;
                Ok(calls == 2)
            },
            || Ok(Some(11))
        ),
        Err(TraceProofUnknown::TargetGone)
    );
    assert_eq!(
        checked_cookie(true, || Ok(false), || Err(())),
        Err(TraceProofUnknown::Unreadable)
    );
}
// Prepared behavior tests for shared state machine, before production transitions.
#[test]
fn detailed_proof_old_or_equal_event_cannot_arm() {
    for ts in [5, 9, 10] {
        let proof = ProofSession::test_session();
        let seed = proof.test_pending(7, 9, 10);
        proof.test_call(7, ts, 11, 0, 21);
        assert_eq!(proof.test_witness(seed.id()), None);
        proof.test_call(7, 20, 11, 0, 21);
        assert_eq!(proof.test_witness(seed.id()), Some((11, 0, 20)));
    }
}
#[test]
fn detailed_proof_exec_during_sample_refuses() {
    let proof = ProofSession::test_session();
    let seed = proof.test_pending(7, 9, 10);
    proof.test_exec(7, 9);
    assert_eq!(
        proof.test_problem(seed.id()),
        Some(TraceProofUnknown::ExecChanged)
    );
}
#[test]
fn detailed_proof_equal_or_earlier_horizons_refuse() {
    for horizon in [21, 22] {
        let proof = ProofSession::test_session();
        let seed = proof.test_pending(7, 9, 10);
        proof.test_call(7, 20, 11, 0, 21);
        proof.test_arm(&seed, 11, 22).unwrap();
        proof.test_health(Ok(0), horizon, horizon).unwrap();
        proof.test_empty(horizon);
        assert!(proof.settle(&seed).unwrap().is_none());
        proof.test_health(Ok(0), 23, 24).unwrap();
        proof.test_empty(23);
        assert!(proof.settle(&seed).unwrap().is_some());
    }
}
#[test]
fn detailed_proof_health_exhaustion_is_sticky() {
    let proof = ProofSession::test_session();
    let seed = proof.test_pending(7, 9, 10);
    assert_eq!(
        proof.test_health(Ok(u64::MAX), 23, 24),
        Err(TraceProofUnknown::LifecycleLoss)
    );
    assert!(proof.test_health(Ok(0), 25, 26).is_err());
    assert!(matches!(
        proof.reserve(0),
        Err(TraceProofUnknown::LifecycleLoss)
    ));
    assert_eq!(
        proof.test_problem(seed.id()),
        Some(TraceProofUnknown::LifecycleLoss)
    );
}

#[test]
fn detailed_proof_loss_epoch_pressure_is_constant_work() {
    let proof = ProofSession::test_session();
    let held: Vec<_> = (1..=16384)
        .map(|pid| proof.test_pending(pid, 9, 10))
        .collect();
    let tap = proof.test_discovery_tap();
    for _ in 0..1000 {
        tap.observe_failure();
    }
    assert_eq!(proof.test_epoch(), 1000);
    assert_eq!(proof.usage(), (16384, 229376));
    for seed in &held {
        assert_eq!(proof.ready(seed), Err(TraceProofUnknown::LifecycleLoss));
    }
    drop(held);
    assert_eq!(proof.usage(), (0, 0));
}
#[test]
fn detailed_proof_internal_exhaustion_refuses_new_admissions() {
    let proof = ProofSession::test_session();
    let seed = proof.test_pending(7, 9, 10);
    {
        let mut ledger = proof.ledger().unwrap();
        ledger.loss_epoch = u64::MAX - 1;
    }
    proof.test_discovery_tap().observe_failure();
    assert!(matches!(
        proof.reserve(0),
        Err(TraceProofUnknown::LifecycleLoss)
    ));
    assert_eq!(proof.ready(&seed), Err(TraceProofUnknown::LifecycleLoss));
    assert!(proof.test_health(Ok(0), 23, 24).is_err());
}
#[test]
fn detailed_proof_delayed_pre_sample_does_not_replace_armed_witness() {
    let proof = ProofSession::test_session();
    let seed = proof.test_pending(7, 9, 10);
    proof.test_call(7, 20, 11, 2, 21);
    proof.test_arm(&seed, 11, 22).unwrap();
    proof.test_call(7, 5, 99, 0, 30);
    proof.test_exec(7, 5);
    proof.test_health(Ok(0), 31, 32).unwrap();
    proof.test_empty(31);
    assert_eq!(proof.ready(&seed).unwrap().unwrap().exec_id, 2);
    assert_eq!(proof.test_witness(seed.id()), Some((11, 2, 20)));
    proof.test_call(7, 33, 11, 1, 34);
    assert_eq!(
        proof.ready(&seed),
        Err(TraceProofUnknown::ExecChanged),
        "post-eligibility lower exec ID contradicts this candidate"
    );
}
#[test]
fn detailed_proof_poison_cleanup_has_no_recursive_lock() {
    let proof = ProofSession::test_session();
    let seed = proof.test_pending(7, 9, 10);
    let authority = proof.authority.clone();
    let _ = std::panic::catch_unwind(|| {
        let _guard = authority.ledger.lock().unwrap();
        panic!("poison fixture");
    });
    assert_eq!(proof.ready(&seed), Err(TraceProofUnknown::Unreadable));
    drop(seed);
    assert_eq!(proof.usage(), (0, 0));
}

// Existing reservation cleanup must also remove cgroup's nonowning admission
// indexes after poison, without destructor re-entry or retaining a descriptor.
#[test]
fn cgroup_trace_bracket_poisoned_registration_returns_its_only_charge() {
    let scope = Scope::Cgroup {
        id: 1,
        path: "/retained-only".into(),
        dir: Arc::new(std::fs::File::open("/dev/null").unwrap()),
    };
    let proof = ProofSession::test_scope(&scope, true);
    proof.test_set_time(100);
    let view = crate::process::ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let mut work = TraceWorkTicket::test_new(proof.clone(), 100, 5_000_100);
    let candidate = proof.register_cgroup(&view, &mut work).unwrap();
    assert_eq!(proof.usage(), (1, 0));
    let authority = proof.authority.clone();
    let _ = std::panic::catch_unwind(|| {
        let _guard = authority.ledger.lock().unwrap();
        panic!("poison registered authority");
    });
    assert_eq!(
        proof.cgroup_registration_status(&candidate, &view, &work),
        Err(TraceWorkError::Unknown(TraceProofUnknown::Unreadable))
    );
    drop(candidate);
    assert_eq!(proof.usage(), (0, 0));
    let ledger = authority
        .ledger
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    assert!(ledger.pending.is_empty() && ledger.pids.is_empty() && ledger.cgroup_views.is_empty());
}

// Catches stale cancellation or drop erasing an already registered successor's
// original admission alias. The old owner stays charged until its real drop.
#[test]
fn cgroup_trace_bracket_stale_owner_cannot_cancel_or_drop_successor() {
    let scope = Scope::Cgroup {
        id: 1,
        path: "/retained-only".into(),
        dir: Arc::new(std::fs::File::open("/dev/null").unwrap()),
    };
    let proof = ProofSession::test_scope(&scope, true);
    proof.test_set_time(100);
    let view = crate::process::ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let mut work = TraceWorkTicket::test_new(proof.clone(), 100, 5_000_100);
    let old = proof.register_cgroup(&view, &mut work).unwrap();
    proof.cancel_cgroup_view(&old);
    let next = crate::process::ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let successor = proof.register_cgroup(&next, &mut work).unwrap();
    assert_eq!(proof.usage(), (2, 0));
    proof.cancel_cgroup_view(&old);
    assert_eq!(
        proof.cgroup_registration_status(&successor, &next, &work),
        Ok(())
    );
    let foreign = ProofSession::test_scope(&scope, true);
    foreign.test_set_time(100);
    let mut foreign_work = TraceWorkTicket::test_new(foreign.clone(), 100, 5_000_100);
    let foreign_candidate = foreign.register_cgroup(&next, &mut foreign_work).unwrap();
    proof.cancel_cgroup_view(&foreign_candidate);
    foreign.cancel_cgroup_view(&successor);
    assert_eq!(
        proof.cgroup_registration_status(&successor, &next, &work),
        Ok(())
    );
    assert_eq!(
        foreign.cgroup_registration_status(&foreign_candidate, &next, &foreign_work),
        Ok(())
    );
    drop(foreign_candidate);
    assert_eq!(foreign.usage(), (0, 0));
    drop(old);
    assert_eq!(proof.usage(), (1, 0));
    assert_eq!(
        proof.cgroup_registration_status(&successor, &next, &work),
        Ok(())
    );
    drop(successor);
    assert_eq!(proof.usage(), (0, 0));
}

struct InterruptSample<'a> {
    inner: FixtureSample<'a>,
    interrupt: u8,
    links: usize,
}
impl SampleSource for InterruptSample<'_> {
    fn exited(&mut self) -> Result<bool, TraceProofUnknown> {
        self.inner.exited()
    }
    fn stat(&mut self) -> Result<ExeStat, TraceProofUnknown> {
        self.inner.stat()
    }
    fn link(&mut self, buf: &mut [u8; IMAGE_PATH_CAP + 1]) -> Result<usize, TraceProofUnknown> {
        self.links += 1;
        if self.links == 1 {
            match self.interrupt {
                1 => self.inner.proof.lifecycle(
                    self.inner.view.pid(),
                    self.inner.proof.test_time(),
                    true,
                ),
                2 => self.inner.proof.test_set_time(5_000_009),
                3 => self.inner.proof.test_discovery_tap().observe_failure(),
                _ => {}
            }
        }
        self.inner.link(buf)
    }
    fn birth(
        &mut self,
        proof: &ProofSession,
        work: &mut TraceWorkTicket,
    ) -> Result<u64, TraceWorkError> {
        self.inner.birth(proof, work)
    }
    fn namespace(&mut self) -> Result<crate::process::MountNamespaceId, TraceProofUnknown> {
        self.inner.namespace()
    }
}
fn sample_fixture() -> (ProofSession, crate::process::ProcessView, TraceWorkTicket) {
    let proof = ProofSession::test_session();
    proof.test_health(Ok(0), 7, 8).unwrap();
    proof.test_set_time(8);
    let view = crate::process::ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
    let work = TraceWorkTicket::test_new(proof.clone(), 8, 5_000_008);
    (proof, view, work)
}
#[test]
fn detailed_proof_physical_sample_uses_borrowed_original_view() {
    let (proof, view, mut work) = sample_fixture();
    let seed = proof
        .sample_from(&view, &mut work, &mut OsSample { view: &view })
        .unwrap();
    let expected = std::fs::read_link(format!("/proc/{}/exe", view.pid())).unwrap();
    assert_eq!(
        seed.identity.path.as_deref(),
        Some(expected.to_str().unwrap())
    );
    assert!(seed.identity.ino > 0);
    assert_eq!(
        proof.usage(),
        (1, seed.identity.path.as_ref().unwrap().len())
    );
    drop(seed);
    assert_eq!(proof.usage(), (0, 0));
}
#[test]
fn detailed_proof_exec_observed_inside_sample_refuses() {
    let (proof, view, mut work) = sample_fixture();
    let mut source = InterruptSample {
        inner: FixtureSample {
            view: &view,
            proof: &proof,
            link: b"/owned/fixture",
            after_first_link: None,
        },
        interrupt: 1,
        links: 0,
    };
    assert!(matches!(
        proof.sample_from(&view, &mut work, &mut source),
        Err(TraceWorkError::Unknown(TraceProofUnknown::ExecChanged))
    ));
    assert_eq!(proof.usage(), (0, 0));
}
#[test]
fn detailed_proof_partial_sample_drops_scratch_and_stops_reads() {
    for interrupt in [2, 3] {
        let (proof, view, mut work) = sample_fixture();
        let mut source = InterruptSample {
            inner: FixtureSample {
                view: &view,
                proof: &proof,
                link: b"/owned/fixture",
                after_first_link: None,
            },
            interrupt,
            links: 0,
        };
        assert!(proof.sample_from(&view, &mut work, &mut source).is_err());
        if interrupt == 2 {
            assert_eq!(source.links, 1, "no second read starts after deadline");
        }
        assert_eq!(proof.usage(), (0, 0));
        assert!(proof.ledger().unwrap().pending.is_empty());
    }
}
#[test]
fn detailed_proof_bounded_link_and_utf8_conversion_rollback() {
    for (bytes, valid) in [
        (vec![b'x'; 4096], true),
        (vec![b'x'; 4097], false),
        (vec![0xff; 1366], false),
        (vec![0xff; 1365], true),
    ] {
        let (proof, view, mut work) = sample_fixture();
        let result = proof.sample_from(
            &view,
            &mut work,
            &mut FixtureSample {
                view: &view,
                proof: &proof,
                link: &bytes,
                after_first_link: None,
            },
        );
        assert_eq!(result.is_ok(), valid);
        if let Ok(seed) = result {
            let path = seed.identity.path.as_ref().unwrap();
            assert!(path.len() <= 4096);
            assert_eq!(
                path.capacity(),
                seed.entry.bytes,
                "retained allocation fits its byte reservation"
            );
            drop(seed);
        }
        assert_eq!(proof.usage(), (0, 0));
    }
    let (proof, view, mut work) = sample_fixture();
    let held = proof.reserve(PATH_CAP - SAMPLE_WORK_BYTES + 1).unwrap();
    let mut source = InterruptSample {
        inner: FixtureSample {
            view: &view,
            proof: &proof,
            link: b"/owned/fixture",
            after_first_link: None,
        },
        interrupt: 0,
        links: 0,
    };
    assert!(matches!(
        proof.sample_from(&view, &mut work, &mut source),
        Err(TraceWorkError::Unknown(TraceProofUnknown::Budget))
    ));
    assert_eq!(source.links, 0);
    drop(held);
    assert_eq!(proof.usage(), (0, 0));
}
#[test]
fn detailed_proof_sample_before_coverage_and_loss_rebaseline() {
    let (_, view, _) = sample_fixture();
    let proof = ProofSession::new(
        EventsDomain::test_standin(7),
        DiscoveryDomain::test_standin(8),
        TraceCoverage {
            scope: CoveredScope::System,
            started_ns: 100,
        },
        true,
    );
    proof.test_health(Ok(0), 7, 8).unwrap();
    proof.test_set_time(8);
    let mut work = TraceWorkTicket::test_new(proof.clone(), 8, 5_000_008);
    assert!(proof.test_sample_view(&view, &mut work).is_err());
    assert_eq!(proof.usage(), (0, 0));
    proof.test_set_time(120);
    let mut work = TraceWorkTicket::test_new(proof.clone(), 120, 5_000_120);
    proof.test_refresh_read(&mut work, Ok(1)).unwrap();
    let seed = proof.test_sample_view(&view, &mut work).unwrap();
    assert_eq!(proof.test_problem(seed.id()), None);
    drop(seed);
    assert_eq!(proof.usage(), (0, 0));
}

#[test]
fn detailed_proof_baseline_completion_precedes_all_sample_reads() {
    for baseline_end in [9, 100] {
        let (proof, view, mut work) = sample_fixture();
        proof.test_health(Ok(0), 7, baseline_end).unwrap();
        let mut source = InterruptSample {
            inner: FixtureSample {
                view: &view,
                proof: &proof,
                link: b"/owned/fixture",
                after_first_link: None,
            },
            interrupt: 0,
            links: 0,
        };
        assert!(matches!(
            proof.sample_from(&view, &mut work, &mut source),
            Err(TraceWorkError::Unknown(TraceProofUnknown::ProofPending))
        ));
        assert_eq!(
            source.links, 0,
            "equal/future baseline completion refuses before proc reads"
        );
        assert_eq!(proof.usage(), (0, 0));
    }
}
