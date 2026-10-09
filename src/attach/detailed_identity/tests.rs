//! SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

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
