//! SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::attach::ProducerProgram;
use crate::attach::pid_continuity::tests::fixture;
use std::fs::File;
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct NativeSession {
    retirement: NativeRetirement,
    links: Vec<RegisteredLink>,
    retained: BTreeMap<u32, RetainedStaticTarget>,
    pairs: PairBook,
    gaps: Retirements,
    worker: CleanupWorker,
}

impl NativeSession {
    fn new(
        target: RetainedStaticTarget,
        closer: Box<
            dyn FnMut(OwnedLink, ProducerProgram) -> std::result::Result<(), String> + Send,
        >,
    ) -> Self {
        let mut pairs = PairBook::default();
        let links = ["p11_return", "p11_entry"]
            .into_iter()
            .map(|program| RegisteredLink::MultiUProbe {
                program,
                slots: vec![target.slot.index],
                fds: vec![File::open("/dev/null").unwrap().into()],
                registration: pairs.register(),
            })
            .collect();
        Self {
            retirement: NativeRetirement::default(),
            links,
            retained: BTreeMap::from([(target.slot.index, target)]),
            pairs,
            gaps: Retirements::default(),
            worker: CleanupWorker::pre_start_with(closer, Arc::new(|| Duration::ZERO)),
        }
    }

    fn begin(
        &mut self,
        scope: UProbeScope,
        stopped: bool,
        failed_cleanup: bool,
        ended: bool,
    ) -> Result<Option<RetirementTicket>> {
        let slots: Vec<_> = self
            .retained
            .values()
            .map(|target| target.slot.clone())
            .collect();
        self.retirement.begin_with(
            scope,
            stopped,
            failed_cleanup,
            ended,
            &slots,
            &mut self.links,
            &mut self.retained,
            &mut self.pairs,
            &mut self.gaps,
            &self.worker,
            |link| match link {
                RegisteredLink::MultiUProbe { fds, .. } => Ok(vec![OwnedLink::Multi(fds)]),
                _ => anyhow::bail!("unexpected scripted link"),
            },
            || Some(40),
        )
    }
}

fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "native retirement did not reach expected settlement"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn bounded_cleanup_detailed_batch_keeps_original_pin_after_session_owner_drops() {
    use crate::attach::cleanup_worker::concurrency_tests::{CloseGate, ReleaseGuard};

    let (directory, pins, target) = fixture();
    let lease = target.held.as_ref().unwrap().retirement_lease();
    let weak = Arc::downgrade(&lease);
    drop(lease);
    let gate = Arc::new(CloseGate::default());
    let closer_gate = Arc::clone(&gate);
    let closer_pin = weak.clone();
    let mut session = NativeSession::new(
        target,
        Box::new(move |owned, producer| {
            let id = usize::from(producer == ProducerProgram::UProbe("p11_return"));
            if closer_pin.upgrade().is_none() {
                closer_gate.missing_pin();
            }
            closer_gate.before_close(id);
            drop(owned);
            if closer_pin.upgrade().is_none() {
                closer_gate.missing_pin();
            }
            closer_gate.after_close(id);
            Ok(())
        }),
    );
    let ticket = session
        .begin(UProbeScope::AllProcesses, false, false, false)
        .unwrap()
        .expect("real held target is selected for owned retirement");
    let release_guard = ReleaseGuard(Arc::clone(&gate));
    let entry_blocked = gate.wait_for(Duration::from_secs(2), |state| state.started.contains(&0));
    let pinned_before_owner_drop = weak.upgrade().is_some();
    let NativeSession {
        retirement,
        links,
        retained,
        pairs,
        gaps,
        mut worker,
    } = session;
    // Keep the actual running worker and original ticket, while removing
    // every session-side file owner. The worker has one in-flight entry and
    // one queued return from the same real physical target.
    drop(retirement);
    drop(links);
    drop(retained);
    drop(pairs);
    drop(gaps);
    drop(pins);
    drop(directory);
    let pinned_while_worker_owns_batch = weak.upgrade().is_some();
    let still_pending = ticket
        .identity
        .batch
        .as_ref()
        .is_some_and(|batch| batch.status() == BatchStatus::Pending);
    gate.release_all();
    let receipt = worker.join();
    drop(release_guard);
    let settled = gate.snapshot();
    drop(ticket);
    assert!(entry_blocked && pinned_before_owner_drop && still_pending);
    assert!(
        pinned_while_worker_owns_batch,
        "queued/in-flight native ownership outlived its original physical file lease: {settled:?}"
    );
    assert!(receipt.completed, "{receipt:?}");
    assert_eq!((receipt.released, receipt.total), (2, 2));
    assert!(settled.failures.is_empty(), "{settled:?}");
    assert!(
        weak.upgrade().is_none(),
        "completed batch has no remaining file owner"
    );
}

#[test]
fn native_retirement_session_handoff_returns_with_final_kernel_close_pending() {
    let (_dir, _pins, target) = fixture();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let mut session = NativeSession::new(
        target,
        Box::new(move |owned, producer| {
            if producer == ProducerProgram::UProbe("p11_return") {
                entered_tx.send(()).unwrap();
                release_rx
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(|error| error.to_string())?;
            }
            drop(owned);
            Ok(())
        }),
    );
    let ticket = session
        .begin(UProbeScope::AllProcesses, false, false, false)
        .unwrap()
        .expect("actual global retirement is deferred");
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(session.links.is_empty());
    assert!(session.retained.is_empty());
    assert!(
        session.retirement.blocking(),
        "the held-point quarantine blocks all attachment until final close settles"
    );
    assert_eq!(session.worker.progress().remaining, 0);
    assert_eq!(
        session.retirement.poll(&ticket, &session.worker),
        RetirementPoll::Pending
    );
    assert_eq!(ticket.retired_slots(), &BTreeSet::from([0]));
    assert!(
        session
            .begin(UProbeScope::AllProcesses, false, false, false)
            .is_err(),
        "pending ownership cannot enqueue another batch or report untouched fallback"
    );
    release_tx.send(()).unwrap();
    wait_for(|| session.retirement.poll(&ticket, &session.worker) == RetirementPoll::Settled);
    assert!(!session.retirement.blocking());
    assert!(session.worker.join().completed);
}

#[test]
fn native_retirement_none_is_untouched_for_pid_stop_cleanup_endproof_and_partial_multi() {
    for (scope, stopped, failed_cleanup, ended) in [
        (
            UProbeScope::OneProcess(std::num::NonZeroU32::new(123).unwrap()),
            false,
            false,
            false,
        ),
        (UProbeScope::AllProcesses, true, false, false),
        (UProbeScope::AllProcesses, false, true, false),
        (UProbeScope::AllProcesses, false, false, true),
    ] {
        let (_dir, _pins, target) = fixture();
        let mut session = NativeSession::new(
            target,
            Box::new(|_, _| panic!("ineligible live retirement must never reach the closer")),
        );
        assert!(
            session
                .begin(scope, stopped, failed_cleanup, ended)
                .unwrap()
                .is_none()
        );
        assert_eq!(session.links.len(), 2);
        assert_eq!(session.retained.len(), 1);
        assert!(!session.retirement.blocking());
        assert!(session.worker.join().completed);
    }
    let (_dir, _pins, target) = fixture();
    let mut session = NativeSession::new(
        target,
        Box::new(|_, _| panic!("partial Multi rebuild stays synchronous")),
    );
    for link in &mut session.links {
        if let RegisteredLink::MultiUProbe { slots, .. } = link {
            slots.push(1);
        }
    }
    assert!(
        session
            .begin(UProbeScope::AllProcesses, false, false, false)
            .unwrap()
            .is_none()
    );
    assert_eq!(session.links.len(), 2);
    assert_eq!(session.retained.len(), 1);
    assert!(session.worker.join().completed);
}

#[test]
fn native_retirement_foreign_or_old_ticket_cannot_clear_current_quarantine() {
    let (_dir, _pins, target) = fixture();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let mut session = NativeSession::new(
        target,
        Box::new(move |owned, _| {
            entered_tx.send(()).unwrap();
            release_rx
                .recv_timeout(Duration::from_secs(2))
                .map_err(|error| error.to_string())?;
            drop(owned);
            Ok(())
        }),
    );
    let ticket = session
        .begin(UProbeScope::AllProcesses, false, false, false)
        .unwrap()
        .unwrap();
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let mut foreign = NativeRetirement::default();
    assert_eq!(
        foreign.poll(&ticket, &session.worker),
        RetirementPoll::Refused
    );
    let mut other_worker = CleanupWorker::pre_start_with(
        Box::new(|owned, _| {
            drop(owned);
            Ok(())
        }),
        Arc::new(|| Duration::ZERO),
    );
    assert_eq!(
        session.retirement.poll(&ticket, &other_worker),
        RetirementPoll::Refused,
        "the exact Session ticket also requires its actual worker allocation"
    );
    assert!(other_worker.join().completed);
    assert_eq!(
        session.retirement.poll(&ticket, &session.worker),
        RetirementPoll::Pending
    );
    release_tx.send(()).unwrap();
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    release_tx.send(()).unwrap();
    wait_for(|| session.retirement.poll(&ticket, &session.worker) == RetirementPoll::Settled);
    assert_eq!(
        session.retirement.poll(&ticket, &session.worker),
        RetirementPoll::Refused,
        "settlement consumes the exact current ticket; it cannot be replayed"
    );
    assert!(session.worker.join().completed);
}

#[test]
fn native_retirement_failed_close_keeps_quarantine_after_all_attempts() {
    let (_dir, _pins, target) = fixture();
    let mut session = NativeSession::new(
        target,
        Box::new(|owned, producer| {
            drop(owned);
            if producer == ProducerProgram::UProbe("p11_return") {
                Err("real scripted native closer failure".into())
            } else {
                Ok(())
            }
        }),
    );
    let ticket = session
        .begin(UProbeScope::AllProcesses, false, false, false)
        .unwrap()
        .unwrap();
    wait_for(|| session.worker.progress().uncertain == 1);
    assert_eq!(session.worker.progress().remaining, 0);
    assert_eq!(
        session.retirement.poll(&ticket, &session.worker),
        RetirementPoll::Refused
    );
    assert!(session.retirement.blocking());
    assert!(
        session
            .begin(UProbeScope::AllProcesses, false, false, false)
            .is_err()
    );
    let receipt = session.worker.join();
    assert!(!receipt.completed);
    assert_eq!(
        (receipt.released, receipt.total, receipt.uncertain),
        (1, 2, 1)
    );
}

#[test]
fn native_retirement_unavailable_worker_preserves_untouched_synchronous_fallback() {
    let (_dir, _pins, target) = fixture();
    let mut session = NativeSession::new(target, Box::new(|_, _| panic!("unavailable worker")));
    session.worker = CleanupWorker::pre_start_with_spawn(
        Box::new(|_, _| panic!("failed startup must never close")),
        Arc::new(|| Duration::ZERO),
        |_| Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
    );
    assert!(
        session
            .begin(UProbeScope::AllProcesses, false, false, false)
            .unwrap()
            .is_none()
    );
    assert_eq!((session.links.len(), session.retained.len()), (2, 1));
    assert!(!session.retirement.blocking());
    assert_eq!(
        session.gaps.summary(),
        super::super::pid_continuity::PhysicalGapSummary::default(),
        "startup refusal never claims a physical retirement"
    );
    assert!(
        session
            .begin(UProbeScope::AllProcesses, false, false, false)
            .unwrap()
            .is_none()
    );
    assert!(!session.worker.join().completed);
}

#[test]
fn native_retirement_nonstatic_slot_link_is_untouched_synchronous_fallback() {
    let (_dir, _pins, target) = fixture();
    let mut session = NativeSession::new(target, Box::new(|_, _| panic!("nonstatic ownership")));
    session.links.push(RegisteredLink::MultiUProbe {
        program: "rtld_activity",
        slots: vec![0],
        fds: vec![File::open("/dev/null").unwrap().into()],
        registration: session.pairs.register(),
    });
    assert!(
        session
            .begin(UProbeScope::AllProcesses, false, false, false)
            .unwrap()
            .is_none()
    );
    assert_eq!((session.links.len(), session.retained.len()), (3, 1));
    assert!(!session.retirement.blocking());
    assert!(session.worker.join().completed);
}

#[test]
fn native_retirement_replacement_descriptor_retires_the_actual_old_pair() {
    let (_dir, pins, mut target) = fixture();
    let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
    target.slot.descriptor_index = descriptor;
    target.slot.semantics = crate::kinds::DESCRIPTORS[descriptor as usize];
    target.slot.semantic_authorized = true;
    let pinned = pins.pinned().next().unwrap();
    let module = crate::plan::ModuleSummary {
        id: target.slot.module_ids[0],
        object: pinned.id,
        key: pinned.key,
        path: pinned.path.into(),
        tables: vec![],
        interfaces: 0,
        source: "scan",
        corroborated: false,
        skipped: vec![],
    };
    let mut plan = crate::plan::AttachPlan::from_slots(vec![target.slot.clone()]);
    plan.modules = vec![module.clone()];
    let mut replacement = target.slot.clone();
    replacement.descriptor_index = 0;
    replacement.semantics = p11scope_ebpf_common::SlotSemantics::COUNT_ONLY;
    replacement.semantic_authorized = false;
    replacement.semantic_ambiguous = true;
    let mut rebuilt = crate::plan::AttachPlan::from_slots(vec![replacement]);
    rebuilt.modules = vec![module];
    // The real planner supplies updated replacement metadata, exactly as the
    // Engine's retire+replace selection does. Old native ownership is unchanged.
    let delta = plan.extend_exact(rebuilt).unwrap();
    assert!(delta.new.is_empty() && delta.retire.is_empty());
    assert_eq!(delta.replace.len(), 1);
    assert_eq!(delta.replace[0].descriptor_index, 0);
    assert_ne!(delta.replace[0], target.slot);
    let mut session = NativeSession::new(
        target,
        Box::new(|owned, _| {
            drop(owned);
            Ok(())
        }),
    );
    let ticket = session
        .retirement
        .begin_with(
            UProbeScope::AllProcesses,
            false,
            false,
            false,
            &delta.replace,
            &mut session.links,
            &mut session.retained,
            &mut session.pairs,
            &mut session.gaps,
            &session.worker,
            |link| match link {
                RegisteredLink::MultiUProbe { fds, .. } => Ok(vec![OwnedLink::Multi(fds)]),
                _ => anyhow::bail!("unexpected scripted link"),
            },
            || Some(40),
        )
        .unwrap()
        .expect("replacement-only retirement transfers the old held native pair");
    assert!(session.links.is_empty());
    assert_eq!(ticket.retired_slots(), &BTreeSet::from([0]));
    wait_for(|| session.retirement.poll(&ticket, &session.worker) == RetirementPoll::Settled);
    assert!(session.worker.join().completed);
}

#[test]
fn native_retirement_transfer_failure_cannot_report_untouched_or_recovered() {
    let (_dir, _pins, target) = fixture();
    let mut session = NativeSession::new(
        target,
        Box::new(|owned, _| {
            drop(owned);
            Ok(())
        }),
    );
    let slots: Vec<_> = session
        .retained
        .values()
        .map(|target| target.slot.clone())
        .collect();
    let ticket = session
        .retirement
        .begin_with(
            UProbeScope::AllProcesses,
            false,
            false,
            false,
            &slots,
            &mut session.links,
            &mut session.retained,
            &mut session.pairs,
            &mut session.gaps,
            &session.worker,
            |_link| anyhow::bail!("actual transfer refusal"),
            || Some(40),
        )
        .unwrap()
        .expect("mutated ownership carries a refused ticket");
    assert!(session.links.is_empty());
    assert!(session.retirement.blocking());
    assert_eq!(
        session.retirement.poll(&ticket, &session.worker),
        RetirementPoll::Refused
    );
    assert!(!session.worker.join().completed);
}
