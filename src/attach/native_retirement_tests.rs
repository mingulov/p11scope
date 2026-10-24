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
        Self::new_concurrent(
            target,
            super::super::cleanup_worker::legacy_test_closer(closer),
        )
    }

    fn new_concurrent(
        target: RetainedStaticTarget,
        closer: super::super::cleanup_worker::BoxCloser,
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
    let mut session = NativeSession::new_concurrent(
        target,
        Box::new(move |owned, producer| {
            let id = usize::from(producer == ProducerProgram::UProbe("p11_return"));
            if closer_pin.upgrade().is_none() {
                closer_gate.missing_pin();
            }
            closer_gate.before_close(id);
            drop(owned.take());
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
        super::super::cleanup_worker::legacy_test_closer(Box::new(|owned, _| {
            drop(owned);
            Ok(())
        })),
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
        super::super::cleanup_worker::legacy_test_closer(Box::new(|_, _| {
            panic!("failed startup must never close")
        })),
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

// These are source-first pins for the collected path. Existing live-retirement
// controls above stay unchanged; harmless FDs do not qualify a BPF Session.
use super::fixture::CollectedRetirementFixture;
use crate::semantics_edge::resources::{
    ResourceLease, SEMANTIC_TRANSITION_SCRATCH, SemanticResourcePool, SemanticResourceReserver,
};

const COLLECTED_INPUT_BYTES: usize = 64 * 1024;
const COLLECTED_POOL_BYTES: usize = SEMANTIC_TRANSITION_SCRATCH + 2 * 1024 * 1024;
const COLLECTED_CREDITS: usize = 8192;

fn collected_case(
    count: usize,
    closer: super::fixture::Closer,
) -> (
    tempfile::TempDir,
    crate::discovery::identity::PinnedObjects,
    CollectedRetirementFixture,
    Vec<Slot>,
) {
    let (dir, pins, target) = fixture();
    let slots: Vec<_> = (0..count)
        .map(|index| {
            let mut slot = target.slot.clone();
            slot.index = u32::try_from(index).unwrap();
            // Distinct original physical offsets within the small held file.
            slot.file_offset = u64::try_from(index).unwrap();
            slot.names.reserve_exact(7);
            slot.names[0].reserve_exact(96 + index * 16);
            slot.names.push("签名-é".repeat(index + 1));
            slot
        })
        .collect();
    let native = CollectedRetirementFixture::new(&slots, &pins, closer);
    (dir, pins, native, slots)
}

fn collected_input(slots: Vec<Slot>, storage: ResourceLease) -> RetainedRetirementInput {
    match RetainedRetirementInput::from_reserved_removed(slots, storage) {
        Ok(input) => input,
        Err(_) => panic!("a fresh process-local input identity must be available"),
    }
}

fn collected_prepare_to_ticket(
    native: &mut CollectedRetirementFixture,
    q: &super::super::CollectedFinishQ,
    input: &mut Option<RetainedRetirementInput>,
    reserve: &SemanticResourceReserver,
) -> anyhow::Result<CollectedRetirementTicket> {
    for _ in 0..COLLECTED_CREDITS {
        let progress = native.prepare(q, input, reserve, 1)?;
        assert_eq!(progress.used, 1);
        match progress.state {
            CollectedRetirementState::Preparing => {}
            CollectedRetirementState::Prepared(ticket) => return Ok(ticket),
            CollectedRetirementState::RefusedUntouched(original) => {
                assert!(input.is_none());
                *input = Some(original);
                anyhow::bail!("valid original input returned after untouched preparation refusal");
            }
            _ => anyhow::bail!("unexpected collected preparation phase"),
        }
    }
    anyhow::bail!("small real-owner preparation exhausted its finite credits")
}

fn collected_submit(
    native: &mut CollectedRetirementFixture,
    q: &super::super::CollectedFinishQ,
    ticket: &CollectedRetirementTicket,
) {
    for _ in 0..COLLECTED_CREDITS {
        let progress = native.begin(q, ticket, 1).unwrap();
        assert_eq!(progress.used, 1);
        match progress.state {
            CollectedRetirementState::Transferring => {}
            CollectedRetirementState::Pending => return,
            _ => panic!("healthy original ownership did not reach its own worker"),
        }
    }
    panic!("small original transfer exhausted its finite credits");
}

fn collected_close(
    native: &mut CollectedRetirementFixture,
    q: &super::super::CollectedFinishQ,
    ticket: &CollectedRetirementTicket,
) -> RetainedRetirementInput {
    let deadline = Instant::now() + Duration::from_secs(2);
    for _ in 0..COLLECTED_CREDITS {
        assert!(Instant::now() < deadline, "original close did not settle");
        let progress = native.poll(q, ticket, 1).unwrap();
        assert_eq!(progress.used, 1);
        match progress.state {
            CollectedRetirementState::Pending => std::thread::yield_now(),
            CollectedRetirementState::Closed(input) => return input,
            _ => panic!("healthy original batch produced no exact closure result"),
        }
    }
    panic!("small original closure exhausted its finite credits");
}

#[test]
fn collected_retirement_work_zero_and_one_preserve_original_owner() {
    let _prepare: fn(
        &mut super::super::Session,
        &super::super::CollectedFinishQ,
        &mut Option<RetainedRetirementInput>,
        &SemanticResourceReserver,
        usize,
    ) -> anyhow::Result<RetirementProgress> =
        super::super::Session::prepare_collected_static_retirement;
    let _begin: fn(
        &mut super::super::Session,
        &super::super::CollectedFinishQ,
        &CollectedRetirementTicket,
        usize,
    ) -> anyhow::Result<RetirementProgress> =
        super::super::Session::begin_collected_static_retirement;
    let _poll: fn(
        &mut super::super::Session,
        &super::super::CollectedFinishQ,
        &CollectedRetirementTicket,
        usize,
    ) -> anyhow::Result<RetirementProgress> =
        super::super::Session::poll_collected_static_retirement;

    let (_dir, _pins, mut native, slots) = collected_case(
        4,
        Box::new(|_, _| panic!("preparation must not submit a native close")),
    );
    let q = native.observe_q();
    let pool = SemanticResourcePool::reference_limit(COLLECTED_POOL_BYTES);
    let reserve = pool.reserver();
    let ptr = slots.as_ptr();
    let mut input = Some(collected_input(
        slots,
        reserve.reserve(COLLECTED_INPUT_BYTES).unwrap(),
    ));
    let links = native.original_links();
    let retained = native.retained_slots();
    let budget = pool.snapshot();
    let ((progress, allocations, bytes), before_reads) = (
        crate::test_alloc::count_allocs_during(|| native.prepare(&q, &mut input, &reserve, 0)),
        native.reads_and_transfers(),
    );
    let progress = progress.unwrap();
    assert_eq!(progress.used, 0);
    assert!(matches!(progress.state, CollectedRetirementState::Yielded));
    assert_eq!((allocations, bytes), (0, 0));
    assert_eq!(before_reads, ((0, 0), 0));
    assert_eq!(input.as_ref().unwrap().removed.as_ptr(), ptr);
    assert_eq!(pool.snapshot(), budget);
    assert_eq!(native.original_links(), links);
    assert_eq!(native.retained_slots(), retained);
    assert_eq!(native.native_counts(), (0, 0, 0, 0));

    let progress = native.prepare(&q, &mut input, &reserve, 1).unwrap();
    assert_eq!(progress.used, 1);
    assert!(matches!(
        progress.state,
        CollectedRetirementState::Preparing
    ));
    assert!(
        input.is_some(),
        "one credit cannot size every deep original"
    );
    assert_eq!(native.original_links(), links);
    assert_eq!(native.retained_slots(), retained);
    assert_eq!(native.native_counts(), (0, 0, 0, 0));
    assert_eq!(native.remaining_records(), (1, 1));
}

#[test]
fn collected_retirement_input_foreign_or_undercharged_stays_with_caller() {
    for (foreign, deep_spare_capacity) in [(false, false), (false, true), (true, false)] {
        let (_dir, _pins, mut native, mut slots) = collected_case(
            2,
            Box::new(|_, _| panic!("invalid payment must refuse before native transfer")),
        );
        if deep_spare_capacity {
            slots[0].names[0].reserve_exact(4096);
        }
        let original = slots.clone();
        let ptr = slots.as_ptr();
        let capacity = slots.capacity();
        let q = native.observe_q();
        let actual = SemanticResourcePool::reference_limit(COLLECTED_POOL_BYTES);
        let other = SemanticResourcePool::reference_limit(COLLECTED_POOL_BYTES);
        let reserve = actual.reserver();
        let input_bytes = if foreign { COLLECTED_INPUT_BYTES } else { 2048 };
        assert!(
            slots.capacity() * std::mem::size_of::<Slot>()
                + std::mem::size_of::<RetainedRetirementInput>()
                < input_bytes,
            "this lease covers the actual shallow holders"
        );
        if deep_spare_capacity {
            assert!(slots[0].names[0].capacity() > input_bytes);
        }
        let storage = if foreign {
            other.reserve(input_bytes).unwrap()
        } else {
            actual.reserve(input_bytes).unwrap()
        };
        assert_eq!(reserve.covers(&storage, input_bytes), !foreign);
        let mut input = Some(collected_input(slots, storage));
        let identity = input.as_ref().unwrap().identity;
        let actual_before = actual.snapshot().charged_bytes;
        let other_before = other.snapshot().charged_bytes;
        let links = native.original_links();
        let retained = native.retained_slots();
        if !foreign && !deep_spare_capacity {
            // This healthy twin uses the same small envelope and values. Only
            // spare deep capacity differs in the undercharged twin below;
            // testing a one-byte lease would miss len-only sizing bugs.
            let _ticket =
                collected_prepare_to_ticket(&mut native, &q, &mut input, &reserve).unwrap();
            assert!(input.is_none());
            assert_eq!(native.original_links(), links);
            assert_eq!(native.retained_slots(), retained);
            assert_eq!(native.native_counts(), (0, 0, 0, 0));
            continue;
        }
        let mut refused = false;
        for _ in 0..COLLECTED_CREDITS {
            match native.prepare(&q, &mut input, &reserve, 1) {
                Err(_) => {
                    refused = true;
                    break;
                }
                Ok(progress) => {
                    assert_eq!(progress.used, 1);
                    assert!(matches!(
                        progress.state,
                        CollectedRetirementState::Preparing
                    ));
                    assert!(input.is_some(), "invalid input cannot be taken first");
                }
            }
        }
        assert!(refused, "actual same-pool/deep coverage must be checked");
        let input = input
            .as_ref()
            .expect("pre-take Err preserves the caller Option");
        assert_eq!(input.identity, identity);
        assert_eq!(input.removed.as_ptr(), ptr);
        assert_eq!(input.removed.capacity(), capacity);
        assert_eq!(input.removed, original);
        assert_eq!(actual.snapshot().charged_bytes, actual_before);
        assert_eq!(other.snapshot().charged_bytes, other_before);
        assert_eq!(native.original_links(), links);
        assert_eq!(native.retained_slots(), retained);
        assert_eq!(native.native_counts(), (0, 0, 0, 0));
        assert_eq!(native.reads_and_transfers().1, 0);
    }
}

#[test]
fn collected_retirement_same_pool_exact_fit_and_one_short() {
    let (_dir, pins, mut baseline, slots) = collected_case(
        2,
        Box::new(|_, _| panic!("sizing and seal do not close original links")),
    );
    let pool = SemanticResourcePool::reference_limit(COLLECTED_POOL_BYTES);
    let reserve = pool.reserver();
    let mut input = Some(collected_input(
        slots.clone(),
        reserve.reserve(COLLECTED_INPUT_BYTES).unwrap(),
    ));
    let q = baseline.observe_q();
    let (ticket, requested) = crate::test_alloc::requested_peak_during(|| {
        collected_prepare_to_ticket(&mut baseline, &q, &mut input, &reserve).unwrap()
    });
    assert!(!requested.incomplete && requested.failed_requests == 0);
    let exact = pool.snapshot().peak_charged_bytes;
    let initial = SEMANTIC_TRANSITION_SCRATCH + COLLECTED_INPUT_BYTES;
    assert!(
        exact > initial,
        "native cursor/ticket storage must be prepaid"
    );
    assert!(
        exact - initial >= requested.realloc_overlap_bytes,
        "actual new allocations must fit their additional live charge: {requested:?}"
    );
    assert!(input.is_none());
    assert_eq!(baseline.native_counts(), (0, 0, 0, 0));
    drop(ticket);
    drop(baseline);

    // Repeat the real admission boundary on the SAME provider/file and same
    // input capacities, rather than mirroring a production sizing formula.
    for (limit, healthy) in [(exact, true), (exact - 1, false)] {
        let mut native = CollectedRetirementFixture::new(
            &slots,
            &pins,
            Box::new(|_, _| panic!("an envelope test must not close native ownership")),
        );
        let q = native.observe_q();
        let pool = SemanticResourcePool::reference_limit(limit);
        let reserve = pool.reserver();
        let removed = slots.clone();
        let ptr = removed.as_ptr();
        let mut input = Some(collected_input(
            removed,
            reserve.reserve(COLLECTED_INPUT_BYTES).unwrap(),
        ));
        let links = native.original_links();
        let retained = native.retained_slots();
        let result = collected_prepare_to_ticket(&mut native, &q, &mut input, &reserve);
        assert_eq!(result.is_ok(), healthy);
        if healthy {
            assert!(input.is_none());
            assert_eq!(pool.snapshot().peak_charged_bytes, exact);
        } else {
            let input = input
                .as_ref()
                .expect("short admission returns its untouched input");
            assert_eq!(input.removed.as_ptr(), ptr);
            assert_eq!(input.removed, slots);
            assert_eq!(pool.snapshot().charged_bytes, initial);
        }
        assert_eq!(native.original_links(), links);
        assert_eq!(native.retained_slots(), retained);
        assert_eq!(native.native_counts(), (0, 0, 0, 0));
        assert_eq!(native.reads_and_transfers().1, 0);
    }
}

#[test]
fn collected_retirement_foreign_q_ticket_and_worker_are_untouched() {
    use super::super::cleanup_worker::concurrency_tests::{CloseGate, ReleaseGuard};

    let gate = Arc::new(CloseGate::default());
    let closer_gate = Arc::clone(&gate);
    let (_dir, pins, mut native, slots) = collected_case(
        1,
        Box::new(move |owned, producer| {
            if producer == ProducerProgram::UProbe("p11_return") {
                closer_gate.before_close(0);
                drop(owned);
                closer_gate.after_close(0);
            } else {
                drop(owned);
            }
            Ok(())
        }),
    );
    let release_guard = ReleaseGuard(Arc::clone(&gate));
    let mut foreign = CollectedRetirementFixture::new(
        &slots,
        &pins,
        Box::new(|_, _| panic!("foreign ownership must not be submitted")),
    );
    let q = native.observe_q();
    let other_q = foreign.observe_q();
    let pool = SemanticResourcePool::reference_limit(COLLECTED_POOL_BYTES);
    let reserve = pool.reserver();
    let removed = slots.clone();
    let ptr = removed.as_ptr();
    let mut input = Some(collected_input(
        removed,
        reserve.reserve(COLLECTED_INPUT_BYTES).unwrap(),
    ));
    let links = native.original_links();
    let before = pool.snapshot();
    assert!(native.prepare(&other_q, &mut input, &reserve, 1).is_err());
    assert_eq!(input.as_ref().unwrap().removed.as_ptr(), ptr);
    assert_eq!(pool.snapshot(), before);
    assert_eq!(native.original_links(), links);
    assert_eq!(native.native_counts(), (0, 0, 0, 0));

    let mut stale = CollectedRetirementFixture::new(
        &slots,
        &pins,
        Box::new(|_, _| panic!("post-Q producer movement cannot authorize detach")),
    );
    let stale_q = stale.observe_q();
    stale.append_after_q();
    let mut stale_input = Some(collected_input(
        slots.clone(),
        reserve.reserve(COLLECTED_INPUT_BYTES).unwrap(),
    ));
    let stale_identity = stale_input.as_ref().unwrap().identity;
    let stale_links = stale.original_links();
    assert!(
        stale
            .prepare(&stale_q, &mut stale_input, &reserve, 1)
            .is_err()
    );
    assert_eq!(stale_input.as_ref().unwrap().identity, stale_identity);
    assert_eq!(stale.original_links(), stale_links);
    assert_eq!(stale.native_counts(), (0, 0, 0, 0));
    assert_eq!(stale.remaining_records(), (2, 1));

    let ticket = collected_prepare_to_ticket(&mut native, &q, &mut input, &reserve).unwrap();
    let other_pool = SemanticResourcePool::reference_limit(COLLECTED_POOL_BYTES);
    let other_reserve = other_pool.reserver();
    let mut other_input = Some(collected_input(
        slots,
        other_reserve.reserve(COLLECTED_INPUT_BYTES).unwrap(),
    ));
    let other_ticket =
        collected_prepare_to_ticket(&mut foreign, &other_q, &mut other_input, &other_reserve)
            .unwrap();
    assert!(native.begin(&q, &other_ticket, 1).is_err());
    assert!(foreign.begin(&other_q, &ticket, 1).is_err());
    assert_eq!(native.original_links(), links);
    assert_eq!(native.native_counts(), (0, 0, 0, 0));
    assert_eq!(foreign.native_counts(), (0, 0, 0, 0));

    collected_submit(&mut native, &q, &ticket);
    assert!(gate.wait_for(Duration::from_secs(2), |state| state.started.contains(&0)));
    assert_eq!(native.native_counts(), (2, 2, 1, 0));
    assert!(
        native
            .poll_with_worker(&q, &ticket, foreign.worker())
            .is_err()
    );
    let before = native.reads_and_transfers();
    let no_work = native.poll(&q, &ticket, 0).unwrap();
    assert_eq!(no_work.used, 0);
    assert!(matches!(no_work.state, CollectedRetirementState::Yielded));
    assert_eq!(native.reads_and_transfers(), before);
    let pending = native.poll(&q, &ticket, 1).unwrap();
    assert_eq!(pending.used, 1);
    assert!(matches!(pending.state, CollectedRetirementState::Pending));
    gate.release_all();
    let original = collected_close(&mut native, &q, &ticket);
    let (removed, storage) = original.into_removed();
    assert_eq!(removed.as_ptr(), ptr);
    assert!(reserve.covers(&storage, COLLECTED_INPUT_BYTES));
    assert!(
        native.worker().running(),
        "batch release must not require pool join"
    );
    assert!(native.poll(&q, &ticket, 1).is_err(), "closure is once-only");
    assert!(native.join().completed);
    drop(release_guard);
}

#[test]
fn collected_retirement_changed_input_cannot_inherit_preflight_credit() {
    for (same_allocation, grow_deep) in [(false, true), (true, false), (true, true)] {
        let (_dir, _pins, mut native, slots) = collected_case(
            4,
            Box::new(|_, _| panic!("changed preflight input cannot reach native mutation")),
        );
        let q = native.observe_q();
        let pool = SemanticResourcePool::reference_limit(COLLECTED_POOL_BYTES);
        let reserve = pool.reserver();
        let mut input = Some(collected_input(
            slots,
            reserve.reserve(COLLECTED_INPUT_BYTES).unwrap(),
        ));
        let old_identity = input.as_ref().unwrap().identity;
        for _ in 0..3 {
            let progress = native.prepare(&q, &mut input, &reserve, 1).unwrap();
            assert_eq!(progress.used, 1);
            assert!(matches!(
                progress.state,
                CollectedRetirementState::Preparing
            ));
            assert!(input.is_some(), "the deep input is still caller-owned");
        }
        let (original, storage) = input.take().unwrap().into_removed();
        let old_ptr = original.as_ptr();
        let mut replacement = if same_allocation {
            original
        } else {
            let copy = original.clone();
            // Keep the previous owner alive so pointer reuse cannot make this
            // distinct-input branch accidentally equal the old allocation.
            assert_ne!(copy.as_ptr(), old_ptr);
            copy
        };
        if grow_deep {
            replacement[0].names[0].reserve_exact(COLLECTED_INPUT_BYTES * 2);
        }
        if same_allocation {
            assert_eq!(replacement.as_ptr(), old_ptr);
        }
        let ptr = replacement.as_ptr();
        let capacity = replacement.capacity();
        input = Some(collected_input(replacement, storage));
        assert_ne!(input.as_ref().unwrap().identity, old_identity);
        let identity = input.as_ref().unwrap().identity;
        let links = native.original_links();
        // Pin refusal of an input replacement during this active preflight.
        // Even an unchanged, fully covered SAME Vec re-wrap has a new owner;
        // eventual budget rejection would not detect inherited sizing credit.
        assert!(native.prepare(&q, &mut input, &reserve, 1).is_err());
        let input = input.as_ref().unwrap();
        assert_eq!(input.identity, identity);
        assert_eq!(input.removed.as_ptr(), ptr);
        assert_eq!(input.removed.capacity(), capacity);
        if grow_deep {
            assert!(input.removed[0].names[0].capacity() > COLLECTED_INPUT_BYTES);
        }
        assert_eq!(native.original_links(), links);
        assert_eq!(native.native_counts(), (0, 0, 0, 0));
        assert_eq!(native.reads_and_transfers().1, 0);
        assert_eq!(
            pool.snapshot().charged_bytes,
            SEMANTIC_TRANSITION_SCRATCH + COLLECTED_INPUT_BYTES
        );
    }
}

#[test]
fn collected_retirement_input_identity_exhaustion_returns_original_owners() {
    use std::sync::atomic::{AtomicU64, Ordering};

    let (_dir, _pins, _native, slots) = collected_case(
        1,
        Box::new(|_, _| panic!("input packaging does not retire a native link")),
    );
    let ptr = slots.as_ptr();
    let original = slots.clone();
    let pool = SemanticResourcePool::reference_limit(COLLECTED_POOL_BYTES);
    let reserve = pool.reserver();
    let storage = reserve.reserve(COLLECTED_INPUT_BYTES).unwrap();
    let issuer = AtomicU64::new(u64::MAX - 1);
    let (last, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
        RetainedRetirementInput::from_reserved_removed_with_issuer(slots, storage, &issuer)
    });
    assert_eq!((allocations, bytes), (0, 0));
    let last = match last {
        Ok(input) => input,
        Err(_) => panic!("the final nonzero identity is still available"),
    };
    assert_eq!(last.identity.get(), u64::MAX);
    let (mut removed, mut storage) = last.into_removed();
    for _ in 0..2 {
        let (result, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
            RetainedRetirementInput::from_reserved_removed_with_issuer(removed, storage, &issuer)
        });
        assert_eq!((allocations, bytes), (0, 0));
        let refusal = match result {
            Err(refusal) => refusal,
            Ok(_) => panic!("exhausted identities must never wrap or be reused"),
        };
        (removed, storage) = refusal.into_removed();
        assert_eq!(removed.as_ptr(), ptr);
        assert_eq!(removed, original);
        assert!(reserve.covers(&storage, COLLECTED_INPUT_BYTES));
        assert_eq!(issuer.load(Ordering::Relaxed), u64::MAX);
        assert_eq!(
            pool.snapshot().charged_bytes,
            SEMANTIC_TRANSITION_SCRATCH + COLLECTED_INPUT_BYTES
        );
    }
    drop(storage);
    assert_eq!(pool.snapshot().charged_bytes, SEMANTIC_TRANSITION_SCRATCH);
}

#[test]
fn collected_retirement_external_ticket_clone_is_bounded_and_inert() {
    let (dir, pins, mut native, slots) = collected_case(
        4,
        Box::new(|owned, _| {
            drop(owned);
            Ok(())
        }),
    );
    let file = native.original_file();
    let q = native.observe_q();
    let pool = SemanticResourcePool::reference_limit(COLLECTED_POOL_BYTES);
    let reserve = pool.reserver();
    let ptr = slots.as_ptr();
    let original = slots.clone();
    let mut input = Some(collected_input(
        slots,
        reserve.reserve(COLLECTED_INPUT_BYTES).unwrap(),
    ));
    let (external, requested) = crate::test_alloc::requested_peak_during(|| {
        let ticket = collected_prepare_to_ticket(&mut native, &q, &mut input, &reserve).unwrap();
        let before_clone = crate::test_alloc::armed_requested_snapshot();
        let external = ticket.clone();
        assert_eq!(crate::test_alloc::armed_requested_snapshot(), before_clone);
        collected_submit(&mut native, &q, &ticket);
        let returned = collected_close(&mut native, &q, &ticket);
        assert_eq!(native.native_counts(), (8, 8, 8, 0));
        assert!(native.worker().running());
        let (removed, storage) = returned.into_removed();
        assert_eq!(removed.as_ptr(), ptr);
        assert_eq!(removed, original);
        assert!(reserve.covers(&storage, COLLECTED_INPUT_BYTES));
        let receipt = native.join();
        assert!(receipt.completed);
        assert_eq!(
            (receipt.total, receipt.released, receipt.uncertain),
            (8, 8, 0)
        );
        drop(removed);
        drop(storage);
        drop(ticket);
        drop(native);
        drop(pins);
        drop(dir);
        assert!(
            file.upgrade().is_none(),
            "external identity cannot retain an old provider"
        );
        assert_eq!(pool.snapshot().charged_bytes, SEMANTIC_TRANSITION_SCRATCH);
        external
    });
    assert!(!requested.incomplete && requested.failed_requests == 0);
    assert!(
        requested.live_bytes <= 64 && requested.live_blocks <= 2,
        "an external ticket may retain only constant-size identities, not a selection: {requested:?}"
    );
    let charged = pool.snapshot();
    let (_, allocations, bytes) = crate::test_alloc::count_allocs_during(|| drop(external));
    assert_eq!((allocations, bytes), (0, 0));
    assert_eq!(pool.snapshot(), charged);
    assert!(file.upgrade().is_none());
}

#[test]
fn collected_retirement_cancel_before_and_after_first_mutation() {
    for post_take in [false, true] {
        let (_dir, _pins, mut native, slots) = collected_case(
            2,
            Box::new(|_, _| panic!("untouched cancellation cannot close")),
        );
        let q = native.observe_q();
        let pool = SemanticResourcePool::reference_limit(COLLECTED_POOL_BYTES);
        let reserve = pool.reserver();
        let ptr = slots.as_ptr();
        let mut input = Some(collected_input(
            slots,
            reserve.reserve(COLLECTED_INPUT_BYTES).unwrap(),
        ));
        let original = native.original_links();
        let mut ticket = None;
        for _ in 0..COLLECTED_CREDITS {
            let progress = native.prepare(&q, &mut input, &reserve, 1).unwrap();
            assert_eq!(progress.used, 1);
            if !post_take {
                break;
            }
            if input.is_none() {
                assert!(matches!(
                    progress.state,
                    CollectedRetirementState::Preparing
                ));
                ticket = Some(
                    progress
                        .ticket
                        .expect("post-take preparation has a cancel identity"),
                );
                break;
            }
        }
        assert_eq!(input.is_none(), post_take);
        assert_eq!(ticket.is_some(), post_take);
        let before = (native.reads_and_transfers(), pool.snapshot());
        let (zero, allocations, _) = crate::test_alloc::count_allocs_during(|| {
            native.cancel(input.as_ref(), ticket.as_ref(), 0).unwrap()
        });
        assert_eq!((zero.used, allocations), (0, 0));
        assert!(zero.ticket.is_none());
        assert_eq!((native.reads_and_transfers(), pool.snapshot()), before);
        let mut returned = None;
        for _ in 0..COLLECTED_CREDITS {
            let progress = native.cancel(input.as_ref(), ticket.as_ref(), 1).unwrap();
            assert_eq!(progress.used, 1);
            match progress.state {
                CollectedRetirementState::Yielded if !post_take => break,
                CollectedRetirementState::Preparing => {}
                CollectedRetirementState::RefusedUntouched(input) => {
                    returned = Some(input);
                    break;
                }
                _ => panic!("untouched cancellation lost its original owner"),
            }
        }
        if post_take {
            input = Some(returned.expect("same input returned after bounded cleanup"));
        }
        assert_eq!(input.as_ref().unwrap().removed.as_ptr(), ptr);
        assert_eq!(native.original_links(), original);
        assert_eq!(native.native_counts(), (0, 0, 0, 0));
        assert_eq!(
            pool.snapshot().charged_bytes,
            SEMANTIC_TRANSITION_SCRATCH + COLLECTED_INPUT_BYTES
        );
        assert!(!native.blocking());
    }

    let (_dir, _pins, mut native, slots) = collected_case(
        2,
        Box::new(|_, _| panic!("first invalidation precedes FD extraction")),
    );
    let q = native.observe_q();
    let pool = SemanticResourcePool::reference_limit(COLLECTED_POOL_BYTES);
    let reserve = pool.reserver();
    let mut input = Some(collected_input(
        slots,
        reserve.reserve(COLLECTED_INPUT_BYTES).unwrap(),
    ));
    let ticket = collected_prepare_to_ticket(&mut native, &q, &mut input, &reserve).unwrap();
    let links = native.original_links();
    for _ in 0..COLLECTED_CREDITS {
        let progress = native.begin(&q, &ticket, 1).unwrap();
        assert_eq!(progress.used, 1);
        if native.recorded_generation(0).is_none() {
            break;
        }
        assert_eq!(native.native_counts(), (0, 0, 0, 0));
    }
    assert!(native.recorded_generation(0).is_none());
    assert_eq!(native.original_links().len(), links.len());
    assert_eq!(native.native_counts(), (0, 0, 0, 0));
    let charge = pool.snapshot().charged_bytes;
    let refused = native.cancel(None, Some(&ticket), 1).unwrap();
    assert!(matches!(
        refused.state,
        CollectedRetirementState::RefusedRetained
    ));
    assert!(native.blocking());
    assert_eq!(pool.snapshot().charged_bytes, charge);
    assert_eq!(native.native_counts(), (0, 0, 0, 0));
}

#[test]
fn collected_retirement_foreign_cancel_preserves_active_preparation() {
    let (_dir, _pins, mut native, slots) =
        collected_case(2, Box::new(|_, _| panic!("no transfer")));
    let q = native.observe_q();
    let pool = SemanticResourcePool::reference_limit(COLLECTED_POOL_BYTES);
    let reserve = pool.reserver();
    let mut input = Some(collected_input(
        slots.clone(),
        reserve.reserve(COLLECTED_INPUT_BYTES).unwrap(),
    ));
    let other = collected_input(slots, reserve.reserve(COLLECTED_INPUT_BYTES).unwrap());
    native.prepare(&q, &mut input, &reserve, 1).unwrap();
    let before = pool.snapshot();
    assert!(native.cancel(Some(&other), None, 1).is_err());
    assert_eq!(pool.snapshot(), before);
    assert!(native.blocking());
    let ticket = collected_prepare_to_ticket(&mut native, &q, &mut input, &reserve).unwrap();
    assert!(native.cancel(Some(&other), Some(&ticket), 1).is_err());
    assert!(native.cancel(Some(&other), None, 1).is_err());
    assert!(native.blocking());
    collected_submit(&mut native, &q, &ticket);
    drop(collected_close(&mut native, &q, &ticket));
    assert!(native.join().completed);
}

#[test]
fn collected_retirement_batch_close_precedes_terminal_join() {
    let (_dir, _pins, mut native, slots) = collected_case(
        2,
        Box::new(|owned, _| {
            drop(owned);
            Ok(())
        }),
    );
    let q = native.observe_q();
    let pool = SemanticResourcePool::reference_limit(COLLECTED_POOL_BYTES);
    let reserve = pool.reserver();
    let mut input = Some(collected_input(
        slots,
        reserve.reserve(COLLECTED_INPUT_BYTES).unwrap(),
    ));
    let ticket = collected_prepare_to_ticket(&mut native, &q, &mut input, &reserve).unwrap();
    collected_submit(&mut native, &q, &ticket);
    drop(collected_close(&mut native, &q, &ticket));
    assert!(native.worker().running());
    assert_eq!(native.native_counts(), (4, 4, 4, 0));
    assert!(!native.blocking());
    let receipt = native.join();
    assert!(receipt.completed);
    assert_eq!(
        (receipt.total, receipt.released, receipt.uncertain),
        (4, 4, 0)
    );
    assert_eq!(pool.snapshot().charged_bytes, SEMANTIC_TRANSITION_SCRATCH);
}

#[test]
fn collected_retirement_failed_handoff_keeps_files_and_charge() {
    let (_dir, pins, mut native, slots) =
        collected_case(2, Box::new(|_, _| panic!("closed worker must refuse")));
    let file = native.original_file();
    let q = native.observe_q();
    let pool = SemanticResourcePool::reference_limit(COLLECTED_POOL_BYTES);
    let reserve = pool.reserver();
    let mut input = Some(collected_input(
        slots,
        reserve.reserve(COLLECTED_INPUT_BYTES).unwrap(),
    ));
    let ticket = collected_prepare_to_ticket(&mut native, &q, &mut input, &reserve).unwrap();
    for _ in 0..COLLECTED_CREDITS {
        let progress = native.begin(&q, &ticket, 1).unwrap();
        assert_eq!(progress.used, 1);
        if native.recorded_generation(0).is_none() {
            break;
        }
    }
    assert!(native.recorded_generation(0).is_none());
    assert_eq!(native.native_counts(), (0, 0, 0, 0));
    let charged = pool.snapshot().charged_bytes;
    native.worker().begin_terminal();
    let mut refused = false;
    for _ in 0..COLLECTED_CREDITS {
        let progress = native.begin(&q, &ticket, 1).unwrap();
        if matches!(progress.state, CollectedRetirementState::RefusedRetained) {
            refused = true;
            break;
        }
    }
    assert!(refused);
    assert!(native.blocking());
    assert!(file.upgrade().is_some());
    assert_eq!(pool.snapshot().charged_bytes, charged);
    drop(pins);
    drop(native);
    assert!(
        file.upgrade().is_some(),
        "abandoned debt retains provider custody"
    );
    assert_eq!(pool.snapshot().charged_bytes, charged);
}

#[test]
fn collected_retirement_rank_and_partial_multi_are_exact() {
    use super::super::cleanup_worker::concurrency_tests::{CloseGate, ReleaseGuard};
    let gate = Arc::new(CloseGate::default());
    let closer = Arc::clone(&gate);
    let returned = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let returns = Arc::clone(&returned);
    let (_dir, _pins, mut native, slots) = collected_case(
        2,
        Box::new(move |owned, producer| {
            if producer == ProducerProgram::UProbe("p11_entry") {
                closer.before_close(0);
                drop(owned);
                closer.after_close(0);
            } else {
                returns.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                drop(owned);
            }
            Ok(())
        }),
    );
    native.combine_original_groups();
    let release = ReleaseGuard(Arc::clone(&gate));
    let q = native.observe_q();
    let pool = SemanticResourcePool::reference_limit(COLLECTED_POOL_BYTES);
    let reserve = pool.reserver();
    let mut partial = Some(collected_input(
        vec![slots[0].clone()],
        reserve.reserve(COLLECTED_INPUT_BYTES).unwrap(),
    ));
    let ptr = partial.as_ref().unwrap().removed.as_ptr();
    let links = native.original_links();
    let result = collected_prepare_to_ticket(&mut native, &q, &mut partial, &reserve);
    assert!(result.is_err());
    assert_eq!(partial.as_ref().unwrap().removed.as_ptr(), ptr);
    assert_eq!(native.original_links(), links);
    assert_eq!(native.native_counts(), (0, 0, 0, 0));
    assert!(
        !native.blocking(),
        "untouched partial refusal must release its own fence"
    );
    drop(partial);
    let mut full = Some(collected_input(
        slots,
        reserve.reserve(COLLECTED_INPUT_BYTES).unwrap(),
    ));
    let ticket = collected_prepare_to_ticket(&mut native, &q, &mut full, &reserve).unwrap();
    collected_submit(&mut native, &q, &ticket);
    assert!(gate.wait_for(Duration::from_secs(2), |state| state.started.contains(&0)));
    assert_eq!(returned.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert!(matches!(
        native.poll(&q, &ticket, 1).unwrap().state,
        CollectedRetirementState::Pending
    ));
    gate.release_all();
    drop(collected_close(&mut native, &q, &ticket));
    assert_eq!(returned.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(native.native_counts(), (2, 2, 2, 0));
    assert!(native.join().completed);
    drop(release);
}

#[test]
fn collected_retirement_metadata_release_respects_one_credit() {
    let (_dir, _pins, mut native, slots) = collected_case(
        4,
        Box::new(|owned, _| {
            drop(owned);
            Ok(())
        }),
    );
    let file = native.original_file();
    let q = native.observe_q();
    let pool = SemanticResourcePool::reference_limit(COLLECTED_POOL_BYTES);
    let reserve = pool.reserver();
    let mut input = Some(collected_input(
        slots,
        reserve.reserve(COLLECTED_INPUT_BYTES).unwrap(),
    ));
    let ticket = collected_prepare_to_ticket(&mut native, &q, &mut input, &reserve).unwrap();
    collected_submit(&mut native, &q, &ticket);
    wait_for(|| native.native_counts() == (8, 8, 8, 0));
    let count = native.retained_slots().len();
    let before = pool.snapshot().charged_bytes;
    let progress = native.poll(&q, &ticket, 1).unwrap();
    assert_eq!(progress.used, 1);
    assert!(matches!(progress.state, CollectedRetirementState::Pending));
    assert!(native.retained_slots().len() >= count.saturating_sub(1));
    assert_eq!(
        pool.snapshot().charged_bytes,
        before,
        "backing remains paid throughout disposal"
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut closed = false;
    for _ in 0..COLLECTED_CREDITS {
        assert!(Instant::now() < deadline);
        let before = file.strong_count();
        let progress = native.poll(&q, &ticket, 1).unwrap();
        assert_eq!(progress.used, 1);
        assert!(
            before.saturating_sub(file.strong_count()) <= 1,
            "one credit cannot drop multiple real target/stamp/provider owners"
        );
        match progress.state {
            CollectedRetirementState::Pending => {}
            CollectedRetirementState::Closed(input) => {
                drop(input);
                closed = true;
                break;
            }
            _ => panic!("healthy metadata disposition lost original ownership"),
        }
    }
    assert!(closed);
    assert!(native.join().completed);
    assert_eq!(pool.snapshot().charged_bytes, SEMANTIC_TRANSITION_SCRATCH);
}

#[test]
fn collected_retirement_authenticates_bound_from_original_registry() {
    let (_dir, pins, _old, mut slots) = collected_case(2, Box::new(|_, _| panic!("unused owner")));
    // A small real owner demonstrates the validated physical index domain;
    // no8192 native population or experimental scalar grants authority here.
    slots[1].index = p11scope_ebpf_common::MAX_SLOTS + 1;
    let mut native = CollectedRetirementFixture::new(
        &slots,
        &pins,
        Box::new(|owned, _| {
            drop(owned);
            Ok(())
        }),
    );
    let q = native.observe_q();
    let pool = SemanticResourcePool::reference_limit(COLLECTED_POOL_BYTES);
    let reserve = pool.reserver();
    let mut input = Some(collected_input(
        slots,
        reserve.reserve(COLLECTED_INPUT_BYTES).unwrap(),
    ));
    let ticket = collected_prepare_to_ticket(&mut native, &q, &mut input, &reserve).unwrap();
    collected_submit(&mut native, &q, &ticket);
    drop(collected_close(&mut native, &q, &ticket));
    assert_eq!(native.native_counts(), (4, 4, 4, 0));
    assert!(native.join().completed);
    assert_eq!(pool.snapshot().charged_bytes, SEMANTIC_TRANSITION_SCRATCH);
}

#[test]
fn collected_retirement_worker_failure_retains_actual_paid_provider() {
    use super::super::cleanup_worker::{CollectedCleanupRetention, collected_allocation_charge};
    for failure in 0..3 {
        let closed_channel = failure == 2;
        let (dir, pins, target) = fixture();
        let file = target.retirement_lease().unwrap();
        let weak = Arc::downgrade(&file);
        let pool = SemanticResourcePool::reference_limit(COLLECTED_POOL_BYTES);
        let reserve = pool.reserver();
        let bytes = collected_allocation_charge(1, 1).unwrap();
        let guard = CollectedCleanupRetention::new(reserve.reserve(bytes).unwrap(), 1);
        guard.retain_file(file);
        let mut worker = CleanupWorker::pre_start_with(
            Box::new(move |_owned, _| {
                if failure == 1 {
                    panic!("actual caught native-close panic");
                }
                Err("actual retained native-close failure".into())
            }),
            Arc::new(|| Duration::ZERO),
        );
        if closed_channel {
            assert!(worker.join().completed);
        }
        let leaf = OwnedLink::Multi(vec![File::open("/dev/null").unwrap().into()]);
        let result = worker.submit_collected(
            vec![(leaf, ProducerProgram::UProbe("p11_entry"))],
            Arc::new(Vec::new()),
            Arc::clone(&guard),
        );
        let ticket = if closed_channel {
            let failure = result.expect_err("closed original worker refuses the same owned leaf");
            worker.retain_unsubmitted(failure);
            None
        } else {
            Some(result.expect("original running worker owns the leaf"))
        };
        drop(guard);
        drop(target);
        drop(pins);
        drop(dir);
        if let Some(ticket) = ticket {
            wait_for(|| ticket.status() == BatchStatus::Failed);
            let receipt = worker.join();
            assert!(!receipt.completed);
            assert_eq!(
                (receipt.total, receipt.released, receipt.uncertain),
                (1, 0, 1)
            );
            drop(ticket);
        }
        assert!(weak.upgrade().is_some());
        assert_eq!(
            pool.snapshot().charged_bytes,
            SEMANTIC_TRANSITION_SCRATCH + bytes
        );
        drop(worker);
        assert!(
            weak.upgrade().is_some(),
            "explicit abandon retains its original guard"
        );
        assert_eq!(
            pool.snapshot().charged_bytes,
            SEMANTIC_TRANSITION_SCRATCH + bytes
        );
    }
}
