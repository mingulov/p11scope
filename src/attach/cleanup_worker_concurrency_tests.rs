//! SPDX-License-Identifier: GPL-3.0-or-later
//! Gated ownership/scheduling controls; harmless FDs do not prove BPF speed.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::sync::Condvar;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

#[derive(Clone, Debug, Default)]
pub(crate) struct CloseSnapshot {
    pub(crate) started: BTreeSet<usize>,
    pub(crate) completed: BTreeSet<usize>,
    pub(crate) in_flight: usize,
    pub(crate) maximum_in_flight: usize,
    pub(crate) failures: Vec<&'static str>,
}

#[derive(Default)]
struct GateState {
    snapshot: CloseSnapshot,
    allowed: BTreeSet<usize>,
    release_all: bool,
}

#[derive(Default)]
pub(crate) struct CloseGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

impl CloseGate {
    pub(crate) fn before_close(&self, id: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut state = self.state.lock().unwrap();
        if !state.snapshot.started.insert(id) {
            state.snapshot.failures.push("payload close started twice");
        }
        state.snapshot.in_flight += 1;
        state.snapshot.maximum_in_flight = state
            .snapshot
            .maximum_in_flight
            .max(state.snapshot.in_flight);
        self.changed.notify_all();
        while !state.release_all && !state.allowed.contains(&id) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                state.snapshot.failures.push("close gate deadline expired");
                break;
            }
            state = self.changed.wait_timeout(state, remaining).unwrap().0;
        }
    }

    pub(crate) fn after_close(&self, id: usize) {
        let mut state = self.state.lock().unwrap();
        state.snapshot.in_flight = state.snapshot.in_flight.saturating_sub(1);
        if !state.snapshot.completed.insert(id) {
            state
                .snapshot
                .failures
                .push("payload close completed twice");
        }
        self.changed.notify_all();
    }

    pub(crate) fn missing_pin(&self) {
        self.state
            .lock()
            .unwrap()
            .snapshot
            .failures
            .push("original physical file lease vanished during inner drop");
        self.changed.notify_all();
    }

    pub(crate) fn snapshot(&self) -> CloseSnapshot {
        self.state.lock().unwrap().snapshot.clone()
    }

    pub(crate) fn release(&self, ids: impl IntoIterator<Item = usize>) {
        self.state.lock().unwrap().allowed.extend(ids);
        self.changed.notify_all();
    }

    pub(crate) fn release_all(&self) {
        self.state.lock().unwrap().release_all = true;
        self.changed.notify_all();
    }

    pub(crate) fn wait_for(
        &self,
        within: Duration,
        predicate: impl Fn(&CloseSnapshot) -> bool,
    ) -> bool {
        let deadline = Instant::now() + within;
        let mut state = self.state.lock().unwrap();
        while !predicate(&state.snapshot) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            state = self.changed.wait_timeout(state, remaining).unwrap().0;
        }
        true
    }
}

pub(crate) struct ReleaseGuard(pub(crate) Arc<CloseGate>);

impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        self.0.release_all();
    }
}

#[test]
fn bounded_cleanup_detailed_closes_four_same_rank_payloads_before_advancing_ranks() {
    let gate = Arc::new(CloseGate::default());
    let mut identities = BTreeMap::new();
    let links = (0..8)
        .map(|id| {
            let fd = File::open("/dev/null").unwrap();
            identities.insert(fd.as_raw_fd(), id);
            let producer = match id {
                0..=4 => ProducerProgram::UProbe("p11_entry"),
                5 => ProducerProgram::BtfTracePoint("task_newtask"),
                6 => ProducerProgram::UProbe("p11_return"),
                _ => ProducerProgram::RawTracePoint("sched_process_exit"),
            };
            (OwnedLink::Multi(vec![fd.into()]), producer)
        })
        .collect();
    let closer_gate = Arc::clone(&gate);
    let mut worker = CleanupWorker::pre_start_with(
        Box::new(move |owned, _| {
            let Some(OwnedLink::Multi(fds)) = owned.as_ref() else {
                return Err("unexpected test payload".into());
            };
            let id = identities[&fds[0].as_raw_fd()];
            closer_gate.before_close(id);
            drop(owned.take());
            closer_gate.after_close(id);
            Ok(())
        }),
        Arc::new(|| Duration::ZERO),
    );
    let ticket = worker
        .submit_live(links, Arc::default(), DetachOrder)
        .unwrap();
    let release_guard = ReleaseGuard(Arc::clone(&gate));
    let concurrent = gate.wait_for(Duration::from_secs(2), |state| {
        state
            .started
            .intersection(&BTreeSet::from([0, 1, 2, 3, 4]))
            .count()
            >= 4
    });
    // A fifth blocked ordinary payload makes the width bound observable.
    let excessive = gate.wait_for(Duration::from_millis(100), |state| state.in_flight > 4);
    let first = gate.snapshot();
    let pending_at_first = ticket.status() == BatchStatus::Pending;
    let mut phase_boundaries = Vec::new();
    let mut final_progress = None;
    if concurrent {
        // Release the first four; the remaining same-rank payload must still
        // block every later producer until its actual close returns.
        let first_entries: Vec<_> = first.started.iter().copied().filter(|id| *id < 5).collect();
        let last_entry = (0..5).find(|id| !first.started.contains(id));
        gate.release(first_entries);
        if let Some(last_entry) = last_entry {
            let entered = gate.wait_for(Duration::from_secs(2), |state| {
                state.started.contains(&last_entry)
            });
            phase_boundaries.push(entered && gate.snapshot().started.iter().all(|id| *id < 5));
            phase_boundaries.push(ticket.status() == BatchStatus::Pending);
            gate.release([last_entry]);
        }
        for id in 5..8 {
            let entered =
                gate.wait_for(Duration::from_secs(2), |state| state.started.contains(&id));
            let snapshot = gate.snapshot();
            phase_boundaries.push(
                entered
                    && (0..id).all(|prior| snapshot.completed.contains(&prior))
                    && snapshot.started.iter().all(|started| *started <= id)
                    && ticket.status() == BatchStatus::Pending,
            );
            if id == 7 {
                final_progress = Some(worker.progress());
            }
            gate.release([id]);
        }
    }
    // Serial RED and every failed observation release all gates and reap the
    // real worker before asserting; no assertion can strand a test closer.
    gate.release_all();
    let receipt = worker.join();
    drop(release_guard);
    let settled = gate.snapshot();
    assert!(
        concurrent,
        "serial same-rank closes cannot overlap independent waits: {first:?}; {receipt:?}"
    );
    assert!(!excessive && settled.maximum_in_flight == 4, "{settled:?}");
    assert!(pending_at_first && first.started.iter().all(|id| *id < 5));
    assert!(
        phase_boundaries.iter().all(|passed| *passed),
        "{phase_boundaries:?}"
    );
    let final_progress = final_progress.unwrap();
    assert_eq!((final_progress.attempted, final_progress.remaining), (8, 0));
    assert!(receipt.completed, "{receipt:?}");
    assert_eq!(
        (receipt.total, receipt.released, receipt.uncertain),
        (8, 8, 0)
    );
    assert_eq!(ticket.status(), BatchStatus::Released);
    assert!(settled.failures.is_empty(), "{settled:?}");
}

struct GuardedPoolPayload {
    fd: Option<OwnedFd>,
    fail: bool,
    _leases: FileLeases,
}

fn pool_payload(fail: bool, leases: &FileLeases) -> CloseSlot<GuardedPoolPayload> {
    Arc::new(Mutex::new(GuardedPoolPayload {
        fd: Some(File::open("/dev/null").unwrap().into()),
        fail,
        _leases: Arc::clone(leases),
    }))
}

#[test]
fn bounded_cleanup_partial_helper_startup_joins_started_empty_helpers() {
    let reaped = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&reaped);
    let mut starts = 0;
    let result = ClosePool::<GuardedPoolPayload>::start_with(Arc::new(|_| Ok(())), move |task| {
        starts += 1;
        if starts == 2 {
            return Err(std::io::Error::other("injected second helper refusal"));
        }
        let observed = Arc::clone(&observed);
        std::thread::Builder::new().spawn(move || {
            task();
            observed.fetch_add(1, Ordering::SeqCst);
        })
    });
    assert!(
        result.is_err(),
        "partial helper startup cannot report ready"
    );
    assert_eq!(
        reaped.load(Ordering::SeqCst),
        1,
        "started helper actually joined"
    );
}

#[test]
fn bounded_cleanup_helper_panic_keeps_residual_fd_and_original_file_guard() {
    let file = Arc::new(tempfile::tempfile().unwrap());
    let weak = Arc::downgrade(&file);
    let leases = Arc::new(vec![file]);
    let slots = [pool_payload(true, &leases), pool_payload(false, &leases)];
    let raw = slots[0].lock().unwrap().fd.as_ref().unwrap().as_raw_fd();
    drop(leases);
    let mut pool = ClosePool::start(Arc::new(|item: &mut GuardedPoolPayload| {
        if item.fail {
            panic!("injected helper close panic before ownership release");
        }
        drop(item.fd.take());
        Ok(())
    }))
    .unwrap();
    let results = pool.close_chunk(&slots);
    drop(pool);
    assert_eq!(
        results
            .iter()
            .filter(|result| result.result.is_ok())
            .count(),
        1
    );
    assert!(results.iter().any(|result| {
        result
            .result
            .as_ref()
            .is_err_and(|error| error.contains("injected helper close panic"))
    }));
    assert!(slots[0].lock().unwrap().fd.is_some());
    // SAFETY: this control inspects its still-owned harmless descriptor only.
    assert!(unsafe { libc::fcntl(raw, libc::F_GETFD) } >= 0);
    assert!(
        weak.upgrade().is_some(),
        "failed residual retains original file"
    );
    drop(results);
    drop(slots);
    assert!(weak.upgrade().is_none());
}

#[test]
fn bounded_cleanup_failed_dispatch_keeps_all_unstarted_payloads_and_files() {
    let file = Arc::new(tempfile::tempfile().unwrap());
    let weak = Arc::downgrade(&file);
    let leases = Arc::new(vec![file]);
    let slots = [pool_payload(false, &leases), pool_payload(false, &leases)];
    drop(leases);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let mut pool = ClosePool::start(Arc::new(move |item: &mut GuardedPoolPayload| {
        observed.fetch_add(1, Ordering::SeqCst);
        drop(item.fd.take());
        Ok(())
    }))
    .unwrap();
    let (closed, receiver) = mpsc::sync_channel(1);
    drop(receiver);
    drop(std::mem::replace(&mut pool.senders[0], closed));
    let results = pool.close_chunk(&slots);
    drop(pool);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|result| result.result.is_err()));
    assert!(slots.iter().all(|slot| slot.lock().unwrap().fd.is_some()));
    assert!(weak.upgrade().is_some());
    drop(results);
    drop(slots);
    assert!(weak.upgrade().is_none());
}
