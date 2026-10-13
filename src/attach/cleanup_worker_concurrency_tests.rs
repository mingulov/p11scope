//! SPDX-License-Identifier: GPL-3.0-or-later
//! Gated ownership/scheduling controls; harmless FDs do not prove BPF speed.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::sync::Condvar;
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
            let OwnedLink::Multi(fds) = &owned else {
                return Err("unexpected test payload".into());
            };
            let id = identities[&fds[0].as_raw_fd()];
            closer_gate.before_close(id);
            drop(owned);
            closer_gate.after_close(id);
            Ok(())
        }),
        Arc::new(|| Duration::ZERO),
    );
    let ticket = worker.submit_live(links, DetachOrder).unwrap();
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
