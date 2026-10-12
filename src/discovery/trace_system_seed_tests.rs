//! SPDX-License-Identifier: GPL-3.0-or-later
//! Fresh SYSTEM trace readiness through the production scheduler and proof ingress.
//!
//! The process pins and executable sample are real. Only native CALL production,
//! cookie-map reads, loss-map reads and the clock are scripted. No receipt is
//! constructed by the fixture and no native counter or map is populated.

use super::*;
use crate::attach::detailed_identity::{CgroupCandidate, TraceSeed};
use crate::events::{DiscoveryDrain, EventDrain, ScriptedRecords};
use crate::semantics::ProcessKey;
use crate::trace_identity::TraceIdentityStore;
use p11scope_ebpf_common::{Event, ImageIdentity};
use std::cell::RefCell;
use std::ops::ControlFlow;
use std::process::{Child, Command};

const FRAME_NS: u64 = 200_000_000;
const ATTEMPT_WAIT_NS: u64 = 500_000_000;
const FIRST_MARKER_NS: u64 = 5_798_412;
const MAX_ATTEMPTS: usize = 20;
const READINESS_NS: u64 = 15_000_000_000;
const START_NS: u64 = 100_000_000;

struct Children(Vec<Child>);
impl Drop for Children {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct Io {
    proof: ProofSession,
    target: u32,
    cookie: Cell<Option<u64>>,
    boundaries: RefCell<Vec<String>>,
}
impl Io {
    fn boundary(&self, kind: &str, result: impl std::fmt::Debug) {
        self.boundaries.borrow_mut().push(format!(
            "{kind} at {}ns: {result:?}",
            self.proof.test_time() - START_NS,
        ));
    }

    fn pending(&self, engine: &Engine, kind: &str) {
        let Some((id, start, completed, witness)) = self.proof.test_pending_times(self.target)
        else {
            self.boundary(kind, "no pending target sample");
            return;
        };
        let status = engine.trace_seeds.get(&id).and_then(|candidate| {
            let TraceCandidateBody::PidSystem(seed) = &candidate.body else {
                return None;
            };
            Some((
                self.proof
                    .seed_status(seed, &engine.views[candidate.position]),
                self.proof.ready_to_transfer(seed),
            ))
        });
        self.boundary(
            kind,
            (
                start - START_NS,
                completed.saturating_sub(START_NS),
                witness,
                status,
            ),
        );
    }
}
impl TraceIo for Io {
    fn proof(&self) -> Option<&ProofSession> {
        Some(&self.proof)
    }

    fn cookie(
        &self,
        pin: &crate::process::PidPin,
        work: &mut TraceWorkTicket,
    ) -> Result<u64, TraceWorkError> {
        let result = self.proof.test_cookie_read(
            pin,
            work,
            (pin.pid() == self.target)
                .then(|| self.cookie.get())
                .flatten(),
        );
        if pin.pid() == self.target {
            self.boundary("original-pin cookie read", &result);
        }
        result
    }

    fn refresh_health(&self, work: &mut TraceWorkTicket) -> Result<(), TraceWorkError> {
        self.proof.test_refresh_read(work, Ok(0))
    }

    fn sample(
        &self,
        view: &ProcessView,
        work: &mut TraceWorkTicket,
    ) -> Result<TraceSeed, TraceWorkError> {
        let result = self.proof.test_sample_os_view(view, work);
        if view.pid() == self.target {
            let allowance = work.state.as_ref().map(|state| {
                let state = state.lock().unwrap();
                (
                    state.reads,
                    state.visits,
                    state.deadline.saturating_sub(self.proof.test_time()),
                    state.closed,
                )
            });
            self.boundary(
                "original-view OS sample",
                (result.as_ref().map(|_| ()), allowance),
            );
        }
        result
    }

    fn sample_cgroup(
        &self,
        _: &mut CgroupCandidate,
        _: &ProcessView,
        _: &mut TraceWorkTicket,
    ) -> Result<(), TraceWorkError> {
        panic!("PID/SYSTEM reproduction cannot acquire cgroup proof")
    }

    fn confirm_cgroup(
        &self,
        _: &mut CgroupCandidate,
        _: &ProcessView,
        _: &mut TraceWorkTicket,
    ) -> Result<(), TraceWorkError> {
        panic!("PID/SYSTEM reproduction cannot acquire cgroup proof")
    }
}

struct Capture {
    engine: Engine,
    io: Io,
    store: TraceIdentityStore,
    key: ProcessKey,
    expected_path: String,
    _children: Children,
}
impl Capture {
    fn fresh(unrelated: usize, system: bool) -> Self {
        let mut children = Children(Vec::new());
        let mut views = Vec::new();
        for index in 0..=unrelated {
            let child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
            let pid = child.id();
            children.0.push(child);
            views.push(ProcessView::open(ProcessViewId(index as u32), pid).unwrap());
        }
        let target = views.last().unwrap().pid();
        assert!(views[..unrelated].iter().all(|view| view.pid() < target));
        let expected_path = std::fs::read_link(format!("/proc/{target}/exe"))
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let mut engine = Engine::empty();
        engine.scope = if system {
            Scope::System
        } else {
            Scope::Pid(target)
        };
        engine.frame_work_budget_ns = LIVE_FRAME_WORK_BUDGET_NS;
        engine.views = views;
        let proof = ProofSession::test_scope(&engine.scope, true);
        proof.test_set_time(START_NS);
        let key = ProcessKey {
            domain: proof.test_events_domain().id(),
            pid: target,
            generation: 11,
            exec_id: 0,
        };
        Self {
            engine,
            store: TraceIdentityStore::new(proof.clone()),
            io: Io {
                proof,
                target,
                cookie: Cell::new(None),
                boundaries: RefCell::new(Vec::new()),
            },
            key,
            expected_path,
            _children: children,
        }
    }

    fn frame(&mut self, at: u64) {
        self.io.proof.test_set_time(START_NS + at);
        let store = &mut self.store;
        self.engine
            .with_trace_frame(&mut self.io, |engine, io, work| {
                let accept = |receipt: VerifiedTraceSeed| {
                    io.boundary(
                        "verified transfer",
                        (receipt.key(), receipt.eligible_after_ns()),
                    );
                    let result = store.admit(receipt);
                    io.boundary("store admission", &result);
                    result.unwrap();
                };
                engine.service_trace_images(io, work, accept);
                io.pending(engine, "before discovery drain");
                // This is the same retained lifecycle transport used by the
                // production proof tap. An empty read must follow confirmation.
                let mut drain = DiscoveryDrain::over_domain(
                    ScriptedRecords::records([], 0),
                    io.proof.test_discovery_domain(),
                );
                drain
                    .attach_trace_tap(io.proof.test_discovery_tap())
                    .unwrap();
                assert!(drain.dequeue().is_none());
                engine.service_trace_images(io, work, |receipt| {
                    io.boundary(
                        "verified transfer",
                        (receipt.key(), receipt.eligible_after_ns()),
                    );
                    let result = store.admit(receipt);
                    io.boundary("store admission", &result);
                    result.unwrap();
                });
                io.pending(engine, "after discovery drain");
                Ok(())
            })
            .unwrap();
    }

    fn marker(&mut self, at: u64) -> bool {
        self.io.proof.test_set_time(START_NS + at);
        let event = Event {
            pid_tgid: (u64::from(self.key.pid) << 32) | u64::from(self.key.pid),
            ts_ns: START_NS + at,
            image: ImageIdentity {
                task_cookie: self.key.generation,
                exec_id: self.key.exec_id,
            },
            ..Event::default()
        };
        let mut drain = EventDrain::over_domain(
            ScriptedRecords::events([event], 1),
            self.io.proof.test_events_domain(),
        );
        drain
            .attach_trace_tap(self.io.proof.test_events_tap())
            .unwrap();
        let mut count = 0;
        drain.poll(Some(2), |_| {
            count += 1;
            ControlFlow::Continue(())
        });
        assert_eq!(count, 1);
        self.io.cookie.set(Some(self.key.generation));
        self.io.pending(&self.engine, "CALL witness ingress");
        let observed = self.store.lookup(self.key, event.ts_ns).path();
        assert!(observed.is_none_or(|path| path == self.expected_path));
        self.io.boundary("emitted row named", observed.is_some());
        observed.is_some()
    }

    fn readiness(&mut self) -> Option<usize> {
        let mut next_frame = 0;
        for attempt in 1..=MAX_ATTEMPTS {
            let marker = FIRST_MARKER_NS + (attempt - 1) as u64 * ATTEMPT_WAIT_NS;
            assert!(marker < READINESS_NS);
            while next_frame <= marker {
                self.frame(next_frame);
                next_frame += FRAME_NS;
            }
            if self.marker(marker) {
                return Some(attempt);
            }
        }
        None
    }
}

#[test]
fn fresh_pid_trace_names_original_view_within_readiness_bounds() {
    let mut capture = Capture::fresh(0, false);
    assert!(
        capture.readiness().is_some(),
        "{}",
        capture.io.boundaries.borrow().join("\n")
    );
}

#[test]
fn fresh_system_trace_names_original_last_view_within_readiness_bounds() {
    // Successful discovery retains unrelated readable views even when they
    // have no provider modules. Their actual original pins remain held here.
    let mut capture = Capture::fresh(131, true);
    assert!(
        capture.readiness().is_some(),
        "{}",
        capture.io.boundaries.borrow().join("\n")
    );
}
