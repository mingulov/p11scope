//! SPDX-License-Identifier: GPL-3.0-or-later
//! Fresh SYSTEM trace readiness through the production scheduler and proof ingress.
//!
//! The provider association, process pins and executable sample are real.
//! Only native CALL production,
//! cookie-map reads, loss-map reads and the clock are scripted. No receipt is
//! constructed by the fixture and no native counter or map is populated.
//! The time-overrun refusal control uses the existing sealed fixture sampler;
//! positive readiness and exploratory progress use actual OS samples.

use super::*;
use crate::attach::detailed_identity::{CgroupCandidate, TraceSeed};
use crate::events::{DiscoveryDrain, EventDrain, ScriptedRecords};
use crate::semantics::ProcessKey;
use crate::trace_identity::TraceIdentityStore;
use p11scope_ebpf_common::{Event, ImageIdentity};
use std::cell::RefCell;
use std::ops::ControlFlow;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};

const FRAME_NS: u64 = 200_000_000;
const ATTEMPT_WAIT_NS: u64 = 500_000_000;
const FIRST_MARKER_NS: u64 = 5_798_412;
const MAX_ATTEMPTS: usize = 20;
const READINESS_NS: u64 = 15_000_000_000;
const START_NS: u64 = 100_000_000;
static CAPTURE_LOCK: Mutex<()> = Mutex::new(());

struct ProviderFixture {
    _directory: tempfile::TempDir,
    library: PathBuf,
    driver: PathBuf,
}
impl ProviderFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let library = directory.path().join("trace-provider.so");
        assert!(
            Command::new("gcc")
                .args(["-shared", "-fPIC", "-DMATRIX_INTERFACES=0", "-o"])
                .arg(&library)
                .arg(root.join("crates/discover/tests/fixture/version_matrix.c"))
                .status()
                .unwrap()
                .success()
        );
        let driver = directory.path().join("trace-caller");
        assert!(
            Command::new("gcc")
                .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-o"])
                .arg(&driver)
                .arg(root.join("tests/fixtures/live-discovery-driver.c"))
                .args(["-ldl", "-pthread"])
                .status()
                .unwrap()
                .success()
        );
        Self {
            _directory: directory,
            library,
            driver,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.driver);
        command
            .arg("dlopen")
            .arg(&self.library)
            .env_clear()
            .env("P11SCOPE_FIXTURE_INTERFACES", "0")
            .env("P11SCOPE_FIXTURE_POST_GATE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        command
    }

    fn ready(child: &mut Child) {
        use std::io::Read as _;
        use std::os::fd::AsRawFd as _;
        let mut output = child.stderr.take().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"P11SCOPE_FIXTURE driver done\n") {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(!remaining.is_zero() && bytes.len() < 4096);
            assert!(
                crate::discovery::test_subject::poll_fd(output.as_raw_fd(), remaining).unwrap()
            );
            let mut byte = [0];
            output.read_exact(&mut byte).unwrap();
            bytes.extend_from_slice(&byte);
        }
    }
}

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
    overrun_target: bool,
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
            self.boundary("original-pin cookie read", result);
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
        let overran = Cell::new(false);
        let result = if view.pid() == self.target && self.overrun_target {
            // This refusal control uses the existing sealed fixture sampler to
            // expire the actual ticket inside the link bracket. Positive and
            // exploratory samples continue to use the real OS sampler.
            self.proof.test_sample_view_after_link(view, work, &mut || {
                overran.set(true);
                self.proof.test_set_time(self.proof.test_time() + 5_000_000);
            })
        } else {
            self.proof.test_sample_os_view(view, work)
        };
        if overran.get() {
            let state = work.state.as_ref().unwrap().lock().unwrap();
            assert!(
                state.reads > 0,
                "this refusal is time, not read-credit exhaustion"
            );
            assert_eq!(state.closed, Some(CgroupWorkRefusal::BudgetDeferred));
            self.boundary("sample time overrun", state.reads);
        }
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
                if self.overrun_target {
                    "original-view after-link refusal sample"
                } else {
                    "original-view OS sample"
                },
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
    _provider: Option<ProviderFixture>,
    _serial: MutexGuard<'static, ()>,
}

#[derive(Clone, Copy)]
enum ProviderStage {
    Absent,
    InitiallyMapped,
    AfterInitialScan,
}

impl Capture {
    fn fresh(unrelated: usize, system: bool) -> Self {
        Self::build(unrelated, system, ProviderStage::Absent)
    }

    fn mapped(unrelated: usize) -> Self {
        Self::build(unrelated, true, ProviderStage::InitiallyMapped)
    }

    fn late_mapped(unrelated: usize) -> Self {
        Self::build(unrelated, true, ProviderStage::AfterInitialScan)
    }

    fn build(unrelated: usize, system: bool, provider_stage: ProviderStage) -> Self {
        // The fixture owns up to 132 processes and their original pidfds. Keep
        // these controls serial even when the unit-test harness is parallel.
        let serial = CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let provider =
            (!matches!(provider_stage, ProviderStage::Absent)).then(ProviderFixture::new);
        let mut children = Children(Vec::new());
        let mut views = Vec::new();
        for index in 0..=unrelated {
            let child = if index == unrelated {
                if let Some(provider) = &provider {
                    let mut command = provider.command();
                    if matches!(provider_stage, ProviderStage::AfterInitialScan) {
                        command.env("P11SCOPE_FIXTURE_GATE", "1");
                    }
                    command.spawn().unwrap()
                } else {
                    Command::new("/bin/sleep").arg("30").spawn().unwrap()
                }
            } else {
                Command::new("/bin/sleep").arg("30").spawn().unwrap()
            };
            let pid = child.id();
            children.0.push(child);
            if index == unrelated && matches!(provider_stage, ProviderStage::InitiallyMapped) {
                ProviderFixture::ready(children.0.last_mut().unwrap());
            }
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
        if let Some(provider) = &provider {
            engine.module_hints = vec![provider.library.clone()];
            for position in 0..engine.views.len() {
                let view = &engine.views[position];
                let id = view.id();
                let admission = view.view_admission();
                let mut counters = DiscoveryCounters::default();
                let (modules, pins) = scan_and_pin(
                    view,
                    &engine.module_hints,
                    &engine.hooks,
                    &mut engine.budget,
                    &mut counters,
                    false,
                    &mut engine.stage_timings,
                )
                .unwrap();
                assert_eq!(
                    modules.is_empty(),
                    position != unrelated
                        || !matches!(provider_stage, ProviderStage::InitiallyMapped),
                    "only an actually mapped PKCS#11 caller contributes a module"
                );
                assert!(modules.iter().all(|module| module.view == id));
                // This is the discover_plan ingress. Scheduling metadata is
                // produced by the real scanner, separately from trace proof.
                engine.note_scan_observed(id, admission, &modules);
                engine.scan_inputs.insert(
                    id,
                    ScanInput {
                        modules,
                        pins,
                        counters,
                    },
                );
            }
        }
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
                overrun_target: false,
                boundaries: RefCell::new(Vec::new()),
            },
            key,
            expected_path,
            _children: children,
            _provider: provider,
            _serial: serial,
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
                    io.boundary("store admission", result);
                    result.unwrap();
                };
                let mut visits = engine.service_trace_images(io, work, accept).visited;
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
                visits += engine
                    .service_trace_images(io, work, |receipt| {
                        io.boundary(
                            "verified transfer",
                            (receipt.key(), receipt.eligible_after_ns()),
                        );
                        let result = store.admit(receipt);
                        io.boundary("store admission", result);
                        result.unwrap();
                    })
                    .visited;
                io.pending(engine, "after discovery drain");
                assert!(visits <= 32 && engine.trace_phase_visits <= 8);
                let state = work.state.as_ref().unwrap().lock().unwrap();
                assert!(state.reads <= 32 && state.visits <= 32);
                assert!(state.deadline - state.last_clock.min(state.deadline) <= 5_000_000);
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
        self.readiness_from(0)
    }

    fn readiness_from(&mut self, start: u64) -> Option<usize> {
        let mut next_frame = start;
        for attempt in 1..=MAX_ATTEMPTS {
            let marker = start + FIRST_MARKER_NS + (attempt - 1) as u64 * ATTEMPT_WAIT_NS;
            assert!(marker < READINESS_NS);
            while next_frame <= marker {
                self.frame(next_frame);
                next_frame += FRAME_NS;
            }
            if self.marker(marker) {
                eprintln!(
                    "trace readiness: {} views, {:?}, marker {attempt}, at {marker}ns",
                    self.engine.views.len(),
                    self.engine.scope,
                );
                for boundary in self.io.boundaries.borrow().iter().filter(|boundary| {
                    boundary.starts_with("original-view OS sample")
                        || boundary.starts_with("original-pin cookie read")
                        || boundary.starts_with("verified transfer")
                        || boundary.starts_with("store admission")
                        || (boundary.starts_with("CALL witness ingress")
                            && !boundary.contains("no pending target sample"))
                }) {
                    eprintln!("{boundary}");
                }
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
    let mut capture = Capture::mapped(131);
    assert!(
        capture.readiness().is_some(),
        "{}",
        capture.io.boundaries.borrow().join("\n")
    );
}

#[test]
fn fresh_system_trace_names_provider_found_after_initial_scan() {
    use std::io::Write as _;

    let mut capture = Capture::late_mapped(131);
    let view = capture.engine.views.last().unwrap();
    let id = view.id();
    let original = view.view_admission();
    assert_eq!(capture.engine.scan_inputs.len(), 132);
    assert!(
        capture
            .engine
            .scan_inputs
            .values()
            .all(|input| input.modules.is_empty())
    );
    assert!(capture.engine.trace_provider_views.is_empty());

    // Naming service has started while the original caller remains at its
    // pre-dlopen gate. Releasing stdin changes mappings, never the process or
    // its executable. The post-call gate then retains the mapped provider.
    capture.frame(0);
    let child = capture._children.0.last_mut().unwrap();
    assert_eq!(child.id(), capture.io.target);
    child.stdin.as_mut().unwrap().write_all(b"!").unwrap();
    ProviderFixture::ready(child);
    assert!(original.same_allocation(&capture.engine.views.last().unwrap().view_admission()));
    assert!(capture.engine.views.last().unwrap().still_the_same());

    // Use the actual refresh-scan ingress, which performs scan_and_pin and
    // note_scan_observed itself. Keep its real modules and pins held through
    // readiness; do not fill or alter the initial per-view scan input.
    let (late_scans, failed, deferred, _) = capture.engine.scan_inventory_views(
        &BTreeSet::from([id]),
        "late mapped provider refresh",
        &mut crate::attach::monotonic_ns,
    );
    assert!(failed.is_empty() && deferred.is_empty());
    assert_eq!(late_scans.len(), 1);
    assert_eq!(late_scans[0].0, id);
    assert!(!late_scans[0].1.is_empty());
    assert!(late_scans[0].1.iter().all(|module| module.view == id));
    assert!(capture.engine.trace_provider_views.contains_key(&id));
    capture.io.boundary(
        "late mapped provider scan association",
        (
            late_scans[0].1.len(),
            capture
                .engine
                .scan_inputs
                .get(&id)
                .map(|input| input.modules.len()),
            capture
                .engine
                .trace_provider_associated(capture.engine.views.last().unwrap()),
        ),
    );

    // Start at the next ordinary frame, preserving monotonic proof time and
    // the same twenty markers, 500ms cadence, 15s bound and 8/32/5ms tickets.
    assert!(
        capture.readiness_from(FRAME_NS).is_some(),
        "{}",
        capture.io.boundaries.borrow().join("\n")
    );
}

#[test]
fn fresh_system_trace_provider_target_survives_dead_unreadable_exploratory_first() {
    let mut capture = Capture::mapped(131);
    let mut dead = capture._children.0.remove(0);
    let pid = dead.id();
    dead.kill().unwrap();
    dead.wait().unwrap();
    assert_eq!(capture.engine.views[0].pid(), pid);
    assert!(
        capture.engine.views[0]
            .retained_pin()
            .original_exited()
            .unwrap()
    );
    assert!(std::fs::read_link(format!("/proc/{pid}/exe")).is_err());
    assert!(
        capture.readiness().is_some(),
        "{}",
        capture.io.boundaries.borrow().join("\n")
    );
}

#[test]
fn fresh_system_trace_exploratory_sampling_progresses_under_provider_calls() {
    let mut capture = Capture::mapped(131);
    let exploratory = capture.engine.views[0].pid();
    let mut next_frame = 0;
    let mut named = false;
    for attempt in 0..MAX_ATTEMPTS {
        let marker = FIRST_MARKER_NS + attempt as u64 * ATTEMPT_WAIT_NS;
        while next_frame <= marker {
            capture.frame(next_frame);
            next_frame += FRAME_NS;
        }
        named |= capture.marker(marker);
    }
    assert!(named, "{}", capture.io.boundaries.borrow().join("\n"));
    let (_, start, completed, witness) = capture
        .io
        .proof
        .test_pending_times(exploratory)
        .expect("the original exploratory view must obtain a real completed OS sample");
    assert!(start < completed && completed < START_NS + READINESS_NS);
    assert!(
        witness.is_none(),
        "provider CALLs cannot witness the exploratory process"
    );
}

#[test]
fn fresh_system_trace_provider_time_overrun_preserves_exploratory_progress() {
    let mut capture = Capture::mapped(1);
    let exploratory = capture.engine.views[0].pid();
    capture.io.overrun_target = true;
    for frame in 0..16 {
        capture.frame(frame * FRAME_NS);
        assert!(
            capture
                .io
                .proof
                .test_pending_times(capture.io.target)
                .is_none()
        );
        assert!(
            capture
                .store
                .lookup(capture.key, START_NS + frame * FRAME_NS)
                .path()
                .is_none()
        );
    }
    assert!(
        capture
            .io
            .boundaries
            .borrow()
            .iter()
            .any(|boundary| boundary.starts_with("sample time overrun")),
        "the provider-associated view must hit the real ticket time refusal"
    );
    let (_, start, completed, witness) = capture
        .io
        .proof
        .test_pending_times(exploratory)
        .expect("provider time overruns must advance to the original exploratory view");
    assert!(start < completed && completed < START_NS + READINESS_NS);
    assert!(witness.is_none());
}

#[test]
fn fresh_system_trace_provider_association_alone_cannot_grant_a_name() {
    for association in [
        "current", "missing", "stale", "foreign", "reused", "replaced",
    ] {
        let mut capture = if association == "missing" {
            Capture::late_mapped(1)
        } else {
            Capture::mapped(1)
        };
        let id = capture.engine.views.last().unwrap().id();
        assert_eq!(
            capture.engine.trace_provider_views.contains_key(&id),
            association != "missing"
        );
        match association {
            "missing" => {}
            "stale" => {
                let position = capture.engine.views.len() - 1;
                let unrelated_pid = capture.engine.views[0].pid();
                capture.engine.views[position] = ProcessView::open(id, unrelated_pid).unwrap();
                // A real empty refresh on the replacement allocation must
                // clear the formerly observed provider association at ingress.
                let (scans, failed, deferred, _) = capture.engine.scan_inventory_views(
                    &BTreeSet::from([id]),
                    "empty replacement association",
                    &mut crate::attach::monotonic_ns,
                );
                assert!(failed.is_empty() && deferred.is_empty());
                assert_eq!(scans.len(), 1);
                assert!(scans[0].1.is_empty());
                assert!(!capture.engine.trace_provider_views.contains_key(&id));
            }
            "foreign" => {
                // Supply actual discovery data from a different held caller;
                // no ScannedModule is constructed or its origin rewritten.
                let child = capture
                    ._provider
                    .as_ref()
                    .unwrap()
                    .command()
                    .spawn()
                    .unwrap();
                let pid = child.id();
                capture._children.0.push(child);
                ProviderFixture::ready(capture._children.0.last_mut().unwrap());
                let foreign = ProcessView::open(ProcessViewId(id.0 + 1), pid).unwrap();
                let (scan, _) = Engine::scan_retained_view(
                    &foreign,
                    &capture.engine.module_hints,
                    &capture.engine.hooks,
                    &mut capture.engine.budget,
                    false,
                    &mut capture.engine.stage_timings,
                );
                let (modules, _pins, _) = scan.unwrap();
                assert!(!modules.is_empty());
                assert!(modules.iter().all(|module| module.view == foreign.id()));
                let admission = capture.engine.views.last().unwrap().view_admission();
                capture.engine.note_scan_observed(id, admission, &modules);
                assert!(!capture.engine.trace_provider_views.contains_key(&id));
            }
            "reused" => {
                capture.engine.release_view_id(id);
                assert!(!capture.engine.trace_provider_views.contains_key(&id));
                let position = capture.engine.views.len() - 1;
                let unrelated_pid = capture.engine.views[0].pid();
                capture.engine.views[position] = ProcessView::open(id, unrelated_pid).unwrap();
            }
            "replaced" => {
                let position = capture.engine.views.len() - 1;
                let pid = capture.engine.views[position].pid();
                let old = capture.engine.views[position].view_admission();
                capture.engine.views[position] = ProcessView::open(id, pid).unwrap();
                let new = capture.engine.views[position].view_admission();
                assert!(!old.same_allocation(&new));
                assert!(
                    !capture
                        .engine
                        .trace_provider_associated(&capture.engine.views[position])
                );
                assert!(capture.engine.trace_provider_views.contains_key(&id));
            }
            "current" => {}
            _ => unreachable!(),
        }
        // A discovery association, even one cached before becoming stale, is
        // only a scheduling hint. No native CALL is supplied in this control.
        for at in (0..READINESS_NS).step_by(FRAME_NS as usize) {
            capture.frame(at);
            assert!(
                capture
                    .store
                    .lookup(capture.key, START_NS + at)
                    .path()
                    .is_none(),
                "{association} provider association must not construct naming proof"
            );
        }
        assert_eq!(
            capture.engine.trace_provider_views.contains_key(&id),
            association == "current"
        );
    }
}
