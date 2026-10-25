//! SPDX-License-Identifier: GPL-3.0-or-later
//! Native home of the Joint state×event cells for the owned-detach
//! states J14–J16 (§8.7): J14 `OwnedProducerDetach::Pending`, J15
//! detach Unproved, J16 detach Complete with completion minted, each
//! against the nine events other than retire_own.
//!
//! Each event is applied as its native effect only: additional `poll`
//! calls for stop, deadline, cancel, capture_error and sink_failure;
//! no native call for promote and replace_foreign; and
//! `ExitRetention::hold` of the detach owner for the typed-exit (T)
//! cells, after which nothing is joined and no completion mints. The
//! B (promotion admission), H (held-install reclaim) and retire
//! aspects are driver/lane-owned; these cells prove the detach side
//! they leave behind: preservation under zero native calls.

use super::{
    CleanupWorker, DetachOrder, OwnedLink, OwnedProducerDetach, ProducerDetachProgress,
    ProducerProgram, SessionNativeCompletion,
};
use crate::inventory_capture::ExitRetention;
use anyhow::Result;
use std::fs::File;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak, mpsc};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

/// The contract cell macro: the test name is passed as an argument
/// (no `paste`). Each invocation builds its state with `scene_for`
/// and runs its body against the built scene and event.
macro_rules! joint_cell {
    ($name:ident, $state:expr, $event:expr, $body:expr) => {
        #[test]
        fn $name() {
            $body(scene_for($state), $event)
        }
    };
}

/// The Native home's states: the owned-detach states J14–J16.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JointState {
    J14,
    J15,
    J16,
}

/// The Native home's events: the nine events other than retire_own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JointEvent {
    Stop,
    Deadline,
    Cancel,
    Promote,
    ReplaceForeign,
    CaptureError,
    SinkFailure,
    HeldInstall,
    Sigint2,
}

/// Pending-poll rounds per O cell: the SAME worker thread id across
/// at least three polls.
const POLL_ROUNDS: usize = 3;
/// Backstop for the blocked-close gate and the join loops. Cells
/// finish in milliseconds; the timeouts only bound failures.
const GATE_TIMEOUT: Duration = Duration::from_secs(5);
const JOIN_DEADLINE: Duration = Duration::from_secs(5);
/// The genuine close failure that drives the J15 scenes Unproved.
const GENUINE_CLOSE_FAILURE: &str = "joint native cell genuine close failure";
/// First errors recorded by the capture_error and sink_failure events
/// where no error exists yet (J14, J16). The native property is
/// preservation: polls never lose or overwrite them.
const CAPTURE_ERROR: &str = "joint native cell capture error";
const SINK_FAILURE: &str = "joint native cell sink failure";
/// Exact production texts pinned by the refusal assertions.
const UNPROVED_REFUSAL: &str =
    "producer detach has no unsettled owned job; completion remains unproven";
const UNCERTAIN_PREFIX: &str = "producer detach ownership remains uncertain: ";
const JOIN_GATE_TEXT: &str = "native completion requires joined producer detach";
/// Stand-in EVENTS identity carried by the minted J16 completions.
const EVENTS_ID: u64 = 7;

/// One owned link over a clone of the lease file. This mirrors the
/// `mod tests` helper of the same name, which is unreachable from this
/// top-level test module; its body is intentionally identical.
fn terminal_fixture_payload(
    file: &std::fs::File,
    producer: ProducerProgram,
) -> (OwnedLink, ProducerProgram) {
    (
        OwnedLink::Multi(vec![file.try_clone().unwrap().into()]),
        producer,
    )
}

/// Drop spy owned by value inside the detach owner: it fires if and
/// only if the owner is dropped. `ExitRetention::hold` forgets the
/// owner, so the spy never fires on the typed-exit path.
struct HoldSpy {
    fired: Arc<AtomicBool>,
}

impl Drop for HoldSpy {
    fn drop(&mut self) {
        self.fired.store(true, Ordering::SeqCst);
    }
}

/// The detach owner: the Session's exact detach fields that
/// `Session::poll_owned_producer_detach` delegates to. A full Session
/// cannot be built in a unit test (it needs the BPF object, the
/// STOP_GATE mapping and the EVENTS domains), so the cells own these
/// fields directly, following the §8.2 test pattern.
struct NativeDetachOwner {
    job: OwnedProducerDetach,
    failures: Vec<String>,
    detached: bool,
    wall_ms: u64,
    _hold_spy: HoldSpy,
}

/// A built J14/J15/J16 state: the detach owner plus the control
/// handles and spies that live outside the owner and survive `hold`.
struct NativeScene {
    owner: Option<NativeDetachOwner>,
    /// Gate release for the J14 blocked closer (`None` once joined).
    release: Option<mpsc::Sender<()>>,
    /// Closes still holding the gate; released by `Drop`.
    pending_closes: usize,
    /// The original lease file; alive while the worker holds the batch.
    lease: Weak<File>,
    /// The original worker thread id (J14; `None` once joined).
    thread: Option<ThreadId>,
    /// Closer invocations; the typed exit must add none.
    runs: Arc<AtomicUsize>,
    /// The minted completion (J16 only).
    completion: Option<SessionNativeCompletion>,
    /// The hold spy flag.
    spy: Arc<AtomicBool>,
}

impl NativeScene {
    fn release_closes(&mut self, n: usize) {
        for _ in 0..n {
            if let Some(release) = &self.release {
                let _ = release.send(());
            }
        }
        self.pending_closes = self.pending_closes.saturating_sub(n);
    }
}

impl Drop for NativeScene {
    fn drop(&mut self) {
        // Backstop only: every gated close is released so no dropped
        // or retained worker ever hits its gate timeout. Joins happen
        // only through explicit polls in N bodies, never here.
        let pending = self.pending_closes;
        self.release_closes(pending);
    }
}

fn scene_for(state: JointState) -> NativeScene {
    match state {
        JointState::J14 => scene_pending_blocked(),
        JointState::J15 => scene_unproved_failed(),
        JointState::J16 => scene_complete_minted(),
    }
}

/// J14: a real worker with a blocked closer and a real lease file,
/// already inside its first close.
fn scene_pending_blocked() -> NativeScene {
    let file = Arc::new(tempfile::tempfile().expect("lease file"));
    let lease = Arc::downgrade(&file);
    let runs = Arc::new(AtomicUsize::new(0));
    let runs_in = Arc::clone(&runs);
    let (release, released) = mpsc::channel();
    let released = Mutex::new(released);
    let (entered, entered_rx) = mpsc::channel();
    let worker = CleanupWorker::pre_start_with(
        Box::new(move |payload, _| {
            runs_in.fetch_add(1, Ordering::SeqCst);
            entered.send(()).expect("entered signal");
            released
                .lock()
                .expect("gate")
                .recv_timeout(GATE_TIMEOUT)
                .expect("gate release");
            drop(payload.take());
            Ok(())
        }),
        Arc::new(|| Duration::ZERO),
    );
    worker.submit(
        vec![terminal_fixture_payload(
            &file,
            ProducerProgram::UProbe("p11_entry"),
        )],
        Arc::new(vec![file]),
        DetachOrder,
    );
    entered_rx
        .recv_timeout(GATE_TIMEOUT)
        .expect("the closer blocks in its first close");
    let thread = worker.original_thread_id();
    assert!(
        thread.is_some(),
        "the J14 worker thread is prestarted before the event"
    );
    assert_eq!(
        runs.load(Ordering::SeqCst),
        1,
        "the J14 closer entered exactly once before the event"
    );
    let job = OwnedProducerDetach::Pending {
        worker,
        started: Instant::now(),
        had_work: true,
    };
    let spy = Arc::new(AtomicBool::new(false));
    NativeScene {
        owner: Some(NativeDetachOwner {
            job,
            failures: Vec::new(),
            detached: false,
            wall_ms: 0,
            _hold_spy: HoldSpy {
                fired: Arc::clone(&spy),
            },
        }),
        release: Some(release),
        pending_closes: 1,
        lease,
        thread,
        runs,
        completion: None,
        spy,
    }
}

/// J15: the same shape, driven Unproved through the production poll
/// by a genuine close failure.
fn scene_unproved_failed() -> NativeScene {
    let file = Arc::new(tempfile::tempfile().expect("lease file"));
    let lease = Arc::downgrade(&file);
    let runs = Arc::new(AtomicUsize::new(0));
    let runs_in = Arc::clone(&runs);
    let worker = CleanupWorker::pre_start_with(
        Box::new(move |_, _| {
            runs_in.fetch_add(1, Ordering::SeqCst);
            Err(GENUINE_CLOSE_FAILURE.to_string())
        }),
        Arc::new(|| Duration::ZERO),
    );
    worker.submit(
        vec![terminal_fixture_payload(
            &file,
            ProducerProgram::UProbe("p11_entry"),
        )],
        Arc::new(vec![file]),
        DetachOrder,
    );
    let spy = Arc::new(AtomicBool::new(false));
    let mut scene = NativeScene {
        owner: Some(NativeDetachOwner {
            job: OwnedProducerDetach::Pending {
                worker,
                started: Instant::now(),
                had_work: true,
            },
            failures: Vec::new(),
            detached: false,
            wall_ms: 0,
            _hold_spy: HoldSpy {
                fired: Arc::clone(&spy),
            },
        }),
        release: None,
        pending_closes: 0,
        lease,
        thread: None,
        runs,
        completion: None,
        spy,
    };
    let deadline = Instant::now() + JOIN_DEADLINE;
    loop {
        match poll_now(&mut scene) {
            Ok(ProducerDetachProgress::Pending) => {
                assert!(Instant::now() < deadline, "the failing close must settle");
                std::thread::yield_now();
            }
            Ok(ProducerDetachProgress::Complete) => {
                panic!("a genuine close failure cannot complete the detach")
            }
            Err(error) => {
                assert!(
                    format!("{error:#}").contains(GENUINE_CLOSE_FAILURE),
                    "the genuine failure drives Unproved: {error:#}"
                );
                break;
            }
        }
    }
    let owner = scene.owner.as_ref().expect("detach owner");
    assert!(
        matches!(owner.job, OwnedProducerDetach::Unproved),
        "the J15 scene is genuinely Unproved"
    );
    assert!(!owner.detached, "the J15 scene detached nothing");
    assert_eq!(
        owner.failures,
        [GENUINE_CLOSE_FAILURE.to_owned()],
        "the J15 scene keeps its genuine first error"
    );
    assert_eq!(
        scene.runs.load(Ordering::SeqCst),
        1,
        "the J15 closer ran exactly once"
    );
    scene
}

/// J16: driven Complete through the production poll over a joined
/// receipt, with the completion minted through the minter's own
/// adjudication over the real joined-detach evidence. The quiescence
/// input stands in for the stop-gate proof, which lives at the mint
/// seam, not the detach seam.
fn scene_complete_minted() -> NativeScene {
    let file = Arc::new(tempfile::tempfile().expect("lease file"));
    let lease = Arc::downgrade(&file);
    let runs = Arc::new(AtomicUsize::new(0));
    let runs_in = Arc::clone(&runs);
    let worker = CleanupWorker::pre_start_with(
        Box::new(move |payload, _| {
            runs_in.fetch_add(1, Ordering::SeqCst);
            drop(payload.take());
            Ok(())
        }),
        Arc::new(|| Duration::ZERO),
    );
    worker.submit(
        vec![terminal_fixture_payload(
            &file,
            ProducerProgram::UProbe("p11_entry"),
        )],
        Arc::new(vec![file]),
        DetachOrder,
    );
    let spy = Arc::new(AtomicBool::new(false));
    let mut scene = NativeScene {
        owner: Some(NativeDetachOwner {
            job: OwnedProducerDetach::Pending {
                worker,
                started: Instant::now(),
                had_work: true,
            },
            failures: Vec::new(),
            detached: false,
            wall_ms: 0,
            _hold_spy: HoldSpy {
                fired: Arc::clone(&spy),
            },
        }),
        release: None,
        pending_closes: 0,
        lease,
        thread: None,
        runs,
        completion: None,
        spy,
    };
    let deadline = Instant::now() + JOIN_DEADLINE;
    loop {
        let progress = poll_now(&mut scene).expect("the succeeding close settles the owned detach");
        if matches!(progress, ProducerDetachProgress::Complete) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the succeeding close must settle"
        );
        std::thread::yield_now();
    }
    let wall_ms = {
        let owner = scene.owner.as_ref().expect("detach owner");
        assert!(
            matches!(owner.job, OwnedProducerDetach::Complete),
            "the J16 scene is genuinely Complete"
        );
        assert!(
            owner.detached && owner.failures.is_empty(),
            "the J16 scene detached cleanly"
        );
        owner.wall_ms
    };
    let completion = SessionNativeCompletion::from_joined_evidence(
        true, true, false, false, 0, 0, 0, wall_ms, false, EVENTS_ID,
    )
    .expect("the joined detach mints");
    scene.completion = Some(completion);
    scene
}

/// One non-consuming reap over the scene's detach owner.
fn poll_now(scene: &mut NativeScene) -> Result<ProducerDetachProgress> {
    let owner = scene
        .owner
        .as_mut()
        .expect("the detach owner is live until the typed exit");
    owner.job.poll(
        &mut owner.failures,
        &mut owner.detached,
        &mut owner.wall_ms,
        &mut std::io::sink(),
    )
}

fn pending_thread(scene: &NativeScene) -> Option<ThreadId> {
    match &scene.owner.as_ref().expect("detach owner").job {
        OwnedProducerDetach::Pending { worker, .. } => worker.original_thread_id(),
        _ => None,
    }
}

fn pending_worker(scene: &NativeScene) -> &CleanupWorker {
    match &scene.owner.as_ref().expect("detach owner").job {
        OwnedProducerDetach::Pending { worker, .. } => worker,
        _ => panic!("the scene holds no pending worker"),
    }
}

/// O at J14: Pending across the poll rounds with the SAME worker
/// thread, the original leases alive, and the outputs preserved.
fn assert_pending_owner_kept(scene: &mut NativeScene) {
    let failures_before = scene.owner.as_ref().expect("detach owner").failures.clone();
    for _ in 0..POLL_ROUNDS {
        let progress = poll_now(scene).expect("a blocked close keeps the owned detach pending");
        assert!(
            matches!(progress, ProducerDetachProgress::Pending),
            "a blocked close keeps the owned detach pending"
        );
        assert_eq!(
            pending_thread(scene),
            scene.thread,
            "a pending poll keeps the SAME worker thread"
        );
        assert!(
            !scene.owner.as_ref().expect("detach owner").detached,
            "a pending poll detaches nothing"
        );
        assert!(
            scene
                .lease
                .upgrade()
                .is_some_and(|file| file.metadata().is_ok()),
            "a pending poll keeps the original leases"
        );
    }
    assert_eq!(
        scene.owner.as_ref().expect("detach owner").failures,
        failures_before,
        "a pending poll keeps the original outputs"
    );
}

/// O at J15: every poll is refused with the exact text, Unproved is
/// kept, and the outputs are preserved without naming their content
/// (E cells name the first error separately).
fn assert_unproved_refused_and_kept(scene: &mut NativeScene) {
    let failures_before = scene.owner.as_ref().expect("detach owner").failures.clone();
    for _ in 0..POLL_ROUNDS {
        let error = poll_now(scene).expect_err("an unproved detach refuses every poll");
        assert_eq!(format!("{error:#}"), UNPROVED_REFUSAL);
        assert!(
            matches!(
                scene.owner.as_ref().expect("detach owner").job,
                OwnedProducerDetach::Unproved
            ),
            "a refused poll keeps Unproved"
        );
        assert!(
            !scene.owner.as_ref().expect("detach owner").detached,
            "a refused poll detaches nothing"
        );
    }
    assert_eq!(
        scene.owner.as_ref().expect("detach owner").failures,
        failures_before,
        "a refused poll keeps the original outputs"
    );
}

/// E: exactly the first error is kept, never overwritten or appended to.
fn assert_first_error_kept(scene: &NativeScene, expected: &str) {
    assert_eq!(
        scene.owner.as_ref().expect("detach owner").failures,
        [expected.to_owned()],
        "the first error is kept"
    );
}

/// O/idempotent at J16: every poll reports Complete, the detached
/// flag stays set, and the outputs are preserved.
fn assert_completed_detach_preserved(scene: &mut NativeScene) {
    let failures_before = scene.owner.as_ref().expect("detach owner").failures.clone();
    for _ in 0..POLL_ROUNDS {
        let progress = poll_now(scene).expect("a completed detach stays complete");
        assert!(
            matches!(progress, ProducerDetachProgress::Complete),
            "a completed detach stays complete"
        );
        assert!(
            scene.owner.as_ref().expect("detach owner").detached,
            "a completed poll keeps the detached flag"
        );
    }
    assert_eq!(
        scene.owner.as_ref().expect("detach owner").failures,
        failures_before,
        "a completed poll keeps the original outputs"
    );
}

/// E at J16: the recorded first error refuses every completed poll
/// with the exact text while the completed state is preserved.
fn assert_completed_error_kept(scene: &mut NativeScene, expected: &str) {
    assert_first_error_kept(scene, expected);
    for _ in 0..POLL_ROUNDS {
        let error = poll_now(scene).expect_err("a recorded error refuses the completed poll");
        assert_eq!(
            format!("{error:#}"),
            format!("{UNCERTAIN_PREFIX}{expected}"),
        );
        assert!(
            matches!(
                scene.owner.as_ref().expect("detach owner").job,
                OwnedProducerDetach::Complete
            ),
            "the refusal preserves the completed state"
        );
        assert!(
            !scene.owner.as_ref().expect("detach owner").detached,
            "the refusal clears the detached flag"
        );
        assert_first_error_kept(scene, expected);
    }
}

/// Proves a J14 event issued no native call: any poll would have
/// latched Shutdown and refused this probe submit, so its acceptance
/// (the worker total grows) proves the event polled nothing.
fn assert_event_issued_no_native_call(scene: &mut NativeScene) {
    let total_before = pending_worker(scene).progress().total;
    pending_worker(scene).submit(
        vec![(
            OwnedLink::Multi(Vec::new()),
            ProducerProgram::UProbe("p11_entry"),
        )],
        Arc::default(),
        DetachOrder,
    );
    scene.pending_closes += 1;
    assert_eq!(
        pending_worker(scene).progress().total,
        total_before + 1,
        "the event issued no poll: the probe submit is accepted"
    );
}

/// The B/X native aspect at J14/J15: no completion exists and none
/// can mint from the unjoined detach.
fn assert_no_completion_mints(scene: &NativeScene) {
    let detach_complete = matches!(
        scene.owner.as_ref().expect("detach owner").job,
        OwnedProducerDetach::Complete
    );
    assert!(
        !detach_complete,
        "J14/J15 hold no joined detach to mint from"
    );
    let refusal = SessionNativeCompletion::join_gates(detach_complete, true)
        .expect_err("no completion mints before the joined detach");
    assert_eq!(format!("{refusal:#}"), JOIN_GATE_TEXT);
}

type CompletionSnapshot = (u64, u64, usize, u64, bool, u64);

fn snapshot_completion(scene: &NativeScene) -> CompletionSnapshot {
    let completion = scene
        .completion
        .as_ref()
        .expect("J16 holds a minted completion");
    (
        completion.terminal_events(),
        completion.terminal_malformed(),
        completion.scrubbed_objects(),
        completion.detach_wall_ms(),
        completion.selected_terminal(),
        completion.events_id(),
    )
}

fn assert_completion_unchanged(scene: &NativeScene, before: &CompletionSnapshot) {
    assert_eq!(
        &snapshot_completion(scene),
        before,
        "the minted completion is unchanged"
    );
}

/// N at J14: release the blocked close; the joined receipt completes
/// the detach. The retire itself is lane-owned.
fn release_and_join(scene: &mut NativeScene) {
    let pending = scene.pending_closes;
    assert!(pending > 0, "the N cell releases a blocked close");
    scene.release_closes(pending);
    let deadline = Instant::now() + JOIN_DEADLINE;
    loop {
        let progress = poll_now(scene).expect("the released close settles the owned detach");
        if matches!(progress, ProducerDetachProgress::Complete) {
            break;
        }
        assert!(Instant::now() < deadline, "the released close must settle");
        std::thread::yield_now();
    }
    let owner = scene.owner.as_ref().expect("detach owner");
    assert!(
        matches!(owner.job, OwnedProducerDetach::Complete),
        "the joined receipt completes the detach"
    );
    assert!(
        owner.detached && owner.failures.is_empty(),
        "the joined receipt detaches cleanly"
    );
}

/// T: retain the detach owner through the typed process-exit path.
/// Nothing is joined afterwards and no completion mints. Only
/// unsettled (J14/J15) detaches take this path. The J14 gate stays
/// closed through the assertions and is released by the scene's Drop.
fn assert_typed_exit_retains_without_join(scene: &mut NativeScene, lease_kept: bool) {
    let detach_complete = matches!(
        scene.owner.as_ref().expect("detach owner").job,
        OwnedProducerDetach::Complete
    );
    assert!(
        !detach_complete,
        "only an unsettled detach takes the typed exit"
    );
    assert!(
        !scene.spy.load(Ordering::SeqCst),
        "the owner is alive before the typed exit"
    );
    let runs_before = scene.runs.load(Ordering::SeqCst);
    let owner = scene
        .owner
        .take()
        .expect("the detach owner is held exactly once");
    ExitRetention::hold(owner);
    assert!(
        !scene.spy.load(Ordering::SeqCst),
        "the typed exit retains the owner without drop"
    );
    assert_eq!(
        scene.runs.load(Ordering::SeqCst),
        runs_before,
        "the typed exit joins nothing afterwards"
    );
    if lease_kept {
        assert!(
            scene
                .lease
                .upgrade()
                .is_some_and(|file| file.metadata().is_ok()),
            "the typed exit retains the original leases"
        );
    }
    let refusal = SessionNativeCompletion::join_gates(detach_complete, true)
        .expect_err("no completion mints from a retained detach");
    assert_eq!(
        format!("{refusal:#}"),
        JOIN_GATE_TEXT,
        "no completion mints from a retained detach"
    );
}

// J14 cells: `OwnedProducerDetach::Pending` with a blocked closer.

/// J14×stop (O N): the blocked close stays pending with the SAME
/// worker, then the joined receipt completes the detach.
fn joint_cell_j14_stop_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Stop));
    assert_pending_owner_kept(&mut scene);
    release_and_join(&mut scene);
}

/// J14×deadline (O N): the table shares the stop row; the Deadline
/// cause-once is machine-owned, so the native effect twins stop.
fn joint_cell_j14_deadline_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Deadline));
    assert_pending_owner_kept(&mut scene);
    release_and_join(&mut scene);
}

/// J14×cancel (O): cancel releases nothing; the blocked close stays
/// pending with the SAME worker.
fn joint_cell_j14_cancel_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Cancel));
    assert_pending_owner_kept(&mut scene);
}

/// J14×promote (O B): promote issues no native call (B is prepared
/// only after A retires, driver-owned); the pending owner is kept and
/// nothing can mint yet.
fn joint_cell_j14_promote_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Promote));
    assert_event_issued_no_native_call(&mut scene);
    assert_no_completion_mints(&scene);
    assert_pending_owner_kept(&mut scene);
}

/// J14×replace_foreign (X O): the foreign replace is refused with no
/// native call; no completion exists, and the pending owner is kept.
fn joint_cell_j14_replace_foreign_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::ReplaceForeign));
    assert_event_issued_no_native_call(&mut scene);
    assert_no_completion_mints(&scene);
    assert_pending_owner_kept(&mut scene);
}

/// J14×capture_error (O E): the capture error is the first error kept
/// against the pending detach; polls preserve it and stay pending.
fn joint_cell_j14_capture_error_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::CaptureError));
    scene
        .owner
        .as_mut()
        .expect("detach owner")
        .failures
        .push(CAPTURE_ERROR.to_owned());
    assert_pending_owner_kept(&mut scene);
    assert_first_error_kept(&scene, CAPTURE_ERROR);
}

/// J14×sink_failure (O E): twins capture_error; the sink/capture
/// distinction lives in the lane I/O seams, not the detach seam.
fn joint_cell_j14_sink_failure_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::SinkFailure));
    scene
        .owner
        .as_mut()
        .expect("detach owner")
        .failures
        .push(SINK_FAILURE.to_owned());
    assert_pending_owner_kept(&mut scene);
    assert_first_error_kept(&scene, SINK_FAILURE);
}

/// J14×held_install (O H): H (the held install reclaimed once with
/// RunStopped) is driver-owned; the reclaim issues no detach call, so
/// the native cell proves the pending owner preserved.
fn joint_cell_j14_held_install_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::HeldInstall));
    assert_pending_owner_kept(&mut scene);
}

/// J14×sigint2 (O T, no join): the pending owner is kept, then
/// retained through the typed exit without any join or mint.
fn joint_cell_j14_sigint2_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Sigint2));
    assert_pending_owner_kept(&mut scene);
    assert_typed_exit_retains_without_join(&mut scene, true);
}

// J15 cells: detach Unproved by a genuine close failure.

/// J15×stop (O E T): every poll is refused, the genuine first error
/// is kept, then the owner is retained through the typed exit.
fn joint_cell_j15_stop_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Stop));
    assert_unproved_refused_and_kept(&mut scene);
    assert_first_error_kept(&scene, GENUINE_CLOSE_FAILURE);
    assert_typed_exit_retains_without_join(&mut scene, false);
}

/// J15×deadline (O E T): the table shares the stop row; the Deadline
/// cause-once is machine-owned, so the native effect twins stop.
fn joint_cell_j15_deadline_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Deadline));
    assert_unproved_refused_and_kept(&mut scene);
    assert_first_error_kept(&scene, GENUINE_CLOSE_FAILURE);
    assert_typed_exit_retains_without_join(&mut scene, false);
}

/// J15×cancel (O E): every poll is refused and the genuine first
/// error is kept; cancel takes no typed exit.
fn joint_cell_j15_cancel_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Cancel));
    assert_unproved_refused_and_kept(&mut scene);
    assert_first_error_kept(&scene, GENUINE_CLOSE_FAILURE);
}

/// J15×promote (O E B): promote issues no native call (B is prepared
/// only after A retires, driver-owned); the Unproved owner and its
/// genuine first error are kept, and nothing can mint.
fn joint_cell_j15_promote_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Promote));
    assert_no_completion_mints(&scene);
    assert_unproved_refused_and_kept(&mut scene);
    assert_first_error_kept(&scene, GENUINE_CLOSE_FAILURE);
}

/// J15×replace_foreign (X O): the foreign replace is refused; no
/// completion exists, and the Unproved owner is kept.
fn joint_cell_j15_replace_foreign_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::ReplaceForeign));
    assert_no_completion_mints(&scene);
    assert_unproved_refused_and_kept(&mut scene);
}

/// J15×capture_error (O E T): the event appends nothing, so the
/// genuine close failure stays the first error kept; then the owner
/// is retained through the typed exit.
fn joint_cell_j15_capture_error_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::CaptureError));
    assert_unproved_refused_and_kept(&mut scene);
    assert_first_error_kept(&scene, GENUINE_CLOSE_FAILURE);
    assert_typed_exit_retains_without_join(&mut scene, false);
}

/// J15×sink_failure (O E): the event appends nothing, so the genuine
/// close failure stays the first error kept; no typed exit.
fn joint_cell_j15_sink_failure_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::SinkFailure));
    assert_unproved_refused_and_kept(&mut scene);
    assert_first_error_kept(&scene, GENUINE_CLOSE_FAILURE);
}

/// J15×held_install (O E H T): H (the held install reclaimed once
/// with RunStopped) is driver-owned; the reclaim issues no detach
/// call. The Unproved owner and its genuine first error are kept,
/// then retained through the typed exit.
fn joint_cell_j15_held_install_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::HeldInstall));
    assert_unproved_refused_and_kept(&mut scene);
    assert_first_error_kept(&scene, GENUINE_CLOSE_FAILURE);
    assert_typed_exit_retains_without_join(&mut scene, false);
}

/// J15×sigint2 (O T): the Unproved owner is kept, then retained
/// through the typed exit without any join or mint.
fn joint_cell_j15_sigint2_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Sigint2));
    assert_unproved_refused_and_kept(&mut scene);
    assert_typed_exit_retains_without_join(&mut scene, false);
}

// J16 cells: detach Complete with completion minted.

/// J16×stop (idempotent): repeated polls report Complete and change
/// nothing, including the minted completion.
fn joint_cell_j16_stop_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Stop));
    let before = snapshot_completion(&scene);
    assert_completed_detach_preserved(&mut scene);
    assert_completion_unchanged(&scene, &before);
}

/// J16×deadline (idempotent): the table shares the stop row; the
/// Deadline cause-once is machine-owned, so the native effect twins
/// stop.
fn joint_cell_j16_deadline_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Deadline));
    let before = snapshot_completion(&scene);
    assert_completed_detach_preserved(&mut scene);
    assert_completion_unchanged(&scene, &before);
}

/// J16×cancel (O): cancel after completion keeps the completed owner
/// and the minted completion.
fn joint_cell_j16_cancel_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Cancel));
    let before = snapshot_completion(&scene);
    assert_completed_detach_preserved(&mut scene);
    assert_completion_unchanged(&scene, &before);
}

/// J16×promote (B after retire): promote issues no native call; the
/// single minted completion stands unchanged for the retire-then-
/// promote order (retire is lane-owned, admission driver-owned).
fn joint_cell_j16_promote_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Promote));
    let before = snapshot_completion(&scene);
    assert_completed_detach_preserved(&mut scene);
    assert_completion_unchanged(&scene, &before);
}

/// J16×replace_foreign (X O): the foreign replace is refused and
/// returns the completion unchanged; the completed owner is kept.
fn joint_cell_j16_replace_foreign_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::ReplaceForeign));
    let before = snapshot_completion(&scene);
    assert_completed_detach_preserved(&mut scene);
    assert_completion_unchanged(&scene, &before);
}

/// J16×capture_error (E): the capture error is the first error kept
/// against the completed detach; it refuses every later poll while
/// the completed state is preserved. The completion is unasserted:
/// this cell carries no O.
fn joint_cell_j16_capture_error_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::CaptureError));
    scene
        .owner
        .as_mut()
        .expect("detach owner")
        .failures
        .push(CAPTURE_ERROR.to_owned());
    assert_completed_error_kept(&mut scene, CAPTURE_ERROR);
}

/// J16×sink_failure (E): twins capture_error; the sink/capture
/// distinction lives in the lane I/O seams, not the detach seam.
fn joint_cell_j16_sink_failure_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::SinkFailure));
    scene
        .owner
        .as_mut()
        .expect("detach owner")
        .failures
        .push(SINK_FAILURE.to_owned());
    assert_completed_error_kept(&mut scene, SINK_FAILURE);
}

/// J16×held_install (H): H (the held install reclaimed once with
/// RunStopped) is driver-owned; the reclaim issues no detach call, so
/// the native cell proves the completed detach and minted completion
/// undisturbed.
fn joint_cell_j16_held_install_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::HeldInstall));
    let before = snapshot_completion(&scene);
    assert_completed_detach_preserved(&mut scene);
    assert_completion_unchanged(&scene, &before);
}

/// J16×sigint2 (O): the second signal after the joined detach keeps
/// the completed owner and the minted completion; nothing is
/// unsettled, so no typed exit is needed.
fn joint_cell_j16_sigint2_body(mut scene: NativeScene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Sigint2));
    let before = snapshot_completion(&scene);
    assert_completed_detach_preserved(&mut scene);
    assert_completion_unchanged(&scene, &before);
}

// The 27 state×event cells plus the J14×promote alias.

joint_cell!(
    joint_cell_j14_stop,
    JointState::J14,
    JointEvent::Stop,
    joint_cell_j14_stop_body
);
joint_cell!(
    joint_cell_j14_deadline,
    JointState::J14,
    JointEvent::Deadline,
    joint_cell_j14_deadline_body
);
joint_cell!(
    joint_cell_j14_cancel,
    JointState::J14,
    JointEvent::Cancel,
    joint_cell_j14_cancel_body
);
joint_cell!(
    joint_cell_j14_promote,
    JointState::J14,
    JointEvent::Promote,
    joint_cell_j14_promote_body
);
joint_cell!(
    joint_cell_j14_replace_foreign,
    JointState::J14,
    JointEvent::ReplaceForeign,
    joint_cell_j14_replace_foreign_body
);
joint_cell!(
    joint_cell_j14_capture_error,
    JointState::J14,
    JointEvent::CaptureError,
    joint_cell_j14_capture_error_body
);
joint_cell!(
    joint_cell_j14_sink_failure,
    JointState::J14,
    JointEvent::SinkFailure,
    joint_cell_j14_sink_failure_body
);
joint_cell!(
    joint_cell_j14_held_install,
    JointState::J14,
    JointEvent::HeldInstall,
    joint_cell_j14_held_install_body
);
joint_cell!(
    joint_cell_j14_sigint2,
    JointState::J14,
    JointEvent::Sigint2,
    joint_cell_j14_sigint2_body
);
joint_cell!(
    joint_cell_j15_stop,
    JointState::J15,
    JointEvent::Stop,
    joint_cell_j15_stop_body
);
joint_cell!(
    joint_cell_j15_deadline,
    JointState::J15,
    JointEvent::Deadline,
    joint_cell_j15_deadline_body
);
joint_cell!(
    joint_cell_j15_cancel,
    JointState::J15,
    JointEvent::Cancel,
    joint_cell_j15_cancel_body
);
joint_cell!(
    joint_cell_j15_promote,
    JointState::J15,
    JointEvent::Promote,
    joint_cell_j15_promote_body
);
joint_cell!(
    joint_cell_j15_replace_foreign,
    JointState::J15,
    JointEvent::ReplaceForeign,
    joint_cell_j15_replace_foreign_body
);
joint_cell!(
    joint_cell_j15_capture_error,
    JointState::J15,
    JointEvent::CaptureError,
    joint_cell_j15_capture_error_body
);
joint_cell!(
    joint_cell_j15_sink_failure,
    JointState::J15,
    JointEvent::SinkFailure,
    joint_cell_j15_sink_failure_body
);
joint_cell!(
    joint_cell_j15_held_install,
    JointState::J15,
    JointEvent::HeldInstall,
    joint_cell_j15_held_install_body
);
joint_cell!(
    joint_cell_j15_sigint2,
    JointState::J15,
    JointEvent::Sigint2,
    joint_cell_j15_sigint2_body
);
joint_cell!(
    joint_cell_j16_stop,
    JointState::J16,
    JointEvent::Stop,
    joint_cell_j16_stop_body
);
joint_cell!(
    joint_cell_j16_deadline,
    JointState::J16,
    JointEvent::Deadline,
    joint_cell_j16_deadline_body
);
joint_cell!(
    joint_cell_j16_cancel,
    JointState::J16,
    JointEvent::Cancel,
    joint_cell_j16_cancel_body
);
joint_cell!(
    joint_cell_j16_promote,
    JointState::J16,
    JointEvent::Promote,
    joint_cell_j16_promote_body
);
joint_cell!(
    joint_cell_j16_replace_foreign,
    JointState::J16,
    JointEvent::ReplaceForeign,
    joint_cell_j16_replace_foreign_body
);
joint_cell!(
    joint_cell_j16_capture_error,
    JointState::J16,
    JointEvent::CaptureError,
    joint_cell_j16_capture_error_body
);
joint_cell!(
    joint_cell_j16_sink_failure,
    JointState::J16,
    JointEvent::SinkFailure,
    joint_cell_j16_sink_failure_body
);
joint_cell!(
    joint_cell_j16_held_install,
    JointState::J16,
    JointEvent::HeldInstall,
    joint_cell_j16_held_install_body
);
joint_cell!(
    joint_cell_j16_sigint2,
    JointState::J16,
    JointEvent::Sigint2,
    joint_cell_j16_sigint2_body
);
joint_cell!(
    joint_pending_detach_retains_owner_then_promotes_b,
    JointState::J14,
    JointEvent::Promote,
    joint_cell_j14_promote_body
);
