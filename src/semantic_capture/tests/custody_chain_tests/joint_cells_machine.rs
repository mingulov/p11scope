//! SPDX-License-Identifier: GPL-3.0-or-later
//! Machine-home joint cells (§8.7): J0–J8, J10 × {stop, deadline,
//! capture_error, sink_failure}. Each cell builds its state through
//! `scene_for`, applies its event, and proves the table's codes: R
//! (the same phase/raw resumes to Q, Finish once), O (owners kept),
//! E (the first error kept), P (no replay, one attempt), G (terminal
//! I/O exactly once). N is Finish published exactly once; the detach
//! suffix is the J14×stop Native cell.

use super::*;
use crate::discovery::engine::inventory_coordinator::JointCommitProgress;

macro_rules! joint_cell {
    ($name:ident, $state:expr, $event:expr, $body:expr) => {
        #[test]
        fn $name() {
            $body(scene_for($state), $event)
        }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CellState {
    J0,
    J1,
    J2,
    J3,
    J4,
    J5,
    J6,
    J7,
    J8,
    J10,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CellEvent {
    Stop,
    Deadline,
    CaptureError,
    SinkFailure,
}

fn phase_of(scene: &MachineScene) -> &'static str {
    scene.machine.diagnostic_snapshot_for_test().0
}

/// Step the running machine until one of the wanted phases holds.
fn reach_any(scene: &mut MachineScene, wants: &[&str]) -> &'static str {
    for _ in 0..512 {
        let phase = phase_of(scene);
        if wants.contains(&phase) {
            return phase;
        }
        scene
            .service(1)
            .expect("setup service must succeed before the event");
    }
    panic!(
        "setup never reached {wants:?}; stuck at {}",
        phase_of(scene)
    );
}

/// A primed scene: sealed history published, machine Idle.
fn primed_scene(providers: usize) -> MachineScene {
    let mut scene = MachineScene::new(providers);
    scene.prime(providers);
    assert_eq!(phase_of(&scene), "Idle");
    scene
}

fn scene_for(state: CellState) -> MachineScene {
    match state {
        CellState::J0 => primed_scene(1),
        CellState::J1 => running_scene(&["Collecting"]),
        CellState::J2 => {
            // No prime: priming mints a drain grant, and J2 needs
            // grant == None (Binding precedes the first grant mint).
            let mut scene = MachineScene::new(1);
            scene
                .scene
                .push(std::process::id(), 0, "C_CreateObject", 100);
            scene.machine.begin_commit(true).unwrap();
            reach_any(&mut scene, &["Binding", "BindingKeys"]);
            assert!(
                scene.machine.retained_drain_grant_for_test().is_none(),
                "J2 needs grant == None"
            );
            scene
        }
        CellState::J3 => running_scene(&["AwaitH0"]),
        CellState::J4 => {
            // PendingQReport is entered only through the standalone
            // pending-Q entry: a pending-H0 fixture at AwaitH0, its
            // own Q observed, resolved with one credit (no merge
            // budget left, so the report stays held). The cell's
            // stop observes its own Q.
            let (mut scene, observer, _foreign) = pending_h0_finish_fixture(false);
            let q = observe_pending_finish_q(&scene, &observer);
            scene
                .resolve_pending_q(&q, observer.discovery_domain(), 1)
                .expect("single-credit resolve holds the pending report");
            assert_eq!(phase_of(&scene), "PendingQReport");
            scene
        }
        CellState::J5 => {
            running_scene(&["Preparing", "PreparationAttempted", "PreparingAdmissions"])
        }
        CellState::J6 => running_scene(&[
            "Ingesting",
            "StagingNegative",
            "Claiming",
            "InstallingClosure",
            "Births",
        ]),
        CellState::J7 => {
            let mut scene = primed_scene(2);
            scene
                .scene
                .push(std::process::id(), 0, "C_CreateObject", 100);
            scene
                .scene
                .push(std::process::id(), 1, "C_CreateObject", 101);
            scene.machine.begin_commit(true).unwrap();
            // Past the seal start: Staging precedes it. One quantum
            // covers both providers' calls (the drain is empty on
            // arrival), so the seal spans the second domain.
            reach_any(&mut scene, &["Auditing", "Negative", "Audited"]);
            assert_eq!(
                scene.scene.drain.source_mut().remaining(),
                0,
                "both calls are collected into the sealed quantum"
            );
            scene
        }
        CellState::J8 => begun_finish_ready_scene(Vec::new()),
        CellState::J10 => {
            let mut scene = primed_scene(1);
            scene
                .scene
                .push(std::process::id(), 0, "C_CreateObject", 100);
            scene.machine.begin_commit(true).unwrap();
            scene.enable_finish_fixture(Vec::new());
            scene
                .scene
                .real
                .scene
                .coordinator
                .seed_collected_finish_work_for_test(crate::process::ProcessViewId(4242));
            scene.begin_finish().expect("setup begins the finish");
            // Two single-credit polls: Q observed, then one engine
            // credit. Outstanding engine work, no verdict yet.
            assert!(matches!(
                scene.poll_finish(1),
                Ok(JointCommitProgress::Pending)
            ));
            assert!(matches!(
                scene.poll_finish(1),
                Ok(JointCommitProgress::Pending)
            ));
            scene
        }
    }
}

/// A primed scene with one fresh call, stepped to a running phase.
fn running_scene(wants: &[&str]) -> MachineScene {
    let mut scene = primed_scene(1);
    scene
        .scene
        .push(std::process::id(), 0, "C_CreateObject", 100);
    scene.machine.begin_commit(true).unwrap();
    reach_any(&mut scene, wants);
    scene
}

/// The retained raw's identity, when the machine holds one. The
/// accessor goes blind past BindingKeys (Claiming and later return
/// None), so identity chains cover the visible prefix only.
fn raw_identity_of(
    scene: &MachineScene,
) -> Option<crate::semantics_objects::journal::joint_driver::RawQuantumIdentity> {
    scene
        .machine
        .retained_raw_for_test()
        .map(|raw| raw.h0_identity())
}

/// The registry revision published so far.
fn revision_of(scene: &MachineScene) -> u64 {
    scene
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .published_revision()
}

/// Poll Finish with an expired budget: the deadline yields Pending
/// without progress of any kind.
fn poll_finish_expired(scene: &mut MachineScene) -> Result<JointCommitProgress, SemanticRefusal> {
    let mut budget = crate::inventory_semantics::JointWorkBudget {
        remaining_actions: 1024,
        deadline: Instant::now() - Duration::from_secs(1),
    };
    let MachineScene {
        scene,
        machine,
        native,
        finish,
    } = scene;
    let mut io = HeldMachineIo {
        drain: &mut scene.drain,
        h0: &scene.real.h0,
        producers: &scene.producers,
        attached: scene.attached.as_ref().unwrap(),
        native,
        finish: finish.as_mut(),
    };
    machine.poll_finish_with_io(
        &mut scene.real.lane,
        &mut scene.real.scene.coordinator,
        &mut io,
        &mut budget,
    )
}

/// What one stepped Finish drain observed.
struct DrainTrace {
    /// The single publication's receipt.
    receipt: crate::discovery::engine::inventory_coordinator::BatchReceipt,
    /// Total Published outcomes across the stepped drain and the
    /// three full-budget confirmation polls.
    published: usize,
    /// The phase right after the event, before the drain.
    first_phase: &'static str,
    /// Idle strictly after a non-Idle phase and before the
    /// publication: the retained demand completed ordinarily.
    saw_mid_idle: bool,
    /// The raw held at the first FinishStopReady observation.
    fsready_raw: Option<crate::semantics_objects::journal::joint_driver::RawQuantumIdentity>,
    /// The pre-event raw was observed after the event (not dropped).
    pre_raw_seen: bool,
    /// Every observed identity after the mid-Idle is the same single
    /// terminal quantum (and at least one was observed).
    post_idle_single: bool,
    /// Every observed identity is the same single quantum (states
    /// without a retained demand).
    all_single: bool,
}

/// Step single-credit polls to the first publication, recording the
/// walk, then confirm with three full-budget polls that never
/// publish again. Every stepped poll must succeed.
fn drain_stepped(
    scene: &mut MachineScene,
    pre_raw: Option<crate::semantics_objects::journal::joint_driver::RawQuantumIdentity>,
    event_fsready: Option<crate::semantics_objects::journal::joint_driver::RawQuantumIdentity>,
) -> DrainTrace {
    let first_phase = phase_of(scene);
    let mut identities: Vec<(
        usize,
        crate::semantics_objects::journal::joint_driver::RawQuantumIdentity,
    )> = Vec::new();
    let mut saw_non_idle = false;
    let mut mid_idle_at = None;
    let mut fsready_raw = event_fsready;
    let mut pre_raw_seen = false;
    let mut receipt = None;
    for i in 0..128 {
        let outcome = scene
            .poll_finish(1)
            .expect("finish polls must succeed until publish");
        if let JointCommitProgress::Published(first) = outcome {
            receipt = Some(first);
            break;
        }
        let phase = phase_of(scene);
        if phase != "Idle" {
            saw_non_idle = true;
        } else if saw_non_idle && mid_idle_at.is_none() {
            mid_idle_at = Some(i);
        }
        if let Some(raw) = raw_identity_of(scene) {
            if Some(raw) == pre_raw {
                pre_raw_seen = true;
            }
            identities.push((i, raw));
        }
        if phase == "FinishStopReady" && fsready_raw.is_none() {
            fsready_raw = raw_identity_of(scene);
        }
    }
    let receipt = receipt.expect("the finish publishes (N)");
    let post_idle = match mid_idle_at {
        Some(at) => identities
            .iter()
            .filter(|(i, _)| *i > at)
            .map(|(_, raw)| *raw)
            .collect::<Vec<_>>(),
        None => Vec::new(),
    };
    let post_idle_single =
        !post_idle.is_empty() && post_idle.iter().all(|raw| *raw == post_idle[0]);
    let all_single =
        !identities.is_empty() && identities.iter().all(|(_, raw)| *raw == identities[0].1);
    let mut published = 1;
    for _ in 0..3 {
        if matches!(
            scene.poll_finish(1024),
            Ok(JointCommitProgress::Published(_))
        ) {
            published += 1;
        }
    }
    DrainTrace {
        receipt,
        published,
        first_phase,
        saw_mid_idle: mid_idle_at.is_some(),
        fsready_raw,
        pre_raw_seen,
        post_idle_single,
        all_single,
    }
}

/// Exactly-once terminal I/O: one stop request, one Q observation,
/// one H0 stop (G).
fn assert_gate_quiet_once(scene: &MachineScene) {
    let finish = scene.finish.as_ref().expect("finish fixture enabled");
    assert_eq!(finish.stop_requests, 1, "one stop request (G)");
    assert_eq!(finish.q_observations, 1, "one Q observation (G)");
    assert_eq!(finish.stops, 1, "one H0 stop (G)");
}

/// Recover the cell state from the scene's phase. The J-states are
/// disjoint phase sets by definition, so the mapping is exact.
fn state_of(scene: &MachineScene) -> CellState {
    match phase_of(scene) {
        "Idle" if !scene.machine.finish_begun() => CellState::J0,
        "Collecting" => CellState::J1,
        "Binding" | "BindingKeys" => CellState::J2,
        "AwaitH0" => CellState::J3,
        "PendingQReport" => CellState::J4,
        "Preparing" | "PreparationAttempted" | "PreparingAdmissions" => CellState::J5,
        "Ingesting" | "StagingNegative" | "Claiming" | "InstallingClosure" | "Births" => {
            CellState::J6
        }
        "Staging" | "Auditing" | "Negative" | "Audited" => CellState::J7,
        "FinishStopReady" | "FinishStopReport" => CellState::J8,
        "Idle" => CellState::J10,
        other => panic!("no cell state holds phase {other}"),
    }
}

/// Assert the shared resume/ownership/publication shape: the
/// retained demand (when any) completes ordinarily mid-drain, the
/// single terminal quantum reaches the stop, and the receipt
/// accounts exactly the expected publications.
fn assert_resume_shape(
    scene: &MachineScene,
    trace: &DrainTrace,
    pre_raw: Option<crate::semantics_objects::journal::joint_driver::RawQuantumIdentity>,
    pre_rev: u64,
) {
    assert_eq!(trace.published, 1, "the finish publishes exactly once (N)");
    let at_stop = scene
        .finish
        .as_ref()
        .unwrap()
        .at_stop
        .as_ref()
        .expect("H0 stopped at Q");
    assert!(
        trace.fsready_raw == Some(at_stop.raw),
        "the stop observes the terminal quantum (R)"
    );
    if trace.saw_mid_idle {
        // A retained demand completed ordinarily first: two
        // publications, no more.
        assert_eq!(
            trace.receipt.registry_published,
            pre_rev + 2,
            "the demand and the finish publish exactly once each (N)"
        );
        assert!(
            trace.post_idle_single,
            "one terminal quantum follows the demand (R)"
        );
    } else {
        assert_eq!(
            trace.receipt.registry_published,
            pre_rev + 1,
            "the finish publishes exactly once (N)"
        );
        assert!(
            trace.all_single,
            "one quantum end to end, never recollected (R)"
        );
    }
    if pre_raw.is_some() {
        assert!(
            trace.pre_raw_seen,
            "the retained raw resumes; no fresh H0 tick (R)"
        );
    }
    assert_gate_quiet_once(scene);
}

fn stop_body(mut scene: MachineScene, event: CellEvent) {
    assert_eq!(event, CellEvent::Stop);
    let begun = scene.machine.finish_begun();
    let pre_phase = phase_of(&scene);
    let pre_raw = raw_identity_of(&scene);
    let pre_rev = revision_of(&scene);
    if !begun {
        scene.enable_finish_fixture(Vec::new());
    }
    apply_begin(&mut scene, pre_phase, pre_raw);
    let event_fsready = if pre_phase == "FinishStopReady" {
        pre_raw
    } else {
        None
    };
    let trace = drain_stepped(&mut scene, pre_raw, event_fsready);
    assert_eq!(trace.first_phase, pre_phase, "the drain resumes (R)");
    assert_resume_shape(&scene, &trace, pre_raw, pre_rev);
}

/// Apply the begin half of the event: unbegun finishes begin
/// (phase and raw preserved); begun finishes refuse a second begin
/// (nothing moves). The fixture must already be enabled.
fn apply_begin(
    scene: &mut MachineScene,
    pre_phase: &'static str,
    pre_raw: Option<crate::semantics_objects::journal::joint_driver::RawQuantumIdentity>,
) {
    if scene.machine.finish_begun() {
        assert_eq!(
            scene.begin_finish(),
            Err(SemanticRefusal::Unavailable),
            "a begun finish refuses a second begin"
        );
        assert_eq!(
            phase_of(scene),
            pre_phase,
            "a refused begin moves nothing (R)"
        );
    } else {
        scene.begin_finish().expect("stop begins the finish");
        assert_eq!(
            phase_of(scene),
            pre_phase,
            "begin preserves the retained phase (R)"
        );
        assert!(
            raw_identity_of(scene) == pre_raw,
            "begin keeps the retained raw (O)"
        );
    }
}

fn tails_of(scene: &MachineScene) -> (u64, u64) {
    scene
        .scene
        .real
        .scene
        .coordinator
        .reference_engine_tail_stats()
}

/// A begun FinishStopReady setup with the given discovery staged.
/// J8 cells share the empty-discovery setup; the capture cell needs
/// its fault pre-staged (Q precedes the begun state, so an
/// event-time fault would land post-Q and stay invisible).
fn begun_finish_ready_scene(discovery: Vec<Vec<u8>>) -> MachineScene {
    let mut scene = primed_scene(1);
    scene.enable_finish_fixture(discovery);
    scene.begin_finish().expect("setup begins the finish");
    scene.reach_finish_stop_ready();
    scene
}

fn deadline_body(mut scene: MachineScene, event: CellEvent) {
    assert_eq!(event, CellEvent::Deadline);
    let begun = scene.machine.finish_begun();
    let pre_phase = phase_of(&scene);
    let pre_raw = raw_identity_of(&scene);
    let pre_rev = revision_of(&scene);
    if !begun {
        scene.enable_finish_fixture(Vec::new());
    }
    apply_begin(&mut scene, pre_phase, pre_raw);
    // The expired budget yields without progress of any kind: the
    // machine honors the deadline. The Deadline cause itself is
    // driver-recorded (T11n twins deadline with stop the same way).
    let finish = scene.finish.as_ref().unwrap();
    let (pre_q, pre_stops) = (finish.q_observations, finish.stops);
    assert!(
        matches!(
            poll_finish_expired(&mut scene),
            Ok(JointCommitProgress::Pending)
        ),
        "an expired deadline yields Pending"
    );
    assert_eq!(phase_of(&scene), pre_phase, "no phase moves on expiry");
    assert!(raw_identity_of(&scene) == pre_raw, "no raw moves on expiry");
    let finish = scene.finish.as_ref().unwrap();
    assert_eq!(finish.q_observations, pre_q, "no Q observation on expiry");
    assert_eq!(finish.stops, pre_stops, "no H0 stop on expiry");
    // The same finish then resumes to its single publication.
    let event_fsready = if pre_phase == "FinishStopReady" {
        pre_raw
    } else {
        None
    };
    let trace = drain_stepped(&mut scene, pre_raw, event_fsready);
    assert_resume_shape(&scene, &trace, pre_raw, pre_rev);
    // Once: even after publication a second begin is refused and
    // moves no terminal I/O.
    assert_eq!(
        scene.begin_finish(),
        Err(SemanticRefusal::Unavailable),
        "the begin happens once"
    );
    assert_gate_quiet_once(&scene);
}

fn capture_error_body(mut scene: MachineScene, event: CellEvent) {
    assert_eq!(event, CellEvent::CaptureError);
    // Malformed discovery before Q: skipped and counted, never
    // dispatched. Undecodable by construction (asserted), so the
    // engine records it without dispatching it.
    let fault = vec![0x7f; 11];
    assert!(
        crate::events::decode_discovery(&fault).is_none(),
        "the fault bytes never decode"
    );
    if scene.machine.finish_begun() {
        scene = begun_finish_ready_scene(vec![fault]);
    } else {
        scene.enable_finish_fixture(vec![fault]);
    }
    let pre_phase = phase_of(&scene);
    let pre_raw = raw_identity_of(&scene);
    let pre_rev = revision_of(&scene);
    apply_begin(&mut scene, pre_phase, pre_raw);
    let state = state_of(&scene);
    let event_fsready = if pre_phase == "FinishStopReady" {
        pre_raw
    } else {
        None
    };
    let trace = drain_stepped(&mut scene, pre_raw, event_fsready);
    assert_eq!(trace.first_phase, pre_phase, "the drain resumes (R)");
    assert_resume_shape(&scene, &trace, pre_raw, pre_rev);
    // E: the malformed record was recorded exactly once and kept.
    // The twin scene (the same state, empty discovery) publishes
    // with engine facts exactly one lower; the twin's own shape
    // proves the control took the same path.
    let mut twin = scene_for(state);
    let twin_pre_raw = raw_identity_of(&twin);
    let twin_pre_rev = revision_of(&twin);
    if !twin.machine.finish_begun() {
        twin.enable_finish_fixture(Vec::new());
    }
    let twin_pre_phase = phase_of(&twin);
    apply_begin(&mut twin, twin_pre_phase, twin_pre_raw);
    let twin_event_fsready = if twin_pre_phase == "FinishStopReady" {
        twin_pre_raw
    } else {
        None
    };
    let twin_trace = drain_stepped(&mut twin, twin_pre_raw, twin_event_fsready);
    assert_resume_shape(&twin, &twin_trace, twin_pre_raw, twin_pre_rev);
    assert_eq!(
        trace.receipt.engine_facts,
        twin_trace.receipt.engine_facts + 1,
        "the malformed record is recorded once and kept (E)"
    );
}

fn sink_failure_body(mut scene: MachineScene, event: CellEvent) {
    assert_eq!(event, CellEvent::SinkFailure);
    let begun = scene.machine.finish_begun();
    if !begun {
        scene.enable_finish_fixture(Vec::new());
        scene.native.fail_after_preparation = true;
    } else {
        // Preparation already ran: fail the commit-side sink
        // instead. One-shot: consumed on the first attempt, so a
        // retry would succeed and publish.
        scene
            .machine
            .inject_finish_site_for_test(crate::inventory_semantics::FinishSite::CompleteFinish);
    }
    let pre_prep = scene.native.preparations.len();
    let pre_tails = tails_of(&scene);
    let pre_phase = phase_of(&scene);
    let pre_raw = raw_identity_of(&scene);
    apply_begin(&mut scene, pre_phase, pre_raw);
    let mut errors = Vec::new();
    let mut published = 0;
    let mut tails_at_first_error = None;
    for _ in 0..64 {
        match scene.poll_finish(64) {
            Ok(JointCommitProgress::Published(_)) => published += 1,
            Ok(JointCommitProgress::Pending) => {}
            Err(reason) => {
                if tails_at_first_error.is_none() {
                    tails_at_first_error = Some(tails_of(&scene));
                }
                errors.push(reason);
            }
        }
    }
    assert_eq!(published, 0, "a failed sink never publishes");
    assert!(!errors.is_empty(), "the sink error surfaces (E)");
    assert!(
        errors.iter().all(|reason| *reason == errors[0]),
        "the first error is kept (E)"
    );
    assert!(
        scene.machine.finish_disposition_required(),
        "the sink error latches (E)"
    );
    if !begun {
        assert_eq!(
            scene.native.preparations.len(),
            pre_prep + 1,
            "one attempt, no replay (P)"
        );
    } else {
        assert_eq!(
            scene.native.preparations.len(),
            pre_prep,
            "no second preparation (P)"
        );
    }
    let (before_attempts, before_failed) = pre_tails;
    let (first_attempts, first_failed) = tails_at_first_error.expect("an error surfaced");
    if !begun {
        // The preparation's physical tail ran once, then the
        // handoff failed.
        assert_eq!(
            first_attempts + first_failed - before_attempts - before_failed,
            1,
            "one real attempt before the failure (P)"
        );
    } else {
        // The commit runs no tail; the one-shot complete fails
        // before any second attempt could start.
        assert_eq!(
            (first_attempts, first_failed),
            (before_attempts, before_failed),
            "no tail attempt before the failure (P)"
        );
    }
    assert_eq!(
        tails_of(&scene),
        tails_at_first_error.unwrap(),
        "no second attempt after the first (P)"
    );
    // Finite: the bounded poll loop above returned.
}

fn charged_of(scene: &MachineScene) -> usize {
    scene
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot()
        .charged_bytes
}

/// Pin the J10 window: a begun finish with outstanding engine
/// work and no verdict yet.
fn assert_j10_window(scene: &MachineScene) {
    assert!(
        scene.machine.finish_begun(),
        "J10 is mid-finish (begun, unpublished)"
    );
    assert!(
        !scene.scene.real.lane.is_finished(),
        "J10 has no verdict yet"
    );
    let coordinator = &scene.scene.real.scene.coordinator;
    assert!(
        coordinator
            .reference_collected_finish_discovery_backlog(0)
            .1,
        "J10 has outstanding engine work (backlog)"
    );
    assert!(
        coordinator.engine_collected_finish_calls() >= 1,
        "J10 engaged the engine"
    );
    assert_eq!(
        scene.machine.diagnostic_snapshot_for_test().1,
        "Requested",
        "J10 still owes its demand"
    );
}

fn j10_stop_body(scene: MachineScene, event: CellEvent) {
    assert_eq!(event, CellEvent::Stop);
    assert_j10_window(&scene);
    stop_body(scene, CellEvent::Stop);
}

fn j10_deadline_body(scene: MachineScene, event: CellEvent) {
    assert_eq!(event, CellEvent::Deadline);
    assert_j10_window(&scene);
    deadline_body(scene, CellEvent::Deadline);
}

fn j10_error_body(mut scene: MachineScene, event: CellEvent) {
    assert_j10_window(&scene);
    match event {
        // Capture-side, always hit past Q-observation, latching.
        CellEvent::CaptureError => scene
            .machine
            .inject_finish_site_for_test(crate::inventory_semantics::FinishSite::DiscoveryDomain),
        // Commit-side: preparation has not run yet at J10 entry.
        CellEvent::SinkFailure => scene.native.fail_after_preparation = true,
        _ => panic!("J10 error cells take capture_error or sink_failure"),
    }
    assert_eq!(
        scene.begin_finish(),
        Err(SemanticRefusal::Unavailable),
        "a begun finish refuses a second begin"
    );
    let mut errors = Vec::new();
    let mut published = 0;
    let mut first_phase = None;
    let mut first_charged = None;
    let mut phases_stable = true;
    for _ in 0..64 {
        match scene.poll_finish(64) {
            Ok(JointCommitProgress::Published(_)) => published += 1,
            Ok(JointCommitProgress::Pending) => {}
            Err(reason) => {
                match first_phase {
                    None => {
                        first_phase = Some(phase_of(&scene));
                        first_charged = Some(charged_of(&scene));
                    }
                    Some(phase) => {
                        phases_stable &= phase_of(&scene) == phase;
                    }
                }
                errors.push(reason);
            }
        }
    }
    assert_eq!(published, 0, "no publication past the error");
    assert!(!errors.is_empty(), "the error surfaces (E)");
    assert!(
        errors.iter().all(|reason| *reason == errors[0]),
        "the first error is kept (E)"
    );
    assert!(
        scene.machine.finish_disposition_required(),
        "the error latches (E)"
    );
    assert!(
        phases_stable,
        "the latched phase is retained, never reset (O)"
    );
    assert_eq!(
        charged_of(&scene),
        first_charged.unwrap(),
        "leases are kept: nothing freed, nothing leaked (O)"
    );
    assert!(
        !scene.scene.real.lane.is_finished(),
        "nothing handed off (O)"
    );
}

joint_cell!(
    joint_cell_j0_stop,
    CellState::J0,
    CellEvent::Stop,
    stop_body
);
joint_cell!(
    joint_cell_j0_deadline,
    CellState::J0,
    CellEvent::Deadline,
    deadline_body
);
joint_cell!(
    joint_cell_j0_capture_error,
    CellState::J0,
    CellEvent::CaptureError,
    capture_error_body
);
joint_cell!(
    joint_cell_j0_sink_failure,
    CellState::J0,
    CellEvent::SinkFailure,
    sink_failure_body
);
joint_cell!(
    joint_cell_j1_stop,
    CellState::J1,
    CellEvent::Stop,
    stop_body
);
joint_cell!(
    joint_cell_j1_deadline,
    CellState::J1,
    CellEvent::Deadline,
    deadline_body
);
joint_cell!(
    joint_cell_j1_capture_error,
    CellState::J1,
    CellEvent::CaptureError,
    capture_error_body
);
joint_cell!(
    joint_cell_j1_sink_failure,
    CellState::J1,
    CellEvent::SinkFailure,
    sink_failure_body
);
joint_cell!(
    joint_cell_j2_stop,
    CellState::J2,
    CellEvent::Stop,
    stop_body
);
joint_cell!(
    joint_cell_j2_deadline,
    CellState::J2,
    CellEvent::Deadline,
    deadline_body
);
joint_cell!(
    joint_cell_j2_capture_error,
    CellState::J2,
    CellEvent::CaptureError,
    capture_error_body
);
joint_cell!(
    joint_cell_j2_sink_failure,
    CellState::J2,
    CellEvent::SinkFailure,
    sink_failure_body
);
joint_cell!(
    joint_cell_j3_stop,
    CellState::J3,
    CellEvent::Stop,
    stop_body
);
joint_cell!(
    joint_cell_j3_deadline,
    CellState::J3,
    CellEvent::Deadline,
    deadline_body
);
joint_cell!(
    joint_cell_j3_capture_error,
    CellState::J3,
    CellEvent::CaptureError,
    capture_error_body
);
joint_cell!(
    joint_cell_j3_sink_failure,
    CellState::J3,
    CellEvent::SinkFailure,
    sink_failure_body
);
joint_cell!(
    joint_cell_j4_stop,
    CellState::J4,
    CellEvent::Stop,
    stop_body
);
joint_cell!(
    joint_cell_j4_deadline,
    CellState::J4,
    CellEvent::Deadline,
    deadline_body
);
joint_cell!(
    joint_cell_j4_capture_error,
    CellState::J4,
    CellEvent::CaptureError,
    capture_error_body
);
joint_cell!(
    joint_cell_j4_sink_failure,
    CellState::J4,
    CellEvent::SinkFailure,
    sink_failure_body
);
joint_cell!(
    joint_cell_j5_stop,
    CellState::J5,
    CellEvent::Stop,
    stop_body
);
joint_cell!(
    joint_cell_j5_deadline,
    CellState::J5,
    CellEvent::Deadline,
    deadline_body
);
joint_cell!(
    joint_cell_j5_capture_error,
    CellState::J5,
    CellEvent::CaptureError,
    capture_error_body
);
joint_cell!(
    joint_cell_j5_sink_failure,
    CellState::J5,
    CellEvent::SinkFailure,
    sink_failure_body
);
joint_cell!(
    joint_cell_j6_stop,
    CellState::J6,
    CellEvent::Stop,
    stop_body
);
joint_cell!(
    joint_cell_j6_deadline,
    CellState::J6,
    CellEvent::Deadline,
    deadline_body
);
joint_cell!(
    joint_cell_j6_capture_error,
    CellState::J6,
    CellEvent::CaptureError,
    capture_error_body
);
joint_cell!(
    joint_cell_j6_sink_failure,
    CellState::J6,
    CellEvent::SinkFailure,
    sink_failure_body
);
joint_cell!(
    joint_cell_j7_stop,
    CellState::J7,
    CellEvent::Stop,
    stop_body
);
joint_cell!(
    joint_cell_j7_deadline,
    CellState::J7,
    CellEvent::Deadline,
    deadline_body
);
joint_cell!(
    joint_cell_j7_capture_error,
    CellState::J7,
    CellEvent::CaptureError,
    capture_error_body
);
joint_cell!(
    joint_cell_j7_sink_failure,
    CellState::J7,
    CellEvent::SinkFailure,
    sink_failure_body
);
joint_cell!(
    joint_cell_j8_stop,
    CellState::J8,
    CellEvent::Stop,
    stop_body
);
joint_cell!(
    joint_cell_j8_deadline,
    CellState::J8,
    CellEvent::Deadline,
    deadline_body
);
joint_cell!(
    joint_cell_j8_capture_error,
    CellState::J8,
    CellEvent::CaptureError,
    capture_error_body
);
joint_cell!(
    joint_cell_j8_sink_failure,
    CellState::J8,
    CellEvent::SinkFailure,
    sink_failure_body
);
joint_cell!(
    joint_cell_j10_stop,
    CellState::J10,
    CellEvent::Stop,
    j10_stop_body
);
joint_cell!(
    joint_cell_j10_deadline,
    CellState::J10,
    CellEvent::Deadline,
    j10_deadline_body
);
joint_cell!(
    joint_cell_j10_capture_error,
    CellState::J10,
    CellEvent::CaptureError,
    j10_error_body
);
joint_cell!(
    joint_cell_j10_sink_failure,
    CellState::J10,
    CellEvent::SinkFailure,
    j10_error_body
);

/// Control: the R16 shape WITH journal rows present stages and
/// publishes. Two providers, many modeled calls in one quantum, every
/// birth refused (the marker is unwired, so no Joint feed exists), zero
/// Joint feeds. The H8-absent twin below is the live case.
#[test]
fn joint_machine_h8_present_s1only_batch_publishes() {
    let mut scene = MachineScene::new(2);
    scene.native.fail_births = true;
    let pid = std::process::id();
    let mut seq = 1u64;
    for _ in 0..2 {
        for file in [0u32, 1] {
            for name in [
                "C_CreateObject",
                "C_SignInit",
                "C_SignUpdate",
                "C_SignFinal",
            ] {
                scene.scene.push(pid, file, name, seq);
                seq += 1;
            }
        }
    }
    scene.machine.begin_commit(true).unwrap();
    scene.published_labeled("h8-present-s1only", None);
    assert_eq!(
        scene.machine.staging_detail_for_test(),
        None,
        "successful Staging retains no refusal"
    );
    assert!(
        scene.machine.retained_drain_grant_for_test().is_some(),
        "a grant exists: the machine took the ingest path, like live"
    );
    assert!(
        !scene.native.birth_outcomes.is_empty()
            && scene
                .native
                .birth_outcomes
                .iter()
                .all(|(_, result)| result.is_err()),
        "every birth refused, like live: {:?}",
        scene.native.birth_outcomes
    );
    assert_eq!(
        scene.scene.real.scene.coordinator.registry().joint_feeds(),
        0,
        "zero Joint feeds, like live"
    );
    let api: u64 = scene
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .filter_map(|record| record.api_returns)
        .sum();
    assert_eq!(api, 16, "all sixteen S1-only calls stage their S1 facts");
}

/// The live R16 case: ordinary EVENTS rows with NO journal rows (the
/// object-journal BPF is compiled into no flavor, so live emits one
/// CALL row per call and opens no H8 entry). Every birth refused, zero
/// Joint feeds. The transaction must still publish its S1 facts.
#[test]
fn joint_machine_h8_absent_s1only_batch_publishes() {
    use p11scope_ebpf_common::object_journal::JournalRecord;
    let mut scene = MachineScene::new(1);
    scene.native.fail_births = true;
    let pid = std::process::id();
    let descriptors = p11scope_ebpf_common::object_wire::publish_object_descriptors();
    for seq in 1..=8u64 {
        let (_, end) = scene.scene.encoded(pid, 0, "C_SignInit", seq);
        let payload =
            match p11scope_ebpf_common::object_journal::decode_journal_record(&end, &descriptors) {
                Some(JournalRecord::End(end)) => end.payload_base(),
                other => panic!("the shaped END decodes: {other:?}"),
            };
        // The bare CALL row only: no journal BEGIN/END enters the drain,
        // so ingest opens no H8 entry for these admissions.
        scene
            .scene
            .drain
            .source_mut()
            .push_record(crate::events::record_bytes(&payload));
    }
    scene.machine.begin_commit(true).unwrap();
    scene.published_labeled("h8-absent-s1only", None);
    assert_eq!(
        scene.machine.staging_detail_for_test(),
        None,
        "successful Staging retains no refusal"
    );
    assert!(
        scene.machine.retained_drain_grant_for_test().is_some(),
        "a grant exists: the machine took the ingest path, like live"
    );
    assert!(
        !scene.native.birth_outcomes.is_empty()
            && scene
                .native
                .birth_outcomes
                .iter()
                .all(|(_, result)| result.is_err()),
        "every birth refused, like live: {:?}",
        scene.native.birth_outcomes
    );
    assert_eq!(
        scene.scene.real.scene.coordinator.registry().joint_feeds(),
        0,
        "zero Joint feeds, like live"
    );
    let api: u64 = scene
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .filter_map(|record| record.api_returns)
        .sum();
    assert_eq!(api, 8, "all eight S1-only calls stage their S1 facts");
}

/// Staging names its refusal: with journal rows present but the H8
/// adapter stopped, the per-admission step refuses and the machine
/// retains the exact sub-exit for the drive line.
#[test]
fn joint_machine_staging_refusal_names_its_sub_exit() {
    use crate::inventory_semantics::{SemanticRefusal, StagingDetail};
    let mut scene = MachineScene::new(1);
    scene.native.fail_births = true;
    let pid = std::process::id();
    for seq in 1..=2u64 {
        scene.scene.push(pid, 0, "C_SignInit", seq);
    }
    scene.machine.begin_commit(true).unwrap();
    scene.reach_phase("Staging");
    assert_eq!(
        scene.machine.staging_detail_for_test(),
        None,
        "no diagnosis before the refusal"
    );
    {
        let (adapter, model) = scene
            .scene
            .real
            .scene
            .coordinator
            .joint_capture_mut()
            .parts();
        let _ = adapter.stop(model);
    }
    assert_eq!(
        scene.service(1024).unwrap_err(),
        SemanticRefusal::Unavailable
    );
    assert_eq!(phase_of(&scene), "Staging");
    let (_, stage, _, _) = scene
        .scene
        .real
        .scene
        .coordinator
        .prepared_staging_progress(&scene.scene.real.lane)
        .expect("the refused batch is still prepared");
    let detail = scene
        .machine
        .staging_detail_for_test()
        .expect("the Staging refusal is retained");
    assert_eq!(
        detail,
        StagingDetail::StageNext {
            reason: "Admission",
            stage,
        }
    );
    assert_eq!(detail.to_string(), format!("stage_next:Admission@{stage}"));
}

/// Push one bare CALL row (the live H8-absent shape: no journal
/// BEGIN/END enters the drain, so ingest opens no H8 entry).
fn push_bare_call(scene: &mut MachineScene, pid: u32, name: &str, seq: u64) {
    use p11scope_ebpf_common::object_journal::JournalRecord;
    let descriptors = p11scope_ebpf_common::object_wire::publish_object_descriptors();
    let (_, end) = scene.scene.encoded(pid, 0, name, seq);
    let payload =
        match p11scope_ebpf_common::object_journal::decode_journal_record(&end, &descriptors) {
            Some(JournalRecord::End(end)) => end.payload_base(),
            other => panic!("the shaped END decodes: {other:?}"),
        };
    scene
        .scene
        .drain
        .source_mut()
        .push_record(crate::events::record_bytes(&payload));
}

/// The live R16 cell-1 case: a published q1 (H8-absent S1-only batch,
/// every birth refused, zero Joint feeds) followed by an empty q2 with
/// Requested demand (the fixture is quiet, the cell still begins a
/// commit). The empty follow-up must publish (or refuse loudly), never
/// wedge in Audited/Bound with Pending forever.
#[test]
fn joint_machine_empty_followup_transaction_publishes() {
    let mut scene = MachineScene::new(1);
    scene.native.fail_births = true;
    let pid = std::process::id();
    for seq in 1..=8u64 {
        push_bare_call(&mut scene, pid, "C_SignInit", seq);
    }
    scene.machine.begin_commit(true).unwrap();
    scene.published_labeled("empty-followup-q1", None);
    let revision_q1 = scene.scene.real.scene.coordinator.registry().published_revision();
    let JointCommitProgress::Published(_) = scene.poll_commit(0).unwrap() else {
        panic!("q1 publishes exactly once");
    };
    assert_eq!(
        scene.scene.real.scene.coordinator.registry().published_revision(),
        revision_q1,
        "the poll takes the q1 receipt without a second publication"
    );
    assert_eq!(
        scene.scene.real.scene.coordinator.registry().joint_feeds(),
        0,
        "zero Joint feeds, like live"
    );
    // The live q2: nothing new in the drain, engine unchanged, but the
    // cell begins a commit anyway.
    assert_eq!(scene.scene.drain.source_mut().remaining(), 0);
    scene.machine.begin_commit(false).unwrap();
    scene.published_labeled("empty-followup-q2", None);
    assert_eq!(
        scene.scene.real.scene.coordinator.registry().published_revision(),
        revision_q1 + 1,
        "the empty follow-up publishes exactly one more revision"
    );
}

/// The live R16 cell-1 drive, faithfully: q1 publishes B's completed
/// calls plus A's SignInit while A's Sign is still held (no row for
/// it yet); the cell idles the machine three times (fresh polls, empty
/// drain); then A's END lands and the cell begins q2. q2 must collect
/// the landed END and publish exactly once more, never strand the row
/// and never wedge in Audited/Bound.
#[test]
fn joint_machine_followup_collects_row_landed_after_idle_poll() {
    use crate::inventory_semantics::JointServiceProgress;
    let mut scene = MachineScene::new(1);
    scene.native.fail_births = true;
    let pid = std::process::id();
    for seq in 1..=8u64 {
        push_bare_call(&mut scene, pid, "C_SignInit", seq);
    }
    push_bare_call(&mut scene, pid, "C_SignInit", 9);
    scene.machine.begin_commit(true).unwrap();
    scene.published_labeled("landed-after-idle-q1", None);
    let JointCommitProgress::Published(_) = scene.poll_commit(0).unwrap() else {
        panic!("q1 publishes exactly once");
    };
    let revision_q1 = scene.scene.real.scene.coordinator.registry().published_revision();
    assert_eq!(scene.scene.drain.source_mut().remaining(), 0);
    // The cell's three idle services: fresh polls against an empty
    // drain, publishing nothing.
    for _ in 0..3 {
        let progress = scene.service(1024).unwrap();
        assert_eq!(progress, JointServiceProgress::Pending);
    }
    assert_eq!(
        scene.scene.real.scene.coordinator.registry().published_revision(),
        revision_q1,
        "idle service publishes nothing"
    );
    assert_eq!(phase_of(&scene), "Collecting");
    // A's END lands after the last idle poll, then the cell begins q2.
    push_bare_call(&mut scene, pid, "C_SignFinal", 10);
    scene.machine.begin_commit(false).unwrap();
    let mut published = None;
    for _ in 0..600 {
        let progress = scene.service(1024).unwrap();
        if matches!(progress, JointServiceProgress::Published) {
            published = Some(());
            break;
        }
        if matches!(
            scene.poll_commit(1024).unwrap(),
            JointCommitProgress::Published(_)
        ) {
            published = Some(());
            break;
        }
    }
    assert!(
        published.is_some(),
        "q2 publishes within its bound; stuck at snapshot={:?} audit={:?}",
        scene.machine.diagnostic_snapshot_for_test(),
        scene.machine.diagnostic_audit_for_test(),
    );
    assert_eq!(
        scene.scene.drain.source_mut().remaining(),
        0,
        "q2 collects the row that landed before its begin"
    );
    assert_eq!(
        scene.scene.real.scene.coordinator.registry().published_revision(),
        revision_q1 + 1,
        "q2 publishes exactly one more revision"
    );
}
