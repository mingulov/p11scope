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
        live_discovery,
    } = scene;
    let mut io = HeldMachineIo {
        drain: &mut scene.drain,
        h0: &scene.real.h0,
        producers: &scene.producers,
        attached: scene.attached.as_ref().unwrap(),
        native,
        finish: finish.as_mut(),
        live_discovery: live_discovery.as_mut(),
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
    let mut staged = 0u64;
    for record in scene
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .instance_semantic_edges()
    {
        staged += 1;
        // Two observed `C_SignInit` calls start two operations and the
        // two `C_SignFinal` calls complete them; nothing is orphaned.
        // Exact counts: an invented start or completion would fail
        // here.
        assert_eq!(
            record.semantics.as_ref().map(|edge| edge.started()),
            Some(2),
            "the staged edge starts exactly its two observed calls"
        );
        assert_eq!(
            record.semantics.as_ref().map(|edge| edge.completed()),
            Some(2),
            "the staged edge completes exactly its two observed calls"
        );
        assert_eq!(
            record.semantics.as_ref().map(|edge| edge.orphans()),
            Some(0),
            "the staged edge stages no orphans"
        );
    }
    assert_eq!(staged, 2, "the batch stages one edge per file");
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
    let mut staged = 0u64;
    for record in scene
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .instance_semantic_edges()
    {
        staged += 1;
        // Eight observed `C_SignInit` calls start eight operations;
        // nothing finalizes, so nothing completes and nothing is
        // orphaned. Exact counts: an invented start or completion
        // would fail here.
        assert_eq!(
            record.semantics.as_ref().map(|edge| edge.started()),
            Some(8),
            "the staged edge starts exactly the eight observed calls"
        );
        assert_eq!(
            record.semantics.as_ref().map(|edge| edge.completed()),
            Some(0),
            "the staged edge completes nothing without a final call"
        );
        assert_eq!(
            record.semantics.as_ref().map(|edge| edge.orphans()),
            Some(0),
            "the staged edge stages no orphans"
        );
    }
    assert_eq!(staged, 1, "the batch stages one edge");
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
    let revision_q1 = scene
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .published_revision();
    let JointCommitProgress::Published(_) = scene.poll_commit(0).unwrap() else {
        panic!("q1 publishes exactly once");
    };
    assert_eq!(
        scene
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .published_revision(),
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
        scene
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .published_revision(),
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
    let revision_q1 = scene
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .published_revision();
    assert_eq!(scene.scene.drain.source_mut().remaining(), 0);
    // The cell's three idle services: fresh polls against an empty
    // drain, publishing nothing.
    for _ in 0..3 {
        let progress = scene.service(1024).unwrap();
        assert_eq!(progress, JointServiceProgress::Pending);
    }
    assert_eq!(
        scene
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .published_revision(),
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
        scene
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .published_revision(),
        revision_q1 + 1,
        "q2 publishes exactly one more revision"
    );
}

/// One bare CALL row on `file` (an ordinary record without a journal
/// BEGIN/END).
fn push_bare_call_on(scene: &mut MachineScene, pid: u32, file: u32, name: &str, seq: u64) {
    use p11scope_ebpf_common::object_journal::JournalRecord;
    let descriptors = p11scope_ebpf_common::object_wire::publish_object_descriptors();
    let (_, end) = scene.scene.encoded(pid, file, name, seq);
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

/// Two observed births in one batch, one refused natively (its only call
/// is the fixture's unmarked `C_GetSessionInfo`). Every New candidate
/// installs a Joint feed or names its refusal: disclosing one refusal must
/// not cost the sibling its birth. Both orders run, because the births
/// are decided in descending receipt order and only a disclosure that
/// precedes the sibling's reservation can disturb it. The refused
/// provider makes no journaled call: the image-scoped fallback caused by
/// journaled S1Only calls belongs to the separate F2 regression. This
/// fixture isolates the sibling's birth decision.
fn two_births_one_refused(refused_file: u32) {
    let mut scene = MachineScene::with_initial_files(2, &[0, 1], true);
    let pid = std::process::id();
    let mut seq = 1u64;
    for file in 0..2u32 {
        if file == refused_file {
            // Proved irrelevant: an ordinary row, never a journal entry.
            push_bare_call_on(&mut scene, pid, file, "C_GetSessionInfo", seq);
            seq += 1;
            continue;
        }
        for name in ["C_SignInit", "C_SignInit"] {
            scene.scene.push(pid, file, name, seq);
            seq += 1;
        }
    }
    scene.machine.begin_commit(true).unwrap();
    scene.published_labeled("two-births-one-refused", None);
    let registry = scene.scene.real.scene.coordinator.registry();
    let refusals: Vec<&str> = registry
        .gaps()
        .iter()
        .filter(|gap| gap.subject == "Joint birth unavailable; retained S1")
        .map(|gap| gap.reason.as_str())
        .collect();
    assert_eq!(
        scene.native.birth_outcomes.len(),
        2,
        "both New candidates reach native observation: {:?} refusals {refusals:?}",
        scene.native.birth_outcomes
    );
    assert_eq!(
        refusals.len(),
        1,
        "only the refused birth is disclosed: {refusals:?}"
    );
    assert!(
        refusals[0].starts_with("joint_birth_native_"),
        "the refusal names its native cause: {refusals:?}"
    );
    assert_eq!(
        registry.joint_feeds(),
        1,
        "the sibling's birth installs its Joint feed"
    );
    // (Joint, API returns, reduced) per edge: the refused provider made
    // one call, the sibling two, so the Joint edge names the sibling.
    let mut edges: Vec<(bool, Option<u64>, u64)> = registry
        .instance_semantic_edges()
        .map(|record| {
            (
                record.feed.mode() == crate::semantics_key_use::FeedMode::Joint,
                record.api_returns,
                record.feed.reduced(),
            )
        })
        .collect();
    edges.sort();
    assert_eq!(
        edges,
        [(false, Some(1), 0), (true, Some(2), 2)],
        "the refused provider stays S1Only; the sibling is Joint and reduces both calls"
    );
}

#[test]
fn joint_machine_refused_first_file_birth_keeps_sibling_joint() {
    two_births_one_refused(0);
}

#[test]
fn joint_machine_refused_second_file_birth_keeps_sibling_joint() {
    two_births_one_refused(1);
}

/// The extra modeled call on the refused provider must not cost a different
/// incarnation its Joint feed. Real prepared proofs, rather than file/router
/// aliases, establish which subjects are distinct before birth or audit.
fn journaled_refusal_keeps_joint_sibling(refused_file: u32, unrelated_image: bool) {
    use crate::key_operation_projection::ObsStatus;

    let mut scene = if unrelated_image {
        MachineScene::with_initial_files(1, &[0], true)
    } else {
        MachineScene::with_initial_files(2, &[0, 1], true)
    };
    let refused_pid = std::process::id();
    let child = unrelated_image.then(OwnedStoppedChild::new);
    let healthy_pid = if let Some(child) = &child {
        // Mirror the machine's initial physical setup: retain the actual
        // pidfd and mapping, then let the collected original bind H3. A
        // legacy pre-bind would scan New before these calls arrive.
        let caller = scene.scene.real.scene.admit(child.id(), 50);
        let (module, path) = &scene.scene.real.modules[0];
        scene
            .scene
            .real
            .scene
            .coordinator
            .registry_mut()
            .note_mapping(
                caller,
                child.id(),
                ModuleInfo {
                    path: path.clone(),
                    key: module.clone(),
                    double_loaded: false,
                    build_id: None,
                    identity_source: Some("held-provider".into()),
                    admission: AdmissionState::Admitted,
                    admission_class: Some("exact".into()),
                    admission_endpoints: Some(5),
                    admission_reasons: Vec::new(),
                },
                60,
            );
        scene
            .scene
            .real
            .scene
            .coordinator
            .commit_batch(false)
            .unwrap();
        let candidate = scene
            .scene
            .real
            .scene
            .coordinator
            .prepare_legacy_semantic_candidate(caller, scene.scene.real.lane.domain())
            .unwrap();
        scene.scene.real.h0.0.borrow_mut().io.targets.insert(
            child.id(),
            (
                candidate.pin(),
                ImageIdentity {
                    task_cookie: 73,
                    exec_id: 0,
                },
            ),
        );
        drop(candidate);
        child.id()
    } else {
        refused_pid
    };
    let mut sequence = 1;
    for subject in 0..2 {
        let file = if unrelated_image { 0 } else { subject };
        let pid = if subject == refused_file {
            refused_pid
        } else {
            healthy_pid
        };
        if subject == refused_file {
            // This original makes the native birth observation refuse.
            push_bare_call_on(&mut scene, pid, file, "C_GetSessionInfo", sequence);
        } else {
            scene.scene.push(pid, file, "C_SignInit", sequence);
        }
        sequence += 1;
        // Unlike the prerequisite twin, the refused provider has its own
        // genuine BEGIN/END and admitted affecting call in this frame.
        scene.scene.push(pid, file, "C_SignInit", sequence);
        sequence += 1;
    }
    scene.machine.begin_commit(true).unwrap();
    reach_any(&mut scene, &["Births"]);
    let coordinator = &scene.scene.real.scene.coordinator;
    let prepared = coordinator.prepared_semantic_batch().unwrap();
    let inputs = prepared.admissions().cloned().collect::<Vec<_>>();
    let proofs = prepared
        .claims()
        .map(|(_, proof)| (*proof).expect("all four original admissions have genuine claims"))
        .collect::<Vec<_>>();
    assert_eq!((inputs.len(), proofs.len()), (4, 4));
    for (input, proof) in inputs.iter().zip(&proofs) {
        assert!(proof.matches_admitted(input));
        assert_eq!(
            input.journal_binding().0,
            scene.scene.producers.native_domain()
        );
    }
    assert_eq!(proofs[0], proofs[1]);
    assert_eq!(proofs[2], proofs[3]);
    assert_ne!(
        proofs[0], proofs[2],
        "actual admitted incarnation keys differ"
    );
    assert_eq!(
        inputs[0].journal_binding().1 == inputs[2].journal_binding().1,
        !unrelated_image,
        "the control changes the actual process image, not a router label"
    );
    reach_any(&mut scene, &["Staging"]);
    let coordinator = &scene.scene.real.scene.coordinator;
    let refused_proof = proofs[(refused_file * 2) as usize];
    eprintln!(
        "journaled_refusal pre_audit refused_file={refused_file} unrelated_image={unrelated_image} \
         births={:?} refusals={:?} remaining_current={:?}",
        scene.native.birth_outcomes,
        staged_birth_refusals(coordinator),
        coordinator
            .prepared_semantic_batch()
            .unwrap()
            .current_receipts()
            .iter()
            .map(|receipt| (receipt.image(), receipt.birth_quantum().is_some()))
            .collect::<Vec<_>>(),
    );
    for input in &inputs {
        assert_eq!(
            coordinator.registry().admitted_feed_is_s1only(input),
            refused_proof.matches_admitted(input),
            "only the genuinely refused incarnation lacks its original grant"
        );
    }
    let mut decisions = scene
        .native
        .birth_outcomes
        .iter()
        .map(|(file, result)| (*file, result.as_ref().err().copied()))
        .collect::<Vec<_>>();
    decisions.sort_by_key(|(file, _)| *file);
    if unrelated_image {
        assert_eq!(decisions.len(), 2);
        assert!(decisions.iter().all(|(file, _)| *file == 0));
        assert_eq!(
            decisions
                .iter()
                .filter(|(_, refusal)| *refusal == Some(BirthObservationRefusal::MarkerNotReady))
                .count(),
            1,
            "the other real image uses the same physical provider without sharing its incarnation"
        );
        assert_eq!(
            decisions
                .iter()
                .filter(|(_, refusal)| refusal.is_none())
                .count(),
            1
        );
    } else {
        assert_eq!(
            decisions,
            (0..2)
                .map(|file| {
                    (
                        file,
                        (file == refused_file).then_some(BirthObservationRefusal::MarkerNotReady),
                    )
                })
                .collect::<Vec<_>>(),
            "both original births are decided before any refusal fanout"
        );
    }
    reach_any(&mut scene, &["Audited"]);
    let audit = scene.machine.diagnostic_audit_for_test();
    scene.published_labeled("journaled-refused-sibling", None);
    let registry = scene.scene.real.scene.coordinator.registry();
    let mut counts = registry
        .instance_semantic_edges()
        .map(|record| record.api_returns)
        .collect::<Vec<_>>();
    counts.sort();
    assert_eq!(
        counts,
        [Some(2), Some(2)],
        "all four original API returns survive"
    );
    let refusals = registry
        .gaps()
        .iter()
        .filter(|gap| gap.subject == "Joint birth unavailable; retained S1")
        .map(|gap| gap.reason.as_str())
        .collect::<Vec<_>>();
    assert_eq!(refusals, ["joint_birth_native_MarkerNotReady"]);
    assert_eq!(
        scene.native.birth_outcomes.len(),
        2,
        "no repeated birth read"
    );
    let observations = registry.joint_observations(registry.published_revision());
    eprintln!(
        "journaled_refusal refused_file={refused_file} unrelated_image={unrelated_image} \
         decisions={decisions:?} audit={audit:?} feeds={} counts={counts:?} observation={:?}/{}",
        registry.joint_feeds(),
        observations.status,
        observations.reason,
    );
    assert_eq!(
        (
            registry.joint_feeds(),
            observations.status,
            observations.reason
        ),
        (1, ObsStatus::Populated, "none"),
        "a different admitted incarnation retains its healthy Joint observations"
    );
}

#[test]
fn joint_machine_journaled_refused_first_file_keeps_sibling_joint() {
    journaled_refusal_keeps_joint_sibling(0, false);
}

#[test]
fn joint_machine_journaled_refused_second_file_keeps_sibling_joint() {
    journaled_refusal_keeps_joint_sibling(1, false);
}

#[test]
fn joint_machine_journaled_refusal_keeps_unrelated_image_joint() {
    journaled_refusal_keeps_joint_sibling(0, true);
}

/// A live Joint key is structurally excluded from the S1Only marking gate.
/// Its own failed fresh native read still falls back. Once S1Only, later
/// admitted originals can name that exact retained key and take the real
/// S1Only-subject path without ever reactivating its Joint history.
#[test]
fn joint_machine_same_incarnation_native_refusal_retains_s1_history() {
    use crate::key_operation_projection::ObsStatus;
    use crate::semantics_key_use::FeedMode;
    use crate::semantics_objects::journal::JournalGap;

    let mut scene = MachineScene::with_initial_files(1, &[0], false);
    let pid = std::process::id();
    for sequence in [1, 2] {
        scene.scene.push(pid, 0, "C_SignInit", sequence);
    }
    scene.machine.begin_commit(true).unwrap();
    scene.published_labeled("same-incarnation-initial-birth", None);
    assert!(matches!(
        scene.poll_commit(0).unwrap(),
        JointCommitProgress::Published(_)
    ));
    let targets = scene
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .joint_feed_targets()
        .collect::<Vec<_>>();
    assert_eq!(targets.len(), 1);
    let target = targets[0];
    let proof = target.bootstrap().proof();
    assert_eq!(scene.native.birth_outcomes.len(), 1);
    assert!(scene.native.birth_outcomes[0].1.is_ok());

    for sequence in [3, 4] {
        scene.scene.push(pid, 0, "C_SignInit", sequence);
    }
    scene.machine.begin_commit(true).unwrap();
    reach_any(&mut scene, &["Births"]);
    let coordinator = &scene.scene.real.scene.coordinator;
    let prepared = coordinator.prepared_semantic_batch().unwrap();
    assert_eq!(prepared.admissions().count(), 2);
    for input in prepared.admissions() {
        assert!(proof.matches_admitted(input));
        assert!(input.joint_resource_origin().is_some());
        assert!(
            !coordinator.registry().admitted_feed_is_s1only(input),
            "the exact still-Joint incarnation cannot enter S1Only disposition"
        );
    }
    for (_, claim) in prepared.claims() {
        assert_eq!(*claim, Ok(proof), "same actual retained key and era");
    }
    let generation = scene.scene.attached.as_ref().unwrap().generation();
    let (row, control, _) = scene
        .native
        .publisher
        .publish_stamped(&["0", "0", "0", "0", "1"], generation);
    assert!(
        scene
            .native
            .rows
            .insert(
                target.bootstrap().domain(),
                NativeBirthRows { row, control }
            )
            .is_some(),
        "replace only the selected incarnation's real native read leaf"
    );
    scene.published_labeled("same-incarnation-native-read-refusal", None);
    assert!(matches!(
        scene.poll_commit(0).unwrap(),
        JointCommitProgress::Published(_)
    ));
    let registry = scene.scene.real.scene.coordinator.registry();
    assert_eq!(registry.joint_feeds(), 0);
    assert_eq!(
        registry.feed_mode_for_test(target.id()),
        Some(FeedMode::S1Only)
    );
    let observations = registry.joint_observations(registry.published_revision());
    eprintln!(
        "same_incarnation native_read_refusal observation={:?}/{}",
        observations.status, observations.reason
    );
    assert_eq!(observations.status, ObsStatus::Unavailable);

    for (sequences, count) in [([5, 6], 6), ([7, 8], 8)] {
        for sequence in sequences {
            scene.scene.push(pid, 0, "C_SignInit", sequence);
        }
        scene.machine.begin_commit(true).unwrap();
        reach_any(&mut scene, &["Births"]);
        let coordinator = &scene.scene.real.scene.coordinator;
        let prepared = coordinator.prepared_semantic_batch().unwrap();
        assert_eq!(prepared.admissions().count(), 2);
        for input in prepared.admissions() {
            assert!(
                proof.matches_admitted(input),
                "actual same-key S1Only original"
            );
            assert!(input.joint_resource_origin().is_some());
            assert!(coordinator.registry().admitted_feed_is_s1only(input));
        }
        reach_any(&mut scene, &["Audited"]);
        let audit = scene.machine.diagnostic_audit_for_test().unwrap();
        assert_eq!(audit.0, Some(JournalGap::DomainTainted));
        scene.published_labeled("same-incarnation-s1only-history", None);
        assert!(matches!(
            scene.poll_commit(0).unwrap(),
            JointCommitProgress::Published(_)
        ));
        let coordinator = &scene.scene.real.scene.coordinator;
        let registry = coordinator.registry();
        let history = registry.joint_history_targets().collect::<Vec<_>>();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].0.id(), target.id());
        assert!(history[0].0.bootstrap() == target.bootstrap());
        assert_eq!(history[0].1, FeedMode::S1Only);
        let records = registry.instance_semantic_edges().collect::<Vec<_>>();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].api_returns, Some(count));
        assert_eq!(registry.joint_feeds(), 0);
        assert_eq!(
            scene.native.birth_outcomes.len(),
            1,
            "no rebirth after refusal"
        );
        assert!(
            coordinator
                .joint_capture()
                .adapter()
                .proof_refused_for_test(proof)
        );
        let observations = registry.joint_observations(registry.published_revision());
        eprintln!(
            "same_incarnation s1only_subject audit={audit:?} observation={:?}/{}",
            observations.status, observations.reason
        );
        assert_eq!(observations.status, ObsStatus::Unavailable);
        scene.scene.assert_claims(&[]);
    }
}

fn add_initial_machine_image(scene: &mut MachineScene, pid: u32, image: ImageIdentity) {
    let caller = scene.scene.real.scene.admit(pid, 50);
    let (module, path) = &scene.scene.real.modules[0];
    let admission_endpoints = scene
        .scene
        .real
        .h0
        .0
        .borrow()
        .io
        .endpoints
        .iter()
        .filter(|(_, _, endpoint)| endpoint.file_slot == 0)
        .count();
    scene
        .scene
        .real
        .scene
        .coordinator
        .registry_mut()
        .note_mapping(
            caller,
            pid,
            ModuleInfo {
                path: path.clone(),
                key: module.clone(),
                double_loaded: false,
                build_id: None,
                identity_source: Some("held-provider".into()),
                admission: AdmissionState::Admitted,
                admission_class: Some("exact".into()),
                admission_endpoints: Some(admission_endpoints),
                admission_reasons: Vec::new(),
            },
            60,
        );
    scene
        .scene
        .real
        .scene
        .coordinator
        .commit_batch(false)
        .unwrap();
    let candidate = scene
        .scene
        .real
        .scene
        .coordinator
        .prepare_legacy_semantic_candidate(caller, scene.scene.real.lane.domain())
        .unwrap();
    scene
        .scene
        .real
        .h0
        .0
        .borrow_mut()
        .io
        .targets
        .insert(pid, (candidate.pin(), image));
}

#[test]
fn joint_machine_mixed_image_and_exact_refusal_keeps_pending_continuation() {
    mixed_image_and_exact_refusal_pending(MixedRefusalControl::Pending);
}

#[test]
fn joint_machine_pending_refusal_requires_exact_original_provenance() {
    mixed_image_and_exact_refusal_pending(MixedRefusalControl::Provenance);
}

#[test]
fn joint_machine_resource_flag_with_pending_h3_keeps_originals_local() {
    mixed_image_and_exact_refusal_pending(MixedRefusalControl::ResourcePending);
}

#[test]
fn joint_machine_negative_only_image_taint_preserves_unrelated_joint() {
    mixed_image_and_exact_refusal_pending(MixedRefusalControl::ImageOnly);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MixedRefusalControl {
    Pending,
    Provenance,
    ResourcePending,
    ImageOnly,
}

fn mixed_image_and_exact_refusal_pending(scenario: MixedRefusalControl) {
    use crate::semantics_key_use::FeedMode;
    use crate::semantics_objects::journal::{EndpointClass, JournalGap, endpoint_class};
    let pending = scenario != MixedRefusalControl::ImageOnly;
    let resource_refused = scenario == MixedRefusalControl::ResourcePending;

    let mut scene = MachineScene::with_initial_files_and_functions(
        1,
        &[0],
        &[
            "C_CreateObject",
            "C_SignInit",
            "C_SignUpdate",
            "C_SignFinal",
            "C_GetSessionInfo",
            "C_EncapsulateKey",
            // Packet 6.07c: the still-negative control (appended so
            // existing slots never shift).
            "C_WrapKeyAuthenticated",
        ],
        true,
    );
    let c_pid = std::process::id();
    let child_b = OwnedStoppedChild::new();
    let child_a = OwnedStoppedChild::new();
    add_initial_machine_image(
        &mut scene,
        child_b.id(),
        ImageIdentity {
            task_cookie: 72,
            exec_id: 0,
        },
    );
    add_initial_machine_image(
        &mut scene,
        child_a.id(),
        ImageIdentity {
            task_cookie: 74,
            exec_id: 0,
        },
    );
    for (pid, sequence) in [(c_pid, 1), (c_pid, 2), (child_b.id(), 1), (child_b.id(), 2)] {
        scene.scene.push(pid, 0, "C_SignInit", sequence);
    }
    push_bare_call_on(&mut scene, child_a.id(), 0, "C_GetSessionInfo", 1);
    scene.machine.begin_commit(true).unwrap();
    reach_any(&mut scene, &["Births"]);
    let prepared = scene
        .scene
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap();
    let a_input = prepared
        .admissions()
        .find(|input| input.journal_binding().1.task_cookie == 74)
        .unwrap()
        .clone();
    let a_proof = prepared
        .claims()
        .find(|(at, _)| *at == a_input.h0_ordinal())
        .unwrap()
        .1
        .as_ref()
        .copied()
        .expect("the irrelevant A original binds its actual retained key");
    scene.published_labeled("mixed-scope-original-births", None);
    assert!(matches!(
        scene.poll_commit(0).unwrap(),
        JointCommitProgress::Published(_)
    ));
    let coordinator = &scene.scene.real.scene.coordinator;
    let targets = coordinator
        .registry()
        .joint_feed_targets()
        .collect::<Vec<_>>();
    assert_eq!(targets.len(), 2);
    let c = targets
        .iter()
        .copied()
        .find(|target| {
            coordinator
                .semantic_bindings()
                .get(target.caller())
                .unwrap()
                .image()
                .task_cookie
                == 71
        })
        .unwrap();
    let b = targets
        .iter()
        .copied()
        .find(|target| target.id() != c.id())
        .unwrap();
    let c_proof = c.bootstrap().proof();
    assert_ne!(a_proof, c_proof);

    for (pid, sequence) in [(c_pid, 3), (c_pid, 4), (child_b.id(), 3), (child_b.id(), 4)] {
        scene.scene.push(pid, 0, "C_SignInit", sequence);
    }
    scene.machine.begin_commit(true).unwrap();
    reach_any(&mut scene, &["Births"]);
    let prepared = scene
        .scene
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap();
    let c_input = prepared
        .admissions()
        .find(|input| c_proof.matches_admitted(input))
        .unwrap()
        .clone();
    let (row, control, _) = scene.native.publisher.publish_stamped(
        &["0", "0", "0", "0", "1"],
        scene.scene.attached.as_ref().unwrap().generation(),
    );
    assert!(
        scene
            .native
            .rows
            .insert(c.bootstrap().domain(), NativeBirthRows { row, control })
            .is_some()
    );
    scene.published_labeled("mixed-scope-native-c-refusal", None);
    assert!(matches!(
        scene.poll_commit(0).unwrap(),
        JointCommitProgress::Published(_)
    ));
    let coordinator = &mut scene.scene.real.scene.coordinator;
    assert_eq!(
        coordinator.registry().feed_mode_for_test(c.id()),
        Some(FeedMode::S1Only)
    );
    assert_eq!(
        coordinator.registry().feed_mode_for_test(b.id()),
        Some(FeedMode::Joint)
    );
    assert_eq!(
        coordinator
            .joint_capture_mut()
            .adapter_mut()
            .bind_admitted_key(&c_input),
        Ok(c_proof),
        "C retains its original key-era without an image taint"
    );
    assert_eq!(
        coordinator
            .joint_capture_mut()
            .adapter_mut()
            .bind_admitted_key(&a_input),
        Ok(a_proof)
    );

    let child_e = OwnedStoppedChild::new();
    let e_image = ImageIdentity {
        task_cookie: 75,
        exec_id: 0,
    };
    scene.scene.real.bind(child_e.id(), e_image, 0);
    if resource_refused {
        let (begin_a, _) = scene.scene.encoded(child_a.id(), 0, "C_SignInit", 2);
        scene.scene.drain.source_mut().push_record(begin_a.to_vec());
        scene.scene.drain.source_mut().push_record(begin_a.to_vec());
    } else {
        // KEM used to be the still-negative control here; it is
        // modeled now, so the still-negative authenticated wrap
        // carries the control.
        assert_eq!(
            endpoint_class(function_id("C_WrapKeyAuthenticated")),
            Some(EndpointClass::NegativeOnlyAffecting)
        );
        assert_ne!(
            crate::kinds::descriptor("C_WrapKeyAuthenticated").unwrap(),
            p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
        );
        let (mut begin_a, _) = scene
            .scene
            .encoded(child_a.id(), 0, "C_WrapKeyAuthenticated", 2);
        begin_a[5] = p11scope_ebpf_common::object_journal::JOURNAL_BEGIN_NO_END;
        assert!(
            p11scope_ebpf_common::object_journal::validate_begin(&begin_a, None)
                .unwrap()
                .no_end()
        );
        scene.scene.drain.source_mut().push_record(begin_a.to_vec());
    }
    scene.scene.push(child_b.id(), 0, "C_SignInit", 5);
    scene.scene.push(c_pid, 0, "C_SignInit", 5);
    if pending {
        scene.scene.push(child_e.id(), 0, "C_SignInit", 1);
    }
    let mut raw = scene.scene.collect_with_fault(&BirthFault);
    let first = {
        let mut held = scene.scene.real.h0.0.borrow_mut();
        let HeldH0 { capture, io, .. } = &mut *held;
        io.script.fail_cookie = pending.then_some(e_image.task_cookie);
        let first = capture.tick_collected_with(io, &mut raw).unwrap();
        assert_eq!(first.calls().count(), 2);
        assert_eq!(first.awaiting_floor(), pending.then_some(12));
        first
    };
    if pending {
        let mut held = scene.scene.real.h0.0.borrow_mut();
        let HeldH0 {
            capture, io, stash, ..
        } = &mut *held;
        io.script.fail_cookie = None;
        let mut completed = capture.tick_collected_with(io, &mut raw).unwrap();
        assert_eq!(completed.calls().count(), 1);
        assert_eq!(completed.calls().next().unwrap().position(), Some(12));
        assert_eq!(completed.allocated_below(), 13);
        assert_eq!(stash_refresh_report(stash, &mut completed).1, 0);
        assert_eq!(stash.min_outcome_position(), Some(12));
    }
    let coordinator = &mut scene.scene.real.scene.coordinator;
    coordinator.stage_semantic_batch(
        SemanticBatch::from_tick_report(
            scene.scene.real.lane.domain(),
            first,
            Vec::new(),
            now_ns(),
        )
        .unwrap(),
    );
    coordinator
        .prepare_staged_semantic_batch(&mut scene.scene.real.lane, None)
        .unwrap();
    let mut ingested = raw
        .ingest(
            coordinator.joint_capture_mut().adapter_mut(),
            &scene.scene.producers,
            scene.machine.retained_drain_grant_for_test().unwrap(),
        )
        .unwrap_or_else(|(_, reason)| panic!("original mixed-scope raw: {reason:?}"));
    let mut claims = Vec::new();
    while let Some(claim) = coordinator
        .claim_next_prepared_admission(&scene.scene.producers, &ingested)
        .unwrap()
    {
        claims.push(claim);
    }
    assert_eq!(claims.len(), 2);
    assert_eq!(claims[0], (10, Ok(b.bootstrap().proof())));
    let exact = coordinator
        .prepared_semantic_batch()
        .unwrap()
        .admissions()
        .find(|input| input.h0_ordinal() == 11)
        .unwrap();
    assert!(c_proof.matches_admitted(exact));
    assert!(coordinator.registry().admitted_feed_is_s1only(exact));
    while coordinator
        .stage_next_prepared_admission_with_disposition(&scene.scene.producers, &mut ingested)
        .unwrap()
    {}
    assert!(coordinator.finish_prepared_semantic_batch(&scene.scene.real.lane));
    coordinator
        .commit_batch_with_semantics(false, Some(&mut scene.scene.real.lane))
        .unwrap();
    let attached = scene.scene.attached.as_ref().unwrap();
    let mut frame = coordinator
        .audit_ingested_quantum(ingested, &scene.scene.producers, attached, &BirthFault)
        .unwrap_or_else(|(_, reason)| panic!("original mixed-scope audit: {reason:?}"));
    assert_eq!(
        frame.audit_for_test().resource_refused_for_test(),
        resource_refused,
        "valid negative-only NO_END taints A without a resource-custody contradiction"
    );
    let failures = frame.original_failures_for_test().collect::<Vec<_>>();
    assert_eq!(
        failures
            .iter()
            .map(|failure| failure.gap)
            .collect::<Vec<_>>(),
        if pending {
            vec![JournalGap::ImageTainted, JournalGap::H3Pending]
        } else {
            vec![JournalGap::ImageTainted]
        }
    );
    assert!(failures[0].affects_proof_for_test(&a_proof));
    assert!(failures[0].affects_proof_for_test(&c_proof));
    assert!(!failures[0].affects_domain(b.bootstrap().domain()));
    assert!(
        coordinator
            .joint_capture()
            .adapter()
            .proof_refused_for_test(c_proof)
    );
    assert_eq!(
        coordinator
            .joint_capture_mut()
            .adapter_mut()
            .bind_admitted_key(&c_input),
        Ok(c_proof),
        "the exact refused C image is still untainted and keeps its era"
    );
    let work =
        failures[0].effects.effects.len() + coordinator.registry().joint_history_targets().count();
    if scenario == MixedRefusalControl::Provenance {
        frame.assert_pending_refusal_provenance_for_test(
            coordinator.joint_capture_mut().adapter_mut(),
            c_proof,
            a_proof,
            b.bootstrap().proof(),
        );
    }
    if !pending {
        let attached = scene.scene.attached.take().unwrap();
        let mut rows = vec![(
            b.bootstrap().domain(),
            scene.native.rows.remove(&b.bootstrap().domain()).unwrap(),
        )];
        finish_reserved_birth_frame(
            &mut scene.scene,
            &attached,
            scene.machine.retained_births_for_test(),
            &mut rows,
            frame,
        );
        let coordinator = &scene.scene.real.scene.coordinator;
        assert_eq!(coordinator.registry().joint_feeds(), 1);
        assert_eq!(
            coordinator.registry().feed_mode_for_test(b.id()),
            Some(FeedMode::Joint)
        );
        for target in [b, c] {
            assert_eq!(
                coordinator
                    .registry()
                    .instance_semantic_edges()
                    .find(|record| record.id == target.id())
                    .unwrap()
                    .api_returns,
                Some(5)
            );
        }
        assert_live_sign_associations(coordinator.registry(), &[b.id(), c.id()]);
        assert_eq!(
            coordinator.joint_capture().ledger().roles_for_test(),
            [0, 0, 0, 0, 2],
            "only the exact B/C live operations retain association custody"
        );
        scene.scene.assert_claims(&[]);
        let before = coordinator
            .registry()
            .instance_semantic_edges()
            .filter(|record| [b.id(), c.id()].contains(&record.id))
            .map(|record| {
                (
                    record.id,
                    (
                        record.semantics.as_ref().unwrap().completed(),
                        record.api_returns.unwrap(),
                    ),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        scene.scene.push(child_b.id(), 0, "C_SignFinal", 6);
        scene.scene.push(c_pid, 0, "C_SignFinal", 6);
        let ingested = prepare_disposing_s1_batch(
            &mut scene.scene,
            2,
            scene.machine.retained_drain_grant_for_test().unwrap(),
        );
        let terminal = acquire(&mut scene.scene, ingested, &attached, &BirthFault);
        finish_reserved_birth_frame(
            &mut scene.scene,
            &attached,
            scene.machine.retained_births_for_test(),
            &mut rows,
            terminal,
        );
        let coordinator = &scene.scene.real.scene.coordinator;
        assert_eq!(coordinator.registry().joint_feeds(), 1);
        assert_eq!(
            coordinator.registry().feed_mode_for_test(b.id()),
            Some(FeedMode::Joint)
        );
        assert!(coordinator.registry().keyuse_for_test().open().is_empty());
        assert_eq!(
            coordinator.joint_capture().ledger().roles_for_test(),
            [0; 5]
        );
        for record in coordinator.registry().instance_semantic_edges() {
            if let Some((completed, physical)) = before.get(&record.id) {
                assert_eq!(record.api_returns, Some(physical + 1));
                assert_eq!(
                    record.semantics.as_ref().unwrap().completed(),
                    completed + 1
                );
                assert!(
                    record
                        .semantics
                        .as_ref()
                        .unwrap()
                        .active_summary()
                        .is_empty()
                );
            }
        }
        scene.scene.assert_claims(&[]);
        return;
    }
    let mut ports = coordinator
        .joint_frame_ports(&scene.scene.producers)
        .unwrap();
    frame.bind_targets(&ports).unwrap();
    for _ in 0..work {
        if frame.negative_effects_complete_for_test(c.bootstrap().domain()) == Some(true) {
            break;
        }
        let mut remaining = 1;
        frame
            .deliver_next_bounded(&mut ports, &mut remaining)
            .unwrap();
    }
    assert_eq!(
        frame.negative_effects_complete_for_test(c.bootstrap().domain()),
        Some(true)
    );
    if resource_refused {
        use crate::semantics_key_use::{SealFailureDisposition, disposition_of};
        assert_eq!(
            disposition_of(
                frame
                    .original_failures_for_test()
                    .find(|failure| failure.gap == JournalGap::H3Pending)
                    .unwrap()
                    .gap
            ),
            SealFailureDisposition::Retry
        );
        assert!(
            frame
                .original_failures_for_test()
                .all(|failure| failure.gap != JournalGap::ResourceUnavailable)
        );
        assert_eq!(
            frame
                .audited_failure_for_test(c.bootstrap().domain())
                .unwrap()
                .disposition(),
            SealFailureDisposition::Fallback,
            "the resource flag cannot manufacture an absent ResourceUnavailable original"
        );
        let before = (
            ports.read().1.adapter().invocation_claims_for_test(),
            ports.read().1.ledger().roles_for_test(),
        );
        for _ in 0..2 {
            assert_eq!(
                frame.defer_pending_h3(&mut ports, &scene.scene.real.lane),
                Ok(QuantumSealProgress::LocalPending)
            );
        }
        let (_, refusal) = frame
            .finish_pending_h3(&mut ports, &scene.scene.real.lane)
            .err()
            .expect("incomplete resource custody must remain local");
        assert_eq!(refusal, RawQuantumRefusal::H3Undisposed);
        assert_eq!(
            (
                ports.read().1.adapter().invocation_claims_for_test(),
                ports.read().1.ledger().roles_for_test(),
            ),
            before
        );
        return;
    }
    assert_eq!(
        frame.defer_pending_h3(&mut ports, &scene.scene.real.lane),
        Ok(QuantumSealProgress::AwaitFutureInput),
        "the mixed union preserves exact-key negative delivery and original pending custody"
    );
    frame
        .finish_pending_h3(&mut ports, &scene.scene.real.lane)
        .unwrap_or_else(|(_, reason)| panic!("original mixed pending finish: {reason:?}"));
}

/// Scripts the EVENTS ring-loss counter over a faithful H0: every
/// other seam delegates to the scene's shared H0 unchanged.
struct PublishRingLossStub<I> {
    inner: I,
    ring_loss: std::collections::VecDeque<u64>,
}

impl<I: crate::inventory_semantics::LaneTestIo> crate::inventory_semantics::LaneTestIo
    for PublishRingLossStub<I>
{
    fn events_ring_loss(&mut self) -> Option<u64> {
        self.ring_loss.pop_front()
    }

    fn stash_pending_floor(&self) -> Option<u64> {
        self.inner.stash_pending_floor()
    }

    fn inspect_pending_h3(
        &self,
        inspect: &mut dyn FnMut(
            &crate::semantic_capture::SemanticCapture,
            &crate::inventory_semantics::RefreshReceiptStash,
            &crate::attach::SessionDrainProducers,
        ),
    ) {
        self.inner.inspect_pending_h3(inspect)
    }

    fn semantic_published(&mut self) {
        self.inner.semantic_published()
    }

    fn begin_terminal_cleanup(&mut self) -> anyhow::Result<()> {
        self.inner.begin_terminal_cleanup()
    }

    fn finish_terminal_cleanup(
        &mut self,
        second_signal: &dyn Fn() -> bool,
        out: &mut dyn std::io::Write,
    ) -> anyhow::Result<()> {
        self.inner.finish_terminal_cleanup(second_signal, out)
    }

    fn poll_terminal_detach(
        &mut self,
        out: &mut dyn std::io::Write,
    ) -> anyhow::Result<crate::attach::ProducerDetachProgress> {
        self.inner.poll_terminal_detach(out)
    }

    fn tick_targets(&mut self, pins: &[std::sync::Arc<crate::process::PidPin>]) {
        self.inner.tick_targets(pins)
    }

    fn service_live_discovery(&mut self) {
        self.inner.service_live_discovery()
    }

    fn collection_saturated(&self) -> bool {
        self.inner.collection_saturated()
    }

    fn retained_registration_ns(&self, image: p11scope_ebpf_common::ImageIdentity) -> Option<u64> {
        self.inner.retained_registration_ns(image)
    }

    fn validate_attachment(
        &mut self,
        subset: &crate::inventory_semantics::AttestedSubset,
    ) -> Result<(), crate::inventory_semantics::SemanticRefusal> {
        self.inner.validate_attachment(subset)
    }

    fn take_refresh_receipt(
        &mut self,
        pin: &std::sync::Arc<crate::process::PidPin>,
        slot: u32,
    ) -> Option<crate::semantic_capture::CurrentPartitionReceipt> {
        self.inner.take_refresh_receipt(pin, slot)
    }

    fn stash_admission_evidence(
        &mut self,
        receipts: Vec<crate::semantic_capture::CurrentPartitionReceipt>,
        outcomes: Vec<crate::semantic_capture::TickOutcome>,
    ) {
        self.inner.stash_admission_evidence(receipts, outcomes)
    }

    fn physical_gaps(
        &mut self,
        domain: crate::attach::capture::NativeDomainId,
        gaps: &mut Vec<crate::semantic_capture::PhysicalSemanticGap>,
    ) -> Option<
        Result<
            crate::inventory_semantics::SemanticBatch,
            crate::inventory_semantics::SemanticRefusal,
        >,
    > {
        self.inner.physical_gaps(domain, gaps)
    }

    fn validate_collected_preparation(
        &self,
        raw: &crate::semantics_objects::journal::joint_driver::RawJointQuantum,
    ) -> Result<(), crate::inventory_semantics::SemanticRefusal> {
        self.inner.validate_collected_preparation(raw)
    }

    fn physical_gaps_collected(
        &mut self,
        domain: crate::attach::capture::NativeDomainId,
        gaps: &mut Vec<crate::semantic_capture::PhysicalSemanticGap>,
        raw: &mut crate::semantics_objects::journal::joint_driver::RawJointQuantum,
    ) -> Option<
        Result<
            crate::inventory_semantics::SemanticBatch,
            crate::inventory_semantics::SemanticRefusal,
        >,
    > {
        self.inner.physical_gaps_collected(domain, gaps, raw)
    }

    fn validate_current(
        &mut self,
        receipt: &crate::semantic_capture::CurrentPartitionReceipt,
        report: &mut crate::semantic_capture::TickReport,
    ) -> Result<(), crate::semantic_capture::CurrentReceiptRefusal> {
        self.inner.validate_current(receipt, report)
    }

    fn tick(
        &mut self,
        domain: crate::attach::capture::NativeDomainId,
    ) -> Result<
        crate::inventory_semantics::SemanticBatch,
        crate::inventory_semantics::SemanticRefusal,
    > {
        self.inner.tick(domain)
    }

    fn refresh(
        &mut self,
        pin: std::sync::Arc<crate::process::PidPin>,
        slot: u32,
    ) -> Result<
        (
            Vec<p11scope_ebpf_common::ImageIdentity>,
            std::sync::Arc<crate::process::PidPin>,
        ),
        crate::inventory_semantics::SemanticRefusal,
    > {
        self.inner.refresh(pin, slot)
    }

    fn refresh_collected(
        &mut self,
        pin: std::sync::Arc<crate::process::PidPin>,
        slot: u32,
        raw: &mut crate::semantics_objects::journal::joint_driver::RawJointQuantum,
        adapter: &crate::semantics_objects::journal::JournalAdapter,
        producers: &crate::attach::SessionDrainProducers,
    ) -> Result<
        (
            Vec<p11scope_ebpf_common::ImageIdentity>,
            std::sync::Arc<crate::process::PidPin>,
        ),
        crate::inventory_semantics::SemanticRefusal,
    > {
        self.inner
            .refresh_collected(pin, slot, raw, adapter, producers)
    }

    fn has_pending_evidence(&self) -> bool {
        self.inner.has_pending_evidence()
    }

    fn finish(
        &mut self,
        domain: crate::attach::capture::NativeDomainId,
    ) -> crate::inventory_semantics::SemanticBatch {
        self.inner.finish(domain)
    }

    fn quiescent(&mut self) -> bool {
        self.inner.quiescent()
    }

    fn positions(&mut self) -> Option<[(usize, usize); 2]> {
        self.inner.positions()
    }

    fn drain_events_to(
        &mut self,
        stop: usize,
        quantum: usize,
    ) -> crate::inventory_semantics::LaneDrainOutcome {
        self.inner.drain_events_to(stop, quantum)
    }

    fn drain_discovery_to(
        &mut self,
        stop: usize,
        quantum: usize,
    ) -> crate::inventory_semantics::LaneDrainOutcome {
        self.inner.drain_discovery_to(stop, quantum)
    }
}

/// The machine publish path polls the EVENTS ring-loss counter like
/// the plain commit path: a rise discloses exactly once even though
/// both poll sites read the same cumulative counter.
#[test]
fn joint_machine_publish_discloses_events_ring_loss_rise() {
    let mut scene = MachineScene::new(1);
    scene.native.fail_births = true;
    let h0 = scene.scene.real.h0.clone();
    scene
        .scene
        .real
        .lane
        .install_test_io(Box::new(PublishRingLossStub {
            inner: h0,
            ring_loss: std::collections::VecDeque::from([9, 9, 9]),
        }));
    let pid = std::process::id();
    for (seq, name) in (1u64..).zip([
        "C_CreateObject",
        "C_SignInit",
        "C_SignUpdate",
        "C_SignFinal",
    ]) {
        scene.scene.push(pid, 0, name, seq);
    }
    scene.machine.begin_commit(true).unwrap();
    scene.published_labeled("m1-ring-loss", None);
    // M1 stages one named gap at publish; the counts land immediately.
    let staged: Vec<_> = scene
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .staged_scope_gaps_for_test()
        .into_iter()
        .filter(|(subject, _)| subject == "native capture events lost")
        .collect();
    assert_eq!(
        staged,
        [(
            "native capture events lost".to_string(),
            "the EVENTS ring was full; the kernel refused records \
             before the drain could read them \
             (kernel reserve failures; exact count in events_lost)"
                .to_string(),
        )],
        "a rise stages one named gap at machine publish"
    );
    let lane = &scene.scene.real.lane;
    let summary = lane.semantic_summary();
    assert_eq!(
        (
            lane.shed_calls_disclosed(),
            lane.events_ring_loss_disclosed(),
            summary.unrouted_returns,
            summary.events_lost
        ),
        (0, 9, 0, 9),
        "the disclosed delta counts exactly once across poll sites"
    );
    // And it surfaces through the production final commit, never stuck staged.
    let real = &mut scene.scene.real;
    let (lane, scene) = (&mut real.lane, &mut real.scene);
    scene
        .coordinator
        .commit_batch_with_semantics(false, Some(lane))
        .expect("the production final commit publishes the staged gap");
    let coordinator = &scene.coordinator;
    let gaps: Vec<_> = coordinator
        .registry()
        .gaps()
        .iter()
        .zip(coordinator.registry().gap_repeats().iter())
        .filter(|(gap, _)| gap.subject == "native capture events lost")
        .map(|(gap, repeats)| (gap.reason.clone(), *repeats))
        .collect();
    assert_eq!(gaps.len(), 1, "the staged gap surfaces: {gaps:?}");
    assert_eq!(gaps[0].1, 1, "a single rise surfaces once: {gaps:?}");
}

/// Plain and machine polls share one ring-loss baseline on one
/// lane: a rise on either side discloses exactly once, and a flat
/// read on either side discloses nothing, in either order.
#[test]
fn plain_and_machine_polls_share_one_ring_loss_baseline() {
    let mut scene = MachineScene::new(1);
    scene.native.fail_births = true;
    let h0 = scene.scene.real.h0.clone();
    scene
        .scene
        .real
        .lane
        .install_test_io(Box::new(PublishRingLossStub {
            inner: h0,
            ring_loss: std::collections::VecDeque::from([4, 10, 10, 10]),
        }));
    let pid = std::process::id();
    for (seq, name) in (1u64..).zip([
        "C_CreateObject",
        "C_SignInit",
        "C_SignUpdate",
        "C_SignFinal",
    ]) {
        scene.scene.push(pid, 0, name, seq);
    }
    // The machine publish discloses the first rise (4).
    scene.machine.begin_commit(true).unwrap();
    scene.published_labeled("interleave-machine-first", None);
    // A plain production commit discloses the second rise (4 -> 10).
    {
        let real = &mut scene.scene.real;
        let (lane, scene) = (&mut real.lane, &mut real.scene);
        scene
            .coordinator
            .commit_batch_with_semantics(false, Some(lane))
            .expect("the interleaved plain commit publishes");
    }
    // A second machine publish finds the counter flat (autonomous:
    // the first demand is consumed, like the absence twins).
    for (seq, name) in (5u64..).zip([
        "C_CreateObject",
        "C_SignInit",
        "C_SignUpdate",
        "C_SignFinal",
    ]) {
        scene.scene.push(pid, 0, name, seq);
    }
    scene.published_labeled("interleave-machine-second", None);
    // One more plain commit publishes the coalesced gap row.
    {
        let real = &mut scene.scene.real;
        let (lane, scene) = (&mut real.lane, &mut real.scene);
        scene
            .coordinator
            .commit_batch_with_semantics(false, Some(lane))
            .expect("the trailing plain commit publishes");
    }
    let lane = &scene.scene.real.lane;
    let summary = lane.semantic_summary();
    assert_eq!(
        (
            lane.shed_calls_disclosed(),
            lane.events_ring_loss_disclosed(),
            summary.unrouted_returns,
            summary.events_lost
        ),
        (0, 10, 0, 10),
        "interleaved rises disclose exactly once across poll sites"
    );
    let coordinator = &scene.scene.real.scene.coordinator;
    let gaps: Vec<_> = coordinator
        .registry()
        .gaps()
        .iter()
        .zip(coordinator.registry().gap_repeats().iter())
        .filter(|(gap, _)| gap.subject == "native capture events lost")
        .map(|(gap, repeats)| (gap.reason.clone(), *repeats))
        .collect();
    assert_eq!(gaps.len(), 1, "rises coalesce onto one gap row: {gaps:?}");
    assert_eq!(gaps[0].1, 2, "two rises surface twice: {gaps:?}");
}

// Pre-grant linked-quantum extension: on a linked lane with no grant
// yet, a quantum stays open while a journaled START is in flight or
// its H0 records are only count-only setup calls, within wall-time,
// table and capacity bounds. Stop, failure and unlinked lanes close
// exactly as before.

/// One provider with a setup call and a modeled lifecycle call.
fn pregrant_scene() -> MachineScene {
    MachineScene::with_initial_files_and_functions(
        1,
        &[0],
        &["C_GetFunctionList", "C_Initialize"],
        true,
    )
}

/// Stage one completed call as a bare H0 record, with no journal row.
fn push_ordinary_payload(scene: &mut MachineScene, pid: u32, name: &str, sequence: u64) {
    use crate::events::record_bytes;
    use p11scope_ebpf_common::object_journal::{JournalRecord, decode_journal_record};
    use p11scope_ebpf_common::object_wire::publish_object_descriptors;
    let rows = publish_object_descriptors();
    let (_, end) = scene.scene.encoded(pid, 0, name, sequence);
    let payload = match decode_journal_record(&end, &rows) {
        Some(JournalRecord::End(end)) => end.payload_base(),
        other => panic!("{name} END decodes, got {other:?}"),
    };
    scene
        .scene
        .drain
        .source_mut()
        .push_record(record_bytes(&payload));
}

/// Stage one journaled START now; the caller holds the END bytes for
/// a later poll.
fn push_begin(scene: &mut MachineScene, pid: u32, name: &str, sequence: u64) -> [u8; 632] {
    let (begin, end) = scene.scene.encoded(pid, 0, name, sequence);
    scene.scene.drain.source_mut().push_record(begin.to_vec());
    end
}

/// Publish one empty requested quantum, leaving the demand
/// published: later quanta collect unrequested, like live traffic
/// quanta after the commit's first.
fn publish_empty_first_quantum(scene: &mut MachineScene) {
    scene.machine.begin_commit(true).unwrap();
    scene.published();
}

/// Drive until the machine leaves Collecting or 64 polls pass.
/// The first poll runs even from Idle, so a fresh quantum starts.
fn drive_collecting_quiescent(scene: &mut MachineScene) -> &'static str {
    for _ in 0..64 {
        scene.service(1).expect("quiescent service succeeds");
        if phase_of(scene) != "Collecting" {
            break;
        }
    }
    phase_of(scene)
}

/// Drive until the machine leaves Collecting; true when it closes
/// within the bound. The first poll runs even from Idle.
fn drive_until_closed(scene: &mut MachineScene, polls: usize) -> bool {
    for _ in 0..polls {
        scene.service(1).expect("close poll succeeds");
        if phase_of(scene) != "Collecting" {
            return true;
        }
    }
    false
}

/// The one staged admission, cloned before the machine consumes it.
fn cloned_only_admission(
    scene: &mut MachineScene,
) -> crate::discovery::caller_registry::instance_input::AdmittedInstanceCall {
    let coordinator = &mut scene.scene.real.scene.coordinator;
    let (prepared, _) = coordinator
        .prepared_joint_parts()
        .expect("a prepared batch stages");
    assert_eq!(
        prepared.admissions().count(),
        1,
        "exactly the modeled call admits"
    );
    prepared.admissions().next().expect("modeled call").clone()
}

/// Re-run the admission's key bind read-only in effect: success is a
/// no-op on an already-bound key, and refusal mutates nothing.
fn bind_probe_outcome(
    scene: &mut MachineScene,
    input: &crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
) -> Result<
    crate::semantics_objects::journal::JournalDomainProof,
    crate::semantics_objects::journal::AttestationRefusal,
> {
    scene
        .scene
        .real
        .scene
        .coordinator
        .joint_capture_mut()
        .adapter_mut()
        .bind_admitted_key(input)
}

/// A skewed END joins the quantum its START opened: the in-flight
/// START holds the pre-grant quantum, one quantum holds both rows,
/// the bind mints the grant, Births runs, the lane latches, and the
/// image stays untainted.
#[test]
fn joint_pregrant_skewed_end_joins_one_quantum() {
    let mut scene = pregrant_scene();
    publish_empty_first_quantum(&mut scene);
    // Model the pre-birth unlatched world (production starts
    // unlatched; test registries default latched), so the later
    // latch assertion proves the birth path latched.
    scene
        .scene
        .real
        .scene
        .coordinator
        .registry_mut()
        .note_journal_linked(false);
    let pid = std::process::id();
    push_ordinary_payload(&mut scene, pid, "C_GetFunctionList", 1);
    let init_end = push_begin(&mut scene, pid, "C_Initialize", 2);
    assert_eq!(
        drive_collecting_quiescent(&mut scene),
        "Collecting",
        "the in-flight START holds the pre-grant quantum open"
    );
    let held = raw_identity_of(&scene).expect("a held raw");
    scene
        .scene
        .drain
        .source_mut()
        .push_record(init_end.to_vec());
    assert_eq!(reach_any(&mut scene, &["BindingKeys"]), "BindingKeys");
    let input = cloned_only_admission(&mut scene);
    assert!(
        raw_identity_of(&scene) == Some(held),
        "one quantum holds both rows"
    );
    assert_eq!(reach_any(&mut scene, &["Births"]), "Births");
    assert!(
        scene.machine.retained_drain_grant_for_test().is_some(),
        "the bind mints the grant"
    );
    scene.published();
    assert!(
        scene
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .journal_linked(),
        "the birth path latches the linked lane"
    );
    assert!(
        bind_probe_outcome(&mut scene, &input).is_ok(),
        "the image stays untainted"
    );
}

/// The linked grant path (grant minted, the pre-grant flag off)
/// stages no D1 row: staging discloses nothing, the modeled call
/// reduces S1 exactly, and the grant mints. Linked producers; the
/// real unlinked ordinary capture is pinned separately below.
#[test]
fn joint_pregrant_linked_grant_path_stages_without_disclosure() {
    let mut scene = pregrant_scene();
    publish_empty_first_quantum(&mut scene);
    scene
        .scene
        .real
        .scene
        .coordinator
        .registry_mut()
        .note_journal_linked(false);
    let pid = std::process::id();
    push_ordinary_payload(&mut scene, pid, "C_GetFunctionList", 1);
    let init_end = push_begin(&mut scene, pid, "C_Initialize", 2);
    assert_eq!(
        drive_collecting_quiescent(&mut scene),
        "Collecting",
        "the in-flight START holds the pre-grant quantum open"
    );
    scene
        .scene
        .drain
        .source_mut()
        .push_record(init_end.to_vec());
    assert_eq!(reach_any(&mut scene, &["BindingKeys"]), "BindingKeys");
    assert_eq!(reach_any(&mut scene, &["Births"]), "Births");
    assert!(
        scene.machine.retained_drain_grant_for_test().is_some(),
        "the bind mints the grant, so staging runs with the flag off"
    );
    scene.published();
    let coordinator = &scene.scene.real.scene.coordinator;
    let disclosed: Vec<String> = coordinator
        .registry()
        .gaps()
        .iter()
        .filter(|gap| gap.subject == "Joint birth unavailable; retained S1")
        .map(|gap| gap.reason.clone())
        .collect();
    assert!(
        disclosed.is_empty(),
        "the birth path discloses nothing: {disclosed:?}"
    );
    let api_total: u64 = crate::semantic_capture::tests::custody_chain_tests::operation_edge_rows(
        &scene.scene.real.scene,
    )
    .iter()
    .filter_map(|row| row.0)
    .sum();
    assert_eq!(api_total, 1, "the modeled call still reduces S1");
}

/// Count-only setup records hold the pre-grant quantum across idle
/// polls until modeled work arrives, then one quantum binds it.
#[test]
fn joint_pregrant_count_only_prefix_holds_for_late_begin() {
    let mut scene = pregrant_scene();
    publish_empty_first_quantum(&mut scene);
    let pid = std::process::id();
    push_ordinary_payload(&mut scene, pid, "C_GetFunctionList", 1);
    assert_eq!(
        drive_collecting_quiescent(&mut scene),
        "Collecting",
        "count-only setup records hold the pre-grant quantum open"
    );
    let held = raw_identity_of(&scene).expect("a held raw");
    for _ in 0..8 {
        scene.service(1).expect("idle poll succeeds");
    }
    assert_eq!(
        phase_of(&scene),
        "Collecting",
        "the pause extends, never closes"
    );
    assert!(
        raw_identity_of(&scene) == Some(held),
        "the pause keeps one quantum"
    );
    let init_end = push_begin(&mut scene, pid, "C_Initialize", 2);
    scene
        .scene
        .drain
        .source_mut()
        .push_record(init_end.to_vec());
    assert_eq!(reach_any(&mut scene, &["BindingKeys"]), "BindingKeys");
    let input = cloned_only_admission(&mut scene);
    assert!(
        raw_identity_of(&scene) == Some(held),
        "one quantum holds the late call"
    );
    assert_eq!(reach_any(&mut scene, &["Births"]), "Births");
    assert!(
        scene.machine.retained_drain_grant_for_test().is_some(),
        "the late bind mints the grant"
    );
    scene.published();
    assert!(
        bind_probe_outcome(&mut scene, &input).is_ok(),
        "the image stays untainted"
    );
}

/// The wall-time bound closes an extended quantum: disposal taints,
/// the next bind discloses its taint refusal, the label reads
/// linked-bootstrap, S1 still reduces, and no grant mints.
#[test]
fn joint_pregrant_timeout_closes_and_discloses_tainted_birth() {
    use crate::semantics_objects::journal::AttestationRefusal;
    let mut scene = pregrant_scene();
    publish_empty_first_quantum(&mut scene);
    let pid = std::process::id();
    push_ordinary_payload(&mut scene, pid, "C_GetFunctionList", 1);
    let init_end = push_begin(&mut scene, pid, "C_Initialize", 2);
    assert_eq!(
        drive_collecting_quiescent(&mut scene),
        "Collecting",
        "the START holds first"
    );
    scene.machine.pose_pregrant_close_timeout_for_test(true);
    assert!(
        drive_until_closed(&mut scene, 64),
        "the expired bound closes the extended quantum"
    );
    scene.published();
    scene
        .scene
        .drain
        .source_mut()
        .push_record(init_end.to_vec());
    assert_eq!(reach_any(&mut scene, &["BindingKeys"]), "BindingKeys");
    let input = cloned_only_admission(&mut scene);
    scene.published();
    assert!(
        scene.machine.retained_drain_grant_for_test().is_none(),
        "the tainted bind mints no grant"
    );
    let outcome = bind_probe_outcome(&mut scene, &input);
    assert!(
        matches!(outcome, Err(AttestationRefusal::ImageTainted)),
        "disposal tainted the image: {outcome:?}"
    );
    let coordinator = &scene.scene.real.scene.coordinator;
    let reasons: Vec<String> = coordinator
        .registry()
        .gaps()
        .iter()
        .filter(|gap| gap.subject == "Joint birth unavailable; retained S1")
        .map(|gap| gap.reason.clone())
        .collect();
    assert_eq!(
        reasons,
        vec!["joint_birth_claim_ImageTainted".to_string()],
        "the refused bind discloses its cause"
    );
    // The init-time latch with the producers' value. The machine twin
    // cannot run the live init path, so it replicates the latch input
    // exactly; the privileged twin pins the production call site.
    let linked = scene.scene.producers.journal_linked();
    assert!(linked, "the twin runs linked producers");
    scene
        .scene
        .real
        .scene
        .coordinator
        .registry_mut()
        .note_journal_linked(linked);
    let registry = scene.scene.real.scene.coordinator.registry();
    let observations = registry.joint_observations(registry.published_revision());
    assert_eq!(observations.reason, "bootstrap_unavailable");
    let api_total: u64 = crate::semantic_capture::tests::custody_chain_tests::operation_edge_rows(
        &scene.scene.real.scene,
    )
    .iter()
    .filter_map(|row| row.0)
    .sum();
    assert_eq!(api_total, 1, "the modeled call still reduces S1");
}

/// The real 2 s timeout, without the pose seam: an open START holds
/// the quantum, then a backdated first-poll stamp trips the actual
/// wall-time comparison — the quantum closes, disposal taints, the
/// next bind discloses ImageTainted, the label reads
/// linked-bootstrap, S1 still reduces, and no grant mints. Kills a
/// clock-comparison mutant the posed twin cannot see.
#[test]
fn joint_pregrant_real_timeout_closes_and_taints() {
    use crate::semantics_objects::journal::AttestationRefusal;
    let mut scene = pregrant_scene();
    publish_empty_first_quantum(&mut scene);
    let pid = std::process::id();
    push_ordinary_payload(&mut scene, pid, "C_GetFunctionList", 1);
    let init_end = push_begin(&mut scene, pid, "C_Initialize", 2);
    assert_eq!(
        drive_collecting_quiescent(&mut scene),
        "Collecting",
        "the START holds first"
    );
    // Exactly the bound (PREGRANT_CLOSE_TIMEOUT): the comparison is
    // `elapsed >= bound`, so the backdated stamp trips it on the
    // next poll through the real clock.
    scene.machine.set_pregrant_first_poll_for_test(Some(
        std::time::Instant::now() - std::time::Duration::from_secs(2),
    ));
    assert!(
        drive_until_closed(&mut scene, 64),
        "the expired bound closes the extended quantum"
    );
    scene.published();
    scene
        .scene
        .drain
        .source_mut()
        .push_record(init_end.to_vec());
    assert_eq!(reach_any(&mut scene, &["BindingKeys"]), "BindingKeys");
    let input = cloned_only_admission(&mut scene);
    scene.published();
    assert!(
        scene.machine.retained_drain_grant_for_test().is_none(),
        "the tainted bind mints no grant"
    );
    let outcome = bind_probe_outcome(&mut scene, &input);
    assert!(
        matches!(outcome, Err(AttestationRefusal::ImageTainted)),
        "disposal tainted the image: {outcome:?}"
    );
    let coordinator = &scene.scene.real.scene.coordinator;
    let reasons: Vec<String> = coordinator
        .registry()
        .gaps()
        .iter()
        .filter(|gap| gap.subject == "Joint birth unavailable; retained S1")
        .map(|gap| gap.reason.clone())
        .collect();
    assert_eq!(
        reasons,
        vec!["joint_birth_claim_ImageTainted".to_string()],
        "the refused bind discloses its cause"
    );
    let linked = scene.scene.producers.journal_linked();
    assert!(linked, "the twin runs linked producers");
    scene
        .scene
        .real
        .scene
        .coordinator
        .registry_mut()
        .note_journal_linked(linked);
    let registry = scene.scene.real.scene.coordinator.registry();
    let observations = registry.joint_observations(registry.published_revision());
    assert_eq!(observations.reason, "bootstrap_unavailable");
    let api_total: u64 = crate::semantic_capture::tests::custody_chain_tests::operation_edge_rows(
        &scene.scene.real.scene,
    )
    .iter()
    .filter_map(|row| row.0)
    .sum();
    assert_eq!(api_total, 1, "the modeled call still reduces S1");
}

/// Close-reason counter (Opus F4): it names each pre-grant linked
/// close. The timeout flow closes twice: the empty first quantum by
/// request, the held quantum by timeout; nothing else counts, and
/// the counts change no decision.
#[test]
fn joint_pregrant_close_reasons_counted() {
    let mut scene = pregrant_scene();
    publish_empty_first_quantum(&mut scene);
    let pid = std::process::id();
    push_ordinary_payload(&mut scene, pid, "C_GetFunctionList", 1);
    let _init_end = push_begin(&mut scene, pid, "C_Initialize", 2);
    assert_eq!(
        drive_collecting_quiescent(&mut scene),
        "Collecting",
        "the START holds first"
    );
    scene.machine.pose_pregrant_close_timeout_for_test(true);
    assert!(
        drive_until_closed(&mut scene, 64),
        "the expired bound closes the extended quantum"
    );
    let counts = scene.machine.pregrant_close_counts_for_test();
    assert_eq!(
        counts.request, 1,
        "the empty first quantum closes by request"
    );
    assert_eq!(counts.timeout, 1, "the held quantum closes by timeout");
    assert_eq!(counts.raw_capacity, 0, "no RAW close");
    assert_eq!(counts.max_pending, 0, "no MAX_PENDING close");
    assert_eq!(counts.q, 0, "no Q close");
    assert_eq!(counts.custody, 0, "no custody close");
    assert_eq!(counts.begin_table, 0, "no table close");
    assert_eq!(counts.no_hold, 0, "no idle close");
}

/// F4: a pre-grant admission whose caller has a pending exit stages
/// no D1 gap — the custody conversion wins and the peek skips the
/// disclosure, so the input stages exactly the custody refusal and
/// reduces no S1. Same taint setup as the timeout twin.
#[test]
fn joint_pregrant_custody_refused_input_stages_no_d1_gap() {
    let mut scene = pregrant_scene();
    publish_empty_first_quantum(&mut scene);
    let pid = std::process::id();
    push_ordinary_payload(&mut scene, pid, "C_GetFunctionList", 1);
    let init_end = push_begin(&mut scene, pid, "C_Initialize", 2);
    assert_eq!(
        drive_collecting_quiescent(&mut scene),
        "Collecting",
        "the START holds first"
    );
    scene.machine.pose_pregrant_close_timeout_for_test(true);
    assert!(
        drive_until_closed(&mut scene, 64),
        "the expired bound closes the extended quantum"
    );
    scene.published();
    scene
        .scene
        .drain
        .source_mut()
        .push_record(init_end.to_vec());
    assert_eq!(reach_any(&mut scene, &["BindingKeys"]), "BindingKeys");
    let input = cloned_only_admission(&mut scene);
    assert!(
        bind_probe_outcome(&mut scene, &input).is_err(),
        "the disposed quantum tainted the image, so the peek would disclose"
    );
    // The exit lands after admission but before staging — the F4
    // conjunction: the staged input is Ok, the probe refuses, and the
    // staging conversion turns custody at the same time.
    let caller = scene
        .scene
        .real
        .scene
        .coordinator
        .adapter()
        .live_id(pid)
        .expect("an admitted caller");
    scene
        .scene
        .real
        .scene
        .coordinator
        .adapter_mut()
        .mark_leader_exit_pending(caller, true);
    scene.published();
    assert!(
        scene.machine.retained_drain_grant_for_test().is_none(),
        "the tainted bind mints no grant"
    );
    let coordinator = &scene.scene.real.scene.coordinator;
    let d1: Vec<&str> = coordinator
        .registry()
        .gaps()
        .iter()
        .filter(|gap| gap.subject == "Joint birth unavailable; retained S1")
        .map(|gap| gap.reason.as_str())
        .collect();
    assert!(
        d1.is_empty(),
        "a custody-refused input stages no D1 gap: {d1:?}"
    );
    // The quantum-1 setup staging also refuses with Slot (pre-existing,
    // unasserted in the timeout twin too); the F4 shape is the custody
    // reason appearing exactly once, with no D1 companion.
    let custody: Vec<&str> = coordinator
        .registry()
        .gaps()
        .iter()
        .filter(|gap| gap.subject == "semantic input refused" && gap.reason == "custody")
        .map(|gap| gap.reason.as_str())
        .collect();
    assert_eq!(
        custody,
        vec!["custody"],
        "exactly one custody refusal stages"
    );
    let api_total: u64 = crate::semantic_capture::tests::custody_chain_tests::operation_edge_rows(
        &scene.scene.real.scene,
    )
    .iter()
    .filter_map(|row| row.0)
    .sum();
    assert_eq!(api_total, 0, "the refused call reduces no S1");
}

/// The H0 pending cap closes an extending quantum at the bound: the
/// open START holds below it, and the close lands exactly on it.
#[test]
fn joint_pregrant_pending_capacity_closes_during_extension() {
    use crate::discovery::instances::MAX_PENDING;
    use crate::events::record_bytes;
    use p11scope_ebpf_common::object_journal::{JournalRecord, decode_journal_record};
    use p11scope_ebpf_common::object_wire::publish_object_descriptors;
    let mut scene = pregrant_scene();
    let pid = std::process::id();
    let rows = publish_object_descriptors();
    let (_, end) = scene.scene.encoded(pid, 0, "C_GetFunctionList", 1);
    let payload = match decode_journal_record(&end, &rows) {
        Some(JournalRecord::End(end)) => end.payload_base(),
        other => panic!("setup END decodes, got {other:?}"),
    };
    let bytes = record_bytes(&payload);
    publish_empty_first_quantum(&mut scene);
    scene.scene.drain.source_mut().bound = 4_096;
    let _init_end = push_begin(&mut scene, pid, "C_Initialize", 2);
    for chunk in 0..5 {
        for _ in 0..200 {
            scene.scene.drain.source_mut().push_record(bytes.clone());
        }
        scene.service(100_000).expect("chunk collects");
        assert_eq!(
            phase_of(&scene),
            "Collecting",
            "chunk {chunk} extends below the bound"
        );
    }
    for _ in 0..24 {
        scene.scene.drain.source_mut().push_record(bytes.clone());
    }
    assert!(
        drive_until_closed(&mut scene, 256),
        "the pending cap closes the extended quantum"
    );
    let raw = scene
        .machine
        .retained_raw_for_test()
        .expect("a retained raw");
    assert_eq!(
        raw.pending_h0_records(),
        MAX_PENDING,
        "the close lands exactly on the bound"
    );
    assert!(
        raw.has_open_affecting_start(),
        "the START was open: the bound closed, not idleness"
    );
}

/// A filled BEGIN table closes an extending quantum even with a
/// thousand open STARTs: the setup record keeps the no-H0 hold out
/// of the way, so only the table bound can close it.
#[test]
fn joint_pregrant_begin_table_full_closes_during_extension() {
    use crate::semantics_objects::journal::tests::{begin_bytes, function_id};
    let mut scene = pregrant_scene();
    publish_empty_first_quantum(&mut scene);
    scene.scene.drain.source_mut().bound = 4_096;
    let pid = std::process::id();
    push_ordinary_payload(&mut scene, pid, "C_GetFunctionList", 1);
    for (chunk, threads) in [1..=400, 401..=800].into_iter().enumerate() {
        for thread in threads {
            let begin = begin_bytes(thread, 1, function_id("C_SignInit"), 0);
            scene.scene.drain.source_mut().push_record(begin.to_vec());
        }
        scene.service(100_000).expect("chunk collects");
        assert_eq!(
            phase_of(&scene),
            "Collecting",
            "chunk {chunk} extends below the table bound"
        );
    }
    for thread in 801..=1_024 {
        let begin = begin_bytes(thread, 1, function_id("C_SignInit"), 0);
        scene.scene.drain.source_mut().push_record(begin.to_vec());
    }
    for _ in 0..512 {
        scene.service(1).expect("close poll succeeds");
        if phase_of(&scene) != "Collecting" {
            break;
        }
    }
    assert_ne!(
        phase_of(&scene),
        "Collecting",
        "the full BEGIN table closes despite open STARTs"
    );
    let raw = scene
        .machine
        .retained_raw_for_test()
        .expect("a retained raw");
    assert!(raw.begin_table_full_or_refused(), "the table bound engaged");
    assert!(
        raw.has_open_affecting_start(),
        "STARTs were open: the bound closed, not idleness"
    );
}

/// A refused record closes an extending quantum: the open START and
/// the count-only record would hold, but the refusal wins.
#[test]
fn joint_pregrant_refused_record_closes_during_extension() {
    let mut scene = pregrant_scene();
    publish_empty_first_quantum(&mut scene);
    let pid = std::process::id();
    push_ordinary_payload(&mut scene, pid, "C_GetFunctionList", 1);
    let _init_end = push_begin(&mut scene, pid, "C_Initialize", 2);
    let (dup_begin, _) = scene.scene.encoded(pid, 0, "C_GetFunctionList", 3);
    scene
        .scene
        .drain
        .source_mut()
        .push_record(dup_begin.to_vec());
    scene
        .scene
        .drain
        .source_mut()
        .push_record(dup_begin.to_vec());
    assert!(
        drive_until_closed(&mut scene, 64),
        "the refused record closes despite the open START"
    );
    let raw = scene
        .machine
        .retained_raw_for_test()
        .expect("a retained raw");
    assert!(raw.begin_table_full_or_refused(), "the refusal latched");
    assert!(
        raw.has_open_affecting_start(),
        "the START was open: the bound closed it"
    );
}

/// A failed collection never extends: the quantum closes on
/// today's unlocalized path — published S1-only with the adapter
/// invalidated, never tainted.
#[test]
fn joint_pregrant_failed_collection_closes_without_extension() {
    let mut scene = pregrant_scene();
    publish_empty_first_quantum(&mut scene);
    let pid = std::process::id();
    push_ordinary_payload(&mut scene, pid, "C_GetFunctionList", 1);
    let _init_end = push_begin(&mut scene, pid, "C_Initialize", 2);
    scene.scene.drain.source_mut().push_record(vec![0x5A; 100]);
    assert!(
        drive_until_closed(&mut scene, 64),
        "a failed collection never extends"
    );
    scene.published();
    assert!(
        scene
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .invalidated_for_test(),
        "the failed quantum takes today's unlocalized path: invalidated, never tainted"
    );
}

/// Stop overrides the extension at once, and the finish still
/// publishes within its bound.
#[test]
fn joint_pregrant_stop_closes_and_finishes_bounded() {
    let mut scene = pregrant_scene();
    publish_empty_first_quantum(&mut scene);
    let pid = std::process::id();
    let _init_end = push_begin(&mut scene, pid, "C_Initialize", 1);
    assert_eq!(
        drive_collecting_quiescent(&mut scene),
        "Collecting",
        "the open START extends first"
    );
    scene.enable_finish_fixture(Vec::new());
    scene.begin_finish().expect("stop begins the finish");
    for _ in 0..8 {
        scene.poll_finish(1).expect("stop poll succeeds");
    }
    assert_ne!(
        phase_of(&scene),
        "Collecting",
        "stop overrides the extension at once"
    );
    for _ in 0..512 {
        if matches!(scene.poll_finish(1), Ok(JointCommitProgress::Published(_))) {
            return;
        }
    }
    panic!("the finish publishes within its bound");
}

/// An unlinked pre-grant scene with the O0 init replicated:
/// production `initialize_joint` latches the producers' linkage and,
/// unlinked, discloses the one lane row (the privileged T9 pins that
/// call site). The machine twin cannot run the live init path, so it
/// replicates both calls exactly.
fn unlinked_pregrant_scene() -> MachineScene {
    let mut scene = MachineScene::with_initial_files_and_functions(
        1,
        &[0],
        &["C_GetFunctionList", "C_Initialize"],
        true,
    );
    {
        let events = scene
            .scene
            .drain
            .consumption_cut()
            .unwrap()
            .events()
            .clone();
        scene.scene.producers = crate::attach::SessionDrainProducers::test_pair_unlinked(
            scene.scene.real.lane.domain(),
            events,
        );
        let reserve = scene
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .semantic_storage_reserver();
        scene.machine =
            crate::inventory_semantics::LiveJointMachine::new(&scene.scene.producers, &reserve)
                .unwrap();
    }
    assert!(
        !scene.scene.producers.journal_linked(),
        "the twin runs unlinked producers"
    );
    scene
        .scene
        .real
        .scene
        .coordinator
        .registry_mut()
        .note_journal_linked(false);
    scene
        .scene
        .real
        .scene
        .coordinator
        .registry_mut()
        .disclose_joint_journal_unavailable_once();
    scene
}

/// An unlinked lane never extends: the skewed quantum closes at
/// once with the same boundary, mints no grant, and keeps the
/// unlinked label.
#[test]
fn joint_pregrant_unlinked_lane_closes_without_extension() {
    let mut scene = unlinked_pregrant_scene();
    publish_empty_first_quantum(&mut scene);
    let pid = std::process::id();
    push_ordinary_payload(&mut scene, pid, "C_GetFunctionList", 1);
    let _init_end = push_begin(&mut scene, pid, "C_Initialize", 2);
    assert!(
        drive_until_closed(&mut scene, 64),
        "an unlinked lane never extends"
    );
    assert_eq!(
        scene.machine.diagnostic_snapshot_for_test().2,
        Some((2, 1)),
        "the boundary is unchanged: two wire rows, one H0 record"
    );
    scene.published();
    assert!(
        scene.machine.retained_drain_grant_for_test().is_none(),
        "no grant mints"
    );
}

/// T8 (O6-6 F1), skewed order: an unlinked lane discloses once at
/// the lane, never per birth. The skewed quantum closes at once (no
/// extension) and disposal taints, but the tainted bind stages no D1
/// row — the lane keeps its single O0 `joint_journal_unavailable`
/// row, S1 still reduces exactly, the label reads unlinked, and no
/// grant mints.
#[test]
fn joint_pregrant_unlinked_lane_discloses_with_s1_exact() {
    use crate::semantics_objects::journal::AttestationRefusal;
    let mut scene = unlinked_pregrant_scene();
    publish_empty_first_quantum(&mut scene);
    let pid = std::process::id();
    push_ordinary_payload(&mut scene, pid, "C_GetFunctionList", 1);
    let init_end = push_begin(&mut scene, pid, "C_Initialize", 2);
    assert!(
        drive_until_closed(&mut scene, 64),
        "an unlinked lane never extends"
    );
    scene.published();
    scene
        .scene
        .drain
        .source_mut()
        .push_record(init_end.to_vec());
    assert_eq!(reach_any(&mut scene, &["BindingKeys"]), "BindingKeys");
    let input = cloned_only_admission(&mut scene);
    scene.published();
    assert!(
        scene.machine.retained_drain_grant_for_test().is_none(),
        "no grant mints"
    );
    let outcome = bind_probe_outcome(&mut scene, &input);
    assert!(
        matches!(outcome, Err(AttestationRefusal::ImageTainted)),
        "disposal tainted the image: {outcome:?}"
    );
    assert_unlinked_lane_disclosure(&scene.scene.real.scene);
}

/// T8, unskewed order: the BEGIN arrives before the setup CALL in
/// the first quantum, the END still later. Same unlinked shape: one
/// lane disclosure, no D1 row, S1 exact, unlinked label, no grant.
#[test]
fn joint_pregrant_unlinked_begin_first_discloses_once_with_s1_exact() {
    use crate::semantics_objects::journal::AttestationRefusal;
    let mut scene = unlinked_pregrant_scene();
    publish_empty_first_quantum(&mut scene);
    let pid = std::process::id();
    let init_end = push_begin(&mut scene, pid, "C_Initialize", 1);
    push_ordinary_payload(&mut scene, pid, "C_GetFunctionList", 2);
    assert!(
        drive_until_closed(&mut scene, 64),
        "an unlinked lane never extends"
    );
    scene.published();
    scene
        .scene
        .drain
        .source_mut()
        .push_record(init_end.to_vec());
    assert_eq!(reach_any(&mut scene, &["BindingKeys"]), "BindingKeys");
    let input = cloned_only_admission(&mut scene);
    scene.published();
    assert!(
        scene.machine.retained_drain_grant_for_test().is_none(),
        "no grant mints"
    );
    let outcome = bind_probe_outcome(&mut scene, &input);
    assert!(
        matches!(outcome, Err(AttestationRefusal::ImageTainted)),
        "disposal tainted the image: {outcome:?}"
    );
    assert_unlinked_lane_disclosure(&scene.scene.real.scene);
}

/// The real no-flag ordinary capture: unlinked producers with bare
/// CALL rows only (no journal BEGIN/END at all). The bind succeeds
/// on the untainted image so a drain grant mints, but the Births
/// guard installs no feed; the lane keeps one disclosure, stages no
/// D1 row, reduces S1 exactly, and reads the unlinked label.
#[test]
fn joint_pregrant_unlinked_ordinary_capture_discloses_once_with_s1_exact() {
    let mut scene = unlinked_pregrant_scene();
    publish_empty_first_quantum(&mut scene);
    let pid = std::process::id();
    push_ordinary_payload(&mut scene, pid, "C_GetFunctionList", 1);
    push_ordinary_payload(&mut scene, pid, "C_Initialize", 2);
    assert!(
        drive_until_closed(&mut scene, 64),
        "an unlinked lane never extends"
    );
    scene.published();
    assert!(
        scene.machine.retained_drain_grant_for_test().is_some(),
        "the untainted bind mints the drain grant"
    );
    assert_eq!(
        scene.scene.real.scene.coordinator.registry().joint_feeds(),
        0,
        "the Births guard installs no feed on an unlinked lane"
    );
    assert_unlinked_lane_disclosure(&scene.scene.real.scene);
}

/// The honest unlinked shape: exactly one caller-less
/// `joint_journal_unavailable` row (repeats counted), no
/// per-birth "Joint birth unavailable" row, the `journal_unavailable`
/// label, and S1 reduced exactly (the one modeled call).
fn assert_unlinked_lane_disclosure(
    scene: &crate::semantic_capture::tests::custody_chain_tests::CustodyScene,
) {
    let coordinator = &scene.coordinator;
    let d1: Vec<&str> = coordinator
        .registry()
        .gaps()
        .iter()
        .filter(|gap| gap.subject == "Joint birth unavailable; retained S1")
        .map(|gap| gap.reason.as_str())
        .collect();
    assert!(
        d1.is_empty(),
        "an unlinked lane stages no per-birth D1 row: {d1:?}"
    );
    let lane_rows: u64 = coordinator
        .registry()
        .gaps()
        .iter()
        .zip(coordinator.registry().gap_repeats().iter())
        .filter(|(gap, _)| gap.caller.is_none() && gap.reason == "joint_journal_unavailable")
        .map(|(_, repeats)| *repeats)
        .sum();
    assert_eq!(lane_rows, 1, "exactly one lane disclosure");
    let registry = coordinator.registry();
    let observations = registry.joint_observations(registry.published_revision());
    assert_eq!(observations.reason, "journal_unavailable");
    let api_total: u64 =
        crate::semantic_capture::tests::custody_chain_tests::operation_edge_rows(scene)
            .iter()
            .filter_map(|row| row.0)
            .sum();
    assert_eq!(api_total, 1, "the modeled call still reduces S1");
}

/// A real client's count-only setup calls (`C_GetFunctionList`,
/// `C_GetSlotList`: ordinary H0 calls on COUNT_ONLY slots, never
/// journaled) precede its modeled work in the first linked quantum.
/// Conversion refuses them because they carry no semantic facts, but
/// the journal proves them irrelevant to object proof, so H3 disposes
/// their positions: the first seal certifies, the feed stays Joint and
/// the section populates. A shed barrier here voided the first live
/// linked `--system` seal as H3Loss and left a silent `authority_lost`.
#[test]
fn joint_machine_count_only_setup_calls_seal_populated() {
    use crate::key_operation_projection::ObsStatus;
    use crate::semantics_objects::journal::JournalGap;

    let mut scene = MachineScene::with_initial_files_and_functions(
        1,
        &[0],
        &["C_GetFunctionList", "C_GetSlotList", "C_SignInit"],
        true,
    );
    let pid = std::process::id();
    push_ordinary_payload(&mut scene, pid, "C_GetFunctionList", 1);
    push_ordinary_payload(&mut scene, pid, "C_GetSlotList", 2);
    scene.scene.push(pid, 0, "C_SignInit", 3);
    scene.scene.push(pid, 0, "C_SignInit", 4);
    scene.machine.begin_commit(true).unwrap();
    assert_eq!(reach_any(&mut scene, &["Audited"]), "Audited");
    let audit = scene
        .machine
        .diagnostic_audit_for_test()
        .map(|(gap, h3, _, floor, _)| (gap, h3, floor));
    assert!(
        !matches!(
            audit,
            Some((Some(JournalGap::H3Loss), _, _)) | Some((_, "StagedLoss", _))
        ),
        "count-only setup calls are disposed, never an H3 loss barrier: {audit:?}"
    );
    scene.published_labeled("count-only-setup", None);
    let registry = scene.scene.real.scene.coordinator.registry();
    let observations = registry.joint_observations(registry.published_revision());
    assert_eq!(
        (
            registry.joint_feeds(),
            observations.status,
            observations.reason
        ),
        (1, ObsStatus::Populated, "none"),
        "the first seal certifies across the setup calls: audit {audit:?}"
    );
}
