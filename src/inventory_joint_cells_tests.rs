// SPDX-License-Identifier: GPL-3.0-or-later
// Driver home of the Joint state×event cells (§8.7): J0–J11 ×
// {cancel, promote, held_install, replace_foreign, sigint2}, J9/J11 ×
// {stop, deadline, capture_error, sink_failure}, J16 × retire_own =
// 69 cells. The 18 J12/J13 cells stay `Deferred(R1.5)` rows (T16b),
// not ignored tests.
//
// Scenes are driver-level: a substituted lane with the retained-frame
// seam set (production jointness is the live machine, which unit
// tests cannot build; the seam drives the same driver branch),
// finished through the real H0 stop where the cell needs a
// completable finish, latched where the cell needs a disposition.
// J0–J8 share the pre-finish scene (machine phases are
// Machine-home detail); J9/J11 share the dispositioned scene with
// per-state latch reasons; J10 presets the in-flight finish; J16
// presets the post-publish retire. Every cell asserts its codes
// from the §8.7 table: R (begin once, publish once, retire once),
// O (kept until joined, held after), N (the wound-down chain), E
// (first error kept), B (B untouched), X (proof retained
// unchanged), H (reclaim once with RunStopped, never installs), T
// (typed exit: held, no join, no mint), U (the finite stop).

use super::*;

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

/// The Driver home's states: J0–J11 plus the retiring J16.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JointState {
    J0,
    J1,
    J2,
    J3,
    J4,
    J5,
    J6,
    J7,
    J8,
    J9,
    J10,
    J11,
    J16,
}

/// The Driver home's events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JointEvent {
    Stop,
    Deadline,
    Cancel,
    Promote,
    RetireOwn,
    ReplaceForeign,
    CaptureError,
    SinkFailure,
    HeldInstall,
    Sigint2,
}

/// The cell scene: an owned coordinator and display plus the state.
/// Bodies seat the lane the state prescribes and build the driver.
struct Scene {
    coordinator: InventoryCoordinator<OsProcessSource>,
    display: Display,
    state: JointState,
}

fn scene_for(state: JointState) -> Scene {
    Scene {
        coordinator: coordinator(),
        display: headless_display().display,
        state,
    }
}

/// What seating a lane observes: its domain plus the shared
/// drop, poll and join counters.
struct Seat {
    domain: NativeDomainId,
    drops: Rc<Cell<usize>>,
    polls: Rc<Cell<usize>>,
    completes: Rc<Cell<usize>>,
}

/// Seat the state-prescribed lane on a fresh driver: pre-finish
/// lanes finished with the frame held, dispositioned lanes
/// unfinished with the per-state latch, J10 finished for its
/// in-flight finish, J16 finished with the frame held. Every
/// namespace is quiesced retire-ready through the real path. Cells
/// needing another detach script build their lane by hand.
fn seat_state_lane(driver: &mut ClassicDriver<'_>, state: JointState) -> Seat {
    use crate::inventory_semantics::SemanticRefusal;
    let mut io = WindDownIo::completing();
    let drops = Rc::new(Cell::new(0));
    io.drop_spy = Some(Rc::clone(&drops));
    let polls = Rc::clone(&io.polls);
    let completes = Rc::clone(&io.completes);
    let finished = !matches!(state, JointState::J9 | JointState::J11);
    let mut lane = joint_lane(io, finished);
    match state {
        JointState::J9 => lane.note_joint_finish_failure(SemanticRefusal::Unavailable),
        JointState::J11 => lane.note_joint_finish_failure(SemanticRefusal::ProviderStorage),
        _ => {}
    }
    let domain = lane.domain();
    driver.semantic = Some(lane);
    quiesce_domain_for_retire(&mut *driver.coordinator, domain);
    Seat {
        domain,
        drops,
        polls,
        completes,
    }
}

/// Flip the winding lane's retained frame (the seal drain).
fn set_winding_frame(driver: &mut ClassicDriver<'_>, on: bool) {
    driver
        .retiring
        .as_mut()
        .expect("retiring")
        .winding
        .as_mut()
        .expect("winding")
        .lane
        .as_mut()
        .expect("lane")
        .set_test_joint_frame(on);
}

/// Record a promotion-installed lane without cancelling: the
/// promotion stays active for stop-with-install cells.
fn install_promotion_active(driver: &mut ClassicDriver<'_>) -> NativeDomainId {
    use crate::inventory_promotion::lifecycle::scripted_promotion_view_for_test;
    let display = driver.display.as_mut().expect("display");
    assert!(display.promotion_enable(CaptureId::new(11)));
    display
        .queue_promotion_request_for_test(
            scripted_promotion_view_for_test(),
            CallerId(3),
            ModuleId(5),
        )
        .expect("exact pair queues");
    let taken = display.take_promotion_request().expect("mailbox holds it");
    let domain = driver.semantic.as_ref().expect("lane").domain();
    driver.installed_promotion = Some(InstalledPromotion {
        capture: CaptureId::new(11),
        request: taken.id(),
        pair: crate::inventory_promotion::PromotionPair::new(3, 5),
    });
    domain
}

/// B waits: queued, idle, nothing parked (B).
fn assert_b_untouched(driver: &mut ClassicDriver<'_>) {
    assert_eq!(
        driver.display.as_ref().expect("display").promotion_state(),
        PromotionState::Queued,
        "B waits (B)"
    );
    assert!(
        driver.lifecycle.is_idle(),
        "B prepares nothing (B)"
    );
    assert!(
        driver.pending_install.is_none(),
        "B parks nothing (B)"
    );
}

/// J0–J8 × cancel (R O): the cancel winds A down through the real
/// stopping leg; the finish begins once, completes once, retires
/// once, and the lane is kept until joined.
fn cancel_pre_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Cancel));
    assert!(matches!(
        scene.state,
        JointState::J0
            | JointState::J1
            | JointState::J2
            | JointState::J3
            | JointState::J4
            | JointState::J5
            | JointState::J6
            | JointState::J7
            | JointState::J8
    ));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let seat = seat_state_lane(&mut driver, state);
    install_promotion_for_wind_down(&mut driver);
    let (source, _, _) = CountingSource::scripted(Some(
        SessionNativeCompletion::scripted(seat.domain),
    ));
    driver.completion_source = Some(Box::new(source));
    driver.on_tick();
    assert_eq!(driver.joint_begin_calls, 1, "R: the finish begins once");
    assert_eq!(
        driver
            .retiring
            .as_ref()
            .expect("retiring")
            .winding
            .as_ref()
            .expect("winding")
            .finish,
        JointFinishDriver::Published,
        "R: the finish publishes"
    );
    assert_eq!(
        driver.retiring_domain(),
        Some(seat.domain),
        "the held frame holds the retire"
    );
    assert_eq!(seat.drops.get(), 0, "O: the lane is kept until joined");
    set_winding_frame(&mut driver, false);
    driver.on_tick();
    assert_eq!(
        driver.retiring_domain(),
        None,
        "R: the finish completes once"
    );
    assert!(
        seat.completes.get() >= 1,
        "O: joined before release (each hold tick reaps idempotently)"
    );
    assert_eq!(seat.drops.get(), 1, "O: released after the join");
    assert_eq!(
        driver.joint_begin_calls, 1,
        "R: a further cancel never re-begins"
    );
    driver
        .coordinator
        .stage_semantic_batch(crate::inventory_semantics::SemanticBatch::scripted(
            seat.domain,
            Vec::new(),
            9,
        ));
    assert!(
        gaps(&mut driver)
            .iter()
            .any(|(subject, _)| subject == "semantic batch refused for an ended domain"),
        "R: the retired domain stays refused: {:?}",
        gaps(&mut driver)
    );
}

/// J0–J8 × promote (R O B): A completes while the queued B waits
/// untouched; B is processed only after A retires.
fn promote_pre_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Promote));
    assert!(matches!(
        scene.state,
        JointState::J0
            | JointState::J1
            | JointState::J2
            | JointState::J3
            | JointState::J4
            | JointState::J5
            | JointState::J6
            | JointState::J7
            | JointState::J8
    ));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let seat = seat_state_lane(&mut driver, state);
    install_promotion_for_wind_down(&mut driver);
    let (source, _, _) = CountingSource::scripted(Some(
        SessionNativeCompletion::scripted(seat.domain),
    ));
    driver.completion_source = Some(Box::new(source));
    driver.on_tick();
    assert_eq!(driver.joint_begin_calls, 1, "R: the finish begins once");
    queue_request(driver.display.as_mut().expect("display"));
    driver.on_tick();
    assert_eq!(
        driver.retiring_domain(),
        Some(seat.domain),
        "A holds while its frame stays live"
    );
    assert_b_untouched(&mut driver);
    assert!(
        driver.semantic.is_none(),
        "B installs nothing while A winds down (B)"
    );
    assert_eq!(seat.drops.get(), 0, "O: the lane is kept until joined");
    set_winding_frame(&mut driver, false);
    driver.on_tick();
    assert_eq!(
        driver.retiring_domain(),
        None,
        "R: the finish completes once"
    );
    assert!(
        seat.completes.get() >= 1,
        "O: joined before release (each hold tick reaps idempotently)"
    );
    assert_eq!(
        driver.display.as_ref().expect("display").promotion_state(),
        PromotionState::Refused(PromotionRefusal::ProviderUnloaded),
        "B is taken once A retired (B)"
    );
}

/// J0–J8 × held_install (R O N H): the stop begins the active
/// finish once, reclaims once with RunStopped without installing,
/// and the wound-down chain completes the lane.
fn heldinstall_pre_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::HeldInstall));
    assert!(matches!(
        scene.state,
        JointState::J0
            | JointState::J1
            | JointState::J2
            | JointState::J3
            | JointState::J4
            | JointState::J5
            | JointState::J6
            | JointState::J7
            | JointState::J8
    ));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let seat = seat_state_lane(&mut driver, state);
    install_promotion_active(&mut driver);
    driver.on_stop_requested();
    assert_eq!(driver.joint_begin_calls, 1, "R: the finish begins once");
    assert_eq!(
        driver.joint_finish,
        JointFinishDriver::Published,
        "R: the finish publishes"
    );
    assert_eq!(
        driver.reclaim_calls,
        vec![PromotionEnd::RunStopped],
        "H: the held install reclaims once with RunStopped"
    );
    assert!(
        driver.pending_install.is_none(),
        "H: nothing installs after the stop"
    );
    assert!(
        driver.semantic.as_ref().is_some_and(|lane| lane.domain() == seat.domain),
        "H: the live lane stays A"
    );
    assert_eq!(seat.drops.get(), 0, "O: the lane is kept until joined");
    driver.on_lane_stopped();
    assert_eq!(seat.completes.get(), 1, "N: one joined receipt");
    assert!(
        driver.semantic.is_none(),
        "N: the wound-down lane completes"
    );
    assert_eq!(seat.drops.get(), 1, "O: released after the join");
    assert_eq!(driver.joint_begin_calls, 1, "R: never re-begun");
}

/// J0–J8 × sigint2 (O T): the second stop holds the lane through
/// the typed exit: no join, no mint.
fn sigint2_pre_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Sigint2));
    assert!(matches!(
        scene.state,
        JointState::J0
            | JointState::J1
            | JointState::J2
            | JointState::J3
            | JointState::J4
            | JointState::J5
            | JointState::J6
            | JointState::J7
            | JointState::J8
    ));
    let Scene {
        mut coordinator,
        display,
        ..
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let (io, gate) = WindDownIo::gated();
    let polls = Rc::clone(&io.polls);
    let drops = Rc::new(Cell::new(0));
    let mut io = io;
    io.drop_spy = Some(Rc::clone(&drops));
    driver.semantic = Some(joint_lane(io, true));
    let (source, mint_polls, _) = CountingSource::scripted(None);
    driver.completion_source = Some(Box::new(source));
    driver.on_stop_requested();
    assert_eq!(
        driver.joint_finish,
        JointFinishDriver::Published,
        "the first stop publishes"
    );
    driver.on_stop_requested();
    assert_eq!(
        driver.joint_finish,
        JointFinishDriver::Abandoned,
        "the second stop takes the typed exit"
    );
    assert!(driver.semantic.is_none(), "O: the lane is held");
    assert_eq!(drops.get(), 0, "O: held means never dropped");
    assert_eq!(mint_polls.load(Ordering::SeqCst), 0, "T: no mint");
    let polls_at_hold = polls.get();
    release_gate(&gate);
    driver.on_tick();
    driver.on_tick();
    assert_eq!(
        polls.get(),
        polls_at_hold,
        "T: nothing joins after the hold"
    );
    assert!(
        gaps(&mut driver)
            .iter()
            .any(|(subject, _)| subject == "joint finish held for exit"),
        "T: the typed exit records honestly: {:?}",
        gaps(&mut driver)
    );
    assert!(
        gaps(&mut driver)
            .iter()
            .all(|(subject, _)| subject != "joint finish abandoned for exit"),
        "a finished lane skips the abandon: {:?}",
        gaps(&mut driver)
    );
}

/// J9/J11 × cancel (O E): the cancel abandons the dispositioned
/// finish and holds its owner with the first error kept.
fn cancel_disp_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Cancel));
    assert!(matches!(scene.state, JointState::J9 | JointState::J11));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let seat = seat_state_lane(&mut driver, state);
    install_promotion_for_wind_down(&mut driver);
    let (source, mint_polls, _) = CountingSource::scripted(None);
    driver.completion_source = Some(Box::new(source));
    driver.on_tick();
    let winding = driver
        .retiring
        .as_ref()
        .expect("retiring")
        .winding
        .as_ref()
        .expect("the abandoned finish stays winding");
    assert_eq!(
        winding.finish,
        JointFinishDriver::Abandoned,
        "a dispositioned begin abandons"
    );
    assert!(winding.lane.is_none(), "O: the lane is held");
    assert_eq!(seat.drops.get(), 0, "O: held means never dropped");
    assert_eq!(
        driver.joint_first_error.as_deref(),
        Some("joint finish disposition required"),
        "E: the first error is kept"
    );
    assert_eq!(mint_polls.load(Ordering::SeqCst), 0, "no mint on abandon");
    let abandons: Vec<(String, String)> = gaps(&mut driver)
        .into_iter()
        .filter(|(subject, _)| subject == "joint finish abandoned for exit")
        .collect();
    assert_eq!(
        abandons.len(),
        1,
        "exactly one abandon gap: {:?}",
        gaps(&mut driver)
    );
    assert_eq!(
        abandons[0].1, "joint finish disposition required",
        "E: the gap carries the first error"
    );
}

/// J9/J11 × promote (O E B): the dispositioned finish abandons
/// while the queued B waits untouched.
fn promote_disp_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Promote));
    assert!(matches!(scene.state, JointState::J9 | JointState::J11));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let seat = seat_state_lane(&mut driver, state);
    install_promotion_for_wind_down(&mut driver);
    driver.on_tick();
    let winding = driver
        .retiring
        .as_ref()
        .expect("retiring")
        .winding
        .as_ref()
        .expect("the abandoned finish stays winding");
    assert_eq!(winding.finish, JointFinishDriver::Abandoned);
    assert!(winding.lane.is_none(), "O: the lane is held");
    assert_eq!(seat.drops.get(), 0, "O: held means never dropped");
    assert_eq!(
        driver.joint_first_error.as_deref(),
        Some("joint finish disposition required"),
        "E: the first error is kept"
    );
    queue_request(driver.display.as_mut().expect("display"));
    for _ in 0..3 {
        driver.on_tick();
    }
    assert_b_untouched(&mut driver);
    assert!(
        driver.semantic.is_none(),
        "B installs nothing behind the abandoned finish (B)"
    );
}

/// J9/J11 × held_install (U H): the stop abandons through the
/// finite stop and reclaims once with RunStopped.
fn heldinstall_disp_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::HeldInstall));
    assert!(matches!(scene.state, JointState::J9 | JointState::J11));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let seat = seat_state_lane(&mut driver, state);
    install_promotion_active(&mut driver);
    let (source, mint_polls, _) = CountingSource::scripted(None);
    driver.completion_source = Some(Box::new(source));
    driver.on_stop_requested();
    assert_eq!(
        driver.joint_finish,
        JointFinishDriver::Abandoned,
        "U: the dispositioned stop abandons"
    );
    assert!(driver.semantic.is_none(), "U: the lane is held");
    assert_eq!(seat.drops.get(), 0, "U: held means never dropped");
    assert!(
        driver.joint_first_error.is_some(),
        "U: the first error is kept"
    );
    assert_eq!(mint_polls.load(Ordering::SeqCst), 0, "U: no mint");
    assert!(
        gaps(&mut driver)
            .iter()
            .any(|(subject, _)| subject == "joint finish abandoned for exit"),
        "U: the abandon records honestly: {:?}",
        gaps(&mut driver)
    );
    assert_eq!(
        driver.reclaim_calls,
        vec![PromotionEnd::RunStopped],
        "H: the held install reclaims once with RunStopped"
    );
    assert!(
        driver.pending_install.is_none(),
        "H: nothing installs after the stop"
    );
}

/// J9/J11 × sigint2 (O T E): the first stop already abandons; the
/// second changes nothing: held, unjoined, unminted, first error.
fn sigint2_disp_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Sigint2));
    assert!(matches!(scene.state, JointState::J9 | JointState::J11));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let seat = seat_state_lane(&mut driver, state);
    let (source, mint_polls, _) = CountingSource::scripted(None);
    driver.completion_source = Some(Box::new(source));
    driver.on_stop_requested();
    assert_eq!(driver.joint_finish, JointFinishDriver::Abandoned);
    assert!(driver.semantic.is_none(), "O: the lane is held");
    driver.on_stop_requested();
    assert_eq!(
        driver.joint_finish,
        JointFinishDriver::Abandoned,
        "the second stop changes nothing"
    );
    assert_eq!(seat.drops.get(), 0, "O: held means never dropped");
    assert_eq!(seat.polls.get(), 0, "T: the detach is never even reaped");
    assert_eq!(mint_polls.load(Ordering::SeqCst), 0, "T: no mint");
    assert_eq!(
        driver.joint_first_error.as_deref(),
        Some("joint finish disposition required"),
        "E: the first error is kept"
    );
}

/// J9/J11 × stop (U E): the bare stop abandons the dispositioned
/// finish with the first error kept.
fn stop_disp_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Stop));
    assert!(matches!(scene.state, JointState::J9 | JointState::J11));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let seat = seat_state_lane(&mut driver, state);
    let (source, mint_polls, _) = CountingSource::scripted(None);
    driver.completion_source = Some(Box::new(source));
    driver.on_stop_requested();
    assert_eq!(
        driver.joint_finish,
        JointFinishDriver::Abandoned,
        "U: the dispositioned stop abandons"
    );
    assert!(driver.semantic.is_none(), "U: the lane is held");
    assert_eq!(seat.drops.get(), 0, "U: held means never dropped");
    assert_eq!(
        driver.joint_first_error.as_deref(),
        Some("joint finish disposition required"),
        "E: the first error is kept"
    );
    assert_eq!(mint_polls.load(Ordering::SeqCst), 0, "U: no mint");
    assert!(
        gaps(&mut driver)
            .iter()
            .any(|(subject, _)| subject == "joint finish abandoned for exit"),
        "U: the abandon records honestly: {:?}",
        gaps(&mut driver)
    );
}

/// J9/J11 × deadline (U E): like stop; the Deadline cause-once is
/// machine-owned, so the driver twins stop.
fn deadline_disp_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Deadline));
    assert!(matches!(scene.state, JointState::J9 | JointState::J11));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let seat = seat_state_lane(&mut driver, state);
    driver.deadline = Some(Instant::now() - Duration::from_secs(1));
    driver.on_stop_requested();
    assert_eq!(
        driver.joint_finish,
        JointFinishDriver::Abandoned,
        "U: the expired deadline abandons"
    );
    assert!(driver.semantic.is_none(), "U: the lane is held");
    assert_eq!(seat.drops.get(), 0, "U: held means never dropped");
    assert!(
        driver.joint_first_error.is_some(),
        "E: the first error is kept"
    );
}

/// J9/J11 × capture_error (U E): the capture failure is the first
/// error the finite stop keeps.
fn capture_disp_body(scene: Scene, event: JointEvent) {
    use crate::inventory_semantics::SemanticRefusal;
    assert!(matches!(event, JointEvent::CaptureError));
    assert!(matches!(scene.state, JointState::J9 | JointState::J11));
    let Scene {
        mut coordinator,
        display,
        ..
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let mut lane = joint_lane(WindDownIo::completing(), false);
    lane.note_joint_finish_failure(SemanticRefusal::Attachment);
    driver.semantic = Some(lane);
    driver.on_stop_requested();
    assert_eq!(
        driver.joint_finish,
        JointFinishDriver::Abandoned,
        "U: the capture failure abandons"
    );
    assert!(driver.semantic.is_none(), "U: the lane is held");
    assert!(
        driver.joint_first_error.is_some(),
        "E: the first error is kept"
    );
    let abandons: Vec<(String, String)> = gaps(&mut driver)
        .into_iter()
        .filter(|(subject, _)| subject == "joint finish abandoned for exit")
        .collect();
    assert_eq!(
        abandons.len(),
        1,
        "exactly one abandon gap: {:?}",
        gaps(&mut driver)
    );
}

/// J9/J11 × sink_failure (U E): the sink failure is the first
/// error the finite stop keeps.
fn sink_disp_body(scene: Scene, event: JointEvent) {
    use crate::inventory_semantics::SemanticRefusal;
    assert!(matches!(event, JointEvent::SinkFailure));
    assert!(matches!(scene.state, JointState::J9 | JointState::J11));
    let Scene {
        mut coordinator,
        display,
        ..
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let mut lane = joint_lane(WindDownIo::completing(), false);
    lane.note_joint_finish_failure(SemanticRefusal::ProviderStorage);
    driver.semantic = Some(lane);
    driver.on_stop_requested();
    assert_eq!(
        driver.joint_finish,
        JointFinishDriver::Abandoned,
        "U: the sink failure abandons"
    );
    assert!(driver.semantic.is_none(), "U: the lane is held");
    assert!(
        driver.joint_first_error.is_some(),
        "E: the first error is kept"
    );
    let abandons: Vec<(String, String)> = gaps(&mut driver)
        .into_iter()
        .filter(|(subject, _)| subject == "joint finish abandoned for exit")
        .collect();
    assert_eq!(
        abandons.len(),
        1,
        "exactly one abandon gap: {:?}",
        gaps(&mut driver)
    );
}

/// J10 × cancel (O): a re-cancel during A's in-flight promotion
/// finish is a no-op; the finish is kept, never re-begun, never
/// completed, never abandoned. (A cancel cannot reach a preset
/// in-flight final finish through ticks: item 9 gates those hooks,
/// so the in-flight promotion finish is the coherent reading.)
fn cancel_graph_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Cancel));
    assert!(matches!(scene.state, JointState::J10));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let seat = seat_state_lane(&mut driver, state);
    install_promotion_for_wind_down(&mut driver);
    driver.on_tick();
    assert_eq!(driver.joint_begin_calls, 1, "A's finish begins once");
    assert!(
        driver.coordinator.promotion_finish(),
        "A's promotion finish holds its flag"
    );
    // In-flight (live-machine behavior the substituted begin skips).
    driver
        .retiring
        .as_mut()
        .expect("retiring")
        .winding
        .as_mut()
        .expect("winding")
        .finish = JointFinishDriver::Polling;
    let (source, mint_polls, _) = CountingSource::scripted(None);
    driver.completion_source = Some(Box::new(source));
    assert_eq!(
        driver.display.as_mut().expect("display").cancel_promotion_for_test(),
        crate::inventory_promotion::PromotionCancel::NothingToCancel,
        "the re-cancel during the wind-down is a no-op"
    );
    for _ in 0..3 {
        driver.on_tick();
    }
    assert_eq!(
        driver.retiring_domain(),
        Some(seat.domain),
        "O: the lane is kept, never completed"
    );
    assert_eq!(
        driver
            .retiring
            .as_ref()
            .expect("retiring")
            .winding
            .as_ref()
            .expect("winding")
            .finish,
        JointFinishDriver::Polling,
        "O-only: never abandoned"
    );
    assert_eq!(driver.joint_begin_calls, 1, "never re-begun");
    assert_eq!(seat.drops.get(), 0, "O: the lane is kept");
    assert_eq!(mint_polls.load(Ordering::SeqCst), 0, "O-only: no mint");
    // The transfer arm: a wind-down that meets an in-flight finish
    // moves its state into the winding untouched (called directly:
    // item 9 would gate its ticks, so this arm is begin-once safety,
    // not tick flow).
    {
        let mut coordinator2 = super::coordinator();
        let headless2 = super::headless_display();
        let mut driver2 = super::driver_with_display(&mut coordinator2, headless2.display);
        let _ = seat_state_lane(&mut driver2, state);
        driver2.joint_finish = JointFinishDriver::Polling;
        install_promotion_for_wind_down(&mut driver2);
        driver2.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert_eq!(
            driver2.joint_begin_calls, 0,
            "the transfer never re-begins"
        );
        assert_eq!(
            driver2
                .retiring
                .as_ref()
                .expect("retiring")
                .winding
                .as_ref()
                .expect("winding")
                .finish,
            JointFinishDriver::Polling,
            "the in-flight state transfers into the winding"
        );
        assert_eq!(
            driver2.joint_finish,
            JointFinishDriver::NotBegun,
            "the driver state resets for full ticks"
        );
        assert!(
            !driver2.coordinator.promotion_finish(),
            "the transfer preserves the flag"
        );
    }
}

/// J10 × promote (O B): the in-flight finish is kept while B waits.
fn promote_graph_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Promote));
    assert!(matches!(scene.state, JointState::J10));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let seat = seat_state_lane(&mut driver, state);
    install_promotion_for_wind_down(&mut driver);
    driver.on_tick();
    assert_eq!(driver.joint_begin_calls, 1, "A's finish begins once");
    driver
        .retiring
        .as_mut()
        .expect("retiring")
        .winding
        .as_mut()
        .expect("winding")
        .finish = JointFinishDriver::Polling;
    queue_request(driver.display.as_mut().expect("display"));
    for _ in 0..3 {
        driver.on_tick();
    }
    assert_eq!(
        driver.retiring_domain(),
        Some(seat.domain),
        "O: the lane is kept, never completed"
    );
    assert_eq!(
        driver
            .retiring
            .as_ref()
            .expect("retiring")
            .winding
            .as_ref()
            .expect("winding")
            .finish,
        JointFinishDriver::Polling,
        "O-only: never abandoned"
    );
    assert_eq!(driver.joint_begin_calls, 1, "never re-begun");
    assert_eq!(seat.drops.get(), 0, "O: the lane is kept");
    assert_b_untouched(&mut driver);
    assert!(
        driver.semantic.is_none(),
        "B installs nothing while A winds down (B)"
    );
}

/// J10 × held_install (O H): the stop keeps the in-flight finish
/// and reclaims once with RunStopped.
fn heldinstall_graph_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::HeldInstall));
    assert!(matches!(scene.state, JointState::J10));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let seat = seat_state_lane(&mut driver, state);
    driver.joint_finish = JointFinishDriver::Polling;
    install_promotion_active(&mut driver);
    driver.on_stop_requested();
    assert_eq!(
        driver.joint_begin_calls, 0,
        "an in-flight finish never re-begins"
    );
    assert_eq!(
        driver.joint_finish,
        JointFinishDriver::Polling,
        "O: the in-flight finish stays polling"
    );
    assert!(
        driver.semantic.as_ref().is_some_and(|lane| lane.domain() == seat.domain),
        "O: the lane is kept"
    );
    assert_eq!(seat.drops.get(), 0, "O: held means kept");
    assert_eq!(
        driver.reclaim_calls,
        vec![PromotionEnd::RunStopped],
        "H: the held install reclaims once with RunStopped"
    );
    assert!(
        driver.pending_install.is_none(),
        "H: nothing installs after the stop"
    );
}

/// J10 × sigint2 (O T): the second stop holds the in-flight
/// finish: no join, no mint, no abandon on a finished lane.
fn sigint2_graph_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Sigint2));
    assert!(matches!(scene.state, JointState::J10));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let seat = seat_state_lane(&mut driver, state);
    driver.joint_finish = JointFinishDriver::Polling;
    let (source, mint_polls, _) = CountingSource::scripted(None);
    driver.completion_source = Some(Box::new(source));
    driver.on_stop_requested();
    assert_eq!(
        driver.joint_begin_calls, 0,
        "an in-flight finish never re-begins"
    );
    assert_eq!(
        driver.joint_finish,
        JointFinishDriver::Polling,
        "the first stop keeps polling"
    );
    driver.on_stop_requested();
    assert_eq!(
        driver.joint_finish,
        JointFinishDriver::Abandoned,
        "the second stop takes the typed exit"
    );
    assert!(driver.semantic.is_none(), "O: the lane is held");
    assert_eq!(seat.drops.get(), 0, "O: held means never dropped");
    assert_eq!(seat.polls.get(), 0, "T: the detach is never reaped");
    assert_eq!(mint_polls.load(Ordering::SeqCst), 0, "T: no mint");
    assert!(
        gaps(&mut driver)
            .iter()
            .any(|(subject, _)| subject == "joint finish held for exit"),
        "T: the typed exit records honestly: {:?}",
        gaps(&mut driver)
    );
    assert!(
        gaps(&mut driver)
            .iter()
            .all(|(subject, _)| subject != "joint finish abandoned for exit"),
        "a finished lane skips the abandon: {:?}",
        gaps(&mut driver)
    );
}

/// J0–J11 × replace_foreign (X O): a foreign proof for a live
/// winding holds with the completion retained unchanged; the lane
/// is kept. The retire poll runs post-publish, where no latch is
/// consulted, so all twelve states share this body.
fn replace_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::ReplaceForeign));
    assert!(matches!(
        scene.state,
        JointState::J0
            | JointState::J1
            | JointState::J2
            | JointState::J3
            | JointState::J4
            | JointState::J5
            | JointState::J6
            | JointState::J7
            | JointState::J8
            | JointState::J9
            | JointState::J10
            | JointState::J11
    ));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let seat = seat_state_lane(&mut driver, state);
    // The retire poll runs post-publish: finish the lane through the
    // real stop. J9/J11 keep their latch: Published never consults
    // it, which the absent abandon gap pins.
    let mut lane = driver.semantic.take().expect("lane");
    if !lane.is_finished() {
        let _ = lane.finish_semantic_stop();
    }
    driver.retiring = Some(RetiringDomain::winding(lane, true));
    driver
        .retiring
        .as_mut()
        .expect("retiring")
        .winding
        .as_mut()
        .expect("winding")
        .finish = JointFinishDriver::Published;
    set_winding_frame(&mut driver, false);
    let foreign = NativeDomainId::try_mint().expect("a foreign domain");
    assert_ne!(foreign, seat.domain, "the proof names another domain");
    let (source, mint_polls, _) = CountingSource::scripted(Some(
        SessionNativeCompletion::scripted(foreign),
    ));
    driver.completion_source = Some(Box::new(source));
    driver.on_tick();
    assert_eq!(
        driver.retiring_domain(),
        Some(seat.domain),
        "a foreign proof holds the live winding"
    );
    driver.on_tick();
    assert_eq!(
        mint_polls.load(Ordering::SeqCst),
        1,
        "X: the completion is retained unchanged, never re-polled"
    );
    assert_eq!(
        driver.retiring_domain(),
        Some(seat.domain),
        "the winding still holds"
    );
    assert_eq!(seat.drops.get(), 0, "O: the lane is kept");
    assert!(
        gaps(&mut driver)
            .iter()
            .all(|(subject, _)| subject != "joint finish abandoned for exit"),
        "Published never consults the latch: {:?}",
        gaps(&mut driver)
    );
    let failures: Vec<(String, String)> = gaps(&mut driver)
        .into_iter()
        .filter(|(subject, _)| subject == "selected promotion completion failed")
        .collect();
    assert_eq!(
        failures.len(),
        1,
        "exactly one foreign-proof gap: {:?}",
        gaps(&mut driver)
    );
    assert!(
        failures[0].1.contains("foreign"),
        "the gap names the foreign proof: {:?}",
        failures[0].1
    );
}

/// J16 × retire_own (ok once, then X): the drained retire succeeds
/// once; a later foreign proof for a live winding holds with its
/// proof retained unchanged.
fn retire_own_16_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::RetireOwn));
    assert!(matches!(scene.state, JointState::J16));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let seat = seat_state_lane(&mut driver, state);
    // The retire event applies post-publish with the frame drained.
    let lane = driver.semantic.take().expect("lane");
    driver.retiring = Some(RetiringDomain::winding(lane, true));
    {
        let winding = driver
            .retiring
            .as_mut()
            .expect("retiring")
            .winding
            .as_mut()
            .expect("winding");
        winding.finish = JointFinishDriver::Published;
    }
    set_winding_frame(&mut driver, false);
    let (source, mint_polls, _) = CountingSource::scripted(Some(
        SessionNativeCompletion::scripted(seat.domain),
    ));
    driver.completion_source = Some(Box::new(source));
    driver.on_tick();
    assert_eq!(
        driver.retiring_domain(),
        None,
        "the drained retire succeeds"
    );
    assert_eq!(mint_polls.load(Ordering::SeqCst), 1, "ok once: one poll, one retire");
    driver
        .coordinator
        .stage_semantic_batch(crate::inventory_semantics::SemanticBatch::scripted(
            seat.domain,
            Vec::new(),
            9,
        ));
    assert!(
        gaps(&mut driver)
            .iter()
            .any(|(subject, _)| subject == "semantic batch refused for an ended domain"),
        "the retired domain stays refused: {:?}",
        gaps(&mut driver)
    );
    // Then X: a foreign proof for another live winding holds with
    // its proof retained unchanged.
    let mut io = WindDownIo::completing();
    let drops = Rc::new(Cell::new(0));
    io.drop_spy = Some(Rc::clone(&drops));
    let mut lane = joint_lane(io, true);
    lane.set_test_joint_frame(false);
    let domain = lane.domain();
    quiesce_domain_for_retire(&mut *driver.coordinator, domain);
    driver.retiring = Some(RetiringDomain::winding(lane, true));
    driver
        .retiring
        .as_mut()
        .expect("retiring")
        .winding
        .as_mut()
        .expect("winding")
        .finish = JointFinishDriver::Published;
    let foreign = NativeDomainId::try_mint().expect("a foreign domain");
    let (source, mint_polls, _) = CountingSource::scripted(Some(
        SessionNativeCompletion::scripted(foreign),
    ));
    driver.completion_source = Some(Box::new(source));
    driver.on_tick();
    driver.on_tick();
    assert_eq!(
        mint_polls.load(Ordering::SeqCst),
        1,
        "X: the completion is retained unchanged, never re-polled"
    );
    assert_eq!(
        driver.retiring_domain(),
        Some(domain),
        "then X: the live winding holds"
    );
    assert_eq!(drops.get(), 0, "the winding lane is kept");
}

joint_cell!(
    joint_cell_j0_cancel,
    JointState::J0,
    JointEvent::Cancel,
    cancel_pre_body
);
joint_cell!(
    joint_cell_j0_promote,
    JointState::J0,
    JointEvent::Promote,
    promote_pre_body
);
joint_cell!(
    joint_cell_j0_held_install,
    JointState::J0,
    JointEvent::HeldInstall,
    heldinstall_pre_body
);
joint_cell!(
    joint_cell_j0_replace_foreign,
    JointState::J0,
    JointEvent::ReplaceForeign,
    replace_body
);
joint_cell!(
    joint_cell_j0_sigint2,
    JointState::J0,
    JointEvent::Sigint2,
    sigint2_pre_body
);
joint_cell!(
    joint_cell_j1_cancel,
    JointState::J1,
    JointEvent::Cancel,
    cancel_pre_body
);
joint_cell!(
    joint_cell_j1_promote,
    JointState::J1,
    JointEvent::Promote,
    promote_pre_body
);
joint_cell!(
    joint_cell_j1_held_install,
    JointState::J1,
    JointEvent::HeldInstall,
    heldinstall_pre_body
);
joint_cell!(
    joint_cell_j1_replace_foreign,
    JointState::J1,
    JointEvent::ReplaceForeign,
    replace_body
);
joint_cell!(
    joint_cell_j1_sigint2,
    JointState::J1,
    JointEvent::Sigint2,
    sigint2_pre_body
);
joint_cell!(
    joint_cell_j2_cancel,
    JointState::J2,
    JointEvent::Cancel,
    cancel_pre_body
);
joint_cell!(
    joint_cell_j2_promote,
    JointState::J2,
    JointEvent::Promote,
    promote_pre_body
);
joint_cell!(
    joint_cell_j2_held_install,
    JointState::J2,
    JointEvent::HeldInstall,
    heldinstall_pre_body
);
joint_cell!(
    joint_cell_j2_replace_foreign,
    JointState::J2,
    JointEvent::ReplaceForeign,
    replace_body
);
joint_cell!(
    joint_cell_j2_sigint2,
    JointState::J2,
    JointEvent::Sigint2,
    sigint2_pre_body
);
joint_cell!(
    joint_cell_j3_cancel,
    JointState::J3,
    JointEvent::Cancel,
    cancel_pre_body
);
joint_cell!(
    joint_cell_j3_promote,
    JointState::J3,
    JointEvent::Promote,
    promote_pre_body
);
joint_cell!(
    joint_cell_j3_held_install,
    JointState::J3,
    JointEvent::HeldInstall,
    heldinstall_pre_body
);
joint_cell!(
    joint_cell_j3_replace_foreign,
    JointState::J3,
    JointEvent::ReplaceForeign,
    replace_body
);
joint_cell!(
    joint_cell_j3_sigint2,
    JointState::J3,
    JointEvent::Sigint2,
    sigint2_pre_body
);
joint_cell!(
    joint_cell_j4_cancel,
    JointState::J4,
    JointEvent::Cancel,
    cancel_pre_body
);
joint_cell!(
    joint_cell_j4_promote,
    JointState::J4,
    JointEvent::Promote,
    promote_pre_body
);
joint_cell!(
    joint_cell_j4_held_install,
    JointState::J4,
    JointEvent::HeldInstall,
    heldinstall_pre_body
);
joint_cell!(
    joint_cell_j4_replace_foreign,
    JointState::J4,
    JointEvent::ReplaceForeign,
    replace_body
);
joint_cell!(
    joint_cell_j4_sigint2,
    JointState::J4,
    JointEvent::Sigint2,
    sigint2_pre_body
);
joint_cell!(
    joint_cell_j5_cancel,
    JointState::J5,
    JointEvent::Cancel,
    cancel_pre_body
);
joint_cell!(
    joint_cell_j5_promote,
    JointState::J5,
    JointEvent::Promote,
    promote_pre_body
);
joint_cell!(
    joint_cell_j5_held_install,
    JointState::J5,
    JointEvent::HeldInstall,
    heldinstall_pre_body
);
joint_cell!(
    joint_cell_j5_replace_foreign,
    JointState::J5,
    JointEvent::ReplaceForeign,
    replace_body
);
joint_cell!(
    joint_cell_j5_sigint2,
    JointState::J5,
    JointEvent::Sigint2,
    sigint2_pre_body
);
joint_cell!(
    joint_cell_j6_cancel,
    JointState::J6,
    JointEvent::Cancel,
    cancel_pre_body
);
joint_cell!(
    joint_cell_j6_promote,
    JointState::J6,
    JointEvent::Promote,
    promote_pre_body
);
joint_cell!(
    joint_cell_j6_held_install,
    JointState::J6,
    JointEvent::HeldInstall,
    heldinstall_pre_body
);
joint_cell!(
    joint_cell_j6_replace_foreign,
    JointState::J6,
    JointEvent::ReplaceForeign,
    replace_body
);
joint_cell!(
    joint_cell_j6_sigint2,
    JointState::J6,
    JointEvent::Sigint2,
    sigint2_pre_body
);
joint_cell!(
    joint_cell_j7_cancel,
    JointState::J7,
    JointEvent::Cancel,
    cancel_pre_body
);
joint_cell!(
    joint_cell_j7_promote,
    JointState::J7,
    JointEvent::Promote,
    promote_pre_body
);
joint_cell!(
    joint_cell_j7_held_install,
    JointState::J7,
    JointEvent::HeldInstall,
    heldinstall_pre_body
);
joint_cell!(
    joint_cell_j7_replace_foreign,
    JointState::J7,
    JointEvent::ReplaceForeign,
    replace_body
);
joint_cell!(
    joint_cell_j7_sigint2,
    JointState::J7,
    JointEvent::Sigint2,
    sigint2_pre_body
);
joint_cell!(
    joint_cell_j8_cancel,
    JointState::J8,
    JointEvent::Cancel,
    cancel_pre_body
);
joint_cell!(
    joint_cell_j8_promote,
    JointState::J8,
    JointEvent::Promote,
    promote_pre_body
);
joint_cell!(
    joint_cell_j8_held_install,
    JointState::J8,
    JointEvent::HeldInstall,
    heldinstall_pre_body
);
joint_cell!(
    joint_cell_j8_replace_foreign,
    JointState::J8,
    JointEvent::ReplaceForeign,
    replace_body
);
joint_cell!(
    joint_cell_j8_sigint2,
    JointState::J8,
    JointEvent::Sigint2,
    sigint2_pre_body
);
joint_cell!(
    joint_cell_j9_cancel,
    JointState::J9,
    JointEvent::Cancel,
    cancel_disp_body
);
joint_cell!(
    joint_cell_j9_promote,
    JointState::J9,
    JointEvent::Promote,
    promote_disp_body
);
joint_cell!(
    joint_cell_j9_held_install,
    JointState::J9,
    JointEvent::HeldInstall,
    heldinstall_disp_body
);
joint_cell!(
    joint_cell_j9_replace_foreign,
    JointState::J9,
    JointEvent::ReplaceForeign,
    replace_body
);
joint_cell!(
    joint_cell_j9_sigint2,
    JointState::J9,
    JointEvent::Sigint2,
    sigint2_disp_body
);
joint_cell!(
    joint_cell_j9_stop,
    JointState::J9,
    JointEvent::Stop,
    stop_disp_body
);
joint_cell!(
    joint_cell_j9_deadline,
    JointState::J9,
    JointEvent::Deadline,
    deadline_disp_body
);
joint_cell!(
    joint_cell_j9_capture_error,
    JointState::J9,
    JointEvent::CaptureError,
    capture_disp_body
);
joint_cell!(
    joint_cell_j9_sink_failure,
    JointState::J9,
    JointEvent::SinkFailure,
    sink_disp_body
);
joint_cell!(
    joint_cell_j11_cancel,
    JointState::J11,
    JointEvent::Cancel,
    cancel_disp_body
);
joint_cell!(
    joint_cell_j11_promote,
    JointState::J11,
    JointEvent::Promote,
    promote_disp_body
);
joint_cell!(
    joint_cell_j11_held_install,
    JointState::J11,
    JointEvent::HeldInstall,
    heldinstall_disp_body
);
joint_cell!(
    joint_cell_j11_replace_foreign,
    JointState::J11,
    JointEvent::ReplaceForeign,
    replace_body
);
joint_cell!(
    joint_cell_j11_sigint2,
    JointState::J11,
    JointEvent::Sigint2,
    sigint2_disp_body
);
joint_cell!(
    joint_cell_j11_stop,
    JointState::J11,
    JointEvent::Stop,
    stop_disp_body
);
joint_cell!(
    joint_cell_j11_deadline,
    JointState::J11,
    JointEvent::Deadline,
    deadline_disp_body
);
joint_cell!(
    joint_cell_j11_capture_error,
    JointState::J11,
    JointEvent::CaptureError,
    capture_disp_body
);
joint_cell!(
    joint_cell_j11_sink_failure,
    JointState::J11,
    JointEvent::SinkFailure,
    sink_disp_body
);
joint_cell!(
    joint_cell_j10_cancel,
    JointState::J10,
    JointEvent::Cancel,
    cancel_graph_body
);
joint_cell!(
    joint_cell_j10_promote,
    JointState::J10,
    JointEvent::Promote,
    promote_graph_body
);
joint_cell!(
    joint_cell_j10_held_install,
    JointState::J10,
    JointEvent::HeldInstall,
    heldinstall_graph_body
);
joint_cell!(
    joint_cell_j10_replace_foreign,
    JointState::J10,
    JointEvent::ReplaceForeign,
    replace_body
);
joint_cell!(
    joint_cell_j10_sigint2,
    JointState::J10,
    JointEvent::Sigint2,
    sigint2_graph_body
);
joint_cell!(
    joint_cell_j16_retire_own,
    JointState::J16,
    JointEvent::RetireOwn,
    retire_own_16_body
);
