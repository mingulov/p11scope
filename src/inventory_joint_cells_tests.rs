// SPDX-License-Identifier: GPL-3.0-or-later
// Driver home of the Joint state×event cells (§8.7): J0–J11 ×
// {cancel, promote, held_install, replace_foreign, sigint2}, J9/J11 ×
// {stop, deadline, capture_error, sink_failure}, J16 × retire_own,
// J12/J13 × {stop, deadline, cancel, promote, replace_foreign,
// capture_error, sink_failure, held_install, sigint2} = 87 cells.
//
// Scenes are driver-level: a substituted lane with the retained-frame
// seam set (production jointness is the live machine, which unit
// tests cannot build; the seam drives the same driver branch),
// finished through the real H0 stop where the cell needs a
// completable finish, latched where the cell needs a disposition.
// J0–J8 share the pre-finish scene (machine phases are
// Machine-home detail); J9/J11 share the dispositioned scene with
// per-state latch reasons; J10 presets the in-flight finish; J16
// presets the post-publish retire. J12/J13 retain a publication
// through the real loop — pending (flag) or failed (flag plus the
// retention error) — and drive the event against the suspended
// driver; cells whose codes exclude U retain through a polling
// finish or clear the flag once the pending commit publishes, so
// the substituted commit refusal (which unit lanes always raise)
// never invents a finite stop the codes do not claim. Every cell
// asserts its codes from the §8.7 table: R (begin once, publish
// once, retire once), O (kept until joined, held after), N (the
// wound-down chain), E (first error kept), B (B untouched), X
// (proof retained unchanged), H (reclaim once with RunStopped,
// never installs), T (typed exit: held, no join, no mint), U (the
// finite stop), P (no commit replay, attempt 1), G (the suspension
// gate does no terminal I/O).

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

/// The Driver home's states: J0–J11 plus the retiring J16 and the
/// retained publications J12/J13.
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
    J12,
    J13,
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

/// The J11 graph refusal planted in the engine: the hold prefers a
/// recorded terminal graph refusal over the default abandon reason
/// (§6.4), so J11's first error is this text, not the default.
const GRAPH_REFUSAL_J11: &str = "terminal graph refused before native mutation";

/// The exact first error a dispositioned (J9/J11) abandon keeps:
/// J9 the default reason, J11 its recorded graph refusal.
fn expected_disp_first_error(state: JointState) -> &'static str {
    match state {
        JointState::J11 => GRAPH_REFUSAL_J11,
        _ => "joint finish disposition required",
    }
}

/// Seat the state-prescribed lane on a fresh driver: pre-finish
/// lanes finished with the frame held, dispositioned lanes
/// unfinished with the per-state latch, J10 unfinished with a
/// scripted in-flight finish (begin Ok, polls Pending), J16
/// finished with the frame held. Every namespace is quiesced
/// retire-ready through the real path. Cells needing another
/// detach script build their lane by hand.
fn seat_state_lane(driver: &mut ClassicDriver<'_>, state: JointState) -> Seat {
    use crate::inventory_semantics::SemanticRefusal;
    let mut io = WindDownIo::completing();
    let drops = Rc::new(Cell::new(0));
    io.drop_spy = Some(Rc::clone(&drops));
    let polls = Rc::clone(&io.polls);
    let completes = Rc::clone(&io.completes);
    let finished = !matches!(
        state,
        JointState::J9 | JointState::J10 | JointState::J11
    );
    let mut lane = joint_lane(io, finished);
    match state {
        JointState::J9 => lane.note_joint_finish_failure(SemanticRefusal::Unavailable),
        JointState::J10 => {
            lane.set_scripted_finish_begin_for_test(Some(Ok(())));
            lane.set_scripted_finish_poll_for_test(Some(Ok(JointCommitProgress::Pending)));
        }
        JointState::J11 => {
            lane.note_joint_finish_failure(SemanticRefusal::ProviderStorage);
            // J11 is a real engine graph refusal, not just a latch:
            // the machine latched from its failed progress, and the
            // hold prefers the recorded refusal text (§6.4).
            driver
                .coordinator
                .seed_collected_graph_refusal_for_test(GRAPH_REFUSAL_J11);
        }
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
        ..
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    // Gated detach: the cancel winds A down through the real
    // stopping leg while the seal drains; the drained retry retires
    // on one joined receipt.
    let (io, gate) = WindDownIo::gated();
    let submits = Rc::clone(&io.submits);
    let completes = Rc::clone(&io.completes);
    let drops = Rc::new(Cell::new(0));
    let mut io = io;
    io.drop_spy = Some(Rc::clone(&drops));
    driver.semantic = Some(joint_lane(io, true));
    let domain = install_promotion_for_wind_down(&mut driver);
    quiesce_domain_for_retire(&mut *driver.coordinator, domain);
    let (source, _, _) = CountingSource::scripted(Some(
        SessionNativeCompletion::scripted(domain),
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
        Some(domain),
        "the pending detach holds the retire"
    );
    assert_eq!(drops.get(), 0, "O: the lane is kept until joined");
    set_winding_frame(&mut driver, false);
    release_gate(&gate);
    driver.on_tick();
    assert_eq!(
        driver.retiring_domain(),
        None,
        "R: the finish completes once"
    );
    assert_eq!(
        completes.get(),
        1,
        "N: one joined receipt across the hold"
    );
    assert_eq!(submits.get(), 1, "N: one submit across the hold");
    assert_eq!(drops.get(), 1, "O: released after the join");
    assert_eq!(
        driver.joint_begin_calls, 1,
        "R: a further cancel never re-begins"
    );
    driver
        .coordinator
        .stage_semantic_batch(crate::inventory_semantics::SemanticBatch::scripted(
            domain,
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
        ..
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    // Gated detach: the cancel winds A down through the real
    // stopping leg while the seal drains; the drained retry retires
    // on one joined receipt.
    let (io, gate) = WindDownIo::gated();
    let submits = Rc::clone(&io.submits);
    let completes = Rc::clone(&io.completes);
    let drops = Rc::new(Cell::new(0));
    let mut io = io;
    io.drop_spy = Some(Rc::clone(&drops));
    driver.semantic = Some(joint_lane(io, true));
    let domain = install_promotion_for_wind_down(&mut driver);
    quiesce_domain_for_retire(&mut *driver.coordinator, domain);
    let (source, _, _) = CountingSource::scripted(Some(
        SessionNativeCompletion::scripted(domain),
    ));
    driver.completion_source = Some(Box::new(source));
    driver.on_tick();
    assert_eq!(driver.joint_begin_calls, 1, "R: the finish begins once");
    queue_request(driver.display.as_mut().expect("display"));
    driver.on_tick();
    assert_eq!(
        driver.retiring_domain(),
        Some(domain),
        "A holds while its detach stays pending"
    );
    assert_b_untouched(&mut driver);
    assert!(
        driver.semantic.is_none(),
        "B installs nothing while A winds down (B)"
    );
    assert_eq!(drops.get(), 0, "O: the lane is kept until joined");
    set_winding_frame(&mut driver, false);
    release_gate(&gate);
    driver.on_tick();
    assert_eq!(
        driver.retiring_domain(),
        None,
        "R: the finish completes once"
    );
    assert_eq!(
        completes.get(),
        1,
        "N: one joined receipt across the hold"
    );
    assert_eq!(submits.get(), 1, "N: one submit across the hold");
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
    // The seal drains before the completion, as in production.
    driver
        .semantic
        .as_mut()
        .expect("lane")
        .set_test_joint_frame(false);
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
        Some(expected_disp_first_error(state)),
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
        abandons[0].1,
        expected_disp_first_error(state),
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
        Some(expected_disp_first_error(state)),
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
    assert_eq!(
        driver.joint_first_error.as_deref(),
        Some(expected_disp_first_error(state)),
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
        Some(expected_disp_first_error(state)),
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
        Some(expected_disp_first_error(state)),
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

/// J9/J11 × deadline (U E): the expired deadline is really
/// applied — the Driver records it as the retention cause through
/// the real loop helper (F1: cause ownership is driver-side,
/// never machine-owned) — then the suspended tick abandons the
/// dispositioned finish with the first error kept.
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
    let (run, _) = retain_publication(&mut driver, state, event, false);
    assert_eq!(
        run.stop_cause,
        Some(ZeroPassCause::Deadline),
        "the Driver records the deadline cause (F1)"
    );
    driver.on_tick();
    assert_eq!(
        driver.joint_finish,
        JointFinishDriver::Abandoned,
        "U: the dispositioned finish abandons under the deadline"
    );
    assert!(driver.semantic.is_none(), "U: the lane is held");
    assert_eq!(seat.drops.get(), 0, "U: held means never dropped");
    assert_eq!(
        driver.joint_first_error.as_deref(),
        Some(expected_disp_first_error(state)),
        "E: the first error is kept"
    );
}

/// J9/J11 × capture_error (U E): the capture failure is really
/// applied — the begin refuses with the attachment error and
/// latches it — then the stop abandons with the first error kept.
fn capture_disp_body(scene: Scene, event: JointEvent) {
    use crate::inventory_semantics::SemanticRefusal;
    assert!(matches!(event, JointEvent::CaptureError));
    assert!(matches!(scene.state, JointState::J9 | JointState::J11));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    if state == JointState::J11 {
        driver
            .coordinator
            .seed_collected_graph_refusal_for_test(GRAPH_REFUSAL_J11);
    }
    let mut lane = joint_lane(WindDownIo::completing(), false);
    lane.set_scripted_finish_begin_for_test(Some(Err(SemanticRefusal::Attachment)));
    driver.semantic = Some(lane);
    driver.on_stop_requested();
    assert_eq!(
        driver.joint_finish,
        JointFinishDriver::Abandoned,
        "U: the capture failure abandons"
    );
    assert!(driver.semantic.is_none(), "U: the lane is held");
    assert_eq!(
        driver.joint_first_error.as_deref(),
        Some(expected_disp_first_error(state)),
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

/// J9/J11 × sink_failure (U E): the sink failure is really
/// applied — the begin refuses with the storage error and latches
/// it — then the stop abandons with the first error kept.
fn sink_disp_body(scene: Scene, event: JointEvent) {
    use crate::inventory_semantics::SemanticRefusal;
    assert!(matches!(event, JointEvent::SinkFailure));
    assert!(matches!(scene.state, JointState::J9 | JointState::J11));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    if state == JointState::J11 {
        driver
            .coordinator
            .seed_collected_graph_refusal_for_test(GRAPH_REFUSAL_J11);
    }
    let mut lane = joint_lane(WindDownIo::completing(), false);
    lane.set_scripted_finish_begin_for_test(Some(Err(SemanticRefusal::ProviderStorage)));
    driver.semantic = Some(lane);
    driver.on_stop_requested();
    assert_eq!(
        driver.joint_finish,
        JointFinishDriver::Abandoned,
        "U: the sink failure abandons"
    );
    assert!(driver.semantic.is_none(), "U: the lane is held");
    assert_eq!(
        driver.joint_first_error.as_deref(),
        Some(expected_disp_first_error(state)),
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
    // In-flight through the scripted begin: the finish polls on.
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
        "the scripted begin reaches Polling"
    );
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
    // In-flight through the scripted begin: the finish polls on.
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
        "the scripted begin reaches Polling"
    );
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

use super::super::tests::{consume_clock, retain_with_cause, retained_run_of};
use crate::inventory_capture::{
    ClassicOutcome, FacadeLane, Publish, RetainedBlock, RetainedClassicRun, ZeroPassCause,
};

/// Retain a J12/J13 publication scene through the real loop: the
/// caller seats the lane, then the pending commit flag (or a
/// polling finish for cells whose codes exclude U) suspends before
/// any collection. J13 adds the retention error of the failed
/// publication. Returns the retained run beside its error after
/// pinning the suspension gate (G).
fn retain_publication(
    driver: &mut ClassicDriver<'_>,
    state: JointState,
    event: JointEvent,
    via_flag: bool,
) -> (RetainedClassicRun<FacadeLane>, Option<anyhow::Error>) {
    if via_flag {
        driver.joint_commit_pending = true;
    } else {
        driver.joint_finish = JointFinishDriver::Polling;
    }
    let cause = if event == JointEvent::Deadline {
        ZeroPassCause::Deadline
    } else {
        ZeroPassCause::OperatorStop
    };
    let initial = (state == JointState::J13).then(|| anyhow::anyhow!("the publication failure"));
    let outcome = retain_with_cause(driver, cause, initial);
    assert!(driver.suspended, "G: retention suspends the driver");
    assert_eq!(
        driver.terminal_seq_calls, 0,
        "G: the gate runs no terminal I/O"
    );
    assert_eq!(driver.joint_begin_calls, 0, "G: the gate begins nothing");
    assert_eq!(driver.joint_step_calls, 0, "G: the gate steps nothing");
    assert_eq!(driver.joint_commit_polls, 0, "G: the gate polls nothing");
    assert_eq!(driver.commit_calls, 0, "G: the gate commits nothing");
    retained_run_of(outcome)
}

/// Rebuild a consumable outcome from a retained run and its error.
/// The publication scene owes its publication row: without a live
/// lane the real loop retains no block, so the test plants the owed
/// Publication the live closer would carry.
fn consumable(
    run: RetainedClassicRun<FacadeLane>,
    error: Option<anyhow::Error>,
) -> ClassicOutcome<FacadeLane> {
    let mut run = run;
    run.block = Some(RetainedBlock::Publication);
    ClassicOutcome {
        stopped: None,
        error,
        zero_pass: None,
        retained: Some(run),
    }
}

/// J12/J13 × stop, deadline: J12 (O P G, N after publish) records
/// its cause once and runs the wound-down chain after the pending
/// commit publishes; J13 (O E P, then U) keeps its first error and
/// takes the finite stop through the refused commit.
fn stopdead_pub_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Stop | JointEvent::Deadline));
    assert!(matches!(scene.state, JointState::J12 | JointState::J13));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let mut io = WindDownIo::completing();
    let drops = Rc::new(Cell::new(0));
    io.drop_spy = Some(Rc::clone(&drops));
    let polls = Rc::clone(&io.polls);
    driver.semantic = Some(joint_lane(io, state == JointState::J12));
    let (run, error) = retain_publication(&mut driver, state, event, true);
    let cause = if event == JointEvent::Deadline {
        ZeroPassCause::Deadline
    } else {
        ZeroPassCause::OperatorStop
    };
    assert_eq!(
        run.stop_cause,
        Some(cause),
        "the run records the event cause"
    );
    assert!(driver.semantic.is_some(), "O: the lane is kept");
    assert_eq!(drops.get(), 0, "O: kept means never dropped");
    assert_eq!(driver.commit_calls, 0, "P: nothing attempted yet");
    if state == JointState::J13 {
        {
            let error = error.as_ref().expect("J13 retains its failure");
            assert!(
                format!("{error:#}").contains("the publication failure"),
                "E: the failed publication keeps its error: {error:#}"
            );
        }
        // The failed commit's poll refuses; the finite stop takes it.
        let stop = Cell::new(false);
        let stop_now = || stop.get();
        let clock = consume_clock(&stop_now);
        let (_, error, _) =
            driver.consume_outcome(consumable(run, error), &clock, &mut |_, _| Ok(()));
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "U: the refused commit takes the finite stop"
        );
        assert!(driver.semantic.is_none(), "U: the lane is held");
        assert_eq!(drops.get(), 0, "O: held means never dropped");
        assert_eq!(polls.get(), 0, "U: the abandon never joins");
        let error = error.expect("U: the finite stop exits with an error");
        assert!(
            format!("{error:#}").contains("the publication failure"),
            "E: the first error predates the finite stop: {error:#}"
        );
        assert_eq!(
            driver.commit_calls, 1,
            "P: the abandon commits once; the error run stays markerless"
        );
        let abandons: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|(subject, _)| subject == "joint finish abandoned for exit")
            .collect();
        assert_eq!(
            abandons.len(),
            1,
            "U: exactly one abandon gap: {:?}",
            gaps(&mut driver)
        );
        return;
    }
    assert!(error.is_none(), "J12 retains no error");
    // The pending commit publishes; the wound-down chain runs after.
    driver.joint_commit_pending = false;
    // The seal drains before the completion, as in production.
    driver
        .semantic
        .as_mut()
        .expect("lane")
        .set_test_joint_frame(false);
    // A stop clock during the drain: the recorded cause survives it.
    let stop = Cell::new(true);
    let stop_now = || stop.get();
    let clock = consume_clock(&stop_now);
    let (_, error, zero_pass) =
        driver.consume_outcome(consumable(run, error), &clock, &mut |_, _| Ok(()));
    assert!(error.is_none(), "no error on the publish path");
    let zero = zero_pass.expect("zero passes report once");
    assert_eq!(
        zero.cause, cause,
        "the recorded cause reaches presentation once"
    );
    assert_eq!(driver.joint_begin_calls, 1, "N: the finish begins once");
    assert!(
        polls.get() >= 1,
        "N: the detach reaps: {}",
        polls.get()
    );
    assert!(
        driver.semantic.is_none(),
        "N: the wound-down lane completes"
    );
    assert_eq!(drops.get(), 1, "O: released after the join");
    assert!(
        driver.joint_first_error.is_none(),
        "no error on the publish path"
    );
    assert_eq!(
        driver.commit_calls, 1,
        "P: the delivered stop commits once; the substituted resolve stages nothing"
    );
}

/// J12/J13 × cancel (O P / O E): the cancel parks but never winds
/// down while suspended: the install waits, the lane is kept, and
/// nothing commits or begins.
fn cancel_pub_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Cancel));
    assert!(matches!(scene.state, JointState::J12 | JointState::J13));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let mut io = WindDownIo::completing();
    let drops = Rc::new(Cell::new(0));
    io.drop_spy = Some(Rc::clone(&drops));
    // In-flight through the scripted poll: the finish polls on
    // without latching while the cancel waits.
    let mut lane = joint_lane(io, false);
    lane.set_scripted_finish_poll_for_test(Some(Ok(JointCommitProgress::Pending)));
    driver.semantic = Some(lane);
    let (_, error) = retain_publication(&mut driver, state, event, false);
    install_promotion_for_wind_down(&mut driver);
    for _ in 0..8 {
        driver.on_tick();
    }
    assert!(
        driver.installed_promotion.is_some(),
        "the install waits while suspended"
    );
    assert!(
        driver.retiring.is_none(),
        "no wind-down starts while suspended"
    );
    assert!(driver.semantic.is_some(), "O: the lane is kept");
    assert_eq!(drops.get(), 0, "O: kept means never dropped");
    assert_eq!(
        driver.joint_finish,
        JointFinishDriver::Polling,
        "no latch, no finite stop"
    );
    assert_eq!(driver.joint_begin_calls, 0, "P: nothing begins");
    assert_eq!(driver.commit_calls, 0, "P: nothing commits");
    assert!(
        driver.joint_first_error.is_none(),
        "no error is invented"
    );
    if state == JointState::J13 {
        let error = error.as_ref().expect("J13 retains its failure");
        assert!(
            format!("{error:#}").contains("the publication failure"),
            "E: the failed publication keeps its error: {error:#}"
        );
    } else {
        assert!(error.is_none(), "J12 retains no error");
    }
}

/// J12/J13 × promote (O P B / O E B): the queued request waits
/// untouched while suspended; the lane is kept and nothing commits.
fn promote_pub_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Promote));
    assert!(matches!(scene.state, JointState::J12 | JointState::J13));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let mut io = WindDownIo::completing();
    let drops = Rc::new(Cell::new(0));
    io.drop_spy = Some(Rc::clone(&drops));
    // In-flight through the scripted poll: the finish polls on
    // without latching while B waits.
    let mut lane = joint_lane(io, false);
    lane.set_scripted_finish_poll_for_test(Some(Ok(JointCommitProgress::Pending)));
    driver.semantic = Some(lane);
    let (_, error) = retain_publication(&mut driver, state, event, false);
    queue_request(driver.display.as_mut().expect("display"));
    for _ in 0..8 {
        driver.on_tick();
    }
    assert_b_untouched(&mut driver);
    assert!(driver.semantic.is_some(), "O: the lane is kept");
    assert_eq!(drops.get(), 0, "O: kept means never dropped");
    assert_eq!(driver.commit_calls, 0, "P: nothing commits");
    assert!(
        driver.joint_first_error.is_none(),
        "no error is invented"
    );
    if state == JointState::J13 {
        let error = error.as_ref().expect("J13 retains its failure");
        assert!(
            format!("{error:#}").contains("the publication failure"),
            "E: the failed publication keeps its error: {error:#}"
        );
    } else {
        assert!(error.is_none(), "J12 retains no error");
    }
}

/// J12/J13 × replace_foreign (X O): a foreign completion refuses
/// with its proof unchanged; the retained lane is kept.
fn replace_pub_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::ReplaceForeign));
    assert!(matches!(scene.state, JointState::J12 | JointState::J13));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let mut io = WindDownIo::completing();
    let drops = Rc::new(Cell::new(0));
    io.drop_spy = Some(Rc::clone(&drops));
    let mut lane = joint_lane(io, true);
    let domain = lane.domain();
    quiesce_domain_for_retire(&mut *driver.coordinator, domain);
    lane.set_test_joint_frame(false);
    driver.semantic = Some(lane);
    let (_, _) = retain_publication(&mut driver, state, event, false);
    let foreign = NativeDomainId::try_mint().expect("mintable");
    let offered = SessionNativeCompletion::scripted(foreign);
    let lane = driver.semantic.as_ref().expect("lane");
    match driver
        .coordinator
        .retire_joint_domain_with_lane(lane, offered)
    {
        Err((returned, crate::discovery::engine::inventory_coordinator::semantics::JointRetireRefusal::NotLiveDomain)) => {
            assert_eq!(
                returned.domain(),
                foreign,
                "X: the refusal returns the completion unchanged"
            );
        }
        outcome => panic!("a foreign completion refuses, got {outcome:?}"),
    }
    assert!(driver.semantic.is_some(), "O: the lane is kept");
    assert_eq!(drops.get(), 0, "O: kept means never dropped");
}

/// J12/J13 × capture_error (O P E / O E): a capture commit fails
/// once during the drain; nothing replays, and the lane joins
/// normally. J13 keeps its retention error; J12's failure strikes
/// the best-effort terminal commit (the fault is consumed) and the
/// F9 rule swallows it, like the sink.
fn capture_pub_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::CaptureError));
    assert!(matches!(scene.state, JointState::J12 | JointState::J13));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let mut io = WindDownIo::completing();
    let drops = Rc::new(Cell::new(0));
    io.drop_spy = Some(Rc::clone(&drops));
    driver.semantic = Some(joint_lane(io, true));
    let (run, error) = retain_publication(&mut driver, state, event, true);
    // The pending commit publishes; the capture error strikes the drain.
    driver.joint_commit_pending = false;
    // The seal drains before the completion, as in production.
    driver
        .semantic
        .as_mut()
        .expect("lane")
        .set_test_joint_frame(false);
    super::super::fail_next_classic_commit_for_test("the capture failure");
    let stop = Cell::new(false);
    let stop_now = || stop.get();
    let clock = consume_clock(&stop_now);
    let (_, error, zero_pass) =
        driver.consume_outcome(consumable(run, error), &clock, &mut |_, _| Ok(()));
    if state == JointState::J13 {
        assert!(
            zero_pass.is_none(),
            "no zero-pass report beside a retention error"
        );
    } else {
        let zero = zero_pass.expect("the stop delivered before the capture failure");
        assert_eq!(zero.cause, ZeroPassCause::OperatorStop, "cause kept");
    }
    if state == JointState::J13 {
        let error = error.expect("the capture error is kept");
        assert!(
            format!("{error:#}").contains("the publication failure"),
            "E: the first error predates the capture failure: {error:#}"
        );
    } else {
        assert!(
            error.is_none(),
            "E: the best-effort terminal commit swallows the capture failure"
        );
        assert!(
            super::super::take_classic_commit_fault_for_test().is_none(),
            "E: the capture failure struck once"
        );
    }
    assert_eq!(
        driver.commit_calls, 1,
        "P: the drain commits once, never replayed"
    );
    let failures: Vec<(String, String)> = gaps(&mut driver)
        .into_iter()
        .filter(|(subject, _)| subject == "inventory capture failed")
        .collect();
    if state == JointState::J13 {
        assert_eq!(
            failures.len(),
            1,
            "E: one failure gap: {:?}",
            gaps(&mut driver)
        );
    } else {
        assert!(
            failures.is_empty(),
            "E: the swallowed failure records nothing: {:?}",
            gaps(&mut driver)
        );
    }
    assert_eq!(driver.joint_begin_calls, 1, "O: the finish begins once");
    assert!(
        driver.semantic.is_none(),
        "O: the wound-down lane completes"
    );
    assert_eq!(drops.get(), 1, "O: released after the join");
    assert!(
        driver.joint_first_error.is_none(),
        "no finish error beside the capture failure"
    );
}

/// J12/J13 × sink_failure (E P): the stop sink fails once during
/// the drain; the error is kept, the stop is never re-emitted.
fn sink_pub_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::SinkFailure));
    assert!(matches!(scene.state, JointState::J12 | JointState::J13));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    driver.semantic = Some(joint_lane(WindDownIo::completing(), true));
    let (run, error) = retain_publication(&mut driver, state, event, true);
    // The pending commit publishes; the sink fails on the stop.
    driver.joint_commit_pending = false;
    // The seal drains before the completion, as in production.
    driver
        .semantic
        .as_mut()
        .expect("lane")
        .set_test_joint_frame(false);
    let mut stops = 0;
    let stop = Cell::new(false);
    let stop_now = || stop.get();
    let clock = consume_clock(&stop_now);
    let (_, error, _) = driver.consume_outcome(
        consumable(run, error),
        &clock,
        &mut |_, point| {
            if matches!(point, Publish::Stop { .. }) {
                stops += 1;
                return Err(anyhow::anyhow!("the sink failure"));
            }
            Ok(())
        },
    );
    if state == JointState::J13 {
        assert_eq!(
            stops, 0,
            "P: the retained error suppresses the stop; the sink never strikes"
        );
    } else {
        assert_eq!(stops, 1, "P: the failed stop is never re-emitted");
    }
    if state == JointState::J13 {
        let error = error.expect("E: the first error is kept");
        assert!(
            format!("{error:#}").contains("the publication failure"),
            "E: the first error predates the sink failure: {error:#}"
        );
    } else {
        assert!(
            error.is_none(),
            "E: the best-effort sink failure keeps the run-status channel"
        );
    }
}

/// J12/J13 × held_install (O P H / O E H): the stop begins the
/// active finish once and reclaims the held install once with
/// RunStopped; nothing installs, the lane stays live.
fn heldinstall_pub_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::HeldInstall));
    assert!(matches!(scene.state, JointState::J12 | JointState::J13));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let mut io = WindDownIo::completing();
    let drops = Rc::new(Cell::new(0));
    io.drop_spy = Some(Rc::clone(&drops));
    driver.semantic = Some(joint_lane(io, true));
    let domain = driver.semantic.as_ref().expect("lane").domain();
    let (_, error) = retain_publication(&mut driver, state, event, false);
    install_promotion_active(&mut driver);
    driver.on_stop_requested();
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
        driver
            .semantic
            .as_ref()
            .is_some_and(|lane| lane.domain() == domain),
        "H: the live lane stays"
    );
    assert_eq!(drops.get(), 0, "O: the lane is kept until joined");
    assert_eq!(driver.commit_calls, 0, "P: the stop commits nothing");
    assert_eq!(
        driver.terminal_seq_calls, 0,
        "the joint stop runs no terminal sequence"
    );
    if state == JointState::J13 {
        let error = error.as_ref().expect("J13 retains its failure");
        assert!(
            format!("{error:#}").contains("the publication failure"),
            "E: the failed publication keeps its error: {error:#}"
        );
    } else {
        assert!(error.is_none(), "J12 retains no error");
    }
}

/// J12/J13 × sigint2 (O T G / O T E): the second stop holds the
/// retained lane through the typed exit: no join, no mint.
fn sigint2_pub_body(scene: Scene, event: JointEvent) {
    assert!(matches!(event, JointEvent::Sigint2));
    assert!(matches!(scene.state, JointState::J12 | JointState::J13));
    let Scene {
        mut coordinator,
        display,
        state,
    } = scene;
    let mut driver = driver_with_display(&mut coordinator, display);
    let mut io = WindDownIo::completing();
    let drops = Rc::new(Cell::new(0));
    io.drop_spy = Some(Rc::clone(&drops));
    let polls = Rc::clone(&io.polls);
    driver.semantic = Some(joint_lane(io, true));
    let (source, mint_polls, _) = CountingSource::scripted(None);
    driver.completion_source = Some(Box::new(source));
    let (_, error) = retain_publication(&mut driver, state, event, false);
    driver.on_stop_requested();
    driver.on_stop_requested();
    assert_eq!(
        driver.joint_finish,
        JointFinishDriver::Abandoned,
        "T: the second stop abandons"
    );
    assert!(driver.semantic.is_none(), "T: the lane is held");
    assert_eq!(drops.get(), 0, "O: held means never dropped");
    assert_eq!(polls.get(), 0, "T: the typed exit never joins");
    assert_eq!(
        mint_polls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "T: the typed exit never mints"
    );
    assert_eq!(
        driver.terminal_seq_calls, 0,
        "G: the stops run no terminal I/O"
    );
    let holds: Vec<(String, String)> = gaps(&mut driver)
        .into_iter()
        .filter(|(subject, _)| subject == "joint finish held for exit")
        .collect();
    assert_eq!(
        holds.len(),
        1,
        "T: exactly one hold gap: {:?}",
        gaps(&mut driver)
    );
    if state == JointState::J13 {
        let error = error.as_ref().expect("J13 retains its failure");
        assert!(
            format!("{error:#}").contains("the publication failure"),
            "E: the failed publication keeps its error: {error:#}"
        );
    } else {
        assert!(error.is_none(), "J12 retains no error");
    }
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
joint_cell!(
    joint_cell_j12_stop,
    JointState::J12,
    JointEvent::Stop,
    stopdead_pub_body
);
joint_cell!(
    joint_cell_j12_deadline,
    JointState::J12,
    JointEvent::Deadline,
    stopdead_pub_body
);
joint_cell!(
    joint_cell_j12_cancel,
    JointState::J12,
    JointEvent::Cancel,
    cancel_pub_body
);
joint_cell!(
    joint_cell_j12_promote,
    JointState::J12,
    JointEvent::Promote,
    promote_pub_body
);
joint_cell!(
    joint_cell_j12_replace_foreign,
    JointState::J12,
    JointEvent::ReplaceForeign,
    replace_pub_body
);
joint_cell!(
    joint_cell_j12_capture_error,
    JointState::J12,
    JointEvent::CaptureError,
    capture_pub_body
);
joint_cell!(
    joint_cell_j12_sink_failure,
    JointState::J12,
    JointEvent::SinkFailure,
    sink_pub_body
);
joint_cell!(
    joint_cell_j12_held_install,
    JointState::J12,
    JointEvent::HeldInstall,
    heldinstall_pub_body
);
joint_cell!(
    joint_cell_j12_sigint2,
    JointState::J12,
    JointEvent::Sigint2,
    sigint2_pub_body
);
joint_cell!(
    joint_cell_j13_stop,
    JointState::J13,
    JointEvent::Stop,
    stopdead_pub_body
);
joint_cell!(
    joint_cell_j13_deadline,
    JointState::J13,
    JointEvent::Deadline,
    stopdead_pub_body
);
joint_cell!(
    joint_cell_j13_cancel,
    JointState::J13,
    JointEvent::Cancel,
    cancel_pub_body
);
joint_cell!(
    joint_cell_j13_promote,
    JointState::J13,
    JointEvent::Promote,
    promote_pub_body
);
joint_cell!(
    joint_cell_j13_replace_foreign,
    JointState::J13,
    JointEvent::ReplaceForeign,
    replace_pub_body
);
joint_cell!(
    joint_cell_j13_capture_error,
    JointState::J13,
    JointEvent::CaptureError,
    capture_pub_body
);
joint_cell!(
    joint_cell_j13_sink_failure,
    JointState::J13,
    JointEvent::SinkFailure,
    sink_pub_body
);
joint_cell!(
    joint_cell_j13_held_install,
    JointState::J13,
    JointEvent::HeldInstall,
    heldinstall_pub_body
);
joint_cell!(
    joint_cell_j13_sigint2,
    JointState::J13,
    JointEvent::Sigint2,
    sigint2_pub_body
);
