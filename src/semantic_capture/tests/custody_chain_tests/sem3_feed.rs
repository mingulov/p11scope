//! SPDX-License-Identifier: GPL-3.0-or-later
//! sem-3: late-binding join at the production H0 seam.
//!
//! Live shape (system run, pre-existing caller): mapped and
//! manifest-matched before the lane's first pass attempt, no binding
//! before first usage (the H0 refresh scan refuses while the task has
//! no BPF cookie), then one short burst drained before the next pass
//! binds the caller. The burst must wait for the imminent binding and
//! join once that binding's scan observes; occupancy advances. Only
//! calls still unbound past the pending window shed as unobserved.

use super::sem1_feed::{
    WORKLOAD_MAIN, admit_mapped, enqueue_live_like, semantic_gap_subjects, workload_scene,
};
use super::*;
use std::time::Duration;

/// One production per-pass bind attempt (what ClassicDriver::apply
/// runs): selection, candidate seal, H0 refresh admission, consume.
/// Returns whether the caller holds a binding afterwards.
fn attempt_production_bind(scene: &mut RealScene, caller: CallerId, pid: u32) -> bool {
    let pin = scene
        .scene
        .coordinator
        .adapter()
        .shared_semantic_custody(caller)
        .expect("the live caller shares its custody Arc");
    scene
        .h0
        .0
        .borrow_mut()
        .io
        .targets
        .insert(pid, (pin, image(7)));
    crate::inventory_semantics::bind_semantic_callers_inner(
        &mut scene.scene.coordinator,
        &mut scene.lane,
        None,
    );
    scene
        .scene
        .coordinator
        .semantic_bindings()
        .get(caller)
        .is_some()
}

fn held_pending(scene: &RealScene) -> usize {
    scene
        .h0
        .0
        .borrow()
        .capture
        .router()
        .pending_facts()
        .count()
}

fn joined_calls(scene: &RealScene) -> u64 {
    scene.h0.0.borrow().capture.router().counters().joined
}

fn occupied(scene: &RealScene) -> usize {
    scene
        .scene
        .coordinator
        .registry()
        .instance_semantic_occupied()
}

#[test]
fn pre_existing_burst_waits_for_binding_and_joins() {
    let mut scene = workload_scene();
    let pid = std::process::id();
    let caller = admit_mapped(&mut scene, pid);
    // Pre-burst passes: the refresh scan refuses (no BPF task cookie
    // on a task the probes never observed), so no binding is admitted
    // and empty ticks observe nothing.
    scene.h0.0.borrow_mut().io.script.fail_file = Some(0);
    for _ in 0..3 {
        assert!(
            !attempt_production_bind(&mut scene, caller, pid),
            "no binding before first usage: the scan proof cannot hold yet"
        );
        let batch = scene.lane.tick(&[]).unwrap();
        scene.publish(batch);
    }
    assert!(
        semantic_gap_subjects(&scene).iter().any(|(subject, reason)| {
            subject == "semantic admission refused"
                && reason.starts_with("semantic_unavailable")
        }),
        "pre-burst attempts are refused, not skipped"
    );
    // One short burst, drained before the next pass binds the caller:
    // targets shape the records' image (as BPF would), then drop
    // before the tick so H0 serves no scan target, exactly like a
    // production tick over empty binding pins.
    for (name, mechanism) in WORKLOAD_MAIN.iter() {
        enqueue_live_like(&mut scene, pid, name, *mechanism);
    }
    scene.h0.0.borrow_mut().io.targets.clear();
    let batch = scene.lane.tick(&[]).unwrap();
    scene.publish(batch);
    assert_eq!(
        held_pending(&scene),
        WORKLOAD_MAIN.len(),
        "the drained burst waits for the imminent binding"
    );
    assert_eq!(
        scene.lane.shed_calls_disclosed(),
        0,
        "nothing sheds before the binding lands"
    );
    // The next pass binds (the burst minted the cookie): the binding's
    // own scan observes and resolves the held burst.
    scene.h0.0.borrow_mut().io.script.fail_file = None;
    assert!(
        attempt_production_bind(&mut scene, caller, pid),
        "the mapped caller binds once its scan proof holds"
    );
    let batch = scene.lane.tick(&[]).unwrap();
    scene.publish(batch);
    assert_eq!(
        joined_calls(&scene),
        WORKLOAD_MAIN.len() as u64,
        "the late-bound burst joins"
    );
    assert!(
        occupied(&scene) > 0,
        "joined calls advance occupancy, got 0"
    );
    assert_eq!(
        scene.lane.shed_calls_disclosed(),
        0,
        "the joined burst never sheds"
    );
    assert!(
        !semantic_gap_subjects(&scene)
            .iter()
            .any(|(subject, _)| subject == "semantic calls unrouted"),
        "no unrouted gap for the joined burst"
    );
}

#[test]
fn refused_admission_names_the_unavailable_site() {
    let mut scene = workload_scene();
    let pid = std::process::id();
    let caller = admit_mapped(&mut scene, pid);
    // The refresh scan refuses (no receipt is minted), so admission
    // refuses `semantic_unavailable` with the exact firing site.
    scene.h0.0.borrow_mut().io.script.fail_file = Some(0);
    assert!(!attempt_production_bind(&mut scene, caller, pid));
    scene.scene.coordinator.commit_batch(false).unwrap();
    assert_eq!(
        semantic_gap_subjects(&scene),
        vec![(
            "semantic admission refused".to_string(),
            "semantic_unavailable:no_receipt".to_string()
        )]
    );
}

#[test]
fn pinless_calls_expire_past_the_pending_window() {
    let mut scene = workload_scene();
    let pid = std::process::id();
    let _caller = admit_mapped(&mut scene, pid);
    // The burst drains with no binding and is held; the binding never
    // comes, so the wait ends at the pending window, honestly shed.
    let pin = std::sync::Arc::new(
        scene
            .scene
            .coordinator
            .adapter()
            .live_pin(pid)
            .unwrap()
            .1
            .try_clone()
            .unwrap(),
    );
    scene
        .h0
        .0
        .borrow_mut()
        .io
        .targets
        .insert(pid, (pin, image(7)));
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid, name, *mechanism);
    }
    scene.h0.0.borrow_mut().io.targets.clear();
    let batch = scene.lane.tick(&[]).unwrap();
    scene.publish(batch);
    assert_eq!(held_pending(&scene), 2, "the burst is held first");
    assert_eq!(scene.lane.shed_calls_disclosed(), 0);
    scene.h0.0.borrow_mut().io.script.now += Duration::from_secs(3);
    let batch = scene.lane.tick(&[]).unwrap();
    scene.publish(batch);
    assert_eq!(held_pending(&scene), 0, "the window ends the wait");
    assert_eq!(joined_calls(&scene), 0, "nothing unbound joins");
    assert_eq!(occupied(&scene), 0, "nothing unbound materializes");
    assert_eq!(scene.lane.shed_calls_disclosed(), 2);
    assert_eq!(
        semantic_gap_subjects(&scene),
        vec![(
            "semantic calls unrouted".to_string(),
            "2 calls shed without a route (unobserved=2) with 0 bindings".to_string()
        )]
    );
}
