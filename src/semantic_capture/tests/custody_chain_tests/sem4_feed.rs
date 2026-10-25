//! SPDX-License-Identifier: GPL-3.0-or-later
//! sem-4: post-attach first-burst retention at the production H0 seam.
//!
//! Live shape (system run, process started after the observer): mapped by
//! the next pass, one burst before its first binding pass. The ticks drain
//! the burst with no binding pin, so every call sheds as unobserved and the
//! binding (passes later) finds nothing to join. A task that started after
//! the semantic lane attached has no unobserved earlier calls, so shedding
//! its first burst is not contracted (unlike pre-existing callers under
//! R-34): the pin-less calls must be retained until the binding lands, then
//! join as current calls with no boundary gap. Twin cases pin the contracted
//! shed for pre-attach tasks, the never-join on image mismatch (pid reuse,
//! exec), and the named reason when retention meets the pending budget.

use super::sem1_feed::{
    WORKLOAD_MAIN, admit_mapped, enqueue_live_like, production_bind, semantic_gap_subjects,
    workload_scene,
};
use super::*;
use crate::discovery::caller_registry::RegistryGap;
use crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild;
use std::time::Duration;

/// Reasons of the `semantic calls unrouted` gaps published so far.
fn unrouted_reasons(scene: &RealScene) -> Vec<String> {
    semantic_gap_subjects(scene)
        .into_iter()
        .filter(|(subject, _)| subject == "semantic calls unrouted")
        .map(|(_, reason)| reason)
        .collect()
}

/// The initial-coverage boundary gaps published so far.
fn boundary_gaps(scene: &RealScene) -> Vec<RegistryGap> {
    scene
        .scene
        .coordinator
        .registry()
        .gaps()
        .iter()
        .filter(|gap| gap.reason == "before_semantic_boundary")
        .cloned()
        .collect()
}

/// Stage counted physical use for the caller's held provider edge.
fn stage_physical_use(scene: &mut RealScene, caller: CallerId, first_ns: u64, last_ns: u64) {
    let module = scene.modules[0].0.clone();
    scene
        .scene
        .coordinator
        .registry_mut()
        .note_counted_use(caller, &module, 2, first_ns, last_ns, 0);
}

/// (api_returns, historical_only_returns, lossy, [(mechanism, calls)],
/// completed) of the first instance semantic row, if any.
fn semantic_row_summary(
    scene: &RealScene,
) -> Option<(Option<u64>, u64, bool, Vec<(u64, u64)>, u64)> {
    let row = scene
        .scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .next()?;
    let semantics = row.semantics.as_ref();
    let mut mechanisms: Vec<(u64, u64)> = semantics
        .map(|state| {
            state
                .mechanisms()
                .iter()
                .map(|(id, stat)| (*id, stat.calls))
                .collect()
        })
        .unwrap_or_default();
    mechanisms.sort_unstable();
    Some((
        row.api_returns,
        row.historical_only_returns,
        row.lossy,
        mechanisms,
        semantics.map(|state| state.completed()).unwrap_or(0),
    ))
}

/// Shape one two-call burst for `pid` without serving H0 a scan target:
/// the records carry the image (as BPF would tag them), then the scripted
/// targets drop before the tick, exactly like a production tick over an
/// unbound caller.
fn burst_without_pin(scene: &mut RealScene, pid: u32, cookie: u64) {
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
        .insert(pid, (pin, image(cookie)));
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(scene, pid, name, *mechanism);
    }
    scene.h0.0.borrow_mut().io.targets.clear();
}

/// A caller whose task provably started after the scene's H0 was built:
/// the lane-attach stamp is taken at H0 construction, and the sleep
/// separates the child start from it by far more than the tick
/// granularity, so the test never depends on sub-tick timing.
fn spawn_post_attach_child() -> OwnedStoppedChild {
    std::thread::sleep(Duration::from_millis(100));
    OwnedStoppedChild::new()
}

#[test]
fn post_attach_first_burst_joins_without_boundary_gap() {
    let mut scene = workload_scene();
    let child = spawn_post_attach_child();
    let pid = child.id();
    let caller = admit_mapped(&mut scene, pid);
    burst_without_pin(&mut scene, pid, 7);
    let batch = scene.lane.tick(&[]).unwrap();
    scene.publish(batch);
    assert!(
        unrouted_reasons(&scene).is_empty(),
        "post-attach burst is retained for the imminent binding, not shed: {:?}",
        unrouted_reasons(&scene)
    );
    // Physical use is first observed after the drain that retained the
    // burst, as in the live run (counters read later in the pass).
    let first_ns = now_ns() + 1_000_000;
    stage_physical_use(&mut scene, caller, first_ns, first_ns + 1_000);
    production_bind(&mut scene, caller, pid, image(7));
    let batch = scene.tick();
    scene.publish(batch);
    let (api_returns, historical, lossy, mechanisms, completed) =
        semantic_row_summary(&scene).expect("the retained burst registers an instance row");
    assert_eq!(api_returns, Some(2), "both retained calls join as current");
    assert_eq!(
        historical, 0,
        "retained calls are current, never historical"
    );
    assert!(!lossy, "nothing was lost: the whole burst joined");
    assert_eq!(
        mechanisms,
        vec![(0x250, 2)],
        "the joined burst attributes CKM_SHA256"
    );
    assert_eq!(completed, 1, "the digest pair completes one operation");
    assert_eq!(
        scene
            .scene
            .coordinator
            .registry()
            .instance_semantic_occupied(),
        1,
        "the joined burst materializes semantic state"
    );
    assert!(
        boundary_gaps(&scene).is_empty(),
        "a fully joined post-attach burst leaves no boundary gap: {:?}",
        boundary_gaps(&scene)
    );
}

#[test]
fn pre_attach_first_burst_still_sheds_with_boundary_gap() {
    let mut scene = workload_scene();
    // The test runner started long before the lane: R-34 contracted shed.
    let pid = std::process::id();
    let caller = admit_mapped(&mut scene, pid);
    burst_without_pin(&mut scene, pid, 7);
    let batch = scene.lane.tick(&[]).unwrap();
    scene.publish(batch);
    assert_eq!(
        unrouted_reasons(&scene),
        vec!["2 calls shed without a route (unobserved=2) with 0 bindings".to_string()],
        "pre-attach pin-less calls shed immediately"
    );
    // Physical use predates the binding, as in the live run.
    let first_ns = now_ns().saturating_sub(1_000_000);
    stage_physical_use(&mut scene, caller, first_ns, first_ns + 1_000);
    production_bind(&mut scene, caller, pid, image(7));
    let batch = scene.tick();
    scene.publish(batch);
    let gaps = boundary_gaps(&scene);
    assert_eq!(gaps.len(), 1, "the shed burst keeps its boundary gap");
    assert_eq!(gaps[0].caller, Some(caller));
    assert_eq!(
        gaps[0].subject,
        "physical provider use preceded first observed semantic registration"
    );
    let (api_returns, _, _, mechanisms, _) =
        semantic_row_summary(&scene).expect("the binding still registers an instance row");
    assert_eq!(api_returns, None, "shed calls never return");
    assert!(mechanisms.is_empty(), "shed calls attribute nothing");
    assert_eq!(
        scene
            .scene
            .coordinator
            .registry()
            .instance_semantic_occupied(),
        0,
        "shed calls materialize nothing"
    );
}

#[test]
fn bound_caller_with_other_cookie_never_joins_retained_calls() {
    let mut scene = workload_scene();
    let child = spawn_post_attach_child();
    let pid = child.id();
    let caller = admit_mapped(&mut scene, pid);
    // The burst is retained under cookie 7 ...
    burst_without_pin(&mut scene, pid, 7);
    let batch = scene.lane.tick(&[]).unwrap();
    scene.publish(batch);
    // ... but the binding proves another task (pid reuse mints a new
    // cookie), so the retained calls must never join it.
    production_bind(&mut scene, caller, pid, image(9));
    let batch = scene.tick();
    scene.publish(batch);
    let (api_returns, _, _, mechanisms, _) =
        semantic_row_summary(&scene).expect("the binding still registers an instance row");
    assert_eq!(api_returns, None, "another task's calls never join");
    assert!(
        mechanisms.is_empty(),
        "another task's calls attribute nothing"
    );
    assert!(
        unrouted_reasons(&scene).is_empty(),
        "mismatched retained calls stay held, never shed as unobserved: {:?}",
        unrouted_reasons(&scene)
    );
}

#[test]
fn bound_caller_with_newer_exec_never_joins_retained_calls() {
    let mut scene = workload_scene();
    let child = spawn_post_attach_child();
    let pid = child.id();
    let caller = admit_mapped(&mut scene, pid);
    // The burst is retained under (cookie 7, exec 1) ...
    burst_without_pin(&mut scene, pid, 7);
    let batch = scene.lane.tick(&[]).unwrap();
    scene.publish(batch);
    // ... but the binding proves a later exec of the task, so the
    // pre-exec calls must never join it.
    let newer = ImageIdentity {
        task_cookie: 7,
        exec_id: 2,
    };
    production_bind(&mut scene, caller, pid, newer);
    let batch = scene.tick();
    scene.publish(batch);
    let (api_returns, _, _, mechanisms, _) =
        semantic_row_summary(&scene).expect("the binding still registers an instance row");
    assert_eq!(api_returns, None, "pre-exec calls never join the new exec");
    assert!(mechanisms.is_empty(), "pre-exec calls attribute nothing");
    assert!(
        unrouted_reasons(&scene).is_empty(),
        "mismatched retained calls stay held, never shed as unobserved: {:?}",
        unrouted_reasons(&scene)
    );
}

#[test]
fn retention_overflow_sheds_with_named_capacity_reason() {
    let mut scene = workload_scene();
    let child = spawn_post_attach_child();
    let pid = child.id();
    let _caller = admit_mapped(&mut scene, pid);
    // More retained records than the pending-join budget holds: the
    // first tick fills it, the second tick's record must shed named.
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
    for _ in 0..1025 {
        enqueue_live_like(&mut scene, pid, "C_SignInit", 0x251);
    }
    scene.h0.0.borrow_mut().io.targets.clear();
    let batch = scene.lane.tick(&[]).unwrap();
    scene.publish(batch);
    let batch = scene.lane.tick(&[]).unwrap();
    scene.publish(batch);
    assert_eq!(
        unrouted_reasons(&scene),
        vec!["1 calls shed without a route (pending_capacity=1) with 0 bindings".to_string()],
        "retention past the pending budget sheds named and counted"
    );
    assert_eq!(
        scene.lane.shed_calls_disclosed(),
        1,
        "exactly the over-budget call is disclosed shed"
    );
}

#[test]
fn withheld_edge_with_claimed_children_names_the_children() {
    use crate::inventory_present::{Presentation, render_snapshot};
    // Bind first so the burst joins without retention (post-registration
    // calls join on the contracted path): the edge keeps no per-edge
    // state while its instance child holds mechanism claims, the live
    // shape where the edge label must not deny the observed feed.
    let mut scene = workload_scene();
    let pid = std::process::id();
    let caller = admit_mapped(&mut scene, pid);
    production_bind(&mut scene, caller, pid, image(7));
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid, name, *mechanism);
    }
    let batch = scene.tick();
    scene.publish(batch);
    let (_, _, _, mechanisms, _) =
        semantic_row_summary(&scene).expect("the bound burst registers an instance row");
    assert_eq!(
        mechanisms,
        vec![(0x250, 2)],
        "the fixture holds mechanism claims in its instance child"
    );
    let presentation = Presentation::capture(&scene.scene.coordinator, "system", 0, now_ns(), 2);
    let snapshot = render_snapshot(&presentation);
    let module = scene
        .scene
        .coordinator
        .registry()
        .module_id_for(&scene.modules[0].0)
        .unwrap();
    let edge_line = snapshot
        .lines()
        .find(|line| line.starts_with(&format!("edge {} -> {}", caller.label(), module.label())))
        .unwrap_or_else(|| panic!("no edge line for the fixture pair:\n{snapshot}"));
    assert!(
        edge_line.contains("unknown (per-edge summary withheld; see semantic children)"),
        "the edge label points at the claimed children: {edge_line}"
    );
    assert!(
        snapshot
            .lines()
            .any(|line| { line.starts_with("  instance ") && line.contains("observed") }),
        "the instance child line shows the observed feed:\n{snapshot}"
    );
}
