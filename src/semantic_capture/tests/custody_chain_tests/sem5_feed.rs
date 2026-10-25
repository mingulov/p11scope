//! SPDX-License-Identifier: GPL-3.0-or-later
//! sem-5: instance continuity across passes (E) and once-only call accounting (F).
//!
//! Live shape (system run, two providers callers, 17 passes): one still-mapped
//! caller accumulates roughly one new instance per discovery pass (11
//! instances for 2 processes, all but the last retired as `instance_retired`),
//! and the stop line counts 495 collected / 410 shed for 102 physical calls.
//! These tests pin the required behavior at the production H0 seam
//! (RealScene: real attested held files, real H0 decisions, substituted map
//! I/O): a still-mapped caller keeps ONE instance across passes, a real
//! remap or task turnover mints a new instance with the stated reason, and
//! every physical call is counted exactly once.

use super::sem1_feed::{
    WORKLOAD_MAIN, admit_mapped, enqueue_live_like, production_bind, workload_scene,
};
use super::*;
use crate::discovery::caller_registry::RegistryGap;
use crate::discovery::caller_registry::instance_input::{InstanceLifecycle, InstanceReason};
use crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild;
use std::time::Duration;

/// (reason, repeats) of the `semantic calls unrouted` gaps published so far.
fn unrouted_reasons(scene: &RealScene) -> Vec<(String, u64)> {
    let registry = scene.scene.coordinator.registry();
    registry
        .gaps()
        .iter()
        .zip(registry.gap_repeats().iter())
        .filter(|(gap, _)| gap.subject == "semantic calls unrouted")
        .map(|(gap, repeats)| (gap.reason.clone(), *repeats))
        .collect()
}

/// Total shed calls disclosed across the `semantic calls unrouted` gaps.
fn unrouted_total_shed(scene: &RealScene) -> u64 {
    unrouted_reasons(scene)
        .iter()
        .map(|(reason, repeats)| {
            reason
                .split_whitespace()
                .next()
                .and_then(|first| first.parse::<u64>().ok())
                .unwrap_or(0)
                * repeats
        })
        .sum()
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

/// One production discovery pass after the initial bind: the refresh
/// rotation re-proves bound callers (what ClassicDriver::apply runs),
/// then the lane ticks and the batch publishes.
fn discovery_pass(scene: &mut RealScene) {
    crate::inventory_semantics::bind_semantic_callers_inner(
        &mut scene.scene.coordinator,
        &mut scene.lane,
        None,
    );
    let batch = scene.tick();
    scene.publish(batch);
}

/// (id, caller, state, reason, first_seen_ns, last_seen_ns) per instance.
fn instance_summary(scene: &RealScene) -> Vec<(String, String, String, String, u64, u64)> {
    scene
        .scene
        .coordinator
        .registry()
        .instances()
        .map(|record| {
            (
                record.id.label(),
                record.caller.label(),
                record.state.label().to_string(),
                record
                    .reason
                    .map(|reason| reason.label().to_string())
                    .unwrap_or_else(|| "-".to_string()),
                record.first_seen_ns,
                record.last_seen_ns,
            )
        })
        .collect()
}

/// (instance, api_returns, historical_only_returns, lossy) per semantic row.
fn semantic_rows(scene: &RealScene) -> Vec<(String, Option<u64>, u64, bool)> {
    scene
        .scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .map(|row| {
            (
                row.id.label(),
                row.api_returns,
                row.historical_only_returns,
                row.lossy,
            )
        })
        .collect()
}

/// A caller whose task provably started after the scene's H0 was built.
fn spawn_post_attach_child() -> OwnedStoppedChild {
    std::thread::sleep(Duration::from_millis(100));
    OwnedStoppedChild::new()
}

#[test]
fn still_mapped_caller_keeps_one_instance_across_three_passes() {
    let mut scene = workload_scene();
    let pid = std::process::id();
    let caller = admit_mapped(&mut scene, pid);
    production_bind(&mut scene, caller, pid, image(7));
    for _ in 0..3 {
        crate::inventory_semantics::bind_semantic_callers_inner(
            &mut scene.scene.coordinator,
            &mut scene.lane,
            None,
        );
        for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
            enqueue_live_like(&mut scene, pid, name, *mechanism);
        }
        let batch = scene.tick();
        scene.publish(batch);
    }
    assert_eq!(
        instance_summary(&scene).len(),
        1,
        "one unchanged mapping keeps one instance, got {:?}",
        instance_summary(&scene)
    );
    assert_eq!(
        semantic_rows(&scene).len(),
        1,
        "one instance renders one semantic row, got {:?}",
        semantic_rows(&scene)
    );
    let (id, api_returns, historical, lossy) = &semantic_rows(&scene)[0];
    assert_eq!(
        (id.as_str(), api_returns, historical, lossy),
        ("i0", &Some(6), &0, &false),
        "all six calls between the passes join the one instance"
    );
    let (_, _, state, reason, first, last) = &instance_summary(&scene)[0];
    assert_eq!(
        (state.as_str(), reason.as_str()),
        (InstanceLifecycle::Observed.label(), "-",),
        "the surviving instance stays observed, never retired"
    );
    assert!(
        last >= first,
        "the instance is touched across passes ({first}..{last})"
    );
    assert!(
        unrouted_reasons(&scene).is_empty(),
        "nothing sheds on the joined path: {:?}",
        unrouted_reasons(&scene)
    );
}

#[test]
fn epoch_bump_with_unchanged_mapping_keeps_one_instance() {
    // The live churn shape: the epoch triple advances between passes
    // (kernel VMA adjustments such as split/merge, or a spurious hook
    // fire) while the mapped file, addresses, offsets and permissions
    // stay identical. The mapping is unchanged, so the instance stays.
    let mut scene = workload_scene();
    let pid = std::process::id();
    let caller = admit_mapped(&mut scene, pid);
    production_bind(&mut scene, caller, pid, image(7));
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid, name, *mechanism);
    }
    let batch = scene.tick();
    scene.publish(batch);
    for bump in 1..=2u32 {
        scene
            .h0
            .0
            .borrow_mut()
            .io
            .scan_inputs
            .insert(0, (0x1000_0000, bump));
        crate::inventory_semantics::bind_semantic_callers_inner(
            &mut scene.scene.coordinator,
            &mut scene.lane,
            None,
        );
        for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
            enqueue_live_like(&mut scene, pid, name, *mechanism);
        }
        let batch = scene.tick();
        scene.publish(batch);
    }
    assert_eq!(
        instance_summary(&scene).len(),
        1,
        "mapping-stable bumps keep one instance, got {:?}",
        instance_summary(&scene)
    );
    assert_eq!(
        semantic_rows(&scene).len(),
        1,
        "one instance renders one semantic row, got {:?}",
        semantic_rows(&scene)
    );
    assert_eq!(
        semantic_rows(&scene)[0].1,
        Some(6),
        "all six calls across the bumps join the one instance, got {:?}",
        semantic_rows(&scene)
    );
    let (_, _, state, reason, _, _) = &instance_summary(&scene)[0];
    assert_eq!(
        (state.as_str(), reason.as_str()),
        (InstanceLifecycle::Observed.label(), "-"),
        "the surviving instance stays observed, never retired"
    );
    assert!(
        unrouted_reasons(&scene).is_empty(),
        "bumps shed nothing: {:?}",
        unrouted_reasons(&scene)
    );
}

#[test]
fn remap_mints_new_instance_and_retires_prior_with_reason() {
    let mut scene = workload_scene();
    let pid = std::process::id();
    let caller = admit_mapped(&mut scene, pid);
    production_bind(&mut scene, caller, pid, image(7));
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid, name, *mechanism);
    }
    let batch = scene.tick();
    scene.publish(batch);
    assert_eq!(
        instance_summary(&scene).len(),
        1,
        "one instance before the remap, got {:?}",
        instance_summary(&scene)
    );
    // Unmap + map again: a new load base at a new epoch, the real remap
    // shape. Later calls carry the new stamps; the next pass re-proves.
    scene
        .h0
        .0
        .borrow_mut()
        .io
        .scan_inputs
        .insert(0, (0x2000_0000, 1));
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid, name, *mechanism);
    }
    discovery_pass(&mut scene);
    let instances = instance_summary(&scene);
    assert_eq!(
        instances.len(),
        2,
        "the remap mints exactly one successor, got {instances:?}"
    );
    assert_eq!(
        (instances[0].2.as_str(), instances[0].3.as_str()),
        (
            InstanceLifecycle::Retired.label(),
            InstanceReason::InstanceRetired.label(),
        ),
        "the prior load retires stating instance_retired, got {instances:?}"
    );
    assert_eq!(
        (instances[1].2.as_str(), instances[1].3.as_str()),
        (InstanceLifecycle::Observed.label(), "-"),
        "the successor stays observed, got {instances:?}"
    );
    let rows = semantic_rows(&scene);
    assert_eq!(
        rows.iter()
            .map(|(_, returns, _, _)| returns.unwrap_or(0))
            .sum::<u64>(),
        4,
        "each burst joins its own load, got {rows:?}"
    );
    assert_eq!(
        rows[0].1,
        Some(2),
        "the retired load keeps its history, got {rows:?}"
    );
    assert_eq!(
        rows[1].1,
        Some(2),
        "the successor joins the post-remap burst, got {rows:?}"
    );
}

#[test]
fn replaced_task_mints_new_instance_without_cross_join() {
    let mut scene = workload_scene();
    let child_a = spawn_post_attach_child();
    let pid_a = child_a.id();
    let caller_a = admit_mapped(&mut scene, pid_a);
    production_bind(&mut scene, caller_a, pid_a, image(7));
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid_a, name, *mechanism);
    }
    let batch = scene.tick();
    scene.publish(batch);
    assert_eq!(
        instance_summary(&scene).len(),
        1,
        "one instance before the turnover, got {:?}",
        instance_summary(&scene)
    );
    // The task exits; its pidfd turns READY, so the next tick retires it.
    drop(child_a);
    let batch = scene.tick();
    scene.publish(batch);
    let instances = instance_summary(&scene);
    assert_eq!(
        (
            instances.len(),
            instances[0].2.as_str(),
            instances[0].3.as_str()
        ),
        (
            1,
            InstanceLifecycle::Retired.label(),
            InstanceReason::TaskRetired.label(),
        ),
        "the exited task retires stating task_retired, got {instances:?}"
    );
    // A successor task (new cookie, as pid reuse mints) binds and runs.
    let child_b = spawn_post_attach_child();
    let pid_b = child_b.id();
    let caller_b = admit_mapped(&mut scene, pid_b);
    assert_ne!(caller_b, caller_a, "the successor is a new caller");
    production_bind(&mut scene, caller_b, pid_b, image(9));
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid_b, name, *mechanism);
    }
    let batch = scene.tick();
    scene.publish(batch);
    let instances = instance_summary(&scene);
    assert_eq!(
        instances.len(),
        2,
        "the successor mints exactly one instance, got {instances:?}"
    );
    assert_eq!(
        (instances[1].2.as_str(), instances[1].3.as_str()),
        (InstanceLifecycle::Observed.label(), "-"),
        "the successor stays observed, got {instances:?}"
    );
    let rows = semantic_rows(&scene);
    assert_eq!(
        rows[0].1,
        Some(2),
        "the retired task keeps its history, got {rows:?}"
    );
    assert_eq!(
        rows[1].1,
        Some(2),
        "the successor joins only its own burst, got {rows:?}"
    );
}

#[test]
fn stop_names_route_waiting_calls_in_the_final_accounting() {
    // Still route-waiting at stop (a retained post-attach burst that
    // never bound): the Finish flush must name them in the disclosed
    // shed count, never hide them behind Stopped.
    let mut scene = workload_scene();
    let child = spawn_post_attach_child();
    let pid = child.id();
    let _caller = admit_mapped(&mut scene, pid);
    // The image must exist for enqueueing, but no pin is ever published
    // to the drain: the lane ticks with no pins, so the drain retains.
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
    // Pinlessness in the harness is the targets map, not the pins arg:
    // clearing it keeps the drain pinless so the burst retains.
    scene.h0.0.borrow_mut().io.targets.clear();
    let batch = scene.lane.tick(&[]).unwrap();
    scene.publish(batch);
    assert_eq!(
        unrouted_reasons(&scene),
        Vec::<(String, u64)>::new(),
        "retained calls wait, they do not shed mid-run"
    );
    let finish = scene.h0.finish(scene.lane.domain());
    scene.publish(finish);
    let joined = scene.h0.0.borrow().capture.router().counters().joined;
    let shed = scene.lane.shed_calls_disclosed();
    assert_eq!((joined, shed), (0, 2), "stop sheds exactly the two waiters");
    assert_eq!(
        unrouted_reasons(&scene),
        vec![(
            "2 calls shed without a route (unobserved=2) with 0 bindings".to_string(),
            1
        )],
        "the stop flush names the two waiters once"
    );
    assert_eq!(
        joined + shed,
        2,
        "joined + shed still equals the physical calls at stop"
    );
}

#[test]
fn physical_calls_count_once_across_ticks_and_bindings() {
    // The test runner started long before the lane: pre-attach, R-34.
    let mut scene = workload_scene();
    let pid = std::process::id();
    let caller = admit_mapped(&mut scene, pid);
    // Burst 1 drains with no binding pin: the contracted R-34 shed.
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
    // Physical use predates the binding, as in the live run.
    let first_ns = now_ns().saturating_sub(1_000_000);
    stage_physical_use(&mut scene, caller, first_ns, first_ns + 1_000);
    production_bind(&mut scene, caller, pid, image(7));
    // Bursts 2 and 3 join across two more ticks on the live binding.
    for _ in 0..2 {
        for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
            enqueue_live_like(&mut scene, pid, name, *mechanism);
        }
        let batch = scene.tick();
        scene.publish(batch);
    }
    // N = 6 physical calls: 2 shed + 4 joined, each counted once.
    let joined = scene.h0.0.borrow().capture.router().counters().joined;
    let shed = scene.lane.shed_calls_disclosed();
    let router_pending = scene.h0.0.borrow().capture.router().pending_len() as u64;
    let awaiting_floor = scene
        .h0
        .0
        .borrow()
        .capture
        .pending_h3_watermark()
        .and_then(|(_, awaiting, _)| awaiting);
    assert_eq!(joined, 4, "the post-bind bursts join exactly once");
    assert_eq!(shed, 2, "the pre-bind burst sheds exactly once");
    assert_eq!(
        (router_pending, awaiting_floor),
        (0, None),
        "nothing is still route-waiting at the end"
    );
    assert_eq!(
        joined + shed + router_pending,
        6,
        "joined + shed (+ pending) equals the physical calls"
    );
    assert_eq!(
        unrouted_total_shed(&scene),
        shed,
        "the unrouted gaps disclose each shed call once, got {:?}",
        unrouted_reasons(&scene)
    );
    assert_eq!(
        unrouted_reasons(&scene),
        vec![(
            "2 calls shed without a route (unobserved=2) with 0 bindings".to_string(),
            1
        )],
        "one gap for the one shed burst"
    );
    let rows = semantic_rows(&scene);
    assert_eq!(
        rows.iter()
            .map(|(_, returns, _, _)| returns.unwrap_or(0))
            .sum::<u64>(),
        4,
        "the joined bursts attribute exactly once, got {rows:?}"
    );
    assert_eq!(
        boundary_gaps(&scene).len(),
        1,
        "the R-34 shed keeps its boundary disclosure"
    );
}
