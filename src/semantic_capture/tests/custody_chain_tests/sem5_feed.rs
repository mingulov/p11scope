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
use crate::attach::image_query::ImageQueryRefusal;
use crate::discovery::caller_registry::RegistryGap;
use std::io::Write as _;
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
    // The live churn shape: only the per-file global epoch advances
    // between passes (unattributable mappings of the same file by other
    // processes, or the observer's own self-mapping probe) while the
    // process's own local epoch and the mapped file, addresses, offsets
    // and permissions stay identical. The mapping is unchanged and the
    // witness attributed nothing to this process, so the instance stays.
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
        let (_, local, _) = scene.h0.0.borrow().io.scan_input(0);
        scene
            .h0
            .0
            .borrow_mut()
            .io
            .scan_inputs
            .insert(0, (0x1000_0000, local, bump));
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
fn same_base_local_bump_mints_and_retires_prior() {
    // The local twin of the global-only continuity test: the process's
    // own epoch moves at the SAME base (an attributed mapping change,
    // e.g. a same-address unload+reload the witness saw). This mints a
    // successor and retires the prior load; the two bursts never join
    // across the reload.
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
        "one instance before the local move, got {:?}",
        instance_summary(&scene)
    );
    // Same base, new local epoch: the witness attributed a change here.
    let (base, local, global) = scene.h0.0.borrow().io.scan_input(0);
    scene
        .h0
        .0
        .borrow_mut()
        .io
        .scan_inputs
        .insert(0, (base, local + 1, global));
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid, name, *mechanism);
    }
    discovery_pass(&mut scene);
    let instances = instance_summary(&scene);
    assert_eq!(
        instances.len(),
        2,
        "the local move mints exactly one successor, got {instances:?}"
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
        "the successor joins only the post-move burst, got {rows:?}"
    );
}

#[test]
fn storage_null_move_mints_through_tick() {
    // Q1(b) through the production tick: a global-only advance observed
    // after INSTANCE_COUNT.storage_null moved mints a successor and
    // retires the prior load, even though the mapping and the process's
    // own epoch are unchanged. Fail closed on a possibly unattributed
    // mapping change. The bind runs first with the old inputs, so the
    // mint lands in the tick's own scan.
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
        "one instance before the storage move, got {:?}",
        instance_summary(&scene)
    );
    crate::inventory_semantics::bind_semantic_callers_inner(
        &mut scene.scene.coordinator,
        &mut scene.lane,
        None,
    );
    // Same base and local epoch, advanced global epoch, moved counter.
    let (base, local, global) = scene.h0.0.borrow().io.scan_input(0);
    scene
        .h0
        .0
        .borrow_mut()
        .io
        .scan_inputs
        .insert(0, (base, local, global + 1));
    scene.h0.0.borrow_mut().io.storage_null += 1;
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid, name, *mechanism);
    }
    let batch = scene.tick();
    scene.publish(batch);
    let instances = instance_summary(&scene);
    assert_eq!(
        instances.len(),
        2,
        "the storage move mints exactly one successor, got {instances:?}"
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
        "the successor joins only the post-move burst, got {rows:?}"
    );
}

#[test]
fn storage_null_move_mints_through_refresh() {
    // Q1(b) through the bind refresh: the same moved-counter mint, but
    // the discovery pass re-binds first, so the refresh scan observes
    // the advance before the tick collects the post-move burst.
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
        "one instance before the storage move, got {:?}",
        instance_summary(&scene)
    );
    // Same base and local epoch, advanced global epoch, moved counter.
    let (base, local, global) = scene.h0.0.borrow().io.scan_input(0);
    scene
        .h0
        .0
        .borrow_mut()
        .io
        .scan_inputs
        .insert(0, (base, local, global + 1));
    scene.h0.0.borrow_mut().io.storage_null += 1;
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid, name, *mechanism);
    }
    discovery_pass(&mut scene);
    let instances = instance_summary(&scene);
    assert_eq!(
        instances.len(),
        2,
        "the storage move mints exactly one successor, got {instances:?}"
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
        "the successor joins only the post-move burst, got {rows:?}"
    );
}

#[test]
fn absence_then_same_base_reload_mints() {
    // A scan that proves the module unmapped breaks continuity: the next
    // scan mints even when the reload lands at the same base with the
    // local epoch unchanged (a global-only reload the witness did not
    // attribute). Without the break this would continue the old ID and
    // join two load lifetimes under one instance.
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
        "one instance before the absence, got {:?}",
        instance_summary(&scene)
    );
    // The module vanishes mid-run: calls still join the current
    // observation, but the refresh scan proves it unmapped.
    scene.h0.0.borrow_mut().io.absent_files.insert(0);
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid, name, *mechanism);
    }
    discovery_pass(&mut scene);
    assert_eq!(
        instance_summary(&scene).len(),
        1,
        "the absence alone mints nothing, got {:?}",
        instance_summary(&scene)
    );
    // The reload lands at the same base; only the global epoch moved.
    scene.h0.0.borrow_mut().io.absent_files.remove(&0);
    let (base, local, global) = scene.h0.0.borrow().io.scan_input(0);
    scene
        .h0
        .0
        .borrow_mut()
        .io
        .scan_inputs
        .insert(0, (base, local, global + 1));
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid, name, *mechanism);
    }
    discovery_pass(&mut scene);
    let instances = instance_summary(&scene);
    assert_eq!(
        instances.len(),
        2,
        "the reload after proven absence mints, got {instances:?}"
    );
    assert_eq!(
        (instances[0].2.as_str(), instances[0].3.as_str()),
        (
            InstanceLifecycle::Retired.label(),
            InstanceReason::InstanceRetired.label(),
        ),
        "the pre-absence load retires stating instance_retired, got {instances:?}"
    );
    assert_eq!(
        (instances[1].2.as_str(), instances[1].3.as_str()),
        (InstanceLifecycle::Observed.label(), "-"),
        "the reloaded mapping stays observed, got {instances:?}"
    );
    let rows = semantic_rows(&scene);
    assert_eq!(
        rows.iter()
            .map(|(_, returns, _, _)| returns.unwrap_or(0))
            .sum::<u64>(),
        6,
        "all three bursts attribute exactly once, got {rows:?}"
    );
    assert_eq!(
        rows[0].1,
        Some(4),
        "the retired load keeps both pre-reload bursts, got {rows:?}"
    );
    assert_eq!(
        rows[1].1,
        Some(2),
        "the successor joins only the post-reload burst, got {rows:?}"
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
    // The local epoch moves (the witness attributed the remap here), so
    // this mints under both the old triple rule and the local gate.
    scene
        .h0
        .0
        .borrow_mut()
        .io
        .scan_inputs
        .insert(0, (0x2000_0000, 1, 0));
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
fn retained_never_bound_burst_sheds_at_the_horizon_and_frees_admission() {
    // A retained post-attach burst whose image exits before binding must
    // not occupy the pending budget until stop: past the retention
    // horizon it sheds mid-run as Unobserved with the existing
    // disclosure, and a later live caller still binds and joins.
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
    scene.h0.0.borrow_mut().io.targets.clear();
    let batch = scene.lane.tick(&[]).unwrap();
    scene.publish(batch);
    assert_eq!(
        unrouted_reasons(&scene),
        Vec::<(String, u64)>::new(),
        "retained calls wait inside the horizon, they do not shed yet"
    );
    // The image exits before binding; the horizon passes with no proof.
    drop(child);
    scene
        .h0
        .0
        .borrow_mut()
        .io
        .script
        .advance_now(Duration::from_secs(31));
    let batch = scene.lane.tick(&[]).unwrap();
    scene.publish(batch);
    let router_pending = scene.h0.0.borrow().capture.router().pending_len() as u64;
    assert_eq!(
        router_pending, 0,
        "the horizon expiry frees the pending budget mid-run"
    );
    assert_eq!(
        scene.lane.shed_calls_disclosed(),
        2,
        "the never-bound burst sheds mid-run, not at stop"
    );
    assert_eq!(
        unrouted_reasons(&scene),
        vec![(
            "2 calls shed without a route (unobserved=2) with 0 bindings".to_string(),
            1
        )],
        "the horizon shed keeps the existing disclosure"
    );
    // A later live caller is admitted: it binds and its burst joins.
    let live = std::process::id();
    let live_caller = admit_mapped(&mut scene, live);
    production_bind(&mut scene, live_caller, live, image(9));
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, live, name, *mechanism);
    }
    let batch = scene.tick();
    scene.publish(batch);
    let joined = scene.h0.0.borrow().capture.router().counters().joined;
    assert_eq!(joined, 2, "the live burst joins after the horizon shed");
    // Stop stays finite and the full account reconciles.
    let finish = scene.h0.finish(scene.lane.domain());
    scene.publish(finish);
    let shed = scene.lane.shed_calls_disclosed();
    assert_eq!(
        joined + shed,
        4,
        "joined + shed still equals the physical calls at stop"
    );
}

#[test]
fn backpressure_drop_sheds_unjoined_calls_with_the_drop_label() {
    // A batch dropped for backpressure sheds its unjoined calls with
    // the drop label at the commit: joined + shed still equals the
    // physical calls, on the drop path as on the success path.
    let mut scene = workload_scene();
    let pid = std::process::id();
    let caller = admit_mapped(&mut scene, pid);
    // The first burst drains pinless and pre-attach: the contracted
    // R-34 shed, two Unknown outcomes inside its batch.
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
    let shed_batch = scene.lane.tick(&[]).unwrap();
    // Then the caller binds and its live burst joins.
    production_bind(&mut scene, caller, pid, image(7));
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid, name, *mechanism);
    }
    let first = scene.tick();
    // The occupying batch commits only after the shed batch stages,
    // so the shed batch drops for backpressure.
    scene.scene.coordinator.stage_semantic_batch(first);
    scene.scene.coordinator.stage_semantic_batch(shed_batch);
    scene
        .scene
        .coordinator
        .commit_batch_with_semantics(false, Some(&mut scene.lane))
        .unwrap();
    let joined = scene.h0.0.borrow().capture.router().counters().joined;
    let shed = scene.lane.shed_calls_disclosed();
    assert_eq!(joined, 2, "the occupying batch joins exactly once");
    assert_eq!(shed, 2, "the dropped batch sheds its unknown calls once");
    assert_eq!(
        joined + shed,
        4,
        "joined + shed equals the physical calls across the drop"
    );
    assert_eq!(
        unrouted_reasons(&scene),
        vec![(
            "2 calls shed from a dropped backpressure batch (unobserved=2) with 1 bindings"
                .to_string(),
            1
        )],
        "the drop shed keeps its drop label"
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

/// (ctime seconds, ctime nanoseconds, length) of a held provider file:
/// the corruption check for the changed-file tests below.
fn provider_stamp(path: &str) -> (i64, i64, u64) {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = std::fs::metadata(path).unwrap();
    (
        metadata.ctime(),
        metadata.ctime_nsec(),
        metadata.len(),
    )
}

#[test]
fn changed_provider_file_refuses_scans_and_sheds_the_pending_burst() {
    // The punch-hole rule at the fake scan seam: once the watched
    // provider file reports changed, every later scan refuses Custody —
    // the `LiveImageScan::audit` guard — so a global-advanced burst
    // can never observe and sheds as Unobserved with the existing
    // disclosure. The pre-change instance stays observed; nothing
    // mints, nothing joins, no other refusal appears.
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
        "one instance before the change, got {:?}",
        instance_summary(&scene)
    );
    // The hole: the provider file changes on disk after pinning.
    let scans_before_change = scene.h0.0.borrow().io.scan_results.len();
    let provider = scene.modules[0].1.clone();
    let before = provider_stamp(&provider);
    std::fs::OpenOptions::new()
        .append(true)
        .open(&provider)
        .unwrap()
        .write_all(b"sem-8-hole")
        .unwrap();
    let after = provider_stamp(&provider);
    assert_ne!(
        before, after,
        "the test setup must actually change the file"
    );
    assert_eq!(
        scene.h0.0.borrow().io.watched[0].check_unchanged(),
        Ok(false),
        "the watched file reports changed after the on-disk write"
    );
    // The hole's epoch shape: the global epoch advanced while the
    // mapping and the process's own epoch stayed identical, so the
    // next burst needs a fresh observation instead of a cached join.
    let (base, local, global) = scene.h0.0.borrow().io.scan_input(0);
    scene
        .h0
        .0
        .borrow_mut()
        .io
        .scan_inputs
        .insert(0, (base, local, global + 1));
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid, name, *mechanism);
    }
    discovery_pass(&mut scene);
    let joined = scene.h0.0.borrow().capture.router().counters().joined;
    assert_eq!(
        joined, 2,
        "the post-change burst waits for its observation, got {joined} joined"
    );
    assert_eq!(
        scene.lane.shed_calls_disclosed(),
        0,
        "route-waiting calls shed at the deadline, not before"
    );
    // Past the 2 s scan-job deadline the burst expires unobserved.
    scene
        .h0
        .0
        .borrow_mut()
        .io
        .script
        .advance_now(Duration::from_secs(3));
    let batch = scene.tick();
    scene.publish(batch);
    let joined = scene.h0.0.borrow().capture.router().counters().joined;
    let shed = scene.lane.shed_calls_disclosed();
    assert_eq!((joined, shed), (2, 2), "only the pre-change burst joins");
    assert_eq!(joined + shed, 4, "joined + shed equals the physical calls");
    assert_eq!(
        unrouted_reasons(&scene),
        vec![(
            "2 calls shed without a route (unobserved=2) with 1 bindings".to_string(),
            1
        )],
        "the expired burst keeps the unobserved disclosure"
    );
    // Every scan after the change refuses Custody (the refresh scan
    // and the tick scan alike); every scan before it sealed a proof.
    let held = scene.h0.0.borrow();
    let (sealed, refused) = held.io.scan_results.split_at(scans_before_change);
    assert!(
        sealed.iter().all(|result| result.is_ok()),
        "pre-change scans seal proofs, got {sealed:?}"
    );
    assert_eq!(
        refused.len(),
        2,
        "the refresh scan and the tick scan both ran after the change, got {refused:?}"
    );
    assert!(
        refused
            .iter()
            .all(|result| *result == Err(ImageQueryRefusal::Custody)),
        "every post-change scan refuses Custody, got {refused:?}"
    );
    drop(held);
    let instances = instance_summary(&scene);
    assert_eq!(
        instances.len(),
        1,
        "the change mints nothing, got {instances:?}"
    );
    assert_eq!(
        (instances[0].2.as_str(), instances[0].3.as_str()),
        (InstanceLifecycle::Observed.label(), "-"),
        "the pre-change instance stays observed, got {instances:?}"
    );
    let rows = semantic_rows(&scene);
    assert_eq!(
        rows.iter()
            .map(|(_, returns, _, _)| returns.unwrap_or(0))
            .sum::<u64>(),
        2,
        "only the pre-change burst attributes, got {rows:?}"
    );
    assert_eq!(
        rows[0].1,
        Some(2),
        "the surviving instance keeps exactly its own burst, got {rows:?}"
    );
}

#[test]
fn unchanged_provider_file_joins_across_a_global_advance() {
    // The healthy twin: the same global advance with an unchanged
    // watched file observes (Continued) and joins. No scan refuses.
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
        scene.h0.0.borrow().io.watched[0].check_unchanged(),
        Ok(true),
        "the untouched watched file reports unchanged"
    );
    let (base, local, global) = scene.h0.0.borrow().io.scan_input(0);
    scene
        .h0
        .0
        .borrow_mut()
        .io
        .scan_inputs
        .insert(0, (base, local, global + 1));
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid, name, *mechanism);
    }
    discovery_pass(&mut scene);
    let joined = scene.h0.0.borrow().capture.router().counters().joined;
    let shed = scene.lane.shed_calls_disclosed();
    assert_eq!((joined, shed), (4, 0), "both bursts join, nothing sheds");
    // The twin's ledger: scans were attempted and every one sealed.
    let held = scene.h0.0.borrow();
    assert!(
        !held.io.scan_results.is_empty(),
        "the joined path attempted scans"
    );
    assert!(
        held.io.scan_results.iter().all(|result| result.is_ok()),
        "an unchanged file refuses no scan, got {:?}",
        held.io.scan_results
    );
    drop(held);
    assert!(
        unrouted_reasons(&scene).is_empty(),
        "nothing sheds on the joined path: {:?}",
        unrouted_reasons(&scene)
    );
    assert_eq!(
        instance_summary(&scene).len(),
        1,
        "the advance continues the one instance, got {:?}",
        instance_summary(&scene)
    );
    let rows = semantic_rows(&scene);
    assert_eq!(
        rows.iter()
            .map(|(_, returns, _, _)| returns.unwrap_or(0))
            .sum::<u64>(),
        4,
        "both bursts attribute to the one instance, got {rows:?}"
    );
}
