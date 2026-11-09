//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! sem-3: refused-admission disclosure at the production H0 seam.
//!
//! Live shape (system run, pre-existing caller): mapped and
//! manifest-matched, no binding before first usage (the H0 refresh
//! scan refuses while the task has no BPF cookie). The refused
//! attempt must name the exact firing site, not a bare reason.

use super::sem1_feed::{
    WORKLOAD_MAIN, admit_mapped, enqueue_live_like, production_bind, semantic_gap_subjects,
    workload_scene,
};
use super::*;

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
            "semantic admission deferred".to_string(),
            "semantic_unavailable:no_receipt".to_string()
        )]
    );
}

fn joined_calls(scene: &RealScene) -> u64 {
    scene.h0.0.borrow().capture.router().counters().joined
}

/// The calls the caller's own S1 edges joined (`api_returns`), read
/// from the published registry rather than the router's counter.
fn caller_edge_calls(scene: &RealScene, caller: CallerId) -> u64 {
    scene
        .scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .filter(|record| record.caller == caller)
        .filter_map(|record| record.api_returns)
        .sum()
}

fn has_loss_subject(scene: &RealScene) -> bool {
    semantic_gap_subjects(scene).iter().any(|(subject, _)| {
        subject == "semantic admission refused" || subject == "semantic calls unrouted"
    })
}

/// A receipt-less pass defers admission; the next pass retries it and
/// the caller's later calls join. The deferral is a named non-loss
/// note, never a loss gap. (Calls made *while* deferred are covered by
/// `deferred_admission_calls_before_the_retry_join`.)
#[test]
fn deferred_admission_retry_joins_every_call() {
    let mut scene = workload_scene();
    let pid = std::process::id();
    let caller = admit_mapped(&mut scene, pid);
    scene.h0.0.borrow_mut().io.script.fail_file = Some(0);
    assert!(!attempt_production_bind(&mut scene, caller, pid));
    scene.scene.coordinator.commit_batch(false).unwrap();
    scene.h0.0.borrow_mut().io.script.fail_file = None;
    production_bind(&mut scene, caller, pid, image(7));
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid, name, *mechanism);
    }
    let batch = scene.tick();
    scene.publish(batch);
    assert_eq!(joined_calls(&scene), 2, "every call joins after the retry");
    assert_eq!(
        caller_edge_calls(&scene, caller),
        2,
        "the caller's S1 edge counts both calls"
    );
    assert_eq!(
        scene
            .scene
            .coordinator
            .registry()
            .instance_semantic_occupied(),
        1
    );
    assert!(
        !has_loss_subject(&scene),
        "a retried admission is not loss: {:?}",
        semantic_gap_subjects(&scene)
    );
    assert!(
        semantic_gap_subjects(&scene).contains(&(
            "semantic admission deferred".to_string(),
            "semantic_unavailable:no_receipt".to_string()
        )),
        "the deferral stays named: {:?}",
        semantic_gap_subjects(&scene)
    );
}

/// Failure twin: the caller is never admitted, so its calls shed with
/// no route. That loss is disclosed under its own loss subject; the
/// deferral note never hides it.
#[test]
fn deferred_admission_never_retried_discloses_shed_calls() {
    let mut scene = workload_scene();
    let pid = std::process::id();
    let caller = admit_mapped(&mut scene, pid);
    scene.h0.0.borrow_mut().io.script.fail_file = Some(0);
    assert!(!attempt_production_bind(&mut scene, caller, pid));
    scene.scene.coordinator.commit_batch(false).unwrap();
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid, name, *mechanism);
    }
    scene.h0.0.borrow_mut().io.targets.clear();
    let batch = scene.lane.tick(&[]).unwrap();
    scene.publish(batch);
    assert_eq!(joined_calls(&scene), 0);
    assert!(
        semantic_gap_subjects(&scene)
            .iter()
            .any(|(subject, _)| subject == "semantic calls unrouted"),
        "shed calls are a named loss: {:?}",
        semantic_gap_subjects(&scene)
    );
}

/// Calls queued between the deferred pass and the retry, with a frame
/// tick in between (the live order), join after the retry.
#[test]
fn deferred_admission_calls_before_the_retry_join() {
    let mut scene = workload_scene();
    let pid = std::process::id();
    let caller = admit_mapped(&mut scene, pid);
    scene.h0.0.borrow_mut().io.script.fail_file = Some(0);
    assert!(!attempt_production_bind(&mut scene, caller, pid));
    scene.scene.coordinator.commit_batch(false).unwrap();
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid, name, *mechanism);
    }
    let batch = scene.tick();
    scene.publish(batch);
    scene.h0.0.borrow_mut().io.script.fail_file = None;
    production_bind(&mut scene, caller, pid, image(7));
    let batch = scene.tick();
    scene.publish(batch);
    assert_eq!(joined_calls(&scene), 2, "queued calls join after the retry");
    assert_eq!(
        caller_edge_calls(&scene, caller),
        2,
        "the caller's S1 edge counts both calls made while deferred"
    );
    assert!(
        !has_loss_subject(&scene),
        "{:?}",
        semantic_gap_subjects(&scene)
    );
}

/// Only a missing receipt defers: every other unavailable site keeps
/// the `semantic admission refused` loss gap at the coordinator.
#[test]
fn non_receipt_unavailable_sites_stay_refused_at_the_coordinator() {
    use crate::inventory_semantics::{AdmissionPreparationError, AdmissionUnavailableSite as Site};
    for (site, deferred) in [
        (Site::RefreshFailed, false),
        (Site::CollectedQInvalid, false),
        (Site::NoReceipt, true),
    ] {
        let mut scene = workload_scene();
        let caller = admit_mapped(&mut scene, std::process::id());
        scene.scene.coordinator.semantic_admission_prepare_failed(
            caller,
            AdmissionPreparationError::unavailable(site),
        );
        scene.scene.coordinator.commit_batch(false).unwrap();
        let subject = if deferred {
            "semantic admission deferred"
        } else {
            "semantic admission refused"
        };
        assert_eq!(
            semantic_gap_subjects(&scene),
            vec![(
                subject.to_string(),
                format!("semantic_unavailable:{}", site.label())
            )],
            "site {}",
            site.label()
        );
    }
}
