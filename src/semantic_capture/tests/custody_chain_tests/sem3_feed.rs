//! SPDX-License-Identifier: GPL-3.0-or-later
//! sem-3: refused-admission disclosure at the production H0 seam.
//!
//! Live shape (system run, pre-existing caller): mapped and
//! manifest-matched, no binding before first usage (the H0 refresh
//! scan refuses while the task has no BPF cookie). The refused
//! attempt must name the exact firing site, not a bare reason.

use super::sem1_feed::{admit_mapped, semantic_gap_subjects, workload_scene};
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
            "semantic admission refused".to_string(),
            "semantic_unavailable:no_receipt".to_string()
        )]
    );
}
