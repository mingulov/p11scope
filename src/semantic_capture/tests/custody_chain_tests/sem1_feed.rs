//! SPDX-License-Identifier: GPL-3.0-or-later
//! sem-1: shed-call disclosure at the production H0 seam.
//!
//! Live-shaped records (manifest-A function set, P1/P7 mechanism workload)
//! through production admission, tick, stage, finalize and publish. Calls
//! that never join an instance shed silently today: no gap, no counter,
//! occupancy stays 0. These tests pin the disclosure the honest-reporting
//! contract requires; they are ignored until the owning lane lands it.

use super::*;
use p11scope_ebpf_common::{MECH_NONE, SESSION_NONE};

/// The live workload's exact function set (a subset of manifest-A's 68
/// resolved 2.40 functions; slot iteration has no count gate, so the
/// subset preserves every production decision on this path).
const WORKLOAD_FUNCTIONS: [&str; 11] = [
    "C_DigestInit",
    "C_Digest",
    "C_GenerateKey",
    "C_EncryptInit",
    "C_Encrypt",
    "C_SignInit",
    "C_Sign",
    "C_DestroyObject",
    "C_Logout",
    "C_CloseSession",
    "C_Finalize",
];

/// (function, mechanism): the 8 paired calls per live iteration.
const WORKLOAD_MAIN: [(&str, u64); 8] = [
    ("C_DigestInit", 0x250),
    ("C_Digest", 0),
    ("C_GenerateKey", 0x1080),
    ("C_EncryptInit", 0x1087),
    ("C_Encrypt", 0),
    ("C_GenerateKey", 0x350),
    ("C_SignInit", 0x251),
    ("C_Sign", 0),
];

fn workload_scene() -> RealScene {
    RealScene::from_held(HeldProviders::with_functions(1, &WORKLOAD_FUNCTIONS))
}

/// Admit one caller and publish its mapped attested edge (the scan-lane
/// projection), without binding it: mirrors the live P1 state after the
/// mapping commits and before semantic admission runs.
fn admit_mapped(scene: &mut RealScene, pid: u32) -> CallerId {
    let caller = scene.scene.admit(pid, 50);
    for (file, (key, path)) in scene.modules.iter().enumerate() {
        scene.scene.coordinator.registry_mut().note_mapping(
            caller,
            pid,
            ModuleInfo {
                path: path.clone(),
                key: key.clone(),
                double_loaded: false,
                build_id: None,
                identity_source: Some("held-provider".into()),
                admission: AdmissionState::Admitted,
                admission_class: Some("exact".into()),
                admission_endpoints: Some(
                    scene
                        .h0
                        .0
                        .borrow()
                        .io
                        .endpoints
                        .iter()
                        .filter(|(_, _, endpoint)| endpoint.file_slot as usize == file)
                        .count(),
                ),
                admission_reasons: Vec::new(),
            },
            60,
        );
    }
    scene.scene.coordinator.commit_batch(false).unwrap();
    caller
}

/// Bind through the production per-pass entry (what ClassicDriver::apply
/// runs): selection, candidate seal, H0 refresh admission and consume.
/// H0 scan targets are served through the adapter's shared custody Arc
/// up front, so refresh, binding and tick share one custody Arc exactly
/// as in production.
fn production_bind(scene: &mut RealScene, caller: CallerId, pid: u32, image: ImageIdentity) {
    let pin = scene
        .scene
        .coordinator
        .adapter()
        .shared_semantic_custody(caller)
        .expect("the live caller shares its custody Arc");
    scene.h0.0.borrow_mut().io.targets.insert(pid, (pin, image));
    crate::inventory_semantics::bind_semantic_callers_inner(
        &mut scene.scene.coordinator,
        &mut scene.lane,
        None,
    );
    let binding = scene
        .scene
        .coordinator
        .semantic_bindings()
        .get(caller)
        .expect("production bind admits the attested mapped caller");
    assert_eq!(binding.image(), image);
    assert!(
        std::sync::Arc::ptr_eq(&binding.pin(), &scene.h0.0.borrow().io.targets[&pid].0),
        "binding and H0 targets share one custody Arc"
    );
}

/// Enqueue one workload call shaped like the live BPF record: the real
/// slot, captured mechanism argument on mechanism-bearing calls, session
/// handle, rv 0 and main-thread identity.
fn enqueue_live_like(scene: &mut RealScene, pid: u32, name: &str, mechanism: u64) {
    scene
        .h0
        .0
        .borrow_mut()
        .io
        .enqueue(pid, 0, name, mechanism, 0);
    let mut h0 = scene.h0.0.borrow_mut();
    let record = h0.io.script.records.back_mut().unwrap();
    record.base.event.pid_tgid |= record.base.event.pid_tgid >> 32;
    if mechanism != MECH_NONE {
        record.base.event.capture |= capture::MECHANISM_VALUE;
    }
    if name == "C_Finalize" {
        record.base.event.session = SESSION_NONE;
    }
}

fn semantic_gap_subjects(scene: &RealScene) -> Vec<(String, String)> {
    scene
        .scene
        .coordinator
        .registry()
        .gaps()
        .iter()
        .map(|gap| (gap.subject.clone(), gap.reason.clone()))
        .filter(|(subject, _)| subject.contains("semantic") || subject.contains("instance"))
        .collect()
}

#[ignore = "shed semantic calls are not disclosed yet (no gap or counter); un-ignore when disclosure lands"]
#[test]
fn unbound_eligible_calls_are_disclosed() {
    let mut scene = workload_scene();
    let pid = std::process::id();
    let _caller = admit_mapped(&mut scene, pid);
    // No binding is ever admitted (the live run's shape: bindings
    // absent, no gaps): the pending calls expire with no target.
    // Targets shape the records' image (as BPF would), then drop
    // before the tick so H0 serves no scan target, exactly like a
    // production tick over empty binding pins.
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
        scene
            .scene
            .coordinator
            .registry()
            .instance_semantic_occupied(),
        0,
        "unbound calls materialize nothing"
    );
    assert!(
        !semantic_gap_subjects(&scene).is_empty(),
        "shed eligible calls are disclosed, got no semantic gap"
    );
}

#[ignore = "shed semantic calls are not disclosed yet (no gap or counter); un-ignore when disclosure lands"]
#[test]
fn fault_era_unknown_calls_are_disclosed() {
    let mut scene = workload_scene();
    let pid = std::process::id();
    let caller = admit_mapped(&mut scene, pid);
    production_bind(&mut scene, caller, pid, image(7));
    // Stale-era stamps (a live fault-raise race shape): every call
    // routes Unknown and sheds at finalization.
    for (name, mechanism) in WORKLOAD_MAIN.iter().take(2) {
        enqueue_live_like(&mut scene, pid, name, *mechanism);
    }
    {
        let mut h0 = scene.h0.0.borrow_mut();
        for record in h0.io.script.records.iter_mut() {
            record.base.continuity.entry_stamp.fault = 1;
            record.base.continuity.return_stamp.fault = 1;
        }
    }
    let batch = scene.tick();
    scene.publish(batch);
    assert_eq!(
        scene
            .scene
            .coordinator
            .registry()
            .instance_semantic_occupied(),
        0,
        "unrouted calls materialize nothing"
    );
    assert!(
        !semantic_gap_subjects(&scene).is_empty(),
        "shed eligible calls are disclosed, got no semantic gap"
    );
}
