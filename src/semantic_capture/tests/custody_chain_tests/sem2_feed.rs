//! SPDX-License-Identifier: GPL-3.0-or-later
//! sem-2: disclosure collateral for the system-scale semantic feed.
//!
//! Pins the finite scan-refusal vocabulary, the per-reason counting,
//! the aggregate scan-refusal gap text (with its no-refusal negative
//! control), the lane's shed-call accumulation beside the unrouted
//! gap, and the exact stop-line format.

use super::sem1_feed::{
    WORKLOAD_MAIN, admit_mapped, enqueue_live_like, semantic_gap_subjects, workload_scene,
};
use super::*;
use crate::attach::image_query::ImageQueryRefusal;
use crate::discovery::instances::UnknownReason;
use crate::inventory_semantics::{
    SCAN_REFUSAL_LABELS, admitted_mints_line, count_scan_refusals, image_query_refusal_index,
    image_query_refusal_label, joint_seals_line, scan_refusals_gap_reason, semantic_stop_line,
};

#[test]
fn unknown_reason_labels_are_finite_and_distinct() {
    use UnknownReason as U;
    let labeled = [
        (U::ForeignDomain, "foreign_domain"),
        (U::AuthorityExhausted, "authority_exhausted"),
        (U::InvalidImage, "invalid_image"),
        (U::Unstamped, "unstamped"),
        (U::NoFile, "no_file"),
        (U::SharedMm, "shared_mm"),
        (U::Overflow, "overflow"),
        (U::LocalFault, "local_fault"),
        (U::Straddle, "straddle"),
        (U::FaultEra, "fault_era"),
        (U::Sticky, "sticky"),
        (U::CoverageFault, "coverage_fault"),
        (U::Unobserved, "unobserved"),
        (U::Evicted, "evicted"),
        (U::IpOutside, "ip_outside"),
        (U::NotExecutable, "not_executable"),
        (U::OffsetMismatch, "offset_mismatch"),
        (U::Unpartitionable, "unpartitionable"),
        (U::InstanceCapacity, "instance_capacity"),
        (U::RangeCapacity, "range_capacity"),
        (U::PendingCapacity, "pending_capacity"),
        (U::BindingCapacity, "binding_capacity"),
        (U::Retired, "retired"),
    ];
    let mut seen = std::collections::BTreeSet::new();
    for (reason, expected) in labeled {
        assert_eq!(reason.label(), expected);
        assert!(seen.insert(expected), "duplicate label {expected}");
    }
}

#[test]
fn scan_refusal_vocabulary_is_finite_and_stable() {
    let refusals = [
        ImageQueryRefusal::Policy,
        ImageQueryRefusal::Coverage,
        ImageQueryRefusal::Custody,
        ImageQueryRefusal::Deadline,
        ImageQueryRefusal::Capacity,
        ImageQueryRefusal::Exhausted,
        ImageQueryRefusal::Stream,
        ImageQueryRefusal::Unknown,
        ImageQueryRefusal::Unstable,
        ImageQueryRefusal::Empty,
        ImageQueryRefusal::Fence,
        ImageQueryRefusal::Present,
    ];
    let labels: Vec<&str> = refusals
        .iter()
        .map(|refusal| image_query_refusal_label(*refusal))
        .collect();
    assert_eq!(
        labels.as_slice(),
        &[
            "policy",
            "coverage",
            "custody",
            "deadline",
            "capacity",
            "exhausted",
            "stream",
            "unknown",
            "unstable",
            "empty",
            "fence",
            "present"
        ]
    );
    // Index and label agree, and every slot is reached exactly once.
    let mut seen = [false; 12];
    for refusal in refusals {
        let index = image_query_refusal_index(refusal);
        assert_eq!(
            SCAN_REFUSAL_LABELS[index],
            image_query_refusal_label(refusal)
        );
        assert!(!seen[index], "duplicate slot for {refusal:?}");
        seen[index] = true;
    }
    assert!(seen.iter().all(|seen| *seen));
}

#[test]
fn scan_refusal_counting_matches_report_entries() {
    let mut counts = [0u64; 12];
    count_scan_refusals(&mut counts, &[]);
    assert_eq!(counts, [0; 12]);
    count_scan_refusals(
        &mut counts,
        &[
            ImageQueryRefusal::Unknown,
            ImageQueryRefusal::Custody,
            ImageQueryRefusal::Unknown,
        ],
    );
    let mut expected = [0u64; 12];
    expected[image_query_refusal_index(ImageQueryRefusal::Unknown)] = 2;
    expected[image_query_refusal_index(ImageQueryRefusal::Custody)] = 1;
    assert_eq!(counts, expected);
}

#[test]
fn scan_refusals_gap_names_per_reason_counts() {
    let mut scene = workload_scene();
    // The live 12-style shape: every refresh scan refused.
    let mut counts = [0u64; 12];
    count_scan_refusals(
        &mut counts,
        &[
            ImageQueryRefusal::Unknown,
            ImageQueryRefusal::Unknown,
            ImageQueryRefusal::Unknown,
            ImageQueryRefusal::Unknown,
            ImageQueryRefusal::Unknown,
            ImageQueryRefusal::Unknown,
            ImageQueryRefusal::Unknown,
            ImageQueryRefusal::Unknown,
            ImageQueryRefusal::Unknown,
            ImageQueryRefusal::Unknown,
            ImageQueryRefusal::Custody,
            ImageQueryRefusal::Custody,
        ],
    );
    scene.scene.coordinator.record_scan_refusals_gap(&counts);
    // Gaps stage until commit, as in the production stop sequence.
    scene.scene.coordinator.commit_batch(false).unwrap();
    assert_eq!(
        semantic_gap_subjects(&scene),
        vec![(
            "semantic scan refused".to_string(),
            "12 scan refusals (custody=2 unknown=10)".to_string()
        )]
    );
}

#[test]
fn scan_refusals_gap_absent_without_refusals() {
    let mut scene = workload_scene();
    scene.scene.coordinator.record_scan_refusals_gap(&[0; 12]);
    scene.scene.coordinator.commit_batch(false).unwrap();
    assert!(
        semantic_gap_subjects(&scene).is_empty(),
        "no refusals means no refusal gap"
    );
}

#[test]
fn shed_calls_accumulate_beside_unrouted_gap() {
    let mut scene = workload_scene();
    let pid = std::process::id();
    let _caller = admit_mapped(&mut scene, pid);
    // The unbound shape (as in sem1_feed): eligible records expire
    // with no target, then shed at finalization.
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
    assert_eq!(scene.lane.shed_calls_disclosed(), 0);
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
    assert_eq!(scene.lane.shed_calls_disclosed(), 2);
    assert_eq!(
        semantic_gap_subjects(&scene),
        vec![(
            "semantic calls unrouted".to_string(),
            "2 calls shed without a route (unobserved=2) with 0 bindings".to_string()
        )]
    );
}

#[test]
fn semantic_stop_line_format_is_exact() {
    assert_eq!(
        semantic_stop_line(0, 0, 0, 0, 0, 0, 0, 0, 0),
        "p11scope: semantic calls: collected 0, joined 0, shed 0, lost 0, bindings 0, refused 0, \
         hook misses 0, eras 0, instances 0"
    );
    // The live run's shape: burst collected, nothing joined, every
    // refresh scan refused.
    assert_eq!(
        semantic_stop_line(68, 0, 68, 0, 0, 12, 2318, 41, 3),
        "p11scope: semantic calls: collected 68, joined 0, shed 68, lost 0, bindings 0, refused 12, \
         hook misses 2318, eras 41, instances 3"
    );
    assert_eq!(scan_refusals_gap_reason(&[0; 12]), None);
}

#[test]
fn admitted_mints_line_format_is_exact() {
    assert_eq!(
        admitted_mints_line(0, 0, 0),
        "p11scope: admitted mints: reported=0 attached=0 feeds=0"
    );
    assert_eq!(
        admitted_mints_line(3, 1, 1),
        "p11scope: admitted mints: reported=3 attached=1 feeds=1"
    );
}

#[test]
fn joint_seals_line_format_is_exact() {
    assert_eq!(
        joint_seals_line(0, 0, 0, 0, 0, 0, "none", 0, 0, 0, 0, 0, 0, 0),
        "p11scope: joint seals: attempts=0 local_pending=0 await_future_input=0 \
         delivery_ready=0 complete=0 refused=0 last_refusal=none \
         d_complete=0 d_yielded=0 d_held=0 d_replayed=0 d_disposed=0 \
         d_entry_zero=0 d_entry_exhausted=0"
    );
    assert_eq!(
        joint_seals_line(12, 3, 7, 1, 1, 2, "Capacity", 4, 5, 6, 70, 8, 9, 10),
        "p11scope: joint seals: attempts=12 local_pending=3 await_future_input=7 \
         delivery_ready=1 complete=1 refused=2 last_refusal=Capacity \
         d_complete=4 d_yielded=5 d_held=6 d_replayed=70 d_disposed=8 \
         d_entry_zero=9 d_entry_exhausted=10"
    );
}
