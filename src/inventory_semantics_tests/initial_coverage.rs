//! SPDX-License-Identifier: GPL-3.0-or-later
//! Registry publication ordering, using the existing converted-registration
//! seam. These timestamps disclose observation order, never call authority.

use super::*;
use crate::discovery::caller_registry::{
    CallerRegistry, CoverageNote, RegistryGap, RegistryLimits, UseCoverage,
};

fn gaps(registry: &CallerRegistry) -> Vec<RegistryGap> {
    registry
        .gaps()
        .iter()
        .filter(|gap| gap.reason == "before_semantic_boundary")
        .cloned()
        .collect()
}

fn assert_same_pass_disclosure(physical_first: bool) {
    let mut conv = ConversionScene::new();
    let module = conv.scene.module.clone();
    let id = conv.ids[0];
    let coverage = conv.coverage(vec![id]);
    if physical_first {
        conv.scene.coordinator.registry_mut().note_counted_use(
            conv.caller,
            &module,
            7,
            100,
            300,
            0,
        );
    }
    conv.register(&coverage, id, 200, None);
    conv.register(&coverage, id, 220, None);
    if !physical_first {
        conv.scene.coordinator.registry_mut().note_counted_use(
            conv.caller,
            &module,
            7,
            100,
            300,
            0,
        );
    }
    conv.commit();
    let registry = conv.scene.coordinator.registry();
    let disclosed = gaps(registry);
    assert_eq!(disclosed.len(), 1, "physical_first={physical_first}");
    assert_eq!(disclosed[0].caller, Some(conv.caller));
    assert_eq!(disclosed[0].module, registry.module_id_for(&module));
    assert_eq!(disclosed[0].pid, None);
    assert_eq!(disclosed[0].budget, None);
    assert_eq!(registry.instances().count(), 1);
    assert_eq!(registry.instances().next().unwrap().first_seen_ns, 200);
    assert_eq!(conv.edge_rows(), vec![(None, 0, false, 0, 0)]);
    let gap_index = registry
        .gaps()
        .iter()
        .position(|gap| gap == &disclosed[0])
        .unwrap();
    for _ in 0..3 {
        conv.register(&coverage, id, 400, None);
        conv.commit();
        let registry = conv.scene.coordinator.registry();
        assert_eq!(gaps(registry), disclosed);
        assert_eq!(registry.gap_repeats()[gap_index], 1);
        assert_eq!(
            registry
                .edge(conv.caller, registry.module_id_for(&module).unwrap())
                .unwrap()
                .entry_count,
            7
        );
    }
}

#[test]
fn native_semantic_initial_coverage_physical_then_instance_discloses_once() {
    assert_same_pass_disclosure(true);
}

#[test]
fn native_semantic_initial_coverage_instance_then_physical_discloses_once() {
    assert_same_pass_disclosure(false);
}

#[test]
fn native_semantic_initial_coverage_delayed_physical_reveal_discloses() {
    let mut conv = ConversionScene::new();
    let module = conv.scene.module.clone();
    let id = conv.ids[0];
    let coverage = conv.coverage(vec![id]);
    conv.register(&coverage, id, 200, None);
    conv.commit();
    assert!(gaps(conv.scene.coordinator.registry()).is_empty());
    conv.scene
        .coordinator
        .registry_mut()
        .note_counted_use(conv.caller, &module, 7, 100, 400, 0);
    conv.commit();
    assert_eq!(gaps(conv.scene.coordinator.registry()).len(), 1);
    assert_eq!(conv.edge_rows(), vec![(None, 0, false, 0, 0)]);
}

#[test]
fn native_semantic_initial_coverage_requires_strictly_earlier_positive_use() {
    for (kind, first_ns, expected) in [
        ("counted", 100, 1),
        ("witnessed", 100, 1),
        ("zero", 100, 0),
        ("watch", 100, 0),
        ("map", 100, 0),
        ("counted", 200, 0),
        ("counted", 300, 0),
        ("witnessed", 200, 0),
        ("witnessed", 300, 0),
    ] {
        let mut conv = ConversionScene::new();
        let module = conv.scene.module.clone();
        let id = conv.ids[0];
        let coverage = conv.coverage(vec![id]);
        let registry = conv.scene.coordinator.registry_mut();
        match kind {
            "counted" | "zero" => registry.note_counted_use(
                conv.caller,
                &module,
                if kind == "zero" { 0 } else { 7 },
                first_ns,
                400,
                0,
            ),
            "witnessed" => registry.note_witness(conv.caller, &module, first_ns),
            "watch" => registry.note_coverage(
                conv.caller,
                &module,
                CoverageNote::Watched { since_ns: first_ns },
            ),
            "map" => {}
            _ => unreachable!(),
        }
        conv.register(&coverage, id, 200, None);
        conv.commit();
        assert_eq!(
            gaps(conv.scene.coordinator.registry()).len(),
            expected,
            "{kind} first={first_ns}"
        );
        assert_eq!(conv.edge_rows(), vec![(None, 0, false, 0, 0)]);
    }
}

#[test]
fn native_semantic_initial_coverage_uses_earliest_registration_for_exact_pair() {
    let mut conv = ConversionScene::new();
    let module = conv.scene.module.clone();
    let other = ModuleKey::physical(7, 7, 778, None, "/task3/other.so");
    let sibling = CallerId(conv.caller.0 + 1);
    conv.scene.map(sibling, std::process::id() + 1, 60);
    map_sibling_module(&mut conv, &other, "/task3/other.so", 70);
    let (first, replacement) = (conv.ids[0], conv.ids[1]);
    let coverage = conv.coverage(vec![first, replacement]);
    conv.register(&coverage, first, 200, None);
    conv.commit();
    conv.scene
        .coordinator
        .registry_mut()
        .note_counted_use(sibling, &module, 7, 100, 400, 0);
    conv.scene
        .coordinator
        .registry_mut()
        .note_counted_use(conv.caller, &other, 7, 100, 400, 0);
    conv.scene
        .coordinator
        .registry_mut()
        .note_counted_use(conv.caller, &module, 7, 300, 400, 0);
    conv.register(&coverage, replacement, 500, None);
    conv.commit();
    assert!(
        gaps(conv.scene.coordinator.registry()).is_empty(),
        "a replacement cannot restart the original interval; other callers/modules have no registration"
    );
    assert_eq!(conv.scene.coordinator.registry().instances().count(), 2);

    let input = instance::registration(
        instance::key(conv.detailed(), conv.image, conv.ids[2], other.clone()),
        conv.caller,
        500,
        None,
    );
    conv.scene.coordinator.registry_mut().note_instance(input);
    conv.commit();
    let registry = conv.scene.coordinator.registry();
    let disclosed = gaps(registry);
    assert_eq!(disclosed.len(), 1);
    assert_eq!(
        (disclosed[0].caller, disclosed[0].module),
        (Some(conv.caller), registry.module_id_for(&other))
    );
}

#[test]
fn native_semantic_initial_coverage_refused_registration_cannot_disclose() {
    let mut conv = ConversionScene::new();
    let module = conv.scene.module.clone();
    let id = conv.ids[0];
    let coverage = conv.coverage(vec![id]);
    conv.scene
        .coordinator
        .registry_mut()
        .reference_instance_limit(0);
    conv.scene
        .coordinator
        .registry_mut()
        .note_counted_use(conv.caller, &module, 7, 100, 300, 0);
    conv.register(&coverage, id, 200, None);
    conv.commit();
    let registry = conv.scene.coordinator.registry();
    assert_eq!(registry.instances().count(), 0);
    assert_eq!(registry.instance_refused(), 1);
    assert!(
        registry
            .gaps()
            .iter()
            .any(|gap| gap.reason == "instance_capacity")
    );
    assert!(gaps(registry).is_empty());
    assert_eq!(
        registry
            .edge(conv.caller, registry.module_id_for(&module).unwrap())
            .unwrap()
            .entry_count,
        7
    );
}

#[test]
fn native_semantic_initial_coverage_suppression_stays_bounded() {
    let conv = ConversionScene::new();
    let module = conv.scene.module.clone();
    let domain = conv.detailed();
    let key = instance::key(domain, conv.image, conv.ids[0], module.clone());
    // Exercise the same registry with a one-gap retention limit. Registration
    // uses a router-minted key; no H0 authority is claimed by this unit seam.
    let mut registry = CallerRegistry::new(RegistryLimits::new(8, 8, 8, 1, 64, 8).unwrap());
    registry.note_mapping(
        conv.caller,
        std::process::id(),
        ModuleInfo {
            path: "/task3/provider.so".into(),
            key: module.clone(),
            double_loaded: false,
            build_id: None,
            identity_source: Some("task3".into()),
            admission: AdmissionState::Admitted,
            admission_class: Some("exact".into()),
            admission_endpoints: Some(1),
            admission_reasons: Vec::new(),
        },
        60,
    );
    registry.record_gap(RegistryGap {
        caller: None,
        module: None,
        pid: None,
        subject: "existing gap".into(),
        reason: "existing".into(),
        budget: None,
    });
    registry.note_counted_use(conv.caller, &module, 7, 100, 300, 0);
    registry.note_instance(instance::registration(key.clone(), conv.caller, 200, None));
    registry.publish();
    assert_eq!(registry.gaps().len(), 1);
    assert_eq!(registry.gaps_suppressed(), 1);
    for _ in 0..3 {
        registry.note_instance(instance::registration(key.clone(), conv.caller, 400, None));
        registry.publish();
        assert_eq!(
            registry.gaps_suppressed(),
            1,
            "one distinct suppressed ordering gap"
        );
        assert_eq!(registry.gap_repeats(), &[1]);
    }
}

#[test]
fn native_semantic_initial_coverage_stamp_does_not_demote_current_calls() {
    let mut conv = ConversionScene::new();
    let module = conv.scene.module.clone();
    let id = conv.ids[0];
    let coverage = conv.coverage(vec![id]);
    conv.scene
        .coordinator
        .registry_mut()
        .note_counted_use(conv.caller, &module, 7, 100, 300, 0);
    conv.register(&coverage, id, 200, None);
    // Actual current coverage authorizes these calls even though their event
    // timestamps precede the registration's later batch observation stamp.
    conv.feed(
        conv.evidence(1, id, conv.init_slot, conv.init_event(110)),
        CallStanding::Current(&coverage),
        None,
    );
    conv.feed(
        conv.evidence(2, id, conv.sign_slot, conv.sign_event(120)),
        CallStanding::Current(&coverage),
        None,
    );
    conv.commit();
    let registry = conv.scene.coordinator.registry();
    assert_eq!(gaps(registry).len(), 1);
    assert_eq!(conv.edge_rows(), vec![(Some(2), 0, false, 1, 1)]);
    assert_eq!(conv.instance_states(), vec![InstanceLifecycle::Observed]);
    assert_eq!(
        registry.coverage(
            registry
                .edge(conv.caller, registry.module_id_for(&module).unwrap())
                .unwrap()
        ),
        UseCoverage::Counted {
            since_ns: 100,
            lossy: false
        }
    );
}
