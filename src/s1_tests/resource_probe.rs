//! SPDX-License-Identifier: GPL-3.0-or-later
//! Retained H2 metadata and output costs, separately from reducer costs.
//! H3's final unpublished-batch and instance-emitter types do not exist yet;
//! measuring H2 envelopes here does not stand in for those future types.

use super::*;
use crate::discovery::caller_registry::instance_input::{
    AdmittedInstance, AdmittedInstanceCall, InstanceRecord, InstanceSemanticRecord,
    MAX_INSTANCE_NEGATIVE_SCOPES, MAX_REGISTRY_INSTANCES,
};
use crate::semantics_edge::resource_tests::{Memory, measure, run_child};
use std::mem::size_of;

#[test]
fn native_semantic_resource_legacy_and_instance_share_one_pool() {
    use crate::semantics_edge::resources::{
        ACTIVE_MACHINE_CHARGE, REDUCER_BASE_CHARGE, SEMANTIC_TRANSITION_SCRATCH,
    };
    let (mut h, caller, module) = single_edge();
    let domain = NativeDomainId::mint();
    let key = instance_key(domain, instance_router_ids(domain, 1)[0], &module);
    h.coordinator_mut()
        .registry_mut()
        .reference_semantic_resource_limit(
            SEMANTIC_TRANSITION_SCRATCH + 2 * REDUCER_BASE_CHARGE + 2 * ACTIVE_MACHINE_CHARGE,
        );
    let unknown = SemanticCall {
        capture: capture::MECHANISM_UNREADABLE,
        ..init("C_SignInit", 1, RSA_PSS, 100)
    };
    h.observe_semantic(caller, &module, unknown.clone());
    instance_register(&mut h, &key, caller, 100);
    instance_feed(&mut h, &key, caller, domain, 2, unknown);
    h.coordinator_mut()
        .registry_mut()
        .observe_entries(caller, &module, 17, 100);
    h.commit();
    let registry = h.coordinator().registry();
    assert_eq!(
        registry
            .edges()
            .next()
            .unwrap()
            .semantics
            .as_ref()
            .unwrap()
            .started(),
        1
    );
    assert_eq!(
        registry
            .instance_semantic_edges()
            .next()
            .unwrap()
            .semantics
            .as_ref()
            .unwrap()
            .started(),
        1
    );
    assert_eq!(
        registry.semantic_resource_snapshot().charged_bytes,
        registry.semantic_resource_snapshot().limit_bytes
    );
    instance_feed(
        &mut h,
        &key,
        caller,
        domain,
        4,
        SemanticCall {
            capture: capture::MECHANISM_UNREADABLE,
            ..init("C_SignInit", 2, RSA_PSS, 110)
        },
    );
    h.commit();
    let registry = h.coordinator().registry();
    let legacy = registry.edges().next().unwrap();
    assert_eq!(legacy.entry_count, 17);
    assert!(legacy.semantics.as_ref().unwrap().has_live_operations());
    let instance = registry.instance_semantic_edges().next().unwrap();
    assert_eq!(instance.api_returns, Some(2));
    let state = instance.semantics.as_ref().unwrap();
    assert_eq!((state.started(), state.unknown()), (1, 1));
    assert!(!state.has_live_operations());
    assert!(
        instance
            .reasons
            .iter()
            .any(|reason| reason.label() == "semantic_resource_capacity")
    );
    assert_eq!(registry.semantic_resource_snapshot().refused, 1);
    assert!(
        registry
            .gaps()
            .iter()
            .any(|gap| gap.reason == "semantic_resource_capacity")
    );
    // A unique return minted before the refusal remains countable, but
    // the persisted ordinal boundary prevents it from reopening authority.
    instance_feed(
        &mut h,
        &key,
        caller,
        domain,
        3,
        SemanticCall {
            capture: capture::MECHANISM_UNREADABLE,
            ..init("C_SignInit", 3, RSA_PSS, 105)
        },
    );
    h.commit();
    let instance = h
        .coordinator()
        .registry()
        .instance_semantic_edges()
        .next()
        .unwrap();
    assert_eq!(
        (instance.api_returns, instance.historical_only_returns),
        (Some(3), 1)
    );
    assert_eq!(instance.semantics.as_ref().unwrap().started(), 1);
    assert!(!instance.semantics.as_ref().unwrap().has_live_operations());
    instance_feed(
        &mut h,
        &key,
        caller,
        domain,
        5,
        SemanticCall {
            capture: capture::MECHANISM_UNREADABLE,
            ..init("C_SignInit", 4, RSA_PSS, 120)
        },
    );
    instance_feed(&mut h, &key, caller, domain, 6, op("C_Sign", 4, 130));
    h.commit();
    let registry = h.coordinator().registry();
    let instance = registry.instance_semantic_edges().next().unwrap();
    assert_eq!(
        (instance.api_returns, instance.historical_only_returns),
        (Some(5), 1)
    );
    let state = instance.semantics.as_ref().unwrap();
    assert_eq!(
        (state.started(), state.completed(), state.unknown()),
        (2, 1, 1)
    );
    assert!(!state.has_live_operations());
    assert_eq!(registry.edges().next().unwrap().entry_count, 17);
    assert!(
        registry
            .edges()
            .next()
            .unwrap()
            .semantics
            .as_ref()
            .unwrap()
            .has_live_operations()
    );
}

#[test]
fn native_semantic_resource_registry_probe_child() {
    let Ok(profile) = std::env::var("P11SCOPE_S1_RESOURCE_PROFILE") else {
        return;
    };
    let (kind, population) = profile.rsplit_once(':').unwrap();
    let population = population.parse::<usize>().unwrap();
    assert!(population > 0 && population <= MAX_REGISTRY_INSTANCES);
    assert!(matches!(kind, "metadata" | "published"));
    let (mut h, caller, _) = single_edge();
    let mut info = crate::discovery::inventory_workload::scale_module_info(1, 1);
    info.key = ModuleKey::physical(8, 1, 100_001, Some("a".repeat(64)), &info.path);
    let module = info.key.clone();
    h.coordinator_mut()
        .registry_mut()
        .note_mapping(caller, 9000, info, 1);
    let domain = NativeDomainId::mint();
    let router = instance_router_ids(domain, 1)[0];
    h.coordinator_mut()
        .registry_mut()
        .observe_entries(caller, &module, 17, 1);
    h.commit();
    let (keys, keys_cost) = measure("full_instance_keys", || {
        (0..population)
            .map(|index| {
                instance::key(
                    domain,
                    ImageIdentity {
                        task_cookie: 1000 + index as u64,
                        exec_id: 0,
                    },
                    router,
                    module.clone(),
                )
            })
            .collect::<Vec<_>>()
    });
    let (_, registry_cost) = measure("register_and_publish_retained_instances", || {
        for key in &keys {
            instance_register(&mut h, key, caller, 100);
        }
        h.commit();
    });
    assert_eq!(h.coordinator().registry().instances().count(), population);
    assert_eq!(h.coordinator().registry().instance_semantic_occupied(), 0);
    let mut stages = vec![keys_cost, registry_cost];
    if kind == "published" {
        let (_, reducer_cost) = measure("feed_sparse_instance_reducers", || {
            // A publication carries at most 1024 calls, matching the
            // ordinary H0 quantum rather than measuring an unbounded FIFO.
            for quantum in keys.chunks(512) {
                for key in quantum {
                    instance_feed(
                        &mut h,
                        key,
                        caller,
                        domain,
                        1,
                        init("C_SignInit", 1, RSA_PSS, 101),
                    );
                    instance_feed(&mut h, key, caller, domain, 2, op("C_Sign", 1, 102));
                }
                h.commit();
            }
        });
        assert_eq!(
            h.coordinator().registry().instance_semantic_occupied(),
            population
        );
        stages.push(reducer_cost);
    }
    // The actual sealed H2 envelopes are a measured lower-level component
    // of H3's bounded unpublished batch; no second queue is added to runtime.
    let batch_count = population.min(1024);
    let (batch, batch_cost) = measure("unpublished_h2_call_envelopes", || {
        keys.iter()
            .take(batch_count)
            .map(|key| {
                instance::call(
                    key.clone(),
                    caller,
                    instance::position(domain, 3),
                    op("C_Sign", 1, 103),
                    Some(InstanceReason::SemanticLoss),
                )
            })
            .collect::<Vec<_>>()
    });
    assert_eq!(batch.len(), batch_count);
    stages.push(batch_cost);
    let (_, negative_cost) = measure("retain_full_negative_ledger", || {
        for index in 0..MAX_INSTANCE_NEGATIVE_SCOPES {
            h.coordinator_mut()
                .registry_mut()
                .note_instance_semantic_loss(instance::loss(
                    instance::Scope::Image(
                        domain,
                        ImageIdentity {
                            task_cookie: 10_000 + index as u64,
                            exec_id: 0,
                        },
                    ),
                    instance::position(domain, 4),
                    InstanceReason::SemanticLoss,
                ));
        }
        h.commit();
    });
    assert_eq!(
        h.coordinator().registry().instance_negative_occupied(),
        MAX_INSTANCE_NEGATIVE_SCOPES
    );
    stages.push(negative_cost);
    let (presentation, presentation_cost) = measure("immutable_presentation", || {
        Presentation::capture(h.coordinator(), "resource-probe", 0, 105, 1)
    });
    assert_eq!(presentation.instances.len(), population);
    assert_eq!(presentation.semantic_edges.len(), population);
    stages.push(presentation_cost);
    let (document, document_cost) = measure("json_value_from_same_presentation", || {
        crate::inventory::render_json_from_presentation(&presentation)
    });
    assert_eq!(document["instances"].as_array().unwrap().len(), population);
    assert_eq!(
        document["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| edge["entries"]["count"].as_u64().unwrap())
            .sum::<u64>(),
        17
    );
    stages.push(document_cost);
    let (serialized, serialize_cost) = measure("serialized_json_buffer", || {
        serde_json::to_vec(&document).unwrap()
    });
    stages.push(serialize_cost);
    let (size, needs_drop, _) = instance::negative_payload_debug(
        domain,
        ImageIdentity {
            task_cookie: 1,
            exec_id: 0,
        },
    );
    assert!(!needs_drop);
    let memory = Memory::read();
    let row = serde_json::json!({
        "profile": profile, "instances": population, "negative_scopes": MAX_INSTANCE_NEGATIVE_SCOPES,
        "h2_unpublished_envelopes": batch.len(), "serialized_json_bytes": serialized.len(),
        "sample_physical_key_sha256_bytes": 64,
        "stages": stages, "after_measurement": memory.json(),
        "actual_type_sizes": {
            "InstanceKey": size_of::<InstanceKey>(), "ModuleKey": size_of::<ModuleKey>(),
            "InstanceRecord": size_of::<InstanceRecord>(), "InstanceSemanticRecord": size_of::<InstanceSemanticRecord>(),
            "AdmittedInstance": size_of::<AdmittedInstance>(), "AdmittedInstanceCall": size_of::<AdmittedInstanceCall>(),
            "negative_record": size, "Presentation": size_of::<Presentation>(),
            "InstanceView": size_of::<crate::inventory_present::InstanceView>(),
            "InstanceSemanticView": size_of::<crate::inventory_present::InstanceSemanticView>(),
        },
        "unmeasured_future_types": ["H3 SemanticBatch owner/receipts", "Task5 InstanceEmitter tracking"],
    });
    println!("\nS1_RESOURCE_ROW {row}");
    std::hint::black_box((h, keys, batch, presentation, document, serialized));
}

#[test]
#[ignore = "explicit controller-granted host measurement; spawns bounded children"]
fn native_semantic_resource_registry_probe() {
    for profile in [
        "metadata:1",
        "metadata:4096",
        "published:1",
        "published:256",
        "published:4096",
    ] {
        let row = run_child(
            "s1_tests::resource_probe::native_semantic_resource_registry_probe_child",
            profile,
        );
        println!("S1_RESOURCE_RESULT {row}");
    }
}
