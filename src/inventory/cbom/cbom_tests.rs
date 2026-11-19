//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Focused CBOM twins: classifier mapping, mechanism union, key
//! filtering, profile input and degraded-row handling.

use serde_json::{Value, json};

use super::classify::classify;
use super::input::{parse_input, parse_input_with_limits};

fn classified(name: &str, operations: &[&str]) -> super::classify::AlgorithmProperties {
    let operations: Vec<String> = operations.iter().map(|op| (*op).to_string()).collect();
    classify(name, &operations)
}

#[test]
fn classifier_maps_families_modes_and_padding() {
    let gcm = classified("CKM_AES_GCM", &["encrypt", "decrypt"]);
    assert_eq!(gcm.primitive, Some("ae"));
    assert_eq!(gcm.mode, Some("gcm"));
    assert_eq!(gcm.padding, None);
    assert_eq!(gcm.functions, vec!["decrypt", "encrypt"]);

    let cbc_pad = classified("CKM_AES_CBC_PAD", &["encrypt"]);
    assert_eq!(cbc_pad.primitive, Some("block-cipher"));
    assert_eq!(cbc_pad.mode, Some("cbc"));
    assert_eq!(cbc_pad.padding, Some("pkcs7"));

    let rsa = classified("CKM_RSA_PKCS", &["decrypt"]);
    assert_eq!(rsa.primitive, Some("pke"));
    assert_eq!(rsa.padding, Some("pkcs1v15"));

    let oaep = classified("CKM_RSA_PKCS_OAEP", &["encrypt"]);
    assert_eq!(oaep.primitive, Some("pke"));
    assert_eq!(oaep.padding, Some("oaep"));

    let pss = classified("CKM_SHA256_RSA_PKCS_PSS", &["sign"]);
    assert_eq!(pss.primitive, Some("signature"));

    let hash_sign = classified("CKM_SHA256_RSA_PKCS", &["sign"]);
    assert_eq!(hash_sign.primitive, Some("signature"));
    assert_eq!(hash_sign.padding, Some("pkcs1v15"));

    let sha = classified("CKM_SHA256", &["digest"]);
    assert_eq!(sha.primitive, Some("hash"));
    assert_eq!(sha.functions, vec!["digest"]);

    let hmac = classified("CKM_SHA256_HMAC", &["sign"]);
    assert_eq!(hmac.primitive, Some("mac"));

    let ecdsa = classified("CKM_ECDSA", &["sign"]);
    assert_eq!(ecdsa.primitive, Some("signature"));

    let ecdh = classified("CKM_ECDH1_DERIVE", &["derive"]);
    assert_eq!(ecdh.primitive, Some("key-agree"));
    assert_eq!(ecdh.functions, vec!["keyderive"]);

    let hkdf = classified("CKM_HKDF_DERIVE", &["derive"]);
    assert_eq!(hkdf.primitive, Some("kdf"));

    let chacha = classified("CKM_CHACHA20_POLY1305", &["encrypt"]);
    assert_eq!(chacha.primitive, Some("ae"));

    let rc4 = classified("CKM_RC4", &["encrypt"]);
    assert_eq!(rc4.primitive, Some("stream-cipher"));
}

#[test]
fn classifier_maps_pqc_and_key_generation() {
    let kem = classified("CKM_ML_KEM", &["encapsulate", "decapsulate"]);
    assert_eq!(kem.primitive, Some("kem"));
    assert_eq!(kem.functions, vec!["decapsulate", "encapsulate"]);

    let dsa = classified("CKM_ML_DSA", &["sign"]);
    assert_eq!(dsa.primitive, Some("signature"));

    let hash_dsa = classified("CKM_HASH_ML_DSA_SHAKE256", &["sign"]);
    assert_eq!(hash_dsa.primitive, Some("signature"));

    let slh = classified("CKM_SLH_DSA", &["sign"]);
    assert_eq!(slh.primitive, Some("signature"));

    let rsa_gen = classified("CKM_RSA_PKCS_KEY_PAIR_GEN", &["generate_key_pair"]);
    assert_eq!(rsa_gen.primitive, Some("pke"));
    assert_eq!(rsa_gen.padding, None);
    assert_eq!(rsa_gen.functions, vec!["keygen"]);

    let aes_gen = classified("CKM_AES_KEY_GEN", &["generate_key"]);
    assert_eq!(aes_gen.primitive, Some("block-cipher"));
    assert_eq!(aes_gen.functions, vec!["keygen"]);

    let generic = classified("CKM_GENERIC_SECRET_KEY_GEN", &["generate_key"]);
    assert_eq!(generic.primitive, Some("unknown"));
    assert_eq!(generic.functions, vec!["keygen"]);

    let future = classified("CKM_FUTURE_MECHANISM", &["frobnicate"]);
    assert_eq!(future.primitive, Some("unknown"));
    assert_eq!(future.functions, vec!["unknown"]);
}

fn caller(id: &str, path: Option<&str>) -> Value {
    json!({
        "id": id,
        "pid": 4242,
        "start_time": 1000,
        "start_time_unit": "clock_ticks_since_boot",
        "incarnation": 0,
        "image": {
            "authority": "scan_pinned",
            "task_cookie": null,
            "exec_id": null,
            "exe": path.map(|path| json!({
                "dev": 1, "ino": 100,
                "mtime_secs": 10, "mtime_nanos": 0,
                "path": path
            })),
            "exec_observed": path.is_some()
        },
        "lifecycle": "mapped",
        "lifecycle_reason": null,
        "first_seen_ns": 110,
        "last_seen_ns": 190,
        "retired": false
    })
}

fn module(id: &str, path: &str, sha256: Option<&str>) -> Value {
    json!({
        "id": id,
        "paths": [path],
        "identity": {
            "device": {"major": 8, "minor": 1},
            "inode": 100000,
            "sha256": sha256,
            "build_id": null,
            "source": "workload"
        },
        "admission": {
            "state": "admitted", "class": "exact", "endpoints": 4,
            "reasons": [],
            "note": "scan-only admission: manifest corroboration was not consulted",
            "history": []
        },
        "lifecycle": "mapped",
        "unloaded_observed": false,
        "unbound_use": null
    })
}

fn mechanism_row(id: u64, name: Option<&str>, operations: &[&str], calls: u64) -> Value {
    json!({
        "mechanism": id,
        "mechanism_hex": format!("0x{id:x}"),
        "name": name,
        "operations": operations,
        "calls": calls,
        "errors": 0,
        "last_seen_ns": 180,
        "evidence": {
            "functions": ["C_EncryptInit"],
            "returns": [{"rv": 0, "rv_hex": "0x0", "name": "CKR_OK"}],
            "truncated": false
        }
    })
}

fn edge(caller: &str, module: &str, mechanisms: Option<Vec<Value>>) -> Value {
    json!({
        "caller": caller,
        "module": module,
        "mapping": {
            "state": "mapped", "evidence": "deep_scan", "reason": null,
            "first_seen_ns": 110, "last_seen_ns": 190, "interruptions": 0
        },
        "entries": {
            "count": 1, "saturated": false, "cap": 18446744073709551615u64,
            "first_seen_ns": 111, "last_seen_ns": 189, "in_flight": false,
            "observation": "observed",
            "coverage": {
                "state": "counted", "since_ns": 110, "until_ns": null,
                "first_ns": null, "lossy": false, "reason": null, "detail": null
            }
        },
        "semantics": if mechanisms.is_some() { "observed" } else { "unknown (no operation evidence)" },
        "mechanisms": mechanisms,
        "operations": null
    })
}

fn inventory_document(callers: Vec<Value>, modules: Vec<Value>, edges: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "p11scope/inventory/v1",
        "scope": "pid:4242",
        "clock": {"basis": "CLOCK_MONOTONIC", "unit": "ns"},
        "observation": {"started_ns": 100, "ended_ns": 200, "passes": 1, "usage_feed": true},
        "budgets": {},
        "callers": callers,
        "modules": modules,
        "edges": edges,
        "gaps": [],
        "gaps_suppressed": 0
    }))
    .unwrap()
}

#[test]
fn projection_unions_mechanisms_and_links_dependencies() {
    let bytes = inventory_document(
        vec![caller("c0", Some("/bin/driver"))],
        vec![module("m0", "/lib/p.so", Some(&"a".repeat(64)))],
        vec![edge(
            "c0",
            "m0",
            Some(vec![
                mechanism_row(4231, Some("CKM_AES_GCM"), &["encrypt"], 10),
                mechanism_row(4231, Some("CKM_AES_GCM"), &["decrypt"], 5),
            ]),
        )],
    );
    let projection = parse_input(&bytes).unwrap();
    assert_eq!(projection.applications.len(), 1);
    assert_eq!(projection.providers.len(), 1);
    assert_eq!(projection.mechanisms.len(), 1);
    let mechanism = &projection.mechanisms[0];
    assert_eq!(mechanism.calls, 15);
    assert_eq!(mechanism.operations, vec!["decrypt", "encrypt"]);
    assert_eq!(mechanism.rows, 2);
    assert_eq!(mechanism.bom_ref, "p11scope:mechanism:0x1087");
    // Application -> provider, application -> mechanism, provider -> mechanism.
    assert_eq!(projection.dependencies.len(), 3);
    assert_eq!(projection.unknowns.mechanisms_unnamed, 0);
}

#[test]
fn projection_degrades_unknowns_without_stopping() {
    let bytes = inventory_document(
        vec![
            caller("c0", Some("/bin/driver")),
            caller("c1", None),
            json!({"pid": 1}),
        ],
        vec![
            module("m0", "/lib/p.so", Some("not-a-digest")),
            json!({"paths": []}),
        ],
        vec![
            edge(
                "c0",
                "m0",
                Some(vec![mechanism_row(1, None, &["encrypt"], 2)]),
            ),
            edge(
                "c0",
                "missing",
                Some(vec![mechanism_row(1, None, &["encrypt"], 2)]),
            ),
            edge("c0", "m0", None),
        ],
    );
    let projection = parse_input(&bytes).unwrap();
    assert_eq!(projection.applications.len(), 1);
    assert_eq!(projection.unknowns.callers_unknown_exe, 1);
    assert_eq!(projection.unknowns.callers_skipped, 1);
    assert_eq!(projection.unknowns.modules_skipped, 1);
    assert_eq!(projection.unknowns.modules_invalid_digest, 1);
    assert!(projection.providers[0].sha256.is_none());
    assert_eq!(projection.unknowns.dangling_edge_refs, 1);
    assert_eq!(projection.unknowns.edges_without_mechanisms, 1);
    assert_eq!(projection.mechanisms.len(), 1);
    assert_eq!(projection.unknowns.mechanisms_unnamed, 1);
    assert_eq!(projection.unknowns.mechanisms_unknown_primitive, 1);
}

#[test]
fn projection_reads_semantic_edges_when_summaries_withhold() {
    let mut document: Value = serde_json::from_slice(&inventory_document(
        vec![caller("c0", Some("/bin/driver"))],
        vec![module("m0", "/lib/p.so", Some(&"b".repeat(64)))],
        vec![edge("c0", "m0", None)],
    ))
    .unwrap();
    document["edges"][0]["semantics"] =
        json!("unknown (per-edge summary withheld; see semantic children)");
    document["semantic_edges"] = json!([
        {
            "caller": "c0", "module": "m0", "instance": "i0",
            "entries": {"unit": "api_entries", "count": null, "observation": "unavailable"},
            "semantics": "observed",
            "mechanisms": [mechanism_row(592, Some("CKM_SHA256"), &["digest"], 4)],
            "operations": null,
            "coverage": {"lossy": false, "reasons": []}
        }
    ]);
    let projection = parse_input(&serde_json::to_vec(&document).unwrap()).unwrap();
    assert_eq!(projection.mechanisms.len(), 1);
    assert_eq!(projection.mechanisms[0].name.as_deref(), Some("CKM_SHA256"));
    assert_eq!(projection.mechanisms[0].calls, 4);
}

fn metadata_block(class: Option<u64>, key_type: Option<u64>, len: Option<u64>) -> Value {
    let slot = |value: Option<u64>| {
        if let Some(value) = value {
            json!({"status": "value", "value": value})
        } else {
            json!({"status": "unknown", "value": null})
        }
    };
    json!({
        "class": slot(class),
        "key_type": slot(key_type),
        "token": slot(Some(0)),
        "value_len": slot(len),
        "modulus_bits": slot(None),
        "ec_params": {"status": "unknown", "value": null}
    })
}

#[test]
fn projection_maps_keys_from_established_facts_only() {
    let mut document: Value = serde_json::from_slice(&inventory_document(
        vec![caller("c0", Some("/bin/driver"))],
        vec![module("m0", "/lib/p.so", Some(&"c".repeat(64)))],
        vec![edge("c0", "m0", None)],
    ))
    .unwrap();
    document["instances"] = json!([
        {"id": "i0", "caller": "c0", "module": "m0", "state": "observed",
         "reason": null, "first_seen_ns": 110, "last_seen_ns": 190}
    ]);
    document["object_observations"] = json!({
        "version": 1, "revision": 1, "status": "populated", "reason": "none",
        "sessions": [{"session": 0, "origin": "opened", "status": "live"}],
        "objects": [
            {
                "object": 0, "session": 0, "origin": "created",
                "creation": "generate", "birth": {"start_ns": 1, "end_ns": 2},
                "lifetime": "live", "lifetime_reason": null,
                "attribution": "valid", "attribution_reason": null,
                "requested": metadata_block(Some(4), Some(31), Some(16)),
                "established": metadata_block(Some(4), Some(31), Some(16)),
                "queries": {"class": "established", "key_type": "established",
                            "token": "established", "value_len": "established",
                            "modulus_bits": "not_queried", "ec_params": "not_queried"},
                "label": "aes_128",
                "successful_references": 3, "successful_key_references": 3,
                "accessing_sessions": 1
            },
            {
                "object": 1, "session": 0, "origin": "created",
                "creation": "generate", "birth": {"start_ns": 1, "end_ns": 2},
                "lifetime": "live", "lifetime_reason": null,
                "attribution": "valid", "attribution_reason": null,
                "requested": metadata_block(Some(4), Some(31), Some(32)),
                "established": metadata_block(None, None, None),
                "queries": {"class": "not_queried", "key_type": "not_queried",
                            "token": "not_queried", "value_len": "not_queried",
                            "modulus_bits": "not_queried", "ec_params": "not_queried"},
                "label": null,
                "successful_references": 1, "successful_key_references": 1,
                "accessing_sessions": 1
            },
            {
                "object": 2, "session": 0, "origin": "created",
                "creation": "create", "birth": {"start_ns": 1, "end_ns": 2},
                "lifetime": "live", "lifetime_reason": null,
                "attribution": "valid", "attribution_reason": null,
                "requested": metadata_block(Some(0), None, None),
                "established": metadata_block(Some(0), None, None),
                "queries": {"class": "established", "key_type": "not_queried",
                            "token": "established", "value_len": "not_queried",
                            "modulus_bits": "not_queried", "ec_params": "not_queried"},
                "label": null,
                "successful_references": 1, "successful_key_references": 0,
                "accessing_sessions": 1
            },
            {
                "object": 3, "session": 0, "origin": "first_observed",
                "creation": null, "birth": null,
                "lifetime": "live", "lifetime_reason": null,
                "attribution": "valid", "attribution_reason": null,
                "requested": metadata_block(None, None, None),
                "established": metadata_block(None, None, None),
                "queries": {"class": "not_queried", "key_type": "not_queried",
                            "token": "not_queried", "value_len": "not_queried",
                            "modulus_bits": "not_queried", "ec_params": "not_queried"},
                "label": null,
                "successful_references": 2, "successful_key_references": 2,
                "accessing_sessions": 1
            }
        ],
        "key_operations": [
            {"instance": "i0", "object": 0, "category": "encrypt", "role": "key",
             "metadata_at_use": "aes_128", "unit": "operations",
             "started": 3, "completed": 3, "failed": 0, "cancelled": 0,
             "unknown": 0, "active": 0, "key_join_lost": 0},
            {"instance": "i0", "object": 3, "category": "sign", "role": "key",
             "metadata_at_use": "rsa_2048", "unit": "operations",
             "started": 2, "completed": 2, "failed": 0, "cancelled": 0,
             "unknown": 0, "active": 0, "key_join_lost": 0}
        ],
        "unknown_key_operations": [],
        "gaps": {"rows": [], "suppressed": 0},
        "budgets": {
            "key_rows": {"limit": 65536, "occupied": 1, "refused": 0},
            "object_rows": {"limit": 65536, "occupied": 3, "refused": 0},
            "unknown_rows": {"occupied": 0},
            "encoded_bytes": 100, "allocation_refused": false, "refusal_reason": "none"
        }
    });
    let projection = parse_input(&serde_json::to_vec(&document).unwrap()).unwrap();
    // The data object and the requested-only object are skipped; the
    // metadata-less object with a proved key use is kept as unknown.
    assert_eq!(projection.keys.len(), 2);
    assert_eq!(projection.unknowns.objects_skipped_non_key, 2);
    let key = &projection.keys[0];
    assert_eq!(key.size_bits, Some(128));
    assert_eq!(key.class, Some(4));
    assert_eq!(key.key_type, Some(31));
    assert_eq!(projection.unknowns.keys_unknown_size, 1);
    assert_eq!(projection.unknowns.keys_unknown_type, 1);
    // Key joins its provider module and its caller application.
    assert!(projection.dependencies.contains(&(
        "p11scope:key:0".to_string(),
        "p11scope:module:0".to_string()
    )));
    assert!(projection.dependencies.contains(&(
        "p11scope:key:0".to_string(),
        "p11scope:caller:0".to_string()
    )));
}

#[test]
fn projection_accepts_profile_mechanisms_and_modules() {
    let bytes = serde_json::to_vec(&json!({
        "schema": "p11scope/observed-profile/v3",
        "capture": {
            "mode": "profile",
            "start": "2026-11-07T00:00:00Z",
            "end": "2026-11-07T00:01:00Z",
            "modules": [
                {"path": "/lib/p.so", "dev": [8, 1], "ino": 7,
                 "sha256": "d".repeat(64), "build_id": null}
            ]
        },
        "evidence": {"completeness": "PARTIAL"},
        "functions": [],
        "mechanisms": [
            {"mechanism": 4231, "mechanism_hex": "0x1087",
             "registered": true, "ops": ["encrypt"], "calls": 5, "errors": 0}
        ],
        "sessions": {}, "logins": {}, "templates": {"operations": []}, "cgroups": []
    }))
    .unwrap();
    let projection = parse_input(&bytes).unwrap();
    assert!(projection.applications.is_empty());
    assert!(projection.keys.is_empty());
    assert_eq!(projection.providers.len(), 1);
    assert_eq!(projection.mechanisms.len(), 1);
    assert_eq!(projection.mechanisms[0].name, None);
    assert!(projection.profile_note.is_some());
    assert_eq!(projection.completeness.as_deref(), Some("PARTIAL"));
    assert!(projection.dependencies.is_empty());
}

/// O9: a profile input without a scope note renders "(scope
/// unknown)", never the doubled "(scope unknown scope)".
#[test]
fn concise_head_names_an_unknown_scope_once() {
    let bytes = serde_json::to_vec(&json!({
        "schema": "p11scope/observed-profile/v3",
        "capture": {
            "mode": "profile",
            "start": "2026-11-07T00:00:00Z",
            "end": "2026-11-07T00:01:00Z",
            "modules": [
                {"path": "/lib/p.so", "dev": [8, 1], "ino": 7,
                 "sha256": "d".repeat(64), "build_id": null}
            ]
        },
        "evidence": {"completeness": "PARTIAL"},
        "functions": [],
        "mechanisms": [],
        "sessions": {}, "logins": {}, "templates": {"operations": []}, "cgroups": []
    }))
    .unwrap();
    let projection = parse_input(&bytes).unwrap();
    assert!(
        projection.scope_note.is_none(),
        "the fixture carries no scope"
    );
    let mut output = Vec::new();
    super::render::render_concise(&projection, &mut output).unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("(scope unknown):"), "{text}");
    assert!(!text.contains("unknown scope"), "no doubled word: {text}");
}

#[test]
fn projection_enforces_the_shared_row_bound() {
    let bytes = inventory_document(
        vec![caller("c0", Some("/bin/driver"))],
        vec![module("m0", "/lib/p.so", Some(&"e".repeat(64)))],
        vec![edge("c0", "m0", None)],
    );
    let limits = crate::inventory_diff::input::InputLimits {
        rows: 2,
        ..crate::inventory_diff::input::InputLimits::default()
    };
    let error = parse_input_with_limits(&bytes, limits)
        .unwrap_err()
        .to_string();
    assert!(error.contains("inventory row limit exceeded"), "{error}");
    // The same document passes under the default bound.
    assert!(parse_input(&bytes).is_ok());
}

#[test]
fn destination_replaced_by_an_input_hardlink_at_precommit_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.json");
    let bytes = inventory_document(
        vec![caller("c0", Some("/bin/driver"))],
        vec![module("m0", "/lib/p.so", Some(&"f".repeat(64)))],
        vec![edge("c0", "m0", None)],
    );
    std::fs::write(&input, &bytes).unwrap();
    let out = dir.path().join("out.cdx.json");
    std::fs::write(&out, b"old report").unwrap();
    let args = crate::cli::InventoryCbomArgs {
        input: input.clone(),
        json: false,
        out: Some(out.clone()),
        output_owner: None,
        verbose: false,
        quiet: false,
    };
    let mut output = Vec::new();
    let error = super::run_with_writer_before_commit(&args, &mut output, || {
        std::fs::remove_file(&out).unwrap();
        std::fs::hard_link(&input, &out).unwrap();
    })
    .unwrap_err();
    assert!(format!("{error:#}").contains("input alias"), "{error:#}");
    assert!(output.is_empty());
    assert_eq!(std::fs::read(&input).unwrap(), bytes);
    assert_eq!(std::fs::read(&out).unwrap(), bytes);
}

#[test]
fn projection_refuses_unsupported_schemas() {
    for schema in [
        "p11scope/inventory-diff/v1",
        "p11scope/observed-profile/v3-metrics",
    ] {
        let error = parse_input(
            serde_json::to_vec(&json!({"schema": schema}))
                .unwrap()
                .as_slice(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unsupported CBOM input schema"), "{error}");
    }
    let error = parse_input(br#"{"scope": "pid:1"}"#)
        .unwrap_err()
        .to_string();
    assert!(error.contains("no schema string"), "{error}");
}

// Task 7 (spec §17.5) CBOM twins: supplier/version on the library,
// device token components, per-reporter mechanism limit properties,
// and the serial-absence proof.

fn provider_info_value() -> Value {
    json!({
        "cryptoki_major": 3,
        "cryptoki_minor": 1,
        "manufacturer": "SoftHSM",
        "description": "SoftHSM v2",
        "flags": 0,
        "library_major": 2,
        "library_minor": 6
    })
}

fn module_with_info(id: &str, path: &str, sha256: Option<&str>) -> Value {
    let mut module = module(id, path, sha256);
    module["provider_info"] = provider_info_value();
    module
}

fn token_row(caller: &str, slot: u64) -> Value {
    json!({
        "module": "m0",
        "caller": caller,
        "slot": slot,
        "manufacturer": "TokenMfr",
        "model": "Model-X",
        "hardware_major": 2,
        "hardware_minor": 6,
        "firmware_major": 2,
        "firmware_minor": 7,
        "flags": 6,
        "pin_min_len": 4,
        "pin_max_len": 255,
        "completions": 12,
        "changes": 1
    })
}

fn mechanism_limit_row(caller: &str, slot: u64, mechanism: u64) -> Value {
    json!({
        "module": "m0",
        "caller": caller,
        "slot": slot,
        "mechanism": mechanism,
        "min_key_size": 1024,
        "max_key_size": 4096,
        "flags": 1,
        "completions": 2,
        "changes": 0
    })
}

fn inventory_document_with_info(
    callers: Vec<Value>,
    modules: Vec<Value>,
    edges: Vec<Value>,
    tokens: Vec<Value>,
    mechanisms: Vec<Value>,
) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "p11scope/inventory/v1",
        "scope": "pid:4242",
        "clock": {"basis": "CLOCK_MONOTONIC", "unit": "ns"},
        "observation": {"started_ns": 100, "ended_ns": 200, "passes": 1, "usage_feed": true},
        "budgets": {},
        "callers": callers,
        "modules": modules,
        "edges": edges,
        "provider_observations": {
            "version": 8,
            "tokens": tokens,
            "mechanisms": mechanisms,
            "gaps": []
        },
        "gaps": [],
        "gaps_suppressed": 0
    }))
    .unwrap()
}

fn library_component(document: &Value, bom_ref: &str) -> Value {
    document["components"]
        .as_array()
        .expect("components array")
        .iter()
        .find(|component| component["bom-ref"] == bom_ref)
        .unwrap_or_else(|| panic!("component {bom_ref}"))
        .clone()
}

fn walk_keys(node: &Value, found: &mut Vec<String>) {
    match node {
        Value::Object(map) => {
            for (key, value) in map {
                found.push(key.clone());
                walk_keys(value, found);
            }
        }
        Value::Array(items) => {
            for item in items {
                walk_keys(item, found);
            }
        }
        _ => {}
    }
}

#[test]
fn cbom_provider_gains_supplier_object_and_version() {
    let bytes = inventory_document_with_info(
        vec![caller("c0", Some("/bin/driver"))],
        vec![module_with_info("m0", "/lib/p.so", Some(&"a".repeat(64)))],
        vec![edge("c0", "m0", None)],
        vec![],
        vec![],
    );
    let projection = parse_input(&bytes).unwrap();
    assert_eq!(projection.providers.len(), 1);
    assert_eq!(projection.providers[0].name, "/lib/p.so");
    let document = super::render::render_json(&projection);
    let library = library_component(&document, "p11scope:module:0");
    assert_eq!(library["name"], "/lib/p.so");
    assert_eq!(library["supplier"], json!({"name": "SoftHSM"}));
    assert_eq!(library["version"], "2.6");
}

#[test]
fn cbom_refused_manufacturer_omits_supplier() {
    let mut info = provider_info_value();
    info["manufacturer"] = Value::Null;
    info["manufacturer_reason"] = json!("non_utf8_bytes");
    let mut module = module("m0", "/lib/p.so", Some(&"a".repeat(64)));
    module["provider_info"] = info;
    let bytes = inventory_document_with_info(
        vec![caller("c0", Some("/bin/driver"))],
        vec![module],
        vec![edge("c0", "m0", None)],
        vec![],
        vec![],
    );
    let projection = parse_input(&bytes).unwrap();
    assert_eq!(projection.providers[0].supplier, None);
    let document = super::render::render_json(&projection);
    let library = library_component(&document, "p11scope:module:0");
    assert!(library.get("supplier").is_none());
    assert_eq!(library["version"], "2.6");
}

#[test]
fn cbom_projection_rejects_unknown_info_version() {
    let bytes = serde_json::to_vec(&json!({
        "schema": "p11scope/inventory/v1",
        "scope": "pid:4242",
        "clock": {"basis": "CLOCK_MONOTONIC", "unit": "ns"},
        "observation": {"started_ns": 100, "ended_ns": 200, "passes": 1, "usage_feed": true},
        "budgets": {},
        "callers": [caller("c0", Some("/bin/driver"))],
        "modules": [module("m0", "/lib/p.so", Some(&"a".repeat(64)))],
        "edges": [edge("c0", "m0", None)],
        "provider_observations": {
            "version": 9,
            "tokens": [],
            "mechanisms": [],
            "gaps": []
        },
        "gaps": [],
        "gaps_suppressed": 0
    }))
    .unwrap();
    let error = parse_input(&bytes).unwrap_err().to_string();
    assert!(error.contains("provider_observations"), "{error}");
}

#[test]
fn cbom_token_projects_device_component() {
    let bytes = inventory_document_with_info(
        vec![caller("c0", Some("/bin/driver"))],
        vec![module_with_info("m0", "/lib/p.so", Some(&"a".repeat(64)))],
        vec![edge("c0", "m0", None)],
        vec![token_row("c0", 0)],
        vec![],
    );
    let projection = parse_input(&bytes).unwrap();
    assert_eq!(projection.tokens.len(), 1);
    let document = super::render::render_json(&projection);
    let device = library_component(&document, "p11scope:token:0");
    assert_eq!(device["type"], "device");
    assert_eq!(device["name"], "TokenMfr Model-X");
    let properties = device["properties"].as_array().expect("properties");
    let prop = |name: &str| {
        properties
            .iter()
            .find(|property| property["name"] == name)
            .unwrap_or_else(|| panic!("property {name}"))
            .get("value")
            .expect("value")
            .clone()
    };
    assert_eq!(prop("p11scope:hardware-version"), "2.6");
    assert_eq!(prop("p11scope:firmware-version"), "2.7");
    assert_eq!(prop("p11scope:token-flags"), "6");
    assert_eq!(prop("p11scope:pin-min-len"), "4");
    assert_eq!(prop("p11scope:pin-max-len"), "255");
    assert_eq!(prop("p11scope:slot"), "0");
    let dependencies = document["dependencies"].as_array().expect("dependencies");
    assert!(
        dependencies.iter().any(|dependency| {
            dependency["ref"] == "p11scope:token:0"
                && dependency["dependsOn"]
                    .as_array()
                    .expect("dependsOn")
                    .contains(&json!("p11scope:module:0"))
        }),
        "device links its library, got: {dependencies:?}"
    );
}

#[test]
fn cbom_token_devices_dedup_per_module_slot_identity() {
    // Same (module, slot, token identity) from two callers projects
    // one device; a conflicting identity on the same slot keeps its
    // own device (slot ids are per-process).
    let mut conflict = token_row("c2", 0);
    conflict["model"] = json!("Model-Y");
    let bytes = inventory_document_with_info(
        vec![
            caller("c0", Some("/bin/driver")),
            caller("c1", Some("/bin/other")),
            caller("c2", Some("/bin/third")),
        ],
        vec![module_with_info("m0", "/lib/p.so", Some(&"a".repeat(64)))],
        vec![
            edge("c0", "m0", None),
            edge("c1", "m0", None),
            edge("c2", "m0", None),
        ],
        vec![
            token_row("c0", 0),
            token_row("c1", 0),
            conflict,
            token_row("c0", 1),
        ],
        vec![],
    );
    let projection = parse_input(&bytes).unwrap();
    assert_eq!(projection.tokens.len(), 3);
    let mut names: Vec<(&str, u64)> = projection
        .tokens
        .iter()
        .map(|token| (token.name.as_str(), token.slot))
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec![
            ("TokenMfr Model-X", 0),
            ("TokenMfr Model-X", 1),
            ("TokenMfr Model-Y", 0),
        ]
    );
    let mut refs: Vec<&str> = projection
        .tokens
        .iter()
        .map(|token| token.bom_ref.as_str())
        .collect();
    refs.sort_unstable();
    refs.dedup();
    assert_eq!(refs.len(), 3, "one bom-ref per device");
}

#[test]
fn cbom_never_emits_serial_keys() {
    let bytes = inventory_document_with_info(
        vec![caller("c0", Some("/bin/driver"))],
        vec![module_with_info("m0", "/lib/p.so", Some(&"a".repeat(64)))],
        vec![edge(
            "c0",
            "m0",
            Some(vec![mechanism_row(
                1082,
                Some("CKM_SHA256_RSA_PKCS"),
                &["sign"],
                4,
            )]),
        )],
        vec![token_row("c0", 0)],
        vec![mechanism_limit_row("c0", 0, 1082)],
    );
    let projection = parse_input(&bytes).unwrap();
    let document = super::render::render_json(&projection);
    let mut keys = Vec::new();
    walk_keys(&document, &mut keys);
    for key in &keys {
        let lowered = key.to_lowercase();
        for forbidden in ["serial", "label", "utctime"] {
            assert!(
                !lowered.contains(forbidden),
                "excluded key {key:?} in CBOM output"
            );
        }
    }
    let serialized = serde_json::to_string(&document).expect("serialize");
    assert!(!serialized.to_lowercase().contains("serial"));
}

#[test]
fn cbom_single_reporter_limits_are_plain() {
    let bytes = inventory_document_with_info(
        vec![caller("c0", Some("/bin/driver"))],
        vec![module("m0", "/lib/p.so", Some(&"a".repeat(64)))],
        vec![edge(
            "c0",
            "m0",
            Some(vec![mechanism_row(
                1082,
                Some("CKM_SHA256_RSA_PKCS"),
                &["sign"],
                4,
            )]),
        )],
        vec![],
        vec![mechanism_limit_row("c0", 0, 1082)],
    );
    let projection = parse_input(&bytes).unwrap();
    assert_eq!(projection.mechanisms.len(), 1);
    let document = super::render::render_json(&projection);
    let algorithm = library_component(&document, "p11scope:mechanism:0x43a");
    let properties = algorithm["properties"].as_array().expect("properties");
    let values: Vec<(&str, &str)> = properties
        .iter()
        .map(|property| {
            (
                property["name"].as_str().expect("name"),
                property["value"].as_str().expect("value"),
            )
        })
        .collect();
    assert!(values.contains(&("p11scope:min-key-size", "1024")));
    assert!(values.contains(&("p11scope:max-key-size", "4096")));
    assert!(values.contains(&("p11scope:mechanism-flags", "1")));
    assert!(values.contains(&("p11scope:mechanism-hw", "true")));
    assert!(
        !values
            .iter()
            .any(|(name, _)| name.contains("slot-limits-truncated"))
    );
    assert!(
        algorithm["description"]
            .as_str()
            .expect("description")
            .ends_with("; provider key-size limits in properties.")
    );
}

#[test]
fn cbom_multi_reporter_limits_are_suffixed() {
    let bytes = inventory_document_with_info(
        vec![
            caller("c0", Some("/bin/driver")),
            caller("c1", Some("/bin/other")),
        ],
        vec![module("m0", "/lib/p.so", Some(&"a".repeat(64)))],
        vec![edge(
            "c0",
            "m0",
            Some(vec![mechanism_row(
                1082,
                Some("CKM_SHA256_RSA_PKCS"),
                &["sign"],
                4,
            )]),
        )],
        vec![],
        vec![
            mechanism_limit_row("c0", 0, 1082),
            mechanism_limit_row("c1", 1, 1082),
        ],
    );
    let projection = parse_input(&bytes).unwrap();
    let document = super::render::render_json(&projection);
    let algorithm = library_component(&document, "p11scope:mechanism:0x43a");
    let properties = algorithm["properties"].as_array().expect("properties");
    let names: Vec<&str> = properties
        .iter()
        .map(|property| property["name"].as_str().expect("name"))
        .collect();
    assert!(names.contains(&"p11scope:slot-0:min-key-size"));
    assert!(names.contains(&"p11scope:slot-1:min-key-size"));
    assert!(!names.contains(&"p11scope:min-key-size"));
    assert!(!names.contains(&"p11scope:slot-limits-truncated"));
}

#[test]
fn cbom_limit_reporters_truncate_on_collision_and_cap() {
    // Two reporters sharing a slot id: no merge, truncation flag.
    let bytes = inventory_document_with_info(
        vec![
            caller("c0", Some("/bin/driver")),
            caller("c1", Some("/bin/other")),
        ],
        vec![module("m0", "/lib/p.so", Some(&"a".repeat(64)))],
        vec![edge(
            "c0",
            "m0",
            Some(vec![mechanism_row(
                1082,
                Some("CKM_SHA256_RSA_PKCS"),
                &["sign"],
                4,
            )]),
        )],
        vec![],
        vec![
            mechanism_limit_row("c0", 0, 1082),
            mechanism_limit_row("c1", 0, 1082),
        ],
    );
    let projection = parse_input(&bytes).unwrap();
    let document = super::render::render_json(&projection);
    let algorithm = library_component(&document, "p11scope:mechanism:0x43a");
    let properties = algorithm["properties"].as_array().expect("properties");
    let truncated = properties
        .iter()
        .find(|property| property["name"] == "p11scope:slot-limits-truncated")
        .expect("truncation flag")
        .get("value")
        .expect("value");
    assert_eq!(truncated, "true");

    // Seventeen reporters: sixteen report, truncation flag.
    let mut callers = Vec::new();
    let mut rows = Vec::new();
    for index in 0..17u64 {
        let id = format!("c{index}");
        callers.push(caller(&id, Some(&format!("/bin/app{index}"))));
        rows.push(mechanism_limit_row(&id, index, 1082));
    }
    let bytes = inventory_document_with_info(
        callers,
        vec![module("m0", "/lib/p.so", Some(&"a".repeat(64)))],
        vec![edge(
            "c0",
            "m0",
            Some(vec![mechanism_row(
                1082,
                Some("CKM_SHA256_RSA_PKCS"),
                &["sign"],
                4,
            )]),
        )],
        vec![],
        rows,
    );
    let projection = parse_input(&bytes).unwrap();
    let document = super::render::render_json(&projection);
    let algorithm = library_component(&document, "p11scope:mechanism:0x43a");
    let properties = algorithm["properties"].as_array().expect("properties");
    let names: Vec<&str> = properties
        .iter()
        .map(|property| property["name"].as_str().expect("name"))
        .collect();
    assert!(names.contains(&"p11scope:slot-15:min-key-size"));
    assert!(!names.contains(&"p11scope:slot-16:min-key-size"));
    assert!(names.contains(&"p11scope:slot-limits-truncated"));
}

#[test]
fn cbom_limit_only_mechanism_mints_algorithm_component() {
    let bytes = inventory_document_with_info(
        vec![caller("c0", Some("/bin/driver"))],
        vec![module("m0", "/lib/p.so", Some(&"a".repeat(64)))],
        vec![edge("c0", "m0", None)],
        vec![],
        vec![mechanism_limit_row("c0", 0, 4231)],
    );
    let projection = parse_input(&bytes).unwrap();
    assert_eq!(projection.mechanisms.len(), 1);
    assert_eq!(projection.mechanisms[0].id, 4231);
    assert_eq!(projection.unknowns.mechanisms_unnamed, 0);
    assert_eq!(projection.unknowns.mechanisms_unknown_primitive, 0);
    let document = super::render::render_json(&projection);
    let algorithm = library_component(&document, "p11scope:mechanism:0x1087");
    assert_eq!(algorithm["name"], "PKCS#11 mechanism 0x1087");
    let properties = algorithm["properties"].as_array().expect("properties");
    assert!(
        properties
            .iter()
            .any(|property| property["name"] == "p11scope:min-key-size")
    );
}

#[test]
fn cbom_text_names_tokens_verbose_only() {
    let bytes = inventory_document_with_info(
        vec![caller("c0", Some("/bin/driver"))],
        vec![module_with_info("m0", "/lib/p.so", Some(&"a".repeat(64)))],
        vec![edge("c0", "m0", None)],
        vec![token_row("c0", 0)],
        vec![],
    );
    let projection = parse_input(&bytes).unwrap();
    let mut verbose = Vec::new();
    super::render::render_verbose(&projection, &mut verbose).unwrap();
    let verbose = String::from_utf8(verbose).expect("utf8");
    assert!(
        verbose.contains("TokenMfr Model-X"),
        "verbose names the token, got:\n{verbose}"
    );
    let mut concise = Vec::new();
    super::render::render_concise(&projection, &mut concise).unwrap();
    let concise = String::from_utf8(concise).expect("utf8");
    assert!(
        concise.lines().next().expect("head").contains("1 token"),
        "head counts the token, got:\n{concise}"
    );

    let plain = inventory_document(
        vec![caller("c0", Some("/bin/driver"))],
        vec![module("m0", "/lib/p.so", Some(&"a".repeat(64)))],
        vec![edge("c0", "m0", None)],
    );
    let projection = parse_input(&plain).unwrap();
    let mut concise = Vec::new();
    super::render::render_concise(&projection, &mut concise).unwrap();
    let concise = String::from_utf8(concise).expect("utf8");
    assert!(
        !concise.lines().next().expect("head").contains("token"),
        "head byte-stable without tokens, got:\n{concise}"
    );
}

// Departed-fold twins: callers folded into `modules[].departed_use`
// rejoin the CBOM as application components, app->provider joins and
// mechanism totals; fold bounds stay named unknowns.

fn departed_identity(caller: &str, path: Option<&str>, lifecycle: &str) -> Value {
    json!({
        "caller": caller, "pid": 4242, "start_time": 1000, "incarnation": 0,
        "exe": path.map(|path| json!({
            "dev": 1, "ino": 100,
            "mtime_secs": 10, "mtime_nanos": 0,
            "path": path
        })),
        "authority": "scan_pinned", "lifecycle": lifecycle,
        "lifecycle_reason": "process exited (pid names no live process)",
        "first_seen_ns": 110, "last_seen_ns": 190,
        "exec_observed": true, "metadata_status": "historical"
    })
}

fn departed_overflow(mechs: u64, calls: u64, errors: u64) -> Value {
    json!({"mechs": mechs, "calls": calls, "errors": errors})
}

/// A producer-shaped aggregate: the converter reads callers,
/// mechanisms, overflow, identities, saturation and drops, and
/// ignores the accounting subtrees it does not project.
fn departed_use(
    callers: u64,
    edges: u64,
    mechanisms: Value,
    identities: Vec<Value>,
    saturated: bool,
    dropped: u64,
    overflow: Value,
) -> Value {
    json!({
        "first_ns": 100, "callers": callers, "edges": edges,
        "entries": {
            "count": 3, "saturated": 0, "first_min_ns": 101, "last_max_ns": 202,
            "in_flight": 0, "logical": 3, "forwarding": 0,
            "observation": {"observed": 1},
            "coverage": {
                "counted": 1, "witnessed": 0, "watched_no_use": 0,
                "lossy": 0, "pid_exit": 0, "unknown": {},
                "since_min_ns": 101, "until_max_ns": null, "first_min_ns": null,
            },
        },
        "mapping": {
            "state": {"mapped": 0, "ended": 1, "uncertain": 0},
            "evidence": {"deep_scan": 1, "maps_match": 0},
            "interruptions": 0, "first_min_ns": 101, "last_max_ns": 202,
            "reasons": {"process exited (pid names no live process)": 1},
            "reasons_overflow": 0,
        },
        "semantics": {"labels": {"observed": 1}},
        "mechanisms": mechanisms,
        "mechanisms_overflow": overflow,
        "operations": null,
        "instances": {
            "folded": 0, "observed": 0, "uncertain": 0, "retired": 0,
            "settled_live": 0, "reasons": {},
            "null_reasons": 0, "first_min_ns": null, "last_max_ns": null,
            "api_returns": 0, "api_returns_saturated_rows": 0,
            "historical_only_returns": 0, "lossy_rows": 0, "loss_reasons": {},
        },
        "identities": identities,
        "identities_saturated": saturated, "identities_dropped": dropped,
    })
}

fn module_with_departed(id: &str, path: &str, sha256: &str, departed: Value) -> Value {
    let mut module = module(id, path, Some(sha256));
    module["departed_use"] = departed;
    module
}

fn component_properties(component: &Value) -> Vec<(&str, &str)> {
    component["properties"]
        .as_array()
        .expect("properties")
        .iter()
        .map(|property| {
            (
                property["name"].as_str().expect("name"),
                property["value"].as_str().expect("value"),
            )
        })
        .collect()
}

fn metadata_value(document: &Value, name: &str) -> Value {
    document
        .pointer("/metadata/properties")
        .and_then(Value::as_array)
        .expect("metadata properties")
        .iter()
        .find(|property| property["name"] == name)
        .unwrap_or_else(|| panic!("metadata property {name}"))
        .get("value")
        .expect("value")
        .clone()
}

#[test]
fn cbom_folded_departed_matches_the_alive_control() {
    let control = inventory_document(
        vec![caller("c0", Some("/bin/driver"))],
        vec![module("m0", "/lib/p.so", Some(&"a".repeat(64)))],
        vec![edge(
            "c0",
            "m0",
            Some(vec![mechanism_row(
                4231,
                Some("CKM_AES_GCM"),
                &["encrypt"],
                10,
            )]),
        )],
    );
    let departed = departed_use(
        1,
        1,
        json!([mechanism_row(4231, Some("CKM_AES_GCM"), &["encrypt"], 10,)]),
        vec![departed_identity("c0", Some("/bin/driver"), "exited")],
        false,
        0,
        departed_overflow(0, 0, 0),
    );
    let folded = inventory_document(
        vec![],
        vec![module_with_departed(
            "m0",
            "/lib/p.so",
            &"a".repeat(64),
            departed,
        )],
        vec![],
    );
    let control = parse_input(&control).unwrap();
    let folded = parse_input(&folded).unwrap();
    // Same application, same incarnations; only the attribution differs.
    assert_eq!(folded.applications.len(), 1);
    assert_eq!(folded.applications[0].path, control.applications[0].path);
    assert_eq!(
        folded.applications[0].incarnations,
        control.applications[0].incarnations
    );
    assert_eq!(control.applications[0].departed_incarnations, 0);
    assert_eq!(folded.applications[0].departed_incarnations, 1);
    assert_eq!(control.applications[0].lifecycles, vec!["mapped"]);
    assert_eq!(folded.applications[0].lifecycles, vec!["exited"]);
    // Same mechanism totals, same rows, same provenance.
    assert_eq!(folded.mechanisms.len(), 1);
    let (expected, actual) = (&control.mechanisms[0], &folded.mechanisms[0]);
    assert_eq!(actual.id, expected.id);
    assert_eq!(actual.name, expected.name);
    assert_eq!(actual.calls, expected.calls);
    assert_eq!(actual.errors, expected.errors);
    assert_eq!(actual.operations, expected.operations);
    assert_eq!(actual.functions, expected.functions);
    assert_eq!(actual.returns, expected.returns);
    assert_eq!(actual.rows, expected.rows);
    assert_eq!(actual.bom_ref, expected.bom_ref);
    // Same joins: the single folded caller proves the same edges.
    assert_eq!(folded.dependencies, control.dependencies);
    assert_eq!(folded.dependencies.len(), 3);
    // No unknowns either way: nothing dropped, saturated or past bounds.
    assert_eq!(folded.unknowns.departed_identities_dropped, 0);
    assert_eq!(folded.unknowns.departed_identities_saturated, 0);
    assert_eq!(folded.unknowns.departed_mechs_overflow, 0);
    assert_eq!(folded.unknowns.departed_mechs_overflow_calls, 0);
    assert_eq!(folded.unknowns.departed_mechs_overflow_errors, 0);
    assert_eq!(folded.unknowns.departed_links_withheld, 0);
    // Rendered JSON matches except the departed marker on the application.
    let control_document = super::render::render_json(&control);
    let folded_document = super::render::render_json(&folded);
    assert_eq!(
        folded_document["dependencies"],
        control_document["dependencies"]
    );
    assert_eq!(folded_document["metadata"], control_document["metadata"]);
    let control_app = library_component(&control_document, "p11scope:caller:0");
    let folded_app = library_component(&folded_document, "p11scope:caller:0");
    assert_eq!(folded_app["name"], control_app["name"]);
    let folded_props = component_properties(&folded_app);
    assert!(
        folded_props.contains(&("p11scope:departed_incarnations", "1")),
        "folded application carries the departed marker, got: {folded_props:?}"
    );
    assert!(
        !component_properties(&control_app)
            .iter()
            .any(|(name, _)| *name == "p11scope:departed_incarnations"),
        "the live control carries no departed marker"
    );
    // Concise text is byte-identical; verbose names the departed incarnation.
    let mut control_text = Vec::new();
    super::render::render_concise(&control, &mut control_text).unwrap();
    let mut folded_text = Vec::new();
    super::render::render_concise(&folded, &mut folded_text).unwrap();
    assert_eq!(folded_text, control_text);
    let mut verbose = Vec::new();
    super::render::render_verbose(&folded, &mut verbose).unwrap();
    let verbose = String::from_utf8(verbose).unwrap();
    assert!(verbose.contains("1 departed"), "{verbose}");
}

#[test]
fn cbom_departed_incarnations_merge_into_the_live_application() {
    let departed = departed_use(
        2,
        2,
        json!([mechanism_row(592, Some("CKM_SHA256"), &["digest"], 4)]),
        vec![
            departed_identity("c1", Some("/bin/driver"), "exited"),
            departed_identity("c2", Some("/bin/gone"), "exec_retired"),
        ],
        false,
        0,
        departed_overflow(0, 0, 0),
    );
    let bytes = inventory_document(
        vec![caller("c0", Some("/bin/driver"))],
        vec![module_with_departed(
            "m0",
            "/lib/p.so",
            &"b".repeat(64),
            departed,
        )],
        vec![edge("c0", "m0", None)],
    );
    let projection = parse_input(&bytes).unwrap();
    assert_eq!(projection.applications.len(), 2);
    let driver = projection
        .applications
        .iter()
        .find(|app| app.path == "/bin/driver")
        .expect("the live path keeps one component");
    assert_eq!(driver.incarnations, 2);
    assert_eq!(driver.departed_incarnations, 1);
    assert_eq!(driver.lifecycles, vec!["exited", "mapped"]);
    let gone = projection
        .applications
        .iter()
        .find(|app| app.path == "/bin/gone")
        .expect("the departed-only path mints a component");
    assert_eq!(gone.incarnations, 1);
    assert_eq!(gone.departed_incarnations, 1);
    // Both applications join the provider they were folded at.
    for app in ["p11scope:caller:0", "p11scope:caller:1"] {
        assert!(
            projection
                .dependencies
                .contains(&(app.to_string(), "p11scope:module:0".to_string())),
            "missing {app} -> provider, got: {:?}",
            projection.dependencies
        );
    }
}

#[test]
fn cbom_departed_multi_caller_names_bounds_and_withholds_linkage() {
    let departed = departed_use(
        2,
        3,
        json!([
            mechanism_row(4231, Some("CKM_AES_GCM"), &["encrypt"], 10),
            mechanism_row(4231, Some("CKM_AES_GCM"), &["decrypt"], 5),
            mechanism_row(9999, None, &["encrypt"], 2),
        ]),
        vec![
            departed_identity("c0", Some("/bin/first"), "exited"),
            departed_identity("c1", Some("/bin/second"), "exec_retired"),
            departed_identity("c2", None, "exited"),
            json!({"pid": 9}),
        ],
        true,
        3,
        departed_overflow(2, 40, 5),
    );
    let bytes = inventory_document(
        vec![],
        vec![module_with_departed(
            "m0",
            "/lib/p.so",
            &"b".repeat(64),
            departed,
        )],
        vec![],
    );
    let projection = parse_input(&bytes).unwrap();
    assert_eq!(projection.applications.len(), 2);
    assert_eq!(projection.unknowns.callers_unknown_exe, 1);
    assert_eq!(projection.unknowns.callers_skipped, 1);
    // Departed rows union into the same per-id totals.
    assert_eq!(projection.mechanisms.len(), 2);
    let gcm = projection
        .mechanisms
        .iter()
        .find(|mechanism| mechanism.id == 4231)
        .expect("the folded id");
    assert_eq!(gcm.calls, 15);
    assert_eq!(gcm.rows, 2);
    assert_eq!(gcm.operations, vec!["decrypt", "encrypt"]);
    assert_eq!(projection.unknowns.mechanisms_unnamed, 1);
    assert_eq!(projection.unknowns.mechanisms_unknown_primitive, 1);
    // Every fold bound is a named unknown.
    assert_eq!(projection.unknowns.departed_identities_dropped, 3);
    assert_eq!(projection.unknowns.departed_identities_saturated, 1);
    assert_eq!(projection.unknowns.departed_mechs_overflow, 2);
    assert_eq!(projection.unknowns.departed_mechs_overflow_calls, 40);
    assert_eq!(projection.unknowns.departed_mechs_overflow_errors, 5);
    assert_eq!(projection.unknowns.departed_links_withheld, 1);
    // Applications join their provider and the provider joins its
    // mechanisms; per-app mechanism pairs are withheld, not guessed.
    for app in ["p11scope:caller:0", "p11scope:caller:1"] {
        assert!(
            projection
                .dependencies
                .contains(&(app.to_string(), "p11scope:module:0".to_string())),
            "missing {app} -> provider, got: {:?}",
            projection.dependencies
        );
    }
    for mechanism in ["p11scope:mechanism:0x1087", "p11scope:mechanism:0x270f"] {
        assert!(
            projection
                .dependencies
                .contains(&("p11scope:module:0".to_string(), mechanism.to_string())),
            "missing provider -> {mechanism}, got: {:?}",
            projection.dependencies
        );
    }
    assert!(
        !projection.dependencies.iter().any(|(from, to)| {
            from.starts_with("p11scope:caller:") && to.starts_with("p11scope:mechanism:")
        }),
        "no guessed app->mechanism pairs, got: {:?}",
        projection.dependencies
    );
    // JSON metadata names every departed unknown.
    let document = super::render::render_json(&projection);
    assert_eq!(
        metadata_value(&document, "p11scope:departed_identities_dropped"),
        "3"
    );
    assert_eq!(
        metadata_value(&document, "p11scope:departed_identities_saturated"),
        "1"
    );
    assert_eq!(
        metadata_value(&document, "p11scope:departed_mech_overflow"),
        "2"
    );
    assert_eq!(
        metadata_value(&document, "p11scope:departed_mech_overflow_calls"),
        "40"
    );
    assert_eq!(
        metadata_value(&document, "p11scope:departed_mech_overflow_errors"),
        "5"
    );
    assert_eq!(
        metadata_value(&document, "p11scope:departed_links_withheld"),
        "1"
    );
    // Concise text names them too.
    let mut concise = Vec::new();
    super::render::render_concise(&projection, &mut concise).unwrap();
    let concise = String::from_utf8(concise).unwrap();
    for expected in [
        "3 departed identities dropped",
        "1 module with saturated departed identities",
        "2 departed mechanisms past bounds (40 calls, 5 errors)",
        "1 module with withheld departed mechanism linkage",
    ] {
        assert!(
            concise.contains(expected),
            "coverage names {expected:?}, got:\n{concise}"
        );
    }
}

#[test]
fn cbom_departed_rows_count_toward_the_row_bound() {
    let departed = departed_use(
        1,
        1,
        json!([mechanism_row(4231, Some("CKM_AES_GCM"), &["encrypt"], 10)]),
        vec![departed_identity("c0", Some("/bin/driver"), "exited")],
        false,
        0,
        departed_overflow(0, 0, 0),
    );
    let bytes = inventory_document(
        vec![],
        vec![module_with_departed(
            "m0",
            "/lib/p.so",
            &"c".repeat(64),
            departed,
        )],
        vec![],
    );
    // 1 module + 1 folded identity + 1 folded mechanism = 3 rows.
    let limits = crate::inventory_diff::input::InputLimits {
        rows: 2,
        ..crate::inventory_diff::input::InputLimits::default()
    };
    let error = parse_input_with_limits(&bytes, limits)
        .unwrap_err()
        .to_string();
    assert!(error.contains("inventory row limit exceeded"), "{error}");
    assert!(parse_input(&bytes).is_ok());
}

#[test]
fn cbom_folded_caller_at_two_modules_counts_one_incarnation() {
    // Alive control: one caller with edges at two providers.
    let control = inventory_document(
        vec![caller("c0", Some("/bin/driver"))],
        vec![
            module("m0", "/lib/a.so", Some(&"a".repeat(64))),
            module("m1", "/lib/b.so", Some(&"b".repeat(64))),
        ],
        vec![
            edge(
                "c0",
                "m0",
                Some(vec![mechanism_row(
                    4231,
                    Some("CKM_AES_GCM"),
                    &["encrypt"],
                    10,
                )]),
            ),
            edge(
                "c0",
                "m1",
                Some(vec![mechanism_row(592, Some("CKM_SHA256"), &["digest"], 4)]),
            ),
        ],
    );
    // The fold writes the same caller identity into every module
    // the caller touched; the projection still counts one incarnation.
    let folded = inventory_document(
        vec![],
        vec![
            module_with_departed(
                "m0",
                "/lib/a.so",
                &"a".repeat(64),
                departed_use(
                    1,
                    1,
                    json!([mechanism_row(4231, Some("CKM_AES_GCM"), &["encrypt"], 10,)]),
                    vec![departed_identity("c0", Some("/bin/driver"), "exited")],
                    false,
                    0,
                    departed_overflow(0, 0, 0),
                ),
            ),
            module_with_departed(
                "m1",
                "/lib/b.so",
                &"b".repeat(64),
                departed_use(
                    1,
                    1,
                    json!([mechanism_row(592, Some("CKM_SHA256"), &["digest"], 4,)]),
                    vec![departed_identity("c0", Some("/bin/driver"), "exited")],
                    false,
                    0,
                    departed_overflow(0, 0, 0),
                ),
            ),
        ],
        vec![],
    );
    let control = parse_input(&control).unwrap();
    let folded = parse_input(&folded).unwrap();
    assert_eq!(control.applications.len(), 1);
    assert_eq!(folded.applications.len(), 1);
    assert_eq!(folded.applications[0].incarnations, 1);
    assert_eq!(
        folded.applications[0].incarnations,
        control.applications[0].incarnations
    );
    assert_eq!(folded.applications[0].departed_incarnations, 1);
    // Both providers joined, both mechanisms merged, same pairs.
    assert_eq!(folded.mechanisms.len(), 2);
    assert_eq!(folded.dependencies, control.dependencies);
    assert_eq!(folded.dependencies.len(), 6);
    assert_eq!(folded.unknowns.departed_links_withheld, 0);
}

#[test]
fn cbom_folded_pathless_caller_at_two_modules_counts_unknown_once() {
    // The fold writes the same caller identity into every module
    // the caller touched; a pathless caller counts one unknown, not
    // one per module.
    let folded = inventory_document(
        vec![],
        vec![
            module_with_departed(
                "m0",
                "/lib/a.so",
                &"a".repeat(64),
                departed_use(
                    1,
                    1,
                    json!([]),
                    vec![departed_identity("c0", None, "exited")],
                    false,
                    0,
                    departed_overflow(0, 0, 0),
                ),
            ),
            module_with_departed(
                "m1",
                "/lib/b.so",
                &"b".repeat(64),
                departed_use(
                    1,
                    1,
                    json!([]),
                    vec![departed_identity("c0", None, "exited")],
                    false,
                    0,
                    departed_overflow(0, 0, 0),
                ),
            ),
        ],
        vec![],
    );
    let folded = parse_input(&folded).unwrap();
    assert_eq!(
        folded.unknowns.callers_unknown_exe, 1,
        "one pathless caller counts once across modules"
    );
    // Negative control: two distinct pathless callers still count two.
    let two = inventory_document(
        vec![],
        vec![module_with_departed(
            "m0",
            "/lib/a.so",
            &"a".repeat(64),
            departed_use(
                2,
                2,
                json!([]),
                vec![
                    departed_identity("c0", None, "exited"),
                    departed_identity("c1", None, "exec_retired"),
                ],
                false,
                0,
                departed_overflow(0, 0, 0),
            ),
        )],
        vec![],
    );
    let two = parse_input(&two).unwrap();
    assert_eq!(
        two.unknowns.callers_unknown_exe, 2,
        "distinct pathless callers each count"
    );
    // A contradictory row (pathless in one module, pathed in
    // another) names both facts: the pathless sighting must not
    // consume the caller's incarnation.
    let mixed = inventory_document(
        vec![],
        vec![
            module_with_departed(
                "m0",
                "/lib/a.so",
                &"a".repeat(64),
                departed_use(
                    1,
                    1,
                    json!([]),
                    vec![departed_identity("c0", None, "exited")],
                    false,
                    0,
                    departed_overflow(0, 0, 0),
                ),
            ),
            module_with_departed(
                "m1",
                "/lib/b.so",
                &"b".repeat(64),
                departed_use(
                    1,
                    1,
                    json!([]),
                    vec![departed_identity("c0", Some("/bin/driver"), "exited")],
                    false,
                    0,
                    departed_overflow(0, 0, 0),
                ),
            ),
        ],
        vec![],
    );
    let mixed = parse_input(&mixed).unwrap();
    assert_eq!(
        mixed.unknowns.callers_unknown_exe, 1,
        "the pathless sighting stays named"
    );
    assert_eq!(
        mixed.applications.len(),
        1,
        "the pathed sighting still joins its component"
    );
    assert_eq!(mixed.applications[0].incarnations, 1);
}

#[test]
fn cbom_folded_key_instance_stays_named_but_unjoinable() {
    // Characterization (the Opus-escalated join question): proved
    // key rows survive the fold, but their instance left
    // `instances[]`, so CBOM names the key without provider or
    // application edges. Counts stay exact; only the join degrades.
    // If the fold ever preserves folded join provenance, this twin
    // must move with it deliberately.
    let observations = json!({
        "version": 1, "revision": 1, "status": "populated", "reason": "none",
        "sessions": [{"session": 0, "origin": "opened", "status": "live"}],
        "objects": [
            {
                "object": 0, "session": 0, "origin": "created",
                "creation": "generate", "birth": {"start_ns": 1, "end_ns": 2},
                "lifetime": "live", "lifetime_reason": null,
                "attribution": "valid", "attribution_reason": null,
                "requested": metadata_block(Some(4), Some(31), Some(16)),
                "established": metadata_block(Some(4), Some(31), Some(16)),
                "queries": {"class": "established", "key_type": "established",
                            "token": "established", "value_len": "established",
                            "modulus_bits": "not_queried", "ec_params": "not_queried"},
                "label": "aes_128",
                "successful_references": 3, "successful_key_references": 3,
                "accessing_sessions": 1
            },
        ],
        "key_operations": [
            {"instance": "i0", "object": 0, "category": "encrypt", "role": "key",
             "metadata_at_use": "aes_128", "unit": "operations",
             "started": 3, "completed": 3, "failed": 0, "cancelled": 0,
             "unknown": 0, "active": 0, "key_join_lost": 0},
        ],
        "unknown_key_operations": [],
        "gaps": {"rows": [], "suppressed": 0},
        "budgets": {
            "key_rows": {"limit": 65536, "occupied": 1, "refused": 0},
            "object_rows": {"limit": 65536, "occupied": 1, "refused": 0},
            "unknown_rows": {"occupied": 0},
            "encoded_bytes": 100, "allocation_refused": false, "refusal_reason": "none"
        }
    });
    // Control: the live instance joins provider and application.
    let mut live: Value = serde_json::from_slice(&inventory_document(
        vec![caller("c0", Some("/bin/driver"))],
        vec![module("m0", "/lib/p.so", Some(&"c".repeat(64)))],
        vec![edge("c0", "m0", None)],
    ))
    .unwrap();
    live["instances"] = json!([
        {"id": "i0", "caller": "c0", "module": "m0", "state": "observed",
         "reason": null, "first_seen_ns": 110, "last_seen_ns": 190}
    ]);
    live["object_observations"] = observations.clone();
    let live = parse_input(&serde_json::to_vec(&live).unwrap()).unwrap();
    assert_eq!(live.object_observations, "populated");
    assert_eq!(live.keys.len(), 1);
    assert_eq!(live.unknowns.keys_unjoinable, 0);
    assert!(live.dependencies.contains(&(
        "p11scope:key:0".to_string(),
        "p11scope:module:0".to_string()
    )));
    assert!(live.dependencies.contains(&(
        "p11scope:key:0".to_string(),
        "p11scope:caller:0".to_string()
    )));
    // Folded: the same proved rows with the instance row gone and
    // the caller folded into `departed_use`.
    let mut folded: Value = serde_json::from_slice(&inventory_document(
        vec![],
        vec![module_with_departed(
            "m0",
            "/lib/p.so",
            &"c".repeat(64),
            departed_use(
                1,
                1,
                json!([]),
                vec![departed_identity("c0", Some("/bin/driver"), "exited")],
                false,
                0,
                departed_overflow(0, 0, 0),
            ),
        )],
        vec![],
    ))
    .unwrap();
    folded["object_observations"] = observations;
    let folded = parse_input(&serde_json::to_vec(&folded).unwrap()).unwrap();
    assert_eq!(folded.object_observations, "populated");
    assert_eq!(folded.keys.len(), 1);
    assert_eq!(
        folded.unknowns.keys_unjoinable, 1,
        "the folded instance cannot rejoin its key"
    );
    assert!(
        !folded
            .dependencies
            .iter()
            .any(|(from, _)| from == "p11scope:key:0"),
        "the named key carries no join edges: {:?}",
        folded.dependencies
    );
}

#[test]
fn cbom_departed_single_path_incomplete_withholds_and_counts_linkage() {
    // Every incomplete aggregate with rows withholds its
    // app->mechanism pairs and counts the module once, even with a
    // single path (or none): drops, saturation, a named/callers
    // mismatch, a pathless named sibling, or no paths at all.
    let row = || json!([mechanism_row(4231, Some("CKM_AES_GCM"), &["encrypt"], 10,)]);
    let named = || departed_identity("c0", Some("/bin/driver"), "exited");
    let shapes: Vec<(&str, Value, bool)> = vec![
        (
            "dropped",
            departed_use(
                2,
                1,
                row(),
                vec![named()],
                false,
                1,
                departed_overflow(0, 0, 0),
            ),
            true,
        ),
        (
            "saturated",
            departed_use(
                2,
                1,
                row(),
                vec![named()],
                true,
                1,
                departed_overflow(0, 0, 0),
            ),
            true,
        ),
        (
            "mismatch",
            departed_use(
                2,
                1,
                row(),
                vec![named()],
                false,
                0,
                departed_overflow(0, 0, 0),
            ),
            true,
        ),
        (
            "pathless_sibling",
            departed_use(
                2,
                1,
                row(),
                vec![named(), departed_identity("c1", None, "exited")],
                false,
                0,
                departed_overflow(0, 0, 0),
            ),
            true,
        ),
        (
            "zero_paths",
            departed_use(
                1,
                1,
                row(),
                vec![departed_identity("c0", None, "exited")],
                false,
                0,
                departed_overflow(0, 0, 0),
            ),
            false,
        ),
    ];
    for (name, departed, expect_app_join) in &shapes {
        let bytes = inventory_document(
            vec![],
            vec![module_with_departed(
                "m0",
                "/lib/p.so",
                &"d".repeat(64),
                departed.clone(),
            )],
            vec![],
        );
        let projection = parse_input(&bytes).unwrap();
        assert!(
            !projection.dependencies.iter().any(|(from, to)| {
                from.starts_with("p11scope:caller:") && to.starts_with("p11scope:mechanism:")
            }),
            "{name}: no guessed app->mechanism pairs, got: {:?}",
            projection.dependencies
        );
        if *expect_app_join {
            assert!(
                projection.dependencies.contains(&(
                    "p11scope:caller:0".to_string(),
                    "p11scope:module:0".to_string()
                )),
                "{name}: the named path still joins its provider, got: {:?}",
                projection.dependencies
            );
        }
        assert!(
            projection.dependencies.contains(&(
                "p11scope:module:0".to_string(),
                "p11scope:mechanism:0x1087".to_string()
            )),
            "{name}: the provider still joins its mechanism, got: {:?}",
            projection.dependencies
        );
        assert_eq!(
            projection.unknowns.departed_links_withheld, 1,
            "{name}: the withheld module counts"
        );
        let document = super::render::render_json(&projection);
        assert_eq!(
            metadata_value(&document, "p11scope:departed_links_withheld"),
            "1",
            "{name}: JSON names the withholding"
        );
        let mut concise = Vec::new();
        super::render::render_concise(&projection, &mut concise).unwrap();
        let concise = String::from_utf8(concise).unwrap();
        assert!(
            concise.contains("1 module with withheld departed mechanism linkage"),
            "{name}: coverage names the withholding, got:\n{concise}"
        );
    }
    // No mechanism rows means no pairs to withhold: the module stays
    // uncounted even for a multi-path aggregate.
    let quiet = departed_use(
        2,
        0,
        Value::Null,
        vec![
            departed_identity("c0", Some("/bin/first"), "exited"),
            departed_identity("c1", Some("/bin/second"), "exited"),
        ],
        false,
        0,
        departed_overflow(0, 0, 0),
    );
    let bytes = inventory_document(
        vec![],
        vec![module_with_departed(
            "m0",
            "/lib/p.so",
            &"d".repeat(64),
            quiet,
        )],
        vec![],
    );
    let projection = parse_input(&bytes).unwrap();
    assert_eq!(projection.unknowns.departed_links_withheld, 0);
}

#[test]
fn cbom_departed_rows_without_a_module_id_stay_named_unknowns() {
    let mut orphan = module_with_departed(
        "m0",
        "/lib/p.so",
        &"e".repeat(64),
        departed_use(
            1,
            1,
            json!([mechanism_row(4231, Some("CKM_AES_GCM"), &["encrypt"], 10,)]),
            vec![departed_identity("c0", Some("/bin/driver"), "exited")],
            false,
            0,
            departed_overflow(5, 50, 6),
        ),
    );
    orphan.as_object_mut().expect("module object").remove("id");
    let bytes = inventory_document(vec![], vec![orphan], vec![]);
    let projection = parse_input(&bytes).unwrap();
    // The malformed module counts, and so does its folded content.
    assert_eq!(projection.unknowns.modules_skipped, 1);
    assert_eq!(projection.unknowns.departed_mechs_overflow, 5);
    assert_eq!(projection.unknowns.departed_mechs_overflow_calls, 50);
    assert_eq!(projection.unknowns.departed_mechs_overflow_errors, 6);
    assert_eq!(projection.unknowns.dangling_edge_refs, 1);
    // Nothing joins a provider that was never minted.
    assert!(projection.providers.is_empty());
    assert!(projection.mechanisms.is_empty());
    assert!(projection.dependencies.is_empty());
    // The folded identity still rejoins its application.
    assert_eq!(projection.applications.len(), 1);
    assert_eq!(projection.applications[0].incarnations, 1);
    // JSON names the overflow; concise text names the rows too.
    let document = super::render::render_json(&projection);
    assert_eq!(
        metadata_value(&document, "p11scope:departed_mech_overflow"),
        "5"
    );
    let mut concise = Vec::new();
    super::render::render_concise(&projection, &mut concise).unwrap();
    let concise = String::from_utf8(concise).unwrap();
    assert!(
        concise.contains("5 departed mechanisms past bounds (50 calls, 6 errors)"),
        "coverage names the overflow, got:\n{concise}"
    );
    assert!(
        concise.contains("1 dangling edge reference"),
        "coverage names the unjoinable row, got:\n{concise}"
    );
}

// ---------------------------------------------------------------------------
// Keymeta Task 3 (R2 RED): K4 qualification, provenance tallies, HKDF key
// type and inferred exclusion. The GREEN commit renders them; the tally
// and HKDF twins fail until then (qualification and exclusion pin
// behavior that already holds).
// ---------------------------------------------------------------------------

/// One v7 inventory document: an HKDF object with mixed-source
/// established facts plus a deliberately mismatched inferred row
/// (RSA-2048 inferred on the HKDF key — CBOM must never repeat it).
fn keymeta_v7_document() -> Vec<u8> {
    let mut document: Value = serde_json::from_slice(&inventory_document(
        vec![caller("c0", Some("/bin/driver"))],
        vec![module("m0", "/lib/p.so", Some(&"c".repeat(64)))],
        vec![edge("c0", "m0", None)],
    ))
    .unwrap();
    document["instances"] = json!([
        {"id": "i0", "caller": "c0", "module": "m0", "state": "observed",
         "reason": null, "first_seen_ns": 110, "last_seen_ns": 190}
    ]);
    let slot = |value: Value, source: Value| json!({"status": "value", "value": value, "source": source, "reason": Value::Null});
    document["object_observations"] = json!({
        "version": 7, "revision": 1, "status": "populated", "reason": "none",
        "sessions": [{"session": 0, "origin": "opened", "status": "live"}],
        "objects": [
            {
                "object": 0, "session": 0, "origin": "created",
                "creation": "generate", "birth": {"start_ns": 1, "end_ns": 2},
                "lifetime": "live", "lifetime_reason": null,
                "attribution": "valid", "attribution_reason": null,
                "requested": metadata_block(Some(4), Some(66), Some(32)),
                "established": {
                    "class": slot(json!(4), json!("query")),
                    "key_type": slot(json!(66), json!("creation_success")),
                    "token": slot(json!(0), json!("query")),
                    "value_len": slot(json!(32), json!("creation_success")),
                    "modulus_bits": {"status": "unknown", "value": Value::Null},
                    "ec_params": {"status": "unknown", "value": Value::Null}
                },
                "queries": {"class": "established", "key_type": "established",
                            "token": "established", "value_len": "established",
                            "modulus_bits": "not_queried", "ec_params": "not_queried",
                            "parameter_set": "not_queried"},
                "label": "hkdf_256",
                "successful_references": 2,
                "successful_key_references": 2,
                "accessing_sessions": 1
            }
        ],
        "key_operations": [
            {
                "instance": "i0", "object": 0, "category": "sign",
                "role": "key", "metadata_at_use": "unknown",
                "unit": "operations", "started": 1, "completed": 1,
                "failed": 0, "cancelled": 0, "unknown": 0, "active": 0,
                "key_join_lost": 0,
                "inferred_family": {"status": "inferred", "value": "rsa",
                                    "completions": 1},
                "inferred_size": {"status": "inferred",
                                  "detail": {"kind": "rsa", "size_class": 2048,
                                             "modulus_bytes": 256,
                                             "evidence": "sign_output"},
                                  "completions": 1}
            }
        ],
        "unknown_key_operations": [],
        "unattributed": [],
        "gaps": {"rows": [], "suppressed": 0},
        "budgets": {
            "key_rows": {"limit": 65536, "occupied": 1, "refused": 0},
            "object_rows": {"limit": 8192, "occupied": 1, "refused": 0},
            "unknown_rows": {"occupied": 0},
            "encoded_bytes": 10,
            "allocation_refused": false,
            "refusal_reason": "none"
        }
    });
    serde_json::to_vec(&document).unwrap()
}

/// K4: `creation_success` facts qualify as established (promotion
/// soundness rests on provider compliance, like queries).
#[test]
fn cbom_qualifies_creation_success_as_established() {
    let projection = parse_input(&keymeta_v7_document()).unwrap();
    assert_eq!(projection.keys.len(), 1);
    assert_eq!(projection.keys[0].key_type, Some(66));
    assert_eq!(projection.keys[0].size_bits, Some(256));
}

/// The exporter records per-slot sources in metadata provenance
/// tallies (query vs creation_success vs unrecorded).
#[test]
fn cbom_records_source_provenance_tallies() {
    let projection = parse_input(&keymeta_v7_document()).unwrap();
    let document = super::render::render_json(&projection);
    let properties = document["metadata"]["properties"]
        .as_array()
        .expect("metadata properties");
    let tally = |name: &str| {
        properties
            .iter()
            .find(|prop| prop["name"] == name)
            .unwrap_or_else(|| panic!("{name} tally"))["value"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(tally("p11scope:established_source_query"), "2");
    assert_eq!(tally("p11scope:established_source_creation_success"), "2");
    assert_eq!(tally("p11scope:established_source_unrecorded"), "0");
}

/// Key type 66 renders HKDF, never `unknown`.
#[test]
fn cbom_names_hkdf_key_type() {
    let projection = parse_input(&keymeta_v7_document()).unwrap();
    let document = super::render::render_json(&projection);
    let components = document["components"].as_array().expect("components");
    let key = components
        .iter()
        .find(|component| component["bom-ref"] == "p11scope:key:0")
        .expect("key component");
    let properties = key["properties"].as_array().expect("key properties");
    let key_type = properties
        .iter()
        .find(|prop| prop["name"] == "p11scope:key_type")
        .expect("key_type property");
    assert_eq!(key_type["value"], "66 (hkdf)");
}

/// Inferred facts never qualify for established CBOM fields: the
/// deliberately mismatched RSA-2048 inference leaves no trace.
#[test]
fn cbom_excludes_inferred_facts() {
    let projection = parse_input(&keymeta_v7_document()).unwrap();
    let document = super::render::render_json(&projection);
    let components = document["components"].as_array().expect("components");
    let key = components
        .iter()
        .find(|component| component["bom-ref"] == "p11scope:key:0")
        .expect("key component");
    let related = &key["cryptoProperties"]["relatedCryptoMaterialProperties"];
    assert_eq!(related["size"], 256, "established size only");
    let rendered = serde_json::to_string(key).unwrap();
    for leaked in ["rsa", "2048", "inferred"] {
        assert!(
            !rendered.contains(leaked),
            "no {leaked:?} leaks into the key component:\n{rendered}"
        );
    }
}

/// A CBOM `-o` write failure (ENOSPC here) saves the rendered
/// document to the recovery dir instead of dropping it: the error
/// names the fallback, the saved bytes are the complete document
/// plus its newline, and no temp litters the destination.
#[test]
fn cbom_out_write_failure_saves_the_document_to_recovery() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let input = dir.path().join("input.json");
    let bytes = inventory_document(
        vec![caller("c0", Some("/bin/driver"))],
        vec![module("m0", "/lib/p.so", Some(&"c".repeat(64)))],
        vec![edge("c0", "m0", None)],
    );
    std::fs::write(&input, &bytes).unwrap();
    let out = dir.path().join("out.cdx.json");
    let recovered_base = dir.path().join("p11scope-recovered");
    let loaded = super::input::read_input(&input).unwrap();
    let input_path = super::normalized_path(&input).unwrap();
    let document = super::render::render_json(&loaded.projection);
    let mut sink = crate::output::AtomicFile::create(&out).unwrap();
    sink.set_fail_write_with(libc::ENOSPC);
    let _override = crate::output::hold_recovered_override(&recovered_base);
    let error =
        super::write_sink(&out, &input_path, &loaded.source, &document, sink, || {}).unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("capture saved to"),
        "the error names the fallback, got: {message}"
    );
    assert!(!out.exists(), "the requested -o does not exist");
    let saved: Vec<std::path::PathBuf> = std::fs::read_dir(&recovered_base)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(saved.len(), 1, "one fallback file: {saved:?}");
    let mut expected = serde_json::to_vec(&document).unwrap();
    expected.push(b'\n');
    assert_eq!(
        std::fs::read(&saved[0]).unwrap(),
        expected,
        "the fallback holds the complete document"
    );
    assert!(
        message.contains(&saved[0].display().to_string()),
        "the error names the fallback path, got: {message}"
    );
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        assert!(
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".p11scope."),
            "no temp litters the destination"
        );
    }
}
