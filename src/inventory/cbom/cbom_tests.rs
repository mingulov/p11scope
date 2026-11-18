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
