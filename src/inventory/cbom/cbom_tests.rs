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
