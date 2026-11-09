//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Offline CBOM export contracts; every input is owned or read-only.

use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const CRYPTO_FIXTURE: &[u8] = include_bytes!("fixtures/cbom/inventory-with-crypto.json");
const SCAN_FIXTURE: &[u8] = include_bytes!("fixtures/inventory-diff/scan-current.json");
const BOM_SCHEMA: &str = include_str!("fixtures/cbom/bom-1.6.schema.json");
const JSF_SCHEMA: &str = include_str!("fixtures/cbom/jsf-0.82.schema.json");
const SPDX_SCHEMA: &str = include_str!("fixtures/cbom/spdx.schema.json");

fn command(input: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_p11scope"));
    command.args(["inventory", "cbom"]).arg(input);
    command.stdin(Stdio::null());
    command
}

fn success(output: &Output) {
    assert_eq!(output.status.code(), Some(0), "{output:?}");
}

fn write_input(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

/// The official CycloneDX 1.6 schema plus its two sibling documents,
/// preloaded under their canonical URIs so validation stays offline.
fn assert_valid(document: &Value) {
    let schema: Value = serde_json::from_str(BOM_SCHEMA).unwrap();
    let jsf: Value = serde_json::from_str(JSF_SCHEMA).unwrap();
    let spdx: Value = serde_json::from_str(SPDX_SCHEMA).unwrap();
    let registry = jsonschema::Registry::new()
        .add(
            "http://cyclonedx.org/schema/jsf-0.82.schema.json",
            jsonschema::Resource::from_contents(jsf),
        )
        .unwrap()
        .add(
            "http://cyclonedx.org/schema/spdx.schema.json",
            jsonschema::Resource::from_contents(spdx),
        )
        .unwrap()
        .prepare()
        .unwrap();
    let validator = jsonschema::options()
        .with_registry(&registry)
        .build(&schema)
        .unwrap();
    let errors: Vec<String> = validator
        .iter_errors(document)
        .map(|error| format!("{error} @ {}", error.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "CBOM fails the CycloneDX 1.6 schema: {errors:?}"
    );
}

fn components(document: &Value) -> Vec<&Value> {
    document
        .get("components")
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

fn find<'a>(items: &[&'a Value], name: &str) -> &'a Value {
    items
        .iter()
        .find(|item| item.get("name").and_then(Value::as_str) == Some(name))
        .unwrap_or_else(|| panic!("missing component {name:?}"))
}

fn properties(item: &Value) -> Vec<(&str, &str)> {
    item.get("properties")
        .and_then(Value::as_array)
        .map(|props| {
            props
                .iter()
                .filter_map(|prop| {
                    Some((
                        prop.get("name")?.as_str()?,
                        prop.get("value")?.as_str().unwrap_or(""),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn metadata_properties(document: &Value) -> Vec<(String, String)> {
    document
        .pointer("/metadata/properties")
        .and_then(Value::as_array)
        .map(|props| {
            props
                .iter()
                .filter_map(|prop| {
                    Some((
                        prop.get("name")?.as_str()?.to_string(),
                        prop.get("value")?.as_str().unwrap_or("").to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn crypto_inventory_converts_to_schema_valid_cbom() {
    let dir = tempfile::tempdir().unwrap();
    let input = write_input(dir.path(), "inventory.json", CRYPTO_FIXTURE);
    let output = command(&input).arg("--json").output().unwrap();
    success(&output);
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_valid(&document);

    assert_eq!(document["bomFormat"], "CycloneDX");
    assert_eq!(document["specVersion"], "1.6");
    assert!(output.stdout.ends_with(b"\n"));
    assert!(!output.stdout.ends_with(b"\n\n"));
    assert!(output.stderr.is_empty());

    let meta = metadata_properties(&document);
    assert!(
        meta.contains(&(
            "p11scope:source_schema".to_string(),
            "p11scope/inventory/v1".to_string()
        )),
        "provenance properties: {meta:?}"
    );

    let items = components(&document);
    // 2 applications, 2 providers, 6 mechanisms, 3 keys.
    assert_eq!(items.len(), 13, "components: {items:?}");

    let driver = find(&items, "/bin/driver");
    assert_eq!(driver["type"], "application");
    let signer = find(&items, "/usr/bin/signer");
    assert_eq!(signer["type"], "application");

    let provider = find(&items, "/opt/vendor/lib/pkcs11.so");
    assert_eq!(provider["type"], "library");
    assert_eq!(
        provider["hashes"][0]["alg"], "SHA-256",
        "provider hashes: {provider:?}"
    );
    assert_eq!(
        provider["hashes"][0]["content"],
        "1ff5c9fa5dd56dd556dcc7fa0e44f20a078015298119d76b3ef11833aa3a4a66"
    );

    let gcm = find(&items, "CKM_AES_GCM");
    assert_eq!(gcm["type"], "cryptographic-asset");
    assert_eq!(gcm["cryptoProperties"]["assetType"], "algorithm");
    assert_eq!(
        gcm["cryptoProperties"]["algorithmProperties"]["primitive"],
        "ae"
    );
    assert_eq!(
        gcm["cryptoProperties"]["algorithmProperties"]["mode"],
        "gcm"
    );
    // Unioned across both edges: 24 + 8 calls.
    let gcm_props = properties(gcm);
    assert!(
        gcm_props.contains(&("p11scope:calls", "32")),
        "gcm properties: {gcm_props:?}"
    );

    let kem = find(&items, "CKM_ML_KEM");
    assert_eq!(
        kem["cryptoProperties"]["algorithmProperties"]["primitive"],
        "kem"
    );
    let rsa = find(&items, "CKM_RSA_PKCS");
    assert_eq!(
        rsa["cryptoProperties"]["algorithmProperties"]["primitive"],
        "pke"
    );
    assert_eq!(
        rsa["cryptoProperties"]["algorithmProperties"]["padding"],
        "pkcs1v15"
    );
    let sha = find(&items, "CKM_SHA256");
    assert_eq!(
        sha["cryptoProperties"]["algorithmProperties"]["primitive"],
        "hash"
    );
    let ecdsa = find(&items, "CKM_ECDSA");
    assert_eq!(
        ecdsa["cryptoProperties"]["algorithmProperties"]["primitive"],
        "signature"
    );
    // The unregistered id keeps its hex identity and an unknown primitive.
    let vendor = find(&items, "PKCS#11 mechanism 0x80000001");
    assert_eq!(
        vendor["cryptoProperties"]["algorithmProperties"]["primitive"],
        "unknown"
    );

    let rsa_key = find(&items, "rsa_2048");
    assert_eq!(
        rsa_key["cryptoProperties"]["assetType"],
        "related-crypto-material"
    );
    assert_eq!(
        rsa_key["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"],
        "private-key"
    );
    assert_eq!(
        rsa_key["cryptoProperties"]["relatedCryptoMaterialProperties"]["size"],
        2048
    );
    let aes_key = find(&items, "aes_128");
    assert_eq!(
        aes_key["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"],
        "secret-key"
    );
    assert_eq!(
        aes_key["cryptoProperties"]["relatedCryptoMaterialProperties"]["size"],
        128
    );
    let unknown_key = find(&items, "key object 2");
    assert_eq!(
        unknown_key["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"],
        "private-key"
    );
    assert!(
        unknown_key["cryptoProperties"]["relatedCryptoMaterialProperties"]
            .get("size")
            .is_none(),
        "unsized key must not guess: {unknown_key:?}"
    );

    // No key material, identifiers, states or dates on the material
    // objects: only type, size and the traceability properties.
    for item in &items {
        if let Some(material) = item.pointer("/cryptoProperties/relatedCryptoMaterialProperties") {
            let object = material.as_object().unwrap();
            for forbidden in [
                "value",
                "id",
                "state",
                "creationDate",
                "activationDate",
                "updateDate",
                "expirationDate",
            ] {
                assert!(
                    !object.contains_key(forbidden),
                    "forbidden key {forbidden:?} on {item:?}"
                );
            }
        }
    }

    // Proven joins only: application -> provider -> mechanism.
    let dependencies = document["dependencies"].as_array().unwrap();
    let driver_ref = driver["bom-ref"].as_str().unwrap();
    let provider_ref = provider["bom-ref"].as_str().unwrap();
    let driver_deps = dependencies
        .iter()
        .find(|entry| entry["ref"] == driver_ref)
        .unwrap();
    assert!(
        driver_deps["dependsOn"]
            .as_array()
            .unwrap()
            .contains(&json!(provider_ref)),
        "driver dependencies: {driver_deps:?}"
    );
    let provider_deps = dependencies
        .iter()
        .find(|entry| entry["ref"] == provider_ref)
        .unwrap();
    assert!(
        !provider_deps["dependsOn"].as_array().unwrap().is_empty(),
        "provider dependencies: {provider_deps:?}"
    );
}

#[test]
fn schema_validator_rejects_tampered_bom() {
    let dir = tempfile::tempdir().unwrap();
    let input = write_input(dir.path(), "inventory.json", CRYPTO_FIXTURE);
    let output = command(&input).arg("--json").output().unwrap();
    success(&output);
    let mut document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_valid(&document);

    // Negative controls: the same validator must reject broken documents,
    // or the green above would prove nothing.
    let mut tampered = document.clone();
    tampered["components"][0]["cryptoProperties"]["assetType"] = json!("bogus");
    let schema: Value = serde_json::from_str(BOM_SCHEMA).unwrap();
    let jsf: Value = serde_json::from_str(JSF_SCHEMA).unwrap();
    let spdx: Value = serde_json::from_str(SPDX_SCHEMA).unwrap();
    let registry = jsonschema::Registry::new()
        .add(
            "http://cyclonedx.org/schema/jsf-0.82.schema.json",
            jsonschema::Resource::from_contents(jsf),
        )
        .unwrap()
        .add(
            "http://cyclonedx.org/schema/spdx.schema.json",
            jsonschema::Resource::from_contents(spdx),
        )
        .unwrap()
        .prepare()
        .unwrap();
    let validator = jsonschema::options()
        .with_registry(&registry)
        .build(&schema)
        .unwrap();
    assert!(!validator.is_valid(&tampered));
    document.as_object_mut().unwrap().remove("specVersion");
    assert!(!validator.is_valid(&document));
}

#[test]
fn concise_and_verbose_text_name_applications_providers_and_unknowns() {
    let dir = tempfile::tempdir().unwrap();
    let input = write_input(dir.path(), "inventory.json", CRYPTO_FIXTURE);
    let output = command(&input).output().unwrap();
    success(&output);
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "/bin/driver",
        "/usr/bin/signer",
        "/opt/vendor/lib/pkcs11.so",
        "2 applications",
        "2 providers",
        "6 cryptographic algorithms",
        "3 key objects",
        "unknown",
    ] {
        assert!(text.contains(expected), "missing {expected:?}: {text}");
    }
    assert!(!text.as_bytes().contains(&0x1b));

    let output = command(&input).arg("-v").output().unwrap();
    success(&output);
    let verbose = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "CKM_AES_GCM",
        "CKM_ML_KEM",
        "0x80000001",
        "rsa_2048",
        "aes_128",
        "key object 2",
        "private-key",
    ] {
        assert!(
            verbose.contains(expected),
            "missing {expected:?}: {verbose}"
        );
    }

    let output = command(&input).arg("--quiet").output().unwrap();
    success(&output);
    let quiet = String::from_utf8(output.stdout).unwrap();
    assert!(quiet.contains("2 applications"), "quiet: {quiet}");
    assert!(!quiet.contains("-v"), "quiet keeps no hint: {quiet}");
}

#[test]
fn dash_o_writes_cbom_file_and_stdout_stays_text() {
    let dir = tempfile::tempdir().unwrap();
    let input = write_input(dir.path(), "inventory.json", CRYPTO_FIXTURE);
    let out = dir.path().join("out.cdx.json");
    let output = command(&input).arg("-o").arg(&out).output().unwrap();
    success(&output);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("2 applications"), "stdout: {text}");
    let document: Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_valid(&document);
    assert_eq!(document["bomFormat"], "CycloneDX");
}

#[test]
fn scan_fixture_without_crypto_stays_honest() {
    let dir = tempfile::tempdir().unwrap();
    let input = write_input(dir.path(), "inventory.json", SCAN_FIXTURE);
    let output = command(&input).arg("--json").output().unwrap();
    success(&output);
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_valid(&document);
    let items = components(&document);
    assert_eq!(items.len(), 2, "scan components: {items:?}");
    assert_eq!(find(&items, "/bin/driver")["type"], "application");
    assert_eq!(find(&items, "/scale/m0.so")["type"], "library");
    let meta = metadata_properties(&document);
    assert!(
        meta.contains(&("p11scope:algorithms".to_string(), "0".to_string())),
        "counts: {meta:?}"
    );
    // The observed mapping joins application and provider even with no
    // mechanism claims.
    let dependencies = document["dependencies"].as_array().unwrap();
    assert_eq!(dependencies.len(), 1);
    assert_eq!(dependencies[0]["ref"], "p11scope:caller:0");
    assert_eq!(dependencies[0]["dependsOn"], json!(["p11scope:module:0"]));
    let output = command(&input).output().unwrap();
    success(&output);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("0 cryptographic algorithms"), "{text}");
    assert!(text.contains("0 key objects"), "{text}");
}

#[test]
fn profile_input_projects_mechanisms_without_names() {
    let dir = tempfile::tempdir().unwrap();
    let profile = json!({
        "schema": "p11scope/observed-profile/v3",
        "capture": {
            "mode": "profile",
            "modules": [
                {
                    "path": "/usr/lib/softhsm/libsofthsm2.so",
                    "dev": [8, 1],
                    "ino": 500,
                    "sha256": "aaaa".repeat(16),
                    "build_id": null
                }
            ]
        },
        "evidence": {},
        "functions": [],
        "mechanisms": [
            {
                "mechanism": 4231,
                "mechanism_hex": "0x1087",
                "registered": true,
                "ops": ["encrypt"],
                "calls": 10,
                "errors": 0
            },
            {
                "mechanism": 2147483649u64,
                "mechanism_hex": "0x80000001",
                "registered": false,
                "ops": [],
                "calls": 1,
                "errors": 1
            }
        ],
        "sessions": {},
        "logins": {},
        "templates": {"operations": []},
        "cgroups": []
    });
    let input = write_input(
        dir.path(),
        "profile.json",
        &serde_json::to_vec(&profile).unwrap(),
    );
    let output = command(&input).arg("--json").output().unwrap();
    success(&output);
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_valid(&document);
    let items = components(&document);
    // Provider plus two numeric-only algorithms; profile publishes no
    // caller or key linkage, so those components stay absent and noted.
    assert_eq!(items.len(), 3, "profile components: {items:?}");
    let gcm = find(&items, "PKCS#11 mechanism 0x1087");
    assert_eq!(
        gcm["cryptoProperties"]["algorithmProperties"]["primitive"],
        "unknown"
    );
    let meta = metadata_properties(&document);
    assert!(
        meta.iter().any(|(name, _)| name == "p11scope:profile_note"),
        "profile honesty note: {meta:?}"
    );
}

#[test]
fn refuses_unusable_input_and_usage_errors() {
    let dir = tempfile::tempdir().unwrap();
    let garbage = write_input(dir.path(), "garbage.json", b"{not json");
    let output = command(&garbage).output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");

    let wrong_schema = write_input(
        dir.path(),
        "diff.json",
        br#"{"schema": "p11scope/inventory-diff/v1"}"#,
    );
    let output = command(&wrong_schema).arg("--json").output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());

    let input = write_input(dir.path(), "inventory.json", CRYPTO_FIXTURE);
    let binary = env!("CARGO_BIN_EXE_p11scope");
    let output = Command::new(binary)
        .args(["inventory", "cbom", "-o"])
        .arg(&input)
        .arg(&input)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");

    let output = Command::new(binary)
        .args(["inventory", "cbom"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");

    let output = command(&input).arg("-o").arg("-").output().unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}
