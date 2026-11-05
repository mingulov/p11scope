//! SPDX-License-Identifier: GPL-3.0-or-later
//! H7 object producer contracts: alias agreement across S1/object protocols,
//! canary/Rust marker parity, catalog pins and ordinary-path compatibility.

use p11scope::kinds::{self, AliasAgreement};
use p11scope_ebpf_common::object_policy;
use p11scope_ebpf_common::object_wire::{
    StartMarkerVerdict, publish_object_descriptors, validate_start_marker,
};
use std::process::Command;

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|name| name.to_string()).collect()
}

#[test]
fn object_producer_aliases_require_both_protocols() {
    // Same S1 shape, differing object protocols: count-only with a reason.
    assert_eq!(
        kinds::descriptor_index_with_object_agreement(&names(&[
            "C_CopyObject",
            "C_SetAttributeValue"
        ])),
        (0, AliasAgreement::ObjectDisagree)
    );
    assert_eq!(
        kinds::descriptor_index_with_object_agreement(&names(&[
            "C_SetAttributeValue",
            "C_CopyObject"
        ])),
        (0, AliasAgreement::ObjectDisagree)
    );
    assert_eq!(
        kinds::descriptor_index_with_object_agreement(&names(&[
            "C_DestroyObject",
            "C_GetObjectSize"
        ])),
        (0, AliasAgreement::ObjectDisagree)
    );
    // Same S1 shape and same object protocol: agree on the lowest id.
    assert_eq!(
        kinds::descriptor_index_with_object_agreement(&names(&[
            "C_VerifyInit",
            "C_VerifySignatureInit"
        ])),
        (49, AliasAgreement::Agree)
    );
    assert_eq!(
        kinds::descriptor_index_with_object_agreement(&names(&["C_Verify", "C_VerifyFinal"])),
        (50, AliasAgreement::Agree)
    );
    assert_eq!(
        kinds::descriptor_index_with_object_agreement(&names(&["C_CreateObject"])),
        (21, AliasAgreement::Agree)
    );
    // S1 disagreement and unknown names stay S1-ambiguous (fail closed);
    // the empty set agrees on count-only exactly as before.
    assert_eq!(
        kinds::descriptor_index_with_object_agreement(&names(&[
            "C_CreateObject",
            "C_DestroyObject"
        ])),
        (0, AliasAgreement::S1Ambiguous)
    );
    assert_eq!(
        kinds::descriptor_index_with_object_agreement(&names(&["C_NoSuchFunction"])),
        (0, AliasAgreement::S1Ambiguous)
    );
    assert_eq!(
        kinds::descriptor_index_with_object_agreement(&[]),
        (0, AliasAgreement::Agree)
    );
}

/// 6.07c item 15: the two KEM functions differ in their S1 shape
/// (distinct direct kinds; encapsulation carries an output
/// marker), so a KEM slot aliased with a disagreeing name is
/// S1-ambiguous and fails closed to count-only.
#[test]
fn object_producer_kem_alias_is_s1_ambiguous() {
    assert_eq!(
        kinds::descriptor_index_with_object_agreement(&names(&[
            "C_EncapsulateKey",
            "C_DecapsulateKey"
        ])),
        (0, AliasAgreement::S1Ambiguous)
    );
    assert_eq!(
        kinds::descriptor_index_with_object_agreement(&names(&[
            "C_DecapsulateKey",
            "C_EncapsulateKey"
        ])),
        (0, AliasAgreement::S1Ambiguous)
    );
    assert_eq!(
        kinds::descriptor_index_with_object_agreement(&names(&[
            "C_EncapsulateKey",
            "C_EncapsulateKey",
            "C_DecapsulateKey"
        ])),
        (0, AliasAgreement::S1Ambiguous)
    );
    // Each KEM name alone agrees with itself on its canonical index.
    assert_eq!(
        kinds::descriptor_index_with_object_agreement(&names(&["C_EncapsulateKey"])),
        (93, AliasAgreement::Agree)
    );
    assert_eq!(
        kinds::descriptor_index_with_object_agreement(&names(&["C_DecapsulateKey"])),
        (94, AliasAgreement::Agree)
    );
}

#[test]
fn object_producer_unit_fixture_ids_match_canonical_catalog() {
    // Every function ordinal hardcoded in unit tests and canary vectors.
    for (name, id) in [
        ("C_CreateObject", 20),
        ("C_CopyObject", 21),
        ("C_DestroyObject", 22),
        ("C_GetObjectSize", 23),
        ("C_SetAttributeValue", 25),
        ("C_VerifyInit", 48),
        ("C_Verify", 49),
        ("C_VerifyFinal", 51),
        ("C_GenerateKeyPair", 59),
        ("C_UnwrapKey", 61),
        ("C_VerifySignatureInit", 94),
    ] {
        assert_eq!(kinds::function_id(name), Some(id), "{name}");
    }
}

#[test]
fn object_producer_ordinary_aliases_stay_compatible() {
    // The production S1 path is unchanged: S1-equal aliases still share
    // their lowest descriptor while the object lane disagrees above.
    assert_eq!(
        kinds::descriptor_index(&names(&["C_CopyObject", "C_SetAttributeValue"])),
        (22, false)
    );
    assert_eq!(
        kinds::descriptor_index(&names(&["C_DestroyObject", "C_GetObjectSize"])),
        (23, false)
    );
    assert!(!kinds::descriptor_slot(&names(&["C_CopyObject", "C_SetAttributeValue"])).1);
}

#[test]
fn object_producer_canary_matches_rust_marker_rule() {
    let table = publish_object_descriptors();
    let mut markers: Vec<u64> = (0..=106).collect();
    markers.extend([255, 256, 1 << 32, u64::MAX]);
    // Every eligible catalog ordinal requires its exact marker.
    for function in 0..104u32 {
        if object_policy::object_descriptor(function).is_some() {
            assert_eq!(
                validate_start_marker(u64::from(function) + 2, &table),
                StartMarkerVerdict::Required {
                    index: function + 1
                },
                "function {function}"
            );
        }
    }
    let rust: Vec<bool> = markers
        .iter()
        .map(|marker| {
            !matches!(
                validate_start_marker(*marker, &table),
                StartMarkerVerdict::Invalid
            )
        })
        .collect();
    // The exact canary decoder must accept/reject the same markers.
    let script = format!(
        "{}/scripts/check-canary-evidence.py",
        env!("CARGO_MANIFEST_DIR")
    );
    let driver = r#"
import importlib.util, struct, sys
spec = importlib.util.spec_from_file_location("canary", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
for token in sys.argv[2:]:
    raw = bytearray(mod.CALL_START_SIZE)
    struct.pack_into("<Q", raw, 264, int(token))
    try:
        mod.decode_start(bytes(raw))
        print(token, "accept")
    except AssertionError:
        print(token, "reject")
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(driver)
        .arg(&script)
        .args(markers.iter().map(u64::to_string))
        .output()
        .expect("canary parity driver runs");
    assert!(
        output.status.success(),
        "canary driver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();
    for (marker, expected) in markers.iter().zip(rust.iter()) {
        let line = lines.next().unwrap_or_default();
        let accepted = line == format!("{marker} accept");
        assert!(
            line == format!("{marker} accept") || line == format!("{marker} reject"),
            "unparsed canary line: {line:?}"
        );
        assert_eq!(accepted, *expected, "marker {marker}");
    }
    assert_eq!(lines.count(), 0);
}
