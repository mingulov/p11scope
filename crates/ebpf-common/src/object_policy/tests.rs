//! SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use crate::{LinuxLayout, ARG_NONE as N};

const SELECTORS: &[(u64, SafeAttributeKind)] = &[
    (0x0000, SafeAttributeKind::Class),
    (0x0001, SafeAttributeKind::Token),
    (0x0100, SafeAttributeKind::KeyType),
    (0x0121, SafeAttributeKind::ModulusBits),
    (0x0161, SafeAttributeKind::ValueLen),
    (0x0180, SafeAttributeKind::EcParams),
];

const SCALARS: &[(SafeAttributeKind, &[u64])] = &[
    (SafeAttributeKind::Class, &[0, 1, 2, 3, 4]),
    (
        SafeAttributeKind::KeyType,
        &[0x00, 0x01, 0x02, 0x03, 0x04, 0x10, 0x1f, 0x3a, 0x3b],
    ),
    (SafeAttributeKind::Token, &[0, 1]),
    (SafeAttributeKind::ValueLen, &[16, 24, 32]),
    (
        SafeAttributeKind::ModulusBits,
        &[1024, 2048, 3072, 4096, 8192],
    ),
    (SafeAttributeKind::EcParams, &[]),
];

const CURVES: &[(&[u8], SafeCurve)] = &[
    (
        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        SafeCurve::Secp256r1,
    ),
    (
        &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
        SafeCurve::Secp384r1,
    ),
    (
        &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23],
        SafeCurve::Secp521r1,
    ),
];

const DERIVE: &[(u64, ScalarDeriveMechanism)] = &[
    (0x21, ScalarDeriveMechanism::DhPkcs),
    (0x393, ScalarDeriveMechanism::Sha256),
    (0x1050, ScalarDeriveMechanism::Ecdh1),
    (0x1051, ScalarDeriveMechanism::Ecdh1Cofactor),
];

// Mutation caught: any additional selector or scalar permission, including an
// excluded ID/unique-ID selector, or an accidental loss of valid zero values.
#[test]
fn s2s3_safe_attribute_sets_are_closed() {
    for raw in 0..=u16::MAX as u64 {
        let expected = SELECTORS
            .iter()
            .find(|(value, _)| *value == raw)
            .map(|(_, kind)| *kind);
        assert_eq!(safe_attribute_kind(raw), expected, "selector {raw:#x}");
    }
    for raw in [0x102, 0x2e, u32::MAX as u64, u64::MAX] {
        assert_eq!(safe_attribute_kind(raw), None);
    }
    for &(kind, accepted) in SCALARS {
        for value in 0..=u16::MAX as u64 {
            let expected = accepted.contains(&value).then_some(value as u16);
            assert_eq!(
                classify_attribute_scalar(kind, value),
                expected,
                "{kind:?}: {value:#x}"
            );
        }
        for value in [u32::MAX as u64, u64::MAX] {
            assert_eq!(classify_attribute_scalar(kind, value), None);
        }
    }
}

// Mutation caught: host-width scalar reads, multi-byte booleans, or permissive
// curve lengths instead of the exact target-layout shapes.
#[test]
fn s2s3_safe_lengths_follow_target_width() {
    for (layout, word) in [(LinuxLayout::Lp64, 8), (LinuxLayout::Ilp32, 4)] {
        for &(kind, _) in SCALARS {
            for len in 0..=16 {
                let expected = match kind {
                    SafeAttributeKind::Token => len == 1,
                    SafeAttributeKind::EcParams => len == 7 || len == 10,
                    _ => len == word,
                };
                assert_eq!(
                    valid_safe_attribute_length(kind, len, layout),
                    expected,
                    "{layout:?} {kind:?}: {len}"
                );
            }
            for len in [u32::MAX as u64, u64::MAX] {
                assert!(!valid_safe_attribute_length(kind, len, layout));
            }
        }
    }
}

// Mutation caught: a prefix/substring/hash/BER parser admitting bytes outside
// the complete reviewed DER encodings, including a changed tag, length or OID.
#[test]
fn s2s3_curve_encodings_are_exact() {
    for &(bytes, curve) in CURVES {
        assert_eq!(classify_ec_params(bytes), Some(curve));
        for end in 0..bytes.len() {
            assert_eq!(classify_ec_params(&bytes[..end]), None);
        }
        let mut buffer = [0u8; 12];
        buffer[..bytes.len()].copy_from_slice(bytes);
        assert_eq!(classify_ec_params(&buffer[..bytes.len() + 1]), None);
        buffer[1..bytes.len() + 1].copy_from_slice(bytes);
        buffer[0] = 0x51;
        assert_eq!(classify_ec_params(&buffer[..bytes.len() + 1]), None);
        for index in 0..bytes.len() {
            buffer[..bytes.len()].copy_from_slice(bytes);
            buffer[index] ^= 0x80;
            assert_eq!(
                classify_ec_params(&buffer[..bytes.len()]),
                None,
                "changed byte {index}"
            );
        }
        buffer[0] = 0x06;
        buffer[1] = 0x81;
        buffer[2] = bytes[1];
        buffer[3..bytes.len() + 1].copy_from_slice(&bytes[2..]);
        assert_eq!(classify_ec_params(&buffer[..bytes.len() + 1]), None);
        buffer[..bytes.len()].copy_from_slice(bytes);
        buffer[bytes.len() - 4..bytes.len()].copy_from_slice(&[0x51, 0x52, 0x53, 0x54]);
        assert_eq!(classify_ec_params(&buffer[..bytes.len()]), None);
    }
}

// Mutation caught: narrowing/masking any selector, scalar, length or mechanism
// before comparing it. The u64 API also rejects unrepresentable ia32 inputs.
#[test]
fn s2s3_classification_rejects_high_bits() {
    let derive_id = function_id("C_DeriveKey");
    for high in [1u64 << 16, 1u64 << 32] {
        for &(selector, kind) in SELECTORS {
            assert_eq!(safe_attribute_kind(selector), Some(kind));
            assert_eq!(safe_attribute_kind(selector | high), None);
        }
        for &(kind, values) in SCALARS {
            for &value in values {
                assert_eq!(classify_attribute_scalar(kind, value), Some(value as u16));
                assert_eq!(classify_attribute_scalar(kind, value | high), None);
            }
            for (layout, word) in [(LinuxLayout::Lp64, 8), (LinuxLayout::Ilp32, 4)] {
                let lengths: &[u64] = match kind {
                    SafeAttributeKind::Token => &[1],
                    SafeAttributeKind::EcParams => &[7, 10],
                    _ => core::slice::from_ref(&word),
                };
                for &len in lengths {
                    assert!(valid_safe_attribute_length(kind, len, layout));
                    assert!(!valid_safe_attribute_length(kind, len | high, layout));
                }
            }
        }
        for &(mechanism, expected) in DERIVE {
            assert_eq!(
                derive_result_protocol(mechanism),
                DeriveResultProtocol::ScalarHandle(expected)
            );
            assert_eq!(
                derive_result_protocol(mechanism | high),
                DeriveResultProtocol::Unavailable
            );
            assert_eq!(
                authorized_result_pointer_args(derive_id, Some(mechanism | high)),
                [N, N]
            );
        }
    }
}

// Literal policy rows, independent of the production descriptor constructor.
// Fields: name, action, input indices, result indices, template/count pairs,
// find capacity/count indices, result-protocol guard.
struct Expected(
    &'static str,
    ObjectAction,
    [u8; 2],
    [u8; 2],
    [(u8, u8); 2],
    [u8; 2],
    ResultProtocolGuard,
);

use ObjectAction::*;
use ResultProtocolGuard::{NamedFunction, ScalarDeriveMechanism as DeriveGuard};

const EXPECTED: &[Expected] = &[
    Expected(
        "C_CreateObject",
        Create,
        [N, N],
        [3, N],
        [(1, 2), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_CopyObject",
        Copy,
        [1, N],
        [4, N],
        [(2, 3), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_GenerateKey",
        Generate,
        [N, N],
        [4, N],
        [(2, 3), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_GenerateKeyPair",
        GeneratePair,
        [N, N],
        [6, 7],
        [(2, 3), (4, 5)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_DeriveKey",
        Derive,
        [2, N],
        [5, N],
        [(3, 4), (N, N)],
        [N, N],
        DeriveGuard,
    ),
    Expected(
        "C_UnwrapKey",
        Unwrap,
        [2, N],
        [7, N],
        [(5, 6), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_DestroyObject",
        Destroy,
        [1, N],
        [N, N],
        [(N, N), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_GetObjectSize",
        Access,
        [1, N],
        [N, N],
        [(N, N), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_GetAttributeValue",
        GetAttributes,
        [1, N],
        [N, N],
        [(2, 3), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_SetAttributeValue",
        SetAttributes,
        [1, N],
        [N, N],
        [(N, N), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_EncryptInit",
        Access,
        [2, N],
        [N, N],
        [(N, N), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_DecryptInit",
        Access,
        [2, N],
        [N, N],
        [(N, N), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_SignInit",
        Access,
        [2, N],
        [N, N],
        [(N, N), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_SignRecoverInit",
        Access,
        [2, N],
        [N, N],
        [(N, N), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_VerifyInit",
        Access,
        [2, N],
        [N, N],
        [(N, N), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_VerifyRecoverInit",
        Access,
        [2, N],
        [N, N],
        [(N, N), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_MessageEncryptInit",
        Access,
        [2, N],
        [N, N],
        [(N, N), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_MessageDecryptInit",
        Access,
        [2, N],
        [N, N],
        [(N, N), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_MessageSignInit",
        Access,
        [2, N],
        [N, N],
        [(N, N), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_MessageVerifyInit",
        Access,
        [2, N],
        [N, N],
        [(N, N), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_VerifySignatureInit",
        Access,
        [2, N],
        [N, N],
        [(N, N), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_DigestKey",
        Access,
        [1, N],
        [N, N],
        [(N, N), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_WrapKey",
        Access,
        [2, 3],
        [N, N],
        [(N, N), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_SetOperationState",
        OperationImport,
        [3, 4],
        [N, N],
        [(N, N), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_FindObjects",
        Find,
        [N, N],
        [1, N],
        [(N, N), (N, N)],
        [2, 3],
        NamedFunction,
    ),
];

fn function_id(name: &str) -> u32 {
    pkcs11_module::FUNCTION_NAMES
        .iter()
        .position(|candidate| *candidate == name)
        .unwrap() as u32
}

fn literal_descriptor(row: &Expected) -> ObjectCaptureDescriptor {
    ObjectCaptureDescriptor {
        action: row.1,
        input_args: row.2,
        result_pointer_args: row.3,
        template_args: row.4,
        find_capacity_arg: row.5[0],
        find_count_ptr_arg: row.5[1],
        result_protocol_guard: row.6,
    }
}

// Mutation caught: any wrong role/index/template protocol or authorization
// added to an unlisted standard function anywhere in the frozen 104-name set.
#[test]
fn s2s3_object_descriptor_matrix() {
    assert_eq!(pkcs11_module::FUNCTION_NAMES.len(), 104);
    assert_eq!(EXPECTED.len(), 25);
    for (id, name) in pkcs11_module::FUNCTION_NAMES.iter().enumerate() {
        let expected = EXPECTED
            .iter()
            .find(|row| row.0 == *name)
            .map(literal_descriptor);
        assert_eq!(object_descriptor(id as u32), expected, "{name}");
        for mechanism in [None, Some(0), Some(0x21), Some(0x372), Some(u64::MAX)] {
            let expected_args = match EXPECTED.iter().find(|row| row.0 == *name) {
                Some(row) if row.0 == "C_DeriveKey" => {
                    if mechanism == Some(0x21) {
                        [5, N]
                    } else {
                        [N, N]
                    }
                }
                Some(row) => row.3,
                None => [N, N],
            };
            assert_eq!(
                authorized_result_pointer_args(id as u32, mechanism),
                expected_args,
                "{name}: {mechanism:?}"
            );
        }
    }
    for name in [
        "C_UnwrapKeyAuthenticated",
        "C_EncapsulateKey",
        "C_FindObjectsInit",
        "C_DecapsulateKey",
        "C_WrapKeyAuthenticated",
        "C_AsyncComplete",
    ] {
        assert_eq!(object_descriptor(function_id(name)), None);
    }
    for id in [104, 105, 0x8000_0000, u32::MAX] {
        assert_eq!(object_descriptor(id), None);
        assert_eq!(authorized_result_pointer_args(id, Some(0x21)), [N, N]);
        for row in EXPECTED {
            assert!(!valid_object_descriptor(id, &literal_descriptor(row)));
        }
    }
}

fn replace_argument(
    mut descriptor: ObjectCaptureDescriptor,
    position: usize,
    value: u8,
) -> ObjectCaptureDescriptor {
    match position {
        0..=1 => descriptor.input_args[position] = value,
        2..=3 => descriptor.result_pointer_args[position - 2] = value,
        4 => descriptor.template_args[0].0 = value,
        5 => descriptor.template_args[0].1 = value,
        6 => descriptor.template_args[1].0 = value,
        7 => descriptor.template_args[1].1 = value,
        8 => descriptor.find_capacity_arg = value,
        9 => descriptor.find_count_ptr_arg = value,
        _ => unreachable!(),
    }
    descriptor
}

// Mutation caught: validating only a generic argument bound, or allowing 7 in
// another field or another named function. Neither 8 nor 9 is authorized.
#[test]
fn s2s3_argument_seven_is_named_only() {
    assert_eq!(
        object_descriptor(function_id("C_GenerateKeyPair"))
            .unwrap()
            .result_pointer_args,
        [6, 7]
    );
    assert_eq!(
        object_descriptor(function_id("C_UnwrapKey"))
            .unwrap()
            .result_pointer_args,
        [7, N]
    );
    for row in EXPECTED {
        let id = function_id(row.0);
        let expected = literal_descriptor(row);
        for position in 0..10 {
            for value in [7, 8, 9] {
                let candidate = replace_argument(expected, position, value);
                let permitted = value == 7
                    && ((row.0 == "C_GenerateKeyPair" && position == 3)
                        || (row.0 == "C_UnwrapKey" && position == 2));
                assert_eq!(
                    valid_object_descriptor(id, &candidate),
                    permitted,
                    "{}: position {position}, value {value}",
                    row.0
                );
            }
        }
    }
}

// Mutation caught: partial validation that ignores a field or treats another
// in-range argument, action, or protocol discriminator as interchangeable.
#[test]
fn s2s3_descriptor_validation_rejects_all_changed_fields() {
    for row in EXPECTED {
        let id = function_id(row.0);
        let expected = literal_descriptor(row);
        assert!(valid_object_descriptor(id, &expected));
        let original_args = [
            row.2[0], row.2[1], row.3[0], row.3[1], row.4[0].0, row.4[0].1, row.4[1].0, row.4[1].1,
            row.5[0], row.5[1],
        ];
        for (position, original) in original_args.into_iter().enumerate() {
            for value in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, N] {
                let candidate = replace_argument(expected, position, value);
                assert_eq!(
                    valid_object_descriptor(id, &candidate),
                    value == original,
                    "{}: position {position}, value {value}",
                    row.0
                );
            }
        }
        for action in [
            Create,
            Copy,
            Generate,
            GeneratePair,
            Derive,
            Unwrap,
            Destroy,
            Access,
            OperationImport,
            Find,
            GetAttributes,
            SetAttributes,
        ] {
            let candidate = ObjectCaptureDescriptor { action, ..expected };
            assert_eq!(valid_object_descriptor(id, &candidate), action == row.1);
        }
        for guard in [NamedFunction, DeriveGuard] {
            let candidate = ObjectCaptureDescriptor {
                result_protocol_guard: guard,
                ..expected
            };
            assert_eq!(valid_object_descriptor(id, &candidate), guard == row.6);
        }
    }
}

// Mutation caught: accepting an adjacent/unknown mechanism or returning the
// wrong discriminator, which would defeat a later entry/return comparison.
#[test]
fn s2s3_derive_result_protocol_is_closed() {
    for raw in 0..=u16::MAX as u64 {
        let expected = DERIVE
            .iter()
            .find(|(value, _)| *value == raw)
            .map(|(_, mechanism)| DeriveResultProtocol::ScalarHandle(*mechanism))
            .unwrap_or(DeriveResultProtocol::Unavailable);
        assert_eq!(derive_result_protocol(raw), expected, "mechanism {raw:#x}");
    }
    for raw in [
        0x372,
        0x3e1,
        0x3d3,
        0x3d4,
        0x3d5,
        0x8000_0000,
        u32::MAX as u64,
        u64::MAX,
    ] {
        assert_eq!(
            derive_result_protocol(raw),
            DeriveResultProtocol::Unavailable
        );
    }
}

// Mutation caught: using Derive's nominal arg 5 without mechanism authority.
// This API has no handle or memory input. The actual untouched nonzero phKey
// sentinel/no-read/no-result oracle belongs to Task 4/C3, not these pure tests.
#[test]
fn s2s3_derive_ignored_phkey_protocol_is_not_authorized() {
    let id = function_id("C_DeriveKey");
    for mechanism in [
        None,
        Some(0x372),
        Some(0x3e1),
        Some(0x3d3),
        Some(0x3d4),
        Some(0x3d5),
        Some(0),
        Some(0x8000_0000),
        Some(u64::MAX),
    ] {
        assert_eq!(authorized_result_pointer_args(id, mechanism), [N, N]);
    }
}

// Mutation caught: blanket refusal of allowed scalar-result derives, or
// bypass of their protocol guard by substituting a NamedFunction descriptor.
#[test]
fn s2s3_derive_scalar_phkey_is_authorized() {
    let id = function_id("C_DeriveKey");
    for &(mechanism, expected) in DERIVE {
        assert_eq!(
            derive_result_protocol(mechanism),
            DeriveResultProtocol::ScalarHandle(expected)
        );
        assert_eq!(authorized_result_pointer_args(id, Some(mechanism)), [5, N]);
    }
    let changed = ObjectCaptureDescriptor {
        action: Derive,
        input_args: [2, N],
        result_pointer_args: [5, N],
        template_args: [(3, 4), (N, N)],
        find_capacity_arg: N,
        find_count_ptr_arg: N,
        result_protocol_guard: NamedFunction,
    };
    assert!(!valid_object_descriptor(id, &changed));
}
