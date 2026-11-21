//! SPDX-License-Identifier: GPL-2.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>

use super::*;
use crate::{LinuxLayout, ARG_NONE as N};

const SELECTORS: &[(u64, SafeAttributeKind)] = &[
    (0x0000, SafeAttributeKind::Class),
    (0x0001, SafeAttributeKind::Token),
    (0x0100, SafeAttributeKind::KeyType),
    (0x0121, SafeAttributeKind::ModulusBits),
    (0x0161, SafeAttributeKind::ValueLen),
    (0x0180, SafeAttributeKind::EcParams),
    // F16 (7.05 PQC) reviewed row: the parameter-set selector.
    (0x061d, SafeAttributeKind::ParameterSet),
];

/// A closed scalar set: an exact list or a closed range. Ranges keep
/// their ends pinned by the closed-set test (every value inside and
/// outside the range, exhaustively over the u16 span that covers them).
#[derive(Clone, Copy)]
enum ScalarSet {
    Exact(&'static [u64]),
    Range { lo: u64, hi: u64 },
}

impl ScalarSet {
    fn contains(&self, value: u64) -> bool {
        match self {
            ScalarSet::Exact(list) => list.contains(&value),
            ScalarSet::Range { lo, hi } => *lo <= value && value <= *hi,
        }
    }
}

// Relaxed-dialect fix1 reviewed rows: Class gains the remaining assigned
// CKO_* (5..=11); KeyType gains every assigned standard CKK_*
// (0x05 KEA plus the contiguous 0x11..=0x4b block: RC2/RC4/DES/DES3,
// CAST/RC5/IDEA/legacy, AES, Blowfish/Twofish, SecurID/HOTP/ACTI,
// Camellia/Aria, the HMAC block, SEED, GOST/ChaCha20/Poly1305/AES-XTS,
// SHA3/BLAKE2 HMACs, Salsa20/X2RATCHET, Edwards/Montgomery, HKDF,
// SHA512 HMACs, HSS/XMSS, PQC); ValueLen/ModulusBits become closed
// ranges (0 and absurd sizes stay refused).
const CLASS_VALUES: &[u64] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
const KEY_TYPE_VALUES: &[u64] = &[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
    0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
    0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4a, 0x4b,
];

const SCALARS: &[(SafeAttributeKind, ScalarSet)] = &[
    (SafeAttributeKind::Class, ScalarSet::Exact(CLASS_VALUES)),
    (
        SafeAttributeKind::KeyType,
        ScalarSet::Exact(KEY_TYPE_VALUES),
    ),
    (SafeAttributeKind::Token, ScalarSet::Exact(&[0, 1])),
    (
        SafeAttributeKind::ValueLen,
        ScalarSet::Range { lo: 1, hi: 4096 },
    ),
    (
        SafeAttributeKind::ModulusBits,
        ScalarSet::Range { lo: 256, hi: 16384 },
    ),
    (SafeAttributeKind::EcParams, ScalarSet::Exact(&[])),
    // F16 (7.05 PQC) reviewed row: the CKP_* union 1..=12.
    (
        SafeAttributeKind::ParameterSet,
        ScalarSet::Exact(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
    ),
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
    // R2 new-site reviewed rows: the measured 11-byte draft-josefsson
    // Curve25519 OID plus the four RFC 8410 5-byte OIDs.
    (
        &[
            0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01,
        ],
        SafeCurve::X25519,
    ),
    (&[0x06, 0x03, 0x2b, 0x65, 0x6e], SafeCurve::X25519),
    (&[0x06, 0x03, 0x2b, 0x65, 0x6f], SafeCurve::X448),
    (&[0x06, 0x03, 0x2b, 0x65, 0x70], SafeCurve::Ed25519),
    (&[0x06, 0x03, 0x2b, 0x65, 0x71], SafeCurve::Ed448),
    // Relaxed-dialect fix1 reviewed rows: secp256k1 + brainpool
    // P-256/384r1 OIDs plus the two SoftHSM PrintableString Edwards
    // spellings (same curves as the RFC 8410 OIDs above).
    (
        &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a],
        SafeCurve::Secp256k1,
    ),
    (
        &[
            0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07,
        ],
        SafeCurve::BrainpoolP256r1,
    ),
    (
        &[
            0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b,
        ],
        SafeCurve::BrainpoolP384r1,
    ),
    (
        &[
            0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
        ],
        SafeCurve::Ed25519,
    ),
    (
        &[
            0x13, 0x0a, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x34, 0x34, 0x38,
        ],
        SafeCurve::Ed448,
    ),
];

const DERIVE: &[(u64, ScalarDeriveMechanism)] = &[
    (0x21, ScalarDeriveMechanism::DhPkcs),
    (0x393, ScalarDeriveMechanism::Sha256),
    (0x1050, ScalarDeriveMechanism::Ecdh1),
    (0x1051, ScalarDeriveMechanism::Ecdh1Cofactor),
    // R2 new-site reviewed rows: HKDF derive/data and concatenation.
    (0x402a, ScalarDeriveMechanism::HkdfDerive),
    (0x402b, ScalarDeriveMechanism::HkdfData),
    (0x360, ScalarDeriveMechanism::ConcatBaseAndKey),
    // Relaxed-dialect fix1 reviewed rows: the two remaining standard
    // concatenation variants (0x361 stays refused: unassigned).
    (0x362, ScalarDeriveMechanism::ConcatBaseAndData),
    (0x363, ScalarDeriveMechanism::ConcatDataAndBase),
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
            let expected = accepted.contains(value).then_some(value as u16);
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
    // The one attested vendor spelling normalizes to its standard
    // meaning; its neighbors and the bare vendor base stay refused.
    assert_eq!(
        classify_attribute_scalar(SafeAttributeKind::KeyType, 0xCE53_4356),
        Some(0x49),
        "CKK_NSS_ML_KEM normalizes to CKK_ML_KEM"
    );
    for refused in [
        0xCE53_4355u64,
        0xCE53_4357,
        0x8000_0000,
        0xCE53_4356 | (1 << 32),
    ] {
        assert_eq!(
            classify_attribute_scalar(SafeAttributeKind::KeyType, refused),
            None,
            "vendor key type {refused:#x} refused"
        );
    }
}

// Controller ruling fix2 (2026-11-21, NSS vendor key types): the NSS
// vendor key-type spellings (`CKK_NSS + 1..6`, NSS
// `lib/util/pkcs11n.h`) map only where a standard meaning exists —
// `CKK_NSS_CHACHA20` (0xCE53_4354) normalizes to `CKK_CHACHA20`
// (0x33), documented as a vendor-specific spelling, not a standard
// id. `CKK_NSS_ML_KEM` keeps its fix1 mapping (above); PKCS8, the
// JPAKE round keys and legacy KYBER have no standard meaning and
// stay refused with the named reason (Kyber is not ML-KEM).
#[test]
fn s2s3_nss_vendor_key_types_map_or_refuse() {
    assert_eq!(
        classify_attribute_scalar(SafeAttributeKind::KeyType, 0xCE53_4354),
        Some(0x33),
        "CKK_NSS_CHACHA20 normalizes to CKK_CHACHA20"
    );
    for refused in [
        0xCE53_4351u64, // CKK_NSS_PKCS8 (no standard meaning)
        0xCE53_4352,   // CKK_NSS_JPAKE_ROUND1 (no standard meaning)
        0xCE53_4353,   // CKK_NSS_JPAKE_ROUND2 (no standard meaning)
        0xCE53_4355,   // CKK_NSS_KYBER (Kyber is not ML-KEM)
        0xCE53_4354 | (1 << 32), // hostile-width alias of CKK_NSS_CHACHA20
    ] {
        assert_eq!(
            classify_attribute_scalar(SafeAttributeKind::KeyType, refused),
            None,
            "vendor key type {refused:#x} refused"
        );
    }
}

// Mutation caught: a key-type vocabulary drifting from the OASIS PKCS #11
// 3.2 numbers, including the pinned pkcs11-types misnumbering that puts
// Edwards/Montgomery at 0x3a/0x3b (those are BLAKE2b HMAC per OASIS and
// classify as themselves; Edwards/Montgomery stay at 0x40/0x41).
#[test]
fn s2s3_key_types_pin_oasis_numbers() {
    // F16 (7.05 PQC) reviewed values: CKK_ML_KEM/CKK_ML_DSA/CKK_SLH_DSA
    // from OASIS PKCS #11 3.2 sections 6.67.1/6.68.1/6.69.1. Fix1
    // accepts every assigned standard id; the table is the contract.
    for value in KEY_TYPE_VALUES {
        assert_eq!(
            classify_attribute_scalar(SafeAttributeKind::KeyType, *value),
            Some(*value as u16),
            "key type {value:#x}"
        );
    }
    // Reserved gaps and the first unassigned id stay refused.
    for refused in [0x06u64, 0x07, 0x0f, 0x4c, 0x4d, 0xff] {
        assert_eq!(
            classify_attribute_scalar(SafeAttributeKind::KeyType, refused),
            None,
            "key type {refused:#x} refused"
        );
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
                    SafeAttributeKind::EcParams => {
                        len == 5 || len == 7 || len == 10 || len == 11 || len == 12 || len == 14
                    }
                    // Fix1: the short 4-byte scalar encoding reads on
                    // either layout (on ILP32 it is the full word).
                    _ => len == word || len == 4,
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
        // Fix1: the longest accepted form is 14 bytes; the probe
        // buffer covers one byte past it.
        let mut buffer = [0u8; 16];
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
        for &(kind, set) in SCALARS {
            // Ranges pin their ends plus interior samples; lists pin
            // every member. High-bit variants of all refuse.
            let mut values = [0u64; 80];
            let count = match set {
                ScalarSet::Exact(list) => {
                    values[..list.len()].copy_from_slice(list);
                    list.len()
                }
                ScalarSet::Range { lo, hi } => {
                    values[..5].copy_from_slice(&[lo, hi, (lo + hi) / 2, lo + 1, hi - 1]);
                    5
                }
            };
            for value in values[..count].iter().copied() {
                assert_eq!(
                    classify_attribute_scalar(kind, value),
                    Some(value as u16),
                    "{kind:?}: {value:#x}"
                );
                assert_eq!(
                    classify_attribute_scalar(kind, value | high),
                    None,
                    "{kind:?}: {value:#x} | high"
                );
            }
            for (layout, word) in [(LinuxLayout::Lp64, 8), (LinuxLayout::Ilp32, 4)] {
                let lengths: &[u64] = match kind {
                    SafeAttributeKind::Token => &[1],
                    SafeAttributeKind::EcParams => &[5, 7, 10, 11, 12, 14],
                    _ if word == 4 => &[4],
                    _ => &[8, 4],
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
        "C_EncapsulateKey",
        Encapsulate,
        [2, N],
        [7, N],
        [(N, N), (N, N)],
        [N, N],
        NamedFunction,
    ),
    Expected(
        "C_DecapsulateKey",
        Decapsulate,
        [2, N],
        [7, N],
        [(N, N), (N, N)],
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
    assert_eq!(EXPECTED.len(), 27);
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
        "C_FindObjectsInit",
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
    assert_eq!(
        object_descriptor(function_id("C_EncapsulateKey"))
            .unwrap()
            .result_pointer_args,
        [7, N]
    );
    assert_eq!(
        object_descriptor(function_id("C_DecapsulateKey"))
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
                        || (row.0 == "C_UnwrapKey" && position == 2)
                        || (row.0 == "C_EncapsulateKey" && position == 2)
                        || (row.0 == "C_DecapsulateKey" && position == 2));
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
            Encapsulate,
            Decapsulate,
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

// Mutation caught: a KEM template-pointee authorization (T0 forbids it),
// a scalar mechanism guard on the named KEM result, or a moved argument.
#[test]
fn s2s3_kem_descriptors_are_named_scalar_result_without_templates() {
    for (name, action) in [
        ("C_EncapsulateKey", Encapsulate),
        ("C_DecapsulateKey", Decapsulate),
    ] {
        let id = function_id(name);
        let descriptor = object_descriptor(id).unwrap_or_else(|| panic!("{name} modeled"));
        assert_eq!(descriptor.action, action, "{name}");
        assert_eq!(descriptor.input_args, [2, N], "{name}");
        assert_eq!(descriptor.result_pointer_args, [7, N], "{name}");
        assert_eq!(
            descriptor.template_args,
            [(N, N), (N, N)],
            "{name}: T0 keeps template pairs absent"
        );
        assert_eq!(descriptor.find_capacity_arg, N, "{name}");
        assert_eq!(descriptor.find_count_ptr_arg, N, "{name}");
        assert_eq!(
            descriptor.result_protocol_guard, NamedFunction,
            "{name}: no new mechanism read"
        );
        // NamedFunction authorizes the nominal result slot for every
        // mechanism evidence shape, including absent evidence.
        for mechanism in [None, Some(0), Some(0x17), Some(u64::MAX)] {
            assert_eq!(
                authorized_result_pointer_args(id, mechanism),
                [7, N],
                "{name}: {mechanism:?}"
            );
        }
        // Any template authorization breaks exact descriptor validation.
        let mut templated = descriptor;
        templated.template_args = [(3, 4), (N, N)];
        assert!(!valid_object_descriptor(id, &templated), "{name}");
    }
}

// F16 (7.05 PQC) RED: the parameter-set selector classifies and the
// three PQC key types classify. Existing-API only (raw selector,
// frozen KeyType kind): compiles before GREEN, fails on the
// membership assertions. The closed-set tables gain their reviewed
// rows with GREEN.
#[test]
fn pqc_parameter_set_selector_and_key_type_scalars() {
    assert!(
        safe_attribute_kind(0x061d).is_some(),
        "CKA_PARAMETER_SET selects"
    );
    for key_type in [0x49u64, 0x4a, 0x4b] {
        assert_eq!(
            classify_attribute_scalar(SafeAttributeKind::KeyType, key_type),
            Some(key_type as u16),
            "key type {key_type:#x}"
        );
    }
}

// R2 new-site RED: Montgomery/Edwards curve encodings classify.
// Existing-API only (byte slices in, Option out): compiles before
// GREEN, fails on the membership assertions. The closed CURVES
// table gains the reviewed rows with GREEN.
#[test]
fn newsite_montgomery_edwards_curve_encodings_classify() {
    // Measured (gdb oracle, Playwright Firefox 1555, new TLS site):
    // NSS passes the draft-josefsson Curve25519 OID (11 bytes) in the
    // ephemeral X25519 keypair template.
    const X25519_DRAFT: &[u8] = &[
        0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01,
    ];
    assert!(
        classify_ec_params(X25519_DRAFT).is_some(),
        "measured X25519 params classify"
    );
    // RFC 8410 5-byte OID forms.
    for oid in [
        [0x06, 0x03, 0x2b, 0x65, 0x6e], // X25519 1.3.101.110
        [0x06, 0x03, 0x2b, 0x65, 0x6f], // X448 1.3.101.111
        [0x06, 0x03, 0x2b, 0x65, 0x70], // Ed25519 1.3.101.112
        [0x06, 0x03, 0x2b, 0x65, 0x71], // Ed448 1.3.101.113
    ] {
        assert!(
            classify_ec_params(&oid).is_some(),
            "RFC 8410 params classify: {oid:02x?}"
        );
    }
}

// R2 new-site RED: the HKDF key type and the measured HKDF/AES value
// lengths classify. Compiles before GREEN, fails on membership.
#[test]
fn newsite_hkdf_type_and_value_lens_classify() {
    assert_eq!(
        classify_attribute_scalar(SafeAttributeKind::KeyType, 0x42),
        Some(0x42),
        "CKK_HKDF classifies"
    );
    for len in [12u64, 48] {
        assert_eq!(
            classify_attribute_scalar(SafeAttributeKind::ValueLen, len),
            Some(len as u16),
            "value len {len} classifies"
        );
    }
}

// R2 new-site RED: EC parameter reads cover the 5-byte RFC 8410 and
// 11-byte draft encodings. Compiles before GREEN, fails on the
// length guards.
#[test]
fn newsite_ecparams_lengths_cover_montgomery_edwards() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        assert!(
            valid_safe_attribute_length(SafeAttributeKind::EcParams, 5, layout),
            "{layout:?}: 5-byte params read"
        );
        assert!(
            valid_safe_attribute_length(SafeAttributeKind::EcParams, 11, layout),
            "{layout:?}: 11-byte params read"
        );
    }
}

// R2 new-site RED: HKDF/concat derives authorize their scalar result
// handle. Compiles before GREEN, fails on the closed mechanism set.
#[test]
fn newsite_hkdf_derive_result_protocol_is_authorized() {
    let id = function_id("C_DeriveKey");
    for mechanism in [0x402au64, 0x402b, 0x360] {
        assert_ne!(
            derive_result_protocol(mechanism),
            DeriveResultProtocol::Unavailable,
            "mechanism {mechanism:#x} authorizes its result"
        );
        assert_eq!(
            authorized_result_pointer_args(id, Some(mechanism)),
            [5, N],
            "mechanism {mechanism:#x} retains arg 5"
        );
    }
}
