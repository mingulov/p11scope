//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! v0.8.0 keymeta inference engine (userspace only): mechanism family
//! (§4), family/established compatibility (§4.5) and length-to-size
//! classification (§5.2). Pure tables over already-captured mechanism
//! ids and length words: no reads, no retention, no I/O. Sizes and
//! classes only — never key material, payloads or PINs.
//!
//! § references are to
//! `docs/superpowers/specs/2026-11-14-v080-keymeta-design.md`.

use p11scope_ebpf_common::object_policy::SafeCurve;

use crate::semantics_objects::KeyLabel;

/// Inferred key family: the §4.2 finite vocabulary (schema order).
/// Explicit discriminants back the further-value bitmask (21
/// families fit a u32).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub(crate) enum KeyFamily {
    Rsa = 0,
    Ec = 1,
    Eddsa = 2,
    Xeddsa = 3,
    Secret = 4,
    Dsa = 5,
    Dh = 6,
    Aes = 7,
    GenericSecret = 8,
    Hkdf = 9,
    MlKem = 10,
    MlDsa = 11,
    SlhDsa = 12,
    Chacha20 = 13,
    Poly1305 = 14,
    Des = 15,
    Des3 = 16,
    Camellia = 17,
    Aria = 18,
    Seed = 19,
    Gost = 20,
}

/// Per-family §4.2 id tables (sorted, for binary search). Generated
/// from the reviewed name assignment; the catalog coverage test pins
/// every id against `mechanism_names` plus the full universe.
const RSA_IDS: &[u64] = &[
    0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000005, 0x00000006, 0x00000007, 0x00000008,
    0x00000009, 0x0000000b, 0x0000000c, 0x0000000d, 0x0000000e, 0x00000040, 0x00000041, 0x00000042,
    0x00000043, 0x00000044, 0x00000045, 0x00000046, 0x00000047, 0x00000060, 0x00000061, 0x00000062,
    0x00000063, 0x00000064, 0x00000065, 0x00000066, 0x00000067, 0x00001054, 0x00004001, 0x00004002,
];
const EC_IDS: &[u64] = &[
    0x00001041, 0x00001042, 0x00001043, 0x00001044, 0x00001045, 0x00001046, 0x00001047, 0x00001048,
    0x00001049, 0x0000104a, 0x00001050, 0x00001051, 0x00001052, 0x00001053, 0x00004038, 0x00004039,
];
const EDDSA_IDS: &[u64] = &[0x00001057];
const XEDDSA_IDS: &[u64] = &[0x00004029];
const SECRET_IDS: &[u64] = &[
    0x0000004b, 0x0000004f, 0x00000053, 0x00000056, 0x00000057, 0x00000360, 0x00000362, 0x00000363,
    0x00000364, 0x00000365, 0x00000371, 0x00000372, 0x00000373, 0x00000375, 0x00000376, 0x00000377,
    0x00000378, 0x00000390, 0x00000391, 0x00000392, 0x00000393, 0x00000394, 0x00000395, 0x00000396,
    0x00000397, 0x00000398, 0x00000399, 0x0000039a, 0x0000039b, 0x0000039c, 0x000003ac, 0x000003ad,
    0x000003ae, 0x000003d1, 0x000003d2, 0x000003d3, 0x000003d4, 0x000003d5, 0x000003d9, 0x000003e0,
    0x000003e1, 0x000003e2, 0x000003e3, 0x000003e5, 0x00000510, 0x00000511, 0x00000512, 0x0000402e,
    0x0000402f, 0x00004030, 0x00004031,
];
const DSA_IDS: &[u64] = &[
    0x00000011, 0x00000012, 0x00000013, 0x00000014, 0x00000015, 0x00000016, 0x00000018, 0x00000019,
    0x0000001a, 0x0000001b,
];
const DH_IDS: &[u64] = &[
    0x00000021, 0x00000031, 0x00000032, 0x00000033, 0x00001011, 0x00001012,
];
const AES_IDS: &[u64] = &[
    0x00001071, 0x00001081, 0x00001082, 0x00001083, 0x00001084, 0x00001085, 0x00001086, 0x00001087,
    0x00001088, 0x00001089, 0x0000108a, 0x0000108b, 0x0000108c, 0x0000108d, 0x0000108e, 0x00001104,
    0x00001105, 0x00002104, 0x00002105, 0x00002106, 0x00002107, 0x00002108, 0x00002109, 0x0000210a,
    0x0000210b, 0x0000210c,
];
const GENERIC_SECRET_IDS: &[u64] = &[
    0x00000049, 0x0000004a, 0x0000004d, 0x0000004e, 0x00000051, 0x00000052, 0x00000201, 0x00000202,
    0x00000211, 0x00000212, 0x00000221, 0x00000222, 0x00000231, 0x00000232, 0x00000241, 0x00000242,
    0x00000251, 0x00000252, 0x00000256, 0x00000257, 0x00000261, 0x00000262, 0x00000271, 0x00000272,
    0x00000291, 0x000002b1, 0x000002b2, 0x000002b6, 0x000002b7, 0x000002c1, 0x000002c2, 0x000002d1,
    0x000002d2, 0x00001211, 0x0000400d, 0x0000400e, 0x00004012, 0x00004013, 0x00004017, 0x00004018,
    0x0000401c, 0x0000401d,
];
const HKDF_IDS: &[u64] = &[0x0000402a, 0x0000402b];
const ML_KEM_IDS: &[u64] = &[0x00000017];
const ML_DSA_IDS: &[u64] = &[
    0x0000001d, 0x0000001f, 0x00000023, 0x00000024, 0x00000025, 0x00000026, 0x00000027, 0x00000028,
    0x00000029, 0x0000002a, 0x0000002b, 0x0000002c,
];
const SLH_DSA_IDS: &[u64] = &[
    0x0000002e, 0x00000034, 0x00000036, 0x00000037, 0x00000038, 0x00000039, 0x0000003a, 0x0000003b,
    0x0000003c, 0x0000003d, 0x0000003e, 0x0000003f,
];
const CHACHA20_IDS: &[u64] = &[0x00001226, 0x00004021];
const POLY1305_IDS: &[u64] = &[0x00001228];
const DES_IDS: &[u64] = &[
    0x00000121, 0x00000122, 0x00000123, 0x00000124, 0x00000125, 0x00000150, 0x00000151, 0x00000152,
    0x00000153, 0x00001100, 0x00001101,
];
const DES3_IDS: &[u64] = &[
    0x00000132, 0x00000133, 0x00000134, 0x00000135, 0x00000136, 0x00000137, 0x00000138, 0x00001102,
    0x00001103,
];
const CAMELLIA_IDS: &[u64] = &[
    0x00000551, 0x00000552, 0x00000553, 0x00000554, 0x00000555, 0x00000556, 0x00000557, 0x00000558,
];
const ARIA_IDS: &[u64] = &[
    0x00000561, 0x00000562, 0x00000563, 0x00000564, 0x00000565, 0x00000566, 0x00000567,
];
const SEED_IDS: &[u64] = &[
    0x00000651, 0x00000652, 0x00000653, 0x00000654, 0x00000655, 0x00000656, 0x00000657,
];
const GOST_IDS: &[u64] = &[0x00001221, 0x00001222, 0x00001223, 0x00001224];

/// §5.2 mechanism subsets: the ECDSA sign/verify ids (ECDSA plus the
/// nine hash variants).
const ECDSA_IDS: &[u64] = &[
    0x00001041, 0x00001042, 0x00001043, 0x00001044, 0x00001045, 0x00001046, 0x00001047, 0x00001048,
    0x00001049, 0x0000104a,
];
/// §5.2 ECDH1-family subset (family-only): derive plus wrap ids,
/// ECMQV included.
const ECDH1_FAMILY_IDS: &[u64] = &[
    0x00001050, 0x00001051, 0x00001052, 0x00001053, 0x00004038, 0x00004039,
];
/// §4.5 ECDH1 qualifier (Montgomery compatibility): ECMQV excluded.
const ECDH1_QUALIFIED_IDS: &[u64] = &[0x00001050, 0x00001051, 0x00001053, 0x00004038, 0x00004039];
const RSA_AES_KEY_WRAP_ID: u64 = 0x00001054;
const AES_XTS_ID: u64 = 0x00001071;
pub(crate) const AES_KW_ID: u64 = 0x00002109;

/// Whether one mechanism id is in the AES-KW family (plain wrap plus
/// the padded variants): their wrap/unwrap lengths concern the
/// wrapped key or fresh view, never the operation key.
pub(crate) fn is_aes_kw_family(mechanism: u64) -> bool {
    matches!(
        mechanism,
        x if x == AES_KW_ID || x == AES_KW_PAD_ID || x == AES_KW_KWP_ID || x == AES_KW_PKCS7_ID
    )
}
const AES_KW_PAD_ID: u64 = 0x0000210a;
const AES_KW_KWP_ID: u64 = 0x0000210b;
const AES_KW_PKCS7_ID: u64 = 0x0000210c;

/// Infer the §4.2 family for one mechanism id, or `None` when the id
/// infers nothing (unlisted, vendor, keygen/parameter-gen, CMS_SIG,
/// PBKD2, PBA, or an unobserved legacy id). Full-width equality:
/// hostile-width aliases never match.
pub(crate) fn infer_family(mechanism: u64) -> Option<KeyFamily> {
    // Spec order; each table is sorted for binary search.
    if RSA_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::Rsa);
    }
    if EC_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::Ec);
    }
    if EDDSA_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::Eddsa);
    }
    if XEDDSA_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::Xeddsa);
    }
    if SECRET_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::Secret);
    }
    if DSA_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::Dsa);
    }
    if DH_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::Dh);
    }
    if AES_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::Aes);
    }
    if GENERIC_SECRET_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::GenericSecret);
    }
    if HKDF_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::Hkdf);
    }
    if ML_KEM_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::MlKem);
    }
    if ML_DSA_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::MlDsa);
    }
    if SLH_DSA_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::SlhDsa);
    }
    if CHACHA20_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::Chacha20);
    }
    if POLY1305_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::Poly1305);
    }
    if DES_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::Des);
    }
    if DES3_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::Des3);
    }
    if CAMELLIA_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::Camellia);
    }
    if ARIA_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::Aria);
    }
    if SEED_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::Seed);
    }
    if GOST_IDS.binary_search(&mechanism).is_ok() {
        return Some(KeyFamily::Gost);
    }
    None
}

/// The §10.2 schema spelling of one family.
pub(crate) fn family_value(family: KeyFamily) -> &'static str {
    match family {
        KeyFamily::Rsa => "rsa",
        KeyFamily::Ec => "ec",
        KeyFamily::Eddsa => "eddsa",
        KeyFamily::Xeddsa => "xeddsa",
        KeyFamily::Secret => "secret",
        KeyFamily::Dsa => "dsa",
        KeyFamily::Dh => "dh",
        KeyFamily::Aes => "aes",
        KeyFamily::GenericSecret => "generic_secret",
        KeyFamily::Hkdf => "hkdf",
        KeyFamily::MlKem => "ml_kem",
        KeyFamily::MlDsa => "ml_dsa",
        KeyFamily::SlhDsa => "slh_dsa",
        KeyFamily::Chacha20 => "chacha20",
        KeyFamily::Poly1305 => "poly1305",
        KeyFamily::Des => "des",
        KeyFamily::Des3 => "des3",
        KeyFamily::Camellia => "camellia",
        KeyFamily::Aria => "aria",
        KeyFamily::Seed => "seed",
        KeyFamily::Gost => "gost",
    }
}

/// The `-v`/concise display spelling of one family.
pub(crate) fn family_display(family: KeyFamily) -> &'static str {
    match family {
        KeyFamily::Rsa => "RSA",
        KeyFamily::Ec => "EC",
        KeyFamily::Eddsa => "EdDSA",
        KeyFamily::Xeddsa => "XEdDSA",
        KeyFamily::Secret => "secret-key",
        KeyFamily::Dsa => "DSA",
        KeyFamily::Dh => "DH",
        KeyFamily::Aes => "AES",
        KeyFamily::GenericSecret => "generic-secret",
        KeyFamily::Hkdf => "HKDF",
        KeyFamily::MlKem => "ML-KEM",
        KeyFamily::MlDsa => "ML-DSA",
        KeyFamily::SlhDsa => "SLH-DSA",
        KeyFamily::Chacha20 => "ChaCha20",
        KeyFamily::Poly1305 => "Poly1305",
        KeyFamily::Des => "DES",
        KeyFamily::Des3 => "DES3",
        KeyFamily::Camellia => "Camellia",
        KeyFamily::Aria => "Aria",
        KeyFamily::Seed => "SEED",
        KeyFamily::Gost => "GOST",
    }
}

/// Named size/family unknown reasons (owner rule: every unknown is a
/// named counted reason). JSON carries statuses; `-v` text carries
/// these reasons via [`reason_display`].
pub(crate) const REASON_UNLISTED_MECHANISM: &str = "unlisted_mechanism";
pub(crate) const REASON_OPERATION_KEY_ONLY: &str = "operation_key_only";
pub(crate) const REASON_SIZE_INFERENCE_OFF: &str = "size_inference_off";
pub(crate) const REASON_NO_LENGTH_EVIDENCE: &str = "no_length_evidence";
pub(crate) const REASON_LENGTH_UNAVAILABLE: &str = "length_unavailable";
pub(crate) const REASON_HYBRID_WRAP_FORMAT: &str = "hybrid_wrap_format";
pub(crate) const REASON_VARIABLE_LENGTH_ENCODING: &str = "variable_length_encoding";
pub(crate) const REASON_PADDING_AMBIGUITY: &str = "padding_ambiguity";
pub(crate) const REASON_UNMAPPED_LENGTH: &str = "unmapped_length";
pub(crate) const REASON_NO_LENGTH_MAP: &str = "no_length_map";
pub(crate) const REASON_FAMILY_ONLY_SUBSET: &str = "family_only_subset";
pub(crate) const REASON_OUTSIDE_ADMISSION_BOUND: &str = "outside_admission_bound";

/// The `-v` display phrase for one unknown reason (explicit phrases,
/// never mechanical joins: `variable_length_encoding` reads
/// "variable-length encoding").
pub(crate) fn reason_display(reason: &str) -> &'static str {
    match reason {
        REASON_UNLISTED_MECHANISM => "unlisted mechanism",
        REASON_OPERATION_KEY_ONLY => "mechanism types the operation key",
        REASON_SIZE_INFERENCE_OFF => "needs --key-sizes",
        REASON_NO_LENGTH_EVIDENCE => "no length evidence",
        REASON_LENGTH_UNAVAILABLE => "length unavailable",
        REASON_HYBRID_WRAP_FORMAT => "hybrid wrap format",
        REASON_VARIABLE_LENGTH_ENCODING => "variable-length encoding",
        REASON_PADDING_AMBIGUITY => "padding ambiguity",
        REASON_UNMAPPED_LENGTH => "unmapped length",
        REASON_NO_LENGTH_MAP => "no length map for this mechanism",
        REASON_FAMILY_ONLY_SUBSET => "family-only mechanism",
        REASON_OUTSIDE_ADMISSION_BOUND => "outside admission bound",
        _ => "unknown reason",
    }
}

/// The receipt's frozen established key type (§4.5 left side), from
/// its [`KeyLabel`]. Variants past [`EstablishedKind::SlhDsa`] are
/// unreachable through today's labels (no label covers them) but
/// complete the §4.5 table; a receipt without one skips the
/// comparison and the inference stands alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Tail variants: reserved vocabulary for labels not yet mapped.
pub(crate) enum EstablishedKind {
    Rsa { bits: u16 },
    Aes { bytes: u16 },
    Ec { curve: SafeCurve },
    Montgomery,
    Edwards { curve: SafeCurve },
    GenericSecret { bytes: u16 },
    Hkdf { bytes: u16 },
    MlKem { set: &'static str },
    MlDsa { set: &'static str },
    SlhDsa { set: &'static str },
    Dsa,
    Dh,
    X9_42Dh,
    AesXts,
    Des,
    Des2,
    Des3,
    Camellia,
    Aria,
    Seed,
    Gost,
    Chacha20,
    Poly1305,
}

/// Map one established [`KeyLabel`] to its §4.5 kind. PQC codes map
/// to their parameter-set spellings (the §10.2 `parameter_set`
/// vocabulary); Montgomery/Edwards curves split by name.
pub(crate) fn established_kind(label: KeyLabel) -> EstablishedKind {
    use crate::semantics_objects::PqcCode;
    match label {
        KeyLabel::Rsa { modulus_bits } => EstablishedKind::Rsa { bits: modulus_bits },
        KeyLabel::Aes { value_len } => EstablishedKind::Aes { bytes: value_len },
        KeyLabel::Ec { curve } => match curve {
            SafeCurve::X25519 | SafeCurve::X448 => EstablishedKind::Montgomery,
            SafeCurve::Ed25519 | SafeCurve::Ed448 => EstablishedKind::Edwards { curve },
            curve => EstablishedKind::Ec { curve },
        },
        KeyLabel::Hkdf { value_len } => EstablishedKind::Hkdf { bytes: value_len },
        KeyLabel::GenericSecret { value_len } => {
            EstablishedKind::GenericSecret { bytes: value_len }
        }
        KeyLabel::Pqc(code) => match code {
            PqcCode::MlKem512 => EstablishedKind::MlKem { set: "ml_kem_512" },
            PqcCode::MlKem768 => EstablishedKind::MlKem { set: "ml_kem_768" },
            PqcCode::MlKem1024 => EstablishedKind::MlKem { set: "ml_kem_1024" },
            PqcCode::MlDsa44 => EstablishedKind::MlDsa { set: "ml_dsa_44" },
            PqcCode::MlDsa65 => EstablishedKind::MlDsa { set: "ml_dsa_65" },
            PqcCode::MlDsa87 => EstablishedKind::MlDsa { set: "ml_dsa_87" },
            PqcCode::SlhDsaSha2128s | PqcCode::SlhDsaShake128s => EstablishedKind::SlhDsa {
                set: "slh_dsa_128s",
            },
            PqcCode::SlhDsaSha2128f | PqcCode::SlhDsaShake128f => EstablishedKind::SlhDsa {
                set: "slh_dsa_128f",
            },
            PqcCode::SlhDsaSha2192s | PqcCode::SlhDsaShake192s => EstablishedKind::SlhDsa {
                set: "slh_dsa_192s",
            },
            PqcCode::SlhDsaSha2192f | PqcCode::SlhDsaShake192f => EstablishedKind::SlhDsa {
                set: "slh_dsa_192f",
            },
            PqcCode::SlhDsaSha2256s | PqcCode::SlhDsaShake256s => EstablishedKind::SlhDsa {
                set: "slh_dsa_256s",
            },
            PqcCode::SlhDsaSha2256f | PqcCode::SlhDsaShake256f => EstablishedKind::SlhDsa {
                set: "slh_dsa_256f",
            },
        },
    }
}

/// Whether one inferred family is compatible with one established
/// kind under the §4.5 table (`mechanism` carries the ECDH1/XTS
/// qualifiers). Everything cross-name outside the table conflicts.
pub(crate) fn families_compatible(
    inferred: KeyFamily,
    mechanism: u64,
    established: EstablishedKind,
) -> bool {
    use EstablishedKind as E;
    use KeyFamily as F;
    // The secret superclass never flips, either direction, against
    // any inferred family or established kind.
    if inferred == F::Secret {
        return true;
    }
    match (inferred, established) {
        (F::Rsa, E::Rsa { .. }) => true,
        (F::Ec, E::Ec { .. }) => true,
        // The Firefox X25519/X448 derive case: ECDH1-qualified only
        // (ECMQV and ECDSA uses stay conflicting).
        (F::Ec, E::Montgomery) => ECDH1_QUALIFIED_IDS.binary_search(&mechanism).is_ok(),
        (F::Eddsa, E::Edwards { .. }) => true,
        (F::Xeddsa, E::Montgomery) => true,
        (F::Dsa, E::Dsa) => true,
        (F::Dh, E::Dh | E::X9_42Dh) => true,
        (F::Aes, E::Aes { .. }) => true,
        (F::Aes, E::AesXts) => mechanism == AES_XTS_ID,
        (F::GenericSecret, E::GenericSecret { .. } | E::Hkdf { .. }) => true,
        // The Firefox TLS 1.3 case: ECDH results established as
        // generic secret, then HKDF.
        (F::Hkdf, E::Hkdf { .. } | E::GenericSecret { .. }) => true,
        // Inert while both stay unlisted in the KeyType set.
        (F::Des3, E::Des3 | E::Des2) => true,
        (F::MlKem, E::MlKem { .. }) => true,
        (F::MlDsa, E::MlDsa { .. }) => true,
        (F::SlhDsa, E::SlhDsa { .. }) => true,
        (F::Chacha20, E::Chacha20) => true,
        (F::Poly1305, E::Poly1305) => true,
        (F::Des, E::Des) => true,
        (F::Camellia, E::Camellia) => true,
        (F::Aria, E::Aria) => true,
        (F::Seed, E::Seed) => true,
        (F::Gost, E::Gost) => true,
        // Everything else cross-name conflicts.
        _ => false,
    }
}

/// Whether one inferred size is compatible with one established kind
/// (§3: a contradicting size conflicts beside the standing label).
/// Family compatibility comes first (same §4.5 table, mechanism
/// qualified); same-family pairs then compare exact size params
/// (RSA bytes, EC field octets, Edwards curves, PQC sets, exact
/// secret lengths for wrapped material). Demonstrable contradiction
/// only — anything unmeasurable stays compatible.
pub(crate) fn size_compatible(
    detail: &SizeDetail,
    mechanism: u64,
    established: EstablishedKind,
) -> bool {
    use EstablishedKind as E;
    // Wrapped material sizes without typing: only an exact secret
    // length can contradict it; every other kind is unmeasurable.
    if let SizeDetail::WrappedMaterial {
        material_octets, ..
    } = detail
    {
        return match established {
            E::Aes { bytes } | E::GenericSecret { bytes } | E::Hkdf { bytes } => {
                u64::from(bytes) == *material_octets
            }
            _ => true,
        };
    }
    // Family gate first (same table, mechanism qualified).
    let Some(family) = size_family(detail) else {
        return true;
    };
    if !families_compatible(family, mechanism, established) {
        return false;
    }
    // Same-family exact params.
    match (detail, established) {
        (SizeDetail::Rsa { modulus_bytes, .. }, E::Rsa { bits }) => {
            *modulus_bytes == u64::from(bits).div_ceil(8)
        }
        (SizeDetail::Ec { octets, .. }, E::Ec { curve }) => {
            let field = match curve {
                SafeCurve::Secp256r1 => 32,
                SafeCurve::Secp384r1 => 48,
                SafeCurve::Secp521r1 => 66,
                // Montgomery/Edwards curves never reach here: the
                // family gate above already refused them for ECDSA
                // mechanisms (only ECDH1 qualifies, and derive calls
                // carry no lengths).
                _ => return true,
            };
            *octets == 2 * field
        }
        (SizeDetail::Eddsa { curve, .. }, E::Edwards { curve: established }) => {
            *curve == edwards_curve_name(established)
        }
        (
            SizeDetail::PqcSet { parameter_set, .. },
            E::MlKem { set } | E::MlDsa { set } | E::SlhDsa { set },
        ) => *parameter_set == set,
        // DSA classes, unit kinds and cross-kind survivors of the
        // family gate carry no further params to contradict.
        _ => true,
    }
}

/// The §10.2 curve spelling for one Edwards curve.
fn edwards_curve_name(curve: SafeCurve) -> &'static str {
    match curve {
        SafeCurve::Ed25519 => "ed25519",
        SafeCurve::Ed448 => "ed448",
        _ => "?",
    }
}

/// Length evidence kind: the §10.2 `detail.evidence` vocabulary, one
/// per §8.1 length position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceTag {
    SignOutput,
    VerifyInput,
    EncryptOutput,
    DecryptInput,
    WrapOutput,
    UnwrapInput,
    EncapsulateOutput,
    DecapsulateInput,
}

/// The evidence kind for one operation category, or `None` when the
/// category carries no §5.1 position (derive, message, generate,
/// verify_recover, ...). `sign_recover` reads `SignOutput`: the RSA
/// single-block output is signature evidence.
pub(crate) fn evidence_tag_for_category(category: &str) -> Option<EvidenceTag> {
    match category {
        "sign" | "sign_recover" => Some(EvidenceTag::SignOutput),
        "verify" => Some(EvidenceTag::VerifyInput),
        "encrypt" => Some(EvidenceTag::EncryptOutput),
        "decrypt" => Some(EvidenceTag::DecryptInput),
        "wrap" => Some(EvidenceTag::WrapOutput),
        "unwrap" => Some(EvidenceTag::UnwrapInput),
        "encapsulate" => Some(EvidenceTag::EncapsulateOutput),
        "decapsulate" => Some(EvidenceTag::DecapsulateInput),
        _ => None,
    }
}

/// The §10.2 schema spelling of one evidence kind.
pub(crate) fn evidence_value(tag: EvidenceTag) -> &'static str {
    match tag {
        EvidenceTag::SignOutput => "sign_output",
        EvidenceTag::VerifyInput => "verify_input",
        EvidenceTag::EncryptOutput => "encrypt_output",
        EvidenceTag::DecryptInput => "decrypt_input",
        EvidenceTag::WrapOutput => "wrap_output",
        EvidenceTag::UnwrapInput => "unwrap_input",
        EvidenceTag::EncapsulateOutput => "encapsulate_output",
        EvidenceTag::DecapsulateInput => "decapsulate_input",
    }
}

/// The `-v` noun for one evidence kind (§10.3).
pub(crate) fn evidence_noun(tag: EvidenceTag) -> &'static str {
    match tag {
        EvidenceTag::SignOutput | EvidenceTag::VerifyInput => "signature",
        EvidenceTag::EncryptOutput
        | EvidenceTag::DecryptInput
        | EvidenceTag::EncapsulateOutput
        | EvidenceTag::DecapsulateInput => "ciphertext",
        EvidenceTag::WrapOutput => "wrap output",
        EvidenceTag::UnwrapInput => "unwrap input",
    }
}

/// One call's admitted length outcome: a classified-candidate value
/// or a BPF-unavailable trailer (refused shapes retain zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LengthOutcome {
    Value(u64),
    Unavailable,
}

/// Per-replay completion evidence from the seal (never reconstructed
/// from S1 shape): the settled call's length trailer outcome plus,
/// for result-creating directs, the exact-one fresh view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct CompletionEvidence {
    pub length: Option<LengthOutcome>,
    pub fresh_view: Option<u64>,
}

impl CompletionEvidence {
    pub(crate) const NONE: Self = Self {
        length: None,
        fresh_view: None,
    };
}

/// One classified size (§10.2 `detail` shapes, without the kind tag
/// and evidence tag the renderer adds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SizeDetail {
    Rsa {
        size_class: Option<u16>,
        modulus_bytes: u64,
    },
    Ec {
        curve: &'static str,
        octets: u64,
    },
    Eddsa {
        curve: &'static str,
        octets: u64,
    },
    DsaClass {
        label: &'static str,
        octets: u64,
    },
    PqcSet {
        parameter_set: &'static str,
        octets: u64,
    },
    WrappedMaterial {
        material_octets: u64,
        octets: u64,
    },
}

/// One §5.2 triple outcome: a classified size, an unknown with its
/// named reason, or an unsupported subset with its named reason. A
/// length alone never maps and a family alone neither: every map
/// entry keys on (mechanism subset, evidence kind, length).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SizeOutcome {
    Inferred(SizeDetail),
    Unknown { reason: &'static str },
    Unsupported { reason: &'static str },
}

/// Classify one (mechanism, evidence kind, length) triple per §5.2.
/// `None` mechanism (no usable id) classifies unknown with the
/// unlisted-mechanism reason: a length alone never maps.
pub(crate) fn classify_size(mechanism: Option<u64>, tag: EvidenceTag, length: u64) -> SizeOutcome {
    let Some(mechanism) = mechanism else {
        // A length alone never maps.
        return SizeOutcome::Unknown {
            reason: REASON_UNLISTED_MECHANISM,
        };
    };
    // The hybrid wrap sizes neither key (family-only §5.2 row).
    if mechanism == RSA_AES_KEY_WRAP_ID {
        return SizeOutcome::Unknown {
            reason: REASON_HYBRID_WRAP_FORMAT,
        };
    }
    if RSA_IDS.binary_search(&mechanism).is_ok() {
        return classify_rsa(tag, length);
    }
    if ECDSA_IDS.binary_search(&mechanism).is_ok() {
        return classify_ecdsa(tag, length);
    }
    if ECDH1_FAMILY_IDS.binary_search(&mechanism).is_ok() {
        return SizeOutcome::Unsupported {
            reason: REASON_FAMILY_ONLY_SUBSET,
        };
    }
    if EDDSA_IDS.binary_search(&mechanism).is_ok() {
        return classify_eddsa(tag, length);
    }
    if XEDDSA_IDS.binary_search(&mechanism).is_ok() {
        // A 64-octet XEdDSA signature would alias Ed25519: family
        // only, and the §12.1 twin pins unknown (not unsupported).
        return SizeOutcome::Unknown {
            reason: REASON_FAMILY_ONLY_SUBSET,
        };
    }
    if ML_KEM_IDS.binary_search(&mechanism).is_ok() {
        return classify_ml_kem(tag, length);
    }
    if ML_DSA_IDS.binary_search(&mechanism).is_ok() {
        return classify_ml_dsa(tag, length);
    }
    if SLH_DSA_IDS.binary_search(&mechanism).is_ok() {
        return classify_slh_dsa(tag, length);
    }
    if DSA_IDS.binary_search(&mechanism).is_ok() {
        return classify_dsa(tag, length);
    }
    if mechanism == AES_KW_ID {
        return classify_aes_kw(tag, length);
    }
    if mechanism == AES_KW_PAD_ID || mechanism == AES_KW_KWP_ID || mechanism == AES_KW_PKCS7_ID {
        return match tag {
            EvidenceTag::WrapOutput | EvidenceTag::UnwrapInput => SizeOutcome::Unknown {
                reason: REASON_PADDING_AMBIGUITY,
            },
            _ => SizeOutcome::Unknown {
                reason: REASON_NO_LENGTH_MAP,
            },
        };
    }
    // Legacy ciphers sign/encrypt use into a display family with no
    // size class.
    if DES_IDS.binary_search(&mechanism).is_ok()
        || DES3_IDS.binary_search(&mechanism).is_ok()
        || CAMELLIA_IDS.binary_search(&mechanism).is_ok()
        || ARIA_IDS.binary_search(&mechanism).is_ok()
        || SEED_IDS.binary_search(&mechanism).is_ok()
        || GOST_IDS.binary_search(&mechanism).is_ok()
    {
        return SizeOutcome::Unsupported {
            reason: REASON_NO_LENGTH_MAP,
        };
    }
    // Every other triple: unlisted mechanisms name the mechanism gap,
    // listed ones without a map name the subset gap — never a
    // neighboring class.
    SizeOutcome::Unknown {
        reason: if infer_family(mechanism).is_none() {
            REASON_UNLISTED_MECHANISM
        } else {
            REASON_NO_LENGTH_MAP
        },
    }
}

/// RSA-subset lengths (§5.2): standard octets name the standard size
/// with the byte count beside them; other admitted octets mask the
/// class; anything outside the anti-alias bound is unsupported.
fn classify_rsa(tag: EvidenceTag, length: u64) -> SizeOutcome {
    match tag {
        EvidenceTag::SignOutput
        | EvidenceTag::VerifyInput
        | EvidenceTag::EncryptOutput
        | EvidenceTag::DecryptInput
        | EvidenceTag::WrapOutput
        | EvidenceTag::UnwrapInput => {}
        _ => {
            return SizeOutcome::Unknown {
                reason: REASON_NO_LENGTH_MAP,
            };
        }
    }
    let size_class = match length {
        128 => Some(1024),
        256 => Some(2048),
        384 => Some(3072),
        512 => Some(4096),
        64..=2048 => None,
        _ => {
            return SizeOutcome::Unsupported {
                reason: REASON_OUTSIDE_ADMISSION_BOUND,
            };
        }
    };
    SizeOutcome::Inferred(SizeDetail::Rsa {
        size_class,
        modulus_bytes: length,
    })
}

/// ECDSA raw r||s lengths name curves; anything else is DER or another
/// curve (N6: the PKCS#11 result representation is what was measured).
fn classify_ecdsa(tag: EvidenceTag, length: u64) -> SizeOutcome {
    match tag {
        EvidenceTag::SignOutput | EvidenceTag::VerifyInput => {}
        _ => {
            return SizeOutcome::Unknown {
                reason: REASON_NO_LENGTH_MAP,
            };
        }
    }
    let curve = match length {
        64 => "p256",
        96 => "p384",
        132 => "p521",
        _ => {
            return SizeOutcome::Unknown {
                reason: REASON_VARIABLE_LENGTH_ENCODING,
            };
        }
    };
    SizeOutcome::Inferred(SizeDetail::Ec {
        curve,
        octets: length,
    })
}

/// EdDSA fixed lengths determine the curve (RFC 8032: the mechanism
/// carries no curve parameter).
fn classify_eddsa(tag: EvidenceTag, length: u64) -> SizeOutcome {
    match tag {
        EvidenceTag::SignOutput | EvidenceTag::VerifyInput => {}
        _ => {
            return SizeOutcome::Unknown {
                reason: REASON_NO_LENGTH_MAP,
            };
        }
    }
    let curve = match length {
        64 => "ed25519",
        114 => "ed448",
        _ => {
            return SizeOutcome::Unknown {
                reason: REASON_UNMAPPED_LENGTH,
            };
        }
    };
    SizeOutcome::Inferred(SizeDetail::Eddsa {
        curve,
        octets: length,
    })
}

/// ML-KEM ciphertext lengths (FIPS 203 Table 2).
fn classify_ml_kem(tag: EvidenceTag, length: u64) -> SizeOutcome {
    match tag {
        EvidenceTag::EncapsulateOutput | EvidenceTag::DecapsulateInput => {}
        _ => {
            return SizeOutcome::Unknown {
                reason: REASON_NO_LENGTH_MAP,
            };
        }
    }
    let parameter_set = match length {
        768 => "ml_kem_512",
        1088 => "ml_kem_768",
        1568 => "ml_kem_1024",
        _ => {
            return SizeOutcome::Unknown {
                reason: REASON_UNMAPPED_LENGTH,
            };
        }
    };
    SizeOutcome::Inferred(SizeDetail::PqcSet {
        parameter_set,
        octets: length,
    })
}

/// ML-DSA signature lengths (FIPS 204 Table 2).
fn classify_ml_dsa(tag: EvidenceTag, length: u64) -> SizeOutcome {
    match tag {
        EvidenceTag::SignOutput | EvidenceTag::VerifyInput => {}
        _ => {
            return SizeOutcome::Unknown {
                reason: REASON_NO_LENGTH_MAP,
            };
        }
    }
    let parameter_set = match length {
        2420 => "ml_dsa_44",
        3309 => "ml_dsa_65",
        4627 => "ml_dsa_87",
        _ => {
            return SizeOutcome::Unknown {
                reason: REASON_UNMAPPED_LENGTH,
            };
        }
    };
    SizeOutcome::Inferred(SizeDetail::PqcSet {
        parameter_set,
        octets: length,
    })
}

/// SLH-DSA signature lengths (FIPS 205 Table 2); SHA2-vs-SHAKE stays
/// ambiguous on shared sizes and is said so in text.
fn classify_slh_dsa(tag: EvidenceTag, length: u64) -> SizeOutcome {
    match tag {
        EvidenceTag::SignOutput | EvidenceTag::VerifyInput => {}
        _ => {
            return SizeOutcome::Unknown {
                reason: REASON_NO_LENGTH_MAP,
            };
        }
    }
    let parameter_set = match length {
        7856 => "slh_dsa_128s",
        17088 => "slh_dsa_128f",
        16224 => "slh_dsa_192s",
        35664 => "slh_dsa_192f",
        29792 => "slh_dsa_256s",
        49856 => "slh_dsa_256f",
        _ => {
            return SizeOutcome::Unknown {
                reason: REASON_UNMAPPED_LENGTH,
            };
        }
    };
    SizeOutcome::Inferred(SizeDetail::PqcSet {
        parameter_set,
        octets: length,
    })
}

/// DSA legacy classes (ambiguous classes said so).
fn classify_dsa(tag: EvidenceTag, length: u64) -> SizeOutcome {
    match tag {
        EvidenceTag::SignOutput | EvidenceTag::VerifyInput => {}
        _ => {
            return SizeOutcome::Unknown {
                reason: REASON_NO_LENGTH_MAP,
            };
        }
    }
    let label = match length {
        40 => "dsa_1024",
        56 => "dsa_2048_224",
        64 => "dsa_2048_256_or_3072",
        _ => {
            return SizeOutcome::Unknown {
                reason: REASON_UNMAPPED_LENGTH,
            };
        }
    };
    SizeOutcome::Inferred(SizeDetail::DsaClass {
        label,
        octets: length,
    })
}

/// AES-KW output/input lengths size the wrapped key's material
/// (L-8); outputs under 8 octets cannot map.
fn classify_aes_kw(tag: EvidenceTag, length: u64) -> SizeOutcome {
    match tag {
        EvidenceTag::WrapOutput | EvidenceTag::UnwrapInput => {}
        _ => {
            return SizeOutcome::Unknown {
                reason: REASON_NO_LENGTH_MAP,
            };
        }
    }
    let Some(material_octets) = length.checked_sub(8) else {
        return SizeOutcome::Unknown {
            reason: REASON_UNMAPPED_LENGTH,
        };
    };
    SizeOutcome::Inferred(SizeDetail::WrappedMaterial {
        material_octets,
        octets: length,
    })
}

/// The implied family of one size detail, or `None` for wrapped
/// material (which sizes the wrapped key without typing it).
pub(crate) fn size_family(detail: &SizeDetail) -> Option<KeyFamily> {
    match detail {
        SizeDetail::Rsa { .. } => Some(KeyFamily::Rsa),
        SizeDetail::Ec { .. } => Some(KeyFamily::Ec),
        SizeDetail::Eddsa { .. } => Some(KeyFamily::Eddsa),
        SizeDetail::DsaClass { .. } => Some(KeyFamily::Dsa),
        SizeDetail::PqcSet { parameter_set, .. } => Some(if parameter_set.starts_with("ml_kem") {
            KeyFamily::MlKem
        } else if parameter_set.starts_with("ml_dsa") {
            KeyFamily::MlDsa
        } else {
            KeyFamily::SlhDsa
        }),
        SizeDetail::WrappedMaterial { .. } => None,
    }
}

/// The concise parenthetical label for one size detail
/// ("RSA 2048", "EC P-256", "RSA (non-standard length)", ...):
/// family-implied standalone form.
pub(crate) fn size_concise(detail: &SizeDetail) -> String {
    match detail {
        SizeDetail::Rsa {
            size_class: Some(class),
            ..
        } => format!("RSA {class}"),
        SizeDetail::Rsa { .. } => "RSA (non-standard length)".to_string(),
        SizeDetail::Ec { curve, .. } => format!("EC {}", ec_curve_display(curve)),
        SizeDetail::Eddsa { curve, .. } => eddsa_curve_display(curve).to_string(),
        SizeDetail::DsaClass { label, .. } => {
            format!("DSA {}", dsa_class_display(label))
        }
        SizeDetail::PqcSet { parameter_set, .. } => pqc_set_display(parameter_set).to_string(),
        SizeDetail::WrappedMaterial {
            material_octets, ..
        } => {
            format!("wrapped material {material_octets} bytes")
        }
    }
}

/// The `-v` fragment for one size detail with its evidence tag
/// ("RSA 2048 (from signature length)", ...).
pub(crate) fn size_verbose(detail: &SizeDetail, tag: EvidenceTag) -> String {
    let noun = evidence_noun(tag);
    match detail {
        SizeDetail::Rsa {
            size_class: Some(class),
            ..
        } => format!("RSA {class} (from {noun} length)"),
        SizeDetail::Rsa { modulus_bytes, .. } => format!(
            "RSA, {}-bit class (from {noun} length)",
            masked_rsa_class(*modulus_bytes)
        ),
        SizeDetail::Ec { curve, .. } => {
            format!("EC {} (from {noun} length)", ec_curve_display(curve))
        }
        SizeDetail::Eddsa { curve, .. } => {
            format!("{} (from {noun} length)", eddsa_curve_display(curve))
        }
        SizeDetail::DsaClass { label, .. } => {
            format!("DSA {} (from {noun} length)", dsa_class_display(label))
        }
        SizeDetail::PqcSet { parameter_set, .. } => {
            let ambiguous = parameter_set.starts_with("slh_dsa");
            if ambiguous {
                format!(
                    "{} (from {noun} length; SHA-2/SHAKE ambiguous)",
                    pqc_set_display(parameter_set)
                )
            } else {
                format!("{} (from {noun} length)", pqc_set_display(parameter_set))
            }
        }
        SizeDetail::WrappedMaterial {
            material_octets,
            octets,
        } => match tag {
            EvidenceTag::WrapOutput => format!(
                "wrapped material {material_octets} bytes (from {octets}-byte wrap output, about wrapped key)"
            ),
            EvidenceTag::UnwrapInput => {
                format!("wrapped material {material_octets} bytes (from {octets}-byte wrapped key)")
            }
            _ => format!("wrapped material {material_octets} bytes (from {octets}-byte {noun})"),
        },
    }
}

/// EC curve display ("p256" to "P-256"); unknown spellings pass
/// through, never hidden.
fn ec_curve_display(curve: &str) -> &str {
    match curve {
        "p256" => "P-256",
        "p384" => "P-384",
        "p521" => "P-521",
        curve => curve,
    }
}

/// EdDSA curve display ("ed25519" to "Ed25519").
fn eddsa_curve_display(curve: &str) -> &str {
    match curve {
        "ed25519" => "Ed25519",
        "ed448" => "Ed448",
        curve => curve,
    }
}

/// DSA class display ("dsa_1024" to "1024-bit class").
fn dsa_class_display(label: &str) -> &str {
    match label {
        "dsa_1024" => "1024-bit class",
        "dsa_2048_224" => "2048/224 class",
        "dsa_2048_256_or_3072" => "2048/256-or-3072 class",
        label => label,
    }
}

/// PQC parameter-set display ("ml_kem_768" to "ML-KEM-768").
fn pqc_set_display(set: &str) -> &str {
    match set {
        "ml_kem_512" => "ML-KEM-512",
        "ml_kem_768" => "ML-KEM-768",
        "ml_kem_1024" => "ML-KEM-1024",
        "ml_dsa_44" => "ML-DSA-44",
        "ml_dsa_65" => "ML-DSA-65",
        "ml_dsa_87" => "ML-DSA-87",
        "slh_dsa_128s" => "SLH-DSA-128s",
        "slh_dsa_128f" => "SLH-DSA-128f",
        "slh_dsa_192s" => "SLH-DSA-192s",
        "slh_dsa_192f" => "SLH-DSA-192f",
        "slh_dsa_256s" => "SLH-DSA-256s",
        "slh_dsa_256f" => "SLH-DSA-256f",
        set => set,
    }
}

/// The masked non-standard RSA class for `octets` (8·octets with the
/// last two digits masked: 256 → "2,0xx"). Never a range.
pub(crate) fn masked_rsa_class(octets: u64) -> String {
    let bits = octets.saturating_mul(8);
    let grouped = grouped_thousands(bits);
    let masked_len = grouped.len().saturating_sub(2);
    format!("{}xx", &grouped[..masked_len])
}

/// Thousands-grouped decimal rendering (no locale, no allocation
/// beyond the string).
fn grouped_thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// Whether two size details are the same size (§10.2): same detail
/// kind plus size params. The evidence tag never enters (it is not a
/// parameter), so same-size evidence keeps the first tag by
/// construction.
pub(crate) fn same_size(a: &SizeDetail, b: &SizeDetail) -> bool {
    // Tags never enter: same kind plus same size params only.
    a == b
}

/// The concise combined label for one valued family plus one valued
/// size ("RSA 2048", "EC P-256", "Ed25519", "DSA 1024-bit class",
/// "ML-KEM-768", "AES wrapped material 24 bytes"). Self-sufficient
/// size displays (EdDSA curves, PQC sets) stand alone; every other
/// kind names the family.
pub(crate) fn concise_label(family: KeyFamily, detail: &SizeDetail) -> String {
    let fam = family_display(family);
    match detail {
        SizeDetail::Rsa {
            size_class: Some(class),
            ..
        } => format!("{fam} {class}"),
        SizeDetail::Rsa { .. } => format!("{fam} (non-standard length)"),
        SizeDetail::Ec { curve, .. } => format!("{fam} {}", ec_curve_display(curve)),
        SizeDetail::Eddsa { curve, .. } => eddsa_curve_display(curve).to_string(),
        SizeDetail::DsaClass { label, .. } => {
            format!("{fam} {}", dsa_class_display(label))
        }
        SizeDetail::PqcSet { parameter_set, .. } => pqc_set_display(parameter_set).to_string(),
        SizeDetail::WrappedMaterial {
            material_octets, ..
        } => {
            format!("{fam} wrapped material {material_octets} bytes")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exhaustive §4.2 classification: (id, CKM name, expected family).
    // Generated from the reviewed assignment; names reviewed vs spec §4.2.
    const CATALOG_EXPECTED: &[(u64, &str, Option<KeyFamily>)] = &[
        (0x00000000, "CKM_RSA_PKCS_KEY_PAIR_GEN", None),
        (0x00000001, "CKM_RSA_PKCS", Some(KeyFamily::Rsa)),
        (0x00000002, "CKM_RSA_9796", Some(KeyFamily::Rsa)),
        (0x00000003, "CKM_RSA_X_509", Some(KeyFamily::Rsa)),
        (0x00000004, "CKM_MD2_RSA_PKCS", Some(KeyFamily::Rsa)),
        (0x00000005, "CKM_MD5_RSA_PKCS", Some(KeyFamily::Rsa)),
        (0x00000006, "CKM_SHA1_RSA_PKCS", Some(KeyFamily::Rsa)),
        (0x00000007, "CKM_RIPEMD128_RSA_PKCS", Some(KeyFamily::Rsa)),
        (0x00000008, "CKM_RIPEMD160_RSA_PKCS", Some(KeyFamily::Rsa)),
        (0x00000009, "CKM_RSA_PKCS_OAEP", Some(KeyFamily::Rsa)),
        (0x0000000a, "CKM_RSA_X9_31_KEY_PAIR_GEN", None),
        (0x0000000b, "CKM_RSA_X9_31", Some(KeyFamily::Rsa)),
        (0x0000000c, "CKM_SHA1_RSA_X9_31", Some(KeyFamily::Rsa)),
        (0x0000000d, "CKM_RSA_PKCS_PSS", Some(KeyFamily::Rsa)),
        (0x0000000e, "CKM_SHA1_RSA_PKCS_PSS", Some(KeyFamily::Rsa)),
        (0x0000000f, "CKM_ML_KEM_KEY_PAIR_GEN", None),
        (0x00000010, "CKM_DSA_KEY_PAIR_GEN", None),
        (0x00000011, "CKM_DSA", Some(KeyFamily::Dsa)),
        (0x00000012, "CKM_DSA_SHA1", Some(KeyFamily::Dsa)),
        (0x00000013, "CKM_DSA_SHA224", Some(KeyFamily::Dsa)),
        (0x00000014, "CKM_DSA_SHA256", Some(KeyFamily::Dsa)),
        (0x00000015, "CKM_DSA_SHA384", Some(KeyFamily::Dsa)),
        (0x00000016, "CKM_DSA_SHA512", Some(KeyFamily::Dsa)),
        (0x00000017, "CKM_ML_KEM", Some(KeyFamily::MlKem)),
        (0x00000018, "CKM_DSA_SHA3_224", Some(KeyFamily::Dsa)),
        (0x00000019, "CKM_DSA_SHA3_256", Some(KeyFamily::Dsa)),
        (0x0000001a, "CKM_DSA_SHA3_384", Some(KeyFamily::Dsa)),
        (0x0000001b, "CKM_DSA_SHA3_512", Some(KeyFamily::Dsa)),
        (0x0000001c, "CKM_ML_DSA_KEY_PAIR_GEN", None),
        (0x0000001d, "CKM_ML_DSA", Some(KeyFamily::MlDsa)),
        (0x0000001f, "CKM_HASH_ML_DSA", Some(KeyFamily::MlDsa)),
        (0x00000020, "CKM_DH_PKCS_KEY_PAIR_GEN", None),
        (0x00000021, "CKM_DH_PKCS_DERIVE", Some(KeyFamily::Dh)),
        (0x00000023, "CKM_HASH_ML_DSA_SHA224", Some(KeyFamily::MlDsa)),
        (0x00000024, "CKM_HASH_ML_DSA_SHA256", Some(KeyFamily::MlDsa)),
        (0x00000025, "CKM_HASH_ML_DSA_SHA384", Some(KeyFamily::MlDsa)),
        (0x00000026, "CKM_HASH_ML_DSA_SHA512", Some(KeyFamily::MlDsa)),
        (
            0x00000027,
            "CKM_HASH_ML_DSA_SHA3_224",
            Some(KeyFamily::MlDsa),
        ),
        (
            0x00000028,
            "CKM_HASH_ML_DSA_SHA3_256",
            Some(KeyFamily::MlDsa),
        ),
        (
            0x00000029,
            "CKM_HASH_ML_DSA_SHA3_384",
            Some(KeyFamily::MlDsa),
        ),
        (
            0x0000002a,
            "CKM_HASH_ML_DSA_SHA3_512",
            Some(KeyFamily::MlDsa),
        ),
        (
            0x0000002b,
            "CKM_HASH_ML_DSA_SHAKE128",
            Some(KeyFamily::MlDsa),
        ),
        (
            0x0000002c,
            "CKM_HASH_ML_DSA_SHAKE256",
            Some(KeyFamily::MlDsa),
        ),
        (0x0000002d, "CKM_SLH_DSA_KEY_PAIR_GEN", None),
        (0x0000002e, "CKM_SLH_DSA", Some(KeyFamily::SlhDsa)),
        (0x00000030, "CKM_X9_42_DH_KEY_PAIR_GEN", None),
        (0x00000031, "CKM_X9_42_DH_DERIVE", Some(KeyFamily::Dh)),
        (
            0x00000032,
            "CKM_X9_42_DH_HYBRID_DERIVE",
            Some(KeyFamily::Dh),
        ),
        (0x00000033, "CKM_X9_42_MQV_DERIVE", Some(KeyFamily::Dh)),
        (0x00000034, "CKM_HASH_SLH_DSA", Some(KeyFamily::SlhDsa)),
        (
            0x00000036,
            "CKM_HASH_SLH_DSA_SHA224",
            Some(KeyFamily::SlhDsa),
        ),
        (
            0x00000037,
            "CKM_HASH_SLH_DSA_SHA256",
            Some(KeyFamily::SlhDsa),
        ),
        (
            0x00000038,
            "CKM_HASH_SLH_DSA_SHA384",
            Some(KeyFamily::SlhDsa),
        ),
        (
            0x00000039,
            "CKM_HASH_SLH_DSA_SHA512",
            Some(KeyFamily::SlhDsa),
        ),
        (
            0x0000003a,
            "CKM_HASH_SLH_DSA_SHA3_224",
            Some(KeyFamily::SlhDsa),
        ),
        (
            0x0000003b,
            "CKM_HASH_SLH_DSA_SHA3_256",
            Some(KeyFamily::SlhDsa),
        ),
        (
            0x0000003c,
            "CKM_HASH_SLH_DSA_SHA3_384",
            Some(KeyFamily::SlhDsa),
        ),
        (
            0x0000003d,
            "CKM_HASH_SLH_DSA_SHA3_512",
            Some(KeyFamily::SlhDsa),
        ),
        (
            0x0000003e,
            "CKM_HASH_SLH_DSA_SHAKE128",
            Some(KeyFamily::SlhDsa),
        ),
        (
            0x0000003f,
            "CKM_HASH_SLH_DSA_SHAKE256",
            Some(KeyFamily::SlhDsa),
        ),
        (0x00000040, "CKM_SHA256_RSA_PKCS", Some(KeyFamily::Rsa)),
        (0x00000041, "CKM_SHA384_RSA_PKCS", Some(KeyFamily::Rsa)),
        (0x00000042, "CKM_SHA512_RSA_PKCS", Some(KeyFamily::Rsa)),
        (0x00000043, "CKM_SHA256_RSA_PKCS_PSS", Some(KeyFamily::Rsa)),
        (0x00000044, "CKM_SHA384_RSA_PKCS_PSS", Some(KeyFamily::Rsa)),
        (0x00000045, "CKM_SHA512_RSA_PKCS_PSS", Some(KeyFamily::Rsa)),
        (0x00000046, "CKM_SHA224_RSA_PKCS", Some(KeyFamily::Rsa)),
        (0x00000047, "CKM_SHA224_RSA_PKCS_PSS", Some(KeyFamily::Rsa)),
        (0x00000048, "CKM_SHA512_224", None),
        (
            0x00000049,
            "CKM_SHA512_224_HMAC",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x0000004a,
            "CKM_SHA512_224_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x0000004b,
            "CKM_SHA512_224_KEY_DERIVATION",
            Some(KeyFamily::Secret),
        ),
        (0x0000004c, "CKM_SHA512_256", None),
        (
            0x0000004d,
            "CKM_SHA512_256_HMAC",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x0000004e,
            "CKM_SHA512_256_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x0000004f,
            "CKM_SHA512_256_KEY_DERIVATION",
            Some(KeyFamily::Secret),
        ),
        (0x00000050, "CKM_SHA512_T", None),
        (
            0x00000051,
            "CKM_SHA512_T_HMAC",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x00000052,
            "CKM_SHA512_T_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x00000053,
            "CKM_SHA512_T_KEY_DERIVATION",
            Some(KeyFamily::Secret),
        ),
        (
            0x00000056,
            "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE",
            Some(KeyFamily::Secret),
        ),
        (
            0x00000057,
            "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH",
            Some(KeyFamily::Secret),
        ),
        (0x00000060, "CKM_SHA3_256_RSA_PKCS", Some(KeyFamily::Rsa)),
        (0x00000061, "CKM_SHA3_384_RSA_PKCS", Some(KeyFamily::Rsa)),
        (0x00000062, "CKM_SHA3_512_RSA_PKCS", Some(KeyFamily::Rsa)),
        (
            0x00000063,
            "CKM_SHA3_256_RSA_PKCS_PSS",
            Some(KeyFamily::Rsa),
        ),
        (
            0x00000064,
            "CKM_SHA3_384_RSA_PKCS_PSS",
            Some(KeyFamily::Rsa),
        ),
        (
            0x00000065,
            "CKM_SHA3_512_RSA_PKCS_PSS",
            Some(KeyFamily::Rsa),
        ),
        (0x00000066, "CKM_SHA3_224_RSA_PKCS", Some(KeyFamily::Rsa)),
        (
            0x00000067,
            "CKM_SHA3_224_RSA_PKCS_PSS",
            Some(KeyFamily::Rsa),
        ),
        (0x00000100, "CKM_RC2_KEY_GEN", None),
        (0x00000101, "CKM_RC2_ECB", None),
        (0x00000102, "CKM_RC2_CBC", None),
        (0x00000103, "CKM_RC2_MAC", None),
        (0x00000104, "CKM_RC2_MAC_GENERAL", None),
        (0x00000105, "CKM_RC2_CBC_PAD", None),
        (0x00000110, "CKM_RC4_KEY_GEN", None),
        (0x00000111, "CKM_RC4", None),
        (0x00000120, "CKM_DES_KEY_GEN", None),
        (0x00000121, "CKM_DES_ECB", Some(KeyFamily::Des)),
        (0x00000122, "CKM_DES_CBC", Some(KeyFamily::Des)),
        (0x00000123, "CKM_DES_MAC", Some(KeyFamily::Des)),
        (0x00000124, "CKM_DES_MAC_GENERAL", Some(KeyFamily::Des)),
        (0x00000125, "CKM_DES_CBC_PAD", Some(KeyFamily::Des)),
        (0x00000130, "CKM_DES2_KEY_GEN", None),
        (0x00000131, "CKM_DES3_KEY_GEN", None),
        (0x00000132, "CKM_DES3_ECB", Some(KeyFamily::Des3)),
        (0x00000133, "CKM_DES3_CBC", Some(KeyFamily::Des3)),
        (0x00000134, "CKM_DES3_MAC", Some(KeyFamily::Des3)),
        (0x00000135, "CKM_DES3_MAC_GENERAL", Some(KeyFamily::Des3)),
        (0x00000136, "CKM_DES3_CBC_PAD", Some(KeyFamily::Des3)),
        (0x00000137, "CKM_DES3_CMAC_GENERAL", Some(KeyFamily::Des3)),
        (0x00000138, "CKM_DES3_CMAC", Some(KeyFamily::Des3)),
        (0x00000140, "CKM_CDMF_KEY_GEN", None),
        (0x00000141, "CKM_CDMF_ECB", None),
        (0x00000142, "CKM_CDMF_CBC", None),
        (0x00000143, "CKM_CDMF_MAC", None),
        (0x00000144, "CKM_CDMF_MAC_GENERAL", None),
        (0x00000145, "CKM_CDMF_CBC_PAD", None),
        (0x00000150, "CKM_DES_OFB64", Some(KeyFamily::Des)),
        (0x00000151, "CKM_DES_OFB8", Some(KeyFamily::Des)),
        (0x00000152, "CKM_DES_CFB64", Some(KeyFamily::Des)),
        (0x00000153, "CKM_DES_CFB8", Some(KeyFamily::Des)),
        (0x00000200, "CKM_MD2", None),
        (0x00000201, "CKM_MD2_HMAC", Some(KeyFamily::GenericSecret)),
        (
            0x00000202,
            "CKM_MD2_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (0x00000210, "CKM_MD5", None),
        (0x00000211, "CKM_MD5_HMAC", Some(KeyFamily::GenericSecret)),
        (
            0x00000212,
            "CKM_MD5_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (0x00000220, "CKM_SHA_1", None),
        (0x00000221, "CKM_SHA_1_HMAC", Some(KeyFamily::GenericSecret)),
        (
            0x00000222,
            "CKM_SHA_1_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (0x00000230, "CKM_RIPEMD128", None),
        (
            0x00000231,
            "CKM_RIPEMD128_HMAC",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x00000232,
            "CKM_RIPEMD128_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (0x00000240, "CKM_RIPEMD160", None),
        (
            0x00000241,
            "CKM_RIPEMD160_HMAC",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x00000242,
            "CKM_RIPEMD160_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (0x00000250, "CKM_SHA256", None),
        (
            0x00000251,
            "CKM_SHA256_HMAC",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x00000252,
            "CKM_SHA256_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (0x00000255, "CKM_SHA224", None),
        (
            0x00000256,
            "CKM_SHA224_HMAC",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x00000257,
            "CKM_SHA224_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (0x00000260, "CKM_SHA384", None),
        (
            0x00000261,
            "CKM_SHA384_HMAC",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x00000262,
            "CKM_SHA384_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (0x00000270, "CKM_SHA512", None),
        (
            0x00000271,
            "CKM_SHA512_HMAC",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x00000272,
            "CKM_SHA512_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (0x00000280, "CKM_SECURID_KEY_GEN", None),
        (0x00000282, "CKM_SECURID", None),
        (0x00000290, "CKM_HOTP_KEY_GEN", None),
        (0x00000291, "CKM_HOTP", Some(KeyFamily::GenericSecret)),
        (0x000002a0, "CKM_ACTI", None),
        (0x000002a1, "CKM_ACTI_KEY_GEN", None),
        (0x000002b0, "CKM_SHA3_256", None),
        (
            0x000002b1,
            "CKM_SHA3_256_HMAC",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x000002b2,
            "CKM_SHA3_256_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (0x000002b3, "CKM_SHA3_256_KEY_GEN", None),
        (0x000002b5, "CKM_SHA3_224", None),
        (
            0x000002b6,
            "CKM_SHA3_224_HMAC",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x000002b7,
            "CKM_SHA3_224_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (0x000002b8, "CKM_SHA3_224_KEY_GEN", None),
        (0x000002c0, "CKM_SHA3_384", None),
        (
            0x000002c1,
            "CKM_SHA3_384_HMAC",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x000002c2,
            "CKM_SHA3_384_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (0x000002c3, "CKM_SHA3_384_KEY_GEN", None),
        (0x000002d0, "CKM_SHA3_512", None),
        (
            0x000002d1,
            "CKM_SHA3_512_HMAC",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x000002d2,
            "CKM_SHA3_512_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (0x000002d3, "CKM_SHA3_512_KEY_GEN", None),
        (0x00000300, "CKM_CAST_KEY_GEN", None),
        (0x00000301, "CKM_CAST_ECB", None),
        (0x00000302, "CKM_CAST_CBC", None),
        (0x00000303, "CKM_CAST_MAC", None),
        (0x00000304, "CKM_CAST_MAC_GENERAL", None),
        (0x00000305, "CKM_CAST_CBC_PAD", None),
        (0x00000310, "CKM_CAST3_KEY_GEN", None),
        (0x00000311, "CKM_CAST3_ECB", None),
        (0x00000312, "CKM_CAST3_CBC", None),
        (0x00000313, "CKM_CAST3_MAC", None),
        (0x00000314, "CKM_CAST3_MAC_GENERAL", None),
        (0x00000315, "CKM_CAST3_CBC_PAD", None),
        (0x00000320, "CKM_CAST128_KEY_GEN", None),
        (0x00000321, "CKM_CAST128_ECB", None),
        (0x00000322, "CKM_CAST128_CBC", None),
        (0x00000323, "CKM_CAST128_MAC", None),
        (0x00000324, "CKM_CAST128_MAC_GENERAL", None),
        (0x00000325, "CKM_CAST128_CBC_PAD", None),
        (0x00000330, "CKM_RC5_KEY_GEN", None),
        (0x00000331, "CKM_RC5_ECB", None),
        (0x00000332, "CKM_RC5_CBC", None),
        (0x00000333, "CKM_RC5_MAC", None),
        (0x00000334, "CKM_RC5_MAC_GENERAL", None),
        (0x00000335, "CKM_RC5_CBC_PAD", None),
        (0x00000340, "CKM_IDEA_KEY_GEN", None),
        (0x00000341, "CKM_IDEA_ECB", None),
        (0x00000342, "CKM_IDEA_CBC", None),
        (0x00000343, "CKM_IDEA_MAC", None),
        (0x00000344, "CKM_IDEA_MAC_GENERAL", None),
        (0x00000345, "CKM_IDEA_CBC_PAD", None),
        (0x00000350, "CKM_GENERIC_SECRET_KEY_GEN", None),
        (
            0x00000360,
            "CKM_CONCATENATE_BASE_AND_KEY",
            Some(KeyFamily::Secret),
        ),
        (
            0x00000362,
            "CKM_CONCATENATE_BASE_AND_DATA",
            Some(KeyFamily::Secret),
        ),
        (
            0x00000363,
            "CKM_CONCATENATE_DATA_AND_BASE",
            Some(KeyFamily::Secret),
        ),
        (0x00000364, "CKM_XOR_BASE_AND_DATA", Some(KeyFamily::Secret)),
        (
            0x00000365,
            "CKM_EXTRACT_KEY_FROM_KEY",
            Some(KeyFamily::Secret),
        ),
        (0x00000370, "CKM_SSL3_PRE_MASTER_KEY_GEN", None),
        (
            0x00000371,
            "CKM_SSL3_MASTER_KEY_DERIVE",
            Some(KeyFamily::Secret),
        ),
        (
            0x00000372,
            "CKM_SSL3_KEY_AND_MAC_DERIVE",
            Some(KeyFamily::Secret),
        ),
        (
            0x00000373,
            "CKM_SSL3_MASTER_KEY_DERIVE_DH",
            Some(KeyFamily::Secret),
        ),
        (0x00000374, "CKM_TLS_PRE_MASTER_KEY_GEN", None),
        (
            0x00000375,
            "CKM_TLS_MASTER_KEY_DERIVE",
            Some(KeyFamily::Secret),
        ),
        (
            0x00000376,
            "CKM_TLS_KEY_AND_MAC_DERIVE",
            Some(KeyFamily::Secret),
        ),
        (
            0x00000377,
            "CKM_TLS_MASTER_KEY_DERIVE_DH",
            Some(KeyFamily::Secret),
        ),
        (0x00000378, "CKM_TLS_PRF", Some(KeyFamily::Secret)),
        (0x00000380, "CKM_SSL3_MD5_MAC", None),
        (0x00000381, "CKM_SSL3_SHA1_MAC", None),
        (
            0x00000390,
            "CKM_MD5_KEY_DERIVATION",
            Some(KeyFamily::Secret),
        ),
        (
            0x00000391,
            "CKM_MD2_KEY_DERIVATION",
            Some(KeyFamily::Secret),
        ),
        (
            0x00000392,
            "CKM_SHA1_KEY_DERIVATION",
            Some(KeyFamily::Secret),
        ),
        (
            0x00000393,
            "CKM_SHA256_KEY_DERIVATION",
            Some(KeyFamily::Secret),
        ),
        (
            0x00000394,
            "CKM_SHA384_KEY_DERIVATION",
            Some(KeyFamily::Secret),
        ),
        (
            0x00000395,
            "CKM_SHA512_KEY_DERIVATION",
            Some(KeyFamily::Secret),
        ),
        (
            0x00000396,
            "CKM_SHA224_KEY_DERIVATION",
            Some(KeyFamily::Secret),
        ),
        (
            0x00000397,
            "CKM_SHA3_256_KEY_DERIVATION",
            Some(KeyFamily::Secret),
        ),
        (
            0x00000398,
            "CKM_SHA3_224_KEY_DERIVATION",
            Some(KeyFamily::Secret),
        ),
        (
            0x00000399,
            "CKM_SHA3_384_KEY_DERIVATION",
            Some(KeyFamily::Secret),
        ),
        (
            0x0000039a,
            "CKM_SHA3_512_KEY_DERIVATION",
            Some(KeyFamily::Secret),
        ),
        (
            0x0000039b,
            "CKM_SHAKE_128_KEY_DERIVATION",
            Some(KeyFamily::Secret),
        ),
        (
            0x0000039c,
            "CKM_SHAKE_256_KEY_DERIVATION",
            Some(KeyFamily::Secret),
        ),
        (0x000003a0, "CKM_PBE_MD2_DES_CBC", None),
        (0x000003a1, "CKM_PBE_MD5_DES_CBC", None),
        (0x000003a2, "CKM_PBE_MD5_CAST_CBC", None),
        (0x000003a3, "CKM_PBE_MD5_CAST3_CBC", None),
        (0x000003a4, "CKM_PBE_MD5_CAST128_CBC", None),
        (0x000003a5, "CKM_PBE_SHA1_CAST128_CBC", None),
        (0x000003a6, "CKM_PBE_SHA1_RC4_128", None),
        (0x000003a7, "CKM_PBE_SHA1_RC4_40", None),
        (0x000003a8, "CKM_PBE_SHA1_DES3_EDE_CBC", None),
        (0x000003a9, "CKM_PBE_SHA1_DES2_EDE_CBC", None),
        (0x000003aa, "CKM_PBE_SHA1_RC2_128_CBC", None),
        (0x000003ab, "CKM_PBE_SHA1_RC2_40_CBC", None),
        (
            0x000003ac,
            "CKM_SP800_108_COUNTER_KDF",
            Some(KeyFamily::Secret),
        ),
        (
            0x000003ad,
            "CKM_SP800_108_FEEDBACK_KDF",
            Some(KeyFamily::Secret),
        ),
        (
            0x000003ae,
            "CKM_SP800_108_DOUBLE_PIPELINE_KDF",
            Some(KeyFamily::Secret),
        ),
        (0x000003b0, "CKM_PKCS5_PBKD2", None),
        (0x000003c0, "CKM_PBA_SHA1_WITH_SHA1_HMAC", None),
        (0x000003d0, "CKM_WTLS_PRE_MASTER_KEY_GEN", None),
        (
            0x000003d1,
            "CKM_WTLS_MASTER_KEY_DERIVE",
            Some(KeyFamily::Secret),
        ),
        (
            0x000003d2,
            "CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC",
            Some(KeyFamily::Secret),
        ),
        (0x000003d3, "CKM_WTLS_PRF", Some(KeyFamily::Secret)),
        (
            0x000003d4,
            "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE",
            Some(KeyFamily::Secret),
        ),
        (
            0x000003d5,
            "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE",
            Some(KeyFamily::Secret),
        ),
        (0x000003d6, "CKM_TLS10_MAC_SERVER", None),
        (0x000003d7, "CKM_TLS10_MAC_CLIENT", None),
        (0x000003d8, "CKM_TLS12_MAC", None),
        (0x000003d9, "CKM_TLS12_KDF", Some(KeyFamily::Secret)),
        (
            0x000003e0,
            "CKM_TLS12_MASTER_KEY_DERIVE",
            Some(KeyFamily::Secret),
        ),
        (
            0x000003e1,
            "CKM_TLS12_KEY_AND_MAC_DERIVE",
            Some(KeyFamily::Secret),
        ),
        (
            0x000003e2,
            "CKM_TLS12_MASTER_KEY_DERIVE_DH",
            Some(KeyFamily::Secret),
        ),
        (
            0x000003e3,
            "CKM_TLS12_KEY_SAFE_DERIVE",
            Some(KeyFamily::Secret),
        ),
        (0x000003e4, "CKM_TLS_MAC", None),
        (0x000003e5, "CKM_TLS_KDF", Some(KeyFamily::Secret)),
        (0x00000400, "CKM_KEY_WRAP_LYNKS", None),
        (0x00000401, "CKM_KEY_WRAP_SET_OAEP", None),
        (0x00000500, "CKM_CMS_SIG", None),
        (0x00000510, "CKM_KIP_DERIVE", Some(KeyFamily::Secret)),
        (0x00000511, "CKM_KIP_WRAP", Some(KeyFamily::Secret)),
        (0x00000512, "CKM_KIP_MAC", Some(KeyFamily::Secret)),
        (0x00000550, "CKM_CAMELLIA_KEY_GEN", None),
        (0x00000551, "CKM_CAMELLIA_ECB", Some(KeyFamily::Camellia)),
        (0x00000552, "CKM_CAMELLIA_CBC", Some(KeyFamily::Camellia)),
        (0x00000553, "CKM_CAMELLIA_MAC", Some(KeyFamily::Camellia)),
        (
            0x00000554,
            "CKM_CAMELLIA_MAC_GENERAL",
            Some(KeyFamily::Camellia),
        ),
        (
            0x00000555,
            "CKM_CAMELLIA_CBC_PAD",
            Some(KeyFamily::Camellia),
        ),
        (
            0x00000556,
            "CKM_CAMELLIA_ECB_ENCRYPT_DATA",
            Some(KeyFamily::Camellia),
        ),
        (
            0x00000557,
            "CKM_CAMELLIA_CBC_ENCRYPT_DATA",
            Some(KeyFamily::Camellia),
        ),
        (0x00000558, "CKM_CAMELLIA_CTR", Some(KeyFamily::Camellia)),
        (0x00000560, "CKM_ARIA_KEY_GEN", None),
        (0x00000561, "CKM_ARIA_ECB", Some(KeyFamily::Aria)),
        (0x00000562, "CKM_ARIA_CBC", Some(KeyFamily::Aria)),
        (0x00000563, "CKM_ARIA_MAC", Some(KeyFamily::Aria)),
        (0x00000564, "CKM_ARIA_MAC_GENERAL", Some(KeyFamily::Aria)),
        (0x00000565, "CKM_ARIA_CBC_PAD", Some(KeyFamily::Aria)),
        (
            0x00000566,
            "CKM_ARIA_ECB_ENCRYPT_DATA",
            Some(KeyFamily::Aria),
        ),
        (
            0x00000567,
            "CKM_ARIA_CBC_ENCRYPT_DATA",
            Some(KeyFamily::Aria),
        ),
        (0x00000650, "CKM_SEED_KEY_GEN", None),
        (0x00000651, "CKM_SEED_ECB", Some(KeyFamily::Seed)),
        (0x00000652, "CKM_SEED_CBC", Some(KeyFamily::Seed)),
        (0x00000653, "CKM_SEED_MAC", Some(KeyFamily::Seed)),
        (0x00000654, "CKM_SEED_MAC_GENERAL", Some(KeyFamily::Seed)),
        (0x00000655, "CKM_SEED_CBC_PAD", Some(KeyFamily::Seed)),
        (
            0x00000656,
            "CKM_SEED_ECB_ENCRYPT_DATA",
            Some(KeyFamily::Seed),
        ),
        (
            0x00000657,
            "CKM_SEED_CBC_ENCRYPT_DATA",
            Some(KeyFamily::Seed),
        ),
        (0x00001000, "CKM_SKIPJACK_KEY_GEN", None),
        (0x00001001, "CKM_SKIPJACK_ECB64", None),
        (0x00001002, "CKM_SKIPJACK_CBC64", None),
        (0x00001003, "CKM_SKIPJACK_OFB64", None),
        (0x00001004, "CKM_SKIPJACK_CFB64", None),
        (0x00001005, "CKM_SKIPJACK_CFB32", None),
        (0x00001006, "CKM_SKIPJACK_CFB16", None),
        (0x00001007, "CKM_SKIPJACK_CFB8", None),
        (0x00001008, "CKM_SKIPJACK_WRAP", None),
        (0x00001009, "CKM_SKIPJACK_PRIVATE_WRAP", None),
        (0x0000100a, "CKM_SKIPJACK_RELAYX", None),
        (0x00001010, "CKM_KEA_KEY_PAIR_GEN", None),
        (0x00001011, "CKM_KEA_KEY_DERIVE", Some(KeyFamily::Dh)),
        (0x00001012, "CKM_KEA_DERIVE", Some(KeyFamily::Dh)),
        (0x00001020, "CKM_FORTEZZA_TIMESTAMP", None),
        (0x00001030, "CKM_BATON_KEY_GEN", None),
        (0x00001031, "CKM_BATON_ECB128", None),
        (0x00001032, "CKM_BATON_ECB96", None),
        (0x00001033, "CKM_BATON_CBC128", None),
        (0x00001034, "CKM_BATON_COUNTER", None),
        (0x00001035, "CKM_BATON_SHUFFLE", None),
        (0x00001036, "CKM_BATON_WRAP", None),
        (0x00001040, "CKM_EC_KEY_PAIR_GEN", None),
        (0x00001041, "CKM_ECDSA", Some(KeyFamily::Ec)),
        (0x00001042, "CKM_ECDSA_SHA1", Some(KeyFamily::Ec)),
        (0x00001043, "CKM_ECDSA_SHA224", Some(KeyFamily::Ec)),
        (0x00001044, "CKM_ECDSA_SHA256", Some(KeyFamily::Ec)),
        (0x00001045, "CKM_ECDSA_SHA384", Some(KeyFamily::Ec)),
        (0x00001046, "CKM_ECDSA_SHA512", Some(KeyFamily::Ec)),
        (0x00001047, "CKM_ECDSA_SHA3_224", Some(KeyFamily::Ec)),
        (0x00001048, "CKM_ECDSA_SHA3_256", Some(KeyFamily::Ec)),
        (0x00001049, "CKM_ECDSA_SHA3_384", Some(KeyFamily::Ec)),
        (0x0000104a, "CKM_ECDSA_SHA3_512", Some(KeyFamily::Ec)),
        (0x00001050, "CKM_ECDH1_DERIVE", Some(KeyFamily::Ec)),
        (0x00001051, "CKM_ECDH1_COFACTOR_DERIVE", Some(KeyFamily::Ec)),
        (0x00001052, "CKM_ECMQV_DERIVE", Some(KeyFamily::Ec)),
        (0x00001053, "CKM_ECDH_AES_KEY_WRAP", Some(KeyFamily::Ec)),
        (0x00001054, "CKM_RSA_AES_KEY_WRAP", Some(KeyFamily::Rsa)),
        (0x00001055, "CKM_EC_EDWARDS_KEY_PAIR_GEN", None),
        (0x00001056, "CKM_EC_MONTGOMERY_KEY_PAIR_GEN", None),
        (0x00001057, "CKM_EDDSA", Some(KeyFamily::Eddsa)),
        (0x00001060, "CKM_JUNIPER_KEY_GEN", None),
        (0x00001061, "CKM_JUNIPER_ECB128", None),
        (0x00001062, "CKM_JUNIPER_CBC128", None),
        (0x00001063, "CKM_JUNIPER_COUNTER", None),
        (0x00001064, "CKM_JUNIPER_SHUFFLE", None),
        (0x00001065, "CKM_JUNIPER_WRAP", None),
        (0x00001070, "CKM_FASTHASH", None),
        (0x00001071, "CKM_AES_XTS", Some(KeyFamily::Aes)),
        (0x00001072, "CKM_AES_XTS_KEY_GEN", None),
        (0x00001080, "CKM_AES_KEY_GEN", None),
        (0x00001081, "CKM_AES_ECB", Some(KeyFamily::Aes)),
        (0x00001082, "CKM_AES_CBC", Some(KeyFamily::Aes)),
        (0x00001083, "CKM_AES_MAC", Some(KeyFamily::Aes)),
        (0x00001084, "CKM_AES_MAC_GENERAL", Some(KeyFamily::Aes)),
        (0x00001085, "CKM_AES_CBC_PAD", Some(KeyFamily::Aes)),
        (0x00001086, "CKM_AES_CTR", Some(KeyFamily::Aes)),
        (0x00001087, "CKM_AES_GCM", Some(KeyFamily::Aes)),
        (0x00001088, "CKM_AES_CCM", Some(KeyFamily::Aes)),
        (0x00001089, "CKM_AES_CTS", Some(KeyFamily::Aes)),
        (0x0000108a, "CKM_AES_CMAC", Some(KeyFamily::Aes)),
        (0x0000108b, "CKM_AES_CMAC_GENERAL", Some(KeyFamily::Aes)),
        (0x0000108c, "CKM_AES_XCBC_MAC", Some(KeyFamily::Aes)),
        (0x0000108d, "CKM_AES_XCBC_MAC_96", Some(KeyFamily::Aes)),
        (0x0000108e, "CKM_AES_GMAC", Some(KeyFamily::Aes)),
        (0x00001090, "CKM_BLOWFISH_KEY_GEN", None),
        (0x00001091, "CKM_BLOWFISH_CBC", None),
        (0x00001092, "CKM_TWOFISH_KEY_GEN", None),
        (0x00001093, "CKM_TWOFISH_CBC", None),
        (0x00001094, "CKM_BLOWFISH_CBC_PAD", None),
        (0x00001095, "CKM_TWOFISH_CBC_PAD", None),
        (0x00001100, "CKM_DES_ECB_ENCRYPT_DATA", Some(KeyFamily::Des)),
        (0x00001101, "CKM_DES_CBC_ENCRYPT_DATA", Some(KeyFamily::Des)),
        (
            0x00001102,
            "CKM_DES3_ECB_ENCRYPT_DATA",
            Some(KeyFamily::Des3),
        ),
        (
            0x00001103,
            "CKM_DES3_CBC_ENCRYPT_DATA",
            Some(KeyFamily::Des3),
        ),
        (0x00001104, "CKM_AES_ECB_ENCRYPT_DATA", Some(KeyFamily::Aes)),
        (0x00001105, "CKM_AES_CBC_ENCRYPT_DATA", Some(KeyFamily::Aes)),
        (0x00001200, "CKM_GOSTR3410_KEY_PAIR_GEN", None),
        (0x00001201, "CKM_GOSTR3410", None),
        (0x00001202, "CKM_GOSTR3410_WITH_GOSTR3411", None),
        (0x00001203, "CKM_GOSTR3410_KEY_WRAP", None),
        (0x00001204, "CKM_GOSTR3410_DERIVE", None),
        (0x00001210, "CKM_GOSTR3411", None),
        (
            0x00001211,
            "CKM_GOSTR3411_HMAC",
            Some(KeyFamily::GenericSecret),
        ),
        (0x00001220, "CKM_GOST28147_KEY_GEN", None),
        (0x00001221, "CKM_GOST28147_ECB", Some(KeyFamily::Gost)),
        (0x00001222, "CKM_GOST28147", Some(KeyFamily::Gost)),
        (0x00001223, "CKM_GOST28147_MAC", Some(KeyFamily::Gost)),
        (0x00001224, "CKM_GOST28147_KEY_WRAP", Some(KeyFamily::Gost)),
        (0x00001225, "CKM_CHACHA20_KEY_GEN", None),
        (0x00001226, "CKM_CHACHA20", Some(KeyFamily::Chacha20)),
        (0x00001227, "CKM_POLY1305_KEY_GEN", None),
        (0x00001228, "CKM_POLY1305", Some(KeyFamily::Poly1305)),
        (0x0000140b, "CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS", None),
        (0x00002000, "CKM_DSA_PARAMETER_GEN", None),
        (0x00002001, "CKM_DH_PKCS_PARAMETER_GEN", None),
        (0x00002002, "CKM_X9_42_DH_PARAMETER_GEN", None),
        (0x00002003, "CKM_DSA_PROBABILISTIC_PARAMETER_GEN", None),
        (0x00002004, "CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN", None),
        (0x00002005, "CKM_DSA_FIPS_G_GEN", None),
        (0x00002104, "CKM_AES_OFB", Some(KeyFamily::Aes)),
        (0x00002105, "CKM_AES_CFB64", Some(KeyFamily::Aes)),
        (0x00002106, "CKM_AES_CFB8", Some(KeyFamily::Aes)),
        (0x00002107, "CKM_AES_CFB128", Some(KeyFamily::Aes)),
        (0x00002108, "CKM_AES_CFB1", Some(KeyFamily::Aes)),
        (0x00002109, "CKM_AES_KEY_WRAP", Some(KeyFamily::Aes)),
        (0x0000210a, "CKM_AES_KEY_WRAP_PAD", Some(KeyFamily::Aes)),
        (0x0000210b, "CKM_AES_KEY_WRAP_KWP", Some(KeyFamily::Aes)),
        (0x0000210c, "CKM_AES_KEY_WRAP_PKCS7", Some(KeyFamily::Aes)),
        (0x00004001, "CKM_RSA_PKCS_TPM_1_1", Some(KeyFamily::Rsa)),
        (
            0x00004002,
            "CKM_RSA_PKCS_OAEP_TPM_1_1",
            Some(KeyFamily::Rsa),
        ),
        (0x00004003, "CKM_SHA_1_KEY_GEN", None),
        (0x00004004, "CKM_SHA224_KEY_GEN", None),
        (0x00004005, "CKM_SHA256_KEY_GEN", None),
        (0x00004006, "CKM_SHA384_KEY_GEN", None),
        (0x00004007, "CKM_SHA512_KEY_GEN", None),
        (0x00004008, "CKM_SHA512_224_KEY_GEN", None),
        (0x00004009, "CKM_SHA512_256_KEY_GEN", None),
        (0x0000400a, "CKM_SHA512_T_KEY_GEN", None),
        (0x0000400b, "CKM_NULL", None),
        (0x0000400c, "CKM_BLAKE2B_160", None),
        (
            0x0000400d,
            "CKM_BLAKE2B_160_HMAC",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x0000400e,
            "CKM_BLAKE2B_160_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (0x0000400f, "CKM_BLAKE2B_160_KEY_DERIVE", None),
        (0x00004010, "CKM_BLAKE2B_160_KEY_GEN", None),
        (0x00004011, "CKM_BLAKE2B_256", None),
        (
            0x00004012,
            "CKM_BLAKE2B_256_HMAC",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x00004013,
            "CKM_BLAKE2B_256_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (0x00004014, "CKM_BLAKE2B_256_KEY_DERIVE", None),
        (0x00004015, "CKM_BLAKE2B_256_KEY_GEN", None),
        (0x00004016, "CKM_BLAKE2B_384", None),
        (
            0x00004017,
            "CKM_BLAKE2B_384_HMAC",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x00004018,
            "CKM_BLAKE2B_384_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (0x00004019, "CKM_BLAKE2B_384_KEY_DERIVE", None),
        (0x0000401a, "CKM_BLAKE2B_384_KEY_GEN", None),
        (0x0000401b, "CKM_BLAKE2B_512", None),
        (
            0x0000401c,
            "CKM_BLAKE2B_512_HMAC",
            Some(KeyFamily::GenericSecret),
        ),
        (
            0x0000401d,
            "CKM_BLAKE2B_512_HMAC_GENERAL",
            Some(KeyFamily::GenericSecret),
        ),
        (0x0000401e, "CKM_BLAKE2B_512_KEY_DERIVE", None),
        (0x0000401f, "CKM_BLAKE2B_512_KEY_GEN", None),
        (0x00004020, "CKM_SALSA20", None),
        (
            0x00004021,
            "CKM_CHACHA20_POLY1305",
            Some(KeyFamily::Chacha20),
        ),
        (0x00004022, "CKM_SALSA20_POLY1305", None),
        (0x00004023, "CKM_X3DH_INITIALIZE", None),
        (0x00004024, "CKM_X3DH_RESPOND", None),
        (0x00004025, "CKM_X2RATCHET_INITIALIZE", None),
        (0x00004026, "CKM_X2RATCHET_RESPOND", None),
        (0x00004027, "CKM_X2RATCHET_ENCRYPT", None),
        (0x00004028, "CKM_X2RATCHET_DECRYPT", None),
        (0x00004029, "CKM_XEDDSA", Some(KeyFamily::Xeddsa)),
        (0x0000402a, "CKM_HKDF_DERIVE", Some(KeyFamily::Hkdf)),
        (0x0000402b, "CKM_HKDF_DATA", Some(KeyFamily::Hkdf)),
        (0x0000402c, "CKM_HKDF_KEY_GEN", None),
        (0x0000402d, "CKM_SALSA20_KEY_GEN", None),
        (
            0x0000402e,
            "CKM_IKE2_PRF_PLUS_DERIVE",
            Some(KeyFamily::Secret),
        ),
        (0x0000402f, "CKM_IKE_PRF_DERIVE", Some(KeyFamily::Secret)),
        (0x00004030, "CKM_IKE1_PRF_DERIVE", Some(KeyFamily::Secret)),
        (
            0x00004031,
            "CKM_IKE1_EXTENDED_DERIVE",
            Some(KeyFamily::Secret),
        ),
        (0x00004032, "CKM_HSS_KEY_PAIR_GEN", None),
        (0x00004033, "CKM_HSS", None),
        (0x00004034, "CKM_XMSS_KEY_PAIR_GEN", None),
        (0x00004035, "CKM_XMSSMT_KEY_PAIR_GEN", None),
        (0x00004036, "CKM_XMSS", None),
        (0x00004037, "CKM_XMSSMT", None),
        (0x00004038, "CKM_ECDH_X_AES_KEY_WRAP", Some(KeyFamily::Ec)),
        (0x00004039, "CKM_ECDH_COF_AES_KEY_WRAP", Some(KeyFamily::Ec)),
        (0x0000403a, "CKM_PUB_KEY_FROM_PRIV_KEY", None),
    ];

    /// Parse the registered id universe from the registry source: every
    /// `0x… => Some("CKM_…")` row. The vendor fallthrough tuples and the
    /// file's own tests never match this shape.
    fn registered_universe() -> Vec<(u64, String)> {
        let mut out = Vec::new();
        for line in include_str!("mechanism_names.rs").lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix("0x") else {
                continue;
            };
            let Some(arrow) = rest.find("=> Some(\"CKM_") else {
                continue;
            };
            let digits: String = rest[..arrow].chars().filter(|c| *c != '_').collect();
            let id = u64::from_str_radix(digits.trim(), 16).expect("registry id parses");
            let name_start = arrow + "=> Some(\"".len();
            let name_end = rest[name_start..].find('"').expect("name closes") + name_start;
            out.push((id, rest[name_start..name_end].to_string()));
        }
        out
    }

    /// Spec §4.2 catalog coverage: every registered id resolves to its
    /// expected name and classifies to its expected family; the
    /// universe is exactly the 463 pinned rows (registry growth fails
    /// loudly until the new id is classified).
    #[test]
    fn catalog_covers_every_registered_mechanism() {
        let universe = registered_universe();
        assert_eq!(universe.len(), 463, "registered universe size");
        assert_eq!(CATALOG_EXPECTED.len(), 463, "pinned catalog size");
        let mut listed = 0usize;
        for (id, name, expected) in CATALOG_EXPECTED {
            assert_eq!(
                crate::mechanism_names::official_mechanism_name(*id),
                Some(*name),
                "id 0x{id:08x} resolves to its pinned name"
            );
            assert_eq!(
                infer_family(*id),
                *expected,
                "id 0x{id:08x} ({name}) classifies"
            );
            if expected.is_some() {
                listed += 1;
            }
        }
        assert_eq!(listed, 261, "listed ids across 21 families");
        for (id, name) in &universe {
            assert!(
                CATALOG_EXPECTED.iter().any(|(pinned_id, pinned_name, _)| {
                    pinned_id == id && *pinned_name == name.as_str()
                }),
                "universe id 0x{id:08x} ({name}) is pinned",
            );
        }
    }

    /// Hand-typed infer-nothing spots (independent of the generated
    /// table): vendor, keygen/parameter-gen, CMS_SIG/PBA/PBKD2,
    /// digests, unobserved legacy, and hostile-width aliases.
    #[test]
    fn infer_nothing_spots() {
        for id in [
            0x8000_0000u64,
            0xCE53_43A9,
            u64::MAX,
            0x0000_0500,      // CKM_CMS_SIG
            0x0000_03B0,      // CKM_PKCS5_PBKD2
            0x0000_03C0,      // CKM_PBA_SHA1_WITH_SHA1_HMAC
            0x0000_0000,      // CKM_RSA_PKCS_KEY_PAIR_GEN
            0x0000_1040,      // CKM_EC_KEY_PAIR_GEN
            0x0000_0350,      // CKM_GENERIC_SECRET_KEY_GEN
            0x0000_2000,      // CKM_DSA_PARAMETER_GEN
            0x0000_2005,      // CKM_DSA_FIPS_G_GEN
            0x0000_0250,      // CKM_SHA256 (digest)
            0x0000_1020,      // CKM_FORTEZZA_TIMESTAMP
            0x0000_1201,      // CKM_GOSTR3410 (signatures stay unknown)
            0x0000_4020,      // CKM_SALSA20
            0x0000_4033,      // CKM_HSS
            0x0000_4036,      // CKM_XMSS
            0x0000_4023,      // CKM_X3DH_INITIALIZE
            0x0000_403A,      // CKM_PUB_KEY_FROM_PRIV_KEY
            0x0000_0400,      // CKM_KEY_WRAP_LYNKS
            0x0000_03A0,      // CKM_PBE_MD2_DES_CBC
            0x0000_400F,      // CKM_BLAKE2B_160_KEY_DERIVE (_DERIVE, not _DERIVATION)
            0x0000_03E4,      // CKM_TLS_MAC (MACs are not HMACs)
            0x0000_0111,      // CKM_RC4
            0x0000_1001,      // CKM_SKIPJACK_ECB64
            0x0000_1091,      // CKM_BLOWFISH_CBC
            0x0001_0000_0001, // 1<<32 OR-alias of CKM_RSA_PKCS
            0x0001_0001,      // 1<<16 OR-alias of CKM_RSA_PKCS
        ] {
            assert_eq!(infer_family(id), None, "id 0x{id:x} infers nothing");
        }
    }

    /// Family value/display spellings (§10.2 enum + §10.3 fragments).
    #[test]
    fn family_spellings() {
        for (family, value, display) in [
            (KeyFamily::Rsa, "rsa", "RSA"),
            (KeyFamily::Ec, "ec", "EC"),
            (KeyFamily::Eddsa, "eddsa", "EdDSA"),
            (KeyFamily::Xeddsa, "xeddsa", "XEdDSA"),
            (KeyFamily::Secret, "secret", "secret-key"),
            (KeyFamily::Dsa, "dsa", "DSA"),
            (KeyFamily::Dh, "dh", "DH"),
            (KeyFamily::Aes, "aes", "AES"),
            (KeyFamily::GenericSecret, "generic_secret", "generic-secret"),
            (KeyFamily::Hkdf, "hkdf", "HKDF"),
            (KeyFamily::MlKem, "ml_kem", "ML-KEM"),
            (KeyFamily::MlDsa, "ml_dsa", "ML-DSA"),
            (KeyFamily::SlhDsa, "slh_dsa", "SLH-DSA"),
            (KeyFamily::Chacha20, "chacha20", "ChaCha20"),
            (KeyFamily::Poly1305, "poly1305", "Poly1305"),
            (KeyFamily::Des, "des", "DES"),
            (KeyFamily::Des3, "des3", "DES3"),
            (KeyFamily::Camellia, "camellia", "Camellia"),
            (KeyFamily::Aria, "aria", "Aria"),
            (KeyFamily::Seed, "seed", "SEED"),
            (KeyFamily::Gost, "gost", "GOST"),
        ] {
            assert_eq!(family_value(family), value);
            assert_eq!(family_display(family), display);
        }
    }

    /// [`KeyLabel`] to §4.5 kind mapping.
    #[test]
    fn established_kind_mapping() {
        use crate::semantics_objects::{KeyLabel, PqcCode};
        assert_eq!(
            established_kind(KeyLabel::Rsa { modulus_bits: 2048 }),
            EstablishedKind::Rsa { bits: 2048 }
        );
        assert_eq!(
            established_kind(KeyLabel::Aes { value_len: 32 }),
            EstablishedKind::Aes { bytes: 32 }
        );
        assert_eq!(
            established_kind(KeyLabel::Ec {
                curve: SafeCurve::Secp256r1
            }),
            EstablishedKind::Ec {
                curve: SafeCurve::Secp256r1
            }
        );
        assert_eq!(
            established_kind(KeyLabel::Ec {
                curve: SafeCurve::X25519
            }),
            EstablishedKind::Montgomery
        );
        assert_eq!(
            established_kind(KeyLabel::Ec {
                curve: SafeCurve::Ed25519
            }),
            EstablishedKind::Edwards {
                curve: SafeCurve::Ed25519
            }
        );
        assert_eq!(
            established_kind(KeyLabel::Hkdf { value_len: 32 }),
            EstablishedKind::Hkdf { bytes: 32 }
        );
        assert_eq!(
            established_kind(KeyLabel::GenericSecret { value_len: 16 }),
            EstablishedKind::GenericSecret { bytes: 16 }
        );
        assert_eq!(
            established_kind(KeyLabel::Pqc(PqcCode::MlKem768)),
            EstablishedKind::MlKem { set: "ml_kem_768" }
        );
        assert_eq!(
            established_kind(KeyLabel::Pqc(PqcCode::MlDsa65)),
            EstablishedKind::MlDsa { set: "ml_dsa_65" }
        );
        assert_eq!(
            established_kind(KeyLabel::Pqc(PqcCode::SlhDsaShake128s)),
            EstablishedKind::SlhDsa {
                set: "slh_dsa_128s"
            }
        );
    }

    /// Every §4.5 row, both directions of the qualifiers, plus the
    /// cross-name default (everything else conflicts) and the inert
    /// des2/des3 pair.
    #[test]
    fn compat_table() {
        const ECDH1: u64 = 0x1050;
        const ECDH1_COF: u64 = 0x1051;
        const ECMQV: u64 = 0x1052;
        const ECDH_AES_KW: u64 = 0x1053;
        const ECDSA: u64 = 0x1041;
        const XTS: u64 = 0x1071;
        const AES_CBC: u64 = 0x1082;
        const RSA_PKCS: u64 = 0x0001;
        const CONCAT: u64 = 0x0360;
        const HKDF: u64 = 0x402A;
        const XEDDSA: u64 = 0x4029;
        let rsa = EstablishedKind::Rsa { bits: 2048 };
        let mont = EstablishedKind::Montgomery;
        let edw = EstablishedKind::Edwards {
            curve: SafeCurve::Ed25519,
        };
        let generic = EstablishedKind::GenericSecret { bytes: 32 };
        let hkdf = EstablishedKind::Hkdf { bytes: 32 };
        let aes = EstablishedKind::Aes { bytes: 16 };
        let xts = EstablishedKind::AesXts;
        // Same-name pairs.
        assert!(families_compatible(KeyFamily::Rsa, RSA_PKCS, rsa));
        assert!(families_compatible(
            KeyFamily::Ec,
            ECDSA,
            EstablishedKind::Ec {
                curve: SafeCurve::Secp256r1
            }
        ));
        assert!(families_compatible(KeyFamily::Aes, AES_CBC, aes));
        assert!(families_compatible(KeyFamily::Hkdf, HKDF, hkdf));
        // X25519 + ECDH1 compatible (qualified); ECMQV/ECDSA are not.
        assert!(families_compatible(KeyFamily::Ec, ECDH1, mont));
        assert!(families_compatible(KeyFamily::Ec, ECDH1_COF, mont));
        assert!(families_compatible(KeyFamily::Ec, ECDH_AES_KW, mont));
        assert!(!families_compatible(KeyFamily::Ec, ECMQV, mont));
        assert!(!families_compatible(KeyFamily::Ec, ECDSA, mont));
        // Generic-secret + HKDF cross-compatible (TLS 1.3 case).
        assert!(families_compatible(KeyFamily::Hkdf, HKDF, generic));
        assert!(families_compatible(KeyFamily::GenericSecret, HKDF, hkdf));
        // XTS only under XTS.
        assert!(families_compatible(KeyFamily::Aes, XTS, xts));
        assert!(!families_compatible(KeyFamily::Aes, AES_CBC, xts));
        // XEDDSA + Montgomery compatible, + Edwards conflicting.
        assert!(families_compatible(KeyFamily::Xeddsa, XEDDSA, mont));
        assert!(!families_compatible(KeyFamily::Xeddsa, XEDDSA, edw));
        // RSA-established + ECDSA-inferred conflicting.
        assert!(!families_compatible(KeyFamily::Ec, ECDSA, rsa));
        // `secret` never flips, either direction, any established kind.
        for established in [rsa, mont, edw, generic, hkdf, aes, xts] {
            assert!(families_compatible(KeyFamily::Secret, CONCAT, established));
        }
        // des2/des3 inert: unlisted kinds never arrive, and same-name
        // pairs hold where the table names them.
        assert!(families_compatible(
            KeyFamily::Des3,
            0x132,
            EstablishedKind::Des3
        ));
        assert!(families_compatible(
            KeyFamily::Des3,
            0x132,
            EstablishedKind::Des2
        ));
        assert!(!families_compatible(
            KeyFamily::Des,
            0x121,
            EstablishedKind::Des3
        ));
        // Cross-name default: everything else conflicts.
        assert!(!families_compatible(KeyFamily::Rsa, RSA_PKCS, aes));
        assert!(!families_compatible(KeyFamily::Aes, AES_CBC, rsa));
        assert!(!families_compatible(
            KeyFamily::Chacha20,
            0x1226,
            EstablishedKind::Poly1305
        ));
    }

    /// The remaining §4.5 same-name rows (R3 top-up): every
    /// same-name-only pair holds, and cross pairs conflict.
    #[test]
    fn compat_same_name_matrix() {
        use EstablishedKind as E;
        use KeyFamily as F;
        for (family, mechanism, established) in [
            (F::Dsa, 0x0011u64, E::Dsa),
            (F::Dh, 0x0021u64, E::Dh),
            (F::Dh, 0x0031u64, E::X9_42Dh),
            (F::MlKem, 0x0017u64, E::MlKem { set: "ml_kem_768" }),
            (F::MlDsa, 0x001Du64, E::MlDsa { set: "ml_dsa_65" }),
            (
                F::SlhDsa,
                0x002Eu64,
                E::SlhDsa {
                    set: "slh_dsa_128s",
                },
            ),
            (F::Chacha20, 0x1226u64, E::Chacha20),
            (F::Poly1305, 0x1228u64, E::Poly1305),
            (F::Des, 0x0121u64, E::Des),
            (F::Des3, 0x0132u64, E::Des3),
            (F::Camellia, 0x0551u64, E::Camellia),
            (F::Aria, 0x0561u64, E::Aria),
            (F::Seed, 0x0651u64, E::Seed),
            (F::Gost, 0x1221u64, E::Gost),
            (
                F::Eddsa,
                0x1057u64,
                E::Edwards {
                    curve: SafeCurve::Ed25519,
                },
            ),
        ] {
            assert!(
                families_compatible(family, mechanism, established),
                "{family:?} holds its name"
            );
        }
        // Cross pairs conflict (same-name-only rows).
        assert!(!families_compatible(
            F::MlKem,
            0x0017,
            E::MlDsa { set: "ml_dsa_65" }
        ));
        assert!(!families_compatible(F::Des, 0x0121, E::Des3));
        assert!(!families_compatible(F::Eddsa, 0x1057, E::Montgomery));
        assert!(!families_compatible(F::Dh, 0x0021, E::Rsa { bits: 2048 }));
    }

    /// §3 size compatibility: family gate first, then exact size
    /// params; demonstrable contradiction only.
    #[test]
    fn size_compatible_matrix() {
        use EstablishedKind as E;
        let rsa_2048 = SizeDetail::Rsa {
            size_class: Some(2048),
            modulus_bytes: 256,
        };
        // RSA bytes against established bits.
        assert!(size_compatible(&rsa_2048, 0x0001, E::Rsa { bits: 2048 }));
        assert!(!size_compatible(&rsa_2048, 0x0001, E::Rsa { bits: 1024 }));
        assert!(size_compatible(&rsa_2048, 0x0001, E::Rsa { bits: 2041 }));
        assert!(!size_compatible(&rsa_2048, 0x0001, E::Aes { bytes: 16 }));
        // EC field octets against established curves.
        let p256 = SizeDetail::Ec {
            curve: "p256",
            octets: 64,
        };
        assert!(size_compatible(
            &p256,
            0x1044,
            E::Ec {
                curve: SafeCurve::Secp256r1
            }
        ));
        assert!(!size_compatible(
            &p256,
            0x1044,
            E::Ec {
                curve: SafeCurve::Secp384r1
            }
        ));
        assert!(!size_compatible(&p256, 0x1044, E::Montgomery));
        // Edwards curves.
        let ed25519 = SizeDetail::Eddsa {
            curve: "ed25519",
            octets: 64,
        };
        assert!(size_compatible(
            &ed25519,
            0x1057,
            E::Edwards {
                curve: SafeCurve::Ed25519
            }
        ));
        assert!(!size_compatible(
            &ed25519,
            0x1057,
            E::Edwards {
                curve: SafeCurve::Ed448
            }
        ));
        // PQC sets.
        let kem_768 = SizeDetail::PqcSet {
            parameter_set: "ml_kem_768",
            octets: 1088,
        };
        assert!(size_compatible(
            &kem_768,
            0x0017,
            E::MlKem { set: "ml_kem_768" }
        ));
        assert!(!size_compatible(
            &kem_768,
            0x0017,
            E::MlKem { set: "ml_kem_512" }
        ));
        assert!(!size_compatible(
            &kem_768,
            0x0017,
            E::MlDsa { set: "ml_dsa_65" }
        ));
        // Wrapped material against exact secret lengths; unmeasurable
        // pairs stay compatible.
        let wrapped_16 = SizeDetail::WrappedMaterial {
            material_octets: 16,
            octets: 24,
        };
        assert!(size_compatible(&wrapped_16, 0x2109, E::Aes { bytes: 16 }));
        assert!(!size_compatible(&wrapped_16, 0x2109, E::Aes { bytes: 32 }));
        assert!(size_compatible(&wrapped_16, 0x2109, E::Rsa { bits: 2048 }));
        assert!(size_compatible(
            &wrapped_16,
            0x2109,
            E::Ec {
                curve: SafeCurve::Secp256r1
            }
        ));
    }

    /// Every §5.2 triple: standard RSA classes, masked non-standard
    /// octets, the hybrid exclusion, ECDSA curves + DER negative,
    /// EdDSA/XEdDSA, PQC sets, DSA classes, AES-KW wrapped material +
    /// U1 shape, padded-wrap ambiguity, and every negative family.
    #[test]
    fn size_triples() {
        use EvidenceTag::*;
        const RSA_PKCS: u64 = 0x0001;
        const RSA_AES_KW: u64 = 0x1054;
        const ECDSA: u64 = 0x1041;
        const EDDSA: u64 = 0x1057;
        const XEDDSA: u64 = 0x4029;
        const ML_KEM: u64 = 0x0017;
        const ML_DSA: u64 = 0x001D;
        const SLH_DSA: u64 = 0x002E;
        const DSA: u64 = 0x0011;
        const AES_KW: u64 = 0x2109;
        const AES_KWP: u64 = 0x210B;
        const AES_GCM: u64 = 0x1087;
        const HMAC: u64 = 0x0251;
        const DES_ECB: u64 = 0x0121;
        const CHACHA20: u64 = 0x1226;
        // Standard RSA octet lengths name the standard size.
        for (octets, class) in [(128, 1024), (256, 2048), (384, 3072), (512, 4096)] {
            assert_eq!(
                classify_size(Some(RSA_PKCS), SignOutput, octets),
                SizeOutcome::Inferred(SizeDetail::Rsa {
                    size_class: Some(class),
                    modulus_bytes: octets,
                }),
                "{octets} octets"
            );
        }
        // The 2041-bit control shape: 256 bytes classifies 2048 with
        // the byte count beside it (the metadata_at_use pin is at the
        // reducer seam).
        assert_eq!(
            classify_size(Some(RSA_PKCS), SignOutput, 256),
            SizeOutcome::Inferred(SizeDetail::Rsa {
                size_class: Some(2048),
                modulus_bytes: 256,
            })
        );
        // Non-standard admitted octets mask the class, byte count only.
        assert_eq!(
            classify_size(Some(RSA_PKCS), SignOutput, 257),
            SizeOutcome::Inferred(SizeDetail::Rsa {
                size_class: None,
                modulus_bytes: 257,
            })
        );
        assert_eq!(
            classify_size(Some(RSA_PKCS), VerifyInput, 192),
            SizeOutcome::Inferred(SizeDetail::Rsa {
                size_class: None,
                modulus_bytes: 192,
            })
        );
        // Outside 64..=2048 is unsupported (anti-alias bound).
        assert_eq!(
            classify_size(Some(RSA_PKCS), SignOutput, 63),
            SizeOutcome::Unsupported {
                reason: REASON_OUTSIDE_ADMISSION_BOUND
            }
        );
        assert_eq!(
            classify_size(Some(RSA_PKCS), SignOutput, 2049),
            SizeOutcome::Unsupported {
                reason: REASON_OUTSIDE_ADMISSION_BOUND
            }
        );
        // The hybrid wrap sizes neither key.
        assert_eq!(
            classify_size(Some(RSA_AES_KW), WrapOutput, 296),
            SizeOutcome::Unknown {
                reason: REASON_HYBRID_WRAP_FORMAT
            }
        );
        // ECDSA raw lengths name curves; anything else is DER/other.
        for (octets, curve) in [(64, "p256"), (96, "p384"), (132, "p521")] {
            assert_eq!(
                classify_size(Some(ECDSA), SignOutput, octets),
                SizeOutcome::Inferred(SizeDetail::Ec { curve, octets }),
                "{octets} octets"
            );
        }
        assert_eq!(
            classify_size(Some(ECDSA), VerifyInput, 70),
            SizeOutcome::Unknown {
                reason: REASON_VARIABLE_LENGTH_ENCODING
            }
        );
        // EdDSA fixed lengths determine the curve; XEdDSA never aliases.
        assert_eq!(
            classify_size(Some(EDDSA), SignOutput, 64),
            SizeOutcome::Inferred(SizeDetail::Eddsa {
                curve: "ed25519",
                octets: 64,
            })
        );
        assert_eq!(
            classify_size(Some(EDDSA), VerifyInput, 114),
            SizeOutcome::Inferred(SizeDetail::Eddsa {
                curve: "ed448",
                octets: 114,
            })
        );
        assert_eq!(
            classify_size(Some(EDDSA), SignOutput, 65),
            SizeOutcome::Unknown {
                reason: REASON_UNMAPPED_LENGTH
            }
        );
        assert_eq!(
            classify_size(Some(XEDDSA), SignOutput, 64),
            SizeOutcome::Unknown {
                reason: REASON_FAMILY_ONLY_SUBSET
            }
        );
        // PQC ciphertext/signature lengths name parameter sets.
        for (octets, set) in [
            (768, "ml_kem_512"),
            (1088, "ml_kem_768"),
            (1568, "ml_kem_1024"),
        ] {
            assert_eq!(
                classify_size(Some(ML_KEM), EncapsulateOutput, octets),
                SizeOutcome::Inferred(SizeDetail::PqcSet {
                    parameter_set: set,
                    octets,
                }),
                "{octets} octets"
            );
        }
        assert_eq!(
            classify_size(Some(ML_KEM), DecapsulateInput, 769),
            SizeOutcome::Unknown {
                reason: REASON_UNMAPPED_LENGTH
            }
        );
        for (octets, set) in [
            (2420, "ml_dsa_44"),
            (3309, "ml_dsa_65"),
            (4627, "ml_dsa_87"),
        ] {
            assert_eq!(
                classify_size(Some(ML_DSA), SignOutput, octets),
                SizeOutcome::Inferred(SizeDetail::PqcSet {
                    parameter_set: set,
                    octets,
                }),
                "{octets} octets"
            );
        }
        for (octets, set) in [
            (7856, "slh_dsa_128s"),
            (17088, "slh_dsa_128f"),
            (16224, "slh_dsa_192s"),
            (35664, "slh_dsa_192f"),
            (29792, "slh_dsa_256s"),
            (49856, "slh_dsa_256f"),
        ] {
            assert_eq!(
                classify_size(Some(SLH_DSA), VerifyInput, octets),
                SizeOutcome::Inferred(SizeDetail::PqcSet {
                    parameter_set: set,
                    octets,
                }),
                "{octets} octets"
            );
        }
        // DSA legacy classes.
        for (octets, label) in [
            (40, "dsa_1024"),
            (56, "dsa_2048_224"),
            (64, "dsa_2048_256_or_3072"),
        ] {
            assert_eq!(
                classify_size(Some(DSA), SignOutput, octets),
                SizeOutcome::Inferred(SizeDetail::DsaClass { label, octets }),
                "{octets} octets"
            );
        }
        // AES-KW output sizes the wrapped key (L-8); padded variants
        // are ambiguous; short outputs unmappable.
        assert_eq!(
            classify_size(Some(AES_KW), WrapOutput, 32),
            SizeOutcome::Inferred(SizeDetail::WrappedMaterial {
                material_octets: 24,
                octets: 32,
            })
        );
        assert_eq!(
            classify_size(Some(AES_KW), UnwrapInput, 40),
            SizeOutcome::Inferred(SizeDetail::WrappedMaterial {
                material_octets: 32,
                octets: 40,
            })
        );
        assert_eq!(
            classify_size(Some(AES_KWP), WrapOutput, 32),
            SizeOutcome::Unknown {
                reason: REASON_PADDING_AMBIGUITY
            }
        );
        assert_eq!(
            classify_size(Some(AES_KW), WrapOutput, 7),
            SizeOutcome::Unknown {
                reason: REASON_UNMAPPED_LENGTH
            }
        );
        // Closed negatives: HMAC/GCM/stream lengths, legacy ciphers,
        // unlisted mechanisms and kind mismatches never neighbor-map.
        assert_eq!(
            classify_size(Some(HMAC), SignOutput, 32),
            SizeOutcome::Unknown {
                reason: REASON_NO_LENGTH_MAP
            }
        );
        assert_eq!(
            classify_size(Some(AES_GCM), EncryptOutput, 100),
            SizeOutcome::Unknown {
                reason: REASON_NO_LENGTH_MAP
            }
        );
        assert_eq!(
            classify_size(Some(CHACHA20), EncryptOutput, 100),
            SizeOutcome::Unknown {
                reason: REASON_NO_LENGTH_MAP
            }
        );
        assert_eq!(
            classify_size(Some(DES_ECB), EncryptOutput, 64),
            SizeOutcome::Unsupported {
                reason: REASON_NO_LENGTH_MAP
            }
        );
        assert_eq!(
            classify_size(Some(0x0500), SignOutput, 256),
            SizeOutcome::Unknown {
                reason: REASON_UNLISTED_MECHANISM
            }
        );
        assert_eq!(
            classify_size(None, SignOutput, 256),
            SizeOutcome::Unknown {
                reason: REASON_UNLISTED_MECHANISM
            }
        );
        assert_eq!(
            classify_size(Some(RSA_PKCS), EncapsulateOutput, 256),
            SizeOutcome::Unknown {
                reason: REASON_NO_LENGTH_MAP
            }
        );
    }

    /// Category to evidence-kind mapping (reducer seam vocabulary).
    #[test]
    fn evidence_tags() {
        use EvidenceTag::*;
        for (category, expected) in [
            ("sign", Some(SignOutput)),
            ("sign_recover", Some(SignOutput)),
            ("verify", Some(VerifyInput)),
            ("encrypt", Some(EncryptOutput)),
            ("decrypt", Some(DecryptInput)),
            ("wrap", Some(WrapOutput)),
            ("unwrap", Some(UnwrapInput)),
            ("encapsulate", Some(EncapsulateOutput)),
            ("decapsulate", Some(DecapsulateInput)),
            ("verify_recover", None),
            ("derive", None),
            ("digest", None),
            ("generate_key", None),
            ("message_sign", None),
            ("operation", None),
            ("direct", None),
            ("unknown", None),
        ] {
            assert_eq!(evidence_tag_for_category(category), expected, "{category}");
        }
    }

    /// Evidence schema spellings, `-v` nouns, and size displays.
    #[test]
    fn evidence_and_size_spellings() {
        use EvidenceTag::*;
        for (tag, value, noun) in [
            (SignOutput, "sign_output", "signature"),
            (VerifyInput, "verify_input", "signature"),
            (EncryptOutput, "encrypt_output", "ciphertext"),
            (DecryptInput, "decrypt_input", "ciphertext"),
            (WrapOutput, "wrap_output", "wrap output"),
            (UnwrapInput, "unwrap_input", "unwrap input"),
            (EncapsulateOutput, "encapsulate_output", "ciphertext"),
            (DecapsulateInput, "decapsulate_input", "ciphertext"),
        ] {
            assert_eq!(evidence_value(tag), value);
            assert_eq!(evidence_noun(tag), noun);
        }
        // Masked classes never render a range.
        assert_eq!(masked_rsa_class(256), "2,0xx");
        assert_eq!(masked_rsa_class(192), "1,5xx");
        assert_eq!(masked_rsa_class(64), "5xx");
        // Concise labels.
        let rsa = SizeDetail::Rsa {
            size_class: Some(2048),
            modulus_bytes: 256,
        };
        assert_eq!(size_concise(&rsa), "RSA 2048");
        let masked = SizeDetail::Rsa {
            size_class: None,
            modulus_bytes: 257,
        };
        assert_eq!(size_concise(&masked), "RSA (non-standard length)");
        let ec = SizeDetail::Ec {
            curve: "p256",
            octets: 64,
        };
        assert_eq!(size_concise(&ec), "EC P-256");
        let pqc = SizeDetail::PqcSet {
            parameter_set: "ml_kem_768",
            octets: 1088,
        };
        assert_eq!(size_concise(&pqc), "ML-KEM-768");
        let wrapped = SizeDetail::WrappedMaterial {
            material_octets: 24,
            octets: 32,
        };
        assert_eq!(size_concise(&wrapped), "wrapped material 24 bytes");
        // Verbose fragments (§10.3 pins).
        assert_eq!(
            size_verbose(&rsa, SignOutput),
            "RSA 2048 (from signature length)"
        );
        assert_eq!(
            size_verbose(&masked, SignOutput),
            "RSA, 2,0xx-bit class (from signature length)"
        );
        assert_eq!(
            size_verbose(&ec, VerifyInput),
            "EC P-256 (from signature length)"
        );
        assert_eq!(
            size_verbose(&pqc, EncapsulateOutput),
            "ML-KEM-768 (from ciphertext length)"
        );
        assert_eq!(
            size_verbose(&wrapped, WrapOutput),
            "wrapped material 24 bytes (from 32-byte wrap output, about wrapped key)"
        );
        // Size-implied families (wrapped material types nothing).
        assert_eq!(size_family(&rsa), Some(KeyFamily::Rsa));
        assert_eq!(size_family(&ec), Some(KeyFamily::Ec));
        assert_eq!(size_family(&pqc), Some(KeyFamily::MlKem));
        assert_eq!(size_family(&wrapped), None);
    }

    /// Same-size comparison ignores evidence tags by construction
    /// (tags are not parameters): equal kinds with equal params match
    /// across tags; any param or kind difference does not.
    #[test]
    fn same_size_ignores_tags() {
        let rsa = || SizeDetail::Rsa {
            size_class: Some(2048),
            modulus_bytes: 256,
        };
        assert!(same_size(&rsa(), &rsa()));
        assert!(!same_size(
            &rsa(),
            &SizeDetail::Rsa {
                size_class: Some(3072),
                modulus_bytes: 384,
            }
        ));
        assert!(!same_size(
            &rsa(),
            &SizeDetail::Rsa {
                size_class: None,
                modulus_bytes: 256,
            }
        ));
        assert!(same_size(
            &SizeDetail::Ec {
                curve: "p256",
                octets: 64,
            },
            &SizeDetail::Ec {
                curve: "p256",
                octets: 64,
            }
        ));
        assert!(!same_size(
            &SizeDetail::Ec {
                curve: "p256",
                octets: 64,
            },
            &SizeDetail::Ec {
                curve: "p384",
                octets: 96,
            }
        ));
        assert!(!same_size(
            &rsa(),
            &SizeDetail::WrappedMaterial {
                material_octets: 24,
                octets: 32,
            }
        ));
    }

    /// Concise combined labels per size kind.
    #[test]
    fn concise_labels() {
        let rsa = SizeDetail::Rsa {
            size_class: Some(2048),
            modulus_bytes: 256,
        };
        assert_eq!(concise_label(KeyFamily::Rsa, &rsa), "RSA 2048");
        let masked = SizeDetail::Rsa {
            size_class: None,
            modulus_bytes: 257,
        };
        assert_eq!(
            concise_label(KeyFamily::Rsa, &masked),
            "RSA (non-standard length)"
        );
        let ec = SizeDetail::Ec {
            curve: "p256",
            octets: 64,
        };
        assert_eq!(concise_label(KeyFamily::Ec, &ec), "EC P-256");
        let eddsa = SizeDetail::Eddsa {
            curve: "ed25519",
            octets: 64,
        };
        assert_eq!(concise_label(KeyFamily::Eddsa, &eddsa), "Ed25519");
        let dsa = SizeDetail::DsaClass {
            label: "dsa_1024",
            octets: 40,
        };
        assert_eq!(concise_label(KeyFamily::Dsa, &dsa), "DSA 1024-bit class");
        let pqc = SizeDetail::PqcSet {
            parameter_set: "ml_kem_768",
            octets: 1088,
        };
        assert_eq!(concise_label(KeyFamily::MlKem, &pqc), "ML-KEM-768");
        let wrapped = SizeDetail::WrappedMaterial {
            material_octets: 24,
            octets: 32,
        };
        assert_eq!(
            concise_label(KeyFamily::Aes, &wrapped),
            "AES wrapped material 24 bytes"
        );
    }

    /// Verbose fragments for the remaining size kinds: DSA classes,
    /// EdDSA curves, PQC sets with the SHA-2/SHAKE ambiguity said
    /// aloud, and the U1 noun.
    #[test]
    fn verbose_fragments() {
        use EvidenceTag::*;
        let dsa = SizeDetail::DsaClass {
            label: "dsa_2048_224",
            octets: 56,
        };
        assert_eq!(
            size_verbose(&dsa, SignOutput),
            "DSA 2048/224 class (from signature length)"
        );
        let eddsa = SizeDetail::Eddsa {
            curve: "ed448",
            octets: 114,
        };
        assert_eq!(
            size_verbose(&eddsa, VerifyInput),
            "Ed448 (from signature length)"
        );
        let pqc = SizeDetail::PqcSet {
            parameter_set: "slh_dsa_128s",
            octets: 7856,
        };
        assert_eq!(
            size_verbose(&pqc, SignOutput),
            "SLH-DSA-128s (from signature length; SHA-2/SHAKE ambiguous)"
        );
        let ml = SizeDetail::PqcSet {
            parameter_set: "ml_kem_768",
            octets: 1088,
        };
        assert_eq!(
            size_verbose(&ml, DecapsulateInput),
            "ML-KEM-768 (from ciphertext length)"
        );
        let wrapped = SizeDetail::WrappedMaterial {
            material_octets: 24,
            octets: 32,
        };
        assert_eq!(
            size_verbose(&wrapped, UnwrapInput),
            "wrapped material 24 bytes (from 32-byte wrapped key)"
        );
        assert_eq!(
            size_verbose(
                &SizeDetail::Rsa {
                    size_class: Some(2048),
                    modulus_bytes: 256,
                },
                UnwrapInput,
            ),
            "RSA 2048 (from unwrap input length)"
        );
    }

    /// Reason display phrases (explicit, never mechanical).
    #[test]
    fn reason_displays() {
        for (reason, display) in [
            (REASON_UNLISTED_MECHANISM, "unlisted mechanism"),
            (
                REASON_OPERATION_KEY_ONLY,
                "mechanism types the operation key",
            ),
            (REASON_SIZE_INFERENCE_OFF, "needs --key-sizes"),
            (REASON_NO_LENGTH_EVIDENCE, "no length evidence"),
            (REASON_LENGTH_UNAVAILABLE, "length unavailable"),
            (REASON_HYBRID_WRAP_FORMAT, "hybrid wrap format"),
            (REASON_VARIABLE_LENGTH_ENCODING, "variable-length encoding"),
            (REASON_PADDING_AMBIGUITY, "padding ambiguity"),
            (REASON_UNMAPPED_LENGTH, "unmapped length"),
            (REASON_NO_LENGTH_MAP, "no length map for this mechanism"),
            (REASON_FAMILY_ONLY_SUBSET, "family-only mechanism"),
            (REASON_OUTSIDE_ADMISSION_BOUND, "outside admission bound"),
        ] {
            assert_eq!(reason_display(reason), display, "{reason}");
        }
    }
}
