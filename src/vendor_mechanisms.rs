//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Display-only vendor mechanism names.
//!
//! Every observed mechanism id is counted and published by number
//! through the generic path: the BPF return path publishes ids at or
//! below `0xFFFFFFFF` with counts, and the userspace per-id table keys
//! rows by the exact id. No table gates any of that — this module is
//! only a naming layer on top. Removing it must change only the
//! displayed name, never counts, publication or JSON presence (pinned
//! by the render invariance test and the label test in
//! `mechanism_names`).
//!
//! Catalog rules (deliberate, reviewable): an id enters the table only
//! from an authoritative public vendor source (the vendor's public
//! PKCS#11 header or official documentation page, cited per family
//! below), only for key generation, key derivation or wrap/unwrap,
//! and only when no table entry already claims the number. Different
//! vendors can reuse one vendor-range number; a colliding number must
//! never gain one vendor's name (that would misattribute another
//! vendor's calls), so it stays out of the table and renders as the
//! generic bare number. The uniqueness test enforces this at commit
//! time and the lookup refuses to pick at run time.

/// Well-known vendor key-creation/derivation/wrap mechanisms, `(id,
/// name)` sorted by id: 41 NSS, 6 AWS CloudHSM, 4 Thales Luna and 2
/// Yubico ids. Per-family sources (every number below comes from one
/// of these, never guessed):
/// - NSS `lib/util/pkcs11n.h` (`CKM_NSS` = `0xCE534350`); every entry
///   was confirmed exposed by a real softoken (snap Firefox build
///   and/or system NSS 3.120) via `C_GetMechanismList`.
///   Purpose-filtered: pure cipher/digest/auth ids
///   (`CHACHA20_POLY1305`, `CHACHA20_CTR`, constant-time MACs),
///   unassigned gaps, the `PUB_FROM_PRIV` id no surveyed softoken
///   exposes, and the historical `0x8000000x` / `CKM_TLS_PRF_GENERAL`
///   ids are excluded.
/// - AWS CloudHSM Client SDK 5 `cloudhsm_pkcs11_vendor_defs.h` from
///   the public `cloudhsm-pkcs11-5.18.1` EL8 package
///   (`s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL8/`,
///   fetched 2026-11-10; `CKM_VENDOR_DEFINED |` the documented
///   offset or standard id, bases verified against the shipped
///   `pkcs11t.h`). Purpose-filtered: the pure sign/verify ids
///   (`CKM_CLOUDHSM_ML_DSA`, `CKM_CLOUDHSM_EXT_MU_ML_DSA`,
///   `CKM_CLOUDHSM_EDDSA`) stay unnamed; the deprecated
///   `CKM_SP800_108_COUNTER_KDF` alias shares its number with the
///   recommended `CKM_CLOUDHSM_SP800_108_COUNTER_KDF`, so only the
///   recommended name is listed. Wrap use of `CKM_CLOUDHSM_AES_GCM`
///   per the SDK 5 mechanisms documentation page.
/// - Yubico YubiHSM 2, yubihsm-shell master (fetched 2026-11-10):
///   `pkcs11/pkcs11y.h` (`YUBICO_BASE_VENDOR` = `0x59554200`) with
///   `YH_WRAP_KEY` = `0x04` / `YH_PUBLIC_WRAP_KEY` = `0x09` from
///   `lib/yubihsm.h`; both ids are exposed via
///   `C_GetMechanismList` (`pkcs11/util_pkcs11.c`) and used on the
///   wrap paths (`pkcs11/yubihsm_pkcs11.c`).
/// - Thales Luna, spelled exactly as the vendor spells them (their
///   names carry no vendor prefix): `CKM_NIST_PRF_KDF` /
///   `CKM_PRF_KDF` from the Luna Network HSM 7.1 counter-mode KDF
///   extensions page (13 December 2019;
///   `CKM_VENDOR_DEFINED + 0xA02/0xA03`, corroborated by the Luna 7
///   `hsm showmechanism` page), `CKM_ECDSA_KEY_PAIR_GEN_W_EXTRA_BITS`
///   / `CKM_SM3_KEY_DERIVATION` from the Luna JSP 7.1.0 `LunaAPI`
///   constant values (hosted in the Luna 7.7.0 PCI docs).
///   Purpose-filtered: pure cipher/sign/digest ids, `CKM_ECIES`
///   (encrypt) and the ids only the unobserved vendor cloning
///   functions carry stay unnamed.
///
/// This count is a deliberate catalog decision, not a number to update
/// casually.
pub const VENDOR_MECHANISMS: &[(u64, &str)] = &[
    // AWS CloudHSM (low run; the family continues past the Luna run
    // to keep the table sorted by id).
    (0x8000_0001, "CKM_CLOUDHSM_SP800_108_COUNTER_KDF"),
    (0x8000_001C, "CKM_CLOUDHSM_ML_DSA_KEY_PAIR_GEN"),
    // Thales Luna.
    (0x8000_0160, "CKM_ECDSA_KEY_PAIR_GEN_W_EXTRA_BITS"),
    (0x8000_0A02, "CKM_NIST_PRF_KDF"),
    (0x8000_0A03, "CKM_PRF_KDF"),
    (0x8000_0B04, "CKM_SM3_KEY_DERIVATION"),
    // AWS CloudHSM (high run).
    (0x8000_1087, "CKM_CLOUDHSM_AES_GCM"),
    (0x8000_2109, "CKM_CLOUDHSM_AES_KEY_WRAP_NO_PAD"),
    (0x8000_210A, "CKM_CLOUDHSM_AES_KEY_WRAP_PKCS5_PAD"),
    (0x8000_216F, "CKM_CLOUDHSM_AES_KEY_WRAP_ZERO_PAD"),
    // NSS.
    (0xCE53_4351, "CKM_NSS_AES_KEY_WRAP"),
    (0xCE53_4352, "CKM_NSS_AES_KEY_WRAP_PAD"),
    (0xCE53_4353, "CKM_NSS_HKDF_SHA1"),
    (0xCE53_4354, "CKM_NSS_HKDF_SHA256"),
    (0xCE53_4355, "CKM_NSS_HKDF_SHA384"),
    (0xCE53_4356, "CKM_NSS_HKDF_SHA512"),
    (0xCE53_4357, "CKM_NSS_JPAKE_ROUND1_SHA1"),
    (0xCE53_4358, "CKM_NSS_JPAKE_ROUND1_SHA256"),
    (0xCE53_4359, "CKM_NSS_JPAKE_ROUND1_SHA384"),
    (0xCE53_435A, "CKM_NSS_JPAKE_ROUND1_SHA512"),
    (0xCE53_435B, "CKM_NSS_JPAKE_ROUND2_SHA1"),
    (0xCE53_435C, "CKM_NSS_JPAKE_ROUND2_SHA256"),
    (0xCE53_435D, "CKM_NSS_JPAKE_ROUND2_SHA384"),
    (0xCE53_435E, "CKM_NSS_JPAKE_ROUND2_SHA512"),
    (0xCE53_435F, "CKM_NSS_JPAKE_FINAL_SHA1"),
    (0xCE53_4360, "CKM_NSS_JPAKE_FINAL_SHA256"),
    (0xCE53_4361, "CKM_NSS_JPAKE_FINAL_SHA384"),
    (0xCE53_4362, "CKM_NSS_JPAKE_FINAL_SHA512"),
    (0xCE53_4365, "CKM_NSS_TLS_PRF_GENERAL_SHA256"),
    (0xCE53_4366, "CKM_NSS_TLS_MASTER_KEY_DERIVE_SHA256"),
    (0xCE53_4367, "CKM_NSS_TLS_KEY_AND_MAC_DERIVE_SHA256"),
    (0xCE53_4368, "CKM_NSS_TLS_MASTER_KEY_DERIVE_DH_SHA256"),
    (0xCE53_4369, "CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE"),
    (0xCE53_436A, "CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_DH"),
    (0xCE53_436B, "CKM_NSS_CHACHA20_KEY_GEN"),
    (0xCE53_436D, "CKM_NSS_PKCS12_PBE_SHA224_HMAC_KEY_GEN"),
    (0xCE53_436E, "CKM_NSS_PKCS12_PBE_SHA256_HMAC_KEY_GEN"),
    (0xCE53_436F, "CKM_NSS_PKCS12_PBE_SHA384_HMAC_KEY_GEN"),
    (0xCE53_4370, "CKM_NSS_PKCS12_PBE_SHA512_HMAC_KEY_GEN"),
    (0xCE53_4372, "CKM_NSS_IKE_PRF_PLUS_DERIVE"),
    (0xCE53_4373, "CKM_NSS_IKE_PRF_DERIVE"),
    (0xCE53_4374, "CKM_NSS_IKE1_PRF_DERIVE"),
    (0xCE53_4375, "CKM_NSS_IKE1_APP_B_PRF_DERIVE"),
    (0xCE53_437A, "CKM_NSS_SP800_108_COUNTER_KDF_DERIVE_DATA"),
    (0xCE53_437B, "CKM_NSS_SP800_108_FEEDBACK_KDF_DERIVE_DATA"),
    (
        0xCE53_437C,
        "CKM_NSS_SP800_108_DOUBLE_PIPELINE_KDF_DERIVE_DATA",
    ),
    (0xCE53_437D, "CKM_NSS_KYBER_KEY_PAIR_GEN"),
    (0xCE53_437E, "CKM_NSS_KYBER"),
    (0xCE53_437F, "CKM_NSS_ECDHE_NO_PAIRWISE_CHECK_KEY_PAIR_GEN"),
    (0xCE53_4380, "CKM_NSS_ML_KEM_KEY_PAIR_GEN"),
    (0xCE53_4381, "CKM_NSS_ML_KEM"),
    // Yubico YubiHSM 2.
    (0xD955_4204, "CKM_YUBICO_AES_CCM_WRAP"),
    (0xD955_4209, "CKM_YUBICO_RSA_WRAP"),
];

/// Single-name lookup over an `(id, name)` table that refuses to
/// pick when an id collides: two vendors can reuse one vendor-range
/// number, and naming it for either would misattribute the other's
/// calls. A colliding id resolves to `None` (the caller renders the
/// generic bare number), never to one vendor's name.
fn name_in_table(table: &[(u64, &'static str)], id: u64) -> Option<&'static str> {
    let mut matches = table.iter().filter(|&&(entry, _)| entry == id);
    let (_, name) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(name)
}

/// `CKM_*` display name for a listed vendor id, or `None` for any
/// other id — including an id the table ever lists twice, which must
/// never resolve to one vendor's name. Names come from the
/// per-family vendor sources cited on [`VENDOR_MECHANISMS`], never
/// guessed. Display only: naming never affects counts, publication
/// or row presence.
pub fn vendor_mechanism_name(id: u64) -> Option<&'static str> {
    name_in_table(VENDOR_MECHANISMS, id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// NSS TLS ephemeral key-pair generation, per NSS `lib/util/pkcs11n.h`
    /// (`CKM_NSS` = `0xCE534350`): ECDHE (+47, every curve including
    /// X25519 — `lib/ssl/ssl3ecc.c` `ssl_CreateECDHEPrivateKey`), ML-KEM
    /// (+48 — `lib/ssl/tls13con.c` `tls13_CreateKEMKeyPair`), and legacy
    /// Kyber (+45, still exposed by system NSS 3.120).
    const CKM_NSS_ECDHE_NO_PAIRWISE_CHECK_KEY_PAIR_GEN: u64 = 0xCE53_437F;
    const CKM_NSS_ML_KEM_KEY_PAIR_GEN: u64 = 0xCE53_4380;
    const CKM_NSS_KYBER_KEY_PAIR_GEN: u64 = 0xCE53_437D;

    /// AWS CloudHSM Client SDK 5 key-derivation, key-generation and
    /// key-wrap mechanisms, per `cloudhsm_pkcs11_vendor_defs.h`
    /// (`CKM_VENDOR_DEFINED |` the documented offset or standard id).
    const CLOUDHSM_MECHANISMS: &[(u64, &str)] = &[
        (0x8000_0001, "CKM_CLOUDHSM_SP800_108_COUNTER_KDF"),
        (0x8000_001C, "CKM_CLOUDHSM_ML_DSA_KEY_PAIR_GEN"),
        (0x8000_1087, "CKM_CLOUDHSM_AES_GCM"),
        (0x8000_2109, "CKM_CLOUDHSM_AES_KEY_WRAP_NO_PAD"),
        (0x8000_210A, "CKM_CLOUDHSM_AES_KEY_WRAP_PKCS5_PAD"),
        (0x8000_216F, "CKM_CLOUDHSM_AES_KEY_WRAP_ZERO_PAD"),
    ];

    /// Yubico YubiHSM 2 wrap mechanisms, per yubihsm-shell
    /// `pkcs11/pkcs11y.h` (`CKM_VENDOR_DEFINED | YUBICO_BASE_VENDOR |
    /// object type`, with `YH_WRAP_KEY = 0x04` and
    /// `YH_PUBLIC_WRAP_KEY = 0x09` from `lib/yubihsm.h`).
    const YUBICO_MECHANISMS: &[(u64, &str)] = &[
        (0xD955_4204, "CKM_YUBICO_AES_CCM_WRAP"),
        (0xD955_4209, "CKM_YUBICO_RSA_WRAP"),
    ];

    /// Thales Luna key-generation and key-derivation mechanisms, per
    /// the Luna 7.1 counter-mode KDF extensions page (`CKM_PRF_KDF`,
    /// `CKM_NIST_PRF_KDF`) and the Luna JSP 7.1.0 `LunaAPI` constant
    /// values (`CKM_ECDSA_KEY_PAIR_GEN_W_EXTRA_BITS`,
    /// `CKM_SM3_KEY_DERIVATION`).
    const LUNA_MECHANISMS: &[(u64, &str)] = &[
        (0x8000_0160, "CKM_ECDSA_KEY_PAIR_GEN_W_EXTRA_BITS"),
        (0x8000_0A02, "CKM_NIST_PRF_KDF"),
        (0x8000_0A03, "CKM_PRF_KDF"),
        (0x8000_0B04, "CKM_SM3_KEY_DERIVATION"),
    ];

    fn assert_named_family(family: &[(u64, &str)]) {
        for &(id, name) in family {
            assert_eq!(vendor_mechanism_name(id), Some(name), "id 0x{id:x}");
        }
    }

    #[test]
    fn nss_tls_keygen_ids_are_named() {
        for id in [
            CKM_NSS_ECDHE_NO_PAIRWISE_CHECK_KEY_PAIR_GEN,
            CKM_NSS_ML_KEM_KEY_PAIR_GEN,
            CKM_NSS_KYBER_KEY_PAIR_GEN,
        ] {
            assert!(
                vendor_mechanism_name(id).is_some(),
                "vendor keygen id 0x{id:x} must resolve a display name"
            );
        }
        assert_eq!(
            vendor_mechanism_name(CKM_NSS_ECDHE_NO_PAIRWISE_CHECK_KEY_PAIR_GEN),
            Some("CKM_NSS_ECDHE_NO_PAIRWISE_CHECK_KEY_PAIR_GEN")
        );
        assert_eq!(
            vendor_mechanism_name(CKM_NSS_ML_KEM_KEY_PAIR_GEN),
            Some("CKM_NSS_ML_KEM_KEY_PAIR_GEN")
        );
        assert_eq!(
            vendor_mechanism_name(CKM_NSS_KYBER_KEY_PAIR_GEN),
            Some("CKM_NSS_KYBER_KEY_PAIR_GEN")
        );
    }

    #[test]
    fn cloudhsm_ids_are_named() {
        assert_named_family(CLOUDHSM_MECHANISMS);
    }

    #[test]
    fn yubico_ids_are_named() {
        assert_named_family(YUBICO_MECHANISMS);
    }

    #[test]
    fn luna_ids_are_named() {
        assert_named_family(LUNA_MECHANISMS);
    }

    #[test]
    fn unlisted_vendor_ids_have_no_name() {
        // Unassigned NSS gap (+89), the codebase's unknown-vendor
        // sentinel, and purpose-filtered ids: exact table membership
        // only, never a range.
        assert_eq!(vendor_mechanism_name(0xCE53_43A9), None);
        assert_eq!(vendor_mechanism_name(0x8000_1042), None);
        assert_eq!(vendor_mechanism_name(0x8000_001D), None);
        assert_eq!(vendor_mechanism_name(0x8000_0A00), None);
    }

    #[test]
    fn name_table_has_no_duplicate_ids() {
        // Collision detection: different vendors can reuse one
        // vendor-range number, and a colliding number must never gain
        // one vendor's name. Any future addition that reuses an id
        // fails here instead of silently misattributing calls.
        let mut seen = BTreeSet::new();
        for &(id, name) in VENDOR_MECHANISMS {
            assert!(
                seen.insert(id),
                "duplicate name-table id 0x{id:x} ({name}): leave a colliding number unnamed"
            );
        }
        let ids: Vec<u64> = VENDOR_MECHANISMS.iter().map(|&(id, _)| id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "name table must stay sorted by id");
    }

    #[test]
    fn colliding_vendor_id_resolves_to_no_name() {
        // Two vendors reusing one vendor-range number: the lookup
        // must not pick either name. A synthetic table (not catalog
        // entries) so the guard is pinned even though the real table
        // currently holds no collision.
        let table: &[(u64, &str)] = &[
            (0x8000_FFFF, "CKM_VENDOR_A_EXAMPLE"),
            (0x8000_FFFF, "CKM_VENDOR_B_EXAMPLE"),
            (0x8000_FFFE, "CKM_VENDOR_A_OTHER"),
        ];
        assert_eq!(name_in_table(table, 0x8000_FFFF), None);
        assert_eq!(
            name_in_table(table, 0x8000_FFFE),
            Some("CKM_VENDOR_A_OTHER")
        );
        assert_eq!(name_in_table(table, 0x8000_FFFD), None);
    }

    #[test]
    fn name_table_pins_fifty_three_sorted_ids() {
        assert_eq!(
            VENDOR_MECHANISMS.len(),
            53,
            "the name catalog is a deliberate decision; changing it is a reviewable change"
        );
        for &(id, name) in VENDOR_MECHANISMS {
            assert_eq!(vendor_mechanism_name(id), Some(name), "id 0x{id:x}");
        }
    }
}
