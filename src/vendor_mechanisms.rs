//! SPDX-License-Identifier: GPL-3.0-or-later
//! p11scope-owned vendor mechanism overlay.
//!
//! The BPF return path publishes a mechanism id only on exact membership
//! in the `MECH_SHAPE` approval union (`shapes::approved_mechanisms`):
//! the official PKCS#11 3.2 catalog plus the ids registered in the
//! `pkcs11-types` mechanism registry. Anything else is counted as
//! `unregistered_mechanisms` and withheld, by the allowlist-v1 finite
//! published set rule.
//!
//! NSS softoken performs TLS ephemeral key generation under vendor ids
//! (`CKM_NSS_ECDHE_NO_PAIRWISE_CHECK_KEY_PAIR_GEN` for every ECDHE share
//! including X25519, `CKM_NSS_ML_KEM_KEY_PAIR_GEN` for every ML-KEM share;
//! older NSS used `CKM_NSS_KYBER_KEY_PAIR_GEN`), so every
//! `C_GenerateKeyPair` call was withheld even though seeing that a key
//! was created is explicitly not a privacy problem (owner, 2026-11-03).
//! This module extends the registry with a fixed, named, p11scope-owned
//! set of well-known vendor key-creation/derivation mechanisms. Every
//! overlay id is published with `shape::NONE`: counted and named, never
//! parameter-decoded. Unknown vendor ids stay withheld.

use pkcs11_types::mechanism_registry::MechanismRegistry;

/// Well-known vendor key-creation/derivation mechanisms, `(id, name)`
/// sorted by id. Source: NSS `lib/util/pkcs11n.h` (`CKM_NSS` =
/// `0xCE534350`); every entry was confirmed exposed by a real softoken
/// (snap Firefox build and/or system NSS 3.120) via
/// `C_GetMechanismList`. Purpose-filtered: pure cipher/digest/auth ids
/// (`CHACHA20_POLY1305`, `CHACHA20_CTR`, constant-time MACs), unassigned
/// gaps, the `PUB_FROM_PRIV` id no surveyed softoken exposes, and the
/// historical `0x8000000x` / `CKM_TLS_PRF_GENERAL` ids are excluded.
/// This count is a deliberate catalog decision, not a number to update
/// casually.
pub const VENDOR_MECHANISMS: &[(u64, &str)] = &[
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
];

/// The registry overlay, generated from the single table above so the
/// approval set and the name set cannot desync. Every vendor id is
/// `parameterless`: the registry records the id but no parameter shape,
/// which is approval without decoding.
fn overlay_toml() -> String {
    let ids = VENDOR_MECHANISMS
        .iter()
        .map(|&(id, _)| format!("0x{id:X}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("parameterless = [{ids}]")
}

/// `CKM_*` display name for an overlay vendor id, or `None` for any
/// other id. Names come from NSS `pkcs11n.h`, never guessed.
pub fn vendor_mechanism_name(id: u64) -> Option<&'static str> {
    VENDOR_MECHANISMS
        .iter()
        .find_map(|&(entry, name)| (entry == id).then_some(name))
}

/// Load the mechanism registry with the p11scope vendor overlay applied.
pub fn load_registry() -> Result<MechanismRegistry, String> {
    MechanismRegistry::load_with_override_str(Some(&overlay_toml()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::{MAX_MECH_SHAPES, shape};
    use std::collections::BTreeSet;

    /// NSS TLS ephemeral key-pair generation, per NSS `lib/util/pkcs11n.h`
    /// (`CKM_NSS` = `0xCE534350`): ECDHE (+47, every curve including
    /// X25519 — `lib/ssl/ssl3ecc.c` `ssl_CreateECDHEPrivateKey`), ML-KEM
    /// (+48 — `lib/ssl/tls13con.c` `tls13_CreateKEMKeyPair`), and legacy
    /// Kyber (+45, still exposed by system NSS 3.120).
    const CKM_NSS_ECDHE_NO_PAIRWISE_CHECK_KEY_PAIR_GEN: u64 = 0xCE53_437F;
    const CKM_NSS_ML_KEM_KEY_PAIR_GEN: u64 = 0xCE53_4380;
    const CKM_NSS_KYBER_KEY_PAIR_GEN: u64 = 0xCE53_437D;

    #[test]
    fn nss_tls_keygen_ids_are_approved_without_param_shape() {
        let registry = load_registry().expect("overlay registry loads");
        let approved = crate::shapes::approved_mechanisms(&registry);
        for id in [
            CKM_NSS_ECDHE_NO_PAIRWISE_CHECK_KEY_PAIR_GEN,
            CKM_NSS_ML_KEM_KEY_PAIR_GEN,
            CKM_NSS_KYBER_KEY_PAIR_GEN,
        ] {
            assert_eq!(
                approved.get(&id),
                Some(&shape::NONE),
                "vendor keygen id 0x{id:x} must publish (counted, never decoded)"
            );
            assert_eq!(
                registry.param_shape(id),
                None,
                "vendor keygen id 0x{id:x} must never gain a parameter shape"
            );
        }
    }

    #[test]
    fn unassigned_vendor_ids_stay_withheld() {
        let registry = load_registry().expect("overlay registry loads");
        let approved = crate::shapes::approved_mechanisms(&registry);
        // Unassigned NSS gap (+89) and the codebase's unknown-vendor
        // sentinel: exact membership only, never a range.
        assert!(!approved.contains_key(&0xCE53_43A9));
        assert!(!approved.contains_key(&0x8000_1042));
    }

    #[test]
    fn overlay_keeps_mech_shape_capacity() {
        let registry = load_registry().expect("overlay registry loads");
        let approved = crate::shapes::approved_mechanisms(&registry);
        assert!(
            approved.len() <= MAX_MECH_SHAPES as usize,
            "approval union has {} entries but MECH_SHAPE holds only {MAX_MECH_SHAPES}",
            approved.len()
        );
    }

    #[test]
    fn overlay_registers_exactly_the_named_table() {
        assert_eq!(
            VENDOR_MECHANISMS.len(),
            41,
            "the overlay catalog is a deliberate decision; changing it is a reviewable change"
        );
        let base = MechanismRegistry::load(None).expect("base registry loads");
        let overlaid = load_registry().expect("overlay registry loads");
        let base_ids: BTreeSet<u64> = base.registered_mechanisms().into_iter().collect();
        let overlaid_ids: BTreeSet<u64> = overlaid.registered_mechanisms().into_iter().collect();
        let added: Vec<u64> = overlaid_ids.difference(&base_ids).copied().collect();
        let table: Vec<u64> = VENDOR_MECHANISMS.iter().map(|&(id, _)| id).collect();
        assert_eq!(added, table, "overlay must add exactly the table, sorted");
        for &(id, name) in VENDOR_MECHANISMS {
            assert!(
                overlaid.is_parameterless(id),
                "overlay id 0x{id:x} must be parameterless"
            );
            assert_eq!(overlaid.param_shape(id), None);
            assert_eq!(vendor_mechanism_name(id), Some(name));
        }
    }
}
