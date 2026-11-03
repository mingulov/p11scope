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

/// Load the mechanism registry with the p11scope vendor overlay applied.
pub fn load_registry() -> Result<MechanismRegistry, String> {
    MechanismRegistry::load(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::{MAX_MECH_SHAPES, shape};

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
}
