//! Bridges proxy-ng's shared mechanism registry to the BPF `MECH_SHAPE`
//! map. *Which* mechanisms have decodable parameters comes from the
//! registry (config), not a hardcoded mechanism-id list (code) — so
//! scope and proxy speak one dialect and vendor mechanisms are handled
//! by config alone. An unrecognized or absent shape always maps to
//! `shape::NONE`: that is the safe default when anything goes wrong.

use anyhow::{Context as _, Result};
use aya::Ebpf;
use aya::maps::HashMap;
use p11scope_ebpf_common::shape;
use pkcs11_proxy_ng_types::mechanism_registry::MechanismRegistry;

/// Maps the registry's shape string to a BPF shape code. Only shapes
/// this phase decodes get a non-NONE code; everything else — including
/// any string the registry might add later — degrades to NONE.
///
/// Verified against the embedded-default registry (rev pinned in
/// Cargo.toml): `CKM_RSA_PKCS_PSS` and `CKM_SHA256_RSA_PKCS_PSS` both
/// report shape `"rsa_pss"` (not `"rsa_pkcs_pss"` — the brief's
/// alternate spelling to check for), and `CKM_AES_GCM` reports `"gcm"`.
pub fn code_for(shape_name: &str) -> u32 {
    match shape_name {
        "rsa_pss" => shape::RSA_PKCS_PSS,
        "gcm" => shape::GCM,
        _ => shape::NONE,
    }
}

/// Every registered mechanism id whose shape maps to a non-NONE code,
/// mapped to that code — exactly the set `publish` writes into the BPF
/// `MECH_SHAPE` map. Exposed so userspace can also answer "does this
/// mechanism id have an allowlisted parameter shape at all" without a
/// second registry parse — e.g. `semantics::State` uses this to tell "no
/// decodable shape" apart from "a decodable shape whose decode failed on
/// every observed call" (see `render`'s `mechanisms[].note`).
pub fn expected_shapes(reg: &MechanismRegistry) -> std::collections::BTreeMap<u64, u32> {
    reg.registered_mechanisms()
        .into_iter()
        .filter_map(|mech| reg.param_shape(mech).map(|name| (mech, code_for(name))))
        .filter(|&(_, code)| code != shape::NONE)
        .collect()
}

/// Publishes MECH_SHAPE from the registry: every registered mechanism
/// whose shape maps to a non-NONE code gets an entry. Returns how many
/// were published. Called once, before uprobes attach — same
/// publish-before-attach pattern `SLOT_SEMANTICS` uses, for the same reason:
/// a probe that fires before its shape is published must decode
/// nothing, and NONE is that safe default.
pub fn publish(ebpf: &mut Ebpf, reg: &MechanismRegistry) -> Result<usize> {
    let mut shapes: HashMap<_, u64, u32> =
        HashMap::try_from(ebpf.map_mut("MECH_SHAPE").context("MECH_SHAPE map")?)?;
    let expected = expected_shapes(reg);
    for (&mech, &code) in &expected {
        shapes.insert(mech, code, 0)?;
    }
    Ok(expected.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_for_maps_known_shapes() {
        assert_eq!(code_for("rsa_pss"), shape::RSA_PKCS_PSS);
        assert_eq!(code_for("gcm"), shape::GCM);
    }

    #[test]
    fn code_for_defaults_to_none_for_unknown_or_empty() {
        assert_eq!(code_for(""), shape::NONE);
        assert_eq!(code_for("rsa_pkcs_pss"), shape::NONE);
        assert_eq!(code_for("ecdh1_derive"), shape::NONE);
        assert_eq!(code_for("totally-made-up"), shape::NONE);
    }

    /// CKM_RSA_PKCS_PSS / CKM_SHA256_RSA_PKCS_PSS / CKM_AES_GCM, per the
    /// PKCS#11 mechanism id table.
    const CKM_RSA_PKCS_PSS: u64 = 0x0D;
    const CKM_SHA256_RSA_PKCS_PSS: u64 = 0x43;
    const CKM_AES_GCM: u64 = 0x1087;

    #[test]
    fn embedded_registry_shapes_known_ids_as_expected() {
        let reg = MechanismRegistry::load(None).expect("load embedded registry");
        assert_eq!(
            code_for(reg.param_shape(CKM_RSA_PKCS_PSS).unwrap()),
            shape::RSA_PKCS_PSS
        );
        assert_eq!(
            code_for(reg.param_shape(CKM_SHA256_RSA_PKCS_PSS).unwrap()),
            shape::RSA_PKCS_PSS
        );
        assert_eq!(code_for(reg.param_shape(CKM_AES_GCM).unwrap()), shape::GCM);
    }

    /// The full registered set, filtered through `code_for`, must include
    /// at least one GCM- and one PSS-shaped mechanism id — a regression
    /// guard for the mapping's real effect, not just the unit function.
    #[test]
    fn registry_shape_set_includes_gcm_and_pss_mechanisms() {
        let reg = MechanismRegistry::load(None).expect("load embedded registry");
        let shaped: Vec<(u64, u32)> = reg
            .registered_mechanisms()
            .into_iter()
            .filter_map(|m| reg.param_shape(m).map(|s| (m, code_for(s))))
            .filter(|(_, c)| *c != shape::NONE)
            .collect();
        assert!(
            !shaped.is_empty(),
            "expected at least one non-NONE shaped mechanism"
        );
        assert!(
            shaped
                .iter()
                .any(|&(id, c)| id == CKM_AES_GCM && c == shape::GCM),
            "expected CKM_AES_GCM among the GCM-shaped mechanisms"
        );
        assert!(
            shaped
                .iter()
                .any(|&(id, c)| id == CKM_RSA_PKCS_PSS && c == shape::RSA_PKCS_PSS),
            "expected CKM_RSA_PKCS_PSS among the PSS-shaped mechanisms"
        );
    }

    #[test]
    fn expected_shapes_matches_what_publish_would_write() {
        let reg = MechanismRegistry::load(None).expect("load embedded registry");
        let expected = expected_shapes(&reg);
        assert_eq!(expected.get(&CKM_AES_GCM), Some(&shape::GCM));
        assert_eq!(expected.get(&CKM_RSA_PKCS_PSS), Some(&shape::RSA_PKCS_PSS));
        assert!(!expected.is_empty());
        assert!(
            expected.values().all(|&c| c != shape::NONE),
            "NONE-shaped mechanisms must never appear in the published set"
        );
    }
}
