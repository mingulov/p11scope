//! Bridges proxy-ng's shared mechanism registry to the BPF `MECH_SHAPE`
//! map. *Which* mechanisms have decodable parameters comes from the
//! registry (config), not a hardcoded mechanism-id list (code) — so
//! scope and proxy speak one dialect and vendor mechanisms are handled
//! by config alone. An unrecognized or absent shape always maps to
//! `shape::NONE`: that is the safe default when anything goes wrong.

use anyhow::{Context as _, Result, bail};
use aya::Ebpf;
use aya::maps::{HashMap, MapType};
use p11scope_ebpf_common::{MAX_MECH_SHAPES, shape};
use pkcs11_proxy_ng_types::{
    PKCS11_3_2_OFFICIAL_MECHANISMS, mechanism_registry::MechanismRegistry,
};
use std::collections::BTreeMap;

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

/// Every registered mechanism whose configured parameter shape has a supported
/// decoder. This shaped-only view lets userspace distinguish "no decodable
/// shape" from "a decodable shape whose decode failed on every observed call"
/// (see `render`'s `mechanisms[].note`). `publish` additionally writes approved
/// unshaped mechanisms with `shape::NONE` so map presence remains authorization.
pub fn expected_shapes(reg: &MechanismRegistry) -> std::collections::BTreeMap<u64, u32> {
    reg.registered_mechanisms()
        .into_iter()
        .filter_map(|mech| reg.param_shape(mech).map(|name| (mech, code_for(name))))
        .filter(|&(_, code)| code != shape::NONE)
        .collect()
}

/// Every mechanism id safe mode may publish: the complete official 3.2
/// catalog plus configured registered ids. Presence is approval; the value is
/// only an optional decoder shape.
pub fn approved_mechanisms(reg: &MechanismRegistry) -> BTreeMap<u64, u32> {
    let mut approved = PKCS11_3_2_OFFICIAL_MECHANISMS
        .iter()
        .map(|mechanism| (mechanism.0, shape::NONE))
        .collect::<BTreeMap<_, _>>();
    for mechanism in reg.registered_mechanisms() {
        let code = reg
            .param_shape(mechanism)
            .map(code_for)
            .unwrap_or(shape::NONE);
        approved.insert(mechanism, code);
    }
    approved
}

fn ensure_approval_capacity(approved: &BTreeMap<u64, u32>) -> Result<()> {
    if approved.len() > MAX_MECH_SHAPES as usize {
        bail!(
            "mechanism approval union has {} entries but MECH_SHAPE holds only {}; refusing to publish a prefix",
            approved.len(),
            MAX_MECH_SHAPES
        );
    }
    Ok(())
}

/// Publishes the complete approved mechanism union, verifies exact readback,
/// and returns how many entries were published. Capacity is checked before the
/// first insert, so overflow cannot silently publish a prefix.
pub fn publish(ebpf: &mut Ebpf, reg: &MechanismRegistry) -> Result<usize> {
    let expected = approved_mechanisms(reg);
    ensure_approval_capacity(&expected)?;
    let info = crate::attach::policy_map_data(
        "MECH_SHAPE",
        ebpf.map("MECH_SHAPE").context("MECH_SHAPE map")?,
    )?
    .info()
    .context("reading MECH_SHAPE map info")?;
    if info.map_type()? != MapType::Hash || info.max_entries() != MAX_MECH_SHAPES {
        bail!(
            "MECH_SHAPE has type {:?} and capacity {}, expected Hash and {}",
            info.map_type()?,
            info.max_entries(),
            MAX_MECH_SHAPES
        );
    }
    let mut shapes: HashMap<_, u64, u32> =
        HashMap::try_from(ebpf.map_mut("MECH_SHAPE").context("MECH_SHAPE map")?)?;
    for (&mech, &code) in &expected {
        shapes.insert(mech, code, 0)?;
    }
    let shapes: HashMap<_, u64, u32> =
        HashMap::try_from(ebpf.map("MECH_SHAPE").context("MECH_SHAPE map")?)?;
    let actual = shapes.iter().collect::<Result<BTreeMap<_, _>, _>>()?;
    if actual != expected {
        bail!("MECH_SHAPE exact readback differs from the approved mechanism union");
    }
    Ok(expected.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::MAX_MECH_SHAPES;
    use pkcs11_proxy_ng_types::{DiscoveryMode, PKCS11_3_2_OFFICIAL_MECHANISMS};
    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

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
    fn expected_shapes_is_the_supported_decoder_subset() {
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

    #[test]
    fn approvals_are_the_exact_official_and_registered_union() {
        // This count belongs to the dependency pinned in Cargo.toml at
        // a2aab6cd67d21d140277a4584942e06c903f165b. A revision change is a
        // deliberate catalog decision, not a number to update casually.
        let official = PKCS11_3_2_OFFICIAL_MECHANISMS
            .iter()
            .map(|mechanism| mechanism.0)
            .collect::<BTreeSet<_>>();
        assert_eq!(official.len(), 463);

        let registry = MechanismRegistry::load(None).expect("load embedded registry");
        let approved = approved_mechanisms(&registry);
        assert_eq!(
            approved.len(),
            463,
            "official/registered overlap must deduplicate"
        );
        assert!(official.iter().all(|id| approved.contains_key(id)));
        assert_eq!(approved.get(&0), Some(&shape::NONE));
        assert_eq!(approved.get(&CKM_AES_GCM), Some(&shape::GCM));
    }

    #[test]
    fn configured_maximum_mechanism_id_is_preserved_as_data() {
        let registry = MechanismRegistry::from_parts(
            HashMap::new(),
            HashSet::from([u64::MAX]),
            DiscoveryMode::Transparent,
            "max-id-control".into(),
        );
        let approved = approved_mechanisms(&registry);

        assert_eq!(approved.len(), 464);
        assert_eq!(approved.get(&u64::MAX), Some(&shape::NONE));
    }

    #[test]
    fn approval_capacity_refuses_the_whole_oversized_union() {
        let oversized = (0..=u64::from(MAX_MECH_SHAPES))
            .map(|id| (id, shape::NONE))
            .collect::<BTreeMap<_, _>>();
        let error = ensure_approval_capacity(&oversized)
            .unwrap_err()
            .to_string();

        assert!(error.contains("1025"), "{error}");
        assert!(error.contains("1024"), "{error}");
        assert!(error.contains("refusing"), "{error}");
    }
}
