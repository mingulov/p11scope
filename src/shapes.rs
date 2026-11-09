//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Bridges pkcs11-types' shared mechanism registry to the BPF `MECH_SHAPE`
//! map. *Which* mechanisms have decodable parameters comes from the
//! registry (config), not a hardcoded mechanism-id list (code) — so
//! scope and proxy speak one dialect and vendor mechanisms are handled
//! by config alone. An unrecognized or absent shape always maps to
//! `shape::NONE`: that is the safe default when anything goes wrong.

use anyhow::{Context as _, Result, bail};
use aya::Ebpf;
use aya::maps::{HashMap, MapType};
use p11scope_ebpf_common::{MAX_MECH_SHAPES, shape};
use pkcs11_types::{PKCS11_3_2_OFFICIAL_MECHANISMS, mechanism_registry::MechanismRegistry};
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

/// Every mechanism id safe mode approves: the complete official 3.2
/// catalog plus configured registered ids. Presence is approval; the value is
/// only an optional decoder shape. When the union exceeds `MECH_SHAPE`
/// capacity, [`select_publishable`] publishes the official-first prefix and
/// the unpublished tail keeps counting through the unregistered path.
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

/// The deterministic publishable prefix of an approval union, capped at
/// `MECH_SHAPE` capacity: the official PKCS#11 3.2 catalog first
/// (ascending), then the remaining registered ids (ascending). Returns the
/// subset to publish and how many approved ids stay unpublished.
pub fn select_publishable(approved: &BTreeMap<u64, u32>) -> (BTreeMap<u64, u32>, u64) {
    let cap = MAX_MECH_SHAPES as usize;
    if approved.len() <= cap {
        return (approved.clone(), 0);
    }
    let official: std::collections::BTreeSet<u64> = PKCS11_3_2_OFFICIAL_MECHANISMS
        .iter()
        .map(|mechanism| mechanism.0)
        .collect();
    let mut subset = BTreeMap::new();
    for (id, code) in approved.iter().filter(|(id, _)| official.contains(id)) {
        if subset.len() >= cap {
            break;
        }
        subset.insert(*id, *code);
    }
    for (id, code) in approved.iter().filter(|(id, _)| !official.contains(id)) {
        if subset.len() >= cap {
            break;
        }
        subset.insert(*id, *code);
    }
    let unpublished = approved.len() as u64 - subset.len() as u64;
    (subset, unpublished)
}

/// The shaped subset of the publishable prefix: what render may claim a
/// published shape for (see [`expected_shapes`]). Ids approved but
/// unpublished have no published shape, so they read "no diagnostic
/// shape", never "decode failed".
pub fn published_expected_shapes(reg: &MechanismRegistry) -> BTreeMap<u64, u32> {
    let approved = approved_mechanisms(reg);
    let (published, _) = select_publishable(&approved);
    let mut shaped = expected_shapes(reg);
    shaped.retain(|id, _| published.contains_key(id));
    shaped
}

/// What one `MECH_SHAPE` publication established: how many approved
/// mechanisms were published and how many stayed unpublished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShapePublication {
    pub published: usize,
    pub unpublished: u64,
}

/// Publishes the publishable prefix of the approved mechanism union (see
/// [`select_publishable`]), verifies exact readback of what was published,
/// and returns the publication counts. An oversized union no longer
/// refuses the session: the unpublished tail is gapped by count.
pub fn publish(ebpf: &mut Ebpf, reg: &MechanismRegistry) -> Result<ShapePublication> {
    let approved = approved_mechanisms(reg);
    let (expected, unpublished) = select_publishable(&approved);
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
        bail!("MECH_SHAPE exact readback differs from the published mechanism subset");
    }
    Ok(ShapePublication {
        published: expected.len(),
        unpublished,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::MAX_MECH_SHAPES;
    use pkcs11_types::{DiscoveryMode, PKCS11_3_2_OFFICIAL_MECHANISMS};
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
        // This count belongs to pkcs11-types 0.2.3 from crates.io (Cargo.toml).
        // A version change is a deliberate catalog decision, not a number
        // to update casually. The official 3.2 catalog is unchanged at 463;
        // the approved union adds the two proposed 3.3 external-mu
        // registrations (0x403b/0x403c) from the embedded default registry.
        let official = PKCS11_3_2_OFFICIAL_MECHANISMS
            .iter()
            .map(|mechanism| mechanism.0)
            .collect::<BTreeSet<_>>();
        assert_eq!(official.len(), 463);

        let registry = MechanismRegistry::load(None).expect("load embedded registry");
        let approved = approved_mechanisms(&registry);
        assert_eq!(
            approved.len(),
            465,
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
    fn approval_overflow_partitions_exactly_into_published_and_count() {
        // Ruling JK-22a: overflow no longer refuses; the subset and the
        // unpublished count partition the union exactly — nothing is
        // invented, dropped silently, or published twice.
        let oversized = (0..=u64::from(MAX_MECH_SHAPES))
            .map(|id| (id, shape::NONE))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(oversized.len(), MAX_MECH_SHAPES as usize + 1);

        let (subset, unpublished) = select_publishable(&oversized);
        assert_eq!(subset.len(), MAX_MECH_SHAPES as usize);
        assert_eq!(unpublished, 1);
        let tail: Vec<u64> = oversized
            .keys()
            .filter(|id| !subset.contains_key(id))
            .copied()
            .collect();
        assert_eq!(tail.len() as u64, unpublished);
        assert_eq!(subset.len() + tail.len(), oversized.len());
        assert!(
            subset.keys().all(|id| oversized.contains_key(id)),
            "the subset publishes approved ids only"
        );
    }

    #[test]
    fn approval_overflow_publishes_the_official_first_subset() {
        // Ruling JK-22a: an oversized approval union publishes a
        // deterministic official-first subset instead of refusing the
        // session; the rest is gapped by count.
        let official: BTreeSet<u64> = PKCS11_3_2_OFFICIAL_MECHANISMS
            .iter()
            .map(|mechanism| mechanism.0)
            .collect();
        let mut approved: BTreeMap<u64, u32> =
            official.iter().map(|id| (*id, shape::NONE)).collect();
        // Vendor ids from zero upward, skipping official members: they
        // interleave below official ids, so naive truncation would drop
        // official mechanisms while the subset must keep every one.
        let mut vendor = 0u64;
        let mut added = 0;
        while added < 600 {
            if !official.contains(&vendor) {
                approved.insert(vendor, shape::NONE);
                added += 1;
            }
            vendor += 1;
        }
        assert_eq!(approved.len(), official.len() + 600);

        let (subset, unpublished) = select_publishable(&approved);
        assert_eq!(subset.len(), MAX_MECH_SHAPES as usize);
        assert_eq!(
            unpublished,
            approved.len() as u64 - u64::from(MAX_MECH_SHAPES)
        );
        assert!(
            official.iter().all(|id| subset.contains_key(id)),
            "every official id publishes first"
        );
        let unpublished_ids: Vec<u64> = approved
            .keys()
            .filter(|id| !subset.contains_key(id))
            .copied()
            .collect();
        assert_eq!(unpublished_ids.len() as u64, unpublished);
        assert!(
            unpublished_ids.iter().all(|id| !official.contains(id)),
            "the unpublished tail is vendor-only: {unpublished_ids:?}"
        );
        // Deterministic: the same union always selects the same subset.
        let (again, unpublished_again) = select_publishable(&approved);
        assert_eq!(subset, again);
        assert_eq!(unpublished, unpublished_again);
    }

    #[test]
    fn approval_within_capacity_publishes_the_whole_union() {
        let registry = MechanismRegistry::load(None).expect("load embedded registry");
        let approved = approved_mechanisms(&registry);
        assert!(approved.len() <= MAX_MECH_SHAPES as usize);

        let (subset, unpublished) = select_publishable(&approved);
        assert_eq!(unpublished, 0);
        assert_eq!(subset, approved, "no overflow: everything publishes");
    }
}
