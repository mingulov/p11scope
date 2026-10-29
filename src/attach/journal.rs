//! SPDX-License-Identifier: GPL-3.0-or-later
//! Production journal-object selection, load contract and class fill.
//!
//! The production journal object is a Detailed object whose entry/return
//! roots are replaced by the journal pair (`p11_entry_journal` /
//! `p11_return_journal`) plus the four journal maps. It is built only by the
//! opt-in `P11SCOPE_JOURNAL=1` route; the private proof ELF is never selected
//! or embedded here. Loading stays unlinked: this module reports linkage as a
//! value the Session preparation consumes, and the seal/drain flags keep
//! their literal `false` until the activation packet wires them.

use super::instance::INSTANCE_PROGRAMS;
use super::selected_detailed::PROGRAMS as SELECTED_DETAILED_PROGRAMS;
use super::{
    BPF_F_RDONLY_PROG, DEFAULT_PROGRAMS, EmbeddedFlavor, ExactMapMetadata, map_metadata,
    validate_policy_map,
};
use crate::semantics_objects::journal::{EndpointClass, endpoint_class};
use anyhow::{Result, anyhow, bail};
use aya::Ebpf;
use aya::maps::MapType;
use p11scope_ebpf_common::MAX_DESCRIPTORS;
use std::collections::BTreeSet;

/// The journal entry/return pair replacing the ordinary roots.
pub(crate) const PROGRAMS: [&str; 2] = ["p11_entry_journal", "p11_return_journal"];

/// The ordinary roots a journal object must not carry.
const ORDINARY_PAIR: [&str; 2] = ["p11_entry", "p11_return"];

/// Exact metadata of the four journal maps. Shapes match the link-contract
/// pins; `JOURNAL_CLASSES` is userspace-filled before its deferred freeze.
const JOURNAL_MAPS: [(&str, ExactMapMetadata); 4] = [
    (
        "JOURNAL_START",
        map_metadata(MapType::Hash, 16, 24, 16_384, 0),
    ),
    ("JOURNAL_CTL", map_metadata(MapType::Array, 4, 24, 1, 0)),
    (
        "JOURNAL_MARKER_CTL",
        map_metadata(MapType::Array, 4, 16, 1, 0),
    ),
    (
        "JOURNAL_CLASSES",
        map_metadata(MapType::Array, 4, 4, MAX_DESCRIPTORS, BPF_F_RDONLY_PROG),
    ),
];

/// Production journal capture request. The Session start chain resolves one
/// through [`JournalSpec::prepare`] before anything loads.
#[derive(Debug)]
pub(crate) struct JournalSpec;

impl JournalSpec {
    /// Resolve the embedded production object. Builds that omit it refuse
    /// with the finite build reason before any load, parse or fill.
    pub(crate) fn prepare(&self) -> Result<JournalPreparation<'static>> {
        check_journal_build(
            env!("P11SCOPE_JOURNAL_ENABLED"),
            env!("P11SCOPE_JOURNAL_OUTPUTS"),
        )
        .map_err(anyhow::Error::msg)?;
        Ok(JournalPreparation {
            object: journal_object(),
        })
    }
}

/// Resolved production journal object bytes for one Session preparation.
#[derive(Debug)]
pub(crate) struct JournalPreparation<'a> {
    pub(crate) object: &'a [u8],
}

/// The embedded production journal object. Omitted builds carry an empty
/// static and refuse through [`check_journal_build`] before any use.
pub(crate) fn journal_object() -> &'static [u8] {
    crate::EBPF_JOURNAL_OBJECT
}

/// Deterministic build gate, checked before any journal parse or load:
/// builds that omit the production object refuse every preparation with
/// `journal-pair-unavailable-in-build`. Reads only the emitted pair.
pub(crate) fn check_journal_build(enabled: &str, outputs: &str) -> Result<(), String> {
    if enabled != "1" {
        return Err(
            "journal-pair-unavailable-in-build: this build omits the production journal object"
                .into(),
        );
    }
    if outputs.is_empty() {
        return Err(
            "journal-pair-unavailable-in-build: production journal outputs were not emitted".into(),
        );
    }
    Ok(())
}

/// Flavor of the production journal object, from its bytes: parse, then
/// [`journal_flavor_from_parsed`]. Unparseable bytes refuse with the pair
/// named. The journal object never carries stub or unsafe-decoder markers.
pub(crate) fn checked_journal_flavor(object: &[u8]) -> Result<EmbeddedFlavor> {
    let parsed = aya_obj::Object::parse(object).map_err(|error| {
        anyhow!(
            "cannot determine journal BPF object flavor: {error:#} (stale or mismatched embedded object; rebuild p11scope from a clean target directory)"
        )
    })?;
    journal_flavor_from_parsed(&parsed)
}

/// The parsed-object mapping: the journal pair must be present and named
/// when missing, the ordinary pair must be absent, and the four journal
/// maps must carry their exact shapes.
pub(crate) fn journal_flavor_from_parsed(parsed: &aya_obj::Object) -> Result<EmbeddedFlavor> {
    let missing: Vec<&str> = PROGRAMS
        .iter()
        .copied()
        .filter(|name| !parsed.programs.contains_key(*name))
        .collect();
    if !missing.is_empty() {
        bail!(
            "journal BPF object flavor mismatch: missing journal roots {} (expected the production journal pair)",
            missing.join(", ")
        );
    }
    let present: Vec<&str> = ORDINARY_PAIR
        .iter()
        .copied()
        .filter(|name| parsed.programs.contains_key(*name))
        .collect();
    if !present.is_empty() {
        bail!(
            "journal BPF object flavor mismatch: ordinary roots {} present in a journal object (stale or mismatched embedded object)",
            present.join(", ")
        );
    }
    for (name, expected) in JOURNAL_MAPS {
        let Some(map) = parsed.maps.get(name) else {
            bail!(
                "journal BPF object map mismatch: {name} missing from the production journal object"
            );
        };
        let actual = (
            map.map_type(),
            map.key_size(),
            map.value_size(),
            map.max_entries(),
            map.map_flags(),
        );
        let expected = metadata_tuple(&expected);
        if actual != expected {
            bail!(
                "journal BPF object map mismatch: {name} metadata {actual:?} differs from exact expected {expected:?}"
            );
        }
    }
    Ok(EmbeddedFlavor {
        stubbed: false,
        unsafe_present: false,
    })
}

/// Raw shape tuple behind [`JOURNAL_MAPS`], so the parsed-bytes rule and the
/// loaded-map validation share one shape source.
fn metadata_tuple(meta: &ExactMapMetadata) -> (u32, u32, u32, u32, u32) {
    let map_type = match meta.map_type {
        MapType::Array => 2,
        MapType::Hash => 1,
        other => unreachable!("journal map metadata uses unexpected map type {other:?}"),
    };
    (
        map_type,
        meta.key_size,
        meta.value_size,
        meta.max_entries,
        meta.flags,
    )
}

/// Programs a journal object loads: ordinary Detailed with the entry/return
/// pair swapped for the journal pair. The journal build refuses unsafe
/// decoders, so there is no unsafe variant.
pub(crate) fn journal_expected_programs() -> BTreeSet<&'static str> {
    DEFAULT_PROGRAMS
        .into_iter()
        .filter(|name| !ORDINARY_PAIR.contains(name))
        .chain(PROGRAMS)
        .collect()
}

/// Exact program inventory of a loaded journal object: the swapped pair plus
/// every retained ordinary program. Mirrors the Detailed inventory contract.
pub(crate) fn validate_journal_inventory(ebpf: &Ebpf) -> Result<()> {
    let mut expected = journal_expected_programs();
    expected.extend(INSTANCE_PROGRAMS.iter().map(|(program, _)| *program));
    expected.insert("p11_image_query");
    expected.extend(SELECTED_DETAILED_PROGRAMS);
    let actual: BTreeSet<_> = ebpf.programs().map(|(name, _)| name).collect();
    if actual != expected {
        bail!("eBPF program inventory {actual:?} differs from {expected:?}");
    }
    Ok(())
}

/// Exact metadata of the four journal maps in a loaded object.
pub(crate) fn validate_journal_maps(ebpf: &Ebpf) -> Result<()> {
    for (name, expected) in JOURNAL_MAPS {
        validate_policy_map(ebpf, name, expected)?;
    }
    Ok(())
}

/// Production `JOURNAL_CLASSES` value for one descriptor: the configured
/// class from the frozen userspace classifier. Zero is unconfigured
/// (descriptor 0, out of range, or classifier-unknown) and stays a gap;
/// 1/2/3 are proved-irrelevant/tracked/negative-only. The BPF root maps
/// 1/2/3 to native 0/1/2 and treats every other value as a gap.
pub(crate) fn journal_class_for_descriptor(descriptor: u32) -> u32 {
    if descriptor == 0 || descriptor >= MAX_DESCRIPTORS {
        return 0;
    }
    match endpoint_class(descriptor - 1) {
        Some(EndpointClass::ProvedIrrelevant) => 1,
        Some(EndpointClass::ModeledAffecting) => 2,
        Some(EndpointClass::NegativeOnlyAffecting) => 3,
        None => 0,
    }
}

/// Fill all 105 `JOURNAL_CLASSES` slots from the frozen classifier and
/// refuse on any readback drift. Mirrors `publish_descriptors`.
pub(crate) fn publish_journal_classes<S>(
    state: &mut S,
    mut set: impl FnMut(&mut S, u32, u32) -> Result<()>,
    readback: impl FnOnce(&mut S) -> Result<Vec<u32>>,
) -> Result<()> {
    let expected: Vec<u32> = (0..MAX_DESCRIPTORS)
        .map(journal_class_for_descriptor)
        .collect();
    for (index, value) in expected.iter().copied().enumerate() {
        set(state, index as u32, value)?;
    }
    let actual = readback(state)?;
    if actual != expected {
        bail!("JOURNAL_CLASSES exact readback differs from the frozen classifier");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        JournalSpec, PROGRAMS, check_journal_build, checked_journal_flavor,
        journal_class_for_descriptor, journal_expected_programs, journal_flavor_from_parsed,
        journal_object, publish_journal_classes,
    };
    use p11scope_ebpf_common::MAX_DESCRIPTORS;

    /// The production mapping follows the frozen classifier: descriptor 0
    /// and out-of-range stay 0, and the configured census matches the
    /// proof-pinned `[0, 19, 76, 9]`. Zero marks exactly the unconfigured
    /// slots, never a misclassified gap.
    #[test]
    fn journal_class_values_follow_the_frozen_classifier() {
        assert_eq!(journal_class_for_descriptor(0), 0);
        for descriptor in [MAX_DESCRIPTORS, MAX_DESCRIPTORS + 1, u32::MAX] {
            assert_eq!(journal_class_for_descriptor(descriptor), 0);
        }
        let mut counts = [0usize; 4];
        for descriptor in 1..MAX_DESCRIPTORS {
            let class = journal_class_for_descriptor(descriptor);
            counts[class as usize] += 1;
        }
        assert_eq!(counts, [0, 19, 76, 9]);
        for descriptor in 0..MAX_DESCRIPTORS {
            assert_eq!(
                journal_class_for_descriptor(descriptor) == 0,
                descriptor == 0,
                "descriptor {descriptor}"
            );
        }
    }

    /// Healthy fill twin: all 105 slots written from the classifier with
    /// exact readback, over garbage initial contents.
    #[test]
    fn journal_fill_writes_all_105_with_exact_readback() {
        let mut state = vec![u32::MAX; MAX_DESCRIPTORS as usize];
        publish_journal_classes(
            &mut state,
            |state, index, value| {
                state[index as usize] = value;
                Ok(())
            },
            |state| Ok(state.clone()),
        )
        .unwrap();
        let expected: Vec<u32> = (0..MAX_DESCRIPTORS)
            .map(journal_class_for_descriptor)
            .collect();
        assert_eq!(state.len(), MAX_DESCRIPTORS as usize);
        assert_eq!(state, expected);
    }

    /// Drift twin: a readback that differs in one slot refuses naming the
    /// map, at the first, a middle, and the last slot.
    #[test]
    fn journal_fill_refuses_readback_drift() {
        for slot in [0, 57, MAX_DESCRIPTORS - 1] {
            let mut state = vec![0u32; MAX_DESCRIPTORS as usize];
            let error = publish_journal_classes(
                &mut state,
                |state, index, value| {
                    state[index as usize] = value;
                    Ok(())
                },
                |state| {
                    let mut drifted = state.clone();
                    drifted[slot as usize] = drifted[slot as usize].wrapping_add(1);
                    Ok(drifted)
                },
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("JOURNAL_CLASSES exact readback differs from the frozen classifier"),
                "slot {slot}: {error}"
            );
        }
    }

    /// Build-gate twins: omitted builds refuse with the finite reason, the
    /// emitted pair admits, and the embedded static matches the selection.
    #[test]
    fn journal_build_gate_reports_unbuilt_production_object() {
        for (enabled, outputs) in [
            ("0", ""),
            ("0", "journal-v1"),
            ("", ""),
            ("2", "journal-v1"),
        ] {
            let error = check_journal_build(enabled, outputs).unwrap_err();
            assert!(
                error.contains("journal-pair-unavailable-in-build"),
                "{enabled:?}/{outputs:?}: {error}"
            );
        }
        let error = check_journal_build("1", "").unwrap_err();
        assert!(
            error.contains("journal-pair-unavailable-in-build") && error.contains("not emitted"),
            "{error}"
        );
        check_journal_build("1", "journal-v1").unwrap();
        if env!("P11SCOPE_JOURNAL_ENABLED") == "1" {
            assert_eq!(env!("P11SCOPE_JOURNAL_OUTPUTS"), "journal-v1");
            assert!(!journal_object().is_empty());
        } else {
            assert_eq!(env!("P11SCOPE_JOURNAL_ENABLED"), "0");
            assert_eq!(env!("P11SCOPE_JOURNAL_OUTPUTS"), "");
            assert!(journal_object().is_empty());
        }
    }

    /// R-a: without a built production object the spec refuses before any
    /// parse, load or fill; with one it resolves nonempty bytes.
    #[test]
    fn journal_spec_prepare_reports_unbuilt_before_any_work() {
        if env!("P11SCOPE_JOURNAL_ENABLED") == "1" {
            let prepared = JournalSpec.prepare().unwrap();
            assert!(!prepared.object.is_empty());
        } else {
            let error = JournalSpec.prepare().unwrap_err();
            assert!(
                format!("{error:#}").contains("journal-pair-unavailable-in-build"),
                "{error:#}"
            );
        }
    }

    /// R-b: corrupt and empty bytes refuse naming the journal flavor.
    #[test]
    fn journal_flavor_refuses_corrupt_production_bytes() {
        for bytes in [b"not an ELF object".as_slice(), b""] {
            let error = checked_journal_flavor(bytes).unwrap_err();
            let text = format!("{error:#}");
            assert!(
                text.contains("cannot determine journal BPF object flavor"),
                "{text}"
            );
            assert!(text.contains("stale or mismatched"), "{text}");
        }
    }

    /// R-c without a journal build: ordinary bytes miss both roots by name,
    /// and planting one root leaves exactly the other missing.
    #[test]
    fn journal_flavor_refuses_pair_missing_from_inventory() {
        let error = checked_journal_flavor(crate::EBPF_OBJECT).unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("missing journal roots"), "{text}");
        assert!(text.contains("p11_entry_journal"), "{text}");
        assert!(text.contains("p11_return_journal"), "{text}");
        let mut one = aya_obj::Object::parse(crate::EBPF_OBJECT).expect("ordinary bytes parse");
        let program = one
            .programs
            .values()
            .next()
            .expect("ordinary bytes carry programs")
            .clone();
        one.programs
            .insert("p11_entry_journal".to_string(), program);
        let error = journal_flavor_from_parsed(&one).unwrap_err();
        let text = format!("{error:#}");
        assert!(
            text.contains("missing journal roots p11_return_journal"),
            "{text}"
        );
    }

    /// Production-bytes twins: the real journal object is accepted, one
    /// missing root is named either way, a planted ordinary root refuses as
    /// mixed, and a removed or drifted journal map refuses. Omitted-object
    /// builds assert the omission and skip.
    #[test]
    fn journal_flavor_accepts_production_bytes_and_refuses_partial_and_mixed() {
        if env!("P11SCOPE_JOURNAL_ENABLED") != "1" {
            assert_eq!(env!("P11SCOPE_JOURNAL_OUTPUTS"), "");
            return;
        }
        let bytes = journal_object();
        assert!(!bytes.is_empty());
        checked_journal_flavor(bytes).unwrap();
        for missing in PROGRAMS {
            let mut partial = aya_obj::Object::parse(bytes).expect("journal bytes parse");
            assert!(partial.programs.remove(missing).is_some());
            let error = journal_flavor_from_parsed(&partial).unwrap_err();
            let text = format!("{error:#}");
            assert!(text.contains("missing journal roots"), "{text}");
            assert!(text.contains(missing), "{text}");
        }
        let mut mixed = aya_obj::Object::parse(bytes).expect("journal bytes parse");
        let program = mixed
            .programs
            .values()
            .next()
            .expect("journal bytes carry programs")
            .clone();
        mixed.programs.insert("p11_entry".to_string(), program);
        let error = journal_flavor_from_parsed(&mixed).unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("ordinary roots"), "{text}");
        assert!(text.contains("p11_entry"), "{text}");
        let mut unmapped = aya_obj::Object::parse(bytes).expect("journal bytes parse");
        assert!(unmapped.maps.remove("JOURNAL_CLASSES").is_some());
        let error = journal_flavor_from_parsed(&unmapped).unwrap_err();
        assert!(
            format!("{error:#}").contains("JOURNAL_CLASSES missing"),
            "{error:#}"
        );
        let mut drifted = aya_obj::Object::parse(bytes).expect("journal bytes parse");
        drifted
            .maps
            .get_mut("JOURNAL_CLASSES")
            .expect("journal maps carry JOURNAL_CLASSES")
            .set_value_size(8);
        let error = journal_flavor_from_parsed(&drifted).unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("JOURNAL_CLASSES metadata"), "{text}");
        assert!(text.contains("differs from exact expected"), "{text}");
    }

    /// The journal load set is exactly ordinary Detailed with the pair
    /// swapped: same size, journal pair in, ordinary pair out.
    #[test]
    fn journal_expected_programs_swap_the_pair() {
        let expected = super::super::expected_programs(false);
        let journal = journal_expected_programs();
        assert_eq!(journal.len(), expected.len());
        for name in PROGRAMS {
            assert!(journal.contains(name), "{name}");
        }
        for name in ["p11_entry", "p11_return"] {
            assert!(!journal.contains(name), "{name}");
        }
        let mut swapped: std::collections::BTreeSet<&str> = expected
            .into_iter()
            .filter(|name| *name != "p11_entry" && *name != "p11_return")
            .collect();
        swapped.extend(PROGRAMS);
        assert_eq!(journal, swapped);
    }
}
