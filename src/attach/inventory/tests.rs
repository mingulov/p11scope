//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
use super::*;
use crate::capacity::InventoryBudget;
use p11scope_ebpf_common::{InventoryUsageConfig, ThreadOwnerControl};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::rc::Rc;

fn capacity(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap()
}

#[test]
fn inventory_freeze_owner_metadata_matches_both_embedded_flavors() {
    for bytes in [
        crate::EBPF_INVENTORY_OBJECT,
        crate::EBPF_INVENTORY_CALLERS_OBJECT,
    ] {
        let object = aya_obj::Object::parse(bytes).unwrap();
        let owner = object.maps.get("THREAD_OWNER").unwrap();
        let actual = map_metadata(
            MapType::TaskStorage,
            owner.key_size(),
            owner.value_size(),
            owner.max_entries(),
            owner.map_flags(),
        );
        assert_eq!(actual.value_size, 544);
        validate_inventory_owner_freeze_metadata(actual).unwrap();
        for changed in [
            ExactMapMetadata {
                map_type: MapType::Hash,
                ..actual
            },
            ExactMapMetadata {
                key_size: actual.key_size + 1,
                ..actual
            },
            ExactMapMetadata {
                value_size: 560,
                ..actual
            },
            ExactMapMetadata {
                max_entries: actual.max_entries + 1,
                ..actual
            },
            ExactMapMetadata {
                flags: actual.flags ^ 1,
                ..actual
            },
        ] {
            assert!(validate_inventory_owner_freeze_metadata(changed).is_err());
        }
    }
}

fn map_fixture(n: u32) -> BTreeMap<String, (InventoryMapKind, ExactMapMetadata)> {
    use InventoryMapKind as K;
    #[cfg_attr(feature = "stub-object-attributes", allow(unused_mut))]
    let mut rows = vec![
        ("CONFIG", K::Array, MapType::Array, 4, 8, 2, 128),
        ("PID_FILTER", K::Hash, MapType::Hash, 4, 8, 1024, 128),
        (
            "CGROUP_FILTER",
            K::CgroupArray,
            MapType::CgroupArray,
            4,
            4,
            1,
            0,
        ),
        (
            "TAIL_CALLS",
            K::ProgramArray,
            MapType::ProgramArray,
            4,
            4,
            2,
            0,
        ),
        (
            "STACK_GUARD",
            K::ProgramArray,
            MapType::ProgramArray,
            4,
            4,
            1,
            0,
        ),
        (
            "EVIDENCE",
            K::PerCpuArray,
            MapType::PerCpuArray,
            4,
            8,
            11,
            0,
        ),
        ("COUNTERS", K::PerCpuArray, MapType::PerCpuArray, 4, 8, 5, 0),
        (
            "PRODUCED",
            K::PerCpuArray,
            MapType::PerCpuArray,
            4,
            8,
            PRODUCED_CELLS,
            0,
        ),
        (
            "DISCOVERY",
            K::RingBuf,
            MapType::RingBuf,
            0,
            0,
            EXPECTED_INVENTORY_DISCOVERY_BYTES,
            0,
        ),
        ("DISCOVERY_STATE", K::Hash, MapType::Hash, 24, 24, 64, 0),
        (
            "THREAD_OWNER",
            K::Unsupported,
            MapType::TaskStorage,
            4,
            544,
            0,
            1,
        ),
        ("OWNER_CTL", K::Array, MapType::Array, 4, 56, 1, 0),
        ("USAGE", K::Array, MapType::Array, 4, 8, n, 0),
        ("USAGE_CONFIG", K::Array, MapType::Array, 4, 8, 1, 128),
        (
            "USAGE_EVIDENCE",
            K::PerCpuArray,
            MapType::PerCpuArray,
            4,
            8,
            3,
            0,
        ),
    ];
    // Keymeta Task 7 (spec §17.4): the FULL manifest gains the INFO
    // rows; the P0 manifest keeps the pre-info set.
    #[cfg(not(feature = "stub-object-attributes"))]
    rows.extend([
        ("INFO_START", K::Hash, MapType::Hash, 16, 32, 1024, 0),
        (
            "INFO",
            K::RingBuf,
            MapType::RingBuf,
            0,
            0,
            EXPECTED_INVENTORY_INFO_BYTES,
            0,
        ),
        (
            "INFO_KIND",
            K::Array,
            MapType::Array,
            4,
            8,
            n,
            BPF_F_RDONLY_PROG,
        ),
        (
            "INFO_EVIDENCE",
            K::PerCpuArray,
            MapType::PerCpuArray,
            4,
            8,
            4,
            0,
        ),
    ]);
    rows.into_iter()
        .map(
            |(name, kind, map_type, key_size, value_size, max_entries, flags)| {
                (
                    name.to_string(),
                    (
                        kind,
                        ExactMapMetadata {
                            map_type,
                            key_size,
                            value_size,
                            max_entries,
                            flags,
                        },
                    ),
                )
            },
        )
        .collect()
}

#[test]
fn inventory_capacity_and_map_contract_accept_one_and_unrelated_budget_sizes() {
    for n in [1, 576, 4097, u32::MAX] {
        let budget = InventoryBudget::new(u64::from(n), u64::from(n) * 8).unwrap();
        assert_eq!(inventory_capacity(budget).unwrap().get(), n);
        validate_inventory_maps(&map_fixture(n), capacity(n)).unwrap();
    }
}

#[test]
fn inventory_map_contract_rejects_each_metadata_field_and_wrong_aya_variant() {
    let original = map_fixture(576);
    for name in original.keys() {
        for field in 0..5 {
            let mut changed = original.clone();
            let meta = &mut changed.get_mut(name).unwrap().1;
            match field {
                0 => {
                    meta.map_type = if meta.map_type == MapType::Hash {
                        MapType::Array
                    } else {
                        MapType::Hash
                    }
                }
                1 => meta.key_size ^= 1,
                2 => meta.value_size ^= 1,
                3 => meta.max_entries ^= 1,
                4 => meta.flags ^= 1,
                _ => unreachable!(),
            }
            let error = validate_inventory_maps(&changed, capacity(576)).unwrap_err();
            assert!(
                format!("{error:#}").contains(name),
                "{name}, field {field}: {error:#}"
            );
        }
        let mut changed = original.clone();
        changed.get_mut(name).unwrap().0 = if name == "THREAD_OWNER" {
            InventoryMapKind::Array
        } else {
            InventoryMapKind::Unsupported
        };
        assert!(
            validate_inventory_maps(&changed, capacity(576)).is_err(),
            "{name}"
        );
    }
}

#[test]
fn inventory_map_contract_refuses_missing_extra_unresized_and_opportunistic_small_maps() {
    let original = map_fixture(576);
    for name in original.keys() {
        let mut changed = original.clone();
        changed.remove(name);
        assert!(
            validate_inventory_maps(&changed, capacity(576)).is_err(),
            "{name}"
        );
    }
    for extra in ["EVENTS", "TASK_COOKIE", "ROOT_AFFILIATION", "UNKNOWN"] {
        let mut changed = original.clone();
        changed.insert(extra.into(), original["USAGE"]);
        assert!(
            validate_inventory_maps(&changed, capacity(576)).is_err(),
            "{extra}"
        );
    }
    for wrong_capacity in [1, 575, 577] {
        assert!(validate_inventory_maps(&map_fixture(wrong_capacity), capacity(576)).is_err());
    }
    let mut changed = original;
    // A DISCOVERY size from another flavor never loads here: the small
    // ring in a stock build, the stock Detailed ring in a small build.
    let other_flavor = if EXPECTED_INVENTORY_DISCOVERY_BYTES == 4_096 {
        2 * 1024 * 1024
    } else {
        4_096
    };
    changed.get_mut("DISCOVERY").unwrap().1.max_entries = other_flavor;
    assert!(validate_inventory_maps(&changed, capacity(576)).is_err());
}

/// Both embedded Inventory objects carry exactly the loader
/// manifest's maps: a BPF-side map addition without the manifest twin
/// refuses every load at runtime, and the fixture twins above compare
/// the manifest against themselves, so only this object-vs-manifest
/// check sees that drift. Shapes compare exactly except the load-time
/// resizes (`USAGE`/`ENDPOINT_OBJECT` capacity, `CALLER_USE` pairs).
#[test]
fn inventory_objects_carry_exactly_the_loader_manifest_maps() {
    // The caller flavor's extra maps, restated from
    // `callers::validate_caller_maps` (entries for the resized maps
    // are placeholders; the comparison skips them).
    let caller_extra: &[(&str, MapType, u32, u32, u32, u32)] = &[
        ("INV_BASELINE_RQ", MapType::Hash, 4, 16, 1024, 129),
        ("INV_BASELINE_CT", MapType::Array, 4, 56, 1, 0),
        (
            "ENDPOINT_OBJECT",
            MapType::Array,
            4,
            8,
            1,
            BPF_F_RDONLY_PROG,
        ),
        ("CALLER_USE", MapType::Hash, 24, 40, 1, 0),
        ("CALLER_EVIDENCE", MapType::PerCpuArray, 4, 8, 4, 0),
        ("TASK_COOKIE", MapType::TaskStorage, 4, 8, 0, 1),
        ("COOKIE_CTL", MapType::Array, 4, 40, 1, 0),
    ];
    // Keymeta Task 7 (spec §17.4): `INFO_KIND` rides the loader's
    // capacity patch beside `USAGE` (placeholder 1 in the object).
    let resized = ["USAGE", "ENDPOINT_OBJECT", "CALLER_USE", "INFO_KIND"];
    let manifest = inventory_maps(capacity(576));
    for (flavor, bytes, extra) in [
        ("inventory", crate::EBPF_INVENTORY_OBJECT, &[][..]),
        (
            "inventory-callers",
            crate::EBPF_INVENTORY_CALLERS_OBJECT,
            caller_extra,
        ),
    ] {
        let object = aya_obj::Object::parse(bytes).unwrap();
        let actual: BTreeSet<&str> = object.maps.keys().map(String::as_str).collect();
        let mut expected: BTreeSet<&str> = manifest.keys().copied().collect();
        expected.extend(extra.iter().map(|(name, ..)| *name));
        assert_eq!(
            actual, expected,
            "{flavor} map names match the loader manifest"
        );
        for (name, (_, expected)) in &manifest {
            let map = object.maps.get(*name).unwrap();
            assert_eq!(
                map.map_type(),
                expected.map_type as u32,
                "{flavor} {name} type"
            );
            assert_eq!(map.key_size(), expected.key_size, "{flavor} {name} key");
            assert_eq!(
                map.value_size(),
                expected.value_size,
                "{flavor} {name} value"
            );
            if !resized.contains(name) {
                assert_eq!(
                    map.max_entries(),
                    expected.max_entries,
                    "{flavor} {name} entries"
                );
            }
            assert_eq!(map.map_flags(), expected.flags, "{flavor} {name} flags");
        }
        for (name, map_type, key_size, value_size, max_entries, flags) in extra {
            let map = object.maps.get(*name).unwrap();
            assert_eq!(map.map_type(), *map_type as u32, "{flavor} {name} type");
            assert_eq!(map.key_size(), *key_size, "{flavor} {name} key");
            assert_eq!(map.value_size(), *value_size, "{flavor} {name} value");
            if !resized.contains(name) {
                assert_eq!(map.max_entries(), *max_entries, "{flavor} {name} entries");
            }
            assert_eq!(map.map_flags(), *flags, "{flavor} {name} flags");
        }
    }
}

fn program_fixture() -> BTreeMap<String, InventoryProgramKind> {
    use InventoryProgramKind::*;
    // Keymeta Task 7 (spec §17.4): the FULL flavors carry the
    // inventory info pair (12 → 15); the P0 flavor omits it.
    let mut programs = vec![
        ("p11_usage_entry_lp64", Entry),
        ("p11_usage_entry_ia32", Entry),
        ("dl_debug_state", Entry),
        ("function_list_entry", Entry),
        ("interface_list_entry", Entry),
        ("interface_entry", Entry),
        ("function_list_return", Return),
        ("interface_list_return", Return),
        ("interface_list_worker", Return),
        ("interface_return", Return),
        ("sched_process_exec", RawTracePoint),
        ("sched_process_exit", RawTracePoint),
    ];
    if cfg!(feature = "stub-object-attributes") {
        assert_eq!(programs.len(), 12);
    } else {
        programs.extend([
            ("p11_info_entry_lp64", Entry),
            ("p11_info_entry_ia32", Entry),
            ("p11_info_return", Return),
        ]);
        assert_eq!(programs.len(), 15);
    }
    programs
        .into_iter()
        .map(|(name, kind)| (name.to_string(), kind))
        .collect()
}

#[test]
fn inventory_program_contract_rejects_missing_extra_and_every_kind_change() {
    let original = program_fixture();
    validate_inventory_programs(&original).unwrap();
    for name in original.keys() {
        let mut missing = original.clone();
        missing.remove(name);
        assert!(validate_inventory_programs(&missing).is_err(), "{name}");
        for kind in [
            InventoryProgramKind::Entry,
            InventoryProgramKind::Return,
            InventoryProgramKind::RawTracePoint,
        ] {
            if kind != original[name] {
                let mut changed = original.clone();
                changed.insert(name.clone(), kind);
                assert!(
                    validate_inventory_programs(&changed).is_err(),
                    "{name}: {kind:?}"
                );
            }
        }
    }
    for extra in ["p11_entry", "p11_return", "task_newtask", "UNKNOWN"] {
        let mut changed = original.clone();
        changed.insert(extra.into(), InventoryProgramKind::Entry);
        assert!(validate_inventory_programs(&changed).is_err(), "{extra}");
    }
}

/// The validator's expectation is the shared BPF constant in a stock
/// build (the small-ring mirror is pinned by the embedded sizes below).
#[cfg(not(p11scope_small_discovery_ring))]
#[test]
fn expected_inventory_discovery_is_the_shared_constant() {
    assert_eq!(
        EXPECTED_INVENTORY_DISCOVERY_BYTES,
        p11scope_ebpf_common::INVENTORY_DISCOVERY_BYTES
    );
    assert_eq!(EXPECTED_INVENTORY_DISCOVERY_BYTES, 8 * 1024 * 1024);
}

/// A size pin per flavor over the embedded objects: both Inventory
/// flavors compile this build's ring (8 MiB stock, 4 KiB small), while
/// Detailed keeps 2 MiB (4 KiB when the small-ring feature shrank every
/// flavor's compiled ring, as today).
#[test]
fn embedded_discovery_sizes_pin_each_flavor() {
    #[cfg(p11scope_small_discovery_ring)]
    let detailed = 4_096;
    #[cfg(not(p11scope_small_discovery_ring))]
    let detailed = 2 * 1024 * 1024;
    for (flavor, bytes, expected) in [
        ("detailed", crate::EBPF_OBJECT, detailed),
        (
            "inventory",
            crate::EBPF_INVENTORY_OBJECT,
            EXPECTED_INVENTORY_DISCOVERY_BYTES,
        ),
        (
            "inventory-callers",
            crate::EBPF_INVENTORY_CALLERS_OBJECT,
            EXPECTED_INVENTORY_DISCOVERY_BYTES,
        ),
    ] {
        let object = aya_obj::Object::parse(bytes).unwrap();
        let discovery = object.maps.get("DISCOVERY").unwrap();
        assert_eq!(discovery.max_entries(), expected, "{flavor}");
    }
}

#[test]
fn inventory_embedded_program_sections_preserve_entry_return_and_raw_tracepoint_kinds() {
    use aya_obj::ProgramSection;
    let object = aya_obj::Object::parse(crate::EBPF_INVENTORY_OBJECT).unwrap();
    let actual = object
        .programs
        .iter()
        .map(|(name, program)| {
            let kind = match program.section {
                ProgramSection::UProbe {
                    sleepable: false,
                    multi: false,
                } => InventoryProgramKind::Entry,
                ProgramSection::URetProbe {
                    sleepable: false,
                    multi: false,
                } => InventoryProgramKind::Return,
                ProgramSection::RawTracePoint => InventoryProgramKind::RawTracePoint,
                ref other => panic!("unexpected section for {name}: {other:?}"),
            };
            (name.clone(), kind)
        })
        .collect();
    validate_inventory_programs(&actual).unwrap();
    assert_eq!(actual, program_fixture());
}

/// Keymeta Task 7 (spec §17.4): Multi load extends to the info
/// entries and the info return beside the two ordinary usage
/// entries; the lifecycle roots stay plain.
#[test]
fn inventory_multi_load_is_confined_to_the_usage_entries_and_the_info_pair() {
    use InventoryProgramLoad::*;
    for name in program_fixture().keys() {
        let expected_single = if name.starts_with("sched_process_") {
            RawTracePoint
        } else {
            UProbe
        };
        let expected_multi = match name.as_str() {
            "p11_usage_entry_lp64"
            | "p11_usage_entry_ia32"
            | "p11_info_entry_lp64"
            | "p11_info_entry_ia32"
            | "p11_info_return" => UProbeMulti,
            "sched_process_exec" | "sched_process_exit" => RawTracePoint,
            _ => UProbe,
        };
        assert_eq!(
            inventory_program_load(name, AttachBackend::Singles).unwrap(),
            expected_single
        );
        assert_eq!(
            inventory_program_load(name, AttachBackend::Multi).unwrap(),
            expected_multi
        );
    }
    assert!(inventory_program_load("p11_entry", AttachBackend::Singles).is_err());
    assert!(inventory_program_load("task_newtask", AttachBackend::Multi).is_err());
}

#[test]
fn inventory_usage_config_must_match_version_budget_and_actual_array_capacity() {
    for n in [1, 576, 4097] {
        let config = InventoryUsageConfig {
            version: 1,
            endpoint_capacity: n,
        };
        validate_inventory_usage_config(capacity(n), n, config).unwrap();
        for bad in [
            InventoryUsageConfig {
                version: 0,
                ..config
            },
            InventoryUsageConfig {
                version: 2,
                ..config
            },
            InventoryUsageConfig {
                endpoint_capacity: 0,
                ..config
            },
            InventoryUsageConfig {
                endpoint_capacity: n + 1,
                ..config
            },
        ] {
            assert!(validate_inventory_usage_config(capacity(n), n, bad).is_err());
        }
        for actual in [0, n - 1, n + 1] {
            assert!(validate_inventory_usage_config(capacity(n), actual, config).is_err());
        }
    }
}

#[test]
fn inventory_owner_readback_checks_all_seven_words_without_a_start_limit() {
    let expected = ThreadOwnerControl {
        limit: 64,
        ..ThreadOwnerControl::default()
    };
    validate_inventory_owner_control(expected).unwrap();
    for word in 0..7 {
        let mut actual = expected;
        match word {
            0 => actual.limit = 16_448,
            1 => actual.outstanding = 1,
            2 => actual.poison = 1,
            3 => actual.admission_failures = 1,
            4 => actual.reclamation_failures = 1,
            5 => actual.abandoned_start = 1,
            6 => actual.abandoned_discovery = 1,
            _ => unreachable!(),
        }
        assert!(
            validate_inventory_owner_control(actual).is_err(),
            "word {word}"
        );
    }
}

fn preparation_steps(backend: AttachBackend) -> Vec<InventoryPreparation> {
    use InventoryPreparation::*;
    use InventoryProgramLoad::{RawTracePoint, UProbe, UProbeMulti};
    let usage = if backend == AttachBackend::Multi {
        UProbeMulti
    } else {
        UProbe
    };
    // Keymeta Task 7 (spec §17.4): the FULL flavors load the info
    // pair beside the usage entries; the freeze sequence gains
    // nothing (admission-published maps are never frozen).
    let mut steps = vec![
        LoadObject,
        ValidateMaps,
        ValidatePrograms,
        PublishScope,
        WriteUsageConfig,
        ReadUsageConfig,
        WriteOwner,
        ReadOwner,
        Freeze("PID_FILTER"),
        Freeze("CGROUP_FILTER"),
        Freeze("USAGE_CONFIG"),
        Freeze("THREAD_OWNER"),
        Freeze("OWNER_CTL"),
        Freeze("USAGE"),
        Freeze("STACK_GUARD"),
        LoadProgram("dl_debug_state", UProbe),
        LoadProgram("function_list_entry", UProbe),
        LoadProgram("function_list_return", UProbe),
        LoadProgram("interface_entry", UProbe),
        LoadProgram("interface_list_entry", UProbe),
        LoadProgram("interface_list_return", UProbe),
        LoadProgram("interface_list_worker", UProbe),
        LoadProgram("interface_return", UProbe),
    ];
    if cfg!(feature = "stub-object-attributes") {
        assert_eq!(program_fixture().len(), 12);
    } else {
        steps.extend([
            LoadProgram("p11_info_entry_ia32", usage),
            LoadProgram("p11_info_entry_lp64", usage),
            LoadProgram("p11_info_return", usage),
        ]);
    }
    steps.extend([
        LoadProgram("p11_usage_entry_ia32", usage),
        LoadProgram("p11_usage_entry_lp64", usage),
        LoadProgram("sched_process_exec", RawTracePoint),
        LoadProgram("sched_process_exit", RawTracePoint),
        Freeze("CONFIG"),
        PublishTailCalls,
        RetainDiscovery,
        RecheckCustody,
    ]);
    steps
}

#[derive(Debug)]
struct InjectedFailure(usize);
impl std::fmt::Display for InjectedFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "injected operation {}", self.0)
    }
}
impl std::error::Error for InjectedFailure {}

#[derive(Debug)]
struct OwnedPreparationResource(Rc<Cell<usize>>);
impl Drop for OwnedPreparationResource {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

#[test]
fn inventory_preparation_defers_config_freeze_and_retains_resources_only_on_success() {
    for backend in [AttachBackend::Singles, AttachBackend::Multi] {
        let dropped = Rc::new(Cell::new(0));
        let mut seen = Vec::new();
        let prepared = prepare_inventory_with(
            backend,
            OwnedPreparationResource(dropped.clone()),
            |_, step| {
                seen.push(step);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(seen, preparation_steps(backend));
        assert_eq!(dropped.get(), 0);
        drop(prepared);
        assert_eq!(dropped.get(), 1);
    }
}

#[test]
fn inventory_preparation_stops_at_each_failure_preserves_its_source_and_drops_resources() {
    for backend in [AttachBackend::Singles, AttachBackend::Multi] {
        let expected = preparation_steps(backend);
        for failed in 0..expected.len() {
            let dropped = Rc::new(Cell::new(0));
            let seen = RefCell::new(Vec::new());
            let error = prepare_inventory_with(
                backend,
                OwnedPreparationResource(dropped.clone()),
                |_, step| {
                    let mut seen = seen.borrow_mut();
                    seen.push(step);
                    if seen.len() == failed + 1 {
                        return Err(InjectedFailure(failed).into());
                    }
                    Ok(())
                },
            )
            .unwrap_err();
            assert_eq!(error.downcast_ref::<InjectedFailure>().unwrap().0, failed);
            assert_eq!(seen.into_inner(), expected[..=failed]);
            assert_eq!(dropped.get(), 1, "failure at {:?}", expected[failed]);
        }
    }
}

#[test]
fn inventory_final_custody_refuses_stale_or_unknown_lifetimes() {
    require_inventory_custody_with(|| Ok(true)).unwrap();
    assert!(require_inventory_custody_with(|| Ok(false)).is_err());
    let error = require_inventory_custody_with(|| Err(InjectedFailure(99).into())).unwrap_err();
    assert_eq!(error.downcast_ref::<InjectedFailure>().unwrap().0, 99);
}

/// The object checker keeps every program array to one expected attach type
/// (CVE-2025-40123) from its MULTI_LOADED_PROGRAMS set. That set must be
/// exactly the programs userspace may load for uprobe-multi, in both objects,
/// or the checker proves the wrong split.
#[test]
fn object_checker_multi_loaded_programs_match_the_loaders() {
    let checker = include_str!("../../../scripts/check-bpf-map-defs.py");
    let start = checker
        .find("MULTI_LOADED_PROGRAMS = frozenset({")
        .expect("checker names its multi-loaded programs");
    let body = &checker[start..];
    let body = &body[body.find('{').unwrap() + 1..body.find("})").unwrap()];
    let pinned: BTreeSet<&str> = body
        .split(',')
        .map(|name| name.trim().trim_matches('"'))
        .filter(|name| !name.is_empty())
        .collect();
    let mut loaders = BTreeSet::new();
    for unsafe_enabled in [false, true] {
        for name in crate::attach::expected_programs(unsafe_enabled) {
            let multi = crate::attach::loads_with_multi_flag(AttachBackend::Multi, name, false);
            assert!(!crate::attach::loads_with_multi_flag(
                AttachBackend::Singles,
                name,
                false
            ));
            if multi {
                loaders.insert(name);
            }
        }
    }
    for (name, _) in INVENTORY_PROGRAMS {
        if inventory_program_load(name, AttachBackend::Multi).unwrap()
            == InventoryProgramLoad::UProbeMulti
        {
            loaders.insert(name);
        }
        assert_ne!(
            inventory_program_load(name, AttachBackend::Singles).unwrap(),
            InventoryProgramLoad::UProbeMulti
        );
    }
    assert_eq!(pinned, loaders);
}

/// Keymeta Task 7 (spec §17.4): the FULL inventory flavors carry the
/// inventory info pair beside the usage entries (12 → 15); the P0
/// flavor omits the info programs (exact 12-program list). RED-a: the
/// FULL object still lists 12.
#[test]
fn inventory_full_program_shape_carries_the_info_pair() {
    use InventoryProgramKind::*;
    let mut expected = program_fixture();
    if cfg!(feature = "stub-object-attributes") {
        assert_eq!(expected.len(), 12, "the P0 flavor omits the info pair");
    } else {
        expected.insert("p11_info_entry_lp64".to_string(), Entry);
        expected.insert("p11_info_entry_ia32".to_string(), Entry);
        expected.insert("p11_info_return".to_string(), Return);
        assert_eq!(expected.len(), 15);
    }
    validate_inventory_programs(&expected).unwrap();
}

/// Keymeta Task 7 (spec §17.4): the FULL inventory manifest gains the
/// `INFO_START` stash, the `INFO` ring, the `INFO_KIND` publication
/// and the `INFO_EVIDENCE` cells, and `PRODUCED` grows 2 → 3. RED-a:
/// the manifest still lists the pre-info set.
#[test]
fn inventory_full_map_manifest_carries_the_info_ring_and_stash() {
    use InventoryMapKind as K;
    let manifest = inventory_maps(capacity(576));
    if cfg!(feature = "stub-object-attributes") {
        for absent in ["INFO_START", "INFO", "INFO_KIND", "INFO_EVIDENCE"] {
            assert!(
                !manifest.contains_key(absent),
                "the P0 flavor omits {absent}"
            );
        }
        return;
    }
    let produced = manifest.get("PRODUCED").expect("PRODUCED row");
    assert_eq!(produced.1.max_entries, 3, "PRODUCED counts the INFO ring");
    for (name, kind, map_type, key_size, value_size, max_entries, flags) in [
        ("INFO_START", K::Hash, MapType::Hash, 16, 32, 1024, 0),
        ("INFO", K::RingBuf, MapType::RingBuf, 0, 0, 64 * 1024, 0),
        (
            "INFO_KIND",
            K::Array,
            MapType::Array,
            4,
            8,
            576,
            BPF_F_RDONLY_PROG,
        ),
        (
            "INFO_EVIDENCE",
            K::PerCpuArray,
            MapType::PerCpuArray,
            4,
            8,
            4,
            0,
        ),
    ] {
        let (actual_kind, actual) = manifest.get(name).unwrap_or_else(|| panic!("{name} row"));
        assert_eq!(*actual_kind, kind, "{name} kind");
        assert_eq!(actual.map_type, map_type, "{name} type");
        assert_eq!(actual.key_size, key_size, "{name} key");
        assert_eq!(actual.value_size, value_size, "{name} value");
        assert_eq!(actual.max_entries, max_entries, "{name} entries");
        assert_eq!(actual.flags, flags, "{name} flags");
    }
}

/// Keymeta Task 7 `INFO_KIND` publication (spec §17.4, fix9 R1): the
/// endpoint→kind cell is written once with the kind in the low byte
/// and read back; re-publication, a nonzero cell, kind zero and a
/// readback mismatch all refuse. Follows the `ENDPOINT_OBJECT`
/// precedent; the map is never frozen.
#[test]
fn info_kind_publication_writes_once_and_reads_back() {
    use p11scope_ebpf_common::inventory_info::INFO_KIND_PROVIDER;
    struct Cells {
        cells: BTreeMap<u32, u64>,
        corrupt_readback: bool,
    }
    impl super::InfoKindIo for Cells {
        fn read_kind(&mut self, endpoint: u32) -> Result<u64> {
            let value = self.cells.get(&endpoint).copied().unwrap_or(0);
            Ok(if self.corrupt_readback {
                value ^ 0xFF
            } else {
                value
            })
        }
        fn write_kind(&mut self, endpoint: u32, value: u64) -> Result<()> {
            self.cells.insert(endpoint, value);
            Ok(())
        }
    }
    let mut io = Cells {
        cells: BTreeMap::new(),
        corrupt_readback: false,
    };
    super::publish_info_kind_with(&mut io, 7, INFO_KIND_PROVIDER).unwrap();
    assert_eq!(io.cells.get(&7), Some(&1));
    assert!(super::publish_info_kind_with(&mut io, 7, INFO_KIND_PROVIDER).is_err());
    assert!(super::publish_info_kind_with(&mut io, 9, 0).is_err());
    io.cells.insert(11, 2);
    assert!(super::publish_info_kind_with(&mut io, 11, INFO_KIND_PROVIDER).is_err());
    io.corrupt_readback = true;
    assert!(super::publish_info_kind_with(&mut io, 13, INFO_KIND_PROVIDER).is_err());
}

/// Keymeta Task 7 revocation pacing (spec §17.4, INV-2): the
/// deadline gates every map operation, not just the cell
/// transaction — when the initial lookup itself reaches the
/// deadline, the zero-write must not start, and the next extend
/// resumes at the write without redoing the read.
#[test]
fn revoke_step_yields_when_the_initial_lookup_reaches_the_deadline() {
    use std::time::{Duration, Instant};
    struct Cells {
        cells: BTreeMap<u32, u64>,
        clock: Rc<Cell<Instant>>,
        past: Instant,
        reads: usize,
        writes: usize,
    }
    impl super::InfoKindIo for Cells {
        fn read_kind(&mut self, endpoint: u32) -> Result<u64> {
            self.reads += 1;
            // The lookup itself consumes the window: the clock reads
            // past the deadline from here on.
            self.clock.set(self.past);
            Ok(self.cells.get(&endpoint).copied().unwrap_or(0))
        }
        fn write_kind(&mut self, endpoint: u32, value: u64) -> Result<()> {
            self.writes += 1;
            self.cells.insert(endpoint, value);
            Ok(())
        }
    }
    let start = Instant::now();
    let deadline = start + Duration::from_secs(30);
    let past = deadline + Duration::from_secs(1);
    let clock = Rc::new(Cell::new(start));
    let mut io = Cells {
        cells: BTreeMap::from([(7u32, 1u64)]),
        clock: Rc::clone(&clock),
        past,
        reads: 0,
        writes: 0,
    };
    let mut now = || clock.get();
    let outcome = super::revoke_info_kind_step(
        &mut io,
        7,
        super::RevokeSubstep::ReadInitial,
        deadline,
        &mut now,
    )
    .unwrap();
    assert_eq!(
        outcome,
        super::RevokeStepOutcome::Yielded {
            next: super::RevokeSubstep::WriteZero
        },
        "the crossed deadline yields at the pending write"
    );
    assert_eq!(io.reads, 1, "the initial lookup ran");
    assert_eq!(io.writes, 0, "no zero-write starts past the deadline");
    assert_eq!(io.cells.get(&7), Some(&1), "the cell keeps its kind");
    // The next extend resumes at the write: one write plus its
    // read-back, and no second initial read.
    clock.set(start);
    let (reads_before, writes_before) = (io.reads, io.writes);
    let outcome = super::revoke_info_kind_step(
        &mut io,
        7,
        super::RevokeSubstep::WriteZero,
        deadline,
        &mut now,
    )
    .unwrap();
    assert_eq!(outcome, super::RevokeStepOutcome::Done);
    assert_eq!(
        io.reads - reads_before,
        1,
        "the resume reads back once and redoes no finished read"
    );
    assert_eq!(
        io.writes - writes_before,
        1,
        "the resume writes the cell once"
    );
    assert_eq!(io.cells.get(&7), Some(&0), "the cell clears");
}
