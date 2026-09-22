//! SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::capacity::InventoryBudget;
use p11scope_ebpf_common::{InventoryUsageConfig, ThreadOwnerControl};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::rc::Rc;

fn capacity(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap()
}

fn map_fixture(n: u32) -> BTreeMap<String, (InventoryMapKind, ExactMapMetadata)> {
    use InventoryMapKind as K;
    [
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
        ("EVIDENCE", K::PerCpuArray, MapType::PerCpuArray, 4, 8, 9, 0),
        ("COUNTERS", K::PerCpuArray, MapType::PerCpuArray, 4, 8, 5, 0),
        ("DISCOVERY", K::RingBuf, MapType::RingBuf, 0, 0, 65536, 0),
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
    ]
    .into_iter()
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
    changed.get_mut("DISCOVERY").unwrap().1.max_entries = 4096;
    assert!(validate_inventory_maps(&changed, capacity(576)).is_err());
}

fn program_fixture() -> BTreeMap<String, InventoryProgramKind> {
    use InventoryProgramKind::*;
    [
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
    ]
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

#[test]
fn inventory_multi_load_is_confined_to_the_two_ordinary_usage_entries() {
    use InventoryProgramLoad::*;
    for name in program_fixture().keys() {
        let expected_single = if name.starts_with("sched_process_") {
            RawTracePoint
        } else {
            UProbe
        };
        let expected_multi = match name.as_str() {
            "p11_usage_entry_lp64" | "p11_usage_entry_ia32" => UProbeMulti,
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
    vec![
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
        LoadProgram("dl_debug_state", UProbe),
        LoadProgram("function_list_entry", UProbe),
        LoadProgram("function_list_return", UProbe),
        LoadProgram("interface_entry", UProbe),
        LoadProgram("interface_list_entry", UProbe),
        LoadProgram("interface_list_return", UProbe),
        LoadProgram("interface_list_worker", UProbe),
        LoadProgram("interface_return", UProbe),
        LoadProgram("p11_usage_entry_ia32", usage),
        LoadProgram("p11_usage_entry_lp64", usage),
        LoadProgram("sched_process_exec", RawTracePoint),
        LoadProgram("sched_process_exit", RawTracePoint),
        Freeze("CONFIG"),
        PublishTailCalls,
        RetainDiscovery,
        RecheckCustody,
    ]
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
