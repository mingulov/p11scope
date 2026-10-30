//! SPDX-License-Identifier: GPL-3.0-or-later
//! H7 slice D: reviewed finite object capture activation gates.
//!
//! Production publication lifts ONLY on the reviewed allowlisted attested
//! lane: BPF emits 608-byte records for marker-bound calls, userspace
//! decodes them against the frozen receipt-bound table and carries the
//! private validated tail through the owned H3 routed call into the
//! consuming admission result. No model construction, no public object
//! projection. These tests pin the emission preconditions (a)-(d), the
//! lane gate and the absence properties; the full-record cursor/pending
//! behavior lives in `object_producer_full_record_mixed_cursor_and_pending`.

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "support/object_adapter.rs"]
mod adapter;
#[path = "support/transport_boundaries.rs"]
mod transport_boundaries;

fn source_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let from = source
        .find(start)
        .unwrap_or_else(|| panic!("missing source marker {start:?}"));
    let rest = &source[from + start.len()..];
    let until = rest
        .find(end)
        .unwrap_or_else(|| panic!("missing source marker {end:?}"));
    &rest[..until]
}

fn bpf_source() -> String {
    std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF return root")
}

fn embedded_object(directory: &Path) -> PathBuf {
    let object = directory.join("p11scope-ebpf");
    std::fs::write(&object, p11scope::EBPF_OBJECT).expect("write actual embedded BPF object");
    object
}

const COUNTER_ARTIFACT_MODES: [(&str, &str, u64, u64); 3] = [
    ("counts", "p11scope-ebpf-counter-counts", 24, 12_288),
    ("timestamps", "p11scope-ebpf-counter-timestamps", 40, 20_480),
    ("latency", "p11scope-ebpf-counter-latency", 296, 151_552),
];

fn counter_artifacts_enabled() -> bool {
    match env!("P11SCOPE_COUNTER_ARTIFACTS_ENABLED") {
        "0" => false,
        "1" => true,
        other => panic!("invalid private counter artifact selection {other:?}"),
    }
}

fn counter_artifact_path(name: &str) -> PathBuf {
    Path::new(env!("OUT_DIR"))
        .join("counter-artifacts")
        .join(name)
}

fn counter_bank_mode_check(mode: &str, profile: &str, path: &Path) -> std::process::Output {
    Command::new("python3")
        .args([
            "-I",
            "scripts/check-counter-object.py",
            "--mode",
            mode,
            "--profile",
            profile,
        ])
        .arg(path)
        .output()
        .expect("run bank timing checker")
}

fn counter_objects_enabled() -> bool {
    match env!("P11SCOPE_COUNTER_OBJECTS_ENABLED") {
        "0" => false,
        "1" => true,
        other => panic!("invalid counter objects selection {other:?}"),
    }
}

fn counter_object_bytes(token: &str) -> &'static [u8] {
    match token {
        "counts-bank-growth-v2" => p11scope::EBPF_COUNTER_COUNTS_OBJECT,
        "timestamps-bank-growth-v2" => p11scope::EBPF_COUNTER_TIMESTAMPS_OBJECT,
        "latency-bank-growth-v2" => p11scope::EBPF_COUNTER_LATENCY_OBJECT,
        other => panic!("unknown counter bank token {other:?}"),
    }
}

fn write_counter_object(token: &str, directory: &Path) -> PathBuf {
    let path = directory.join(format!("p11scope-ebpf-{token}"));
    std::fs::write(&path, counter_object_bytes(token)).expect("write embedded counter object");
    path
}

fn counter_bank_mode_check_mutants(mode: &str, profile: &str, path: &Path) -> std::process::Output {
    Command::new("python3")
        .args([
            "-I",
            "scripts/check-counter-object.py",
            "--mode",
            mode,
            "--profile",
            profile,
            "--self-test-mutants",
        ])
        .arg(path)
        .output()
        .expect("run bank mutants checker")
}

const COUNTER_BANK_TOKENS: [&str; 3] = [
    "counts-bank-growth-v2",
    "timestamps-bank-growth-v2",
    "latency-bank-growth-v2",
];

const COUNTER_BANK_MODES: [(&str, &str, u64, u64); 3] = [
    ("counts", "counts-bank-growth-v2", 24, 0x0200_0018_0010_0200),
    (
        "timestamps",
        "timestamps-bank-growth-v2",
        40,
        0x0200_0028_0010_0200,
    ),
    (
        "latency",
        "latency-bank-growth-v2",
        296,
        0x0200_0128_0010_0200,
    ),
];

/// The ordinary FULL build embeds all three bank objects. `=0`, SMALL and
/// WIDE omit them (empty outputs); anything else fails the build before work.
#[test]
fn counter_objects_switch_matches_emitted_contract() {
    let requested = match option_env!("P11SCOPE_COUNTER_OBJECTS") {
        None | Some("1") => true,
        Some("0") => false,
        other => panic!("malformed counter objects request {other:?}"),
    };
    let small = matches!(option_env!("P11SCOPE_SMALL_RING"), Some("1" | "true"))
        || matches!(option_env!("P11SCOPE_SMALL_STATE_MAPS"), Some("1" | "true"))
        || matches!(
            option_env!("P11SCOPE_SMALL_DISCOVERY_RING"),
            Some("1" | "true")
        );
    let wide = cfg!(feature = "wide-detailed-2112");
    // An explicit `=1` with SMALL/WIDE never builds (build.rs panics); only
    // unset omits silently, and `=0` omits explicitly.
    if small || wide {
        assert_ne!(
            option_env!("P11SCOPE_COUNTER_OBJECTS"),
            Some("1"),
            "explicit counter objects with SMALL/WIDE must fail the build"
        );
    }
    let enabled = requested && !small && !wide;
    assert_eq!(counter_objects_enabled(), enabled);
    assert_eq!(
        env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"),
        if enabled {
            "counts-bank-growth-v2,timestamps-bank-growth-v2,latency-bank-growth-v2"
        } else {
            ""
        },
        "the emitted set must follow this compilation, not stale files"
    );
    if enabled {
        let mut bodies = Vec::new();
        for token in COUNTER_BANK_TOKENS {
            let body = counter_object_bytes(token);
            assert!(!body.is_empty(), "{token} embedded object is empty");
            assert_ne!(
                body,
                p11scope::EBPF_OBJECT,
                "{token} selected Detailed bytes"
            );
            assert!(
                !bodies.contains(&body),
                "two counter modes share their object"
            );
            bodies.push(body);
        }
    } else {
        for token in COUNTER_BANK_TOKENS {
            assert!(
                counter_object_bytes(token).is_empty(),
                "{token} must be omitted when disabled"
            );
        }
        // Disabled builds refuse each mode at the checker too: Detailed is
        // not a bank object under any profile.
        let directory = tempfile::tempdir().unwrap();
        let ordinary = embedded_object(directory.path());
        for (mode, profile, _, _) in COUNTER_BANK_MODES {
            let result = counter_bank_mode_check(mode, profile, &ordinary);
            assert_eq!(result.status.code(), Some(2), "Detailed passed as {mode}");
            assert!(String::from_utf8_lossy(&result.stderr).contains("counter object refused:"));
        }
    }
}

/// Every embedded bank object carries the exact format2 maps, the exact
/// config word, and the mode's clock/histogram reachability. The checker's
/// acceptance is the proof for access bounds (counts: no STATS or inner
/// access at offset >= 24; timestamps: CAS writes at 24/32, none >= 40;
/// latency: buckets only from the return root), both health dispositions,
/// and the absence of semantic/event helpers or maps; the report fields
/// below pin the shape that acceptance was computed on.
#[test]
fn counter_bank_modes_have_exact_maps_clock_and_histogram_reachability() {
    if !counter_objects_enabled() {
        assert_eq!(env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"), "");
        for token in COUNTER_BANK_TOKENS {
            assert!(
                counter_object_bytes(token).is_empty(),
                "{token} must be omitted when disabled"
            );
        }
        return;
    }
    assert_eq!(
        env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"),
        "counts-bank-growth-v2,timestamps-bank-growth-v2,latency-bank-growth-v2"
    );
    let directory = tempfile::tempdir().unwrap();
    for (mode, profile, value_bytes, configuration) in COUNTER_BANK_MODES {
        let path = write_counter_object(profile, directory.path());
        let output = counter_bank_mode_check(mode, profile, &path);
        assert!(
            output.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            report["schema"], "p11scope-counter-bank-object/v2",
            "{mode}"
        );
        assert_eq!(report["configuration"], configuration, "{mode}");
        assert_eq!(report["native_owner_slot_bound"], 8_192, "{mode}");
        for (name, kind, key, value, entries, flags) in [
            ("STATS", 6, 4, 24, 512, 0),
            ("COUNTER_BANKS", 13, 4, 4, 16, 128),
            ("COUNTER_BANK_META", 1, 4, 32, 8_192, 128),
            ("COUNTER_BANK_COMMIT", 1, 8, 16, 8_192, 128),
            ("COUNTER_BANK_FAULT", 6, 4, 8, 1, 0),
            ("COUNTER_HEALTH", 6, 4, 8, 2, 0),
            ("START", 1, 16, 288, 16_384, 0),
            ("RV_COUNTS", 5, 16, 8, 65_536, 0),
            ("SLOT_FILE", 2, 4, 4, 8_192, 128),
        ] {
            for (field, expected) in [
                ("type", kind),
                ("key_size", key),
                ("value_size", value),
                ("max_entries", entries),
                ("flags", flags),
            ] {
                assert_eq!(
                    report["maps"][name][field], expected,
                    "{mode} {name}.{field}"
                );
            }
        }
        assert_eq!(report["inner_template"]["type"], 6, "{mode}");
        assert_eq!(report["inner_template"]["key_size"], 4, "{mode}");
        assert_eq!(
            report["inner_template"]["value_size"], value_bytes,
            "{mode}"
        );
        assert_eq!(report["inner_template"]["max_entries"], 512, "{mode}");
        assert_eq!(report["inner_template"]["flags"], 0, "{mode}");
        assert_eq!(report["ordinary_counter_profile"], "refused", "{mode}");
        for root in ["p11_counter_bank_entry", "p11_counter_bank_return"] {
            assert!(
                report["roots"][root]["stack_chain"].as_u64().unwrap() <= 512,
                "{mode} {root}"
            );
            if mode == "counts" {
                assert_eq!(
                    report["roots"][root]["clocks"], 0,
                    "{mode} {root} must not read the clock"
                );
            } else {
                assert!(
                    report["roots"][root]["clocks"].as_u64().unwrap() >= 1,
                    "{mode} {root} must read the clock"
                );
            }
            assert_eq!(
                report["roots"][root]["semantic_or_event_work"], false,
                "{mode} {root}"
            );
        }
        let controls = report["controls"].as_object().unwrap();
        assert!(!controls.is_empty(), "{mode}");
        for (name, verdict) in controls {
            assert_eq!(verdict, "accepted", "{mode} {name}");
        }
    }
    // The three configuration words are pairwise distinct, so every
    // cross-profile check below is also a wrong-config control.
    assert_ne!(
        COUNTER_BANK_MODES[0].3, COUNTER_BANK_MODES[1].3,
        "counts and timestamps configurations must differ"
    );
    assert_ne!(
        COUNTER_BANK_MODES[0].3, COUNTER_BANK_MODES[2].3,
        "counts and latency configurations must differ"
    );
    assert_ne!(
        COUNTER_BANK_MODES[1].3, COUNTER_BANK_MODES[2].3,
        "timestamps and latency configurations must differ"
    );
}

/// Causal mutants for the embedded bank objects: the counts self-test
/// mutants (including an injected clock and a missing START removal) plus
/// every swapped mode token (including a 40-byte template under the counts
/// token, histogram bytes as timestamps, and wrong configs) refuse with a
/// named cause.
#[test]
fn counter_bank_mode_mutations_are_causally_rejected() {
    if !counter_objects_enabled() {
        assert_eq!(env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"), "");
        for token in COUNTER_BANK_TOKENS {
            assert!(
                counter_object_bytes(token).is_empty(),
                "{token} must be omitted when disabled"
            );
        }
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = write_counter_object("counts-bank-growth-v2", directory.path());
    let output = counter_bank_mode_check_mutants("counts", "counts-bank-growth-v2", &path);
    assert!(
        output.status.success(),
        "counts mutants: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let mutants = report["mutants"].as_object().unwrap();
    for name in [
        "inner_value_width",
        "inner_cell_count",
        "outer_bank_count",
        "outer_type",
        "route_value_width",
        "route_max_entries",
        "commit_max_entries",
        "rv_max_entries",
        "slot_file_max_entries",
        "slot_file_flags",
        "native_owner_slot_bound",
        "missing_native_owner_slot_bound",
        "legacy_native_owner_slot_bound",
        "logical_index",
        "inner_index",
        "bank_global_linkage",
        "bank_global_abi",
        "commit_gate",
        "commit_first",
        "commit_end",
        "route_first",
        "route_end",
        "route_bank",
        "route_cell",
        "route_inner_id_zero",
        "route_reserved",
        "configuration",
        "configuration_version",
        "transaction_width",
        "optional_start_get",
        "required_start_remove",
        "missing_start_get",
        "missing_start_remove",
        "route_fault",
        "legacy_stats_write",
        "endpoint_clock",
        "semantic_helper",
        "unknown_call",
    ] {
        assert_eq!(
            mutants.get(name),
            Some(&serde_json::json!("refused")),
            "{name}"
        );
    }
    // Every swapped mode token refuses with a named cause: a 40-byte
    // template under the counts token, histogram bytes as timestamps, a
    // missing clock as timing, and wrong configs in every direction.
    for (mode, profile, _, _) in COUNTER_BANK_MODES {
        let path = write_counter_object(profile, directory.path());
        for (wrong_mode, wrong_profile, _, _) in COUNTER_BANK_MODES {
            if wrong_profile == profile {
                continue;
            }
            let wrong = counter_bank_mode_check(wrong_mode, wrong_profile, &path);
            assert_eq!(
                wrong.status.code(),
                Some(2),
                "{mode} accepted as {wrong_mode}"
            );
            let stderr = String::from_utf8_lossy(&wrong.stderr);
            assert!(
                stderr.contains("counter object refused:"),
                "{mode} refused without a cause as {wrong_mode}"
            );
            let cause = stderr.split("counter object refused:").nth(1).unwrap_or("");
            assert!(
                !cause.trim().is_empty(),
                "{mode} refusal has an empty cause as {wrong_mode}"
            );
        }
    }
}

/// Creates owned anonymous maps and loads both bank and exec/exit roots from the
/// embedded counts object. Aya may run feature probes; no attachment, commit
/// publication or workload runs here.
#[test]
#[ignore = "requires the default build with embedded counter objects and an authorized BTF/map/program-load lane"]
fn counter_bank_btf_maps_and_programs_load() {
    assert!(
        counter_objects_enabled(),
        "default build with embedded counter objects is required"
    );
    let directory = tempfile::tempdir().unwrap();
    let path = write_counter_object("counts-bank-growth-v2", directory.path());
    let output = counter_bank_mode_check("counts", "counts-bank-growth-v2", &path);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut object = aya::EbpfLoader::new()
        .allow_unsupported_maps()
        .load_file(&path)
        .expect("load bank BTF and maps");
    // Match the production loader's raw task-storage handles, while
    // refusing any other unsupported map or mismatched native layout.
    let storage: std::collections::BTreeMap<_, _> = object
        .maps()
        .filter_map(|(name, map)| match map {
            aya::maps::Map::Unsupported(data) => Some((name, data)),
            _ => None,
        })
        .collect();
    let expected = std::collections::BTreeMap::from([
        ("PROC_EPOCH", 152u32),
        ("ROOT_AFFILIATION", 8),
        ("TASK_COOKIE", 8),
        ("THREAD_OWNER", 560),
    ]);
    assert_eq!(
        storage.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    for (name, value_size) in expected {
        let info = storage[name].info().expect("read native task-storage info");
        assert_eq!(
            (
                info.map_type().unwrap(),
                info.key_size(),
                info.value_size(),
                info.max_entries(),
                info.map_flags(),
            ),
            (aya::maps::MapType::TaskStorage, 4, value_size, 0, 1),
            "{name}"
        );
    }
    drop(storage);
    let native_banks: Vec<_> = (0..16)
        .map(|bank| {
            aya::maps::MapData::create(
                aya_obj::Map::new_from_params(6, 4, 24, 512, 0),
                &format!("counts_bank{bank}"),
                None,
            )
            .expect("allocate actual 512-cell Counts bank")
        })
        .collect();
    let ids: std::collections::BTreeSet<_> = native_banks
        .iter()
        .map(|bank| {
            let info = bank.info().expect("actual inner-map metadata");
            assert_eq!(
                (
                    info.map_type().unwrap(),
                    info.key_size(),
                    info.value_size(),
                    info.max_entries(),
                    info.map_flags()
                ),
                (aya::maps::MapType::PerCpuArray, 4, 24, 512, 0),
            );
            assert_ne!(info.id(), 0);
            info.id()
        })
        .collect();
    assert_eq!(
        ids.len(),
        16,
        "all sixteen banks retain distinct native IDs"
    );
    {
        let mut banks: aya::maps::HashOfMaps<_, u32> = object
            .map_mut("COUNTER_BANKS")
            .expect("real outer map")
            .try_into()
            .expect("real HashOfMaps ABI");
        for (index, bank) in native_banks.iter().enumerate() {
            banks
                .insert(index as u32, bank, 1)
                .expect("stage bank with BPF_NOEXIST");
            assert_eq!(
                banks.get(&(index as u32), 0).unwrap().info().unwrap().id(),
                bank.info().unwrap().id(),
            );
        }
    }
    for name in ["p11_counter_bank_entry", "p11_counter_bank_return"] {
        let program: &mut aya::programs::UProbe = object
            .program_mut(name)
            .expect("proof root")
            .try_into()
            .expect("uprobe program kind");
        program
            .load()
            .expect("actual outer-to-inner verifier bridge");
    }
    // The bounded owner callbacks are reached only by these mandatory
    // lifecycle roots. Loading endpoint roots alone cannot validate them.
    for name in ["sched_process_exec", "sched_process_exit"] {
        let program: &mut aya::programs::RawTracePoint = object
            .program_mut(name)
            .expect("actual lifecycle root")
            .try_into()
            .expect("raw tracepoint program kind");
        program
            .load()
            .expect("actual full-bound owner cleanup verifier");
    }
}

fn counter_artifact_check(mode: &str, object: &Path, mutants: bool) -> std::process::Output {
    let mut command = Command::new("python3");
    command
        .arg("-I")
        .arg("scripts/check-counter-object.py")
        .arg("--mode")
        .arg(mode);
    if mutants {
        command.arg("--self-test-mutants");
    }
    command
        .arg(object)
        .output()
        .expect("run actual counter object checker")
}

/// The ordinary build remains the existing three selectable objects. A
/// disabled build publishes an empty counter set even if an earlier opt-in
/// left disposable output files in that build directory.
#[test]
fn counter_artifact_build_selection_matches_emitted_contract() {
    let requested = match option_env!("P11SCOPE_COUNTER_ARTIFACTS") {
        None | Some("0") => false,
        Some("1") => true,
        other => panic!("malformed private counter artifact request {other:?}"),
    };
    assert_eq!(counter_artifacts_enabled(), requested);
    assert_eq!(
        env!("P11SCOPE_COUNTER_ARTIFACTS_OUTPUTS"),
        if requested {
            "counts,timestamps,latency"
        } else {
            ""
        },
        "the emitted set must follow this compilation, not stale files"
    );
    for (name, embedded) in [
        ("p11scope-ebpf", p11scope::EBPF_OBJECT),
        ("p11scope-ebpf-inventory", p11scope::EBPF_INVENTORY_OBJECT),
        (
            "p11scope-ebpf-inventory-callers",
            p11scope::EBPF_INVENTORY_CALLERS_OBJECT,
        ),
    ] {
        let body = std::fs::read(Path::new(env!("OUT_DIR")).join(name)).unwrap();
        assert_eq!(
            body.as_slice(),
            embedded,
            "ordinary object changed selection: {name}"
        );
    }
    assert!(
        Path::new(env!("OUT_DIR"))
            .join("p11scope-ebpf-identity")
            .is_file()
    );

    if requested {
        let mut bodies = Vec::new();
        for (_, name, _, _) in COUNTER_ARTIFACT_MODES {
            let body = std::fs::read(counter_artifact_path(name)).unwrap();
            assert_ne!(
                body,
                p11scope::EBPF_OBJECT,
                "counter mode selected Detailed bytes"
            );
            assert!(
                !bodies.contains(&body),
                "two counter modes share their object"
            );
            bodies.push(body);
        }
    } else {
        let directory = tempfile::tempdir().unwrap();
        let ordinary = embedded_object(directory.path());
        for mode in ["counts", "timestamps", "latency"] {
            let result = counter_artifact_check(mode, &ordinary, false);
            assert_eq!(
                result.status.code(),
                Some(2),
                "ordinary object passed as {mode}"
            );
            assert!(String::from_utf8_lossy(&result.stderr).contains("counter object refused"));
        }
    }
}

#[test]
#[ignore = "requires P11SCOPE_COUNTER_ARTIFACTS=1 in its own build configuration"]
fn counter_artifact_modes_have_exact_maps_and_root_work() {
    assert!(
        counter_artifacts_enabled(),
        "explicit counter artifact build required"
    );
    for (mode, name, value_bytes, stats_bytes) in COUNTER_ARTIFACT_MODES {
        let path = counter_artifact_path(name);
        let output = counter_artifact_check(mode, &path, false);
        assert!(
            output.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["schema"], "p11scope-counter-object/v3");
        assert_eq!(report["mode"], mode);
        assert_eq!(report["native_owner_slot_bound"], 512);
        for (map, kind, key, value, maximum) in [
            ("STATS", 6, 4, value_bytes, 512),
            ("RV_COUNTS", 5, 16, 8, 4_096),
            ("COUNTER_HEALTH", 6, 4, 8, 2),
            (
                "START",
                1,
                16,
                std::mem::size_of::<p11scope_ebpf_common::CallStart>() as u64,
                16_384,
            ),
        ] {
            assert_eq!(report["maps"][map]["type"], kind, "{mode} {map}");
            assert_eq!(report["maps"][map]["key_size"], key, "{mode} {map}");
            assert_eq!(report["maps"][map]["value_size"], value, "{mode} {map}");
            assert_eq!(report["maps"][map]["max_entries"], maximum, "{mode} {map}");
        }
        assert_eq!(
            report["payload_per_possible_cpu_bytes"]["STATS"],
            stats_bytes
        );
        assert_eq!(
            report["payload_per_possible_cpu_bytes"]["RV_COUNTS"],
            32_768
        );
        assert_eq!(
            report["payload_per_possible_cpu_bytes"]["COUNTER_HEALTH"],
            16
        );
        for root in ["p11_entry", "p11_return"] {
            let work = &report["endpoint_timing"][root];
            assert_eq!(
                work["clocks"].as_array().unwrap().is_empty(),
                mode == "counts"
            );
            assert_eq!(
                work["histogram_work"],
                mode == "latency" && root == "p11_return"
            );
        }
        for (wrong_mode, _, _, _) in COUNTER_ARTIFACT_MODES {
            if wrong_mode == mode {
                continue;
            }
            let wrong = counter_artifact_check(wrong_mode, &path, false);
            assert_eq!(
                wrong.status.code(),
                Some(2),
                "{mode} accepted as {wrong_mode}"
            );
        }
    }
}

#[test]
#[ignore = "requires P11SCOPE_COUNTER_ARTIFACTS=1 in its own build configuration"]
fn counter_artifact_mutations_are_causally_rejected() {
    assert!(
        counter_artifacts_enabled(),
        "explicit counter artifact build required"
    );
    for (mode, name, _, _) in COUNTER_ARTIFACT_MODES {
        let output = counter_artifact_check(mode, &counter_artifact_path(name), true);
        assert!(
            output.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["mode"], mode);
        let controls = report["transfer_controls"].as_object().unwrap();
        assert_eq!(controls.len(), 37);
        for name in [
            "ordinary_copy",
            "full_spill",
            "saved_call_copy",
            "health_one_0",
            "health_one_1",
            "le_healthy_index31",
            "lt_healthy_index31",
            "constant_left_clamp64",
            "constant_left_clamp32_bounded",
            "unsigned_gt_taken",
            "unsigned_gt_untaken",
            "unsigned_ge_taken",
            "unsigned_ge_untaken",
            "unsigned_lt_taken",
            "unsigned_lt_untaken",
            "unsigned_le_taken",
            "unsigned_le_untaken",
            "unsigned_zero_max_empty_intersections",
        ] {
            assert_eq!(controls[name], "accepted", "{mode} {name}");
        }
        for name in [
            "movsx8_copy",
            "movsx16_copy",
            "movsx32_copy",
            "mov32_copy",
            "unknown_destination",
            "partial_spill",
            "caller_saved_clobber",
            "unknown_call",
            "mixed_pointer_join",
            "health_zero_0",
            "health_zero_1",
            "health_unknown_key",
            "cumulative_delete",
            "le_equality32_oob",
            "lt_fallthrough_equality32_oob",
            "constant_left_clamp32_high_alias",
            "histogram_guard_direction",
            "histogram_index32",
            "histogram_stride16",
        ] {
            assert_eq!(controls[name], "refused", "{mode} {name}");
        }
        for mutant in [
            "stats_value_size",
            "stats_endpoint_limit",
            "rv_key_size",
            "rv_capacity",
            "health_value_size",
            "health_capacity",
            "start_capacity",
            "native_owner_slot_bound",
            "owner_aggregate_linkage",
            "missing_start_entry",
            "missing_start_return_get",
            "missing_start_return_remove",
            "semantic_helper",
            "event_helper",
            "unknown_call",
            "stats_out_of_bounds",
            "health_saturated_writer",
            "health_contended_writer",
        ] {
            assert_eq!(report["mutants"][mutant], "refused", "{mode} {mutant}");
        }
        let timing_mutant = if mode == "counts" {
            "endpoint_clock"
        } else {
            "missing_clock"
        };
        assert_eq!(report["mutants"][timing_mutant], "refused", "{mode}");
        let histogram_mutant = if mode == "latency" {
            "missing_histogram_write"
        } else {
            "histogram_access"
        };
        assert_eq!(report["mutants"][histogram_mutant], "refused", "{mode}");
        if mode == "latency" {
            for mutant in [
                "histogram_guard_direction",
                "histogram_index32",
                "histogram_stride16",
            ] {
                assert_eq!(report["mutants"][mutant], "refused", "{mode} {mutant}");
            }
        }
    }
}

/// Precondition (a): pair slot-1 keeps a raw retained pointer with ABSENT
/// status while slot-0 VALUE is pre-cross-check. Emission recomputes
/// alias/duplicate/partial from the retained pointers; it never trusts
/// slot-0 as final.
#[test]
fn object_producer_emission_recomputes_pair_from_retained_pointers() {
    // The executed shared return fill reads the second retained result
    // pointer (pair second slot) instead of trusting slot-0 alone.
    let flow = std::fs::read_to_string("crates/ebpf-common/src/object_flow.rs")
        .expect("read shared adapter flow");
    let fill = source_between(
        &flow,
        "pub fn adapter_fill_return(",
        "pub unsafe fn adapter_tail_fill(",
    );
    assert!(
        fill.contains("result_ptrs[1]"),
        "return emission must read the retained second result pointer"
    );
    // The pair cross-checks run on the return path: overlap refuses the
    // pair, equal nonzero handles invalidate both, one readable member
    // is explicitly partial.
    for marker in ["ALIAS", "DUPLICATE", "PARTIAL"] {
        assert!(
            fill.contains(marker),
            "return emission must compute the pair {marker} cross-check"
        );
    }
}

/// Precondition (b): Find `result_ptrs[0]` holds the array base, never a
/// handle. The emitted Find single-handle result cell is pinned to the
/// constant unavailable cell; Find facts live in the Find section only.
#[test]
fn object_producer_find_emits_result_cell_not_array_base() {
    let source = bpf_source();
    let returned = source_between(
        &source,
        "fn p11_return_impl<const JOURNAL: bool>(ctx: RetProbeContext) -> u32 {",
        "pub extern \"C\" fn p11_link_fork_allowed",
    );
    // The Find section is populated on the return path (bounded element
    // reads into the reserved tail), and the single-handle result cell
    // carries the constant unavailable status, never the array word.
    assert!(
        returned.contains("find_handles") || source.contains("fn object_emit_find"),
        "return emission must populate the Find section"
    );
    let flow = std::fs::read_to_string("crates/ebpf-common/src/object_flow.rs")
        .expect("read shared adapter flow");
    assert!(
        flow.contains("PROTOCOL_UNAVAILABLE"),
        "Find result cell must use the constant unavailable status"
    );
    // The array base word must never be stored as an observed handle.
    let fill = source_between(
        &flow,
        "pub fn adapter_fill_return(",
        "pub unsafe fn adapter_tail_fill(",
    );
    assert!(
        !fill.contains("result_ptrs[0]).write(word"),
        "Find must not overwrite its array base with a handle word"
    );
}

/// Precondition (c): uninspected attribute lists are all-zero, which
/// validates as inspected-empty. Emission marks lists whose inspection
/// never ran with the uninspected marker instead of emitting a fake
/// inspected-empty list.
#[test]
fn object_producer_uninspected_lists_carry_marker() {
    // The wire validator accepts the honest uninspected marker.
    let wire = std::fs::read_to_string("crates/ebpf-common/src/object_wire.rs")
        .expect("read object wire validator");
    assert!(
        wire.contains("UNINSPECTED"),
        "the tail validator must name the uninspected list marker"
    );
    // BPF emission marks request lists it never inspected.
    let flow = std::fs::read_to_string("crates/ebpf-common/src/object_flow.rs")
        .expect("read shared adapter flow");
    assert!(
        flow.contains("UNINSPECTED"),
        "BPF emission must mark uninspected attribute lists"
    );
}

/// Precondition (d): Derive return is currently gated on entry evidence
/// only. Emission wires the full S1 return match (existing
/// MECHANISM_VALUE evidence exactly equal to the entry code) into the
/// gate before any phKey read.
#[test]
fn object_producer_derive_return_requires_s1_match() {
    let source = bpf_source();
    let returned = source_between(
        &source,
        "fn p11_return_impl<const JOURNAL: bool>(ctx: RetProbeContext) -> u32 {",
        "pub extern \"C\" fn p11_link_fork_allowed",
    );
    // The S1 return-time mechanism read supplies Derive return evidence,
    // so it must precede emission (which precedes the drain retire).
    let mechanism_read = returned
        .find("MECHANISM_VALUE")
        .expect("return must read S1 return-time mechanism evidence");
    let fill_site = returned
        .find("object_fill_return(")
        .expect("emission fills");
    assert!(
        mechanism_read < fill_site,
        "S1 mechanism evidence must precede emission"
    );
    // The shared Derive gate wires the full S1 match; a bare
    // entry-nonzero check no longer authorizes the result read.
    let flow = std::fs::read_to_string("crates/ebpf-common/src/object_flow.rs")
        .expect("read shared adapter flow");
    let fill = source_between(
        &flow,
        "pub fn adapter_fill_return(",
        "pub unsafe fn adapter_tail_fill(",
    );
    assert!(
        fill.contains("authorize_derive_return"),
        "Derive return must wire the full S1 mechanism match"
    );
    assert!(
        !fill.contains("side.derive != 0"),
        "Derive return must not gate on entry evidence alone"
    );
}

/// Slice D lifts the production gate ONLY on the reviewed allowlisted
/// attested lane: marker-bound calls emit 608-byte records through the
/// frozen descriptor row; everything else keeps the ordinary form.
#[test]
fn object_producer_publication_lifts_gate_only_on_attested_lane() {
    let source = bpf_source();
    // Emission exists now: the return path constructs the object tail.
    assert!(
        source.contains("ObjectCallWire")
            || source.contains("object: ObjectCallWire")
            || source.contains("ObjectEventRecord"),
        "slice D must construct the object tail on the return path"
    );
    // ... behind the required-object marker: ordinary calls keep one
    // 368-byte reservation and never touch the tail.
    let returned = source_between(
        &source,
        "fn p11_return_impl<const JOURNAL: bool>(ctx: RetProbeContext) -> u32 {",
        "pub extern \"C\" fn p11_link_fork_allowed",
    );
    assert!(
        returned.contains("object_required"),
        "emission stays behind the required-object marker"
    );
    // Each return implementation reserves exactly its own record form:
    // the ordinary half its 368-byte record, each object copy its own
    // 608-byte record. The whole-region count guards against added
    // sites.
    for (name, start, end) in [
        (
            "ordinary return",
            "fn ordinary_return(",
            "fn object_return_ordinary(",
        ),
        (
            "ordinary object copy",
            "fn object_return_ordinary(",
            "fn object_return<const JOURNAL: bool, Record: ReturnPayload>(",
        ),
        (
            "generic object copy",
            "fn object_return<const JOURNAL: bool, Record: ReturnPayload>(",
            "pub extern \"C\" fn p11_link_fork_allowed",
        ),
    ] {
        let body = source_between(&source, start, end);
        assert_eq!(
            body.matches("EVENTS.reserve").count(),
            1,
            "{name} reserves exactly its own record form"
        );
    }
    assert_eq!(
        returned.matches("EVENTS.reserve").count(),
        3,
        "return reserves exactly the ordinary and the two object record forms"
    );
    // The userspace decode gate needs the receipt-bound table: the
    // session freezes object rows against its attested receipt.
    let attach = std::fs::read_to_string("src/attach.rs").expect("read attach");
    assert!(
        attach.contains("object_decode_table") || attach.contains("ObjectDecodeTable"),
        "the session must freeze object rows for the attested decode lane"
    );
}

/// The required-object marker arms only under the allowlisted policy:
/// entry seeds `object_required` to zero (ordinary) and calls
/// `object_marker_for` exactly once, inside the allowlisted-policy
/// branch. Aggregate-only (`metrics`), unsafe-unvalidated-metadata and
/// the count-only inventory object therefore arm no marker. P0 arms it
/// for the slice-D handle, Find and Derive-mechanism reads, but
/// performs no attribute read.
#[test]
fn object_marker_arms_only_under_allowlisted_policy() {
    let source = bpf_source();
    let entry = source_between(
        &source,
        "fn p11_entry_impl<const TEMPLATE_MODE: u8, const ENTRY_ABI: u8, const JOURNAL: bool>(",
        "fn p11_return_impl<const JOURNAL: bool>(ctx: RetProbeContext) -> u32 {",
    );
    // The seed starts ordinary: no marker without the policy branch.
    assert!(
        entry.contains("object_required: 0,"),
        "entry must seed object_required to zero (ordinary)"
    );
    // Exactly one arming site in entry, and it names the marker helper.
    assert_eq!(
        entry.matches("object_marker_for").count(),
        1,
        "entry must arm the object marker at exactly one site"
    );
    // No other write arms the seed.
    assert_eq!(
        entry.matches("seed.object_required =").count(),
        1,
        "entry must assign seed.object_required exactly once (the guarded arm)"
    );
    // That site is exactly the allowlisted-policy branch body: match
    // the full three-line block so moving the call below the `if`
    // block's closing brace fails.
    assert!(
        entry.contains(
            "if flags & FLAG_POLICY_ALLOWLISTED != 0 {\n        seed.object_required = object_marker_for(cookie_of(&ctx));\n    }"
        ),
        "the marker call must be the body of the allowlisted-policy branch"
    );
}

/// KEM entry acquisition runs only through the shared KEM adapter:
/// the generic input/result paths skip both KEM actions, and the one
/// KEM wrapper binds the build's FULL gate plus the owned call's
/// validated S1 output verdict. No direct arg-7 or template read may
/// bypass the adapter.
#[test]
fn object_kem_entry_runs_only_through_the_shared_adapter() {
    let source = bpf_source();
    let fill = source_between(&source, "fn object_fill_entry(", "fn object_entry_derive(");
    assert!(
        fill.contains("OBJECT_ACTION_ENCAPSULATE") && fill.contains("OBJECT_ACTION_DECAPSULATE"),
        "generic input acquisition must skip both KEM actions"
    );
    let results = source_between(&source, "fn object_entry_results(", "fn object_entry_find(");
    assert!(
        results.contains("OBJECT_ACTION_ENCAPSULATE")
            && results.contains("OBJECT_ACTION_DECAPSULATE"),
        "generic result retention must skip both KEM actions"
    );
    let kem = source_between(&source, "fn object_entry_kem(", "fn object_entry_results(");
    assert!(
        kem.contains("adapter_kem_entry"),
        "the KEM wrapper must call the shared adapter"
    );
    assert!(
        kem.contains("KEM_CAPTURE_WIRED"),
        "the KEM wrapper must pass the build FULL gate, never a literal"
    );
    assert!(
        kem.contains("OUTPUT_MASK") && kem.contains("OUTPUT_NON_NULL"),
        "the KEM wrapper must derive the query verdict from the owned S1 output state"
    );
    let entry = source_between(
        &source,
        "fn p11_entry_impl<const TEMPLATE_MODE: u8, const ENTRY_ABI: u8, const JOURNAL: bool>(",
        "fn p11_return_impl<const JOURNAL: bool>(ctx: RetProbeContext) -> u32 {",
    );
    assert_eq!(
        entry.matches("object_entry_kem(").count(),
        1,
        "entry must call the KEM wrapper at exactly one site"
    );
}

/// Finding 4 (policy/flavor selection): KEM acquisition activates only
/// under the selected FULL allowlisted gate. This witness consumes the
/// actual selected build switches and executes the real gating seam in
/// every configuration cell (default FULL, Host P0, unsafe): the marker
/// arm (allowlisted policy only), the behind-required wrapper call, the
/// aggregate constructor (never a side), the shared entry adapter driven
/// with the cell's own gate, and the counter bank objects (aggregate
/// roots only, no object-entry code). P0, every counter mode, aggregate,
/// unsafe policy and unknown/count-only providers select no new KEM
/// acquisition. The FULL exact fetch lists are the S1 control: the
/// allowlisted S1 fields flow (no less), nothing new reads (no more).
///
/// The host `KEM_CAPTURE_WIRED` const is deliberately NOT the cell gate:
/// root features never forward to the host common crate, so it stays
/// FULL in every root cell; P0 reaches only the Detailed BPF bytes via
/// build.rs. The cell gate here is the root selection itself.
#[test]
fn object_kem_policy_and_flavor_zero_new_reads() {
    use p11scope_ebpf_common::object_flow::adapter_kem_entry;
    use p11scope_ebpf_common::object_wire::{ObjectStart, canonical_object_wire};
    use p11scope_ebpf_common::{ImageIdentity, LinuxLayout};

    // The actual selected switches drive every leg below.
    let p0 = cfg!(feature = "stub-object-attributes");
    let unsafe_build = cfg!(feature = "unsafe-unvalidated-metadata");
    let gate = !p0;

    // Marker arm (every cell, including unsafe/P0): ordinary seed,
    // exactly one arm site, exactly the allowlisted branch. Unsafe and
    // unknown/count-only providers keep the zero seed.
    let source = bpf_source();
    let entry = source_between(
        &source,
        "fn p11_entry_impl<const TEMPLATE_MODE: u8, const ENTRY_ABI: u8, const JOURNAL: bool>(",
        "fn p11_return_impl<const JOURNAL: bool>(ctx: RetProbeContext) -> u32 {",
    );
    assert!(
        entry.contains("object_required: 0,"),
        "entry must seed object_required to zero (ordinary)"
    );
    assert_eq!(
        entry.matches("object_marker_for").count(),
        1,
        "entry must arm the object marker at exactly one site"
    );
    assert!(
        entry.contains(
            "if flags & FLAG_POLICY_ALLOWLISTED != 0 {\n        seed.object_required = object_marker_for(cookie_of(&ctx));\n    }"
        ),
        "the marker call must be the body of the allowlisted-policy branch"
    );

    // KEM-behind-required: no KEM acquisition before the required gate;
    // exactly one wrapper call behind it, passing the build gate.
    let before_required = source_between(
        &source,
        "fn p11_entry_impl<const TEMPLATE_MODE: u8, const ENTRY_ABI: u8, const JOURNAL: bool>(",
        "if object_required != 0 {",
    );
    assert!(
        !before_required.contains("object_entry_kem("),
        "no KEM acquisition before the required gate (unsafe={unsafe_build})"
    );
    let required_region =
        source_between(&source, "if object_required != 0 {", "fn p11_return_impl<");
    assert_eq!(
        required_region.matches("object_entry_kem(").count(),
        1,
        "the KEM wrapper runs at exactly one site behind the required gate"
    );
    let kem = source_between(&source, "fn object_entry_kem(", "fn object_entry_results(");
    assert!(
        kem.contains("KEM_CAPTURE_WIRED"),
        "the KEM wrapper must pass the build gate, never a literal"
    );

    // Aggregate constructor (native): accounting-only delegation with a
    // null side source; no side allocation for any call including KEM.
    // The runtime no-side proof is the aggregate neighbor (owner suite).
    let native =
        std::fs::read_to_string("crates/ebpf/native/task_owner.c").expect("read native owner");
    let aggregate = source_between(
        &native,
        "u32 p11_owner_start_aggregate(",
        "/* Validated live subordinate row, or NULL.",
    );
    assert!(
        aggregate.contains("begin_owned_start(key, (void *)0, timestamp, 1)"),
        "aggregate must delegate with a null side source"
    );
    assert!(
        !aggregate.contains("object_side_alloc") && !aggregate.contains("OBJECT_START"),
        "aggregate must name no side allocation"
    );

    // Real gating seam: healthy vectors for both functions through the
    // shared entry adapter with the cell's own gate.
    fn entry_side(descriptor: u32, action: u8) -> ObjectStart {
        ObjectStart {
            image: ImageIdentity {
                task_cookie: 0xC0FF_EE00_C0FF_EE00,
                exec_id: 0xDEAD_BEEF_DEAD_BEEF,
            },
            entry_ns: 0x1111_2222_3333_4444,
            descriptor_index: descriptor,
            action,
            phase: 1,
            ..ObjectStart::default()
        }
    }
    for (function, non_null_fetches) in
        [(92u32, vec![2u8, 3, 4, 6, 5]), (93u32, vec![2u8, 3, 4, 5])]
    {
        let row = canonical_object_wire(function);
        let descriptor = function + 1;
        for output_non_null in [false, true] {
            let mut side = entry_side(descriptor, row.action);
            let mut fetches = Vec::new();
            let mut reads: Vec<u64> = Vec::new();
            let table: [(u8, Option<u64>); 7] = [
                (2, Some(0x1111)),
                (3, Some(0x5000)),
                (4, Some(2)),
                (5, Some(if output_non_null { 0x8000 } else { 0 })),
                (6, Some(0x6000)),
                (7, None),
                (0, None),
            ];
            let ok = adapter_kem_entry(
                Some(&mut side),
                descriptor,
                Some(&row),
                LinuxLayout::Lp64,
                0x1000,
                gate,
                output_non_null,
                false,
                &mut |index| {
                    fetches.push(index);
                    if index == 7 {
                        return None;
                    }
                    table
                        .iter()
                        .find_map(|slot| (slot.0 == index).then_some(slot.1).flatten())
                },
                |address| {
                    reads.push(address);
                    Ok(0x7000)
                },
            );
            if p0 {
                // P0 is blind to the S1 verdict: the gate refuses first
                // as a successful finite refusal — READY with unavailable
                // verdicts, zero fetches, zero reads.
                use p11scope_ebpf_common::object_capture::handle_status as hst;
                assert!(
                    ok && fetches.is_empty() && reads.is_empty(),
                    "P0 function {function} non_null={output_non_null}: finite refusal, no acquisition"
                );
                assert_eq!(side.inputs, [0, 0]);
                assert_eq!(
                    side.input_statuses,
                    [hst::PROTOCOL_UNAVAILABLE, hst::ABSENT]
                );
                assert_eq!(side.result_ptrs, [0, 0]);
                assert_eq!(side.phase, 2, "P0 finite refusal reaches READY");
            } else if output_non_null {
                // FULL allowlisted positive: the exact allowlisted S1
                // fields flow — no less (control), no more (no new reads).
                assert!(ok, "FULL function {function}: healthy entry acquires");
                assert_eq!(
                    fetches, non_null_fetches,
                    "FULL function {function}: exact fetches"
                );
                assert_eq!(
                    reads,
                    vec![0x1010],
                    "FULL function {function}: exactly the cell read"
                );
                assert_eq!(side.inputs, [0x1111, 0]);
                assert_eq!(side.result_ptrs, [0x7000, 0]);
                assert_eq!(side.phase, 2, "FULL reaches READY");
            } else if function == 92 {
                // FULL encap query: enters, retains nothing, reads
                // nothing. A null ciphertext probe performs no
                // cryptographic operation (entry + model guards).
                assert!(ok, "FULL encap: query enters");
                assert_eq!(
                    side.result_ptrs,
                    [0, 0],
                    "FULL encap: query retains nothing"
                );
                assert!(reads.is_empty(), "FULL encap: query reads nothing");
            } else {
                // FULL decap under a null secret-output verdict: the key
                // output is independent of secret sizing, so entry still
                // acquires and retains the provider-written key cell
                // exactly as the non-null leg. No over-refusal: the
                // query guards are encap-only by design.
                assert!(ok, "FULL decap: null-secret verdict still enters");
                assert_eq!(
                    fetches, non_null_fetches,
                    "FULL decap: null-secret verdict fetches identically"
                );
                assert_eq!(
                    reads,
                    vec![0x1010],
                    "FULL decap: null-secret verdict reads the cell"
                );
                assert_eq!(side.result_ptrs, [0x7000, 0]);
                assert_eq!(
                    side.phase, 2,
                    "FULL decap: null-secret verdict reaches READY"
                );
            }
        }
    }

    // Counter modes: selection-consistent, and no object-entry code in
    // any bank object (aggregate roots only). The bank maps/objects
    // share definitions with main; acquisition is code, and the code
    // is absent. The main object is the positive control.
    if !counter_objects_enabled() {
        assert_eq!(env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"), "");
        for token in COUNTER_BANK_TOKENS {
            assert!(
                counter_object_bytes(token).is_empty(),
                "{token} must be omitted when disabled"
            );
        }
        return;
    }
    let directory = tempfile::tempdir().expect("counter KEM-absence check");
    let main = embedded_object(directory.path());
    let mut paths = vec![main];
    for token in COUNTER_BANK_TOKENS {
        paths.push(write_counter_object(token, directory.path()));
    }
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-I", "-c", KEM_COUNTER_CHECKER])
        .args(&paths)
        .output()
        .expect("inspect counter objects for KEM acquisition");
    assert!(
        output.status.success(),
        "counter KEM-absence failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{}", String::from_utf8_lossy(&output.stdout));
}

/// Counter-bank KEM absence: argv[1] is the main object (positive
/// control: KEM acquisition code present), the rest are bank objects
/// (aggregate roots only, no object-entry code).
const KEM_COUNTER_CHECKER: &str = r##"
from pathlib import Path
import sys

sys.path.insert(0, str(Path('scripts').resolve()))
from _loader import load_path

checker = load_path(Path('scripts/check-bpf-map-defs.py'), 'kem_counter_checker')

main = Path(sys.argv[1])
names = [s[0] for s in checker.Elf(main.read_bytes()).symbols]
assert names, 'main object has no symbols (vacuous)'
assert any('object_entry_kem' in n for n in names), 'main object lacks object_entry_kem (positive control)'
assert 'p11_object_side_get' in names, 'main object lacks p11_object_side_get (positive control)'
assert 'p11_owner_start_begin' in names, 'main object lacks p11_owner_start_begin (positive control)'
print(f'main: {len(names)} symbols, KEM acquisition present (positive control)')

for path in sys.argv[2:]:
    names = [s[0] for s in checker.Elf(Path(path).read_bytes()).symbols]
    assert names, f'{path}: no symbols (vacuous)'
    assert 'p11_owner_start_aggregate' in names, f'{path}: no aggregate root (vacuous)'
    bad = [n for n in names
           if 'object_entry' in n or 'object_fill' in n
           or n in ('p11_object_side_get', 'p11_owner_start_begin')]
    assert not bad, f'{path}: object acquisition code present: {bad}'
    print(f'{path}: {len(names)} symbols, aggregate-only, no object acquisition')
"##;

/// The private validated tail accompanies the owned H3 routed call into
/// the consuming admission result, but it cannot construct the H9 model:
/// no ObjectDomain, OriginFact, RefCut, CallToken, CompleteInputPrefix,
/// and no ObjectSemantics::{begin,complete,settle} in the transport. Only the
/// three exact borrowed model parameters on Joint delivery callbacks may name
/// ObjectSemantics; their bodies and other transport remain construction-free.
#[test]
fn object_producer_tail_builds_no_model() {
    // Existence: the transport carries the tail end to end.
    let capture = std::fs::read_to_string("src/semantic_capture.rs").expect("read capture router");
    assert!(
        capture.contains("decoded: DecodedEventRecord"),
        "RoutedCall must carry the decoded envelope with its tail"
    );
    assert!(
        capture.contains("fn into_object_tail(self) -> Option<ValidatedObjectCall>"),
        "RoutedCall must hand its tail move-only to the sole consumer"
    );
    let input = std::fs::read_to_string("src/discovery/caller_registry/instance_input.rs")
        .expect("read evidence adapter");
    assert!(
        input.matches("object: Option<ValidatedObjectCall>").count() >= 2,
        "CallEvidence and the admission result must carry the tail"
    );
    // Absence: no model construction in the H7 transport windows.
    for (name, body) in [
        (
            "src/events.rs",
            std::fs::read_to_string("src/events.rs").expect("read events"),
        ),
        ("src/semantic_capture.rs", capture),
        ("src/discovery/caller_registry/instance_input.rs", input),
    ] {
        assert_eq!(
            transport_boundaries::model_marker(name, &body),
            None,
            "{name} transport must not name the H9 model outside sanctioned borrowed parameters"
        );
    }
    let coordinator = std::fs::read_to_string("src/discovery/inventory_coordinator/semantics.rs")
        .expect("read coordinator");
    assert_eq!(
        transport_boundaries::model_marker(
            "src/discovery/inventory_coordinator/semantics.rs",
            &coordinator
        ),
        None,
        "coordinator transport must not name the H9 model"
    );
}

/// The tail and its envelopes carry raw target words: no raw-value
/// Debug/Serialize anywhere on the H7 transport path.
#[test]
fn object_producer_tail_has_no_raw_debug_or_serialize() {
    let wire =
        std::fs::read_to_string("crates/ebpf-common/src/object_wire.rs").expect("read object wire");
    let validated = source_between(
        &wire,
        "pub struct ValidatedObjectCall {",
        "/// Meaning of a START `object_required` marker word against the frozen",
    );
    // No Debug derive/impl and no Serialize: only the doc comment names
    // the deliberately absent Debug.
    assert!(
        !validated.contains("Serialize")
            && !validated.contains("Debug for ValidatedObjectCall")
            && !validated.contains("derive("),
        "ValidatedObjectCall must stay Debug/Serialize-free"
    );
    let head = wire
        .find("pub struct ValidatedObjectCall {")
        .expect("validated tail struct");
    assert!(
        wire[head.saturating_sub(200)..head].contains("#[derive(Clone, Copy)]"),
        "ValidatedObjectCall derives only Clone and Copy"
    );
    // Existence: the envelopes that must stay redacted.
    for (path, redacted) in [
        ("src/events.rs", "pub(crate) struct DecodedEventRecord {"),
        (
            "src/discovery/caller_registry/instance_input.rs",
            "pub(crate) struct CallEvidence {",
        ),
    ] {
        let body = std::fs::read_to_string(path).expect("read envelope");
        assert!(
            body.contains("Option<ValidatedObjectCall>"),
            "{path} must carry the private validated tail"
        );
        assert!(
            !body.contains("Serialize"),
            "{path} transport must not Serialize raw tails"
        );
        let _ = redacted;
    }
    let input = std::fs::read_to_string("src/discovery/caller_registry/instance_input.rs")
        .expect("read evidence adapter");
    assert!(
        input.contains("CallEvidence(<private>)"),
        "CallEvidence Debug must stay redacted"
    );
}

/// H7 publishes no object arrays, IDs, birth/destruction or key-use
/// labels: the admission result carries the tail privately with no
/// public object projection.
#[test]
fn object_producer_public_surface_has_no_object_labels() {
    let input = std::fs::read_to_string("src/discovery/caller_registry/instance_input.rs")
        .expect("read evidence adapter");
    // Existence: the admission result carries the tail.
    let admitted = source_between(
        &input,
        "pub(crate) struct AdmittedInstanceCall {",
        "enum InstanceScope {",
    );
    assert!(
        admitted.contains("Option<ValidatedObjectCall>"),
        "the admission result must carry the private tail"
    );
    // Absence: no public object projection on the result.
    for marker in [
        "pub fn objects",
        "pub fn object_ids",
        "pub fn birth",
        "pub fn destruction",
        "pub fn key_use",
        "object_ids",
        "key_use_labels",
    ] {
        assert!(
            !admitted.contains(marker),
            "the admission result must not project {marker}"
        );
    }
}

/// The outlined emission helpers survive in the embedded object next to
/// the five adapter helpers; no monolithic native drain appears.
#[test]
fn object_producer_emission_helpers_in_elf() {
    let directory = tempfile::tempdir().expect("temporary emission ELF check");
    let object = embedded_object(directory.path());
    let output = Command::new("nm")
        .arg("--defined-only")
        .arg(&object)
        .output()
        .expect("run nm on embedded object");
    assert!(
        output.status.success(),
        "nm failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let symbols = String::from_utf8_lossy(&output.stdout).into_owned();
    for helper in ["object_tail_fill", "object_emit_find"] {
        let hits: Vec<&str> = symbols
            .lines()
            .filter(|line| line.contains(helper) && (line.contains(" T ") || line.contains(" t ")))
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "expected one .text {helper}, saw {}: {hits:?}",
            hits.len()
        );
    }
    assert!(
        !symbols.contains("p11_object_return_remove"),
        "no monolithic native drain"
    );
}

/// A joinable entry/return stamp pair: equal epochs, a watched file, the
/// VALID bit and no refusal flag.
fn clean_stamps() -> (
    p11scope_ebpf_common::InstanceStamp,
    p11scope_ebpf_common::InstanceStamp,
) {
    let stamp = p11scope_ebpf_common::InstanceStamp {
        epoch: 7,
        global: 9,
        fault: 11,
        file_slot_plus1: 3,
        flags: p11scope_ebpf_common::instance::STAMP_VALID,
    };
    (stamp, stamp)
}

/// Every continuity refusal the return gate must enforce: absent entry
/// (all-zero stamp), straddled epoch/global/fault/file-slot, missing
/// VALID, and each blocking flag.
fn refused_stamp_pairs() -> Vec<(
    &'static str,
    p11scope_ebpf_common::InstanceStamp,
    p11scope_ebpf_common::InstanceStamp,
)> {
    use p11scope_ebpf_common::instance;
    let (entry, ret) = clean_stamps();
    let zero = p11scope_ebpf_common::InstanceStamp::default();
    let mut cases = Vec::new();
    cases.push(("absent entry", zero, ret));
    for (name, mutate) in [
        ("epoch straddle", 0u8),
        ("global straddle", 1u8),
        ("fault straddle", 2u8),
        ("file-slot straddle", 3u8),
    ] {
        let mut moved = ret;
        match mutate {
            0 => moved.epoch = moved.epoch.wrapping_add(1),
            1 => moved.global = moved.global.wrapping_add(1),
            2 => moved.fault = moved.fault.wrapping_add(1),
            _ => moved.file_slot_plus1 = moved.file_slot_plus1.wrapping_add(1),
        };
        cases.push((name, entry, moved));
    }
    let mut no_valid = ret;
    no_valid.flags &= !instance::STAMP_VALID;
    cases.push(("missing VALID", entry, no_valid));
    for (name, flag) in [
        ("NO_FILE", instance::STAMP_NO_FILE),
        ("NO_TASK", instance::STAMP_NO_TASK),
        ("SHARED_MM", instance::STAMP_SHARED_MM),
        ("OVERFLOW", instance::STAMP_OVERFLOW),
        ("LOCAL_FAULT", instance::STAMP_LOCAL_FAULT),
    ] {
        let mut flagged = entry;
        flagged.flags |= flag;
        cases.push((name, flagged, flagged));
    }
    cases
}

/// H7-E1 return-arm harness. Executes the REAL production adapter bodies
/// (`object_flow::{continuity_joins, adapter_fill_return, adapter_tail_fill,
/// adapter_emit_find, adapter_emit_get_attributes}` — the same functions the
/// BPF wrappers call) in the root's order (gate → fill → tail → find → get,
/// each `&&` short-circuiting like the root) with instrumented readers and
/// a caller-owned side row. Every outcome below is computed by production
/// code; the only modeled input is the native retirement result (the C
/// fixture executes the real removal; see G03). The order pins below bind
/// the harness sequence to the root.
struct EmissionOutcome {
    joined: bool,
    filled: bool,
    tailed: bool,
    emitted: bool,
    fault_required: bool,
    base_emitted: bool,
    base_output_attempts: usize,
    side: p11scope_ebpf_common::object_wire::ObjectStart,
    tail: p11scope_ebpf_common::object_wire::ObjectCallWire,
}

/// A frozen descriptor row for the harness: `descriptor` names function
/// `descriptor - 1`, one result arg, no templates, valid action/guard.
fn harness_row(
    descriptor: u32,
    action: u8,
    result_args: [u8; 2],
) -> p11scope_ebpf_common::object_wire::ObjectDescriptorWire {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::object_wire::{OBJECT_GUARD_NAMED, ObjectDescriptorWire};
    ObjectDescriptorWire {
        function: descriptor.wrapping_sub(1),
        input_args: [ARG_NONE; 2],
        result_args,
        template_args: [ARG_NONE; 4],
        find_capacity_arg: ARG_NONE,
        find_count_arg: ARG_NONE,
        action,
        guard: OBJECT_GUARD_NAMED,
    }
}

/// A READY (phase 2) caller-owned side row, as the required=1 return query
/// hands it to the fill adapter.
fn ready_side(descriptor: u32) -> p11scope_ebpf_common::object_wire::ObjectStart {
    p11scope_ebpf_common::object_wire::ObjectStart {
        descriptor_index: descriptor,
        phase: 2,
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
fn run_production_return_arm(
    target: &std::cell::RefCell<adapter::FakeTarget>,
    layout: p11scope_ebpf_common::LinuxLayout,
    mut side: p11scope_ebpf_common::object_wire::ObjectStart,
    row: &p11scope_ebpf_common::object_wire::ObjectDescriptorWire,
    rv: u64,
    continuity: &p11scope_ebpf_common::InstanceContinuity,
    mech_status: u32,
    mech: u64,
    retire_ok: bool,
) -> EmissionOutcome {
    use p11scope_ebpf_common::object_flow::{
        RefusedBaseOutcome, adapter_emit_find, adapter_emit_get_attributes, adapter_fill_return,
        adapter_tail_fill, continuity_joins, emission_finalize, preserve_refused_base,
    };
    use p11scope_ebpf_common::object_wire::ObjectCallWire;
    let descriptor = side.descriptor_index;
    // Gate: the production predicate on the reserved record's stamps.
    let joined = continuity_joins(continuity);
    if !joined {
        let outputs = std::cell::Cell::new(0);
        let outcome = preserve_refused_base(
            || retire_ok,
            || {},
            || {
                outputs.set(outputs.get() + 1);
                true
            },
        );
        return EmissionOutcome {
            joined,
            filled: false,
            tailed: false,
            emitted: false,
            fault_required: true,
            base_emitted: outcome == RefusedBaseOutcome::Emitted,
            base_output_attempts: outputs.get(),
            side,
            tail: ObjectCallWire::default(),
        };
    }
    // Fills in root order; each stage short-circuits like the root, so a
    // refused fill runs no later adapter and touches no tail.
    let (reader, _) = adapter::readers(target);
    let filled = adapter_fill_return(
        Some(&mut side),
        descriptor,
        Some(row),
        rv,
        layout,
        mech_status,
        mech,
        joined,
        reader,
    );
    let mut tail = ObjectCallWire::default();
    let tailed = filled
        && unsafe { adapter_tail_fill(&mut tail as *mut _, Some(&side), descriptor, Some(row)) };
    let (reader, _) = adapter::readers(target);
    let emitted = tailed
        && unsafe {
            adapter_emit_find(
                &mut tail as *mut _,
                Some(&side),
                descriptor,
                Some(row),
                layout,
                rv,
                joined,
                reader,
            )
        };
    // The root's fourth emission stage: Get result establishment. The G02
    // vectors are all non-Get rows, so this stage succeeds trivially with
    // zero reads here; it executes for root fidelity.
    let (reader, bytes) = adapter::readers(target);
    let emitted = emitted
        && unsafe {
            adapter_emit_get_attributes(
                &mut tail as *mut _,
                Some(&side),
                descriptor,
                Some(row),
                layout,
                rv,
                joined,
                reader,
                bytes,
            )
        };
    // The fault decision is production's `emission_finalize` (the same
    // function the BPF return root calls); only the native `retire_ok`
    // input is modeled here.
    let outcome = emission_finalize(emitted, || retire_ok);
    EmissionOutcome {
        joined,
        filled,
        tailed,
        emitted,
        fault_required: !joined || outcome.faulted,
        base_emitted: false,
        base_output_attempts: 0,
        side,
        tail,
    }
}

/// Wrap an entry/return stamp pair the way the reserved record carries it.
fn continuity_of(
    entry: p11scope_ebpf_common::InstanceStamp,
    ret: p11scope_ebpf_common::InstanceStamp,
) -> p11scope_ebpf_common::InstanceContinuity {
    p11scope_ebpf_common::InstanceContinuity {
        entry_ip: 0,
        entry_stamp: entry,
        return_stamp: ret,
    }
}

/// Every production attribute read must be a read the oracle also
/// performs: the production path may read less (nothing, while E4 is
/// unwired) but never more. Guards a wired E4 against over-reading.
fn assert_reads_subset(
    prod: &std::cell::RefCell<adapter::FakeTarget>,
    oracle: &std::cell::RefCell<adapter::FakeTarget>,
    what: &str,
) {
    for entry in prod.borrow().log().iter() {
        assert!(
            oracle.borrow().log().contains(entry),
            "{what}: production read {entry:?} is outside the oracle set"
        );
    }
}

fn pin_continuity_gate_precedes_fills() {
    let source = bpf_source();
    // Each object copy fills continuity and gates on the join before
    // every object result read; the refused gate arm retires ownership
    // through the copy's own removal and faults, preserves only the
    // ordinary base, then discards the unfilled object reservation.
    // The ordinary copy retires through the owned removal, the generic
    // copy through the journal removal with its identity reason.
    for (name, start, end, retire) in [
        (
            "ordinary copy",
            "fn object_return_ordinary(",
            "fn object_return<const JOURNAL: bool, Record: ReturnPayload>(",
            "owned_start_remove(&key, true)",
        ),
        (
            "generic copy",
            "fn object_return<const JOURNAL: bool, Record: ReturnPayload>(",
            "pub extern \"C\" fn p11_link_fork_allowed",
            "start_remove_for::<JOURNAL>(&key, true, JOURNAL_REASON_IDENTITY_REFUSED)",
        ),
    ] {
        let body = source_between(&source, start, end);
        let continuity = body
            .find("p11_instance_return(&key,")
            .unwrap_or_else(|| panic!("{name} must fill continuity on the object arm"));
        let gate = body
            .find("continuity_joins(")
            .unwrap_or_else(|| panic!("{name} must gate object reads on the shared stamp join"));
        let fill = body
            .find("object_fill_return(")
            .unwrap_or_else(|| panic!("{name} emission fills after the gate"));
        let find = body
            .find("object_emit_find(")
            .unwrap_or_else(|| panic!("{name} Find emits after the gate"));
        assert!(
            continuity < gate && gate < fill && fill < find,
            "{name}: continuity fill, join gate, result fill and Find emission must run in that order"
        );
        let arm = &body[gate..fill];
        for marker in ["entry.discard(0)", retire, "p11_object_fault()"] {
            assert!(
                arm.contains(marker),
                "{name}: the refused gate arm must {marker} before any object read"
            );
        }
        // The copy threads its verdict into the fill adapters, which
        // enforce it again inside the executed production flow.
        let filled_call = source_between(body, "let filled = object_fill_return(", ");");
        assert!(
            filled_call.contains("joined"),
            "{name}: the result fill must receive the root continuity verdict"
        );
        let emitted_call = source_between(body, "let emitted =", ";");
        assert!(
            emitted_call.contains("joined"),
            "{name}: Find emission must receive the root continuity verdict"
        );
    }
    // Delegation: the BPF wrappers bind BPF-local state and call the
    // shared adapters the harness executes — no second inline copy.
    for (wrapper, shared) in [
        ("fn object_fill_return(", "adapter_fill_return_control("),
        ("fn object_tail_fill(", "adapter_tail_fill("),
        ("fn object_emit_find(", "adapter_emit_find_control("),
    ] {
        let body = source_between(&source, wrapper, "\n}\n");
        assert_eq!(
            body.matches(shared).count(),
            1,
            "{wrapper} must delegate to exactly one shared {shared}"
        );
    }
    // Executed order: inside the shared fill, the continuity gate runs
    // before any slot read.
    let flow = std::fs::read_to_string("crates/ebpf-common/src/object_flow.rs")
        .expect("read shared adapter flow");
    let shared_fill = source_between(
        &flow,
        "pub fn adapter_fill_return(",
        "pub unsafe fn adapter_tail_fill(",
    );
    let shared_gate = shared_fill
        .find("if !joined")
        .expect("the shared fill must gate on continuity");
    let first_read = shared_fill
        .find("slot_word(")
        .expect("the shared fill reads result words");
    assert!(
        shared_gate < first_read,
        "the executed fill must gate before its first read"
    );
}

/// Continuity refusal preserves the initialized ordinary return without
/// granting permission to fill an object tail. The shared adapter's executed
/// cleanup/output controls are covered by the common and raw decoder tests.
#[test]
fn object_return_refused_continuity_keeps_ordinary_base() {
    pin_continuity_gate_precedes_fills();
    let source = bpf_source();
    // Both object copies preserve exactly the initialized 368-byte base
    // on refused continuity: same output shape and stamps, same loss
    // accounting, no fill/emission in the refused arm, no second record
    // on the healthy path. Only the retirement differs per copy.
    for (name, start, end, retire) in [
        (
            "ordinary copy",
            "fn object_return_ordinary(",
            "fn object_return<const JOURNAL: bool, Record: ReturnPayload>(",
            "|| owned_start_remove(&key, true).is_ok()",
        ),
        (
            "generic copy",
            "fn object_return<const JOURNAL: bool, Record: ReturnPayload>(",
            "pub extern \"C\" fn p11_link_fork_allowed",
            "|| start_remove_for::<JOURNAL>(&key, true, JOURNAL_REASON_IDENTITY_REFUSED).is_ok()",
        ),
    ] {
        let returned = source_between(&source, start, end);
        let arm = source_between(returned, "if !joined {", "let tail =");
        let preserve = arm.find("preserve_refused_base(").unwrap_or_else(|| {
            panic!("{name}: a refused object join must preserve one ordinary base after checked retirement")
        });
        let output = arm
            .find(".output::<EventRecord>(unsafe { &(*raw).base }, 0)")
            .unwrap_or_else(|| {
                panic!("{name}: copy exactly the initialized 368-byte EventRecord, with its original stamps")
            });
        let discard = arm
            .find("entry.discard(0)")
            .unwrap_or_else(|| panic!("{name}: release the original reservation"));
        assert!(
            preserve < output && output < discard,
            "{name}: output must run while the original reservation is owned"
        );
        assert!(
            arm.contains(retire),
            "{name}: refused arm must retire through its own removal"
        );
        assert!(arm.contains("RefusedBaseOutcome::OutputFailed"));
        assert!(arm.contains("bump_evidence(EVIDENCE_RING_LOSS)"));
        assert!(arm.contains("bump_evidence(EVIDENCE_UNMATCHED_RETURNS)"));
        assert!(
            !arm[discard..].contains("raw"),
            "{name}: never read a discarded reservation"
        );
        assert!(!arm.contains("object_fill_return("));
        assert!(!arm.contains("object_tail_fill("));
        assert!(!arm.contains("object_emit_"));
        // Changed-image order (F4): the image refusal precedes the first
        // fill in the object return arm, so a return whose task image
        // changed retires before any read. The arm is
        // descriptor-agnostic; KEM flows through it (behind-required pin).
        assert_eq!(
            returned.matches("image_pair_matches").count(),
            1,
            "{name}: exactly one image check in the object arm"
        );
        let image_at = returned.find("image_pair_matches").unwrap();
        let fill_at = returned.find("object_fill_return(").unwrap();
        assert!(
            image_at < fill_at,
            "{name}: image refusal must precede the first fill"
        );
        let healthy = source_between(returned, "let tail =", "entry.submit(0)");
        assert!(
            !healthy.contains("EVENTS.output"),
            "{name}: healthy 608-byte returns do not copy a second record"
        );
    }
}

/// G02/E1: refused continuity performs zero result-handle reads. Healthy
/// twin reads the exact expected result once and retains the joined
/// stamps; every refusal (absent entry, straddled epoch/global/fault/
/// file-slot, missing VALID, each blocking flag) reads nothing, runs no
/// later adapter, leaves the tail zero and faults visibly. All fills run
/// through the production adapters, so neutering the production gate
/// fails this test.
#[test]
fn object_return_continuity_refuses_before_reads() {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::capture;
    use p11scope_ebpf_common::object_capture::handle_status;
    use p11scope_ebpf_common::object_wire::{OBJECT_ACTION_CREATE, ObjectCallWire};
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        let row = harness_row(23, OBJECT_ACTION_CREATE, [5, ARG_NONE]);
        let healthy_side = || {
            let mut side = ready_side(23);
            side.result_ptrs = [0x10000, 0];
            side
        };
        // Healthy twin: one present result, CKR_OK, joined stamps.
        let target = adapter::FakeTarget::new(w);
        let target = std::cell::RefCell::new(target);
        target.borrow_mut().set_word(0x10000, 0x42);
        let (entry, ret) = clean_stamps();
        let outcome = run_production_return_arm(
            &target,
            layout,
            healthy_side(),
            &row,
            adapter::rv_ok(),
            &continuity_of(entry, ret),
            capture::MECHANISM_VALUE,
            0,
            true,
        );
        assert_eq!(
            target.borrow().log(),
            &[(adapter::READ_WORD, 0x10000, w)],
            "{layout:?} healthy twin must read the exact result once"
        );
        assert!(outcome.joined && outcome.filled && outcome.tailed && outcome.emitted);
        assert!(!outcome.base_emitted);
        assert_eq!(
            outcome.base_output_attempts, 0,
            "healthy 608 path copies no base"
        );
        assert_eq!(
            outcome.side.result_statuses,
            [handle_status::VALUE, handle_status::ABSENT]
        );
        assert_eq!(outcome.side.result_ptrs, [0x42, 0]);
        assert_eq!(outcome.side.phase, 3);
        assert_eq!(outcome.tail.result_handles, [0x42, 0]);
        assert_eq!(
            outcome.tail.result_status,
            [handle_status::VALUE, handle_status::ABSENT]
        );
        assert!(!outcome.fault_required, "healthy twin faults nothing");
        assert!(
            p11scope_ebpf_common::instance::stamp_joinable(entry, ret),
            "healthy twin retains the joined stamps"
        );
        // Failed reads are distinct from refused reads: a joined call
        // whose result word is unreadable attempts the read once and
        // carries UNREADABLE, never VALUE and never zero-read silence.
        // The finite failure still completes every stage.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        target.borrow_mut().set_fail(0x10000);
        let (entry, ret) = clean_stamps();
        let outcome = run_production_return_arm(
            &target,
            layout,
            healthy_side(),
            &row,
            adapter::rv_ok(),
            &continuity_of(entry, ret),
            capture::MECHANISM_VALUE,
            0,
            true,
        );
        assert_eq!(
            target.borrow().log(),
            &[(adapter::READ_WORD, 0x10000, w)],
            "{layout:?} failed result word is attempted once"
        );
        assert!(outcome.joined && outcome.filled && outcome.tailed && outcome.emitted);
        assert_eq!(
            outcome.side.result_statuses,
            [handle_status::UNREADABLE, handle_status::ABSENT]
        );
        assert_eq!(outcome.side.result_ptrs, [0, 0]);
        // Ordinary accounting stays truthful: joined stamps with a
        // non-OK RV read nothing, keep the honest tail (unavailable
        // cells, never values) and fault nothing.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        target.borrow_mut().set_word(0x10000, 0x42);
        let (entry, ret) = clean_stamps();
        let outcome = run_production_return_arm(
            &target,
            layout,
            healthy_side(),
            &row,
            7,
            &continuity_of(entry, ret),
            capture::MECHANISM_VALUE,
            0,
            true,
        );
        adapter::assert_no_target_reads(&target, &format!("{layout:?} result reads on RV 7"));
        assert!(outcome.joined && outcome.filled && outcome.tailed && outcome.emitted);
        assert_eq!(
            outcome.side.result_statuses,
            [handle_status::PROTOCOL_UNAVAILABLE, handle_status::ABSENT]
        );
        assert_eq!(
            outcome.tail.result_status,
            [handle_status::PROTOCOL_UNAVAILABLE, handle_status::ABSENT]
        );
        assert!(!outcome.fault_required, "non-OK RV faults nothing");
        // A failed native retirement faults even when every adapter
        // stage succeeded (the native half is executed by the G03 C
        // fixture; this input only threads its verdict).
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        target.borrow_mut().set_word(0x10000, 0x42);
        let (entry, ret) = clean_stamps();
        let outcome = run_production_return_arm(
            &target,
            layout,
            healthy_side(),
            &row,
            adapter::rv_ok(),
            &continuity_of(entry, ret),
            capture::MECHANISM_VALUE,
            0,
            false,
        );
        assert!(outcome.joined && outcome.filled && outcome.tailed && outcome.emitted);
        assert!(
            outcome.fault_required,
            "{layout:?} failed retirement faults visibly"
        );
        // Every refusal: zero reads, no later adapter, zero tail, the
        // retained pointers preserved, visible fault.
        for (name, entry, ret) in refused_stamp_pairs() {
            let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            target.borrow_mut().set_word(0x10000, 0x42);
            let outcome = run_production_return_arm(
                &target,
                layout,
                healthy_side(),
                &row,
                adapter::rv_ok(),
                &continuity_of(entry, ret),
                capture::MECHANISM_VALUE,
                0,
                true,
            );
            adapter::assert_no_target_reads(&target, &format!("{layout:?} result reads on {name}"));
            assert!(
                !outcome.joined && !outcome.filled && !outcome.tailed && !outcome.emitted,
                "{layout:?} {name}: refused continuity runs no adapter stage"
            );
            assert!(
                outcome.tail == ObjectCallWire::default(),
                "{layout:?} {name}: refused continuity leaves the tail zero"
            );
            assert_eq!(
                outcome.side.result_ptrs,
                [0x10000, 0],
                "{layout:?} {name}: refused continuity preserves retained pointers"
            );
            assert_eq!(outcome.side.phase, 2, "{layout:?} {name}: side stays READY");
            assert!(
                outcome.fault_required,
                "{layout:?} {name}: refused continuity faults visibly"
            );
            assert!(
                outcome.base_emitted,
                "{layout:?} {name}: retain one ordinary return"
            );
            assert_eq!(outcome.base_output_attempts, 1);

            let failed_retirement = run_production_return_arm(
                &target,
                layout,
                healthy_side(),
                &row,
                adapter::rv_ok(),
                &continuity_of(entry, ret),
                capture::MECHANISM_VALUE,
                0,
                false,
            );
            assert!(!failed_retirement.base_emitted);
            assert_eq!(failed_retirement.base_output_attempts, 0);
            adapter::assert_no_target_reads(&target, "failed retirement grants no object reads");
        }
    }
    pin_continuity_gate_precedes_fills();
}

/// G02/E1: refused continuity performs zero Find reads: no count read,
/// no element reads, no reread. Healthy twin streams the exact
/// count/element/reread sequence through the production Find adapter;
/// every refusal reads nothing and streams no Find section.
#[test]
fn object_find_continuity_refuses_before_reads() {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::capture;
    use p11scope_ebpf_common::object_capture::handle_status;
    use p11scope_ebpf_common::object_wire::{OBJECT_ACTION_FIND, ObjectCallWire};
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        let row = harness_row(23, OBJECT_ACTION_FIND, [ARG_NONE, ARG_NONE]);
        let program_find = |target: &std::cell::RefCell<adapter::FakeTarget>| {
            let mut borrowed = target.borrow_mut();
            borrowed.set_word(0x21000, 2);
            borrowed.set_word(0x20000, 0x51);
            borrowed.set_word(0x20000 + w, 0x52);
        };
        let healthy_side = || {
            let mut side = ready_side(23);
            side.result_ptrs = [0x20000, 0];
            side.find_capacity = 8;
            side.find_count_ptr = 0x21000;
            side
        };
        // Healthy twin: count read, two elements, count reread.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_find(&target);
        let (entry, ret) = clean_stamps();
        let outcome = run_production_return_arm(
            &target,
            layout,
            healthy_side(),
            &row,
            adapter::rv_ok(),
            &continuity_of(entry, ret),
            capture::MECHANISM_VALUE,
            0,
            true,
        );
        assert_eq!(
            target.borrow().log(),
            &[
                (adapter::READ_WORD, 0x21000, w),
                (adapter::READ_WORD, 0x20000, w),
                (adapter::READ_WORD, 0x20000 + w, w),
                (adapter::READ_WORD, 0x21000, w),
            ],
            "{layout:?} healthy Find twin must stream count, elements, reread"
        );
        assert!(outcome.joined && outcome.filled && outcome.tailed && outcome.emitted);
        assert_eq!(outcome.tail.find_valid, 1, "healthy Find twin validates");
        assert_eq!(outcome.tail.find_len, 2);
        assert_eq!(
            outcome.tail.find_status[..2],
            [handle_status::VALUE, handle_status::VALUE]
        );
        assert_eq!(outcome.tail.find_handles[..2], [0x51, 0x52]);
        assert_eq!(
            outcome.tail.result_status,
            [handle_status::PROTOCOL_UNAVAILABLE, handle_status::ABSENT],
            "{layout:?} Find result cell stays the constant unavailable cell"
        );
        assert!(!outcome.fault_required, "healthy Find twin faults nothing");
        // Ordinary accounting stays truthful: joined stamps with a
        // non-OK RV read neither count nor elements, validate nothing
        // and fault nothing, while every stage still completes.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_find(&target);
        let (entry, ret) = clean_stamps();
        let outcome = run_production_return_arm(
            &target,
            layout,
            healthy_side(),
            &row,
            7,
            &continuity_of(entry, ret),
            capture::MECHANISM_VALUE,
            0,
            true,
        );
        adapter::assert_no_target_reads(&target, &format!("{layout:?} Find reads on RV 7"));
        assert!(outcome.joined && outcome.filled && outcome.tailed && outcome.emitted);
        assert_eq!(
            outcome.tail.find_valid, 0,
            "non-OK RV validates no Find batch"
        );
        assert!(!outcome.fault_required, "non-OK RV faults nothing");
        // Every refusal: the count word itself is unread.
        for (name, entry, ret) in refused_stamp_pairs() {
            let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            program_find(&target);
            let outcome = run_production_return_arm(
                &target,
                layout,
                healthy_side(),
                &row,
                adapter::rv_ok(),
                &continuity_of(entry, ret),
                capture::MECHANISM_VALUE,
                0,
                true,
            );
            adapter::assert_no_target_reads(&target, &format!("{layout:?} Find reads on {name}"));
            assert!(
                !outcome.joined && !outcome.filled && !outcome.tailed && !outcome.emitted,
                "{layout:?} {name}: refused continuity runs no adapter stage"
            );
            assert!(
                outcome.tail == ObjectCallWire::default(),
                "{layout:?} {name}: refused continuity leaves the tail zero"
            );
            assert!(
                outcome.fault_required,
                "{layout:?} {name}: refused continuity faults visibly"
            );
        }
    }
    pin_continuity_gate_precedes_fills();
}

/// Fix round 1 mutation control for the G02 probe: the production gate
/// and adapter custody are load-bearing. Deleting `if !joined` from the
/// shared adapters, or substituting one stamp for the other in
/// `continuity_joins`, fails this test (verified by manual mutant during
/// the fix round). Refused custody reads nothing on every adapter.
#[test]
fn object_return_gate_and_custody_refuse_without_reads() {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::capture;
    use p11scope_ebpf_common::object_flow::{
        adapter_derive_entry, adapter_emit_find, adapter_fill_return, adapter_tail_fill,
        continuity_joins,
    };
    use p11scope_ebpf_common::object_wire::{
        OBJECT_ACTION_CREATE, OBJECT_ACTION_DERIVE, ObjectCallWire,
    };
    // The shared predicate joins clean stamps and refuses every
    // asymmetric pair.
    let (entry, ret) = clean_stamps();
    assert!(continuity_joins(&continuity_of(entry, ret)));
    for (name, entry, ret) in refused_stamp_pairs() {
        assert!(
            !continuity_joins(&continuity_of(entry, ret)),
            "{name} must not join"
        );
    }
    // Substituting the current stamp for the retained one would join the
    // absent-entry case: the predicate genuinely reads both fields, so a
    // substitution mutant fails the refusal asserts above.
    let (_, absent_entry, clean_ret) = refused_stamp_pairs()[0];
    assert!(continuity_joins(&continuity_of(clean_ret, clean_ret)));
    assert!(!continuity_joins(&continuity_of(absent_entry, clean_ret)));
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        let row = harness_row(23, OBJECT_ACTION_CREATE, [5, ARG_NONE]);
        // `joined = false` refuses inside every reading adapter with
        // zero reads, however the adapter was reached.
        for gate in [true, false] {
            let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            target.borrow_mut().set_word(0x10000, 0x42);
            let mut side = ready_side(23);
            side.result_ptrs = [0x10000, 0];
            let (reader, _) = adapter::readers(&target);
            let filled = adapter_fill_return(
                Some(&mut side),
                23,
                Some(&row),
                adapter::rv_ok(),
                layout,
                capture::MECHANISM_VALUE,
                0,
                gate,
                reader,
            );
            assert_eq!(filled, gate, "{layout:?} fill follows the gate");
            if gate {
                assert_eq!(
                    target.borrow().log(),
                    &[(adapter::READ_WORD, 0x10000, w)],
                    "{layout:?} joined fill reads its result once"
                );
            } else {
                adapter::assert_no_target_reads(&target, &format!("{layout:?} gated fill"));
            }
            // Find emission follows the same gate.
            let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            target.borrow_mut().set_word(0x21000, 1);
            let mut side = ready_side(23);
            side.phase = 3;
            side.result_ptrs = [0x20000, 0];
            side.find_capacity = 8;
            side.find_count_ptr = 0x21000;
            let mut tail = ObjectCallWire::default();
            let (reader, _) = adapter::readers(&target);
            let emitted = unsafe {
                adapter_emit_find(
                    &mut tail as *mut _,
                    Some(&side),
                    23,
                    Some(&harness_row(
                        23,
                        p11scope_ebpf_common::object_wire::OBJECT_ACTION_FIND,
                        [ARG_NONE, ARG_NONE],
                    )),
                    layout,
                    adapter::rv_ok(),
                    gate,
                    reader,
                )
            };
            assert_eq!(emitted, gate, "{layout:?} Find emission follows the gate");
            if !gate {
                adapter::assert_no_target_reads(&target, &format!("{layout:?} gated Find"));
            }
        }
        // Custody failures refuse without reads: missing side, wrong
        // phase, missing or mismatched row, null tail.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        target.borrow_mut().set_word(0x10000, 0x42);
        let mut side = ready_side(23);
        side.result_ptrs = [0x10000, 0];
        let (reader, _) = adapter::readers(&target);
        assert!(
            !adapter_fill_return(
                None,
                23,
                Some(&row),
                adapter::rv_ok(),
                layout,
                capture::MECHANISM_VALUE,
                0,
                true,
                reader,
            ),
            "{layout:?} missing side refuses the fill"
        );
        let mut wrong_phase = ready_side(23);
        wrong_phase.phase = 1;
        wrong_phase.result_ptrs = [0x10000, 0];
        let (reader, _) = adapter::readers(&target);
        assert!(
            !adapter_fill_return(
                Some(&mut wrong_phase),
                23,
                Some(&row),
                adapter::rv_ok(),
                layout,
                capture::MECHANISM_VALUE,
                0,
                true,
                reader,
            ),
            "{layout:?} non-READY phase refuses the fill"
        );
        let (reader, _) = adapter::readers(&target);
        assert!(
            !adapter_fill_return(
                Some(&mut side),
                23,
                None,
                adapter::rv_ok(),
                layout,
                capture::MECHANISM_VALUE,
                0,
                true,
                reader,
            ),
            "{layout:?} missing row refuses the fill"
        );
        let bad_row = harness_row(24, OBJECT_ACTION_CREATE, [5, ARG_NONE]);
        let (reader, _) = adapter::readers(&target);
        assert!(
            !adapter_fill_return(
                Some(&mut side),
                23,
                Some(&bad_row),
                adapter::rv_ok(),
                layout,
                capture::MECHANISM_VALUE,
                0,
                true,
                reader,
            ),
            "{layout:?} mismatched row refuses the fill"
        );
        let mut tail = ObjectCallWire::default();
        assert!(
            !unsafe { adapter_tail_fill(core::ptr::null_mut(), Some(&side), 23, Some(&row),) },
            "{layout:?} null tail refuses"
        );
        let (reader, _) = adapter::readers(&target);
        assert!(
            !unsafe {
                adapter_emit_find(
                    &mut tail as *mut _,
                    None,
                    23,
                    Some(&row),
                    layout,
                    adapter::rv_ok(),
                    true,
                    reader,
                )
            },
            "{layout:?} missing side refuses Find emission"
        );
        adapter::assert_no_target_reads(&target, &format!("{layout:?} custody refusals"));
        // The Derive adapter needs no continuity gate (entry runs before
        // any return stamp exists) but keeps its custody checks.
        let derive_row = harness_row(23, OBJECT_ACTION_DERIVE, [5, ARG_NONE]);
        let (reader, _) = adapter::readers(&target);
        let mut fetch = |_: u8| None;
        assert!(
            !adapter_derive_entry(None, 23, Some(&derive_row), layout, &mut fetch, reader),
            "{layout:?} missing side refuses Derive entry"
        );
        adapter::assert_no_target_reads(&target, &format!("{layout:?} Derive custody"));
    }
}

// H7-E4 production attribute paths (see `object_flow` seams). The tests
// below run the REAL shared protocol on each vector as the oracle (with
// independent literal expectations) and require the PRODUCTION path —
// same vectors, same readers — to match it cell for cell. RED while the
// production path is unwired (zero reads, zero cells); a budgeted E4
// implements the seams and flips these tests with no fixture change.

fn program_attr_slot(
    target: &std::cell::RefCell<adapter::FakeTarget>,
    base: u64,
    index: u64,
    w: u64,
    selector: u64,
    ptr: u64,
    len: u64,
) {
    let slot = base + index * 3 * w;
    let mut mem = target.borrow_mut();
    mem.set_word(slot, selector);
    mem.set_word(slot + w, ptr);
    mem.set_word(slot + 2 * w, len);
}

/// Program one eight-slot six-field template: class, key type, token,
/// value length, modulus bits and all three curves. Values live away
/// from the headers so no selected span aliases inspected headers.
fn program_six_field_template(
    target: &std::cell::RefCell<adapter::FakeTarget>,
    base: u64,
    values: u64,
    w: u64,
) {
    program_attr_slot(target, base, 0, w, 0x0000, values, w);
    target.borrow_mut().set_word(values, 3);
    program_attr_slot(target, base, 1, w, 0x0100, values + 0x10, w);
    target.borrow_mut().set_word(values + 0x10, 0x1f);
    program_attr_slot(target, base, 2, w, 0x0001, values + 0x20, 1);
    target.borrow_mut().set_bytes(values + 0x20, &[1]);
    program_attr_slot(target, base, 3, w, 0x0161, values + 0x30, w);
    target.borrow_mut().set_word(values + 0x30, 32);
    program_attr_slot(target, base, 4, w, 0x0121, values + 0x40, w);
    target.borrow_mut().set_word(values + 0x40, 2048);
    program_attr_slot(target, base, 5, w, 0x0180, values + 0x50, 10);
    target.borrow_mut().set_bytes(
        values + 0x50,
        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
    );
    program_attr_slot(target, base, 6, w, 0x0180, values + 0x60, 7);
    target
        .borrow_mut()
        .set_bytes(values + 0x60, &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]);
    program_attr_slot(target, base, 7, w, 0x0180, values + 0x70, 7);
    target
        .borrow_mut()
        .set_bytes(values + 0x70, &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]);
}

/// Length of the raw string literal opening at `i` (`r`, `br` or `cr`
/// prefix, any hash count), or `None` when position `i` does not open
/// one. The prefix counts only outside identifiers, and a raw
/// identifier (`r#foo`) is not a string start. The literal closes at
/// the first quote followed by at least the opening hash count and
/// consumes exactly that many hashes — a further `#` is a new token,
/// never part of the string (backslashes are literal inside); an
/// unterminated literal runs to end of input, so the pin fails closed.
fn raw_string_len(bytes: &[u8], i: usize) -> Option<usize> {
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut j = i;
    if (bytes.get(j) == Some(&b'b') || bytes.get(j) == Some(&b'c'))
        && bytes.get(j + 1) == Some(&b'r')
    {
        if i > 0 && ident(bytes[i - 1]) {
            return None;
        }
        j += 1;
    }
    if bytes.get(j) != Some(&b'r') {
        return None;
    }
    if j == i && i > 0 && ident(bytes[i - 1]) {
        return None;
    }
    j += 1;
    let mut hashes = 0;
    while bytes.get(j) == Some(&b'#') {
        hashes += 1;
        j += 1;
    }
    if bytes.get(j) != Some(&b'"') {
        return None;
    }
    j += 1;
    while j < bytes.len() {
        if bytes[j] == b'"' {
            let mut k = j + 1;
            let mut seen = 0;
            while bytes.get(k) == Some(&b'#') {
                seen += 1;
                k += 1;
            }
            if seen >= hashes {
                return Some(j + 1 + hashes - i);
            }
        }
        j += 1;
    }
    Some(bytes.len() - i)
}

/// Strip Rust line comments, (nested) block comments, string literals
/// (plain, byte, C, raw, raw byte and raw C forms) and character
/// literals, so static pins count code tokens — never prose. A `'`
/// only opens a character literal when exactly one plain character or
/// escape plus the closing quote follows, so lifetimes survive; raw
/// strings lex by delimiter count, so their content (quotes, comment
/// markers, prose naming an adapter) never counts as code.
fn strip_rust_prose(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < bytes.len() {
        let rest = &bytes[i..];
        if rest.starts_with(b"//") {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if rest.starts_with(b"/*") {
            let mut depth = 0;
            while i < bytes.len() {
                if bytes[i..].starts_with(b"/*") {
                    depth += 1;
                    i += 2;
                } else if bytes[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if let Some(len) = raw_string_len(bytes, i) {
            i += len;
            out.push(' ');
        } else if bytes[i] == b'"' {
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 2;
                } else {
                    i += 1;
                    if bytes[i - 1] == b'"' {
                        break;
                    }
                }
            }
            out.push(' ');
        } else if bytes[i] == b'\'' {
            let mut j = i + 1;
            if bytes.get(j) == Some(&b'\\') {
                j += 1;
                if bytes.get(j) == Some(&b'u') {
                    j += 1;
                    if bytes.get(j) == Some(&b'{') {
                        j += 1;
                        while j < bytes.len() && bytes[j] != b'}' && bytes[j] != b'\n' {
                            j += 1;
                        }
                        if bytes.get(j) == Some(&b'}') {
                            j += 1;
                        }
                    }
                } else if j < bytes.len() && bytes[j] != b'\n' {
                    j += 1;
                }
            } else if j < bytes.len() && bytes[j] != b'\'' && bytes[j] != b'\n' {
                j += 1;
            }
            if j > i + 1 && bytes.get(j) == Some(&b'\'') {
                i = j + 1;
                out.push(' ');
            } else {
                out.push('\'');
                i += 1;
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// G05/E4 production-wiring pin: the BPF attribute wrappers must delegate
/// to the shared adapters the suite executes — no second inline copy.
/// Comment-proof: prose is stripped before counting, so comments (or
/// strings) naming the adapters cannot satisfy it. The adapter-to-seam edge
/// needs no pin: the G05 tests drive the adapters, so a missing seam
/// call observes zero cells (the disconnect mutant keeps wired seams
/// RED). The BPF wrapper-to-adapter edge itself is host-inexecutable, like
/// every other BPF call edge — this pin requires it textually, and live
/// populated transport (U10) qualifies it end to end.
fn pin_attribute_wrappers_delegate_to_shared_adapters() {
    let stripped = strip_rust_prose(&bpf_source());
    for (wrapper, shared, end) in [
        (
            "fn object_entry_attributes(",
            "adapter_attributes_entry(",
            "fn object_fill_return(",
        ),
        (
            "fn object_emit_get_attributes(",
            "adapter_emit_get_control(",
            "fn owned_start_discard(",
        ),
    ] {
        let body = source_between(&stripped, wrapper, end);
        assert_eq!(
            body.matches(shared).count(),
            1,
            "{wrapper} must delegate to exactly one shared {shared}"
        );
        assert!(
            !body.contains("production_"),
            "{wrapper} must not bypass its adapter with a direct seam call"
        );
    }
    // Exactly one production caller per wrapper: the definition plus the
    // single root call site, counted over stripped code. The attribute
    // emission wrapper keeps one call site in each object copy.
    assert_eq!(
        stripped.matches("object_entry_attributes(").count(),
        2,
        "object_entry_attributes( keeps its single definition plus one root call site"
    );
    for (name, start, end) in [
        (
            "ordinary copy",
            "fn object_return_ordinary(",
            "fn object_return<const JOURNAL: bool, Record: ReturnPayload>(",
        ),
        (
            "generic copy",
            "fn object_return<const JOURNAL: bool, Record: ReturnPayload>(",
            // String-free: the prose stripper removes the `"C"` ABI
            // string, so the full `pub extern` anchor cannot match.
            "fn p11_link_fork_allowed",
        ),
    ] {
        let body = source_between(&stripped, start, end);
        assert_eq!(
            body.matches("object_emit_get_attributes(").count(),
            1,
            "{name} keeps its single attribute-emission call site"
        );
    }
    assert_eq!(
        stripped.matches("object_emit_get_attributes(").count(),
        3,
        "object_emit_get_attributes( keeps its single definition plus one root call site per object copy"
    );
}

/// G05(b) regression: the prose stripper behind the delegation pin must
/// lex every Rust prose form — line/block comments, plain/byte strings,
/// raw strings (`r`, `r#`, `r##`, byte forms) and character literals —
/// so prose naming an adapter never counts as a delegation call. Both
/// directions, reviewer-style: the doctored body below (real delegation
/// removed, the name only in line comments, a valid raw-string literal
/// confusing naive stripping) must count ZERO code occurrences — the
/// naive stripper falsely counted one — while the same prose next to a
/// real delegation call must count exactly one.
#[test]
fn strip_rust_prose_handles_raw_string_prose() {
    // Every prose form naming the adapter strips to zero on its own.
    // (Outer literals use extra hashes so fixture delimiters survive.)
    for (name, prose) in [
        ("line comment", "// adapter_attributes_entry(\n"),
        (
            "line comment with quote",
            "// \" adapter_attributes_entry(\n",
        ),
        ("block comment", "/* adapter_attributes_entry( */"),
        (
            "nested block comment",
            "/* outer /* adapter_attributes_entry( */ still comment */",
        ),
        ("string", "\"adapter_attributes_entry(\""),
        (
            "string with escapes",
            "\"quote \\\" adapter_attributes_entry(\"",
        ),
        ("raw string", "r\"adapter_attributes_entry(\""),
        (
            "raw string with quotes",
            r##"r#"say "hi" adapter_attributes_entry(" y"#"##,
        ),
        (
            "r-hash string with stray quote",
            r##"r#"prefix " suffix"#"##,
        ),
        (
            "r-double-hash string",
            r###"r##"contains "# but adapter_attributes_entry(" inside"##"###,
        ),
        ("byte string", "b\"adapter_attributes_entry(\""),
        (
            "raw byte string",
            r##"br#"adapter_attributes_entry(" with " quote"#"##,
        ),
        (
            "block opener inside raw string",
            r##"r#"/* adapter_attributes_entry(" */"#"##,
        ),
    ] {
        let stripped = strip_rust_prose(prose);
        assert!(
            !stripped.contains("adapter_attributes_entry("),
            "{name} must strip, got {stripped:?}"
        );
    }
    // Characters strip; lifetimes and code survive.
    assert_eq!(strip_rust_prose("'a'"), " ");
    assert_eq!(strip_rust_prose("b'\\n'"), "b ");
    assert_eq!(strip_rust_prose("'\\u{7}'"), " ");
    assert_eq!(strip_rust_prose("x: &'a u8"), "x: &'a u8");
    assert_eq!(
        strip_rust_prose("fn g<'long>(x: &'long u8) -> bool { 'a' == 97 }"),
        "fn g<'long>(x: &'long u8) -> bool {   == 97 }"
    );
    // RED direction: the reviewer-style doctored body — no delegation
    // call, the name only in line comments, a valid raw string whose
    // interior quote misaligns naive stripping — counts zero.
    let doctored = concat!(
        "fn object_entry_attributes(\n",
        "    ctx: &ProbeContext,\n",
        ") -> bool {\n",
        "    // adapter_attributes_entry(\n",
        "    let _cover = r#\"prefix \" suffix\"#;\n",
        "    // \" adapter_attributes_entry(\n",
        "    true\n",
        "}\n",
    );
    assert_eq!(
        strip_rust_prose(doctored)
            .matches("adapter_attributes_entry(")
            .count(),
        0,
        "the doctored body must count zero delegation calls"
    );
    // GREEN direction: the same prose next to a real delegation call
    // counts exactly one.
    let wired = doctored.replace(
        "    true\n",
        "    adapter_attributes_entry(side, descriptor);\n",
    );
    assert_eq!(
        strip_rust_prose(&wired)
            .matches("adapter_attributes_entry(")
            .count(),
        1,
        "prose plus one real call must count exactly one delegation call"
    );
}

/// G05(b) round-5 regression: both reviewer-reproduced stripper
/// bypasses. (1) The trailing-`#` macro case: `sink!(r""#)` is a
/// COMPLETE raw string followed by a SEPARATE `#` token, at 0/1/2
/// opening hashes; the lexer must match exactly N closing hashes and
/// stop, so the quoted line comment after it still strips as a
/// comment. (2) Raw C strings (`cr#"..."#`) lex as strings, not as
/// prose misaligned by a missed prefix. Both directions: each
/// doctored body (real delegation removed, the name only in prose)
/// counts ZERO, while the same body next to a real delegation call
/// counts exactly one.
#[test]
fn strip_rust_prose_rejects_trailing_hash_and_c_string_bypasses() {
    // Bypass 1, the reviewer's own probe at 0/1/2 opening hashes.
    // Each quoted comment carries exactly the opening hash count, so
    // the N-hash closing delimiter a confused lexer hunts for lands
    // inside the comment and the prose name leaks out as code.
    for (name, literal, comment) in [
        (
            "trailing hash, 0 opening hashes",
            "r\"\"#",
            "// \" adapter_attributes_entry(",
        ),
        (
            "trailing hash, 1 opening hash",
            "r#\"\"##",
            "// \"# adapter_attributes_entry(",
        ),
        (
            "trailing hash, 2 opening hashes",
            "r##\"\"###",
            "// \"## adapter_attributes_entry(",
        ),
    ] {
        let doctored = format!(
            "fn object_entry_attributes(\n    let _ = (ctx, side, layout);\n    macro_rules! sink {{ ($($t:tt)*) => {{}}; }}\n    sink!({literal});\n    {comment}\n    true\n}}\n"
        );
        assert_eq!(
            strip_rust_prose(&doctored)
                .matches("adapter_attributes_entry(")
                .count(),
            0,
            "{name}: doctored body must count zero delegation calls"
        );
        let wired = doctored.replace(
            "    true\n",
            "    adapter_attributes_entry(side, descriptor);\n",
        );
        assert_eq!(
            strip_rust_prose(&wired)
                .matches("adapter_attributes_entry(")
                .count(),
            1,
            "{name}: prose plus one real call must count exactly one"
        );
    }
    // Bypass 2: the name hidden in a raw C string whose interior
    // quote misaligns prefix-blind stripping, plus a quoted comment.
    let doctored = concat!(
        "fn object_entry_attributes(\n",
        "    let _cover = cr#\"prefix \" suffix\"#;\n",
        "    // \" adapter_attributes_entry(\n",
        "    true\n",
        "}\n",
    );
    assert_eq!(
        strip_rust_prose(doctored)
            .matches("adapter_attributes_entry(")
            .count(),
        0,
        "raw C string bypass must count zero delegation calls"
    );
    let wired = doctored.replace(
        "    true\n",
        "    adapter_attributes_entry(side, descriptor);\n",
    );
    assert_eq!(
        strip_rust_prose(&wired)
            .matches("adapter_attributes_entry(")
            .count(),
        1,
        "raw C string prose plus one real call must count exactly one"
    );
    // The name directly inside a raw C string strips on its own.
    assert!(
        !strip_rust_prose(r##"cr#"adapter_attributes_entry("#"##)
            .contains("adapter_attributes_entry("),
        "raw C string content must strip"
    );
}

/// G05(b) round-5 vectors: every string prefix (`"`, `b"`, `c"`,
/// `r"`, `br"`, `cr"`, each raw form at 0/1/2 hashes), raw
/// identifiers, char-vs-lifetime, nested block comments, escapes and
/// unterminated literals (which run to end, failing closed).
#[test]
fn strip_rust_prose_lexes_every_prefix_and_edge() {
    // Every prefix hides the adapter name behind an interior quote
    // (where the form allows one) to catch naive lexing.
    for (name, prose) in [
        ("plain string", "\"adapter_attributes_entry(\""),
        (
            "plain string with escaped quotes",
            "\"say \\\"hi\\\" adapter_attributes_entry(\"",
        ),
        ("byte string", "b\"adapter_attributes_entry(\""),
        (
            "byte string with escapes",
            "b\"a\\\"b\\\\ adapter_attributes_entry(\"",
        ),
        ("c string", "c\"adapter_attributes_entry(\""),
        (
            "c string with escape",
            "c\"a\\0b adapter_attributes_entry(\"",
        ),
        ("raw string", "r\"adapter_attributes_entry(\""),
        (
            "raw 1-hash string with quotes",
            r##"r#"say "hi" adapter_attributes_entry(" y"#"##,
        ),
        (
            "raw 2-hash string with quotes and hashes",
            r###"r##"say "hi" adapter_attributes_entry("# still prose"##"###,
        ),
        ("raw byte string", "br\"adapter_attributes_entry(\""),
        (
            "raw byte 1-hash string with quote",
            r##"br#"say "hi" adapter_attributes_entry("#"##,
        ),
        (
            "raw byte 2-hash string with quote",
            r###"br##"say "hi" adapter_attributes_entry("##"###,
        ),
        ("raw c string", "cr\"adapter_attributes_entry(\""),
        (
            "raw c 1-hash string with quote",
            r##"cr#"say "hi" adapter_attributes_entry("#"##,
        ),
        (
            "raw c 2-hash string with quote",
            r###"cr##"say "hi" adapter_attributes_entry("##"###,
        ),
        (
            "deeply nested block comment",
            "/* a /* b /* adapter_attributes_entry( */ c */ d */",
        ),
        (
            "block comment with strings inside",
            "/* \"adapter_attributes_entry(\" r#\"x\"# */",
        ),
        (
            "line comment after char slash",
            "let c = '/'; // adapter_attributes_entry(\n",
        ),
    ] {
        let stripped = strip_rust_prose(prose);
        assert!(
            !stripped.contains("adapter_attributes_entry("),
            "{name} must strip, got {stripped:?}"
        );
    }
    // Trailing-`#` macro cases: the literal strips to one space and
    // the extra `#` survives as its own token.
    assert_eq!(strip_rust_prose("sink!(r\"\"#);"), "sink!( #);");
    assert_eq!(strip_rust_prose("sink!(r#\"\"##);"), "sink!( #);");
    assert_eq!(strip_rust_prose("sink!(r##\"\"###);"), "sink!( #);");
    // Adjacent literals each strip.
    assert_eq!(strip_rust_prose("r#\"a\"#\"b\""), "  ");
    assert_eq!(strip_rust_prose("br\"a\"cr\"b\""), "  ");
    // Prefix-looking code that is NOT a string survives verbatim.
    assert_eq!(strip_rust_prose("let r#type = 1;"), "let r#type = 1;");
    assert_eq!(strip_rust_prose("let br = 1;"), "let br = 1;");
    assert_eq!(strip_rust_prose("let cry = 1;"), "let cry = 1;");
    assert_eq!(
        strip_rust_prose("let r#match = adapter_attributes_entry(x);"),
        "let r#match = adapter_attributes_entry(x);"
    );
    // Characters strip; lifetimes and `'static` survive.
    assert_eq!(strip_rust_prose("'a'"), " ");
    assert_eq!(strip_rust_prose("b'a'"), "b ");
    assert_eq!(strip_rust_prose("'\\n'"), " ");
    assert_eq!(strip_rust_prose("let q = '\"';"), "let q =  ;");
    assert_eq!(strip_rust_prose("x: &'a u8"), "x: &'a u8");
    assert_eq!(
        strip_rust_prose("fn f<'a>(x: &'a u8) -> &'a u8"),
        "fn f<'a>(x: &'a u8) -> &'a u8"
    );
    assert_eq!(strip_rust_prose("x: &'static str"), "x: &'static str");
    // Escapes close cooked strings exactly: an escaped quote does not
    // end the literal, an escaped backslash does not escape the quote.
    assert_eq!(
        strip_rust_prose("\"a\\\"b\" + adapter_attributes_entry(")
            .matches("adapter_attributes_entry(")
            .count(),
        1
    );
    assert_eq!(
        strip_rust_prose("\"a\\\\\" + adapter_attributes_entry(")
            .matches("adapter_attributes_entry(")
            .count(),
        1
    );
    // Unterminated prose runs to end, failing closed: the name never
    // counts as code.
    assert_eq!(strip_rust_prose("\"adapter_attributes_entry("), " ");
    assert_eq!(strip_rust_prose("r#\"adapter_attributes_entry("), " ");
    assert_eq!(strip_rust_prose("/* adapter_attributes_entry("), "");
}

/// A pure policy test cannot detect a producer that still narrows the
/// captured target word instead of using the full-width finite policy.
#[test]
fn login_user_type_capture_uses_full_width_finite_policy() {
    let stripped = strip_rust_prose(&bpf_source());
    let capture = source_between(
        &stripped,
        "if let Some(value) = capture_scalar(&ctx, semantics.user_type_arg, layout, start) {",
        "if semantics.mechanism_arg != ARG_NONE {",
    );
    assert_eq!(
        capture.split_whitespace().collect::<String>(),
        "start.user_type=finite_login_user_type(value);}",
        "the producer must classify the full captured user type before narrowing"
    );
}

/// G05(b) round-5 stability: the stripped dump of the real BPF source
/// is byte-identical before and after the lexer correction (baseline
/// captured pre-fix: 114413 B, sha256 below). Re-baseline deliberately
/// if `crates/ebpf/src/main.rs` legitimately changes.
/// Re-baselined after the E4 outlined return branches, scalar scope flags,
/// alias-header acquisition and Some-only flags load (safe eight-commit
/// integration through 242ba841): 113589 B, measured with this actual lexer.
/// Re-baselined again for full-width login user-type capture and scalar
/// object-capture globals with constant-layout alias readers; measured with
/// this actual lexer. Request-cell extraction adds one scalar-only global;
/// its source pin is measured with that same executable lexer.
/// The private counter artifact branches are measured with the same lexer;
/// ordinary emitted-object noninterference remains a separate compiled check.
/// The private bank RV cfg stays on its existing line; its conditional
/// re-export is appended. The timing bank proof features share the counts
/// cfg lines. Measured with the unchanged executable lexer.
/// Re-baselined after the return lost-code removal (the halves gap the
/// leader row in place; the dispatcher is a plain tail again) and the
/// timing cfg gates together: 123365 B, sha256 below, measured with
/// this actual lexer.
/// Re-baselined for getter-ABI acquisition bounds, verifier-visible index
/// guards without panic subprograms, and ordinary-base preservation on a
/// refused object join: 123958 B, measured with the unchanged lexer.
/// Re-baselined for the shared birth-marker compile selector and forbidden
/// counter/inventory combination: 124730 B, measured with that same lexer.
/// Re-baselined for the appended private image-bank-proof module cfg;
/// the lexer and existing ordinary-source line positions are unchanged.
/// Re-baselined for the private journal roots: const-generic JOURNAL
/// threading through the entry/return roots, outlined capture with an
/// explicit completion token, and the reason-aware removal wrapper:
/// 131833 B, sha256 below, measured with the unchanged executable lexer.
/// Re-baselined for packet 6.07c on its branch: the T0 KEM entry
/// wrapper (`object_entry_kem` plus the two generic-path KEM skips,
/// the entry-root KEM call and the KEM imports): 133820 B, sha256
/// below, measured with the unchanged executable lexer. (That value
/// was branch-measured, not combined-tree measured.)
/// Re-baselined on the combined tree at pick I-13 (controller
/// ruling): the pin was already stale pre-pick (actual 137641 B vs
/// pinned 132203 B — intervening main.rs changes never re-pinned),
/// and the pick adds exactly the KEM delta above (+1617 stripped B,
/// matching the branch-measured KEM step; stripped diff shows only
/// KEM content): 139258 B, sha256 below, measured with the unchanged
/// executable lexer and reproduced byte-exact by standalone lexing.
#[test]
fn strip_rust_prose_real_bpf_source_dump_stable() {
    use sha2::{Digest as _, Sha256};
    let stripped = strip_rust_prose(&bpf_source());
    let digest = Sha256::digest(stripped.as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        (stripped.len(), hex.as_str()),
        (
            139258,
            "d75401418981ac221b9585c3980d2384785613c50c4f319f9dbd89ab94ceccbc"
        ),
        "stripped BPF dump must stay byte-identical"
    );
}

/// Drive one creation-template vector through the PRODUCTION entry path:
/// the shared `adapter_attributes_entry` the BPF entry adapter calls,
/// programmed with the pair scalars at the row's template args — then the
/// COMPLETE production emission sequence the return root executes, in
/// root order (tail fill, Find emission, Get emission). Returns the side
/// row AFTER the production entry store plus the emitted tail. The
/// harness never writes `side.requested` itself: a missing production
/// entry-store operation observes zero cells here. G05(e): stopping
/// after the tail fill would blind the harness to any construction
/// finalizing request state in a later stage, so the driver runs every
/// stage (Find and Get emissions are trivially true on request vectors,
/// which are neither Find nor Get calls).
#[allow(clippy::type_complexity)]
fn run_production_request_path(
    target: &std::cell::RefCell<adapter::FakeTarget>,
    layout: p11scope_ebpf_common::LinuxLayout,
    action: u8,
    pairs: [(u64, u64); 2],
    template_args: [u8; 4],
) -> (
    p11scope_ebpf_common::object_wire::ObjectStart,
    p11scope_ebpf_common::object_wire::ObjectCallWire,
) {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::object_flow::{
        adapter_attributes_entry, adapter_emit_find, adapter_emit_get_attributes, adapter_tail_fill,
    };
    use p11scope_ebpf_common::object_wire::{
        OBJECT_LAYOUT_ILP32, OBJECT_LAYOUT_LP64, ObjectCallWire,
    };
    let mut row = harness_row(23, action, [5, ARG_NONE]);
    row.template_args = template_args;
    let mut side = p11scope_ebpf_common::object_wire::ObjectStart {
        descriptor_index: 23,
        layout: if layout == p11scope_ebpf_common::LinuxLayout::Lp64 {
            OBJECT_LAYOUT_LP64
        } else {
            OBJECT_LAYOUT_ILP32
        },
        ..Default::default()
    };
    // Argument acquisition is counted at the seam: every call below is
    // a probe register/stack read on BPF.
    let mut fetches = 0u32;
    let mut fetch_arg = |arg: u8| {
        fetches += 1;
        if arg == template_args[0] {
            Some(pairs[0].0)
        } else if arg == template_args[1] {
            Some(pairs[0].1)
        } else if arg == template_args[2] {
            Some(pairs[1].0)
        } else if arg == template_args[3] {
            Some(pairs[1].1)
        } else {
            None
        }
    };
    let (reader, bytes) = adapter::readers(target);
    assert!(
        adapter_attributes_entry(
            Some(&mut side),
            23,
            Some(&row),
            layout,
            &mut fetch_arg,
            reader,
            bytes,
        ),
        "{layout:?} production entry adapter accepts the vector"
    );
    // Wired, the production path acquires exactly the present template
    // arguments: every call here is a probe register/stack read on BPF,
    // so reintroduced, dropped or duplicated fetches fail here on every
    // vector, before any store assert. Full pairs only: a half-present
    // pair acquires nothing (the adapter refuses it before any target
    // read).
    let present_pairs = u32::from(template_args[0] != ARG_NONE && template_args[1] != ARG_NONE)
        + u32::from(template_args[2] != ARG_NONE && template_args[3] != ARG_NONE);
    assert_eq!(
        fetches,
        2 * present_pairs,
        "{layout:?} wired entry acquires exactly its present template arguments"
    );
    // RETURNING arrival state (harness sequencing, as the fill adapter
    // would leave it); the inspected pair lists arrive only via the
    // production entry store above.
    side.phase = 3;
    let mut tail = ObjectCallWire::default();
    let tailed = unsafe { adapter_tail_fill(&mut tail as *mut _, Some(&side), 23, Some(&row)) };
    assert!(tailed, "{layout:?} production tail fills");
    // Root order continues: Find emission, then Get establishment — the
    // same stage chain `run_production_return_arm` executes. Both succeed
    // trivially on request vectors (non-Find, non-Get) with zero reads;
    // they execute so any E4 construction finalizing request state in a
    // later stage is observed, exactly as the root would emit it.
    let (reader, _) = adapter::readers(target);
    let find_emitted = tailed
        && unsafe {
            adapter_emit_find(
                &mut tail as *mut _,
                Some(&side),
                23,
                Some(&row),
                layout,
                adapter::rv_ok(),
                true,
                reader,
            )
        };
    assert!(
        find_emitted,
        "{layout:?} production Find emission accepts the vector"
    );
    let (reader, bytes) = adapter::readers(target);
    let emitted = find_emitted
        && unsafe {
            adapter_emit_get_attributes(
                &mut tail as *mut _,
                Some(&side),
                23,
                Some(&row),
                layout,
                adapter::rv_ok(),
                true,
                reader,
                bytes,
            )
        };
    assert!(
        emitted,
        "{layout:?} production Get emission accepts the vector"
    );
    (side, tail)
}

/// Drive one Get vector through the PRODUCTION Get path: entry retention
/// via the shared `adapter_attributes_entry` the BPF entry adapter
/// calls, then the COMPLETE production emission sequence the return
/// root executes, in root order (tail fill, Find emission, Get
/// establishment). Returns the side row after retention plus the emitted
/// tail. The harness never writes the Get fields or the emitted list
/// itself.
#[allow(clippy::type_complexity)]
fn run_production_get_path(
    target: &std::cell::RefCell<adapter::FakeTarget>,
    layout: p11scope_ebpf_common::LinuxLayout,
    template_base: u64,
    count: u64,
) -> (
    p11scope_ebpf_common::object_wire::ObjectStart,
    p11scope_ebpf_common::object_wire::ObjectCallWire,
) {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::object_flow::{
        adapter_attributes_entry, adapter_emit_find, adapter_emit_get_attributes, adapter_tail_fill,
    };
    use p11scope_ebpf_common::object_wire::{
        OBJECT_ACTION_GET, OBJECT_LAYOUT_ILP32, OBJECT_LAYOUT_LP64, ObjectCallWire,
    };
    let mut row = harness_row(23, OBJECT_ACTION_GET, [ARG_NONE, ARG_NONE]);
    row.template_args = [2, 3, ARG_NONE, ARG_NONE];
    let mut side = p11scope_ebpf_common::object_wire::ObjectStart {
        descriptor_index: 23,
        layout: if layout == p11scope_ebpf_common::LinuxLayout::Lp64 {
            OBJECT_LAYOUT_LP64
        } else {
            OBJECT_LAYOUT_ILP32
        },
        ..Default::default()
    };
    // Argument acquisition is counted at the seam (see the request
    // driver): every call below is a probe register/stack read on BPF.
    let mut fetches = 0u32;
    let mut fetch_arg = |arg: u8| {
        fetches += 1;
        match arg {
            2 => Some(template_base),
            3 => Some(count),
            _ => None,
        }
    };
    let (reader, bytes) = adapter::readers(target);
    assert!(
        adapter_attributes_entry(
            Some(&mut side),
            23,
            Some(&row),
            layout,
            &mut fetch_arg,
            reader,
            bytes,
        ),
        "{layout:?} production Get entry accepts the vector"
    );
    // Wired, the production Get entry acquires exactly its template
    // pointer and count: every call here is a probe register/stack read
    // on BPF, so reintroduced, dropped or duplicated fetches fail here.
    assert_eq!(
        fetches, 2,
        "{layout:?} wired Get entry acquires exactly its template arguments"
    );
    // RETURNING arrival state (harness sequencing); retention arrives
    // only via the production entry store above.
    side.phase = 3;
    let mut tail = ObjectCallWire::default();
    let tailed = unsafe { adapter_tail_fill(&mut tail as *mut _, Some(&side), 23, Some(&row)) };
    assert!(tailed, "{layout:?} production Get tail fills");
    // Root order: Find emission precedes Get establishment (trivially
    // true on Get vectors with zero reads; executes for root fidelity,
    // like the request driver's chain above).
    let (reader, _) = adapter::readers(target);
    let find_emitted = tailed
        && unsafe {
            adapter_emit_find(
                &mut tail as *mut _,
                Some(&side),
                23,
                Some(&row),
                layout,
                adapter::rv_ok(),
                true,
                reader,
            )
        };
    assert!(
        find_emitted,
        "{layout:?} production Find emission accepts the vector"
    );
    let (reader, bytes) = adapter::readers(target);
    assert!(
        unsafe {
            adapter_emit_get_attributes(
                &mut tail as *mut _,
                Some(&side),
                23,
                Some(&row),
                layout,
                adapter::rv_ok(),
                true,
                reader,
                bytes,
            )
        },
        "{layout:?} production Get emission accepts the vector"
    );
    (side, tail)
}

/// Retained Get slots pack densely (the shared protocol only appends),
/// so the retained count is the leading selected-slot prefix.
fn retained_get_prefix_count(side: &p11scope_ebpf_common::object_wire::ObjectStart) -> u8 {
    let mut count = 0;
    while count < 8 && side.slots[count as usize].kind != 0 {
        count += 1;
    }
    count
}

/// Wired production attribute transport (H7-E4): entry-inspected
/// request pairs emit as inspected lists, while authorized-but-refused
/// pairs (failed argument acquisition, refused Derive) keep the honest
/// UNINSPECTED marking with zero cells, zero inspected count and zero
/// target reads. Absent pairs stay all-zero. The G05 six-field test
/// owns cell-level oracle equality; this test owns the marking level
/// plus the failure twins that keep the transport honest.
#[test]
fn object_attributes_wired_marking_is_production() {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::object_capture::{attr_list_flag, object_flag};
    use p11scope_ebpf_common::object_flow::{
        adapter_attributes_entry, adapter_emit_get_attributes, adapter_tail_fill,
    };
    use p11scope_ebpf_common::object_wire::{
        GET_ENTRY_UNINSPECTED, OBJECT_ACTION_CREATE, OBJECT_ACTION_DERIVE, OBJECT_ACTION_GET,
        OBJECT_DERIVE_SHA256, OBJECT_DERIVE_UNAVAILABLE, OBJECT_GUARD_SCALAR_DERIVE,
        OBJECT_LAYOUT_ILP32, OBJECT_LAYOUT_LP64, ObjectAttributeListWire, ObjectCallWire,
    };
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        let side_layout = if layout == LinuxLayout::Lp64 {
            OBJECT_LAYOUT_LP64
        } else {
            OBJECT_LAYOUT_ILP32
        };
        // Healthy creation: the full production path emits pair zero
        // as an inspected eight-slot list (present, no uninspected
        // marking) while the absent pair stays all-zero.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&target, 0x40000, 0x50000, w);
        let (_, tail) = run_production_request_path(
            &target,
            layout,
            OBJECT_ACTION_CREATE,
            [(0x40000, 8), (0, 0)],
            [2, 3, ARG_NONE, ARG_NONE],
        );
        assert_eq!(tail.requested[0].inspected, 8);
        assert_eq!(
            tail.requested[0].flags & attr_list_flag::UNINSPECTED,
            0,
            "{layout:?} inspected pair carries no uninspected marking"
        );
        assert_eq!(
            tail.requested[0].flags & attr_list_flag::PRESENT,
            attr_list_flag::PRESENT,
            "{layout:?} inspected pair carries the present bit"
        );
        assert!(
            tail.requested[1] == ObjectAttributeListWire::default(),
            "{layout:?} absent pair stays all-zero"
        );
        // Failed argument acquisition: the adapter marks the present
        // pair honestly, books the read failure, reads nothing and
        // emits the marked-only list through the production tail.
        let fail_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&fail_target, 0x40000, 0x50000, w);
        let mut row = harness_row(23, OBJECT_ACTION_CREATE, [5, ARG_NONE]);
        row.template_args = [2, 3, ARG_NONE, ARG_NONE];
        let mut side = p11scope_ebpf_common::object_wire::ObjectStart {
            descriptor_index: 23,
            layout: side_layout,
            ..Default::default()
        };
        let mut fetches = 0u32;
        let mut fetch_arg = |_: u8| {
            fetches += 1;
            None
        };
        let (reader, bytes) = adapter::readers(&fail_target);
        assert!(
            adapter_attributes_entry(
                Some(&mut side),
                23,
                Some(&row),
                layout,
                &mut fetch_arg,
                reader,
                bytes,
            ),
            "{layout:?} acquisition failure is not custody failure"
        );
        assert_eq!(
            fetches, 2,
            "{layout:?} both present arguments are attempted before refusal"
        );
        adapter::assert_no_target_reads(&fail_target, &format!("{layout:?} acquisition refusal"));
        assert_eq!(
            side.requested[0].flags,
            attr_list_flag::UNINSPECTED,
            "{layout:?} failed acquisition marks the present pair"
        );
        assert_eq!(side.requested[0].inspected, 0);
        assert!(
            side.requested[0].cells == [ObjectAttributeListWire::default().cells[0]; 8],
            "{layout:?} failed acquisition keeps zero cells"
        );
        assert_eq!(
            side.flags & object_flag::ARG_READ_FAILURE as u16,
            object_flag::ARG_READ_FAILURE as u16,
            "{layout:?} failed acquisition books the read failure"
        );
        side.phase = 3;
        let mut tail = ObjectCallWire::default();
        assert!(
            unsafe { adapter_tail_fill(&mut tail as *mut _, Some(&side), 23, Some(&row)) },
            "{layout:?} production tail fills"
        );
        assert!(
            tail.requested[0]
                == ObjectAttributeListWire {
                    flags: attr_list_flag::UNINSPECTED,
                    ..ObjectAttributeListWire::default()
                },
            "{layout:?} failed acquisition emits the marked-only list"
        );
        // Refused Derive authorizes no template access: no fetch, no
        // read, no flag — the present pair keeps the honest marking
        // (the unavailable derive code tells the refusal story).
        let derive_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&derive_target, 0x40000, 0x50000, w);
        let mut derive_row = harness_row(23, OBJECT_ACTION_DERIVE, [5, ARG_NONE]);
        derive_row.template_args = [3, 4, ARG_NONE, ARG_NONE];
        derive_row.guard = OBJECT_GUARD_SCALAR_DERIVE;
        let mut derive_side = p11scope_ebpf_common::object_wire::ObjectStart {
            descriptor_index: 23,
            layout: side_layout,
            derive: OBJECT_DERIVE_UNAVAILABLE,
            ..Default::default()
        };
        let mut derive_fetches = 0u32;
        let mut derive_fetch = |_: u8| {
            derive_fetches += 1;
            None
        };
        let (reader, bytes) = adapter::readers(&derive_target);
        assert!(
            adapter_attributes_entry(
                Some(&mut derive_side),
                23,
                Some(&derive_row),
                layout,
                &mut derive_fetch,
                reader,
                bytes,
            ),
            "{layout:?} refused Derive is not custody failure"
        );
        assert_eq!(
            derive_fetches, 0,
            "{layout:?} refused Derive acquires zero arguments"
        );
        adapter::assert_no_target_reads(&derive_target, &format!("{layout:?} refused Derive"));
        assert_eq!(
            derive_side.flags, 0,
            "{layout:?} refused Derive sets no flag"
        );
        assert_eq!(
            derive_side.requested[0].flags,
            attr_list_flag::UNINSPECTED,
            "{layout:?} refused Derive marks its present pair"
        );
        derive_side.phase = 3;
        let mut tail = ObjectCallWire::default();
        assert!(
            unsafe {
                adapter_tail_fill(
                    &mut tail as *mut _,
                    Some(&derive_side),
                    23,
                    Some(&derive_row),
                )
            },
            "{layout:?} production tail fills"
        );
        assert_eq!(
            tail.requested[0].flags,
            attr_list_flag::UNINSPECTED,
            "{layout:?} refused Derive emits the marked-only list"
        );
        // Accepted Derive (evidence retained by the Derive adapter
        // earlier in the entry chain) inspects through the same
        // creation protocol: the stored list equals the oracle wire.
        let accepted_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&accepted_target, 0x40000, 0x50000, w);
        let (reader, bytes) = adapter::readers(&accepted_target);
        let expected = p11scope_ebpf_common::object_capture::inspect_request_template(
            0x40000, 8, None, layout, reader, bytes,
        );
        let prod_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&prod_target, 0x40000, 0x50000, w);
        let mut accepted_side = p11scope_ebpf_common::object_wire::ObjectStart {
            descriptor_index: 23,
            layout: side_layout,
            derive: OBJECT_DERIVE_SHA256,
            ..Default::default()
        };
        let mut accepted_fetches = 0u32;
        let mut accepted_fetch = |arg: u8| {
            accepted_fetches += 1;
            match arg {
                3 => Some(0x40000),
                4 => Some(8),
                _ => None,
            }
        };
        let (reader, bytes) = adapter::readers(&prod_target);
        assert!(
            adapter_attributes_entry(
                Some(&mut accepted_side),
                23,
                Some(&derive_row),
                layout,
                &mut accepted_fetch,
                reader,
                bytes,
            ),
            "{layout:?} accepted Derive inspects"
        );
        assert_eq!(
            accepted_fetches, 2,
            "{layout:?} accepted Derive acquires its pair once"
        );
        assert_reads_subset(
            &prod_target,
            &accepted_target,
            &format!("{layout:?} accepted-Derive inspection"),
        );
        assert!(
            accepted_side.requested[0] == expected.to_wire(),
            "{layout:?} accepted Derive stores the inspected list"
        );
        // Failed Get acquisition: retention stays zero, the private
        // uninspected bit plus the read failure are booked, and the
        // production emission keeps the marked-only list with zero
        // reads.
        let get_fail_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&get_fail_target, 0x40000, 0x50000, w);
        let mut get_row = harness_row(23, OBJECT_ACTION_GET, [ARG_NONE, ARG_NONE]);
        get_row.template_args = [2, 3, ARG_NONE, ARG_NONE];
        let mut get_side = p11scope_ebpf_common::object_wire::ObjectStart {
            descriptor_index: 23,
            layout: side_layout,
            ..Default::default()
        };
        let mut get_fetches = 0u32;
        let mut get_fetch = |_: u8| {
            get_fetches += 1;
            None
        };
        let (reader, bytes) = adapter::readers(&get_fail_target);
        assert!(
            adapter_attributes_entry(
                Some(&mut get_side),
                23,
                Some(&get_row),
                layout,
                &mut get_fetch,
                reader,
                bytes,
            ),
            "{layout:?} Get acquisition failure is not custody failure"
        );
        assert_eq!(get_fetches, 2, "{layout:?} Get attempts both arguments");
        adapter::assert_no_target_reads(
            &get_fail_target,
            &format!("{layout:?} Get acquisition refusal"),
        );
        assert_eq!(get_side.get_template_base, 0);
        assert_eq!(get_side.get_inspected, 0);
        assert_eq!(
            get_side.flags & (object_flag::ARG_READ_FAILURE as u16 | GET_ENTRY_UNINSPECTED),
            object_flag::ARG_READ_FAILURE as u16 | GET_ENTRY_UNINSPECTED,
            "{layout:?} Get acquisition failure books read failure plus uninspected"
        );
        get_side.phase = 3;
        let mut tail = ObjectCallWire::default();
        assert!(
            unsafe { adapter_tail_fill(&mut tail as *mut _, Some(&get_side), 23, Some(&get_row)) },
            "{layout:?} production Get tail fills"
        );
        let (reader, bytes) = adapter::readers(&get_fail_target);
        assert!(
            unsafe {
                adapter_emit_get_attributes(
                    &mut tail as *mut _,
                    Some(&get_side),
                    23,
                    Some(&get_row),
                    layout,
                    adapter::rv_ok(),
                    true,
                    reader,
                    bytes,
                )
            },
            "{layout:?} Get emission accepts after acquisition failure"
        );
        assert!(
            tail.result_attributes
                == ObjectAttributeListWire {
                    flags: attr_list_flag::UNINSPECTED,
                    ..ObjectAttributeListWire::default()
                },
            "{layout:?} failed Get acquisition emits the marked-only list"
        );
    }
}

/// Wired production entry attribute path (H7-E4): the shared entry
/// adapter inspects creation vectors into the side request lists and
/// retains Get headers into the side Get fields (acquisition counted at
/// the seam by the drivers — dropped or duplicated fetches fail there).
/// Set still authorizes no template and touches nothing; entry-list
/// flags stay in private side bits, masked out of every public tail
/// copy. The refusal gates stay: refused continuity refuses Get
/// emission before any read, refused return values keep the UNINSPECTED
/// marking, non-Get families leave the result list zero, and custody
/// failures refuse without acquiring arguments.
#[test]
fn object_attributes_wired_entry_stores_inspected() {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::object_capture::{attr_list_flag, inspect_request_template};
    use p11scope_ebpf_common::object_flow::{
        adapter_attributes_entry, adapter_emit_get_attributes, adapter_tail_fill,
    };
    use p11scope_ebpf_common::object_wire::{
        GET_ENTRY_FLAGS_SHIFT, OBJECT_ACTION_CREATE, OBJECT_ACTION_GET, OBJECT_ACTION_SET,
        OBJECT_FLAGS_MASK, ObjectAttributeListWire, ObjectCallWire,
    };
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        // Creation vector through the production entry adapter: the
        // stored request list equals the oracle wire (the G05 six-field
        // test owns the per-cell proof; this pins the entry store).
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&target, 0x40000, 0x50000, w);
        let (side, tail) = run_production_request_path(
            &target,
            layout,
            OBJECT_ACTION_CREATE,
            [(0x40000, 8), (0, 0)],
            [2, 3, ARG_NONE, ARG_NONE],
        );
        let oracle_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&oracle_target, 0x40000, 0x50000, w);
        let (reader, bytes) = adapter::readers(&oracle_target);
        let expected = inspect_request_template(0x40000, 8, None, layout, reader, bytes);
        assert!(
            side.requested[0] == expected.to_wire(),
            "{layout:?} wired entry stores the inspected request list"
        );
        assert!(
            side.requested[1] == ObjectAttributeListWire::default(),
            "{layout:?} wired entry leaves the absent pair zero"
        );
        assert!(
            tail.requested[0] == expected.to_wire(),
            "{layout:?} wired entry emits the inspected request list"
        );
        // Set authorizes no template: the adapter accepts the row and
        // touches nothing (its pair ordinals are all absent).
        let set_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        let (set_side, _) = run_production_request_path(
            &set_target,
            layout,
            OBJECT_ACTION_SET,
            [(0x40000, 8), (0, 0)],
            [ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE],
        );
        adapter::assert_no_target_reads(&set_target, &format!("{layout:?} Set entry"));
        assert!(
            set_side.requested == [ObjectAttributeListWire::default(); 2],
            "{layout:?} Set entry stores no request state"
        );
        // Get retention through the production entry adapter: the
        // base, header end, inspected count and dense selected prefix
        // match the entry protocol, and the return path establishes
        // the retained results (the G05 six-field test owns the
        // per-slot oracle proof; this pins the retention shape).
        let get_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&get_target, 0x40000, 0x50000, w);
        let (get_side, get_tail) = run_production_get_path(&get_target, layout, 0x40000, 8);
        assert_eq!(get_side.get_template_base, 0x40000);
        assert_eq!(
            get_side.inspected_header_end,
            0x40000 + 8 * 3 * w,
            "{layout:?} wired Get entry retains the header end"
        );
        assert_eq!(get_side.get_inspected, 8);
        assert_eq!(
            retained_get_prefix_count(&get_side),
            8,
            "{layout:?} wired Get entry retains eight headers"
        );
        assert_eq!(
            get_tail.result_attributes.inspected, 8,
            "{layout:?} wired Get path establishes eight results"
        );
        // A nine-slot Get template truncates retention at eight: the
        // entry flag lives in private side bits (never in a public
        // tail copy) while the emitted result list carries it publicly.
        let trunc_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&trunc_target, 0x40000, 0x50000, w);
        let (trunc_side, trunc_tail) = run_production_get_path(&trunc_target, layout, 0x40000, 9);
        assert_eq!(trunc_side.get_inspected, 8);
        assert_eq!(
            trunc_side.flags,
            u16::from(attr_list_flag::TRUNCATED) << GET_ENTRY_FLAGS_SHIFT,
            "{layout:?} truncated Get entry keeps its flag in private bits"
        );
        assert_eq!(
            trunc_tail.flags & !OBJECT_FLAGS_MASK,
            0,
            "{layout:?} public tail flags carry no private entry bits"
        );
        assert_eq!(
            trunc_tail.result_attributes.flags & attr_list_flag::TRUNCATED,
            attr_list_flag::TRUNCATED,
            "{layout:?} emitted Get list carries truncation publicly"
        );
        // The Get emission refuses before any read unless continuity
        // joined, and keeps the marking on refused return values.
        let get_row = harness_row(23, OBJECT_ACTION_GET, [ARG_NONE, ARG_NONE]);
        let mut refused_tail = ObjectCallWire::default();
        let mut refused_side = get_side;
        refused_side.phase = 3;
        let refused_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        let (reader, bytes) = adapter::readers(&refused_target);
        assert!(
            !unsafe {
                adapter_emit_get_attributes(
                    &mut refused_tail as *mut _,
                    Some(&refused_side),
                    23,
                    Some(&get_row),
                    layout,
                    adapter::rv_ok(),
                    false,
                    reader,
                    bytes,
                )
            },
            "{layout:?} refused continuity refuses Get emission"
        );
        adapter::assert_no_target_reads(
            &refused_target,
            &format!("{layout:?} refused Get emission"),
        );
        let bad_rv_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        let mut bad_rv_tail = ObjectCallWire::default();
        assert!(
            unsafe {
                adapter_tail_fill(
                    &mut bad_rv_tail as *mut _,
                    Some(&refused_side),
                    23,
                    Some(&get_row),
                )
            },
            "{layout:?} production Get tail fills"
        );
        let (reader, bytes) = adapter::readers(&bad_rv_target);
        assert!(
            unsafe {
                adapter_emit_get_attributes(
                    &mut bad_rv_tail as *mut _,
                    Some(&refused_side),
                    23,
                    Some(&get_row),
                    layout,
                    5,
                    true,
                    reader,
                    bytes,
                )
            },
            "{layout:?} refused RV keeps the Get list without failing emission"
        );
        assert_eq!(
            bad_rv_tail.result_attributes.flags,
            attr_list_flag::UNINSPECTED,
            "{layout:?} refused RV keeps the UNINSPECTED marking"
        );
        adapter::assert_no_target_reads(&bad_rv_target, &format!("{layout:?} refused-RV Get"));
        // Non-Get families leave the result list zero through the Get
        // emission (their result list stays absent, never marked).
        let create_row = harness_row(23, OBJECT_ACTION_CREATE, [5, ARG_NONE]);
        let plain_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        let mut plain_tail = ObjectCallWire::default();
        assert!(
            unsafe {
                adapter_tail_fill(
                    &mut plain_tail as *mut _,
                    Some(&refused_side),
                    23,
                    Some(&create_row),
                )
            },
            "{layout:?} production tail fills"
        );
        let (reader, bytes) = adapter::readers(&plain_target);
        assert!(
            unsafe {
                adapter_emit_get_attributes(
                    &mut plain_tail as *mut _,
                    Some(&refused_side),
                    23,
                    Some(&create_row),
                    layout,
                    adapter::rv_ok(),
                    true,
                    reader,
                    bytes,
                )
            },
            "{layout:?} non-Get emission succeeds trivially"
        );
        assert!(
            plain_tail.result_attributes == ObjectAttributeListWire::default(),
            "{layout:?} non-Get result list stays all-zero"
        );
        // Custody: the entry adapter refuses missing rows without
        // reads — and without acquiring arguments.
        let custody_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        let create_row = harness_row(23, OBJECT_ACTION_CREATE, [5, ARG_NONE]);
        let mut custody_fetches = 0u32;
        let mut fetch_arg = |_: u8| {
            custody_fetches += 1;
            None
        };
        let (reader, bytes) = adapter::readers(&custody_target);
        assert!(
            !adapter_attributes_entry(
                None,
                23,
                Some(&create_row),
                layout,
                &mut fetch_arg,
                reader,
                bytes
            ),
            "{layout:?} missing side refuses entry"
        );
        let (reader, bytes) = adapter::readers(&custody_target);
        assert!(
            !adapter_attributes_entry(
                Some(&mut refused_side),
                23,
                None,
                layout,
                &mut fetch_arg,
                reader,
                bytes,
            ),
            "{layout:?} missing row refuses entry"
        );
        assert_eq!(
            custody_fetches, 0,
            "{layout:?} entry custody refuses before acquiring arguments"
        );
        adapter::assert_no_target_reads(&custody_target, &format!("{layout:?} entry custody"));
    }
}

/// G05/E4 BPF delegation: the entry and Get emission wrappers bind
/// BPF-local state and call the shared adapters the suite executes.
/// Comment-proof (prose stripped before counting): comments or strings
/// naming the adapters cannot satisfy this pin.
#[test]
fn object_attributes_bpf_wrappers_delegate_to_shared_adapters() {
    pin_attribute_wrappers_delegate_to_shared_adapters();
}

/// G05/E4: the production attribute path captures all six attribute
/// fields, not UNINSPECTED-only transport. Creation-request and
/// GetAttributeValue vectors on LP64/ia32 must yield nonempty finite
/// cells for class, key type, token, value length, modulus bits and all
/// three curves, with distinct pair templates and no promotion of
/// requests to established results. Both halves drive the PRODUCTION
/// adapters the BPF programs call and assert on production side state
/// plus the EMITTED wire lists. RED while E4 is unwired (zero cells vs
/// the oracle's VALUE cells, UNINSPECTED transport); a budgeted E4 flips
/// these tests with zero test changes.
#[test]
fn object_attributes_real_adapter_six_fields() {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::object_capture::{
        GetEntryState, attr_kind, attr_list_flag, attr_status, capture_get_entry,
        capture_get_return, inspect_request_template,
    };
    use p11scope_ebpf_common::object_wire::{
        OBJECT_ACTION_CREATE, OBJECT_ACTION_PAIR, ObjectAttributeListWire,
    };
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        // Creation request: the oracle proves the vectors valid (with
        // independent literal expectations) on its own target, then the
        // PRODUCTION entry adapter — the same shared function the BPF
        // entry calls — runs on an identically programmed target and must
        // store the oracle wire cell for cell while reading only what it
        // reads. The harness never writes the side pair itself.
        let oracle_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&oracle_target, 0x40000, 0x50000, w);
        let (reader, bytes) = adapter::readers(&oracle_target);
        let expected = inspect_request_template(0x40000, 8, None, layout, reader, bytes);
        assert_eq!(expected.inspected, 8, "{layout:?} oracle inspects eight");
        assert_eq!(
            expected.flags & attr_list_flag::PRESENT,
            attr_list_flag::PRESENT
        );
        let kinds: Vec<u8> = expected.cells.iter().map(|cell| cell.kind).collect();
        assert_eq!(
            kinds,
            [
                attr_kind::CLASS,
                attr_kind::KEY_TYPE,
                attr_kind::TOKEN,
                attr_kind::VALUE_LEN,
                attr_kind::MODULUS_BITS,
                attr_kind::EC_PARAMS,
                attr_kind::EC_PARAMS,
                attr_kind::EC_PARAMS,
            ],
            "{layout:?} oracle classifies all six fields"
        );
        for (i, cell) in expected.cells.iter().enumerate() {
            assert_eq!(
                cell.status,
                attr_status::VALUE,
                "{layout:?} oracle cell {i} is VALUE"
            );
        }
        assert_eq!(
            expected
                .cells
                .iter()
                .map(|cell| cell.value)
                .collect::<Vec<u16>>(),
            [3, 0x1f, 1, 32, 2048, 1, 2, 3],
            "{layout:?} oracle values are the finite codes"
        );
        let prod_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&prod_target, 0x40000, 0x50000, w);
        let (prod_side, prod_tail) = run_production_request_path(
            &prod_target,
            layout,
            OBJECT_ACTION_CREATE,
            [(0x40000, 8), (0, 0)],
            [2, 3, ARG_NONE, ARG_NONE],
        );
        assert_reads_subset(
            &prod_target,
            &oracle_target,
            &format!("{layout:?} creation-request inspection"),
        );
        assert!(
            prod_side.requested[0].cells == expected.to_wire().cells,
            "{layout:?} the production entry path must capture the six fields, not UNINSPECTED"
        );
        assert_eq!(
            prod_side.requested[0].inspected, expected.inspected,
            "{layout:?} the production entry path must report its inspection"
        );
        assert!(
            prod_side.requested[1] == ObjectAttributeListWire::default(),
            "{layout:?} the absent pair stays all-zero in production side state"
        );
        // Production transport: the stored list must EMIT as the oracle
        // wire through the production tail — UNINSPECTED stays RED at the
        // flags until E4 wires inspected emission.
        assert!(
            prod_tail.requested[0] == expected.to_wire(),
            "{layout:?} production tail must emit the inspected request list, not UNINSPECTED"
        );
        assert!(
            prod_tail.requested[1] == ObjectAttributeListWire::default(),
            "{layout:?} absent pair stays all-zero"
        );
        // GetAttributeValue: the production entry retains headers into
        // production side state and the production return emission
        // establishes the same six fields on the EMITTED Get wire list.
        let oracle_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&oracle_target, 0x40000, 0x50000, w);
        let mut oracle_state = GetEntryState::default();
        let (reader, _) = adapter::readers(&oracle_target);
        let oracle_entry = capture_get_entry(0x40000, 8, layout, &mut oracle_state, reader);
        assert_eq!(
            oracle_entry.inspected, 8,
            "{layout:?} Get oracle entry inspects eight"
        );
        assert_eq!(
            oracle_entry.slot_count, 8,
            "{layout:?} Get oracle entry retains eight"
        );
        let prod_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&prod_target, 0x40000, 0x50000, w);
        let (prod_side, prod_tail) = run_production_get_path(&prod_target, layout, 0x40000, 8);
        assert_eq!(
            prod_side.get_template_base, oracle_state.template_base,
            "{layout:?} the production Get entry must retain the template base"
        );
        assert_eq!(
            prod_side.inspected_header_end, oracle_state.header_end,
            "{layout:?} the production Get entry must retain the header end"
        );
        assert_eq!(
            prod_side.get_inspected, oracle_state.inspected,
            "{layout:?} the production Get entry must report its inspection"
        );
        assert_eq!(
            retained_get_prefix_count(&prod_side),
            oracle_state.slot_count,
            "{layout:?} the production Get entry must retain eight headers"
        );
        for k in 0..8 {
            assert_eq!(
                prod_side.slots[k].value_ptr, oracle_state.slots[k].value_ptr,
                "{layout:?} the production Get entry must retain slot {k} pointer"
            );
            assert_eq!(
                prod_side.slots[k].entry_capacity, oracle_state.slots[k].entry_capacity,
                "{layout:?} the production Get entry must retain slot {k} capacity"
            );
            assert_eq!(
                prod_side.slots[k].kind, oracle_state.slots[k].kind,
                "{layout:?} the production Get entry must retain slot {k} kind"
            );
            assert_eq!(
                prod_side.slots[k].slot_index, oracle_state.slots[k].slot_index,
                "{layout:?} the production Get entry must retain slot {k} index"
            );
        }
        let (reader, bytes) = adapter::readers(&oracle_target);
        let expected = capture_get_return(
            &oracle_state,
            adapter::rv_ok(),
            adapter::owner_ready_authority(),
            layout,
            reader,
            bytes,
        );
        assert_eq!(expected.inspected, 8);
        for (i, cell) in expected.cells.iter().enumerate() {
            assert_eq!(
                cell.status,
                attr_status::VALUE,
                "{layout:?} Get oracle cell {i} is VALUE"
            );
        }
        assert_reads_subset(
            &prod_target,
            &oracle_target,
            &format!("{layout:?} GetAttributeValue inspection"),
        );
        // The EMITTED Get wire list (cells plus flags) must equal the
        // oracle wire: seam-outcome comparisons alone cannot observe Get
        // transport, so this assert executes the production return-side
        // emission. RED today (UNINSPECTED emitted vs VALUE expected).
        assert!(
            prod_tail.result_attributes == expected.to_wire(),
            "{layout:?} production Get emission must establish the six fields, not UNINSPECTED"
        );
        // Pair separation: a second template keeps its own cells while
        // the peer's headers (not values) are re-read for alias checks.
        // The oracle proves the shape; the PRODUCTION entry adapter must
        // then store both pairs (pair one with pair zero as its alias
        // peer) and emit both as their oracle wires.
        let oracle_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&oracle_target, 0x40000, 0x50000, w);
        program_attr_slot(&oracle_target, 0x60000, 0, w, 0x0000, 0x70000, w);
        oracle_target.borrow_mut().set_word(0x70000, 2);
        let (reader, bytes) = adapter::readers(&oracle_target);
        let expected_pair0 = inspect_request_template(0x40000, 8, None, layout, reader, bytes);
        let before = oracle_target.borrow().log().len();
        let (reader, bytes) = adapter::readers(&oracle_target);
        let pair = inspect_request_template(0x60000, 1, Some((0x40000, 8)), layout, reader, bytes);
        assert_eq!(pair.cells[0].kind, attr_kind::CLASS);
        assert_eq!(pair.cells[0].status, attr_status::VALUE);
        assert_eq!(pair.cells[0].value, 2);
        assert!(
            oracle_target.borrow().log()[before..]
                .iter()
                .any(|(_, addr, _)| *addr == 0x40000),
            "{layout:?} pair inspection re-reads peer headers"
        );
        assert_eq!(
            oracle_target.borrow().log()[before..]
                .iter()
                .filter(|(_, addr, _)| *addr == 0x50000)
                .count(),
            0,
            "{layout:?} pair inspection reads no peer value"
        );
        let prod_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&prod_target, 0x40000, 0x50000, w);
        program_attr_slot(&prod_target, 0x60000, 0, w, 0x0000, 0x70000, w);
        prod_target.borrow_mut().set_word(0x70000, 2);
        let (prod_side, prod_tail) = run_production_request_path(
            &prod_target,
            layout,
            OBJECT_ACTION_PAIR,
            [(0x40000, 8), (0x60000, 1)],
            [2, 3, 4, 5],
        );
        assert_reads_subset(
            &prod_target,
            &oracle_target,
            &format!("{layout:?} pair inspection"),
        );
        assert!(
            prod_side.requested[0] == expected_pair0.to_wire(),
            "{layout:?} the production entry path must capture pair zero"
        );
        assert!(
            prod_side.requested[1] == pair.to_wire(),
            "{layout:?} the production entry path must capture pair one with its peer"
        );
        assert!(
            prod_tail.requested[0] == expected_pair0.to_wire(),
            "{layout:?} production tail must emit pair zero"
        );
        assert!(
            prod_tail.requested[1] == pair.to_wire(),
            "{layout:?} production tail must emit pair one"
        );
        // No promotion: a fresh Get call without entry state establishes
        // nothing, however valid the creation request was.
        let fresh = GetEntryState::default();
        let (reader, bytes) = adapter::readers(&oracle_target);
        let unestablished = capture_get_return(
            &fresh,
            adapter::rv_ok(),
            adapter::owner_ready_authority(),
            layout,
            reader,
            bytes,
        );
        assert_eq!(unestablished.inspected, 0);
        for (i, cell) in unestablished.cells.iter().enumerate() {
            assert_eq!(
                (cell.kind, cell.status, cell.value),
                (0, 0, 0),
                "{layout:?} fresh Get cell {i} stays zero"
            );
        }
    }
}

/// G05/E4: the production attribute path refuses before unsafe reads.
/// Unknown and excluded selectors authorize no pointer/length reads;
/// rejected cells carry finite status while usable disjoint neighbors
/// survive; SetAttributeValue authorizes zero template reads under the
/// approved policy. Contamination vectors are representable on their
/// layout (a 64-bit-only vector cannot arrive through a four-byte read).
/// Both layers drive the PRODUCTION entry adapter the BPF entry calls:
/// the stored side pair plus the emitted wire list. RED while E4 is
/// unwired; a budgeted E4 flips this test with zero test changes.
#[test]
fn object_attributes_refuse_before_unsafe_read() {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::object_capture::{
        DeriveEntry, attr_kind, attr_status, authorize_entry_templates, inspect_request_template,
    };
    use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;
    let set_fn: u32 = pkcs11_module::FUNCTION_NAMES
        .iter()
        .position(|name| *name == "C_SetAttributeValue")
        .expect("C_SetAttributeValue exists") as u32;
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        // The fixture enforces target width: high bits programmed on a
        // four-byte target never reach the reader.
        if layout == LinuxLayout::Ilp32 {
            let width = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            width.borrow_mut().set_word(0x90000, 0x1_0000_0021);
            assert_eq!(width.borrow_mut().read_word(0x90000), Ok(0x21));
        }
        // Unknown and excluded selectors: no pointer/length reads, the
        // secret sentinel behind them unread, all-zero cells. The
        // full-width vector is LP64-only; ia32 uses the representable
        // high-bit refusal.
        let contamination = if layout == LinuxLayout::Lp64 {
            0x1_0000_0000u64
        } else {
            0x8000_0000u64
        };
        for (name, selector) in [
            ("unknown selector", 0xdead_beefu64),
            ("excluded CKA_ID", 0x0102u64),
            ("full-width contamination", contamination),
        ] {
            let oracle_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            program_attr_slot(&oracle_target, 0x40000, 0, w, selector, 0x50000, w);
            oracle_target.borrow_mut().set_word(0x50000, 0x5ec4e7);
            let slot = 0x40000;
            let (reader, bytes) = adapter::readers(&oracle_target);
            let expected = inspect_request_template(0x40000, 1, None, layout, reader, bytes);
            assert_eq!(
                (
                    expected.cells[0].kind,
                    expected.cells[0].status,
                    expected.cells[0].value
                ),
                (0, 0, 0),
                "{layout:?} {name} leaves an all-zero cell"
            );
            assert_eq!(
                oracle_target.borrow().reads_of(slot + w),
                0,
                "{layout:?} {name} reads no pointer field"
            );
            assert_eq!(
                oracle_target.borrow().reads_of(slot + 2 * w),
                0,
                "{layout:?} {name} reads no length field"
            );
            assert_eq!(
                oracle_target.borrow().reads_of(0x50000),
                0,
                "{layout:?} {name} reads no secret value"
            );
            // The PRODUCTION entry adapter runs on the identically
            // programmed target: its stored cells must agree with the
            // silent oracle (and keep agreeing once E4 wires it), while
            // the stored list and the emitted wire must carry the
            // inspected refusal (PRESENT with silent cells), not the
            // UNINSPECTED marking.
            let prod_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            program_attr_slot(&prod_target, 0x40000, 0, w, selector, 0x50000, w);
            prod_target.borrow_mut().set_word(0x50000, 0x5ec4e7);
            let (prod_side, prod_tail) = run_production_request_path(
                &prod_target,
                layout,
                OBJECT_ACTION_CREATE,
                [(0x40000, 1), (0, 0)],
                [2, 3, ARG_NONE, ARG_NONE],
            );
            assert_reads_subset(
                &prod_target,
                &oracle_target,
                &format!("{layout:?} {name} inspection"),
            );
            assert!(
                prod_side.requested[0].cells == expected.to_wire().cells,
                "{layout:?} {name}: the production path stays silent"
            );
            assert!(
                prod_side.requested[0] == expected.to_wire(),
                "{layout:?} {name}: production entry stores the inspected refusal"
            );
            assert!(
                prod_tail.requested[0] == expected.to_wire(),
                "{layout:?} {name}: production tail emits the inspected refusal"
            );
        }
        // A rejected cell carries finite status while its usable
        // disjoint neighbor survives as VALUE. The production path must
        // match the oracle on both.
        let oracle_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_attr_slot(&oracle_target, 0x40000, 0, w, 0x0001, 0x50000, 2);
        oracle_target.borrow_mut().set_bytes(0x50000, &[1, 0]);
        program_attr_slot(&oracle_target, 0x40000, 1, w, 0x0000, 0x50010, w);
        oracle_target.borrow_mut().set_word(0x50010, 4);
        let (reader, bytes) = adapter::readers(&oracle_target);
        let expected = inspect_request_template(0x40000, 2, None, layout, reader, bytes);
        assert_eq!(expected.cells[0].kind, attr_kind::TOKEN);
        assert_eq!(expected.cells[0].status, attr_status::INVALID_LENGTH);
        assert_eq!(expected.cells[1].status, attr_status::VALUE);
        assert_eq!(expected.cells[1].value, 4);
        let prod_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_attr_slot(&prod_target, 0x40000, 0, w, 0x0001, 0x50000, 2);
        prod_target.borrow_mut().set_bytes(0x50000, &[1, 0]);
        program_attr_slot(&prod_target, 0x40000, 1, w, 0x0000, 0x50010, w);
        prod_target.borrow_mut().set_word(0x50010, 4);
        let (prod_side, prod_tail) = run_production_request_path(
            &prod_target,
            layout,
            OBJECT_ACTION_CREATE,
            [(0x40000, 2), (0, 0)],
            [2, 3, ARG_NONE, ARG_NONE],
        );
        assert_reads_subset(
            &prod_target,
            &oracle_target,
            &format!("{layout:?} neighbor inspection"),
        );
        assert!(
            prod_side.requested[0].cells[1] == expected.cells[1].to_wire(),
            "{layout:?} the production path must keep the usable neighbor"
        );
        assert!(
            prod_side.requested[0].cells[0] == expected.cells[0].to_wire(),
            "{layout:?} the production path must carry the finite rejection"
        );
        assert!(
            prod_tail.requested[0] == expected.to_wire(),
            "{layout:?} production tail emits neighbor and rejection"
        );
        // SetAttributeValue is an invalidation/control call: zero
        // template reads under the approved policy.
        let templates =
            authorize_entry_templates(set_fn, [(0x40000, 2), (0, 0)], DeriveEntry::Unavailable);
        assert_eq!(
            templates,
            [None, None],
            "{layout:?} Set authorizes no template"
        );
    }
}
