//! SPDX-License-Identifier: GPL-3.0-or-later
//! The native suite compiles real ELF fixtures and exercises the shared decoder.
use std::process::Command;

#[test]
fn embedded_scalar_helpers_have_exact_linkage_btf_bodies_and_real_calls() {
    let directory = tempfile::tempdir().expect("temporary embedded BPF object");
    let object = directory.path().join("p11scope-ebpf");
    std::fs::write(&object, p11scope::EBPF_OBJECT).expect("write actual embedded object");
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-I", "scripts/check-bpf-map-defs.py", "--json"])
        .arg(&object)
        .output()
        .expect("inspect actual embedded owner linkage and calls");
    assert!(
        output.status.success(),
        "embedded owner contract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let contract: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("decode embedded owner contract report");
    let symbols = contract["symbols"]
        .as_array()
        .expect("embedded owner symbol inventory");
    for helper in ["p11_owner_lease", "p11_owner_refund"] {
        assert!(
            symbols.iter().any(|symbol| symbol == helper),
            "embedded object must export {helper}"
        );
    }
    assert!(
        symbols.iter().any(|symbol| symbol == "p11_read_ia32_arg"),
        "embedded object must export p11_read_ia32_arg"
    );
    let variant = if cfg!(feature = "unsafe-unvalidated-metadata") {
        "diagnostic"
    } else {
        "default"
    };
    let mutations = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("P11SCOPE_IA32_OBJECT", &object)
        .env("P11SCOPE_IA32_VARIANT", variant)
        .args([
            "-I",
            "tests/python/test_bpf_map_defs.py",
            "MapDefsTests.test_ia32_reader_linkage_signature_body_and_call",
        ])
        .output()
        .expect("run actual ia32 reader object mutations");
    assert!(
        mutations.status.success(),
        "actual ia32 reader mutations failed: stdout={} stderr={}",
        String::from_utf8_lossy(&mutations.stdout),
        String::from_utf8_lossy(&mutations.stderr)
    );
}

#[test]
fn embedded_object_capture_globals_have_exact_scalar_abis_and_calls() {
    let directory = tempfile::tempdir().expect("temporary scalar object capture mutations");
    let object = directory.path().join("p11scope-ebpf");
    std::fs::write(&object, p11scope::EBPF_OBJECT).expect("write actual embedded BPF object");
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("P11SCOPE_OBJECT_CAPTURE_OBJECT", &object)
        .env(
            "P11SCOPE_OBJECT_CAPTURE_FULL",
            if cfg!(feature = "stub-object-attributes") {
                "0"
            } else {
                "1"
            },
        )
        .args([
            "-I",
            "tests/python/test_bpf_map_defs.py",
            "ObjectCaptureGlobalsTests.test_object_capture_globals_linkage_signature_and_calls",
        ])
        .output()
        .expect("run actual scalar capture ABI and call mutations");
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "scalar capture globals: {report}");
    assert!(report.contains("Ran 1 test"), "zero selection: {report}");
    assert!(
        !report.contains("skipped"),
        "skipped scalar proof: {report}"
    );
}

/// Relocation itself is an object transformation. Distinct sentinel descriptors
/// exercise the real Aya parser/relocator without creating or loading BPF maps.
#[test]
fn embedded_maps_relocate_without_kernel_syscalls() {
    let mut object = aya_obj::Object::parse(p11scope::EBPF_OBJECT).expect("parse embedded object");
    let maps = object.maps.clone();
    let mut names: Vec<_> = maps.keys().collect();
    names.sort();
    let descriptors: std::collections::BTreeMap<_, _> = names
        .into_iter()
        .enumerate()
        .map(|(index, name)| (name.as_str(), 1000 + index as i32))
        .collect();
    let code_sections = object
        .functions
        .keys()
        .map(|(section, _)| *section)
        .collect();
    object
        .relocate_maps(
            maps.iter()
                .map(|(name, map)| (name.as_str(), descriptors[name.as_str()], map)),
            &code_sections,
        )
        .expect("relocate every embedded map reference");
    let referenced: std::collections::BTreeSet<_> = object
        .functions
        .values()
        .flat_map(|function| &function.instructions)
        .filter(|instruction| instruction.code == 0x18 && instruction.src_reg() == 1)
        .map(|instruction| instruction.imm)
        .collect();
    for name in [
        "TASK_COOKIE",
        "COOKIE_CTL",
        "THREAD_OWNER",
        "OWNER_CTL",
        "ROOT_AFFILIATION",
        "ROOT_CTL",
    ] {
        assert!(
            referenced.contains(&descriptors[name]),
            "native map {name} must retain its own descriptor after relocation"
        );
    }
}

#[test]
fn native_bpf_map_decoder_contracts() {
    let cases = [
        "MapDefsTests.test_mixed_extraction",
        "MapDefsTests.test_elf_refusals",
        "MapDefsTests.test_btf_refusals",
        "MapDefsTests.test_relocation_refusals",
        "MapDefsTests.test_duplicate_and_missing_native_entries",
        "MapDefsTests.test_exact_helpers",
        "MapDefsTests.test_classic_uprobe_kernel_stack",
        "MapDefsTests.test_owner_linkage",
        "MapDefsTests.test_root_helpers",
        "MapDefsTests.test_json_and_legacy_cli",
        "MapDefsTests.test_runner_guards",
        "MapDefsTests.test_frozen_map_names_survive_kernel_truncation",
        "Ia32SpanProofTests.test_saved_sentinel_requires_proven_full_width_register_flow",
    ];
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-I", "tests/python/test_bpf_map_defs.py"])
        .args(cases)
        .output()
        .expect("run required native map decoder tests");
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "native map decoder suite: {report}"
    );
    assert!(report.contains("Ran 13 tests"), "zero selection: {report}");
    assert!(report.contains("\nOK\n"), "skipped decoder proof: {report}");
}

/// Release marker-OFF inventory and future native marker call-site twins.
#[test]
fn embedded_birth_marker_twins_are_driven() {
    let cases = [
        "JournalMarkerInventoryTests.test_release_detailed_marker_absence_accepts",
        "JournalMarkerInventoryTests.test_release_detailed_stale_marker_inventory_refused",
        "JournalMarkerInventoryTests.test_release_half_linked_marker_globals_refused",
        "JournalMarkerInventoryTests.test_inventory_with_marker_map_refused",
        "JournalMarkerInventoryTests.test_inventory_with_marker_symbols_refused",
        "JournalMarkerInventoryTests.test_release_stale_marker_wrong_abi_refused",
        "JournalMarkerInventoryTests.test_core_instance_helper_missing_still_refused",
        "JournalMarkerInventoryTests.test_marker_helper_boundary",
        "JournalMarkerInventoryTests.test_marker_helper_boundary_refuses_user_read",
        "JournalMarkerInventoryTests.test_marker_single_global_refused",
        "JournalMarkerCallSiteTests.test_marker_calls_healthy_diagnostic",
        "JournalMarkerCallSiteTests.test_marker_calls_healthy_default",
        "JournalMarkerCallSiteTests.test_marker_calls_without_markers_skipped",
        "JournalMarkerCallSiteTests.test_marker_call_dropped_from_entry_refused",
        "JournalMarkerCallSiteTests.test_marker_call_dropped_from_ia32_entry_refused",
        "JournalMarkerCallSiteTests.test_marker_call_dropped_from_return_refused",
        "JournalMarkerCallSiteTests.test_marker_call_dropped_from_template_continuation_refused",
        "JournalMarkerCallSiteTests.test_marker_call_dropped_from_exec_refused",
        "JournalMarkerCallSiteTests.test_marker_call_dropped_from_exit_refused",
        "JournalMarkerCallSiteTests.test_marker_call_dropped_from_template_refused",
        "JournalMarkerCallSiteTests.test_marker_call_dropped_from_template_types_refused",
        "JournalMarkerCallSiteTests.test_marker_call_dropped_from_template_pair_refused",
    ];
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-I", "tests/python/test_bpf_map_defs.py"])
        .args(cases)
        .output()
        .expect("run birth marker twins");
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "birth marker twins: {report}");
    assert!(report.contains("Ran 22 tests"), "zero selection: {report}");
    assert!(report.contains("\nOK\n"), "skipped marker proof: {report}");
}
