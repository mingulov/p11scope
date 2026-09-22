//! SPDX-License-Identifier: GPL-3.0-or-later
//! Actual caller object checks without loading BPF or creating kernel maps.
use std::process::Command;

#[test]
fn caller_inventory_object_has_exact_maps_native_boundary_and_entry_controls() {
    let directory = tempfile::tempdir().expect("caller object test directory");
    let path = directory.path().join("inventory-callers.o");
    std::fs::write(&path, p11scope::EBPF_INVENTORY_CALLERS_OBJECT)
        .expect("write embedded caller object");
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "-I",
            "scripts/check-bpf-map-defs.py",
            "--inventory",
            env!("P11SCOPE_INVENTORY_CALLERS_VARIANT"),
        ])
        .arg(&path)
        .output()
        .expect("caller object manifest and native graph check");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-I", "tests/python/test_inventory_caller_object.py"])
        .env("P11SCOPE_INVENTORY_CALLERS_OBJECT", &path)
        .env(
            "P11SCOPE_INVENTORY_CALLERS_VARIANT",
            env!("P11SCOPE_INVENTORY_CALLERS_VARIANT"),
        )
        .output()
        .expect("actual caller ordinary-entry controls and object mutations");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut object = aya_obj::Object::parse(p11scope::EBPF_INVENTORY_CALLERS_OBJECT)
        .expect("parse caller object");
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
        .expect("relocate caller maps without kernel syscalls");
    let referenced: std::collections::BTreeSet<_> = object
        .functions
        .values()
        .flat_map(|function| &function.instructions)
        .filter(|instruction| instruction.code == 0x18 && instruction.src_reg() == 1)
        .map(|instruction| instruction.imm)
        .collect();
    for name in [
        "THREAD_OWNER",
        "OWNER_CTL",
        "DISCOVERY_STATE",
        "USAGE",
        "USAGE_CONFIG",
        "USAGE_EVIDENCE",
        "ENDPOINT_OBJECT",
        "CALLER_USE",
        "CALLER_EVIDENCE",
        "TASK_COOKIE",
        "COOKIE_CTL",
    ] {
        assert!(
            referenced.contains(&descriptors[name]),
            "unreferenced caller map {name}"
        );
    }
}
