// SPDX-License-Identifier: GPL-3.0-or-later
use std::process::Command;

#[test]
fn compact_inventory_object_matches_manifest_and_relocates_without_kernel_syscalls() {
    let directory = tempfile::tempdir().expect("inventory object test directory");
    let path = directory.path().join("inventory.o");
    std::fs::write(&path, p11scope::EBPF_INVENTORY_OBJECT)
        .expect("write embedded inventory object");
    let output = Command::new("python3")
        .args([
            "-I",
            "scripts/check-bpf-map-defs.py",
            "--inventory",
            env!("P11SCOPE_INVENTORY_VARIANT"),
        ])
        .arg(&path)
        .output()
        .expect("inventory object check");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("python3")
        .args(["-I", "tests/python/test_inventory_object.py"])
        .env("P11SCOPE_INVENTORY_OBJECT", &path)
        .env(
            "P11SCOPE_INVENTORY_VARIANT",
            env!("P11SCOPE_INVENTORY_VARIANT"),
        )
        .output()
        .expect("actual inventory object mutation checks");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut object =
        aya_obj::Object::parse(p11scope::EBPF_INVENTORY_OBJECT).expect("parse inventory object");
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
        .expect("relocate every inventory map reference");
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
    ] {
        assert!(
            referenced.contains(&descriptors[name]),
            "unreferenced inventory map {name}"
        );
    }
}
