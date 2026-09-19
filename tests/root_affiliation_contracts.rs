//! SPDX-License-Identifier: GPL-3.0-or-later
use std::process::Command;

#[test]
fn production_root_affiliation_helpers_and_hook_order() {
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "-I",
            "tests/python/test_root_affiliation.py",
            "RootAffiliationTests.test_production_hook_order",
            "RootAffiliationTests.test_native_production_helpers",
            "RootAffiliationTests.test_native_birth_hook",
        ])
        .output()
        .expect("execute native root-affiliation contracts");
    assert!(
        output.status.success(),
        "root-affiliation contracts: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
