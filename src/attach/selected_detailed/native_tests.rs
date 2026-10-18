//! SPDX-License-Identifier: GPL-3.0-or-later
//! Can run directly with rustc --test; no Cargo/BPF build or kernel loading.
use std::path::PathBuf;
use std::process::Command;
#[test]
fn actual_selected_native_gate_and_irreversible_state() {
    let root = PathBuf::from(option_env!("CARGO_MANIFEST_DIR").unwrap_or(env!("PWD")));
    assert!(
        root.join("crates/ebpf/native/selected_detailed.c")
            .is_file(),
        "selected native gate is not implemented"
    );
    let binary =
        std::env::temp_dir().join(format!("p11scope-selected-host-{}", std::process::id()));
    let output = Command::new("clang-18")
        .args([
            "-std=gnu11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unknown-attributes",
        ])
        .args(
            ["native_tests.c", "identity_fixture.c", "query_fixture.c"]
                .map(|name| root.join("src/attach/selected_detailed").join(name)),
        )
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_file(binary);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("29 controls passed"));
}

#[test]
fn actual_selected_bootstrap_uses_real_allocator_and_continuity() {
    let root = PathBuf::from(option_env!("CARGO_MANIFEST_DIR").unwrap_or(env!("PWD")));
    let binary = std::env::temp_dir().join(format!(
        "p11scope-selected-bootstrap-{}",
        std::process::id()
    ));
    let output = Command::new("clang-18")
        .args([
            "-std=gnu11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unknown-attributes",
        ])
        .args(
            ["bootstrap_tests.c", "identity_fixture.c", "query_fixture.c"]
                .map(|name| root.join("src/attach/selected_detailed").join(name)),
        )
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_file(binary);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("9 controls passed"));
}

#[test]
fn actual_inventory_baseline_uses_identity_only_allocator() {
    let root = PathBuf::from(option_env!("CARGO_MANIFEST_DIR").unwrap_or(env!("PWD")));
    assert!(
        root.join("crates/ebpf/native/selected_detailed_baseline.c")
            .is_file(),
        "Inventory-side baseline is not implemented"
    );
    let binary = std::env::temp_dir().join(format!(
        "p11scope-inventory-baseline-{}",
        std::process::id()
    ));
    let output = Command::new("clang-18")
        .args([
            "-std=gnu11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unknown-attributes",
        ])
        .args(
            ["baseline_tests.c", "identity_fixture.c"]
                .map(|name| root.join("src/attach/selected_detailed").join(name)),
        )
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_file(binary);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("7 controls passed"));
}
