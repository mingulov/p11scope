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
        .arg(root.join("src/attach/selected_detailed/native_tests.c"))
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
    assert!(String::from_utf8_lossy(&output.stdout).contains("28 controls passed"));
}
