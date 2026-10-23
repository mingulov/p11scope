//! SPDX-License-Identifier: GPL-3.0-or-later
use std::process::Command;

#[test]
fn production_task_owner_transactions_and_lifecycle() {
    let temporary = tempfile::tempdir().expect("native owner test directory");
    for (small, inventory) in [(false, false), (true, false), (false, true), (true, true)] {
        let binary = temporary
            .path()
            .join(format!("small-{small}-inventory-{inventory}"));
        let mut compiler = Command::new("clang-18");
        compiler
            .args([
                "-O2",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pthread",
                "-I",
                "crates/ebpf/native",
                "tests/fixtures/task-owner/helper_tests.c",
                "-o",
            ])
            .arg(&binary);
        if small {
            compiler.arg("-DP11SCOPE_SMALL_STATE_MAPS");
        }
        if inventory {
            compiler.arg("-DP11SCOPE_INVENTORY_ONLY");
        }
        let output = compiler.output().expect("execute clang-18");
        assert!(
            output.status.success(),
            "native compile: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(binary)
            .output()
            .expect("execute native owner test");
        assert!(
            output.status.success(),
            "native owner test: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// Sparse high-key tests over the actual C owner. This is no map-load,
/// population, verifier or 8192-endpoint collection acceptance.
#[test]
fn production_counter_bank_owner_full_bound_cleanup_is_fail_closed() {
    let temporary = tempfile::tempdir().expect("counter owner test directory");
    let binary = temporary.path().join("counter-bank-owner");
    let output = Command::new("clang-18")
        .args([
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
            "-DP11SCOPE_COUNTER_BANK_PROOF",
            "-I",
            "crates/ebpf/native",
            "tests/fixtures/task-owner/helper_tests.c",
            "-o",
        ])
        .arg(&binary)
        .output()
        .expect("compile actual counter-bank native owner");
    assert!(
        output.status.success(),
        "native counter owner compile: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for selector in [
        "counter_bank_owner_high_slot",
        "counter_bank_owner_start_failures",
        "counter_bank_owner_orphan_failures",
        "counter_bank_owner_incomplete_loops",
    ] {
        let output = Command::new(&binary).arg(selector).output().unwrap();
        assert!(
            output.status.success(),
            "native counter owner {selector}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
