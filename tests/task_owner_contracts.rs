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
