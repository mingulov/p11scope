//! SPDX-License-Identifier: GPL-3.0-or-later
//! H7-E shared native-fixture driver: compile the real task-owner C
//! fixture and run one subcommand under default and small-state maps.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Compile the native owner fixture the way the repo builds it.
pub fn compile_owner_fixture(directory: &Path, name: &str, small: bool) -> PathBuf {
    let binary = directory.join(name);
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
    let output = compiler.output().expect("execute clang-18");
    assert!(
        output.status.success(),
        "native owner compile: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

pub fn run_fixture_subcommand(binary: &Path, subcommand: &str, marker: &str) {
    let output = Command::new(binary)
        .arg(subcommand)
        .output()
        .expect("execute native owner fixture");
    assert!(
        output.status.success(),
        "fixture {subcommand}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(marker),
        "fixture {subcommand} missed its marker: {stdout:?}"
    );
}

/// Run one object-custody fixture control under default and small-state maps.
pub fn run_object_subcommand(subcommand: &str, marker: &str) {
    let temporary = tempfile::tempdir().expect("native owner test directory");
    for small in [false, true] {
        let binary = compile_owner_fixture(
            temporary.path(),
            &format!("object-{subcommand}-small-{small}"),
            small,
        );
        run_fixture_subcommand(&binary, subcommand, marker);
    }
}
