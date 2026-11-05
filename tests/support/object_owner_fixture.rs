//! SPDX-License-Identifier: GPL-3.0-or-later
//! H7-E shared native-fixture driver: compile the real task-owner C
//! fixture and run one subcommand under default and small-state maps.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

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

/// Compile the native owner fixture as a bridge shared library.
///
/// Same sources and warning discipline as the fixture binaries, plus
/// position-independent shared linkage and the `P11SCOPE_BRIDGE_LIB`
/// inspection exports. Lets one host test drive the real native
/// START allocation, side query and removal in-process with the real
/// shared Rust adapters on the same owned row. Used by the owner
/// suite's connected KEM test; allowed dead for suites that share
/// this file without the bridge.
#[allow(dead_code)]
pub fn compile_owner_bridge(directory: &Path, name: &str, small: bool) -> PathBuf {
    let library = directory.join(name);
    let mut compiler = Command::new("clang-18");
    compiler
        .args([
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
            "-fPIC",
            "-shared",
            "-DP11SCOPE_BRIDGE_LIB",
            "-I",
            "crates/ebpf/native",
            "tests/fixtures/task-owner/helper_tests.c",
            "-o",
        ])
        .arg(&library);
    if small {
        compiler.arg("-DP11SCOPE_SMALL_STATE_MAPS");
    }
    let output = compiler.output().expect("execute clang-18");
    assert!(
        output.status.success(),
        "native owner bridge compile: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    library
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
    use std::fs::File;
    use std::os::fd::AsRawFd as _;

    // Every invocation still starts a fresh fixture process. Only compilation
    // of the identical two variants is shared within this test executable.
    // Keep the actual executable FDs open, then remove their private directory;
    // /proc/self/fd resolves them before exec closes the CLOEXEC descriptors.
    // No cross-run cache or named temporary executable survives the test.
    static BINARIES: OnceLock<[(File, PathBuf); 2]> = OnceLock::new();
    let binaries = BINARIES.get_or_init(|| {
        let temporary = tempfile::tempdir().expect("native owner test directory");
        [false, true].map(|small| {
            let binary = compile_owner_fixture(
                temporary.path(),
                &format!("object-owner-small-{small}"),
                small,
            );
            let held = File::open(binary).expect("retain compiled native owner fixture");
            let executable = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd()));
            (held, executable)
        })
    });
    for (_, binary) in binaries {
        run_fixture_subcommand(binary, subcommand, marker);
    }
}
