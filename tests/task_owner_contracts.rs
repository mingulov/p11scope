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

/// Timing-bank producer units over the actual C helpers: saturating add,
/// exact maximum, ts-before-remove ordering and entry-write fences.
/// Host-only; no BPF load, no attach.
#[test]
fn production_counter_bank_timing_helpers() {
    let temporary = tempfile::tempdir().expect("counter timing test directory");
    let binary = temporary.path().join("counter-bank-timing");
    let output = Command::new("clang-18")
        .args([
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
            "-DP11SCOPE_COUNTER_BANK_PROOF",
            "-DP11SCOPE_BANK_MODE_LATENCY",
            "-I",
            "crates/ebpf/native",
            "tests/fixtures/task-owner/helper_tests.c",
            "-o",
        ])
        .arg(&binary)
        .output()
        .expect("compile actual counter-bank timing helpers");
    assert!(
        output.status.success(),
        "native counter timing compile: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for selector in [
        "bank_timing_add_saturates",
        "bank_timing_max_exact_eight_and_contention",
        "bank_timing_ts_before_remove",
        "bank_timing_enter_writes_no_buckets",
        "bank_timing_enter_stores_clock",
    ] {
        let output = Command::new(&binary).arg(selector).output().unwrap();
        assert!(
            output.status.success(),
            "native counter timing {selector}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// Timing producer compiles warning-free in both modes under the exact BPF
/// object flags, so a caller-less mode can never rot. Host-only; emits LLVM
/// bitcode to a temp dir, no BPF load, no attach.
#[test]
fn production_counter_bank_timing_producer_compiles_in_both_modes() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let temporary = tempfile::tempdir().expect("counter timing modes directory");
    let target = if cfg!(target_endian = "big") {
        "bpfeb"
    } else {
        "bpfel"
    };
    let prefix = format!("-ffile-prefix-map={manifest}=/p11scope");
    let source = format!("{manifest}/crates/ebpf/native/counter_bank_timing.c");
    for mode in ["TIMESTAMPS", "LATENCY"] {
        let output_name = format!("counter_bank_timing-{mode}.bc");
        let output_path = temporary.path().join(&output_name);
        let mode_flag = format!("-DP11SCOPE_BANK_MODE_{mode}");
        let output = Command::new("clang-18")
            .current_dir(temporary.path())
            .args([
                "-target",
                target,
                "-O2",
                "-g",
                "-gno-record-gcc-switches",
                "-fdebug-compilation-dir=/p11scope/native",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-emit-llvm",
                "-c",
            ])
            .arg(&prefix)
            .arg(&source)
            .arg("-DP11SCOPE_COUNTER_BANK_PROOF")
            .arg(&mode_flag)
            .arg("-o")
            .arg(&output_name)
            .output()
            .expect("compile timing producer unit");
        assert!(
            output.status.success(),
            "native {mode} producer compile: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output_path.exists(),
            "native {mode} producer bitcode emitted"
        );
    }
}
