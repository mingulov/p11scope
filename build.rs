//! SPDX-License-Identifier: GPL-3.0-or-later
//! Builds the BPF object with the nightly toolchain and hands cargo the
//! path via OUT_DIR, so `p11scope` ships one self-contained binary.
//!
//! `aya_build::build_ebpf` was tried first (per the brief) and shells out to
//! `cargo build --package <name> --bins ...` with no `--manifest-path` and
//! no `current_dir` override — it only resolves `<name>` when the eBPF
//! crate is a real member of *this* workspace. `crates/ebpf` deliberately
//! is not (Task 3): it pins its own `[workspace]` table so the bpf-target,
//! `#![no_std]` bin never gets pulled into a host-target build. Making it a
//! real member (even via `default-members` exclusion, as the upstream
//! aya-template does) breaks `cargo test --workspace`, which ignores
//! `default-members` and tries to compile the bin for the host, failing
//! with "duplicate lang item `panic_impl`" (verified locally). Declaring it
//! as a `[build-dependencies]` path dep instead trips a cargo resolver
//! panic ("did not find features for ... within activated_features") on
//! this toolchain, since it's a bin-only crate pulled in as a build-dep.
//! So: fallback per the brief — shell out to the same nightly command
//! Task 3 used and copy the artifact into OUT_DIR ourselves.
//!
use std::{env, path::PathBuf, process::Command};

#[path = "build_support/bpf_tools.rs"]
mod bpf_tools;

/// Drops host-only coverage instrumentation from rustflags before they are
/// forwarded to the freestanding BPF target: `-C instrument-coverage`
/// pairs, `--cfg=coverage`, and `--cfg coverage` pairs. Everything else
/// passes through untouched, reseparated with `sep`.
fn strip_coverage_flags_separated(encoded: &str, sep: char) -> String {
    let tokens: Vec<&str> = encoded
        .split(sep)
        .filter(|token| !token.is_empty())
        .collect();
    let mut kept = Vec::with_capacity(tokens.len());
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index];
        if token == "-C"
            && tokens.get(index + 1).is_some_and(|next| {
                next == &"instrument-coverage" || next == &"instrument_coverage"
            })
        {
            index += 2;
            continue;
        }
        if token == "--cfg=coverage" || token == "--cfg=coverage-nightly" {
            index += 1;
            continue;
        }
        if token == "--cfg"
            && tokens
                .get(index + 1)
                .is_some_and(|next| next == &"coverage" || next == &"coverage-nightly")
        {
            index += 2;
            continue;
        }
        kept.push(token);
        index += 1;
    }
    kept.join(&sep.to_string())
}

/// [`strip_coverage_flags_separated`] for `\u{1f}`-encoded rustflags.
fn strip_coverage_flags(encoded: &str) -> String {
    strip_coverage_flags_separated(encoded, '\u{1f}')
}

fn main() {
    println!("cargo:rerun-if-changed=crates/ebpf/src");
    println!("cargo:rerun-if-changed=crates/ebpf/native/image_identity.c");
    println!("cargo:rerun-if-changed=crates/ebpf/native/image_identity.h");
    println!("cargo:rerun-if-changed=crates/ebpf/native/image_identity_fork.c");
    println!("cargo:rerun-if-changed=crates/ebpf/native/task_owner.c");
    println!("cargo:rerun-if-changed=crates/ebpf/native/task_owner.h");
    println!("cargo:rerun-if-changed=crates/ebpf/native/root_affiliation.c");
    println!("cargo:rerun-if-changed=crates/ebpf/native/root_affiliation.h");
    println!("cargo:rerun-if-changed=crates/ebpf/Cargo.toml");
    println!("cargo:rerun-if-changed=crates/ebpf/Cargo.lock");
    println!("cargo:rerun-if-changed=crates/ebpf/rust-toolchain.toml");
    println!("cargo:rerun-if-changed=crates/ebpf-common/src");
    println!("cargo:rerun-if-changed=crates/ebpf-common/Cargo.toml");
    println!("cargo:rerun-if-changed=build_support/bpf_tools.rs");
    // Gate G2 induced-gap test (Task 7): forces a tiny RING_BYTES so a high
    // call rate overflows the ring buffer deliberately. Unset (the default)
    // leaves the build byte-for-byte identical to before this flag existed.
    println!("cargo:rerun-if-env-changed=P11SCOPE_SMALL_RING");
    println!("cargo:rerun-if-env-changed=P11SCOPE_SMALL_STATE_MAPS");
    println!("cargo:rerun-if-env-changed=P11SCOPE_SMALL_DISCOVERY_RING");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_UNSAFE_UNVALIDATED_METADATA");
    println!("cargo:rerun-if-env-changed=P11SCOPE_PREPARED_BPF_CARGO");
    println!("cargo:rerun-if-env-changed=P11SCOPE_PREPARED_BPF_RUSTC");
    println!("cargo:rerun-if-env-changed=LD_LIBRARY_PATH");
    let small_ring = matches!(
        env::var("P11SCOPE_SMALL_RING").as_deref(),
        Ok("1") | Ok("true")
    );
    let small_state_maps = matches!(
        env::var("P11SCOPE_SMALL_STATE_MAPS").as_deref(),
        Ok("1") | Ok("true")
    );
    let small_discovery_ring = matches!(
        env::var("P11SCOPE_SMALL_DISCOVERY_RING").as_deref(),
        Ok("1") | Ok("true")
    );

    build_variant(false, small_ring, small_state_maps, small_discovery_ring);
    build_variant(true, small_ring, small_state_maps, small_discovery_ring);
    println!(
        "cargo:rustc-env=P11SCOPE_INVENTORY_VARIANT={}",
        if small_discovery_ring {
            "inventory-small-discovery"
        } else {
            "inventory"
        }
    );
}

fn build_variant(
    inventory: bool,
    small_ring: bool,
    small_state_maps: bool,
    small_discovery_ring: bool,
) {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));

    let target = match env::var("CARGO_CFG_TARGET_ENDIAN").as_deref() {
        Ok("big") => "bpfeb-unknown-none",
        _ => "bpfel-unknown-none",
    };
    let mut cmd = bpf_tools::bpf_cargo_command_from_env()
        .unwrap_or_else(|error| panic!("selecting BPF Cargo and rustc: {error}"));

    // The native variant is isolated as well as the Cargo target directory.
    // Inventory has no image identity, root affiliation, or START dependency.
    let native_units: &[&str] = if inventory {
        &["task_owner"]
    } else {
        &[
            "image_identity",
            "image_identity_fork",
            "task_owner",
            "root_affiliation",
        ]
    };
    let mut native_bitcodes = Vec::new();
    for unit in native_units {
        let suffix = if inventory { "inventory" } else { "detailed" };
        let bitcode = out_dir.join(format!("{unit}-{suffix}.bc"));
        let mut compile = Command::new("clang-18");
        compile
            .args([
                "-target",
                if target.starts_with("bpfeb") {
                    "bpfeb"
                } else {
                    "bpfel"
                },
                "-O2",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-emit-llvm",
                "-c",
            ])
            .arg(manifest_dir.join(format!("crates/ebpf/native/{unit}.c")))
            .arg("-o")
            .arg(&bitcode);
        if inventory {
            compile.arg("-DP11SCOPE_INVENTORY_ONLY");
        } else if small_state_maps && !matches!(*unit, "image_identity" | "image_identity_fork") {
            compile.arg("-DP11SCOPE_SMALL_STATE_MAPS");
        }
        let status = compile
            .status()
            .expect("failed to spawn clang-18 for native state");
        assert!(
            status.success(),
            "building native {unit} ({suffix}) failed: {status}"
        );
        native_bitcodes.push(bitcode);
    }

    let ebpf_manifest = manifest_dir.join("crates/ebpf/Cargo.toml");
    let target_dir = out_dir.join(if inventory {
        "ebpf-inventory-target"
    } else {
        "ebpf-target"
    });
    cmd.args([
        "build",
        "--locked",
        "--release",
        "--target",
        target,
        "-Z",
        "build-std=core",
        "--manifest-path",
    ])
    .arg(&ebpf_manifest)
    .arg("--target-dir")
    .arg(&target_dir);
    let mut features = Vec::new();
    if inventory {
        features.push("inventory-only");
    }
    if small_ring && !inventory {
        features.push("small-ring");
    }
    if small_state_maps && !inventory {
        features.push("small-state-maps");
    }
    if small_discovery_ring {
        features.push("small-discovery-ring");
    }
    // Coverage instrumentation is host-only: strip it before forwarding to
    // the freestanding BPF target, which has no profiler runtime (SYSPLAN
    // residual F-40). A no-op for ordinary builds, which carry no such flags.
    let mut flags = strip_coverage_flags(&env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default());
    let mut append_flag = |flag: &str| {
        if !flags.is_empty() {
            flags.push('\u{1f}');
        }
        flags.push_str(flag);
    };
    // Native task storage and typed tracepoint require BTF/CO-RE in every build.
    for flag in [
        "-C",
        "linker=bpf-linker",
        "-C",
        "debuginfo=2",
        "-C",
        "link-arg=--btf",
        "-C",
        "link-arg=--export=p11_owner_reserve",
        "-C",
        "link-arg=--export=p11_owner_refund",
        "-C",
        "link-arg=--export=p11_read_ia32_arg",
    ] {
        append_flag(flag);
    }
    if !inventory {
        for flag in [
            "-C",
            "link-arg=--export=p11_link_current_identity",
            "-C",
            "link-arg=--export=p11_link_fork_allowed",
            "-C",
            "link-arg=--export=p11_link_emit_fork",
            "-C",
            "link-arg=--export=task_newtask",
        ] {
            append_flag(flag);
        }
        append_flag("-C");
        append_flag("link-arg=--export=START");
    }
    for bitcode in native_bitcodes {
        append_flag("-C");
        append_flag(&format!("link-arg={}", bitcode.display()));
    }
    append_flag("-C");
    append_flag("link-arg=--export=DISCOVERY_STATE");
    if !inventory && env::var_os("CARGO_FEATURE_UNSAFE_UNVALIDATED_METADATA").is_some() {
        features.push("unsafe-unvalidated-metadata");
        // Preserve separately verified diagnostic helpers and their BTF signatures.
        for flag in [
            "-C",
            "link-arg=--export=p11_decode_params",
            "-C",
            "link-arg=--export=p11_walk_template",
        ] {
            append_flag(flag);
        }
    }
    cmd.env("CARGO_ENCODED_RUSTFLAGS", flags);
    // Coverage instrumentation is host-only, and it arrives on three
    // channels: plain RUSTFLAGS, the encoded var above, and (for
    // cargo-llvm-cov) a RUSTC_WRAPPER that injects flags per rustc
    // invocation. Strip all three so the freestanding BPF target, which
    // has no profiler runtime, builds clean under coverage (F-40).
    if let Ok(rustflags) = env::var("RUSTFLAGS") {
        cmd.env("RUSTFLAGS", strip_coverage_flags_separated(&rustflags, ' '));
    }
    cmd.env_remove("RUSTC_WRAPPER");
    for key in [
        "CARGO_LLVM_COV",
        "CARGO_LLVM_COV_SHOW_ENV",
        "CARGO_LLVM_COV_TARGET_DIR",
        "CARGO_LLVM_COV_BUILD_DIR",
        "__CARGO_LLVM_COV_RUSTC_WRAPPER",
        "__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS",
        "__CARGO_LLVM_COV_RUSTC_WRAPPER_CRATE_NAMES",
    ] {
        cmd.env_remove(key);
    }
    if !features.is_empty() {
        cmd.arg("--features").arg(features.join(","));
    }
    let status = cmd
        .status()
        .expect("failed to spawn selected Cargo for crates/ebpf");
    assert!(status.success(), "building crates/ebpf failed: {status}");

    let built = target_dir.join(target).join("release/p11scope-ebpf");
    std::fs::copy(
        &built,
        out_dir.join(if inventory {
            "p11scope-ebpf-inventory"
        } else {
            "p11scope-ebpf"
        }),
    )
    .unwrap_or_else(|e| panic!("copying {} to OUT_DIR: {e}", built.display()));
}
