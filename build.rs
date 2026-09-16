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

fn main() {
    println!("cargo:rerun-if-changed=crates/ebpf/src");
    println!("cargo:rerun-if-changed=crates/ebpf/native/image_identity.c");
    println!("cargo:rerun-if-changed=crates/ebpf/native/image_identity.h");
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

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));

    let target = match env::var("CARGO_CFG_TARGET_ENDIAN").as_deref() {
        Ok("big") => "bpfeb-unknown-none",
        _ => "bpfel-unknown-none",
    };
    let mut cmd = bpf_tools::bpf_cargo_command_from_env()
        .unwrap_or_else(|error| panic!("selecting BPF Cargo and rustc: {error}"));

    let native_bitcode = out_dir.join("image_identity.bc");
    let status = Command::new("clang-18")
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
        .arg(manifest_dir.join("crates/ebpf/native/image_identity.c"))
        .arg("-o")
        .arg(&native_bitcode)
        .status()
        .expect("failed to spawn clang-18 for image identity");
    assert!(
        status.success(),
        "building native image identity failed: {status}"
    );

    let owner_bitcode = out_dir.join("task_owner.bc");
    let root_bitcode = out_dir.join("root_affiliation.bc");
    for (unit, bitcode) in [
        ("task_owner", &owner_bitcode),
        ("root_affiliation", &root_bitcode),
    ] {
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
            .arg(bitcode);
        if small_state_maps {
            compile.arg("-DP11SCOPE_SMALL_STATE_MAPS");
        }
        let status = compile
            .status()
            .expect("failed to spawn clang-18 for native state");
        assert!(status.success(), "building native {unit} failed: {status}");
    }

    let ebpf_manifest = manifest_dir.join("crates/ebpf/Cargo.toml");
    let target_dir = out_dir.join("ebpf-target");
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
    if small_ring {
        features.push("small-ring");
    }
    if small_state_maps {
        features.push("small-state-maps");
    }
    if small_discovery_ring {
        features.push("small-discovery-ring");
    }
    let mut flags = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
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
        "link-arg=--export=p11_link_current_identity",
        "-C",
        "link-arg=--export=p11_link_fork_allowed",
        "-C",
        "link-arg=--export=p11_link_emit_fork",
        "-C",
        "link-arg=--export=task_newtask",
        "-C",
        "link-arg=--export=p11_owner_reserve",
        "-C",
        "link-arg=--export=p11_owner_refund",
        "-C",
        "link-arg=--export=p11_read_ia32_arg",
    ] {
        append_flag(flag);
    }
    append_flag("-C");
    append_flag(&format!("link-arg={}", native_bitcode.display()));
    append_flag("-C");
    append_flag(&format!("link-arg={}", owner_bitcode.display()));
    append_flag("-C");
    append_flag(&format!("link-arg={}", root_bitcode.display()));
    for symbol in ["START", "DISCOVERY_STATE"] {
        append_flag("-C");
        append_flag(&format!("link-arg=--export={symbol}"));
    }
    if env::var_os("CARGO_FEATURE_UNSAFE_UNVALIDATED_METADATA").is_some() {
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
    if !features.is_empty() {
        cmd.arg("--features").arg(features.join(","));
    }
    let status = cmd
        .status()
        .expect("failed to spawn selected Cargo for crates/ebpf");
    assert!(status.success(), "building crates/ebpf failed: {status}");

    let built = target_dir.join(target).join("release/p11scope-ebpf");
    std::fs::copy(&built, out_dir.join("p11scope-ebpf"))
        .unwrap_or_else(|e| panic!("copying {} to OUT_DIR: {e}", built.display()));
}
