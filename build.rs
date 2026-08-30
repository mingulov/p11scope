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

fn main() {
    println!("cargo:rerun-if-changed=crates/ebpf/src");
    println!("cargo:rerun-if-changed=crates/ebpf/Cargo.toml");
    println!("cargo:rerun-if-changed=crates/ebpf/Cargo.lock");
    println!("cargo:rerun-if-changed=crates/ebpf/rust-toolchain.toml");
    println!("cargo:rerun-if-changed=crates/ebpf-common/src");
    println!("cargo:rerun-if-changed=crates/ebpf-common/Cargo.toml");
    // Gate G2 induced-gap test (Task 7): forces a tiny RING_BYTES so a high
    // call rate overflows the ring buffer deliberately. Unset (the default)
    // leaves the build byte-for-byte identical to before this flag existed.
    println!("cargo:rerun-if-env-changed=P11SCOPE_SMALL_RING");
    println!("cargo:rerun-if-env-changed=P11SCOPE_SMALL_STATE_MAPS");
    println!("cargo:rerun-if-env-changed=P11SCOPE_SMALL_DISCOVERY_RING");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_UNSAFE_UNVALIDATED_METADATA");
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

    let ebpf_manifest = manifest_dir.join("crates/ebpf/Cargo.toml");
    let target_dir = out_dir.join("ebpf-target");
    let mut cmd = Command::new("cargo");
    cmd.args([
        "+nightly-2026-05-20",
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
    if env::var_os("CARGO_FEATURE_UNSAFE_UNVALIDATED_METADATA").is_some() {
        features.push("unsafe-unvalidated-metadata");
    }
    if !features.is_empty() {
        cmd.arg("--features").arg(features.join(","));
    }
    let status = cmd
        // Cargo sets these for build-script subprocesses to point at the
        // *outer* (stable) toolchain; left alone they'd override `+nightly-2026-05-20`
        // on the inner cargo invocation. Same workaround as `aya-build`.
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .status()
        .expect("failed to spawn `cargo +nightly-2026-05-20 build` for crates/ebpf");
    assert!(status.success(), "building crates/ebpf failed: {status}");

    let built = target_dir.join(target).join("release/p11scope-ebpf");
    std::fs::copy(&built, out_dir.join("p11scope-ebpf"))
        .unwrap_or_else(|e| panic!("copying {} to OUT_DIR: {e}", built.display()));
}
