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
//! Set AYA_BUILD_SKIP=1 to skip (e.g. doc-only builds).
use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=AYA_BUILD_SKIP");
    if matches!(env::var("AYA_BUILD_SKIP").as_deref(), Ok("1") | Ok("true")) {
        println!("cargo:warning=AYA_BUILD_SKIP set; skipping eBPF build");
        return;
    }
    println!("cargo:rerun-if-changed=crates/ebpf/src");
    println!("cargo:rerun-if-changed=crates/ebpf/Cargo.toml");
    println!("cargo:rerun-if-changed=crates/ebpf-common/src");

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));

    let target = match env::var("CARGO_CFG_TARGET_ENDIAN").as_deref() {
        Ok("big") => "bpfeb-unknown-none",
        _ => "bpfel-unknown-none",
    };

    let ebpf_manifest = manifest_dir.join("crates/ebpf/Cargo.toml");
    let status = Command::new("cargo")
        .args([
            "+nightly",
            "build",
            "--release",
            "--target",
            target,
            "-Z",
            "build-std=core",
            "--manifest-path",
        ])
        .arg(&ebpf_manifest)
        // Cargo sets these for build-script subprocesses to point at the
        // *outer* (stable) toolchain; left alone they'd override `+nightly`
        // on the inner cargo invocation. Same workaround as `aya-build`.
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .status()
        .expect("failed to spawn `cargo +nightly build` for crates/ebpf");
    assert!(status.success(), "building crates/ebpf failed: {status}");

    let built = manifest_dir
        .join("crates/ebpf/target")
        .join(target)
        .join("release/p11scope-ebpf");
    std::fs::copy(&built, out_dir.join("p11scope-ebpf"))
        .unwrap_or_else(|e| panic!("copying {} to OUT_DIR: {e}", built.display()));
}
