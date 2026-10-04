//! SPDX-License-Identifier: GPL-3.0-or-later
//! The release compiler is single-sourced from `.release-rust-version`.
//!
//! Every live toolchain selector (shell, Python, CI) reads that file instead
//! of pinning a literal, and the crate `rust-version` fields equal that
//! compiler's major.minor (latest only, no older supported floor). These tests
//! pin the mechanism so a future bump touches the version file first and cannot
//! silently reintroduce a literal selector or a stale-toolchain job.

use std::fs;

fn release_rust() -> String {
    fs::read_to_string(".release-rust-version")
        .expect("read the release Rust version")
        .trim()
        .to_string()
}

#[test]
fn version_file_is_one_pinned_triple() {
    let raw = fs::read_to_string(".release-rust-version").expect("read the version file");
    let version = release_rust();
    assert_eq!(
        raw,
        format!("{version}\n"),
        "the version file must hold exactly one trailing-newline version"
    );
    let parts: Vec<&str> = version.split('.').collect();
    assert_eq!(parts.len(), 3, "the release version must be X.Y.Z");
    for part in parts {
        assert!(
            !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()),
            "the release version must be numeric X.Y.Z"
        );
    }
}

#[test]
fn mise_pins_the_release_compiler() {
    let mise = fs::read_to_string("mise.toml").expect("read mise.toml");
    assert!(
        mise.contains(&format!("rust = \"{}\"", release_rust())),
        "mise.toml must mirror .release-rust-version"
    );
}

#[test]
fn live_shell_selectors_read_the_version_file() {
    for path in [
        "scripts/build-release.sh",
        "scripts/prepared-dependency-tools.sh",
        "scripts/product-build.sh",
        "scripts/release-gate.sh",
        "scripts/release-notices.py",
        "scripts/package-release.py",
        "scripts/lane-receipt-lane16-oracle-1.py",
        "scripts/matrix/verify-docker.sh",
        "scripts/matrix/verify-kind-pod.sh",
        "scripts/matrix/verify-proxy-stack.sh",
        "scripts/verify-inspect-doctor.sh",
        "scripts/bench-overhead.sh",
        "scripts/system-scope-measure.sh",
        "scripts/attach-pod.sh",
        "scripts/kind-e2e.sh",
        "scripts/run-flake-quarantine.sh",
    ] {
        let text = fs::read_to_string(path).expect("read a live selector");
        assert!(
            text.contains(".release-rust-version"),
            "{path} must read the release Rust version file"
        );
        assert!(
            !text.contains("1.88"),
            "{path} must not pin a literal 1.88 selector"
        );
    }
}

#[test]
fn ci_selectors_read_the_version_file() {
    let ci = fs::read_to_string(".github/workflows/ci.yml").expect("read ci.yml");
    assert!(
        ci.contains("$(cat .release-rust-version)"),
        "CI must read the release Rust version file"
    );
    // Full-comment lines cannot pin a selector; executable steps can.
    let executable: String = ci
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !executable.contains("1.88"),
        "CI must not pin a literal 1.88 selector"
    );
}

#[test]
fn ci_has_no_stale_toolchain_job() {
    let ci = fs::read_to_string(".github/workflows/ci.yml").expect("read ci.yml");
    assert!(
        !ci.contains("\n  msrv:\n"),
        "CI must not define an msrv job: the release compiler is the only supported toolchain"
    );
    // Every `cargo +X` / `rustup toolchain install X` selector in executable
    // steps must be the release version file or the pinned BPF nightly.
    for line in ci
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
    {
        for marker in ["cargo +", "toolchain install "] {
            let mut rest = line;
            while let Some(index) = rest.find(marker) {
                rest = &rest[index + marker.len()..];
                let selector = rest.trim_start_matches('"');
                assert!(
                    selector.starts_with("$(cat .release-rust-version)")
                        || selector.starts_with("nightly-2026-05-20"),
                    "CI toolchain selector must be the release compiler or the BPF nightly: {line}"
                );
            }
        }
    }
}

#[test]
fn rust_version_declarations_track_the_release_compiler() {
    let release = release_rust();
    let mut parts = release.split('.');
    let expected = format!(
        "{}.{}",
        parts.next().expect("major"),
        parts.next().expect("minor")
    );
    for manifest in [
        "Cargo.toml",
        "crates/discover/Cargo.toml",
        "crates/manifest/Cargo.toml",
        "crates/bpf-multi/Cargo.toml",
    ] {
        let text = fs::read_to_string(manifest).expect("read a workspace manifest");
        assert!(
            text.contains(&format!("rust-version = \"{expected}\"")),
            "{manifest} rust-version must equal the release compiler's major.minor {expected}"
        );
    }
}

/// `p11scope-ebpf-common` is also compiled by the pinned BPF nightly
/// (`nightly-2026-05-20`, rustc 1.97), which rejects a higher `rust-version`.
/// It tracks that nightly's major.minor instead of the release compiler's.
#[test]
fn ebpf_common_rust_version_matches_the_bpf_nightly() {
    let text = fs::read_to_string("crates/ebpf-common/Cargo.toml").expect("read ebpf-common");
    assert!(
        text.contains("rust-version = \"1.97\""),
        "ebpf-common rust-version must match the pinned BPF nightly (1.97)"
    );
}

#[test]
fn release_docs_name_the_version_file() {
    for doc in [
        "docs/development.md",
        "docs/build-offline.md",
        "RELEASING.md",
        "README.md",
    ] {
        let text = fs::read_to_string(doc).expect("read a release doc");
        assert!(
            text.contains(".release-rust-version"),
            "{doc} must name the release version file"
        );
    }
}
