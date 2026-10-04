//! SPDX-License-Identifier: GPL-3.0-or-later
//! The release compiler is single-sourced from `.release-rust-version`.
//!
//! Every live toolchain selector (shell, Python, CI) reads that file instead
//! of pinning a literal, while the crate `rust-version` fields stay at the
//! 1.88 minimum. These tests pin the mechanism so a future bump touches the
//! version file first and cannot silently reintroduce a literal selector.

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

/// Byte span of the `msrv` job block: from its `  msrv:` line to the next
/// exactly-2-space-indented line (the next job or a trailing comment) or EOF.
/// The `msrv` block is the one CI span allowed to pin literal 1.88.
fn ci_msrv_span(ci: &str) -> (usize, usize) {
    let start = ci.find("\n  msrv:\n").expect("CI must define an msrv job") + 1;
    let mut end = ci.len();
    let mut offset = start + "  msrv:\n".len();
    while offset < ci.len() {
        let next = ci[offset..].find('\n');
        let line_start = match next {
            Some(index) => offset + index + 1,
            None => break,
        };
        if line_start >= ci.len() {
            break;
        }
        let line = &ci[line_start..];
        if line.starts_with("  ") && !line.starts_with("   ") {
            end = line_start;
            break;
        }
        offset = line_start;
    }
    (start, end)
}

#[test]
fn ci_selectors_read_the_version_file() {
    let ci = fs::read_to_string(".github/workflows/ci.yml").expect("read ci.yml");
    assert!(
        ci.contains("$(cat .release-rust-version)"),
        "CI must read the release Rust version file"
    );
    let (start, end) = ci_msrv_span(&ci);
    let without = format!("{}{}", &ci[..start], &ci[end..]);
    // Full-comment lines cannot pin a selector; executable steps can.
    let executable: String = without
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !executable.contains("1.88"),
        "CI must not pin a literal 1.88 selector outside the msrv job"
    );
}

#[test]
fn ci_msrv_exemption_is_scoped() {
    let ci = fs::read_to_string(".github/workflows/ci.yml").expect("read ci.yml");
    // The msrv job exists, pins 1.88, runs the four gates, and never reads
    // the release version file (the lanes stay split).
    let (start, end) = ci_msrv_span(&ci);
    let block = &ci[start..end];
    assert!(
        block.contains("cargo +1.88 fmt")
            && block.contains("cargo +1.88 check")
            && block.contains("cargo +1.88 test")
            && block.contains("cargo +1.88 clippy"),
        "the msrv job must run the four canonical gates on 1.88"
    );
    assert!(
        !block.contains(".release-rust-version"),
        "the msrv job must not read the release version file"
    );
}

#[test]
fn msrv_declarations_stay_at_1_88() {
    for manifest in [
        "Cargo.toml",
        "crates/discover/Cargo.toml",
        "crates/ebpf-common/Cargo.toml",
        "crates/manifest/Cargo.toml",
        "crates/bpf-multi/Cargo.toml",
    ] {
        let text = fs::read_to_string(manifest).expect("read a workspace manifest");
        assert!(
            text.contains("rust-version = \"1.88\""),
            "{manifest} must keep the 1.88 MSRV floor"
        );
    }
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
