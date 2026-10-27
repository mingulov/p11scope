//! SPDX-License-Identifier: GPL-3.0-or-later
//! The release compiler is single-sourced from `.release-rust-version`.
//!
//! Live release toolchain selectors (shell, Python, CI) read that file instead
//! of pinning a literal; the exact BPF comparison rebuilds both sides with the
//! release compiler and installs no historical toolchain. The crate
//! `rust-version` fields equal the release compiler's major.minor (latest only,
//! no older supported floor). These tests
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

fn validate_ci_toolchain_selectors(ci: &str) -> Result<(), String> {
    if ci.contains("\n  msrv:\n") {
        return Err(
            "CI must not define an msrv job: the release compiler is the only supported toolchain"
                .into(),
        );
    }
    let mut comparison_job = false;
    let mut comparison = String::new();
    // Every `cargo +X` / `rustup toolchain install X` selector in executable
    // steps uses the release pin or BPF nightly. The host-compiler transition
    // is complete: no historical compiler remains anywhere, including the
    // exact comparison job.
    for line in ci
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
    {
        // Follow the existing workflow's two-space job boundary, without
        // introducing another YAML parser.
        if !line.trim().is_empty() && !line.starts_with("    ") {
            comparison_job = line == "  bpf-noninterference:";
        }
        if comparison_job {
            comparison.push_str(line);
            comparison.push('\n');
        }
        for marker in ["cargo +", "toolchain install "] {
            let mut rest = line;
            while let Some(index) = rest.find(marker) {
                rest = &rest[index + marker.len()..];
                let selector = rest.trim_start_matches('"');
                if selector.starts_with("$(cat .release-rust-version)")
                    || selector.starts_with("nightly-2026-05-20")
                {
                    continue;
                }
                return Err(format!(
                    "CI toolchain selector must use the release pin or BPF nightly: {line}"
                ));
            }
        }
    }
    // The comparison keeps both calls on the moved baseline: the repeat
    // control, then the integration call with no transition flag. The
    // integration text ends at its line end, so a re-added flag breaks it.
    let repeat = r#"
          python3 -I scripts/check-bpf-noninterference.py \
            --repo "$GITHUB_WORKSPACE" --baseline "$BASELINE" --candidate "$BASELINE" \
            --work "$comparison_root/repeat-baseline" --repeat-baseline
"#;
    let integration = r#"
          python3 -I scripts/check-bpf-noninterference.py \
            --repo "$GITHUB_WORKSPACE" --baseline "$BASELINE" --candidate "$GITHUB_SHA" \
            --work "$comparison_root/integration"
"#;
    if !comparison
        .lines()
        .any(|line| line == "          BASELINE=869a79cae71e4ce566f896274768241131de87c2")
        || !comparison.contains(repeat)
        || !comparison.contains(integration)
        || comparison.contains("--host-compiler-transition")
    {
        return Err("the comparison job must run the exact pinned repeat and integration calls without a host compiler transition".into());
    }
    Ok(())
}

#[test]
fn ci_has_no_stale_toolchain_job() {
    let ci = fs::read_to_string(".github/workflows/ci.yml").expect("read ci.yml");
    validate_ci_toolchain_selectors(&ci).unwrap();
    let with_msrv = ci.replacen(
        "\n  lint:\n",
        "\n  msrv:\n    runs-on: ubuntu-24.04\n  lint:\n",
        1,
    );
    assert!(
        validate_ci_toolchain_selectors(&with_msrv).is_err(),
        "an added msrv job must be rejected"
    );
}

#[test]
fn ci_comparison_job_installs_no_historical_compiler() {
    let ci = fs::read_to_string(".github/workflows/ci.yml").expect("read ci.yml");
    validate_ci_toolchain_selectors(&ci).unwrap();
    let header = "\n  bpf-noninterference:\n";
    assert!(ci.contains(header), "missing comparison job");
    for selector in [
        "      - run: rustup toolchain install 1.98.1 --profile minimal",
        "      - run: cargo +1.98.1 test --locked",
    ] {
        let changed = ci.replacen(header, &format!("{header}{selector}\n"), 1);
        assert!(
            validate_ci_toolchain_selectors(&changed).is_err(),
            "historical compiler leaked into the comparison job: {selector}"
        );
    }
}

#[test]
fn ci_ordinary_jobs_install_no_historical_compiler() {
    let ci = fs::read_to_string(".github/workflows/ci.yml").expect("read ci.yml");
    validate_ci_toolchain_selectors(&ci).unwrap();
    for job in ["lint", "tests", "coverage"] {
        let header = format!("\n  {job}:\n");
        assert!(ci.contains(&header), "missing healthy job {job}");
        for selector in [
            "      - run: rustup toolchain install 1.98.1 --profile minimal",
            "      - run: cargo +1.98.1 test --locked",
        ] {
            let changed = ci.replacen(&header, &format!("{header}{selector}\n"), 1);
            assert!(
                validate_ci_toolchain_selectors(&changed).is_err(),
                "historical compiler leaked into {job}: {selector}"
            );
        }
    }
}

#[test]
fn ci_comparison_job_keeps_the_exact_moved_baseline_calls() {
    let ci = fs::read_to_string(".github/workflows/ci.yml").expect("read ci.yml");
    validate_ci_toolchain_selectors(&ci).unwrap();
    let header = "\n  bpf-noninterference:\n";
    assert!(ci.contains(header), "missing comparison job");
    let renamed = ci.replacen(header, "\n  ordinary-history:\n", 1);
    assert_ne!(renamed, ci, "renamed comparison must differ");
    assert!(
        renamed.contains("\n  ordinary-history:\n"),
        "renamed comparison must carry the new job name"
    );
    assert!(
        validate_ci_toolchain_selectors(&renamed).is_err(),
        "a renamed comparison job must be rejected"
    );
    for marker in [
        "BASELINE=869a79cae71e4ce566f896274768241131de87c2",
        "--repeat-baseline",
        "--candidate \"$GITHUB_SHA\"",
        "--work \"$comparison_root/integration\"",
    ] {
        assert!(ci.contains(marker), "missing healthy comparison {marker}");
        assert!(
            validate_ci_toolchain_selectors(&ci.replacen(marker, "", 1)).is_err(),
            "comparison call survived removal of {marker}"
        );
    }
    let revived = ci.replacen(
        "--work \"$comparison_root/integration\"\n",
        "--work \"$comparison_root/integration\" --host-compiler-transition\n",
        1,
    );
    assert!(
        validate_ci_toolchain_selectors(&revived).is_err(),
        "a revived host compiler transition must be rejected"
    );
    let selector = "      - run: rustup toolchain install 1.98.0 --profile minimal";
    let injected = ci.replacen(header, &format!("{header}{selector}\n"), 1);
    assert!(
        injected.contains(selector),
        "missing injected unreviewed compiler selector"
    );
    assert!(
        validate_ci_toolchain_selectors(&injected).is_err(),
        "an unreviewed compiler version must be rejected: {selector}"
    );
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

#[test]
fn licence_recipe_toolchain_tracks_the_release_compiler() {
    let recipe: serde_json::Value = serde_json::from_str(
        &fs::read_to_string("third-party/licenses/sources.json").expect("read licence recipe"),
    )
    .expect("parse licence recipe");
    let name = recipe["toolchains"][0]["name"]
        .as_str()
        .expect("first toolchain has a name");
    assert_eq!(
        name,
        release_rust(),
        "licence recipe toolchain must equal .release-rust-version"
    );
}

#[test]
fn licence_rust_patches_match_their_payload_hashes() {
    use sha2::{Digest, Sha256};
    let recipe: serde_json::Value = serde_json::from_str(
        &fs::read_to_string("third-party/licenses/sources.json").expect("read licence recipe"),
    )
    .expect("parse licence recipe");
    let patches = recipe["musl"][0]["rust_patches"]
        .as_array()
        .expect("musl recipe has rust_patches");
    assert!(!patches.is_empty(), "rust_patches must not be empty");
    for entry in patches {
        let file = entry["file"].as_str().expect("patch has a file");
        let want = entry["sha256"].as_str().expect("patch has a sha256");
        let recorded = recipe["files"][file]["sha256"]
            .as_str()
            .unwrap_or_else(|| panic!("rust_patches entry {file} has no files record"));
        assert_eq!(
            recorded, want,
            "rust_patches {file} drifted from its files record"
        );
        let bytes = fs::read(format!("third-party/licenses/{file}"))
            .unwrap_or_else(|_| panic!("read patch payload {file}"));
        let got: String = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            got, want,
            "rust_patches {file} bytes do not match its recorded sha256"
        );
    }
}
