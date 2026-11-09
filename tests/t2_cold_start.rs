//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! T2 first-use cold-start pins: the product boots with no ambient
//! credentials and refuses honestly where it cannot run.
//!
//! Every trial spawns the real binary with a scrubbed environment
//! (`env_clear`, the `env -i` equivalent) and asserts the behavior observed
//! on 2026-09-26: doctor/help/version complete, capture lanes refuse with a
//! named cause, nothing panics, and a spoofed `SUDO_UID` changes no doctor
//! verdict. Environment-dependent lanes branch on the observer's own doctor
//! verdict instead of assuming this host's capture lane, so the suite is
//! unprivileged-safe. The distinction between startup checks and first-call
//! qualification is in `docs/qualification/first-use-contract.md`.

use std::process::Command;

/// The observer under test: the `P11SCOPE_E2E_OBSERVER` override when the
/// runner stages a prebuilt binary elsewhere, else the binary Cargo built
/// beside this test target.
fn bin() -> String {
    std::env::var("P11SCOPE_E2E_OBSERVER")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_p11scope").to_string())
}

struct Outcome {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Runs the binary with a fully scrubbed environment: no `PATH`, no `HOME`,
/// no `TMPDIR`, no `SUDO_*`, no `P11SCOPE_*` — the `env -i` cold start.
fn cold_run(args: &[&str]) -> Outcome {
    let output = Command::new(bin())
        .args(args)
        .env_clear()
        .output()
        .unwrap_or_else(|error| panic!("cold run p11scope {args:?}: {error}"));
    Outcome {
        code: output.status.code(),
        stdout: String::from_utf8(output.stdout).expect("stdout is UTF-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr is UTF-8"),
    }
}

fn assert_no_panic(outcome: &Outcome, args: &[&str]) {
    assert!(
        !outcome.stdout.contains("panicked"),
        "cold {args:?} panicked on stdout: {}",
        outcome.stdout
    );
    assert!(
        !outcome.stderr.contains("panicked"),
        "cold {args:?} panicked on stderr: {}",
        outcome.stderr
    );
}

/// Whether this host and these privileges allow the capture lane at all —
/// asked with the observer's own doctor rather than a second copy of the rule.
fn capture_available() -> bool {
    p11scope::doctor::verdict(&p11scope::doctor::probe(None, None)) == 0
}

/// With `P11SCOPE_REQUIRE_CAPTURE=1` (the privileged root run) the
/// capture-unavailable branch is a named failure instead of a passing
/// refusal, so the run proves the positive branch. Without the variable
/// this is a no-op and the test keeps its two-branch behavior.
fn require_capture_positive(test: &str) {
    if !matches!(
        std::env::var("P11SCOPE_REQUIRE_CAPTURE").as_deref(),
        Ok("1")
    ) {
        return;
    }
    panic!(
        "P11SCOPE_REQUIRE_CAPTURE=1 requires the positive branch, \
         but capture is unavailable ({test})"
    );
}

#[test]
fn cold_start_doctor_with_scrubbed_env_completes_honestly() {
    let outcome = cold_run(&["doctor", "-v"]);
    assert!(
        matches!(outcome.code, Some(0) | Some(1)),
        "cold doctor must exit 0/1, never crash: {:?}\n{}",
        outcome.code,
        outcome.stderr
    );
    assert!(
        outcome.stdout.contains("capability tier:"),
        "cold doctor must print its tier: {}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("verdict:"),
        "cold doctor must print its verdict: {}",
        outcome.stdout
    );
    assert_no_panic(&outcome, &["doctor"]);
}

#[test]
fn cold_start_help_and_version_need_no_environment() {
    let help = cold_run(&["doctor", "--help"]);
    assert_eq!(help.code, Some(0), "{}", help.stderr);
    assert!(
        help.stdout.contains("p11scope doctor"),
        "cold doctor --help must print usage: {}",
        help.stdout
    );
    let version = cold_run(&["--version"]);
    assert_eq!(version.code, Some(0), "{}", version.stderr);
    assert!(
        version.stdout.contains("p11scope "),
        "cold --version must print a version: {}",
        version.stdout
    );
}

#[test]
fn cold_start_extra_strict_refusal_is_explicit() {
    let outcome = cold_run(&["doctor", "--extra-strict"]);
    match outcome.code {
        Some(1) => assert!(
            outcome.stdout.contains("extra-strict refusal:"),
            "a refusal must name its violating rows: {}",
            outcome.stdout
        ),
        Some(0) => assert!(
            outcome.stdout.contains("no qualification violations"),
            "a clean host must say so explicitly: {}",
            outcome.stdout
        ),
        other => panic!("cold doctor --extra-strict exited {other:?}"),
    }
    assert_no_panic(&outcome, &["doctor", "--extra-strict"]);
}

#[test]
fn cold_start_doctor_ignores_spoofed_sudo_uid() {
    let output = Command::new(bin())
        .arg("doctor")
        .arg("-v")
        .env_clear()
        .env("SUDO_UID", "0")
        .env("SUDO_GID", "0")
        .output()
        .expect("run doctor with spoofed SUDO_UID");
    let spoofed = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let clean = cold_run(&["doctor", "-v"]);
    // Only the categorical lines are compared: per-row BPF diagnostics may
    // name whichever map the loader attempted first (T2-C2), but the
    // verdict and tier must not move under a spoofed credential.
    for marker in ["capability tier:", "verdict:"] {
        let spoofed_line = spoofed
            .lines()
            .find(|line| line.starts_with(marker))
            .unwrap_or_else(|| panic!("{marker} missing from spoofed run: {spoofed}"));
        let clean_line = clean
            .stdout
            .lines()
            .find(|line| line.starts_with(marker))
            .unwrap_or_else(|| panic!("{marker} missing from clean run: {}", clean.stdout));
        assert_eq!(
            spoofed_line, clean_line,
            "SUDO_UID must not move the doctor {marker} line"
        );
    }
}

#[test]
fn cold_start_profile_lane_is_honest_without_ambient_state() {
    let outcome = cold_run(&["profile", "--pid", "1", "--duration", "1s"]);
    assert_no_panic(&outcome, &["profile"]);
    if capture_available() {
        eprintln!("P11SCOPE_TEST_BRANCH=positive");
        assert!(
            matches!(outcome.code, Some(0) | Some(1)),
            "cold profile on a capable host must exit 0/1: {:?}\n{}",
            outcome.code,
            outcome.stderr
        );
    } else {
        eprintln!("P11SCOPE_TEST_BRANCH=unavailable");
        require_capture_positive("cold_start_profile_lane_is_honest_without_ambient_state");
        assert_eq!(
            outcome.code,
            Some(1),
            "cold profile without capture must refuse: {}",
            outcome.stderr
        );
        assert!(!outcome.stderr.is_empty(), "a refusal must name its cause");
    }
}

#[test]
fn cold_start_run_lane_is_honest_without_ambient_state() {
    let outcome = cold_run(&["run", "--duration", "1s", "--", "/bin/true"]);
    assert_no_panic(&outcome, &["run"]);
    if capture_available() {
        eprintln!("P11SCOPE_TEST_BRANCH=positive");
        assert!(
            matches!(outcome.code, Some(0) | Some(1)),
            "cold run on a capable host must exit 0/1: {:?}\n{}",
            outcome.code,
            outcome.stderr
        );
    } else {
        eprintln!("P11SCOPE_TEST_BRANCH=unavailable");
        require_capture_positive("cold_start_run_lane_is_honest_without_ambient_state");
        assert_eq!(
            outcome.code,
            Some(1),
            "cold run without capture must refuse: {}",
            outcome.stderr
        );
        assert!(!outcome.stderr.is_empty(), "a refusal must name its cause");
    }
}

/// Static guard: every test in this file that branches on capture
/// availability reads `P11SCOPE_REQUIRE_CAPTURE` through
/// `require_capture_positive`, so the privileged root run cannot pass on
/// the refusal branch. A new dual-outcome test that forgets the call
/// fails here by name.
#[test]
fn every_capture_branch_names_the_require_guard() {
    let path = format!("{}/tests/t2_cold_start.rs", env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(&path).unwrap();
    assert!(
        source.contains("fn require_capture_positive"),
        "the require guard is missing from {path}"
    );
    assert!(
        source.contains("P11SCOPE_REQUIRE_CAPTURE"),
        "the require guard no longer reads the variable in {path}"
    );
    for segment in source.split("#[test]") {
        let Some(name) = test_fn_name(segment) else {
            continue;
        };
        if name == "every_capture_branch_names_the_require_guard" {
            continue;
        }
        if segment.contains("capture_available()") {
            assert!(
                segment.contains("require_capture_positive"),
                "{name} branches on capture availability without reading \
                 P11SCOPE_REQUIRE_CAPTURE"
            );
        }
    }
}

/// The `fn` name of a `#[test]` segment, if the segment holds a test.
fn test_fn_name(segment: &str) -> Option<&str> {
    let rest = segment.split("fn ").nth(1)?;
    let end = rest.find(|c: char| !c.is_alphanumeric() && c != '_')?;
    Some(&rest[..end])
}

/// Static guard: the staged-binary override `bin()` reads is the dedicated
/// `P11SCOPE_E2E_OBSERVER` variable. A stray matrix export must not silently
/// switch the binary in an ordinary `cargo test`, so `bin()` must not read
/// that variable. (The needle is spelled in two halves so this guard does
/// not match its own source.)
#[test]
fn observer_override_uses_the_dedicated_variable() {
    let path = format!("{}/tests/t2_cold_start.rs", env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(&path).unwrap();
    assert!(
        source.contains(r#"std::env::var("P11SCOPE_E2E_OBSERVER")"#),
        "bin() must read P11SCOPE_E2E_OBSERVER in {path}"
    );
    assert!(
        !source.contains(&["P11SCOPE", "BIN"].join("_")),
        "bin() must not read the matrix override variable in {path}"
    );
}
