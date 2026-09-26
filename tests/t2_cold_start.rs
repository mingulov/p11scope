//! SPDX-License-Identifier: GPL-3.0-or-later
//! T2 first-use cold-start pins: the product boots with no ambient
//! credentials and refuses honestly where it cannot run.
//!
//! Every trial spawns the real binary with a scrubbed environment
//! (`env_clear`, the `env -i` equivalent) and asserts the behavior observed
//! on 2026-09-26: doctor/help/version complete, capture lanes refuse with a
//! named cause, nothing panics, and a spoofed `SUDO_UID` changes no doctor
//! verdict. Environment-dependent lanes branch on the observer's own doctor
//! verdict instead of assuming this host's capture lane, so the suite is
//! unprivileged-safe. Findings and the full gap enumeration live in
//! `docs/qualification/system-first-use.md`.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_p11scope")
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

#[test]
fn cold_start_doctor_with_scrubbed_env_completes_honestly() {
    let outcome = cold_run(&["doctor"]);
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
        .env_clear()
        .env("SUDO_UID", "0")
        .env("SUDO_GID", "0")
        .output()
        .expect("run doctor with spoofed SUDO_UID");
    let spoofed = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let clean = cold_run(&["doctor"]);
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
        assert!(
            matches!(outcome.code, Some(0) | Some(1)),
            "cold profile on a capable host must exit 0/1: {:?}\n{}",
            outcome.code,
            outcome.stderr
        );
    } else {
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
        assert!(
            matches!(outcome.code, Some(0) | Some(1)),
            "cold run on a capable host must exit 0/1: {:?}\n{}",
            outcome.code,
            outcome.stderr
        );
    } else {
        assert_eq!(
            outcome.code,
            Some(1),
            "cold run without capture must refuse: {}",
            outcome.stderr
        );
        assert!(!outcome.stderr.is_empty(), "a refusal must name its cause");
    }
}
