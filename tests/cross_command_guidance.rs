//! SPDX-License-Identifier: GPL-3.0-or-later
//! Guidance must agree with real doctor verdicts and helper output channels.

use p11scope::doctor::{self, Check, Status};
use std::path::{Path, PathBuf};
use std::process::Command;

fn row(name: &str, status: Status) -> Check {
    Check {
        name: name.into(),
        status,
    }
}

fn ready_checks() -> Vec<Check> {
    [
        "BPF map create",
        "uprobe attach (self)",
        "host program preflight",
        "target readability",
        "/proc/4242/maps",
        "/proc/4242/mem",
        "lifecycle preflight",
        "scope preflight",
    ]
    .map(|name| row(name, Status::Ok("available".into())))
    .to_vec()
}

fn replace(checks: &mut [Check], name: &str, status: Status) {
    checks.iter_mut().find(|c| c.name == name).unwrap().status = status;
}

// Catches a summary that advertises readiness despite a failed requested lane,
// or turns diagnostic-only warnings into a default refusal.
#[test]
fn doctor_summary_matches_requested_lane_verdict() {
    let ready = ready_checks();
    assert_eq!(doctor::verdict(&ready), 0);
    assert_eq!(doctor::verdict_extra_strict(&ready), 0);
    assert!(doctor::render(&ready).starts_with(&doctor::summary(&ready, false)));
    assert!(doctor::render_extra_strict(&ready).starts_with(&doctor::summary(&ready, true)));
    assert_eq!(
        doctor::render(&ready).lines().next(),
        Some("Doctor: requested-lane checks passed.")
    );
    assert_eq!(
        doctor::render_extra_strict(&ready).lines().next(),
        Some("Doctor: extra-strict qualification passed.")
    );

    for (name, detail, action, forbidden) in [
        (
            "BPF map create",
            "Operation not permitted (os error 1)",
            "denial cause is unclassified",
            "Next: grant",
        ),
        (
            "BPF map create",
            "Operation not permitted (os error 1) (origin: controlled seccomp denial)",
            "review the specific denied operation in the launcher seccomp policy",
            "Next: grant",
        ),
        (
            "BPF map create",
            "Operation not permitted (os error 1) (origin: missing required capability)",
            "review the required capabilities for the failed operation",
            "launcher seccomp policy",
        ),
        (
            "host program preflight",
            "required BPF feature unsupported",
            "use a host with the required BPF/uprobe support",
            "Next: grant",
        ),
        (
            "target readability",
            "generation unavailable",
            "verify the target is live and readable",
            "Next: grant",
        ),
        (
            "target readability",
            "generation changed",
            "select a live target and rerun p11scope doctor --pid <PID>",
            "Next: grant",
        ),
        (
            "target readability",
            "mem unavailable",
            "check access to the target's maps, memory, root and provider files",
            "Next: grant",
        ),
        (
            "cgroup path",
            "cgroup v2 required: no unified hierarchy",
            "choose a cgroup v2 directory with cgroup.procs",
            "Next: grant",
        ),
    ] {
        let mut checks = ready_checks();
        if name == "cgroup path" {
            checks.push(row(name, Status::Fail(detail.into())));
        } else {
            replace(&mut checks, name, Status::Fail(detail.into()));
        }
        assert_eq!(doctor::verdict(&checks), 1, "{name}: {detail}");
        assert_eq!(doctor::verdict_extra_strict(&checks), 1);
        let text = doctor::render(&checks);
        assert_eq!(
            text.lines().next(),
            Some("Doctor: requested lane unavailable."),
            "{text}"
        );
        let next = text
            .lines()
            .find(|line| line.starts_with("Next: "))
            .unwrap();
        assert!(next.contains(action), "{text}");
        assert!(!next.contains(forbidden), "{text}");
        assert!(
            !next.contains("sudo") && !next.contains("disable"),
            "{text}"
        );
        assert!(
            text.contains(detail),
            "the original diagnostic survives: {text}"
        );
        assert!(!text.contains('\u{1b}'));
    }

    let mut warning = ready_checks();
    warning.push(row("live export reads", Status::Warn("unavailable".into())));
    assert_eq!(doctor::verdict(&warning), 0);
    assert_eq!(doctor::verdict_extra_strict(&warning), 1);
    let normal = doctor::render(&warning);
    let strict = doctor::render_extra_strict(&warning);
    assert_eq!(
        normal.lines().next(),
        Some("Doctor: requested-lane checks passed.")
    );
    assert_eq!(
        strict.lines().next(),
        Some("Doctor: extra-strict qualification refused.")
    );
    assert!(
        strict
            .lines()
            .find(|line| line.starts_with("Next: "))
            .unwrap()
            .contains("live export reads")
    );

    let mut build_limit = ready_checks();
    build_limit.push(row(
        "loader timing (dlopen)",
        Status::Warn("unproven".into()),
    ));
    assert_eq!(doctor::verdict_extra_strict(&build_limit), 0);
    assert_eq!(
        doctor::render_extra_strict(&build_limit).lines().next(),
        Some("Doctor: extra-strict qualification passed.")
    );
}

// Catches promoting missing or explicitly unexamined target/scope rows into a
// ready target, including an empty input that is not a host probe result.
#[test]
fn doctor_no_target_does_not_claim_target_ready() {
    for explicit_na in [false, true] {
        let mut checks = ready_checks();
        checks.retain(|c| {
            ![
                "target readability",
                "/proc/4242/maps",
                "/proc/4242/mem",
                "scope preflight",
            ]
            .contains(&c.name.as_str())
        });
        if explicit_na {
            checks.push(row(
                "target readability",
                Status::NotApplicable("no --pid".into()),
            ));
            checks.push(row(
                "scope preflight",
                Status::NotApplicable("no requested scope".into()),
            ));
        }
        let text = doctor::render(&checks);
        assert_eq!(doctor::verdict(&checks), 0);
        assert!(
            text.lines().any(|line| line == "Target: unassessed."),
            "{text}"
        );
        assert!(
            text.lines().any(|line| line == "Scope: unassessed."),
            "{text}"
        );
        assert!(
            text.lines()
                .find(|line| line.starts_with("Next: "))
                .unwrap()
                .contains("--pid <PID> or --cgroup <PATH>"),
            "{text}"
        );
        assert!(
            !text.contains("target available") && !text.contains("target ready"),
            "{text}"
        );
    }
    let empty = doctor::render(&[]);
    assert_eq!(doctor::verdict(&[]), 0, "copy must not change exits");
    assert_eq!(
        empty.lines().next(),
        Some("Doctor: no requested lanes assessed.")
    );
    assert!(empty.contains("Target: unassessed.") && empty.contains("Scope: unassessed."));
}

// A readable cgroup directory alone does not prove that scope filtering was
// preflighted. Missing and explicitly unexamined preflight evidence stay unknown.
#[test]
fn doctor_cgroup_path_does_not_replace_scope_preflight() {
    for (preflight, expected_scope, strict_exit) in [
        (None, "Scope: unassessed.", 0),
        (
            Some(Status::NotApplicable("not examined".into())),
            "Scope: unassessed.",
            0,
        ),
        (Some(Status::Ok("available".into())), "Scope: available.", 0),
        (
            Some(Status::Warn("unavailable".into())),
            "Scope: unavailable.",
            1,
        ),
        (
            Some(Status::Fail("unavailable".into())),
            "Scope: unavailable.",
            1,
        ),
    ] {
        let mut checks = ready_checks();
        checks.retain(|check| check.name != "scope preflight");
        checks.push(row("cgroup path", Status::Ok("readable".into())));
        if let Some(status) = preflight {
            checks.push(row("scope preflight", status));
        }
        assert_eq!(doctor::verdict(&checks), 0, "scope preflight is diagnostic");
        assert_eq!(doctor::verdict_extra_strict(&checks), strict_exit);
        for text in [
            doctor::summary(&checks, false),
            doctor::summary(&checks, true),
            doctor::render(&checks),
            doctor::render_extra_strict(&checks),
        ] {
            assert!(text.lines().any(|line| line == expected_scope), "{text}");
        }
    }
}

fn helper() -> PathBuf {
    // Build the workspace helper before running this root-package target.
    // Missing binaries are failures, never zero-coverage skips.
    Path::new(env!("CARGO_BIN_EXE_p11scope")).with_file_name("p11scope-discover")
}

// Catches successful help going to stderr, provider execution being concealed,
// or a manifest being advertised as proof/automatic observer authority.
#[test]
fn helper_help_explains_execution_and_attestation() {
    for flag in ["--help", "-h"] {
        let output = Command::new(helper()).arg(flag).output().unwrap();
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            text.contains("executes provider code in its own helper process"),
            "{text}"
        );
        assert!(text.contains("host ABI"), "{text}");
        assert!(
            text.contains("explicit") && text.contains("--manifest"),
            "{text}"
        );
        assert!(
            text.contains("does not prove application use or semantic attestation"),
            "{text}"
        );
        assert!(
            text.contains("p11scope-discover --module /absolute/provider.so -o manifest.json"),
            "{text}"
        );
        assert!(!text.contains('\u{1b}'));
    }
    let error = Command::new(helper())
        .args(["--module", "relative.so"])
        .output()
        .unwrap();
    assert_eq!(error.status.code(), Some(2));
    assert!(error.stdout.is_empty());
    let error = String::from_utf8(error.stderr).unwrap();
    assert!(error.contains("--module must be an absolute path"));
    assert!(!error.contains("Manifest written"));
}

fn compile(source: &Path, output: &Path, arguments: &[String]) {
    let result = Command::new("cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(output)
        .arg(source)
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

// Catches prose/ANSI contaminating JSON, success notices missing from stderr,
// notices printed despite publication failure, or file/stdout schema drift.
#[test]
fn helper_stdout_remains_manifest_json() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/discover/tests/fixture");
    let dependency = temp.path().join("helper.so");
    let provider = temp.path().join("provider.so");
    compile(
        &fixture.join("helper.c"),
        &dependency,
        &["-Wl,-soname,helper.so".into()],
    );
    compile(
        &fixture.join("provider.c"),
        &provider,
        &[
            dependency.to_string_lossy().into_owned(),
            format!("-Wl,-rpath,{}", temp.path().display()),
        ],
    );
    let stdout = Command::new(helper())
        .arg("--module")
        .arg(&provider)
        .output()
        .unwrap();
    assert_eq!(
        stdout.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&stdout.stderr)
    );
    let manifest: p11scope_discover::manifest::Manifest =
        serde_json::from_slice(&stdout.stdout).unwrap();
    assert_eq!(manifest.schema, "p11scope-manifest/5");
    assert!(!manifest.surfaces.is_empty());
    assert!(!stdout.stdout.contains(&0x1b));
    let notice = String::from_utf8(stdout.stderr).unwrap();
    assert!(
        notice.starts_with("Manifest written to stdout."),
        "{notice}"
    );
    assert!(
        notice.contains("explicit") && notice.contains("--manifest"),
        "{notice}"
    );
    assert!(
        notice.contains("does not prove application use or semantic attestation"),
        "{notice}"
    );

    let destination = temp.path().join("manifest.json");
    let file = Command::new(helper())
        .arg("--module")
        .arg(&provider)
        .arg("-o")
        .arg(&destination)
        .output()
        .unwrap();
    assert_eq!(
        file.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&file.stderr)
    );
    assert!(file.stdout.is_empty());
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&destination).unwrap()).unwrap();
    let piped: serde_json::Value = serde_json::from_slice(&stdout.stdout).unwrap();
    assert_eq!(saved, piped);
    assert!(
        String::from_utf8(file.stderr)
            .unwrap()
            .starts_with("Manifest written to file.")
    );

    let failed = Command::new(helper())
        .arg("--module")
        .arg(&provider)
        .arg("-o")
        .arg(temp.path())
        .output()
        .unwrap();
    assert_eq!(failed.status.code(), Some(1));
    assert!(failed.stdout.is_empty());
    let error = String::from_utf8(failed.stderr).unwrap();
    assert!(error.contains("refusing to replace"), "{error}");
    assert!(!error.contains("Manifest written"), "{error}");
}
