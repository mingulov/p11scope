//! SPDX-License-Identifier: GPL-3.0-or-later
//! `--pause never|auto|always` as an operator sees it, through the same one
//! public facade (`p11scope::run_owned`). The coordinator itself — its clock,
//! its maps, its drains, its owner guard and its injected actions — is
//! crate-private and is never reached from here; these tests only assert the
//! published lattice (design §5.1, §5.6) and the refusal contract.

use p11scope::attach::BackendSelection;
use p11scope::cli::{Kind, PausePolicy, RunArgs};
use p11scope::discovery::hooks::HookRegistry;
use p11scope::run_owned;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

fn work_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("pause-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    if unsafe { libc::geteuid() } == 0 {
        // A root observer demotes its owned child to the invoking user, so
        // the marker leaf must let a non-root child create the marker while
        // the sticky bit keeps other users from unlinking it.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1733)).unwrap();
    }
    dir
}

fn paused_run(pause: PausePolicy, marker: &Path) -> RunArgs {
    RunArgs {
        track_short_lived: false,
        verbose: false,
        quiet: false,
        kind: Kind::Profile,
        modules: Vec::new(),
        exclude_modules: vec![],
        manifests: Vec::new(),
        prearm_modules: Vec::new(),
        hooks: HookRegistry::builtin(),
        metrics: false,
        counter_mode: None,
        select_endpoint: None,
        duration: None,
        out: None,
        max_events: None,
        max_scan_pids: None,
        ring_bytes: None,
        drain_interval: None,
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        pause,
        attach_backend: BackendSelection::default(),
        kill_on_timeout: false,
        verbose: false,
        command: vec![
            "/bin/sh".into(),
            "-c".into(),
            format!("printf ran > {}", marker.display()).into(),
        ],
    }
}

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

/// `pause_confirmed + pause_partial == pause_attempts` and the three-value
/// lattice, for every normally rendered capture (design §5.6).
fn assert_pause_lattice(evidence: &p11scope::render::Evidence) {
    assert_eq!(
        evidence.pause_confirmed + evidence.pause_partial,
        evidence.pause_attempts,
        "pause counters do not add up"
    );
    let expected = if evidence.pause_attempts == 0 {
        "none"
    } else if evidence.pause_partial > 0 {
        "partial"
    } else {
        "sigstop"
    };
    assert_eq!(evidence.pause, expected);
    if evidence.pause_attempts == 0 {
        assert_eq!(evidence.pause_confirmed, 0);
        assert_eq!(evidence.pause_partial, 0);
    }
}

#[test]
fn omitted_pause_is_never_and_publishes_the_neutral_lattice() {
    let dir = work_dir("never");
    let marker = dir.join("ran");
    let omitted = paused_run(PausePolicy::Never, &marker);
    assert_eq!(omitted.pause, PausePolicy::Never, "omission is never");

    match (capture_available(), run_owned(&omitted)) {
        (true, Ok(outcome)) => {
            eprintln!("P11SCOPE_TEST_BRANCH=positive");
            // Nothing this observer started was stopped, and no pause
            // authorization was published.
            assert_eq!(outcome.evidence.pause, "none");
            assert_eq!(outcome.evidence.pause_attempts, 0);
            assert_pause_lattice(&outcome.evidence);
            assert!(marker.exists());
        }
        (false, Err(_)) => {
            eprintln!("P11SCOPE_TEST_BRANCH=unavailable");
            require_capture_positive("omitted_pause_is_never_and_publishes_the_neutral_lattice");
            assert!(!marker.exists(), "a refused run released the child");
        }
        (true, Err(error)) => panic!("capture lane available but run failed: {error:#}"),
        (false, Ok(_)) => panic!("capture lane unavailable but run reported success"),
    }
}

/// `always` never falls back as a successful unpaused run: if arming, request
/// acceptance, confirmation, required attachment, or protected resume cannot be
/// completed, it cleans up and returns a named nonzero failure.
#[test]
fn explicit_always_refuses_rather_than_completing_unpaused() {
    let dir = work_dir("always");
    let marker = dir.join("ran");
    let args = paused_run(PausePolicy::Always, &marker);

    match run_owned(&args) {
        Ok(outcome) => {
            eprintln!("P11SCOPE_TEST_BRANCH=positive");
            // A successful `always` run must be exactly the confirmed lattice —
            // never `none`, never `partial`.
            assert_eq!(outcome.evidence.pause, "sigstop");
            assert!(outcome.evidence.pause_attempts > 0);
            assert_eq!(outcome.evidence.pause_partial, 0);
            assert_eq!(
                outcome.evidence.pause_confirmed,
                outcome.evidence.pause_attempts
            );
            assert_pause_lattice(&outcome.evidence);
        }
        Err(error) => {
            eprintln!("P11SCOPE_TEST_BRANCH=refused");
            let text = format!("{error:#}");
            assert!(!text.contains("panicked"), "{text}");
            assert!(
                text.contains("pause"),
                "an always refusal names pause: {text}"
            );
        }
    }
}

/// `auto` is explicit best effort: an attempt that cannot be confirmed falls
/// back to attach/resume and renders `pause: partial`, which is sticky and
/// forces `PARTIAL` — it is never silently upgraded to `none`.
#[test]
fn explicit_auto_falls_back_to_a_partial_attempt_instead_of_failing() {
    let dir = work_dir("auto");
    let marker = dir.join("ran");
    let args = paused_run(PausePolicy::Auto, &marker);

    match (capture_available(), run_owned(&args)) {
        (true, Ok(outcome)) => {
            eprintln!("P11SCOPE_TEST_BRANCH=positive");
            assert!(
                ["sigstop", "partial"].contains(&outcome.evidence.pause),
                "auto rendered {}",
                outcome.evidence.pause
            );
            assert!(
                outcome.evidence.pause_attempts > 0,
                "auto attempted nothing"
            );
            assert_pause_lattice(&outcome.evidence);
            if outcome.evidence.pause_partial > 0 {
                assert_eq!(outcome.evidence.pause, "partial");
                assert_eq!(outcome.evidence.completeness, "PARTIAL");
            }
            assert!(marker.exists(), "auto must not stop the run from happening");
        }
        (false, Err(_)) => {
            eprintln!("P11SCOPE_TEST_BRANCH=unavailable");
            require_capture_positive(
                "explicit_auto_falls_back_to_a_partial_attempt_instead_of_failing",
            );
            assert!(!marker.exists(), "a refused run released the child");
        }
        (true, Err(error)) => panic!("capture lane available but auto failed: {error:#}"),
        (false, Ok(_)) => panic!("capture lane unavailable but run reported success"),
    }
}

/// Pause is limited to the observer's own owned child: there is no way to ask
/// for it against an external target, and the CLI is where that is enforced.
#[test]
fn no_external_target_can_be_paused() {
    for external in [
        vec!["profile", "--pid", "1", "--pause", "always"],
        vec!["trace", "--cgroup", "/sys/fs/cgroup", "--pause", "auto"],
    ] {
        let parsed = p11scope::cli::parse(external.iter().map(|a| a.to_string()));
        assert!(
            matches!(parsed, Err(p11scope::cli::CliError::Usage { message: m, .. }) if m.contains("`p11scope run`")),
            "{external:?}"
        );
    }
}

/// Static guard: every test in this file that branches on capture
/// availability reads `P11SCOPE_REQUIRE_CAPTURE` through
/// `require_capture_positive`, so the privileged root run cannot pass on
/// the refusal branch. A new dual-outcome test that forgets the call
/// fails here by name.
#[test]
fn every_capture_branch_names_the_require_guard() {
    let path = format!("{}/tests/pause.rs", env!("CARGO_MANIFEST_DIR"));
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
