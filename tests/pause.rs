//! `--pause never|auto|always` as an operator sees it, through the same one
//! public facade (`p11scope::run_owned`). The coordinator itself — its clock,
//! its maps, its drains, its owner guard and its injected actions — is
//! crate-private and is never reached from here; these tests only assert the
//! published lattice (design §5.1, §5.6) and the refusal contract.

use p11scope::cli::{Kind, PausePolicy, RunArgs};
use p11scope::discovery::hooks::HookRegistry;
use p11scope::run_owned;
use std::path::{Path, PathBuf};

fn work_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("pause-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn paused_run(pause: PausePolicy, marker: &Path) -> RunArgs {
    RunArgs {
        kind: Kind::Profile,
        modules: Vec::new(),
        manifests: Vec::new(),
        hooks: HookRegistry::builtin(),
        metrics: false,
        duration: None,
        out: None,
        unsafe_requested: false,
        pause,
        kill_on_timeout: false,
        command: vec![
            "/bin/sh".into(),
            "-c".into(),
            format!("printf ran > {}", marker.display()),
        ],
    }
}

fn capture_available() -> bool {
    p11scope::doctor::verdict(&p11scope::doctor::probe(None, None)) == 0
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
            // Nothing this observer started was stopped, and no pause
            // authorization was published.
            assert_eq!(outcome.evidence.pause, "none");
            assert_eq!(outcome.evidence.pause_attempts, 0);
            assert_pause_lattice(&outcome.evidence);
            assert!(marker.exists());
        }
        (false, Err(_)) => assert!(!marker.exists(), "a refused run released the child"),
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
        (false, Err(_)) => assert!(!marker.exists(), "a refused run released the child"),
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
            matches!(parsed, Err(p11scope::cli::CliError::Usage(m)) if m.contains("`p11scope run`")),
            "{external:?}"
        );
    }
}
