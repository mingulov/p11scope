//! `p11scope run` owned-child lifecycle, through the one public production
//! facade the binary uses (`p11scope::run_owned`). The coordinator clocks,
//! maps, drains, guards and injected actions behind it stay crate-private and
//! are deliberately unreachable from here.
//!
//! Every test states the outcome the documented rules require for the observed
//! configuration rather than skipping a precondition it cannot control: on a
//! host where the capture lane is unavailable, `run` must refuse *before* the
//! child crosses its pre-exec barrier, so "the command never ran" is as much a
//! contract as the exit status is where capture works.

use p11scope::cli::{Kind, PausePolicy, RunArgs};
use p11scope::discovery::hooks::HookRegistry;
use p11scope::run_owned;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn work_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("run-lifecycle-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_args(command: &[&str]) -> RunArgs {
    RunArgs {
        kind: Kind::Profile,
        modules: Vec::new(),
        manifests: Vec::new(),
        hooks: HookRegistry::builtin(),
        metrics: false,
        duration: None,
        out: None,
        unsafe_requested: false,
        pause: PausePolicy::Never,
        kill_on_timeout: false,
        command: command.iter().map(|a| a.to_string()).collect(),
    }
}

/// Whether this host and these privileges allow the capture lane at all —
/// asked with the observer's own doctor rather than a second copy of the rule.
fn capture_available() -> bool {
    p11scope::doctor::verdict(&p11scope::doctor::probe(None, None)) == 0
}

/// A refusal is a refusal: the named failure must not have released the child.
fn refused_before_the_barrier(error: &anyhow::Error, marker: &Path) {
    let text = format!("{error:#}");
    assert!(!text.is_empty(), "a refusal must name its cause");
    assert!(!text.contains("panicked"), "{text}");
    assert!(
        !marker.exists(),
        "a refused run released the child anyway: {text}"
    );
}

fn wait_until_gone(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Path::new(&format!("/proc/{pid}")).exists() {
        assert!(
            Instant::now() < deadline,
            "owned child {pid} outlived its run"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn an_owned_run_reports_the_exact_child_status_and_reaps_it() {
    let dir = work_dir("status");
    let marker = dir.join("ran");
    let args = run_args(&[
        "/bin/sh",
        "-c",
        &format!("printf ran > {}; exit 23", marker.display()),
    ]);

    match (capture_available(), run_owned(&args)) {
        (true, Ok(outcome)) => {
            assert_eq!(outcome.child_exit_code, Some(23));
            assert!(!outcome.child_still_running);
            assert!(marker.exists(), "the observed command never ran");
            // The child ended inside the run: nothing is left to reap, and the
            // evidence says so rather than leaving the field to be guessed.
            assert!(!outcome.evidence.child_still_running.unwrap_or(true));
        }
        (false, Err(error)) => refused_before_the_barrier(&error, &marker),
        (true, Err(error)) => panic!("capture lane available but run failed: {error:#}"),
        (false, Ok(_)) => panic!("capture lane unavailable but run reported success"),
    }
}

#[test]
fn a_signalled_child_reports_the_signal_status_the_shell_would() {
    let dir = work_dir("signal");
    let marker = dir.join("ran");
    let args = run_args(&[
        "/bin/sh",
        "-c",
        &format!("printf ran > {}; kill -TERM $$", marker.display()),
    ]);

    match (capture_available(), run_owned(&args)) {
        (true, Ok(outcome)) => {
            assert_eq!(outcome.child_exit_code, Some(128 + libc::SIGTERM));
            assert!(!outcome.child_still_running);
        }
        (false, Err(error)) => refused_before_the_barrier(&error, &marker),
        (true, Err(error)) => panic!("capture lane available but run failed: {error:#}"),
        (false, Ok(_)) => panic!("capture lane unavailable but run reported success"),
    }
}

#[test]
fn duration_expiry_hands_back_a_running_child_unless_kill_on_timeout_was_asked_for() {
    let dir = work_dir("duration");
    let marker = dir.join("ran");
    let mut handed_back = run_args(&[
        "/bin/sh",
        "-c",
        &format!("printf ran > {}; exec /bin/sleep 30", marker.display()),
    ]);
    handed_back.duration = Some(Duration::from_secs(1));

    match (capture_available(), run_owned(&handed_back)) {
        (true, Ok(outcome)) => {
            // An expired duration is not a reason to kill someone else's work.
            assert_eq!(outcome.child_exit_code, None);
            assert!(outcome.child_still_running);
            assert_eq!(outcome.evidence.child_still_running, Some(true));
            // A handed-back child is still someone's problem: `run` must name
            // it, or the operator cannot find what it left running.
            assert!(Path::new(&format!("/proc/{}", outcome.child_pid)).exists());
            unsafe { libc::kill(-(outcome.child_pid as libc::pid_t), libc::SIGKILL) };
        }
        (false, Err(error)) => refused_before_the_barrier(&error, &marker),
        (true, Err(error)) => panic!("capture lane available but run failed: {error:#}"),
        (false, Ok(_)) => panic!("capture lane unavailable but run reported success"),
    }

    let mut killed = handed_back.clone();
    killed.kill_on_timeout = true;
    match (capture_available(), run_owned(&killed)) {
        (true, Ok(outcome)) => {
            assert_eq!(outcome.child_exit_code, Some(128 + libc::SIGTERM));
            assert!(!outcome.child_still_running);
            assert_eq!(outcome.evidence.child_still_running, Some(false));
            wait_until_gone(outcome.child_pid);
        }
        (false, Err(error)) => refused_before_the_barrier(&error, &marker),
        (true, Err(error)) => panic!("capture lane available but run failed: {error:#}"),
        (false, Ok(_)) => panic!("capture lane unavailable but run reported success"),
    }
}

#[test]
fn a_command_that_cannot_execute_fails_by_name_and_leaves_nothing_behind() {
    let dir = work_dir("exec");
    let marker = dir.join("ran");
    let args = run_args(&["/definitely/missing/p11scope-run-facade"]);

    let error = run_owned(&args).expect_err("a missing command must fail");
    let text = format!("{error:#}");
    assert!(!text.contains("panicked"), "{text}");
    assert!(!marker.exists());
    // The exec failure is its own finite category, not a generic runtime error
    // and not a silent capture with no target.
    assert!(text.contains("exec"), "{text}");
}

/// `child_still_running` is the one run-only evidence field: it exists in a
/// `run` document and must not appear in a `--pid`/`--cgroup` capture.
#[test]
fn the_run_only_evidence_field_reaches_the_written_document() {
    let dir = work_dir("document");
    let marker = dir.join("ran");
    let out = dir.join("run.json");
    let mut args = run_args(&[
        "/bin/sh",
        "-c",
        &format!("printf ran > {}", marker.display()),
    ]);
    args.out = Some(out.clone());

    match (capture_available(), run_owned(&args)) {
        (true, Ok(_)) => {
            let document: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
            let evidence = &document["evidence"];
            assert_eq!(evidence["child_still_running"], serde_json::json!(false));
            for field in [
                "attach_gap_ms",
                "pause",
                "pause_attempts",
                "pause_confirmed",
                "pause_partial",
                "discovery_ring_loss",
                "discovery_state_failures",
                "discovery_read_failures",
                "discovery_truncated",
                "loader_discovery",
            ] {
                assert!(
                    evidence.get(field).is_some(),
                    "{field} missing from run evidence"
                );
            }
        }
        (false, Err(error)) => refused_before_the_barrier(&error, &marker),
        (true, Err(error)) => panic!("capture lane available but run failed: {error:#}"),
        (false, Ok(_)) => panic!("capture lane unavailable but run reported success"),
    }
}
