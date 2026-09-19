//! SPDX-License-Identifier: GPL-3.0-or-later
//! Whole-machine (`--system`) scope: select-all semantics with no cgroup
//! path, per-process/module attribution, and cap-driven PARTIAL. All
//! discovery here is unprivileged userspace (`Engine::discover`); no BPF
//! object is loaded.
use p11scope::attach::Scope;
use p11scope::cli::{CaptureArgs, CliError, Kind, ScopeArg, parse};
use p11scope::discovery::engine::Engine;
use p11scope::discovery::hooks::HookRegistry;
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[allow(dead_code)]
mod support;

fn tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn build_fixture(dir: &Path, name: &str) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/discover/tests/fixture/version_matrix.c");
    let library = dir.join(format!("{name}.so"));
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-DMATRIX_INTERFACES=0", "-o"])
            .arg(&library)
            .arg(source)
            .status()
            .unwrap()
            .success()
    );
    library
}

fn build_driver(dir: &Path) -> PathBuf {
    let driver = dir.join("driver");
    assert!(
        Command::new("gcc")
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-o"])
            .arg(&driver)
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/live-discovery-driver.c")
            )
            .args(["-ldl", "-pthread"])
            .status()
            .unwrap()
            .success()
    );
    driver
}

/// A native child with one provider dlopened, held until the guard drops.
fn spawn_loaded(driver: &Path, provider: &Path) -> support::ChildGuard {
    let mut child = support::ChildGuard::new(
        Command::new(driver)
            .arg("dlopen")
            .arg(provider)
            .env_clear()
            .env("P11SCOPE_FIXTURE_INTERFACES", "0")
            .env("P11SCOPE_FIXTURE_POST_GATE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut stderr = child.child.stderr.take().unwrap();
    let mut readiness = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !readiness.ends_with(b"P11SCOPE_FIXTURE driver done\n") {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero() && readiness.len() < 4096);
        assert!(support::poll_fd(stderr.as_raw_fd(), remaining).unwrap());
        let mut byte = [0];
        assert_eq!(
            stderr.read(&mut byte).unwrap(),
            1,
            "fixture exited before ready"
        );
        readiness.extend_from_slice(&byte);
    }
    child
}

fn system_args(hints: Vec<PathBuf>, max_scan_pids: Option<usize>) -> CaptureArgs {
    CaptureArgs {
        kind: Kind::Profile,
        modules: hints,
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: ScopeArg::System,
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        max_scan_pids,
        ring_bytes: None,
        drain_interval: None,
        unsafe_requested: false,
        allow_confined_uretprobe: false,
    }
}

fn argv(words: &[&str]) -> std::vec::IntoIter<String> {
    words
        .iter()
        .map(|word| word.to_string())
        .collect::<Vec<_>>()
        .into_iter()
}

#[test]
fn system_scope_parses_for_profile_and_trace() {
    let p11scope::cli::Command::Profile(profile) = parse(argv(&["profile", "--system"])).unwrap()
    else {
        panic!("expected profile")
    };
    assert_eq!(profile.scope, ScopeArg::System);
    let p11scope::cli::Command::Trace(trace) =
        parse(argv(&["trace", "--system", "--duration", "5"])).unwrap()
    else {
        panic!("expected trace")
    };
    assert_eq!(trace.scope, ScopeArg::System);
    assert!(p11scope::cli::USAGE.contains("--system"));
    assert!(
        p11scope::cli::HelpTopic::Profile
            .text()
            .contains("--system")
    );
}

#[test]
fn system_scope_is_one_of_three_and_mutually_exclusive() {
    assert!(
        matches!(parse(argv(&["profile"])), Err(CliError::Usage(message))
            if message.contains("exactly one of --pid, --cgroup, or --system"))
    );
    for extra in [
        vec!["--pid", "1"],
        vec!["--cgroup", "/sys/fs/cgroup/x"],
        vec!["--pid", "1", "--cgroup", "/sys/fs/cgroup/x"],
    ] {
        let mut words = vec!["profile", "--system"];
        words.extend(extra.clone());
        assert!(
            matches!(parse(argv(&words)), Err(CliError::Usage(message))
                if message.contains("mutually exclusive")),
            "{words:?}"
        );
        let mut words = vec!["trace", "--system"];
        words.extend(extra);
        assert!(
            matches!(parse(argv(&words)), Err(CliError::Usage(message))
                if message.contains("mutually exclusive")),
            "{words:?}"
        );
    }
    assert!(matches!(
        parse(argv(&["run", "--system", "--", "/bin/true"])),
        Err(CliError::Usage(message)) if message.contains("run has no --pid or --cgroup")
    ));
}

/// Two children loading distinct providers are both discovered and
/// attributed to their own modules; a child spawned after the first pass is
/// picked up by the next sweep. No cgroup path is involved anywhere.
#[test]
fn system_scope_observes_two_processes_and_picks_up_a_new_child() {
    let dir = tmp(&format!("system-scope-two-proc-{}", std::process::id()));
    let first = build_fixture(&dir, "system-first");
    let second = build_fixture(&dir, "system-second");
    let driver = build_driver(&dir);

    let _child_a = spawn_loaded(&driver, &first);
    let engine = Engine::discover(
        &system_args(vec![first.clone(), second.clone()], None),
        &Scope::System,
        None,
    )
    .unwrap();
    let paths: Vec<&str> = engine
        .discovery()
        .modules
        .iter()
        .map(|module| module.path.as_str())
        .collect();
    assert!(
        paths.iter().any(|path| path.ends_with("system-first.so")),
        "first child must be discovered: {paths:?}"
    );
    assert!(
        !paths.iter().any(|path| path.ends_with("system-second.so")),
        "nothing maps the second provider yet: {paths:?}"
    );

    let _child_b = spawn_loaded(&driver, &second);
    let engine = Engine::discover(
        &system_args(vec![first.clone(), second.clone()], None),
        &Scope::System,
        None,
    )
    .unwrap();
    let paths: Vec<&str> = engine
        .discovery()
        .modules
        .iter()
        .map(|module| module.path.as_str())
        .collect();
    assert!(
        paths.iter().any(|path| path.ends_with("system-first.so")),
        "{paths:?}"
    );
    assert!(
        paths.iter().any(|path| path.ends_with("system-second.so")),
        "the new child must be picked up: {paths:?}"
    );
    assert!(
        engine.plan().slots.len() >= 60,
        "both providers contribute attachable slots"
    );
    assert_eq!(engine.plan().modules.len(), 2);
}

/// A one-process scan cap on a multi-process machine records the bound as a
/// plan skip, which `Evidence::verdict` turns into PARTIAL.
#[test]
fn system_scope_over_the_scan_cap_records_the_bound() {
    let dir = tmp(&format!("system-scope-cap-{}", std::process::id()));
    let provider = build_fixture(&dir, "system-capped");
    let driver = build_driver(&dir);
    let _child = spawn_loaded(&driver, &provider);

    let engine = Engine::discover(
        &system_args(vec![provider.clone()], Some(1)),
        &Scope::System,
        None,
    )
    .unwrap();
    let cap = engine.plan().skipped.iter().find(|skip| {
        skip.subject == "system"
            && skip.reason.contains("selected 1 for deep scanning")
            && skip.reason.contains("by provider rarity")
    });
    assert!(
        cap.is_some(),
        "the scan cap must be published as a plan skip: {:?}",
        engine.plan().skipped
    );
}
