//! SPDX-License-Identifier: GPL-3.0-or-later
//! Whole-machine (`--system`) scope: select-all semantics with no cgroup
//! path, per-process/module attribution, and cap-driven PARTIAL. All
//! discovery here is unprivileged userspace (`Engine::discover`); no BPF
//! object is loaded.
use p11scope::attach::{BackendSelection, Scope};
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
        attach_backend: BackendSelection::default(),
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
        matches!(parse(argv(&["profile"])), Err(CliError::Usage { message, .. })
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
            matches!(parse(argv(&words)), Err(CliError::Usage { message, .. })
                if message.contains("mutually exclusive")),
            "{words:?}"
        );
        let mut words = vec!["trace", "--system"];
        words.extend(extra);
        assert!(
            matches!(parse(argv(&words)), Err(CliError::Usage { message, .. })
                if message.contains("mutually exclusive")),
            "{words:?}"
        );
    }
    assert!(matches!(
        parse(argv(&["run", "--system", "--", "/bin/true"])),
        Err(CliError::Usage { message, .. }) if message.contains("run has no --pid, --cgroup, or --system")
    ));
}

/// Two independent engines snapshot the machine: the first sees only the
/// first child, and a second engine constructed after the later child
/// starts sees both providers. Same-engine refresh coverage lives in
/// `system_scope_refresh_admits_later_generation_in_same_engine`; this
/// test keeps the provider-module smoke assertions for separate snapshots.
/// No cgroup path is involved anywhere.
#[test]
fn system_scope_separate_snapshots_discover_later_process() {
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

// SYSPLAN Package C (E05): the small multi-user/provider matrix with exact
// private workload identity. Same-user cells (shared inode, copied inode,
// distinct-bytes inode, multiple providers in one process) run everywhere;
// the cross-UID restricted-procfs cell is sudo-gated and skips loudly where
// unauthorized.

/// Fixture variant with distinct bytes but the identical driven surface
/// (`-O2` codegen, same `MATRIX_INTERFACES=0`).
fn build_fixture_variant(dir: &Path, name: &str) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/discover/tests/fixture/version_matrix.c");
    let library = dir.join(format!("{name}.so"));
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-O2", "-DMATRIX_INTERFACES=0", "-o"])
            .arg(&library)
            .arg(source)
            .status()
            .unwrap()
            .success()
    );
    library
}

/// A native child with several providers dlopened (the driver loops over
/// every argument and prints one `done`).
fn spawn_loaded_multi(driver: &Path, providers: &[PathBuf]) -> support::ChildGuard {
    let mut child = support::ChildGuard::new(
        Command::new(driver)
            .arg("dlopen")
            .args(providers)
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

/// Exact private workload identity: the (device major, device minor, inode)
/// triples the workload's own `/proc/<pid>/maps` reports for mappings whose
/// pathname ends with `suffix`. One triple per distinct file backing the
/// name in that process.
fn maps_identities(pid: u32, suffix: &str) -> std::collections::BTreeSet<(u32, u32, u64)> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .unwrap_or_else(|error| panic!("maps for owned pid {pid} must read: {error}"));
    let mut identities = std::collections::BTreeSet::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(_range), Some(_perms), Some(_offset), Some(dev), Some(inode), Some(path)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        if !path.ends_with(suffix) {
            continue;
        }
        let Some((major_hex, minor_hex)) = dev.split_once(':') else {
            continue;
        };
        let (Some(major), Some(minor), Some(inode)) = (
            u32::from_str_radix(major_hex, 16).ok(),
            u32::from_str_radix(minor_hex, 16).ok(),
            inode.parse::<u64>().ok(),
        ) else {
            continue;
        };
        identities.insert((major, minor, inode));
    }
    identities
}

/// Filesystem identity of a fixture path for comparison with maps identity.
fn stat_identity(path: &Path) -> (u32, u32, u64) {
    use std::os::unix::fs::MetadataExt as _;
    let stat = std::fs::metadata(path).unwrap();
    (libc::major(stat.dev()), libc::minor(stat.dev()), stat.ino())
}

/// E05 matrix, same-user cells: two processes share file A, one maps B (A's
/// equal bytes on a distinct inode), one maps C (distinct bytes), one maps A
/// and C together. Discovery admits exactly the three physical providers —
/// shared once, copies never merged — with attachable slots each, and every
/// workload's own maps identity matches the fixture it was given.
#[test]
fn system_scope_provider_matrix_shared_copied_variant_and_multi() {
    let dir = tmp(&format!("system-scope-matrix-{}", std::process::id()));
    let provider_a = build_fixture(&dir, "mx-a");
    let provider_b = dir.join("mx-b.so");
    std::fs::copy(&provider_a, &provider_b).expect("an equal-bytes copy");
    let provider_c = build_fixture_variant(&dir, "mx-c");
    let driver = build_driver(&dir);

    let children = [
        spawn_loaded(&driver, &provider_a),
        spawn_loaded(&driver, &provider_a),
        spawn_loaded(&driver, &provider_b),
        spawn_loaded(&driver, &provider_c),
        spawn_loaded_multi(&driver, &[provider_a.clone(), provider_c.clone()]),
    ];
    let pids: Vec<u32> = children.iter().map(|guard| guard.child.id()).collect();

    // Exact private workload identity from each workload's own mount
    // namespace, before discovery runs. Compared maps-to-maps: on overlayfs
    // the stat device disagrees with the maps device for the same file (only
    // the inode agrees), so stat contributes the inode cross-check while the
    // triples come from the workloads' own mappings — the same
    // maps-consistent source the product pins.
    let inode_a = stat_identity(&provider_a).2;
    let inode_b = stat_identity(&provider_b).2;
    let inode_c = stat_identity(&provider_c).2;
    assert_ne!(inode_a, inode_b, "the copy has its own inode");
    assert_ne!(inode_a, inode_c, "the variant has its own inode");
    let maps_a0 = maps_identities(pids[0], "mx-a.so");
    let maps_a1 = maps_identities(pids[1], "mx-a.so");
    let maps_b = maps_identities(pids[2], "mx-b.so");
    let maps_c = maps_identities(pids[3], "mx-c.so");
    let maps_multi_a = maps_identities(pids[4], "mx-a.so");
    let maps_multi_c = maps_identities(pids[4], "mx-c.so");
    for (label, maps) in [
        ("first A child", &maps_a0),
        ("second A child", &maps_a1),
        ("multi child file A", &maps_multi_a),
    ] {
        assert_eq!(maps.len(), 1, "{label} maps exactly one file for A");
    }
    assert_eq!(maps_a0, maps_a1, "both A children share file A");
    assert_eq!(maps_a0, maps_multi_a, "the multi child shares file A");
    assert_eq!(maps_a0.iter().next().unwrap().2, inode_a);
    assert_eq!(maps_b.len(), 1, "B child maps exactly the copy");
    assert_ne!(
        maps_a0, maps_b,
        "the equal-bytes copy is identity-distinct from A"
    );
    assert_eq!(maps_b.iter().next().unwrap().2, inode_b);
    assert_eq!(maps_c.len(), 1, "C child maps exactly the variant");
    assert_eq!(maps_c, maps_multi_c, "the multi child shares file C");
    assert_ne!(maps_a0, maps_c, "the variant is identity-distinct");
    assert_eq!(maps_c.iter().next().unwrap().2, inode_c);

    let engine = Engine::discover(
        &system_args(vec![provider_a, provider_b, provider_c], None),
        &Scope::System,
        None,
    )
    .unwrap();
    let mut names: Vec<&str> = engine
        .plan()
        .modules
        .iter()
        .map(|module| module.path.rsplit('/').next().unwrap_or_default())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec!["mx-a.so", "mx-b.so", "mx-c.so"],
        "exactly the three physical providers, shared once: {names:?}"
    );
    for name in ["mx-a.so", "mx-b.so", "mx-c.so"] {
        let module_id = engine
            .plan()
            .modules
            .iter()
            .find(|module| module.path.ends_with(name))
            .unwrap_or_else(|| panic!("the plan names {name}"))
            .id;
        let slots = engine
            .plan()
            .slots
            .iter()
            .filter(|slot| slot.module_ids.as_slice() == [module_id])
            .count();
        assert!(slots > 0, "{name} admits attachable slots");
    }
}

/// Whether `sudo -n -u nobody true` succeeds (passwordless, non-interactive).
fn sudo_as_nobody_available() -> bool {
    Command::new("sudo")
        .args(["-n", "-u", "nobody", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// E05/E14 matrix, restricted-procfs cell: a provider workload owned by
/// `nobody` is unscannable across the UID boundary (the kernel denies its
/// maps), so discovery must neither admit its provider from the pathname
/// label nor fail silently: the provider stays absent and the capture
/// carries the explicit discovery-unavailable record. Sudo-gated; skips
/// loudly where unauthorized.
#[test]
fn system_scope_restricted_procfs_cross_uid_cell() {
    if !sudo_as_nobody_available() {
        eprintln!(
            "SKIP system_scope_restricted_procfs_cross_uid_cell: no passwordless sudo for -u nobody"
        );
        return;
    }
    // This cross-UID fixture cannot use the repository's private (0700)
    // TMPDIR: nobody must traverse every parent. Keep its owned directory
    // directly under /var/tmp and let TempDir remove it after the child.
    let dir = tempfile::Builder::new()
        .prefix("sysplan-c-xuid-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let provider = build_fixture(dir.path(), "mx-d");
    let driver = build_driver(dir.path());
    // `nobody` must traverse, read, and execute the fixtures (tempdirs are
    // 0700): the directory and driver take 0755, the provider 0644.
    use std::os::unix::fs::PermissionsExt as _;
    for (path, mode) in [(dir.path(), 0o755), (&provider, 0o644), (&driver, 0o755)] {
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(mode);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    let mut child = support::ChildGuard::new(
        Command::new("sudo")
            .args([
                "-n",
                "-u",
                "nobody",
                "env",
                "P11SCOPE_FIXTURE_INTERFACES=0",
                "P11SCOPE_FIXTURE_POST_GATE=1",
            ])
            .arg(&driver)
            .arg("dlopen")
            .arg(&provider)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    // Readiness uses the driver's marker; the child pid behind sudo is found
    // by command line (sudo forwards stderr, so the marker still arrives).
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
    let nobody_pid = {
        // The driver's own command line starts with its path (sudo's own
        // command line merely contains the needle further along).
        let needle = format!("{} dlopen {}", driver.display(), provider.display());
        let mut found = None;
        for entry in std::fs::read_dir("/proc").unwrap().flatten() {
            let name = entry.file_name();
            let Ok(pid) = name.to_string_lossy().parse::<u32>() else {
                continue;
            };
            let command = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
                .unwrap_or_default()
                .replace('\0', " ");
            if command.starts_with(&needle) {
                found = Some(pid);
                break;
            }
        }
        found.expect("the nobody workload must be visible in /proc")
    };

    // The restriction itself, proven by the kernel: cross-UID maps reads fail.
    let maps_result = std::fs::read_to_string(format!("/proc/{nobody_pid}/maps"));
    assert!(
        maps_result.is_err(),
        "cross-UID maps must be unreadable, proving restriction"
    );
    // Exact private workload identity, read with privilege for comparison.
    let sudo_maps = Command::new("sudo")
        .args([
            "-n",
            "-u",
            "nobody",
            "cat",
            &format!("/proc/{nobody_pid}/maps"),
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(sudo_maps.status.success());
    let maps_text = String::from_utf8_lossy(&sudo_maps.stdout);
    let expected_inode = stat_identity(&provider).2.to_string();
    assert!(
        maps_text
            .lines()
            .any(|line| line.contains("mx-d.so") && line.contains(&expected_inode)),
        "the workload privately maps {expected_inode} for mx-d.so"
    );

    let engine = Engine::discover(&system_args(vec![provider], None), &Scope::System, None)
        .expect("system discovery tolerates an unscannable member");
    assert!(
        !engine
            .plan()
            .modules
            .iter()
            .any(|module| module.path.ends_with("mx-d.so")),
        "pathname labels never authorize discovery: the provider stays absent"
    );
    let unavailable = engine.plan().skipped.iter().any(|skip| {
        let projected = p11scope::render::capture_skipped_out(skip);
        projected.name == "discovery subject" && projected.reason == "discovery unavailable"
    });
    assert!(
        unavailable,
        "restriction carries the explicit discovery-unavailable record: {:?}",
        engine.plan().skipped
    );
}
