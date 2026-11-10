//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
use std::path::Path;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_p11scope-discover");
const SOFTHSM: &str = "/usr/lib/softhsm/libsofthsm2.so";

#[test]
fn manifest_json_on_stdout() {
    if !Path::new(SOFTHSM).exists() {
        eprintln!("SKIP: {SOFTHSM} not present");
        return;
    }
    let out = Command::new(BIN)
        .args(["--module", SOFTHSM])
        .output()
        .unwrap();
    assert!(out.status.success());
    let m: p11scope_discover::manifest::Manifest = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(m.schema, "p11scope-manifest/5");
    assert_eq!(m.surfaces[0].functions.len(), 68);
}

#[test]
fn version_prints_the_release_version_and_exits_zero() {
    for flag in ["--version", "-V"] {
        let out = Command::new(BIN).arg(flag).output().unwrap();
        assert_eq!(out.status.code(), Some(0), "{flag}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("p11scope-discover {}\n", env!("CARGO_PKG_VERSION")),
            "{flag}"
        );
        assert!(out.stderr.is_empty(), "{flag}: {:?}", out.stderr);
    }
}

#[test]
fn version_takes_no_arguments() {
    let out = Command::new(BIN)
        .args(["--version", "--module", SOFTHSM])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--version takes no arguments"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The helper ships beside the observer, so both report one release version.
#[test]
fn helper_version_matches_the_observer_version() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let manifest = std::fs::read_to_string(&root).unwrap();
    let package = manifest
        .split("\n[")
        .find(|section| section.starts_with("[package]") || section.starts_with("package]"))
        .expect("root manifest has a [package] section");
    let version = package
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == "version").then(|| value.trim().trim_matches('"').to_string())
        })
        .expect("root [package] declares a version");
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn missing_module_is_usage_error() {
    let out = Command::new(BIN).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage"));
}

#[test]
fn relative_module_is_rejected_before_dlopen() {
    let out = Command::new(BIN)
        .args(["--module", "provider.so"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--module must be an absolute path"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn non_object_module_is_refused_before_dlopen() {
    let out = Command::new(BIN)
        .args(["--module", "/dev/null"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not a regular file"), "{stderr}");
}

#[test]
fn o_writes_manifest_file() {
    if !Path::new(SOFTHSM).exists() {
        eprintln!("SKIP: {SOFTHSM} not present");
        return;
    }
    let tmpdir = env!("CARGO_TARGET_TMPDIR");
    let outfile = format!("{tmpdir}/manifest-test.json");
    let out = Command::new(BIN)
        .args(["--module", SOFTHSM, "-o", &outfile])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).is_empty());
    assert!(Path::new(&outfile).exists());
    let contents = std::fs::read(&outfile).unwrap();
    let m: p11scope_discover::manifest::Manifest = serde_json::from_slice(&contents).unwrap();
    assert_eq!(m.schema, "p11scope-manifest/5");
}

#[test]
fn o_missing_value_is_usage_error() {
    let out = Command::new(BIN)
        .args(["--module", "/dev/null", "-o"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("-o requires a value"));
}

#[test]
fn control_fd_flag_is_gone() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_p11scope-discover"))
        .args(["--control-fd", "3", "--module", "/nonexistent.so"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown argument: --control-fd"));
}

#[test]
fn o_write_failure_exits_1() {
    if !Path::new(SOFTHSM).exists() {
        eprintln!("SKIP: {SOFTHSM} not present");
        return;
    }
    let out = Command::new(BIN)
        .args(["--module", SOFTHSM, "-o", "/nonexistent-dir/m.json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("write"));
}

#[test]
fn constructor_sees_no_planted_fd_or_loader_env() {
    use std::io::Read as _;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fd-canary");
    std::fs::create_dir_all(&dir).unwrap();
    let provider = dir.join("fd-env-canary.so");
    let dependency = dir.join("fd-env-dependency.so");
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture/fd_env_canary.c");
    assert!(
        Command::new("gcc")
            .arg(format!("-m{}", usize::BITS))
            .args(["-shared", "-fPIC", "-o"])
            .arg(&provider)
            .arg(&src)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("gcc")
            .arg(format!("-m{}", usize::BITS))
            .args(["-shared", "-fPIC", "-DDEPENDENCY", "-o"])
            .arg(&dependency)
            .arg(&src)
            .status()
            .unwrap()
            .success()
    );

    let (mut reader, writer) = std::io::pipe().unwrap();
    let raw = writer.as_raw_fd();
    let mut cmd = Command::new(BIN);
    cmd.arg("--module")
        .arg(&provider)
        .env("LD_LIBRARY_PATH", &dir)
        .env("LD_PRELOAD", &dependency)
        .stderr(std::process::Stdio::piped());
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(raw, 17) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    drop(writer);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("CANARY_FD=closed"),
        "planted fd survived: {stderr}"
    );
    assert!(
        stderr.contains("CANARY_SEARCH=absent"),
        "LD_LIBRARY_PATH survived: {stderr}"
    );
    assert!(
        stderr.contains("CANARY_PRELOAD=absent"),
        "LD_PRELOAD survived: {stderr}"
    );
    let mut leaked = Vec::new();
    reader.read_to_end(&mut leaked).unwrap();
    assert!(
        leaked.is_empty(),
        "constructor wrote through planted fd: {leaked:?}"
    );

    let forged = Command::new(BIN)
        .arg("--module")
        .arg(&provider)
        .env("P11SCOPE_LOADER_ENV_SANITIZED", "forged")
        .env("LD_LIBRARY_PATH", &dir)
        .output()
        .unwrap();
    assert_eq!(forged.status.code(), Some(1));
    let forged_stderr = String::from_utf8_lossy(&forged.stderr);
    assert!(
        forged_stderr.contains("loader environment sanitization failed"),
        "forged marker was accepted: {forged_stderr}"
    );
    assert!(
        !forged_stderr.contains("CANARY_"),
        "provider loaded before forged marker refusal: {forged_stderr}"
    );
}

/// A fresh private directory under the cargo test scratch root.
fn scratch(name: &str) -> std::path::PathBuf {
    scratch_in(Path::new(env!("CARGO_TARGET_TMPDIR")), name)
}

/// Scratch root for the btrfs-gated cell: `$P11SCOPE_DISCOVER_BTRFS_SCRATCH`
/// when set to a non-empty directory (a provisioned btrfs mount), else
/// the cargo test scratch root.
fn btrfs_scratch_root() -> std::path::PathBuf {
    std::env::var_os("P11SCOPE_DISCOVER_BTRFS_SCRATCH")
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_TARGET_TMPDIR")).to_path_buf())
}

/// The deterministic [`scratch_in`] path without filesystem effects, so
/// the twin chain can compare candidates before creating them.
fn scratch_in_path(root: &Path, name: &str) -> std::path::PathBuf {
    root.join(format!("discover-{name}-{}", std::process::id()))
}

/// A fresh private directory under `root` (the btrfs-gated cell passes
/// its provisioned mount here; every other test uses [`scratch`]).
fn scratch_in(root: &Path, name: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = scratch_in_path(root, name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn discover_to(out: &Path) -> std::process::Output {
    Command::new(BIN)
        .args(["--module", SOFTHSM, "-o"])
        .arg(out)
        .output()
        .unwrap()
}

fn litter(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with('.'))
        .collect()
}

/// F-56: `-o` never follows a symlink at the output name — dangling or
/// not — and leaves it and its target exactly as they were.
#[test]
fn o_refuses_a_symlink_at_the_output_name() {
    if !Path::new(SOFTHSM).exists() {
        eprintln!("SKIP: {SOFTHSM} not present");
        return;
    }
    let dir = scratch("symlink");
    let target = dir.join("target.json");
    let dangling = dir.join("dangling.json");
    std::os::unix::fs::symlink(&target, &dangling).unwrap();
    let out = discover_to(&dangling);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(
        std::fs::symlink_metadata(&dangling)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(!target.exists(), "the write followed the dangling symlink");

    std::fs::write(&target, b"keep").unwrap();
    let pointing = dir.join("pointing.json");
    std::os::unix::fs::symlink(&target, &pointing).unwrap();
    let out = discover_to(&pointing);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("symbolic link"));
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    assert_eq!(litter(&dir), Vec::<String>::new());
}

/// F-56: the manifest is published private (0600) whatever the umask, and
/// atomically: an existing regular file is replaced whole, nothing is left
/// behind beside it.
#[test]
fn o_publishes_a_private_file_atomically() {
    use std::os::unix::fs::PermissionsExt as _;
    if !Path::new(SOFTHSM).exists() {
        eprintln!("SKIP: {SOFTHSM} not present");
        return;
    }
    let dir = scratch("private");
    let fresh = dir.join("fresh.json");
    let out = discover_to(&fresh);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let stale = dir.join("stale.json");
    std::fs::write(&stale, b"stale").unwrap();
    std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = discover_to(&stale);
    assert!(out.status.success(), "{out:?}");
    let m: p11scope_discover::manifest::Manifest =
        serde_json::from_slice(&std::fs::read(&stale).unwrap()).unwrap();
    assert_eq!(m.schema, "p11scope-manifest/5");
    assert_eq!(
        std::fs::metadata(&stale).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(litter(&dir), Vec::<String>::new());
}

/// Build the isolation probe provider and its lazy backend in a fresh
/// scratch directory. The backend is resolved by the probe's getter via
/// `$ORIGIN`, never through `DT_NEEDED`.
fn build_isolation_probe(dir: &Path) -> std::path::PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture");
    let backend = dir.join("isolation-backend.so");
    let provider = dir.join("isolation-probe.so");
    assert!(
        Command::new("gcc")
            .arg(format!("-m{}", usize::BITS))
            .args(["-shared", "-fPIC", "-o"])
            .arg(&backend)
            .arg(source.join("isolation_backend.c"))
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("gcc")
            .arg(format!("-m{}", usize::BITS))
            .args(["-shared", "-fPIC", "-o"])
            .arg(&provider)
            .arg(source.join("isolation_probe.c"))
            .arg("-ldl")
            .arg("-Wl,-rpath,$ORIGIN")
            .status()
            .unwrap()
            .success()
    );
    let dynamic = Command::new("readelf")
        .args(["-d"])
        .arg(&provider)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    assert!(
        !String::from_utf8_lossy(&dynamic.stdout).contains("isolation-backend"),
        "backend must be acquired lazily, not through DT_NEEDED"
    );
    provider
}

fn build_isolation_needy(dir: &Path) -> std::path::PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture");
    let provider = dir.join("isolation-needy.so");
    assert!(
        Command::new("gcc")
            .arg(format!("-m{}", usize::BITS))
            .args(["-shared", "-fPIC", "-o"])
            .arg(&provider)
            .arg(source.join("isolation_needy.c"))
            .status()
            .unwrap()
            .success()
    );
    provider
}

fn build_isolation_select_needy(dir: &Path) -> std::path::PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture");
    let provider = dir.join("isolation-select-needy.so");
    assert!(
        Command::new("gcc")
            .arg(format!("-m{}", usize::BITS))
            .args(["-shared", "-fPIC", "-o"])
            .arg(&provider)
            .arg(source.join("isolation_select_needy.c"))
            .status()
            .unwrap()
            .success()
    );
    provider
}

/// A repeated `--isolation` refuses instead of silently taking the last.
#[test]
fn isolation_repeated_flag_is_usage_error() {
    let out = Command::new(BIN)
        .args([
            "--isolation",
            "trusted",
            "--isolation",
            "isolated",
            "--module",
            "/dev/null",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--isolation may be given only once"),
        "{stderr}"
    );
}

/// R1: only the two named profiles exist.
#[test]
fn isolation_unknown_profile_is_usage_error() {
    let out = Command::new(BIN)
        .args(["--isolation", "bogus", "--module", "/dev/null"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--isolation must be trusted or isolated"),
        "{stderr}"
    );
}

/// The isolated fence is active before provider code runs: the probe
/// constructor's socket creation and file write are both denied, while the
/// healthy sparse provider still discovers fully.
#[test]
fn isolation_constructor_access_is_enforced_before_provider_load() {
    use p11scope_discover::manifest::{Acquisition, Resolution, WalkOutcome};
    let dir = scratch("isolation-enforced");
    let provider = build_isolation_probe(&dir);
    let out = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ISOLATION_SOCKET=denied(errno=13)"),
        "socket creation was not fenced: {stderr}"
    );
    assert!(
        stderr.contains("ISOLATION_WRITE=denied(errno=13)"),
        "file write was not fenced: {stderr}"
    );
    let m: p11scope_discover::manifest::Manifest = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(m.schema, "p11scope-manifest/5");
    let legacy = &m.surfaces[0];
    assert!(matches!(legacy.acquisition, Acquisition::Ok));
    assert!(matches!(legacy.walk, WalkOutcome::Full));
    assert_eq!(legacy.functions.len(), 68);
    let nulls = legacy
        .functions
        .iter()
        .filter(|f| matches!(f.resolution, Resolution::NullPointer))
        .count();
    assert_eq!(nulls, 3, "the sparse NULLs must survive the fence");
    assert!(
        m.provenance_objects
            .iter()
            .any(|object| object.path.ends_with("isolation-backend.so")),
        "the lazy backend must load under the fence"
    );
}

/// Twin: a healthy sparse/all-NULL/lazy provider discovers byte-identically
/// with and without the fence; the fence changes nothing it need not.
#[test]
fn isolation_healthy_sparse_lazy_provider_matches_trusted() {
    use p11scope_discover::manifest::{Acquisition, WalkOutcome};
    let dir = scratch("isolation-twin");
    let provider = build_isolation_probe(&dir);
    let run = |extra: &[&str]| {
        let mut args: Vec<&std::ffi::OsStr> = extra.iter().map(std::ffi::OsStr::new).collect();
        args.push(std::ffi::OsStr::new("--module"));
        args.push(provider.as_os_str());
        Command::new(BIN).args(&args).output().unwrap()
    };
    let default = run(&[]);
    let trusted = run(&["--isolation", "trusted"]);
    let isolated = run(&["--isolation", "isolated"]);
    for (name, out) in [
        ("default", &default),
        ("trusted", &trusted),
        ("isolated", &isolated),
    ] {
        assert_eq!(out.status.code(), Some(0), "{name}: {out:?}");
    }
    assert_eq!(
        default.stdout, trusted.stdout,
        "explicit trusted differs from default"
    );
    assert_eq!(
        default.stdout, isolated.stdout,
        "the fence changed a healthy provider's manifest"
    );
    for (name, out) in [("default", &default), ("trusted", &trusted)] {
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("ISOLATION_SOCKET=allowed"),
            "{name}: {stderr}"
        );
        assert!(
            stderr.contains("ISOLATION_WRITE=allowed"),
            "{name}: {stderr}"
        );
    }
    let m: p11scope_discover::manifest::Manifest =
        serde_json::from_slice(&isolated.stdout).unwrap();
    assert_eq!(m.surfaces.len(), 2);
    assert!(matches!(m.interface_list, Acquisition::Ok));
    let null_surface = &m.surfaces[1];
    assert!(matches!(null_surface.acquisition, Acquisition::Ok));
    assert!(null_surface.version.is_none());
    assert!(matches!(null_surface.walk, WalkOutcome::NotWalked));
    assert!(null_surface.functions.is_empty());
    assert!(
        m.objects.iter().any(|object| {
            object.path.ends_with("isolation-backend.so") && object.identity.reusable
        }),
        "the lazy backend must get its own reusable object identity"
    );
}

/// R8: a getter that needs a denied socket fails plainly. Trusted walks its
/// table; isolated records the acquisition error in the manifest and names
/// the profile on stderr. Neither hides nor crashes.
#[test]
fn isolation_socket_needy_getter_is_recorded_not_hidden() {
    use p11scope_discover::manifest::{Acquisition, WalkOutcome};
    let dir = scratch("isolation-needy");
    let provider = build_isolation_needy(&dir);
    let trusted = Command::new(BIN)
        .args(["--module"])
        .arg(&provider)
        .output()
        .unwrap();
    assert_eq!(trusted.status.code(), Some(0), "{trusted:?}");
    let m: p11scope_discover::manifest::Manifest = serde_json::from_slice(&trusted.stdout).unwrap();
    assert!(matches!(m.surfaces[0].acquisition, Acquisition::Ok));
    assert!(matches!(m.surfaces[0].walk, WalkOutcome::Full));
    assert_eq!(m.surfaces[0].functions.len(), 68);

    let isolated = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .output()
        .unwrap();
    assert_eq!(isolated.status.code(), Some(0), "{isolated:?}");
    let m: p11scope_discover::manifest::Manifest =
        serde_json::from_slice(&isolated.stdout).unwrap();
    match &m.surfaces[0].acquisition {
        Acquisition::Error { detail } => assert!(
            detail.contains("C_GetFunctionList returned 0x00000030"),
            "{detail}"
        ),
        other => panic!("a denied getter must record its error, got {other:?}"),
    }
    let stderr = String::from_utf8_lossy(&isolated.stderr);
    assert!(
        stderr.contains("isolated profile: C_GetFunctionList failed"),
        "{stderr}"
    );
}

/// R8 for `C_GetInterface`: a getter that needs a denied socket records
/// each selection failure per query (the rv, no result) under the fence
/// and full results when trusted. Exit 0 in both: recorded in the
/// manifest, never hidden and never a crash.
#[test]
fn isolation_select_needy_getter_is_recorded_per_query() {
    use p11scope_discover::manifest::SelectionAcquisition;
    let dir = scratch("isolation-select-needy");
    let provider = build_isolation_select_needy(&dir);
    let trusted = Command::new(BIN)
        .args(["--module"])
        .arg(&provider)
        .output()
        .unwrap();
    assert_eq!(trusted.status.code(), Some(0), "{trusted:?}");
    let tm: p11scope_discover::manifest::Manifest =
        serde_json::from_slice(&trusted.stdout).unwrap();
    assert!(matches!(
        tm.selection_evidence.acquisition,
        SelectionAcquisition::Queried
    ));
    assert!(
        !tm.selection_evidence.queries.is_empty(),
        "trusted must run selection queries"
    );
    for query in &tm.selection_evidence.queries {
        assert_eq!(query.rv, 0, "trusted query {} must succeed", query.selector);
        assert!(
            query.result.is_some(),
            "trusted query {} must record its result",
            query.selector
        );
    }

    let isolated = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .output()
        .unwrap();
    assert_eq!(isolated.status.code(), Some(0), "{isolated:?}");
    let m: p11scope_discover::manifest::Manifest =
        serde_json::from_slice(&isolated.stdout).unwrap();
    assert!(matches!(
        m.selection_evidence.acquisition,
        SelectionAcquisition::Queried
    ));
    assert_eq!(
        m.selection_evidence.queries.len(),
        tm.selection_evidence.queries.len(),
        "the fence must not drop queries"
    );
    for query in &m.selection_evidence.queries {
        assert_eq!(
            query.rv, 0x30,
            "isolated query {} must record the device error",
            query.selector
        );
        assert!(
            query.result.is_none(),
            "isolated query {} must record no result",
            query.selector
        );
    }
}

/// The `-o` parent directory stays writable under the fence (private
/// atomic publish), and an unusable one refuses before provider load: no
/// constructor marker may appear.
#[test]
fn isolation_o_writes_through_the_fenced_output_directory() {
    use std::os::unix::fs::PermissionsExt as _;
    let provider_dir = scratch("isolation-o-provider");
    let out_dir = scratch("isolation-o-out");
    let provider = build_isolation_probe(&provider_dir);
    let outfile = out_dir.join("manifest.json");
    let out = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .args(["-o"])
        .arg(&outfile)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).is_empty());
    let m: p11scope_discover::manifest::Manifest =
        serde_json::from_slice(&std::fs::read(&outfile).unwrap()).unwrap();
    assert_eq!(m.schema, "p11scope-manifest/5");
    assert_eq!(
        std::fs::metadata(&outfile).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let missing = out_dir.join("no-such-dir").join("manifest.json");
    let refused = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .args(["-o"])
        .arg(&missing)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("isolated profile: "), "{stderr}");
    assert!(
        !stderr.contains("ISOLATION_"),
        "provider ran before the output refusal: {stderr}"
    );
    assert!(!missing.exists());
}

/// R7/R9: a loader failure under the fence keeps its ordinary diagnosis
/// and additionally names the profile; the trusted twin has no suffix.
#[test]
fn isolation_loader_failure_names_the_profile() {
    let dir = scratch("isolation-broken");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture");
    let vanishing = dir.join("libvanishing.so");
    assert!(
        Command::new("gcc")
            .arg(format!("-m{}", usize::BITS))
            .args(["-shared", "-fPIC", "-o"])
            .arg(&vanishing)
            .arg(source.join("isolation_backend.c"))
            .status()
            .unwrap()
            .success()
    );
    let provider = dir.join("isolation-broken.so");
    assert!(
        Command::new("gcc")
            .arg(format!("-m{}", usize::BITS))
            .args(["-shared", "-fPIC", "-o"])
            .arg(&provider)
            .arg(source.join("isolation_probe.c"))
            .arg("-ldl")
            .arg(format!("-L{}", dir.display()))
            .arg("-Wl,--no-as-needed")
            .arg("-lvanishing")
            .status()
            .unwrap()
            .success()
    );
    std::fs::remove_file(&vanishing).unwrap();
    let trusted = Command::new(BIN)
        .args(["--module"])
        .arg(&provider)
        .output()
        .unwrap();
    assert_eq!(trusted.status.code(), Some(1), "{trusted:?}");
    let trusted_stderr = String::from_utf8_lossy(&trusted.stderr);
    assert!(trusted_stderr.contains("cannot dlopen"), "{trusted_stderr}");
    assert!(
        !trusted_stderr.contains("isolated"),
        "trusted failure must never name the isolated profile: {trusted_stderr}"
    );
    let isolated = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .output()
        .unwrap();
    assert_eq!(isolated.status.code(), Some(1), "{isolated:?}");
    let isolated_stderr = String::from_utf8_lossy(&isolated.stderr);
    assert!(
        isolated_stderr.contains("cannot dlopen"),
        "{isolated_stderr}"
    );
    assert!(
        isolated_stderr.contains("(under the isolated profile)"),
        "{isolated_stderr}"
    );
}

/// F-56: `--help` is an exit-0 answer, so it goes to stdout like
/// `--version` and like `p11scope --help`.
#[test]
fn help_prints_usage_on_stdout_and_exits_zero() {
    for flag in ["--help", "-h"] {
        let out = Command::new(BIN).arg(flag).output().unwrap();
        assert_eq!(out.status.code(), Some(0), "{flag}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("usage: p11scope-discover"),
            "{flag}: {out:?}"
        );
        assert!(out.stderr.is_empty(), "{flag}: {out:?}");
    }
}

/// Contract §1: `--help` documents each profile in its own paragraph, and
/// the trusted paragraph never calls trusted "isolated" (D4).
#[test]
fn help_documents_each_profile_in_its_own_paragraph() {
    let out = Command::new(BIN).arg("--help").output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let paragraphs: Vec<&str> = stdout.split("\n\n").collect();
    let find = |needle: &str| {
        paragraphs
            .iter()
            .filter(|p| p.to_lowercase().contains(needle))
            .copied()
            .collect::<Vec<&str>>()
    };
    let trusted = find("trusted (default)");
    assert_eq!(trusted.len(), 1, "one trusted paragraph: {stdout:?}");
    assert!(
        !trusted[0].to_lowercase().contains("isolated"),
        "trusted must never be called isolated: {:?}",
        trusted[0]
    );
    let fenced = find("additionally fences");
    assert_eq!(fenced.len(), 1, "one isolated paragraph: {stdout:?}");
    assert_ne!(
        trusted[0], fenced[0],
        "each profile needs its own paragraph: {stdout:?}"
    );
}

/// A `-o` parent of `/` must refuse before provider load: granting the
/// whole tree write access would void the read-only promise (contract
/// §2/D6) while the operator believes the provider is fenced. Every
/// spelling of the root refuses: direct, `.`, `..`, double slash and a
/// symlink to `/` all resolve before the comparison, as does a bare `-o`
/// name when the helper runs from `/`.
#[test]
fn isolation_output_directory_filesystem_root_is_refused() {
    let dir = scratch("isolation-root");
    let provider = build_isolation_probe(&dir);
    let name = format!("p11scope-helper-iso-root-test-{}.json", std::process::id());
    let link = dir.join("rootlink");
    std::os::unix::fs::symlink("/", &link).unwrap();
    let outputs = [
        Path::new("/").join(&name),
        Path::new("/.").join(&name),
        Path::new("/tmp").join("..").join(&name),
        Path::new("//").join(&name),
        link.join(&name),
    ];
    for outfile in &outputs {
        let _ = std::fs::remove_file(outfile);
        let out = Command::new(BIN)
            .args(["--isolation", "isolated", "--module"])
            .arg(&provider)
            .args(["-o"])
            .arg(outfile)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{outfile:?}: {out:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(
                "isolated profile: output directory / is unusable: refusing the filesystem root"
            ),
            "{outfile:?}: {stderr}"
        );
        assert!(
            !stderr.contains("ISOLATION_"),
            "provider ran before the root refusal: {outfile:?}: {stderr}"
        );
        assert!(
            !outfile.exists(),
            "a refusal must not create a manifest: {outfile:?}"
        );
    }
    // A bare `-o` name resolves its parent (`.`) against the working
    // directory; from `/` that is the root as well.
    let out = Command::new(BIN)
        .current_dir("/")
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .args(["-o"])
        .arg(&name)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "cwd=/ bare name: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(
            "isolated profile: output directory / is unusable: refusing the filesystem root"
        ),
        "cwd=/ bare name: {stderr}"
    );
    assert!(
        !stderr.contains("ISOLATION_"),
        "provider ran before the root refusal from cwd=/: {stderr}"
    );
    assert!(
        !Path::new("/").join(&name).exists(),
        "a refusal must not create a manifest"
    );
}

/// An unusable `-o` parent refuses with the contract §3 step-1 shape
/// `isolated profile: output directory <dir> is unusable: <reason>`,
/// before provider load.
#[test]
fn isolation_missing_output_directory_uses_contract_wording() {
    let dir = scratch("isolation-missing-wording");
    let provider = build_isolation_probe(&dir);
    let missing = dir.join("no-such-dir").join("manifest.json");
    let out = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .args(["-o"])
        .arg(&missing)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let parent = missing.parent().unwrap();
    assert!(
        stderr.contains(&format!(
            "isolated profile: output directory {} is unusable:",
            parent.display()
        )),
        "{stderr}"
    );
    assert!(
        !stderr.contains("ISOLATION_"),
        "provider ran before the output refusal: {stderr}"
    );
    assert!(!missing.exists());
}

/// Overwriting an existing file outside the `-o` directory is denied
/// (`WRITE_FILE`), not just creation (`MAKE_REG`). Trusted opens the
/// scratch sibling; the fence denies it with `EACCES` and leaves it
/// untouched.
#[test]
fn isolation_overwrite_of_existing_file_is_denied() {
    let dir = scratch("isolation-overwrite");
    let provider = build_isolation_probe(&dir);
    let sibling = dir.join("isolation-overwrite.tmp");
    std::fs::write(&sibling, b"overwrite probe").unwrap();
    let trusted = Command::new(BIN)
        .args(["--module"])
        .arg(&provider)
        .output()
        .unwrap();
    assert_eq!(trusted.status.code(), Some(0), "{trusted:?}");
    let stderr = String::from_utf8_lossy(&trusted.stderr);
    assert!(
        stderr.contains("ISOLATION_OVERWRITE=allowed"),
        "trusted must open the scratch sibling: {stderr}"
    );
    let isolated = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .output()
        .unwrap();
    assert_eq!(isolated.status.code(), Some(0), "{isolated:?}");
    let stderr = String::from_utf8_lossy(&isolated.stderr);
    assert!(
        stderr.contains("ISOLATION_OVERWRITE=denied(errno=13)"),
        "overwrite was not fenced: {stderr}"
    );
    assert_eq!(
        std::fs::read(&sibling).unwrap(),
        b"overwrite probe",
        "the probe must not modify the scratch sibling"
    );
    std::fs::remove_file(&sibling).unwrap();
}

/// io_uring socket/connect syscalls never hit the seccomp network checks,
/// so the ring setup itself must be denied: the constructor's probe fails
/// with `EACCES` under the fence. Trusted proves the probe exercises a
/// working `io_uring_setup` on this host.
#[test]
fn isolation_io_uring_setup_is_denied() {
    let dir = scratch("isolation-uring");
    let provider = build_isolation_probe(&dir);
    let trusted = Command::new(BIN)
        .args(["--module"])
        .arg(&provider)
        .output()
        .unwrap();
    assert_eq!(trusted.status.code(), Some(0), "{trusted:?}");
    let stderr = String::from_utf8_lossy(&trusted.stderr);
    assert!(
        stderr.contains("ISOLATION_URING_SETUP=allowed"),
        "the probe must exercise a working io_uring_setup: {stderr}"
    );
    let isolated = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .output()
        .unwrap();
    assert_eq!(isolated.status.code(), Some(0), "{isolated:?}");
    let stderr = String::from_utf8_lossy(&isolated.stderr);
    assert!(
        stderr.contains("ISOLATION_URING_SETUP=denied(errno=13)"),
        "io_uring_setup was not fenced: {stderr}"
    );
}

/// Landlock cannot restrict chmod, so the seccomp denylist must: the
/// constructor's chmod of a test-owned file outside the output fails with
/// `EACCES` under the fence and the mode is untouched. Trusted proves the
/// probe changes the mode when unfenced.
#[test]
fn isolation_chmod_outside_the_output_is_denied() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = scratch("isolation-chmod");
    let provider = build_isolation_probe(&dir);
    let trusted_target = dir.join("chmod-trusted.tmp");
    let isolated_target = dir.join("chmod-isolated.tmp");
    std::fs::write(&trusted_target, b"chmod probe").unwrap();
    std::fs::write(&isolated_target, b"chmod probe").unwrap();
    std::fs::set_permissions(&trusted_target, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&isolated_target, std::fs::Permissions::from_mode(0o600)).unwrap();
    let trusted = Command::new(BIN)
        .args(["--module"])
        .arg(&provider)
        .env("ISOLATION_CHMOD_PATH", &trusted_target)
        .output()
        .unwrap();
    assert_eq!(trusted.status.code(), Some(0), "{trusted:?}");
    let stderr = String::from_utf8_lossy(&trusted.stderr);
    assert!(
        stderr.contains("ISOLATION_CHMOD=allowed"),
        "trusted must chmod the scratch file: {stderr}"
    );
    assert_eq!(
        std::fs::metadata(&trusted_target)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o666,
        "the trusted probe must change the mode"
    );
    let isolated = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .env("ISOLATION_CHMOD_PATH", &isolated_target)
        .output()
        .unwrap();
    assert_eq!(isolated.status.code(), Some(0), "{isolated:?}");
    let stderr = String::from_utf8_lossy(&isolated.stderr);
    assert!(
        stderr.contains("ISOLATION_CHMOD=denied(errno=13)"),
        "chmod was not fenced: {stderr}"
    );
    assert_eq!(
        std::fs::metadata(&isolated_target)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "the fenced probe must not change the mode"
    );
    assert_eq!(
        std::fs::read(&isolated_target).unwrap(),
        b"chmod probe",
        "the fenced probe must not modify the scratch file"
    );
}

/// AF_UNIX creation stays allowed for the loader, but connecting to a
/// live test listener and `execve` of /bin/true in a child are both
/// denied with `EACCES` under the fence. Trusted proves both probes
/// succeed when unfenced.
#[test]
fn isolation_unix_connect_and_execve_are_denied() {
    use std::os::unix::net::UnixListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let dir = scratch("isolation-unixexec");
    let provider = build_isolation_probe(&dir);
    // The listener lives directly under TMPDIR: the cargo scratch nesting
    // blows past SUN_LEN (108 bytes).
    let socket = std::env::temp_dir().join(format!("p11scope-iso-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    // The listener stays open for both runs; the acceptor drains any
    // unexpected allowed connect so it never blocks the suite.
    let done = Arc::new(AtomicBool::new(false));
    let acceptor = std::thread::spawn({
        let done = done.clone();
        move || {
            while !done.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((connection, _)) => drop(connection),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        }
    });
    let run = |extra: &[&str]| {
        let mut args: Vec<&std::ffi::OsStr> = extra.iter().map(std::ffi::OsStr::new).collect();
        args.push(std::ffi::OsStr::new("--module"));
        args.push(provider.as_os_str());
        Command::new(BIN)
            .args(&args)
            .env("ISOLATION_UNIX_PATH", &socket)
            .output()
            .unwrap()
    };
    let trusted = run(&[]);
    assert_eq!(trusted.status.code(), Some(0), "{trusted:?}");
    let stderr = String::from_utf8_lossy(&trusted.stderr);
    assert!(
        stderr.contains("ISOLATION_UNIX_CONNECT=allowed"),
        "trusted must connect to the listener: {stderr}"
    );
    assert!(
        stderr.contains("ISOLATION_EXECVE=allowed"),
        "trusted must exec /bin/true in the child: {stderr}"
    );
    let isolated = run(&["--isolation", "isolated"]);
    assert_eq!(isolated.status.code(), Some(0), "{isolated:?}");
    let stderr = String::from_utf8_lossy(&isolated.stderr);
    assert!(
        stderr.contains("ISOLATION_UNIX_CONNECT=denied(errno=13)"),
        "AF_UNIX connect was not fenced: {stderr}"
    );
    assert!(
        stderr.contains("ISOLATION_EXECVE=denied(errno=13)"),
        "execve was not fenced: {stderr}"
    );
    done.store(true, Ordering::Relaxed);
    acceptor.join().unwrap();
    std::fs::remove_file(&socket).unwrap();
}

/// Landlock path rules grant a whole subtree, so a `-o` parent that is
/// not empty (or holding only the target name) refuses before provider
/// load: no constructor marker may appear and the planted victim beneath
/// the directory keeps its bytes.
#[test]
fn isolation_nonempty_output_directory_is_refused_before_provider_load() {
    let dir = scratch("isolation-nonempty");
    let provider = build_isolation_probe(&dir);
    let out = dir.join("out");
    let sub = out.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    let victim = sub.join("victim");
    std::fs::write(&victim, b"keep").unwrap();
    let outfile = out.join("manifest.json");
    let refused = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .args(["-o"])
        .arg(&outfile)
        .env("ISOLATION_SUBTREE_PATH", &victim)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("not empty; use a dedicated directory"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("ISOLATION_"),
        "provider ran before the output refusal: {stderr}"
    );
    assert_eq!(
        std::fs::read(&victim).unwrap(),
        b"keep",
        "a refusal must not let the provider near the victim"
    );
    assert!(!outfile.exists(), "a refusal must not create a manifest");
}

/// Terminal-input-injection ioctls are denied under the fence: on the
/// non-terminal probe fd the calls reach the kernel as `ENOTTY` when
/// trusted, while the fence denies them with `EACCES` first.
#[test]
fn isolation_terminal_injection_ioctls_are_denied() {
    let dir = scratch("isolation-tioc");
    let provider = build_isolation_probe(&dir);
    let trusted = Command::new(BIN)
        .args(["--module"])
        .arg(&provider)
        .output()
        .unwrap();
    assert_eq!(trusted.status.code(), Some(0), "{trusted:?}");
    let stderr = String::from_utf8_lossy(&trusted.stderr);
    assert!(
        stderr.contains("ISOLATION_TIOCSTI=denied(errno=25)"),
        "trusted must reach the kernel as ENOTTY: {stderr}"
    );
    assert!(
        stderr.contains("ISOLATION_TIOCLINUX=denied(errno=25)"),
        "trusted must reach the kernel as ENOTTY: {stderr}"
    );
    let isolated = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .output()
        .unwrap();
    assert_eq!(isolated.status.code(), Some(0), "{isolated:?}");
    let stderr = String::from_utf8_lossy(&isolated.stderr);
    assert!(
        stderr.contains("ISOLATION_TIOCSTI=denied(errno=13)"),
        "TIOCSTI was not fenced: {stderr}"
    );
    assert!(
        stderr.contains("ISOLATION_TIOCLINUX=denied(errno=13)"),
        "TIOCLINUX was not fenced: {stderr}"
    );
}

/// `--help` names the isolated profile's residuals beside the fence:
/// the provider still runs as the operator's uid with the operator's
/// environment and readable files.
#[test]
fn help_names_the_isolated_residuals() {
    let out = Command::new(BIN).arg("--help").output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let fenced = stdout
        .split("\n\n")
        .find(|p| p.contains("additionally fences"))
        .expect("one isolated paragraph");
    for word in ["uid", "environment", "readable"] {
        assert!(
            fenced.contains(word),
            "the isolated paragraph must name the {word} residual: {fenced:?}"
        );
    }
}

/// The dedicated-directory rule keeps the rename-over case working: a
/// `-o` parent holding only the target name is accepted and the stale
/// file is replaced with a private manifest.
#[test]
fn isolation_output_directory_holding_only_the_target_is_accepted() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = scratch("isolation-only-target");
    let provider = build_isolation_probe(&dir);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let outfile = out.join("manifest.json");
    std::fs::write(&outfile, b"stale").unwrap();
    std::fs::set_permissions(&outfile, std::fs::Permissions::from_mode(0o644)).unwrap();
    let run = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .args(["-o"])
        .arg(&outfile)
        .output()
        .unwrap();
    assert_eq!(run.status.code(), Some(0), "{run:?}");
    let m: p11scope_discover::manifest::Manifest =
        serde_json::from_slice(&std::fs::read(&outfile).unwrap()).unwrap();
    assert_eq!(m.schema, "p11scope-manifest/5");
    assert_eq!(
        std::fs::metadata(&outfile).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(litter(&out), Vec::<String>::new());
}

/// N1: the target-name exception holds only for a single-link regular
/// file. A directory at the target name refuses before provider load:
/// no constructor marker, the victim beneath it keeps its bytes, and no
/// manifest or planted file appears.
#[test]
fn isolation_target_name_holding_a_directory_is_refused() {
    let dir = scratch("isolation-target-dir");
    let provider = build_isolation_probe(&dir);
    let out = dir.join("out");
    let target = out.join("manifest.json");
    std::fs::create_dir_all(&target).unwrap();
    let victim = target.join("victim");
    std::fs::write(&victim, b"keep").unwrap();
    let refused = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .args(["-o"])
        .arg(&target)
        .env("ISOLATION_SUBTREE_PATH", &victim)
        .env("ISOLATION_NOTRUNC_PATH", &victim)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("not empty; use a dedicated directory"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("ISOLATION_"),
        "provider ran before the output refusal: {stderr}"
    );
    assert_eq!(
        std::fs::read(&victim).unwrap(),
        b"keep",
        "a refusal must not let the provider near the victim"
    );
    assert!(
        std::fs::read_dir(&target).unwrap().count() == 1,
        "a refusal must plant nothing beneath the target"
    );
}

/// N1: a hard link at the target name refuses before provider load: the
/// outside inode keeps its bytes (the fence would otherwise grant the
/// shared inode through the writable subtree).
#[test]
fn isolation_target_name_holding_a_hard_link_is_refused() {
    let dir = scratch("isolation-target-nlink");
    let provider = build_isolation_probe(&dir);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let outside = dir.join("outside.txt");
    std::fs::write(&outside, b"outside-keep").unwrap();
    let target = out.join("manifest.json");
    std::fs::hard_link(&outside, &target).unwrap();
    let refused = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .args(["-o"])
        .arg(&target)
        .env("ISOLATION_SUBTREE_PATH", &target)
        .env("ISOLATION_NOTRUNC_PATH", &target)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("not empty; use a dedicated directory"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("ISOLATION_"),
        "provider ran before the output refusal: {stderr}"
    );
    assert_eq!(
        std::fs::read(&outside).unwrap(),
        b"outside-keep",
        "a refusal must not let the provider near the linked inode"
    );
}

/// Read the inode flags of a test-owned file via FS_IOC_GETFLAGS.
fn inode_flags(path: &Path) -> i32 {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    // `libc::Ioctl` is the request parameter's own type (c_int on musl,
    // c_ulong on glibc); the `as` cast keeps the identical bit pattern.
    const FS_IOC_GETFLAGS: libc::Ioctl = 0x8008_6601_u32 as libc::Ioctl;
    let raw = CString::new(path.as_os_str().as_bytes()).unwrap();
    let fd = unsafe { libc::open(raw.as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0, "cannot open {} for flags", path.display());
    let mut flags: i32 = 0;
    let ret = unsafe { libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags) };
    unsafe { libc::close(fd) };
    assert_eq!(ret, 0, "FS_IOC_GETFLAGS failed on {}", path.display());
    flags
}

/// Probe whether `dir` can host the N2 twins: a fresh file there must
/// take FS_NODUMP_FL via FS_IOC_SETFLAGS and show it back via
/// FS_IOC_GETFLAGS. Returns the reason (write/open/ioctl errno) when it
/// cannot, so the caller can try the next candidate instead of failing.
fn setflags_probe(dir: &Path) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    // `libc::Ioctl` is the request parameter's own type (c_int on musl,
    // c_ulong on glibc); the `as` cast keeps the identical bit pattern.
    const FS_IOC_GETFLAGS: libc::Ioctl = 0x8008_6601_u32 as libc::Ioctl;
    const FS_IOC_SETFLAGS: libc::Ioctl = 0x4008_6602_u32 as libc::Ioctl;
    const FS_NODUMP_FL: i32 = 0x40;
    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }
    static PROBE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let probe = dir.join(format!(
        "setflags-probe-{}-{}.tmp",
        std::process::id(),
        PROBE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    if let Err(error) = std::fs::write(&probe, b"setflags probe") {
        return Err(format!("cannot write the probe file: {error}"));
    }
    let raw = CString::new(probe.as_os_str().as_bytes()).unwrap();
    // SAFETY: the fd is open from here until the close below; both ioctls
    // take a pointer to an int-sized flag word.
    let outcome = unsafe {
        let fd = libc::open(raw.as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            Err(format!("probe open failed with errno={}", errno()))
        } else {
            let mut flags: i32 = 0;
            let result = if libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags) != 0 {
                Err(format!("GETFLAGS failed with errno={}", errno()))
            } else if flags & FS_NODUMP_FL != 0 {
                Err("a fresh probe file already has NODUMP".to_string())
            } else {
                let set: i32 = FS_NODUMP_FL;
                if libc::ioctl(fd, FS_IOC_SETFLAGS, &set) != 0 {
                    Err(format!("SETFLAGS failed with errno={}", errno()))
                } else {
                    let mut back: i32 = 0;
                    if libc::ioctl(fd, FS_IOC_GETFLAGS, &mut back) != 0 {
                        Err(format!("flag reread failed with errno={}", errno()))
                    } else if back & FS_NODUMP_FL == 0 {
                        Err("SETFLAGS succeeded but NODUMP is missing".to_string())
                    } else {
                        Ok(())
                    }
                }
            };
            libc::close(fd);
            result
        }
    };
    let _ = std::fs::remove_file(&probe);
    outcome
}

/// Filesystem identity of `dir` for the loud N2 precondition failure: a
/// short name for the known scratch filesystems, else the statfs magic
/// in hex (unambiguous, with no table to keep complete).
fn dir_fstype_name(dir: &Path) -> String {
    use std::os::unix::ffi::OsStrExt as _;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: statfs writes the whole struct on success.
    if unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return format!(
            "statfs errno={}",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        );
    }
    // SAFETY: success above initialized it.
    let stat = unsafe { stat.assume_init() };
    // `f_type` is signed on glibc and unsigned on musl; the magic fits both.
    #[allow(clippy::unnecessary_cast)]
    let magic = stat.f_type as u64;
    let name = match magic {
        0xef53 => "ext2/3/4",
        0x0102_1994 => "tmpfs",
        0x9123_683e => "btrfs",
        0x794c_7630 => "overlayfs",
        0x5846_5342 => "xfs",
        _ => return format!("statfs magic 0x{magic:x}"),
    };
    name.to_string()
}

/// Caller tags for [`setflags_twin_dir`]: each caller needs its own tag
/// so concurrent fallbacks land in distinct pid-tagged dirs instead of
/// racing on one shared `setflags-fallback` dir.
const N2_SETFLAGS_TAG: &str = "n2";
const SELECTION_SETFLAGS_TAG: &str = "selection";

/// Owned N2 twin directory: a fallback dir is removed on drop, so a panic
/// still cleans the shared dir; the test's own scratch dir is borrowed
/// and left in place.
struct SetflagsTwinDir {
    path: std::path::PathBuf,
    fallback: bool,
    /// In-process probe outcome per twin candidate tried while selecting
    /// this dir (rejected candidates with their reason, then the winner
    /// with its `probe ok` row), so a later trusted-child failure can
    /// report what the probes saw beside what the child saw. Guards
    /// created while advancing past a child-rejected candidate carry no
    /// rows; the caller keeps the seeded rows for the whole chain.
    probe_attempts: Vec<String>,
}

impl SetflagsTwinDir {
    fn path(&self) -> &Path {
        &self.path
    }

    fn is_fallback(&self) -> bool {
        self.fallback
    }

    fn probe_attempts(&self) -> &[String] {
        &self.probe_attempts
    }
}

impl Drop for SetflagsTwinDir {
    fn drop(&mut self) {
        if self.fallback {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Directory that holds the N2 twin files: the test's own scratch
/// directory when its filesystem applies FS_IOC_SETFLAGS, else a fresh
/// pid-tagged directory on a tmpfs fallback (`/dev/shm`, then the
/// process temp directory), named per caller `tag` so concurrent callers
/// never share one dir. Some hosted runners return EOPNOTSUPP for
/// SETFLAGS on the cargo scratch disk; the fence assertions do not
/// depend on the directory (the isolated run carries no `-o` at all),
/// so the twins move while the positive stays a positive. Panics with
/// the named reason SETFLAGS_TWIN_PRECONDITION_FAILED, listing every
/// candidate with its filesystem and probe error, when no candidate
/// applies the flag. The returned guard removes a fallback dir on drop
/// (panic-safe); the scratch dir is borrowed and left in place.
fn setflags_twin_dir(scratch: &Path, tag: &str) -> SetflagsTwinDir {
    if let Err(reason) = setflags_probe(scratch) {
        let mut attempts = vec![format!(
            "{} [{}]: {reason}",
            scratch.display(),
            dir_fstype_name(scratch)
        )];
        for root in [Path::new("/dev/shm"), &std::env::temp_dir()] {
            if !root.is_dir() {
                attempts.push(format!("{}: not a usable directory", root.display()));
                continue;
            }
            let dir = scratch_in(root, &format!("setflags-fallback-{tag}"));
            match setflags_probe(&dir) {
                Ok(()) => {
                    return SetflagsTwinDir {
                        path: dir,
                        fallback: true,
                        probe_attempts: Vec::new(),
                    };
                }
                Err(reason) => {
                    attempts.push(format!(
                        "{} [{}]: {reason}",
                        dir.display(),
                        dir_fstype_name(&dir)
                    ));
                    let _ = std::fs::remove_dir_all(&dir);
                }
            }
        }
        panic!(
            "SETFLAGS_TWIN_PRECONDITION_FAILED: no twin directory applies FS_IOC_SETFLAGS: {}",
            attempts.join("; ")
        );
    }
    SetflagsTwinDir {
        path: scratch.to_path_buf(),
        fallback: false,
        probe_attempts: Vec::new(),
    }
}

/// Trusted-child SETFLAGS verdict for one twin dir: the flag applied
/// (run the fence assertions there), the filesystem cannot take the
/// flag for the child (EOPNOTSUPP: try the next twin candidate), or
/// anything else (a real error that fails loud, never falls back).
enum TrustedSetflags {
    Allowed,
    FsUnsupported,
    HardError,
}

/// Classify the trusted child's SETFLAGS marker. Only a filesystem
/// EOPNOTSUPP advances the twin chain: a fenced trusted child
/// (EACCES), an unknown marker or a missing marker is a hard failure.
/// The EOPNOTSUPP shape is the hosted-runner observation (the child
/// reports the numeric errno, as the fence pins prove for EACCES).
fn classify_trusted_setflags(stderr: &str) -> TrustedSetflags {
    if stderr.contains("ISOLATION_SETFLAGS=allowed") {
        TrustedSetflags::Allowed
    } else if stderr.contains(&format!(
        "ISOLATION_SETFLAGS=denied(errno={})",
        libc::EOPNOTSUPP
    )) {
        TrustedSetflags::FsUnsupported
    } else {
        TrustedSetflags::HardError
    }
}

/// The twin candidate after `current` in N2 fallback order (the test's
/// own scratch dir, then a fresh pid-tagged dir under `/dev/shm`, then
/// under the process temp dir): `None` when `current` is the last
/// candidate. Fallback dirs are created on demand with the same
/// `setflags-fallback-{tag}` naming as [`setflags_twin_dir`]; the
/// returned guard removes a fallback dir on drop. Roots that are not
/// usable directories are skipped with a recorded attempt. There is no
/// in-process flag probe here: the trusted child qualifies each
/// candidate on its own twin file, so the probe and the asserted child
/// run observe the identical file location and kind.
fn setflags_next_twin_dir(
    current: &Path,
    scratch: &Path,
    tag: &str,
    attempts: &mut Vec<String>,
) -> Option<SetflagsTwinDir> {
    let tmp = std::env::temp_dir();
    // Each entry is the candidate dir plus its fallback root (none for
    // the borrowed scratch dir).
    let mut chain: Vec<(std::path::PathBuf, Option<std::path::PathBuf>)> =
        vec![(scratch.to_path_buf(), None)];
    for root in [Path::new("/dev/shm"), tmp.as_path()] {
        if !root.is_dir() {
            attempts.push(format!("{}: not a usable directory", root.display()));
            continue;
        }
        chain.push((
            scratch_in_path(root, &format!("setflags-fallback-{tag}")),
            Some(root.to_path_buf()),
        ));
    }
    // Advance past every position holding `current` (two roots can
    // resolve to the same dir); the next distinct dir wins.
    let mut seen_current = false;
    for (dir, root) in chain {
        if dir.as_path() == current {
            seen_current = true;
            continue;
        }
        if !seen_current {
            continue;
        }
        match root {
            Some(root) => {
                let made = scratch_in(&root, &format!("setflags-fallback-{tag}"));
                debug_assert_eq!(made, dir);
                return Some(SetflagsTwinDir {
                    path: made,
                    fallback: true,
                    probe_attempts: Vec::new(),
                });
            }
            None => {
                return Some(SetflagsTwinDir {
                    path: dir,
                    fallback: false,
                    probe_attempts: Vec::new(),
                });
            }
        }
    }
    None
}

/// Trusted-child qualification of the N2 twin directory: the twin
/// files live on the first candidate whose in-process probe passed,
/// and the trusted child must set the flag there before the fence
/// assertions run. A child EOPNOTSUPP advances to the next twin
/// candidate; any other child outcome fails loud. `bin` is the helper
/// under test as a path so the precondition-table test can drive the
/// chain with a fake child without touching the real helper. `provider`
/// is the isolation probe fixture every trusted child loads. Returns
/// the selected twin dir guard with the trusted and isolated paths.
fn qualify_setflags_twins(
    bin: &Path,
    dir: &Path,
    tag: &str,
    provider: &Path,
) -> (SetflagsTwinDir, std::path::PathBuf, std::path::PathBuf) {
    const FS_NODUMP_FL: i32 = 0x40;
    let mut attempts: Vec<String> = Vec::new();
    let mut twins = setflags_twin_dir(dir, tag);
    loop {
        let trusted_target = twins.path().join("setflags-trusted.tmp");
        let isolated_target = twins.path().join("setflags-isolated.tmp");
        std::fs::write(&trusted_target, b"setflags probe").unwrap();
        std::fs::write(&isolated_target, b"setflags probe").unwrap();
        assert_eq!(
            inode_flags(&trusted_target) & FS_NODUMP_FL,
            0,
            "fresh files must start without NODUMP"
        );
        let trusted = Command::new(bin)
            .args(["--module"])
            .arg(&provider)
            .env("ISOLATION_SETFLAGS_PATH", &trusted_target)
            .output()
            .unwrap();
        assert_eq!(trusted.status.code(), Some(0), "{trusted:?}");
        let stderr = String::from_utf8_lossy(&trusted.stderr);
        match classify_trusted_setflags(&stderr) {
            TrustedSetflags::Allowed => break (twins, trusted_target, isolated_target),
            TrustedSetflags::FsUnsupported => {
                attempts.push(format!(
                    "{} [{}]: trusted child ISOLATION_SETFLAGS=denied(errno={})",
                    twins.path().display(),
                    dir_fstype_name(twins.path()),
                    libc::EOPNOTSUPP
                ));
                match setflags_next_twin_dir(twins.path(), dir, tag, &mut attempts) {
                    Some(next) => {
                        twins = next;
                    }
                    None => panic!(
                        "SETFLAGS_TWIN_PRECONDITION_FAILED: no twin directory takes FS_IOC_SETFLAGS for the child: {}",
                        attempts.join("; ")
                    ),
                }
            }
            TrustedSetflags::HardError => {
                panic!("trusted must set the flag: {stderr}");
            }
        }
    }
}

/// N2: inode-attribute change outside -o is denied. The constructor's
/// FS_IOC_SETFLAGS from an O_RDONLY fd sets FS_NODUMP_FL when trusted
/// (twin proves the probe applies) and fails with EACCES under the fence
/// with the flags and bytes untouched. The twin files live on the first
/// candidate that takes the flag for the child (cargo scratch, then a
/// tmpfs fallback), since some hosted runners return EOPNOTSUPP on the
/// scratch disk; a candidate whose in-process probe passed but whose
/// trusted child still reports EOPNOTSUPP is skipped the same way.
/// Anything but `allowed` or a filesystem EOPNOTSUPP from the trusted
/// child fails loud: a fenced trusted child is never a fallback.
#[test]
fn isolation_setflags_outside_the_output_is_denied() {
    const FS_NODUMP_FL: i32 = 0x40;
    let dir = scratch("isolation-setflags");
    let provider = build_isolation_probe(&dir);
    let (twins, trusted_target, isolated_target) =
        qualify_setflags_twins(Path::new(BIN), &dir, N2_SETFLAGS_TAG, &provider);
    assert_ne!(
        inode_flags(&trusted_target) & FS_NODUMP_FL,
        0,
        "the trusted probe must apply FS_NODUMP_FL"
    );
    let isolated = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .env("ISOLATION_SETFLAGS_PATH", &isolated_target)
        .output()
        .unwrap();
    assert_eq!(isolated.status.code(), Some(0), "{isolated:?}");
    let stderr = String::from_utf8_lossy(&isolated.stderr);
    assert!(
        stderr.contains("ISOLATION_SETFLAGS=denied(errno=13)"),
        "SETFLAGS was not fenced: {stderr}"
    );
    assert_eq!(
        inode_flags(&isolated_target) & FS_NODUMP_FL,
        0,
        "the fenced probe must not change the flags"
    );
    assert_eq!(
        std::fs::read(&isolated_target).unwrap(),
        b"setflags probe",
        "the fenced probe must not modify the scratch file"
    );
    if twins.is_fallback() {
        std::fs::remove_dir_all(twins.path()).unwrap();
    }
}

/// The N2 precondition report names every twin candidate with its
/// in-process probe outcome beside the trusted child's verdict: a fake
/// child that always reports EOPNOTSUPP walks the whole chain, and the
/// loud failure must still show that the probes passed (the hosted
/// divergence shape: probe ok, child refused). The fake binary exits 0
/// so the run reaches the classifier exactly like a real child the
/// filesystem refused, and it uses its own caller tag so its fallback
/// dirs never collide with the concurrently running N2 twins.
#[test]
fn setflags_precondition_names_probe_and_child_outcomes() {
    use std::os::unix::fs::PermissionsExt as _;
    const TAG: &str = "neg-table";
    let dir = scratch("isolation-setflags-neg-table");
    let fake = dir.join("fake-discover-95.sh");
    std::fs::write(
        &fake,
        "#!/bin/sh\necho 'ISOLATION_SETFLAGS=denied(errno=95)' >&2\nexit 0\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let provider = build_isolation_probe(&dir);
    let message = match std::panic::catch_unwind(|| {
        qualify_setflags_twins(&fake, &dir, TAG, &provider)
    }) {
        Ok(_) => panic!("a child that always reports EOPNOTSUPP must exhaust the chain"),
        Err(payload) => match payload.downcast_ref::<String>() {
            Some(message) => message.clone(),
            None => panic!("the precondition failure must carry a message"),
        },
    };
    for pinned in [
        "SETFLAGS_TWIN_PRECONDITION_FAILED",
        "probe ok",
        "trusted child",
        "errno=95",
    ] {
        assert!(
            message.contains(pinned),
            "the report must name {pinned}: {message}"
        );
    }
}

/// The trusted-child SETFLAGS classifier: `allowed` runs the fence
/// assertions, a filesystem EOPNOTSUPP advances the twin chain, and a
/// fenced trusted child (EACCES), an unknown marker or a missing marker
/// fails loud. The EOPNOTSUPP marker is the hosted-runner observation;
/// the `allowed` and EACCES shapes are pinned against real children by
/// the N2 test itself every run.
#[test]
fn trusted_setflags_classifier_pins_its_three_outcomes() {
    assert!(matches!(
        classify_trusted_setflags("ISOLATION_SETFLAGS=allowed\n"),
        TrustedSetflags::Allowed
    ));
    assert!(matches!(
        classify_trusted_setflags("ISOLATION_SETFLAGS=denied(errno=95)\n"),
        TrustedSetflags::FsUnsupported
    ));
    assert_eq!(libc::EOPNOTSUPP, 95, "the pinned marker must be EOPNOTSUPP");
    // A fenced trusted child is a real failure, never a fallback.
    assert!(matches!(
        classify_trusted_setflags("ISOLATION_SETFLAGS=denied(errno=13)\n"),
        TrustedSetflags::HardError
    ));
    assert!(matches!(
        classify_trusted_setflags("ISOLATION_SETFLAGS=unknown(no target)\n"),
        TrustedSetflags::HardError
    ));
    assert!(matches!(
        classify_trusted_setflags("ISOLATION_SOCKET=allowed\n"),
        TrustedSetflags::HardError
    ));
}

/// The twin chain advances past a child-rejected candidate in fallback
/// order and terminates: each step resolves a distinct existing dir,
/// and past the last candidate it is None. A path that is not on the
/// chain ends it too (negative control: no revisit, no invention).
#[test]
fn setflags_chain_advances_past_rejected_candidates() {
    let dir = scratch("isolation-setflags-chain");
    let mut attempts = Vec::new();
    // Negative control first: a path off the chain ends it.
    assert!(
        setflags_next_twin_dir(&dir.join("no-such-dir"), &dir, "pin-chain", &mut attempts)
            .is_none(),
        "advancing past an off-chain path must end the chain"
    );
    let mut seen: Vec<std::path::PathBuf> = Vec::new();
    let mut current = dir.clone();
    while let Some(next) = setflags_next_twin_dir(&current, &dir, "pin-chain", &mut attempts) {
        assert!(
            next.path().is_dir(),
            "the next candidate must exist: {}",
            next.path().display()
        );
        assert!(
            !seen.contains(&next.path().to_path_buf()),
            "candidates must not repeat: {}",
            next.path().display()
        );
        seen.push(next.path().to_path_buf());
        current = next.path().to_path_buf();
        // `next` drops here, removing each rejected fallback promptly.
    }
    let tmp = std::env::temp_dir();
    if Path::new("/dev/shm").is_dir() && tmp.is_dir() {
        let shm = scratch_in_path(Path::new("/dev/shm"), "setflags-fallback-pin-chain");
        let tmproot = scratch_in_path(&tmp, "setflags-fallback-pin-chain");
        if shm != tmproot {
            assert_eq!(
                seen,
                vec![shm, tmproot],
                "fallback order must be /dev/shm then the temp dir"
            );
        }
    }
}

/// The N2 twins run where the flag applies: an unusable primary (a path
/// that cannot hold files) selects a working fallback instead of
/// failing, and the fallback really takes the flag.
#[test]
fn setflags_twins_fall_back_when_the_primary_is_unusable() {
    let dir = scratch("isolation-setflags-fallback");
    let missing = dir.join("no-such-dir");
    // Negative control: the setup must genuinely present an unusable
    // primary, or a pass below would be vacuous.
    assert!(
        setflags_probe(&missing).is_err(),
        "the missing primary must fail the probe"
    );
    let twins = setflags_twin_dir(&missing, SELECTION_SETFLAGS_TAG);
    assert_ne!(
        twins.path(),
        missing.as_path(),
        "an unusable primary must select a fallback"
    );
    assert!(
        setflags_probe(twins.path()).is_ok(),
        "the fallback must take the flag: {}",
        twins.path().display()
    );
    let probe_attempts = twins.probe_attempts();
    assert!(
        !probe_attempts.is_empty(),
        "selecting a fallback must record the probe history"
    );
    assert!(
        probe_attempts.iter().any(|row| row.contains("probe ok")),
        "the selected fallback must have passed the probe: {probe_attempts:?}"
    );
    let missing_text = missing.to_string_lossy();
    assert!(
        probe_attempts
            .iter()
            .any(|row| row.contains(missing_text.as_ref())),
        "the history must name the rejected primary: {probe_attempts:?}"
    );
    std::fs::remove_dir_all(twins.path()).unwrap();
}

/// The two `setflags_twin_dir` callers must resolve to distinct fallback
/// dirs, or they race on shared twin files. The tag assert pins the two
/// production tags apart; the live half proves distinct tags actually
/// select distinct dirs (dedicated pin tags, disjoint from both
/// production callers, so this never shares a dir with them).
#[test]
fn setflags_fallback_dirs_are_unique_per_caller() {
    assert_ne!(
        N2_SETFLAGS_TAG, SELECTION_SETFLAGS_TAG,
        "N2 and the selection test must use distinct fallback tags"
    );
    let dir = scratch("isolation-setflags-uniqueness");
    let first = setflags_twin_dir(&dir.join("no-such-first"), "pin-first");
    let second = setflags_twin_dir(&dir.join("no-such-second"), "pin-second");
    assert_ne!(
        first.path(),
        second.path(),
        "distinct tags must select distinct fallback dirs"
    );
    std::fs::remove_dir_all(first.path()).unwrap();
    std::fs::remove_dir_all(second.path()).unwrap();
}

/// A fallback dir is removed when its guard drops, so a panic still cleans
/// the shared dir (Drop runs on panic as well as on normal exit).
#[test]
fn setflags_fallback_dir_is_removed_on_drop() {
    let dir = scratch("isolation-setflags-drop");
    let twins = setflags_twin_dir(&dir.join("no-such-dir"), "pin-drop");
    let path = twins.path().to_path_buf();
    assert!(path.is_dir(), "the fallback must exist before drop");
    drop(twins);
    assert!(!path.exists(), "Drop must remove the fallback dir");
}

/// Whether `dir` lives on btrfs (statfs magic), for the fs-gated cell.
fn dir_is_btrfs(dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    const BTRFS_SUPER_MAGIC: u64 = 0x9123_683e;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: statfs writes the whole struct on success.
    let rc = unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) };
    assert_eq!(rc, 0, "statfs {} failed", dir.display());
    // SAFETY: success above initialized it.
    let stat = unsafe { stat.assume_init() };
    // `f_type` is signed on glibc and unsigned on musl; the magic fits both.
    #[allow(clippy::unnecessary_cast)]
    {
        stat.f_type as u64 == BTRFS_SUPER_MAGIC
    }
}

/// The btrfs gate itself: `/proc` and `/sys` are never btrfs, so the
/// detector must say so (portable negative control; the positive side
/// is the subvolume twin running instead of NOT_RUN on btrfs hosts).
#[test]
fn btrfs_gate_rejects_non_btrfs_filesystems() {
    assert!(!dir_is_btrfs(Path::new("/proc")));
    assert!(!dir_is_btrfs(Path::new("/sys")));
}

/// The btrfs subvolume hole: BTRFS_IOC_SUBVOL_CREATE bypasses the
/// Landlock path hooks, so only the seccomp type-byte rule stops it.
/// Trusted creates the subvolume outside -o; isolated fails with EACCES
/// and creates nothing. Ignored by default: it needs scratch on btrfs
/// (via `$P11SCOPE_DISCOVER_BTRFS_SCRATCH` or a btrfs cargo scratch),
/// and elsewhere it reports NOT_RUN instead of passing.
#[test]
#[ignore = "needs btrfs scratch; run by exact selector"]
fn isolation_btrfs_subvolume_outside_the_output_is_denied() {
    let dir = scratch_in(&btrfs_scratch_root(), "isolation-subvol");
    assert!(
        dir_is_btrfs(&dir),
        "NOT_RUN: needs scratch on btrfs for the subvolume twin ({} is not btrfs); \
         set P11SCOPE_DISCOVER_BTRFS_SCRATCH to a btrfs directory or run where \
         CARGO_TARGET_TMPDIR is on btrfs",
        dir.display()
    );
    let provider = build_isolation_probe(&dir);
    let trusted_target = dir.join("sv-trusted");
    let trusted = Command::new(BIN)
        .args(["--module"])
        .arg(&provider)
        .env("ISOLATION_SUBVOL_PATH", &trusted_target)
        .output()
        .unwrap();
    assert_eq!(trusted.status.code(), Some(0), "{trusted:?}");
    let stderr = String::from_utf8_lossy(&trusted.stderr);
    assert!(
        stderr.contains("ISOLATION_SUBVOL=allowed"),
        "trusted must create the subvolume: {stderr}"
    );
    assert!(
        trusted_target.is_dir(),
        "the trusted probe must leave the subvolume behind"
    );
    // Empty subvolumes remove with rmdir; no privilege needed.
    std::fs::remove_dir(&trusted_target).unwrap();
    assert!(
        !trusted_target.exists(),
        "trusted cleanup must remove the subvolume"
    );
    let isolated_target = dir.join("sv-isolated");
    let isolated = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .env("ISOLATION_SUBVOL_PATH", &isolated_target)
        .output()
        .unwrap();
    assert_eq!(isolated.status.code(), Some(0), "{isolated:?}");
    let stderr = String::from_utf8_lossy(&isolated.stderr);
    assert!(
        stderr.contains("ISOLATION_SUBVOL=denied(errno=13)"),
        "subvolume creation was not fenced: {stderr}"
    );
    assert!(
        !isolated_target.exists(),
        "the fenced probe must create nothing"
    );
}

/// N4: prlimit64 on another pid is denied. Reading the parent's
/// RLIMIT_NOFILE succeeds when trusted (the twin proves the call
/// applies) and fails with EACCES under the fence.
#[test]
fn isolation_prlimit_on_the_parent_is_denied() {
    let dir = scratch("isolation-prlimit");
    let provider = build_isolation_probe(&dir);
    let trusted = Command::new(BIN)
        .args(["--module"])
        .arg(&provider)
        .output()
        .unwrap();
    assert_eq!(trusted.status.code(), Some(0), "{trusted:?}");
    let stderr = String::from_utf8_lossy(&trusted.stderr);
    assert!(
        stderr.contains("ISOLATION_PRLIMIT=allowed"),
        "trusted must read the parent's limits: {stderr}"
    );
    let isolated = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .output()
        .unwrap();
    assert_eq!(isolated.status.code(), Some(0), "{isolated:?}");
    let stderr = String::from_utf8_lossy(&isolated.stderr);
    assert!(
        stderr.contains("ISOLATION_PRLIMIT=denied(errno=13)"),
        "prlimit on another pid was not fenced: {stderr}"
    );
}
