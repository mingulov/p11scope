//! SPDX-License-Identifier: GPL-3.0-or-later
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
    use std::os::unix::fs::PermissionsExt as _;
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("discover-{name}-{}", std::process::id()));
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
/// §2/D6) while the operator believes the provider is fenced.
#[test]
fn isolation_output_directory_filesystem_root_is_refused() {
    let dir = scratch("isolation-root");
    let provider = build_isolation_probe(&dir);
    let outfile = Path::new("/").join(format!(
        "p11scope-helper-iso-root-test-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&outfile);
    let out = Command::new(BIN)
        .args(["--isolation", "isolated", "--module"])
        .arg(&provider)
        .args(["-o"])
        .arg(&outfile)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(
            "isolated profile: output directory / is unusable: refusing the filesystem root"
        ),
        "{stderr}"
    );
    assert!(
        !stderr.contains("ISOLATION_"),
        "provider ran before the root refusal: {stderr}"
    );
    assert!(!outfile.exists(), "a refusal must not create a manifest");
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
