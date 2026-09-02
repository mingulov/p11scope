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
            .args(["-shared", "-fPIC", "-o"])
            .arg(&provider)
            .arg(&src)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("gcc")
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
