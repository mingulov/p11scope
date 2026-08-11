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
    let out = Command::new(BIN).args(["--module", SOFTHSM]).output().unwrap();
    assert!(out.status.success());
    let m: p11scope_discover::manifest::Manifest = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(m.schema, "p11scope-manifest/1");
    assert_eq!(m.surfaces[0].functions.len(), 68);
}

#[test]
fn missing_module_is_usage_error() {
    let out = Command::new(BIN).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage"));
}

#[test]
fn undlopenable_module_fails_loudly() {
    let out = Command::new(BIN).args(["--module", "/dev/null"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot dlopen"));
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
    assert_eq!(m.schema, "p11scope-manifest/1");
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
