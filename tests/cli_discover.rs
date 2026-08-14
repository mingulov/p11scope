use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

const BIN: &str = env!("CARGO_BIN_EXE_p11scope");
static IN_PROCESS_DISCOVERY: Mutex<()> = Mutex::new(());

fn build_provider(dir: &Path) -> PathBuf {
    let provider = dir.join("provider.so");
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&provider)
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("crates/discover/tests/fixture/version_matrix.c",)
            )
            .status()
            .unwrap()
            .success()
    );
    provider
}

fn build_manifest_oracle(dir: &Path, manifest: &Path) -> PathBuf {
    let source = dir.join("oracle.c");
    let helper = dir.join("p11scope-discover");
    let marker = dir.join("oracle-ran");
    std::fs::write(
        &source,
        format!(
            r#"#include <stdio.h>
int main(void) {{
  FILE *marker = fopen({:?}, "wb");
  if (!marker || fclose(marker)) return 3;
  FILE *in = fopen({:?}, "rb");
  if (!in) return 2;
  for (int c; (c = fgetc(in)) != EOF;) fputc(c, stdout);
  return ferror(in) || ferror(stdout);
}}
"#,
            marker.display().to_string(),
            manifest.display().to_string()
        ),
    )
    .unwrap();
    assert!(
        Command::new("gcc")
            .args(["-o"])
            .arg(&helper)
            .arg(&source)
            .status()
            .unwrap()
            .success()
    );
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    helper
}

/// Resolve the p11scope-discover helper binary.
/// If CARGO_BIN_EXE_p11scope-discover is not available, walk from the p11scope
/// binary to find a sibling named p11scope-discover.
fn resolve_helper() -> Option<String> {
    // Try the environment variable first (available when running tests from the discover crate)
    if let Ok(helper) = std::env::var("CARGO_BIN_EXE_p11scope-discover") {
        return Some(helper);
    }

    // Fall back to finding a sibling of the p11scope binary
    let p11scope_path = std::path::PathBuf::from(BIN);
    if let Some(parent) = p11scope_path.parent() {
        let helper_path = parent.join("p11scope-discover");
        if helper_path.exists() {
            return Some(helper_path.to_string_lossy().to_string());
        }
    }

    None
}

#[test]
fn missing_helper_names_every_place_searched() {
    // Explicit --helper is authoritative: should fail immediately without falling through to PATH
    let out = Command::new(BIN)
        .args([
            "discover",
            "--module",
            "/dev/null",
            "--helper",
            "/nonexistent/helper",
        ])
        .env("PATH", "/nonexistent")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "should exit 1 for missing explicit helper"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    // Must name the explicit path
    assert!(
        err.contains("/nonexistent/helper"),
        "stderr must contain explicit helper path: {err}"
    );
    // Must NOT fall through to trying PATH
    assert!(
        !err.contains("on PATH"),
        "stderr must not mention PATH for explicit --helper: {err}"
    );
}

#[test]
fn discover_forwards_to_the_helper() {
    // The helper is built into the same target dir by the workspace.
    let helper = match resolve_helper() {
        Some(h) => h,
        None => {
            eprintln!("SKIP: p11scope-discover helper not found");
            return;
        }
    };

    let softhsm = "/usr/lib/softhsm/libsofthsm2.so";
    if !std::path::Path::new(softhsm).exists() {
        eprintln!("SKIP: no SoftHSM2");
        return;
    }
    let out = Command::new(BIN)
        .args(["discover", "--module", softhsm, "--helper", &helper])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema"], "p11scope-manifest/4");
}

#[test]
fn missing_module_is_usage_error() {
    let out = Command::new(BIN).args(["discover"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn attach_commands_require_an_explicit_provider_authority() {
    for command in ["profile", "trace"] {
        let out = Command::new(BIN)
            .args([
                command,
                "--trusted-workload",
                "--manifest",
                "/nonexistent/manifest.json",
                "--pid",
                "1",
            ])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{command}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("--provenance-module is required"),
            "{stderr}"
        );
    }
}

#[test]
fn implicit_helper_resolves_sibling() {
    // Without --helper, the helper should be found as a sibling of current_exe().
    // This test verifies the implicit search works by checking that the error message
    // is from the helper trying to load the module, not from p11scope failing to find the helper.
    let _helper = match resolve_helper() {
        Some(h) => h,
        None => {
            eprintln!("SKIP: p11scope-discover helper not found");
            return;
        }
    };

    // Use a module path that the helper will reject (so we see its error, not our missing-helper error)
    let out = Command::new(BIN)
        .args(["discover", "--module", "/nonexistent/fake.so"])
        .output()
        .unwrap();

    // The helper should be found and executed, so the error is from the helper
    // (not from p11scope failing to find the helper)
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("cannot dlopen")
            || err.contains("cannot execute")
            || err.contains("cannot open"),
        "error should be from helper trying to load module or not finding module: {err}"
    );
}

#[test]
fn profile_refuses_a_forged_function_role_before_bpf_startup() {
    use p11scope_manifest::manifest::Resolution;

    let _serial = IN_PROCESS_DISCOVERY.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let provider = build_provider(dir.path());
    let genuine = p11scope_discover::discover::discover(&provider).unwrap();
    let genuine_path = dir.path().join("genuine.json");
    let mut oracle = genuine.clone();
    let provider_sha = genuine.objects[0].identity.sha256.as_deref().unwrap();
    oracle
        .provenance_objects
        .retain(|object| object.identity.sha256.as_deref() == Some(provider_sha));
    assert_eq!(oracle.provenance_objects.len(), 1);
    std::fs::write(&genuine_path, serde_json::to_vec(&oracle).unwrap()).unwrap();

    let mut forged = oracle;
    let legacy = &mut forged.surfaces[0];
    let initialize = legacy
        .functions
        .iter()
        .find(|function| function.name == "C_Initialize")
        .unwrap()
        .resolution
        .clone();
    assert!(matches!(initialize, Resolution::Resolved { .. }));
    legacy
        .functions
        .iter_mut()
        .find(|function| function.name == "C_EncryptInit")
        .unwrap()
        .resolution = initialize;
    let forged_path = dir.path().join("forged.json");
    std::fs::write(&forged_path, serde_json::to_vec(&forged).unwrap()).unwrap();

    let observer = dir.path().join("p11scope");
    std::fs::copy(BIN, &observer).unwrap();
    std::fs::set_permissions(&observer, std::fs::Permissions::from_mode(0o755)).unwrap();
    build_manifest_oracle(dir.path(), &genuine_path);

    let output = Command::new(observer)
        .args(["profile", "--manifest"])
        .arg(&forged_path)
        .args(["--provenance-module"])
        .arg(&provider)
        .args([
            "--pid",
            &std::process::id().to_string(),
            "--trusted-workload",
            "--duration",
            "0",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("C_EncryptInit provenance"), "{stderr}");
    assert!(stderr.contains("refusing to attach"), "{stderr}");
    assert!(!stderr.contains("starting attach session"), "{stderr}");
}

#[test]
fn dynamic_observer_without_acknowledgement_refuses_before_oracle_execution() {
    let _serial = IN_PROCESS_DISCOVERY.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let provider = build_provider(dir.path());
    let mut manifest = p11scope_discover::discover::discover(&provider).unwrap();
    let provider_sha = manifest.objects[0].identity.sha256.as_deref().unwrap();
    manifest
        .provenance_objects
        .retain(|object| object.identity.sha256.as_deref() == Some(provider_sha));
    let manifest_path = dir.path().join("manifest.json");
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

    let observer = dir.path().join("p11scope");
    std::fs::copy(BIN, &observer).unwrap();
    std::fs::set_permissions(&observer, std::fs::Permissions::from_mode(0o755)).unwrap();
    build_manifest_oracle(dir.path(), &manifest_path);

    for command in ["profile", "trace"] {
        let output = Command::new(&observer)
            .args([command, "--manifest"])
            .arg(&manifest_path)
            .arg("--provenance-module")
            .arg(&provider)
            .args(["--pid", &std::process::id().to_string(), "--duration", "0"])
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(1), "{command}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("--trusted-workload"), "{stderr}");
        assert!(!dir.path().join("oracle-ran").exists(), "{command}");
    }
}

#[test]
fn trusted_acknowledgement_does_not_bypass_reuse_validation() {
    let _serial = IN_PROCESS_DISCOVERY.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let provider = build_provider(dir.path());
    let mut manifest = p11scope_discover::discover::discover(&provider).unwrap();
    let provider_sha = manifest.objects[0].identity.sha256.as_deref().unwrap();
    manifest
        .provenance_objects
        .retain(|object| object.identity.sha256.as_deref() == Some(provider_sha));
    let manifest_path = dir.path().join("manifest.json");
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let replacement = dir.path().join("replacement.so");
    std::fs::copy("/bin/false", &replacement).unwrap();
    std::fs::rename(replacement, &provider).unwrap();

    let observer = dir.path().join("p11scope");
    std::fs::copy(BIN, &observer).unwrap();
    std::fs::set_permissions(&observer, std::fs::Permissions::from_mode(0o755)).unwrap();
    build_manifest_oracle(dir.path(), &manifest_path);

    let output = Command::new(observer)
        .args(["profile", "--manifest"])
        .arg(&manifest_path)
        .arg("--provenance-module")
        .arg(&provider)
        .args([
            "--pid",
            &std::process::id().to_string(),
            "--trusted-workload",
            "--duration",
            "0",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("current files"), "{stderr}");
    assert!(!dir.path().join("oracle-ran").exists());
}

#[test]
fn standalone_discover_rejects_trusted_workload_acknowledgement() {
    let output = Command::new(BIN)
        .args([
            "discover",
            "--trusted-workload",
            "--module",
            "/dev/null",
            "--helper",
            "/definitely/missing/p11scope-discover",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unknown argument: --trusted-workload")
    );
}
