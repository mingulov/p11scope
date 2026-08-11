use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_p11scope");

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
    let out = Command::new(BIN)
        .args(["discover", "--module", "/dev/null", "--helper", "/nonexistent/helper"])
        .env("PATH", "/nonexistent")
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("/nonexistent/helper"), "stderr: {err}");
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
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema"], "p11scope-manifest/1");
}

#[test]
fn missing_module_is_usage_error() {
    let out = Command::new(BIN).args(["discover"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}
