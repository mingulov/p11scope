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
    // Explicit --helper is authoritative: should fail immediately without falling through to PATH
    let out = Command::new(BIN)
        .args(["discover", "--module", "/dev/null", "--helper", "/nonexistent/helper"])
        .env("PATH", "/nonexistent")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "should exit 1 for missing explicit helper");
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
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema"], "p11scope-manifest/1");
}

#[test]
fn missing_module_is_usage_error() {
    let out = Command::new(BIN).args(["discover"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
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
        err.contains("cannot dlopen") || err.contains("cannot execute"),
        "error should be from helper trying to load module or not finding module: {err}"
    );
}
