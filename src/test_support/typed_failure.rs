// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Typed failure records for known-failing privileged lib tests.
//!
//! The privileged runner points `P11SCOPE_TYPED_FAILURE_PATH` at one empty
//! per-cell path. A known-failing reproducer writes its closed typed branch
//! there before failing; libtest output and log text are never part of the
//! typed signature.

#[allow(dead_code)] // active once the first privileged known-failing row lands
pub(crate) const TYPED_FAILURE_PATH_ENV: &str = "P11SCOPE_TYPED_FAILURE_PATH";

fn write_failure_to_path(signature: &serde_json::Value, path: &std::ffi::OsStr) {
    let encoded = serde_json::to_string(signature).expect("typed signature serializes");
    std::fs::write(path, encoded + "\n").expect("typed failure sidecar must be writable");
}

/// Records the exact typed failure branch for the current cell when the
/// runner supplied a sidecar path. Without the runner there is no typed
/// result stream, so local assertion behavior is unchanged.
#[allow(dead_code)] // active once the first privileged known-failing row lands
pub(crate) fn record_failure(signature: &serde_json::Value) {
    assert!(
        signature
            .as_object()
            .is_some_and(|object| !object.is_empty())
    );
    let Some(path) = std::env::var_os(TYPED_FAILURE_PATH_ENV) else {
        return;
    };
    write_failure_to_path(signature, &path);
}

/// Records `signature` and fails the test without putting semantic state in
/// the panic text. The panic is only the libtest failure trigger; the typed
/// sidecar is the oracle record.
#[allow(dead_code)] // active once the first privileged known-failing row lands
pub(crate) fn fail(signature: serde_json::Value) -> ! {
    record_failure(&signature);
    panic!("typed known-failing oracle fired")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn write_failure_to_path_preserves_the_exact_json_object() {
        let directory =
            std::env::temp_dir().join(format!("p11scope-typed-failure-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("temp dir");
        let path = directory.join("signature.json");
        let signature = json!({"cell":"X","branch":"exactly_one_module"});
        write_failure_to_path(&signature, path.as_os_str());
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("sidecar"))
                .expect("sidecar json");
        assert_eq!(written, signature);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&directory);
    }
}
