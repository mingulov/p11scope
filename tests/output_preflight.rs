//! SPDX-License-Identifier: GPL-3.0-or-later
//! Task 3.3 (F-Scale-6): the output sink is trust-validated before the
//! discovery scan, so a bad `-o` path fails fast instead of after a scan.

use p11scope::attach::BackendSelection;
use p11scope::capture;
use p11scope::cli::{CaptureArgs, Kind, ScopeArg};
use p11scope::discovery::hooks::HookRegistry;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

#[test]
fn untrusted_output_is_refused_before_the_discovery_scan() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    // Group-writable without the sticky bit: untrusted (cf. F-Scale-6's 0775 dir).
    let untrusted = dir.path().join("untrusted");
    std::fs::create_dir(&untrusted).unwrap();
    std::fs::set_permissions(&untrusted, std::fs::Permissions::from_mode(0o775)).unwrap();

    let args = CaptureArgs {
        kind: Kind::Profile,
        modules: Vec::new(),
        // Poison the discovery scan too: this missing manifest is read inside
        // `Engine::discover`, after the sweep — so if the scan ran first, the
        // manifest would be the error. Sink-first means the untrusted dir wins.
        manifests: vec![PathBuf::from("/definitely/not/a/manifest.json")],
        hooks: HookRegistry::builtin(),
        scope: ScopeArg::Pid(std::process::id()),
        metrics: false,
        duration: None,
        out: Some(untrusted.join("observed.json")),
        max_events: None,
        max_scan_pids: None,
        ring_bytes: None,
        drain_interval: None,
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    };
    let error = capture(&args).expect_err("untrusted output must fail the capture");
    let text = format!("{error:#}");
    assert!(text.contains("untrusted"), "{text}");
    assert!(!text.contains("manifest"), "{text}");
}
