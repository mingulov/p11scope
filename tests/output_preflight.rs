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

fn poisoned_profile_args(out: PathBuf) -> CaptureArgs {
    CaptureArgs {
        kind: Kind::Profile,
        modules: Vec::new(),
        // Read inside `Engine::discover`: if discovery ran first, the missing
        // manifest would be the error instead of the output refusal.
        manifests: vec![PathBuf::from("/definitely/not/a/manifest.json")],
        hooks: HookRegistry::builtin(),
        scope: ScopeArg::Pid(std::process::id()),
        metrics: false,
        duration: None,
        out: Some(out),
        max_events: None,
        max_scan_pids: None,
        ring_bytes: None,
        drain_interval: None,
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    }
}

/// HIGH-3 / RB-1: `-o <directory>`, `-o dir/` and `-o <FIFO>` used to pass
/// the preflight and fail (or replace the node) only at publication, after
/// the whole capture. They are refused before the discovery scan now.
#[test]
fn directory_and_special_file_outputs_are_refused_before_the_discovery_scan() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let captures = dir.path().join("captures");
    std::fs::create_dir(&captures).unwrap();
    let mut slashed = captures.clone().into_os_string();
    slashed.push("/");
    let fifo = dir.path().join("null");
    let c_fifo = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);

    for (out, expected) in [
        (captures.clone(), "is a directory"),
        (PathBuf::from(slashed), "names a directory"),
        (fifo.clone(), "a FIFO"),
    ] {
        let error = capture(&poisoned_profile_args(out.clone()))
            .expect_err("a non-file output must fail the capture");
        let text = format!("{error:#}");
        assert!(text.contains(expected), "{}: {text}", out.display());
        assert!(!text.contains("manifest"), "{}: {text}", out.display());
    }
    use std::os::unix::fs::FileTypeExt as _;
    assert!(
        std::fs::symlink_metadata(&fifo)
            .unwrap()
            .file_type()
            .is_fifo()
    );
    let litter: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .chain(std::fs::read_dir(&captures).unwrap())
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name.to_string_lossy().starts_with(".p11scope."))
        .collect();
    assert!(litter.is_empty(), "{litter:?}");
}

/// M-2: a trace whose capture never starts (here: discovery fails on a
/// missing manifest, after the sink preflight) must not destroy the
/// previous `-o` file. Privilege-independent: discovery fails either way.
#[test]
fn a_failed_trace_keeps_the_previous_output_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let previous = dir.path().join("prior-trace.log");
    std::fs::write(&previous, b"yesterday's trace lines\n").unwrap();
    let fresh = dir.path().join("fresh-trace.log");

    for out in [previous.clone(), fresh.clone()] {
        let mut args = poisoned_profile_args(out);
        args.kind = Kind::Trace;
        args.duration = Some(std::time::Duration::from_secs(1));
        let error = capture(&args).expect_err("the poisoned manifest fails discovery");
        let text = format!("{error:#}");
        assert!(text.contains("manifest"), "{text}");
    }
    assert_eq!(
        std::fs::read(&previous).unwrap(),
        b"yesterday's trace lines\n"
    );
    assert!(
        std::fs::symlink_metadata(&fresh).is_err(),
        "a capture that never started left {}",
        fresh.display()
    );
}
