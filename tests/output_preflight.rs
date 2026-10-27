//! SPDX-License-Identifier: GPL-3.0-or-later
//! Task 3.3 (F-Scale-6): the output sink is trust-validated before the
//! discovery scan, so a bad `-o` path fails fast instead of after a scan.

use p11scope::attach::BackendSelection;
use p11scope::capture;
use p11scope::cli::{CaptureArgs, Kind, ScopeArg};
use p11scope::discovery::hooks::HookRegistry;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

#[path = "support/multi_host.rs"]
mod multi_host;

fn assert_failure_stage(text: &str, expected_after_admission: &str, host_refusal: Option<&str>) {
    if let Some(reason) = host_refusal {
        assert_eq!(
            text, reason,
            "host admission must precede sink/discovery work"
        );
    } else {
        assert!(text.contains(expected_after_admission), "{text}");
    }
}

#[test]
fn untrusted_output_is_refused_before_the_discovery_scan() {
    let host_refusal = multi_host::refusal();
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
        counter_mode: None,
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
    assert_failure_stage(&text, "untrusted", host_refusal.as_deref());
    assert!(!text.contains("manifest"), "{text}");
    assert!(std::fs::read_dir(&untrusted).unwrap().next().is_none());
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
        counter_mode: None,
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
    let host_refusal = multi_host::refusal();
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
        assert_failure_stage(&text, expected, host_refusal.as_deref());
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
/// previous `-o` file. OD36 may refuse host admission even earlier; either
/// failure must preserve the previous file and leave a fresh path absent.
#[test]
fn a_failed_trace_keeps_the_previous_output_file() {
    let host_refusal = multi_host::refusal();
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let previous = dir.path().join("prior-trace.log");
    std::fs::write(&previous, b"yesterday's trace lines\n").unwrap();
    let fresh = dir.path().join("fresh-trace.log");

    for out in [previous.clone(), fresh.clone()] {
        let mut args = poisoned_profile_args(out);
        args.kind = Kind::Trace;
        args.duration = Some(std::time::Duration::from_secs(1));
        let error =
            capture(&args).expect_err("host admission or the poisoned manifest refuses capture");
        let text = format!("{error:#}");
        assert_failure_stage(&text, "manifest", host_refusal.as_deref());
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
