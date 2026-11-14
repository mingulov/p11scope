//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! `--output-owner UID[:GID]`: `-o` into directories owned by another
//! user (a container bind mount owned by the host user), with the
//! report handed to that owner.

use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

fn p11scope() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_p11scope"));
    command.stdin(std::process::Stdio::null());
    command
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// A fixture uid that is neither root, the caller, nor the sudo
/// invoker, so only the named leg — never the sudo leg — can accept
/// a directory owned by it.
fn foreign_uid() -> u32 {
    let sudo_uid = std::env::var_os("SUDO_UID")
        .and_then(|value| value.to_str().and_then(|value| value.parse::<u32>().ok()))
        .filter(|uid| *uid != 0 && *uid != u32::MAX);
    [1u32, 2, 3]
        .into_iter()
        .find(|uid| Some(*uid) != sudo_uid)
        .expect("a foreign fixture uid must be available")
}

fn chown(path: &Path, uid: u32, gid: u32) {
    let raw = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::chown(raw.as_ptr(), uid, gid) }, 0);
}

fn seed() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/inventory-diff/scan-current.json")
}

/// A root-owned private dir holding a `foreign`-owned private subdir,
/// like a container bind mount owned by the host user.
fn foreign_mount() -> (tempfile::TempDir, PathBuf, u32) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700)).unwrap();
    let foreign = foreign_uid();
    chown(&out, foreign, foreign);
    (dir, out, foreign)
}

fn assert_handed(path: &Path, uid: u32, gid: u32) {
    let metadata = std::fs::metadata(path).unwrap();
    assert_eq!(metadata.uid(), uid, "{} owner", path.display());
    assert_eq!(metadata.gid(), gid, "{} group", path.display());
    assert_eq!(
        metadata.permissions().mode() & 0o777,
        0o600,
        "{} stays private",
        path.display()
    );
}

#[test]
fn output_owner_without_root_is_refused_like_a_usage_error() {
    if is_root() {
        eprintln!("skipped: this leg refuses only away from root");
        return;
    }
    // Every -o command refuses before anything runs (the inputs below
    // do not exist; the child is never started): exit 2, one cause
    // line plus the topic hint.
    for (argv, hint) in [
        (
            vec![
                "profile",
                "--pid",
                "4242",
                "-o",
                "p.json",
                "--output-owner",
                "1000",
            ],
            "Try 'p11scope profile --help'.",
        ),
        (
            vec![
                "trace",
                "--pid",
                "4242",
                "-o",
                "t.log",
                "--output-owner",
                "1000",
            ],
            "Try 'p11scope trace --help'.",
        ),
        (
            vec![
                "run",
                "-o",
                "r.json",
                "--output-owner",
                "1000",
                "--",
                "/bin/false",
            ],
            "Try 'p11scope run --help'.",
        ),
        (
            vec![
                "inventory",
                "--pid",
                "4242",
                "-o",
                "i.json",
                "--output-owner",
                "1000",
            ],
            "Try 'p11scope inventory --help'.",
        ),
        (
            vec![
                "inventory",
                "diff",
                "before.json",
                "after.json",
                "-o",
                "d.json",
                "--output-owner",
                "1000",
            ],
            "Try 'p11scope inventory diff --help'.",
        ),
        (
            vec![
                "inventory",
                "cbom",
                "input.json",
                "-o",
                "c.json",
                "--output-owner",
                "1000",
            ],
            "Try 'p11scope inventory cbom --help'.",
        ),
    ] {
        let output = p11scope().args(&argv).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{argv:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{argv:?}: {output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("--output-owner 1000:1000 needs root"),
            "{argv:?}: {stderr}"
        );
        assert_eq!(stderr.lines().count(), 2, "cause plus one hint: {stderr}");
        assert_eq!(stderr.lines().last(), Some(hint), "{stderr}");
    }
}

#[test]
fn foreign_owned_directory_refuses_without_the_flag_and_names_it() {
    if !is_root() {
        eprintln!("skipped: needs root");
        return;
    }
    let (_dir, out, foreign) = foreign_mount();
    let seed = seed();
    let report = out.join("report.json");
    let output = p11scope()
        .arg("inventory")
        .arg("diff")
        .arg(&seed)
        .arg(&seed)
        .arg("-o")
        .arg(&report)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("untrusted"), "{stderr}");
    assert!(
        stderr.contains(&format!("--output-owner {foreign}")),
        "the refusal names the exact fix: {stderr}"
    );
    assert!(
        std::fs::read_dir(&out).unwrap().next().is_none(),
        "a refusal creates nothing"
    );
}

#[test]
fn flag_trusts_the_named_owner_and_hands_the_files_over() {
    if !is_root() {
        eprintln!("skipped: needs root");
        return;
    }
    let (_dir, out, foreign) = foreign_mount();
    let third = [1u32, 2, 3]
        .into_iter()
        .find(|uid| *uid != foreign)
        .expect("a second fixture id must be available");
    let seed = seed();
    // UID alone: the gid defaults to the uid.
    let defaulted = out.join("defaulted.json");
    let output = p11scope()
        .arg("inventory")
        .arg("diff")
        .arg(&seed)
        .arg(&seed)
        .arg("-o")
        .arg(&defaulted)
        .arg("--output-owner")
        .arg(foreign.to_string())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_handed(&defaulted, foreign, foreign);
    // An explicit gid, with neither id needing a passwd entry.
    let explicit = out.join("explicit.json");
    let output = p11scope()
        .arg("inventory")
        .arg("diff")
        .arg(&seed)
        .arg(&seed)
        .arg("-o")
        .arg(&explicit)
        .arg("--output-owner")
        .arg(format!("{foreign}:{third}"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_handed(&explicit, foreign, third);
    // The handed-over report is a real diff document.
    let text = std::fs::read_to_string(&explicit).unwrap();
    assert!(text.contains("inventory-diff"), "{text}");
}

#[test]
fn symlink_and_mode_protections_hold_with_the_flag() {
    if !is_root() {
        eprintln!("skipped: needs root");
        return;
    }
    let (_dir, out, foreign) = foreign_mount();
    let seed = seed();
    let owner = foreign.to_string();
    // A symlinked final name is refused and its target untouched.
    let target = out.join("target.json");
    std::fs::write(&target, b"do not touch").unwrap();
    let link = out.join("report.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let output = p11scope()
        .arg("inventory")
        .arg("diff")
        .arg(&seed)
        .arg(&seed)
        .arg("-o")
        .arg(&link)
        .arg("--output-owner")
        .arg(&owner)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(std::fs::read(&target).unwrap(), b"do not touch");
    std::fs::remove_file(&link).unwrap();
    // A symlinked parent is refused too.
    let parent = out.join("parent");
    std::os::unix::fs::symlink(&out, &parent).unwrap();
    let output = p11scope()
        .arg("inventory")
        .arg("diff")
        .arg(&seed)
        .arg(&seed)
        .arg("-o")
        .arg(parent.join("nested.json"))
        .arg("--output-owner")
        .arg(&owner)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    // A world-writable ancestor is refused even with the flag: the
    // mode leg is unchanged, and the flag cannot fix it.
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o777)).unwrap();
    let output = p11scope()
        .arg("inventory")
        .arg("diff")
        .arg(&seed)
        .arg(&seed)
        .arg("-o")
        .arg(out.join("loose.json"))
        .arg("--output-owner")
        .arg(&owner)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("untrusted"), "{stderr}");
    assert!(
        !stderr.contains("--output-owner"),
        "the mode refusal offers no flag: {stderr}"
    );
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn trace_stream_is_handed_over_and_reused_by_a_second_run() {
    if !is_root() {
        eprintln!("skipped: needs root");
        return;
    }
    let (_dir, out, foreign) = foreign_mount();
    let log = out.join("trace.log");
    let owner = foreign.to_string();
    let target = std::process::id().to_string();
    for run in 1..=2 {
        let output = p11scope()
            .arg("trace")
            .arg("--pid")
            .arg(&target)
            .arg("--duration")
            .arg("1s")
            .arg("-o")
            .arg(&log)
            .arg("--output-owner")
            .arg(&owner)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "run {run}: {output:?}");
        assert_handed(&log, foreign, foreign);
    }
    // The second run reused the handed-over file instead of refusing
    // it: the stream holds one run's complete events.
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(text.contains("EVIDENCE"), "{text}");
}

#[test]
fn inventory_scan_hands_the_report_over() {
    if !is_root() {
        eprintln!("skipped: needs root");
        return;
    }
    let (_dir, out, foreign) = foreign_mount();
    let report = out.join("inventory.json");
    let output = p11scope()
        .arg("inventory")
        .arg("--pid")
        .arg(std::process::id().to_string())
        .arg("--capture")
        .arg("scan")
        .arg("-o")
        .arg(&report)
        .arg("--output-owner")
        .arg(foreign.to_string())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_handed(&report, foreign, foreign);
}
