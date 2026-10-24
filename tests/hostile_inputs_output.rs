//! SPDX-License-Identifier: GPL-3.0-or-later
//! Hostile output/path regression tests: symlinked, special-file and
//! unusable destinations are refused before any capture bytes exist, a
//! failed or abandoned publish keeps the existing destination byte-exact,
//! and replacement is atomic (the destination holds the old or the new
//! bytes, never a mixture). Temporary files stay private while open.

use p11scope::output::{AtomicFile, create_private_stream};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

fn workdir(name: &str) -> PathBuf {
    let base = std::env::var("TMPDIR").unwrap_or_else(|_| {
        std::env::var("CARGO_TARGET_TMPDIR").expect("TMPDIR or CARGO_TARGET_TMPDIR")
    });
    let dir = PathBuf::from(base).join(format!("hostile-output-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

fn temp_names(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".p11scope.") && name.ends_with(".tmp"))
        })
        .collect()
}

#[test]
fn committed_publish_replaces_atomically() {
    let dir = workdir("baseline");
    let dest = dir.join("report.json");
    std::fs::write(&dest, b"old bytes").unwrap();
    let mut file = AtomicFile::create(&dest).expect("create over a regular file must succeed");
    file.file().write_all(b"new bytes").unwrap();
    file.commit().expect("commit must succeed");
    assert_eq!(std::fs::read(&dest).unwrap(), b"new bytes");
    assert!(
        temp_names(&dir).is_empty(),
        "no temp file may survive commit"
    );
}

#[test]
fn abandoned_publish_keeps_the_destination() {
    let dir = workdir("abandon");
    let dest = dir.join("report.json");
    std::fs::write(&dest, b"old bytes").unwrap();
    {
        let mut file = AtomicFile::create(&dest).expect("create must succeed");
        file.file().write_all(b"unpublished bytes").unwrap();
        // Drop without commit: the temp file is unlinked, the destination kept.
    }
    assert_eq!(std::fs::read(&dest).unwrap(), b"old bytes");
    assert!(
        temp_names(&dir).is_empty(),
        "no temp file may survive abandonment"
    );
    // Abandoning a publish to an absent name creates nothing.
    let absent = dir.join("absent.json");
    {
        let mut file = AtomicFile::create(&absent).expect("create must succeed");
        file.file().write_all(b"unpublished bytes").unwrap();
    }
    assert!(!absent.exists(), "abandoned publish must create nothing");
    assert!(temp_names(&dir).is_empty());
}

#[test]
fn symlink_fifo_and_special_destinations_are_refused() {
    let dir = workdir("special");
    let target = dir.join("target.txt");
    std::fs::write(&target, b"target bytes").unwrap();
    // A symlink destination is refused; the link target is untouched.
    for (label, link) in [
        ("inside", dir.join("link.json")),
        ("dangling", dir.join("dangle.json")),
    ] {
        let target_path = if label == "inside" {
            target.clone()
        } else {
            dir.join("nowhere.txt")
        };
        std::os::unix::fs::symlink(&target_path, &link).unwrap();
        let error = AtomicFile::create(&link)
            .err()
            .expect("symlink destination must be refused");
        assert!(
            !error.is_empty(),
            "{label} symlink refusal must explain itself"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"target bytes");
        assert!(temp_names(&dir).is_empty());
        std::fs::remove_file(&link).unwrap();
    }
    // FIFOs, directories and directory spellings are refused without blocking.
    let fifo = dir.join("pipe.json");
    assert_eq!(
        unsafe {
            libc::mkfifo(
                std::ffi::CString::new(fifo.to_str().unwrap())
                    .unwrap()
                    .as_ptr(),
                0o644,
            )
        },
        0
    );
    assert!(
        AtomicFile::create(&fifo).is_err(),
        "FIFO destination must be refused"
    );
    assert!(
        AtomicFile::create(&dir).is_err(),
        "directory destination must be refused"
    );
    let trailing = format!("{}/", dir.join("report.json").display());
    assert!(
        AtomicFile::create(Path::new(&trailing)).is_err(),
        "trailing-slash destination must be refused"
    );
    assert!(
        AtomicFile::create(Path::new("/dev/null")).is_err(),
        "/dev/null must be refused"
    );
    assert!(temp_names(&dir).is_empty());
}

#[test]
fn hardlink_alias_detaches_on_replace() {
    let dir = workdir("hardlink");
    let first = dir.join("first.json");
    let second = dir.join("second.json");
    std::fs::write(&first, b"old bytes").unwrap();
    std::fs::hard_link(&first, &second).unwrap();
    let mut file = AtomicFile::create(&first).expect("create over a hardlink must succeed");
    file.file().write_all(b"new bytes").unwrap();
    file.commit().expect("commit must succeed");
    // Atomic replacement swaps the directory entry: the replaced name shows
    // the new bytes while the alias still shows the old bytes. Neither is
    // ever a mixture.
    assert_eq!(std::fs::read(&first).unwrap(), b"new bytes");
    assert_eq!(std::fs::read(&second).unwrap(), b"old bytes");
}

#[test]
fn failed_commit_keeps_old_or_new_bytes_never_a_mixture() {
    let dir = workdir("commit-fail");
    let dest = dir.join("report.json");
    std::fs::write(&dest, b"old bytes").unwrap();
    let mut file = AtomicFile::create(&dest).expect("create must succeed");
    file.file().write_all(b"new bytes").unwrap();
    // Revoking directory write permission fails the rename for anyone but
    // root; root still renames and the atomicity property covers both.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    let committed = file.commit();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    if is_root() {
        assert!(committed.is_ok(), "root renames despite the mode bit");
    } else {
        assert!(
            committed.is_err(),
            "unwritable directory must fail the commit"
        );
    }
    let after = std::fs::read(&dest).unwrap();
    assert!(
        after == b"old bytes" || after == b"new bytes",
        "destination must be old or new bytes, got {after:?}"
    );
    // Unlinking was impossible while the directory was unwritable, so a
    // temp may survive the failed commit; it must still be a private
    // regular file. Remove it now that the directory is writable again.
    for temp in temp_names(&dir) {
        let metadata = std::fs::metadata(&temp).unwrap();
        assert!(metadata.is_file(), "leftover temp must be a regular file");
        assert_eq!(
            metadata.permissions().mode() & 0o777,
            0o600,
            "leftover temp must stay owner-only"
        );
        std::fs::remove_file(&temp).unwrap();
    }
}

#[test]
fn tampered_temp_is_refused_and_unlinked() {
    let dir = workdir("tampered-temp");
    let dest = dir.join("report.json");
    std::fs::write(&dest, b"old bytes").unwrap();
    let mut file = AtomicFile::create(&dest).expect("create must succeed");
    file.file().write_all(b"capture bytes").unwrap();
    let temps = temp_names(&dir);
    assert_eq!(temps.len(), 1, "one temp file must exist while open");
    // Widen the temp mode behind the publisher's back: commit must refuse
    // the identity check and the destination must stay byte-exact. Drop is
    // fail-closed — the temp no longer matches the private identity
    // created, so it is left for the operator rather than unlinked.
    std::fs::set_permissions(&temps[0], std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = file.commit().unwrap_err();
    assert!(
        error.contains("identity"),
        "tampered temp must fail identity: {error}"
    );
    assert_eq!(std::fs::read(&dest).unwrap(), b"old bytes");
    let leftovers = temp_names(&dir);
    assert_eq!(leftovers.len(), 1, "tampered temp is left, not unlinked");
    assert_eq!(
        std::fs::metadata(&leftovers[0])
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644,
        "leftover temp keeps its tampered mode for inspection"
    );
    std::fs::remove_file(&leftovers[0]).unwrap();
}

#[test]
fn read_only_directory_refuses_creation() {
    let dir = workdir("readonly");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    let result = AtomicFile::create(&dir.join("report.json"));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    if is_root() {
        // Root bypasses the mode bit; the publish must then complete cleanly.
        let mut file = result.expect("root creates despite the mode bit");
        file.file().write_all(b"root bytes").unwrap();
        file.commit().expect("root commit must succeed");
        assert_eq!(
            std::fs::read(dir.join("report.json")).unwrap(),
            b"root bytes"
        );
    } else {
        assert!(result.is_err(), "unwritable directory must refuse creation");
        assert!(!dir.join("report.json").exists());
    }
}

#[test]
fn temp_file_is_private_while_open() {
    let dir = workdir("temp-private");
    let dest = dir.join("report.json");
    let mut file = AtomicFile::create(&dest).expect("create must succeed");
    let temps = temp_names(&dir);
    assert_eq!(temps.len(), 1, "one temp file must exist while open");
    let metadata = std::fs::metadata(&temps[0]).unwrap();
    assert!(metadata.is_file(), "temp must be a regular file");
    assert_eq!(
        metadata.permissions().mode() & 0o777,
        0o600,
        "temp must be owner-only"
    );
    assert_eq!(
        metadata.uid(),
        unsafe { libc::geteuid() },
        "temp must be owned by the caller"
    );
    file.file().write_all(b"bytes").unwrap();
    file.commit().unwrap();
}

#[test]
fn symlinked_parent_is_not_followed() {
    let dir = workdir("parent-symlink");
    let real = dir.join("real");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, dir.join("link")).unwrap();
    let error = AtomicFile::create(&dir.join("link/report.json"))
        .err()
        .expect("symlinked parent must be refused");
    assert!(!error.is_empty());
    assert!(
        !real.join("report.json").exists(),
        "nothing may be created through the link"
    );
    assert!(temp_names(&dir).is_empty() && temp_names(&real).is_empty());
}

#[test]
fn private_stream_refuses_links_and_fifos() {
    let dir = workdir("stream-special");
    let target = dir.join("target.txt");
    std::fs::write(&target, b"target bytes").unwrap();
    let link = dir.join("link.jsonl");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(
        create_private_stream(&link).is_err(),
        "symlink stream target must be refused"
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"target bytes");
    let fifo = dir.join("pipe.jsonl");
    assert_eq!(
        unsafe {
            libc::mkfifo(
                std::ffi::CString::new(fifo.to_str().unwrap())
                    .unwrap()
                    .as_ptr(),
                0o644,
            )
        },
        0
    );
    assert!(
        create_private_stream(&fifo).is_err(),
        "FIFO stream target must fail, not block"
    );
    assert!(
        create_private_stream(&dir).is_err(),
        "directory stream target must be refused"
    );
}

#[test]
fn private_stream_truncates_only_at_begin() {
    let dir = workdir("stream-begin");
    // A pre-existing target keeps its bytes until begin, then truncates to
    // an owner-only file.
    let dest = dir.join("trace.jsonl");
    std::fs::write(&dest, b"previous run bytes").unwrap();
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o644)).unwrap();
    let stream = create_private_stream(&dest).expect("create over a regular file must succeed");
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        b"previous run bytes",
        "create must not truncate"
    );
    let mut file = stream.begin().expect("begin must succeed");
    file.write_all(b"line\n").unwrap();
    drop(file);
    assert_eq!(std::fs::read(&dest).unwrap(), b"line\n");
    assert_eq!(
        std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
        0o600,
        "begun stream must be owner-only"
    );
    // Dropping before begin leaves a pre-existing target untouched and
    // removes a file created for an absent name.
    std::fs::write(&dest, b"kept bytes").unwrap();
    drop(create_private_stream(&dest).expect("create must succeed"));
    assert_eq!(std::fs::read(&dest).unwrap(), b"kept bytes");
    let absent = dir.join("absent.jsonl");
    drop(create_private_stream(&absent).expect("create must succeed"));
    assert!(
        !absent.exists(),
        "a file created for an absent name must be removed"
    );
}
