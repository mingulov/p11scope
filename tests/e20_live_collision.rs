//! SPDX-License-Identifier: GPL-3.0-or-later
//! FU-3 (Package E): fixture groundwork for the E20 same-domain /
//! distinct-cookie trigger pair.
//!
//! The reducer-level trigger pair (same EVENTS domain, distinct task
//! cookies, equal module/slot/target-function/async ID, different pending
//! mechanisms) is pinned by `e20_f75_*` in `src/history_tests.rs`. This
//! file carries only unprivileged fixture construction that always runs:
//! two live processes mapping the same provider file.
//!
//! The live E20 same-domain collision check (privileged BPF confirmation
//! of the trigger pair end-to-end) is NOT implemented; it remains an open
//! requirement. Nothing in this file drives the reducer or the kernel.

#[allow(dead_code)]
mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn build_fixture(dir: &Path, name: &str) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/discover/tests/fixture/version_matrix.c");
    let library = dir.join(format!("{name}.so"));
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-DMATRIX_INTERFACES=0", "-o"])
            .arg(&library)
            .arg(source)
            .status()
            .unwrap()
            .success()
    );
    library
}

fn build_driver(dir: &Path) -> PathBuf {
    let driver = dir.join("driver");
    assert!(
        Command::new("gcc")
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-o"])
            .arg(&driver)
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/live-discovery-driver.c")
            )
            .args(["-ldl", "-pthread"])
            .status()
            .unwrap()
            .success()
    );
    driver
}

fn spawn_loaded(driver: &Path, provider: &Path) -> support::ChildGuard {
    use std::io::Read as _;
    use std::os::fd::AsRawFd as _;
    let mut child = support::ChildGuard::new(
        Command::new(driver)
            .arg("dlopen")
            .arg(provider)
            .env_clear()
            .env("P11SCOPE_FIXTURE_INTERFACES", "0")
            .env("P11SCOPE_FIXTURE_POST_GATE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut stderr = child.child.stderr.take().unwrap();
    let mut readiness = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !readiness.ends_with(b"P11SCOPE_FIXTURE driver done\n") {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero() && readiness.len() < 4096);
        assert!(support::poll_fd(stderr.as_raw_fd(), remaining).unwrap());
        let mut byte = [0];
        assert_eq!(
            stderr.read(&mut byte).unwrap(),
            1,
            "fixture exited before ready"
        );
        readiness.extend_from_slice(&byte);
    }
    child
}

fn maps_inode(pid: u32, suffix: &str) -> std::collections::BTreeSet<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .unwrap_or_else(|error| panic!("maps for owned pid {pid} must read: {error}"));
    let mut inodes = std::collections::BTreeSet::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(_range), Some(_perms), Some(_offset), Some(_dev), Some(inode), Some(path)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        if path.ends_with(suffix) {
            if let Ok(inode) = inode.parse::<u64>() {
                inodes.insert(inode);
            }
        }
    }
    inodes
}

/// FU-3 fixture (unprivileged, always runs): two live processes map the
/// same provider file (one shared inode) under distinct PIDs. This checks
/// shared-provider identity only; it does not drive the reducer and does
/// not observe task cookies (kernel-authenticated; the privileged live
/// cell that could observe them is not implemented).
#[test]
fn e20_fu3_fixture_two_processes_share_one_provider_inode() {
    let dir = tmp(&format!("e20-fu3-fixture-{}", std::process::id()));
    let provider = build_fixture(&dir, "mx-fu3");
    let driver = build_driver(&dir);
    let children = [
        spawn_loaded(&driver, &provider),
        spawn_loaded(&driver, &provider),
    ];
    let pids: Vec<u32> = children.iter().map(|guard| guard.child.id()).collect();
    assert_ne!(pids[0], pids[1], "two distinct live tasks");

    let maps0 = maps_inode(pids[0], "mx-fu3.so");
    let maps1 = maps_inode(pids[1], "mx-fu3.so");
    assert_eq!(maps0.len(), 1, "first task maps exactly one file");
    assert_eq!(maps0, maps1, "both tasks share the provider inode");

    // Sanity: C_SignInit resolves to a real function id.
    let target = p11scope::kinds::function_id("C_SignInit").unwrap();
    assert_ne!(target, p11scope_ebpf_common::FUNCTION_NONE);
}
