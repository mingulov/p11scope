//! SPDX-License-Identifier: GPL-3.0-or-later
//! H5 C7 durable late-real-provider cell (unprivileged, always runs).
//!
//! A sustained retained population (eight children on one early provider)
//! is snapshotted, then a late provider and an equal-content different-file
//! copy join the same live population and a second independent snapshot
//! must admit both with actual physical target/offset joins. Attempted
//! service and successful admission are reported separately, and startup
//! and whole-pass timings are reported separately from each other.
//!
//! What this cell pins: late admission follows live mappings (the late
//! provider is absent before any process maps it and present after),
//! identity joins key on the kernel's `(dev, ino)` rendering plus the file
//! digest (never on content alone: the byte-identical copy is a distinct
//! module with its own slots), every planned slot into an owned provider
//! resolves inside that object's bytes, and the run cleans up its
//! children, files and file descriptors.
//!
//! What this cell does NOT pin: 256-request pressure service episodes are
//! unreachable through the public API, so they stay pinned by unit tests
//! over the same loaded-seed-provider machinery instead
//! (`discovery::engine::tests::pressure_all_blocked_fifo_refuses_once_then_advances`,
//! `discovery::engine::tests::pressure_services_unprotected_request_before_original_head`,
//! `discovery::engine::tests::pressure_attempt_rotation_is_finite_and_keeps_serials`).
//! The privileged live BPF pressure lane (sustained 256-request service,
//! inter-drain maximum, pending ages under a live ring) remains root's
//! lane and is an open requirement here, as in `tests/e20_live_collision.rs`.

#[allow(dead_code)]
mod support;

use p11scope::attach::{BackendSelection, Scope};
use p11scope::cli::{CaptureArgs, Kind, ScopeArg};
use p11scope::discovery::engine::Engine;
use p11scope::discovery::hooks::HookRegistry;
use sha2::{Digest as _, Sha256};
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Retained children held across both snapshots: a sustained multi-child
/// population without host-cost excess. The 256-request pressure shape is
/// pinned by the unit tests named above, not by spawning 256 children here.
const RETAINED_CHILDREN: usize = 8;

/// Hang guard per snapshot: discovery of a handful of tiny providers takes
/// seconds; anything past this bound is a hang, not a slow host.
const SNAPSHOT_DEADLINE: Duration = Duration::from_secs(120);

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

/// A native child with one provider dlopened, held until the guard drops.
fn spawn_loaded(driver: &Path, provider: &Path) -> support::ChildGuard {
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

fn system_args(hints: Vec<PathBuf>) -> CaptureArgs {
    CaptureArgs {
        kind: Kind::Profile,
        modules: hints,
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: ScopeArg::System,
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        max_scan_pids: None,
        ring_bytes: None,
        drain_interval: None,
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    }
}

fn sha256_file(path: &Path) -> String {
    Sha256::digest(std::fs::read(path).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn file_name(path: &Path) -> String {
    path.file_name().unwrap().to_string_lossy().into_owned()
}

/// The kernel's rendering of one live mapping: the independent side of the
/// identity join. First mapping in `pid` whose pathname ends with `name`,
/// as `(dev, ino)`.
fn mapping_for(pid: u32, name: &str) -> ((u64, u64), u64) {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .unwrap_or_else(|error| panic!("maps for owned pid {pid} must read: {error}"));
    for line in maps.lines() {
        let fields: Vec<&str> = line.splitn(6, ' ').collect();
        if fields.len() != 6 || !fields[5].ends_with(name) {
            continue;
        }
        let (major, minor) = fields[3].split_once(':').unwrap();
        let dev = (
            u64::from_str_radix(major, 16).unwrap(),
            u64::from_str_radix(minor, 16).unwrap(),
        );
        return (dev, fields[4].parse::<u64>().unwrap());
    }
    panic!("owned pid {pid} maps no object ending with {name}");
}

fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

fn vm_hwm_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest.split_whitespace().next().unwrap().parse().unwrap();
        }
    }
    panic!("VmHWM missing from /proc/self/status");
}

/// A discovered module is admitted with the kernel's identity rendering
/// and the fixture's digest, and every planned slot into it resolves to a
/// target/offset inside the object's own bytes.
fn assert_module_joined(engine: &Engine, pid: u32, object: &Path) {
    let name = file_name(object);
    let (dev, ino) = mapping_for(pid, &name);
    let module = engine
        .discovery()
        .modules
        .iter()
        .find(|module| module.path.ends_with(&name))
        .unwrap_or_else(|| panic!("{name} must be a discovered module"));
    assert_eq!(
        (module.dev, module.ino),
        (dev, ino),
        "{name} joins the kernel's (dev, ino) rendering"
    );
    assert_eq!(
        module.sha256.as_deref(),
        Some(sha256_file(object).as_str()),
        "{name} joins the fixture's digest"
    );
    let len = std::fs::metadata(object).unwrap().len();
    let slots: Vec<_> = engine
        .plan()
        .slots
        .iter()
        .filter(|slot| slot.object_path.ends_with(&name))
        .collect();
    assert!(!slots.is_empty(), "{name} admits at least one planned slot");
    for slot in &slots {
        assert!(
            slot.file_offset < len,
            "{name} slot offset 0x{:x} resolves inside {} bytes",
            slot.file_offset,
            len
        );
    }
    println!(
        "c7: {name} admitted: {} slot(s), ino={ino} sha256={}",
        slots.len(),
        module.sha256.as_deref().unwrap_or("none"),
    );
}

fn assert_module_absent(engine: &Engine, object: &Path) {
    let name = file_name(object);
    assert!(
        !engine
            .discovery()
            .modules
            .iter()
            .any(|module| module.path.ends_with(&name)),
        "nothing maps {name} yet"
    );
    assert!(
        !engine
            .plan()
            .slots
            .iter()
            .any(|slot| slot.object_path.ends_with(&name)),
        "no slot targets unmapped {name}"
    );
}

#[test]
fn pressure_late_provider_admission_with_physical_joins() {
    let wall_start = Instant::now();
    let fds_start = fd_count();
    let dir = tmp(&format!("pressure-late-provider-{}", std::process::id()));
    let early = build_fixture(&dir, "c7-early");
    let late = build_fixture(&dir, "c7-late");
    // Equal content, distinct physical file: a byte copy, never a hardlink.
    let early_copy = dir.join("c7-early-copy.so");
    assert_eq!(
        std::fs::copy(&early, &early_copy).unwrap(),
        std::fs::metadata(&early).unwrap().len()
    );
    assert_eq!(sha256_file(&early), sha256_file(&early_copy));
    assert_ne!(
        std::fs::metadata(&early).unwrap().ino(),
        std::fs::metadata(&early_copy).unwrap().ino(),
        "the copy must be a distinct physical file"
    );
    let driver = build_driver(&dir);
    let hints = vec![early.clone(), late.clone(), early_copy.clone()];

    // Phase 1 (startup): a sustained retained population on the early
    // provider. Hints name all three objects, but admission follows live
    // mappings: the late provider and the copy must stay absent.
    let mut children = Vec::with_capacity(RETAINED_CHILDREN + 2);
    for _ in 0..RETAINED_CHILDREN {
        children.push(spawn_loaded(&driver, &early));
    }
    let early_pid = children[0].child.id();
    let started = Instant::now();
    let engine1 = Engine::discover(&system_args(hints.clone()), &Scope::System, None).unwrap();
    let t_startup = started.elapsed();
    assert!(
        t_startup < SNAPSHOT_DEADLINE,
        "startup snapshot must finish, took {t_startup:?}"
    );
    assert_module_joined(&engine1, early_pid, &early);
    assert_module_absent(&engine1, &late);
    assert_module_absent(&engine1, &early_copy);
    let attempted1 = engine1.plan().entries_seen;
    let admitted1 = engine1.plan().slots.len();
    assert!(admitted1 > 0, "startup admits attachable slots");
    assert!(
        admitted1 <= attempted1,
        "every planned slot derives from a seen record"
    );
    println!("c7: startup attempted={attempted1} admitted={admitted1} in {t_startup:?}");

    // Phase 2 (whole pass): the late provider and the equal-content copy
    // join the same sustained population; one independent snapshot admits
    // both with physical joins while the early provider stays retained.
    children.push(spawn_loaded(&driver, &late));
    let late_pid = children[RETAINED_CHILDREN].child.id();
    children.push(spawn_loaded(&driver, &early_copy));
    let copy_pid = children[RETAINED_CHILDREN + 1].child.id();
    let started = Instant::now();
    let engine2 = Engine::discover(&system_args(hints.clone()), &Scope::System, None).unwrap();
    let t_whole = started.elapsed();
    assert!(
        t_whole < SNAPSHOT_DEADLINE,
        "whole-pass snapshot must finish, took {t_whole:?}"
    );
    assert_module_joined(&engine2, late_pid, &late);
    assert_module_joined(&engine2, copy_pid, &early_copy);
    assert_module_joined(&engine2, early_pid, &early);
    // Equal content, distinct identity: the copy shares the early
    // provider's digest but keeps its own (dev, ino) and its own slots.
    let early_module = engine2
        .discovery()
        .modules
        .iter()
        .find(|module| module.path.ends_with("c7-early.so"))
        .unwrap();
    let copy_module = engine2
        .discovery()
        .modules
        .iter()
        .find(|module| module.path.ends_with("c7-early-copy.so"))
        .unwrap();
    assert_eq!(early_module.sha256, copy_module.sha256);
    assert_ne!(
        (early_module.dev, early_module.ino),
        (copy_module.dev, copy_module.ino),
        "content-identical files keep distinct physical identities"
    );
    let attempted2 = engine2.plan().entries_seen;
    let admitted2 = engine2.plan().slots.len();
    assert!(admitted2 > 0, "the whole pass admits attachable slots");
    assert!(
        admitted2 <= attempted2,
        "every planned slot derives from a seen record"
    );
    println!("c7: whole-pass attempted={attempted2} admitted={admitted2} in {t_whole:?}");
    println!("c7: timing split: startup={t_startup:?} whole-pass={t_whole:?}");

    // Cleanup: every owned child reaps, every owned file goes, and no file
    // descriptor leaks out of the cell.
    let pids: Vec<u32> = children.iter().map(|child| child.child.id()).collect();
    drop(children);
    drop(engine1);
    drop(engine2);
    for pid in &pids {
        assert!(
            std::fs::read_to_string(format!("/proc/{pid}/cmdline")).is_err(),
            "owned child {pid} must reap"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(!dir.exists(), "the cell removes its fixtures");
    let fds_end = fd_count();
    assert!(
        fds_end <= fds_start + 2,
        "no descriptor leak: start={fds_start} end={fds_end}"
    );
    println!(
        "c7: resources: wall={:?} VmHWM={}KiB fds: {fds_start}->{fds_end}",
        wall_start.elapsed(),
        vm_hwm_kb(),
    );
}
