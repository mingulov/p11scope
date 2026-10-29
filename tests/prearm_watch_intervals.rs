//! SPDX-License-Identifier: GPL-3.0-or-later
//! Packet 6.13 phase 1 — RED tests for pre-armed named providers (B19) and
//! explicit watch intervals (B18), plus healthy twins pinning current behavior.
//!
//! Status: RED phase. The four `prearm_*` tests FAIL at base `00e38b0a`
//! because the pre-arm input route and the additive per-provider interval
//! keys do not exist yet; each twin (`generic_*`, `manifest_*`,
//! `never_mapped_*`) PASSES, proving the seam itself works. No production,
//! CLI or parser code is touched (hard gate: contract precedes syntax).
//!
//! Contract proposal: `docs/notes/2026-10-29-613-phase1-contract-draft.md`
//! (O1 input shape, O2 lifecycle, O3 output keys, O4 allowlist note).
//! Root may rename the proposed keys; the RED asserts name the draft keys.
//!
//! Seams (all real, unprivileged): `Engine::discover` over a pid-scoped
//! child before/after it dlopens (`tests/fixtures/discovery-lifecycle.c`
//! barrier protocol), manifest pinning (`pin_manifest_objects`), and the
//! serialized `DiscoveryEvidence` module records. BPF exact-count proof and
//! cold/warm installed cells stay privileged C6-D work on the controller lane.

#[allow(dead_code)]
mod support;

use p11scope::attach::{BackendSelection, Scope};
use p11scope::cli::{CaptureArgs, Kind, ScopeArg};
use p11scope::discovery::engine::Engine;
use p11scope::discovery::hooks::HookRegistry;
use p11scope::process::{ProcessView, ProcessViewId};
use p11scope_discover::discover::discover as discover_provider;
use p11scope_manifest::manifest::Manifest;
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn tmpdir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("prearm-613-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn gcc(output: &Path, source: &Path, extra: &[&str], libs: &[&str]) {
    let mut cmd = Command::new("gcc");
    cmd.args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .args(extra)
        .arg(source)
        .arg("-o")
        .arg(output)
        .args(libs);
    assert!(
        cmd.status().unwrap().success(),
        "compile {}",
        output.display()
    );
}

/// Offline attestation for a provider, via the real discover helper (the
/// same call the `discovery::engine::tests` lifecycle fixture makes in its
/// isolated manifest helper). The observer never executes provider code.
fn write_manifest(dir: &Path, provider: &Path) -> PathBuf {
    let manifest: Manifest = discover_provider(provider)
        .unwrap_or_else(|error| panic!("discover {}: {error}", provider.display()));
    let path = dir.join("provider.json");
    std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    path
}

fn capture_args(modules: Vec<PathBuf>, manifests: Vec<PathBuf>, pid: u32) -> CaptureArgs {
    CaptureArgs {
        kind: Kind::Profile,
        modules,
        manifests,
        hooks: HookRegistry::builtin(),
        scope: ScopeArg::Pid(pid),
        metrics: false,
        counter_mode: None,
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

fn discover_pid(args: &CaptureArgs, pid: u32) -> Engine {
    let view = ProcessView::open(ProcessViewId(0), pid).expect("retain the pid view");
    Engine::discover(args, &Scope::Pid(pid), Some(view)).expect("unprivileged pid discover")
}

fn discovery_json(engine: &Engine) -> serde_json::Value {
    serde_json::to_value(engine.discovery()).expect("discovery evidence serializes")
}

fn manifest_key(path: &Path) -> p11scope_manifest::maps::ObjectKey {
    let file = p11scope_manifest::identity::open_object(path).unwrap();
    let key = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
    p11scope_manifest::maps::ObjectKey {
        device: p11scope_manifest::maps::Device {
            major: key.device_major,
            minor: key.device_minor,
        },
        inode: key.inode,
    }
}

/// A throwaway shared object (never attested, never discovered): rename-over
/// payload for the replacement tests.
fn cc_so(dir: &Path, name: &str, body: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, body).unwrap();
    let so = dir.join(format!("{name}.so"));
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&so)
            .arg(&src)
            .status()
            .unwrap()
            .success()
    );
    so
}

struct Lifecycle {
    dir: PathBuf,
    driver: PathBuf,
    provider: PathBuf,
    manifest: PathBuf,
}

/// The `tests/fixtures/discovery-lifecycle.c` provider (68-entry file-backed
/// 2.40 table) plus its acknowledged loader driver and offline manifest.
fn build_lifecycle(name: &str) -> Lifecycle {
    let dir = tmpdir(name);
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/discovery-lifecycle.c");
    let provider = dir.join("lifecycle-provider.so");
    let driver = dir.join("lifecycle-driver");
    gcc(
        &provider,
        &source,
        &["-shared", "-fPIC", "-DDISCOVERY_LIFECYCLE_PROVIDER"],
        &["-ldl"],
    );
    gcc(&driver, &source, &[], &["-ldl"]);
    let manifest = write_manifest(&dir, &provider);
    Lifecycle {
        dir,
        driver,
        provider,
        manifest,
    }
}

/// The acknowledged loader behind its pre-load barrier: `READY <pid>`,
/// `L` → `LOADED <pid> <dev> <ino> 68`, `X` → clean exit. Drop terminates.
struct Barrier {
    guard: support::ChildGuard,
    stdout: std::process::ChildStdout,
    pid: u32,
}

impl Barrier {
    fn start(driver: &Path, provider: &Path) -> Self {
        let mut guard = support::ChildGuard::new(
            Command::new(driver)
                .arg(provider)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("start the owned loader behind its pre-load barrier"),
        );
        let pid = guard.child.id();
        let mut barrier = Self {
            stdout: guard.child.stdout.take().unwrap(),
            guard,
            pid,
        };
        assert_eq!(barrier.read_ack(), format!("READY {pid}\n"));
        barrier
    }

    fn read_ack(&mut self) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut ack = Vec::new();
        while !ack.ends_with(b"\n") {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero() && ack.len() < 256,
                "bounded fixture acknowledgement: {ack:?}"
            );
            assert!(support::poll_fd(self.stdout.as_raw_fd(), remaining).unwrap());
            let mut byte = [0];
            assert_eq!(
                self.stdout.read(&mut byte).unwrap(),
                1,
                "fixture exited before acknowledgement: {ack:?}"
            );
            ack.push(byte[0]);
        }
        String::from_utf8(ack).unwrap()
    }

    fn load(&mut self) {
        self.guard
            .child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"L")
            .unwrap();
        let ack = self.read_ack();
        assert!(
            ack.starts_with(&format!("LOADED {} ", self.pid)) && ack.ends_with(" 68\n"),
            "unexpected load acknowledgement: {ack:?}"
        );
    }

    fn pid(&self) -> u32 {
        self.pid
    }

    fn shutdown(&mut self) {
        if let Some(stdin) = self.guard.child.stdin.as_mut() {
            let _ = stdin.write_all(b"X");
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match self.guard.child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            }
        }
    }
}

/// A live pid that maps nothing of ours: the never-mapped scope member.
fn sleep_child() -> support::ChildGuard {
    support::ChildGuard::new(
        Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

/// TWIN-1 (GREEN): generic scan-only discovery invents no count before any
/// mapping — zero modules and zero slots pre-load — and admits the late
/// provider once it is mapped. This is the currently-true half of the
/// brief's generic twin (no invented count); the explicit unobserved-window
/// half is the O3 addition RED-1 pins as missing.
#[test]
fn generic_scan_only_admits_nothing_before_mapping() {
    let lifecycle = build_lifecycle("twin1");
    let mut barrier = Barrier::start(&lifecycle.driver, &lifecycle.provider);
    let pid = barrier.pid();

    let pre = discover_pid(&capture_args(vec![], vec![], pid), pid);
    assert!(
        pre.discovery().modules.is_empty(),
        "scan-only pre-load admits nothing: {:?}",
        pre.discovery().modules
    );
    assert!(
        pre.plan().slots.is_empty(),
        "no invented count before any mapping"
    );
    assert_eq!(pre.discovery().uncorroborated, 0);

    barrier.load();
    let post = discover_pid(&capture_args(vec![], vec![], pid), pid);
    assert_eq!(post.discovery().modules.len(), 1);
    assert!(
        !post.discovery().modules[0].corroborated,
        "scan-only stays single-source"
    );
    assert_eq!(post.discovery().modules[0].sources, ["scan"]);
    assert!(
        !post.plan().slots.is_empty(),
        "the mapped provider is admitted with real slots"
    );
    barrier.shutdown();
}

/// RED-1 (FAILS): late-dlopen first-call burst is exact for a pre-armed
/// provider. Probes precede the mapping, so after the load the module
/// record must carry explicit exactness — an attach instant at or before
/// the mapping, or an explicitly empty unobserved window — never a silent
/// count and never an undisclosed gap. Contract rows O2/O3.
#[test]
fn prearm_late_dlopen_first_burst_is_exact() {
    let lifecycle = build_lifecycle("red1");
    let mut barrier = Barrier::start(&lifecycle.driver, &lifecycle.provider);
    let pid = barrier.pid();

    // Setup: the manifest pins the held file before any mapping (mirrors
    // `discover_before_load`). These asserts pass at base.
    let pre = discover_pid(
        &capture_args(vec![], vec![lifecycle.manifest.clone()], pid),
        pid,
    );
    assert_eq!(pre.discovery().uncorroborated, 1);
    assert_eq!(pre.discovery().modules.len(), 1);
    assert!(!pre.discovery().modules[0].corroborated);
    assert_eq!(pre.discovery().modules[0].corroboration, ["uncorroborated"]);
    eprintln!(
        "RED-1 diagnosis: pre-load plan holds {} slots for the pinned-but-unmapped file",
        pre.plan().slots.len()
    );

    barrier.load();
    let post = discover_pid(
        &capture_args(vec![], vec![lifecycle.manifest.clone()], pid),
        pid,
    );
    assert_eq!(post.discovery().modules.len(), 1);
    assert!(
        post.discovery().modules[0].corroborated,
        "scan and manifest agree after the load: {:?}",
        post.discovery().modules[0].corroboration
    );
    assert_eq!(post.discovery().modules[0].corroboration, ["agreed"]);

    // RED: explicit first-burst exactness on the module record.
    let record = &discovery_json(&post)["discovery"][0];
    assert!(
        record.get("attached_at_ns").is_some() || record.get("unobserved_windows").is_some(),
        "RED-1: a pre-armed late-dlopen burst must read exact via an explicit \
         attach instant or an explicit (possibly empty) unobserved window; \
         record keys today: {:?}",
        record
            .as_object()
            .map(|object| object.keys().collect::<Vec<_>>())
    );
    barrier.shutdown();
}

/// TWIN-2 (GREEN): a manifest-backed discover before any mapping marks the
/// held file's module `uncorroborated` with a manifest source. Mirrors
/// `discover_before_load` at the public seam.
#[test]
fn manifest_backed_discover_before_load_marks_module_uncorroborated() {
    let lifecycle = build_lifecycle("twin2");
    let child = sleep_child();
    let pid = child.child.id();
    let engine = discover_pid(
        &capture_args(vec![], vec![lifecycle.manifest.clone()], pid),
        pid,
    );
    assert_eq!(engine.discovery().uncorroborated, 1);
    assert_eq!(engine.discovery().modules.len(), 1);
    let module = &engine.discovery().modules[0];
    assert!(!module.corroborated);
    assert_eq!(module.corroboration, ["uncorroborated"]);
    assert!(module.sources.contains(&"manifest"));
}

/// RED-2 (FAILS): a quiet watched interval is watched, not unwatched. A
/// pinned file with no calls in the window must render an explicit quiet
/// watch (`watch.state`), distinct from an unwatched window. Today the
/// record carries no watch interval at all. Contract rows O2/O3.
#[test]
fn prearm_quiet_interval_is_watched_not_unwatched() {
    let lifecycle = build_lifecycle("red2");
    let child = sleep_child();
    let pid = child.child.id();
    // Setup (passes): the never-called pinned file is recorded.
    let engine = discover_pid(
        &capture_args(vec![], vec![lifecycle.manifest.clone()], pid),
        pid,
    );
    assert_eq!(engine.discovery().uncorroborated, 1);
    assert_eq!(engine.discovery().modules.len(), 1);

    // RED: the explicit quiet-watch interval.
    let record = &discovery_json(&engine)["discovery"][0];
    let state = record.get("watch").and_then(|watch| watch.get("state"));
    assert!(
        state.is_some(),
        "RED-2: a quiet pinned file must render an explicit watched-quiet \
         interval (`watch.state`), distinct from an unwatched window; \
         record keys today: {:?}",
        record
            .as_object()
            .map(|object| object.keys().collect::<Vec<_>>())
    );
}

/// TWIN-3 (GREEN): a never-mapped manifest file stays pinned and unchanged:
/// the pin opens the held file (no mapping needed), `check_unchanged` holds,
/// and the attach path is a `/proc/self/fd` descriptor reading back the
/// provider bytes. The custody the pre-arm watch will reuse.
#[test]
fn never_mapped_manifest_file_stays_pinned_and_unchanged() {
    let lifecycle = build_lifecycle("twin3");
    let manifest = discover_provider(&lifecycle.provider).unwrap();
    let pinned = p11scope::discovery::identity::pin_manifest_objects(&manifest).unwrap();
    assert!(pinned.check_unchanged().unwrap());
    let key = manifest_key(&lifecycle.provider);
    let id = pinned.pinned().find(|pin| pin.key == key).unwrap().id;
    let attach = pinned.attach_path_for(id).unwrap();
    assert!(attach.starts_with("/proc/self/fd/"));
    assert_eq!(
        std::fs::read(&attach).unwrap(),
        std::fs::read(&lifecycle.provider).unwrap(),
        "the attach descriptor reads the held file"
    );
}

/// RED-3 (FAILS): a never-mapped selected file gets a bounded watch with
/// cancel semantics and no attachment-by-guess. The no-guess guard passes
/// today (every slot resolves to a pinned object id, never by path); the
/// bounded-watch record (`watch.cancel`) does not exist yet. Contract O2.
#[test]
fn prearm_never_mapped_file_has_bounded_watch_and_cancel() {
    let lifecycle = build_lifecycle("red3");
    let child = sleep_child();
    let pid = child.child.id();
    // Setup (passes): the never-mapped file is pinned and recorded.
    let engine = discover_pid(
        &capture_args(vec![], vec![lifecycle.manifest.clone()], pid),
        pid,
    );
    assert_eq!(engine.discovery().uncorroborated, 1);
    assert_eq!(engine.discovery().modules.len(), 1);

    // Guard (passes): no attachment-by-guess — every planned slot resolves
    // to a pinned object id held by this engine, never by path.
    let held: std::collections::BTreeSet<_> = engine.pinned().pinned().map(|pin| pin.id).collect();
    assert!(
        !held.is_empty(),
        "the watch is on a held file, not a pathname"
    );
    assert!(
        engine
            .plan()
            .slots
            .iter()
            .all(|slot| held.contains(&slot.object)),
        "every slot attaches into a pinned object"
    );
    eprintln!(
        "RED-3 diagnosis: never-mapped plan holds {} slots over {} pinned objects",
        engine.plan().slots.len(),
        held.len()
    );

    // RED: the bounded watch/cancel record.
    let record = &discovery_json(&engine)["discovery"][0];
    let cancel = record.get("watch").and_then(|watch| watch.get("cancel"));
    assert!(
        cancel.is_some(),
        "RED-3: a never-mapped selected file must carry a bounded watch \
         with cancel semantics (`watch.cancel`); record keys today: {:?}",
        record
            .as_object()
            .map(|object| object.keys().collect::<Vec<_>>())
    );
}

/// TWIN-4 (GREEN): rename-over between pin and attach keeps the old inode
/// behind `/proc/self/fd` and reports a change — via the direct manifest
/// pin route whose worker the pre-arm route reuses. Mirrors the existing
/// `manifest_pinning` rename control.
#[test]
fn manifest_rename_over_keeps_pinned_inode_and_reports_change() {
    let lifecycle = build_lifecycle("twin4");
    let manifest = discover_provider(&lifecycle.provider).unwrap();
    let pinned = p11scope::discovery::identity::pin_manifest_objects(&manifest).unwrap();
    let old_bytes = std::fs::read(&lifecycle.provider).unwrap();
    let key = manifest_key(&lifecycle.provider);
    let id = pinned.pinned().find(|pin| pin.key == key).unwrap().id;
    let attach = pinned.attach_path_for(id).unwrap();
    assert!(attach.starts_with("/proc/self/fd/"));
    std::thread::sleep(std::time::Duration::from_millis(20)); // ctime granularity margin
    let other = cc_so(&lifecycle.dir, "other", "int g(void){return 2;}\n");
    std::fs::rename(&other, &lifecycle.provider).unwrap();
    assert_eq!(
        std::fs::read(&attach).unwrap(),
        old_bytes,
        "the old inode is what we hold"
    );
    assert!(
        !pinned.check_unchanged().unwrap(),
        "rename-over is reported as a change"
    );
}

/// RED-4 (FAILS): same-path replacement on the pre-arm route — rename-over
/// between pin and attach keeps the old inode behind `/proc/self/fd`
/// (never retargets) AND discloses the replacement as a bounded window so
/// the capture continues PARTIAL. Custody asserts pass today; the
/// replacement-window record (`watch.replaced`) does not exist, and a
/// fresh discover may error instead of disclosing. Contract row O2.
#[test]
fn prearm_same_path_replacement_keeps_pinned_inode_and_reports_change() {
    let lifecycle = build_lifecycle("red4");
    let child = sleep_child();
    let pid = child.child.id();
    let old_bytes = std::fs::read(&lifecycle.provider).unwrap();
    // Pin through the engine route the pre-arm path will extend.
    let engine = discover_pid(
        &capture_args(vec![], vec![lifecycle.manifest.clone()], pid),
        pid,
    );
    assert_eq!(engine.discovery().uncorroborated, 1);

    std::thread::sleep(std::time::Duration::from_millis(20)); // ctime granularity margin
    let other = cc_so(&lifecycle.dir, "other", "int g(void){return 2;}\n");
    std::fs::rename(&other, &lifecycle.provider).unwrap();

    // Custody (passes): the held old inode survives, the change is reported.
    let held_old = engine
        .pinned()
        .pinned()
        .filter_map(|pin| engine.pinned().attach_path_for(pin.id).ok())
        .any(|path| std::fs::read(&path).is_ok_and(|bytes| bytes == old_bytes));
    assert!(
        held_old,
        "the pre-arm route must keep the old inode behind /proc/self/fd \
         across rename-over, never retargeting to the new file"
    );
    assert!(
        !engine.pinned().check_unchanged().unwrap(),
        "rename-over is reported as a change"
    );

    // RED: the replacement is disclosed as a bounded window, not an error
    // and not a silent retarget.
    let view = ProcessView::open(ProcessViewId(0), pid).expect("retain the pid view");
    let args = capture_args(vec![], vec![lifecycle.manifest.clone()], pid);
    match Engine::discover(&args, &Scope::Pid(pid), Some(view)) {
        Err(error) => panic!(
            "RED-4: same-path replacement between pin and attach must be \
             disclosed as a bounded replacement window (capture continues, \
             PARTIAL); a fresh discover errors instead: {error}"
        ),
        Ok(replaced) => {
            let json = discovery_json(&replaced);
            let window = json
                .get("discovery")
                .and_then(|modules| modules.get(0))
                .and_then(|record| record.get("watch"))
                .and_then(|watch| watch.get("replaced"));
            assert!(
                window.is_some(),
                "RED-4: the post-replacement record must disclose the bounded \
                 replacement window (`watch.replaced`); evidence today: {json}"
            );
        }
    }
}
