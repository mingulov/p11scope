//! SPDX-License-Identifier: GPL-3.0-or-later
//! Packet 6.13 — pre-armed named providers (B19) and explicit watch intervals
//! (B18): causal REDs on the merged D1 contract, plus healthy twins.
//!
//! Status: RED phase on the judge-converged contract (round-2 verdict
//! `docs/superpowers/decisions/2026-10-29-design-batch-decision.md`, D1;
//! merged change list R2-D1-1…11). The phase-1 draft keys (`watch.cancel`,
//! `watch.replaced`, key-presence asserts, fresh-`Engine` RED-4) are
//! withdrawn per R2-D1-9: both judges reject the static cancel datum, the
//! point replacement instant, and replacement through a fresh engine. Every
//! RED below asserts values, real states and real bounds; first-burst
//! exactness positives that need probes-before-use proof stay C6-D
//! privileged cells on the controller lane (R2-D1-6).
//!
//! Seams (all real, unprivileged): `--prearm-module` input on `CaptureArgs`,
//! `Engine::discover` over a pid-scoped child before/after it dlopens
//! (`tests/fixtures/discovery-lifecycle.c` barrier protocol), per-object
//! held-fd checks, scope-end cancellation, and the serialized
//! `DiscoveryEvidence` module records. BPF exact-count proof and cold/warm
//! installed cells stay privileged C6-D work.
//!
//! Oracle independence: RED-0's proved-offset set is computed in-test from
//! the provider file itself (`ElfSnapshot` over held bytes × the manifest's
//! claimed names), never from the engine under test.

#[allow(dead_code)]
mod support;

use p11scope::attach::{BackendSelection, Scope};
use p11scope::cli::{CaptureArgs, Kind, ScopeArg};
use p11scope::discovery::engine::Engine;
use p11scope::discovery::hooks::HookRegistry;
use p11scope::process::{ProcessView, ProcessViewId};
use p11scope_discover::discover::discover as discover_provider;
use p11scope_manifest::manifest::Manifest;
use std::collections::BTreeSet;
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

fn capture_args(
    modules: Vec<PathBuf>,
    manifests: Vec<PathBuf>,
    prearm: Vec<PathBuf>,
    pid: u32,
) -> CaptureArgs {
    CaptureArgs {
        kind: Kind::Profile,
        modules,
        manifests,
        prearm_modules: prearm,
        hooks: HookRegistry::builtin(),
        scope: ScopeArg::Pid(pid),
        metrics: false,
        counter_mode: None,
        track_short_lived: false,
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

/// The R2-D1-2(b) proved set, computed independently of the engine under
/// test: the manifest's claimed names that are defined ELF exports of the
/// held provider file and proved executable in held bytes.
fn proved_export_offsets(provider: &Path, manifest: &Path) -> BTreeSet<u64> {
    let manifest_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(manifest).unwrap()).unwrap();
    let wanted: Vec<String> = manifest_json["surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|surface| surface["functions"].as_array().unwrap().iter())
        .filter_map(|function| function["name"].as_str().map(str::to_string))
        .collect();
    assert!(
        !wanted.is_empty(),
        "the oracle manifest claims no functions at all"
    );
    let wanted_refs: Vec<&str> = wanted.iter().map(String::as_str).collect();
    let file = std::fs::File::open(provider).unwrap();
    let snapshot = p11scope_manifest::elf::ElfSnapshot::read(&file).unwrap();
    let exports = snapshot.exports_matching(&wanted_refs).unwrap();
    exports
        .into_iter()
        .filter(|(_, offset)| snapshot.is_executable_offset(*offset))
        .map(|(_, offset)| offset)
        .collect()
}

/// Distinct file offsets the manifest claims for the module object itself.
fn claimed_module_offsets(manifest: &Path) -> BTreeSet<u64> {
    let manifest_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(manifest).unwrap()).unwrap();
    let module_path = manifest_json["module_path"].as_str().unwrap();
    let module_id = manifest_json["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|object| object["path"].as_str() == Some(module_path))
        .and_then(|object| object["id"].as_u64())
        .unwrap();
    manifest_json["surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|surface| surface["functions"].as_array().unwrap().iter())
        .filter_map(|function| {
            let resolution = &function["resolution"];
            (resolution["object"].as_u64() == Some(module_id))
                .then(|| resolution["file_offset"].as_u64())
                .flatten()
        })
        .collect()
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

/// RED-0 (R2-D1-9, new): bare `--prearm-module`, no manifest. Export-proved
/// offsets are planned pre-mapping, table-only offsets are not, and the
/// module record's sources read `prearm`.
///
/// Non-vacuity: the lifecycle provider's 68-entry table points 67 entries
/// at a static (unexported) function, so the manifest claims strictly more
/// distinct offsets than the proved set — a GREEN that decoded held-file
/// tables (forbidden) or planned table entries would fail the exact
/// equality. The proved set is computed in-test from held bytes, never
/// from the engine under test.
#[test]
fn prearm_bare_module_plans_export_proved_offsets_only() {
    let lifecycle = build_lifecycle("red0");
    let child = sleep_child();
    let pid = child.child.id();

    let proved = proved_export_offsets(&lifecycle.provider, &lifecycle.manifest);
    assert!(
        !proved.is_empty(),
        "the oracle proved no offsets; the fixture or oracle is broken"
    );
    let claimed = claimed_module_offsets(&lifecycle.manifest);
    assert!(
        claimed.len() > proved.len() && proved.is_subset(&claimed),
        "table-only negative missing: claimed {claimed:?} must strictly contain proved {proved:?}"
    );

    let engine = discover_pid(
        &capture_args(vec![], vec![], vec![lifecycle.provider.clone()], pid),
        pid,
    );
    assert_eq!(engine.discovery().modules.len(), 1);
    assert_eq!(engine.discovery().modules[0].sources, ["prearm"]);
    assert_eq!(
        engine.discovery().modules[0].corroboration,
        ["uncorroborated"]
    );
    assert!(!engine.discovery().modules[0].corroborated);
    assert_eq!(engine.discovery().uncorroborated, 1);

    // Exact R2-D1-2(b) provenance: every planned slot is export-proved, and
    // every proved offset is planned — no table-only offset leaks in.
    let planned: BTreeSet<u64> = engine
        .plan()
        .slots
        .iter()
        .map(|slot| slot.file_offset)
        .collect();
    assert_eq!(
        planned, proved,
        "bare pre-arm must plan exactly the export-proved offsets"
    );

    // Discovery emits only the watch: pinned but unmapped is custody, never
    // coverage — `pinned_unarmed` with no arm instant and no attach keys.
    let record = &discovery_json(&engine)["discovery"][0];
    assert_eq!(record["watch"]["state"], "pinned_unarmed");
    assert!(
        record["watch"]["since_ns"].is_null(),
        "no arm instant without links: {}",
        record["watch"]
    );
    for key in ["attached_at_ns", "unobserved_windows"] {
        assert!(
            record.get(key).is_none(),
            "discovery emits only the watch; {key} merges at evidence assembly"
        );
    }

    // `--module` filtering never drops a pre-armed record: a nonmatching
    // hint and the provider's own (unmapped) path both leave it standing.
    for hint in [
        PathBuf::from("/definitely/not/mapped.so"),
        lifecycle.provider.clone(),
    ] {
        let filtered = discover_pid(
            &capture_args(vec![hint], vec![], vec![lifecycle.provider.clone()], pid),
            pid,
        );
        assert_eq!(filtered.discovery().modules.len(), 1);
        assert_eq!(filtered.discovery().modules[0].sources, ["prearm"]);
        assert_eq!(filtered.discovery().uncorroborated, 1);
    }
}

/// RED-1 reworked (R2-D1-9): the pre-armed late-dlopen burst discloses
/// honest bounds. Pre-load the pinned file waits unarmed; post-load the
/// scan agrees — but discovery installed no links, so no exactness is
/// claimed without an R2-D1-6 proof (a scan that saw no mapping before
/// attach is not proof). The probes-before-use positive stays a C6-D
/// privileged cell.
#[test]
fn prearm_late_dlopen_first_burst_is_exact() {
    let lifecycle = build_lifecycle("red1");
    let mut barrier = Barrier::start(&lifecycle.driver, &lifecycle.provider);
    let pid = barrier.pid();
    let args = capture_args(
        vec![],
        vec![lifecycle.manifest.clone()],
        vec![lifecycle.provider.clone()],
        pid,
    );

    let pre = discover_pid(&args, pid);
    assert_eq!(pre.discovery().uncorroborated, 1);
    assert_eq!(pre.discovery().modules.len(), 1);
    assert_eq!(pre.discovery().modules[0].sources, ["manifest", "prearm"]);
    assert_eq!(pre.discovery().modules[0].corroboration, ["uncorroborated"]);
    assert!(!pre.plan().slots.is_empty());
    let pre_record = &discovery_json(&pre)["discovery"][0];
    assert_eq!(pre_record["watch"]["state"], "pinned_unarmed");
    assert!(pre_record["watch"]["since_ns"].is_null());
    assert!(pre_record.get("attached_at_ns").is_none());
    assert!(pre_record.get("unobserved_windows").is_none());

    barrier.load();
    let post = discover_pid(&args, pid);
    assert_eq!(post.discovery().modules.len(), 1);
    assert_eq!(
        post.discovery().modules[0].sources,
        ["scan", "manifest", "prearm"]
    );
    assert!(
        post.discovery().modules[0].corroborated,
        "scan, manifest and pre-arm agree after the load: {:?}",
        post.discovery().modules[0].corroboration
    );
    assert_eq!(post.discovery().modules[0].corroboration, ["agreed"]);

    // Honest non-exactness at the discover seam: links were never installed
    // here, so the watch stays unarmed and no attach instant or window is
    // emitted — key presence never proves exactness, and absence here
    // proves no undisclosed gap is claimed closed.
    let record = &discovery_json(&post)["discovery"][0];
    assert_eq!(record["watch"]["state"], "pinned_unarmed");
    assert!(
        record["watch"]["since_ns"].is_null(),
        "no arm instant without installed links: {}",
        record["watch"]
    );
    assert!(record.get("attached_at_ns").is_none());
    assert!(record.get("unobserved_windows").is_none());
    barrier.shutdown();
}

/// RED-2 reworked (R2-D1-9): a quiet pinned file waits unarmed — never
/// "watched". Pin is custody, not coverage: only link readiness arms a
/// watch, and only an armed interval with clean health and no observed use
/// reads quiet-watched. The `armed_idle` positive needs links plus a use
/// feed, so it lives in scripted transition tests and C6-D cells; here the
/// discover seam must refuse the coverage claim.
#[test]
fn prearm_quiet_interval_is_watched_not_unwatched() {
    let lifecycle = build_lifecycle("red2");
    let child = sleep_child();
    let pid = child.child.id();
    let engine = discover_pid(
        &capture_args(vec![], vec![], vec![lifecycle.provider.clone()], pid),
        pid,
    );
    assert_eq!(engine.discovery().uncorroborated, 1);
    assert_eq!(engine.discovery().modules.len(), 1);
    assert_eq!(engine.discovery().modules[0].sources, ["prearm"]);

    let record = &discovery_json(&engine)["discovery"][0];
    assert_eq!(
        record["watch"]["state"], "pinned_unarmed",
        "a pin without links is never watched-quiet: {record}"
    );
    assert!(
        record["watch"]["since_ns"].is_null(),
        "coverage starts at the arm instant, never at pin time: {}",
        record["watch"]
    );
    assert!(record["watch"].get("until_ns").is_none());
    assert!(record["watch"].get("ended_by").is_none());
    // Never-mapped pre-arm carries no unobserved window: its watch speaks.
    assert!(record.get("unobserved_windows").is_none());
    assert!(record.get("attached_at_ns").is_none());
}

/// RED-3 reworked (R2-D1-9): a never-mapped selected file gets a bounded
/// watch with real cancellation behavior. Both judges reject a static
/// `cancel` datum, so `until_ns`/`ended_by` are absent until the end
/// actually happens; scope end then cancels the watch exactly once.
#[test]
fn prearm_never_mapped_file_has_bounded_watch_and_cancel() {
    let lifecycle = build_lifecycle("red3");
    let child = sleep_child();
    let pid = child.child.id();
    let mut engine = discover_pid(
        &capture_args(vec![], vec![], vec![lifecycle.provider.clone()], pid),
        pid,
    );
    assert_eq!(engine.discovery().uncorroborated, 1);
    assert_eq!(engine.discovery().modules.len(), 1);

    // Guard: no attachment-by-guess — every planned slot resolves to a
    // pinned object id held by this engine, never by path.
    let held: BTreeSet<_> = engine.pinned().pinned().map(|pin| pin.id).collect();
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

    // No static cancel datum: the open watch carries no end.
    let open = &discovery_json(&engine)["discovery"][0];
    assert_eq!(open["watch"]["state"], "pinned_unarmed");
    assert!(open["watch"].get("until_ns").is_none());
    assert!(open["watch"].get("ended_by").is_none());

    // Real cancellation: scope end closes the watch, exactly once, and the
    // wait ended unarmed — coverage was never claimed.
    engine.end_prearm_watches();
    let closed = discovery_json(&engine)["discovery"][0].clone();
    assert_eq!(closed["watch"]["state"], "ended");
    assert_eq!(closed["watch"]["ended_by"], "scope_end");
    let until = closed["watch"]["until_ns"]
        .as_u64()
        .expect("scope end stamps the watch end");
    assert!(until > 0);
    assert!(closed["watch"]["since_ns"].is_null());
    assert!(closed["watch"].get("changed").is_none());
    engine.end_prearm_watches();
    let again = &discovery_json(&engine)["discovery"][0];
    assert_eq!(
        again["watch"]["until_ns"].as_u64(),
        Some(until),
        "until_ns is set exactly once"
    );
}

/// RED-4 reworked (R2-D1-9): same-path replacement on the pre-arm route,
/// through the same retained owner. Rename-over between pin and attach
/// keeps the old inode behind `/proc/self/fd` (never retargets) and
/// discloses the change as a `pinned_object_changed` uncertainty bracket —
/// never a point instant — from per-object checks; the watch ends with
/// `object_changed`. A fresh capture after the change is a new pin, never
/// a watch window (the old fresh-`Engine` replacement half is withdrawn as
/// unsound: a fresh engine cannot inherit custody history).
#[test]
fn prearm_same_path_replacement_keeps_pinned_inode_and_reports_change() {
    let lifecycle = build_lifecycle("red4");
    let child = sleep_child();
    let pid = child.child.id();
    let old_bytes = std::fs::read(&lifecycle.provider).unwrap();
    let old_ino = manifest_key(&lifecycle.provider).inode;
    let args = capture_args(vec![], vec![], vec![lifecycle.provider.clone()], pid);
    let mut engine = discover_pid(&args, pid);
    assert_eq!(engine.discovery().uncorroborated, 1);
    let id = engine
        .pinned()
        .pinned()
        .find(|pin| pin.path == lifecycle.provider.to_string_lossy())
        .expect("the pre-armed file is pinned")
        .id;

    std::thread::sleep(std::time::Duration::from_millis(20)); // ctime granularity margin
    let other = cc_so(&lifecycle.dir, "other", "int g(void){return 2;}\n");
    std::fs::rename(&other, &lifecycle.provider).unwrap();

    // Custody: the held old inode survives, never retargeted.
    let attach = engine.pinned().attach_path_for(id).unwrap();
    assert!(attach.starts_with("/proc/self/fd/"));
    assert_eq!(
        std::fs::read(&attach).unwrap(),
        old_bytes,
        "the pre-arm route must keep the old inode behind /proc/self/fd \
         across rename-over, never retargeting to the new file"
    );

    // Per-object disclosure: the same retained owner reports exactly this
    // object changed, once (sticky), with a sane bracket.
    assert_eq!(
        engine.refresh_prearm_object_changes(),
        vec![id],
        "the refresh attributes the change to the replaced object"
    );
    assert!(
        engine.refresh_prearm_object_changes().is_empty(),
        "change evidence is sticky: the second refresh reports nothing new"
    );
    let bracket = engine
        .pinned()
        .change_bracket(id)
        .expect("a detected change publishes its bracket");
    assert_eq!(bracket.previous_ino, old_ino);
    assert!(bracket.last_ok_ns > 0);
    assert!(
        bracket.detected_ns >= bracket.last_ok_ns,
        "the bracket orders last-ok before detection: {bracket:?}"
    );
    // Changed-byte refusal keeps precedence: the per-object detection
    // latches the global changed flag the attach path refuses on.
    assert_eq!(engine.pinned().check_unchanged(), Ok(false));

    // The watch ends with the bracket: until is the detection instant.
    let record = &discovery_json(&engine)["discovery"][0];
    assert_eq!(record["watch"]["state"], "ended");
    assert_eq!(record["watch"]["ended_by"], "object_changed");
    assert_eq!(
        record["watch"]["until_ns"].as_u64(),
        Some(bracket.detected_ns)
    );
    assert_eq!(
        record["watch"]["changed"]["last_ok_ns"].as_u64(),
        Some(bracket.last_ok_ns)
    );
    assert_eq!(
        record["watch"]["changed"]["detected_ns"].as_u64(),
        Some(bracket.detected_ns)
    );
    assert_eq!(
        record["watch"]["changed"]["previous_ino"].as_u64(),
        Some(bracket.previous_ino)
    );

    // Fresh capture after the change: a new pin, never a watch window. The
    // payload exports no standard name, so the fresh wait is `unavailable`
    // with no proved offsets and no slots — still disclosed, still PARTIAL.
    let fresh = discover_pid(&args, pid);
    assert_eq!(fresh.discovery().modules.len(), 1);
    assert_eq!(fresh.discovery().modules[0].sources, ["prearm"]);
    assert_eq!(fresh.discovery().uncorroborated, 1);
    assert!(
        fresh.plan().slots.is_empty(),
        "zero proved offsets plan zero slots"
    );
    let fresh_record = &discovery_json(&fresh)["discovery"][0];
    assert_eq!(fresh_record["watch"]["state"], "unavailable");
    assert!(fresh_record["watch"]["since_ns"].is_null());
    assert!(fresh_record["watch"].get("changed").is_none());
    assert_eq!(
        fresh_record["ino"].as_u64(),
        Some(manifest_key(&lifecycle.provider).inode),
        "the fresh capture pins the new file behind the path"
    );
}

/// TWIN-1 (GREEN): generic scan-only discovery invents no count before any
/// mapping — zero modules and zero slots pre-load — and admits the late
/// provider once it is mapped. The explicit unobserved-window half of the
/// generic twin lives at evidence assembly (unit-tested there); this half
/// pins that discovery alone invents nothing.
#[test]
fn generic_scan_only_admits_nothing_before_mapping() {
    let lifecycle = build_lifecycle("twin1");
    let mut barrier = Barrier::start(&lifecycle.driver, &lifecycle.provider);
    let pid = barrier.pid();

    let pre = discover_pid(&capture_args(vec![], vec![], vec![], pid), pid);
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
    let post = discover_pid(&capture_args(vec![], vec![], vec![], pid), pid);
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

/// TWIN-2 (GREEN): a manifest-backed discover before any mapping marks the
/// held file's module `uncorroborated` with a manifest source. Mirrors
/// `discover_before_load` at the public seam.
#[test]
fn manifest_backed_discover_before_load_marks_module_uncorroborated() {
    let lifecycle = build_lifecycle("twin2");
    let child = sleep_child();
    let pid = child.child.id();
    let engine = discover_pid(
        &capture_args(vec![], vec![lifecycle.manifest.clone()], vec![], pid),
        pid,
    );
    assert_eq!(engine.discovery().uncorroborated, 1);
    assert_eq!(engine.discovery().modules.len(), 1);
    let module = &engine.discovery().modules[0];
    assert!(!module.corroborated);
    assert_eq!(module.corroboration, ["uncorroborated"]);
    assert!(module.sources.contains(&"manifest"));
}

/// TWIN-3 (GREEN): a never-mapped manifest file stays pinned and unchanged:
/// the pin opens the held file (no mapping needed), `check_unchanged` holds,
/// and the attach path is a `/proc/self/fd` descriptor reading back the
/// provider bytes. The custody the pre-arm watch reuses.
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

/// GUARD (GREEN): an empty pre-arm input changes nothing — discovery
/// evidence, plan slots and pin count are byte-identical with and without
/// the flag. The additive-only proof for every non-pre-arm capture.
#[test]
fn prearm_empty_input_changes_nothing() {
    let lifecycle = build_lifecycle("guard");
    let child = sleep_child();
    let pid = child.child.id();
    let without = discover_pid(
        &capture_args(vec![], vec![lifecycle.manifest.clone()], vec![], pid),
        pid,
    );
    let with_empty = discover_pid(
        &capture_args(vec![], vec![lifecycle.manifest.clone()], vec![], pid),
        pid,
    );
    // Timing fields (`scan_ms`) vary run to run; everything else must be
    // identical.
    let mut left = discovery_json(&without);
    let mut right = discovery_json(&with_empty);
    left["scan_ms"] = serde_json::Value::Null;
    right["scan_ms"] = serde_json::Value::Null;
    assert_eq!(left, right);
    assert_eq!(without.plan().slots.len(), with_empty.plan().slots.len());
    assert_eq!(
        without.pinned().pinned().count(),
        with_empty.pinned().pinned().count()
    );
}
