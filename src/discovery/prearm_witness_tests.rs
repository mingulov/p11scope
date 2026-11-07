//! SPDX-License-Identifier: GPL-3.0-or-later
//! Pre-arm witness engine twins (WU-13 P-C phase 2, P2-6): the binding §11
//! list through the real `finish_prearm_capture` with `ScriptedSession` and
//! planted verdicts. Every test asserts exact window lists, never `is_some`.

use super::session_fixture::ScriptedSession;
use super::tests::{
    DiscoveryLifecycleFixture, prearm_mapped_engine_with_declared_stamps, watched_prearm_record,
};
use super::{Engine, WitnessProof};
use crate::attach::prearm_witness::{FileVerdict, KeepReason};
use crate::discovery::identity::PinnedObjectId;
use crate::render::{PrearmWatchEnd, UnobservedReason, UnobservedWindow};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// Today's exact window for the mapped helper (scope 50, stamps 900).
fn pre_attach_window_50_900() -> Vec<UnobservedWindow> {
    vec![UnobservedWindow {
        start_ns: 50,
        end_ns: 900,
        reason: UnobservedReason::PreAttach,
    }]
}

/// The standard terminal finish.
fn finish(engine: &mut Engine, session: &ScriptedSession, owned_run: bool) {
    engine.finish_prearm_capture(
        session,
        PrearmWatchEnd::ScopeEnd,
        &BTreeSet::new(),
        &[],
        Some(5000),
        &crate::metrics::KernelEvidence::default(),
        0,
        None,
        owned_run,
        None,
    );
}

/// A clean proof input for `object` with the pin's held-fd identity
/// mirrored (the condition-4 join domain), the witness active before the
/// scope start and the walk after attach.
fn clean_proof(
    engine: &Engine,
    object: PinnedObjectId,
    scope_start: u64,
    attached_at: u64,
) -> WitnessProof {
    use std::os::unix::fs::MetadataExt as _;
    let meta = engine
        .pinned
        .file_for(object)
        .expect("pin holds an fd")
        .metadata()
        .expect("fstat the held fd");
    WitnessProof {
        verdict: FileVerdict::Clear,
        active_ns: scope_start - 10,
        scope_start_ns: Some(scope_start),
        walk_started_ns: attached_at + 1,
        fd_dev: meta.dev(),
        fd_ino: meta.ino(),
    }
}

fn plant(engine: &mut Engine, object: PinnedObjectId, proof: WitnessProof) {
    engine
        .prearm_witness
        .get_or_insert_with(BTreeMap::new)
        .insert(object, proof);
}

fn watched_object(engine: &Engine) -> PinnedObjectId {
    *engine.prearm.watches().keys().next().expect("one watch")
}

fn record_for_object(engine: &Engine, object: PinnedObjectId) -> &crate::render::DiscoveredModule {
    let module = engine
        .plan
        .modules
        .iter()
        .find(|module| module.object == object)
        .expect("plan module for object");
    engine
        .discovery
        .modules
        .iter()
        .find(|record| record.id == module.id)
        .expect("record for module")
}

/// Bare `--prearm-module` discover for `paths` (never mapped: no load),
/// mirroring the lifecycle fixture's pre-load shape under `metrics` policy.
fn discover_prearm_never_mapped(
    fixture: &DiscoveryLifecycleFixture,
    paths: &[PathBuf],
    metrics: bool,
) -> Engine {
    let pid = fixture.pid();
    let args = crate::cli::CaptureArgs {
        track_short_lived: false,
        verbose: false,
        quiet: false,
        kind: crate::cli::Kind::Profile,
        modules: Vec::new(),
        exclude_modules: Vec::new(),
        manifests: Vec::new(),
        prearm_modules: paths.to_vec(),
        hooks: crate::discovery::hooks::HookRegistry::builtin(),
        scope: crate::cli::ScopeArg::Pid(pid),
        metrics,
        counter_mode: None,
        select_endpoint: None,
        duration: None,
        out: None,
        max_events: None,
        max_scan_pids: None,
        ring_bytes: None,
        drain_interval: None,
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: crate::attach::BackendSelection::default(),
    };
    let view = crate::process::ProcessView::open(crate::process::ProcessViewId(0), pid)
        .expect("retain the owned generation");
    let engine = Engine::discover(&args, &crate::attach::Scope::Pid(pid), Some(view))
        .expect("pre-arm discovery before load");
    assert!(
        engine.modules.is_empty(),
        "the child has not mapped the provider"
    );
    engine
}

/// Script every plan slot's stamp (and link): the declared set is fully
/// stamped, so `attached_at` exists.
fn stamp_all_slots(engine: &Engine, session: &mut ScriptedSession, stamp: u64) {
    for slot in engine.plan.slots.iter() {
        session.scripted_links.insert(slot.index);
        session.scripted_stamps.insert(slot.index, stamp);
    }
}

#[test]
fn witness_clean_verdict_on_mapped_module_empties_window() {
    let (_fixture, mut engine, session, _declared) = prearm_mapped_engine_with_declared_stamps(900);
    let object = watched_object(&engine);
    let proof = clean_proof(&engine, object, 50, 900);
    plant(&mut engine, object, proof);
    finish(&mut engine, &session, false);
    let record = watched_prearm_record(&engine);
    assert_eq!(record.unobserved_windows, Some(Vec::new()));
}

#[test]
fn witness_clean_verdict_on_never_mapped_module_is_some_empty() {
    let fixture = DiscoveryLifecycleFixture::start();
    let provider = fixture.provider_path().to_path_buf();
    let mut engine = discover_prearm_never_mapped(&fixture, &[provider], false);
    assert!(engine.has_prearm_watches());
    assert!(
        !engine.plan.slots.is_empty(),
        "bare pre-arm must plan its proved exports"
    );
    let scope_start = engine
        .prearm
        .scope_start_ns()
        .expect("discover stamps the scope start");
    let mut session = ScriptedSession::default();
    stamp_all_slots(&engine, &mut session, 900);
    let object = watched_object(&engine);
    let proof = clean_proof(&engine, object, scope_start, 900);
    plant(&mut engine, object, proof);
    finish(&mut engine, &session, false);
    let record = watched_prearm_record(&engine);
    assert_eq!(record.unobserved_windows, Some(Vec::new()));
}

#[test]
fn witness_every_keep_reason_keeps_todays_window_when_mapped() {
    // Each of the 12 §6.1 reasons yields today's exact window.
    for reason in KeepReason::all() {
        let (_fixture, mut engine, session, _declared) =
            prearm_mapped_engine_with_declared_stamps(900);
        let object = watched_object(&engine);
        let mut proof = clean_proof(&engine, object, 50, 900);
        proof.verdict = FileVerdict::Keep(reason);
        plant(&mut engine, object, proof);
        finish(&mut engine, &session, false);
        let record = watched_prearm_record(&engine);
        assert_eq!(
            record.unobserved_windows,
            Some(pre_attach_window_50_900()),
            "{} keeps today's window",
            reason.as_str(),
        );
    }
}

#[test]
fn witness_every_keep_reason_stays_absent_when_never_mapped() {
    for reason in KeepReason::all() {
        let fixture = DiscoveryLifecycleFixture::start();
        let provider = fixture.provider_path().to_path_buf();
        let mut engine = discover_prearm_never_mapped(&fixture, &[provider], false);
        let scope_start = engine
            .prearm
            .scope_start_ns()
            .expect("discover stamps the scope start");
        let mut session = ScriptedSession::default();
        stamp_all_slots(&engine, &mut session, 900);
        let object = watched_object(&engine);
        let mut proof = clean_proof(&engine, object, scope_start, 900);
        proof.verdict = FileVerdict::Keep(reason);
        plant(&mut engine, object, proof);
        finish(&mut engine, &session, false);
        let record = watched_prearm_record(&engine);
        assert_eq!(
            record.unobserved_windows,
            None,
            "{} stays absent when never mapped",
            reason.as_str(),
        );
    }
}

#[test]
fn witness_active_at_scope_start_keeps_window() {
    let (_fixture, mut engine, session, _declared) = prearm_mapped_engine_with_declared_stamps(900);
    let object = watched_object(&engine);
    let mut proof = clean_proof(&engine, object, 50, 900);
    proof.active_ns = 50;
    plant(&mut engine, object, proof);
    finish(&mut engine, &session, false);
    let record = watched_prearm_record(&engine);
    assert_eq!(record.unobserved_windows, Some(pre_attach_window_50_900()));
}

#[test]
fn witness_overridden_scope_start_keeps_window() {
    let (_fixture, mut engine, session, _declared) = prearm_mapped_engine_with_declared_stamps(900);
    let object = watched_object(&engine);
    // The engine's scope start reads 50, but the witness recorded a
    // different stamp (the run override moved it): condition 3 fails.
    let mut proof = clean_proof(&engine, object, 50, 900);
    proof.scope_start_ns = Some(51);
    plant(&mut engine, object, proof);
    finish(&mut engine, &session, false);
    let record = watched_prearm_record(&engine);
    assert_eq!(record.unobserved_windows, Some(pre_attach_window_50_900()));
}

#[test]
fn witness_walk_at_attach_keeps_window() {
    let (_fixture, mut engine, session, _declared) = prearm_mapped_engine_with_declared_stamps(900);
    let object = watched_object(&engine);
    let mut proof = clean_proof(&engine, object, 50, 900);
    proof.walk_started_ns = 900;
    plant(&mut engine, object, proof);
    finish(&mut engine, &session, false);
    let record = watched_prearm_record(&engine);
    assert_eq!(record.unobserved_windows, Some(pre_attach_window_50_900()));
}

#[test]
fn witness_partially_stamped_declared_set_keeps_window() {
    let (_fixture, mut engine, mut session, declared) =
        prearm_mapped_engine_with_declared_stamps(900);
    // Unstamp one declared slot (whatever the declared count, the
    // declared-set rule then yields no attached_at).
    session.scripted_stamps.remove(&declared[0]);
    session.scripted_links.remove(&declared[0]);
    let object = watched_object(&engine);
    let proof = clean_proof(&engine, object, 50, 900);
    plant(&mut engine, object, proof);
    finish(&mut engine, &session, false);
    let record = watched_prearm_record(&engine);
    assert_eq!(record.attached_at_ns, Some(None));
    assert_eq!(record.unobserved_windows, None);
}

#[test]
fn witness_pin_identity_mismatch_keeps_window() {
    let (_fixture, mut engine, session, _declared) = prearm_mapped_engine_with_declared_stamps(900);
    let object = watched_object(&engine);
    let mut proof = clean_proof(&engine, object, 50, 900);
    proof.fd_ino ^= 0x9e37;
    proof.fd_dev ^= 0x79b9;
    plant(&mut engine, object, proof);
    finish(&mut engine, &session, false);
    let record = watched_prearm_record(&engine);
    assert_eq!(record.unobserved_windows, Some(pre_attach_window_50_900()));
}

#[test]
fn witness_no_verdict_keeps_window() {
    // No verdict at all: today's exact window (the baseline every Keep
    // case above must equal).
    let (_fixture, mut engine, session, _declared) = prearm_mapped_engine_with_declared_stamps(900);
    assert!(engine.prearm_witness.is_none());
    finish(&mut engine, &session, false);
    let record = watched_prearm_record(&engine);
    assert_eq!(record.unobserved_windows, Some(pre_attach_window_50_900()));
    // A verdict map that names no entry for this object either.
    let (_fixture, mut engine, session, _declared) = prearm_mapped_engine_with_declared_stamps(900);
    engine.prearm_witness = Some(BTreeMap::new());
    finish(&mut engine, &session, false);
    let record = watched_prearm_record(&engine);
    assert_eq!(record.unobserved_windows, Some(pre_attach_window_50_900()));
}

#[test]
fn witness_two_files_found_only_dirties_its_own() {
    let fixture = DiscoveryLifecycleFixture::start();
    // A byte-identical second provider under another name: a distinct
    // object with the same proved exports.
    let second_dir = tempfile::tempdir().expect("second provider dir");
    let second = second_dir.path().join("lifecycle-second.so");
    std::fs::copy(fixture.provider_path(), &second).expect("copy provider");
    let mut engine = discover_prearm_never_mapped(
        &fixture,
        &[fixture.provider_path().to_path_buf(), second],
        false,
    );
    let objects: Vec<PinnedObjectId> = engine.prearm.watches().keys().copied().collect();
    assert_eq!(objects.len(), 2, "two pre-armed files, two watches");
    assert!(
        !engine.plan.slots.is_empty(),
        "bare pre-arm must plan its proved exports"
    );
    let scope_start = engine
        .prearm
        .scope_start_ns()
        .expect("discover stamps the scope start");
    let mut session = ScriptedSession::default();
    stamp_all_slots(&engine, &mut session, 900);
    let clean = clean_proof(&engine, objects[0], scope_start, 900);
    plant(&mut engine, objects[0], clean);
    let mut found = clean_proof(&engine, objects[1], scope_start, 900);
    found.verdict = FileVerdict::Keep(KeepReason::Found);
    plant(&mut engine, objects[1], found);
    finish(&mut engine, &session, false);
    assert_eq!(
        record_for_object(&engine, objects[0]).unobserved_windows,
        Some(Vec::new()),
        "only the clean file clears"
    );
    assert_eq!(
        record_for_object(&engine, objects[1]).unobserved_windows,
        None,
        "the found file stays absent"
    );
}

#[test]
fn witness_proof_keeps_mapped_unattached_window() {
    let (_fixture, mut engine, session, _declared) = prearm_mapped_engine_with_declared_stamps(900);
    // An attached endpoint outside the declared set: clone a slot onto a
    // fresh index and an undeclared offset.
    let object = watched_object(&engine);
    let declared_offsets: BTreeSet<u64> = engine
        .prearm
        .watches()
        .get(&object)
        .expect("watch")
        .declared()
        .iter()
        .map(|key| key.file_offset)
        .collect();
    let template = engine.plan.slots[0].clone();
    let fresh = engine
        .plan
        .slots
        .iter()
        .map(|slot| slot.index)
        .max()
        .expect("slots")
        + 1;
    let mut extra = template;
    extra.index = fresh;
    extra.file_offset = declared_offsets.iter().max().copied().unwrap_or(0) + 0x1000;
    assert!(
        !declared_offsets.contains(&extra.file_offset),
        "the extra slot stays undeclared"
    );
    engine.plan.slots.push(extra);
    let mut session = session;
    session.scripted_links.insert(fresh);
    session.scripted_stamps.insert(fresh, 700);
    let proof = clean_proof(&engine, object, 50, 900);
    plant(&mut engine, object, proof);
    finish(&mut engine, &session, false);
    let record = watched_prearm_record(&engine);
    // The proof kills the base window; the undeclared endpoint keeps its
    // own window next to it.
    assert_eq!(
        record.unobserved_windows,
        Some(vec![UnobservedWindow {
            start_ns: 50,
            end_ns: 700,
            reason: UnobservedReason::MappedUnattached,
        }])
    );
}

#[test]
fn witness_owned_run_session_gets_no_ordering_proof() {
    // Even with a planted clean verdict, an owned run admits no
    // ordering proof (P-B's pause hold is run's only proof).
    let (_fixture, mut engine, session, _declared) = prearm_mapped_engine_with_declared_stamps(900);
    let object = watched_object(&engine);
    let proof = clean_proof(&engine, object, 50, 900);
    plant(&mut engine, object, proof);
    finish(&mut engine, &session, true);
    let record = watched_prearm_record(&engine);
    assert_eq!(record.unobserved_windows, Some(pre_attach_window_50_900()));
}

#[test]
fn witness_metrics_policy_capture_with_stamps_clears() {
    // Ordering proofs need no pause hold: a metrics-policy capture with
    // real declared-set stamps clears.
    let fixture = DiscoveryLifecycleFixture::start();
    let provider = fixture.provider_path().to_path_buf();
    let mut engine = discover_prearm_never_mapped(&fixture, &[provider], true);
    assert!(engine.has_prearm_watches());
    assert!(
        !engine.plan.slots.is_empty(),
        "metrics pre-arm must plan its proved exports"
    );
    let scope_start = engine
        .prearm
        .scope_start_ns()
        .expect("discover stamps the scope start");
    let mut session = ScriptedSession::default();
    stamp_all_slots(&engine, &mut session, 900);
    let object = watched_object(&engine);
    let proof = clean_proof(&engine, object, scope_start, 900);
    plant(&mut engine, object, proof);
    finish(&mut engine, &session, false);
    let record = watched_prearm_record(&engine);
    assert_eq!(record.unobserved_windows, Some(Vec::new()));
}

#[test]
fn witness_verdict_slots_key_to_objects_by_pin_identity() {
    use crate::attach::prearm_witness::{WitnessSlot, WitnessVerdict};
    let (_fixture, engine, _session, _declared) = prearm_mapped_engine_with_declared_stamps(900);
    let object = watched_object(&engine);
    use std::os::unix::fs::MetadataExt as _;
    let meta = engine
        .pinned
        .file_for(object)
        .expect("pin holds an fd")
        .metadata()
        .expect("fstat the held fd");
    let (dev, ino) = (meta.dev(), meta.ino());
    let verdict = WitnessVerdict {
        active_ns: 40,
        scope_start_ns: Some(50),
        walk_started_ns: 1000,
        slots: vec![
            WitnessSlot {
                verdict: FileVerdict::Clear,
                fd_dev: dev,
                fd_ino: ino,
            },
            // An identity no object pins: dropped, never attributed.
            WitnessSlot {
                verdict: FileVerdict::Clear,
                fd_dev: dev ^ 0x79b9,
                fd_ino: ino ^ 0x9e37,
            },
        ],
    };
    let map =
        Engine::map_verdict_slots_to_objects(engine.prearm.watches(), &engine.pinned, &verdict);
    assert_eq!(map.len(), 1);
    let proof = map.get(&object).expect("slot keys to its object");
    assert_eq!(proof.verdict, FileVerdict::Clear);
    assert_eq!(proof.active_ns, 40);
    assert_eq!(proof.scope_start_ns, Some(50));
    assert_eq!(proof.walk_started_ns, 1000);
    assert_eq!(proof.fd_dev, dev);
    assert_eq!(proof.fd_ino, ino);
}

#[test]
fn witness_discover_plants_no_verdicts() {
    // Discover starts (or skips) the live witness, but verdicts only ever
    // come from `start_session` finalize: discover plants none, whether or
    // not startup succeeded on this host.
    let fixture = DiscoveryLifecycleFixture::start();
    let provider = fixture.provider_path().to_path_buf();
    let engine = discover_prearm_never_mapped(&fixture, &[provider], false);
    assert!(engine.has_prearm_watches());
    assert!(
        engine.prearm_witness.is_none(),
        "discover never plants verdicts"
    );
}

#[test]
fn witness_finalize_without_live_witness_is_noop() {
    // Without a live witness (startup unavailable or already consumed),
    // finalize changes nothing on either path.
    let (_fixture, mut engine, _session, _declared) =
        prearm_mapped_engine_with_declared_stamps(900);
    // Hermetic on any host: drop whatever discover started (privileged
    // runs may hold a live witness) and prove the empty arm is a no-op.
    engine.prearm_witness_live = None;
    engine.finalize_prearm_witness(false);
    assert!(engine.prearm_witness.is_none());
    engine.finalize_prearm_witness(true);
    assert!(engine.prearm_witness.is_none());
}

/// Redirects process stderr to `path` until dropped (restores even on
/// panic). Other test threads may interleave; the sentinel asserts
/// absence of unique values, so interleaving is harmless.
struct StderrCapture {
    saved: std::os::fd::OwnedFd,
}

impl StderrCapture {
    fn start(path: &std::path::Path) -> (Self, std::fs::File) {
        use std::os::unix::io::{AsRawFd as _, FromRawFd as _};
        let file = std::fs::File::create(path).expect("stderr capture file");
        // SAFETY: dup of the stderr fd; checked return.
        let saved_raw = unsafe { libc::dup(2) };
        assert!(saved_raw >= 0, "dup stderr");
        // SAFETY: owned dup from the checked call above.
        let saved = unsafe { std::os::fd::OwnedFd::from_raw_fd(saved_raw) };
        // SAFETY: flush C streams before swapping the fd.
        unsafe {
            libc::fflush(std::ptr::null_mut());
        }
        // SAFETY: stderr (fd 2) redirected to the capture file; checked.
        let redirected = unsafe { libc::dup2(file.as_raw_fd(), 2) };
        assert_eq!(redirected, 2, "redirect stderr");
        (Self { saved }, file)
    }
}

impl Drop for StderrCapture {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd as _;
        // SAFETY: restore stderr from the saved dup; best effort.
        unsafe {
            libc::fflush(std::ptr::null_mut());
            libc::dup2(self.saved.as_raw_fd(), 2);
        }
    }
}

#[test]
fn witness_sentinel_values_reach_no_render_or_stderr() {
    // P2-5 contract: a planted verdict with distinctive values renders a
    // profile, a JSONL and a trace shape, captures stderr, and none of
    // the values appear anywhere. Near-`u64::MAX` stamps cannot collide
    // with real monotonic clocks.
    let fixture = DiscoveryLifecycleFixture::start();
    let provider = fixture.provider_path().to_path_buf();
    let mut engine = discover_prearm_never_mapped(&fixture, &[provider], false);
    let scope_start = engine
        .prearm
        .scope_start_ns()
        .expect("discover stamps the scope start");
    let mut session = ScriptedSession::default();
    stamp_all_slots(&engine, &mut session, 900);
    let object = watched_object(&engine);
    let sentinel = WitnessProof {
        verdict: FileVerdict::Clear,
        active_ns: u64::MAX - 101,
        scope_start_ns: Some(scope_start),
        walk_started_ns: u64::MAX - 202,
        fd_dev: u64::MAX - 303,
        fd_ino: u64::MAX - 404,
    };
    plant(&mut engine, object, sentinel);
    let dir = tempfile::tempdir().expect("sentinel dir");
    let stderr_path = dir.path().join("stderr.log");
    let (_capture, _file) = StderrCapture::start(&stderr_path);
    finish(&mut engine, &session, false);
    // Profile: the full discovery evidence as JSON.
    let profile = serde_json::to_string_pretty(&engine.discovery).expect("profile JSON");
    // JSONL: one compact record per line.
    let mut jsonl = String::new();
    for record in &engine.discovery.modules {
        jsonl.push_str(&serde_json::to_string(record).expect("record JSON"));
        jsonl.push('\n');
    }
    // Trace shape: the compact discovery evidence plus the record Debug
    // (what trace headers and diagnostic logs can carry).
    let trace = format!(
        "{}\n{:?}",
        serde_json::to_string(&engine.discovery).expect("trace JSON"),
        engine.discovery.modules,
    );
    drop(_capture);
    let stderr = std::fs::read_to_string(&stderr_path).expect("read stderr");
    for value in [
        sentinel.active_ns,
        sentinel.walk_started_ns,
        sentinel.fd_dev,
        sentinel.fd_ino,
    ] {
        let decimal = value.to_string();
        for (name, text) in [
            ("profile", profile.as_str()),
            ("jsonl", jsonl.as_str()),
            ("trace", trace.as_str()),
            ("stderr", stderr.as_str()),
        ] {
            assert!(
                !text.contains(&decimal),
                "sentinel {decimal} leaks into {name}"
            );
        }
    }
}

#[test]
fn witness_clear_path_emits_no_sentinel_or_reason() {
    // Clear-path twin of the refusal sentinel above: the planted
    // proof passes every ordering condition, so the record publishes
    // the explicitly empty window list, and the distinctive stamps
    // still reach no render or diagnostic. Distinctive but
    // order-valid: active before the scope start, the walk after
    // attach; real monotonic stamps are large, so these decimals
    // cannot collide with scripted small numbers.
    let fixture = DiscoveryLifecycleFixture::start();
    let provider = fixture.provider_path().to_path_buf();
    let mut engine = discover_prearm_never_mapped(&fixture, &[provider], false);
    let scope_start = engine
        .prearm
        .scope_start_ns()
        .expect("discover stamps the scope start");
    let attached_at = scope_start + 1000;
    let mut session = ScriptedSession::default();
    stamp_all_slots(&engine, &mut session, attached_at);
    let object = watched_object(&engine);
    let mut proof = clean_proof(&engine, object, scope_start, attached_at);
    proof.active_ns = scope_start - 101;
    proof.walk_started_ns = attached_at + 202;
    plant(&mut engine, object, proof);
    let dir = tempfile::tempdir().expect("sentinel dir");
    let stderr_path = dir.path().join("stderr.log");
    let (_capture, _file) = StderrCapture::start(&stderr_path);
    finish(&mut engine, &session, false);
    let published = watched_prearm_record(&engine);
    assert_eq!(published.unobserved_windows, Some(Vec::new()));
    // Profile: the full discovery evidence as JSON.
    let profile = serde_json::to_string_pretty(&engine.discovery).expect("profile JSON");
    // JSONL: one compact record per line.
    let mut jsonl = String::new();
    for record in &engine.discovery.modules {
        jsonl.push_str(&serde_json::to_string(record).expect("record JSON"));
        jsonl.push('\n');
    }
    // Trace shape: the compact discovery evidence plus the record Debug
    // (what trace headers and diagnostic logs can carry).
    let trace = format!(
        "{}\n{:?}",
        serde_json::to_string(&engine.discovery).expect("trace JSON"),
        engine.discovery.modules,
    );
    drop(_capture);
    let stderr = std::fs::read_to_string(&stderr_path).expect("read stderr");
    for value in [proof.active_ns, proof.walk_started_ns] {
        let decimal = value.to_string();
        for (name, text) in [
            ("profile", profile.as_str()),
            ("jsonl", jsonl.as_str()),
            ("trace", trace.as_str()),
            ("stderr", stderr.as_str()),
        ] {
            assert!(
                !text.contains(&decimal),
                "sentinel {decimal} leaks into {name}"
            );
        }
    }
    for reason in KeepReason::all() {
        let word = reason.as_str();
        for (name, text) in [
            ("profile", profile.as_str()),
            ("jsonl", jsonl.as_str()),
            ("trace", trace.as_str()),
            ("stderr", stderr.as_str()),
        ] {
            assert!(!text.contains(word), "reason {word} leaks into {name}");
        }
    }
}
