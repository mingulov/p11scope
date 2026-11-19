//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! DR-C5-EDGE: production `edge_observed` records through the real
//! per-pass emitter and the terminal sweep in `finish_output` — only on
//! class changes, capped per pass with a counted deferred carry, a digest
//! per edge bounded by the edge limit, and a replay equal to the snapshot.

use super::*;
use crate::discovery::caller_registry::{
    CallerId, CoverageNote, ImageAuthority, ModuleKey, RegistryLimits,
};
use crate::discovery::engine::inventory_coordinator::PassReport;
use crate::discovery::inventory_workload::{Harness, ScaleSpec};
use crate::inventory_events::{EDGE_EVENTS_PER_PASS, EdgeEmitter, InstanceEmitter, edge_payload};
use crate::inventory_present::EdgeView;

const FIRST_PID: u32 = 91_000;

/// A tempdir the event-writer trust check accepts under any umask:
/// `tempfile` honors the process umask (0775 under the default 0002),
/// and the writer refuses group-writable ancestors.
fn private_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    dir
}

fn harness(callers: usize, modules: usize) -> Harness {
    let mut harness = Harness::new(RegistryLimits::default_limits()).unwrap();
    harness.stage_scale(&ScaleSpec {
        name: "edge-stream",
        callers,
        modules,
        edges_per_caller: modules,
        endpoints_per_module: 4,
        first_pid: FIRST_PID,
    });
    harness.commit();
    harness
}

fn key(index: u64) -> ModuleKey {
    let path = format!("/scale/m{index}.so");
    ModuleKey::physical(8, 1, 100_000 + index, Some(format!("sha{index:06}")), &path)
}

fn caller(harness: &Harness, index: u32) -> CallerId {
    harness
        .coordinator()
        .adapter()
        .live_id(FIRST_PID + index)
        .unwrap()
}

fn presentation(harness: &Harness) -> Presentation {
    let now = harness.now_ns();
    let passes = harness.coordinator().passes();
    Presentation::capture(harness.coordinator(), "workload", 0, now, passes)
}

fn report(pass: u64) -> PassReport {
    PassReport {
        pass,
        scanned: 0,
        maps_matched: 0,
        native_callers: 0,
        scan_callers: 0,
        engine_changed: false,
        pending_refresh: Vec::new(),
        events: Vec::new(),
        timings: crate::timing::StageTimings::new(),
    }
}

fn lines(path: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// The stream's edge replay: the last record per (caller, module), with
/// the three derived states split off.
fn replay(lines: &[serde_json::Value]) -> BTreeMap<(String, String), serde_json::Value> {
    let mut last = BTreeMap::new();
    for line in lines.iter().filter(|line| line["kind"] == "edge_observed") {
        let event = &line["event"];
        last.insert(
            (
                event["caller"].as_str().unwrap().to_string(),
                event["module"].as_str().unwrap().to_string(),
            ),
            event.clone(),
        );
    }
    last
}

fn without_states(event: &serde_json::Value) -> serde_json::Value {
    let mut edge = event.clone();
    for state in ["presence", "capture", "activity", "identity_context"] {
        edge.as_object_mut().unwrap().remove(state);
    }
    edge
}

/// `edge_observed` lines and the pass marker of one emitted pass.
fn pass_lines(all: &[serde_json::Value], pass: u64) -> (usize, serde_json::Value) {
    let marker = all
        .iter()
        .position(|line| line["kind"] == "pass_committed" && line["event"]["pass"] == pass)
        .unwrap();
    let start = all[..marker]
        .iter()
        .rposition(|line| line["kind"] == "pass_committed")
        .map_or(0, |at| at + 1);
    let records = all[start..marker]
        .iter()
        .filter(|line| line["kind"] == "edge_observed")
        .count();
    (records, all[marker]["event"].clone())
}

/// An edge record goes out when the edge is new and again when its
/// coverage, presence, capture, activity or entries class changes — not
/// on a quiet pass, and not for a change outside those classes (that one
/// waits for the sweep). Kills "emit only first sightings".
#[test]
fn edge_records_follow_class_changes_mid_run_not_every_pass() {
    let mut harness = harness(1, 2);
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
    let mut state = StreamState::new();
    let c0 = caller(&harness, 0);
    let mut emit = |harness: &Harness, state: &mut StreamState, pass: u64| {
        let presentation = presentation(harness);
        emit_pass_events(&mut writer, state, &report(pass), &presentation, pass).unwrap();
    };
    // Pass 1: both edges are new.
    emit(&harness, &mut state, 1);
    // Pass 2: nothing changed.
    harness.advance(10);
    emit(&harness, &mut state, 2);
    // Pass 3: m0's coverage changes (a watch starts).
    harness.advance(10);
    let at = harness.now_ns();
    harness.coordinator_mut().registry_mut().note_coverage(
        c0,
        &key(0),
        CoverageNote::Watched { since_ns: at },
    );
    harness.commit();
    emit(&harness, &mut state, 3);
    // Pass 4: m1 is re-seen later: only its mapping instants move.
    harness.advance(10);
    let info = crate::discovery::inventory_workload::scale_module_info(1, 4);
    let now = harness.now_ns();
    harness
        .coordinator_mut()
        .registry_mut()
        .note_mapping(c0, FIRST_PID, info, now);
    harness.commit();
    emit(&harness, &mut state, 4);
    drop(writer);
    let all = lines(&path);
    let counts: Vec<usize> = (1..=4).map(|pass| pass_lines(&all, pass).0).collect();
    assert_eq!(counts, [2, 0, 1, 0], "records per pass");
    for pass in 1..=4u64 {
        let (records, marker) = pass_lines(&all, pass);
        assert_eq!(marker["edge_events"], records, "pass {pass} accounting");
        assert_eq!(marker["edge_events_deferred"], 0);
    }
    let changed: Vec<&serde_json::Value> = all
        .iter()
        .filter(|line| line["kind"] == "edge_observed")
        .map(|line| &line["event"])
        .collect();
    assert_eq!(changed[2]["module"], changed[0]["module"]);
    assert_eq!(changed[2]["entries"]["coverage"]["state"], "watched_no_use");
    assert_eq!(changed[2]["capture"], "armed");
}

/// The terminal sweep in `finish_output` writes whatever changed after the
/// last pass (a stop-time coverage change, non-class mapping instants), so
/// the replay equals the snapshot edges exactly; `ended` counts the sweep.
/// Kills "skip the final sweep".
#[test]
fn the_final_sweep_makes_the_replayed_edges_equal_the_snapshot() {
    let mut harness = harness(2, 2);
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
    let mut state = StreamState::new();
    let first = presentation(&harness);
    emit_pass_events(&mut writer, &mut state, &report(1), &first, 1).unwrap();
    // After the last pass: one class change and one instant-only change.
    harness.advance(50);
    let c0 = caller(&harness, 0);
    let c1 = caller(&harness, 1);
    let at = harness.now_ns();
    harness.coordinator_mut().registry_mut().note_coverage(
        c0,
        &key(1),
        CoverageNote::Watched { since_ns: at },
    );
    let info = crate::discovery::inventory_workload::scale_module_info(0, 4);
    harness
        .coordinator_mut()
        .registry_mut()
        .note_mapping(c1, FIRST_PID + 1, info, at);
    harness.commit();
    let last = presentation(&harness);
    let mut text = Vec::new();
    let outcome = finish_output(
        None,
        &mut EventLogState::new(Some(writer)),
        &mut state,
        &last,
        false,
        false,
        &mut crate::inventory_output::WriterStdout(&mut text),
        None,
        None,
    );
    assert_eq!(outcome.exit_code(), 0);
    assert_eq!(outcome.event_log_confirmed, Some(true));
    let all = lines(&path);
    assert_eq!(all.last().unwrap()["kind"], "ended");
    assert_eq!(all.last().unwrap()["event"]["edge_events"], 2, "swept");
    let document = render_json_from_presentation(&last);
    let snapshot = document["edges"].as_array().unwrap();
    let replayed = replay(&all);
    assert_eq!(replayed.len(), snapshot.len(), "every edge streamed");
    for edge in snapshot {
        let key = (
            edge["caller"].as_str().unwrap().to_string(),
            edge["module"].as_str().unwrap().to_string(),
        );
        assert_eq!(without_states(&replayed[&key]), *edge, "{key:?}");
    }
    // The derived states equal the presentation's (the third consumer, the
    // pager text, renders them from the same view). Full detail: the
    // per-edge lines are verbose-only since CLI-1.
    let _ = String::from_utf8(text).unwrap();
    let text = crate::inventory_present::render_snapshot_with_verbosity(
        &last,
        crate::cli::TextVerbosity::Verbose,
    );
    for edge in &last.edges {
        let event = &replayed[&(edge.caller.label(), edge.module.label())];
        assert_eq!(event["presence"], edge.presence.label());
        assert_eq!(event["capture"], edge.capture.label());
        assert_eq!(event["activity"], edge.activity.label());
        let line = text
            .lines()
            .find(|line| {
                line.starts_with(&format!(
                    "edge {} -> {} ",
                    edge.caller.label(),
                    edge.module.label()
                ))
            })
            .unwrap();
        assert!(
            line.contains(&format!(
                "presence {} capture {} activity {} ",
                edge.presence.label(),
                edge.capture.label(),
                edge.activity.label()
            )),
            "{line}"
        );
    }
    // A sweep over an unchanged stream writes nothing more.
    let mut writer = EventWriter::create(&dir.path().join("again.jsonl"), 1 << 20, 2).unwrap();
    assert_eq!(
        state
            .edges
            .sweep(
                &mut writer,
                &last.edges,
                &IdentityIndex::new(&last),
                last.budgets.edges_limit,
                1,
                0
            )
            .unwrap()
            .emitted,
        0
    );
}

/// `count` synthetic edges cloned from one real view, one caller each.
fn synthetic_edges(count: u32) -> Vec<EdgeView> {
    let harness = harness(1, 1);
    let template = presentation(&harness).edges[0].clone();
    (0..count)
        .map(|index| {
            let mut edge = template.clone();
            edge.caller = CallerId(index);
            edge
        })
        .collect()
}

fn edge_records(path: &std::path::Path) -> Vec<String> {
    lines(path)
        .iter()
        .filter(|line| line["kind"] == "edge_observed")
        .map(|line| line["event"]["caller"].as_str().unwrap().to_string())
        .collect()
}

/// The production cap: 4,096 records per pass, the rest counted as
/// deferred and written on the next pass.
#[test]
fn a_pass_writes_at_most_4096_edge_records_and_defers_the_rest() {
    // Synthetic edge fixtures have no retained caller/module records.
    let identity_revision = presentation(&harness(0, 0));
    let identities = IdentityIndex::new(&identity_revision);
    assert_eq!(EDGE_EVENTS_PER_PASS, 4096);
    let edges = synthetic_edges(5000);
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 30, 2).unwrap();
    let mut emitter = EdgeEmitter::new();
    let first = emitter
        .emit(&mut writer, &edges, &identities, 32_768, 1)
        .unwrap();
    assert_eq!((first.emitted, first.deferred), (4096, 904));
    let second = emitter
        .emit(&mut writer, &edges, &identities, 32_768, 2)
        .unwrap();
    assert_eq!((second.emitted, second.deferred), (904, 0));
    let third = emitter
        .emit(&mut writer, &edges, &identities, 32_768, 3)
        .unwrap();
    assert_eq!((third.emitted, third.deferred), (0, 0));
    drop(writer);
    let records = edge_records(&path);
    assert_eq!(records.len(), 5000);
    let distinct: std::collections::BTreeSet<&String> = records.iter().collect();
    assert_eq!(distinct.len(), 5000, "each edge exactly once");
}

/// Deferred edges are carried first-in first-out: a later change never
/// overtakes an earlier deferred one, each goes out with its state at
/// emission time, and the sweep drains whatever is still waiting.
#[test]
fn deferred_edges_carry_to_the_next_pass_in_arrival_order() {
    // Synthetic edge fixtures have no retained caller/module records.
    let identity_revision = presentation(&harness(0, 0));
    let identities = IdentityIndex::new(&identity_revision);
    let mut edges = synthetic_edges(5);
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
    let mut emitter = EdgeEmitter::with_cap(2);
    let pass = emitter
        .emit(&mut writer, &edges, &identities, 64, 1)
        .unwrap();
    assert_eq!((pass.emitted, pass.deferred), (2, 3));
    // c0 changes class while c2..c4 wait; c3 changes too.
    edges[0].entry_count = 1;
    edges[3].entry_count = 1;
    let pass = emitter
        .emit(&mut writer, &edges, &identities, 64, 2)
        .unwrap();
    assert_eq!((pass.emitted, pass.deferred), (2, 2));
    let pass = emitter
        .emit(&mut writer, &edges, &identities, 64, 3)
        .unwrap();
    assert_eq!((pass.emitted, pass.deferred), (2, 0));
    // One more deferral, then the sweep drains it.
    edges[1].entry_count = 1;
    edges[2].entry_count = 1;
    edges[4].entry_count = 1;
    let pass = emitter
        .emit(&mut writer, &edges, &identities, 64, 4)
        .unwrap();
    assert_eq!((pass.emitted, pass.deferred), (2, 1));
    assert_eq!(
        emitter
            .sweep(&mut writer, &edges, &identities, 64, 5, 0)
            .unwrap()
            .emitted,
        1
    );
    drop(writer);
    let records = edge_records(&path);
    assert_eq!(
        records,
        ["c0", "c1", "c2", "c3", "c4", "c0", "c1", "c2", "c4"],
        "FIFO carry; c3's change rode its first record"
    );
    let all = lines(&path);
    let c3 = all
        .iter()
        .filter(|line| line["kind"] == "edge_observed" && line["event"]["caller"] == "c3")
        .collect::<Vec<_>>();
    assert_eq!(c3.len(), 1);
    assert_eq!(c3[0]["event"]["entries"]["count"], 1, "current state");
}

/// One digest per edge, never more than the edge limit; an edge past the
/// bound is treated as always changed (over-emits, never under-emits).
#[test]
fn edge_digests_are_bounded_by_the_edge_limit() {
    // Synthetic edge fixtures have no retained caller/module records.
    let identity_revision = presentation(&harness(0, 0));
    let identities = IdentityIndex::new(&identity_revision);
    let edges = synthetic_edges(3);
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
    let mut emitter = EdgeEmitter::new();
    for pass in 1..=3 {
        emitter
            .emit(&mut writer, &edges, &identities, 2, pass)
            .unwrap();
        assert_eq!(emitter.tracked(), 2, "bounded by the limit");
    }
    assert_eq!(
        emitter
            .sweep(&mut writer, &edges, &identities, 2, 4, 0)
            .unwrap()
            .emitted,
        1
    );
    assert_eq!(emitter.tracked(), 2);
    drop(writer);
    assert_eq!(
        edge_records(&path),
        ["c0", "c1", "c2", "c2", "c2", "c2"],
        "the untracked edge re-emits; tracked ones stay quiet"
    );
    // The production bound is the registry's edge limit.
    assert_eq!(
        RegistryLimits::default_limits().max_edges,
        crate::discovery::caller_registry::DEFAULT_MAX_EDGES
    );
    assert_eq!(crate::discovery::caller_registry::DEFAULT_MAX_EDGES, 32_768);
}

/// A change that reverts while it waits behind the cap is already what the
/// stream carries: its turn writes nothing and costs no record.
#[test]
fn a_deferred_change_that_reverts_is_not_written() {
    // Synthetic edge fixtures have no retained caller/module records.
    let identity_revision = presentation(&harness(0, 0));
    let identities = IdentityIndex::new(&identity_revision);
    let mut edges = synthetic_edges(2);
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
    let mut emitter = EdgeEmitter::with_cap(1);
    let pass = emitter
        .emit(&mut writer, &edges, &identities, 64, 1)
        .unwrap();
    assert_eq!((pass.emitted, pass.deferred), (1, 1));
    edges[0].entry_count = 1;
    let pass = emitter
        .emit(&mut writer, &edges, &identities, 64, 2)
        .unwrap();
    assert_eq!((pass.emitted, pass.deferred), (1, 1), "c1 first, c0 waits");
    edges[0].entry_count = 0;
    let pass = emitter
        .emit(&mut writer, &edges, &identities, 64, 3)
        .unwrap();
    assert_eq!((pass.emitted, pass.deferred), (0, 0));
    assert_eq!(
        emitter
            .sweep(&mut writer, &edges, &identities, 64, 4, 0)
            .unwrap()
            .emitted,
        0
    );
    drop(writer);
    assert_eq!(edge_records(&path), ["c0", "c1"]);
}

/// Every retained line of the stream at `path` (rotations included).
fn retained_lines(path: &std::path::Path) -> Vec<serde_json::Value> {
    let dir = path.parent().unwrap();
    let live = path.file_name().unwrap().to_string_lossy().into_owned();
    let mut lines = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == live || name.starts_with(&format!("{live}.")) {
            lines.extend(self::lines(&entry.path()));
        }
    }
    lines.sort_by_key(|line| line["seq"].as_u64().unwrap());
    lines
}

/// The last retained `edge_observed` per caller label.
fn retained_edges(path: &std::path::Path) -> BTreeMap<String, serde_json::Value> {
    retained_lines(path)
        .into_iter()
        .filter(|line| line["kind"] == "edge_observed")
        .map(|line| {
            (
                line["event"]["caller"].as_str().unwrap().to_string(),
                line["event"].clone(),
            )
        })
        .collect()
}

/// Review M-1, probe 1: an unchanged edge whose only record rotated out
/// mid-run (4 KiB x 2 files; c1 changes on 198 passes) is re-sent by the
/// sweep, so every edge keeps a retained record equal to its state (it
/// used to read "swept 0; retained c1").
#[test]
fn the_sweep_resends_an_unchanged_edge_whose_record_was_evicted() {
    // Synthetic edge fixtures have no retained caller/module records.
    let identity_revision = presentation(&harness(0, 0));
    let identities = IdentityIndex::new(&identity_revision);
    let mut edges = synthetic_edges(2);
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 4096, 2).unwrap();
    let mut emitter = EdgeEmitter::new();
    emitter
        .emit(&mut writer, &edges, &identities, 64, 1)
        .unwrap();
    for pass in 2..200u64 {
        edges[1].entry_count = pass % 2;
        emitter
            .emit(&mut writer, &edges, &identities, 64, pass)
            .unwrap();
    }
    assert!(writer.oldest_generation() > 0, "c0's record was evicted");
    assert!(!retained_edges(&path).contains_key("c0"));
    let sweep = emitter
        .sweep(&mut writer, &edges, &identities, 64, 200, 0)
        .unwrap();
    assert!(sweep.emitted >= 1, "{sweep:?}");
    assert_eq!(sweep.unretained, 0);
    drop(writer);
    let retained = retained_edges(&path);
    assert_eq!(retained.keys().collect::<Vec<_>>(), ["c0", "c1"]);
    for edge in &edges {
        assert_eq!(
            retained[&edge.caller.label()],
            edge_payload(edge, &identities)
        );
    }
}

/// Review M-1, probe 2: a sweep larger than the retention (200 edges,
/// 8 KiB x 3 files) cannot keep its own early records. No dump is tried
/// (it cannot fit), and the sweep reports exactly the edges left without a
/// retained record (it used to claim nothing: 200 sent, 29 kept).
#[test]
fn a_sweep_larger_than_the_retention_reports_its_unretained_edges() {
    // Synthetic edge fixtures have no retained caller/module records.
    let identity_revision = presentation(&harness(0, 0));
    let identities = IdentityIndex::new(&identity_revision);
    let edges = synthetic_edges(200);
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 8192, 3).unwrap();
    let mut emitter = EdgeEmitter::new();
    let sweep = emitter
        .sweep(&mut writer, &edges, &identities, 64_000, 1, 0)
        .unwrap();
    drop(writer);
    let kept = retained_edges(&path).len();
    assert_eq!(sweep.emitted, 200, "one record per edge, no futile dump");
    assert!(kept < 200, "{kept}");
    assert_eq!(sweep.unretained, 200 - kept);
}

/// When the sweep's own lines rotate an unchanged edge's record out and a
/// contiguous dump of every edge fits the retention, the sweep writes that
/// dump: every edge keeps a retained record equal to its state.
#[test]
fn a_sweep_that_rotates_out_a_needed_record_dumps_every_edge_when_it_fits() {
    // Synthetic edge fixtures have no retained caller/module records.
    let identity_revision = presentation(&harness(0, 0));
    let identities = IdentityIndex::new(&identity_revision);
    let mut edges = synthetic_edges(10);
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 16 * 1024, 4).unwrap();
    let mut emitter = EdgeEmitter::new();
    emitter
        .emit(&mut writer, &edges, &identities, 64, 1)
        .unwrap();
    let pad = serde_json::json!({"pad": "x".repeat(64)});
    while writer.rotations() < 3 {
        writer.append("probe", pad.clone(), 2).unwrap();
    }
    for _ in 0..80 {
        writer.append("probe", pad.clone(), 2).unwrap();
    }
    assert_eq!(writer.oldest_generation(), 0, "every record still retained");
    for edge in edges.iter_mut().skip(1) {
        edge.entry_count = 1;
    }
    let sweep = emitter
        .sweep(&mut writer, &edges, &identities, 64, 3, 0)
        .unwrap();
    assert!(
        writer.oldest_generation() > 0,
        "the sweep rotated gen 0 out"
    );
    assert_eq!(
        sweep,
        crate::inventory_events::EdgeSweep {
            emitted: 9 + 10,
            unretained: 0,
            dumped: true,
        }
    );
    drop(writer);
    let retained = retained_edges(&path);
    assert_eq!(retained.len(), 10);
    for edge in &edges {
        assert_eq!(
            retained[&edge.caller.label()],
            edge_payload(edge, &identities)
        );
    }
}

/// Mid-run, an edge whose record rotated out is re-sent on the next pass
/// while every edge's record fits the retention; when they cannot fit, it
/// is not (re-sending would only evict others, every pass), and the sweep
/// is left to account for it.
#[test]
fn evicted_edges_are_refreshed_mid_run_only_when_the_records_fit() {
    // Synthetic edge fixtures have no retained caller/module records.
    let identity_revision = presentation(&harness(0, 0));
    let identities = IdentityIndex::new(&identity_revision);
    for (max_bytes, files, refreshed) in [(16 * 1024, 4, 3), (4096, 2, 0)] {
        let edges = synthetic_edges(3);
        let dir = private_tempdir();
        let path = dir.path().join("events.jsonl");
        let mut writer = EventWriter::create(&path, max_bytes, files).unwrap();
        let mut emitter = EdgeEmitter::new();
        emitter
            .emit(&mut writer, &edges, &identities, 64, 1)
            .unwrap();
        let pad = serde_json::json!({"pad": "x".repeat(64)});
        while writer.oldest_generation() == 0 {
            writer.append("probe", pad.clone(), 2).unwrap();
        }
        let pass = emitter
            .emit(&mut writer, &edges, &identities, 64, 3)
            .unwrap();
        assert_eq!(pass.emitted, refreshed, "{max_bytes} x {files}");
        let pass = emitter
            .emit(&mut writer, &edges, &identities, 64, 4)
            .unwrap();
        assert_eq!(pass.emitted, 0, "{max_bytes} x {files}: refreshed once");
    }
}

/// Review L-5: each of the three derived states alone triggers a record,
/// so freezing any of them in the change check fails here, not only in
/// the 14 s command-level test.
#[test]
fn presence_capture_and_activity_each_trigger_a_record_alone() {
    // Synthetic edge fixtures have no retained caller/module records.
    let identity_revision = presentation(&harness(0, 0));
    let identities = IdentityIndex::new(&identity_revision);
    use crate::inventory_present::{Activity, Capture, Presence};
    let mut edges = synthetic_edges(1);
    edges[0].presence = Presence::Mapped;
    edges[0].capture = Capture::ScanOnly;
    edges[0].activity = Activity::Uncovered;
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
    let mut emitter = EdgeEmitter::new();
    assert_eq!(
        emitter
            .emit(&mut writer, &edges, &identities, 64, 1)
            .unwrap()
            .emitted,
        1
    );
    let mut emitted = Vec::new();
    edges[0].presence = Presence::Unloaded;
    emitted.push(
        emitter
            .emit(&mut writer, &edges, &identities, 64, 2)
            .unwrap()
            .emitted,
    );
    edges[0].capture = Capture::Retired;
    emitted.push(
        emitter
            .emit(&mut writer, &edges, &identities, 64, 3)
            .unwrap()
            .emitted,
    );
    edges[0].activity = Activity::Unknown;
    emitted.push(
        emitter
            .emit(&mut writer, &edges, &identities, 64, 4)
            .unwrap()
            .emitted,
    );
    emitted.push(
        emitter
            .emit(&mut writer, &edges, &identities, 64, 5)
            .unwrap()
            .emitted,
    );
    assert_eq!(emitted, [1, 1, 1, 0], "presence, capture, activity, quiet");
    drop(writer);
    let last = lines(&path).pop().unwrap();
    assert_eq!(last["event"]["presence"], "unloaded");
    assert_eq!(last["event"]["capture"], "retired");
    assert_eq!(last["event"]["activity"], "unknown");
}

/// One R-1 scenario: `edges` emitted mid-run over `passes` passes (from
/// pass 2 on, one edge changes and a few unrelated lines go out per
/// pass), the stream rotated `rotations` times and the live file padded
/// until less than `room` bytes are left, then the edges in `changed`
/// change. The sweep runs with the padded `ended` reservation, the count
/// is settled for the real `ended` line exactly as `finish_output` does,
/// `ended` is written, and the retained files must hold exactly the edges
/// not reported unretained, each equal to its payload.
#[derive(Debug)]
struct Shape {
    max_bytes: u64,
    files: usize,
    passes: u64,
    rotations: u64,
    room: u64,
    ended_pad: usize,
}

/// The sweep's own result (its count is the padded upper bound) and the
/// settled count `ended` carries.
#[derive(Debug)]
struct Outcome {
    sweep: EdgeSweep,
    settled: usize,
}

fn run_shape(shape: &Shape, mut edges: Vec<EdgeView>, changed: &[usize]) -> Outcome {
    // Synthetic edge fixtures have no retained caller/module records.
    let identity_revision = presentation(&harness(0, 0));
    let identities = IdentityIndex::new(&identity_revision);
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, shape.max_bytes, shape.files).unwrap();
    let mut emitter = EdgeEmitter::new();
    let pad = serde_json::json!({"pad": "p".repeat(40)});
    emitter
        .emit(&mut writer, &edges, &identities, 64, 1)
        .unwrap();
    for pass in 2..=shape.passes {
        let index = pass as usize % edges.len();
        edges[index].entry_count += 1;
        for _ in 0..3 {
            writer.append("probe", pad.clone(), pass).unwrap();
        }
        emitter
            .emit(&mut writer, &edges, &identities, 64, pass)
            .unwrap();
    }
    while writer.rotations() < shape.rotations {
        writer.append("probe", pad.clone(), 2).unwrap();
    }
    let line = 140; // a probe line is under 140 bytes
    while writer.live_bytes() + shape.room.max(line) <= shape.max_bytes {
        writer.append("probe", pad.clone(), 2).unwrap();
    }
    for &index in changed {
        edges[index].entry_count += 1;
    }
    let ended = |unretained: usize| serde_json::json!({"pad": "e".repeat(shape.ended_pad), "edges_unretained": unretained});
    let tail =
        ended(usize::MAX).to_string().len() as u64 + crate::inventory_events::ENDED_TAIL_SLACK;
    let sweep = emitter
        .sweep(&mut writer, &edges, &identities, 64, 3, tail)
        .unwrap();
    let (settled, payload) = emitter.settle_ended(&writer, &edges, sweep.unretained, 4, ended);
    assert!(
        settled <= sweep.unretained,
        "the reservation bounds the count"
    );
    writer.finish(payload, 4).unwrap();
    drop(writer);
    // `rotated`/`retention_evicted` lines take seqs after the line that
    // triggered them, so the live file's own last line is checked.
    let live = lines(&path);
    assert_eq!(live.last().unwrap()["kind"], "ended");
    assert_eq!(live.last().unwrap()["event"]["edges_unretained"], settled);
    let retained = retained_edges(&path);
    for edge in &edges {
        if let Some(record) = retained.get(&edge.caller.label()) {
            assert_eq!(
                *record,
                edge_payload(edge, &identities),
                "a retained record is exact"
            );
        }
    }
    assert_eq!(
        edges.len() - retained.len(),
        settled,
        "edges_unretained is exact after `ended`"
    );
    Outcome { sweep, settled }
}

use crate::inventory_events::EdgeSweep;

/// Review R-1, the reviewer's 4 KiB x 2 shape: two unchanged edges sit in
/// the oldest retained file and `ended` would rotate it out after the
/// sweep counted 0 (the stream then said 0 with both records gone). The
/// sweep now reserves `ended`'s room first, so the rotation happens before
/// the count; a copy of both cannot fit one 4 KiB file beside the tail, so
/// it reports both, exactly.
#[test]
fn ended_cannot_evict_records_after_the_sweep_counted_4k_x2() {
    let shape = Shape {
        max_bytes: 4096,
        files: 2,
        passes: 1,
        rotations: 1,
        room: 600,
        ended_pad: 1000,
    };
    let outcome = run_shape(&shape, synthetic_edges(2), &[]);
    assert_eq!((outcome.sweep.emitted, outcome.settled), (0, 2));
}

/// Review R-1, the 16 KiB x 4 shape where one copy of every edge fits:
/// the sweep has nothing to write, the reserve's rotation evicts
/// generation 0, and the sweep dumps every edge, so nothing is lost after
/// `ended`. With one changed edge its own record rotates generation 0 out
/// mid-sweep; the result is the same.
#[test]
fn ended_cannot_evict_records_after_the_sweep_counted_16k_x4() {
    let shape = Shape {
        max_bytes: 16 * 1024,
        files: 4,
        passes: 1,
        rotations: 3,
        room: 600,
        ended_pad: 1000,
    };
    let outcome = run_shape(&shape, synthetic_edges(10), &[]);
    assert!(outcome.sweep.dumped);
    assert_eq!((outcome.sweep.emitted, outcome.settled), (10, 0));
    let outcome = run_shape(&shape, synthetic_edges(10), &[3]);
    assert_eq!(outcome.settled, 0, "{outcome:?}");
}

/// A file too small for even a fresh file to take `ended` after its
/// rotation marker: `ended` still rotates after the reserve. With 3 files
/// the edge's generation survives the reserve's rotation and is evicted
/// only by `ended`'s, which the count already accounts for.
#[test]
fn a_tail_larger_than_a_fresh_file_is_counted_before_it_rotates() {
    let shape = Shape {
        max_bytes: 1024,
        files: 3,
        passes: 1,
        rotations: 1,
        room: 200,
        ended_pad: 1200,
    };
    let outcome = run_shape(&shape, synthetic_edges(1), &[]);
    assert_eq!((outcome.sweep.emitted, outcome.settled), (0, 1));
}

/// Review R2-1: a 1918-byte rotate size. After the reserve rotates, the
/// fresh file (its `rotated` and `retention_evicted` lines in it) cannot
/// take the 256-byte-padded reservation but can take the real `ended`
/// line, so the sweep's bound predicts a rotation that never happens and
/// over-counts one edge whose record is still retained. Settling for the
/// real line reports the exact 0.
#[test]
fn edges_unretained_is_recounted_for_the_real_ended_line() {
    let shape = Shape {
        max_bytes: 1918,
        files: 3,
        passes: 1,
        rotations: 3,
        room: 164,
        ended_pad: 1170,
    };
    let mut edges = synthetic_edges(2);
    edges[0].mapping_reason = Some("r".repeat(115));
    edges[1].mapping_reason = Some("r".repeat(67));
    let outcome = run_shape(&shape, edges, &[]);
    assert_eq!(outcome.sweep.unretained, 1, "the padded bound: {outcome:?}");
    assert_eq!(outcome.settled, 0, "exact for the real line");
}

/// One randomized shape from `next` (a deterministic xorshift draw).
fn random_shape(next: &mut impl FnMut(u64) -> u64, template: &EdgeView) -> Outcome {
    // A third of the shapes use rotate sizes under 2 KiB (review R2-1's
    // window: a fresh file can take the real `ended` but not the padded
    // reservation), the rest up to 32 KiB; 1 to 6 files.
    let max_bytes = if next(3) == 0 {
        1024 + next(1024)
    } else {
        2048 + next(30 * 1024)
    };
    let files = 1 + next(6) as usize;
    let shape = Shape {
        max_bytes,
        files,
        passes: 1 + next(6),
        rotations: next(files as u64 + 1),
        room: 50 + next(2000),
        ended_pad: 100 + next(1400) as usize,
    };
    let count = 2 + next(40) as u32;
    let edges: Vec<EdgeView> = (0..count)
        .map(|index| {
            let mut edge = template.clone();
            edge.caller = CallerId(index);
            edge.mapping_reason = Some("r".repeat(next(600) as usize));
            edge
        })
        .collect();
    let changed: Vec<usize> = (0..count as usize).filter(|_| next(3) == 0).collect();
    run_shape(&shape, edges, &changed)
}

/// Review R-1 / R2-2, randomized: rotate sizes (including under 2 KiB),
/// 1 to 6 files, records over several passes, padding, changed subsets
/// and `ended` lengths vary; after `ended` the retained files always hold
/// exactly the edges `ended` does not report unretained. 120 shapes by
/// default; set `P11SCOPE_EDGE_SHAPES=<n>` (for example 2000) for a long
/// run. Each outcome (none lost, some lost, a full copy written, and an
/// over-reserved count that settling lowered) must occur at least once.
#[test]
fn edges_unretained_is_final_after_ended_over_random_shapes() {
    let shapes: usize = std::env::var("P11SCOPE_EDGE_SHAPES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(120);
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = |bound: u64| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state % bound
    };
    let template = synthetic_edges(1).remove(0);
    let (mut lossy, mut clean, mut dumped, mut settled) = (0, 0, 0, 0);
    for _ in 0..shapes {
        let outcome = random_shape(&mut next, &template);
        if outcome.settled > 0 {
            lossy += 1;
        } else {
            clean += 1;
        }
        dumped += usize::from(outcome.sweep.dumped);
        settled += usize::from(outcome.settled < outcome.sweep.unretained);
    }
    assert!(
        lossy > 0 && clean > 0 && dumped > 0 && settled > 0,
        "every outcome exercised: lossy {lossy} clean {clean} dumped {dumped} settled {settled}"
    );
}

/// C5.3 re-check R2: a dashboard pass streams the classic view, not the
/// display's 5 s window. A counted edge is recent on pass 1 in both
/// windows; by pass 2 its last use is 10 s old, so the display reads it
/// `quiet` while the classic view still reads `recently observed`. The
/// dashboard's stream, through `dashboard_stream_pass`, must equal a
/// classic run's stream byte for byte (streaming the display view would
/// add a mid-run activity record on pass 2).
#[test]
fn a_dashboard_pass_streams_the_classic_view_when_the_display_window_expires() {
    let mut harness = harness(1, 1);
    let started = harness.now_ns();
    let c0 = caller(&harness, 0);
    harness.advance(1_000);
    let at = harness.now_ns();
    {
        let registry = harness.coordinator_mut().registry_mut();
        registry.note_coverage(c0, &key(0), CoverageNote::Counted { since_ns: at });
        registry.observe_entries(c0, &key(0), 3, at);
    }
    harness.commit();
    let dir = private_tempdir();
    let dashboard_path = dir.path().join("dashboard.jsonl");
    let classic_path = dir.path().join("classic.jsonl");
    let mut dashboard = EventLogState::new(Some(
        EventWriter::create(&dashboard_path, 1 << 20, 2).unwrap(),
    ));
    let mut classic = EventLogState::new(Some(
        EventWriter::create(&classic_path, 1 << 20, 2).unwrap(),
    ));
    let mut dashboard_state = StreamState::new();
    let mut classic_state = StreamState::new();
    let mut display_activity = Vec::new();
    for (pass, age) in [(1u64, 1_000_000_000u64), (2, 10_000_000_000)] {
        let now = at + age;
        let coordinator = harness.coordinator();
        let (display, error) = dashboard_stream_pass(
            &mut dashboard,
            &mut dashboard_state,
            &report(pass),
            coordinator,
            "pid",
            started,
            now,
            crate::inventory_semantics::SemanticCaptureSummary::default(),
        );
        assert!(error.is_none());
        display_activity.push(display.edges[0].activity.label());
        let view = stream_presentation(coordinator, "pid", started, now);
        emit_pass_events(
            classic.writer.as_mut().unwrap(),
            &mut classic_state,
            &report(pass),
            &view,
            now,
        )
        .unwrap();
    }
    assert_eq!(
        display_activity,
        ["recently observed", "quiet"],
        "the display window expires mid-run"
    );
    let end = at + 11_000_000_000;
    let last = stream_presentation(harness.coordinator(), "pid", started, end);
    for (writer, state) in [
        (&mut dashboard, &mut dashboard_state),
        (&mut classic, &mut classic_state),
    ] {
        let mut sink = Vec::new();
        let outcome = finish_output(
            None,
            writer,
            state,
            &last,
            false,
            true,
            &mut crate::inventory_output::WriterStdout(&mut sink),
            None,
            None,
        );
        assert_eq!(outcome.exit_code(), 0);
        assert_eq!(outcome.event_log_confirmed, Some(true));
    }
    drop((dashboard, classic));
    let dashboard_lines = lines(&dashboard_path);
    assert!(
        dashboard_lines
            .iter()
            .filter(|line| line["kind"] == "edge_observed")
            .all(|line| line["event"]["activity"] == "recently observed")
    );
    assert_eq!(
        std::fs::read(&dashboard_path).unwrap(),
        std::fs::read(&classic_path).unwrap()
    );
}

/// C7 C4 (D-C7-5): a count change that is not a class change emits at
/// most once per edge per 10 s, with the latest count. Within-bucket
/// drift waits; the 10 s record carries every rise since the last one.
#[test]
fn count_drift_emits_at_most_once_per_edge_per_ten_seconds() {
    // Synthetic edge fixtures have no retained caller/module records.
    let identity_revision = presentation(&harness(0, 0));
    let identities = IdentityIndex::new(&identity_revision);
    use crate::discovery::caller_registry::UseCoverage;
    use crate::inventory_events::EDGE_COUNT_EMIT_INTERVAL_NS;
    use crate::inventory_present::Activity;
    assert_eq!(EDGE_COUNT_EMIT_INTERVAL_NS, 10_000_000_000);
    let mut edges = synthetic_edges(1);
    edges[0].coverage = UseCoverage::Counted {
        since_ns: 100,
        lossy: false,
        pid_exit: false,
    };
    edges[0].entry_count = 4;
    edges[0].entry_observation = "observed";
    edges[0].activity = Activity::Quiet;
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
    let mut emitter = EdgeEmitter::new();
    assert_eq!(
        emitter
            .emit(&mut writer, &edges, &identities, 64, 1)
            .unwrap()
            .emitted,
        1
    );
    // Same power-of-two bucket (4-7): drift, never a class change.
    edges[0].entry_count = 5;
    assert_eq!(
        emitter
            .emit(&mut writer, &edges, &identities, 64, 2)
            .unwrap()
            .emitted,
        0
    );
    edges[0].entry_count = 6;
    assert_eq!(
        emitter
            .emit(&mut writer, &edges, &identities, 64, 5_000_000_000)
            .unwrap()
            .emitted,
        0
    );
    edges[0].entry_count = 7;
    assert_eq!(
        emitter
            .emit(&mut writer, &edges, &identities, 64, 10_000_000_001)
            .unwrap()
            .emitted,
        1,
        "ten seconds after the last record the drift goes out"
    );
    // No new drift since the 10 s record: nothing goes out.
    assert_eq!(
        emitter
            .emit(&mut writer, &edges, &identities, 64, 11_000_000_000)
            .unwrap()
            .emitted,
        0
    );
    drop(writer);
    let last = lines(&path).pop().unwrap();
    assert_eq!(last["event"]["entries"]["count"], 7);
}

/// A class emission carries the latest count, so it resets the 10 s
/// cadence; a bucket jump is a class change and still goes out at
/// once, never waiting for the cadence.
#[test]
fn class_emissions_reset_the_count_cadence_and_buckets_stay_immediate() {
    // Synthetic edge fixtures have no retained caller/module records.
    let identity_revision = presentation(&harness(0, 0));
    let identities = IdentityIndex::new(&identity_revision);
    use crate::discovery::caller_registry::UseCoverage;
    use crate::inventory_present::Activity;
    let mut edges = synthetic_edges(1);
    edges[0].coverage = UseCoverage::Counted {
        since_ns: 100,
        lossy: false,
        pid_exit: false,
    };
    edges[0].entry_count = 4;
    edges[0].entry_observation = "observed";
    edges[0].activity = Activity::Quiet;
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
    let mut emitter = EdgeEmitter::new();
    assert_eq!(
        emitter
            .emit(&mut writer, &edges, &identities, 64, 1)
            .unwrap()
            .emitted,
        1
    );
    edges[0].entry_count = 5;
    assert_eq!(
        emitter
            .emit(&mut writer, &edges, &identities, 64, 2)
            .unwrap()
            .emitted,
        0
    );
    // A class change goes out at once, carrying the drifted count.
    edges[0].activity = Activity::RecentlyObserved;
    assert_eq!(
        emitter
            .emit(&mut writer, &edges, &identities, 64, 3)
            .unwrap()
            .emitted,
        1
    );
    edges[0].entry_count = 6;
    assert_eq!(
        emitter
            .emit(&mut writer, &edges, &identities, 64, 4)
            .unwrap()
            .emitted,
        0,
        "the class record carried 5, so 6 waits a fresh ten seconds"
    );
    assert_eq!(
        emitter
            .emit(&mut writer, &edges, &identities, 64, 10_000_000_004)
            .unwrap()
            .emitted,
        1
    );
    // A bucket jump (7 to 8) is a class change: immediate.
    edges[0].entry_count = 8;
    assert_eq!(
        emitter
            .emit(&mut writer, &edges, &identities, 64, 10_000_000_005)
            .unwrap()
            .emitted,
        1
    );
    drop(writer);
    let counts: Vec<u64> = lines(&path)
        .iter()
        .filter(|line| line["kind"] == "edge_observed")
        .map(|line| line["event"]["entries"]["count"].as_u64().unwrap())
        .collect();
    assert_eq!(counts, [4, 5, 6, 8]);
}

/// N11: a populated key section with retention too small for the
/// final sweep + terminal record (30 rows ≈ 15 KiB against 4 KiB x
/// 2 files) discloses exactly which key rows lost their last
/// record — `ended` carries the exact unretained count, never
/// silent loss.
#[test]
fn final_sweep_under_tiny_retention_discloses_unretained_key_rows() {
    use crate::key_operation_projection::{KeyAggRow, ObjectObservations, ObsBudgets, ObsStatus};

    const ROWS: u64 = 30;
    let rows: Vec<KeyAggRow> = (0..ROWS)
        .map(|n| KeyAggRow {
            instance: "i3".to_string(),
            object: 1000 + n,
            category: "sign",
            role: "key",
            metadata_at_use: "rsa_2048",
            unit: "operations",
            started: 1,
            completed: 1,
            failed: 0,
            cancelled: 0,
            unknown: 0,
            active: 0,
            key_join_lost: 0,
            inferred: None,
        })
        .collect();
    let observations = ObjectObservations {
        revision: 1,
        status: ObsStatus::Populated,
        reason: "none",
        sessions: Vec::new(),
        objects: Vec::new(),
        key_operations: rows,
        unknown_key_operations: Vec::new(),
        unattributed: Vec::new(),
        gaps: Vec::new(),
        gaps_suppressed: 0,
        budgets: ObsBudgets {
            key_limit: 64,
            key_occupied: ROWS as usize,
            key_refused: 0,
            object_limit: 65_536,
            object_occupied: 0,
            object_refused: 0,
            unknown_occupied: 0,
            encoded_bytes: 0,
        },
    };
    let harness = harness(0, 0);
    let mut last = presentation(&harness);
    last.object_observations = observations;
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let writer = EventWriter::create(&path, 4096, 2).unwrap();
    let mut state = StreamState::new();
    let mut text = Vec::new();
    let outcome = finish_output(
        None,
        &mut EventLogState::new(Some(writer)),
        &mut state,
        &last,
        false,
        false,
        &mut crate::inventory_output::WriterStdout(&mut text),
        None,
        None,
    );
    assert_eq!(outcome.exit_code(), 0);
    assert_eq!(outcome.event_log_confirmed, Some(true));
    let mut retained = std::collections::BTreeSet::new();
    let mut ended = None;
    for line in retained_lines(&path) {
        if line["kind"] == "key_operations_observed" {
            let row = &line["event"]["row"];
            retained.insert((
                row["instance"].as_str().unwrap().to_string(),
                row["object"].as_u64().unwrap(),
            ));
        }
        if line["kind"] == "ended" {
            ended = Some(line["event"].clone());
        }
    }
    let ended = ended.expect("the terminal record is retained");
    assert_eq!(
        ended["key_operation_events"], ROWS,
        "every row written by the sweep"
    );
    let unretained = ended["key_operations_unretained"]
        .as_u64()
        .expect("the exact key disclosure");
    assert!(unretained > 0, "tiny retention cannot keep the sweep");
    assert_eq!(
        unretained as usize,
        ROWS as usize - retained.len(),
        "the disclosure is exact"
    );
}

/// N11 (repair): under retention pressure some swept key rows lose
/// their last record and the counter names them exactly; when one
/// contiguous copy fits, the repair dump rewrites every row and
/// nothing stays unretained.
#[test]
fn key_rows_lost_to_pressure_are_repaired_by_the_dump_when_it_fits() {
    use crate::inventory_events::KeyOperationEmitter;
    use crate::key_operation_projection::{KeyAggRow, ObjectObservations, ObsBudgets, ObsStatus};

    fn observations(bump_through: u64) -> ObjectObservations {
        ObjectObservations {
            revision: 1,
            status: ObsStatus::Populated,
            reason: "none",
            sessions: Vec::new(),
            objects: Vec::new(),
            key_operations: (0..20u64)
                .map(|n| KeyAggRow {
                    instance: "i3".to_string(),
                    object: 1000 + n,
                    category: "sign",
                    role: "key",
                    metadata_at_use: "rsa_2048",
                    unit: "operations",
                    started: 1,
                    completed: if n < bump_through { 2 } else { 1 },
                    failed: 0,
                    cancelled: 0,
                    unknown: 0,
                    active: 0,
                    key_join_lost: 0,
                    inferred: None,
                })
                .collect(),
            unknown_key_operations: Vec::new(),
            unattributed: Vec::new(),
            gaps: Vec::new(),
            gaps_suppressed: 0,
            budgets: ObsBudgets {
                key_limit: 64,
                key_occupied: 20,
                key_refused: 0,
                object_limit: 65_536,
                object_occupied: 0,
                object_refused: 0,
                unknown_occupied: 0,
                encoded_bytes: 0,
            },
        }
    }

    fn retained_completed(path: &std::path::Path) -> std::collections::BTreeMap<u64, u64> {
        let mut completed = std::collections::BTreeMap::new();
        for line in retained_lines(path) {
            if line["kind"] == "key_operations_observed" {
                let row = &line["event"]["row"];
                completed.insert(
                    row["object"].as_u64().unwrap(),
                    row["completed"].as_u64().unwrap(),
                );
            }
        }
        completed
    }

    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 8 * 1024, 4).unwrap();
    let mut emitter = KeyOperationEmitter::new();
    emitter.emit(&mut writer, &observations(0), 1).unwrap();
    assert_eq!(emitter.tracked(), 20);
    // Most rows change; the sweep rewrites them while the rest keep
    // their older records.
    let swept_state = observations(16);
    let swept = emitter.sweep_exact(&mut writer, &swept_state, 2).unwrap();
    assert_eq!(swept, 16, "only changed rows rewritten");
    // Pressure until rows actually lose their last record (measured,
    // not sized by arithmetic).
    let pad = serde_json::json!({"pad": "x".repeat(64)});
    for _ in 0..10_000 {
        if emitter.unretained_after(&writer, &swept_state, 0) > 0 {
            break;
        }
        writer.append("probe", pad.clone(), 2).unwrap();
    }
    let missing = 20 - retained_completed(&path).len();
    assert!(missing > 0, "pressure evicted rows before the assertion");
    assert_eq!(
        emitter.unretained_after(&writer, &swept_state, 0),
        missing,
        "the counter names exactly the rows without a record"
    );
    let tail = 512u64;
    writer.reserve(tail).unwrap();
    assert!(
        crate::inventory_events::combined_dump_fits(
            &crate::inventory_events::EdgeEmitter::new(),
            &crate::inventory_events::InstanceEmitter::new(),
            &emitter,
            &writer,
            tail,
        ),
        "one contiguous copy fits"
    );
    let dumped = emitter.dump_all(&mut writer, &swept_state, 2).unwrap();
    assert_eq!(dumped, 20);
    assert_eq!(
        emitter.unretained_after(&writer, &swept_state, tail),
        0,
        "the repair keeps every row past the tail"
    );
    drop(writer);
    let completed = retained_completed(&path);
    assert_eq!(completed.len(), 20);
    for (object, count) in &completed {
        let expected = if object - 1000 < 16 { 2 } else { 1 };
        assert_eq!(*count, expected, "retained rows equal the swept state");
    }
}

/// N11 remainder (fix round 2): the finish path threads the SAME
/// SELECTED publication through every convergence/count/bound step.
/// The current presentation names object#2 but the publisher retains
/// the stale object#1 selection (exact-byte refusal); under
/// retention pressure the swept object#1 row loses its record and
/// `ended` must disclose 1 unretained (the selected row) — never 0
/// (the current row, which was never swept).
#[test]
fn finish_counts_the_selected_stale_publication_not_the_current() {
    use crate::key_operation_projection::{
        MetadataBlock, MetadataField, ObjectObservations, ObjectRow, ObsBudgets, ObsStatus,
        ObservationPublisher, QueriesBlock,
    };

    fn row(object: u64) -> ObjectRow {
        let blank = MetadataField {
            status: "absent",
            scalar: None,
            curve: None,
            source: None,
            reason: None,
        };
        let block = MetadataBlock {
            class: blank,
            key_type: blank,
            token: blank,
            value_len: blank,
            modulus_bits: blank,
            ec_params: blank,
            parameter_set: blank,
        };
        ObjectRow {
            object,
            session: 7,
            origin: "observed",
            creation: None,
            birth: None,
            lifetime: "active",
            lifetime_reason: None,
            attribution: "valid",
            attribution_reason: None,
            requested: block,
            established: block,
            queries: QueriesBlock {
                class: "not_queried",
                key_type: "not_queried",
                token: "not_queried",
                value_len: "not_queried",
                modulus_bits: "not_queried",
                ec_params: "not_queried",
                parameter_set: "not_queried",
            },
            label: None,
            successful_references: 1,
            successful_key_references: 0,
            accessing_sessions: 1,
            creation_truncated: false,
        }
    }

    fn observations(revision: u64, object: u64, bytes: usize) -> ObjectObservations {
        ObjectObservations {
            revision,
            status: ObsStatus::Populated,
            reason: "none",
            sessions: Vec::new(),
            objects: vec![row(object)],
            key_operations: Vec::new(),
            unknown_key_operations: Vec::new(),
            unattributed: Vec::new(),
            gaps: Vec::new(),
            gaps_suppressed: 0,
            budgets: ObsBudgets {
                key_limit: 64,
                key_occupied: 0,
                key_refused: 0,
                object_limit: 65_536,
                object_occupied: 1,
                object_refused: 0,
                unknown_occupied: 0,
                encoded_bytes: bytes,
            },
        }
    }

    // The retained selection names object#1; the current presentation
    // names object#2 but refuses the exact-byte bound (stale).
    let old = observations(1, 1, 1000);
    let current = observations(u64::MAX, 2, 1001);
    let mut publisher = ObservationPublisher::with_byte_limit(old.budgets.encoded_bytes);
    publisher.publish(old);
    let mut state = StreamState::new();
    state.reference_key_publisher(publisher);
    let harness = harness(0, 0);
    let mut last = presentation(&harness);
    last.object_observations = current;
    // Retention too small for the swept row plus the terminal record:
    // the swept row must lose its record while `ended` survives.
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let writer = EventWriter::create(&path, 512, 2).unwrap();
    let mut text = Vec::new();
    let outcome = finish_output(
        None,
        &mut EventLogState::new(Some(writer)),
        &mut state,
        &last,
        false,
        false,
        &mut crate::inventory_output::WriterStdout(&mut text),
        None,
        None,
    );
    assert_eq!(outcome.exit_code(), 0);
    assert_eq!(outcome.event_log_confirmed, Some(true));
    let mut swept_object = None;
    let mut ended = None;
    for line in retained_lines(&path) {
        if line["kind"] == "object_observed" {
            swept_object = Some(line["event"]["row"]["object"].as_u64().unwrap());
        }
        if line["kind"] == "ended" {
            ended = Some(line["event"].clone());
        }
    }
    assert_eq!(swept_object, None, "pressure evicted the swept row");
    let ended = ended.expect("the terminal record is retained");
    assert_eq!(
        ended["key_operation_events"], 1,
        "the sweep wrote the selected row"
    );
    assert_eq!(
        ended["key_operations_unretained"], 1,
        "the disclosure counts the SELECTED row, not the current one"
    );
}

/// N11 remainder (fix round 2, guard): when the stale selection fits
/// retention, nothing is unretained — threading the selected
/// publication must not over-count either.
#[test]
fn finish_with_fitting_stale_selection_discloses_nothing() {
    use crate::key_operation_projection::{
        MetadataBlock, MetadataField, ObjectObservations, ObjectRow, ObsBudgets, ObsStatus,
        ObservationPublisher, QueriesBlock,
    };

    fn row(object: u64) -> ObjectRow {
        let blank = MetadataField {
            status: "absent",
            scalar: None,
            curve: None,
            source: None,
            reason: None,
        };
        let block = MetadataBlock {
            class: blank,
            key_type: blank,
            token: blank,
            value_len: blank,
            modulus_bits: blank,
            ec_params: blank,
            parameter_set: blank,
        };
        ObjectRow {
            object,
            session: 7,
            origin: "observed",
            creation: None,
            birth: None,
            lifetime: "active",
            lifetime_reason: None,
            attribution: "valid",
            attribution_reason: None,
            requested: block,
            established: block,
            queries: QueriesBlock {
                class: "not_queried",
                key_type: "not_queried",
                token: "not_queried",
                value_len: "not_queried",
                modulus_bits: "not_queried",
                ec_params: "not_queried",
                parameter_set: "not_queried",
            },
            label: None,
            successful_references: 1,
            successful_key_references: 0,
            accessing_sessions: 1,
            creation_truncated: false,
        }
    }

    fn observations(revision: u64, object: u64, bytes: usize) -> ObjectObservations {
        ObjectObservations {
            revision,
            status: ObsStatus::Populated,
            reason: "none",
            sessions: Vec::new(),
            objects: vec![row(object)],
            key_operations: Vec::new(),
            unknown_key_operations: Vec::new(),
            unattributed: Vec::new(),
            gaps: Vec::new(),
            gaps_suppressed: 0,
            budgets: ObsBudgets {
                key_limit: 64,
                key_occupied: 0,
                key_refused: 0,
                object_limit: 65_536,
                object_occupied: 1,
                object_refused: 0,
                unknown_occupied: 0,
                encoded_bytes: bytes,
            },
        }
    }

    let old = observations(1, 1, 1000);
    let current = observations(u64::MAX, 2, 1001);
    let mut publisher = ObservationPublisher::with_byte_limit(old.budgets.encoded_bytes);
    publisher.publish(old);
    let mut state = StreamState::new();
    state.reference_key_publisher(publisher);
    let harness = harness(0, 0);
    let mut last = presentation(&harness);
    last.object_observations = current;
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let writer = EventWriter::create(&path, 1 << 20, 5).unwrap();
    let mut text = Vec::new();
    let outcome = finish_output(
        None,
        &mut EventLogState::new(Some(writer)),
        &mut state,
        &last,
        false,
        false,
        &mut crate::inventory_output::WriterStdout(&mut text),
        None,
        None,
    );
    assert_eq!(outcome.exit_code(), 0);
    assert_eq!(outcome.event_log_confirmed, Some(true));
    let mut swept_object = None;
    let mut ended = None;
    for line in retained_lines(&path) {
        if line["kind"] == "object_observed" {
            swept_object = Some(line["event"]["row"]["object"].as_u64().unwrap());
        }
        if line["kind"] == "ended" {
            ended = Some(line["event"].clone());
        }
    }
    assert_eq!(swept_object, Some(1), "the SELECTED row is swept");
    let ended = ended.expect("the terminal record is retained");
    assert_eq!(ended["key_operation_events"], 1);
    assert_eq!(
        ended["key_operations_unretained"], 0,
        "a fitting selection discloses nothing"
    );
}

// ==================== v0.7.2 F3: fold waits for terminal rows ====================

/// Kill one harness pid through the production reconcile path.
fn kill_pid(harness: &mut Harness, pid: u32, survivors: &[u32]) {
    harness.source().kill(pid);
    let observed: BTreeSet<u32> = survivors.iter().copied().collect();
    let now = harness.now_ns();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    harness.advance(10);
}

/// F3 edge twin: a small-cap FIFO defers an exited edge's terminal
/// update. The fold must wait for the queued exit revision — folding
/// on the stale carried digest would drop the terminal update and
/// leave the stream with a stale count and no loss marker. Entry
/// counts ride on the captured views (the emitter and the gate both
/// read views; the registry carries row existence), so the terminal
/// revision is exact without BPF realism.
#[test]
fn fold_waits_for_deferred_exit_update_before_folding_edge() {
    use crate::inventory_present::Presence;
    let mut harness = harness(2, 1);
    let exiting_pid = FIRST_PID + 1;
    let exiting = caller(&harness, 1);
    let ahead = caller(&harness, 0);
    assert!(ahead < exiting, "the live edge queues ahead of the exit");

    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
    let mut state = StreamState::new();
    state.edges = EdgeEmitter::with_cap(1);
    // Pass 1 carries the initial rows: the exiting edge at 2 entries.
    let mut pass1 = presentation(&harness);
    for edge in &mut pass1.edges {
        if edge.caller == exiting {
            edge.entry_count = 2;
        }
    }
    emit_pass_events(&mut writer, &mut state, &report(1), &pass1, 1).unwrap();
    assert_eq!(state.last_deferred.edge_events, 1);
    emit_pass_events(&mut writer, &mut state, &report(2), &pass1, 2).unwrap();
    assert_eq!(state.last_deferred.edge_events, 0, "both rows carried");

    // The exit: the caller dies, its edge reaches its terminal
    // revision (exit presence, 3 entries), and the live edge bumps
    // across a count bucket so both rows are due with the live row
    // ahead in FIFO order.
    kill_pid(&mut harness, exiting_pid, &[FIRST_PID]);
    assert!(
        harness
            .coordinator()
            .adapter()
            .record(exiting)
            .is_some_and(|record| record.retired),
        "production reconcile retires the dead pid"
    );
    let mut pass2 = presentation(&harness);
    assert_eq!(
        pass2
            .edges
            .iter()
            .find(|edge| edge.caller == exiting)
            .expect("exited edge retained")
            .presence,
        Presence::ProcessExited,
        "the exit flips presence"
    );
    for edge in &mut pass2.edges {
        if edge.caller == exiting {
            edge.entry_count = 3;
        } else {
            edge.entry_count = 1;
        }
    }
    emit_pass_events(&mut writer, &mut state, &report(3), &pass2, 3).unwrap();
    assert_eq!(
        state.last_deferred.edge_events, 1,
        "the exit update waits behind the cap"
    );

    // The fold must wait: the terminal exit revision is still queued.
    state.last_stream_view = Some(std::sync::Arc::new(pass2));
    let dummy = dir.path().join("dummy.jsonl");
    let stream = EventLogState::new(Some(EventWriter::create(&dummy, 1 << 20, 2).unwrap()));
    assert!(stream.emits(), "the gate runs on the streaming path");
    let now = harness.now_ns();
    retire_rendered_callers(harness.coordinator_mut(), None, &stream, &mut state, now);
    assert!(
        harness.coordinator().adapter().record(exiting).is_some(),
        "the fold waits for the queued exit revision"
    );

    // The next pass drains the terminal revision with the same
    // terminal rows; then the fold runs.
    let mut pass3 = presentation(&harness);
    for edge in &mut pass3.edges {
        if edge.caller == exiting {
            edge.entry_count = 3;
        } else {
            edge.entry_count = 1;
        }
    }
    emit_pass_events(&mut writer, &mut state, &report(4), &pass3, 4).unwrap();
    assert_eq!(
        state.last_deferred.edge_events, 0,
        "the exit revision drains"
    );
    state.last_stream_view = Some(std::sync::Arc::new(pass3));
    let carried_before = state.edges.carried_bytes();
    let now = harness.now_ns();
    retire_rendered_callers(harness.coordinator_mut(), None, &stream, &mut state, now);
    assert!(
        harness.coordinator().adapter().record(exiting).is_none(),
        "the published terminal revision folds"
    );
    drop(writer);

    // The stream alone proves the terminal count and the retention
    // accounting: FIFO order with the exit revision last, pass
    // markers naming the deferral, and the folded digest leaving the
    // retention bound.
    let all = lines(&path);
    let counts: Vec<u64> = all
        .iter()
        .filter(|line| line["kind"] == "edge_observed")
        .map(|line| line["event"]["entries"]["count"].as_u64().unwrap())
        .collect();
    assert_eq!(
        counts,
        vec![0, 2, 1, 3],
        "FIFO order with the terminal revision last"
    );
    assert_eq!(pass_lines(&all, 3).1["edge_events_deferred"], 1);
    assert_eq!(pass_lines(&all, 4).1["edge_events_deferred"], 0);
    assert_eq!(state.edges.tracked_len(), 1, "one live digest retained");
    assert!(
        state.edges.carried_bytes() < carried_before,
        "the folded digest leaves the retention bound"
    );
}

/// F3 instance twin: the same small-cap deferral for the two instance
/// rows. The instance row drains first, its semantic revision waits,
/// and the fold must wait for it: the stream's last records must be
/// the terminal revisions of both rows.
#[test]
fn fold_waits_for_deferred_instance_rows_before_folding_caller() {
    use crate::attach::capture::NativeDomainId;
    use crate::discovery::caller_registry::instance_input::{AdmittedInstance, InstanceKey};
    use crate::discovery::instances::InstanceId;
    use p11scope_ebpf_common::ImageIdentity;
    let mut harness = harness(1, 1);
    let exiting_pid = FIRST_PID;
    let exiting = caller(&harness, 0);
    let domain = NativeDomainId::try_mint().expect("fresh domain");
    let module = key(99);
    harness
        .coordinator_mut()
        .registry_mut()
        .scripted_module_edge(module.clone(), exiting);
    let instance_key = InstanceKey::scripted(
        domain,
        ImageIdentity {
            task_cookie: 300,
            exec_id: 1,
        },
        InstanceId::from_raw(7),
        module,
    );
    harness
        .coordinator_mut()
        .registry_mut()
        .note_instance(AdmittedInstance::scripted(instance_key, exiting));
    harness.coordinator_mut().registry_mut().publish();

    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
    let mut state = StreamState::new();
    state.instances = InstanceEmitter::with_cap(1);
    let pass1 = presentation(&harness);
    assert_eq!(pass1.instances.len(), 1, "the instance row renders");
    assert_eq!(pass1.semantic_edges.len(), 1, "the semantic row renders");
    emit_pass_events(&mut writer, &mut state, &report(1), &pass1, 1).unwrap();
    emit_pass_events(&mut writer, &mut state, &report(2), &pass1, 2).unwrap();
    assert_eq!(state.last_deferred.instance_events, 0);
    assert_eq!(
        state.last_deferred.semantic_edge_events, 0,
        "both rows carried"
    );

    // The exit with a final semantic revision: both rows change, the
    // instance row writes first, the semantic revision waits behind
    // the cap.
    kill_pid(&mut harness, exiting_pid, &[]);
    let mut pass2 = presentation(&harness);
    assert_eq!(pass2.instances.len(), 1, "the instance row survives");
    let terminal_seen = pass2.instances[0].last_seen_ns + 1;
    for row in &mut pass2.instances {
        row.last_seen_ns = terminal_seen;
    }
    for row in &mut pass2.semantic_edges {
        row.api_returns = Some(row.api_returns.unwrap_or(0) + 5);
    }
    emit_pass_events(&mut writer, &mut state, &report(3), &pass2, 3).unwrap();
    assert_eq!(
        state.last_deferred.instance_events, 0,
        "the instance row drains"
    );
    assert_eq!(
        state.last_deferred.semantic_edge_events, 1,
        "the semantic revision waits behind the cap"
    );

    // The fold must wait for the queued semantic revision.
    state.last_stream_view = Some(std::sync::Arc::new(pass2));
    let dummy = dir.path().join("dummy.jsonl");
    let stream = EventLogState::new(Some(EventWriter::create(&dummy, 1 << 20, 2).unwrap()));
    let now = harness.now_ns();
    retire_rendered_callers(harness.coordinator_mut(), None, &stream, &mut state, now);
    assert!(
        harness.coordinator().adapter().record(exiting).is_some(),
        "the fold waits for the queued semantic revision"
    );

    // The next pass drains the terminal semantic revision with the
    // same terminal rows; then the fold runs.
    let mut pass3 = presentation(&harness);
    for row in &mut pass3.instances {
        row.last_seen_ns = terminal_seen;
    }
    for row in &mut pass3.semantic_edges {
        row.api_returns = Some(5);
    }
    emit_pass_events(&mut writer, &mut state, &report(4), &pass3, 4).unwrap();
    assert_eq!(state.last_deferred.semantic_edge_events, 0);
    state.last_stream_view = Some(std::sync::Arc::new(pass3));
    let now = harness.now_ns();
    retire_rendered_callers(harness.coordinator_mut(), None, &stream, &mut state, now);
    assert!(
        harness.coordinator().adapter().record(exiting).is_none(),
        "the published terminal revisions fold"
    );
    drop(writer);

    // The stream alone proves both terminal revisions: the last
    // record of each row kind carries the terminal payload, and the
    // folded digest leaves the retention bound.
    let all = lines(&path);
    let last_instance = all
        .iter()
        .rev()
        .find(|line| line["kind"] == "instance_observed")
        .expect("instance records streamed");
    assert_eq!(
        last_instance["event"]["last_seen_ns"].as_u64().unwrap(),
        terminal_seen,
        "the terminal instance revision streams last"
    );
    let last_semantic = all
        .iter()
        .rev()
        .find(|line| line["kind"] == "semantic_edge_observed")
        .expect("semantic records streamed");
    assert_eq!(
        last_semantic["event"]["api_returns"]["count"]
            .as_u64()
            .unwrap(),
        5,
        "the terminal semantic revision streams last"
    );
    assert_eq!(pass_lines(&all, 3).1["edge_events_deferred"], 0);
    assert_eq!(state.instances.tracked_len(), 0, "no digest retained");
}

/// F4 wrapper twin: a stop delivered before terminal certification
/// aborts the streaming wrapper — nothing folds, and the partial
/// pass notes nothing into the carry — and clearing it resumes
/// normally.
#[test]
fn fold_streaming_wrapper_checks_stop_before_certifying_terminal_rows() {
    use crate::inventory_present::Presence;
    let mut harness = harness(2, 1);
    let exiting_pid = FIRST_PID + 1;
    let exiting = caller(&harness, 1);
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
    let mut state = StreamState::new();
    // Carry the initial rows, then the terminal exit revision.
    let mut pass1 = presentation(&harness);
    for edge in &mut pass1.edges {
        if edge.caller == exiting {
            edge.entry_count = 2;
        }
    }
    emit_pass_events(&mut writer, &mut state, &report(1), &pass1, 1).unwrap();
    emit_pass_events(&mut writer, &mut state, &report(2), &pass1, 2).unwrap();
    assert_eq!(state.last_deferred.edge_events, 0, "the initial rows drain");
    kill_pid(&mut harness, exiting_pid, &[FIRST_PID]);
    let mut pass2 = presentation(&harness);
    for edge in &mut pass2.edges {
        if edge.caller == exiting {
            assert_eq!(
                edge.presence,
                Presence::ProcessExited,
                "the exit flips presence"
            );
            edge.entry_count = 3;
        } else {
            edge.entry_count = 1;
        }
    }
    emit_pass_events(&mut writer, &mut state, &report(3), &pass2, 3).unwrap();
    emit_pass_events(&mut writer, &mut state, &report(4), &pass2, 4).unwrap();
    assert_eq!(
        state.last_deferred.edge_events, 0,
        "the terminal revision drains"
    );
    state.last_stream_view = Some(std::sync::Arc::new(pass2));
    let dummy = dir.path().join("dummy.jsonl");
    let stream = EventLogState::new(Some(EventWriter::create(&dummy, 1 << 20, 2).unwrap()));
    assert!(stream.emits(), "the gate runs on the streaming path");
    // The stop lands before certification: nothing folds.
    let signals = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(1));
    harness
        .coordinator_mut()
        .set_stop_source(std::sync::Arc::clone(&signals));
    let now = harness.now_ns();
    retire_rendered_callers(harness.coordinator_mut(), None, &stream, &mut state, now);
    assert!(
        harness.coordinator().adapter().record(exiting).is_some(),
        "a stop before certification folds nothing"
    );
    // The aborted pass noted nothing: with the stop cleared, a bare
    // coordinator retirement (no wrapper re-note) finds no carry.
    signals.store(0, std::sync::atomic::Ordering::SeqCst);
    let now = harness.now_ns();
    assert_eq!(
        harness
            .coordinator_mut()
            .retire_rendered_callers(now, None)
            .retired,
        0,
        "the aborted pass notes nothing into the carry"
    );
    // Clearing the stop resumes normally through the wrapper.
    let now = harness.now_ns();
    retire_rendered_callers(harness.coordinator_mut(), None, &stream, &mut state, now);
    assert!(
        harness.coordinator().adapter().record(exiting).is_none(),
        "clearing the stop folds the terminal row"
    );
    drop(writer);
}

/// Stage a 70-caller stream scene with one exited caller, one extra
/// module edge and three instances on the first live caller: every
/// row carried, the exit terminal, so the wrapper certifies 70 rows
/// through the caller copy, the membership scans, the identity build
/// and the carry stage. Returns the harness, an emitting stream, the
/// stream state, the exiting caller, the tempdir holding the logs and
/// the wired stop counter (quiet).
fn stage_cert_scene() -> (
    Harness,
    EventLogState,
    StreamState,
    CallerId,
    tempfile::TempDir,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    use crate::attach::capture::NativeDomainId;
    use crate::discovery::caller_registry::instance_input::{AdmittedInstance, InstanceKey};
    use crate::discovery::instances::InstanceId;
    use p11scope_ebpf_common::ImageIdentity;
    const CALLERS: u32 = 70;
    let mut harness = harness(CALLERS as usize, 2);
    let live = caller(&harness, 0);
    let exiting = caller(&harness, CALLERS - 1);
    // One extra edge plus three instances on the first live caller,
    // so the membership scans examine edges and instances alike.
    let domain = NativeDomainId::try_mint().expect("fresh domain");
    let extra = key(99);
    harness
        .coordinator_mut()
        .registry_mut()
        .scripted_module_edge(extra.clone(), live);
    for (slot, cookie) in [7u64, 8, 9].into_iter().zip([300u64, 301, 302]) {
        let instance = InstanceKey::scripted(
            domain,
            ImageIdentity {
                task_cookie: cookie,
                exec_id: 1,
            },
            InstanceId::from_raw(slot),
            extra.clone(),
        );
        harness
            .coordinator_mut()
            .registry_mut()
            .note_instance(AdmittedInstance::scripted(instance, live));
    }
    harness.coordinator_mut().registry_mut().publish();
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 24, 4).unwrap();
    let mut state = StreamState::new();
    let mut pass = 0u64;
    let mut emit_until_carried =
        |writer: &mut EventWriter, state: &mut StreamState, view: &Presentation| {
            for _ in 0..100_000 {
                pass += 1;
                let at = pass;
                emit_pass_events(writer, state, &report(pass), view, at).unwrap();
                if state.last_deferred.edge_events == 0
                    && state.last_deferred.instance_events == 0
                    && state.last_deferred.semantic_edge_events == 0
                {
                    return;
                }
            }
            panic!("the capped FIFO never drained");
        };
    // Carry every initial row: the exiting edges at 2 entries.
    let mut pass1 = presentation(&harness);
    for edge in &mut pass1.edges {
        if edge.caller == exiting {
            edge.entry_count = 2;
        }
    }
    emit_until_carried(&mut writer, &mut state, &pass1);
    // The exit: the caller dies and its edges reach their terminal
    // revision (exit presence, 3 entries).
    let exiting_pid = FIRST_PID + CALLERS - 1;
    let survivors: Vec<u32> = (FIRST_PID..FIRST_PID + CALLERS - 1).collect();
    kill_pid(&mut harness, exiting_pid, &survivors);
    let mut pass2 = presentation(&harness);
    for edge in &mut pass2.edges {
        if edge.caller == exiting {
            assert_eq!(
                edge.presence,
                crate::inventory_present::Presence::ProcessExited,
                "the exit flips presence"
            );
            edge.entry_count = 3;
        }
    }
    emit_until_carried(&mut writer, &mut state, &pass2);
    state.last_stream_view = Some(std::sync::Arc::new(pass2));
    drop(writer);
    let dummy = dir.path().join("dummy.jsonl");
    let stream = EventLogState::new(Some(EventWriter::create(&dummy, 1 << 20, 2).unwrap()));
    assert!(stream.emits(), "the gate runs on the streaming path");
    let wired = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    harness
        .coordinator_mut()
        .set_stop_source(std::sync::Arc::clone(&wired));
    (harness, stream, state, exiting, dir, wired)
}

/// Certification-stride twin, wired: trip the wired operator counter
/// from a visit hook after a nonzero stride inside the caller copy,
/// the identity build and the carry stage in turn, while the
/// production wrapper polls it through its own stop query. Each trip
/// aborts the pass — nothing folds and the carry stays intact — and
/// clearing the counter resumes to an exact fold of the exited row
/// with every live row surviving.
#[test]
fn fold_certification_aborts_and_resumes_at_every_stride_phase() {
    for (trip_after, phase) in [(10u64, "copy"), (300, "identity"), (350, "carry")] {
        let (mut harness, stream, mut state, exiting, _dir, wired) = stage_cert_scene();
        if phase == "carry" {
            // A credit-deferred row the commit would replace: the
            // aborted carry stage must leave it untouched.
            harness
                .coordinator_mut()
                .note_rendered_callers(&[CallerId(999_999)]);
        }
        // The signal travels hook -> wired counter -> production stop
        // query: no injected predicate stands between the trip and the
        // abort, so the abort below proves the production wiring.
        let _guard = crate::discovery::engine::inventory_coordinator::test_visit_hook::hold({
            let wired = std::sync::Arc::clone(&wired);
            move |units| {
                if units > trip_after {
                    wired.store(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        });
        let now = harness.now_ns();
        let report =
            retire_rendered_callers(harness.coordinator_mut(), None, &stream, &mut state, now);
        assert_eq!(
            wired.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "{phase}: the hook trips the wired counter"
        );
        assert_eq!(
            report.retired, 0,
            "{phase}: a mid-certification stop folds nothing"
        );
        assert!(
            !report.committed,
            "{phase}: the aborted pass commits no carry"
        );
        match phase {
            "copy" => {
                assert_eq!(
                    report.units, 64,
                    "copy: the first stride lap aborts the ID copy"
                );
                assert_eq!(
                    report.callers_copied, 63,
                    "copy: the ID copy aborts partway, past a nonzero stride"
                );
                assert!(
                    !report.identity_built,
                    "copy: the identity index never builds"
                );
                assert_eq!(report.certified, 0, "copy: nothing certifies");
            }
            "identity" => {
                assert_eq!(
                    report.units, 320,
                    "identity: the trip lands inside the identity build"
                );
                assert_eq!(
                    report.callers_copied, 70,
                    "identity: the ID copy completed first"
                );
                assert!(
                    !report.identity_built,
                    "identity: the index build aborts before completing"
                );
                assert_eq!(
                    report.certified, 0,
                    "identity: nothing certifies before the index completes"
                );
            }
            "carry" => {
                assert_eq!(
                    report.units, 384,
                    "carry: the trip lands inside the carry stage"
                );
                assert!(
                    report.identity_built,
                    "carry: certification completed before the trip"
                );
                assert_eq!(
                    report.certified, 70,
                    "carry: every row certified before the trip"
                );
                assert_eq!(
                    harness.coordinator().rendered_len_for_test(),
                    1,
                    "carry: the aborted stage leaves the prior carry untouched"
                );
            }
            _ => unreachable!("the loop above names every phase"),
        }
        if phase != "carry" {
            assert_eq!(
                harness.coordinator().rendered_len_for_test(),
                0,
                "{phase}: the aborted pass notes nothing"
            );
        }
        assert!(
            harness.coordinator().adapter().record(exiting).is_some(),
            "{phase}: no row folds on the aborted pass"
        );
        // Clearing the counter and releasing the hook resumes to an
        // exact fold.
        drop(_guard);
        wired.store(0, std::sync::atomic::Ordering::SeqCst);
        if phase != "carry" {
            // The aborted pass noted nothing: a quiet bare retirement
            // finds no carry.
            let now = harness.now_ns();
            assert_eq!(
                harness
                    .coordinator_mut()
                    .retire_rendered_callers(now, None)
                    .retired,
                0,
                "{phase}: the aborted pass notes nothing into the carry"
            );
        }
        let now = harness.now_ns();
        retire_rendered_callers(harness.coordinator_mut(), None, &stream, &mut state, now);
        assert!(
            harness.coordinator().adapter().record(exiting).is_none(),
            "{phase}: the resume folds the exited row"
        );
        assert_eq!(
            harness.coordinator().retired_caller_rows_for_test(),
            1,
            "{phase}: the resume publishes the row once"
        );
        for index in 0..69u32 {
            assert!(
                harness
                    .coordinator()
                    .adapter()
                    .record(caller(&harness, index))
                    .is_some(),
                "{phase}: live rows survive the resume"
            );
        }
    }
}

/// F1 credit-boundary twin (fix2): 1,025 exited callers share one
/// publication while the fold carries 1,024 credits, so the last
/// caller (the largest id) waits at the credit boundary. A retained
/// terminal revision then lands for the waiting caller — a count
/// bucket jump on its edge plus both instance-slot revisions — while
/// the FIFO holds a live row ahead of each update. The fold must
/// wait for the queued terminal revisions: the carried credit
/// membership alone must not authorize the fold, since the post-fold
/// forget would erase the digest and the queued update together and
/// leave the stream with a stale terminal record. Counts ride on the
/// captured views (the emitter and the gate both read views; the
/// registry carries row existence and freezes counts at retirement),
/// so the revision is exact without BPF realism. In production the
/// retained-row revision arrives as a native-side coverage downgrade
/// (the frozen-watch overflow twin pins that path); the count
/// revision exercises the identical exact-payload gate.
#[test]
fn fold_credit_deferred_caller_revised_behind_fifo_waits_for_terminal() {
    use crate::attach::capture::NativeDomainId;
    use crate::discovery::caller_registry::instance_input::{AdmittedInstance, InstanceKey};
    use crate::discovery::instances::InstanceId;
    use crate::inventory_present::Presence;
    use p11scope_ebpf_common::ImageIdentity;
    const EXITED: u32 = 1025;
    let mut harness = harness((EXITED + 1) as usize, 1);
    let live = caller(&harness, 0);
    let target = caller(&harness, EXITED);
    assert!(
        live < target,
        "the live edge queues ahead of the deferred exit"
    );
    let mut exited = Vec::new();
    for index in 1..=EXITED {
        exited.push(caller(&harness, index));
    }
    assert_eq!(
        exited.iter().max(),
        Some(&target),
        "the deferred caller sorts last, past the credit boundary"
    );
    // The deferred caller owns an instance, so both instance slots
    // gate with its edge.
    let domain = NativeDomainId::try_mint().expect("fresh domain");
    let extra = key(99);
    harness
        .coordinator_mut()
        .registry_mut()
        .scripted_module_edge(extra.clone(), target);
    let instance_key = InstanceKey::scripted(
        domain,
        ImageIdentity {
            task_cookie: 300,
            exec_id: 1,
        },
        InstanceId::from_raw(7),
        extra,
    );
    harness
        .coordinator_mut()
        .registry_mut()
        .note_instance(AdmittedInstance::scripted(instance_key, target));
    harness.coordinator_mut().registry_mut().publish();

    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 24, 4).unwrap();
    let mut state = StreamState::new();
    state.edges = EdgeEmitter::with_cap(1);
    state.instances = InstanceEmitter::with_cap(1);
    let mut pass = 0u64;
    let emit_until_carried =
        |writer: &mut EventWriter, state: &mut StreamState, view: &Presentation, pass: &mut u64| {
            for _ in 0..100_000 {
                *pass += 1;
                let at = *pass;
                emit_pass_events(writer, state, &report(*pass), view, at).unwrap();
                if state.last_deferred.edge_events == 0
                    && state.last_deferred.instance_events == 0
                    && state.last_deferred.semantic_edge_events == 0
                {
                    return;
                }
            }
            panic!("the capped FIFO never drained");
        };
    // Carry every initial row: the exiting edges at 2 entries.
    let mut pass1 = presentation(&harness);
    assert_eq!(
        pass1.edges.len(),
        (EXITED + 2) as usize,
        "one edge per caller plus the deferred second"
    );
    assert_eq!(pass1.instances.len(), 1, "the instance row renders");
    assert_eq!(pass1.semantic_edges.len(), 1, "the semantic row renders");
    for edge in &mut pass1.edges {
        if edge.caller != live {
            edge.entry_count = 2;
        }
    }
    emit_until_carried(&mut writer, &mut state, &pass1, &mut pass);

    // The exits: every caller but the live one dies through the
    // production reconcile path, and each edge reaches its terminal
    // revision (exit presence, 3 entries) with the live edge bumped
    // across a count bucket.
    for pid in FIRST_PID + 1..=FIRST_PID + EXITED {
        harness.source().kill(pid);
    }
    let observed: BTreeSet<u32> = [FIRST_PID].into_iter().collect();
    let now = harness.now_ns();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    harness.advance(10);
    for id in &exited {
        assert!(
            harness
                .coordinator()
                .adapter()
                .record(*id)
                .is_some_and(|record| record.retired),
            "production reconcile retires every dead pid"
        );
    }
    let mut pass_terminal = presentation(&harness);
    for edge in &mut pass_terminal.edges {
        if edge.caller == live {
            edge.entry_count = 1;
        } else {
            assert_eq!(
                edge.presence,
                Presence::ProcessExited,
                "the exit flips presence"
            );
            edge.entry_count = 3;
        }
    }
    let terminal_seen = pass_terminal.instances[0].last_seen_ns;
    let terminal_returns = pass_terminal.semantic_edges[0].api_returns;
    emit_until_carried(&mut writer, &mut state, &pass_terminal, &mut pass);

    // Pass A: the fold carries 1,024 credits and defers the largest
    // id. Every other exited row folds.
    state.last_stream_view = Some(std::sync::Arc::new(pass_terminal.clone()));
    let dummy = dir.path().join("dummy.jsonl");
    let stream = EventLogState::new(Some(EventWriter::create(&dummy, 1 << 20, 2).unwrap()));
    assert!(stream.emits(), "the gate runs on the streaming path");
    let now = harness.now_ns();
    retire_rendered_callers(harness.coordinator_mut(), None, &stream, &mut state, now);
    assert!(
        harness.coordinator().adapter().record(target).is_some(),
        "the credit boundary defers the largest id"
    );
    for id in exited.iter().filter(|id| **id != target) {
        assert!(
            harness.coordinator().adapter().record(*id).is_none(),
            "every credited row folds"
        );
    }
    assert_eq!(state.edges.tracked_len(), 3, "live plus the deferred pair");
    let totals = harness.coordinator().registry().departed_totals();
    assert_eq!(totals.edges, u64::from(EXITED - 1), "1,024 edges folded");

    // The retained revision: the deferred edge jumps a count bucket
    // (3 to 4) and both instance slots move, while the live edge's
    // own bump (1 to 2) queues ahead behind the unit cap.
    let mut pass_revised = presentation(&harness);
    assert_eq!(
        pass_revised.edges.len(),
        3,
        "only the live edge and the deferred pair survive the fold"
    );
    // The live edge owns only the scale module, so it names the
    // revised edge: the deferred caller's scale-module edge jumps 3
    // to 4 while its second edge stays at its carried 3.
    let m0 = pass_revised
        .edges
        .iter()
        .find(|edge| edge.caller == live)
        .expect("live edge retained")
        .module;
    for edge in &mut pass_revised.edges {
        if edge.caller == live {
            edge.entry_count = 2;
        } else if edge.caller == target {
            edge.entry_count = if edge.module == m0 { 4 } else { 3 };
        }
    }
    for row in &mut pass_revised.instances {
        row.last_seen_ns = terminal_seen + 1;
    }
    for row in &mut pass_revised.semantic_edges {
        row.api_returns = Some(terminal_returns.unwrap_or(0) + 5);
    }
    pass += 1;
    emit_pass_events(&mut writer, &mut state, &report(pass), &pass_revised, pass).unwrap();
    assert_eq!(
        state.last_deferred.edge_events, 1,
        "the edge revision waits behind the live row"
    );
    assert_eq!(
        state.last_deferred.instance_events, 0,
        "the instance row drains"
    );
    assert_eq!(
        state.last_deferred.semantic_edge_events, 1,
        "the semantic revision waits behind the cap"
    );

    // Pass B: the carried credit membership alone must not fold the
    // caller whose terminal revisions are still queued.
    state.last_stream_view = Some(std::sync::Arc::new(pass_revised.clone()));
    let carried_before = state.edges.carried_bytes();
    let now = harness.now_ns();
    retire_rendered_callers(harness.coordinator_mut(), None, &stream, &mut state, now);
    assert!(
        harness.coordinator().adapter().record(target).is_some(),
        "the fold waits for the queued terminal revisions past the credit boundary"
    );
    assert_eq!(
        state.edges.tracked_len(),
        3,
        "the waiting caller's digests survive the pass"
    );
    assert_eq!(
        state.edges.carried_bytes(),
        carried_before,
        "no digest leaves the retention bound before its revision lands"
    );

    // The next passes drain both terminal revisions with the same
    // terminal rows; then the fold runs.
    emit_until_carried(&mut writer, &mut state, &pass_revised, &mut pass);
    state.last_stream_view = Some(std::sync::Arc::new(pass_revised));
    let now = harness.now_ns();
    retire_rendered_callers(harness.coordinator_mut(), None, &stream, &mut state, now);
    assert!(
        harness.coordinator().adapter().record(target).is_none(),
        "the published terminal revisions fold"
    );
    drop(writer);

    // The stream alone proves the terminal payloads: the last record
    // of each row kind carries the terminal revision, the folded
    // digests leave the retention bound, and the departed aggregate
    // counts the folded pair.
    let all = lines(&path);
    let last_edge = all
        .iter()
        .rev()
        .find(|line| line["kind"] == "edge_observed")
        .expect("edge records streamed");
    assert_eq!(
        last_edge["event"]["entries"]["count"].as_u64().unwrap(),
        4,
        "the terminal edge revision streams last"
    );
    let last_instance = all
        .iter()
        .rev()
        .find(|line| line["kind"] == "instance_observed")
        .expect("instance records streamed");
    assert_eq!(
        last_instance["event"]["last_seen_ns"].as_u64().unwrap(),
        terminal_seen + 1,
        "the terminal instance revision streams last"
    );
    let last_semantic = all
        .iter()
        .rev()
        .find(|line| line["kind"] == "semantic_edge_observed")
        .expect("semantic records streamed");
    assert_eq!(
        last_semantic["event"]["api_returns"]["count"]
            .as_u64()
            .unwrap(),
        terminal_returns.unwrap_or(0) + 5,
        "the terminal semantic revision streams last"
    );
    assert_eq!(state.edges.tracked_len(), 1, "one live digest retained");
    assert!(
        state.edges.carried_bytes() < carried_before,
        "the folded digests leave the retention bound"
    );
    assert_eq!(state.instances.tracked_len(), 0, "no digest retained");
    let totals = harness.coordinator().registry().departed_totals();
    assert_eq!(
        totals.edges,
        u64::from(EXITED + 1),
        "the deferred pair folds"
    );
}

/// Staged-authority twin: an oversized caller stages across the credit
/// boundary while 1,022 exited siblings fold, then revises its terminal
/// payload (same member keys) behind the capped FIFO while the live
/// leader stays certified. The streaming wrapper excludes the staged
/// caller from the fresh carry; the coordinator must cancel the stage
/// without folding — the row, its sequences and its queued terminal
/// revision all survive the pass — and the caller folds once its
/// revision lands, with the stream carrying the terminal payloads
/// last. Counts ride on the captured views, as in the credit-deferred
/// twin; the binder sequences that make the caller oversized never
/// render.
#[test]
fn fold_staged_caller_revised_behind_fifo_cancels_without_forgetting_terminal() {
    use crate::attach::capture::NativeDomainId;
    use crate::discovery::caller_registry::instance_input::{AdmittedInstance, InstanceKey};
    use crate::discovery::instances::InstanceId;
    use crate::inventory_present::Presence;
    use p11scope_ebpf_common::ImageIdentity;
    const SIBLINGS: u32 = 1022;
    // Members: 65,533 sequences + 2 edges + 1 instance = 65,536 =
    // 1,024 strides, so the caller costs 1,025 credits and stages.
    // Pass A folds the siblings (1,022 credits) and rehearses two
    // strides of the stage; a carry violation would drain the
    // remaining 1,022 strides in pass B and fold.
    const BINDER: u64 = 65_533;
    let mut harness = harness((SIBLINGS + 2) as usize, 1);
    let live = caller(&harness, 0);
    let heavy = caller(&harness, SIBLINGS + 1);
    assert!(live < heavy, "the live edge queues ahead of the staged exit");
    let mut exited = Vec::new();
    for index in 1..=SIBLINGS + 1 {
        exited.push(caller(&harness, index));
    }
    assert_eq!(
        exited.iter().max(),
        Some(&heavy),
        "the staged caller sorts last, past the credit boundary"
    );
    // The staged caller owns a second edge, an instance (so both
    // instance slots gate with its edges) and the binder sequences
    // that make it oversized.
    let domain = NativeDomainId::try_mint().expect("fresh domain");
    let extra = key(99);
    harness
        .coordinator_mut()
        .registry_mut()
        .scripted_module_edge(extra.clone(), heavy);
    let instance_key = InstanceKey::scripted(
        domain,
        ImageIdentity {
            task_cookie: 300,
            exec_id: 1,
        },
        InstanceId::from_raw(7),
        extra,
    );
    harness
        .coordinator_mut()
        .registry_mut()
        .note_instance(AdmittedInstance::scripted(instance_key, heavy));
    harness.coordinator_mut().registry_mut().publish();
    let binder_domain = NativeDomainId::try_mint().expect("fresh binder domain");
    for sequence in 0..BINDER {
        harness.coordinator_mut().stage_binder_cookie_for_test(
            binder_domain,
            100 + sequence,
            sequence,
            Some(heavy),
        );
    }

    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 24, 4).unwrap();
    let mut state = StreamState::new();
    state.edges = EdgeEmitter::with_cap(1);
    state.instances = InstanceEmitter::with_cap(1);
    let mut pass = 0u64;
    let emit_until_carried =
        |writer: &mut EventWriter, state: &mut StreamState, view: &Presentation, pass: &mut u64| {
            for _ in 0..100_000 {
                *pass += 1;
                let at = *pass;
                emit_pass_events(writer, state, &report(*pass), view, at).unwrap();
                if state.last_deferred.edge_events == 0
                    && state.last_deferred.instance_events == 0
                    && state.last_deferred.semantic_edge_events == 0
                {
                    return;
                }
            }
            panic!("the capped FIFO never drained");
        };
    // Carry every initial row: the exiting edges at 2 entries.
    let mut pass1 = presentation(&harness);
    assert_eq!(
        pass1.edges.len(),
        (SIBLINGS + 3) as usize,
        "one edge per caller plus the staged second"
    );
    assert_eq!(pass1.instances.len(), 1, "the instance row renders");
    assert_eq!(pass1.semantic_edges.len(), 1, "the semantic row renders");
    for edge in &mut pass1.edges {
        if edge.caller != live {
            edge.entry_count = 2;
        }
    }
    emit_until_carried(&mut writer, &mut state, &pass1, &mut pass);

    // The exits: every caller but the live one dies through the
    // production reconcile path, and each edge reaches its terminal
    // revision (exit presence, 3 entries).
    for pid in FIRST_PID + 1..=FIRST_PID + SIBLINGS + 1 {
        harness.source().kill(pid);
    }
    let observed: BTreeSet<u32> = [FIRST_PID].into_iter().collect();
    let now = harness.now_ns();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    harness.advance(10);
    for id in &exited {
        assert!(
            harness
                .coordinator()
                .adapter()
                .record(*id)
                .is_some_and(|record| record.retired),
            "production reconcile retires every dead pid"
        );
    }
    let mut pass_terminal = presentation(&harness);
    for edge in &mut pass_terminal.edges {
        if edge.caller == live {
            edge.entry_count = 1;
        } else {
            assert_eq!(
                edge.presence,
                Presence::ProcessExited,
                "the exit flips presence"
            );
            edge.entry_count = 3;
        }
    }
    let terminal_seen = pass_terminal.instances[0].last_seen_ns;
    let terminal_returns = pass_terminal.semantic_edges[0].api_returns;
    emit_until_carried(&mut writer, &mut state, &pass_terminal, &mut pass);

    // Pass A: the fold carries 1,024 credits, folds the 1,022 siblings
    // and stages the oversized caller with the remaining two.
    state.last_stream_view = Some(std::sync::Arc::new(pass_terminal.clone()));
    let dummy = dir.path().join("dummy.jsonl");
    let stream = EventLogState::new(Some(EventWriter::create(&dummy, 1 << 20, 2).unwrap()));
    assert!(stream.emits(), "the gate runs on the streaming path");
    let now = harness.now_ns();
    let report_a = retire_rendered_callers(harness.coordinator_mut(), None, &stream, &mut state, now);
    assert_eq!(
        report_a.retired,
        u64::from(SIBLINGS),
        "pass A folds the credited siblings"
    );
    assert!(
        harness.coordinator().adapter().record(heavy).is_some(),
        "the oversized caller waits staged"
    );
    assert_eq!(
        harness.coordinator().staged_fold_complete_for_test(),
        Some(false),
        "pass A leaves the stage open"
    );
    for id in exited.iter().filter(|id| **id != heavy) {
        assert!(
            harness.coordinator().adapter().record(*id).is_none(),
            "every credited row folds"
        );
    }
    assert_eq!(state.edges.tracked_len(), 3, "live plus the staged pair");
    let totals = harness.coordinator().registry().departed_totals();
    assert_eq!(totals.edges, u64::from(SIBLINGS), "1,022 edges folded");

    // The retained revision: the staged scale edge jumps a count
    // bucket (3 to 4) and both instance slots move, while the live
    // edge's own bump (1 to 2) queues ahead behind the unit cap.
    // Member keys stay identical, so only the carry exclusion guards
    // the stage.
    let mut pass_revised = presentation(&harness);
    assert_eq!(
        pass_revised.edges.len(),
        3,
        "only the live edge and the staged pair survive the fold"
    );
    let m0 = pass_revised
        .edges
        .iter()
        .find(|edge| edge.caller == live)
        .expect("live edge retained")
        .module;
    for edge in &mut pass_revised.edges {
        if edge.caller == live {
            edge.entry_count = 2;
        } else if edge.caller == heavy {
            edge.entry_count = if edge.module == m0 { 4 } else { 3 };
        }
    }
    for row in &mut pass_revised.instances {
        row.last_seen_ns = terminal_seen + 1;
    }
    for row in &mut pass_revised.semantic_edges {
        row.api_returns = Some(terminal_returns.unwrap_or(0) + 5);
    }
    pass += 1;
    emit_pass_events(&mut writer, &mut state, &report(pass), &pass_revised, pass).unwrap();
    assert_eq!(
        state.last_deferred.edge_events, 1,
        "the edge revision waits behind the live row"
    );
    assert_eq!(
        state.last_deferred.instance_events, 0,
        "the instance row drains"
    );
    assert_eq!(
        state.last_deferred.semantic_edge_events, 1,
        "the semantic revision waits behind the cap"
    );

    // Pass B: the fresh carry excludes the staged caller (its terminal
    // revisions are still queued) while the live leader stays
    // certified. The stage must cancel without folding: live state and
    // the queued payloads survive the pass.
    state.last_stream_view = Some(std::sync::Arc::new(pass_revised.clone()));
    let carried_before = state.edges.carried_bytes();
    let now = harness.now_ns();
    let report_b = retire_rendered_callers(harness.coordinator_mut(), None, &stream, &mut state, now);
    assert_eq!(
        report_b.retired, 0,
        "the excluded stage folds nothing past the queued revisions"
    );
    assert!(
        harness.coordinator().adapter().record(heavy).is_some(),
        "the staged row survives the exclusion pass"
    );
    assert!(
        !harness.coordinator().staged_fold_open_for_test(),
        "the excluded stage cancels instead of folding"
    );
    let owners = harness.coordinator().binder_bound_owners_for_test();
    assert_eq!(
        owners.len(),
        BINDER as usize,
        "the cancelled stage keeps every sequence bound"
    );
    assert!(
        owners.iter().all(|owner| *owner == heavy),
        "no other row loses evidence to the pass"
    );
    assert_eq!(
        harness.coordinator().registry().edges_of(heavy).count(),
        2,
        "the cancelled stage keeps every edge live"
    );
    assert_eq!(
        state.edges.tracked_len(),
        3,
        "the waiting caller's digests survive the pass"
    );
    assert_eq!(
        state.edges.carried_bytes(),
        carried_before,
        "no digest leaves the retention bound before its revision lands"
    );

    // The next passes drain both terminal revisions with the same
    // terminal rows; then the fold runs.
    emit_until_carried(&mut writer, &mut state, &pass_revised, &mut pass);
    let edges_before = harness.coordinator().fold_edge_commit_visits_for_test();
    let instances_before = harness
        .coordinator()
        .fold_instance_commit_visits_for_test();
    state.last_stream_view = Some(std::sync::Arc::new(pass_revised));
    let now = harness.now_ns();
    let report_c = retire_rendered_callers(harness.coordinator_mut(), None, &stream, &mut state, now);
    assert_eq!(
        report_c.retired, 1,
        "the published terminal revisions fold the staged caller"
    );
    assert!(
        harness.coordinator().adapter().record(heavy).is_none(),
        "the staged row folds once its revision lands"
    );
    assert!(
        harness.coordinator().binder_bound_owners_for_test().is_empty(),
        "every staged sequence clears exactly once"
    );
    let marks = harness
        .coordinator()
        .fold_identity_insert_marks_for_test();
    assert_eq!(
        &marks[marks.len().saturating_sub(2)..],
        &[(edges_before + 1, instances_before), (edges_before + 2, instances_before)],
        "the staged commit names each module while its first edge folds"
    );
    drop(writer);

    // The stream alone proves the terminal payloads: the last record
    // of each row kind carries the terminal revision, the folded
    // digests leave the retention bound, and the departed aggregate
    // counts the folded pair.
    let all = lines(&path);
    let last_edge = all
        .iter()
        .rev()
        .find(|line| line["kind"] == "edge_observed")
        .expect("edge records streamed");
    assert_eq!(
        last_edge["event"]["entries"]["count"].as_u64().unwrap(),
        4,
        "the terminal edge revision streams last"
    );
    let last_instance = all
        .iter()
        .rev()
        .find(|line| line["kind"] == "instance_observed")
        .expect("instance records streamed");
    assert_eq!(
        last_instance["event"]["last_seen_ns"].as_u64().unwrap(),
        terminal_seen + 1,
        "the terminal instance revision streams last"
    );
    let last_semantic = all
        .iter()
        .rev()
        .find(|line| line["kind"] == "semantic_edge_observed")
        .expect("semantic records streamed");
    assert_eq!(
        last_semantic["event"]["api_returns"]["count"]
            .as_u64()
            .unwrap(),
        terminal_returns.unwrap_or(0) + 5,
        "the terminal semantic revision streams last"
    );
    assert_eq!(state.edges.tracked_len(), 1, "one live digest retained");
    assert!(
        state.edges.carried_bytes() < carried_before,
        "the folded digests leave the retention bound"
    );
    assert_eq!(state.instances.tracked_len(), 0, "no digest retained");
    let totals = harness.coordinator().registry().departed_totals();
    assert_eq!(
        totals.edges,
        u64::from(SIBLINGS + 2),
        "the staged pair folds"
    );
}

/// F1 slot twin: at the credit boundary, each instance slot vetoes
/// independently while its edge is current. Two waiters defer past
/// 1,024 credited folds; w1's instance row then moves alone and
/// w2's semantic row moves alone, with every edge carried and
/// exact. Each waiter is retained first with its revision stale
/// behind no emission, then with its revision queued behind the
/// unit cap, and folds once its revision lands — the stream's last
/// records carry each terminal payload and the folded aggregates
/// count both waiters.
#[test]
fn fold_credit_deferred_waiters_veto_per_instance_slot_with_current_edges() {
    use crate::attach::capture::NativeDomainId;
    use crate::discovery::caller_registry::instance_input::{AdmittedInstance, InstanceKey};
    use crate::discovery::instances::InstanceId;
    use crate::inventory_present::Presence;
    use p11scope_ebpf_common::ImageIdentity;
    const FILLERS: u32 = 1024;
    const EXITED: u32 = FILLERS + 2;
    let mut harness = harness((EXITED + 1) as usize, 1);
    let live = caller(&harness, 0);
    let w1 = caller(&harness, FILLERS + 1);
    let w2 = caller(&harness, FILLERS + 2);
    let mut exited = Vec::new();
    for index in 1..=EXITED {
        exited.push(caller(&harness, index));
    }
    assert_eq!(
        exited.iter().max(),
        Some(&w2),
        "the two waiters sort last, past the credit boundary"
    );
    // The live caller and both waiters own an instance, so each
    // instance slot gates beside a current edge.
    let domain = NativeDomainId::try_mint().expect("fresh domain");
    let extra = key(99);
    let image = ImageIdentity {
        task_cookie: 300,
        exec_id: 1,
    };
    for (at, owner) in [live, w1, w2].iter().enumerate() {
        harness
            .coordinator_mut()
            .registry_mut()
            .scripted_module_edge(extra.clone(), *owner);
        let instance_key = InstanceKey::scripted(
            domain,
            image,
            InstanceId::from_raw(7 + at as u64),
            extra.clone(),
        );
        harness
            .coordinator_mut()
            .registry_mut()
            .note_instance(AdmittedInstance::scripted(instance_key, *owner));
    }
    harness.coordinator_mut().registry_mut().publish();

    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 24, 4).unwrap();
    let mut state = StreamState::new();
    state.edges = EdgeEmitter::with_cap(1);
    state.instances = InstanceEmitter::with_cap(1);
    let mut pass = 0u64;
    let emit_until_carried =
        |writer: &mut EventWriter, state: &mut StreamState, view: &Presentation, pass: &mut u64| {
            for _ in 0..100_000 {
                *pass += 1;
                let at = *pass;
                emit_pass_events(writer, state, &report(*pass), view, at).unwrap();
                if state.last_deferred.edge_events == 0
                    && state.last_deferred.instance_events == 0
                    && state.last_deferred.semantic_edge_events == 0
                {
                    return;
                }
            }
            panic!("the capped FIFO never drained");
        };
    // Carry every initial row: the exiting edges at 2 entries.
    let mut pass1 = presentation(&harness);
    assert_eq!(
        pass1.edges.len(),
        (EXITED + 1 + 3) as usize,
        "one edge per caller plus the three second edges"
    );
    assert_eq!(pass1.instances.len(), 3, "three instance rows render");
    assert_eq!(pass1.semantic_edges.len(), 3, "three semantic rows render");
    for edge in &mut pass1.edges {
        if edge.caller != live {
            edge.entry_count = 2;
        }
    }
    emit_until_carried(&mut writer, &mut state, &pass1, &mut pass);

    // The exits: every caller but the live one dies through the
    // production reconcile path, and each edge reaches its terminal
    // revision (exit presence, 3 entries).
    for pid in FIRST_PID + 1..=FIRST_PID + EXITED {
        harness.source().kill(pid);
    }
    let observed: BTreeSet<u32> = [FIRST_PID].into_iter().collect();
    let now = harness.now_ns();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    harness.advance(10);
    for id in &exited {
        assert!(
            harness
                .coordinator()
                .adapter()
                .record(*id)
                .is_some_and(|record| record.retired),
            "production reconcile retires every dead pid"
        );
    }
    let mut pass_terminal = presentation(&harness);
    for edge in &mut pass_terminal.edges {
        if edge.caller == live {
            edge.entry_count = 1;
        } else {
            assert_eq!(
                edge.presence,
                Presence::ProcessExited,
                "the exit flips presence"
            );
            edge.entry_count = 3;
        }
    }
    let seen_of = |rows: &[crate::inventory_present::InstanceView], owner| {
        rows.iter()
            .find(|row| row.caller == owner)
            .expect("the owner's instance row renders")
            .last_seen_ns
    };
    let returns_of = |rows: &[crate::inventory_present::InstanceSemanticView], owner| {
        rows.iter()
            .find(|row| row.caller == owner)
            .expect("the owner's semantic row renders")
            .api_returns
    };
    let terminal_seen_w1 = seen_of(&pass_terminal.instances, w1);
    let terminal_returns_w2 = returns_of(&pass_terminal.semantic_edges, w2);
    emit_until_carried(&mut writer, &mut state, &pass_terminal, &mut pass);

    // Pass A: the fold carries 1,024 credits and defers the two
    // largest ids. Every filler folds.
    state.last_stream_view = Some(std::sync::Arc::new(pass_terminal.clone()));
    let dummy = dir.path().join("dummy.jsonl");
    let stream = EventLogState::new(Some(EventWriter::create(&dummy, 1 << 20, 2).unwrap()));
    assert!(stream.emits(), "the gate runs on the streaming path");
    let now = harness.now_ns();
    retire_rendered_callers(harness.coordinator_mut(), None, &stream, &mut state, now);
    for waiter in [w1, w2] {
        assert!(
            harness.coordinator().adapter().record(waiter).is_some(),
            "the credit boundary defers the waiter"
        );
    }
    for id in exited.iter().filter(|id| **id != w1 && **id != w2) {
        assert!(
            harness.coordinator().adapter().record(*id).is_none(),
            "every credited row folds"
        );
    }
    let totals = harness.coordinator().registry().departed_totals();
    assert_eq!(
        totals.edges,
        u64::from(FILLERS),
        "1,024 filler edges folded"
    );

    // The retained revisions move one slot per waiter while every
    // edge stays carried and exact: w1's instance row, w2's semantic
    // row. Nothing emits yet, so both revisions sit stale. The fresh
    // presentation renders registry counts, so every edge is reset
    // to its carried terminal value (live 1, waiters 3).
    let mut pass_revised = presentation(&harness);
    assert_eq!(
        pass_revised.edges.len(),
        6,
        "only the live pair and the waiter pairs survive the fold"
    );
    for edge in &mut pass_revised.edges {
        if edge.caller == live {
            edge.entry_count = 1;
        } else {
            edge.entry_count = 3;
        }
    }
    for row in &mut pass_revised.instances {
        if row.caller == w1 {
            row.last_seen_ns = terminal_seen_w1 + 1;
        }
    }
    for row in &mut pass_revised.semantic_edges {
        if row.caller == w2 {
            row.api_returns = Some(terminal_returns_w2.unwrap_or(0) + 5);
        }
    }

    // Pass B1: with edges current, each stale slot alone retains its
    // waiter past the credit boundary.
    state.last_stream_view = Some(std::sync::Arc::new(pass_revised.clone()));
    let carried_before = state.edges.carried_bytes();
    let now = harness.now_ns();
    retire_rendered_callers(harness.coordinator_mut(), None, &stream, &mut state, now);
    for waiter in [w1, w2] {
        assert!(
            harness.coordinator().adapter().record(waiter).is_some(),
            "the stale slot retains its waiter past the credit boundary"
        );
    }
    assert_eq!(
        state.edges.carried_bytes(),
        carried_before,
        "no digest leaves the retention bound before its revision lands"
    );

    // The live instance moves both slots ahead of the waiters; one
    // capped pass carries the live instance row and queues every
    // waiter revision behind it.
    for row in &mut pass_revised.instances {
        if row.caller == live {
            row.last_seen_ns += 100;
        }
    }
    for row in &mut pass_revised.semantic_edges {
        if row.caller == live {
            row.api_returns = Some(row.api_returns.unwrap_or(0) + 500);
        }
    }
    pass += 1;
    emit_pass_events(&mut writer, &mut state, &report(pass), &pass_revised, pass).unwrap();
    assert_eq!(
        state.last_deferred.edge_events, 0,
        "no edge revision waits: the edges are current"
    );
    assert_eq!(
        state.last_deferred.instance_events, 1,
        "w1's instance revision waits behind the live row"
    );
    assert_eq!(
        state.last_deferred.semantic_edge_events, 2,
        "the live and w2 semantic revisions wait behind the cap"
    );

    // Pass B2: with edges current, each queued slot alone retains
    // its waiter past the credit boundary.
    state.last_stream_view = Some(std::sync::Arc::new(pass_revised.clone()));
    let now = harness.now_ns();
    retire_rendered_callers(harness.coordinator_mut(), None, &stream, &mut state, now);
    for waiter in [w1, w2] {
        assert!(
            harness.coordinator().adapter().record(waiter).is_some(),
            "the queued slot retains its waiter past the credit boundary"
        );
    }

    // The next passes drain every revision with the same terminal
    // rows; then the fold runs.
    emit_until_carried(&mut writer, &mut state, &pass_revised, &mut pass);
    state.last_stream_view = Some(std::sync::Arc::new(pass_revised));
    let now = harness.now_ns();
    retire_rendered_callers(harness.coordinator_mut(), None, &stream, &mut state, now);
    for waiter in [w1, w2] {
        assert!(
            harness.coordinator().adapter().record(waiter).is_none(),
            "the published terminal revisions fold"
        );
    }
    drop(writer);

    // The stream alone proves each terminal payload: the last record
    // of each waiter's revised row carries its terminal revision,
    // and the departed aggregates count both waiters.
    let all = lines(&path);
    let w1_label = w1.label();
    let last_w1_instance = all
        .iter()
        .rev()
        .find(|line| line["kind"] == "instance_observed" && line["event"]["caller"] == w1_label)
        .expect("w1 instance records streamed");
    assert_eq!(
        last_w1_instance["event"]["last_seen_ns"].as_u64().unwrap(),
        terminal_seen_w1 + 1,
        "w1's terminal instance revision streams last"
    );
    let w2_label = w2.label();
    let last_w2_semantic = all
        .iter()
        .rev()
        .find(|line| {
            line["kind"] == "semantic_edge_observed" && line["event"]["caller"] == w2_label
        })
        .expect("w2 semantic records streamed");
    assert_eq!(
        last_w2_semantic["event"]["api_returns"]["count"]
            .as_u64()
            .unwrap(),
        terminal_returns_w2.unwrap_or(0) + 5,
        "w2's terminal semantic revision streams last"
    );
    assert_eq!(state.edges.tracked_len(), 2, "the live pair retained");
    assert_eq!(
        state.instances.tracked_len(),
        1,
        "the live instance retained"
    );
    let totals = harness.coordinator().registry().departed_totals();
    assert_eq!(
        totals.edges,
        u64::from(FILLERS + 4),
        "the waiter pairs fold beside the fillers"
    );
    assert_eq!(
        totals.instances_folded, 2,
        "both waiter instances fold through the registry"
    );
}
