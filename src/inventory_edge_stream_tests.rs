//! SPDX-License-Identifier: GPL-3.0-or-later
//! DR-C5-EDGE: production `edge_observed` records through the real
//! per-pass emitter and the terminal sweep in `finish_output` — only on
//! class changes, capped per pass with a counted deferred carry, a digest
//! per edge bounded by the edge limit, and a replay equal to the snapshot.

use super::*;
use crate::discovery::caller_registry::{CallerId, CoverageNote, ModuleKey, RegistryLimits};
use crate::discovery::engine::inventory_coordinator::PassReport;
use crate::discovery::inventory_workload::{Harness, ScaleSpec};
use crate::inventory_events::{EDGE_EVENTS_PER_PASS, EdgeEmitter, edge_payload};
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
    Presentation::capture(harness.coordinator(), "workload", 0, now, passes, now, now)
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
    for state in ["presence", "capture", "activity"] {
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
    finish_output(
        None,
        Some(&mut writer),
        &mut state,
        &last,
        false,
        false,
        &mut text,
        None,
    )
    .unwrap();
    drop(writer);
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
    // pager text, renders them from the same view).
    let text = String::from_utf8(text).unwrap();
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
            .sweep(&mut writer, &last.edges, last.budgets.edges_limit, 1, 0)
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
    assert_eq!(EDGE_EVENTS_PER_PASS, 4096);
    let edges = synthetic_edges(5000);
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 30, 2).unwrap();
    let mut emitter = EdgeEmitter::new();
    let first = emitter.emit(&mut writer, &edges, 32_768, 1).unwrap();
    assert_eq!((first.emitted, first.deferred), (4096, 904));
    let second = emitter.emit(&mut writer, &edges, 32_768, 2).unwrap();
    assert_eq!((second.emitted, second.deferred), (904, 0));
    let third = emitter.emit(&mut writer, &edges, 32_768, 3).unwrap();
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
    let mut edges = synthetic_edges(5);
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
    let mut emitter = EdgeEmitter::with_cap(2);
    let pass = emitter.emit(&mut writer, &edges, 64, 1).unwrap();
    assert_eq!((pass.emitted, pass.deferred), (2, 3));
    // c0 changes class while c2..c4 wait; c3 changes too.
    edges[0].entry_count = 1;
    edges[3].entry_count = 1;
    let pass = emitter.emit(&mut writer, &edges, 64, 2).unwrap();
    assert_eq!((pass.emitted, pass.deferred), (2, 2));
    let pass = emitter.emit(&mut writer, &edges, 64, 3).unwrap();
    assert_eq!((pass.emitted, pass.deferred), (2, 0));
    // One more deferral, then the sweep drains it.
    edges[1].entry_count = 1;
    edges[2].entry_count = 1;
    edges[4].entry_count = 1;
    let pass = emitter.emit(&mut writer, &edges, 64, 4).unwrap();
    assert_eq!((pass.emitted, pass.deferred), (2, 1));
    assert_eq!(
        emitter
            .sweep(&mut writer, &edges, 64, 5, 0)
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
    let edges = synthetic_edges(3);
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
    let mut emitter = EdgeEmitter::new();
    for pass in 1..=3 {
        emitter.emit(&mut writer, &edges, 2, pass).unwrap();
        assert_eq!(emitter.tracked(), 2, "bounded by the limit");
    }
    assert_eq!(
        emitter.sweep(&mut writer, &edges, 2, 4, 0).unwrap().emitted,
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
    let mut edges = synthetic_edges(2);
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
    let mut emitter = EdgeEmitter::with_cap(1);
    let pass = emitter.emit(&mut writer, &edges, 64, 1).unwrap();
    assert_eq!((pass.emitted, pass.deferred), (1, 1));
    edges[0].entry_count = 1;
    let pass = emitter.emit(&mut writer, &edges, 64, 2).unwrap();
    assert_eq!((pass.emitted, pass.deferred), (1, 1), "c1 first, c0 waits");
    edges[0].entry_count = 0;
    let pass = emitter.emit(&mut writer, &edges, 64, 3).unwrap();
    assert_eq!((pass.emitted, pass.deferred), (0, 0));
    assert_eq!(
        emitter
            .sweep(&mut writer, &edges, 64, 4, 0)
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
    let mut edges = synthetic_edges(2);
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 4096, 2).unwrap();
    let mut emitter = EdgeEmitter::new();
    emitter.emit(&mut writer, &edges, 64, 1).unwrap();
    for pass in 2..200u64 {
        edges[1].entry_count = pass % 2;
        emitter.emit(&mut writer, &edges, 64, pass).unwrap();
    }
    assert!(writer.oldest_generation() > 0, "c0's record was evicted");
    assert!(!retained_edges(&path).contains_key("c0"));
    let sweep = emitter.sweep(&mut writer, &edges, 64, 200, 0).unwrap();
    assert!(sweep.emitted >= 1, "{sweep:?}");
    assert_eq!(sweep.unretained, 0);
    drop(writer);
    let retained = retained_edges(&path);
    assert_eq!(retained.keys().collect::<Vec<_>>(), ["c0", "c1"]);
    for edge in &edges {
        assert_eq!(retained[&edge.caller.label()], edge_payload(edge));
    }
}

/// Review M-1, probe 2: a sweep larger than the retention (200 edges,
/// 8 KiB x 3 files) cannot keep its own early records. No dump is tried
/// (it cannot fit), and the sweep reports exactly the edges left without a
/// retained record (it used to claim nothing: 200 sent, 29 kept).
#[test]
fn a_sweep_larger_than_the_retention_reports_its_unretained_edges() {
    let edges = synthetic_edges(200);
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 8192, 3).unwrap();
    let mut emitter = EdgeEmitter::new();
    let sweep = emitter.sweep(&mut writer, &edges, 64_000, 1, 0).unwrap();
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
    let mut edges = synthetic_edges(10);
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 16 * 1024, 4).unwrap();
    let mut emitter = EdgeEmitter::new();
    emitter.emit(&mut writer, &edges, 64, 1).unwrap();
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
    let sweep = emitter.sweep(&mut writer, &edges, 64, 3, 0).unwrap();
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
        assert_eq!(retained[&edge.caller.label()], edge_payload(edge));
    }
}

/// Mid-run, an edge whose record rotated out is re-sent on the next pass
/// while every edge's record fits the retention; when they cannot fit, it
/// is not (re-sending would only evict others, every pass), and the sweep
/// is left to account for it.
#[test]
fn evicted_edges_are_refreshed_mid_run_only_when_the_records_fit() {
    for (max_bytes, files, refreshed) in [(16 * 1024, 4, 3), (4096, 2, 0)] {
        let edges = synthetic_edges(3);
        let dir = private_tempdir();
        let path = dir.path().join("events.jsonl");
        let mut writer = EventWriter::create(&path, max_bytes, files).unwrap();
        let mut emitter = EdgeEmitter::new();
        emitter.emit(&mut writer, &edges, 64, 1).unwrap();
        let pad = serde_json::json!({"pad": "x".repeat(64)});
        while writer.oldest_generation() == 0 {
            writer.append("probe", pad.clone(), 2).unwrap();
        }
        let pass = emitter.emit(&mut writer, &edges, 64, 3).unwrap();
        assert_eq!(pass.emitted, refreshed, "{max_bytes} x {files}");
        let pass = emitter.emit(&mut writer, &edges, 64, 4).unwrap();
        assert_eq!(pass.emitted, 0, "{max_bytes} x {files}: refreshed once");
    }
}

/// Review L-5: each of the three derived states alone triggers a record,
/// so freezing any of them in the change check fails here, not only in
/// the 14 s command-level test.
#[test]
fn presence_capture_and_activity_each_trigger_a_record_alone() {
    use crate::inventory_present::{Activity, Capture, Presence};
    let mut edges = synthetic_edges(1);
    edges[0].presence = Presence::Mapped;
    edges[0].capture = Capture::ScanOnly;
    edges[0].activity = Activity::Uncovered;
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
    let mut emitter = EdgeEmitter::new();
    assert_eq!(emitter.emit(&mut writer, &edges, 64, 1).unwrap().emitted, 1);
    let mut emitted = Vec::new();
    edges[0].presence = Presence::Unloaded;
    emitted.push(emitter.emit(&mut writer, &edges, 64, 2).unwrap().emitted);
    edges[0].capture = Capture::Retired;
    emitted.push(emitter.emit(&mut writer, &edges, 64, 3).unwrap().emitted);
    edges[0].activity = Activity::Unknown;
    emitted.push(emitter.emit(&mut writer, &edges, 64, 4).unwrap().emitted);
    emitted.push(emitter.emit(&mut writer, &edges, 64, 5).unwrap().emitted);
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
    let dir = private_tempdir();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, shape.max_bytes, shape.files).unwrap();
    let mut emitter = EdgeEmitter::new();
    let pad = serde_json::json!({"pad": "p".repeat(40)});
    emitter.emit(&mut writer, &edges, 64, 1).unwrap();
    for pass in 2..=shape.passes {
        let index = pass as usize % edges.len();
        edges[index].entry_count += 1;
        for _ in 0..3 {
            writer.append("probe", pad.clone(), pass).unwrap();
        }
        emitter.emit(&mut writer, &edges, 64, pass).unwrap();
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
    let sweep = emitter.sweep(&mut writer, &edges, 64, 3, tail).unwrap();
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
            assert_eq!(*record, edge_payload(edge), "a retained record is exact");
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
    let mut dashboard = EventWriter::create(&dashboard_path, 1 << 20, 2).unwrap();
    let mut classic = EventWriter::create(&classic_path, 1 << 20, 2).unwrap();
    let mut dashboard_state = StreamState::new();
    let mut classic_state = StreamState::new();
    let mut display_activity = Vec::new();
    for (pass, age) in [(1u64, 1_000_000_000u64), (2, 10_000_000_000)] {
        let now = at + age;
        let coordinator = harness.coordinator();
        let display = dashboard_stream_pass(
            Some(&mut dashboard),
            &mut dashboard_state,
            &report(pass),
            coordinator,
            "pid",
            started,
            now,
        )
        .unwrap();
        display_activity.push(display.edges[0].activity.label());
        let view = stream_presentation(coordinator, "pid", started, now);
        emit_pass_events(&mut classic, &mut classic_state, &report(pass), &view, now).unwrap();
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
        finish_output(
            None,
            Some(writer),
            state,
            &last,
            false,
            true,
            &mut sink,
            None,
        )
        .unwrap();
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
