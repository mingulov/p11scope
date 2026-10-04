//! SPDX-License-Identifier: GPL-3.0-or-later
//! U0/D event-stream tests: versioned schema, rotation that never
//! loses silently, retention accounting, stream gaps identical in
//! meaning to snapshot gaps, and privacy bounds equal to snapshots.

use super::*;
use crate::discovery::caller_registry::{ImageAuthority, RegistryLimits};
use crate::discovery::inventory_workload::{Harness, ScaleSpec};
use std::collections::BTreeSet;

fn limited(callers: usize) -> Harness {
    Harness::new(RegistryLimits::new(callers, 64, 256, 64, 1 << 20, 64).unwrap()).unwrap()
}

/// A workload with refused captures: 4 retained callers, the 5th
/// refused on the caller budget with a named gap.
fn refused_harness() -> Harness {
    let mut harness = limited(4);
    let spec = ScaleSpec {
        name: "events-refused",
        callers: 4,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 60_004 - 4,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let now = harness.now_ns();
    harness.source().spawn(60_004, 1111);
    let observed: BTreeSet<u32> = [60_004].into_iter().collect();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    harness.commit();
    harness
}

fn presentation_for(harness: &Harness) -> (Presentation, serde_json::Value) {
    let document = harness.render();
    let started = document["observation"]["started_ns"].as_u64().unwrap();
    let ended = document["observation"]["ended_ns"].as_u64().unwrap();
    let passes = document["observation"]["passes"].as_u64().unwrap();
    let presentation = Presentation::capture(
        harness.coordinator(),
        "workload",
        started,
        ended,
        passes,
        ended,
        ended.saturating_sub(started),
    );
    (presentation, document)
}

/// Read every stream file (live + rotations) into parsed lines.
fn read_stream(dir: &std::path::Path, live: &str) -> Vec<(String, serde_json::Value)> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name == live || name.starts_with(&format!("{live}.")))
        .collect();
    files.sort();
    let mut lines = Vec::new();
    for name in files {
        let body = std::fs::read_to_string(dir.join(&name)).unwrap();
        for line in body.lines() {
            let value: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|_| panic!("{name}: unparsable line: {line:?}"));
            lines.push((name.clone(), value));
        }
    }
    lines
}

#[test]
fn stream_gaps_are_identical_in_meaning_to_snapshot_gaps() {
    let harness = refused_harness();
    let (presentation, document) = presentation_for(&harness);
    assert_eq!(document["budgets"]["callers"]["refused"], 1);
    assert_eq!(document["gaps"].as_array().unwrap().len(), 1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 5).unwrap();
    emit_snapshot_as_events(&mut writer, &presentation, 999).unwrap();
    writer
        .finish(ended_payload(&presentation, 1000, &writer), 1000)
        .unwrap();
    let lines = read_stream(dir.path(), "events.jsonl");
    // Every line is the versioned envelope, seqs contiguous from 0.
    for (index, (_, line)) in lines.iter().enumerate() {
        assert_eq!(line["schema"], EVENT_SCHEMA, "{line}");
        assert_eq!(line["seq"], index as u64, "{line}");
        assert!(line["at_ns"].is_number(), "{line}");
        assert!(line["kind"].is_string(), "{line}");
    }
    // Gap events equal the snapshot gaps value-for-value (subject,
    // reason, caller/module/pid, budget triple) — a refused capture
    // produces stream gaps identical in meaning to snapshot gaps.
    let stream_gaps: Vec<&serde_json::Value> = lines
        .iter()
        .filter(|(_, line)| line["kind"] == "gap_recorded")
        .map(|(_, line)| &line["event"])
        .collect();
    let snapshot_gaps = document["gaps"].as_array().unwrap();
    assert_eq!(stream_gaps.len(), snapshot_gaps.len());
    for (position, (stream, snapshot)) in stream_gaps.iter().zip(snapshot_gaps.iter()).enumerate() {
        // gap_recorded is the snapshot entry minus `repeats`.
        let mut identity = (*snapshot).clone();
        identity.as_object_mut().unwrap().remove("repeats");
        identity["index"] = serde_json::json!(position);
        assert_eq!(**stream, identity, "gap event == snapshot gap identity");
    }
    let refusal = &stream_gaps[0];
    assert_eq!(refusal["budget"]["resource"], "callers");
    assert_eq!(refusal["budget"]["limit"], 4);
    assert_eq!(refusal["budget"]["requested"], 5);
    // Callers/modules/edges round-trip with the same identities.
    let kinds: Vec<&str> = lines
        .iter()
        .map(|(_, line)| line["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        lines
            .iter()
            .filter(|(_, line)| line["kind"] == "caller_observed")
            .count(),
        4
    );
    assert!(kinds.contains(&"snapshot"));
    assert!(kinds.contains(&"ended"));
    let ended = lines
        .iter()
        .find(|(_, line)| line["kind"] == "ended")
        .unwrap();
    assert_eq!(ended.1["event"]["budgets"]["callers"]["refused"], 1);
    assert_eq!(ended.1["event"]["stream"]["rotations"], 0);
}

#[test]
fn rotation_never_loses_an_event_silently() {
    let harness = refused_harness();
    let (presentation, _) = presentation_for(&harness);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    // A tiny threshold forces several rotations; wide retention keeps
    // every file, so every event must be present exactly once.
    let mut writer = EventWriter::create(&path, 1024, 100).unwrap();
    emit_snapshot_as_events(&mut writer, &presentation, 999).unwrap();
    writer
        .finish(ended_payload(&presentation, 1000, &writer), 1000)
        .unwrap();
    assert!(writer.rotations() >= 2, "rotations happened");
    assert_eq!(writer.evicted_events(), 0, "nothing evicted");
    let lines = read_stream(dir.path(), "events.jsonl");
    // Seqs contiguous across ALL files: no event lost, none duplicated.
    let mut seqs: Vec<u64> = lines
        .iter()
        .map(|(_, line)| line["seq"].as_u64().unwrap())
        .collect();
    seqs.sort_unstable();
    for (index, seq) in seqs.iter().enumerate() {
        assert_eq!(*seq, index as u64, "seq contiguous at {index}");
    }
    // Every rotation marker names a retained prior file whose line
    // count matches the marker's accounting.
    for (_, line) in lines.iter().filter(|(_, line)| line["kind"] == "rotated") {
        let prior = line["event"]["prior_file"].as_str().unwrap();
        let events = line["event"]["prior_events"].as_u64().unwrap();
        let body = std::fs::read_to_string(dir.path().join(prior))
            .unwrap_or_else(|_| panic!("{prior} retained"));
        assert_eq!(body.lines().count() as u64, events, "{prior} line count");
    }
    // Payload events survived rotation intact.
    let gap_events = lines
        .iter()
        .filter(|(_, line)| line["kind"] == "gap_recorded")
        .count();
    assert_eq!(gap_events, 1);
    // The live file's line count is exactly the writer's live tally.
    let live_lines = std::fs::read_to_string(&path).unwrap();
    assert_eq!(live_lines.lines().count() as u64, writer.live_events());
}

#[test]
fn retention_eviction_is_accounted_not_silent() {
    let harness = refused_harness();
    let (presentation, _) = presentation_for(&harness);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    // Two files retained against many rotations: evictions must occur,
    // each accounted in a retained event.
    let mut writer = EventWriter::create(&path, 1024, 2).unwrap();
    emit_snapshot_as_events(&mut writer, &presentation, 999).unwrap();
    writer
        .finish(ended_payload(&presentation, 1000, &writer), 1000)
        .unwrap();
    assert!(writer.rotations() >= 2);
    assert!(writer.evicted_events() > 0, "evictions happened");
    let lines = read_stream(dir.path(), "events.jsonl");
    // Retained files respect the bound (live + one rotation).
    let files: BTreeSet<&str> = lines.iter().map(|(name, _)| name.as_str()).collect();
    assert!(files.len() <= 2, "retention bound holds: {files:?}");
    // Exact conservation: retained lines + accounted (direct +
    // transitive) == emitted. Every emission is retained exactly once
    // or covered exactly once by a retained record.
    let emitted: u64 = lines
        .iter()
        .map(|(_, line)| line["seq"].as_u64().unwrap())
        .max()
        .unwrap()
        + 1;
    let evicted: u64 = lines
        .iter()
        .filter(|(_, line)| line["kind"] == "retention_evicted")
        .map(|(_, line)| {
            line["event"]["evicted_events"].as_u64().unwrap()
                + line["event"]["covered_events"].as_u64().unwrap()
        })
        .sum();
    assert_eq!(
        lines.len() as u64 + evicted,
        emitted,
        "every emission is retained or accounted"
    );
    // Evicted files are gone AND named with their counts.
    for (_, line) in lines
        .iter()
        .filter(|(_, line)| line["kind"] == "retention_evicted")
    {
        let victim = line["event"]["evicted_file"].as_str().unwrap();
        assert!(
            !dir.path().join(victim).exists(),
            "{victim} deleted after accounting"
        );
        assert!(line["event"]["evicted_events"].as_u64().unwrap() > 0);
        assert!(
            line["event"]["reason"]
                .as_str()
                .unwrap()
                .contains("retention")
        );
    }
}

#[test]
fn stream_privacy_bounds_match_snapshots_exactly() {
    let harness = refused_harness();
    let (presentation, document) = presentation_for(&harness);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 5).unwrap();
    emit_snapshot_as_events(&mut writer, &presentation, 999).unwrap();
    drop(writer);
    let lines = read_stream(dir.path(), "events.jsonl");
    // Envelope keys are fixed and documented.
    for (_, line) in &lines {
        let keys: BTreeSet<&str> = line
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            ["at_ns", "event", "kind", "schema", "seq"]
                .into_iter()
                .collect()
        );
    }
    // Caller/module payloads carry exactly the snapshot caller/module
    // keys — no new capture, however derived.
    let caller_keys: BTreeSet<&str> = document["callers"][0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    for (_, line) in lines
        .iter()
        .filter(|(_, line)| line["kind"] == "caller_observed")
    {
        let keys: BTreeSet<&str> = line["event"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, caller_keys, "caller payload == snapshot keys");
    }
    let module_keys: BTreeSet<&str> = document["modules"][0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    for (_, line) in lines
        .iter()
        .filter(|(_, line)| line["kind"] == "module_observed")
    {
        let keys: BTreeSet<&str> = line["event"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, module_keys, "module payload == snapshot keys");
    }
    // Edge payloads add ONLY the three derived presentation states.
    let mut edge_keys: BTreeSet<&str> = document["edges"][0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    edge_keys.extend(["presence", "capture", "activity"]);
    for (_, line) in lines
        .iter()
        .filter(|(_, line)| line["kind"] == "edge_observed")
    {
        let keys: BTreeSet<&str> = line["event"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, edge_keys, "edge payload == snapshot keys + states");
    }
}

#[test]
fn incremental_pass_events_match_the_final_snapshot() {
    // The production incremental path (per-pass caller/gap/pass
    // markers), replayed through the harness exactly as the run loops
    // emit it.
    let mut harness = refused_harness();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 5).unwrap();
    // One more pass with an exit, emitted incrementally (the
    // refused harness admitted pids 60000-60003).
    harness.source().kill(60_000);
    let observed: BTreeSet<u32> = [60_001, 60_002, 60_003].into_iter().collect();
    let now = harness.now_ns();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    harness.commit();
    let document = harness.render();
    let started = document["observation"]["started_ns"].as_u64().unwrap();
    let ended = document["observation"]["ended_ns"].as_u64().unwrap();
    let passes = document["observation"]["passes"].as_u64().unwrap();
    let presentation = Presentation::capture(
        harness.coordinator(),
        "workload",
        started,
        ended,
        passes,
        ended,
        ended.saturating_sub(started),
    );
    // Emit the pass the way production does (caller turnover, new
    // gaps, pass marker).
    for event in &events {
        writer
            .append("caller_event", caller_event_payload(event), now)
            .unwrap();
    }
    let emitted_gaps = GapEmitter::new()
        .emit(&mut writer, &presentation.gaps, false, now)
        .unwrap();
    assert!(emitted_gaps > 0);
    drop(writer);
    let lines = read_stream(dir.path(), "events.jsonl");
    // The exit is an event; the gaps equal the snapshot gaps.
    assert!(
        lines
            .iter()
            .any(|(_, line)| line["kind"] == "caller_event" && line["event"]["event"] == "exited"),
        "exit emitted"
    );
    let stream_gaps: Vec<&serde_json::Value> = lines
        .iter()
        .filter(|(_, line)| line["kind"] == "gap_recorded")
        .map(|(_, line)| &line["event"])
        .collect();
    let snapshot_gaps = document["gaps"].as_array().unwrap();
    assert_eq!(stream_gaps.len(), snapshot_gaps.len());
    for (position, (stream, snapshot)) in stream_gaps.iter().zip(snapshot_gaps.iter()).enumerate() {
        let mut identity = (*snapshot).clone();
        identity.as_object_mut().unwrap().remove("repeats");
        identity["index"] = serde_json::json!(position);
        assert_eq!(**stream, identity);
    }
}

#[test]
fn rotation_sequences_never_collide_across_runs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    let mut first = EventWriter::create(&path, 256, 10).unwrap();
    for index in 0..20 {
        first
            .append("probe", serde_json::json!({"i": index}), 1000 + index)
            .unwrap();
    }
    let first_rotations = first.rotations();
    assert!(first_rotations > 0);
    drop(first);
    // A second run in the same directory continues the sequence past
    // the first run's rotations (no overwrite, no collision).
    let mut second = EventWriter::create(&path, 256, 10).unwrap();
    for index in 0..20 {
        second
            .append("probe", serde_json::json!({"i": index}), 2000 + index)
            .unwrap();
    }
    drop(second);
    let mut seqs: Vec<u64> = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter_map(|name| {
            name.strip_prefix("events.jsonl.")
                .and_then(|suffix| suffix.parse::<u64>().ok())
        })
        .collect();
    seqs.sort_unstable();
    seqs.dedup();
    assert_eq!(
        seqs.len(),
        std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("events.jsonl.")
            })
            .count(),
        "no rotated name reused across runs"
    );
    // All retained lines still parse (both runs' markers intact).
    for (_, line) in read_stream(dir.path(), "events.jsonl") {
        assert_eq!(line["schema"], EVENT_SCHEMA);
    }
}

/// DR-K8S-4: a gap repeated on every pass is one gap with a repeat
/// count, and the snapshot, the event stream and the presentation the
/// dashboard renders all agree on both.
#[test]
fn snapshot_events_and_dashboard_agree_on_a_repeated_gap() {
    use crate::discovery::caller_registry::RegistryGap;
    let mut harness = limited(8);
    for pass in 0..20 {
        harness
            .coordinator_mut()
            .registry_mut()
            .record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "overlay collapse".into(),
                reason: "two overlay instances map one inode".into(),
                budget: None,
            });
        if pass == 9 {
            harness
                .coordinator_mut()
                .registry_mut()
                .record_gap(RegistryGap {
                    caller: None,
                    module: None,
                    pid: Some(5),
                    subject: "distinct".into(),
                    reason: "seen once".into(),
                    budget: None,
                });
        }
        harness.commit();
    }
    let (presentation, document) = presentation_for(&harness);
    let json_gaps = document["gaps"].as_array().unwrap();
    assert_eq!(json_gaps.len(), 2, "{json_gaps:?}");
    assert_eq!(json_gaps[0]["subject"], "overlay collapse");
    assert_eq!(json_gaps[0]["repeats"], 20);
    assert_eq!(json_gaps[1]["repeats"], 1);
    assert_eq!(document["gaps_suppressed"], 0);
    // Dashboard/snapshot consumers read the same view.
    let view: Vec<u64> = presentation.gaps.iter().map(|gap| gap.repeats).collect();
    assert_eq!(view, vec![20, 1]);
    // The event stream: one gap_recorded per distinct gap, carrying the
    // same payload as the snapshot entry.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 20, 4).unwrap();
    emit_snapshot_as_events(&mut writer, &presentation, 999).unwrap();
    drop(writer);
    let lines = read_stream(dir.path(), "events.jsonl");
    let stream: Vec<&serde_json::Value> = lines
        .iter()
        .filter(|(_, line)| line["kind"] == "gap_recorded")
        .map(|(_, line)| &line["event"])
        .collect();
    assert_eq!(stream.len(), 2);
    let repeated: Vec<&serde_json::Value> = lines
        .iter()
        .filter(|(_, line)| line["kind"] == "gap_repeated")
        .map(|(_, line)| &line["event"])
        .collect();
    assert_eq!(
        repeated,
        vec![&serde_json::json!({"index": 0, "repeats": 20})]
    );
    for (position, (stream, snapshot)) in stream.iter().zip(json_gaps).enumerate() {
        let mut identity = (*snapshot).clone();
        identity.as_object_mut().unwrap().remove("repeats");
        identity["index"] = serde_json::json!(position);
        assert_eq!(**stream, identity);
    }
}

/// Review R-1 (margins): the dump fit bound holds exactly at its
/// boundary. With the records an emitter carries, the smallest rotate
/// size whose contiguous capacity covers carried bytes + per-edge slack +
/// the tail reserve fits; one byte less does not. Loosening any margin
/// (the tail reserve, the largest line, the rotation overhead, the slack)
/// moves the boundary and fails here.
#[test]
fn the_dump_fit_bound_is_exact_at_its_boundary() {
    let mut harness = limited(8);
    harness.stage_scale(&ScaleSpec {
        name: "fit-boundary",
        callers: 3,
        modules: 2,
        edges_per_caller: 2,
        endpoints_per_module: 4,
        first_pid: 70_000,
    });
    harness.commit();
    let (presentation, _) = presentation_for(&harness);
    assert_eq!(presentation.edges.len(), 6);
    let dir = tempfile::tempdir().unwrap();
    let mut writer = EventWriter::create(&dir.path().join("big.jsonl"), 1 << 20, 2).unwrap();
    let mut emitter = EdgeEmitter::new();
    emitter
        .emit(&mut writer, &presentation.edges, 64, 1)
        .unwrap();
    let edges = presentation.edges.len() as u64;
    let need = emitter.carried_bytes + DUMP_LINE_SLACK * edges + DUMP_TAIL_RESERVE;
    let per_line = emitter.largest_line + DUMP_LINE_SLACK + ROTATION_OVERHEAD;
    for files in [2u64, 3, 5] {
        let per_file = need.div_ceil(files - 1);
        let boundary = per_file + per_line;
        let probe = dir.path().join(format!("probe-{files}.jsonl"));
        let fits = |max_bytes: u64| {
            emitter.fits(&EventWriter::create(&probe, max_bytes, files as usize).unwrap())
        };
        assert!(fits(boundary), "{files} files at {boundary}");
        assert!(!fits(boundary - 1), "{files} files at {}", boundary - 1);
    }
}
