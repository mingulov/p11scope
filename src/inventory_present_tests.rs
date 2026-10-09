//! SPDX-License-Identifier: GPL-3.0-or-later
//! U0 presentation tests: ONE model for JSON and snapshots (A1/A2),
//! exact dashboard vocabulary with its distinctions (B2), and the
//! withheld semantic column (B3). JSON-vs-snapshot agreement is pinned
//! by parsing, not eyeballing.

use super::*;
use crate::discovery::caller_registry::{
    AdmissionState, CallerId, CoverageNote, ImageAuthority, ModuleInfo, ModuleKey, RegistryGap,
    RegistryLimits, UnknownReason, UseCoverage,
};
use crate::discovery::inventory_workload::{Harness, ScaleSpec};
use crate::inventory::{render_json, render_text};
use std::collections::BTreeSet;

fn harness() -> Harness {
    Harness::new(RegistryLimits::default_limits()).unwrap()
}

fn refused_module_info(index: usize) -> ModuleInfo {
    let path = format!("/scale/refused{index}.so");
    ModuleInfo {
        path: path.clone(),
        key: ModuleKey::physical(
            8,
            1,
            200_000 + index as u64,
            Some(format!("rsha{index:06}")),
            &path,
        ),
        double_loaded: false,
        build_id: None,
        identity_source: Some("workload".into()),
        admission: AdmissionState::Refused,
        admission_class: Some("refused".into()),
        admission_endpoints: None,
        admission_reasons: vec!["fixture refusal".into()],
    }
}

fn scale_key(index: usize) -> ModuleKey {
    let path = format!("/scale/m{index}.so");
    ModuleKey::physical(
        8,
        1,
        100_000 + index as u64,
        Some(format!("sha{index:06}")),
        &path,
    )
}

/// A workload with state variety: admitted + refused modules, a live
/// caller, an exited caller, and an exec turnover.
fn varied_harness() -> Harness {
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "present-varied",
        callers: 3,
        modules: 2,
        edges_per_caller: 2,
        endpoints_per_module: 4,
        first_pid: 70_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    harness.advance(10);
    let now = harness.now_ns();
    // A refused module on the first live caller.
    let live = harness.coordinator().adapter().live_id(70_000).unwrap();
    harness.coordinator_mut().registry_mut().note_mapping(
        live,
        70_000,
        refused_module_info(0),
        now,
    );
    harness.commit();
    harness.advance(10);
    // The second caller exits; the third execs.
    harness.source().kill(70_001);
    harness.source().exec(70_002, 4242, "/bin/driver-v2");
    let observed: BTreeSet<u32> = [70_000, 70_002].into_iter().collect();
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
    harness
}

fn capture_for(harness: &Harness, document: &serde_json::Value) -> Presentation {
    let started = document["observation"]["started_ns"].as_u64().unwrap();
    let ended = document["observation"]["ended_ns"].as_u64().unwrap();
    let passes = document["observation"]["passes"].as_u64().unwrap();
    Presentation::capture(harness.coordinator(), "workload", started, ended, passes)
}

#[test]
fn state_vocab_is_the_plans_exact_wording() {
    assert_eq!(Presence::Mapped.label(), "mapped");
    assert_eq!(Presence::Unloaded.label(), "unloaded");
    assert_eq!(Presence::ProcessExited.label(), "process exited");
    assert_eq!(Presence::Unknown.label(), "unknown");
    assert_eq!(Capture::Armed.label(), "armed");
    assert_eq!(Capture::ScanOnly.label(), "scan only");
    assert_eq!(Capture::Refused.label(), "refused");
    assert_eq!(Capture::Retired.label(), "retired");
    assert_eq!(Capture::CoverageLost.label(), "coverage lost");
    assert_eq!(Capture::WatchEnded.label(), "watch ended");
    assert_eq!(Activity::RecentlyObserved.label(), "recently observed");
    assert_eq!(
        Activity::InFlight.label(),
        "operation initialized / in flight"
    );
    assert_eq!(Activity::Used.label(), "used (recency unknown)");
    assert_eq!(Activity::Quiet.label(), "quiet");
    assert_eq!(Activity::Lossy.label(), "unknown (lossy)");
    assert_eq!(Activity::Uncovered.label(), "not covered");
    assert_eq!(Activity::Unknown.label(), "unknown");
}

#[test]
fn a_pending_first_use_renders_unknown_not_quiet_or_not_covered() {
    // DR-LIVE-LABEL-LAG: the edge is watched, so "not covered" would lie,
    // and the use may already have happened, so quiet would lie.
    let pending = UseCoverage::Unknown(UnknownReason::PendingFirstUse);
    assert_eq!(
        Activity::for_edge(MappingState::Mapped, false, false, false, &pending),
        Activity::Unknown
    );
    assert_eq!(coverage_label(&pending), "unknown (first use undecided)");
    assert_eq!(pending.state(), "unknown");
    assert_eq!(UnknownReason::PendingFirstUse.code(), "pending_first_use");
}

#[test]
fn refused_but_quiet_renders_both_states_not_one_merged_label() {
    let harness = varied_harness();
    let document = harness.render();
    let presentation = capture_for(&harness, &document);
    let refused: Vec<&EdgeView> = presentation
        .edges
        .iter()
        .filter(|edge| edge.capture == Capture::Refused)
        .collect();
    assert_eq!(refused.len(), 1, "exactly the refused edge");
    let edge = refused[0];
    // Capture refusal is not application inactivity: the refused edge
    // is mapped, refused, and its activity is unknown (nothing covers
    // its usage) — never quiet.
    assert_eq!(edge.presence, Presence::Mapped);
    assert_eq!(edge.capture, Capture::Refused);
    assert_eq!(edge.activity, Activity::Uncovered);
    let snapshot = render_snapshot(&presentation);
    let line = snapshot
        .lines()
        .find(|line| {
            line.starts_with(&format!(
                "edge {} -> {} ",
                edge.caller.label(),
                edge.module.label()
            ))
        })
        .unwrap();
    assert!(line.contains("presence mapped"), "{line}");
    assert!(line.contains("capture refused"), "{line}");
    assert!(line.contains("activity not covered"), "{line}");
    // The JSON agrees the module refused while the mapping stayed live.
    let edge_json = document["edges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["caller"] == edge.caller.label() && item["module"] == edge.module.label())
        .unwrap();
    assert_eq!(edge_json["mapping"]["state"], "mapped");
    assert_eq!(
        edge_json["entries"]["observation"],
        "unknown (not admitted)"
    );
}

#[test]
fn quiet_is_not_unloaded() {
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "present-unload",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 71_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    // Baseline: mapped, watched, and quiet.
    let watcher = harness.coordinator().adapter().live_id(71_000).unwrap();
    let since = harness.now_ns();
    harness.coordinator_mut().registry_mut().note_coverage(
        watcher,
        &scale_key(0),
        CoverageNote::Watched { since_ns: since },
    );
    harness.commit();
    let document = harness.render();
    let presentation = capture_for(&harness, &document);
    assert_eq!(presentation.edges[0].presence, Presence::Mapped);
    assert_eq!(presentation.edges[0].activity, Activity::Quiet);
    // A complete rescan proves the module gone.
    let now = harness.now_ns();
    let caller = harness.coordinator().adapter().live_id(71_000).unwrap();
    let module = harness
        .coordinator()
        .registry()
        .module_id_for(&scale_key(0))
        .unwrap();
    harness
        .coordinator_mut()
        .registry_mut()
        .note_module_absent(caller, module, true, now);
    harness.commit();
    let document = harness.render();
    assert_eq!(document["modules"][0]["lifecycle"], "unloaded");
    assert_eq!(document["modules"][0]["unloaded_observed"], true);
    let presentation = capture_for(&harness, &document);
    assert_eq!(presentation.edges[0].presence, Presence::Unloaded);
    // Unloaded edges never read as quiet: no live mapping, unknown
    // activity — the quiet/unloaded distinction.
    assert_eq!(presentation.edges[0].activity, Activity::Unknown);
    let snapshot = render_snapshot(&presentation);
    assert!(snapshot.contains("presence unloaded"), "{snapshot}");
    assert!(!snapshot.contains("activity quiet"), "{snapshot}");
}

#[test]
fn a_frozen_watch_renders_watch_ended_never_armed_or_quiet() {
    // C5.2 M-2 and review fix 2: a frozen watch (capture stop, or a custody
    // loss before it) is a fact about `since..until` only: never armed,
    // never quiet now, and its zero is no current fact. The interval
    // survives in the coverage label.
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "present-frozen",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 72_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let watcher = harness.coordinator().adapter().live_id(72_000).unwrap();
    let since = harness.now_ns();
    harness.coordinator_mut().registry_mut().note_coverage(
        watcher,
        &scale_key(0),
        CoverageNote::Watched { since_ns: since },
    );
    harness.commit();
    let document = harness.render();
    let presentation = capture_for(&harness, &document);
    assert_eq!(presentation.edges[0].capture, Capture::Armed, "ongoing");
    harness
        .coordinator_mut()
        .registry_mut()
        .note_watch_end("native capture stopped", since + 10);
    harness.commit();
    let document = harness.render();
    assert_eq!(
        document["edges"][0]["entries"]["coverage"]["until_ns"],
        since + 10
    );
    let presentation = capture_for(&harness, &document);
    let edge = &presentation.edges[0];
    assert_eq!(
        edge.coverage,
        UseCoverage::WatchedNoUse {
            since_ns: since,
            until_ns: Some(since + 10)
        }
    );
    assert_eq!(edge.capture, Capture::WatchEnded);
    assert_eq!(edge.activity, Activity::Unknown);
    assert_eq!(entries_display(edge), "?");
    let snapshot = render_snapshot(&presentation);
    let line = edge_line(&snapshot, edge);
    assert!(
        line.contains("capture watch ended activity unknown "),
        "{line}"
    );
    assert!(
        line.contains(&format!("no use from {since} to {}", since + 10)),
        "{line}"
    );
}

#[test]
fn exited_exec_and_uncertain_states_map_as_specified() {
    let harness = varied_harness();
    let document = harness.render();
    let presentation = capture_for(&harness, &document);
    let by_caller: std::collections::HashMap<String, &EdgeView> = presentation
        .edges
        .iter()
        .map(|edge| (edge.caller.label(), edge))
        .collect();
    // The exited caller (incarnation 0 of pid 70001): presence
    // "process exited", capture retired, activity unknown.
    let exited_id = document["callers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|caller| caller["pid"] == 70_001)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let exited = by_caller[&exited_id];
    assert_eq!(exited.presence, Presence::ProcessExited);
    assert_eq!(exited.capture, Capture::Retired);
    assert_eq!(exited.activity, Activity::Unknown);
    // The exec-retired incarnation: not exited (the process lives on
    // under a new image), so presence unknown with capture retired.
    let retired: Vec<&EdgeView> = presentation
        .edges
        .iter()
        .filter(|edge| edge.presence == Presence::Unknown && edge.capture == Capture::Retired)
        .collect();
    assert_eq!(
        retired.len(),
        2,
        "the two exec-retired edges read unknown/retired"
    );
}

#[test]
fn activity_splits_in_flight_from_recent_from_quiet() {
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "present-activity",
        callers: 3,
        modules: 3,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 72_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    harness.advance(1_000);
    let now = harness.now_ns();
    let c0 = harness.coordinator().adapter().live_id(72_000).unwrap();
    let c1 = harness.coordinator().adapter().live_id(72_001).unwrap();
    // c0: entries observed now (recent). c1: in flight. c2: watched
    // and silent.
    let c2 = harness.coordinator().adapter().live_id(72_002).unwrap();
    harness.coordinator_mut().registry_mut().note_coverage(
        c2,
        &scale_key(2),
        CoverageNote::Watched { since_ns: now },
    );
    harness
        .coordinator_mut()
        .registry_mut()
        .observe_entries(c0, &scale_key(0), 5, now);
    harness
        .coordinator_mut()
        .registry_mut()
        .set_in_flight(c1, &scale_key(1), true);
    harness.commit();
    let document = harness.render();
    assert_eq!(document["edges"][0]["entries"]["count"], 5);
    let presentation = capture_for(&harness, &document);
    let activity = |caller: CallerId| {
        presentation
            .edges
            .iter()
            .find(|edge| edge.caller == caller)
            .unwrap()
            .activity
    };
    assert_eq!(activity(c0), Activity::RecentlyObserved);
    assert_eq!(activity(c1), Activity::InFlight);
    assert_eq!(activity(c2), Activity::Quiet);
    // The dashboard display keeps its window: an old entry outside it
    // reads as quiet, not recent.
    let stale = Presentation::capture_dashboard(
        harness.coordinator(),
        "workload",
        0,
        now,
        1,
        now.saturating_add(1_000_000_000),
        1,
    );
    let stale_activity = stale
        .edges
        .iter()
        .find(|edge| edge.caller == c0)
        .unwrap()
        .activity;
    assert_eq!(stale_activity, Activity::Quiet);
}

#[test]
fn app_first_snapshot_joins_retained_identities_without_merging() {
    // Joining by basename instead of ID would merge these distinct physical
    // modules and caller incarnations, or borrow the wrong retained path.
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    presentation.callers[0].exe.as_mut().unwrap().path = Some("/opt/a/python3".into());
    presentation.callers[1].exe.as_mut().unwrap().path = Some("/opt/b/python3".into());
    presentation.modules[0].paths = vec!["/opt/a/provider.so".into()];
    presentation.modules[1].paths = vec!["/opt/b/provider.so".into()];
    presentation.edges[0].entry_count = 128;
    let before = serde_json::to_vec(&crate::inventory::render_json_from_presentation(
        &presentation,
    ))
    .unwrap();
    assert_eq!(
        application_label(&presentation, presentation.callers[0].id),
        "python3"
    );
    assert_eq!(
        application_label(&presentation, presentation.callers[1].id),
        "python3"
    );
    assert_eq!(
        module_label(&presentation, presentation.modules[0].id),
        "provider.so"
    );
    assert_eq!(
        module_label(&presentation, presentation.modules[1].id),
        "provider.so"
    );
    for caller in &presentation.callers {
        let _ = caller_lifecycle_label(caller);
    }
    for edge in &presentation.edges {
        let _ = observation_label(edge);
    }
    let snapshot = render_snapshot(&presentation);
    let overview: Vec<_> = snapshot
        .lines()
        .filter(|line| line.starts_with("application "))
        .collect();
    assert_eq!(overview.len(), presentation.edges.len(), "{snapshot}");
    for (line, edge) in overview.iter().zip(&presentation.edges) {
        assert!(
            line.contains(&format!("[{} pid ", edge.caller.label())),
            "{line}"
        );
        assert!(
            line.contains(&format!("[{}]: ", edge.module.label())),
            "{line}"
        );
    }
    for caller in &presentation.callers[..2] {
        let rows: Vec<_> = overview
            .iter()
            .filter(|line| line.contains(&format!("[{} pid ", caller.id.label())))
            .collect();
        assert!(!rows.is_empty());
        assert!(
            rows.iter()
                .all(|line| line.starts_with("application python3 ["))
        );
    }
    for module in &presentation.modules[..2] {
        assert!(
            overview
                .iter()
                .filter(|line| line.contains(&format!("[{}]: ", module.id.label())))
                .all(|line| line.contains("-> module provider.so ["))
        );
    }
    for path in [
        "/opt/a/python3",
        "/opt/b/python3",
        "/opt/a/provider.so",
        "/opt/b/provider.so",
    ] {
        assert!(
            snapshot.lines().any(|line| (line.starts_with("caller ")
                || line.starts_with("module "))
                && line.contains(path)),
            "{snapshot}"
        );
    }
    let detail_edges: Vec<_> = snapshot
        .lines()
        .filter(|line| line.starts_with("edge "))
        .collect();
    assert_eq!(detail_edges.len(), presentation.edges.len());
    for (line, edge) in detail_edges.iter().zip(&presentation.edges) {
        assert!(line.starts_with(&format!(
            "edge {} -> {} mapping ",
            edge.caller.label(),
            edge.module.label()
        )));
        assert!(line.contains(&format!("entries {} (", edge.entry_count)));
    }
    assert!(overview[0].contains("At least 128 entries observed"));
    assert_eq!(
        snapshot.lines().nth(1).unwrap(),
        format!(
            "coverage: {} gaps, {} refusals, {} suppressed",
            presentation.gaps.len(),
            presentation.budgets.refusals(),
            presentation.gaps_suppressed
        )
    );
    let marker = "Details: retained paths, identities, states and coverage follow.";
    assert!(snapshot.contains(&format!("\n{marker}\nbudgets: ")));
    assert_eq!(
        before,
        serde_json::to_vec(&crate::inventory::render_json_from_presentation(
            &presentation
        ))
        .unwrap()
    );

    presentation.edges.clear();
    let empty = render_snapshot(&presentation);
    assert!(empty.contains("No application/module associations observed; this does not prove that no PKCS#11 activity occurred."));
    assert!(!empty.lines().any(|line| line.starts_with("application ")));
}

#[test]
fn retained_labels_preserve_unknown_deleted_and_incarnation() {
    // A live-PID lookup would overwrite a retired incarnation's name; an
    // unescaped retained path could inject terminal control sequences.
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    let caller0 = presentation.callers[0].id;
    let caller1 = presentation.callers[1].id;
    let module = presentation.modules[0].id;
    presentation.callers[0].pid = 4242;
    presentation.callers[0].incarnation = 0;
    presentation.callers[0].lifecycle = CallerLifecycle::ExecRetired;
    presentation.callers[0].exe.as_mut().unwrap().path = Some("/opt/a/python3".into());
    presentation.callers[1].pid = 4242;
    presentation.callers[1].incarnation = 1;
    presentation.callers[1].lifecycle = CallerLifecycle::Exited;
    presentation.callers[1].exe.as_mut().unwrap().path = Some("/opt/firefox (deleted)".into());
    presentation.modules[0].paths = vec!["/opt/provider.so".into()];
    let template = presentation.edges[0].clone();
    presentation.edges = [caller0, caller1]
        .into_iter()
        .map(|caller| EdgeView {
            caller,
            module,
            ..template.clone()
        })
        .collect();
    let snapshot = render_snapshot(&presentation);
    assert!(
        snapshot.contains(&format!(
            "application python3 [{} pid 4242 incarnation 0]",
            caller0.label()
        )),
        "{snapshot}"
    );
    assert!(
        snapshot.contains(&format!(
            "application firefox (deleted) [{} pid 4242 incarnation 1]",
            caller1.label()
        )),
        "{snapshot}"
    );
    assert!(snapshot.contains("Application executed a new image"));
    assert!(snapshot.contains("Process exited"));
    assert!(snapshot.contains("(/opt/firefox (deleted))"));
    assert_eq!(
        application_label(&presentation, caller1),
        "firefox (deleted)"
    );
    assert_eq!(
        caller_lifecycle_label(&presentation.callers[0]),
        Some("Application executed a new image")
    );
    assert_eq!(
        caller_lifecycle_label(&presentation.callers[1]),
        Some("Process exited")
    );
    presentation.callers[0].lifecycle = CallerLifecycle::Mapped;
    assert_eq!(caller_lifecycle_label(&presentation.callers[0]), None);
    for (path, label) in [
        ("/opt/a/python3///", "python3"),
        ("////", "Unknown executable"),
        (" (deleted)", "Unknown executable"),
        ("/opt/app (deleted elsewhere)", "app (deleted elsewhere)"),
    ] {
        presentation.callers[0].exe.as_mut().unwrap().path = Some(path.into());
        assert_eq!(application_label(&presentation, caller0), label);
    }

    presentation.edges.truncate(1);
    for exe in [
        None,
        Some(ExeIdentity {
            path: None,
            ..presentation.callers[0].exe.clone().unwrap()
        }),
        Some(ExeIdentity {
            path: Some(String::new()),
            ..presentation.callers[0].exe.clone().unwrap()
        }),
    ] {
        presentation.callers[0].exe = exe;
        let snapshot = render_snapshot(&presentation);
        assert!(
            snapshot.contains(&format!(
                "application Unknown executable [{} pid 4242 incarnation 0]",
                caller0.label()
            )),
            "{snapshot}"
        );
    }
    for paths in [vec![], vec![String::new()]] {
        presentation.modules[0].paths = paths;
        let snapshot = render_snapshot(&presentation);
        assert!(
            snapshot.contains(&format!("-> module Unknown module [{}]:", module.label())),
            "{snapshot}"
        );
    }
    presentation.callers[0].exe = Some(ExeIdentity {
        dev: 1,
        ino: 1,
        mtime_secs: 0,
        mtime_nanos: 0,
        path: Some("/opt/日本語\u{1b}[31m\u{7}\u{9b}\u{7f}".into()),
    });
    presentation.callers[0].lifecycle = CallerLifecycle::Unknown;
    assert_eq!(
        caller_lifecycle_label(&presentation.callers[0]),
        Some("Process state unknown")
    );
    presentation.modules[0].paths = vec!["/opt/provider\u{1b}[2J\u{7}\u{9b}\u{7f}.so".into()];
    let snapshot = render_snapshot(&presentation);
    assert!(
        snapshot.contains("application 日本語\\u{1b}[31m\\u{7}\\u{9b}\\u{7f}"),
        "{snapshot}"
    );
    assert!(snapshot.contains("Process state unknown"));
    for control in ['\u{1b}', '\u{7}', '\u{9b}', '\u{7f}'] {
        assert!(!snapshot.contains(control), "{snapshot:?}");
    }
    presentation.edges[0].caller = CallerId(u32::MAX);
    presentation.edges[0].module = ModuleId(u32::MAX);
    assert_eq!(
        application_label(&presentation, CallerId(u32::MAX)),
        "Unknown executable"
    );
    assert_eq!(
        module_label(&presentation, ModuleId(u32::MAX)),
        "Unknown module"
    );
    let snapshot = render_snapshot(&presentation);
    let overview = snapshot
        .lines()
        .find(|line| line.starts_with("application "))
        .unwrap();
    assert!(
        overview.starts_with(
            "application Unknown executable [c4294967295] -> module Unknown module [m4294967295]:"
        ),
        "{overview}"
    );
    assert!(!overview.contains("pid "), "{overview}");
}

#[test]
fn overview_observations_preserve_evidence_meaning() {
    // Erasing positive history on retirement, interpreting an unknown as
    // zero, or dropping a frozen watch interval would misstate evidence.
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    presentation.edges.truncate(1);
    let counted = |lossy| UseCoverage::Counted {
        since_ns: 10,
        lossy,
    };
    let cases = [
        (
            128,
            false,
            counted(false),
            MappingState::Ended,
            "At least 128 entries observed",
            None,
        ),
        (
            128,
            false,
            counted(true),
            MappingState::Uncertain,
            "At least 128 entries observed (capture incomplete)",
            None,
        ),
        (
            128,
            true,
            counted(true),
            MappingState::Ended,
            "At least 128 entries observed (counter saturated) (capture incomplete)",
            None,
        ),
        (
            128,
            true,
            UseCoverage::Unknown(UnknownReason::RetiredBeforeCoverage),
            MappingState::Ended,
            "At least 128 entries observed (counter saturated)",
            Some("unknown (retired before coverage)"),
        ),
        (
            0,
            false,
            UseCoverage::Witnessed { first_ns: 10 },
            MappingState::Ended,
            "Use observed; count unavailable",
            None,
        ),
        (
            0,
            false,
            counted(false),
            MappingState::Mapped,
            "No entries observed in counted interval",
            Some("counted since 10"),
        ),
        (
            0,
            false,
            counted(true),
            MappingState::Mapped,
            "Activity unknown; capture incomplete",
            Some("counted since 10 (lossy)"),
        ),
        (
            0,
            false,
            UseCoverage::WatchedNoUse {
                since_ns: 10,
                until_ns: None,
            },
            MappingState::Mapped,
            "No entries observed during the covered interval",
            Some("no use since 10"),
        ),
        (
            0,
            false,
            UseCoverage::WatchedNoUse {
                since_ns: 10,
                until_ns: Some(20),
            },
            MappingState::Ended,
            "No entries observed during the covered interval",
            Some("no use from 10 to 20"),
        ),
        (
            0,
            false,
            UseCoverage::Unknown(UnknownReason::PendingFirstUse),
            MappingState::Mapped,
            "Observation pending",
            Some("unknown (first use undecided)"),
        ),
        (
            0,
            false,
            UseCoverage::Unknown(UnknownReason::ScanOnly),
            MappingState::Mapped,
            "Module mapped; activity not captured",
            Some("unknown (scan only)"),
        ),
        (
            0,
            false,
            UseCoverage::Unknown(UnknownReason::ScanOnly),
            MappingState::Ended,
            "Activity not captured",
            Some("unknown (scan only)"),
        ),
        (
            0,
            false,
            UseCoverage::Unknown(UnknownReason::Loss("bad\u{1b}[2J\u{7}\u{9b}\u{7f}".into())),
            MappingState::Mapped,
            "Activity unknown",
            Some("unknown (loss: bad\\u{1b}[2J\\u{7}\\u{9b}\\u{7f})"),
        ),
    ];
    for (count, saturated, coverage, mapping, explanation, interval) in cases {
        let edge = &mut presentation.edges[0];
        edge.entry_count = count;
        edge.entry_saturated = saturated;
        edge.coverage = coverage;
        edge.mapping = mapping;
        let before = serde_json::to_vec(&crate::inventory::render_json_from_presentation(
            &presentation,
        ))
        .unwrap();
        let label = observation_label(&presentation.edges[0]);
        if matches!(
            presentation.edges[0].coverage,
            UseCoverage::Unknown(UnknownReason::Loss(_))
        ) {
            assert_eq!(
                label,
                "Activity unknown; unknown (loss: bad\\u{1b}[2J\\u{7}\\u{9b}\\u{7f})"
            );
        } else {
            assert_eq!(label, explanation);
        }
        let snapshot = render_snapshot(&presentation);
        let overview = snapshot
            .lines()
            .find(|line| line.starts_with("application "))
            .unwrap_or_else(|| panic!("missing overview:\n{snapshot}"));
        assert!(
            overview.contains(&format!("]: {explanation}")),
            "{overview}"
        );
        if let Some(interval) = interval {
            assert!(overview.contains(interval), "{overview}");
        }
        if explanation == "Observation pending"
            || explanation.starts_with("Activity unknown")
            || explanation.ends_with("not captured")
        {
            assert!(
                !overview.contains("No entries") && !overview.contains("0 entries"),
                "{overview}"
            );
        }
        assert!(!overview.chars().any(char::is_control), "{overview:?}");
        assert_eq!(
            before,
            serde_json::to_vec(&crate::inventory::render_json_from_presentation(
                &presentation
            ))
            .unwrap()
        );
    }
}

#[test]
fn snapshot_and_json_agree_on_identities_states_totals_and_gaps() {
    let harness = varied_harness();
    let document = harness.render();
    let presentation = capture_for(&harness, &document);
    let snapshot = render_snapshot(&presentation);
    let lines: Vec<&str> = snapshot.lines().collect();

    // Header totals match the document arrays + pass count.
    assert!(
        lines[0].starts_with("inventory workload ("),
        "header: {}",
        lines[0]
    );
    for (label, key) in [
        ("caller", "callers"),
        ("module", "modules"),
        ("edge", "edges"),
    ] {
        let count = document[key].as_array().unwrap().len();
        let plural = if count == 1 { "" } else { "s" };
        assert!(
            lines[0].contains(&format!("{count} {label}{plural}")),
            "header {label} count: {}",
            lines[0]
        );
    }
    let passes = document["observation"]["passes"].as_u64().unwrap();
    assert!(lines[0].contains(&format!("{passes} pass")), "{}", lines[0]);

    // Budgets line matches every budget row.
    let budgets = lines
        .iter()
        .find(|line| line.starts_with("budgets: "))
        .unwrap();
    assert!(budgets.starts_with("budgets: "), "{budgets}");
    for row in ["callers", "modules", "edges", "endpoints"] {
        let limit = document["budgets"][row]["limit"].as_u64().unwrap();
        let occupied = document["budgets"][row]["occupied"].as_u64().unwrap();
        let refused = document["budgets"][row]["refused"].as_u64().unwrap();
        assert!(
            budgets.contains(&format!("{row} {occupied}/{limit} refused {refused}")),
            "budgets {row}: {budgets}"
        );
    }
    assert!(
        budgets.contains(&format!(
            " | inventory_endpoints {}/{} refused {} | inventory_attach_modules {}/{} refused {} | ",
            document["budgets"]["inventory_endpoints"]["occupied"],
            document["budgets"]["inventory_endpoints"]["limit"],
            document["budgets"]["inventory_endpoints"]["refused"],
            document["budgets"]["inventory_attach_modules"]["occupied"],
            document["budgets"]["inventory_attach_modules"]["limit"],
            document["budgets"]["inventory_attach_modules"]["refused"],
        )),
        "budgets inventory_endpoints: {budgets}"
    );
    let resources = &document["budgets"]["instance_semantic_resources"];
    assert!(
        budgets.contains(&format!(
            " | semantic {}/{}B peak={} refused={} | open={} active={} pending={} detached={}",
            resources["charged_bytes"],
            resources["limit_bytes"],
            resources["peak_charged_bytes"],
            resources["refused"],
            resources["occupancy"]["open_bindings"],
            resources["occupancy"]["active_machines"],
            resources["occupancy"]["pending_calls"],
            resources["occupancy"]["detached_calls"],
        )),
        "shared semantic resource budget: {budgets}"
    );
    assert!(
        budgets.contains(&format!(
            "counters observed {} saturated {}",
            document["budgets"]["counters"]["observed_edges"],
            document["budgets"]["counters"]["saturated_edges"]
        )),
        "{budgets}"
    );
    assert!(
        budgets.contains(&format!(
            "semantic_state {} held {}/{} unknown {} refused {}",
            document["budgets"]["semantic_state"]["status"]
                .as_str()
                .unwrap(),
            document["budgets"]["semantic_state"]["occupied"],
            document["budgets"]["semantic_state"]["limit"],
            document["budgets"]["semantic_state"]["unknown_edges"],
            document["budgets"]["semantic_state"]["refused"],
        )),
        "{budgets}"
    );
    assert!(
        budgets.contains(&format!(
            "retained_history {}/{} suppressed {}",
            document["budgets"]["retained_history"]["retained"],
            document["budgets"]["retained_history"]["limit"],
            document["budgets"]["retained_history"]["suppressed"]
        )),
        "{budgets}"
    );

    // Caller identities + lifecycles.
    for caller in document["callers"].as_array().unwrap() {
        let id = caller["id"].as_str().unwrap();
        let line = lines
            .iter()
            .find(|line| line.starts_with(&format!("caller {id} ")))
            .unwrap_or_else(|| panic!("missing caller line for {id}:\n{snapshot}"));
        assert!(line.contains(&format!("pid {}", caller["pid"])), "{line}");
        assert!(
            line.contains(&format!("incarnation {}", caller["incarnation"])),
            "{line}"
        );
        assert!(
            line.contains(caller["lifecycle"].as_str().unwrap()),
            "{line}"
        );
    }

    // Module identities + lifecycle + admission.
    for module in document["modules"].as_array().unwrap() {
        let id = module["id"].as_str().unwrap();
        let line = lines
            .iter()
            .find(|line| line.starts_with(&format!("module {id} ")))
            .unwrap_or_else(|| panic!("missing module line for {id}:\n{snapshot}"));
        assert!(
            line.contains(module["lifecycle"].as_str().unwrap()),
            "{line}"
        );
        assert!(
            line.contains(module["admission"]["state"].as_str().unwrap()),
            "{line}"
        );
    }

    // Edge states: mapping, counts, observation, presence, capture,
    // activity, semantics — every edge, both forms.
    for edge_json in document["edges"].as_array().unwrap() {
        let caller = edge_json["caller"].as_str().unwrap();
        let module = edge_json["module"].as_str().unwrap();
        let line = lines
            .iter()
            .find(|line| line.starts_with(&format!("edge {caller} -> {module} ")))
            .unwrap_or_else(|| panic!("missing edge line {caller}->{module}:\n{snapshot}"));
        assert!(
            line.contains(&format!(
                "mapping {}",
                edge_json["mapping"]["state"].as_str().unwrap()
            )),
            "{line}"
        );
        assert!(
            line.contains(&format!("entries {}", edge_json["entries"]["count"])),
            "{line}"
        );
        assert!(
            line.contains(edge_json["entries"]["observation"].as_str().unwrap()),
            "{line}"
        );
        let edge_view = presentation
            .edges
            .iter()
            .find(|edge| edge.caller.label() == caller && edge.module.label() == module)
            .unwrap();
        assert!(
            line.contains(&format!("presence {}", edge_view.presence.label())),
            "{line}"
        );
        assert!(
            line.contains(&format!("capture {}", edge_view.capture.label())),
            "{line}"
        );
        // Coverage: the JSON state and the snapshot label render the
        // same view; the scan lane reads unknown with its reason.
        assert_eq!(
            edge_json["entries"]["coverage"]["state"],
            edge_view.coverage.state(),
            "{line}"
        );
        // New fields append at the line end; older fields keep their
        // positions.
        assert!(
            line.ends_with(&format!(
                " coverage {}",
                coverage_label(&edge_view.coverage)
            )),
            "{line}"
        );
        let reason = edge_json["entries"]["coverage"]["reason"].as_str().unwrap();
        assert!(
            reason == "scan_only" || reason == "not_admitted",
            "scan-lane coverage reason: {reason}"
        );
        assert!(
            line.contains(&format!("activity {}", edge_view.activity.label())),
            "{line}"
        );
        assert!(
            line.contains("unknown (semantic capture withheld)"),
            "{line}"
        );
        assert_eq!(
            edge_json["semantics"], "unknown (semantic capture withheld)",
            "JSON semantics for {caller}->{module}"
        );
    }

    // Gaps: same count, subjects, and budget triples.
    let gaps_json = document["gaps"].as_array().unwrap();
    let gap_lines: Vec<&&str> = lines
        .iter()
        .filter(|line| line.starts_with("gap ["))
        .collect();
    assert_eq!(gap_lines.len(), gaps_json.len(), "{snapshot}");
    for gap in gaps_json {
        let subject = gap["subject"].as_str().unwrap();
        let line = gap_lines
            .iter()
            .find(|line| line.contains(&format!("[{subject}]")))
            .unwrap_or_else(|| panic!("missing gap line for {subject}:\n{snapshot}"));
        assert!(line.contains(gap["reason"].as_str().unwrap()), "{line}");
        if gap["budget"].is_null() {
            assert!(!line.contains("(budget "), "{line}");
        } else {
            assert!(
                line.contains(&format!(
                    "(budget {}: limit {}, requested {})",
                    gap["budget"]["resource"].as_str().unwrap(),
                    gap["budget"]["limit"],
                    gap["budget"]["requested"]
                )),
                "{line}"
            );
        }
    }
    assert_eq!(
        document["gaps_suppressed"].as_u64().unwrap(),
        0,
        "varied fixture retains every gap"
    );
    assert!(
        !snapshot.contains("gaps suppressed:"),
        "no suppression marker without suppression:\n{snapshot}"
    );
}

#[test]
fn snapshot_is_deterministic_sorted_and_stable() {
    let harness = varied_harness();
    let document = harness.render();
    let first = render_snapshot(&capture_for(&harness, &document));
    let second = render_snapshot(&capture_for(&harness, &document));
    assert_eq!(first, second, "same fixture renders byte-identical");
    // Sorted identities: callers, modules, edges in label order.
    let caller_ids: Vec<&str> = first
        .lines()
        .filter(|line| line.starts_with("caller "))
        .map(|line| line.split_whitespace().nth(1).unwrap())
        .collect();
    let mut sorted = caller_ids.clone();
    sorted.sort();
    assert_eq!(caller_ids, sorted, "caller lines sorted");
    let module_ids: Vec<&str> = first
        .lines()
        .filter(|line| line.starts_with("module "))
        .map(|line| line.split_whitespace().nth(1).unwrap())
        .collect();
    let mut sorted = module_ids.clone();
    sorted.sort();
    assert_eq!(module_ids, sorted, "module lines sorted");
    // The legacy text entry points render through the same model.
    let legacy = render_text(harness.coordinator(), "workload", 0, harness.now_ns(), 99);
    assert!(
        legacy.starts_with("inventory workload (99 passes,"),
        "{legacy}"
    );
    let legacy_json = render_json(harness.coordinator(), "workload", 0, harness.now_ns(), 99);
    assert_eq!(legacy_json["observation"]["passes"], 99);
}

#[test]
fn mapping_columns_never_report_calls() {
    // A mapped-but-quiet edge is "mapped, quiet" with zero counts and
    // no last-seen — never "active".
    let harness = varied_harness();
    let document = harness.render();
    let presentation = capture_for(&harness, &document);
    let snapshot = render_snapshot(&presentation);
    let quiet_mapped: Vec<&EdgeView> = presentation
        .edges
        .iter()
        .filter(|edge| {
            edge.presence == Presence::Mapped
                && !matches!(
                    edge.activity,
                    Activity::RecentlyObserved | Activity::InFlight
                )
        })
        .collect();
    assert!(!quiet_mapped.is_empty(), "varied fixture has silent edges");
    for edge in quiet_mapped {
        assert_eq!(edge.entry_count, 0);
        let line = snapshot
            .lines()
            .find(|line| {
                line.starts_with(&format!(
                    "edge {} -> {} ",
                    edge.caller.label(),
                    edge.module.label()
                ))
            })
            .unwrap();
        assert!(!line.contains(", active"), "{line}");
    }
    // Unknown mapping lifecycles are covered by the coordinator's own
    // uncertain-state tests; here every snapshot mapping state is one
    // of the three registry labels.
    for line in snapshot.lines().filter(|line| line.starts_with("edge ")) {
        assert!(
            line.contains("mapping mapped")
                || line.contains("mapping ended")
                || line.contains("mapping uncertain"),
            "{line}"
        );
    }
}

/// One live caller (pid 73_000) mapping `modules` scale modules.
fn single_caller_harness(name: &'static str, modules: usize) -> (Harness, CallerId) {
    let mut harness = harness();
    let spec = ScaleSpec {
        name,
        callers: 1,
        modules,
        edges_per_caller: modules,
        endpoints_per_module: 4,
        first_pid: 73_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let caller = harness.coordinator().adapter().live_id(73_000).unwrap();
    (harness, caller)
}

fn edge_line<'a>(snapshot: &'a str, edge: &EdgeView) -> &'a str {
    snapshot
        .lines()
        .find(|line| {
            line.starts_with(&format!(
                "edge {} -> {} ",
                edge.caller.label(),
                edge.module.label()
            ))
        })
        .unwrap()
}

#[test]
fn a_witnessed_edge_is_never_idle_in_any_output_even_after_exit() {
    let (mut harness, caller) = single_caller_harness("present-witness", 2);
    harness.advance(10_000);
    let now = harness.now_ns();
    harness
        .coordinator_mut()
        .registry_mut()
        .note_witness(caller, &scale_key(0), now);
    harness.commit();
    let document = harness.render();
    let presentation = capture_for(&harness, &document);
    let witnessed = &presentation.edges[0];
    assert_eq!(witnessed.coverage.state(), "witnessed");
    // Witnessed use is never quiet: "used (recency unknown)".
    assert_eq!(witnessed.activity, Activity::Used);
    assert_eq!(presentation.edges[1].activity, Activity::Uncovered);
    let entries = &document["edges"][0]["entries"];
    assert_eq!(entries["count"], 0);
    assert_eq!(
        entries["observation"],
        "unknown (count unavailable; use witnessed)"
    );
    assert_eq!(entries["coverage"]["state"], "witnessed");
    assert_eq!(entries["coverage"]["first_ns"], now);
    assert!(entries["coverage"]["since_ns"].is_null());
    assert!(
        entries["last_seen_ns"].is_null(),
        "no recency from a witness"
    );
    let snapshot = render_snapshot(&presentation);
    let line = edge_line(&snapshot, witnessed);
    assert!(line.contains("activity used (recency unknown)"), "{line}");
    assert!(!line.contains("activity quiet"), "{line}");
    assert!(
        line.contains(&format!("coverage used, count unavailable (first {now})")),
        "{line}"
    );
    assert_eq!(entries_display(witnessed), "?");
    // The caller exits: the edge ends, the witness stands, and the
    // activity still says used — never quiet, never erased.
    harness.source().kill(73_000);
    harness.advance(10);
    let now = harness.now_ns();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &BTreeSet::new(),
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    harness.commit();
    let document = harness.render();
    let presentation = capture_for(&harness, &document);
    let witnessed = &presentation.edges[0];
    assert_eq!(witnessed.mapping, MappingState::Ended);
    assert_eq!(witnessed.coverage.state(), "witnessed");
    assert_eq!(witnessed.activity, Activity::Used);
    assert_eq!(
        document["edges"][0]["entries"]["coverage"]["state"],
        "witnessed"
    );
    // Exhaustively: whatever the mapping, a witnessed edge renders used
    // unless a counted recency or a live call outranks it.
    for mapping in [
        MappingState::Mapped,
        MappingState::Ended,
        MappingState::Uncertain,
    ] {
        let witnessed = UseCoverage::Witnessed { first_ns: 1 };
        assert_eq!(
            Activity::for_edge(mapping, false, false, false, &witnessed),
            Activity::Used
        );
        assert_eq!(
            Activity::for_edge(mapping, true, false, false, &witnessed),
            Activity::InFlight
        );
    }
}

#[test]
fn partial_attach_renders_no_use_since_and_unknown_side_by_side() {
    let (mut harness, caller) = single_caller_harness("present-partial", 2);
    let now = harness.now_ns();
    let refused = refused_module_info(0);
    let refused_key = refused.key.clone();
    harness
        .coordinator_mut()
        .registry_mut()
        .note_mapping(caller, 73_000, refused, now);
    harness.commit();
    harness.advance(10);
    let since = harness.now_ns();
    {
        let registry = harness.coordinator_mut().registry_mut();
        registry.set_uncovered_reason(UnknownReason::NotAttached);
        registry.note_coverage(
            caller,
            &scale_key(0),
            CoverageNote::Watched { since_ns: since },
        );
        registry.note_coverage(
            caller,
            &refused_key,
            CoverageNote::Watched { since_ns: since },
        );
    }
    harness.commit();
    let document = harness.render();
    let presentation = capture_for(&harness, &document);
    let snapshot = render_snapshot(&presentation);
    let by_path = |path: &str| {
        let module = document["modules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|module| module["paths"][0] == path)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let index = presentation
            .edges
            .iter()
            .position(|edge| edge.module.label() == module)
            .unwrap();
        (index, &presentation.edges[index])
    };
    let (attached_index, attached) = by_path("/scale/m0.so");
    let attached_json = &document["edges"][attached_index]["entries"];
    assert_eq!(attached_json["count"], 0);
    assert_eq!(attached_json["observation"], "observed");
    assert_eq!(attached_json["coverage"]["state"], "watched_no_use");
    assert_eq!(attached_json["coverage"]["since_ns"], since);
    assert!(
        edge_line(&snapshot, attached).contains(&format!("coverage no use since {since}")),
        "{snapshot}"
    );
    assert_eq!(entries_display(attached), "0");
    let (refused_index, refused) = by_path("/scale/refused0.so");
    let refused_json = &document["edges"][refused_index]["entries"];
    assert_eq!(refused_json["count"], 0);
    assert_eq!(refused_json["observation"], "unknown (not admitted)");
    assert_eq!(refused_json["coverage"]["state"], "unknown");
    assert_eq!(refused_json["coverage"]["reason"], "not_admitted");
    assert!(
        edge_line(&snapshot, refused).contains("coverage unknown (not admitted)"),
        "{snapshot}"
    );
    assert_eq!(entries_display(refused), "?");
    let (other_index, other) = by_path("/scale/m1.so");
    assert_eq!(
        document["edges"][other_index]["entries"]["coverage"]["reason"],
        "not_attached"
    );
    assert!(
        edge_line(&snapshot, other).contains("coverage unknown (not attached)"),
        "{snapshot}"
    );
    assert_eq!(
        document["observation"]["usage_feed"], true,
        "derived summary"
    );
}

#[test]
fn a_module_admitted_after_a_first_refusal_never_reads_refused() {
    // I2 through the presentation: the first pass refused the module,
    // the attach set admitted it later; every output reads admitted,
    // the capture state is no longer refused, and the change is kept.
    let (mut harness, caller) = single_caller_harness("present-i2", 1);
    let now = harness.now_ns();
    let refused = refused_module_info(5);
    let key = refused.key.clone();
    harness
        .coordinator_mut()
        .registry_mut()
        .note_mapping(caller, 73_000, refused.clone(), now);
    harness.commit();
    let presentation = capture_for(&harness, &harness.render());
    assert!(
        presentation
            .edges
            .iter()
            .any(|edge| edge.capture == Capture::Refused)
    );
    harness.advance(10);
    let later = harness.now_ns();
    let admitted = ModuleInfo {
        admission: AdmissionState::Admitted,
        admission_class: Some("exact".into()),
        admission_endpoints: Some(544),
        admission_reasons: Vec::new(),
        ..refused
    };
    harness
        .coordinator_mut()
        .registry_mut()
        .note_mapping(caller, 73_000, admitted, later);
    harness.commit();
    let document = harness.render();
    let presentation = capture_for(&harness, &document);
    let module_id = harness
        .coordinator()
        .registry()
        .module_id_for(&key)
        .unwrap();
    let module_json = document["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|module| module["id"] == module_id.label())
        .unwrap();
    assert_eq!(module_json["admission"]["state"], "admitted");
    assert_eq!(module_json["admission"]["endpoints"], 544);
    assert_eq!(
        module_json["admission"]["history"],
        serde_json::json!([{"from": "refused", "to": "admitted", "at_ns": later}])
    );
    assert!(
        presentation
            .edges
            .iter()
            .all(|edge| edge.capture != Capture::Refused),
        "an instrumented module never reads refused"
    );
    let snapshot = render_snapshot(&presentation);
    assert!(
        snapshot.contains(&format!(
            "({}) admission history refused->admitted@{later}",
            "admitted"
        )),
        "{snapshot}"
    );
    assert!(
        document["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap["subject"] == "module admission changed"),
        "{document}"
    );
}

#[test]
fn budgets_carry_the_inventory_attach_set_endpoints() {
    let harness = varied_harness();
    let document = harness.render();
    let row = &document["budgets"]["inventory_endpoints"];
    assert_eq!(row["limit"], 4096, "the coordinator's Inventory budget");
    assert_eq!(
        row["occupied"],
        harness.coordinator().attach_set().len(),
        "occupancy is the attach set's endpoint count"
    );
    let presentation = capture_for(&harness, &document);
    assert_eq!(presentation.budgets.inventory_endpoints_limit, 4096);
    assert_eq!(document["budgets"]["inventory_endpoints"]["refused"], 0);
    assert_eq!(
        document["budgets"]["inventory_attach_modules"],
        serde_json::json!({"limit": 4096, "occupied": 0, "refused": 0})
    );
    let snapshot = render_snapshot(&presentation);
    let budgets = snapshot
        .lines()
        .find(|line| line.starts_with("budgets: "))
        .unwrap();
    assert!(
        budgets.contains(
            " | inventory_endpoints 0/4096 refused 0 | inventory_attach_modules 0/4096 refused 0 | "
        ),
        "{budgets}"
    );
    assert!(
        budgets.contains(" | semantic 1048576/67108864B peak=1048576 refused=0 | "),
        "{budgets}"
    );
    assert!(budgets.ends_with(
        "open=0 active=0 pending=0 detached=0 mechanisms=0 categories=0 functions=0 function_bytes=0 function_capacity=0 returns=0 async_bytes=0 async_capacity=0 origins=0 origin_elements=0 origin_capacity=0"
    ), "{budgets}");
}

#[test]
fn snapshot_gap_lines_escape_target_controlled_control_characters() {
    // DR-11: gap subjects and reasons carry target-controlled strings
    // (paths, error text). The pager snapshot escapes them like every
    // other field; the JSON keeps them verbatim.
    let (mut harness, _caller) = single_caller_harness("present-gap-escape", 1);
    let hostile_subject = "/tmp/evil\u{1b}[2J\u{1b}]0;owned\u{7}.so";
    let hostile_reason = "unreadable\r\nfake line\u{9b}31m";
    for budget in [
        None,
        Some(crate::discovery::caller_registry::BudgetRefusal {
            resource: "callers",
            limit: 1,
            requested: 2,
        }),
    ] {
        harness
            .coordinator_mut()
            .registry_mut()
            .record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: Some(4242),
                subject: hostile_subject.into(),
                reason: hostile_reason.into(),
                budget,
            });
    }
    harness.commit();
    let document = harness.render();
    let presentation = capture_for(&harness, &document);
    let snapshot = render_snapshot(&presentation);
    for raw in ['\u{1b}', '\u{7}', '\r', '\u{9b}'] {
        assert!(
            !snapshot.contains(raw),
            "raw {raw:?} in snapshot:\n{snapshot:?}"
        );
    }
    let gap_lines: Vec<&str> = snapshot
        .lines()
        .filter(|line| line.starts_with("gap ["))
        .collect();
    assert_eq!(
        gap_lines.len(),
        2,
        "one line per gap, no injected line:\n{snapshot}"
    );
    let subject = crate::render::escape_controls(hostile_subject).into_owned();
    let reason = crate::render::escape_controls(hostile_reason).into_owned();
    assert_eq!(gap_lines[0], format!("gap [{subject}] {reason}"));
    assert_eq!(
        gap_lines[1],
        format!("gap [{subject}] {reason} (budget callers: limit 1, requested 2)")
    );
    assert!(!snapshot.contains("\nfake line"), "{snapshot:?}");
    // JSON is unaffected: the verbatim strings, escaped by JSON itself.
    let gaps = document["gaps"].as_array().unwrap();
    assert!(
        gaps.iter()
            .any(|gap| gap["subject"] == hostile_subject && gap["reason"] == hostile_reason)
    );
}

#[test]
fn uncovered_edges_read_neither_idle_nor_armed() {
    // I3 (review): quiet is a fact only under a loss-free count or a
    // watch; armed only where usage is actually covered. Every other
    // live edge reads an explicit unknown activity and a capture state
    // that says why (scan only, or coverage lost with the reason in
    // `entries.coverage`).
    let (mut harness, caller) = single_caller_harness("present-uncovered", 6);
    harness.advance(10_000_000_000);
    let now = harness.now_ns();
    let refused = refused_module_info(9);
    let refused_key = refused.key.clone();
    {
        let registry = harness.coordinator_mut().registry_mut();
        registry.note_mapping(caller, 73_000, refused, now);
        // m0 scan only (no note). m1 watched. m2 counted, loss-free and
        // old. m3 counted, then lossy. m4 attach failed. m5 witnessed.
        registry.note_coverage(
            caller,
            &scale_key(1),
            CoverageNote::Watched { since_ns: 10 },
        );
        registry.note_coverage(
            caller,
            &scale_key(3),
            CoverageNote::Counted { since_ns: 10 },
        );
        registry.note_coverage(
            caller,
            &scale_key(4),
            CoverageNote::Unknown(UnknownReason::AttachFailed),
        );
        registry.note_witness(caller, &scale_key(5), 30);
    }
    harness.commit();
    harness
        .coordinator_mut()
        .registry_mut()
        .note_capture_loss("EVENTS ring lost 2 records".into());
    harness.commit();
    // m2: a counting feed that started after the loss: loss-free, old.
    {
        let registry = harness.coordinator_mut().registry_mut();
        registry.note_coverage(
            caller,
            &scale_key(2),
            CoverageNote::Counted { since_ns: 10 },
        );
        registry.observe_entries(caller, &scale_key(2), 2, 20);
    }
    harness.commit();
    // One more pass without counts: per-pass activity clears the rise,
    // so the old counted edge reads quiet.
    harness.commit();
    let document = harness.render();
    let presentation = Presentation::capture(harness.coordinator(), "workload", 0, now, 3);
    let view = |key: &ModuleKey| {
        let id = harness.coordinator().registry().module_id_for(key).unwrap();
        presentation
            .edges
            .iter()
            .find(|edge| edge.module == id)
            .unwrap()
            .clone()
    };
    let expect = [
        (scale_key(0), Capture::ScanOnly, Activity::Uncovered),
        (scale_key(1), Capture::Armed, Activity::Quiet),
        (scale_key(2), Capture::Armed, Activity::Quiet),
        (scale_key(3), Capture::Armed, Activity::Lossy),
        (scale_key(4), Capture::CoverageLost, Activity::Uncovered),
        (scale_key(5), Capture::Armed, Activity::Used),
        (refused_key, Capture::Refused, Activity::Uncovered),
    ];
    let snapshot = render_snapshot(&presentation);
    for (key, capture, activity) in expect {
        let edge = view(&key);
        assert_eq!(
            (edge.capture, edge.activity),
            (capture, activity),
            "{key:?}: {:?}",
            edge.coverage
        );
        let line = edge_line(&snapshot, &edge);
        assert!(
            line.contains(&format!(
                "capture {} activity {} ",
                capture.label(),
                activity.label()
            )),
            "{line}"
        );
    }
    // The attach failure's reason rides in the coverage, in every form.
    let failed = view(&scale_key(4));
    assert!(
        edge_line(&snapshot, &failed).ends_with("coverage unknown (attach failed)"),
        "{snapshot}"
    );
    let failed_json = document["edges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|edge| edge["module"] == failed.module.label())
        .unwrap();
    assert_eq!(
        failed_json["entries"]["coverage"]["reason"],
        "attach_failed"
    );
    assert!(failed_json["entries"]["coverage"]["lossy"].is_null());
    // `lossy` is a boolean exactly for counted coverage.
    let lossy_json = document["edges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|edge| edge["module"] == view(&scale_key(3)).module.label())
        .unwrap();
    assert_eq!(lossy_json["entries"]["coverage"]["lossy"], true);
}

// F3-06 doc-accuracy pin (round-2 F2-07): `docs/schema/inventory-events-v1.md`
// states the per-pass `recently observed` precedence exception (an in-flight
// edge, or one with active operations, reads `operation initialized /
// in flight` over a rise — production `Activity::for_edge`) and the
// `last_seen_ns` correction (records and the snapshot DO carry
// `entries.last_seen_ns`, serialized by `edge_json` verbatim into
// `edge_observed` payloads — only the dashboard's trailing 5 s window
// over it is display-only). Either old sentence returning fails the pin.
#[test]
fn event_doc_pins_activity_precedence_and_last_seen_presence() {
    const DOC: &str = include_str!("../docs/schema/inventory-events-v1.md");
    let counted = UseCoverage::Counted {
        since_ns: 7,
        lossy: false,
    };
    assert_eq!(
        Activity::for_edge(MappingState::Mapped, true, true, false, &counted),
        Activity::InFlight,
        "in-flight takes precedence over a rise"
    );
    assert_eq!(
        Activity::for_edge(MappingState::Mapped, false, true, true, &counted),
        Activity::InFlight,
        "active operations take precedence over a rise"
    );
    assert_eq!(Activity::RecentlyObserved.label(), "recently observed");
    assert!(
        DOC.contains("take precedence") && DOC.contains("over a rise"),
        "the precedence exception is stated"
    );
    assert!(
        !DOC.contains("`recently observed` iff"),
        "the old unconditional `iff` must not return"
    );
    assert!(
        DOC.contains("do carry `entries.last_seen_ns`")
            && DOC.contains("display-only, never the recorded signal"),
        "the `last_seen_ns` display-only correction is stated"
    );
    assert!(
        !DOC.contains("never appears in records or the snapshot"),
        "the old `never appears` claim must not return"
    );
}
