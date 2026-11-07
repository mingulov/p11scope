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
    assert_eq!(
        coverage_label_at(&pending, 2),
        "unknown (first use undecided)"
    );
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
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
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

/// The snapshot and JSON list `--exclude-module` files as "excluded by
/// you" with path, identity, and process count, plus unmatched inputs.
#[test]
fn snapshot_and_json_list_excluded_modules_and_unmatched_inputs() {
    let harness = varied_harness();
    let document = harness.render();
    let mut presentation = capture_for(&harness, &document);
    presentation.excluded_modules = vec![crate::render::ExcludedOut {
        path: "/opt/libp11-kit.so.0.4.8".into(),
        dev: 42,
        ino: 1001,
        processes: 3,
    }];
    presentation.unmatched_excludes = vec!["nope.so".into()];
    let snapshot = render_snapshot(&presentation);
    assert!(
        snapshot.contains("Excluded by you (1 files):"),
        "{snapshot}"
    );
    assert!(
        snapshot.contains("/opt/libp11-kit.so.0.4.8: excluded by you (device 42 inode 1001, 3 processes mapped it)"),
        "{snapshot}"
    );
    assert!(
        snapshot.contains("Unmatched exclusions (1): nope.so"),
        "{snapshot}"
    );
    let out = crate::inventory::render_json_from_presentation(&presentation);
    assert_eq!(
        out["excluded_modules"][0]["path"],
        "/opt/libp11-kit.so.0.4.8"
    );
    assert_eq!(out["excluded_modules"][0]["processes"], 3);
    assert_eq!(out["unmatched_excludes"][0], "nope.so");
}

/// The snapshot names a refused module with its admission reason in plain
/// words, on the module's own detail line.
#[test]
fn snapshot_names_a_refused_module_with_its_admission_reason() {
    let harness = varied_harness();
    let document = harness.render();
    let presentation = capture_for(&harness, &document);
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    let lines: Vec<&str> = snapshot.lines().collect();
    let position = lines
        .iter()
        .position(|line| line.contains("/scale/refused0.so") && line.contains("(refused)"))
        .expect("the refused module line");
    assert!(
        lines[position + 1].contains("fixture refusal"),
        "{snapshot}"
    );
    // Admitted modules carry no admission detail line.
    let admitted = lines
        .iter()
        .position(|line| line.contains("/scale/m0.so") && line.contains("(admitted)"))
        .expect("an admitted module line");
    assert!(
        !lines[admitted + 1].trim_start().starts_with("admission:"),
        "{snapshot}"
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
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
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
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    let line = edge_line(&snapshot, edge);
    assert!(
        line.contains("capture watch ended activity unknown "),
        "{line}"
    );
    let ago = crate::render::fmt_ns(Some(presentation.ended_ns.saturating_sub(since + 10)));
    assert!(
        line.contains(&format!("no use for 10ns (watch ended {ago} ago)")),
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
        let _ = observation_label_at(edge, presentation.ended_ns);
    }
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
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
    assert_eq!(snapshot.lines().nth(1).unwrap(), "coverage: complete");
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

/// Item 24: the inventory coverage line uses the one lowercase
/// format and omits zero counts — `coverage: complete`, or
/// `coverage: partial — 2 gaps, 1 refused, 3 more not shown` with
/// zero segments dropped.
#[test]
fn coverage_line_uses_lowercase_verdict_and_omits_zero_counts() {
    let coverage_of = |gaps: usize, refused: u64, suppressed: u64| {
        let harness = varied_harness();
        let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
        presentation.gaps.clear();
        for index in 0..gaps {
            presentation.gaps.push(GapView {
                caller: None,
                module: None,
                pid: None,
                subject: format!("scope-{index}"),
                reason: "reason".into(),
                budget: None,
                repeats: 1,
            });
        }
        presentation.budgets.callers_refused = 0;
        presentation.budgets.modules_refused = 0;
        presentation.budgets.edges_refused = 0;
        presentation.budgets.endpoints_refused = refused;
        presentation.gaps_suppressed = suppressed;
        let snapshot = render_snapshot(&presentation);
        snapshot.lines().nth(1).unwrap().to_string()
    };
    assert_eq!(coverage_of(0, 0, 0), "coverage: complete");
    assert_eq!(coverage_of(2, 0, 0), "coverage: partial — 2 gaps");
    assert_eq!(coverage_of(1, 1, 0), "coverage: partial — 1 gap, 1 refused");
    assert_eq!(coverage_of(0, 0, 3), "coverage: partial — 3 more not shown");
    assert_eq!(
        coverage_of(2, 1, 3),
        "coverage: partial — 2 gaps, 1 refused, 3 more not shown"
    );
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
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
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
        let snapshot =
            render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
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
        let snapshot =
            render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
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
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
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
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
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
    let ended = presentation.ended_ns;
    let ago = |then_ns: u64| crate::render::fmt_ns(Some(ended.saturating_sub(then_ns)));
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
            Some("unknown (retired before coverage)".to_string()),
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
            Some(format!("counted exactly for the last {}", ago(10))),
        ),
        (
            0,
            false,
            counted(true),
            MappingState::Mapped,
            "Activity unknown; capture incomplete",
            Some(format!(
                "counted for the last {} (lossy: some records dropped)",
                ago(10)
            )),
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
            Some(format!("no use for the last {}", ago(10))),
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
            Some(format!("no use for 10ns (watch ended {} ago)", ago(20))),
        ),
        (
            0,
            false,
            UseCoverage::Unknown(UnknownReason::PendingFirstUse),
            MappingState::Mapped,
            "Observation pending",
            Some("unknown (first use undecided)".to_string()),
        ),
        (
            0,
            false,
            UseCoverage::Unknown(UnknownReason::ScanOnly),
            MappingState::Mapped,
            "Module mapped; activity not captured",
            Some("unknown (scan only)".to_string()),
        ),
        (
            0,
            false,
            UseCoverage::Unknown(UnknownReason::ScanOnly),
            MappingState::Ended,
            "Activity not captured",
            Some("unknown (scan only)".to_string()),
        ),
        (
            0,
            false,
            UseCoverage::Unknown(UnknownReason::Loss("bad\u{1b}[2J\u{7}\u{9b}\u{7f}".into())),
            MappingState::Mapped,
            "Activity unknown",
            Some("unknown (loss: bad\\u{1b}[2J\\u{7}\\u{9b}\\u{7f})".to_string()),
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
        let label = observation_label_at(&presentation.edges[0], presentation.ended_ns);
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
        let snapshot =
            render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
        let overview = snapshot
            .lines()
            .find(|line| line.starts_with("application "))
            .unwrap_or_else(|| panic!("missing overview:\n{snapshot}"));
        assert!(
            overview.contains(&format!("]: {explanation}")),
            "{overview}"
        );
        if let Some(interval) = interval {
            assert!(overview.contains(interval.as_str()), "{overview}");
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

/// Item 38: a watched edge whose mapping predates the watch discloses
/// the pre-watch window: calls before the watch started are not
/// counted. A zero (unknown) or post-watch first sighting keeps the
/// plain covered-interval line.
#[test]
fn watched_no_use_with_pre_watch_mapping_discloses_window() {
    for (first_seen, expected) in [
        (
            40,
            "No entries observed during the covered interval; mapped at least 60ns before the \
             watch started, earlier calls are not counted",
        ),
        (0, "No entries observed during the covered interval"),
        (100, "No entries observed during the covered interval"),
        (150, "No entries observed during the covered interval"),
    ] {
        let harness = varied_harness();
        let mut presentation = capture_for(&harness, &harness.render());
        presentation.edges.truncate(1);
        let edge = &mut presentation.edges[0];
        edge.entry_count = 0;
        edge.entry_saturated = false;
        edge.coverage = UseCoverage::WatchedNoUse {
            since_ns: 100,
            until_ns: None,
        };
        edge.mapping_first_seen_ns = first_seen;
        let label = observation_label_at(&presentation.edges[0], presentation.ended_ns);
        assert_eq!(label, expected, "first_seen {first_seen}");
    }
}

#[test]
fn snapshot_and_json_agree_on_identities_states_totals_and_gaps() {
    let harness = varied_harness();
    let document = harness.render();
    let presentation = capture_for(&harness, &document);
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    let lines: Vec<&str> = snapshot.lines().collect();

    // Header totals match the document arrays + pass count.
    assert!(
        lines[0].starts_with("inventory workload ("),
        "header: {}",
        lines[0]
    );
    for (label, key) in [
        ("caller", "callers"),
        ("provider file", "modules"),
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
                coverage_label_at(&edge_view.coverage, presentation.ended_ns)
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
        !snapshot.contains("more gaps not shown:"),
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
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
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
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    let line = edge_line(&snapshot, witnessed);
    assert!(line.contains("activity used (recency unknown)"), "{line}");
    assert!(!line.contains("activity quiet"), "{line}");
    let ago = crate::render::fmt_ns(Some(presentation.ended_ns.saturating_sub(now)));
    assert!(
        line.contains(&format!(
            "coverage used, count unavailable (first use {ago} ago)"
        )),
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
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
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
        edge_line(&snapshot, attached).contains(&format!(
            "coverage no use for the last {}",
            crate::render::fmt_ns(Some(presentation.ended_ns.saturating_sub(since)))
        )),
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
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    let ago = crate::render::fmt_ns(Some(presentation.ended_ns.saturating_sub(later)));
    assert!(
        snapshot.contains(&format!(
            "({}) admission history refused->admitted@{ago} ago",
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
    assert_eq!(row["limit"], 32768, "the coordinator's Inventory budget");
    assert_eq!(
        row["occupied"],
        harness.coordinator().attach_set().len(),
        "occupancy is the attach set's endpoint count"
    );
    let presentation = capture_for(&harness, &document);
    assert_eq!(presentation.budgets.inventory_endpoints_limit, 32768);
    assert_eq!(document["budgets"]["inventory_endpoints"]["refused"], 0);
    assert_eq!(
        document["budgets"]["inventory_attach_modules"],
        serde_json::json!({"limit": 32768, "occupied": 0, "refused": 0})
    );
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    let budgets = snapshot
        .lines()
        .find(|line| line.starts_with("budgets: "))
        .unwrap();
    assert!(
        budgets.contains(
            " | inventory_endpoints 0/32768 refused 0 | inventory_attach_modules 0/32768 refused 0 | "
        ),
        "{budgets}"
    );
    assert!(
        budgets.contains(" | semantic 1048896/67108864B peak=1049056 refused=0 | "),
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
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
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
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
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
    const DOC: &str = include_str!("../../docs/schema/inventory-events-v1.md");
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

#[test]
fn f7_snapshot_baseline_preserves_interleaved_children() {
    // Catch a renderer that attaches children to the wrong physical pair,
    // reorders them, or drops unknown, retired, saturated or loss evidence.
    use crate::discovery::caller_registry::instance_input::{
        InstanceLifecycle, RegistryInstanceId,
    };

    let mut harness = harness();
    harness.stage_scale(&ScaleSpec {
        name: "f7-snapshot-baseline",
        callers: 2,
        modules: 2,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 70_000,
    });
    harness.commit();
    let mut presentation = Presentation::capture(harness.coordinator(), "f7", 100, 200, 1);
    for (index, caller) in presentation.callers.iter_mut().enumerate() {
        caller.incarnation = 0;
        caller.exe.as_mut().unwrap().path = Some(format!("/usr/bin/f7-app{index}"));
    }
    for module in &mut presentation.modules {
        module.admission_history.clear();
    }
    for (edge, count) in presentation.edges.iter_mut().zip([34, 55]) {
        edge.entry_count = count;
        edge.entry_observation = "observed";
        edge.coverage = UseCoverage::Counted {
            since_ns: 100,
            lossy: false,
        };
        edge.capture = Capture::Armed;
        edge.activity = Activity::Used;
    }
    for (id, pair, state, returns, saturated, historical, lossy, reasons) in [
        (
            2,
            0,
            InstanceLifecycle::Observed,
            Some(3),
            false,
            0,
            false,
            vec![],
        ),
        (
            7,
            1,
            InstanceLifecycle::Uncertain,
            None,
            false,
            0,
            true,
            vec!["semantic_loss"],
        ),
        (
            11,
            0,
            InstanceLifecycle::Retired,
            Some(5),
            true,
            1,
            true,
            vec!["instance_retired", "semantic_loss"],
        ),
        (
            4095,
            1,
            InstanceLifecycle::Observed,
            Some(0),
            false,
            0,
            false,
            vec![],
        ),
    ] {
        let edge = &presentation.edges[pair];
        let instance = RegistryInstanceId::from_raw(id);
        presentation.instances.push(InstanceView {
            id: instance,
            caller: edge.caller,
            module: edge.module,
            state,
            reason: None,
            first_seen_ns: 100,
            last_seen_ns: 200,
        });
        presentation.semantic_edges.push(InstanceSemanticView {
            instance,
            caller: edge.caller,
            module: edge.module,
            api_returns: returns,
            saturated,
            historical_only_returns: historical,
            semantics: EdgeSemanticsView {
                label: if returns.is_none() {
                    "unknown (no calls observed)"
                } else {
                    "unknown (no operation evidence)"
                },
                mechanisms: Vec::new(),
                operations: None,
            },
            lossy,
            reasons,
        });
    }
    presentation.gaps = vec![GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "fixture scope".into(),
        reason: "semantic state refused".into(),
        budget: Some(BudgetRefusal {
            resource: "semantic_state",
            limit: 4,
            requested: 5,
        }),
        repeats: 1,
    }];
    // Give this renderer-only fixture explicit small budget inputs, rather
    // than coupling its expected bytes to changing production default limits.
    let budgets = &mut presentation.budgets;
    budgets.callers_limit = 2;
    budgets.modules_limit = 2;
    budgets.edges_limit = 2;
    budgets.endpoints_limit = 8;
    budgets.counters_observed = 2;
    budgets.semantic_limit = 4;
    budgets.semantic_refused = 1;
    budgets.instances_occupied = 4;
    budgets.instance_semantic_unknown_edges = 4;
    budgets.retained_limit = 4;
    budgets.retained = 1;
    budgets.inventory_endpoints_limit = 8;
    budgets.inventory_modules_limit = 2;
    budgets.instance_semantic_resources = SemanticResourceView {
        charges: SemanticResourceSnapshot {
            limit_bytes: 4096,
            charged_bytes: 128,
            peak_charged_bytes: 256,
            refused: 1,
        },
        occupancy: S1Occupancy::default(),
    };

    presentation.render_index =
        PresentationRenderIndex::build(&presentation.instances, &presentation.semantic_edges);
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert_eq!(
        snapshot,
        concat!(
            "inventory f7 (1 pass, 2 callers, 2 provider files, 2 edges)\n",
            "coverage: partial — 1 gap\n",
            "key operations: not available — per-key tracking never started, so no key can be named yet (reason: bootstrap_unavailable)\n",
            "application f7-app0 [c0 pid 70000 incarnation 0] -> module m0.so [m0]: At least 34 entries observed\n",
            "application f7-app1 [c1 pid 70001 incarnation 0] -> module m1.so [m1]: At least 55 entries observed\n",
            "Details: retained paths, identities, states and coverage follow.\n",
            "budgets: callers 2/2 refused 0 | modules 2/2 refused 0 | edges 2/2 refused 0 | endpoints 8/8 refused 0 | counters observed 2 saturated 0 | semantic_state withheld held 0/4 unknown 2 refused 1 | retained_history 1/4 suppressed 0 | inventory_endpoints 0/8 refused 0 | inventory_attach_modules 0/2 refused 0 | semantic 128/4096B peak=256 refused=1 | open=0 active=0 pending=0 detached=0 mechanisms=0 categories=0 functions=0 function_bytes=0 function_capacity=0 returns=0 async_bytes=0 async_capacity=0 origins=0 origin_elements=0 origin_capacity=0\n",
            "caller c0 pid 70000 incarnation 0 mapped (/usr/bin/f7-app0)\n",
            "caller c1 pid 70001 incarnation 0 mapped (/usr/bin/f7-app1)\n",
            "module m0 /scale/m0.so mapped (admitted)\n",
            "module m1 /scale/m1.so mapped (admitted)\n",
            "edge c0 -> m0 mapping mapped entries 34 (observed) presence mapped capture armed activity used (recency unknown) semantics unknown (semantic capture withheld) coverage counted exactly for the last 100ns\n",
            "  instance i2 observed api_returns=3 historical_only_returns=0 semantics unknown (no operation evidence) coverage lossy=false reasons=[]\n",
            "  instance i11 retired api_returns=5 (saturated) historical_only_returns=1 semantics unknown (no operation evidence) coverage lossy=true reasons=[instance_retired,semantic_loss]\n",
            "edge c1 -> m1 mapping mapped entries 55 (observed) presence mapped capture armed activity used (recency unknown) semantics unknown (semantic capture withheld) coverage counted exactly for the last 100ns\n",
            "  instance i7 uncertain api_returns=unknown historical_only_returns=0 semantics unknown (no calls observed) coverage lossy=true reasons=[semantic_loss]\n",
            "  instance i4095 observed api_returns=0 historical_only_returns=0 semantics unknown (no operation evidence) coverage lossy=false reasons=[]\n",
            "gap [fixture scope] semantic state refused (budget semantic_state: limit 4, requested 5)\n",
        )
    );
    assert_eq!(snapshot.matches("entries 34 (").count(), 1);
    assert_eq!(snapshot.matches("entries 55 (").count(), 1);
}

/// `--quiet` keeps the summary head (header, coverage, key operations,
/// every application edge) and drops the limits line, the hint and
/// everything from `Details:` on.
#[test]
fn quiet_summary_keeps_the_head_and_drops_details() {
    let harness = varied_harness();
    let presentation = capture_for(&harness, &harness.render());
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(verbose.contains("Details: retained paths"), "{verbose}");
    assert!(verbose.contains("application "), "{verbose}");
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let summary = render_snapshot_summary(&presentation);
    let head: String = concise
        .lines()
        .take_while(|line| !line.starts_with("limits:"))
        .map(|line| format!("{line}\n"))
        .collect();
    assert_eq!(summary, head);
    assert!(summary.contains("application "), "{summary}");
}

/// Empty edges under `--quiet`: the absence line stands alone.
#[test]
fn quiet_summary_on_empty_edges_keeps_the_absence_line() {
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    presentation.edges.clear();
    let summary = render_snapshot_summary(&presentation);
    assert!(
        summary.contains("No application/module associations observed"),
        "{summary}"
    );
    assert!(!summary.contains("Details:"), "{summary}");
}

/// Nested-forwarding inventory twin: a closure-array forwarding layer
/// whose entries each contain one provider entry on the same thread.
/// Provider edges are the logical totals; the forwarding layer is
/// stated separately per layer in text, and JSON keeps both layers
/// explicitly labelled with `layer_totals`.
#[test]
fn forwarding_layer_entries_count_separately_with_per_layer_split() {
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    for module in &mut presentation.modules {
        if module.admission == AdmissionState::Refused {
            module.admission = AdmissionState::Admitted;
        }
    }
    assert!(
        presentation.modules.len() >= 2,
        "the twin needs two modules: {}",
        presentation.modules.len()
    );
    presentation.modules[0].paths = vec!["/opt/libforward.so".into()];
    presentation.modules[0].admission_class = Some("closure_array".into());
    presentation.modules[1].paths = vec!["/opt/libbackend.so".into()];
    presentation.modules[1].admission_class = Some("exact".into());
    let fwd_id = presentation.modules[0].id;
    let prov_id = presentation.modules[1].id;
    for edge in &mut presentation.edges {
        edge.entry_count = 0;
    }
    presentation
        .edges
        .iter_mut()
        .find(|edge| edge.module == fwd_id)
        .expect("a forwarding edge")
        .entry_count = 500;
    presentation
        .edges
        .iter_mut()
        .find(|edge| edge.module == prov_id)
        .expect("a provider edge")
        .entry_count = 744;
    let summary = render_snapshot_summary(&presentation);
    assert!(
        summary.contains("Forwarding-layer entries counted separately"),
        "forwarding split stated in plain words: {summary}"
    );
    assert!(
        summary.contains("/opt/libforward.so") && summary.contains("500"),
        "forwarding layer shown per layer: {summary}"
    );
    let document = crate::inventory::render_json_from_presentation(&presentation);
    let modules = document["modules"].as_array().unwrap();
    let fwd_json = modules
        .iter()
        .find(|module| module["id"] == fwd_id.label())
        .expect("forwarding module JSON");
    assert_eq!(fwd_json["admission"]["class"], "closure_array");
    assert_eq!(document["layer_totals"]["logical_entries"], 744);
    assert_eq!(document["layer_totals"]["forwarding_entries"], 500);
    // Negative control: without the closure class the same entries read
    // as logical and the forwarding line is gone.
    presentation.modules[0].admission_class = Some("exact".into());
    let plain = render_snapshot_summary(&presentation);
    assert!(
        !plain.contains("Forwarding-layer entries counted separately"),
        "no forwarding line without a forwarding layer: {plain}"
    );
    let plain_json = crate::inventory::render_json_from_presentation(&presentation);
    assert_eq!(plain_json["layer_totals"]["logical_entries"], 1244);
    assert_eq!(plain_json["layer_totals"]["forwarding_entries"], 0);
}

/// The inventory forwarding line states the counting rule honestly:
/// provider edges are the logical totals, self-answered layer entries
/// stay in the forwarding line, and multi-provider layer entries count
/// at each — not an exactness claim the code does not have.
#[test]
fn forwarding_entries_line_states_the_counting_rule() {
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    for module in &mut presentation.modules {
        if module.admission == AdmissionState::Refused {
            module.admission = AdmissionState::Admitted;
        }
    }
    assert!(presentation.modules.len() >= 2);
    presentation.modules[0].paths = vec!["/opt/libforward.so".into()];
    presentation.modules[0].admission_class = Some("closure_array".into());
    presentation.modules[1].paths = vec!["/opt/libbackend.so".into()];
    presentation.modules[1].admission_class = Some("exact".into());
    let fwd_id = presentation.modules[0].id;
    let prov_id = presentation.modules[1].id;
    for edge in &mut presentation.edges {
        edge.entry_count = 0;
    }
    presentation
        .edges
        .iter_mut()
        .find(|edge| edge.module == fwd_id)
        .expect("a forwarding edge")
        .entry_count = 500;
    presentation
        .edges
        .iter_mut()
        .find(|edge| edge.module == prov_id)
        .expect("a provider edge")
        .entry_count = 744;
    let summary = render_snapshot_summary(&presentation);
    assert!(
        summary.contains(
            "Provider edges, plus the layer edges of callers that entered no watched provider, are the logical totals; \
             entries a layer answered itself appear only here, \
             and a layer entry that reaches several providers counts at each."
        ),
        "honest counting rule stated: {summary}"
    );
    assert!(
        !summary
            .contains("Each forwarding-layer entry is counted at the provider it forwards into"),
        "no exactness claim beyond the code: {summary}"
    );
    assert!(
        !summary.contains("Each contains one provider entry on the same thread"),
        "no structural nesting claim: {summary}"
    );
}

/// Two callers share a closure-array layer; only one also uses the
/// provider. The closure edge of the provider-active caller splits to
/// forwarding; the closure-only caller's edge stays logical.
#[test]
fn closure_only_caller_edges_stay_logical_beside_an_active_caller() {
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    for module in &mut presentation.modules {
        if module.admission == AdmissionState::Refused {
            module.admission = AdmissionState::Admitted;
        }
    }
    assert!(
        presentation.modules.len() >= 2,
        "the twin needs two modules: {}",
        presentation.modules.len()
    );
    presentation.modules[0].paths = vec!["/opt/libforward.so".into()];
    presentation.modules[0].admission_class = Some("closure_array".into());
    presentation.modules[1].paths = vec!["/opt/libbackend.so".into()];
    presentation.modules[1].admission_class = Some("exact".into());
    let fwd_id = presentation.modules[0].id;
    let prov_id = presentation.modules[1].id;
    let mut callers: Vec<CallerId> = presentation
        .edges
        .iter()
        .filter(|edge| edge.module == fwd_id)
        .map(|edge| edge.caller)
        .collect();
    callers.sort();
    callers.dedup();
    assert!(
        callers.len() >= 2,
        "the twin needs two callers at the layer: {}",
        callers.len()
    );
    for edge in &mut presentation.edges {
        edge.entry_count = 0;
    }
    presentation
        .edges
        .iter_mut()
        .find(|edge| edge.module == fwd_id && edge.caller == callers[0])
        .expect("an active-caller forwarding edge")
        .entry_count = 500;
    presentation
        .edges
        .iter_mut()
        .find(|edge| edge.module == prov_id && edge.caller == callers[0])
        .expect("an active-caller provider edge")
        .entry_count = 744;
    presentation
        .edges
        .iter_mut()
        .find(|edge| edge.module == fwd_id && edge.caller == callers[1])
        .expect("a closure-only forwarding edge")
        .entry_count = 22;
    let summary = render_snapshot_summary(&presentation);
    assert!(
        summary.contains("Forwarding-layer entries counted separately"),
        "forwarding split stated in plain words: {summary}"
    );
    assert!(
        summary.contains("/opt/libforward.so") && summary.contains("500"),
        "forwarding layer shown per layer: {summary}"
    );
    // Concise groups edges per provider, so the layer's module line honestly
    // sums all 522 observed entries; the split itself lives in the
    // forwarding line, which must exclude the closure-only caller's 22.
    let forwarding_line = summary
        .lines()
        .find(|line| line.contains("Forwarding-layer entries counted separately"))
        .expect("forwarding line present");
    assert!(
        !forwarding_line.contains("522"),
        "the closure-only caller's entries are not in the forwarding line: {summary}"
    );
    let document = crate::inventory::render_json_from_presentation(&presentation);
    assert_eq!(document["layer_totals"]["logical_entries"], 766);
    assert_eq!(document["layer_totals"]["forwarding_entries"], 500);
}

/// Lone-layer inventory twin: every edge sits at closure-array modules,
/// so no caller has a provider edge and all entries stay logical.
#[test]
fn lone_forwarding_layer_edges_stay_logical() {
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    assert!(
        presentation.modules.len() >= 2,
        "the twin needs two modules: {}",
        presentation.modules.len()
    );
    presentation.modules[0].paths = vec!["/opt/libforward.so".into()];
    presentation.modules[0].admission_class = Some("closure_array".into());
    presentation.modules[1].paths = vec!["/opt/libother.so".into()];
    presentation.modules[1].admission_class = Some("closure_array".into());
    let fwd_id = presentation.modules[0].id;
    for edge in &mut presentation.edges {
        edge.entry_count = 0;
    }
    presentation
        .edges
        .iter_mut()
        .find(|edge| edge.module == fwd_id)
        .expect("a forwarding edge")
        .entry_count = 22;
    let summary = render_snapshot_summary(&presentation);
    assert!(
        !summary.contains("Forwarding-layer entries counted separately"),
        "no forwarding line without a provider edge: {summary}"
    );
    let document = crate::inventory::render_json_from_presentation(&presentation);
    assert_eq!(document["layer_totals"]["logical_entries"], 22);
    assert_eq!(document["layer_totals"]["forwarding_entries"], 0);
}

/// P1 shape per caller (controller ruling): a caller with a refused
/// backend keeps its layer edges logical even beside an unrelated active
/// provider. A disclosed overcount (697) beats hiding the caller's calls.
#[test]
fn refused_backend_keeps_caller_layer_edges_logical() {
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    let admitted: Vec<crate::discovery::caller_registry::ModuleId> = presentation
        .modules
        .iter()
        .filter(|module| module.admission == AdmissionState::Admitted)
        .map(|module| module.id)
        .collect();
    assert!(
        admitted.len() >= 2,
        "the twin needs two admitted modules: {}",
        admitted.len()
    );
    let refused_id = presentation
        .modules
        .iter()
        .find(|module| module.admission == AdmissionState::Refused)
        .expect("varied harness carries a refused module")
        .id;
    let fwd_id = admitted[0];
    let unrelated_id = admitted[1];
    for module in &mut presentation.modules {
        if module.id == fwd_id {
            module.paths = vec!["/opt/libforward.so".into()];
            module.admission_class = Some("closure_array".into());
        } else if module.id == unrelated_id {
            module.paths = vec!["/opt/libunrelated.so".into()];
            module.admission_class = Some("exact".into());
        } else if module.id == refused_id {
            module.paths = vec!["/opt/libbackend.so".into()];
            module.admission_class = Some("exact".into());
        }
    }
    let caller = presentation
        .edges
        .iter()
        .find(|edge| edge.module == refused_id)
        .expect("an edge to the refused backend")
        .caller;
    for edge in &mut presentation.edges {
        edge.entry_count = 0;
    }
    presentation
        .edges
        .iter_mut()
        .find(|edge| edge.module == fwd_id && edge.caller == caller)
        .expect("the refused caller's layer edge")
        .entry_count = 695;
    presentation
        .edges
        .iter_mut()
        .find(|edge| edge.module == unrelated_id && edge.caller == caller)
        .expect("the refused caller's unrelated provider edge")
        .entry_count = 2;
    let summary = render_snapshot_summary(&presentation);
    assert!(
        !summary.contains("Forwarding-layer entries counted separately"),
        "no forwarding line when the caller's backend is refused: {summary}"
    );
    let document = crate::inventory::render_json_from_presentation(&presentation);
    assert_eq!(
        document["layer_totals"]["logical_entries"], 697,
        "a refused backend keeps the layer logical: {summary}"
    );
    assert_eq!(document["layer_totals"]["forwarding_entries"], 0);
}

#[test]
fn f7_snapshot_high_cardinality_allocation_baseline() {
    // Exercise the real renderer with all 4096 edges/children, rather than
    // timing a toy index or accidentally measuring an empty selection.
    use crate::discovery::caller_registry::instance_input::{
        InstanceLifecycle, RegistryInstanceId,
    };
    let mut harness = harness();
    harness.stage_scale(&ScaleSpec {
        name: "f7-snapshot-scale",
        callers: 4096,
        modules: 4096,
        edges_per_caller: 1,
        endpoints_per_module: 1,
        first_pid: 100_000,
    });
    harness.commit();
    let mut presentation = Presentation::capture(harness.coordinator(), "f7", 100, 200, 1);
    for id in 0..4096 {
        // 17 is coprime to 4096: every physical edge gets exactly one
        // child, interleaved against the globally increasing instance IDs.
        let edge = &presentation.edges[(id * 17) % 4096];
        let instance = RegistryInstanceId::from_raw(id as u32);
        presentation.instances.push(InstanceView {
            id: instance,
            caller: edge.caller,
            module: edge.module,
            state: InstanceLifecycle::Observed,
            reason: None,
            first_seen_ns: 100,
            last_seen_ns: 200,
        });
        presentation.semantic_edges.push(InstanceSemanticView {
            instance,
            caller: edge.caller,
            module: edge.module,
            api_returns: Some(1),
            saturated: false,
            historical_only_returns: 0,
            semantics: EdgeSemanticsView {
                label: "unknown (no operation evidence)",
                mechanisms: Vec::new(),
                operations: None,
            },
            lossy: false,
            reasons: Vec::new(),
        });
    }
    assert_eq!(presentation.edges.len(), 4096);
    assert_eq!(presentation.instances.len(), 4096);
    assert_eq!(presentation.semantic_edges.len(), 4096);
    presentation.render_index =
        PresentationRenderIndex::build(&presentation.instances, &presentation.semantic_edges);
    let (snapshot, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose)
    });
    assert_eq!(
        snapshot
            .lines()
            .filter(|line| line.starts_with("edge "))
            .count(),
        4096
    );
    assert_eq!(
        snapshot
            .lines()
            .filter(|line| line.starts_with("  instance "))
            .count(),
        4096
    );
    assert!(allocations > 0);
    assert!(bytes >= snapshot.len());
    eprintln!(
        "F7 snapshot baseline: edges=4096 children=4096 allocations={allocations} requested_bytes={bytes} output_bytes={}",
        snapshot.len(),
    );
}

#[test]
fn quiet_summary_omits_gap_lines_while_json_keeps_every_gap() {
    // JSON completeness: the concise quiet head drops every `gap [..]`
    // detail line, but the JSON document still carries each retained
    // gap with its exact subject, reason and budget, and the coverage
    // count line agrees with the JSON array length.
    let (mut harness, _caller) = single_caller_harness("present-quiet-json-gaps", 1);
    for (subject, budget) in [
        ("quiet coverage gap", None),
        (
            "quiet budget gap",
            Some(crate::discovery::caller_registry::BudgetRefusal {
                resource: "callers",
                limit: 1,
                requested: 2,
            }),
        ),
    ] {
        harness
            .coordinator_mut()
            .registry_mut()
            .record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: Some(4242),
                subject: subject.into(),
                reason: format!("{subject} reason"),
                budget,
            });
    }
    harness.commit();
    let document = harness.render();
    let presentation = capture_for(&harness, &document);
    assert_eq!(presentation.gaps.len(), 2, "two retained gaps");
    let summary = render_snapshot_summary(&presentation);
    assert!(
        !summary.lines().any(|line| line.starts_with("gap [")),
        "the concise head carries no gap lines:\n{summary}"
    );
    let json = crate::inventory::render_json_from_presentation(&presentation);
    let gaps = json["gaps"].as_array().expect("the JSON gaps array");
    assert_eq!(gaps.len(), 2, "JSON keeps every gap: {json}");
    for view in &presentation.gaps {
        let row = gaps
            .iter()
            .find(|row| row["subject"].as_str() == Some(view.subject.as_str()))
            .unwrap_or_else(|| panic!("missing JSON gap for {}: {json}", view.subject));
        assert_eq!(row["reason"].as_str(), Some(view.reason.as_str()));
        match &view.budget {
            None => assert!(row["budget"].is_null(), "{row}"),
            Some(refusal) => {
                assert_eq!(row["budget"]["resource"].as_str(), Some(refusal.resource));
                assert_eq!(
                    row["budget"]["limit"].as_u64(),
                    Some(refusal.limit as u64),
                    "{row}"
                );
                assert_eq!(
                    row["budget"]["requested"].as_u64(),
                    Some(refusal.requested as u64),
                    "{row}"
                );
            }
        }
    }
    let coverage = summary
        .lines()
        .find(|line| line.starts_with("coverage: "))
        .expect("the quiet head keeps its coverage line");
    assert!(
        coverage.contains("2 gaps"),
        "the count line agrees with JSON: {coverage}"
    );
}

#[test]
fn partial_results_with_gaps_exit_zero_while_a_failed_sink_exits_one() {
    // CLI exit codes: named gaps are partial results, not failures.
    // The same gap-bearing report exits 0 when every sink lands, and
    // 1 only when a sink fails.
    struct FailingStdout;
    impl std::io::Write for FailingStdout {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected stdout failure",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (mut harness, _caller) = single_caller_harness("present-partial-exit", 1);
    harness
        .coordinator_mut()
        .registry_mut()
        .record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: Some(4242),
            subject: "partial coverage gap".into(),
            reason: "partial coverage gap reason".into(),
            budget: None,
        });
    harness.commit();
    let document = harness.render();
    let presentation = capture_for(&harness, &document);
    assert_eq!(presentation.gaps.len(), 1, "one retained gap");
    let mut stdout = Vec::new();
    let ok = crate::inventory::finish_output(
        None,
        &mut crate::inventory::EventLogState::new(None),
        &mut crate::inventory::StreamState::new(),
        &presentation,
        true,
        false,
        &mut crate::inventory_output::WriterStdout(&mut stdout),
        None,
        None,
    );
    assert_eq!(ok.exit_code(), 0, "partial results exit 0");
    assert!(!stdout.is_empty(), "the report actually landed");
    let mut failed_stdout = FailingStdout;
    let failed = crate::inventory::finish_output(
        None,
        &mut crate::inventory::EventLogState::new(None),
        &mut crate::inventory::StreamState::new(),
        &presentation,
        true,
        false,
        &mut crate::inventory_output::WriterStdout(&mut failed_stdout),
        None,
        None,
    );
    assert_eq!(failed.exit_code(), 1, "a failed sink exits 1");
    assert!(
        failed.failures().iter().any(|line| line.contains("stdout")),
        "the failure names its sink: {:?}",
        failed.failures()
    );
}

#[test]
fn flagged_unregistered_mechanism_renders_row_without_name() {
    // Round-2 P2-b: a Detailed unregistered id (VALUE +
    // MECHANISM_UNREGISTERED) admitted by the edge renders an S1
    // mechanism row keyed by the raw id with no name; the inventory
    // JSON layer maps `None` to `null` (`mechanisms_json`).
    use crate::semantics_edge::{EdgeSemantics, SemanticCall};
    use p11scope_ebpf_common::capture;
    let mut edge = EdgeSemantics::default();
    edge.observe(&SemanticCall {
        function: "C_SignInit".into(),
        session: 7,
        mechanism: 0xCE53_43A9,
        capture: capture::MECHANISM_VALUE
            | capture::MECHANISM_UNREGISTERED
            | capture::OUTPUT_NON_NULL,
        ts_ns: 100,
        ..SemanticCall::default()
    });
    let view = super::semantics_view(Some(&edge), false);
    assert_eq!(view.mechanisms.len(), 1);
    let row = &view.mechanisms[0];
    assert_eq!(row.id, 0xCE53_43A9);
    assert_eq!(row.name, None);
    assert_eq!((row.calls, row.errors), (1, 0));
}

/// CLI-1: the concise snapshot keeps the summary head, the limits
/// line and the `-v` hint; the `Details:` tail is verbose-only.
#[test]
fn concise_snapshot_keeps_head_limits_and_hint() {
    let harness = varied_harness();
    let presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(out.contains("inventory workload ("), "{out}");
    assert!(out.contains("coverage: "), "{out}");
    assert!(out.contains("key operations: "), "{out}");
    assert!(out.contains("limits:"), "{out}");
    assert!(out.contains("Full budget detail: -v or --json."), "{out}");
    assert!(!out.contains("budgets:"), "{out}");
    assert!(!out.contains("Details:"), "{out}");
    assert!(!out.contains("gap ["), "{out}");
    assert!(out.contains(crate::cli::VERBOSE_HINT), "{out}");
}

/// F1: the concise snapshot groups gap reasons with counts, so a
/// partial result names WHY (two distinct reasons both appear);
/// per-gap `gap [` lines stay verbose-only.
#[test]
fn concise_snapshot_groups_gap_reasons_with_counts() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "Joint key operations unavailable; retained S1".into(),
        reason: "joint_birth_unoffered".into(),
        budget: None,
        repeats: 1,
    });
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "fixture scope".into(),
        reason: "fixture reason".into(),
        budget: None,
        repeats: 1,
    });
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(out.contains("coverage: partial"), "{out}");
    // Both plain reasons appear with counts; no per-gap flood.
    assert!(
        out.contains("no key session was offered to track"),
        "first gap reason missing: {out}"
    );
    assert!(
        out.contains("fixture reason"),
        "second gap reason missing: {out}"
    );
    assert!(!out.contains("gap ["), "{out}");
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(verbose.contains("gap ["), "{verbose}");
}

/// F1+F3: the concise gap summary uses plain words for the Joint
/// seal/fallback/journal gaps, never the raw `S1` / `joint_*` tokens.
#[test]
fn concise_gap_summary_uses_plain_words_for_joint_gaps() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    for reason in [
        "joint_seal_h3_loss_history_loss",
        "joint_fallback_staging_full",
        "joint_journal_unavailable",
    ] {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: None,
            subject: if reason == "joint_journal_unavailable" {
                "per-key tracking is off; this capture keeps S1 mechanisms and API results".into()
            } else {
                "Joint key operations unavailable; retained S1".into()
            },
            reason: reason.into(),
            budget: None,
            repeats: 1,
        });
    }
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    // Plain reasons stay intact on their group lines.
    for plain in [
        "per-key tracking ended early",
        "per-key tracking fell back to plain counts",
        "per-key tracking is off in this run",
    ] {
        assert!(out.contains(plain), "{plain} missing: {out}");
    }
    // Long plain subjects truncate (marked) to hold the 100-char cap;
    // verbose and JSON keep them whole.
    for stem in [
        "Per-key tracking did not start",
        "per-key tracking is off; function",
    ] {
        assert!(out.contains(stem), "{stem} missing: {out}");
    }
    let lines: Vec<&str> = out.lines().collect();
    let start = lines
        .iter()
        .position(|line| *line == "gaps: 3")
        .expect("gaps header");
    for line in &lines[start..start + 4] {
        assert!(
            line.chars().count() <= 100,
            "over 100 chars: {line:?}:\n{out}"
        );
    }
    for machine in [
        "joint_seal_",
        "joint_fallback_",
        "joint_journal_unavailable",
        "keeps S1",
    ] {
        assert!(!out.contains(machine), "{machine} leaked: {out}");
    }
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    for full in [
        "Per-key tracking did not start for this process; function counts above are unaffected",
        "per-key tracking is off; function and mechanism counts are unaffected",
    ] {
        assert!(verbose.contains(full), "{full} missing: {verbose}");
    }
}

/// F1: the readable gaps block lists every group on its own indented
/// line under `gaps: N` while the group count stays within the fold
/// boundary (twenty; beyond that the block folds, pinned by
/// `gaps_block_folds_beyond_twenty_groups`).
#[test]
fn concise_gap_summary_lists_small_groups_without_fold() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    for (subject, reason) in [
        ("scope-a", "reason-a"),
        ("scope-b", "reason-b"),
        ("scope-c", "reason-c"),
        ("scope-d", "reason-d"),
    ] {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: None,
            subject: subject.into(),
            reason: reason.into(),
            budget: None,
            repeats: 1,
        });
    }
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let lines: Vec<&str> = out.lines().collect();
    let start = lines
        .iter()
        .position(|line| *line == "gaps: 4")
        .expect("gaps header");
    let block = &lines[start..start + 5];
    assert_eq!(
        block,
        &[
            "gaps: 4",
            "  1 × scope-a — reason-a",
            "  1 × scope-b — reason-b",
            "  1 × scope-c — reason-c",
            "  1 × scope-d — reason-d",
        ],
        "{out}"
    );
    assert!(
        !block.iter().any(|line| line.contains("more")),
        "nothing folds: {block:?}"
    );
    assert!(!out.contains("gap ["), "{out}");
}

/// CLI-1: the concise limits line uses singular nouns for counts of
/// one (a 1×1×1 capture reads "1 caller", never "1 callers").
#[test]
fn concise_limits_line_uses_singular_nouns_for_one() {
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "present-limits-singular",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 73_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let presentation = Presentation::capture(harness.coordinator(), "workload", 1, 1, 1);
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let limits = out
        .lines()
        .find(|line| line.starts_with("limits:"))
        .unwrap_or_else(|| panic!("no limits line: {out}"));
    assert!(
        limits.starts_with("limits: 1 caller, 1 provider file, 1 edge (0 refused);"),
        "{limits}"
    );
    assert!(limits.contains("function"), "{limits}");
    assert!(!limits.contains("callers"), "{limits}");
    assert!(!limits.contains("files"), "{limits}");
    assert!(!limits.contains("edges"), "{limits}");
}

/// CLI-1: the verbose snapshot keeps the full `Details:` tail and no hint.
#[test]
fn verbose_snapshot_keeps_details_without_hint() {
    let harness = varied_harness();
    let presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(out.contains("Details:"), "{out}");
    assert!(out.contains("budgets:"), "{out}");
    assert!(!out.contains(crate::cli::VERBOSE_HINT), "{out}");
}

/// CLI-1: the quiet snapshot is the summary head, identical to the
/// `--quiet` direct entry, with no hint.
#[test]
fn quiet_snapshot_matches_summary_head_without_hint() {
    let harness = varied_harness();
    let presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Quiet);
    assert_eq!(out, render_snapshot_summary(&presentation));
    assert!(!out.contains(crate::cli::VERBOSE_HINT), "{out}");
}

/// CLI-1/STAT-1: the coverage line carries a COMPLETE verdict when
/// nothing is lost and a PARTIAL verdict with counts otherwise.
#[test]
fn coverage_line_carries_a_complete_or_partial_verdict() {
    let harness = varied_harness();
    let mut clean = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    clean.gaps.clear();
    clean.gaps_suppressed = 0;
    clean.budgets.callers_refused = 0;
    clean.budgets.modules_refused = 0;
    clean.budgets.edges_refused = 0;
    clean.budgets.endpoints_refused = 0;
    let out = render_snapshot_with_verbosity(&clean, crate::cli::TextVerbosity::Concise);
    assert!(out.contains("coverage: complete"), "{out}");
    let varied = varied_harness();
    let mut presentation = Presentation::capture(varied.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "fixture gap".into(),
        reason: "fixture reason".into(),
        budget: None,
        repeats: 1,
    });
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(out.contains("coverage: partial"), "{out}");
    assert!(!out.contains("suppressed"), "{out}");
}

/// Item 13: the scan-identity gap reads in plain words in concise and
/// verbose text; JSON keeps the stored subject/reason.
#[test]
fn concise_gap_summary_uses_plain_words_for_scan_identity_gap() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "exact image authority unavailable".into(),
        reason: "no BPF image identity; scan-lane incarnations by pidfd/start-time with exe-identity exec detection".into(),
        budget: None,
        repeats: 1,
    });
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    // The long plain subject truncates (marked) to hold the 100-char
    // cap; the reason stays intact and verbose keeps the full subject.
    assert!(out.contains("process identity checked from /proc"), "{out}");
    assert!(
        out.contains("some processes were identified from /proc only"),
        "{out}"
    );
    let lines: Vec<&str> = out.lines().collect();
    let start = lines
        .iter()
        .position(|line| *line == "gaps: 1")
        .expect("gaps header");
    for line in &lines[start..start + 2] {
        assert!(
            line.chars().count() <= 100,
            "over 100 chars: {line:?}:\n{out}"
        );
    }
    assert!(!out.contains("exact image authority unavailable"), "{out}");
    assert!(!out.contains("pidfd/start-time"), "{out}");
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        verbose.contains(
            "process identity checked from /proc (PID and start time), not by the kernel"
        ),
        "{verbose}"
    );
}

/// Item 16: the concise limits line counts watched functions against the
/// real inventory endpoint budget, never the registry ceiling.
#[test]
fn concise_limits_line_uses_real_inventory_endpoint_budget() {
    let harness = varied_harness();
    let presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let limits = out
        .lines()
        .find(|line| line.starts_with("limits:"))
        .unwrap_or_else(|| panic!("no limits line: {out}"));
    let budget = presentation.budgets.inventory_endpoints_limit;
    assert!(
        limits.contains(&format!("of {budget}")),
        "limits line must use the inventory budget {budget}: {limits}"
    );
    assert!(!limits.contains("of 1048576"), "{limits}");
}

/// Item 15: concise groups application edges per provider without
/// internal ids; verbose keeps one line per edge with ids.
#[test]
fn concise_groups_edges_per_provider_without_ids() {
    let harness = varied_harness();
    let presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    assert!(presentation.edges.len() > 1, "fixture needs several edges");
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(!out.contains("[c"), "{out}");
    assert!(!out.contains("[m"), "{out}");
    assert!(!out.contains("incarnation"), "{out}");
    assert!(!out.contains(" -> module "), "{out}");
    assert!(
        !out.lines().any(|line| line.starts_with("application ")),
        "{out}"
    );
    for module in &presentation.modules {
        let name = module
            .paths
            .first()
            .map(|p| p.rsplit('/').next().unwrap_or(p))
            .unwrap_or("?");
        assert!(out.contains(name), "provider {name} missing: {out}");
    }
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(verbose.contains("application "), "{verbose}");
    assert!(verbose.contains("incarnation"), "{verbose}");
}

/// Item 31: the limits line counts edges, like the header and JSON —
/// never "links".
#[test]
fn concise_limits_line_counts_edges_not_links() {
    let harness = varied_harness();
    let presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let limits = out
        .lines()
        .find(|line| line.starts_with("limits:"))
        .unwrap_or_else(|| panic!("no limits line: {out}"));
    assert!(limits.contains("edge"), "{limits}");
    assert!(!limits.contains("link"), "{limits}");
}

/// Item 37: deleted mappings read as a notes line, not gaps —
/// never in the gaps block, never forcing PARTIAL; verbose keeps
/// each record.
#[test]
fn concise_deleted_mappings_read_as_notes_not_gaps() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    presentation.budgets.callers_refused = 0;
    presentation.budgets.modules_refused = 0;
    presentation.budgets.edges_refused = 0;
    presentation.budgets.endpoints_refused = 0;
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: Some(11),
        subject: "/usr/lib/libpcre2-8.so (deleted)".into(),
        reason: "deleted mapping".into(),
        budget: None,
        repeats: 1,
    });
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: Some(12),
        subject: "/usr/lib/libfoo.so (deleted)".into(),
        reason: "deleted mapping".into(),
        budget: None,
        repeats: 1,
    });
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "fixture scope".into(),
        reason: "fixture reason".into(),
        budget: None,
        repeats: 1,
    });
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        out.lines().any(|line| line == "coverage: partial — 1 gap"),
        "deleted mappings count as notes, not gaps: {out}"
    );
    let lines: Vec<&str> = out.lines().collect();
    let start = lines
        .iter()
        .position(|line| *line == "gaps: 1")
        .expect("gaps header");
    assert_eq!(
        &lines[start..start + 2],
        &["gaps: 1", "  1 × fixture scope — fixture reason",],
        "the gaps block holds the fixture gap only: {out}"
    );
    assert!(
        out.lines().any(
            |line| line == "notes: 2 unloaded libraries — mapped files were deleted (not loss)"
        ),
        "the notes line discloses the deleted mappings: {out}"
    );
    assert!(!out.contains("libpcre2"), "no per-path groups: {out}");
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(verbose.contains("libpcre2-8.so (deleted)"), "{verbose}");
}

/// Item 37: deleted mappings alone keep coverage complete — the
/// notes line discloses them and no gaps block prints.
#[test]
fn deleted_only_gaps_keep_coverage_complete_with_notes() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    presentation.budgets.callers_refused = 0;
    presentation.budgets.modules_refused = 0;
    presentation.budgets.edges_refused = 0;
    presentation.budgets.endpoints_refused = 0;
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: Some(11),
        subject: "/usr/lib/libpcre2-8.so (deleted)".into(),
        reason: "deleted mapping".into(),
        budget: None,
        repeats: 1,
    });
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        out.lines().any(|line| line == "coverage: complete"),
        "deleted mappings alone keep coverage complete: {out}"
    );
    assert!(
        !out.lines().any(|line| line.starts_with("gaps:")),
        "no gaps block for notes alone: {out}"
    );
    assert!(
        out.lines()
            .any(|line| line == "notes: 1 unloaded library — mapped file was deleted (not loss)"),
        "the notes line discloses the deleted mapping: {out}"
    );
}

const SCOPE_DOCKER_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const SCOPE_POD_UID: &str = "12345678-1234-abcd-9876-1234567890ab";

fn scope_metadata_for(path: &str) -> crate::caller_metadata::presentation::CallerMetadata {
    let bytes = format!("0::/{path}\n").into_bytes();
    let membership = crate::caller_metadata::parse_cgroup_membership(&bytes);
    let now = std::time::Instant::now();
    let sample = crate::caller_metadata::acquisition::UncommittedSample {
        membership,
        validity: crate::caller_metadata::acquisition::SampleValidity::EndpointSampleOnly,
        numeric: crate::caller_metadata::acquisition::NumericAbsence::NamespaceUnresolved,
        started: now,
        ended: now,
    };
    crate::caller_metadata::presentation::CallerMetadata::sampled(1, 10, 20, &sample)
}

/// F10: the concise per-caller scope line names a Docker container with
/// its 12-hex prefix and per-caller entry total, marked as a hint.
#[test]
fn concise_caller_scope_line_names_docker_container() {
    let metadata = scope_metadata_for(&format!("system.slice/docker-{SCOPE_DOCKER_ID}.scope"));
    assert_eq!(
        concise_caller_scope_line("pkcs11-tool", 4242, 17, Some(metadata)).as_deref(),
        Some(
            "caller pkcs11-tool pid 4242: 17 entries observed, container 0123456789ab (docker, cgroup hint)"
        )
    );
}

/// F10: the concise per-caller scope line names a Kubernetes pod with
/// 8-hex pod and 12-hex container prefixes, marked as a hint.
#[test]
fn concise_caller_scope_line_names_pod_and_container() {
    let metadata = scope_metadata_for(&format!(
        "kubepods/burstable/pod{SCOPE_POD_UID}/{SCOPE_DOCKER_ID}"
    ));
    assert_eq!(
        concise_caller_scope_line("gated", 7, 1, Some(metadata)).as_deref(),
        Some(
            "caller gated pid 7: 1 entry observed, pod 12345678 / container 0123456789ab (cgroup hint)"
        )
    );
}

/// F10: host callers and missing metadata print no scope line.
#[test]
fn concise_caller_scope_line_silent_without_label() {
    let host = scope_metadata_for("user.slice/user-1000.slice/session-2.scope");
    assert_eq!(concise_caller_scope_line("tool", 1, 5, Some(host)), None);
    assert_eq!(concise_caller_scope_line("tool", 1, 5, None), None);
}

/// F10: with the opt-in off, concise prints no caller scope lines and
/// verbose caller lines carry no scope suffix.
#[test]
fn concise_opt_off_prints_no_scope_lines() {
    let harness = varied_harness();
    let presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    assert!(
        !presentation.caller_metadata.summary.enabled,
        "fixture must be opt-off"
    );
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        !out.lines().any(|line| line.starts_with("caller ")),
        "{out}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(!verbose.contains(", container "), "{verbose}");
    assert!(!verbose.contains(", pod "), "{verbose}");
}

/// F10: an enabled-but-unavailable metadata frame degrades to no scope
/// lines; the view continues.
#[test]
fn concise_unavailable_metadata_prints_no_scope_lines() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.caller_metadata = crate::caller_metadata::runtime::MetadataFrame::unavailable(
        crate::caller_metadata::presentation::MetadataReason::LookupLimit,
    );
    assert!(presentation.caller_metadata.summary.enabled);
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        !out.lines().any(|line| line.starts_with("caller ")),
        "{out}"
    );
    assert!(out.contains("inventory "), "{out}");
}

/// F10: an enabled frame with labeled rows prints one exact concise
/// scope line per caller with edges, and the verbose Details caller
/// line carries the full-ID suffix. Entry totals are fixed fixture
/// constants (17 and 1), never recomputed with the product's sum, so a
/// forwarding double-count fails this test; the forwarding shape itself
/// is pinned by `concise_scope_totals_skip_forwarding_edges`.
#[test]
fn concise_enabled_frame_prints_scope_lines_and_verbose_suffix() {
    use std::collections::BTreeSet;
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    let docker = scope_metadata_for(&format!("system.slice/docker-{SCOPE_DOCKER_ID}.scope"));
    let pod = scope_metadata_for(&format!(
        "kubepods/burstable/pod{SCOPE_POD_UID}/{SCOPE_DOCKER_ID}"
    ));
    let with_edges: BTreeSet<CallerId> =
        presentation.edges.iter().map(|edge| edge.caller).collect();
    let mut labeled: Vec<(CallerId, &str, u64)> = Vec::new();
    for caller in &presentation.callers {
        if !with_edges.contains(&caller.id) {
            continue;
        }
        let (short, total) = if labeled.is_empty() {
            ("container 0123456789ab (docker, cgroup hint)", 17u64)
        } else {
            ("pod 12345678 / container 0123456789ab (cgroup hint)", 1u64)
        };
        labeled.push((caller.id, short, total));
        if labeled.len() == 2 {
            break;
        }
    }
    assert_eq!(labeled.len(), 2, "fixture must give two callers with edges");
    // Fixed counts: every edge starts at zero, then one edge per labeled
    // caller carries its exact total. No product-sum mirror.
    for edge in &mut presentation.edges {
        edge.entry_count = 0;
    }
    for (id, _, total) in &labeled {
        presentation
            .edges
            .iter_mut()
            .find(|edge| edge.caller == *id)
            .expect("a labeled edge")
            .entry_count = *total;
    }
    let rows: Vec<(
        CallerId,
        crate::caller_metadata::presentation::CallerMetadata,
    )> = labeled
        .iter()
        .enumerate()
        .map(|(index, (id, _, _))| (*id, if index == 0 { docker } else { pod }))
        .collect();
    presentation.caller_metadata = crate::caller_metadata::runtime::MetadataFrame::for_test(&rows);
    assert!(presentation.caller_metadata.summary.enabled);
    let expected: Vec<String> = labeled
        .iter()
        .map(|(id, short, total)| {
            let caller = presentation
                .callers
                .iter()
                .find(|caller| caller.id == *id)
                .unwrap();
            let noun = if *total == 1 { "entry" } else { "entries" };
            format!(
                "caller {} pid {}: {total} {noun} observed, {short}",
                application_label(&presentation, caller.id),
                caller.pid,
            )
        })
        .collect();
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let scope_lines: Vec<&str> = out
        .lines()
        .filter(|line| line.starts_with("caller "))
        .collect();
    assert_eq!(scope_lines, expected, "{out}");
    // The concise count line names the labeled rows and the unlabeled
    // callers with edges (pending by default); sampled host rows would
    // stay silent, but this fixture labels the first two and leaves the
    // rest pending.
    let pending = with_edges.len().saturating_sub(labeled.len());
    let expected_context = if pending > 0 {
        format!("caller context: 2 labeled, {pending} pending (-v for details)")
    } else {
        "caller context: 2 labeled (-v for details)".to_string()
    };
    assert!(
        out.lines().any(|line| line == expected_context),
        "missing concise count line {expected_context:?}\n{out}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    for caller in &presentation.callers {
        let exe = caller
            .exe
            .as_ref()
            .and_then(|exe| exe.path.as_deref())
            .unwrap_or("?");
        let mut expected_line = format!(
            "caller {} pid {} incarnation {} {} ({})",
            caller.id.label(),
            caller.pid,
            caller.incarnation,
            caller.lifecycle.label(),
            escape_controls(exe),
        );
        if labeled.iter().any(|(id, _, _)| *id == caller.id) {
            let suffix = if caller.id == labeled[0].0 {
                format!("container {SCOPE_DOCKER_ID} (docker, cgroup hint)")
            } else {
                format!("pod {SCOPE_POD_UID} / container {SCOPE_DOCKER_ID} (cgroup hint)")
            };
            expected_line.push_str(", ");
            expected_line.push_str(&suffix);
        }
        assert!(
            verbose.lines().any(|line| line == expected_line),
            "missing Details line {expected_line:?}\n{verbose}"
        );
    }
}

/// F10: the same labeled frame flipped to disabled prints no concise
/// scope lines and no verbose suffix: the opt-in gate guards real rows.
#[test]
fn concise_disabled_frame_with_rows_prints_no_scope_lines() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    let docker = scope_metadata_for(&format!("system.slice/docker-{SCOPE_DOCKER_ID}.scope"));
    let pod = scope_metadata_for(&format!(
        "kubepods/burstable/pod{SCOPE_POD_UID}/{SCOPE_DOCKER_ID}"
    ));
    let ids: Vec<CallerId> = presentation
        .callers
        .iter()
        .map(|caller| caller.id)
        .collect();
    assert!(ids.len() >= 2, "fixture must give two callers to label");
    let mut frame = crate::caller_metadata::runtime::MetadataFrame::for_test(&[
        (ids[0], docker),
        (ids[1], pod),
    ]);
    frame.summary.enabled = false;
    presentation.caller_metadata = frame;
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        !out.lines().any(|line| line.starts_with("caller ")),
        "{out}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(!verbose.contains(", container "), "{verbose}");
    assert!(!verbose.contains(", pod "), "{verbose}");
}

/// F10: per-caller scope totals skip forwarding-layer edges. The caller
/// has a 500-entry forwarding edge plus a 744-entry provider edge; the
/// scope line must read 744 (logical), never 1244 (double-count).
#[test]
fn concise_scope_totals_skip_forwarding_edges() {
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    for module in &mut presentation.modules {
        if module.admission == AdmissionState::Refused {
            module.admission = AdmissionState::Admitted;
        }
    }
    assert!(
        presentation.modules.len() >= 2,
        "the twin needs two modules"
    );
    presentation.modules[0].paths = vec!["/opt/libforward.so".into()];
    presentation.modules[0].admission_class = Some("closure_array".into());
    presentation.modules[1].paths = vec!["/opt/libbackend.so".into()];
    presentation.modules[1].admission_class = Some("exact".into());
    let fwd_id = presentation.modules[0].id;
    let prov_id = presentation.modules[1].id;
    let caller = presentation
        .edges
        .iter()
        .filter(|edge| edge.module == fwd_id)
        .map(|edge| edge.caller)
        .find(|caller| {
            presentation
                .edges
                .iter()
                .any(|edge| edge.module == prov_id && edge.caller == *caller)
        })
        .expect("a caller at both layers");
    for edge in &mut presentation.edges {
        edge.entry_count = 0;
    }
    presentation
        .edges
        .iter_mut()
        .find(|edge| edge.module == fwd_id && edge.caller == caller)
        .expect("a forwarding edge")
        .entry_count = 500;
    presentation
        .edges
        .iter_mut()
        .find(|edge| edge.module == prov_id && edge.caller == caller)
        .expect("a provider edge")
        .entry_count = 744;
    let metadata = scope_metadata_for(&format!("system.slice/docker-{SCOPE_DOCKER_ID}.scope"));
    presentation.caller_metadata =
        crate::caller_metadata::runtime::MetadataFrame::for_test(&[(caller, metadata)]);
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let line = out
        .lines()
        .find(|line| line.starts_with("caller "))
        .expect("one scope line for the labeled caller");
    assert!(
        line.contains("744 entries observed"),
        "logical total only: {line}"
    );
    assert!(!line.contains("1244"), "no forwarding double-count: {line}");
    assert!(
        line.contains("container 0123456789ab (docker, cgroup hint)"),
        "hint-marked label: {line}"
    );
}

/// F10: the concise count line names labeled, unknown and pending
/// callers with edges (nonzero parts only); unknown/pending rows print
/// no scope line but never vanish silently.
#[test]
fn concise_count_line_names_unknown_and_pending() {
    use std::collections::BTreeSet;
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    let with_edges: BTreeSet<CallerId> =
        presentation.edges.iter().map(|edge| edge.caller).collect();
    assert!(
        with_edges.len() >= 3,
        "fixture must give three callers with edges: {}",
        with_edges.len()
    );
    let ids: Vec<CallerId> = presentation
        .callers
        .iter()
        .map(|caller| caller.id)
        .filter(|id| with_edges.contains(id))
        .collect();
    let labeled = scope_metadata_for(&format!("system.slice/docker-{SCOPE_DOCKER_ID}.scope"));
    let unknown = crate::caller_metadata::presentation::CallerMetadata::unknown(
        crate::caller_metadata::presentation::MetadataReason::ReadFailed,
        2,
    );
    presentation.caller_metadata = crate::caller_metadata::runtime::MetadataFrame::for_test(&[
        (ids[0], labeled),
        (ids[1], unknown),
    ]);
    // ids[2..] have edges but no row, so they read pending.
    let pending = with_edges.len() - 2;
    assert!(pending >= 1, "fixture must leave a pending caller");
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let scope_lines: Vec<&str> = out
        .lines()
        .filter(|line| line.starts_with("caller "))
        .collect();
    assert_eq!(
        scope_lines.len(),
        1,
        "only the labeled caller prints: {out}"
    );
    let expected =
        format!("caller context: 1 labeled, 1 unknown, {pending} pending (-v for details)");
    assert!(
        out.lines().any(|line| line == expected),
        "missing count line {expected:?}\n{out}"
    );
}

/// F10: stale and historical rows keep their hints in concise scope
/// lines but never print as current: stale appends `, stale` and
/// retired rows append `, exited`.
#[test]
fn concise_stale_and_historical_scope_lines_mark_status() {
    use std::collections::BTreeSet;
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    let with_edges: BTreeSet<CallerId> =
        presentation.edges.iter().map(|edge| edge.caller).collect();
    let ids: Vec<CallerId> = presentation
        .callers
        .iter()
        .map(|caller| caller.id)
        .filter(|id| with_edges.contains(id))
        .collect();
    assert!(ids.len() >= 2, "fixture must give two callers with edges");
    let healthy = scope_metadata_for(&format!("system.slice/docker-{SCOPE_DOCKER_ID}.scope"));
    presentation.caller_metadata = crate::caller_metadata::runtime::MetadataFrame::for_test(&[
        (ids[0], healthy.to_stale()),
        (ids[1], healthy.to_historical()),
    ]);
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let scope_lines: Vec<&str> = out
        .lines()
        .filter(|line| line.starts_with("caller "))
        .collect();
    assert_eq!(scope_lines.len(), 2, "{out}");
    assert!(
        scope_lines[0].contains("(docker, cgroup hint, stale)"),
        "stale marked: {}",
        scope_lines[0]
    );
    assert!(
        scope_lines[1].contains("(docker, cgroup hint, exited)"),
        "retired marked: {}",
        scope_lines[1]
    );
}

/// F10: concise scope lines cap at eight; the overflow names its count
/// while the count line still reports the full labeled total.
#[test]
fn concise_scope_lines_cap_at_eight() {
    let mut harness = harness();
    harness.stage_scale(&ScaleSpec {
        name: "f10-cap",
        callers: 10,
        modules: 2,
        edges_per_caller: 1,
        endpoints_per_module: 1,
        first_pid: 80_000,
    });
    harness.commit();
    let mut presentation = Presentation::capture(harness.coordinator(), "f10-cap", 1, 2, 1);
    assert_eq!(presentation.edges.len(), 10, "one edge per caller");
    let metadata = scope_metadata_for(&format!("system.slice/docker-{SCOPE_DOCKER_ID}.scope"));
    let rows: Vec<(
        CallerId,
        crate::caller_metadata::presentation::CallerMetadata,
    )> = presentation
        .callers
        .iter()
        .map(|caller| (caller.id, metadata))
        .collect();
    assert_eq!(rows.len(), 10, "ten callers to label");
    presentation.caller_metadata = crate::caller_metadata::runtime::MetadataFrame::for_test(&rows);
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let scope_lines: Vec<&str> = out
        .lines()
        .filter(|line| line.starts_with("caller "))
        .collect();
    assert_eq!(scope_lines.len(), 8, "eight printed scope lines: {out}");
    assert!(
        out.lines()
            .any(|line| line == "and 2 more labeled callers (-v or --json)"),
        "overflow line names its count: {out}"
    );
    assert!(
        out.lines()
            .any(|line| line == "caller context: 10 labeled (-v for details)"),
        "count line reports the full total: {out}"
    );
}

/// F10: quiet output with labeled rows prints no scope lines and no
/// caller-context count line: concise-only content stays out of quiet.
#[test]
fn quiet_with_labeled_rows_prints_no_scope_lines() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    let metadata = scope_metadata_for(&format!("system.slice/docker-{SCOPE_DOCKER_ID}.scope"));
    let rows: Vec<(
        CallerId,
        crate::caller_metadata::presentation::CallerMetadata,
    )> = presentation
        .callers
        .iter()
        .map(|caller| (caller.id, metadata))
        .collect();
    assert!(!rows.is_empty(), "fixture must give callers to label");
    presentation.caller_metadata = crate::caller_metadata::runtime::MetadataFrame::for_test(&rows);
    assert!(presentation.caller_metadata.summary.enabled);
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Quiet);
    assert!(
        !out.lines().any(|line| line.starts_with("caller ")),
        "quiet carries no scope lines: {out}"
    );
    assert!(
        !out.lines().any(|line| line.starts_with("caller context:")),
        "quiet carries no count line: {out}"
    );
    assert!(
        !out.lines().any(|line| line.starts_with("and ")),
        "quiet carries no overflow line: {out}"
    );
}

/// F10: a labeled caller without edges prints no scope line; the view
/// degrades to the provider lines plus the labeled count of zero.
#[test]
fn concise_edge_less_labeled_caller_prints_no_scope_line() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.edges.clear();
    let metadata = scope_metadata_for(&format!("system.slice/docker-{SCOPE_DOCKER_ID}.scope"));
    let ids: Vec<CallerId> = presentation
        .callers
        .iter()
        .map(|caller| caller.id)
        .collect();
    assert!(!ids.is_empty(), "fixture must give callers to label");
    presentation.caller_metadata =
        crate::caller_metadata::runtime::MetadataFrame::for_test(&[(ids[0], metadata)]);
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        !out.lines().any(|line| line.starts_with("caller ")),
        "edge-less labeled caller stays silent: {out}"
    );
    assert!(
        !out.lines().any(|line| line.starts_with("caller context:")),
        "no callers with edges means no count line: {out}"
    );
}
