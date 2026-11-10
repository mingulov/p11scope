//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! U0 presentation tests: ONE model for JSON and snapshots (A1/A2),
//! exact dashboard vocabulary with its distinctions (B2), and the
//! withheld semantic column (B3). JSON-vs-snapshot agreement is pinned
//! by parsing, not eyeballing.

use super::*;
use crate::discovery::caller_registry::{
    AdmissionChange, AdmissionState, CallerId, CoverageNote, ExeResolution, ImageAuthority,
    ModuleInfo, ModuleKey, RegistryGap, RegistryLimits, UnboundExe, UnboundPid, UnknownReason,
    UseCoverage,
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

/// The `-v` launcher chain names the chain per caller; the concise
/// default shows one hop beside the caller; JSON carries generations.
#[test]
fn launcher_chain_renders_verbose_chain_and_concise_hop() {
    use crate::discovery::caller_registry::{LauncherAncestor, LauncherOrigin};
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    presentation.callers[0].exe.as_mut().unwrap().path = Some("/usr/bin/pkcs11-tool".into());
    presentation.callers[0].launched_by = vec![
        LauncherAncestor {
            pid: 900,
            start_time: Some(90),
            exe: Some("sh".into()),
            label: None,
            exe_gap: None,
        },
        LauncherAncestor {
            pid: 800,
            start_time: Some(80),
            exe: Some("cron".into()),
            label: None,
            exe_gap: None,
        },
    ];
    presentation.callers[0].launcher_gap = None;
    presentation.callers[0].launched_by_origin = LauncherOrigin::Chain;
    presentation.callers[0].launched_by_unit = None;
    let id = presentation.callers[0].id;
    assert_eq!(
        launcher_chain_text(&presentation, id).as_deref(),
        Some("pkcs11-tool <- sh <- cron")
    );
    assert_eq!(
        caller_origin_suffix(&presentation, id).as_deref(),
        Some(" (from sh)")
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        verbose.contains("  pkcs11-tool <- sh <- cron\n"),
        "{verbose}"
    );
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(concise.contains("pkcs11-tool (from sh)"), "{concise}");
    let out = crate::inventory::render_json_from_presentation(&presentation);
    let row = out["callers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == id.label())
        .unwrap();
    assert_eq!(row["launched_by"][0]["pid"], 900);
    assert_eq!(row["launched_by"][0]["start_time"], 90);
    assert_eq!(row["launched_by"][1]["exe"], "cron");
    assert_eq!(row["launched_by_origin"], "chain");
    assert!(row["launched_by_unit"].is_null());
    assert!(row["launched_by_gap"].is_null());
}

/// Repeated identical wrappers collapse in -v and JSON; an init-only
/// parent shows its unit in both texts and JSON.
#[test]
fn launcher_chain_collapses_wrappers_and_shows_init_parent_units() {
    use crate::discovery::caller_registry::{LauncherAncestor, LauncherOrigin};
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    presentation.callers[0].exe.as_mut().unwrap().path = Some("/usr/bin/pkcs11-tool".into());
    presentation.callers[0].launched_by = vec![
        LauncherAncestor {
            pid: 900,
            start_time: Some(90),
            exe: Some("sh".into()),
            label: None,
            exe_gap: None,
        },
        LauncherAncestor {
            pid: 890,
            start_time: Some(89),
            exe: Some("sh".into()),
            label: None,
            exe_gap: None,
        },
        LauncherAncestor {
            pid: 800,
            start_time: Some(80),
            exe: Some("cron".into()),
            label: None,
            exe_gap: None,
        },
    ];
    presentation.callers[0].launcher_gap = None;
    presentation.callers[0].launched_by_origin = LauncherOrigin::Chain;
    presentation.callers[0].launched_by_unit = None;
    presentation.callers[1].exe.as_mut().unwrap().path = Some("/usr/bin/svc-tool".into());
    presentation.callers[1].launched_by = vec![];
    presentation.callers[1].launcher_gap = None;
    presentation.callers[1].launched_by_origin = LauncherOrigin::InitParent;
    presentation.callers[1].launched_by_unit = Some("backup.service".into());
    let folded = presentation.callers[0].id;
    let unit = presentation.callers[1].id;
    assert_eq!(
        launcher_chain_text(&presentation, folded).as_deref(),
        Some("pkcs11-tool <- sh (×2) <- cron")
    );
    assert_eq!(
        caller_origin_suffix(&presentation, unit).as_deref(),
        Some(" (from backup.service)")
    );
    assert_eq!(
        launcher_chain_text(&presentation, unit).as_deref(),
        Some("svc-tool (from backup.service)")
    );
    let out = crate::inventory::render_json_from_presentation(&presentation);
    let rows = out["callers"].as_array().unwrap();
    let row = rows.iter().find(|row| row["id"] == folded.label()).unwrap();
    assert_eq!(row["launched_by"].as_array().unwrap().len(), 2);
    assert_eq!(row["launched_by"][0]["exe"], "sh");
    assert_eq!(row["launched_by"][0]["folded"], 1);
    assert!(row["launched_by"][1].get("folded").is_none());
    let urow = rows.iter().find(|row| row["id"] == unit.label()).unwrap();
    assert_eq!(urow["launched_by_origin"], "init_parent");
    assert_eq!(urow["launched_by_unit"], "backup.service");
    assert!(urow["launched_by_gap"].is_null());
}

/// A partial chain keeps the gap beside it; an init parent without a
/// unit, a missing chain and a gap-only record print no hop; gap-only
/// detail stays in JSON. An unreadable ancestor exe carries its named
/// gap in JSON while text shows the honest pid.
#[test]
fn launcher_chain_suppresses_roots_and_keeps_partial_gaps() {
    use crate::discovery::caller_registry::{
        LAUNCHER_GAP_EXE_UNREADABLE, LAUNCHER_GAP_EXITED, LAUNCHER_GAP_SUBJECT, LauncherAncestor,
        LauncherGap, LauncherOrigin,
    };
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    presentation.callers[0].exe.as_mut().unwrap().path = Some("/usr/bin/pkcs11-tool".into());
    presentation.callers[0].launched_by = vec![LauncherAncestor {
        pid: 900,
        start_time: Some(90),
        exe: None,
        label: None,
        exe_gap: Some(LAUNCHER_GAP_EXE_UNREADABLE),
    }];
    presentation.callers[0].launcher_gap = Some(LauncherGap {
        subject: LAUNCHER_GAP_SUBJECT,
        reason: LAUNCHER_GAP_EXITED.into(),
    });
    presentation.callers[0].launched_by_origin = LauncherOrigin::Chain;
    presentation.callers[0].launched_by_unit = None;
    presentation.callers[1].exe.as_mut().unwrap().path = Some("/usr/bin/other".into());
    presentation.callers[1].launched_by = vec![];
    presentation.callers[1].launcher_gap = None;
    presentation.callers[1].launched_by_origin = LauncherOrigin::InitParent;
    presentation.callers[1].launched_by_unit = None;
    presentation.callers[2].launcher_gap = Some(LauncherGap {
        subject: LAUNCHER_GAP_SUBJECT,
        reason: LAUNCHER_GAP_EXITED.into(),
    });
    presentation.callers[2].launched_by_origin = LauncherOrigin::Gap;
    presentation.callers[2].launched_by_unit = None;
    let partial = presentation.callers[0].id;
    let rooted = presentation.callers[1].id;
    let gap_only = presentation.callers[2].id;
    assert_eq!(
        launcher_chain_text(&presentation, partial).as_deref(),
        Some("pkcs11-tool <- pid 900 <- ? (launcher exited before read)")
    );
    assert_eq!(
        caller_origin_suffix(&presentation, partial),
        None,
        "concise shows named links only; `pid N` stays in -v/JSON"
    );
    assert_eq!(launcher_chain_text(&presentation, gap_only), None);
    assert_eq!(launcher_chain_text(&presentation, rooted), None);
    assert_eq!(caller_origin_suffix(&presentation, rooted), None);
    assert_eq!(caller_origin_suffix(&presentation, gap_only), None);
    let out = crate::inventory::render_json_from_presentation(&presentation);
    let rows = out["callers"].as_array().unwrap();
    let prow = rows
        .iter()
        .find(|row| row["id"] == partial.label())
        .unwrap();
    assert_eq!(
        prow["launched_by"][0]["exe_gap"],
        LAUNCHER_GAP_EXE_UNREADABLE
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        verbose.contains("  pkcs11-tool <- pid 900 <- ? (launcher exited before read)\n"),
        "{verbose}"
    );
    assert!(
        !verbose.contains("other <- "),
        "init_parent without a unit shows no chain: {verbose}"
    );
    assert!(
        !verbose.contains("launcher chain unknown"),
        "gap-only detail stays in JSON: {verbose}"
    );
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(!concise.contains("(from pid 900)"), "{concise}");
    assert!(concise.contains("pkcs11-tool"), "{concise}");
    assert!(concise.contains("other"), "{concise}");
    assert!(
        !concise.contains("(from systemd)"),
        "no hop beside an init-parent caller: {concise}"
    );
    let out = crate::inventory::render_json_from_presentation(&presentation);
    let row = out["callers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == gap_only.label())
        .unwrap();
    assert!(row["launched_by"].as_array().unwrap().is_empty());
    assert_eq!(row["launched_by_gap"]["subject"], LAUNCHER_GAP_SUBJECT);
    assert_eq!(row["launched_by_gap"]["reason"], LAUNCHER_GAP_EXITED);
}

/// Concise shows named links and `.service` units only: nameless
/// links (`pid N`) and scopes/transient units stay in `-v`/JSON.
#[test]
fn launcher_chain_concise_hides_nameless_links_and_non_service_units() {
    use crate::discovery::caller_registry::{
        LAUNCHER_GAP_EXE_UNREADABLE, LauncherAncestor, LauncherOrigin,
    };
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    presentation.callers[0].exe.as_mut().unwrap().path = Some("/usr/bin/pkcs11-tool".into());
    presentation.callers[0].launched_by = vec![LauncherAncestor {
        pid: 900,
        start_time: Some(90),
        exe: None,
        label: None,
        exe_gap: Some(LAUNCHER_GAP_EXE_UNREADABLE),
    }];
    presentation.callers[0].launcher_gap = None;
    presentation.callers[0].launched_by_origin = LauncherOrigin::Chain;
    presentation.callers[0].launched_by_unit = None;
    presentation.callers[1].exe.as_mut().unwrap().path = Some("/usr/bin/svc-tool".into());
    presentation.callers[1].launched_by = vec![];
    presentation.callers[1].launcher_gap = None;
    presentation.callers[1].launched_by_origin = LauncherOrigin::InitParent;
    presentation.callers[1].launched_by_unit = Some("session-c2.scope".into());
    presentation.callers[2].exe.as_mut().unwrap().path = Some("/usr/bin/other".into());
    presentation.callers[2].launched_by = vec![];
    presentation.callers[2].launcher_gap = None;
    presentation.callers[2].launched_by_origin = LauncherOrigin::InitParent;
    presentation.callers[2].launched_by_unit = Some("backup.service".into());
    let nameless = presentation.callers[0].id;
    let scoped = presentation.callers[1].id;
    let serviced = presentation.callers[2].id;
    assert_eq!(caller_origin_suffix(&presentation, nameless), None);
    assert_eq!(
        launcher_chain_text(&presentation, nameless).as_deref(),
        Some("pkcs11-tool <- pid 900")
    );
    assert_eq!(caller_origin_suffix(&presentation, scoped), None);
    assert_eq!(
        launcher_chain_text(&presentation, scoped).as_deref(),
        Some("svc-tool (from session-c2.scope)")
    );
    assert_eq!(
        caller_origin_suffix(&presentation, serviced).as_deref(),
        Some(" (from backup.service)")
    );
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(!concise.contains("(from pid 900)"), "{concise}");
    assert!(!concise.contains("(from session-c2.scope)"), "{concise}");
    assert!(concise.contains("other (from backup.service)"), "{concise}");
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
        pid_exit: false,
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

/// F4 (11b): the verbose edge names the pre-watch window once, in the
/// observation: the coverage clause does not repeat it. Zero (unknown)
/// or post-watch sightings keep the plain "no use" line.
#[test]
fn verbose_edge_names_pre_watch_window_once() {
    for (first_seen, discloses) in [(40u64, true), (0, false), (100, false), (150, false)] {
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
        let snapshot =
            render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
        let overview = snapshot
            .lines()
            .find(|line| line.starts_with("application "))
            .unwrap_or_else(|| panic!("missing overview:\n{snapshot}"));
        let coverage_part = overview
            .split("; coverage ")
            .nth(1)
            .unwrap_or_else(|| panic!("missing coverage clause:\n{overview}"));
        assert!(
            !coverage_part.contains("mapped at least"),
            "the coverage clause never repeats the window:\n{overview}"
        );
        let mentions = overview.matches("mapped at least").count();
        assert_eq!(
            mentions,
            usize::from(discloses),
            "the window is named exactly once:\n{overview}"
        );
    }
}

/// F4: concise module status names the pre-watch window, never a
/// bare "no use in the covered interval" when calls before the
/// watch were missed. Zero (unknown) or post-watch sightings keep
/// the plain line.
#[test]
fn concise_module_status_names_pre_watch_window() {
    for (first_seen, discloses) in [(40u64, true), (0, false), (100, false), (150, false)] {
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
        let snapshot =
            render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
        let line = snapshot
            .lines()
            .find(|line| line.contains("mapped by 1 application"))
            .unwrap_or_else(|| panic!("missing concise module line:\n{snapshot}"));
        if discloses {
            assert!(
                line.contains("mapped at least 60ns before the watch started"),
                "concise names the window:\n{line}"
            );
            assert!(
                line.contains("earlier calls are not counted"),
                "concise names the miss:\n{line}"
            );
        } else {
            assert!(
                !line.contains("mapped at least"),
                "no window without a pre-watch mapping:\n{line}"
            );
        }
    }
}

/// F4: concise module status counts pre-watch mappings across the
/// group's edges, never a bare "no use in the covered interval" when
/// some mapping predates the watch.
#[test]
fn concise_module_status_counts_pre_watch_mappings_across_edges() {
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    presentation.edges.truncate(2);
    assert_eq!(presentation.edges.len(), 2);
    let module = presentation.edges[0].module;
    for edge in &mut presentation.edges {
        edge.module = module;
        edge.entry_count = 0;
        edge.entry_saturated = false;
        edge.coverage = UseCoverage::WatchedNoUse {
            since_ns: 100,
            until_ns: None,
        };
    }
    presentation.edges[0].mapping_first_seen_ns = 40;
    presentation.edges[1].mapping_first_seen_ns = 150;
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let line = snapshot
        .lines()
        .find(|line| line.contains("predate the watch"))
        .unwrap_or_else(|| panic!("missing multi-edge pre-watch line:\n{snapshot}"));
    assert!(
        line.contains("1 of 2 mappings predate the watch"),
        "concise counts the pre-watch mappings:\n{line}"
    );
    assert!(
        line.contains("earlier calls are not counted"),
        "concise names the miss:\n{line}"
    );
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
        budgets.contains(" | semantic 1048896/167772160B peak=1049056 refused=0 | "),
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
        pid_exit: false,
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

// v070-event-stdout pins: `docs/schema/inventory-events-v1.md` states the
// `--event-log -` stdout transport (same lines, no rotation, bounded
// shed with counters, summary to stderr) and the additive `totals`
// kind (`--event-interval`) with its `stdout_lost` accounting.
#[test]
fn event_doc_pins_stdout_transport_and_totals_kind() {
    const DOC: &str = include_str!("../../docs/schema/inventory-events-v1.md");
    assert!(
        DOC.contains("`--event-log -` streams")
            && DOC.contains("never rotated")
            && DOC.contains("shed with counters"),
        "the stdout transport contract is stated"
    );
    assert!(
        DOC.contains("the text summary moves to stderr"),
        "the stdout ownership rule is stated"
    );
    assert!(
        DOC.contains("`totals`")
            && DOC.contains("`--event-interval`")
            && DOC.contains("`stdout_lost`"),
        "the additive totals kind and its loss accounting are stated"
    );
    assert!(
        DOC.contains("phase-locked to actual emissions"),
        "the no-burst cadence rule is stated"
    );
    // A shed that leaves a partial line is repaired with a newline,
    // so the delivered head is a fragment line that does not parse
    // as JSON: consumers must skip such lines.
    assert!(
        DOC.contains("does not parse as JSON")
            && DOC.contains("shed fragment")
            && DOC.contains("skip it"),
        "the shed-fragment skip rule is stated"
    );
    const USAGE: &str = include_str!("../../docs/usage.md");
    assert!(
        USAGE.contains("does not parse as JSON")
            && USAGE.contains("shed fragment")
            && USAGE.contains("skip it"),
        "usage states the shed-fragment skip rule"
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
            pid_exit: false,
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

/// Declared-forwarding inventory twin: a single-table shim (pkcs11-spy
/// shape — corroborated, never a closure array) the operator named with
/// `--forwarding-module` splits exactly like a closure layer under the
/// same per-caller gates.
#[test]
fn declared_forwarding_edges_count_separately() {
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
    presentation.modules[0].paths = vec!["/opt/libshim.so".into()];
    presentation.modules[0].admission_class = Some("exact".into());
    presentation.modules[0].operator_forwarding = true;
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
        summary.contains("/opt/libshim.so") && summary.contains("500"),
        "declared layer shown per layer: {summary}"
    );
    let document = crate::inventory::render_json_from_presentation(&presentation);
    assert_eq!(document["layer_totals"]["logical_entries"], 744);
    assert_eq!(document["layer_totals"]["forwarding_entries"], 500);
    // Negative control: without the declaration the same entries read
    // as logical and the forwarding line is gone.
    presentation.modules[0].operator_forwarding = false;
    let plain = render_snapshot_summary(&presentation);
    assert!(
        !plain.contains("Forwarding-layer entries counted separately"),
        "no forwarding line without a declaration: {plain}"
    );
    let plain_json = crate::inventory::render_json_from_presentation(&presentation);
    assert_eq!(plain_json["layer_totals"]["logical_entries"], 1244);
    assert_eq!(plain_json["layer_totals"]["forwarding_entries"], 0);
}

/// Declared-gate twin: a declared layer beside a refused backend keeps
/// its edges logical for that caller — a disclosed overcount beats
/// hiding the caller's entries.
#[test]
fn declared_layer_with_refused_backend_stays_logical() {
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    presentation.modules[0].paths = vec!["/opt/libshim.so".into()];
    presentation.modules[0].admission_class = Some("exact".into());
    presentation.modules[0].operator_forwarding = true;
    presentation.modules[1].paths = vec!["/opt/libbackend.so".into()];
    presentation.modules[1].admission_class = Some("exact".into());
    presentation.modules[1].admission = AdmissionState::Refused;
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
    let (logical, forwarding) = layer_entry_totals(&presentation);
    assert_eq!(logical, 1244, "a refused backend keeps the layer logical");
    assert_eq!(forwarding, 0);
}

/// Coincidence hint: one caller with exactly equal entries at two
/// attached non-layer modules gets a text hint naming both modules and
/// the `--forwarding-module` remedy. Advisory only — totals never move.
#[test]
fn coincident_entries_suggest_forwarding_flag() {
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    for module in &mut presentation.modules {
        if module.admission == AdmissionState::Refused {
            module.admission = AdmissionState::Admitted;
        }
    }
    presentation.modules[0].paths = vec!["/opt/libshim.so".into()];
    presentation.modules[0].admission_class = Some("exact".into());
    presentation.modules[1].paths = vec!["/opt/libbackend.so".into()];
    presentation.modules[1].admission_class = Some("exact".into());
    let fwd_id = presentation.modules[0].id;
    let prov_id = presentation.modules[1].id;
    for edge in &mut presentation.edges {
        edge.entry_count = 0;
    }
    // One caller with exactly equal entries at both modules.
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
        .expect("a caller with edges to both modules");
    presentation
        .edges
        .iter_mut()
        .find(|edge| edge.module == fwd_id && edge.caller == caller)
        .expect("the caller forwarding edge")
        .entry_count = 9;
    presentation
        .edges
        .iter_mut()
        .find(|edge| edge.module == prov_id && edge.caller == caller)
        .expect("the caller provider edge")
        .entry_count = 9;
    let summary = render_snapshot_summary(&presentation);
    assert!(
        summary.contains("--forwarding-module"),
        "coincident entries suggest the flag: {summary}"
    );
    assert!(
        summary.contains("/opt/libshim.so") && summary.contains("/opt/libbackend.so"),
        "the hint names both modules: {summary}"
    );
}

/// Hint negative control: unequal entries suggest nothing.
#[test]
fn unequal_entries_suggest_nothing() {
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    for module in &mut presentation.modules {
        if module.admission == AdmissionState::Refused {
            module.admission = AdmissionState::Admitted;
        }
    }
    presentation.modules[0].paths = vec!["/opt/libfirst.so".into()];
    presentation.modules[0].admission_class = Some("exact".into());
    presentation.modules[1].paths = vec!["/opt/libsecond.so".into()];
    presentation.modules[1].admission_class = Some("exact".into());
    let first_id = presentation.modules[0].id;
    let second_id = presentation.modules[1].id;
    for edge in &mut presentation.edges {
        edge.entry_count = 0;
    }
    presentation
        .edges
        .iter_mut()
        .find(|edge| edge.module == first_id)
        .expect("a first edge")
        .entry_count = 9;
    presentation
        .edges
        .iter_mut()
        .find(|edge| edge.module == second_id)
        .expect("a second edge")
        .entry_count = 4;
    let summary = render_snapshot_summary(&presentation);
    assert!(
        !summary.contains("--forwarding-module"),
        "unequal entries suggest nothing: {summary}"
    );
}

/// A `--forwarding-module` input that matched no mapped file is named —
/// a declaration that matched nothing must never silently do nothing.
#[test]
fn unmatched_forwarding_inputs_are_named() {
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    presentation.unmatched_forwarding = vec!["nope.so".into()];
    let summary = render_snapshot_summary(&presentation);
    assert!(
        summary.contains("nope.so") && summary.contains("forwarding"),
        "unmatched forwarding inputs are named: {summary}"
    );
}

/// The inventory JSON twin of the unmatched-forwarding text line: a
/// declaration that matched nothing is machine-readable, omitted when
/// empty.
#[test]
fn unmatched_forwarding_inputs_are_serialized() {
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    presentation.unmatched_forwarding = vec!["nope.so".into()];
    let out = crate::inventory::render_json_from_presentation(&presentation);
    assert_eq!(out["unmatched_forwarding"][0], "nope.so");
    presentation.unmatched_forwarding = Vec::new();
    let empty = crate::inventory::render_json_from_presentation(&presentation);
    assert!(
        empty.get("unmatched_forwarding").is_none(),
        "empty unmatched_forwarding is omitted"
    );
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

/// Concise inventory names missed short-lived processes with a pointer
/// to the right mode, not just "activity unknown" on the edges.
#[test]
fn concise_inventory_points_short_lived_misses_to_run() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: crate::discovery::engine::inventory_coordinator::SHORT_LIVED_NEVER_SCANNED_SUBJECT
            .into(),
        reason: crate::discovery::engine::inventory_coordinator::short_lived_never_scanned_reason(
            54, 0,
        ),
        budget: None,
        repeats: 1,
    });
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        out.contains("54 short-lived process(es)"),
        "concise names the missed count: {out}"
    );
    assert!(
        out.contains("p11scope run"),
        "concise points to the one-shot mode: {out}"
    );
}

/// Concise gap lines keep path tails and short names whole: distinct
/// files must not collapse to one identical truncated prefix.
#[test]
fn concise_gap_lines_keep_path_tails_and_short_subjects_whole() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    for path in [
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libm.so.6",
    ] {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: None,
            subject: (*path).into(),
            reason: "opening object within retained target root: No such file or directory".into(),
            budget: None,
            repeats: 1,
        });
    }
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "native endpoint attach failed".into(),
        reason: "native deficit detail line one with enough words to force truncation now".into(),
        budget: None,
        repeats: 1,
    });
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(out.contains("libc.so.6"), "libc basename visible: {out}");
    assert!(out.contains("libm.so.6"), "libm basename visible: {out}");
    assert!(
        out.contains("native endpoint attach failed"),
        "short subject kept whole: {out}"
    );
}

/// Exited-process races on present system files read as the race,
/// not as a missing library: calm plain words in both modes, with
/// verbose keeping the machine error beside them.
#[test]
fn gap_reason_words_exited_process_races_calmly() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    for reason in [
        "opening object within retained target root: No such file or directory (os error 2)",
        "opening object within retained target root: No such process (os error 3)",
    ] {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: None,
            subject: "/usr/lib64/libc.so.6".into(),
            reason: (*reason).into(),
            budget: None,
            repeats: 1,
        });
    }
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        concise.contains("process exited during scan"),
        "concise words the race calmly: {concise}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        verbose.contains("process exited during scan"),
        "verbose leads with calm words: {verbose}"
    );
    assert!(
        verbose.contains("opening object within retained target root"),
        "verbose keeps the machine error beside them: {verbose}"
    );
}

/// A chrooted-target failure that attempted the gated host-root
/// fallback names a live process whose object missed (or was refused)
/// under both roots — never an exit race, even when the target half
/// reads ENOENT. Concise names the fallback instead of claiming the
/// process exited; verbose keeps the machine reason beside the words.
#[test]
fn gap_reason_names_the_host_root_fallback_when_attempted() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    for reason in [
        "opening object within retained target root: No such file or directory (os error 2) (host-root fallback: open failed: No such file or directory (os error 2))",
        "opening object within retained target root: No such file or directory (os error 2) (host-root fallback: object is 278755480 bytes; limit is 268435456)",
    ] {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: None,
            subject: "/usr/lib64/libc.so.6".into(),
            reason: (*reason).into(),
            budget: None,
            repeats: 1,
        });
    }
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        !concise.contains("process exited during scan"),
        "a fallback-attempted failure is not an exit race: {concise}"
    );
    assert!(
        concise.contains("object unavailable from the process's root or the host-root fallback"),
        "concise names the attempted fallback: {concise}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        verbose.contains("object unavailable from the process's root or the host-root fallback"),
        "verbose leads with the fallback wording: {verbose}"
    );
    assert!(
        verbose.contains("opening object within retained target root"),
        "verbose keeps the machine error beside it: {verbose}"
    );
}

/// Foreign-root failures fold in concise only: three identical
/// retained-root reasons with their target-root suffix become one
/// counted line naming the root — never an exit race — while a
/// size-cap refusal and a precondition refusal keep their own lines.
/// Verbose lists every gap with its machine reason; JSON keeps every
/// record verbatim.
#[test]
fn concise_folds_foreign_root_gaps_by_reason_and_keeps_json_complete() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    let foreign = "opening object within retained target root: No such file or directory (os error 2) (target root /etc/avahi differs from the observer root)";
    for subject in ["/lib/a.so", "/lib/b.so", "/bin/daemon"] {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: None,
            subject: (*subject).into(),
            reason: (*foreign).into(),
            budget: None,
            repeats: 1,
        });
    }
    for (subject, reason) in [
        (
            "/lib/big.so",
            "object is 278755480 bytes; limit is 268435456",
        ),
        (
            "relative/path.so",
            "target-root object requires an absolute path without parent traversal",
        ),
    ] {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: None,
            subject: (*subject).into(),
            reason: (*reason).into(),
            budget: None,
            repeats: 1,
        });
    }
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        !concise.contains("process exited during scan"),
        "a foreign-root failure is not an exit race: {concise}"
    );
    assert!(
        concise.contains("3 ×")
            && concise.contains("/etc/avahi")
            && concise.contains("--json lists each"),
        "concise folds the three identical foreign reasons into one counted line: {concise}"
    );
    assert!(
        concise.contains("/lib/big.so") && concise.contains("relative/path.so"),
        "size-cap and precondition refusals keep their own lines: {concise}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    for subject in ["/lib/a.so", "/lib/b.so", "/bin/daemon"] {
        assert!(
            verbose.contains(subject),
            "verbose keeps every object: {verbose}"
        );
    }
    let document = crate::inventory::render_json_from_presentation(&presentation);
    let gaps = document["gaps"]
        .as_array()
        .expect("JSON keeps a gaps array");
    assert_eq!(gaps.len(), 5, "JSON keeps every record: {document}");
}

/// Unreachable-process family fold (system demo): ESRCH
/// retained-root opens across two foreign roots become ONE concise
/// line naming the outcome with exact object and process counts —
/// never one machine-token line per root — while verbose keeps
/// every object row and JSON keeps every record. ESRCH under a
/// foreign root means the process ended mid-scan or its foreign
/// root became unusable (a sandbox jail dangling through a dead
/// pid reads exactly this way on alive processes); the line hedges
/// honestly instead of claiming every process exited. One row
/// carries repeats 3: the fold counts rows, like the header.
#[test]
fn concise_folds_unreachable_process_races_into_one_counted_line() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    let root_a = "opening object within retained target root: No such process (os error 3) (target root /proc/2431044/fdinfo differs from the observer root)";
    let root_b = "opening object within retained target root: No such process (os error 3) (target root /proc/2431006/fdinfo differs from the observer root)";
    let rows = [
        (2431043u32, root_a, "/snap/firefox/a.so", 1u64),
        (2431043u32, root_a, "/snap/firefox/b.so", 3u64),
        (2431043u32, root_a, "/snap/firefox/c.so", 1u64),
        (2431005u32, root_b, "/snap/firefox/d.so", 1u64),
        (2431005u32, root_b, "/snap/firefox/e.so", 1u64),
    ];
    for (pid, reason, subject, repeats) in rows {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: Some(pid),
            subject: (*subject).into(),
            reason: (*reason).into(),
            budget: None,
            repeats,
        });
    }
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        concise.contains("gaps: 5"),
        "header counts every retained row: {concise}"
    );
    assert!(
        concise.contains(
            "5 × mapped objects not examined — in 2 processes ended or unreachable (--json lists each)"
        ),
        "one family line carries exact object and process counts: {concise}"
    );
    assert!(
        !concise.contains("No such process"),
        "no machine errno in concise: {concise}"
    );
    assert!(
        !concise.contains("os error 3"),
        "no raw errno in concise: {concise}"
    );
    assert!(
        !concise.contains("fdinfo"),
        "no raw target-root path in concise: {concise}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    for subject in [
        "/snap/firefox/a.so",
        "/snap/firefox/b.so",
        "/snap/firefox/c.so",
        "/snap/firefox/d.so",
        "/snap/firefox/e.so",
    ] {
        assert!(
            verbose.contains(subject),
            "verbose keeps every object row: {verbose}"
        );
    }
    let document = crate::inventory::render_json_from_presentation(&presentation);
    let gaps = document["gaps"]
        .as_array()
        .expect("JSON keeps a gaps array");
    assert_eq!(gaps.len(), 5, "JSON keeps every record: {document}");
}

/// Healthy twin: rows outside the unreachable-process family never
/// join its line — foreign ENOENT keeps its per-root fold, the
/// fallback keeps its fallback words, size-cap and precondition
/// keep their own lines, and same-root ESRCH/ENOENT keep their
/// per-object lines (their reasons still word the race calmly,
/// pinned above).
#[test]
fn concise_keeps_other_object_failures_out_of_the_unreachable_line() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    let foreign_enoent = "opening object within retained target root: No such file or directory (os error 2) (target root /etc/avahi differs from the observer root)";
    for subject in ["/lib/a.so", "/lib/b.so"] {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: Some(4242),
            subject: (*subject).into(),
            reason: (*foreign_enoent).into(),
            budget: None,
            repeats: 1,
        });
    }
    for (subject, reason) in [
        (
            "/lib/c.so",
            "opening object within retained target root: No such file or directory (os error 2) (host-root fallback: open failed: No such file or directory (os error 2))",
        ),
        (
            "/lib/f.so",
            "opening object within retained target root: No such process (os error 3) (host-root fallback: open failed: No such file or directory (os error 2)) (target root /etc/avahi differs from the observer root)",
        ),
        (
            "/lib/big.so",
            "object is 278755480 bytes; limit is 268435456",
        ),
        (
            "relative/path.so",
            "target-root object requires an absolute path without parent traversal",
        ),
        (
            "/lib/d.so",
            "opening object within retained target root: No such file or directory (os error 2)",
        ),
        (
            "/lib/e.so",
            "opening object within retained target root: No such process (os error 3)",
        ),
    ] {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: Some(4243),
            subject: (*subject).into(),
            reason: (*reason).into(),
            budget: None,
            repeats: 1,
        });
    }
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        concise.contains("gaps: 8"),
        "header counts every retained row: {concise}"
    );
    assert!(
        concise.contains("host-root fallback") && concise.contains("/etc/avahi"),
        "an ESRCH row with a fallback attempt keeps the foreign fold: {concise}"
    );
    assert!(
        concise.contains("2 ×")
            && concise.contains("/etc/avahi")
            && concise.contains("--json lists each"),
        "foreign ENOENT keeps its per-root fold: {concise}"
    );
    assert!(
        concise.contains("object unavailable from the process's root or the host-root fallback"),
        "fallback keeps its fallback words: {concise}"
    );
    assert!(
        concise.contains("/lib/big.so") && concise.contains("relative/path.so"),
        "size-cap and precondition refusals keep their own lines: {concise}"
    );
    assert!(
        concise.contains("/lib/e.so") && concise.contains("process exited during scan"),
        "same-root ESRCH keeps its per-object line with calm words: {concise}"
    );
    assert!(
        !concise.contains("mapped objects not examined"),
        "no family line without a foreign-ESRCH row: {concise}"
    );
}

/// Family line boundaries: a single foreign-ESRCH row still reads
/// as one counted line (never a bare object row), and rows without
/// a pid read as unreachable objects rather than counting zero
/// processes.
#[test]
fn concise_unreachable_line_handles_single_and_pidless_rows() {
    let harness = varied_harness();
    let foreign_esrch = "opening object within retained target root: No such process (os error 3) (target root /srv/jail differs from the observer root)";
    let mut single = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    single.gaps.clear();
    single.gaps_suppressed = 0;
    single.gaps.push(GapView {
        caller: None,
        module: None,
        pid: Some(4242),
        subject: "/lib/only.so".into(),
        reason: (*foreign_esrch).into(),
        budget: None,
        repeats: 1,
    });
    let concise = render_snapshot_with_verbosity(&single, crate::cli::TextVerbosity::Concise);
    assert!(
        concise.contains(
            "1 × mapped objects not examined — in 1 process ended or unreachable (--json lists each)"
        ),
        "a single race reads as one counted line: {concise}"
    );
    let mut pidless = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    pidless.gaps.clear();
    pidless.gaps_suppressed = 0;
    for subject in ["/lib/x.so", "/lib/y.so"] {
        pidless.gaps.push(GapView {
            caller: None,
            module: None,
            pid: None,
            subject: (*subject).into(),
            reason: (*foreign_esrch).into(),
            budget: None,
            repeats: 1,
        });
    }
    let concise = render_snapshot_with_verbosity(&pidless, crate::cli::TextVerbosity::Concise);
    assert!(
        concise.contains(
            "2 × mapped objects not examined — 2 mapped objects unreachable (--json lists each)"
        ),
        "pidless rows read as unreachable objects: {concise}"
    );
}

/// Busy-host folds: replaced-file rows across many files become ONE
/// concise line with exact row and file counts (a small family keeps
/// its per-file lines, pinned below and by
/// `concise_replaced_providers_read_as_gaps`); verbose and JSON keep
/// every row. One row carries repeats 2: the fold counts rows.
#[test]
fn concise_folds_many_replaced_files_into_one_counted_line() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    let rows = [
        (11u32, "/usr/lib/libpcre2-8.so.0.14.0 (deleted)", 2u64),
        (12u32, "/usr/lib/libpcre2-8.so.0.14.0 (deleted)", 1u64),
        (11u32, "/usr/lib/gvfs/libgvfscommon.so (deleted)", 1u64),
        (13u32, "/usr/lib/gio/modules/libgvfsdbus.so (deleted)", 1u64),
        (13u32, "/usr/lib/libsoup-3.0.so.0.7.4 (deleted)", 1u64),
    ];
    for (pid, subject, repeats) in rows {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: Some(pid),
            subject: (*subject).into(),
            reason: "replaced on disk while running; not examined, calls not counted".into(),
            budget: None,
            repeats,
        });
    }
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(concise.contains("gaps: 5"), "header counts rows: {concise}");
    assert!(
        concise.contains(
            "5 × replaced files not examined — 4 files replaced while running (--json lists each)"
        ),
        "one family line carries exact row and file counts: {concise}"
    );
    assert!(
        !concise.contains("libpcre2"),
        "no per-file flood in concise: {concise}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        verbose.contains("libpcre2-8.so.0.14.0 (deleted)"),
        "{verbose}"
    );
    let document = crate::inventory::render_json_from_presentation(&presentation);
    assert_eq!(
        document["gaps"].as_array().expect("gaps array").len(),
        5,
        "JSON keeps every record: {document}"
    );
}

/// Flood twin: a replaced file that is or was an admitted provider
/// keeps its own named concise row even when unrelated replaced
/// files fold (a provider must never hide in a count); the fold then
/// counts only the rest. Verbose and JSON keep every row.
#[test]
fn concise_keeps_replaced_admitted_providers_named_in_a_flood() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    // An admitted provider plus a was-admitted one (refused now, with
    // an admission in its history); the replaced copy lives under a
    // different directory than the admitted path, so only the file
    // name matches.
    let admitted = presentation
        .modules
        .iter_mut()
        .find(|module| module.admission == AdmissionState::Admitted)
        .expect("varied harness admits a module");
    admitted
        .paths
        .push("/usr/lib/x86_64-linux-gnu/libsoftokn3.so".to_string());
    let retired = presentation
        .modules
        .iter_mut()
        .find(|module| module.admission != AdmissionState::Admitted)
        .expect("varied harness refuses a module");
    retired.paths.push("/usr/lib/ykcs11.so".to_string());
    retired.admission_history.push(AdmissionChange {
        from: AdmissionState::Unresolved,
        to: AdmissionState::Admitted,
        at_ns: 1,
    });
    for (pid, subject) in [
        (21u32, "/usr/lib/firefox/libsoftokn3.so (deleted)"),
        (22u32, "/usr/lib/ykcs11.so (deleted)"),
        (23u32, "/usr/lib/libpcre2-8.so.0.14.0 (deleted)"),
        (24u32, "/usr/lib/gvfs/libgvfscommon.so (deleted)"),
        (25u32, "/usr/lib/libsoup-3.0.so.0.7.4 (deleted)"),
    ] {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: Some(pid),
            subject: (*subject).into(),
            reason: "replaced on disk while running; not examined, calls not counted".into(),
            budget: None,
            repeats: 1,
        });
    }
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(concise.contains("gaps: 5"), "header counts rows: {concise}");
    assert!(
        concise.contains(
            "3 × replaced files not examined — 3 files replaced while running (--json lists each)"
        ),
        "the fold counts only the non-provider rest: {concise}"
    );
    assert!(
        concise.contains("libsoftokn3.so (deleted)"),
        "an admitted provider keeps its named gap row: {concise}"
    );
    assert!(
        concise.contains("ykcs11.so (deleted)"),
        "a was-admitted provider keeps its named gap row: {concise}"
    );
    assert!(
        !concise.contains("libpcre2")
            && !concise.contains("libgvfscommon")
            && !concise.contains("libsoup"),
        "no per-file flood in concise: {concise}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        verbose.contains("libpcre2-8.so.0.14.0 (deleted)"),
        "{verbose}"
    );
    let document = crate::inventory::render_json_from_presentation(&presentation);
    assert_eq!(
        document["gaps"].as_array().expect("gaps array").len(),
        5,
        "JSON keeps every record: {document}"
    );
}

/// Healthy twin: a two-file replaced family keeps its named per-file
/// lines (the fold serves floods, not small named losses), and a
/// maps-attribution lookalike with an unparsable reason stays out of
/// the maps family.
#[test]
fn concise_keeps_small_replaced_and_unparsable_maps_rows_named() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    for (pid, subject) in [
        (11u32, "/usr/lib/libsoftokn3.so (deleted)"),
        (12u32, "/usr/lib/p11-kit-trust.so (deleted)"),
    ] {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: Some(pid),
            subject: (*subject).into(),
            reason: "replaced on disk while running; not examined, calls not counted".into(),
            budget: None,
            repeats: 1,
        });
    }
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: Some(14),
        subject: "maps attribution".into(),
        reason: "maps snapshots unavailable for this process".into(),
        budget: None,
        repeats: 1,
    });
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(concise.contains("gaps: 3"), "header counts rows: {concise}");
    assert!(
        concise.contains("libsoftokn3") && concise.contains("p11-kit-trust"),
        "small replaced families stay named per file: {concise}"
    );
    assert!(
        !concise.contains("replaced files not examined"),
        "no family line for a two-file family: {concise}"
    );
    assert!(
        concise.contains("maps snapshots unavailable"),
        "an unparsable maps reason keeps its own line: {concise}"
    );
}

/// Maps-attribution rows (one per pid per pass, each naming how many
/// shared objects no deep scan examined) fold into ONE concise line
/// with the exact row and process counts and the mapping counts
/// summed over passes (never a distinct-object count: the same
/// objects recur across passes and processes); verbose and JSON keep
/// every row.
#[test]
fn concise_folds_maps_attribution_into_one_counted_line() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    let rows = [
        (
            21u32,
            "maps 1 shared object no deep scan examined this pass; it may be an undiscovered provider",
        ),
        (
            22u32,
            "maps 2 shared objects no deep scan examined this pass; each may be an undiscovered provider",
        ),
        (
            23u32,
            "maps 4 shared objects no deep scan examined this pass; each may be an undiscovered provider",
        ),
        (
            21u32,
            "maps 1 shared object no deep scan examined this pass; it may be an undiscovered provider",
        ),
    ];
    for (pid, reason) in rows {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: Some(pid),
            subject: "maps attribution".into(),
            reason: (*reason).into(),
            budget: None,
            repeats: 1,
        });
    }
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(concise.contains("gaps: 4"), "header counts rows: {concise}");
    assert!(
        concise.contains(
            "4 × maps attribution — 3 processes; 8 mappings summed over passes (--json lists each)"
        ),
        "one family line carries exact row and process counts with the summed mappings: {concise}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(verbose.contains("maps 4 shared objects"), "{verbose}");
    let document = crate::inventory::render_json_from_presentation(&presentation);
    assert_eq!(
        document["gaps"].as_array().expect("gaps array").len(),
        4,
        "JSON keeps every record: {document}"
    );
}

/// Twin: marker text without the retained-root prefix is not a
/// foreign-root failure — it passes through verbatim instead of
/// borrowing the foreign plain words. (A real foreign reason keeps its
/// plain words, pinned by
/// `concise_folds_foreign_root_gaps_by_reason_and_keeps_json_complete`.)
#[test]
fn gap_plain_reason_keeps_unprefixed_marker_text_verbatim() {
    for reason in [
        "lane noted (target root /etc/avahi) mid-text",
        "lane noted (host-root fallback: refused) mid-text",
    ] {
        assert_eq!(gap_plain_reason(reason), reason);
    }
    // Healthy halves: the real foreign forms keep their plain words.
    assert_eq!(
        gap_plain_reason(
            "opening object within retained target root: No such file or directory (os error 2) (target root /etc/avahi differs from the observer root)"
        ),
        "object unavailable in foreign target root"
    );
    assert_eq!(
        gap_plain_reason(
            "opening object within retained target root: No such file or directory (os error 2) (host-root fallback: open failed: No such file or directory (os error 2)) (target root /etc/avahi differs from the observer root)"
        ),
        "object unavailable from the process's root or the host-root fallback"
    );
}

/// F1+F3: the concise gap summary uses plain words for the Joint
/// seal/fallback gaps, never the raw `S1` / `joint_*` tokens. The
/// journal gap reads on the key-operations line instead of here, so
/// concise states "per-key tracking is off" once; verbose keeps its
/// plain words with the machine tokens beside them.
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
    ] {
        assert!(out.contains(plain), "{plain} missing: {out}");
    }
    // The journal gap is not a group here: the key-operations line
    // states it, so concise shows it once.
    assert!(
        !out.contains("per-key tracking is off in this run"),
        "the journal gap reads on the key-operations line, not here: {out}"
    );
    // Long plain subjects truncate (marked) to hold the 100-char cap;
    // verbose and JSON keep them whole.
    assert!(
        out.contains("Per-key tracking did not start"),
        "seal subject stem missing: {out}"
    );
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

/// Concise gaps use plain words for the semantic-tracking tokens, never
/// the machine names: the pre-registration boundary, the Joint birth
/// registration refusal, and the deferred admission note. Verbose keeps
/// each token beside its plain words; JSON keeps the stored reason.
#[test]
fn concise_gap_summary_uses_plain_words_for_semantic_tracking_tokens() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    for (subject, reason) in [
        (
            "physical provider use preceded first observed semantic registration",
            "before_semantic_boundary",
        ),
        (
            JOINT_BIRTH_UNAVAILABLE_SUBJECT,
            "joint_birth_registration_Capacity",
        ),
        (
            "semantic admission deferred",
            "semantic_unavailable:no_receipt",
        ),
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
    for plain in [
        "earlier calls not counted",
        "per-key tracking hit its capacity",
        "will retry on the next scan; no calls lost",
    ] {
        assert!(out.contains(plain), "{plain} missing: {out}");
    }
    for machine in [
        "before_semantic_boundary",
        "joint_birth_registration_Capacity",
        "semantic_unavailable:no_receipt",
    ] {
        assert!(!out.contains(machine), "{machine} leaked to concise: {out}");
    }
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    for (plain, machine) in [
        ("earlier calls not counted", "before_semantic_boundary"),
        (
            "per-key tracking hit its capacity",
            "joint_birth_registration_Capacity",
        ),
        (
            "will retry on the next scan; no calls lost",
            "semantic_unavailable:no_receipt",
        ),
    ] {
        assert!(verbose.contains(plain), "{plain} missing in -v: {verbose}");
        assert!(
            verbose.contains(&format!("{plain} ({machine})")),
            "{machine} not paired in -v: {verbose}"
        );
    }
    let document = crate::inventory::render_json_from_presentation(&presentation);
    let text = serde_json::to_string(&document).unwrap();
    for machine in [
        "before_semantic_boundary",
        "joint_birth_registration_Capacity",
        "semantic_unavailable:no_receipt",
    ] {
        assert!(text.contains(machine), "{machine} missing in JSON: {text}");
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

/// A scan-only inventory (kept first pass, scan fallback) records
/// endpoints without attaching any: the limits line says recorded
/// with 0 attached, never "watched".
#[test]
fn concise_limits_line_says_recorded_when_no_endpoint_attached() {
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "present-limits-scan-only",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 74_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 1, 1);
    presentation.usage_feed = false;
    presentation.budgets.endpoints_occupied = 0;
    presentation.budgets.inventory_endpoints_occupied = 213;
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let limits = out
        .lines()
        .find(|line| line.starts_with("limits:"))
        .unwrap_or_else(|| panic!("no limits line: {out}"));
    assert!(
        limits.contains("213 functions recorded, 0 attached"),
        "{limits}"
    );
    assert!(!limits.contains("watched"), "{limits}");
}

/// A live `--cgroup` capture attaches probes but stages every edge
/// unknown with membership unproven: the limits line keeps the
/// "watched" wording, never "recorded, 0 attached".
#[test]
fn concise_limits_line_says_watched_when_membership_unproven() {
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "present-limits-unproven",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 75_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 1, 1);
    assert!(!presentation.edges.is_empty(), "fixture needs edges");
    for edge in &mut presentation.edges {
        edge.coverage = UseCoverage::Unknown(UnknownReason::ScopeMembershipUnproven);
    }
    presentation.budgets.endpoints_occupied = 0;
    presentation.budgets.inventory_endpoints_occupied = 213;
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let limits = out
        .lines()
        .find(|line| line.starts_with("limits:"))
        .unwrap_or_else(|| panic!("no limits line: {out}"));
    assert!(limits.contains("213 functions watched"), "{limits}");
    assert!(!limits.contains("recorded, 0 attached"), "{limits}");
}

/// A live capture whose every edge is unknown for a non-scan reason
/// (an uncounted feed here) still ran a producer: "watched" stays.
#[test]
fn concise_limits_line_says_watched_when_every_edge_is_uncounted() {
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "present-limits-uncounted",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 76_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 1, 1);
    assert!(!presentation.edges.is_empty(), "fixture needs edges");
    for edge in &mut presentation.edges {
        edge.coverage = UseCoverage::Unknown(UnknownReason::Uncounted(
            "fixture pair insert failed".into(),
        ));
    }
    presentation.budgets.endpoints_occupied = 0;
    presentation.budgets.inventory_endpoints_occupied = 213;
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let limits = out
        .lines()
        .find(|line| line.starts_with("limits:"))
        .unwrap_or_else(|| panic!("no limits line: {out}"));
    assert!(limits.contains("213 functions watched"), "{limits}");
    assert!(!limits.contains("recorded, 0 attached"), "{limits}");
}

/// Guard twin: a capture with a counted edge keeps "watched" — the
/// scan-only wording must never leak onto a producing capture.
#[test]
fn concise_limits_line_keeps_watched_when_an_edge_is_counted() {
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "present-limits-counted",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 77_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 1, 1);
    assert!(!presentation.edges.is_empty(), "fixture needs edges");
    presentation.edges[0].coverage = UseCoverage::Counted {
        since_ns: 1,
        lossy: false,
        pid_exit: false,
    };
    presentation.usage_feed = true;
    presentation.budgets.endpoints_occupied = 0;
    presentation.budgets.inventory_endpoints_occupied = 213;
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let limits = out
        .lines()
        .find(|line| line.starts_with("limits:"))
        .unwrap_or_else(|| panic!("no limits line: {out}"));
    assert!(limits.contains("213 functions watched"), "{limits}");
    assert!(!limits.contains("recorded, 0 attached"), "{limits}");
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

/// Item 37, re-pinned per owner rule 2026-11-09 (data-always):
/// replaced providers read as gaps — the gaps block names each
/// running copy and coverage counts them; verbose keeps each record.
#[test]
fn concise_replaced_providers_read_as_gaps() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    presentation.budgets.callers_refused = 0;
    presentation.budgets.modules_refused = 0;
    presentation.budgets.edges_refused = 0;
    presentation.budgets.endpoints_refused = 0;
    for (pid, subject) in [
        (11, "/usr/lib/libsoftokn3.so (deleted)"),
        (12, "/usr/lib/p11-kit-trust.so (deleted)"),
    ] {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: Some(pid),
            subject: subject.into(),
            reason: "replaced on disk while running; not examined, calls not counted".into(),
            budget: None,
            repeats: 1,
        });
    }
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
        out.lines().any(|line| line == "coverage: partial — 3 gaps"),
        "replaced providers count as gaps: {out}"
    );
    let lines: Vec<&str> = out.lines().collect();
    let start = lines
        .iter()
        .position(|line| *line == "gaps: 3")
        .expect("gaps header");
    let block = &lines[start + 1..start + 4];
    assert!(
        block.contains(&"  1 × fixture scope — fixture reason"),
        "the gaps block holds the fixture gap: {out}"
    );
    for fragment in ["libsoftokn3", "p11-kit-trust"] {
        assert!(
            block.iter().any(|line| line.contains(fragment)
                && line.ends_with(
                    " — replaced on disk while running; not examined, calls not counted"
                )),
            "the gaps block names the {fragment} running copy with its loss: {out}"
        );
    }
    assert!(
        !out.lines().any(|line| line.starts_with("notes:")),
        "no not-loss note for replaced providers: {out}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(verbose.contains("libsoftokn3.so (deleted)"), "{verbose}");
}

/// Item 37, re-pinned per owner rule 2026-11-09 (data-always): a
/// replaced provider alone forces PARTIAL — the gaps block names the
/// running copy and no notes line prints.
#[test]
fn replaced_only_gaps_force_partial_with_gaps_block() {
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
        subject: "/usr/lib/libsoftokn3.so (deleted)".into(),
        reason: "replaced on disk while running; not examined, calls not counted".into(),
        budget: None,
        repeats: 1,
    });
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        out.lines().any(|line| line == "coverage: partial — 1 gap"),
        "a replaced provider alone forces PARTIAL: {out}"
    );
    assert!(
        out.lines().any(|line| line == "gaps: 1"),
        "the gaps block names the running copy: {out}"
    );
    assert!(
        !out.lines().any(|line| line.starts_with("notes:")),
        "no not-loss note for a replaced provider: {out}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(verbose.contains("libsoftokn3.so (deleted)"), "{verbose}");
}

/// Audit P0-1: a replaced-provider gap forces PARTIAL coverage — the
/// gaps block names the running copy, never a "not loss" note.
#[test]
fn replaced_provider_gap_forces_partial_coverage() {
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
        subject: "/usr/lib/libsoftokn3.so (deleted)".into(),
        reason: "replaced on disk while running; not examined, calls not counted".into(),
        budget: None,
        repeats: 1,
    });
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        out.lines().any(|line| line == "coverage: partial — 1 gap"),
        "a replaced-provider gap forces PARTIAL: {out}"
    );
    assert!(
        out.lines().any(|line| line == "gaps: 1"),
        "the gaps block names the replaced provider: {out}"
    );
    assert!(
        out.contains("replaced on disk while running; not examined, calls not counted"),
        "the named gap surfaces verbatim: {out}"
    );
    assert!(
        !out.lines().any(|line| line.starts_with("notes:")),
        "no not-loss note for a replaced provider: {out}"
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
/// lines; the view continues, and the count line names every caller
/// with edges as unknown instead of vanishing silently.
#[test]
fn concise_unavailable_metadata_prints_no_scope_lines() {
    use std::collections::BTreeSet;
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.caller_metadata = crate::caller_metadata::runtime::MetadataFrame::unavailable(
        crate::caller_metadata::presentation::MetadataReason::LookupLimit,
    );
    assert!(presentation.caller_metadata.summary.enabled);
    let with_edges: BTreeSet<CallerId> =
        presentation.edges.iter().map(|edge| edge.caller).collect();
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        !out.lines()
            .any(|line| line.starts_with("caller ") && line.contains(" pid ")),
        "{out}"
    );
    let expected = format!(
        "caller context: {} unknown (-v for details)",
        with_edges.len()
    );
    assert!(
        out.lines().any(|line| line == expected),
        "missing unknown count line {expected:?}\n{out}"
    );
    assert!(out.contains("inventory "), "{out}");
}

/// F10: an enabled frame with labeled rows prints one exact concise
/// scope line per caller with edges, and the verbose Details caller
/// line carries the full-ID suffix. Entry totals are fixed fixture
/// constants (17 and 1), never recomputed with the product's sum, so a
/// wrong per-caller sum fails this test; the forwarding shape itself
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
        .filter(|line| line.starts_with("caller ") && line.contains(" pid "))
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
        .filter(|line| line.starts_with("caller ") && line.contains(" pid "))
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
        .filter(|line| line.starts_with("caller ") && line.contains(" pid "))
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
        .filter(|line| line.starts_with("caller ") && line.contains(" pid "))
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

/// Sampled host rows stay silent when they age or retire: a host
/// cgroup matched no container pattern, so it carries no scope line,
/// and its sampled/stale/historical rows with edges contribute no
/// `caller context:` part. Only never-sampled or refused rows count
/// as unknown.
#[test]
fn concise_sampled_host_rows_stay_silent_when_stale_or_historical() {
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
    let host = scope_metadata_for("user.slice/user-1000.slice/session-2.scope");
    assert!(host.validity.is_some(), "host fixture must be sampled");
    assert_eq!(
        crate::caller_metadata::presentation::concise_scope_label(&host, false),
        None,
        "host must carry no scope label"
    );
    let stale = host.to_stale();
    let historical = host.to_historical();
    assert!(stale.validity.is_some());
    assert!(historical.validity.is_some());
    assert_eq!(
        crate::caller_metadata::presentation::concise_scope_label(&stale, false),
        None
    );
    assert_eq!(
        crate::caller_metadata::presentation::concise_scope_label(&historical, false),
        None
    );
    let rows: Vec<(
        CallerId,
        crate::caller_metadata::presentation::CallerMetadata,
    )> = ids
        .iter()
        .enumerate()
        .map(|(index, id)| {
            let metadata = match index % 3 {
                0 => host,
                1 => stale,
                _ => historical,
            };
            (*id, metadata)
        })
        .collect();
    presentation.caller_metadata = crate::caller_metadata::runtime::MetadataFrame::for_test(&rows);
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        !out.lines()
            .any(|line| line.starts_with("caller ") && line.contains(" pid ")),
        "host rows print no scope lines: {out}"
    );
    assert!(
        !out.lines().any(|line| line.starts_with("caller context:")),
        "sampled host rows stay silent: {out}"
    );
}

/// A retired caller that was never sampled carries no validity and
/// counts as unknown, not silent: it matched nothing because it was
/// never observed, not because it matched no container pattern.
#[test]
fn concise_never_sampled_historical_counts_unknown() {
    let mut harness = harness();
    harness.stage_scale(&ScaleSpec {
        name: "host-historical-unknown",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 1,
        first_pid: 81_000,
    });
    harness.commit();
    let mut presentation =
        Presentation::capture(harness.coordinator(), "host-historical-unknown", 1, 2, 1);
    assert_eq!(presentation.edges.len(), 1, "one edge for one caller");
    let id = presentation.edges[0].caller;
    let never_sampled =
        crate::caller_metadata::presentation::CallerMetadata::pending().to_historical();
    assert!(never_sampled.validity.is_none());
    assert_eq!(
        crate::caller_metadata::presentation::concise_scope_label(&never_sampled, false),
        None
    );
    presentation.caller_metadata =
        crate::caller_metadata::runtime::MetadataFrame::for_test(&[(id, never_sampled)]);
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        !out.lines()
            .any(|line| line.starts_with("caller ") && line.contains(" pid ")),
        "never-sampled row prints no scope line: {out}"
    );
    assert!(
        out.lines()
            .any(|line| line == "caller context: 1 unknown (-v for details)"),
        "never-sampled historical counts unknown: {out}"
    );
}

fn ambiguous_exe(shown: &str, candidates: &[&str]) -> UnboundExe {
    UnboundExe {
        dev: 35,
        ino: 99,
        path: Some(shown.to_string()),
        resolution: ExeResolution::ScanLearned,
        identity_candidates: candidates.iter().map(|path| path.to_string()).collect(),
    }
}

fn unbound_image(pid_host: u32, first_call_ns: u64, calls: u64, exe: UnboundExe) -> UnboundPid {
    UnboundPid {
        pid_host,
        first_call_ns,
        calls_at_least: calls,
        exe,
    }
}

/// The executable name stays visible first: the concise marker
/// lists the candidates' full paths beside the kept name, and
/// counts never change.
#[test]
fn concise_ambiguous_marker_lists_candidate_paths_beside_the_name() {
    let exe = ambiguous_exe("/snap/a/tool", &["/snap/a/tool", "/snap/b/tool"]);
    let line =
        render_unidentified_executables(&[unbound_image(9, 210, 1, exe)], 0).expect("one group");
    assert_eq!(
        line,
        "unidentified executables: tool (ambiguous: /snap/a/tool, /snap/b/tool) (1 call, host pid 9)"
    );
}

/// Past two candidates the concise marker keeps the first two
/// (sorted) and counts the rest; the name still leads.
#[test]
fn concise_ambiguous_marker_counts_candidates_past_two() {
    let exe = ambiguous_exe(
        "/snap/a/tool",
        &[
            "/snap/a/tool",
            "/snap/b/tool",
            "/snap/c/tool",
            "/snap/d/tool",
        ],
    );
    let line =
        render_unidentified_executables(&[unbound_image(9, 210, 3, exe)], 0).expect("one group");
    assert_eq!(
        line,
        "unidentified executables: tool (ambiguous: /snap/a/tool, /snap/b/tool (+2 more)) (3 calls, host pid 9)"
    );
}

/// Control characters in candidate paths escape exactly like the
/// group name; the marker never leaks a raw control.
#[test]
fn concise_ambiguous_marker_escapes_controls_in_candidates() {
    let exe = ambiguous_exe("/snap/a/tool", &["/snap/a/tool", "/snap/b\x01tool"]);
    let line =
        render_unidentified_executables(&[unbound_image(9, 210, 1, exe)], 0).expect("one group");
    assert_eq!(
        line,
        "unidentified executables: tool (ambiguous: /snap/a/tool, /snap/b\\u{1}tool) (1 call, host pid 9)"
    );
}

/// Members that disagree keep the richest candidate list beside
/// the shared name; folded counts still read exactly.
#[test]
fn concise_ambiguous_marker_uses_richest_member_when_members_disagree() {
    let thin = ambiguous_exe("/snap/a/tool", &["/snap/a/tool", "/snap/b/tool"]);
    let rich = ambiguous_exe(
        "/snap/a/tool",
        &["/snap/a/tool", "/snap/b/tool", "/snap/c/tool"],
    );
    let line = render_unidentified_executables(
        &[
            unbound_image(9, 210, 1, thin),
            unbound_image(10, 220, 2, rich),
        ],
        0,
    )
    .expect("one group");
    assert_eq!(
        line,
        "unidentified executables: tool (ambiguous: /snap/a/tool, /snap/b/tool (+1 more)) (3 calls, host pids 9, 10)"
    );
}

#[test]
fn app_hint_appends_a_bracketed_label_and_json_value() {
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    let caller = presentation.callers[0].id;
    presentation.callers[0].exe.as_mut().unwrap().path = Some("/usr/bin/python3".into());
    presentation.callers[0].app_hint = Some(crate::app_hint::AppHint {
        value: "pkcs11-check".into(),
        source: crate::app_hint::AppHintSource::Argv,
    });
    assert_eq!(
        application_label(&presentation, caller),
        "python3 [pkcs11-check]"
    );
    let document = crate::inventory::render_json_from_presentation(&presentation);
    let rendered = document["callers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == caller.label())
        .unwrap();
    assert_eq!(rendered["app_hint"]["value"], "pkcs11-check");
    assert_eq!(rendered["app_hint"]["source"], "argv");
}

#[test]
fn app_hint_source_shows_in_verbose_only() {
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    presentation.callers[0].exe.as_mut().unwrap().path = Some("/usr/bin/python3".into());
    presentation.callers[0].app_hint = Some(crate::app_hint::AppHint {
        value: "pkcs11-check".into(),
        source: crate::app_hint::AppHintSource::Argv,
    });
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        verbose.contains("app hint \"pkcs11-check\" via argv"),
        "{verbose}"
    );
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        concise.contains("python3 [pkcs11-check]") && !concise.contains("via argv"),
        "{concise}"
    );
}

#[test]
fn missing_app_hint_renders_no_brackets_and_no_key() {
    let harness = varied_harness();
    let mut presentation = capture_for(&harness, &harness.render());
    let caller = presentation.callers[0].id;
    presentation.callers[0].exe.as_mut().unwrap().path = Some("/usr/bin/python3".into());
    assert_eq!(application_label(&presentation, caller), "python3");
    let document = crate::inventory::render_json_from_presentation(&presentation);
    let rendered = document["callers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == caller.label())
        .unwrap();
    assert!(
        rendered.get("app_hint").is_none(),
        "absent hint stays absent: {rendered}"
    );
}

#[test]
fn app_hints_change_labels_only_never_counts_or_identity() {
    // Twin: the same presentation rendered with hints on every caller
    // versus no hints. Labels must differ (the toggle really applied);
    // the JSON documents must then agree exactly once the display-only
    // `app_hint` keys are removed — same ids, joins, counts, edges.
    let harness = varied_harness();
    let document = harness.render();
    let plain = capture_for(&harness, &document);
    let mut hinted = capture_for(&harness, &document);
    assert!(!hinted.callers.is_empty(), "the twin needs callers");
    for caller in &mut hinted.callers {
        caller.app_hint = Some(crate::app_hint::AppHint {
            value: "hint-probe".into(),
            source: crate::app_hint::AppHintSource::Unit,
        });
    }
    let plain_labels: Vec<String> = plain
        .callers
        .iter()
        .map(|caller| application_label(&plain, caller.id))
        .collect();
    let hinted_labels: Vec<String> = hinted
        .callers
        .iter()
        .map(|caller| application_label(&hinted, caller.id))
        .collect();
    assert_ne!(
        plain_labels, hinted_labels,
        "the hint toggle must show in labels"
    );
    for (base, labeled) in plain_labels.iter().zip(hinted_labels.iter()) {
        assert_eq!(labeled, &format!("{base} [hint-probe]"), "label twin");
    }
    let plain_doc = crate::inventory::render_json_from_presentation(&plain);
    let mut hinted_doc = crate::inventory::render_json_from_presentation(&hinted);
    assert!(
        plain_doc["callers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row.get("app_hint").is_none()),
        "plain twin carries no hint keys"
    );
    for row in hinted_doc["callers"].as_array_mut().unwrap() {
        assert!(
            row.get("app_hint").is_some(),
            "hinted twin carries the key: {row}"
        );
        row.as_object_mut().unwrap().remove("app_hint");
    }
    assert_eq!(
        plain_doc, hinted_doc,
        "counts, edges, joins and ids are identical ± hints"
    );
}

/// I1: a long replaced-file path keeps its END (the file name) on the
/// concise gap line, not its start.
#[test]
fn gap_group_line_keeps_path_tail() {
    let line = gap_group_line(
        1,
        "/var/tmp/p11scope-ws-tmp/replaced-holder/prov/libsofthsm2.so (deleted)",
        "replaced on disk while running; not examined, calls not counted",
    );
    assert!(
        line.starts_with("  1 × …"),
        "the line keeps the path tail: {line}"
    );
    assert!(
        line.contains("libsofthsm2.so (deleted)"),
        "the line names the file: {line}"
    );
    assert!(
        !line.contains("/var/tmp"),
        "the line drops the path head: {line}"
    );
    assert!(line.chars().count() <= 100, "over 100 chars: {line}");
}

/// I1 twin: a prose subject still keeps its START on the concise gap
/// line; only paths keep the tail. The subject is longer than the
/// short-subject keep (short machine names stay whole and the reason
/// gives way instead, pinned in the key-ops twin). The head cuts on a
/// word boundary, never mid-word.
#[test]
fn gap_group_line_keeps_prose_head() {
    let line = gap_group_line(
        1,
        "native usage feed unavailable for this capture window",
        "live capture refused (missing capabilities); run 'p11scope doctor'",
    );
    assert_eq!(
        line,
        "  1 × native usage feed… — live capture refused (missing capabilities); run \
         'p11scope doctor'"
    );
}

/// Concise gap lines cut prose subjects on a word boundary, never
/// mid-word, so titles read whole.
#[test]
fn gap_group_line_cuts_prose_on_word_boundary() {
    let line = gap_group_line(
        1,
        "native usage feed unavailable for this capture window",
        "live capture refused (missing capabilities); run 'p11scope doctor'",
    );
    assert!(
        line.contains("native usage feed…"),
        "cuts on a word boundary: {line}"
    );
    assert!(!line.contains("unavai…"), "never cuts mid-word: {line}");
    assert!(line.chars().count() <= 100, "over 100 chars: {line}");
}
/// F1: an empty inventory with replaced-file gaps names the loss:
/// "No counted associations; N programs run files replaced on disk
/// (below)" plus one not-counted line per program/file with restart
/// advice. Text only; JSON unchanged.
#[test]
fn empty_inventory_with_replaced_files_names_not_counted() {
    let harness = varied_harness();
    let caller = harness.coordinator().adapter().live_id(70_000).unwrap();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.edges.clear();
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    presentation.budgets.callers_refused = 0;
    presentation.budgets.modules_refused = 0;
    presentation.budgets.edges_refused = 0;
    presentation.budgets.endpoints_refused = 0;
    presentation.gaps.push(GapView {
        caller: Some(caller),
        module: None,
        pid: Some(70_000),
        subject: "/var/tmp/p11scope-ws-tmp/replaced-holder/prov/libsofthsm2.so (deleted)".into(),
        reason: "replaced on disk while running; not examined, calls not counted".into(),
        budget: None,
        repeats: 1,
    });
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        out.contains("No counted associations; 1 program runs files replaced on disk (below)."),
        "the absence line names the replaced-file loss: {out}"
    );
    assert!(
        !out.contains("No application/module associations observed"),
        "the bare absence line is gone: {out}"
    );
    assert!(
        out.contains(
            "not counted: driver (PID 70000) runs \
             /var/tmp/p11scope-ws-tmp/replaced-holder/prov/libsofthsm2.so (deleted), a file \
             replaced on disk while it runs; restart it to count its calls"
        ),
        "the not-counted line names program, pid and file: {out}"
    );
    let quiet = render_snapshot_summary(&presentation);
    assert!(
        quiet.contains("No counted associations; 1 program"),
        "{quiet}"
    );
    assert!(quiet.contains("not counted: driver (PID 70000)"), "{quiet}");
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        verbose.contains("No counted associations; 1 program"),
        "{verbose}"
    );
    assert!(
        verbose.contains("not counted: driver (PID 70000)"),
        "{verbose}"
    );
    // JSON unchanged: the gap row keeps caller/pid/subject/reason
    // verbatim, and no new text leaks in.
    let document = crate::inventory::render_json_from_presentation(&presentation);
    let text = serde_json::to_string(&document).unwrap();
    assert!(
        !text.contains("not counted:"),
        "text-only line leaked to JSON: {text}"
    );
    assert!(
        !text.contains("No counted associations"),
        "text-only line leaked to JSON: {text}"
    );
    assert!(
        text.contains("replaced on disk while running; not examined, calls not counted"),
        "the JSON gap keeps the verbatim reason: {text}"
    );
}

/// F1 plural: two programs with replaced files count as two.
#[test]
fn empty_inventory_with_two_replaced_programs_counts_two() {
    let harness = varied_harness();
    let caller = harness.coordinator().adapter().live_id(70_000).unwrap();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.edges.clear();
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    for (caller, pid, subject) in [
        (
            Some(caller),
            Some(70_000),
            "/prov/a/libsofthsm2.so (deleted)",
        ),
        (None, Some(70_001), "/prov/b/libpcre2-8.so.0 (deleted)"),
    ] {
        presentation.gaps.push(GapView {
            caller,
            module: None,
            pid,
            subject: subject.into(),
            reason: "replaced on disk while running; not examined, calls not counted".into(),
            budget: None,
            repeats: 1,
        });
    }
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        out.contains("No counted associations; 2 programs run files replaced on disk (below)."),
        "the absence line counts both programs: {out}"
    );
    assert!(
        out.contains("not counted: driver (PID 70000) runs /prov/a/libsofthsm2.so (deleted)"),
        "the known caller is named: {out}"
    );
    assert!(
        out.contains("not counted: PID 70001 runs /prov/b/libpcre2-8.so.0 (deleted)"),
        "the caller-less gap falls back to its pid: {out}"
    );
}

/// F1 guard: an empty inventory without replaced files keeps the bare
/// absence line.
#[test]
fn empty_inventory_without_replaced_files_keeps_bare_absence_line() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.edges.clear();
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
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
        out.contains(
            "No application/module associations observed; this does not prove that no PKCS#11 activity occurred."
        ),
        "the bare absence line stays without replaced files: {out}"
    );
    assert!(
        !out.contains("No counted associations"),
        "no replaced-file line without replaced files: {out}"
    );
}

/// F1 guard: the notices belong to the empty view only; a capture
/// with edges keeps the gaps block as the replaced-file disclosure.
#[test]
fn nonempty_inventory_with_replaced_files_adds_no_not_counted_lines() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    assert!(!presentation.edges.is_empty(), "the twin needs edges");
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: Some(70_000),
        subject: "/prov/libsofthsm2.so (deleted)".into(),
        reason: "replaced on disk while running; not examined, calls not counted".into(),
        budget: None,
        repeats: 1,
    });
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        !out.contains("No counted associations"),
        "no absence line with edges: {out}"
    );
    assert!(
        !out.contains("not counted:"),
        "no not-counted lines with edges: {out}"
    );
}

/// F1: the notices fold past twenty entries; `--json` keeps every item.
#[test]
fn replaced_notices_fold_beyond_twenty() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.edges.clear();
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    for index in 0..21 {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: Some(80_000 + index),
            subject: format!("/prov/file{index}.so (deleted)"),
            reason: "replaced on disk while running; not examined, calls not counted".into(),
            budget: None,
            repeats: 1,
        });
    }
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        out.contains("No counted associations; 21 programs run files replaced on disk (below)."),
        "the absence line counts every program: {out}"
    );
    assert_eq!(
        out.lines()
            .filter(|line| line.starts_with("not counted:"))
            .count(),
        20,
        "twenty notices print: {out}"
    );
    assert!(
        out.contains("  and 1 more replaced file (--json has every item)"),
        "the remainder folds: {out}"
    );
}

/// F2: twenty-two notices fold with the plural remainder line.
#[test]
fn replaced_notices_fold_uses_plural_beyond_twenty_one() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.edges.clear();
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    for index in 0..22 {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: Some(80_000 + index),
            subject: format!("/prov/file{index}.so (deleted)"),
            reason: "replaced on disk while running; not examined, calls not counted".into(),
            budget: None,
            repeats: 1,
        });
    }
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        out.contains("No counted associations; 22 programs run files replaced on disk (below)."),
        "the absence line counts every program: {out}"
    );
    assert_eq!(
        out.lines()
            .filter(|line| line.starts_with("not counted:"))
            .count(),
        20,
        "twenty notices print: {out}"
    );
    assert!(
        out.contains("  and 2 more replaced files (--json has every item)"),
        "the remainder folds with the plural line: {out}"
    );
    assert!(
        !out.contains("1 more replaced file ("),
        "the singular line stays away from a plural remainder: {out}"
    );
}

/// F2: two gaps with the same (program, file) pair print one notice.
#[test]
fn replaced_notices_deduplicate_same_program_and_file() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.edges.clear();
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    for _ in 0..2 {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: Some(80_000),
            subject: "/prov/dup.so (deleted)".into(),
            reason: "replaced on disk while running; not examined, calls not counted".into(),
            budget: None,
            repeats: 1,
        });
    }
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: Some(80_001),
        subject: "/prov/other.so (deleted)".into(),
        reason: "replaced on disk while running; not examined, calls not counted".into(),
        budget: None,
        repeats: 1,
    });
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        out.contains("No counted associations; 2 programs run files replaced on disk (below)."),
        "the absence line counts both programs: {out}"
    );
    assert_eq!(
        out.lines()
            .filter(|line| line.starts_with("not counted:"))
            .count(),
        2,
        "the duplicated pair prints once, the distinct pair prints too: {out}"
    );
    assert_eq!(
        out.lines()
            .filter(|line| line.starts_with("not counted:") && line.contains("/prov/dup.so"))
            .count(),
        1,
        "the duplicated pair names one notice line: {out}"
    );
}

/// F2: a replaced gap without caller or pid names an unknown program,
/// while a caller without a pid keeps its retained pid.
#[test]
fn replaced_notices_name_unknown_program_and_retained_pid() {
    let harness = varied_harness();
    let caller = harness.coordinator().adapter().live_id(70_000).unwrap();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.edges.clear();
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "/prov/ghost.so (deleted)".into(),
        reason: "replaced on disk while running; not examined, calls not counted".into(),
        budget: None,
        repeats: 1,
    });
    presentation.gaps.push(GapView {
        caller: Some(caller),
        module: None,
        pid: None,
        subject: "/prov/retained.so (deleted)".into(),
        reason: "replaced on disk while running; not examined, calls not counted".into(),
        budget: None,
        repeats: 1,
    });
    let out = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        out.contains("No counted associations; 2 programs run files replaced on disk (below)."),
        "the absence line counts both programs: {out}"
    );
    assert!(
        out.contains("not counted: an unknown program runs /prov/ghost.so (deleted)"),
        "the caller-less pid-less gap names an unknown program: {out}"
    );
    assert!(
        out.contains("not counted: driver (PID 70000) runs /prov/retained.so (deleted)"),
        "the caller without a pid keeps its retained pid: {out}"
    );
}

/// v0.7.0 demo: the per-pass kernel-thread absence notes (rc-11 showed
/// five lines for 108/109/121/122/123) fold into one concise line that
/// carries the summed examination total, never a max. The header still
/// counts every retained row; verbose keeps every row; JSON keeps every
/// record.
#[test]
fn concise_gap_summary_folds_kernel_thread_notes_with_summed_total() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    for absences in [108u64, 109, 121, 122, 123] {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: None,
            subject: "kernel threads".into(),
            reason: format!(
                "{absences} processes examined are kernel threads with no user memory to scan"
            ),
            budget: None,
            repeats: 1,
        });
    }
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "short-lived processes never scanned".into(),
        reason: "179 short-lived process(es) started and exited before a completed pass".into(),
        budget: None,
        repeats: 1,
    });
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        concise.contains(
            "  5 × kernel threads — 583 processes examined are kernel threads with no user memory to scan"
        ),
        "one folded line carries the summed total:\n{concise}"
    );
    for count in [108u64, 109, 121, 122, 123] {
        assert!(
            !concise.contains(&format!("{count} processes examined")),
            "pass count {count} folds away:\n{concise}"
        );
    }
    assert!(
        concise.lines().any(|line| line == "gaps: 6"),
        "the header still counts every retained row:\n{concise}"
    );
    assert!(
        concise.contains("179 short-lived process(es) started and exited before a completed pass"),
        "other subjects keep their own lines:\n{concise}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    for count in [108u64, 109, 121, 122, 123] {
        assert!(
            verbose.contains(&format!("{count} processes examined")),
            "verbose keeps the pass row {count}:\n{verbose}"
        );
    }
    let document = crate::inventory::render_json_from_presentation(&presentation);
    let gaps = document["gaps"]
        .as_array()
        .expect("JSON keeps a gaps array");
    assert_eq!(gaps.len(), 6, "JSON keeps every record: {document}");
}

/// The kernel-thread fold multiplies by `repeats` (an identical row
/// recorded twice examined twice its count) and folds the singular
/// producer template with the plural one.
#[test]
fn concise_kernel_thread_fold_sums_repeats_and_singular_template() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "kernel threads".into(),
        reason: "108 processes examined are kernel threads with no user memory to scan".into(),
        budget: None,
        repeats: 2,
    });
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "kernel threads".into(),
        reason: "1 process examined is a kernel thread with no user memory to scan".into(),
        budget: None,
        repeats: 1,
    });
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        concise.contains(
            "  2 × kernel threads — 217 processes examined are kernel threads with no user memory to scan"
        ),
        "two rows fold with repeats multiplied (108x2 + 1):\n{concise}"
    );
}

/// The kernel-thread fold is narrow: an unparsable kernel-thread
/// reason, an attributed kernel-thread row, and same-shaped numeric
/// reasons under any other subject all keep their own lines.
#[test]
fn concise_kernel_thread_fold_keeps_other_reasons_separate() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "kernel threads".into(),
        reason: "kthreads seen: many".into(),
        budget: None,
        repeats: 1,
    });
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: Some(4321),
        subject: "kernel threads".into(),
        reason: "7 processes examined are kernel threads with no user memory to scan".into(),
        budget: None,
        repeats: 1,
    });
    for count in [3u64, 5] {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: None,
            subject: "widget scans".into(),
            reason: format!("{count} widgets scanned this pass"),
            budget: None,
            repeats: 1,
        });
    }
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        concise.contains("kthreads seen: many"),
        "an unparsable kernel-thread reason keeps its line:\n{concise}"
    );
    assert!(
        concise.contains("7 processes examined are kernel threads"),
        "an attributed kernel-thread row keeps its line:\n{concise}"
    );
    for count in [3u64, 5] {
        assert!(
            concise.contains(&format!("{count} widgets scanned this pass")),
            "other numeric subjects never fold ({count}):\n{concise}"
        );
    }
    assert!(
        !concise.contains("8 widgets scanned"),
        "no summed line for other subjects:\n{concise}"
    );
}

/// v0.7.0 demo: the concise key-operations line already states that
/// per-key tracking is off, so the concise gaps block shows it once —
/// on that line, never again as a gap. The seal/fallback gaps still
/// show; verbose and JSON keep the journal row.
#[test]
fn concise_gap_summary_shows_per_key_off_once() {
    let harness = varied_harness();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.gaps.clear();
    presentation.gaps_suppressed = 0;
    presentation.object_observations =
        crate::key_operation_projection::ObjectObservations::unavailable(7, "journal_unavailable");
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "per-key tracking is off; this capture keeps S1 mechanisms and API results".into(),
        reason: "joint_journal_unavailable".into(),
        budget: None,
        repeats: 1,
    });
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "Joint key operations unavailable; retained S1".into(),
        reason: "joint_seal_h3_loss_history_loss".into(),
        budget: None,
        repeats: 1,
    });
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        concise.contains("key operations: not reported (per-key tracking is off)"),
        "the key-operations line states it:\n{concise}"
    );
    assert_eq!(
        concise.matches("per-key tracking is off").count(),
        1,
        "concise states it exactly once:\n{concise}"
    );
    assert!(
        concise.contains("per-key tracking ended early"),
        "the seal gap still shows:\n{concise}"
    );
    assert!(
        concise.lines().any(|line| line == "gaps: 2"),
        "the header still counts every retained row:\n{concise}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        verbose.contains("per-key tracking is off in this run"),
        "verbose keeps the journal row:\n{verbose}"
    );
    let document = crate::inventory::render_json_from_presentation(&presentation);
    let gaps = document["gaps"]
        .as_array()
        .expect("JSON keeps a gaps array");
    assert_eq!(gaps.len(), 2, "JSON keeps every record: {document}");
}
