//! SPDX-License-Identifier: GPL-3.0-or-later
//! U0 presentation tests: ONE model for JSON and snapshots (A1/A2),
//! exact dashboard vocabulary with its distinctions (B2), and the
//! withheld semantic column (B3). JSON-vs-snapshot agreement is pinned
//! by parsing, not eyeballing.

use super::*;
use crate::discovery::caller_registry::{
    AdmissionState, CallerId, ImageAuthority, ModuleInfo, ModuleKey, RegistryLimits,
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
    Presentation::capture(
        harness.coordinator(),
        "workload",
        started,
        ended,
        passes,
        ended,
        ended.saturating_sub(started),
    )
}

#[test]
fn state_vocab_is_the_plans_exact_wording() {
    assert_eq!(Presence::Mapped.label(), "mapped");
    assert_eq!(Presence::Unloaded.label(), "unloaded");
    assert_eq!(Presence::ProcessExited.label(), "process exited");
    assert_eq!(Presence::Unknown.label(), "unknown");
    assert_eq!(Capture::Armed.label(), "armed");
    assert_eq!(Capture::Refused.label(), "refused");
    assert_eq!(Capture::Retired.label(), "retired");
    assert_eq!(Capture::CoverageLost.label(), "coverage lost");
    assert_eq!(Activity::RecentlyObserved.label(), "recently observed");
    assert_eq!(
        Activity::InFlight.label(),
        "operation initialized / in flight"
    );
    assert_eq!(Activity::Quiet.label(), "quiet");
    assert_eq!(Activity::Unknown.label(), "unknown");
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
    // is mapped and quiet, and renders all three states.
    assert_eq!(edge.presence, Presence::Mapped);
    assert_eq!(edge.capture, Capture::Refused);
    assert_eq!(edge.activity, Activity::Quiet);
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
    assert!(line.contains("activity quiet"), "{line}");
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
    // Baseline: mapped and quiet.
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
    // c0: entries observed now (recent). c1: in flight. c2: silent.
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
    let c2 = harness.coordinator().adapter().live_id(72_002).unwrap();
    assert_eq!(activity(c2), Activity::Quiet);
    // An old entry outside the window reads as quiet, not recent.
    let stale = Presentation::capture(
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
    let budgets = lines[1];
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
        .filter(|edge| edge.presence == Presence::Mapped && edge.activity == Activity::Quiet)
        .collect();
    assert!(!quiet_mapped.is_empty(), "varied fixture has quiet edges");
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
