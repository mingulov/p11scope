//! SPDX-License-Identifier: GPL-3.0-or-later
//! Positive projections, uncertainty, multiplicity and canonical output.
use super::{
    compare::compare,
    input::{self, Snapshot},
    model::{self, Presence, Side, UnresolvedKind},
};
use serde_json::{Value, json};

fn module_fact(s: &model::SnapshotSummary, r: model::ModuleRef) -> &model::ModuleEvidence {
    &s.evidence.modules[r.0]
}
fn caller_fact(s: &model::SnapshotSummary, r: model::CallerRef) -> &model::CallerEvidence {
    &s.evidence.callers[r.0]
}
fn edge_fact(s: &model::SnapshotSummary, r: model::EdgeRef) -> &model::EdgeEvidence {
    &s.evidence.edges[r.0]
}
fn app_path<'a>(r: &'a model::DiffReport, a: &model::ApplicationChange) -> &'a str {
    &r.comparison.application_paths[a.key.exe_path_ref.0]
}

const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/inventory-diff/scan-current.json");
fn document() -> Value {
    serde_json::from_slice(FIXTURE).unwrap()
}
fn snapshot(v: &Value) -> Snapshot {
    input::parse_snapshot(&serde_json::to_vec(v).unwrap()).unwrap()
}
fn base() -> Snapshot {
    snapshot(&document())
}
fn label(raw: &str, known: bool) -> input::Label {
    input::Label {
        raw: raw.to_owned(),
        known,
    }
}
fn empty() -> Snapshot {
    let mut s = base();
    s.callers.clear();
    s.modules.clear();
    s.edges.clear();
    s.gaps.clear();
    s.gaps_suppressed = 0;
    s.budgets.callers.occupied = 0;
    s.budgets.modules.occupied = 0;
    s.budgets.edges.occupied = 0;
    s.budgets.endpoints.occupied = 0;
    s.budgets.semantic_state.unknown_edges = 0;
    s.budgets.retained_history.retained = 0;
    s
}
fn counted(s: &mut Snapshot, count: u64, lossy: bool) {
    s.edges[0].entries.count = count;
    s.edges[0].entries.observation = label("observed", true);
    s.edges[0].coverage = Some(input::Coverage {
        state: label("counted", true),
        since_ns: Some(110),
        until_ns: None,
        first_ns: None,
        lossy: Some(lossy),
        reason: None,
        detail: None,
    });
}

#[test]
fn common_content_with_changed_paths_is_useful() {
    let before = base();
    let mut after = before.clone();
    after.modules[0].paths = vec!["/new/lib.so".into()];
    let report = compare(&before, &after);
    assert_eq!(
        (
            report.summary.content_both,
            report.summary.content_before_only,
            report.summary.content_after_only
        ),
        (1, 0, 0)
    );
    assert_eq!(report.module_contents.len(), 1);
    assert_eq!(report.module_contents[0].presence, Presence::Both);
    assert_eq!(report.module_contents[0].changes, vec!["paths"]);
    assert_eq!(report.application_changes.len(), 1);
    assert_eq!(
        app_path(&report, &report.application_changes[0]),
        "/bin/driver"
    );
    assert_eq!(report.application_changes[0].changes, vec!["paths"]);
    assert_eq!(report.module_path_changes.len(), 2);
    assert_eq!(report.summary.module_paths_changed, 2);
}

#[test]
fn different_digest_at_one_path_has_two_presence_rows_and_one_application() {
    let before = base();
    let mut after = before.clone();
    after.modules[0].sha256 = Some("b".repeat(64));
    let report = compare(&before, &after);
    assert_eq!(
        (
            report.summary.content_both,
            report.summary.content_before_only,
            report.summary.content_after_only
        ),
        (0, 1, 1)
    );
    assert_eq!(
        (
            report.summary.application_groups_compared,
            report.summary.application_groups_changed
        ),
        (1, 1)
    );
    assert_eq!(report.application_changes.len(), 2);
    assert!(
        report
            .application_changes
            .iter()
            .any(|r| r.presence == Presence::BeforeOnly)
    );
    assert!(
        report
            .application_changes
            .iter()
            .any(|r| r.presence == Presence::AfterOnly)
    );
    assert_eq!(report.module_path_changes.len(), 1);
    let row = &report.module_path_changes[0];
    assert_eq!(row.key.path, "/scale/m0.so");
    assert_eq!(row.presence, Presence::Both);
    assert_eq!(row.changes, vec!["content_presence"]);
    assert_eq!(row.before[0].sha256, before.modules[0].sha256);
    assert_eq!(row.after[0].sha256, after.modules[0].sha256);
}

#[test]
fn equal_digest_different_inodes_preserves_physical_records_and_edge_counts() {
    let mut before = base();
    counted(&mut before, 128, false);
    let mut after = before.clone();
    let mut second = after.modules[0].clone();
    second.inode = 200000;
    second.paths = vec!["/copy/lib.so".into()];
    after.modules.push(second);
    after.edges[0].entries.count = 24;
    let mut edge = after.edges[0].clone();
    edge.module = 1;
    edge.entries.count = 16;
    after.edges.push(edge);
    let report = compare(&before, &after);
    let content = &report.module_contents[0];
    assert_eq!(content.presence, Presence::Both);
    assert_eq!(content.before.len(), 1);
    assert_eq!(content.after.len(), 2);
    assert_eq!(
        content
            .after
            .iter()
            .map(|m| module_fact(&report.after, *m).identity.inode)
            .collect::<Vec<_>>(),
        vec![100000, 200000]
    );
    let application = &report.application_changes[0];
    assert_eq!(
        application
            .before
            .iter()
            .map(|e| edge_fact(&report.before, *e).entries.count)
            .collect::<Vec<_>>(),
        vec![128]
    );
    assert_eq!(
        application
            .after
            .iter()
            .map(|e| edge_fact(&report.after, *e).entries.count)
            .collect::<Vec<_>>(),
        vec![24, 16]
    );
    assert!(application.changes.contains(&"physical_records"));
}

#[test]
fn unknown_digest_never_matches_by_path_or_build_id() {
    let mut before = base();
    before.modules[0].sha256 = None;
    before.modules[0].build_id = Some("shared build id".into());
    let after = before.clone();
    let report = compare(&before, &after);
    assert!(report.module_contents.is_empty());
    assert!(report.application_changes.is_empty());
    assert_eq!(report.unresolved.len(), 4);
    assert_eq!(report.summary.unresolved_observations, 4);
    assert_eq!(
        report
            .unresolved
            .iter()
            .filter(|r| r.kind == UnresolvedKind::Module)
            .count(),
        2
    );
    assert_eq!(
        report
            .unresolved
            .iter()
            .filter(|r| r.kind == UnresolvedKind::Edge)
            .count(),
        2
    );
    assert!(
        report
            .unresolved
            .iter()
            .all(|r| r.reasons.contains(&"missing_module_digest"))
    );
    assert!(report.unresolved.iter().any(|r| r.side == Side::Before));
    assert!(report.unresolved.iter().any(|r| r.side == Side::After));
}

#[test]
fn equal_basename_at_different_executable_paths_is_two_groups() {
    let mut v = matrix_document(2, 1, 1);
    v["callers"][0]["image"]["exe"]["path"] = json!("/apps/one/driver");
    v["callers"][1]["image"]["exe"]["path"] = json!("/apps/two/driver");
    let before = snapshot(&v);
    let mut after = before.clone();
    after.edges[0].entries.count = 10;
    after.edges[1].entries.count = 20;
    let report = compare(&before, &after);
    assert_eq!(report.summary.application_groups_compared, 2);
    assert_eq!(report.summary.application_groups_changed, 2);
    assert_eq!(
        report
            .application_changes
            .iter()
            .map(|r| app_path(&report, r))
            .collect::<Vec<_>>(),
        vec!["/apps/one/driver", "/apps/two/driver"]
    );
}

#[test]
fn missing_and_empty_executable_paths_remain_unresolved() {
    for variant in 0..3 {
        let mut before = base();
        match variant {
            0 => before.callers[0].image.exe = None,
            1 => before.callers[0].image.exe.as_mut().unwrap().path = None,
            _ => before.callers[0].image.exe.as_mut().unwrap().path = Some(String::new()),
        };
        let report = compare(&before, &before);
        assert_eq!(report.summary.application_groups_compared, 0);
        assert!(report.application_changes.is_empty());
        assert_eq!(report.unresolved.len(), 2);
        assert!(
            report
                .unresolved
                .iter()
                .all(|r| r.kind == UnresolvedKind::Edge)
        );
        assert!(
            report
                .unresolved
                .iter()
                .all(|r| r.reasons.contains(&"missing_executable_path"))
        );
        assert_eq!(report.module_contents.len(), 1);
    }
}

#[test]
fn callers_without_edges_are_visible_as_unresolved() {
    let mut before = base();
    before.edges.clear();
    let report = compare(&before, &before);
    assert_eq!(report.unresolved.len(), 2);
    assert!(
        report
            .unresolved
            .iter()
            .all(|r| r.kind == UnresolvedKind::Caller)
    );
    assert!(
        report
            .unresolved
            .iter()
            .all(|r| r.reasons.contains(&"no_module_observation"))
    );
}

#[test]
fn identical_numeric_identities_never_establish_continuity() {
    let before = base();
    let report = compare(&before, &before);
    assert_eq!(report.comparison.host_relation, "unknown");
    assert_eq!(report.comparison.boot_relation, "unknown");
    assert_eq!(report.comparison.process_continuity, "unknown");
    assert_eq!(report.comparison.physical_continuity, "unknown");
    assert_eq!(report.comparison.counter_relation, "independent_windows");
    assert_eq!(report.comparison.scope_relation, "same_recorded_label");
    assert!(report.application_changes.is_empty());
    assert!(report.module_path_changes.is_empty());
    assert_eq!(report.module_contents[0].presence, Presence::Both);
}

#[test]
fn equal_and_different_scope_labels_both_keep_completeness_unknown() {
    let before = empty();
    let mut after = before.clone();
    assert_eq!(
        compare(&before, &after).comparison.scope_relation,
        "same_recorded_label"
    );
    after.scope = "system".into();
    let report = compare(&before, &after);
    assert_eq!(
        report.comparison.scope_relation,
        "different_recorded_labels"
    );
    assert_eq!(report.before.scope_completeness, "unknown");
    assert_eq!(report.after.scope_completeness, "unknown");
    assert_eq!(
        (report.before.reported_gaps, report.after.reported_gaps),
        (0, 0)
    );
    assert!(
        report
            .limitations
            .contains(&"scope_completeness_unknown".into())
    );
}

#[test]
fn partial_presence_and_absence_are_only_observations() {
    let before = base();
    let mut after = empty();
    after.scope = "system".into();
    after.gaps_suppressed = 3;
    after.budgets.callers.refused = 2;
    let report = compare(&before, &after);
    assert_eq!(report.module_contents[0].presence, Presence::BeforeOnly);
    assert_eq!(report.application_changes[0].presence, Presence::BeforeOnly);
    assert_eq!(report.after.suppressed_gaps, 3);
    assert_eq!(report.after.refusals.budget_counters["callers"], Some(2));
    assert_eq!(report.after.scope_completeness, "unknown");
    assert!(
        report
            .limitations
            .contains(&"absence_is_not_removal".into())
    );
    let serialized = serde_json::to_value(&report).unwrap();
    assert!(
        serialized["application_changes"][0]
            .get("removed")
            .is_none()
    );
    let reverse = compare(&after, &before);
    assert_eq!(reverse.module_contents[0].presence, Presence::AfterOnly);
}

#[test]
fn independent_counts_are_preserved_without_subtraction() {
    let mut before = base();
    counted(&mut before, 128, false);
    let mut after = before.clone();
    after.edges[0].entries.count = 24;
    let report = compare(&before, &after);
    let row = &report.application_changes[0];
    assert_eq!(row.changes, vec!["entries"]);
    assert_eq!(edge_fact(&report.before, row.before[0]).entries.count, 128);
    assert_eq!(edge_fact(&report.after, row.after[0]).entries.count, 24);
    let raw = serde_json::to_string(&report).unwrap();
    assert!(!raw.contains("delta"));
    assert!(!raw.contains("-104"));
}

#[test]
fn coverage_missing_witnessed_lossy_pending_and_saturation_stay_distinct() {
    let before = base();
    for variant in [
        "missing",
        "witnessed",
        "counted_lossy",
        "pending_first_use",
        "saturated",
        "future_coverage",
        "watched_no_use",
    ] {
        let mut after = before.clone();
        match variant {
            "missing" => after.edges[0].coverage = None,
            "witnessed" => {
                let c = after.edges[0].coverage.as_mut().unwrap();
                c.state = label("witnessed", true);
                c.first_ns = Some(123);
                c.reason = None;
                after.edges[0].entries.observation =
                    label("unknown (count unavailable; use witnessed)", true);
            }
            "counted_lossy" => counted(&mut after, 24, true),
            "pending_first_use" => {
                let c = after.edges[0].coverage.as_mut().unwrap();
                c.reason = Some(label("pending_first_use", true));
            }
            "saturated" => {
                counted(&mut after, u64::MAX, false);
                after.edges[0].entries.saturated = true;
            }
            "future_coverage" => {
                after.edges[0].coverage.as_mut().unwrap().state = label("future_coverage", false);
            }
            _ => {
                let c = after.edges[0].coverage.as_mut().unwrap();
                c.state = label("watched_no_use", true);
                c.since_ns = Some(110);
                c.until_ns = Some(190);
                c.reason = None;
                after.edges[0].entries.observation = label("observed", true);
            }
        }
        let report = compare(&before, &after);
        assert_eq!(report.application_changes.len(), 1, "{variant}");
        let fact = edge_fact(&report.after, report.application_changes[0].after[0]);
        assert!(
            report.application_changes[0].changes.contains(&"coverage"),
            "{variant}"
        );
        assert_eq!(fact.coverage, after.edges[0].coverage);
        assert_eq!(fact.entries, after.edges[0].entries);
    }
}

#[test]
fn root_evidence_is_preserved_and_gap_references_are_resolved() {
    let mut v = document();
    v["gaps"][0]["budget"] =
        json!({"resource":"inventory_endpoints","limit":4096,"requested":4100});
    v["gaps"][0]["repeats"] = json!(9);
    v["gaps_suppressed"] = json!(7);
    v["observation"]["lane"] = json!("native");
    v["observation"]["settlement"] = json!("unsettled");
    v["observation"]["retirement"] = json!("unsettled");
    v["observation"]["lifecycle"] =
        json!({"records":3,"ring_loss":2,"malformed":1,"failed_quanta":1,"recovery_rescans":1});
    v["observation"]["native_witnesses"]["integrity"] = json!(4);
    v["budgets"]["inventory_endpoints"]
        .as_object_mut()
        .unwrap()
        .remove("refused");
    let s = snapshot(&v);
    let report = compare(&s, &s);
    let side = &report.before;
    assert_eq!(side.observation, s.observation);
    assert_eq!(side.budgets, s.budgets);
    assert_eq!(side.pid_namespace, s.pid_namespace);
    assert_eq!(side.clock, s.clock);
    assert_eq!(
        (
            side.reported_gaps,
            side.suppressed_gaps,
            side.refusals.reported_budget_gaps
        ),
        (1, 7, 1)
    );
    assert_eq!(side.refusals.budget_counters["inventory_endpoints"], None);
    assert_eq!(side.loss_evidence.lifecycle.as_ref().unwrap().ring_loss, 2);
    assert_eq!(
        side.loss_evidence
            .native_witnesses
            .as_ref()
            .unwrap()
            .integrity,
        4
    );
    let gap = &side.gaps[0];
    assert_eq!(gap.repeats, 9);
    assert_eq!(caller_fact(side, gap.caller.unwrap()).pid, 4242);
    assert_eq!(
        module_fact(side, gap.module.unwrap()).identity.inode,
        100000
    );
    let json = serde_json::to_value(&report).unwrap();
    let caller_ref = json["before"]["gaps"][0]["caller"].as_u64().unwrap() as usize;
    assert_eq!(
        json["before"]["evidence"]["callers"][caller_ref]["image"]["exe"]["path"],
        "/bin/driver"
    );
    assert!(json["before"]["gaps"][0]["caller"].get("id").is_none());
    assert!(json["before"].get("filename").is_none());
}

#[test]
fn population_duplicates_are_multisets_and_counts_are_not_aggregated() {
    let mut before = base();
    counted(&mut before, 128, false);
    let mut after = before.clone();
    after.callers.push(after.callers[0].clone());
    let mut edge = after.edges[0].clone();
    edge.caller = 1;
    after.edges.push(edge);
    let report = compare(&before, &after);
    let row = &report.application_changes[0];
    assert_eq!(row.before.len(), 1);
    assert_eq!(row.after.len(), 2);
    assert!(row.changes.contains(&"caller_population"));
    assert_eq!(
        row.after
            .iter()
            .map(|e| edge_fact(&report.after, *e).entries.count)
            .collect::<Vec<_>>(),
        vec![128, 128]
    );
}

#[test]
fn swapping_counts_between_known_observations_is_detected() {
    let mut v = matrix_document(2, 2, 1);
    for caller in v["callers"].as_array_mut().unwrap() {
        caller["image"]["exe"]["path"] = json!("/bin/driver");
    }
    let digest = v["modules"][0]["identity"]["sha256"].clone();
    v["modules"][1]["identity"]["sha256"] = digest;
    let mut before = snapshot(&v);
    before.edges[0].entries.count = 128;
    before.edges[1].entries.count = 24;
    let mut after = before.clone();
    after.edges[0].entries.count = 24;
    after.edges[1].entries.count = 128;
    let report = compare(&before, &after);
    assert_eq!(report.application_changes.len(), 1);
    assert!(report.application_changes[0].changes.contains(&"entries"));
    assert_eq!(
        report.application_changes[0]
            .before
            .iter()
            .map(|e| {
                let e = edge_fact(&report.before, *e);
                (caller_fact(&report.before, e.caller).pid, e.entries.count)
            })
            .collect::<Vec<_>>(),
        vec![(5000, 128), (5001, 24)]
    );
}

#[test]
fn changing_only_times_and_local_incarnations_is_not_an_application_change() {
    let mut before = base();
    counted(&mut before, 128, false);
    before.modules[0].admission.history = Some(vec![input::AdmissionChange {
        from: label("refused", true),
        to: label("admitted", true),
        at_ns: 111,
    }]);
    before.modules[0].unbound_use = Some(input::UnboundUse {
        first_ns: 111,
        rows: 1,
        reasons: [("no_live_caller".into(), 1)].into_iter().collect(),
    });
    let mut after = before.clone();
    after.observation.started_ns = 10000;
    after.observation.ended_ns = 20000;
    after.callers[0].first_seen_ns = 10100;
    after.callers[0].last_seen_ns = 19000;
    after.callers[0].incarnation = 900;
    after.callers[0].image.task_cookie = Some(42);
    after.callers[0].image.exec_id = Some(8);
    after.modules[0].admission.history.as_mut().unwrap()[0].at_ns = 11000;
    after.modules[0].unbound_use.as_mut().unwrap().first_ns = 11000;
    after.edges[0].mapping.first_seen_ns = 10100;
    after.edges[0].mapping.last_seen_ns = 19000;
    after.edges[0].entries.first_seen_ns = Some(11000);
    after.edges[0].entries.last_seen_ns = Some(19000);
    after.edges[0].coverage.as_mut().unwrap().since_ns = Some(10100);
    let report = compare(&before, &after);
    assert!(report.application_changes.is_empty());
    assert!(report.module_contents[0].changes.is_empty());
    assert_eq!(
        module_fact(&report.after, report.module_contents[0].after[0])
            .unbound_use
            .as_ref()
            .unwrap()
            .first_ns,
        11000
    );
    assert_eq!(report.after.observation.started_ns, 10000);
}

#[test]
fn normalized_evidence_fields_produce_sorted_reason_codes() {
    for code in [
        "paths",
        "caller_population",
        "physical_records",
        "admission",
        "mapping",
        "lifecycle",
        "coverage",
        "entries",
        "semantics",
    ] {
        let before = base();
        let mut after = before.clone();
        match code {
            "paths" => after.modules[0].paths.push("/alias/lib.so".into()),
            "caller_population" => after.callers[0].pid = 6000,
            "physical_records" => after.modules[0].inode = 200000,
            "admission" => after.modules[0].admission.state = label("refused", true),
            "mapping" => after.edges[0].mapping.state = label("uncertain", true),
            "lifecycle" => after.callers[0].lifecycle = label("exited", true),
            "coverage" => {
                after.edges[0].coverage.as_mut().unwrap().reason = Some(label("loss", true))
            }
            "entries" => after.edges[0].entries.count = 17,
            _ => after.edges[0].semantics = label("observed", true),
        }
        let report = compare(&before, &after);
        assert_eq!(report.application_changes.len(), 1, "{code}");
        let changes = &report.application_changes[0].changes;
        assert!(changes.contains(&code), "{code}: {changes:?}");
        let mut sorted = changes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(&sorted, changes);
    }
}

#[test]
fn unanalysed_instance_and_semantic_details_do_not_duplicate_physical_counts() {
    let mut before = document();
    before["edges"][0]["semantics"] = json!("observed");
    before["edges"][0]["entries"]["count"] = json!(128);
    before["edges"][0]["mechanisms"] = json!([{"mechanism":1,"mechanism_hex":"0x1","name":null,"operations":["sign"],"calls":3,"errors":0,"last_seen_ns":190,"evidence":{"functions":["C_Sign"],"returns":[],"truncated":false}}]);
    before["future_instance_records"] = json!([{"load":1},{"load":2}]);
    before["future_semantic_edges"] = json!([{"load":1,"calls":55}]);
    let mut after = before.clone();
    after["edges"][0]["mechanisms"][0]["calls"] = json!(999);
    after["future_instance_records"] = json!([{"load":8}]);
    after["future_semantic_edges"] = json!([{"load":8,"calls":900}]);
    let before = snapshot(&before);
    let after = snapshot(&after);
    let report = compare(&before, &after);
    assert!(report.application_changes.is_empty());
    assert!(
        report
            .limitations
            .contains(&"semantic_details_not_compared".into())
    );
    assert_eq!(report.summary.content_both, 1);
    let mut changed = after;
    changed.edges[0].entries.count = 24;
    let report = compare(&before, &changed);
    assert_eq!(report.application_changes[0].before.len(), 1);
    assert_eq!(
        edge_fact(&report.before, report.application_changes[0].before[0])
            .entries
            .count,
        128
    );
    assert_eq!(
        edge_fact(&report.after, report.application_changes[0].after[0])
            .entries
            .count,
        24
    );
    let raw = serde_json::to_string(&report).unwrap();
    for field in [
        "future_instance_records",
        "future_semantic_edges",
        "mechanisms",
        "operations",
    ] {
        assert!(!raw.contains(field), "{field}");
    }
}

#[test]
fn row_reordering_id_renaming_and_path_set_permutations_are_byte_stable() {
    let mut before = matrix_document(3, 3, 2);
    before["gaps"] = json!([
        {"caller":"c1","module":"m1","pid":5001,"subject":"fixture second","reason":"reason two","budget":null,"repeats":2},
        {"caller":"c0","module":"m0","pid":5000,"subject":"fixture first","reason":"reason one","budget":null,"repeats":1}
    ]);
    let mut after = before.clone();
    after["edges"][0]["entries"]["count"] = json!(42);
    let expected = serde_json::to_vec(&compare(&snapshot(&before), &snapshot(&after))).unwrap();
    let transformed_before = permuted(before);
    let transformed_after = permuted(after);
    assert_eq!(
        serde_json::to_vec(&compare(
            &snapshot(&transformed_before),
            &snapshot(&transformed_after)
        ))
        .unwrap(),
        expected
    );
}

#[test]
fn equivalent_fact_ties_use_full_evidence_and_keep_multiplicity() {
    let mut before = base();
    let mut caller = before.callers[0].clone();
    caller.first_seen_ns = 99;
    before.callers.push(caller);
    let mut edge = before.edges[0].clone();
    edge.caller = 1;
    before.edges.push(edge);
    let mut after = before.clone();
    after.edges[0].entries.count = 42;
    after.edges[1].entries.count = 42;
    let expected = serde_json::to_vec(&compare(&before, &after)).unwrap();
    before.callers.swap(0, 1);
    after.callers.swap(0, 1);
    for s in [&mut before, &mut after] {
        s.edges.reverse();
        for e in &mut s.edges {
            e.caller = 1 - e.caller;
        }
        for g in &mut s.gaps {
            g.caller = g.caller.map(|i| 1 - i);
        }
    }
    let report = compare(&before, &after);
    assert_eq!(serde_json::to_vec(&report).unwrap(), expected);
    assert_eq!(report.application_changes[0].before.len(), 2);
    assert_eq!(report.application_changes[0].after.len(), 2);
}

#[test]
fn public_root_keys_and_mandatory_limitations_are_stable() {
    let report = compare(&empty(), &empty());
    let v = serde_json::to_value(&report).unwrap();
    assert_eq!(v["schema"], "p11scope/inventory-diff/v1");
    assert_eq!(
        v.as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec![
            "after",
            "application_changes",
            "before",
            "comparison",
            "limitations",
            "module_contents",
            "module_path_changes",
            "schema",
            "summary",
            "unresolved"
        ]
    );
    let mut sorted = report.limitations.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted, report.limitations);
    assert!(sorted.contains(&"semantic_details_not_compared".to_owned()));
}

fn matrix_document(callers: usize, modules: usize, fanout: usize) -> Value {
    let mut v = document();
    let caller = v["callers"][0].clone();
    let module = v["modules"][0].clone();
    let edge = v["edges"][0].clone();
    v["callers"] = Value::Array(
        (0..callers)
            .map(|i| {
                let mut c = caller.clone();
                c["id"] = json!(format!("c{i}"));
                c["pid"] = json!(5000 + i);
                c["start_time"] = json!(1000 + i);
                c["image"]["exe"]["path"] = json!(format!("/apps/{i}/driver"));
                c
            })
            .collect(),
    );
    v["modules"] = Value::Array(
        (0..modules)
            .map(|i| {
                let mut m = module.clone();
                m["id"] = json!(format!("m{i}"));
                m["identity"]["inode"] = json!(100000 + i);
                m["identity"]["sha256"] = json!(format!("{:064x}", i + 1));
                m["paths"] = json!([format!("/mods/lib{i}.so"), format!("/alias/lib{i}.so")]);
                m
            })
            .collect(),
    );
    let mut edges = Vec::new();
    for c in 0..callers {
        for k in 0..fanout {
            let mut e = edge.clone();
            e["caller"] = json!(format!("c{c}"));
            e["module"] = json!(format!("m{}", (c + k) % modules));
            edges.push(e);
        }
    }
    v["edges"] = Value::Array(edges);
    v["gaps"] = json!([]);
    v["budgets"]["callers"]["occupied"] = json!(callers);
    v["budgets"]["modules"]["occupied"] = json!(modules);
    v["budgets"]["edges"]["occupied"] = json!(callers * fanout);
    v
}
fn permuted(mut v: Value) -> Value {
    for row in v["callers"].as_array_mut().unwrap() {
        let id = row["id"].as_str().unwrap().to_owned();
        row["id"] = json!(format!("renamed-{id}"));
    }
    for row in v["modules"].as_array_mut().unwrap() {
        let id = row["id"].as_str().unwrap().to_owned();
        row["id"] = json!(format!("renamed-{id}"));
        row["paths"].as_array_mut().unwrap().reverse();
    }
    for row in v["edges"].as_array_mut().unwrap() {
        for key in ["caller", "module"] {
            let id = row[key].as_str().unwrap().to_owned();
            row[key] = json!(format!("renamed-{id}"));
        }
    }
    for row in v["gaps"].as_array_mut().unwrap() {
        for key in ["caller", "module"] {
            if let Some(id) = row[key].as_str() {
                row[key] = json!(format!("renamed-{id}"));
            }
        }
    }
    for key in ["callers", "modules", "edges", "gaps"] {
        v[key].as_array_mut().unwrap().reverse();
    }
    v
}

#[test]
fn typed_comparator_10000_callers_10000_modules_50000_edges() {
    use std::time::Instant;
    let started = Instant::now();
    let (before, mut after) = typed_scale();
    after.modules[0].sha256 = Some("f".repeat(64));
    for e in &mut after.edges {
        if e.module == 0 {
            e.entries.count = 24;
        }
    }
    let report = compare(&before, &after);
    assert_eq!(
        (
            report.summary.application_groups_compared,
            report.summary.application_groups_changed
        ),
        (10000, 5)
    );
    assert_eq!(
        (
            report.summary.content_both,
            report.summary.content_before_only,
            report.summary.content_after_only
        ),
        (9999, 1, 1)
    );
    assert_eq!(report.application_changes.len(), 10);
    assert_eq!(report.module_path_changes.len(), 1);
    assert_eq!(
        report
            .application_changes
            .iter()
            .map(|r| r.before.len())
            .sum::<usize>(),
        5
    );
    assert_eq!(
        report
            .application_changes
            .iter()
            .map(|r| r.after.len())
            .sum::<usize>(),
        5
    );
    assert!(
        report
            .application_changes
            .iter()
            .flat_map(|r| &r.before)
            .all(|e| edge_fact(&report.before, *e).entries.count == 128)
    );
    assert!(
        report
            .application_changes
            .iter()
            .flat_map(|r| &r.after)
            .all(|e| edge_fact(&report.after, *e).entries.count == 24)
    );
    eprintln!(
        "comparator-only: callers=10000 modules=10000 edges=50000 changed_apps=5 before_only=1 after_only=1 elapsed_ms={}",
        started.elapsed().as_millis()
    );
}
fn typed_scale() -> (Snapshot, Snapshot) {
    let mut s = base();
    counted(&mut s, 128, false);
    s.edges[0].entries.first_seen_ns = Some(110);
    s.edges[0].entries.last_seen_ns = Some(190);
    let c = s.callers[0].clone();
    let m = s.modules[0].clone();
    let e = s.edges[0].clone();
    s.gaps.clear();
    s.callers = (0..10000)
        .map(|i| {
            let mut c = c.clone();
            c.pid = 5000 + i;
            c.start_time = Some(1000 + u64::from(i));
            c.image.exe.as_mut().unwrap().path = Some(format!("/apps/{i}/driver"));
            c
        })
        .collect();
    s.modules = (0..10000)
        .map(|i| {
            let mut m = m.clone();
            m.inode = 100000 + i;
            m.sha256 = Some(format!("{:064x}", i + 1));
            m.paths = vec![format!("/mods/lib{i}.so")];
            m
        })
        .collect();
    s.edges.clear();
    for c in 0..10000 {
        for k in 0..5 {
            let mut edge = e.clone();
            edge.caller = c;
            edge.module = (c + k) % 10000;
            s.edges.push(edge);
        }
    }
    s.budgets.callers.limit = 10000;
    s.budgets.callers.occupied = 10000;
    s.budgets.modules.limit = 10000;
    s.budgets.modules.occupied = 10000;
    s.budgets.edges.limit = 50000;
    s.budgets.edges.occupied = 50000;
    s.budgets.endpoints.limit = 40000;
    s.budgets.endpoints.occupied = 40000;
    s.budgets.inventory_endpoints.as_mut().unwrap().limit = 40000;
    s.budgets.inventory_endpoints.as_mut().unwrap().occupied = 40000;
    s.budgets.inventory_attach_modules.as_mut().unwrap().limit = 10000;
    s.budgets
        .inventory_attach_modules
        .as_mut()
        .unwrap()
        .occupied = 10000;
    s.budgets.counters.observed_edges = 50000;
    s.budgets.semantic_state.unknown_edges = 50000;
    s.budgets.retained_history.retained = 0;
    s.observation.usage_feed = true;
    assert_eq!(s.callers.len() + s.modules.len() + s.edges.len(), 70000);
    let after = s.clone();
    (s, after)
}

#[test]
fn reader_admitted_5000_callers_5000_modules_25000_edges_is_useful() {
    let v = matrix_document(5000, 5000, 5);
    let raw = serde_json::to_vec(&v).unwrap();
    drop(v);
    assert!(raw.len() < 67_108_864);
    let before = input::parse_snapshot(&raw).unwrap();
    drop(raw);
    let mut after = before.clone();
    after.modules[0].sha256 = Some("f".repeat(64));
    let report = compare(&before, &after);
    assert_eq!(
        (
            report.summary.application_groups_compared,
            report.summary.application_groups_changed
        ),
        (5000, 5)
    );
    assert_eq!(
        (
            report.summary.content_both,
            report.summary.content_before_only,
            report.summary.content_after_only
        ),
        (4999, 1, 1)
    );
    assert_eq!(report.module_path_changes.len(), 2);
}

#[test]
fn exact_70000_row_json_exceeds_current_node_bound() {
    let v = matrix_document(10000, 10000, 5);
    let raw = serde_json::to_vec(&v).unwrap();
    drop(v);
    assert!(raw.len() < 67_108_864);
    let error = input::parse_snapshot(&raw).unwrap_err().to_string();
    assert!(error.contains("node limit"), "{error}");
}

/// Stops serialization before a regressed inline model could emit gigabytes.
struct CountingSink {
    bytes: usize,
    ceiling: usize,
}
impl std::io::Write for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.ceiling.saturating_sub(self.bytes) {
            return Err(std::io::Error::other("test compact JSON ceiling exceeded"));
        }
        self.bytes += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn compact_size(report: &model::DiffReport, ceiling: usize) -> usize {
    let mut sink = CountingSink { bytes: 0, ceiling };
    serde_json::to_writer(&mut sink, report).unwrap();
    sink.bytes
}
fn shared_document(callers: usize) -> Value {
    let mut v = matrix_document(callers, 1, 1);
    v["modules"][0]["paths"] = Value::Array(
        (0..512)
            .map(|i| json!(format!("/shared/{i:04}/{}", "x".repeat(8179))))
            .collect(),
    );
    for e in v["edges"].as_array_mut().unwrap() {
        e["entries"]["count"] = json!(128);
    }
    v
}
fn validate_references(report: &model::DiffReport) {
    for s in [&report.before, &report.after] {
        for r in &s.evidence.caller_occurrences {
            assert!(r.0 < s.evidence.callers.len());
        }
        for r in &s.evidence.module_occurrences {
            assert!(r.0 < s.evidence.modules.len());
        }
        for r in &s.evidence.edge_occurrences {
            assert!(r.0 < s.evidence.edges.len());
        }
        for e in &s.evidence.edges {
            assert!(e.caller.0 < s.evidence.callers.len());
            assert!(e.module.0 < s.evidence.modules.len());
        }
        for g in &s.gaps {
            if let Some(r) = g.caller {
                assert!(r.0 < s.evidence.callers.len());
            }
            if let Some(r) = g.module {
                assert!(r.0 < s.evidence.modules.len());
            }
        }
    }
    for c in &report.module_contents {
        for r in &c.before {
            assert!(r.0 < report.before.evidence.modules.len());
        }
        for r in &c.after {
            assert!(r.0 < report.after.evidence.modules.len());
        }
    }
    for a in &report.application_changes {
        assert!(a.key.exe_path_ref.0 < report.comparison.application_paths.len());
        for (s, refs, pop) in [
            (&report.before, &a.before, &a.before_population),
            (&report.after, &a.after, &a.after_population),
        ] {
            for r in refs {
                assert!(r.0 < s.evidence.edges.len());
            }
            for r in &pop.callers {
                assert!(r.0 < s.evidence.callers.len());
            }
            for r in &pop.modules {
                assert!(r.0 < s.evidence.modules.len());
            }
        }
    }
    for u in &report.unresolved {
        let s = match u.side {
            Side::Before => &report.before,
            Side::After => &report.after,
        };
        match u.kind {
            UnresolvedKind::Caller => {
                assert!(u.caller.unwrap().0 < s.evidence.callers.len());
                assert!(u.module.is_none() && u.observation.is_none());
            }
            UnresolvedKind::Module => {
                assert!(u.module.unwrap().0 < s.evidence.modules.len());
                assert!(u.caller.is_none() && u.observation.is_none());
            }
            UnresolvedKind::Edge => {
                assert!(u.observation.unwrap().0 < s.evidence.edges.len());
                assert!(u.caller.is_none() && u.module.is_none());
            }
        }
    }
}

#[test]
fn admitted_shared_payload_fanout_serializes_once_per_side() {
    let mut sizes = Vec::new();
    for fanout in [16, 10000] {
        let v = shared_document(fanout);
        let raw = serde_json::to_vec(&v).unwrap();
        drop(v);
        assert!(raw.len() < 67_108_864);
        let before = input::parse_snapshot(&raw).unwrap();
        drop(raw);
        assert_eq!(
            (
                before.callers.len(),
                before.modules.len(),
                before.edges.len()
            ),
            (fanout, 1, fanout)
        );
        let mut after = before.clone();
        for e in &mut after.edges {
            e.entries.count = 24;
        }
        let report = compare(&before, &after);
        validate_references(&report);
        assert_eq!(report.summary.application_groups_changed, fanout);
        assert_eq!(report.application_changes.len(), fanout);
        assert_eq!(report.before.evidence.modules.len(), 1);
        assert_eq!(report.after.evidence.modules.len(), 1);
        for s in [&report.before, &report.after] {
            let m = &s.evidence.modules[0];
            assert_eq!(m.paths, before.modules[0].paths);
            assert_eq!(m.admission, before.modules[0].admission);
            assert_eq!(s.evidence.caller_occurrences.len(), fanout);
            assert_eq!(s.evidence.edge_occurrences.len(), fanout);
        }
        for a in &report.application_changes {
            assert_eq!(a.before.len(), 1);
            assert_eq!(a.after.len(), 1);
            assert_eq!(edge_fact(&report.before, a.before[0]).entries.count, 128);
            assert_eq!(edge_fact(&report.after, a.after[0]).entries.count, 24);
        }
        let payload = before.modules[0]
            .paths
            .iter()
            .map(String::len)
            .sum::<usize>();
        let bytes = compact_size(&report, 2 * payload + 4096 * fanout + 65536);
        eprintln!(
            "admitted shared payload: callers={fanout} edges={fanout} module_payload_bytes={payload} compact_json_bytes={bytes}"
        );
        sizes.push(bytes);
    }
    assert!(sizes[1] - sizes[0] < 4096 * (10000 - 16));
}

#[test]
fn shared_payload_gap_and_unresolved_fanout_is_compact() {
    for missing_exe in [false, true] {
        let mut v = shared_document(1000);
        if missing_exe {
            for c in v["callers"].as_array_mut().unwrap() {
                c["image"]["exe"]["path"] = Value::Null;
            }
        } else {
            v["modules"][0]["identity"]["sha256"] = Value::Null;
        }
        v["gaps"]=Value::Array((0..1000).map(|i|json!({"caller":format!("c{i}"),"module":"m0","pid":5000+i,"subject":"shared module","reason":"not attributable","budget":null,"repeats":7})).collect());
        let before = snapshot(&v);
        drop(v);
        let report = compare(&before, &before);
        validate_references(&report);
        assert_eq!(
            report.unresolved.len(),
            if missing_exe { 2000 } else { 2002 }
        );
        assert_eq!(report.before.gaps.len(), 1000);
        assert_eq!(report.after.gaps.len(), 1000);
        assert!(report.before.gaps.iter().all(|g| g.repeats == 7));
        for s in [&report.before, &report.after] {
            assert_eq!(s.evidence.modules.len(), 1);
            assert_eq!(s.evidence.modules[0].paths, before.modules[0].paths);
        }
        let payload = before.modules[0]
            .paths
            .iter()
            .map(String::len)
            .sum::<usize>();
        let bytes = compact_size(&report, 2 * payload + 4096 * 1000 + 65536);
        eprintln!(
            "shared gap/unresolved: missing_exe={missing_exe} gaps_per_side=1000 unresolved={} compact_json_bytes={bytes}",
            report.unresolved.len()
        );
    }
}

#[test]
fn long_application_path_is_dictionary_label_not_group_payload() {
    let mut v = matrix_document(1, 500, 500);
    let path = format!("/{}", "p".repeat(16383));
    v["callers"][0]["image"]["exe"]["path"] = json!(path);
    let before = snapshot(&v);
    drop(v);
    let mut after = before.clone();
    for e in &mut after.edges {
        e.entries.count = 24;
    }
    let report = compare(&before, &after);
    validate_references(&report);
    assert_eq!(report.comparison.application_paths, vec![path.clone()]);
    assert_eq!(
        (
            report.summary.application_groups_compared,
            report.summary.application_groups_changed
        ),
        (1, 1)
    );
    assert_eq!(report.application_changes.len(), 500);
    assert!(report.application_changes.iter().all(|a| a.key.exe_path_ref
        == model::ApplicationPathRef(0)
        && app_path(&report, a) == path));
    assert!(
        report
            .application_changes
            .windows(2)
            .all(|a| a[0].key.sha256 < a[1].key.sha256)
    );
    let raw = serde_json::to_value(&report).unwrap();
    assert!(raw["application_changes"][0]["key"]["exe_path_ref"].is_u64());
    assert!(
        raw["application_changes"][0]["key"]
            .get("exe_path")
            .is_none()
    );
    let bytes = compact_size(&report, 3 * 16384 + 4096 * 500 + 65536);
    eprintln!("long label: label_bytes=16384 digest_groups=500 compact_json_bytes={bytes}");
}

#[test]
fn full_fact_pools_keep_source_occurrences_and_unchanged_evidence() {
    let mut before = base();
    counted(&mut before, 128, false);
    before.callers.push(before.callers[0].clone());
    before.callers.push(before.callers[0].clone());
    before.modules.push(before.modules[0].clone());
    let mut e = before.edges[0].clone();
    e.caller = 1;
    e.module = 1;
    before.edges.push(e);
    let mut after = before.clone();
    for e in &mut after.edges {
        e.entries.count = 24;
    }
    let report = compare(&before, &after);
    validate_references(&report);
    for s in [&report.before, &report.after] {
        assert_eq!(
            (
                s.evidence.callers.len(),
                s.evidence.modules.len(),
                s.evidence.edges.len()
            ),
            (1, 1, 1)
        );
        assert_eq!(s.evidence.caller_occurrences, vec![model::CallerRef(0); 3]);
        assert_eq!(s.evidence.module_occurrences, vec![model::ModuleRef(0); 2]);
        assert_eq!(s.evidence.edge_occurrences, vec![model::EdgeRef(0); 2]);
    }
    assert_eq!(
        report.module_contents[0].before,
        vec![model::ModuleRef(0); 2]
    );
    let a = &report.application_changes[0];
    assert_eq!(a.before, vec![model::EdgeRef(0); 2]);
    assert_eq!(a.after, vec![model::EdgeRef(0); 2]);
    assert_eq!(a.before_population.callers, vec![model::CallerRef(0); 2]);
    assert_eq!(a.before_population.modules, vec![model::ModuleRef(0); 2]);
    assert_eq!(
        a.before
            .iter()
            .map(|r| edge_fact(&report.before, *r).entries.count)
            .collect::<Vec<_>>(),
        vec![128, 128]
    );
    assert_eq!(
        a.after
            .iter()
            .map(|r| edge_fact(&report.after, *r).entries.count)
            .collect::<Vec<_>>(),
        vec![24, 24]
    );
    assert_eq!(report.unresolved.len(), 2);
    assert!(
        report
            .unresolved
            .iter()
            .all(|u| u.kind == UnresolvedKind::Caller)
    );
    let unchanged = compare(&before, &before);
    assert!(unchanged.application_changes.is_empty());
    assert_eq!(unchanged.before.evidence.edge_occurrences.len(), 2);
    assert_eq!(unchanged.before.evidence.caller_occurrences.len(), 3);
}

#[test]
fn caller_population_uses_source_rows_before_pooling() {
    let mut before = base();
    before.modules.push(before.modules[0].clone());
    let mut e = before.edges[0].clone();
    e.module = 1;
    before.edges.push(e);
    let mut after = before.clone();
    after.callers.push(after.callers[0].clone());
    after.edges[1].caller = 1;
    let report = compare(&before, &after);
    validate_references(&report);
    let a = &report.application_changes[0];
    assert_eq!(a.before, a.after);
    assert_eq!(a.changes, vec!["caller_population"]);
    assert_eq!(
        (
            a.before_population.callers.len(),
            a.after_population.callers.len()
        ),
        (1, 2)
    );
    assert_eq!(
        (
            a.before_population.modules.len(),
            a.after_population.modules.len()
        ),
        (2, 2)
    );
    let expected = serde_json::to_vec(&report).unwrap();
    before.edges.reverse();
    after.edges.reverse();
    after.callers.reverse();
    for e in &mut after.edges {
        e.caller = 1 - e.caller;
    }
    assert_eq!(
        serde_json::to_vec(&compare(&before, &after)).unwrap(),
        expected
    );
}

#[test]
fn module_population_uses_source_rows_before_pooling() {
    let mut before = base();
    before.callers.push(before.callers[0].clone());
    let mut e = before.edges[0].clone();
    e.caller = 1;
    before.edges.push(e);
    let mut after = before.clone();
    after.modules.push(after.modules[0].clone());
    after.edges[1].module = 1;
    let report = compare(&before, &after);
    validate_references(&report);
    let a = &report.application_changes[0];
    assert_eq!(a.before, a.after);
    assert_eq!(a.changes, vec!["physical_records"]);
    assert_eq!(
        (
            a.before_population.modules.len(),
            a.after_population.modules.len()
        ),
        (1, 2)
    );
    assert_eq!(
        (
            a.before_population.callers.len(),
            a.after_population.callers.len()
        ),
        (2, 2)
    );
    let expected = serde_json::to_vec(&report).unwrap();
    after.modules.reverse();
    for e in &mut after.edges {
        e.module = 1 - e.module;
    }
    before.edges.reverse();
    after.edges.reverse();
    assert_eq!(
        serde_json::to_vec(&compare(&before, &after)).unwrap(),
        expected
    );
}

#[test]
fn shifted_side_pool_indices_do_not_mark_equal_groups_changed() {
    let before = base();
    let mut after = before.clone();
    let mut c = after.callers[0].clone();
    c.pid = 1;
    c.image.exe.as_mut().unwrap().path = Some("/unrelated".into());
    after.callers.push(c);
    let mut m = after.modules[0].clone();
    m.inode = 1;
    m.sha256 = Some("a".repeat(64));
    after.modules.push(m);
    let report = compare(&before, &after);
    validate_references(&report);
    assert!(report.application_changes.is_empty());
    assert_eq!(report.summary.application_groups_changed, 0);
    assert_ne!(
        report.before.evidence.edges[0].caller,
        report.after.evidence.edges[0].caller
    );
    assert_ne!(
        report.before.evidence.edges[0].module,
        report.after.evidence.edges[0].module
    );
}

#[test]
fn nested_reference_schema_and_set_permutations_are_stable() {
    let mut before = matrix_document(2, 2, 1);
    before["modules"][0]["admission"]["reasons"] = json!(["z", "a", "a"]);
    let mut after = before.clone();
    after["edges"][0]["entries"]["count"] = json!(24);
    let report = compare(&snapshot(&before), &snapshot(&after));
    validate_references(&report);
    let v = serde_json::to_value(&report).unwrap();
    assert_eq!(
        v["before"]["evidence"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec![
            "caller_occurrences",
            "callers",
            "edge_occurrences",
            "edges",
            "module_occurrences",
            "modules"
        ]
    );
    assert_eq!(
        v["application_changes"][0]["before_population"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["callers", "modules"]
    );
    assert!(v["before"]["evidence"]["edges"][0]["caller"].is_u64());
    assert!(v["before"]["evidence"]["edges"][0]["module"].is_u64());
    assert!(v["application_changes"][0]["before"][0].is_u64());
    let bytes = serde_json::to_vec(&report).unwrap();
    for v in [&mut before, &mut after] {
        v["modules"][0]["admission"]["reasons"] = json!(["a", "z"]);
    }
    assert_eq!(
        serde_json::to_vec(&compare(
            &snapshot(&permuted(before)),
            &snapshot(&permuted(after))
        ))
        .unwrap(),
        bytes
    );
}

#[test]
fn equal_anchor_joint_correlations_are_compared() {
    let mut before = base();
    before.callers.push(before.callers[0].clone());
    let mut e = before.edges[0].clone();
    e.caller = 1;
    before.edges.push(e);
    before.edges[0].entries.count = 128;
    before.edges[1].entries.count = 24;
    before.edges[1].mapping.state = label("uncertain", true);
    let mut after = before.clone();
    after.edges[0].entries.count = 24;
    after.edges[1].entries.count = 128;
    let report = compare(&before, &after);
    assert_eq!(report.application_changes.len(), 1);
    let a = &report.application_changes[0];
    assert!(a.changes.contains(&"entries"));
    assert!(a.changes.contains(&"mapping"));
    assert_eq!(a.before_population.callers.len(), 2);
    assert_eq!(a.after_population.callers.len(), 2);
}

#[test]
fn higher_order_observation_correlations_are_compared() {
    let mut before = base();
    let c = before.callers[0].clone();
    let e = before.edges[0].clone();
    before.callers = vec![c; 4];
    before.edges = (0..4)
        .map(|i| {
            let mut e = e.clone();
            e.caller = i;
            e
        })
        .collect();
    let mut after = before.clone();
    for (s, patterns) in [(&mut before, [0, 3, 5, 6]), (&mut after, [1, 2, 4, 7])] {
        for (e, bits) in s.edges.iter_mut().zip(patterns) {
            e.mapping.state = label(if bits & 4 == 0 { "mapped" } else { "uncertain" }, true);
            e.entries.count = if bits & 2 == 0 { 128 } else { 24 };
            e.semantics = label(
                if bits & 1 == 0 {
                    "observed"
                } else {
                    "unknown (semantic capture withheld)"
                },
                true,
            );
        }
    }
    let report = compare(&before, &after);
    assert_eq!(report.application_changes.len(), 1);
    assert_eq!(
        report.application_changes[0].changes,
        vec!["entries", "mapping", "semantics"]
    );
}

#[test]
fn joint_changes_without_equal_complements_remain_visible() {
    let mut before = base();
    let c = before.callers[0].clone();
    let e = before.edges[0].clone();
    before.callers = vec![c; 2];
    before.edges = (0..2)
        .map(|i| {
            let mut e = e.clone();
            e.caller = i;
            e
        })
        .collect();
    let mut after = before.clone();
    for (s, patterns) in [(&mut before, [0, 15]), (&mut after, [3, 12])] {
        for (e, bits) in s.edges.iter_mut().zip(patterns) {
            e.mapping.state = label(if bits & 8 == 0 { "mapped" } else { "uncertain" }, true);
            e.entries.count = if bits & 4 == 0 { 128 } else { 24 };
            e.coverage.as_mut().unwrap().lossy = Some(bits & 2 != 0);
            e.semantics = label(
                if bits & 1 == 0 {
                    "observed"
                } else {
                    "unknown (semantic capture withheld)"
                },
                true,
            );
        }
    }
    let report = compare(&before, &after);
    assert_eq!(report.application_changes.len(), 1);
    assert_eq!(
        report.application_changes[0].changes,
        vec!["coverage", "entries", "mapping", "semantics"]
    );
}

fn no_edge_modules() -> Snapshot {
    let mut s = base();
    s.callers.clear();
    s.edges.clear();
    s.gaps.clear();
    let mut m = s.modules[0].clone();
    m.inode = 200000;
    s.modules.push(m);
    s
}

#[test]
fn no_edge_content_admission_swap_preserves_inode_association() {
    let mut before = no_edge_modules();
    before.modules[1].admission.state = label("refused", true);
    let mut after = before.clone();
    after.modules[0].admission.state = label("refused", true);
    after.modules[1].admission.state = label("admitted", true);
    let report = compare(&before, &after);
    assert_eq!(report.module_contents.len(), 1);
    assert!(report.application_changes.is_empty());
    assert!(report.module_path_changes.is_empty());
    assert_eq!(report.module_contents[0].changes, vec!["admission"]);
    assert_eq!(
        report.module_contents[0]
            .before
            .iter()
            .map(|r| {
                let m = module_fact(&report.before, *r);
                (m.identity.inode, m.admission.state.raw.as_str())
            })
            .collect::<Vec<_>>(),
        vec![(100000, "admitted"), (200000, "refused")]
    );
    assert_eq!(
        report.module_contents[0]
            .after
            .iter()
            .map(|r| {
                let m = module_fact(&report.after, *r);
                (m.identity.inode, m.admission.state.raw.as_str())
            })
            .collect::<Vec<_>>(),
        vec![(100000, "refused"), (200000, "admitted")]
    );
}

#[test]
fn no_edge_content_path_swap_preserves_inode_association() {
    let mut before = no_edge_modules();
    before.modules[0].paths = vec!["/a/lib.so".into()];
    before.modules[1].paths = vec!["/b/lib.so".into()];
    let mut after = before.clone();
    after.modules[0].paths = vec!["/b/lib.so".into()];
    after.modules[1].paths = vec!["/a/lib.so".into()];
    let report = compare(&before, &after);
    assert_eq!(report.module_contents.len(), 1);
    assert!(report.module_path_changes.is_empty());
    assert!(report.application_changes.is_empty());
    assert_eq!(report.module_contents[0].changes, vec!["paths"]);
}

#[test]
fn no_edge_content_joint_correlations_are_compared() {
    let mut before = no_edge_modules();
    before.modules[1].inode = before.modules[0].inode;
    before.modules[0].paths = vec!["/a/lib.so".into()];
    before.modules[1].paths = vec!["/b/lib.so".into()];
    before.modules[1].admission.state = label("refused", true);
    let mut after = before.clone();
    after.modules[0].admission.state = label("refused", true);
    after.modules[1].admission.state = label("admitted", true);
    let report = compare(&before, &after);
    assert_eq!(report.module_contents.len(), 1);
    assert!(report.application_changes.is_empty());
    assert!(report.module_path_changes.is_empty());
    assert_eq!(
        report.module_contents[0].changes,
        vec!["admission", "paths"]
    );
    assert_eq!(report.module_contents[0].before.len(), 2);
    assert_eq!(report.module_contents[0].after.len(), 2);
    let expected = serde_json::to_vec(&report).unwrap();
    before.modules.reverse();
    after.modules.reverse();
    assert_eq!(
        serde_json::to_vec(&compare(&before, &after)).unwrap(),
        expected
    );
}

fn population_edges(v: &Value, pairs: &[(usize, usize)]) -> Value {
    Value::Array(
        pairs
            .iter()
            .map(|(c, m)| {
                let mut e = v["edges"][0].clone();
                e["caller"] = json!(format!("c{c}"));
                e["module"] = json!(format!("m{m}"));
                e["entries"]["count"] = json!(128);
                e["entries"]["observation"] = json!("observed");
                e["entries"]["coverage"]["state"] = json!("counted");
                e["entries"]["coverage"]["lossy"] = json!(false);
                e["entries"]["coverage"]["reason"] = Value::Null;
                e
            })
            .collect(),
    )
}

fn shifted_population_times(mut s: Snapshot) -> Snapshot {
    s.observation.started_ns += 10000;
    s.observation.ended_ns += 10000;
    for c in &mut s.callers {
        c.first_seen_ns += 10000;
        c.last_seen_ns += 10000;
        c.incarnation = 900;
        c.image.task_cookie = Some(42);
        c.image.exec_id = Some(8);
    }
    for m in &mut s.modules {
        if let Some(h) = &mut m.admission.history {
            for entry in h {
                entry.at_ns += 10000;
            }
        }
        if let Some(u) = &mut m.unbound_use {
            u.first_ns += 10000;
        }
    }
    for e in &mut s.edges {
        e.mapping.first_seen_ns += 10000;
        e.mapping.last_seen_ns += 10000;
        e.entries.first_seen_ns = e.entries.first_seen_ns.map(|t| t + 10000);
        e.entries.last_seen_ns = e.entries.last_seen_ns.map(|t| t + 10000);
        if let Some(c) = &mut e.coverage {
            c.since_ns = c.since_ns.map(|t| t + 10000);
            c.until_ns = c.until_ns.map(|t| t + 10000);
            c.first_ns = c.first_ns.map(|t| t + 10000);
        }
    }
    s
}

fn assert_source_population_change(b: &Value, a: &Value, code: &str) -> model::DiffReport {
    // Both fixtures pass the real reader, including its unique ID/pair checks.
    let before = snapshot(b);
    let after = snapshot(a);
    let report = compare(&before, &after);
    validate_references(&report);
    assert_eq!(report.summary.application_groups_compared, 1);
    assert_eq!(report.summary.application_groups_changed, 1);
    assert_eq!(report.application_changes.len(), 1);
    let app = &report.application_changes[0];
    assert_eq!(app.presence, Presence::Both);
    assert_eq!(app_path(&report, app), "/bin/driver");
    assert_eq!(app.key.sha256, before.modules[0].sha256.clone().unwrap());
    assert_eq!(app.changes, vec![code]);
    assert_eq!((app.before.len(), app.after.len()), (4, 4));
    for (s, edges) in [(&report.before, &app.before), (&report.after, &app.after)] {
        assert_eq!(s.evidence.edge_occurrences.len(), 4);
        assert_eq!(
            edges
                .iter()
                .map(|r| edge_fact(s, *r).entries.count)
                .collect::<Vec<_>>(),
            vec![128; 4]
        );
    }
    // Complete fanout-weighted facts are equal despite changed source populations.
    assert_eq!(report.before.evidence.edges, report.after.evidence.edges);
    assert_eq!(
        report.before.evidence.edge_occurrences,
        report.after.evidence.edge_occurrences
    );
    assert!(report.module_contents.iter().all(|r| r.changes.is_empty()));
    assert!(report.module_path_changes.is_empty());
    assert_eq!(
        report.before.evidence.modules,
        report.after.evidence.modules
    );
    assert_eq!(
        report.before.evidence.module_occurrences,
        report.after.evidence.module_occurrences
    );
    assert!(report.unresolved.is_empty());
    assert_eq!(report.comparison.host_relation, "unknown");
    assert_eq!(report.comparison.boot_relation, "unknown");
    assert_eq!(report.comparison.process_continuity, "unknown");
    assert_eq!(report.comparison.physical_continuity, "unknown");
    assert_eq!(
        serde_json::to_vec(&compare(
            &snapshot(&permuted(b.clone())),
            &snapshot(&permuted(a.clone()))
        ))
        .unwrap(),
        serde_json::to_vec(&report).unwrap()
    );
    let time_only = compare(&before, &shifted_population_times(before.clone()));
    assert!(time_only.application_changes.is_empty());
    assert!(
        time_only
            .module_contents
            .iter()
            .all(|r| r.changes.is_empty())
    );
    let changed_times = compare(&before, &shifted_population_times(after));
    assert_eq!(changed_times.summary.application_groups_changed, 1);
    assert_eq!(changed_times.application_changes[0].changes, vec![code]);
    let reverse = compare(&snapshot(a), &before);
    assert_eq!(reverse.summary.application_groups_changed, 1);
    assert_eq!(reverse.application_changes[0].changes, vec![code]);
    report
}

#[test]
fn caller_lifecycle_source_population_changes_despite_equal_edge_multisets() {
    let mut b = document();
    let c = b["callers"][0].clone();
    b["callers"] = Value::Array(
        (0..3)
            .map(|i| {
                let mut c = c.clone();
                c["id"] = json!(format!("c{i}"));
                if i == 2 {
                    c["lifecycle"] = json!("exited");
                    c["lifecycle_reason"] = json!("process exited");
                    c["retired"] = json!(true);
                }
                c
            })
            .collect(),
    );
    let mut m = b["modules"][0].clone();
    m["id"] = json!("m1");
    m["identity"]["inode"] = json!(200000);
    b["modules"].as_array_mut().unwrap().push(m);
    b["gaps"] = json!([]);
    let mut a = b.clone();
    a["callers"][1]["lifecycle"] = json!("exited");
    a["callers"][1]["lifecycle_reason"] = json!("process exited");
    a["callers"][1]["retired"] = json!(true);
    b["edges"] = population_edges(&b, &[(0, 0), (1, 1), (2, 0), (2, 1)]);
    a["edges"] = population_edges(&a, &[(0, 0), (0, 1), (1, 0), (2, 1)]);
    let report = assert_source_population_change(&b, &a, "lifecycle");
    let app = &report.application_changes[0];
    for (s, pop, mapped, exited) in [
        (&report.before, &app.before_population, 2, 1),
        (&report.after, &app.after_population, 1, 2),
    ] {
        assert_eq!((pop.callers.len(), pop.modules.len()), (3, 2));
        let mut states = pop
            .callers
            .iter()
            .map(|r| {
                let c = caller_fact(s, *r);
                assert_eq!((c.pid, c.start_time), (4242, Some(1000)));
                (
                    c.lifecycle.raw.as_str(),
                    c.lifecycle_reason.as_deref(),
                    c.retired,
                )
            })
            .collect::<Vec<_>>();
        states.sort();
        let mut expected = vec![("mapped", None, false); mapped];
        expected.extend(vec![("exited", Some("process exited"), true); exited]);
        expected.sort();
        assert_eq!(states, expected);
        assert_eq!(
            pop.modules
                .iter()
                .map(|r| module_fact(s, *r).identity.inode)
                .collect::<Vec<_>>(),
            vec![100000, 200000]
        );
    }
}

fn module_source_population_change(facet: &str) {
    let mut b = document();
    let mut c = b["callers"][0].clone();
    c["id"] = json!("c1");
    c["pid"] = json!(4243);
    b["callers"].as_array_mut().unwrap().push(c);
    let m = b["modules"][0].clone();
    b["modules"] = Value::Array(
        (0..4)
            .map(|i| {
                let mut m = m.clone();
                m["id"] = json!(format!("m{i}"));
                if i >= 2 {
                    match facet {
                        "admission" => m["admission"]["state"] = json!("refused"),
                        "paths" => m["paths"] = json!(["/other/lib.so"]),
                        "lifecycle" => {
                            m["lifecycle"] = json!("unloaded");
                            m["unloaded_observed"] = json!(true);
                        }
                        _ => unreachable!(),
                    }
                }
                m
            })
            .collect(),
    );
    b["gaps"] = json!([]);
    let mut a = b.clone();
    b["edges"] = population_edges(&b, &[(0, 0), (1, 1), (0, 2), (1, 2)]);
    a["edges"] = population_edges(&a, &[(0, 0), (1, 0), (0, 2), (1, 3)]);
    let report = assert_source_population_change(&b, &a, facet);
    let app = &report.application_changes[0];
    for (s, pop, acount, bcount) in [
        (&report.before, &app.before_population, 2, 1),
        (&report.after, &app.after_population, 1, 2),
    ] {
        assert_eq!((pop.callers.len(), pop.modules.len()), (2, 3));
        assert_eq!(s.evidence.module_occurrences.len(), 4);
        let mut values = pop
            .modules
            .iter()
            .map(|r| {
                let m = module_fact(s, *r);
                assert_eq!(m.identity.inode, 100000);
                match facet {
                    "admission" => m.admission.state.raw.clone(),
                    "paths" => m.paths[0].clone(),
                    "lifecycle" => {
                        assert_eq!(m.unloaded_observed, m.lifecycle.raw == "unloaded");
                        m.lifecycle.raw.clone()
                    }
                    _ => unreachable!(),
                }
            })
            .collect::<Vec<_>>();
        values.sort();
        let (av, bv) = match facet {
            "admission" => ("admitted", "refused"),
            "paths" => ("/scale/m0.so", "/other/lib.so"),
            "lifecycle" => ("mapped", "unloaded"),
            _ => unreachable!(),
        };
        let mut expected = vec![av.to_owned(); acount];
        expected.extend(vec![bv.to_owned(); bcount]);
        expected.sort();
        assert_eq!(values, expected);
        assert_eq!(
            pop.callers
                .iter()
                .map(|r| caller_fact(s, *r).pid)
                .collect::<Vec<_>>(),
            vec![4242, 4243]
        );
    }
}

#[test]
fn module_admission_source_population_changes_with_unchanged_global_facts() {
    module_source_population_change("admission");
}

#[test]
fn module_path_source_population_changes_with_unchanged_global_facts() {
    module_source_population_change("paths");
}

#[test]
fn module_lifecycle_source_population_changes_with_unchanged_global_facts() {
    module_source_population_change("lifecycle");
}

#[test]
fn instance_s1_additive_details_do_not_change_physical_diff() {
    let old = document();
    let mut before = old.clone();
    before["instances"] = json!([{"id":"i0","caller":"c0","module":"m0","state":"observed"}]);
    before["semantic_edges"] = json!([{"instance":"i0","api_returns":{"unit":"api_returns","count":7},"operations":{"completed":1}}]);
    let mut after = before.clone();
    after["instances"][0]["state"] = json!("retired");
    after["semantic_edges"][0]["api_returns"]["count"] = json!(99);
    after["semantic_edges"][0]["operations"]["completed"] = json!(8);
    let baseline = serde_json::to_value(compare(&snapshot(&old), &snapshot(&old))).unwrap();
    for left in [&old, &before, &after] {
        for right in [&old, &before, &after] {
            let report = compare(&snapshot(left), &snapshot(right));
            assert_eq!(serde_json::to_value(&report).unwrap(), baseline);
            assert!(
                report
                    .limitations
                    .contains(&"semantic_details_not_compared".into())
            );
        }
    }
}

#[test]
fn native_semantic_resource_budgets_do_not_change_physical_diff() {
    let old = document();
    let mut charged = old.clone();
    charged["budgets"]["instance_semantic_resources"] = json!({
        "limit_bytes": 67108864, "charged_bytes": 1074691,
        "peak_charged_bytes": 1074691, "refused": 0,
        "occupancy": {"active_machines": 1, "detached_calls": 1, "mechanisms": 1}
    });
    let mut refused = charged.clone();
    refused["budgets"]["instance_semantic_resources"]["charged_bytes"] = json!(1068880);
    refused["budgets"]["instance_semantic_resources"]["refused"] = json!(7);
    refused["budgets"]["instance_semantic_resources"]["occupancy"]["active_machines"] = json!(0);
    let baseline = serde_json::to_value(compare(&snapshot(&old), &snapshot(&old))).unwrap();
    for left in [&old, &charged, &refused] {
        for right in [&old, &charged, &refused] {
            let report = compare(&snapshot(left), &snapshot(right));
            assert_eq!(serde_json::to_value(&report).unwrap(), baseline);
            assert!(
                report
                    .limitations
                    .contains(&"semantic_details_not_compared".into())
            );
        }
    }
}
