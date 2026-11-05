//! SPDX-License-Identifier: GPL-3.0-or-later
//! Family-28 key-operation text summary: the `key operations:` line
//! `render_snapshot` prints directly after the `coverage:` line. Counts
//! per operation category from the shared `ObjectObservations` — the
//! same tallies the dashboard line shows, never object identity.

use super::*;
use crate::discovery::caller_registry::RegistryLimits;
use crate::discovery::inventory_workload::{Harness, ScaleSpec};
use crate::inventory_dashboard::{DashboardState, DisplayFrame, LogTail, Viewport, render_frame};
use crate::key_operation_projection::{
    KeyAggRow, MetadataBlock, MetadataField, ObjectObservations, ObjectRow, ObsStatus,
    QueriesBlock, SECONDARY_ROLE, SessionRow, UnknownAggRow, object_observations_json,
};

/// A captured scale presentation carrying `observations`, the way the
/// live loop embeds a committed revision (mirrors
/// `key_operation_tests::harness_presentation`, which lives in another
/// test module).
fn key_ops_presentation(observations: ObjectObservations) -> Presentation {
    let mut harness = Harness::new(RegistryLimits::default_limits()).unwrap();
    harness.stage_scale(&ScaleSpec {
        name: "key-ops-text",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 92_000,
    });
    harness.commit();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.object_observations = observations;
    presentation
}

fn populated(revision: u64) -> ObjectObservations {
    let mut observations = ObjectObservations::unavailable(revision, "bootstrap_unavailable");
    observations.status = ObsStatus::Populated;
    observations.reason = "none";
    observations
}

fn key_row(
    category: &'static str,
    role: &'static str,
    completed: u64,
    failed: u64,
    active: u64,
    unit: &'static str,
) -> KeyAggRow {
    KeyAggRow {
        instance: "test-instance".to_string(),
        object: 11,
        category,
        role,
        metadata_at_use: "rsa_2048",
        unit,
        started: completed.saturating_add(failed).saturating_add(active),
        completed,
        failed,
        cancelled: 0,
        unknown: 0,
        active,
        key_join_lost: 0,
    }
}

fn unknown_row(
    category: &'static str,
    completed: u64,
    failed: u64,
    active: u64,
    unit: &'static str,
) -> UnknownAggRow {
    UnknownAggRow {
        category,
        reason: "unbound",
        unit,
        completed,
        failed,
        cancelled: 0,
        unknown: 0,
        active,
    }
}

/// Blank-metadata object record (mirrors the N9 `churned` record in
/// `key_operation_tests`, which lives in another test module).
fn object_row(object: u64) -> ObjectRow {
    let blank = MetadataField {
        status: "absent",
        scalar: None,
        curve: None,
    };
    let block = MetadataBlock {
        class: blank,
        key_type: blank,
        token: blank,
        value_len: blank,
        modulus_bits: blank,
        ec_params: blank,
    };
    ObjectRow {
        object,
        session: 7,
        origin: "observed",
        creation: None,
        birth: None,
        lifetime: "destroyed",
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
        },
        label: None,
        successful_references: 1,
        successful_key_references: 0,
        accessing_sessions: 1,
    }
}

/// The single `key operations:` line of a snapshot.
fn key_ops_line(snapshot: &str) -> &str {
    let lines: Vec<&str> = snapshot
        .lines()
        .filter(|line| line.starts_with("key operations:"))
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "exactly one key operations line:\n{snapshot}"
    );
    lines[0]
}

/// The dashboard H9 projection line at a wide viewport (mirrors
/// `key_operation_tests::dashboard_text`, which lives in another test
/// module).
fn dashboard_projection_line(presentation: &Presentation) -> String {
    let mut tail = LogTail::bounded();
    tail.push("p11scope: pass 1: key ops text");
    let frame = DisplayFrame {
        presentation: std::sync::Arc::new(presentation.clone()),
        log: tail.snapshot(),
    };
    let bytes = render_frame(
        &frame,
        Viewport {
            width: 300,
            height: 24,
        },
        &DashboardState::new(),
    );
    let text = String::from_utf8(bytes).expect("frames are valid UTF-8");
    text.replace("\x1b[H", "")
        .replace("\x1b[K", "")
        .lines()
        .find(|line| line.starts_with("objects/keys"))
        .expect("projection line")
        .to_string()
}

/// Per-category (completed, failed, active) parsed from a snapshot
/// `key operations:` line.
fn snapshot_tallies(line: &str) -> Vec<(&str, u64, u64, u64)> {
    let mut tallies = Vec::new();
    for segment in line.split("; ").skip(2) {
        if segment == "no key operations observed" {
            continue;
        }
        // "<category> <completed> completed, <failed> failed, <active> active <unit>"
        let (category, rest) = segment.split_once(' ').expect("category");
        let rest = rest
            .strip_suffix(" operations")
            .or_else(|| rest.strip_suffix(" message_contexts"))
            .expect("unit");
        let mut words = rest.split(' ');
        let completed: u64 = words.next().expect("completed").parse().expect("digits");
        assert_eq!(words.next(), Some("completed,"));
        let failed: u64 = words.next().expect("failed").parse().expect("digits");
        assert_eq!(words.next(), Some("failed,"));
        let active: u64 = words.next().expect("active").parse().expect("digits");
        assert_eq!(words.next(), Some("active"));
        assert_eq!(words.next(), None);
        tallies.push((category, completed, failed, active));
    }
    tallies
}

/// Per-category (completed, failed, active) parsed from a dashboard
/// `objects/keys` line.
fn dashboard_tallies(line: &str) -> Vec<(&str, u64, u64, u64)> {
    let tail = line.split(" | ").nth(2).expect("tally tail");
    let mut tallies = Vec::new();
    for segment in tail.split(", ") {
        // "<category> <completed>/<failed>/<active> <unit>"
        let (category, rest) = segment.split_once(' ').expect("category");
        let (counts, _unit) = rest.split_once(' ').expect("unit");
        let mut counts = counts.split('/');
        let completed: u64 = counts.next().expect("completed").parse().expect("digits");
        let failed: u64 = counts.next().expect("failed").parse().expect("digits");
        let active: u64 = counts.next().expect("active").parse().expect("digits");
        assert_eq!(counts.next(), None);
        tallies.push((category, completed, failed, active));
    }
    tallies
}

#[test]
fn key_ops_line_unavailable_names_reason() {
    let presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "bootstrap_unavailable"));
    let snapshot = render_snapshot(&presentation);
    let lines: Vec<&str> = snapshot.lines().collect();
    let coverage = lines
        .iter()
        .position(|line| line.starts_with("coverage: "))
        .expect("coverage line");
    assert_eq!(
        lines[coverage + 1],
        "key operations: unavailable (bootstrap_unavailable)",
        "the unavailable line sits directly after coverage:\n{snapshot}"
    );
    assert_eq!(
        snapshot
            .lines()
            .filter(|line| line.starts_with("key operations:"))
            .count(),
        1,
        "exactly one key operations line:\n{snapshot}"
    );
}

#[test]
fn key_ops_line_counts_not_attributed_beside_exact_rows() {
    let mut observations = populated(9);
    observations.status = ObsStatus::Partial;
    observations.reason = "authority_lost";
    observations
        .key_operations
        .push(key_row("sign", "key", 4, 0, 0, "operations"));
    observations.add_unattributed("record_lost", 2);
    observations.add_unattributed("proof_refused_fallback", 3);
    let presentation = key_ops_presentation(observations);
    let snapshot = render_snapshot(&presentation);
    let line = key_ops_line(&snapshot);
    assert!(
        line.contains("sign 4 completed, 0 failed, 0 active operations"),
        "exact rows stay: {line}"
    );
    assert!(
        line.ends_with("; not attributed: record_lost 2, proof_refused_fallback 3"),
        "counts sit beside the rows in frozen order: {line}"
    );
}

/// DEMO-4: a first-observed key row under the `unknown` metadata
/// label reads in text as a type not established in the observed
/// window, beside the exact tallies. The text claims no timing it
/// cannot prove (the key may predate attach or its attribute call may
/// simply be unobserved).
#[test]
fn key_ops_line_names_unknown_type_not_established_in_window() {
    let mut observations = populated(9);
    let mut row = key_row("sign", "key", 2, 0, 0, "operations");
    row.metadata_at_use = "unknown";
    observations.key_operations.push(row);
    let presentation = key_ops_presentation(observations);
    let snapshot = render_snapshot(&presentation);
    let line = key_ops_line(&snapshot);
    assert!(
        line.contains("sign 2 completed, 0 failed, 0 active operations"),
        "the tallies stay exact: {line}"
    );
    assert!(
        line.ends_with("; type not established in the observed window (1 key row)"),
        "the unknown type is named, never guessed: {line}"
    );
}

#[test]
fn key_ops_line_journal_unavailable_names_tracking_off() {
    let presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    let snapshot = render_snapshot(&presentation);
    assert_eq!(
        key_ops_line(&snapshot),
        "key operations: not reported (per-key tracking is off)",
        "journal_unavailable names tracking off:\n{snapshot}"
    );
}

#[test]
fn key_ops_line_populated_counts_primary_once() {
    let mut observations = populated(3);
    observations.sessions.push(SessionRow {
        session: 7,
        origin: "opened",
        status: "live",
    });
    observations.objects.push(object_row(11));
    observations
        .key_operations
        .push(key_row("sign", "key", 2, 1, 0, "operations"));
    // The secondary association stands beside the primary's row: its
    // large counts must never leak into the tally (H9 §82).
    observations
        .key_operations
        .push(key_row("sign", SECONDARY_ROLE, 100, 50, 25, "operations"));
    observations
        .unknown_key_operations
        .push(unknown_row("sign", 3, 0, 1, "operations"));
    let presentation = key_ops_presentation(observations);
    let snapshot = render_snapshot(&presentation);
    assert_eq!(
        key_ops_line(&snapshot),
        "key operations: rev 3 populated; 1 session, 1 object; \
         sign 5 completed, 1 failed, 1 active operations",
        "primary + unknown only, secondary never double-counted:\n{snapshot}"
    );
}

#[test]
fn key_ops_line_stale_shows_reason() {
    let mut observations = ObjectObservations::unavailable(9, "bootstrap_unavailable");
    observations.status = ObsStatus::Stale;
    observations.reason = "publication_budget_exhausted";
    let presentation = key_ops_presentation(observations);
    let snapshot = render_snapshot(&presentation);
    assert_eq!(
        key_ops_line(&snapshot),
        "key operations: rev 9 stale (publication_budget_exhausted); \
         0 sessions, 0 objects; no key operations observed",
        "stale names its reason:\n{snapshot}"
    );
}

#[test]
fn key_ops_line_lossless_large_values() {
    let mut observations = populated(5);
    observations.key_operations.push(key_row(
        "sign",
        "key",
        18_446_744_073_709_551_614,
        0,
        0,
        "operations",
    ));
    observations
        .key_operations
        .push(key_row("verify", "key", u64::MAX, 0, 0, "operations"));
    let presentation = key_ops_presentation(observations);
    let snapshot = render_snapshot(&presentation);
    assert_eq!(
        key_ops_line(&snapshot),
        "key operations: rev 5 populated; 0 sessions, 0 objects; \
         sign 18446744073709551614 completed, 0 failed, 0 active operations; \
         verify 18446744073709551615 completed, 0 failed, 0 active operations",
        "u64 digits render exactly, categories in order:\n{snapshot}"
    );
}

#[test]
fn key_ops_line_matches_dashboard_tallies() {
    let mut observations = populated(11);
    observations.sessions.push(SessionRow {
        session: 7,
        origin: "opened",
        status: "live",
    });
    observations.objects.push(object_row(11));
    observations.objects.push(object_row(12));
    observations
        .key_operations
        .push(key_row("sign", "key", 2, 1, 3, "operations"));
    observations
        .key_operations
        .push(key_row("wrap", "wrapping_key", 4, 0, 1, "operations"));
    observations
        .key_operations
        .push(key_row("wrap", SECONDARY_ROLE, 40, 41, 42, "operations"));
    observations
        .unknown_key_operations
        .push(unknown_row("sign", 5, 6, 7, "operations"));
    let presentation = key_ops_presentation(observations.clone());
    let snapshot = render_snapshot(&presentation);
    let text_tallies = snapshot_tallies(key_ops_line(&snapshot));
    let frame_line = dashboard_projection_line(&presentation);
    let frame_tallies = dashboard_tallies(&frame_line);
    assert_eq!(
        text_tallies, frame_tallies,
        "text and dashboard agree per category"
    );
    assert_eq!(
        text_tallies,
        vec![("sign", 7, 7, 10), ("wrap", 4, 0, 1)],
        "primary + unknown only, category order"
    );

    // Negative control: a different projection disagrees.
    let mut other = observations;
    other.key_operations[0].completed = 200;
    let other_presentation = key_ops_presentation(other);
    let other_line = dashboard_projection_line(&other_presentation);
    let other_frame = dashboard_tallies(&other_line);
    assert_ne!(
        text_tallies, other_frame,
        "the comparison is sensitive to the tallies"
    );
}

#[test]
fn key_ops_line_carries_no_object_identity() {
    let mut observations = populated(13);
    observations.sessions.push(SessionRow {
        session: 123_456_789,
        origin: "first_observed",
        status: "live",
    });
    let mut row = object_row(987_654_321_098);
    row.label = Some("label-7X-secret");
    row.requested.value_len = MetadataField {
        status: "value",
        scalar: Some(42421),
        curve: None,
    };
    row.established.ec_params = MetadataField {
        status: "value",
        scalar: None,
        curve: Some("secp384r1"),
    };
    observations.objects.push(row);
    let mut key = key_row("sign", "key", 2, 0, 1, "operations");
    key.instance = "instance-9Z-private".to_string();
    key.object = 987_654_321_098;
    observations.key_operations.push(key);
    let presentation = key_ops_presentation(observations.clone());
    let snapshot = render_snapshot(&presentation);
    let line = key_ops_line(&snapshot).to_string();
    for forbidden in [
        "987654321098",
        "123456789",
        "label-7X-secret",
        "42421",
        "secp384r1",
        "instance-9Z-private",
    ] {
        assert!(
            !line.contains(forbidden),
            "text line carries no object identity ({forbidden}): {line}"
        );
    }
    // Positive control: the JSON section still carries every token.
    let document = serde_json::to_string(&object_observations_json(&observations)).unwrap();
    for token in [
        "987654321098",
        "123456789",
        "label-7X-secret",
        "42421",
        "secp384r1",
        "instance-9Z-private",
    ] {
        assert!(
            document.contains(token),
            "JSON keeps the identity token ({token})"
        );
    }
}

fn named_gap(subject: &str, reason: &str) -> GapView {
    GapView {
        caller: None,
        module: None,
        pid: None,
        subject: subject.into(),
        reason: reason.into(),
        budget: None,
        repeats: 1,
    }
}

/// A linked lane with observed semantic calls and no Joint feed or
/// birth refusal names its `bootstrap_unavailable` once; the twins
/// (no calls, a named refusal, any other reason) add nothing.
#[test]
fn silent_bootstrap_unavailable_is_named_once() {
    let silent = ObjectObservations::unavailable(7, "bootstrap_unavailable");
    let gap = silent_bootstrap_gap(&silent, 1, &[named_gap("semantic input refused", "slot")])
        .expect("observed calls with no birth and no refusal are named");
    assert_eq!(gap.subject, "Joint birth unavailable; retained S1");
    assert_eq!(gap.reason, "joint_birth_unoffered");
    assert_eq!(gap.repeats, 1);
    assert!(
        silent_bootstrap_gap(&silent, 0, &[]).is_none(),
        "no observed calls: nothing owed"
    );
    let refused = [named_gap(
        "Joint birth unavailable; retained S1",
        "joint_birth_native_RowUnreadable",
    )];
    assert!(
        silent_bootstrap_gap(&silent, 1, &refused).is_none(),
        "a refusal already names it"
    );
    for reason in [
        "journal_unavailable",
        "proof_refused_fallback",
        "authority_lost",
    ] {
        let other = ObjectObservations::unavailable(7, reason);
        assert!(
            silent_bootstrap_gap(&other, 1, &[]).is_none(),
            "{reason} carries its own cause"
        );
    }
    assert!(silent_bootstrap_gap(&populated(7), 1, &[]).is_none());
}

/// The wiring's twin: a linked capture without any observed semantic
/// call has nothing to name, so its presentation adds no gap.
#[test]
fn presentation_without_semantic_calls_adds_no_bootstrap_gap() {
    let mut harness = Harness::new(RegistryLimits::default_limits()).unwrap();
    harness.stage_scale(&ScaleSpec {
        name: "idle-bootstrap",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 93_000,
    });
    harness.commit();
    let presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    assert_eq!(
        presentation.object_observations.reason,
        "bootstrap_unavailable"
    );
    assert!(presentation.semantic_edges.is_empty());
    assert!(
        presentation
            .gaps
            .iter()
            .all(|gap| gap.reason != "joint_birth_unoffered")
    );
}

/// The middle twin: one registered instance with zero reduced calls
/// still yields a semantic row, so its silent `bootstrap_unavailable`
/// is named. The gap fires on registration, not on observed calls.
#[test]
fn presentation_with_registered_instance_and_no_calls_names_bootstrap_gap() {
    use crate::attach::capture::NativeDomainId;
    use crate::discovery::caller_registry::ModuleKey;
    use crate::discovery::caller_registry::instance_input as instance;
    use crate::discovery::instances::InstanceId;
    use p11scope_ebpf_common::ImageIdentity;
    let mut harness = Harness::new(RegistryLimits::default_limits()).unwrap();
    harness.stage_scale(&ScaleSpec {
        name: "idle-registered",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 94_000,
    });
    harness.commit();
    let caller = harness
        .coordinator()
        .adapter()
        .live_id(94_000)
        .expect("live caller");
    let module = ModuleKey::physical(8, 1, 100_000, Some("sha000000".into()), "/scale/m0.so");
    let domain = NativeDomainId::mint();
    let key = instance::key(
        domain,
        ImageIdentity {
            task_cookie: 1000,
            exec_id: 0,
        },
        InstanceId::from_raw(1),
        module,
    );
    harness
        .coordinator_mut()
        .registry_mut()
        .note_instance(instance::registration(key, caller, 100, None));
    harness.commit();
    let presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    assert_eq!(
        presentation.object_observations.reason,
        "bootstrap_unavailable"
    );
    assert_eq!(presentation.semantic_edges.len(), 1);
    assert!(
        presentation
            .gaps
            .iter()
            .any(|gap| gap.reason == "joint_birth_unoffered"),
        "a registered instance with no calls is still owed a name"
    );
}
