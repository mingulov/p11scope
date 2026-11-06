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
        .find(|line| line.starts_with("keys revision"))
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
        // "<category> <completed> completed, <failed> returned an error/errors, <active> active <unit>"
        let (category, rest) = segment.split_once(' ').expect("category");
        let rest = rest
            .strip_suffix(" operations")
            .or_else(|| rest.strip_suffix(" message_contexts"))
            .expect("unit");
        let mut words = rest.split(' ');
        let completed: u64 = words.next().expect("completed").parse().expect("digits");
        assert_eq!(words.next(), Some("completed,"));
        let failed: u64 = words.next().expect("failed").parse().expect("digits");
        assert_eq!(words.next(), Some("returned"));
        match words.next() {
            Some("an") => {
                assert_eq!(failed, 1, "singular for one: {line}");
                assert_eq!(words.next(), Some("error,"));
            }
            Some("errors,") => {}
            other => panic!("failed noun: {other:?} in {line}"),
        }
        let active: u64 = words.next().expect("active").parse().expect("digits");
        assert_eq!(words.next(), Some("active"));
        assert_eq!(words.next(), None);
        tallies.push((category, completed, failed, active));
    }
    tallies
}

/// Per-category (completed, failed, active) parsed from a dashboard
/// `keys revision` line.
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
        "key operations: not available — per-key tracking never started, so no key can be named yet",
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
/// label reads in text as type unknown (not established while
/// observed), beside the exact tallies. The text claims no timing it
/// cannot prove (the key may predate attach or its attribute call may
/// simply be unobserved).
#[test]
fn key_ops_line_names_unknown_type_not_established_while_observed() {
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
        line.ends_with("; type unknown (not established while observed) (1 key row)"),
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
fn key_ops_line_requested_without_manifest_names_manifest() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.key_operations_requested = true;
    presentation.manifests_present = false;
    let snapshot = render_snapshot(&presentation);
    assert_eq!(
        key_ops_line(&snapshot),
        "key operations: requested, but per-key tracking needs --manifest on this build",
        "requested without a manifest never reads 'off':\n{snapshot}"
    );
}

#[test]
fn key_ops_line_requested_with_manifest_and_no_gap_stays_off() {
    // Requested with a manifest but no start was recorded and no gap
    // exists (no start was refused): the conservative fallthrough is
    // "off", and only the manifest-less request names --manifest.
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.key_operations_requested = true;
    presentation.manifests_present = true;
    let snapshot = render_snapshot(&presentation);
    assert_eq!(
        key_ops_line(&snapshot),
        "key operations: not reported (per-key tracking is off)",
        "manifested request without a gap stays off:\n{snapshot}"
    );
}

/// Item 6: concise folds a denied live-capture refusal to one short
/// clause; the full host summary stays verbose-only.
#[test]
fn concise_gap_summary_folds_denied_capture_refusal() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.gaps.clear();
    let stored = "live capture refused (live capture needs root: the kernel refused to load \
        p11scope's BPF programs (Operation not permitted). Run with sudo, or use 'p11scope \
        inspect --pid N' for a scan without capture.); run with sudo for full capture";
    presentation.gaps.push(named_gap(
        "native usage feed unavailable",
        stored,
    ));
    let concise =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let gaps = concise
        .lines()
        .find(|line| line.starts_with("gaps: "))
        .expect("the concise gaps line");
    assert_eq!(
        gaps,
        "gaps: 1 × native usage feed unavailable — live capture refused (needs root); run \
         with sudo for full capture (--json has every item)"
    );
    assert!(!concise.contains("Operation not permitted"), "{concise}");
    let verbose =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(verbose.contains(stored), "{verbose}");
}

/// Item 6: a non-denied refusal (old kernel, verifier) folds without
/// sudo advice; sudo cannot help there.
#[test]
fn concise_gap_summary_folds_unproven_capture_refusal() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.gaps.clear();
    let stored = "live capture refused (live capture did not start: loading p11scope's BPF \
        programs failed (Permission denied); run 'p11scope doctor' for host readiness, or use \
        'p11scope inspect --pid N' for a scan without capture.)";
    presentation.gaps.push(named_gap(
        "native usage feed unavailable",
        stored,
    ));
    let concise =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let gaps = concise
        .lines()
        .find(|line| line.starts_with("gaps: "))
        .expect("the concise gaps line");
    assert_eq!(
        gaps,
        "gaps: 1 × native usage feed unavailable — live capture refused (see 'p11scope \
         doctor') (--json has every item)"
    );
    assert!(!concise.contains("sudo"), "{concise}");
    let verbose =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(verbose.contains(stored), "{verbose}");
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
         sign 5 completed, 1 returned an error, 1 active operations",
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
        "key operations: rev 9 stale (key publication hit its budget; plain counts are unaffected); \
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
         sign 18446744073709551614 completed, 0 returned errors, 0 active operations; \
         verify 18446744073709551615 completed, 0 returned errors, 0 active operations",
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

/// F5: the tally says what happened to the call ("returned an
/// error/errors"), not "failed" (which reads as an observer failure).
/// JSON keys stay `failed`.
#[test]
fn key_ops_tally_says_returned_an_error_not_failed() {
    let mut observations = populated(3);
    observations
        .key_operations
        .push(key_row("sign", "key", 2, 1, 0, "operations"));
    observations
        .key_operations
        .push(key_row("verify", "key", 5, 2, 0, "operations"));
    let presentation = key_ops_presentation(observations);
    let snapshot = render_snapshot(&presentation);
    let line = key_ops_line(&snapshot);
    assert!(
        line.contains("1 returned an error"),
        "singular tally missing: {line}"
    );
    assert!(
        line.contains("2 returned errors"),
        "plural tally missing: {line}"
    );
    assert!(
        !line.contains(" failed"),
        "observer-failure wording leaked: {line}"
    );
}

/// F5: the dashboard projection line spells its fields (sessions,
/// keys, per-key rows, unattributed rows, revision, refused), not
/// `sess/obj/krows/urows/rev`.
#[test]
fn dashboard_projection_line_spells_fields() {
    let mut observations = populated(91);
    observations.status = ObsStatus::Populated;
    observations.reason = "none";
    observations.sessions.push(SessionRow {
        session: 7,
        origin: "opened",
        status: "live",
    });
    observations.objects.push(object_row(11));
    observations
        .key_operations
        .push(key_row("sign", "key", 2, 1, 0, "operations"));
    let presentation = key_ops_presentation(observations);
    let mut tail = LogTail::bounded();
    tail.push("p11scope: pass 1: f5");
    let frame = DisplayFrame {
        presentation: std::sync::Arc::new(presentation),
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
    let line = text
        .replace("\x1b[H", "")
        .replace("\x1b[K", "")
        .lines()
        .find(|line| line.contains("rev"))
        .expect("projection line")
        .to_string();
    for plain in [
        "revision",
        "sessions",
        "per-key rows",
        "unattributed rows",
        "refused",
    ] {
        assert!(line.contains(plain), "{plain} missing: {line}");
    }
    for abbrev in ["sess ", "krows", "urows", " rev "] {
        assert!(!line.contains(abbrev), "{abbrev} leaked: {line}");
    }
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

/// CLI-1/KEY-2: an unavailable key-operations section names its reason
/// in plain words; verbose pairs the machine reason beside it.
#[test]
fn unavailable_key_operations_name_plain_reason_with_machine_code() {
    for (reason, plain) in [
        (
            "bootstrap_unavailable",
            "per-key tracking never started, so no key can be named yet",
        ),
        (
            "authority_lost",
            "per-key tracking stopped; plain counts are unaffected",
        ),
        (
            "row_budget_exhausted",
            "per-key rows hit their budget; plain counts are unaffected",
        ),
    ] {
        let presentation = key_ops_presentation(ObjectObservations::unavailable(3, reason));
        let concise =
            render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
        assert!(
            concise.contains(&format!("key operations: not available — {plain}")),
            "{reason}: {concise}"
        );
        assert!(!concise.contains(reason), "{reason} leaked: {concise}");
        let verbose =
            render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
        assert!(verbose.contains(plain), "{reason}: {verbose}");
        assert!(
            verbose.contains(&format!("(reason: {reason})")),
            "{reason}: {verbose}"
        );
    }
}

/// F3: the unlinked-journal, seal and fallback gaps render in plain
/// words with their machine tokens beside them (verbose); concise
/// must never see the raw `S1` / `joint_*` strings.
#[test]
fn joint_journal_seal_fallback_gaps_render_plain_words_with_machine_tokens() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(3, "bootstrap_unavailable"));
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
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "Joint key operations unavailable; retained S1".into(),
        reason: "joint_fallback_staging_full".into(),
        budget: None,
        repeats: 1,
    });
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        verbose.contains("per-key tracking is off; function and mechanism counts are unaffected"),
        "keeps-S1 subject needs a plain twin: {verbose}"
    );
    assert!(
        verbose.contains("per-key tracking ended early"),
        "joint_seal_* needs a plain twin: {verbose}"
    );
    assert!(
        verbose.contains("per-key tracking fell back to plain counts"),
        "joint_fallback_* needs a plain twin: {verbose}"
    );
    // The machine tokens stay beside the plain words in verbose text.
    assert!(
        verbose.contains("(joint_seal_h3_loss_history_loss)"),
        "{verbose}"
    );
    assert!(
        verbose.contains("(joint_fallback_staging_full)"),
        "{verbose}"
    );
    assert!(
        verbose.contains(
            "(per-key tracking is off; this capture keeps S1 mechanisms and API results)"
        ),
        "{verbose}"
    );
}

/// CLI-1/KEY-3: the Joint birth gap renders in plain words with the
/// machine subject and reason beside it.
#[test]
fn joint_birth_gap_renders_plain_words_with_machine_reason() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(3, "bootstrap_unavailable"));
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
        subject: JOINT_BIRTH_UNAVAILABLE_SUBJECT.into(),
        reason: "joint_birth_unoffered".into(),
        budget: None,
        repeats: 1,
    });
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        verbose.contains("Per-key tracking did not start for this process"),
        "{verbose}"
    );
    assert!(
        verbose.contains("no key session was offered to track"),
        "{verbose}"
    );
    assert!(verbose.contains("(joint_birth_unoffered)"), "{verbose}");
    assert!(
        verbose.contains("(Joint key operations unavailable; retained S1)"),
        "{verbose}"
    );
    assert!(
        verbose.contains("(Joint birth unavailable; retained S1)"),
        "{verbose}"
    );
}

/// Item 14: when --key-operations was requested but per-key tracking did
/// not start, the line names the request and the cause; without the
/// request gap it stays "not reported (per-key tracking is off)".
#[test]
fn key_ops_line_requested_but_not_started_names_cause() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "key operations unavailable".into(),
        reason:
            "test journal refused; broad inventory continues with S1 mechanisms and API results"
                .into(),
        budget: None,
        repeats: 1,
    });
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        key_ops_line(&snapshot)
            .starts_with("key operations: requested, but per-key tracking did not start"),
        "{snapshot}"
    );
    assert!(
        !key_ops_line(&snapshot).contains("not reported"),
        "{snapshot}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        key_ops_line(&verbose)
            .starts_with("key operations: requested, but per-key tracking did not start"),
        "{verbose}"
    );
    let plain = key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    assert_eq!(
        key_ops_line(&render_snapshot(&plain)),
        "key operations: not reported (per-key tracking is off)",
    );
}
