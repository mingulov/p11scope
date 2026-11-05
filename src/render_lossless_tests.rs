//! SPDX-License-Identifier: GPL-3.0-or-later
//! Lossless large-value + unknown parity pins across the text, JSON,
//! JSONL and dashboard lanes (V5-28a).
//!
//! Counts and IDs are exact in every lane at 80x24 and above; a `…`
//! mark is allowed only below the stated dashboard floor. Durations
//! stay exact in JSON only — text `fmt_ns` is lossy by design and is
//! never pinned here, and latency percentiles above 2^53 are never
//! asserted exact (f64 step, `metrics.rs:380`).

use super::*;
use crate::attach::CapturePolicy;
use crate::cli::InventoryDiffArgs;
use crate::discovery::caller_registry::RegistryLimits;
use crate::discovery::identity::PinnedObjects;
use crate::discovery::inventory_workload::{Harness, ScaleSpec};
use crate::discovery::scan::ScanOutcome;
use crate::inspect::render_json as inspect_json;
use crate::inventory::render_json_from_presentation;
use crate::inventory_dashboard::{DashboardState, DisplayFrame, LogTail, Viewport, render_frame};
use crate::inventory_diagnostics::{
    CaptureOutcome, CaptureSettlement, DiagnosticConfig, DiagnosticOutcome, Recorder,
    RetainedIdentityView,
};
use crate::inventory_diff::run_with_writer;
use crate::inventory_event_identity::IdentityIndex;
use crate::inventory_events::{EVENT_SCHEMA, EventWriter, edge_payload};
use crate::inventory_present::{Activity, Presentation, render_snapshot};
use crate::key_operation_projection::OBSERVATIONS_VERSION;
use crate::metrics::SlotReport;
use crate::plan::AttachPlan;
use crate::semantics::State;
use crate::trace::{evidence_line, format_line};
use p11scope_ebpf_common::{
    CounterMode, Event, LATENCY_BUCKETS, MECH_NONE, SESSION_NONE, USER_TYPE_NONE, shape,
};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::sync::Arc;

/// Assert a JSON number carries `expected` losslessly: the typed value
/// round-trips AND the serialized bytes spell the exact digits. A float
/// detour fails both legs (`as_u64` is `None` for floats, and the bytes
/// would print the rounded value).
pub(crate) fn assert_lossless_u64_json(value: &serde_json::Value, expected: u64) {
    assert_eq!(
        value.as_u64(),
        Some(expected),
        "JSON number is not the exact u64: {value}"
    );
    assert_eq!(
        serde_json::to_string(value).expect("number serializes"),
        expected.to_string(),
        "JSON bytes are not the exact digits"
    );
}

/// Values no float lane can carry: 2^53+1, u64::MAX-1, u64::MAX.
const LOSSLESS_VALUES: [u64; 3] = [9_007_199_254_740_993, 18_446_744_073_709_551_614, u64::MAX];

/// What `value as f64` would print on this platform — asserted ABSENT
/// (in the lane's delimited form) wherever the exact digits are
/// asserted present.
fn lossy_digits(value: u64) -> String {
    format!("{}", value as f64)
}

fn slot_report(calls: u64, in_flight: u64) -> SlotReport {
    SlotReport {
        file_offset: 0,
        target_object: None,
        ordinals: Vec::new(),
        names: vec!["C_Sign".into()],
        aliased: false,
        semantic_authorized: true,
        module: None,
        module_ambiguous: false,
        module_unresolved: false,
        // Counts carry no timing: the percentile path is never entered.
        mode: CounterMode::Counts,
        calls,
        errors: 0,
        in_flight,
        total_ns: 0,
        max_ns: 0,
        buckets: [0; LATENCY_BUCKETS],
        rv_counts: Default::default(),
    }
}

fn capture_meta() -> CaptureMeta<'static> {
    CaptureMeta {
        started: "t0",
        ended: "t1",
        kernel: "6.8.0",
        policy: CapturePolicy::Allowlisted,
        scope: "pid",
        ring_bytes: p11scope_ebpf_common::RING_BYTES,
        drain_interval_ms: 1000,
    }
}

fn clean_evidence() -> Evidence {
    super::tests::evidence()
}

fn empty_state() -> State {
    State::with_policy(
        &AttachPlan::from_slots(Vec::new()),
        CapturePolicy::Allowlisted,
    )
}

/// One caller, one module, one edge — the smallest revision that
/// reaches every inventory lane.
fn lossless_presentation() -> Presentation {
    let mut harness = Harness::new(RegistryLimits::default_limits()).unwrap();
    harness.stage_scale(&ScaleSpec {
        name: "lossless-parity",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 91_000,
    });
    harness.commit();
    let view = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    assert_eq!(view.callers.len(), 1, "one-caller fixture");
    assert_eq!(view.edges.len(), 1, "one-edge fixture");
    view
}

/// Append `payload` as one `kind` line at `at_ns` through the real
/// rotation/flush path and return the exact bytes on disk.
fn jsonl_bytes(kind: &str, payload: serde_json::Value, at_ns: u64) -> Vec<u8> {
    let file = tempfile::tempfile().unwrap();
    let mut reader = file.try_clone().unwrap();
    let mut writer = EventWriter::anonymous_test_sink(file);
    writer.append(kind, payload, at_ns).unwrap();
    drop(writer);
    reader.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert!(bytes.ends_with(b"\n"), "one LF-delimited line");
    bytes
}

/// Render `view` at the given viewport and strip the frame's own
/// cursor-home / clear-line bytes for content assertions.
fn frame_text_at(view: &Presentation, width: usize, height: usize) -> String {
    let mut tail = LogTail::bounded();
    tail.push("p11scope: pass 0: 1 scanned (0 native, 1 scan-pinned)");
    let frame = DisplayFrame {
        presentation: Arc::new(view.clone()),
        log: tail.snapshot(),
    };
    let bytes = render_frame(&frame, Viewport { width, height }, &DashboardState::new());
    let text = String::from_utf8(bytes).expect("frames are valid UTF-8");
    assert!(text.starts_with("\x1b[H"), "frames home first");
    text.replace("\x1b[H", "").replace("\x1b[K", "")
}

/// The digit token immediately after the first `marker`, if any.
fn token_after<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    let start = text.find(marker)? + marker.len();
    let rest = &text[start..];
    let len = rest.bytes().take_while(u8::is_ascii_digit).count();
    if len == 0 {
        return None;
    }
    Some(&rest[..len])
}

/// Every digit token following each `marker` occurrence.
fn tokens_after<'a>(text: &'a str, marker: &str) -> Vec<&'a str> {
    let mut tokens = Vec::new();
    let mut rest = text;
    while let Some(found) = rest.find(marker) {
        let after = &rest[found + marker.len()..];
        let len = after.bytes().take_while(u8::is_ascii_digit).count();
        if len > 0 {
            tokens.push(&after[..len]);
        }
        rest = after;
    }
    tokens
}

#[test]
fn render_lossless_u64_parity_across_lanes() {
    for value in LOSSLESS_VALUES {
        let exact = value.to_string();
        let lossy = lossy_digits(value);
        assert_ne!(
            lossy, exact,
            "2^53+1/u64::MAX-1/u64::MAX are not f64-exact, or the control is void"
        );

        // Metrics JSON: function calls through `json`.
        let capture = capture_meta();
        let mut metrics_ev = clean_evidence();
        metrics_ev.verdict_with_selection(false);
        let metrics = json(&[slot_report(value, 0)], &metrics_ev, &capture);
        assert_lossless_u64_json(&metrics["functions"][0]["calls"], value);

        // Profile JSON: the same report through `profile_json`.
        let mut profile_ev = clean_evidence();
        profile_ev.verdict();
        let profile = profile_json(
            &[slot_report(value, 0)],
            VersionedEvidence::wrap(&profile_ev),
            &empty_state(),
            &capture,
        );
        assert_lossless_u64_json(&profile["functions"][0]["calls"], value);

        // Trace text: the session pseudonym spells the exact digits.
        let event = Event {
            ts_ns: 0,
            duration_ns: 18_000,
            pid_tgid: (12345u64 << 32) | 12401,
            cgroup_id: 0,
            session: SESSION_NONE,
            mechanism: MECH_NONE,
            user_type: USER_TYPE_NONE,
            shape: shape::NONE,
            ..Event::default()
        };
        let line = format_line(&event, 1_000_000_000, "C_Sign", Some(value));
        assert_eq!(
            token_after(&line, "sess#"),
            Some(exact.as_str()),
            "trace line: {line}"
        );
        assert!(
            !line.contains(format!("sess#{lossy}").as_str()),
            "trace line carries f64-rounded digits: {line}"
        );

        // JSONL bytes: the same edge count in envelope and payload.
        let mut view = lossless_presentation();
        view.edges[0].entry_count = value;
        let identities = IdentityIndex::new(&view);
        let payload = edge_payload(&view.edges[0], &identities);
        let bytes = jsonl_bytes("edge_observed", payload, value);
        let text = std::str::from_utf8(&bytes).expect("JSONL is UTF-8");
        let streamed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(streamed["schema"], EVENT_SCHEMA);
        assert_lossless_u64_json(&streamed["at_ns"], value);
        assert_lossless_u64_json(&streamed["event"]["entries"]["count"], value);
        assert!(
            text.contains(format!("\"at_ns\":{exact}").as_str()),
            "envelope bytes: {text}"
        );
        assert!(
            text.contains(format!("\"count\":{exact}").as_str()),
            "payload bytes: {text}"
        );
        assert!(
            !text.contains(format!("\"at_ns\":{lossy}").as_str()),
            "envelope bytes carry f64-rounded digits: {text}"
        );
        assert!(
            !text.contains(format!("\"count\":{lossy}").as_str()),
            "payload bytes carry f64-rounded digits: {text}"
        );

        // Dashboard cell at exactly 80x24.
        let frame = frame_text_at(&view, 80, 24);
        let entries = tokens_after(&frame, "entries ");
        assert!(
            entries.contains(&exact.as_str()),
            "dashboard frame lacks the exact count: {frame}"
        );
        assert!(
            !entries.contains(&lossy.as_str()),
            "dashboard frame carries f64-rounded digits: {frame}"
        );
    }
}

/// The per-lane missing-return form: PARTIAL + `concrete_gap`, with the
/// open call named as the `in_flight_at_end` observation cause and
/// counted in `gap_classes.open_calls`.
fn assert_missing_return_form(evidence: &serde_json::Value, lane: &str) {
    assert_eq!(evidence["completeness"], "PARTIAL", "{lane}");
    assert_eq!(evidence["verdict_detail"], "concrete_gap", "{lane}");
    assert_eq!(evidence["gap_classes"]["open_calls"], 1, "{lane}");
    let causes = evidence["gap_classes"]["observation"]["causes"]
        .as_array()
        .unwrap_or_else(|| panic!("{lane} observation causes are an array: {evidence}"));
    assert!(
        causes.iter().any(|cause| cause == "in_flight_at_end"),
        "{lane} names the missing-return cause: {causes:?}"
    );
}

#[test]
fn render_missing_return_stays_partial_everywhere() {
    let capture = capture_meta();
    let reports = [slot_report(5, 1)];

    // Metrics JSON: PARTIAL + concrete_gap + open_calls.
    let mut metrics_ev = clean_evidence();
    metrics_ev.in_flight_at_end = 1;
    metrics_ev.verdict_with_selection(false);
    let metrics = json(&reports, &metrics_ev, &capture);
    assert_missing_return_form(&metrics["evidence"], "metrics");
    assert_eq!(metrics["functions"][0]["in_flight"], 1);

    // Profile JSON: the same form under the selection-aware verdict.
    let mut profile_ev = clean_evidence();
    profile_ev.in_flight_at_end = 1;
    profile_ev.verdict();
    let profile = profile_json(
        &reports,
        VersionedEvidence::wrap(&profile_ev),
        &empty_state(),
        &capture,
    );
    assert_missing_return_form(&profile["evidence"], "profile");
    assert_eq!(profile["functions"][0]["in_flight"], 1);

    // Trace EVIDENCE: the same sealed form.
    let evidence_text = evidence_line(&profile_ev, CapturePolicy::Allowlisted);
    let body = evidence_text
        .strip_prefix("EVIDENCE ")
        .expect("EVIDENCE prefix");
    let terminal: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_missing_return_form(&terminal, "trace EVIDENCE");

    // Negative control: without the open call the cause is absent.
    let mut clean = clean_evidence();
    clean.verdict();
    assert!(
        !clean
            .gap_classes
            .observation
            .causes
            .contains(&"in_flight_at_end"),
        "clean evidence must not name the missing-return cause: {:?}",
        clean.gap_classes.observation.causes
    );
    assert_eq!(clean.gap_classes.open_calls, 0);

    // Inventory lanes at one Presentation revision: JSON + JSONL +
    // dashboard carry entries.in_flight with the RETAINED admission
    // identity, never a current-occupant lookup (renderers do no I/O).
    let mut view = lossless_presentation();
    let retained_pid = view.callers[0].pid;
    let retained_exe = view.callers[0]
        .exe
        .as_ref()
        .and_then(|exe| exe.path.clone());

    // Quiet baseline first: the lanes distinguish the in-flight edge
    // from one that is not.
    let quiet_json = render_json_from_presentation(&view);
    assert_eq!(quiet_json["edges"][0]["entries"]["in_flight"], false);
    let quiet_identities = IdentityIndex::new(&view);
    let quiet_payload = edge_payload(&view.edges[0], &quiet_identities);
    let quiet_activity = quiet_payload["activity"]
        .as_str()
        .expect("activity label")
        .to_string();
    assert_ne!(quiet_activity, Activity::InFlight.label());
    let quiet_frame = frame_text_at(&view, 80, 24);
    assert!(
        quiet_frame.contains(format!("activity {quiet_activity}").as_str()),
        "quiet dashboard frame: {quiet_frame}"
    );
    assert!(
        !quiet_frame.contains("activity operation initialized / in flight"),
        "quiet dashboard frame names no in-flight activity: {quiet_frame}"
    );

    view.edges[0].entry_in_flight = true;
    view.edges[0].activity = Activity::InFlight;

    let document = render_json_from_presentation(&view);
    assert_eq!(document["edges"][0]["entries"]["in_flight"], true);
    assert_eq!(document["edges"][0]["caller"], "c0");
    assert_eq!(document["callers"][0]["pid"], retained_pid);
    assert_eq!(
        document["callers"][0]["image"]["exe"]["path"],
        retained_exe
            .as_deref()
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null),
        "JSON carries the retained executable, never a fresh lookup"
    );

    let identities = IdentityIndex::new(&view);
    let payload = edge_payload(&view.edges[0], &identities);
    assert_eq!(payload["activity"], Activity::InFlight.label());
    assert_eq!(payload["entries"]["in_flight"], true);
    let bytes = jsonl_bytes("edge_observed", payload, 7);
    let streamed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(streamed["event"]["activity"], Activity::InFlight.label());
    assert_eq!(streamed["event"]["entries"]["in_flight"], true);
    assert_eq!(streamed["event"]["identity_context"]["caller"]["id"], "c0");
    assert_eq!(
        streamed["event"]["identity_context"]["caller"]["pid"],
        retained_pid
    );
    assert_eq!(
        streamed["event"]["identity_context"]["caller"]["executable"]["path"],
        document["callers"][0]["image"]["exe"]["path"],
        "JSONL context echoes the retained executable"
    );

    let frame = frame_text_at(&view, 80, 24);
    assert!(
        frame.contains("activity operation initialized / in flight"),
        "dashboard frame: {frame}"
    );
    assert!(frame.contains("[c0]"), "dashboard frame: {frame}");
    match retained_exe.as_deref() {
        Some(path) => {
            let basename = path
                .rsplit('/')
                .find(|part| !part.is_empty())
                .expect("nonempty retained path");
            assert!(
                frame.contains(basename),
                "dashboard names the retained executable {basename:?}: {frame}"
            );
        }
        None => assert!(
            frame.contains("Unknown executable"),
            "dashboard withholds the unknown executable honestly: {frame}"
        ),
    }
}

#[test]
fn presentation_revision_agrees_across_all_lanes() {
    let mut view = lossless_presentation();
    view.edges[0].entry_count = 123_456_789;
    let expected_caller = view.edges[0].caller.label();
    let expected_pid = view.callers[0].pid;
    let expected_count = view.edges[0].entry_count;
    let expected_activity = view.edges[0].activity.label();

    // JSON lane: the reference projection of this revision.
    let document = render_json_from_presentation(&view);
    assert_eq!(document["edges"][0]["caller"], expected_caller);
    assert_lossless_u64_json(&document["edges"][0]["entries"]["count"], expected_count);
    assert_eq!(document["callers"][0]["pid"], expected_pid);

    // Text lane: the same caller, pid and count in words.
    let snapshot = render_snapshot(&view);
    assert!(
        snapshot.contains(expected_caller.as_str()),
        "text snapshot: {snapshot}"
    );
    assert!(
        snapshot.contains(format!("pid {expected_pid}").as_str()),
        "text snapshot: {snapshot}"
    );
    assert_eq!(
        token_after(&snapshot, "pid "),
        Some(expected_pid.to_string()).as_deref(),
        "text snapshot: {snapshot}"
    );
    assert!(
        snapshot.contains(format!("At least {expected_count} entries observed").as_str()),
        "text snapshot: {snapshot}"
    );

    // JSONL lane: the same edge record on the stream.
    let identities = IdentityIndex::new(&view);
    let payload = edge_payload(&view.edges[0], &identities);
    let bytes = jsonl_bytes("edge_observed", payload, 9);
    let streamed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(streamed["event"]["caller"], expected_caller);
    assert_lossless_u64_json(&streamed["event"]["entries"]["count"], expected_count);
    assert_eq!(streamed["event"]["activity"], expected_activity);

    // Dashboard lane at 80x24: the same identity, count and activity.
    let frame = frame_text_at(&view, 80, 24);
    assert!(
        frame.contains(format!("[{expected_caller}]").as_str()),
        "dashboard frame: {frame}"
    );
    assert!(
        tokens_after(&frame, "entries ").contains(&expected_count.to_string().as_str()),
        "dashboard frame: {frame}"
    );
    assert!(
        frame.contains(format!("activity {expected_activity}").as_str()),
        "dashboard frame: {frame}"
    );

    // Negative controls: a revision that is NOT this one matches nowhere.
    assert_ne!(document["callers"][0]["pid"], 91_001);
    assert_ne!(streamed["event"]["entries"]["count"], 123_456_788);
    for (lane, text) in [("text", snapshot.as_str()), ("dashboard", frame.as_str())] {
        assert!(!text.contains("pid 91001"), "{lane} names no foreign pid");
        assert!(
            !text.contains("123456788"),
            "{lane} carries no foreign count"
        );
    }
}

struct NoLabels;

impl RetainedIdentityView for NoLabels {
    fn application(&self, _: u32) -> Option<&str> {
        None
    }
    fn module(&self, _: u32) -> Option<&str> {
        None
    }
}

/// The `schema` of a real first diagnostics export line (header).
fn diagnostics_header_schema() -> String {
    let recorder = Recorder::try_new(DiagnosticConfig {
        ordinary_capacity: 2,
        exceptional_capacity: 2,
        ..DiagnosticConfig::default()
    })
    .unwrap();
    let finished = recorder.finish(DiagnosticOutcome {
        capture_outcome: CaptureOutcome::Completed,
        capture_settlement: CaptureSettlement::Unsettled,
    });
    let mut bytes = Vec::new();
    finished
        .write_jsonl(&mut bytes, &NoLabels, || false)
        .unwrap();
    let header = bytes.split(|byte| *byte == b'\n').next().unwrap();
    let value: serde_json::Value = serde_json::from_slice(header).unwrap();
    assert_eq!(value["kind"], "header");
    value["schema"].as_str().expect("header schema").into()
}

const DIFF_FIXTURE: &[u8] = include_bytes!("../tests/fixtures/inventory-diff/scan-current.json");

/// The `schema` of a real offline diff report over owned fixture bytes.
fn diff_report_schema() -> String {
    let dir = tempfile::tempdir().unwrap();
    let before = dir.path().join("before.json");
    let after = dir.path().join("after.json");
    std::fs::write(&before, DIFF_FIXTURE).unwrap();
    std::fs::write(&after, DIFF_FIXTURE).unwrap();
    let args = InventoryDiffArgs {
        before,
        after,
        json: true,
        out: None,
    };
    let mut out = Vec::new();
    let code = run_with_writer(&args, &mut out).unwrap();
    assert_eq!(code, 0, "identical inputs compare clean");
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    report["schema"].as_str().expect("report schema").into()
}

#[test]
fn schema_identifiers_versioned_separately_from_product() {
    let capture = capture_meta();
    let state = empty_state();
    let reports = [slot_report(5, 0)];

    let mut metrics_ev = clean_evidence();
    metrics_ev.verdict_with_selection(false);
    let metrics = json(&reports, &metrics_ev, &capture);
    assert_eq!(metrics["schema"], "p11scope/observed-profile/v3-metrics");

    let mut profile_ev = clean_evidence();
    profile_ev.verdict();
    let profile = profile_json(
        &reports,
        VersionedEvidence::wrap(&profile_ev),
        &state,
        &capture,
    );
    assert_eq!(profile["schema"], "p11scope/observed-profile/v3");

    let outcome = ScanOutcome::Unavailable {
        reason: "schema pin control",
        modules: Vec::new(),
        skipped: Vec::new(),
    };
    let inspect = inspect_json(4242, &outcome, &PinnedObjects::empty());
    assert_eq!(inspect["schema"], "p11scope/inspect/v1");

    let view = lossless_presentation();
    let inventory = render_json_from_presentation(&view);
    assert_eq!(inventory["schema"], "p11scope/inventory/v1");

    assert_eq!(EVENT_SCHEMA, "p11scope/inventory-events/v1");
    let identities = IdentityIndex::new(&view);
    let bytes = jsonl_bytes(
        "edge_observed",
        edge_payload(&view.edges[0], &identities),
        11,
    );
    let streamed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(streamed["schema"], "p11scope/inventory-events/v1");

    assert_eq!(
        crate::inventory_diagnostics::SCHEMA,
        "p11scope/inventory-diagnostics/v1"
    );
    assert_eq!(
        diagnostics_header_schema(),
        "p11scope/inventory-diagnostics/v1"
    );

    assert_eq!(diff_report_schema(), "p11scope/inventory-diff/v1");

    assert_eq!(inventory["object_observations"]["version"], 1);
    assert_eq!(OBSERVATIONS_VERSION, 1);
    assert_eq!(p11scope_manifest::manifest::SCHEMA, "p11scope-manifest/5");

    // No schema identifier embeds the product version.
    let product = env!("CARGO_PKG_VERSION");
    assert!(!product.is_empty());
    assert!(
        format!("carrier {product}").contains(product),
        "the absence check below can fire"
    );
    for id in [
        metrics["schema"].as_str().unwrap(),
        profile["schema"].as_str().unwrap(),
        inspect["schema"].as_str().unwrap(),
        inventory["schema"].as_str().unwrap(),
        EVENT_SCHEMA,
        streamed["schema"].as_str().unwrap(),
        crate::inventory_diagnostics::SCHEMA,
        "p11scope/inventory-diff/v1",
        p11scope_manifest::manifest::SCHEMA,
    ] {
        assert!(!id.contains(product), "schema id embeds {product}: {id}");
    }
}
