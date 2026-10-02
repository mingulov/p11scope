//! SPDX-License-Identifier: GPL-3.0-or-later
//! S1 validation: reference-model sequences (D1), the false-join
//! matrix (D2), Phase-4 workload replay with four-way agreement (D3),
//! and the matched overhead runs (D5) — all through the real reducer
//! and the SAME in-crate harness, asserting rendered JSON.
//!
//! Every sequence drives scripted [`SemanticCall`] streams through the
//! production batch boundary (stage → `commit_batch` → render) and
//! asserts calls ≠ operations counts plus the exact end state. D4
//! (public-command matrix) lives in `tests/inventory_command.rs`.

use crate::discovery::caller_registry::{CallerId, ModuleKey, RegistryLimits};
use crate::discovery::inventory_workload::{Harness, ScaleSpec};
use crate::inventory_dashboard::{DashboardState, Viewport, render_frame};
use crate::inventory_events::{EventWriter, emit_snapshot_as_events};
use crate::inventory_present::{Presentation, render_snapshot};
use crate::semantics_edge::SemanticCall;
use p11scope_ebpf_common::{SESSION_NONE, capture};
use pkcs11_types::CkRv;
use std::collections::BTreeSet;

const AES_GCM: u64 = 0x1087;
const RSA_PSS: u64 = 0x000d;
const ECDSA: u64 = 0x1041;
const VENDOR: u64 = 0x8000_1042;

fn harness() -> Harness {
    Harness::new(RegistryLimits::default_limits()).unwrap()
}

/// One caller, one module, one edge, committed: the D1/D2 stage.
fn single_edge() -> (Harness, CallerId, ModuleKey) {
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "s1-single",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 1,
        first_pid: 9000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let caller = caller_of(&harness, 9000);
    (harness, caller, scale_key(0))
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

fn caller_of(harness: &Harness, pid: u32) -> CallerId {
    harness
        .coordinator()
        .adapter()
        .live_id(pid)
        .expect("live caller")
}

fn call(function: &str, session: u64, rv: u64, ts_ns: u64) -> SemanticCall {
    SemanticCall {
        function: function.into(),
        rv,
        session,
        ts_ns,
        ..SemanticCall::default()
    }
}

fn init(function: &str, session: u64, mechanism: u64, ts_ns: u64) -> SemanticCall {
    SemanticCall {
        function: function.into(),
        session,
        mechanism,
        capture: capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL,
        ts_ns,
        ..SemanticCall::default()
    }
}

fn op(function: &str, session: u64, ts_ns: u64) -> SemanticCall {
    SemanticCall {
        function: function.into(),
        session,
        capture: capture::MECHANISM_NONE | capture::OUTPUT_NON_NULL,
        ts_ns,
        ..SemanticCall::default()
    }
}

fn edge_json<'a>(
    document: &'a serde_json::Value,
    caller: &str,
    module: &str,
) -> &'a serde_json::Value {
    document["edges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|edge| edge["caller"] == caller && edge["module"] == module)
        .unwrap_or_else(|| panic!("missing edge {caller}->{module}"))
}

fn render(harness: &mut Harness) -> serde_json::Value {
    harness.commit();
    harness.render()
}

// ---------------------------------------------------------------------------
// D1: reference-model sequences through the real reducer to JSON.
// ---------------------------------------------------------------------------

#[test]
fn d1_init_success_completes_with_exact_mechanism_row() {
    let (mut harness, caller, key) = single_edge();
    harness.observe_semantic(caller, &key, init("C_SignInit", 7, RSA_PSS, 100));
    harness.observe_semantic(caller, &key, op("C_Sign", 7, 110));
    let document = render(&mut harness);
    let edge = edge_json(&document, "c0", "m0");
    assert_eq!(edge["semantics"], "observed");
    let mechs = edge["mechanisms"].as_array().unwrap();
    assert_eq!(mechs.len(), 1);
    assert_eq!(mechs[0]["mechanism"], RSA_PSS);
    assert_eq!(mechs[0]["mechanism_hex"], "0xd");
    assert_eq!(mechs[0]["name"], "CKM_RSA_PKCS_PSS");
    assert_eq!(mechs[0]["operations"], serde_json::json!(["sign"]));
    assert_eq!(mechs[0]["calls"], 2);
    assert_eq!(mechs[0]["errors"], 0);
    assert_eq!(mechs[0]["last_seen_ns"], 110);
    assert_eq!(
        mechs[0]["evidence"]["functions"],
        serde_json::json!(["C_Sign", "C_SignInit"])
    );
    assert_eq!(
        mechs[0]["evidence"]["returns"],
        serde_json::json!([{"rv": 0, "rv_hex": "0x0", "name": "CKR_OK"}])
    );
    assert_eq!(mechs[0]["evidence"]["truncated"], false);
    let ops = &edge["operations"];
    assert_eq!(ops["calls"], 2);
    assert_eq!(ops["started"], 1);
    assert_eq!(ops["completed"], 1);
    assert_eq!(ops["cancelled"], 0);
    assert_eq!(ops["failed"], 0);
    assert_eq!(ops["unknown"], 0);
    assert_eq!(ops["orphans"], 0);
    assert_eq!(ops["active"], serde_json::json!([]));
    assert_eq!(document["budgets"]["semantic_state"]["occupied"], 1);
    assert_eq!(document["budgets"]["semantic_state"]["status"], "observed");
    assert_eq!(document["budgets"]["semantic_state"]["unknown_edges"], 0);
}

#[test]
fn d1_failed_init_means_no_operation_and_no_evidence_label() {
    let (mut harness, caller, key) = single_edge();
    let failed = SemanticCall {
        rv: CkRv::OPERATION_ACTIVE.0,
        ..init("C_SignInit", 7, RSA_PSS, 100)
    };
    harness.observe_semantic(caller, &key, failed);
    let document = render(&mut harness);
    let edge = edge_json(&document, "c0", "m0");
    assert_eq!(edge["semantics"], "unknown (no operation evidence)");
    assert!(edge["mechanisms"].is_null());
    assert!(edge["operations"].is_null());
    // The feed exists (occupied) but established no claim (unknown).
    assert_eq!(document["budgets"]["semantic_state"]["occupied"], 1);
    assert_eq!(document["budgets"]["semantic_state"]["status"], "observed");
    assert_eq!(document["budgets"]["semantic_state"]["unknown_edges"], 1);
}

#[test]
fn d1_multipart_retry_is_n_calls_one_operation() {
    let (mut harness, caller, key) = single_edge();
    harness.observe_semantic(caller, &key, init("C_EncryptInit", 7, AES_GCM, 100));
    let mut retry = op("C_EncryptUpdate", 7, 110);
    retry.rv = CkRv::BUFFER_TOO_SMALL.0;
    harness.observe_semantic(caller, &key, retry);
    harness.observe_semantic(caller, &key, op("C_EncryptUpdate", 7, 120));
    harness.observe_semantic(caller, &key, op("C_EncryptFinal", 7, 130));
    let document = render(&mut harness);
    let edge = edge_json(&document, "c0", "m0");
    let ops = &edge["operations"];
    assert_eq!(ops["calls"], 4, "retry loop: N calls");
    assert_eq!(ops["started"], 1, "retry loop: one operation");
    assert_eq!(ops["completed"], 1);
    assert_eq!(edge["mechanisms"][0]["calls"], 4);
    assert_eq!(edge["mechanisms"][0]["errors"], 1);
    assert_eq!(edge["mechanisms"][0]["name"], "CKM_AES_GCM");
}

#[test]
fn d1_size_query_then_retry_completes() {
    let (mut harness, caller, key) = single_edge();
    harness.observe_semantic(caller, &key, init("C_SignInit", 7, RSA_PSS, 100));
    let mut query = op("C_Sign", 7, 110);
    query.rv = CkRv::BUFFER_TOO_SMALL.0;
    harness.observe_semantic(caller, &key, query);
    harness.observe_semantic(caller, &key, op("C_Sign", 7, 120));
    let document = render(&mut harness);
    let ops = &edge_json(&document, "c0", "m0")["operations"];
    assert_eq!(ops["calls"], 3);
    assert_eq!(ops["started"], 1);
    assert_eq!(ops["completed"], 1);
}

#[test]
fn d1_cancellation_paths_end_cancelled_never_completed() {
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "s1-cancel",
        callers: 1,
        modules: 4,
        edges_per_caller: 4,
        endpoints_per_module: 1,
        first_pid: 9100,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let caller = caller_of(&harness, 9100);
    // Explicit cancel.
    harness.observe_semantic(caller, &scale_key(0), init("C_SignInit", 7, RSA_PSS, 100));
    let mut cancel = call("C_SessionCancel", 7, CkRv::OK.0, 110);
    cancel.flags = 0x0000_0800; // CKF_SIGN
    harness.observe_semantic(caller, &scale_key(0), cancel);
    // Competing Init.
    harness.observe_semantic(caller, &scale_key(1), init("C_SignInit", 7, RSA_PSS, 100));
    harness.observe_semantic(caller, &scale_key(1), init("C_SignInit", 7, AES_GCM, 110));
    // Session close.
    harness.observe_semantic(caller, &scale_key(2), init("C_SignInit", 7, RSA_PSS, 100));
    harness.observe_semantic(
        caller,
        &scale_key(2),
        call("C_CloseSession", 7, CkRv::OK.0, 110),
    );
    // Finalize.
    harness.observe_semantic(caller, &scale_key(3), init("C_SignInit", 7, RSA_PSS, 100));
    harness.observe_semantic(
        caller,
        &scale_key(3),
        call("C_Finalize", SESSION_NONE, CkRv::OK.0, 110),
    );
    let document = render(&mut harness);
    for (module, started) in [("m0", 1), ("m1", 2), ("m2", 1), ("m3", 1)] {
        let ops = &edge_json(&document, "c0", module)["operations"];
        assert_eq!(ops["started"], started, "{module}");
        assert_eq!(ops["cancelled"], 1, "{module}");
        assert_eq!(ops["completed"], 0, "{module}: never completed");
    }
    for module in ["m0", "m2", "m3"] {
        let ops = &edge_json(&document, "c0", module)["operations"];
        assert_eq!(ops["active"], serde_json::json!([]), "{module}");
    }
    // The competing Init cancelled exactly the replaced operation —
    // and its replacement is still live.
    let ops = &edge_json(&document, "c0", "m1")["operations"];
    assert_eq!(ops["cancelled"], 1);
    assert_eq!(
        ops["active"],
        serde_json::json!([{"category": "sign", "state": "initialized", "count": 1}])
    );
}

#[test]
fn d1_message_based_flow_completes_in_its_category() {
    let (mut harness, caller, key) = single_edge();
    harness.observe_semantic(caller, &key, init("C_MessageSignInit", 7, RSA_PSS, 100));
    harness.observe_semantic(caller, &key, op("C_SignMessage", 7, 110));
    harness.observe_semantic(caller, &key, op("C_MessageSignFinal", 7, 120));
    let document = render(&mut harness);
    let edge = edge_json(&document, "c0", "m0");
    let ops = &edge["operations"];
    assert_eq!(ops["calls"], 3);
    assert_eq!(ops["started"], 1);
    assert_eq!(ops["completed"], 1);
    assert_eq!(
        edge["mechanisms"][0]["operations"],
        serde_json::json!(["message_sign"])
    );
}

#[test]
fn d1_async_pending_flow_completes() {
    let (mut harness, caller, key) = single_edge();
    harness.observe_semantic(caller, &key, init("C_SignInit", 7, RSA_PSS, 100));
    let mut pending = op("C_Sign", 7, 110);
    pending.rv = CkRv::PENDING.0;
    harness.observe_semantic(caller, &key, pending);
    let mut complete = call("C_AsyncComplete", 7, CkRv::OK.0, 120);
    complete.target_function = crate::kinds::function_id("C_Sign").unwrap();
    harness.observe_semantic(caller, &key, complete);
    let document = render(&mut harness);
    let ops = &edge_json(&document, "c0", "m0")["operations"];
    assert_eq!(ops["calls"], 3);
    assert_eq!(ops["started"], 1);
    assert_eq!(ops["completed"], 1);
}

#[test]
fn d1_no_overclaim_keys_and_exact_shapes() {
    // One multi-mechanism edge: GCM encrypt, PSS sign, ECDSA sign,
    // plus a vendor id — then the output must carry no size, curve,
    // or parameter keys anywhere (B2).
    let (mut harness, caller, key) = single_edge();
    harness.observe_semantic(caller, &key, init("C_EncryptInit", 7, AES_GCM, 100));
    harness.observe_semantic(caller, &key, op("C_Encrypt", 7, 110));
    harness.observe_semantic(caller, &key, init("C_SignInit", 8, RSA_PSS, 120));
    harness.observe_semantic(caller, &key, op("C_Sign", 8, 130));
    harness.observe_semantic(caller, &key, init("C_SignInit", 9, ECDSA, 140));
    harness.observe_semantic(caller, &key, op("C_Sign", 9, 150));
    harness.observe_semantic(caller, &key, init("C_DecryptInit", 10, VENDOR, 160));
    harness.observe_semantic(caller, &key, op("C_Decrypt", 10, 170));
    let document = render(&mut harness);
    let edge = edge_json(&document, "c0", "m0");
    let names: Vec<&str> = edge["mechanisms"]
        .as_array()
        .unwrap()
        .iter()
        .map(|mech| mech["name"].as_str().unwrap_or("null"))
        .collect();
    assert_eq!(
        names,
        vec!["CKM_RSA_PKCS_PSS", "CKM_ECDSA", "CKM_AES_GCM", "null"]
    );
    // The vendor id survives verbatim, unnamed.
    let vendor = edge["mechanisms"]
        .as_array()
        .unwrap()
        .iter()
        .find(|mech| mech["mechanism"] == VENDOR)
        .unwrap();
    assert_eq!(vendor["mechanism_hex"], "0x80001042");
    assert!(vendor["name"].is_null());
    // Exact key sets: nothing may creep in unreviewed.
    for mech in edge["mechanisms"].as_array().unwrap() {
        let keys: BTreeSet<&str> = mech
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            BTreeSet::from([
                "mechanism",
                "mechanism_hex",
                "name",
                "operations",
                "calls",
                "errors",
                "last_seen_ns",
                "evidence"
            ])
        );
        let evidence: BTreeSet<&str> = mech["evidence"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            evidence,
            BTreeSet::from(["functions", "returns", "truncated"])
        );
    }
    let ops_keys: BTreeSet<&str> = edge["operations"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        ops_keys,
        BTreeSet::from([
            "calls",
            "started",
            "completed",
            "cancelled",
            "failed",
            "unknown",
            "orphans",
            "dropped",
            "last_seen_ns",
            "active",
            "evidence"
        ])
    );
    // The over-claim pin: no size/curve/parameter key anywhere.
    let mut forbidden = Vec::new();
    collect_keys(&document, &mut forbidden);
    assert!(forbidden.is_empty(), "over-claim keys: {forbidden:?}");
}

/// Every object key in the document containing a forbidden
/// over-claim substring (case-insensitive).
fn collect_keys(value: &serde_json::Value, forbidden: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let lower = key.to_lowercase();
                if lower.contains("size") || lower.contains("curve") || lower.contains("param") {
                    forbidden.push(key.clone());
                }
                collect_keys(child, forbidden);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_keys(item, forbidden);
            }
        }
        _ => {}
    }
}

#[test]
fn d1_right_now_trichotomy_stays_three_distinct_facts() {
    // Edge m0: recently observed entries, no operation. Edge m1: an
    // initialized operation, quiet entries. Edge m2: an API call in
    // flight. Three distinct states, never merged (B3).
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "s1-trichotomy",
        callers: 1,
        modules: 3,
        edges_per_caller: 3,
        endpoints_per_module: 1,
        first_pid: 9200,
    };
    harness.stage_scale(&spec);
    harness.commit();
    harness
        .coordinator_mut()
        .registry_mut()
        .set_usage_feed(true);
    let caller = caller_of(&harness, 9200);
    let now = harness.now_ns();
    harness
        .coordinator_mut()
        .registry_mut()
        .observe_entries(caller, &scale_key(0), 2, now);
    harness.observe_semantic(caller, &scale_key(1), init("C_SignInit", 7, RSA_PSS, 100));
    harness
        .coordinator_mut()
        .registry_mut()
        .set_in_flight(caller, &scale_key(2), true);
    harness.commit();
    let document = harness.render();
    let recent = edge_json(&document, "c0", "m0");
    let initialized = edge_json(&document, "c0", "m1");
    let in_flight = edge_json(&document, "c0", "m2");
    // Recently observed call: entries recency, no operation.
    assert_eq!(recent["entries"]["count"], 2);
    assert!(recent["operations"].is_null());
    assert!(!recent["entries"]["in_flight"].as_bool().unwrap());
    // Operation initialized: live machine, quiet entries.
    assert_eq!(initialized["entries"]["count"], 0);
    assert!(!initialized["entries"]["in_flight"].as_bool().unwrap());
    assert_eq!(
        initialized["operations"]["active"],
        serde_json::json!([{"category": "sign", "state": "initialized", "count": 1}])
    );
    // API call in flight: the usage flag, nothing else.
    assert!(in_flight["entries"]["in_flight"].as_bool().unwrap());
    assert_eq!(in_flight["entries"]["count"], 0);
    assert!(in_flight["operations"].is_null());
    // The dashboard activity wires genuine operation state (B4):
    // initialized-op and in-flight edges read in-flight; the recent
    // edge reads recently observed.
    let presentation = presentation_for(&harness, &document);
    let activity = |module: &str| {
        presentation
            .edges
            .iter()
            .find(|edge| edge.module.label() == module)
            .unwrap()
            .activity
    };
    use crate::inventory_present::Activity;
    assert_eq!(activity("m0"), Activity::RecentlyObserved);
    assert_eq!(activity("m1"), Activity::InFlight);
    assert_eq!(activity("m2"), Activity::InFlight);
}

/// Re-capture the document's exact observation window (the
/// `inventory_events_tests` pattern): one capture for every renderer.
fn presentation_for(harness: &Harness, document: &serde_json::Value) -> Presentation {
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

// ---------------------------------------------------------------------------
// D2: false-join matrix.
// ---------------------------------------------------------------------------

#[test]
fn d2_identical_handles_across_callers_never_merge() {
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "s1-handles-callers",
        callers: 2,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 1,
        first_pid: 9300,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let c0 = caller_of(&harness, 9300);
    let c1 = caller_of(&harness, 9301);
    // Same numeric handle 7 on both edges, different mechanisms.
    harness.observe_semantic(c0, &scale_key(0), init("C_SignInit", 7, RSA_PSS, 100));
    harness.observe_semantic(c0, &scale_key(0), op("C_Sign", 7, 110));
    harness.observe_semantic(c1, &scale_key(0), init("C_EncryptInit", 7, AES_GCM, 120));
    harness.observe_semantic(c1, &scale_key(0), op("C_Encrypt", 7, 130));
    let document = render(&mut harness);
    let first = edge_json(&document, "c0", "m0");
    let second = edge_json(&document, "c1", "m0");
    assert_eq!(first["mechanisms"][0]["name"], "CKM_RSA_PKCS_PSS");
    assert_eq!(first["operations"]["completed"], 1);
    assert_eq!(second["mechanisms"][0]["name"], "CKM_AES_GCM");
    assert_eq!(second["operations"]["completed"], 1);
    // Neither edge saw the other's mechanism.
    assert_eq!(first["mechanisms"].as_array().unwrap().len(), 1);
    assert_eq!(second["mechanisms"].as_array().unwrap().len(), 1);
}

#[test]
fn d2_identical_handles_across_modules_never_merge() {
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "s1-handles-modules",
        callers: 1,
        modules: 2,
        edges_per_caller: 2,
        endpoints_per_module: 1,
        first_pid: 9400,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let caller = caller_of(&harness, 9400);
    harness.observe_semantic(caller, &scale_key(0), init("C_SignInit", 7, RSA_PSS, 100));
    harness.observe_semantic(caller, &scale_key(1), init("C_SignInit", 7, ECDSA, 110));
    let document = render(&mut harness);
    let first = edge_json(&document, "c0", "m0");
    let second = edge_json(&document, "c0", "m1");
    assert_eq!(first["mechanisms"][0]["mechanism"], RSA_PSS);
    assert_eq!(second["mechanisms"][0]["mechanism"], ECDSA);
    assert_eq!(first["operations"]["started"], 1);
    assert_eq!(second["operations"]["started"], 1);
}

#[test]
fn d2_successive_lifetimes_never_merge() {
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "s1-lifetimes",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 1,
        first_pid: 9500,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let first = caller_of(&harness, 9500);
    harness.observe_semantic(first, &scale_key(0), init("C_SignInit", 7, RSA_PSS, 100));
    harness.commit();
    // The pid dies: the first incarnation retires, its live operation
    // ends unknown (never completed), its claims are retained.
    harness.source().kill(9500);
    harness.advance(10);
    let now = harness.now_ns();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &BTreeSet::new(),
        &mut |_| crate::discovery::caller_registry::ImageAuthority::ScanPinned,
        now,
    );
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    harness.commit();
    // The pid is reused by a new generation: a new incarnation with
    // the same numeric handle space, never merged.
    harness.source().spawn(9500, 9999);
    harness.advance(10);
    let now = harness.now_ns();
    let mut observed = BTreeSet::new();
    observed.insert(9500);
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| crate::discovery::caller_registry::ImageAuthority::ScanPinned,
        now,
    );
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    harness.commit();
    let second = caller_of(&harness, 9500);
    assert_ne!(first, second);
    // The new incarnation maps the module (its own edge) and starts
    // its own operation on the same numeric handle.
    let now = harness.now_ns();
    harness.coordinator_mut().registry_mut().note_mapping(
        second,
        9500,
        crate::discovery::caller_registry::ModuleInfo {
            path: "/scale/m0.so".into(),
            key: scale_key(0),
            build_id: None,
            identity_source: Some("workload".into()),
            admission: crate::discovery::caller_registry::AdmissionState::Admitted,
            admission_class: Some("exact".into()),
            admission_endpoints: Some(1),
            admission_reasons: Vec::new(),
        },
        now,
    );
    harness.commit();
    harness.observe_semantic(
        second,
        &scale_key(0),
        init("C_EncryptInit", 7, AES_GCM, 200),
    );
    let document = render(&mut harness);
    let old = edge_json(&document, &first.label(), "m0");
    let new = edge_json(&document, &second.label(), "m0");
    // Old edge: claims retained, live op ended unknown by retirement.
    assert_eq!(old["mechanisms"][0]["mechanism"], RSA_PSS);
    assert_eq!(old["operations"]["started"], 1);
    assert_eq!(old["operations"]["unknown"], 1);
    assert_eq!(old["operations"]["completed"], 0);
    assert_eq!(old["mapping"]["state"], "ended");
    // New edge: its own operation, none of the old claims.
    assert_eq!(new["mechanisms"][0]["mechanism"], AES_GCM);
    assert_eq!(new["mechanisms"].as_array().unwrap().len(), 1);
    assert_eq!(new["operations"]["started"], 1);
    assert_eq!(new["operations"]["unknown"], 0);
    assert_eq!(
        new["operations"]["active"],
        serde_json::json!([{"category": "encrypt", "state": "initialized", "count": 1}])
    );
}

#[test]
fn d2_cross_session_init_update_never_joins() {
    let (mut harness, caller, key) = single_edge();
    harness.observe_semantic(caller, &key, init("C_SignInit", 7, RSA_PSS, 100));
    harness.observe_semantic(caller, &key, op("C_SignUpdate", 8, 110));
    let document = render(&mut harness);
    let ops = &edge_json(&document, "c0", "m0")["operations"];
    assert_eq!(ops["started"], 1);
    assert_eq!(ops["orphans"], 1);
    assert_eq!(
        ops["active"],
        serde_json::json!([{"category": "sign", "state": "initialized", "count": 1}])
    );
}

#[test]
fn d2_midlife_attach_treats_preexisting_as_unknown_origin() {
    let (mut harness, caller, key) = single_edge();
    // No Init, no Open observed: an Update, a completion for nothing
    // pending, and a close the capture never saw opening.
    harness.observe_semantic(caller, &key, op("C_SignUpdate", 7, 100));
    let mut complete = call("C_AsyncComplete", 7, CkRv::OK.0, 110);
    complete.target_function = crate::kinds::function_id("C_Sign").unwrap();
    harness.observe_semantic(caller, &key, complete);
    harness.observe_semantic(caller, &key, call("C_CloseSession", 7, CkRv::OK.0, 120));
    let document = render(&mut harness);
    let edge = edge_json(&document, "c0", "m0");
    // Unknown-origin evidence, never invented operations.
    assert_eq!(edge["semantics"], "unknown (no operation evidence)");
    assert!(edge["mechanisms"].is_null());
    assert!(edge["operations"].is_null());
    // ... while the registry still counts the orphans internally:
    // re-run with an Init first and the orphans show in the open.
    let (mut harness, caller, key) = single_edge();
    harness.observe_semantic(caller, &key, init("C_SignInit", 7, RSA_PSS, 100));
    harness.observe_semantic(caller, &key, op("C_SignUpdate", 8, 110));
    let document = render(&mut harness);
    let ops = &edge_json(&document, "c0", "m0")["operations"];
    assert_eq!(ops["started"], 1);
    assert_eq!(ops["orphans"], 1);
}

#[test]
fn d2_capture_loss_invalidates_with_explicit_accounting() {
    let (mut harness, caller, key) = single_edge();
    harness.observe_semantic(caller, &key, init("C_SignInit", 7, RSA_PSS, 100));
    harness.observe_semantic(caller, &key, op("C_SignUpdate", 7, 110));
    harness.note_semantic_loss("ring-buffer overflow evicted 12 events");
    let document = render(&mut harness);
    let edge = edge_json(&document, "c0", "m0");
    let ops = &edge["operations"];
    assert_eq!(ops["unknown"], 1);
    assert_eq!(ops["completed"], 0);
    assert_eq!(ops["active"], serde_json::json!([]));
    // Historical claims stand.
    assert_eq!(edge["mechanisms"][0]["calls"], 2);
    // The loss itself is a named gap, never silent.
    let gaps = document["gaps"].as_array().unwrap();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0]["subject"], "semantic capture loss");
    assert_eq!(gaps[0]["reason"], "ring-buffer overflow evicted 12 events");
}

#[test]
fn d2_semantic_budget_refusal_is_named_and_counted() {
    let mut harness =
        Harness::new(RegistryLimits::new(64, 64, 64, 64, 1 << 20, 1).unwrap()).unwrap();
    let spec = ScaleSpec {
        name: "s1-semantic-budget",
        callers: 1,
        modules: 2,
        edges_per_caller: 2,
        endpoints_per_module: 1,
        first_pid: 9600,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let caller = caller_of(&harness, 9600);
    harness.observe_semantic(caller, &scale_key(0), init("C_SignInit", 7, RSA_PSS, 100));
    harness.observe_semantic(caller, &scale_key(1), init("C_SignInit", 7, RSA_PSS, 110));
    let document = render(&mut harness);
    let budget = &document["budgets"]["semantic_state"];
    assert_eq!(budget["limit"], 1);
    assert_eq!(budget["occupied"], 1);
    assert_eq!(budget["refused"], 1);
    assert_eq!(edge_json(&document, "c0", "m0")["semantics"], "observed");
    // The refused edge stays withheld: refusal never invents state.
    assert_eq!(
        edge_json(&document, "c0", "m1")["semantics"],
        "unknown (semantic capture withheld)"
    );
    let gaps = document["gaps"].as_array().unwrap();
    assert!(
        gaps.iter()
            .any(|gap| gap["subject"] == "semantic state capacity exhausted"
                && gap["budget"]["resource"] == "semantic_state"
                && gap["budget"]["limit"] == 1
                && gap["budget"]["requested"] == 2)
    );
}

// ---------------------------------------------------------------------------
// D3: Phase-4 workload replay with four-way agreement (JSON, snapshot,
// dashboard, stream) on identities, states, totals, gaps, AND the new
// semantic fields — through the SAME in-crate harness.
// ---------------------------------------------------------------------------

#[test]
fn d3_replay_scale_workload_with_four_way_semantic_agreement() {
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "s1-replay",
        callers: 4,
        modules: 2,
        edges_per_caller: 2,
        endpoints_per_module: 2,
        first_pid: 9700,
    };
    harness.stage_scale(&spec);
    harness.commit();
    harness
        .coordinator_mut()
        .registry_mut()
        .set_usage_feed(true);
    let now = harness.now_ns();
    // Completed sign, in-flight encrypt, unauthorized feed, failed
    // Init, plus bare entries — every semantic shape in one replay.
    let c0 = caller_of(&harness, 9700);
    harness.observe_semantic(c0, &scale_key(0), init("C_SignInit", 7, RSA_PSS, 100));
    harness.observe_semantic(c0, &scale_key(0), op("C_Sign", 7, 110));
    let c1 = caller_of(&harness, 9701);
    harness.observe_semantic(c1, &scale_key(1), init("C_EncryptInit", 7, AES_GCM, 120));
    harness.observe_semantic(c1, &scale_key(1), op("C_EncryptUpdate", 7, 130));
    let c2 = caller_of(&harness, 9702);
    let mut unauthorized = init("C_SignInit", 7, RSA_PSS, 140);
    unauthorized.authorized = false;
    harness.observe_semantic(c2, &scale_key(0), unauthorized);
    let c3 = caller_of(&harness, 9703);
    let failed = SemanticCall {
        rv: CkRv::OPERATION_ACTIVE.0,
        ..init("C_SignInit", 7, RSA_PSS, 150)
    };
    harness.observe_semantic(c3, &scale_key(1), failed);
    harness
        .coordinator_mut()
        .registry_mut()
        .observe_entries(c0, &scale_key(1), 5, now);
    let document = render(&mut harness);
    assert_eq!(document["callers"].as_array().unwrap().len(), 4);
    assert_eq!(document["modules"].as_array().unwrap().len(), 2);
    assert_eq!(document["edges"].as_array().unwrap().len(), 8);
    assert_eq!(document["budgets"]["semantic_state"]["occupied"], 4);
    assert_eq!(document["budgets"]["semantic_state"]["status"], "observed");
    assert_eq!(document["budgets"]["semantic_state"]["unknown_edges"], 6);
    let presentation = presentation_for(&harness, &document);
    assert_four_way_semantic_agreement(&document, &presentation);
}

#[test]
fn d3_canonical_churn_storm_stays_withheld_and_agrees() {
    // Equal-coverage leg: the VERBATIM canonical Phase-4 churn-storm
    // spec (128 pids x 8 generations x 16 modules) replays through S1
    // with no semantic feed — nothing materializes, every column
    // reads withheld, and all four renderers agree.
    let mut harness = harness();
    let spec = crate::discovery::inventory_workload::ChurnSpec {
        pids: 128,
        generations: 8,
        modules: 16,
        first_pid: 80_000,
    };
    let (admitted, _events) = harness.run_churn(&spec);
    assert_eq!(admitted, 1024, "canonical storm admits every incarnation");
    let document = harness.render();
    assert_eq!(document["edges"].as_array().unwrap().len(), 1024);
    assert_eq!(document["budgets"]["semantic_state"]["occupied"], 0);
    assert_eq!(document["budgets"]["semantic_state"]["status"], "withheld");
    assert_eq!(document["budgets"]["semantic_state"]["refused"], 0);
    assert_eq!(document["budgets"]["semantic_state"]["unknown_edges"], 1024);
    for edge in document["edges"].as_array().unwrap() {
        assert_eq!(edge["semantics"], "unknown (semantic capture withheld)");
        assert!(edge["mechanisms"].is_null());
        assert!(edge["operations"].is_null());
    }
    let presentation = presentation_for(&harness, &document);
    assert_four_way_semantic_agreement(&document, &presentation);
}

/// JSON vs snapshot vs dashboard vs stream on one capture: every
/// edge's semantic label in all four, and every mechanism row and
/// operation aggregate of observed edges in all four.
fn assert_four_way_semantic_agreement(document: &serde_json::Value, presentation: &Presentation) {
    let snapshot = render_snapshot(presentation);
    let frame = crate::inventory_dashboard::DisplayFrame {
        presentation: std::sync::Arc::new(presentation.clone()),
        log: crate::inventory_dashboard::LogTail::bounded().snapshot(),
    };
    let bytes = render_frame(
        &frame,
        Viewport {
            width: 200,
            height: presentation
                .edges
                .len()
                .saturating_mul(12)
                .saturating_add(40),
        },
        &DashboardState::new(),
    );
    let dashboard = String::from_utf8_lossy(&bytes);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s1-events.jsonl");
    let mut writer = EventWriter::create(&path, 1 << 30, 5).unwrap();
    emit_snapshot_as_events(&mut writer, presentation, 999).unwrap();
    writer.finish(serde_json::json!({}), 999).unwrap();
    let stream = std::fs::read_to_string(&path).unwrap();
    let events: Vec<serde_json::Value> = stream
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    for edge_json in document["edges"].as_array().unwrap() {
        let caller = edge_json["caller"].as_str().unwrap();
        let module = edge_json["module"].as_str().unwrap();
        let label = edge_json["semantics"].as_str().unwrap();
        let snapshot_line = snapshot
            .lines()
            .find(|line| line.starts_with(&format!("edge {caller} -> {module} ")))
            .unwrap_or_else(|| panic!("missing snapshot line for {caller}->{module}"));
        assert!(
            snapshot_line.contains(label),
            "snapshot label for {caller}->{module}: {snapshot_line}"
        );
        assert!(
            dashboard.contains(&format!("semantics {label}")),
            "dashboard label for {caller}->{module}"
        );
        let streamed = events
            .iter()
            .find(|event| {
                event["kind"] == "edge_observed"
                    && event["event"]["caller"] == caller
                    && event["event"]["module"] == module
            })
            .unwrap_or_else(|| panic!("missing stream event for {caller}->{module}"));
        assert_eq!(streamed["event"]["semantics"], label);
        assert_eq!(streamed["event"]["mechanisms"], edge_json["mechanisms"]);
        assert_eq!(streamed["event"]["operations"], edge_json["operations"]);
        if edge_json["operations"].is_null() {
            continue;
        }
        // Observed edge: every mechanism name and operation fact in
        // the snapshot and the dashboard too.
        for mech in edge_json["mechanisms"].as_array().unwrap() {
            let name = mech["name"].as_str().unwrap_or("null");
            let hex = mech["mechanism_hex"].as_str().unwrap();
            let tag = if name == "null" {
                hex.to_string()
            } else {
                format!("{name}/{hex}")
            };
            assert!(
                snapshot_line.contains(&tag),
                "snapshot mech {tag} for {caller}->{module}: {snapshot_line}"
            );
            assert!(
                dashboard.contains(name) || dashboard.contains(hex),
                "dashboard mech {tag} for {caller}->{module}"
            );
            for function in mech["evidence"]["functions"].as_array().unwrap() {
                assert!(
                    snapshot_line.contains(function.as_str().unwrap()),
                    "snapshot provenance for {caller}->{module}: {snapshot_line}"
                );
            }
        }
        let ops = &edge_json["operations"];
        for text in [
            format!("calls={}", ops["calls"]),
            format!("started={}", ops["started"]),
            format!("completed={}", ops["completed"]),
            format!("orphans={}", ops["orphans"]),
        ] {
            assert!(
                snapshot_line.contains(&text),
                "snapshot {text} for {caller}->{module}: {snapshot_line}"
            );
        }
        assert!(
            dashboard.contains(&format!("{} calls", ops["calls"])),
            "dashboard calls for {caller}->{module}"
        );
        for active in ops["active"].as_array().unwrap() {
            let tag = format!(
                "{}:{}",
                active["category"].as_str().unwrap(),
                active["state"].as_str().unwrap()
            );
            assert!(
                snapshot_line.contains(&tag),
                "snapshot active {tag} for {caller}->{module}"
            );
            assert!(
                dashboard.contains(&tag),
                "dashboard active {tag} for {caller}->{module}"
            );
        }
    }
    // Snapshot and dashboard budgets mirror the JSON semantic row.
    assert!(
        snapshot.contains(&format!(
            "semantic_state {} held {}/{} unknown {} refused {}",
            document["budgets"]["semantic_state"]["status"]
                .as_str()
                .unwrap(),
            document["budgets"]["semantic_state"]["occupied"],
            document["budgets"]["semantic_state"]["limit"],
            document["budgets"]["semantic_state"]["unknown_edges"],
            document["budgets"]["semantic_state"]["refused"],
        )),
        "snapshot semantic budget"
    );
    assert!(
        dashboard.contains(&format!(
            "semantic {} ({} held, {} unknown, {} refused)",
            document["budgets"]["semantic_state"]["status"]
                .as_str()
                .unwrap(),
            document["budgets"]["semantic_state"]["occupied"],
            document["budgets"]["semantic_state"]["unknown_edges"],
            document["budgets"]["semantic_state"]["refused"],
        )),
        "dashboard semantic budget"
    );
}

// ---------------------------------------------------------------------------
// D5: overhead report (not a gate) — matched runs with S1 semantic
// computation on vs the reducer baseline over the same workload.
// ---------------------------------------------------------------------------

#[test]
fn d5_matched_runs_report_identical_totals_with_measured_overhead() {
    let spec = ScaleSpec {
        name: "s1-overhead",
        callers: 16,
        modules: 4,
        edges_per_caller: 4,
        endpoints_per_module: 2,
        first_pid: 20000,
    };
    let run = |semantic: bool| {
        let mut harness = harness();
        harness.stage_scale(&spec);
        harness.commit();
        harness
            .coordinator_mut()
            .registry_mut()
            .set_usage_feed(true);
        let now = harness.now_ns();
        for (index, (caller_index, module_index)) in spec.layout().iter().enumerate() {
            let pid = spec.first_pid + *caller_index as u32;
            let caller = caller_of(&harness, pid);
            let key = scale_key(*module_index);
            harness.coordinator_mut().registry_mut().observe_entries(
                caller,
                &key,
                (index % 5 + 1) as u64,
                now,
            );
            if semantic {
                feed_semantic_script(&mut harness, caller, &key, index);
            }
        }
        let started = std::time::Instant::now();
        harness.commit();
        let document = harness.render();
        (document, started.elapsed())
    };
    let (base, base_elapsed) = run(false);
    let (sem, sem_elapsed) = run(true);
    // Capture totals identical modulo the semantic extension.
    assert_eq!(
        base["callers"].as_array().unwrap().len(),
        sem["callers"].as_array().unwrap().len()
    );
    assert_eq!(
        base["modules"].as_array().unwrap().len(),
        sem["modules"].as_array().unwrap().len()
    );
    assert_eq!(
        base["edges"].as_array().unwrap().len(),
        sem["edges"].as_array().unwrap().len()
    );
    for (base_edge, sem_edge) in base["edges"]
        .as_array()
        .unwrap()
        .iter()
        .zip(sem["edges"].as_array().unwrap().iter())
    {
        assert_eq!(base_edge["caller"], sem_edge["caller"]);
        assert_eq!(base_edge["module"], sem_edge["module"]);
        // States and counts are identical; timestamps ride the real
        // harness clock and legitimately differ between runs.
        assert_eq!(base_edge["mapping"]["state"], sem_edge["mapping"]["state"]);
        assert_eq!(
            base_edge["mapping"]["interruptions"],
            sem_edge["mapping"]["interruptions"]
        );
        assert_eq!(base_edge["entries"]["count"], sem_edge["entries"]["count"]);
        assert_eq!(
            base_edge["entries"]["observation"],
            sem_edge["entries"]["observation"]
        );
    }
    assert_eq!(base["gaps"], sem["gaps"]);
    for row in ["callers", "modules", "edges", "endpoints", "counters"] {
        assert_eq!(base["budgets"][row], sem["budgets"][row], "{row}");
    }
    assert!(
        sem["budgets"]["semantic_state"]["occupied"]
            .as_u64()
            .unwrap()
            > 0
    );
    eprintln!(
        "S1 overhead over {} edges: baseline {base_elapsed:?}, semantic {sem_elapsed:?}",
        spec.layout().len(),
    );
}

/// Deterministic per-edge semantic script (D5): completed signs,
/// in-flight encrypts, failed Inits, and unauthorized feeds.
fn feed_semantic_script(harness: &mut Harness, caller: CallerId, key: &ModuleKey, index: usize) {
    let ts = 1000 + index as u64;
    match index % 4 {
        0 => {
            harness.observe_semantic(caller, key, init("C_SignInit", 7, RSA_PSS, ts));
            harness.observe_semantic(caller, key, op("C_Sign", 7, ts + 1));
        }
        1 => {
            harness.observe_semantic(caller, key, init("C_EncryptInit", 7, AES_GCM, ts));
            harness.observe_semantic(caller, key, op("C_EncryptUpdate", 7, ts + 1));
        }
        2 => {
            let failed = SemanticCall {
                rv: CkRv::OPERATION_ACTIVE.0,
                ..init("C_SignInit", 7, RSA_PSS, ts)
            };
            harness.observe_semantic(caller, key, failed);
        }
        _ => {
            let mut unauthorized = init("C_SignInit", 7, RSA_PSS, ts);
            unauthorized.authorized = false;
            harness.observe_semantic(caller, key, unauthorized);
        }
    }
}
