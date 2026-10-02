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

use crate::discovery::caller_registry::{CallerId, ModuleInfo, ModuleKey, RegistryLimits};
use crate::discovery::inventory_workload::{Harness, ScaleSpec};
use crate::inventory_dashboard::{DashboardState, Viewport, render_frame};
use crate::inventory_events::{EventWriter, emit_snapshot_as_events};
use crate::inventory_present::{Presentation, render_snapshot};
use crate::semantics_edge::SemanticCall;
use p11scope_ebpf_common::{SESSION_NONE, capture};
use pkcs11_types::CkRv;
use std::collections::{BTreeMap, BTreeSet};

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
fn d1_unreadable_mechanism_init_reports_operation_without_mechanism_row() {
    // F5 at JSON level: one operation, completed, with null
    // mechanisms — the unknown mechanism invents no row.
    let (mut harness, caller, key) = single_edge();
    let mut unreadable = init("C_SignInit", 7, 0, 100);
    unreadable.capture = capture::MECHANISM_UNREADABLE | capture::OUTPUT_NON_NULL;
    harness.observe_semantic(caller, &key, unreadable);
    harness.observe_semantic(caller, &key, op("C_Sign", 7, 110));
    let document = render(&mut harness);
    let edge = edge_json(&document, "c0", "m0");
    assert_eq!(edge["semantics"], "observed");
    assert!(edge["mechanisms"].is_null(), "no invented mechanism row");
    let ops = &edge["operations"];
    assert_eq!(ops["calls"], 2);
    assert_eq!(ops["started"], 1);
    assert_eq!(ops["completed"], 1);
    assert_eq!(ops["orphans"], 0);
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
fn d2_same_inode_distinct_instances_never_join() {
    // F7b companion: two module INSTANCES sharing one inode (same
    // device + inode, distinct content hashes — in-place replacement
    // generations, distinct ModuleKeys per the file-identity
    // contract) in ONE process, using overlapping numeric session
    // handles: their operations never join. (The same-FILE case —
    // identical key — merges; see
    // d2_same_file_double_load_merges_boundary_for_s2.)
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "s1-same-inode",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 1,
        first_pid: 9900,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let caller = caller_of(&harness, 9900);
    let first = scale_key(0);
    let info_for = |key: ModuleKey, path: &str| ModuleInfo {
        path: path.into(),
        key,
        double_loaded: false,
        build_id: None,
        identity_source: Some("workload".into()),
        admission: crate::discovery::caller_registry::AdmissionState::Admitted,
        admission_class: Some("exact".into()),
        admission_endpoints: Some(1),
        admission_reasons: Vec::new(),
    };
    // Contrast anchor: re-mapping the IDENTICAL key merges — one
    // object, one module, one edge, one session namespace.
    let now = harness.now_ns();
    harness.coordinator_mut().registry_mut().note_mapping(
        caller,
        9900,
        info_for(first.clone(), "/scale/m0.so"),
        now,
    );
    harness.commit();
    assert_eq!(harness.render()["modules"].as_array().unwrap().len(), 1);
    // The replacement generation: same device + inode, different
    // bytes — a distinct instance with its own edge.
    let second = ModuleKey::physical(
        8,
        1,
        100_000,
        Some("sha9ffff9".into()),
        "/scale/m0-replacement.so",
    );
    assert_ne!(first, second);
    let now = harness.now_ns();
    harness.coordinator_mut().registry_mut().note_mapping(
        caller,
        9900,
        info_for(second.clone(), "/scale/m0-replacement.so"),
        now,
    );
    // Overlapping numeric handle 7 on both instances, different
    // mechanisms and categories.
    harness.observe_semantic(caller, &first, init("C_SignInit", 7, RSA_PSS, 100));
    harness.observe_semantic(caller, &first, op("C_Sign", 7, 110));
    harness.observe_semantic(caller, &second, init("C_EncryptInit", 7, AES_GCM, 120));
    harness.observe_semantic(caller, &second, op("C_Encrypt", 7, 130));
    let document = render(&mut harness);
    assert_eq!(document["modules"].as_array().unwrap().len(), 2);
    assert_eq!(document["edges"].as_array().unwrap().len(), 2);
    let mut mechs: Vec<u64> = Vec::new();
    for edge in document["edges"].as_array().unwrap() {
        let rows = edge["mechanisms"].as_array().unwrap();
        assert_eq!(rows.len(), 1, "no foreign mechanism joins this edge");
        mechs.push(rows[0]["mechanism"].as_u64().unwrap());
        assert_eq!(edge["operations"]["started"], 1);
        assert_eq!(edge["operations"]["completed"], 1);
        assert_eq!(edge["operations"]["orphans"], 0);
    }
    mechs.sort_unstable();
    assert_eq!(mechs, vec![RSA_PSS, AES_GCM]);
}

#[test]
fn d2_same_file_double_load_merges_boundary_for_s2() {
    // F7b BOUNDARY PIN (merge WITHOUT scan evidence): two same-key
    // notes whose mapping evidence carries no double-load verdict —
    // the `dlopen` re-scan shape, a second loader spelling — merge
    // into ONE module and ONE edge, and overlapping numeric session
    // handles join in that edge's single session namespace with no
    // gap. The merge-by-construction stands (for `dlopen` in one
    // namespace it is CORRECT: same file → same loaded object → one
    // PKCS#11 session namespace); detection rides the scan verdict,
    // not note multiplicity (see the owned-`dlmopen` regression
    // below, which stages a flagged note and fails closed). S2's
    // instance authority MUST replace this pin with a separation
    // regression (see docs/notes/s2-instance-authority.md).
    //
    // Where the merge happens below S1, and what each layer can see:
    // - scan: `candidate_groups` (discovery/scan.rs) groups every
    //   mapping by ObjectKey (device, inode); one ScannedModule per
    //   group — but the group keeps full MapEntry refs, so duplicate
    //   executable file-offset coverage IS visible here and rides
    //   `ScannedModule::double_loaded` (fix round 3 corrected the
    //   round-2 claim that addresses never survive grouping).
    // - identity: `insert_entry_with_aliases` (discovery/identity.rs)
    //   pins same-file observations to one pinned object.
    // - observation: uprobes attach by (path, absolute file offset)
    //   (attach.rs `slot_attach_point`), so one probe fires for every
    //   same-file mapping; `Event` carries no mapping discriminator.
    // - feed: `SemanticCall` carries no instance field, and
    //   `observe_semantic` routes by (caller, ModuleKey).
    // - registry: `apply_mapping` merges same-key notes into one
    //   module/edge; a FLAGGED note latches that edge closed instead
    //   (unknown semantics + the named gap), an unflagged one merges
    //   silently, as pinned here.
    // R0 doctrine binds the framing: a pathname/hash alone cannot
    // prove a semantic module instance.
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "s1-double-load",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 1,
        first_pid: 9950,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let caller = caller_of(&harness, 9950);
    let key = scale_key(0);
    // The second load of the SAME file: identical key (same device,
    // inode, bytes), a distinct loader mapping the scan evidence
    // cannot distinguish from a re-scan of the first.
    let now = harness.now_ns();
    harness.coordinator_mut().registry_mut().note_mapping(
        caller,
        9950,
        ModuleInfo {
            path: "/scale/m0-second-load.so".into(),
            key: key.clone(),
            double_loaded: false,
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
    // The merge: one module, one edge — separation would mint two of
    // each (asserting 2 fails with left 1; see the fix-round-2
    // report for the retained RED run).
    assert_eq!(harness.render()["modules"].as_array().unwrap().len(), 1);
    assert_eq!(harness.render()["edges"].as_array().unwrap().len(), 1);
    // Overlapping numeric handle 7 on BOTH instances, different
    // mechanisms and categories: every call joins the one edge's
    // single session namespace.
    harness.observe_semantic(caller, &key, init("C_SignInit", 7, RSA_PSS, 100));
    harness.observe_semantic(caller, &key, op("C_Sign", 7, 110));
    harness.observe_semantic(caller, &key, init("C_EncryptInit", 7, AES_GCM, 120));
    harness.observe_semantic(caller, &key, op("C_Encrypt", 7, 130));
    let document = render(&mut harness);
    assert_eq!(document["modules"].as_array().unwrap().len(), 1);
    let edges = document["edges"].as_array().unwrap();
    assert_eq!(edges.len(), 1);
    // The join is silent AND total: the merged edge is
    // indistinguishable from one instance doing sign-then-encrypt —
    // both mechanisms attributed, both operations completed, zero
    // orphans.
    assert_eq!(edges[0]["mechanisms"].as_array().unwrap().len(), 2);
    assert_eq!(edges[0]["operations"]["started"], 2);
    assert_eq!(edges[0]["operations"]["completed"], 2);
    assert_eq!(edges[0]["operations"]["orphans"], 0);
    // No scan verdict rides these notes, so no detection fires: the
    // merge leaves no gap at all. (A flagged note fails closed
    // instead — see the owned-`dlmopen` regression below.)
    assert_eq!(document["gaps"].as_array().unwrap().len(), 0);
}

/// The owned double-loader: compiled from C, killed on drop.
struct DoubleLoadChild {
    child: std::process::Child,
}

impl Drop for DoubleLoadChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn d2_same_file_double_load_with_scan_evidence_forces_unknown_with_named_gap() {
    // F7b path (2): an OWNED `dlmopen` double-load — the fixture
    // driver loads one provider object in two new namespaces with
    // overlapping lifetime — detected from the child's REAL scan
    // mapping evidence (real maps → real `candidate_groups` → the
    // real `duplicate_exec_coverage` verdict), failing the merged
    // edge closed: unknown semantics + the named gap, never a silent
    // join. A later single-load note unlatches and later calls
    // attribute; the one gap stands as the window's history.
    use sha2::Digest as _;
    let dir = tempfile::tempdir().unwrap();
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/s1-dlmopen-double-load.c");
    let provider = dir.path().join("s1-dlmopen-provider.so");
    let driver = dir.path().join("s1-dlmopen-driver");
    for (output, extra) in [
        (
            &provider,
            &["-shared", "-fPIC", "-DS1_DLMOPEN_PROVIDER"][..],
        ),
        (&driver, &[][..]),
    ] {
        assert!(
            std::process::Command::new("gcc")
                .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
                .args(extra)
                .arg(&source)
                .arg("-o")
                .arg(output)
                .arg("-ldl")
                .status()
                .expect("compile the owned double-load fixture")
                .success()
        );
    }
    let mut spawned = std::process::Command::new(&driver)
        .arg(&provider)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start the owned double-loader");
    // Bounded READY read: the loader acks or the test fails loud.
    let stdout = spawned.stdout.take().unwrap();
    let (ack_tx, ack_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::BufRead as _;
        let mut lines = std::io::BufReader::new(stdout).lines();
        let _ = ack_tx.send(lines.next().map(|line| line.unwrap_or_default()));
    });
    let child = DoubleLoadChild { child: spawned };
    let ack = ack_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the double-loader acks within 10s")
        .expect("the double-loader's stdout stays open through READY");
    let ack: Vec<&str> = ack.split_whitespace().collect();
    assert_eq!(ack.len(), 4, "READY shape");
    assert_eq!(ack[0], "READY");
    assert_eq!(
        ack[1].parse::<u32>().unwrap(),
        child.child.id(),
        "the ack names the owned child"
    );
    assert_ne!(ack[2], "0x0", "the first namespace handle is loaded");
    assert_ne!(ack[3], "0x0", "the second namespace handle is loaded");
    assert_ne!(ack[2], ack[3], "two namespaces, two handles");
    // Scan evidence: the child's REAL maps through the REAL grouping
    // and the REAL detector.
    let maps_text = std::fs::read(format!("/proc/{}/maps", child.child.id()))
        .expect("read the owned child's maps while both loads live");
    let maps = p11scope_manifest::maps::parse_maps(&maps_text).unwrap();
    let groups = crate::discovery::scan::candidate_groups(&maps);
    let provider_name = b"s1-dlmopen-provider.so";
    let provider_key = maps
        .iter()
        .find(|entry| {
            entry
                .raw_path
                .as_ref()
                .is_some_and(|path| path.ends_with(provider_name))
        })
        .map(p11scope_manifest::maps::ObjectKey::of)
        .expect("the provider maps in the owned child");
    let provider_group = groups.get(&provider_key).unwrap();
    let exec_starts: Vec<u64> = provider_group
        .iter()
        .filter(|entry| entry.permissions[2] == b'x')
        .map(|entry| entry.start)
        .collect();
    assert!(
        exec_starts.len() >= 2,
        "two executable mappings of one file: {exec_starts:x?}"
    );
    let detected =
        crate::discovery::scan::duplicate_exec_coverage(provider_group);
    assert!(detected, "scan evidence shows the double-load");
    // Control: the driver's own executable loads once — no duplicate.
    let driver_bytes = driver.as_os_str().as_encoded_bytes();
    let driver_key = maps
        .iter()
        .find(|entry| entry.raw_path.as_deref() == Some(driver_bytes))
        .map(p11scope_manifest::maps::ObjectKey::of)
        .expect("the driver maps in the owned child");
    assert!(
        !crate::discovery::scan::duplicate_exec_coverage(
            groups.get(&driver_key).unwrap()
        ),
        "a single load shows no duplicate"
    );
    // The registry fact keys the REAL file: the maps identity the
    // scan saw, the SHA-256 of the provider bytes, its real path —
    // and the detector's own verdict staged as the note's evidence.
    let provider_bytes = std::fs::read(&provider).unwrap();
    let mut digest = sha2::Sha256::new();
    digest.update(&provider_bytes);
    let sha256: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let key = ModuleKey::physical(
        provider_key.device.major,
        provider_key.device.minor,
        provider_key.inode,
        Some(sha256),
        provider.to_str().unwrap(),
    );
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "s1-double-load",
        callers: 1,
        modules: 0,
        edges_per_caller: 0,
        endpoints_per_module: 1,
        first_pid: 9960,
    };
    harness.stage_scale(&spec);
    harness.commit();
    harness
        .coordinator_mut()
        .registry_mut()
        .set_usage_feed(true);
    let caller = caller_of(&harness, 9960);
    let now = harness.now_ns();
    harness.coordinator_mut().registry_mut().note_mapping(
        caller,
        child.child.id(),
        ModuleInfo {
            path: provider.to_str().unwrap().into(),
            key: key.clone(),
            double_loaded: detected,
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
    // Overlapping numeric handle 7 on both instances, different
    // mechanisms and categories — the shape that joined silently
    // before detection.
    harness.observe_semantic(caller, &key, init("C_SignInit", 7, RSA_PSS, 100));
    harness.observe_semantic(caller, &key, op("C_Sign", 7, 110));
    harness.observe_semantic(caller, &key, init("C_EncryptInit", 7, AES_GCM, 120));
    harness.observe_semantic(caller, &key, op("C_Encrypt", 7, 130));
    let document = render(&mut harness);
    // The merge stands (one key, one module, one edge) but fails
    // closed: no claims, the double-load label, exactly the named gap.
    assert_eq!(document["modules"].as_array().unwrap().len(), 1);
    let edges = document["edges"].as_array().unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0]["semantics"], "unknown (same-file double-load)");
    assert!(edges[0]["mechanisms"].is_null());
    assert!(edges[0]["operations"].is_null());
    let gaps = document["gaps"].as_array().unwrap();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0]["subject"], "same-file double-load detected");
    assert_eq!(gaps[0]["caller"], "c0");
    assert_eq!(gaps[0]["module"], "m0");
    assert_eq!(gaps[0]["pid"], child.child.id());
    assert_eq!(document["budgets"]["semantic_state"]["occupied"], 1);
    assert_eq!(document["budgets"]["semantic_state"]["unknown_edges"], 1);
    let presentation = presentation_for(&harness, &document);
    assert_four_way_semantic_agreement(&document, &presentation);
    // Resolution: a later single-load note unlatches and later calls
    // attribute; the one gap stands as the window's history.
    let now = harness.now_ns();
    harness.coordinator_mut().registry_mut().note_mapping(
        caller,
        child.child.id(),
        ModuleInfo {
            path: provider.to_str().unwrap().into(),
            key: key.clone(),
            double_loaded: false,
            build_id: None,
            identity_source: Some("workload".into()),
            admission: crate::discovery::caller_registry::AdmissionState::Admitted,
            admission_class: Some("exact".into()),
            admission_endpoints: Some(1),
            admission_reasons: Vec::new(),
        },
        now,
    );
    harness.observe_semantic(caller, &key, init("C_SignInit", 7, RSA_PSS, 200));
    harness.observe_semantic(caller, &key, op("C_Sign", 7, 210));
    let document = render(&mut harness);
    let edge = edge_json(&document, "c0", "m0");
    assert_eq!(edge["semantics"], "observed");
    assert_eq!(edge["operations"]["started"], 1);
    assert_eq!(edge["operations"]["completed"], 1);
    assert_eq!(document["gaps"].as_array().unwrap().len(), 1);
    assert_eq!(
        document["gaps"][0]["subject"],
        "same-file double-load detected"
    );
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
            double_loaded: false,
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

/// The F6 divergent fixture: 7 edges with deliberately different
/// counts, categories, recencies, returns, and gaps, plus 3 gaps
/// with distinct subjects. Staged and fed; the caller renders.
/// Shared by the four-way proof and the 80x14 display leg so both
/// validate the SAME fixture.
fn divergent_harness() -> Harness {
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "s1-divergent",
        callers: 1,
        modules: 7,
        edges_per_caller: 7,
        endpoints_per_module: 1,
        first_pid: 9800,
    };
    harness.stage_scale(&spec);
    harness.commit();
    harness
        .coordinator_mut()
        .registry_mut()
        .set_usage_feed(true);
    let caller = caller_of(&harness, 9800);
    let now = harness.now_ns();
    // m0: two mechanisms completed, one with a retry error.
    harness.observe_semantic(caller, &scale_key(0), init("C_SignInit", 7, RSA_PSS, 100));
    harness.observe_semantic(caller, &scale_key(0), op("C_Sign", 7, 110));
    harness.observe_semantic(
        caller,
        &scale_key(0),
        init("C_EncryptInit", 8, AES_GCM, 120),
    );
    let mut retry = op("C_EncryptUpdate", 8, 130);
    retry.rv = CkRv::BUFFER_TOO_SMALL.0;
    harness.observe_semantic(caller, &scale_key(0), retry);
    harness.observe_semantic(caller, &scale_key(0), op("C_EncryptUpdate", 8, 140));
    harness.observe_semantic(caller, &scale_key(0), op("C_EncryptFinal", 8, 150));
    harness
        .coordinator_mut()
        .registry_mut()
        .observe_entries(caller, &scale_key(0), 3, now);
    // m1: a live decrypt, ended unknown by the pass-wide loss below.
    harness.observe_semantic(caller, &scale_key(1), init("C_DecryptInit", 7, ECDSA, 200));
    harness.observe_semantic(caller, &scale_key(1), op("C_DecryptUpdate", 7, 210));
    // m2: a failed verify plus an unmatched close.
    harness.observe_semantic(caller, &scale_key(2), init("C_VerifyInit", 7, RSA_PSS, 300));
    harness.observe_semantic(
        caller,
        &scale_key(2),
        call("C_Verify", 7, CkRv::SIGNATURE_INVALID.0, 310),
    );
    harness.observe_semantic(
        caller,
        &scale_key(2),
        call("C_CloseSession", 7, CkRv::OK.0, 320),
    );
    // m3: an unauthoritative feed — materialized, unknown, no claims.
    let mut unauthorized = init("C_SignInit", 7, RSA_PSS, 400);
    unauthorized.authorized = false;
    harness.observe_semantic(caller, &scale_key(3), unauthorized);
    // m4: bare — never fed, withheld.
    // m5: an unknown-mechanism operation (F5): operations without rows.
    let mut unreadable = init("C_SignInit", 7, 0, 500);
    unreadable.capture = capture::MECHANISM_UNREADABLE | capture::OUTPUT_NON_NULL;
    harness.observe_semantic(caller, &scale_key(5), unreadable);
    harness.observe_semantic(caller, &scale_key(5), op("C_SignUpdate", 7, 510));
    harness.observe_semantic(caller, &scale_key(5), op("C_SignFinal", 7, 520));
    // m6: nine single-use mechanisms — past the dashboard's per-edge
    // cap, so the cap marker itself is pinned per edge.
    for index in 0..9 {
        let session = 20 + index as u64;
        let ts = 600 + index as u64 * 2;
        harness.observe_semantic(
            caller,
            &scale_key(6),
            init("C_SignInit", session, 0x2000 + index as u64, ts),
        );
        harness.observe_semantic(caller, &scale_key(6), op("C_Sign", session, ts + 1));
    }
    // Three gaps with distinct subjects: capture loss, a semantic
    // call without mapping evidence, entries without mapping evidence.
    harness.note_semantic_loss("divergent replay loss");
    harness.observe_semantic(caller, &scale_key(99), init("C_SignInit", 7, RSA_PSS, 700));
    harness
        .coordinator_mut()
        .registry_mut()
        .observe_entries(caller, &scale_key(99), 5, now);
    harness
}

#[test]
fn d3_divergent_edges_compare_per_edge_across_all_outputs() {
    // F6 focused regression: several edges with deliberately different
    // counts, categories, recencies, returns, and gaps — each
    // dashboard edge's facts must match its own JSON edge.
    let mut harness = divergent_harness();
    let document = render(&mut harness);
    let edge = |module: &str| edge_json(&document, "c0", module);
    assert_eq!(edge("m0")["operations"]["started"], 2);
    assert_eq!(edge("m0")["operations"]["completed"], 2);
    assert_eq!(edge("m0")["mechanisms"].as_array().unwrap().len(), 2);
    assert_eq!(edge("m0")["entries"]["count"], 3);
    assert_eq!(edge("m1")["operations"]["unknown"], 1);
    assert_eq!(edge("m1")["operations"]["active"], serde_json::json!([]));
    assert_eq!(edge("m2")["operations"]["failed"], 1);
    assert_eq!(edge("m2")["operations"]["evidence"]["unmatched_closes"], 1);
    assert_eq!(edge("m3")["semantics"], "unknown (unauthoritative module)");
    assert!(edge("m3")["operations"].is_null());
    assert_eq!(
        edge("m4")["semantics"],
        "unknown (semantic capture withheld)"
    );
    assert!(edge("m5")["mechanisms"].is_null());
    assert_eq!(edge("m5")["operations"]["completed"], 1);
    assert_eq!(edge("m6")["mechanisms"].as_array().unwrap().len(), 9);
    assert_eq!(edge("m6")["operations"]["completed"], 9);
    assert_eq!(document["gaps"].as_array().unwrap().len(), 3);
    let presentation = presentation_for(&harness, &document);
    assert_four_way_semantic_agreement(&document, &presentation);
}

#[test]
fn d3_divergent_fixture_displays_at_80x14_with_honest_budgets() {
    // F6 display leg: the SAME divergent fixture at the minimal full
    // viewport (80x14, 7-row edge window). Every edge is reachable via
    // scroll with its identity, states, counts, and operations; the
    // tight room shaves expandable detail (mechanism rows, evidence
    // counters, gap rows) with explicit markers instead of rejecting
    // whole blocks. Exact item matches pin the 80-column fit (a
    // truncated item could never match whole).
    let mut harness = divergent_harness();
    let document = render(&mut harness);
    let presentation = presentation_for(&harness, &document);
    let frame = crate::inventory_dashboard::DisplayFrame {
        presentation: std::sync::Arc::new(presentation.clone()),
        log: crate::inventory_dashboard::LogTail::bounded().snapshot(),
    };
    let edges = document["edges"].as_array().unwrap();
    assert_eq!(edges.len(), 7, "the divergent fixture has seven edges");
    let gaps = document["gaps"].as_array().unwrap();
    for (index, edge_json) in edges.iter().enumerate() {
        let caller = edge_json["caller"].as_str().unwrap();
        let module = edge_json["module"].as_str().unwrap();
        let mut state = DashboardState::new();
        for _ in 0..index {
            state.scroll_down(edges.len());
        }
        let bytes = render_frame(
            &frame,
            Viewport {
                width: 80,
                height: 14,
            },
            &state,
        );
        let text = String::from_utf8_lossy(bytes.as_ref()).into_owned();
        assert_eq!(text.lines().count(), 14, "scroll {index} fills 80x14");
        assert!(
            !text.contains("no edges fit"),
            "scroll {index} shows its edge: {text}"
        );
        let blocks = dashboard_edge_blocks(&text);
        assert_eq!(blocks.len(), 1, "scroll {index} shows one block: {text}");
        let block = blocks
            .get(&(caller.to_string(), module.to_string()))
            .unwrap_or_else(|| panic!("scroll {index} shows {caller}->{module}: {text}"));
        let view = presentation
            .edges
            .iter()
            .find(|edge| edge.caller.label() == caller && edge.module.label() == module)
            .unwrap();
        for (state, name) in [
            (view.presence.label(), "presence"),
            (view.capture.label(), "capture"),
            (view.activity.label(), "activity"),
        ] {
            assert!(
                block.contains(&format!("{name} {state}")),
                "scroll {index} {name}: {block}"
            );
        }
        assert!(
            block.contains(&format!(
                "mapping {}",
                edge_json["mapping"]["state"].as_str().unwrap()
            )),
            "scroll {index} mapping: {block}"
        );
        assert!(
            block.contains(&format!("entries {}", edge_json["entries"]["count"])),
            "scroll {index} entries: {block}"
        );
        let label = edge_json["semantics"].as_str().unwrap();
        assert!(
            block.contains(&format!("semantics {label}")),
            "scroll {index} label: {block}"
        );
        let items = dashboard_items(block);
        // Riding gaps hide behind an explicitly counted marker.
        let riding = gaps
            .iter()
            .filter(|gap| {
                (gap["caller"].is_null() || gap["caller"].as_str() == Some(caller))
                    && (gap["module"].is_null() || gap["module"].as_str() == Some(module))
            })
            .count();
        assert!(
            riding > 0,
            "the divergent fixture names every edge in a gap"
        );
        assert!(
            items
                .iter()
                .any(|item| item == &format!("gaps +{riding} hidden")),
            "scroll {index} gap marker: {block}"
        );
        assert!(
            !block.contains("gap ["),
            "scroll {index} shows no gap rows: {block}"
        );
        if edge_json["operations"].is_null() {
            assert!(
                !block.contains("mechs ")
                    && !block.contains("ops ")
                    && !block.contains("active ")
                    && !block.contains("ev ")
                    && !block.contains("evidence "),
                "scroll {index} bare label: {block}"
            );
        } else {
            // Mechanism rows shave to zero; the count and the hidden
            // rows stay explicit.
            let mechs = edge_json["mechanisms"]
                .as_array()
                .map(Vec::len)
                .unwrap_or(0);
            if mechs == 0 {
                assert!(
                    items.iter().any(|item| item == "mechs 0: none"),
                    "scroll {index} empty mechs: {block}"
                );
            } else {
                assert!(
                    items.iter().any(|item| item == &format!("mechs {mechs}")),
                    "scroll {index} mech count: {block}"
                );
                assert!(
                    items
                        .iter()
                        .any(|item| item == &format!("+{mechs} more mechs")),
                    "scroll {index} mech marker: {block}"
                );
            }
            assert!(
                !block.contains("mech ["),
                "scroll {index} shows no mech rows: {block}"
            );
            // Operations render whole; evidence hides counted.
            let ops = &edge_json["operations"];
            for expected in [
                format!(
                    "ops calls={} started={} completed={} cancelled={}",
                    ops["calls"], ops["started"], ops["completed"], ops["cancelled"],
                ),
                format!(
                    "ops failed={} unknown={} orphans={} dropped={} last={}",
                    ops["failed"],
                    ops["unknown"],
                    ops["orphans"],
                    ops["dropped"],
                    ops["last_seen_ns"],
                ),
            ] {
                assert!(
                    items.iter().any(|item| item == &expected),
                    "scroll {index} {expected}: {block}"
                );
            }
            assert!(
                items.iter().any(|item| item == "active none"),
                "scroll {index} idle active: {block}"
            );
            assert!(
                items.iter().any(|item| item == "evidence +9 hidden"),
                "scroll {index} evidence marker: {block}"
            );
            assert!(
                !block.contains("ev "),
                "scroll {index} shows no ev rows: {block}"
            );
        }
        // The header range names exactly the shown edge; markers point
        // both directions except at the ends.
        assert!(
            text.contains(&format!("--- edges {}-{} of 7", index + 1, index + 1)),
            "scroll {index} honest range: {text}"
        );
        assert!(
            text.contains(&format!("scroll {index}/6")),
            "scroll {index} honest footer: {text}"
        );
        assert_eq!(
            text.contains("more above"),
            index > 0,
            "scroll {index} above marker: {text}"
        );
        assert_eq!(
            text.contains("more below"),
            index + 1 < edges.len(),
            "scroll {index} below marker: {text}"
        );
    }
}

/// Parse the dashboard's per-edge blocks: identity lines start at
/// column 0 (`{caller} pid {pid} ({exe}) -> {module} ({path})`) while
/// item lines are indented, so each block's facts attribute to exactly
/// one edge (F6: no global substring can satisfy another edge).
fn dashboard_edge_blocks(dashboard: &str) -> BTreeMap<(String, String), String> {
    fn parse_identity(line: &str) -> Option<(String, String)> {
        let (left, right) = line.rsplit_once(" -> ")?;
        let mut left_tokens = left.split_whitespace();
        let caller = left_tokens.next()?;
        if left_tokens.next() != Some("pid") {
            return None;
        }
        let module = right.split_whitespace().next()?;
        if !caller.starts_with('c') || !module.starts_with('m') {
            return None;
        }
        Some((caller.to_string(), module.to_string()))
    }
    let mut blocks: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut current: Option<((String, String), Vec<&str>)> = None;
    let mut flush = |current: &mut Option<((String, String), Vec<&str>)>| {
        if let Some((key, lines)) = current.take() {
            blocks.insert(key, lines.join("\n"));
        }
    };
    for line in dashboard.lines() {
        if !line.starts_with(' ') && !line.is_empty() {
            match parse_identity(line) {
                Some(key) => {
                    flush(&mut current);
                    current = Some((key, vec![line]));
                }
                None => flush(&mut current),
            }
            continue;
        }
        if let Some((_, lines)) = current.as_mut() {
            lines.push(line);
        }
    }
    flush(&mut current);
    blocks
}

/// One dashboard gap row as the renderer formats it: the snapshot
/// gap line verbatim (subject, reason, budget clause), built here
/// from the JSON gap independently of the renderer.
fn dashboard_gap_line(gap: &serde_json::Value) -> String {
    let mut line = format!(
        "gap [{}] {}",
        gap["subject"].as_str().unwrap(),
        gap["reason"].as_str().unwrap()
    );
    if !gap["budget"].is_null() {
        line.push_str(&format!(
            " (budget {}: limit {}, requested {})",
            gap["budget"]["resource"].as_str().unwrap(),
            gap["budget"]["limit"],
            gap["budget"]["requested"],
        ));
    }
    line
}

/// Split a dashboard edge block into its exact pieces: the identity
/// line, then every wrapped item. Item lines rejoin with `|` because
/// the renderer wraps BETWEEN items without repeating the separator;
/// the wrap never splits mid-item, so every piece is whole. Counter
/// assertions match whole pieces, so `ev reconc=0` can never match a
/// `reconc=10`. (Item text in these fixtures carries no `|`; gap rows
/// assert via `contains`, not via this splitter.)
fn dashboard_items(block: &str) -> Vec<String> {
    // Blocks carry the frame's own `\x1b[K` line ends; strip those
    // (and only those) before splitting into exact items.
    let clean = block.replace("\x1b[K", "");
    let mut lines = clean.lines();
    let mut pieces = Vec::new();
    if let Some(identity) = lines.next() {
        pieces.push(identity.trim().to_string());
    }
    let rest: String = lines.collect::<Vec<_>>().join("|");
    pieces.extend(
        rest.split('|')
            .map(|piece| piece.trim().to_string())
            .filter(|piece| !piece.is_empty()),
    );
    pieces
}

/// JSON vs snapshot vs dashboard vs stream on one capture (F6/C1/D3):
/// every edge's identities, states, and semantic facts in all four —
/// each dashboard edge's facts against its corresponding JSON edge —
/// plus the replay's totals, budgets, and gaps across all outputs.
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
    let blocks = dashboard_edge_blocks(&dashboard);
    assert_eq!(
        blocks.len(),
        document["edges"].as_array().unwrap().len(),
        "one dashboard block per JSON edge"
    );
    for edge_json in document["edges"].as_array().unwrap() {
        let caller = edge_json["caller"].as_str().unwrap();
        let module = edge_json["module"].as_str().unwrap();
        let label = edge_json["semantics"].as_str().unwrap();
        let view = presentation
            .edges
            .iter()
            .find(|edge| edge.caller.label() == caller && edge.module.label() == module)
            .unwrap_or_else(|| panic!("missing presentation edge for {caller}->{module}"));
        let snapshot_line = snapshot
            .lines()
            .find(|line| line.starts_with(&format!("edge {caller} -> {module} ")))
            .unwrap_or_else(|| panic!("missing snapshot line for {caller}->{module}"));
        let block = blocks
            .get(&(caller.to_string(), module.to_string()))
            .unwrap_or_else(|| panic!("missing dashboard block for {caller}->{module}"));
        // Identities and states in all four.
        assert!(
            snapshot_line.contains(&format!(
                "mapping {}",
                edge_json["mapping"]["state"].as_str().unwrap()
            )),
            "snapshot mapping for {caller}->{module}: {snapshot_line}"
        );
        assert!(
            snapshot_line.contains(&format!("entries {}", edge_json["entries"]["count"])),
            "snapshot entries for {caller}->{module}: {snapshot_line}"
        );
        assert!(
            snapshot_line.contains(edge_json["entries"]["observation"].as_str().unwrap()),
            "snapshot entry observation for {caller}->{module}: {snapshot_line}"
        );
        for (state, name) in [
            (view.presence.label(), "presence"),
            (view.capture.label(), "capture"),
            (view.activity.label(), "activity"),
        ] {
            assert!(
                snapshot_line.contains(&format!("{name} {state}")),
                "snapshot {name} for {caller}->{module}: {snapshot_line}"
            );
            assert!(
                block.contains(&format!("{name} {state}")),
                "dashboard {name} for {caller}->{module}: {block}"
            );
        }
        assert!(
            block.contains(&format!(
                "mapping {}",
                edge_json["mapping"]["state"].as_str().unwrap()
            )),
            "dashboard mapping for {caller}->{module}: {block}"
        );
        assert!(
            block.contains(&format!("entries {}", edge_json["entries"]["count"])),
            "dashboard entries for {caller}->{module}: {block}"
        );
        assert!(
            snapshot_line.contains(label),
            "snapshot label for {caller}->{module}: {snapshot_line}"
        );
        assert!(
            block.contains(&format!("semantics {label}")),
            "dashboard label for {caller}->{module}: {block}"
        );
        let streamed = events
            .iter()
            .find(|event| {
                event["kind"] == "edge_observed"
                    && event["event"]["caller"] == caller
                    && event["event"]["module"] == module
            })
            .unwrap_or_else(|| panic!("missing stream event for {caller}->{module}"));
        for key in [
            "caller",
            "module",
            "mapping",
            "entries",
            "semantics",
            "mechanisms",
            "operations",
        ] {
            assert_eq!(
                streamed["event"][key], edge_json[key],
                "stream {key} for {caller}->{module}"
            );
        }
        assert_eq!(streamed["event"]["presence"], view.presence.label());
        assert_eq!(streamed["event"]["capture"], view.capture.label());
        assert_eq!(streamed["event"]["activity"], view.activity.label());
        // Riding gaps (every edge, including unknown ones): the
        // dashboard block shows each gap that names this edge — global
        // gaps ride all blocks, caller gaps their caller's blocks,
        // module-qualified gaps exactly their edge — as the snapshot
        // gap line verbatim. Coverage holes are edge-relevant
        // regardless of semantic state.
        let riding: Vec<&serde_json::Value> = document["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|gap| {
                (gap["caller"].is_null() || gap["caller"].as_str() == Some(caller))
                    && (gap["module"].is_null() || gap["module"].as_str() == Some(module))
            })
            .collect();
        for gap in &riding {
            assert!(
                block.contains(&dashboard_gap_line(gap)),
                "dashboard gap [{}] for {caller}->{module}: {block}",
                gap["subject"].as_str().unwrap(),
            );
        }
        assert_eq!(
            block.matches("gap [").count(),
            riding.len(),
            "dashboard gap rows for {caller}->{module}: {block}"
        );
        // Proof viewports are roomy: nothing hides behind a marker.
        assert!(
            !block.contains("hidden"),
            "dashboard full detail for {caller}->{module}: {block}"
        );
        if edge_json["operations"].is_null() {
            // Unknown edge: the bare semantic label everywhere, no
            // semantic detail rows (gaps above are coverage rows, not
            // semantic detail).
            assert!(
                snapshot_line.ends_with(&format!("semantics {label}")),
                "snapshot bare label for {caller}->{module}: {snapshot_line}"
            );
            assert!(
                !block.contains("mechs ")
                    && !block.contains("mech [")
                    && !block.contains("ops ")
                    && !block.contains("active ")
                    && !block.contains("ev ")
                    && !block.contains("hidden"),
                "dashboard bare label for {caller}->{module}: {block}"
            );
            continue;
        }
        // Observed edge: every mechanism row's exact facts — id, name,
        // categories, counts, recency, provenance — in the snapshot
        // segment and the dashboard's own block. (`mechanisms` is null
        // — never `[]` — when operations exist without attributed
        // mechanisms, e.g. unknown-mechanism Inits.)
        let empty;
        let mechs: &[serde_json::Value] = if edge_json["mechanisms"].is_null() {
            empty = Vec::new();
            &empty
        } else {
            edge_json["mechanisms"].as_array().unwrap()
        };
        if mechs.is_empty() {
            assert!(
                snapshot_line.contains("mechs  ops ["),
                "snapshot empty mechs for {caller}->{module}: {snapshot_line}"
            );
            assert!(
                block.contains("mechs 0: none"),
                "dashboard empty mechs for {caller}->{module}: {block}"
            );
        } else {
            assert!(
                block.contains(&format!("mechs {}", mechs.len())),
                "dashboard mech count for {caller}->{module}: {block}"
            );
        }
        for (index, mech) in mechs.iter().enumerate() {
            let id = match mech["name"].as_str() {
                Some(name) => format!("{name}/{}", mech["mechanism_hex"].as_str().unwrap()),
                None => mech["mechanism_hex"].as_str().unwrap().to_string(),
            };
            let categories = mech["operations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|category| category.as_str().unwrap())
                .collect::<Vec<_>>()
                .join(",");
            let by = mech["evidence"]["functions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|function| function.as_str().unwrap())
                .collect::<Vec<_>>()
                .join(",");
            let rv = mech["evidence"]["returns"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| format!("0x{:x}", row["rv"].as_u64().unwrap()))
                .collect::<Vec<_>>()
                .join(",");
            let segment = format!(
                "[{id} {categories} calls={} errors={} last={} by=[{by}] rv=[{rv}]{}]",
                mech["calls"],
                mech["errors"],
                mech["last_seen_ns"],
                if mech["evidence"]["truncated"].as_bool().unwrap() {
                    " truncated"
                } else {
                    ""
                },
            );
            assert!(
                snapshot_line.contains(&segment),
                "snapshot mech {id} for {caller}->{module}: {snapshot_line}"
            );
            // The dashboard shows the first 8 mechs per edge, then an
            // explicit marker — both pinned against this edge's block.
            if index < crate::inventory_dashboard::DASHBOARD_MAX_MECHS {
                assert!(
                    block.contains(&format!("mech {segment}")),
                    "dashboard mech {id} for {caller}->{module}: {block}"
                );
            }
        }
        if mechs.len() > crate::inventory_dashboard::DASHBOARD_MAX_MECHS {
            assert!(
                block.contains(&format!(
                    "+{} more mechs",
                    mechs.len() - crate::inventory_dashboard::DASHBOARD_MAX_MECHS
                )),
                "dashboard mech cap marker for {caller}->{module}: {block}"
            );
        }
        // Operation aggregates: every counter plus recency, active
        // machines, and the nine evidence counters — in the snapshot
        // segment and the dashboard's own block.
        let ops = &edge_json["operations"];
        assert!(
            snapshot_line.contains(&format!(
                "ops [calls={} started={} completed={} cancelled={} failed={} unknown={} orphans={} dropped={} last={}]",
                ops["calls"],
                ops["started"],
                ops["completed"],
                ops["cancelled"],
                ops["failed"],
                ops["unknown"],
                ops["orphans"],
                ops["dropped"],
                ops["last_seen_ns"],
            )),
            "snapshot ops for {caller}->{module}: {snapshot_line}"
        );
        // Operation aggregates: two whole items with correct labels
        // (each label names its own counter), matched exactly.
        let items = dashboard_items(block);
        for expected in [
            format!(
                "ops calls={} started={} completed={} cancelled={}",
                ops["calls"], ops["started"], ops["completed"], ops["cancelled"],
            ),
            format!(
                "ops failed={} unknown={} orphans={} dropped={} last={}",
                ops["failed"], ops["unknown"], ops["orphans"], ops["dropped"], ops["last_seen_ns"],
            ),
        ] {
            assert!(
                items.iter().any(|item| item == &expected),
                "dashboard {expected} for {caller}->{module}: {block}"
            );
        }
        let active = ops["active"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                format!(
                    "{}:{}x{}",
                    row["category"].as_str().unwrap(),
                    row["state"].as_str().unwrap(),
                    row["count"].as_u64().unwrap(),
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            snapshot_line.contains(&format!("active [{active}]")),
            "snapshot active for {caller}->{module}: {snapshot_line}"
        );
        if active.is_empty() {
            assert!(
                block.contains("active none"),
                "dashboard idle active for {caller}->{module}: {block}"
            );
        } else {
            assert!(
                block.contains(&format!("active {active}")),
                "dashboard active for {caller}->{module}: {block}"
            );
        }
        let evidence = &ops["evidence"];
        assert!(
            snapshot_line.contains(&format!(
                "evidence [state_reconciliations={} session_cancel_ambiguities={} session_cancel_unknown_flags={} operation_state_imports={} auth_state_ambiguities={} semantic_capture_failures={} async_duplicates={} async_evictions={} unmatched_closes={}]",
                evidence["state_reconciliations"],
                evidence["session_cancel_ambiguities"],
                evidence["session_cancel_unknown_flags"],
                evidence["operation_state_imports"],
                evidence["auth_state_ambiguities"],
                evidence["semantic_capture_failures"],
                evidence["async_duplicates"],
                evidence["async_evictions"],
                evidence["unmatched_closes"],
            )),
            "snapshot evidence for {caller}->{module}: {snapshot_line}"
        );
        // Dashboard evidence: the same nine counters as compact `ev`
        // items (full JSON key → short dashboard key), matched whole.
        for (full, short) in [
            ("state_reconciliations", "reconc"),
            ("session_cancel_ambiguities", "cancel_amb"),
            ("session_cancel_unknown_flags", "cancel_flags"),
            ("operation_state_imports", "op_imports"),
            ("auth_state_ambiguities", "auth_amb"),
            ("semantic_capture_failures", "cap_fail"),
            ("async_duplicates", "async_dup"),
            ("async_evictions", "async_evict"),
            ("unmatched_closes", "unmatch_close"),
        ] {
            let expected = format!("ev {short}={}", evidence[full]);
            assert!(
                items.iter().any(|item| item == &expected),
                "dashboard {expected} for {caller}->{module}: {block}"
            );
        }
    }
    // Totals, budgets, and gaps across all outputs.
    let scope = document["scope"].as_str().unwrap();
    let passes = document["observation"]["passes"].as_u64().unwrap();
    let callers = document["callers"].as_array().unwrap().len();
    let modules = document["modules"].as_array().unwrap().len();
    let edges = document["edges"].as_array().unwrap().len();
    let plural = |count: usize, single: &str, plural: &str| {
        if count == 1 {
            format!("1 {single}")
        } else {
            format!("{count} {plural}")
        }
    };
    assert!(
        snapshot.contains(&format!(
            "inventory {} ({} pass{}, {}, {}, {})",
            scope,
            passes,
            if passes == 1 { "" } else { "es" },
            plural(callers, "caller", "callers"),
            plural(modules, "module", "modules"),
            plural(edges, "edge", "edges"),
        )),
        "snapshot totals"
    );
    let budgets = &document["budgets"];
    let row = |resource: &str| {
        format!(
            "{}/{} refused {}",
            budgets[resource]["occupied"], budgets[resource]["limit"], budgets[resource]["refused"],
        )
    };
    assert!(
        snapshot.contains(&format!(
            "budgets: callers {} | modules {} | edges {} | endpoints {} | counters observed {} saturated {} | semantic_state {} held {}/{} unknown {} refused {} | retained_history {}/{} suppressed {}",
            row("callers"),
            row("modules"),
            row("edges"),
            row("endpoints"),
            budgets["counters"]["observed_edges"],
            budgets["counters"]["saturated_edges"],
            budgets["semantic_state"]["status"].as_str().unwrap(),
            budgets["semantic_state"]["occupied"],
            budgets["semantic_state"]["limit"],
            budgets["semantic_state"]["unknown_edges"],
            budgets["semantic_state"]["refused"],
            budgets["retained_history"]["retained"],
            budgets["retained_history"]["limit"],
            budgets["retained_history"]["suppressed"],
        )),
        "snapshot budgets"
    );
    assert!(
        dashboard.contains(&format!(
            "p11scope inventory {scope} | {passes} passes | {callers} callers {modules} modules {edges} edges"
        )),
        "dashboard totals"
    );
    let refusals = ["callers", "modules", "edges", "endpoints"]
        .iter()
        .map(|resource| budgets[resource]["refused"].as_u64().unwrap())
        .sum::<u64>();
    let gaps = document["gaps"].as_array().unwrap();
    let suppressed = document["gaps_suppressed"].as_u64().unwrap();
    assert!(
        dashboard.contains(&format!(
            "coverage: {} gaps {} refusals {} suppressed | endpoints {}/{} | semantic {} ({} held, {} unknown, {} refused)",
            gaps.len(),
            refusals,
            suppressed,
            budgets["endpoints"]["occupied"],
            budgets["endpoints"]["limit"],
            budgets["semantic_state"]["status"].as_str().unwrap(),
            budgets["semantic_state"]["occupied"],
            budgets["semantic_state"]["unknown_edges"],
            budgets["semantic_state"]["refused"],
        )),
        "dashboard coverage"
    );
    assert!(
        dashboard.contains(&format!(
            "budgets: callers {} | modules {} | edges {} | counters observed {} saturated {} | retained {}/{} suppressed {}",
            row("callers"),
            row("modules"),
            row("edges"),
            budgets["counters"]["observed_edges"],
            budgets["counters"]["saturated_edges"],
            budgets["retained_history"]["retained"],
            budgets["retained_history"]["limit"],
            budgets["retained_history"]["suppressed"],
        )),
        "dashboard budgets"
    );
    for gap in gaps {
        let mut expected = format!(
            "gap [{}] {}",
            gap["subject"].as_str().unwrap(),
            gap["reason"].as_str().unwrap()
        );
        if !gap["budget"].is_null() {
            expected.push_str(&format!(
                " (budget {}: limit {}, requested {})",
                gap["budget"]["resource"].as_str().unwrap(),
                gap["budget"]["limit"],
                gap["budget"]["requested"],
            ));
        }
        assert!(snapshot.contains(&expected), "snapshot gap: {expected}");
    }
    if suppressed > 0 {
        assert!(
            snapshot.contains(&format!("gaps suppressed: {suppressed}")),
            "snapshot suppressed gaps"
        );
    } else {
        assert!(
            !snapshot.contains("gaps suppressed:"),
            "snapshot hides a zero suppression count"
        );
    }
    let gap_events: Vec<&serde_json::Value> = events
        .iter()
        .filter(|event| event["kind"] == "gap_recorded")
        .collect();
    assert_eq!(gap_events.len(), gaps.len(), "one stream gap per JSON gap");
    for (event, gap) in gap_events.iter().zip(gaps.iter()) {
        assert_eq!(event["event"], *gap, "stream gap payload");
    }
    let streamed_snapshot = events
        .iter()
        .find(|event| event["kind"] == "snapshot")
        .expect("stream snapshot summary");
    assert_eq!(streamed_snapshot["event"]["scope"], scope);
    assert_eq!(streamed_snapshot["event"]["passes"], passes);
    assert_eq!(streamed_snapshot["event"]["budgets"], *budgets);
    assert_eq!(streamed_snapshot["event"]["gaps_suppressed"], suppressed);
    let caller_events: Vec<&serde_json::Value> = events
        .iter()
        .filter(|event| event["kind"] == "caller_observed")
        .collect();
    let module_events: Vec<&serde_json::Value> = events
        .iter()
        .filter(|event| event["kind"] == "module_observed")
        .collect();
    assert_eq!(
        caller_events.len(),
        callers,
        "one stream caller per JSON caller"
    );
    assert_eq!(
        module_events.len(),
        modules,
        "one stream module per JSON module"
    );
    for (event, row) in caller_events
        .iter()
        .zip(document["callers"].as_array().unwrap().iter())
    {
        assert_eq!(event["event"], *row, "stream caller payload");
    }
    for (event, row) in module_events
        .iter()
        .zip(document["modules"].as_array().unwrap().iter())
    {
        assert_eq!(event["event"], *row, "stream module payload");
    }
    for row in document["callers"].as_array().unwrap() {
        assert!(
            snapshot.contains(&format!(
                "caller {} pid {}",
                row["id"].as_str().unwrap(),
                row["pid"].as_u64().unwrap()
            )),
            "snapshot caller row"
        );
    }
    for row in document["modules"].as_array().unwrap() {
        assert!(
            snapshot.contains(&format!(
                "module {} {}",
                row["id"].as_str().unwrap(),
                row["paths"].as_array().unwrap()[0].as_str().unwrap()
            )),
            "snapshot module row"
        );
    }
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
        let mut fed = 0u64;
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
                fed += feed_semantic_script(&mut harness, caller, &key, index);
            }
        }
        let started = std::time::Instant::now();
        harness.commit();
        let document = harness.render();
        (document, started.elapsed(), fed)
    };
    let (base, base_elapsed, _) = run(false);
    let (sem, sem_elapsed, fed) = run(true);
    // The scripted denominator, pinned against the script (F8): 64
    // edges × the 4-class script (2 + 2 + 1 + 1 calls) = 96 fed.
    assert_eq!(spec.layout().len(), 64);
    assert_eq!(fed, 96);
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
        "S1 overhead over {} edges ({} semantic calls fed): baseline {base_elapsed:?}, semantic {sem_elapsed:?}",
        spec.layout().len(),
        fed,
    );
}

/// Deterministic per-edge semantic script (D5): completed signs,
/// in-flight encrypts, failed Inits, and unauthorized feeds. Returns
/// the number of calls fed (2 + 2 + 1 + 1 per 4 edges).
fn feed_semantic_script(
    harness: &mut Harness,
    caller: CallerId,
    key: &ModuleKey,
    index: usize,
) -> u64 {
    let ts = 1000 + index as u64;
    match index % 4 {
        0 => {
            harness.observe_semantic(caller, key, init("C_SignInit", 7, RSA_PSS, ts));
            harness.observe_semantic(caller, key, op("C_Sign", 7, ts + 1));
            2
        }
        1 => {
            harness.observe_semantic(caller, key, init("C_EncryptInit", 7, AES_GCM, ts));
            harness.observe_semantic(caller, key, op("C_EncryptUpdate", 7, ts + 1));
            2
        }
        2 => {
            let failed = SemanticCall {
                rv: CkRv::OPERATION_ACTIVE.0,
                ..init("C_SignInit", 7, RSA_PSS, ts)
            };
            harness.observe_semantic(caller, key, failed);
            1
        }
        _ => {
            let mut unauthorized = init("C_SignInit", 7, RSA_PSS, ts);
            unauthorized.authorized = false;
            harness.observe_semantic(caller, key, unauthorized);
            1
        }
    }
}
