//! SPDX-License-Identifier: GPL-3.0-or-later
//! Reader contract tests use complete producer-shaped inputs and real files.

use super::input::*;
use serde_json::{Value, json};
use std::{fs, os::unix::fs::MetadataExt};

const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/inventory-diff/scan-current.json");

fn fixture() -> Value {
    serde_json::from_slice(FIXTURE).unwrap()
}
fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn rejected(value: &Value, field: &str) {
    let error = parse_snapshot(&bytes(value)).unwrap_err().to_string();
    assert!(error.contains(field), "expected {field:?}, got {error:?}");
}

#[test]
fn current_fixture_resolves_nonempty_evidence() {
    let snapshot = parse_snapshot(FIXTURE).unwrap();
    assert_eq!(snapshot.scope, "pid:4242");
    assert_eq!(
        (
            snapshot.callers.len(),
            snapshot.modules.len(),
            snapshot.edges.len(),
            snapshot.gaps.len()
        ),
        (1, 1, 1, 1)
    );
    assert_eq!((snapshot.edges[0].caller, snapshot.edges[0].module), (0, 0));
    assert_eq!(snapshot.callers[0].start_time, Some(1000));
    assert_eq!(
        snapshot.modules[0].sha256.as_deref(),
        Some("d392738570eaab6fcc9aa561001275faf4c774e2bba7f47745b15a388f17f0a2")
    );
}

#[test]
fn actual_current_producer_is_accepted() {
    use crate::discovery::{
        caller_registry::RegistryLimits,
        inventory_workload::{Harness, ScaleSpec},
    };
    let mut harness = Harness::new(RegistryLimits::default_limits()).unwrap();
    harness.stage_scale(&ScaleSpec {
        name: "reader",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 4242,
    });
    harness.commit();
    let mut document = harness.render();
    document["modules"][0]["identity"]["sha256"] =
        fixture()["modules"][0]["identity"]["sha256"].clone();
    let snapshot = parse_snapshot(&bytes(&document)).unwrap();
    assert_eq!(
        (
            snapshot.callers.len(),
            snapshot.modules.len(),
            snapshot.edges.len()
        ),
        (1, 1, 1)
    );
}

fn semantic_document() -> Value {
    let mut v = fixture();
    v["edges"][0]["semantics"] = json!("observed");
    v["edges"][0]["mechanisms"] = json!([{"mechanism":2147483664u64,"mechanism_hex":"0x80000010","name":null,"operations":["sign"],"calls":3,"errors":1,"last_seen_ns":190,"evidence":{"functions":["C_SignInit","C_Sign"],"returns":[{"rv":2147483651u64,"rv_hex":"0x80000003","name":null}],"truncated":false}}]);
    v["edges"][0]["operations"] = json!({"calls":3,"started":1,"completed":0,"cancelled":0,"failed":1,"unknown":0,"orphans":0,"dropped":0,"last_seen_ns":190,"active":[{"category":"sign","state":"in_progress","count":1}],"evidence":{"state_reconciliations":0,"session_cancel_ambiguities":0,"session_cancel_unknown_flags":0,"operation_state_imports":0,"auth_state_ambiguities":0,"semantic_capture_failures":0,"async_duplicates":0,"async_evictions":0,"unmatched_closes":0}});
    v
}

#[test]
fn present_semantic_details_retain_availability_and_validate_fields() {
    let v = semantic_document();
    let snapshot = parse_snapshot(&bytes(&v)).unwrap();
    assert_eq!(snapshot.edges[0].semantics.raw, "observed");
    assert!(snapshot.edges[0].mechanisms.is_some());
    assert!(snapshot.edges[0].operations.is_some());
    for path in [
        "/edges/0/mechanisms/0/mechanism",
        "/edges/0/mechanisms/0/errors",
        "/edges/0/mechanisms/0/evidence/returns/0/rv",
        "/edges/0/operations/completed",
        "/edges/0/operations/active/0/count",
        "/edges/0/operations/evidence/unmatched_closes",
    ] {
        let mut bad = v.clone();
        *bad.pointer_mut(path).unwrap() = json!("bad");
        rejected(&bad, path.rsplit('/').next().unwrap());
    }
    let mut unknown = v;
    unknown["edges"][0]["operations"]["active"][0]["state"] = json!("future_state");
    assert!(
        !parse_snapshot(&bytes(&unknown)).unwrap().edges[0]
            .operations
            .as_ref()
            .unwrap()
            .active[0]
            .state
            .known
    );
}

#[test]
fn unknown_additive_payloads_are_bounded_and_discarded() {
    let mut v = fixture();
    v["extra_secret"] = json!({"payload":"must not leave reader"});
    v["callers"][0]["extra_secret"] = json!(["must not leave reader"]);
    let snapshot = parse_snapshot(&bytes(&v)).unwrap();
    let retained = serde_json::to_string(&snapshot).unwrap();
    assert!(!retained.contains("extra_secret"));
    assert!(!retained.contains("must not leave reader"));
}

#[test]
fn legacy_additions_are_optional() {
    for path in [
        "/pid_namespace",
        "/observation/native_witnesses",
        "/modules/0/admission/history",
        "/edges/0/mapping/evidence",
        "/edges/0/entries/coverage",
        "/gaps/0/repeats",
        "/budgets/inventory_endpoints",
        "/budgets/inventory_attach_modules",
        "/budgets/native_preadmission",
        "/edges/0/mechanisms",
        "/edges/0/operations",
        "/budgets/inventory_endpoints/refused",
    ] {
        let mut v = fixture();
        let (parent, key) = path.rsplit_once('/').unwrap();
        v.pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(key);
        let snapshot = parse_snapshot(&bytes(&v)).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!((snapshot.edges[0].caller, snapshot.edges[0].module), (0, 0));
        assert_eq!(snapshot.gaps[0].repeats, 1);
        if path.ends_with("coverage") {
            assert!(snapshot.edges[0].coverage.is_none());
        }
    }
}

#[test]
fn unknown_labels_stay_unknown() {
    let mut v = fixture();
    v["modules"][0]["admission"]["state"] = json!("future_admission");
    v["edges"][0]["entries"]["coverage"]["state"] = json!("future_coverage");
    let snapshot = parse_snapshot(&bytes(&v)).unwrap();
    assert_eq!(snapshot.modules[0].admission.state.raw, "future_admission");
    assert!(!snapshot.modules[0].admission.state.known);
    let coverage = snapshot.edges[0].coverage.as_ref().unwrap();
    assert_eq!(coverage.state.raw, "future_coverage");
    assert!(!coverage.state.known);
}

#[test]
fn unknown_clock_and_start_time_units_are_not_reinterpreted() {
    let mut v = fixture();
    v["clock"]["basis"] = json!("future_clock");
    v["clock"]["unit"] = json!("future_unit");
    v["callers"][0]["start_time_unit"] = json!("future_start_unit");
    let snapshot = parse_snapshot(&bytes(&v)).unwrap();
    assert_eq!(snapshot.callers[0].start_time, Some(1000));
    assert!(
        snapshot
            .limitations
            .contains(&"unknown_clock_basis".to_owned())
    );
    assert!(
        snapshot
            .limitations
            .contains(&"unknown_clock_unit".to_owned())
    );
    assert!(
        snapshot
            .limitations
            .contains(&"unknown_start_time_unit".to_owned())
    );
}

#[test]
fn native_additions_are_validated_when_present() {
    let mut v = fixture();
    v["observation"]["lane"] = json!("native");
    v["observation"]["settlement"] = json!("unsettled");
    v["observation"]["retirement"] = json!("closed");
    v["observation"]["attach"] =
        json!({"selection":"auto","mechanism":"uprobe-multi","fallback":null,"scope_filter":null});
    v["observation"]["lifecycle"] =
        json!({"records":2,"ring_loss":1,"malformed":0,"failed_quanta":0,"recovery_rescans":1});
    v["modules"][0]["unbound_use"] =
        json!({"first_ns":123,"rows":1,"reasons":{"no_live_caller":1}});
    v["budgets"]["native_preadmission"] = json!({"limit":4096,"occupied":1,"refused":0,"pruned":0});
    assert!(parse_snapshot(&bytes(&v)).is_ok());
    for path in [
        "/observation/lane",
        "/observation/settlement",
        "/observation/retirement",
        "/observation/attach",
        "/observation/lifecycle",
        "/modules/0/unbound_use",
    ] {
        let mut absent = v.clone();
        let (parent, key) = path.rsplit_once('/').unwrap();
        absent
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert!(parse_snapshot(&bytes(&absent)).is_ok(), "{path}");
        let mut wrong = v.clone();
        *wrong.pointer_mut(path).unwrap() = json!(false);
        rejected(&wrong, path.rsplit('/').next().unwrap());
    }
    for path in [
        "/observation/lifecycle/ring_loss",
        "/observation/native_witnesses/rows",
        "/modules/0/unbound_use/rows",
        "/budgets/native_preadmission/pruned",
    ] {
        let mut wrong = v.clone();
        *wrong.pointer_mut(path).unwrap() = json!("bad");
        rejected(&wrong, path.rsplit('/').next().unwrap());
    }
}

#[test]
fn invalid_references_fail() {
    for (row, field) in [
        ("callers", "caller id"),
        ("modules", "module id"),
        ("edges", "edge pair"),
    ] {
        let mut v = fixture();
        let duplicate = v[row][0].clone();
        v[row].as_array_mut().unwrap().push(duplicate);
        rejected(&v, field);
    }
    for (row, key) in [
        ("edges", "caller"),
        ("edges", "module"),
        ("gaps", "caller"),
        ("gaps", "module"),
    ] {
        let mut v = fixture();
        v[row][0][key] = json!("absent");
        rejected(&v, key);
    }
}

#[test]
fn original_fields_are_required_and_wrong_types_are_rejected() {
    for path in [
        "/scope",
        "/clock",
        "/observation",
        "/budgets",
        "/callers",
        "/modules",
        "/edges",
        "/gaps",
        "/gaps_suppressed",
        "/callers/0/start_time",
        "/callers/0/image/exe",
        "/modules/0/identity/sha256",
        "/edges/0/semantics",
        "/edges/0/mapping/reason",
        "/gaps/0/budget",
    ] {
        let mut v = fixture();
        let (parent, key) = path.rsplit_once('/').unwrap();
        v.pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(key);
        rejected(&v, key);
    }
    for path in [
        "/pid_namespace",
        "/observation/native_witnesses",
        "/modules/0/admission/history",
        "/edges/0/mapping/evidence",
        "/edges/0/entries/coverage",
        "/gaps/0/repeats",
        "/budgets/inventory_endpoints",
        "/budgets/inventory_attach_modules",
        "/budgets/native_preadmission",
        "/edges/0/mechanisms",
        "/edges/0/operations",
        "/budgets/inventory_endpoints/refused",
    ] {
        let mut v = fixture();
        *v.pointer_mut(path).unwrap() = json!(false);
        rejected(&v, path.rsplit('/').next().unwrap());
    }
}

#[test]
fn digest_normalization_and_nullable_identities() {
    let mut v = fixture();
    v["modules"][0]["identity"]["sha256"] = json!("AB".repeat(32));
    v["callers"][0]["start_time"] = Value::Null;
    let snapshot = parse_snapshot(&bytes(&v)).unwrap();
    assert_eq!(
        snapshot.modules[0].sha256.as_deref(),
        Some("abababababababababababababababababababababababababababababababab")
    );
    assert_eq!(snapshot.callers[0].start_time, None);
    for digest in [
        "abc…",
        "g000000000000000000000000000000000000000000000000000000000000000",
        "a",
    ] {
        v["modules"][0]["identity"]["sha256"] = json!(digest);
        rejected(&v, "sha256");
    }
}

#[test]
fn numeric_types_and_overflow_are_errors() {
    for bad in [json!(-1), json!(1.5), json!("1"), json!(true)] {
        let mut v = fixture();
        v["edges"][0]["entries"]["count"] = bad;
        rejected(&v, "count");
    }
    let raw = String::from_utf8(bytes(&fixture())).unwrap().replacen(
        "\"count\":0",
        "\"count\":18446744073709551616",
        1,
    );
    assert!(
        parse_snapshot(raw.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("count")
    );
    let mut v = fixture();
    v["callers"][0]["pid"] = json!(4294967296u64);
    rejected(&v, "pid");
    v = fixture();
    v["gaps"][0]["repeats"] = json!(0);
    rejected(&v, "repeats");
}

#[test]
fn dispatch_and_json_syntax_are_strict() {
    rejected(&json!([]), "root");
    let mut v = fixture();
    v["schema"] = json!("p11scope/profile/v3");
    rejected(&v, "schema");
    for raw in [
        b"{} {}".as_slice(),
        b"{\"schema\":1,\"schema\":2}",
        b"{\"unknown\":{\"x\":1,\"x\":2}}",
    ] {
        assert!(parse_snapshot(raw).is_err());
    }
    assert!(parse_snapshot(b"\xff").is_err());
    let raw = String::from_utf8(bytes(&fixture())).unwrap();
    let duplicate = raw.replacen("\"scope\":", "\"scope\":\"duplicate\",\"scope\":", 1);
    assert!(
        parse_snapshot(duplicate.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("duplicate key")
    );
}

#[test]
fn byte_and_row_bounds_include_exact_boundary() {
    let raw = bytes(&fixture());
    let mut limits = InputLimits {
        bytes: raw.len(),
        rows: 4,
        ..InputLimits::default()
    };
    assert!(parse_with_limits(&raw, limits).is_ok());
    limits.bytes -= 1;
    assert!(
        parse_with_limits(&raw, limits)
            .unwrap_err()
            .to_string()
            .contains("byte limit")
    );
    limits.bytes = raw.len();
    limits.rows = 3;
    assert!(
        parse_with_limits(&raw, limits)
            .unwrap_err()
            .to_string()
            .contains("row limit")
    );
}

#[test]
fn decoded_string_and_key_bounds_cover_unknown_fields() {
    for (key, value) in [("extra", json!("éééé")), ("éééé", json!(0))] {
        let mut v = fixture();
        v[key] = value;
        // Core labels are longer, so use an independent unknown field just at
        // the fixture's largest decoded string boundary.
        let largest = 64;
        v[key] = if key == "extra" {
            json!("é".repeat(largest / 2))
        } else {
            json!(0)
        };
        if key != "extra" {
            v.as_object_mut().unwrap().remove(key);
            v["é".repeat(largest / 2)] = json!(0);
        }
        let limits = InputLimits {
            string_bytes: largest,
            ..InputLimits::default()
        };
        assert!(parse_with_limits(&bytes(&v), limits).is_ok());
        if key == "extra" {
            v[key] = json!("é".repeat(largest / 2) + "x");
        } else {
            v["é".repeat(largest / 2) + "x"] = json!(0);
        }
        assert!(
            parse_with_limits(&bytes(&v), limits)
                .unwrap_err()
                .to_string()
                .contains("string limit")
        );
    }
}

fn nodes(v: &Value) -> usize {
    match v {
        Value::Array(a) => 1 + a.iter().map(nodes).sum::<usize>(),
        Value::Object(m) => 1 + m.iter().map(|(_, v)| 1 + nodes(v)).sum::<usize>(),
        _ => 1,
    }
}

#[test]
fn total_values_and_keys_are_bounded_in_unknown_subtrees() {
    let mut v = fixture();
    v["extra"] = json!({"a":[null,true,1,{"b":"x"}]});
    let total = nodes(&v);
    let mut limits = InputLimits {
        nodes: total,
        ..InputLimits::default()
    };
    assert!(parse_with_limits(&bytes(&v), limits).is_ok());
    limits.nodes -= 1;
    assert!(
        parse_with_limits(&bytes(&v), limits)
            .unwrap_err()
            .to_string()
            .contains("node limit")
    );
}

#[test]
fn depth_is_bounded_for_unknown_arrays_and_objects() {
    for object in [false, true] {
        let mut value = json!(0);
        for _ in 0..7 {
            value = if object {
                json!({"x":value})
            } else {
                json!([value])
            };
        }
        let mut v = fixture();
        v["extra"] = value;
        let mut limits = InputLimits {
            depth: 9,
            ..InputLimits::default()
        };
        assert!(parse_with_limits(&bytes(&v), limits).is_ok());
        limits.depth = 8;
        assert!(
            parse_with_limits(&bytes(&v), limits)
                .unwrap_err()
                .to_string()
                .contains("depth limit")
        );
    }
}

#[test]
fn regular_symlink_preserves_open_descriptor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input");
    fs::write(&path, FIXTURE).unwrap();
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    let loaded = read_snapshot(&alias).unwrap();
    let original = loaded.source.metadata().unwrap();
    assert_eq!(loaded.snapshot.scope, "pid:4242");
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"replacement").unwrap();
    assert_ne!((original.dev(), original.ino()), {
        let m = fs::metadata(&path).unwrap();
        (m.dev(), m.ino())
    });
    assert_eq!(loaded.source.metadata().unwrap().ino(), original.ino());
}

#[test]
fn fifo_without_writer_is_rejected_promptly() {
    use std::{
        ffi::CString,
        os::unix::ffi::OsStrExt,
        time::{Duration, Instant},
    };
    const CHILD: &str = "P11SCOPE_DIFF_FIFO_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fifo");
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        struct Owned(std::process::Child);
        impl Drop for Owned {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Owned(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "inventory_diff::input_tests::fifo_without_writer_is_rejected_promptly",
                    "--nocapture",
                ])
                .env(CHILD, &path)
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success(), "FIFO child failed: {status}");
                return;
            }
            assert!(Instant::now() < deadline, "FIFO open hung without a writer");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let path = std::path::PathBuf::from(std::env::var_os(CHILD).unwrap());
    let start = Instant::now();
    let error = read_snapshot(&path).unwrap_err().to_string();
    assert!(error.contains("regular file"), "{error}");
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn bytes_read_bound_ignores_a_readers_original_size() {
    use std::io::{Cursor, Read};
    // The second source becomes available only after the first is exhausted;
    // no cached metadata length can decide whether it fits.
    let source = Cursor::new(b"first").chain(Cursor::new(b"grown"));
    assert_eq!(read_bounded(source, 10).unwrap(), b"firstgrown");
    let source = Cursor::new(b"first").chain(Cursor::new(b"grown!"));
    assert!(
        read_bounded(source, 10)
            .unwrap_err()
            .to_string()
            .contains("byte limit")
    );
    assert!(
        read_bounded(Cursor::new(b""), usize::MAX)
            .unwrap_err()
            .to_string()
            .contains("byte limit overflow")
    );
}

#[test]
fn oversized_regular_file_and_directory_are_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("large");
    fs::write(&path, FIXTURE).unwrap();
    let limits = InputLimits {
        bytes: FIXTURE.len() - 1,
        ..InputLimits::default()
    };
    assert!(
        read_with_limits(&path, limits)
            .unwrap_err()
            .to_string()
            .contains("byte limit")
    );
    assert!(
        read_snapshot(dir.path())
            .unwrap_err()
            .to_string()
            .contains("regular file")
    );
}

#[test]
fn cgroup_native_filter_is_a_known_label_with_nonempty_evidence() {
    let mut document = fixture();
    document["scope"] = json!("cgroup:/sys/fs/cgroup/owned.scope");
    document["observation"]["lane"] = json!("native");
    document["observation"]["attach"] = json!({
        "selection": "auto", "mechanism": "uprobe-multi",
        "fallback": null, "scope_filter": "bpf-cgroup"
    });
    let snapshot = parse_snapshot(&bytes(&document)).unwrap();
    assert_eq!(
        (
            snapshot.callers.len(),
            snapshot.modules.len(),
            snapshot.edges.len()
        ),
        (1, 1, 1)
    );
    let filter = snapshot
        .observation
        .attach
        .as_ref()
        .unwrap()
        .scope_filter
        .as_ref()
        .unwrap();
    assert_eq!(filter.raw, "bpf-cgroup");
    assert!(
        filter.known,
        "the current producer's cgroup filter must be recognized"
    );
}

#[test]
fn cgroup_membership_uncertainty_is_a_known_label_with_nonempty_evidence() {
    let mut document = fixture();
    document["scope"] = json!("cgroup:/sys/fs/cgroup/owned.scope");
    document["edges"][0]["entries"]["coverage"]["state"] = json!("unknown");
    document["edges"][0]["entries"]["coverage"]["reason"] = json!("scope_membership_unproven");
    let snapshot = parse_snapshot(&bytes(&document)).unwrap();
    assert_eq!(
        (
            snapshot.callers.len(),
            snapshot.modules.len(),
            snapshot.edges.len()
        ),
        (1, 1, 1)
    );
    let coverage = snapshot.edges[0].coverage.as_ref().unwrap();
    let reason = coverage.reason.as_ref().unwrap();
    assert_eq!(coverage.state.raw, "unknown");
    assert_eq!(reason.raw, "scope_membership_unproven");
    assert!(
        reason.known,
        "the current producer's finite cgroup uncertainty must be recognized"
    );
}

#[test]
fn instance_s1_additive_arrays_still_obey_parser_limits() {
    let mut v = fixture();
    v["instances"] = json!([{"id":"i0"}]);
    v["semantic_edges"] = json!([{"instance":"i0","extra":[null,true,1]}]);
    let raw = bytes(&v);
    let mut limits = InputLimits {
        bytes: raw.len(),
        nodes: nodes(&v),
        ..InputLimits::default()
    };
    assert!(parse_with_limits(&raw, limits).is_ok());
    limits.nodes -= 1;
    assert!(
        parse_with_limits(&raw, limits)
            .unwrap_err()
            .to_string()
            .contains("node limit")
    );
    limits.nodes = nodes(&v);
    limits.bytes -= 1;
    assert!(
        parse_with_limits(&raw, limits)
            .unwrap_err()
            .to_string()
            .contains("byte limit")
    );
    let mut deep = json!(0);
    for _ in 0..12 {
        deep = json!([deep]);
    }
    v["semantic_edges"] = deep;
    assert!(
        parse_with_limits(
            &bytes(&v),
            InputLimits {
                depth: 9,
                ..InputLimits::default()
            }
        )
        .unwrap_err()
        .to_string()
        .contains("depth limit")
    );
}
