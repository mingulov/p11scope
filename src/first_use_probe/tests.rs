//! SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use p11scope_ebpf_common::{ImageIdentity, event_type};

fn endpoint() -> Endpoint {
    Endpoint {
        object: Object {
            device: 37,
            inode: 101,
            size: 8192,
            ctime_sec: 50,
            ctime_nsec: 1,
            sha256: "ab".repeat(32),
        },
        file_offset: 4586,
    }
}

fn journal(limit: usize) -> Journal {
    let e = endpoint();
    Journal::new(
        Target {
            device: e.object.device,
            inode: e.object.inode,
            sha256: e.object.sha256,
            file_offset: e.file_offset,
        },
        42,
        limit,
    )
}

fn event() -> Event {
    Event {
        event_type: event_type::CALL,
        pid_tgid: (42u64 << 32) | 42,
        slot: 3,
        ts_ns: 100,
        duration_ns: 20,
        image: ImageIdentity {
            task_cookie: 8,
            exec_id: 1,
        },
        // These private payload scalars must never appear in the journal.
        session: 987654321,
        p0: 876543219,
        mechanism: 765432198,
        ..Event::default()
    }
}

fn calls(j: &Journal) -> Vec<serde_json::Value> {
    j.facts
        .iter()
        .filter(|f| matches!(f, Fact::Call { .. }))
        .map(|f| serde_json::to_value(f).unwrap())
        .collect()
}

#[test]
fn real_binding_preserves_raw_clocks_image_and_only_allowed_metadata() {
    let mut j = journal(8);
    j.bind(9, 3, endpoint(), Some(70));
    j.call(9, &event(), Some(110));
    let c = calls(&j);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0]["endpoint"]["object"]["inode"], 101);
    assert_eq!(c[0]["entry_ns"], 80);
    assert_eq!(c[0]["return_ns"], 100);
    assert_eq!(c[0]["duration_ns"], 20);
    assert_eq!(c[0]["task_cookie"], 8);
    assert_eq!(c[0]["exec_id"], 1);
    let text = serde_json::to_string(&j).unwrap();
    for secret in [
        "987654321",
        "876543219",
        "765432198",
        "session",
        "mechanism",
        "attr_types",
    ] {
        assert!(!text.contains(secret), "private payload escaped: {secret}");
    }
}

#[test]
fn equal_bytes_on_a_different_physical_file_or_offset_are_not_the_target() {
    for changed in ["device", "inode", "digest", "offset"] {
        let mut foreign = endpoint();
        match changed {
            "device" => foreign.object.device += 1,
            "inode" => foreign.object.inode += 1,
            "digest" => foreign.object.sha256 = "cd".repeat(32),
            "offset" => foreign.file_offset += 1,
            _ => unreachable!(),
        }
        let mut j = journal(8);
        j.bind(9, 3, foreign.clone(), Some(70));
        j.call(9, &event(), Some(110));
        assert!(!j.facts.iter().any(|f| matches!(f, Fact::Attached { .. })));
        // Keep the counterexample's actual binding; never substitute expected.
        assert_eq!(
            calls(&j)[0]["endpoint"],
            serde_json::to_value(foreign).unwrap()
        );
    }
}

#[test]
fn later_binding_never_backfills_an_already_consumed_call() {
    let mut j = journal(8);
    j.call(9, &event(), Some(110));
    j.bind(9, 3, endpoint(), Some(120));
    j.call(9, &event(), Some(130));
    let c = calls(&j);
    assert!(c[0]["endpoint"].is_null());
    assert!(!c[1]["endpoint"].is_null());
    assert_eq!(c[0]["consumed_ns"], 110);
}

#[test]
fn producer_domains_and_slot_rebinding_cannot_alias() {
    let mut j = journal(8);
    j.bind(9, 3, endpoint(), Some(70));
    j.call(10, &event(), Some(110));
    assert!(calls(&j)[0]["endpoint"].is_null());
    let mut other = endpoint();
    other.object.inode += 1;
    j.bind(9, 3, other, Some(120));
    j.bind(9, 3, endpoint(), Some(130));
    j.call(9, &event(), Some(140));
    assert!(j.binding_conflicts > 0);
    assert!(calls(&j)[1]["endpoint"].is_null(), "ambiguity is sticky");
}

#[test]
fn missing_clocks_and_invalid_subtraction_do_not_become_zero() {
    let mut j = journal(8);
    j.bind(9, 3, endpoint(), None);
    let attached = serde_json::to_value(&j.facts[0]).unwrap();
    assert!(attached["post_attach_ns"].is_null());
    for (returned, duration) in [(10, 11), (0, 0), (20, 20)] {
        let mut e = event();
        e.ts_ns = returned;
        e.duration_ns = duration;
        j.call(9, &e, None);
    }
    for c in calls(&j) {
        assert!(c["entry_ns"].is_null());
        assert!(c["consumed_ns"].is_null());
    }
}

#[test]
fn saturation_is_explicit_and_bounds_facts_and_binding_history() {
    let mut j = journal(2);
    j.bind(9, 3, endpoint(), Some(70));
    j.call(9, &event(), Some(110));
    for slot in 4..100 {
        j.bind(9, slot, endpoint(), Some(120));
        j.call(9, &event(), Some(130));
    }
    assert_eq!(j.facts.len(), 2);
    assert!(j.dropped > 0);
    assert!(j.bindings.len() <= 2);
}

#[test]
fn foreign_pid_and_lifecycle_records_do_not_supply_owned_calls() {
    let mut j = journal(8);
    j.bind(9, 3, endpoint(), Some(70));
    let mut e = event();
    e.pid_tgid = (43u64 << 32) | 43;
    j.call(9, &e, Some(110));
    e = event();
    e.event_type = event_type::FORK;
    j.call(9, &e, Some(110));
    assert!(calls(&j).is_empty());
    j.call(9, &event(), Some(110));
    assert_eq!(calls(&j).len(), 1, "owned positive control");
}

#[test]
fn real_scan_boundary_records_failure_without_inventing_a_completed_scan() {
    use crate::discovery::hooks::HookRegistry;
    use crate::discovery::scan::{ScanRequest, scan_process_view};
    use crate::process::ProcessViewId;
    let pid = std::process::id();
    let view = ProcessView::open(ProcessViewId(71), pid).unwrap();
    let probe = test_probe(pid);
    let result = scan_process_view(
        &ScanRequest {
            pid: pid + 1,
            hints: &[],
            hooks: &HookRegistry::default(),
        },
        &view,
        &mut CaptureWorkBudget::default(),
    );
    assert!(result.is_err(), "positive control: request/view mismatch");
    let j = probe.finish();
    let facts = serde_json::to_value(&j).unwrap();
    assert_eq!(facts["facts"].as_array().unwrap().len(), 1);
    let f = &facts["facts"][0];
    assert_eq!(f["fact"], "scan_returned");
    assert_eq!(f["outcome"], "error");
    assert_eq!(f["pid"], pid);
    assert_eq!(f["view"], 71);
    assert!(f["returned_ns"].as_u64().unwrap() > 0);
    assert_eq!(f["birth_ticks"].as_u64(), view.first_use_birth_ticks());
}

#[test]
fn scan_identity_truncation_is_bounded_and_invalidates_the_journal() {
    use crate::discovery::scan::ScannedModule;
    use crate::process::ProcessViewId;
    use p11scope_manifest::maps::{Device, ObjectKey};
    let pid = std::process::id();
    let view = ProcessView::open(ProcessViewId(73), pid).unwrap();
    let module = ScannedModule {
        view: view.id(),
        mount_namespace: view.mount_namespace(),
        key: ObjectKey {
            device: Device {
                major: 0,
                minor: 35,
            },
            inode: 1,
        },
        path: String::new(),
        decoder_abi: None,
        exports: vec![],
        tables: vec![],
        interfaces: vec![],
    };
    let result = Ok(ScanOutcome::Scanned {
        modules: vec![module; 65],
        skipped: vec![],
        scan_ms: 1,
    });
    let probe = test_probe(pid);
    scan_returned(&view, true, &CaptureWorkBudget::default(), &result);
    publication_validated(&view, &result.as_ref().unwrap().modules()[0], 0);
    let journal = probe.finish();
    assert!(!journal.intact());
    assert_eq!(journal.truncated_scans, 1);
    let facts = serde_json::to_value(&journal).unwrap();
    assert_eq!(
        facts["facts"][0]["matching_inode_modules"]
            .as_array()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(facts["facts"][1]["fact"], "publication_validated");
    assert!(facts["facts"][1]["publication_hook_ns"].is_null());
    assert_eq!(facts["facts"][1]["mapping_device_minor"], 35);
    assert_eq!(facts["facts"][1]["mapping_inode"], 1);
}

#[test]
fn producer_domain_lives_until_probe_finishes_and_unwind_disarms_the_probe() {
    use std::io::Read as _;
    use std::os::unix::net::UnixStream;
    let probe = test_probe(42);
    let (mut reader, writer) = UnixStream::pair().unwrap();
    reader.set_nonblocking(true).unwrap();
    let domain = EventsDomain::test_with_fd(29, writer.into());
    loop_started(&domain, Some(70));
    drop(domain);
    assert_eq!(
        reader.read(&mut [0]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "journal retains the domain descriptor"
    );
    let journal = probe.finish();
    assert!(journal.intact());
    assert_eq!(
        reader.read(&mut [0]).unwrap(),
        0,
        "exact retained descriptor closed"
    );
    let failed = std::panic::catch_unwind(|| {
        let _probe = test_probe(42);
        panic!("scripted capture failure");
    });
    assert!(failed.is_err());
    assert!(test_probe(42).finish().intact(), "scope disarmed on unwind");
}

#[test]
fn marker_backpressure_never_blocks_capture_and_is_visible() {
    let (sender, _receiver) = std::sync::mpsc::sync_channel(0);
    let probe = Probe::install(journal(8), Some(sender));
    let domain = EventsDomain::test_standin(29);
    loop_started(&domain, Some(70));
    let j = probe.finish();
    assert_eq!(j.notification_drops, 1);
    assert!(!j.intact());
}
