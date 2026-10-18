// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn caller(id: u32) -> MetadataCaller {
    MetadataCaller {
        id: CallerId(id),
        incarnation: 0,
        image: Some(BinderMetadataKey::for_test(
            CallerId(id),
            0,
            u64::from(id) + 1,
            0x8000_0000_0000_0001,
        )),
        retired: false,
    }
}

#[test]
fn scheduler_starts_one_admitted_native_caller_without_blocking_admission() {
    let mut runtime = MetadataRuntime::new(7);
    runtime.synchronize([caller(0)], 0);
    assert!(
        runtime.next(0).is_some(),
        "admitted caller must enter the bounded sampling lane"
    );
    assert!(runtime.next(0).is_none(), "only one metadata job may run");
}

fn sample() -> UncommittedSample {
    let now = std::time::Instant::now();
    UncommittedSample {
        membership: super::super::parse_cgroup_membership(
            format!("0::/docker/{}\n", "a".repeat(64)).as_bytes(),
        ),
        validity: super::super::acquisition::SampleValidity::EndpointSampleOnly,
        numeric: super::super::acquisition::NumericAbsence::NamespaceUnresolved,
        started: now,
        ended: now,
    }
}

#[test]
fn scheduler_round_robins_all_4096_without_reusing_retired_identity() {
    let mut runtime = MetadataRuntime::new(7);
    runtime.synchronize((0..4096).map(caller), 0);
    for id in 0..4096u32 {
        let now = u64::from(id / STARTS_PER_WINDOW) * START_WINDOW_NS;
        let ticket = runtime.next(now).expect("every admitted caller selected");
        assert_eq!(ticket.caller.id, CallerId(id));
        runtime.refuse(ticket, MetadataReason::ReadFailed);
    }
    let mut retired = caller(0);
    retired.retired = true;
    runtime.synchronize([retired], STALE_NS * 2);
    let next = runtime.next(STALE_NS * 2).unwrap();
    assert_eq!(next.caller.id, CallerId(1));
    let frame = runtime.frame();
    assert_eq!(frame.summary.historical, 1);
    assert_eq!(
        frame.metadata(CallerId(0)).unwrap().status,
        MetadataStatus::Historical
    );
    assert_eq!(frame.summary.unknown, 4095);
}

#[test]
fn start_window_and_refresh_target_are_independent_finite_limits() {
    let mut runtime = MetadataRuntime::new(7);
    runtime.synchronize((0..65).map(caller), 0);
    for _ in 0..STARTS_PER_WINDOW {
        let ticket = runtime.next(0).unwrap();
        runtime.refuse(ticket, MetadataReason::Deadline);
    }
    assert!(runtime.next(START_WINDOW_NS - 1).is_none());
    let ticket = runtime.next(START_WINDOW_NS).unwrap();
    assert_eq!(ticket.caller.id, CallerId(64));
    runtime.refuse(ticket, MetadataReason::Deadline);
    assert!(runtime.next(REFRESH_NS - 1).is_none());
    assert_eq!(runtime.next(REFRESH_NS).unwrap().caller.id, CallerId(0));
}

#[test]
fn no_unbound_image_upgrade_and_zero_exec_is_a_valid_native_image() {
    let mut runtime = MetadataRuntime::new(7);
    runtime.synchronize(
        [
            MetadataCaller {
                image: None,
                ..caller(0)
            },
            MetadataCaller {
                image: Some(BinderMetadataKey::for_test(CallerId(1), 0, 2, 0)),
                ..caller(1)
            },
        ],
        0,
    );
    let ticket = runtime.next(0).unwrap();
    assert_eq!(ticket.caller.id, CallerId(1));
    let frame = runtime.frame();
    assert_eq!(
        frame.metadata(CallerId(0)).unwrap().reason,
        Some(MetadataReason::IdentityUnavailable)
    );
    assert_eq!(
        frame.metadata(CallerId(1)).unwrap().status,
        MetadataStatus::Pending
    );
}

#[test]
fn completion_checks_capture_incarnation_sequence_fence_stop_and_current_image() {
    for change in 0..7 {
        let mut runtime = MetadataRuntime::new(7);
        runtime.synchronize([caller(0)], 0);
        let ticket = runtime.next(0).unwrap();
        let mut completion = ticket;
        let mut current = caller(0);
        match change {
            0 => completion.epoch += 1,
            1 => completion.caller.incarnation += 1,
            2 => completion.sequence += 1,
            3 => runtime.invalidate(),
            4 => runtime.stop(),
            5 => current.image = Some(BinderMetadataKey::for_test(CallerId(0), 0, 1, 1)), // high64-bit change must matter
            6 => {
                current.retired = true;
                runtime.synchronize([current], 10);
            }
            _ => unreachable!(),
        }
        assert!(
            !runtime.finish(completion, current, Ok(sample()), 20),
            "change={change}"
        );
        assert!(
            runtime
                .frame()
                .metadata(CallerId(0))
                .unwrap()
                .container
                .id
                .is_none()
        );
    }
    let mut runtime = MetadataRuntime::new(7);
    runtime.synchronize([caller(0)], 0);
    let ticket = runtime.next(0).unwrap();
    assert!(runtime.finish(ticket, caller(0), Ok(sample()), 20));
    assert_eq!(
        runtime
            .frame()
            .metadata(CallerId(0))
            .unwrap()
            .container
            .id
            .unwrap()
            .as_str(),
        "a".repeat(64)
    );
    assert!(
        !runtime.finish(ticket, caller(0), Ok(sample()), 20),
        "one completion only"
    );
}

#[test]
fn stale_pending_unknown_and_historical_have_truthful_refresh_semantics() {
    let mut runtime = MetadataRuntime::new(7);
    runtime.synchronize((0..3).map(caller), 0);
    let healthy = runtime.next(0).unwrap();
    assert!(runtime.finish(healthy, caller(0), Ok(sample()), 10));
    let failed = runtime.next(0).unwrap();
    runtime.refuse(failed, MetadataReason::ProcessExited);
    runtime.synchronize((0..3).map(caller), STALE_NS + 11);
    let frame = runtime.frame();
    assert_eq!(
        frame.metadata(CallerId(0)).unwrap().status,
        MetadataStatus::Stale
    );
    assert_eq!(
        frame.metadata(CallerId(1)).unwrap().reason,
        Some(MetadataReason::ProcessExited)
    );
    assert_eq!(
        frame.metadata(CallerId(2)).unwrap().status,
        MetadataStatus::Pending
    );
    let ticket = runtime.next(STALE_NS + 11).unwrap();
    assert_eq!(ticket.caller.id, CallerId(2));
    runtime.refuse(ticket, MetadataReason::ReadFailed);
    let ticket = runtime.next(STALE_NS + 11).unwrap();
    runtime.refuse(ticket, MetadataReason::ReadFailed);
    assert!(
        runtime
            .frame()
            .metadata(CallerId(0))
            .unwrap()
            .container
            .id
            .is_none()
    );
    assert!(
        frame.metadata(CallerId(0)).unwrap().container.id.is_some(),
        "old frame immutable"
    );
}

#[test]
fn actual_table_worker_and_live_snapshot_overlap_stays_below_8mib() {
    let mut runtime = MetadataRuntime::new(7);
    runtime.synchronize((0..4096).map(caller), 0);
    let baseline = runtime.census().retained_bytes;
    let worker = runtime.reserve_worker().unwrap();
    assert_eq!(
        runtime.census().retained_bytes,
        baseline + WORKER_STORAGE_BYTES
    );
    let first = runtime.frame();
    let after_first = runtime.census().retained_bytes;
    let clone = first.clone();
    assert_eq!(
        runtime.census().retained_bytes,
        after_first,
        "Arc clone copies no metadata rows"
    );
    let mut held = vec![first];
    loop {
        let frame = runtime.frame();
        if frame.refusal.is_some() {
            assert_eq!(frame.summary.unknown, 4096);
            assert_eq!(
                frame.metadata(CallerId(4095)).unwrap().reason,
                Some(MetadataReason::LookupLimit)
            );
            break;
        }
        held.push(frame);
        assert!(
            held.len() < 64,
            "actual allocations must be admitted, not just estimated once"
        );
    }
    assert!(runtime.census().peak_retained_bytes <= CALLER_METADATA_TABLE_CEILING);
    drop(held);
    drop(clone);
    drop(worker);
    assert_eq!(
        runtime.census().retained_bytes,
        baseline,
        "last actual owner refunds all copies and work"
    );
    let frame = runtime.frame();
    assert_eq!(
        frame.summary.pending, 4096,
        "budget refusal never evicts table identities"
    );
}

#[test]
fn off_frame_has_no_metadata_or_storage_and_epoch_zero_never_starts() {
    let frame = MetadataFrame::default();
    assert!(frame.metadata(CallerId(0)).is_none());
    assert_eq!(frame.summary.json()["mode"], "none");
    let mut invalid = MetadataRuntime::new(0);
    invalid.synchronize([caller(0)], 0);
    assert!(invalid.next(0).is_none());
}

#[test]
fn immutable_frame_projection_agrees_across_json_identity_text_and_stream() {
    use crate::discovery::caller_registry::RegistryLimits;
    use crate::discovery::inventory_workload::{Harness, ScaleSpec};
    use crate::inventory_event_identity::IdentityIndex;
    use crate::inventory_events::EventWriter;
    use crate::inventory_present::Presentation;
    use std::io::{Read as _, Seek as _};

    let mut harness = Harness::new(RegistryLimits::default_limits()).unwrap();
    harness.stage_scale(&ScaleSpec {
        name: "metadata-consumers",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 91_000,
    });
    harness.commit();
    let mut view = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    let before = crate::inventory::render_json_from_presentation(&view);
    assert!(before["callers"][0].get("metadata").is_none());
    assert_eq!(before["caller_metadata"]["mode"], "none");

    let mut runtime = MetadataRuntime::new(7);
    let mut observed = caller(view.callers[0].id.0);
    observed.incarnation = view.callers[0].incarnation;
    runtime.synchronize([observed], 0);
    let ticket = runtime.next(0).unwrap();
    assert!(runtime.finish(ticket, observed, Ok(sample()), 20));
    view.caller_metadata = runtime.frame();
    let json = crate::inventory::render_json_from_presentation(&view);
    let context = IdentityIndex::new(&view).caller_context(observed.id);
    assert_eq!(json["callers"][0]["metadata"], context["metadata"]);
    assert_eq!(
        json["callers"][0]["metadata"]["container"]["id"],
        "a".repeat(64)
    );
    assert_eq!(
        json["budgets"], before["budgets"],
        "display context cannot change accounting"
    );
    assert_eq!(
        json["edges"], before["edges"],
        "display context cannot grant admission or counts"
    );
    let detail = crate::caller_metadata::consumer::detail(
        view.caller_metadata.metadata(observed.id).unwrap(),
        view.ended_ns,
    );
    assert!(crate::inventory_present::render_snapshot(&view).contains(&detail));

    let file = tempfile::tempfile().unwrap();
    let mut reader = file.try_clone().unwrap();
    let mut writer = EventWriter::anonymous_test_sink(file);
    let mut emitter = crate::caller_metadata::consumer::MetadataEmitter::default();
    assert_eq!(emitter.emit(&mut writer, &view, 20, false).unwrap(), 1);
    assert_eq!(emitter.emit(&mut writer, &view, 30, false).unwrap(), 0);
    runtime.synchronize([observed], REFRESH_NS);
    let ticket = runtime.next(REFRESH_NS).unwrap();
    runtime.finish(ticket, observed, Ok(sample()), REFRESH_NS + 20);
    view.caller_metadata = runtime.frame();
    assert_eq!(
        emitter
            .emit(&mut writer, &view, REFRESH_NS + 20, false)
            .unwrap(),
        0,
        "unchanged refresh not an event"
    );
    runtime.synchronize([observed], REFRESH_NS * 2);
    let ticket = runtime.next(REFRESH_NS * 2).unwrap();
    runtime.refuse(ticket, MetadataReason::ReadFailed);
    view.caller_metadata = runtime.frame();
    assert_eq!(
        emitter
            .emit(&mut writer, &view, REFRESH_NS * 2, false)
            .unwrap(),
        1
    );
    let failure =
        crate::inventory::render_json_from_presentation(&view)["callers"][0]["metadata"].clone();
    observed.retired = true;
    runtime.synchronize([observed], REFRESH_NS * 3);
    view.caller_metadata = runtime.frame();
    assert_eq!(
        emitter
            .emit(&mut writer, &view, REFRESH_NS * 3, false)
            .unwrap(),
        1
    );
    reader.rewind().unwrap();
    let mut bytes = String::new();
    reader.read_to_string(&mut bytes).unwrap();
    let records: Vec<serde_json::Value> = bytes
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 3);
    assert!(
        records
            .iter()
            .all(|record| record["kind"] == "caller_metadata_changed")
    );
    assert_eq!(
        records[0]["event"]["metadata"],
        json["callers"][0]["metadata"]
    );
    assert_eq!(records[1]["event"]["metadata"], failure);
    assert_eq!(records[2]["event"]["metadata"]["status"], "historical");
    assert_eq!(records[2]["event"]["metadata"]["reason"], "read_failed");
}

#[test]
fn final_frame_ages_sample_without_mutating_table_or_unknown_causes() {
    let mut runtime = MetadataRuntime::new(7);
    runtime.synchronize([caller(0), caller(1)], 0);
    let healthy = runtime.next(0).unwrap();
    runtime.finish(healthy, caller(0), Ok(sample()), 10);
    let failed = runtime.next(0).unwrap();
    runtime.refuse(failed, MetadataReason::ProcessExited);
    let fresh = runtime.frame();
    let final_frame = runtime.frame_at(STALE_NS + 11);
    assert_eq!(
        final_frame.metadata(CallerId(0)).unwrap().status,
        MetadataStatus::Stale
    );
    assert_eq!(final_frame.summary.stale, 1);
    assert_eq!(final_frame.summary.sampled, 0);
    assert_eq!(
        final_frame.metadata(CallerId(1)).unwrap().reason,
        Some(MetadataReason::ProcessExited)
    );
    assert_eq!(
        fresh.metadata(CallerId(0)).unwrap().status,
        MetadataStatus::Sampled
    );
    assert_eq!(
        runtime.frame().metadata(CallerId(0)).unwrap().status,
        MetadataStatus::Sampled
    );
}

#[test]
fn first_binding_availability_is_not_reported_as_an_observed_exec() {
    let mut runtime = MetadataRuntime::new(7);
    let unbound = MetadataCaller {
        image: None,
        ..caller(0)
    };
    runtime.synchronize([unbound], 0);
    assert!(runtime.next(0).is_none());
    assert_eq!(
        runtime.frame().metadata(CallerId(0)).unwrap().reason,
        Some(MetadataReason::IdentityUnavailable)
    );
    runtime.synchronize([caller(0)], 1);
    assert_eq!(
        runtime.frame().metadata(CallerId(0)).unwrap().reason,
        Some(MetadataReason::IdentityUnavailable),
        "the first binding must not invent an execution transition"
    );
    let ticket = runtime.next(REFRESH_NS).unwrap();
    runtime.finish(ticket, caller(0), Ok(sample()), REFRESH_NS + 20);
    runtime.synchronize([unbound], REFRESH_NS + 30);
    assert_eq!(
        runtime.frame().metadata(CallerId(0)).unwrap().reason,
        Some(MetadataReason::IdentityUnavailable)
    );
    assert!(
        runtime
            .frame()
            .metadata(CallerId(0))
            .unwrap()
            .container
            .id
            .is_none()
    );
}

#[test]
fn stop_keeps_last_sample_when_native_binding_is_retired_and_rejects_late_work() {
    let mut runtime = MetadataRuntime::new(7);
    runtime.synchronize([caller(0)], 0);
    let first = runtime.next(0).unwrap();
    runtime.finish(first, caller(0), Ok(sample()), 20);
    let late = runtime.next(REFRESH_NS).unwrap();
    runtime.stop();
    let unbound = MetadataCaller {
        image: None,
        ..caller(0)
    };
    runtime.synchronize([unbound], REFRESH_NS + 1);
    assert_eq!(
        runtime.frame().metadata(CallerId(0)).unwrap().status,
        MetadataStatus::Sampled,
        "normal native retirement after stop cannot erase the last sample"
    );
    assert!(!runtime.finish(late, caller(0), Ok(sample()), REFRESH_NS + 2));
    assert!(runtime.next(REFRESH_NS * 2).is_none());
    assert_eq!(
        runtime
            .frame_at(STALE_NS + 21)
            .metadata(CallerId(0))
            .unwrap()
            .status,
        MetadataStatus::Stale
    );
    runtime.synchronize(
        [MetadataCaller {
            retired: true,
            ..unbound
        }],
        STALE_NS + 22,
    );
    assert_eq!(
        runtime.frame().metadata(CallerId(0)).unwrap().status,
        MetadataStatus::Historical
    );
}
