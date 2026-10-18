// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn caller(id: u32) -> MetadataCaller {
    MetadataCaller {
        id: CallerId(id),
        incarnation: 0,
        image: Some((u64::from(id) + 1, 0x8000_0000_0000_0001)),
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
fn no_scan_authority_upgrade_and_zero_exec_is_a_valid_native_image() {
    let mut runtime = MetadataRuntime::new(7);
    runtime.synchronize(
        [
            MetadataCaller {
                image: None,
                ..caller(0)
            },
            MetadataCaller {
                image: Some((2, 0)),
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
            5 => current.image = Some((1, 1)), // high64-bit change must matter
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
        if frame.refused_revision.is_some() {
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
