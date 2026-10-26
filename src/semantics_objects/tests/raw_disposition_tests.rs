//! SPDX-License-Identifier: GPL-3.0-or-later
//! Actual collector custody and negative disposal, with substituted ring I/O.

use super::tests::{SteadyFault, producers};
use super::*;
use crate::events::{
    BoundedRecord, BoundedRecordSource, EventsDomain, RecordSource, ScriptedRecords,
};
use crate::semantics_edge::resources::SemanticResourcePool;
use crate::semantics_objects::journal::tests::{
    COOKIE, ENTRY_NS, EXEC, begin_bytes, end_bytes_absent, function_id,
};
use p11scope_ebpf_common::object_wire::publish_object_descriptors;

fn collect(
    owner: &mut JointCaptureOwner,
    pool: &SemanticResourcePool,
    retained: &SessionDrainProducers,
    events: &EventsDomain,
    records: impl IntoIterator<Item = Vec<u8>>,
) -> RawJointQuantum {
    assert!(retained.matches_events(events));
    let mut drain = EventDrain::over_domain(ScriptedRecords::records(records, 8), events.clone());
    RawJointQuantum::collect_with_adapter(
        &mut drain,
        &publish_object_descriptors(),
        8,
        &SteadyFault(Cell::new(None)),
        retained,
        |bytes| pool.reserve(bytes),
        owner.adapter_mut(),
    )
    .unwrap()
}

#[test]
fn joint_raw_adapter_equal_id_foreign_allocation_refuses_genuine_raw() {
    let events = EventsDomain::test_standin(0xb222);
    let retained = producers(&events);
    let foreign = SessionDrainProducers::test_pair(
        retained.native_domain(),
        EventsDomain::test_standin(events.id()),
    );
    let pool = SemanticResourcePool::default();
    let mut owner = JointCaptureOwner::new(JournalLimits::policy(), pool.reserver());
    let raw = collect(&mut owner, &pool, &retained, &events, []);
    let before = pool.snapshot().charged_bytes;
    assert!(raw.matches_producers(&retained));
    owner.adapter.resource_producers = Some(foreign);
    assert_eq!(
        raw.ready_for_ingest(owner.adapter(), &retained),
        Err(RawQuantumRefusal::ForeignCapture),
        "the adapter's retained allocation is checked independently of the raw owner"
    );
    assert_eq!(pool.snapshot().charged_bytes, before);
    assert_eq!(owner.adapter.consumed_through_for_test(), 0);
}

#[test]
fn joint_raw_disposal_refunds_only_owned_roles() {
    let events = EventsDomain::test_standin(0xb223);
    let retained = producers(&events);
    let pool = SemanticResourcePool::default();
    let baseline = pool.snapshot().charged_bytes;
    let mut owner = JointCaptureOwner::new(JournalLimits::policy(), pool.reserver());
    owner.ledger_mut().prepare_capacity().unwrap();
    let table_baseline = pool.snapshot().charged_bytes;
    let begin = begin_bytes(1, 1, function_id("C_Sign"), 0);
    let end = end_bytes_absent(&begin, 0, ENTRY_NS + 100);
    let mut raw = collect(
        &mut owner,
        &pool,
        &retained,
        &events,
        [begin.to_vec(), end.to_vec()],
    );
    let origin = raw.ordinary[0].joint_resource.unwrap();
    let report = crate::semantic_capture::deliver_collected_raw_for_resource_test(
        &mut raw,
        retained.native_domain(),
    );
    assert!(!report.outcomes().is_empty());
    assert!(raw.h0_reported && raw.ordinary.is_empty() && !raw.h0_pending);

    // Resource-only roles over the collector's actual original BEGIN/END.
    // These memberships grant no admission, model registration or seal.
    owner
        .ledger_mut()
        .charge_h8open_from_raw(100, 100, origin.reservation())
        .unwrap();
    let h8 = owner.ledger().h8_reservation(100).unwrap();
    owner
        .ledger_mut()
        .charge_model_from_open(200, 200, &h8)
        .unwrap();
    let staged = owner
        .ledger_mut()
        .charge_collected(retained.native_domain(), 300, 300, Some(&origin))
        .unwrap();
    let association = owner
        .ledger_mut()
        .mint_keyassoc_from_stage(400, Some(&staged))
        .unwrap();
    let other_begin = begin_bytes(2, 1, function_id("C_Sign"), 0);
    let other = collect(
        &mut owner,
        &pool,
        &retained,
        &events,
        [other_begin.to_vec()],
    );
    let before = pool.snapshot().charged_bytes;
    assert_eq!(owner.ledger().census(), 2);
    assert_eq!(owner.ledger().charged_bytes(), 1_000);
    let identity = raw.h0_identity();
    let disposed = raw
        .dispose_without_ingest(&mut owner, &retained, RawDisposeReason::NoAdmission)
        .unwrap_or_else(|(_, reason)| panic!("owned disposal: {reason:?}"));
    assert_eq!(disposed.reason(), RawDisposeReason::NoAdmission);
    assert!(disposed.failure().is_some());
    assert!(disposed.identity() == identity);
    let prepaid = disposed.prepaid_bytes();
    assert!(
        prepaid > 0,
        "the original negative and following audit remain paid"
    );
    let disposed_frontier = disposed.frontier();
    assert!(disposed_frontier == owner.adapter.consumed_frontier());
    assert_eq!(disposed.validate_owner(owner.adapter(), &retained), Ok(()));
    assert_eq!(owner.ledger().census(), 2, "the other raw role survives");
    assert_eq!(owner.ledger().staged(), 1);
    assert_eq!(owner.ledger().charged_bytes(), 1_000);
    assert!(owner.ledger().h8_reservation(100).is_some());
    assert_eq!(
        pool.snapshot().charged_bytes,
        before - RawJointQuantum::storage_bytes(8) - OWNED_ALLOCATION_PADDING + prepaid,
        "physical raw buffers refund while the original negative/audit allowance stays paid"
    );
    let _ = other
        .dispose_without_ingest(&mut owner, &retained, RawDisposeReason::Capacity)
        .unwrap_or_else(|(_, reason)| panic!("second disposal: {reason:?}"));
    assert!(disposed.frontier() == disposed_frontier);
    assert_eq!(owner.ledger().census(), 1);
    owner.ledger_mut().release_h8open(100);
    assert_eq!(owner.ledger().charged_bytes(), 900);
    owner.ledger_mut().release_model(200);
    assert_eq!(owner.ledger().charged_bytes(), 700);
    owner
        .ledger_mut()
        .release_collected(retained.native_domain(), 300);
    assert_eq!(owner.ledger().charged_bytes(), 400);
    owner.ledger_mut().release_keyassoc(association);
    assert_eq!(owner.ledger().census(), 0);
    assert_eq!(owner.ledger().charged_bytes(), 0);
    assert_eq!(pool.snapshot().charged_bytes, table_baseline + prepaid);
    drop(disposed);
    assert_eq!(
        pool.snapshot().charged_bytes,
        table_baseline,
        "only dropping the actual negative owner refunds its full allowance"
    );
    drop(owner);
    assert_eq!(pool.snapshot().charged_bytes, baseline);
}

#[test]
fn joint_raw_disposal_refuses_foreign_and_undelivered_input_without_mutation() {
    let events = EventsDomain::test_standin(0xb224);
    let retained = producers(&events);
    let pool = SemanticResourcePool::default();
    let mut owner = JointCaptureOwner::new(JournalLimits::policy(), pool.reserver());
    let begin = begin_bytes(1, 1, function_id("C_Sign"), 0);
    let end = end_bytes_absent(&begin, 0, ENTRY_NS + 100);
    let mut raw = collect(
        &mut owner,
        &pool,
        &retained,
        &events,
        [begin.to_vec(), end.to_vec()],
    );
    let identity = raw.h0_identity();
    let charged = pool.snapshot().charged_bytes;
    let foreign = SessionDrainProducers::test_pair(
        retained.native_domain(),
        EventsDomain::test_standin(events.id()),
    );
    raw = match raw.dispose_without_ingest(&mut owner, &foreign, RawDisposeReason::NoAdmission) {
        Err((raw, reason)) => {
            assert_eq!(reason, RawQuantumRefusal::ForeignCapture);
            raw
        }
        Ok(_) => panic!("foreign allocation disposed the original"),
    };
    let mut other_owner = JointCaptureOwner::new(JournalLimits::policy(), pool.reserver());
    assert!(other_owner.adapter.bind_resource_producers(&retained));
    raw = match raw.dispose_without_ingest(
        &mut other_owner,
        &retained,
        RawDisposeReason::NoAdmission,
    ) {
        Err((raw, reason)) => {
            assert_eq!(reason, RawQuantumRefusal::ForeignLedger);
            raw
        }
        Ok(_) => panic!("foreign ledger disposed the original"),
    };
    raw = match raw.dispose_without_ingest(&mut owner, &retained, RawDisposeReason::NoAdmission) {
        Err((raw, reason)) => {
            assert_eq!(reason, RawQuantumRefusal::H0Undelivered);
            raw
        }
        Ok(_) => panic!("ordinary facts were discarded before actual H0 delivery"),
    };
    assert!(raw.h0_identity() == identity);
    assert_eq!(raw.ordinary.len(), 1);
    assert_eq!(pool.snapshot().charged_bytes, charged);
    assert!(!owner.adapter.is_tainted((COOKIE, EXEC)));
    assert_eq!(owner.adapter.consumed_through_for_test(), 0);
    assert_eq!(other_owner.adapter.consumed_through_for_test(), 0);
    let _ = crate::semantic_capture::deliver_collected_raw_for_resource_test(
        &mut raw,
        retained.native_domain(),
    );
    raw = match raw.dispose_without_ingest(&mut owner, &retained, RawDisposeReason::Empty) {
        Err((raw, reason)) => {
            assert_eq!(reason, RawQuantumRefusal::DispositionMismatch);
            raw
        }
        Ok(_) => panic!("nonempty raw was labeled empty"),
    };
    let negative = raw
        .dispose_without_ingest(&mut owner, &retained, RawDisposeReason::NoAdmission)
        .unwrap_or_else(|(_, reason)| panic!("actual H0 disposition: {reason:?}"));
    assert!(negative.identity() == identity);
    assert_eq!(negative.validate_owner(owner.adapter(), &retained), Ok(()));
    assert_eq!(
        negative.validate_owner(other_owner.adapter(), &retained),
        Err(RawQuantumRefusal::ForeignLedger)
    );
    assert!(owner.adapter.is_tainted((COOKIE, EXEC)));
    assert_eq!(owner.ledger().census(), 0);
}

#[test]
fn joint_empty_and_capacity_raw_dispositions_need_no_drain_grant() {
    let events = EventsDomain::test_standin(0xb225);
    let retained = producers(&events);
    let pool = SemanticResourcePool::default();
    let mut owner = JointCaptureOwner::new(JournalLimits::policy(), pool.reserver());
    let mut drain = EventDrain::over_domain(ScriptedRecords::records([], 4), events);
    let raw = RawJointQuantum::collect_bounded_with_adapter(
        &mut drain,
        &publish_object_descriptors(),
        4,
        None,
        &SteadyFault(Cell::new(None)),
        &retained,
        |bytes| pool.reserve(bytes),
        owner.adapter_mut(),
    )
    .unwrap();
    let empty = raw
        .dispose_without_ingest(&mut owner, &retained, RawDisposeReason::Empty)
        .unwrap_or_else(|(_, reason)| panic!("genuine empty disposition: {reason:?}"));
    assert!(empty.failure().is_none());
    assert!(owner.adapter.keys.is_empty() && owner.adapter.drain_pins.is_empty());
    assert_eq!(owner.adapter.consumed_through_for_test(), 0);
    let begin = begin_bytes(1, 1, function_id("C_Sign"), 0);
    drain.source_mut().push_record(begin.to_vec());
    let raw = RawJointQuantum::collect_bounded_with_adapter(
        &mut drain,
        &publish_object_descriptors(),
        1,
        None,
        &SteadyFault(Cell::new(None)),
        &retained,
        |bytes| pool.reserve(bytes),
        owner.adapter_mut(),
    )
    .unwrap();
    assert_eq!(raw.attempted, raw.capacity);
    assert!(raw.ordinary.is_empty());
    let capacity = raw
        .dispose_without_ingest(&mut owner, &retained, RawDisposeReason::Capacity)
        .unwrap_or_else(|(_, reason)| panic!("pre-completion capacity disposal: {reason:?}"));
    assert!(capacity.failure().is_some());
    assert!(owner.adapter.is_tainted((COOKIE, EXEC)));
    assert_eq!(owner.ledger().census(), 0);
    assert_eq!(owner.adapter.consumed_through_for_test(), 1);
    let capacity_frontier = capacity.frontier();
    assert!(capacity_frontier == owner.adapter.consumed_frontier());
    assert!(owner.adapter.keys.is_empty() && owner.adapter.drain_pins.is_empty());
    drain
        .source_mut()
        .push_record(end_bytes_absent(&begin, 0, ENTRY_NS + 100).to_vec());
    let mut next = RawJointQuantum::collect_bounded_with_adapter(
        &mut drain,
        &publish_object_descriptors(),
        1,
        None,
        &SteadyFault(Cell::new(None)),
        &retained,
        |bytes| pool.reserve(bytes),
        owner.adapter_mut(),
    )
    .expect("genuine negative consumption permits the next real collection");
    assert_eq!(
        next.ordinary.len(),
        1,
        "q2 retains the genuine original END"
    );
    let report = crate::semantic_capture::deliver_collected_raw_for_resource_test(
        &mut next,
        retained.native_domain(),
    );
    assert!(!report.outcomes().is_empty());
    let _ = next
        .dispose_without_ingest(&mut owner, &retained, RawDisposeReason::NoAdmission)
        .unwrap_or_else(|(_, reason)| panic!("genuine END negative disposition: {reason:?}"));
    assert_eq!(owner.adapter.consumed_through_for_test(), 2);
    assert!(capacity.frontier() == capacity_frontier);
    assert_eq!(owner.ledger().census(), 0);
    assert!(owner.adapter.is_tainted((COOKIE, EXEC)));
}

#[test]
fn joint_stopped_raw_has_only_a_terminal_negative_disposition() {
    let events = EventsDomain::test_standin(0xb226);
    let retained = producers(&events);
    let pool = SemanticResourcePool::default();
    let mut owner = JointCaptureOwner::new(JournalLimits::policy(), pool.reserver());
    let begin = begin_bytes(1, 1, function_id("C_Sign"), 0);
    let raw = collect(&mut owner, &pool, &retained, &events, [begin.to_vec()]);
    let (adapter, model) = owner.parts();
    let _ = adapter.stop(model);
    assert_eq!(
        raw.ready_for_ingest(owner.adapter(), &retained),
        Err(RawQuantumRefusal::Stopped)
    );
    let negative = raw
        .dispose_without_ingest(&mut owner, &retained, RawDisposeReason::TerminalLoss)
        .unwrap_or_else(|(_, reason)| panic!("stopped raw disposal: {reason:?}"));
    assert_eq!(negative.failure().unwrap().gap, JournalGap::Stopped);
    assert_eq!(owner.ledger().census(), 0);
    assert!(owner.adapter.stopped);
}

#[test]
fn joint_unlocalizable_raw_loss_never_becomes_an_empty_prefix() {
    let events = EventsDomain::test_standin(0xb227);
    let retained = producers(&events);
    let pool = SemanticResourcePool::default();
    let mut owner = JointCaptureOwner::new(JournalLimits::policy(), pool.reserver());
    let mut drain = EventDrain::over_domain(ScriptedRecords::records([vec![1, 2, 3]], 1), events);
    let raw = RawJointQuantum::collect_bounded_with_adapter(
        &mut drain,
        &publish_object_descriptors(),
        4,
        None,
        &SteadyFault(Cell::new(None)),
        &retained,
        |bytes| pool.reserve(bytes),
        owner.adapter_mut(),
    )
    .unwrap();
    assert!(raw.ordered.is_empty());
    assert_eq!(raw.audit.malformed_delta, 1);
    let raw = match raw.dispose_without_ingest(&mut owner, &retained, RawDisposeReason::Empty) {
        Err((raw, reason)) => {
            assert_eq!(reason, RawQuantumRefusal::DispositionMismatch);
            raw
        }
        Ok(_) => panic!("malformed input was relabeled as empty"),
    };
    let negative = raw
        .dispose_without_ingest(&mut owner, &retained, RawDisposeReason::TerminalLoss)
        .unwrap_or_else(|(_, reason)| panic!("malformed raw disposal: {reason:?}"));
    assert_eq!(negative.failure().unwrap().gap, JournalGap::Malformed);
    assert!(owner.adapter.invalidated && owner.adapter.stream_broken);
    assert_eq!(owner.adapter.consumed_through_for_test(), 0);
    assert_eq!(owner.ledger().census(), 0);
}

#[test]
fn joint_unlinked_broken_stream_resyncs_next_collect() {
    // man-1 Cause 1: one failed quantum (malformed input stands in for
    // the live single-discard quantum) breaks the adapter stream; an
    // S1-only (unlinked) lane must re-sync the next quantum on a fresh
    // stream instead of refusing Gap forever and stranding the run.
    let events = EventsDomain::test_standin(0xd15c);
    let retained =
        SessionDrainProducers::test_pair_unlinked(NativeDomainId::mint(), events.clone());
    let pool = SemanticResourcePool::default();
    let mut owner = JointCaptureOwner::new(JournalLimits::policy(), pool.reserver());
    let mut drain =
        EventDrain::over_domain(ScriptedRecords::records([vec![1, 2, 3]], 1), events.clone());
    let raw = RawJointQuantum::collect_bounded_with_adapter(
        &mut drain,
        &publish_object_descriptors(),
        4,
        None,
        &SteadyFault(Cell::new(None)),
        &retained,
        |bytes| pool.reserve(bytes),
        owner.adapter_mut(),
    )
    .unwrap();
    assert_eq!(raw.audit.malformed_delta, 1);
    raw.dispose_without_ingest(&mut owner, &retained, RawDisposeReason::TerminalLoss)
        .unwrap_or_else(|(_, reason)| panic!("malformed raw disposal: {reason:?}"));
    assert!(
        owner.adapter.invalidated && owner.adapter.stream_broken,
        "the failed disposal breaks the stream"
    );
    // The next tick's Idle collect on the same unlinked lane re-syncs.
    let mut drain =
        EventDrain::over_domain(ScriptedRecords::records([vec![1, 2, 3]], 1), events.clone());
    let next = RawJointQuantum::collect_bounded_with_adapter(
        &mut drain,
        &publish_object_descriptors(),
        4,
        None,
        &SteadyFault(Cell::new(None)),
        &retained,
        |bytes| pool.reserve(bytes),
        owner.adapter_mut(),
    );
    assert!(
        next.is_ok(),
        "an unlinked lane re-syncs after a break: {:?}",
        next.err()
    );
    assert!(
        !(owner.adapter.invalidated || owner.adapter.stream_broken),
        "the re-sync clears the broken stream"
    );
}

#[test]
fn joint_unlinked_discarded_stream_resyncs_next_collect() {
    // The live break trigger is a discarded ring reservation
    // (discarded_delta = 1, kernel-overwritten), not a malformed
    // record: break the adapter stream with a discard on an unlinked
    // lane and assert the next collect re-syncs. Twin of the
    // malformed-break test above, which stays as the second twin.
    struct DiscardingRecords {
        inner: ScriptedRecords,
        discarded: std::rc::Rc<Cell<u64>>,
    }
    impl RecordSource for DiscardingRecords {
        fn next_record(&mut self) -> Option<impl std::ops::Deref<Target = [u8]> + '_> {
            self.inner.next_record()
        }
        fn discarded(&self) -> u64 {
            self.discarded.get()
        }
    }
    impl BoundedRecordSource for DiscardingRecords {
        fn positions(&self) -> aya::maps::ring_buf::RingBufPositions {
            self.inner.positions()
        }
        fn consumer(&self) -> usize {
            self.inner.consumer()
        }
        fn bounded_record(
            &mut self,
            stop: usize,
        ) -> anyhow::Result<BoundedRecord<impl std::ops::Deref<Target = [u8]> + '_>> {
            self.inner.bounded_record(stop)
        }
    }
    let events = EventsDomain::test_standin(0xd15c);
    let retained =
        SessionDrainProducers::test_pair_unlinked(NativeDomainId::mint(), events.clone());
    let pool = SemanticResourcePool::default();
    let mut owner = JointCaptureOwner::new(JournalLimits::policy(), pool.reserver());
    let counter = std::rc::Rc::new(Cell::new(0));
    let mut drain = EventDrain::over_domain(
        DiscardingRecords {
            inner: ScriptedRecords::records([], 4),
            discarded: counter.clone(),
        },
        events.clone(),
    );
    let fault = SteadyFault(Cell::new(None));
    let mut raw = RawJointQuantum::collect_bounded_with_adapter(
        &mut drain,
        &publish_object_descriptors(),
        4,
        None,
        &fault,
        &retained,
        |bytes| pool.reserve(bytes),
        owner.adapter_mut(),
    )
    .unwrap();
    counter.set(1);
    raw.continue_collect_with_adapter(
        &mut drain,
        &publish_object_descriptors(),
        1,
        &fault,
        &retained,
        owner.adapter_mut(),
    )
    .unwrap();
    assert_eq!(raw.audit.malformed_delta, 0, "no malformed input here");
    assert_eq!(raw.audit.discarded_delta, 1, "one discarded reservation");
    raw.dispose_without_ingest(&mut owner, &retained, RawDisposeReason::TerminalLoss)
        .unwrap_or_else(|(_, reason)| panic!("discarded raw disposal: {reason:?}"));
    assert!(
        owner.adapter.invalidated && owner.adapter.stream_broken,
        "the failed disposal breaks the stream"
    );
    // The next tick's collect on the same unlinked lane re-syncs.
    let later = std::rc::Rc::new(Cell::new(1));
    let mut drain = EventDrain::over_domain(
        DiscardingRecords {
            inner: ScriptedRecords::records([], 4),
            discarded: later,
        },
        events.clone(),
    );
    let next = RawJointQuantum::collect_bounded_with_adapter(
        &mut drain,
        &publish_object_descriptors(),
        4,
        None,
        &SteadyFault(Cell::new(None)),
        &retained,
        |bytes| pool.reserve(bytes),
        owner.adapter_mut(),
    );
    assert!(
        next.is_ok(),
        "an unlinked lane re-syncs after a discard break: {:?}",
        next.err()
    );
    assert!(
        !(owner.adapter.invalidated || owner.adapter.stream_broken),
        "the re-sync clears the broken stream"
    );
}

#[test]
fn joint_linked_broken_stream_keeps_gap_refusal() {
    // Healthy twin: a journal-linked lane keeps the fail-closed Gap
    // refusal after a stream break; only S1-only lanes re-sync.
    let events = EventsDomain::test_standin(0x61a9);
    let retained = producers(&events);
    assert!(retained.journal_linked());
    let pool = SemanticResourcePool::default();
    let mut owner = JointCaptureOwner::new(JournalLimits::policy(), pool.reserver());
    let mut drain =
        EventDrain::over_domain(ScriptedRecords::records([vec![1, 2, 3]], 1), events.clone());
    let raw = RawJointQuantum::collect_bounded_with_adapter(
        &mut drain,
        &publish_object_descriptors(),
        4,
        None,
        &SteadyFault(Cell::new(None)),
        &retained,
        |bytes| pool.reserve(bytes),
        owner.adapter_mut(),
    )
    .unwrap();
    raw.dispose_without_ingest(&mut owner, &retained, RawDisposeReason::TerminalLoss)
        .unwrap_or_else(|(_, reason)| panic!("malformed raw disposal: {reason:?}"));
    assert!(
        owner.adapter.invalidated && owner.adapter.stream_broken,
        "the failed disposal breaks the stream"
    );
    let mut drain =
        EventDrain::over_domain(ScriptedRecords::records([vec![1, 2, 3]], 1), events.clone());
    let next = RawJointQuantum::collect_bounded_with_adapter(
        &mut drain,
        &publish_object_descriptors(),
        4,
        None,
        &SteadyFault(Cell::new(None)),
        &retained,
        |bytes| pool.reserve(bytes),
        owner.adapter_mut(),
    );
    let err = next.err();
    assert!(
        matches!(
            err,
            Some(RawQuantumRefusal::Cut(
                crate::semantics_objects::journal::BirthCutRefusal::Gap
            ))
        ),
        "a linked lane still refuses Gap after a break: {err:?}"
    );
    assert!(
        owner.adapter.invalidated && owner.adapter.stream_broken,
        "the break stays fail-closed for linked lanes"
    );
}
