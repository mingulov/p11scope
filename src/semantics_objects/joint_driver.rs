//! SPDX-License-Identifier: GPL-3.0-or-later
//! Retained, bounded wire custody for one production Joint quantum.
//!
//! Raw custody is not admission, bootstrap or drain-binding authority.

use super::{FaultEpoch, FaultReadError, JournalCollection, JournalIngestItem};
use crate::attach::SessionDrainProducers;
use crate::attach::capture::NativeDomainId;
use crate::events::{DecodedEventRecord, EventDrain, LIVE_POLL_QUANTUM, RecordSource};
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SemanticResourceRefusal,
};
use p11scope_ebpf_common::MAX_DESCRIPTORS;
use p11scope_ebpf_common::object_wire::ObjectDescriptorWire;
use std::cell::{Cell, RefCell};
use std::ops::ControlFlow;

/// One bounded original poll. Neither the wire buffer nor its audit establishes
/// key, birth, drain-binding or H3 authority. The charge remains owned until the
/// complete quantum (including H0's physical ordinary copy) is disposed.
pub(crate) struct RawJointQuantum {
    ordered: Vec<JournalIngestItem>,
    ordinary: Vec<DecodedEventRecord>,
    audit: JournalCollection,
    native: NativeDomainId,
    h0_origins: Vec<usize>,
    h0_delivered: usize,
    completed_delivered: bool,
    h0_pending: bool,
    _charge: ResourceLease,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RawQuantumRefusal {
    #[cfg(test)]
    Unavailable,
    #[cfg(test)]
    Capacity,
    ForeignDrain,
    ForeignCapture,
    InvalidLimit,
    Resource(SemanticResourceRefusal),
    Allocation,
    Fault(FaultReadError),
}

impl RawJointQuantum {
    fn storage_bytes(limit: usize) -> usize {
        // Both arrays coexist. reserve_exact requests these capacities once;
        // callbacks never grow either array. Include each allocation's padding.
        limit
            * (size_of::<JournalIngestItem>()
                + size_of::<DecodedEventRecord>()
                + size_of::<usize>())
            + 3 * OWNED_ALLOCATION_PADDING
            + size_of::<Self>()
    }

    pub(crate) fn matches_producers(&self, producers: &SessionDrainProducers) -> bool {
        self.native == producers.native_domain() && self.audit.drain_domain == producers.events_id()
    }

    pub(crate) fn pending_h0_records(&self) -> usize {
        self.ordinary.len()
    }

    /// Move each original ordinary/END payload to H0 once. Repeated empty
    /// takes service pending scans; they neither poll nor replay old inputs.
    pub(crate) fn take_h0_input(
        &mut self,
        native: NativeDomainId,
        limit: usize,
    ) -> Result<(Vec<DecodedEventRecord>, bool), RawQuantumRefusal> {
        if native != self.native {
            return Err(RawQuantumRefusal::ForeignCapture);
        }
        if self.ordinary.len() > limit {
            return Err(RawQuantumRefusal::InvalidLimit);
        }
        let records = std::mem::take(&mut self.ordinary);
        self.h0_delivered += records.len();
        self.completed_delivered |= records
            .iter()
            .any(|record| record.base.event.event_type == p11scope_ebpf_common::event_type::CALL);
        let failed = self.audit.malformed_delta != 0
            || self.audit.discarded_delta != 0
            || self.audit.fault_error.is_some()
            || self.audit.fault_before != self.audit.fault_after;
        Ok((records, failed))
    }

    /// Only the actual collected-leaf capture stamps this opaque report. The
    /// original poll's fault/counter observations remain unchanged.
    pub(crate) fn note_h0_report(&mut self, report: &crate::semantic_capture::TickReport) {
        self.audit.h0_allocated_below = report.allocated_below();
        self.h0_pending = report.awaiting_floor().is_some();
    }

    // RED scaffold for native-first continuation. It remains test-only until
    // the real BEGIN-only/capacity/audit regressions execute in the batch.
    #[cfg(test)]
    fn continue_collect<S: RecordSource>(
        &mut self,
        _drain: &mut EventDrain<S>,
        _descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
        _work: usize,
        _fault: &impl FaultEpoch,
        _producers: &SessionDrainProducers,
    ) -> Result<crate::events::DispatchPoll, RawQuantumRefusal> {
        Err(RawQuantumRefusal::Unavailable)
    }

    /// Collect validated original records through the actual retained cursor.
    /// Reserve both arrays from the capture's existing pool BEFORE allocation,
    /// fault reads or polling. Refusal leaves the cursor untouched. Comparing
    /// the retained producer pair here establishes only wire custody: the
    /// existing admission-based SessionDrainGrant remains necessary for ingest.
    pub(crate) fn collect<S: RecordSource>(
        drain: &mut EventDrain<S>,
        descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
        limit: usize,
        fault: &impl FaultEpoch,
        producers: &SessionDrainProducers,
        reserve: impl FnOnce(usize) -> Result<ResourceLease, SemanticResourceRefusal>,
    ) -> Result<Self, RawQuantumRefusal> {
        if drain.domain_id() != producers.events_id() {
            return Err(RawQuantumRefusal::ForeignDrain);
        }
        if !(1..=LIVE_POLL_QUANTUM).contains(&limit) {
            return Err(RawQuantumRefusal::InvalidLimit);
        }
        let charge = reserve(Self::storage_bytes(limit)).map_err(RawQuantumRefusal::Resource)?;
        let mut ordered = Vec::new();
        let mut ordinary = Vec::new();
        let mut h0_origins = Vec::new();
        ordered
            .try_reserve_exact(limit)
            .map_err(|_| RawQuantumRefusal::Allocation)?;
        ordinary
            .try_reserve_exact(limit)
            .map_err(|_| RawQuantumRefusal::Allocation)?;
        h0_origins
            .try_reserve_exact(limit)
            .map_err(|_| RawQuantumRefusal::Allocation)?;
        let fault_before = fault.fault_epoch().map_err(RawQuantumRefusal::Fault)?;
        let malformed_before = drain.malformed();
        let discarded_before = drain.discarded();
        let ordered = RefCell::new(ordered);
        let ordinary = RefCell::new(ordinary);
        let h0_origins = RefCell::new(h0_origins);
        let journal_count = Cell::new(0u64);
        let ordinary_wire_count = Cell::new(0u64);
        drain.poll_dispatched_quantum(
            Some(limit.min(1_024)),
            descriptors,
            |record| {
                let index = ordered.borrow().len();
                h0_origins.borrow_mut().push(index);
                ordinary.borrow_mut().push(record);
                ordered
                    .borrow_mut()
                    .push(JournalIngestItem::Ordinary(record));
                ordinary_wire_count.set(ordinary_wire_count.get() + 1);
                ControlFlow::Continue(())
            },
            |record| {
                let index = ordered.borrow().len();
                if let p11scope_ebpf_common::object_journal::JournalRecord::End(end) = &record {
                    // Dispatch already validated and observed this completed
                    // payload. Copy it for H0; never fabricate an extra wire
                    // item, ordinal or trace observation.
                    if let Some(completed) =
                        crate::events::project_journal_end_payload(end, descriptors)
                    {
                        h0_origins.borrow_mut().push(index);
                        ordinary.borrow_mut().push(completed);
                    }
                }
                ordered
                    .borrow_mut()
                    .push(JournalIngestItem::Journal(record));
                journal_count.set(journal_count.get() + 1);
                ControlFlow::Continue(())
            },
        );
        let ordered = ordered.into_inner();
        let ordinary = ordinary.into_inner();
        let h0_origins = h0_origins.into_inner();
        let (fault_after, fault_error) = match fault.fault_epoch() {
            Ok(epoch) => (epoch, None),
            Err(error) => (fault_before, Some(error)),
        };
        let audit = JournalCollection {
            ingested: journal_count.get(),
            ordinary: ordinary_wire_count.get(),
            malformed_delta: drain.malformed().saturating_sub(malformed_before),
            discarded_delta: drain.discarded().saturating_sub(discarded_before),
            fault_before,
            fault_after,
            fault_error,
            drain_domain: drain.domain_id(),
            // No H0 allocation happened during raw collection. Only the actual
            // collected-leaf tick may attach its post-routing watermark.
            h0_allocated_below: 0,
        };
        Ok(Self {
            ordered,
            ordinary,
            audit,
            native: producers.native_domain(),
            h0_origins,
            h0_delivered: 0,
            completed_delivered: false,
            h0_pending: false,
            _charge: charge,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attach::capture::NativeDomainId;
    use crate::events::{EventsDomain, ScriptedRecords};
    use crate::semantics_edge::resources::{SEMANTIC_TRANSITION_SCRATCH, SemanticResourcePool};
    use p11scope_ebpf_common::Event;
    use p11scope_ebpf_common::object_wire::publish_object_descriptors;
    use std::cell::Cell;

    struct FaultProbe(Cell<u64>);
    impl FaultEpoch for FaultProbe {
        fn fault_epoch(&self) -> Result<u64, FaultReadError> {
            let epoch = self.0.get();
            self.0.set(epoch + 1);
            Ok(epoch)
        }
    }

    fn producers(events: &EventsDomain) -> SessionDrainProducers {
        SessionDrainProducers::test_pair(NativeDomainId::mint(), events.clone())
    }

    struct SteadyFault(Cell<Option<FaultReadError>>);
    impl FaultEpoch for SteadyFault {
        fn fault_epoch(&self) -> Result<u64, FaultReadError> {
            self.0.get().map_or(Ok(7), Err)
        }
    }

    struct ArrivingRecords(std::rc::Rc<RefCell<std::collections::VecDeque<Vec<u8>>>>);
    impl RecordSource for ArrivingRecords {
        fn next_record(&mut self) -> Option<impl std::ops::Deref<Target = [u8]> + '_> {
            self.0.borrow_mut().pop_front()
        }
    }

    #[test]
    fn joint_native_first_begin_idle_then_end_keeps_one_reserved_quantum() {
        use crate::semantics_objects::journal::tests::{
            ENTRY_NS, begin_bytes, end_bytes_absent, function_id,
        };
        let rows = publish_object_descriptors();
        let begin = begin_bytes(1, 1, function_id("C_Sign"), 0);
        let end = end_bytes_absent(&begin, 0, ENTRY_NS + 100);
        let queue = std::rc::Rc::new(RefCell::new(std::collections::VecDeque::from([
            begin.to_vec()
        ])));
        let events = EventsDomain::test_standin(38);
        let retained = producers(&events);
        let mut drain = EventDrain::over_domain(ArrivingRecords(queue.clone()), events);
        let pool = SemanticResourcePool::default();
        let fault = SteadyFault(Cell::new(None));
        let mut quantum =
            RawJointQuantum::collect(&mut drain, &rows, 4_096, &fault, &retained, |bytes| {
                pool.reserve(bytes)
            })
            .unwrap();
        let charged = pool.snapshot().charged_bytes;
        assert_eq!(quantum.ordered.len(), 1);
        assert_eq!(quantum.pending_h0_records(), 0);
        for _ in 0..16 {
            let idle = quantum
                .continue_collect(&mut drain, &rows, 1_024, &fault, &retained)
                .unwrap();
            assert_eq!(idle.attempted, 0);
            assert_eq!(quantum.ordered.len(), 1);
            assert_eq!(pool.snapshot().charged_bytes, charged);
        }
        // No provider timer exists in this collector. Empty ticks do not
        // manufacture an END, expiry or new raw reservation.
        queue.borrow_mut().push_back(end.to_vec());
        let returned = quantum
            .continue_collect(&mut drain, &rows, 1_024, &fault, &retained)
            .unwrap();
        assert_eq!(returned.attempted, 1);
        assert_eq!(quantum.ordered.len(), 2);
        assert_eq!(quantum.h0_origins, vec![1]);
        assert_eq!(quantum.pending_h0_records(), 1);
        assert_eq!(
            quantum.ordinary[0].base.event.event_type,
            p11scope_ebpf_common::event_type::CALL
        );
        assert_eq!(quantum.audit.ingested, 2);
        assert_eq!(quantum.audit.ordinary, 0);
        assert_eq!(pool.snapshot().charged_bytes, charged);
    }

    #[test]
    fn joint_native_first_1024_owners_do_not_fill_4096_custody_at_work_boundary() {
        use crate::semantics_objects::journal::tests::{
            ENTRY_NS, begin_bytes, end_bytes_absent, function_id,
        };
        let rows = publish_object_descriptors();
        let begins: Vec<_> = (1..=1_024)
            .map(|thread| begin_bytes(thread, 1, function_id("C_Sign"), 0))
            .collect();
        let records = begins.iter().map(|begin| begin.to_vec()).chain(
            begins
                .iter()
                .map(|begin| end_bytes_absent(begin, 0, ENTRY_NS + 100).to_vec()),
        );
        let events = EventsDomain::test_standin(39);
        let retained = producers(&events);
        let mut drain = EventDrain::over_domain(ScriptedRecords::records(records, 2_048), events);
        let pool = SemanticResourcePool::default();
        let fault = SteadyFault(Cell::new(None));
        let mut quantum =
            RawJointQuantum::collect(&mut drain, &rows, 4_096, &fault, &retained, |bytes| {
                pool.reserve(bytes)
            })
            .unwrap();
        let charged = pool.snapshot().charged_bytes;
        assert_eq!(quantum.ordered.len(), 1_024);
        assert_eq!(quantum.pending_h0_records(), 0);
        assert_eq!(drain.source().remaining(), 1_024);
        let poll = quantum
            .continue_collect(&mut drain, &rows, 1_024, &fault, &retained)
            .unwrap();
        assert_eq!(poll.attempted, 1_024);
        assert_eq!(quantum.ordered.len(), 2_048);
        assert_eq!(quantum.pending_h0_records(), 1_024);
        assert_eq!(quantum.h0_origins, (1_024..2_048).collect::<Vec<_>>());
        assert_eq!(drain.source().remaining(), 0);
        assert_eq!(quantum.audit.ingested, 2_048);
        assert_eq!(quantum.audit.ordinary, 0);
        assert_eq!(pool.snapshot().charged_bytes, charged);
    }

    #[test]
    fn joint_native_first_malformed_attempts_exhaust_capacity_without_extra_poll() {
        let rows = publish_object_descriptors();
        let events = EventsDomain::test_standin(40);
        let retained = producers(&events);
        let mut drain = EventDrain::over_domain(
            ScriptedRecords::records(vec![vec![0xff; 3]; 1_027], 1_025),
            events,
        );
        let pool = SemanticResourcePool::default();
        let fault = SteadyFault(Cell::new(None));
        let mut quantum =
            RawJointQuantum::collect(&mut drain, &rows, 1_025, &fault, &retained, |bytes| {
                pool.reserve(bytes)
            })
            .unwrap();
        assert_eq!(quantum.audit.malformed_delta, 1_024);
        assert_eq!(quantum.ordered.len(), 0);
        let poll = quantum
            .continue_collect(&mut drain, &rows, 1_024, &fault, &retained)
            .unwrap();
        assert_eq!(poll.attempted, 1);
        assert_eq!(drain.source().remaining(), 2);
        assert_eq!(quantum.audit.malformed_delta, 1_025);
        assert_eq!(quantum.pending_h0_records(), 0);
        assert!(matches!(
            quantum.continue_collect(&mut drain, &rows, 1_024, &fault, &retained),
            Err(RawQuantumRefusal::Capacity)
        ));
        assert_eq!(drain.source().remaining(), 2);
    }

    #[test]
    fn joint_native_first_later_healthy_read_cannot_erase_interpoll_failure() {
        use crate::semantics_objects::journal::tests::{begin_bytes, function_id};
        let rows = publish_object_descriptors();
        let events = EventsDomain::test_standin(41);
        let retained = producers(&events);
        let begin = begin_bytes(1, 1, function_id("C_Sign"), 0);
        let mut drain =
            EventDrain::over_domain(ScriptedRecords::records([begin.to_vec()], 1), events);
        let pool = SemanticResourcePool::default();
        let fault = SteadyFault(Cell::new(None));
        let mut quantum =
            RawJointQuantum::collect(&mut drain, &rows, 4_096, &fault, &retained, |bytes| {
                pool.reserve(bytes)
            })
            .unwrap();
        let original = (quantum.audit.fault_before, quantum.audit.fault_after);
        let charged = pool.snapshot().charged_bytes;
        fault.0.set(Some(FaultReadError::Unreadable));
        assert!(matches!(
            quantum.continue_collect(&mut drain, &rows, 1_024, &fault, &retained),
            Err(RawQuantumRefusal::Fault(FaultReadError::Unreadable))
        ));
        fault.0.set(None);
        assert_eq!(
            quantum
                .continue_collect(&mut drain, &rows, 1_024, &fault, &retained)
                .unwrap()
                .attempted,
            0
        );
        assert_eq!(
            (quantum.audit.fault_before, quantum.audit.fault_after),
            original
        );
        let (records, failed) = quantum
            .take_h0_input(retained.native_domain(), 1_024)
            .unwrap();
        assert!(records.is_empty());
        assert!(
            failed,
            "lost interpolation evidence stays failed after later healthy reads"
        );
        assert_eq!(pool.snapshot().charged_bytes, charged);
    }

    #[test]
    fn joint_raw_quantum_retains_original_dispatch_order_and_h0_records() {
        use crate::semantics_objects::journal::tests::{
            begin_bytes, end_bytes_absent, function_id, ordinary_for,
        };
        let begin = begin_bytes(1, 1, function_id("C_Sign"), 0);
        let mut ordinary = ordinary_for(&begin, 0);
        let end = end_bytes_absent(&begin, 0, ordinary.ts_ns);
        ordinary.event_type = p11scope_ebpf_common::event_type::FORK;
        let events = EventsDomain::test_standin(33);
        let mut drain = EventDrain::over_domain(
            ScriptedRecords::records(
                [
                    begin.to_vec(),
                    crate::events::event_bytes(&ordinary),
                    end.to_vec(),
                ],
                3,
            ),
            events.clone(),
        );
        let pool = SemanticResourcePool::default();
        let before = pool.snapshot().charged_bytes;
        let fault = FaultProbe(Cell::new(11));
        let quantum = RawJointQuantum::collect(
            &mut drain,
            &publish_object_descriptors(),
            3,
            &fault,
            &producers(&events),
            |bytes| pool.reserve(bytes),
        )
        .unwrap_or_else(|reason| panic!("original quantum must be retained: {reason:?}"));
        assert!(matches!(quantum.ordered[0], JournalIngestItem::Journal(_)));
        assert!(matches!(quantum.ordered[1], JournalIngestItem::Ordinary(_)));
        assert!(matches!(quantum.ordered[2], JournalIngestItem::Journal(_)));
        assert_eq!(quantum.ordinary.len(), 2);
        assert_eq!(quantum.h0_origins, vec![1, 2]);
        assert_eq!(
            quantum.ordinary[0].base.event.event_type,
            p11scope_ebpf_common::event_type::FORK
        );
        assert_eq!(
            quantum.ordinary[1].base.event.event_type,
            p11scope_ebpf_common::event_type::CALL
        );
        assert_eq!(quantum.ordinary[0].base.event.ts_ns, ordinary.ts_ns);
        assert_eq!(quantum.ordinary[0].base.event.pid_tgid, ordinary.pid_tgid);
        assert_eq!(quantum.audit.ingested, 2);
        assert_eq!(quantum.audit.ordinary, 1);
        assert_eq!(
            (quantum.audit.fault_before, quantum.audit.fault_after),
            (11, 12)
        );
        assert_eq!(quantum.audit.drain_domain, events.id());
        assert_eq!(quantum.audit.malformed_delta, 0);
        assert_eq!(drain.source().remaining(), 0);
        assert_eq!(
            pool.snapshot().charged_bytes,
            before + RawJointQuantum::storage_bytes(3)
        );
        drop(quantum);
        assert_eq!(pool.snapshot().charged_bytes, before);
    }

    #[test]
    fn joint_raw_quantum_shared_pool_refuses_before_poll_and_holds_exact_bound() {
        let bytes = RawJointQuantum::storage_bytes(1);
        for spare in [bytes - 1, bytes] {
            let pool = SemanticResourcePool::reference_limit(SEMANTIC_TRANSITION_SCRATCH + spare);
            let events = EventsDomain::test_standin(34);
            let mut drain = EventDrain::over_domain(
                ScriptedRecords::events([Event::default(), Event::default()], 1),
                events.clone(),
            );
            let fault = FaultProbe(Cell::new(20));
            let outcome = RawJointQuantum::collect(
                &mut drain,
                &publish_object_descriptors(),
                1,
                &fault,
                &producers(&events),
                |requested| pool.reserve(requested),
            );
            if spare < bytes {
                assert!(matches!(outcome, Err(RawQuantumRefusal::Resource(_))));
                assert_eq!(drain.source().remaining(), 2);
                assert_eq!(fault.0.get(), 20, "refusal precedes even fault I/O");
            } else {
                let quantum = outcome.unwrap_or_else(|reason| panic!("N must fit: {reason:?}"));
                assert_eq!(quantum.ordinary.len(), 1);
                assert_eq!(drain.source().remaining(), 1);
                assert_eq!(
                    pool.snapshot().charged_bytes,
                    SEMANTIC_TRANSITION_SCRATCH + bytes
                );
                drop(quantum);
                assert_eq!(pool.snapshot().charged_bytes, SEMANTIC_TRANSITION_SCRATCH);
            }
        }
    }

    #[test]
    fn joint_raw_quantum_foreign_drain_refuses_without_reserve_or_poll() {
        let actual = EventsDomain::test_standin(35);
        let foreign = EventsDomain::test_standin(36);
        let mut drain =
            EventDrain::over_domain(ScriptedRecords::events([Event::default()], 1), actual);
        let fault = FaultProbe(Cell::new(30));
        let outcome = RawJointQuantum::collect(
            &mut drain,
            &publish_object_descriptors(),
            1,
            &fault,
            &producers(&foreign),
            |_| panic!("foreign raw custody cannot reserve"),
        );
        assert!(matches!(outcome, Err(RawQuantumRefusal::ForeignDrain)));
        assert_eq!(fault.0.get(), 30);
        assert_eq!(drain.source().remaining(), 1);
    }

    #[test]
    fn joint_raw_quantum_keeps_original_malformed_audit_without_repoll() {
        let events = EventsDomain::test_standin(37);
        let mut drain = EventDrain::over_domain(
            ScriptedRecords::records(
                [vec![0xff; 3], crate::events::event_bytes(&Event::default())],
                2,
            ),
            events.clone(),
        );
        let pool = SemanticResourcePool::default();
        let fault = FaultProbe(Cell::new(40));
        let quantum = RawJointQuantum::collect(
            &mut drain,
            &publish_object_descriptors(),
            2,
            &fault,
            &producers(&events),
            |bytes| pool.reserve(bytes),
        )
        .unwrap_or_else(|reason| {
            panic!("malformed prefix still retains consumed truth: {reason:?}")
        });
        assert_eq!(quantum.ordinary.len(), 1);
        assert_eq!(quantum.audit.malformed_delta, 1);
        assert_eq!(
            (quantum.audit.fault_before, quantum.audit.fault_after),
            (40, 41)
        );
        assert_eq!(drain.source().remaining(), 0);
        assert_eq!(drain.malformed(), 1);
    }
}
