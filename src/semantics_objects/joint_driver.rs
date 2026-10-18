//! SPDX-License-Identifier: GPL-3.0-or-later
//! Retained, bounded wire custody for one production Joint quantum.
//!
//! Raw custody is not admission, bootstrap or drain-binding authority.

use super::{FaultEpoch, FaultReadError, JournalCollection, JournalIngestItem};
use crate::attach::SessionDrainProducers;
use crate::events::{DecodedEventRecord, EventDrain, LIVE_POLL_QUANTUM, RecordSource};
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SemanticResourceRefusal,
};
use p11scope_ebpf_common::MAX_DESCRIPTORS;
use p11scope_ebpf_common::object_wire::ObjectDescriptorWire;
use std::cell::RefCell;
use std::ops::ControlFlow;

/// One bounded original poll. Neither the wire buffer nor its audit establishes
/// key, birth, drain-binding or H3 authority. The charge remains owned until the
/// complete quantum (including H0's physical ordinary copy) is disposed.
pub(crate) struct RawJointQuantum {
    ordered: Vec<JournalIngestItem>,
    ordinary: Vec<DecodedEventRecord>,
    audit: JournalCollection,
    _charge: ResourceLease,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RawQuantumRefusal {
    ForeignDrain,
    InvalidLimit,
    Resource(SemanticResourceRefusal),
    Allocation,
    Fault(FaultReadError),
}

impl RawJointQuantum {
    fn storage_bytes(limit: usize) -> usize {
        // Both arrays coexist. reserve_exact requests these capacities once;
        // callbacks never grow either array. Include each allocation's padding.
        limit * (size_of::<JournalIngestItem>() + size_of::<DecodedEventRecord>())
            + 2 * OWNED_ALLOCATION_PADDING
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
        ordered
            .try_reserve_exact(limit)
            .map_err(|_| RawQuantumRefusal::Allocation)?;
        ordinary
            .try_reserve_exact(limit)
            .map_err(|_| RawQuantumRefusal::Allocation)?;
        let fault_before = fault.fault_epoch().map_err(RawQuantumRefusal::Fault)?;
        let malformed_before = drain.malformed();
        let discarded_before = drain.discarded();
        let ordered = RefCell::new(ordered);
        drain.poll_dispatched_records(
            Some(limit),
            descriptors,
            |record| {
                ordinary.push(record);
                ordered
                    .borrow_mut()
                    .push(JournalIngestItem::Ordinary(record));
                ControlFlow::Continue(())
            },
            |record| {
                ordered
                    .borrow_mut()
                    .push(JournalIngestItem::Journal(record));
                ControlFlow::Continue(())
            },
        );
        let ordered = ordered.into_inner();
        let (fault_after, fault_error) = match fault.fault_epoch() {
            Ok(epoch) => (epoch, None),
            Err(error) => (fault_before, Some(error)),
        };
        let audit = JournalCollection {
            ingested: (ordered.len() - ordinary.len()) as u64,
            ordinary: ordinary.len() as u64,
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

    #[test]
    fn joint_raw_quantum_retains_original_dispatch_order_and_h0_records() {
        use crate::semantics_objects::journal::tests::{
            begin_bytes, end_bytes_absent, function_id, ordinary_for,
        };
        let begin = begin_bytes(1, 1, function_id("C_Sign"), 0);
        let ordinary = ordinary_for(&begin, 0);
        let end = end_bytes_absent(&begin, 0, ordinary.ts_ns);
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
        assert_eq!(quantum.ordinary.len(), 1);
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
