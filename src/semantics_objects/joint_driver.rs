//! SPDX-License-Identifier: GPL-3.0-or-later
//! Retained, bounded wire custody for one production Joint quantum.
//!
//! Raw custody is not admission, bootstrap or drain-binding authority.

#[cfg(test)]
mod tests {
    use super::super::{FaultEpoch, FaultReadError, JournalCollection, JournalIngestItem};
    use crate::attach::SessionDrainProducers;
    use crate::attach::capture::NativeDomainId;
    use crate::events::{DecodedEventRecord, EventDrain, EventsDomain, ScriptedRecords};
    use crate::semantics_edge::resources::{
        OWNED_ALLOCATION_PADDING, ResourceLease, SEMANTIC_TRANSITION_SCRATCH, SemanticResourcePool,
        SemanticResourceRefusal,
    };
    use p11scope_ebpf_common::object_wire::{ObjectDescriptorWire, publish_object_descriptors};
    use p11scope_ebpf_common::{Event, MAX_DESCRIPTORS};
    use std::cell::Cell;

    // Compile-safe RED scaffold for the absent production collection port.
    // It is replaced only after the intended failures execute. No production
    // collector or authority path uses this unavailable test implementation.
    struct RawJointQuantum {
        ordered: Vec<JournalIngestItem>,
        ordinary: Vec<DecodedEventRecord>,
        audit: JournalCollection,
        _charge: ResourceLease,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum RawQuantumRefusal {
        Unavailable,
        ForeignDrain,
        Resource(SemanticResourceRefusal),
    }

    impl RawJointQuantum {
        fn storage_bytes(limit: usize) -> usize {
            limit * (size_of::<JournalIngestItem>() + size_of::<DecodedEventRecord>())
                + 2 * OWNED_ALLOCATION_PADDING
        }

        #[allow(clippy::too_many_arguments)]
        fn collect(
            _drain: &mut EventDrain<ScriptedRecords>,
            _descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
            _limit: usize,
            _fault: &impl FaultEpoch,
            _producers: &SessionDrainProducers,
            _reserve: impl FnOnce(usize) -> Result<ResourceLease, SemanticResourceRefusal>,
        ) -> Result<Self, RawQuantumRefusal> {
            Err(RawQuantumRefusal::Unavailable)
        }
    }

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
