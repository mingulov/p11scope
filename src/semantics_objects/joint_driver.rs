//! SPDX-License-Identifier: GPL-3.0-or-later
//! Retained, bounded wire custody for one production Joint quantum.
//!
//! Raw custody is not admission, bootstrap or drain-binding authority.

use super::ledger::{ExistingReservation, LedgerGeneration};
use super::{
    FaultEpoch, FaultReadError, JournalAdapter, JournalCollection, JournalIngestItem,
    JournalLimits, JournalNativeKey, OpenEntry, SessionDrainGrant, StagingLedger,
    end_agrees_with_begin,
};
use crate::attach::SessionDrainProducers;
use crate::attach::capture::NativeDomainId;
use crate::events::{DecodedEventRecord, EventDrain, LIVE_POLL_QUANTUM, RecordSource};
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SemanticResourceRefusal, SemanticResourceReserver,
};
use crate::semantics_objects::ObjectSemantics;
use p11scope_ebpf_common::MAX_DESCRIPTORS;
use p11scope_ebpf_common::object_journal::{JournalRecord, ValidatedJournalBegin};
use p11scope_ebpf_common::object_wire::ObjectDescriptorWire;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_RAW_QUANTUM: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RawQuantumIdentity(u64);

/// Immutable resource provenance from the actual retained END projection.
/// It grants no attribution, H0 position, admission, birth or seal authority.
/// Only the collector below constructs one after pairing the actual decoded
/// END with its retained original BEGIN under one Session/native/EVENTS tuple.
#[derive(Clone, Copy)]
pub(crate) struct JointResourceOrigin {
    reservation: ExistingReservation,
    native: NativeDomainId,
    events: u64,
    invocation: (u64, u64),
}

impl JointResourceOrigin {
    pub(crate) fn matches_native(&self, native: NativeDomainId) -> bool {
        self.native == native
    }
    pub(super) fn reservation(&self) -> &ExistingReservation {
        &self.reservation
    }
    pub(super) fn matches_producers(&self, producers: &SessionDrainProducers) -> bool {
        self.native == producers.native_domain() && self.events == producers.events_id()
    }
}

impl std::fmt::Debug for JointResourceOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JointResourceOrigin(<private>)")
    }
}

/// One capture's joint owner: the capture's single journal adapter (with
/// its move-only reservation ledger) plus the capture's single object
/// model (with its retained history).
///
/// Raw collection ingests through the adapter; staged H8 opens, model
/// pending calls, staged H9 payloads and prospective key associations
/// all take tickets from the adapter's ledger; ledger-bearing
/// publications borrow that same ledger; seal delivery and projection
/// borrow the model. One ledger generation, one model, one census: a
/// release on one path frees allowance on the others, pended releases
/// flush at every ledger-bearing publication, and genuine adapter
/// origins survive the bridge into publication charges instead of
/// refusing as foreign generations. Move-only: parked/active transfer
/// moves the whole owner by value, preserving model/history identity.
/// Only ledger-bearing production publications share this ledger: the
/// ledger-less publish twin and standalone scene adapters keep their
/// own ledgers for tests. The staged H3 seal tick borrows the model;
/// publications borrow the ledger. Gating transfer on genuine stopped-A
/// completion is a separate carry; no transfer runs here.
pub(crate) struct JointCaptureOwner {
    // Field order is load-bearing: Rust drops fields in declaration
    // order, so the model (with its retained history) drops before
    // the adapter's ledger refunds its charges. Live model bytes stay
    // accounted until the storage itself is gone; declaring the
    // adapter first would refund the ledger while model storage is
    // still alive (transient underaccounting at teardown).
    model: ObjectSemantics,
    adapter: JournalAdapter,
}

impl JointCaptureOwner {
    /// Build the capture's owner over the registry's existing pool: the
    /// adapter takes policy limits with the pool's reserver behind its
    /// ledger, and the model starts empty. The ledger's table storage
    /// stays lazy: the first charge reserves it before allocating, so
    /// construction itself never refuses.
    pub(crate) fn new(limits: JournalLimits, reserver: SemanticResourceReserver) -> Self {
        Self {
            model: ObjectSemantics::new(),
            adapter: JournalAdapter::with_ledger(limits, StagingLedger::with_resources(reserver)),
        }
    }

    /// Disjoint mutable access to the capture's adapter and model: the
    /// staged seal tick wires both at once, and H9 delivery runs model
    /// calls against the adapter's mutable ledger. Splitting through
    /// the owner keeps the one-ledger/one-model identity that separate
    /// whole-owner borrows cannot lend simultaneously.
    #[cfg_attr(not(test), allow(dead_code))] // Seal-tick/H9 wiring borrows the owner once those lanes land.
    pub(crate) fn parts(&mut self) -> (&mut JournalAdapter, &mut ObjectSemantics) {
        (&mut self.adapter, &mut self.model)
    }

    /// The capture's one journal adapter (read side): raw collection
    /// binds producers and ingests through this identity.
    #[cfg_attr(not(test), allow(dead_code))] // Raw collection through the owner arrives with the capture lane.
    pub(crate) fn adapter(&self) -> &JournalAdapter {
        &self.adapter
    }

    /// The capture's one journal adapter (collection side).
    #[cfg_attr(not(test), allow(dead_code))] // Raw collection through the owner arrives with the capture lane.
    pub(crate) fn adapter_mut(&mut self) -> &mut JournalAdapter {
        &mut self.adapter
    }

    /// The capture's one reservation ledger (read side): the adapter's
    /// ledger, which every ledger-bearing publication shares.
    #[cfg_attr(not(test), allow(dead_code))] // Projection-side reads arrive with the seal tick.
    pub(crate) fn ledger(&self) -> &StagingLedger {
        self.adapter.ledger()
    }

    /// The capture's one reservation ledger (charge side): every
    /// ledger-bearing production publication borrows this, never a
    /// second ledger on that path.
    pub(crate) fn ledger_mut(&mut self) -> &mut StagingLedger {
        self.adapter.ledger_mut()
    }

    /// The capture's one object model, with its retained history (read
    /// side): seal delivery and projection borrow this identity.
    #[cfg_attr(not(test), allow(dead_code))] // Seal delivery borrows the owner once the tick lands.
    pub(crate) fn model(&self) -> &ObjectSemantics {
        &self.model
    }

    /// The capture's one object model (seal-tick side).
    #[cfg_attr(not(test), allow(dead_code))] // The staged seal tick owns the model's write side.
    pub(crate) fn model_mut(&mut self) -> &mut ObjectSemantics {
        &mut self.model
    }
}

impl std::fmt::Debug for JointCaptureOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JointCaptureOwner(<retained>)")
    }
}

struct RawInvocation {
    begin: ValidatedJournalBegin,
    reservation: ExistingReservation,
    terminal: bool,
    poisoned: bool,
    owns_raw: bool,
}

type ResourceContext<'a> = (
    &'a mut StagingLedger,
    &'a BTreeMap<JournalNativeKey, OpenEntry>,
    &'a SessionDrainProducers,
);

/// One bounded original poll. Neither the wire buffer nor its audit establishes
/// key, birth, drain-binding or H3 authority. The charge remains owned until the
/// complete quantum (including H0's physical ordinary copy) is disposed.
pub(crate) struct RawJointQuantum {
    identity: RawQuantumIdentity,
    ordered: Vec<JournalIngestItem>,
    ordinary: Vec<DecodedEventRecord>,
    audit: JournalCollection,
    native: NativeDomainId,
    descriptors: [ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
    capacity: usize,
    attempted: usize,
    malformed_seen: u64,
    discarded_seen: u64,
    h0_origins: Vec<usize>,
    h0_delivered: usize,
    completed_delivered: bool,
    h0_pending: bool,
    h0_reported: bool,
    invocations: Vec<RawInvocation>,
    ledger_generation: Option<LedgerGeneration>,
    resource_refused: bool,
    _charge: ResourceLease,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RawQuantumRefusal {
    Capacity,
    H0Active,
    ForeignDescriptors,
    ForeignDrain,
    ForeignCapture,
    ForeignLedger,
    DrainUnbound,
    H0Undelivered,
    IdentityExhausted,
    InvalidLimit,
    Resource(SemanticResourceRefusal),
    Ledger(super::LedgerRefusal),
    Allocation,
    Fault(FaultReadError),
}

impl RawJointQuantum {
    fn storage_bytes(limit: usize) -> usize {
        // All four arrays coexist. reserve_exact requests capacity once;
        // callbacks never grow them. Include each allocation's padding.
        limit
            * (size_of::<JournalIngestItem>()
                + size_of::<DecodedEventRecord>()
                + size_of::<usize>())
            + limit.min(super::MAX_UNSETTLED_STAGED) * size_of::<RawInvocation>()
            + 4 * OWNED_ALLOCATION_PADDING
            + size_of::<Self>()
    }

    pub(crate) fn matches_producers(&self, producers: &SessionDrainProducers) -> bool {
        self.native == producers.native_domain() && self.audit.drain_domain == producers.events_id()
    }

    pub(crate) fn pending_h0_records(&self) -> usize {
        self.ordinary.len()
    }

    pub(super) fn ready_for_ingest(
        &self,
        adapter: &JournalAdapter,
        producers: &SessionDrainProducers,
    ) -> Result<(), RawQuantumRefusal> {
        if !self.matches_producers(producers)
            || !adapter.resource_producers.as_ref().is_some_and(|retained| {
                retained.native_domain() == producers.native_domain()
                    && retained.events_id() == producers.events_id()
            })
        {
            return Err(RawQuantumRefusal::ForeignCapture);
        }
        if self.ledger_generation.is_none() || self.ledger_generation != adapter.ledger.generation()
        {
            return Err(RawQuantumRefusal::ForeignLedger);
        }
        if !self.h0_reported || !self.ordinary.is_empty() || self.h0_pending {
            return Err(RawQuantumRefusal::H0Undelivered);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn retained_capacities(&self) -> (usize, usize, usize) {
        (
            self.ordered.capacity(),
            self.ordinary.capacity(),
            self.h0_origins.capacity(),
        )
    }

    fn collection_failed(&self) -> bool {
        self.audit.malformed_delta != 0
            || self.audit.discarded_delta != 0
            || self.audit.counter_error
            || self.audit.fault_error.is_some()
            || self.audit.fault_before != self.audit.fault_after
    }

    /// Borrow the retained H0 inputs. The collected leaf consumes copies into
    /// its existing router, then acknowledges them with its actual report.
    /// Keeping this Vec in place preserves the original preallocation even
    /// when a lifecycle-only slice precedes the eventual completed call.
    pub(crate) fn h0_input(
        &self,
        native: NativeDomainId,
        limit: usize,
    ) -> Result<(&[DecodedEventRecord], bool), RawQuantumRefusal> {
        if native != self.native {
            return Err(RawQuantumRefusal::ForeignCapture);
        }
        if self.ordinary.len() > limit {
            return Err(RawQuantumRefusal::InvalidLimit);
        }
        Ok((&self.ordinary, self.collection_failed()))
    }

    #[cfg(test)]
    pub(crate) fn take_h0_input(
        &mut self,
        native: NativeDomainId,
        limit: usize,
    ) -> Result<(Vec<DecodedEventRecord>, bool), RawQuantumRefusal> {
        let (_, failed) = self.h0_input(native, limit)?;
        Ok((std::mem::take(&mut self.ordinary), failed))
    }

    /// Only the actual collected-leaf capture stamps this opaque report. It
    /// has processed the borrowed inputs, so retain their wire mapping while
    /// clearing their delivery buffer without releasing its capacity.
    pub(crate) fn h0_identity(&self) -> RawQuantumIdentity {
        self.identity
    }

    pub(crate) fn note_h0_report(
        &mut self,
        report: crate::semantic_capture::CollectedH0Disposition,
    ) -> Result<(), RawQuantumRefusal> {
        let (allocated_below, pending) = report
            .for_quantum(self.identity, self.native)
            .ok_or(RawQuantumRefusal::ForeignCapture)?;
        self.h0_reported = true;
        self.h0_delivered += self.ordinary.len();
        self.completed_delivered |= self
            .ordinary
            .iter()
            .any(|record| record.base.event.event_type == p11scope_ebpf_common::event_type::CALL);
        self.ordinary.clear();
        self.audit.h0_allocated_below = allocated_below;
        self.h0_pending = pending;
        Ok(())
    }

    fn observe_fault(
        &mut self,
        reading: Result<u64, FaultReadError>,
    ) -> Result<(), FaultReadError> {
        let reading = reading.and_then(|epoch| {
            if epoch > u64::from(u32::MAX) {
                Err(FaultReadError::Saturated)
            } else {
                Ok(epoch)
            }
        });
        match reading {
            Ok(epoch) => {
                // Retain the first observed change even if a later read
                // returns to the original value. Never heal a broken chain.
                if self.audit.fault_after == self.audit.fault_before {
                    self.audit.fault_after = epoch;
                }
                Ok(())
            }
            Err(error) => {
                if self.audit.fault_error.is_none() || error == FaultReadError::Saturated {
                    self.audit.fault_error = Some(error);
                }
                Err(error)
            }
        }
    }

    fn observe_counters(&mut self, malformed: u64, discarded: u64) {
        fn advance(previous: &mut u64, total: &mut u64, current: u64) -> bool {
            let delta = current.checked_sub(*previous);
            let accumulated = delta.and_then(|delta| total.checked_add(delta));
            let failed = *previous == u64::MAX || current == u64::MAX || accumulated.is_none();
            if let Some(accumulated) = accumulated {
                *total = accumulated;
            }
            *previous = current;
            failed
        }
        self.audit.counter_error |= advance(
            &mut self.malformed_seen,
            &mut self.audit.malformed_delta,
            malformed,
        );
        self.audit.counter_error |= advance(
            &mut self.discarded_seen,
            &mut self.audit.discarded_delta,
            discarded,
        );
    }

    /// Continue the SAME allocation before completed-call H0 delivery. Work
    /// is bounded independently from total custody, including failed decode
    /// attempts. A full quantum refuses without asking the cursor for N+1.
    #[cfg(test)]
    pub(crate) fn continue_collect<S: RecordSource>(
        &mut self,
        drain: &mut EventDrain<S>,
        descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
        work: usize,
        fault: &impl FaultEpoch,
        producers: &SessionDrainProducers,
    ) -> Result<crate::events::DispatchPoll, RawQuantumRefusal> {
        self.continue_collect_inner(drain, descriptors, work, fault, producers, None)
    }

    pub(crate) fn continue_collect_with_adapter<S: RecordSource>(
        &mut self,
        drain: &mut EventDrain<S>,
        descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
        work: usize,
        fault: &impl FaultEpoch,
        producers: &SessionDrainProducers,
        adapter: &mut JournalAdapter,
    ) -> Result<crate::events::DispatchPoll, RawQuantumRefusal> {
        if self.ledger_generation.is_none() || self.ledger_generation != adapter.ledger.generation()
        {
            return Err(RawQuantumRefusal::ForeignLedger);
        }
        if !adapter.bind_resource_producers(producers) {
            return Err(RawQuantumRefusal::ForeignCapture);
        }
        self.continue_collect_inner(
            drain,
            descriptors,
            work,
            fault,
            producers,
            Some((&mut adapter.ledger, &adapter.open, producers)),
        )
    }

    #[allow(clippy::too_many_arguments)] // Existing cursor plus its one retained resource owner.
    fn continue_collect_inner<S: RecordSource>(
        &mut self,
        drain: &mut EventDrain<S>,
        descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
        work: usize,
        fault: &impl FaultEpoch,
        producers: &SessionDrainProducers,
        resources: Option<ResourceContext<'_>>,
    ) -> Result<crate::events::DispatchPoll, RawQuantumRefusal> {
        if !self.matches_producers(producers) {
            return Err(RawQuantumRefusal::ForeignCapture);
        }
        if drain.domain_id() != self.audit.drain_domain {
            return Err(RawQuantumRefusal::ForeignDrain);
        }
        if descriptors != &self.descriptors {
            return Err(RawQuantumRefusal::ForeignDescriptors);
        }
        if !(1..=1_024).contains(&work) {
            return Err(RawQuantumRefusal::InvalidLimit);
        }
        if self.h0_pending || self.completed_delivered {
            return Err(RawQuantumRefusal::H0Active);
        }
        if self.attempted == self.capacity {
            return Err(RawQuantumRefusal::Capacity);
        }
        self.observe_counters(drain.malformed(), drain.discarded());
        self.observe_fault(fault.fault_epoch())
            .map_err(RawQuantumRefusal::Fault)?;
        Ok(self.poll_slice(
            drain,
            descriptors,
            work.min(self.capacity - self.attempted),
            fault,
            resources,
        ))
    }

    fn poll_slice<S: RecordSource>(
        &mut self,
        drain: &mut EventDrain<S>,
        descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
        work: usize,
        fault: &impl FaultEpoch,
        mut resources: Option<ResourceContext<'_>>,
    ) -> crate::events::DispatchPoll {
        let ordered = RefCell::new(&mut self.ordered);
        let ordinary = RefCell::new(&mut self.ordinary);
        let h0_origins = RefCell::new(&mut self.h0_origins);
        let invocations = &mut self.invocations;
        let resource_refused = &mut self.resource_refused;
        let journal_count = Cell::new(0u64);
        let ordinary_wire_count = Cell::new(0u64);
        let poll = drain.poll_dispatched_quantum(
            Some(work),
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
                let resource = resources.as_mut().and_then(|(ledger, open, producers)| {
                    Self::resource_for_record(
                        &record,
                        invocations,
                        ledger,
                        open,
                        producers,
                        resource_refused,
                    )
                });
                if let JournalRecord::End(end) = &record {
                    // Dispatch already validated and observed this completed
                    // payload. Its H0 copy is not a second wire item or tap.
                    if let Some(mut completed) =
                        crate::events::project_journal_end_payload(end, descriptors)
                    {
                        completed.joint_resource = resource;
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
        self.attempted += poll.attempted;
        self.audit.ingested += journal_count.get();
        self.audit.ordinary += ordinary_wire_count.get();
        self.observe_counters(drain.malformed(), drain.discarded());
        let _ = self.observe_fault(fault.fault_epoch());
        poll
    }

    fn resource_for_record(
        record: &JournalRecord,
        invocations: &mut Vec<RawInvocation>,
        ledger: &mut StagingLedger,
        open: &BTreeMap<JournalNativeKey, OpenEntry>,
        producers: &SessionDrainProducers,
        refused: &mut bool,
    ) -> Option<JointResourceOrigin> {
        let key = match record {
            JournalRecord::Begin(begin) => (begin.thread(), begin.sequence()),
            JournalRecord::End(end) => (end.thread(), end.sequence()),
            JournalRecord::Abandon(abandon) => (abandon.thread(), abandon.sequence()),
        };
        let current = invocations
            .iter()
            .position(|entry| (entry.begin.thread(), entry.begin.sequence()) == key);
        if let JournalRecord::Begin(begin) = record {
            if let Some(at) = current {
                invocations[at].poisoned = true;
                *refused = true;
                return None;
            }
            // A retained BEGIN is an original observation, never permission
            // to merge a newly presented duplicate with that observation.
            if open.contains_key(&key) || invocations.len() == invocations.capacity() {
                *refused = true;
                return None;
            }
            match ledger.reserve_raw(producers) {
                Ok(reservation) => invocations.push(RawInvocation {
                    begin: *begin,
                    reservation,
                    terminal: false,
                    poisoned: false,
                    owns_raw: true,
                }),
                Err(_) => *refused = true,
            }
            return None;
        }
        let at = match current {
            Some(at) => at,
            None => {
                let Some(entry) = open.get(&key) else {
                    *refused = true;
                    return None;
                };
                let Some(reservation) = entry.raw_resource else {
                    *refused = true;
                    return None;
                };
                if entry.end.is_some()
                    || entry.abandon.is_some()
                    || entry.corroborated_return.is_some()
                    || invocations.len() == invocations.capacity()
                    || !ledger.matches_reservation(&reservation)
                {
                    *refused = true;
                    return None;
                }
                invocations.push(RawInvocation {
                    begin: entry.begin,
                    reservation,
                    terminal: false,
                    poisoned: false,
                    owns_raw: false,
                });
                invocations.len() - 1
            }
        };
        let entry = &mut invocations[at];
        if entry.terminal || entry.poisoned || !ledger.matches_reservation(&entry.reservation) {
            *refused = true;
            entry.poisoned = true;
            return None;
        }
        entry.terminal = true;
        let JournalRecord::End(end) = record else {
            return None;
        };
        if entry.begin.no_end() || !end_agrees_with_begin(&entry.begin, end) {
            *refused = true;
            entry.poisoned = true;
            return None;
        }
        Some(JointResourceOrigin {
            reservation: entry.reservation,
            native: producers.native_domain(),
            events: producers.events_id(),
            invocation: key,
        })
    }

    /// Consume the original wire sequence once after actual H0 disposition.
    /// Resource custody alone never binds a drain: the caller must first mint
    /// and bind the existing admission-based grant from these SAME producers.
    /// Refusal returns the unchanged owner, including all paid buffers.
    pub(super) fn ingest(
        self,
        adapter: &mut JournalAdapter,
        producers: &SessionDrainProducers,
        grant: &SessionDrainGrant,
    ) -> Result<JournalCollection, (Self, RawQuantumRefusal)> {
        let refusal = if let Err(refusal) = self.ready_for_ingest(adapter, producers) {
            Some(refusal)
        } else if grant.domain_tag != producers.native_domain().journal_tag()
            || grant.events_id != producers.events_id()
            || adapter.drain_pins.get(&grant.domain_tag) != Some(&grant.events_id)
        {
            Some(RawQuantumRefusal::DrainUnbound)
        } else {
            None
        };
        if let Some(refusal) = refusal {
            return Err((self, refusal));
        }
        for item in &self.ordered {
            let resource = match item {
                JournalIngestItem::Journal(JournalRecord::Begin(begin)) => self
                    .invocations
                    .iter()
                    .find(|entry| entry.owns_raw && entry.begin.bytes() == begin.bytes())
                    .map(|entry| entry.reservation),
                _ => None,
            };
            adapter.ingest_any_from_raw(*item, resource);
        }
        // Preserve IDs on the stack, then actually drop every physical raw
        // copy before removing Raw memberships. The quantum's lease is last.
        let mut releases = [None; super::MAX_UNSETTLED_STAGED];
        for (slot, entry) in releases.iter_mut().zip(&self.invocations) {
            if entry.owns_raw {
                *slot = Some(entry.reservation);
            }
        }
        let audit = JournalCollection {
            resource_refused: self.resource_refused,
            ..self.audit
        };
        drop(self.ordered);
        drop(self.ordinary);
        drop(self.h0_origins);
        drop(self.invocations);
        for reservation in releases.iter().flatten() {
            adapter.ledger.release_raw(reservation);
        }
        drop(self._charge);
        Ok(audit)
    }

    /// Collect validated original records through the actual retained cursor.
    /// Reserve both arrays from the capture's existing pool BEFORE allocation,
    /// fault reads or polling. Refusal leaves the cursor untouched. Comparing
    /// the retained producer pair here establishes only wire custody: the
    /// existing admission-based SessionDrainGrant remains necessary for ingest.
    #[cfg(test)]
    pub(crate) fn collect<S: RecordSource>(
        drain: &mut EventDrain<S>,
        descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
        limit: usize,
        fault: &impl FaultEpoch,
        producers: &SessionDrainProducers,
        reserve: impl FnOnce(usize) -> Result<ResourceLease, SemanticResourceRefusal>,
    ) -> Result<Self, RawQuantumRefusal> {
        Self::collect_inner(drain, descriptors, limit, fault, producers, reserve, None)
    }

    #[allow(clippy::too_many_arguments)] // One retained cursor, pool and resource owner, no second handle.
    pub(crate) fn collect_with_adapter<S: RecordSource>(
        drain: &mut EventDrain<S>,
        descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
        limit: usize,
        fault: &impl FaultEpoch,
        producers: &SessionDrainProducers,
        reserve: impl FnOnce(usize) -> Result<ResourceLease, SemanticResourceRefusal>,
        adapter: &mut JournalAdapter,
    ) -> Result<Self, RawQuantumRefusal> {
        if drain.domain_id() != producers.events_id() {
            return Err(RawQuantumRefusal::ForeignDrain);
        }
        if !adapter.bind_resource_producers(producers) {
            return Err(RawQuantumRefusal::ForeignCapture);
        }
        if adapter.ledger.generation().is_none() {
            return Err(RawQuantumRefusal::ForeignLedger);
        }
        adapter
            .ledger
            .prepare_capacity()
            .map_err(RawQuantumRefusal::Ledger)?;
        Self::collect_inner(
            drain,
            descriptors,
            limit,
            fault,
            producers,
            reserve,
            Some((&mut adapter.ledger, &adapter.open, producers)),
        )
    }

    #[allow(clippy::too_many_arguments)] // Common allocation path for the marked legacy fixture and actual owner.
    fn collect_inner<S: RecordSource>(
        drain: &mut EventDrain<S>,
        descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
        limit: usize,
        fault: &impl FaultEpoch,
        producers: &SessionDrainProducers,
        reserve: impl FnOnce(usize) -> Result<ResourceLease, SemanticResourceRefusal>,
        resources: Option<ResourceContext<'_>>,
    ) -> Result<Self, RawQuantumRefusal> {
        if drain.domain_id() != producers.events_id() {
            return Err(RawQuantumRefusal::ForeignDrain);
        }
        if !(1..=LIVE_POLL_QUANTUM).contains(&limit) {
            return Err(RawQuantumRefusal::InvalidLimit);
        }
        let identity = NEXT_RAW_QUANTUM
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                last.checked_add(1)
            })
            .map(|last| RawQuantumIdentity(last + 1))
            .map_err(|_| RawQuantumRefusal::IdentityExhausted)?;
        let charge = reserve(Self::storage_bytes(limit)).map_err(RawQuantumRefusal::Resource)?;
        let mut ordered = Vec::new();
        let mut ordinary = Vec::new();
        let mut h0_origins = Vec::new();
        let mut invocations = Vec::new();
        ordered
            .try_reserve_exact(limit)
            .map_err(|_| RawQuantumRefusal::Allocation)?;
        ordinary
            .try_reserve_exact(limit)
            .map_err(|_| RawQuantumRefusal::Allocation)?;
        h0_origins
            .try_reserve_exact(limit)
            .map_err(|_| RawQuantumRefusal::Allocation)?;
        invocations
            .try_reserve_exact(limit.min(super::MAX_UNSETTLED_STAGED))
            .map_err(|_| RawQuantumRefusal::Allocation)?;
        // Capacity is the requested allocation, not an advisory callback
        // limit. Refuse an allocator over-reservation before touching EVENTS.
        if ordered.capacity() != limit
            || ordinary.capacity() != limit
            || h0_origins.capacity() != limit
            || invocations.capacity() != limit.min(super::MAX_UNSETTLED_STAGED)
        {
            return Err(RawQuantumRefusal::Allocation);
        }
        let fault_before = fault.fault_epoch().map_err(RawQuantumRefusal::Fault)?;
        if fault_before > u64::from(u32::MAX) {
            return Err(RawQuantumRefusal::Fault(FaultReadError::Saturated));
        }
        let malformed_seen = drain.malformed();
        let discarded_seen = drain.discarded();
        let audit = JournalCollection {
            ingested: 0,
            ordinary: 0,
            malformed_delta: 0,
            discarded_delta: 0,
            counter_error: malformed_seen == u64::MAX || discarded_seen == u64::MAX,
            resource_refused: false,
            fault_before,
            fault_after: fault_before,
            fault_error: None,
            drain_domain: drain.domain_id(),
            h0_allocated_below: 0,
        };
        let mut retained = Self {
            identity,
            ordered,
            ordinary,
            audit,
            native: producers.native_domain(),
            descriptors: *descriptors,
            capacity: limit,
            attempted: 0,
            malformed_seen,
            discarded_seen,
            h0_origins,
            h0_delivered: 0,
            completed_delivered: false,
            h0_pending: false,
            h0_reported: false,
            invocations,
            ledger_generation: resources
                .as_ref()
                .and_then(|(ledger, _, _)| ledger.generation()),
            resource_refused: false,
            _charge: charge,
        };
        retained.poll_slice(drain, descriptors, limit.min(1_024), fault, resources);
        Ok(retained)
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

    fn resource_adapter(pool: &SemanticResourcePool) -> JournalAdapter {
        JournalAdapter::with_ledger(
            crate::semantics_objects::journal::JournalLimits::policy(),
            StagingLedger::with_resources(pool.reserver()),
        )
    }

    #[test]
    fn joint_resource_1024_original_origins_share_all_five_roles_without_growth() {
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
        let events = EventsDomain::test_standin(0xf101);
        let retained = producers(&events);
        let mut drain = EventDrain::over_domain(ScriptedRecords::records(records, 2_048), events);
        let pool = SemanticResourcePool::default();
        let mut adapter = resource_adapter(&pool);
        let fault = SteadyFault(Cell::new(None));
        let mut quantum = RawJointQuantum::collect_with_adapter(
            &mut drain,
            &rows,
            4_096,
            &fault,
            &retained,
            |bytes| pool.reserve(bytes),
            &mut adapter,
        )
        .unwrap();
        assert_eq!(adapter.ledger.census(), 1_024);
        let (poll, allocations, _) = crate::test_alloc::count_allocs_during(|| {
            quantum
                .continue_collect_with_adapter(
                    &mut drain,
                    &rows,
                    1_024,
                    &fault,
                    &retained,
                    &mut adapter,
                )
                .unwrap()
        });
        assert_eq!(poll.attempted, 1_024);
        assert_eq!(allocations, 0);
        assert!(!quantum.resource_refused);
        let ((), allocations, _) = crate::test_alloc::count_allocs_during(|| {
            for (index, completed) in quantum.ordinary.iter().enumerate() {
                let origin = completed
                    .joint_resource
                    .as_ref()
                    .expect("same original END");
                assert!(origin.matches_producers(&retained));
                assert_eq!(origin.invocation, (index as u64 + 1, 1));
                let ticket = index as u64 + 1;
                adapter
                    .ledger
                    .charge_h8open_from_raw(ticket, 100, origin.reservation())
                    .unwrap();
                let h8 = adapter.ledger.h8_reservation(ticket).unwrap();
                adapter
                    .ledger
                    .charge_model_from_open(ticket, 200, &h8)
                    .unwrap();
                let staged = adapter
                    .ledger
                    .charge_collected(retained.native_domain(), ticket, 300, Some(origin))
                    .unwrap();
                adapter
                    .ledger
                    .mint_keyassoc_from_stage(400, Some(&staged))
                    .unwrap();
            }
        });
        assert_eq!(allocations, 0);
        assert_eq!(adapter.ledger.census(), 1_024);
        assert_eq!(adapter.ledger.staged(), 1_024);
        assert_eq!(quantum.audit.ingested, 2_048);
        assert_eq!(quantum.audit.ordinary, 0);
        assert_eq!(drain.source().remaining(), 0);
        // This is actual collector + actual pool/role bookkeeping. It does
        // not pretend to run H0 admission, C2, model/container allocation or
        // native Session completion; those retain separate positive gates.
    }

    #[test]
    fn joint_resource_1025_refuses_before_member_allocation_and_preserves_wire_audit() {
        use crate::semantics_objects::journal::tests::{
            ENTRY_NS, begin_bytes, end_bytes_absent, function_id,
        };
        let rows = publish_object_descriptors();
        let begins: Vec<_> = (1..=1_025)
            .map(|thread| begin_bytes(thread, 1, function_id("C_Sign"), 0))
            .collect();
        let records = begins.iter().map(|begin| begin.to_vec()).chain(
            begins[..1_024]
                .iter()
                .map(|begin| end_bytes_absent(begin, 0, ENTRY_NS + 100).to_vec()),
        );
        let events = EventsDomain::test_standin(0xf102);
        let retained = producers(&events);
        let mut drain = EventDrain::over_domain(ScriptedRecords::records(records, 2_049), events);
        let pool = SemanticResourcePool::default();
        let mut adapter = resource_adapter(&pool);
        let fault = SteadyFault(Cell::new(None));
        let mut quantum = RawJointQuantum::collect_with_adapter(
            &mut drain,
            &rows,
            4_096,
            &fault,
            &retained,
            |bytes| pool.reserve(bytes),
            &mut adapter,
        )
        .unwrap();
        let (_, allocations, _) = crate::test_alloc::count_allocs_during(|| {
            quantum
                .continue_collect_with_adapter(
                    &mut drain,
                    &rows,
                    1_024,
                    &fault,
                    &retained,
                    &mut adapter,
                )
                .unwrap();
            quantum
                .continue_collect_with_adapter(
                    &mut drain,
                    &rows,
                    1,
                    &fault,
                    &retained,
                    &mut adapter,
                )
                .unwrap();
        });
        assert_eq!(allocations, 0);
        assert!(quantum.resource_refused);
        assert_eq!(adapter.ledger.census(), 1_024);
        assert_eq!(quantum.ordinary.len(), 1_024);
        assert_eq!(quantum.audit.ingested, 2_049);
        assert_eq!(quantum.audit.ordinary, 0);
        assert_eq!(quantum.audit.malformed_delta, 0);
        assert_eq!(quantum.audit.discarded_delta, 0);
        assert!(!quantum.audit.counter_error);
        assert_eq!(drain.source().remaining(), 0);
    }

    #[test]
    fn joint_resource_duplicate_and_mismatched_terminals_mint_no_additional_origin() {
        use crate::semantics_objects::journal::tests::{
            ENTRY_NS, begin_bytes, end_bytes_absent, function_id,
        };
        let rows = publish_object_descriptors();
        for mismatch in [false, true] {
            let mut begin = begin_bytes(1, 1, function_id("C_Sign"), 0);
            let end = end_bytes_absent(&begin, 0, ENTRY_NS + 100);
            if mismatch {
                // Keep two independently valid records, but change the
                // original BEGIN's repeated session evidence.
                begin[80..88].copy_from_slice(&7u64.to_le_bytes());
            }
            let events = EventsDomain::test_standin(0xf103);
            let retained = producers(&events);
            let mut drain = EventDrain::over_domain(
                ScriptedRecords::records([begin.to_vec(), end.to_vec(), end.to_vec()], 3),
                events,
            );
            let pool = SemanticResourcePool::default();
            let mut adapter = resource_adapter(&pool);
            let quantum = RawJointQuantum::collect_with_adapter(
                &mut drain,
                &rows,
                4,
                &SteadyFault(Cell::new(None)),
                &retained,
                |bytes| pool.reserve(bytes),
                &mut adapter,
            )
            .unwrap();
            assert!(quantum.resource_refused);
            assert_eq!(quantum.ordinary.len(), 2);
            assert_eq!(quantum.ordinary[0].joint_resource.is_some(), !mismatch);
            assert!(quantum.ordinary[1].joint_resource.is_none());
            assert_eq!(adapter.ledger.census(), 1);
            assert_eq!(quantum.audit.malformed_delta, 0);
        }
    }

    #[test]
    fn joint_resource_foreign_session_events_and_ledger_refuse_before_mutation() {
        use crate::semantics_objects::journal::tests::{
            ENTRY_NS, begin_bytes, end_bytes_absent, function_id,
        };
        let rows = publish_object_descriptors();
        let begin = begin_bytes(1, 1, function_id("C_Sign"), 0);
        let end = end_bytes_absent(&begin, 0, ENTRY_NS + 100);
        let events = EventsDomain::test_standin(0xf104);
        let retained = producers(&events);
        let mut drain = EventDrain::over_domain(
            ScriptedRecords::records([begin.to_vec(), end.to_vec()], 2),
            events.clone(),
        );
        let pool = SemanticResourcePool::default();
        let mut adapter = resource_adapter(&pool);
        let fault = SteadyFault(Cell::new(None));
        let mut quantum = RawJointQuantum::collect_with_adapter(
            &mut drain,
            &rows,
            4,
            &fault,
            &retained,
            |bytes| pool.reserve(bytes),
            &mut adapter,
        )
        .unwrap();
        let origin = quantum.ordinary[0].joint_resource.unwrap();
        for foreign in [
            SessionDrainProducers::test_pair(NativeDomainId::mint(), events),
            SessionDrainProducers::test_pair(
                retained.native_domain(),
                EventsDomain::test_standin(0xf105),
            ),
        ] {
            let before = pool.snapshot().charged_bytes;
            let (result, allocations, _) = crate::test_alloc::count_allocs_during(|| {
                quantum.continue_collect_with_adapter(
                    &mut drain,
                    &rows,
                    1,
                    &fault,
                    &foreign,
                    &mut adapter,
                )
            });
            assert_eq!(result, Err(RawQuantumRefusal::ForeignCapture));
            assert_eq!(allocations, 0);
            assert_eq!(pool.snapshot().charged_bytes, before);
            assert_eq!(adapter.ledger.census(), 1);
        }
        let mut other = resource_adapter(&pool);
        let (result, allocations, _) = crate::test_alloc::count_allocs_during(|| {
            other
                .ledger
                .charge_collected(retained.native_domain(), 1, 1, Some(&origin))
        });
        assert!(matches!(
            result,
            Err(super::super::LedgerRefusal::ReplayRefused)
        ));
        assert_eq!(allocations, 0);
        assert_eq!(other.ledger.census(), 0);
        assert_eq!(quantum.audit.ingested, 2);
        assert!(!quantum.h0_reported);
        assert_eq!(
            quantum.ready_for_ingest(&adapter, &retained),
            Err(RawQuantumRefusal::H0Undelivered)
        );
    }

    #[test]
    fn joint_resource_original_open_preserves_lineage_across_raw_quanta() {
        use crate::semantics_objects::journal::tests::{
            ENTRY_NS, begin_bytes, end_bytes_absent, function_id,
        };
        let rows = publish_object_descriptors();
        let begin = begin_bytes(1, 1, function_id("C_Sign"), 0);
        let end = end_bytes_absent(&begin, 0, ENTRY_NS + 100);
        let events = EventsDomain::test_standin(0xf106);
        let retained = producers(&events);
        let pool = SemanticResourcePool::default();
        let mut adapter = resource_adapter(&pool);
        let fault = SteadyFault(Cell::new(None));
        let mut start_drain = EventDrain::over_domain(
            ScriptedRecords::records([begin.to_vec()], 1),
            events.clone(),
        );
        let start = RawJointQuantum::collect_with_adapter(
            &mut start_drain,
            &rows,
            4,
            &fault,
            &retained,
            |bytes| pool.reserve(bytes),
            &mut adapter,
        )
        .unwrap();
        let reservation = start.invocations[0].reservation;
        // Exercise resource custody only at the actual original ingest
        // helper. No H0 watermark, grant, bootstrap or seal is fabricated.
        assert_eq!(
            adapter.ingest_any_from_raw(start.ordered[0], Some(reservation)),
            super::super::JournalDisposition::BeginAdmitted
        );
        drop(start);
        adapter.ledger.release_raw(&reservation);
        assert_eq!(adapter.ledger.census(), 1);
        let mut end_drain =
            EventDrain::over_domain(ScriptedRecords::records([end.to_vec()], 1), events);
        let end = RawJointQuantum::collect_with_adapter(
            &mut end_drain,
            &rows,
            4,
            &fault,
            &retained,
            |bytes| pool.reserve(bytes),
            &mut adapter,
        )
        .unwrap();
        let origin = end.ordinary[0]
            .joint_resource
            .as_ref()
            .expect("retained original BEGIN");
        assert!(origin.matches_producers(&retained));
        assert!(!end.resource_refused);
        adapter
            .ledger
            .charge_collected(retained.native_domain(), 1, 10, Some(origin))
            .unwrap();
        assert_eq!(adapter.ledger.census(), 1);
        assert_eq!(adapter.ledger.staged(), 1);
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
    fn joint_native_first_foreign_continuation_is_nonconsuming() {
        use crate::semantics_objects::journal::tests::{begin_bytes, function_id};
        let rows = publish_object_descriptors();
        let begin = begin_bytes(1, 1, function_id("C_Sign"), 0);
        let events = EventsDomain::test_standin(42);
        let retained = producers(&events);
        let queue = std::rc::Rc::new(RefCell::new(std::collections::VecDeque::new()));
        let mut drain = EventDrain::over_domain(ArrivingRecords(queue.clone()), events.clone());
        let fault = SteadyFault(Cell::new(None));
        let pool = SemanticResourcePool::default();
        let mut quantum =
            RawJointQuantum::collect(&mut drain, &rows, 4, &fault, &retained, |bytes| {
                pool.reserve(bytes)
            })
            .unwrap();
        queue.borrow_mut().push_back(begin.to_vec());
        let stranger = producers(&events);
        assert_eq!(
            quantum.continue_collect(&mut drain, &rows, 1, &fault, &stranger),
            Err(RawQuantumRefusal::ForeignCapture)
        );
        let mut changed_rows = rows;
        changed_rows[0].guard ^= 1;
        assert_eq!(
            quantum.continue_collect(&mut drain, &changed_rows, 1, &fault, &retained),
            Err(RawQuantumRefusal::ForeignDescriptors)
        );
        let foreign_events = EventsDomain::test_standin(43);
        let mut foreign_drain =
            EventDrain::over_domain(ArrivingRecords(queue.clone()), foreign_events);
        assert_eq!(
            quantum.continue_collect(&mut foreign_drain, &rows, 1, &fault, &retained),
            Err(RawQuantumRefusal::ForeignDrain)
        );
        for work in [0, 1_025] {
            assert_eq!(
                quantum.continue_collect(&mut drain, &rows, work, &fault, &retained),
                Err(RawQuantumRefusal::InvalidLimit)
            );
        }
        assert_eq!(queue.borrow().len(), 1);
        assert_eq!(quantum.attempted, 0);
        assert_eq!(
            quantum
                .continue_collect(&mut drain, &rows, 1, &fault, &retained)
                .unwrap()
                .attempted,
            1
        );
        assert_eq!(quantum.ordered.len(), 1);
        assert!(queue.borrow().is_empty());
    }

    #[test]
    fn joint_native_first_changed_and_saturated_faults_stay_failed() {
        struct MutableFault(Cell<u64>);
        impl FaultEpoch for MutableFault {
            fn fault_epoch(&self) -> Result<u64, FaultReadError> {
                Ok(self.0.get())
            }
        }
        for saturated in [false, true] {
            let rows = publish_object_descriptors();
            let events = EventsDomain::test_standin(44);
            let retained = producers(&events);
            let mut drain = EventDrain::over_domain(ScriptedRecords::records([], 0), events);
            let fault = MutableFault(Cell::new(7));
            let pool = SemanticResourcePool::default();
            let mut quantum =
                RawJointQuantum::collect(&mut drain, &rows, 4, &fault, &retained, |bytes| {
                    pool.reserve(bytes)
                })
                .unwrap();
            fault.0.set(if saturated { u64::MAX } else { 8 });
            let changed = quantum.continue_collect(&mut drain, &rows, 1, &fault, &retained);
            if saturated {
                assert_eq!(
                    changed,
                    Err(RawQuantumRefusal::Fault(FaultReadError::Saturated))
                );
            } else {
                assert_eq!(changed.unwrap().attempted, 0);
                assert_eq!(quantum.audit.fault_after, 8);
            }
            fault.0.set(7);
            assert_eq!(
                quantum
                    .continue_collect(&mut drain, &rows, 1, &fault, &retained)
                    .unwrap()
                    .attempted,
                0
            );
            assert!(quantum.collection_failed());
            assert_eq!(quantum.audit.fault_before, 7);
            if saturated {
                assert_eq!(quantum.audit.fault_error, Some(FaultReadError::Saturated));
            }
        }
    }

    #[test]
    fn joint_native_first_counter_regression_saturation_and_discard_only_are_explicit() {
        struct CounterSource(std::rc::Rc<Cell<u64>>);
        impl RecordSource for CounterSource {
            fn next_record(&mut self) -> Option<impl std::ops::Deref<Target = [u8]> + '_> {
                None::<Vec<u8>>
            }
            fn discarded(&self) -> u64 {
                self.0.get()
            }
        }
        for (initial, later, expected_error, delta) in [
            (2, 2, false, 0),
            (2, 3, false, 1),
            (2, 1, true, 0),
            (u64::MAX, u64::MAX, true, 0),
            (0, u64::MAX, true, u64::MAX),
        ] {
            let rows = publish_object_descriptors();
            let events = EventsDomain::test_standin(45);
            let retained = producers(&events);
            let counter = std::rc::Rc::new(Cell::new(initial));
            let mut drain = EventDrain::over_domain(CounterSource(counter.clone()), events);
            let fault = SteadyFault(Cell::new(None));
            let pool = SemanticResourcePool::default();
            let mut quantum =
                RawJointQuantum::collect(&mut drain, &rows, 4, &fault, &retained, |bytes| {
                    pool.reserve(bytes)
                })
                .unwrap();
            counter.set(later);
            assert_eq!(
                quantum
                    .continue_collect(&mut drain, &rows, 1, &fault, &retained)
                    .unwrap()
                    .attempted,
                0
            );
            assert_eq!(
                quantum.audit.malformed_delta, 0,
                "an unprovable counter is not an invented malformed record"
            );
            assert_eq!(quantum.audit.discarded_delta, delta);
            assert_eq!(quantum.audit.counter_error, expected_error);
            let mut finalizer = crate::semantics_objects::journal::ScriptedH3Source::once(
                crate::semantics_objects::journal::H3DispositionEvidence::scripted_clean(1),
            );
            let receipt = crate::semantics_objects::journal::JournalAuditReceipt::collect(
                &quantum.audit,
                &mut finalizer,
                1,
            );
            let checked = receipt.check(None, 0, 1, &Ok(7));
            assert_eq!(
                checked,
                if expected_error {
                    Err(crate::semantics_objects::journal::JournalGap::CounterUnprovable)
                } else if delta != 0 {
                    Err(crate::semantics_objects::journal::JournalGap::Discarded)
                } else {
                    Ok(())
                }
            );
            counter.set(2);
            quantum
                .continue_collect(&mut drain, &rows, 1, &fault, &retained)
                .unwrap();
            assert_eq!(quantum.audit.counter_error, expected_error || later > 2);
            assert_eq!(quantum.audit.malformed_delta, 0);
        }
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

    /// The owner's disjoint split lends the adapter and the model at
    /// once: the H9 delivery shape (a model call against the adapter's
    /// mutable ledger) compiles and accounts through the one ledger.
    /// Separate whole-owner borrows cannot express this pair.
    #[test]
    fn joint_capture_owner_parts_lends_disjoint_adapter_and_model() {
        use crate::kinds::function_id;
        use crate::semantics_objects::{
            CallKey, HandleInput, LostOutcome, MechanismEvidence, ObjectDomain, OriginFact, RefCut,
            SlotScope,
        };

        let pool = SemanticResourcePool::default();
        let mut owner = JointCaptureOwner::new(
            crate::semantics_objects::journal::JournalLimits::policy(),
            pool.reserver(),
        );
        let (adapter, model) = owner.parts();
        let domain = ObjectDomain::reference(11, 12, 13, 14, 1);
        model
            .register_domain(domain)
            .expect("reference domain registers");
        let origin = OriginFact {
            domain,
            cut: RefCut::reference(1),
            key: CallKey::reference(1),
            entry_ns: 100,
            function: function_id("C_CreateObject").expect("known function"),
            session: HandleInput::Absent,
            inputs: [HandleInput::Absent, HandleInput::Absent],
            requested: [None, None],
            entry_mechanism: MechanismEvidence::NotCaptured,
            scope: SlotScope::Unknown,
        };
        let token = model
            .begin(origin, adapter.ledger_mut())
            .expect("begin admits against the owner's ledger");
        assert_eq!(
            adapter.ledger().census(),
            1,
            "the model charge lands in the owner's ledger"
        );
        assert!(
            adapter.ledger().charged_bytes() > 0,
            "admitted model storage is accounted"
        );
        // The lost-outcome bound releases the same pending call through
        // the same split borrow; the model and ledger stay consistent.
        let _ = model.outcome_lost(
            LostOutcome::Ticket(token, RefCut::reference(2)),
            adapter.ledger_mut(),
        );
        assert_eq!(adapter.ledger().census(), 0);
        assert_eq!(adapter.ledger().charged_bytes(), 0);
    }

    /// A populated owner's teardown keeps storage accounted until the
    /// storage itself is released, then refunds the pool exactly once.
    /// Field order (model before adapter) keeps the ledger alive across
    /// model teardown; the drop below pins the full refund.
    #[test]
    fn joint_capture_owner_populated_drop_refunds_pool_exactly_once() {
        use crate::kinds::function_id;
        use crate::semantics_objects::{
            CallKey, HandleInput, MechanismEvidence, ObjectDomain, OriginFact, RefCut, SlotScope,
        };

        let pool = SemanticResourcePool::default();
        let baseline = pool.snapshot().charged_bytes;
        let mut owner = JointCaptureOwner::new(
            crate::semantics_objects::journal::JournalLimits::policy(),
            pool.reserver(),
        );
        {
            let (adapter, model) = owner.parts();
            let domain = ObjectDomain::reference(21, 22, 23, 24, 1);
            model
                .register_domain(domain)
                .expect("reference domain registers");
            let origin = OriginFact {
                domain,
                cut: RefCut::reference(1),
                key: CallKey::reference(1),
                entry_ns: 100,
                function: function_id("C_CreateObject").expect("known function"),
                session: HandleInput::Absent,
                inputs: [HandleInput::Absent, HandleInput::Absent],
                requested: [None, None],
                entry_mechanism: MechanismEvidence::NotCaptured,
                scope: SlotScope::Unknown,
            };
            model
                .begin(origin, adapter.ledger_mut())
                .expect("begin admits against the owner's ledger");
        }
        assert_eq!(
            owner.ledger().census(),
            1,
            "live model storage stays accounted before teardown"
        );
        assert!(
            owner.ledger().charged_bytes() > 0,
            "live model bytes stay charged before teardown"
        );
        assert!(
            pool.snapshot().charged_bytes > baseline,
            "the pool holds the owner's charges while it lives"
        );
        drop(owner);
        assert_eq!(
            pool.snapshot().charged_bytes,
            baseline,
            "teardown refunds every owner charge exactly once"
        );
    }
}
