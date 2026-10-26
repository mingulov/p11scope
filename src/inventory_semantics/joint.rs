//! SPDX-License-Identifier: GPL-3.0-or-later
//! Scope-bound borrows of one live Joint lane; no additional retained owner.
#![cfg_attr(not(test), allow(dead_code))] // The following machine slice supplies these borrows.

use super::{
    AttestedSemanticLane, LiveLane, PendingH3Continuation, RefreshReceiptStash, SemanticCapture,
    SemanticRefusal,
};
use crate::attach::{AttachedSemanticSet, BirthObservationRefusal, Session, SessionDrainProducers};
use crate::discovery::caller_registry::instance_input::JointFeedTarget;
use crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding;
use crate::semantic_capture::{
    CommittedAbsenceBirth, CurrentPartitionReceipt, RetainedBirthWitness,
};
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SemanticResourceReserver,
};
use crate::semantics_objects::journal::joint_audit::JointBirthEvidenceSource;
use crate::semantics_objects::journal::{FaultEpoch, FaultReadError, SessionBirthEvidence};
use std::borrow::Borrow;
use std::cell::RefCell;

mod machine;
#[cfg(test)]
pub(crate) use machine::JointMachineIo;
#[cfg(test)]
pub(crate) use machine::StagingDetail;
pub(crate) use machine::{
    JOINT_FINISH_NO_PROGRESS_TIMEOUT, JOINT_FINISH_SETTLE_TIMEOUT, JointCommitRefusal,
    JointServiceMode, JointServiceProgress, JointWorkBudget, LiveJointMachine,
};

/// One original negative or completed witness in the SAME paid allocation.
/// Pending entries have no receipt and cannot implement Borrow<witness>.
#[allow(clippy::large_enum_variant)] // Both move-only originals stay inline in the same paid entry.
enum RetainedBirth {
    PendingAbsence(CommittedAbsenceBirth),
    Ready(RetainedBirthWitness),
}

pub(crate) struct RetainedJointBirth {
    birth: RetainedBirth,
    nested_bytes: usize,
    _storage: ResourceLease,
}
impl RetainedJointBirth {
    fn ready(&self) -> Option<&RetainedBirthWitness> {
        match &self.birth {
            RetainedBirth::Ready(witness) => Some(witness),
            RetainedBirth::PendingAbsence(_) => None,
        }
    }
}

/// Container capacity and each heterogeneous original's nested bytes are
/// paid before acquisition/New moves. Replacing Pending with Ready keeps
/// the old original and lease until native consumption actually occurs.
#[derive(Default)]
pub(crate) struct RetainedJointBirths {
    witnesses: Vec<RetainedJointBirth>,
    capacity_storage: Option<ResourceLease>,
}
pub(crate) struct RetainedBirthSlot<'a> {
    owner: &'a mut RetainedJointBirths,
    pending: Option<usize>,
    nested_limit: usize,
    storage: ResourceLease,
    // The consumed negative's allocations stay charged across native I/O.
    _pending_storage: Option<ResourceLease>,
}
impl RetainedJointBirths {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[RetainedJointBirth] {
        &self.witnesses
    }

    fn capacity_charge(capacity: usize) -> Option<usize> {
        capacity
            .checked_mul(std::mem::size_of::<RetainedJointBirth>())?
            .checked_add(OWNED_ALLOCATION_PADDING)?
            .checked_add(std::mem::size_of::<Self>())
    }

    pub(crate) fn reserve_for(
        &mut self,
        reserve: &SemanticResourceReserver,
        nested_bytes: usize,
    ) -> Result<RetainedBirthSlot<'_>, ()> {
        self.reserve_at(reserve, nested_bytes, None)
    }

    pub(crate) fn reserve_for_current(
        &mut self,
        reserve: &SemanticResourceReserver,
        current: &CurrentPartitionReceipt,
    ) -> Result<RetainedBirthSlot<'_>, ()> {
        let pending = self.witnesses.iter().position(|entry| {
            matches!(&entry.birth, RetainedBirth::PendingAbsence(negative)
                if negative.matches_current(current))
        });
        self.reserve_at(reserve, current.owned_storage_bytes().ok_or(())?, pending)
    }

    fn reserve_at(
        &mut self,
        reserve: &SemanticResourceReserver,
        nested_bytes: usize,
        pending: Option<usize>,
    ) -> Result<RetainedBirthSlot<'_>, ()> {
        let storage = reserve.reserve(nested_bytes).map_err(|_| ())?;
        if pending.is_none() && self.witnesses.len() == self.witnesses.capacity() {
            let next = self.witnesses.capacity().checked_mul(2).ok_or(())?.max(1);
            if next > crate::discovery::caller_registry::instance_input::MAX_REGISTRY_INSTANCES {
                return Err(());
            }
            // Full replacement is reserved while the old physical allocation
            // and its charge are live, before either reallocation or query.
            let capacity_storage = reserve
                .reserve(Self::capacity_charge(next).ok_or(())?)
                .map_err(|_| ())?;
            self.witnesses
                .try_reserve_exact(next - self.witnesses.len())
                .map_err(|_| ())?;
            assert!(
                self.witnesses.capacity() <= next,
                "retained birth capacity exceeds its precharge"
            );
            self.capacity_storage = Some(capacity_storage);
        }
        Ok(RetainedBirthSlot {
            owner: self,
            pending,
            nested_limit: nested_bytes,
            storage,
            _pending_storage: None,
        })
    }

    pub(crate) fn subject_at(
        &self,
        at: usize,
        binding: &SemanticCallerBinding,
        pins: &crate::discovery::identity::PinnedObjects,
        object: crate::discovery::identity::PinnedObjectId,
    ) -> Option<bool> {
        Some(match &self.witnesses.get(at)?.birth {
            RetainedBirth::PendingAbsence(negative) => {
                negative.matches_binding_target(binding, pins, object)
            }
            RetainedBirth::Ready(witness) => witness.matches_binding_target(binding, pins, object),
        })
    }

    #[cfg(test)]
    fn contains_subject(
        &self,
        binding: &SemanticCallerBinding,
        pins: &crate::discovery::identity::PinnedObjects,
        object: crate::discovery::identity::PinnedObjectId,
    ) -> bool {
        (0..self.witnesses.len()).any(|at| self.subject_at(at, binding, pins, object) == Some(true))
    }

    pub(crate) fn order_for_native_reads(&mut self) {
        self.witnesses.sort_unstable_by_key(|entry| {
            (
                entry.ready().is_none(),
                entry.ready().map(|witness| witness.receipt().domain()),
            )
        });
    }

    /// Borrow only an exact completed original. Pending has no receipt or
    /// domain and is outside this binary search, including mixed tables.
    pub(crate) fn find_ready(&self, target: &JointFeedTarget) -> Option<&RetainedBirthWitness> {
        let ready = self
            .witnesses
            .partition_point(|entry| entry.ready().is_some());
        let at = self.witnesses[..ready]
            .binary_search_by_key(&target.bootstrap().domain(), |entry| {
                entry.ready().expect("the ready prefix").receipt().domain()
            })
            .ok()?;
        let witness = self.witnesses[at].ready()?;
        (witness.receipt() == target.bootstrap()).then_some(witness)
    }

    #[cfg(test)]
    pub(crate) fn pending_for_test(&self) -> impl Iterator<Item = &CommittedAbsenceBirth> {
        self.witnesses
            .iter()
            .filter_map(|entry| match &entry.birth {
                RetainedBirth::PendingAbsence(negative) => Some(negative),
                RetainedBirth::Ready(_) => None,
            })
    }

    #[cfg(test)]
    pub(crate) fn ready_for_test(&self) -> impl Iterator<Item = &RetainedBirthWitness> {
        self.witnesses.iter().filter_map(RetainedJointBirth::ready)
    }

    #[cfg(test)]
    pub(crate) fn next_allocation_for_test(&self, nested: usize) -> Option<(usize, usize, usize)> {
        if self.witnesses.len() != self.witnesses.capacity() {
            return None;
        }
        let next = self.witnesses.capacity().checked_mul(2)?.max(1);
        Some((
            self.capacity_storage.as_ref().map_or(Some(0), |_| {
                Self::capacity_charge(self.witnesses.capacity())
            })?,
            Self::capacity_charge(next)?,
            nested,
        ))
    }

    #[cfg(test)]
    pub(crate) fn retained_storage_for_test(&self) -> usize {
        let capacity = self.capacity_storage.as_ref().map_or(0, |_| {
            Self::capacity_charge(self.witnesses.capacity()).expect("the actual reserved capacity")
        });
        self.witnesses.iter().fold(capacity, |bytes, entry| {
            bytes
                .checked_add(entry.nested_bytes)
                .expect("bounded actual resource leases")
        })
    }
}
impl RetainedBirthSlot<'_> {
    pub(crate) fn accepts(&self, witness: &RetainedBirthWitness) -> bool {
        witness
            .owned_storage_bytes()
            .is_some_and(|bytes| bytes <= self.nested_limit)
            && (self.pending.is_some()
                || self.owner.witnesses.len() < self.owner.witnesses.capacity())
    }

    /// Called only AFTER registry reservation and candidate extraction. A
    /// storage refusal before this point leaves the original negative in place.
    pub(crate) fn take_absence(&mut self) -> Option<CommittedAbsenceBirth> {
        let at = self.pending.take()?;
        let entry = self.owner.witnesses.swap_remove(at);
        let RetainedBirth::PendingAbsence(negative) = entry.birth else {
            unreachable!("the lexical slot selected an original negative")
        };
        self._pending_storage = Some(entry._storage);
        Some(negative)
    }

    pub(crate) fn retain(self, witness: RetainedBirthWitness) {
        assert!(
            self.accepts(&witness),
            "original witness storage was precharged before installation"
        );
        self.owner.witnesses.push(RetainedJointBirth {
            birth: RetainedBirth::Ready(witness),
            nested_bytes: self.nested_limit,
            _storage: self.storage,
        });
    }

    #[allow(clippy::result_large_err)] // Refusal returns the original negative without another allocation.
    pub(crate) fn retain_absence(
        self,
        negative: CommittedAbsenceBirth,
    ) -> Result<(), CommittedAbsenceBirth> {
        if self.pending.is_some()
            || negative
                .owned_storage_bytes()
                .is_none_or(|bytes| bytes > self.nested_limit)
            || self.owner.witnesses.len() == self.owner.witnesses.capacity()
        {
            return Err(negative);
        }
        self.owner.witnesses.push(RetainedJointBirth {
            birth: RetainedBirth::PendingAbsence(negative),
            nested_bytes: self.nested_limit,
            _storage: self.storage,
        });
        self.owner.order_for_native_reads();
        Ok(())
    }
}

/// Immutable access to the same producer's pending H0/stash. Construction
/// stays inside the lane; a consumer cannot supply a floor or raw records.
pub(crate) struct JointContinuationView<'a> {
    pending: PendingH3Continuation<'a>,
}

impl JointContinuationView<'_> {
    pub(crate) fn matches_producers(&self, producers: &SessionDrainProducers) -> bool {
        self.pending.producers.same_producers(producers)
            && self.pending.capture.router().domain() == producers.native_domain()
    }

    pub(crate) fn inspect<R>(&self, inspect: impl FnOnce(&PendingH3Continuation<'_>) -> R) -> R {
        inspect(&self.pending)
    }
}

/// Stack-only readers plus immutable continuation custody. Native readers
/// share one Session cell; neither can retain a borrow across callbacks.
pub(crate) struct JointCommitIo<'a> {
    attachment: &'a AttachedSemanticSet,
    continuation: JointContinuationView<'a>,
    births: &'a mut dyn JointBirthEvidenceSource,
    fault: &'a dyn FaultEpoch,
}

impl<'a> JointCommitIo<'a> {
    /// The original attachment already borrowed by these same native readers.
    pub(crate) fn attachment(&self) -> &'a AttachedSemanticSet {
        self.attachment
    }

    pub(crate) fn continuation(&self) -> &JointContinuationView<'a> {
        &self.continuation
    }

    pub(crate) fn native_checks(&mut self) -> (&mut dyn JointBirthEvidenceSource, &dyn FaultEpoch) {
        (&mut *self.births, self.fault)
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        JointContinuationView<'a>,
        &'a mut dyn JointBirthEvidenceSource,
        &'a dyn FaultEpoch,
    ) {
        (self.continuation, self.births, self.fault)
    }
}

// Production constructs this leaf only from its actual Session. The test
// implementation substitutes native reads below the same scoped cell/core.
pub(crate) trait JointNativeIo {
    fn recheck_birth(
        &mut self,
        witness: &RetainedBirthWitness,
        capture: &SemanticCapture,
        attached: &AttachedSemanticSet,
        binding: &SemanticCallerBinding,
    ) -> Result<SessionBirthEvidence, BirthObservationRefusal>;

    fn fault_epoch(&self) -> Result<u64, FaultReadError>;
}

impl JointNativeIo for Session {
    fn recheck_birth(
        &mut self,
        witness: &RetainedBirthWitness,
        capture: &SemanticCapture,
        attached: &AttachedSemanticSet,
        binding: &SemanticCallerBinding,
    ) -> Result<SessionBirthEvidence, BirthObservationRefusal> {
        witness.fresh_evidence(self, capture, attached, binding)
    }

    fn fault_epoch(&self) -> Result<u64, FaultReadError> {
        FaultEpoch::fault_epoch(&self.instance_maps())
    }
}

trait ReadyBirthLookup {
    fn find_ready(&self, target: &JointFeedTarget) -> Option<&RetainedBirthWitness>;
}

impl<W: Borrow<RetainedBirthWitness>> ReadyBirthLookup for [W] {
    fn find_ready(&self, target: &JointFeedTarget) -> Option<&RetainedBirthWitness> {
        let at = self
            .binary_search_by_key(&target.bootstrap().domain(), |witness| {
                witness.borrow().receipt().domain()
            })
            .ok()?;
        let witness = self[at].borrow();
        (witness.receipt() == target.bootstrap()).then_some(witness)
    }
}

impl ReadyBirthLookup for RetainedJointBirths {
    fn find_ready(&self, target: &JointFeedTarget) -> Option<&RetainedBirthWitness> {
        RetainedJointBirths::find_ready(self, target)
    }
}

struct NativeBirths<'io, 'native, N, W: ?Sized> {
    native: &'io RefCell<&'native mut N>,
    capture: &'io SemanticCapture,
    attached: &'io AttachedSemanticSet,
    witnesses: &'io W,
}

impl<N: JointNativeIo, W: ReadyBirthLookup + ?Sized> JointBirthEvidenceSource
    for NativeBirths<'_, '_, N, W>
{
    fn take_for(
        &mut self,
        target: &JointFeedTarget,
        binding: &SemanticCallerBinding,
    ) -> Result<SessionBirthEvidence, BirthObservationRefusal> {
        if target.caller() != binding.caller() || binding.domain() != self.capture.router().domain()
        {
            return Err(BirthObservationRefusal::BindingMismatch);
        }
        // The owner supplies its original table. Pending entries never
        // masquerade as witnesses or enter the ready-domain binary search.
        let witness = self
            .witnesses
            .find_ready(target)
            .ok_or(BirthObservationRefusal::BindingMismatch)?;
        let mut native = self
            .native
            .try_borrow_mut()
            .map_err(|_| BirthObservationRefusal::CurrentPartition)?;
        native.recheck_birth(witness, self.capture, self.attached, binding)
    }
}

struct NativeFault<'io, 'native, N>(&'io RefCell<&'native mut N>);

impl<N: JointNativeIo> FaultEpoch for NativeFault<'_, '_, N> {
    fn fault_epoch(&self) -> Result<u64, FaultReadError> {
        let native = self
            .0
            .try_borrow()
            .map_err(|_| FaultReadError::Unreadable)?;
        native.fault_epoch()
    }
}

#[allow(clippy::too_many_arguments)] // The immutable fields are disjoint original lane borrows.
fn with_native<N: JointNativeIo, W: ReadyBirthLookup + ?Sized, R>(
    capture: &SemanticCapture,
    stash: &RefreshReceiptStash,
    producers: &SessionDrainProducers,
    attached: &AttachedSemanticSet,
    witnesses: &W,
    native: &RefCell<&mut N>,
    inspect: impl for<'io> FnOnce(JointCommitIo<'io>) -> R,
) -> Result<R, SemanticRefusal> {
    if capture.router().domain() != producers.native_domain()
        || attached.domain() != producers.native_domain()
    {
        return Err(SemanticRefusal::Attachment);
    }
    let mut births = NativeBirths {
        native,
        capture,
        attached,
        witnesses,
    };
    let fault = NativeFault(native);
    Ok(inspect(JointCommitIo {
        attachment: attached,
        continuation: JointContinuationView {
            pending: PendingH3Continuation {
                capture,
                stash,
                producers,
            },
        },
        births: &mut births,
        fault: &fault,
    }))
}

impl AttestedSemanticLane {
    /// Borrow the actual Session sequentially, while birth and pending
    /// checks share the same immutable Capture. H0 mutations run outside
    /// this scope; the callback cannot return a reader or owner borrow.
    #[allow(dead_code)] // The following machine slice calls the actual Session entrypoint.
    pub(crate) fn with_joint_commit_io<W: Borrow<RetainedBirthWitness>, R>(
        &mut self,
        witnesses: &[W],
        inspect: impl for<'io> FnOnce(JointCommitIo<'io>) -> R,
    ) -> Result<R, SemanticRefusal> {
        self.with_joint_native(witnesses, inspect)
    }

    #[cfg_attr(test, allow(dead_code))] // Test I/O substitutes the native leaf; the actual Session uses this entrypoint.
    pub(crate) fn with_joint_commit_io_for_births<R>(
        &mut self,
        witnesses: &RetainedJointBirths,
        inspect: impl for<'io> FnOnce(JointCommitIo<'io>) -> R,
    ) -> Result<R, SemanticRefusal> {
        self.with_joint_native(witnesses, inspect)
    }

    fn with_joint_native<W: ReadyBirthLookup + ?Sized, R>(
        &mut self,
        witnesses: &W,
        inspect: impl for<'io> FnOnce(JointCommitIo<'io>) -> R,
    ) -> Result<R, SemanticRefusal> {
        let live = self.live.as_mut().ok_or(SemanticRefusal::Unavailable)?;
        let LiveLane {
            session,
            capture,
            attached,
            stashed_refresh,
            finished,
            ..
        } = &mut **live;
        if *finished {
            return Err(SemanticRefusal::Unavailable);
        }
        let producers = session
            .drain_producers()
            .ok_or(SemanticRefusal::Unavailable)?;
        let native = RefCell::new(session);
        with_native(
            capture,
            stashed_refresh,
            &producers,
            attached,
            witnesses,
            &native,
            inspect,
        )
    }

    /// Compatibility consumers borrow a view only for their pending check,
    /// never while an old test birth source borrows its substituted owner.
    pub(crate) fn with_joint_continuation<R>(
        &self,
        inspect: impl FnOnce(&JointContinuationView<'_>) -> R,
    ) -> Option<R> {
        self.with_pending_h3_continuation(|pending| inspect(&JointContinuationView { pending }))
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)] // Forward the exact disjoint native-fixture borrows.
pub(crate) fn with_joint_commit_io_for_test<
    N: JointNativeIo,
    W: Borrow<RetainedBirthWitness>,
    R,
>(
    capture: &SemanticCapture,
    stash: &RefreshReceiptStash,
    producers: &SessionDrainProducers,
    attached: &AttachedSemanticSet,
    witnesses: &[W],
    native: &RefCell<&mut N>,
    inspect: impl for<'io> FnOnce(JointCommitIo<'io>) -> R,
) -> Result<R, SemanticRefusal> {
    with_native(
        capture, stash, producers, attached, witnesses, native, inspect,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)] // Same disjoint borrows, now over the actual mixed original table.
pub(crate) fn with_joint_commit_io_for_births_test<N: JointNativeIo, R>(
    capture: &SemanticCapture,
    stash: &RefreshReceiptStash,
    producers: &SessionDrainProducers,
    attached: &AttachedSemanticSet,
    witnesses: &RetainedJointBirths,
    native: &RefCell<&mut N>,
    inspect: impl for<'io> FnOnce(JointCommitIo<'io>) -> R,
) -> Result<R, SemanticRefusal> {
    with_native(
        capture, stash, producers, attached, witnesses, native, inspect,
    )
}

// One authority loop for the legacy caller and the inactive collected machine.
#[allow(dead_code)] // The collected runtime calls this path after its AwaitH0 state lands.
pub(crate) fn bind_collected_semantic_callers(
    coordinator: &mut super::InventoryCoordinator<super::OsProcessSource>,
    lane: &mut AttestedSemanticLane,
    raw: &mut crate::semantics_objects::journal::joint_driver::RawJointQuantum,
    producers: &crate::attach::SessionDrainProducers,
) -> Result<(), crate::semantics_objects::journal::joint_driver::RawQuantumRefusal> {
    // No refresh selector/cursor or admission write precedes this preflight.
    raw.validate_refresh(coordinator.joint_capture().adapter(), producers)?;
    bind_semantic_callers_inner(coordinator, lane, Some((raw, producers)));
    Ok(())
}

pub(crate) fn bind_semantic_callers_inner(
    coordinator: &mut super::InventoryCoordinator<super::OsProcessSource>,
    lane: &mut AttestedSemanticLane,
    collected: Option<(
        &mut crate::semantics_objects::journal::joint_driver::RawJointQuantum,
        &crate::attach::SessionDrainProducers,
    )>,
) {
    bind_semantic_callers_with_q(coordinator, lane, collected, None)
}

pub(crate) fn bind_collected_semantic_callers_at_q(
    coordinator: &mut super::InventoryCoordinator<super::OsProcessSource>,
    lane: &mut AttestedSemanticLane,
    raw: &mut crate::semantics_objects::journal::joint_driver::RawJointQuantum,
    producers: &SessionDrainProducers,
    discovery: &crate::events::DiscoveryDomain,
    q: &crate::attach::CollectedFinishQ,
) -> Result<(), crate::semantics_objects::journal::joint_driver::RawQuantumRefusal> {
    raw.validate_refresh(coordinator.joint_capture().adapter(), producers)?;
    raw.validate_collected_q(producers, discovery, q)?;
    // An empty terminal collection may flush existing jobs/stash in its H0
    // tick, but must not start a fresh provider scan after admission STOP.
    // Nonempty pre-Q originals retain the existing collected binder path.
    if raw.pending_h0_records() == 0 {
        return Ok(());
    }
    bind_semantic_callers_with_q(
        coordinator,
        lane,
        Some((raw, producers)),
        Some((discovery, q)),
    );
    Ok(())
}

fn bind_semantic_callers_with_q(
    coordinator: &mut super::InventoryCoordinator<super::OsProcessSource>,
    lane: &mut AttestedSemanticLane,
    mut collected: Option<(
        &mut crate::semantics_objects::journal::joint_driver::RawJointQuantum,
        &SessionDrainProducers,
    )>,
    terminal: Option<(
        &crate::events::DiscoveryDomain,
        &crate::attach::CollectedFinishQ,
    )>,
) {
    if !lane.is_live() || lane.is_finished() {
        return;
    }
    for attempt in coordinator.semantic_refresh_attempts(lane, None, |_| true) {
        let Some(module) = attempt.module else {
            coordinator.semantic_admission_refused(attempt.caller, "provider_mapping_unproven");
            continue;
        };
        let Some(candidate) =
            coordinator.prepare_legacy_semantic_candidate(attempt.caller, lane.domain())
        else {
            coordinator.semantic_admission_refused(attempt.caller, "caller_custody_unproven");
            continue;
        };
        let prepared = match collected.as_mut() {
            Some((raw, producers)) if terminal.is_some() => {
                let (discovery, q) = terminal.expect("same terminal borrow");
                lane.prepare_caller_admission_collected_at_q(
                    candidate.pin(),
                    attempt.slot,
                    &module,
                    raw,
                    coordinator.joint_capture().adapter(),
                    producers,
                    discovery,
                    q,
                    |bytes| coordinator.registry().reserve_semantic_storage(bytes),
                )
            }
            Some((raw, producers)) => lane.prepare_caller_admission_collected(
                candidate.pin(),
                attempt.slot,
                &module,
                raw,
                coordinator.joint_capture().adapter(),
                producers,
                |bytes| coordinator.registry().reserve_semantic_storage(bytes),
            ),
            None => {
                lane.prepare_caller_admission(candidate.pin(), attempt.slot, &module, |bytes| {
                    coordinator.registry().reserve_semantic_storage(bytes)
                })
            }
        };
        match prepared {
            Ok(prepared) => {
                let (receipt, _) =
                    coordinator.consume_semantic_admission(candidate, prepared, None);
                lane.deliver_admission_receipt(receipt);
            }
            Err(reason) => {
                coordinator.semantic_admission_refused(attempt.caller, &reason.to_string())
            }
        }
    }
}
