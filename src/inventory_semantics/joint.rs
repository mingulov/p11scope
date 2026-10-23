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
use crate::semantic_capture::RetainedBirthWitness;
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SemanticResourceReserver,
};
use crate::semantics_objects::journal::joint_audit::JointBirthEvidenceSource;
use crate::semantics_objects::journal::{FaultEpoch, FaultReadError, SessionBirthEvidence};
use std::borrow::Borrow;
use std::cell::RefCell;

mod machine;
pub(crate) use machine::{
    JointCommitRefusal, JointMachineIo, JointServiceMode, JointServiceProgress, JointWorkBudget,
    LiveJointMachine,
};

/// One original witness and its transferred nested-allocation charge. The
/// existing native source borrows this same table through Borrow, not a copy.
pub(crate) struct RetainedJointBirth {
    witness: RetainedBirthWitness,
    _storage: ResourceLease,
}
impl Borrow<RetainedBirthWitness> for RetainedJointBirth {
    fn borrow(&self) -> &RetainedBirthWitness {
        &self.witness
    }
}
impl RetainedJointBirth {
    pub(crate) fn receipt(&self) -> &crate::semantics_objects::journal::BootstrapReceipt {
        self.witness.receipt()
    }
}

/// The eventual lane keeps its actual witnesses here. Container capacity and
/// each heterogeneous receipt's nested bytes are paid before New/native move;
/// PreparedSemanticBatch may then refund its original overlapping charge.
#[derive(Default)]
pub(crate) struct RetainedJointBirths {
    witnesses: Vec<RetainedJointBirth>,
    capacity_storage: Option<ResourceLease>,
}
pub(crate) struct RetainedBirthSlot<'a> {
    owner: &'a mut RetainedJointBirths,
    nested_limit: usize,
    storage: ResourceLease,
}
impl RetainedJointBirths {
    pub(crate) fn new() -> Self {
        Self::default()
    }
    pub(crate) fn as_slice(&self) -> &[RetainedJointBirth] {
        &self.witnesses
    }

    pub(crate) fn reserve_for(
        &mut self,
        reserve: &SemanticResourceReserver,
        nested_bytes: usize,
    ) -> Result<RetainedBirthSlot<'_>, ()> {
        let storage = reserve.reserve(nested_bytes).map_err(|_| ())?;
        if self.witnesses.len() == self.witnesses.capacity() {
            let next = self.witnesses.capacity().checked_mul(2).ok_or(())?.max(1);
            if next > crate::discovery::caller_registry::instance_input::MAX_REGISTRY_INSTANCES {
                return Err(());
            }
            let bytes = next
                .checked_mul(std::mem::size_of::<RetainedJointBirth>())
                .and_then(|bytes| bytes.checked_add(OWNED_ALLOCATION_PADDING))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
                .ok_or(())?;
            let capacity_storage = reserve.reserve(bytes).map_err(|_| ())?;
            self.witnesses
                .try_reserve_exact(next - self.witnesses.len())
                .map_err(|_| ())?;
            assert!(
                self.witnesses.capacity() <= next,
                "retained witness capacity exceeds its precharge"
            );
            self.capacity_storage = Some(capacity_storage);
        }
        Ok(RetainedBirthSlot {
            owner: self,
            nested_limit: nested_bytes,
            storage,
        })
    }

    pub(crate) fn order_for_native_reads(&mut self) {
        self.witnesses
            .sort_unstable_by_key(|witness| witness.receipt().domain());
    }
}
impl RetainedBirthSlot<'_> {
    pub(crate) fn accepts(&self, witness: &RetainedBirthWitness) -> bool {
        witness
            .owned_storage_bytes()
            .is_some_and(|bytes| bytes <= self.nested_limit)
            && self.owner.witnesses.len() < self.owner.witnesses.capacity()
    }
    pub(crate) fn retain(self, witness: RetainedBirthWitness) {
        assert!(
            self.accepts(&witness),
            "original witness storage was precharged before installation"
        );
        self.owner.witnesses.push(RetainedJointBirth {
            witness,
            _storage: self.storage,
        });
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

struct NativeBirths<'io, 'native, N, W> {
    native: &'io RefCell<&'native mut N>,
    capture: &'io SemanticCapture,
    attached: &'io AttachedSemanticSet,
    witnesses: &'io [W],
}

impl<N: JointNativeIo, W: Borrow<RetainedBirthWitness>> JointBirthEvidenceSource
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
        // The owner supplies its original witnesses in domain order. This
        // borrows the existing table, with no per-head scan or copied facts.
        let at = self
            .witnesses
            .binary_search_by_key(&target.bootstrap().domain(), |witness| {
                witness.borrow().receipt().domain()
            })
            .map_err(|_| BirthObservationRefusal::BindingMismatch)?;
        let witness = self.witnesses[at].borrow();
        if witness.receipt() != target.bootstrap() {
            return Err(BirthObservationRefusal::BindingMismatch);
        }
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
fn with_native<N: JointNativeIo, W: Borrow<RetainedBirthWitness>, R>(
    capture: &SemanticCapture,
    stash: &RefreshReceiptStash,
    producers: &SessionDrainProducers,
    attached: &AttachedSemanticSet,
    witnesses: &[W],
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
    mut collected: Option<(
        &mut crate::semantics_objects::journal::joint_driver::RawJointQuantum,
        &crate::attach::SessionDrainProducers,
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
