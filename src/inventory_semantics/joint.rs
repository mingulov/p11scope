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
use crate::semantics_objects::journal::joint_audit::JointBirthEvidenceSource;
use crate::semantics_objects::journal::{FaultEpoch, FaultReadError, SessionBirthEvidence};
use std::borrow::Borrow;
use std::cell::RefCell;

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
    continuation: JointContinuationView<'a>,
    births: &'a mut dyn JointBirthEvidenceSource,
    fault: &'a dyn FaultEpoch,
}

impl<'a> JointCommitIo<'a> {
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
    pub(crate) fn with_joint_commit_io<R>(
        &mut self,
        witnesses: &[RetainedBirthWitness],
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
pub(crate) fn with_joint_commit_io_for_test<N: JointNativeIo, R>(
    capture: &SemanticCapture,
    stash: &RefreshReceiptStash,
    producers: &SessionDrainProducers,
    attached: &AttachedSemanticSet,
    witnesses: &[&RetainedBirthWitness],
    native: &RefCell<&mut N>,
    inspect: impl for<'io> FnOnce(JointCommitIo<'io>) -> R,
) -> Result<R, SemanticRefusal> {
    with_native(
        capture, stash, producers, attached, witnesses, native, inspect,
    )
}
