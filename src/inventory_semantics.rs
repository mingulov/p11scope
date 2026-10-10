//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private authority carried from retained Inventory inputs to a Detailed lane.

use crate::attach::capture::NativeDomainId;
use crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding;
use crate::semantic_capture::{
    CurrentPartitionReceipt, CurrentReceiptRefusal, Endpoint, PhysicalSemanticGap, TickOutcome,
    TickReport,
};
use p11scope_ebpf_common::ImageIdentity;

/// Finite refusal; no private manifest or native record is rendered here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SemanticRefusal {
    ManifestInput,
    Unattested,
    IncompleteProvider,
    Attachment,
    Descriptor,
    ProviderInstanceUnproven,
    /// The lane cannot serve this operation yet: Task 5 owns Session
    /// startup and H0 driving; the Task 3 shell refuses honestly.
    Unavailable,
}

impl std::fmt::Display for SemanticRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ManifestInput => "manifest_input_refused",
            Self::Unattested => "unattested",
            Self::IncompleteProvider => "incomplete_provider",
            Self::Attachment => "semantic_attachment_refused",
            Self::Descriptor => "semantic_descriptor_refused",
            Self::ProviderInstanceUnproven => "provider_instance_unproven",
            Self::Unavailable => "semantic_unavailable",
        })
    }
}

pub(crate) use crate::discovery::engine::inventory_coordinator::semantics::AttestedSubset;

/// Lane-staged negative facts: the accompanying negatives one owned H0
/// outcome batch carries. The cut barrier ordinal is H0-timeline evidence
/// (allocated by H0's checked counter after all issued positions), never
/// caller-selected; tests script it exactly as H2 scripts positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // Task5 lane stages negatives.
pub(crate) enum LaneNegative {
    /// One coalesced physical cut applied before every unpublished call.
    CutBarrier { ordinal: u64 },
    /// A refused collection, recorded through the audited path.
    CollectionRefused { reason: LaneCollectionRefusal },
}

/// Finite lane-collection refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // Task5 lane stages negatives.
pub(crate) enum LaneCollectionRefusal {
    Backpressure,
    CollectionFailed,
}

impl LaneCollectionRefusal {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Backpressure => "backpressure",
            Self::CollectionFailed => "collection_failed",
        }
    }
}

/// One owned H0 outcome batch plus its current-partition receipts and
/// lane-staged negative facts. Move-only: private fields, no
/// Clone/Default/from_parts, redacted Debug. The lane alone constructs
/// it; the coordinator finalizer alone consumes it.
pub(crate) struct SemanticBatch {
    domain: NativeDomainId,
    outcomes: Vec<TickOutcome>,
    current: Vec<CurrentPartitionReceipt>,
    negatives: Vec<LaneNegative>,
    observed_ns: u64,
}

/// Lane negatives per batch: one cut barrier plus bounded collection
/// refusals for the quantum. H0 outcomes and receipts keep H0's own
/// capacity; the lane re-checks them defensively below.
#[cfg_attr(not(test), expect(dead_code, reason = "Task5 lane constructs batches"))]
pub(crate) const MAX_LANE_NEGATIVES: usize = 64;

impl std::fmt::Debug for SemanticBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SemanticBatch")
            .field("outcomes", &self.outcomes.len())
            .field("current", &self.current.len())
            .field("negatives", &self.negatives.len())
            .finish_non_exhaustive()
    }
}

impl SemanticBatch {
    /// The lane's batch constructor: bounds-checked before ownership.
    #[cfg_attr(not(test), expect(dead_code, reason = "Task5 lane constructs batches"))]
    pub(crate) fn from_tick_report(
        domain: NativeDomainId,
        report: TickReport,
        negatives: Vec<LaneNegative>,
        observed_ns: u64,
    ) -> Result<Self, SemanticRefusal> {
        let (outcomes, current) = report.into_parts();
        if outcomes.len() > crate::discovery::instances::MAX_INSTANCES
            || current.len() > crate::discovery::instances::MAX_INSTANCES
            || negatives.len() > MAX_LANE_NEGATIVES
        {
            return Err(SemanticRefusal::Unavailable);
        }
        Ok(Self {
            domain,
            outcomes,
            current,
            negatives,
            observed_ns,
        })
    }

    #[cfg(test)]
    pub(crate) fn scripted(
        domain: NativeDomainId,
        negatives: Vec<LaneNegative>,
        observed_ns: u64,
    ) -> Self {
        Self::from_tick_report(domain, TickReport::default(), negatives, observed_ns)
            .expect("scripted batch respects lane bounds")
    }

    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }

    pub(crate) fn observed_ns(&self) -> u64 {
        self.observed_ns
    }

    /// The batch's own cut fence, if any: the maximum cut-barrier
    /// ordinal the lane staged. The finalizer carries the cut's
    /// barrier into the queued ordinary quantum; tokens admitted by
    /// the finalization itself never feed it.
    pub(crate) fn cut_barrier(&self) -> Option<u64> {
        self.negatives
            .iter()
            .filter_map(|negative| match negative {
                LaneNegative::CutBarrier { ordinal } => Some(*ordinal),
                LaneNegative::CollectionRefused { .. } => None,
            })
            .max()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Vec<TickOutcome>,
        Vec<CurrentPartitionReceipt>,
        Vec<LaneNegative>,
    ) {
        (self.outcomes, self.current, self.negatives)
    }
}

/// Validated current-partition coverage, decomposed from a receipt the
/// lane owner validated against current retained binding/router state.
/// The coverage is the conversion's registration and standing proof.
pub(crate) struct LaneCoverage {
    domain: NativeDomainId,
    image: ImageIdentity,
    endpoint: Endpoint,
    ids: Vec<crate::discovery::instances::InstanceId>,
}

impl std::fmt::Debug for LaneCoverage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LaneCoverage(<private>)")
    }
}

impl LaneCoverage {
    #[cfg(test)]
    pub(crate) fn scripted(
        domain: NativeDomainId,
        image: ImageIdentity,
        endpoint: Endpoint,
        ids: Vec<crate::discovery::instances::InstanceId>,
    ) -> Self {
        Self {
            domain,
            image,
            endpoint,
            ids,
        }
    }

    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }

    pub(crate) fn image(&self) -> ImageIdentity {
        self.image
    }

    pub(crate) fn endpoint(&self) -> Endpoint {
        self.endpoint
    }

    pub(crate) fn instances(&self) -> &[crate::discovery::instances::InstanceId] {
        &self.ids
    }
}

/// One optional Detailed lane: the Session owner, H0 `SemanticCapture`
/// driver and proof-bearing batch supplier. Task 3 carries the type, its
/// pinned signatures and the finalizer wiring; Task 5 owns Session
/// startup, loop/stop/emitter integration and retention. Until then every
/// H0-driving method refuses honestly and broad Inventory is preserved.
pub(crate) struct AttestedSemanticLane {
    subset: AttestedSubset,
    domain: NativeDomainId,
    #[cfg(test)]
    recorded_gaps: Vec<PhysicalSemanticGap>,
    #[cfg(test)]
    scripted_barrier: Option<u64>,
    #[cfg(test)]
    fail_next_cut: bool,
}

impl std::fmt::Debug for AttestedSemanticLane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AttestedSemanticLane(<retained>)")
    }
}

impl AttestedSemanticLane {
    #[cfg_attr(not(test), expect(dead_code, reason = "Task5 owns lane startup"))]
    pub(crate) fn start(
        subset: AttestedSubset,
        _scope: &crate::attach::Scope,
        _backend: crate::attach::BackendSelection,
    ) -> Result<Self, SemanticRefusal> {
        // Task 5 consumes scope/backend for Session startup and replaces
        // the minted domain with the Session's native domain.
        if subset.plan().slots.is_empty() {
            return Err(SemanticRefusal::Unattested);
        }
        let domain = NativeDomainId::try_mint().map_err(|_| SemanticRefusal::Unavailable)?;
        Ok(Self {
            subset,
            domain,
            #[cfg(test)]
            recorded_gaps: Vec::new(),
            #[cfg(test)]
            scripted_barrier: None,
            #[cfg(test)]
            fail_next_cut: false,
        })
    }

    pub(crate) fn subset(&self) -> &AttestedSubset {
        &self.subset
    }

    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }

    #[cfg_attr(not(test), expect(dead_code, reason = "Task5 owns the lane loop"))]
    pub(crate) fn tick(
        &mut self,
        _bindings: &[SemanticCallerBinding],
    ) -> Result<SemanticBatch, SemanticRefusal> {
        // Task 5 drives H0 collect/audit/route here; the Task 3 shell
        // refuses instead of inventing calls.
        Err(SemanticRefusal::Unavailable)
    }

    pub(crate) fn apply_physical_gaps(
        &mut self,
        gaps: Vec<PhysicalSemanticGap>,
    ) -> Result<SemanticBatch, SemanticRefusal> {
        #[cfg(not(test))]
        {
            let _ = gaps;
            // Task 5 runs the H0 atomic fault cut here; until then the
            // finalizer treats the refusal as a cut failure and preserves
            // broad Inventory.
            Err(SemanticRefusal::Unavailable)
        }
        #[cfg(test)]
        {
            if self.fail_next_cut {
                self.fail_next_cut = false;
                self.recorded_gaps.extend(gaps);
                return Err(SemanticRefusal::Unavailable);
            }
            self.recorded_gaps.extend(gaps);
            let mut negatives = Vec::new();
            if let Some(ordinal) = self.scripted_barrier.take() {
                negatives.push(LaneNegative::CutBarrier { ordinal });
            }
            Ok(SemanticBatch::scripted(self.domain, negatives, 0))
        }
    }

    /// The actual-owner receipt validator. Task 5 validates against the
    /// live Session's retained binding/router state; the Task 3 shell has
    /// no Session to re-prove custody through and refuses.
    pub(crate) fn validate_current(
        &mut self,
        _receipt: &CurrentPartitionReceipt,
    ) -> Result<LaneCoverage, CurrentReceiptRefusal> {
        Err(CurrentReceiptRefusal::Custody)
    }

    /// Gaps the shell consumed, in order. Tests assert adjudication
    /// reached the lane; the gaps stay opaque.
    #[cfg(test)]
    pub(crate) fn recorded_gaps(&self) -> &[PhysicalSemanticGap] {
        &self.recorded_gaps
    }

    /// Script the next cut's barrier ordinal (test H0-timeline evidence).
    #[cfg(test)]
    pub(crate) fn script_cut_barrier(&mut self, ordinal: u64) {
        self.scripted_barrier = Some(ordinal);
    }

    /// Fail the next cut (test cut-failure handling).
    #[cfg(test)]
    pub(crate) fn fail_cut_once(&mut self) {
        self.fail_next_cut = true;
    }

    /// Drain recorded gaps (test isolation between publications).
    #[cfg(test)]
    pub(crate) fn take_recorded_gaps(&mut self) -> Vec<PhysicalSemanticGap> {
        std::mem::take(&mut self.recorded_gaps)
    }
}
