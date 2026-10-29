//! SPDX-License-Identifier: GPL-3.0-or-later
//! Staged T-L3 Engine acknowledgement for loader lifetimes (packet 6.09b).
//!
//! Engine-facing endpoints over the L1 [`LifetimeRegistry`]: every Engine
//! queue, scan, descriptor and link-cleanup site charges here, and the slot
//! acknowledges only after each reaches disposition. Staged: production
//! allocation stays on [`LoaderRegistry`]'s 256-context refusal path until
//! activation; no production caller exists yet.
//!
//! QueueKind to Engine mapping (OPEN-2; activation connects these sites):
//! - `Collected`: `Engine::pending_discovery_records` (`engine.rs:391`);
//!   charge at ring-pull append (`:20002`, `:22404`, Finish `:26466`),
//!   dispose at dispatch drain (Finish `:26668-26673`).
//! - `Pending`: `Engine::pending_loader_arm_scans` (`engine.rs:620`); charge
//!   at owed-catch-up insert (`:17228-17231`), dispose at serve (`:14905`,
//!   `:14920`, `:14923`, `:15522`) or retirement prune (`:18235`).
//! - `Deferred`: `TerminalDispatch::deferred_mismatches` (`engine.rs:4686`);
//!   charge at deferral (`:15475`), dispose at
//!   `settle_deferred_loader_mismatches` (`:20230`, `:19475`).
//! - `TerminalBatch`: `Engine::terminal_batch` (`engine.rs:389`); charge at
//!   `retain_terminal_batch` (`:17822`), `TerminalBatch::extend` (`:4703`)
//!   and `handoff_precharged_terminal_records` (`:17792`), dispose at
//!   `dispatch_terminal_batch` (`:18031`) or `take_terminal_batch_for_deferred`
//!   (`:17945`).
//! - `SelectionHandoff`: `TerminalSelectionHandoffs` (`engine.rs:2601`);
//!   charge per-context handoff vecs (`:20012`, `:25976`), dispose at the move
//!   into the batch (`:18302`) or `reject_terminal_selection_handoffs`
//!   (`:18299`, `:18354`).
//! - scans: `Engine::pending_loader_scans` (`engine.rs:617`); charge at
//!   `defer_loader_memory_scan` (`:11882`, `:15524`), settle at `:11911`,
//!   `:11928`, `:11945`, `:15317` and `:15557`.
//! - descriptors: per-context dynamic export cookies (`attach_dynamic_export`,
//!   `:16818`); charge at attach success, release at `detach_dynamic_context`
//!   (`:17555`, `:18250`), settle at terminal dispatch completion.
//! - link cleanup: the `EngineSession::detach_dynamic_context` verdict
//!   (`:17555`, `:18250`): `record_link_cleanup(!detach_failed)`.
//! - native retirement: T-L2 `insert_state`/`remove_state`; a failed removal
//!   keeps quarantine plus replacement refusal, never an automatic reclaim.
//!
//! Finish/stop repairs (the `391a9e36` port): [`LoaderAckDriver::finish_ack`]
//! surfaces the actual refusal while keeping custody, quarantine and the
//! replacement block; a spent fence for reclaimed storage settles
//! idempotently and never names a successor.

use super::loader::{LoaderContextId, LoaderRegistry};
use super::loader_lifetime::{
    ConsumerDrain, ExportBinding, LifetimeDomain, LifetimeError, LifetimeRegistry,
    LoaderRetirement, LoaderRetirementFence, LoaderToken, PrefixOutcome, QueueKind, ReclaimedSlot,
    SlotPhase, SlotView,
};

/// Staged T-L3 acknowledgement driver: one Session domain over one staged
/// generation registry. Activation owns exactly one of these per Engine.
pub(crate) struct LoaderAckDriver {
    registry: LifetimeRegistry,
    domain: LifetimeDomain,
}

impl LoaderAckDriver {
    pub(crate) fn new(descriptor_ceiling: u64) -> Result<Self, LifetimeError> {
        let domain = LifetimeDomain::mint();
        Ok(Self {
            registry: LifetimeRegistry::new(domain, descriptor_ceiling)?,
            domain,
        })
    }

    /// Reserve storage and burn one generation for a new loader incarnation.
    pub(crate) fn prepare_new(&mut self) -> Result<LoaderToken, LifetimeError> {
        self.registry.prepare_new(self.domain)
    }

    pub(crate) fn activate(&mut self, token: LoaderToken) -> Result<(), LifetimeError> {
        self.registry.activate(self.domain, token)
    }

    pub(crate) fn slot_state(&self, slot: u8) -> SlotView {
        self.registry.slot_state(slot)
    }

    pub(crate) fn phase_of(&self, token: LoaderToken) -> Option<SlotPhase> {
        self.registry.phase_of(token)
    }

    pub(crate) fn charged_contexts(&self) -> usize {
        self.registry.charged_contexts()
    }

    /// Whether a successor incarnation is refused for this slot. True while
    /// the slot is live, including permanent quarantine; only reclaimable
    /// storage admits a successor. Never auto-clears.
    pub(crate) fn replacement_blocked(&self, slot: u8) -> bool {
        matches!(self.registry.slot_state(slot), SlotView::Live { .. })
    }

    /// Activation bridge: resolve one allocated Engine context to its staged
    /// adapter token (generation 1). Consumes the (a) gate; unallocated ids
    /// refuse.
    pub(crate) fn token_for_context(
        registry: &LoaderRegistry,
        id: LoaderContextId,
    ) -> Option<LoaderToken> {
        registry.token_for(id)
    }

    /// Activation bridge: resolve one staged adapter token to its allocated
    /// Engine context. Consumes the (a) gate; stale and foreign tokens refuse.
    pub(crate) fn context_for_token(
        registry: &LoaderRegistry,
        token: LoaderToken,
    ) -> Option<LoaderContextId> {
        registry.id_for_token(token)
    }

    /// Collected: one loader record entered `pending_discovery_records`.
    pub(crate) fn note_collected_record(
        &mut self,
        token: LoaderToken,
    ) -> Result<(), LifetimeError> {
        self.registry
            .collect_record(self.domain, token, QueueKind::Collected)
    }

    /// Collected: one queued loader record dispatched.
    pub(crate) fn note_record_dispatched(
        &mut self,
        token: LoaderToken,
    ) -> Result<(), LifetimeError> {
        self.registry
            .dispose_record(self.domain, token, QueueKind::Collected)
    }

    /// Pending: one catch-up scan owed (`pending_loader_arm_scans` insert).
    pub(crate) fn note_arm_scan_owed(&mut self, token: LoaderToken) -> Result<(), LifetimeError> {
        self.registry
            .collect_record(self.domain, token, QueueKind::Pending)
    }

    /// Pending: one owed catch-up scan served or pruned.
    pub(crate) fn note_arm_scan_served(&mut self, token: LoaderToken) -> Result<(), LifetimeError> {
        self.registry
            .dispose_record(self.domain, token, QueueKind::Pending)
    }

    /// Deferred: one loader mismatch deferred for EXEC explanation.
    pub(crate) fn note_mismatch_deferred(
        &mut self,
        token: LoaderToken,
    ) -> Result<(), LifetimeError> {
        self.registry
            .collect_record(self.domain, token, QueueKind::Deferred)
    }

    /// Deferred: one deferred mismatch settled.
    pub(crate) fn note_mismatch_settled(
        &mut self,
        token: LoaderToken,
    ) -> Result<(), LifetimeError> {
        self.registry
            .dispose_record(self.domain, token, QueueKind::Deferred)
    }

    /// TerminalBatch: one record retained in `terminal_batch`.
    pub(crate) fn note_terminal_record_retained(
        &mut self,
        token: LoaderToken,
    ) -> Result<(), LifetimeError> {
        self.registry
            .collect_record(self.domain, token, QueueKind::TerminalBatch)
    }

    /// TerminalBatch: one terminal record dispatched or transferred.
    pub(crate) fn note_terminal_record_dispatched(
        &mut self,
        token: LoaderToken,
    ) -> Result<(), LifetimeError> {
        self.registry
            .dispose_record(self.domain, token, QueueKind::TerminalBatch)
    }

    /// SelectionHandoff: one precharged selection record staged.
    pub(crate) fn note_handoff_staged(&mut self, token: LoaderToken) -> Result<(), LifetimeError> {
        self.registry
            .collect_record(self.domain, token, QueueKind::SelectionHandoff)
    }

    /// SelectionHandoff: one staged record moved into the terminal batch.
    pub(crate) fn note_handoff_moved(&mut self, token: LoaderToken) -> Result<(), LifetimeError> {
        self.registry
            .dispose_record(self.domain, token, QueueKind::SelectionHandoff)
    }

    /// SelectionHandoff: one staged record rejected (wrong owner or failed
    /// authority). A disposed rejection, like the move.
    pub(crate) fn note_handoff_rejected(
        &mut self,
        token: LoaderToken,
    ) -> Result<(), LifetimeError> {
        self.registry
            .dispose_record(self.domain, token, QueueKind::SelectionHandoff)
    }

    /// Scans: one loader memory scan deferred (`pending_loader_scans`).
    pub(crate) fn note_scan_deferred(&mut self, token: LoaderToken) -> Result<(), LifetimeError> {
        self.registry.register_scan(self.domain, token)
    }

    /// Scans: one deferred scan serviced or settled.
    pub(crate) fn note_scan_settled(&mut self, token: LoaderToken) -> Result<(), LifetimeError> {
        self.registry.settle_scan(self.domain, token)
    }

    /// Descriptors: one dynamic export bound; returns its cookie.
    pub(crate) fn note_export_bound(
        &mut self,
        token: LoaderToken,
        binding: ExportBinding,
    ) -> Result<u64, LifetimeError> {
        self.registry.bind_export(self.domain, token, binding)
    }

    /// Descriptors: one export's links closed at detach. The charge stays
    /// until deferred dispatch settles.
    pub(crate) fn note_export_released(
        &mut self,
        token: LoaderToken,
        cookie: u64,
    ) -> Result<(), LifetimeError> {
        self.registry.release_export(self.domain, token, cookie)
    }

    /// Descriptors: one export settled after its deferred dispatch.
    pub(crate) fn note_export_settled(
        &mut self,
        token: LoaderToken,
        cookie: u64,
    ) -> Result<(), LifetimeError> {
        self.registry.settle_export(self.domain, token, cookie)
    }

    /// Native: one short callback guard acquired (T-L2 seam).
    pub(crate) fn note_short_acquired(&mut self, token: LoaderToken) -> Result<(), LifetimeError> {
        self.registry.acquire_short(self.domain, token)
    }

    /// Native: one short callback guard released (T-L2 seam).
    pub(crate) fn note_short_released(&mut self, token: LoaderToken) -> Result<(), LifetimeError> {
        self.registry.release_short(self.domain, token)
    }

    /// Native: one discovery-state long lease inserted (T-L2 seam).
    pub(crate) fn note_state_inserted(&mut self, token: LoaderToken) -> Result<(), LifetimeError> {
        self.registry.insert_state(self.domain, token)
    }

    /// Native: one guarded removal settled (T-L2 seam). A failed removal
    /// quarantines permanently and refuses replacement; nothing reclaims.
    pub(crate) fn note_state_removed(
        &mut self,
        token: LoaderToken,
        deleted: bool,
    ) -> Result<(), LifetimeError> {
        self.registry.remove_state(self.domain, token, deleted)
    }

    /// Link cleanup: the `detach_dynamic_context` verdict for one retiring
    /// context. Failure retains custody; a later success may still complete.
    pub(crate) fn note_link_cleanup(
        &mut self,
        token: LoaderToken,
        detached_cleanly: bool,
    ) -> Result<(), LifetimeError> {
        self.registry
            .record_link_cleanup(self.domain, token, detached_cleanly)
    }

    /// Close new entry admission for the exact token.
    pub(crate) fn begin_retirement(
        &mut self,
        token: LoaderToken,
    ) -> Result<LoaderRetirement, LifetimeError> {
        self.registry.begin_retirement(self.domain, token)
    }

    /// Observe closed-and-zero: every accepted body and discovery-state lease
    /// has finished.
    pub(crate) fn observe_closed_zero(
        &mut self,
        retirement: &LoaderRetirement,
    ) -> Result<(), LifetimeError> {
        self.registry.observe_closed_zero(retirement)
    }

    /// Sample the retained ring's exact producer position. Fixed once.
    pub(crate) fn sample_q(
        &mut self,
        retirement: &LoaderRetirement,
        fence_q: u64,
    ) -> Result<(), LifetimeError> {
        self.registry.sample_q(retirement, fence_q)
    }

    /// Drain the fixed prefix with the single consumer.
    pub(crate) fn drain_prefix(
        &mut self,
        retirement: &LoaderRetirement,
        drain: ConsumerDrain,
    ) -> Result<PrefixOutcome, LifetimeError> {
        self.registry.drain_prefix(retirement, drain)
    }

    /// Mint the typed fence after close, closed-zero and Q sampling. Queue
    /// and scan disposition are the acknowledgement's business, not the
    /// mint's.
    pub(crate) fn mint_fence(
        &mut self,
        retirement: &LoaderRetirement,
    ) -> Result<LoaderRetirementFence, LifetimeError> {
        self.registry.mint_fence(retirement)
    }

    /// Finish-path acknowledgement for one loader retirement fence (the
    /// `391a9e36` port). Every refusal keeps custody: the context, its queued
    /// references, scans, descriptors and ownership stay held, and replacement
    /// stays blocked until a settled acknowledgement frees storage. Nothing
    /// auto-reclaims; a spent fence never names a successor.
    pub(crate) fn finish_ack(
        &mut self,
        fence: &LoaderRetirementFence,
        drain: ConsumerDrain,
    ) -> LoaderFinishOutcome {
        // Idempotent Finish: a spent fence for already-reclaimed storage
        // settles without touching any successor. Anything else goes through
        // the acknowledgement, which keeps custody on every refusal.
        let token = fence.token();
        if let SlotView::Reclaimable { generation } = self.registry.slot_state(token.slot())
            && generation == token.generation()
        {
            return LoaderFinishOutcome::AlreadySettled {
                slot: token.slot(),
                retired_generation: generation,
            };
        }
        match self.registry.ack_fence(fence, drain) {
            Ok(receipt) => LoaderFinishOutcome::Settled(receipt),
            Err(error) if is_waiting_for_custody(&error) => LoaderFinishOutcome::Waiting(error),
            Err(error) => LoaderFinishOutcome::Abandoned(error),
        }
    }
}

/// Acknowledgement refusals that name outstanding custody a later Finish
/// pass may still dispose. Every other refusal is terminal for the fence:
/// quarantine-class failure or a spent fence.
fn is_waiting_for_custody(error: &LifetimeError) -> bool {
    matches!(
        error,
        LifetimeError::DrainIncomplete { .. }
            | LifetimeError::ForeignBusyBeforeQ
            | LifetimeError::RecordsPending { .. }
            | LifetimeError::ScansPending(_)
            | LifetimeError::DescriptorsPending(_)
            | LifetimeError::CleanupIncomplete
    )
}

/// Finish-path acknowledgement outcome for one loader retirement fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LoaderFinishOutcome {
    /// The fence acknowledged; storage is reclaimable for a successor.
    Settled(ReclaimedSlot),
    /// The fence is spent but its retirement already settled: the slot is
    /// reclaimable for the fence's own generation. Idempotent Finish.
    AlreadySettled { slot: u8, retired_generation: u32 },
    /// Outstanding custody the Finish pass must wait for. Nothing dropped.
    Waiting(LifetimeError),
    /// Terminal refusal: quarantine-class failure. Finish ends incompletely
    /// with the actual refusal; quarantine and replacement refusal stay held.
    Abandoned(LifetimeError),
}

impl LoaderFinishOutcome {
    /// Finish/first-stop surfacing text. Settled outcomes have none. Waiting
    /// names the outstanding custody; Abandoned names the actual refusal and
    /// the held replacement block. Messages carry counts, never token bits.
    pub(crate) fn refusal_text(&self) -> Option<String> {
        match self {
            Self::Settled(_) | Self::AlreadySettled { .. } => None,
            Self::Waiting(error) => Some(format!("loader retirement waits: {error}")),
            Self::Abandoned(LifetimeError::StaleToken) => Some(
                "loader retirement fence is spent; the successor (if any) is untouched".to_string(),
            ),
            Self::Abandoned(error) => Some(format!(
                "loader native retirement failed to prove completion: {error}; replacement admission is blocked"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use p11scope_manifest::elf::{ElfAbi, SymbolFact};

    use super::super::identity::PinnedObjectId;
    use super::super::loader::LoaderContextSpec;
    use super::*;
    use crate::process::ProcessViewId;

    fn driver() -> LoaderAckDriver {
        LoaderAckDriver::new(4096).unwrap()
    }

    fn binding(object: u64) -> ExportBinding {
        ExportBinding {
            view: ProcessViewId(7),
            object: PinnedObjectId(object as u32),
            file_offset: 0x2100,
            hook: SymbolFact {
                virtual_address: 0x2100,
                file_offset: 0x2100,
            },
            abi: ElfAbi::Lp64,
        }
    }

    fn drain_at(fence_q: u64) -> ConsumerDrain {
        ConsumerDrain {
            consumer: fence_q,
            busy_before_q: false,
        }
    }

    /// Drive one incarnation through useful work and full retirement: every
    /// Engine queue charges and disposes, one scan registers and settles, one
    /// export binds, releases and settles, and the native lease completes.
    fn drive_to_fence(
        driver: &mut LoaderAckDriver,
        token: LoaderToken,
        fence_q: u64,
    ) -> LoaderRetirementFence {
        driver.activate(token).unwrap();
        driver.note_collected_record(token).unwrap();
        driver.note_record_dispatched(token).unwrap();
        driver.note_arm_scan_owed(token).unwrap();
        driver.note_arm_scan_served(token).unwrap();
        driver.note_mismatch_deferred(token).unwrap();
        driver.note_mismatch_settled(token).unwrap();
        driver.note_terminal_record_retained(token).unwrap();
        driver.note_terminal_record_dispatched(token).unwrap();
        driver.note_handoff_staged(token).unwrap();
        driver.note_handoff_moved(token).unwrap();
        driver.note_handoff_staged(token).unwrap();
        driver.note_handoff_rejected(token).unwrap();
        driver.note_scan_deferred(token).unwrap();
        driver.note_scan_settled(token).unwrap();
        let cookie = driver.note_export_bound(token, binding(9)).unwrap();
        driver.note_export_released(token, cookie).unwrap();
        driver.note_export_settled(token, cookie).unwrap();
        driver.note_short_acquired(token).unwrap();
        driver.note_state_inserted(token).unwrap();
        driver.note_state_removed(token, true).unwrap();
        driver.note_short_released(token).unwrap();
        let retirement = driver.begin_retirement(token).unwrap();
        driver.observe_closed_zero(&retirement).unwrap();
        driver.sample_q(&retirement, fence_q).unwrap();
        let drain = drain_at(fence_q);
        assert_eq!(
            driver.drain_prefix(&retirement, drain),
            Ok(PrefixOutcome::PrefixComplete)
        );
        driver.mint_fence(&retirement).unwrap()
    }

    #[test]
    fn t_l3_fence_mints_after_close_zero_and_q_sample_then_settles() {
        let mut driver = driver();
        let token = driver.prepare_new().unwrap();
        assert!(driver.replacement_blocked(token.slot()));
        let fence = drive_to_fence(&mut driver, token, 41);
        driver.note_link_cleanup(token, true).unwrap();
        let outcome = driver.finish_ack(&fence, drain_at(41));
        let LoaderFinishOutcome::Settled(receipt) = outcome else {
            panic!("a fully disposed retirement settles: {outcome:?}");
        };
        assert_eq!(receipt.slot(), token.slot());
        assert_eq!(receipt.retired_generation(), token.generation());
        assert_eq!(
            driver.slot_state(token.slot()),
            SlotView::Reclaimable {
                generation: token.generation()
            }
        );
        assert_eq!(driver.charged_contexts(), 0);
        assert!(!driver.replacement_blocked(token.slot()));
        assert_eq!(LoaderFinishOutcome::Settled(receipt).refusal_text(), None);
    }

    #[test]
    fn t_l3_mint_requires_close_zero_and_q_sample() {
        let mut driver = driver();
        let token = driver.prepare_new().unwrap();
        // No retirement cursor exists before activation closes over Active.
        assert_eq!(
            driver.begin_retirement(token),
            Err(LifetimeError::UnexpectedPhase {
                expected: "Active",
                actual: SlotPhase::Prepared,
            })
        );
        driver.activate(token).unwrap();
        let retirement = driver.begin_retirement(token).unwrap();
        assert_eq!(
            driver.mint_fence(&retirement),
            Err(LifetimeError::UnexpectedPhase {
                expected: "Draining",
                actual: SlotPhase::Closing,
            })
        );
        driver.observe_closed_zero(&retirement).unwrap();
        assert_eq!(
            driver.mint_fence(&retirement),
            Err(LifetimeError::UnexpectedPhase {
                expected: "Draining",
                actual: SlotPhase::ProducersQuiet,
            })
        );
        assert_eq!(driver.sample_q(&retirement, 7), Ok(()));
        assert_eq!(
            driver.sample_q(&retirement, 8),
            Err(LifetimeError::QAlreadyFixed)
        );
        driver.mint_fence(&retirement).unwrap();
    }

    #[test]
    fn t_l3_close_zero_refuses_while_producers_active() {
        let mut driver = driver();
        let token = driver.prepare_new().unwrap();
        driver.activate(token).unwrap();
        driver.note_short_acquired(token).unwrap();
        driver.note_state_inserted(token).unwrap();
        let retirement = driver.begin_retirement(token).unwrap();
        assert_eq!(
            driver.observe_closed_zero(&retirement),
            Err(LifetimeError::ProducersActive { short: 1, long: 1 })
        );
        driver.note_state_removed(token, true).unwrap();
        assert_eq!(
            driver.observe_closed_zero(&retirement),
            Err(LifetimeError::ProducersActive { short: 1, long: 0 })
        );
        driver.note_short_released(token).unwrap();
        driver.observe_closed_zero(&retirement).unwrap();
    }

    #[test]
    fn t_l3_ack_refuses_while_each_queue_outstanding() {
        // One twin per model queue: a single outstanding charge refuses the
        // acknowledgement with the exact queue and count; disposition clears it.
        type Endpoint = fn(&mut LoaderAckDriver, LoaderToken) -> Result<(), LifetimeError>;
        let charges = [
            (
                QueueKind::Collected,
                LoaderAckDriver::note_collected_record as Endpoint,
                LoaderAckDriver::note_record_dispatched as Endpoint,
            ),
            (
                QueueKind::Pending,
                LoaderAckDriver::note_arm_scan_owed as Endpoint,
                LoaderAckDriver::note_arm_scan_served as Endpoint,
            ),
            (
                QueueKind::Deferred,
                LoaderAckDriver::note_mismatch_deferred as Endpoint,
                LoaderAckDriver::note_mismatch_settled as Endpoint,
            ),
            (
                QueueKind::TerminalBatch,
                LoaderAckDriver::note_terminal_record_retained as Endpoint,
                LoaderAckDriver::note_terminal_record_dispatched as Endpoint,
            ),
            (
                QueueKind::SelectionHandoff,
                LoaderAckDriver::note_handoff_staged as Endpoint,
                LoaderAckDriver::note_handoff_moved as Endpoint,
            ),
        ];
        for (queue, charge, dispose) in charges {
            let mut driver = driver();
            let token = driver.prepare_new().unwrap();
            driver.activate(token).unwrap();
            charge(&mut driver, token).unwrap();
            let retirement = driver.begin_retirement(token).unwrap();
            driver.observe_closed_zero(&retirement).unwrap();
            driver.sample_q(&retirement, 3).unwrap();
            let fence = driver.mint_fence(&retirement).unwrap();
            driver.note_link_cleanup(token, true).unwrap();
            assert_eq!(
                driver.finish_ack(&fence, drain_at(3)),
                LoaderFinishOutcome::Waiting(LifetimeError::RecordsPending { queue, count: 1 }),
                "one outstanding {queue:?} record refuses the acknowledgement"
            );
            dispose(&mut driver, token).unwrap();
            assert!(
                matches!(
                    driver.finish_ack(&fence, drain_at(3)),
                    LoaderFinishOutcome::Settled(_)
                ),
                "disposing the {queue:?} record settles"
            );
        }
        // The rejection dispose site clears handoff custody exactly like the move.
        let mut driver = driver();
        let token = driver.prepare_new().unwrap();
        driver.activate(token).unwrap();
        driver.note_handoff_staged(token).unwrap();
        let retirement = driver.begin_retirement(token).unwrap();
        driver.observe_closed_zero(&retirement).unwrap();
        driver.sample_q(&retirement, 3).unwrap();
        let fence = driver.mint_fence(&retirement).unwrap();
        driver.note_link_cleanup(token, true).unwrap();
        assert_eq!(
            driver.finish_ack(&fence, drain_at(3)),
            LoaderFinishOutcome::Waiting(LifetimeError::RecordsPending {
                queue: QueueKind::SelectionHandoff,
                count: 1
            })
        );
        driver.note_handoff_rejected(token).unwrap();
        assert!(matches!(
            driver.finish_ack(&fence, drain_at(3)),
            LoaderFinishOutcome::Settled(_)
        ));
    }

    #[test]
    fn t_l3_ack_refuses_while_scans_outstanding() {
        let mut driver = driver();
        let token = driver.prepare_new().unwrap();
        let fence = drive_to_fence(&mut driver, token, 11);
        driver.note_scan_deferred(token).unwrap();
        driver.note_scan_deferred(token).unwrap();
        driver.note_link_cleanup(token, true).unwrap();
        assert_eq!(
            driver.finish_ack(&fence, drain_at(11)),
            LoaderFinishOutcome::Waiting(LifetimeError::ScansPending(2))
        );
        driver.note_scan_settled(token).unwrap();
        assert_eq!(
            driver.finish_ack(&fence, drain_at(11)),
            LoaderFinishOutcome::Waiting(LifetimeError::ScansPending(1))
        );
        driver.note_scan_settled(token).unwrap();
        assert!(matches!(
            driver.finish_ack(&fence, drain_at(11)),
            LoaderFinishOutcome::Settled(_)
        ));
    }

    #[test]
    fn t_l3_ack_refuses_while_descriptors_outstanding() {
        let mut driver = driver();
        let token = driver.prepare_new().unwrap();
        // New binds stop when admission closes, so the leftover binds early
        // and stays outstanding through the fenced retirement.
        let cookie = driver.note_export_bound(token, binding(11)).unwrap();
        let fence = drive_to_fence(&mut driver, token, 13);
        driver.note_link_cleanup(token, true).unwrap();
        assert_eq!(
            driver.finish_ack(&fence, drain_at(13)),
            LoaderFinishOutcome::Waiting(LifetimeError::DescriptorsPending(1))
        );
        // Links close first; the charge stays until deferred dispatch settles.
        assert_eq!(
            driver.note_export_settled(token, cookie),
            Err(LifetimeError::LinksStillOpen)
        );
        driver.note_export_released(token, cookie).unwrap();
        assert_eq!(
            driver.finish_ack(&fence, drain_at(13)),
            LoaderFinishOutcome::Waiting(LifetimeError::DescriptorsPending(1))
        );
        driver.note_export_settled(token, cookie).unwrap();
        assert!(matches!(
            driver.finish_ack(&fence, drain_at(13)),
            LoaderFinishOutcome::Settled(_)
        ));
    }

    #[test]
    fn t_l3_ack_refuses_until_link_cleanup_recorded() {
        let mut driver = driver();
        let token = driver.prepare_new().unwrap();
        let fence = drive_to_fence(&mut driver, token, 17);
        // Cleanup is checked before queues: even with a record outstanding,
        // the missing cleanup names the refusal.
        driver.note_collected_record(token).unwrap();
        assert_eq!(
            driver.finish_ack(&fence, drain_at(17)),
            LoaderFinishOutcome::Waiting(LifetimeError::CleanupIncomplete)
        );
        driver.note_record_dispatched(token).unwrap();
        assert_eq!(
            driver.finish_ack(&fence, drain_at(17)),
            LoaderFinishOutcome::Waiting(LifetimeError::CleanupIncomplete)
        );
        let waiting = LoaderFinishOutcome::Waiting(LifetimeError::CleanupIncomplete);
        assert_eq!(
            waiting.refusal_text(),
            Some("loader retirement waits: link cleanup is not recorded".to_string())
        );
        driver.note_link_cleanup(token, true).unwrap();
        assert!(matches!(
            driver.finish_ack(&fence, drain_at(17)),
            LoaderFinishOutcome::Settled(_)
        ));
    }

    #[test]
    fn t_l3_failed_link_cleanup_abandons_until_a_later_success() {
        let mut driver = driver();
        let token = driver.prepare_new().unwrap();
        let fence = drive_to_fence(&mut driver, token, 19);
        driver.note_link_cleanup(token, false).unwrap();
        assert_eq!(
            driver.finish_ack(&fence, drain_at(19)),
            LoaderFinishOutcome::Abandoned(LifetimeError::CleanupFailed)
        );
        let abandoned = LoaderFinishOutcome::Abandoned(LifetimeError::CleanupFailed);
        assert_eq!(
            abandoned.refusal_text(),
            Some(
                "loader native retirement failed to prove completion: link cleanup failed; custody is retained; replacement admission is blocked"
                    .to_string()
            )
        );
        // A failed cleanup retains custody without quarantining: the phase
        // stays Draining and a later success may still complete.
        assert_eq!(driver.phase_of(token), Some(SlotPhase::Draining));
        assert!(driver.replacement_blocked(token.slot()));
        driver.note_link_cleanup(token, true).unwrap();
        assert!(matches!(
            driver.finish_ack(&fence, drain_at(19)),
            LoaderFinishOutcome::Settled(_)
        ));
    }

    #[test]
    fn t_l3_ack_waits_for_the_fixed_prefix_drain() {
        let mut driver = driver();
        let token = driver.prepare_new().unwrap();
        let fence = drive_to_fence(&mut driver, token, 23);
        driver.note_link_cleanup(token, true).unwrap();
        let short = ConsumerDrain {
            consumer: 22,
            busy_before_q: false,
        };
        assert_eq!(
            driver.finish_ack(&fence, short),
            LoaderFinishOutcome::Waiting(LifetimeError::DrainIncomplete {
                consumer: 22,
                fence_q: 23
            })
        );
        let busy = ConsumerDrain {
            consumer: 22,
            busy_before_q: true,
        };
        assert_eq!(
            driver.finish_ack(&fence, busy),
            LoaderFinishOutcome::Waiting(LifetimeError::ForeignBusyBeforeQ)
        );
        assert!(matches!(
            driver.finish_ack(&fence, drain_at(23)),
            LoaderFinishOutcome::Settled(_)
        ));
    }

    #[test]
    fn t_l3_second_ack_after_reclaim_finds_stale_token_never_successor() {
        let mut driver = driver();
        let token = driver.prepare_new().unwrap();
        let fence = drive_to_fence(&mut driver, token, 29);
        driver.note_link_cleanup(token, true).unwrap();
        assert!(matches!(
            driver.finish_ack(&fence, drain_at(29)),
            LoaderFinishOutcome::Settled(_)
        ));
        // A repeated Finish settles idempotently: the slot is reclaimable for
        // the fence's own generation.
        assert_eq!(
            driver.finish_ack(&fence, drain_at(29)),
            LoaderFinishOutcome::AlreadySettled {
                slot: token.slot(),
                retired_generation: token.generation(),
            }
        );
        assert_eq!(
            LoaderFinishOutcome::AlreadySettled {
                slot: token.slot(),
                retired_generation: token.generation(),
            }
            .refusal_text(),
            None
        );
        // A successor reuses storage, never identity; the spent fence must not
        // name it.
        let successor = driver.prepare_new().unwrap();
        assert_eq!(successor.slot(), token.slot());
        assert_eq!(successor.generation(), token.generation() + 1);
        assert_eq!(
            driver.finish_ack(&fence, drain_at(29)),
            LoaderFinishOutcome::Abandoned(LifetimeError::StaleToken)
        );
        assert_eq!(
            LoaderFinishOutcome::Abandoned(LifetimeError::StaleToken).refusal_text(),
            Some(
                "loader retirement fence is spent; the successor (if any) is untouched".to_string()
            )
        );
        assert_eq!(driver.phase_of(successor), Some(SlotPhase::Prepared));
        assert_eq!(driver.phase_of(token), None);
    }

    #[test]
    fn t_l3_failed_native_removal_keeps_quarantine_and_refuses_replacement() {
        let mut driver = driver();
        let token = driver.prepare_new().unwrap();
        driver.activate(token).unwrap();
        driver.note_short_acquired(token).unwrap();
        driver.note_state_inserted(token).unwrap();
        assert_eq!(
            driver.note_state_removed(token, false),
            Err(LifetimeError::StateDeleteFailed)
        );
        assert_eq!(driver.phase_of(token), Some(SlotPhase::Quarantined));
        assert_eq!(
            driver.begin_retirement(token),
            Err(LifetimeError::PermanentQuarantine)
        );
        assert!(driver.replacement_blocked(token.slot()));
        assert_eq!(driver.charged_contexts(), 1);
        // Releasing the short guard changes nothing: the long lease was never
        // refunded and quarantine is permanent.
        driver.note_short_released(token).unwrap();
        assert_eq!(
            driver.begin_retirement(token),
            Err(LifetimeError::PermanentQuarantine)
        );
        assert!(driver.replacement_blocked(token.slot()));
        assert_eq!(driver.charged_contexts(), 1);
    }

    #[test]
    fn t_l3_quarantine_never_auto_reclaims_under_allocation_pressure() {
        let mut driver = driver();
        let quarantined = driver.prepare_new().unwrap();
        driver.activate(quarantined).unwrap();
        driver.note_short_acquired(quarantined).unwrap();
        driver.note_state_inserted(quarantined).unwrap();
        driver.note_state_removed(quarantined, false).unwrap_err();
        // Fill every other slot: the quarantined slot never frees, so no
        // successor token ever names it.
        let mut issued_slots = vec![quarantined.slot()];
        for _ in 1..super::super::loader_lifetime::MAX_LIFETIME_SLOTS {
            issued_slots.push(driver.prepare_new().unwrap().slot());
        }
        assert_eq!(driver.prepare_new(), Err(LifetimeError::CapacityExhausted));
        assert_eq!(driver.charged_contexts(), 256);
        assert_eq!(
            issued_slots
                .iter()
                .filter(|slot| **slot == quarantined.slot())
                .count(),
            1
        );
        assert_eq!(driver.phase_of(quarantined), Some(SlotPhase::Quarantined));
        assert!(driver.replacement_blocked(quarantined.slot()));
        assert_eq!(
            driver.begin_retirement(quarantined),
            Err(LifetimeError::PermanentQuarantine)
        );
    }

    #[test]
    fn t_l3_finish_waiting_keeps_custody_across_repeated_polls() {
        let mut driver = driver();
        let token = driver.prepare_new().unwrap();
        let fence = drive_to_fence(&mut driver, token, 31);
        driver.note_terminal_record_retained(token).unwrap();
        driver.note_link_cleanup(token, true).unwrap();
        let waiting = LoaderFinishOutcome::Waiting(LifetimeError::RecordsPending {
            queue: QueueKind::TerminalBatch,
            count: 1,
        });
        // Repeated Finish polls refuse identically: nothing is dropped, half
        // settled or auto-reclaimed between polls.
        for _ in 0..3 {
            assert_eq!(driver.finish_ack(&fence, drain_at(31)), waiting);
        }
        assert_eq!(driver.phase_of(token), Some(SlotPhase::Draining));
        driver.note_terminal_record_dispatched(token).unwrap();
        assert!(matches!(
            driver.finish_ack(&fence, drain_at(31)),
            LoaderFinishOutcome::Settled(_)
        ));
    }

    #[test]
    fn t_l3_abandoned_retirement_leaves_unrelated_contexts_untouched() {
        let mut driver = driver();
        let abandoned = driver.prepare_new().unwrap();
        driver.activate(abandoned).unwrap();
        driver.note_short_acquired(abandoned).unwrap();
        driver.note_state_inserted(abandoned).unwrap();
        driver.note_state_removed(abandoned, false).unwrap_err();
        // A sibling retires fully while the abandoned context stays
        // quarantined: no custody leaks across slots in either direction.
        let sibling = driver.prepare_new().unwrap();
        let fence = drive_to_fence(&mut driver, sibling, 37);
        driver.note_link_cleanup(sibling, true).unwrap();
        let outcome = driver.finish_ack(&fence, drain_at(37));
        let LoaderFinishOutcome::Settled(receipt) = outcome else {
            panic!("the unrelated sibling settles: {outcome:?}");
        };
        assert_eq!(receipt.slot(), sibling.slot());
        assert_eq!(driver.phase_of(abandoned), Some(SlotPhase::Quarantined));
        assert!(driver.replacement_blocked(abandoned.slot()));
        assert!(!driver.replacement_blocked(sibling.slot()));
        assert_eq!(driver.charged_contexts(), 1);
    }

    #[test]
    fn t_l3_repeated_settled_finish_changes_no_state() {
        let mut driver = driver();
        let token = driver.prepare_new().unwrap();
        let fence = drive_to_fence(&mut driver, token, 43);
        driver.note_link_cleanup(token, true).unwrap();
        assert!(matches!(
            driver.finish_ack(&fence, drain_at(43)),
            LoaderFinishOutcome::Settled(_)
        ));
        let state = driver.slot_state(token.slot());
        let charged = driver.charged_contexts();
        for _ in 0..3 {
            assert_eq!(
                driver.finish_ack(&fence, drain_at(43)),
                LoaderFinishOutcome::AlreadySettled {
                    slot: token.slot(),
                    retired_generation: token.generation(),
                }
            );
        }
        assert_eq!(driver.slot_state(token.slot()), state);
        assert_eq!(driver.charged_contexts(), charged);
    }

    #[test]
    fn t_l3_context_token_bridge_resolves_allocated_storage_only() {
        use p11scope_manifest::maps::{Device, MapEntry};

        let mut registry = LoaderRegistry::default();
        let spec = LoaderContextSpec {
            view: ProcessViewId(7),
            loader: PinnedObjectId(9),
            mapping: Some(MapEntry {
                start: 0x4000_0000,
                end: 0x4000_1000,
                file_offset: 0x2000,
                permissions: *b"r-xp",
                device: Device { major: 8, minor: 1 },
                inode: 7,
                raw_path: Some(b"/lib64/ld-linux-x86-64.so.2".to_vec()),
            }),
            hook: SymbolFact {
                virtual_address: 0x2100,
                file_offset: 0x2100,
            },
            state_address: None,
        };
        // Unallocated ids refuse without touching the registry.
        let unallocated = super::super::loader::LoaderContextId::from_case_id(0);
        assert_eq!(
            LoaderAckDriver::token_for_context(&registry, unallocated),
            None
        );
        let prepared = registry.preflight(spec).unwrap();
        let id = registry.prepare(prepared).unwrap();
        let token = LoaderAckDriver::token_for_context(&registry, id)
            .expect("allocated storage resolves to its adapter token");
        assert_eq!(token.generation(), 1);
        assert_eq!(
            LoaderAckDriver::context_for_token(&registry, token),
            Some(id)
        );
        // A foreign generation refuses even for the allocated slot.
        let foreign = LoaderToken::new(2, token.slot()).unwrap();
        assert_eq!(LoaderAckDriver::context_for_token(&registry, foreign), None);
    }
}
