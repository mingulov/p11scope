//! SPDX-License-Identifier: GPL-3.0-or-later
//! Original call and effect positions from one actual conversion/settlement.

use super::{ConsumptionOrdinal, JournalAdapter, SealSuccess, SealedCall, SealedObjectPrefix};
use crate::semantics_edge::resources::{OWNED_ALLOCATION_PADDING, ResourceLease};
use crate::semantics_objects::state::SettlementTransition;
use crate::semantics_objects::{CallKey, CallToken, ObjectEffect, ObjectSemantics};
use std::mem::size_of;
use std::num::NonZeroUsize;
use std::ops::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealReplayPhase {
    Conversion,
    SettlementPrelude,
    Begin,
    End,
    /// Only the actual validated ABANDON-9/outcome_lost conversion mints
    /// this exact-subject history disposition. It never grants S1 replay.
    BoundedLoss,
    SettlementTail,
}

/// No independent constructor or effect copy. A call index is meaningful
/// only inside its owning prefix; an End phase comes from actual settlement.
#[derive(Debug)]
pub(crate) struct SealReplayStep {
    phase: SealReplayPhase,
    call: Option<NonZeroUsize>,
    cut: Option<ConsumptionOrdinal>,
    effects: Range<usize>,
}

impl SealReplayStep {
    pub(crate) fn phase(&self) -> super::SealReplayPhase {
        self.phase
    }

    pub(crate) fn cut(&self) -> Option<u64> {
        self.cut.map(ConsumptionOrdinal::cut)
    }

    pub(crate) fn effect_range(&self) -> Range<usize> {
        self.effects.clone()
    }
}

impl SealedObjectPrefix {
    pub(crate) fn replay_steps(&self) -> &[SealReplayStep] {
        &self.replay_steps
    }

    /// Includes retained earlier conversions omitted from the legacy delta.
    /// Table membership alone grants no permission to replay a staged head.
    pub(crate) fn replay_calls(&self) -> &[SealedCall] {
        &self.settled
    }

    fn owns_step(&self, step: &SealReplayStep) -> bool {
        self.replay_steps
            .as_ptr_range()
            .contains(&std::ptr::from_ref(step))
    }

    pub(crate) fn call_for_step(&self, step: &SealReplayStep) -> Option<&SealedCall> {
        if !self.owns_step(step) {
            return None;
        }
        self.settled.get(step.call?.get() - 1)
    }

    /// One charged index over the original table. Readiness/consumption is
    /// separate: this lookup only returns an actual retained terminal step.
    fn indexed_terminal(&self, admission: u64) -> Option<(usize, &SealReplayStep)> {
        let index = self.replay_index.as_ref()?;
        let entry = &index.locator[index
            .locator
            .binary_search_by_key(&admission, |entry| entry.key.admission())
            .ok()?];
        let original = self.settled.get(entry.index.get() - 1)?;
        if original.key != entry.key || original.ticket != entry.token {
            return None;
        }
        let position = entry.terminal?.get() - 1;
        let step = self.replay_steps.get(position)?;
        (matches!(
            step.phase,
            SealReplayPhase::End | SealReplayPhase::BoundedLoss
        ) && self.call_for_step(step) == Some(original))
        .then_some((position, step))
    }
}

/// Inline progress belongs to one ActiveSeal. Effect emission order and the
/// feed's exact admission frontier advance independently; neither mints End.
#[derive(Default)]
pub(super) struct SealReplayCursor {
    step: usize,
    effect: usize,
}

/// Only the owning journal/frame pairs this original result and its cursor.
/// The registry borrows the view; it cannot construct, clone or reseal it.
pub(crate) struct SealBatchDelivery<'frame> {
    seal: &'frame SealSuccess,
    cursor: &'frame mut SealReplayCursor,
}

impl<'frame> SealBatchDelivery<'frame> {
    pub(super) fn new(seal: &'frame SealSuccess, cursor: &'frame mut SealReplayCursor) -> Self {
        Self { seal, cursor }
    }

    pub(crate) fn seal(&self) -> &'frame SealSuccess {
        self.seal
    }

    /// A typed terminal is ready only after its original effect span passed.
    /// A later-emitted End may unblock the admission head while an earlier
    /// loss subject waits for that SAME head to be irreversibly consumed.
    pub(crate) fn ready_terminal(&self, admission: u64) -> Option<&'frame SealReplayStep> {
        let (index, step) = self.seal.prefix.indexed_terminal(admission)?;
        (index < self.cursor.step).then_some(step)
    }

    pub(crate) fn effects_complete(&self) -> bool {
        self.cursor.step == self.seal.prefix.replay_steps.len()
            && self.cursor.effect == self.seal.effects.effects.len()
    }

    /// Spend one work unit before this call: one actual effect, or one empty
    /// transition. Large spans keep their bounded subcursor between slices.
    /// None means no valid next transition; Some(None) is an original empty
    /// span and still requires work. No copied effects or batch-wide rescan.
    pub(crate) fn advance_effect(&mut self) -> Option<Option<&'frame ObjectEffect>> {
        let step = self.seal.prefix.replay_steps.get(self.cursor.step)?;
        if self.cursor.effect < step.effects.start || self.cursor.effect > step.effects.end {
            return None;
        }
        let effect = if self.cursor.effect < step.effects.end {
            let effect = self.seal.effects.effects.get(self.cursor.effect)?;
            self.cursor.effect += 1;
            Some(effect)
        } else {
            None
        };
        if self.cursor.effect == step.effects.end {
            self.cursor.step += 1;
        }
        Some(effect)
    }
}

impl SealSuccess {
    pub(crate) fn effects_for_step(&self, step: &SealReplayStep) -> Option<&[ObjectEffect]> {
        if !self.prefix.owns_step(step) {
            return None;
        }
        self.effects.effects.get(step.effects.clone())
    }
}

fn allocation_bytes<T>(capacity: usize) -> Option<usize> {
    capacity
        .checked_mul(size_of::<T>())?
        .checked_add(if capacity == 0 {
            0
        } else {
            OWNED_ALLOCATION_PADDING
        })
}

/// Sampled before any fault read, birth consumption or model mutation.
/// Global cardinalities conservatively include other domains and future cuts.
#[derive(Clone, Copy)]
pub(super) struct ReplayBounds {
    calls: usize,
    steps: usize,
}

impl ReplayBounds {
    pub(super) fn sample(adapter: &JournalAdapter, model: &ObjectSemantics) -> Option<Self> {
        let refused = adapter.refused.len();
        let begins = adapter
            .open
            .values()
            .filter(|entry| entry.converted_ticket.is_none())
            .count();
        let terminals = adapter
            .open
            .values()
            .filter(|entry| entry.end.is_some() && !entry.end_converted)
            .count();
        let abandoned = adapter
            .open
            .values()
            .filter(|entry| {
                entry.abandon.is_some_and(|staged| {
                    staged.abandon.reason() == super::JOURNAL_REASON_SYNC_RETURN_RESULT_LOST
                })
            })
            .count();
        let pending = model.replay_pending_count();
        let steps = refused
            .checked_add(usize::from(refused != 0))?
            .checked_add(begins)?
            .checked_add(terminals)?
            .checked_add(abandoned)?
            .checked_add(pending.checked_add(begins)?.checked_mul(2)?)?
            .checked_add(2)?;
        Some(Self {
            calls: adapter.open.len(),
            steps,
        })
    }

    /// The original table is already included in the existing result bound.
    pub(super) fn retained_bytes(self) -> Option<usize> {
        allocation_bytes::<SealReplayStep>(self.steps)
    }

    pub(super) fn temporary_bytes(self) -> Option<usize> {
        allocation_bytes::<CallLocator>(self.calls)
    }
}

#[derive(Debug)]
struct CallLocator {
    key: CallKey,
    token: CallToken,
    index: NonZeroUsize,
    terminal: Option<NonZeroUsize>,
}

/// Retain the SAME paid locator after conversion. No copied facts or second
/// replay queue: its entries only locate original table/step positions.
#[derive(Debug)]
pub(super) struct ReplayIndex {
    locator: Vec<CallLocator>,
    // The actual buffer drops before its original allocation is refunded.
    _storage: ResourceLease,
}

impl ReplayIndex {
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        allocation_bytes::<CallLocator>(self.locator.capacity())
    }
}

/// The existing result reservation pays calls/steps; the locator's SAME pool
/// lease follows its original allocation through successful replay delivery.
pub(super) struct ReplayPreparation {
    steps: Vec<SealReplayStep>,
    calls: Vec<SealedCall>,
    locator: Vec<CallLocator>,
    next_effect: usize,
    invalid: bool,
    _locator_storage: ResourceLease,
}

impl ReplayPreparation {
    pub(super) fn allocate(bounds: ReplayBounds, locator_storage: ResourceLease) -> Option<Self> {
        let mut steps = Vec::new();
        let mut calls = Vec::new();
        let mut locator = Vec::new();
        steps.try_reserve_exact(bounds.steps).ok()?;
        calls.try_reserve_exact(bounds.calls).ok()?;
        locator.try_reserve_exact(bounds.calls).ok()?;
        // Account actual capacities, including allocator padding. An allocator
        // returning excess capacity cannot make the paid bound silently grow.
        if allocation_bytes::<SealReplayStep>(steps.capacity())? > bounds.retained_bytes()?
            || calls.capacity() > bounds.calls
            || allocation_bytes::<CallLocator>(locator.capacity())? > bounds.temporary_bytes()?
        {
            return None;
        }
        Some(Self {
            steps,
            calls,
            locator,
            next_effect: 0,
            invalid: false,
            _locator_storage: locator_storage,
        })
    }

    pub(super) fn take_calls(&mut self) -> Vec<SealedCall> {
        std::mem::take(&mut self.calls)
    }

    fn index_calls(&mut self, calls: &[SealedCall]) -> bool {
        self.locator.clear();
        if calls.len() > self.locator.capacity() {
            return false;
        }
        for (index, call) in calls.iter().enumerate() {
            let Some(index) = index.checked_add(1).and_then(NonZeroUsize::new) else {
                return false;
            };
            self.locator.push(CallLocator {
                key: call.key,
                token: call.ticket,
                index,
                terminal: None,
            });
        }
        self.locator
            .sort_unstable_by_key(|entry| (entry.key, entry.token));
        self.locator
            .windows(2)
            .all(|pair| (pair[0].key, pair[0].token) != (pair[1].key, pair[1].token))
    }

    /// Preserve the begin-ordered legacy prefix and append only missing
    /// retained originals. Freeze indexes BEFORE settlement can prune them.
    pub(super) fn freeze_calls(
        &mut self,
        calls: &mut Vec<SealedCall>,
        retained: impl Iterator<Item = SealedCall>,
    ) -> bool {
        if !self.index_calls(calls) {
            return false;
        }
        for call in retained {
            if self
                .locator
                .binary_search_by_key(&(call.key, call.ticket), |entry| (entry.key, entry.token))
                .is_err()
            {
                if calls.len() == calls.capacity() {
                    return false;
                }
                calls.push(call);
            }
        }
        self.index_calls(calls)
    }

    fn record(
        &mut self,
        phase: SealReplayPhase,
        call: Option<NonZeroUsize>,
        cut: Option<ConsumptionOrdinal>,
        effects: Range<usize>,
    ) {
        if self.invalid
            || self.steps.len() == self.steps.capacity()
            || effects.start != self.next_effect
            || effects.end < effects.start
        {
            self.invalid = true;
            return;
        }
        self.next_effect = effects.end;
        self.steps.push(SealReplayStep {
            phase,
            call,
            cut,
            effects,
        });
    }

    pub(super) fn conversion(&mut self, cut: u64, effects: Range<usize>) {
        self.record(
            SealReplayPhase::Conversion,
            None,
            Some(ConsumptionOrdinal(cut)),
            effects,
        );
    }

    /// The owner calls this only after actual outcome_lost for the exact
    /// converted native entry. The complete original table is already frozen.
    pub(super) fn bounded_loss(
        &mut self,
        key: CallKey,
        token: CallToken,
        cut: u64,
        effects: Range<usize>,
    ) {
        self.terminal(SealReplayPhase::BoundedLoss, key, token, cut, effects);
    }

    fn terminal(
        &mut self,
        phase: SealReplayPhase,
        key: CallKey,
        token: CallToken,
        cut: u64,
        effects: Range<usize>,
    ) {
        let Ok(index) = self
            .locator
            .binary_search_by_key(&(key, token), |entry| (entry.key, entry.token))
        else {
            self.invalid = true;
            return;
        };
        let Some(step) = self.steps.len().checked_add(1).and_then(NonZeroUsize::new) else {
            self.invalid = true;
            return;
        };
        if self.locator[index].terminal.is_some() {
            self.invalid = true;
            return;
        }
        self.locator[index].terminal = Some(step);
        self.record(
            phase,
            Some(self.locator[index].index),
            Some(ConsumptionOrdinal(cut)),
            effects,
        );
    }

    pub(super) fn settlement(
        &mut self,
        transition: SettlementTransition,
        effects: Range<usize>,
        offset: usize,
    ) {
        let Some(start) = effects.start.checked_add(offset) else {
            self.invalid = true;
            return;
        };
        let Some(end) = effects.end.checked_add(offset) else {
            self.invalid = true;
            return;
        };
        let (phase, call) = match transition {
            SettlementTransition::Prelude => (SealReplayPhase::SettlementPrelude, None),
            SettlementTransition::Tail => (SealReplayPhase::SettlementTail, None),
            SettlementTransition::Begin { key, token, cut }
            | SettlementTransition::End { key, token, cut } => {
                let Ok(index) = self
                    .locator
                    .binary_search_by_key(&(key, token), |entry| (entry.key, entry.token))
                else {
                    self.invalid = true;
                    return;
                };
                let phase = if matches!(transition, SettlementTransition::End { .. }) {
                    SealReplayPhase::End
                } else {
                    SealReplayPhase::Begin
                };
                if phase == SealReplayPhase::End {
                    self.terminal(phase, key, token, cut, start..end);
                    return;
                }
                self.record(
                    phase,
                    Some(self.locator[index].index),
                    Some(ConsumptionOrdinal(cut)),
                    start..end,
                );
                return;
            }
        };
        self.record(phase, call, None, start..end);
    }

    pub(super) fn finish(self, effects: usize) -> Option<(Vec<SealReplayStep>, ReplayIndex)> {
        if self.invalid || self.next_effect != effects {
            return None;
        }
        let Self {
            steps,
            calls,
            locator,
            _locator_storage,
            ..
        } = self;
        drop(calls);
        Some((
            steps,
            ReplayIndex {
                locator,
                _storage: _locator_storage,
            },
        ))
    }
}
