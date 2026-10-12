//! SPDX-License-Identifier: GPL-3.0-or-later
//! Session-owned quarantine for a whole global static retirement batch.

use super::cleanup_worker::{BatchStatus, BatchTicket};
use super::global_retirement::Retirements;
use super::pid_continuity::PairBook;
use super::{
    CleanupWorker, DetachOrder, OwnedLink, RegisteredLink, RetainedStaticTarget,
    current_static_sides_from, extract_selected_links, plan_group_rebuild, prune_linkless_retained,
};
use crate::plan::Slot;
use anyhow::{Result, bail};
use aya::programs::uprobe::UProbeScope;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct RetirementTicket {
    identity: Arc<TicketIdentity>,
}

struct TicketIdentity {
    allocation: Arc<()>,
    batch: Option<BatchTicket>,
    retired_slots: BTreeSet<u32>,
}

impl std::fmt::Debug for RetirementTicket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RetirementTicket(<Session-owned batch>)")
    }
}

impl PartialEq for RetirementTicket {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
    }
}
impl Eq for RetirementTicket {}

impl RetirementTicket {
    pub(crate) fn retired_slots(&self) -> &BTreeSet<u32> {
        &self.identity.retired_slots
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetirementPoll {
    Pending,
    Settled,
    Refused,
}

#[derive(Default)]
pub(super) struct NativeRetirement {
    allocation: Arc<()>,
    pending: Option<Pending>,
}

struct Pending {
    ticket: RetirementTicket,
    // The actual original opened file, offset and ABI remain held while any
    // old native ownership is pending or uncertain. Paths are never reopened.
    _points: BTreeMap<u32, RetainedStaticTarget>,
    refused: bool,
}

impl NativeRetirement {
    pub(super) fn blocking(&self) -> bool {
        self.pending.is_some()
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn begin_with(
        &mut self,
        scope: UProbeScope,
        stopped: bool,
        failed_cleanup: bool,
        ended: bool,
        requested: &[Slot],
        links: &mut Vec<RegisteredLink>,
        retained: &mut BTreeMap<u32, RetainedStaticTarget>,
        pairs: &mut PairBook,
        gaps: &mut Retirements,
        worker: &CleanupWorker,
        mut transfer: impl FnMut(RegisteredLink) -> Result<Vec<OwnedLink>>,
        clock: impl FnOnce() -> Option<u64>,
    ) -> Result<Option<RetirementTicket>> {
        if self.blocking() {
            bail!("an earlier global native retirement is pending or uncertain");
        }
        if !matches!(scope, UProbeScope::AllProcesses) || stopped || failed_cleanup || ended {
            return Ok(None);
        }
        let requested_indices: BTreeSet<_> = requested.iter().map(|slot| slot.index).collect();
        if requested_indices.is_empty()
            || requested_indices.len() != requested.len()
            || requested_indices.len() > p11scope_ebpf_common::MAX_SLOTS as usize
            || plan_group_rebuild(links, &requested_indices).is_some()
        {
            return Ok(None);
        }
        if links.iter().any(|link| {
            link.slots()
                .iter()
                .any(|slot| requested_indices.contains(slot))
                && !matches!(link.producer(), super::ProducerProgram::UProbe(program)
                if super::static_probe_side(program).is_some())
        }) {
            return Ok(None);
        }
        let choices: Vec<_> = links
            .iter()
            .map(|link| {
                matches!(
                    link,
                    RegisteredLink::UProbe { .. } | RegisteredLink::MultiUProbe { .. }
                ) && !link.slots().is_empty()
                    && link
                        .slots()
                        .iter()
                        .all(|slot| requested_indices.contains(slot))
            })
            .collect();
        let retired_slots: BTreeSet<_> = links
            .iter()
            .zip(&choices)
            .filter(|(_, chosen)| **chosen)
            .flat_map(|(link, _)| link.slots().iter().copied())
            .collect();
        if retired_slots.is_empty() {
            return Ok(None);
        }
        let sides = current_static_sides_from(links);
        let mut points = BTreeMap::new();
        for index in &retired_slots {
            let Some(target) = retained.get(index) else {
                return Ok(None);
            };
            // Requested indices select within this Session only. Replacement
            // descriptors already carry updated metadata; old physical
            // authority comes solely from the original held target and pair.
            if target.slot.index != *index
                || super::pid_continuity::current_pair(*index, links, &sides).is_none()
                || target.held.as_ref().is_none_or(|held| {
                    held.abi() != target.abi
                        || held.attach_path() != target.path
                        || held.check_unchanged() != Ok(true)
                })
            {
                return Ok(None);
            }
            points.insert(*index, target.clone());
        }
        // Before any ownership transfer, an unavailable prestarted worker is
        // an untouched fallback. The caller can synchronously detach its still
        // owned original links; no physical gap or quarantine is opened here.
        if worker.live_admission().is_err() {
            return Ok(None);
        }
        gaps.retire_selected(
            scope,
            false,
            links,
            &choices,
            &BTreeSet::new(),
            retained,
            clock,
        );
        let mut choices = choices.into_iter();
        let selected = extract_selected_links(links, pairs, |_| choices.next().unwrap());
        prune_linkless_retained(retained, links);
        let mut owned = Vec::new();
        let mut refused = false;
        for link in selected {
            let producer = link.producer();
            match transfer(link) {
                Ok(transferred) if !transferred.is_empty() => {
                    owned.extend(transferred.into_iter().map(|link| (link, producer)));
                }
                result => {
                    refused = true;
                    worker.note_transfer_failed(1);
                    worker.note_failure(match result {
                        Err(error) => format!("global native ownership transfer: {error:#}"),
                        Ok(_) => "global native ownership transfer produced no owned handle".into(),
                    });
                }
            }
        }
        let batch = if owned.is_empty() {
            None
        } else {
            match worker.submit_live(owned, DetachOrder) {
                Ok(batch) => Some(batch),
                Err(failure) => {
                    refused = true;
                    worker.retain_unsubmitted(failure);
                    None
                }
            }
        };
        let ticket = RetirementTicket {
            identity: Arc::new(TicketIdentity {
                allocation: Arc::clone(&self.allocation),
                batch,
                retired_slots,
            }),
        };
        self.pending = Some(Pending {
            ticket: ticket.clone(),
            _points: points,
            refused,
        });
        // Once ownership was extracted this can never return untouched None,
        // including a transfer/channel failure with no successful worker batch.
        Ok(Some(ticket))
    }

    pub(super) fn poll(
        &mut self,
        ticket: &RetirementTicket,
        worker: &CleanupWorker,
    ) -> RetirementPoll {
        let Some(pending) = &mut self.pending else {
            return RetirementPoll::Refused;
        };
        if !Arc::ptr_eq(&ticket.identity.allocation, &self.allocation)
            || ticket != &pending.ticket
            || pending.refused
        {
            return RetirementPoll::Refused;
        }
        let Some(batch) = &ticket.identity.batch else {
            return RetirementPoll::Refused;
        };
        if !batch.belongs_to(worker) {
            return RetirementPoll::Refused;
        }
        match batch.status() {
            BatchStatus::Pending if worker.running() => RetirementPoll::Pending,
            BatchStatus::Pending => {
                pending.refused = true;
                RetirementPoll::Refused
            }
            BatchStatus::Failed => {
                pending.refused = true;
                RetirementPoll::Refused
            }
            BatchStatus::Released => {
                self.pending = None;
                RetirementPoll::Settled
            }
        }
    }
}

#[cfg(test)]
#[path = "native_retirement_tests.rs"]
mod tests;
