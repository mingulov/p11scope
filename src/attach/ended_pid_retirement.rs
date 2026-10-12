//! SPDX-License-Identifier: GPL-3.0-or-later
//! Eager retirement after the retained original named process group ended.

use super::pid_continuity::{PairBook, RegistrationId, current_pair};
use super::{RegisteredLink, RetainedStaticTarget, current_static_sides_from, plan_group_rebuild};
use crate::events::DiscoveryDomain;
use crate::plan::Slot;
use crate::process::{OriginalGenerationState, PidPin, ProcessView, ProcessViewId, ViewAdmission};
use aya::programs::uprobe::UProbeScope;
use std::collections::{BTreeMap, BTreeSet};

#[derive(PartialEq, Eq)]
struct RetiringPair {
    slot: Slot,
    entry: RegistrationId,
    return_: RegistrationId,
}

/// A private proof of one original owner's end and the exact registered pairs
/// selected for retirement. Neither stop nor a lifecycle hint can mint it.
pub(crate) struct EndedPidRetirement {
    domain: DiscoveryDomain,
    admission: ViewAdmission,
    view: ProcessViewId,
    original: PidPin,
    pairs: BTreeMap<u32, RetiringPair>,
}

/// Created only by final owner/endpoint validation, immediately before detach.
pub(super) struct CheckedEndedPidRetirement {
    affected: BTreeSet<u32>,
}

fn original_group_ended(state: Result<OriginalGenerationState, String>) -> bool {
    state == Ok(OriginalGenerationState::Exited)
}

fn retiring_pairs(
    slots: &[Slot],
    links: &[RegisteredLink],
    retained: &BTreeMap<u32, RetainedStaticTarget>,
) -> Option<BTreeMap<u32, RetiringPair>> {
    let requested: BTreeSet<_> = slots.iter().map(|slot| slot.index).collect();
    if requested.is_empty()
        || requested.len() != slots.len()
        || requested.len() > p11scope_ebpf_common::MAX_SLOTS as usize
        || plan_group_rebuild(links, &requested).is_some()
    {
        return None;
    }
    let sides = current_static_sides_from(links);
    slots
        .iter()
        .map(|slot| {
            if retained.get(&slot.index)?.slot != *slot {
                return None;
            }
            let (entry, return_) = current_pair(slot.index, links, &sides)?;
            Some((
                slot.index,
                RetiringPair {
                    slot: slot.clone(),
                    entry,
                    return_,
                },
            ))
        })
        .collect()
}

impl EndedPidRetirement {
    pub(super) fn prepare(
        domain: &DiscoveryDomain,
        scope: UProbeScope,
        view: &ProcessView,
        slots: &[Slot],
        links: &[RegisteredLink],
        retained: &BTreeMap<u32, RetainedStaticTarget>,
    ) -> Option<Self> {
        if !matches!(scope, UProbeScope::OneProcess(pid) if pid.get() == view.pid())
            || !original_group_ended(view.original_generation_state())
            || view.retained_pin().pidfd().is_err()
        {
            return None;
        }
        let original = view.retained_pin().try_clone().ok()?;
        if !original_group_ended(original.original_generation_state()) {
            return None;
        }
        Some(Self {
            domain: domain.clone(),
            admission: view.view_admission(),
            view: view.id(),
            original,
            pairs: retiring_pairs(slots, links, retained)?,
        })
    }

    pub(super) fn check(
        &self,
        domain: &DiscoveryDomain,
        scope: UProbeScope,
        view: &ProcessView,
        slots: &[Slot],
        links: &[RegisteredLink],
        retained: &BTreeMap<u32, RetainedStaticTarget>,
    ) -> Option<CheckedEndedPidRetirement> {
        self.check_with_original_state(domain, scope, view, slots, links, retained, || {
            self.original.original_generation_state()
        })
    }

    #[allow(clippy::too_many_arguments)] // Exact owner/registry facts plus the fallible original-pin read.
    pub(super) fn check_with_original_state(
        &self,
        domain: &DiscoveryDomain,
        scope: UProbeScope,
        view: &ProcessView,
        slots: &[Slot],
        links: &[RegisteredLink],
        retained: &BTreeMap<u32, RetainedStaticTarget>,
        original_state: impl FnOnce() -> Result<OriginalGenerationState, String>,
    ) -> Option<CheckedEndedPidRetirement> {
        if !self.domain.same_allocation(domain)
            || !self.admission.same_allocation(&view.view_admission())
            || self.view != view.id()
            || self.original.pid() != view.pid()
            || !matches!(scope, UProbeScope::OneProcess(pid) if pid.get() == view.pid())
            || !original_group_ended(view.original_generation_state())
            || !original_group_ended(original_state())
            || self.pairs != retiring_pairs(slots, links, retained)?
        {
            return None;
        }
        Some(CheckedEndedPidRetirement {
            affected: self.pairs.keys().copied().collect(),
        })
    }
}

/// Live detaches always begin the existing physical interval. A final checked
/// original-group end permits only this exact retirement to leave history alone.
pub(super) fn begin_detach_gap(
    book: &mut PairBook,
    affected: &BTreeSet<u32>,
    started_ns: Option<u64>,
    retained: &BTreeMap<u32, RetainedStaticTarget>,
    ended: Option<CheckedEndedPidRetirement>,
) {
    if ended.is_some_and(|proof| proof.affected == *affected) {
        return;
    }
    book.begin_gap(affected, started_ns, retained);
}
