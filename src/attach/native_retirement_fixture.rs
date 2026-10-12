//! SPDX-License-Identifier: GPL-3.0-or-later
//! Engine controls mint tickets only through real held ownership and worker closes.

use super::*;
use crate::discovery::identity::PinnedObjects;
use std::fs::File;

pub(crate) type Closer = Box<
    dyn FnMut(OwnedLink, super::super::ProducerProgram) -> std::result::Result<(), String> + Send,
>;

pub(crate) struct RetirementFixture {
    retirement: NativeRetirement,
    links: Vec<RegisteredLink>,
    retained: BTreeMap<u32, RetainedStaticTarget>,
    pairs: PairBook,
    gaps: Retirements,
    worker: CleanupWorker,
    pub(crate) begins: usize,
    pub(crate) polls: usize,
}

impl RetirementFixture {
    pub(crate) fn new(slots: &[Slot], pins: &PinnedObjects, closer: Closer) -> Self {
        let mut pairs = PairBook::default();
        let mut links = Vec::new();
        let mut retained = BTreeMap::new();
        for slot in slots {
            let held = pins.retain_inventory_target(slot.object).unwrap();
            assert_eq!(
                held.check_unchanged(),
                Ok(true),
                "fixture uses the original actual opened file"
            );
            retained.insert(
                slot.index,
                RetainedStaticTarget {
                    slot: slot.clone(),
                    path: held.attach_path(),
                    abi: held.abi(),
                    held: Some(held),
                },
            );
            for program in ["p11_entry", "p11_return"] {
                links.push(RegisteredLink::MultiUProbe {
                    program,
                    slots: vec![slot.index],
                    fds: vec![File::open("/dev/null").unwrap().into()],
                    registration: pairs.register(),
                });
            }
        }
        Self {
            retirement: NativeRetirement::default(),
            links,
            retained,
            pairs,
            gaps: Retirements::default(),
            worker: CleanupWorker::pre_start_with(closer, Arc::new(|| std::time::Duration::ZERO)),
            begins: 0,
            polls: 0,
        }
    }

    pub(crate) fn begin(&mut self, selected: &[Slot]) -> Result<Option<RetirementTicket>> {
        self.begins += 1;
        self.retirement.begin_with(
            UProbeScope::AllProcesses,
            false,
            false,
            false,
            selected,
            &mut self.links,
            &mut self.retained,
            &mut self.pairs,
            &mut self.gaps,
            &self.worker,
            |link| match link {
                RegisteredLink::MultiUProbe { fds, .. } => Ok(vec![OwnedLink::Multi(fds)]),
                _ => bail!("unexpected fixture ownership"),
            },
            super::super::pid_continuity::comparable_monotonic_ns,
        )
    }

    pub(crate) fn poll(&mut self, ticket: &RetirementTicket) -> RetirementPoll {
        self.polls += 1;
        self.retirement.poll(ticket, &self.worker)
    }

    pub(crate) fn has_slot_link(&self, slot: u32) -> bool {
        super::super::links_cover_slot(&self.links, slot)
    }

    pub(crate) fn blocking(&self) -> bool {
        self.retirement.blocking()
    }

    pub(crate) fn released(&self) -> usize {
        self.worker.progress().released
    }
}
