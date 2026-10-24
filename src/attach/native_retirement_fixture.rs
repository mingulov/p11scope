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
            worker: CleanupWorker::pre_start_with(
                super::super::cleanup_worker::legacy_test_closer(closer),
                Arc::new(|| std::time::Duration::ZERO),
            ),
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

// The collected controls reuse the existing real mmap Q observer and the
// original held-file/FD worker. Harmless FDs are not a prepared BPF Session.
pub(super) struct CollectedRetirementFixture {
    native: RetirementFixture,
    observer: super::super::CollectedFinishQObserverForTest,
    producers: super::super::SessionDrainProducers,
    events: crate::events::EventDrain<crate::events::ScriptedRecords>,
    reads: std::cell::Cell<(usize, usize)>,
    transfers: std::cell::Cell<usize>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct OriginalLink {
    program: &'static str,
    slots: Vec<u32>,
    fds: Vec<std::os::fd::RawFd>,
    registration: Option<super::super::pid_continuity::RegistrationId>,
    generations: Vec<Option<u64>>,
}

impl CollectedRetirementFixture {
    pub(super) fn new(slots: &[Slot], pins: &PinnedObjects, closer: Closer) -> Self {
        let mut native = RetirementFixture::new(slots, pins, closer);
        // Actual PairBook state makes premature invalidation observable. The
        // controlled clock/health leaves confer no process-continuity proof.
        native.pairs.seal(
            &[super::super::pid_continuity::AttachRound {
                slots: slots.iter().map(|slot| slot.index).collect(),
                started_ns: Some(10),
                last_call_ns: Some(20),
            }],
            Some(super::super::pid_continuity::AttachBaseline { loss: 0, fault: 0 }),
            Some(0),
            &native.links,
            &super::super::current_static_sides_from(&native.links),
            &native.retained,
            || Some(30),
        );
        for slot in slots {
            assert_eq!(native.pairs.recorded_generation(slot.index), Some(1));
        }
        let producers = super::super::SessionDrainProducers {
            native: super::super::capture::NativeDomainId::mint(),
            events: crate::events::EventsDomain::test_standin(0xc011),
        };
        let events = crate::events::EventDrain::over_domain(
            crate::events::ScriptedRecords::records([vec![0]], 1),
            producers.events.clone(),
        );
        Self {
            native,
            observer: super::super::CollectedFinishQObserverForTest::new(&producers),
            producers,
            events,
            reads: std::cell::Cell::new((0, 0)),
            transfers: std::cell::Cell::new(0),
        }
    }

    pub(super) fn observe_q(&self) -> super::super::CollectedFinishQ {
        assert!(
            self.observer
                .observe(&self.producers, None, &self.events)
                .unwrap()
                .is_none(),
            "count0 without actual STOP cannot mint Q"
        );
        self.observer.request_stop();
        self.observer
            .observe(&self.producers, None, &self.events)
            .unwrap()
            .expect("the retained original observer sees actual STOP/count0")
    }

    pub(super) fn prepare(
        &mut self,
        q: &super::super::CollectedFinishQ,
        input: &mut Option<RetainedRetirementInput>,
        reserve: &crate::semantics_edge::resources::SemanticResourceReserver,
        work: usize,
    ) -> Result<RetirementProgress> {
        let (events, discovery) = collected_reads(&self.observer, &self.events, &self.reads);
        self.native.retirement.prepare_collected_with(
            self.observer.retained_owner(),
            q,
            UProbeScope::AllProcesses,
            input,
            reserve,
            &self.native.links,
            &self.native.retained,
            &self.native.pairs,
            &self.native.worker,
            events,
            discovery,
            work,
        )
    }

    pub(super) fn begin(
        &mut self,
        q: &super::super::CollectedFinishQ,
        ticket: &CollectedRetirementTicket,
        work: usize,
    ) -> Result<RetirementProgress> {
        let (events, discovery) = collected_reads(&self.observer, &self.events, &self.reads);
        let transfers = &self.transfers;
        self.native.retirement.begin_collected_with(
            self.observer.retained_owner(),
            q,
            UProbeScope::AllProcesses,
            ticket,
            &mut self.native.links,
            &mut self.native.retained,
            &mut self.native.pairs,
            &mut self.native.gaps,
            &self.native.worker,
            |link| {
                transfers.set(transfers.get() + 1);
                match link {
                    RegisteredLink::MultiUProbe { fds, .. } => Ok(vec![OwnedLink::Multi(fds)]),
                    _ => bail!("unexpected collected fixture ownership"),
                }
            },
            events,
            discovery,
            work,
        )
    }

    pub(super) fn poll(
        &mut self,
        q: &super::super::CollectedFinishQ,
        ticket: &CollectedRetirementTicket,
        work: usize,
    ) -> Result<RetirementProgress> {
        let (events, discovery) = collected_reads(&self.observer, &self.events, &self.reads);
        self.native.retirement.poll_collected_with(
            self.observer.retained_owner(),
            q,
            ticket,
            &self.native.worker,
            events,
            discovery,
            work,
        )
    }

    pub(super) fn poll_with_worker(
        &mut self,
        q: &super::super::CollectedFinishQ,
        ticket: &CollectedRetirementTicket,
        worker: &CleanupWorker,
    ) -> Result<RetirementProgress> {
        let (events, discovery) = collected_reads(&self.observer, &self.events, &self.reads);
        self.native.retirement.poll_collected_with(
            self.observer.retained_owner(),
            q,
            ticket,
            worker,
            events,
            discovery,
            1,
        )
    }

    pub(super) fn worker(&self) -> &CleanupWorker {
        &self.native.worker
    }

    pub(super) fn reads_and_transfers(&self) -> ((usize, usize), usize) {
        (self.reads.get(), self.transfers.get())
    }

    pub(super) fn native_counts(&self) -> (usize, usize, usize, usize) {
        let p = self.native.worker.progress();
        (p.total, p.attempted, p.released, p.uncertain)
    }

    pub(super) fn original_links(&self) -> Vec<OriginalLink> {
        use std::os::fd::AsRawFd as _;
        self.native
            .links
            .iter()
            .map(|link| match link {
                RegisteredLink::MultiUProbe {
                    program,
                    slots,
                    fds,
                    registration,
                } => OriginalLink {
                    program,
                    slots: slots.clone(),
                    fds: fds.iter().map(|fd| fd.as_raw_fd()).collect(),
                    registration: *registration,
                    generations: slots
                        .iter()
                        .map(|slot| self.native.pairs.recorded_generation(*slot))
                        .collect(),
                },
                _ => panic!("unexpected original fixture link"),
            })
            .collect()
    }

    pub(super) fn retained_slots(&self) -> Vec<Slot> {
        self.native
            .retained
            .values()
            .map(|target| target.slot.clone())
            .collect()
    }

    pub(super) fn original_file(&self) -> std::sync::Weak<File> {
        let file = self
            .native
            .retained
            .first_key_value()
            .unwrap()
            .1
            .retirement_lease()
            .unwrap();
        Arc::downgrade(&file)
    }

    pub(super) fn remaining_records(&self) -> (usize, usize) {
        (
            self.events.source().remaining(),
            self.observer.discovery_remaining(),
        )
    }

    pub(super) fn append_after_q(&mut self) {
        self.events.source_mut().push_record(vec![1]);
    }

    pub(super) fn join(&mut self) -> super::super::cleanup_worker::CleanupReceipt {
        self.native.worker.join()
    }
}

fn collected_reads<'a>(
    observer: &'a super::super::CollectedFinishQObserverForTest,
    events: &'a crate::events::EventDrain<crate::events::ScriptedRecords>,
    reads: &'a std::cell::Cell<(usize, usize)>,
) -> (
    impl FnOnce() -> Result<crate::events::EventsConsumptionCut> + 'a,
    impl FnOnce() -> Result<aya::maps::ring_buf::RingBufPositions> + 'a,
) {
    (
        move || {
            let (e, d) = reads.get();
            reads.set((e + 1, d));
            events
                .consumption_cut()
                .map_err(|reason| anyhow::anyhow!("original EVENTS cut refused: {reason:?}"))
        },
        move || {
            let (e, d) = reads.get();
            reads.set((e, d + 1));
            Ok(crate::events::discovery_drain_positions(
                observer.discovery_drain(),
            ))
        },
    )
}

// Lifecycle controls share the same original registry/worker, never a new Q.
impl CollectedRetirementFixture {
    pub(super) fn cancel(
        &mut self,
        input: Option<&RetainedRetirementInput>,
        ticket: Option<&CollectedRetirementTicket>,
        work: usize,
    ) -> Result<RetirementProgress> {
        self.native
            .retirement
            .cancel_collected_with(input, ticket, work)
    }

    pub(super) fn recorded_generation(&self, slot: u32) -> Option<u64> {
        self.native.pairs.recorded_generation(slot)
    }

    pub(super) fn blocking(&self) -> bool {
        self.native.retirement.blocking()
    }

    pub(super) fn combine_original_groups(&mut self) {
        let mut grouped = Vec::new();
        for program in ["p11_entry", "p11_return"] {
            let mut members = Vec::new();
            let mut owned = Vec::new();
            let mut index = 0;
            while index < self.native.links.len() {
                if self.native.links[index].producer()
                    == super::super::ProducerProgram::UProbe(program)
                {
                    let RegisteredLink::MultiUProbe { slots, fds, .. } =
                        self.native.links.remove(index)
                    else {
                        panic!("actual multi fixture ownership")
                    };
                    members.extend(slots);
                    owned.extend(fds);
                } else {
                    index += 1;
                }
            }
            grouped.push(RegisteredLink::MultiUProbe {
                program,
                slots: members,
                fds: owned,
                registration: self.native.pairs.register(),
            });
        }
        assert!(self.native.links.is_empty());
        self.native.links = grouped;
    }
}

type TestPreflightCheckpoint = (
    std::mem::Discriminant<PreflightPhase>,
    bool,
    usize,
    usize,
    usize,
    usize,
    [usize; 10],
);

impl CollectedRetirementFixture {
    pub(super) fn preflight_checkpoint(&self) -> Option<TestPreflightCheckpoint> {
        self.native.retirement.preflight.as_ref().map(|preflight| {
            (
                std::mem::discriminant(&preflight.phase),
                preflight.sizing.base,
                preflight.sizing.name,
                preflight.bytes,
                preflight.backing,
                preflight.high,
                preflight.ranks,
            )
        })
    }

    pub(super) fn preflight_at_input_coverage(&self) -> bool {
        self.native
            .retirement
            .preflight
            .as_ref()
            .is_some_and(|preflight| matches!(preflight.phase, PreflightPhase::InputCovered))
    }

    pub(super) fn preflight_at_admission(&self) -> bool {
        self.native
            .retirement
            .preflight
            .as_ref()
            .is_some_and(|preflight| matches!(preflight.phase, PreflightPhase::Admit))
    }

    pub(super) fn cursor_phase(&self) -> Option<std::mem::Discriminant<CollectedPhase>> {
        self.native
            .retirement
            .collected
            .as_ref()
            .map(|cursor| std::mem::discriminant(&cursor.phase))
    }

    // Fault injection uses actual move-only leases; no scalar lease mint or
    // production setter exposes the retained input's private payment.
    pub(super) fn replace_taken_input_storage(
        &mut self,
        storage: crate::semantics_edge::resources::ResourceLease,
    ) -> crate::semantics_edge::resources::ResourceLease {
        std::mem::replace(
            &mut self
                .native
                .retirement
                .collected
                .as_mut()
                .unwrap()
                .input
                .as_mut()
                .unwrap()
                .storage,
            storage,
        )
    }
}

impl CollectedRetirementFixture {
    pub(super) fn extraction_has_return_before_entry(&self) -> bool {
        self.native
            .links
            .iter()
            .any(|link| link.producer() == super::super::ProducerProgram::UProbe("p11_entry"))
            && self
                .native
                .retirement
                .collected
                .as_ref()
                .is_some_and(|cursor| {
                    !cursor.buckets[super::super::DetachOrder
                        .rank(&super::super::ProducerProgram::UProbe("p11_return"))
                        as usize]
                        .is_empty()
                })
    }

    pub(super) fn all_extracted_before_transfer(&self) -> bool {
        self.native.links.is_empty()
            && self
                .native
                .retirement
                .collected
                .as_ref()
                .is_some_and(|cursor| cursor.buckets.iter().any(|bucket| !bucket.is_empty()))
    }

    pub(super) fn original_return_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd as _;
        self.native
            .links
            .iter()
            .find_map(|link| match link {
                RegisteredLink::MultiUProbe {
                    program: "p11_return",
                    fds,
                    ..
                } => Some(fds[0].as_raw_fd()),
                _ => None,
            })
            .unwrap()
    }

    // Exact production abandonment helper precedes the existing remaining-
    // registry terminal submit. The harmless FD transfer is the native leaf.
    pub(super) fn abandon_for_drop(mut self) -> CleanupWorker {
        self.native
            .retirement
            .abandon_collected_with(Some(&self.native.worker), |original| match original {
                RegisteredLink::MultiUProbe { fds, .. } => Ok(vec![OwnedLink::Multi(fds)]),
                _ => bail!("unexpected original fixture registration"),
            });
        let leases = Arc::new(
            self.native
                .retained
                .values()
                .filter_map(RetainedStaticTarget::retirement_lease)
                .collect(),
        );
        let owned = std::mem::take(&mut self.native.links)
            .into_iter()
            .map(|original| {
                let producer = original.producer();
                let RegisteredLink::MultiUProbe { fds, .. } = original else {
                    panic!("real owned fixture FD")
                };
                (OwnedLink::Multi(fds), producer)
            })
            .collect();
        self.native.worker.submit(owned, leases, DetachOrder);
        self.native.worker
    }
}
