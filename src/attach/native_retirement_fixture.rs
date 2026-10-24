//! SPDX-License-Identifier: GPL-3.0-or-later
//! Engine controls mint tickets only through real held ownership and worker closes.

use super::*;
use crate::discovery::identity::PinnedObjects;
use std::fs::File;

pub(crate) type Closer = Box<
    dyn FnMut(OwnedLink, super::super::ProducerProgram) -> std::result::Result<(), String> + Send,
>;

struct CollectedLeaf {
    observer: super::super::CollectedFinishQObserverForTest,
    producers: super::super::SessionDrainProducers,
    events: crate::events::EventDrain<crate::events::ScriptedRecords>,
    reads: std::cell::Cell<(usize, usize)>,
    transfers: std::cell::Cell<usize>,
    q: Box<super::super::CollectedFinishQ>,
    begun: Option<Arc<()>>,
}

pub(crate) struct RetirementFixture {
    retirement: NativeRetirement,
    links: Vec<RegisteredLink>,
    retained: BTreeMap<u32, RetainedStaticTarget>,
    pairs: PairBook,
    gaps: Retirements,
    worker: CleanupWorker,
    collected: Option<Box<CollectedLeaf>>,
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
            collected: None,
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

    pub(crate) fn new_collected(slots: &[Slot], pins: &PinnedObjects, closer: Closer) -> Self {
        let mut native = Self::new(slots, pins, closer);
        let (observer, producers, events) = seal_collected(&mut native, slots);
        assert!(
            observer
                .observe(&producers, None, &events)
                .unwrap()
                .is_none(),
            "count0 without actual STOP cannot mint Q"
        );
        observer.request_stop();
        let q = observer
            .observe(&producers, None, &events)
            .unwrap()
            .expect("the retained original observer sees actual STOP/count0");
        native.collected = Some(Box::new(CollectedLeaf {
            observer,
            producers,
            events,
            reads: std::cell::Cell::new((0, 0)),
            transfers: std::cell::Cell::new(0),
            q: Box::new(q),
            begun: None,
        }));
        native
    }

    pub(crate) fn collected_q(&self) -> Option<&super::super::CollectedFinishQ> {
        self.collected.as_ref().map(|leaf| &*leaf.q)
    }

    pub(crate) fn collected_prepare(
        &mut self,
        input: &mut Option<RetainedRetirementInput>,
        reserve: &crate::semantics_edge::resources::SemanticResourceReserver,
        work: usize,
    ) -> Result<RetirementProgress> {
        let Self {
            retirement,
            links,
            retained,
            pairs,
            worker,
            collected,
            ..
        } = self;
        let Some(leaf) = collected.as_mut() else {
            bail!("retirement fixture has no collected leaf");
        };
        let (events, discovery) = collected_reads(&leaf.observer, &leaf.events, &leaf.reads);
        retirement.prepare_collected_with(
            leaf.observer.retained_owner(),
            &leaf.q,
            UProbeScope::AllProcesses,
            input,
            reserve,
            links,
            retained,
            pairs,
            worker,
            events,
            discovery,
            work,
        )
    }

    pub(crate) fn collected_begin(
        &mut self,
        ticket: &CollectedRetirementTicket,
        work: usize,
    ) -> Result<RetirementProgress> {
        let Self {
            retirement,
            links,
            retained,
            pairs,
            gaps,
            worker,
            collected,
            begins,
            ..
        } = self;
        let Some(leaf) = collected.as_mut() else {
            bail!("retirement fixture has no collected leaf");
        };
        let (events, discovery) = collected_reads(&leaf.observer, &leaf.events, &leaf.reads);
        let transfers = &leaf.transfers;
        let progress = retirement.begin_collected_with(
            leaf.observer.retained_owner(),
            &leaf.q,
            UProbeScope::AllProcesses,
            ticket,
            links,
            retained,
            pairs,
            gaps,
            worker,
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
        )?;
        if matches!(progress.state, CollectedRetirementState::Pending)
            && !leaf
                .begun
                .as_ref()
                .is_some_and(|begun| Arc::ptr_eq(begun, &ticket.cursor))
        {
            leaf.begun = Some(Arc::clone(&ticket.cursor));
            *begins += 1;
        }
        Ok(progress)
    }

    pub(crate) fn collected_poll(
        &mut self,
        ticket: &CollectedRetirementTicket,
        work: usize,
    ) -> Result<RetirementProgress> {
        let Self {
            retirement,
            worker,
            collected,
            ..
        } = self;
        let Some(leaf) = collected.as_mut() else {
            bail!("retirement fixture has no collected leaf");
        };
        let (events, discovery) = collected_reads(&leaf.observer, &leaf.events, &leaf.reads);
        retirement.poll_collected_with(
            leaf.observer.retained_owner(),
            &leaf.q,
            ticket,
            worker,
            events,
            discovery,
            work,
        )
    }

    pub(crate) fn collected_cancel(
        &mut self,
        input: Option<&RetainedRetirementInput>,
        ticket: Option<&CollectedRetirementTicket>,
        work: usize,
    ) -> Result<RetirementProgress> {
        self.retirement
            .cancel_collected_with(input, ticket, &self.worker, work)
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

fn seal_collected(
    native: &mut RetirementFixture,
    slots: &[Slot],
) -> (
    super::super::CollectedFinishQObserverForTest,
    super::super::SessionDrainProducers,
    crate::events::EventDrain<crate::events::ScriptedRecords>,
) {
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
    let observer = super::super::CollectedFinishQObserverForTest::new(&producers);
    (observer, producers, events)
}

impl CollectedRetirementFixture {
    pub(super) fn new(slots: &[Slot], pins: &PinnedObjects, closer: Closer) -> Self {
        let mut native = RetirementFixture::new(slots, pins, closer);
        let (observer, producers, events) = seal_collected(&mut native, slots);
        Self {
            native,
            observer,
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

    pub(super) fn observe_q_again(&self) -> super::super::CollectedFinishQ {
        self.observer
            .observe(&self.producers, None, &self.events)
            .unwrap()
            .expect("the retained observer still sees STOP/count0")
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
            .cancel_collected_with(input, ticket, &self.native.worker, work)
    }

    pub(super) fn foreground_backing_items(&self) -> usize {
        self.native
            .retirement
            .collected
            .as_ref()
            .map_or(0, |cursor| {
                cursor.rows.len()
                    + cursor.choices.len()
                    + cursor.chunks.len()
                    + cursor.tickets.len()
                    + cursor.buckets.iter().map(Vec::len).sum::<usize>()
            })
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
        self.native.retirement.abandon_collected_with(
            &self.native.links,
            Some(&self.native.worker),
            |original| match original {
                RegisteredLink::MultiUProbe { fds, .. } => Ok(vec![OwnedLink::Multi(fds)]),
                _ => bail!("unexpected original fixture registration"),
            },
        );
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

// A small valid ELF DSO with two real .dynsym function definitions. This
// file-only fixture is parsed/hashed/pinned; it is never loaded or executed.
type ExportedOwnerCase = (
    tempfile::TempDir,
    PinnedObjects,
    CollectedRetirementFixture,
    Vec<Slot>,
    std::sync::Weak<[(String, u64)]>,
);

pub(super) fn exported_owner_case() -> ExportedOwnerCase {
    fn put16(bytes: &mut [u8], at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    let mut bytes = vec![0u8; 0x1010];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut bytes, 16, 3);
    put16(&mut bytes, 18, 62);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 32, 64);
    put64(&mut bytes, 40, 0x400);
    for (at, value) in [(52, 64), (54, 56), (56, 1), (58, 64), (60, 5), (62, 4)] {
        put16(&mut bytes, at, value);
    }
    put32(&mut bytes, 64, 1);
    put32(&mut bytes, 68, 5);
    for (at, value) in [
        (72, 0x1000),
        (80, 0x1000),
        (88, 0x1000),
        (96, 16),
        (104, 16),
        (112, 0x1000),
    ] {
        put64(&mut bytes, at, value);
    }
    let names = b"\0C_Sign\0C_Encrypt\0";
    bytes[0x200..0x200 + names.len()].copy_from_slice(names);
    for (symbol, name, offset) in [(1, 1, 0x1000), (2, 8, 0x1008)] {
        let at = 0x240 + 24 * symbol;
        put32(&mut bytes, at, name);
        bytes[at + 4] = 0x12;
        put16(&mut bytes, at + 6, 1);
        put64(&mut bytes, at + 8, offset);
        put64(&mut bytes, at + 16, 3);
    }
    let sections = b"\0.text\0.dynstr\0.dynsym\0.shstrtab\0";
    bytes[0x300..0x300 + sections.len()].copy_from_slice(sections);
    let headers: [[u64; 10]; 4] = [
        [1, 1, 6, 0x1000, 0x1000, 16, 0, 0, 1, 0],
        [7, 3, 2, 0x200, 0x200, names.len() as u64, 0, 0, 1, 0],
        [15, 11, 2, 0x240, 0x240, 72, 2, 1, 8, 24],
        [23, 3, 0, 0, 0x300, sections.len() as u64, 0, 0, 1, 0],
    ];
    for (index, header) in headers.into_iter().enumerate() {
        let at = 0x400 + 64 * (index + 1);
        put32(&mut bytes, at, header[0] as u32);
        put32(&mut bytes, at + 4, header[1] as u32);
        for (i, value) in header.iter().enumerate().take(6).skip(2) {
            put64(&mut bytes, at + 8 + (i - 2) * 8, *value);
        }
        put32(&mut bytes, at + 40, header[6] as u32);
        put32(&mut bytes, at + 44, header[7] as u32);
        put64(&mut bytes, at + 48, header[8]);
        put64(&mut bytes, at + 56, header[9]);
    }
    bytes[0x1000..0x1003].copy_from_slice(b"\x31\xc0\xc3");
    bytes[0x1008..0x100b].copy_from_slice(b"\x31\xc0\xc3");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("retained-owner.so");
    std::fs::write(&path, &bytes).unwrap();
    let file = File::open(&path).unwrap();
    let inspected = p11scope_manifest::identity::inspect_file(&file).unwrap();
    let elf = p11scope_manifest::elf::ElfSnapshot::read(&file).unwrap();
    assert_eq!(
        elf.exports_matching(&["C_Sign", "C_Encrypt"])
            .unwrap()
            .len(),
        2
    );
    assert!(
        elf.exports_matching(&["C_GetFunctionList"])
            .unwrap()
            .is_empty()
    );
    use std::os::unix::fs::MetadataExt as _;
    let metadata = file.metadata().unwrap();
    use p11scope_manifest::manifest::{
        Acquisition, Manifest, ObjectRecord, ProvenanceObject, SCHEMA, SurfaceRecord,
        SurfaceSource, WalkOutcome,
    };
    let manifest = Manifest {
        schema: SCHEMA.into(),
        module_path: path.to_str().unwrap().into(),
        objects: vec![ObjectRecord {
            id: 0,
            path: path.to_str().unwrap().into(),
            identity: inspected.identity.clone(),
        }],
        provenance_objects: vec![ProvenanceObject {
            path: path.to_str().unwrap().into(),
            device_major: u64::from(libc::major(metadata.dev())),
            device_minor: u64::from(libc::minor(metadata.dev())),
            inode: metadata.ino(),
            identity: inspected.identity,
        }],
        interface_list: Acquisition::Absent,
        // This fixture exports only the two named function bodies. Record
        // the required legacy acquisition honestly; no table was acquired.
        surfaces: vec![SurfaceRecord {
            source: SurfaceSource::LegacyFunctionList,
            acquisition: Acquisition::Absent,
            version: None,
            walk: WalkOutcome::NotWalked,
            functions: Vec::new(),
        }],
        vendor_interfaces: Vec::new(),
        alias_groups: Vec::new(),
        selection_evidence: Default::default(),
    };
    let pins = crate::discovery::identity::pin_manifest_objects(&manifest).unwrap();
    let object = pins.pinned().next().unwrap().id;
    let exports = pins.exports_for(object);
    assert_eq!(
        &*exports,
        &[
            (String::from("C_Sign"), 0x1000),
            (String::from("C_Encrypt"), 0x1008)
        ]
    );
    let export_owner = Arc::downgrade(&exports);
    let slots = exports
        .iter()
        .enumerate()
        .map(|(index, (name, offset))| Slot {
            index: index as u32,
            descriptor_index: 0,
            object,
            object_path: path.to_str().unwrap().into(),
            file_offset: *offset,
            names: vec![name.clone()],
            aliased: false,
            semantics: p11scope_ebpf_common::SlotSemantics::COUNT_ONLY,
            semantic_authorized: false,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![crate::plan::ModuleId(0)],
        })
        .collect::<Vec<_>>();
    let native = CollectedRetirementFixture::new(
        &slots,
        &pins,
        Box::new(|owned, _| {
            drop(owned);
            Ok(())
        }),
    );
    (dir, pins, native, slots, export_owner)
}

impl CollectedRetirementFixture {
    pub(super) fn original_worker_thread_id(&self) -> std::thread::ThreadId {
        self.native
            .worker
            .original_thread_id()
            .expect("the actual original worker")
    }

    pub(super) fn observe_retained_release(
        &self,
        entered: std::sync::mpsc::Sender<std::thread::ThreadId>,
        resume: std::sync::mpsc::Receiver<()>,
    ) {
        self.native
            .retirement
            .collected
            .as_ref()
            .unwrap()
            .retention
            .as_ref()
            .unwrap()
            .observe_release(entered, resume);
    }
}
