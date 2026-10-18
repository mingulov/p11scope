//! SPDX-License-Identifier: GPL-3.0-or-later
//! Draining the EVENTS ring buffer into typed `Event` values. Every
//! record is size-checked before it is treated as an `Event`: a record of
//! the wrong length means the writer and reader have drifted, and that
//! must be visible as a `malformed` count, never guessed at via a
//! transmute of the wrong number of bytes.

use anyhow::{Context as _, Result};
use aya::Ebpf;
use aya::maps::{Map, MapData};
use p11scope_ebpf_common::object_journal::{JournalRecord, decode_journal_record};
use p11scope_ebpf_common::object_wire::{
    OBJECT_TAIL_BYTES, ObjectDescriptorWire, ValidatedObjectCall,
};
use p11scope_ebpf_common::{
    DiscoveryRecord, Event, EventRecord, MAX_DESCRIPTORS, event_type, valid_discovery_record,
};
use std::mem::size_of;
use std::ops::{ControlFlow, Deref};
use std::{
    num::NonZeroU64,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    sync::Arc,
};

/// Retains one live EVENTS map so its kernel ID cannot be reused while history survives.
#[derive(Clone)]
pub(crate) struct EventsDomain(Arc<RetainedEvents>);
struct RetainedEvents {
    id: NonZeroU64,
    _fd: OwnedFd,
}
impl EventsDomain {
    pub(crate) fn from_events(ebpf: &Ebpf) -> Result<Self> {
        let Map::RingBuf(map) = ebpf.map("EVENTS").context("EVENTS map")? else {
            anyhow::bail!("EVENTS is not a ring buffer");
        };
        let id = NonZeroU64::new(u64::from(map.info()?.id())).context("EVENTS map ID is zero")?;
        let fd = map
            .fd()
            .as_fd()
            .try_clone_to_owned()
            .context("retaining EVENTS map descriptor")?;
        Ok(Self(Arc::new(RetainedEvents { id, _fd: fd })))
    }
    pub(crate) fn same_allocation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub(crate) fn id(&self) -> u64 {
        self.0.id.get()
    }
}

/// Retains the exact DISCOVERY map independently of the loaded BPF object.
#[derive(Clone)]
pub(crate) struct DiscoveryDomain(Arc<RetainedDiscovery>);
struct RetainedDiscovery {
    id: NonZeroU64,
    _fd: OwnedFd,
}
impl DiscoveryDomain {
    pub(crate) fn from_discovery(ebpf: &Ebpf) -> Result<Self> {
        let Map::RingBuf(map) = ebpf.map("DISCOVERY").context("DISCOVERY map")? else {
            anyhow::bail!("DISCOVERY is not a ring buffer");
        };
        let id =
            NonZeroU64::new(u64::from(map.info()?.id())).context("DISCOVERY map ID is zero")?;
        let fd = map
            .fd()
            .as_fd()
            .try_clone_to_owned()
            .context("retaining DISCOVERY map descriptor")?;
        Ok(Self(Arc::new(RetainedDiscovery { id, _fd: fd })))
    }
    pub(crate) fn same_allocation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub(crate) fn id(&self) -> u64 {
        self.0.id.get()
    }
}

#[cfg(test)]
impl DiscoveryDomain {
    pub(crate) fn test_standin(id: u64) -> Self {
        Self(Arc::new(RetainedDiscovery {
            id: NonZeroU64::new(id).unwrap(),
            _fd: std::fs::File::open("/dev/null").unwrap().into(),
        }))
    }
}

impl AsFd for DiscoveryDomain {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0._fd.as_fd()
    }
}

impl AsFd for EventsDomain {
    /// The retained EVENTS map descriptor, for readiness waits. Polling
    /// observes readability without consuming anything; the single
    /// consumer stays the event drain.
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0._fd.as_fd()
    }
}

impl EventsDomain {
    /// Synthetic identity for reducer tests; the owned FD is NOT a BPF map.
    #[cfg(test)]
    pub(crate) fn test_standin(id: u64) -> Self {
        Self::test_with_fd(id, std::fs::File::open("/dev/null").unwrap().into())
    }
    #[cfg(test)]
    pub(crate) fn test_with_fd(id: u64, fd: OwnedFd) -> Self {
        Self(Arc::new(RetainedEvents {
            id: NonZeroU64::new(id).unwrap(),
            _fd: fd,
        }))
    }
}

/// Records one live poll consumes before returning to its caller's duration,
/// signal and `--max-events` checks. Sized against small explicit rings
/// (256 KiB holds 780): a poll stopped here has emptied such a ring
/// repeatedly and leaves only what the producer wrote during the poll
/// itself; an overflow before the next tick is the kernel's loss counter,
/// reported as `LOST n events` / `ring_loss` like any other.
pub const LIVE_POLL_QUANTUM: usize = 4096;

/// Explicit record bound of the post-detach terminal `EVENTS` drain: the
/// terminal poll takes at most this many records, and backlog past it is
/// reported as truncation, never silently absorbed. Sixteen live quanta —
/// several ringfuls at the largest supported ring — so a bound stop is a
/// real detach-window backlog, not a calibration miss.
pub const TERMINAL_DRAIN_BOUND: usize = 65536;

/// The bound one poll of the `EVENTS` ring gets: the quantum while producers
/// can still refill it, the explicit terminal bound once they are all
/// detached. A partially failed detach keeps the ring live, so it keeps
/// the live bound.
pub fn poll_quantum(producers_detached: bool) -> Option<usize> {
    if producers_detached {
        Some(TERMINAL_DRAIN_BOUND)
    } else {
        Some(LIVE_POLL_QUANTUM)
    }
}

fn decode_exact<T: aya::Pod>(bytes: &[u8]) -> Option<T> {
    if bytes.len() != size_of::<T>() {
        return None;
    }
    // SAFETY: the exact length was checked and all shared transport types are
    // repr(C) Pod values. Ring records need not satisfy T's alignment.
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}

/// Decodes one ring-buffer record into its `Event`, or `None` if its length
/// differs from `size_of::<EventRecord>()` or its root affiliation is invalid.
/// The record's private continuity tail is dropped here: renderers and
/// reducers only ever receive the bare `Event`.
pub fn decode(bytes: &[u8]) -> Option<Event> {
    decode_record(bytes).map(|record| record.event)
}

/// The whole `EVENTS` record, private continuity included (Task 3 Stage A).
/// Only the load-instance router may consume the continuity.
pub(crate) fn decode_record(bytes: &[u8]) -> Option<EventRecord> {
    let record: EventRecord = decode_exact(bytes)?;
    (record.event.root_affiliation <= 1).then_some(record)
}

pub(crate) fn decode_discovery(bytes: &[u8]) -> Option<DiscoveryRecord> {
    let record = decode_exact(bytes)?;
    valid_discovery_record(&record).then_some(record)
}

/// One decoded EVENTS record with its optional validated object tail.
/// Slice D wires this envelope through the H3 drain, collection, pending
/// queue and routed call on the attested allowlisted lane only. Like the
/// base record it wraps, it is a plain validated value; move-only
/// discipline lives one level up in the owned routed call and evidence.
#[derive(Clone, Copy)]
pub(crate) struct DecodedEventRecord {
    pub(crate) base: EventRecord,
    pub(crate) object: Option<ValidatedObjectCall>,
}

/// Decode the exact 368/608-byte forms atomically; the extended form is
/// CALL-only and returns the validated tail intact. The prefix alone
/// never validates: a malformed tail refuses the whole record even when
/// its Event prefix looks valid. Bare `decode_record` stays 368-only.
pub(crate) fn decode_object_record(
    bytes: &[u8],
    descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
) -> Option<DecodedEventRecord> {
    if bytes.len() == size_of::<EventRecord>() {
        return decode_record(bytes).map(|base| DecodedEventRecord { base, object: None });
    }
    if bytes.len() != size_of::<EventRecord>() + OBJECT_TAIL_BYTES {
        return None;
    }
    let base = decode_record(&bytes[..size_of::<EventRecord>()])?;
    if base.event.event_type != event_type::CALL {
        return None;
    }
    let index = u32::from_le_bytes(bytes[372..376].try_into().ok()?);
    if index == 0 || index >= MAX_DESCRIPTORS {
        return None;
    }
    let object = ValidatedObjectCall::validate(
        &bytes[size_of::<EventRecord>()..],
        &descriptors[index as usize],
    )?;
    Some(DecodedEventRecord {
        base,
        object: Some(object),
    })
}

type ObjectTransportRows = Arc<[ObjectDescriptorWire; MAX_DESCRIPTORS as usize]>;

/// Ordinary consumers receive the base only after the entire producer record
/// validates. Transport rows authorize its wire form, never semantic admission.
fn decode_transport_record(
    bytes: &[u8],
    descriptors: Option<&[ObjectDescriptorWire; MAX_DESCRIPTORS as usize]>,
) -> Option<EventRecord> {
    match descriptors {
        Some(rows) => decode_object_record(bytes, rows).map(|record| record.base),
        None => decode_record(bytes),
    }
}

#[derive(Clone, Copy)]
#[allow(clippy::large_enum_variant)] // The fixed 920-byte ring ABI stays allocation-free per dequeue.
pub(crate) enum DiscoveryItem {
    Record(DiscoveryRecord),
    Malformed,
}

/// One ring's records, one at a time. `RingBuf::next` lends each record for
/// as long as the ring stays borrowed, so this is a lending method rather
/// than an `Iterator`; the scripted test source hands out owned bytes.
pub trait RecordSource {
    fn next_record(&mut self) -> Option<impl Deref<Target = [u8]> + '_>;

    /// Kernel-discarded reservations this source's reader has consumed
    /// so far. The retained Aya reader counts them; scripted sources
    /// report none unless a test says otherwise.
    fn discarded(&self) -> u64 {
        0
    }
}

impl RecordSource for aya::maps::RingBuf<MapData> {
    fn next_record(&mut self) -> Option<impl Deref<Target = [u8]> + '_> {
        self.next()
    }

    fn discarded(&self) -> u64 {
        self.discarded()
    }
}

/// The session's single retained `EVENTS` consumer: an owned map-backed
/// ring reader over a duplicate of the retained domain descriptor. It
/// owns its mappings and descriptor for the whole capture, so one cursor
/// and one malformed total survive every live, root-tail and terminal
/// poll without per-poll mmap/munmap and identity-query work.
pub type OwnedDrain = EventDrain<aya::maps::RingBuf<MapData>>;

pub(crate) enum BoundedRecord<T> {
    Item(T),
    Pending,
    Reached,
}

/// A proven-Q bounded drain met an uncommitted (BUSY) record below the
/// Q stop. Under a proven Q no admitted writer remains, so this is the
/// ungated-writer signature. It carries the unread span, so committed
/// records behind it are accounted, never silently lost.
#[derive(Debug)]
pub(crate) enum BoundedDrainError {
    UngatedWriterBeforeQ { consumer: usize, stop: usize },
}

impl std::fmt::Display for BoundedDrainError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UngatedWriterBeforeQ { consumer, stop } => write!(
                formatter,
                "ungated writer before Q: consumer {consumer}, stop {stop} ({} bytes unread)",
                stop.wrapping_sub(*consumer),
            ),
        }
    }
}

impl std::error::Error for BoundedDrainError {}

/// Scheduling seam only. The native implementation delegates every byte read
/// and discard to Aya's existing bounded parser.
pub(crate) trait BoundedRecordSource: RecordSource {
    fn positions(&self) -> aya::maps::ring_buf::RingBufPositions;
    fn consumer(&self) -> usize;
    fn bounded_record(
        &mut self,
        stop: usize,
    ) -> Result<BoundedRecord<impl Deref<Target = [u8]> + '_>>;
}
impl BoundedRecordSource for aya::maps::RingBuf<MapData> {
    fn positions(&self) -> aya::maps::ring_buf::RingBufPositions {
        self.snapshot_positions()
    }
    fn consumer(&self) -> usize {
        self.consumer_position()
    }
    fn bounded_record(
        &mut self,
        stop: usize,
    ) -> Result<BoundedRecord<impl Deref<Target = [u8]> + '_>> {
        use aya::maps::ring_buf::BoundedRingBufRead;
        Ok(match self.next_before(stop)? {
            BoundedRingBufRead::Item(item) => BoundedRecord::Item(item),
            BoundedRingBufRead::Pending => BoundedRecord::Pending,
            BoundedRingBufRead::Reached => BoundedRecord::Reached,
        })
    }
}

pub(crate) const ROOT_TAIL_FENCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RootTailProgress {
    Pending,
    Yielded,
    Reached,
}

/// Owns the original child and retained map independently of borrowed drains.
pub(crate) struct OwnedRootTail {
    exit: crate::run::OriginalRootExit,
    positions: Option<aya::maps::ring_buf::RingBufPositions>,
    remaining: usize,
    deadline: std::time::Instant,
    reached: bool,
    failed: bool,
}
pub(crate) struct ConsumedOriginalRootTail {
    exit: crate::run::OriginalRootExit,
}
impl ConsumedOriginalRootTail {
    pub(crate) fn domain(&self) -> u64 {
        self.exit.domain().id()
    }
}
impl OwnedRootTail {
    /// Copies only the saved boundary and progress; never samples the producer.
    #[cfg(test)]
    pub(crate) fn observed_boundary(
        &self,
    ) -> (Option<aya::maps::ring_buf::RingBufPositions>, usize, bool) {
        (self.positions, self.remaining, self.reached)
    }

    pub(crate) fn new(exit: crate::run::OriginalRootExit, deadline: std::time::Instant) -> Self {
        Self {
            exit,
            positions: None,
            remaining: 0,
            deadline,
            reached: false,
            failed: false,
        }
    }
    pub(crate) fn check(&mut self, cancelled: bool, now: std::time::Instant) -> Result<()> {
        let reason = if self.failed {
            Some("previous failure")
        } else if cancelled {
            Some("cancelled")
        } else if now >= self.deadline {
            Some("deadline")
        } else {
            None
        };
        if let Some(reason) = reason {
            self.failed = true;
            anyhow::bail!(
                "root_tail_incomplete: {reason}; remaining={}",
                self.remaining
            );
        }
        Ok(())
    }
    /// Expected cancellation abandons only this optional retirement. Existing
    /// failure and deadline checks take precedence; they remain genuine errors.
    pub(crate) fn cancellation(
        &mut self,
        cancelled: bool,
        now: std::time::Instant,
    ) -> Result<Option<usize>> {
        self.check(false, now)?;
        if cancelled {
            self.failed = true;
            Ok(Some(self.remaining))
        } else {
            Ok(None)
        }
    }
    pub(crate) fn complete(self) -> Result<ConsumedOriginalRootTail> {
        anyhow::ensure!(
            self.reached && !self.failed,
            "root_tail_incomplete: prefix not reduced"
        );
        Ok(ConsumedOriginalRootTail { exit: self.exit })
    }
}

impl<S: RecordSource> EventDrain<S> {
    pub(crate) fn begin_root_tail(&mut self, tail: &mut OwnedRootTail) -> Result<()>
    where
        S: BoundedRecordSource,
    {
        let result = (|| {
            tail.check(false, std::time::Instant::now())?;
            anyhow::ensure!(tail.positions.is_none(), "root tail snapshot already taken");
            anyhow::ensure!(
                self.domain_id() == tail.exit.domain().id(),
                "foreign EVENTS domain"
            );
            let p = self.source.positions();
            let distance = p.producer.wrapping_sub(p.consumer);
            anyhow::ensure!(
                p.capacity >= 8
                    && p.capacity.is_power_of_two()
                    && p.consumer.is_multiple_of(8)
                    && p.producer.is_multiple_of(8)
                    && distance < p.capacity,
                "invalid root tail boundary"
            );
            tail.remaining = distance;
            tail.positions = Some(p);
            Ok(())
        })();
        if result.is_err() {
            tail.failed = true;
        }
        result.context("root_tail_incomplete: snapshot")
    }

    pub(crate) fn poll_root_tail(
        &mut self,
        tail: &mut OwnedRootTail,
        quantum: usize,
        mut reduce: impl FnMut(Event) -> Result<()>,
    ) -> Result<RootTailProgress>
    where
        S: BoundedRecordSource,
    {
        let result = (|| {
            tail.check(false, std::time::Instant::now())?;
            let p = tail
                .positions
                .as_mut()
                .context("root tail has no snapshot")?;
            anyhow::ensure!(
                self.domain_id() == tail.exit.domain().id(),
                "foreign EVENTS domain"
            );
            anyhow::ensure!(
                self.source.consumer() == p.consumer,
                "unexpected EVENTS consumer cursor"
            );
            for _ in 0..quantum {
                let progress = match self.source.bounded_record(p.producer)? {
                    BoundedRecord::Item(item) => {
                        match decode_transport_record(&item, self.object_transport.as_deref())
                            .map(|record| record.event)
                        {
                            Some(event) => {
                                if let Some(tap) = &self.trace_tap {
                                    tap.observe_call(&event);
                                }
                                reduce(event)?;
                            }
                            None => {
                                self.malformed += 1;
                                if let Some(tap) = &self.trace_tap {
                                    tap.observe_failure();
                                }
                            }
                        }
                        drop(item);
                        RootTailProgress::Yielded
                    }
                    BoundedRecord::Pending => RootTailProgress::Pending,
                    BoundedRecord::Reached => RootTailProgress::Reached,
                };
                let current = self.source.consumer();
                let delta = current.wrapping_sub(p.consumer);
                anyhow::ensure!(
                    delta <= tail.remaining && delta < p.capacity && delta % 8 == 0,
                    "crossed root tail boundary"
                );
                tail.remaining -= delta;
                p.consumer = current;
                anyhow::ensure!(
                    current.wrapping_add(tail.remaining) == p.producer,
                    "invalid root tail progress"
                );
                if tail.remaining == 0 && current == p.producer {
                    tail.reached = true;
                    return Ok(RootTailProgress::Reached);
                }
                anyhow::ensure!(
                    progress != RootTailProgress::Reached,
                    "reader reached before semantic prefix"
                );
                if progress == RootTailProgress::Pending {
                    return Ok(progress);
                }
            }
            Ok(RootTailProgress::Yielded)
        })();
        if result.is_err() {
            tail.failed = true;
            if let Some(tap) = &self.trace_tap {
                tap.observe_failure();
            }
        }
        result.context("root_tail_incomplete: bounded reduction")
    }
}

/// Drains the `EVENTS` ring buffer, handing each well-formed record to a
/// caller-supplied closure and counting the rest as malformed.
pub struct EventDrain<S> {
    source: S,
    malformed: u64,
    malformed_reported: u64,
    domain: Option<EventsDomain>,
    trace_tap: Option<crate::attach::detailed_identity::ProofTap>,
    object_transport: Option<ObjectTransportRows>,
}

impl OwnedDrain {
    /// Builds the session's single retained consumer. The live `EVENTS`
    /// map must still match the retained domain (the same check the
    /// retired per-poll constructor made); the reader itself is then
    /// mmapped over a duplicate of the retained descriptor, so the
    /// returned value owns everything and never borrows `ebpf`. Call
    /// exactly once per session: the ring has one consumer cursor, and a
    /// second reader would desynchronize this value's in-memory position.
    pub(crate) fn for_session(ebpf: &Ebpf, domain: &EventsDomain) -> Result<Self> {
        let Map::RingBuf(data) = ebpf.map("EVENTS").context("EVENTS map")? else {
            anyhow::bail!("EVENTS is not a ring buffer");
        };
        anyhow::ensure!(
            u64::from(data.info()?.id()) == domain.id(),
            "EVENTS map does not match retained domain"
        );
        let retained = domain
            .as_fd()
            .try_clone_to_owned()
            .context("duplicating retained EVENTS descriptor")?;
        let data = MapData::from_fd(retained).context("reopening retained EVENTS map")?;
        anyhow::ensure!(
            u64::from(data.info()?.id()) == domain.id(),
            "EVENTS map does not match retained domain"
        );
        let ring = aya::maps::RingBuf::try_from(Map::from_map_data(data)?)?;
        Ok(Self {
            source: ring,
            malformed: 0,
            malformed_reported: 0,
            domain: Some(domain.clone()),
            trace_tap: None,
            object_transport: None,
        })
    }

    /// The same retained cursor with the producer's verified transport rows.
    /// This does not expose object facts or enable attested semantic admission.
    pub(crate) fn for_session_with_transport(
        ebpf: &Ebpf,
        domain: &EventsDomain,
        descriptors: Option<ObjectTransportRows>,
    ) -> Result<Self> {
        let mut drain = Self::for_session(ebpf, domain)?;
        drain.object_transport = descriptors;
        Ok(drain)
    }
}

impl<S: RecordSource> EventDrain<S> {
    pub(crate) fn attach_trace_tap(
        &mut self,
        tap: crate::attach::detailed_identity::ProofTap,
    ) -> Result<(), crate::attach::detailed_identity::TraceProofUnknown> {
        if !self
            .domain
            .as_ref()
            .is_some_and(|domain| tap.matches_events(domain))
        {
            return Err(crate::attach::detailed_identity::TraceProofUnknown::DomainMismatch);
        }
        self.trace_tap = Some(tap);
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn over(source: S) -> Self {
        Self {
            source,
            malformed: 0,
            malformed_reported: 0,
            domain: None,
            trace_tap: None,
            object_transport: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn source(&self) -> &S {
        &self.source
    }

    #[cfg(test)]
    pub(crate) fn over_domain(source: S, domain: EventsDomain) -> Self {
        Self {
            source,
            malformed: 0,
            malformed_reported: 0,
            domain: Some(domain),
            trace_tap: None,
            object_transport: None,
        }
    }
    #[cfg(test)]
    pub(crate) fn over_test_domain(source: S, id: u64) -> Self {
        if id == 0 {
            Self::over(source)
        } else {
            Self::over_domain(source, EventsDomain::test_standin(id))
        }
    }
    pub(crate) fn domain_id(&self) -> u64 {
        self.domain.as_ref().map_or(0, EventsDomain::id)
    }

    /// Drains up to `quantum` records without blocking; `None` reads the
    /// ring whole with no bound. Production always passes an explicit
    /// bound (`poll_quantum`); unbounded polls are tests pinning drain
    /// behavior on finite scripts. Returns `true` when it stopped with
    /// records possibly still queued — the quantum was reached or `f`
    /// broke — and `false` once the ring read empty.
    pub fn poll(
        &mut self,
        quantum: Option<usize>,
        mut f: impl FnMut(Event) -> ControlFlow<()>,
    ) -> bool {
        let mut left = quantum;
        loop {
            if left == Some(0) {
                return true;
            }
            let Some(item) = self.source.next_record() else {
                return false;
            };
            if let Some(left) = left.as_mut() {
                *left -= 1;
            }
            match decode_transport_record(&item, self.object_transport.as_deref())
                .map(|record| record.event)
            {
                Some(event) => {
                    if let Some(tap) = &self.trace_tap {
                        tap.observe_call(&event);
                    }
                    if f(event).is_break() {
                        return true;
                    }
                }
                None => {
                    self.malformed = self.malformed.saturating_add(1);
                    if let Some(tap) = &self.trace_tap {
                        tap.observe_failure();
                    }
                }
            }
        }
    }

    /// `poll` delivering whole records, private continuity included, for the
    /// load-instance router (Task 3 Stage A). Same bound, malformed counting
    /// and stop semantics as `poll`.
    #[allow(dead_code)] // Task 6 native seam (DR-T3A-1); privileged gates today.
    pub(crate) fn poll_records(
        &mut self,
        quantum: Option<usize>,
        mut f: impl FnMut(EventRecord) -> ControlFlow<()>,
    ) -> bool {
        let mut left = quantum;
        loop {
            if left == Some(0) {
                return true;
            }
            let Some(item) = self.source.next_record() else {
                return false;
            };
            if let Some(left) = left.as_mut() {
                *left -= 1;
            }
            match decode_transport_record(&item, self.object_transport.as_deref()) {
                Some(record) => {
                    if let Some(tap) = &self.trace_tap {
                        tap.observe_call(&record.event);
                    }
                    if f(record).is_break() {
                        return true;
                    }
                }
                None => {
                    self.malformed = self.malformed.saturating_add(1);
                    if let Some(tap) = &self.trace_tap {
                        tap.observe_failure();
                    }
                }
            }
        }
    }

    /// `poll_records` delivering whole records with the optional
    /// validated object tail intact (slice D transport). The caller
    /// supplies the frozen receipt-bound descriptor table: only the
    /// reviewed allowlisted attested lane decodes 608-byte records;
    /// malformed tails and lengths count exactly like before, through
    /// this same single cursor. Bare consumers keep `poll_records`.
    pub(crate) fn poll_object_records(
        &mut self,
        quantum: Option<usize>,
        descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
        mut f: impl FnMut(DecodedEventRecord) -> ControlFlow<()>,
    ) -> bool {
        let mut left = quantum;
        loop {
            if left == Some(0) {
                return true;
            }
            let Some(item) = self.source.next_record() else {
                return false;
            };
            if let Some(left) = left.as_mut() {
                *left -= 1;
            }
            match decode_object_record(&item, descriptors) {
                Some(record) => {
                    if let Some(tap) = &self.trace_tap {
                        tap.observe_call(&record.base.event);
                    }
                    if f(record).is_break() {
                        return true;
                    }
                }
                None => {
                    self.malformed = self.malformed.saturating_add(1);
                    if let Some(tap) = &self.trace_tap {
                        tap.observe_failure();
                    }
                }
            }
        }
    }

    /// One-cursor dispatch poll (H8): each consumed record goes to exactly
    /// one consumer by length — 368/608-byte forms through the existing
    /// object decoder to `ordinary`, journal forms through the frozen
    /// journal validators to `journal` — with the same quantum, malformed
    /// counting and stop semantics as the single-consumer polls. No second
    /// cursor and no decoded-count inference: consumption order is
    /// reservation order for every form. Activation-gated: production H0/H3
    /// call sites keep their polls until the producer wires.
    #[allow(dead_code)]
    pub(crate) fn poll_dispatched_records(
        &mut self,
        quantum: Option<usize>,
        descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
        mut ordinary: impl FnMut(DecodedEventRecord) -> ControlFlow<()>,
        mut journal: impl FnMut(JournalRecord) -> ControlFlow<()>,
    ) -> bool {
        use p11scope_ebpf_common::object_journal::{
            JOURNAL_ABANDON_BYTES, JOURNAL_BEGIN_BYTES, JOURNAL_END_COMPACT_BYTES,
            JOURNAL_END_FULL_BYTES,
        };
        let mut left = quantum;
        loop {
            if left == Some(0) {
                return true;
            }
            let Some(item) = self.source.next_record() else {
                return false;
            };
            if let Some(left) = left.as_mut() {
                *left -= 1;
            }
            let delivered = match item.len() {
                JOURNAL_BEGIN_BYTES
                | JOURNAL_END_FULL_BYTES
                | JOURNAL_END_COMPACT_BYTES
                | JOURNAL_ABANDON_BYTES => {
                    decode_journal_record(&item, descriptors).map(&mut journal)
                }
                _ => decode_object_record(&item, descriptors).map(&mut ordinary),
            };
            match delivered {
                Some(flow) => {
                    if flow.is_break() {
                        return true;
                    }
                }
                None => {
                    self.malformed = self.malformed.saturating_add(1);
                    if let Some(tap) = &self.trace_tap {
                        tap.observe_failure();
                    }
                }
            }
        }
    }

    /// Records rejected by the size or affiliation check so far.
    pub fn malformed(&self) -> u64 {
        self.malformed
    }

    /// Kernel-discarded reservations the retained reader consumed so
    /// far. Drains audit the per-collection delta and refuse seals
    /// that span unaccounted discards.
    pub fn discarded(&self) -> u64 {
        self.source.discarded()
    }

    /// Malformed records since the last delta was taken, advancing the
    /// checkpoint to the current total. With one retained consumer per
    /// session, callers sum these per-poll deltas instead of the
    /// fresh-drain totals they summed before.
    pub fn take_malformed_delta(&mut self) -> u64 {
        let delta = self.malformed.saturating_sub(self.malformed_reported);
        self.malformed_reported = self.malformed;
        delta
    }
}

/// Maps a bounded-read failure to the post-Q flag: `BoundaryOutOfRange`
/// means the consumer already stands past `stop`, so records past the Q
/// positions existed and the producer moved after Q — the post-Q
/// invariant violation (an unbounded terminal consumer, such as the
/// root tail or a loader drain, already took them). Any other failure
/// is genuine and propagates.
fn map_bounded_error(error: anyhow::Error) -> Result<bool> {
    match error.downcast::<aya::maps::ring_buf::RingBufBoundaryError>() {
        Ok(aya::maps::ring_buf::RingBufBoundaryError::BoundaryOutOfRange { .. }) => Ok(true),
        Ok(invalid) => Err(invalid.into()),
        Err(error) => Err(error),
    }
}

/// The EVENTS ring's current producer/consumer positions, for reading
/// the Q stop positions after quiescence is proven.
pub(crate) fn event_drain_positions<S: BoundedRecordSource>(
    drain: &EventDrain<S>,
) -> aya::maps::ring_buf::RingBufPositions {
    drain.source.positions()
}

/// Drains one bounded EVENTS quantum up to the producer `stop` position
/// read at Q, never consuming past it. Returns `(post_q_record, backlog)`:
/// `post_q_record` when the producer has moved past `stop` — under a
/// proven Q no admitted body remains, so that is an invariant violation
/// (an ungated writer); `backlog` when the quantum ran out or the
/// callback broke early, so the caller re-polls. Fails with
/// `BoundedDrainError::UngatedWriterBeforeQ` when an uncommitted (BUSY)
/// record stands below `stop`: the other ungated-writer signature.
pub(crate) fn poll_events_to_position<S: BoundedRecordSource>(
    drain: &mut EventDrain<S>,
    stop: usize,
    quantum: Option<usize>,
    mut f: impl FnMut(Event) -> ControlFlow<()>,
) -> Result<(bool, bool)> {
    let mut left = quantum;
    loop {
        if left == Some(0) {
            return Ok((false, true));
        }
        // Decode to an owned event first: matching the borrowed item
        // directly keeps the source borrow alive across the match,
        // blocking the post-Reached positions read below.
        let record: BoundedRecord<Option<Event>> = match drain.source.bounded_record(stop) {
            Ok(bounded) => match bounded {
                BoundedRecord::Item(item) => BoundedRecord::Item(
                    decode_transport_record(&item, drain.object_transport.as_deref())
                        .map(|record| record.event),
                ),
                BoundedRecord::Reached => BoundedRecord::Reached,
                BoundedRecord::Pending => BoundedRecord::Pending,
            },
            Err(error) => {
                if let Some(tap) = &drain.trace_tap {
                    tap.observe_failure();
                }
                return Ok((map_bounded_error(error)?, false));
            }
        };
        match record {
            BoundedRecord::Item(event) => {
                if let Some(left) = left.as_mut() {
                    *left -= 1;
                }
                match event {
                    Some(event) => {
                        if let Some(tap) = &drain.trace_tap {
                            tap.observe_call(&event);
                        }
                        if f(event).is_break() {
                            return Ok((false, true));
                        }
                    }
                    None => {
                        drain.malformed = drain.malformed.saturating_add(1);
                        if let Some(tap) = &drain.trace_tap {
                            tap.observe_failure();
                        }
                    }
                }
            }
            BoundedRecord::Reached => {
                let post_q_record = drain.source.positions().producer != stop;
                return Ok((post_q_record, false));
            }
            BoundedRecord::Pending => {
                // Below the Q stop the producer must still hold data: it
                // only advances, so it stands at or past the recorded stop.
                // Pending is therefore necessarily a BUSY uncommitted
                // record: the ungated-writer signature. At the stop the
                // boundary is reached and clean.
                let consumer = drain.source.consumer();
                if consumer != stop {
                    return Err(BoundedDrainError::UngatedWriterBeforeQ { consumer, stop }.into());
                }
                return Ok((false, false));
            }
        }
    }
}

/// The full-`EventRecord` counterpart of [`poll_events_to_position`]:
/// the same proven-Q bounded drain over the same owned consumer, but
/// delivering whole records with the private continuity tail intact
/// instead of decoding it away to `Event`. The Detailed lane's
/// terminal drain consumes its own cursor through here, in bounded
/// quanta, never creating another consumer. Same contract:
/// `(post_q_record, backlog)`, same `UngatedWriterBeforeQ` failure,
/// same malformed accounting.
pub(crate) fn poll_records_to_position<S: BoundedRecordSource>(
    drain: &mut EventDrain<S>,
    stop: usize,
    quantum: Option<usize>,
    mut f: impl FnMut(EventRecord) -> ControlFlow<()>,
) -> Result<(bool, bool)> {
    let mut left = quantum;
    loop {
        if left == Some(0) {
            return Ok((false, true));
        }
        // Decode to an owned record first: matching the borrowed item
        // directly keeps the source borrow alive across the match,
        // blocking the post-Reached positions read below.
        let record: BoundedRecord<Option<EventRecord>> = match drain.source.bounded_record(stop) {
            Ok(bounded) => match bounded {
                BoundedRecord::Item(item) => BoundedRecord::Item(decode_transport_record(
                    &item,
                    drain.object_transport.as_deref(),
                )),
                BoundedRecord::Reached => BoundedRecord::Reached,
                BoundedRecord::Pending => BoundedRecord::Pending,
            },
            Err(error) => {
                if let Some(tap) = &drain.trace_tap {
                    tap.observe_failure();
                }
                return Ok((map_bounded_error(error)?, false));
            }
        };
        match record {
            BoundedRecord::Item(record) => {
                if let Some(left) = left.as_mut() {
                    *left -= 1;
                }
                match record {
                    Some(record) => {
                        if let Some(tap) = &drain.trace_tap {
                            tap.observe_call(&record.event);
                        }
                        if f(record).is_break() {
                            return Ok((false, true));
                        }
                    }
                    None => {
                        drain.malformed = drain.malformed.saturating_add(1);
                        if let Some(tap) = &drain.trace_tap {
                            tap.observe_failure();
                        }
                    }
                }
            }
            BoundedRecord::Reached => {
                let post_q_record = drain.source.positions().producer != stop;
                return Ok((post_q_record, false));
            }
            BoundedRecord::Pending => {
                let consumer = drain.source.consumer();
                if consumer != stop {
                    return Err(BoundedDrainError::UngatedWriterBeforeQ { consumer, stop }.into());
                }
                return Ok((false, false));
            }
        }
    }
}

/// `poll_records_to_position` delivering whole records with the
/// optional validated object tail intact (slice D stop-time transport).
/// Same proven-Q contract, same malformed accounting, same single
/// cursor; the frozen receipt-bound table gates 608-byte records.
pub(crate) fn poll_object_records_to_position<S: BoundedRecordSource>(
    drain: &mut EventDrain<S>,
    stop: usize,
    quantum: Option<usize>,
    descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
    mut f: impl FnMut(DecodedEventRecord) -> ControlFlow<()>,
) -> Result<(bool, bool)> {
    let mut left = quantum;
    loop {
        if left == Some(0) {
            return Ok((false, true));
        }
        // Decode to an owned record first: matching the borrowed item
        // directly keeps the source borrow alive across the match,
        // blocking the post-Reached positions read below.
        let record: BoundedRecord<Option<DecodedEventRecord>> =
            match drain.source.bounded_record(stop) {
                Ok(bounded) => match bounded {
                    BoundedRecord::Item(item) => {
                        BoundedRecord::Item(decode_object_record(&item, descriptors))
                    }
                    BoundedRecord::Reached => BoundedRecord::Reached,
                    BoundedRecord::Pending => BoundedRecord::Pending,
                },
                Err(error) => {
                    if let Some(tap) = &drain.trace_tap {
                        tap.observe_failure();
                    }
                    return Ok((map_bounded_error(error)?, false));
                }
            };
        match record {
            BoundedRecord::Item(record) => {
                if let Some(left) = left.as_mut() {
                    *left -= 1;
                }
                match record {
                    Some(record) => {
                        if let Some(tap) = &drain.trace_tap {
                            tap.observe_call(&record.base.event);
                        }
                        if f(record).is_break() {
                            return Ok((false, true));
                        }
                    }
                    None => {
                        drain.malformed = drain.malformed.saturating_add(1);
                        if let Some(tap) = &drain.trace_tap {
                            tap.observe_failure();
                        }
                    }
                }
            }
            BoundedRecord::Reached => {
                let post_q_record = drain.source.positions().producer != stop;
                return Ok((post_q_record, false));
            }
            BoundedRecord::Pending => {
                let consumer = drain.source.consumer();
                if consumer != stop {
                    return Err(BoundedDrainError::UngatedWriterBeforeQ { consumer, stop }.into());
                }
                return Ok((false, false));
            }
        }
    }
}

/// `poll_object_records_to_position` dispatching journal forms (H8): the
/// same proven-Q bounded drain over the same owned consumer, but each
/// record goes to exactly one consumer by length — 368/608-byte forms
/// through the existing object decoder to `ordinary`, journal forms
/// through the frozen journal validators to `journal`. Same proven-Q
/// contract, same malformed accounting, same single cursor. In
/// particular a BUSY (Pending) record below no admitted writer stops the
/// drain with the cursor held: the journal frontier cannot pass it.
/// Activation-gated alongside the dispatch poll.
#[allow(dead_code)]
pub(crate) fn poll_dispatched_records_to_position<S: BoundedRecordSource>(
    drain: &mut EventDrain<S>,
    stop: usize,
    quantum: Option<usize>,
    descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
    mut ordinary: impl FnMut(DecodedEventRecord) -> ControlFlow<()>,
    mut journal: impl FnMut(JournalRecord) -> ControlFlow<()>,
) -> Result<(bool, bool)> {
    use p11scope_ebpf_common::object_journal::{
        JOURNAL_ABANDON_BYTES, JOURNAL_BEGIN_BYTES, JOURNAL_END_COMPACT_BYTES,
        JOURNAL_END_FULL_BYTES,
    };
    let mut left = quantum;
    loop {
        if left == Some(0) {
            return Ok((false, true));
        }
        // Decode to an owned outcome first: matching the borrowed item
        // directly keeps the source borrow alive across the match,
        // blocking the post-Reached positions read below.
        enum Delivered {
            Ordinary(DecodedEventRecord),
            Journal(JournalRecord),
            Malformed,
        }
        let record: BoundedRecord<Delivered> = match drain.source.bounded_record(stop) {
            Ok(bounded) => match bounded {
                BoundedRecord::Item(item) => BoundedRecord::Item(match item.len() {
                    JOURNAL_BEGIN_BYTES
                    | JOURNAL_END_FULL_BYTES
                    | JOURNAL_END_COMPACT_BYTES
                    | JOURNAL_ABANDON_BYTES => decode_journal_record(&item, descriptors)
                        .map_or(Delivered::Malformed, Delivered::Journal),
                    _ => decode_object_record(&item, descriptors)
                        .map_or(Delivered::Malformed, Delivered::Ordinary),
                }),
                BoundedRecord::Reached => BoundedRecord::Reached,
                BoundedRecord::Pending => BoundedRecord::Pending,
            },
            Err(error) => {
                if let Some(tap) = &drain.trace_tap {
                    tap.observe_failure();
                }
                return Ok((map_bounded_error(error)?, false));
            }
        };
        match record {
            BoundedRecord::Item(delivered) => {
                if let Some(left) = left.as_mut() {
                    *left -= 1;
                }
                match delivered {
                    Delivered::Ordinary(record) => {
                        if let Some(tap) = &drain.trace_tap {
                            tap.observe_call(&record.base.event);
                        }
                        if ordinary(record).is_break() {
                            return Ok((false, true));
                        }
                    }
                    Delivered::Journal(record) => {
                        if journal(record).is_break() {
                            return Ok((false, true));
                        }
                    }
                    Delivered::Malformed => {
                        drain.malformed = drain.malformed.saturating_add(1);
                        if let Some(tap) = &drain.trace_tap {
                            tap.observe_failure();
                        }
                    }
                }
            }
            BoundedRecord::Reached => {
                let post_q_record = drain.source.positions().producer != stop;
                return Ok((post_q_record, false));
            }
            BoundedRecord::Pending => {
                let consumer = drain.source.consumer();
                if consumer != stop {
                    return Err(BoundedDrainError::UngatedWriterBeforeQ { consumer, stop }.into());
                }
                return Ok((false, false));
            }
        }
    }
}

/// A ring standing in for the live one: it hands out the scripted records
/// and fails the test outright once a poll takes one more than `bound`, so a
/// missing quantum is a panic on a finite script, never a hang.
#[cfg(test)]
pub(crate) struct ScriptedRecords {
    queue: std::collections::VecDeque<Vec<u8>>,
    pub(crate) bound: usize,
    taken: usize,
}

#[cfg(test)]
impl ScriptedRecords {
    pub(crate) fn events(events: impl IntoIterator<Item = Event>, bound: usize) -> Self {
        Self::records(events.into_iter().map(|event| event_bytes(&event)), bound)
    }

    pub(crate) fn records(records: impl IntoIterator<Item = Vec<u8>>, bound: usize) -> Self {
        Self {
            queue: records.into_iter().collect(),
            bound,
            taken: 0,
        }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
impl RecordSource for ScriptedRecords {
    fn next_record(&mut self) -> Option<impl Deref<Target = [u8]> + '_> {
        let item = self.queue.pop_front()?;
        self.taken += 1;
        assert!(
            self.taken <= self.bound,
            "the poll took record {} past its bound of {}",
            self.taken,
            self.bound
        );
        Some(item)
    }
}

#[cfg(test)]
impl ScriptedRecords {
    /// A record committed after the script was fixed: advances the producer
    /// past any position observed before the push, like a post-Q write.
    pub(crate) fn push_event(&mut self, event: &Event) {
        self.queue.push_back(event_bytes(event));
    }
}

#[cfg(test)]
impl BoundedRecordSource for ScriptedRecords {
    fn positions(&self) -> aya::maps::ring_buf::RingBufPositions {
        aya::maps::ring_buf::RingBufPositions {
            consumer: self.taken * 8,
            producer: (self.taken + self.queue.len()) * 8,
            capacity: 4096,
        }
    }
    fn consumer(&self) -> usize {
        self.taken * 8
    }
    fn bounded_record(
        &mut self,
        stop: usize,
    ) -> Result<BoundedRecord<impl Deref<Target = [u8]> + '_>> {
        if self.taken * 8 == stop {
            return Ok(BoundedRecord::Reached);
        }
        match self.queue.pop_front() {
            Some(item) => {
                self.taken += 1;
                assert!(
                    self.taken <= self.bound,
                    "the poll took record {} past its bound of {}",
                    self.taken,
                    self.bound
                );
                Ok(BoundedRecord::Item(item))
            }
            None => Ok(BoundedRecord::Pending),
        }
    }
}

/// The bytes the kernel side commits for one `Event`: its `EventRecord` with
/// an all-zero (invalid) continuity tail, read back raw.
#[cfg(test)]
pub(crate) fn event_bytes(ev: &Event) -> Vec<u8> {
    record_bytes(&EventRecord {
        event: *ev,
        continuity: Default::default(),
    })
}

/// The raw bytes of one whole `EVENTS` record.
#[cfg(test)]
pub(crate) fn record_bytes(record: &EventRecord) -> Vec<u8> {
    // SAFETY: `EventRecord` is a repr(C) Pod value without implicit padding
    // (pinned in ebpf-common); this reads exactly its bytes.
    unsafe {
        std::slice::from_raw_parts(
            (record as *const EventRecord).cast::<u8>(),
            size_of::<EventRecord>(),
        )
        .to_vec()
    }
}

/// The session's single retained consumer for the private live-discovery ring.
/// It owns a duplicate descriptor and its mappings, while malformed records
/// remain deliberately independent from the public call-event transport.
pub(crate) type OwnedDiscoveryDrain = DiscoveryDrain<aya::maps::RingBuf<MapData>>;

pub(crate) struct DiscoveryDrain<S> {
    source: S,
    _domain: Option<DiscoveryDomain>,
    trace_tap: Option<crate::attach::detailed_identity::ProofTap>,
    pid_lifecycle_tap: Option<crate::attach::PidLifecycleTap>,
}

impl OwnedDiscoveryDrain {
    pub(crate) fn for_session(ebpf: &Ebpf, domain: &DiscoveryDomain) -> Result<Self> {
        let Map::RingBuf(data) = ebpf.map("DISCOVERY").context("DISCOVERY map")? else {
            anyhow::bail!("DISCOVERY is not a ring buffer");
        };
        anyhow::ensure!(
            u64::from(data.info()?.id()) == domain.id(),
            "DISCOVERY map does not match retained domain"
        );
        let retained = domain
            .as_fd()
            .try_clone_to_owned()
            .context("duplicating retained DISCOVERY descriptor")?;
        let data = MapData::from_fd(retained).context("reopening retained DISCOVERY map")?;
        anyhow::ensure!(
            u64::from(data.info()?.id()) == domain.id(),
            "DISCOVERY map does not match retained domain"
        );
        let ring = aya::maps::RingBuf::try_from(Map::from_map_data(data)?)?;
        Ok(Self {
            source: ring,
            _domain: Some(domain.clone()),
            trace_tap: None,
            pid_lifecycle_tap: None,
        })
    }
}

impl<S: RecordSource> DiscoveryDrain<S> {
    pub(crate) fn attach_pid_lifecycle_tap(
        &mut self,
        tap: crate::attach::PidLifecycleTap,
    ) -> Result<(), crate::attach::PidContinuityRefusal> {
        if !self
            ._domain
            .as_ref()
            .is_some_and(|domain| tap.matches_domain(domain))
            || self
                .pid_lifecycle_tap
                .as_ref()
                .is_some_and(|installed| !installed.same_observer(&tap))
        {
            tap.observe_failure();
            if let Some(installed) = &self.pid_lifecycle_tap {
                installed.observe_failure();
            }
            return Err(crate::attach::PidContinuityRefusal::Domain);
        }
        self.pid_lifecycle_tap = Some(tap);
        Ok(())
    }

    pub(crate) fn attach_trace_tap(
        &mut self,
        tap: crate::attach::detailed_identity::ProofTap,
    ) -> Result<(), crate::attach::detailed_identity::TraceProofUnknown> {
        if !self
            ._domain
            .as_ref()
            .is_some_and(|domain| tap.matches_discovery(domain))
        {
            return Err(crate::attach::detailed_identity::TraceProofUnknown::DomainMismatch);
        }
        self.trace_tap = Some(tap);
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn over_domain(source: S, domain: DiscoveryDomain) -> Self {
        Self {
            source,
            _domain: Some(domain),
            trace_tap: None,
            pid_lifecycle_tap: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn over(source: S) -> Self {
        Self {
            source,
            _domain: None,
            trace_tap: None,
            pid_lifecycle_tap: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn source(&self) -> &S {
        &self.source
    }

    #[cfg(test)]
    pub(crate) fn domain_id(&self) -> u64 {
        self._domain.as_ref().map_or(0, DiscoveryDomain::id)
    }

    pub(crate) fn dequeue(&mut self) -> Option<DiscoveryItem>
    where
        S: BoundedRecordSource,
    {
        self.dequeue_with_clock(crate::attach::monotonic_ns)
    }

    fn dequeue_with_clock(&mut self, clock: impl FnOnce() -> Option<u64>) -> Option<DiscoveryItem>
    where
        S: BoundedRecordSource,
    {
        let pid_started = self
            .pid_lifecycle_tap
            .as_ref()
            .and_then(|tap| tap.begin_read(clock()));
        let started = self.trace_tap.as_ref().and_then(|tap| tap.read_started());
        let decoded = self
            .source
            .next_record()
            .map(|item| match decode_discovery(&item) {
                Some(record) => DiscoveryItem::Record(record),
                None => DiscoveryItem::Malformed,
            });
        let empty_positions = if decoded.is_none()
            && (self.pid_lifecycle_tap.is_some() || self.trace_tap.is_some())
        {
            Some(self.source.positions())
        } else {
            None
        };
        // Observe the first raw consumption before any caller can stage or hold it.
        if let Some(tap) = &self.pid_lifecycle_tap {
            match &decoded {
                Some(DiscoveryItem::Record(record)) => tap.observe_record(record),
                Some(DiscoveryItem::Malformed) => tap.observe_malformed(),
                None => {
                    let positions = empty_positions.expect("empty observed cursor");
                    tap.observe_empty(pid_started, positions.producer, positions.consumer);
                }
            }
        }
        if let Some(tap) = &self.trace_tap {
            match &decoded {
                Some(DiscoveryItem::Record(record)) => tap.observe_discovery(record),
                Some(DiscoveryItem::Malformed) => tap.observe_failure(),
                None => {
                    let positions = empty_positions.expect("empty observed cursor");
                    tap.observe_empty(started, positions.producer == positions.consumer);
                }
            }
        }
        decoded
    }

    pub(crate) fn invalidate_pid_lifecycle_terminal(&self) {
        if let Some(tap) = &self.pid_lifecycle_tap {
            tap.invalidate_terminal();
        }
    }
}

/// The DISCOVERY ring's current producer/consumer positions, for reading
/// the Q stop positions after quiescence is proven.
pub(crate) fn discovery_drain_positions<S: BoundedRecordSource>(
    drain: &DiscoveryDrain<S>,
) -> aya::maps::ring_buf::RingBufPositions {
    drain.source.positions()
}

/// The DISCOVERY ring still holds unconsumed bytes. Read after a dequeue
/// came back empty, it means the head is reserved but not committed, and
/// records committed behind it stay invisible: that empty read did not
/// drain the ring. Only the drain advances `consumer` and `producer` only
/// grows, so `consumer == producer` proves the ring was empty at the read.
pub(crate) fn discovery_head_pending<S: BoundedRecordSource>(drain: &DiscoveryDrain<S>) -> bool {
    let positions = drain.source.positions();
    positions.producer != positions.consumer
}

/// Unconsumed DISCOVERY bytes at these positions: what the producer
/// reserved minus what the drain consumed. The lifecycle high-water is
/// the maximum of this sample across a drain.
pub(crate) fn discovery_pending_bytes(positions: aya::maps::ring_buf::RingBufPositions) -> u64 {
    (positions.producer as u64).saturating_sub(positions.consumer as u64)
}

/// Drains one bounded discovery quantum up to the producer `stop`
/// position read at Q, never consuming past it. Same
/// `(post_q_record, backlog)` contract as the EVENTS drain, including the
/// `BoundedDrainError::UngatedWriterBeforeQ` failure on a BUSY record
/// below `stop`.
pub(crate) fn poll_discovery_to_position<S: BoundedRecordSource>(
    drain: &mut DiscoveryDrain<S>,
    stop: usize,
    quantum: Option<usize>,
    mut f: impl FnMut(DiscoveryItem) -> ControlFlow<()>,
) -> Result<(bool, bool)> {
    drain.invalidate_pid_lifecycle_terminal();
    let mut left = quantum;
    loop {
        if left == Some(0) {
            return Ok((false, true));
        }
        // Decode to an owned item first: matching the borrowed item
        // directly keeps the source borrow alive across the match,
        // blocking the post-Reached positions read below.
        let started = drain.trace_tap.as_ref().and_then(|tap| tap.read_started());
        let record: BoundedRecord<DiscoveryItem> = match drain.source.bounded_record(stop) {
            Ok(bounded) => match bounded {
                BoundedRecord::Item(item) => BoundedRecord::Item(match decode_discovery(&item) {
                    Some(record) => DiscoveryItem::Record(record),
                    None => DiscoveryItem::Malformed,
                }),
                BoundedRecord::Reached => BoundedRecord::Reached,
                BoundedRecord::Pending => BoundedRecord::Pending,
            },
            Err(error) => {
                if let Some(tap) = &drain.trace_tap {
                    tap.observe_failure();
                }
                return Ok((map_bounded_error(error)?, false));
            }
        };
        match record {
            BoundedRecord::Item(item) => {
                if let Some(left) = left.as_mut() {
                    *left -= 1;
                }
                if let Some(tap) = &drain.trace_tap {
                    match &item {
                        DiscoveryItem::Record(record) => tap.observe_discovery(record),
                        DiscoveryItem::Malformed => tap.observe_failure(),
                    }
                }
                if f(item).is_break() {
                    return Ok((false, true));
                }
            }
            BoundedRecord::Reached => {
                let positions = drain.source.positions();
                let post_q_record = positions.producer != stop;
                if let Some(tap) = &drain.trace_tap {
                    tap.observe_empty(
                        started,
                        !post_q_record && positions.producer == positions.consumer,
                    );
                }
                return Ok((post_q_record, false));
            }
            BoundedRecord::Pending => {
                // Below the Q stop the producer must still hold data: it
                // only advances, so it stands at or past the recorded stop.
                // Pending is therefore necessarily a BUSY uncommitted
                // record: the ungated-writer signature. At the stop the
                // boundary is reached and clean.
                let consumer = drain.source.consumer();
                if consumer != stop {
                    if let Some(tap) = &drain.trace_tap {
                        tap.observe_failure();
                    }
                    return Err(BoundedDrainError::UngatedWriterBeforeQ { consumer, stop }.into());
                }
                return Ok((false, false));
            }
        }
    }
}

#[cfg(test)]
mod runtime_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::DISCOVERY_KIND_LEADER_EXIT;

    #[test]
    fn object_producer_decoded_envelope_carries_validated_tail() {
        use p11scope_ebpf_common::object_wire::{
            OBJECT_ACTION_CREATE, OBJECT_CALL_BYTES, OBJECT_CALL_VERSION, OBJECT_LAYOUT_LP64,
            OBJECT_TAIL_BYTES, publish_object_descriptors,
        };
        let table = publish_object_descriptors();
        let base_record = |kind: u32, root_affiliation: u64| EventRecord {
            event: Event {
                event_type: kind,
                root_affiliation,
                ..Default::default()
            },
            continuity: Default::default(),
        };
        fn put(buf: &mut [u8], offset: usize, bytes: &[u8]) {
            buf[offset..offset + bytes.len()].copy_from_slice(bytes);
        }
        // Valid Create tail, encoded byte by byte: version 1, 240 bytes,
        // index 21 (C_CreateObject), LP64, one value result.
        let mut tail = [0u8; OBJECT_TAIL_BYTES];
        put(&mut tail, 0, &OBJECT_CALL_VERSION.to_le_bytes());
        put(&mut tail, 2, &OBJECT_CALL_BYTES.to_le_bytes());
        put(&mut tail, 4, &21u32.to_le_bytes());
        tail[12] = OBJECT_LAYOUT_LP64;
        tail[13] = OBJECT_ACTION_CREATE;
        put(&mut tail, 32, &0x1234u64.to_le_bytes());
        tail[114] = 1;

        // Ordinary form: CALL and lifecycle decode without a tail.
        let call = record_bytes(&base_record(event_type::CALL, 0));
        let decoded = decode_object_record(&call, &table).expect("ordinary CALL decodes");
        assert_eq!(decoded.base.event.event_type, event_type::CALL);
        assert!(decoded.object.is_none());
        let fork = record_bytes(&base_record(event_type::FORK, 1));
        let decoded = decode_object_record(&fork, &table).expect("lifecycle decodes");
        assert!(decoded.object.is_none());
        assert!(
            decode_object_record(&record_bytes(&base_record(event_type::CALL, 2)), &table)
                .is_none()
        );
        assert!(decode_object_record(&[0u8; 367], &table).is_none());
        assert!(decode_object_record(&[0u8; 369], &table).is_none());

        // Extended form is CALL-only and returns the exact tail.
        let mut extended = record_bytes(&base_record(event_type::CALL, 0));
        extended.extend_from_slice(&tail);
        let decoded = decode_object_record(&extended, &table).expect("extended CALL decodes");
        assert_eq!(decoded.base.event.event_type, event_type::CALL);
        let object = decoded.object.expect("validated tail rides along");
        assert_eq!(object.tail_bytes(), &tail);
        assert_eq!(object.descriptor_index(), 21);
        assert_eq!(object.action(), OBJECT_ACTION_CREATE);
        assert_eq!(object.layout(), OBJECT_LAYOUT_LP64);

        let mut forked = record_bytes(&base_record(event_type::FORK, 0));
        forked.extend_from_slice(&tail);
        assert!(decode_object_record(&forked, &table).is_none());
        let mut zeroed = record_bytes(&base_record(event_type::CALL, 0));
        zeroed.extend_from_slice(&[0u8; OBJECT_TAIL_BYTES]);
        assert!(decode_object_record(&zeroed, &table).is_none());
        let mut unaffiliated = record_bytes(&base_record(event_type::CALL, 2));
        unaffiliated.extend_from_slice(&tail);
        assert!(decode_object_record(&unaffiliated, &table).is_none());
        assert!(decode_object_record(&[0u8; 607], &table).is_none());
        assert!(decode_object_record(&[0u8; 609], &table).is_none());

        // Production decoding stays 368-only until the transport handoff.
        assert!(decode_record(&extended).is_none());
        assert!(decode(&extended).is_none());
    }

    fn ordinary_object_transport_record(slot: u32) -> Vec<u8> {
        let mut bytes = event_bytes(&Event {
            event_type: event_type::CALL,
            slot,
            rv: 7,
            duration_ns: 91,
            ..Default::default()
        });
        let mut tail = [0u8; 240];
        tail[..2].copy_from_slice(&1u16.to_le_bytes());
        tail[2..4].copy_from_slice(&240u16.to_le_bytes());
        tail[4..8].copy_from_slice(&21u32.to_le_bytes());
        tail[12] = 1; // LP64
        tail[13] = 1; // C_CreateObject
        tail[32..40].copy_from_slice(&0x1234u64.to_le_bytes());
        tail[114] = 1; // result handle VALUE
        bytes.extend_from_slice(&tail);
        bytes
    }

    // A drift back to the strict 368-byte decoder loses the first call;
    // accepting only a valid prefix of the 608-byte envelope admits slot 99.
    fn check_ordinary_object_transport_route(route: u8) {
        let good = ordinary_object_transport_record(12);
        let mut malformed_tail = ordinary_object_transport_record(99);
        malformed_tail[368] = 2; // unsupported tail version
        let ordinary = event_bytes(&Event {
            event_type: event_type::CALL,
            slot: 13,
            rv: 7,
            duration_ns: 91,
            ..Default::default()
        });
        let domain = EventsDomain::test_standin(811);
        let mut drain = EventDrain::over_domain(
            ScriptedRecords::records([good, malformed_tail, ordinary], 3),
            domain.clone(),
        );
        let command = if route % 2 == 0 { "profile" } else { "trace" };
        let policy = crate::attach::CapturePolicy::from_cli(command, false, false).unwrap();
        drain.object_transport = crate::attach::object_transport_rows_with(policy, None, || {
            Ok(Arc::new(
                p11scope_ebpf_common::object_wire::publish_object_descriptors(),
            ))
        })
        .unwrap();
        let mut seen = Vec::new();
        let mut observe = |event: Event| {
            seen.push((event.slot, event.rv, event.duration_ns));
            ControlFlow::Continue(())
        };
        match route {
            0 => assert!(!drain.poll(Some(4), &mut observe)),
            1 => assert!(!drain.poll_records(Some(4), |record| observe(record.event))),
            2 => assert_eq!(
                poll_events_to_position(&mut drain, 24, Some(4), &mut observe).unwrap(),
                (false, false)
            ),
            3 => assert_eq!(
                poll_records_to_position(&mut drain, 24, Some(4), |record| observe(record.event))
                    .unwrap(),
                (false, false)
            ),
            4 => {
                let mut tail = OwnedRootTail::new(
                    crate::run::OriginalRootExit::test_reaped(domain),
                    Instant::now() + Duration::from_secs(1),
                );
                drain.begin_root_tail(&mut tail).unwrap();
                assert_eq!(
                    drain
                        .poll_root_tail(&mut tail, 4, |event| {
                            let _ = observe(event);
                            Ok(())
                        })
                        .unwrap(),
                    RootTailProgress::Reached
                );
                tail.complete().unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(seen, [(12, 7, 91), (13, 7, 91)], "route {route}");
        assert_eq!(drain.malformed(), 1, "route {route}");
        assert_eq!(drain.take_malformed_delta(), 1);
        assert_eq!(drain.take_malformed_delta(), 0);
        assert_eq!(drain.source.consumer(), 24);
    }

    #[test]
    fn ordinary_object_transport_live_poll_preserves_call() {
        check_ordinary_object_transport_route(0);
    }

    #[test]
    fn ordinary_object_transport_record_poll_preserves_call() {
        check_ordinary_object_transport_route(1);
    }

    #[test]
    fn ordinary_object_transport_terminal_poll_preserves_call() {
        check_ordinary_object_transport_route(2);
    }

    #[test]
    fn ordinary_object_transport_terminal_record_poll_preserves_call() {
        check_ordinary_object_transport_route(3);
    }

    #[test]
    fn ordinary_object_transport_root_tail_preserves_call() {
        check_ordinary_object_transport_route(4);
    }

    #[test]
    fn ordinary_object_transport_without_capability_stays_strict() {
        let extended = ordinary_object_transport_record(12);
        let ordinary = event_bytes(&Event {
            slot: 13,
            ..Default::default()
        });
        let mut drain = EventDrain::over(ScriptedRecords::records([extended, ordinary], 2));
        let mut slots = Vec::new();
        assert!(!drain.poll(Some(3), |event| {
            slots.push(event.slot);
            ControlFlow::Continue(())
        }));
        assert_eq!(slots, [13]);
        assert_eq!(drain.malformed(), 1);
    }

    #[test]
    fn poll_records_to_position_delivers_whole_records_to_q() {
        use p11scope_ebpf_common::{InstanceContinuity, InstanceStamp};
        let record = |slot: u32, entry_ip: u64| EventRecord {
            event: Event {
                slot,
                ..Default::default()
            },
            continuity: InstanceContinuity {
                entry_ip,
                entry_stamp: InstanceStamp {
                    epoch: 9,
                    ..Default::default()
                },
                return_stamp: InstanceStamp::default(),
            },
        };
        let bytes = [record(3, 0x1111), record(4, 0x2222)]
            .into_iter()
            .map(|record| record_bytes(&record));
        let mut drain = EventDrain::over_test_domain(ScriptedRecords::records(bytes, 8), 7);
        // The Q stop stands after both records (8 bytes each in the
        // scripted positions); a quantum of one drains in two calls.
        let mut seen = Vec::new();
        let (post_q, backlog) = poll_records_to_position(&mut drain, 16, Some(1), |record| {
            seen.push((record.event.slot, record.continuity.entry_ip));
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!((post_q, backlog), (false, true));
        let (post_q, backlog) = poll_records_to_position(&mut drain, 16, Some(8), |record| {
            seen.push((record.event.slot, record.continuity.entry_ip));
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!((post_q, backlog), (false, false));
        assert_eq!(seen, vec![(3, 0x1111), (4, 0x2222)]);
        // A third record past Q is the post-Q signature at Reached:
        // reported, never silently consumed.
        let bytes = [record(3, 0x1111), record(4, 0x2222), record(5, 0x3333)]
            .into_iter()
            .map(|record| record_bytes(&record));
        let mut drain = EventDrain::over_test_domain(ScriptedRecords::records(bytes, 8), 7);
        let mut seen = 0;
        let (post_q, backlog) = poll_records_to_position(&mut drain, 16, Some(8), |_| {
            seen += 1;
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!((post_q, backlog), (true, false));
        assert_eq!(seen, 2);
        // Malformed bytes count without yielding a record.
        let mut drain =
            EventDrain::over_test_domain(ScriptedRecords::records([vec![7u8; 3]], 8), 7);
        let (post_q, backlog) =
            poll_records_to_position(&mut drain, 8, Some(8), |_| ControlFlow::Continue(()))
                .unwrap();
        assert_eq!((post_q, backlog), (false, false));
        assert_eq!(drain.malformed(), 1);
    }

    #[test]
    fn pending_bytes_is_producer_minus_consumer() {
        let positions = |producer: usize, consumer: usize| aya::maps::ring_buf::RingBufPositions {
            producer,
            consumer,
            capacity: 65_536,
        };
        assert_eq!(discovery_pending_bytes(positions(100, 100)), 0);
        assert_eq!(discovery_pending_bytes(positions(1_000, 100)), 900);
        assert_eq!(discovery_pending_bytes(positions(100, 1_000)), 0);
    }

    #[test]
    fn domain_boundary_retention_survives_session_and_temporary_drains() {
        const CHILD: &str = "P11SCOPE_EVENTS_RETENTION_CHILD";
        const COMPLETE: &str = "EVENTS_RETENTION_CHILD_COMPLETE";
        if std::env::var_os(CHILD).is_none() {
            // A parallel OwnedChild test may fork while this fixture's socket
            // is open. Its child then retains the socket until exec, despite
            // our local FD being closed. Create this fixture only after exec.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "events::tests::domain_boundary_retention_survives_session_and_temporary_drains",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .expect("run isolated EVENTS retention fixture");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success() && stdout.lines().any(|line| line == COMPLETE),
                "isolated retention fixture: {}\nstdout: {stdout}\nstderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        // A real owned file descriptor tests lifetime only, NOT BPF map identity.
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        let (owner, mut peer) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        let domain = EventsDomain::test_with_fd(7, owner.into());
        let weak = Arc::downgrade(&domain.0);
        let tracker = crate::process::Tracker::for_producer(domain.clone(), 16);
        let plan = crate::plan::AttachPlan::from_slots(vec![]);
        let state = crate::semantics::State::for_capture(
            &plan,
            crate::attach::CapturePolicy::Allowlisted,
            domain.clone(),
        );
        for _ in 0..2 {
            let drain = EventDrain::over_domain(ScriptedRecords::events([], 0), domain.clone());
            assert_eq!(drain.domain_id(), 7);
            assert!(Arc::ptr_eq(&domain.0, &drain.domain.as_ref().unwrap().0));
        }
        drop(domain);
        assert!(weak.upgrade().is_some());
        drop(tracker);
        assert!(
            weak.upgrade().is_some(),
            "State retains the map after Tracker and Session"
        );
        let written = peer.write(&[1]);
        assert!(written.is_ok(), "retained socket write: {written:?}");
        drop(state);
        assert!(weak.upgrade().is_none());
        // Closing the last descriptor is visible at its actual peer.
        let result = peer.read(&mut [0; 1]);
        assert!(
            matches!(result, Ok(0))
                || result.is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset)
        );

        let domain = EventsDomain::test_standin(8);
        let weak = Arc::downgrade(&domain.0);
        let tracker = crate::process::Tracker::for_producer(domain.clone(), 16);
        drop(domain);
        assert!(
            weak.upgrade().is_some(),
            "Tracker independently retains the map"
        );
        drop(tracker);
        assert!(weak.upgrade().is_none());
        println!("\n{COMPLETE}");
    }

    #[test]
    fn domain_boundary_decoder_accepts_only_event368_and_affiliations_zero_one() {
        for tag in [0, 1, 2, u64::MAX] {
            let event = Event {
                root_affiliation: tag,
                ..sample_event()
            };
            let bytes = event_bytes(&event);
            assert_eq!(bytes.len(), 368);
            assert_eq!(decode(&bytes).is_some(), tag <= 1);
            assert!(decode(&bytes[..360]).is_none());
        }
    }

    fn sample_event() -> Event {
        Event {
            ts_ns: 1,
            duration_ns: 2,
            pid_tgid: 3,
            cgroup_id: 4,
            session: 5,
            mechanism: 6,
            rv: 7,
            p0: 0,
            p1: 0,
            p2: 0,
            slot: 8,
            user_type: 10,
            shape: 0,
            attr_types: [0; 8],
            attr_count: 0,
            attr_total: 0,
            attr_bools: 0,
            attr_bools_seen: 0,
            ..Event::default()
        }
    }

    fn to_bytes(ev: &Event) -> Vec<u8> {
        event_bytes(ev)
    }

    fn counting_poll<S: RecordSource>(
        drain: &mut EventDrain<S>,
        quantum: Option<usize>,
    ) -> (usize, bool) {
        let mut seen = 0;
        let backlog = drain.poll(quantum, |_| {
            seen += 1;
            ControlFlow::Continue(())
        });
        (seen, backlog)
    }

    /// A scripted ring with an explicit consumer cursor shared by ordinary
    /// and bounded reads: ordinary polls advance it, the root fence
    /// snapshots it, and the terminal poll observes it — exactly the
    /// one-cursor sequence the retained production consumer must keep.
    struct CursorScript {
        positions_reads: std::cell::Cell<usize>,
        cursor: std::rc::Rc<std::cell::Cell<usize>>,
        producer: usize,
        capacity: usize,
        queue: std::collections::VecDeque<Vec<u8>>,
    }

    struct CursorItem {
        bytes: Vec<u8>,
        cursor: std::rc::Rc<std::cell::Cell<usize>>,
    }

    impl Deref for CursorItem {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Drop for CursorItem {
        fn drop(&mut self) {
            self.cursor.set(self.cursor.get().wrapping_add(8));
        }
    }

    impl CursorScript {
        fn scripted(records: impl IntoIterator<Item = Vec<u8>>) -> Self {
            let queue: std::collections::VecDeque<_> = records.into_iter().collect();
            Self {
                positions_reads: std::cell::Cell::new(0),
                cursor: std::rc::Rc::new(std::cell::Cell::new(0)),
                producer: queue.len() * 8,
                capacity: 4096,
                queue,
            }
        }
    }

    impl RecordSource for CursorScript {
        fn next_record(&mut self) -> Option<impl Deref<Target = [u8]> + '_> {
            if self.cursor.get() == self.producer {
                return None;
            }
            let bytes = self.queue.pop_front()?;
            Some(CursorItem {
                bytes,
                cursor: self.cursor.clone(),
            })
        }
    }

    impl BoundedRecordSource for CursorScript {
        fn positions(&self) -> aya::maps::ring_buf::RingBufPositions {
            self.positions_reads.set(self.positions_reads.get() + 1);
            aya::maps::ring_buf::RingBufPositions {
                consumer: self.cursor.get(),
                producer: self.producer,
                capacity: self.capacity,
            }
        }
        fn consumer(&self) -> usize {
            self.cursor.get()
        }
        fn bounded_record(
            &mut self,
            stop: usize,
        ) -> Result<BoundedRecord<impl Deref<Target = [u8]> + '_>> {
            if self.cursor.get() == stop {
                return Ok(BoundedRecord::Reached);
            }
            match self.queue.pop_front() {
                Some(bytes) => Ok(BoundedRecord::Item(CursorItem {
                    bytes,
                    cursor: self.cursor.clone(),
                })),
                None => Ok(BoundedRecord::Pending),
            }
        }
    }

    #[test]
    fn pid_continuity_raw_cursor_observes_startup_lazy_metrics_once() {
        use crate::attach::{DiscoveryStage, PidLifecycleTap, ensure_pid_discovery_consumer_with};
        use p11scope_ebpf_common::DISCOVERY_EXEC_SAME_TASK_CANDIDATE;
        for route in 0..3 {
            let domain = DiscoveryDomain::test_standin(701);
            let tap = PidLifecycleTap::test_for(7, domain.clone());
            let mut exec = proof_lifecycle(7, 100, DISCOVERY_KIND_EXEC);
            exec.case_id = DISCOVERY_EXEC_SAME_TASK_CANDIDATE;
            let mut consumer = None;
            let create = || {
                Ok(DiscoveryDrain::over_domain(
                    CursorScript::scripted([discovery_bytes(&exec)]),
                    domain,
                ))
            };
            assert!(ensure_pid_discovery_consumer_with(&mut consumer, Some(&tap), create).unwrap());
            let drain = consumer.as_mut().unwrap();
            assert!(
                drain.trace_tap.is_none(),
                "metrics and startup do not require trace proof"
            );
            let mut stage = DiscoveryStage::default();
            let item = if route == 1 {
                let item = drain.dequeue_with_clock(|| Some(200)).unwrap();
                assert_eq!(
                    tap.test_facts().unwrap().observation_serial,
                    1,
                    "first raw dequeue must observe before direct delivery"
                );
                item
            } else {
                let outcome = stage.stage(1, DiscoveryStage::CAPACITY, || {
                    let item = drain.dequeue_with_clock(|| Some(200));
                    assert_eq!(
                        tap.test_facts().unwrap().observation_serial,
                        1,
                        "first raw dequeue must observe before startup or lazy staging"
                    );
                    item
                });
                assert_eq!(outcome.staged, 1);
                stage.pop().unwrap()
            };
            let first = tap.test_facts().unwrap();
            assert_eq!(first.latest_exec.unwrap().hook_ts_ns, 100);
            let held = item;
            assert!(matches!(held, DiscoveryItem::Record(_)));
            assert_eq!(
                tap.test_facts().unwrap(),
                first,
                "staged and held replay cannot acquire another observation key"
            );
            assert!(
                !ensure_pid_discovery_consumer_with(&mut consumer, Some(&tap), || panic!(
                    "reuse the original cursor"
                ))
                .unwrap()
            );
        }
    }

    fn pid_lifecycle_record(ts: u64, class: u8) -> DiscoveryRecord {
        let mut record = proof_lifecycle(7, ts, DISCOVERY_KIND_EXEC);
        record.case_id = class;
        record
    }

    fn pid_cursor(
        records: impl IntoIterator<Item = Vec<u8>>,
    ) -> (DiscoveryDrain<CursorScript>, crate::attach::PidLifecycleTap) {
        let domain = DiscoveryDomain::test_standin(702);
        let tap = crate::attach::PidLifecycleTap::test_for(7, domain.clone());
        let mut drain = DiscoveryDrain::over_domain(CursorScript::scripted(records), domain);
        drain.attach_pid_lifecycle_tap(tap.clone()).unwrap();
        (drain, tap)
    }

    #[test]
    fn pid_continuity_frontier_requires_genuine_empty_cursor() {
        use p11scope_ebpf_common::DISCOVERY_EXEC_SAME_TASK_CANDIDATE as SAME;
        let (mut drain, tap) = pid_cursor([]);
        assert!(drain.dequeue_with_clock(|| Some(200)).is_none());
        let empty = tap.test_facts().unwrap().empty.unwrap();
        assert_eq!(
            (
                empty.read_started_ns,
                empty.producer_position,
                empty.observation_serial
            ),
            (200, 0, 0)
        );
        drain.source.producer = 8;
        assert_eq!(
            discovery_drain_positions(&drain).producer,
            8,
            "a saved empty never conceals a later producer advance"
        );
        assert!(drain.dequeue_with_clock(|| Some(210)).is_none());
        assert!(
            tap.test_facts().unwrap().empty.is_none(),
            "BUSY is not a genuine empty"
        );
        let (mut drain, tap) = pid_cursor([
            discovery_bytes(&pid_lifecycle_record(100, SAME)),
            discovery_bytes(&pid_lifecycle_record(101, SAME)),
        ]);
        let mut staged = crate::attach::DiscoveryStage::default();
        assert_eq!(
            staged
                .stage(1, 1, || drain.dequeue_with_clock(|| Some(200)))
                .staged,
            1
        );
        assert!(
            tap.test_facts().unwrap().empty.is_none(),
            "quantum exhaustion cannot create an empty frontier"
        );
        let before = tap.test_facts().unwrap();
        assert!(
            staged
                .stage(10, 1, || panic!("capacity stop must not read the ring"))
                .capacity_blocked
        );
        assert_eq!(tap.test_facts().unwrap(), before);
        assert!(discovery_head_pending(&drain));
        staged.pop();
        assert_eq!(
            staged
                .stage(1, 1, || drain.dequeue_with_clock(|| Some(210)))
                .staged,
            1
        );
        assert!(tap.test_facts().unwrap().empty.is_none());
        assert!(drain.dequeue_with_clock(|| Some(220)).is_none());
        let empty = tap.test_facts().unwrap().empty.unwrap();
        assert_eq!(
            (
                empty.read_started_ns,
                empty.producer_position,
                empty.observation_serial
            ),
            (220, 16, 2)
        );
        for second in [0, 99, 100] {
            let (mut drain, tap) = pid_cursor([
                discovery_bytes(&pid_lifecycle_record(100, SAME)),
                discovery_bytes(&pid_lifecycle_record(second, SAME)),
            ]);
            assert!(drain.dequeue_with_clock(|| Some(200)).is_some());
            assert!(drain.dequeue_with_clock(|| Some(210)).is_some());
            let facts = tap.test_facts().unwrap();
            assert_eq!(facts.observation_serial, 2);
            assert_eq!(facts.fault_serial, 1);
            assert!(
                facts.latest_exec.is_none(),
                "zero, backward and equal lifecycle times refuse an ambiguous key"
            );
        }
        for clock in [None, Some(0), Some(199)] {
            let (mut drain, tap) = pid_cursor([]);
            assert!(drain.dequeue_with_clock(|| Some(200)).is_none());
            assert!(drain.dequeue_with_clock(|| clock).is_none());
            assert!(tap.test_facts().unwrap().empty.is_none());
            assert_eq!(tap.test_facts().unwrap().fault_serial, 1);
        }
    }

    #[test]
    fn pid_continuity_preserves_breaks_and_transport_faults() {
        use crate::attach::{
            PidContinuityRefusal, PidLifecycleTap, ensure_pid_discovery_consumer_with,
        };
        use p11scope_ebpf_common::{
            DISCOVERY_EXEC_SAME_TASK_CANDIDATE as SAME, DISCOVERY_EXEC_TASK_REPLACED as REPLACED,
            DISCOVERY_EXEC_UNKNOWN as UNKNOWN,
        };
        let exit = proof_lifecycle(7, 120, p11scope_ebpf_common::DISCOVERY_KIND_LEADER_EXIT);
        let (mut drain, tap) = pid_cursor([
            discovery_bytes(&pid_lifecycle_record(100, REPLACED)),
            discovery_bytes(&pid_lifecycle_record(110, UNKNOWN)),
            discovery_bytes(&exit),
            discovery_bytes(&pid_lifecycle_record(130, SAME)),
            discovery_bytes(&pid_lifecycle_record(140, SAME)),
            vec![0],
        ]);
        let mut held = None;
        for index in 0..5 {
            let item = drain.dequeue_with_clock(|| Some(200 + index)).unwrap();
            if index == 3 {
                held = Some(item);
            }
        }
        let latest = tap.test_facts().unwrap();
        assert_eq!(latest.greatest_break_ns, Some(120));
        let latest_exec = latest.latest_exec.unwrap();
        assert_eq!(
            (latest_exec.hook_ts_ns, latest_exec.observation_serial),
            (140, 5)
        );
        let Some(DiscoveryItem::Record(old)) = held else {
            panic!("held EXEC");
        };
        assert_eq!(old.hook_ts_ns, 130);
        assert_ne!(
            old.hook_ts_ns, latest_exec.hook_ts_ns,
            "held replay cannot borrow the newer EXEC key"
        );
        assert_eq!(tap.test_facts().unwrap(), latest);
        assert!(matches!(
            drain.dequeue_with_clock(|| Some(210)),
            Some(DiscoveryItem::Malformed)
        ));
        let failed = tap.test_facts().unwrap();
        assert_eq!((failed.observation_serial, failed.fault_serial), (6, 1));
        assert!(failed.latest_exec.is_none());
        assert_eq!(failed.greatest_break_ns, Some(120));
        assert!(drain.dequeue_with_clock(|| Some(220)).is_none());
        assert_eq!(
            tap.test_facts().unwrap().fault_serial,
            1,
            "a later empty never erases the transport fault"
        );
        let domain = DiscoveryDomain::test_standin(703);
        let tap = PidLifecycleTap::test_for(7, domain.clone());
        let mut consumer: Option<DiscoveryDrain<CursorScript>> = None;
        assert!(
            ensure_pid_discovery_consumer_with(&mut consumer, Some(&tap), || Err(anyhow::anyhow!(
                "consumer construction failed"
            )))
            .is_err()
        );
        assert_eq!(tap.test_facts().unwrap().fault_serial, 1);
        assert!(consumer.is_none());
        assert!(
            ensure_pid_discovery_consumer_with(&mut consumer, Some(&tap), || Ok(
                DiscoveryDrain::over_domain(
                    CursorScript::scripted([]),
                    DiscoveryDomain::test_standin(703)
                )
            ))
            .is_err(),
            "the same map number cannot replace the retained allocation"
        );
        assert_eq!(tap.test_facts().unwrap().fault_serial, 2);
        assert!(consumer.is_none());
        assert!(
            ensure_pid_discovery_consumer_with(&mut consumer, Some(&tap), || Ok(
                DiscoveryDrain::over_domain(CursorScript::scripted([]), domain.clone())
            ))
            .unwrap()
        );
        assert!(
            consumer
                .as_mut()
                .unwrap()
                .dequeue_with_clock(|| Some(300))
                .is_none()
        );
        let before = tap.test_facts().unwrap().fault_serial;
        let replacement = PidLifecycleTap::test_for(7, domain);
        assert_eq!(
            consumer
                .as_mut()
                .unwrap()
                .attach_pid_lifecycle_tap(replacement),
            Err(PidContinuityRefusal::Domain)
        );
        assert_eq!(tap.test_facts().unwrap().fault_serial, before + 1);
        assert!(tap.test_facts().unwrap().empty.is_none());
        let (mut drain, tap) = pid_cursor([
            discovery_bytes(&pid_lifecycle_record(150, SAME)),
            discovery_bytes(&pid_lifecycle_record(145, REPLACED)),
            discovery_bytes(&pid_lifecycle_record(160, SAME)),
        ]);
        for now in [200, 210, 220] {
            drain.dequeue_with_clock(|| Some(now));
        }
        assert_eq!(tap.test_facts().unwrap().greatest_break_ns, Some(145));
        assert_eq!(
            tap.test_facts().unwrap().fault_serial,
            1,
            "an out-of-order breaking record is retained and faults continuity"
        );
    }

    #[test]
    fn pid_continuity_terminal_bypass_is_irreversible() {
        use crate::attach::{
            DiscoveryStage, PidContinuityRefusal, collect_staged_discovery_to_position,
        };
        use p11scope_ebpf_common::DISCOVERY_EXEC_SAME_TASK_CANDIDATE as SAME;
        for route in 0..7 {
            let records = match route {
                3 | 4 => vec![discovery_bytes(&pid_lifecycle_record(100, SAME))],
                5 => vec![vec![0]],
                _ => vec![],
            };
            let (mut drain, tap) = pid_cursor([]);
            assert!(drain.dequeue_with_clock(|| Some(200)).is_none());
            assert!(tap.test_facts().unwrap().empty.is_some());
            drain.source.producer = records.len() * 8;
            drain.source.queue.extend(records);
            if route == 2 {
                drain.source.producer = 8;
            } // BUSY below the terminal stop
            let mut count = 0;
            let mut malformed = 0;
            let result = match route {
                0 => poll_discovery_to_position(&mut drain, 0, Some(0), |_| panic!("zero quantum")),
                1 => poll_discovery_to_position(&mut drain, 0, Some(1), |_| panic!("Reached")),
                2 => poll_discovery_to_position(&mut drain, 8, Some(1), |_| panic!("BUSY")),
                3 | 5 => poll_discovery_to_position(&mut drain, 8, Some(2), |item| {
                    match item {
                        DiscoveryItem::Record(_) => count += 1,
                        DiscoveryItem::Malformed => malformed += 1,
                    }
                    ControlFlow::Continue(())
                }),
                4 => poll_discovery_to_position(&mut drain, 8, Some(1), |_| {
                    count += 1;
                    ControlFlow::Break(())
                }),
                _ => {
                    let mut staged = DiscoveryStage::default();
                    staged.stage(1, 1, || {
                        Some(DiscoveryItem::Record(pid_lifecycle_record(100, SAME)))
                    });
                    let (records, bad, post, backlog) =
                        collect_staged_discovery_to_position(&mut staged, &mut drain, 0, 1)
                            .unwrap();
                    count = records.len();
                    malformed = bad;
                    assert!(staged.len() == 0 && !post && backlog);
                    Ok((post, backlog))
                }
            };
            if route == 2 {
                assert!(result.is_err());
                drain.source.producer = 0;
            } else {
                assert!(result.is_ok());
            }
            assert_eq!(count, usize::from(matches!(route, 3 | 4 | 6)));
            assert_eq!(malformed, u64::from(route == 5));
            assert_eq!(
                tap.test_facts(),
                Err(PidContinuityRefusal::Terminal),
                "every terminal route invalidates before returning"
            );
            assert!(drain.dequeue_with_clock(|| Some(300)).is_none());
            assert_eq!(
                tap.test_facts(),
                Err(PidContinuityRefusal::Terminal),
                "ordinary reads cannot restore terminal authority"
            );
        }
    }

    /// M1 (C4 review): a reserved-but-uncommitted head makes the dequeue
    /// return nothing while a committed exec record waits behind it. That
    /// empty read is not a drain; only `consumer == producer` is.
    #[test]
    fn an_empty_read_behind_a_busy_head_is_not_a_drained_ring() {
        let mut exit: DiscoveryRecord = unsafe { std::mem::zeroed() };
        exit.kind = DISCOVERY_KIND_LEADER_EXIT;

        let mut empty = DiscoveryDrain::over(CursorScript::scripted([]));
        assert!(empty.dequeue().is_none());
        assert!(!discovery_head_pending(&empty), "an empty ring is drained");

        // One record reserved at the head (producer advanced), not committed.
        let mut busy = CursorScript::scripted([]);
        busy.producer = 8;
        let mut busy = DiscoveryDrain::over(busy);
        assert!(busy.dequeue().is_none(), "the busy head reads as empty");
        assert!(discovery_head_pending(&busy), "but the ring is not drained");

        let mut consumed = DiscoveryDrain::over(CursorScript::scripted([discovery_bytes(&exit)]));
        assert!(matches!(consumed.dequeue(), Some(DiscoveryItem::Record(_))));
        assert!(consumed.dequeue().is_none());
        assert!(
            !discovery_head_pending(&consumed),
            "consumed to the producer"
        );
    }

    /// E04 correctness gate: one retained consumer serves two quanta; a
    /// malformed record in quantum 1 plus valid records in quantum 2 is
    /// counted exactly once — per-poll deltas, never re-summed totals.
    #[test]
    fn persistent_consumer_counts_malformed_then_valid_quanta_exactly_once() {
        let records = vec![
            vec![0u8; 3],
            to_bytes(&sample_event()),
            to_bytes(&sample_event()),
            to_bytes(&sample_event()),
        ];
        let mut drain = EventDrain::over(ScriptedRecords::records(records, 4));

        let (seen, backlog) = counting_poll(&mut drain, Some(2));
        assert_eq!((seen, backlog), (1, true));
        assert_eq!(drain.take_malformed_delta(), 1);

        // A quantum stop reports backlog even when it took the last
        // record; only a read that finds the ring empty reports none.
        let (seen, backlog) = counting_poll(&mut drain, Some(2));
        assert_eq!((seen, backlog), (2, true));
        assert_eq!(drain.take_malformed_delta(), 0);

        let (seen, backlog) = counting_poll(&mut drain, Some(2));
        assert_eq!((seen, backlog), (0, false));
        assert_eq!(drain.take_malformed_delta(), 0);

        assert_eq!(drain.malformed(), 1);
    }

    /// Deltas checkpoint: polls with no malformed records report zero
    /// without disturbing the cumulative total a later poll still deltas.
    #[test]
    fn per_poll_malformed_deltas_never_recount_or_lose() {
        let records = vec![
            vec![0u8; 3],
            to_bytes(&sample_event()),
            vec![0u8; 5],
            vec![0u8; 7],
        ];
        let mut drain = EventDrain::over(ScriptedRecords::records(records, 4));

        let (seen, _) = counting_poll(&mut drain, Some(1));
        assert_eq!(seen, 0);
        assert_eq!(drain.take_malformed_delta(), 1);

        let (seen, _) = counting_poll(&mut drain, Some(1));
        assert_eq!(seen, 1);
        assert_eq!(drain.take_malformed_delta(), 0);

        let (seen, backlog) = counting_poll(&mut drain, Some(2));
        assert_eq!((seen, backlog), (0, true));
        assert_eq!(drain.take_malformed_delta(), 2);

        let (seen, backlog) = counting_poll(&mut drain, Some(2));
        assert_eq!((seen, backlog), (0, false));
        assert_eq!(drain.take_malformed_delta(), 0);

        assert_eq!(drain.malformed(), 3);
    }

    /// The terminal poll keeps the explicit bound on the retained drain:
    /// one record past it is backlog (truncation), not a re-poll, and the
    /// delta still accounts the quantum exactly.
    #[test]
    fn terminal_poll_reports_backlog_past_the_explicit_bound_on_one_drain() {
        let events = (0..=TERMINAL_DRAIN_BOUND).map(|_| sample_event());
        let mut drain = EventDrain::over(ScriptedRecords::events(events, TERMINAL_DRAIN_BOUND));

        let (seen, backlog) = counting_poll(&mut drain, poll_quantum(true));

        assert_eq!(seen, TERMINAL_DRAIN_BOUND);
        assert!(backlog, "backlog past the terminal bound is truncation");
        assert_eq!(drain.source().remaining(), 1);
        assert_eq!(drain.take_malformed_delta(), 0);
        assert_eq!(drain.malformed(), 0);
    }

    /// One consumer cursor spans the ordinary, root-tail and terminal
    /// phases: ordinary polls advance it, the tail snapshots the advanced
    /// cursor and reduces to its boundary (counting its malformed record
    /// in the delta), and the terminal poll finds the ring empty.
    #[test]
    fn one_consumer_cursor_spans_ordinary_root_tail_and_terminal_polls() {
        let domain = EventsDomain::test_standin(201);
        let mut drain = EventDrain::over_domain(
            CursorScript::scripted([
                to_bytes(&sample_event()),
                to_bytes(&sample_event()),
                vec![0u8; 3],
                to_bytes(&sample_event()),
            ]),
            domain.clone(),
        );

        let (seen, backlog) = counting_poll(&mut drain, Some(2));
        assert_eq!((seen, backlog), (2, true));
        assert_eq!(drain.take_malformed_delta(), 0);
        assert_eq!(drain.source.consumer(), 16);

        let mut tail = OwnedRootTail::new(
            crate::run::OriginalRootExit::test_reaped(domain),
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        );
        drain.begin_root_tail(&mut tail).unwrap();
        let mut reduced = 0;
        assert_eq!(
            drain
                .poll_root_tail(&mut tail, LIVE_POLL_QUANTUM, |_| {
                    reduced += 1;
                    Ok(())
                })
                .unwrap(),
            RootTailProgress::Reached
        );
        assert_eq!(reduced, 1);
        assert_eq!(drain.take_malformed_delta(), 1);
        assert!(tail.complete().is_ok());

        let (seen, backlog) = counting_poll(&mut drain, poll_quantum(true));
        assert_eq!((seen, backlog), (0, false));
        assert_eq!(drain.take_malformed_delta(), 0);
        assert_eq!(drain.malformed(), 1);
    }

    #[test]
    fn detached_ring_is_polled_with_the_explicit_terminal_bound() {
        assert_eq!(poll_quantum(false), Some(LIVE_POLL_QUANTUM));
        assert_eq!(poll_quantum(true), Some(TERMINAL_DRAIN_BOUND));
    }

    #[test]
    fn terminal_drain_bound_is_sixteen_live_quanta() {
        assert_eq!(TERMINAL_DRAIN_BOUND, 16 * LIVE_POLL_QUANTUM);
        assert_eq!(TERMINAL_DRAIN_BOUND, 65536);
    }

    #[test]
    fn malformed_counter_saturates_instead_of_wrapping() {
        // LOW: published counters saturate — a wrap would corrupt evidence
        // and a debug overflow would abort the capture mid-drain.
        let mut drain = EventDrain::over(ScriptedRecords::records([vec![0u8; 3]], 1));
        drain.malformed = u64::MAX;
        drain.poll(None, |_| ControlFlow::Continue(()));
        assert_eq!(drain.malformed(), u64::MAX);
    }

    /// One record past the quantum, then a record the poll must never take.
    #[test]
    fn poll_stops_at_its_quantum_and_reports_the_backlog() {
        let events = (0..=LIVE_POLL_QUANTUM).map(|_| sample_event());
        let mut drain = EventDrain::over(ScriptedRecords::events(events, LIVE_POLL_QUANTUM));

        let (seen, backlog) = counting_poll(&mut drain, Some(LIVE_POLL_QUANTUM));

        assert_eq!(seen, LIVE_POLL_QUANTUM);
        assert!(backlog, "a quantum stop is a backlog, not an empty ring");
        assert_eq!(drain.source().remaining(), 1);
        assert_eq!(drain.malformed(), 0);
    }

    /// Producers detached, the drain is finite: `None` reads the ring whole
    /// and reports no backlog.
    #[test]
    fn poll_without_a_quantum_reads_the_ring_empty() {
        let events = (0..LIVE_POLL_QUANTUM + 3).map(|_| sample_event());
        let mut drain = EventDrain::over(ScriptedRecords::events(events, usize::MAX));

        let (seen, backlog) = counting_poll(&mut drain, None);

        assert_eq!(seen, LIVE_POLL_QUANTUM + 3);
        assert!(!backlog);
        assert_eq!(drain.source().remaining(), 0);
    }

    #[test]
    fn a_breaking_callback_stops_the_poll_at_once_with_the_rest_queued() {
        let events = (0..3).map(|_| sample_event());
        let mut drain = EventDrain::over(ScriptedRecords::events(events, 1));

        let backlog = drain.poll(Some(LIVE_POLL_QUANTUM), |_| ControlFlow::Break(()));

        assert!(backlog);
        assert_eq!(drain.source().remaining(), 2);
    }

    /// A malformed record is one dequeue of work like any other: it counts
    /// against the quantum and is reported, never skipped over for free.
    #[test]
    fn malformed_records_count_against_the_quantum() {
        let records = vec![
            to_bytes(&sample_event()),
            vec![0u8; 3],
            to_bytes(&sample_event()),
        ];
        let mut drain = EventDrain::over(ScriptedRecords::records(records, 2));

        let (seen, backlog) = counting_poll(&mut drain, Some(2));

        assert_eq!(seen, 1);
        assert_eq!(drain.malformed(), 1);
        assert!(backlog);
        assert_eq!(drain.source().remaining(), 1);
    }

    #[test]
    fn correct_size_round_trips_field_values() {
        let ev = sample_event();
        let decoded = decode(&to_bytes(&ev)).expect("correct-size bytes must decode");
        assert_eq!(decoded.ts_ns, ev.ts_ns);
        assert_eq!(decoded.duration_ns, ev.duration_ns);
        assert_eq!(decoded.pid_tgid, ev.pid_tgid);
        assert_eq!(decoded.cgroup_id, ev.cgroup_id);
        assert_eq!(decoded.session, ev.session);
        assert_eq!(decoded.mechanism, ev.mechanism);
        assert_eq!(decoded.rv, ev.rv);
        assert_eq!(decoded.slot, ev.slot);
        assert_eq!(decoded.user_type, ev.user_type);
    }

    #[test]
    fn short_slice_is_rejected() {
        let bytes = to_bytes(&sample_event());
        assert!(decode(&bytes[..bytes.len() - 1]).is_none());
    }

    #[test]
    fn oversized_slice_is_rejected() {
        let mut bytes = to_bytes(&sample_event());
        bytes.push(0);
        assert!(decode(&bytes).is_none());
    }

    #[test]
    fn empty_slice_is_rejected() {
        assert!(decode(&[]).is_none());
    }

    use crate::attach::detailed_identity::{ProofSession, TraceProofUnknown};
    use p11scope_ebpf_common::DISCOVERY_KIND_EXEC;
    use std::time::{Duration, Instant};
    fn proof_call(pid: u32, ts: u64, cookie: u64, exec: u64) -> Event {
        Event {
            pid_tgid: u64::from(pid) << 32,
            ts_ns: ts,
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: cookie,
                exec_id: exec,
            },
            ..Event::default()
        }
    }
    fn proof_lifecycle(pid: u32, ts: u64, kind: u8) -> DiscoveryRecord {
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.pid_tgid = (u64::from(pid) << 32) | u64::from(pid);
        record.hook_ts_ns = ts;
        record.kind = kind;
        record
    }
    fn cgroup_proof_cursor_fixture() -> (
        ProofSession,
        crate::process::ProcessView,
        crate::attach::detailed_identity::CgroupCandidate,
    ) {
        let scope = crate::attach::Scope::Cgroup {
            id: 1,
            path: "/retained-only".into(),
            dir: std::sync::Arc::new(std::fs::File::open("/dev/null").unwrap()),
        };
        let proof = ProofSession::test_scope(&scope, true);
        proof.test_set_time(100);
        let view =
            crate::process::ProcessView::open(crate::process::ProcessViewId(0), std::process::id())
                .unwrap();
        let mut work = crate::attach::detailed_identity::TraceWorkTicket::test_new(
            proof.clone(),
            100,
            5_000_100,
        );
        let candidate = proof.register_cgroup(&view, &mut work).unwrap();
        proof.test_set_time(200);
        (proof, view, candidate)
    }
    #[test]
    fn cgroup_trace_bracket_all_actual_event_routes_preserve_delivery() {
        for route in 0..4 {
            let (proof, view, pending) = cgroup_proof_cursor_fixture();
            let source = CursorScript::scripted([event_bytes(&proof_call(view.pid(), 101, 11, 0))]);
            let cursor = source.cursor.clone();
            let mut drain = EventDrain::over_domain(source, proof.test_events_domain());
            drain.attach_trace_tap(proof.test_events_tap()).unwrap();
            let mut seen = 0;
            let mut callback = || {
                seen += 1;
                assert_eq!(
                    cursor.get(),
                    if route == 2 { 8 } else { 0 },
                    "retain each route's existing item release boundary"
                );
                assert_eq!(proof.test_witness(pending.id()), Some((11, 0, 101)));
                assert_eq!(proof.usage(), (1, 0), "tap only mutates charged metadata");
            };
            match route {
                0 => {
                    drain.poll(Some(2), |_| {
                        callback();
                        ControlFlow::Continue(())
                    });
                }
                1 => {
                    drain.poll_records(Some(2), |_| {
                        callback();
                        ControlFlow::Continue(())
                    });
                }
                2 => {
                    poll_events_to_position(&mut drain, 8, Some(2), |_| {
                        callback();
                        ControlFlow::Continue(())
                    })
                    .unwrap();
                }
                _ => {
                    let mut tail = OwnedRootTail::new(
                        crate::run::OriginalRootExit::test_reaped(proof.test_events_domain()),
                        Instant::now() + Duration::from_secs(1),
                    );
                    drain.begin_root_tail(&mut tail).unwrap();
                    drain
                        .poll_root_tail(&mut tail, 2, |_| {
                            callback();
                            Ok(())
                        })
                        .unwrap();
                }
            }
            assert_eq!(seen, 1);
            assert_eq!(cursor.get(), 8);
        }
    }
    #[test]
    fn cgroup_trace_bracket_actual_discovery_routes_apply_once() {
        for route in 0..3 {
            let (proof, view, pending) = cgroup_proof_cursor_fixture();
            let mut events = EventDrain::over_domain(
                ScriptedRecords::events([proof_call(view.pid(), 101, 11, 0)], 1),
                proof.test_events_domain(),
            );
            events.attach_trace_tap(proof.test_events_tap()).unwrap();
            events.poll(None, |_| ControlFlow::Continue(()));
            let source = CursorScript::scripted([discovery_bytes(&proof_lifecycle(
                view.pid(),
                150,
                DISCOVERY_KIND_EXEC,
            ))]);
            let mut drain = DiscoveryDrain::over_domain(source, proof.test_discovery_domain());
            drain.attach_trace_tap(proof.test_discovery_tap()).unwrap();
            match route {
                0 => assert!(matches!(drain.dequeue(), Some(DiscoveryItem::Record(_)))),
                1 => {
                    let mut staged = ProofSession::test_stage_once(&mut drain);
                    let stamps = proof.test_clock_calls();
                    assert!(matches!(staged.pop(), Some(DiscoveryItem::Record(_))));
                    assert_eq!(
                        proof.test_clock_calls(),
                        stamps,
                        "FIFO replay is not a second observation"
                    );
                }
                _ => {
                    assert_eq!(
                        poll_discovery_to_position(&mut drain, 8, Some(1), |_| {
                            ControlFlow::Continue(())
                        })
                        .unwrap(),
                        (false, true)
                    );
                }
            }
            assert_eq!(
                proof
                    .test_cgroup_snapshot(pending.id())
                    .unwrap()
                    .contradiction,
                Some(150)
            );
            assert_eq!(proof.test_horizon(), None);
            assert!(drain.dequeue().is_none());
            assert_eq!(proof.test_horizon(), Some(200));
        }
    }
    #[test]
    fn cgroup_trace_bracket_root_tail_error_releases_and_invalidates() {
        let (proof, view, pending) = cgroup_proof_cursor_fixture();
        let source = CursorScript::scripted([event_bytes(&proof_call(view.pid(), 101, 11, 0))]);
        let cursor = source.cursor.clone();
        let mut drain = EventDrain::over_domain(source, proof.test_events_domain());
        drain.attach_trace_tap(proof.test_events_tap()).unwrap();
        let mut tail = OwnedRootTail::new(
            crate::run::OriginalRootExit::test_reaped(proof.test_events_domain()),
            Instant::now() + Duration::from_secs(1),
        );
        drain.begin_root_tail(&mut tail).unwrap();
        assert!(
            drain
                .poll_root_tail(&mut tail, 1, |_| {
                    assert_eq!(cursor.get(), 0);
                    anyhow::bail!("ordinary callback error")
                })
                .is_err()
        );
        assert_eq!(cursor.get(), 8);
        assert_eq!(
            proof.test_problem(pending.id()),
            Some(TraceProofUnknown::LifecycleLoss)
        );
    }
    // Preparation only: intended insertion into leased events.rs after shared core RED.
    // Every test calls retained production decoder entrypoints; pure decode cannot witness.
    #[test]
    fn detailed_proof_all_event_decoders_stamp_witness() {
        for route in 0..4 {
            let proof = ProofSession::test_session();
            let pending = proof.test_pending(7, 9, 10);
            let event = proof_call(7, 20, 11, 0);
            let mut drain = EventDrain::over_domain(
                ScriptedRecords::events([event], 1),
                proof.test_events_domain(),
            );
            drain.attach_trace_tap(proof.test_events_tap()).unwrap();
            let mut seen = 0;
            match route {
                0 => {
                    drain.poll(Some(2), |_| {
                        seen += 1;
                        ControlFlow::Continue(())
                    });
                }
                1 => {
                    drain.poll_records(Some(2), |_| {
                        seen += 1;
                        ControlFlow::Continue(())
                    });
                }
                2 => {
                    poll_events_to_position(&mut drain, 8, Some(2), |_| {
                        seen += 1;
                        ControlFlow::Continue(())
                    })
                    .unwrap();
                }
                _ => {
                    let mut tail = OwnedRootTail::new(
                        crate::run::OriginalRootExit::test_reaped(proof.test_events_domain()),
                        Instant::now() + Duration::from_secs(1),
                    );
                    drain.begin_root_tail(&mut tail).unwrap();
                    drain
                        .poll_root_tail(&mut tail, 2, |_| {
                            seen += 1;
                            Ok(())
                        })
                        .unwrap();
                }
            }
            assert_eq!(seen, 1);
            assert_eq!(proof.test_witness(pending.id()), Some((11, 0, 20)));
        }
    }

    #[test]
    fn detailed_proof_busy_head_is_not_empty() {
        let proof = ProofSession::test_session();
        let _pending = proof.test_pending(7, 9, 10);
        let mut source = CursorScript::scripted([]);
        source.producer = 8;
        let mut drain = DiscoveryDrain::over_domain(source, proof.test_discovery_domain());
        drain.attach_trace_tap(proof.test_discovery_tap()).unwrap();
        assert!(drain.dequeue().is_none());
        assert!(discovery_head_pending(&drain));
        assert_eq!(proof.test_horizon(), None);
        drain.source.producer = 0;
        assert!(drain.dequeue().is_none());
        assert_eq!(proof.test_horizon(), Some(100));
    }

    #[test]
    fn detailed_proof_quantum_and_q_boundary_do_not_grant_horizon() {
        for post_q in [false, true] {
            let proof = ProofSession::test_session();
            let _pending = proof.test_pending(7, 9, 10);
            let record = proof_lifecycle(8, 20, DISCOVERY_KIND_EXEC);
            let mut drain = DiscoveryDrain::over_domain(
                CursorScript::scripted([discovery_bytes(&record)]),
                proof.test_discovery_domain(),
            );
            drain.attach_trace_tap(proof.test_discovery_tap()).unwrap();
            assert_eq!(
                poll_discovery_to_position(&mut drain, 8, Some(1), |_| ControlFlow::Continue(()))
                    .unwrap(),
                (false, true)
            );
            assert_eq!(proof.test_horizon(), None);
            if post_q {
                drain.source.producer = 16;
            }
            assert_eq!(
                poll_discovery_to_position(&mut drain, 8, Some(1), |_| ControlFlow::Continue(()))
                    .unwrap(),
                (post_q, false)
            );
            assert_eq!(proof.test_horizon(), if post_q { None } else { Some(100) });
        }
    }

    #[test]
    fn detailed_proof_quiesce_direct_dequeue_invalidates() {
        let proof = ProofSession::test_session();
        let pending = proof.test_pending(7, 9, 10);
        let record = proof_lifecycle(7, 9, DISCOVERY_KIND_EXEC);
        let mut drain = DiscoveryDrain::over_domain(
            ScriptedRecords::records([discovery_bytes(&record)], 1),
            proof.test_discovery_domain(),
        );
        drain.attach_trace_tap(proof.test_discovery_tap()).unwrap();
        assert!(matches!(drain.dequeue(), Some(DiscoveryItem::Record(_))));
        assert_eq!(
            proof.test_problem(pending.id()),
            Some(TraceProofUnknown::ExecChanged)
        );
        assert!(drain.dequeue().is_none());
        assert_eq!(proof.test_horizon(), Some(100));
    }

    #[test]
    fn detailed_proof_stage_and_replay_observe_lifecycle_once() {
        let proof = ProofSession::test_session();
        let _pending = proof.test_pending(7, 9, 10);
        let mut drain = DiscoveryDrain::over_domain(
            ScriptedRecords::records([vec![0]], 1),
            proof.test_discovery_domain(),
        );
        drain.attach_trace_tap(proof.test_discovery_tap()).unwrap();
        let mut fifo = ProofSession::test_stage_once(&mut drain);
        assert_eq!(proof.test_epoch(), 1);
        assert!(matches!(fifo.pop(), Some(DiscoveryItem::Malformed)));
        assert_eq!(
            proof.test_epoch(),
            1,
            "replay cannot apply malformed loss twice"
        );
        assert!(drain.dequeue().is_none());
        assert_eq!(proof.test_horizon(), Some(100));
    }

    #[test]
    fn detailed_proof_disabled_tap_has_no_extra_operations() {
        let source = CursorScript::scripted([event_bytes(&Event::default())]);
        let cursor = source.cursor.clone();
        let mut drain = EventDrain::over(source);
        let mut seen = 0;
        drain.poll(Some(2), |_| {
            assert_eq!(cursor.get(), 0);
            seen += 1;
            ControlFlow::Continue(())
        });
        assert_eq!(seen, 1);
        assert_eq!(drain.malformed(), 0);
        // A counting proof clock/source is never installed and performs zero new operations.
    }
    #[test]
    fn detailed_proof_enabled_root_tail_preserves_callback_cursor_and_error() {
        for failed_clock in [false, true] {
            let proof = ProofSession::test_session();
            let pending = proof.test_pending(7, 9, 10);
            if failed_clock {
                proof.test_set_time(u64::MAX);
            }
            let source = CursorScript::scripted([event_bytes(&proof_call(7, 20, 11, 0))]);
            let cursor = source.cursor.clone();
            let mut drain = EventDrain::over_domain(source, proof.test_events_domain());
            drain.attach_trace_tap(proof.test_events_tap()).unwrap();
            let mut tail = OwnedRootTail::new(
                crate::run::OriginalRootExit::test_reaped(proof.test_events_domain()),
                Instant::now() + Duration::from_secs(1),
            );
            drain.begin_root_tail(&mut tail).unwrap();
            assert!(
                drain
                    .poll_root_tail(&mut tail, 1, |_| {
                        assert_eq!(cursor.get(), 0);
                        anyhow::bail!("ordinary callback error")
                    })
                    .is_err()
            );
            assert_eq!(cursor.get(), 8);
            assert_eq!(proof.test_horizon(), None);
            assert_eq!(
                proof.test_problem(pending.id()),
                Some(TraceProofUnknown::LifecycleLoss)
            );
        }
    }
    #[test]
    fn detailed_proof_disabled_discovery_does_no_new_clock_or_positions() {
        let proof = ProofSession::test_session();
        let before = proof.test_clock_calls();
        let mut drain = DiscoveryDrain::over(CursorScript::scripted([vec![0]]));
        assert!(matches!(drain.dequeue(), Some(DiscoveryItem::Malformed)));
        assert!(drain.dequeue().is_none());
        assert_eq!(proof.test_clock_calls(), before);
        assert_eq!(drain.source.positions_reads.get(), 0);
        let mut enabled = DiscoveryDrain::over_domain(
            CursorScript::scripted([vec![0]]),
            proof.test_discovery_domain(),
        );
        enabled
            .attach_trace_tap(proof.test_discovery_tap())
            .unwrap();
        assert!(matches!(enabled.dequeue(), Some(DiscoveryItem::Malformed)));
        assert!(enabled.dequeue().is_none());
        assert_eq!(proof.test_clock_calls(), before + 2);
        assert_eq!(enabled.source.positions_reads.get(), 1);
    }
    #[test]
    fn detailed_proof_bounded_discovery_break_and_busy_never_complete() {
        let proof = ProofSession::test_session();
        let seed = proof.test_pending(7, 9, 10);
        let mut drain = DiscoveryDrain::over_domain(
            CursorScript::scripted([discovery_bytes(&proof_lifecycle(7, 9, DISCOVERY_KIND_EXEC))]),
            proof.test_discovery_domain(),
        );
        drain.attach_trace_tap(proof.test_discovery_tap()).unwrap();
        let mut callbacks = 0;
        assert_eq!(
            poll_discovery_to_position(&mut drain, 8, None, |_| {
                callbacks += 1;
                assert_eq!(
                    proof.test_problem(seed.id()),
                    Some(TraceProofUnknown::ExecChanged)
                );
                ControlFlow::Break(())
            })
            .unwrap(),
            (false, true)
        );
        assert_eq!(callbacks, 1);
        assert_eq!(proof.test_horizon(), None);
        assert_eq!(
            poll_discovery_to_position(&mut drain, 8, None, |_| panic!("already consumed"))
                .unwrap(),
            (false, false)
        );
        assert_eq!(proof.test_horizon(), Some(100));
        let other = ProofSession::test_session();
        let _seed = other.test_pending(7, 9, 10);
        let mut source = CursorScript::scripted([]);
        source.producer = 8;
        let mut busy = DiscoveryDrain::over_domain(source, other.test_discovery_domain());
        busy.attach_trace_tap(other.test_discovery_tap()).unwrap();
        assert!(
            poll_discovery_to_position(&mut busy, 8, None, |_| panic!("reserved head")).is_err()
        );
        assert_eq!(other.test_horizon(), None);
        assert_eq!(other.test_epoch(), 1);
    }
    fn discovery_bytes(record: &DiscoveryRecord) -> Vec<u8> {
        // SAFETY: the shared repr(C) record is transported as these exact raw
        // bytes by the kernel ring buffer.
        unsafe {
            std::slice::from_raw_parts(
                (record as *const DiscoveryRecord).cast::<u8>(),
                size_of::<DiscoveryRecord>(),
            )
            .to_vec()
        }
    }

    /// Mutation caught: DISCOVERY is decoded with Event's size/validator or
    /// malformed discovery records leak into the Task 6 consumer.
    #[test]
    fn discovery_decode_is_exact_and_independent_from_events() {
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_LEADER_EXIT;
        record.pid_tgid = 7u64 << 32;
        let bytes = discovery_bytes(&record);
        assert_eq!(decode_discovery(&bytes).unwrap().pid_tgid, 7u64 << 32);
        assert!(decode_discovery(&bytes[..bytes.len() - 1]).is_none());
        let mut long = bytes.clone();
        long.push(0);
        assert!(decode_discovery(&long).is_none());

        let mut malformed = record;
        malformed.reserved_tail_zero[0] = 1;
        assert!(decode_discovery(&discovery_bytes(&malformed)).is_none());
    }

    #[test]
    fn exec_task_decode_keeps_920_byte_transport_and_private_finite_class() {
        let mut record = proof_lifecycle(7, 9, DISCOVERY_KIND_EXEC);
        for class in 0..=2 {
            record.case_id = class;
            let bytes = discovery_bytes(&record);
            assert_eq!(bytes.len(), 920);
            assert_eq!(bytes[865], class);
            assert_eq!(decode_discovery(&bytes).unwrap().case_id, class);
            assert!(decode_discovery(&bytes[..919]).is_none());
            let mut long = bytes;
            long.push(0);
            assert!(decode_discovery(&long).is_none());
        }
        for class in 3..=u8::MAX {
            record.case_id = class;
            assert!(decode_discovery(&discovery_bytes(&record)).is_none());
        }
        record.case_id = 1;
        for pid_tgid in [0, 7 << 32, (7 << 32) | 8, (1 << 63) | (1 << 31)] {
            record.pid_tgid = pid_tgid;
            assert!(decode_discovery(&discovery_bytes(&record)).is_none());
        }
        record.pid_tgid = (7 << 32) | 7;
        record.reserved_tail_zero[0] = 1;
        assert!(decode_discovery(&discovery_bytes(&record)).is_none());
        record.reserved_tail_zero[0] = 0;
        record.announced_count = 1;
        assert!(decode_discovery(&discovery_bytes(&record)).is_none());
    }

    /// Regression: one retained reader advances through backlog once, rejects
    /// malformed bytes once, and stays empty after the queue is consumed.
    #[test]
    fn retained_discovery_consumer_spans_valid_malformed_backlog_and_empty_polls() {
        let mut first: DiscoveryRecord = unsafe { std::mem::zeroed() };
        first.kind = DISCOVERY_KIND_LEADER_EXIT;
        first.pid_tgid = 7u64 << 32;
        let mut second = first;
        second.pid_tgid = 11u64 << 32;
        let records = [
            discovery_bytes(&first),
            vec![0u8; 3],
            discovery_bytes(&second),
        ];
        let mut drain = DiscoveryDrain::over(ScriptedRecords::records(records, 3));

        let Some(DiscoveryItem::Record(record)) = drain.dequeue() else {
            panic!("first valid discovery record was not dequeued");
        };
        assert_eq!(record.pid_tgid, 7u64 << 32);
        assert_eq!(drain.source().remaining(), 2, "backlog stays on one cursor");
        assert!(matches!(drain.dequeue(), Some(DiscoveryItem::Malformed)));
        assert_eq!(drain.source().remaining(), 1);
        let Some(DiscoveryItem::Record(record)) = drain.dequeue() else {
            panic!("second valid discovery record was not dequeued");
        };
        assert_eq!(record.pid_tgid, 11u64 << 32);
        assert_eq!(drain.source().remaining(), 0);
        assert!(drain.dequeue().is_none());
        assert!(drain.dequeue().is_none());
    }
}

#[cfg(test)]
pub(crate) mod root_fence_tests {
    use super::*;
    use std::{
        cell::Cell,
        collections::VecDeque,
        rc::Rc,
        time::{Duration, Instant},
    };
    pub(crate) struct Source {
        pub(crate) cursor: Rc<Cell<usize>>,
        pub(crate) producer: usize,
        pub(crate) capacity: usize,
        pub(crate) records: VecDeque<Option<Vec<u8>>>,
        pub(crate) busy: bool,
    }
    pub(crate) struct Item {
        bytes: Vec<u8>,
        cursor: Rc<Cell<usize>>,
    }
    impl Deref for Item {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            &self.bytes
        }
    }
    impl Drop for Item {
        fn drop(&mut self) {
            self.cursor.set(self.cursor.get().wrapping_add(8));
        }
    }
    fn forbidden_ordinary_read() -> Option<Vec<u8>> {
        panic!("ordinary read bypassed the root fence")
    }
    impl RecordSource for Source {
        fn next_record(&mut self) -> Option<impl Deref<Target = [u8]> + '_> {
            forbidden_ordinary_read()
        }
    }
    impl BoundedRecordSource for Source {
        fn positions(&self) -> aya::maps::ring_buf::RingBufPositions {
            aya::maps::ring_buf::RingBufPositions {
                consumer: self.cursor.get(),
                producer: self.producer,
                capacity: self.capacity,
            }
        }
        fn consumer(&self) -> usize {
            self.cursor.get()
        }
        fn bounded_record(
            &mut self,
            stop: usize,
        ) -> Result<BoundedRecord<impl Deref<Target = [u8]> + '_>> {
            if self.cursor.get() == stop {
                return Ok(BoundedRecord::Reached);
            }
            if self.busy {
                return Ok(BoundedRecord::Pending);
            }
            match self.records.pop_front() {
                Some(Some(bytes)) => Ok(BoundedRecord::Item(Item {
                    bytes,
                    cursor: self.cursor.clone(),
                })),
                Some(None) => {
                    self.cursor.set(self.cursor.get().wrapping_add(8));
                    Ok(BoundedRecord::Pending)
                }
                None => Ok(BoundedRecord::Pending),
            }
        }
    }
    pub(crate) fn source(events: impl IntoIterator<Item = Event>) -> Source {
        let records: VecDeque<_> = events.into_iter().map(|e| Some(event_bytes(&e))).collect();
        Source {
            producer: records.len() * 8,
            cursor: Rc::new(Cell::new(0)),
            capacity: 4096,
            records,
            busy: false,
        }
    }
    fn tail(domain: EventsDomain) -> OwnedRootTail {
        OwnedRootTail::new(
            crate::run::OriginalRootExit::test_reaped(domain),
            Instant::now() + Duration::from_secs(1),
        )
    }
    #[test]
    fn root_fence_fixed_boundary_resumes_after_callback_and_drop() {
        let domain = EventsDomain::test_standin(101);
        let mut source = source([Event::default(); 3]);
        source.producer = 16; // The third record is a later reservation.
        let cursor = source.cursor.clone();
        let mut tail = tail(domain.clone());
        let mut drain = EventDrain::over_domain(source, domain.clone());
        drain.begin_root_tail(&mut tail).unwrap();
        let mut callbacks = 0;
        assert_eq!(
            drain
                .poll_root_tail(&mut tail, 1, |_| {
                    assert_eq!(cursor.get(), 0);
                    callbacks += 1;
                    Ok(())
                })
                .unwrap(),
            RootTailProgress::Yielded
        );
        let mut source = drain.source;
        source.producer = 24;
        let mut drain = EventDrain::over_domain(source, domain);
        assert_eq!(
            drain
                .poll_root_tail(&mut tail, 1, |_| {
                    assert_eq!(cursor.get(), 8);
                    callbacks += 1;
                    Ok(())
                })
                .unwrap(),
            RootTailProgress::Reached
        );
        assert_eq!(
            (callbacks, cursor.get(), drain.source.records.len()),
            (2, 16, 1)
        );
        assert!(tail.complete().is_ok());
    }
    #[test]
    fn root_fence_foreign_cursor_busy_timeout_cancel_and_reduction_refuse_completion() {
        for failure in 0..5 {
            let domain = EventsDomain::test_standin(102);
            let mut tail = tail(domain.clone());
            let mut drain = EventDrain::over_domain(source([Event::default()]), domain);
            drain.begin_root_tail(&mut tail).unwrap();
            match failure {
                0 => drain.domain = Some(EventsDomain::test_standin(103)),
                1 => drain.source.cursor.set(8),
                2 => {
                    drain.source.busy = true;
                    assert_eq!(
                        drain.poll_root_tail(&mut tail, 1, |_| Ok(())).unwrap(),
                        RootTailProgress::Pending
                    );
                    tail.check(false, Instant::now() + Duration::from_secs(2))
                        .unwrap_err();
                }
                3 => {
                    tail.check(true, Instant::now()).unwrap_err();
                }
                _ => {}
            }
            assert!(
                drain
                    .poll_root_tail(&mut tail, 1, |_| if failure == 4 {
                        anyhow::bail!("reducer failed")
                    } else {
                        Ok(())
                    })
                    .is_err()
            );
            assert!(tail.complete().is_err());
        }
    }
    #[test]
    fn root_fence_crossed_progress_and_resnapshot_never_complete() {
        for resnapshot in [false, true] {
            let domain = EventsDomain::test_standin(105);
            let mut tail = tail(domain.clone());
            let mut drain = EventDrain::over_domain(source([Event::default()]), domain);
            drain.begin_root_tail(&mut tail).unwrap();
            if resnapshot {
                drain.source.producer = 16;
                assert!(drain.begin_root_tail(&mut tail).is_err());
            } else {
                let cursor = drain.source.cursor.clone();
                assert!(
                    drain
                        .poll_root_tail(&mut tail, 1, |_| {
                            cursor.set(8);
                            Ok(())
                        })
                        .is_err()
                );
            }
            assert!(tail.complete().is_err());
        }
    }

    #[test]
    fn root_fence_zero_wrapping_discard_malformed_and_invalid_boundaries() {
        for (start, stop, valid) in [
            (0, 0, true),
            (usize::MAX - 7, 8, true),
            (0, 4096, false),
            (1, 8, false),
            (0, 7, false),
        ] {
            let domain = EventsDomain::test_standin(104);
            let mut tail = tail(domain.clone());
            let mut source = source([]);
            source.cursor.set(start);
            source.producer = stop;
            source.records.extend([None, Some(vec![1])]);
            let mut drain = EventDrain::over_domain(source, domain);
            assert_eq!(drain.begin_root_tail(&mut tail).is_ok(), valid);
            if !valid {
                assert!(tail.complete().is_err());
                continue;
            }
            loop {
                if drain.poll_root_tail(&mut tail, 1, |_| Ok(())).unwrap()
                    == RootTailProgress::Reached
                {
                    break;
                }
            }
            assert_eq!(drain.source.cursor.get(), stop);
            assert_eq!(drain.malformed(), u64::from(start != stop));
            assert!(tail.complete().is_ok());
        }
    }
}
