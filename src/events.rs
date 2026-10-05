//! SPDX-License-Identifier: GPL-3.0-or-later
//! Draining the EVENTS ring buffer into typed `Event` values. Every
//! record is size-checked before it is treated as an `Event`: a record of
//! the wrong length means the writer and reader have drifted, and that
//! must be visible as a `malformed` count, never guessed at via a
//! transmute of the wrong number of bytes.

use anyhow::{Context as _, Result};
use aya::Ebpf;
use aya::maps::{Map, MapData};
use p11scope_ebpf_common::{DiscoveryRecord, Event, valid_discovery_record};
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
    pub(crate) fn id(&self) -> u64 {
        self.0.id.get()
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

/// Decodes one ring-buffer record into an `Event`, or `None` if its
/// length differs from `size_of::<Event>()` or its root affiliation is invalid.
pub fn decode(bytes: &[u8]) -> Option<Event> {
    let event: Event = decode_exact(bytes)?;
    (event.root_affiliation <= 1).then_some(event)
}

pub(crate) fn decode_discovery(bytes: &[u8]) -> Option<DiscoveryRecord> {
    let record = decode_exact(bytes)?;
    valid_discovery_record(&record).then_some(record)
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
}

impl RecordSource for aya::maps::RingBuf<MapData> {
    fn next_record(&mut self) -> Option<impl Deref<Target = [u8]> + '_> {
        self.next()
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
                        match decode(&item) {
                            Some(event) => reduce(event)?,
                            None => self.malformed += 1,
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
        })
    }
}

impl<S: RecordSource> EventDrain<S> {
    #[cfg(test)]
    pub(crate) fn over(source: S) -> Self {
        Self {
            source,
            malformed: 0,
            malformed_reported: 0,
            domain: None,
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
            match decode(&item) {
                Some(event) => {
                    if f(event).is_break() {
                        return true;
                    }
                }
                None => self.malformed = self.malformed.saturating_add(1),
            }
        }
    }

    /// Records rejected by the size or affiliation check so far.
    pub fn malformed(&self) -> u64 {
        self.malformed
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
                BoundedRecord::Item(item) => BoundedRecord::Item(decode(&item)),
                BoundedRecord::Reached => BoundedRecord::Reached,
                BoundedRecord::Pending => BoundedRecord::Pending,
            },
            Err(error) => return Ok((map_bounded_error(error)?, false)),
        };
        match record {
            BoundedRecord::Item(event) => {
                if let Some(left) = left.as_mut() {
                    *left -= 1;
                }
                match event {
                    Some(event) => {
                        if f(event).is_break() {
                            return Ok((false, true));
                        }
                    }
                    None => drain.malformed = drain.malformed.saturating_add(1),
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

/// The bytes the kernel side commits for one `Event`: the value read back raw.
#[cfg(test)]
pub(crate) fn event_bytes(ev: &Event) -> Vec<u8> {
    // SAFETY: `Event` is a repr(C) Pod value; this reads exactly its bytes.
    unsafe {
        std::slice::from_raw_parts((ev as *const Event).cast::<u8>(), size_of::<Event>()).to_vec()
    }
}

/// The session's single retained consumer for the private live-discovery ring.
/// It owns a duplicate descriptor and its mappings, while malformed records
/// remain deliberately independent from the public call-event transport.
pub(crate) type OwnedDiscoveryDrain = DiscoveryDrain<aya::maps::RingBuf<MapData>>;

pub(crate) struct DiscoveryDrain<S> {
    source: S,
    _domain: Option<DiscoveryDomain>,
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
        })
    }
}

impl<S: RecordSource> DiscoveryDrain<S> {
    #[cfg(test)]
    pub(crate) fn over(source: S) -> Self {
        Self {
            source,
            _domain: None,
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

    pub(crate) fn dequeue(&mut self) -> Option<DiscoveryItem> {
        let item = self.source.next_record()?;
        match decode_discovery(&item) {
            Some(record) => Some(DiscoveryItem::Record(record)),
            None => Some(DiscoveryItem::Malformed),
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
    let mut left = quantum;
    loop {
        if left == Some(0) {
            return Ok((false, true));
        }
        // Decode to an owned item first: matching the borrowed item
        // directly keeps the source borrow alive across the match,
        // blocking the post-Reached positions read below.
        let record: BoundedRecord<DiscoveryItem> = match drain.source.bounded_record(stop) {
            Ok(bounded) => match bounded {
                BoundedRecord::Item(item) => BoundedRecord::Item(match decode_discovery(&item) {
                    Some(record) => DiscoveryItem::Record(record),
                    None => DiscoveryItem::Malformed,
                }),
                BoundedRecord::Reached => BoundedRecord::Reached,
                BoundedRecord::Pending => BoundedRecord::Pending,
            },
            Err(error) => return Ok((map_bounded_error(error)?, false)),
        };
        match record {
            BoundedRecord::Item(item) => {
                if let Some(left) = left.as_mut() {
                    *left -= 1;
                }
                if f(item).is_break() {
                    return Ok((false, true));
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

#[cfg(test)]
mod runtime_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::DISCOVERY_KIND_LEADER_EXIT;

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
        assert!(peer.write(&[1]).is_ok());
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
    fn domain_boundary_decoder_accepts_only_event328_and_affiliations_zero_one() {
        for tag in [0, 1, 2, u64::MAX] {
            let event = Event {
                root_affiliation: tag,
                ..sample_event()
            };
            let bytes = event_bytes(&event);
            assert_eq!(bytes.len(), 328);
            assert_eq!(decode(&bytes).is_some(), tag <= 1);
            assert!(decode(&bytes[..320]).is_none());
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
