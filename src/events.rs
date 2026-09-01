//! Draining the EVENTS ring buffer into typed `Event` values. Every
//! record is size-checked before it is treated as an `Event`: a record of
//! the wrong length means the writer and reader have drifted, and that
//! must be visible as a `malformed` count, never guessed at via a
//! transmute of the wrong number of bytes.

use anyhow::{Context as _, Result};
use aya::Ebpf;
use aya::maps::MapData;
use p11scope_ebpf_common::{DiscoveryRecord, Event, valid_discovery_record};
use std::mem::size_of;
use std::ops::{ControlFlow, Deref};

/// Records one live poll consumes before returning to its caller's duration,
/// signal and `--max-events` checks. Several times the 256 KiB ring's ~900
/// record capacity, so a poll stopped here has emptied the ring repeatedly
/// and leaves only what the producer wrote during the poll itself; an
/// overflow before the next tick is the kernel's loss counter, reported as
/// `LOST n events` / `ring_loss` like any other.
pub const LIVE_POLL_QUANTUM: usize = 4096;

/// The bound one poll of the `EVENTS` ring gets: the quantum while producers
/// can still refill it, none once they are all detached and the drain is
/// finite. A partially failed detach keeps the ring live, so it keeps the bound.
pub fn poll_quantum(producers_detached: bool) -> Option<usize> {
    if producers_detached {
        None
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
/// length doesn't match `size_of::<Event>()`.
pub fn decode(bytes: &[u8]) -> Option<Event> {
    decode_exact(bytes)
}

pub(crate) fn decode_discovery(bytes: &[u8]) -> Option<DiscoveryRecord> {
    let record = decode_exact(bytes)?;
    valid_discovery_record(&record).then_some(record)
}

#[derive(Clone, Copy)]
#[allow(clippy::large_enum_variant)] // The fixed 896-byte ring ABI stays allocation-free per dequeue.
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

impl RecordSource for aya::maps::RingBuf<&mut MapData> {
    fn next_record(&mut self) -> Option<impl Deref<Target = [u8]> + '_> {
        self.next()
    }
}

/// The `EVENTS` drain over the live ring.
pub type Drain<'a> = EventDrain<aya::maps::RingBuf<&'a mut MapData>>;

/// Drains the `EVENTS` ring buffer, handing each well-formed record to a
/// caller-supplied closure and counting the rest as malformed.
pub struct EventDrain<S> {
    source: S,
    malformed: u64,
}

impl<'a> Drain<'a> {
    pub(crate) fn new(ebpf: &'a mut Ebpf) -> Result<Self> {
        let ring = aya::maps::RingBuf::try_from(ebpf.map_mut("EVENTS").context("EVENTS map")?)?;
        Ok(Self {
            source: ring,
            malformed: 0,
        })
    }
}

impl<S: RecordSource> EventDrain<S> {
    #[cfg(test)]
    pub(crate) fn over(source: S) -> Self {
        Self {
            source,
            malformed: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn source(&self) -> &S {
        &self.source
    }

    /// Drains up to `quantum` records without blocking; `None` is for a ring
    /// whose producers are detached, where the drain is finite. Returns
    /// `true` when it stopped with records possibly still queued — the
    /// quantum was reached or `f` broke — and `false` once the ring read empty.
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
                None => self.malformed += 1,
            }
        }
    }

    /// Records rejected by the size check so far.
    pub fn malformed(&self) -> u64 {
        self.malformed
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

/// The bytes the kernel side commits for one `Event`: the value read back raw.
#[cfg(test)]
pub(crate) fn event_bytes(ev: &Event) -> Vec<u8> {
    // SAFETY: `Event` is a repr(C) Pod value; this reads exactly its bytes.
    unsafe {
        std::slice::from_raw_parts((ev as *const Event).cast::<u8>(), size_of::<Event>()).to_vec()
    }
}

/// Fixed-purpose owner for the private live-discovery ring. Its malformed
/// count is deliberately independent from the public call-event transport.
pub(crate) struct DiscoveryDrain<'a> {
    ring: aya::maps::RingBuf<&'a mut MapData>,
}

impl<'a> DiscoveryDrain<'a> {
    pub(crate) fn new(ebpf: &'a mut Ebpf) -> Result<Self> {
        let ring =
            aya::maps::RingBuf::try_from(ebpf.map_mut("DISCOVERY").context("DISCOVERY map")?)?;
        Ok(Self { ring })
    }

    pub(crate) fn dequeue(&mut self) -> Option<DiscoveryItem> {
        let item = self.ring.next()?;
        match decode_discovery(&item) {
            Some(record) => Some(DiscoveryItem::Record(record)),
            None => Some(DiscoveryItem::Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::DISCOVERY_KIND_LEADER_EXIT;

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

    fn counting_poll(
        drain: &mut EventDrain<ScriptedRecords>,
        quantum: Option<usize>,
    ) -> (usize, bool) {
        let mut seen = 0;
        let backlog = drain.poll(quantum, |_| {
            seen += 1;
            ControlFlow::Continue(())
        });
        (seen, backlog)
    }

    #[test]
    fn only_a_fully_detached_ring_is_polled_without_a_quantum() {
        assert_eq!(poll_quantum(false), Some(LIVE_POLL_QUANTUM));
        assert_eq!(poll_quantum(true), None);
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
}
