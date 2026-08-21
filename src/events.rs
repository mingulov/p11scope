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

/// Drains the `EVENTS` ring buffer, handing each well-formed record to a
/// caller-supplied closure and counting the rest as malformed.
pub struct Drain<'a> {
    ring: aya::maps::RingBuf<&'a mut MapData>,
    malformed: u64,
}

impl<'a> Drain<'a> {
    pub(crate) fn new(ebpf: &'a mut Ebpf) -> Result<Self> {
        let ring = aya::maps::RingBuf::try_from(ebpf.map_mut("EVENTS").context("EVENTS map")?)?;
        Ok(Self { ring, malformed: 0 })
    }

    /// Drains every record currently available without blocking.
    pub fn poll(&mut self, mut f: impl FnMut(Event)) {
        while let Some(item) = self.ring.next() {
            match decode(&item) {
                Some(event) => f(event),
                None => self.malformed += 1,
            }
        }
    }

    /// Records rejected by the size check so far.
    pub fn malformed(&self) -> u64 {
        self.malformed
    }
}

/// Fixed-purpose owner for the private live-discovery ring. Its malformed
/// count is deliberately independent from the public call-event transport.
pub(crate) struct DiscoveryDrain<'a> {
    ring: aya::maps::RingBuf<&'a mut MapData>,
    malformed: u64,
}

impl<'a> DiscoveryDrain<'a> {
    pub(crate) fn new(ebpf: &'a mut Ebpf) -> Result<Self> {
        let ring =
            aya::maps::RingBuf::try_from(ebpf.map_mut("DISCOVERY").context("DISCOVERY map")?)?;
        Ok(Self { ring, malformed: 0 })
    }

    pub(crate) fn poll(&mut self, mut f: impl FnMut(DiscoveryRecord)) {
        while let Some(item) = self.ring.next() {
            match decode_discovery(&item) {
                Some(record) => f(record),
                None => self.malformed += 1,
            }
        }
    }

    pub(crate) fn malformed(&self) -> u64 {
        self.malformed
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
        // SAFETY: mirrors what the kernel side does when it commits an
        // `Event` to the ring buffer: read it back as its raw bytes.
        unsafe {
            std::slice::from_raw_parts((ev as *const Event).cast::<u8>(), size_of::<Event>())
                .to_vec()
        }
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
