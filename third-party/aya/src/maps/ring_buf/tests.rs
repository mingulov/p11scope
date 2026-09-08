use std::{fs::File, io::Write as _, os::unix::fs::FileExt as _, ptr};

use super::*;
use crate::sys::TEST_MMAP_RET;

// Aya's unit-test syscall layer substitutes mmap and suppresses munmap. Supply
// real mappings to that existing hook, restoring it even if construction panics.
struct Mapping {
    ptr: *mut libc::c_void,
    len: usize,
}

impl Mapping {
    fn new(file: &File, len: usize, prot: libc::c_int, offset: usize) -> Self {
        // SAFETY: the owned file was fully initialized through offset + len.
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                prot,
                MAP_SHARED,
                file.as_raw_fd(),
                offset.try_into().unwrap(),
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        Self { ptr, len }
    }

    fn construct<T>(&self, f: impl FnOnce() -> T) -> T {
        struct Restore(*mut libc::c_void);
        impl Drop for Restore {
            fn drop(&mut self) {
                TEST_MMAP_RET.with(|ret| *ret.borrow_mut() = self.0);
            }
        }
        let _restore = Restore(TEST_MMAP_RET.with(|ret| ret.replace(self.ptr)));
        f()
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this guard owns the mapping; the reader is dropped first.
        let _ret = unsafe { libc::munmap(self.ptr, self.len) };
    }
}

struct Fixture {
    // Field drop order keeps the mappings and original FD alive for the reader.
    ring: RingBuf<()>,
    consumer_mapping: Mapping,
    producer_mapping: Mapping,
    file: File,
}

impl Fixture {
    fn new(consumer: usize, producer: usize, records: &[(usize, u32, &[u8])]) -> Self {
        let page = page_size();
        // Consumer metadata, producer metadata, and two finite data banks.
        // These are regular-file pages, NOT kernel double-map aliases. Each
        // record stays in the first data bank, including one ending at wrap.
        let mut bytes = vec![0; 4 * page];
        bytes[..size_of::<usize>()].copy_from_slice(&consumer.to_ne_bytes());
        bytes[page..page + size_of::<usize>()].copy_from_slice(&producer.to_ne_bytes());
        for &(position, flags, payload) in records {
            let offset = position & (page - 1);
            assert_eq!(offset % 8, 0);
            assert!(offset + 8 + payload.len() <= page);
            let start = 2 * page + offset;
            let header = u32::try_from(payload.len()).unwrap() | flags;
            bytes[start..start + 4].copy_from_slice(&header.to_ne_bytes());
            bytes[start + 8..start + 8 + payload.len()].copy_from_slice(payload);
        }
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&bytes).unwrap();
        let consumer_mapping = Mapping::new(&file, page, PROT_READ | PROT_WRITE, 0);
        let producer_mapping = Mapping::new(&file, 3 * page, PROT_READ, page);
        let consumer = consumer_mapping
            .construct(|| ConsumerPos::new(ConsumerMetadata::new(file.as_fd(), 0, page).unwrap()));
        let producer = producer_mapping.construct(|| {
            ProducerData::new(file.as_fd(), page, page, page.try_into().unwrap()).unwrap()
        });
        Self {
            ring: RingBuf {
                map: (),
                consumer,
                producer,
            },
            consumer_mapping,
            producer_mapping,
            file,
        }
    }

    fn assert_position(&self, expected: usize) {
        assert_eq!(self.ring.consumer.pos, expected);
        assert_eq!(
            self.ring.consumer.metadata.as_ref().load(Ordering::Acquire),
            expected
        );
    }

    fn set_producer_position(&self, producer: usize) {
        self.file
            .write_all_at(&producer.to_ne_bytes(), page_size().try_into().unwrap())
            .unwrap();
    }

    fn set_record_flags(&self, position: usize, payload_len: usize, flags: u32) {
        let offset = position & (page_size() - 1);
        let header = u32::try_from(payload_len).unwrap() | flags;
        self.file
            .write_all_at(
                &header.to_ne_bytes(),
                (2 * page_size() + offset).try_into().unwrap(),
            )
            .unwrap();
    }

    fn recreate_ring(&self) -> RingBuf<()> {
        let page = page_size();
        let consumer = self.consumer_mapping.construct(|| {
            ConsumerPos::new(ConsumerMetadata::new(self.file.as_fd(), 0, page).unwrap())
        });
        let producer = self.producer_mapping.construct(|| {
            ProducerData::new(self.file.as_fd(), page, page, page.try_into().unwrap()).unwrap()
        });
        RingBuf {
            map: (),
            consumer,
            producer,
        }
    }
}

#[test]
fn snapshot_positions_reads_fresh_producer_and_actual_capacity() {
    let fixture = Fixture::new(0, 16, &[(0, 0, b"payload!")]);
    assert_eq!(fixture.ring.producer.pos_cache, 16);
    fixture.set_producer_position(32);

    assert_eq!(
        fixture.ring.snapshot_positions(),
        RingBufPositions {
            consumer: 0,
            producer: 32,
            capacity: page_size(),
        }
    );
    assert_eq!(fixture.ring.producer.pos_cache, 16);
    assert_eq!(fixture.ring.consumer_position(), 0);
}

#[test]
fn bounded_data_reaches_stop_only_after_item_release() {
    let mut fixture = Fixture::new(0, 16, &[(0, 0, b"payload!")]);
    let item = assert_matches::assert_matches!(
        fixture.ring.next_before(16).unwrap(),
        BoundedRingBufRead::Item(item) => item
    );
    assert_eq!(&*item, b"payload!");
    assert_eq!(item.consumer.pos, 0);
    drop(item);
    assert_eq!(fixture.ring.consumer_position(), 16);
    assert!(matches!(
        fixture.ring.next_before(16).unwrap(),
        BoundedRingBufRead::Reached
    ));
}

#[test]
fn bounded_discarded_last_record_reaches_stop() {
    let mut fixture = Fixture::new(0, 16, &[(0, BPF_RINGBUF_DISCARD_BIT, b"discard!")]);
    assert!(matches!(
        fixture.ring.next_before(16).unwrap(),
        BoundedRingBufRead::Reached
    ));
    fixture.assert_position(16);
}

#[test]
fn bounded_all_discard_prefix_does_not_consume_sentinel() {
    let mut fixture = Fixture::new(
        0,
        48,
        &[
            (0, BPF_RINGBUF_DISCARD_BIT, b"discard!"),
            (16, BPF_RINGBUF_DISCARD_BIT, b"discard!"),
            (32, 0, b"sentinel"),
        ],
    );
    assert!(matches!(
        fixture.ring.next_before(32).unwrap(),
        BoundedRingBufRead::Reached
    ));
    fixture.assert_position(32);
    let sentinel = fixture.ring.next().unwrap();
    assert_eq!(&*sentinel, b"sentinel");
}

#[test]
fn bounded_busy_before_stop_is_pending_and_busy_at_stop_is_ignored() {
    let mut before = Fixture::new(0, 16, &[(0, BPF_RINGBUF_BUSY_BIT, b"notready")]);
    assert!(matches!(
        before.ring.next_before(16).unwrap(),
        BoundedRingBufRead::Pending
    ));
    before.assert_position(0);

    let mut at_stop = Fixture::new(16, 32, &[(16, BPF_RINGBUF_BUSY_BIT, b"newtraffic")]);
    assert!(matches!(
        at_stop.ring.next_before(16).unwrap(),
        BoundedRingBufRead::Reached
    ));
    at_stop.assert_position(16);
}

#[test]
fn bounded_busy_transition_to_commit_or_discard_uses_same_record() {
    let mut committed = Fixture::new(0, 16, &[(0, BPF_RINGBUF_BUSY_BIT, b"payload!")]);
    assert!(matches!(
        committed.ring.next_before(16).unwrap(),
        BoundedRingBufRead::Pending
    ));
    committed.set_record_flags(0, 8, 0);
    let item = assert_matches::assert_matches!(
        committed.ring.next_before(16).unwrap(),
        BoundedRingBufRead::Item(item) => item
    );
    assert_eq!(&*item, b"payload!");
    drop(item);

    let mut discarded = Fixture::new(0, 16, &[(0, BPF_RINGBUF_BUSY_BIT, b"discard!")]);
    assert!(matches!(
        discarded.ring.next_before(16).unwrap(),
        BoundedRingBufRead::Pending
    ));
    discarded.set_record_flags(0, 8, BPF_RINGBUF_DISCARD_BIT);
    assert!(matches!(
        discarded.ring.next_before(16).unwrap(),
        BoundedRingBufRead::Reached
    ));
    discarded.assert_position(16);
}

#[test]
fn bounded_snapshot_stays_fixed_when_producer_extends() {
    let mut fixture = Fixture::new(0, 16, &[(0, 0, b"original"), (16, 0, b"new data")]);
    let stop = fixture.ring.snapshot_positions().producer;
    fixture.set_producer_position(32);

    let item = assert_matches::assert_matches!(
        fixture.ring.next_before(stop).unwrap(),
        BoundedRingBufRead::Item(item) => item
    );
    assert_eq!(&*item, b"original");
    drop(item);
    assert!(matches!(
        fixture.ring.next_before(stop).unwrap(),
        BoundedRingBufRead::Reached
    ));
    let item = fixture.ring.next().unwrap();
    assert_eq!(&*item, b"new data");
}

#[test]
fn bounded_zero_prefix_is_reached() {
    let mut fixture = Fixture::new(24, 24, &[]);
    assert!(matches!(
        fixture.ring.next_before(24).unwrap(),
        BoundedRingBufRead::Reached
    ));
    fixture.assert_position(24);
}

#[test]
fn bounded_aligned_record_reaches_stop_across_word_wrap() {
    let start = usize::MAX - 15;
    let mut fixture = Fixture::new(start, 0, &[(start, 0, b"at-wrap!")]);
    let item = assert_matches::assert_matches!(
        fixture.ring.next_before(0).unwrap(),
        BoundedRingBufRead::Item(item) => item
    );
    assert_eq!(&*item, b"at-wrap!");
    drop(item);
    assert!(matches!(
        fixture.ring.next_before(0).unwrap(),
        BoundedRingBufRead::Reached
    ));
}

#[test]
fn bounded_invalid_boundaries_are_explicit_and_do_not_advance() {
    let mut invalid_capacity = Fixture::new(0, 0, &[]);
    invalid_capacity.ring.producer.mask = 0;
    assert!(matches!(
        invalid_capacity.ring.next_before(0),
        Err(RingBufBoundaryError::InvalidBoundary { .. })
    ));
    invalid_capacity.assert_position(0);

    let mut unaligned = Fixture::new(0, 16, &[(0, 0, b"payload!")]);
    assert!(matches!(
        unaligned.ring.next_before(7),
        Err(RingBufBoundaryError::InvalidBoundary { .. })
    ));
    unaligned.assert_position(0);

    let mut unaligned_consumer = Fixture::new(1, 16, &[]);
    assert!(matches!(
        unaligned_consumer.ring.next_before(8),
        Err(RingBufBoundaryError::InvalidBoundary { .. })
    ));
    unaligned_consumer.assert_position(1);

    let mut out_of_range = Fixture::new(0, 16, &[(0, 0, b"payload!")]);
    assert!(matches!(
        out_of_range.ring.next_before(page_size() + 8),
        Err(RingBufBoundaryError::BoundaryOutOfRange { .. })
    ));
    out_of_range.assert_position(0);

    let mut crossed = Fixture::new(16, 16, &[]);
    assert!(matches!(
        crossed.ring.next_before(0),
        Err(RingBufBoundaryError::BoundaryOutOfRange { .. })
    ));
    crossed.assert_position(16);
}

#[test]
fn bounded_record_crossing_boundary_is_rejected_without_advancing() {
    let mut data = Fixture::new(0, 16, &[(0, 0, b"payload!")]);
    assert!(matches!(
        data.ring.next_before(8),
        Err(RingBufBoundaryError::RecordCrossesBoundary { .. })
    ));
    data.assert_position(0);

    let mut discard = Fixture::new(0, 16, &[(0, BPF_RINGBUF_DISCARD_BIT, b"discard!")]);
    assert!(matches!(
        discard.ring.next_before(8),
        Err(RingBufBoundaryError::RecordCrossesBoundary { .. })
    ));
    discard.assert_position(0);
}

#[test]
fn bounded_reader_recreation_resumes_from_published_cursor() {
    let fixture = Fixture::new(0, 32, &[(0, 0, b"first!!!"), (16, 0, b"second!!")]);
    let mut ring = fixture.recreate_ring();
    let first = assert_matches::assert_matches!(
        ring.next_before(32).unwrap(),
        BoundedRingBufRead::Item(item) => item
    );
    assert_eq!(&*first, b"first!!!");
    drop(first);
    drop(ring);

    let mut ring = fixture.recreate_ring();
    assert_eq!(ring.consumer_position(), 16);
    let second = assert_matches::assert_matches!(
        ring.next_before(32).unwrap(),
        BoundedRingBufRead::Item(item) => item
    );
    assert_eq!(&*second, b"second!!");
    drop(second);
    assert!(matches!(
        ring.next_before(32).unwrap(),
        BoundedRingBufRead::Reached
    ));
}

#[test]
fn consumer_ordinary_advance_is_aligned_and_published() {
    let mut fixture = Fixture::new(24, 24, &[]);
    fixture.ring.consumer.consume(1);
    fixture.assert_position(40);
    assert!(fixture.ring.consumer.needs_wakeup);
}

#[test]
fn consumer_word_wrap_is_published() {
    let mut fixture = Fixture::new(usize::MAX - 15, 0, &[]);
    fixture.ring.consumer.consume(8);
    fixture.assert_position(0);
    assert!(fixture.ring.consumer.needs_wakeup);
}

#[test]
fn item_drop_consumes_exact_payload_once() {
    let mut fixture = Fixture::new(0, 16, &[(0, 0, b"payload!")]);
    assert_eq!(load_producer_pos(&fixture.ring.producer.mmap), 16);
    {
        let item = fixture.ring.next().unwrap();
        assert_eq!(&*item, b"payload!");
        assert_eq!(item.consumer.pos, 0);
        assert_eq!(item.consumer.metadata.as_ref().load(Ordering::Acquire), 0);
    }
    fixture.assert_position(16);
    assert!(fixture.ring.consumer.needs_wakeup);
    assert!(fixture.ring.next().is_none());
    assert!(!fixture.ring.consumer.needs_wakeup);
    assert!(fixture.ring.next().is_none());
    fixture.assert_position(16);
}

#[test]
fn item_drop_wraps_then_consumes_following_record_once() {
    let start = usize::MAX - 15;
    let mut fixture = Fixture::new(start, 16, &[(start, 0, b"at-wrap!"), (0, 0, b"at-zero!")]);
    let item = fixture.ring.next().unwrap();
    assert_eq!(&*item, b"at-wrap!");
    drop(item);
    fixture.assert_position(0);
    assert!(fixture.ring.consumer.needs_wakeup);
    let item = fixture.ring.next().unwrap();
    assert_eq!(&*item, b"at-zero!");
    drop(item);
    fixture.assert_position(16);
    assert!(fixture.ring.next().is_none());
    fixture.assert_position(16);
}

#[test]
fn discard_before_data_is_consumed_including_at_word_wrap() {
    for (start, data_pos, end) in [(0, 16, 32), (usize::MAX - 15, 0, 16)] {
        let mut fixture = Fixture::new(
            start,
            end,
            &[
                (start, BPF_RINGBUF_DISCARD_BIT, b"discard!"),
                (data_pos, 0, b"payload!"),
            ],
        );
        let item = fixture.ring.next().unwrap();
        assert_eq!(&*item, b"payload!");
        assert_eq!(item.consumer.pos, data_pos);
        assert_eq!(
            item.consumer.metadata.as_ref().load(Ordering::Acquire),
            data_pos
        );
        assert!(item.consumer.needs_wakeup);
        drop(item);
        fixture.assert_position(end);
        assert!(fixture.ring.next().is_none());
        fixture.assert_position(end);
    }
}

#[test]
fn busy_record_is_refused_without_consumption() {
    let mut fixture = Fixture::new(0, 16, &[(0, BPF_RINGBUF_BUSY_BIT, b"notready")]);
    assert!(fixture.ring.next().is_none());
    fixture.assert_position(0);
    // Also exercise the retry after publishing consumer progress.
    fixture.ring.consumer.needs_wakeup = true;
    assert!(fixture.ring.next().is_none());
    assert!(!fixture.ring.consumer.needs_wakeup);
    fixture.assert_position(0);
}
