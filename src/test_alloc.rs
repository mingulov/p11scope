//! SPDX-License-Identifier: GPL-3.0-or-later
//! A test-only allocation counter for reuse microbenchmarks (C7 wave A).
//!
//! The counters are per thread and arm around one closure only, so a
//! count sees exactly the allocations that closure made on its own
//! thread: other tests running in parallel cannot pollute it. Every call
//! forwards to the system allocator with its own entry point (`calloc`
//! and `realloc` included), so the rest of the lib test binary allocates
//! exactly as it would without the counter. Production builds are
//! unaffected: this module only exists under `cfg(test)`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, RefCell};

// Const-initialized and without a destructor, so reading these inside the
// allocator neither allocates nor fails during thread teardown.
thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
    static ALLOC_BYTES: Cell<usize> = const { Cell::new(0) };
    static PEAK_ARMED: Cell<bool> = const { Cell::new(false) };
    static PEAK_INCOMPLETE: Cell<bool> = const { Cell::new(false) };
    // TLS contains the array directly: arming does not allocate a table or
    // construct a large array on the test's stack.
    static PEAK: RefCell<RequestedTracker> = const { RefCell::new(RequestedTracker::new()) };
}

/// Count one fresh heap block of `size` bytes when this thread is armed.
fn note_alloc(size: usize) {
    if ARMED.try_with(Cell::get).unwrap_or(false) {
        let _ = ALLOCS.try_with(|count| count.set(count.get().saturating_add(1)));
        let _ = ALLOC_BYTES.try_with(|bytes| bytes.set(bytes.get().saturating_add(size)));
    }
}

const TRACKED_BLOCK_LIMIT: usize = 8192;

#[derive(Clone, Copy)]
struct RequestedBlock {
    pointer: usize,
    bytes: usize,
    // 0 = empty, 1 = occupied, 2 = tombstone.
    state: u8,
}

impl RequestedBlock {
    const EMPTY: Self = Self {
        pointer: 0,
        bytes: 0,
        state: 0,
    };
}

/// Requested sizes of successful allocations made while armed, rather
/// than allocator usable sizes or process RSS. Baseline blocks are excluded.
/// `realloc_overlap_bytes` also allows the old and new tracked requests to
/// coexist, even if System happens to grow a block in place.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RequestedAllocationPeak {
    pub live_bytes: usize,
    pub peak_bytes: usize,
    pub realloc_overlap_bytes: usize,
    pub live_blocks: usize,
    pub failed_requests: usize,
    pub incomplete: bool,
}

struct RequestedTracker {
    blocks: [RequestedBlock; TRACKED_BLOCK_LIMIT],
    result: RequestedAllocationPeak,
}

impl RequestedTracker {
    const fn new() -> Self {
        Self {
            blocks: [RequestedBlock::EMPTY; TRACKED_BLOCK_LIMIT],
            result: RequestedAllocationPeak {
                live_bytes: 0,
                peak_bytes: 0,
                realloc_overlap_bytes: 0,
                live_blocks: 0,
                failed_requests: 0,
                incomplete: false,
            },
        }
    }

    fn reset(&mut self) {
        self.blocks.fill(RequestedBlock::EMPTY);
        self.result = RequestedAllocationPeak::default();
    }

    fn start(pointer: usize) -> usize {
        (pointer ^ (pointer >> 17) ^ (pointer >> 9)) & (TRACKED_BLOCK_LIMIT - 1)
    }

    fn remove(&mut self, pointer: usize) -> Option<usize> {
        let start = Self::start(pointer);
        for offset in 0..TRACKED_BLOCK_LIMIT {
            let index = (start + offset) & (TRACKED_BLOCK_LIMIT - 1);
            let block = &mut self.blocks[index];
            if block.state == 0 {
                return None;
            }
            if block.state == 1 && block.pointer == pointer {
                let bytes = block.bytes;
                block.state = 2;
                self.result.live_bytes = self.result.live_bytes.saturating_sub(bytes);
                self.result.live_blocks = self.result.live_blocks.saturating_sub(1);
                return Some(bytes);
            }
        }
        None
    }

    fn insert(&mut self, pointer: usize, bytes: usize) {
        let start = Self::start(pointer);
        let mut available = None;
        for offset in 0..TRACKED_BLOCK_LIMIT {
            let index = (start + offset) & (TRACKED_BLOCK_LIMIT - 1);
            let block = self.blocks[index];
            if block.state == 1 && block.pointer == pointer {
                self.result.incomplete = true;
                return;
            }
            if block.state != 1 && available.is_none() {
                available = Some(index);
            }
            if block.state == 0 {
                break;
            }
        }
        let Some(index) = available else {
            self.result.incomplete = true;
            return;
        };
        let Some(live) = self.result.live_bytes.checked_add(bytes) else {
            self.result.incomplete = true;
            return;
        };
        self.blocks[index] = RequestedBlock {
            pointer,
            bytes,
            state: 1,
        };
        self.result.live_bytes = live;
        self.result.live_blocks += 1;
        self.result.peak_bytes = self.result.peak_bytes.max(live);
        self.result.realloc_overlap_bytes = self.result.realloc_overlap_bytes.max(live);
    }

    fn allocated(&mut self, pointer: usize, bytes: usize) {
        if pointer == 0 {
            self.result.failed_requests = self.result.failed_requests.saturating_add(1);
        } else {
            self.insert(pointer, bytes);
        }
    }

    fn reallocated(&mut self, old: usize, new: usize, bytes: usize) {
        if new == 0 {
            // Failed realloc keeps its old block, whether baseline or tracked.
            self.result.failed_requests = self.result.failed_requests.saturating_add(1);
            return;
        }
        match self.result.live_bytes.checked_add(bytes) {
            Some(overlap) => {
                self.result.realloc_overlap_bytes = self.result.realloc_overlap_bytes.max(overlap);
            }
            None => self.result.incomplete = true,
        }
        self.remove(old);
        self.insert(new, bytes);
    }
}

fn note_peak(run: impl FnOnce(&mut RequestedTracker)) {
    if !PEAK_ARMED.try_with(Cell::get).unwrap_or(false) {
        return;
    }
    let complete = PEAK
        .try_with(|tracker| match tracker.try_borrow_mut() {
            Ok(mut tracker) => {
                run(&mut tracker);
                true
            }
            Err(_) => false,
        })
        .unwrap_or(false);
    if !complete {
        let _ = PEAK_INCOMPLETE.try_with(|flag| flag.set(true));
    }
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_alloc(layout.size());
        // SAFETY: delegates to the system allocator with the same layout.
        let pointer = unsafe { System.alloc(layout) };
        note_peak(|tracker| tracker.allocated(pointer as usize, layout.size()));
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_alloc(layout.size());
        // SAFETY: delegates to the system allocator with the same layout.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        note_peak(|tracker| tracker.allocated(pointer as usize, layout.size()));
        pointer
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Counted like the default `realloc` (a fresh block of `new_size`).
        note_alloc(new_size);
        // SAFETY: delegates to the system allocator with the pointer, the
        // layout it was allocated with, and the caller's new size.
        let pointer = unsafe { System.realloc(ptr, layout, new_size) };
        note_peak(|tracker| tracker.reallocated(ptr as usize, pointer as usize, new_size));
        pointer
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        note_peak(|tracker| {
            tracker.remove(ptr as usize);
        });
        // SAFETY: delegates to the system allocator with the same pointer
        // and layout it was allocated with.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static COUNTING: CountingAllocator = CountingAllocator;

/// Run `run` and return `(heap allocations, allocated bytes)` it made on
/// this thread. `alloc`, `alloc_zeroed` and `realloc` each count one
/// block (a `realloc` counts its new size).
pub(crate) fn count_allocs_during<T>(run: impl FnOnce() -> T) -> (T, usize, usize) {
    assert!(
        !ARMED.get() && !PEAK_ARMED.get(),
        "allocation probes cannot nest"
    );
    ALLOCS.set(0);
    ALLOC_BYTES.set(0);
    ARMED.set(true);
    let armed = AllocationProbeGuard(false);
    let value = run();
    drop(armed);
    (value, ALLOCS.get(), ALLOC_BYTES.get())
}

struct AllocationProbeGuard(bool);

impl Drop for AllocationProbeGuard {
    fn drop(&mut self) {
        if self.0 {
            PEAK_ARMED.set(false);
        } else {
            ARMED.set(false);
        }
    }
}

/// Track bounded requested-live storage and a separate conservative realloc
/// overlap peak on this thread. The caller must reject an incomplete report
/// and check `live_bytes/live_blocks` after expected temporary cleanup.
pub(crate) fn requested_peak_during<T>(run: impl FnOnce() -> T) -> (T, RequestedAllocationPeak) {
    assert!(
        !ARMED.get() && !PEAK_ARMED.get(),
        "allocation probes cannot nest"
    );
    PEAK.with(|tracker| tracker.borrow_mut().reset());
    PEAK_INCOMPLETE.set(false);
    PEAK_ARMED.set(true);
    let armed = AllocationProbeGuard(true);
    let value = run();
    drop(armed);
    let mut result = PEAK.with(|tracker| tracker.borrow().result);
    result.incomplete |= PEAK_INCOMPLETE.get();
    (value, result)
}

pub(crate) fn armed_requested_snapshot() -> RequestedAllocationPeak {
    assert!(
        PEAK_ARMED.get(),
        "snapshot is only meaningful inside an armed probe"
    );
    let mut result = PEAK.with(|tracker| tracker.borrow().result);
    result.incomplete |= PEAK_INCOMPLETE.get();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_peak_distinguishes_live_storage_and_realloc_overlap() {
        let baseline = Vec::<u8>::with_capacity(41);
        let (_, peak) = requested_peak_during(|| {
            drop(baseline);
            let zeroed = std::hint::black_box(vec![0u8; 100]);
            let mut grown = std::hint::black_box(Vec::<u8>::with_capacity(10));
            grown.resize(1000, 1);
            assert_eq!(grown.capacity(), 1000);
            drop(grown);
            drop(zeroed);
        });
        assert!(!peak.incomplete);
        assert_eq!((peak.live_bytes, peak.live_blocks), (0, 0));
        assert_eq!(peak.peak_bytes, 1100);
        assert_eq!(peak.realloc_overlap_bytes, 1110);
    }

    #[test]
    fn requested_peak_handles_failed_in_place_and_moving_realloc() {
        // Exercise outcomes deterministically without requesting OOM or
        // depending on which result System's realloc chooses on this host.
        PEAK.with(|tracker| {
            let mut tracker = tracker.borrow_mut();
            tracker.reset();
            tracker.allocated(0x100, 40);
            tracker.reallocated(0x100, 0, 80);
            assert_eq!(tracker.result.live_bytes, 40);
            tracker.reallocated(0x100, 0x100, 80);
            assert_eq!(tracker.result.live_bytes, 80);
            assert_eq!(tracker.result.realloc_overlap_bytes, 120);
            tracker.reallocated(0x100, 0x200, 160);
            assert_eq!(tracker.result.live_bytes, 160);
            assert_eq!(tracker.result.realloc_overlap_bytes, 240);
            assert_eq!(tracker.remove(0x100), None);
            assert_eq!(tracker.remove(0x200), Some(160));
            // Reallocation of a baseline block starts tracking its new
            // request, but does not count pre-probe persistent storage.
            tracker.reallocated(0x300, 0x400, 20);
            assert_eq!(tracker.result.live_bytes, 20);
            assert_eq!(tracker.result.failed_requests, 1);
            assert!(!tracker.result.incomplete);
            tracker.reset();
        });
    }

    #[test]
    fn requested_peak_reports_bounded_table_overflow() {
        PEAK.with(|tracker| {
            let mut tracker = tracker.borrow_mut();
            tracker.reset();
            for pointer in 1..=TRACKED_BLOCK_LIMIT {
                tracker.allocated(pointer, 1);
            }
            assert_eq!(tracker.result.live_blocks, TRACKED_BLOCK_LIMIT);
            assert!(!tracker.result.incomplete);
            tracker.allocated(TRACKED_BLOCK_LIMIT + 1, 1);
            assert!(tracker.result.incomplete);
            assert_eq!(tracker.result.live_blocks, TRACKED_BLOCK_LIMIT);
            tracker.reset();
        });
    }

    #[test]
    fn requested_peak_excludes_other_threads_and_disarms_on_unwind() {
        let barrier = std::sync::Barrier::new(2);
        let peak = std::thread::scope(|scope| {
            // Thread startup is outside the armed parent interval: a
            // startup block can be allocated here and freed by the child.
            let helper = scope.spawn(|| {
                barrier.wait();
                let (_, own) = requested_peak_during(|| {
                    std::hint::black_box(vec![0u8; 123_456]);
                });
                barrier.wait();
                own
            });
            let (_, peak) = requested_peak_during(|| {
                barrier.wait();
                barrier.wait();
            });
            let own = helper.join().unwrap();
            assert!(!own.incomplete);
            assert_eq!(own.peak_bytes, 123_456);
            assert_eq!(own.live_bytes, 0);
            peak
        });
        assert!(!peak.incomplete);
        assert!(peak.peak_bytes < 123_456);
        assert_eq!(peak.live_bytes, 0);
        let panic = std::panic::catch_unwind(|| {
            requested_peak_during(|| {
                let _temporary = std::hint::black_box(vec![0u8; 17]);
                panic!("exercise peak probe guard");
            });
        });
        assert!(panic.is_err());
        assert!(!PEAK_ARMED.get());
        let (_, peak) = requested_peak_during(|| std::hint::black_box(vec![0u8; 23]));
        assert_eq!((peak.live_bytes, peak.peak_bytes), (23, 23));
        assert!(!peak.incomplete);
        // The cumulative counter also disarms during unwinding.
        let panic = std::panic::catch_unwind(|| {
            count_allocs_during(|| panic!("exercise count probe guard"));
        });
        assert!(panic.is_err());
        assert!(!ARMED.get());
    }

    #[test]
    fn requested_peak_refuses_nested_probes_without_losing_outer_guard() {
        let panic = std::panic::catch_unwind(|| {
            requested_peak_during(|| count_allocs_during(|| ()));
        });
        assert!(panic.is_err());
        assert!(!ARMED.get() && !PEAK_ARMED.get());
    }

    /// Allocations another thread makes while this one is armed are not
    /// counted, so the counting tests are exact under parallel runs.
    #[test]
    fn counts_only_the_arming_thread() {
        let (_, allocs, bytes) = super::count_allocs_during(|| {
            std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        for size in 1..=64usize {
                            std::hint::black_box(vec![0u8; size]);
                        }
                    })
                    .join()
                    .unwrap();
            });
        });
        // Spawning the helper may allocate on this thread (its handle and
        // name); the helper's 64 vectors must not show up here.
        assert!(allocs < 64, "the helper thread's allocations were counted");
        assert!(bytes < (1..=64usize).sum::<usize>());

        let (_, allocs, bytes) = super::count_allocs_during(|| {
            let zeroed = std::hint::black_box(vec![0u8; 100]);
            let mut grown = std::hint::black_box(Vec::<u8>::with_capacity(10));
            grown.resize(1000, 1);
            (zeroed, grown)
        });
        assert_eq!(allocs, 3, "alloc_zeroed, alloc and realloc each count");
        assert_eq!(bytes, 100 + 10 + 1000);
    }
}
