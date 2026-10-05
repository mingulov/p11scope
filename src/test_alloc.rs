//! SPDX-License-Identifier: GPL-3.0-or-later
//! A test-only allocation counter for reuse microbenchmarks (C7 wave A).
//!
//! The counters arm around one closure only; run counting tests with
//! `--test-threads=1` and a name filter, since allocations on other test
//! threads while armed would pollute the count. Production builds are
//! unaffected: this module only exists under `cfg(test)`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static ARMED: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        // SAFETY: delegates to the system allocator with the same layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: delegates to the system allocator with the same pointer
        // and layout it was allocated with.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static COUNTING: CountingAllocator = CountingAllocator;

/// Run `run` and return `(heap allocations, allocated bytes)` observed
/// while it ran. Counts only `alloc` (fresh heap blocks); `realloc` is
/// covered through its default `alloc` path.
pub(crate) fn count_allocs_during<T>(run: impl FnOnce() -> T) -> (T, usize, usize) {
    ALLOCS.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    let value = run();
    ARMED.store(false, Ordering::Relaxed);
    (
        value,
        ALLOCS.load(Ordering::Relaxed),
        ALLOC_BYTES.load(Ordering::Relaxed),
    )
}
