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
use std::cell::Cell;

// Const-initialized and without a destructor, so reading these inside the
// allocator neither allocates nor fails during thread teardown.
thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
    static ALLOC_BYTES: Cell<usize> = const { Cell::new(0) };
}

/// Count one fresh heap block of `size` bytes when this thread is armed.
fn note_alloc(size: usize) {
    if ARMED.try_with(Cell::get).unwrap_or(false) {
        let _ = ALLOCS.try_with(|count| count.set(count.get() + 1));
        let _ = ALLOC_BYTES.try_with(|bytes| bytes.set(bytes.get() + size));
    }
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_alloc(layout.size());
        // SAFETY: delegates to the system allocator with the same layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_alloc(layout.size());
        // SAFETY: delegates to the system allocator with the same layout.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Counted like the default `realloc` (a fresh block of `new_size`).
        note_alloc(new_size);
        // SAFETY: delegates to the system allocator with the pointer, the
        // layout it was allocated with, and the caller's new size.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
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
    ALLOCS.set(0);
    ALLOC_BYTES.set(0);
    ARMED.set(true);
    let value = run();
    ARMED.set(false);
    (value, ALLOCS.get(), ALLOC_BYTES.get())
}

#[cfg(test)]
mod tests {
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
