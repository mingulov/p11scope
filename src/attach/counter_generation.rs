//! SPDX-License-Identifier: GPL-3.0-or-later
//! Process-local collection identity, independent of capture authority.

use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

static LAST_ISSUED: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Exhausted;

impl std::fmt::Display for Exhausted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("counter collection generation exhausted")
    }
}

impl std::error::Error for Exhausted {}

pub(super) fn allocate() -> Result<NonZeroU64, Exhausted> {
    allocate_from(&LAST_ISSUED)
}

fn allocate_from(issued: &AtomicU64) -> Result<NonZeroU64, Exhausted> {
    // Reservation order defines identity order. No other memory is published
    // by this token, so neither a fence nor completion-order guarantee applies.
    let previous = issued
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
            last.checked_add(1)
        })
        .map_err(|_| Exhausted)?;
    previous
        .checked_add(1)
        .and_then(NonZeroU64::new)
        .ok_or(Exhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn allocations_are_nonzero_and_increase_after_abandoned_attempts() {
        let issued = AtomicU64::new(0);
        assert_eq!(allocate_from(&issued).unwrap().get(), 1);
        // A failed preparation may abandon a reserved identity; it is never
        // returned to the allocator or reused by the next Session.
        let _abandoned = allocate_from(&issued).unwrap();
        assert_eq!(allocate_from(&issued).unwrap().get(), 3);
        for expected in 4..=16 {
            assert_eq!(allocate_from(&issued).unwrap().get(), expected);
        }
        assert_eq!(issued.load(Ordering::Relaxed), 16);
    }

    #[test]
    fn concurrent_allocations_are_unique_without_completion_order_assumptions() {
        const THREADS: usize = 8;
        const EACH: usize = 64;
        let issued = AtomicU64::new(0);
        let start = Barrier::new(THREADS);
        let mut values = std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..THREADS {
                let issued = &issued;
                let start = &start;
                workers.push(scope.spawn(move || {
                    start.wait();
                    let mut values = Vec::with_capacity(EACH);
                    for _ in 0..EACH {
                        values.push(allocate_from(issued).unwrap().get());
                    }
                    // Calls in one thread are ordered; returns from different
                    // threads need not be delivered in allocation order.
                    assert!(values.windows(2).all(|pair| pair[0] < pair[1]));
                    values
                }));
            }
            workers
                .into_iter()
                .flat_map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        values.sort_unstable();
        assert_eq!(values, (1..=(THREADS * EACH) as u64).collect::<Vec<_>>());
        // This call starts after every earlier allocation has completed.
        assert_eq!(
            allocate_from(&issued).unwrap().get(),
            (THREADS * EACH + 1) as u64
        );
    }

    #[test]
    fn exhaustion_is_sticky_and_never_wraps() {
        let issued = AtomicU64::new(u64::MAX - 1);
        assert_eq!(allocate_from(&issued).unwrap().get(), u64::MAX);
        for _ in 0..4 {
            assert_eq!(allocate_from(&issued), Err(Exhausted));
            assert_eq!(issued.load(Ordering::Relaxed), u64::MAX);
        }
        let already_exhausted = AtomicU64::new(u64::MAX);
        assert_eq!(allocate_from(&already_exhausted), Err(Exhausted));
        assert_eq!(already_exhausted.load(Ordering::Relaxed), u64::MAX);

        let issued = AtomicU64::new(u64::MAX - 3);
        let start = Barrier::new(8);
        let results = std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..8 {
                workers.push(scope.spawn(|| {
                    start.wait();
                    allocate_from(&issued)
                }));
            }
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 5);
        let mut tokens: Vec<_> = results
            .into_iter()
            .filter_map(Result::ok)
            .map(NonZeroU64::get)
            .collect();
        tokens.sort_unstable();
        assert_eq!(tokens, [u64::MAX - 2, u64::MAX - 1, u64::MAX]);
        assert_eq!(issued.load(Ordering::Relaxed), u64::MAX);
        assert_eq!(allocate_from(&issued), Err(Exhausted));
    }
}
