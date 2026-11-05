//! SPDX-License-Identifier: GPL-2.0-or-later
//! Measurement cost is independent of entry/return custody.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CounterMode {
    Counts,
    Timestamps,
    #[default]
    Latency,
}

impl CounterMode {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Counts => "counts",
            Self::Timestamps => "timestamps",
            Self::Latency => "latency",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "counts" => Some(Self::Counts),
            "timestamps" => Some(Self::Timestamps),
            "latency" => Some(Self::Latency),
            _ => None,
        }
    }

    pub const fn has_timing(self) -> bool {
        !matches!(self, Self::Counts)
    }

    pub const fn has_histogram(self) -> bool {
        matches!(self, Self::Latency)
    }

    pub const fn stats_bytes(self) -> u64 {
        match self {
            Self::Counts => 24,
            Self::Timestamps => 40,
            Self::Latency => 296,
        }
    }
}

/// A bounded atomic update never wraps or claims an increment it did not make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterUpdate {
    Added,
    Saturated,
    Contended,
}

/// Shared production policy. The kernel supplies its actual map-value CAS;
/// host controls supply real atomics or finite adversarial interference.
#[inline(always)]
pub fn add_counter_with(
    delta: u64,
    mut load: impl FnMut() -> u64,
    mut compare_exchange: impl FnMut(u64, u64) -> bool,
) -> CounterUpdate {
    for _ in 0..8 {
        let before = load();
        let after = before.saturating_add(delta);
        if compare_exchange(before, after) {
            return if delta > u64::MAX - before {
                CounterUpdate::Saturated
            } else {
                CounterUpdate::Added
            };
        }
    }
    CounterUpdate::Contended
}

/// Outcome of one exact-maximum update. A maximum never saturates: the
/// only loss disposition is bounded CAS contention, reported distinctly
/// like [`CounterUpdate::Contended`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterMaxUpdate {
    /// `candidate` exceeded the loaded value and the CAS installed it.
    Raised,
    /// The cell already held at least `candidate`; no write was needed.
    Kept,
    /// Bounded retries exhausted; the cell may hold less than `candidate`.
    Contended,
}

/// Shared exact-maximum policy. The kernel supplies its actual map-value
/// CAS; host controls supply real atomics or finite adversarial
/// interference. Returns [`CounterMaxUpdate::Kept`] without writing when
/// the cell already covers `candidate`, so a reader never observes a
/// torn or spurious maximum.
#[inline(always)]
pub fn max_counter_with(
    candidate: u64,
    mut load: impl FnMut() -> u64,
    mut compare_exchange: impl FnMut(u64, u64) -> bool,
) -> CounterMaxUpdate {
    for _ in 0..8 {
        let before = load();
        if candidate <= before {
            return CounterMaxUpdate::Kept;
        }
        if compare_exchange(before, candidate) {
            return CounterMaxUpdate::Raised;
        }
    }
    CounterMaxUpdate::Contended
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn real_update_saturates_and_never_wraps() {
        let value = Cell::new(u64::MAX - 1);
        let update = add_counter_with(
            2,
            || value.get(),
            |old, new| {
                assert_eq!(value.get(), old);
                value.set(new);
                true
            },
        );
        assert_eq!(update, CounterUpdate::Saturated);
        assert_eq!(value.get(), u64::MAX);
        assert_eq!(
            add_counter_with(0, || value.get(), |_, _| true),
            CounterUpdate::Added
        );
        assert_eq!(
            add_counter_with(1, || value.get(), |_, _| true),
            CounterUpdate::Saturated
        );
    }

    #[test]
    fn failed_update_has_a_finite_distinct_disposition() {
        let attempts = Cell::new(0);
        assert_eq!(
            add_counter_with(
                1,
                || 17,
                |_, _| {
                    attempts.set(attempts.get() + 1);
                    false
                }
            ),
            CounterUpdate::Contended
        );
        assert_eq!(attempts.get(), 8);
    }

    #[test]
    fn exact_maximum_raises_keeps_and_reports_contention() {
        let value = Cell::new(10u64);
        let attempts = Cell::new(0u32);
        let update = max_counter_with(
            25,
            || value.get(),
            |old, new| {
                attempts.set(attempts.get() + 1);
                assert_eq!(value.get(), old);
                value.set(new);
                true
            },
        );
        assert_eq!(update, CounterMaxUpdate::Raised);
        assert_eq!(value.get(), 25);
        assert_eq!(attempts.get(), 1);

        let writes = Cell::new(0u32);
        for candidate in [25, 9] {
            assert_eq!(
                max_counter_with(
                    candidate,
                    || value.get(),
                    |_, _| {
                        writes.set(writes.get() + 1);
                        true
                    }
                ),
                CounterMaxUpdate::Kept
            );
        }
        assert_eq!(value.get(), 25);
        assert_eq!(writes.get(), 0);

        let retries = Cell::new(0u32);
        assert_eq!(
            max_counter_with(
                40,
                || value.get(),
                |_, _| {
                    retries.set(retries.get() + 1);
                    false
                }
            ),
            CounterMaxUpdate::Contended
        );
        assert_eq!(retries.get(), 8);
        assert_eq!(value.get(), 25);
    }

    #[test]
    fn exact_maximum_keeps_a_concurrent_raise() {
        let value = Cell::new(10u64);
        let raised = Cell::new(false);
        let update = max_counter_with(
            25,
            || value.get(),
            |_, _| {
                if !raised.get() {
                    raised.set(true);
                    value.set(40);
                    false
                } else {
                    panic!("no second CAS once the cell covers the candidate");
                }
            },
        );
        assert_eq!(update, CounterMaxUpdate::Kept);
        assert_eq!(value.get(), 40);
    }

    #[test]
    fn capability_dimensions_are_independent() {
        assert!(!CounterMode::Counts.has_timing());
        assert!(CounterMode::Timestamps.has_timing());
        assert!(!CounterMode::Timestamps.has_histogram());
        assert!(CounterMode::Latency.has_histogram());
        assert_eq!(CounterMode::Counts.stats_bytes(), 24);
        assert_eq!(CounterMode::Timestamps.stats_bytes(), 40);
        assert_eq!(CounterMode::Latency.stats_bytes(), 296);
    }
}
