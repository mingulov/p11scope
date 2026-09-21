//! SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded discovery scheduling (Task 3.1b).
//!
//! Ordinary inventory ticks serve event-driven work (lifecycle/loader refresh
//! requests) plus a fairness-rotation window over unscanned processes, and
//! never re-read the whole machine's maps. A slower periodic reconciliation
//! sweep re-reads one bounded slice per pass — incremental cursor, generation
//! revalidation, wall-time quantum — and keeps rarity-ordered admission for
//! what the slice covers. Every queue is bounded with explicit overflow;
//! every deferral is published as a categorical coverage gap.

use std::collections::BTreeSet;

/// Bound for the lifecycle/loader refresh-request queue: one entry per
/// process-view slot, so queued work can never exceed what the capture
/// could admit. Excess requests are dropped with explicit truncation
/// evidence. Provisional — ratify by measurement.
pub(crate) const MAX_PENDING_REFRESH: usize = 256;

/// Reconciliation cadence: every Nth over-cap inventory pass runs the
/// bounded maps slice; the passes between serve queued and rotated work
/// without reading maps. Provisional — ratify by measurement.
pub(crate) const RECONCILE_EVERY_N_OVER_CAP_PASSES: u64 = 4;

/// Reconcile slice size: at most this many maps snapshots per sweep.
/// Provisional — ratify by measurement.
pub(crate) const RECONCILE_SLICE_PIDS: usize = 64;

/// Wall-time quantum for one reconcile slice, in nanoseconds. The slice
/// stops before a read that would exceed it; the remainder defers to the
/// next sweep with explicit evidence. Provisional — ratify by measurement.
pub(crate) const RECONCILE_QUANTUM_NS: u64 = 50_000_000;

/// Which over-cap selection ran on an inventory pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InventoryCadence {
    /// Queued event-driven work plus the rotation window; no maps reads.
    Ordinary,
    /// The bounded maps slice after the cursor, rarity-ordered inside.
    Reconcile,
}

/// The per-capture discovery schedule: over-cap pass count plus the
/// incremental reconcile cursor. Under-cap passes never touch it, so
/// under-cap behavior is unchanged by scheduling.
#[derive(Debug)]
pub(crate) struct DiscoveryScheduler {
    over_cap_passes: u64,
    cursor: Option<u32>,
    quantum_ns: u64,
    slice_pids: usize,
}

impl DiscoveryScheduler {
    pub(crate) fn new() -> Self {
        Self {
            over_cap_passes: 0,
            cursor: None,
            quantum_ns: RECONCILE_QUANTUM_NS,
            slice_pids: RECONCILE_SLICE_PIDS,
        }
    }

    /// Opens one over-cap inventory pass: counts it and reports whether
    /// this pass reconciles. The first pass after discovery is always
    /// ordinary — discovery just swept everything, so there is nothing
    /// to re-sweep yet.
    pub(crate) fn begin_over_cap_pass(&mut self) -> InventoryCadence {
        self.over_cap_passes = self.over_cap_passes.saturating_add(1);
        if self.over_cap_passes % RECONCILE_EVERY_N_OVER_CAP_PASSES == 0 {
            InventoryCadence::Reconcile
        } else {
            InventoryCadence::Ordinary
        }
    }

    #[cfg(test)]
    pub(crate) fn over_cap_passes(&self) -> u64 {
        self.over_cap_passes
    }

    pub(crate) fn cursor(&self) -> Option<u32> {
        self.cursor
    }

    /// Parks the cursor past the last pid a reconcile slice read.
    pub(crate) fn advance_cursor(&mut self, last_read: u32) {
        self.cursor = Some(last_read);
    }

    pub(crate) fn quantum_ns(&self) -> u64 {
        self.quantum_ns
    }

    pub(crate) fn slice_pids(&self) -> usize {
        self.slice_pids
    }

    #[cfg(test)]
    pub(crate) fn cursor_for_test(&self) -> Option<u32> {
        self.cursor()
    }

    #[cfg(test)]
    pub(crate) fn set_quantum_ns_for_test(&mut self, quantum_ns: u64) {
        self.quantum_ns = quantum_ns;
    }

    #[cfg(test)]
    pub(crate) fn set_slice_pids_for_test(&mut self, slice_pids: usize) {
        self.slice_pids = slice_pids;
    }

    /// The ordinary fairness-rotation window: the lowest `slots` pids
    /// outside `exclude` (retained views plus pending refresh pids), in
    /// pid order. Admitted pids join the excluded set, so successive
    /// passes walk the whole unscanned set; excluded pids are never
    /// returned, so rotation never displaces authoritative evidence.
    /// `pids` must be sorted ascending (`scope_pids` guarantees this).
    pub(crate) fn rotation_window(pids: &[u32], exclude: &BTreeSet<u32>, slots: usize) -> Vec<u32> {
        pids.iter()
            .copied()
            .filter(|pid| !exclude.contains(pid))
            .take(slots)
            .collect()
    }

    /// The enumerated pids rotated to start after `cursor`, wrapping past
    /// the end. A cursor for a departed pid still anchors the slice after
    /// it; `None` starts at the lowest pid. `pids` must be sorted
    /// ascending (`scope_pids` guarantees this).
    pub(crate) fn rotated_after(pids: &[u32], cursor: Option<u32>) -> Vec<u32> {
        let Some(cursor) = cursor else {
            return pids.to_vec();
        };
        let start = pids.partition_point(|pid| *pid <= cursor);
        let mut rotated = Vec::with_capacity(pids.len());
        rotated.extend_from_slice(&pids[start..]);
        rotated.extend_from_slice(&pids[..start]);
        rotated
    }
}

impl Default for DiscoveryScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The reconciliation cadence: ordinary passes serve queued and rotated
    /// work; every Nth over-cap pass runs the bounded maps slice instead.
    #[test]
    fn cadence_is_ordinary_until_every_nth_over_cap_pass() {
        let mut scheduler = DiscoveryScheduler::new();
        let cadences: Vec<InventoryCadence> =
            (0..8).map(|_| scheduler.begin_over_cap_pass()).collect();
        assert_eq!(
            cadences,
            [
                InventoryCadence::Ordinary,
                InventoryCadence::Ordinary,
                InventoryCadence::Ordinary,
                InventoryCadence::Reconcile,
                InventoryCadence::Ordinary,
                InventoryCadence::Ordinary,
                InventoryCadence::Ordinary,
                InventoryCadence::Reconcile,
            ]
        );
        assert_eq!(scheduler.over_cap_passes(), 8);
    }

    /// Ordinary rotation serves the lowest unscanned pids first; admitted
    /// pids join the excluded set, so successive passes walk the whole set.
    #[test]
    fn rotation_window_serves_lowest_unknowns_first() {
        let pids = [1, 2, 3, 4, 5];
        let exclude: BTreeSet<u32> = [2].into_iter().collect();
        assert_eq!(
            DiscoveryScheduler::rotation_window(&pids, &exclude, 2),
            vec![1, 3]
        );
    }

    /// The rotation window never returns an excluded pid: retained views and
    /// pending refresh pids are never displaced by speculative rotation.
    #[test]
    fn rotation_window_never_returns_excluded_pids() {
        let pids = [1, 2, 3];
        let exclude: BTreeSet<u32> = [1, 2, 3].into_iter().collect();
        assert!(DiscoveryScheduler::rotation_window(&pids, &exclude, 2).is_empty());
        let exclude: BTreeSet<u32> = [2].into_iter().collect();
        let window = DiscoveryScheduler::rotation_window(&pids, &exclude, 10);
        assert_eq!(window, vec![1, 3]);
        assert!(window.iter().all(|pid| !exclude.contains(pid)));
    }

    /// Zero free slots select nothing, with or without unscanned pids.
    #[test]
    fn rotation_window_zero_slots_is_empty() {
        let pids = [1, 2, 3];
        let exclude = BTreeSet::new();
        assert!(DiscoveryScheduler::rotation_window(&pids, &exclude, 0).is_empty());
    }

    /// The reconcile slice starts after the cursor and wraps past the end,
    /// so successive sweeps cover successive slices of the enumerated set.
    #[test]
    fn slice_rotation_starts_after_the_cursor_and_wraps() {
        let pids = [10, 20, 30, 40];
        assert_eq!(
            DiscoveryScheduler::rotated_after(&pids, None),
            vec![10, 20, 30, 40]
        );
        assert_eq!(
            DiscoveryScheduler::rotated_after(&pids, Some(20)),
            vec![30, 40, 10, 20]
        );
        assert_eq!(
            DiscoveryScheduler::rotated_after(&pids, Some(40)),
            vec![10, 20, 30, 40]
        );
    }

    /// A cursor for a departed pid still anchors the slice: the sweep
    /// resumes after it instead of restarting or stalling.
    #[test]
    fn slice_rotation_tolerates_a_dead_cursor() {
        let pids = [10, 20, 30];
        assert_eq!(
            DiscoveryScheduler::rotated_after(&pids, Some(99)),
            vec![10, 20, 30]
        );
        assert_eq!(
            DiscoveryScheduler::rotated_after(&pids, Some(15)),
            vec![20, 30, 10]
        );
        assert!(DiscoveryScheduler::rotated_after(&[], Some(15)).is_empty());
    }
}
