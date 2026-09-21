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

use std::collections::{BTreeMap, BTreeSet};

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

/// Exploratory rotation: at most this many provider-free views are evicted
/// per reconcile pass to make room for rarity-selected newcomers. Ordinary
/// passes never evict, so steady-state ticks displace nothing.
/// Provisional — ratify by measurement.
pub(crate) const MAX_EXPLORATORY_EVICTIONS_PER_PASS: usize = 8;

/// Eviction cooldown: a pid evicted as exploratory is ineligible for
/// re-selection for this many reconcile sweeps, so rotation walks forward
/// through the unscanned set instead of churning between two same-rarity
/// subsets. Event-driven refresh requests bypass the cooldown.
/// Provisional — ratify by measurement.
pub(crate) const RECONCILE_EVICTION_COOLDOWN_SWEEPS: u64 = 2;

/// Per-tick admission bound: at most this many new process views are
/// deep-scanned on one inventory tick, under or over the cap. Excess
/// newcomers defer to the next tick with explicit evidence; queued
/// event-driven work for them is retained, never dropped.
/// Provisional — ratify by measurement.
pub(crate) const MAX_NEW_VIEWS_PER_TICK: usize = 64;

/// Polling rescans per polling round: at most this many retained
/// exploratory views are queued for a same-tick refresh rescan, so a
/// retained process that gains a provider is re-examined within a finite
/// number of rounds even though it carries no loader context. A round runs
/// on every over-cap reconcile sweep and every fourth under-cap tick; the
/// poll cursor round-robins the eligible set and the tick quantum still
/// bounds the rescan phase. Provisional — ratify by measurement.
pub(crate) const MAX_POLLING_RESCANS: usize = 8;

/// Wall-time quantum for one tick's deep-scan phase, in nanoseconds:
/// refreshed-view rescans plus new-view admissions. The phase stops before
/// a scan that would exceed it; the remainder defers to the next tick with
/// explicit evidence. Provisional — ratify by measurement.
pub(crate) const TICK_DEEP_SCAN_QUANTUM_NS: u64 = 200_000_000;

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
    reconcile_sweeps: u64,
    /// Pids evicted as exploratory, each with the reconcile-sweep sequence
    /// number of its eviction. Two predicates read it: `cooling_down` (hard
    /// exclusion for `cooldown_sweeps` sweeps, the anti-churn window) and
    /// `is_stale` (soft deprioritization behind never-evicted pids, the
    /// fairness tier). Entries never expire by time — a cooled pid that
    /// rejoined too eagerly would starve higher never-scanned pids — and
    /// clear only on re-admission or departure, so the map holds at most
    /// the live enumerated pids.
    cooling: BTreeMap<u32, u64>,
    max_evictions: usize,
    cooldown_sweeps: u64,
    max_new_views: usize,
    tick_quantum_ns: u64,
    under_cap_ticks: u64,
    poll_cursor: Option<u32>,
    /// Wall-time deadline for the current tick's deep-scan phase, installed
    /// by `begin_deep_scan_tick`. `None` outside a tick means unbounded —
    /// direct scan calls (and unit tests driving them) are not ticks.
    tick_deadline_ns: Option<u64>,
}

impl DiscoveryScheduler {
    pub(crate) fn new() -> Self {
        Self {
            over_cap_passes: 0,
            cursor: None,
            quantum_ns: RECONCILE_QUANTUM_NS,
            slice_pids: RECONCILE_SLICE_PIDS,
            reconcile_sweeps: 0,
            cooling: BTreeMap::new(),
            max_evictions: MAX_EXPLORATORY_EVICTIONS_PER_PASS,
            cooldown_sweeps: RECONCILE_EVICTION_COOLDOWN_SWEEPS,
            max_new_views: MAX_NEW_VIEWS_PER_TICK,
            tick_quantum_ns: TICK_DEEP_SCAN_QUANTUM_NS,
            tick_deadline_ns: None,
            under_cap_ticks: 0,
            poll_cursor: None,
        }
    }

    /// Opens one over-cap inventory pass: counts it and reports whether
    /// this pass reconciles. The first pass after discovery is always
    /// ordinary — discovery just swept everything, so there is nothing
    /// to re-sweep yet. A reconcile pass also advances the sweep sequence
    /// that ages the hard cooldown window; the staleness map itself is
    /// sticky (see `cooling`) and pruned by enumeration, not by time.
    pub(crate) fn begin_over_cap_pass(&mut self) -> InventoryCadence {
        self.over_cap_passes = self.over_cap_passes.saturating_add(1);
        if self.over_cap_passes % RECONCILE_EVERY_N_OVER_CAP_PASSES == 0 {
            self.reconcile_sweeps = self.reconcile_sweeps.saturating_add(1);
            InventoryCadence::Reconcile
        } else {
            InventoryCadence::Ordinary
        }
    }

    /// Records one exploratory eviction at the current sweep sequence, so
    /// the pid sits out re-selection until its cooldown expires and stays
    /// fairness-stale until re-admission or departure.
    pub(crate) fn note_evicted(&mut self, pid: u32) {
        self.cooling.insert(pid, self.reconcile_sweeps);
    }

    /// Clears staleness on (re-)admission: a retained pid competes no more.
    pub(crate) fn note_admitted(&mut self, pid: u32) {
        self.cooling.remove(&pid);
    }

    /// Drops entries for pids no longer enumerated (departed — or PID reuse,
    /// whose new generation is correctly fresh). This is what bounds the
    /// map: at most the live enumerated pids.
    pub(crate) fn prune_stale_to_enumerated(&mut self, enumerated: &BTreeSet<u32>) {
        self.cooling.retain(|pid, _| enumerated.contains(pid));
    }

    /// Whether the pid is cooling down after an exploratory eviction and
    /// must sit out ordinary rotation and reconcile selection. Queued
    /// event-driven refresh requests bypass this test at the call site.
    pub(crate) fn cooling_down(&self, pid: u32) -> bool {
        self.cooling.get(&pid).is_some_and(|evicted_at| {
            self.reconcile_sweeps.saturating_sub(*evicted_at) < self.cooldown_sweeps
        })
    }

    /// Whether the pid was evicted and not since re-admitted (whether or
    /// not its hard window expired). Stale pids stay selectable but sort
    /// behind never-evicted pids within their rarity class, so rotation
    /// covers every pid instead of churning the lowest ones.
    pub(crate) fn is_stale(&self, pid: u32) -> bool {
        self.cooling.contains_key(&pid)
    }

    /// All currently stale pids, for fairness-tiered selection.
    pub(crate) fn stale_pids(&self) -> Vec<u32> {
        self.cooling.keys().copied().collect()
    }

    /// How many pids are currently cooling down (categorical evidence only;
    /// the pids themselves are never published).
    pub(crate) fn cooling_len(&self) -> usize {
        let sweeps = self.reconcile_sweeps;
        let cooldown = self.cooldown_sweeps;
        self.cooling
            .values()
            .filter(|evicted_at| sweeps.saturating_sub(**evicted_at) < cooldown)
            .count()
    }

    pub(crate) fn max_evictions_per_pass(&self) -> usize {
        self.max_evictions
    }

    pub(crate) fn max_new_views_per_tick(&self) -> usize {
        self.max_new_views
    }

    /// Counts one under-cap inventory tick and reports whether it runs a
    /// polling round: every fourth, mirroring the reconcile cadence, so
    /// quiet under-cap ticks keep their no-op behavior between rounds.
    pub(crate) fn begin_under_cap_tick(&mut self) -> bool {
        self.under_cap_ticks = self.under_cap_ticks.saturating_add(1);
        self.under_cap_ticks % RECONCILE_EVERY_N_OVER_CAP_PASSES == 0
    }

    /// The pids rotated to start after the poll cursor, for fair
    /// round-robin polling queueing. `pids` must be sorted ascending.
    pub(crate) fn poll_order(&self, pids: &[u32]) -> Vec<u32> {
        Self::rotated_after(pids, self.poll_cursor)
    }

    /// Parks the poll cursor at the last queued pid, so the next round
    /// continues past it. Never called when a round queues nothing, so an
    /// all-ineligible round retries the same window next time.
    pub(crate) fn advance_poll_cursor(&mut self, last_queued: u32) {
        self.poll_cursor = Some(last_queued);
    }

    /// Installs the current tick's deep-scan deadline from the caller's
    /// clock poll plus the tick quantum. A failed clock installs an
    /// already-expired deadline: with no clock there is no bounded phase,
    /// so new scan work defers rather than running blind.
    pub(crate) fn begin_deep_scan_tick(&mut self, now_ns: Option<u64>) {
        self.tick_deadline_ns =
            Some(now_ns.map_or(0, |now| now.saturating_add(self.tick_quantum_ns)));
    }

    /// Whether the tick's deep-scan phase must stop before another scan. A
    /// failed clock poll also stops the phase, for the same reason as above.
    pub(crate) fn tick_expired(&self, now_ns: Option<u64>) -> bool {
        match (self.tick_deadline_ns, now_ns) {
            (Some(deadline), Some(now)) => now >= deadline,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    /// The finite exploration bound: over-cap frames needed for rotation to
    /// admit `unscanned` pids at `slots_per_sweep` admissions per reconcile
    /// sweep. Pure arithmetic for the stated envelope — measurement tests
    /// supply observed slot counts and the report states the slice-coverage
    /// assumption alongside. Zero slots means no rotation capacity: the
    /// bound is infinite (`u64::MAX`), never a silent zero. Test-only: the
    /// product publishes the underlying counts, not the derived bound.
    #[cfg(test)]
    pub(crate) fn exploration_bound_frames(unscanned: usize, slots_per_sweep: usize) -> u64 {
        if unscanned == 0 {
            return 0;
        }
        if slots_per_sweep == 0 {
            return u64::MAX;
        }
        let sweeps = unscanned.div_ceil(slots_per_sweep) as u64;
        sweeps.saturating_mul(RECONCILE_EVERY_N_OVER_CAP_PASSES)
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

    #[cfg(test)]
    pub(crate) fn set_max_evictions_for_test(&mut self, max_evictions: usize) {
        self.max_evictions = max_evictions;
    }

    #[cfg(test)]
    pub(crate) fn set_cooldown_sweeps_for_test(&mut self, cooldown_sweeps: u64) {
        self.cooldown_sweeps = cooldown_sweeps;
    }

    #[cfg(test)]
    pub(crate) fn set_max_new_views_for_test(&mut self, max_new_views: usize) {
        self.max_new_views = max_new_views;
    }

    #[cfg(test)]
    pub(crate) fn set_tick_quantum_ns_for_test(&mut self, tick_quantum_ns: u64) {
        self.tick_quantum_ns = tick_quantum_ns;
    }

    #[cfg(test)]
    pub(crate) fn reconcile_sweeps_for_test(&self) -> u64 {
        self.reconcile_sweeps
    }

    #[cfg(test)]
    pub(crate) fn cooling_for_test(&self) -> Vec<u32> {
        let sweeps = self.reconcile_sweeps;
        let cooldown = self.cooldown_sweeps;
        self.cooling
            .iter()
            .filter(|(_, evicted_at)| sweeps.saturating_sub(**evicted_at) < cooldown)
            .map(|(pid, _)| *pid)
            .collect()
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

    /// Evicted pids cool down for exactly the configured sweeps: recorded
    /// at the current sweep, ineligible until the sequence advances past
    /// the cooldown, then eligible again — but still fairness-stale until
    /// re-admission, so they sort behind never-evicted pids instead of
    /// churning back ahead of them. Ordinary passes never advance the
    /// sweep count, so only reconcile passes age the cooldown.
    #[test]
    fn eviction_cooldown_expires_after_configured_sweeps() {
        let mut scheduler = DiscoveryScheduler::new();
        scheduler.set_cooldown_sweeps_for_test(2);
        for _ in 0..4 {
            scheduler.begin_over_cap_pass();
        }
        assert_eq!(scheduler.reconcile_sweeps_for_test(), 1);
        scheduler.note_evicted(7);
        assert!(scheduler.cooling_down(7));
        assert!(scheduler.is_stale(7));
        assert_eq!(scheduler.cooling_for_test(), vec![7]);
        assert_eq!(scheduler.cooling_len(), 1);
        for _ in 0..3 {
            scheduler.begin_over_cap_pass();
        }
        assert!(scheduler.cooling_down(7), "ordinary passes age nothing");
        for _ in 0..4 {
            scheduler.begin_over_cap_pass();
        }
        assert_eq!(scheduler.reconcile_sweeps_for_test(), 2);
        assert!(
            scheduler.cooling_down(7),
            "one elapsed sweep is still cooling"
        );
        for _ in 0..4 {
            scheduler.begin_over_cap_pass();
        }
        assert_eq!(scheduler.reconcile_sweeps_for_test(), 3);
        assert!(
            !scheduler.cooling_down(7),
            "two elapsed sweeps rejoin selection"
        );
        assert!(
            scheduler.is_stale(7),
            "rejoining selection does not clear fairness staleness"
        );
        assert!(scheduler.cooling_for_test().is_empty());
        scheduler.note_admitted(7);
        assert!(!scheduler.is_stale(7), "re-admission clears staleness");
    }

    /// The staleness map stays bounded by the live enumerated set: entries
    /// for departed pids prune on every tick, so a long churning capture
    /// cannot grow it past the live scope — while live evictees stay
    /// sticky-stale no matter how many sweeps elapse.
    #[test]
    fn stale_entries_prune_to_the_live_enumerated_set() {
        let mut scheduler = DiscoveryScheduler::new();
        scheduler.set_cooldown_sweeps_for_test(1);
        for _ in 0..4 {
            scheduler.begin_over_cap_pass();
        }
        for pid in 100..140 {
            scheduler.note_evicted(pid);
        }
        assert_eq!(scheduler.cooling_len(), 40);
        for _ in 0..4 {
            scheduler.begin_over_cap_pass();
        }
        assert!(scheduler.cooling_for_test().is_empty());
        assert_eq!(scheduler.cooling_len(), 0);
        assert!(
            scheduler.is_stale(100),
            "sweeps age the window, never the staleness"
        );
        assert_eq!(scheduler.stale_pids().len(), 40);
        let enumerated: BTreeSet<u32> = [100, 101].into_iter().collect();
        scheduler.prune_stale_to_enumerated(&enumerated);
        assert_eq!(scheduler.stale_pids(), vec![100, 101]);
        assert!(!scheduler.is_stale(102), "departed pids prune away");
    }

    /// Outside a tick there is no deep-scan deadline; inside one the phase
    /// stops exactly at the quantum. A failed clock at either end stops
    /// the phase rather than running it unbounded.
    #[test]
    fn tick_deadline_bounds_only_the_installed_phase() {
        let mut scheduler = DiscoveryScheduler::new();
        assert!(!scheduler.tick_expired(Some(1_000)));
        scheduler.set_tick_quantum_ns_for_test(100);
        scheduler.begin_deep_scan_tick(Some(1_000));
        assert!(!scheduler.tick_expired(Some(1_000)));
        assert!(!scheduler.tick_expired(Some(1_099)));
        assert!(scheduler.tick_expired(Some(1_100)));
        assert!(scheduler.tick_expired(None), "no clock, no unbounded phase");
        scheduler.begin_deep_scan_tick(None);
        assert!(
            scheduler.tick_expired(Some(u64::MAX)),
            "a clock failure at install defers the whole phase"
        );
    }

    /// Under-cap ticks poll every fourth, mirroring the reconcile cadence,
    /// and the poll cursor round-robins queueing past the last queued pid.
    #[test]
    fn under_cap_ticks_poll_every_fourth_in_poll_cursor_order() {
        let mut scheduler = DiscoveryScheduler::new();
        assert!(!scheduler.begin_under_cap_tick());
        assert!(!scheduler.begin_under_cap_tick());
        assert!(!scheduler.begin_under_cap_tick());
        assert!(scheduler.begin_under_cap_tick());
        assert!(!scheduler.begin_under_cap_tick());
        assert_eq!(scheduler.poll_order(&[10, 20, 30]), vec![10, 20, 30]);
        scheduler.advance_poll_cursor(20);
        assert_eq!(scheduler.poll_order(&[10, 20, 30]), vec![30, 10, 20]);
    }

    /// The exploration bound is exact small arithmetic: nothing unscanned
    /// needs no frames, no rotation capacity is infinite rather than zero,
    /// and anything else rounds up to whole sweeps times the cadence.
    #[test]
    fn exploration_bound_frames_round_up_whole_sweeps() {
        assert_eq!(DiscoveryScheduler::exploration_bound_frames(0, 8), 0);
        assert_eq!(DiscoveryScheduler::exploration_bound_frames(5, 0), u64::MAX);
        assert_eq!(DiscoveryScheduler::exploration_bound_frames(1, 8), 4);
        assert_eq!(DiscoveryScheduler::exploration_bound_frames(8, 8), 4);
        assert_eq!(DiscoveryScheduler::exploration_bound_frames(9, 8), 8);
        assert_eq!(
            DiscoveryScheduler::exploration_bound_frames(44, 8),
            24,
            "six sweeps at the four-frame cadence"
        );
    }
}
