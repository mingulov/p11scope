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
/// without reading maps. Ratified at 2 by the unparked-head settle
/// measurement (round 2): at 4, sweeps average ~4 of the eviction
/// budget and 256 owned cannot settle within the guard; the slice,
/// eviction budget and cooldown are unchanged, only sweeps run twice as
/// often. The 256 view cap and the 120 s guard stay as they are.
pub(crate) const RECONCILE_EVERY_N_OVER_CAP_PASSES: u64 = 2;

/// Under-cap polling cadence: every Nth under-cap inventory tick runs a
/// polling round. Kept at the old value 4, decoupled from the over-cap
/// reconcile cadence: under-cap captures have no eviction pressure, so
/// they keep their historical I/O rate (round 3, I1).
pub(crate) const UNDER_CAP_POLL_EVERY_N_TICKS: u64 = 4;

/// Reconcile slice size: at most this many maps snapshots per sweep.
/// Provisional — ratify by measurement.
pub(crate) const RECONCILE_SLICE_PIDS: usize = 64;

/// Wall-time quantum for one reconcile slice, in nanoseconds. The slice
/// stops before a read that would exceed it; the remainder defers to the
/// next sweep with explicit evidence. Provisional — ratify by measurement.
pub(crate) const RECONCILE_QUANTUM_NS: u64 = 50_000_000;

/// Exploratory rotation: at most this many provider-free views are evicted
/// per reconcile pass to make room for rarity-selected newcomers. Ordinary
/// passes never evict, so steady-state ticks displace nothing. Raised to 32
/// by the unparked-head settle measurement (round 2): at 16, the fattest
/// admission gates pin at the cap (12 of 68 busy gates admit exactly 16)
/// while sweeps average ~4, so the cap binds burst throughput without
/// binding steady state; 32 still displaces at most an eighth of a full
/// capture per pass. The 256 view cap, the 120 s guard, the slice, the
/// per-tick admission bound and the cooldown stay as they are.
pub(crate) const MAX_EXPLORATORY_EVICTIONS_PER_PASS: usize = 32;

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

/// Bounded newcomer share of one admission tick's window: newcomers take
/// up to this many of the tick's admitted batch — on free ticks the
/// candidates absent from the previous tick's enumeration (see
/// `note_enumeration`), on scarce ticks the pending pids whose refresh
/// request is newer than the previous tick (see
/// `scarce_window_pending_newcomers_first`) — and the rest of the batch
/// serves backlog in rotation order. Either class fills batch slots the
/// other cannot use, so a steady newcomer stream delays the backlog but
/// never starves it: the admitted window interleaves both classes
/// (leading with backlog when the previous tick owed it one), so the
/// tick quantum defers both proportionally instead of striking the
/// backlog tail first. Half the tick batch, so a non-empty backlog keeps
/// at least half of each tick's attempts (rounded down), and at least one
/// attempt in every two attempting ticks.
/// Provisional — ratify by measurement.
pub(crate) const MAX_NEWCOMER_ADMISSIONS_PER_TICK: usize = MAX_NEW_VIEWS_PER_TICK / 2;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InventoryScanClass {
    Retained,
    Newcomer,
}

/// The H1 fairness-accounting cursors a pressure service pass must leave
/// untouched: pass counts, rotation cursors (including the backlog-only
/// cursor and the backlog-owed flag with its per-tick attempt ledger and
/// newcomer-attempt sets), the previous-tick enumeration and tick-start
/// pair for newcomer classification, the scan-class alternation and the
/// tick deadline. Restored verbatim after each selected transaction, so
/// pressure service never consumes an ordinary tick's polling round,
/// reconcile turn, alternation share or newcomer/backlog standing.
/// Cooling entries are real admission facts, not accounting, and are
/// never restored.
#[derive(Debug, Clone)]
pub(crate) struct FairnessCheckpoint {
    over_cap_passes: u64,
    cursor: Option<u32>,
    reconcile_sweeps: u64,
    new_view_cursor: Option<u32>,
    retained_view_cursor: Option<u32>,
    first_scan_class: InventoryScanClass,
    tick_scan_started: bool,
    tick_deadline_ns: Option<u64>,
    under_cap_ticks: u64,
    poll_cursor: Option<u32>,
    backlog_cursor: Option<u32>,
    backlog_owed: bool,
    tick_backlog_waited: bool,
    tick_attempted_any: bool,
    tick_attempted_backlog: bool,
    prev_enumerated: BTreeSet<u32>,
    tick_newcomer_attempts: BTreeSet<u32>,
    last_newcomer_attempts: BTreeSet<u32>,
    prev_tick_start_ns: Option<u64>,
    last_tick_start_ns: Option<u64>,
}

/// The per-capture discovery schedule. Reconciliation, polling and new-view
/// admission have independent cursors so failed candidates cannot monopolize
/// a bounded tick, including when the whole scope fits under the view cap.
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
    new_view_cursor: Option<u32>,
    retained_view_cursor: Option<u32>,
    first_scan_class: InventoryScanClass,
    tick_scan_started: bool,
    tick_quantum_ns: u64,
    under_cap_ticks: u64,
    poll_cursor: Option<u32>,
    /// Wall-time deadline for the current tick's deep-scan phase, installed
    /// by `begin_deep_scan_tick`. `None` outside a tick means unbounded —
    /// direct scan calls (and unit tests driving them) are not ticks.
    tick_deadline_ns: Option<u64>,
    /// Backlog-only rotation cursor: advanced solely by free-slots
    /// backlog attempts, so a newcomer flood cannot drag backlog rotation
    /// toward recent deferrals. Scarce ticks rotate pending backlog (and
    /// rotation, separately) after the newcomer cursor instead and leave
    /// this untouched.
    backlog_cursor: Option<u32>,
    /// Whether the next admission window leads with backlog: set when a
    /// tick attempted work but no backlog while backlog waited, cleared
    /// when a backlog attempt runs or no backlog waits. Covers one
    /// attempt per tick, where interleaving alone cannot alternate the
    /// lead.
    backlog_owed: bool,
    /// Per-tick attempt ledger behind `backlog_owed`: whether this tick's
    /// window saw backlog, attempted anything, and attempted backlog.
    /// Every window — free or scarce — settles the previous tick's debt
    /// and opens a fresh ledger first.
    tick_backlog_waited: bool,
    tick_attempted_any: bool,
    tick_attempted_backlog: bool,
    /// The previous tick's live enumeration for newcomer classification: a
    /// candidate absent here was first observed this tick. Replaced every
    /// tick, so it holds at most the live enumerated pids (the same bound
    /// argument as `cooling`). Timing arrival marks stay timing-only.
    prev_enumerated: BTreeSet<u32>,
    /// Pids attempted as newcomers on the current tick: rotated into
    /// `last_newcomer_attempts` at the next window, so a failed newcomer
    /// — backlog next tick, never seen by the backlog cursor — retries
    /// behind untried backlog instead of ahead of it. At most the tick's
    /// admitted batch (production 64); excess records drop past the cap.
    tick_newcomer_attempts: BTreeSet<u32>,
    /// The previous tick's newcomer attempts, sunk to the end of the
    /// backlog rotation by `backlog_order`. Same bound.
    last_newcomer_attempts: BTreeSet<u32>,
    /// The previous tick's deep-scan-phase start: scarce newcomer
    /// classification reads refresh-request recency against it (a pending
    /// pid requested strictly after it is a newcomer). Shifted by every
    /// `begin_deep_scan_tick` out of `last_tick_start_ns`; a failed clock
    /// installs `None` there, so the next tick classifies everything as
    /// backlog — no reordering without clock evidence.
    prev_tick_start_ns: Option<u64>,
    /// The current tick's deep-scan-phase start: the next tick's
    /// previous start. Shifted by every `begin_deep_scan_tick`.
    last_tick_start_ns: Option<u64>,
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
            new_view_cursor: None,
            retained_view_cursor: None,
            first_scan_class: InventoryScanClass::Retained,
            tick_scan_started: false,
            tick_quantum_ns: TICK_DEEP_SCAN_QUANTUM_NS,
            tick_deadline_ns: None,
            under_cap_ticks: 0,
            poll_cursor: None,
            backlog_cursor: None,
            backlog_owed: false,
            tick_backlog_waited: false,
            tick_attempted_any: false,
            tick_attempted_backlog: false,
            prev_enumerated: BTreeSet::new(),
            tick_newcomer_attempts: BTreeSet::new(),
            last_newcomer_attempts: BTreeSet::new(),
            prev_tick_start_ns: None,
            last_tick_start_ns: None,
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
        if self
            .over_cap_passes
            .is_multiple_of(RECONCILE_EVERY_N_OVER_CAP_PASSES)
        {
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
    /// covers every pid instead of churning the lowest ones. Test-only: the
    /// product reads the whole set via `stale_pids`.
    #[cfg(test)]
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

    /// Rotate sorted newcomers past the last attempted process, even if that
    /// attempt could not retain or scan it. Successful admission alone cannot
    /// advance fairness when lower PIDs remain unreadable on every tick.
    /// Both admission windows rotate their fresh class through this; scarce
    /// windows rotate pending backlog and rotation candidates through it
    /// too, as separate orders (see
    /// `scarce_window_pending_newcomers_first`).
    pub(crate) fn new_view_order(&self, pids: &[u32]) -> Vec<u32> {
        Self::rotated_after(pids, self.new_view_cursor)
    }

    /// Newcomer order with event-driven priority (Lane-A P2a): pids holding
    /// queued refresh requests first, then rotation candidates, each class
    /// rotated after the cursor. Test-only: scarce windows order pending
    /// backlog and rotation as separate classes; this helper pins the
    /// pending-first order. Ordinary ticks serve event-driven work
    /// before exploratory rotation by design; without the priority, freed
    /// view slots refill with ascending ambient candidates while pending
    /// newcomers starve. The pending class drains, so rotation is delayed,
    /// never starved. `pids` must be sorted ascending.
    #[cfg(test)]
    pub(crate) fn new_view_order_pending_first(
        &self,
        pids: &[u32],
        pending: &BTreeSet<u32>,
    ) -> Vec<u32> {
        let (queued, exploratory): (Vec<u32>, Vec<u32>) =
            pids.iter().copied().partition(|pid| pending.contains(pid));
        let mut ordered = Self::rotated_after(&queued, self.new_view_cursor);
        ordered.extend(Self::rotated_after(&exploratory, self.new_view_cursor));
        ordered
    }

    /// Backlog order under its own cursor: the same rotation as
    /// `new_view_order`, but parked by backlog attempts only, so newcomer
    /// attempts never drag it toward recent deferrals — with one repair:
    /// a failed newcomer is backlog next tick without ever parking this
    /// cursor, so the previous tick's newcomer attempts sink to the end,
    /// stable inside each part, instead of retrying ahead of untried
    /// backlog. Free-slots windows use this for the backlog class; scarce
    /// windows rotate the backlog class after the newcomer cursor instead
    /// (see `scarce_window_pending_newcomers_first`). `pids` must be sorted
    /// ascending.
    pub(crate) fn backlog_order(&self, pids: &[u32]) -> Vec<u32> {
        let order = Self::rotated_after(pids, self.backlog_cursor);
        let (mut head, tail): (Vec<u32>, Vec<u32>) = order
            .into_iter()
            .partition(|pid| !self.last_newcomer_attempts.contains(pid));
        head.extend(tail);
        head
    }

    /// Opens one admission window: settles the previous tick's backlog
    /// debt, resets this tick's attempt ledger, and rotates the
    /// newcomer-attempt sets so the backlog rotation sinks exactly the
    /// previous tick's newcomer attempts — unless that tick attempted
    /// nothing, in which case the sets are kept for the retry. Every
    /// admission window calls this first. A backlog attempt paid the debt;
    /// a round that attempted work but no backlog while backlog waited
    /// owes the next lead to backlog; no backlog waiting clears it; a
    /// round that attempted nothing (an expired quantum before the first
    /// scan) leaves it for the retry.
    fn open_attempt_window(&mut self) {
        if self.tick_attempted_backlog {
            self.backlog_owed = false;
        } else if self.tick_backlog_waited && self.tick_attempted_any {
            self.backlog_owed = true;
        } else if !self.tick_backlog_waited {
            self.backlog_owed = false;
        }
        let attempted_any = self.tick_attempted_any;
        self.tick_attempted_any = false;
        self.tick_attempted_backlog = false;
        if attempted_any {
            self.last_newcomer_attempts = std::mem::take(&mut self.tick_newcomer_attempts);
        } else {
            self.tick_newcomer_attempts.clear();
        }
    }

    /// One admission tick's window with newcomers first (free view slots
    /// only; scarce ticks use `scarce_window_pending_newcomers_first`):
    /// `newcomers` (the subset of `pids` absent from the previous
    /// enumeration) take up to `newcomer_share` of the `max_new_views`
    /// batch, and the rest of the batch serves backlog in
    /// backlog-cursor order. Either class fills batch slots the other
    /// cannot use, so the window stays full and a missing class leaves
    /// today's single-class rotation order untouched. The admitted window
    /// interleaves both classes — leading with backlog when the previous
    /// tick owed it one — so the tick quantum defers both proportionally
    /// and the backlog keeps progressing under a steady flood. Settles the
    /// previous tick's backlog debt first (a backlog attempt clears it; an
    /// attempt round with backlog waiting but none attempted raises it;
    /// a tick that attempted nothing leaves it), then opens this tick's
    /// attempt ledger. Returns `(admitted, deferred)` in admission order.
    /// Every input list must be sorted ascending; `newcomers` must be a
    /// subset of `pids`.
    pub(crate) fn new_view_window_newcomers_first(
        &mut self,
        pids: &[u32],
        newcomers: &BTreeSet<u32>,
        max_new_views: usize,
        newcomer_share: usize,
    ) -> (Vec<u32>, Vec<u32>) {
        self.open_attempt_window();
        let (fresh, backlog): (Vec<u32>, Vec<u32>) = pids
            .iter()
            .copied()
            .partition(|pid| newcomers.contains(pid));
        let fresh_order = self.new_view_order(&fresh);
        let backlog_order = self.backlog_order(&backlog);
        self.tick_backlog_waited = !backlog_order.is_empty();
        Self::admit_window_orders(
            &fresh_order,
            &backlog_order,
            max_new_views,
            newcomer_share,
            self.backlog_owed,
        )
    }

    /// One admission tick's scarce window: pending newcomers and pending
    /// backlog first (up to the newcomer share), then rotation candidates.
    /// `fresh` holds the pending pids the caller classified as newcomers
    /// (the engine: refresh requests newer than the previous tick);
    /// pending backlog and rotation rotate separately after the newcomer
    /// cursor, so with no fresh pending the window is pending backlog
    /// then rotation, exactly today's scarce order. The admitted window
    /// interleaves fresh with pending backlog (leading backlog when the
    /// previous tick owed it one) under the same share and owed bound as
    /// the free window, then appends rotation into the remaining slots;
    /// deferred rotation waits behind both pending tails. Only pending
    /// backlog counts for the owed ledger — rotation alone never waits
    /// nor owes — so a quantum-truncated round defers pending
    /// proportionally and eviction-freed slots still reach pending
    /// waiters first. Settles the previous tick's debt and opens this
    /// tick's ledger like the free window. Returns `(admitted, deferred)`
    /// in admission order. Every input list must be sorted ascending.
    pub(crate) fn scarce_window_pending_newcomers_first(
        &mut self,
        fresh: &[u32],
        backlog: &[u32],
        rotation: &[u32],
        max_new_views: usize,
        newcomer_share: usize,
    ) -> (Vec<u32>, Vec<u32>) {
        self.open_attempt_window();
        let fresh_order = self.new_view_order(fresh);
        let pending_backlog_order = self.new_view_order(backlog);
        let rotation_order = self.new_view_order(rotation);
        self.tick_backlog_waited = !pending_backlog_order.is_empty();
        let (mut admitted, mut deferred) = Self::admit_window_orders(
            &fresh_order,
            &pending_backlog_order,
            max_new_views,
            newcomer_share,
            self.backlog_owed,
        );
        let room = max_new_views.saturating_sub(admitted.len());
        admitted.extend(rotation_order.iter().copied().take(room));
        deferred.extend(rotation_order.iter().copied().skip(room));
        (admitted, deferred)
    }

    /// Selects and orders one admission window from two ordered classes:
    /// fresh takes up to its share, the backlog class fills the rest, and
    /// the admitted window interleaves both — leading backlog when owed —
    /// so a truncated attempt round defers both proportionally. Either
    /// class fills batch slots the other cannot use, so the window stays
    /// full and a missing class leaves today's single-class rotation
    /// order untouched. Returns `(admitted, deferred)` in admission order.
    fn admit_window_orders(
        fresh_order: &[u32],
        backlog_order: &[u32],
        max_new_views: usize,
        newcomer_share: usize,
        backlog_owed: bool,
    ) -> (Vec<u32>, Vec<u32>) {
        // Newcomers take up to their share, plus any batch slots the
        // backlog cannot fill; the backlog fills the rest. While backlog
        // waits the share leaves at least one batch slot for it: at a
        // batch at or below the share a flood would otherwise take the
        // whole window and the owed lead would have no backlog slot to
        // lead with.
        let newcomer_share = if backlog_order.is_empty() {
            newcomer_share.min(max_new_views)
        } else {
            newcomer_share.min(max_new_views.saturating_sub(1))
        };
        // One slot with both classes waiting: the owed flag chooses the
        // class, so newcomer and backlog ticks alternate instead of the
        // flood taking every tick.
        let (fresh_take, backlog_take) =
            if max_new_views == 1 && !fresh_order.is_empty() && !backlog_order.is_empty() {
                if backlog_owed {
                    (&fresh_order[..0], &backlog_order[..1])
                } else {
                    (&fresh_order[..1], &backlog_order[..0])
                }
            } else {
                let fresh_take = fresh_order
                    .len()
                    .min(newcomer_share.max(max_new_views.saturating_sub(backlog_order.len())));
                let backlog_take = backlog_order
                    .len()
                    .min(max_new_views.saturating_sub(fresh_take));
                (&fresh_order[..fresh_take], &backlog_order[..backlog_take])
            };
        let mut admitted = Vec::with_capacity(fresh_take.len() + backlog_take.len());
        if fresh_take.is_empty() || backlog_take.is_empty() {
            // A missing class keeps today's single-class rotation order verbatim.
            admitted.extend_from_slice(fresh_take);
            admitted.extend_from_slice(backlog_take);
        } else if backlog_owed {
            // Alternate backlog-first: the owed tick repays the debt even
            // at one attempt per tick.
            let mut fresh = fresh_take.iter().copied();
            let mut backlog = backlog_take.iter().copied();
            loop {
                match (backlog.next(), fresh.next()) {
                    (Some(pid), Some(next)) => {
                        admitted.push(pid);
                        admitted.push(next);
                    }
                    (Some(pid), None) => {
                        admitted.push(pid);
                        admitted.extend(backlog);
                        break;
                    }
                    (None, Some(next)) => {
                        admitted.push(next);
                        admitted.extend(fresh);
                        break;
                    }
                    (None, None) => break,
                }
            }
        } else {
            // Alternate newcomer-first: a lone newcomer still jumps the
            // queue, while the backlog shares every truncated attempt round.
            let mut fresh = fresh_take.iter().copied();
            let mut backlog = backlog_take.iter().copied();
            loop {
                match (fresh.next(), backlog.next()) {
                    (Some(pid), Some(next)) => {
                        admitted.push(pid);
                        admitted.push(next);
                    }
                    (Some(pid), None) => {
                        admitted.push(pid);
                        admitted.extend(fresh);
                        break;
                    }
                    (None, Some(next)) => {
                        admitted.push(next);
                        admitted.extend(backlog);
                        break;
                    }
                    (None, None) => break,
                }
            }
        }
        let mut deferred =
            Vec::with_capacity(fresh_order.len() + backlog_order.len() - admitted.len());
        deferred.extend_from_slice(&fresh_order[fresh_take.len()..]);
        deferred.extend_from_slice(&backlog_order[backlog_take.len()..]);
        (admitted, deferred)
    }

    /// Records the current tick's live enumeration for next tick's newcomer
    /// classification. Replaces (never grows): the next tick's newcomers are
    /// its candidates absent here. The engine calls this every tick, even
    /// empty ones; pressure service passes restore it via the checkpoint.
    pub(crate) fn note_enumeration(&mut self, enumerated: &BTreeSet<u32>) {
        self.prev_enumerated.clone_from(enumerated);
    }

    /// The subset of `new_pids` absent from the previous tick's enumeration:
    /// the truly first-observed candidates. Long runners deferred by an
    /// over-cap pass were enumerated before, so they read as backlog even
    /// though no arrival mark was ever set for them.
    pub(crate) fn newcomers_in(&self, new_pids: &[u32]) -> BTreeSet<u32> {
        new_pids
            .iter()
            .copied()
            .filter(|pid| !self.prev_enumerated.contains(pid))
            .collect()
    }

    /// Called only after the tick's time and capacity checks permit an attempt.
    /// Work deferred before an attempt keeps its place for the next tick.
    /// This bare form parks the newcomer cursor without touching the owed
    /// ledger; classified window attempts record through the recorders
    /// below so the ledger can tell the classes apart. All of them advance
    /// the scan-class alternation alike.
    pub(crate) fn note_new_view_attempt(&mut self, pid: u32) {
        self.new_view_cursor = Some(pid);
        self.note_scan_attempt(InventoryScanClass::Newcomer);
    }

    /// A fresh-class attempt on either window (free newcomers, scarce
    /// pending newcomers): parks the newcomer cursor, records the pid in
    /// this tick's newcomer-attempt set (so the next window sinks it if
    /// it is backlog then), and records the attempt in the owed ledger.
    /// Free backlog attempts use `note_backlog_attempt`, which parks the
    /// backlog cursor instead; scarce backlog-class attempts use
    /// `note_scarce_backlog_attempt`, which parks this same cursor.
    pub(crate) fn note_newcomer_attempt(&mut self, pid: u32) {
        self.new_view_cursor = Some(pid);
        if self.tick_newcomer_attempts.len() < self.max_new_views {
            self.tick_newcomer_attempts.insert(pid);
        }
        self.tick_attempted_any = true;
        self.note_scan_attempt(InventoryScanClass::Newcomer);
    }

    /// A free-slots backlog attempt: parks the backlog cursor (the newcomer
    /// cursor stays, so the two rotations never drag each other) and records
    /// the attempt in the owed ledger, repaying any debt.
    pub(crate) fn note_backlog_attempt(&mut self, pid: u32) {
        self.backlog_cursor = Some(pid);
        self.tick_attempted_any = true;
        self.tick_attempted_backlog = true;
        self.note_scan_attempt(InventoryScanClass::Newcomer);
    }

    /// A scarce pending-backlog attempt: parks the newcomer cursor —
    /// scarce rotation stays single-cursor, so the backlog cursor remains
    /// a free-slots-only anchor — while repaying the shared owed ledger
    /// like any backlog attempt. Scarce rotation attempts park the same
    /// cursor bare via `note_new_view_attempt`, without touching the
    /// ledger.
    pub(crate) fn note_scarce_backlog_attempt(&mut self, pid: u32) {
        self.note_new_view_attempt(pid);
        self.tick_attempted_any = true;
        self.tick_attempted_backlog = true;
    }

    /// Rotate retained views by their capture-local IDs. Failures advance
    /// the cursor; views deferred before an actual scan keep their turn.
    pub(crate) fn retained_view_order(&self, ids: &[u32]) -> Vec<u32> {
        Self::rotated_after(ids, self.retained_view_cursor)
    }

    pub(crate) fn note_retained_view_attempt(&mut self, id: u32) {
        self.retained_view_cursor = Some(id);
        self.note_scan_attempt(InventoryScanClass::Retained);
    }

    /// When both classes are ready, give the other class the first chance
    /// after the class that actually started the preceding service pass.
    /// An expired tick or an absent candidate does not consume a turn.
    pub(crate) fn newcomers_first(&self, retained_ready: bool, newcomer_ready: bool) -> bool {
        newcomer_ready && (!retained_ready || self.first_scan_class == InventoryScanClass::Newcomer)
    }

    fn note_scan_attempt(&mut self, class: InventoryScanClass) {
        if !self.tick_scan_started {
            self.tick_scan_started = true;
            self.first_scan_class = match class {
                InventoryScanClass::Retained => InventoryScanClass::Newcomer,
                InventoryScanClass::Newcomer => InventoryScanClass::Retained,
            };
        }
    }

    /// Counts one under-cap inventory tick and reports whether it runs a
    /// polling round: every fourth, on its own cadence, so quiet
    /// under-cap ticks keep their no-op behavior between rounds.
    pub(crate) fn begin_under_cap_tick(&mut self) -> bool {
        self.under_cap_ticks = self.under_cap_ticks.saturating_add(1);
        self.under_cap_ticks
            .is_multiple_of(UNDER_CAP_POLL_EVERY_N_TICKS)
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
    /// clock poll plus the tick quantum, and shifts the tick-start pair
    /// for scarce newcomer classification. Scarce ticks cannot classify
    /// fresh until a second working tick — `prev_tick_start_ns` stays
    /// `None` until then, so the first tick reads everything as backlog;
    /// tests stage an earlier tick to exercise fresh. A failed clock
    /// installs an already-expired deadline: with no clock there is no
    /// bounded phase, so new scan work defers rather than running blind.
    pub(crate) fn begin_deep_scan_tick(&mut self, now_ns: Option<u64>) {
        self.tick_scan_started = false;
        self.prev_tick_start_ns = self.last_tick_start_ns;
        self.last_tick_start_ns = now_ns;
        self.tick_deadline_ns =
            Some(now_ns.map_or(0, |now| now.saturating_add(self.tick_quantum_ns)));
    }

    /// The previous tick's deep-scan-phase start (`None` before the second
    /// tick, or after a failed clock): a pending pid requested strictly
    /// after it is a newcomer on a scarce tick. See
    /// `scarce_window_pending_newcomers_first`.
    pub(crate) fn prev_tick_start_ns(&self) -> Option<u64> {
        self.prev_tick_start_ns
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

    /// Snapshots the H1 fairness-accounting cursors before a pressure
    /// service pass. The pass runs its selected transaction, then
    /// `restore_fairness` puts every cursor back: the selected attempt is
    /// recorded in the pressure episode's own counters, never in H1 shares.
    pub(crate) fn fairness_checkpoint(&self) -> FairnessCheckpoint {
        FairnessCheckpoint {
            over_cap_passes: self.over_cap_passes,
            cursor: self.cursor,
            reconcile_sweeps: self.reconcile_sweeps,
            new_view_cursor: self.new_view_cursor,
            retained_view_cursor: self.retained_view_cursor,
            first_scan_class: self.first_scan_class,
            tick_scan_started: self.tick_scan_started,
            tick_deadline_ns: self.tick_deadline_ns,
            under_cap_ticks: self.under_cap_ticks,
            poll_cursor: self.poll_cursor,
            backlog_cursor: self.backlog_cursor,
            backlog_owed: self.backlog_owed,
            tick_backlog_waited: self.tick_backlog_waited,
            tick_attempted_any: self.tick_attempted_any,
            tick_attempted_backlog: self.tick_attempted_backlog,
            prev_enumerated: self.prev_enumerated.clone(),
            tick_newcomer_attempts: self.tick_newcomer_attempts.clone(),
            last_newcomer_attempts: self.last_newcomer_attempts.clone(),
            prev_tick_start_ns: self.prev_tick_start_ns,
            last_tick_start_ns: self.last_tick_start_ns,
        }
    }

    /// Restores H1 fairness accounting after a pressure service pass. Cooling
    /// entries stay as the transaction left them: an admission or departure
    /// it observed is a real fact, not a consumed share.
    pub(crate) fn restore_fairness(&mut self, checkpoint: FairnessCheckpoint) {
        self.over_cap_passes = checkpoint.over_cap_passes;
        self.cursor = checkpoint.cursor;
        self.reconcile_sweeps = checkpoint.reconcile_sweeps;
        self.new_view_cursor = checkpoint.new_view_cursor;
        self.retained_view_cursor = checkpoint.retained_view_cursor;
        self.first_scan_class = checkpoint.first_scan_class;
        self.tick_scan_started = checkpoint.tick_scan_started;
        self.tick_deadline_ns = checkpoint.tick_deadline_ns;
        self.under_cap_ticks = checkpoint.under_cap_ticks;
        self.poll_cursor = checkpoint.poll_cursor;
        self.backlog_cursor = checkpoint.backlog_cursor;
        self.backlog_owed = checkpoint.backlog_owed;
        self.tick_backlog_waited = checkpoint.tick_backlog_waited;
        self.tick_attempted_any = checkpoint.tick_attempted_any;
        self.tick_attempted_backlog = checkpoint.tick_attempted_backlog;
        self.prev_enumerated = checkpoint.prev_enumerated;
        self.tick_newcomer_attempts = checkpoint.tick_newcomer_attempts;
        self.last_newcomer_attempts = checkpoint.last_newcomer_attempts;
        self.prev_tick_start_ns = checkpoint.prev_tick_start_ns;
        self.last_tick_start_ns = checkpoint.last_tick_start_ns;
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
    pub(crate) fn under_cap_ticks_for_test(&self) -> u64 {
        self.under_cap_ticks
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

    #[cfg(test)]
    pub(crate) fn backlog_owed_for_test(&self) -> bool {
        self.backlog_owed
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
    /// work; every second over-cap pass runs the bounded maps slice instead,
    /// so owned processes waiting on evictions settle within the guard.
    #[test]
    fn cadence_is_ordinary_until_every_second_over_cap_pass() {
        let mut scheduler = DiscoveryScheduler::new();
        let cadences: Vec<InventoryCadence> =
            (0..8).map(|_| scheduler.begin_over_cap_pass()).collect();
        assert_eq!(
            cadences,
            [
                InventoryCadence::Ordinary,
                InventoryCadence::Reconcile,
                InventoryCadence::Ordinary,
                InventoryCadence::Reconcile,
                InventoryCadence::Ordinary,
                InventoryCadence::Reconcile,
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

    /// Lane-A P2a: the admission window serves pending-request newcomers
    /// before rotation candidates, with cursor fairness inside each class.
    #[test]
    fn pending_requests_sort_before_rotation_candidates() {
        let scheduler = DiscoveryScheduler::new();
        let pending: BTreeSet<u32> = [7, 3].into_iter().collect();
        assert_eq!(
            scheduler.new_view_order_pending_first(&[1, 3, 5, 7, 9], &pending),
            vec![3, 7, 1, 5, 9]
        );
        // No pending: identical to the plain rotation order.
        assert_eq!(
            scheduler.new_view_order_pending_first(&[1, 3, 5], &BTreeSet::new()),
            scheduler.new_view_order(&[1, 3, 5])
        );
        // The cursor rotates inside each class independently.
        let mut rotated = DiscoveryScheduler::new();
        rotated.note_new_view_attempt(5);
        assert_eq!(
            rotated.new_view_order_pending_first(&[1, 3, 5, 7, 9], &pending),
            vec![7, 3, 9, 1, 5]
        );
    }

    /// A mapping first seen this pass admits ahead of backlog: with 2,000
    /// backlog processes and one newcomer, one admission tick puts the
    /// newcomer first while the backlog keeps backlog-cursor order behind
    /// it. Scarce ticks classify pending by request recency instead (see
    /// `scarce_window_pending_newcomers_first` and the engine's
    /// waiter-settle test).
    #[test]
    fn newcomer_mapping_admitted_before_backlog() {
        let batch = MAX_NEW_VIEWS_PER_TICK;
        let share = MAX_NEWCOMER_ADMISSIONS_PER_TICK;
        let backlog: Vec<u32> = (1..=2000).collect();
        let newcomer = 1_000_000u32;
        let mut pids = backlog.clone();
        pids.push(newcomer);
        let newcomers: BTreeSet<u32> = BTreeSet::from([newcomer]);

        let mut scheduler = DiscoveryScheduler::new();
        let (admitted, deferred) =
            scheduler.new_view_window_newcomers_first(&pids, &newcomers, batch, share);
        assert_eq!(admitted.len(), batch);
        assert_eq!(
            admitted[0], newcomer,
            "the newcomer joins the first admitted batch"
        );
        let baseline = scheduler.backlog_order(&backlog);
        assert_eq!(
            &admitted[1..],
            &baseline[..batch - 1],
            "backlog order is otherwise unchanged"
        );
        assert_eq!(
            deferred,
            baseline[batch - 1..],
            "deferred backlog keeps rotation order"
        );
    }

    /// With no backlog, a free tick keeps exactly today's rotation order:
    /// the window is the plain newcomer order, admitted plus deferred.
    /// Scarce ticks classify pending by request recency instead.
    #[test]
    fn free_tick_without_backlog_keeps_rotation_order() {
        let batch = MAX_NEW_VIEWS_PER_TICK;
        let share = MAX_NEWCOMER_ADMISSIONS_PER_TICK;
        let pids: Vec<u32> = (1..=100).collect();
        let newcomers: BTreeSet<u32> = pids.iter().copied().collect();
        let mut scheduler = DiscoveryScheduler::new();
        let (admitted, deferred) =
            scheduler.new_view_window_newcomers_first(&pids, &newcomers, batch, share);
        assert_eq!(admitted.len(), batch);
        assert_eq!(admitted[0], 1, "rotation still leads with the lowest pid");
        let window: Vec<u32> = admitted.into_iter().chain(deferred).collect();
        assert_eq!(
            window,
            scheduler.new_view_order(&pids),
            "no backlog means exactly today's order"
        );
    }

    /// Newcomers cannot starve the backlog: 50 ticks each adding one
    /// newcomer still admit every backlog entry within
    /// `ceil(2000 / batch) + 50` ticks. Each tick's newcomer set holds only
    /// that tick's arrival — a deferred newcomer is marked and rejoins as
    /// backlog next tick, exactly as the engine's arrival marks behave.
    /// A coarse guard: one newcomer per tick drains even with the share at
    /// the full batch; the per-tick share bound itself is pinned by
    /// `newcomer_share_bounded_per_tick_under_flood`.
    #[test]
    fn backlog_not_starved_by_newcomers() {
        let batch = MAX_NEW_VIEWS_PER_TICK;
        let share = MAX_NEWCOMER_ADMISSIONS_PER_TICK;
        let mut scheduler = DiscoveryScheduler::new();
        let mut remaining: BTreeSet<u32> = (1..=2000).collect();
        let bound = 2000usize.div_ceil(batch) + 50;
        let mut tick = 0usize;
        loop {
            tick += 1;
            assert!(
                tick <= bound,
                "backlog still unadmitted after {bound} ticks: {} left",
                remaining.len()
            );
            if tick <= 50 {
                remaining.insert(1_000_000 + tick as u32);
            }
            let pids: Vec<u32> = remaining.iter().copied().collect();
            let newcomers: BTreeSet<u32> = if tick <= 50 {
                BTreeSet::from([1_000_000 + tick as u32])
            } else {
                BTreeSet::new()
            };
            let (admitted, _) =
                scheduler.new_view_window_newcomers_first(&pids, &newcomers, batch, share);
            assert!(
                !admitted.is_empty(),
                "tick {tick}: a non-empty queue admits nothing"
            );
            for pid in &admitted {
                if newcomers.contains(pid) {
                    scheduler.note_newcomer_attempt(*pid);
                } else {
                    scheduler.note_backlog_attempt(*pid);
                }
                remaining.remove(pid);
            }
            if remaining.iter().all(|pid| *pid > 1_000_000) {
                break;
            }
        }
        assert!(
            tick <= bound,
            "every backlog entry admits within {bound} ticks, took {tick}"
        );
    }

    /// The newcomer share is bounded per tick under flood: with 100 fresh
    /// newcomers per tick, the first tick splits the batch evenly and the
    /// backlog still drains at the guaranteed half-batch rate.
    #[test]
    fn newcomer_share_bounded_per_tick_under_flood() {
        let batch = MAX_NEW_VIEWS_PER_TICK;
        let share = MAX_NEWCOMER_ADMISSIONS_PER_TICK;
        assert_eq!(share * 2, batch, "the share is half the batch");
        let mut scheduler = DiscoveryScheduler::new();
        let mut remaining: BTreeSet<u32> = (1..=2000).collect();
        for fresh in 0..100 {
            remaining.insert(1_000_000 + fresh);
        }
        let pids: Vec<u32> = remaining.iter().copied().collect();
        let newcomers: BTreeSet<u32> = (1_000_000..1_000_100).collect();
        let (admitted, _) =
            scheduler.new_view_window_newcomers_first(&pids, &newcomers, batch, share);
        let fresh_admitted = admitted
            .iter()
            .filter(|pid| newcomers.contains(pid))
            .count();
        assert_eq!(
            fresh_admitted, share,
            "the first tick splits the batch: {admitted:?}"
        );
        for pid in &admitted {
            if newcomers.contains(pid) {
                scheduler.note_newcomer_attempt(*pid);
            } else {
                scheduler.note_backlog_attempt(*pid);
            }
            remaining.remove(pid);
        }
        // The flood continues; deferred newcomers rejoin as marked backlog.
        let mut tick = 1usize;
        let mut arrival = 1_000_100u32;
        while remaining.iter().any(|pid| *pid <= 2000) {
            tick += 1;
            assert!(
                tick <= 2000,
                "backlog still unadmitted after {tick} ticks under flood"
            );
            let mut fresh_set = BTreeSet::new();
            for _ in 0..100 {
                remaining.insert(arrival);
                fresh_set.insert(arrival);
                arrival += 1;
            }
            let pids: Vec<u32> = remaining.iter().copied().collect();
            let (admitted, _) =
                scheduler.new_view_window_newcomers_first(&pids, &fresh_set, batch, share);
            for pid in &admitted {
                if fresh_set.contains(pid) {
                    scheduler.note_newcomer_attempt(*pid);
                } else {
                    scheduler.note_backlog_attempt(*pid);
                }
                remaining.remove(pid);
            }
        }
        assert!(
            tick <= 2000usize.div_ceil(share),
            "backlog drains at the guaranteed half-batch rate: {tick} ticks"
        );
    }

    /// A fairness checkpoint covers every H1 accounting cursor: after
    /// polling rounds, reconcile passes, scan attempts and a deep-scan
    /// tick, restoring returns each observable cursor and the alternation
    /// to its checkpoint, while a real admission fact (cooling cleared)
    /// survives the restore.
    #[test]
    fn fairness_checkpoint_restores_h1_accounting_but_keeps_admission_facts() {
        let mut scheduler = DiscoveryScheduler::new();
        scheduler.note_new_view_attempt(7);
        scheduler.note_retained_view_attempt(3);
        scheduler.advance_poll_cursor(11);
        scheduler.advance_cursor(13);
        scheduler.note_backlog_attempt(5);
        scheduler.note_enumeration(&BTreeSet::from([2, 4, 6]));
        for _ in 0..3 {
            scheduler.begin_under_cap_tick();
        }
        scheduler.begin_over_cap_pass();
        let checkpoint = scheduler.fairness_checkpoint();
        let order_before = scheduler.new_view_order(&[5, 7, 9]);
        let retained_before = scheduler.retained_view_order(&[1, 3, 5]);
        let alternation_before = scheduler.newcomers_first(true, true);
        let backlog_before = scheduler.backlog_order(&[1, 5, 9]);
        let newcomers_before = scheduler.newcomers_in(&[2, 3, 4]);
        scheduler.begin_under_cap_tick();
        scheduler.begin_over_cap_pass();
        scheduler.begin_deep_scan_tick(Some(1_000));
        scheduler.note_new_view_attempt(9);
        scheduler.note_retained_view_attempt(5);
        scheduler.advance_poll_cursor(17);
        scheduler.advance_cursor(19);
        scheduler.note_backlog_attempt(9);
        scheduler.note_enumeration(&BTreeSet::from([8, 10]));
        scheduler.note_evicted(21);
        assert_ne!(scheduler.new_view_order(&[5, 7, 9]), order_before);
        assert_ne!(scheduler.backlog_order(&[1, 5, 9]), backlog_before);
        scheduler.note_admitted(21);
        scheduler.note_evicted(23);
        scheduler.restore_fairness(checkpoint);
        assert_eq!(scheduler.new_view_order(&[5, 7, 9]), order_before);
        assert_eq!(scheduler.retained_view_order(&[1, 3, 5]), retained_before);
        assert_eq!(scheduler.newcomers_first(true, true), alternation_before);
        assert_eq!(scheduler.backlog_order(&[1, 5, 9]), backlog_before);
        assert_eq!(scheduler.newcomers_in(&[2, 3, 4]), newcomers_before);
        assert_eq!(scheduler.under_cap_ticks_for_test(), 3);
        assert_eq!(scheduler.over_cap_passes(), 1);
        assert_eq!(scheduler.cursor_for_test(), Some(13));
        assert!(!scheduler.cooling_down(21));
        assert!(!scheduler.is_stale(21));
        assert!(scheduler.cooling_down(23));
        assert!(scheduler.is_stale(23));
    }

    /// The backlog-owed debt survives a pressure checkpoint: a tick that
    /// attempted a newcomer but no backlog while backlog waited owes the
    /// next lead to backlog, and a service pass in between must not consume
    /// or clear that debt.
    #[test]
    fn fairness_checkpoint_restores_the_backlog_debt_ledger() {
        let batch = MAX_NEW_VIEWS_PER_TICK;
        let share = MAX_NEWCOMER_ADMISSIONS_PER_TICK;
        let mut scheduler = DiscoveryScheduler::new();
        let pids = [1, 2, 1_000_000];
        let newcomers = BTreeSet::from([1_000_000]);
        // Tick 1 opens with backlog waiting; only the newcomer is attempted.
        let (admitted, _) =
            scheduler.new_view_window_newcomers_first(&pids, &newcomers, batch, share);
        assert_eq!(admitted[0], 1_000_000, "the first tick leads newcomer");
        scheduler.note_newcomer_attempt(1_000_000);
        assert!(
            !scheduler.backlog_owed_for_test(),
            "the debt settles at the next window, not at the attempt"
        );
        // A pressure service pass runs its own window and attempts, then the
        // checkpoint puts the ledger back: the debt is still pending.
        let checkpoint = scheduler.fairness_checkpoint();
        let (pressure_admitted, _) =
            scheduler.new_view_window_newcomers_first(&pids, &newcomers, batch, share);
        assert_eq!(
            pressure_admitted[0], 1,
            "the pressure window itself leads backlog (debt honored inside)"
        );
        scheduler.note_backlog_attempt(1);
        scheduler.note_enumeration(&BTreeSet::from([7, 8, 9]));
        scheduler.restore_fairness(checkpoint);
        assert!(
            !scheduler.backlog_owed_for_test(),
            "the restore returns the still-pending debt, not the serviced one"
        );
        // The next ordinary window honors the restored debt.
        let (admitted, _) =
            scheduler.new_view_window_newcomers_first(&pids, &newcomers, batch, share);
        assert!(
            scheduler.backlog_owed_for_test(),
            "the restored ledger raises the debt at the next window"
        );
        assert_eq!(admitted[0], 1, "the owed tick leads backlog");
        // Servicing the backlog repays it: the tick after leads newcomer.
        scheduler.note_backlog_attempt(1);
        let (admitted, _) =
            scheduler.new_view_window_newcomers_first(&pids, &newcomers, batch, share);
        assert!(
            !scheduler.backlog_owed_for_test(),
            "a backlog attempt repays the debt"
        );
        assert_eq!(admitted[0], 1_000_000, "the repaid tick leads newcomer");
    }

    /// Newcomer classification reads the previous enumeration, not arrival
    /// marks: long runners deferred by an over-cap pass were enumerated
    /// before, so they are backlog even with no mark ever set. Each tick
    /// replaces the set, bounding it by the live scope.
    #[test]
    fn newcomers_are_candidates_absent_from_the_previous_enumeration() {
        let mut scheduler = DiscoveryScheduler::new();
        assert_eq!(
            scheduler.newcomers_in(&[1, 2, 3]),
            BTreeSet::from([1, 2, 3]),
            "before the first enumeration everything is first-observed"
        );
        scheduler.note_enumeration(&BTreeSet::from([1, 2, 3]));
        assert!(
            scheduler.newcomers_in(&[1, 2, 3]).is_empty(),
            "an unchanged enumeration has no newcomers"
        );
        assert_eq!(
            scheduler.newcomers_in(&[2, 3, 4]),
            BTreeSet::from([4]),
            "only the truly absent pid is a newcomer"
        );
        scheduler.note_enumeration(&BTreeSet::from([2, 3, 4]));
        assert!(
            scheduler.newcomers_in(&[2, 3, 4]).is_empty(),
            "replacement (not growth) bounds the set by the live scope"
        );
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
        for _ in 0..2 {
            scheduler.begin_over_cap_pass();
        }
        assert_eq!(scheduler.reconcile_sweeps_for_test(), 1);
        scheduler.note_evicted(7);
        assert!(scheduler.cooling_down(7));
        assert!(scheduler.is_stale(7));
        assert_eq!(scheduler.cooling_for_test(), vec![7]);
        assert_eq!(scheduler.cooling_len(), 1);
        scheduler.begin_over_cap_pass();
        assert!(scheduler.cooling_down(7), "ordinary passes age nothing");
        for _ in 0..2 {
            scheduler.begin_over_cap_pass();
        }
        assert_eq!(scheduler.reconcile_sweeps_for_test(), 2);
        assert!(
            scheduler.cooling_down(7),
            "one elapsed sweep is still cooling"
        );
        for _ in 0..2 {
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

    #[test]
    fn retained_attempt_cursor_rotates_wraps_and_survives_departure() {
        let mut scheduler = DiscoveryScheduler::new();
        assert_eq!(scheduler.retained_view_order(&[0, 2, 4]), [0, 2, 4]);
        scheduler.note_retained_view_attempt(0);
        assert_eq!(scheduler.retained_view_order(&[0, 2, 4]), [2, 4, 0]);
        scheduler.note_retained_view_attempt(2);
        assert_eq!(scheduler.retained_view_order(&[0, 4]), [4, 0]);
        scheduler.note_retained_view_attempt(4);
        assert_eq!(scheduler.retained_view_order(&[0, 2, 4]), [0, 2, 4]);
        assert!(scheduler.retained_view_order(&[]).is_empty());
    }

    #[test]
    fn ready_scan_classes_alternate_after_the_first_actual_attempt() {
        let mut scheduler = DiscoveryScheduler::new();
        scheduler.begin_deep_scan_tick(Some(0));
        assert!(!scheduler.newcomers_first(true, true));
        scheduler.note_retained_view_attempt(1);
        scheduler.note_new_view_attempt(10);
        scheduler.begin_deep_scan_tick(Some(0));
        assert!(scheduler.newcomers_first(true, true));
        scheduler.note_new_view_attempt(10);
        scheduler.note_retained_view_attempt(2);
        scheduler.begin_deep_scan_tick(Some(0));
        assert!(!scheduler.newcomers_first(true, true));
        assert!(scheduler.newcomers_first(false, true));
        assert!(!scheduler.newcomers_first(true, false));
        assert!(!scheduler.newcomers_first(false, false));
    }

    #[test]
    fn expired_ticks_preserve_attempt_cursor_and_class_turn() {
        let mut scheduler = DiscoveryScheduler::new();
        scheduler.note_retained_view_attempt(1);
        scheduler.set_tick_quantum_ns_for_test(0);
        for now in [Some(0), None] {
            scheduler.begin_deep_scan_tick(now);
            assert!(scheduler.tick_expired(now));
            assert_eq!(scheduler.retained_view_order(&[1, 2]), [2, 1]);
            assert!(scheduler.newcomers_first(true, true));
        }
        scheduler.set_tick_quantum_ns_for_test(1);
        scheduler.begin_deep_scan_tick(Some(0));
        assert!(!scheduler.tick_expired(Some(0)));
        scheduler.note_new_view_attempt(10);
        scheduler.begin_deep_scan_tick(Some(0));
        assert!(!scheduler.newcomers_first(true, true));
    }

    /// Under-cap ticks poll every fourth, on their own cadence, and the
    /// poll cursor round-robins queueing past the last queued pid.
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
        assert_eq!(DiscoveryScheduler::exploration_bound_frames(1, 8), 2);
        assert_eq!(DiscoveryScheduler::exploration_bound_frames(8, 8), 2);
        assert_eq!(DiscoveryScheduler::exploration_bound_frames(9, 8), 4);
        assert_eq!(
            DiscoveryScheduler::exploration_bound_frames(44, 8),
            12,
            "six sweeps at the two-frame cadence"
        );
    }

    /// M6 killer: with no backlog, 40 unmarked newcomers against the
    /// production batch admit all 40, not just the newcomer share. The
    /// `.max(batch - backlog.len())` term lets fresh fill slots the
    /// backlog cannot use; removing it admits only 32.
    #[test]
    fn batch_64_no_backlog_40_newcomers_all_admit() {
        let batch = MAX_NEW_VIEWS_PER_TICK;
        let share = MAX_NEWCOMER_ADMISSIONS_PER_TICK;
        assert_eq!(batch, 64);
        assert_eq!(share, 32);
        let pids: Vec<u32> = (1..=40).collect();
        let newcomers: BTreeSet<u32> = pids.iter().copied().collect();
        let mut scheduler = DiscoveryScheduler::new();
        let (admitted, deferred) =
            scheduler.new_view_window_newcomers_first(&pids, &newcomers, batch, share);
        assert_eq!(
            admitted.len(),
            40,
            "all 40 newcomers admit with no backlog: {admitted:?}"
        );
        assert!(deferred.is_empty());
    }

    /// The newcomer share is literally half the batch under flood: 100 fresh
    /// plus 100 backlog against the production batch admit exactly 32 fresh.
    /// Pinned literally (not via the share constant) so a constant change
    /// fails behaviorally, not just via the constant assertion.
    #[test]
    fn newcomer_share_bounded_per_tick_literal_32() {
        let batch = MAX_NEW_VIEWS_PER_TICK;
        let share = MAX_NEWCOMER_ADMISSIONS_PER_TICK;
        assert_eq!(batch, 64);
        assert_eq!(share, 32);
        let backlog: Vec<u32> = (1..=100).collect();
        let fresh: Vec<u32> = (1_000_000..1_000_100).collect();
        let mut pids = backlog.clone();
        pids.extend(fresh.iter().copied());
        pids.sort_unstable();
        let newcomers: BTreeSet<u32> = fresh.into_iter().collect();
        let mut scheduler = DiscoveryScheduler::new();
        let (admitted, _) =
            scheduler.new_view_window_newcomers_first(&pids, &newcomers, batch, share);
        let fresh_admitted = admitted
            .iter()
            .filter(|pid| newcomers.contains(pid))
            .count();
        assert_eq!(
            fresh_admitted, 32,
            "fresh takes literally half the batch: {admitted:?}"
        );
        assert_eq!(admitted.len(), 64);
    }

    /// A failed newcomer retries behind untried backlog: the next free
    /// window sinks the previous tick's newcomer attempts to the end of
    /// the backlog rotation (stable inside each part). Without the sink
    /// the failed pid — backlog next tick, never seen by the backlog
    /// cursor — retries ahead of untried backlog on every bounded tick.
    #[test]
    fn failed_newcomer_attempts_sink_behind_untried_backlog() {
        let mut scheduler = DiscoveryScheduler::new();
        // Tick 1: both pids are newcomers; the bounded batch admits the
        // lower one and the attempt fails (never recorded as backlog).
        let (admitted, _) = scheduler.new_view_window_newcomers_first(
            &[7, 9],
            &BTreeSet::from([7, 9]),
            1,
            MAX_NEWCOMER_ADMISSIONS_PER_TICK,
        );
        assert_eq!(admitted, vec![7]);
        scheduler.note_newcomer_attempt(7);
        // Tick 2: both are backlog now; the untried pid admits first.
        let (admitted, deferred) = scheduler.new_view_window_newcomers_first(
            &[7, 9],
            &BTreeSet::new(),
            1,
            MAX_NEWCOMER_ADMISSIONS_PER_TICK,
        );
        assert_eq!(
            admitted,
            vec![9],
            "the failed newcomer retries behind untried backlog"
        );
        assert_eq!(deferred, vec![7]);
        scheduler.note_backlog_attempt(9);
        // Tick 3: the sink lasts exactly one tick; the failed pid retries.
        let (admitted, _) = scheduler.new_view_window_newcomers_first(
            &[7],
            &BTreeSet::new(),
            1,
            MAX_NEWCOMER_ADMISSIONS_PER_TICK,
        );
        assert_eq!(admitted, vec![7], "the failed pid retries third");
    }

    /// The fairness checkpoint covers the per-tick newcomer-attempt sets:
    /// a pressure service pass that opens its own window and attempts a
    /// newcomer must not change which pids ordinary backlog rotation
    /// sinks afterwards.
    #[test]
    fn fairness_checkpoint_restores_the_newcomer_attempt_sets() {
        let mut scheduler = DiscoveryScheduler::new();
        let pids = [7, 9];
        let newcomers = BTreeSet::from([7, 9]);
        // Tick 1 admits the lower newcomer and attempts it.
        let (admitted, _) = scheduler.new_view_window_newcomers_first(&pids, &newcomers, 1, 1);
        assert_eq!(admitted, vec![7]);
        scheduler.note_newcomer_attempt(7);
        // A pressure service pass runs its own window — rotating the
        // attempt sets — and attempts the other newcomer.
        let checkpoint = scheduler.fairness_checkpoint();
        let (pressure_admitted, _) =
            scheduler.new_view_window_newcomers_first(&pids, &newcomers, 1, 1);
        assert_eq!(pressure_admitted, vec![9]);
        scheduler.note_newcomer_attempt(9);
        scheduler.restore_fairness(checkpoint);
        // The next ordinary window sinks the restored tick's attempt (7),
        // not the service pass's (9).
        let (admitted, _) =
            scheduler.new_view_window_newcomers_first(&pids, &BTreeSet::new(), 1, 1);
        assert_eq!(
            admitted,
            vec![9],
            "the restored ledger sinks the ordinary attempt"
        );
    }

    /// At a 1-pid batch with both classes waiting, the owed flag chooses
    /// the single slot: the newcomer takes it when nothing is owed, the
    /// waiting backlog pid takes the owed tick, and the repaid tick
    /// returns to the newcomer. Without the choice the flood takes every
    /// tick and the owed lead has no backlog slot to lead with.
    #[test]
    fn batch_1_owed_flag_alternates_the_single_slot() {
        let mut scheduler = DiscoveryScheduler::new();
        let (admitted, _) = scheduler.new_view_window_newcomers_first(
            &[1, 1000],
            &BTreeSet::from([1000]),
            1,
            MAX_NEWCOMER_ADMISSIONS_PER_TICK,
        );
        assert_eq!(admitted, vec![1000]);
        scheduler.note_newcomer_attempt(1000);
        let (admitted, _) = scheduler.new_view_window_newcomers_first(
            &[1, 1001],
            &BTreeSet::from([1001]),
            1,
            MAX_NEWCOMER_ADMISSIONS_PER_TICK,
        );
        assert_eq!(admitted, vec![1], "the owed tick serves the backlog pid");
        scheduler.note_backlog_attempt(1);
        let (admitted, _) = scheduler.new_view_window_newcomers_first(
            &[1002],
            &BTreeSet::from([1002]),
            1,
            MAX_NEWCOMER_ADMISSIONS_PER_TICK,
        );
        assert_eq!(admitted, vec![1002]);
    }

    /// Small batches under sustained flood still serve the backlog: at
    /// batch 1, 2 and 4 with a full batch of fresh arrivals per tick, the
    /// lone backlog pid is attempted within two ticks. The newcomer share
    /// leaves a backlog slot below the production batch; at batch 1 the
    /// owed flag alternates the single slot.
    #[test]
    fn small_batch_sustained_flood_still_serves_backlog() {
        for batch in [1usize, 2, 4] {
            let mut scheduler = DiscoveryScheduler::new();
            let mut remaining: BTreeSet<u32> = BTreeSet::from([1]);
            let mut arrival = 1_000u32;
            let mut served = None;
            for tick in 1..=10 {
                let mut fresh = BTreeSet::new();
                for _ in 0..batch {
                    remaining.insert(arrival);
                    fresh.insert(arrival);
                    arrival += 1;
                }
                let pids: Vec<u32> = remaining.iter().copied().collect();
                let (admitted, _) = scheduler.new_view_window_newcomers_first(
                    &pids,
                    &fresh,
                    batch,
                    MAX_NEWCOMER_ADMISSIONS_PER_TICK,
                );
                for pid in &admitted {
                    if fresh.contains(pid) {
                        scheduler.note_newcomer_attempt(*pid);
                    } else {
                        scheduler.note_backlog_attempt(*pid);
                    }
                    remaining.remove(pid);
                    if *pid == 1 && served.is_none() {
                        served = Some(tick);
                    }
                }
            }
            let expected = if batch == 1 { 2 } else { 1 };
            assert_eq!(
                served,
                Some(expected),
                "batch {batch}: the lone backlog pid serves on tick {expected}"
            );
        }
    }

    /// Without fresh pending, the scarce window keeps exactly today's
    /// pending-first order: pending backlog rotated after the newcomer
    /// cursor, then rotation candidates rotated after it too. Attempts
    /// park the newcomer cursor, as today.
    #[test]
    fn scarce_window_without_fresh_keeps_pending_first_order() {
        let mut scheduler = DiscoveryScheduler::new();
        scheduler.note_new_view_attempt(5);
        let (admitted, deferred) = scheduler.scarce_window_pending_newcomers_first(
            &[],
            &[1, 3, 7],
            &[2, 9],
            MAX_NEW_VIEWS_PER_TICK,
            MAX_NEWCOMER_ADMISSIONS_PER_TICK,
        );
        assert_eq!(admitted, vec![7, 1, 3, 9, 2]);
        assert!(deferred.is_empty());
        scheduler.note_scarce_backlog_attempt(7);
        let (admitted, _) = scheduler.scarce_window_pending_newcomers_first(
            &[],
            &[1, 3, 7],
            &[2, 9],
            MAX_NEW_VIEWS_PER_TICK,
            MAX_NEWCOMER_ADMISSIONS_PER_TICK,
        );
        assert_eq!(admitted, vec![1, 3, 7, 9, 2]);
    }

    /// Scarce pending newcomers take the window first up to the share;
    /// the backlog class (pending backlog, then rotation candidates)
    /// fills the rest, and the admitted window interleaves both
    /// newcomer-first.
    #[test]
    fn scarce_window_serves_pending_newcomers_first_within_share() {
        let batch = MAX_NEW_VIEWS_PER_TICK;
        let share = MAX_NEWCOMER_ADMISSIONS_PER_TICK;
        let fresh: Vec<u32> = (1_000_000..1_000_040).collect();
        let backlog: Vec<u32> = (1..=100).collect();
        let rotation: Vec<u32> = (200..=209).collect();
        let mut scheduler = DiscoveryScheduler::new();
        let (admitted, deferred) = scheduler
            .scarce_window_pending_newcomers_first(&fresh, &backlog, &rotation, batch, share);
        assert_eq!(admitted.len(), batch);
        let fresh_admitted = admitted.iter().filter(|pid| **pid >= 1_000_000).count();
        assert_eq!(fresh_admitted, share, "fresh takes exactly its share");
        assert_eq!(admitted[0], 1_000_000, "the window leads newcomer");
        assert!(
            admitted.iter().all(|pid| *pid <= 100 || *pid >= 1_000_000),
            "rotation waits behind pending backlog: {admitted:?}"
        );
        let pending_tail: Vec<u32> = (33..=100).collect();
        let rotation_all: Vec<u32> = (200..=209).collect();
        assert_eq!(deferred.len(), 8 + pending_tail.len() + rotation_all.len());
        assert_eq!(&deferred[8..8 + pending_tail.len()], &pending_tail[..]);
        assert_eq!(&deferred[8 + pending_tail.len()..], &rotation_all[..]);
    }

    /// The scarce window honors the owed lead: a tick that attempts only
    /// fresh while backlog waits repays with a backlog-first window next,
    /// and the repaid tick leads newcomer again.
    #[test]
    fn scarce_window_owed_tick_leads_with_pending_backlog() {
        let mut scheduler = DiscoveryScheduler::new();
        let (admitted, _) = scheduler.scarce_window_pending_newcomers_first(
            &[1_000_000],
            &[1],
            &[],
            MAX_NEW_VIEWS_PER_TICK,
            MAX_NEWCOMER_ADMISSIONS_PER_TICK,
        );
        assert_eq!(admitted, vec![1_000_000, 1]);
        scheduler.note_newcomer_attempt(1_000_000);
        let (admitted, _) = scheduler.scarce_window_pending_newcomers_first(
            &[1_000_001],
            &[1],
            &[],
            MAX_NEW_VIEWS_PER_TICK,
            MAX_NEWCOMER_ADMISSIONS_PER_TICK,
        );
        assert_eq!(
            admitted,
            vec![1, 1_000_001],
            "the owed tick leads with pending backlog"
        );
        scheduler.note_scarce_backlog_attempt(1);
        let (admitted, _) = scheduler.scarce_window_pending_newcomers_first(
            &[1_000_002],
            &[2],
            &[],
            MAX_NEW_VIEWS_PER_TICK,
            MAX_NEWCOMER_ADMISSIONS_PER_TICK,
        );
        assert_eq!(admitted, vec![1_000_002, 2]);
    }

    /// At a 1-pid scarce batch with fresh and backlog waiting, the owed
    /// flag chooses the single slot, exactly like the free window.
    /// Rotation candidates count as backlog class: they wait behind fresh
    /// on the repaid tick.
    #[test]
    fn scarce_window_batch_1_owed_flag_chooses_the_class() {
        let mut scheduler = DiscoveryScheduler::new();
        let (admitted, _) = scheduler.scarce_window_pending_newcomers_first(
            &[1_000_000],
            &[1],
            &[2],
            1,
            MAX_NEWCOMER_ADMISSIONS_PER_TICK,
        );
        assert_eq!(admitted, vec![1_000_000]);
        scheduler.note_newcomer_attempt(1_000_000);
        let (admitted, _) = scheduler.scarce_window_pending_newcomers_first(
            &[1_000_001],
            &[1],
            &[2],
            1,
            MAX_NEWCOMER_ADMISSIONS_PER_TICK,
        );
        assert_eq!(admitted, vec![1], "the owed tick serves pending backlog");
        scheduler.note_scarce_backlog_attempt(1);
        let (admitted, deferred) = scheduler.scarce_window_pending_newcomers_first(
            &[1_000_002],
            &[],
            &[2],
            1,
            MAX_NEWCOMER_ADMISSIONS_PER_TICK,
        );
        assert_eq!(admitted, vec![1_000_002]);
        assert_eq!(deferred, vec![2]);
    }

    /// The tick-start pair tracks the previous tick: each deep-scan tick
    /// shifts last into previous. A failed clock installs `None` and the
    /// next tick reads no previous start (backlog, never fresh, without
    /// clock evidence).
    #[test]
    fn tick_start_pair_tracks_the_previous_tick() {
        let mut scheduler = DiscoveryScheduler::new();
        assert_eq!(scheduler.prev_tick_start_ns(), None);
        scheduler.begin_deep_scan_tick(Some(100));
        assert_eq!(scheduler.prev_tick_start_ns(), None);
        scheduler.begin_deep_scan_tick(Some(150));
        assert_eq!(scheduler.prev_tick_start_ns(), Some(100));
        scheduler.begin_deep_scan_tick(None);
        assert_eq!(scheduler.prev_tick_start_ns(), Some(150));
        scheduler.begin_deep_scan_tick(Some(200));
        assert_eq!(
            scheduler.prev_tick_start_ns(),
            None,
            "a failed clock leaves the next tick without a previous start"
        );
    }

    /// The fairness checkpoint covers the tick-start pair: a pressure
    /// service pass runs its own deep-scan tick and must not shift scarce
    /// newcomer classification afterwards.
    #[test]
    fn fairness_checkpoint_restores_the_tick_start_pair() {
        let mut scheduler = DiscoveryScheduler::new();
        scheduler.begin_deep_scan_tick(Some(100));
        scheduler.begin_deep_scan_tick(Some(150));
        assert_eq!(scheduler.prev_tick_start_ns(), Some(100));
        let checkpoint = scheduler.fairness_checkpoint();
        scheduler.begin_deep_scan_tick(Some(200));
        assert_eq!(scheduler.prev_tick_start_ns(), Some(150));
        scheduler.restore_fairness(checkpoint);
        assert_eq!(
            scheduler.prev_tick_start_ns(),
            Some(100),
            "the restore returns the pre-service previous tick"
        );
    }

    /// Sustained flood exceeding the per-tick attempts: `k` attempts per
    /// tick but `k + 1` arrivals per tick, deferred arrivals rejoining as
    /// backlog next tick. Every original backlog entry must be attempted,
    /// oldest (lowest pid) first, within a bound; returns the measured
    /// last-attempt tick and whether all served in order. Concatenating
    /// fresh ahead of backlog instead of interleaving would attempt only
    /// newcomers forever and strand every original.
    fn opus_flood(k: usize, originals: u32, ticks_max: usize) -> (usize, bool) {
        let batch = MAX_NEW_VIEWS_PER_TICK;
        let share = MAX_NEWCOMER_ADMISSIONS_PER_TICK;
        let mut scheduler = DiscoveryScheduler::new();
        let mut remaining: BTreeSet<u32> = (1..=originals).collect();
        let mut arrival = 1_000_000u32;
        let mut served_order = Vec::new();
        let mut last = 0usize;
        for tick in 1..=ticks_max {
            let mut fresh = BTreeSet::new();
            for _ in 0..=k {
                remaining.insert(arrival);
                fresh.insert(arrival);
                arrival += 1;
            }
            let pids: Vec<u32> = remaining.iter().copied().collect();
            let (admitted, _) =
                scheduler.new_view_window_newcomers_first(&pids, &fresh, batch, share);
            for pid in admitted.iter().take(k) {
                if fresh.contains(pid) {
                    scheduler.note_newcomer_attempt(*pid);
                } else {
                    scheduler.note_backlog_attempt(*pid);
                }
                remaining.remove(pid);
                if *pid <= originals {
                    served_order.push(*pid);
                    last = tick;
                }
            }
            if !remaining.iter().any(|pid| *pid <= originals) {
                break;
            }
        }
        let all = !remaining.iter().any(|pid| *pid <= originals);
        let ordered = served_order.windows(2).all(|w| w[0] < w[1]);
        eprintln!(
            "OPUS-P1 k={k} originals={originals} all_served={all} last_tick={last} oldest_first={ordered}"
        );
        (last, all && ordered)
    }

    /// The sustained-flood bound, pinned per attempt rate: at one attempt
    /// per tick the owed flag alternates the lead and 200 originals serve
    /// within 401 ticks; at two or three attempts the interleave serves
    /// one backlog pid per tick; at eight it serves four per tick.
    #[test]
    fn opus_p1_sustained_flood_bounds() {
        let (t1, ok1) = opus_flood(1, 200, 2000);
        let (t2, ok2) = opus_flood(2, 200, 2000);
        let (t3, ok3) = opus_flood(3, 200, 2000);
        let (t8, ok8) = opus_flood(8, 200, 2000);
        assert!(ok1 && ok2 && ok3 && ok8);
        assert!(t1 <= 2 * 200 + 1, "k=1 bound {t1}");
        assert!(t2 <= 200 + 1, "k=2 bound {t2}");
        assert!(t3 <= 200 + 1, "k=3 bound {t3}");
        assert!(t8 <= 200 / 4 + 1, "k=8 bound {t8}");
    }

    /// OPUS r4 S1: on a scarce window no rotation candidate precedes a
    /// pending newcomer (ruling order: pending newcomers, pending backlog,
    /// rotation).
    #[test]
    fn opus_r4_scarce_rotation_never_precedes_pending() {
        let mut s = DiscoveryScheduler::new();
        let rotation: Vec<u32> = (1..=200).collect();
        let (admitted, _) = s.scarce_window_pending_newcomers_first(
            &[1000, 1001, 1002],
            &[],
            &rotation,
            MAX_NEW_VIEWS_PER_TICK,
            MAX_NEWCOMER_ADMISSIONS_PER_TICK,
        );
        eprintln!("OPUS-S1 head={:?}", &admitted[..8]);
        let last_pending = admitted.iter().rposition(|p| *p >= 1000).unwrap();
        let first_rotation = admitted.iter().position(|p| *p < 1000).unwrap();
        assert!(
            last_pending < first_rotation,
            "rotation precedes pending: {:?}",
            &admitted[..8]
        );
    }

    /// OPUS r4 S2: a 40-pid fresh pending burst with rotation present and
    /// no pending backlog keeps every pending pid ahead of rotation.
    #[test]
    fn opus_r4_scarce_burst_over_share_all_pending_first() {
        let mut s = DiscoveryScheduler::new();
        let fresh: Vec<u32> = (1000..1040).collect();
        let rotation: Vec<u32> = (1..=200).collect();
        let (admitted, deferred) =
            s.scarce_window_pending_newcomers_first(&fresh, &[], &rotation, 64, 32);
        let fresh_admitted = admitted.iter().filter(|p| **p >= 1000).count();
        eprintln!(
            "OPUS-S2 fresh_admitted={fresh_admitted} deferred_fresh={}",
            deferred.iter().filter(|p| **p >= 1000).count()
        );
        assert_eq!(fresh_admitted, 40);
    }

    /// OPUS r4 S3: rotation-only backlog class must not take the owed lead
    /// ahead of a pending newcomer.
    #[test]
    fn opus_r4_scarce_owed_lead_with_only_rotation() {
        let mut s = DiscoveryScheduler::new();
        let rotation: Vec<u32> = (1..=200).collect();
        let (a1, _) = s.scarce_window_pending_newcomers_first(&[1000], &[], &rotation, 64, 32);
        s.note_newcomer_attempt(a1[0]);
        let (a2, _) = s.scarce_window_pending_newcomers_first(&[1001], &[], &rotation, 64, 32);
        eprintln!("OPUS-S3 tick1={:?} tick2={:?}", &a1[..3], &a2[..3]);
        assert_eq!(
            a2[0], 1001,
            "a rotation candidate took the owed lead ahead of a pending newcomer"
        );
    }

    /// OPUS r4 S4: the failed-newcomer sink survives a zero-attempt window.
    /// A tick that attempts nothing (an expired quantum before the first
    /// scan) must not rotate the newcomer-attempt sets and lose the sink.
    #[test]
    fn opus_r4_sink_survives_zero_attempt_window() {
        let mut s = DiscoveryScheduler::new();
        let (a, _) = s.new_view_window_newcomers_first(&[7, 9], &BTreeSet::from([7, 9]), 1, 32);
        assert_eq!(a, vec![7]);
        s.note_newcomer_attempt(7);
        let (a, _) = s.new_view_window_newcomers_first(&[7, 9], &BTreeSet::new(), 1, 32);
        assert_eq!(a, vec![9]);
        // Nothing attempted (quantum expired before the first scan).
        let (a, _) = s.new_view_window_newcomers_first(&[7, 9], &BTreeSet::new(), 1, 32);
        eprintln!("OPUS-S4 after_zero_attempt_window={a:?}");
        assert_eq!(
            a,
            vec![9],
            "the failed-newcomer sink survives a zero-attempt window"
        );
    }
}
