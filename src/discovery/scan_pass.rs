// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! One per-pass budget owner for every scope and mode (admission owner 2).
//!
//! Every scope charges work and I/O through [`ScanPassOwner`], and every
//! pass boundary renews through [`ScanPassOwner::end_pass`]: per-pass
//! allowances, never a constant raise. Renewable stops (work/IO
//! ceilings, deadline, clock) renew next pass and the refused tail
//! retries first from the [`ResumeCursor`]; collection stops and zero
//! caps never admit. [`CaptureWorkBudget`](super::scan::CaptureWorkBudget)
//! keeps the retained caches, identity stores and disclosure tallies
//! and delegates every budget interaction here.

use super::scan::{
    ActiveInventoryWindow, BudgetDomain, COLLECTION_STOP_REASON, CollectionWork,
    DEFAULT_WORK_CEILING, DiscoveryPolicy, INTERFACE_WINDOW_CEILING_REASON, IO_CEILING_REASON,
    InventoryWindowLimits, SCAN_CLOCK_REASON, SCAN_DEADLINE_REASON, ScanCheckpoint, ScanLimits,
    TABLE_WINDOW_CEILING_REASON, WORK_CEILING_REASON, WindowId, WindowReceipt, WindowToken,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A scan member for cursor purposes: pid plus the proven generation
/// start-time when the driver knows it. Tasks without a start-time key
/// by pid alone (tests, one-shots); drivers that know generations
/// pass them so pid reuse cannot inherit a tier or streak.
pub(crate) type MemberTask = (u32, Option<u64>);

/// What one applied pass decided about one enumerated member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MemberOutcome {
    /// Scanned to completion or maps-matched: joins examined memory
    /// and clears any streak.
    Examined,
    /// Its own scan ended early on a capture budget stop: stays
    /// fresh and accrues toward demotion.
    CutShortBudgetStop,
    /// Its own scan was cut short by a non-budget truncation (mapping
    /// race, replaced file): stays fresh without accruing.
    CutShortOther,
    /// Not attempted this pass (unavailable, unreadable, exited,
    /// not selected): stays fresh without accruing.
    Unattempted,
}

/// What one charge decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChargeOutcome {
    Admitted,
    Stopped {
        reason: &'static str,
        /// A terminal stop never heals: collection stops (external
        /// authority), zero-capacity allowances (degenerate config)
        /// and exhausted capture-lifetime allowances (nothing left
        /// to admit). Renewable stops heal at `end_pass`.
        terminal: bool,
    },
}

/// Budget-stop passes after which a never-completing member yields
/// to never-scanned newcomers (adopted live-proof bound).
pub(crate) const BUDGET_STOP_DEMOTE_AFTER: u32 = 3;

/// The bounded named gap subject a newly demoted member files once
/// per stuck episode (adopted vocabulary: one phenomenon, one row).
pub(crate) fn demotion_gap_subject() -> String {
    format!("member scan budget-stopped {BUDGET_STOP_DEMOTE_AFTER} passes without completing")
}

/// What the next pass continues: member tiers plus budget-stop
/// streaks. Never-attempted members scan first, then cut-short
/// retries, then demoted members past [`BUDGET_STOP_DEMOTE_AFTER`],
/// then examined members. Streaks key by task generation, so pid
/// reuse starts fresh; pruning retains enumerated tasks only.
#[derive(Debug, Clone, Default)]
pub(crate) struct ResumeCursor {
    examined: BTreeSet<MemberTask>,
    fresh: BTreeSet<MemberTask>,
    streaks: BTreeMap<MemberTask, u32>,
}

impl ResumeCursor {
    /// Records one applied pass's member outcomes and returns the
    /// tasks newly demoted this pass — the driver files one
    /// [`demotion_gap_subject`] row per task, never a row per pass.
    /// Discarded passes record nothing. Noting a task with a proven
    /// generation supersedes other generations of the same pid, so
    /// pid reuse never inherits a tier or streak; call
    /// [`ResumeCursor::prune_to_live`] with the pass enumeration to
    /// drop departed pids.
    pub(crate) fn note_member_outcomes(
        &mut self,
        outcomes: &[(MemberTask, MemberOutcome)],
    ) -> Vec<MemberTask> {
        let mut newly_demoted = Vec::new();
        for (task, outcome) in outcomes {
            if task.1.is_some() {
                let superseded = |held: &MemberTask| held.0 == task.0 && held.1 != task.1;
                self.examined.retain(|held| !superseded(held));
                self.fresh.retain(|held| !superseded(held));
                self.streaks.retain(|held, _| !superseded(held));
            }
            match outcome {
                MemberOutcome::Examined => {
                    self.examined.insert(*task);
                    self.fresh.remove(task);
                    self.streaks.remove(task);
                }
                MemberOutcome::CutShortBudgetStop => {
                    self.examined.remove(task);
                    let streak = self.streaks.entry(*task).or_insert(0);
                    *streak = streak.saturating_add(1);
                    if *streak >= BUDGET_STOP_DEMOTE_AFTER {
                        // Graduates to demoted: out of the retry tier
                        // until it genuinely completes.
                        self.fresh.remove(task);
                    } else {
                        self.fresh.insert(*task);
                    }
                    if *streak == BUDGET_STOP_DEMOTE_AFTER {
                        newly_demoted.push(*task);
                    }
                }
                MemberOutcome::CutShortOther | MemberOutcome::Unattempted => {
                    self.examined.remove(task);
                    if self
                        .streaks
                        .get(task)
                        .is_none_or(|streak| *streak < BUDGET_STOP_DEMOTE_AFTER)
                    {
                        self.fresh.insert(*task);
                    }
                }
            }
        }
        newly_demoted
    }

    /// Orders tasks for this pass: never-attempted first, then
    /// cut-short retries, then demoted members, then examined ones
    /// (ascending pid within each tier). Unknown tasks read
    /// never-attempted: work fails toward retry, never toward stall.
    pub(crate) fn order_members(&self, tasks: &[MemberTask]) -> Vec<u32> {
        let mut never = Vec::new();
        let mut retry = Vec::new();
        let mut demoted = Vec::new();
        let mut examined = Vec::new();
        for task in tasks {
            if self.examined.contains(task) {
                examined.push(task.0);
            } else if self
                .streaks
                .get(task)
                .is_some_and(|streak| *streak >= BUDGET_STOP_DEMOTE_AFTER)
            {
                demoted.push(task.0);
            } else if self.fresh.contains(task) || self.streaks.contains_key(task) {
                retry.push(task.0);
            } else {
                never.push(task.0);
            }
        }
        never.sort_unstable();
        retry.sort_unstable();
        demoted.sort_unstable();
        examined.sort_unstable();
        never
            .into_iter()
            .chain(retry)
            .chain(demoted)
            .chain(examined)
            .collect()
    }

    /// Examined tasks, for tests.
    #[cfg(test)]
    pub(crate) fn examined_for_test(&self) -> BTreeSet<MemberTask> {
        self.examined.clone()
    }

    /// Budget-stop streaks, for tests.
    #[cfg(test)]
    pub(crate) fn streaks_for_test(&self) -> BTreeMap<MemberTask, u32> {
        self.streaks.clone()
    }

    /// Examined tasks held, for memory telemetry.
    pub(crate) fn examined_len(&self) -> usize {
        self.examined.len()
    }

    /// Drops tasks whose pid the pass never enumerated (departed
    /// members): tiers track live pids only and stay bounded.
    pub(crate) fn prune_to_live(&mut self, live_pids: &BTreeSet<u32>) {
        self.examined.retain(|task| live_pids.contains(&task.0));
        self.fresh.retain(|task| live_pids.contains(&task.0));
        self.streaks.retain(|task, _| live_pids.contains(&task.0));
    }

    /// Projects the tiers to pid sets for selection: recorded tasks
    /// whose live start-time still matches, plus tasks recorded
    /// without a start-time (nothing verifiable, so nothing dropped).
    /// A recycled pid reads fresh, so reuse never inherits the old
    /// incarnation's slot. Never-attempted is the complement (any pid
    /// in no set); unknown work fails toward retry, never toward stall.
    pub(crate) fn tiers_for_selection(
        &self,
        live_start_time: impl Fn(u32) -> Option<u64>,
    ) -> MemberTiers {
        let mut tiers = MemberTiers::default();
        let live = |task: &MemberTask| {
            task.1
                .is_none_or(|start| live_start_time(task.0) == Some(start))
        };
        for task in self.examined.iter().filter(|task| live(task)) {
            tiers.examined.insert(task.0);
        }
        for task in self.fresh.iter().filter(|task| live(task)) {
            tiers.retry.insert(task.0);
        }
        for (task, streak) in self
            .streaks
            .iter()
            .filter(|(task, _)| live(task))
            .filter(|(_, streak)| **streak >= BUDGET_STOP_DEMOTE_AFTER)
        {
            tiers.demoted.insert(task.0);
        }
        tiers
    }
}

/// The cursor's tiers projected to pids for one selection pass.
/// Never-attempted members are any pid in no set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MemberTiers {
    pub(crate) examined: BTreeSet<u32>,
    pub(crate) retry: BTreeSet<u32>,
    pub(crate) demoted: BTreeSet<u32>,
}

impl MemberTiers {
    /// Pids selection treats as already scanned for rarity tiering:
    /// examined plus demoted (demoted members sort with the
    /// all-scanned groups, after never-scanned ones).
    pub(crate) fn scanned_equivalent(&self) -> BTreeSet<u32> {
        self.examined.union(&self.demoted).copied().collect()
    }

    /// Orders pids for an under-cap pass: never-attempted first,
    /// then cut-short retries, then demoted members, then examined
    /// ones (ascending pid within each tier).
    pub(crate) fn order_under_cap(&self, pids: &[u32]) -> Vec<u32> {
        let mut never = Vec::new();
        let mut retry = Vec::new();
        let mut demoted = Vec::new();
        let mut examined = Vec::new();
        for pid in pids {
            if self.examined.contains(pid) {
                examined.push(*pid);
            } else if self.demoted.contains(pid) {
                demoted.push(*pid);
            } else if self.retry.contains(pid) {
                retry.push(*pid);
            } else {
                never.push(*pid);
            }
        }
        never.sort_unstable();
        retry.sort_unstable();
        demoted.sort_unstable();
        examined.sort_unstable();
        never
            .into_iter()
            .chain(retry)
            .chain(demoted)
            .chain(examined)
            .collect()
    }
}

/// One per-pass budget for every scope: work and I/O allowances,
/// stop latch, inventory windows, collection hook and the resume
/// cursor. Detailed allowances are per-pass (renewed at
/// [`ScanPassOwner::end_pass`]); Inventory windows renew through
/// their own begin/finish lifecycle; the lifetime I/O total is
/// retained for headroom reporting.
#[derive(Debug, Clone)]
pub(crate) struct ScanPassOwner {
    limits: ScanLimits,
    policy: DiscoveryPolicy,
    domain: Option<Arc<BudgetDomain>>,
    collection_work: Option<CollectionWork>,
    work_ceiling: u64,
    work_units: u64,
    pass_io_bytes: u64,
    attempted_io_bytes: u64,
    active_window: Option<ActiveInventoryWindow>,
    last_window: Option<WindowId>,
    active_scan: Option<ScanCheckpoint>,
    next_scan_serial: u64,
    window_exhaustions: u64,
    deadline_ns: Option<u64>,
    #[cfg(test)]
    last_installed_deadline: Option<u64>,
    scan_stop_reason: Option<&'static str>,
    scan_stop_reported: bool,
    cursor: ResumeCursor,
}

impl ScanPassOwner {
    /// A Detailed owner from scan limits (budget construction).
    pub(crate) fn from_limits(limits: ScanLimits) -> Self {
        Self {
            limits,
            policy: DiscoveryPolicy::DetailedLegacy,
            domain: None,
            collection_work: None,
            work_ceiling: DEFAULT_WORK_CEILING,
            work_units: 0,
            pass_io_bytes: 0,
            attempted_io_bytes: 0,
            active_window: None,
            last_window: None,
            active_scan: None,
            next_scan_serial: 0,
            window_exhaustions: 0,
            deadline_ns: None,
            #[cfg(test)]
            last_installed_deadline: None,
            scan_stop_reason: None,
            scan_stop_reported: false,
            cursor: ResumeCursor::default(),
        }
    }

    /// A Detailed owner with per-pass work and I/O allowances.
    pub(crate) fn detailed(work_ceiling: u64, io_bytes: u64) -> Self {
        Self::from_limits(ScanLimits {
            per_object_bytes: io_bytes,
            total_bytes: io_bytes,
        })
        .with_work_ceiling(work_ceiling)
    }

    fn with_work_ceiling(mut self, work_ceiling: u64) -> Self {
        self.work_ceiling = work_ceiling;
        self
    }

    /// An Inventory owner; windows renew through their own lifecycle.
    pub(crate) fn inventory(limits: crate::discovery::scan::InventoryDiscoveryLimits) -> Self {
        Self {
            limits: ScanLimits {
                per_object_bytes: limits.per_operation_bytes,
                total_bytes: limits.window.io_bytes,
            },
            policy: DiscoveryPolicy::Inventory(limits),
            domain: Some(Arc::new(BudgetDomain)),
            collection_work: None,
            work_ceiling: DEFAULT_WORK_CEILING,
            work_units: 0,
            pass_io_bytes: 0,
            attempted_io_bytes: 0,
            active_window: None,
            last_window: None,
            active_scan: None,
            next_scan_serial: 0,
            window_exhaustions: 0,
            deadline_ns: None,
            #[cfg(test)]
            last_installed_deadline: None,
            scan_stop_reason: None,
            scan_stop_reported: false,
            cursor: ResumeCursor::default(),
        }
    }

    pub(crate) fn cursor(&self) -> &ResumeCursor {
        &self.cursor
    }

    pub(crate) fn cursor_mut(&mut self) -> &mut ResumeCursor {
        &mut self.cursor
    }

    pub(crate) fn policy(&self) -> DiscoveryPolicy {
        self.policy
    }

    pub(crate) fn limits(&self) -> ScanLimits {
        self.limits
    }

    /// Lifetime attempted I/O, retained for headroom reporting; the
    /// per-pass allowance is separate and renews at `end_pass`.
    pub(crate) fn attempted_io_bytes(&self) -> u64 {
        self.attempted_io_bytes
    }

    /// Work charged this pass (Detailed) or tallied this capture
    /// (Inventory windows). Tests only.
    #[cfg(test)]
    pub(crate) fn work_units(&self) -> u64 {
        self.work_units
    }

    /// Snapshot the consumed allowance (see [`super::scan::BudgetConsumption`]).
    pub(crate) fn consumption_snapshot(&self) -> super::scan::BudgetConsumption {
        super::scan::BudgetConsumption {
            work_units: self.work_units,
            attempted_io_bytes: self.attempted_io_bytes,
        }
    }

    pub(crate) fn window_exhaustions(&self) -> u64 {
        self.window_exhaustions
    }

    pub(crate) fn set_collection_work(&mut self, work: CollectionWork) {
        self.collection_work = Some(work);
    }

    pub(crate) fn has_collection_work(&self) -> bool {
        self.collection_work.is_some()
    }

    pub(crate) fn poll_collection(&mut self, units: u64) -> bool {
        self.collection_checkpoint(units)
    }

    fn collection_checkpoint(&mut self, units: u64) -> bool {
        let Some(work) = &self.collection_work else {
            return true;
        };
        if self.scan_stop_reason.is_some() {
            return false;
        }
        if !(work.0)(units) {
            self.set_scan_stop(COLLECTION_STOP_REASON);
            return false;
        }
        true
    }

    /// Set the work ceiling (tests of where a ceiling stops).
    #[cfg(test)]
    pub(crate) fn set_work_ceiling_for_test(&mut self, units: u64) {
        self.work_ceiling = units;
    }

    /// Set charged work directly (overflow tests). Tests only.
    #[cfg(test)]
    pub(crate) fn set_work_units_for_test(&mut self, units: u64) {
        self.work_units = units;
    }

    /// Set the scan serial directly (overflow tests). Tests only.
    #[cfg(test)]
    pub(crate) fn set_next_scan_serial_for_test(&mut self, serial: u64) {
        self.next_scan_serial = serial;
    }

    pub(crate) fn has_active_scan(&self) -> bool {
        self.active_scan.is_some()
    }

    pub(crate) fn set_deadline(&mut self, deadline_ns: Option<u64>) {
        #[cfg(test)]
        if deadline_ns.is_some() {
            self.last_installed_deadline = deadline_ns;
        }
        self.deadline_ns = deadline_ns;
        if matches!(self.policy, DiscoveryPolicy::DetailedLegacy)
            && deadline_ns.is_none()
            && matches!(
                self.scan_stop_reason,
                Some(SCAN_DEADLINE_REASON | SCAN_CLOCK_REASON)
            )
        {
            self.scan_stop_reason = None;
            self.scan_stop_reported = false;
        }
    }

    pub(crate) fn has_deadline(&self) -> bool {
        self.deadline_ns.is_some() || self.active_window.is_some() || self.collection_work.is_some()
    }

    /// Ends one pass: renews pass-scoped allowances (I/O bytes,
    /// deadline) and clears renewable stops, keeping the cursor and
    /// capture-lifetime consumed work. Returns the cleared stop when
    /// it was never reported, so the driver files it against its own
    /// pass instead of losing it; `None` for a clean pass, an already
    /// reported stop, an active window (windows own their renewal),
    /// or a terminal stop (collection stops, zero caps and exhausted
    /// capture ceilings are kept and never admit).
    pub(crate) fn end_pass(&mut self) -> Option<&'static str> {
        if self.active_window.is_some() {
            return None;
        }
        self.pass_io_bytes = 0;
        let reason = self.scan_stop_reason?;
        if reason == COLLECTION_STOP_REASON || !self.allowance_allows_progress(reason) {
            return None;
        }
        let unreported = !self.scan_stop_reported;
        self.scan_stop_reason = None;
        self.scan_stop_reported = false;
        self.deadline_ns = None;
        unreported.then_some(reason)
    }

    /// Whether the tripped dimension could admit anything next pass.
    /// An exhausted allowance re-trips instantly, so its stop stays
    /// put; a stop with headroom left renews. Detailed work is
    /// capture-lifetime (consumed units persist across passes), so
    /// its headroom is the ceiling remainder; pass-scoped
    /// allowances renew at `end_pass`, so theirs is the allowance.
    fn allowance_allows_progress(&self, reason: &'static str) -> bool {
        match reason {
            WORK_CEILING_REASON => match self.policy {
                DiscoveryPolicy::DetailedLegacy => self.work_units < self.work_ceiling,
                DiscoveryPolicy::Inventory(_) => self.work_allowance() > 0,
            },
            IO_CEILING_REASON => self.io_allowance() > 0,
            _ => true,
        }
    }

    fn work_allowance(&self) -> u64 {
        match self.policy {
            DiscoveryPolicy::Inventory(_) => self
                .active_window
                .as_ref()
                .map_or(u64::MAX, |window| window.limits.work_units),
            DiscoveryPolicy::DetailedLegacy => self.work_ceiling,
        }
    }

    fn io_allowance(&self) -> u64 {
        match self.policy {
            DiscoveryPolicy::Inventory(_) => self
                .active_window
                .as_ref()
                .map_or(u64::MAX, |window| window.limits.io_bytes),
            DiscoveryPolicy::DetailedLegacy => self.limits.total_bytes,
        }
    }

    pub(crate) fn set_scan_stop(&mut self, reason: &'static str) {
        if self.scan_stop_reason.is_some() {
            return;
        }
        self.scan_stop_reason = Some(reason);
        if let Some(window) = self.active_window.as_mut() {
            window.stop_reason = Some(reason);
            self.window_exhaustions = self.window_exhaustions.saturating_add(1);
        }
    }

    pub(crate) fn stopped_reason(&self) -> Option<&'static str> {
        self.scan_stop_reason
    }

    pub(crate) fn scan_stopped(&self) -> bool {
        self.scan_stop_reason.is_some()
    }

    pub(crate) fn take_scan_stop_reason(&mut self) -> Option<&'static str> {
        let reason = self.scan_stop_reason?;
        if self.scan_stop_reported {
            None
        } else {
            self.scan_stop_reported = true;
            Some(reason)
        }
    }

    pub(crate) fn check_deadline(&mut self, now: Option<u64>) -> Option<&'static str> {
        self.collection_checkpoint(0);
        if let Some(reason) = self.scan_stop_reason {
            return Some(reason);
        }
        let window_deadline = self.active_window.as_ref().map(|window| window.deadline_ns);
        let deadline = match (window_deadline, self.deadline_ns) {
            (Some(window), Some(transaction)) => window.min(transaction),
            (Some(window), None) => window,
            (None, Some(transaction)) => transaction,
            (None, None) => return None,
        };
        let reason = match now {
            Some(now) if now < deadline => return None,
            Some(_) => SCAN_DEADLINE_REASON,
            None => SCAN_CLOCK_REASON,
        };
        self.set_scan_stop(reason);
        Some(reason)
    }

    pub(crate) fn check_deadline_now(&mut self) -> Option<&'static str> {
        if self.deadline_ns.is_some()
            || self.active_window.is_some()
            || self.collection_work.is_some()
        {
            self.check_deadline(crate::attach::monotonic_ns())
        } else {
            None
        }
    }

    /// Charges work, naming a terminal stop when the allowance
    /// itself can never admit.
    pub(crate) fn charge_work(&mut self, units: u64) -> ChargeOutcome {
        if self.scan_stop_reason.is_some() {
            let reason = self.scan_stop_reason.unwrap_or(WORK_CEILING_REASON);
            return ChargeOutcome::Stopped {
                reason,
                terminal: self.latched_stop_is_terminal(reason),
            };
        }
        if !self.collection_checkpoint(units) {
            return ChargeOutcome::Stopped {
                reason: COLLECTION_STOP_REASON,
                terminal: true,
            };
        }
        if let DiscoveryPolicy::Inventory(_) = self.policy {
            if self.active_scan.is_none() {
                return ChargeOutcome::Stopped {
                    reason: WORK_CEILING_REASON,
                    terminal: false,
                };
            }
            let Some(window) = self.active_window.as_mut() else {
                return ChargeOutcome::Stopped {
                    reason: WORK_CEILING_REASON,
                    terminal: false,
                };
            };
            let Some(next) = window.work_units.checked_add(units) else {
                self.set_scan_stop(WORK_CEILING_REASON);
                return ChargeOutcome::Stopped {
                    reason: WORK_CEILING_REASON,
                    terminal: false,
                };
            };
            if next > window.limits.work_units {
                self.set_scan_stop(WORK_CEILING_REASON);
                return ChargeOutcome::Stopped {
                    reason: WORK_CEILING_REASON,
                    terminal: false,
                };
            }
            window.work_units = next;
            self.work_units = self.work_units.saturating_add(units);
            return ChargeOutcome::Admitted;
        }
        if self.work_ceiling == 0 {
            self.set_scan_stop(WORK_CEILING_REASON);
            return ChargeOutcome::Stopped {
                reason: WORK_CEILING_REASON,
                terminal: true,
            };
        }
        let Some(next) = self.work_units.checked_add(units) else {
            self.set_scan_stop(WORK_CEILING_REASON);
            return ChargeOutcome::Stopped {
                reason: WORK_CEILING_REASON,
                terminal: !self.allowance_allows_progress(WORK_CEILING_REASON),
            };
        };
        if next > self.work_ceiling {
            self.set_scan_stop(WORK_CEILING_REASON);
            return ChargeOutcome::Stopped {
                reason: WORK_CEILING_REASON,
                terminal: !self.allowance_allows_progress(WORK_CEILING_REASON),
            };
        }
        self.work_units = next;
        ChargeOutcome::Admitted
    }

    /// Whether an already-latched stop is terminal (kept at
    /// `end_pass`, never heals).
    fn latched_stop_is_terminal(&self, reason: &'static str) -> bool {
        reason == COLLECTION_STOP_REASON || !self.allowance_allows_progress(reason)
    }

    /// Legacy boolean charge (delegated by the budget).
    pub(crate) fn charge(&mut self, units: u64) -> bool {
        matches!(self.charge_work(units), ChargeOutcome::Admitted)
    }

    /// Legacy fallible spend (delegated by the budget).
    pub(crate) fn spend(&mut self, units: u64) -> Result<(), &'static str> {
        if self.charge(units) {
            Ok(())
        } else {
            Err(self.scan_stop_reason.unwrap_or(WORK_CEILING_REASON))
        }
    }

    /// Remaining I/O for this pass: the window remainder on
    /// Inventory, the per-pass allowance on Detailed.
    pub(crate) fn remaining_window_io(&self) -> Result<u64, String> {
        match self.policy {
            DiscoveryPolicy::DetailedLegacy => {
                Ok(self.limits.total_bytes.saturating_sub(self.pass_io_bytes))
            }
            DiscoveryPolicy::Inventory(_) => self
                .active_window
                .as_ref()
                .map(|window| window.limits.io_bytes.saturating_sub(window.io_bytes))
                .ok_or_else(|| "inventory discovery I/O requires an active window".into()),
        }
    }

    /// Charges an I/O read, naming a terminal stop when the allowance
    /// itself can never admit.
    pub(crate) fn charge_io(&mut self, bytes: u64) -> ChargeOutcome {
        if self.scan_stop_reason.is_some() {
            let reason = self.scan_stop_reason.unwrap_or(IO_CEILING_REASON);
            return ChargeOutcome::Stopped {
                reason,
                terminal: self.latched_stop_is_terminal(reason),
            };
        }
        if !self.collection_checkpoint(bytes.div_ceil(32)) {
            return ChargeOutcome::Stopped {
                reason: COLLECTION_STOP_REASON,
                terminal: true,
            };
        }
        let allowance = self.io_allowance();
        if allowance == 0 {
            self.set_scan_stop(IO_CEILING_REASON);
            return ChargeOutcome::Stopped {
                reason: IO_CEILING_REASON,
                terminal: true,
            };
        }
        let left = self.remaining_window_io().unwrap_or(0);
        if bytes > left {
            self.set_scan_stop(IO_CEILING_REASON);
            return ChargeOutcome::Stopped {
                reason: IO_CEILING_REASON,
                terminal: false,
            };
        }
        self.record_io_inner(bytes as usize);
        ChargeOutcome::Admitted
    }

    fn record_io_inner(&mut self, bytes: usize) {
        self.pass_io_bytes = self.pass_io_bytes.saturating_add(bytes as u64);
        self.attempted_io_bytes = self.attempted_io_bytes.saturating_add(bytes as u64);
        if let Some(window) = self.active_window.as_mut() {
            window.io_bytes = window.io_bytes.saturating_add(bytes as u64);
        }
    }

    /// Records read bytes (delegated by the budget): the capture
    /// total, the per-pass allowance, and the window when active.
    pub(crate) fn record_io(&mut self, bytes: usize) {
        // Bound input/parse amplification as well as decoded work. Existing
        // I/O ceilings remain independent. Checks cannot interrupt a read.
        self.collection_checkpoint((bytes as u64).div_ceil(32));
        self.record_io_inner(bytes);
    }

    /// Window-only I/O debit (delegated by the budget): the
    /// demand-paged table walk and the bounded ELF snapshot reader.
    pub(crate) fn record_window_io(&mut self, bytes: usize) {
        self.collection_checkpoint(0);
        self.record_io_inner(bytes);
    }

    /// Window-only allowance for identity hashing (delegated by the
    /// budget): a partial digest is never trusted, so the per-object
    /// leg must not refuse a large provider the window still admits.
    pub(crate) fn allowed_capture_io(&mut self, wanted: usize) -> usize {
        if !self.collection_checkpoint(1) {
            return 0;
        }
        if matches!(self.policy, DiscoveryPolicy::Inventory(_)) && self.active_scan.is_none() {
            return 0;
        }
        let allowed = self
            .remaining_window_io()
            .unwrap_or(0)
            .try_into()
            .map_or(usize::MAX, |left| wanted.min(left));
        if allowed == 0 && wanted != 0 && matches!(self.policy, DiscoveryPolicy::Inventory(_)) {
            self.set_scan_stop(IO_CEILING_REASON);
        }
        allowed
    }

    /// Admits one decoded table's entries against the window
    /// allowance: admitted, skipped (no window/scan/stop), or refused
    /// (ceiling/overflow, trips the stop). The budget tallies its own
    /// disclosure counters from the verdict.
    pub(crate) fn admit_table_decode(&mut self, entries: usize) -> DecodeVerdict {
        if self.scan_stopped() {
            return DecodeVerdict::Skipped;
        }
        if self.active_scan.is_none() {
            return DecodeVerdict::Skipped;
        }
        let Some(window) = self.active_window.as_mut() else {
            return DecodeVerdict::Skipped;
        };
        let Some(tables) = window.decoded_tables.checked_add(1) else {
            self.set_scan_stop(TABLE_WINDOW_CEILING_REASON);
            return DecodeVerdict::Refused;
        };
        let Some(decoded_entries) = window.decoded_entries.checked_add(entries) else {
            self.set_scan_stop(TABLE_WINDOW_CEILING_REASON);
            return DecodeVerdict::Refused;
        };
        if tables > window.limits.decoded_tables || decoded_entries > window.limits.decoded_entries
        {
            self.set_scan_stop(TABLE_WINDOW_CEILING_REASON);
            return DecodeVerdict::Refused;
        }
        window.decoded_tables = tables;
        window.decoded_entries = decoded_entries;
        DecodeVerdict::Admitted
    }

    /// Admits one decoded interface record against the window
    /// allowance (same verdict split as tables).
    pub(crate) fn admit_interface_decode(&mut self) -> DecodeVerdict {
        if self.scan_stopped() {
            return DecodeVerdict::Skipped;
        }
        if self.active_scan.is_none() {
            return DecodeVerdict::Skipped;
        }
        let Some(window) = self.active_window.as_mut() else {
            return DecodeVerdict::Skipped;
        };
        let Some(next) = window.interfaces.checked_add(1) else {
            self.set_scan_stop(INTERFACE_WINDOW_CEILING_REASON);
            return DecodeVerdict::Refused;
        };
        if next > window.limits.interfaces {
            self.set_scan_stop(INTERFACE_WINDOW_CEILING_REASON);
            return DecodeVerdict::Refused;
        }
        window.interfaces = next;
        DecodeVerdict::Admitted
    }
}

/// What a window decode admission decided (the budget tallies its
/// disclosure counters from the verdict).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeVerdict {
    Admitted,
    Skipped,
    Refused,
}

impl ScanPassOwner {
    pub fn begin_window(&mut self, id: WindowId, deadline_ns: u64) -> Result<WindowToken, String> {
        let DiscoveryPolicy::Inventory(limits) = self.policy else {
            return Err("renewable discovery windows require Inventory policy".into());
        };
        self.begin_window_with_limits(id, limits.window, deadline_ns)
    }

    pub fn begin_window_with_limits(
        &mut self,
        id: WindowId,
        window_limits: InventoryWindowLimits,
        deadline_ns: u64,
    ) -> Result<WindowToken, String> {
        let DiscoveryPolicy::Inventory(limits) = self.policy else {
            return Err("renewable discovery windows require Inventory policy".into());
        };
        if self.active_window.is_some() || self.active_scan.is_some() {
            return Err("cannot renew discovery work while a window or scan is active".into());
        }
        if self.last_window.is_some_and(|last| id <= last) {
            return Err("inventory discovery window ID is stale or repeated".into());
        }
        if window_limits.io_bytes > limits.window.io_bytes
            || window_limits.work_units > limits.window.work_units
            || window_limits.decoded_tables > limits.window.decoded_tables
            || window_limits.decoded_entries > limits.window.decoded_entries
            || window_limits.interfaces > limits.window.interfaces
        {
            return Err("adaptive inventory window exceeds its immutable policy maximum".into());
        }
        let token = WindowToken {
            domain: Arc::clone(
                self.domain
                    .as_ref()
                    .expect("Inventory policy owns a budget domain"),
            ),
            id,
        };
        self.active_window = Some(ActiveInventoryWindow {
            token: token.clone(),
            limits: window_limits,
            deadline_ns,
            io_bytes: 0,
            work_units: 0,
            decoded_tables: 0,
            decoded_entries: 0,
            interfaces: 0,
            stop_reason: None,
        });
        self.last_window = Some(id);
        self.deadline_ns = None;
        self.scan_stop_reason = None;
        self.scan_stop_reported = false;
        Ok(token)
    }

    pub fn checkpoint(&mut self, token: WindowToken) -> Result<ScanCheckpoint, String> {
        self.validate_window_token(&token)?;
        if self.active_scan.is_some() {
            return Err("inventory discovery scan is already active".into());
        }
        let serial = self
            .next_scan_serial
            .checked_add(1)
            .ok_or_else(|| "inventory discovery scan serial exhausted".to_string())?;
        self.next_scan_serial = serial;
        let checkpoint = ScanCheckpoint { token, serial };
        self.active_scan = Some(checkpoint.clone());
        Ok(checkpoint)
    }

    pub fn finish_scan(&mut self, checkpoint: ScanCheckpoint) -> Result<(), String> {
        if self.active_scan.as_ref() != Some(&checkpoint) {
            return Err("inventory discovery scan checkpoint is stale or missing".into());
        }
        self.validate_window_token(&checkpoint.token)?;
        self.active_scan = None;
        Ok(())
    }

    pub fn finish_window(&mut self, token: WindowToken) -> Result<WindowReceipt, String> {
        self.validate_window_token(&token)?;
        if self.active_scan.is_some() {
            return Err("cannot finish an inventory discovery window during a scan".into());
        }
        let window = self
            .active_window
            .take()
            .expect("validated inventory window exists");
        self.deadline_ns = None;
        self.scan_stop_reason = None;
        self.scan_stop_reported = false;
        Ok(WindowReceipt {
            id: token.id,
            io_bytes: window.io_bytes,
            work_units: window.work_units,
            stop_reason: window.stop_reason,
        })
    }

    fn validate_window_token(&self, token: &WindowToken) -> Result<(), String> {
        match self.active_window.as_ref() {
            Some(window) if window.token == *token => Ok(()),
            Some(_) => Err("inventory discovery window token is stale".into()),
            None => Err("inventory discovery window token is missing".into()),
        }
    }

    pub(crate) fn inventory_limits(
        &self,
    ) -> Option<crate::discovery::scan::InventoryDiscoveryLimits> {
        match self.policy {
            DiscoveryPolicy::DetailedLegacy => None,
            DiscoveryPolicy::Inventory(limits) => Some(limits),
        }
    }

    pub(crate) fn may_mutate_retained_state(&self) -> bool {
        matches!(self.policy, DiscoveryPolicy::DetailedLegacy) || self.active_scan.is_some()
    }

    /// This owner's [`super::scan::MapsShadowBudget`], as it stands now.
    pub(crate) fn maps_shadow(&self) -> super::scan::MapsShadowBudget {
        let inventory = matches!(self.policy, DiscoveryPolicy::Inventory(_));
        let window_deadline = self.active_window.as_ref().map(|window| window.deadline_ns);
        let deadline = match (window_deadline, self.deadline_ns) {
            (Some(window), Some(transaction)) => Some(window.min(transaction)),
            (window, transaction) => window.or(transaction),
        };
        super::scan::MapsShadowBudget {
            inventory,
            no_active_scan: inventory && self.active_scan.is_none(),
            io_left: self.remaining_window_io().unwrap_or(0),
            deadline,
            has_deadline: self.has_deadline(),
            stop: self.scan_stop_reason,
            stop_reported: self.scan_stop_reported,
        }
    }

    /// What this owner has spent and whether it is stopped: the state
    /// a confirmation's decisions depend on (C7 A5).
    pub(crate) fn confirm_mark(&self) -> super::scan::ConfirmMark {
        super::scan::ConfirmMark {
            io_bytes: self.attempted_io_bytes,
            work_units: self.work_units,
            window: self
                .active_window
                .as_ref()
                .map(|window| (window.io_bytes, window.work_units)),
            stopped: self.scan_stop_reason.is_some(),
        }
    }

    /// The state a confirmation can change, for serial-vs-sharded equality.
    #[cfg(test)]
    pub(crate) fn confirm_state_for_test(&self) -> (super::scan::MapsSweepBudgetState, u64) {
        (self.maps_sweep_state_for_test(), self.work_units)
    }

    /// The state a maps sweep can change, for serial-vs-sharded equality.
    #[cfg(test)]
    pub(crate) fn maps_sweep_state_for_test(&self) -> super::scan::MapsSweepBudgetState {
        super::scan::MapsSweepBudgetState {
            attempted_io_bytes: self.attempted_io_bytes,
            stop: self.scan_stop_reason,
            stop_reported: self.scan_stop_reported,
            window: self
                .active_window
                .as_ref()
                .map(|window| (window.io_bytes, window.stop_reason)),
            window_exhaustions: self.window_exhaustions,
        }
    }

    pub(crate) fn allowed_io(&mut self, operation_bytes: u64, wanted: usize) -> usize {
        if !self.collection_checkpoint(1) {
            return 0;
        }
        if matches!(self.policy, DiscoveryPolicy::Inventory(_)) && self.active_scan.is_none() {
            return 0;
        }
        let operation_left = self.limits.per_object_bytes.saturating_sub(operation_bytes);
        let capture_left = self.remaining_window_io().unwrap_or(0);
        let allowed = wanted.min(
            operation_left
                .min(capture_left)
                .try_into()
                .unwrap_or(usize::MAX),
        );
        // Only a spent window stops the pass: a per-object shortfall
        // refuses its own object (named by `io_shortfall_reason`) while
        // the window still admits the rest of the scan.
        if capture_left == 0 && wanted != 0 && matches!(self.policy, DiscoveryPolicy::Inventory(_))
        {
            self.set_scan_stop(IO_CEILING_REASON);
        }
        allowed
    }

    /// The named gap for a zero allowance at this operation position:
    /// the per-object reason when only the per-object leg is spent,
    /// else the capture I/O ceiling. Agrees with `allowed_io`'s stop:
    /// the ceiling stops the pass, the per-object shortfall never does.
    pub(crate) fn io_shortfall_reason(&self, operation_bytes: u64) -> &'static str {
        let operation_left = self.limits.per_object_bytes.saturating_sub(operation_bytes);
        let capture_left = self.remaining_window_io().unwrap_or(0);
        if operation_left == 0 && capture_left > 0 {
            super::scan::PER_OBJECT_ALLOWANCE_REASON
        } else {
            IO_CEILING_REASON
        }
    }

    /// A metadata reader could not obtain its complete proof within the
    /// allowance returned by allowed_io. Keep the actual resource refusal
    /// distinct from a target read/identity error, preserving any earlier stop.
    pub(crate) fn note_io_refusal(&mut self) {
        self.set_scan_stop(IO_CEILING_REASON);
    }

    /// The capture's stop, sticky reason first and otherwise one clock poll:
    /// the single question every live admission asks before doing more work.
    pub(crate) fn stopped_now(&mut self) -> Option<&'static str> {
        if let Some(reason) = self.scan_stop_reason {
            return Some(reason);
        }
        self.check_deadline_now()
    }

    #[cfg(test)]
    pub(crate) fn deadline_for_test(&self) -> Option<u64> {
        self.deadline_ns
    }

    /// The deadline most recently installed (a `Some` passed to
    /// `set_deadline`); the end-of-batch `None` clear leaves it in
    /// place. Tests only.
    #[cfg(test)]
    pub(crate) fn installed_deadline_for_test(&self) -> Option<u64> {
        self.last_installed_deadline
    }

    /// The existing deadline, without renewing a window or hiding the
    /// absence of one. Callers retain the normal stop/clock checks.
    pub(crate) fn effective_deadline_ns(&self) -> Option<u64> {
        let window = self.active_window.as_ref().map(|window| window.deadline_ns);
        match (window, self.deadline_ns) {
            (Some(window), Some(transaction)) => Some(window.min(transaction)),
            (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
            (None, None) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BUDGET_STOP_DEMOTE_AFTER, ChargeOutcome, MemberOutcome, ScanPassOwner, demotion_gap_subject,
    };
    use crate::discovery::scan::{
        COLLECTION_STOP_REASON, CollectionWork, IO_CEILING_REASON, InventoryWindowLimits,
        SCAN_CLOCK_REASON, SCAN_DEADLINE_REASON, WORK_CEILING_REASON, WindowId,
    };

    fn detailed(work: u64, io: u64) -> ScanPassOwner {
        ScanPassOwner::detailed(work, io)
    }

    fn window_limits() -> InventoryWindowLimits {
        InventoryWindowLimits::new(1024, 100, 10, 100, 10).unwrap()
    }

    fn inventory_limits() -> crate::discovery::scan::InventoryDiscoveryLimits {
        crate::discovery::scan::InventoryDiscoveryLimits::new(
            64,
            window_limits(),
            crate::discovery::scan::InventoryRetainedLimits::new(10, 10, 10, 10, 10, 1024).unwrap(),
        )
        .unwrap()
    }

    fn refusing_collection() -> CollectionWork {
        CollectionWork::new(|_| false)
    }

    /// Owner 2 (admission refactor), renew/terminal table: every stop
    /// on every scope either renews next pass with cursor resume or
    /// stays terminal. Renewable stops (work/IO ceilings with
    /// headroom left, deadline, clock) renew at `end_pass` and the
    /// refused tail retries first; collection stops, zero caps and
    /// exhausted capture ceilings never admit. N/A cells are
    /// marked with their reason (a charge site only trips its own
    /// stop; Inventory windows reject a zero cap at construction).
    #[test]
    fn admission_owner2_pass_budget_renews_and_resumes() {
        // Detailed work × exhausted ceiling: the capture-lifetime
        // stop stays put (consumed work persists across passes); the
        // cursor is kept for the record.
        let mut pass = detailed(100, 1024);
        assert_eq!(pass.charge_work(100), ChargeOutcome::Admitted);
        assert_eq!(
            pass.charge_work(1),
            ChargeOutcome::Stopped {
                reason: WORK_CEILING_REASON,
                terminal: true,
            }
        );
        assert_eq!(pass.stopped_reason(), Some(WORK_CEILING_REASON));
        pass.cursor_mut().note_member_outcomes(&[
            ((1, Some(10)), MemberOutcome::Examined),
            ((2, Some(20)), MemberOutcome::Examined),
            ((3, Some(30)), MemberOutcome::CutShortBudgetStop),
            ((4, Some(40)), MemberOutcome::CutShortBudgetStop),
        ]);
        assert_eq!(pass.end_pass(), None);
        assert_eq!(pass.stopped_reason(), Some(WORK_CEILING_REASON));
        assert_eq!(
            pass.charge_work(1),
            ChargeOutcome::Stopped {
                reason: WORK_CEILING_REASON,
                terminal: true,
            },
            "an exhausted capture ceiling stays sticky"
        );
        assert_eq!(
            pass.cursor().order_members(&[
                (1, Some(10)),
                (2, Some(20)),
                (3, Some(30)),
                (4, Some(40)),
                (5, Some(50))
            ]),
            vec![5, 3, 4, 1, 2],
            "never-attempted first, then cut-short retries, then examined"
        );
        // Detailed work × partially consumed ceiling: the refused
        // charge was too big for the remainder, so the stop renews
        // and small charges still admit next pass.
        let mut pass = detailed(100, 1024);
        assert_eq!(pass.charge_work(90), ChargeOutcome::Admitted);
        assert_eq!(
            pass.charge_work(50),
            ChargeOutcome::Stopped {
                reason: WORK_CEILING_REASON,
                terminal: false,
            }
        );
        assert_eq!(pass.end_pass(), Some(WORK_CEILING_REASON));
        assert_eq!(pass.charge_work(5), ChargeOutcome::Admitted);
        assert_eq!(
            pass.charge_work(50),
            ChargeOutcome::Stopped {
                reason: WORK_CEILING_REASON,
                terminal: false,
            },
            "the remainder still refuses oversized charges"
        );
        // A reported stop renews silently: its row already published.
        let mut pass = detailed(100, 1024);
        assert_eq!(
            pass.charge_work(101),
            ChargeOutcome::Stopped {
                reason: WORK_CEILING_REASON,
                terminal: false,
            }
        );
        assert_eq!(pass.take_scan_stop_reason(), Some(WORK_CEILING_REASON));
        assert_eq!(pass.end_pass(), None);
        assert_eq!(pass.stopped_reason(), None);
        assert_eq!(pass.charge_work(1), ChargeOutcome::Admitted);

        // Detailed work × deadline: renews with a fresh (cleared) deadline.
        let mut pass = detailed(100, 1024);
        pass.set_deadline(Some(1000));
        assert_eq!(pass.check_deadline(Some(1001)), Some(SCAN_DEADLINE_REASON));
        assert_eq!(pass.end_pass(), Some(SCAN_DEADLINE_REASON));
        assert_eq!(pass.charge_work(1), ChargeOutcome::Admitted);

        // Detailed work × clock: an unreadable clock is transient.
        let mut pass = detailed(100, 1024);
        pass.set_deadline(Some(1000));
        assert_eq!(pass.check_deadline(None), Some(SCAN_CLOCK_REASON));
        assert_eq!(pass.end_pass(), Some(SCAN_CLOCK_REASON));
        assert_eq!(pass.charge_work(1), ChargeOutcome::Admitted);

        // Detailed work × collection stop: terminal, kept across passes.
        let mut pass = detailed(100, 1024);
        pass.set_collection_work(refusing_collection());
        assert_eq!(
            pass.charge_work(1),
            ChargeOutcome::Stopped {
                reason: COLLECTION_STOP_REASON,
                terminal: true,
            }
        );
        assert_eq!(pass.end_pass(), None);
        assert_eq!(pass.stopped_reason(), Some(COLLECTION_STOP_REASON));
        assert_eq!(
            pass.charge_work(1),
            ChargeOutcome::Stopped {
                reason: COLLECTION_STOP_REASON,
                terminal: true,
            },
            "a collection stop never heals"
        );

        // Detailed work × zero cap: terminal, never admits.
        let mut pass = detailed(0, 1024);
        assert_eq!(
            pass.charge_work(1),
            ChargeOutcome::Stopped {
                reason: WORK_CEILING_REASON,
                terminal: true,
            }
        );
        assert_eq!(pass.end_pass(), None);
        assert_eq!(pass.stopped_reason(), Some(WORK_CEILING_REASON));
        assert_eq!(
            pass.charge_work(1),
            ChargeOutcome::Stopped {
                reason: WORK_CEILING_REASON,
                terminal: true,
            },
            "a zero cap re-trips every pass without progress"
        );

        // Detailed work × I/O ceiling: N/A (work charging never trips
        // the I/O allowance; the I/O site owns that stop below).

        // Detailed I/O × I/O ceiling: renews.
        let mut pass = detailed(100, 64);
        assert_eq!(pass.charge_io(64), ChargeOutcome::Admitted);
        assert_eq!(
            pass.charge_io(1),
            ChargeOutcome::Stopped {
                reason: IO_CEILING_REASON,
                terminal: false,
            }
        );
        assert_eq!(pass.end_pass(), Some(IO_CEILING_REASON));
        assert_eq!(pass.charge_io(1), ChargeOutcome::Admitted);
        // The lifetime total keeps counting for headroom reporting.
        assert_eq!(pass.attempted_io_bytes(), 65);

        // Detailed I/O × collection stop: terminal.
        let mut pass = detailed(100, 64);
        pass.set_collection_work(refusing_collection());
        assert_eq!(
            pass.charge_io(1),
            ChargeOutcome::Stopped {
                reason: COLLECTION_STOP_REASON,
                terminal: true,
            }
        );
        assert_eq!(pass.end_pass(), None);

        // Detailed I/O × zero cap: terminal.
        let mut pass = detailed(100, 0);
        assert_eq!(
            pass.charge_io(1),
            ChargeOutcome::Stopped {
                reason: IO_CEILING_REASON,
                terminal: true,
            }
        );
        assert_eq!(pass.end_pass(), None);
        assert_eq!(pass.stopped_reason(), Some(IO_CEILING_REASON));

        // Detailed I/O × work/deadline/clock: N/A (the I/O allowance
        // never trips work or time stops).

        // Inventory window × work ceiling (control: windows already
        // renew; the owner preserves that behavior exactly).
        let mut pass = ScanPassOwner::inventory(inventory_limits());
        let window = pass
            .begin_window_with_limits(WindowId::new(1), window_limits(), 1000)
            .unwrap();
        let scan = pass.checkpoint(window.clone()).unwrap();
        for _ in 0..10 {
            assert_eq!(pass.charge_work(10), ChargeOutcome::Admitted);
        }
        assert_eq!(
            pass.charge_work(1),
            ChargeOutcome::Stopped {
                reason: WORK_CEILING_REASON,
                terminal: false,
            }
        );
        // End-of-pass with an active window is a no-op safeguard:
        // windows own their own renewal.
        assert_eq!(pass.end_pass(), None);
        assert_eq!(pass.stopped_reason(), Some(WORK_CEILING_REASON));
        pass.finish_scan(scan).unwrap();
        pass.finish_window(window).unwrap();
        let window = pass
            .begin_window_with_limits(WindowId::new(2), window_limits(), 2000)
            .unwrap();
        let scan = pass.checkpoint(window.clone()).unwrap();
        assert_eq!(pass.charge_work(1), ChargeOutcome::Admitted);
        pass.finish_scan(scan).unwrap();
        pass.finish_window(window).unwrap();

        // Inventory window × I/O ceiling (control, same shape).
        let mut pass = ScanPassOwner::inventory(inventory_limits());
        let window = pass
            .begin_window_with_limits(WindowId::new(1), window_limits(), 1000)
            .unwrap();
        let scan = pass.checkpoint(window.clone()).unwrap();
        assert_eq!(pass.charge_io(1024), ChargeOutcome::Admitted);
        assert_eq!(
            pass.charge_io(1),
            ChargeOutcome::Stopped {
                reason: IO_CEILING_REASON,
                terminal: false,
            }
        );
        pass.finish_scan(scan).unwrap();
        pass.finish_window(window).unwrap();
        let window = pass
            .begin_window_with_limits(WindowId::new(2), window_limits(), 2000)
            .unwrap();
        let scan = pass.checkpoint(window.clone()).unwrap();
        assert_eq!(pass.charge_io(1), ChargeOutcome::Admitted);
        pass.finish_scan(scan).unwrap();
        pass.finish_window(window).unwrap();

        // Inventory × zero cap: N/A (the window constructor rejects
        // a zero limit, so the shape is unrepresentable).
        assert!(InventoryWindowLimits::new(0, 100, 10, 100, 10).is_err());
        assert!(InventoryWindowLimits::new(1024, 0, 10, 100, 10).is_err());

        // Inventory × deadline/clock/collection: covered by
        // construction (the stop latch and renewal are shared with
        // the Detailed legs above; windows clear them at the same
        // boundaries as today).

        // Cgroup inventory × collection stop: the shared hook stops
        // terminally through the same owner.
        let mut pass = detailed(100, 1024);
        pass.set_collection_work(refusing_collection());
        assert_eq!(
            pass.charge_work(1),
            ChargeOutcome::Stopped {
                reason: COLLECTION_STOP_REASON,
                terminal: true,
            }
        );
        assert_eq!(pass.end_pass(), None);
        assert_eq!(
            pass.charge_io(1),
            ChargeOutcome::Stopped {
                reason: COLLECTION_STOP_REASON,
                terminal: true,
            },
            "the shared stop fences every scope it guards"
        );
    }

    /// Adopted bug-1 ordering twin, re-cut onto the cursor: under-cap
    /// members the last applied pass did not examine scan before
    /// re-scanned incumbents (ascending within each tier). Empty
    /// cursor stays plain ascending.
    #[test]
    fn owner2_cursor_orders_never_attempted_first() {
        let mut pass = detailed(u64::MAX, u64::MAX);
        pass.cursor_mut().note_member_outcomes(&[
            ((10, Some(1)), MemberOutcome::Examined),
            ((20, Some(2)), MemberOutcome::Examined),
        ]);
        assert_eq!(
            pass.cursor()
                .order_members(&[(30, None), (10, Some(1)), (40, None), (20, Some(2))]),
            vec![30, 40, 10, 20]
        );
        let fresh = detailed(u64::MAX, u64::MAX);
        assert_eq!(
            fresh.cursor().order_members(&[(30, None), (10, None)]),
            vec![10, 30]
        );
        assert_eq!(
            pass.cursor().order_members(&[(10, Some(1)), (20, Some(2))]),
            vec![10, 20]
        );
    }

    /// Adopted bug-1 cut-short twin, re-cut onto the cursor: a
    /// deep-scanned member whose own scan a truncating gap cut short
    /// stays fresh for a retry instead of joining examined memory. A
    /// gap-free scan still joins.
    #[test]
    fn owner2_cursor_keeps_cut_short_members_fresh_for_retry() {
        let mut pass = detailed(u64::MAX, u64::MAX);
        pass.cursor_mut().note_member_outcomes(&[
            ((11, Some(110)), MemberOutcome::CutShortBudgetStop),
            ((12, Some(120)), MemberOutcome::Examined),
        ]);
        assert_eq!(
            pass.cursor().examined_for_test(),
            [(12, Some(120))].into_iter().collect()
        );
        assert_eq!(
            pass.cursor()
                .order_members(&[(11, Some(110)), (12, Some(120)), (13, Some(130))]),
            vec![13, 11, 12],
            "the cut-short member retries right after the newcomer"
        );
    }

    /// Adopted bug-1 L3-2 twin, re-cut onto the cursor: a member cut
    /// short every pass keeps fresh retry priority for
    /// `BUDGET_STOP_DEMOTE_AFTER` passes, then scans after
    /// never-scanned members until one of its scans completes. It
    /// never joins examined memory while stuck.
    #[test]
    fn owner2_cursor_demotes_member_cut_short_every_pass_behind_newcomers() {
        let mut pass = detailed(u64::MAX, u64::MAX);
        let stuck = (11, None);
        for streak in 1..BUDGET_STOP_DEMOTE_AFTER {
            let demoted = pass
                .cursor_mut()
                .note_member_outcomes(&[(stuck, MemberOutcome::CutShortBudgetStop)]);
            assert!(demoted.is_empty(), "pass {streak} still retries first");
            assert!(
                !pass.cursor().examined_for_test().contains(&stuck),
                "pass {streak}: the retrying member still counts as fresh"
            );
        }
        let demoted = pass
            .cursor_mut()
            .note_member_outcomes(&[(stuck, MemberOutcome::CutShortBudgetStop)]);
        assert_eq!(
            demoted,
            vec![stuck],
            "past the bound the stuck member yields"
        );
        assert!(
            !pass.cursor().examined_for_test().contains(&stuck),
            "the demoted member never joins examined memory"
        );
        assert_eq!(
            pass.cursor().order_members(&[stuck, (12, None)]),
            vec![12, 11],
            "past the bound the stuck member scans after never-scanned pids"
        );
        // A gap-free scan completes it: the streak clears and the
        // member joins examined memory genuinely.
        pass.cursor_mut()
            .note_member_outcomes(&[(stuck, MemberOutcome::Examined)]);
        assert!(
            pass.cursor().streaks_for_test().is_empty(),
            "completing clears the streak"
        );
        assert!(pass.cursor().examined_for_test().contains(&stuck));
    }

    /// Adopted bug-1 demote-gap twin, re-cut onto the cursor: the
    /// stuck member yields exactly one bounded named gap — never a
    /// row per pass — and completing keeps the episode's history.
    #[test]
    fn owner2_cursor_demoted_member_files_one_bounded_gap_until_it_completes() {
        let mut pass = detailed(u64::MAX, u64::MAX);
        let stuck = (11, None);
        let mut crossings = 0;
        for _ in 0..BUDGET_STOP_DEMOTE_AFTER {
            crossings += pass
                .cursor_mut()
                .note_member_outcomes(&[(stuck, MemberOutcome::CutShortBudgetStop)])
                .len();
        }
        assert_eq!(crossings, 1, "one named gap for the stuck member");
        assert_eq!(
            demotion_gap_subject(),
            "member scan budget-stopped 3 passes without completing"
        );
        // Still stuck two passes later: no second row.
        for _ in 0..2 {
            crossings += pass
                .cursor_mut()
                .note_member_outcomes(&[(stuck, MemberOutcome::CutShortBudgetStop)])
                .len();
        }
        assert_eq!(crossings, 1, "no per-pass flood while stuck");
    }

    /// Adopted bug-1 streak-reuse twin, re-cut onto the cursor: pid
    /// reuse starts a fresh streak — a recycled pid never inherits
    /// the old incarnation's demotion.
    #[test]
    fn owner2_cursor_streak_restarts_on_pid_reuse() {
        let mut pass = detailed(u64::MAX, u64::MAX);
        for _ in 0..BUDGET_STOP_DEMOTE_AFTER {
            pass.cursor_mut()
                .note_member_outcomes(&[((11, Some(100)), MemberOutcome::CutShortBudgetStop)]);
        }
        assert_eq!(
            pass.cursor().order_members(&[(11, Some(100)), (12, None)]),
            vec![12, 11],
            "the old incarnation is demoted"
        );
        // The pid is recycled with a new start-time: fresh streak.
        let demoted = pass
            .cursor_mut()
            .note_member_outcomes(&[((11, Some(200)), MemberOutcome::CutShortBudgetStop)]);
        assert!(demoted.is_empty(), "the new incarnation starts unstuck");
        assert_eq!(
            pass.cursor().streaks_for_test().get(&(11, Some(200))),
            Some(&1),
            "the recycled pid accrues its own streak from one"
        );
        assert_eq!(
            pass.cursor().order_members(&[(11, Some(200)), (12, None)]),
            vec![12, 11],
            "the recycled pid retries after the newcomer, never demoted"
        );
    }

    /// Adopted bug-1 budget-only twin, re-cut onto the cursor: only a
    /// budget stop accrues toward demotion. Other truncations and
    /// unattempted members keep ordinary fresh retry priority without
    /// accruing.
    #[test]
    fn owner2_cursor_demotion_counts_only_budget_stops() {
        let mut pass = detailed(u64::MAX, u64::MAX);
        for _ in 0..BUDGET_STOP_DEMOTE_AFTER {
            let demoted = pass.cursor_mut().note_member_outcomes(&[
                ((21, Some(210)), MemberOutcome::CutShortOther),
                ((22, Some(220)), MemberOutcome::Unattempted),
            ]);
            assert!(demoted.is_empty(), "non-budget outcomes never accrue");
        }
        assert!(pass.cursor().streaks_for_test().is_empty());
        assert_eq!(
            pass.cursor()
                .order_members(&[(21, Some(210)), (22, Some(220)), (23, None)]),
            vec![23, 21, 22],
            "unaccrued members keep fresh retry priority"
        );
        // A budget stop does accrue.
        pass.cursor_mut()
            .note_member_outcomes(&[((21, Some(210)), MemberOutcome::CutShortBudgetStop)]);
        assert_eq!(
            pass.cursor().streaks_for_test().get(&(21, Some(210))),
            Some(&1)
        );
    }

    /// The demotion bound is exactly three: the adopted live-proof
    /// constant, shared by the cursor and the gap sentence.
    #[test]
    fn owner2_cursor_demotion_bound_is_three() {
        assert_eq!(BUDGET_STOP_DEMOTE_AFTER, 3);
        assert!(demotion_gap_subject().contains('3'));
    }
}
