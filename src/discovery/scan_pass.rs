//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! One per-pass budget owner for every scope and mode (admission owner 2).
//!
//! Every scope charges work and I/O through [`ScanPassOwner`], and every
//! pass boundary renews through [`ScanPassOwner::end_pass`]: per-pass
//! allowances, never a constant raise. A tripped nonzero work ceiling
//! renews with a counted exhaustion and the refused tail retries first
//! from the [`ResumeCursor`]; the Detailed I/O allowance renews
//! silently (trips surface via member rows) and whole-file hashing
//! carries its charged offset across passes; collection stops and
//! zero caps never admit. [`CaptureWorkBudget`](super::scan::CaptureWorkBudget)
//! keeps the retained caches, identity stores and disclosure tallies
//! and delegates every budget interaction here.

use super::scan::{
    ActiveInventoryWindow, BudgetDomain, COLLECTION_STOP_REASON, CollectionWork,
    DEFAULT_WORK_CEILING, DiscoveryPolicy, INTERFACE_WINDOW_CEILING_REASON, IO_CEILING_REASON,
    InspectedFileKey, InventoryWindowLimits, SCAN_CLOCK_REASON, SCAN_DEADLINE_REASON,
    ScanCheckpoint, ScanLimits, ScannedEntry, ScannedInterface, ScannedTable,
    TABLE_WINDOW_CEILING_REASON, WORK_CEILING_REASON, WindowId, WindowReceipt, WindowToken,
};
use p11scope_manifest::maps::{Device, MapEntry, ObjectKey};
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
        /// authority) and zero-capacity allowances (degenerate
        /// config). A tripped nonzero work allowance renews at
        /// `end_pass`; every other stop heals at its own boundary.
        terminal: bool,
    },
}

/// In-progress whole-file hashes the owner carries across passes:
/// past this many the stalest entry evicts (its file restarts).
pub(crate) const HASH_RESUME_CAP: usize = 64;

/// Budget-stop passes after which a never-completing member yields
/// to never-scanned newcomers (adopted live-proof bound).
pub(crate) const BUDGET_STOP_DEMOTE_AFTER: u32 = 3;

/// The bounded named gap subject a newly demoted member files once
/// per stuck episode (adopted vocabulary: one phenomenon, one row).
pub(crate) fn demotion_gap_subject() -> String {
    format!("member scan budget-stopped {BUDGET_STOP_DEMOTE_AFTER} passes without completing")
}

/// Cap on retained per-object decode cursors, shared by every scope.
/// Cursors are small (a mapping fingerprint plus the tables decoded so
/// far); 8192 matches the retained table-key scale and bounds churn.
/// Reclamation evicts the oldest *completed* cursor first; an unfinished
/// cursor is never evicted (evicting one would stall its object's
/// guaranteed progress — a refused insertion falls back to a fresh scan
/// instead, which is never worse than no cursor at all).
pub(crate) const MAX_DECODE_CURSORS: usize = 8192;

/// Subject of the named in-progress gap: the per-pass view shows it
/// while objects are unfinished. Transient view state, never accumulated
/// history — a converged run shows none, and a run stopped early shows
/// the live one at render time instead of an `exhausted` final state.
pub(crate) const SCAN_IN_PROGRESS_SUBJECT: &str = "scan_in_progress";

/// Render the in-progress reason: `done` of `total` cursor-known objects
/// finished, `tables` tables decoded so far. `total` counts objects the
/// scan has reached at least once; it grows as new objects are first
/// reached, so only `done` is monotonic.
pub(crate) fn scan_in_progress_reason(done: usize, total: usize, tables: usize) -> String {
    format!(
        "scan in progress: {done} of {total} objects finished ({tables} tables decoded so far); \
         the next pass resumes where this one stopped"
    )
}

/// Identity of one resumable object decode: the target process (pid plus
/// start time, defeating pid reuse; plus the executable image read at
/// scan time, defeating in-place exec, which keeps both) and the
/// opened file's identity and pin (defeating file replacement; the
/// held fd's device defeats Btrfs subvolume aliasing, like
/// [`InspectedFileKey`]). The memory the cursor was recorded from
/// belongs to exactly this process image and this file pin; anything
/// else misses and scans fresh. `None` when the image was unreadable
/// (no worse than the pre-exec check: pid plus start time still bind
/// the task).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DecodeCursorKey {
    pub(crate) pid: u32,
    pub(crate) start_time: u64,
    pub(crate) file: InspectedFileKey,
    pub(crate) exec: Option<Vec<u8>>,
}

/// One data mapping's snapshot identity within a cursor fingerprint, in
/// scan order: mapping bounds, file offset and permissions. Resume
/// re-reads only mappings at or after the frontier and only when the
/// fingerprint matches exactly; a remap, repermission or layout change
/// misses and scans fresh. Mapping *contents* are not fingerprinted: a
/// runtime mutation of file-backed data after the cursor completed is
/// the documented staleness bound (same class as the long-standing
/// cross-pass export-fact cache; runtime-built tables outside file-backed
/// data were already out of the memory scan's reach).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct MappingFingerprintEntry {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) file_offset: u64,
    pub(crate) permissions: [u8; 4],
}

/// One sweep's frontier within an object: snapshots before `snapshot`
/// are fully swept, snapshot `snapshot` is swept up to `word` (in words,
/// not bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SweepFrontier {
    pub(crate) snapshot: usize,
    pub(crate) word: u64,
}

/// Committed per-cursor progress for the snapshot resume decision: the
/// layout the frontiers were recorded under, both sweep frontiers, the
/// decoded-table count and completion. Same cursor key plus same layout
/// is the same work; anything else is churn, never progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CommittedCursorProgress {
    /// Hash of the cursor's mapping fingerprint: the layout this
    /// progress was recorded under. A remap changes it, so frontiers
    /// from a shifted layout never compare as advance.
    pub(crate) layout: u64,
    /// Table-sweep frontier.
    pub(crate) tables: SweepFrontier,
    /// Interface-sweep frontier.
    pub(crate) interfaces: SweepFrontier,
    /// Cached tables decoded so far.
    pub(crate) tables_decoded: usize,
    /// Both sweeps finished.
    pub(crate) complete: bool,
}

impl CommittedCursorProgress {
    /// Summarize one carried cursor's committed progress.
    pub(crate) fn of(cursor: &DecodeCursor) -> Self {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        cursor.fingerprint.hash(&mut hasher);
        Self {
            layout: hasher.finish(),
            tables: cursor.tables,
            interfaces: cursor.interfaces,
            tables_decoded: cursor.cached_tables.len(),
            complete: cursor.complete,
        }
    }

    /// Lexicographic sweep position: table snapshot and word, then
    /// interface snapshot and word. A strict increase on the same
    /// cursor and layout is intra-object progress.
    pub(crate) fn sweep_position(&self) -> (usize, u64, usize, u64) {
        (
            self.tables.snapshot,
            self.tables.word,
            self.interfaces.snapshot,
            self.interfaces.word,
        )
    }
}

/// Resumable decode progress for one object: how far the table and
/// interface sweeps reached, the tables and interfaces decoded so far
/// (re-emitted while the object validates unchanged), and the export
/// anchor map the table sweep's prologue already paid for (so a resumed
/// sweep skips the prologue's charges).
#[derive(Debug, Clone)]
pub(crate) struct DecodeCursor {
    /// Data mappings fingerprinted when progress was recorded, in scan
    /// order; snapshot indices below count into this list.
    pub(crate) fingerprint: Vec<MappingFingerprintEntry>,
    /// Table-sweep frontier.
    pub(crate) tables: SweepFrontier,
    /// Interface-sweep frontier.
    pub(crate) interfaces: SweepFrontier,
    /// Export anchor map (`address -> ordinals`) from the last prologue
    /// that ran for the frontier snapshot; `None` re-runs it.
    pub(crate) anchors: Option<BTreeMap<u64, Vec<usize>>>,
    /// Tables decoded on earlier passes, re-emitted while the object
    /// validates unchanged so every pass's view stays complete.
    pub(crate) cached_tables: Vec<ScannedTable>,
    /// Interfaces decoded on earlier passes, re-emitted like the tables.
    pub(crate) cached_interfaces: Vec<ScannedInterface>,
    /// Interface-triple addresses examined against a partial table set:
    /// hints, not evidence. A later pass re-reads each triple from
    /// current memory and links it only against its own final tables;
    /// cleared on completion (final tables never match it) and on any
    /// identity mismatch. Carrying addresses (not decodes) keeps the
    /// link step a bounded re-read instead of a prefix re-scan.
    pub(crate) unlinked: Vec<u64>,
    /// Mappings the cached rows depend on beyond the fingerprinted data
    /// mappings (decoded function targets, often in other objects):
    /// every entry must still resolve to the identical mapping before
    /// the cached rows replay or resume, and the bracket re-validates
    /// them against its own closing snapshot every pass.
    pub(crate) targets: Vec<MapEntry>,
    /// Both sweeps finished: the object is fully decoded and costs ~zero
    /// work on later passes (validation only) until it changes.
    pub(crate) complete: bool,
    /// Mappings and dependencies proven by a bracket that ran: rows
    /// staged after a bracket that never ran (budget-starved before
    /// validating) ride unvalidated and must re-prove their bytes and
    /// re-collect their targets on next use, never replay directly.
    /// Complete implies validated.
    pub(crate) validated: bool,
    /// Creation order: passes scan unfinished cursors oldest-first.
    pub(crate) seq: u64,
}

/// Accounted bytes of one decode cursor: the key and struct shells plus
/// the fingerprint, the cached tables and interfaces (entries included),
/// and the anchor map. Payload bytes only, like the sibling file-fact
/// counters — never allocator overhead.
pub(crate) fn decode_cursor_bytes(key: &DecodeCursorKey, cursor: &DecodeCursor) -> u64 {
    let tables = cursor.cached_tables.iter().fold(0usize, |bytes, table| {
        bytes
            .saturating_add(std::mem::size_of_val(table))
            .saturating_add(
                table
                    .entries
                    .len()
                    .saturating_mul(std::mem::size_of::<ScannedEntry>()),
            )
            .saturating_add(table.entries.iter().fold(0usize, |names, entry| {
                names.saturating_add(entry.object_path.len())
            }))
            .saturating_add(table.unpinned.iter().fold(0usize, |skips, skip| {
                skips
                    .saturating_add(std::mem::size_of_val(skip))
                    .saturating_add(skip.subject.len())
                    .saturating_add(skip.reason.len())
            }))
    });
    let interfaces = cursor
        .cached_interfaces
        .iter()
        .fold(0usize, |bytes, iface| {
            bytes
                .saturating_add(std::mem::size_of_val(iface))
                .saturating_add(iface.name_lossy.as_ref().map_or(0, String::len))
                .saturating_add(iface.name_private.as_ref().map_or(0, Vec::len))
        });
    let anchors = cursor.anchors.as_ref().map_or(0, |anchors| {
        anchors.iter().fold(0usize, |bytes, (_, ordinals)| {
            bytes
                .saturating_add(std::mem::size_of::<u64>())
                .saturating_add(ordinals.len().saturating_mul(std::mem::size_of::<usize>()))
        })
    });
    let targets = cursor.targets.iter().fold(0usize, |bytes, target| {
        bytes
            .saturating_add(std::mem::size_of_val(target))
            .saturating_add(target.raw_path.as_ref().map_or(0, Vec::len))
    });
    let exec = key.exec.as_ref().map_or(0, Vec::len);
    let unlinked = cursor
        .unlinked
        .len()
        .saturating_mul(std::mem::size_of::<u64>());
    u64::try_from(
        std::mem::size_of_val(key)
            .saturating_add(std::mem::size_of_val(cursor))
            .saturating_add(unlinked)
            .saturating_add(
                cursor
                    .fingerprint
                    .len()
                    .saturating_mul(std::mem::size_of::<MappingFingerprintEntry>()),
            )
            .saturating_add(tables)
            .saturating_add(interfaces)
            .saturating_add(anchors)
            .saturating_add(targets)
            .saturating_add(exec),
    )
    .unwrap_or(u64::MAX)
}

/// Sweep start words for a resumed snapshot: the word to arm the
/// sweep at (snapshot-relative) plus the mapping-relative word the
/// swept count accumulates from. The sweep restarts at the proven
/// boundary — the frontier minus one maximum-table span — clamped
/// into the re-read bytes: candidates the earlier pass never proved
/// (a header at word zero after a saturated overlap, a split anchor
/// tail) are re-examined, while long-proven words are never
/// re-swept, so tight recurring budgets still advance instead of
/// re-walking the prefix every pass. The re-swept span costs at most
/// one maximum-table overlap of charges per resumed snapshot.
pub(crate) fn sweep_resume_words(
    frontier_word: u64,
    read_start: usize,
    width: usize,
    overlap_words: u64,
) -> (u64, u64) {
    let read_word = (read_start / width) as u64;
    let proven = frontier_word.saturating_sub(overlap_words);
    let start = read_word.max(proven);
    let resume = start.saturating_sub(read_word);
    (resume, start)
}

/// Whether `device`/`inode` is the file half of `key` (ordering-only
/// match: ordering is advisory, use re-validates the full key plus the
/// pin and fingerprint).
pub(crate) fn cursor_key_matches_object(
    key: &DecodeCursorKey,
    pid: u32,
    start_time: u64,
    device: Device,
    inode: u64,
) -> bool {
    key.pid == pid
        && key.start_time == start_time
        && key.file.device == device
        && key.file.inode == inode
}

/// Resumable per-object decode state: the cursor store plus the
/// per-pass probe cache. The shared retained-byte accounting stays on
/// the budget (one ceiling across file facts and cursors); the owner
/// takes it as a parameter wherever admission or eviction moves it.
#[derive(Debug, Clone, Default)]
pub(crate) struct DecodeResume {
    cursors: BTreeMap<DecodeCursorKey, DecodeCursor>,
    liveness: BTreeMap<(u32, u64), bool>,
    /// Process-liveness probes performed for reclamation. Tests only.
    #[cfg(test)]
    probes: u64,
    /// Whether this pass records decode cursors (armed by installing a
    /// carried bundle: multi-pass inventory collectors only).
    resume_armed: bool,
    table_resume: SweepResume,
    iface_resume: SweepResume,
    /// Interface-triple addresses the sweep examined while their target
    /// table was still unknown: hints the link step re-reads from
    /// current memory once tables are final. Drained into staging per
    /// object; only armed scans record.
    unlinked_triples: Vec<u64>,
}

/// Transient per-call sweep resume: the word to start at plus the cached
/// export anchors (table sweep only), taken at call entry; the words
/// swept plus whether the sweep finished, reported at every exit. Fully
/// examined words only: every early break excludes its current word, so
/// a resume re-examines exactly the words no pass finished. Completion
/// is loop exit, never word arithmetic: the interface sweep examines
/// triple starts (stride 3), so its swept words never equal the snapshot
/// length even when finished.
#[derive(Debug, Clone, Default)]
struct SweepResume {
    start_word: u64,
    swept_words: u64,
    swept_completed: bool,
    anchors: Option<BTreeMap<u64, Vec<usize>>>,
    anchors_out: Option<BTreeMap<u64, Vec<usize>>>,
}

/// What the next pass continues: member tiers plus budget-stop
/// streaks plus per-member own-spend totals. Never-attempted members
/// scan first, then cut-short retries, then demoted members past
/// [`BUDGET_STOP_DEMOTE_AFTER`], then examined members; within each
/// tier the least-spent member scans first, so a refused prefix that
/// already spent its turns cannot camp at the head ahead of a deferred
/// tail. Streaks and spend key by task generation, so pid reuse starts
/// fresh; pruning retains enumerated tasks only.
#[derive(Debug, Clone, Default)]
pub(crate) struct ResumeCursor {
    examined: BTreeSet<MemberTask>,
    fresh: BTreeSet<MemberTask>,
    streaks: BTreeMap<MemberTask, u32>,
    own_spend: BTreeMap<MemberTask, u64>,
}

impl ResumeCursor {
    /// Records one applied pass's member outcomes plus each member's
    /// own work spent this pass, and returns the tasks newly demoted
    /// this pass — the driver files one [`demotion_gap_subject`] row per
    /// task, never a row per pass. Discarded passes record nothing.
    /// Noting a task with a proven generation supersedes other
    /// generations of the same pid, so pid reuse never inherits a tier,
    /// streak or spend total; call [`ResumeCursor::prune_to_live`] with
    /// the pass enumeration to drop departed pids. Unattempted members
    /// (deferred before work, never selected, exited) stay
    /// never-attempted — ahead of retried members — so a deferred tail
    /// retries before a retried prefix.
    pub(crate) fn note_member_outcomes(
        &mut self,
        outcomes: &[(MemberTask, MemberOutcome, u64)],
    ) -> Vec<MemberTask> {
        let mut newly_demoted = Vec::new();
        for (task, outcome, own_work) in outcomes {
            if task.1.is_some() {
                let superseded = |held: &MemberTask| held.0 == task.0 && held.1 != task.1;
                self.examined.retain(|held| !superseded(held));
                self.fresh.retain(|held| !superseded(held));
                self.streaks.retain(|held, _| !superseded(held));
                self.own_spend.retain(|held, _| !superseded(held));
            }
            self.own_spend
                .entry(*task)
                .and_modify(|total| *total = total.saturating_add(*own_work))
                .or_insert(*own_work);
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
                MemberOutcome::CutShortOther => {
                    self.examined.remove(task);
                    if self
                        .streaks
                        .get(task)
                        .is_none_or(|streak| *streak < BUDGET_STOP_DEMOTE_AFTER)
                    {
                        self.fresh.insert(*task);
                    }
                }
                MemberOutcome::Unattempted => {
                    // Stays never-attempted: out of every tier, so the
                    // next pass retries it before any retried member.
                    self.examined.remove(task);
                    self.fresh.remove(task);
                }
            }
        }
        newly_demoted
    }

    /// Orders tasks for this pass: never-attempted first, then
    /// cut-short retries, then demoted members, then examined ones;
    /// within each tier the least-spent member scans first (pid breaks
    /// ties), so a refused prefix cannot camp at the head. Unknown tasks
    /// read never-attempted: work fails toward retry, never toward stall.
    #[cfg(test)]
    pub(crate) fn order_members(&self, tasks: &[MemberTask]) -> Vec<u32> {
        let mut never = Vec::new();
        let mut retry = Vec::new();
        let mut demoted = Vec::new();
        let mut examined = Vec::new();
        for task in tasks {
            let spend = self.own_spend.get(task).copied().unwrap_or(0);
            if self.examined.contains(task) {
                examined.push((spend, task.0));
            } else if self
                .streaks
                .get(task)
                .is_some_and(|streak| *streak >= BUDGET_STOP_DEMOTE_AFTER)
            {
                demoted.push((spend, task.0));
            } else if self.fresh.contains(task) || self.streaks.contains_key(task) {
                retry.push((spend, task.0));
            } else {
                never.push((spend, task.0));
            }
        }
        never.sort_unstable();
        retry.sort_unstable();
        demoted.sort_unstable();
        examined.sort_unstable();
        never
            .into_iter()
            .map(|(_, pid)| pid)
            .chain(retry.into_iter().map(|(_, pid)| pid))
            .chain(demoted.into_iter().map(|(_, pid)| pid))
            .chain(examined.into_iter().map(|(_, pid)| pid))
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

    /// Per-member own-spend totals, for tests.
    #[cfg(test)]
    pub(crate) fn own_spend_for_test(&self) -> BTreeMap<MemberTask, u64> {
        self.own_spend.clone()
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
        self.own_spend.retain(|task, _| live_pids.contains(&task.0));
    }

    /// Projects the tiers to pid sets for selection: recorded tasks
    /// whose live start-time still matches, plus tasks recorded
    /// without a start-time (nothing verifiable, so nothing dropped).
    /// A recycled pid reads fresh, so reuse never inherits the old
    /// incarnation's slot. Never-attempted is the complement (any pid
    /// in no set); unknown work fails toward retry, never toward stall.
    /// Spend projects alongside the tiers, so under-cap selection orders
    /// each tier least-spent first.
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
        for (task, _) in self
            .streaks
            .iter()
            .filter(|(task, _)| live(task))
            .filter(|(_, streak)| **streak >= BUDGET_STOP_DEMOTE_AFTER)
        {
            tiers.demoted.insert(task.0);
        }
        for (task, spend) in self.own_spend.iter().filter(|(task, _)| live(task)) {
            tiers
                .spend
                .entry(task.0)
                .and_modify(|total| *total = total.saturating_add(*spend))
                .or_insert(*spend);
        }
        tiers
    }
}

/// The cursor's tiers projected to pids for one selection pass.
/// Never-attempted members are any pid in no set. Spend maps pid to
/// cumulative own work, so under-cap selection orders each tier
/// least-spent first; pids absent from the map spent nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MemberTiers {
    pub(crate) examined: BTreeSet<u32>,
    pub(crate) retry: BTreeSet<u32>,
    pub(crate) demoted: BTreeSet<u32>,
    pub(crate) spend: BTreeMap<u32, u64>,
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
    /// ones; within each tier the least-spent member scans first (pid
    /// breaks ties), so a refused prefix cannot camp at the head.
    pub(crate) fn order_under_cap(&self, pids: &[u32]) -> Vec<u32> {
        let mut never = Vec::new();
        let mut retry = Vec::new();
        let mut demoted = Vec::new();
        let mut examined = Vec::new();
        for pid in pids {
            let spend = self.spend.get(pid).copied().unwrap_or(0);
            if self.examined.contains(pid) {
                examined.push((spend, *pid));
            } else if self.demoted.contains(pid) {
                demoted.push((spend, *pid));
            } else if self.retry.contains(pid) {
                retry.push((spend, *pid));
            } else {
                never.push((spend, *pid));
            }
        }
        never.sort_unstable();
        retry.sort_unstable();
        demoted.sort_unstable();
        examined.sort_unstable();
        never
            .into_iter()
            .map(|(_, pid)| pid)
            .chain(retry.into_iter().map(|(_, pid)| pid))
            .chain(demoted.into_iter().map(|(_, pid)| pid))
            .chain(examined.into_iter().map(|(_, pid)| pid))
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
    interval_exhaustions: u64,
    deadline_ns: Option<u64>,
    #[cfg(test)]
    last_installed_deadline: Option<u64>,
    scan_stop_reason: Option<&'static str>,
    scan_stop_reported: bool,
    cursor: ResumeCursor,
    hash_resume: BTreeMap<InspectedFileKey, (u64, u64)>,
    hash_resume_seq: u64,
    decode: DecodeResume,
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
            interval_exhaustions: 0,
            deadline_ns: None,
            #[cfg(test)]
            last_installed_deadline: None,
            scan_stop_reason: None,
            scan_stop_reported: false,
            cursor: ResumeCursor::default(),
            hash_resume: BTreeMap::new(),
            hash_resume_seq: 0,
            decode: DecodeResume::default(),
        }
    }

    /// A Detailed owner with a work ceiling and I/O allowances.
    #[cfg(test)]
    pub(crate) fn detailed(work_ceiling: u64, io_bytes: u64) -> Self {
        Self::from_limits(ScanLimits {
            per_object_bytes: io_bytes,
            total_bytes: io_bytes,
        })
        .with_work_ceiling(work_ceiling)
    }

    #[cfg(test)]
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
            interval_exhaustions: 0,
            deadline_ns: None,
            #[cfg(test)]
            last_installed_deadline: None,
            scan_stop_reason: None,
            scan_stop_reported: false,
            cursor: ResumeCursor::default(),
            hash_resume: BTreeMap::new(),
            hash_resume_seq: 0,
            decode: DecodeResume::default(),
        }
    }

    /// Take every decode cursor for the carried bundle, leaving none.
    /// The shared byte counter moves with the budget's own take.
    pub(crate) fn take_decode_cursors(&mut self) -> BTreeMap<DecodeCursorKey, DecodeCursor> {
        std::mem::take(&mut self.decode.cursors)
    }

    /// Install carried decode cursors into a fresh pass, arming resume:
    /// the collector that installs is a multi-pass inventory pass, so
    /// progress it makes this pass must carry a cursor for the next one.
    pub(crate) fn install_decode_cursors(
        &mut self,
        cursors: BTreeMap<DecodeCursorKey, DecodeCursor>,
    ) {
        self.decode.cursors = cursors;
        self.decode.resume_armed = true;
    }

    /// Look up this object's installed decode cursor. The caller
    /// re-validates the process generation, file pin and mapping
    /// fingerprint before trusting it.
    pub(crate) fn decode_cursor(&self, key: &DecodeCursorKey) -> Option<&DecodeCursor> {
        self.decode.cursors.get(key)
    }

    /// Whether `pid`/`start_time` still names a live process generation.
    /// Dead or recycled pids sort their cursors as reclaimable: an
    /// unfinished cursor for a dead pid can never resume, so keeping it
    /// ahead of live work would stall churn under cap pressure.
    fn decode_cursor_pid_live(&mut self, pid: u32, start_time: u64) -> bool {
        #[cfg(test)]
        {
            self.decode.probes = self.decode.probes.saturating_add(1);
        }
        crate::process::process_start_time(pid).is_ok_and(|live| live == start_time)
    }

    /// Test-only: process-liveness probes performed for decode-cursor
    /// reclamation on this owner.
    #[cfg(test)]
    pub(crate) fn decode_liveness_probes(&self) -> u64 {
        self.decode.probes
    }

    /// Whether `pid`/`start_time` still names a live process generation,
    /// cached per distinct generation for this pass: repeated
    /// reclamation over the same cursor set probes each generation once.
    /// Each uncached probe charges one collection-work unit and polls
    /// the pass stop first, so reclamation stays bounded and
    /// cancellable; `None` refuses the reclamation (and keeps the old
    /// cursor).
    fn decode_generation_live_cached(&mut self, pid: u32, start_time: u64) -> Option<bool> {
        if let Some(&live) = self.decode.liveness.get(&(pid, start_time)) {
            return Some(live);
        }
        if self.stopped_now().is_some() {
            return None;
        }
        if !self.collection_checkpoint(1) {
            return None;
        }
        let live = self.decode_cursor_pid_live(pid, start_time);
        self.decode.liveness.insert((pid, start_time), live);
        Some(live)
    }

    /// Cached liveness for victim selection: missing entries sort live
    /// (never evict on missing proof).
    fn decode_cached_live(&self, pid: u32, start_time: u64) -> bool {
        self.decode
            .liveness
            .get(&(pid, start_time))
            .copied()
            .unwrap_or(true)
    }

    /// Record (or advance) one object's decode cursor, bounded by the
    /// shared cursor cap and the retained byte ceiling. `retained` is
    /// the budget's shared counter (file facts plus cursors); `limit`
    /// is its ceiling. Inserts and updates that already fit perform zero
    /// process-liveness probes; reclamation under pressure evicts dead
    /// generations first, then the oldest completed cursor, and never a
    /// live unfinished one (its progress is guaranteed). A refusal keeps
    /// the old cursor, so the next pass re-scans fresh — never worse
    /// than no cursor at all. Returns whether stored.
    pub(crate) fn record_decode_cursor(
        &mut self,
        key: DecodeCursorKey,
        cursor: DecodeCursor,
        retained: &mut u64,
        limit: u64,
    ) -> bool {
        if !self.decode.resume_armed {
            return false;
        }
        let bytes = decode_cursor_bytes(&key, &cursor);
        if bytes > limit {
            return false;
        }
        let old_bytes = self
            .decode
            .cursors
            .get(&key)
            .map(|old| decode_cursor_bytes(&key, old));
        // Fit first: an insert or update that already fits performs zero
        // process-liveness probes — no census ahead of the fit check.
        let fits_now = (old_bytes.is_some() || self.decode.cursors.len() < MAX_DECODE_CURSORS)
            && retained
                .saturating_sub(old_bytes.unwrap_or(0))
                .saturating_add(bytes)
                <= limit;
        if fits_now {
            *retained = retained
                .saturating_sub(old_bytes.unwrap_or(0))
                .saturating_add(bytes);
            self.decode.cursors.insert(key, cursor);
            return true;
        }
        // Pressure: prove admission with one cached liveness probe per
        // distinct generation (a stop or spent shared work refuses and
        // keeps the old cursor).
        let generations: BTreeSet<(u32, u64)> = self
            .decode
            .cursors
            .keys()
            .filter(|candidate| *candidate != &key)
            .map(|candidate| (candidate.pid, candidate.start_time))
            .collect();
        for (pid, start_time) in generations {
            if self
                .decode_generation_live_cached(pid, start_time)
                .is_none()
            {
                return false;
            }
        }
        // Reclaimable without touching a live unfinished cursor or this
        // key: dead generations plus completed cursors, selected from
        // the cached probe results without repeating process I/O.
        let reclaimable: Vec<DecodeCursorKey> = self
            .decode
            .cursors
            .iter()
            .filter(|(candidate, cursor)| {
                *candidate != &key
                    && (cursor.complete
                        || !self.decode_cached_live(candidate.pid, candidate.start_time))
            })
            .map(|(candidate, _)| candidate.clone())
            .collect();
        let reclaimable_bytes = reclaimable.iter().fold(0u64, |bytes, candidate| {
            bytes.saturating_add(
                self.decode
                    .cursors
                    .get(candidate)
                    .map(|old| decode_cursor_bytes(candidate, old))
                    .unwrap_or(0),
            )
        });
        let entries_after = self
            .decode
            .cursors
            .len()
            .saturating_sub(reclaimable.len())
            .saturating_add(usize::from(old_bytes.is_none()));
        let bytes_after = retained
            .saturating_sub(reclaimable_bytes)
            .saturating_sub(old_bytes.unwrap_or(0))
            .saturating_add(bytes);
        // Prove admission before evicting anything: a refusal never
        // destroys a carried cursor for nothing.
        if entries_after > MAX_DECODE_CURSORS || bytes_after > limit {
            return false;
        }
        let fits = |cursors: &BTreeMap<DecodeCursorKey, DecodeCursor>, held: u64| {
            (old_bytes.is_some() || cursors.len() < MAX_DECODE_CURSORS)
                && held
                    .saturating_sub(old_bytes.unwrap_or(0))
                    .saturating_add(bytes)
                    <= limit
        };
        while !fits(&self.decode.cursors, *retained) {
            // Dead generations first, then oldest completed; live
            // unfinished cursors never qualify (filtered above). Victim
            // selection reuses the cached probe results above: no
            // repeated process I/O per victim search.
            let victim = self
                .decode
                .cursors
                .iter()
                .filter(|(candidate, cursor)| {
                    *candidate != &key
                        && (cursor.complete
                            || !self.decode_cached_live(candidate.pid, candidate.start_time))
                })
                .min_by_key(|(candidate, cursor)| {
                    (
                        self.decode_cached_live(candidate.pid, candidate.start_time),
                        cursor.complete,
                        cursor.seq,
                    )
                })
                .map(|(candidate, _)| candidate.clone());
            let Some(victim) = victim else {
                return false;
            };
            if let Some(old) = self.decode.cursors.remove(&victim) {
                *retained = retained.saturating_sub(decode_cursor_bytes(&victim, &old));
            }
        }
        *retained = retained
            .saturating_sub(old_bytes.unwrap_or(0))
            .saturating_add(bytes);
        self.decode.cursors.insert(key, cursor);
        true
    }

    /// Whether this pass records decode cursors (armed by installing a
    /// carried bundle: multi-pass inventory collectors only).
    pub(crate) fn resume_armed(&self) -> bool {
        self.decode.resume_armed
    }

    /// Next decode-cursor sequence number: one past the installed
    /// maximum, monotonic across passes (creation order is the
    /// oldest-first scan order).
    pub(crate) fn decode_cursors_seq_next(&self) -> u64 {
        self.decode
            .cursors
            .values()
            .map(|cursor| cursor.seq)
            .max()
            .map_or(0, |max| max.saturating_add(1))
    }

    /// Drop every cursor for `pid` whatever generation or object it
    /// names: a proven generation loss or death retires the whole
    /// pid, so the next pass re-scans fresh instead of replaying a
    /// dead generation. `retained` is the budget's shared counter.
    pub(crate) fn drop_decode_cursors_for_pid(&mut self, pid: u32, retained: &mut u64) {
        let stale: Vec<DecodeCursorKey> = self
            .decode
            .cursors
            .keys()
            .filter(|key| key.pid == pid)
            .cloned()
            .collect();
        for key in stale {
            if let Some(old) = self.decode.cursors.remove(&key) {
                *retained = retained.saturating_sub(decode_cursor_bytes(&key, &old));
            }
        }
    }

    /// Drop `pid`'s cursors for older generations: the view's pinned
    /// start time proves the pid was reused, so only the live
    /// generation's cursors may resume.
    pub(crate) fn drop_superseded_decode_cursors(
        &mut self,
        pid: u32,
        start_time: u64,
        retained: &mut u64,
    ) {
        let stale: Vec<DecodeCursorKey> = self
            .decode
            .cursors
            .keys()
            .filter(|key| key.pid == pid && key.start_time != start_time)
            .cloned()
            .collect();
        for key in stale {
            if let Some(old) = self.decode.cursors.remove(&key) {
                *retained = retained.saturating_sub(decode_cursor_bytes(&key, &old));
            }
        }
    }

    /// Drop `pid`+`start_time` cursors whose object no mapping covers
    /// anymore: the fresh maps prove it unmapped, so the stale cursor
    /// must not linger in progress totals or replay later.
    pub(crate) fn drop_unmapped_decode_cursors(
        &mut self,
        pid: u32,
        start_time: u64,
        mapped: &BTreeSet<(Device, u64)>,
        retained: &mut u64,
    ) {
        let stale: Vec<DecodeCursorKey> = self
            .decode
            .cursors
            .keys()
            .filter(|key| {
                key.pid == pid
                    && key.start_time == start_time
                    && !mapped.contains(&(key.file.device, key.file.inode))
            })
            .cloned()
            .collect();
        for key in stale {
            if let Some(old) = self.decode.cursors.remove(&key) {
                *retained = retained.saturating_sub(decode_cursor_bytes(&key, &old));
            }
        }
    }

    /// Drop every cursor for `pid`'s object `(device, inode)` whatever
    /// generation or pin it names: the fresh scan of that object
    /// supersedes them (a reused pid, a rewritten file, a remapped
    /// layout). Only called when the object was actually reached and
    /// missed, never speculatively.
    pub(crate) fn drop_stale_decode_cursors(
        &mut self,
        pid: u32,
        device: Device,
        inode: u64,
        retained: &mut u64,
    ) {
        let stale: Vec<DecodeCursorKey> = self
            .decode
            .cursors
            .keys()
            .filter(|key| key.pid == pid && key.file.device == device && key.file.inode == inode)
            .cloned()
            .collect();
        for key in stale {
            if let Some(old) = self.decode.cursors.remove(&key) {
                *retained = retained.saturating_sub(decode_cursor_bytes(&key, &old));
            }
        }
    }

    /// Arm the next table-sweep call to resume at `start_word` with the
    /// cached export anchors (skipping the prologue's charges).
    pub(crate) fn set_table_resume(
        &mut self,
        start_word: u64,
        anchors: Option<BTreeMap<u64, Vec<usize>>>,
    ) {
        self.decode.table_resume.start_word = start_word;
        self.decode.table_resume.swept_words = 0;
        self.decode.table_resume.anchors = anchors;
        self.decode.table_resume.anchors_out = None;
    }

    /// Take the armed table resume (call entry consumes it, so a sweep
    /// that never runs cannot leak resume state into the next object).
    pub(crate) fn take_table_resume(&mut self) -> (u64, Option<BTreeMap<u64, Vec<usize>>>) {
        self.decode.table_resume.swept_words = 0;
        self.decode.table_resume.swept_completed = false;
        self.decode.table_resume.anchors_out = None;
        (
            std::mem::replace(&mut self.decode.table_resume.start_word, 0),
            self.decode.table_resume.anchors.take(),
        )
    }

    /// Report words swept by the table call now returning (fully examined
    /// words only; every early break excludes its current word) and
    /// whether the sweep finished (loop exit, not a break).
    pub(crate) fn note_table_swept(&mut self, words: u64, completed: bool) {
        self.decode.table_resume.swept_words = words;
        self.decode.table_resume.swept_completed = completed;
    }

    /// Words the last table-sweep call swept plus whether it finished;
    /// resets both.
    pub(crate) fn take_table_swept(&mut self) -> (u64, bool) {
        (
            std::mem::replace(&mut self.decode.table_resume.swept_words, 0),
            std::mem::replace(&mut self.decode.table_resume.swept_completed, false),
        )
    }

    /// Publish the anchor map the table prologue just computed (cached
    /// into the frontier cursor when the sweep stops early).
    pub(crate) fn note_table_anchors(&mut self, anchors: BTreeMap<u64, Vec<usize>>) {
        self.decode.table_resume.anchors_out = Some(anchors);
    }

    /// Take the last table prologue's anchor map, if it ran.
    pub(crate) fn take_table_anchors_out(&mut self) -> Option<BTreeMap<u64, Vec<usize>>> {
        self.decode.table_resume.anchors_out.take()
    }

    /// Arm the next interface-sweep call to resume at `start_word`.
    pub(crate) fn set_iface_resume(&mut self, start_word: u64) {
        self.decode.iface_resume.start_word = start_word;
        self.decode.iface_resume.swept_words = 0;
    }

    /// Take the armed interface resume (call entry consumes it).
    pub(crate) fn take_iface_resume(&mut self) -> u64 {
        self.decode.iface_resume.swept_words = 0;
        self.decode.iface_resume.swept_completed = false;
        std::mem::replace(&mut self.decode.iface_resume.start_word, 0)
    }

    /// Report words swept by the interface call now returning, and
    /// whether the sweep finished (loop exit, not a break).
    pub(crate) fn note_iface_swept(&mut self, words: u64, completed: bool) {
        self.decode.iface_resume.swept_words = words;
        self.decode.iface_resume.swept_completed = completed;
    }

    /// Words the last interface-sweep call swept plus whether it
    /// finished; resets both.
    pub(crate) fn take_iface_swept(&mut self) -> (u64, bool) {
        (
            std::mem::replace(&mut self.decode.iface_resume.swept_words, 0),
            std::mem::replace(&mut self.decode.iface_resume.swept_completed, false),
        )
    }

    /// Note one interface-triple address the sweep examined while its
    /// target table was still unknown: a hint the link step re-reads
    /// from current memory once tables are final. Only armed scans
    /// record (single-shot scans have no next pass), only mapped
    /// targets qualify (unmapped look-alikes are data), and each
    /// address records once.
    pub(crate) fn note_unlinked_triple(&mut self, address: u64, target_mapped: bool) {
        if !self.decode.resume_armed
            || !target_mapped
            || self.decode.unlinked_triples.contains(&address)
        {
            return;
        }
        self.decode.unlinked_triples.push(address);
    }

    /// Drain this object's recorded unlinked triples into its staging.
    pub(crate) fn take_unlinked_triples(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.decode.unlinked_triples)
    }

    /// `(done, total, tables)` for one view's cursors: completed objects,
    /// cursor-known objects, and cached tables decoded so far. `None`
    /// when the view holds no unfinished cursor (no in-progress gap).
    pub(crate) fn view_scan_progress(
        &self,
        pid: u32,
        start_time: Option<u64>,
    ) -> Option<(usize, usize, usize)> {
        let start_time = start_time?;
        let mut done = 0usize;
        let mut total = 0usize;
        let mut tables = 0usize;
        for (key, cursor) in &self.decode.cursors {
            if key.pid != pid || key.start_time != start_time {
                continue;
            }
            total += 1;
            tables += cursor.cached_tables.len();
            if cursor.complete {
                done += 1;
            }
        }
        if total > done {
            Some((done, total, tables))
        } else {
            None
        }
    }

    /// The view's named in-progress gap, if it holds unfinished cursors:
    /// `(subject, reason)` with done/total progress. Pushed once at the
    /// end of the view's scan.
    pub(crate) fn view_in_progress_gap(
        &self,
        pid: u32,
        start_time: Option<u64>,
    ) -> Option<(String, String)> {
        self.view_scan_progress(pid, start_time)
            .map(|(done, total, tables)| {
                (
                    SCAN_IN_PROGRESS_SUBJECT.to_string(),
                    scan_in_progress_reason(done, total, tables),
                )
            })
    }

    /// Oldest unfinished cursor sequence for one view's object
    /// (`device`/`inode` match only — ordering is advisory; use
    /// re-validates the full key, pin and fingerprint).
    fn unfinished_seq_for_object(
        &self,
        pid: u32,
        start_time: Option<u64>,
        device: Device,
        inode: u64,
    ) -> Option<u64> {
        let start_time = start_time?;
        self.decode
            .cursors
            .iter()
            .filter(|(key, cursor)| {
                !cursor.complete && cursor_key_matches_object(key, pid, start_time, device, inode)
            })
            .map(|(_, cursor)| cursor.seq)
            .min()
    }

    /// Order one view's object groups oldest-unfinished-first (stable):
    /// unfinished objects scan before new ones, so small new objects
    /// cannot starve them; everything else keeps B-tree order. Without
    /// unfinished cursors this is a no-op.
    pub(crate) fn order_groups_for_resume<'a>(
        &self,
        pid: u32,
        start_time: Option<u64>,
        groups: BTreeMap<ObjectKey, Vec<&'a MapEntry>>,
    ) -> Vec<(ObjectKey, Vec<&'a MapEntry>)> {
        let mut ordered: Vec<(ObjectKey, Vec<&'a MapEntry>)> = groups.into_iter().collect();
        if !ordered.iter().any(|(key, _)| {
            self.unfinished_seq_for_object(pid, start_time, key.device, key.inode)
                .is_some()
        }) {
            return ordered;
        }
        // Stable sort: unfinished (by oldest sequence) first, the rest
        // in B-tree order.
        ordered.sort_by_key(|(key, _)| {
            match self.unfinished_seq_for_object(pid, start_time, key.device, key.inode) {
                Some(seq) => (0u8, seq),
                None => (1u8, u64::MAX),
            }
        });
        ordered
    }

    /// Order one pass's member pids oldest-unfinished-first (stable):
    /// members holding unfinished cursors scan before new members, so a
    /// busy pass cannot starve them behind selection or cap order.
    /// Without unfinished cursors this is a no-op.
    pub(crate) fn order_pids_for_resume(&self, pids: &mut Vec<u32>) {
        if !self.decode.cursors.values().any(|cursor| !cursor.complete) {
            return;
        }
        let min_seq: BTreeMap<u32, u64> = self
            .decode
            .cursors
            .iter()
            .filter(|(_, cursor)| !cursor.complete)
            .fold(BTreeMap::new(), |mut min_seq, (key, cursor)| {
                min_seq
                    .entry(key.pid)
                    .and_modify(|seq| *seq = (*seq).min(cursor.seq))
                    .or_insert(cursor.seq);
                min_seq
            });
        if min_seq.is_empty() {
            return;
        }
        // Stable partition preserving both orders.
        let mut unfinished: Vec<u32> = Vec::new();
        let mut rest: Vec<u32> = Vec::new();
        for pid in pids.iter() {
            if min_seq.contains_key(pid) {
                unfinished.push(*pid);
            } else {
                rest.push(*pid);
            }
        }
        unfinished.sort_by_key(|pid| min_seq.get(pid).copied().unwrap_or(u64::MAX));
        pids.clear();
        pids.extend(unfinished);
        pids.extend(rest);
    }

    /// Reserve capped selection slots for the oldest unfinished members:
    /// every eligible unfinished pid joins `selected` (oldest first),
    /// filling short selections and then displacing the tail
    /// (rarity-lowest) selection — or the youngest selected unfinished
    /// member when the missing one is older, keeping strict
    /// oldest-first across passes. Ineligible pids (unswept,
    /// unavailable, kernel-thread) never enter. Without unfinished
    /// cursors this is a no-op. Called after rarity selection and
    /// before resume ordering, so capped passes cannot starve resumed
    /// work behind selection order.
    pub(crate) fn reserve_unfinished_selection(
        &self,
        selected: &mut Vec<u32>,
        eligible: &BTreeSet<u32>,
        cap: usize,
    ) {
        if cap == 0 {
            return;
        }
        let mut oldest: BTreeMap<u32, u64> = BTreeMap::new();
        for (key, cursor) in &self.decode.cursors {
            if cursor.complete {
                continue;
            }
            oldest
                .entry(key.pid)
                .and_modify(|seq| *seq = (*seq).min(cursor.seq))
                .or_insert(cursor.seq);
        }
        if oldest.is_empty() {
            return;
        }
        let unfinished: BTreeSet<u32> = oldest.keys().copied().collect();
        let mut pending: Vec<(u64, u32)> = oldest.iter().map(|(pid, seq)| (*seq, *pid)).collect();
        pending.sort();
        let mut selected_set: BTreeSet<u32> = selected.iter().copied().collect();
        for (seq, pid) in pending {
            if selected_set.contains(&pid) || !eligible.contains(&pid) {
                continue;
            }
            if selected.len() < cap {
                selected.push(pid);
                selected_set.insert(pid);
                continue;
            }
            if let Some(victim) = selected
                .iter()
                .rposition(|member| !unfinished.contains(member))
            {
                selected_set.remove(&selected[victim]);
                selected[victim] = pid;
                selected_set.insert(pid);
                continue;
            }
            // Every selected member is unfinished: displace the youngest
            // one when the missing member is older. Processed
            // oldest-first, displacement only flows old-over-young, so
            // no pair ping-pongs.
            let youngest = selected
                .iter()
                .enumerate()
                .filter(|(_, member)| unfinished.contains(member))
                .max_by_key(|(_, member)| oldest.get(member).copied().unwrap_or(u64::MAX));
            if let Some((victim, _)) = youngest
                && oldest.get(&selected[victim]).copied().unwrap_or(0) > seq
            {
                selected_set.remove(&selected[victim]);
                selected[victim] = pid;
                selected_set.insert(pid);
            }
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

    /// Passes that tripped the work ceiling: the count behind the
    /// per-interval exhaustion gap. Sticky and never reset.
    #[cfg(test)]
    pub(crate) fn interval_exhaustions(&self) -> u64 {
        self.interval_exhaustions
    }

    /// Bytes of this file already charged in earlier passes: the
    /// whole-file hash re-reads its prefix free and charges only new
    /// bytes, so a file larger than one window resumes instead of
    /// restarting at offset 0 forever. Zero for a fresh file; a
    /// changed file carries a new pin (hence a new key) and misses.
    pub(crate) fn hash_resume_offset(&self, key: &InspectedFileKey) -> u64 {
        self.hash_resume
            .get(key)
            .map_or(0, |(consumed, _)| *consumed)
    }

    /// Notes charged hash progress (monotone: out-of-order notes never
    /// move the offset back). Past [`HASH_RESUME_CAP`] entries the
    /// stalest entry evicts and its file restarts.
    pub(crate) fn note_hash_resume(&mut self, key: InspectedFileKey, consumed: u64) {
        self.hash_resume_seq = self.hash_resume_seq.saturating_add(1);
        let seq = self.hash_resume_seq;
        self.hash_resume
            .entry(key)
            .and_modify(|entry| {
                entry.0 = entry.0.max(consumed);
                entry.1 = seq;
            })
            .or_insert((consumed, seq));
        while self.hash_resume.len() > HASH_RESUME_CAP {
            let stalest = self
                .hash_resume
                .iter()
                .min_by_key(|(_, (_, seq))| *seq)
                .map(|(key, _)| *key);
            let Some(stalest) = stalest else {
                break;
            };
            self.hash_resume.remove(&stalest);
        }
    }

    /// Drops a hash resume entry: the file completed, changed, or
    /// failed beyond budget recovery.
    pub(crate) fn drop_hash_resume(&mut self, key: &InspectedFileKey) {
        self.hash_resume.remove(key);
    }

    /// Partitions one hash read into already-charged prefix (re-read
    /// free from page cache) and suffix (charged): `(prefix, suffix)`
    /// byte counts covering `wanted` exactly.
    pub(crate) fn hash_read_split(consumed: u64, offset: u64, wanted: usize) -> (usize, usize) {
        if offset >= consumed {
            return (0, wanted);
        }
        let prefix = (consumed - offset).min(wanted as u64) as usize;
        (prefix, wanted - prefix)
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

    /// Ends one pass (controller ruling 11:38): the Detailed work
    /// ceiling is a renewing budget, never a capture-lifetime sticky
    /// stop. When the pass tripped the work ceiling on a nonzero
    /// allowance, count the exhaustion, reset the spent units and
    /// clear the latch; the next pass retries with a fresh allowance.
    /// The Detailed I/O allowance renews silently every pass (L1-5:
    /// no capture-lifetime terminal I/O stop): bytes reset and a
    /// tripped nonzero I/O latch heals, with no interval row of its
    /// own because every I/O trip already surfaces via member rows.
    /// Returns the cleared work stop when it was never reported, so
    /// the driver files it against its own pass instead of losing
    /// it. Returns `None` for a clean pass (work spend accumulates
    /// across clean passes, so the lifetime anti-DoS bound holds
    /// until the first trip), an already reported stop, an active
    /// window (windows own their renewal), any other stop
    /// (deadlines clear at their own batch end), or a zero cap
    /// (re-trips instantly, so its stop stays put).
    pub(crate) fn end_pass(&mut self) -> Option<&'static str> {
        if self.active_window.is_some() {
            return None;
        }
        if !matches!(self.policy, DiscoveryPolicy::DetailedLegacy) {
            return None;
        }
        self.pass_io_bytes = 0;
        if self.scan_stop_reason == Some(IO_CEILING_REASON) && self.io_allowance() > 0 {
            self.scan_stop_reason = None;
            self.scan_stop_reported = false;
        }
        if self.scan_stop_reason != Some(WORK_CEILING_REASON) {
            return None;
        }
        if self.work_ceiling == 0 {
            return None;
        }
        self.interval_exhaustions = self.interval_exhaustions.saturating_add(1);
        self.work_units = 0;
        let unreported = !self.scan_stop_reported;
        self.scan_stop_reason = None;
        self.scan_stop_reported = false;
        unreported.then_some(WORK_CEILING_REASON)
    }

    /// Whether the tripped dimension could admit anything next pass.
    /// A zero allowance re-trips instantly, so its stop stays put;
    /// a tripped nonzero work allowance renews at `end_pass`.
    fn allowance_allows_progress(&self, reason: &'static str) -> bool {
        match reason {
            WORK_CEILING_REASON => self.work_allowance() > 0,
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

    /// The pass work allowance for own-spend scheduling: a member whose
    /// own turn spent this much while tripping a budget stop is the hog
    /// that actually spent the window, not an inherited-shortage victim.
    /// No new constant: the existing per-pass bound is the threshold, so
    /// uniform members (about 1/250 of the window) never accrue on spend
    /// alone.
    pub(crate) fn work_allowance_for_scheduling(&self) -> u64 {
        self.work_allowance()
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
                terminal: false,
            };
        };
        if next > self.work_ceiling {
            self.set_scan_stop(WORK_CEILING_REASON);
            return ChargeOutcome::Stopped {
                reason: WORK_CEILING_REASON,
                terminal: false,
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
    #[cfg(test)]
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
    /// stays put. A tripped nonzero work ceiling renews at `end_pass`
    /// (fresh allowance, counted exhaustion) and the refused tail
    /// retries first; clean passes accumulate spend; collection stops
    /// and zero caps never admit; deadlines clear at their own batch
    /// end and I/O stays capture-lifetime. N/A cells are
    /// marked with their reason (a charge site only trips its own
    /// stop; Inventory windows reject a zero cap at construction).
    #[test]
    fn admission_owner2_pass_budget_renews_and_resumes() {
        // Detailed work × tripped ceiling: renews with a fresh
        // allowance and a counted exhaustion; the cursor resumes.
        let mut pass = detailed(100, 1024);
        assert_eq!(pass.charge_work(100), ChargeOutcome::Admitted);
        assert_eq!(
            pass.charge_work(1),
            ChargeOutcome::Stopped {
                reason: WORK_CEILING_REASON,
                terminal: false,
            }
        );
        assert_eq!(pass.stopped_reason(), Some(WORK_CEILING_REASON));
        pass.cursor_mut().note_member_outcomes(&[
            ((1, Some(10)), MemberOutcome::Examined, 0),
            ((2, Some(20)), MemberOutcome::Examined, 0),
            ((3, Some(30)), MemberOutcome::CutShortBudgetStop, 0),
            ((4, Some(40)), MemberOutcome::CutShortBudgetStop, 0),
        ]);
        assert_eq!(pass.end_pass(), Some(WORK_CEILING_REASON));
        assert_eq!(pass.interval_exhaustions(), 1);
        assert_eq!(pass.stopped_reason(), None);
        assert_eq!(pass.charge_work(1), ChargeOutcome::Admitted);
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
        // Detailed work × clean pass: spend accumulates (no trip, no
        // reset), so the lifetime anti-DoS bound holds until the
        // first trip; a heavy workload trips honestly again, one
        // counted gap per quantum.
        let mut pass = detailed(100, 1024);
        assert_eq!(pass.charge_work(90), ChargeOutcome::Admitted);
        assert_eq!(pass.end_pass(), None);
        assert_eq!(pass.interval_exhaustions(), 0);
        assert_eq!(
            pass.charge_work(50),
            ChargeOutcome::Stopped {
                reason: WORK_CEILING_REASON,
                terminal: false,
            },
            "the clean pass kept its spend"
        );
        assert_eq!(pass.end_pass(), Some(WORK_CEILING_REASON));
        assert_eq!(pass.interval_exhaustions(), 1);
        assert_eq!(pass.charge_work(100), ChargeOutcome::Admitted);
        assert_eq!(
            pass.charge_work(1),
            ChargeOutcome::Stopped {
                reason: WORK_CEILING_REASON,
                terminal: false,
            },
            "the fresh quantum trips honestly again"
        );
        assert_eq!(pass.end_pass(), Some(WORK_CEILING_REASON));
        assert_eq!(pass.interval_exhaustions(), 2);
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
        assert_eq!(pass.interval_exhaustions(), 1);
        assert_eq!(pass.stopped_reason(), None);
        assert_eq!(pass.charge_work(1), ChargeOutcome::Admitted);

        // Detailed work × deadline: `end_pass` leaves time stops
        // alone; the batch end clears them via `set_deadline(None)`.
        let mut pass = detailed(100, 1024);
        pass.set_deadline(Some(1000));
        assert_eq!(pass.check_deadline(Some(1001)), Some(SCAN_DEADLINE_REASON));
        assert_eq!(pass.end_pass(), None);
        assert_eq!(pass.stopped_reason(), Some(SCAN_DEADLINE_REASON));
        pass.set_deadline(None);
        assert_eq!(pass.stopped_reason(), None);
        assert_eq!(pass.charge_work(1), ChargeOutcome::Admitted);

        // Detailed work × clock: same shape (an unreadable clock is
        // transient, but its latch still heals at the batch end).
        let mut pass = detailed(100, 1024);
        pass.set_deadline(Some(1000));
        assert_eq!(pass.check_deadline(None), Some(SCAN_CLOCK_REASON));
        assert_eq!(pass.end_pass(), None);
        assert_eq!(pass.stopped_reason(), Some(SCAN_CLOCK_REASON));
        pass.set_deadline(None);
        assert_eq!(pass.stopped_reason(), None);
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

        // Detailed I/O × I/O ceiling: renews silently. The per-pass
        // allowance resets and the latch clears (L1-5 ends: no
        // capture-lifetime terminal I/O stop); the renewal files no
        // interval row because every I/O trip already surfaces via
        // its member take-rows each pass.
        let mut pass = detailed(100, 64);
        assert_eq!(pass.charge_io(64), ChargeOutcome::Admitted);
        assert_eq!(
            pass.charge_io(1),
            ChargeOutcome::Stopped {
                reason: IO_CEILING_REASON,
                terminal: false,
            }
        );
        assert_eq!(pass.end_pass(), None);
        assert_eq!(pass.stopped_reason(), None);
        assert_eq!(pass.charge_io(64), ChargeOutcome::Admitted);
        // The lifetime total keeps counting for headroom reporting
        // (refused attempts record nothing).
        assert_eq!(pass.attempted_io_bytes(), 128);

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

    /// Owner 2c table: whole-file hashing carries its charged offset
    /// across passes, so a file larger than one window resumes instead
    /// of restarting at offset 0 forever (L3-2). Fresh files start at
    /// 0; noted progress extends (monotone: out-of-order notes never
    /// move the offset back); completion drops the entry; a changed
    /// file (new pin, hence a new key) misses and restarts; past the
    /// cap the stalest entry evicts. The read split partitions every
    /// request into already-charged prefix (re-read free) and suffix
    /// (charged): pure prefix, straddle, pure suffix, exact boundary.
    #[test]
    fn admission_owner2c_hash_resume_carries_offsets() {
        use crate::discovery::scan::InspectedFileKey;
        use p11scope_manifest::maps::Device;
        fn key_for(pin_ctime: (i64, i64), inode: u64) -> InspectedFileKey {
            let file = tempfile::NamedTempFile::new().unwrap();
            let pin = crate::discovery::identity::pin_of(file.as_file())
                .unwrap()
                .test_with_ctime(pin_ctime);
            InspectedFileKey {
                device: Device { major: 0, minor: 1 },
                inode,
                pin,
                fd_dev: 7,
            }
        }
        let mut pass = detailed(u64::MAX, u64::MAX);
        let key = key_for((100, 0), 11);
        assert_eq!(pass.hash_resume_offset(&key), 0);
        pass.note_hash_resume(key, 100);
        assert_eq!(pass.hash_resume_offset(&key), 100);
        pass.note_hash_resume(key, 250);
        assert_eq!(pass.hash_resume_offset(&key), 250);
        pass.note_hash_resume(key, 200);
        assert_eq!(
            pass.hash_resume_offset(&key),
            250,
            "out-of-order notes never move the offset back"
        );
        pass.drop_hash_resume(&key);
        assert_eq!(pass.hash_resume_offset(&key), 0);
        // A changed file carries a new pin, hence a new key: miss.
        let changed = key_for((101, 0), 11);
        assert_ne!(key.pin.test_parts(), changed.pin.test_parts());
        pass.note_hash_resume(key, 100);
        assert_eq!(pass.hash_resume_offset(&changed), 0);
        // Past the cap the stalest entry evicts (bounded memory).
        let mut pass = detailed(u64::MAX, u64::MAX);
        let first = key_for((1, 0), 1);
        pass.note_hash_resume(first, 10);
        let mut last = first;
        for index in 2..=(super::HASH_RESUME_CAP as u64 + 1) {
            last = key_for((index as i64, 0), index);
            pass.note_hash_resume(last, 10);
        }
        assert_eq!(
            pass.hash_resume_offset(&first),
            0,
            "the stalest entry evicted past the cap"
        );
        assert_eq!(pass.hash_resume_offset(&last), 10);
        // The read split: (prefix free, suffix charged).
        assert_eq!(ScanPassOwner::hash_read_split(100, 0, 1000), (100, 900));
        assert_eq!(ScanPassOwner::hash_read_split(100, 100, 500), (0, 500));
        assert_eq!(ScanPassOwner::hash_read_split(100, 50, 30), (30, 0));
        assert_eq!(
            ScanPassOwner::hash_read_split(100, 50, 100),
            (50, 50),
            "a straddling request splits at the consumed edge"
        );
        assert_eq!(ScanPassOwner::hash_read_split(0, 0, 10), (0, 10));
        assert_eq!(
            ScanPassOwner::hash_read_split(50, 200, 40),
            (0, 40),
            "a request past the offset charges whole"
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
            ((10, Some(1)), MemberOutcome::Examined, 0),
            ((20, Some(2)), MemberOutcome::Examined, 0),
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
            ((11, Some(110)), MemberOutcome::CutShortBudgetStop, 0),
            ((12, Some(120)), MemberOutcome::Examined, 0),
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
            let demoted = pass.cursor_mut().note_member_outcomes(&[(
                stuck,
                MemberOutcome::CutShortBudgetStop,
                0,
            )]);
            assert!(demoted.is_empty(), "pass {streak} still retries first");
            assert!(
                !pass.cursor().examined_for_test().contains(&stuck),
                "pass {streak}: the retrying member still counts as fresh"
            );
        }
        let demoted = pass.cursor_mut().note_member_outcomes(&[(
            stuck,
            MemberOutcome::CutShortBudgetStop,
            0,
        )]);
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
            .note_member_outcomes(&[(stuck, MemberOutcome::Examined, 0)]);
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
                .note_member_outcomes(&[(stuck, MemberOutcome::CutShortBudgetStop, 0)])
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
                .note_member_outcomes(&[(stuck, MemberOutcome::CutShortBudgetStop, 0)])
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
            pass.cursor_mut().note_member_outcomes(&[(
                (11, Some(100)),
                MemberOutcome::CutShortBudgetStop,
                0,
            )]);
        }
        assert_eq!(
            pass.cursor().order_members(&[(11, Some(100)), (12, None)]),
            vec![12, 11],
            "the old incarnation is demoted"
        );
        // The pid is recycled with a new start-time: fresh streak.
        let demoted = pass.cursor_mut().note_member_outcomes(&[(
            (11, Some(200)),
            MemberOutcome::CutShortBudgetStop,
            0,
        )]);
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
    /// budget stop accrues toward demotion. Other truncations keep
    /// ordinary fresh retry priority without accruing, while unattempted
    /// members stay never-attempted (ahead of retried members), so a
    /// deferred tail retries before a retried prefix and no refused
    /// prefix can camp at the head.
    #[test]
    fn owner2_cursor_demotion_counts_only_budget_stops() {
        let mut pass = detailed(u64::MAX, u64::MAX);
        for _ in 0..BUDGET_STOP_DEMOTE_AFTER {
            let demoted = pass.cursor_mut().note_member_outcomes(&[
                ((21, Some(210)), MemberOutcome::CutShortOther, 0),
                ((22, Some(220)), MemberOutcome::Unattempted, 0),
            ]);
            assert!(demoted.is_empty(), "non-budget outcomes never accrue");
        }
        assert!(pass.cursor().streaks_for_test().is_empty());
        assert_eq!(
            pass.cursor()
                .order_members(&[(21, Some(210)), (22, Some(220)), (23, None)]),
            vec![22, 23, 21],
            "unattempted members stay never-attempted, ahead of retried members"
        );
        // A budget stop does accrue.
        pass.cursor_mut().note_member_outcomes(&[(
            (21, Some(210)),
            MemberOutcome::CutShortBudgetStop,
            0,
        )]);
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

    /// Fair-share ordering: within the retry tier the least-spent member
    /// scans first, so a low-pid refused prefix that already spent its
    /// turns cannot camp at the head ahead of a high-pid tail that spent
    /// little. Never-attempted members still precede all retries.
    #[test]
    fn owner2_cursor_orders_retry_tier_by_least_spent_first() {
        let mut pass = detailed(u64::MAX, u64::MAX);
        pass.cursor_mut().note_member_outcomes(&[
            ((10, Some(100)), MemberOutcome::CutShortOther, 5000),
            ((500, Some(5000)), MemberOutcome::CutShortOther, 100),
        ]);
        assert_eq!(
            pass.cursor()
                .order_members(&[(10, Some(100)), (500, Some(5000)), (501, Some(5010))]),
            vec![501, 500, 10],
            "the least-spent retry scans first, regardless of pid"
        );
    }

    /// Own-spend accumulation: per-member spend totals across passes,
    /// pruned to live pids and cleared on pid reuse, so fair-share
    /// ordering reflects what each incarnation actually spent.
    #[test]
    fn owner2_cursor_accumulates_own_spend_and_clears_on_reuse() {
        let mut pass = detailed(u64::MAX, u64::MAX);
        pass.cursor_mut().note_member_outcomes(&[
            ((10, Some(100)), MemberOutcome::CutShortOther, 5000),
            ((11, Some(110)), MemberOutcome::CutShortOther, 100),
        ]);
        assert_eq!(
            pass.cursor().own_spend_for_test().get(&(10, Some(100))),
            Some(&5000)
        );
        pass.cursor_mut().note_member_outcomes(&[(
            (10, Some(100)),
            MemberOutcome::CutShortOther,
            3000,
        )]);
        assert_eq!(
            pass.cursor().own_spend_for_test().get(&(10, Some(100))),
            Some(&8000),
            "spend accumulates across passes"
        );
        pass.cursor_mut().note_member_outcomes(&[(
            (10, Some(200)),
            MemberOutcome::CutShortOther,
            50,
        )]);
        assert_eq!(
            pass.cursor().own_spend_for_test().get(&(10, Some(200))),
            Some(&50),
            "a recycled pid starts fresh"
        );
        assert!(
            !pass
                .cursor()
                .own_spend_for_test()
                .contains_key(&(10, Some(100))),
            "the old incarnation's spend never transfers"
        );
    }
}
