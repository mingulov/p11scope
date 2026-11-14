//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Producer-owned historical state. Control/liveness is a separate authority.
use crate::semantics::ProcessKey;
use p11scope_ebpf_common::ImageIdentity;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    os::fd::OwnedFd,
    sync::Arc,
};

// Optional control seam retained for the separate preseed/cursor integration.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) enum Membership {
    Live { domain: u64, cookie: u64 },
    Exited,
    Unavailable,
}

/// The adapter retains authenticated original pidfds. Candidate selection is
/// an external task-membership decision, not authority granted by a PID/event.
/// `sample` must operate on this SAME descriptor; it supplies no exec counter.
#[allow(dead_code)]
pub(crate) trait TaskMembership {
    fn candidate(&mut self, pid: u32) -> Option<Arc<OwnedFd>>;
    fn sample(&mut self, original: &OwnedFd) -> Membership;
}
struct Task {
    key: ProcessKey,
    closed: bool,
    called: bool,
    forked: bool,
    root_positive: bool,
    /// Kernel time (`bpf_ktime_get_ns`) of the CALL/FORK that admitted
    /// this task generation. Exit matching retires tasks with
    /// `first_ts_ns` strictly before the exit hook, so a reused pid's
    /// successor (admitted after the old exit) is never retired with
    /// it. Reset on exec-id bump: a new generation, a new first time.
    first_ts_ns: u64,
    /// Exit hook time recorded by exit-retire, never the `closed`
    /// flag (a closed task would refuse the reopened generation's
    /// next event). Cleared only by a reopen: a later event on this
    /// cookie with a timestamp after the exit.
    exit_ts_ns: Option<u64>,
}

/// One tapped `LEADER_EXIT`/`_MAPPINGS` record: the exiting pid and
/// its kernel hook time. The discovery engine taps these before
/// view/ledger routing; the tracker stamps each with the EVENTS
/// producer position at transfer time and retires once the drain
/// reads past it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExitTap {
    pub pid: u32,
    pub hook_ts_ns: u64,
}

/// A transferred tap waiting for the EVENTS drain to read past its
/// tap-time producer position. `passes` counts position-passing
/// drains that matched no task; past two, the exit drops with a
/// counted gap.
struct PendingExit {
    tap: ExitTap,
    tap_producer: usize,
    passes: u8,
}

/// Bound on tapped exits held anywhere: the engine tap queue and the
/// tracker's pending queue each hold at most this many. Transfer
/// moves only what fits, so drops happen only at tap time and count
/// in exactly one place (`exit_tap_overflow` on the engine).
pub(crate) const EXIT_TAP_QUEUE_LIMIT: usize = 16_384;

/// Position-passing drains an unmatched exit survives before it
/// drops with the counted `exit_retire_unmatched` gap.
const EXIT_UNMATCHED_RETRIES: u8 = 2;

/// Whether an exit stamped with tap-time producer `tap_producer` is
/// due at these EVENTS ring positions: the drain read strictly past
/// the stamp, or stands exactly on it with nothing committed past it
/// (a quiet ring — no uncommitted record hides before the drain).
/// The consumer only advances over consumed records in ring order, so
/// either case proves every pre-exit CALL was already reduced.
fn exit_due(consumer_now: usize, producer_now: usize, tap_producer: usize) -> bool {
    consumer_now > tap_producer || (consumer_now == tap_producer && producer_now == tap_producer)
}

pub(crate) struct Registry {
    limit: usize,
    tasks: BTreeMap<u64, Task>,
    // Keep map identity retained through destruction of the indexed tasks.
    domain: Option<crate::events::EventsDomain>,
    root_completed: bool,
    /// pid -> admitted task cookies. Exit matching walks only this
    /// pid's cookies instead of scanning all tasks. Grows only (tasks
    /// are never evicted), bounded by the same task limit.
    pid_index: BTreeMap<u32, BTreeSet<u64>>,
    /// Transferred exits not yet retired, in tap order (tap-time
    /// producer stamps are non-decreasing down the queue).
    pending_exits: VecDeque<PendingExit>,
    /// Exit-matched tasks skipped on a `first_ts_ns == hook_ts_ns`
    /// tie: neither generation is provably older, so neither retires.
    exit_tie_skipped: u64,
    /// Due exits dropped after [`EXIT_UNMATCHED_RETRIES`] retries
    /// with no matching task (never-admitted processes own no rows).
    exit_retire_unmatched: u64,
    /// Events on a retired cookie timestamped after the exit: the
    /// task reopens, the exit timestamp clears, the event is admitted.
    exit_retire_reopened: u64,
    /// Events on a retired cookie timestamped at or before the exit:
    /// admitted (data-always), the exit timestamp stays.
    exit_retire_late: u64,
}
impl Registry {
    // Legacy-ladder support only (SYSPLAN residual F-44): the production
    // tracker always carries a live registry from `for_producer`.
    #[cfg(test)]
    pub(crate) fn disabled() -> Self {
        Self {
            domain: None,
            limit: 0,
            tasks: BTreeMap::new(),
            root_completed: false,
            pid_index: BTreeMap::new(),
            pending_exits: VecDeque::new(),
            exit_tie_skipped: 0,
            exit_retire_unmatched: 0,
            exit_retire_reopened: 0,
            exit_retire_late: 0,
        }
    }
    pub(crate) fn new(domain: crate::events::EventsDomain, limit: usize) -> Self {
        Self {
            domain: Some(domain),
            limit,
            tasks: BTreeMap::new(),
            root_completed: false,
            pid_index: BTreeMap::new(),
            pending_exits: VecDeque::new(),
            exit_tie_skipped: 0,
            exit_retire_unmatched: 0,
            exit_retire_reopened: 0,
            exit_retire_late: 0,
        }
    }
    pub(crate) fn domain(&self) -> u64 {
        self.domain
            .as_ref()
            .map_or(0, crate::events::EventsDomain::id)
    }
    /// A0 lens (R9): admitted task cookies ever. Read-only; the
    /// registry never evicts (the 262,144 cliff), so this only grows.
    pub(crate) fn memory_tasks_row(&self) -> crate::memory_counters::CounterRow {
        crate::memory_counters::counter_row(
            self.tasks.len(),
            std::mem::size_of::<(u64, Task)>(),
            crate::memory_counters::HEAP_MAP_ENTRY,
        )
    }
    /// The domain comes from the sole retained EVENTS consumer, never a wire
    /// field or a live process lookup. The producer authenticates the tuple.
    /// `event_ts_ns` is the admitting event's kernel time, recorded as
    /// the task generation's `first_ts_ns` for exit matching (reset on
    /// exec-id bump).
    pub(crate) fn admit(
        &mut self,
        domain: u64,
        pid: u32,
        image: ImageIdentity,
        event_ts_ns: u64,
    ) -> (Option<ProcessKey>, Vec<ProcessKey>) {
        let mut retired = Vec::new();
        if domain == 0 || domain != self.domain() || image.task_cookie == 0 || pid == 0 {
            return (None, retired);
        }
        if let Some(task) = self.tasks.get_mut(&image.task_cookie) {
            if task.closed || image.exec_id < task.key.exec_id {
                return (None, retired);
            }
            if image.exec_id > task.key.exec_id {
                retired.push(task.key);
                task.key = ProcessKey::history(domain, image.task_cookie, image.exec_id, pid);
                task.called = false;
                task.forked = false;
                task.first_ts_ns = event_ts_ns;
                task.exit_ts_ns = None;
            }
            return (Some(task.key), retired);
        }
        if self.tasks.len() >= self.limit {
            return (None, retired);
        }
        let key = ProcessKey::history(domain, image.task_cookie, image.exec_id, pid);
        self.tasks.insert(
            image.task_cookie,
            Task {
                key,
                closed: false,
                called: false,
                forked: false,
                root_positive: false,
                first_ts_ns: event_ts_ns,
                exit_ts_ns: None,
            },
        );
        self.pid_index
            .entry(pid)
            .or_default()
            .insert(image.task_cookie);
        (Some(key), retired)
    }
    /// Exact-key like every other mutator: a retired generation's CALL must
    /// never mark the successor generation as called.
    pub(crate) fn mark_call(&mut self, key: ProcessKey) {
        if let Some(task) = self.tasks.get_mut(&key.generation)
            && task.key == key
            && !task.closed
        {
            task.called = true;
        }
    }
    pub(crate) fn mark_root(&mut self, key: ProcessKey, affiliation: u64) {
        if affiliation == 1
            && let Some(task) = self.tasks.get_mut(&key.generation)
            && task.key == key
            && !task.closed
        {
            task.root_positive = true;
        }
    }
    pub(crate) fn check_root(&self, domain: u64, affiliation: u64) -> anyhow::Result<()> {
        anyhow::ensure!(affiliation <= 1, "invalid root affiliation");
        anyhow::ensure!(
            !(domain == self.domain() && affiliation == 1 && self.root_completed),
            "positive root event after completed fixed EVENTS tail"
        );
        Ok(())
    }
    pub(crate) fn complete_root(
        &mut self,
        tail: &crate::events::ConsumedOriginalRootTail,
    ) -> anyhow::Result<Vec<ProcessKey>> {
        anyhow::ensure!(
            tail.domain() == self.domain() && !self.root_completed,
            "foreign or repeated root retirement"
        );
        let keys: Vec<_> = self
            .tasks
            .values()
            .filter(|task| task.root_positive && !task.closed)
            .map(|task| task.key)
            .collect();
        self.root_completed = true;
        Ok(keys
            .into_iter()
            .filter_map(|key| self.confirm_retirement(key))
            .collect())
    }
    pub(crate) fn birth(&mut self, parent: ProcessKey, child: ProcessKey) -> bool {
        if parent == child {
            return false;
        }
        // An authentic first FORK can establish an empty parent history.
        if !self
            .tasks
            .get(&parent.generation)
            .is_some_and(|t| !t.closed && t.key == parent)
        {
            return false;
        }
        let Some(task) = self.tasks.get_mut(&child.generation) else {
            return false;
        };
        if task.closed || task.key != child || task.called || task.forked {
            return false;
        }
        task.forked = true;
        true
    }
    /// Exact-key reducer used by token-gated root completion and the legacy
    /// test-only retirement adapter. Liveness observations never call this.
    pub(crate) fn confirm_retirement(&mut self, key: ProcessKey) -> Option<ProcessKey> {
        if key.domain != self.domain() {
            return None;
        }
        let task = self.tasks.get_mut(&key.generation)?;
        if task.closed || task.key != key {
            return None;
        }
        task.closed = true;
        Some(task.key)
    }

    /// Free slots in the pending-exit queue. Transfer takes at most
    /// this many taps from the engine, so this queue never overflows.
    pub(crate) fn exit_tap_space(&self) -> usize {
        EXIT_TAP_QUEUE_LIMIT.saturating_sub(self.pending_exits.len())
    }

    /// Queues engine-tapped exits stamped with the EVENTS producer
    /// position read at transfer time. The caller takes at most
    /// [`Self::exit_tap_space`] taps, so the queue stays bounded.
    pub(crate) fn note_exit_taps(
        &mut self,
        taps: impl IntoIterator<Item = ExitTap>,
        tap_producer: usize,
    ) {
        for tap in taps {
            debug_assert!(self.pending_exits.len() < EXIT_TAP_QUEUE_LIMIT);
            if self.pending_exits.len() >= EXIT_TAP_QUEUE_LIMIT {
                break;
            }
            self.pending_exits.push_back(PendingExit {
                tap,
                tap_producer,
                passes: 0,
            });
        }
    }

    /// Collects the process keys whose exits are due: the drain has
    /// read past the tap-time producer position with no uncommitted
    /// record before it. Examines at most `budget` exits per call;
    /// the rest carry over to the next drain. Matched tasks record
    /// the exit hook time (never `closed`); ties skip with a counted
    /// gap; unmatched exits retry, then drop with a counted gap.
    pub(crate) fn retire_exits_due(
        &mut self,
        consumer_now: usize,
        producer_now: usize,
        budget: usize,
    ) -> BTreeSet<ProcessKey> {
        let mut due = BTreeSet::new();
        let mut keep = Vec::new();
        let mut examined = 0usize;
        while examined < budget {
            let Some(pending) = self.pending_exits.pop_front() else {
                break;
            };
            if !exit_due(consumer_now, producer_now, pending.tap_producer) {
                // Tap stamps are non-decreasing down the queue: nothing
                // behind this exit can be due either.
                self.pending_exits.push_front(pending);
                break;
            }
            examined += 1;
            let matched = self.match_exit_tap(&pending.tap);
            if matched.is_empty() {
                let mut pending = pending;
                pending.passes += 1;
                if pending.passes > EXIT_UNMATCHED_RETRIES {
                    self.exit_retire_unmatched = self.exit_retire_unmatched.saturating_add(1);
                } else {
                    keep.push(pending);
                }
            } else {
                due.extend(matched);
            }
        }
        for pending in keep.into_iter().rev() {
            self.pending_exits.push_front(pending);
        }
        due
    }

    /// Matches one due exit against this pid's open tasks by kernel
    /// time: tasks admitted strictly before the hook retire, ties
    /// skip with a counted gap, successors (admitted after the exit)
    /// are spared. Matched tasks record the exit hook time — the
    /// earliest observed, so any post-exit event reopens — never the
    /// `closed` flag, so the next event is never refused.
    fn match_exit_tap(&mut self, tap: &ExitTap) -> Vec<ProcessKey> {
        let mut matched = Vec::new();
        let Some(cookies) = self.pid_index.get(&tap.pid) else {
            return matched;
        };
        // The cookie set is copied: matching mutates tasks below.
        for cookie in cookies.iter().copied().collect::<Vec<_>>() {
            let Some(task) = self.tasks.get_mut(&cookie) else {
                continue;
            };
            if task.closed {
                continue;
            }
            if task.first_ts_ns < tap.hook_ts_ns {
                task.exit_ts_ns = Some(
                    task.exit_ts_ns
                        .map_or(tap.hook_ts_ns, |exit| exit.min(tap.hook_ts_ns)),
                );
                matched.push(task.key);
            } else if task.first_ts_ns == tap.hook_ts_ns {
                self.exit_tie_skipped = self.exit_tie_skipped.saturating_add(1);
            }
        }
        matched
    }

    /// `(tie_skipped, unmatched, reopened, late)` exit gap counters.
    #[cfg(test)]
    pub(crate) fn exit_counters_for_test(&self) -> (u64, u64, u64, u64) {
        (
            self.exit_tie_skipped,
            self.exit_retire_unmatched,
            self.exit_retire_reopened,
            self.exit_retire_late,
        )
    }

    /// Pending (transferred, not yet retired) exit taps.
    #[cfg(test)]
    pub(crate) fn pending_exit_taps_for_test(&self) -> usize {
        self.pending_exits.len()
    }
}
