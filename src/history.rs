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
    /// Zero means birth unknown (an unstamped pre-fix FORK): it never
    /// matches an exit while ambiguous (see [`Registry::match_exit_tap`])
    /// and upgrades to the first nonzero event time, which the
    /// generation provably lived to see.
    first_ts_ns: u64,
    /// A zero `first_ts_ns` that came from an exec-id bump (the first
    /// post-exec event was an unstamped FORK): the pre-exec leader exit
    /// must never retire the live post-exec generation, so an exit
    /// never matches while this is set. Cleared by the upgrade above.
    /// Only ever set with `first_ts_ns == 0`. Defence in depth: with
    /// the BPF fork stamp in place the producer never emits an
    /// unstamped FORK, so this path is test-only unless the stamp is
    /// ever lost — and then it still spares the live generation.
    birth_unknown_from_exec: bool,
    /// The process's last live session-pseudonym counter, stashed at
    /// every increment. The task is never freed, so a reopen or late
    /// event reseeds from this instead of relabeling from `#1` (which
    /// would reuse a retired session's label). An exec bump clears it:
    /// the new image restarts numbering at #1. Zero means never stashed.
    next_pseudonym: u64,
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
/// counted gap. `synthetic` marks a late-event re-arm (see
/// `late_reap`): it matches only still-retired tasks and drops
/// silently when it matches nothing — never unmatched, never retried.
struct PendingExit {
    tap: ExitTap,
    tap_producer: usize,
    passes: u8,
    synthetic: bool,
}

/// Bound on tapped exits held anywhere: the engine tap queue and the
/// tracker's pending queue each hold at most this many. Transfer
/// moves only what fits, so drops happen only at tap time and count
/// in exactly one place (`exit_tap_overflow` on the engine).
pub(crate) const EXIT_TAP_QUEUE_LIMIT: usize = 16_384;

/// Position-passing drains an unmatched exit survives before it
/// drops with the counted `exit_retire_unmatched` gap. In the final
/// drain (`final_drain == true`, end of run), unmatched exits are
/// dropped on first look instead of retrying.
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
    /// Admitted `(pid, task cookie)` pairs, queried by pid range. Exit
    /// matching walks only this pid's cookies instead of scanning all
    /// tasks. Flat (one entry per open task, no per-pid set shells):
    /// matched exits prune their cookies, and reopen/late/exec-bump
    /// events re-insert, so only matchable tasks stay indexed. Bounded
    /// by the task limit; counted in the A0 lens.
    pid_index: BTreeSet<(u32, u64)>,
    /// Transferred exits not yet retired, in tap order (tap-time
    /// producer stamps are non-decreasing down the queue).
    pending_exits: VecDeque<PendingExit>,
    /// `(pid, exit hook)` pairs armed by late events: a late event
    /// re-creates State rows for an exit-retired task, and with no
    /// later real exit those rows would leak. Each pair becomes one
    /// synthetic exit stamped with the producer position current at
    /// the next retire (see `retire_exits_due`), which reaps exactly
    /// those rows once the drain reads past it. A set: any number of
    /// late events on one retired task arm a single re-arm.
    late_reap: BTreeSet<(u32, u64)>,
    /// Exit-matched tasks skipped on a `first_ts_ns == hook_ts_ns`
    /// tie: neither generation is provably older, so neither retires.
    /// The exit drops immediately with this counted outcome — no retry,
    /// never unmatched.
    exit_tie_skipped: u64,
    /// Due exits dropped after [`EXIT_UNMATCHED_RETRIES`] retries (or
    /// on first look in the final drain, `final_drain == true` at end
    /// of run) with no matching task and no tie (never-admitted
    /// processes own no rows). Ties drop immediately and never count
    /// here.
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
            pid_index: BTreeSet::new(),
            pending_exits: VecDeque::new(),
            late_reap: BTreeSet::new(),
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
            pid_index: BTreeSet::new(),
            pending_exits: VecDeque::new(),
            late_reap: BTreeSet::new(),
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
    /// A0 lens (R9): admitted task cookies ever, plus the pid index
    /// that finds them. Read-only; the registry never evicts (the
    /// 262,144 cliff), so the task count only grows, while the index
    /// entry count follows prunes and re-inserts. `len` counts tasks;
    /// `bytes` covers both maps, so per-task bytes explain the index.
    pub(crate) fn memory_tasks_row(&self) -> crate::memory_counters::CounterRow {
        let tasks = crate::memory_counters::counter_row(
            self.tasks.len(),
            std::mem::size_of::<(u64, Task)>(),
            crate::memory_counters::HEAP_MAP_ENTRY,
        );
        let index = crate::memory_counters::counter_row(
            self.pid_index.len(),
            std::mem::size_of::<(u32, u64)>(),
            crate::memory_counters::HEAP_MAP_ENTRY,
        );
        crate::memory_counters::CounterRow {
            len: tasks.len,
            bytes: tasks.bytes.saturating_add(index.bytes),
        }
    }
    /// The domain comes from the sole retained EVENTS consumer, never a wire
    /// field or a live process lookup. The producer authenticates the tuple.
    /// `event_ts_ns` is the admitting event's kernel time, recorded as
    /// the task generation's `first_ts_ns` for exit matching (reset on
    /// exec-id bump). A zero first time is birth unknown: it upgrades to
    /// the first nonzero event time on the same generation. An event on
    /// an exit-retired cookie reopens the task when timestamped after
    /// the exit (clearing the exit timestamp, counted) or counts late
    /// when at or before it — the exit path never sets `closed`, so
    /// both still admit. The third return tells the caller to reseed
    /// per-process continuity from the task's sticky copy (reopen or
    /// late only; an exec bump restarts numbering at #1).
    pub(crate) fn admit(
        &mut self,
        domain: u64,
        pid: u32,
        image: ImageIdentity,
        event_ts_ns: u64,
    ) -> (Option<ProcessKey>, Vec<ProcessKey>, bool) {
        let mut retired = Vec::new();
        // Continuity reseed: the admitted key continues an exit-retired
        // (reopen/late) generation, so the caller reseeds per-process
        // continuity (the pseudonym counter) from the task's sticky
        // copy. False for fresh, steady, exec-bump and refused admits,
        // which never need it (a bump restarts numbering at #1).
        let mut reseed = false;
        if domain == 0 || domain != self.domain() || image.task_cookie == 0 || pid == 0 {
            return (None, retired, reseed);
        }
        if let Some(task) = self.tasks.get_mut(&image.task_cookie) {
            if task.closed || image.exec_id < task.key.exec_id {
                return (None, retired, reseed);
            }
            if image.exec_id > task.key.exec_id {
                retired.push(task.key);
                task.key = ProcessKey::history(domain, image.task_cookie, image.exec_id, pid);
                task.called = false;
                task.forked = false;
                task.first_ts_ns = event_ts_ns;
                task.birth_unknown_from_exec = event_ts_ns == 0;
                task.exit_ts_ns = None;
                // Pre-B1: an exec restarts session numbering at #1. The
                // bump never reseeds, and the old image's stash is
                // cleared so a later reopen of the new generation cannot
                // seed from it (the new image's own increments re-stash).
                task.next_pseudonym = 0;
                // A pruned-then-bumped task is matchable again under its
                // new generation: re-insert (idempotent when present).
                self.pid_index.insert((pid, image.task_cookie));
            } else if let Some(exit) = task.exit_ts_ns {
                // A live thread on a retired cookie: after the exit the
                // task reopens (the timestamp clears, the event admits);
                // at or before it the event is late (admitted too, the
                // timestamp stays). Never refused either way.
                if event_ts_ns > exit {
                    task.exit_ts_ns = None;
                    self.exit_retire_reopened = self.exit_retire_reopened.saturating_add(1);
                } else {
                    self.exit_retire_late = self.exit_retire_late.saturating_add(1);
                    // The late event re-creates State rows with no later
                    // real exit to free them: re-arm a synthetic exit so
                    // the next retire reaps them (see `late_reap`).
                    self.late_reap.insert((pid, exit));
                }
                reseed = true;
                // A reopened or late event proves the pruned cookie live
                // again: re-insert, so a later exit can match it.
                self.pid_index.insert((pid, image.task_cookie));
                // A birth-unknown generation provably lived to this
                // event: upgrade, so a pre-birth exit can no longer
                // match it while a later real exit still can.
                if task.first_ts_ns == 0 && event_ts_ns != 0 {
                    task.first_ts_ns = event_ts_ns;
                    task.birth_unknown_from_exec = false;
                }
            } else if task.first_ts_ns == 0 && event_ts_ns != 0 {
                // Same upgrade on the steady path: the generation outlived
                // any exit older than this event, so matching those would
                // retire a live task.
                task.first_ts_ns = event_ts_ns;
                task.birth_unknown_from_exec = false;
            }
            return (Some(task.key), retired, reseed);
        }
        if self.tasks.len() >= self.limit {
            return (None, retired, reseed);
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
                birth_unknown_from_exec: false,
                next_pseudonym: 0,
                exit_ts_ns: None,
            },
        );
        self.pid_index.insert((pid, image.task_cookie));
        (Some(key), retired, reseed)
    }

    /// Stashes the live session-pseudonym counter on the task, which is
    /// never freed: a later reopen or late event on the same cookie
    /// reseeds from it. Exact-key like every other mutator, so a stale
    /// key can never clobber the live generation's stash. Called at
    /// every counter increment (rare), never on the steady CALL path.
    pub(crate) fn save_pseudonym_counter(&mut self, key: ProcessKey, counter: u64) {
        if let Some(task) = self.tasks.get_mut(&key.generation)
            && task.key == key
        {
            task.next_pseudonym = counter;
        }
    }

    /// The stashed counter for `key`'s task, if any was ever stashed.
    /// Exact-key: only the live generation reseeds from its own stash.
    pub(crate) fn sticky_pseudonym_counter(&self, key: ProcessKey) -> Option<u64> {
        self.tasks
            .get(&key.generation)
            .filter(|task| task.key == key)
            .map(|task| task.next_pseudonym)
            .filter(|counter| *counter > 0)
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
                synthetic: false,
            });
        }
    }

    /// Collects the process keys whose exits are due: the drain has
    /// read past the tap-time producer position with no uncommitted
    /// record before it. Late-event re-arms convert first, each stamped
    /// with the current producer position (only what fits; the rest
    /// waits for the next retire). Examines at most `budget` exits per
    /// call; the rest carry over to the next drain. Matched tasks
    /// record the exit hook time (never `closed`); ties drop
    /// immediately with their own counted outcome (no retry, never
    /// unmatched); other unmatched exits retry, then drop with a
    /// counted gap — except in `final_drain` mode, where no later
    /// record can admit a match, so they drop counted on first look
    /// instead of requeueing. Synthetic re-arms that match nothing
    /// drop silently.
    pub(crate) fn retire_exits_due(
        &mut self,
        consumer_now: usize,
        producer_now: usize,
        budget: usize,
        final_drain: bool,
    ) -> BTreeSet<ProcessKey> {
        // Late-event re-arms become synthetic exits stamped with the
        // current producer position (the producer only grows, so the
        // queue's non-decreasing stamp order is preserved).
        while self.pending_exits.len() < EXIT_TAP_QUEUE_LIMIT {
            let Some((pid, hook)) = self.late_reap.pop_first() else {
                break;
            };
            self.pending_exits.push_back(PendingExit {
                tap: ExitTap {
                    pid,
                    hook_ts_ns: hook,
                },
                tap_producer: producer_now,
                passes: 0,
                synthetic: true,
            });
        }
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
            let (matched, tie_seen) = self.match_exit_tap(&pending.tap, pending.synthetic);
            if !matched.is_empty() {
                due.extend(matched);
            } else if pending.synthetic {
                // A synthetic re-arm that matches nothing reaps
                // nothing: the task reopened (live) or a sibling
                // re-arm already reaped it. Drop silently — never
                // unmatched, never retried.
            } else if tie_seen {
                // A tie can never match on retry: the tied task's
                // `first_ts` never becomes `< hook`, and any later admit
                // is a successor (`first_ts > hook`). The exit falls out
                // of scope here: dropped immediately with the counted tie
                // outcome, no requeue, never unmatched.
            } else if final_drain {
                // End of run: no later record can admit a match, so
                // retrying cannot help — and requeueing would stall the
                // terminal loop behind the unmatched block. Drop on
                // first look, counted like an exhausted retry, never
                // silently.
                self.exit_retire_unmatched = self.exit_retire_unmatched.saturating_add(1);
            } else {
                let mut pending = pending;
                pending.passes += 1;
                if pending.passes > EXIT_UNMATCHED_RETRIES {
                    self.exit_retire_unmatched = self.exit_retire_unmatched.saturating_add(1);
                } else {
                    keep.push(pending);
                }
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
    /// are spared. A birth-unknown (`first_ts_ns == 0`) task matches
    /// only when unambiguous — the pid's sole open cookie, and not
    /// from an exec bump (whose pre-exec leader exit must never retire
    /// the live post-exec generation); otherwise it counts as a tie.
    /// Returns the matched keys and whether any tie was seen (the
    /// caller drops tied-but-unmatched exits immediately). Matched
    /// tasks record the exit hook time — the earliest observed, so any
    /// post-exit event reopens — never the `closed` flag, so the next
    /// event is never refused; their index entries prune, so a repeated
    /// exit never re-collects them. A synthetic re-arm matches only
    /// still-retired tasks (its late rows exist only while the exit
    /// timestamp stands): live and reopened tasks are spared silently,
    /// and ties are not recounted (the original exit already counted
    /// them).
    fn match_exit_tap(&mut self, tap: &ExitTap, synthetic: bool) -> (Vec<ProcessKey>, bool) {
        let mut matched = Vec::new();
        let mut tie_seen = false;
        // The pid's cookies, copied: matching mutates tasks below.
        let cookies: Vec<u64> = self
            .pid_index
            .range((tap.pid, 0)..=(tap.pid, u64::MAX))
            .map(|(_, cookie)| *cookie)
            .collect();
        let open = cookies
            .iter()
            .filter(|cookie| self.tasks.get(cookie).is_some_and(|task| !task.closed))
            .count();
        for cookie in cookies {
            // A synthetic re-arm reaps only still-retired tasks: a
            // live or reopened task's rows are legitimately held.
            if synthetic
                && self
                    .tasks
                    .get(&cookie)
                    .is_none_or(|task| task.exit_ts_ns.is_none())
            {
                continue;
            }
            let unknown_ambiguous = self.tasks.get(&cookie).is_some_and(|task| {
                !task.closed && task.first_ts_ns == 0 && (task.birth_unknown_from_exec || open >= 2)
            });
            if unknown_ambiguous {
                if !synthetic {
                    self.exit_tie_skipped = self.exit_tie_skipped.saturating_add(1);
                }
                tie_seen = true;
                continue;
            }
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
                // A matched generation is retired: prune its index entry
                // so later exits never re-collect it. A reopen, late
                // event or exec bump re-inserts when the cookie proves
                // live again.
                self.pid_index.remove(&(tap.pid, cookie));
            } else if task.first_ts_ns == tap.hook_ts_ns {
                if !synthetic {
                    self.exit_tie_skipped = self.exit_tie_skipped.saturating_add(1);
                }
                tie_seen = true;
            }
        }
        (matched, tie_seen)
    }

    /// `(tie_skipped, unmatched, reopened, late)` exit gap counters,
    /// for the A0 sampler.
    pub(crate) fn exit_gap_counts(&self) -> (u64, u64, u64, u64) {
        (
            self.exit_tie_skipped,
            self.exit_retire_unmatched,
            self.exit_retire_reopened,
            self.exit_retire_late,
        )
    }

    /// `(tie_skipped, unmatched, reopened, late)` exit gap counters.
    #[cfg(test)]
    pub(crate) fn exit_counters_for_test(&self) -> (u64, u64, u64, u64) {
        self.exit_gap_counts()
    }

    /// Pending (transferred, not yet retired) exit taps, for the A0 sampler.
    pub(crate) fn pending_exit_taps(&self) -> usize {
        self.pending_exits.len()
    }

    /// Late-event re-arms not yet converted to synthetic exits. The
    /// terminal reap loops while either this or the pending queue is
    /// non-empty.
    pub(crate) fn pending_exit_marks(&self) -> usize {
        self.late_reap.len()
    }
}
