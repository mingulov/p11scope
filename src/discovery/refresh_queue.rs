//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! One bounded refresh queue for every retry path (admission owner 3).
//!
//! Every refresh intent funnels through [`RefreshQueue::request`]:
//! requests retain their original age, each renewal gets a unique
//! serial so an older inventory pass cannot complete newer work, and
//! completion drops exactly the snapshot-matching non-failed set.
//! The queue decides admit/refuse/relieve/reclaim/complete; the
//! engine files the disclosure the decision returns.

use super::scheduler::MAX_PENDING_REFRESH;
use crate::process::{ProcessView, ProcessViewId};
use std::collections::{BTreeMap, BTreeSet};

/// Fair-queue relief examinations per pass: one full sweep at most,
/// never an unbounded `/proc` scan per arrival.
pub const RELIEF_SCAN_PER_PASS: u32 = 256;

/// Why one view's committed pins may go: the only retirement
/// justifications the lifecycle admits. A failed rescan is NOT
/// proof — it is unrepresentable here by construction — and keeps
/// the committed pins with a named gap instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetirementProof {
    /// The original generation provably exited (two-way dead).
    Exited,
    /// Observer management ended tracking (capacity eviction,
    /// scope removal, publication restore): re-admit re-proves.
    OperatorRemoval,
    /// The generation provably changed under the view (exec):
    /// old pins are superseded, never carried.
    IdentityChanged,
}

/// Classifies one view's retirement justification from live state:
/// untracked views follow their views out (management); provably
/// exited originals carry [`RetirementProof::Exited`] (reuse proves
/// the original is gone); a live-same generation retires only by
/// management decision; an unreadable generation yields nothing —
/// fail closed (keep pins + named gap at the call site).
pub(crate) fn classify_retirement(
    tracked: bool,
    state: Result<crate::process::OriginalGenerationState, String>,
) -> Option<RetirementProof> {
    use crate::process::OriginalGenerationState::{Current, Exited, Reused};
    if !tracked {
        return Some(RetirementProof::OperatorRemoval);
    }
    match state {
        Ok(Exited) | Ok(Reused) => Some(RetirementProof::Exited),
        Ok(Current) => Some(RetirementProof::OperatorRemoval),
        Err(_) => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RefreshRequest {
    pub(crate) first_seen_ns: Option<u64>,
    /// Latest renewal evidence: the arrival clock of the most recent
    /// (re-)queue for this pid. Queue age (`first_seen_ns`)
    /// schedules; this stamp proves generation: an exit reclaims the
    /// entry only when every stamp predates it, so a successor's
    /// renewal keeps the request alive across a deferred old exit.
    /// Unknown clocks keep the work (fail-closed).
    pub(crate) renewed_ns: Option<u64>,
    pub(crate) serial: u64,
    pub(crate) owner: Option<ProcessViewId>,
    pub(crate) exec_binding: Option<crate::attach::ExecBinding>,
    // The matched, bound EXEC's kernel hook clock, never its arrival clock.
    pub(crate) exec_hook_ts_ns: Option<u64>,
    // Windowed as a fresh newcomer (or into the admission window) but the
    // tick quantum expired before any attempt: the request keeps fresh
    // priority on the NEXT scarce tick instead of demoting to backlog by
    // arrival age alone behind the whole queue. One extra tick only:
    // classification consumes the flag into `fresh_carry_spent`, and a
    // spent carry-over cannot be re-earned, so a persistently
    // unattempted pid cannot bloat the fresh class and starve later
    // arrivals.
    pub(crate) deferred_fresh: bool,
    // The one-tick carry-over above has been spent: this request no
    // longer qualifies as fresh through `deferred_fresh` and cannot
    // earn it again (preserved across serial renewal like the flag).
    pub(crate) fresh_carry_spent: bool,
}

/// What one queue intake decided. Filing (marks, counters, age notes,
/// re-arm markers) stays with the engine; the queue only decides.
pub(crate) enum RefreshIntake {
    Accepted {
        serial: u64,
        owner: Option<ProcessViewId>,
        /// A fresh insert (new serial) as opposed to a retained
        /// existing entry: only inserts advance re-arm markers.
        inserted: bool,
    },
    QueueFull {
        consumed: bool,
    },
    SerialsExhausted {
        consumed: bool,
        existing_first_seen: Option<u64>,
    },
}

#[derive(Debug)]
pub(crate) struct RefreshQueue {
    queue: BTreeMap<u32, RefreshRequest>,
    last_serial: u64,
    relief_allowance: u32,
}

impl RefreshQueue {
    /// A fresh queue with a full relief sweep.
    pub(crate) fn new() -> Self {
        Self {
            queue: BTreeMap::new(),
            last_serial: 0,
            relief_allowance: RELIEF_SCAN_PER_PASS,
        }
    }

    /// A new pass restores the relief sweep.
    pub(crate) fn begin_pass(&mut self) {
        self.relief_allowance = RELIEF_SCAN_PER_PASS;
    }

    /// Queues (or re-queues) one refresh intent: consumed records
    /// renew (fresh serial, restamped renewal clock) so completion
    /// drops exactly the snapshot set, while retry re-queues are
    /// idempotent signals (no new state: the exec re-arm protocol
    /// pins prepared serials, so retries must not churn them). A
    /// full queue relieves one departed ownerless entry for a live
    /// waiter before refusing. `views` resolves owners and judges
    /// liveness; `collected_finish` tells whether the stop-time
    /// collected finish (no service pass) is running.
    pub(crate) fn request(
        &mut self,
        pid: u32,
        now_ns: Option<u64>,
        consumed: bool,
        owner: Option<ProcessViewId>,
        views: &[ProcessView],
        collected_finish: bool,
    ) -> RefreshIntake {
        let existing = self.queue.get(&pid).cloned();
        if existing.is_some() && !consumed {
            return RefreshIntake::Accepted {
                serial: existing.as_ref().map_or(0, |request| request.serial),
                owner: existing.as_ref().and_then(|request| request.owner),
                inserted: false,
            };
        }
        if existing.is_none()
            && self.queue.len() >= MAX_PENDING_REFRESH
            && self.relieve_one(pid, views, collected_finish).is_none()
        {
            return RefreshIntake::QueueFull { consumed };
        }
        let Some(serial) = self.last_serial.checked_add(1) else {
            return RefreshIntake::SerialsExhausted {
                consumed,
                existing_first_seen: existing.as_ref().and_then(|request| request.first_seen_ns),
            };
        };
        self.last_serial = serial;
        let owner = owner.or_else(|| {
            views
                .iter()
                .find(|view| view.pid() == pid && view.still_the_same())
                .map(ProcessView::id)
        });
        self.queue.insert(
            pid,
            RefreshRequest {
                first_seen_ns: existing
                    .as_ref()
                    .map_or(now_ns, |request| request.first_seen_ns),
                renewed_ns: now_ns,
                serial,
                owner,
                exec_binding: None,
                exec_hook_ts_ns: None,
                deferred_fresh: existing
                    .as_ref()
                    .is_some_and(|request| request.deferred_fresh),
                fresh_carry_spent: existing
                    .as_ref()
                    .is_some_and(|request| request.fresh_carry_spent),
            },
        );
        RefreshIntake::Accepted {
            serial,
            owner,
            inserted: true,
        }
    }

    /// Fair-queue relief: a live waiter's request evicts one departed,
    /// ownerless queue entry instead of refusing. Departed entries can
    /// never be serviced; without relief a full queue of short-lived
    /// dead pids starves a late provider's holder unboundedly. Only
    /// entries with no retained owner, no view, and no /proc directory
    /// are evicted, so live pressure waiters keep their pinned
    /// retention. A departed newcomer never triggers relief (it would
    /// only churn the queue). A zombie leader keeps its /proc entry
    /// while a worker still runs, so path liveness retains the whole
    /// live group. Relief is live-operation only: during the
    /// collected finish at stop no refresh service pass runs, so an
    /// admitted head would sit unserviced; refuse it instead. The
    /// sweep spends the per-pass allowance one `/proc` examination at
    /// a time and stops at zero, so arrivals past one full sweep per
    /// pass refuse without scanning; the refused work defers (it is
    /// never dropped as loss) and retries next pass.
    pub(crate) fn relieve_one(
        &mut self,
        waiter: u32,
        views: &[ProcessView],
        collected_finish: bool,
    ) -> Option<u32> {
        if collected_finish || self.relief_allowance == 0 {
            return None;
        }
        let waiter_live = views.iter().any(|view| view.pid() == waiter);
        let newcomer_live = waiter_live || {
            self.relief_allowance -= 1;
            std::path::Path::new(&format!("/proc/{waiter}")).exists()
        };
        if !newcomer_live {
            return None;
        }
        let mut victim = None;
        for (qpid, request) in self.queue.iter() {
            if request.owner.is_some() || views.iter().any(|view| view.pid() == *qpid) {
                continue;
            }
            if self.relief_allowance == 0 {
                break;
            }
            self.relief_allowance -= 1;
            if !std::path::Path::new(&format!("/proc/{qpid}")).exists() {
                victim = Some(*qpid);
                break;
            }
        }
        if let Some(victim) = victim {
            self.queue.remove(&victim);
        }
        victim
    }

    /// Reclaims the bounded slot of an ownerless request whose every
    /// stamp predates a matched exit: that generation ended and the
    /// entry can never be serviced. A successor's renewal, unknown
    /// clocks and owned entries keep the work (fail-closed).
    pub(crate) fn reclaim_on_exit(&mut self, pid: u32, hook_ts: u64) -> bool {
        let reclaims = self.queue.get(&pid).is_some_and(|request| {
            request.owner.is_none()
                && request.first_seen_ns.is_some_and(|seen| seen < hook_ts)
                && request.renewed_ns.is_some_and(|renewed| renewed < hook_ts)
        });
        if reclaims {
            self.queue.remove(&pid);
        }
        reclaims
    }

    /// Drops the queued refresh for `pid` when it belongs to `view`
    /// (owned entries retire with their view).
    pub(crate) fn clear_for_view(&mut self, view: ProcessViewId, pid: u32) {
        if self
            .queue
            .get(&pid)
            .is_some_and(|request| request.owner == Some(view))
        {
            self.queue.remove(&pid);
        }
    }

    /// The service-start snapshot: pid to the serial the pass may complete.
    pub(crate) fn snapshot(&self) -> BTreeMap<u32, u64> {
        self.queue
            .iter()
            .map(|(pid, request)| (*pid, request.serial))
            .collect()
    }

    /// Completes a service pass: entries whose serial still matches the
    /// snapshot and that did not fail leave the queue; re-queued
    /// (renewed serial) and failed entries stay.
    pub(crate) fn complete(&mut self, serviced: &BTreeMap<u32, u64>, failed: &BTreeSet<u32>) {
        self.queue.retain(|pid, request| {
            failed.contains(pid) || serviced.get(pid) != Some(&request.serial)
        });
    }

    pub(crate) fn get(&self, pid: &u32) -> Option<&RefreshRequest> {
        self.queue.get(pid)
    }

    pub(crate) fn get_mut(&mut self, pid: &u32) -> Option<&mut RefreshRequest> {
        self.queue.get_mut(pid)
    }

    pub(crate) fn contains_key(&self, pid: &u32) -> bool {
        self.queue.contains_key(pid)
    }

    pub(crate) fn len(&self) -> usize {
        self.queue.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub(crate) fn iter(&self) -> std::collections::btree_map::Iter<'_, u32, RefreshRequest> {
        self.queue.iter()
    }

    pub(crate) fn keys(&self) -> std::collections::btree_map::Keys<'_, u32, RefreshRequest> {
        self.queue.keys()
    }

    pub(crate) fn values(&self) -> std::collections::btree_map::Values<'_, u32, RefreshRequest> {
        self.queue.values()
    }

    /// Test-only full-map snapshot (before/after comparisons).
    #[cfg(test)]
    pub(crate) fn snapshot_map_for_test(&self) -> BTreeMap<u32, RefreshRequest> {
        self.queue.clone()
    }

    /// Test-only staging: drops one entry unconditionally.
    #[cfg(test)]
    pub(crate) fn remove_for_test(&mut self, pid: &u32) {
        self.queue.remove(pid);
    }

    /// Test-only staging: empties the queue unconditionally.
    #[cfg(test)]
    pub(crate) fn clear_for_test(&mut self) {
        self.queue.clear();
    }

    /// Test-only serial inspection (serial pins in service tests).
    #[cfg(test)]
    pub(crate) fn last_serial_for_test(&self) -> u64 {
        self.last_serial
    }

    /// Test-only serial staging (serial-exhaustion twins).
    #[cfg(test)]
    pub(crate) fn set_last_serial_for_test(&mut self, serial: u64) {
        self.last_serial = serial;
    }

    /// Test-only relief allowance inspection.
    #[cfg(test)]
    pub(crate) fn relief_allowance_for_test(&self) -> u32 {
        self.relief_allowance
    }

    /// Test-only relief allowance staging (bound twins).
    #[cfg(test)]
    pub(crate) fn set_relief_allowance_for_test(&mut self, allowance: u32) {
        self.relief_allowance = allowance;
    }

    /// Test-only staging: retains entries matching the predicate.
    #[cfg(test)]
    pub(crate) fn retain_for_test(&mut self, mut keep: impl FnMut(&u32, &RefreshRequest) -> bool) {
        self.queue.retain(|pid, request| keep(pid, request));
    }
}

impl std::ops::Index<&u32> for RefreshQueue {
    type Output = RefreshRequest;

    fn index(&self, pid: &u32) -> &Self::Output {
        &self.queue[pid]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Owner 3b table: the retirement prover maps live state to
    /// the one justification it admits, or nothing when the
    /// generation is unreadable (fail closed: keep pins + named
    /// gap). Untracked views follow their views out (management);
    /// provably exited originals carry Exited (reuse proves the
    /// original is gone); a live-same generation retires only by
    /// management decision (capacity eviction); exec-changed
    /// generations carry IdentityChanged. Replace/prune N/A: only
    /// successful scans yield refreshed tuples (failures land in
    /// `failed_scan_pids` + rows), so their incoming is proven by
    /// construction.
    #[test]
    fn admission_owner3b_retirement_proofs() {
        use super::{RetirementProof, classify_retirement};
        use crate::process::OriginalGenerationState::{Current, Exited, Reused};
        // Untracked views follow their views out whatever the pins say.
        for state in [
            Ok(Current),
            Ok(Exited),
            Ok(Reused),
            Err("unreadable".to_string()),
        ] {
            assert_eq!(
                classify_retirement(false, state.clone()),
                Some(RetirementProof::OperatorRemoval),
                "untracked: {state:?}"
            );
        }
        // A provably exited original carries Exited; reuse proves
        // the original is gone, so it carries Exited too.
        for state in [Ok(Exited), Ok(Reused)] {
            assert_eq!(
                classify_retirement(true, state.clone()),
                Some(RetirementProof::Exited),
                "gone: {state:?}"
            );
        }
        // A live-same generation retires only by management decision
        // (capacity eviction); re-admit re-proves.
        assert_eq!(
            classify_retirement(true, Ok(Current)),
            Some(RetirementProof::OperatorRemoval)
        );
        // An unreadable generation keeps its pins (fail closed).
        assert_eq!(
            classify_retirement(true, Err("unreadable".to_string())),
            None
        );
    }

    /// Move pin (3a1): intake/complete/snapshot/clear round-trip
    /// through the seam (consumed renewals take a fresh serial,
    /// retries are idempotent; completion drops exactly the serviced
    /// set).
    #[test]
    fn refresh_queue_round_trip() {
        let mut queue = RefreshQueue::new();
        assert!(queue.is_empty());
        let views: Vec<ProcessView> = Vec::new();
        let intake = queue.request(10, Some(100), false, None, &views, false);
        assert!(matches!(
            intake,
            RefreshIntake::Accepted {
                serial: 1,
                owner: None,
                inserted: true,
            }
        ));
        let intake = queue.request(10, Some(200), false, None, &views, false);
        assert!(
            matches!(
                intake,
                RefreshIntake::Accepted {
                    serial: 1,
                    inserted: false,
                    ..
                }
            ),
            "a retry re-queue retains without a new serial"
        );
        assert_eq!(queue.get(&10).unwrap().first_seen_ns, Some(100));
        let intake = queue.request(10, Some(200), true, None, &views, false);
        assert!(
            matches!(
                intake,
                RefreshIntake::Accepted {
                    serial: 2,
                    inserted: true,
                    ..
                }
            ),
            "a consumed renewal bumps the serial"
        );
        let snap = queue.snapshot();
        assert_eq!(snap.get(&10), Some(&2));
        queue.request(20, Some(200), false, None, &views, false);
        queue.complete(&snap, &BTreeSet::new());
        assert!(queue.get(&10).is_none());
        assert!(queue.get(&20).is_some());
        let snap = queue.snapshot();
        queue.complete(&snap, &BTreeSet::from([20]));
        assert!(queue.get(&20).is_some(), "failed entries stay queued");
        queue.request(30, Some(200), false, Some(ProcessViewId(7)), &views, false);
        queue.clear_for_view(ProcessViewId(8), 30);
        assert!(queue.get(&30).is_some(), "a foreign view clears nothing");
        queue.clear_for_view(ProcessViewId(7), 30);
        assert!(queue.get(&30).is_none());
    }

    /// Move pin (3a1): a full queue relieves one departed ownerless
    /// entry for a live waiter; serial exhaustion refuses. (Fake pids
    /// have no `/proc` directory and no views, so they relieve
    /// deterministically.)
    #[test]
    fn refresh_queue_relief_and_serial_exhaustion() {
        let mut queue = RefreshQueue::new();
        let views: Vec<ProcessView> = Vec::new();
        for offset in 0..MAX_PENDING_REFRESH {
            let pid = 4_000_000 + offset as u32;
            let intake = queue.request(pid, Some(100), false, None, &views, false);
            assert!(matches!(intake, RefreshIntake::Accepted { .. }));
        }
        assert_eq!(queue.len(), MAX_PENDING_REFRESH);
        // The waiter is live (its own view carries it); relief evicts
        // one departed entry and the waiter queues.
        let me = std::process::id();
        let views = vec![ProcessView::open(ProcessViewId(0), me).unwrap()];
        let intake = queue.request(me, Some(200), false, None, &views, false);
        assert!(
            matches!(intake, RefreshIntake::Accepted { .. }),
            "relief evicts a departed entry for the waiter"
        );
        assert_eq!(queue.len(), MAX_PENDING_REFRESH);
        // Serial exhaustion refuses even an existing entry's renewal.
        queue.set_last_serial_for_test(u64::MAX);
        let intake = queue.request(me, Some(200), true, None, &views, false);
        assert!(
            matches!(intake, RefreshIntake::SerialsExhausted { .. }),
            "exhausted serials refuse"
        );
    }

    /// Owner 3a2 table: one queue, one serial rule, one reclaim rule,
    /// one relief bound. Consumed records renew (fresh serial, so
    /// completion drops exactly the snapshot set) while retry
    /// re-queues are idempotent (the exec re-arm protocol pins
    /// prepared serials); every insert stamps the renewal clock; a
    /// matched exit reclaims only ownerless entries whose every stamp
    /// predates it (a successor's renewal and unknown clocks keep the
    /// work); relief examines at most one full sweep per pass; the
    /// cap stays 256.
    #[test]
    fn admission_owner3a2_queue_invariants() {
        // Serials: a consumed re-queue bumps, so a request renewed
        // during service survives that service's completion; a retry
        // re-queue is an idempotent signal the service consumes.
        let mut queue = RefreshQueue::new();
        let views: Vec<ProcessView> = Vec::new();
        queue.request(10, Some(100), false, None, &views, false);
        let snap = queue.snapshot();
        queue.request(10, Some(100), true, None, &views, false);
        assert_eq!(
            queue.snapshot().get(&10),
            Some(&2),
            "a consumed re-queue takes a fresh serial"
        );
        queue.complete(&snap, &BTreeSet::new());
        assert!(
            queue.get(&10).is_some(),
            "renewed-during-service survives completion"
        );
        queue.request(10, Some(100), false, None, &views, false);
        assert_eq!(
            queue.snapshot().get(&10),
            Some(&2),
            "a retry re-queue adds no new serial"
        );
        queue.complete(&queue.snapshot(), &BTreeSet::new());
        assert!(
            queue.get(&10).is_none(),
            "an unrenewed retry is consumed by service"
        );
        // Renewal stamps: inserts stamp now; re-queues restamp the
        // renewal clock but keep the scheduling age.
        let mut queue = RefreshQueue::new();
        queue.request(10, Some(100), false, None, &views, false);
        assert_eq!(queue.get(&10).unwrap().renewed_ns, Some(100));
        queue.request(10, Some(200), true, None, &views, false);
        let renewed = queue.get(&10).unwrap();
        assert_eq!(renewed.first_seen_ns, Some(100));
        assert_eq!(renewed.renewed_ns, Some(200));
        // Reclaim: only ownerless entries whose every stamp predates
        // the matched exit go; successors, unknown clocks and owned
        // entries stay.
        let mut queue = RefreshQueue::new();
        queue.request(11, Some(100), false, None, &views, false);
        assert!(queue.reclaim_on_exit(11, 200));
        assert!(queue.get(&11).is_none());
        let mut queue = RefreshQueue::new();
        queue.request(12, Some(100), false, None, &views, false);
        queue.request(12, Some(300), true, None, &views, false);
        assert!(
            !queue.reclaim_on_exit(12, 200),
            "a successor's renewal keeps the request across a deferred old exit"
        );
        assert!(queue.get(&12).is_some());
        let mut queue = RefreshQueue::new();
        queue.request(13, None, false, None, &views, false);
        assert!(
            !queue.reclaim_on_exit(13, 200),
            "unknown clocks keep the work"
        );
        let mut queue = RefreshQueue::new();
        queue.request(14, Some(100), false, Some(ProcessViewId(7)), &views, false);
        assert!(
            !queue.reclaim_on_exit(14, 200),
            "owned entries retire with their view"
        );
        // Relief bound: one full sweep per pass; exhaustion refuses
        // even with a victim present; the next pass restores.
        assert_eq!(
            super::RELIEF_SCAN_PER_PASS,
            256,
            "the relief sweep covers the queue once per pass"
        );
        assert_eq!(
            MAX_PENDING_REFRESH, 256,
            "the queue cap stays 256 (pressure #136/#137)"
        );
        let mut queue = RefreshQueue::new();
        assert_eq!(queue.relief_allowance_for_test(), 256);
        // Self sorts first (real pids < 5M fake floor): ownerless,
        // viewless, present in /proc — examined, never evicted.
        let live = std::process::id();
        queue.request(live, Some(100), false, None, &views, false);
        queue.request(5_000_000, Some(100), false, None, &views, false);
        queue.set_relief_allowance_for_test(1);
        assert_eq!(
            queue.relieve_one(1, &views, false),
            None,
            "an exhausted sweep leaves even a present victim unexamined"
        );
        assert_eq!(queue.relief_allowance_for_test(), 0);
        queue.begin_pass();
        assert_eq!(queue.relief_allowance_for_test(), 256);
        assert_eq!(
            queue.relieve_one(1, &views, false),
            Some(5_000_000),
            "the next pass examines and evicts the victim"
        );
        assert!(queue.get(&5_000_000).is_none());
    }
}
