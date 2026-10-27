//! SPDX-License-Identifier: GPL-3.0-or-later
//! Pending leader exits are uncertainty, never an inferred live worker.

use super::*;
use crate::discovery::caller_registry::SharedCallerPin;
use crate::process::leader_exit::{LeaderExitObservation, LeaderExitReadBudget};
use crate::semantics_edge::resources::{OWNED_ALLOCATION_PADDING, ResourceLease};

pub(super) struct PendingLeaderExit<Pin> {
    pid: u32,
    hook_ns: u64,
    domain: NativeDomainId,
    pin: SharedCallerPin<Pin>,
    _storage: ResourceLease,
}

#[cfg(test)]
mod tests {
    use super::super::tests::NativeScene;
    use super::*;

    #[test]
    fn pending_exit_keeps_custody_then_accepts_a_later_worker_witness() {
        let (mut native, caller) = NativeScene::boxed();
        native
            .scene
            .source
            .set_leader_exit_observation(7, LeaderExitObservation::Unresolved);
        let before = native
            .scene
            .coordinator
            .registry
            .semantic_resource_snapshot()
            .charged_bytes;
        native
            .scene
            .coordinator
            .defer_leader_exit(caller, 7, 1_500, native.domain);
        native
            .scene
            .coordinator
            .retry_pending_leader_exits_with(&mut LeaderExitReadBudget::for_test(128));
        assert!(native.scene.coordinator.adapter.leader_exit_pending(caller));
        assert_eq!(native.scene.coordinator.pending_leader_exits.len(), 1);
        assert_eq!(
            native.scene.coordinator.adapter.live_pin(7).unwrap().1,
            &(7, 500)
        );
        assert!(
            !native
                .scene
                .coordinator
                .adapter
                .record(caller)
                .unwrap()
                .retired
        );
        assert!(
            native
                .scene
                .coordinator
                .registry
                .semantic_resource_snapshot()
                .charged_bytes
                > before
        );
        native
            .scene
            .source
            .set_leader_exit_observation(7, LeaderExitObservation::LiveNonleader);
        native
            .scene
            .coordinator
            .retry_pending_leader_exits_with(&mut LeaderExitReadBudget::for_test(128));
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(!native.scene.coordinator.adapter.leader_exit_pending(caller));
        assert!(native.scene.coordinator.pending_leader_exits.is_empty());
        assert_eq!(
            native
                .scene
                .coordinator
                .registry
                .semantic_resource_snapshot()
                .charged_bytes,
            before
        );
        assert_eq!(
            native
                .scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .filter(|gap| gap.subject == "leader task link loss")
                .count(),
            1
        );
    }

    #[test]
    fn pending_exit_scheduler_rotates_with_one_fixed_budget() {
        let (mut native, first) = NativeScene::boxed();
        native
            .scene
            .source
            .set_leader_exit_observation(7, LeaderExitObservation::Unresolved);
        native
            .scene
            .coordinator
            .defer_leader_exit(first, 7, 1_500, native.domain);
        for pid in 8..17 {
            native.scene.source.spawn(pid, 500 + u64::from(pid));
            let caller = native
                .scene
                .coordinator
                .adapter
                .admit(pid, ImageAuthority::ScanPinned, 50)
                .unwrap();
            native
                .scene
                .coordinator
                .defer_leader_exit(caller, pid, 1_500, native.domain);
        }
        native
            .scene
            .coordinator
            .retry_pending_leader_exits_with(&mut LeaderExitReadBudget::for_test(0));
        assert_eq!(native.scene.source.leader_exit_queries(), 0);
        assert_eq!(native.scene.coordinator.pending_leader_exits.len(), 10);
        native
            .scene
            .coordinator
            .retry_pending_leader_exits_with(&mut LeaderExitReadBudget::for_test(128));
        assert_eq!(
            native.scene.source.leader_exit_queries(),
            8,
            "at most eight callers in one commit"
        );
        for pid in [15, 16] {
            native
                .scene
                .source
                .set_leader_exit_observation(pid, LeaderExitObservation::LiveNonleader);
        }
        native
            .scene
            .coordinator
            .retry_pending_leader_exits_with(&mut LeaderExitReadBudget::for_test(128));
        assert_eq!(native.scene.source.leader_exit_queries(), 16);
        assert_eq!(
            native.scene.coordinator.pending_leader_exits.len(),
            8,
            "later callers are served despite unresolved early callers"
        );
    }

    #[test]
    fn pending_exit_storage_refusal_and_stop_keep_semantic_fence() {
        let (mut native, caller) = NativeScene::boxed();
        let charged = native
            .scene
            .coordinator
            .registry
            .semantic_resource_snapshot()
            .charged_bytes;
        native
            .scene
            .coordinator
            .registry
            .reference_semantic_resource_limit(charged);
        native
            .scene
            .coordinator
            .defer_leader_exit(caller, 7, 1_500, native.domain);
        assert!(native.scene.coordinator.pending_leader_exits.is_empty());
        assert!(native.scene.coordinator.adapter.leader_exit_pending(caller));
        native.scene.coordinator.stop();
        assert!(native.scene.coordinator.adapter.leader_exit_pending(caller));
        assert_eq!(
            native.scene.coordinator.adapter.live_pin(7).unwrap().1,
            &(7, 500)
        );
    }

    #[test]
    fn validated_exec_resolves_pending_before_custody_renewal() {
        let (mut native, caller) = NativeScene::boxed();
        native.answer(7, 500, 41);
        native.witness(vec![native.row(41, 1, 7, 100, 0)]);
        native
            .scene
            .source
            .set_leader_exit_observation(7, LeaderExitObservation::Unresolved);
        native
            .scene
            .coordinator
            .defer_leader_exit(caller, 7, 1_500, native.domain);
        native.scene.source.exec(7, 200, "/bin/other");
        native.scene.source.poison_reopen();
        let opens = native.scene.source.reopen_attempts();
        let events = native.witness(vec![native.row(41, 2, 7, 1_600, 1)]);
        let [CallerEvent::ExecRetired { old, new }] = events.as_slice() else {
            panic!("{events:?}");
        };
        assert_eq!(*old, caller);
        assert!(!native.scene.coordinator.adapter.leader_exit_pending(caller));
        assert!(!native.scene.coordinator.adapter.leader_exit_pending(*new));
        assert!(native.scene.coordinator.pending_leader_exits.is_empty());
        assert_eq!(
            native.scene.coordinator.adapter.live_pin(7).unwrap().1,
            &(7, 500)
        );
        assert_eq!(native.scene.source.reopen_attempts(), opens);
        assert!(
            !native
                .scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .any(|gap| gap.subject == "leader task link loss")
        );
    }

    #[test]
    fn stopped_exit_dispositions_share_one_budget_and_retain_no_retry_rows() {
        let (mut native, first) = NativeScene::boxed();
        native.scene.source.spawn(8, 600);
        native
            .scene
            .source
            .set_leader_exit_observation(8, LeaderExitObservation::LiveNonleader);
        let second = native
            .scene
            .coordinator
            .adapter
            .admit(8, ImageAuthority::ScanPinned, 50)
            .unwrap();
        native.scene.coordinator.stop();
        let mut shared_final_work = LeaderExitReadBudget::for_test(1);
        native.scene.coordinator.adjudicate_stopped_leader_exit(
            first,
            7,
            1_500,
            native.domain,
            &mut shared_final_work,
        );
        native.scene.coordinator.adjudicate_stopped_leader_exit(
            second,
            8,
            1_500,
            native.domain,
            &mut shared_final_work,
        );
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            native.scene.source.leader_exit_queries(),
            1,
            "the second record gets no fresh allowance"
        );
        assert!(native.scene.coordinator.pending_leader_exits.is_empty());
        assert!(!native.scene.coordinator.adapter.leader_exit_pending(first));
        assert!(native.scene.coordinator.adapter.leader_exit_pending(second));
        let gaps = native.scene.coordinator.registry.gaps();
        assert_eq!(
            gaps.iter()
                .filter(|gap| gap.caller == Some(first) && gap.subject == "leader task link loss")
                .count(),
            1
        );
        assert_eq!(
            gaps.iter()
                .filter(|gap| gap.caller == Some(second)
                    && gap.subject == "leader exit status unresolved at stop")
                .count(),
            1
        );
        assert_eq!(
            native.scene.coordinator.adapter.live_pin(8).unwrap().1,
            &(8, 600)
        );
    }

    #[test]
    fn stopped_unknown_exit_is_disposed_once_without_later_retry() {
        let (mut native, caller) = NativeScene::boxed();
        native
            .scene
            .source
            .set_leader_exit_observation(7, LeaderExitObservation::Unresolved);
        native.scene.coordinator.stop();
        native.scene.coordinator.adjudicate_stopped_leader_exit(
            caller,
            7,
            1_500,
            native.domain,
            &mut LeaderExitReadBudget::for_test(128),
        );
        native
            .scene
            .source
            .set_leader_exit_observation(7, LeaderExitObservation::LiveNonleader);
        native.scene.coordinator.adjudicate_stopped_leader_exit(
            caller,
            7,
            1_500,
            native.domain,
            &mut LeaderExitReadBudget::for_test(128),
        );
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(native.scene.source.leader_exit_queries(), 1);
        assert!(native.scene.coordinator.pending_leader_exits.is_empty());
        assert!(native.scene.coordinator.adapter.leader_exit_pending(caller));
        assert!(
            !native
                .scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .any(|gap| gap.subject == "leader task link loss")
        );
    }
}

impl<Source: ProcessSource> InventoryCoordinator<Source> {
    pub(super) fn defer_leader_exit(
        &mut self,
        caller: CallerId,
        pid: u32,
        hook_ns: u64,
        domain: NativeDomainId,
    ) {
        if self.leader_link_loss_noted.contains(&caller) || self.adapter.leader_exit_pending(caller)
        {
            return;
        }
        // This bit lives in the already charged caller. Failed row storage
        // cannot accidentally restore semantic authority.
        self.adapter.mark_leader_exit_pending(caller, true);
        let Some(pin) = self.adapter.share_caller_pin(caller) else {
            return;
        };
        let bytes = std::mem::size_of::<PendingLeaderExit<Source::Pin>>()
            + std::mem::size_of::<CallerId>()
            + 2 * OWNED_ALLOCATION_PADDING;
        let Ok(storage) = self.registry.reserve_semantic_storage(bytes) else {
            self.registry.record_gap(RegistryGap {
                caller: Some(caller), module: None, pid: Some(pid),
                subject: "leader exit adjudication refused".into(),
                reason: "pending-exit storage unavailable; original caller custody stays unresolved and semantic inputs refuse".into(),
                budget: None,
            });
            return;
        };
        self.pending_leader_exits.insert(
            caller,
            PendingLeaderExit {
                pid,
                hook_ns,
                domain,
                pin,
                _storage: storage,
            },
        );
    }

    pub(super) fn retry_pending_leader_exits(&mut self) {
        self.retry_pending_leader_exits_with(&mut LeaderExitReadBudget::for_commit());
    }

    fn retry_pending_leader_exits_with(&mut self, work: &mut LeaderExitReadBudget) {
        if self.stopped || self.pending_leader_exits.is_empty() {
            return;
        }
        // Fair bounded scheduling, without collecting the caller population
        // or walking the whole task set. One caller is tried once per commit.
        const CALLERS: usize = 8;
        let mut selected = [None; CALLERS];
        use std::ops::Bound::{Excluded, Included, Unbounded};
        let start = self.leader_exit_cursor.map_or(Unbounded, Excluded);
        let end = self.leader_exit_cursor.map_or(Unbounded, Included);
        let keys = self.pending_leader_exits.range((start, Unbounded)).chain(
            self.pending_leader_exits
                .range((Unbounded, end))
                .filter(|_| self.leader_exit_cursor.is_some()),
        );
        for (slot, (caller, _)) in selected.iter_mut().zip(keys) {
            *slot = Some(*caller);
        }
        for caller in selected.into_iter().flatten() {
            if !work.spend(1) {
                break;
            }
            self.leader_exit_cursor = Some(caller);
            let Some(pending) = self.pending_leader_exits.remove(&caller) else {
                continue;
            };
            if self.adapter.live_id(pending.pid) != Some(caller)
                || self.adapter.record(caller).is_none_or(|record| {
                    record.retired
                        || (self.exit_clocks_comparable && pending.hook_ns < record.admitted_ns)
                })
            {
                self.adapter.mark_leader_exit_pending(caller, false);
                continue;
            }
            match self
                .adapter
                .source()
                .leader_exit_observation(&pending.pin, work)
            {
                LeaderExitObservation::GroupExited => {
                    // The ordinary adapter retirement remains authoritative;
                    // no inferred survivor gap or tombstone is manufactured.
                    self.adapter.mark_leader_exit_pending(caller, false);
                }
                LeaderExitObservation::LiveNonleader => {
                    self.record_live_nonleader_loss(caller, pending.pid);
                }
                LeaderExitObservation::Unresolved => {
                    self.pending_leader_exits.insert(caller, pending);
                }
            }
        }
    }

    fn record_live_nonleader_loss(&mut self, caller: CallerId, pid: u32) {
        self.adapter.mark_leader_exit_pending(caller, false);
        if self.leader_link_loss_noted.insert(caller) {
            self.registry.record_gap(RegistryGap {
                caller: Some(caller), module: None, pid: Some(pid),
                subject: "leader task link loss".into(),
                reason: "the leader task exited while a same-generation nonleader was proven live and not exiting; original custody is retained with no tombstone, and a later EXEC may renew recovery".into(),
                budget: None,
            });
            if self.semantic_bindings.get(caller).is_some() {
                self.tail_uncertain.insert(caller);
            }
        }
    }

    pub(super) fn adjudicate_stopped_leader_exit(
        &mut self,
        caller: CallerId,
        pid: u32,
        hook_ns: u64,
        domain: NativeDomainId,
        work: &mut LeaderExitReadBudget,
    ) {
        if self.leader_link_loss_noted.contains(&caller) || self.adapter.leader_exit_pending(caller)
        {
            return;
        }
        self.adapter.mark_leader_exit_pending(caller, true);
        let observation = if work.spend(1) {
            self.adapter
                .share_caller_pin(caller)
                .map_or(LeaderExitObservation::Unresolved, |pin| {
                    self.adapter.source().leader_exit_observation(&pin, work)
                })
        } else {
            LeaderExitObservation::Unresolved
        };
        match observation {
            LeaderExitObservation::GroupExited => self.adapter.mark_leader_exit_pending(caller, false),
            LeaderExitObservation::LiveNonleader => self.record_live_nonleader_loss(caller, pid),
            LeaderExitObservation::Unresolved => self.registry.record_gap(RegistryGap {
                caller: Some(caller), module: None, pid: Some(pid),
                subject: "leader exit status unresolved at stop".into(),
                reason: format!("final hook={hook_ns} domain={domain:?} had no live-worker or group-exit proof within the shared final-batch allowance; semantic inputs retain custody refusal"),
                budget: None,
            }),
        }
        // No reservation, retry row or new retained pin survives this
        // final disposition. The caller bit keeps unproved inputs fenced.
    }

    pub(super) fn resolve_leader_exit_for_exec(&mut self, caller: CallerId) {
        if self.adapter.leader_exit_pending(caller) && self.semantic_bindings.get(caller).is_some()
        {
            self.tail_uncertain.insert(caller);
        }
        self.pending_leader_exits.remove(&caller);
        self.adapter.mark_leader_exit_pending(caller, false);
    }

    pub(super) fn stop_pending_leader_exits(&mut self) {
        let count = self.pending_leader_exits.len();
        // Retain the allocation-free fence through final H0 disposition.
        // Stop releases retry rows, not the caller's original custody.
        if let Some((caller, pending)) = self.pending_leader_exits.first_key_value() {
            self.registry.record_gap(RegistryGap {
                caller: Some(*caller), module: None, pid: Some(pending.pid),
                subject: "leader exit status unresolved at stop".into(),
                reason: format!("{count} pending leader exit(s) remain unknown; first hook={} domain={:?}; semantic inputs retain custody refusal", pending.hook_ns, pending.domain),
                budget: None,
            });
        }
        self.pending_leader_exits.clear();
    }
}
