//! SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::attach::{OwnedLink, ProducerProgram, RetirementFixture};
use std::cell::RefCell;
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

struct Case {
    child: std::process::Child,
    engine: Engine,
    session: ScriptedSession,
    modules: Vec<ScannedModule>,
    release: Arc<(Mutex<bool>, Condvar)>,
    entered: mpsc::Receiver<()>,
}

impl Case {
    fn new() -> Self {
        Self::with_close_failure(false)
    }

    fn with_close_failure(fail_return: bool) -> Self {
        let (child, mut engine, modules) = engine_with_one_accepted_provider();
        engine.scope = Scope::System;
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let gate = Arc::clone(&release);
        let (sender, entered) = mpsc::channel();
        let fixture = RetirementFixture::new(
            &engine.plan.slots,
            &engine.pinned,
            Box::new(move |owned: OwnedLink, producer| {
                if producer == ProducerProgram::UProbe("p11_return") {
                    sender.send(()).map_err(|error| error.to_string())?;
                    let (lock, changed) = &*gate;
                    let ready = changed
                        .wait_timeout_while(
                            lock.lock().unwrap(),
                            Duration::from_secs(5),
                            |released| !*released,
                        )
                        .map_err(|error| error.to_string())?;
                    if !*ready.0 {
                        return Err("owned test release deadline".into());
                    }
                    if fail_return {
                        return Err("actual closer refused the final owned link".into());
                    }
                }
                drop(owned);
                Ok(())
            }),
        );
        let mut session = ScriptedSession::default();
        session.global_retirement = Some(RefCell::new(fixture));
        Self {
            child,
            engine,
            session,
            modules,
            release,
            entered,
        }
    }

    fn candidate(&mut self) -> LiveCandidate {
        let mut candidate = peer_candidate(&mut self.engine, &self.modules);
        candidate
            .delta
            .retire
            .push(self.engine.plan.slots[0].clone());
        candidate.plan.deactivate(0);
        candidate
    }

    fn hold_pending(&mut self) {
        let ticket = self
            .session
            .begin_global_static_retirement(&self.engine.plan.slots)
            .unwrap()
            .unwrap();
        for index in ticket.retired_slots() {
            self.engine.plan.deactivate(*index);
        }
        self.engine.pending_global_retirement = Some(ticket);
        self.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    }

    fn release(&self) {
        *self.release.0.lock().unwrap() = true;
        self.release.1.notify_all();
    }

    fn bounded_scope(&mut self) -> tempfile::TempDir {
        let (bounded, directory) = engine_over_cgroup_naming(&[self.child.id()]);
        self.engine.scope = bounded.scope;
        self.engine.frame_work_budget_ns = u64::MAX;
        directory
    }

    fn full_requests(&mut self) {
        self.engine
            .request_refresh_consumed(self.child.id(), Some(11));
        for offset in 0..MAX_PENDING_REFRESH - 1 {
            assert!(
                self.engine
                    .request_refresh(4_000_000 + offset as u32, Some(20 + offset as u64))
            );
        }
        assert_eq!(self.engine.refresh_requested.len(), MAX_PENDING_REFRESH);
    }

    fn scan_context(
        &mut self,
        view: ProcessViewId,
        mapping: Option<MapEntry>,
    ) -> PendingLoaderScanKey {
        let object = self.engine.plan.slots[0].object;
        let offset = mapping
            .as_ref()
            .map_or(0x1000, |mapping| mapping.file_offset + 1);
        let prepared = self
            .engine
            .loader_registry
            .preflight(LoaderContextSpec {
                view,
                loader: object,
                mapping,
                hook: p11scope_manifest::elf::SymbolFact {
                    virtual_address: offset,
                    file_offset: offset,
                },
                state_address: None,
            })
            .unwrap();
        let context = self.engine.loader_registry.prepare(prepared).unwrap();
        self.engine.loader_registry.mark_attached(context).unwrap();
        PendingLoaderScanKey { view, context }
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        self.release();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "actual worker close did not settle"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn async_global_cgroup_departure_defers_conservative_replay_until_actual_close() {
    let (fixture, mut engine, mut session, scope) = exec_rearm_cgroup_twin_route();
    engine.frame_work_budget_ns = u64::MAX;
    let pid = fixture.child.id();
    let peer = fixture.peers[0].id();
    let original = engine.views[0].id();
    let original_admission = engine.views[0].view_admission();
    let sibling = engine.views[1].view_admission();
    let slots = engine.plan.slots.len();
    let attachments = session.attached_slots.iter().sum::<usize>();
    let detaches = session.detached_slot_indices.len();
    let held = engine.pinned.pinned().count();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    struct ReleaseOnDrop(Arc<(Mutex<bool>, Condvar)>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            *self.0.0.lock().unwrap() = true;
            self.0.1.notify_all();
        }
    }
    let release_guard = ReleaseOnDrop(Arc::clone(&release));
    let gate = Arc::clone(&release);
    let (sender, entered) = mpsc::channel();
    session.global_retirement = Some(RefCell::new(RetirementFixture::new(
        &engine.plan.slots,
        &engine.pinned,
        Box::new(move |owned, producer| {
            if producer == ProducerProgram::UProbe("p11_return") {
                sender.send(()).map_err(|error| error.to_string())?;
                let (lock, changed) = &*gate;
                let released = changed
                    .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(5), |ready| {
                        !*ready
                    })
                    .map_err(|error| error.to_string())?;
                if !*released.0 {
                    return Err("owned Cgroup retirement release deadline".into());
                }
            }
            drop(owned);
            Ok(())
        }),
    )));
    // A complete actual scope listing proves departure while the original
    // process stays alive. No EXIT hint or forged pending ticket is supplied.
    e06_write_listing(scope.path(), &[peer]);
    let outcome = apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();
    assert!(
        session.detached_slot_indices[detaches..]
            .iter()
            .all(Vec::is_empty),
        "conservative retirement cannot synchronously close static links before its handoff"
    );
    assert!(
        engine.pending_global_retirement.is_some(),
        "authoritative departure must defer its conservative native retirement"
    );
    assert!(!outcome.required_complete);
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(engine.pending_retirements.contains(&original));
    assert_eq!(engine.pinned.pinned().count(), held);
    assert_eq!(session.attached_slots.iter().sum::<usize>(), attachments);
    assert!(
        engine
            .views
            .iter()
            .any(|view| view.view_admission().same_allocation(&sibling))
    );
    let replay = engine.replay_pending_conservative(
        &mut session,
        &mut true,
        &mut PendingViewRetirements::new(),
    );
    assert_eq!(replay.disposition, ApplyDisposition::Deferred);
    let scans = engine.deep_scans;
    e06_write_listing(scope.path(), &[pid, peer]);
    for _ in 0..3 {
        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();
        assert!(engine.pending_retirements.contains(&original));
        assert_eq!(engine.deep_scans, scans);
        assert_eq!(engine.plan.slots.len(), slots);
        assert_eq!(session.attached_slots.iter().sum::<usize>(), attachments);
    }
    drop(release_guard);
    wait_for(|| {
        engine.service_backlog_quantum(&mut session).unwrap();
        engine.pending_global_retirement.is_none()
    });
    assert!(engine.take_immediate_exec_recovery_frame());
    apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();
    let admitted = engine.views.iter().find(|view| view.pid() == pid).unwrap();
    assert!(
        !admitted
            .view_admission()
            .same_allocation(&original_admission)
    );
    assert!(!engine.pending_retirements.contains(&original));
    assert!(session.attached_slots.iter().sum::<usize>() > attachments);
    assert!(engine.deep_scans > scans);
    assert!(!engine.global_retirement_frame_owed);
}

#[test]
fn async_global_candidate_handoff_keeps_only_actual_historical_retired_prefix() {
    let mut case = Case::new();
    let prior_pins = case.engine.pinned.pinned().count();
    let prior_modules = case.engine.modules.clone();
    let peers = e06_spawn_sleeps(1);
    let peer = peers[0].pid();
    let view = ProcessView::open(ProcessViewId(4), peer).unwrap();
    let module = child_provider_modules(&view)[1].clone();
    case.engine.newcomer_first_seen.insert(peer, Some(17));
    assert!(case.engine.request_refresh(peer, Some(23)));
    let original = case.engine.refresh_requested[&peer].clone();
    let mut pins = case.engine.pinned.clone();
    let skipped = pins.absorb(pin_test_modules(&view, std::slice::from_ref(&module)));
    let mut candidate = case
        .engine
        .live_candidate(pins, vec![case.modules[0].clone(), module], skipped)
        .unwrap();
    candidate
        .delta
        .retire
        .push(case.engine.plan.slots[0].clone());
    candidate.plan.deactivate(0);
    let outcome = case
        .engine
        .apply_candidate(&mut case.session, candidate, &mut true, false, &[&view])
        .unwrap();
    assert_eq!(outcome.disposition, ApplyDisposition::Deferred);
    case.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(case.engine.plan.slots.len(), 1);
    assert!(!case.engine.plan.is_active(0));
    assert_eq!(case.engine.pinned.pinned().count(), prior_pins);
    assert_eq!(case.engine.modules, prior_modules);
    assert!(
        case.session.attached_slots.is_empty() && case.session.replaced_slot_indices.is_empty()
    );
    assert!(outcome.static_failures.is_empty() && outcome.static_completions.is_empty());
    assert!(!outcome.accepted() && !outcome.required_complete() && !outcome.detach_failed);
    assert!(case.engine.pending_global_retirement.is_some());
    assert!(outcome.unpublished_views.contains(&view.id()));
    assert_eq!(case.engine.views.len(), 1);
    assert_eq!(case.engine.refresh_requested[&peer], original);
    assert_eq!(case.engine.newcomer_first_seen[&peer], Some(17));
}

#[test]
fn async_global_replacement_only_candidate_defers_without_new_target_failure() {
    let mut case = Case::new();
    let mut candidate = case
        .engine
        .live_candidate(
            case.engine.pinned.clone(),
            vec![case.modules[0].clone()],
            vec![],
        )
        .unwrap();
    assert!(candidate.delta.new.is_empty());
    candidate
        .delta
        .replace
        .push(candidate.plan.slots[0].clone());
    let outcome = case
        .engine
        .apply_candidate(&mut case.session, candidate, &mut true, false, &[])
        .unwrap();
    assert_eq!(outcome.disposition, ApplyDisposition::Deferred);
    case.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(!case.engine.plan.is_active(0));
    assert!(case.session.replaced_slot_indices.is_empty());
    assert!(outcome.static_failures.is_empty());
}

#[test]
fn async_global_pending_candidate_cannot_allocate_or_admit_a_repeated_prefix() {
    let mut case = Case::new();
    case.hold_pending();
    let prior_len = case.engine.plan.slots.len();
    for _ in 0..3 {
        let candidate = case
            .engine
            .live_candidate(case.engine.pinned.clone(), case.modules.clone(), vec![])
            .unwrap();
        let outcome = case
            .engine
            .apply_candidate(&mut case.session, candidate, &mut true, false, &[])
            .unwrap();
        assert_eq!(outcome.disposition, ApplyDisposition::Deferred);
        assert_eq!(case.engine.plan.slots.len(), prior_len);
        assert!(outcome.static_failures.is_empty() && !outcome.detach_failed);
        assert!(
            case.session.attached_slots.is_empty() && case.session.detached_slot_indices.is_empty()
        );
    }
    assert_eq!(
        case.session
            .global_retirement
            .as_ref()
            .unwrap()
            .borrow()
            .begins,
        1
    );
}

#[test]
fn async_global_empty_queue_poll_keeps_pending_without_progress_or_scan() {
    let mut case = Case::new();
    case.hold_pending();
    let scans = case.engine.deep_scans;
    let counters = case.session.counter_reads();
    assert!(case.engine.discovery_backlog_pending(0));
    let outcome = case
        .engine
        .service_backlog_quantum(&mut case.session)
        .unwrap();
    assert!(outcome.pending && !outcome.progressed && !outcome.changed);
    assert_eq!(case.engine.deep_scans, scans);
    assert_eq!(
        case.session.counter_reads(),
        counters + 1,
        "read-only loss evidence remains fresh while mutation waits"
    );
    assert!(
        case.session
            .global_retirement
            .as_ref()
            .unwrap()
            .borrow()
            .polls
            > 0
    );
}

#[test]
fn async_global_settlement_requests_one_fresh_frame_and_keeps_original_intent() {
    let mut case = Case::new();
    let pid = case.child.id();
    case.engine.request_refresh(pid, Some(123));
    let original = case.engine.refresh_requested[&pid].clone();
    case.hold_pending();
    case.release();
    wait_for(|| {
        case.session
            .global_retirement
            .as_ref()
            .unwrap()
            .borrow()
            .released()
            == 2
    });
    let outcome = case
        .engine
        .service_backlog_quantum(&mut case.session)
        .unwrap();
    assert!(outcome.progressed);
    assert!(case.engine.pending_global_retirement.is_none());
    assert_eq!(case.engine.refresh_requested[&pid].serial, original.serial);
    assert_eq!(case.engine.refresh_requested[&pid].owner, original.owner);
    assert_eq!(
        case.engine.refresh_requested[&pid].first_seen_ns,
        original.first_seen_ns
    );
    assert!(case.engine.take_immediate_exec_recovery_frame());
    assert!(!case.engine.take_immediate_exec_recovery_frame());
    assert!(case.session.attached_slots.is_empty());
}

#[test]
fn async_global_deferred_apply_does_not_settle_original_exec_markers() {
    let mut case = Case::new();
    let view = case.engine.views[0].id();
    let pid = case.child.id();
    case.engine.request_refresh(pid, Some(456));
    let serial = case.engine.refresh_requested[&pid].serial;
    case.engine.exec_rearm_views.insert(view, Some(serial));
    let outcome = ApplyOutcome {
        disposition: ApplyDisposition::Deferred,
        ..ApplyOutcome::default()
    };
    case.engine
        .settle_applied_exec_rearms([(view, serial)], &BTreeSet::new(), &outcome);
    assert_eq!(case.engine.exec_rearm_views.get(&view), Some(&Some(serial)));
    assert_eq!(case.engine.refresh_requested[&pid].serial, serial);
}

#[test]
fn async_global_h5_handoff_keeps_selected_request_and_whole_head() {
    let mut case = Case::new();
    let _scope = case.bounded_scope();
    case.full_requests();
    let original = case.engine.refresh_requested.clone();
    let mut records = vec![refresh_exec(9_000_000), refresh_exec(4_000_000)];
    let mut collect = |_: &mut dyn EngineSession| Ok((Vec::new(), 0));
    case.engine
        .process_discovery_records(
            &mut case.session,
            &mut records,
            &mut PendingViewRetirements::new(),
            &mut true,
            &mut collect,
            &mut PauseClosure::new(true),
        )
        .unwrap();
    assert!(
        case.engine.pending_global_retirement.is_some(),
        "the actual inventory scan retired the accepted original pair"
    );
    case.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(
        case.engine
            .pressure_episode
            .as_ref()
            .unwrap()
            .ruled_out
            .is_empty(),
        "a deferred selected request has not been ruled out"
    );
    assert_eq!(case.engine.refresh_requested, original);
    assert_eq!(case.engine.pending_discovery_records.len(), 2);
    assert_eq!(
        case.engine.pending_discovery_records[0].record.pid_tgid >> 32,
        9_000_000
    );
    assert_eq!(case.engine.pressure_service_passes, 1);
    let scans = case.engine.deep_scans;
    for _ in 0..3 {
        let outcome = case
            .engine
            .service_backlog_quantum(&mut case.session)
            .unwrap();
        assert!(outcome.pending && !outcome.progressed);
    }
    assert_eq!(case.engine.deep_scans, scans);
    assert_eq!(case.engine.discovery_truncated, 0);
    assert_eq!(case.engine.pressure_service_passes, 1);
}

#[test]
fn async_global_mid_batch_handoff_preserves_due_fallback_instead_of_scanning() {
    let mut case = Case::new();
    let _scope = case.bounded_scope();
    case.full_requests();
    let peers = e06_spawn_sleeps(1);
    let other = ProcessView::open(ProcessViewId(4), peers[0].pid()).unwrap();
    let other_id = other.id();
    case.engine.views.push(other);
    // This other held view is outside the selected pressure transaction. Its
    // deferred scan can outlive a context, but must wait behind the boundary.
    let due = PendingLoaderScanKey {
        view: other_id,
        context: LoaderContextId::from_case_id(9),
    };
    case.engine.pending_loader_scans.insert(due, 77);
    let outcome = case
        .engine
        .apply_discovery_batch(&mut case.session, vec![refresh_exec(9_000_000).record], 0)
        .unwrap();
    assert!(outcome, "the actual retired historical prefix changed");
    assert!(case.engine.pending_global_retirement.is_some());
    case.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        case.engine.pending_loader_scans.get(&due),
        Some(&77),
        "fallback must retain its original queued intent until a fresh scoped frame"
    );
    assert_eq!(case.engine.discovery_truncated, 0);
    assert!(case.session.attached_slots.is_empty());
}

#[test]
fn async_global_pending_frames_preserve_scope_and_all_original_ages() {
    let mut case = Case::new();
    let scope = case.bounded_scope();
    let pid = case.child.id();
    case.engine.request_refresh_consumed(pid, Some(123));
    case.engine.newcomer_first_seen.insert(9_000_000, Some(321));
    let requests = case.engine.refresh_requested.clone();
    let newcomers = case.engine.newcomer_first_seen.clone();
    let scans = case.engine.deep_scans;
    case.hold_pending();
    // Enumeration now sees a different population. Pending must not prune the
    // original request/arrival population or manufacture another candidate.
    e06_write_listing(scope.path(), &[]);
    for _ in 0..3 {
        refresh_inventory_with(&mut case.engine, &mut case.session);
    }
    assert_eq!(case.engine.refresh_requested, requests);
    assert_eq!(case.engine.newcomer_first_seen, newcomers);
    assert_eq!(case.engine.deep_scans, scans);
    assert_eq!(case.engine.plan.slots.len(), 1);
    assert!(case.session.attached_slots.is_empty());
}

#[test]
fn async_global_close_refusal_keeps_quarantine_without_recovery_credit() {
    let mut case = Case::with_close_failure(true);
    case.hold_pending();
    case.release();
    wait_for(|| {
        case.session
            .global_retirement
            .as_ref()
            .unwrap()
            .borrow_mut()
            .poll(case.engine.pending_global_retirement.as_ref().unwrap())
            == crate::attach::RetirementPoll::Refused
    });
    for _ in 0..3 {
        let outcome = case
            .engine
            .service_backlog_quantum(&mut case.session)
            .unwrap();
        assert!(outcome.pending && !outcome.progressed && !outcome.changed);
        assert!(!case.engine.take_immediate_exec_recovery_frame());
    }
    assert!(
        case.session
            .global_retirement
            .as_ref()
            .unwrap()
            .borrow()
            .blocking()
    );
    assert!(case.session.attached_slots.is_empty());
    assert_eq!(case.engine.plan.slots.len(), 1);
}

#[test]
fn async_global_stop_after_handoff_never_requests_recovery() {
    let mut case = Case::new();
    case.hold_pending();
    case.engine
        .set_cancel_flag(Arc::new(std::sync::atomic::AtomicBool::new(true)));
    case.release();
    wait_for(|| {
        case.session
            .global_retirement
            .as_ref()
            .unwrap()
            .borrow()
            .released()
            == 2
    });
    case.engine
        .service_backlog_quantum(&mut case.session)
        .unwrap();
    assert!(!case.engine.take_immediate_exec_recovery_frame());
    let candidate = case
        .engine
        .live_candidate(case.engine.pinned.clone(), case.modules.clone(), vec![])
        .unwrap();
    let outcome = case
        .engine
        .apply_candidate(&mut case.session, candidate, &mut true, false, &[])
        .unwrap();
    assert!(outcome.refused());
    assert!(case.session.attached_slots.is_empty());
}

#[test]
fn async_global_settled_frame_rechecks_current_scope_instead_of_old_candidate() {
    let mut case = Case::new();
    let scope = case.bounded_scope();
    case.engine
        .request_refresh_consumed(case.child.id(), Some(101));
    let candidate = case.candidate();
    let outcome = case
        .engine
        .apply_candidate(&mut case.session, candidate, &mut true, false, &[])
        .unwrap();
    assert_eq!(outcome.disposition, ApplyDisposition::Deferred);
    case.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    e06_write_listing(scope.path(), &[]);
    case.release();
    wait_for(|| {
        case.session
            .global_retirement
            .as_ref()
            .unwrap()
            .borrow()
            .released()
            == 2
    });
    case.engine
        .service_backlog_quantum(&mut case.session)
        .unwrap();
    assert!(case.engine.take_immediate_exec_recovery_frame());
    case.engine
        .drain_discovery_shallow_from(&mut case.session, false)
        .unwrap();
    assert!(
        case.engine.views.is_empty(),
        "fresh membership removed the original provider"
    );
    assert!(case.engine.modules.is_empty());
    assert_eq!(
        case.engine.plan.slots.len(),
        1,
        "the old candidate's peer was never published"
    );
    assert!(case.session.attached_slots.iter().all(|count| *count == 0));
}

#[test]
fn async_global_pending_records_keep_newer_exec_order_and_transport_loss() {
    let mut case = Case::new();
    case.engine
        .request_refresh_consumed(case.child.id(), Some(31));
    let original = case.engine.refresh_requested.clone();
    case.hold_pending();
    let first = refresh_exec(case.child.id());
    let second = refresh_exec(9_000_000);
    case.engine
        .apply_discovery_batch(&mut case.session, vec![first.record, second.record], 1)
        .unwrap();
    assert_eq!(
        case.engine.refresh_requested, original,
        "queued newer execs cannot settle or renew the old request early"
    );
    assert_eq!(case.engine.pending_discovery_records.len(), 2);
    assert_eq!(
        case.engine.pending_discovery_records[0].record.pid_tgid >> 32,
        u64::from(case.child.id())
    );
    assert_eq!(
        case.engine.pending_discovery_records[1].record.pid_tgid >> 32,
        9_000_000
    );
    assert_eq!(
        case.engine.malformed_discovery, 1,
        "real transport loss stays explicit behind the barrier"
    );
    assert!(
        case.engine
            .plan
            .skipped
            .iter()
            .any(|skip| skip.reason.contains("malformed private discovery")),
        "a pending frame must publish the actual transport omission"
    );
}

#[test]
fn async_global_quiet_handoff_still_runs_one_fresh_scoped_scan_after_hint_consumption() {
    let mut case = Case::new();
    let _scope = case.bounded_scope();
    assert!(case.engine.refresh_requested.is_empty());
    let scans = case.engine.deep_scans;
    let candidate = case.candidate();
    let outcome = case
        .engine
        .apply_candidate(&mut case.session, candidate, &mut true, false, &[])
        .unwrap();
    assert_eq!(outcome.disposition, ApplyDisposition::Deferred);
    case.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    case.release();
    wait_for(|| {
        case.session
            .global_retirement
            .as_ref()
            .unwrap()
            .borrow()
            .released()
            == 2
    });
    case.engine
        .service_backlog_quantum(&mut case.session)
        .unwrap();
    // The actual run loop consumes this scheduling hint before the next frame.
    assert!(case.engine.take_immediate_exec_recovery_frame());
    assert!(!case.engine.take_immediate_exec_recovery_frame());
    case.engine
        .drain_discovery_shallow_from(&mut case.session, false)
        .unwrap();
    assert!(
        case.engine.deep_scans > scans,
        "the owed frame must rescan actual current scope despite quiet queues"
    );
    assert_eq!(
        case.engine.plan.slots.len(),
        1,
        "fresh scanning cannot replay the synthetic peer candidate"
    );
    assert!(case.session.attached_slots.iter().all(|count| *count == 0));
    assert!(!case.engine.global_retirement_frame_owed);
    assert!(!case.engine.take_immediate_exec_recovery_frame());
}

#[test]
fn async_global_fix_round_fallback_first_scan_parks_other_held_view() {
    let mut case = Case::new();
    let _scope = case.bounded_scope();
    let peers = e06_spawn_sleeps(1);
    let other = ProcessView::open(ProcessViewId(4), peers[0].pid()).unwrap();
    let other_id = other.id();
    case.engine.views.push(other);
    let first = case.scan_context(case.engine.views[0].id(), None);
    let second = case.scan_context(other_id, None);
    case.engine.pending_loader_scans.insert(first, 11);
    case.engine.pending_loader_scans.insert(second, 22);
    let scans = case.engine.deep_scans;
    let outcome = case
        .engine
        .service_pending_loader_scans(
            BTreeSet::from([first, second]),
            &mut case.session,
            &mut true,
            &mut PendingViewRetirements::new(),
        )
        .unwrap();
    assert!(
        case.engine.pending_global_retirement.is_some(),
        "the first real scan handed off its original owned static pair"
    );
    case.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(!outcome.required_complete());
    assert_eq!(
        case.engine.deep_scans,
        scans + 1,
        "the later held view must not be scanned behind the ticket"
    );
    assert_eq!(case.engine.pending_loader_scans.get(&second), Some(&22));
    assert!(case.session.attached_slots.is_empty());
}

#[test]
fn async_global_fix_round_nonpressure_backlog_handoff_keeps_fifo_over_one_quantum() {
    let mut case = Case::new();
    let _scope = case.bounded_scope();
    let object = case.engine.plan.slots[0].object;
    let key = case.engine.pinned.summary(object).unwrap().key;
    let maps = Engine::read_maps(&case.engine.views[0], &mut case.engine.budget).unwrap();
    let mapping = maps
        .iter()
        .find(|mapping| mapping.permissions[2] == b'x' && ObjectKey::of(mapping) == key)
        .unwrap()
        .clone();
    let address = mapping.start + 1;
    let context = case.scan_context(case.engine.views[0].id(), Some(mapping));
    let mut loader = loader_record_for(context.context, case.child.id());
    loader.table_ptr = address;
    loader.hook_ts_ns = case.engine.views[0].admitted_ns() + 1;
    case.session.counters.loader_hits = 1;
    let mut records = vec![QueuedDiscoveryRecord {
        record: loader,
        terminal_owner: None,
        terminal_exports: Vec::new(),
    }];
    for index in 1..300 {
        let mut queued = refresh_exec(9_000_000);
        queued.record.hook_ts_ns = index;
        records.push(queued);
    }
    case.engine.pending_discovery_records = records;
    let outcome = case
        .engine
        .service_backlog_quantum(&mut case.session)
        .unwrap();
    assert!(outcome.pending && outcome.changed);
    assert!(case.engine.pending_global_retirement.is_some());
    case.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        case.engine.pressure_service_passes, 0,
        "this is an ordinary loader handoff"
    );
    assert!(!case.engine.pressure_rotation_pending && !case.engine.frame_deferred);
    let actual: Vec<_> = case
        .engine
        .pending_discovery_records
        .iter()
        .map(|queued| queued.record.hook_ts_ns)
        .collect();
    assert_eq!(
        actual,
        (1..300).collect::<Vec<_>>(),
        "older unserviced head suffix must precede the newer queue rest"
    );
}

#[test]
fn async_global_fix_round_deferred_pending_refused_and_terminal_publish_fresh_counters() {
    for (refused, terminal, backlog) in [
        (false, false, false),
        (false, true, false),
        (true, false, false),
        (true, true, false),
        (false, false, true),
        (true, false, true),
    ] {
        let mut case = Case::with_close_failure(refused);
        case.hold_pending();
        if refused {
            case.release();
            wait_for(|| {
                case.session
                    .global_retirement
                    .as_ref()
                    .unwrap()
                    .borrow_mut()
                    .poll(case.engine.pending_global_retirement.as_ref().unwrap())
                    == crate::attach::RetirementPoll::Refused
            });
        }
        case.session.counters.ring_loss = 3;
        case.session.counters.export_state_failures = 4;
        case.session.counters.export_bounded_read_failures = 5;
        case.session.counters.loader_state_read_failures = 7;
        if backlog {
            let outcome = case
                .engine
                .service_backlog_quantum(&mut case.session)
                .unwrap();
            assert!(outcome.pending && !outcome.progressed);
        } else {
            let mut collect = |_: &mut dyn EngineSession| Ok((Vec::new(), 0));
            let outcome = case
                .engine
                .apply_discovery_batch_with(
                    &mut case.session,
                    Vec::new(),
                    0,
                    !terminal,
                    terminal,
                    &mut collect,
                    None,
                )
                .unwrap();
            assert!(!outcome.required_complete);
        }
        assert_eq!(
            case.engine.capture_facts().discovery_losses(),
            [3, 4, 5, 0],
            "fresh absolute producer loss stays visible while ownership is deferred"
        );
        assert_eq!(case.engine.counter_snapshot.loader_state_read_failures, 7);
        assert!(
            case.engine
                .plan
                .skipped
                .iter()
                .any(|skip| skip.reason.contains("loader-state read failures"))
        );
        assert!(
            case.engine
                .plan
                .skipped
                .iter()
                .any(|skip| skip.reason.contains("could not reserve"))
        );
        assert!(case.engine.pending_global_retirement.is_some());
        assert!(case.session.attached_slots.is_empty());
    }
    let mut case = Case::new();
    case.hold_pending();
    case.session.fail_counter_reads([true]);
    let record = refresh_exec(9_000_000).record;
    assert!(
        case.engine
            .apply_discovery_batch(&mut case.session, vec![record], 0)
            .is_err()
    );
    assert_eq!(
        case.engine.pending_discovery_records.len(),
        1,
        "failed loss reads must retain the undispatched prefix"
    );
    assert!(case.engine.pending_global_retirement.is_some());
}
