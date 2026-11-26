//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
use super::*;
use crate::attach::{OwnedLink, ProducerProgram, RetirementFixture};
use crate::discovery::scheduler::{MAX_NEW_VIEWS_PER_TICK, MAX_NEWCOMER_ADMISSIONS_PER_TICK};
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
                    .request_refresh(FAKE_PID_FLOOR + offset as u32, Some(20 + offset as u64))
            );
        }
        assert_eq!(self.engine.refresh_queue.len(), MAX_PENDING_REFRESH);
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
fn async_global_owned_only_retire_detaches_synchronously_without_ticket() {
    // An owned-run ExecRefresh retires only the owned child's own stale
    // entry slots: they detach synchronously (exactly as an exact-PID
    // capture always did) instead of parking an async global ticket, so
    // the refresh tick completes inside the pause deadline.
    let mut case = Case::new();
    case.engine.owned_run_pid = Some(case.child.id());
    let candidate = case.candidate();
    let outcome = case
        .engine
        .apply_candidate(&mut case.session, candidate, &mut true, false, &[])
        .unwrap();
    assert_eq!(outcome.disposition, ApplyDisposition::Accepted);
    assert!(
        case.engine.pending_global_retirement.is_none(),
        "owned-only retirement must not park an async global ticket"
    );
    assert_eq!(
        case.session
            .global_retirement
            .as_ref()
            .unwrap()
            .borrow()
            .begins,
        0,
        "owned-only retirement never begins the async worker"
    );
    assert!(
        case.session
            .detached_slot_indices
            .iter()
            .any(|slots| !slots.is_empty()),
        "owned-only retirement detaches synchronously like an exact-PID capture"
    );
}

#[test]
fn async_global_owned_only_retire_covers_split_identity_prearm_pin() {
    use crate::discovery::identity::test_fixture::{
        module as fixture_module, own_all_raws, real_scan_pin,
    };
    // Lane-A (pre-6.8 overlay) split twin of the owned-only sync retire:
    // the retiring static slot hangs off the pre-arm pin — a distinct pin
    // over identical bytes — while the owned-view module's entry objects
    // name the scanned identity. Same file, same run capture: the retire
    // must still detach synchronously inside the pause tick instead of
    // parking an async global ticket (on 6.6 the ticket parked the tick
    // incomplete, the pause went partial, and first-burst calls raced).
    let mut case = Case::new();
    case.engine.owned_run_pid = Some(case.child.id());
    let slot_object = case.engine.plan.slots[0].object;
    let summary = case.engine.pinned.summary(slot_object).unwrap();
    let (path, sha) = (summary.path.to_string(), summary.sha256.to_string());
    assert!(!sha.is_empty(), "the accepted pin carries a digest");
    assert!(
        case.engine.modules[0]
            .entry_objects
            .iter()
            .flatten()
            .any(|id| *id == slot_object),
        "entry objects name the scanned identity"
    );
    // The pre-arm-side pin: the same bytes seen through the overlay's
    // other device (lane A renders the backing identity in maps while the
    // pin holds the overlay one).
    let mut split_key = summary.key;
    split_key.device.minor = split_key.device.minor.wrapping_add(1);
    let mut split = real_scan_pin(std::path::Path::new(&path), Some(split_key), 2, &sha);
    own_all_raws(&mut split);
    let skips = case.engine.pinned.absorb(split);
    assert!(skips.is_empty(), "{skips:?}");
    let split_pin = case
        .engine
        .pinned
        .id_for_scanned(&fixture_module(split_key), split_key, &path)
        .unwrap();
    assert_ne!(split_pin, slot_object, "the split mints a distinct pin");
    let mut candidate = case.candidate();
    // The retire delta carries the pre-arm pin identity, the way a live
    // static→exact transition retires its static slots on the lane-A
    // split; the committed plan keeps its scanned identity and stays
    // attach-index valid.
    assert_eq!(
        candidate.delta.retire.len(),
        1,
        "the only retirement is the accepted slot"
    );
    candidate.delta.retire[0].object = split_pin;
    let outcome = case
        .engine
        .apply_candidate(&mut case.session, candidate, &mut true, false, &[])
        .unwrap();
    assert_eq!(outcome.disposition, ApplyDisposition::Accepted);
    assert!(
        case.engine.pending_global_retirement.is_none(),
        "split-identity owned retirement must not park an async global ticket"
    );
    assert_eq!(
        case.session
            .global_retirement
            .as_ref()
            .unwrap()
            .borrow()
            .begins,
        0,
        "split-identity owned retirement never begins the async worker"
    );
    assert!(
        case.session
            .detached_slot_indices
            .iter()
            .any(|slots| !slots.is_empty()),
        "split-identity owned retirement detaches synchronously like an exact-PID capture"
    );
}

#[test]
fn async_global_owned_only_retire_covers_module_first_seen_in_candidate() {
    // Pre-arm on a split-identity (pre-6.8 overlay) file: the static
    // pre-arm slots are live before any module is committed, and the
    // first scan's candidate both introduces the owned child's module and
    // retires those static slots (static -> exact transition). Ownership
    // must be judged against the candidate's modules too; otherwise the
    // retire parks an async global ticket, the pause tick stays
    // incomplete and the owned child is released before attach.
    let mut case = Case::new();
    case.engine.owned_run_pid = Some(case.child.id());
    let candidate = case.candidate();
    assert!(
        candidate.modules.iter().any(|module| {
            module
                .entry_objects
                .iter()
                .flatten()
                .any(|id| *id == candidate.delta.retire[0].object)
        }),
        "the candidate's module names the retiring slot's object"
    );
    case.engine.modules.clear();
    let outcome = case
        .engine
        .apply_candidate(&mut case.session, candidate, &mut true, false, &[])
        .unwrap();
    assert_eq!(outcome.disposition, ApplyDisposition::Accepted);
    assert!(
        case.engine.pending_global_retirement.is_none(),
        "a module first seen in the candidate still owns the retire"
    );
    assert_eq!(
        case.session
            .global_retirement
            .as_ref()
            .unwrap()
            .borrow()
            .begins,
        0
    );
    assert!(
        case.session
            .detached_slot_indices
            .iter()
            .any(|slots| !slots.is_empty()),
        "the retire detaches synchronously inside the tick"
    );
}

#[test]
fn async_global_owned_only_retire_covers_candidate_module_without_entry_objects() {
    // The live pre-6.8 shape: the transition candidate's module has no
    // table entry objects bound yet, so only the module's own object ties
    // the retiring static slot (on that same file) to the owned child.
    let mut case = Case::new();
    case.engine.owned_run_pid = Some(case.child.id());
    let mut candidate = case.candidate();
    let retiring = candidate.delta.retire[0].object;
    assert!(
        candidate
            .modules
            .iter()
            .any(|module| module.object == retiring),
        "the retiring slot sits on a candidate module's own file"
    );
    for module in &mut candidate.modules {
        module.scanned.tables.clear();
        module.entry_objects.clear();
    }
    case.engine.modules.clear();
    let outcome = case
        .engine
        .apply_candidate(&mut case.session, candidate, &mut true, false, &[])
        .unwrap();
    assert!(
        case.engine.pending_global_retirement.is_none(),
        "the module's own object still owns the retire"
    );
    assert_eq!(
        case.session
            .global_retirement
            .as_ref()
            .unwrap()
            .borrow()
            .begins,
        0
    );
    assert!(
        case.session
            .detached_slot_indices
            .iter()
            .any(|slots| !slots.is_empty()),
        "the retire detaches synchronously inside the tick"
    );
    assert_ne!(outcome.disposition, ApplyDisposition::Deferred);
}

#[test]
fn async_global_candidate_module_of_unowned_view_keeps_async_ticket() {
    // Guard twin: the candidate's module belongs to a view that is not
    // the owned run child, so the same module-first-seen retire keeps
    // the ordinary async global path.
    let mut case = Case::new();
    case.engine.owned_run_pid = Some(case.child.id().wrapping_add(1_000_000));
    let candidate = case.candidate();
    case.engine.modules.clear();
    let outcome = case
        .engine
        .apply_candidate(&mut case.session, candidate, &mut true, false, &[])
        .unwrap();
    assert_eq!(outcome.disposition, ApplyDisposition::Deferred);
    assert!(case.engine.pending_global_retirement.is_some());
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
fn async_global_unowned_retire_keeps_async_ticket() {
    // Guard twin: without an owned run child, the same candidate keeps
    // the ordinary async global path.
    let mut case = Case::new();
    let candidate = case.candidate();
    let outcome = case
        .engine
        .apply_candidate(&mut case.session, candidate, &mut true, false, &[])
        .unwrap();
    assert_eq!(outcome.disposition, ApplyDisposition::Deferred);
    assert!(case.engine.pending_global_retirement.is_some());
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
    let original = case.engine.refresh_queue[&peer].clone();
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
    assert_eq!(case.engine.refresh_queue[&peer], original);
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
    let original = case.engine.refresh_queue[&pid].clone();
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
    assert_eq!(case.engine.refresh_queue[&pid].serial, original.serial);
    assert_eq!(case.engine.refresh_queue[&pid].owner, original.owner);
    assert_eq!(
        case.engine.refresh_queue[&pid].first_seen_ns,
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
    let serial = case.engine.refresh_queue[&pid].serial;
    case.engine.exec_rearm_views.insert(view, Some(serial));
    let outcome = ApplyOutcome {
        disposition: ApplyDisposition::Deferred,
        ..ApplyOutcome::default()
    };
    case.engine
        .settle_applied_exec_rearms([(view, serial)], &BTreeSet::new(), &outcome);
    assert_eq!(case.engine.exec_rearm_views.get(&view), Some(&Some(serial)));
    assert_eq!(case.engine.refresh_queue[&pid].serial, serial);
}

#[test]
fn async_global_h5_handoff_keeps_selected_request_and_whole_head() {
    let mut case = Case::new();
    let _scope = case.bounded_scope();
    case.full_requests();
    let original = case.engine.refresh_queue.snapshot_map_for_test();
    let mut records = vec![refresh_exec(9_000_000), refresh_exec(FAKE_PID_FLOOR)];
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
    assert_eq!(case.engine.refresh_queue.snapshot_map_for_test(), original);
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
    case.engine.pending_loader_scans.insert(due, (77, 1));
    let outcome = case
        .engine
        .apply_discovery_batch(&mut case.session, vec![refresh_exec(9_000_000).record], 0)
        .unwrap();
    assert!(outcome, "the actual retired historical prefix changed");
    assert!(case.engine.pending_global_retirement.is_some());
    case.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        case.engine.pending_loader_scans.get(&due),
        Some(&(77, 1)),
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
    let requests = case.engine.refresh_queue.snapshot_map_for_test();
    let newcomers = case.engine.newcomer_first_seen.clone();
    let scans = case.engine.deep_scans;
    case.hold_pending();
    // Enumeration now sees a different population. Pending must not prune the
    // original request/arrival population or manufacture another candidate.
    e06_write_listing(scope.path(), &[]);
    for _ in 0..3 {
        refresh_inventory_with(&mut case.engine, &mut case.session);
    }
    assert_eq!(case.engine.refresh_queue.snapshot_map_for_test(), requests);
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
        .set_cancel_flag(crate::run::mint_test_stop_token(true));
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
    let original = case.engine.refresh_queue.snapshot_map_for_test();
    case.hold_pending();
    let first = refresh_exec(case.child.id());
    let second = refresh_exec(9_000_000);
    case.engine
        .apply_discovery_batch(&mut case.session, vec![first.record, second.record], 1)
        .unwrap();
    assert_eq!(
        case.engine.refresh_queue.snapshot_map_for_test(),
        original,
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
    assert!(case.engine.refresh_queue.is_empty());
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
    // Service is freshest-first: the handoff-triggering scan carries the
    // newer hook timestamp so it is served first and parks the other.
    case.engine.pending_loader_scans.insert(first, (22, 1));
    case.engine.pending_loader_scans.insert(second, (11, 1));
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
    assert_eq!(
        case.engine.pending_loader_scans.get(&second),
        Some(&(11, 1))
    );
    assert!(case.session.attached_slots.is_empty());
}

/// Churn ledger and service, live: the ledger fills to its cap through the
/// real deferral path with a real dead worker's scan as the stalest entry;
/// a live newcomer's arrival evicts exactly that dead scan; and service
/// through the real path serves the live view's freshest scan first (it
/// hands off and parks the stale one), even though key order would serve
/// the stale scan first. Live holders throughout; synchronous kill+wait —
/// no timing.
#[test]
fn churn_ledger_evicts_dead_scan_and_serves_live_freshest_first() {
    let mut case = Case::new();
    let _scope = case.bounded_scope();
    let mut peers = e06_spawn_sleeps(2);
    let dead_view = ProcessView::open(ProcessViewId(4), peers[0].pid()).unwrap();
    let dead_id = dead_view.id();
    let live_view = ProcessView::open(ProcessViewId(5), peers[1].pid()).unwrap();
    let live_id = live_view.id();
    case.engine.views.push(dead_view);
    case.engine.views.push(live_view);
    let views0 = case.engine.views[0].id();
    // The stale deferral is created first so its key sorts first: key order
    // would serve (and hand off from) the stale scan, leaving the fresh one
    // pending. Serving the fresh one first proves freshest-first.
    let stale = case.scan_context(views0, None);
    let fresh = case.scan_context(views0, None);
    assert!(
        stale < fresh,
        "key order must prefer the stale scan for this proof"
    );
    let dead = case.scan_context(dead_id, None);
    let newcomer = case.scan_context(live_id, None);
    // Fill the ledger through the real deferral path: synthetic stale
    // ballast standing in for dead churn, plus the three real deferrals
    // with the dead worker's scan stalest of all.
    let ballast = crate::discovery::loader::LoaderContextId::from_case_id(0);
    for index in 0..(crate::discovery::loader::MAX_LOADER_CONTEXTS - 3) as u32 {
        case.engine.defer_loader_memory_scan(
            PendingLoaderScanKey {
                view: ProcessViewId(100 + index),
                context: ballast,
            },
            101 + u64::from(index),
            1,
        );
    }
    case.engine.defer_loader_memory_scan(dead, 5, 1);
    case.engine.defer_loader_memory_scan(stale, 11, 1);
    case.engine.defer_loader_memory_scan(fresh, 22, 1);
    assert_eq!(
        case.engine.pending_loader_scans.len(),
        crate::discovery::loader::MAX_LOADER_CONTEXTS,
        "the ledger must be full before the newcomer arrives"
    );
    // The dead worker exits before its scan resolves; the live newcomer's
    // arrival evicts exactly that dead scan through the real path.
    peers[0].reap().unwrap();
    assert!(
        case.engine.original_exited(dead_id),
        "the evicted worker must be truly dead"
    );
    let truncated = case.engine.discovery_truncated;
    case.engine.defer_loader_memory_scan(newcomer, 2000, 1);
    assert_eq!(
        case.engine.pending_loader_scans.len(),
        crate::discovery::loader::MAX_LOADER_CONTEXTS,
        "eviction keeps the ledger bounded"
    );
    assert!(
        !case.engine.pending_loader_scans.contains_key(&dead),
        "the dead worker's scan leaves for the live newcomer"
    );
    assert!(
        case.engine.pending_loader_scans.contains_key(&newcomer),
        "the live newcomer's arrival is admitted"
    );
    assert_eq!(
        case.engine.discovery_truncated,
        truncated + 1,
        "the evicted scan counts its truncation"
    );
    // Service serves the live view's freshest scan first: it hands off and
    // parks the stale one behind the handoff.
    let scans = case.engine.deep_scans;
    let outcome = case
        .engine
        .service_pending_loader_scans(
            BTreeSet::from([stale, fresh]),
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
        "only the freshest scan runs before the handoff parks the rest"
    );
    assert!(
        !case.engine.pending_loader_scans.contains_key(&fresh),
        "the freshest scan was served first"
    );
    assert_eq!(
        case.engine.pending_loader_scans.get(&stale),
        Some(&(11, 1)),
        "the stale scan parks behind the handoff"
    );
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

/// Task 7 wiring: a pid first enumerated this pass (no arrival mark yet)
/// is admitted ahead of a deferred, marked backlog pid. With a batch of
/// one, the first tick admits the backlog head and marks the tail; the
/// next tick the fresh pid jumps ahead of the marked one.
#[test]
fn newcomer_pid_admitted_before_deferred_backlog() {
    let guards = e06_spawn_sleeps(4);
    let mut pids: Vec<u32> = guards.iter().map(|guard| guard.pid()).collect();
    pids.sort_unstable();
    let (initial, backlog_head, backlog_tail, newcomer) = (pids[0], pids[1], pids[2], pids[3]);
    let scope_dir = tempfile::tempdir().expect("a scope directory");
    e06_write_listing(scope_dir.path(), &[initial]);
    let scope = crate::scope::cgroup(scope_dir.path()).expect("open scope directory");
    let args = e06_cgroup_args(scope_dir.path(), vec![], None);
    let mut engine = Engine::discover(&args, &scope, None).expect("an uncapped cgroup captures");
    assert_eq!(engine.views.len(), 1);
    engine.scheduler.set_max_new_views_for_test(1);

    e06_write_listing(scope_dir.path(), &[initial, backlog_head, backlog_tail]);
    refresh_inventory_once(&mut engine);
    let kept: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    assert_eq!(kept.len(), 2, "one backlog pid admits: {kept:?}");
    assert!(
        kept.contains(&backlog_head),
        "the backlog head admits first: {kept:?}"
    );
    assert!(!kept.contains(&backlog_tail), "the tail defers: {kept:?}");
    assert!(
        engine.newcomer_first_seen.contains_key(&backlog_tail),
        "the deferred tail is marked backlog"
    );

    e06_write_listing(
        scope_dir.path(),
        &[initial, backlog_head, backlog_tail, newcomer],
    );
    assert!(
        !engine.newcomer_first_seen.contains_key(&newcomer),
        "the fresh pid is an unmarked newcomer"
    );
    refresh_inventory_once(&mut engine);
    let kept: Vec<u32> = engine.views.iter().map(|view| view.pid()).collect();
    assert_eq!(kept.len(), 3, "one more pid admits: {kept:?}");
    assert!(
        kept.contains(&newcomer),
        "the newcomer jumps ahead of the marked backlog: {kept:?}"
    );
    assert!(
        !kept.contains(&backlog_tail),
        "the marked tail waits another tick: {kept:?}"
    );
}

/// Task 7 call-site pin: the engine passes the bounded production share
/// (half the 64-tick batch) to the admission window, not the whole batch.
/// 40 marked backlog pids plus 40 fresh newcomers admit as an exact 32/32
/// split. A call site passing `max_new_views` would admit all 40 fresh;
/// a share of 1 would admit only 24 (the backlog cannot fill the rest).
#[test]
fn newcomer_share_bounded_at_the_engine_call_site() {
    let batch = MAX_NEW_VIEWS_PER_TICK;
    let share = MAX_NEWCOMER_ADMISSIONS_PER_TICK;
    assert_eq!(share * 2, batch, "the production share is half the batch");
    // One initial view, 48 backlog candidates (8 admit, 40 defer marked),
    // and 40 fresh newcomers.
    let guards = e06_spawn_sleeps(1 + 48 + 40);
    let mut pids: Vec<u32> = guards.iter().map(|guard| guard.pid()).collect();
    pids.sort_unstable();
    let initial = pids[0];
    let backlog_pool: Vec<u32> = pids[1..49].to_vec();
    let fresh_pool: Vec<u32> = pids[49..].to_vec();
    assert_eq!(fresh_pool.len(), 40);
    let scope_dir = tempfile::tempdir().expect("a scope directory");
    e06_write_listing(scope_dir.path(), &[initial]);
    let scope = crate::scope::cgroup(scope_dir.path()).expect("open scope directory");
    let args = e06_cgroup_args(scope_dir.path(), vec![], None);
    let mut engine = Engine::discover(&args, &scope, None).expect("an uncapped cgroup captures");
    assert_eq!(engine.views.len(), 1);
    // Deterministic counts: the wall-time quanta have their own tests, so
    // pin the tick quantum — 64 admission scans must never defer mid-window
    // under parallel-test load.
    engine.scheduler.set_tick_quantum_ns_for_test(u64::MAX);
    engine.scheduler.set_max_new_views_for_test(8);

    // Phase 1: 48 newcomers against a batch of 8 admit 8 and mark the other
    // 40 as backlog.
    let mut listing = vec![initial];
    listing.extend(backlog_pool.iter().copied());
    e06_write_listing(scope_dir.path(), &listing);
    refresh_inventory_once(&mut engine);
    assert_eq!(engine.views.len(), 9, "eight backlog pids admit");
    let views: std::collections::BTreeSet<u32> =
        engine.views.iter().map(|view| view.pid()).collect();
    let backlog: std::collections::BTreeSet<u32> = backlog_pool
        .iter()
        .copied()
        .filter(|pid| !views.contains(pid))
        .collect();
    assert_eq!(backlog.len(), 40, "forty backlog pids defer");
    for pid in &backlog {
        assert!(
            engine.newcomer_first_seen.contains_key(pid),
            "deferred pid {pid} is marked backlog"
        );
    }

    // Phase 2: the production batch sees 40 marked backlog plus 40 fresh.
    engine.scheduler.set_max_new_views_for_test(batch);
    listing.extend(fresh_pool.iter().copied());
    e06_write_listing(scope_dir.path(), &listing);
    for pid in &fresh_pool {
        assert!(
            !engine.newcomer_first_seen.contains_key(pid),
            "fresh pid {pid} is an unmarked newcomer"
        );
    }
    refresh_inventory_once(&mut engine);
    let views: std::collections::BTreeSet<u32> =
        engine.views.iter().map(|view| view.pid()).collect();
    let fresh: std::collections::BTreeSet<u32> = fresh_pool.into_iter().collect();
    let fresh_admitted = views.intersection(&fresh).count();
    let backlog_admitted = views.intersection(&backlog).count();
    assert_eq!(views.len(), 9 + batch, "one full batch admits");
    assert_eq!(
        fresh_admitted, share,
        "fresh takes exactly the bounded share: {fresh_admitted} of {share}"
    );
    assert_eq!(
        backlog_admitted,
        batch - share,
        "backlog keeps the rest of the batch"
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == "live discovery tick"
                && skip.reason
                    == "80 new processes pending; tick admitted 64 for deep scanning (tick limit 64)"
        }),
        "the deferral is exact: {:?}",
        engine.counters.object_skips
    );
    let deferred: std::collections::BTreeSet<u32> = fresh
        .union(&backlog)
        .copied()
        .filter(|pid| !views.contains(pid))
        .collect();
    assert_eq!(deferred.len(), 16, "sixteen pids defer to the next tick");
    for pid in &deferred {
        assert!(
            engine.newcomer_first_seen.contains_key(pid),
            "deferred pid {pid} stays marked"
        );
    }
}

/// A refresh that returns early on a pending global retirement applied no
/// candidate: a learned staging stays unapplied (the latch that keeps the
/// next frame from skipping the apply, and that a member hold reads),
/// whatever the refresh's `Ok` says.
#[test]
fn async_global_pending_refresh_keeps_a_learned_staging_unapplied() {
    let mut case = Case::new();
    case.hold_pending();
    case.engine.learned_unapplied = true;
    let mut collect: Box<DiscoveryCollector<'_>> = Box::new(Engine::collect_discovery_records);
    let mut tick_now = crate::attach::monotonic_ns;
    let refreshed = case.engine.refresh_inventory(
        &mut case.session,
        &mut true,
        &mut Vec::new(),
        &mut PendingViewRetirements::new(),
        &mut *collect,
        &mut PauseClosure::new(true),
        &mut tick_now,
    );
    assert!(
        matches!(refreshed, Ok(false)),
        "the pending retirement ends the tick early: {refreshed:?}"
    );
    assert!(
        case.engine.learned_unapplied,
        "no candidate applied, so the staging is still unapplied"
    );
}

/// A mid-capture global retirement of live counting cover opens a
/// `coverage_retired` unobserved window on the affected record, files the
/// paired finite gap row, and counts the retired live slots: the detach
/// interval is disclosed instead of silently losing calls. The peer
/// module's same-apply attach must not suppress module one's window.
#[test]
fn async_global_live_retire_opens_a_counted_coverage_window() {
    let (_child, mut engine, modules) = engine_with_one_accepted_provider();
    let mut candidate = peer_candidate(&mut engine, &modules);
    candidate.delta.retire.push(engine.plan.slots[0].clone());
    candidate.plan.deactivate(0);
    let retired_modules: std::collections::BTreeSet<crate::plan::ModuleId> =
        engine.plan.slots[0].module_ids.iter().copied().collect();
    assert!(
        !retired_modules.is_empty(),
        "the retired slot names its module"
    );
    let mut session = ScriptedSession::default();
    session
        .scripted_stamps
        .insert(engine.plan.slots[0].index, 1);
    let mut additions = true;
    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions, false, &[])
        .unwrap();
    assert!(
        !outcome.detach_failed,
        "premise: the scripted detach commits"
    );
    assert!(
        !engine.plan.is_active(0),
        "premise: the retired slot leaves the active plan"
    );
    assert_eq!(
        engine.coverage_retire_windows().len(),
        1,
        "one window opens for the retired live cover"
    );
    let windows_view = engine.coverage_retire_windows();
    let window = &windows_view[0];
    assert_eq!(window.modules, retired_modules);
    assert_eq!(window.slots, 1);
    assert!(window.start_ns > 0);
    assert_eq!(window.end_ns, None, "nothing revived it yet");
    assert_eq!(engine.coverage_retired_slots(), 1);
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == crate::render::COVERAGE_RETIRED_SUBJECT
                && skip.reason == crate::render::COVERAGE_RETIRED_REASON
        }),
        "the paired finite gap row files: {:?}",
        engine.counters.object_skips
    );
    let facts = engine.capture_facts();
    let record = facts
        .discovery
        .modules
        .iter()
        .find(|record| retired_modules.contains(&record.id))
        .expect("the retired module projects a record");
    let windows = record
        .unobserved_windows
        .as_ref()
        .expect("the record discloses its retire window");
    assert!(
        windows.iter().any(|window| {
            window.reason == crate::render::UnobservedReason::CoverageRetired
                && window.start_ns > 0
                && window.end_ns >= window.start_ns
        }),
        "a coverage_retired window with sane bounds: {windows:?}"
    );
}

/// Re-attaching a retired module closes its coverage window at the
/// revival instant instead of stretching it to capture end.
#[test]
fn async_global_revived_module_closes_its_coverage_window() {
    let (_child, mut engine, modules) = engine_with_one_accepted_provider();
    let mut candidate = peer_candidate(&mut engine, &modules);
    candidate.delta.retire.push(engine.plan.slots[0].clone());
    candidate.plan.deactivate(0);
    let mut session = ScriptedSession::default();
    session
        .scripted_stamps
        .insert(engine.plan.slots[0].index, 1);
    let mut additions = true;
    engine
        .apply_candidate(&mut session, candidate, &mut additions, false, &[])
        .unwrap();
    assert_eq!(
        engine.coverage_retire_windows().len(),
        1,
        "premise: the retire opened its window"
    );
    let mut pins = engine.pinned.clone();
    let skipped = pins.absorb(pin_test_modules(&engine.views[0], &modules[..1]));
    let revive = engine.live_candidate(pins, modules.to_vec(), skipped);
    let revive = revive.expect("the intact pins offer a revive candidate");
    assert!(
        !revive.delta.new.is_empty() || !revive.delta.replace.is_empty(),
        "premise: the revive re-attaches module one"
    );
    let mut additions = true;
    engine
        .apply_candidate(&mut session, revive, &mut additions, false, &[])
        .unwrap();
    assert_eq!(
        engine.coverage_retire_windows().len(),
        1,
        "reviving closes the window instead of opening another"
    );
    let windows_view = engine.coverage_retire_windows();
    let window = &windows_view[0];
    let end = window.end_ns.expect("the revive stamps the window end");
    assert!(
        end >= window.start_ns,
        "the closed window keeps sane bounds"
    );
}

/// One retire of two modules opens one window per module. A partial
/// revival closes only the revived module's window: the still-dark
/// module's record keeps its window open, never silently un-disclosing
/// its tail loss. Only the second revival closes the second window.
#[test]
fn async_global_partial_revive_keeps_the_dark_modules_window_open() {
    let (_child, mut engine, modules) = engine_with_one_accepted_provider();
    let mut session = ScriptedSession::default();
    let peer = peer_candidate(&mut engine, &modules);
    let mut additions = true;
    engine
        .apply_candidate(&mut session, peer, &mut additions, false, &[])
        .unwrap();
    assert_eq!(
        engine.plan.slots.len(),
        2,
        "premise: both providers hold a slot"
    );
    let first = engine.plan.slots[0].index;
    let second = engine.plan.slots[1].index;
    session.scripted_stamps.insert(first, 1);
    session.scripted_stamps.insert(second, 1);
    let mut pins = engine.pinned.clone();
    let skipped = pins.absorb(pin_test_modules(&engine.views[0], &modules));
    let mut retire = engine
        .live_candidate(pins, modules.to_vec(), skipped)
        .expect("the intact pins offer a candidate");
    assert!(
        retire.delta.new.is_empty() && retire.delta.replace.is_empty(),
        "premise: nothing is left to attach"
    );
    retire.delta.retire.push(engine.plan.slots[0].clone());
    retire.delta.retire.push(engine.plan.slots[1].clone());
    retire.plan.deactivate(first);
    retire.plan.deactivate(second);
    let mut additions = true;
    engine
        .apply_candidate(&mut session, retire, &mut additions, false, &[])
        .unwrap();
    let opened = engine.coverage_retire_windows();
    assert_eq!(opened.len(), 2, "one window per retired module: {opened:?}");
    let windowed: std::collections::BTreeSet<crate::plan::ModuleId> = opened
        .iter()
        .flat_map(|window| window.modules.iter().copied())
        .collect();
    assert_eq!(
        windowed.len(),
        2,
        "the windows name both modules: {opened:?}"
    );
    assert!(
        opened
            .iter()
            .all(|window| window.modules.len() == 1 && window.end_ns.is_none()),
        "each window names one module and stays open: {opened:?}"
    );
    assert_eq!(engine.coverage_retired_slots(), 2);
    let one_mods: std::collections::BTreeSet<crate::plan::ModuleId> =
        engine.plan.slots[0].module_ids.iter().copied().collect();
    let mut pins = engine.pinned.clone();
    let skipped = pins.absorb(pin_test_modules(&engine.views[0], &modules));
    let mut partial = engine
        .live_candidate(pins, modules.to_vec(), skipped)
        .expect("the intact pins offer a revive candidate");
    assert_eq!(
        partial.delta.new.len(),
        2,
        "premise: the revive re-attaches both modules"
    );
    // A revival allocates fresh slot positions; partition by module,
    // not by the retired positions.
    let (keep, drop): (Vec<_>, Vec<_>) = partial
        .delta
        .new
        .iter()
        .cloned()
        .partition(|slot| slot.module_ids.iter().any(|id| one_mods.contains(id)));
    assert_eq!(keep.len(), 1, "premise: one new slot covers module one");
    assert_eq!(drop.len(), 1, "premise: one new slot covers module two");
    partial.delta.new = keep;
    for slot in &drop {
        partial.plan.deactivate(slot.index);
    }
    let mut additions = true;
    let outcome = engine
        .apply_candidate(&mut session, partial, &mut additions, false, &[])
        .unwrap();
    assert!(
        outcome.accepted(),
        "premise: the partial revive commits (detach_failed={} changed={})",
        outcome.detach_failed,
        outcome.changed,
    );
    let live_mods: std::collections::BTreeSet<crate::plan::ModuleId> = engine
        .plan
        .slots
        .iter()
        .filter(|slot| engine.plan.is_active(slot.index))
        .flat_map(|slot| slot.module_ids.iter().copied())
        .collect();
    assert!(
        one_mods.iter().all(|id| live_mods.contains(id)),
        "premise: module one revived: {live_mods:?}"
    );
    let partial_view = engine.coverage_retire_windows();
    assert!(
        partial_view
            .iter()
            .flat_map(|window| window.modules.iter())
            .any(|id| !live_mods.contains(id)),
        "premise: a windowed module stayed dark: {live_mods:?}"
    );
    for window in &partial_view {
        let module = *window.modules.iter().next().unwrap();
        if live_mods.contains(&module) {
            let end = window
                .end_ns
                .expect("the revived module's window closes at its revival");
            assert!(end >= window.start_ns, "sane bounds: {window:?}");
        } else {
            assert_eq!(
                window.end_ns, None,
                "the partial revival leaves the dark module's window open"
            );
        }
    }
    let mut pins = engine.pinned.clone();
    let skipped = pins.absorb(pin_test_modules(&engine.views[0], &modules));
    let full = engine
        .live_candidate(pins, modules.to_vec(), skipped)
        .expect("the intact pins offer the second revive");
    let mut additions = true;
    engine
        .apply_candidate(&mut session, full, &mut additions, false, &[])
        .unwrap();
    let full_view = engine.coverage_retire_windows();
    assert_eq!(full_view.len(), 2, "revivals open no new window");
    for window in &full_view {
        let end = window
            .end_ns
            .expect("the full revival stamps every window end");
        assert!(
            end >= window.start_ns,
            "the closed window keeps sane bounds"
        );
    }
}

/// Retiring plan-active cover the session never attached opens no
/// coverage window: probes that never installed observed no calls,
/// so the detach loses nothing (a rejected key's slots, a
/// conservative replay of an unattached plan). Only session-proven
/// attach-complete stamps count.
#[test]
fn async_global_unattached_retire_opens_no_coverage_window() {
    let (_child, mut engine, modules) = engine_with_one_accepted_provider();
    let mut candidate = peer_candidate(&mut engine, &modules);
    candidate.delta.retire.push(engine.plan.slots[0].clone());
    candidate.plan.deactivate(0);
    assert!(
        engine.plan.is_active(engine.plan.slots[0].index),
        "premise: the retired slot is plan-active"
    );
    let mut session = ScriptedSession::default();
    let mut additions = true;
    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions, false, &[])
        .unwrap();
    assert!(
        !outcome.detach_failed,
        "premise: the scripted detach commits"
    );
    assert!(
        engine.coverage_retire_windows().is_empty(),
        "a never-attached retire files no window"
    );
    assert_eq!(engine.coverage_retired_slots(), 0);
    assert!(
        !engine
            .counters
            .object_skips
            .iter()
            .any(|skip| { skip.subject == crate::render::COVERAGE_RETIRED_SUBJECT }),
        "a never-attached retire files no gap row: {:?}",
        engine.counters.object_skips
    );
}

/// Retiring only a later committed slot snapshots that slot's committed
/// endpoint by index: the window attributes to the retired slot's
/// modules with a one-slot count, never to the surviving prefix.
/// (Guards the dense index-position lookup in the retire snapshot.)
#[test]
fn async_global_retire_of_later_slot_snapshots_that_slot_by_index() {
    let (_child, mut engine, modules) = engine_with_one_accepted_provider();
    let peer = peer_candidate(&mut engine, &modules);
    let mut additions = true;
    engine
        .apply_candidate(
            &mut ScriptedSession::default(),
            peer,
            &mut additions,
            false,
            &[],
        )
        .unwrap();
    assert_eq!(
        engine.plan.slots.len(),
        2,
        "premise: both providers hold a slot"
    );
    let first = engine.plan.slots[0].index;
    let second = engine.plan.slots[1].index;
    assert_ne!(first, second, "premise: distinct slot indices");
    let kept_modules: std::collections::BTreeSet<crate::plan::ModuleId> =
        engine.plan.slots[0].module_ids.iter().copied().collect();
    let retired_modules: std::collections::BTreeSet<crate::plan::ModuleId> =
        engine.plan.slots[1].module_ids.iter().copied().collect();
    assert_ne!(
        kept_modules, retired_modules,
        "premise: the retired slot's owner differs from the survivor's"
    );
    let mut pins = engine.pinned.clone();
    let skipped = pins.absorb(pin_test_modules(&engine.views[0], &modules));
    let mut retire = engine
        .live_candidate(pins, modules.to_vec(), skipped)
        .expect("the intact pins offer a candidate");
    assert!(
        retire.delta.new.is_empty() && retire.delta.replace.is_empty(),
        "premise: the retire is pure (no same-apply reattach)"
    );
    retire.delta.retire.push(engine.plan.slots[1].clone());
    retire.plan.deactivate(second);
    let mut session = ScriptedSession::default();
    session.scripted_stamps.insert(second, 1);
    let mut additions = true;
    let outcome = engine
        .apply_candidate(&mut session, retire, &mut additions, false, &[])
        .unwrap();
    assert!(
        !outcome.detach_failed,
        "premise: the scripted detach commits"
    );
    assert!(
        session
            .detached_slot_indices
            .iter()
            .any(|slots| slots == &vec![second]),
        "premise: only the later slot detached: {:?}",
        session.detached_slot_indices
    );
    assert_eq!(
        engine.coverage_retire_windows().len(),
        1,
        "the retired later slot files its window"
    );
    let windows_view = engine.coverage_retire_windows();
    let window = &windows_view[0];
    assert_eq!(window.modules, retired_modules);
    assert_eq!(window.slots, 1);
    assert_eq!(window.end_ns, None, "nothing revived it yet");
    assert_eq!(engine.coverage_retired_slots(), 1);
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == crate::render::COVERAGE_RETIRED_SUBJECT
                && skip.reason == crate::render::COVERAGE_RETIRED_REASON
        }),
        "the paired finite gap row files: {:?}",
        engine.counters.object_skips
    );
}

/// Retiring a dead owner's slots (ended-PID path) opens no coverage
/// window: the dead process can run no calls, so there is no gap.
#[test]
fn async_global_ended_pid_retire_opens_no_coverage_window() {
    let (mut fixture, mut engine, mut session) = continuity_route();
    session
        .pid_continuity
        .as_ref()
        .unwrap()
        .borrow_mut()
        .group_all();
    let slots = engine.plan.slots.clone();
    assert!(
        slots.len() >= 2,
        "the route needs a kept and a retired slot"
    );
    let retired = slots[1..].to_vec();
    for slot in &retired {
        session.scripted_stamps.insert(slot.index, 1);
    }
    assert!(
        retired
            .iter()
            .all(|slot| session.slot_attached_at(slot.index).is_some()),
        "premise: every retired slot is session-proven attached, so only the ended exclusion can silence the window"
    );
    fixture.child.kill().unwrap();
    fixture.child.wait().unwrap();
    let owner = engine.views.remove(0);
    let proof = session
        .prepare_ended_pid_retirement(&owner, &slots)
        .unwrap();
    let ended = PendingEndedPidRetirement { owner, proof };
    let mut plan = engine.plan.clone();
    for slot in &retired {
        plan.deactivate(slot.index);
    }
    let candidate = LiveCandidate {
        pinned: engine.pinned.clone(),
        modules: Vec::new(),
        plan,
        delta: crate::plan::AttachDelta {
            new: Vec::new(),
            replace: Vec::new(),
            retire: retired,
        },
        views: std::collections::BTreeSet::new(),
        corroboration: Vec::new(),
        manifest_fallbacks: Vec::new(),
        selection_claims: std::collections::BTreeMap::new(),
        selection_tables: engine.selection_tables.clone(),
        selection_admission: None,
        manifest_selection_admissions: Vec::new(),
        manifest_inventory_slots: std::collections::BTreeMap::new(),
        loader_plan_proof: None,
        exec_preservations: Vec::new(),
        exec_completions: Vec::new(),
        built_by_full_rebuild: false,
        modules_unchanged: false,
    };
    let outcome = engine
        .apply_candidate_with_ended(
            &mut session,
            candidate,
            &mut true,
            true,
            &[],
            Some(&ended),
            None,
        )
        .unwrap();
    assert!(!outcome.detach_failed, "premise: the ended detach commits");
    assert!(
        engine.coverage_retire_windows().is_empty(),
        "a dead owner's retire files no window"
    );
    assert_eq!(engine.coverage_retired_slots(), 0);
}

/// A running owned child that maps the provider itself loses live calls
/// when its cover retires with no same-apply reattach, exactly like an
/// unowned retire: the pure owned retire files the counted window, not
/// silence. (In `run -- app` where app maps the provider, every slot is
/// owned; a blanket ownership cut-out would hide the whole loss.)
#[test]
fn async_global_running_owned_pure_retire_opens_a_counted_coverage_window() {
    let (child, mut engine, modules) = engine_with_one_accepted_provider();
    engine.owned_run_pid = Some(child.id());
    assert!(
        !engine.pause_owned_batch,
        "premise: the owned child runs (no pause held)"
    );
    let mut pins = engine.pinned.clone();
    let skipped = pins.absorb(pin_test_modules(&engine.views[0], &modules[..1]));
    let mut candidate = engine
        .live_candidate(pins, vec![modules[0].clone()], skipped)
        .expect("the intact pins offer a candidate");
    assert!(
        candidate.delta.new.is_empty() && candidate.delta.replace.is_empty(),
        "premise: the retire is pure (no same-apply reattach)"
    );
    candidate.delta.retire.push(engine.plan.slots[0].clone());
    candidate.plan.deactivate(0);
    let retired_modules: std::collections::BTreeSet<crate::plan::ModuleId> =
        engine.plan.slots[0].module_ids.iter().copied().collect();
    let mut session = ScriptedSession::default();
    session
        .scripted_stamps
        .insert(engine.plan.slots[0].index, 1);
    let mut additions = true;
    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions, false, &[])
        .unwrap();
    assert!(
        !outcome.detach_failed,
        "premise: the scripted detach commits"
    );
    assert!(
        engine.pending_global_retirement.is_none(),
        "premise: the owned retire detaches synchronously"
    );
    assert_eq!(
        engine.coverage_retire_windows().len(),
        1,
        "a running-owned pure retire files its window"
    );
    let windows_view = engine.coverage_retire_windows();
    let window = &windows_view[0];
    assert_eq!(window.modules, retired_modules);
    assert_eq!(window.slots, 1);
    assert_eq!(engine.coverage_retired_slots(), 1);
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == crate::render::COVERAGE_RETIRED_SUBJECT
                && skip.reason == crate::render::COVERAGE_RETIRED_REASON
        }),
        "the paired finite gap row files: {:?}",
        engine.counters.object_skips
    );
}

/// An owned retire composed with same-apply reattach stays silent: the
/// paused ExecRefresh/static-to-exact generation turnover retires the old
/// generation's slots while the reattach carries the new one, so no
/// window is owed.
#[test]
fn async_global_owned_retire_with_reattach_stays_silent() {
    let (child, mut engine, modules) = engine_with_one_accepted_provider();
    engine.owned_run_pid = Some(child.id());
    let mut candidate = peer_candidate(&mut engine, &modules);
    candidate.delta.retire.push(engine.plan.slots[0].clone());
    candidate.plan.deactivate(0);
    assert!(
        !candidate.delta.new.is_empty() || !candidate.delta.replace.is_empty(),
        "premise: the turnover carries same-apply reattach"
    );
    engine.set_pause_owned_batch(true);
    let mut session = ScriptedSession::default();
    session
        .scripted_stamps
        .insert(engine.plan.slots[0].index, 1);
    let mut additions = true;
    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions, false, &[])
        .unwrap();
    assert!(
        !outcome.detach_failed,
        "premise: the scripted detach commits"
    );
    assert!(
        engine.coverage_retire_windows().is_empty(),
        "an owned turnover retire files no window"
    );
    assert_eq!(engine.coverage_retired_slots(), 0);
    assert!(
        !engine
            .counters
            .object_skips
            .iter()
            .any(|skip| { skip.subject == crate::render::COVERAGE_RETIRED_SUBJECT }),
        "an owned turnover retire files no gap row: {:?}",
        engine.counters.object_skips
    );
}

/// A paused owned-generation turnover stays silent: the old generation's
/// endpoint retires while the renewed cover for the same provider (same
/// module, a distinct endpoint) attaches in the same apply and the
/// reattach actually runs. Silence is justified by the pause — the owned
/// child is stopped, so no calls are lost in the gap — not by endpoint
/// cover: the same shape unowned files (the mixed-retire twin), which is
/// what proves the owned exclusion. The implemented exclusion is
/// apply-wide (any same-apply reattach silences, even unrelated);
/// narrowing to the turnover awaits an owner ruling.
#[test]
fn async_global_paused_owned_generation_turnover_with_running_reattach_stays_silent() {
    let (child, mut engine, modules) = engine_with_one_accepted_provider();
    engine.owned_run_pid = Some(child.id());
    engine.set_pause_owned_batch(true);
    assert!(
        engine.pause_owned_batch,
        "premise: the turnover runs under pause"
    );
    assert_eq!(
        engine.views[0].pid(),
        child.id(),
        "premise: the provider cover maps the owned child"
    );
    let mut second = modules[0].clone();
    second.tables[0].entries.push(ScannedEntry {
        name: "C_GetSlotList",
        object: second.key,
        object_path: second.path.clone(),
        file_offset: 0x2000,
    });
    let mut pins = engine.pinned.clone();
    let skipped = pins.absorb(pin_test_modules(
        &engine.views[0],
        std::slice::from_ref(&second),
    ));
    pins.prove_scanned_entries_for_test(std::slice::from_ref(&second));
    let mut candidate = engine
        .live_candidate(pins, vec![second], skipped)
        .expect("the renewed endpoint offers a candidate");
    assert_eq!(
        candidate.delta.new.len(),
        1,
        "premise: the renewed cover allocates exactly one slot"
    );
    assert!(
        candidate.delta.replace.is_empty(),
        "premise: nothing replaces"
    );
    candidate.delta.retire.push(engine.plan.slots[0].clone());
    candidate.plan.deactivate(0);
    let retired_key = crate::plan::AttachKey::of(&engine.plan.slots[0]);
    let fresh_key = crate::plan::AttachKey::of(&candidate.delta.new[0]);
    assert_ne!(retired_key, fresh_key, "premise: distinct endpoints");
    let retired_modules: std::collections::BTreeSet<crate::plan::ModuleId> =
        engine.plan.slots[0].module_ids.iter().copied().collect();
    assert_eq!(
        candidate.delta.new[0]
            .module_ids
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        retired_modules,
        "premise: the renewed cover shares the retired slot's module"
    );
    let fresh_index = candidate.delta.new[0].index;
    let retired_index = engine.plan.slots[0].index;
    let fresh_slot = candidate.delta.new[0].clone();
    let mut session = ScriptedSession::default();
    session
        .scripted_stamps
        .insert(engine.plan.slots[0].index, 1);
    // Fresh attaches stamp + link like the real session's per-slot
    // completion (2 keeps the fresh stamp distinct from the old one).
    session.stamp_attached_slots = Some(2);
    let mut additions = true;
    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions, false, &[])
        .unwrap();
    assert!(
        !outcome.detach_failed,
        "premise: the scripted detach commits"
    );
    assert!(
        engine.plan.is_active(fresh_index),
        "premise: the renewed endpoint re-attached"
    );
    assert!(
        session
            .detached_slot_indices
            .iter()
            .any(|slots| slots == &vec![retired_index]),
        "premise: the old slot detached exactly: {:?}",
        session.detached_slot_indices
    );
    assert_eq!(
        session.attached_requests,
        vec![vec![(
            fresh_slot.index,
            fresh_slot.object,
            fresh_slot.file_offset
        )]],
        "premise: the fresh attachment was submitted exactly once"
    );
    assert!(
        session.slot_attached_at(fresh_index).is_some(),
        "premise: the fresh attach completed with a Session stamp"
    );
    assert!(
        session.has_slot_link(fresh_index),
        "premise: the fresh attach installed a Session link"
    );
    assert!(
        engine.coverage_retire_windows().is_empty(),
        "a paused owned turnover files no window"
    );
    assert_eq!(engine.coverage_retired_slots(), 0);
    assert!(
        !engine
            .counters
            .object_skips
            .iter()
            .any(|skip| { skip.subject == crate::render::COVERAGE_RETIRED_SUBJECT }),
        "a paused owned turnover files no gap row: {:?}",
        engine.counters.object_skips
    );
}

/// The owned-leader-maps-provider capture with a descendant view present:
/// every slot is owned, so a mid-capture pure retire of attached cover
/// still files its counted window. (At the witness seam the trigger — a
/// descendant worker's pin refusal nuking the shared key — is visible
/// only as the resulting pure owned retire; the nuke mechanics are
/// trigger scope.)
#[test]
fn async_global_owned_leader_with_descendant_pure_retire_opens_a_counted_coverage_window() {
    let (child, mut engine, modules) = engine_with_one_accepted_provider();
    engine.owned_run_pid = Some(child.id());
    let peers = e06_spawn_sleeps(1);
    let descendant_view = ProcessView::open(ProcessViewId(4), peers[0].pid()).unwrap();
    engine.views.push(descendant_view);
    engine.next_view_id = 5;
    let peer = peer_candidate(&mut engine, &modules);
    let mut additions = true;
    engine
        .apply_candidate(
            &mut ScriptedSession::default(),
            peer,
            &mut additions,
            false,
            &[],
        )
        .unwrap();
    assert_eq!(
        engine.plan.slots.len(),
        2,
        "premise: both providers hold a slot"
    );
    let first = engine.plan.slots[0].index;
    let second = engine.plan.slots[1].index;
    let mut pins = engine.pinned.clone();
    let skipped = pins.absorb(pin_test_modules(&engine.views[0], &modules));
    let mut retire = engine
        .live_candidate(pins, modules.to_vec(), skipped)
        .expect("the intact pins offer a candidate");
    assert!(
        retire.delta.new.is_empty() && retire.delta.replace.is_empty(),
        "premise: the retire is pure (no same-apply reattach)"
    );
    retire.delta.retire.push(engine.plan.slots[0].clone());
    retire.delta.retire.push(engine.plan.slots[1].clone());
    retire.plan.deactivate(first);
    retire.plan.deactivate(second);
    let retired_modules: std::collections::BTreeSet<crate::plan::ModuleId> = engine
        .plan
        .slots
        .iter()
        .flat_map(|slot| slot.module_ids.iter().copied())
        .collect();
    let mut session = ScriptedSession::default();
    session.scripted_stamps.insert(first, 1);
    session.scripted_stamps.insert(second, 1);
    let mut additions = true;
    let outcome = engine
        .apply_candidate(&mut session, retire, &mut additions, false, &[])
        .unwrap();
    assert!(
        !outcome.detach_failed,
        "premise: the scripted detach commits"
    );
    // Per-module windows (retire-window lane, F2): one open window per
    // retired module, together covering exactly the retired set, and the
    // slot count names the two distinct retired endpoints.
    let windows_view = engine.coverage_retire_windows();
    assert_eq!(
        windows_view.len(),
        retired_modules.len(),
        "an all-owned pure retire files one window per retired module"
    );
    let covered: std::collections::BTreeSet<_> = windows_view
        .iter()
        .flat_map(|window| window.modules.iter().copied())
        .collect();
    assert_eq!(covered, retired_modules);
    assert!(
        windows_view
            .iter()
            .all(|window| window.modules.len() == 1 && window.end_ns.is_none())
    );
    assert_eq!(engine.coverage_retired_slots(), 2);
}

/// An owned capture with a true descendant view present still files its
/// pure retire: the descendant (a live child of the owned leader, with
/// parentage pinned via `/proc/<pid>/status`) does not silence the
/// window. The refused-source-to-pure-retire handoff — the descendant
/// worker's pin refusal nuking the shared key, then retiring pure — is
/// not driven here (the refusal mechanics are trigger scope); this twin
/// pins the narrower witness seam (a manually assembled pure owned retire
/// with a true descendant present) pending an owner ruling on whether a
/// handoff-driving fixture is required.
#[test]
fn async_global_owned_with_true_descendant_pure_retire_opens_a_counted_coverage_window() {
    let owned = std::process::id();
    let owned_view = ProcessView::open(ProcessViewId(3), owned).unwrap();
    let modules = snapshot_two_provider_modules(&owned_view);
    let mut engine = Engine::empty();
    engine.scope = Scope::Pid(owned);
    engine.next_view_id = 4;
    engine.views.push(owned_view);
    engine.owned_run_pid = Some(owned);
    let pins = pin_test_modules(&engine.views[0], &modules[..1]);
    let candidate = engine
        .live_candidate(pins, vec![modules[0].clone()], Vec::new())
        .unwrap();
    assert_eq!(
        candidate.delta.new.len(),
        1,
        "premise: the owned cover allocates exactly one slot"
    );
    let mut session = ScriptedSession::default();
    let mut additions = true;
    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions, false, &[])
        .unwrap();
    assert!(
        outcome.accepted(),
        "premise: the first candidate is accepted whole"
    );
    assert_eq!(
        engine.plan.slots.len(),
        1,
        "premise: the owned cover holds one slot"
    );
    let guards = e06_spawn_sleeps(1);
    let descendant_pid = guards[0].pid();
    let status = std::fs::read_to_string(format!("/proc/{descendant_pid}/status")).unwrap();
    let ppid = status
        .lines()
        .find_map(|line| {
            line.strip_prefix("PPid:")
                .and_then(|ppid| ppid.trim().parse::<u32>().ok())
        })
        .unwrap();
    assert_eq!(
        ppid, owned,
        "premise: the added view is a true descendant of the owned leader"
    );
    let descendant_view = ProcessView::open(ProcessViewId(4), descendant_pid).unwrap();
    engine.views.push(descendant_view);
    engine.next_view_id = 5;
    let mut pins = engine.pinned.clone();
    let skipped = pins.absorb(pin_test_modules(&engine.views[0], &modules[..1]));
    let mut retire = engine
        .live_candidate(pins, vec![modules[0].clone()], skipped)
        .expect("the intact pins offer a candidate");
    assert!(
        retire.delta.new.is_empty() && retire.delta.replace.is_empty(),
        "premise: the retire is pure (no same-apply reattach)"
    );
    retire.delta.retire.push(engine.plan.slots[0].clone());
    retire.plan.deactivate(0);
    let retired_modules: std::collections::BTreeSet<crate::plan::ModuleId> =
        engine.plan.slots[0].module_ids.iter().copied().collect();
    let mut session = ScriptedSession::default();
    session
        .scripted_stamps
        .insert(engine.plan.slots[0].index, 1);
    let mut additions = true;
    let outcome = engine
        .apply_candidate(&mut session, retire, &mut additions, false, &[])
        .unwrap();
    assert!(
        !outcome.detach_failed,
        "premise: the scripted detach commits"
    );
    assert_eq!(
        engine.coverage_retire_windows().len(),
        1,
        "a pure owned retire with a descendant present files its window"
    );
    let windows_view = engine.coverage_retire_windows();
    let window = &windows_view[0];
    assert_eq!(window.modules, retired_modules);
    assert_eq!(window.slots, 1);
    assert_eq!(engine.coverage_retired_slots(), 1);
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == crate::render::COVERAGE_RETIRED_SUBJECT
                && skip.reason == crate::render::COVERAGE_RETIRED_REASON
        }),
        "the paired finite gap row files: {:?}",
        engine.counters.object_skips
    );
    let facts = engine.capture_facts();
    let record = facts
        .discovery
        .modules
        .iter()
        .find(|record| retired_modules.contains(&record.id))
        .expect("the retired owner projects a record");
    assert!(
        record
            .unobserved_windows
            .as_ref()
            .is_some_and(|windows| windows.iter().any(|window| {
                window.reason == crate::render::UnobservedReason::CoverageRetired
            })),
        "the retired owner's record carries the window: {record:?}"
    );
}

/// A same-module mixed retire discloses the darkened endpoint: S1 of M
/// retires with no cover while S2 of the same M re-attaches in the same
/// apply. Exclusion is per endpoint ({object, offset}), not per module,
/// so S1's key files its window + count + row. (The module-granular
/// close still ends the window in the same apply — S2 keeps M
/// plan-active — so the tail rides the count and the row, not the
/// interval.)
#[test]
fn async_global_same_module_mixed_retire_discloses_the_dark_endpoint() {
    let (_child, mut engine, modules) = engine_with_one_accepted_provider();
    let mut second = modules[0].clone();
    second.tables[0].entries.push(ScannedEntry {
        name: "C_GetSlotList",
        object: second.key,
        object_path: second.path.clone(),
        file_offset: 0x2000,
    });
    let mut pins = engine.pinned.clone();
    let skipped = pins.absorb(pin_test_modules(
        &engine.views[0],
        std::slice::from_ref(&second),
    ));
    // Absorb drops incoming entry proofs (fail-closed): re-prove the grown
    // module's entries on the merged set so the strict bind keeps the new
    // endpoint.
    pins.prove_scanned_entries_for_test(std::slice::from_ref(&second));
    let mut candidate = engine
        .live_candidate(pins, vec![second], skipped)
        .expect("the new endpoint offers a candidate");
    assert_eq!(
        candidate.delta.new.len(),
        1,
        "premise: the second endpoint allocates exactly one slot"
    );
    assert!(
        candidate.delta.replace.is_empty(),
        "premise: nothing replaces"
    );
    candidate.delta.retire.push(engine.plan.slots[0].clone());
    candidate.plan.deactivate(0);
    let retired_key = crate::plan::AttachKey::of(&engine.plan.slots[0]);
    let fresh_key = crate::plan::AttachKey::of(&candidate.delta.new[0]);
    assert_ne!(retired_key, fresh_key, "premise: distinct endpoints");
    let retired_modules: std::collections::BTreeSet<crate::plan::ModuleId> =
        engine.plan.slots[0].module_ids.iter().copied().collect();
    assert_eq!(
        candidate.delta.new[0]
            .module_ids
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        retired_modules,
        "premise: the reattach shares the retired slot's module"
    );
    let fresh_index = candidate.delta.new[0].index;
    let mut session = ScriptedSession::default();
    session
        .scripted_stamps
        .insert(engine.plan.slots[0].index, 1);
    let mut additions = true;
    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions, false, &[])
        .unwrap();
    assert!(
        !outcome.detach_failed,
        "premise: the scripted detach commits"
    );
    assert!(
        engine.plan.is_active(fresh_index),
        "premise: the sibling endpoint re-attached"
    );
    assert_eq!(
        engine.coverage_retire_windows().len(),
        1,
        "the dark endpoint files its window"
    );
    let windows_view = engine.coverage_retire_windows();
    let window = &windows_view[0];
    assert_eq!(window.modules, retired_modules);
    assert_eq!(window.slots, 1);
    assert_eq!(engine.coverage_retired_slots(), 1);
    let end = window
        .end_ns
        .expect("the module-active sibling closes it in the same apply");
    assert!(
        end >= window.start_ns,
        "the closed window keeps sane bounds"
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == crate::render::COVERAGE_RETIRED_SUBJECT
                && skip.reason == crate::render::COVERAGE_RETIRED_REASON
        }),
        "the paired finite gap row files: {:?}",
        engine.counters.object_skips
    );
}

/// A replacement the precheck skips leaves its endpoint stranded: the old
/// links detached with `selected`, nothing replaced them, and the slot
/// deactivates. Intent (the planned reattach) excluded the early window,
/// so the outcome — a deactivated replace slot with no cover — files the
/// follow-up window + count + row for the stranded key. The replacement
/// is a rival owner (same index and endpoint, a different stable module
/// id, as `extend_exact_replaces_a_getter_claimed_by_a_rival_manifest_owner`
/// produces): the window must attribute to the committed owner, not the
/// proposal.
#[test]
fn async_global_precheck_failed_replacement_discloses_the_stranded_endpoint() {
    let (child, mut engine, modules) = engine_with_one_accepted_provider();
    let mut pins = engine.pinned.clone();
    let skipped = pins.absorb(pin_test_modules(&engine.views[0], &modules[..1]));
    let mut candidate = engine
        .live_candidate(pins, vec![modules[0].clone()], skipped)
        .expect("the intact pins offer a candidate");
    assert!(
        candidate.delta.new.is_empty() && candidate.delta.replace.is_empty(),
        "premise: nothing is left to attach"
    );
    let mut replacement = engine.plan.slots[0].clone();
    replacement.module_ids = vec![crate::plan::ModuleId(1)];
    assert_ne!(
        replacement.module_ids, engine.plan.slots[0].module_ids,
        "premise: the proposal names a rival owner for the same endpoint"
    );
    assert_eq!(
        crate::plan::AttachKey::of(&replacement),
        crate::plan::AttachKey::of(&engine.plan.slots[0]),
        "premise: the rival reuses the same endpoint and index"
    );
    candidate.delta.replace.push(replacement);
    let retired_index = engine.plan.slots[0].index;
    let retired_modules: std::collections::BTreeSet<crate::plan::ModuleId> =
        engine.plan.slots[0].module_ids.iter().copied().collect();
    let mut session = ScriptedSession::default();
    session.scripted_stamps.insert(retired_index, 1);
    // The child exits inside the apply's second detach — after the
    // new-target attach, before the replacement precheck — so the
    // precheck finds its generation gone and skips the replacement.
    session.lose_generations_at_detach([None, Some(child.id())]);
    let mut additions = true;
    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions, false, &[])
        .unwrap();
    assert!(
        !outcome.detach_failed,
        "premise: the scripted detach commits"
    );
    assert!(
        session
            .detached_slot_indices
            .iter()
            .any(|slots| slots.contains(&retired_index)),
        "premise: the old links detached with selected"
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == "live discovery replacement"
                && skip.reason
                    == "a process generation changed before downgraded exact targets were replaced; they were deactivated"
        }),
        "premise: the precheck skipped the replacement: {:?}",
        engine.counters.object_skips
    );
    assert!(
        !engine.plan.is_active(retired_index),
        "premise: the stranded slot deactivates"
    );
    assert_eq!(
        engine.coverage_retire_windows().len(),
        1,
        "the stranded endpoint files its window"
    );
    let windows_view = engine.coverage_retire_windows();
    let window = &windows_view[0];
    assert_eq!(window.modules, retired_modules);
    assert_eq!(window.slots, 1);
    assert_eq!(window.end_ns, None, "nothing revived it yet");
    assert_eq!(engine.coverage_retired_slots(), 1);
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject == crate::render::COVERAGE_RETIRED_SUBJECT
                && skip.reason == crate::render::COVERAGE_RETIRED_REASON
        }),
        "the paired finite gap row files: {:?}",
        engine.counters.object_skips
    );
    let facts = engine.capture_facts();
    let record = facts
        .discovery
        .modules
        .iter()
        .find(|record| retired_modules.contains(&record.id))
        .expect("the retired owner projects a record");
    assert!(
        record
            .unobserved_windows
            .as_ref()
            .is_some_and(|windows| windows.iter().any(|window| {
                window.reason == crate::render::UnobservedReason::CoverageRetired
            })),
        "the original owner's record carries the window: {record:?}"
    );
}

/// A pending global retirement voids its planned reattach: the apply
/// deactivates the ticket's slots and returns Deferred without ever
/// attaching the reattach, so judging the exclusion on intent would stay
/// silent. The pending path files for every attached selected slot. The
/// planned reattach is a rival owner (same index and endpoint, a different
/// stable module id): the window must attribute to the committed owner.
#[test]
fn async_global_pending_retirement_with_planned_reattach_files_for_every_attached_slot() {
    let mut case = Case::new();
    let mut candidate = case
        .engine
        .live_candidate(
            case.engine.pinned.clone(),
            vec![case.modules[0].clone()],
            vec![],
        )
        .unwrap();
    assert!(
        candidate.delta.new.is_empty(),
        "premise: nothing is left to attach"
    );
    let mut replacement = case.engine.plan.slots[0].clone();
    replacement.module_ids = vec![crate::plan::ModuleId(1)];
    assert_ne!(
        replacement.module_ids, case.engine.plan.slots[0].module_ids,
        "premise: the proposal names a rival owner for the same endpoint"
    );
    assert_eq!(
        crate::plan::AttachKey::of(&replacement),
        crate::plan::AttachKey::of(&case.engine.plan.slots[0]),
        "premise: the rival reuses the same endpoint and index"
    );
    candidate.delta.replace.push(replacement);
    let retired_index = case.engine.plan.slots[0].index;
    let retired_modules: std::collections::BTreeSet<crate::plan::ModuleId> = case.engine.plan.slots
        [0]
    .module_ids
    .iter()
    .copied()
    .collect();
    case.session.scripted_stamps.insert(retired_index, 1);
    let outcome = case
        .engine
        .apply_candidate(&mut case.session, candidate, &mut true, false, &[])
        .unwrap();
    assert_eq!(
        outcome.disposition,
        ApplyDisposition::Deferred,
        "premise: the retire pends on the async worker"
    );
    assert!(
        case.engine.pending_global_retirement.is_some(),
        "premise: the ticket parks the retirement"
    );
    case.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(
        case.session.replaced_slot_indices.is_empty(),
        "premise: the planned reattach never ran"
    );
    assert_eq!(
        case.engine.coverage_retire_windows().len(),
        1,
        "the pending retire files its window"
    );
    let windows_view = case.engine.coverage_retire_windows();
    let window = &windows_view[0];
    assert_eq!(window.modules, retired_modules);
    assert_eq!(window.slots, 1);
    assert_eq!(window.end_ns, None, "nothing revived it yet");
    assert_eq!(case.engine.coverage_retired_slots(), 1);
    assert!(
        case.engine.counters.object_skips.iter().any(|skip| {
            skip.subject == crate::render::COVERAGE_RETIRED_SUBJECT
                && skip.reason == crate::render::COVERAGE_RETIRED_REASON
        }),
        "the paired finite gap row files: {:?}",
        case.engine.counters.object_skips
    );
    let facts = case.engine.capture_facts();
    let record = facts
        .discovery
        .modules
        .iter()
        .find(|record| retired_modules.contains(&record.id))
        .expect("the retired owner projects a record");
    assert!(
        record
            .unobserved_windows
            .as_ref()
            .is_some_and(|windows| windows.iter().any(|window| {
                window.reason == crate::render::UnobservedReason::CoverageRetired
            })),
        "the original owner's record carries the window: {record:?}"
    );
}

// ---------------------------------------------------------------------
// v0.7.2 retire-window lane (F1/F2): a proof-backed retire that leaves
// zero mappers loses nothing and opens no window; a mapper seen again
// before the re-attach discloses from the detach instant; the ledger
// stays bounded with an exact distinct-slot count.
// ---------------------------------------------------------------------

fn retire_skip_filed(engine: &Engine) -> bool {
    engine.counters.object_skips.iter().any(|skip| {
        skip.subject == crate::render::COVERAGE_RETIRED_SUBJECT
            && skip.reason == crate::render::COVERAGE_RETIRED_REASON
    })
}

fn record_retire_windows(engine: &Engine, module: crate::plan::ModuleId) -> Vec<(u64, u64)> {
    engine
        .capture_facts()
        .discovery
        .modules
        .iter()
        .filter(|record| record.id == module)
        .flat_map(|record| record.unobserved_windows.clone().unwrap_or_default())
        .filter(|window| window.reason == crate::render::UnobservedReason::CoverageRetired)
        .map(|window| (window.start_ns, window.end_ns))
        .collect()
}

/// The published `coverage_retired_folded` key of every record of
/// `module`, read from the rendered v3 evidence (the typed JSON a consumer
/// sees, not the ledger): `None` where the key is absent. Panics when the
/// module has no record, so an assertion over it is never vacuous.
fn published_retire_folded(
    engine: &Engine,
    module: crate::plan::ModuleId,
) -> Vec<Option<serde_json::Value>> {
    let facts = engine.capture_facts();
    let ids: Vec<crate::plan::ModuleId> = facts
        .discovery
        .modules
        .iter()
        .map(|record| record.id)
        .collect();
    let mut ev = crate::render::tests::evidence();
    ev.discovery = facts.discovery;
    ev.coverage_retired_slots = engine.coverage_retired_slots();
    let capture = crate::render::CaptureMeta {
        started: "t0",
        ended: "t1",
        kernel: "6.8.0",
        policy: crate::attach::CapturePolicy::Allowlisted,
        scope: "system",
        caller: None,
        ring_bytes: p11scope_ebpf_common::RING_BYTES,
        drain_interval_ms: 1000,
    };
    let document = crate::render::json(&[], &ev, &capture);
    let records = document["evidence"]["discovery"]
        .as_array()
        .expect("evidence.discovery is a list");
    assert_eq!(
        records.len(),
        ids.len(),
        "one JSON record per module record"
    );
    let published: Vec<Option<serde_json::Value>> = ids
        .iter()
        .zip(records)
        .filter(|(id, _)| **id == module)
        .map(|(_, record)| record.get("coverage_retired_folded").cloned())
        .collect();
    assert!(!published.is_empty(), "premise: the module has a record");
    published
}

/// System-scope engine whose only provider mapper exits: the slot is
/// session-proven attached, the child is killed and reaped, and the real
/// ExpectedRemoval path (pin-proven readiness, view removal, conservative
/// replay) runs through `process_discovery_records`. Returns the engine,
/// session, the scanned modules and the retired slot's module ids.
fn system_zero_mapper_exit() -> (
    Engine,
    ScriptedSession,
    Vec<ScannedModule>,
    std::collections::BTreeSet<crate::plan::ModuleId>,
) {
    let (mut child, mut engine, modules) = engine_with_one_accepted_provider();
    engine.scope = Scope::System;
    let slot = engine.plan.slots[0].index;
    let retired: std::collections::BTreeSet<crate::plan::ModuleId> =
        engine.plan.slots[0].module_ids.iter().copied().collect();
    assert!(!retired.is_empty(), "premise: the slot names its module");
    let mut session = ScriptedSession::default();
    session.scripted_stamps.insert(slot, 1);
    child.kill().unwrap();
    child.wait().unwrap();
    let view = engine.views[0].id();
    let mut pending = PendingViewRetirements::new();
    engine.queue_retirement(view, RetirementCause::ExpectedRemoval, &mut pending);
    let mut collect = |_: &mut dyn EngineSession| Ok((Vec::new(), 0));
    engine
        .process_discovery_records(
            &mut session,
            &mut Vec::new(),
            &mut pending,
            &mut true,
            &mut collect,
            &mut PauseClosure::new(true),
        )
        .unwrap();
    assert!(
        engine.views.is_empty(),
        "premise: the proven exit removed the only view"
    );
    assert!(
        !engine.plan.is_active(slot),
        "premise: the replay retired the provider's live slot"
    );
    assert!(
        engine.pending_retirements.is_empty(),
        "premise: the conservative replay consumed the retirement"
    );
    (engine, session, modules, retired)
}

/// Commit a candidate in which a new live process maps the provider
/// again. `reattach` false strips the re-attach (the mapper is seen but
/// its cover does not return in this apply).
fn remap_provider(
    engine: &mut Engine,
    session: &mut ScriptedSession,
    reattach: bool,
) -> std::process::Child {
    let child = std::process::Command::new("sleep")
        .arg("30")
        .die_with_parent()
        .spawn()
        .unwrap();
    let view = ProcessView::open(ProcessViewId(5), child.id()).unwrap();
    let modules = child_provider_modules(&view);
    engine.next_view_id = engine.next_view_id.max(6);
    engine.views.push(view);
    let mut pins = engine.pinned.clone();
    let view = engine
        .views
        .iter()
        .find(|view| view.id() == ProcessViewId(5))
        .unwrap();
    let skipped = pins.absorb(pin_test_modules(view, &modules[..1]));
    let mut candidate = engine
        .live_candidate(pins, vec![modules[0].clone()], skipped)
        .expect("the new mapper offers a candidate");
    assert!(
        !candidate.delta.new.is_empty(),
        "premise: the new mapper re-attaches the provider"
    );
    if !reattach {
        for slot in std::mem::take(&mut candidate.delta.new) {
            candidate.plan.deactivate(slot.index);
        }
    }
    let outcome = engine
        .apply_candidate(session, candidate, &mut true, false, &[])
        .unwrap();
    assert!(outcome.accepted(), "premise: the remap commits");
    child
}

/// F1 twin (a): the most common `--system` flow. A client maps the
/// provider, runs and exits; every scanned mapper exited or provably
/// left the scope and none remains. The retire files no window, no gap
/// row and no retired-slot count: the verdict stays COMPLETE. The retire
/// is parked for the module, in case a mapper returns.
#[test]
fn system_proven_exit_with_zero_mappers_opens_no_coverage_window() {
    let (engine, _session, _modules, retired) = system_zero_mapper_exit();
    assert!(
        engine.coverage_retire_windows().is_empty(),
        "no window: {:?}",
        engine.coverage_retire_windows()
    );
    assert_eq!(engine.coverage_retired_slots(), 0);
    assert!(
        !retire_skip_filed(&engine),
        "no coverage-retired row: {:?}",
        engine.counters.object_skips
    );
    assert_eq!(
        engine.coverage_retire_parked(),
        retired,
        "the zero-mapper retire is parked for its module"
    );
    for module in &retired {
        assert!(record_retire_windows(&engine, *module).is_empty());
    }
}

/// F1 twin (b), re-attach in the same apply: a new process maps the
/// provider after the zero-mapper retire. Its calls before the re-attach
/// were not observed, so the parked retire turns into a disclosed window
/// from the detach instant, closed at the re-attach, with the row and an
/// exact one-slot count.
#[test]
fn system_mapper_seen_after_zero_mapper_retire_discloses_until_reattach() {
    let (mut engine, mut session, _modules, retired) = system_zero_mapper_exit();
    let mut child = remap_provider(&mut engine, &mut session, true);
    let windows = engine.coverage_retire_windows();
    assert_eq!(
        windows.len(),
        retired.len(),
        "one window per module: {windows:?}"
    );
    for window in &windows {
        assert!(retired.is_superset(&window.modules));
        assert_eq!(window.slots, 1);
        let end = window.end_ns.expect("the same-apply re-attach closes it");
        assert!(end >= window.start_ns && window.start_ns > 0);
    }
    assert_eq!(engine.coverage_retired_slots(), 1);
    assert!(retire_skip_filed(&engine), "the row files on promotion");
    assert!(engine.coverage_retire_parked().is_empty());
    for module in &retired {
        assert_eq!(record_retire_windows(&engine, *module).len(), 1);
    }
    child.kill().unwrap();
    child.wait().unwrap();
}

/// F1 twin (b), no re-attach yet: the mapper is seen but its cover has
/// not returned, so the promoted window stays open (PARTIAL), and a later
/// re-attach closes it without opening another.
#[test]
fn system_mapper_seen_without_reattach_keeps_the_window_open() {
    let (mut engine, mut session, _modules, retired) = system_zero_mapper_exit();
    let mut child = remap_provider(&mut engine, &mut session, false);
    let windows = engine.coverage_retire_windows();
    assert_eq!(windows.len(), retired.len());
    assert!(
        windows.iter().all(|window| window.end_ns.is_none()),
        "no cover yet: the window stays open: {windows:?}"
    );
    assert_eq!(engine.coverage_retired_slots(), 1);
    assert!(retire_skip_filed(&engine));
    for module in &retired {
        let projected = record_retire_windows(&engine, *module);
        assert_eq!(projected.len(), 1, "the record discloses it open-ended");
        assert!(projected[0].1 >= projected[0].0);
    }
    let mut pins = engine.pinned.clone();
    let view = engine
        .views
        .iter()
        .find(|view| view.id() == ProcessViewId(5))
        .unwrap();
    let modules = child_provider_modules(view);
    let skipped = pins.absorb(pin_test_modules(view, &modules[..1]));
    let revive = engine
        .live_candidate(pins, vec![modules[0].clone()], skipped)
        .unwrap();
    assert!(
        !revive.delta.new.is_empty(),
        "premise: the re-attach is planned"
    );
    engine
        .apply_candidate(&mut session, revive, &mut true, false, &[])
        .unwrap();
    let windows = engine.coverage_retire_windows();
    assert_eq!(
        windows.len(),
        retired.len(),
        "the re-attach opens no new window"
    );
    assert!(windows.iter().all(|window| window.end_ns.is_some()));
    assert_eq!(
        engine.coverage_retired_slots(),
        1,
        "the endpoint counts once"
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Promotion counts only live mappers: while a pending retire still
/// lists the module in the committed plan, the exited view's stale
/// module row must not promote the parked retire. A live view mapping
/// the provider does.
#[test]
fn parked_retire_promotes_only_for_a_live_mapper() {
    let (child, mut engine, _modules) = engine_with_one_accepted_provider();
    let module = engine.plan.slots[0].module_ids[0];
    let endpoint = crate::discovery::coverage_retire::RetiredEndpoint::Pinned {
        object: engine.plan.slots[0].object,
        file_offset: engine.plan.slots[0].file_offset,
    };
    engine
        .coverage_retire
        .park(&[module].into_iter().collect(), endpoint, 1);
    let view = engine.views.remove(0);
    assert!(
        engine
            .plan
            .modules
            .iter()
            .any(|summary| summary.id == module),
        "premise: the plan still lists the module"
    );
    assert!(
        !engine.promote_remapped_coverage_retires(),
        "an exited view's row is no mapper"
    );
    assert!(engine.coverage_retire_windows().is_empty());
    engine.views.push(view);
    assert!(
        engine.promote_remapped_coverage_retires(),
        "a live view maps it"
    );
    assert_eq!(engine.coverage_retire_windows().len(), 1);
    assert!(retire_skip_filed(&engine));
    let mut child = child;
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Killing twin for the exit proof: the same replay with the retiring
/// view still tracked live (a lost generation or an unproven removal)
/// keeps the lossy window, even when an exit proof was recorded for it.
#[test]
fn system_replay_without_a_proven_exit_keeps_the_lossy_window() {
    for recorded_proof in [false, true] {
        let (mut child, mut engine, _modules) = engine_with_one_accepted_provider();
        engine.scope = Scope::System;
        let slot = engine.plan.slots[0].index;
        let mut session = ScriptedSession::default();
        session.scripted_stamps.insert(slot, 1);
        let view = engine.views[0].id();
        if recorded_proof {
            engine.exit_proven_views.insert(view);
        }
        engine.pending_retirements.insert(view);
        engine.replay_pending_conservative(
            &mut session,
            &mut true,
            &mut PendingViewRetirements::new(),
        );
        assert!(!engine.plan.is_active(slot), "premise: the slot retired");
        assert_eq!(
            engine.coverage_retire_windows().len(),
            1,
            "recorded_proof={recorded_proof}: a live retiring mapper keeps the window"
        );
        assert_eq!(engine.coverage_retired_slots(), 1);
        assert!(retire_skip_filed(&engine));
        assert!(engine.coverage_retire_parked().is_empty());
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

/// Killing twin for the proof source: the same proven-exit replay with
/// the exit proof absent (only `exit_proven_views` vouches for a removed
/// view) keeps the lossy window.
#[test]
fn system_removed_view_without_exit_proof_keeps_the_lossy_window() {
    let (mut child, mut engine, _modules) = engine_with_one_accepted_provider();
    engine.scope = Scope::System;
    let slot = engine.plan.slots[0].index;
    let mut session = ScriptedSession::default();
    session.scripted_stamps.insert(slot, 1);
    child.kill().unwrap();
    child.wait().unwrap();
    let view = engine.views.remove(0).id();
    engine.pending_retirements.insert(view);
    engine.replay_pending_conservative(&mut session, &mut true, &mut PendingViewRetirements::new());
    assert!(!engine.plan.is_active(slot), "premise: the slot retired");
    assert_eq!(engine.coverage_retire_windows().len(), 1);
    assert!(retire_skip_filed(&engine));
    // Twin: the same removal with the pin-proven exit recorded parks.
    let (mut child, mut engine, _modules) = engine_with_one_accepted_provider();
    engine.scope = Scope::System;
    let slot = engine.plan.slots[0].index;
    let mut session = ScriptedSession::default();
    session.scripted_stamps.insert(slot, 1);
    child.kill().unwrap();
    child.wait().unwrap();
    let view = engine.views.remove(0).id();
    engine.exit_proven_views.insert(view);
    engine.pending_retirements.insert(view);
    engine.replay_pending_conservative(&mut session, &mut true, &mut PendingViewRetirements::new());
    assert!(!engine.plan.is_active(slot));
    assert!(engine.coverage_retire_windows().is_empty());
    assert!(!retire_skip_filed(&engine));
    assert!(
        engine.exit_proven_views.is_empty(),
        "the settled replay drops its proof"
    );
}

/// Killing twin for rejected keys: a replay that also retries a rejected
/// object carries no exit proof (the rejected object's mappers live on),
/// so the retire keeps its lossy window.
#[test]
fn system_replay_with_rejected_keys_keeps_the_lossy_window() {
    let (mut child, mut engine, _modules) = engine_with_one_accepted_provider();
    engine.scope = Scope::System;
    let slot = engine.plan.slots[0].index;
    let mut session = ScriptedSession::default();
    session.scripted_stamps.insert(slot, 1);
    child.kill().unwrap();
    child.wait().unwrap();
    let view = engine.views.remove(0).id();
    engine.exit_proven_views.insert(view);
    engine.pending_retirements.insert(view);
    engine.pending_rejected_keys.insert(ObjectKey {
        device: p11scope_manifest::maps::Device { major: 0, minor: 1 },
        inode: 1,
    });
    engine.replay_pending_conservative(&mut session, &mut true, &mut PendingViewRetirements::new());
    assert!(!engine.plan.is_active(slot), "premise: the slot retired");
    assert_eq!(engine.coverage_retire_windows().len(), 1);
    assert!(retire_skip_filed(&engine));
}

/// Killing twin for remaining mappers: an exit proof for the module does
/// not exempt a retire whose candidate still plans the module (some
/// mapper remains and can call while the probes are down).
#[test]
fn exit_proof_with_a_remaining_mapper_keeps_the_lossy_window() {
    let (_child, mut engine, modules) = engine_with_one_accepted_provider();
    let mut candidate = peer_candidate(&mut engine, &modules);
    candidate.delta.retire.push(engine.plan.slots[0].clone());
    candidate.plan.deactivate(0);
    let retired: std::collections::BTreeSet<crate::plan::ModuleId> =
        engine.plan.slots[0].module_ids.iter().copied().collect();
    assert!(
        candidate
            .plan
            .modules
            .iter()
            .any(|module| retired.contains(&module.id)),
        "premise: the candidate still plans the retired module"
    );
    let mut session = ScriptedSession::default();
    session
        .scripted_stamps
        .insert(engine.plan.slots[0].index, 1);
    engine
        .apply_candidate_with_ended(
            &mut session,
            candidate,
            &mut true,
            false,
            &[],
            None,
            Some(&retired),
        )
        .unwrap();
    assert_eq!(engine.coverage_retire_windows().len(), 1);
    assert!(engine.coverage_retire_parked().is_empty());
    assert!(retire_skip_filed(&engine));
}

/// F2 through the real apply path: repeated lossy retire/re-attach
/// cycles of one provider keep at most the per-module cap of windows and
/// count the provider's one endpoint once.
#[test]
fn repeated_retire_cycles_stay_bounded_with_an_exact_slot_count() {
    use crate::discovery::coverage_retire::MAX_COVERAGE_RETIRE_WINDOWS_PER_MODULE;
    let (_child, mut engine, modules) = engine_with_one_accepted_provider();
    let mut session = ScriptedSession::default();
    let peer = peer_candidate(&mut engine, &modules);
    engine
        .apply_candidate(&mut session, peer, &mut true, false, &[])
        .unwrap();
    let module = engine.plan.slots[0].module_ids[0];
    assert!(
        published_retire_folded(&engine, module)
            .iter()
            .all(Option::is_none),
        "no retire window yet, so no folded key"
    );
    let cycles = MAX_COVERAGE_RETIRE_WINDOWS_PER_MODULE + 4;
    // Pin once against the live child and reuse clones: the view and
    // its modules never change across cycles, and every re-pin is a
    // load race against the child exiting mid-discovery.
    let pinned_once = pin_test_modules(&engine.views[0], &modules);
    for cycle in 0..cycles {
        let one = engine
            .plan
            .slots
            .iter()
            .find(|slot| engine.plan.is_active(slot.index) && slot.module_ids.contains(&module))
            .cloned()
            .expect("module one has live cover");
        session.scripted_stamps.insert(one.index, 1);
        let mut pins = engine.pinned.clone();
        let skipped = pins.absorb(pinned_once.clone());
        let mut retire = engine
            .live_candidate(pins, modules.to_vec(), skipped)
            .unwrap();
        retire.delta.retire.push(one.clone());
        retire.plan.deactivate(one.index);
        engine
            .apply_candidate(&mut session, retire, &mut true, false, &[])
            .unwrap();
        assert!(!engine.plan.is_active(one.index), "cycle {cycle}: retired");
        let mut pins = engine.pinned.clone();
        let skipped = pins.absorb(pinned_once.clone());
        let revive = engine
            .live_candidate(pins, modules.to_vec(), skipped)
            .unwrap();
        assert!(
            !revive.delta.new.is_empty(),
            "cycle {cycle}: re-attach planned"
        );
        engine
            .apply_candidate(&mut session, revive, &mut true, false, &[])
            .unwrap();
        // The typed JSON count: present from the first window, 0 until
        // the cap is reached, then one per retire folded past it.
        let folded = (cycle + 1).saturating_sub(MAX_COVERAGE_RETIRE_WINDOWS_PER_MODULE) as u64;
        for published in published_retire_folded(&engine, module) {
            assert_eq!(
                published,
                Some(serde_json::json!(folded)),
                "cycle {cycle}: published folded count"
            );
        }
    }
    let windows = engine.coverage_retire_windows();
    assert_eq!(windows.len(), MAX_COVERAGE_RETIRE_WINDOWS_PER_MODULE);
    assert_eq!(
        engine.coverage_retire.folded_for(module),
        (cycles - MAX_COVERAGE_RETIRE_WINDOWS_PER_MODULE) as u64
    );
    assert!(windows.iter().all(|window| window.end_ns.is_some()));
    assert_eq!(
        engine.coverage_retired_slots(),
        1,
        "one endpoint retired {cycles} times counts once"
    );
    assert_eq!(
        record_retire_windows(&engine, module).len(),
        MAX_COVERAGE_RETIRE_WINDOWS_PER_MODULE
    );
    // 12 cycles, cap 8: the literal pins the cap and the fold together.
    assert_eq!(
        published_retire_folded(&engine, module),
        vec![Some(serde_json::json!(4))]
    );
}

/// The pending (async worker) open point, which the live `--system`
/// path takes: a proof-backed zero-mapper retire parks there too, and the
/// pending ticket (whose plan still lists the module while the exited
/// view's row lingers) never promotes it.
#[test]
fn system_pending_zero_mapper_retire_parks_without_a_window() {
    let mut case = Case::new();
    let slot = case.engine.plan.slots[0].index;
    let retired: std::collections::BTreeSet<crate::plan::ModuleId> = case.engine.plan.slots[0]
        .module_ids
        .iter()
        .copied()
        .collect();
    case.session.scripted_stamps.insert(slot, 1);
    case.child.kill().unwrap();
    case.child.wait().unwrap();
    let view = case.engine.views.remove(0).id();
    case.engine.exit_proven_views.insert(view);
    case.engine.pending_retirements.insert(view);
    let outcome = case.engine.replay_pending_conservative(
        &mut case.session,
        &mut true,
        &mut PendingViewRetirements::new(),
    );
    assert_eq!(
        outcome.disposition,
        ApplyDisposition::Deferred,
        "premise: the retire pends on the async worker"
    );
    assert!(case.engine.pending_global_retirement.is_some());
    case.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(
        case.engine.coverage_retire_windows().is_empty(),
        "the pending zero-mapper retire opens no window: {:?}",
        case.engine.coverage_retire_windows()
    );
    assert_eq!(case.engine.coverage_retired_slots(), 0);
    assert!(!retire_skip_filed(&case.engine));
    assert_eq!(case.engine.coverage_retire_parked(), retired);
    case.release();
    let Case {
        ref mut engine,
        ref mut session,
        ..
    } = case;
    wait_for(|| {
        engine.service_backlog_quantum(session).unwrap();
        engine.pending_global_retirement.is_none()
    });
    assert!(engine.coverage_retire_windows().is_empty());
    assert!(!retire_skip_filed(engine));
}

/// Killing twin for the unproven-mapper subtraction: two processes map
/// the provider; one exits with a pin-proven exit, the other retires
/// without one (still live). The object keeps an unproven mapper, so the
/// retire stays lossy.
#[test]
fn shared_object_with_an_unproven_retiring_mapper_keeps_the_lossy_window() {
    let (mut child, mut engine, modules) = engine_with_one_accepted_provider();
    engine.scope = Scope::System;
    let mut second = std::process::Command::new("sleep")
        .arg("30")
        .die_with_parent()
        .spawn()
        .unwrap();
    let view = ProcessView::open(ProcessViewId(5), second.id()).unwrap();
    let modules2 = child_provider_modules(&view);
    engine.next_view_id = engine.next_view_id.max(6);
    engine.views.push(view);
    let mut pins = engine.pinned.clone();
    let skipped = pins.absorb(pin_test_modules(&engine.views[1], &modules2[..1]));
    let both = engine
        .live_candidate(pins, vec![modules[0].clone(), modules2[0].clone()], skipped)
        .unwrap();
    let mut session = ScriptedSession::default();
    engine
        .apply_candidate(&mut session, both, &mut true, false, &[])
        .unwrap();
    let live: Vec<_> = engine
        .plan
        .slots
        .iter()
        .filter(|slot| engine.plan.is_active(slot.index))
        .map(|slot| slot.index)
        .collect();
    assert!(!live.is_empty(), "premise: the shared provider is attached");
    for index in &live {
        session.scripted_stamps.insert(*index, 1);
    }
    child.kill().unwrap();
    child.wait().unwrap();
    let first = engine.views.remove(0).id();
    let other = engine.views[0].id();
    engine.exit_proven_views.insert(first);
    engine.pending_retirements.insert(first);
    engine.pending_retirements.insert(other);
    engine.replay_pending_conservative(&mut session, &mut true, &mut PendingViewRetirements::new());
    assert!(
        live.iter().all(|index| !engine.plan.is_active(*index)),
        "premise: both retirements retire the shared cover"
    );
    assert!(
        !engine.coverage_retire_windows().is_empty(),
        "an unproven mapper keeps the retire lossy"
    );
    assert!(engine.coverage_retire_parked().is_empty());
    assert!(retire_skip_filed(&engine));
    second.kill().unwrap();
    second.wait().unwrap();
}

/// A reallocated view id names a new generation: an earlier exit proof
/// recorded under that id must not vouch for it.
#[test]
fn reallocated_view_id_drops_its_exit_proof() {
    let mut engine = Engine::empty();
    engine.next_view_id = 8;
    engine.retired_view_ids.push(3);
    engine.exit_proven_views.insert(ProcessViewId(3));
    engine.exit_proven_views.insert(ProcessViewId(4));
    let id = engine.allocate_view_id().unwrap();
    assert_eq!(id, ProcessViewId(3), "premise: the free id is reused");
    assert!(!engine.exit_proven_views.contains(&id));
    assert!(
        engine.exit_proven_views.contains(&ProcessViewId(4)),
        "other proofs stay"
    );
}

/// The `observed-profile/v3-metrics` evidence an engine state projects:
/// the engine's retired-slot count and its skip rows, through the public
/// skip projection and the shared verdict, into the metrics document.
fn metrics_evidence(engine: &Engine) -> serde_json::Value {
    let mut ev = crate::render::tests::evidence();
    ev.coverage_retired_slots = engine.coverage_retired_slots();
    ev.skipped = engine
        .counters
        .object_skips
        .iter()
        .map(crate::render::capture_skipped_out)
        .collect();
    ev.verdict();
    let capture = crate::render::CaptureMeta {
        started: "t0",
        ended: "t1",
        kernel: "6.8.0",
        policy: crate::attach::CapturePolicy::Allowlisted,
        scope: "system",
        caller: None,
        ring_bytes: p11scope_ebpf_common::RING_BYTES,
        drain_interval_ms: 1000,
    };
    let document = crate::render::json(&[], &ev, &capture);
    assert_eq!(
        document["schema"], "p11scope/observed-profile/v3-metrics",
        "premise: the metrics schema"
    );
    document["evidence"].clone()
}

/// F1 twin (a) in metrics mode (addendum G1): the state a proof-backed
/// zero-mapper exit leaves projects a v3-metrics `evidence.completeness`
/// of COMPLETE with zero retired slots; the unproven twin (the same
/// removal without the exit proof) projects PARTIAL with the counted
/// cause, so the typed field decides, not log text.
#[test]
fn system_zero_mapper_exit_keeps_metrics_completeness_complete() {
    let (engine, _session, _modules, _retired) = system_zero_mapper_exit();
    let evidence = metrics_evidence(&engine);
    assert_eq!(evidence["completeness"], "COMPLETE", "{evidence}");
    assert_eq!(evidence["coverage_retired_slots"], 0);
    assert!(
        !evidence["gap_classes"]["observation"]["causes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|cause| cause == "coverage_retired_slots"),
        "{evidence}"
    );

    let (mut child, mut engine, _modules) = engine_with_one_accepted_provider();
    engine.scope = Scope::System;
    let slot = engine.plan.slots[0].index;
    let mut session = ScriptedSession::default();
    session.scripted_stamps.insert(slot, 1);
    child.kill().unwrap();
    child.wait().unwrap();
    let view = engine.views.remove(0).id();
    engine.pending_retirements.insert(view);
    engine.replay_pending_conservative(&mut session, &mut true, &mut PendingViewRetirements::new());
    assert!(!engine.plan.is_active(slot), "premise: the slot retired");
    let evidence = metrics_evidence(&engine);
    assert_eq!(evidence["completeness"], "PARTIAL", "{evidence}");
    assert_eq!(evidence["coverage_retired_slots"], 1);
    assert!(
        evidence["gap_classes"]["observation"]["causes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|cause| cause == "coverage_retired_slots"),
        "{evidence}"
    );
}

/// The inventory-refresh route (live `--cgroup`/`--system` path, audit
/// H1b): the provider's only mapper leaves an authoritative membership
/// walk; the refresh queues it as a ready expected removal, whose
/// pin-proven exit the conservative replay retires with zero mappers.
/// `listed` keeps the reaped pid in `cgroup.procs`: a listed pid with no
/// live process is not a member either (the walk keeps live user
/// processes only), so it departs the same way.
fn cgroup_refresh_retire(
    listed: bool,
) -> (Engine, std::collections::BTreeSet<crate::plan::ModuleId>) {
    let (mut child, mut engine, _modules) = engine_with_one_accepted_provider();
    let pid = child.id();
    let dir = tempfile::tempdir().expect("a scope directory");
    std::fs::write(dir.path().join("cgroup.procs"), format!("{pid}\n")).expect("a cgroup.procs");
    engine.scope = crate::scope::cgroup(dir.path()).expect("open scope directory");
    engine.max_scan_pids = 1024;
    engine.scheduler.set_tick_quantum_ns_for_test(u64::MAX);
    let slot = engine.plan.slots[0].index;
    let retired: std::collections::BTreeSet<crate::plan::ModuleId> =
        engine.plan.slots[0].module_ids.iter().copied().collect();
    assert!(!retired.is_empty(), "premise: the slot names its module");
    child.kill().unwrap();
    child.wait().unwrap();
    let listing = if listed {
        format!("{pid}\n")
    } else {
        String::new()
    };
    std::fs::write(dir.path().join("cgroup.procs"), listing).expect("a cgroup.procs");
    let mut session = ScriptedSession::with_records([], 0);
    session.scripted_stamps.insert(slot, 1);
    refresh_inventory_with(&mut engine, &mut session);
    assert!(
        engine.views.is_empty(),
        "premise: the refresh retired the only view: {:?}",
        engine
            .views
            .iter()
            .map(ProcessView::pid)
            .collect::<Vec<_>>()
    );
    assert!(
        !engine.plan.is_active(slot),
        "premise: the refresh retired the provider's live slot"
    );
    drop(dir);
    (engine, retired)
}

#[test]
fn cgroup_refresh_departure_with_zero_mappers_opens_no_coverage_window() {
    let (engine, retired) = cgroup_refresh_retire(false);
    assert!(
        engine.coverage_retire_windows().is_empty(),
        "no window: {:?}",
        engine.coverage_retire_windows()
    );
    assert_eq!(engine.coverage_retired_slots(), 0);
    assert!(
        !retire_skip_filed(&engine),
        "no coverage-retired row: {:?}",
        engine.counters.object_skips
    );
    assert_eq!(engine.coverage_retire_parked(), retired);
    let evidence = metrics_evidence(&engine);
    assert_eq!(evidence["coverage_retired_slots"], 0, "{evidence}");
}

/// The same departure with the reaped pid still listed: still no member,
/// so still a zero-mapper retire. A generation-lost view (a live reused
/// pid) never vouches; that arm needs pid reuse and has no deterministic
/// fixture (named in the lane report).
#[test]
fn cgroup_refresh_listed_dead_pid_departs_without_a_window() {
    let (engine, retired) = cgroup_refresh_retire(true);
    assert!(
        engine.coverage_retire_windows().is_empty(),
        "{:?}",
        engine.coverage_retire_windows()
    );
    assert_eq!(engine.coverage_retired_slots(), 0);
    assert!(!retire_skip_filed(&engine));
    assert_eq!(engine.coverage_retire_parked(), retired);
}

/// Probe SoftHSM (Debian then Fedora paths); panic loudly when absent —
/// the B1 refresh twins need a real provider the real scan decodes,
/// never a skip.
fn b1_softhsm_path() -> std::path::PathBuf {
    for candidate in [
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib64/pkcs11/libsofthsm2.so",
    ] {
        let path = std::path::PathBuf::from(candidate);
        if path.is_file() {
            return path;
        }
    }
    panic!("SoftHSM not installed (probed Debian and Fedora paths)");
}

/// A long-lived holder mapping the real SoftHSM provider (no calls,
/// just the mapping): `python3 -c` loads it with ctypes, then sleeps.
/// Returns the child once `libsofthsm2.so` is visible in its maps.
fn b1_softhsm_holder() -> std::process::Child {
    let mut child = std::process::Command::new("python3")
        .args([
            "-c",
            "import ctypes, sys, time; ctypes.CDLL(sys.argv[1]); time.sleep(30)",
        ])
        .arg(b1_softhsm_path())
        .die_with_parent()
        .spawn()
        .expect("spawn the SoftHSM holder");
    let pid = child.id();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let maps =
            std::fs::read_to_string(format!("/proc/{pid}/maps")).expect("read the holder maps");
        if maps.contains("libsofthsm2.so") {
            return child;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the holder never mapped SoftHSM"
        );
        assert!(
            child.try_wait().expect("poll the holder").is_none(),
            "the holder exited before mapping SoftHSM"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Tick 0 of the B1 refresh twins: admit the first SoftHSM holder
/// through the real refresh path. Returns the engine, the reused
/// session, the live scope dir, the attached module ids, the live
/// holder (the caller kills it) and the attached endpoint count.
fn cgroup_refresh_admit_first() -> (
    Engine,
    ScriptedSession,
    tempfile::TempDir,
    std::collections::BTreeSet<crate::plan::ModuleId>,
    std::process::Child,
    usize,
) {
    let mut engine = Engine::empty();
    let dir = tempfile::tempdir().expect("a scope directory");
    engine.scope = crate::scope::cgroup(dir.path()).expect("open scope directory");
    engine.max_scan_pids = 1024;
    engine.scheduler.set_tick_quantum_ns_for_test(u64::MAX);
    let mut session = ScriptedSession::with_records([], 0);
    let first = b1_softhsm_holder();
    std::fs::write(dir.path().join("cgroup.procs"), format!("{}\n", first.id()))
        .expect("a cgroup.procs");
    cgroup_refresh_until_cover(&mut engine, &mut session);
    assert!(
        engine.views.iter().any(|view| view.pid() == first.id()),
        "premise: tick 0 admitted the first holder"
    );
    let attached: Vec<u32> = engine
        .plan
        .slots
        .iter()
        .filter(|slot| engine.plan.is_active(slot.index))
        .map(|slot| slot.index)
        .collect();
    assert!(
        !attached.is_empty(),
        "premise: tick 0 attached the provider"
    );
    let retired: std::collections::BTreeSet<crate::plan::ModuleId> =
        engine.plan.slots[0].module_ids.iter().copied().collect();
    assert!(!retired.is_empty(), "premise: the slot names its module");
    let endpoints = attached.len();
    for slot in attached {
        session.scripted_stamps.entry(slot).or_insert(1);
    }
    (engine, session, dir, retired, first, endpoints)
}

/// Tick 1 of the B1 refresh twins: the only mapper exits and the real
/// refresh path parks its zero-mapper retire (no window, no row, no
/// count). Returns the engine, the reused session, the live scope dir
/// (kept alive for later ticks), the retired module ids and the
/// retired endpoint count.
fn cgroup_refresh_park() -> (
    Engine,
    ScriptedSession,
    tempfile::TempDir,
    std::collections::BTreeSet<crate::plan::ModuleId>,
    usize,
) {
    let (mut engine, mut session, dir, retired, mut first, endpoints) =
        cgroup_refresh_admit_first();
    first.kill().unwrap();
    first.wait().unwrap();
    std::fs::write(dir.path().join("cgroup.procs"), String::new()).expect("a cgroup.procs");
    refresh_inventory_with(&mut engine, &mut session);
    assert!(
        engine.views.is_empty(),
        "premise: the refresh retired the only view"
    );
    assert!(
        engine
            .plan
            .slots
            .iter()
            .all(|slot| !engine.plan.is_active(slot.index)),
        "premise: the refresh retired the provider's live slots"
    );
    assert!(
        engine.coverage_retire_windows().is_empty(),
        "premise: the zero-mapper retire parked"
    );
    assert_eq!(
        engine.coverage_retire_parked(),
        retired,
        "premise: parked for its module"
    );
    (engine, session, dir, retired, endpoints)
}

/// Refresh until the provider has live cover again (bounded):
/// newcomer admission pipelines over ticks (a scan can defer a tick),
/// so the B1 twins wait for the re-attach they assert about instead
/// of assuming its tick. Fails loudly when cover never returns.
/// Returns the per-tick apply counts; the completion tick's count pins
/// the no-follow-up shape (the seam suppresses the loader-arm apply).
fn cgroup_refresh_until_cover_counted(
    engine: &mut Engine,
    session: &mut ScriptedSession,
) -> Vec<usize> {
    let mut counts = Vec::new();
    engine.capture_candidates_for_test = true;
    for _ in 0..6 {
        engine.captured_candidates_for_test.clear();
        refresh_inventory_with(engine, session);
        counts.push(engine.captured_candidates_for_test.len());
        if engine
            .plan
            .slots
            .iter()
            .any(|slot| engine.plan.is_active(slot.index))
        {
            engine.capture_candidates_for_test = false;
            return counts;
        }
    }
    engine.capture_candidates_for_test = false;
    panic!("cover never returned within 6 ticks");
}

fn cgroup_refresh_until_cover(engine: &mut Engine, session: &mut ScriptedSession) {
    cgroup_refresh_until_cover_counted(engine, session);
}

/// B1 twin (1), red: a parked retire plus a same-tick admit and
/// re-attach through the real refresh path, on a tick with no
/// follow-up (the seam skips the loader-arm phase, like the
/// production tick whose tail never runs). The mapper rides only as
/// an extra_view: its scans commit in the apply but its view joins
/// `self.views` after it. Only the post-push settlement can promote:
/// removing it leaves the park and no window. Passes with one window
/// from the detach instant, closed at the re-attach, the row and an
/// exact endpoint count — and a later idle tick leaves its end
/// untouched.
#[test]
fn cgroup_refresh_admit_and_reattach_promotes_parked_retire_closed_at_reattach() {
    let (mut engine, mut session, dir, retired, endpoints) = cgroup_refresh_park();
    let mut mapper = b1_softhsm_holder();
    let mapper_pid = mapper.id();
    std::fs::write(dir.path().join("cgroup.procs"), format!("{mapper_pid}\n"))
        .expect("a cgroup.procs");
    engine.skip_tick_arm_for_test = true;
    let counts = cgroup_refresh_until_cover_counted(&mut engine, &mut session);
    assert_eq!(
        counts.last(),
        Some(&1),
        "premise: the completion tick ran only the admit apply, no follow-up: {counts:?}"
    );
    assert!(
        engine.views.iter().any(|view| view.pid() == mapper_pid),
        "premise: the refresh admitted the mapper"
    );
    let windows = engine.coverage_retire_windows();
    assert_eq!(windows.len(), retired.len(), "one window: {windows:?}");
    for window in &windows {
        assert_eq!(
            window.modules, retired,
            "the window attributes to the retired module"
        );
        assert!(
            window.end_ns.is_some(),
            "the re-attach closed the window: {window:?}"
        );
        assert!(
            window.end_ns.unwrap() >= window.start_ns,
            "the window never ends before it starts: {window:?}"
        );
    }
    let closed_end = windows[0].end_ns;
    assert_eq!(
        engine.coverage_retired_slots(),
        endpoints as u64,
        "every retired endpoint counted once"
    );
    assert!(
        retire_skip_filed(&engine),
        "the coverage-retired row is filed"
    );
    assert!(
        engine.coverage_retire_parked().is_empty(),
        "promotion drained the park"
    );
    for module in &retired {
        assert_eq!(record_retire_windows(&engine, *module).len(), 1);
    }
    // An idle tick with the mapper still listed leaves the closed
    // window untouched: its end is the re-attach, not a later apply.
    refresh_inventory_with(&mut engine, &mut session);
    let windows = engine.coverage_retire_windows();
    assert_eq!(
        windows.len(),
        retired.len(),
        "no second window: {windows:?}"
    );
    assert_eq!(windows[0].end_ns, closed_end, "the end is the re-attach");
    mapper.kill().unwrap();
    mapper.wait().unwrap();
}

/// B1 twin (1b), red: the park and the admit share one tick (the common
/// sequential-client shape: A exits while B is already listed), with
/// no follow-up (seam, see twin (1)). The replay parks before B's
/// scans commit, the apply admits and re-attaches B, and only the
/// post-push settlement can promote. The completion tick runs the
/// replay plus the admit when nothing defers (2), else the admit
/// alone (1).
#[test]
fn cgroup_refresh_same_tick_exit_and_admit_discloses_until_reattach() {
    let (mut engine, mut session, dir, retired, mut first, endpoints) =
        cgroup_refresh_admit_first();
    let mut mapper = b1_softhsm_holder();
    let mapper_pid = mapper.id();
    first.kill().unwrap();
    first.wait().unwrap();
    std::fs::write(dir.path().join("cgroup.procs"), format!("{mapper_pid}\n"))
        .expect("a cgroup.procs");
    engine.skip_tick_arm_for_test = true;
    let counts = cgroup_refresh_until_cover_counted(&mut engine, &mut session);
    assert!(
        counts.last().is_some_and(|count| *count <= 2),
        "premise: the completion tick ran no follow-up apply: {counts:?}"
    );
    assert!(
        engine.views.iter().any(|view| view.pid() == mapper_pid),
        "premise: the refresh admitted the mapper"
    );
    let windows = engine.coverage_retire_windows();
    assert_eq!(windows.len(), retired.len(), "one window: {windows:?}");
    for window in &windows {
        assert_eq!(window.modules, retired);
        assert!(
            window.end_ns.is_some(),
            "closed at the re-attach: {window:?}"
        );
    }
    assert_eq!(engine.coverage_retired_slots(), endpoints as u64);
    assert!(retire_skip_filed(&engine));
    assert!(engine.coverage_retire_parked().is_empty());
    mapper.kill().unwrap();
    mapper.wait().unwrap();
}

/// B1 twin (2), red: the mapper admitted with no follow-up (seam,
/// see twin (1)) exits before the next tick. Only the post-push
/// settlement can promote, so removing it leaves the park parked and
/// the exit undisclosed. Passes with the closed window surviving the
/// exit; the exit tick parks the mapper's own exit, like twin (a).
#[test]
fn cgroup_refresh_short_lived_mapper_leaves_a_disclosed_window() {
    let (mut engine, mut session, dir, retired, endpoints) = cgroup_refresh_park();
    let mut mapper = b1_softhsm_holder();
    let mapper_pid = mapper.id();
    std::fs::write(dir.path().join("cgroup.procs"), format!("{mapper_pid}\n"))
        .expect("a cgroup.procs");
    engine.skip_tick_arm_for_test = true;
    let counts = cgroup_refresh_until_cover_counted(&mut engine, &mut session);
    assert_eq!(
        counts.last(),
        Some(&1),
        "premise: the completion tick ran only the admit apply, no follow-up: {counts:?}"
    );
    let windows = engine.coverage_retire_windows();
    assert_eq!(
        windows.len(),
        retired.len(),
        "premise: one window: {windows:?}"
    );
    assert!(
        windows[0].end_ns.is_some(),
        "premise: closed at the re-attach: {:?}",
        windows[0]
    );
    let (start_ns, end_ns) = (windows[0].start_ns, windows[0].end_ns);
    mapper.kill().unwrap();
    mapper.wait().unwrap();
    std::fs::write(dir.path().join("cgroup.procs"), String::new()).expect("a cgroup.procs");
    for slot in engine
        .plan
        .slots
        .iter()
        .map(|slot| slot.index)
        .collect::<Vec<_>>()
    {
        session.scripted_stamps.entry(slot).or_insert(1);
    }
    refresh_inventory_with(&mut engine, &mut session);
    let windows = engine.coverage_retire_windows();
    assert_eq!(
        windows.len(),
        retired.len(),
        "the exit left the window undisclosed or duplicated: {windows:?}"
    );
    assert_eq!(windows[0].start_ns, start_ns, "the detach instant is kept");
    assert_eq!(windows[0].end_ns, end_ns, "the re-attach end is kept");
    assert_eq!(
        engine.coverage_retired_slots(),
        endpoints as u64,
        "every retired endpoint counted once"
    );
    assert!(retire_skip_filed(&engine));
    assert_eq!(
        engine.coverage_retire_parked(),
        retired,
        "the mapper's own exit parks like twin (a)"
    );
}

/// A plan listing is no mapper (audit H1b, the manifest-held getter
/// cell): the candidate still lists the retired module (a manifest keeps
/// its object planned) but no scan the candidate keeps maps it, so the
/// proven exit parks the retire. Twin of
/// `exit_proof_with_a_remaining_mapper_keeps_the_lossy_window`, whose
/// candidate keeps the live scan.
#[test]
fn exit_proof_with_a_plan_listing_but_no_scan_parks_the_retire() {
    let (_child, mut engine, modules) = engine_with_one_accepted_provider();
    let mut candidate = peer_candidate(&mut engine, &modules);
    candidate.delta.retire.push(engine.plan.slots[0].clone());
    candidate.plan.deactivate(0);
    let retired: std::collections::BTreeSet<crate::plan::ModuleId> =
        engine.plan.slots[0].module_ids.iter().copied().collect();
    let objects: std::collections::BTreeSet<_> = candidate
        .plan
        .modules
        .iter()
        .filter(|module| retired.contains(&module.id))
        .map(|module| module.object)
        .collect();
    assert!(
        !objects.is_empty(),
        "premise: the candidate still lists the module"
    );
    candidate
        .modules
        .retain(|module| !objects.contains(&module.object));
    let mut session = ScriptedSession::default();
    session
        .scripted_stamps
        .insert(engine.plan.slots[0].index, 1);
    engine
        .apply_candidate_with_ended(
            &mut session,
            candidate,
            &mut true,
            false,
            &[],
            None,
            Some(&retired),
        )
        .unwrap();
    assert!(!engine.plan.is_active(0), "premise: the slot retired");
    assert!(
        engine.coverage_retire_windows().is_empty(),
        "{:?}",
        engine.coverage_retire_windows()
    );
    assert!(!retire_skip_filed(&engine));
    assert_eq!(engine.coverage_retire_parked(), retired);
}

/// One accepted provider whose final `p11_return` close the test holds
/// open until the returned guard drops (no timeout: the close stays
/// pending for as long as the test keeps the guard), with the global
/// native retirement already handed off to the worker.
fn held_open_retirement() -> (Case, impl Drop) {
    struct ReleaseOnDrop(Arc<(Mutex<bool>, Condvar)>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            *self.0.0.lock().unwrap() = true;
            self.0.1.notify_all();
        }
    }
    let mut case = Case::new();
    let hold = Arc::new((Mutex::new(false), Condvar::new()));
    let gate = Arc::clone(&hold);
    let (sender, entered) = mpsc::channel();
    case.session.global_retirement = Some(RefCell::new(RetirementFixture::new(
        &case.engine.plan.slots,
        &case.engine.pinned,
        Box::new(move |owned: OwnedLink, producer| {
            if producer == ProducerProgram::UProbe("p11_return") {
                sender.send(()).map_err(|error| error.to_string())?;
                let (lock, changed) = &*gate;
                let _released = changed
                    .wait_while(lock.lock().unwrap(), |released| !*released)
                    .map_err(|error| error.to_string())?;
            }
            drop(owned);
            Ok(())
        }),
    )));
    case.entered = entered;
    case.hold_pending();
    (case, ReleaseOnDrop(hold))
}

/// The kill-leg wait fails by name when the actual close is held open
/// past the settle deadline: the named message carries this tick's and
/// the accumulated waits, so a never-finishing close is never mistaken
/// for slow admission.
#[test]
#[should_panic(expected = "twin: the global native retirement did not settle within 120s (tick 3:")]
fn kill_leg_wait_names_a_close_held_open_past_the_settle_deadline() {
    use crate::discovery::engine::pressure_native_tests::{
        RetirementWaits, wait_for_global_retirement,
    };
    let (mut case, _release) = held_open_retirement();
    assert!(case.engine.pending_global_retirement.is_some());
    let mut waits = RetirementWaits::default();
    wait_for_global_retirement(&mut case.engine, &mut case.session, &mut waits, 3, "twin");
}

/// Healthy twins of the kill-leg wait: nothing pending waits nothing and
/// records nothing; a close that finishes is waited out through the
/// production poll and recorded, and the barrier clears.
#[test]
fn kill_leg_wait_records_only_actual_pending_closes() {
    use crate::discovery::engine::pressure_native_tests::{
        RetirementWaits, wait_for_global_retirement,
    };
    let (mut case, release) = held_open_retirement();
    let mut idle = Engine::empty();
    let mut waits = RetirementWaits::default();
    let none = wait_for_global_retirement(&mut idle, &mut case.session, &mut waits, 0, "idle");
    assert_eq!(none, Duration::ZERO);
    assert_eq!(
        waits,
        RetirementWaits::default(),
        "no pending close, no wait"
    );
    drop(release);
    let waited =
        wait_for_global_retirement(&mut case.engine, &mut case.session, &mut waits, 1, "held");
    assert!(case.engine.pending_global_retirement.is_none());
    assert!(waits.polls >= 1, "the pending close was polled: {waits:?}");
    assert_eq!(waits.total, waited, "the one wait is the whole record");
    let again = wait_for_global_retirement(
        &mut case.engine,
        &mut case.session,
        &mut waits,
        2,
        "settled",
    );
    assert_eq!(again, Duration::ZERO);
    assert_eq!(waits.total, waited, "a settled barrier adds no wait");
}

/// Freed-slot admission: a newcomer that arrives while a retired slot's
/// links detach on the cleanup worker waits behind that global
/// retirement (a pending batch owns the whole candidate boundary), however
/// many frames run, and admits on the first frame after the worker
/// settles. The wait is bounded by the worker's actual close, never by a
/// frame count: the deterministic half of the live freed-slot leg.
#[test]
fn async_global_newcomer_waits_for_the_detach_then_admits_on_the_settling_frame() {
    let mut case = Case::new();
    let scope = case.bounded_scope();
    let peers = e06_spawn_sleeps(1);
    let newcomer = peers[0].pid();
    let candidate = case.candidate();
    let outcome = case
        .engine
        .apply_candidate(&mut case.session, candidate, &mut true, false, &[])
        .unwrap();
    assert_eq!(outcome.disposition, ApplyDisposition::Deferred);
    case.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    e06_write_listing(scope.path(), &[case.child.id(), newcomer]);
    let admitted = |engine: &Engine| engine.views.iter().any(|view| view.pid() == newcomer);
    let scans = case.engine.deep_scans;
    for frame in 0..40 {
        case.engine
            .drain_discovery_shallow_from(&mut case.session, false)
            .unwrap();
        case.engine
            .service_backlog_quantum(&mut case.session)
            .unwrap();
        assert!(
            case.engine.pending_global_retirement.is_some(),
            "frame {frame}: the worker still holds the detach"
        );
        assert!(
            !admitted(&case.engine),
            "frame {frame}: no newcomer admits behind a pending retirement"
        );
    }
    assert_eq!(
        case.engine.deep_scans, scans,
        "a blocked frame scans nothing it would have to discard"
    );
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
    assert!(case.engine.take_immediate_exec_recovery_frame());
    case.engine
        .drain_discovery_shallow_from(&mut case.session, false)
        .unwrap();
    assert!(
        admitted(&case.engine),
        "the newcomer admits on the first frame after the worker settles"
    );
}

/// Refresh-skip gate twin (B2a): a batch that arrives with
/// retirements already queued skips the inventory refresh — the
/// `pending_retirements` gate is independent, not redundant with the
/// ticket barrier. The collected-finish budget is exhausted, so the
/// batch's conservative replay is really skipped and the queued id
/// (synthetic: never resolved, never detached) persists to the gate;
/// no ticket exists anywhere. Releasing the budget lets the replay
/// drain it and the next batch refreshes again.
#[test]
fn async_global_pending_retirements_alone_skip_the_refresh() {
    let mut case = Case::new();
    let _scope = case.bounded_scope();
    case.engine
        .pending_retirements
        .insert(ProcessViewId(u32::MAX));
    case.engine.collected_finish_actions = Some(0);
    assert!(
        case.engine.pending_global_retirement.is_none(),
        "premise: no ticket"
    );
    let passes = case.engine.inventory_passes;
    let scans = case.engine.deep_scans;
    apply_ordinary_batch(&mut case.engine, &mut case.session, Vec::new()).unwrap();
    assert_eq!(
        case.engine.inventory_passes, passes,
        "a queued retirement skips the refresh"
    );
    assert_eq!(
        case.engine.deep_scans, scans,
        "a skipped refresh scans nothing"
    );
    assert!(
        case.engine.pending_global_retirement.is_none(),
        "no ticket parks"
    );
    assert!(
        !case.engine.pending_retirements.is_empty(),
        "the skipped replay retains the queue"
    );
    // Releasing the budget lets the replay drain the queue, and the
    // next batch refreshes again.
    case.engine.collected_finish_actions = None;
    apply_ordinary_batch(&mut case.engine, &mut case.session, Vec::new()).unwrap();
    assert!(
        case.engine.pending_retirements.is_empty(),
        "the replay drains the trivial queue"
    );
    assert!(
        case.engine.pending_global_retirement.is_none(),
        "still no ticket"
    );
    assert_eq!(
        case.engine.inventory_passes,
        passes + 1,
        "a clean batch refreshes"
    );
}

/// Apply entry-guard twin (B2c): while a global retirement ticket is
/// pending, a direct newcomer apply defers at the candidate-boundary
/// guard — nothing commits, nothing admits. The guard is the final
/// owner of the pending-batch invariant, behind every caller.
#[test]
fn async_global_apply_defers_behind_a_pending_ticket() {
    let mut case = Case::new();
    let _scope = case.bounded_scope();
    // Establish the ticket exactly like the live leg: the first apply
    // retires a slot and its detach pends on the worker.
    let candidate = case.candidate();
    let outcome = case
        .engine
        .apply_candidate(&mut case.session, candidate, &mut true, false, &[])
        .unwrap();
    assert_eq!(outcome.disposition, ApplyDisposition::Deferred);
    assert!(
        case.engine.pending_global_retirement.is_some(),
        "premise: the detach parks its ticket"
    );
    case.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    // A fresh peer-newcomer candidate against the post-ticket engine:
    // the first apply deactivated its slot, so the peer plus the
    // re-planned slot allocate anew (no count pinned — the Deferred
    // verdict below is the assertion). Nothing here detaches, so only
    // the entry guard can defer it.
    let mut pins = case.engine.pinned.clone();
    let skipped = pins.absorb(pin_test_modules(&case.engine.views[0], &case.modules[1..2]));
    let newcomer = case
        .engine
        .live_candidate(pins, case.modules.clone(), skipped)
        .unwrap();
    let views_before = case.engine.views.len();
    let outcome = case
        .engine
        .apply_candidate(&mut case.session, newcomer, &mut true, false, &[])
        .unwrap();
    assert_eq!(
        outcome.disposition,
        ApplyDisposition::Deferred,
        "a pending batch owns the whole candidate boundary"
    );
    assert_eq!(
        case.engine.views.len(),
        views_before,
        "nothing admits behind the ticket"
    );
    // Teardown settles the worker exactly like the twin, so nothing hangs.
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
}
