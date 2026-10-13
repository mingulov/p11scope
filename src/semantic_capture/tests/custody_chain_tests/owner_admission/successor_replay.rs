//! SPDX-License-Identifier: GPL-3.0-or-later
//! Actual ClassicDriver admission composed with the coordinator's H6 handoff.
//! The child, mapped provider, held files and receipt validation are real.
//! Inventory map reads and Detailed records/clocks are deterministic inputs:
//! this is no kernel attach, nonleader-exec or teardown timing qualification.

use super::*;
use crate::discovery::caller_registry::CallerEvent;
use crate::events::{EventDrain, ScriptedRecords, record_bytes};
use std::ops::ControlFlow;

/// Only the Inventory object's cookie-query transport is substituted. The
/// binder still queries the real original process pin and validates its
/// incarnation. Equal scalar cookies do not bridge this object to Detailed.
struct InventoryReplay {
    domain: NativeDomainId,
    pid: u32,
    cookie: u64,
    queried: Vec<(NativeDomainId, u32)>,
}

impl NativeIdentity<PidPin> for InventoryReplay {
    fn owner_image(&mut self, _: u32) -> Option<ImageIdentity> {
        None
    }

    fn query_cookie(&mut self, domain: NativeDomainId, pin: &PidPin) -> CookieQuery {
        self.queried.push((domain, pin.pid()));
        if domain != self.domain || pin.pid() != self.pid || pin.pidfd().is_err() {
            return CookieQuery::Unavailable("foreign Inventory object or process custody".into());
        }
        CookieQuery::Cookie(DomainCookie::scripted(domain, self.cookie))
    }
}

/// A retained byte sequence, captured before the transition. Replay goes
/// through the actual EVENTS decoder, never by editing an old record's image,
/// timestamps, stamps or position after the boundary.
struct DeferredCalls {
    bytes: Vec<Vec<u8>>,
}

impl DeferredCalls {
    fn take(owned: &mut AdmissionH0) -> Self {
        Self {
            bytes: std::mem::take(&mut owned.io.held.script.records)
                .iter()
                .map(record_bytes)
                .collect(),
        }
    }

    fn replay(self, owned: &mut AdmissionH0, quantum: usize) {
        assert!(quantum > 0);
        assert!(owned.io.held.script.records.is_empty());
        let mut drain = EventDrain::over(ScriptedRecords::records(
            self.bytes.clone(),
            self.bytes.len(),
        ));
        let mut decoded = Vec::new();
        while drain.poll_records(Some(quantum), |record| {
            decoded.push(record_bytes(&record));
            owned.io.held.script.records.push_back(record);
            ControlFlow::Continue(())
        }) {}
        assert_eq!(drain.malformed(), 0);
        assert_eq!(drain.source().remaining(), 0);
        assert_eq!(
            decoded, self.bytes,
            "deferred record bytes must remain exact"
        );
    }
}

#[derive(Clone, Copy, Debug)]
enum ExecShape {
    SameCookie,
    CrossCookie,
}

#[derive(Clone, Copy, Debug)]
enum DeferredOperation {
    InitAndReturn,
    ReturnAfterInit,
}

/// The source-facing read/drain/read wave used by H6: all horizons are
/// deterministic, while the coordinator mints and verifies the original
/// retained-custody handoff itself. No Detailed witness or prebinding occurs.
fn witness_read(
    domain: NativeDomainId,
    rows: Vec<WitnessRow>,
    at_ns: u64,
    custody: ScopeCustody,
) -> WitnessBatch {
    WitnessBatch {
        domain,
        phase: CapturePhase::Active,
        rows,
        integrity: Vec::new(),
        integrity_total: 0,
        visited: 0,
        sweep_completed: true,
        sweeps_completed: 1,
        row_bound_reached: false,
        deadline_reached: false,
        read_failures: Vec::new(),
        unrecorded_rows: 0,
        sweep_gaps: false,
        counts: Vec::new(),
        refresh_sweep_completed: true,
        refresh_sweep_gaps: false,
        refresh_deadline_reached: false,
        refresh_sweeps_completed: 1,
        seen_rows: 0,
        pair_limit: 65_536,
        health: CaptureHealth {
            discovery_counters: Some([0; 5]),
            ..CaptureHealth::default()
        },
        health_regression: None,
        health_unproven: None,
        health_baseline_ns: 0,
        health_read_ns: at_ns,
        rows_anchor_ns: at_ns + 1,
        rows_read_ns: at_ns + 1,
        counts_read_ns: at_ns + 1,
        changed_objects: Vec::new(),
        custody,
        custody_proven_ns: None,
        lifecycle_proven_ns: u64::MAX,
        lifecycle_loss: None,
        unsettled: false,
    }
}

fn witness_wave(
    scene: &mut AdmissionScene,
    identity: &mut InventoryReplay,
    image: ImageIdentity,
    at_ns: u64,
) -> Vec<CallerEvent> {
    SIGHT_NS.with(|clock| clock.set(at_ns + 2));
    let custody = if matches!(scene.scope, Scope::Pid(_)) {
        ScopeCustody::PidHeld
    } else {
        ScopeCustody::System
    };
    let row = WitnessRow::scripted(
        identity.domain,
        image.task_cookie,
        image.exec_id,
        AttachObjectId::scripted(0),
        EndpointId(0),
        scene.child.id(),
        at_ns + 3,
    );
    let mut events = Vec::new();
    for batch in [
        NativeBatch::Witness(Box::new(witness_read(
            identity.domain,
            vec![row],
            at_ns + 4,
            custody.clone(),
        ))),
        NativeBatch::Lifecycle(DiscoveryBatch::scripted(
            identity.domain,
            Vec::new(),
            at_ns + 10,
        )),
        NativeBatch::Witness(Box::new(witness_read(
            identity.domain,
            Vec::new(),
            at_ns + 20,
            custody,
        ))),
    ] {
        events.extend(
            scene
                .coordinator
                .stage_native(batch, identity, at_ns + 22)
                .events,
        );
    }
    scene.coordinator.commit_batch(false).unwrap();
    events
}

fn pass_with_inventory(scene: &mut AdmissionScene, identity: &mut InventoryReplay) {
    let collected = scene.collect();
    scene.lane = Some(crate::inventory::classic_semantic_pass_for_test(
        &mut scene.coordinator,
        scene.lane.take().unwrap(),
        &scene.scope,
        collected,
        identity,
    ));
}

fn completed(scene: &AdmissionScene, caller: CallerId) -> u64 {
    scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .filter(|row| row.caller == caller)
        .filter_map(|row| row.semantics.as_ref())
        .map(|reducer| reducer.completed())
        .sum()
}

fn run_successor_replay(
    selection: Selection,
    shape: ExecShape,
    deferred: DeferredOperation,
    quantum: usize,
) {
    let mut scene = Box::new(AdmissionScene::new(selection));
    scene.prepare_without_cookie();
    let old = scene.caller();
    let pid = scene.child.id();
    let old_start = scene.coordinator.adapter().record(old).unwrap().start_time;
    scene.observe_entry();
    scene.h0.0.borrow_mut().after_refresh = Some(Box::new(move |owned| {
        owned.io.held.enqueue(pid, 0, "C_SignInit", 0x000d, 0);
    }));
    for _ in 0..3 {
        scene.pass();
    }
    scene.assert_admitted();
    let original = scene
        .coordinator
        .semantic_bindings()
        .get(old)
        .unwrap()
        .pin();
    let original_instance = scene.coordinator.registry().instances().next().unwrap().id;
    assert_eq!(completed(&scene, old), 0);
    assert!(
        scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .any(|row| {
                row.caller == old
                    && row
                        .semantics
                        .as_ref()
                        .is_some_and(|reducer| reducer.started() == 1)
            })
    );

    let calls = {
        let mut owned = scene.h0.0.borrow_mut();
        if matches!(deferred, DeferredOperation::InitAndReturn) {
            owned.io.held.enqueue(pid, 0, "C_SignInit", 0x000d, 0);
        }
        owned.io.held.enqueue(pid, 0, "C_Sign", 0, 0);
        DeferredCalls::take(&mut owned)
    };
    assert_eq!(
        calls.bytes.len(),
        if matches!(deferred, DeferredOperation::InitAndReturn) {
            2
        } else {
            1
        }
    );

    let mut inventory = InventoryReplay {
        domain: scene.identity.0,
        pid,
        cookie: 41,
        queried: Vec::new(),
    };
    assert_ne!(inventory.domain, scene.lane.as_ref().unwrap().domain());
    scene.coordinator.set_semantic_binding_clock(sight_clock);
    scene.coordinator.note_extend_receipt(&ExtendReceipt {
        activated_roots: true,
        exec_coverage: Some(ExecCoverage::scripted(inventory.domain, 0)),
        ..ExtendReceipt::default()
    });
    let at_ns = now_ns();
    let old_inventory = ImageIdentity {
        task_cookie: 41,
        exec_id: 1,
    };
    assert!(witness_wave(&mut scene, &mut inventory, old_inventory, at_ns).is_empty());
    let new_inventory = match shape {
        ExecShape::SameCookie => ImageIdentity {
            task_cookie: 41,
            exec_id: 2,
        },
        ExecShape::CrossCookie => ImageIdentity {
            task_cookie: 42,
            exec_id: 0,
        },
    };
    inventory.cookie = new_inventory.task_cookie;
    let events = witness_wave(&mut scene, &mut inventory, new_inventory, at_ns + 100);
    let [CallerEvent::ExecRetired { old: retired, new }] = events.as_slice() else {
        panic!("the actual coordinator must mint one successor: {events:?}");
    };
    assert_eq!(*retired, old);
    let successor = *new;
    assert_ne!(successor, old);
    assert_eq!(scene.caller(), successor);
    assert!(scene.coordinator.adapter().record(old).unwrap().retired);
    assert_eq!(
        scene
            .coordinator
            .adapter()
            .record(successor)
            .unwrap()
            .authority,
        ImageAuthority::ScanPinned,
        "an Inventory replay handoff must not promote scan custody to native authority"
    );
    assert_eq!(
        scene
            .coordinator
            .adapter()
            .record(successor)
            .unwrap()
            .start_time,
        old_start
    );
    assert_eq!(
        completed(&scene, old),
        0,
        "retirement ends the original in-flight operation"
    );

    let successor_image = match shape {
        ExecShape::SameCookie => ImageIdentity {
            task_cookie: 7,
            exec_id: 2,
        },
        ExecShape::CrossCookie => ImageIdentity {
            task_cookie: 8,
            exec_id: 0,
        },
    };
    scene.h0.0.borrow_mut().io.current = Some(successor_image);
    scene.h0.0.borrow_mut().after_refresh =
        Some(Box::new(move |owned| calls.replay(owned, quantum)));
    for _ in 0..3 {
        pass_with_inventory(&mut scene, &mut inventory);
    }
    let binding = scene
        .coordinator
        .semantic_bindings()
        .get(successor)
        .expect("fresh H0 owner coverage must admit the actual successor");
    assert_eq!(binding.image(), successor_image);
    assert!(
        Arc::ptr_eq(
            &binding.pin(),
            scene.h0.0.borrow().last_effective.as_ref().unwrap()
        ),
        "the coordinator must consume H0's effective custody"
    );
    assert!(
        Arc::ptr_eq(&original, &binding.pin()),
        "an actual retained-process handoff must preserve H0's original custody Arc"
    );
    assert_eq!(
        completed(&scene, old),
        0,
        "deferred old returns cannot complete the ended operation"
    );
    assert_eq!(
        completed(&scene, successor),
        0,
        "deferred old Init/return bytes cannot become successor work"
    );
    assert!(scene.coordinator.registry().instances().any(|instance| {
        instance.caller == old
            && instance.id == original_instance
            && instance.state != InstanceLifecycle::Observed
    }));
    assert!(
        scene
            .coordinator
            .registry()
            .instances()
            .any(|instance| { instance.caller == successor && instance.id != original_instance })
    );

    let physical_before: Vec<_> = scene
        .coordinator
        .registry()
        .edges_of(successor)
        .map(|edge| (edge.module, edge.entry_count))
        .collect();
    let slot = scene.h0.0.borrow().io.held.slot(0, "C_SignInit");
    scene
        .lane
        .as_mut()
        .unwrap()
        .refresh_candidate_with_custody(binding.pin(), slot)
        .unwrap();
    {
        let mut owned = scene.h0.0.borrow_mut();
        owned.io.held.enqueue(pid, 0, "C_SignInit", 0x000d, 0);
        owned.io.held.enqueue(pid, 0, "C_Sign", 0, 0);
    }
    pass_with_inventory(&mut scene, &mut inventory);
    assert_eq!(
        completed(&scene, successor),
        1,
        "fresh successor Init/Sign must remain useful"
    );
    assert_eq!(
        scene
            .coordinator
            .adapter()
            .record(successor)
            .unwrap()
            .authority,
        ImageAuthority::ScanPinned,
        "useful H0 semantic receipt coverage leaves caller image authority scan-pinned"
    );
    assert_eq!(completed(&scene, old), 0);
    assert_eq!(
        scene.h0.0.borrow().capture.continuity_cuts(),
        0,
        "an image retirement alone does not invent a physical-gap episode"
    );
    let physical_after: Vec<_> = scene
        .coordinator
        .registry()
        .edges_of(successor)
        .map(|edge| (edge.module, edge.entry_count))
        .collect();
    assert_eq!(
        physical_after, physical_before,
        "semantic replay cannot invent physical entry counts"
    );
    assert!(!inventory.queried.is_empty());
    assert!(
        inventory
            .queried
            .iter()
            .all(|(domain, target)| { *domain == inventory.domain && *target == pid }),
        "only the actual held Inventory domain/process was queried"
    );
}

#[test]
fn same_cookie_successor_replay_keeps_delayed_calls_historical() {
    for selection in [Selection::Pid, Selection::System] {
        for (deferred, quantum) in [
            (DeferredOperation::InitAndReturn, 1),
            (DeferredOperation::ReturnAfterInit, 2),
        ] {
            run_successor_replay(selection, ExecShape::SameCookie, deferred, quantum);
        }
    }
}

#[test]
fn cross_cookie_successor_replay_keeps_delayed_calls_historical() {
    for selection in [Selection::Pid, Selection::System] {
        for (deferred, quantum) in [
            (DeferredOperation::InitAndReturn, 2),
            (DeferredOperation::ReturnAfterInit, 1),
        ] {
            run_successor_replay(selection, ExecShape::CrossCookie, deferred, quantum);
        }
    }
}
