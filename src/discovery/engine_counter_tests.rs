//! SPDX-License-Identifier: GPL-3.0-or-later
//! Engine wiring for counter captures: preflight, pool and growth staging.

use super::session_fixture::ScriptedSession;
use super::*;
use crate::attach::counter_banks::{
    BankExtent, BankPublication, BankRefusal,
};
use crate::attach::{BackendSelection, CapturePolicy};
use crate::discovery::identity::PinnedObjectId;
use p11scope_ebpf_common::CounterMode;

fn counter_slot(index: u32, object: PinnedObjectId) -> plan::Slot {
    plan::Slot {
        index,
        descriptor_index: 0,
        object,
        object_path: "/counter-provider.so".into(),
        file_offset: 0x1000 + u64::from(index),
        names: vec!["C_Sign".into()],
        aliased: false,
        semantics: crate::kinds::DESCRIPTORS[0],
        semantic_authorized: false,
        semantic_ambiguous: false,
        fork_safe: false,
        module_ids: vec![],
    }
}

/// One pinned object plus its assigned ID, so active slots keep exact
/// pinned identity through the candidate preflight.
fn counter_pins() -> (PinnedObjects, PinnedObjectId) {
    use crate::discovery::identity::test_fixture as fixture;
    let pins = fixture::pin_set(&[(fixture::overlay(102), fixture::SHA, 0)], false);
    let id = pins.pinned().next().expect("one pin").id;
    (pins, id)
}

fn detailed_plan(count: u32) -> plan::AttachPlan {
    detailed_plan_on(count, PinnedObjectId(7))
}

fn detailed_plan_on(count: u32, object: PinnedObjectId) -> plan::AttachPlan {
    plan::AttachPlan::from_slots_with_policy(
        (0..count).map(|index| counter_slot(index, object)).collect(),
        plan::AdmissionPolicy::Detailed,
    )
    .unwrap()
}

fn counters_plan(count: u32) -> plan::AttachPlan {
    counters_plan_on(count, PinnedObjectId(7))
}

fn counters_plan_on(count: u32, object: PinnedObjectId) -> plan::AttachPlan {
    plan::AttachPlan::from_slots_with_policy(
        (0..count).map(|index| counter_slot(index, object)).collect(),
        plan::AdmissionPolicy::Counters(
            crate::capacity::CounterBudget::new(8192).unwrap(),
        ),
    )
    .unwrap()
}

#[test]
fn counter_spec_for_startup_routes_policy() {
    let engine = Engine::empty_for_test();
    let baseline = engine.counter_pool.snapshot().charged_bytes;
    for policy in [
        CapturePolicy::AggregateOnly,
        CapturePolicy::Allowlisted,
        CapturePolicy::UnsafeUnvalidatedMetadata,
    ] {
        assert!(
            Engine::counter_spec_for_startup(policy, 8, engine.counter_reserver())
                .unwrap()
                .is_none(),
            "{policy:?} builds no counter spec"
        );
    }
    assert_eq!(
        engine.counter_pool.snapshot().charged_bytes,
        baseline,
        "routing charges nothing"
    );
    for mode in [
        CounterMode::Counts,
        CounterMode::Timestamps,
        CounterMode::Latency,
    ] {
        let spec =
            Engine::counter_spec_for_startup(CapturePolicy::Counter(mode), 8, engine.counter_reserver())
                .unwrap()
                .expect("counter policy builds a spec");
        assert_eq!(spec.mode(), mode);
    }
    assert_eq!(
        engine.counter_pool.snapshot().charged_bytes,
        baseline,
        "sizing charges nothing"
    );
}

#[test]
fn counter_preflight_refuses_before_session_start_with_zero_links() {
    let mut engine = Engine::empty_for_test();
    engine.plan = detailed_plan(1);
    engine.counter_cpus_override = Some(490);
    let baseline = engine.counter_pool.snapshot().charged_bytes;
    let error = match engine.start_session_with(
        CapturePolicy::Counter(CounterMode::Latency),
        None,
        None,
        None,
        BackendSelection::Auto,
    ) {
        Ok(_) => panic!("over-ceiling start must refuse"),
        Err(error) => error,
    };
    let text = format!("{error:#}");
    assert!(text.starts_with("counter-memory-limit:"), "{text}");
    let fixed =
        crate::attach::counter_banks::counter_fixed_map_bytes(490).unwrap();
    let per_bank =
        crate::attach::counter_banks::counter_bank_map_bytes(CounterMode::Latency, 490).unwrap();
    for word in [
        CounterMode::Latency.name(),
        "490",
        &fixed.to_string(),
        &per_bank.to_string(),
        "ceiling 0 endpoints",
        "(requested 1)",
    ] {
        assert!(text.contains(word), "refusal names {word}: {text}");
    }
    assert_eq!(
        engine.counter_pool.snapshot().charged_bytes,
        baseline,
        "preflight refusal charges nothing"
    );
    assert!(
        matches!(
            engine.plan.admission_policy(),
            plan::AdmissionPolicy::Detailed
        ),
        "refusal happens before plan conversion and session start (zero links)"
    );
}

#[test]
fn counter_preflight_passes_under_ceiling_into_session_start() {
    let mut engine = Engine::empty_for_test();
    engine.plan = detailed_plan(1);
    engine.counter_cpus_override = Some(12);
    // Fake pins fail the start later; the preflight itself must pass.
    let error = match engine.start_session_with(
        CapturePolicy::Counter(CounterMode::Counts),
        None,
        None,
        None,
        BackendSelection::Auto,
    ) {
        Ok(_) => panic!("fake pins fail start"),
        Err(error) => error,
    };
    let text = format!("{error:#}");
    assert!(
        !text.starts_with("counter-memory-limit:"),
        "preflight must pass under ceiling: {text}"
    );
}

#[test]
fn counter_pool_covers_terminal_keepalive_and_read() {
    use crate::attach::counter_banks::{
        counter_read_storage_bytes, counter_read_transient_bytes, counter_snapshot_bytes_for,
        counter_terminal_reserve_bytes,
    };
    let engine = Engine::empty_for_test();
    let limit = engine.counter_pool.snapshot().limit_bytes;
    assert_eq!(limit, super::COUNTER_POOL_BYTES);
    let cpus = aya::util::nr_cpus().expect("possible CPUs");
    let terminal = counter_terminal_reserve_bytes(CounterMode::Latency, cpus).unwrap();
    let envelope = 128 * 1024 * 1024 + 32 * 1024 * 1024 + 64 * 1024 * 1024;
    let read = counter_read_transient_bytes(CounterMode::Latency, cpus, 65536, 8192, 8192).unwrap()
        + counter_read_storage_bytes(8192, 65536).unwrap()
        + counter_snapshot_bytes_for(8192, 8192).unwrap();
    assert!(
        limit >= terminal + envelope + read,
        "pool covers worst-case capture needs at P={cpus}"
    );
    // The counter pool never shares the collected graph pool's budget.
    let graph_before = engine.collected_graph_pool.snapshot().charged_bytes;
    let _hold = engine.counter_reserver().reserve(1024 * 1024).unwrap();
    assert_eq!(
        engine.collected_graph_pool.snapshot().charged_bytes,
        graph_before
    );
    let counter_before = engine.counter_pool.snapshot().charged_bytes;
    let _hold = engine.collected_graph_reserver().reserve(1024 * 1024).unwrap();
    assert_eq!(
        engine.counter_pool.snapshot().charged_bytes,
        counter_before
    );
}

fn growth_candidate(
    plan: plan::AttachPlan,
    new: Vec<plan::Slot>,
    pinned: PinnedObjects,
) -> LiveCandidate {
    LiveCandidate {
        pinned,
        modules: Vec::new(),
        plan,
        delta: plan::AttachDelta {
            new,
            replace: Vec::new(),
            retire: Vec::new(),
        },
        views: std::collections::BTreeSet::new(),
        corroboration: Vec::new(),
        manifest_fallbacks: Vec::new(),
        selection_claims: BTreeMap::new(),
        selection_tables: BTreeMap::new(),
        selection_admission: None,
        manifest_selection_admissions: Vec::new(),
        manifest_inventory_slots: BTreeMap::new(),
        loader_plan_proof: None,
        exec_preservations: Vec::new(),
        exec_completions: Vec::new(),
    }
}

#[test]
fn counter_growth_stages_fresh_tail_through_apply() {
    let mut engine = Engine::empty_for_test();
    let (pins, object) = counter_pins();
    engine.plan = counters_plan_on(2, object);
    engine
        .plan
        .consume_counter_extent(0, 2)
        .expect("staged prefix");
    let mut session = ScriptedSession::default();
    session.capture_policy = Some(CapturePolicy::Counter(CounterMode::Counts));
    session.counter_stage_script.push_back(BankPublication::Published {
        transaction: 1,
        extent: BankExtent { first: 2, end: 3 },
    });
    let mut plan = counters_plan_on(3, object);
    plan.adopt_counter_consumed(2).expect("staged prefix");
    let new = vec![plan.slots[2].clone()];
    let candidate = growth_candidate(plan, new, pins);
    let mut additions_allowed = true;
    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions_allowed, false, &[])
        .expect("apply");
    assert_eq!(session.staged_counter_calls, vec![3]);
    assert!(
        session.attached_slots.is_empty(),
        "counter growth never calls slot attach"
    );
    assert_eq!(outcome.static_completions.len(), 1);
    assert!(outcome.static_failures.is_empty());
    assert!(additions_allowed);
    assert_eq!(engine.plan.counter_consumed_end(), 3);
    assert_eq!(engine.plan.slots.len(), 3);
}

#[test]
fn counter_growth_refusal_partials_with_plan_intact() {
    let mut engine = Engine::empty_for_test();
    let (pins, object) = counter_pins();
    engine.plan = counters_plan_on(2, object);
    engine
        .plan
        .consume_counter_extent(0, 2)
        .expect("staged prefix");
    let mut session = ScriptedSession::default();
    session.capture_policy = Some(CapturePolicy::Counter(CounterMode::Counts));
    session.counter_stage_script.push_back(BankPublication::Refused(
        BankRefusal::BudgetExhausted {
            resource: "counter-memory-limit",
            needed: 1,
            available: 0,
        },
    ));
    let mut plan = counters_plan_on(3, object);
    plan.adopt_counter_consumed(2).expect("staged prefix");
    let new = vec![plan.slots[2].clone()];
    let candidate = growth_candidate(plan, new, pins);
    let mut additions_allowed = true;
    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions_allowed, false, &[])
        .expect("apply");
    assert_eq!(session.staged_counter_calls, vec![3]);
    assert!(
        session.attached_slots.is_empty(),
        "refused growth never calls slot attach"
    );
    assert!(outcome.static_completions.is_empty());
    assert!(
        engine.counters.object_skips.iter().any(|skip| {
            skip.subject.contains("counter") && skip.reason.contains("counter-memory-limit")
        }),
        "refused growth reports PARTIAL honestly"
    );
    assert_eq!(engine.plan.counter_consumed_end(), 2);
    assert_eq!(
        engine.plan.slots.len(),
        2,
        "the refused tail withdraws, leaving the staged prefix"
    );
}

#[test]
fn detailed_candidates_skip_counter_staging() {
    let mut engine = Engine::empty_for_test();
    let (pins, object) = counter_pins();
    engine.plan = detailed_plan_on(2, object);
    let mut session = ScriptedSession::default();
    session.capture_policy = Some(CapturePolicy::Allowlisted);
    let plan = detailed_plan_on(3, object);
    let new = vec![plan.slots[2].clone()];
    let candidate = growth_candidate(plan, new, pins);
    let mut additions_allowed = true;
    engine
        .apply_candidate(&mut session, candidate, &mut additions_allowed, false, &[])
        .expect("apply");
    assert!(
        session.staged_counter_calls.is_empty(),
        "detailed growth never stages banks"
    );
    assert_eq!(session.attached_slots, vec![1]);
}

#[test]
fn counter_growth_without_fresh_tail_stages_nothing() {
    let mut engine = Engine::empty_for_test();
    let (pins, object) = counter_pins();
    engine.plan = counters_plan_on(2, object);
    engine
        .plan
        .consume_counter_extent(0, 2)
        .expect("staged prefix");
    let mut session = ScriptedSession::default();
    session.capture_policy = Some(CapturePolicy::Counter(CounterMode::Counts));
    let mut plan = counters_plan_on(2, object);
    plan.consume_counter_extent(0, 2).expect("consumed");
    let candidate = growth_candidate(plan, Vec::new(), pins);
    let mut additions_allowed = true;
    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions_allowed, false, &[])
        .expect("apply");
    assert!(
        session.staged_counter_calls.is_empty(),
        "no fresh tail stages nothing"
    );
    assert!(outcome.static_completions.is_empty());
    assert!(
        !engine.counters.object_skips.iter().any(|skip| {
            skip.subject.contains("counter") || skip.reason.contains("counter")
        }),
        "a no-op stages no PARTIAL"
    );
}
