//! SPDX-License-Identifier: GPL-3.0-or-later
//! Engine wiring for counter captures: preflight, pool and growth staging.

use super::session_fixture::ScriptedSession;
use super::*;
use crate::attach::counter_banks::{BankExtent, BankPublication, BankRefusal};
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
        (0..count)
            .map(|index| counter_slot(index, object))
            .collect(),
        plan::AdmissionPolicy::Detailed,
    )
    .unwrap()
}

fn counters_plan_on(count: u32, object: PinnedObjectId) -> plan::AttachPlan {
    plan::AttachPlan::from_slots_with_policy(
        (0..count)
            .map(|index| counter_slot(index, object))
            .collect(),
        plan::AdmissionPolicy::Counters(crate::capacity::CounterBudget::new(8192).unwrap()),
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
        let spec = Engine::counter_spec_for_startup(
            CapturePolicy::Counter(mode),
            8,
            engine.counter_reserver(),
        )
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
fn counter_start_budget_follows_the_affordable_ceiling_per_mode() {
    // The start budget is the preparation's affordable ceiling, never a
    // hand-written constant: latency drops below 8192 past 88 CPUs while
    // counts holds the full ceiling, and an unaffordable geometry refuses.
    for (mode, cpus, ceiling) in [
        (CounterMode::Counts, 12, 8192u64),
        (CounterMode::Timestamps, 12, 8192),
        (CounterMode::Latency, 12, 8192),
        (CounterMode::Latency, 88, 8192),
        (CounterMode::Latency, 89, 7680),
    ] {
        let budget = Engine::counter_start_budget(mode, cpus).unwrap();
        assert_eq!(budget.endpoint_limit(), ceiling, "{mode:?} at P={cpus}");
    }
    assert!(
        Engine::counter_start_budget(CounterMode::Latency, 490).is_err(),
        "an unaffordable geometry refuses its budget"
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
    let fixed = crate::attach::counter_banks::counter_fixed_map_bytes(490).unwrap();
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
    let _hold = engine
        .collected_graph_reserver()
        .reserve(1024 * 1024)
        .unwrap();
    assert_eq!(engine.counter_pool.snapshot().charged_bytes, counter_before);
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
    session
        .counter_stage_script
        .push_back(BankPublication::Published {
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
    assert!(
        session.replaced_slot_indices.is_empty(),
        "append-only growth never replaces"
    );
}

/// Committed pins with a provider plus a loader, and a loader context
/// registered against the loader: the post-arming shape a growth
/// candidate must resolve.
fn committed_pins_with_loader_context(
    engine: &mut Engine,
) -> (PinnedObjects, PinnedObjectId, PinnedObjectId) {
    use crate::discovery::identity::test_fixture as fixture;
    let committed = fixture::pin_set(
        &[
            (fixture::overlay(102), fixture::SHA, 0),
            (fixture::overlay(103), fixture::SHA, 0),
        ],
        false,
    );
    let ids: Vec<_> = committed.pinned().map(|entry| entry.id).collect();
    let provider = ids.first().copied().expect("provider pin");
    let loader = ids.get(1).copied().expect("loader pin");
    engine.pinned = committed.clone();
    let spec = crate::discovery::loader::LoaderContextSpec {
        view: crate::process::ProcessViewId(7),
        loader,
        mapping: None,
        hook: p11scope_manifest::elf::SymbolFact {
            virtual_address: 0x2100,
            file_offset: 0x2100,
        },
        state_address: None,
    };
    let prepared = engine.loader_registry.preflight(spec).unwrap();
    engine.loader_registry.prepare(prepared).unwrap();
    (committed, provider, loader)
}

#[test]
fn counter_growth_bare_pins_hit_missing_loader_context_identity() {
    // The (0, 0) mechanism: a growth candidate whose pins drop the
    // committed loader context is refused before staging with the
    // identity PARTIAL (not a counter PARTIAL), so completions and static
    // failures both stay empty. Production candidates never do this —
    // they evolve from committed pins — so the early return is correct
    // and the growth seam must build faithful candidates.
    use crate::discovery::identity::test_fixture as fixture;
    let mut engine = Engine::empty_for_test();
    let (_committed, provider, _loader) = committed_pins_with_loader_context(&mut engine);
    engine.plan = counters_plan_on(2, provider);
    engine
        .plan
        .consume_counter_extent(0, 2)
        .expect("staged prefix");
    let mut session = ScriptedSession::default();
    session.capture_policy = Some(CapturePolicy::Counter(CounterMode::Counts));
    session
        .counter_stage_script
        .push_back(BankPublication::Published {
            transaction: 1,
            extent: BankExtent { first: 2, end: 3 },
        });
    let mut plan = counters_plan_on(3, provider);
    plan.adopt_counter_consumed(2).expect("staged prefix");
    let new = vec![plan.slots[2].clone()];
    let bare = fixture::pin_set(&[(fixture::overlay(102), fixture::SHA, 0)], false);
    assert_eq!(
        bare.pinned().next().expect("provider pin").id,
        provider,
        "the bare candidate carries the same provider ID without the loader"
    );
    let candidate = growth_candidate(plan, new, bare);
    let mut additions_allowed = true;
    let outcome = engine
        .apply_candidate(&mut session, candidate, &mut additions_allowed, false, &[])
        .expect("apply");
    assert_eq!(
        (
            outcome.static_completions.len(),
            outcome.static_failures.len()
        ),
        (0, 0)
    );
    assert!(!additions_allowed);
    assert!(
        session.staged_counter_calls.is_empty(),
        "staging is never attempted"
    );
    let identity = engine
        .counters
        .object_skips
        .iter()
        .find(|skip| skip.subject == "live discovery identity")
        .expect("identity PARTIAL");
    assert!(
        identity.reason.contains("loader context"),
        "refusal names the loader context: {}",
        identity.reason
    );
}

#[test]
fn counter_growth_seam_absorbs_committed_loader_identity() {
    // The growth seam must build production-faithful candidates: fresh
    // pins absorbed into committed pins, so registered loader contexts
    // resolve and the fresh tail stages.
    use crate::discovery::identity::test_fixture as fixture;
    let mut engine = Engine::empty_for_test();
    let (_committed, provider, _loader) = committed_pins_with_loader_context(&mut engine);
    engine.plan = counters_plan_on(2, provider);
    engine
        .plan
        .consume_counter_extent(0, 2)
        .expect("staged prefix");
    let mut session = ScriptedSession::default();
    session.capture_policy = Some(CapturePolicy::Counter(CounterMode::Counts));
    session
        .counter_stage_script
        .push_back(BankPublication::Published {
            transaction: 1,
            extent: BankExtent { first: 2, end: 3 },
        });
    let mut plan = counters_plan_on(3, provider);
    plan.adopt_counter_consumed(2).expect("staged prefix");
    let new = vec![plan.slots[2].clone()];
    let fresh = fixture::pin_set(&[(fixture::overlay(102), fixture::SHA, 0)], false);
    let (completed, failed, partials) = engine
        .apply_counter_growth_for_test(&mut session, plan, new, fresh)
        .expect("apply");
    assert_eq!((completed, failed), (1, 0));
    assert!(
        partials.is_empty(),
        "clean growth marks no PARTIAL: {partials:?}"
    );
    assert_eq!(session.staged_counter_calls, vec![3]);
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
    session
        .counter_stage_script
        .push_back(BankPublication::Refused(BankRefusal::BudgetExhausted {
            resource: "counter-memory-limit",
            needed: 1,
            available: 0,
        }));
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
fn counter_staging_refusal_text_names_check() {
    let publication = BankPublication::Refused(BankRefusal::Topology);
    assert_eq!(
        counter_staging_refusal_text(&publication, Some("counter plan has inactive fresh slots")),
        "counter bank staging refused: Refused(Topology) (counter plan has inactive fresh slots)"
    );
    assert_eq!(
        counter_staging_refusal_text(&publication, None),
        "counter bank staging refused: Refused(Topology)"
    );
    let shaped = BankPublication::Refused(BankRefusal::Shape(BankShapeCause::PlanNotCounters));
    assert_eq!(
        counter_staging_refusal_text(&shaped, None),
        "counter bank staging refused: Refused(Shape(PlanNotCounters))"
    );
}

#[test]
fn counter_growth_refusal_text_names_check() {
    let publication = BankPublication::Refused(BankRefusal::Topology);
    assert_eq!(
        counter_growth_refusal_text(&publication, Some("counter pinned provider changed")),
        "Refused(Topology) (counter pinned provider changed)"
    );
    assert_eq!(
        counter_growth_refusal_text(&publication, None),
        "Refused(Topology)"
    );
}

#[test]
fn counter_growth_attach_outcome_reports_scripted_check() {
    let (pins, object) = counter_pins();
    let mut plan = counters_plan_on(2, object);
    let pool = crate::semantics_edge::resources::SemanticResourcePool::reference_limit(1024 * 1024);
    let mut session = ScriptedSession::default();
    session.capture_policy = Some(CapturePolicy::Counter(CounterMode::Counts));
    session
        .counter_stage_script
        .push_back(BankPublication::Refused(BankRefusal::Topology));
    session.scripted_last_check = Some("counter plan has inactive fresh slots");
    let error = counter_growth_attach_outcome(&mut session, &mut plan, &pins, &pool.reserver())
        .expect_err("a scripted Topology refusal must fail the attach");
    let text = format!("{error:#}");
    assert!(
        text.contains("Refused(Topology)")
            && text.contains("counter plan has inactive fresh slots"),
        "growth refusal must carry token and check: {text}"
    );
}

/// Owning module for injected counter slots: one heuristic table over the
/// given slots, bound to the given pins. Mirrors the counter-reader
/// fixture's module; both pin the production invariant (the plan's keys
/// are re-observable from owning modules) without running discovery.
fn owning_module_for_test(
    provider: &std::path::Path,
    pins: &crate::discovery::identity::PinnedObjects,
    object: crate::discovery::identity::PinnedObjectId,
    slots: &[crate::plan::Slot],
) -> crate::discovery::identity::ReconciledModule {
    use crate::discovery::scan::{ScannedEntry, ScannedModule, ScannedTable};
    let key = pins.summary(object).unwrap().key;
    // The loader-arming rebuild re-binds this module against the pins, and
    // the bind key includes the mount namespace. `real_scan_pin` records a
    // synthetic `{device: 1, inode: minor}` namespace, so the module must
    // reproduce it exactly or the bind drops the module.
    let mount_namespace = crate::process::MountNamespaceId {
        device: 1,
        inode: key.device.minor,
    };
    let path = provider.display().to_string();
    let entries = slots
        .iter()
        .map(|slot| ScannedEntry {
            name: "C_Sign",
            object: key,
            object_path: path.clone(),
            file_offset: slot.file_offset,
        })
        .collect::<Vec<_>>();
    crate::discovery::identity::ReconciledModule {
        scanned: ScannedModule {
            mapped_identity: None,
            view: crate::process::ProcessViewId(0),
            mount_namespace,
            key,
            double_loaded: false,
            path,
            decoder_abi: Some(p11scope_manifest::elf::ElfAbi::Lp64),
            exports: vec!["C_GetFunctionList".to_string()],
            tables: vec![ScannedTable {
                version: (2, 40),
                walk: "full",
                entries,
                null_entries: vec![],
                unpinned: vec![],
                address: 0x7000,
                file_offset: Some(0),
                live_return: false,
                manifest_supported: false,
            }],
            interfaces: vec![],
        },
        object,
        entry_objects: vec![vec![object; slots.len()]],
        exports: Default::default(),
    }
}

#[test]
fn counter_start_state_with_owning_modules_survives_loader_arming() {
    // The a2-7a root shape, pinned: an injected counter plan whose slots no
    // module owns is retired wholesale by the first loader-arming rebuild,
    // and staging the all-inactive plan refuses Topology. With owning
    // modules, arming stages the full retained plan and adopts it
    // active, consumed, and in order (growth staging matches keys by index).
    use crate::discovery::identity::test_fixture as fixture;
    let mut engine = Engine::empty_for_test();
    let pid = std::process::id();
    let view = crate::process::ProcessView::open(crate::process::ProcessViewId(0), pid).unwrap();
    let exe = std::env::current_exe().unwrap();
    let pins = fixture::real_scan_pin(&exe, None, 1, &"ab".repeat(32));
    let object = pins.pinned().next().expect("one pin").id;
    let plan = counters_plan_on(8, object);
    let modules = vec![owning_module_for_test(&exe, &pins, object, &plan.slots)];
    engine.inject_counter_start_state_for_test(
        crate::attach::Scope::Pid(pid),
        vec![view],
        plan,
        pins,
        modules,
    );
    engine.begin_start_capture_attempt().unwrap();
    let mut session = ScriptedSession::default();
    session.capture_policy = Some(CapturePolicy::Counter(CounterMode::Counts));
    session
        .counter_stage_script
        .push_back(BankPublication::Published {
            transaction: 1,
            extent: BankExtent { first: 0, end: 8 },
        });
    let mut additions_allowed = true;
    let mut pending_views = PendingViewRetirements::new();
    let fatal = engine.arm_initial_views(&mut session, &mut additions_allowed, &mut pending_views);
    assert!(fatal.is_none(), "loader arming must not fail: {fatal:?}");
    assert_eq!(
        session.staged_counter_calls,
        vec![8],
        "arming must stage the full retained plan"
    );
    assert_eq!(engine.plan.slots.len(), 8);
    assert_eq!(
        engine.plan.counter_consumed_end(),
        8,
        "the staged plan must be adopted consumed"
    );
    assert_eq!(
        engine.plan.active_slot_count(),
        8,
        "owned endpoints must survive the arming rebuild"
    );
    for (index, slot) in engine.plan.slots.iter().enumerate() {
        assert_eq!(slot.index as usize, index);
        assert_eq!(slot.file_offset, 4096 + index as u64);
    }
}

#[test]
#[should_panic(expected = "has no owning module entry")]
fn counter_start_state_rejects_plan_without_owning_modules() {
    let mut engine = Engine::empty_for_test();
    let (pins, object) = counter_pins();
    let plan = counters_plan_on(2, object);
    engine.inject_counter_start_state_for_test(
        crate::attach::Scope::Pid(std::process::id()),
        Vec::new(),
        plan,
        pins,
        Vec::new(),
    );
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
        !engine
            .counters
            .object_skips
            .iter()
            .any(|skip| { skip.subject.contains("counter") || skip.reason.contains("counter") }),
        "a no-op stages no PARTIAL"
    );
}

/// The counter re-admission wiring in the real start path.
/// `start_session_with` captures the counter start budget before the
/// attach-preparation retain loop and re-admits the retained plan under
/// that unchanged budget afterwards; deleting the restore call reintroduces
/// the stale-view policy loss (the first collection read bails) with no
/// other test failing. A runtime test through `start_session_with` cannot
/// observe this without a successful session start — fake pins fail first
/// and the failure path restores the pre-conversion snapshot plan — so this
/// pins the wiring itself: removing the restore call fails this test.
#[test]
fn counter_start_wiring_readmits_the_retained_plan_after_the_retain_loop() {
    let source = include_str!("engine.rs");
    let route = source
        .split_once("    fn start_session_with(")
        .expect("start_session_with exists")
        .1
        .split_once("\n    }\n}")
        .expect("start_session_with body ends")
        .0;
    let capture = route
        .find("let counter_budget = if counter.is_some()")
        .expect("start budget captured before the retain loop");
    let retain = route
        .find("start_retained_with(self,")
        .expect("attach-preparation retain loop runs the start");
    let restore = route
        .find("self.restore_counters_policy_after_retain(budget)")
        .expect("retained plan re-admitted after the retain loop");
    assert!(
        capture < retain && retain < restore,
        "budget capture, retain loop, and re-admission stay in order"
    );
    assert!(
        route[retain..restore].contains("if let Some(budget) = counter_budget"),
        "re-admission runs only for counter starts"
    );
    assert!(
        route[restore..].contains("finish_start_capture_attempt(snapshot, Err(error))"),
        "a re-admission refusal restores the pre-attempt plan"
    );
}

/// Failure twin of the healthy re-admission path: restoring the Counters
/// policy under a budget smaller than the retained plan refuses with the
/// named capacity reason and leaves the Detailed plan untouched
/// (`with_counters_policy` validates before cloning). Three slots, budget
/// for two.
#[test]
fn counter_retain_restore_refuses_an_over_budget_plan_with_its_named_reason() {
    let mut engine = Engine::empty_for_test();
    engine.plan = detailed_plan(3);
    let before = engine.plan.clone();
    let budget = crate::capacity::CounterBudget::new(2).unwrap();
    let error = engine
        .restore_counters_policy_after_retain(budget)
        .expect_err("over-budget re-admission refuses");
    let text = format!("{error:#}");
    assert!(
        text.contains("counter plan requires 3 counter endpoints but only 2 are available"),
        "refusal names the budget: {text}"
    );
    assert!(
        matches!(
            engine.plan.admission_policy(),
            plan::AdmissionPolicy::Detailed
        ),
        "refusal leaves the Detailed plan untouched"
    );
    assert_eq!(
        engine.plan.slots, before.slots,
        "slots untouched on refusal"
    );
}
