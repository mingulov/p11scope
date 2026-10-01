//! SPDX-License-Identifier: GPL-3.0-or-later
//! Phase 4 breadth tests: scale, budgets, failure injection, churn,
//! shutdown, and honest history — every workload through the ONE harness
//! (`super`), every expectation an exact ledger over the real JSON path.

use super::*;
use crate::attach::Scope;
use crate::capacity::{AttachCost, InventoryBudget};
use crate::discovery::caller_registry::{
    AdmissionState, CallerEvent, CallerId, DEFAULT_MAX_CALLERS, DEFAULT_MAX_EDGES,
    DEFAULT_MAX_MODULES, ImageAuthority, ModuleInfo, ModuleKey, OsProcessSource, RegistryLimits,
};
use crate::discovery::engine::inventory::{ImageCheck, ImageGuard, UnavailableImageGuard};
use crate::discovery::engine::inventory_coordinator::{InventoryCoordinator, InventoryScope};
use crate::discovery::hooks::HookRegistry;
use p11scope_ebpf_common::ImageIdentity;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

/// FD and RSS measurements are process-global: tests that assert them
/// hold this guard so a parallel test's transient FDs or allocations
/// cannot perturb the census.
fn serial_guard() -> MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

fn harness() -> Harness {
    Harness::new(RegistryLimits::default_limits()).unwrap()
}

fn limited(
    callers: usize,
    modules: usize,
    edges: usize,
    gaps: usize,
    endpoints: usize,
    semantic: usize,
) -> Harness {
    Harness::new(RegistryLimits::new(callers, modules, edges, gaps, endpoints, semantic).unwrap())
        .unwrap()
}

/// E-test-style fixture build: compile one C source with gcc into the
/// test tmp dir.
fn gcc(dir: &Path, out: &str, source: &Path, args: &[&str], libs: &[&str]) -> PathBuf {
    let bin = dir.join(out);
    let mut cmd = std::process::Command::new("gcc");
    cmd.args(args).arg("-o").arg(&bin).arg(source).args(libs);
    assert!(
        cmd.status().unwrap().success(),
        "gcc failed for {out}: {cmd:?}"
    );
    bin
}

fn wait_for(path: &Path, what: &str) {
    for _ in 0..300 {
        if std::fs::metadata(path).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("fixture {what} never arrived: {}", path.display());
}

/// Kills the owned fixture child on drop, so a failed assert cannot
/// leak a sleeper.
struct ChildReaper(std::process::Child);

impl Drop for ChildReaper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Scripted guard over owned fixtures: every presented identity checks
/// exact (the pids are owned sleepers, never the host's tasks).
struct AcceptAllImages;

impl ImageGuard for AcceptAllImages {
    fn check(&mut self, _: &crate::process::ProcessView, _: ImageIdentity) -> ImageCheck {
        ImageCheck::Exact
    }
}

fn owner_image(pid: u32) -> ImageIdentity {
    ImageIdentity {
        task_cookie: u64::from(pid) + 1,
        exec_id: 7,
    }
}

// ---------------------------------------------------------------------------
// A1: fill to capacity per resource, plus one combined workload.
// ---------------------------------------------------------------------------

#[test]
fn scale_fill_callers_to_capacity_with_exact_ledger() {
    let spec = ScaleSpec {
        name: "fill-callers",
        callers: DEFAULT_MAX_CALLERS,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 1000,
    };
    let mut harness = harness();
    let events = harness.stage_scale(&spec);
    assert_eq!(events.len(), DEFAULT_MAX_CALLERS);
    assert!(
        events
            .iter()
            .all(|event| matches!(event, CallerEvent::Admitted { .. })),
        "every scripted pid admits below the cap"
    );
    let receipt = harness.commit();
    assert_eq!(receipt.registry_facts, receipt.registry_published);
    // One past the cap: the adapter refuses with a named gap while the
    // 4096 retained incarnations stay intact.
    let now = harness.now_ns();
    harness
        .source()
        .spawn(1000 + DEFAULT_MAX_CALLERS as u32, 9999);
    let observed: BTreeSet<u32> = (0..=DEFAULT_MAX_CALLERS)
        .map(|index| 1000 + index as u32)
        .collect();
    let overflow = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    assert_eq!(overflow.len(), 1);
    match &overflow[0] {
        CallerEvent::AdmitFailed { pid, budget, .. } => {
            assert_eq!(*pid, 1000 + DEFAULT_MAX_CALLERS as u32);
            let refusal = budget.expect("caller overflow names its budget");
            assert_eq!(
                (refusal.resource, refusal.limit, refusal.requested),
                ("callers", DEFAULT_MAX_CALLERS, DEFAULT_MAX_CALLERS + 1)
            );
        }
        other => panic!("expected a budget refusal, got {other:?}"),
    }
    harness
        .coordinator_mut()
        .apply_reconcile_events(&overflow, now);
    harness.commit();
    let document = harness.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: DEFAULT_MAX_CALLERS as u64,
            modules: 1,
            edges: DEFAULT_MAX_CALLERS as u64,
            endpoints: 4,
            callers_refused: 1,
            modules_refused: 0,
            edges_refused: 0,
            endpoints_refused: 0,
            gaps: Some(1),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    // Adapter and registry agree on the caller census.
    assert_eq!(
        harness.coordinator().registry().caller_count(),
        DEFAULT_MAX_CALLERS
    );
    // The refusal gap names resource, limit, and requested.
    let gap = &document["gaps"][0];
    assert_eq!(gap["subject"], "caller admission failed");
    assert_eq!(gap["budget"]["resource"], "callers");
    assert_eq!(gap["budget"]["limit"], DEFAULT_MAX_CALLERS);
    assert_eq!(gap["budget"]["requested"], DEFAULT_MAX_CALLERS + 1);
    // Old evidence intact: the first incarnation still maps its module.
    assert_eq!(document["callers"][0]["id"], "c0");
    assert_eq!(document["callers"][0]["lifecycle"], "mapped");
    assert_eq!(document["edges"][0]["mapping"]["state"], "mapped");
}

#[test]
fn scale_fill_modules_to_capacity_with_exact_ledger() {
    let spec = ScaleSpec {
        name: "fill-modules",
        callers: 1,
        modules: DEFAULT_MAX_MODULES,
        edges_per_caller: DEFAULT_MAX_MODULES,
        endpoints_per_module: 4,
        first_pid: 2000,
    };
    let mut harness = harness();
    harness.stage_scale(&spec);
    harness.commit();
    // One module past the cap: the mapping drops with a named gap while
    // the retained catalog stays intact.
    let now = harness.now_ns();
    let caller = harness.coordinator().adapter().live_id(2000).unwrap();
    harness.coordinator_mut().registry_mut().note_mapping(
        caller,
        2000,
        scale_module_info(DEFAULT_MAX_MODULES, 4),
        now,
    );
    harness.commit();
    let document = harness.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 1,
            modules: DEFAULT_MAX_MODULES as u64,
            edges: DEFAULT_MAX_MODULES as u64,
            endpoints: (DEFAULT_MAX_MODULES * 4) as u64,
            callers_refused: 0,
            modules_refused: 1,
            edges_refused: 0,
            endpoints_refused: 0,
            gaps: Some(1),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    let gap = &document["gaps"][0];
    assert_eq!(gap["subject"], "module capacity exhausted");
    assert_eq!(gap["budget"]["resource"], "modules");
    assert_eq!(gap["budget"]["limit"], DEFAULT_MAX_MODULES);
    assert_eq!(gap["budget"]["requested"], DEFAULT_MAX_MODULES + 1);
    assert_eq!(document["modules"].as_array().unwrap().len(), 4096);
    assert_eq!(document["modules"][0]["id"], "m0");
}

#[test]
fn scale_fill_edges_to_capacity_with_exact_ledger() {
    let spec = ScaleSpec {
        name: "fill-edges",
        callers: 128,
        modules: 256,
        edges_per_caller: 256,
        endpoints_per_module: 4,
        first_pid: 3000,
    };
    assert_eq!(spec.layout().len(), DEFAULT_MAX_EDGES);
    let mut harness = harness();
    harness.stage_scale(&spec);
    let receipt = harness.commit();
    assert_eq!(receipt.registry_facts, receipt.registry_published);
    // One edge past the cap: a new caller mapping a new module is
    // refused on edges (both other budgets have headroom) with the old
    // 32768 intact.
    let now = harness.now_ns();
    harness.source().spawn(4000, 4242);
    let observed: BTreeSet<u32> = [4000].into_iter().collect();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    assert_eq!(events.len(), 1);
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    let caller = harness.coordinator().adapter().live_id(4000).unwrap();
    harness.coordinator_mut().registry_mut().note_mapping(
        caller,
        4000,
        scale_module_info(256, 4),
        now,
    );
    harness.commit();
    let document = harness.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 129,
            modules: 257,
            edges: DEFAULT_MAX_EDGES as u64,
            endpoints: (257 * 4) as u64,
            callers_refused: 0,
            modules_refused: 0,
            edges_refused: 1,
            endpoints_refused: 0,
            gaps: Some(1),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    let gap = &document["gaps"][0];
    assert_eq!(gap["subject"], "edge capacity exhausted");
    assert_eq!(gap["budget"]["resource"], "edges");
    assert_eq!(gap["budget"]["limit"], DEFAULT_MAX_EDGES);
    assert_eq!(gap["budget"]["requested"], DEFAULT_MAX_EDGES + 1);
}

#[test]
fn scale_combined_caps_all_resources_with_exact_ledger() {
    // 4096 callers × 8 striped modules: every resource at its cap in one
    // workload (32768 edges, 4096 distinct modules, 16384 endpoints).
    let spec = ScaleSpec {
        name: "combined-caps",
        callers: DEFAULT_MAX_CALLERS,
        modules: DEFAULT_MAX_MODULES,
        edges_per_caller: 8,
        endpoints_per_module: 4,
        first_pid: 5000,
    };
    let layout = spec.layout();
    assert_eq!(layout.len(), DEFAULT_MAX_EDGES);
    let touched: BTreeSet<usize> = layout.iter().map(|(_, module)| *module).collect();
    assert_eq!(touched.len(), DEFAULT_MAX_MODULES);
    let mut harness = harness();
    harness.stage_scale(&spec);
    harness.commit();
    // One past every cap: caller, module, and edge refusals each name
    // their resource while the retained snapshot stays whole.
    let now = harness.now_ns();
    harness
        .source()
        .spawn(5000 + DEFAULT_MAX_CALLERS as u32, 7777);
    let observed: BTreeSet<u32> = [5000 + DEFAULT_MAX_CALLERS as u32].into_iter().collect();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    assert_eq!(events.len(), 1);
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    let caller = harness.coordinator().adapter().live_id(5000).unwrap();
    harness.coordinator_mut().registry_mut().note_mapping(
        caller,
        5000,
        scale_module_info(DEFAULT_MAX_MODULES, 4),
        now,
    );
    // Caller c0 maps modules m0..m7; m8 is retained but unmapped by c0,
    // so this mapping refuses on edges, not modules.
    harness.coordinator_mut().registry_mut().note_mapping(
        caller,
        5000,
        scale_module_info(8, 4),
        now,
    );
    harness.commit();
    let document = harness.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: DEFAULT_MAX_CALLERS as u64,
            modules: DEFAULT_MAX_MODULES as u64,
            edges: DEFAULT_MAX_EDGES as u64,
            endpoints: (DEFAULT_MAX_MODULES * 4) as u64,
            callers_refused: 1,
            modules_refused: 1,
            edges_refused: 1,
            endpoints_refused: 0,
            gaps: Some(3),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    let subjects: Vec<&str> = document["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|gap| gap["subject"].as_str().unwrap())
        .collect();
    assert_eq!(
        subjects,
        [
            "caller admission failed",
            "module capacity exhausted",
            "edge capacity exhausted"
        ]
    );
}

// ---------------------------------------------------------------------------
// A2: the t7 cardinalities as inventory projections, plus 257 native owners.
// ---------------------------------------------------------------------------

/// One t7-cardinality projection: the attach-level family covers these
/// endpoint counts; the inventory side renders the exact caller, module,
/// and edge counts from scripted staging at the same cardinalities.
fn t7_projection(name: &'static str, callers: usize, modules: usize, first_pid: u32) {
    let spec = ScaleSpec {
        name,
        callers,
        modules,
        edges_per_caller: modules,
        endpoints_per_module: 4,
        first_pid,
    };
    let mut harness = harness();
    harness.stage_scale(&spec);
    let receipt = harness.commit();
    assert_eq!(receipt.registry_facts, receipt.registry_published);
    let document = harness.render();
    let ledger = spec.expected_ledger();
    assert!(
        ledger.endpoints > 512,
        "the projection carries >512 endpoints"
    );
    assert_ledger(&document, &ledger);
    assert_settled(&document, 0);
}

#[test]
fn inventory_projection_at_t7_cardinality_4097() {
    // 17 × 241: the attach-level n4097 as 4097 inventory edges.
    t7_projection("t7-4097", 17, 241, 20_000);
}

#[test]
fn inventory_projection_at_t7_cardinality_6530() {
    // 10 × 653: the attach-level 6530 union as 6530 inventory edges.
    t7_projection("t7-6530", 10, 653, 21_000);
}

#[test]
fn inventory_projection_at_t7_cardinality_8192() {
    // 32 × 256: the attach-level n8192 as 8192 inventory edges.
    t7_projection("t7-8192", 32, 256, 22_000);
}

#[test]
fn native_owner_growth_to_257_over_owned_sleepers() {
    let _serial = serial_guard();
    // 257 owned sleepers: the pids behind 257 native owners through the
    // real `open_inventory_owner` growth path.
    let mut children = Vec::new();
    for _ in 0..257 {
        children.push(
            std::process::Command::new("sleep")
                .arg("120")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
    }
    struct Reaper(Vec<std::process::Child>);
    impl Drop for Reaper {
        fn drop(&mut self) {
            for child in &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    let _reaper = Reaper(children);
    let pids: Vec<u32> = _reaper.0.iter().map(|child| child.id()).collect();
    let mut harness = harness();
    let mut guard = AcceptAllImages;
    // FD accounting, measured never assumed: the first owner establishes
    // the unit cost (one pin fd where the kernel offers pidfds, zero
    // where it falls back), and the remaining 256 must cost exactly
    // 256× that unit — retained by design, never leaked beyond it.
    let now = harness.now_ns();
    let before = count_fds();
    harness.source().spawn(pids[0], 5000);
    let first = harness
        .coordinator_mut()
        .test_open_native_owner(pids[0], owner_image(pids[0]), &mut guard, now)
        .unwrap();
    let unit = count_fds().saturating_sub(before);
    assert!(unit <= 1, "one owner retains at most one fd, got {unit}");
    for (index, pid) in pids.iter().enumerate().skip(1) {
        harness.source().spawn(*pid, 5000 + index as u64);
        harness
            .coordinator_mut()
            .test_open_native_owner(*pid, owner_image(*pid), &mut guard, now)
            .unwrap();
    }
    assert_eq!(
        count_fds(),
        before + 257 * unit,
        "257 owners retain exactly the accounted pins"
    );
    assert!(harness.coordinator().owner_of(first).is_some());
    harness.advance(10);
    // One shared module for all 257 callers: 257 native edges.
    let now = harness.now_ns();
    for pid in &pids {
        let caller = harness.coordinator().adapter().live_id(*pid).unwrap();
        harness.coordinator_mut().registry_mut().note_mapping(
            caller,
            *pid,
            scale_module_info(0, 4),
            now,
        );
    }
    harness.commit();
    let document = harness.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 257,
            modules: 1,
            edges: 257,
            endpoints: 4,
            callers_refused: 0,
            modules_refused: 0,
            edges_refused: 0,
            endpoints_refused: 0,
            gaps: Some(0),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    for caller in document["callers"].as_array().unwrap() {
        assert_eq!(
            caller["image"]["authority"], "native_exact",
            "every grown caller carries native authority",
        );
    }
}

/// The attach path at t7 scale is privileged-only: these cells run the
/// real attach preparation at N endpoints (the BPF load fails loudly
/// with EPERM outside the privileged lane) and then prove the inventory
/// projection renders the exact caller/module/edge counts at the same
/// cardinality. Controller lanes run them; implementer lanes record
/// them unrun.
fn attach_projection(n: u64, callers: usize, modules: usize, first_pid: u32) {
    let cost = AttachCost::for_endpoints(n);
    assert_eq!(cost.links, n);
    assert_eq!(cost.program_loads, 2);
    let budget = InventoryBudget::new(n, 8 * n).expect("8N inventory payload");
    assert_eq!(budget.payload_bytes(), 8 * n);
    let prepared = crate::attach::PreparedInventory::prepare(
        Scope::System,
        budget,
        crate::attach::AttachBackend::Multi,
    )
    .expect("the privileged lane prepares inventory attach at scale");
    assert_eq!(
        prepared.endpoint_capacity().get(),
        n as u32,
        "attach prepared exactly N endpoints"
    );
    drop(prepared);
    let spec = ScaleSpec {
        name: "attach-projection",
        callers,
        modules,
        edges_per_caller: modules,
        endpoints_per_module: 4,
        first_pid,
    };
    assert_eq!(spec.layout().len() as u64, n);
    let mut harness = harness();
    harness.stage_scale(&spec);
    harness.commit();
    let document = harness.render();
    assert_ledger(&document, &spec.expected_ledger());
    assert_settled(&document, 0);
}

#[test]
#[ignore = "controller lane: privileged BPF load plus attach-scale projection at 4097 endpoints"]
fn privileged_inventory_attach_projection_n4097() {
    attach_projection(4097, 17, 241, 30_000);
}

#[test]
#[ignore = "controller lane: privileged BPF load plus attach-scale projection at 6530 endpoints"]
fn privileged_inventory_attach_projection_n6530() {
    attach_projection(6530, 10, 653, 31_000);
}

#[test]
#[ignore = "controller lane: privileged BPF load plus attach-scale projection at 8192 endpoints"]
fn privileged_inventory_attach_projection_n8192() {
    attach_projection(8192, 32, 256, 32_000);
}

// ---------------------------------------------------------------------------
// A3: one combined workload beyond 6530 edges.
// ---------------------------------------------------------------------------

#[test]
fn combined_workload_beyond_6530_edges_with_exact_ledger() {
    // 200 × 40 = 8000 (caller, module) edges: the inventory-level
    // counterpart of the attach-level 6530 union — same number family,
    // both sides proven, no unit conflation.
    let spec = ScaleSpec {
        name: "beyond-6530",
        callers: 200,
        modules: 40,
        edges_per_caller: 40,
        endpoints_per_module: 16,
        first_pid: 40_000,
    };
    assert_eq!(spec.layout().len(), 8000);
    let mut harness = harness();
    harness.stage_scale(&spec);
    harness.commit();
    let document = harness.render();
    let ledger = spec.expected_ledger();
    assert_eq!(
        (
            ledger.callers,
            ledger.modules,
            ledger.edges,
            ledger.endpoints
        ),
        (200, 40, 8000, 640)
    );
    assert_ledger(&document, &ledger);
    assert_settled(&document, 0);
}

// ---------------------------------------------------------------------------
// B: separate budgets, named refusal, evidence intact.
// ---------------------------------------------------------------------------

/// One scripted module with full admission control, for budget tests.
fn module_info(index: usize, admission: AdmissionState, endpoints: Option<usize>) -> ModuleInfo {
    let path = format!("/budget/b{index}.so");
    ModuleInfo {
        path: path.clone(),
        key: ModuleKey::physical(
            8,
            2,
            200_000 + index as u64,
            Some(format!("bsha{index:06}")),
            &path,
        ),
        build_id: None,
        identity_source: Some("workload".into()),
        admission,
        admission_class: Some("exact".into()),
        admission_endpoints: endpoints,
        admission_reasons: Vec::new(),
    }
}

#[test]
fn separate_budgets_refuse_by_name_without_erasing_evidence() {
    // Caller budget: 4 retained, the 5th refused at admission.
    let mut callers = limited(4, 64, 64, 64, 1 << 20, 64);
    let spec = ScaleSpec {
        name: "budget-callers",
        callers: 4,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 60_000,
    };
    callers.stage_scale(&spec);
    callers.commit();
    let now = callers.now_ns();
    callers.source().spawn(60_004, 1111);
    let observed: BTreeSet<u32> = [60_004].into_iter().collect();
    let events = callers.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    callers
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    callers.commit();
    let document = callers.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 4,
            modules: 1,
            edges: 4,
            endpoints: 4,
            callers_refused: 1,
            modules_refused: 0,
            edges_refused: 0,
            endpoints_refused: 0,
            gaps: Some(1),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    assert_eq!(document["budgets"]["callers"]["limit"], 4);
    let gap = &document["gaps"][0];
    assert_eq!(gap["budget"]["resource"], "callers");
    assert_eq!(gap["budget"]["limit"], 4);
    assert_eq!(gap["budget"]["requested"], 5);
    // The text summary carries the refusal too.
    let text = crate::inventory::render_text(callers.coordinator(), "workload", 0, now, 2);
    assert!(
        text.contains("(budget callers: limit 4, requested 5)"),
        "text refusal names resource, limit, requested:\n{text}"
    );

    // Module budget: 2 retained, the 3rd refused.
    let mut modules = limited(64, 2, 64, 64, 1 << 20, 64);
    let spec = ScaleSpec {
        name: "budget-modules",
        callers: 1,
        modules: 2,
        edges_per_caller: 2,
        endpoints_per_module: 4,
        first_pid: 61_000,
    };
    modules.stage_scale(&spec);
    modules.commit();
    let now = modules.now_ns();
    let caller = modules.coordinator().adapter().live_id(61_000).unwrap();
    modules.coordinator_mut().registry_mut().note_mapping(
        caller,
        61_000,
        module_info(2, AdmissionState::Admitted, Some(4)),
        now,
    );
    modules.commit();
    let document = modules.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 1,
            modules: 2,
            edges: 2,
            endpoints: 8,
            callers_refused: 0,
            modules_refused: 1,
            edges_refused: 0,
            endpoints_refused: 0,
            gaps: Some(1),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    assert_eq!(document["gaps"][0]["budget"]["resource"], "modules");

    // Edge budget: 2 retained, the 3rd refused (module budget has room).
    let mut edges = limited(64, 64, 2, 64, 1 << 20, 64);
    let spec = ScaleSpec {
        name: "budget-edges",
        callers: 1,
        modules: 2,
        edges_per_caller: 2,
        endpoints_per_module: 4,
        first_pid: 62_000,
    };
    edges.stage_scale(&spec);
    edges.commit();
    let now = edges.now_ns();
    let caller = edges.coordinator().adapter().live_id(62_000).unwrap();
    edges.coordinator_mut().registry_mut().note_mapping(
        caller,
        62_000,
        module_info(7, AdmissionState::Admitted, Some(4)),
        now,
    );
    edges.commit();
    let document = edges.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 1,
            modules: 3,
            edges: 2,
            endpoints: 12,
            callers_refused: 0,
            modules_refused: 0,
            edges_refused: 1,
            endpoints_refused: 0,
            gaps: Some(1),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    assert_eq!(document["gaps"][0]["budget"]["resource"], "edges");
    assert_eq!(document["gaps"][0]["budget"]["requested"], 3);

    // Endpoint budget: 10 retained, a module costing past it refused
    // while the retained catalog and its edges stay.
    let mut endpoints = limited(64, 64, 64, 64, 10, 64);
    let spec = ScaleSpec {
        name: "budget-endpoints",
        callers: 1,
        modules: 2,
        edges_per_caller: 2,
        endpoints_per_module: 4,
        first_pid: 63_000,
    };
    endpoints.stage_scale(&spec);
    endpoints.commit();
    let now = endpoints.now_ns();
    let caller = endpoints.coordinator().adapter().live_id(63_000).unwrap();
    endpoints.coordinator_mut().registry_mut().note_mapping(
        caller,
        63_000,
        module_info(9, AdmissionState::Admitted, Some(4)),
        now,
    );
    endpoints.commit();
    let document = endpoints.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 1,
            modules: 2,
            edges: 2,
            endpoints: 8,
            callers_refused: 0,
            modules_refused: 0,
            edges_refused: 0,
            endpoints_refused: 1,
            gaps: Some(1),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    let gap = &document["gaps"][0];
    assert_eq!(gap["subject"], "endpoint budget exhausted");
    assert_eq!(gap["budget"]["resource"], "endpoints");
    assert_eq!(gap["budget"]["limit"], 10);
    assert_eq!(gap["budget"]["requested"], 12);
    assert_eq!(document["budgets"]["endpoints"]["occupied"], 8);

    // Every budget row carries its own limit, occupancy, and loss
    // counter — including the withheld semantic budget and the
    // retained-history row.
    assert_eq!(document["budgets"]["semantic_state"]["limit"], 64);
    assert_eq!(document["budgets"]["semantic_state"]["occupied"], 0);
    assert_eq!(document["budgets"]["semantic_state"]["status"], "withheld");
    assert_eq!(document["budgets"]["semantic_state"]["unknown_edges"], 2);
    assert_eq!(
        document["budgets"]["counters"]["cap"],
        18446744073709551615u64
    );
    assert_eq!(document["budgets"]["counters"]["observed_edges"], 0);
    assert_eq!(document["budgets"]["counters"]["saturated_edges"], 0);
    assert_eq!(document["budgets"]["retained_history"]["limit"], 64);
    assert_eq!(document["budgets"]["retained_history"]["retained"], 1);
    assert_eq!(document["budgets"]["retained_history"]["suppressed"], 0);
}

#[test]
fn endpoint_census_charges_only_admitted_modules() {
    let mut harness = limited(64, 64, 64, 64, 100, 64);
    let now = harness.now_ns();
    let registry = harness.coordinator_mut().registry_mut();
    // Refused, unresolved, and count-less admitted modules cost nothing.
    registry.note_mapping(
        CallerId(0),
        50,
        module_info(0, AdmissionState::Refused, Some(50)),
        now,
    );
    registry.note_mapping(
        CallerId(1),
        51,
        module_info(1, AdmissionState::Unresolved, Some(60)),
        now,
    );
    registry.note_mapping(
        CallerId(2),
        52,
        module_info(2, AdmissionState::Admitted, None),
        now,
    );
    registry.note_mapping(
        CallerId(3),
        53,
        module_info(3, AdmissionState::Admitted, Some(30)),
        now,
    );
    registry.note_mapping(
        CallerId(4),
        54,
        module_info(4, AdmissionState::Admitted, Some(40)),
        now,
    );
    harness.commit();
    assert_eq!(harness.coordinator().registry().endpoints_total(), 70);
    // 70 + 40 exceeds the 100 census: the new module refuses with a
    // named gap and the retained five stay.
    let now = harness.now_ns();
    harness.coordinator_mut().registry_mut().note_mapping(
        CallerId(5),
        55,
        module_info(5, AdmissionState::Admitted, Some(40)),
        now,
    );
    harness.commit();
    let registry = harness.coordinator().registry();
    assert_eq!(registry.endpoints_total(), 70);
    assert_eq!(registry.module_count(), 5);
    assert_eq!(registry.endpoints_refused(), 1);
    // No render here: these CallerIds were never adapter-admitted (the
    // census rule is registry-level), and the renderer asserts every
    // edge endpoint resolves. The budgets row itself renders in the
    // budget test above.
    assert_eq!(registry.gaps().len(), 1);
    let gap = &registry.gaps()[0];
    assert_eq!(gap.subject, "endpoint budget exhausted");
    let refusal = gap.budget.expect("the refusal names its budget");
    assert_eq!(
        (refusal.resource, refusal.limit, refusal.requested),
        ("endpoints", 100, 110)
    );
}

// ---------------------------------------------------------------------------
// C: failure injection with exact loss accounting and terminal settlement.
// ---------------------------------------------------------------------------

#[test]
fn admission_failures_gap_exactly_with_zero_fd_delta() {
    let _serial = serial_guard();
    inject_admission_failures();
}

/// Admission/growth failure injection, callable from the test above
/// and from the RSS worker.
fn inject_admission_failures() {
    let scope = FdScope::open("admission failure injection");
    let mut harness = harness();
    let now = harness.now_ns();
    for pid in 7000..7008 {
        harness.source().spawn(pid, 1000 + pid as u64);
    }
    for pid in [7001, 7003, 7005] {
        harness.source().set_fail_open(pid, true);
    }
    let observed: BTreeSet<u32> = (7000..7008).collect();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    assert_eq!(events.len(), 8);
    let failed: Vec<&CallerEvent> = events
        .iter()
        .filter(|event| matches!(event, CallerEvent::AdmitFailed { .. }))
        .collect();
    assert_eq!(failed.len(), 3);
    for event in &failed {
        match event {
            CallerEvent::AdmitFailed { reason, budget, .. } => {
                assert!(reason.contains("injected admission failure"), "{reason}");
                assert_eq!(*budget, None, "pin failures carry no budget");
            }
            other => panic!("expected AdmitFailed, got {other:?}"),
        }
    }
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    harness.commit();
    // The injection clears: the failed three admit on the next pass.
    for pid in [7001, 7003, 7005] {
        harness.source().set_fail_open(pid, false);
    }
    let now = harness.now_ns();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    assert_eq!(events.len(), 3);
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    harness.commit();
    scope.assert_delta(0);
    let document = harness.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 8,
            modules: 0,
            edges: 0,
            endpoints: 0,
            callers_refused: 0,
            modules_refused: 0,
            edges_refused: 0,
            endpoints_refused: 0,
            gaps: Some(3),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
}

#[test]
fn provider_mutation_mid_run_splits_module_instances() {
    let _serial = serial_guard();
    inject_provider_mutation();
}

/// Provider-mutation injection (dlclose/dlopen of a changed `.so`),
/// callable from the test above and from the RSS worker.
fn inject_provider_mutation() {
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("workload-mutate");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let v1 = gcc(
        &dir,
        "mut-v1.so",
        &manifest.join("crates/discover/tests/fixture/version_matrix.c"),
        &["-shared", "-fPIC", "-DLEGACY_MINOR=40"],
        &[],
    );
    let v2 = gcc(
        &dir,
        "mut-v2.so",
        &manifest.join("crates/discover/tests/fixture/version_matrix.c"),
        &["-shared", "-fPIC", "-DLEGACY_MINOR=41"],
        &[],
    );
    let driver = gcc(
        &dir,
        "mutate-driver",
        &manifest.join("tests/fixtures/inventory-mutate-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    // The provider path the driver maps; v1 bytes first.
    let prov = dir.join("mut-prov.so");
    std::fs::copy(&v1, &prov).unwrap();
    let ready = dir.join("mut.ready");
    let go = dir.join("mut.go");
    let done = dir.join("mut.done");
    let child = std::process::Command::new(&driver)
        .arg("--ready")
        .arg(&ready)
        .arg("--go")
        .arg(&go)
        .arg("--done")
        .arg(&done)
        .arg(&prov)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let driver_pid = child.id();
    let _reaper = ChildReaper(child);
    wait_for(&ready, "mutate ready");
    let mut coordinator = InventoryCoordinator::new(
        Scope::Pid(driver_pid),
        HookRegistry::builtin(),
        vec![prov.clone()],
        OsProcessSource,
        RegistryLimits::default_limits(),
    )
    .unwrap();
    let t0 = crate::discovery::caller_registry::now_ns();
    coordinator
        .scan_pass(
            &InventoryScope::Pid(driver_pid),
            None,
            &mut UnavailableImageGuard,
            |_| None,
            u64::MAX,
            t0,
        )
        .unwrap();
    coordinator.commit_batch(false).unwrap();
    // Atomic replace plus the driver's dlclose/dlopen: the same path
    // resolves to a new physical instance. The FD scope covers the
    // whole second pass — scans open files transiently and retain
    // nothing new.
    let scope = FdScope::open("provider mutation second pass");
    std::fs::copy(&v2, dir.join("mut-prov.staging")).unwrap();
    std::fs::rename(dir.join("mut-prov.staging"), &prov).unwrap();
    std::fs::write(&go, "go\n").unwrap();
    wait_for(&done, "mutate done");
    let t1 = crate::discovery::caller_registry::now_ns();
    coordinator
        .scan_pass(
            &InventoryScope::Pid(driver_pid),
            None,
            &mut UnavailableImageGuard,
            |_| None,
            u64::MAX,
            t1,
        )
        .unwrap();
    coordinator.commit_batch(false).unwrap();
    scope.assert_delta(0);
    let document = crate::inventory::render_json(&coordinator, "workload", t0, t1, 2);
    assert_settled(&document, 0);
    // One pid, one incarnation, still mapped: dlclose/dlopen is not exec.
    assert_eq!(document["callers"].as_array().unwrap().len(), 1);
    assert_eq!(
        document["callers"][0]["pid"].as_u64().unwrap(),
        u64::from(driver_pid)
    );
    assert_eq!(document["callers"][0]["lifecycle"], "mapped");
    let caller_id = document["callers"][0]["id"].as_str().unwrap().to_string();
    // Two physical instances under one path: the mutation split them.
    let prov_str = prov.to_string_lossy().into_owned();
    let ours: Vec<&serde_json::Value> = document["modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|module| {
            module["paths"]
                .as_array()
                .unwrap()
                .iter()
                .any(|path| path.as_str().unwrap() == prov_str)
        })
        .collect();
    assert_eq!(ours.len(), 2, "one path, two instances");
    assert_ne!(ours[0]["id"], ours[1]["id"]);
    assert_ne!(
        ours[0]["identity"]["sha256"], ours[1]["identity"]["sha256"],
        "v1 and v2 bytes differ"
    );
    let (old, new) = if ours[0]["lifecycle"] == "unloaded" {
        (ours[0], ours[1])
    } else {
        (ours[1], ours[0])
    };
    // The complete rescan proved v1 gone (sticky unload) while v2 maps.
    assert_eq!(old["lifecycle"], "unloaded");
    assert_eq!(old["unloaded_observed"], true);
    assert_eq!(new["lifecycle"], "mapped");
    let edge_for = |module: &str| {
        document["edges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|edge| edge["caller"] == caller_id && edge["module"] == module)
            .unwrap()
            .clone()
    };
    let old_edge = edge_for(old["id"].as_str().unwrap());
    let new_edge = edge_for(new["id"].as_str().unwrap());
    assert_eq!(old_edge["mapping"]["state"], "ended");
    assert_eq!(old_edge["mapping"]["interruptions"], 1);
    assert!(old_edge["mapping"]["reason"].is_string());
    assert_eq!(new_edge["mapping"]["state"], "mapped");
    assert_eq!(new_edge["entries"]["count"], 0);
}

#[test]
fn discovery_loss_marks_uncertain_with_exact_gaps() {
    let _serial = serial_guard();
    inject_discovery_loss();
}

/// Event/discovery-loss injection, callable from the test above and
/// from the RSS worker.
fn inject_discovery_loss() {
    let scope = FdScope::open("discovery loss injection");
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "loss",
        callers: 4,
        modules: 2,
        edges_per_caller: 2,
        endpoints_per_module: 4,
        first_pid: 70_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    // Event loss before the discovery loss: a usage batch for an edge
    // that was never mapped drops with its own gap.
    let now = harness.now_ns();
    let caller = harness.coordinator().adapter().live_id(70_000).unwrap();
    let ghost = ModuleKey::physical(8, 9, 999, Some("ghost".into()), "/loss/ghost.so");
    harness
        .coordinator_mut()
        .registry_mut()
        .observe_entries(caller, &ghost, 5, now);
    harness.commit();
    // Discovery loss: a pass with no observation behind it. Live
    // callers stay live; their edges turn uncertain — neither
    // confirmed nor refuted.
    let report = harness.observe_loss("injected discovery loss");
    assert_eq!(report.scanned, 0);
    scope.assert_delta(0);
    let document = harness.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 4,
            modules: 2,
            edges: 8,
            endpoints: 8,
            callers_refused: 0,
            modules_refused: 0,
            edges_refused: 0,
            endpoints_refused: 0,
            gaps: Some(2),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    assert_eq!(document["observation"]["passes"], 3);
    for edge in document["edges"].as_array().unwrap() {
        assert_eq!(edge["mapping"]["state"], "uncertain");
    }
    let subjects: Vec<&str> = document["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|gap| gap["subject"].as_str().unwrap())
        .collect();
    assert_eq!(
        subjects,
        [
            "entry without mapping evidence",
            "scan pass produced no observation"
        ]
    );
}

#[test]
fn caller_churn_storm_settles_with_exact_ledger() {
    let _serial = serial_guard();
    run_churn_storm();
}

/// Caller churn (spawn/exit storm), callable from the test above and
/// from the RSS worker. RSS itself is bounded by the worker's isolated
/// peak, never by an in-process delta (RSS is process-global and the
/// suite runs parallel).
fn run_churn_storm() {
    let scope = FdScope::open("caller churn storm");
    let mut harness = harness();
    // 128 pids × 8 generations: a spawn/exit storm with PID reuse.
    let spec = ChurnSpec {
        pids: 128,
        generations: 8,
        modules: 16,
        first_pid: 80_000,
    };
    let (admitted, events) = harness.run_churn(&spec);
    assert_eq!(admitted, 1024, "every generation admits every pid");
    let exits = events
        .iter()
        .filter(|event| matches!(event, CallerEvent::Exited { .. }))
        .count();
    assert_eq!(exits, 1024, "every incarnation retires exactly once");
    scope.assert_delta(0);
    let document = harness.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 1024,
            modules: 16,
            edges: 1024,
            endpoints: 64,
            callers_refused: 0,
            modules_refused: 0,
            edges_refused: 0,
            endpoints_refused: 0,
            gaps: Some(0),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    // Terminal settlement, every record: all 1024 retired with reasons,
    // all 1024 edges ended with reasons, modules unknown (a dead
    // caller's absence proves no unload).
    for caller in document["callers"].as_array().unwrap() {
        assert_eq!(caller["lifecycle"], "exited");
        assert_eq!(caller["retired"], true);
    }
    for edge in document["edges"].as_array().unwrap() {
        assert_eq!(edge["mapping"]["state"], "ended");
    }
    for module in document["modules"].as_array().unwrap() {
        assert_eq!(module["lifecycle"], "unknown");
    }
}

#[test]
fn interrupted_shutdown_drops_the_batch_whole_never_partial() {
    let _serial = serial_guard();
    interrupt_shutdown();
}

/// Interrupted-shutdown injection (coordinator dropped mid-batch),
/// callable from the test above and from the RSS worker.
fn interrupt_shutdown() {
    let scope = FdScope::open("interrupted shutdown");
    // Stage a batch and render before the commit: adapter admissions are
    // live, but every staged registry fact is invisible.
    let spec = ScaleSpec {
        name: "interrupted",
        callers: 8,
        modules: 4,
        edges_per_caller: 2,
        endpoints_per_module: 4,
        first_pid: 90_000,
    };
    let mut doomed = harness();
    doomed.stage_scale(&spec);
    let pre = doomed.render();
    assert_eq!(pre["callers"].as_array().unwrap().len(), 8);
    assert_eq!(pre["modules"].as_array().unwrap().len(), 0);
    assert_eq!(pre["edges"].as_array().unwrap().len(), 0);
    // The coordinator drops mid-batch: 16 staged mappings, zero
    // published. Recovery is a deterministic re-run, and the replay's
    // applied count is the exact loss accounting of the dropped batch.
    drop(doomed);
    let mut replay = harness();
    replay.stage_scale(&spec);
    let receipt = replay.commit();
    assert_eq!(receipt.registry_facts, receipt.registry_published);
    assert_eq!(receipt.registry_applied, 16, "the dropped batch staged 16");
    scope.assert_delta(0);
    let document = replay.render();
    assert_ledger(&document, &spec.expected_ledger());
    assert_settled(&document, 0);
}

// ---------------------------------------------------------------------------
// D: honest history — retention caps, eviction markers, never silent.
// ---------------------------------------------------------------------------

#[test]
fn retention_overflow_marks_eviction_never_silent_completeness() {
    use crate::discovery::caller_registry::RegistryGap;
    let mut harness = limited(64, 64, 64, 1024, 1 << 20, 64);
    let spec = ScaleSpec {
        name: "retention",
        callers: 3,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 95_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    // Three edges, three mapping truths: ended (complete evidence),
    // uncertain (truncated observation), mapped (live evidence).
    let now = harness.now_ns();
    harness.source().kill(95_000);
    let observed: BTreeSet<u32> = [95_001, 95_002].into_iter().collect();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    let middle = harness.coordinator().adapter().live_id(95_001).unwrap();
    harness
        .coordinator_mut()
        .registry_mut()
        .note_member_unscanned(middle);
    // Overflow gap retention: 1500 staged into a 1024 bound.
    for index in 0..1500 {
        harness
            .coordinator_mut()
            .registry_mut()
            .record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: format!("retention probe {index}"),
                reason: "the retention test overflows the gap bound on purpose".into(),
                budget: None,
            });
    }
    harness.commit();
    let document = harness.render();
    let gaps = document["gaps"].as_array().unwrap();
    assert_eq!(gaps.len(), 1024, "retention caps at the bound");
    assert_eq!(document["gaps_suppressed"], 476, "476 evicted, exactly");
    assert_eq!(document["budgets"]["retained_history"]["retained"], 1024,);
    assert_eq!(document["budgets"]["retained_history"]["suppressed"], 476,);
    assert_settled(&document, 476);
    let text = crate::inventory::render_text(harness.coordinator(), "workload", 0, now, 2);
    assert!(
        text.contains("gaps suppressed: 476"),
        "the text summary marks the eviction:\n{text}"
    );
    // No silent completeness claim: no key anywhere names completeness.
    fn assert_no_completeness(value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    assert!(
                        key != "complete" && key != "completeness",
                        "no completeness claim key"
                    );
                    assert_no_completeness(child);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    assert_no_completeness(item);
                }
            }
            _ => {}
        }
    }
    assert_no_completeness(&document);
    // Observed-complete vs truncated vs unknown, in one document.
    let states: BTreeSet<&str> = document["edges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|edge| edge["mapping"]["state"].as_str().unwrap())
        .collect();
    assert_eq!(
        states,
        ["ended", "mapped", "uncertain"].into_iter().collect()
    );
    for edge in document["edges"].as_array().unwrap() {
        assert_eq!(
            edge["entries"]["observation"],
            "unknown (usage observation unavailable)"
        );
        assert_eq!(edge["semantics"], "unknown (semantic capture withheld)");
    }
}

// ---------------------------------------------------------------------------
// C: one isolated RSS bound for every in-crate injection.
// ---------------------------------------------------------------------------

/// Stated peak-RSS bound for the whole injection battery (admission
/// failures, discovery loss, interrupted shutdown, provider mutation,
/// and the 1024-incarnation churn storm) in one isolated process.
/// Measured at ~38 MiB (test binary baseline plus the battery); the
/// 256 MiB bound leaves headroom for allocator and platform variance
/// while still catching runaway growth.
const INJECTION_RSS_BOUND_BYTES: u64 = 256 << 20;

/// RSS worker: re-runs every in-crate injection body in one isolated
/// process and prints its peak RSS. A no-op in normal suite runs (the
/// env gate is set only by the parent test's re-exec); the bodies'
/// own assertions re-verify the ledgers in isolation as a bonus.
#[test]
fn workload_rss_worker() {
    if std::env::var_os("P11SCOPE_WORKLOAD_RSS_WORKER").is_none() {
        return;
    }
    inject_admission_failures();
    inject_discovery_loss();
    interrupt_shutdown();
    inject_provider_mutation();
    run_churn_storm();
    println!("WORKLOAD_RSS_HWM_BYTES {}", peak_rss_bytes());
}

#[test]
fn injected_workloads_stay_within_rss_bound() {
    let exe = std::env::current_exe().unwrap();
    let output = std::process::Command::new(exe)
        .arg("discovery::inventory_workload::tests::workload_rss_worker")
        .arg("--exact")
        .arg("--nocapture")
        .env("P11SCOPE_WORKLOAD_RSS_WORKER", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();
    assert!(
        output.status.success(),
        "the RSS worker runs every injection green: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let hwm: u64 = stdout
        .lines()
        .find_map(|line| line.strip_prefix("WORKLOAD_RSS_HWM_BYTES ")?.parse().ok())
        .expect("the worker prints its peak RSS");
    assert!(
        hwm < INJECTION_RSS_BOUND_BYTES,
        "injection battery peak RSS {hwm} bytes stays within {INJECTION_RSS_BOUND_BYTES}"
    );
}
