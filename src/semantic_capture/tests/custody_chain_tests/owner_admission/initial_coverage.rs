//! SPDX-License-Identifier: GPL-3.0-or-later
//! First observed semantic registration after physical use, through the real Cgroup
//! driver/H0 and registry publication. Only native transport is substituted;
//! these controls do not qualify kernel attachment or count missing API calls.

use super::*;
use crate::attach::capture::{AttachedEndpoint, CallerCountUpdate};
use crate::discovery::caller_registry::{ModuleId, RegistryGap, UseCoverage};
use crate::discovery::instances::UnknownReason as RouteUnknown;
use crate::discovery::inventory_attach_set::AttachEndpoint;
use crate::inventory_semantics::LaneTestIo;

/// Observe only routing decisions at the substituted transport boundary. H0
/// still consumes each call once; the production driver stages its real batch.
struct RoutingProbe {
    lane: AdmissionLane,
    routes: Rc<RefCell<Vec<Route>>>,
}

impl LaneTestIo for RoutingProbe {
    fn tick_targets(&mut self, pins: &[Arc<PidPin>]) {
        self.lane.tick_targets(pins);
    }

    fn validate_current(
        &mut self,
        receipt: &CurrentPartitionReceipt,
        report: &mut TickReport,
    ) -> Result<(), CurrentReceiptRefusal> {
        self.lane.validate_current(receipt, report)
    }

    fn tick(&mut self, domain: NativeDomainId) -> Result<SemanticBatch, SemanticRefusal> {
        let mut owned = self.lane.0.borrow_mut();
        let AdmissionH0 {
            capture, io, stash, ..
        } = &mut *owned;
        let mut report = capture
            .tick_with(io)
            .map_err(|_| SemanticRefusal::Unavailable)?;
        assert_eq!(merge_stash_into_report(stash, &mut report), 0);
        self.routes
            .borrow_mut()
            .extend(report.calls().map(RoutedCall::route));
        SemanticBatch::from_tick_report(domain, report, Vec::new(), now_ns())
    }

    fn refresh(
        &mut self,
        pin: Arc<PidPin>,
        slot: u32,
    ) -> Result<(Vec<ImageIdentity>, Arc<PidPin>), SemanticRefusal> {
        self.lane.refresh(pin, slot)
    }

    fn has_pending_evidence(&self) -> bool {
        self.lane.has_pending_evidence()
    }

    fn finish(&mut self, domain: NativeDomainId) -> SemanticBatch {
        self.lane.finish(domain)
    }

    fn quiescent(&mut self) -> bool {
        self.lane.quiescent()
    }

    fn positions(&mut self) -> Option<[(usize, usize); 2]> {
        self.lane.positions()
    }

    fn drain_events_to(&mut self, stop: usize, quantum: usize) -> LaneDrainOutcome {
        self.lane.drain_events_to(stop, quantum)
    }

    fn drain_discovery_to(&mut self, stop: usize, quantum: usize) -> LaneDrainOutcome {
        self.lane.drain_discovery_to(stop, quantum)
    }
}

struct PhysicalIdentity {
    domain: NativeDomainId,
    pid: u32,
    queries: usize,
}

impl NativeIdentity<PidPin> for PhysicalIdentity {
    fn owner_image(&mut self, _: u32) -> Option<ImageIdentity> {
        None
    }

    fn query_cookie(&mut self, domain: NativeDomainId, pin: &PidPin) -> CookieQuery {
        if domain != self.domain || pin.pid() != self.pid {
            return CookieQuery::Unavailable("another Inventory object or caller".into());
        }
        assert!(pin.still_the_same());
        assert!(pin.pidfd().is_ok());
        self.queries += 1;
        CookieQuery::Cookie(DomainCookie::scripted(domain, 7))
    }
}

fn physical_read(
    domain: NativeDomainId,
    rows: Vec<WitnessRow>,
    counts: Vec<CallerCountUpdate>,
    at_ns: u64,
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
        counts,
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
        // AdmissionScene owns the real retained Cgroup root and has already
        // completed collection for these members. No PID/System authority is
        // substituted for that scope. Quiet membership remains unproved.
        custody: ScopeCustody::CgroupHeld,
        custody_proven_ns: None,
        lifecycle_proven_ns: u64::MAX,
        lifecycle_loss: None,
        unsettled: false,
    }
}

fn provider_module(scene: &AdmissionScene) -> ModuleId {
    let pin = scene
        .lane
        .as_ref()
        .unwrap()
        .subset()
        .pins()
        .pinned()
        .next()
        .unwrap();
    let module = ModuleKey::physical(
        pin.key.device.major,
        pin.key.device.minor,
        pin.key.inode,
        Some(pin.sha256.to_owned()),
        pin.path,
    );
    scene.coordinator.registry().module_id_for(&module).unwrap()
}

fn provider_endpoint(scene: &AdmissionScene, subset: &AttestedSubset) -> AttachEndpoint {
    let object = *subset.required().keys().next().unwrap();
    scene
        .coordinator
        .attach_set()
        .endpoints()
        .find(|endpoint| {
            scene
                .coordinator
                .attach_set()
                .target(endpoint.object)
                .is_some_and(|target| target.same_object_as(subset.pins(), object))
        })
        .copied()
        .expect("real catalog retained the exact provider's Inventory endpoint")
}

/// The production native read/drain/read staging seam binds a real original
/// process pin and publishes a count row for its actual retained provider.
/// The caller chooses the publication boundary, never registry mutations.
fn stage_physical_use(scene: &mut AdmissionScene, pid: u32, endpoint: AttachEndpoint) {
    stage_physical_use_from(scene, pid, endpoint, None);
}

fn stage_physical_use_from(
    scene: &mut AdmissionScene,
    pid: u32,
    endpoint: AttachEndpoint,
    first_ns: Option<u64>,
) {
    assert!(matches!(scene.scope, Scope::Cgroup { .. }));
    let domain = scene.identity.0;
    assert_ne!(domain, scene.lane.as_ref().unwrap().domain());
    let at_ns = now_ns();
    let first_ns = first_ns.unwrap_or(at_ns + 3);
    // A retained first-use row may arrive after semantic registration. Its
    // binding sight and attachment precede that use; read anchors remain late.
    assert!(first_ns > 3 && first_ns <= at_ns + 3);
    scene.coordinator.set_semantic_binding_clock(sight_clock);
    SIGHT_NS.with(|clock| clock.set(first_ns - 1));
    scene.coordinator.note_extend_receipt(&ExtendReceipt {
        attached: vec![AttachedEndpoint {
            id: endpoint.id,
            object: endpoint.object,
            at_ns: first_ns - 3,
        }],
        custody: Some(ScopeCustody::CgroupHeld),
        activated_roots: true,
        exec_coverage: Some(ExecCoverage::scripted(domain, 0)),
        ..ExtendReceipt::default()
    });
    let mut identity = PhysicalIdentity {
        domain,
        pid,
        queries: 0,
    };
    let inventory_image = ImageIdentity {
        task_cookie: 7,
        exec_id: 1,
    };
    let row = WitnessRow::scripted(
        domain,
        inventory_image.task_cookie,
        inventory_image.exec_id,
        endpoint.object,
        endpoint.id,
        pid,
        first_ns,
    );
    for batch in [
        NativeBatch::Witness(Box::new(physical_read(
            domain,
            vec![row],
            Vec::new(),
            at_ns + 4,
        ))),
        NativeBatch::Lifecycle(DiscoveryBatch::scripted(domain, Vec::new(), at_ns + 10)),
        NativeBatch::Witness(Box::new(physical_read(
            domain,
            Vec::new(),
            vec![CallerCountUpdate {
                image: inventory_image,
                object: endpoint.object,
                count: 7,
            }],
            at_ns + 20,
        ))),
    ] {
        let receipt = scene
            .coordinator
            .stage_native(batch, &mut identity, at_ns + 22);
        assert!(
            receipt.events.is_empty(),
            "no image transition: {:?}",
            receipt.events
        );
    }
    assert!(
        identity.queries > 0,
        "the real binder queried original custody"
    );
}

fn physical_snapshot(scene: &AdmissionScene) -> Vec<(CallerId, ModuleId, u64, UseCoverage)> {
    let registry = scene.coordinator.registry();
    let mut rows: Vec<_> = registry
        .edges()
        .filter(|edge| edge.entry_count > 0)
        .map(|edge| {
            (
                edge.caller,
                edge.module,
                edge.entry_count,
                registry.coverage(edge),
            )
        })
        .collect();
    rows.sort_by_key(|row| (row.0, row.1));
    rows
}

fn coverage_gaps(scene: &AdmissionScene) -> Vec<RegistryGap> {
    scene
        .coordinator
        .registry()
        .gaps()
        .iter()
        .filter(|gap| gap.reason == "before_semantic_boundary")
        .cloned()
        .collect()
}

fn admit_fresh_pair(scene: &mut AdmissionScene) {
    scene.observe_entry();
    let pid = scene.child.id();
    scene.h0.0.borrow_mut().after_refresh = Some(Box::new(move |owned| {
        owned.io.held.enqueue(pid, 0, "C_SignInit", 0x000d, 0);
        owned.io.held.enqueue(pid, 0, "C_Sign", 0, 0);
        // Two genuine receipts for the same unchanged partition reach this
        // bounded publication. Their first-proof disclosure must be emitted
        // once, independently of the number of accepted registrations.
        let pin = owned.last_effective.as_ref().unwrap().clone();
        let slot = owned.io.held.slot(0, "C_SignInit");
        let AdmissionH0 {
            capture, io, stash, ..
        } = owned;
        let mut report = capture.refresh_with(io, pin, slot).unwrap();
        assert_eq!(report.current().len(), 1);
        let (images, shed) = stash_refresh_report(stash, &mut report);
        assert_eq!(images, vec![image(7)]);
        assert_eq!(shed, 0);
    }));
    scene.pass();
    scene.assert_admitted();
    let row = scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .next()
        .unwrap();
    assert_eq!(row.api_returns, Some(2));
    assert_eq!(row.historical_only_returns, 0);
    assert!(!row.lossy);
    assert_eq!(row.semantics.as_ref().unwrap().completed(), 1);
    assert_eq!(scene.h0.0.borrow().capture.continuity_cuts(), 0);
}

/// Same authorizing production endpoints as the Cgroup commit, with its real
/// preparation/end-sample bracket. The caller controls only when the first
/// registry publication happens so physical and semantic facts can join it.
fn prepare_scoped_first_receipt(scene: &mut AdmissionScene) {
    scene.observe_entry();
    let pid = scene.child.id();
    let caller = scene.caller();
    let module = scene
        .coordinator
        .registry()
        .module(provider_module(scene))
        .unwrap()
        .key
        .clone();
    let CollectedPass::Cgroup(Ok(mut collection)) = scene.collect() else {
        panic!("a genuine owned Cgroup collection is required");
    };
    let preparation = collection.preparation(pid).unwrap();
    let prepared = scene
        .coordinator
        .adapter_mut()
        .prepare_scoped_caller(&preparation)
        .map_err(|failure| failure.reason)
        .unwrap();
    let lane = scene.lane.as_mut().unwrap();
    let candidate = scene
        .coordinator
        .prepare_scoped_semantic_candidate(&prepared, lane.domain())
        .unwrap();
    let slot = scene.h0.0.borrow().io.held.slot(0, "C_SignInit");
    let owner = lane
        .prepare_caller_admission(candidate.pin(), slot, &module, |bytes| {
            scene.coordinator.registry().reserve_semantic_storage(bytes)
        })
        .unwrap();
    collection.sample_end(&std::collections::BTreeSet::from([pid]));
    let (receipt, result) =
        scene
            .coordinator
            .consume_semantic_admission(candidate, owner, collection.permit(pid));
    result.unwrap();
    lane.deliver_admission_receipt(receipt);
    assert_eq!(scene.coordinator.semantic_bindings().len(), 1);
    assert_eq!(scene.coordinator.registry().instances().count(), 0);
    assert_eq!(scene.caller(), caller);
}

fn route_early_unknown_pair(scene: &mut AdmissionScene) {
    let pid = scene.child.id();
    scene.observe_entry();
    // HeldIo uses this map only to encode genuine deterministic CALL bytes.
    // H0 receives no selected tick pins until the coordinator admits custody.
    let event_pin = scene.pin();
    {
        let mut owned = scene.h0.0.borrow_mut();
        owned.io.held.targets.insert(pid, (event_pin, image(7)));
        owned.io.held.enqueue(pid, 0, "C_SignInit", 0x000d, 0);
        owned.io.held.enqueue(pid, 0, "C_Sign", 0, 0);
    }
    let routes = Rc::new(RefCell::new(Vec::new()));
    scene
        .lane
        .as_mut()
        .unwrap()
        .install_test_io(Box::new(RoutingProbe {
            lane: scene.h0.clone(),
            routes: routes.clone(),
        }));
    scene.lane = Some(crate::inventory::classic_semantic_tick_for_test(
        &mut scene.coordinator,
        scene.lane.take().unwrap(),
    ));
    assert_eq!(
        *routes.borrow(),
        vec![Route::Unknown(RouteUnknown::Unobserved); 2],
        "the real prebinding H0 tick cannot attribute either old API return"
    );
    assert!(scene.h0.0.borrow().io.tick_pins.is_empty());
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
    assert_eq!(scene.coordinator.registry().instances().count(), 0);
    assert!(coverage_gaps(scene).is_empty());
    scene
        .lane
        .as_mut()
        .unwrap()
        .install_test_io(Box::new(scene.h0.clone()));
}

#[test]
fn initial_coverage_discloses_prior_committed_use_without_reducing_early_unknowns() {
    let mut scene = Box::new(AdmissionScene::new(Selection::Cgroup));
    scene.prepare_without_cookie();
    let caller = scene.caller();
    let module = provider_module(&scene);
    let endpoint = provider_endpoint(&scene, scene.lane.as_ref().unwrap().subset());
    let pid = scene.child.id();
    stage_physical_use(&mut scene, pid, endpoint);
    scene.coordinator.commit_batch(false).unwrap();
    let physical = physical_snapshot(&scene);
    assert_eq!(physical.len(), 1);
    assert_eq!(
        (physical[0].0, physical[0].1, physical[0].2),
        (caller, module, 7)
    );
    assert!(matches!(
        physical[0].3,
        UseCoverage::Counted { lossy: false, .. }
    ));
    assert!(coverage_gaps(&scene).is_empty(), "no registration yet");
    route_early_unknown_pair(&mut scene);

    admit_fresh_pair(&mut scene);
    let gaps = coverage_gaps(&scene);
    assert_eq!(
        gaps.len(),
        1,
        "first observed registration must disclose the earlier physical-use interval"
    );
    assert_eq!(gaps[0].caller, Some(caller));
    assert_eq!(gaps[0].module, Some(module));
    assert_eq!(
        gaps[0].subject,
        "physical provider use preceded first observed semantic registration"
    );
    assert!(gaps[0].budget.is_none());
    let gap_index = scene
        .coordinator
        .registry()
        .gaps()
        .iter()
        .position(|gap| gap == &gaps[0])
        .unwrap();
    assert_eq!(
        scene.coordinator.registry().gap_repeats()[gap_index],
        1,
        "multiple genuine receipts in one registration batch disclose once"
    );
    assert_eq!(physical_snapshot(&scene), physical);

    scene.pass();
    scene.pass();
    assert_eq!(
        coverage_gaps(&scene),
        gaps,
        "the initial interval remains disclosed"
    );
    assert_eq!(physical_snapshot(&scene), physical);
    let row = scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .next()
        .unwrap();
    assert_eq!(
        row.api_returns,
        Some(2),
        "the old Unknown returns never reappear"
    );
    assert_eq!(row.semantics.as_ref().unwrap().completed(), 1);
    assert_eq!(scene.coordinator.registry().instances().count(), 1);
}

#[test]
fn initial_coverage_same_publication_discloses_physical_use_before_registration() {
    let mut scene = Box::new(AdmissionScene::new(Selection::Cgroup));
    scene.prepare_without_cookie();
    let endpoint = provider_endpoint(&scene, scene.lane.as_ref().unwrap().subset());
    let pid = scene.child.id();
    stage_physical_use(&mut scene, pid, endpoint);
    prepare_scoped_first_receipt(&mut scene);
    assert!(
        physical_snapshot(&scene).is_empty(),
        "physical use is only staged"
    );
    {
        let mut owned = scene.h0.0.borrow_mut();
        owned.io.held.enqueue(pid, 0, "C_SignInit", 0x000d, 0);
        owned.io.held.enqueue(pid, 0, "C_Sign", 0, 0);
    }
    scene.lane = Some(crate::inventory::classic_semantic_tick_for_test(
        &mut scene.coordinator,
        scene.lane.take().unwrap(),
    ));
    scene.assert_admitted();
    let row = scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .next()
        .unwrap();
    assert_eq!(row.api_returns, Some(2));
    assert_eq!(row.historical_only_returns, 0);
    assert!(!row.lossy);
    assert_eq!(row.semantics.as_ref().unwrap().completed(), 1);
    assert_eq!(physical_snapshot(&scene)[0].2, 7);
    let registry = scene.coordinator.registry();
    assert!(
        registry
            .edge(scene.caller(), provider_module(&scene))
            .unwrap()
            .entry_first_seen_ns
            .unwrap()
            < registry.instances().next().unwrap().first_seen_ns
    );
    let gaps = coverage_gaps(&scene);
    assert_eq!(
        gaps.len(),
        1,
        "physical use precedes the first registration even within one publication"
    );
    assert_eq!(
        (gaps[0].caller, gaps[0].module),
        (Some(scene.caller()), Some(provider_module(&scene)))
    );
    let index = scene
        .coordinator
        .registry()
        .gaps()
        .iter()
        .position(|gap| gap == &gaps[0])
        .unwrap();
    scene.pass();
    assert_eq!(scene.coordinator.registry().gap_repeats()[index], 1);
}

#[test]
fn initial_coverage_physical_use_after_first_registration_stays_clean() {
    let mut scene = Box::new(AdmissionScene::new(Selection::Cgroup));
    scene.prepare_without_cookie();
    admit_fresh_pair(&mut scene);
    let endpoint = provider_endpoint(&scene, scene.lane.as_ref().unwrap().subset());
    let pid = scene.child.id();
    stage_physical_use(&mut scene, pid, endpoint);
    scene.coordinator.commit_batch(false).unwrap();
    assert_eq!(physical_snapshot(&scene)[0].2, 7);
    assert!(coverage_gaps(&scene).is_empty());
    let row = scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .next()
        .unwrap();
    assert_eq!(row.api_returns, Some(2));
    assert_eq!(row.historical_only_returns, 0);
    assert!(!row.lossy);
    assert_eq!(row.semantics.as_ref().unwrap().completed(), 1);
}

#[test]
fn initial_coverage_delayed_physical_reveal_preserves_early_unknowns_and_current_calls() {
    let mut scene = Box::new(AdmissionScene::new(Selection::Cgroup));
    scene.prepare_without_cookie();
    route_early_unknown_pair(&mut scene);
    let first_ns = now_ns();
    admit_fresh_pair(&mut scene);
    assert!(physical_snapshot(&scene).is_empty());
    assert!(coverage_gaps(&scene).is_empty());
    assert!(
        first_ns
            < scene
                .coordinator
                .registry()
                .instances()
                .next()
                .unwrap()
                .first_seen_ns
    );
    let endpoint = provider_endpoint(&scene, scene.lane.as_ref().unwrap().subset());
    let pid = scene.child.id();
    stage_physical_use_from(&mut scene, pid, endpoint, Some(first_ns));
    scene.coordinator.commit_batch(false).unwrap();
    let physical = physical_snapshot(&scene);
    assert_eq!(physical[0].2, 7);
    let gaps = coverage_gaps(&scene);
    assert_eq!(
        gaps.len(),
        1,
        "late count reveal must not hide earlier physical use"
    );
    assert_eq!(
        (gaps[0].caller, gaps[0].module),
        (Some(scene.caller()), Some(provider_module(&scene)))
    );
    let index = scene
        .coordinator
        .registry()
        .gaps()
        .iter()
        .position(|gap| gap == &gaps[0])
        .unwrap();
    scene.pass();
    assert_eq!(scene.coordinator.registry().gap_repeats()[index], 1);
    assert_eq!(physical_snapshot(&scene), physical);
    let row = scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .next()
        .unwrap();
    assert_eq!(
        row.api_returns,
        Some(2),
        "earlier Unknown returns do not reappear"
    );
    assert_eq!(row.historical_only_returns, 0);
    assert!(!row.lossy);
    assert_eq!(row.semantics.as_ref().unwrap().completed(), 1);
}

#[test]
fn initial_coverage_quiet_mapped_provider_stays_clean() {
    let mut scene = Box::new(AdmissionScene::new(Selection::Cgroup));
    scene.prepare_without_cookie();
    assert!(physical_snapshot(&scene).is_empty());
    admit_fresh_pair(&mut scene);
    assert!(physical_snapshot(&scene).is_empty());
    assert!(
        coverage_gaps(&scene).is_empty(),
        "mapping alone proves no earlier use"
    );
}

#[test]
fn initial_coverage_unattested_provider_cannot_disclose_or_register() {
    let mut scene = Box::new(AdmissionScene::new(Selection::Cgroup));
    scene.prepare_without_cookie();
    let endpoint = provider_endpoint(&scene, scene.lane.as_ref().unwrap().subset());
    let pid = scene.child.id();
    stage_physical_use(&mut scene, pid, endpoint);
    scene.coordinator.commit_batch(false).unwrap();
    let physical = physical_snapshot(&scene);
    assert_eq!(physical[0].2, 7);
    let unrelated = HeldProviders::new(1);
    let mut lane =
        AttestedSemanticLane::start(unrelated.subset, &scene.scope, BackendSelection::Auto)
            .unwrap();
    lane.install_test_io(Box::new(scene.h0.clone()));
    scene.lane = Some(lane);
    scene.observe_entry();
    scene.pass();
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
    assert_eq!(scene.coordinator.registry().instances().count(), 0);
    assert!(
        coverage_gaps(&scene).is_empty(),
        "no attested successful registration"
    );
    assert_eq!(physical_snapshot(&scene), physical);
}

#[test]
fn initial_coverage_sibling_caller_use_does_not_disclose_this_callers_interval() {
    let mut scene = Box::new(AdmissionScene::new(Selection::Cgroup));
    let ready = scene.dir.path().join("sibling-ready");
    let provider = scene.dir.path().join("scoped-provider.so");
    let sibling = OwnedStoppedChild::spawn_stopped(
        std::process::Command::new(scene.dir.path().join("scoped-driver"))
            .arg("--ready")
            .arg(&ready)
            .arg("--call")
            .arg(&provider)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
        |pid| {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !ready.exists() {
                assert!(
                    Instant::now() < deadline,
                    "sibling driver did not finish exec"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            // SAFETY: this pid names only the retained owned sibling child.
            assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) }, 0);
        },
    );
    std::fs::write(
        scene.dir.path().join("cgroup.procs"),
        format!("{}\n{}\n", scene.child.id(), sibling.id()),
    )
    .unwrap();
    scene.prepare_without_cookie();
    let caller = scene.caller();
    let other = scene.coordinator.adapter().live_id(sibling.id()).unwrap();
    assert_ne!(caller, other);
    let module = provider_module(&scene);
    let endpoint = provider_endpoint(&scene, scene.lane.as_ref().unwrap().subset());
    stage_physical_use(&mut scene, sibling.id(), endpoint);
    scene.coordinator.commit_batch(false).unwrap();
    let physical = physical_snapshot(&scene);
    assert_eq!(physical.len(), 1);
    assert_eq!(
        (physical[0].0, physical[0].1, physical[0].2),
        (other, module, 7)
    );
    assert_eq!(
        scene
            .coordinator
            .registry()
            .edge(caller, module)
            .unwrap()
            .entry_count,
        0
    );
    // Admit the original caller alone under a fresh real membership sample.
    // The sibling stays alive: its positive evidence remains in this registry.
    std::fs::write(
        scene.dir.path().join("cgroup.procs"),
        format!("{}\n", scene.child.id()),
    )
    .unwrap();
    admit_fresh_pair(&mut scene);
    assert!(
        coverage_gaps(&scene).is_empty(),
        "other caller's use is no initial interval for this caller"
    );
    assert_eq!(physical_snapshot(&scene), physical);
}
