//! SPDX-License-Identifier: GPL-3.0-or-later
//! Driver-to-H0 admission regressions. Native map/query I/O is substituted;
//! catalog collection, process custody, held files, H0 and publication are real.
//! The fixture's attested offsets do not qualify native probes or cryptography.

use super::*;
use crate::discovery::engine::inventory_coordinator::{
    InventoryScope, tests::cgroup_provider_scene,
};
use crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild;
use crate::inventory_capture::CollectedPass;
use crate::inventory_semantics::LaneNegative;
use crate::scope::inventory_cgroup::{CgroupWalkLimits, CgroupWalkState, CollectionControl};

#[derive(Clone, Copy, Debug)]
enum Selection {
    Pid,
    System,
    Cgroup,
}

/// The production pass receives Inventory identity, never Detailed identity.
/// Equal numeric cookies in these two native objects are deliberately useless.
struct InventoryIdentity(NativeDomainId);

impl NativeIdentity<PidPin> for InventoryIdentity {
    fn owner_image(&mut self, _: u32) -> Option<ImageIdentity> {
        None
    }
    fn query_cookie(&mut self, domain: NativeDomainId, _: &PidPin) -> CookieQuery {
        if domain == self.0 {
            CookieQuery::Cookie(DomainCookie::scripted(domain, 7))
        } else {
            CookieQuery::Unavailable("another object's domain".into())
        }
    }
}

/// Only Session I/O is replaced. In particular the cookie is absent until
/// observe_entry, and H0 receives only the real driver's selected tick pins.
struct AdmissionIo {
    held: HeldIo,
    current: Option<ImageIdentity>,
    tick_pins: Vec<Arc<PidPin>>,
}

impl CaptureIo for AdmissionIo {
    fn domain(&self) -> Option<NativeDomainId> {
        self.held.domain()
    }
    fn now(&self) -> Instant {
        self.held.now()
    }
    fn collect(&mut self, limit: usize) -> Collection {
        self.held.collect(limit)
    }
    fn health(&mut self) -> Result<Health, ()> {
        self.held.health()
    }
    fn raise_fault(&mut self) -> Result<u64, ()> {
        self.held.raise_fault()
    }
    fn retained_attachment(
        &self,
        slot: u32,
    ) -> Result<RetainedInventoryTarget, CurrentReceiptRefusal> {
        self.held.retained_attachment(slot)
    }
    fn receipt_state(
        &mut self,
        pin: &Arc<PidPin>,
        image: ImageIdentity,
        endpoint: Endpoint,
        slot: u32,
        deadline: Instant,
    ) -> Result<ReceiptState, CurrentReceiptRefusal> {
        if self.current != Some(image) {
            return Err(CurrentReceiptRefusal::Epoch);
        }
        self.held
            .receipt_state(pin, image, endpoint, slot, deadline)
    }
    fn endpoint(&self, slot: u32) -> Option<Endpoint> {
        self.held.endpoint(slot)
    }
    fn target(&self, pid: u32) -> Option<Arc<PidPin>> {
        self.tick_pins.iter().find(|pin| pin.pid() == pid).cloned()
    }
    fn scan(
        &mut self,
        job: &ScanJob,
        deadline: Instant,
        fence: u64,
        current_fence: &dyn Fn() -> u64,
    ) -> Result<ImageScanProof, ImageQueryRefusal> {
        if self.current != Some(job.image) {
            return Err(ImageQueryRefusal::Unknown);
        }
        self.held.scan(job, deadline, fence, current_fence)
    }
    fn scan_selected(
        &mut self,
        pin: &Arc<PidPin>,
        endpoint: Endpoint,
        _: Instant,
        fence: u64,
        _: &dyn Fn() -> u64,
    ) -> Result<ImageScanProof, ImageQueryRefusal> {
        let image = self.current.ok_or(ImageQueryRefusal::Unknown)?;
        self.held.targets.insert(pin.pid(), (pin.clone(), image));
        self.held.scan_proof(image, endpoint, fence)
    }
}

type AfterAdmissionRefresh = Box<dyn FnOnce(&mut AdmissionH0)>;

struct AdmissionH0 {
    capture: SemanticCapture,
    io: AdmissionIo,
    stash: RefreshReceiptStash,
    accepted: usize,
    unknown: usize,
    validations: usize,
    fault_on_validation: bool,
    validation_negatives: usize,
    last_validation_refusal: Option<CurrentReceiptRefusal>,
    last_effective: Option<Arc<PidPin>>,
    after_refresh: Option<AfterAdmissionRefresh>,
}

#[derive(Clone)]
struct AdmissionLane(Rc<RefCell<AdmissionH0>>);

impl LaneTestIo for AdmissionLane {
    fn tick_targets(&mut self, pins: &[Arc<PidPin>]) {
        self.0.borrow_mut().io.tick_pins = pins.to_vec();
    }
    fn validate_attachment(&mut self, subset: &AttestedSubset) -> Result<(), SemanticRefusal> {
        let owned = self.0.borrow();
        for (object, slots) in subset.required() {
            for slot in slots {
                let expected = subset
                    .plan()
                    .slots
                    .iter()
                    .find(|candidate| candidate.index == *slot)
                    .ok_or(SemanticRefusal::Attachment)?;
                let endpoint = owned
                    .io
                    .endpoint(*slot)
                    .ok_or(SemanticRefusal::Attachment)?;
                let target = owned
                    .io
                    .retained_attachment(*slot)
                    .map_err(|_| SemanticRefusal::Attachment)?;
                if endpoint.object != *object
                    || endpoint.offset != expected.file_offset
                    || !target.same_object_as(subset.pins(), *object)
                    || target.check_unchanged() != Ok(true)
                {
                    return Err(SemanticRefusal::Attachment);
                }
            }
        }
        Ok(())
    }
    fn take_refresh_receipt(
        &mut self,
        pin: &Arc<PidPin>,
        slot: u32,
    ) -> Option<CurrentPartitionReceipt> {
        self.0.borrow_mut().stash.take_for_admission(pin, slot)
    }
    fn stash_admission_evidence(
        &mut self,
        receipts: Vec<CurrentPartitionReceipt>,
        outcomes: Vec<TickOutcome>,
    ) {
        assert_eq!(self.0.borrow_mut().stash.push_all(receipts, outcomes), 0);
    }
    fn physical_gaps(
        &mut self,
        domain: NativeDomainId,
        gaps: &mut Vec<PhysicalSemanticGap>,
    ) -> Option<Result<SemanticBatch, SemanticRefusal>> {
        let mut owned = self.0.borrow_mut();
        let AdmissionH0 { capture, io, .. } = &mut *owned;
        Some(
            capture
                .apply_physical_gaps_with(io, std::mem::take(gaps))
                .map_err(|_| SemanticRefusal::Unavailable)
                .and_then(|report| {
                    let negatives = report
                        .outcomes()
                        .iter()
                        .filter_map(|outcome| match outcome {
                            TickOutcome::Invalidation(invalidation)
                                if matches!(invalidation.scope(), InvalidationScope::FaultEra) =>
                            {
                                invalidation.position()
                            }
                            _ => None,
                        })
                        .max()
                        .map(|ordinal| vec![LaneNegative::CutBarrier { ordinal }])
                        .unwrap_or_default();
                    SemanticBatch::from_tick_report(domain, report, negatives, now_ns())
                }),
        )
    }
    fn validate_current(
        &mut self,
        receipt: &CurrentPartitionReceipt,
        report: &mut TickReport,
    ) -> Result<(), CurrentReceiptRefusal> {
        let mut owned = self.0.borrow_mut();
        owned.validations += 1;
        if std::mem::take(&mut owned.fault_on_validation) {
            let clean = owned.io.held.script.last_health;
            owned.io.held.script.health.extend([
                Ok(clean),
                Ok(Health {
                    fault: clean.fault + 1,
                    sticky: clean.sticky,
                }),
            ]);
        }
        let before = report.outcomes().len();
        let AdmissionH0 { capture, io, .. } = &mut *owned;
        let result = capture.validate_current_with(io, receipt, report);
        owned.last_validation_refusal = result.err();
        owned.validation_negatives += report.outcomes()[before..]
            .iter()
            .filter(|outcome| matches!(outcome, TickOutcome::Invalidation(_)))
            .count();
        result
    }
    fn tick(&mut self, domain: NativeDomainId) -> Result<SemanticBatch, SemanticRefusal> {
        let mut owned = self.0.borrow_mut();
        let AdmissionH0 {
            capture, io, stash, ..
        } = &mut *owned;
        let mut report = capture
            .tick_with(io)
            .map_err(|_| SemanticRefusal::Unavailable)?;
        assert_eq!(merge_stash_into_report(stash, &mut report), 0);
        SemanticBatch::from_tick_report(domain, report, Vec::new(), now_ns())
    }
    fn refresh(
        &mut self,
        pin: Arc<PidPin>,
        slot: u32,
    ) -> Result<(Vec<ImageIdentity>, Arc<PidPin>), SemanticRefusal> {
        let mut owned = self.0.borrow_mut();
        let AdmissionH0 { capture, io, .. } = &mut *owned;
        let mut report = capture
            .refresh_with(io, pin.clone(), slot)
            .map_err(|_| SemanticRefusal::Unavailable)?;
        owned.accepted += report.current().len();
        owned.unknown += report
            .scan_refusals
            .iter()
            .filter(|reason| matches!(reason, ImageQueryRefusal::Unknown))
            .count();
        let effective = effective_refresh_custody(&report, pin);
        if !report.current().is_empty() {
            owned.last_effective = Some(effective.clone());
        }
        let (images, shed) = stash_refresh_report(&mut owned.stash, &mut report);
        assert_eq!(shed, 0);
        if let Some(after) = owned.after_refresh.take() {
            after(&mut owned);
        }
        Ok((images, effective))
    }
    fn has_pending_evidence(&self) -> bool {
        !self.0.borrow().stash.is_empty()
    }
    fn finish(&mut self, domain: NativeDomainId) -> SemanticBatch {
        SemanticBatch::from_tick_report(
            domain,
            self.0.borrow_mut().capture.stop(),
            Vec::new(),
            now_ns(),
        )
        .unwrap()
    }
    fn quiescent(&mut self) -> bool {
        true
    }
    fn positions(&mut self) -> Option<[(usize, usize); 2]> {
        Some([(0, 0), (0, 0)])
    }
    fn drain_events_to(&mut self, _: usize, _: usize) -> LaneDrainOutcome {
        LaneDrainOutcome::default()
    }
    fn drain_discovery_to(&mut self, _: usize, _: usize) -> LaneDrainOutcome {
        LaneDrainOutcome::default()
    }
}

struct AdmissionScene {
    coordinator: InventoryCoordinator<OsProcessSource>,
    lane: Option<AttestedSemanticLane>,
    h0: AdmissionLane,
    identity: InventoryIdentity,
    scope: Scope,
    continuation: CgroupWalkState,
    control: CollectionControl,
    child: OwnedStoppedChild,
    dir: tempfile::TempDir,
    _attestations: tempfile::TempDir,
}

impl AdmissionScene {
    fn new(selection: Selection) -> Self {
        let (dir, child, cgroup) = cgroup_provider_scene();
        let provider = dir.path().join("scoped-provider.so");
        let scope = match selection {
            Selection::Pid => Scope::Pid(child.id()),
            Selection::System => Scope::System,
            Selection::Cgroup => crate::scope::cgroup(dir.path()).unwrap(),
        };
        let coordinator = match selection {
            Selection::Cgroup => cgroup,
            _ => InventoryCoordinator::new(
                scope.clone(),
                HookRegistry::builtin(),
                vec![provider.clone()],
                OsProcessSource,
                RegistryLimits::default_limits(),
            )
            .unwrap(),
        };
        let held = HeldProviders::from_paths(tempfile::tempdir().unwrap(), &[provider]);
        let mut lane =
            AttestedSemanticLane::start(held.subset, &scope, BackendSelection::Auto).unwrap();
        let domain = lane.domain();
        let h0 = AdmissionLane(Rc::new(RefCell::new(AdmissionH0 {
            capture: SemanticCapture::in_domain(domain, TickLimits::default()).unwrap(),
            io: AdmissionIo {
                held: HeldIo::new(domain, lane.subset()),
                current: None,
                tick_pins: Vec::new(),
            },
            stash: RefreshReceiptStash::new(),
            accepted: 0,
            unknown: 0,
            validations: 0,
            fault_on_validation: false,
            validation_negatives: 0,
            last_validation_refusal: None,
            last_effective: None,
            after_refresh: None,
        })));
        lane.install_test_io(Box::new(h0.clone()));
        Self {
            coordinator,
            lane: Some(lane),
            h0,
            identity: InventoryIdentity(NativeDomainId::mint()),
            scope,
            continuation: CgroupWalkState::default(),
            control: CollectionControl::new(None),
            child,
            dir,
            _attestations: held._dir,
        }
    }

    fn pass(&mut self) {
        let collected = self.collect();
        self.apply(collected);
    }

    fn collect(&mut self) -> CollectedPass {
        if matches!(self.scope, Scope::Cgroup { .. }) {
            let collection = self
                .coordinator
                .cgroup_collector(
                    std::mem::take(&mut self.continuation),
                    CgroupWalkLimits::default(),
                    self.control.clone(),
                    None,
                )
                .unwrap()();
            CollectedPass::Cgroup(Ok(Box::new(collection)))
        } else {
            // SYSTEM apply consumes a real controlled one-child catalog. This
            // tests its admission path without enumerating unrelated host PIDs.
            CollectedPass::Legacy(
                self.coordinator
                    .collector(InventoryScope::Pid(self.child.id()), None)()
                .map(Box::new),
            )
        }
    }

    fn apply(&mut self, collected: CollectedPass) {
        self.lane = Some(crate::inventory::classic_semantic_pass_for_test(
            &mut self.coordinator,
            self.lane.take().unwrap(),
            &self.scope,
            collected,
            &mut self.identity,
        ));
        if matches!(self.scope, Scope::Cgroup { .. }) {
            self.continuation = self.coordinator.take_cgroup_completion().unwrap().state;
        }
    }

    fn prepare_without_cookie(&mut self) {
        for _ in 0..3 {
            self.pass();
        }
        let caller = self.caller();
        assert_eq!(
            self.coordinator.adapter().record(caller).unwrap().authority,
            ImageAuthority::ScanPinned
        );
        assert!(self.coordinator.registry().edges_of(caller).any(|edge| edge.mapping == crate::discovery::caller_registry::MappingState::Mapped),
                "positive control: the real child actually maps the retained provider");
        let pin = self
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
        let module = self
            .coordinator
            .registry()
            .module_id_for(&module)
            .expect("the real catalog publishes the exact held physical provider");
        assert_eq!(
            self.coordinator
                .registry()
                .edge(caller, module)
                .unwrap()
                .mapping,
            crate::discovery::caller_registry::MappingState::Mapped
        );
        assert_eq!(self.coordinator.semantic_bindings().len(), 0);
        assert_eq!(self.coordinator.registry().instances().count(), 0);
        assert_eq!(self.h0.0.borrow().accepted, 0);
    }

    fn caller(&self) -> CallerId {
        self.coordinator.adapter().live_id(self.child.id()).unwrap()
    }
    fn pin(&self) -> Arc<PidPin> {
        Arc::new(
            self.coordinator
                .adapter()
                .live_pin(self.child.id())
                .unwrap()
                .1
                .try_clone()
                .unwrap(),
        )
    }
    fn observe_entry(&mut self) {
        // Substitute the native entry's Detailed TASK_COOKIE/full-image effect,
        // not an Inventory ticket or a coordinator semantic row.
        self.h0.0.borrow_mut().io.current = Some(image(7));
    }
    fn assert_admitted(&self) {
        let binding = self.coordinator.semantic_bindings().get(self.caller())
            .expect("the actual Detailed owner receipt must admit the mapped caller without a Detailed witness bridge");
        assert_eq!(binding.image(), image(7));
        assert_eq!(binding.domain(), self.lane.as_ref().unwrap().domain());
        assert!(Arc::ptr_eq(
            &binding.pin(),
            self.h0.0.borrow().last_effective.as_ref().unwrap()
        ));
        assert_eq!(self.coordinator.registry().instances().count(), 1);
    }
    fn refresh_direct(&mut self) -> (Vec<ImageIdentity>, Arc<PidPin>) {
        let slot = self.h0.0.borrow().io.held.slot(0, "C_SignInit");
        let pin = self.pin();
        self.lane
            .as_mut()
            .unwrap()
            .refresh_candidate_with_custody(pin, slot)
            .unwrap()
    }
}

#[test]
fn owner_admission_h0_fixture_requires_entry_and_mints_valid_original_receipt() {
    let mut scene = AdmissionScene::new(Selection::Pid);
    scene.prepare_without_cookie();
    assert!(scene.refresh_direct().0.is_empty());
    assert!(scene.h0.0.borrow().unknown > 0);
    scene.observe_entry();
    let (images, effective) = scene.refresh_direct();
    assert_eq!(images, vec![image(7)]);
    let mut owned = scene.h0.0.borrow_mut();
    let receipt = owned.stash.take().pop().unwrap();
    assert!(Arc::ptr_eq(receipt.original_pin(), &effective));
    let AdmissionH0 { capture, io, .. } = &mut *owned;
    capture
        .validate_current_with(io, &receipt, &mut TickReport::default())
        .unwrap();
    assert_eq!(
        scene.coordinator.semantic_bindings().len(),
        0,
        "calibration never pre-binds"
    );
}

#[test]
fn owner_admission_h0_failed_bind_retry_keeps_effective_arc() {
    let mut scene = AdmissionScene::new(Selection::Pid);
    scene.prepare_without_cookie();
    scene.observe_entry();
    let (first_images, first) = scene.refresh_direct();
    let (retry_images, retry) = scene.refresh_direct();
    assert_eq!(first_images, vec![image(7)]);
    assert_eq!(retry_images, vec![image(7)]);
    assert!(
        Arc::ptr_eq(&first, &retry),
        "a fresh duplicate must adopt H0's already-held Arc"
    );
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
}

#[test]
fn owner_admission_h0_physical_cut_control_is_calibrated() {
    let mut scene = AdmissionScene::new(Selection::Pid);
    scene.prepare_without_cookie();
    scene.observe_entry();
    let (_, effective) = scene.refresh_direct();
    let lane = scene.lane.as_mut().unwrap();
    let gap = PhysicalSemanticGap::test_episode(lane.domain(), image(7), effective);
    let batch = lane.apply_physical_gaps(vec![gap]).unwrap();
    assert!(batch.cut_barrier().is_some());
    assert_eq!(scene.h0.0.borrow().capture.continuity_cuts(), 1);
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
}

fn admission_positive(selection: Selection) {
    let mut scene = AdmissionScene::new(selection);
    scene.prepare_without_cookie();
    scene.observe_entry();
    let pid = scene.child.id();
    scene.h0.0.borrow_mut().after_refresh = Some(Box::new(move |owned| {
        // First real calls arrive while this same accepted owner receipt is
        // still awaiting the driver's first tick/publication.
        owned.io.held.enqueue(pid, 0, "C_SignInit", 0x000d, 0);
        owned.io.held.enqueue(pid, 0, "C_Sign", 0, 0);
    }));
    for _ in 0..3 {
        scene.pass();
    }
    scene.assert_admitted();
    assert_eq!(
        scene.h0.0.borrow().capture.continuity_cuts(),
        0,
        "healthy complete scope proof cannot manufacture a cut"
    );
    let rows: Vec<_> = scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .map(|row| {
            (
                row.api_returns,
                row.lossy,
                row.semantics.as_ref().map(|s| s.completed()).unwrap_or(0),
            )
        })
        .collect();
    assert_eq!(rows, vec![(Some(2), false, 1)]);
    assert!(
        scene
            .coordinator
            .registry()
            .edges_of(scene.caller())
            .all(|edge| edge.entry_count == 0),
        "semantic fixture events must not invent Inventory physical counts"
    );
    assert_eq!(
        scene
            .coordinator
            .adapter()
            .record(scene.caller())
            .unwrap()
            .authority,
        ImageAuthority::ScanPinned
    );
}

#[test]
fn owner_admission_pid_uses_detailed_owner_receipt() {
    admission_positive(Selection::Pid);
}
#[test]
fn owner_admission_system_uses_detailed_owner_receipt() {
    admission_positive(Selection::System);
}

#[test]
fn owner_admission_quiet_cached_returns_keep_historical_standing() {
    let mut scene = AdmissionScene::new(Selection::Pid);
    scene.prepare_without_cookie();
    scene.observe_entry();
    for _ in 0..3 {
        scene.pass();
    }
    scene.assert_admitted();
    let pid = scene.child.id();
    scene
        .h0
        .0
        .borrow_mut()
        .io
        .held
        .enqueue(pid, 0, "C_SignInit", 0x000d, 0);
    scene
        .h0
        .0
        .borrow_mut()
        .io
        .held
        .enqueue(pid, 0, "C_Sign", 0, 0);
    scene.pass();
    let row = scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .next()
        .unwrap();
    assert_eq!(row.api_returns, Some(2));
    assert!(row.lossy);
    assert_eq!(
        row.semantics
            .as_ref()
            .map_or(0, |reducer| reducer.completed()),
        0,
        "cached Joined calls without same-publication owner coverage stay historical"
    );
}
#[test]
fn owner_admission_cgroup_uses_current_member_permit() {
    admission_positive(Selection::Cgroup);
}

#[test]
fn owner_admission_failed_cgroup_admission_retry_retains_h0_arc() {
    let mut scene = AdmissionScene::new(Selection::Cgroup);
    scene.prepare_without_cookie();
    scene.observe_entry();
    let membership = scene.dir.path().join("cgroup.procs");
    scene.h0.0.borrow_mut().after_refresh =
        Some(Box::new(move |_| std::fs::write(membership, "").unwrap()));
    scene.pass();
    let first = scene
        .h0
        .0
        .borrow()
        .last_effective
        .clone()
        .expect("the in-scope preparation must run H0 before the final membership sample");
    assert_eq!(
        scene.coordinator.semantic_bindings().len(),
        0,
        "leaving after owner preparation refuses admission"
    );
    assert_eq!(scene.coordinator.registry().instances().count(), 0);
    std::fs::write(
        scene.dir.path().join("cgroup.procs"),
        format!("{}\n", scene.child.id()),
    )
    .unwrap();
    for _ in 0..3 {
        scene.pass();
    }
    scene.assert_admitted();
    assert!(Arc::ptr_eq(
        &first,
        &scene
            .coordinator
            .semantic_bindings()
            .get(scene.caller())
            .unwrap()
            .pin()
    ));
}

#[test]
fn owner_admission_cgroup_cancellation_after_refresh_refuses_publication() {
    let mut scene = AdmissionScene::new(Selection::Cgroup);
    scene.prepare_without_cookie();
    scene.observe_entry();
    let control = scene.control.clone();
    scene.h0.0.borrow_mut().after_refresh = Some(Box::new(move |_| control.cancel()));
    scene.pass();
    assert_eq!(
        scene.h0.0.borrow().accepted,
        1,
        "calibrated owner scan precedes cancellation"
    );
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
    assert_eq!(scene.coordinator.registry().instances().count(), 0);
}

#[derive(Clone, Copy, Debug)]
enum OwnerRefusal {
    Domain,
    Arc,
    Attachment,
    Image,
    Epoch,
    Expired,
}

fn install_owner_refusal(scene: &mut AdmissionScene, refusal: OwnerRefusal) -> HeldProviders {
    // Retain a genuinely different physical file even for the attachment
    // refusal; equal local coordinates never become an ownership substitute.
    let other = HeldProviders::new(1);
    let other_target = other
        .subset
        .pins()
        .retain_inventory_target(*other.subset.required().keys().next().unwrap())
        .unwrap();
    scene.h0.0.borrow_mut().after_refresh = Some(Box::new(move |owned| match refusal {
        OwnerRefusal::Domain => owned.io.held.script.domain = NativeDomainId::mint(),
        OwnerRefusal::Arc => {
            let binding = owned.capture.bindings.get_mut(&7).unwrap();
            binding.pin = Arc::new(binding.pin.try_clone().unwrap());
        }
        OwnerRefusal::Attachment => owned.io.held.watched[0] = other_target,
        OwnerRefusal::Image => {
            owned.io.current = Some(ImageIdentity {
                task_cookie: 7,
                exec_id: 2,
            })
        }
        OwnerRefusal::Epoch => owned.io.held.script.local += 1,
        OwnerRefusal::Expired => owned.io.held.script.now += Duration::from_secs(3),
    }));
    other
}

fn refuse_changed_owner_proof(refusal: OwnerRefusal) {
    let mut scene = AdmissionScene::new(Selection::Pid);
    scene.prepare_without_cookie();
    scene.observe_entry();
    let _other = install_owner_refusal(&mut scene, refusal);
    scene.pass();
    assert_eq!(
        scene.h0.0.borrow().accepted,
        1,
        "{refusal:?}: positive owner scan calibrated before refusal"
    );
    assert_eq!(
        scene.coordinator.semantic_bindings().len(),
        0,
        "{refusal:?}"
    );
    assert_eq!(
        scene.coordinator.registry().instances().count(),
        0,
        "{refusal:?}"
    );
    assert_eq!(
        scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .count(),
        0,
        "{refusal:?}"
    );
}

#[test]
fn owner_admission_h0_refusal_controls_are_calibrated() {
    for (refusal, expected) in [
        (OwnerRefusal::Domain, CurrentReceiptRefusal::Domain),
        (OwnerRefusal::Arc, CurrentReceiptRefusal::Custody),
        (OwnerRefusal::Attachment, CurrentReceiptRefusal::Attachment),
        (OwnerRefusal::Image, CurrentReceiptRefusal::Epoch),
        (OwnerRefusal::Epoch, CurrentReceiptRefusal::Epoch),
        (OwnerRefusal::Expired, CurrentReceiptRefusal::Deadline),
    ] {
        let mut scene = AdmissionScene::new(Selection::Pid);
        scene.prepare_without_cookie();
        scene.observe_entry();
        let _other = install_owner_refusal(&mut scene, refusal);
        assert_eq!(scene.refresh_direct().0, vec![image(7)]);
        let mut owned = scene.h0.0.borrow_mut();
        let receipt = owned.stash.take().pop().unwrap();
        let AdmissionH0 { capture, io, .. } = &mut *owned;
        assert_eq!(
            capture.validate_current_with(io, &receipt, &mut TickReport::default()),
            Err(expected),
            "{refusal:?}"
        );
    }
}

#[test]
fn owner_admission_refuses_foreign_domain() {
    refuse_changed_owner_proof(OwnerRefusal::Domain);
}
#[test]
fn owner_admission_refuses_reduplicated_arc() {
    refuse_changed_owner_proof(OwnerRefusal::Arc);
}
#[test]
fn owner_admission_refuses_replaced_attachment() {
    refuse_changed_owner_proof(OwnerRefusal::Attachment);
}
#[test]
fn owner_admission_refuses_changed_full_image() {
    refuse_changed_owner_proof(OwnerRefusal::Image);
}
#[test]
fn owner_admission_refuses_stale_epochs() {
    refuse_changed_owner_proof(OwnerRefusal::Epoch);
}
#[test]
fn owner_admission_refuses_expired_receipt() {
    refuse_changed_owner_proof(OwnerRefusal::Expired);
}

#[test]
fn owner_admission_first_publication_preserves_validation_gap() {
    let mut scene = AdmissionScene::new(Selection::Pid);
    scene.prepare_without_cookie();
    scene.observe_entry();
    scene.h0.0.borrow_mut().fault_on_validation = true;
    scene.pass();
    assert_eq!(scene.h0.0.borrow().accepted, 1);
    assert_eq!(
        scene.h0.0.borrow().validation_negatives,
        1,
        "the first accepted receipt encounters a real H0 fault-era invalidation"
    );
    assert_eq!(scene.coordinator.registry().instances().count(), 0);
    assert!(
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .any(|gap| gap.subject == "semantic receipt refused"),
        "a refused first publication must retain its finite negative disclosure"
    );
}

#[test]
fn owner_admission_cgroup_final_sample_cuts_old_operation_before_queued_return() {
    let mut scene = AdmissionScene::new(Selection::Cgroup);
    scene.prepare_without_cookie();
    scene.observe_entry();
    let pid = scene.child.id();
    scene.h0.0.borrow_mut().after_refresh = Some(Box::new(move |owned| {
        owned.io.held.enqueue(pid, 0, "C_SignInit", 0x000d, 0);
    }));
    for _ in 0..3 {
        scene.pass();
    }
    scene.assert_admitted();
    let row = scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .next()
        .unwrap();
    assert!(row.semantics.as_ref().unwrap().has_live_operations());
    assert_eq!(scene.h0.0.borrow().capture.continuity_cuts(), 0);

    // The eligible return is already resolved and staged before the real
    // collection's final membership sample rejects this formerly bound caller.
    assert_eq!(scene.refresh_direct().0, vec![image(7)]);
    scene
        .h0
        .0
        .borrow_mut()
        .io
        .held
        .enqueue(pid, 0, "C_Sign", 0, 0);
    let batch = scene
        .lane
        .as_mut()
        .unwrap()
        .tick(
            scene
                .coordinator
                .semantic_bindings_mut()
                .bindings_for_tick(),
        )
        .unwrap();
    scene.coordinator.stage_semantic_batch(batch);
    let collected = scene.collect();
    std::fs::write(scene.dir.path().join("cgroup.procs"), "").unwrap();
    scene.apply(collected);
    assert_eq!(
        scene.h0.0.borrow().capture.continuity_cuts(),
        1,
        "one failed scope publication must consume the physical-gap cut once"
    );
    let row = scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .next()
        .unwrap();
    assert!(row.lossy);
    let reducer = row.semantics.as_ref().unwrap();
    assert!(
        !reducer.has_live_operations(),
        "an owner-valid receipt cannot preserve an out-of-scope operation"
    );
    assert_eq!(
        reducer.completed(),
        0,
        "the queued pre-cut return cannot complete after scope refusal"
    );
    assert_eq!(reducer.unknown(), 1);

    // Owner-valid evidence outside the selected scope must remain unable to
    // register current coverage on a later tick, even without a collection.
    assert_eq!(scene.refresh_direct().0, vec![image(7)]);
    let batch = scene
        .lane
        .as_mut()
        .unwrap()
        .tick(
            scene
                .coordinator
                .semantic_bindings_mut()
                .bindings_for_tick(),
        )
        .unwrap();
    assert!(scene.h0.0.borrow().io.tick_pins.is_empty());
    scene.coordinator.stage_semantic_batch(batch);
    scene
        .coordinator
        .commit_batch_with_semantics(false, scene.lane.as_mut())
        .unwrap();
    assert!(
        !scene
            .coordinator
            .semantic_bindings()
            .get(scene.caller())
            .unwrap()
            .scope_current()
    );
    assert!(
        scene
            .coordinator
            .registry()
            .instances()
            .all(|instance| instance.state
                != crate::discovery::caller_registry::instance_input::InstanceLifecycle::Observed)
    );
    scene.pass();
    assert_eq!(
        scene.h0.0.borrow().capture.continuity_cuts(),
        1,
        "continued absence cannot mint another cut for the suspended episode"
    );

    let original = scene
        .coordinator
        .semantic_bindings()
        .get(scene.caller())
        .unwrap()
        .pin();
    std::fs::write(scene.dir.path().join("cgroup.procs"), format!("{pid}\n")).unwrap();
    scene.h0.0.borrow_mut().after_refresh = Some(Box::new(move |owned| {
        owned.io.held.enqueue(pid, 0, "C_SignInit", 0x000d, 0);
        owned.io.held.enqueue(pid, 0, "C_Sign", 0, 0);
    }));
    for _ in 0..3 {
        scene.pass();
    }
    let restored = scene
        .coordinator
        .semantic_bindings()
        .get(scene.caller())
        .unwrap();
    assert!(restored.scope_current());
    assert!(Arc::ptr_eq(&original, &restored.pin()));
    assert_eq!(scene.h0.0.borrow().capture.continuity_cuts(), 1);
    assert_eq!(
        scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .filter_map(|row| row.semantics.as_ref())
            .map(|reducer| reducer.completed())
            .sum::<u64>(),
        1,
        "only a fresh same-incarnation permit and owner receipt recover useful operations"
    );
}

#[test]
fn owner_admission_failed_scope_then_same_executable_new_image_refuses_old_caller() {
    let mut scene = AdmissionScene::new(Selection::Cgroup);
    scene.prepare_without_cookie();
    scene.observe_entry();
    let old = scene.caller();
    let membership = scene.dir.path().join("cgroup.procs");
    let path = membership.clone();
    scene.h0.0.borrow_mut().after_refresh = Some(Box::new(move |_| {
        std::fs::write(path, "").unwrap();
    }));
    scene.pass();
    assert_eq!(scene.h0.0.borrow().accepted, 1);
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
    std::fs::write(&membership, format!("{}\n", scene.child.id())).unwrap();
    // Same real executable and birth; only actual Detailed full-image I/O
    // reports the exec change. It must not overwrite the old incarnation.
    scene.h0.0.borrow_mut().io.current = Some(ImageIdentity {
        task_cookie: 7,
        exec_id: 2,
    });
    for _ in 0..3 {
        scene.pass();
    }
    assert_eq!(scene.caller(), old);
    assert_eq!(
        scene.coordinator.semantic_bindings().len(),
        0,
        "a later Detailed exec cannot attach to the old scan-pinned CallerId"
    );
    assert_eq!(scene.coordinator.registry().instances().count(), 0);
}

#[test]
fn owner_admission_rejected_validation_remembers_first_accepted_image() {
    let mut scene = AdmissionScene::new(Selection::Pid);
    scene.prepare_without_cookie();
    scene.observe_entry();
    let old = scene.caller();
    let _other = install_owner_refusal(&mut scene, OwnerRefusal::Image);
    scene.pass();
    assert_eq!(scene.h0.0.borrow().accepted, 1);
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
    assert_eq!(scene.coordinator.registry().instances().count(), 0);
    // H0 accepted exec 1 before owner validation observed exec 2. A later
    // successful refresh must not silently join exec 2 to the old CallerId.
    for _ in 0..3 {
        scene.pass();
    }
    assert_eq!(scene.caller(), old);
    assert_eq!(
        scene.coordinator.semantic_bindings().len(),
        0,
        "post-scan refusal must retain accepted full-image history"
    );
    assert_eq!(scene.coordinator.registry().instances().count(), 0);
}

#[test]
fn owner_admission_rejected_first_scope_cuts_unread_pre_refusal_calls() {
    let mut scene = AdmissionScene::new(Selection::Cgroup);
    scene.prepare_without_cookie();
    scene.observe_entry();
    let pid = scene.child.id();
    let unread = Rc::new(RefCell::new(None));
    let delayed = unread.clone();
    let membership = scene.dir.path().join("cgroup.procs");
    scene.h0.0.borrow_mut().after_refresh = Some(Box::new(move |owned| {
        // Actual return records from the accepted image remain unread by H0,
        // as a ring reader may deliver old records in a later quantum.
        owned.io.held.enqueue(pid, 0, "C_SignInit", 0x000d, 0);
        owned.io.held.enqueue(pid, 0, "C_Sign", 0, 0);
        *delayed.borrow_mut() = Some(std::mem::take(&mut owned.io.held.script.records));
        std::fs::write(membership, "").unwrap();
    }));
    scene.pass();
    assert_eq!(scene.h0.0.borrow().accepted, 1);
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
    assert_eq!(scene.coordinator.registry().instances().count(), 0);
    assert_eq!(unread.borrow().as_ref().unwrap().len(), 2);

    std::fs::write(scene.dir.path().join("cgroup.procs"), format!("{pid}\n")).unwrap();
    scene.h0.0.borrow_mut().after_refresh = Some(Box::new(move |owned| {
        // New owner coverage must not make the old fault-era pair current.
        owned.io.held.script.records = unread.borrow_mut().take().unwrap();
    }));
    for _ in 0..3 {
        scene.pass();
    }
    scene.assert_admitted();
    assert_eq!(
        scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .filter_map(|row| row.semantics.as_ref())
            .map(|reducer| reducer.completed())
            .sum::<u64>(),
        0,
        "a rejected first scope admission must fence unread old operations"
    );
    assert_eq!(scene.h0.0.borrow().capture.continuity_cuts(), 1);

    let original = scene
        .coordinator
        .semantic_bindings()
        .get(scene.caller())
        .unwrap()
        .pin();
    assert_eq!(scene.refresh_direct().0, vec![image(7)]);
    {
        let mut owned = scene.h0.0.borrow_mut();
        assert_eq!(owned.io.held.script.last_health.fault, 1);
        owned.io.held.enqueue(pid, 0, "C_SignInit", 0x000d, 0);
        owned.io.held.enqueue(pid, 0, "C_Sign", 0, 0);
    }
    scene.pass();
    assert!(Arc::ptr_eq(
        &original,
        &scene
            .coordinator
            .semantic_bindings()
            .get(scene.caller())
            .unwrap()
            .pin()
    ));
    assert_eq!(scene.h0.0.borrow().capture.continuity_cuts(), 1);
    assert_eq!(
        scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .filter_map(|row| row.semantics.as_ref())
            .map(|reducer| reducer.completed())
            .sum::<u64>(),
        1,
        "a real fresh receipt and fault-1 pair recover useful same-custody work"
    );
}

#[test]
fn owner_admission_fresh_scope_after_expiry_separates_loss_episodes() {
    let mut scene = AdmissionScene::new(Selection::Cgroup);
    scene.prepare_without_cookie();
    scene.observe_entry();
    let pid = scene.child.id();
    let membership = scene.dir.path().join("cgroup.procs");
    let leave = membership.clone();
    scene.h0.0.borrow_mut().after_refresh =
        Some(Box::new(move |_| std::fs::write(leave, "").unwrap()));
    scene.pass();
    assert_eq!(scene.h0.0.borrow().accepted, 1);
    assert_eq!(scene.h0.0.borrow().capture.continuity_cuts(), 1);
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
    let original = scene.h0.0.borrow().last_effective.clone().unwrap();
    for _ in 0..2 {
        scene.pass();
    }
    assert_eq!(scene.h0.0.borrow().capture.continuity_cuts(), 1);
    assert_eq!(scene.h0.0.borrow().accepted, 1);

    std::fs::write(&membership, format!("{pid}\n")).unwrap();
    scene.h0.0.borrow_mut().after_refresh = Some(Box::new(|owned| {
        // Time advances only forward. Expiry refuses this receipt without
        // ending H0; a later actual refresh has its own newly minted deadline.
        owned.io.held.script.now += Duration::from_secs(3);
    }));
    for _ in 0..3 {
        scene.pass();
        if scene.h0.0.borrow().accepted > 1 {
            break;
        }
    }
    assert_eq!(scene.h0.0.borrow().accepted, 2);
    assert_eq!(
        scene.h0.0.borrow().last_validation_refusal,
        Some(CurrentReceiptRefusal::Deadline)
    );
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
    assert_eq!(scene.coordinator.registry().instances().count(), 0);
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "semantic admission refused"
                && gap.reason == "provider_instance_unproven"
        }),
        "owner refusal is reached only after the exact scope/custody guard passed"
    );
    assert_eq!(scene.h0.0.borrow().capture.continuity_cuts(), 1);
    assert!(Arc::ptr_eq(
        &original,
        scene.h0.0.borrow().last_effective.as_ref().unwrap()
    ));

    let unread = Rc::new(RefCell::new(None));
    let delayed = unread.clone();
    let leave = membership.clone();
    scene.h0.0.borrow_mut().after_refresh = Some(Box::new(move |owned| {
        assert_eq!(owned.io.held.script.last_health.fault, 1);
        owned.io.held.enqueue(pid, 0, "C_SignInit", 0x000d, 0);
        owned.io.held.enqueue(pid, 0, "C_Sign", 0, 0);
        *delayed.borrow_mut() = Some(std::mem::take(&mut owned.io.held.script.records));
        std::fs::write(leave, "").unwrap();
    }));
    scene.pass();
    assert_eq!(scene.h0.0.borrow().accepted, 3);
    assert_eq!(scene.coordinator.semantic_bindings().len(), 0);
    assert_eq!(unread.borrow().as_ref().unwrap().len(), 2);
    let after_second_loss = scene.h0.0.borrow().capture.continuity_cuts();
    for _ in 0..2 {
        scene.pass();
    }
    assert_eq!(
        scene.h0.0.borrow().capture.continuity_cuts(),
        after_second_loss,
        "repeated absence must not invent another loss episode"
    );

    std::fs::write(&membership, format!("{pid}\n")).unwrap();
    scene.h0.0.borrow_mut().after_refresh = Some(Box::new(move |owned| {
        owned.io.held.script.records = unread.borrow_mut().take().unwrap();
    }));
    for _ in 0..3 {
        scene.pass();
    }
    scene.assert_admitted();
    assert_eq!(
        scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .filter_map(|row| row.semantics.as_ref())
            .map(|reducer| reducer.completed())
            .sum::<u64>(),
        0,
        "the second genuine scope loss must fence unchanged unread fault-1 calls"
    );
    assert_eq!(scene.h0.0.borrow().capture.continuity_cuts(), 2);

    assert_eq!(scene.refresh_direct().0, vec![image(7)]);
    {
        let mut owned = scene.h0.0.borrow_mut();
        assert_eq!(owned.io.held.script.last_health.fault, 2);
        owned.io.held.enqueue(pid, 0, "C_SignInit", 0x000d, 0);
        owned.io.held.enqueue(pid, 0, "C_Sign", 0, 0);
    }
    scene.pass();
    assert_eq!(
        scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .filter_map(|row| row.semantics.as_ref())
            .map(|reducer| reducer.completed())
            .sum::<u64>(),
        1,
        "a fresh real fault-2 receipt recovers useful work"
    );
    assert!(Arc::ptr_eq(
        &original,
        &scene
            .coordinator
            .semantic_bindings()
            .get(scene.caller())
            .unwrap()
            .pin()
    ));
    assert_eq!(scene.h0.0.borrow().capture.continuity_cuts(), 2);
}
