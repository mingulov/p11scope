//! SPDX-License-Identifier: GPL-3.0-or-later
//! Real attested held files and H0 decisions through substituted map I/O.
//! These tests establish source behavior, not native attachment qualification.

use super::*;
use crate::discovery::caller_registry::instance_input::{InstanceLifecycle, InstanceReason};
use crate::discovery::engine::inventory_coordinator::semantics::{
    AttestedSubset, engine_for_test, prepare_attested_subset,
};
use crate::discovery::identity::PinnedObjects;
use p11scope_ebpf_common::capture;
use p11scope_manifest::identity::{inspect_file, mapping_file_key, open_object};
use p11scope_manifest::manifest::*;
use std::cell::RefCell;
use std::rc::Rc;

struct HeldProviders {
    _dir: tempfile::TempDir,
    subset: AttestedSubset,
}

impl HeldProviders {
    fn new(count: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut paths = Vec::new();
        for index in 0..count {
            let path = dir.path().join(format!("provider-{index}.so"));
            std::fs::copy("/usr/bin/true", &path).unwrap();
            let file = open_object(&path).unwrap();
            let inspected = inspect_file(&file).unwrap();
            let mapping = mapping_file_key(&file).unwrap();
            let executable = inspected
                .executable_ranges
                .iter()
                .find(|(start, end)| end - start > 0x300)
                .unwrap();
            let offsets = [executable.0 + 0x100, executable.0 + 0x200];
            let functions =
                match pkcs11_module::tables_for(pkcs11_module::Surface::LegacyFunctionList {
                    version: cryptoki_sys::CK_VERSION {
                        major: 2,
                        minor: 40,
                    },
                }) {
                    pkcs11_module::TableSet::Walk(spans) => spans
                        .iter()
                        .flat_map(|span| span.fields())
                        .map(|field| FunctionRecord {
                            name: field.name.into(),
                            resolution: match field.name {
                                "C_SignInit" => Resolution::Resolved {
                                    object: 0,
                                    file_offset: offsets[0],
                                },
                                "C_Sign" => Resolution::Resolved {
                                    object: 0,
                                    file_offset: offsets[1],
                                },
                                _ => Resolution::NullPointer,
                            },
                        })
                        .collect(),
                    _ => panic!("the complete standard 2.40 surface is required"),
                };
            let path = path.to_str().unwrap().to_owned();
            let manifest = Manifest {
                schema: SCHEMA.into(),
                module_path: path.clone(),
                objects: vec![ObjectRecord {
                    id: 0,
                    path: path.clone(),
                    identity: inspected.identity.clone(),
                }],
                provenance_objects: vec![ProvenanceObject {
                    path,
                    device_major: mapping.device_major,
                    device_minor: mapping.device_minor,
                    inode: mapping.inode,
                    identity: inspected.identity,
                }],
                interface_list: Acquisition::Absent,
                surfaces: vec![SurfaceRecord {
                    source: SurfaceSource::LegacyFunctionList,
                    acquisition: Acquisition::Ok,
                    version: Some(Version {
                        major: 2,
                        minor: 40,
                    }),
                    walk: WalkOutcome::Full,
                    functions,
                }],
                vendor_interfaces: Vec::new(),
                alias_groups: Vec::new(),
                selection_evidence: Default::default(),
            };
            assert!(crate::manifest_input::validate_structure(&manifest).is_empty());
            let input = dir.path().join(format!("attestation-{index}.json"));
            std::fs::write(&input, serde_json::to_vec(&manifest).unwrap()).unwrap();
            paths.push(input);
        }
        let engine = engine_for_test(Vec::new(), Vec::new(), PinnedObjects::empty());
        let prepared = prepare_attested_subset(&engine, &paths);
        assert!(prepared.refusals.is_empty(), "{:?}", prepared.refusals);
        let subset = prepared
            .subset
            .expect("complete explicit provider attestations");
        assert_eq!(subset.required().len(), count);
        assert_eq!(subset.plan().slots.len(), count * 2);
        Self { _dir: dir, subset }
    }
}

/// The same substituted map I/O as the existing H0 tests, with endpoint
/// offsets and held attachment files taken from the real attested subset.
struct HeldIo {
    script: ScriptIo,
    endpoints: Vec<(u32, String, Endpoint)>,
    watched: Vec<RetainedInventoryTarget>,
    targets: HashMap<u32, (Arc<PidPin>, ImageIdentity)>,
}

impl HeldIo {
    fn new(domain: NativeDomainId, subset: &AttestedSubset) -> Self {
        let providers: Vec<_> = subset.required().keys().copied().collect();
        let watched = providers
            .iter()
            .map(|object| subset.pins().retain_inventory_target(*object).unwrap())
            .collect();
        let endpoints = subset
            .plan()
            .slots
            .iter()
            .map(|slot| {
                let file_slot = providers.iter().position(|id| *id == slot.object).unwrap() as u32;
                (
                    slot.index,
                    slot.names[0].clone(),
                    Endpoint {
                        object: slot.object,
                        file_slot,
                        offset: slot.file_offset,
                    },
                )
            })
            .collect();
        Self {
            script: ScriptIo::new(domain),
            endpoints,
            watched,
            targets: HashMap::new(),
        }
    }

    fn slot(&self, file: u32, name: &str) -> u32 {
        self.endpoints
            .iter()
            .find(|(_, candidate, endpoint)| candidate == name && endpoint.file_slot == file)
            .unwrap()
            .0
    }

    fn enqueue(&mut self, pid: u32, file: u32, name: &str, mechanism: u64, rv: u64) {
        let image = self.targets[&pid].1;
        let slot = self.slot(file, name);
        let endpoint = self.endpoint(slot).unwrap();
        let fault = u32::try_from(self.script.last_health.fault).unwrap();
        self.script.call(image.task_cookie, fault);
        let ts_ns = 10 + self.script.records.len() as u64;
        let record = self.script.records.back_mut().unwrap();
        record.event.image = image;
        record.event.pid_tgid = u64::from(pid) << 32;
        record.event.slot = slot;
        record.event.session = 7;
        record.event.mechanism = mechanism;
        record.event.rv = rv;
        record.event.capture = capture::OUTPUT_NON_NULL
            | if name == "C_SignInit" {
                capture::MECHANISM_VALUE
            } else {
                capture::MECHANISM_NONE
            };
        record.event.ts_ns = ts_ns;
        record.continuity.entry_stamp.file_slot_plus1 = (file + 1) as u16;
        record.continuity.return_stamp.file_slot_plus1 = (file + 1) as u16;
        record.continuity.entry_ip = 0x1000_0000 + u64::from(file) * 0x100_0000 + endpoint.offset;
    }

    fn scan_proof(
        &mut self,
        image: ImageIdentity,
        endpoint: Endpoint,
        fence: u64,
    ) -> Result<ImageScanProof, ImageQueryRefusal> {
        let page = endpoint.offset & !0xfff;
        let base = 0x1000_0000 + u64::from(endpoint.file_slot) * 0x100_0000;
        acquire_test_scan(
            self.script.domain,
            image,
            endpoint.file_slot,
            CompleteEpochs {
                local: u64::from(self.script.local),
                global: 0,
                fault: self.script.last_health.fault,
                sticky: self.script.last_health.sticky,
                record_flags: 0,
            },
            vec![
                MapRange::new(base, base + page, 0, false),
                MapRange::new(base + page, base + page + 0x1000, page, true),
            ],
            fence,
        )
    }
}

impl CaptureIo for HeldIo {
    fn domain(&self) -> Option<NativeDomainId> {
        self.script.domain()
    }
    fn now(&self) -> Instant {
        self.script.now()
    }
    fn collect(&mut self, limit: usize) -> Collection {
        self.script.collect(limit)
    }
    fn health(&mut self) -> Result<Health, ()> {
        self.script.health()
    }
    fn raise_fault(&mut self) -> Result<u64, ()> {
        self.script.raise_fault()
    }
    fn retained_attachment(
        &self,
        slot: u32,
    ) -> Result<RetainedInventoryTarget, CurrentReceiptRefusal> {
        let endpoint = self
            .endpoint(slot)
            .ok_or(CurrentReceiptRefusal::Attachment)?;
        Ok(self.watched[endpoint.file_slot as usize].share())
    }
    fn receipt_state(
        &mut self,
        pin: &Arc<PidPin>,
        _: ImageIdentity,
        endpoint: Endpoint,
        _: u32,
        _: Instant,
    ) -> Result<ReceiptState, CurrentReceiptRefusal> {
        if let Some(refusal) = self.script.receipt_refusal {
            return Err(refusal);
        }
        Ok(ReceiptState {
            image: self.targets[&pin.pid()].1,
            epochs: CompleteEpochs {
                local: u64::from(self.script.local),
                global: 0,
                fault: self.script.last_health.fault,
                sticky: self.script.last_health.sticky,
                record_flags: 0,
            },
            watched: self.watched[endpoint.file_slot as usize].share(),
        })
    }
    fn endpoint(&self, slot: u32) -> Option<Endpoint> {
        self.endpoints
            .iter()
            .find(|(index, _, _)| *index == slot)
            .map(|(_, _, endpoint)| *endpoint)
    }
    fn target(&self, pid: u32) -> Option<Arc<PidPin>> {
        self.targets.get(&pid).map(|(pin, _)| pin.clone())
    }
    fn scan(
        &mut self,
        job: &ScanJob,
        _: Instant,
        fence: u64,
        _: &dyn Fn() -> u64,
    ) -> Result<ImageScanProof, ImageQueryRefusal> {
        self.scan_proof(job.image, job.endpoint, fence)
    }
    fn scan_selected(
        &mut self,
        pin: &Arc<PidPin>,
        endpoint: Endpoint,
        _: Instant,
        fence: u64,
        _: &dyn Fn() -> u64,
    ) -> Result<ImageScanProof, ImageQueryRefusal> {
        self.scan_proof(self.targets[&pin.pid()].1, endpoint, fence)
    }
}

#[derive(Clone, Copy, Debug)]
enum ValidationFailure {
    Fault,
    Sticky,
    NativeRead,
}

struct HeldH0 {
    capture: SemanticCapture,
    io: HeldIo,
    stash: RefreshReceiptStash,
    validations: usize,
    inject: Option<(usize, ValidationFailure)>,
    validation_negatives: Vec<(&'static str, Option<u64>)>,
    last_terminal_tasks: Vec<(u64, u64)>,
    last_calls: Vec<(ImageIdentity, u64)>,
}

#[derive(Clone)]
struct SharedH0(Rc<RefCell<HeldH0>>);

impl LaneTestIo for SharedH0 {
    fn validate_current(
        &mut self,
        receipt: &CurrentPartitionReceipt,
        report: &mut TickReport,
    ) -> Result<(), CurrentReceiptRefusal> {
        let mut owned = self.0.borrow_mut();
        owned.validations += 1;
        let injection = owned.inject.filter(|(at, _)| *at == owned.validations);
        if let Some((_, failure)) = injection {
            owned.inject = None;
            let clean = owned.io.script.last_health;
            let after = match failure {
                ValidationFailure::Fault => Health {
                    fault: clean.fault + 1,
                    sticky: clean.sticky,
                },
                ValidationFailure::Sticky => Health {
                    fault: clean.fault,
                    sticky: 1,
                },
                ValidationFailure::NativeRead => {
                    owned.io.script.receipt_refusal = Some(CurrentReceiptRefusal::Audit);
                    clean
                }
            };
            owned.io.script.health.extend([Ok(clean), Ok(after)]);
        }
        let start = report.outcomes().len();
        let HeldH0 { capture, io, .. } = &mut *owned;
        let result = capture.validate_current_with(io, receipt, report);
        owned.io.script.receipt_refusal = None;
        for outcome in &report.outcomes()[start..] {
            if let TickOutcome::Invalidation(invalidation) = outcome {
                let name = match invalidation.scope() {
                    InvalidationScope::FaultEra => "fault_era",
                    InvalidationScope::CoverageFailed => "coverage_failed",
                    _ => "other",
                };
                owned
                    .validation_negatives
                    .push((name, invalidation.position()));
            }
        }
        result
    }
    fn tick(&mut self, domain: NativeDomainId) -> Result<SemanticBatch, SemanticRefusal> {
        let mut owned = self.0.borrow_mut();
        let HeldH0 {
            capture, io, stash, ..
        } = &mut *owned;
        let mut report = capture
            .tick_with(io)
            .map_err(|_| SemanticRefusal::Unavailable)?;
        assert_eq!(merge_stash_into_report(stash, &mut report), 0);
        owned.last_terminal_tasks = report
            .outcomes()
            .iter()
            .filter_map(|outcome| {
                let TickOutcome::Invalidation(invalidation) = outcome else {
                    return None;
                };
                let InvalidationScope::TaskRetired(cookie) = invalidation.scope() else {
                    return None;
                };
                Some((*cookie, invalidation.position().unwrap()))
            })
            .collect();
        owned.last_calls = report
            .calls()
            .filter_map(|call| Some((call.image(), call.position()?)))
            .collect();
        SemanticBatch::from_tick_report(domain, report, Vec::new(), now_ns())
    }
    fn refresh(
        &mut self,
        pin: Arc<PidPin>,
        slot: u32,
    ) -> Result<(Vec<ImageIdentity>, Arc<PidPin>), SemanticRefusal> {
        let mut owned = self.0.borrow_mut();
        let HeldH0 {
            capture, io, stash, ..
        } = &mut *owned;
        let mut report = capture
            .refresh_with(io, pin.clone(), slot)
            .map_err(|_| SemanticRefusal::Unavailable)?;
        let effective = effective_refresh_custody(&report, pin);
        let (images, shed) = stash_refresh_report(stash, &mut report);
        assert_eq!(shed, 0);
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

struct RealScene {
    scene: CustodyScene,
    lane: AttestedSemanticLane,
    h0: SharedH0,
    modules: Vec<(ModuleKey, String)>,
    _dir: tempfile::TempDir,
}

impl RealScene {
    fn new(providers: usize) -> Self {
        let held = HeldProviders::new(providers);
        let lane = AttestedSemanticLane::start(held.subset, &Scope::System, BackendSelection::Auto)
            .unwrap();
        let domain = lane.domain();
        let io = HeldIo::new(domain, lane.subset());
        let modules = lane
            .subset()
            .required()
            .keys()
            .map(|id| {
                let pin = lane
                    .subset()
                    .pins()
                    .pinned()
                    .find(|pin| pin.id == *id)
                    .unwrap();
                (
                    ModuleKey::physical(
                        pin.key.device.major,
                        pin.key.device.minor,
                        pin.key.inode,
                        Some(pin.sha256.to_owned()),
                        pin.path,
                    ),
                    pin.path.to_owned(),
                )
            })
            .collect();
        let mut scene = CustodyScene::new();
        scene.coordinator = InventoryCoordinator::new(
            Scope::System,
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        scene.coordinator.set_semantic_binding_clock(sight_clock);
        scene.coordinator.note_extend_receipt(&ExtendReceipt {
            activated_roots: true,
            exec_coverage: Some(ExecCoverage::scripted(domain, 0)),
            ..ExtendReceipt::default()
        });
        let h0 = SharedH0(Rc::new(RefCell::new(HeldH0 {
            capture: SemanticCapture::in_domain(domain, TickLimits::default()).unwrap(),
            io,
            stash: RefreshReceiptStash::new(),
            validations: 0,
            inject: None,
            validation_negatives: Vec::new(),
            last_terminal_tasks: Vec::new(),
            last_calls: Vec::new(),
        })));
        let mut scene = Self {
            scene,
            lane,
            h0,
            modules,
            _dir: held._dir,
        };
        scene.lane.install_test_io(Box::new(scene.h0.clone()));
        scene
    }

    fn bind(&mut self, pid: u32, image: ImageIdentity, provider: usize) -> CallerId {
        SIGHT_NS.with(|clock| clock.set(1_005));
        let caller = self.scene.admit(pid, 50);
        for (key, path) in &self.modules {
            self.scene.coordinator.registry_mut().note_mapping(
                caller,
                pid,
                ModuleInfo {
                    path: path.clone(),
                    key: key.clone(),
                    double_loaded: false,
                    build_id: None,
                    identity_source: Some("held-provider".into()),
                    admission: AdmissionState::Admitted,
                    admission_class: Some("exact".into()),
                    admission_endpoints: Some(2),
                    admission_reasons: Vec::new(),
                },
                60,
            );
        }
        self.scene.coordinator.commit_batch(false).unwrap();
        let domain = self.lane.domain();
        self.scene.answer(pid, domain, image.task_cookie);
        self.scene.bind_image(
            domain,
            vec![(image.task_cookie, image.exec_id, pid, 100)],
            1_000,
        );
        let pin = Arc::new(
            self.scene
                .coordinator
                .adapter()
                .live_pin(pid)
                .unwrap()
                .1
                .try_clone()
                .unwrap(),
        );
        self.scene
            .coordinator
            .bind_semantic_caller_with_pin(
                caller,
                self.modules[provider].0.clone(),
                domain,
                image,
                &mut self.scene.identity,
                pin.clone(),
            )
            .unwrap();
        self.h0.0.borrow_mut().io.targets.insert(pid, (pin, image));
        caller
    }

    fn refresh(&mut self, caller: CallerId, file: u32) {
        let pin = self
            .scene
            .coordinator
            .semantic_bindings()
            .get(caller)
            .unwrap()
            .pin();
        let slot = self.h0.0.borrow().io.slot(file, "C_SignInit");
        let (images, _) = self.lane.refresh_candidate_with_custody(pin, slot).unwrap();
        assert_eq!(
            images.len(),
            1,
            "a real accepted H0 scan must mint the receipt"
        );
    }

    fn enqueue(&mut self, pid: u32, file: u32, name: &str, mechanism: u64, rv: u64) {
        self.h0
            .0
            .borrow_mut()
            .io
            .enqueue(pid, file, name, mechanism, rv);
    }

    fn tick(&mut self) -> SemanticBatch {
        let bindings = self
            .scene
            .coordinator
            .semantic_bindings_mut()
            .bindings_for_tick();
        self.lane.tick(bindings).unwrap()
    }

    fn publish(&mut self, batch: SemanticBatch) {
        self.scene.coordinator.stage_semantic_batch(batch);
        self.scene
            .coordinator
            .commit_batch_with_semantics(false, Some(&mut self.lane))
            .unwrap();
    }

    fn inject_validation(&mut self, receipt_number: usize, failure: ValidationFailure) {
        let mut h0 = self.h0.0.borrow_mut();
        h0.inject = Some((h0.validations + receipt_number, failure));
    }
}

fn image(cookie: u64) -> ImageIdentity {
    ImageIdentity {
        task_cookie: cookie,
        exec_id: 1,
    }
}

#[test]
fn semantic_validation_single_held_provider_completes() {
    let mut fixture = RealScene::new(1);
    let pid = std::process::id();
    fixture.bind(pid, image(7), 0);
    fixture.enqueue(pid, 0, "C_SignInit", 0x000d, 0);
    fixture.enqueue(pid, 0, "C_Sign", 0, 0);
    let batch = fixture.tick();
    fixture.publish(batch);
    assert_eq!(
        operation_edge_rows(&fixture.scene),
        vec![(Some(2), 0, false, 1, 1)]
    );
}

#[test]
fn semantic_validation_two_held_providers_never_attribute_b_to_a() {
    let mut fixture = RealScene::new(2);
    assert_ne!(
        fixture.modules[0].0, fixture.modules[1].0,
        "equal-content copies have distinct physical keys"
    );
    let pid = std::process::id();
    fixture.bind(pid, image(7), 0);
    fixture.enqueue(pid, 0, "C_SignInit", 0x000d, 0);
    fixture.enqueue(pid, 0, "C_Sign", 0, 0);
    fixture.enqueue(pid, 1, "C_SignInit", 0x0001, 0);
    fixture.enqueue(pid, 1, "C_Sign", 0, 0x21);
    let batch = fixture.tick();
    // Both physical files have independently accepted, held H0 receipts.
    assert_eq!(fixture.h0.0.borrow().capture.router.instances_minted(), 2);
    fixture.publish(batch);
    let module_a = fixture
        .scene
        .coordinator
        .registry()
        .module_id_for(&fixture.modules[0].0)
        .unwrap();
    let rows_a: Vec<_> = fixture
        .scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .filter(|row| row.module == module_a)
        .collect();
    assert_eq!(
        rows_a
            .iter()
            .map(|row| row.api_returns.unwrap_or(0))
            .sum::<u64>(),
        2,
        "provider B's returns must never be labeled with provider A's physical module"
    );
    assert!(
        rows_a.iter().all(|row| row
            .semantics
            .as_ref()
            .is_none_or(|s| !s.mechanisms().contains_key(&0x0001))),
        "provider B's distinct mechanism must never be attributed to A"
    );
}

fn validation_loss_case(failure: ValidationFailure) {
    let mut fixture = RealScene::new(1);
    let pid = std::process::id();
    let caller = fixture.bind(pid, image(7), 0);
    fixture.enqueue(pid, 0, "C_SignInit", 0x000d, 0);
    let batch = fixture.tick();
    fixture.publish(batch);
    assert_eq!(
        operation_edge_rows(&fixture.scene),
        vec![(Some(1), 0, false, 1, 0)]
    );
    assert!(
        fixture
            .scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .next()
            .unwrap()
            .semantics
            .as_ref()
            .unwrap()
            .has_live_operations()
    );
    fixture.refresh(caller, 0);
    fixture.enqueue(pid, 0, "C_Sign", 0, 0);
    let batch = fixture.tick();
    fixture.inject_validation(1, failure);
    fixture.publish(batch);
    assert_eq!(
        fixture.h0.0.borrow().validation_negatives.len(),
        1,
        "the actual H0 receipt validator emitted the loss fact during validation"
    );
    let edge = fixture
        .scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .next()
        .unwrap();
    assert!(
        edge.lossy,
        "{failure:?}: validation loss must publish in this same commit"
    );
    assert!(edge.reasons.contains(&InstanceReason::SemanticLoss));
    let reducer = edge.semantics.as_ref().unwrap();
    assert_eq!(
        reducer.unknown(),
        1,
        "the previously published operation ends unknown immediately"
    );
    assert!(!reducer.has_live_operations());
    assert_eq!(edge.api_returns, Some(2));
    assert_eq!(edge.historical_only_returns, 1);
    assert_eq!(reducer.completed(), 0);
}

#[test]
fn semantic_validation_fault_loss_publishes_before_next_tick() {
    validation_loss_case(ValidationFailure::Fault);
}

#[test]
fn semantic_validation_sticky_loss_publishes_before_next_tick() {
    validation_loss_case(ValidationFailure::Sticky);
}

#[test]
fn semantic_validation_native_read_loss_publishes_before_next_tick() {
    validation_loss_case(ValidationFailure::NativeRead);
}

#[test]
fn semantic_validation_later_receipt_fault_fences_earlier_same_batch_coverage() {
    let mut fixture = RealScene::new(2);
    let pid = std::process::id();
    let caller = fixture.bind(pid, image(7), 0);
    fixture.enqueue(pid, 0, "C_SignInit", 0x000d, 0);
    let batch = fixture.tick();
    fixture.publish(batch);
    fixture.refresh(caller, 0);
    fixture.refresh(caller, 1);
    fixture.enqueue(pid, 0, "C_Sign", 0, 0);
    let batch = fixture.tick();
    fixture.inject_validation(2, ValidationFailure::Fault);
    fixture.publish(batch);
    assert_eq!(fixture.h0.0.borrow().validation_negatives.len(), 1);
    let first = fixture
        .scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .next()
        .unwrap();
    let reducer = first.semantics.as_ref().unwrap();
    assert_eq!(
        reducer.completed(),
        0,
        "a receipt validated earlier in the batch cannot complete across the later H0 fault"
    );
    assert_eq!(reducer.unknown(), 1);
    assert!(first.lossy);
    assert_eq!(first.historical_only_returns, 1);
}

#[test]
fn semantic_validation_full_batch_preserves_calls_and_distinct_validation_loss() {
    use crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild;
    let child = OwnedStoppedChild::new();
    let pid_b = child.id();
    let pid_a = std::process::id();
    let mut fixture = RealScene::new(1);
    let caller_a = fixture.bind(pid_a, image(7), 0);
    let caller_b = fixture.bind(pid_b, image(8), 0);
    fixture.enqueue(pid_a, 0, "C_SignInit", 0x000d, 0);
    fixture.enqueue(pid_b, 0, "C_SignInit", 0x0001, 0);
    let initial = fixture.tick();
    fixture.publish(initial);
    assert_eq!(
        operation_edge_rows(&fixture.scene),
        vec![(Some(1), 0, false, 1, 0), (Some(1), 0, false, 1, 0),]
    );

    // Exercise the consumer's declared 4096-outcome capacity. Every
    // record is uniquely minted by the same H0 timeline; aggregating these
    // reports is test-only boundary stress, not another production queue.
    let limit = crate::discovery::instances::MAX_INSTANCES;
    let mut outcomes = Vec::new();
    let mut current = Vec::new();
    let mut remaining = limit - 1;
    while remaining != 0 {
        let quantum = remaining.min(MAX_PENDING);
        for _ in 0..quantum {
            fixture.enqueue(pid_a, 0, "C_Sign", 0, 0);
        }
        let (owned, receipts, negatives) = fixture.tick().into_parts();
        assert!(negatives.is_empty());
        assert_eq!(owned.len(), quantum);
        assert!(owned.iter().all(|outcome| matches!(outcome,
            TickOutcome::Call(call) if matches!(call.route(), Route::Joined(_)))));
        outcomes.extend(owned);
        current.extend(receipts);
        remaining -= quantum;
    }
    fixture.refresh(caller_a, 0);
    {
        let mut h0 = fixture.h0.0.borrow_mut();
        h0.io.targets.get_mut(&pid_b).unwrap().1.exec_id = 2;
    }
    fixture.refresh(caller_b, 0);
    let (retirement, receipts, negatives) = fixture.tick().into_parts();
    assert!(negatives.is_empty());
    assert_eq!(retirement.len(), 1);
    assert!(
        matches!(&retirement[0], TickOutcome::Invalidation(invalidation)
        if matches!(invalidation.scope(), InvalidationScope::ImageRetired(retired) if *retired == image(8)))
    );
    outcomes.extend(retirement);
    current.extend(receipts);
    assert_eq!(outcomes.len(), limit);
    assert_eq!(current.len(), 2);
    let batch = SemanticBatch::from_tick_report(
        fixture.lane.domain(),
        TickReport::scripted(outcomes, current),
        Vec::new(),
        now_ns(),
    )
    .unwrap();
    fixture.inject_validation(1, ValidationFailure::Fault);
    fixture.publish(batch);
    assert_eq!(fixture.h0.0.borrow().validation_negatives.len(), 1);
    let edges: Vec<_> = fixture
        .scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .collect();
    let a = edges.iter().find(|row| row.caller == caller_a).unwrap();
    let b = edges.iter().find(|row| row.caller == caller_b).unwrap();
    assert_eq!(
        a.api_returns,
        Some(limit as u64),
        "a validation negative must not spend the bounded positive-call capacity"
    );
    assert_eq!(a.historical_only_returns, (limit - 1) as u64);
    assert_eq!(a.semantics.as_ref().unwrap().unknown(), 1);
    assert!(a.lossy && a.reasons.contains(&InstanceReason::SemanticLoss));
    assert!(
        b.reasons.contains(&InstanceReason::ImageRetired),
        "the distinct image negative must reach H2 beside the domain validation loss"
    );
    assert_eq!(b.semantics.as_ref().unwrap().unknown(), 1);
}

#[test]
fn semantic_validation_terminal_task_preserves_healthy_peer_before_its_barrier() {
    use crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild;
    let child = OwnedStoppedChild::new();
    let pid_a = child.id();
    let pid_b = std::process::id();
    let mut fixture = RealScene::new(1);
    let caller_a = fixture.bind(pid_a, image(7), 0);
    let caller_b = fixture.bind(pid_b, image(8), 0);
    fixture.enqueue(pid_a, 0, "C_SignInit", 0x0001, 0);
    fixture.enqueue(pid_b, 0, "C_SignInit", 0x000d, 0);
    let batch = fixture.tick();
    fixture.publish(batch);
    assert_eq!(
        operation_edge_rows(&fixture.scene),
        vec![(Some(1), 0, false, 1, 0), (Some(1), 0, false, 1, 0),],
        "both real callers have independently published, live operations"
    );
    fixture.refresh(caller_b, 0);
    let pin_a = fixture.h0.0.borrow().io.targets[&pid_a].0.clone();
    // SAFETY: only this retained owned child is signaled. It remains
    // unreaped until its owner drops, so its pid cannot be reused here.
    assert_eq!(
        unsafe { libc::kill(pid_a as libc::pid_t, libc::SIGKILL) },
        0
    );
    assert!(pin_a.wait_ready(Some(Duration::from_secs(3))).unwrap());
    fixture.enqueue(pid_b, 0, "C_Sign", 0, 0);
    let batch = fixture.tick();
    {
        let h0 = fixture.h0.0.borrow();
        assert_eq!(
            h0.last_terminal_tasks.len(),
            1,
            "H0 minted one original-pidfd TaskRetired fact"
        );
        assert_eq!(h0.last_terminal_tasks[0].0, 7);
        let peer_position = h0
            .last_calls
            .iter()
            .find(|(caller_image, _)| *caller_image == image(8))
            .unwrap()
            .1;
        assert!(
            peer_position < h0.last_terminal_tasks[0].1,
            "the healthy peer return was collected before the dead task's barrier"
        );
    }
    fixture.publish(batch);
    let peer = fixture
        .scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .find(|row| row.caller == caller_b)
        .unwrap();
    assert_eq!(peer.api_returns, Some(2));
    assert_eq!(
        peer.historical_only_returns, 0,
        "a different task's barrier cannot demote the healthy peer return"
    );
    assert!(!peer.lossy);
    let reducer = peer.semantics.as_ref().unwrap();
    assert_eq!(
        (reducer.started(), reducer.completed(), reducer.unknown()),
        (1, 1, 0)
    );
    let dead = fixture
        .scene
        .coordinator
        .registry()
        .instances()
        .find(|row| row.caller == caller_a)
        .unwrap();
    assert_eq!(
        dead.state,
        InstanceLifecycle::Retired,
        "a terminal task is permanently retired, with its own operation ended unknown"
    );
    let dead_edge = fixture
        .scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .find(|row| row.caller == caller_a)
        .unwrap();
    assert!(dead_edge.lossy && dead_edge.reasons.contains(&InstanceReason::TaskRetired));
    let dead_reducer = dead_edge.semantics.as_ref().unwrap();
    assert_eq!((dead_reducer.completed(), dead_reducer.unknown()), (0, 1));
    assert!(!dead_reducer.has_live_operations());
    assert!(!peer.reasons.contains(&InstanceReason::TaskRetired));
}

#[test]
fn semantic_validation_global_fault_still_fences_two_real_callers() {
    use crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild;
    let child = OwnedStoppedChild::new();
    let pid_a = child.id();
    let pid_b = std::process::id();
    let mut fixture = RealScene::new(1);
    let caller_a = fixture.bind(pid_a, image(7), 0);
    let caller_b = fixture.bind(pid_b, image(8), 0);
    fixture.enqueue(pid_a, 0, "C_SignInit", 0x0001, 0);
    fixture.enqueue(pid_b, 0, "C_SignInit", 0x000d, 0);
    let batch = fixture.tick();
    fixture.publish(batch);
    assert_eq!(
        operation_edge_rows(&fixture.scene),
        vec![(Some(1), 0, false, 1, 0), (Some(1), 0, false, 1, 0),]
    );
    fixture
        .h0
        .0
        .borrow_mut()
        .io
        .script
        .health
        .push_back(Ok(Health {
            fault: 1,
            sticky: 0,
        }));
    fixture.refresh(caller_a, 0);
    fixture.refresh(caller_b, 0);
    let batch = fixture.tick();
    fixture.publish(batch);
    let old: Vec<_> = fixture
        .scene
        .coordinator
        .registry()
        .instance_semantic_edges()
        .filter(|row| row.api_returns == Some(1))
        .collect();
    assert_eq!(old.len(), 2);
    for edge in old {
        assert!(edge.lossy && edge.reasons.contains(&InstanceReason::SemanticLoss));
        let reducer = edge.semantics.as_ref().unwrap();
        assert_eq!(
            (reducer.completed(), reducer.unknown()),
            (0, 1),
            "the real H0 fault era ends both original operations unknown"
        );
        assert!(!reducer.has_live_operations());
    }
}
