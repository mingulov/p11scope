//! SPDX-License-Identifier: GPL-3.0-or-later
//! Same-caller provider admission through genuine H0 receipts. Only the existing
//! native/Session I/O seam is substituted; no current receipt is constructed here.

use super::*;

struct ProviderScene {
    scene: AdmissionScene,
    modules: Vec<ModuleKey>,
    physical_a_file: u32,
    last_copy_charge: Option<usize>,
}

impl ProviderScene {
    fn new(reverse: bool) -> Self {
        let (dir, original, coordinator) = cgroup_provider_scene();
        drop(coordinator);
        drop(original);
        let first = dir.path().join("scoped-provider.so");
        let second = dir.path().join("scoped-provider-b.so");
        std::fs::copy(&first, &second).unwrap();
        let mut providers = vec![first, second];
        if reverse {
            providers.reverse();
        }
        let ready = dir.path().join("providers-ready");
        let child = OwnedStoppedChild::spawn_stopped(
            std::process::Command::new(dir.path().join("scoped-driver"))
                .arg("--ready")
                .arg(&ready)
                .arg("--call")
                .args(&providers)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null()),
            |pid| {
                let deadline = Instant::now() + Duration::from_secs(5);
                while !ready.exists() {
                    assert!(Instant::now() < deadline, "owned provider startup watchdog");
                    std::thread::sleep(Duration::from_millis(1));
                }
                // SAFETY: spawn_stopped retains this exact owned child.
                assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) }, 0);
            },
        );
        let scope = Scope::Pid(child.id());
        let coordinator = InventoryCoordinator::new(
            scope.clone(),
            HookRegistry::builtin(),
            providers.clone(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        let held = HeldProviders::from_paths(tempfile::tempdir().unwrap(), &providers);
        let mut lane =
            AttestedSemanticLane::start(held.subset, &scope, BackendSelection::Auto).unwrap();
        let modules = lane
            .subset()
            .required()
            .keys()
            .map(|object| {
                let pin = lane
                    .subset()
                    .pins()
                    .pinned()
                    .find(|pin| pin.id == *object)
                    .unwrap();
                ModuleKey::physical(
                    pin.key.device.major,
                    pin.key.device.minor,
                    pin.key.inode,
                    Some(pin.sha256.to_owned()),
                    pin.path,
                )
            })
            .collect::<Vec<_>>();
        let physical_a_file = lane
            .subset()
            .required()
            .keys()
            .position(|object| {
                lane.subset()
                    .pins()
                    .pinned()
                    .find(|pin| pin.id == *object)
                    .is_some_and(|pin| {
                        std::path::Path::new(pin.path).file_name()
                            == Some(std::ffi::OsStr::new("scoped-provider.so"))
                    })
            })
            .expect("fixture labels the original physical file independently of slot order")
            as u32;
        assert_eq!(modules.len(), 2);
        assert_ne!(
            modules[0], modules[1],
            "equal bytes do not merge physical files"
        );
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
            terminal: None,
            terminal_published: false,
        })));
        lane.install_test_io(Box::new(h0.clone()));
        let mut fixture = Self {
            scene: AdmissionScene {
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
            },
            modules,
            physical_a_file,
            last_copy_charge: None,
        };
        fixture.scene.prepare_without_cookie();
        let caller = fixture.scene.caller();
        for module in &fixture.modules {
            let registry = fixture.scene.coordinator.registry();
            let id = registry
                .module_id_for(module)
                .expect("real catalog found provider");
            assert_eq!(
                registry.edge(caller, id).unwrap().mapping,
                crate::discovery::caller_registry::MappingState::Mapped
            );
        }
        fixture.scene.observe_entry();
        fixture
    }

    fn admit(
        &mut self,
        file: u32,
    ) -> Result<
        (),
        crate::discovery::engine::inventory_coordinator::semantics::SemanticBindingRefusal,
    > {
        self.admit_as(file, file)
    }

    fn admit_as(
        &mut self,
        file: u32,
        module_file: u32,
    ) -> Result<
        (),
        crate::discovery::engine::inventory_coordinator::semantics::SemanticBindingRefusal,
    > {
        let caller = self.scene.caller();
        let lane = self.scene.lane.as_mut().unwrap();
        let candidate = self
            .scene
            .coordinator
            .prepare_legacy_semantic_candidate(caller, lane.domain())
            .expect("the real catalog retains original caller custody");
        let slot = self.scene.h0.0.borrow().io.held.slot(file, "C_SignInit");
        let prepared = lane
            .prepare_caller_admission(
                candidate.pin(),
                slot,
                &self.modules[module_file as usize],
                |bytes| {
                    self.last_copy_charge = Some(bytes);
                    self.scene
                        .coordinator
                        .registry()
                        .reserve_semantic_storage(bytes)
                },
            )
            .expect("H0 accepts this original-custody file scan");
        let (receipt, result) = self
            .scene
            .coordinator
            .consume_semantic_admission(candidate, prepared, None);
        lane.deliver_admission_receipt(receipt);
        result
    }

    /// The original producer receipt is validated before the same owned
    /// receipt reaches its normal finalizer; no receipt is constructed here.
    fn refresh_coverage(&mut self, file: u32) -> crate::inventory_semantics::LaneCoverage {
        let caller = self.scene.caller();
        let lane = self.scene.lane.as_mut().unwrap();
        let candidate = self
            .scene
            .coordinator
            .prepare_legacy_semantic_candidate(caller, lane.domain())
            .unwrap();
        let slot = self.scene.h0.0.borrow().io.held.slot(file, "C_SignInit");
        let prepared = lane
            .prepare_caller_admission(
                candidate.pin(),
                slot,
                &self.modules[file as usize],
                |bytes| {
                    self.scene
                        .coordinator
                        .registry()
                        .reserve_semantic_storage(bytes)
                },
            )
            .unwrap();
        let (receipt, result) = self
            .scene
            .coordinator
            .consume_semantic_admission(candidate, prepared, None);
        result.unwrap();
        let mut report = TickReport::default();
        let coverage = lane
            .validate_current(&receipt, &mut report)
            .expect("the original fresh H0 receipt validates");
        assert!(
            report.into_parts().0.is_empty(),
            "healthy validation produces no refusal"
        );
        lane.deliver_admission_receipt(receipt);
        coverage
    }

    fn record_for(
        &self,
        file: u32,
    ) -> (
        crate::discovery::caller_registry::instance_input::RegistryInstanceId,
        crate::discovery::caller_registry::instance_input::InstanceLifecycle,
    ) {
        let registry = self.scene.coordinator.registry();
        let module = registry
            .module_id_for(&self.modules[file as usize])
            .unwrap();
        let records: Vec<_> = registry
            .instances()
            .filter(|record| record.module == module)
            .collect();
        assert_eq!(records.len(), 1);
        (records[0].id, records[0].state)
    }

    fn apply_invalidations(
        &mut self,
        scope: InvalidationScope,
        fresh: &[crate::inventory_semantics::LaneCoverage],
    ) -> (usize, usize) {
        use crate::discovery::caller_registry::instance_input::finalize_invalidation;
        let caller = self.scene.caller();
        let domain = self.scene.lane.as_ref().unwrap().domain();
        let (losses, retirements) = finalize_invalidation(
            &scope,
            Some(1000),
            domain,
            self.scene.coordinator.semantic_bindings().get(caller),
            fresh,
        )
        .unwrap();
        let counts = (losses.len(), retirements.len());
        let registry = self.scene.coordinator.registry_mut();
        for loss in losses {
            registry.note_instance_semantic_loss(loss);
        }
        for retirement in retirements {
            registry.retire_instance(retirement);
        }
        registry.publish();
        counts
    }

    fn pin(&self) -> Arc<PidPin> {
        self.scene
            .coordinator
            .semantic_bindings()
            .get(self.scene.caller())
            .unwrap()
            .pin()
    }

    fn publish(&mut self) {
        let targets = self
            .scene
            .coordinator
            .semantic_bindings_mut()
            .bindings_for_tick();
        assert_eq!(
            targets.len(),
            1,
            "one process target, regardless of provider count"
        );
        let lane = self.scene.lane.as_mut().unwrap();
        let batch = lane.tick(targets).unwrap();
        self.scene.coordinator.stage_semantic_batch(batch);
        self.scene
            .coordinator
            .commit_batch_with_semantics(false, Some(lane))
            .unwrap();
    }

    fn enqueue(&mut self, file: u32, function: &str, mechanism: u64, rv: u64) {
        self.scene.h0.0.borrow_mut().io.held.enqueue(
            self.scene.child.id(),
            file,
            function,
            mechanism,
            rv,
        );
    }

    fn summary(&self, file: usize) -> (u64, u64, u64, u64) {
        let registry = self.scene.coordinator.registry();
        let module = registry.module_id_for(&self.modules[file]).unwrap();
        let rows: Vec<_> = registry
            .instance_semantic_edges()
            .filter(|row| row.module == module)
            .collect();
        assert_eq!(rows.len(), 1, "one owned router instance for this provider");
        let semantics = rows[0]
            .semantics
            .as_ref()
            .expect("provider has its own reducer");
        (
            rows[0].api_returns.unwrap(),
            semantics.started(),
            semantics.completed(),
            semantics.failed(),
        )
    }
}

#[test]
fn prepared_provider_actual_layout_keeps_4096_ordinary_associations_representable() {
    use crate::discovery::instances::MAX_INSTANCES;
    use crate::inventory_semantics::{PreparedSemanticAdmission, SemanticProviderTarget};
    use crate::semantics_edge::resources::{
        OWNED_ALLOCATION_PADDING, REDUCER_BASE_CHARGE, ResourceLease,
    };

    let mut fixture = ProviderScene::new(false);
    assert_eq!(fixture.admit(0), Ok(()));
    let copy = fixture.last_copy_charge.unwrap();
    let slot = std::mem::size_of::<Option<SemanticProviderTarget>>();
    // Fewer than 2N geometric retained slots; another N slots dominates
    // the largest old+new growth peak. N+1 allocation paddings cover one
    // container per caller plus a growing replacement. Include four prepared
    // copies and one ordinary reducer per association under the SAME pool.
    let bytes = (MAX_INSTANCES + 4).checked_mul(copy).unwrap()
        + 3 * MAX_INSTANCES * slot
        + (MAX_INSTANCES + 1) * OWNED_ALLOCATION_PADDING
        + MAX_INSTANCES * REDUCER_BASE_CHARGE;
    let snapshot = fixture
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    assert!(bytes <= snapshot.limit_bytes - snapshot.charged_bytes);
    let reservation = fixture
        .scene
        .coordinator
        .registry()
        .reserve_semantic_storage(bytes)
        .unwrap();
    let reserved = fixture
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    assert_eq!(reserved.charged_bytes, snapshot.charged_bytes + bytes);
    println!(
        "actual provider={} align={} slot={} prepared={} lease={} caller_test={} copy={} population_reservation={}",
        std::mem::size_of::<SemanticProviderTarget>(),
        std::mem::align_of::<SemanticProviderTarget>(),
        slot,
        std::mem::size_of::<PreparedSemanticAdmission>(),
        std::mem::size_of::<ResourceLease>(),
        std::mem::size_of::<
            crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
        >(),
        copy,
        bytes
    );
    drop(reservation);
    assert_eq!(
        fixture
            .scene
            .coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes,
        snapshot.charged_bytes
    );
}

#[test]
fn prepared_provider_copy_reserves_shared_pool_before_retention_and_retries() {
    use crate::discovery::engine::inventory_coordinator::semantics::SemanticBindingRefusal;
    use crate::inventory_semantics::SemanticRefusal;
    use crate::semantics_edge::resources::{SEMANTIC_RESOURCE_LIMIT, SEMANTIC_TRANSITION_SCRATCH};

    let mut fixture = ProviderScene::new(false);
    fixture
        .scene
        .coordinator
        .registry_mut()
        .reference_semantic_resource_limit(SEMANTIC_TRANSITION_SCRATCH);
    let before = fixture
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    assert_eq!(
        fixture.admit(0),
        Err(SemanticBindingRefusal::OwnerRefused(
            SemanticRefusal::ProviderStorage
        ))
    );
    assert!(fixture.last_copy_charge.unwrap() > 0);
    assert_eq!(fixture.scene.coordinator.semantic_bindings().len(), 0);
    let refused = fixture
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    assert_eq!(refused.charged_bytes, before.charged_bytes);
    assert_eq!(refused.peak_charged_bytes, before.peak_charged_bytes);
    assert_eq!(refused.refused, before.refused + 1);
    assert!(
        fixture
            .scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .any(|gap| {
                gap.caller == Some(fixture.scene.caller())
                    && gap.subject.contains("provider file 0")
                    && gap.reason == "provider_storage_refused"
            }),
        "copy refusal identifies the particular requested provider"
    );
    let original = fixture
        .scene
        .h0
        .0
        .borrow()
        .last_effective
        .as_ref()
        .unwrap()
        .clone();
    fixture
        .scene
        .coordinator
        .registry_mut()
        .reference_semantic_resource_limit(SEMANTIC_RESOURCE_LIMIT);
    assert_eq!(fixture.admit(0), Ok(()));
    assert!(Arc::ptr_eq(&original, &fixture.pin()));
}

#[test]
fn prepared_provider_count_and_capacity_refusals_preserve_a_then_retry() {
    use crate::discovery::engine::inventory_coordinator::semantics::SemanticBindingRefusal;

    let mut fixture = ProviderScene::new(false);
    assert_eq!(fixture.admit(0), Ok(()));
    let original = fixture.pin();
    fixture
        .scene
        .coordinator
        .semantic_bindings_mut()
        .reference_provider_limit(1);
    let before = fixture
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    assert_eq!(fixture.admit(1), Err(SemanticBindingRefusal::Capacity));
    let module_b = fixture
        .scene
        .coordinator
        .registry()
        .module_id_for(&fixture.modules[1])
        .unwrap();
    assert!(
        fixture
            .scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .any(|gap| {
                gap.caller == Some(fixture.scene.caller())
                    && gap.module == Some(module_b)
                    && gap.reason == "capacity"
            }),
        "B's association refusal is visible independently of retained A"
    );
    assert_eq!(
        fixture
            .scene
            .coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes,
        before.charged_bytes
    );
    let b_copy = fixture.last_copy_charge.unwrap();
    assert_eq!(
        fixture.admit(0),
        Ok(()),
        "exact reproof remains eligible at the count limit"
    );
    assert!(Arc::ptr_eq(&original, &fixture.pin()));
    fixture
        .scene
        .coordinator
        .semantic_bindings_mut()
        .reference_provider_limit(2);
    let snapshot = fixture
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    let held = fixture
        .scene
        .coordinator
        .registry()
        .reserve_semantic_storage(snapshot.limit_bytes - snapshot.charged_bytes - b_copy)
        .unwrap();
    let held_snapshot = fixture
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    assert_eq!(
        fixture.admit(1),
        Err(SemanticBindingRefusal::Capacity),
        "copy fits but full new container does not"
    );
    let refused = fixture
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    assert_eq!(refused.charged_bytes, held_snapshot.charged_bytes);
    assert_eq!(refused.peak_charged_bytes, refused.limit_bytes);
    assert_eq!(refused.refused, held_snapshot.refused + 1);
    let binding = fixture
        .scene
        .coordinator
        .semantic_bindings()
        .get(fixture.scene.caller())
        .unwrap();
    assert!(binding.provider_for_file(0).is_some());
    assert!(binding.provider_for_file(1).is_none());
    assert!(Arc::ptr_eq(&original, &binding.pin()));
    drop(held);
    assert_eq!(fixture.admit(1), Ok(()));
    assert!(Arc::ptr_eq(&original, &fixture.pin()));
}

#[test]
fn prepared_provider_capacity_charges_old_plus_new_and_reproof_keeps_capacity() {
    let mut fixture = ProviderScene::new(false);
    let baseline = fixture
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot()
        .charged_bytes;
    assert_eq!(fixture.admit(0), Ok(()));
    let slot = fixture.scene.h0.0.borrow().io.held.slot(0, "C_SignInit");
    let endpoint = fixture.scene.h0.0.borrow().io.held.endpoint(slot).unwrap();
    let binding = fixture
        .scene
        .coordinator
        .semantic_bindings()
        .get(fixture.scene.caller())
        .unwrap();
    assert!(binding.provider_for_endpoint(endpoint).is_some());
    let mut wrong_file = endpoint;
    wrong_file.file_slot = 1;
    assert!(binding.provider_for_endpoint(wrong_file).is_none());
    assert!(binding.provider_for_file(1).is_none());
    assert!(
        binding.reference_fixture_module().is_none(),
        "real binding never uses the algorithm fallback"
    );
    let after_a = fixture
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    let a_copy = fixture.last_copy_charge.unwrap();
    let old_capacity = after_a.charged_bytes - baseline - a_copy;
    let slot_size =
        std::mem::size_of::<Option<crate::inventory_semantics::SemanticProviderTarget>>();
    assert_eq!(
        old_capacity,
        slot_size + crate::semantics_edge::resources::OWNED_ALLOCATION_PADDING
    );
    assert_eq!(fixture.admit(1), Ok(()));
    let binding = fixture
        .scene
        .coordinator
        .semantic_bindings()
        .get(fixture.scene.caller())
        .unwrap();
    assert_eq!(
        binding.provider_for_file(0).unwrap().module(),
        &fixture.modules[0]
    );
    assert_eq!(
        binding.provider_for_file(1).unwrap().module(),
        &fixture.modules[1]
    );
    assert!(binding.reference_fixture_module().is_none());
    let after_b = fixture
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    assert_eq!(
        after_b.charged_bytes,
        baseline
            + a_copy
            + fixture.last_copy_charge.unwrap()
            + 2 * slot_size
            + crate::semantics_edge::resources::OWNED_ALLOCATION_PADDING
    );
    assert_eq!(
        after_b.peak_charged_bytes,
        after_b.charged_bytes + old_capacity
    );
    assert_eq!(fixture.admit(0), Ok(()));
    let reproof = fixture
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    assert_eq!(reproof.charged_bytes, after_b.charged_bytes);
    assert!(
        reproof.peak_charged_bytes >= after_b.charged_bytes + fixture.last_copy_charge.unwrap()
    );
    let ambiguous = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fixture
            .scene
            .coordinator
            .semantic_bindings()
            .get(fixture.scene.caller())
            .unwrap()
            .reference_single_provider_module();
    }));
    assert!(
        ambiguous.is_err(),
        "legacy reference helper cannot select among providers"
    );
}

#[test]
fn prepared_wrong_physical_provider_preserves_a() {
    use crate::discovery::engine::inventory_coordinator::semantics::SemanticBindingRefusal;
    use crate::inventory_semantics::SemanticRefusal;

    let mut fixture = ProviderScene::new(false);
    assert_eq!(fixture.admit(0), Ok(()));
    let original = fixture.pin();
    fixture.enqueue(0, "C_SignInit", 0x000d, 0);
    fixture.publish();
    assert_eq!(fixture.summary(0), (1, 1, 0, 0));
    assert_eq!(
        fixture.admit_as(1, 0),
        Err(SemanticBindingRefusal::OwnerRefused(
            SemanticRefusal::ProviderInstanceUnproven
        )),
        "equal digest cannot authorize the other physical provider"
    );
    assert!(Arc::ptr_eq(&original, &fixture.pin()));
    assert_eq!(fixture.summary(0), (1, 1, 0, 0));
    fixture.publish();
    assert_eq!(fixture.scene.coordinator.registry().instances().count(), 1);
    fixture.enqueue(0, "C_Sign", 0, 0);
    fixture.publish();
    assert_eq!(fixture.summary(0), (2, 1, 1, 0));
}

#[test]
fn prepared_providers_share_original_process_custody_in_both_orders() {
    for reverse in [false, true] {
        for physical_a_first in [true, false] {
            let mut fixture = ProviderScene::new(reverse);
            let first = if physical_a_first {
                fixture.physical_a_file
            } else {
                1 - fixture.physical_a_file
            };
            let second = 1 - first;
            assert_eq!(fixture.admit(first), Ok(()));
            let original = fixture.pin();
            let second = fixture.admit(second);
            assert!(Arc::ptr_eq(&original, &fixture.pin()));
            assert!(
                fixture.scene.h0.0.borrow().accepted >= 2,
                "both provider scans minted genuine H0 receipts"
            );
            assert_eq!(second, Ok(()), "B must join the same accepted caller");
            fixture.publish();
            assert_eq!(fixture.scene.coordinator.registry().instances().count(), 2);
            assert_eq!(fixture.admit(0), Ok(()));
            assert_eq!(fixture.admit(1), Ok(()));
            assert!(Arc::ptr_eq(&original, &fixture.pin()));
        }
    }
}

#[test]
fn prepared_late_b_preserves_a_operation_and_one_tick_target() {
    let mut fixture = ProviderScene::new(false);
    assert_eq!(fixture.admit(0), Ok(()));
    let original = fixture.pin();
    fixture.enqueue(0, "C_SignInit", 0x000d, 0);
    fixture.publish();
    assert_eq!(fixture.summary(0), (1, 1, 0, 0));
    let second = fixture.admit(1);
    assert_eq!(
        fixture.summary(0),
        (1, 1, 0, 0),
        "B preparation preserves A's pending operation"
    );
    assert!(Arc::ptr_eq(&original, &fixture.pin()));
    assert_eq!(second, Ok(()));
    fixture.enqueue(0, "C_Sign", 0, 0);
    fixture.enqueue(1, "C_SignInit", 0x0001, 0);
    fixture.enqueue(1, "C_Sign", 0, 0x21);
    fixture.publish();
    assert_eq!(fixture.summary(0), (2, 1, 1, 0));
    assert_eq!(fixture.summary(1), (2, 1, 0, 1));
    assert!(Arc::ptr_eq(&original, &fixture.pin()));
}

#[test]
fn prepared_b_cannot_promote_or_erase_a_historical_returns() {
    let mut fixture = ProviderScene::new(false);
    assert_eq!(fixture.admit(0), Ok(()));
    fixture.publish();
    // The existing real H0 refusal seam removes current permission while
    // retaining cached routing, so these returns are genuinely historical.
    fixture.scene.h0.0.borrow_mut().io.current = None;
    fixture.enqueue(0, "C_SignInit", 0x000d, 0);
    fixture.enqueue(0, "C_Sign", 0, 0);
    fixture.publish();
    let historical = |fixture: &ProviderScene| {
        let registry = fixture.scene.coordinator.registry();
        let module = registry.module_id_for(&fixture.modules[0]).unwrap();
        let rows: Vec<_> = registry
            .instance_semantic_edges()
            .filter(|row| row.module == module)
            .collect();
        assert_eq!(rows.len(), 1);
        (
            rows[0].api_returns,
            rows[0].historical_only_returns,
            rows[0].semantics.as_ref().map_or(0, |s| s.completed()),
        )
    };
    assert_eq!(historical(&fixture), (Some(2), 2, 0));
    let original = fixture.pin();
    fixture.scene.observe_entry();
    let second = fixture.admit(1);
    assert_eq!(historical(&fixture), (Some(2), 2, 0));
    assert!(Arc::ptr_eq(&original, &fixture.pin()));
    assert_eq!(second, Ok(()));
    fixture.publish();
    assert_eq!(historical(&fixture), (Some(2), 2, 0));
}

#[test]
fn prepared_provider_b_file_loss_preserves_a_and_unknown_file_widens() {
    use crate::discovery::caller_registry::instance_input::InstanceLifecycle;
    for unknown in [false, true] {
        for reverse in [false, true] {
            let mut fixture = ProviderScene::new(reverse);
            let a = fixture.physical_a_file;
            let b = 1 - a;
            fixture.admit(a).unwrap();
            fixture.admit(b).unwrap();
            fixture.publish();
            for file in [a, b] {
                fixture.enqueue(file, "C_SignInit", 0x0001, 0);
            }
            fixture.publish();
            let image = fixture
                .scene
                .coordinator
                .semantic_bindings()
                .get(fixture.scene.caller())
                .unwrap()
                .image();
            assert_eq!(
                fixture.apply_invalidations(
                    InvalidationScope::File {
                        image,
                        file_slot: if unknown { 99 } else { b },
                    },
                    &[]
                ),
                (1, 0)
            );
            assert_eq!(fixture.record_for(b).1, InstanceLifecycle::Uncertain);
            assert_eq!(
                fixture.record_for(a).1,
                if unknown {
                    InstanceLifecycle::Uncertain
                } else {
                    InstanceLifecycle::Observed
                }
            );
            fixture.enqueue(a, "C_Sign", 0, 0);
            fixture.publish();
            assert_eq!(
                fixture.summary(a as usize).2,
                u64::from(!unknown),
                "B-local loss keeps A's operation; unknown file ownership conservatively fences both"
            );
        }
    }
}

#[test]
fn prepared_provider_b_retirement_uses_its_genuine_fresh_partition() {
    use crate::discovery::caller_registry::instance_input::InstanceLifecycle;
    for reverse in [false, true] {
        let mut fixture = ProviderScene::new(reverse);
        let a = fixture.physical_a_file;
        let b = 1 - a;
        fixture.admit(a).unwrap();
        let old = fixture.refresh_coverage(b);
        fixture.publish();
        let old_id = fixture.record_for(b).0;
        for file in [a, b] {
            fixture.enqueue(file, "C_SignInit", 0x0001, 0);
        }
        fixture.publish();
        {
            let mut h0 = fixture.scene.h0.0.borrow_mut();
            let (base, local) = h0.io.held.scan_input(b);
            h0.io
                .held
                .scan_inputs
                .insert(b, (base + 0x4000_0000, local + 1));
        }
        let fresh = fixture.refresh_coverage(b);
        assert!(!fresh.instances().is_empty());
        assert!(
            fresh
                .instances()
                .iter()
                .all(|id| !old.instances().contains(id)),
            "the actual H0 scan must mint a genuinely disjoint B partition"
        );
        assert_eq!(
            fixture.apply_invalidations(
                InvalidationScope::InstancesRetired {
                    image: old.image(),
                    file_slot: b,
                    ids: old.instances().to_vec(),
                },
                std::slice::from_ref(&fresh)
            ),
            (0, old.instances().len())
        );
        let registry = fixture.scene.coordinator.registry();
        assert_eq!(
            registry
                .instances()
                .find(|record| record.id == old_id)
                .unwrap()
                .state,
            InstanceLifecycle::Retired
        );
        assert_eq!(fixture.record_for(a).1, InstanceLifecycle::Observed);
        fixture.enqueue(a, "C_Sign", 0, 0);
        fixture.publish();
        assert_eq!(fixture.summary(a as usize), (2, 1, 1, 0));
        let registry = fixture.scene.coordinator.registry();
        let old = registry
            .instance_semantic_edges()
            .find(|record| record.id == old_id)
            .unwrap();
        let semantics = old.semantics.as_ref().unwrap();
        assert_eq!(
            (
                semantics.started(),
                semantics.completed(),
                semantics.unknown()
            ),
            (1, 0, 1),
            "retirement keeps B's original operation history"
        );
    }
}

#[test]
fn prepared_provider_b_retirement_refuses_other_provider_fresh_coverage() {
    use crate::discovery::caller_registry::instance_input::InstanceLifecycle;
    let mut fixture = ProviderScene::new(false);
    let a = fixture.physical_a_file;
    let b = 1 - a;
    let other = fixture.refresh_coverage(a);
    let old = fixture.refresh_coverage(b);
    fixture.publish();
    for file in [a, b] {
        fixture.enqueue(file, "C_SignInit", 0x0001, 0);
    }
    fixture.publish();
    assert_eq!(
        fixture.apply_invalidations(
            InvalidationScope::InstancesRetired {
                image: old.image(),
                file_slot: b,
                ids: old.instances().to_vec(),
            },
            std::slice::from_ref(&other)
        ),
        (old.instances().len(), 0)
    );
    assert_eq!(fixture.record_for(b).1, InstanceLifecycle::Uncertain);
    assert_eq!(fixture.record_for(a).1, InstanceLifecycle::Observed);
    fixture.enqueue(a, "C_Sign", 0, 0);
    fixture.publish();
    assert_eq!(fixture.summary(a as usize), (2, 1, 1, 0));
}
