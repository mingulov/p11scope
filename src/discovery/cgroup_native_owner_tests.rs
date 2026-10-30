//! SPDX-License-Identifier: GPL-3.0-or-later
//! Native-owner admission through the real retained-root cgroup transaction.
//! The owned child, provider mappings, process custody and membership samples
//! are real. Only native record transport is scripted; the temporary directory
//! containing cgroup.procs is not a mounted cgroupv2 qualification.

use super::*;
use crate::attach::capture::{AttachedEndpoint, ExecCoverage};
use crate::discovery::caller_registry::OsProcessSource;
use crate::discovery::native_binding::BoundImage;
use crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild;
use crate::inspect_system::inventory_cgroup::ScopedCollectionGap;
use crate::process::PidPin;
use crate::scope::inventory_cgroup::CgroupIncomplete;
use std::cell::Cell;
use std::rc::Rc;

/// Answer only through the adapter's original allocation, never through a
/// reopened PID or a replacement caller. This supplies no owner-image shortcut.
struct OriginalNativeIdentity {
    domain: NativeDomainId,
    original: Arc<PidPin>,
    queries: usize,
}

impl NativeIdentity<PidPin> for OriginalNativeIdentity {
    fn owner_image(&mut self, _: u32) -> Option<BoundImage> {
        None
    }

    fn query_cookie(&mut self, domain: NativeDomainId, pin: &PidPin) -> CookieQuery {
        if domain != self.domain {
            return CookieQuery::Unavailable("another native capture domain".into());
        }
        assert!(std::ptr::eq(pin, self.original.as_ref()));
        assert!(pin.still_the_same());
        assert!(pin.pidfd().is_ok());
        self.queries += 1;
        CookieQuery::Cookie(DomainCookie::scripted(domain, 41))
    }
}

fn native_read(
    domain: NativeDomainId,
    rows: Vec<WitnessRow>,
    counts: Vec<CallerCountUpdate>,
) -> NativeBatch {
    let at_ns = crate::discovery::caller_registry::now_ns();
    let mut batch = tests::witness_batch();
    batch.domain = domain;
    batch.rows = rows;
    batch.counts = counts;
    batch.health.discovery_counters = Some([0; 5]);
    batch.health_read_ns = at_ns;
    batch.rows_anchor_ns = at_ns + 1;
    batch.rows_read_ns = at_ns + 1;
    batch.counts_read_ns = at_ns + 1;
    batch.custody = ScopeCustody::CgroupHeld;
    NativeBatch::Witness(Box::new(batch))
}

struct ScopedNativeScene {
    coordinator: Box<InventoryCoordinator<OsProcessSource>>,
    identity: OriginalNativeIdentity,
    caller: CallerId,
    module: ModuleId,
    state: CgroupWalkState,
    child: OwnedStoppedChild,
    dir: tempfile::TempDir,
}

impl ScopedNativeScene {
    fn new() -> Self {
        let (dir, child, coordinator) = tests::cgroup_provider_scene();
        let mut coordinator = Box::new(coordinator);
        let collection = coordinator
            .cgroup_collector(
                CgroupWalkState::default(),
                CgroupWalkLimits::default(),
                CollectionControl::new(None),
                None,
            )
            .unwrap()();
        assert!(collection.preparation(child.id()).unwrap().check());
        coordinator
            .apply_cgroup_collection(collection, crate::discovery::caller_registry::now_ns())
            .unwrap();
        coordinator.commit_batch(false).unwrap();
        let completion = coordinator.take_cgroup_completion().unwrap();
        assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
        assert_eq!(completion.admitted, 1);
        assert_eq!(completion.scan_callers, 1);
        let caller = coordinator.adapter().live_id(child.id()).unwrap();
        assert_eq!(
            coordinator.adapter().record(caller).unwrap().authority,
            ImageAuthority::ScanPinned,
            "the initial real membership permit preserves useful scan fallback"
        );
        assert_eq!(coordinator.owner_of(caller), None);
        let original = coordinator
            .adapter()
            .shared_semantic_custody(caller)
            .expect("retain the exact original caller allocation without reopening its PID");
        let edges: Vec<_> = coordinator.registry().edges_of(caller).collect();
        assert_eq!(
            edges.len(),
            1,
            "one real mapped provider feeds this fixture"
        );
        let module = edges[0].module;
        assert_eq!(edges[0].mapping, MappingState::Mapped);

        let delta = coordinator.take_target_delta();
        assert!(!delta.endpoints.is_empty());
        let endpoint = delta.endpoints[0];
        let domain = NativeDomainId::mint();
        let attached_ns = crate::discovery::caller_registry::now_ns();
        coordinator.note_extend_receipt(&ExtendReceipt {
            attached: delta
                .endpoints
                .iter()
                .map(|endpoint| AttachedEndpoint {
                    id: endpoint.id,
                    object: endpoint.object,
                    at_ns: attached_ns,
                })
                .collect(),
            custody: Some(ScopeCustody::CgroupHeld),
            activated_roots: true,
            exec_coverage: Some(ExecCoverage::scripted(domain, 0)),
            ..ExtendReceipt::default()
        });
        let mut identity = OriginalNativeIdentity {
            domain,
            original,
            queries: 0,
        };
        let first_ns = crate::discovery::caller_registry::now_ns();
        assert!(first_ns > attached_ns);
        let mut row = WitnessRow::scripted(
            domain,
            41,
            1,
            endpoint.object,
            endpoint.id,
            child.id(),
            first_ns,
        );
        row.entry_count = 7;
        let mut decided = 0;
        for batch in [
            native_read(domain, vec![row], Vec::new()),
            NativeBatch::Lifecycle(DiscoveryBatch::scripted(
                domain,
                Vec::new(),
                crate::discovery::caller_registry::now_ns(),
            )),
            native_read(
                domain,
                Vec::new(),
                vec![CallerCountUpdate {
                    image: p11scope_ebpf_common::ImageIdentity {
                        task_cookie: 41,
                        exec_id: 1,
                    },
                    object: endpoint.object,
                    count: 7,
                }],
            ),
        ] {
            let receipt = coordinator.stage_native(
                batch,
                &mut identity,
                crate::discovery::caller_registry::now_ns(),
            );
            assert!(receipt.events.is_empty(), "{:?}", receipt.events);
            decided += receipt.decided;
        }
        assert_eq!(decided, 1, "the real binder decided the original witness");
        assert!(identity.queries > 0);
        coordinator.commit_batch(false).unwrap();
        let scene = Self {
            coordinator,
            identity,
            caller,
            module,
            state: completion.state,
            child,
            dir,
        };
        scene.assert_conserved_physical_use();
        scene
    }

    fn assert_conserved_physical_use(&self) {
        assert_eq!(
            self.coordinator.adapter().live_id(self.child.id()),
            Some(self.caller)
        );
        assert!(self.identity.original.still_the_same());
        let registry = self.coordinator.registry();
        let edge = registry.edge(self.caller, self.module).unwrap();
        assert_eq!(edge.entry_count, 7);
        assert_eq!(
            registry.edges().map(|edge| edge.entry_count).sum::<u64>(),
            7
        );
        assert!(matches!(
            registry.coverage(edge),
            UseCoverage::Counted { .. }
        ));
        assert!(
            edge.semantics.is_none(),
            "physical use creates no semantic role"
        );
        assert_eq!(registry.instances().count(), 0);
        assert_eq!(registry.instance_semantic_edges().count(), 0);
        assert_eq!(self.coordinator.semantic_bindings().len(), 0);
        assert_eq!(registry.witness_census().bound, 1);
        assert_eq!(registry.witness_census().unbound_total(), 0);
        assert_eq!(registry.witness_census().pending, 0);
        assert_eq!(registry.witness_placement().edge, 1);
        assert_eq!(registry.witness_placement().module, 0);
        assert_eq!(registry.witness_placement().ambiguous, 0);
        assert_eq!(registry.witness_placement().unresolved, 0);
        assert!(
            registry
                .modules()
                .all(|module| module.unbound_use.is_none())
        );
    }

    fn commit_membership_pass(&mut self, migrate_out: bool) -> CgroupCompletion {
        use crate::discovery::inventory_attach_set::provider_read_test;

        let collection = self
            .coordinator
            .cgroup_collector(
                std::mem::take(&mut self.state),
                CgroupWalkLimits::default(),
                CollectionControl::new(None),
                None,
            )
            .unwrap()();
        let preparation = collection.preparation(self.child.id()).unwrap();
        assert!(preparation.check());
        assert_eq!(
            preparation.generation().start_time,
            self.coordinator
                .adapter()
                .record(self.caller)
                .unwrap()
                .start_time
        );
        self.coordinator
            .apply_cgroup_collection(collection, crate::discovery::caller_registry::now_ns())
            .unwrap();
        assert_eq!(
            self.coordinator.owner_of(self.caller),
            None,
            "preparation alone cannot activate a native owner"
        );
        let reads = Rc::new(Cell::new(0));
        let returned_reads = Rc::clone(&reads);
        let membership = self.dir.path().join("cgroup.procs");
        provider_read_test::observe(
            move || {
                returned_reads.set(returned_reads.get() + 1);
                if migrate_out {
                    std::fs::write(&membership, b"").unwrap();
                }
            },
            || self.coordinator.commit_batch(false).unwrap(),
        );
        assert!(
            reads.get() > 0,
            "the real retained-provider metadata read ran"
        );
        self.coordinator.take_cgroup_completion().unwrap()
    }
}

#[test]
#[ignore = "6.11 activation deferred per docs/superpowers/decisions/2026-10-29-611-bridge-decision.md; tracked RED cell, migration twin cgroup_native_owner_migration_during_provider_retention_refuses_activation stays running"]
fn cgroup_native_owner_stable_retained_member_activates_after_final_permit() {
    // A missing scoped owner path must fail here only after real original
    // binding, fallback and final sampled membership have all succeeded.
    let mut scene = ScopedNativeScene::new();
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(completion.admitted, 0);
    assert_eq!(completion.scan_callers, 1);
    scene.assert_conserved_physical_use();
    let owner = scene.coordinator.owner_of(scene.caller).expect(
        "a stable retained-root member with an original native witness must activate its native owner after the final membership permit",
    );
    let epochs = scene
        .coordinator
        .engine
        .inventory_owner_epochs(owner)
        .unwrap();
    assert_eq!(
        epochs.image_state,
        super::super::inventory::ImageCheck::Exact
    );
    assert_eq!(epochs.requested, epochs.serviced);
    assert!(
        epochs.complete.is_some(),
        "activation commits the owner's real scan"
    );
}

#[test]
fn cgroup_native_owner_migration_during_provider_retention_refuses_activation() {
    // If owner activation moves before the final sample, this twin must fail
    // even though the original live process and native witness stay valid.
    let mut scene = ScopedNativeScene::new();
    let completion = scene.commit_membership_pass(true);
    assert_eq!(
        completion.outcome,
        ScopedCollectionOutcome::Incomplete(ScopedCollectionGap::Membership(
            CgroupIncomplete::ChangedMembership,
        ))
    );
    assert_eq!(completion.admitted, 0);
    assert_eq!(
        completion.scan_callers, 0,
        "the final sample granted no permit"
    );
    assert_eq!(scene.coordinator.owner_of(scene.caller), None);
    assert!(scene.coordinator.take_target_delta().is_empty());
    scene.assert_conserved_physical_use();
}
