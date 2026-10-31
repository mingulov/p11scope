//! SPDX-License-Identifier: GPL-3.0-or-later
//! Native-owner admission through the real retained-root cgroup transaction.
//! The owned child, provider mappings, process custody and membership samples
//! are real. Only native record transport is scripted; the temporary directory
//! containing cgroup.procs is not a mounted cgroupv2 qualification.

use super::super::inventory::image_guard::{ImageAcquisition, ScriptedAcquisition};
use super::*;
use crate::attach::capture::{AttachedEndpoint, ExecCoverage};
use crate::discovery::caller_registry::OsProcessSource;
use crate::discovery::inventory_attach_set::{AttachObjectId, EndpointId};
use crate::discovery::native_binding::BoundImage;
use crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild;
use crate::inspect_system::inventory_cgroup::ScopedCollectionGap;
use crate::process::PidPin;
use crate::scope::inventory_cgroup::CgroupIncomplete;
use p11scope_ebpf_common::{DISCOVERY_KIND_EXEC, DiscoveryRecord};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

/// Answer only through the adapter's original allocation, never through a
/// reopened PID or a replacement caller. This supplies no owner-image shortcut.
struct OriginalNativeIdentity {
    domain: NativeDomainId,
    /// Extra (domain, ticket) answers for the alias twin: the same
    /// original allocation observed by a second native domain.
    aliases: Vec<(NativeDomainId, u64)>,
    original: Arc<PidPin>,
    queries: usize,
}

impl NativeIdentity<PidPin> for OriginalNativeIdentity {
    fn owner_image(&mut self, _: u32) -> Option<BoundImage> {
        None
    }

    fn query_cookie(&mut self, domain: NativeDomainId, pin: &PidPin) -> CookieQuery {
        let ticket = if domain == self.domain {
            Some(41)
        } else {
            self.aliases
                .iter()
                .find(|(alias, _)| *alias == domain)
                .map(|(_, ticket)| *ticket)
        };
        let Some(ticket) = ticket else {
            return CookieQuery::Unavailable("another native capture domain".into());
        };
        assert!(std::ptr::eq(pin, self.original.as_ref()));
        assert!(pin.still_the_same());
        assert!(pin.pidfd().is_ok());
        self.queries += 1;
        CookieQuery::Cookie(DomainCookie::scripted(domain, ticket))
    }
}

/// Shared scripted acquisition: the twin holds the `Rc` while the
/// coordinator owns the boxed handle, so call counts and generations
/// stay observable after the commit. Observations decode through the
/// real baseline decoder; only the transport is scripted.
#[derive(Clone)]
struct SharedAcquisition(Rc<RefCell<ScriptedAcquisition>>);

impl ImageAcquisition for SharedAcquisition {
    fn acquisition_domain(&self) -> NativeDomainId {
        self.0.borrow().acquisition_domain()
    }

    fn acquire_caller_image(
        &mut self,
        original: &Arc<PidPin>,
        window: crate::attach::capture::ReadWindow,
    ) -> anyhow::Result<crate::attach::capture::CallerImageObservation> {
        self.0.borrow_mut().acquire_caller_image(original, window)
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
    domain: NativeDomainId,
    witness_target: (AttachObjectId, EndpointId),
    state: CgroupWalkState,
    child: Option<OwnedStoppedChild>,
    dir: tempfile::TempDir,
}

/// What the provider-read hook does while the commit runs:
/// nothing, migrate the member out, or kill and reap the child.
#[derive(Clone, Copy)]
enum PassAction {
    Stable,
    MigrateOut,
    KillChild,
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
            aliases: Vec::new(),
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
            domain,
            witness_target: (endpoint.object, endpoint.id),
            state: completion.state,
            child: Some(child),
            dir,
        };
        scene.assert_conserved_physical_use();
        scene
    }

    fn child_id(&self) -> u32 {
        self.child.as_ref().expect("retained owned child").id()
    }

    /// Install a scripted acquisition on the coordinator and keep the
    /// shared handle: `script` holds (generation, ticket, exec) rows.
    /// Generations need only be nonzero; every observation decodes
    /// through the real baseline decoder.
    fn set_scripted_acquisition(
        &mut self,
        script: &[(u64, u64, u64)],
    ) -> Rc<RefCell<ScriptedAcquisition>> {
        let mut source = ScriptedAcquisition::new(self.domain);
        for (generation, ticket, exec) in script {
            source.script_observe(*generation, *ticket, *exec);
        }
        let shared = Rc::new(RefCell::new(source));
        self.coordinator
            .set_native_image_acquisition(Box::new(SharedAcquisition(Rc::clone(&shared))));
        shared
    }

    /// Stage one exec lifecycle record for the owned child through the
    /// real staging path, and prove it decided nothing by itself: no
    /// new binding, no event, the caller still live and scan-pinned,
    /// its settled image still held for history.
    fn stage_child_exec(&mut self, hook_ts_ns: u64) {
        // SAFETY: `DiscoveryRecord` is a plain `repr(C)` integer
        // record; all zeroes is a valid value.
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_EXEC;
        let pid = self.child_id();
        record.pid_tgid = (u64::from(pid) << 32) | u64::from(pid);
        record.hook_ts_ns = hook_ts_ns;
        let now_ns = crate::discovery::caller_registry::now_ns();
        let batch = DiscoveryBatch::scripted(self.domain, vec![record], now_ns);
        let receipt = self.coordinator.stage_native(
            NativeBatch::Lifecycle(batch),
            &mut self.identity,
            now_ns,
        );
        assert_eq!(receipt.decided, 0, "an exec record binds no row");
        assert!(receipt.events.is_empty(), "{:?}", receipt.events);
        assert_eq!(
            self.coordinator.adapter().live_id(pid),
            Some(self.caller),
            "the pinned caller stays live: the scan lane cannot see a same-binary exec"
        );
        assert_eq!(
            self.coordinator
                .adapter()
                .record(self.caller)
                .unwrap()
                .authority,
            ImageAuthority::ScanPinned
        );
        assert!(
            self.coordinator
                .binder
                .holds_image(self.domain, self.caller),
            "the settled image stays held for history; only the commit path may refuse it"
        );
    }

    /// Settle a second domain's coincident-ticket image for the same
    /// owned child through the real staging path: the alias rival the
    /// activation must not confuse with the scene domain's image.
    fn settle_alias_domain(&mut self, domain: NativeDomainId, ticket: u64, exec: u64) {
        self.identity.aliases.push((domain, ticket));
        let (object, endpoint) = self.witness_target;
        let pid = self.child_id();
        let attached_ns = crate::discovery::caller_registry::now_ns();
        self.coordinator.note_extend_receipt(&ExtendReceipt {
            attached: vec![AttachedEndpoint {
                id: endpoint,
                object,
                at_ns: attached_ns,
            }],
            custody: Some(ScopeCustody::CgroupHeld),
            activated_roots: true,
            exec_coverage: Some(ExecCoverage::scripted(domain, 0)),
            ..ExtendReceipt::default()
        });
        let first_ns = crate::discovery::caller_registry::now_ns();
        assert!(first_ns > attached_ns);
        let mut row = WitnessRow::scripted(domain, ticket, exec, object, endpoint, pid, first_ns);
        row.entry_count = 9;
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
                        task_cookie: ticket,
                        exec_id: exec,
                    },
                    object,
                    count: 9,
                }],
            ),
        ] {
            let receipt = self.coordinator.stage_native(
                batch,
                &mut self.identity,
                crate::discovery::caller_registry::now_ns(),
            );
            assert!(receipt.events.is_empty(), "{:?}", receipt.events);
            decided += receipt.decided;
        }
        assert_eq!(decided, 1, "the alias domain settled its rival image");
        assert!(self.coordinator.binder.holds_image(domain, self.caller));
        self.coordinator.commit_batch(false).unwrap();
    }

    /// Rewrite the fixture membership to exactly `pids`.
    fn rewrite_membership(&self, pids: &[u32]) {
        let body: String = pids
            .iter()
            .map(|pid| format!("{pid}\n"))
            .collect::<String>();
        std::fs::write(self.dir.path().join("cgroup.procs"), body).unwrap();
    }

    /// Kill and reap the owned child. Dropping the owned handle kills
    /// and waits; the `None` left behind proves no handle survived.
    fn kill_child(&mut self) -> u32 {
        let pid = self.child_id();
        drop(self.child.take());
        assert!(self.child.is_none());
        pid
    }

    /// Spawn a second owned provider child in the same fixture
    /// directory, mirroring the scene's stopped-driver handshake under
    /// its own ready file.
    fn spawn_second_child(&self, ready_name: &str) -> OwnedStoppedChild {
        let ready = self.dir.path().join(ready_name);
        let provider = self.dir.path().join("scoped-provider.so");
        OwnedStoppedChild::spawn_stopped(
            std::process::Command::new(self.dir.path().join("scoped-driver"))
                .arg("--ready")
                .arg(&ready)
                .arg("--call")
                .arg(&provider)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null()),
            |pid| {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while !ready.exists() {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "second owned provider child did not finish startup"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                // SAFETY: pid names the child retained by spawn_stopped.
                assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) }, 0);
            },
        )
    }

    fn assert_conserved_physical_use(&self) {
        assert_eq!(
            self.coordinator.adapter().live_id(self.child_id()),
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
        let caller = self.caller;
        let pid = self.child_id();
        let action = if migrate_out {
            PassAction::MigrateOut
        } else {
            PassAction::Stable
        };
        self.commit_membership_pass_for(Some(caller), pid, action)
    }

    /// One membership pass for an explicit caller/pid, carrying the
    /// walk state forward so scenes can run several passes. `None`
    /// admits a never-observed pid with no pre-commit cross-checks.
    /// The returned completion carries a default walk state: the live
    /// state stays in the scene.
    fn commit_membership_pass_for(
        &mut self,
        caller: Option<CallerId>,
        pid: u32,
        action: PassAction,
    ) -> CgroupCompletion {
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
        let preparation = collection.preparation(pid).unwrap();
        assert!(preparation.check());
        if let Some(caller) = caller {
            assert_eq!(
                preparation.generation().start_time,
                self.coordinator
                    .adapter()
                    .record(caller)
                    .unwrap()
                    .start_time
            );
        }
        self.coordinator
            .apply_cgroup_collection(collection, crate::discovery::caller_registry::now_ns())
            .unwrap();
        if let Some(caller) = caller {
            assert_eq!(
                self.coordinator.owner_of(caller),
                None,
                "preparation alone cannot activate a native owner"
            );
        }
        let reads = Rc::new(Cell::new(0));
        let returned_reads = Rc::clone(&reads);
        let membership = self.dir.path().join("cgroup.procs");
        // Owned hook data only: the observer is 'static. The kill
        // names the child by pid and reaps it; later hook fires find
        // no process and pass through.
        let hook_pid = self.child.as_ref().map(|child| child.id());
        provider_read_test::observe(
            move || {
                returned_reads.set(returned_reads.get() + 1);
                match action {
                    PassAction::Stable => {}
                    PassAction::MigrateOut => {
                        std::fs::write(&membership, b"").unwrap();
                    }
                    PassAction::KillChild => {
                        if let Some(pid) = hook_pid {
                            // SAFETY: pid named the scene's owned child;
                            // ESRCH/ECHILD mean it is already gone.
                            unsafe {
                                libc::kill(pid as libc::pid_t, libc::SIGKILL);
                                let deadline =
                                    std::time::Instant::now() + std::time::Duration::from_secs(5);
                                loop {
                                    let mut status = 0;
                                    let waited = libc::waitpid(
                                        pid as libc::pid_t,
                                        &mut status,
                                        libc::WNOHANG,
                                    );
                                    if waited == pid as libc::pid_t || waited < 0 {
                                        break;
                                    }
                                    assert!(
                                        std::time::Instant::now() < deadline,
                                        "killed fixture child did not reap"
                                    );
                                    std::thread::sleep(std::time::Duration::from_millis(1));
                                }
                            }
                        }
                    }
                }
            },
            || self.coordinator.commit_batch(false).unwrap(),
        );
        assert!(
            reads.get() > 0,
            "the real retained-provider metadata read ran"
        );
        let completion = self.coordinator.take_cgroup_completion().unwrap();
        let CgroupCompletion {
            state,
            outcome,
            events,
            admitted,
            scan_callers,
        } = completion;
        self.state = state;
        CgroupCompletion {
            state: CgroupWalkState::default(),
            outcome,
            events,
            admitted,
            scan_callers,
        }
    }
}

#[test]
#[ignore = "6.11p2 revisions pending: activation commits but the engine tail is not revised yet; un-ignore with the revision handler"]
fn cgroup_native_owner_stable_retained_member_activates_after_final_permit() {
    // A missing scoped owner path must fail here only after real original
    // binding, fallback and final sampled membership have all succeeded.
    let mut scene = ScopedNativeScene::new();
    let acquired = scene.set_scripted_acquisition(&[
        (1, 41, 1),
        (2, 41, 1),
        (3, 41, 1),
        (4, 41, 1),
        (5, 41, 1),
    ]);
    let tail_before = scene.coordinator.engine.tail_publishes;
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
    assert_eq!(
        acquired.borrow().calls(),
        5,
        "one stored plus four scan-bracket acquisitions, all before the final sample"
    );
    // Publication revisions: the late activation dirtied engine facts
    // after the batch tail ran, so the commit must revise the tail
    // before publishing. RED until packet 2 revisions land.
    assert!(
        scene.coordinator.engine.tail_publishes > tail_before,
        "late activation republishes the engine tail"
    );
    assert_eq!(
        scene.coordinator.engine.published_facts_revision, scene.coordinator.engine.facts_revision,
        "no activation revision is left unpublished"
    );
}

#[test]
fn cgroup_native_owner_migration_during_provider_retention_refuses_activation() {
    // If owner activation moves before the final sample, this twin must fail
    // even though the original live process and native witness stay valid.
    // Leg 1 (migration refusal): preparation runs its owner I/O, but the
    // final sample grants no permit, so the commit releases everything.
    let mut scene = ScopedNativeScene::new();
    let acquired = scene.set_scripted_acquisition(&[
        (1, 41, 1),
        (2, 41, 1),
        (3, 41, 1),
        (4, 41, 1),
        (5, 41, 1),
    ]);
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
    // Forward-pins, flipped by the commit path: owner I/O ran before
    // the sample, and the refusal is a named gap, not silence.
    assert_eq!(
        acquired.borrow().calls(),
        5,
        "preparation ran its owner I/O before the final sample"
    );
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.reason.contains("final-sample permit")
        }),
        "a permitless member refuses by name: {:?}",
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| gap.subject.clone())
            .collect::<Vec<_>>()
    );
    let (owners, reservations, leases) = scene
        .coordinator
        .engine
        .inventory_staged_counts_for_test()
        .unwrap();
    assert_eq!(
        (owners, reservations, leases),
        (0, 0, 0),
        "a refused commit releases its reservation and lease"
    );

    // Leg 1b (death during commit): the member dies while the
    // commit runs, after full preparation. No permit can back it, so
    // the commit releases everything with the member-precise reason.
    let mut dying = ScopedNativeScene::new();
    let acquired = dying.set_scripted_acquisition(&[
        (1, 41, 1),
        (2, 41, 1),
        (3, 41, 1),
        (4, 41, 1),
        (5, 41, 1),
    ]);
    let caller = dying.caller;
    let pid = dying.child_id();
    // The outcome depends on which provider phase the hook fires
    // in; the pins below hold either way.
    let _completion = dying.commit_membership_pass_for(Some(caller), pid, PassAction::KillChild);
    assert_eq!(dying.coordinator.owner_of(caller), None);
    assert_eq!(
        acquired.borrow().calls(),
        5,
        "preparation ran its owner I/O before the death"
    );
    assert!(
        dying.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.reason.contains("final-sample permit")
        }),
        "a dead member refuses by name: {:?}",
        dying
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| gap.subject.clone())
            .collect::<Vec<_>>()
    );
    let (owners, reservations, leases) = dying
        .coordinator
        .engine
        .inventory_staged_counts_for_test()
        .unwrap();
    assert_eq!(
        (owners, reservations, leases),
        (0, 0, 0),
        "a death-refused commit releases its reservation and lease"
    );
    drop(dying);

    // Leg 2 (positive control): a stable member activates, proving the
    // commit path runs end to end. RED pre-fix.
    let mut control = ScopedNativeScene::new();
    let acquired = control.set_scripted_acquisition(&[
        (1, 41, 1),
        (2, 41, 1),
        (3, 41, 1),
        (4, 41, 1),
        (5, 41, 1),
    ]);
    let completion = control.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(completion.admitted, 0);
    assert_eq!(completion.scan_callers, 1);
    control.assert_conserved_physical_use();
    let owner = control.coordinator.owner_of(control.caller).expect(
        "control: a stable retained-root member with an original native witness must activate",
    );
    let epochs = control
        .coordinator
        .engine
        .inventory_owner_epochs(owner)
        .unwrap();
    assert_eq!(
        epochs.image_state,
        super::super::inventory::ImageCheck::Exact
    );
    assert_eq!(epochs.requested, epochs.serviced);
    assert!(epochs.complete.is_some());
    assert_eq!(acquired.borrow().calls(), 5);
    let (owners, reservations, leases) = control
        .coordinator
        .engine
        .inventory_staged_counts_for_test()
        .unwrap();
    assert_eq!(
        (owners, reservations, leases),
        (1, 0, 0),
        "activation retains exactly its owner"
    );
}

#[test]
fn cgroup_native_owner_same_binary_exec_refuses_activation() {
    // Leg 1 (exec refusal): a same-binary re-exec the scan lane cannot
    // see must still refuse activation. The permit and the pidfd stay
    // green while the image advanced, so only the native image veto
    // stands between the commit and the wrong image.
    let mut scene = ScopedNativeScene::new();
    let first_seen = scene
        .coordinator
        .adapter()
        .record(scene.caller)
        .unwrap()
        .first_seen_ns;
    scene.stage_child_exec(first_seen + 1);
    let acquired = scene.set_scripted_acquisition(&[(1, 41, 1)]);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(
        completion.scan_callers, 1,
        "the final sample granted its permit"
    );
    assert_eq!(scene.coordinator.owner_of(scene.caller), None);
    assert_eq!(
        scene
            .coordinator
            .adapter()
            .record(scene.caller)
            .unwrap()
            .authority,
        ImageAuthority::ScanPinned,
        "the scan fallback stands: no exact authority for an ended image"
    );
    scene.assert_conserved_physical_use();
    // Forward-pins, flipped by the commit path: the veto fires before
    // any acquisition, and the refusal is a named gap, not silence.
    assert_eq!(
        acquired.borrow().calls(),
        0,
        "the image veto fires before any acquisition"
    );
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.reason.contains("expected native image")
        }),
        "an ended image refuses by name: {:?}",
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| gap.subject.clone())
            .collect::<Vec<_>>()
    );

    // Leg 2 (positive control): the same scene without the exec
    // activates. RED pre-fix.
    let mut control = ScopedNativeScene::new();
    let acquired = control.set_scripted_acquisition(&[
        (1, 41, 1),
        (2, 41, 1),
        (3, 41, 1),
        (4, 41, 1),
        (5, 41, 1),
    ]);
    let completion = control.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let owner = control
        .coordinator
        .owner_of(control.caller)
        .expect("control: a stable member with no exec activates");
    let epochs = control
        .coordinator
        .engine
        .inventory_owner_epochs(owner)
        .unwrap();
    assert_eq!(
        epochs.image_state,
        super::super::inventory::ImageCheck::Exact
    );
    assert!(epochs.complete.is_some());
    assert_eq!(acquired.borrow().calls(), 5);
}

#[test]
fn cgroup_native_owner_cross_domain_alias_activates_exact_domain() {
    // Leg 1 (alias discrimination): a second domain settles the
    // coincident ticket as its own image; activation must still bind
    // the scene domain's exact image, never the alias. RED pre-fix.
    let mut scene = ScopedNativeScene::new();
    let alias = NativeDomainId::mint();
    scene.settle_alias_domain(alias, 41, 5);
    let acquired = scene.set_scripted_acquisition(&[
        (1, 41, 1),
        (2, 41, 1),
        (3, 41, 1),
        (4, 41, 1),
        (5, 41, 1),
    ]);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let owner = scene
        .coordinator
        .owner_of(scene.caller)
        .expect("a settled exact image activates despite a settled cross-domain alias");
    let authority = scene
        .coordinator
        .adapter()
        .record(scene.caller)
        .unwrap()
        .authority;
    let ImageAuthority::NativeExact { image } = authority else {
        panic!("activation installs native-exact authority, not {authority:?}");
    };
    assert!(
        image.belongs_to(scene.domain),
        "activation binds the scene domain's image"
    );
    assert!(
        !image.belongs_to(alias),
        "the alias domain's image never activates here"
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
    assert!(epochs.complete.is_some());
    assert_eq!(acquired.borrow().calls(), 5);
    // Both settled images keep their physical use, max-wins across
    // pairs (never summed): the alias pair's 9 surfaces over the
    // scene pair's 7, while activation still binds the scene image.
    let edge = scene
        .coordinator
        .registry()
        .edge(scene.caller, scene.module)
        .unwrap();
    assert_eq!(edge.entry_count, 9);
    assert_eq!(scene.coordinator.registry().witness_census().bound, 2);
    assert_eq!(scene.coordinator.registry().witness_placement().edge, 2);

    // Leg 2 (positive control): no alias, same activation.
    let mut control = ScopedNativeScene::new();
    let acquired = control.set_scripted_acquisition(&[
        (1, 41, 1),
        (2, 41, 1),
        (3, 41, 1),
        (4, 41, 1),
        (5, 41, 1),
    ]);
    let completion = control.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let owner = control
        .coordinator
        .owner_of(control.caller)
        .expect("control: a stable member with no alias activates");
    let epochs = control
        .coordinator
        .engine
        .inventory_owner_epochs(owner)
        .unwrap();
    assert_eq!(
        epochs.image_state,
        super::super::inventory::ImageCheck::Exact
    );
    assert!(epochs.complete.is_some());
    assert_eq!(acquired.borrow().calls(), 5);
}

#[test]
fn cgroup_native_owner_finished_domain_refuses_activation() {
    // Leg 1 (finish refusal): a finished domain cannot supply fresh
    // owner authority even though its old binding stays for history.
    // A scripted observation sits ready but must never be consumed.
    let mut scene = ScopedNativeScene::new();
    let now_ns = crate::discovery::caller_registry::now_ns();
    let receipt = scene.coordinator.stage_native(
        NativeBatch::Finish {
            domain: scene.domain,
        },
        &mut scene.identity,
        now_ns,
    );
    assert!(receipt.events.is_empty(), "{:?}", receipt.events);
    assert!(
        scene
            .coordinator
            .binder
            .holds_image(scene.domain, scene.caller),
        "finish keeps the old binding for history"
    );
    let acquired = scene.set_scripted_acquisition(&[(1, 41, 1)]);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(
        completion.scan_callers, 1,
        "the final sample granted its permit"
    );
    assert_eq!(scene.coordinator.owner_of(scene.caller), None);
    scene.assert_conserved_physical_use();
    // Forward-pins, flipped by the commit path.
    assert_eq!(
        acquired.borrow().calls(),
        0,
        "a finished domain vetoes before any acquisition"
    );
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.reason.contains("expected native image")
        }),
        "a finished domain refuses by name: {:?}",
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| gap.subject.clone())
            .collect::<Vec<_>>()
    );

    // Leg 2 (acquisition failure): without finish, a failed
    // observation refuses after exactly one attempt, never a retry.
    let mut failed = ScopedNativeScene::new();
    let mut source = ScriptedAcquisition::new(failed.domain);
    source.script_fail("lens cap on");
    let shared = Rc::new(RefCell::new(source));
    failed
        .coordinator
        .set_native_image_acquisition(Box::new(SharedAcquisition(Rc::clone(&shared))));
    let completion = failed.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(failed.coordinator.owner_of(failed.caller), None);
    assert_eq!(
        shared.borrow().calls(),
        1,
        "one genuine attempt, never a retry storm"
    );
    assert!(
        failed.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.reason.contains("observation unavailable")
        }),
        "a failed observation refuses by name: {:?}",
        failed
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| gap.subject.clone())
            .collect::<Vec<_>>()
    );

    // Leg 3 (no acquisition): without any handle the scan fallback
    // stands with a named unavailable gap, never a silent skip.
    let mut bare = ScopedNativeScene::new();
    let completion = bare.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(bare.coordinator.owner_of(bare.caller), None);
    assert!(
        bare.coordinator
            .registry()
            .gaps()
            .iter()
            .any(|gap| { gap.subject == "native owner activation unavailable" }),
        "a missing handle discloses itself: {:?}",
        bare.coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| gap.subject.clone())
            .collect::<Vec<_>>()
    );

    // Leg 4 (positive control): an unfinished domain with a working
    // handle activates. RED pre-fix when the refusal legs pass.
    let mut control = ScopedNativeScene::new();
    let acquired = control.set_scripted_acquisition(&[
        (1, 41, 1),
        (2, 41, 1),
        (3, 41, 1),
        (4, 41, 1),
        (5, 41, 1),
    ]);
    let completion = control.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let owner = control
        .coordinator
        .owner_of(control.caller)
        .expect("control: an unfinished domain activates");
    let epochs = control
        .coordinator
        .engine
        .inventory_owner_epochs(owner)
        .unwrap();
    assert_eq!(
        epochs.image_state,
        super::super::inventory::ImageCheck::Exact
    );
    assert!(epochs.complete.is_some());
    assert_eq!(acquired.borrow().calls(), 5);
}

#[test]
fn cgroup_native_owner_reused_generation_never_inherits_native_image() {
    // A new generation under observation must never inherit the old
    // image's native authority. Same PID numbers cannot be forced
    // deterministically from userspace, so the twin kills the settled
    // child and admits a successor generation: the commit keys on
    // (caller, generation), never on PID numbers — the same-number
    // veto itself is pinned by the binder unit twin
    // `expected_owner_image_rejects_replaced_live_caller_at_same_pid`.
    // Leg 1: the settled child activates. RED pre-fix.
    let mut scene = ScopedNativeScene::new();
    let acquired = scene.set_scripted_acquisition(&[
        (1, 41, 1),
        (2, 41, 1),
        (3, 41, 1),
        (4, 41, 1),
        (5, 41, 1),
    ]);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let first_owner = scene
        .coordinator
        .owner_of(scene.caller)
        .expect("leg 1: the settled child activates before the reuse");
    assert_eq!(acquired.borrow().calls(), 5);

    // Leg 2: the settled child dies; a successor generation arrives
    // under observation and must start scan-pinned, bound to no image.
    let dead_pid = scene.kill_child();
    assert_ne!(dead_pid, 0);
    let successor = scene.spawn_second_child("ready-b");
    let successor_pid = successor.id();
    scene.child = Some(successor);
    scene.rewrite_membership(&[successor_pid]);
    let completion = scene.commit_membership_pass_for(None, successor_pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(
        completion.admitted, 1,
        "the successor generation is admitted"
    );
    assert_eq!(completion.scan_callers, 1);
    let successor_caller = scene
        .coordinator
        .adapter()
        .live_id(successor_pid)
        .expect("the successor generation is admitted");
    assert_ne!(
        successor_caller, scene.caller,
        "a new generation is a new caller, whatever number it carries"
    );
    assert_eq!(
        scene
            .coordinator
            .adapter()
            .record(successor_caller)
            .unwrap()
            .authority,
        ImageAuthority::ScanPinned,
        "the successor starts scan-pinned: it inherits no native image"
    );
    assert_eq!(scene.coordinator.owner_of(successor_caller), None);
    assert!(
        scene
            .coordinator
            .adapter()
            .record(scene.caller)
            .unwrap()
            .retired,
        "the dead generation retires"
    );
    assert_eq!(
        scene.coordinator.owner_of(scene.caller),
        Some(first_owner),
        "activation does not invalidate: refresh/suspend (packet 3) owns it"
    );
    assert_eq!(
        scene.coordinator.registry().witness_census().bound,
        1,
        "the settled row stays bound for history"
    );
    assert!(
        scene.coordinator.registry().gaps().iter().all(|gap| {
            gap.subject != "native owner activation refused" || gap.pid != Some(successor_pid)
        }),
        "a fresh pid is not a candidate: no refusal spam, silence is honest"
    );

    // Leg 3: a further pass finds the successor with a caller but no
    // settled image, and refuses it by name. The veto fires before
    // any acquisition, so the exhausted script stays untouched.
    let completion =
        scene.commit_membership_pass_for(Some(successor_caller), successor_pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(scene.coordinator.owner_of(successor_caller), None);
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.pid == Some(successor_pid)
                && gap.reason.contains("expected native image")
        }),
        "the unsettled successor refuses by name: {:?}",
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| gap.subject.clone())
            .collect::<Vec<_>>()
    );
}
