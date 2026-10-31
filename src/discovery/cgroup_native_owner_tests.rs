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
    /// Extra (allocation, ticket) answers for multi-member twins:
    /// each additional member's own original allocation answers its
    /// own ticket in the scene domain. Empty for single-member scenes.
    extra_pins: Vec<(Arc<PidPin>, u64)>,
    queries: usize,
}

impl NativeIdentity<PidPin> for OriginalNativeIdentity {
    fn owner_image(&mut self, _: u32) -> Option<BoundImage> {
        None
    }

    fn query_cookie(&mut self, domain: NativeDomainId, pin: &PidPin) -> CookieQuery {
        let ticket = if std::ptr::eq(pin, self.original.as_ref()) {
            if domain == self.domain {
                Some(41)
            } else {
                self.aliases
                    .iter()
                    .find(|(alias, _)| *alias == domain)
                    .map(|(_, ticket)| *ticket)
            }
        } else if domain == self.domain {
            self.extra_pins
                .iter()
                .find(|(extra, _)| std::ptr::eq(pin, extra.as_ref()))
                .map(|(_, ticket)| *ticket)
        } else {
            None
        };
        // Hard allocation-identity gate: a query in a supported domain
        // must arrive through the original retained allocation, or an
        // explicitly registered extra member's retained allocation for
        // that domain. A reopened or replacement allocation fails here
        // instead of degrading into ordinary unavailable evidence.
        // Only genuinely foreign domains stay unavailable.
        assert!(
            ticket.is_some()
                || (domain != self.domain
                    && !self.aliases.iter().any(|(alias, _)| *alias == domain)),
            "native query in a supported domain arrived through an unexpected allocation"
        );
        let Some(ticket) = ticket else {
            return CookieQuery::Unavailable("another native capture domain".into());
        };
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
    /// The scripted acquisition handle the scene threads through
    /// the production-shaped commit entry; `None` is the
    /// handle-less path.
    acquisition: Option<SharedAcquisition>,
    identity: OriginalNativeIdentity,
    caller: CallerId,
    module: ModuleId,
    domain: NativeDomainId,
    witness_target: (AttachObjectId, EndpointId),
    state: CgroupWalkState,
    child: Option<OwnedStoppedChild>,
    extra_children: Vec<OwnedStoppedChild>,
    dir: tempfile::TempDir,
}

/// What the provider-read hook does while the commit runs:
/// nothing, migrate the member(s) out, or kill and reap the child.
#[derive(Clone, Copy)]
enum PassAction {
    Stable,
    MigrateOut,
    /// Migrate every member out except `0`: the retained member keeps
    /// its final-sample permit while the transaction goes incomplete.
    RetainOnly(u32),
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
            extra_pins: Vec::new(),
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
            acquisition: None,
            identity,
            caller,
            module,
            domain,
            witness_target: (endpoint.object, endpoint.id),
            state: completion.state,
            child: Some(child),
            extra_children: Vec::new(),
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
        self.acquisition = Some(SharedAcquisition(Rc::clone(&shared)));
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
        let provider = self.dir.path().join("scoped-provider.so");
        self.spawn_second_child_with_provider(ready_name, &provider)
    }

    /// Compile a second provider with distinct bytes and file identity
    /// for the distinct-provider twin. Mirrors the scene's provider
    /// build with a different legacy minor so the bytes differ too.
    fn build_second_provider(&self) -> std::path::PathBuf {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let out = self.dir.path().join("scoped-provider-b.so");
        let mut cmd = std::process::Command::new("gcc");
        cmd.args(["-shared", "-fPIC", "-DLEGACY_MINOR=41"])
            .arg("-o")
            .arg(&out)
            .arg(manifest.join("crates/discover/tests/fixture/version_matrix.c"));
        assert!(
            cmd.status().unwrap().success(),
            "gcc failed for scoped-provider-b.so: {cmd:?}"
        );
        out
    }

    /// Spawn a second owned provider child mapping `provider`,
    /// mirroring the scene's stopped-driver handshake under its own
    /// ready file.
    fn spawn_second_child_with_provider(
        &self,
        ready_name: &str,
        provider: &std::path::Path,
    ) -> OwnedStoppedChild {
        let ready = self.dir.path().join(ready_name);
        OwnedStoppedChild::spawn_stopped(
            std::process::Command::new(self.dir.path().join("scoped-driver"))
                .arg("--ready")
                .arg(&ready)
                .arg("--call")
                .arg(provider)
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
                    PassAction::RetainOnly(pid) => {
                        std::fs::write(&membership, format!("{pid}\n")).unwrap();
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
            || self.commit_scene_batch(),
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
    failed.acquisition = Some(SharedAcquisition(Rc::clone(&shared)));
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
    // stands with the standing unavailable disclosure the installed
    // H6 consumer recognizes, never a silent skip.
    let mut bare = ScopedNativeScene::new();
    let completion = bare.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(bare.coordinator.owner_of(bare.caller), None);
    assert!(
        bare.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation unavailable"
                && gap.reason
                    == "no image acquisition handle is installed; scan-pinned fallback retained"
        }),
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
    let _first_owner = scene
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
        None,
        "the dead caller's owner is suspended on the next complete pass"
    );
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner suspended"
                && gap.caller == Some(scene.caller)
                && gap.pid == Some(dead_pid)
                && gap.reason == "the caller retired; its native owner was released"
        }),
        "the suspend reports by name: {:?}",
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .collect::<Vec<_>>()
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

// --- Second-pass residual twins -------------------------------------------
// R1 reads no provider metadata after the final sample; R2 defers the
// second prepared member of a transaction; R3 keeps the standing
// deferral disclosure on the handle-less path; R4 publishes engine
// revisions dirtied by refused work. The extra negatives pin the
// (permit, incomplete-transaction) fence branch and the fresh
// observation mismatch rollback at activation.

use std::collections::BTreeSet;
use std::path::Path;

/// Provider metadata reads around one observed pass, tagged by the
/// transaction's final membership sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MetadataReads {
    pre_sample: u64,
    post_sample: u64,
}

/// Kill and reap the owned fixture child named by `pid` from
/// inside a commit hook: the synchronous reap makes later
/// liveness checks in the same commit observe the death
/// deterministically.
fn kill_and_reap_owned_child(pid: u32) {
    // SAFETY: pid named the scene's owned child; ESRCH/ECHILD
    // mean it is already gone.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let mut status = 0;
            let waited = libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG);
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

impl ScopedNativeScene {
    /// One membership pass like `commit_membership_pass_for`, returning
    /// the batch receipt and the observed pre/post-sample provider
    /// metadata reads. The metadata observer wraps the whole commit;
    /// the provider-read hook still drives `action` and proves the
    /// real retained-provider metadata read ran.
    fn commit_observed_pass(
        &mut self,
        caller: Option<CallerId>,
        pid: u32,
        action: PassAction,
    ) -> (CgroupCompletion, BatchReceipt, MetadataReads) {
        use crate::discovery::identity::provider_metadata_read_test;
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
        let pre_sample = Rc::new(Cell::new(0u64));
        let pre_counted = Rc::clone(&pre_sample);
        let post_sample = Rc::new(Cell::new(0u64));
        let post_counted = Rc::clone(&post_sample);
        let membership = self.dir.path().join("cgroup.procs");
        let hook_pid = self.child.as_ref().map(|child| child.id());
        let receipt = provider_metadata_read_test::observe(
            move |post| {
                if post {
                    post_counted.set(post_counted.get() + 1);
                } else {
                    pre_counted.set(pre_counted.get() + 1);
                }
            },
            || {
                provider_read_test::observe(
                    move || {
                        returned_reads.set(returned_reads.get() + 1);
                        match action {
                            PassAction::Stable => {}
                            PassAction::MigrateOut => {
                                std::fs::write(&membership, b"").unwrap();
                            }
                            PassAction::RetainOnly(pid) => {
                                std::fs::write(&membership, format!("{pid}\n")).unwrap();
                            }
                            PassAction::KillChild => {
                                if let Some(pid) = hook_pid {
                                    // SAFETY: pid named the scene's owned child;
                                    // ESRCH/ECHILD mean it is already gone.
                                    unsafe {
                                        libc::kill(pid as libc::pid_t, libc::SIGKILL);
                                        let deadline = std::time::Instant::now()
                                            + std::time::Duration::from_secs(5);
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
                    || self.commit_scene_batch(),
                )
            },
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
        let completion = CgroupCompletion {
            state: CgroupWalkState::default(),
            outcome,
            events,
            admitted,
            scan_callers,
        };
        (
            completion,
            receipt,
            MetadataReads {
                pre_sample: pre_sample.get(),
                post_sample: post_sample.get(),
            },
        )
    }

    /// Commit the staged batch through the scene's one commit entry:
    /// the membership helpers and the refresh/suspend twins all commit
    /// here, so the acquisition handle delivery has a single seam.
    fn commit_scene_batch(&mut self) -> BatchReceipt {
        let mut acquisition = self.acquisition.clone();
        let handle = acquisition
            .as_mut()
            .map(|shared| shared as &mut dyn ImageAcquisition);
        self.coordinator
            .commit_batch_with_acquisition(false, None, handle)
            .unwrap()
    }

    /// One membership pass whose scoped commit runs `at_gate` at
    /// each commit decision point (see `scoped_commit_gate_test`):
    /// an external event — member death, operator stop — lands at
    /// one exact phase between the coordinator's own checks. The
    /// caller supplies the collection control so a gate closure
    /// can latch cancellation through a retained clone. Mirrors
    /// `commit_membership_pass_for` without its caller cross-checks.
    fn commit_gated_pass(
        &mut self,
        pid: u32,
        control: CollectionControl,
        at_gate: impl FnMut(super::scoped_commit_gate_test::Phase) + 'static,
    ) -> CgroupCompletion {
        let collection = self
            .coordinator
            .cgroup_collector(
                std::mem::take(&mut self.state),
                CgroupWalkLimits::default(),
                control,
                None,
            )
            .unwrap()();
        let preparation = collection.preparation(pid).unwrap();
        assert!(preparation.check());
        self.coordinator
            .apply_cgroup_collection(collection, crate::discovery::caller_registry::now_ns())
            .unwrap();
        super::scoped_commit_gate_test::observe(at_gate, || self.commit_scene_batch());
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

    /// One pass over the membership file exactly as the twin last
    /// rewrote it, with no member preparation to assert: collect,
    /// apply, commit, and carry the walk state forward. Suspend twins
    /// use this after rewriting a member out (or emptying the file);
    /// the completion proves whether the rewritten membership still
    /// forms a complete transaction.
    fn commit_rewritten_membership_pass(&mut self) -> CgroupCompletion {
        let collection = self
            .coordinator
            .cgroup_collector(
                std::mem::take(&mut self.state),
                CgroupWalkLimits::default(),
                CollectionControl::new(None),
                None,
            )
            .unwrap()();
        self.coordinator
            .apply_cgroup_collection(collection, crate::discovery::caller_registry::now_ns())
            .unwrap();
        self.commit_scene_batch();
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

    /// Admit an already spawned second member mapping the scene's
    /// shared provider, and settle its native witness under `ticket`
    /// with `count` physical uses. Returns the member's caller, pid,
    /// and the shared witness target its rows name.
    fn admit_and_settle_second_member(
        &mut self,
        child: OwnedStoppedChild,
        ticket: u64,
        count: u64,
    ) -> (CallerId, u32, (AttachObjectId, EndpointId)) {
        let second_pid = child.id();
        self.extra_children.push(child);
        let first_pid = self.child_id();
        assert_ne!(first_pid, second_pid);
        self.rewrite_membership(&[first_pid, second_pid]);
        let (completion, _, _) = self.commit_observed_pass(None, second_pid, PassAction::Stable);
        assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
        assert_eq!(completion.admitted, 1, "the second member is admitted");
        assert_eq!(completion.scan_callers, 2);
        let second_caller = self
            .coordinator
            .adapter()
            .live_id(second_pid)
            .expect("the second member is admitted");
        assert_ne!(second_caller, self.caller);
        assert_eq!(
            self.coordinator
                .adapter()
                .record(second_caller)
                .unwrap()
                .authority,
            ImageAuthority::ScanPinned,
            "the second member starts scan-pinned"
        );
        assert_eq!(self.coordinator.owner_of(second_caller), None);
        let second_pin = self
            .coordinator
            .adapter()
            .shared_semantic_custody(second_caller)
            .expect("retain the second member's original allocation without reopening its PID");
        self.identity.extra_pins.push((second_pin, ticket));
        let delta = self.coordinator.take_target_delta();
        assert!(
            delta.is_empty(),
            "the shared provider adds no new attach targets: {} endpoints",
            delta.endpoints.len()
        );
        let (object, endpoint) = self.witness_target;
        let first_ns = crate::discovery::caller_registry::now_ns();
        let mut row = WitnessRow::scripted(
            self.domain,
            ticket,
            1,
            object,
            endpoint,
            second_pid,
            first_ns,
        );
        row.entry_count = count;
        let queries_before = self.identity.queries;
        let mut decided = 0;
        for batch in [
            native_read(self.domain, vec![row], Vec::new()),
            NativeBatch::Lifecycle(DiscoveryBatch::scripted(
                self.domain,
                Vec::new(),
                crate::discovery::caller_registry::now_ns(),
            )),
            native_read(
                self.domain,
                Vec::new(),
                vec![CallerCountUpdate {
                    image: p11scope_ebpf_common::ImageIdentity {
                        task_cookie: ticket,
                        exec_id: 1,
                    },
                    object,
                    count,
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
        assert_eq!(decided, 1, "the real binder decided the second witness");
        assert!(self.identity.queries > queries_before);
        self.coordinator.commit_batch(false).unwrap();
        assert!(
            self.coordinator
                .binder
                .holds_image(self.domain, second_caller),
            "the second member's image settles for activation"
        );
        let edges: Vec<_> = self
            .coordinator
            .registry()
            .edges_of(second_caller)
            .collect();
        assert_eq!(edges.len(), 1, "one shared mapped provider feeds the twin");
        assert_eq!(
            edges[0].module, self.module,
            "both members share one module"
        );
        assert_eq!(edges[0].entry_count, count);
        assert_eq!(edges[0].mapping, MappingState::Mapped);
        (second_caller, second_pid, self.witness_target)
    }

    /// Admit an already spawned second member mapping a DIFFERENT
    /// provider file (`provider`, already registered as a module hint),
    /// and settle its native witness under `ticket` with `count`
    /// physical uses naming the new attach target. Returns the
    /// member's caller, pid, and its own witness target. The distinct
    /// provider adds new attach targets and resolves to a distinct
    /// module; the shared-provider twin keeps the helper above.
    fn admit_and_settle_distinct_member(
        &mut self,
        child: OwnedStoppedChild,
        provider: &std::path::Path,
        ticket: u64,
        count: u64,
    ) -> (CallerId, u32, (AttachObjectId, EndpointId)) {
        let second_pid = child.id();
        self.extra_children.push(child);
        let first_pid = self.child_id();
        assert_ne!(first_pid, second_pid);
        self.rewrite_membership(&[first_pid, second_pid]);
        let (completion, _, _) = self.commit_observed_pass(None, second_pid, PassAction::Stable);
        assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
        assert_eq!(completion.admitted, 1, "the second member is admitted");
        assert_eq!(completion.scan_callers, 2);
        let second_caller = self
            .coordinator
            .adapter()
            .live_id(second_pid)
            .expect("the second member is admitted");
        assert_ne!(second_caller, self.caller);
        assert_eq!(
            self.coordinator
                .adapter()
                .record(second_caller)
                .unwrap()
                .authority,
            ImageAuthority::ScanPinned,
            "the second member starts scan-pinned"
        );
        assert_eq!(self.coordinator.owner_of(second_caller), None);
        let second_pin = self
            .coordinator
            .adapter()
            .shared_semantic_custody(second_caller)
            .expect("retain the second member's original allocation without reopening its PID");
        self.identity.extra_pins.push((second_pin, ticket));
        let delta = self.coordinator.take_target_delta();
        assert!(
            !delta.is_empty(),
            "the distinct provider adds new attach targets"
        );
        assert_eq!(
            delta.objects.len(),
            1,
            "exactly one new attach object for the distinct provider: {:?}",
            delta.objects
        );
        let (first_object, _) = self.witness_target;
        assert_ne!(
            delta.objects[0], first_object,
            "the distinct provider resolves to a distinct attach object"
        );
        assert!(
            !delta.endpoints.is_empty(),
            "the distinct provider adds new endpoints"
        );
        for endpoint in &delta.endpoints {
            assert_ne!(
                endpoint.object, first_object,
                "no new endpoint reuses the first provider's object"
            );
            let target = self
                .coordinator
                .attach_set
                .target(endpoint.object)
                .expect("a new endpoint names a retained target");
            assert_eq!(
                Path::new(target.path()),
                provider,
                "the new endpoints attach the distinct provider"
            );
        }
        let target = (delta.endpoints[0].object, delta.endpoints[0].id);
        let first_ns = crate::discovery::caller_registry::now_ns();
        let mut row = WitnessRow::scripted(
            self.domain,
            ticket,
            1,
            target.0,
            target.1,
            second_pid,
            first_ns,
        );
        row.entry_count = count;
        let queries_before = self.identity.queries;
        let mut decided = 0;
        for batch in [
            native_read(self.domain, vec![row], Vec::new()),
            NativeBatch::Lifecycle(DiscoveryBatch::scripted(
                self.domain,
                Vec::new(),
                crate::discovery::caller_registry::now_ns(),
            )),
            native_read(
                self.domain,
                Vec::new(),
                vec![CallerCountUpdate {
                    image: p11scope_ebpf_common::ImageIdentity {
                        task_cookie: ticket,
                        exec_id: 1,
                    },
                    object: target.0,
                    count,
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
        assert_eq!(decided, 1, "the real binder decided the second witness");
        assert!(self.identity.queries > queries_before);
        self.coordinator.commit_batch(false).unwrap();
        assert!(
            self.coordinator
                .binder
                .holds_image(self.domain, second_caller),
            "the second member's image settles for activation"
        );
        let edges: Vec<_> = self
            .coordinator
            .registry()
            .edges_of(second_caller)
            .collect();
        assert_eq!(
            edges.len(),
            1,
            "one distinct mapped provider feeds the twin"
        );
        assert_ne!(
            edges[0].module, self.module,
            "distinct providers resolve to distinct modules"
        );
        assert_eq!(edges[0].entry_count, count);
        assert_eq!(edges[0].mapping, MappingState::Mapped);
        (second_caller, second_pid, target)
    }

    /// Committed engine module facts as (view, path) pairs.
    fn engine_module_facts(&self) -> BTreeSet<(u32, String)> {
        self.coordinator
            .engine
            .modules
            .iter()
            .map(|module| (module.scanned.view.0, module.scanned.path.clone()))
            .collect()
    }

    /// Committed views naming `provider`: which owners' facts survived.
    fn engine_module_views_for(&self, provider: &Path) -> BTreeSet<u32> {
        self.coordinator
            .engine
            .modules
            .iter()
            .filter(|module| Path::new(&module.scanned.path) == provider)
            .map(|module| module.scanned.view.0)
            .collect()
    }

    /// Attach-set endpoints currently retained for `provider`.
    fn provider_endpoint_count(&self, provider: &Path) -> usize {
        self.coordinator
            .attach_set
            .endpoints()
            .filter(|endpoint| {
                self.coordinator
                    .attach_set
                    .target(endpoint.object)
                    .is_some_and(|target| Path::new(target.path()) == provider)
            })
            .count()
    }

    /// Pin-claim object ids for `owner` mapped to their pinned paths:
    /// which physical providers the owner's committed facts retain.
    fn owner_claim_paths(&self, owner: ProcessViewId) -> BTreeSet<String> {
        let claims = self
            .coordinator
            .engine
            .pinned
            .view_claims(owner)
            .unwrap_or_else(|| panic!("owner {} retains pin claims", owner.0));
        let by_id: std::collections::BTreeMap<_, _> = self
            .coordinator
            .engine
            .pinned
            .pinned()
            .map(|summary| (summary.id, summary.path.to_string()))
            .collect();
        claims
            .tables
            .iter()
            .chain(claims.targets.iter().map(|(id, _)| id))
            .chain(&claims.pins)
            .filter_map(|id| by_id.get(id).cloned())
            .collect()
    }
}

#[test]
fn cgroup_native_owner_activation_reads_no_provider_metadata_after_final_sample() {
    // R1 positive: a stable activation commits, and the permit-backed
    // commit performs no provider metadata reads after the final
    // sample. RED while activation revalidates pins post-sample.
    let mut scene = ScopedNativeScene::new();
    let acquired = scene.set_scripted_acquisition(&[
        (1, 41, 1),
        (2, 41, 1),
        (3, 41, 1),
        (4, 41, 1),
        (5, 41, 1),
    ]);
    let (completion, receipt, reads) =
        scene.commit_observed_pass(Some(scene.caller), scene.child_id(), PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    scene.assert_conserved_physical_use();
    let owner = scene
        .coordinator
        .owner_of(scene.caller)
        .expect("a stable retained-root member activates");
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
    assert_eq!(
        acquired.borrow().calls(),
        5,
        "all image acquisitions precede the final sample"
    );
    assert!(
        reads.pre_sample > 0,
        "pre-sample provider validation really ran: {reads:?}"
    );
    assert_eq!(
        reads.post_sample, 0,
        "the permit-backed commit performs no provider metadata reads: {reads:?}"
    );
    assert_eq!(
        receipt.engine_facts, receipt.engine_published,
        "activation revisions publish"
    );
}

#[test]
fn cgroup_native_owner_refused_pass_reads_no_provider_metadata_after_final_sample() {
    // R1 failure controls: migration and death refuse activation, and
    // neither refusal path reads provider metadata after the final
    // sample. Both legs pass pre-fix (no commit is reached); they pin
    // the refusal paths while the positive above proves the observer.
    let mut scene = ScopedNativeScene::new();
    let acquired = scene.set_scripted_acquisition(&[
        (1, 41, 1),
        (2, 41, 1),
        (3, 41, 1),
        (4, 41, 1),
        (5, 41, 1),
    ]);
    let (completion, _, reads) =
        scene.commit_observed_pass(Some(scene.caller), scene.child_id(), PassAction::MigrateOut);
    assert!(matches!(
        completion.outcome,
        ScopedCollectionOutcome::Incomplete(_)
    ));
    assert_eq!(scene.coordinator.owner_of(scene.caller), None);
    scene.assert_conserved_physical_use();
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.reason.contains("final-sample permit")
        }),
        "a permitless member refuses by name"
    );
    let (owners, reservations, leases) = scene
        .coordinator
        .engine
        .inventory_staged_counts_for_test()
        .unwrap();
    assert_eq!((owners, reservations, leases), (0, 0, 0));
    assert_eq!(acquired.borrow().calls(), 5);
    assert!(
        reads.pre_sample > 0,
        "preparation ran its provider validation: {reads:?}"
    );
    assert_eq!(
        reads.post_sample, 0,
        "the migration refusal reads no provider metadata post-sample: {reads:?}"
    );

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
    let (_, _, reads) = dying.commit_observed_pass(Some(caller), pid, PassAction::KillChild);
    assert_eq!(dying.coordinator.owner_of(caller), None);
    assert!(
        dying.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.reason.contains("final-sample permit")
        }),
        "a dead member refuses by name"
    );
    let (owners, reservations, leases) = dying
        .coordinator
        .engine
        .inventory_staged_counts_for_test()
        .unwrap();
    assert_eq!((owners, reservations, leases), (0, 0, 0));
    assert_eq!(acquired.borrow().calls(), 5);
    assert!(
        reads.pre_sample > 0,
        "preparation ran its provider validation: {reads:?}"
    );
    assert_eq!(
        reads.post_sample, 0,
        "the death refusal reads no provider metadata post-sample: {reads:?}"
    );
    drop(dying);
}

#[test]
fn cgroup_native_owner_second_prepared_member_defers_with_first_intact() {
    // R2 distinct-provider positive: two members map DIFFERENT
    // provider files with distinct nonempty physical identities. Both
    // prepare against the same committed state; the first (pid order)
    // activates while the second defers with a named refusal and
    // released state, and the first member's engine facts are not
    // overwritten. A follow-up pass activates the deferred member;
    // both owners keep nonempty pin claims and modules on their own
    // providers, their published facts survive, and no pre-existing
    // fact is lost. The shared-provider control lives in the next
    // twin. RED while the members share one provider or a commit
    // replaces the other member's facts.
    let mut scene = ScopedNativeScene::new();
    let provider_a = scene.dir.path().join("scoped-provider.so");
    let provider_b = scene.build_second_provider();
    assert_ne!(provider_a, provider_b, "the twin maps two provider files");
    let bytes_a = std::fs::read(&provider_a).unwrap();
    let bytes_b = std::fs::read(&provider_b).unwrap();
    assert!(
        !bytes_a.is_empty() && !bytes_b.is_empty(),
        "both providers are nonempty"
    );
    assert_ne!(bytes_a, bytes_b, "the two providers have distinct bytes");
    let meta_a = std::fs::metadata(&provider_a).unwrap();
    let meta_b = std::fs::metadata(&provider_b).unwrap();
    assert_ne!(
        (
            std::os::unix::fs::MetadataExt::dev(&meta_a),
            std::os::unix::fs::MetadataExt::ino(&meta_a)
        ),
        (
            std::os::unix::fs::MetadataExt::dev(&meta_b),
            std::os::unix::fs::MetadataExt::ino(&meta_b)
        ),
        "the two providers have distinct file identities"
    );
    scene
        .coordinator
        .engine
        .module_hints
        .push(provider_b.clone());
    let second_child = scene.spawn_second_child_with_provider("ready-b", &provider_b);
    let (second_caller, second_pid, _) =
        scene.admit_and_settle_distinct_member(second_child, &provider_b, 42, 11);
    let first_pid = scene.child_id();
    let first_caller = scene.caller;
    // Preparation order follows pid order; script in that same order
    // so each member's checks consume its own ticket's observations.
    let first_member_first = first_pid < second_pid;
    let (early_caller, early_pid, early_ticket) = if first_member_first {
        (first_caller, first_pid, 41)
    } else {
        (second_caller, second_pid, 42)
    };
    let (late_caller, late_pid, late_ticket) = if first_member_first {
        (second_caller, second_pid, 42)
    } else {
        (first_caller, first_pid, 41)
    };
    let mut script = Vec::new();
    for (ticket, first_gen) in [(early_ticket, 1), (late_ticket, 6), (late_ticket, 11)] {
        for generation in first_gen..first_gen + 5 {
            script.push((generation, ticket, 1));
        }
    }
    let acquired = scene.set_scripted_acquisition(&script);
    let facts_before = scene.engine_module_facts();

    // Race pass: exactly one member activates.
    let (completion, receipt, _) =
        scene.commit_observed_pass(Some(early_caller), early_pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(completion.admitted, 0);
    assert_eq!(completion.scan_callers, 2);
    let early_owner = scene
        .coordinator
        .owner_of(early_caller)
        .expect("the first prepared member activates");
    assert_eq!(
        scene.coordinator.owner_of(late_caller),
        None,
        "the second prepared member defers within one transaction"
    );
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.caller == Some(late_caller)
                && gap.pid == Some(late_pid)
                && gap.reason.contains("deferred to a later pass")
        }),
        "the deferred member refuses by name: {:?}",
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .collect::<Vec<_>>()
    );
    let facts_race = scene.engine_module_facts();
    assert!(
        facts_before.iter().all(|fact| facts_race.contains(fact)),
        "no pre-existing fact lost: {facts_before:?} vs {facts_race:?}"
    );
    let (early_provider, late_provider) = if first_member_first {
        (&provider_a, &provider_b)
    } else {
        (&provider_b, &provider_a)
    };
    assert_eq!(
        scene.engine_module_views_for(early_provider),
        BTreeSet::from([early_owner.0]),
        "only the activated member's provider facts commit"
    );
    assert!(
        scene.engine_module_views_for(late_provider).is_empty(),
        "the deferred member's provider commits no facts"
    );
    let (owners, reservations, leases) = scene
        .coordinator
        .engine
        .inventory_staged_counts_for_test()
        .unwrap();
    assert_eq!(
        (owners, reservations, leases),
        (1, 0, 0),
        "the deferred member releases its staged state"
    );
    assert_eq!(
        receipt.engine_facts, receipt.engine_published,
        "race-pass revisions publish"
    );

    // Follow-up pass: the deferred member activates on fresh
    // preparation; both members' facts survive.
    let (completion, receipt, _) =
        scene.commit_observed_pass(Some(late_caller), late_pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let late_owner = scene
        .coordinator
        .owner_of(late_caller)
        .expect("the deferred member activates on the next pass");
    let facts_final = scene.engine_module_facts();
    assert!(
        facts_race.iter().all(|fact| facts_final.contains(fact)),
        "the first member's facts survive the second activation: {facts_race:?} vs {facts_final:?}"
    );
    let (first_owner, second_owner) = if first_member_first {
        (early_owner, late_owner)
    } else {
        (late_owner, early_owner)
    };
    assert_eq!(
        scene.engine_module_views_for(&provider_a),
        BTreeSet::from([first_owner.0]),
        "the first member's provider facts survive"
    );
    assert_eq!(
        scene.engine_module_views_for(&provider_b),
        BTreeSet::from([second_owner.0]),
        "the second member's provider facts survive"
    );
    for (owner, provider) in [(first_owner, &provider_a), (second_owner, &provider_b)] {
        let claims = scene
            .coordinator
            .engine
            .pinned
            .view_claims(owner)
            .unwrap_or_else(|| panic!("owner {} retains pin claims", owner.0));
        assert!(
            !claims.pins.is_empty() || !claims.tables.is_empty() || !claims.targets.is_empty(),
            "owner {} keeps nonempty pin claims",
            owner.0
        );
        let paths = scene.owner_claim_paths(owner);
        assert!(
            !paths.is_empty(),
            "owner {} claims a nonempty provider identity",
            owner.0
        );
        assert!(
            paths
                .iter()
                .any(|path| Path::new(path) == provider.as_path()),
            "owner {} claims its own provider: {paths:?}",
            owner.0
        );
    }
    for owner in [early_owner, late_owner] {
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
        // Additions-only, not VerifiedAbsence: each member maps exactly
        // one of the two hints, so its scan records the other hint as
        // verified-absent (`scan.rs` hint skip), which keeps the receipt
        // from closing a complete revision (`inventory.rs` pinning gate).
        // Authority is still exact and the facts still commit; the
        // single-member twins pin the complete case.
        assert_eq!(
            epochs.complete, None,
            "distinct-provider activation commits additions-only"
        );
    }
    let (owners, reservations, leases) = scene
        .coordinator
        .engine
        .inventory_staged_counts_for_test()
        .unwrap();
    assert_eq!((owners, reservations, leases), (2, 0, 0));
    assert_eq!(
        receipt.engine_facts, receipt.engine_published,
        "follow-up revisions publish"
    );
    assert_eq!(
        acquired.borrow().calls(),
        15,
        "both members prepare in the race pass; the deferred member prepares again"
    );
    let first_edges: Vec<_> = scene
        .coordinator
        .registry()
        .edges_of(first_caller)
        .collect();
    let second_edges: Vec<_> = scene
        .coordinator
        .registry()
        .edges_of(second_caller)
        .collect();
    assert_eq!(first_edges.len(), 1);
    assert_eq!(second_edges.len(), 1);
    assert_ne!(
        first_edges[0].module, second_edges[0].module,
        "the members keep distinct modules"
    );
    assert_eq!(first_edges[0].entry_count, 7, "physical use is conserved");
    assert_eq!(second_edges[0].entry_count, 11, "physical use is conserved");
}

#[test]
fn cgroup_native_owner_shared_provider_members_keep_consistent_claims() {
    // R2 shared-provider case: two members map the same provider
    // file. The race pass activates one and defers the other; the
    // follow-up pass activates the deferred member. Both owners keep
    // their pin claims on the shared object, the attach set gains no
    // duplicate endpoints, and both registry edges share one module.
    // RED while the second commit replaces the first member's facts.
    let mut scene = ScopedNativeScene::new();
    let provider = scene.dir.path().join("scoped-provider.so");
    let second_child = scene.spawn_second_child("ready-b");
    let (second_caller, second_pid, _) = scene.admit_and_settle_second_member(second_child, 42, 11);
    let first_pid = scene.child_id();
    let first_caller = scene.caller;
    let endpoints_admitted = scene.provider_endpoint_count(&provider);
    assert!(
        endpoints_admitted > 0,
        "the shared provider is attached before the race"
    );
    let first_member_first = first_pid < second_pid;
    let (early_caller, early_pid, early_ticket) = if first_member_first {
        (first_caller, first_pid, 41)
    } else {
        (second_caller, second_pid, 42)
    };
    let (late_caller, late_pid, late_ticket) = if first_member_first {
        (second_caller, second_pid, 42)
    } else {
        (first_caller, first_pid, 41)
    };
    let mut script = Vec::new();
    for (ticket, first_gen) in [(early_ticket, 1), (late_ticket, 6), (late_ticket, 11)] {
        for generation in first_gen..first_gen + 5 {
            script.push((generation, ticket, 1));
        }
    }
    let acquired = scene.set_scripted_acquisition(&script);

    let (completion, receipt, _) =
        scene.commit_observed_pass(Some(early_caller), early_pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let early_owner = scene
        .coordinator
        .owner_of(early_caller)
        .expect("the first prepared member activates");
    assert_eq!(
        scene.coordinator.owner_of(late_caller),
        None,
        "the second prepared member defers within one transaction"
    );
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.caller == Some(late_caller)
                && gap.pid == Some(late_pid)
                && gap.reason.contains("deferred to a later pass")
        }),
        "the deferred member refuses by name"
    );
    assert_eq!(
        scene.engine_module_views_for(&provider),
        BTreeSet::from([early_owner.0]),
        "only the activated member's facts commit"
    );
    assert_eq!(
        scene.provider_endpoint_count(&provider),
        endpoints_admitted,
        "the race pass duplicates no shared endpoint"
    );
    assert_eq!(
        receipt.engine_facts, receipt.engine_published,
        "race-pass revisions publish"
    );

    let (completion, receipt, _) =
        scene.commit_observed_pass(Some(late_caller), late_pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let late_owner = scene
        .coordinator
        .owner_of(late_caller)
        .expect("the deferred member activates on the next pass");
    assert_eq!(
        scene.engine_module_views_for(&provider),
        BTreeSet::from([early_owner.0, late_owner.0]),
        "both members' facts survive on the shared provider"
    );
    for owner in [early_owner, late_owner] {
        let claims = scene
            .coordinator
            .engine
            .pinned
            .view_claims(owner)
            .expect("each owner retains pin claims on the shared object");
        assert!(
            !claims.pins.is_empty() || !claims.tables.is_empty() || !claims.targets.is_empty(),
            "owner {} keeps shared claims",
            owner.0
        );
    }
    assert_eq!(
        scene.provider_endpoint_count(&provider),
        endpoints_admitted,
        "the follow-up pass duplicates no shared endpoint"
    );
    assert_eq!(
        receipt.engine_facts, receipt.engine_published,
        "follow-up revisions publish"
    );
    assert_eq!(acquired.borrow().calls(), 15);
    for (caller, count) in [(first_caller, 7), (second_caller, 11)] {
        let edges: Vec<_> = scene.coordinator.registry().edges_of(caller).collect();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].module, scene.module, "one shared module");
        assert_eq!(edges[0].entry_count, count, "physical use is conserved");
    }
}

#[test]
fn cgroup_native_owner_handleless_pass_keeps_standing_deferral_disclosure() {
    // Coordinated replacement: without an acquisition handle, the
    // coordinator emits the precise unavailable disclosure the H6
    // consumer now recognizes under its controlled proof, with its
    // exact reason and caller-less shape, recorded every pass. The
    // superseded deferral subject never emits from current code (old
    // reports keep their own recognition). RED while the producer
    // still emits the superseded subject.
    const OLD_SUBJECT: &str = "native owner activation unavailable";
    const OLD_REASON: &str =
        "no image acquisition handle is installed; scan-pinned fallback retained";
    let mut scene = ScopedNativeScene::new();
    // No acquisition installed: the production handle-less path.
    let gaps = scene.coordinator.registry().gaps();
    let admitted_index = gaps
        .iter()
        .position(|gap| gap.subject == OLD_SUBJECT)
        .expect("the standing deferral disclosure emits on the handle-less path");
    let admitted_gap = &gaps[admitted_index];
    assert_eq!(admitted_gap.reason, OLD_REASON);
    assert_eq!(admitted_gap.caller, None);
    assert_eq!(admitted_gap.module, None);
    assert_eq!(admitted_gap.pid, None);
    assert_eq!(admitted_gap.budget, None);
    let repeats_before = scene.coordinator.registry().gap_repeats()[admitted_index];

    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(scene.coordinator.owner_of(scene.caller), None);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(scene.coordinator.owner_of(scene.caller), None);

    let gaps = scene.coordinator.registry().gaps();
    let index = gaps
        .iter()
        .position(|gap| gap.subject == OLD_SUBJECT)
        .expect("the standing disclosure persists across passes");
    assert_eq!(gaps[index].reason, OLD_REASON);
    assert_eq!(
        scene.coordinator.registry().gap_repeats()[index],
        repeats_before + 2,
        "the disclosure carries matching publication records"
    );
    assert!(
        gaps.iter()
            .all(|gap| gap.subject != "scoped native owner admission deferred"),
        "the superseded deferral subject never emits from current code: {:?}",
        gaps.iter()
            .map(|gap| gap.subject.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn cgroup_native_owner_migration_refusal_publishes_engine_revisions() {
    // R4 migration control: preparation dirties engine facts, every
    // activation is refused, and the final receipt still publishes
    // the dirtied revisions with no subsequent batch to repair them.
    // RED while the revision tail runs only after activation.
    let mut scene = ScopedNativeScene::new();
    let acquired = scene.set_scripted_acquisition(&[
        (1, 41, 1),
        (2, 41, 1),
        (3, 41, 1),
        (4, 41, 1),
        (5, 41, 1),
    ]);
    let (completion, receipt, _) =
        scene.commit_observed_pass(Some(scene.caller), scene.child_id(), PassAction::MigrateOut);
    assert!(matches!(
        completion.outcome,
        ScopedCollectionOutcome::Incomplete(_)
    ));
    assert_eq!(scene.coordinator.owner_of(scene.caller), None);
    scene.assert_conserved_physical_use();
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.reason.contains("final-sample permit")
        }),
        "a permitless member refuses by name"
    );
    let (owners, reservations, leases) = scene
        .coordinator
        .engine
        .inventory_staged_counts_for_test()
        .unwrap();
    assert_eq!((owners, reservations, leases), (0, 0, 0));
    assert_eq!(
        acquired.borrow().calls(),
        5,
        "preparation ran its owner I/O before the refusal"
    );
    assert_eq!(
        receipt.engine_facts, receipt.engine_published,
        "the final receipt publishes the revisions dirtied by refused work"
    );
    assert_eq!(
        scene.coordinator.engine.published_facts_revision, scene.coordinator.engine.facts_revision,
        "no refusal revision is left unpublished"
    );
}

#[test]
fn cgroup_native_owner_death_refusal_publishes_engine_revisions() {
    // R4 death control: the member dies after full preparation; the
    // refusal still publishes the dirtied engine revisions with no
    // subsequent batch. RED while the tail runs only after activation.
    let mut scene = ScopedNativeScene::new();
    let acquired = scene.set_scripted_acquisition(&[
        (1, 41, 1),
        (2, 41, 1),
        (3, 41, 1),
        (4, 41, 1),
        (5, 41, 1),
    ]);
    let caller = scene.caller;
    let pid = scene.child_id();
    let (_, receipt, _) = scene.commit_observed_pass(Some(caller), pid, PassAction::KillChild);
    assert_eq!(scene.coordinator.owner_of(caller), None);
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.reason.contains("final-sample permit")
        }),
        "a dead member refuses by name"
    );
    let (owners, reservations, leases) = scene
        .coordinator
        .engine
        .inventory_staged_counts_for_test()
        .unwrap();
    assert_eq!((owners, reservations, leases), (0, 0, 0));
    assert_eq!(
        acquired.borrow().calls(),
        5,
        "preparation ran its owner I/O before the death"
    );
    assert_eq!(
        receipt.engine_facts, receipt.engine_published,
        "the final receipt publishes the revisions dirtied by refused work"
    );
    assert_eq!(
        scene.coordinator.engine.published_facts_revision, scene.coordinator.engine.facts_revision,
        "no refusal revision is left unpublished"
    );
}

#[test]
fn cgroup_native_owner_permitted_member_of_incomplete_transaction_releases_without_activation() {
    // (Some permit, Incomplete outcome): the retained member keeps
    // its final-sample permit while a migrated sibling makes the
    // transaction incomplete, so the fence releases the permitted
    // member without activation. Authority stays scan-pinned,
    // counts stay conserved, and no staged state survives.
    let mut scene = ScopedNativeScene::new();
    let second_child = scene.spawn_second_child("ready-b");
    let (second_caller, second_pid, _) = scene.admit_and_settle_second_member(second_child, 42, 11);
    let first_pid = scene.child_id();
    let first_caller = scene.caller;
    let first_member_first = first_pid < second_pid;
    let mut script = Vec::new();
    for (ticket, first_gen) in if first_member_first {
        [(41, 1), (42, 6)]
    } else {
        [(42, 1), (41, 6)]
    } {
        for generation in first_gen..first_gen + 5 {
            script.push((generation, ticket, 1));
        }
    }
    let acquired = scene.set_scripted_acquisition(&script);
    let (completion, receipt, reads) = scene.commit_observed_pass(
        Some(first_caller),
        first_pid,
        PassAction::RetainOnly(first_pid),
    );
    assert!(matches!(
        completion.outcome,
        ScopedCollectionOutcome::Incomplete(_)
    ));
    assert_eq!(
        scene.coordinator.owner_of(first_caller),
        None,
        "the fence releases the permitted member without activation"
    );
    assert_eq!(scene.coordinator.owner_of(second_caller), None);
    for caller in [first_caller, second_caller] {
        assert_eq!(
            scene
                .coordinator
                .adapter()
                .record(caller)
                .unwrap()
                .authority,
            ImageAuthority::ScanPinned,
            "no exact authority without activation"
        );
    }
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.caller == Some(first_caller)
                && gap.pid == Some(first_pid)
                && gap.reason.contains("did not complete")
        }),
        "the permitted member of an incomplete transaction refuses by the fence reason: {:?}",
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .collect::<Vec<_>>()
    );
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.caller == Some(second_caller)
                && gap.pid == Some(second_pid)
                && gap.reason.contains("final-sample permit")
        }),
        "the migrated member refuses by the permit reason"
    );
    let (owners, reservations, leases) = scene
        .coordinator
        .engine
        .inventory_staged_counts_for_test()
        .unwrap();
    assert_eq!(
        (owners, reservations, leases),
        (0, 0, 0),
        "no reservation or lease survives the fence"
    );
    assert_eq!(
        acquired.borrow().calls(),
        10,
        "both members prepared before the fence refused"
    );
    for (caller, count) in [(first_caller, 7), (second_caller, 11)] {
        let edges: Vec<_> = scene.coordinator.registry().edges_of(caller).collect();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].entry_count, count, "physical use is conserved");
    }
    assert!(
        reads.pre_sample > 0,
        "preparation ran its provider validation: {reads:?}"
    );
    assert_eq!(
        reads.post_sample, 0,
        "the fence refusal reads no provider metadata post-sample: {reads:?}"
    );
    assert_eq!(
        receipt.engine_facts, receipt.engine_published,
        "the fence refusal publishes the dirtied revisions"
    );
}

#[test]
fn cgroup_native_owner_fresh_observation_mismatch_refuses_with_rollback() {
    // Fresh-observation mismatch after a valid factory result. First,
    // a changed exec at the later scan checkpoint refuses during
    // preparation; then a stored observation mismatch reaches the
    // real activation replay, which refuses, rolls the installed
    // authority back to scan-pinned, publishes nothing for the
    // owner, and releases the staged state. Both publish the
    // revisions their scans dirtied.
    let mut scene = ScopedNativeScene::new();
    let acquired = scene.set_scripted_acquisition(&[(1, 41, 1), (2, 41, 1), (3, 41, 2)]);
    let (completion, receipt, reads) =
        scene.commit_observed_pass(Some(scene.caller), scene.child_id(), PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(
        scene.coordinator.owner_of(scene.caller),
        None,
        "a changed exec at the scan checkpoint refuses activation"
    );
    assert_eq!(
        scene
            .coordinator
            .adapter()
            .record(scene.caller)
            .unwrap()
            .authority,
        ImageAuthority::ScanPinned,
        "the scan fallback stands"
    );
    scene.assert_conserved_physical_use();
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.reason.contains("staged owner scan failed")
                && gap.reason.contains("Changed")
        }),
        "the scan-checkpoint veto refuses by name: {:?}",
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .collect::<Vec<_>>()
    );
    let (owners, reservations, leases) = scene
        .coordinator
        .engine
        .inventory_staged_counts_for_test()
        .unwrap();
    assert_eq!((owners, reservations, leases), (0, 0, 0));
    assert_eq!(
        acquired.borrow().calls(),
        3,
        "the veto fires at the later scan checkpoint"
    );
    assert!(
        reads.pre_sample > 0,
        "preparation ran its provider validation: {reads:?}"
    );
    assert_eq!(
        reads.post_sample, 0,
        "the scan refusal reads no provider metadata post-sample: {reads:?}"
    );
    assert_eq!(
        receipt.engine_facts, receipt.engine_published,
        "the scan refusal publishes the dirtied revisions"
    );

    // Stored observation mismatch: preparation's fresh checks all
    // match, but the stored observation names a changed exec, so the
    // activation replay refuses and rolls back.
    let mut scene = ScopedNativeScene::new();
    let acquired = scene.set_scripted_acquisition(&[
        (1, 41, 2),
        (2, 41, 1),
        (3, 41, 1),
        (4, 41, 1),
        (5, 41, 1),
    ]);
    let facts_before = scene.engine_module_facts();
    let (completion, receipt, reads) =
        scene.commit_observed_pass(Some(scene.caller), scene.child_id(), PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(
        scene.coordinator.owner_of(scene.caller),
        None,
        "a stored observation mismatch refuses activation"
    );
    assert_eq!(
        scene
            .coordinator
            .adapter()
            .record(scene.caller)
            .unwrap()
            .authority,
        ImageAuthority::ScanPinned,
        "the installed authority rolls back on replay mismatch"
    );
    scene.assert_conserved_physical_use();
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.reason.contains("staged owner activation failed")
                && gap.reason.contains("Changed")
        }),
        "the replay mismatch refuses by name: {:?}",
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .collect::<Vec<_>>()
    );
    assert!(
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .all(|gap| !gap.reason.contains("rollback missed")),
        "the rollback lands on its installed image"
    );
    let (owners, reservations, leases) = scene
        .coordinator
        .engine
        .inventory_staged_counts_for_test()
        .unwrap();
    assert_eq!((owners, reservations, leases), (0, 0, 0));
    assert_eq!(acquired.borrow().calls(), 5);
    assert_eq!(
        scene.engine_module_facts(),
        facts_before,
        "the refused commit publishes no owner facts"
    );
    assert!(
        reads.pre_sample > 0,
        "preparation ran its provider validation: {reads:?}"
    );
    assert_eq!(
        reads.post_sample, 0,
        "the replay refusal reads no provider metadata post-sample: {reads:?}"
    );
    assert_eq!(
        receipt.engine_facts, receipt.engine_published,
        "the replay refusal publishes the dirtied revisions"
    );
}

// --- G9/F-10 activation-rollback twins --------------------------------------
// The rollback miss is unreachable through the synchronous commit
// (install, engine-only activation, cancel — no hook runs between),
// so these twins drive the real failure seams directly: a real
// scene, real binder images, a real final-sample permit and proof.

use crate::discovery::caller_registry::CallerLifecycle;

impl ScopedNativeScene {
    /// One final-sampled collection for `pid` without committing: the
    /// same `sample_end` + `permit` seam the commit uses, so the proof
    /// below is a genuine final-sample permit proof.
    fn final_sampled_collection(&mut self, pid: u32) -> CgroupCollection {
        let mut collection = self
            .coordinator
            .cgroup_collector(
                std::mem::take(&mut self.state),
                CgroupWalkLimits::default(),
                CollectionControl::new(None),
                None,
            )
            .unwrap()();
        collection.sample_end(&BTreeSet::from([pid]));
        collection
    }
}

#[test]
fn cgroup_native_owner_missed_rollback_after_failed_activation_retires_caller() {
    // G9/F-10: activation fails after install AND the rollback misses
    // its installed image (the authority was mutated between: rolled
    // back, then re-installed with a rival domain image). The caller
    // must retire with its evidence, so no live NativeExact caller
    // lacks an activated owner. RED pre-fix: the caller stays live
    // NativeExact with gaps only. The healthy leg (rollback lands)
    // runs first on the same caller; the existing
    // stored-observation-mismatch twin pins the real
    // activation-failure text end to end.
    let mut scene = ScopedNativeScene::new();
    let rival_domain = NativeDomainId::mint();
    scene.settle_alias_domain(rival_domain, 42, 1);
    let pid = scene.child_id();
    let caller = scene.caller;
    let expected = scene
        .coordinator
        .binder
        .expected_owner_image(scene.domain, caller, pid, scene.coordinator.adapter())
        .expect("the scene domain settled the member image");
    let rival = scene
        .coordinator
        .binder
        .expected_owner_image(rival_domain, caller, pid, scene.coordinator.adapter())
        .expect("the alias domain settled its rival image");
    assert_ne!(
        expected, rival,
        "the rival image differs from the installed one"
    );
    let collection = scene.final_sampled_collection(pid);
    let preparation = collection
        .preparation(pid)
        .expect("the live member prepares");
    assert!(preparation.check());
    let permit = collection
        .permit(pid)
        .expect("the live member holds its final-sample permit");
    let proof = ScopedOwnerProof::validate(pid, preparation.generation(), &permit)
        .expect("the proof validates for the live member");
    let now_ns = crate::discovery::caller_registry::now_ns();
    // The real activation-failure text (`inventory.rs`
    // `check_inventory_image`; pinned end to end by the
    // stored-observation-mismatch twin).
    let error =
        anyhow::anyhow!("inventory exact-image authority is Changed; existing claims retained");

    // Healthy leg: install, then the failure handler with the
    // installed image — the rollback lands, the caller stays live
    // scan-pinned, and no retirement stages.
    scene
        .coordinator
        .adapter
        .install_scoped_native_authority(caller, expected, &proof)
        .map_err(|failure| failure.reason)
        .expect("install succeeds for the live member");
    assert_eq!(
        scene
            .coordinator
            .adapter()
            .record(caller)
            .unwrap()
            .authority,
        ImageAuthority::NativeExact { image: expected },
    );
    scene
        .coordinator
        .rollback_installed_native_authority(caller, pid, expected, &error, now_ns);
    scene.coordinator.commit_batch(false).unwrap();
    assert_eq!(
        scene
            .coordinator
            .adapter()
            .record(caller)
            .unwrap()
            .authority,
        ImageAuthority::ScanPinned,
        "the landed rollback restores the scan-pinned fallback"
    );
    assert!(
        !scene.coordinator.adapter().record(caller).unwrap().retired,
        "a landed rollback retires nothing"
    );
    assert!(
        !scene.coordinator.staged_retirements.contains(&caller),
        "a landed rollback stages no retirement"
    );
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.reason.contains("staged owner activation failed")
        }),
        "the activation failure reports by name"
    );
    assert!(
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .all(|gap| !gap.reason.contains("rollback missed")),
        "the landed rollback reports no miss"
    );
    // Healthy callers refuse the poisoned-retire seam: live
    // scan-pinned stays, unknown callers stay unknown.
    assert!(
        !scene
            .coordinator
            .adapter
            .retire_native_caller_without_owner(
                caller,
                "probe: a healthy caller must not retire".into(),
                now_ns,
            ),
        "a live scan-pinned caller is healthy and stays"
    );
    assert!(
        !scene
            .coordinator
            .adapter
            .retire_native_caller_without_owner(
                CallerId(u32::MAX),
                "probe: no retained caller".into(),
                now_ns,
            ),
        "an unknown caller retires nothing"
    );
    assert_eq!(
        scene.coordinator.adapter().live_id(pid),
        Some(caller),
        "the probes changed nothing"
    );

    // Failure leg: install, mutate the authority between (roll back,
    // then re-install the rival image), then the failure handler with
    // the stale installed image — the rollback misses.
    scene
        .coordinator
        .adapter
        .install_scoped_native_authority(caller, expected, &proof)
        .map_err(|failure| failure.reason)
        .expect("re-install succeeds for the live member");
    scene
        .coordinator
        .adapter
        .cancel_scoped_native_authority(caller, expected)
        .expect("the intervening rollback lands");
    scene
        .coordinator
        .adapter
        .install_scoped_native_authority(caller, rival, &proof)
        .map_err(|failure| failure.reason)
        .expect("the rival image installs between");
    assert_eq!(
        scene
            .coordinator
            .adapter()
            .record(caller)
            .unwrap()
            .authority,
        ImageAuthority::NativeExact { image: rival },
        "the authority was mutated between install and rollback"
    );
    scene
        .coordinator
        .rollback_installed_native_authority(caller, pid, expected, &error, now_ns);
    scene.coordinator.commit_batch(false).unwrap();
    let record = scene.coordinator.adapter().record(caller).unwrap();
    assert!(
        record.retired,
        "a missed rollback retires the caller: no live NativeExact caller lacks an activated owner"
    );
    assert_eq!(
        record.authority,
        ImageAuthority::NativeExact { image: rival },
        "the retired record keeps its installed authority as evidence"
    );
    assert_eq!(
        record.lifecycle,
        CallerLifecycle::Unknown,
        "the poisoned retirement claims no proven turnover"
    );
    assert!(
        record
            .lifecycle_reason
            .as_ref()
            .is_some_and(|reason| reason.contains("rollback missed")),
        "the retirement reason names the miss: {:?}",
        record.lifecycle_reason
    );
    assert_eq!(
        scene.coordinator.adapter().live_id(pid),
        None,
        "the retired caller leaves the live map"
    );
    assert_eq!(
        scene.coordinator.owner_of(caller),
        None,
        "no activated owner stands behind the retired caller"
    );
    assert!(
        scene
            .coordinator
            .adapter()
            .shared_semantic_custody(caller)
            .is_none(),
        "the retired caller drops its pin"
    );
    assert!(
        scene.coordinator.staged_retirements.contains(&caller),
        "the retirement stages in the registry"
    );
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.caller == Some(caller)
                && gap.pid == Some(pid)
                && gap.reason.contains("rollback missed")
        }),
        "the missed rollback reports by name"
    );
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == "native owner activation refused"
                && gap.caller == Some(caller)
                && gap.reason.contains("retired with its evidence")
        }),
        "the poisoned retirement reports by name"
    );
    // An already retired caller refuses a second retirement: the
    // first reason stands, nothing is overwritten.
    let reason_before = scene
        .coordinator
        .adapter()
        .record(caller)
        .unwrap()
        .lifecycle_reason
        .clone();
    assert!(
        !scene
            .coordinator
            .adapter
            .retire_native_caller_without_owner(
                caller,
                "probe: a second retirement must not land".into(),
                now_ns,
            ),
        "an already retired caller retires nothing twice"
    );
    assert_eq!(
        scene
            .coordinator
            .adapter()
            .record(caller)
            .unwrap()
            .lifecycle_reason,
        reason_before,
        "the first retirement reason is preserved"
    );
}

#[test]
fn cgroup_native_owner_permit_death_between_validate_and_install_refuses_with_fallback() {
    // G9/F-10 death twin: the permit dies after
    // `ScopedOwnerProof::validate`, before install completes —
    // install must refuse without touching the record, and the
    // scan-pinned fallback stands. The live control leg proves the
    // seam installs when alive, so the refusal is the death's doing.
    // Pin: install revalidates custody instead of trusting the proof.
    let mut dying = ScopedNativeScene::new();
    let pid = dying.child_id();
    let caller = dying.caller;
    let expected = dying
        .coordinator
        .binder
        .expected_owner_image(dying.domain, caller, pid, dying.coordinator.adapter())
        .expect("the scene domain settled the member image");
    let collection = dying.final_sampled_collection(pid);
    let preparation = collection
        .preparation(pid)
        .expect("the live member prepares");
    assert!(preparation.check());
    let permit = collection
        .permit(pid)
        .expect("the live member holds its final-sample permit");
    let proof = ScopedOwnerProof::validate(pid, preparation.generation(), &permit)
        .expect("the proof validates for the live member");
    // The permit dies after validation, before install completes.
    assert_eq!(dying.kill_child(), pid);
    let install = dying
        .coordinator
        .adapter
        .install_scoped_native_authority(caller, expected, &proof);
    let Err(failure) = install else {
        panic!("install after the permit's death must refuse");
    };
    assert!(
        failure.reason.contains("custody lapsed"),
        "the refusal names the lapsed custody: {}",
        failure.reason
    );
    assert_eq!(
        dying
            .coordinator
            .adapter()
            .record(caller)
            .unwrap()
            .authority,
        ImageAuthority::ScanPinned,
        "the scan-pinned fallback stands"
    );
    assert!(
        !dying.coordinator.adapter().record(caller).unwrap().retired,
        "an install refusal retires nothing: reconcile owns exit retirement"
    );
    assert_eq!(
        dying.coordinator.owner_of(caller),
        None,
        "no owner activates on a refused install"
    );

    // Live control: the same seam installs when the member is alive,
    // so the death leg's refusal is the death's doing, not setup.
    let mut live = ScopedNativeScene::new();
    let pid = live.child_id();
    let caller = live.caller;
    let expected = live
        .coordinator
        .binder
        .expected_owner_image(live.domain, caller, pid, live.coordinator.adapter())
        .expect("the scene domain settled the member image");
    let collection = live.final_sampled_collection(pid);
    let preparation = collection
        .preparation(pid)
        .expect("the live member prepares");
    assert!(preparation.check());
    let permit = collection
        .permit(pid)
        .expect("the live member holds its final-sample permit");
    let proof = ScopedOwnerProof::validate(pid, preparation.generation(), &permit)
        .expect("the proof validates for the live member");
    live.coordinator
        .adapter
        .install_scoped_native_authority(caller, expected, &proof)
        .map_err(|failure| failure.reason)
        .expect("install succeeds for the live member");
    assert_eq!(
        live.coordinator.adapter().record(caller).unwrap().authority,
        ImageAuthority::NativeExact { image: expected },
        "the live control installs"
    );
    live.coordinator
        .adapter
        .cancel_scoped_native_authority(caller, expected)
        .expect("the control cleanup rollback lands");
    assert_eq!(
        live.coordinator.adapter().record(caller).unwrap().authority,
        ImageAuthority::ScanPinned,
        "the control cleanup restores the fallback"
    );
    assert!(
        !live.coordinator.adapter().record(caller).unwrap().retired,
        "the control retires nothing"
    );
    assert_eq!(
        live.coordinator.owner_of(caller),
        None,
        "the control binds no owner"
    );
}

// --- Refresh/suspend lifecycle twins -----------------------------------
// An activated owner refreshes through the same in-transaction path
// on later passes, and a member absent from a complete transaction
// (or retired, or proven exec-changed) suspends: native authority
// cancels back to scan-pinned where the caller still stands, the
// engine owner releases, and a named gap reports the event. The
// handle-less pass emits the coordinated unavailable disclosure.

const UNAVAILABLE_SUBJECT: &str = "native owner activation unavailable";
const UNAVAILABLE_REASON: &str =
    "no image acquisition handle is installed; scan-pinned fallback retained";
const REFRESH_REFUSED_SUBJECT: &str = "native owner refresh refused";
const SUSPENDED_SUBJECT: &str = "native owner suspended";
const SUSPENDED_ABSENT_REASON: &str = "the caller was absent from the complete cgroup transaction; its native owner was released and scan-pinned fallback retained";
const SUSPENDED_RETIRED_REASON: &str = "the caller retired; its native owner was released";
const SUSPENDED_EXEC_REASON: &str = "the caller's image changed; native authority was cancelled and its native owner was released; scan-pinned fallback retained";
const SUSPENDED_LOST_REASON: &str = "the caller failed its final permit proof after admission; native authority was cancelled and its native owner was released; scan-pinned fallback retained";

fn staged_counts(scene: &ScopedNativeScene) -> (usize, usize, usize) {
    scene
        .coordinator
        .engine
        .inventory_staged_counts_for_test()
        .unwrap()
}

fn assert_suspended_gap(scene: &ScopedNativeScene, caller: CallerId, pid: u32, reason: &str) {
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == SUSPENDED_SUBJECT
                && gap.caller == Some(caller)
                && gap.pid == Some(pid)
                && gap.module.is_none()
                && gap.budget.is_none()
                && gap.reason == reason
        }),
        "the suspend reports by name for {caller:?}: {:?}",
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .collect::<Vec<_>>()
    );
}

fn assert_no_suspended_gap(scene: &ScopedNativeScene) {
    assert!(
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .all(|gap| gap.subject != SUSPENDED_SUBJECT),
        "no suspend reports: {:?}",
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| gap.subject.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn cgroup_native_owner_handle_transition_replaces_standing_disclosure() {
    // Handle-less passes emit the coordinated unavailable disclosure
    // every pass and activate nothing; once the scene installs its
    // acquisition, the next pass activates and adds no further
    // standing disclosure.
    let mut scene = ScopedNativeScene::new();
    let gaps = scene.coordinator.registry().gaps();
    let index = gaps
        .iter()
        .position(|gap| gap.subject == UNAVAILABLE_SUBJECT)
        .expect("the unavailable disclosure emits on the handle-less path");
    let gap = &gaps[index];
    assert_eq!(gap.reason, UNAVAILABLE_REASON);
    assert_eq!(
        (gap.caller, gap.module, gap.pid, gap.budget),
        (None, None, None, None),
        "the standing disclosure names no caller, module, pid, or budget"
    );
    assert!(
        gaps.iter()
            .all(|gap| gap.subject != "scoped native owner admission deferred"),
        "the superseded deferral subject never emits"
    );
    let repeats_before = scene.coordinator.registry().gap_repeats()[index];
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(scene.coordinator.owner_of(scene.caller), None);
    assert_eq!(
        scene.coordinator.registry().gap_repeats()[index],
        repeats_before + 1,
        "each handle-less pass repeats the standing disclosure"
    );

    let acquired = scene.set_scripted_acquisition(&[
        (1, 41, 1),
        (2, 41, 1),
        (3, 41, 1),
        (4, 41, 1),
        (5, 41, 1),
    ]);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert!(
        scene.coordinator.owner_of(scene.caller).is_some(),
        "the handled pass activates"
    );
    assert_eq!(acquired.borrow().calls(), 5);
    assert_eq!(
        scene.coordinator.registry().gap_repeats()[index],
        repeats_before + 1,
        "handled passes add no standing disclosure"
    );
}

#[test]
fn cgroup_native_owner_refresh_commits_in_transaction() {
    // Healthy refresh: the pass after activation re-acquires the
    // member image, rescans under the final bracket, services the
    // requested epoch, and republishes consistent revisions without
    // any refusal. The stopped child cannot change its mappings, so
    // the pins are acquisition count, epoch service, and revisions.
    let mut scene = ScopedNativeScene::new();
    let script: Vec<_> = (1..=10).map(|generation| (generation, 41, 1)).collect();
    let acquired = scene.set_scripted_acquisition(&script);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let owner = scene
        .coordinator
        .owner_of(scene.caller)
        .expect("the stable member activates");
    assert_eq!(acquired.borrow().calls(), 5);
    let epochs = scene
        .coordinator
        .engine
        .inventory_owner_epochs(owner)
        .unwrap();
    assert_eq!((epochs.requested, epochs.serviced), (0, 0));

    let pid = scene.child_id();
    let (completion, receipt, reads) = scene.commit_observed_pass(None, pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(
        scene.coordinator.owner_of(scene.caller),
        Some(owner),
        "refresh keeps the same owner"
    );
    assert_eq!(
        acquired.borrow().calls(),
        10,
        "refresh re-acquires before the final sample"
    );
    let epochs = scene
        .coordinator
        .engine
        .inventory_owner_epochs(owner)
        .unwrap();
    assert_eq!(
        (epochs.requested, epochs.serviced),
        (1, 1),
        "the requested refresh epoch is serviced, none pending"
    );
    assert_eq!(
        epochs.image_state,
        super::super::inventory::ImageCheck::Exact
    );
    assert!(
        epochs.complete.is_some(),
        "refresh commits a complete receipt"
    );
    assert!(
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .all(|gap| gap.subject != REFRESH_REFUSED_SUBJECT),
        "a healthy refresh refuses nothing"
    );
    assert_no_suspended_gap(&scene);
    assert_eq!(staged_counts(&scene), (1, 0, 0));
    assert_eq!(reads.post_sample, 0, "refresh reads nothing post-sample");
    assert_eq!(
        receipt.engine_facts, receipt.engine_published,
        "refresh revisions publish"
    );
    scene.assert_conserved_physical_use();
}

#[test]
fn cgroup_native_owner_refresh_migration_refuses_without_commit() {
    // Migration-out while the commit runs: refresh preparation ran,
    // but the final sample grants no permit, so nothing commits, the
    // owner and its facts stand, the refusal names the permit, and
    // no provider metadata is read after the sample. The incomplete
    // transaction suspends nobody.
    let mut scene = ScopedNativeScene::new();
    let script: Vec<_> = (1..=10).map(|generation| (generation, 41, 1)).collect();
    let acquired = scene.set_scripted_acquisition(&script);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let owner = scene
        .coordinator
        .owner_of(scene.caller)
        .expect("the stable member activates");

    let pid = scene.child_id();
    let (completion, _receipt, reads) =
        scene.commit_observed_pass(None, pid, PassAction::MigrateOut);
    assert!(matches!(
        completion.outcome,
        ScopedCollectionOutcome::Incomplete(_)
    ));
    assert_eq!(
        scene.coordinator.owner_of(scene.caller),
        Some(owner),
        "the owner stands across a refused refresh"
    );
    assert_eq!(
        acquired.borrow().calls(),
        10,
        "refresh preparation ran before the sample"
    );
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == REFRESH_REFUSED_SUBJECT
                && gap.caller == Some(scene.caller)
                && gap.pid == Some(pid)
                && gap.module.is_none()
                && gap.budget.is_none()
                && gap.reason.contains("final-sample permit")
        }),
        "the permitless refresh refuses by name: {:?}",
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .collect::<Vec<_>>()
    );
    assert_no_suspended_gap(&scene);
    assert_eq!(staged_counts(&scene), (1, 0, 0));
    let epochs = scene
        .coordinator
        .engine
        .inventory_owner_epochs(owner)
        .unwrap();
    assert_eq!(
        epochs.image_state,
        super::super::inventory::ImageCheck::Exact,
        "prior exact facts are retained"
    );
    assert_eq!(reads.post_sample, 0, "no post-sample provider reads");
    scene.assert_conserved_physical_use();
}

#[test]
fn cgroup_native_owner_refresh_replay_mismatch_refuses_without_publication() {
    // The stored refresh observation names a changed exec while the
    // preparation's fresh checks match, so the commit replay refuses:
    // no new facts publish for the owner, the refusal names the
    // changed image, native authority cancels, and the owner
    // suspends in the same complete pass.
    let mut scene = ScopedNativeScene::new();
    let acquired = scene.set_scripted_acquisition(&[
        (1, 41, 1),
        (2, 41, 1),
        (3, 41, 1),
        (4, 41, 1),
        (5, 41, 1),
        (6, 41, 2),
        (7, 41, 1),
        (8, 41, 1),
        (9, 41, 1),
        (10, 41, 1),
    ]);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let owner = scene
        .coordinator
        .owner_of(scene.caller)
        .expect("the stable member activates");
    let facts_before = scene.engine_module_facts();

    let pid = scene.child_id();
    let (completion, receipt, reads) = scene.commit_observed_pass(None, pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(acquired.borrow().calls(), 10, "refresh fully prepared");
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == REFRESH_REFUSED_SUBJECT
                && gap.caller == Some(scene.caller)
                && gap.pid == Some(pid)
                && gap.reason.contains("refresh commit failed")
                && gap.reason.contains("Changed")
        }),
        "the replay mismatch refuses by name: {:?}",
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        scene.coordinator.owner_of(scene.caller),
        None,
        "the changed image suspends its owner"
    );
    assert_suspended_gap(&scene, scene.caller, pid, SUSPENDED_EXEC_REASON);
    assert_eq!(
        scene
            .coordinator
            .adapter()
            .record(scene.caller)
            .unwrap()
            .authority,
        ImageAuthority::ScanPinned,
        "native authority cancels back to the fallback"
    );
    let facts_after = scene.engine_module_facts();
    assert!(
        facts_after.is_subset(&facts_before),
        "the refused refresh publishes no new facts: {facts_after:?}"
    );
    assert!(
        facts_after.iter().all(|(view, _)| *view != owner.0),
        "the released owner retains no engine facts"
    );
    assert_eq!(staged_counts(&scene), (0, 0, 0));
    assert_eq!(reads.post_sample, 0, "no post-sample provider reads");
    assert_eq!(
        receipt.engine_facts, receipt.engine_published,
        "the refusal publishes the dirtied revisions"
    );
    scene.assert_conserved_physical_use();
}

#[test]
fn cgroup_native_owner_activation_precedes_refresh_in_one_transaction() {
    // One scoped commit per transaction, shared by activation and
    // refresh with activations first: the race pass activates the
    // early member, the follow-up activates the late member while
    // the early owner's refresh waits silently, and only then do
    // refreshes land, stalest owner first, one per pass, with the
    // other owner's facts intact throughout.
    let mut scene = ScopedNativeScene::new();
    let provider_a = scene.dir.path().join("scoped-provider.so");
    let provider_b = scene.build_second_provider();
    scene
        .coordinator
        .engine
        .module_hints
        .push(provider_b.clone());
    let second_child = scene.spawn_second_child_with_provider("ready-b", &provider_b);
    let (second_caller, second_pid, _) =
        scene.admit_and_settle_distinct_member(second_child, &provider_b, 42, 11);
    let first_pid = scene.child_id();
    let first_caller = scene.caller;
    let first_member_first = first_pid < second_pid;
    let (early_caller, early_pid, early_ticket) = if first_member_first {
        (first_caller, first_pid, 41)
    } else {
        (second_caller, second_pid, 42)
    };
    let (late_caller, late_pid, late_ticket) = if first_member_first {
        (second_caller, second_pid, 42)
    } else {
        (first_caller, first_pid, 41)
    };
    // Preparation order per pass: race (early, late), follow-up
    // (late activation only), refresh pass (early, late), stalest
    // refresh pass (late, early). Five acquisitions each.
    let mut script = Vec::new();
    let mut generation = 1u64;
    for ticket in [
        early_ticket,
        late_ticket,
        late_ticket,
        early_ticket,
        late_ticket,
        late_ticket,
        early_ticket,
    ] {
        for _ in 0..5 {
            script.push((generation, ticket, 1));
            generation += 1;
        }
    }
    let acquired = scene.set_scripted_acquisition(&script);

    let (completion, _, _) =
        scene.commit_observed_pass(Some(early_caller), early_pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let early_owner = scene
        .coordinator
        .owner_of(early_caller)
        .expect("the early member activates in the race pass");
    assert_eq!(scene.coordinator.owner_of(late_caller), None);
    assert_eq!(acquired.borrow().calls(), 10);

    let (completion, _, _) =
        scene.commit_observed_pass(Some(late_caller), late_pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let late_owner = scene
        .coordinator
        .owner_of(late_caller)
        .expect("the late member activates on the follow-up pass");
    assert_eq!(
        acquired.borrow().calls(),
        15,
        "the activation pass spends no acquisition on the waiting refresh"
    );
    let epochs = scene
        .coordinator
        .engine
        .inventory_owner_epochs(early_owner)
        .unwrap();
    assert_eq!(
        (epochs.requested, epochs.serviced),
        (0, 0),
        "the deferred refresh was not requested or serviced"
    );
    assert!(
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .all(|gap| gap.subject != REFRESH_REFUSED_SUBJECT),
        "refresh deferral is silent"
    );
    let facts_activated = scene.engine_module_facts();

    // Refresh pass: both prepare, the early owner commits, the late
    // owner's prepared refresh abandons silently with its epoch
    // pending and its staged state fully released.
    let (completion, receipt, _) = scene.commit_observed_pass(None, early_pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(
        acquired.borrow().calls(),
        25,
        "both owners prepared a refresh"
    );
    let epochs = scene
        .coordinator
        .engine
        .inventory_owner_epochs(early_owner)
        .unwrap();
    assert_eq!((epochs.requested, epochs.serviced), (1, 1));
    let epochs = scene
        .coordinator
        .engine
        .inventory_owner_epochs(late_owner)
        .unwrap();
    assert_eq!(
        (epochs.requested, epochs.serviced),
        (1, 0),
        "the second prepared refresh stays pending"
    );
    assert_eq!(
        staged_counts(&scene),
        (2, 0, 0),
        "no lease survives deferral"
    );
    assert!(
        facts_activated
            .iter()
            .all(|fact| scene.engine_module_facts().contains(fact)),
        "the refresh commit keeps both owners' facts"
    );
    assert_eq!(receipt.engine_facts, receipt.engine_published);

    // Stalest first: the late owner's pending refresh lands next.
    let (completion, _, _) = scene.commit_observed_pass(None, late_pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(acquired.borrow().calls(), 35);
    let epochs = scene
        .coordinator
        .engine
        .inventory_owner_epochs(late_owner)
        .unwrap();
    assert_eq!(
        epochs.requested, epochs.serviced,
        "the pending refresh landed"
    );
    assert!(epochs.serviced >= 1);
    assert_eq!(staged_counts(&scene), (2, 0, 0));
    assert!(
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .all(|gap| gap.subject != REFRESH_REFUSED_SUBJECT),
        "no refresh refused across the sharing passes"
    );
    assert_no_suspended_gap(&scene);
    let (early_provider, late_provider) = if first_member_first {
        (&provider_a, &provider_b)
    } else {
        (&provider_b, &provider_a)
    };
    assert_eq!(
        scene.engine_module_views_for(early_provider),
        BTreeSet::from([early_owner.0])
    );
    assert_eq!(
        scene.engine_module_views_for(late_provider),
        BTreeSet::from([late_owner.0])
    );
}

#[test]
fn cgroup_native_owner_refresh_exec_cancels_authority_and_suspends() {
    // Every fresh observation names the changed exec, so the refresh
    // scan veto fires during preparation: the refusal names the
    // changed image, authority cancels to scan-pinned, the owner
    // releases in the same complete pass, and the caller stays a
    // live scan-pinned member for its new image.
    let mut scene = ScopedNativeScene::new();
    let acquired = scene.set_scripted_acquisition(&[
        (1, 41, 1),
        (2, 41, 1),
        (3, 41, 1),
        (4, 41, 1),
        (5, 41, 1),
        (6, 41, 2),
        (7, 41, 2),
    ]);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert!(scene.coordinator.owner_of(scene.caller).is_some());

    let pid = scene.child_id();
    let (completion, receipt, reads) = scene.commit_observed_pass(None, pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(
        acquired.borrow().calls(),
        7,
        "the veto fires at the first refresh scan check"
    );
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == REFRESH_REFUSED_SUBJECT
                && gap.caller == Some(scene.caller)
                && gap.pid == Some(pid)
                && gap.reason.contains("refresh scan failed")
                && gap.reason.contains("Changed")
        }),
        "the exec veto refuses by name: {:?}",
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .collect::<Vec<_>>()
    );
    assert_eq!(scene.coordinator.owner_of(scene.caller), None);
    assert_suspended_gap(&scene, scene.caller, pid, SUSPENDED_EXEC_REASON);
    assert_eq!(
        scene
            .coordinator
            .adapter()
            .record(scene.caller)
            .unwrap()
            .authority,
        ImageAuthority::ScanPinned,
        "the successor image starts scan-pinned"
    );
    assert_eq!(
        scene.coordinator.adapter().live_id(pid),
        Some(scene.caller),
        "the caller stays live under its new image"
    );
    assert_eq!(staged_counts(&scene), (0, 0, 0));
    assert_eq!(reads.post_sample, 0, "no post-sample provider reads");
    assert_eq!(
        receipt.engine_facts, receipt.engine_published,
        "the refusal publishes the dirtied revisions"
    );
    scene.assert_conserved_physical_use();
}

#[test]
fn cgroup_native_owner_refresh_incomplete_transaction_abandons_prepared_state() {
    // A permitted owner's prepared refresh in an incomplete
    // transaction abandons silently: no commit, no suspend, the
    // staged flag and lease fully release (the next complete pass
    // refreshes normally), and the requested epoch stays pending
    // until that landing pass services it.
    let mut scene = ScopedNativeScene::new();
    let script: Vec<_> = (1..=20).map(|generation| (generation, 41, 1)).collect();
    let acquired = scene.set_scripted_acquisition(&script);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let owner = scene
        .coordinator
        .owner_of(scene.caller)
        .expect("the stable member activates");
    let first_pid = scene.child_id();

    // Admit an unsettled sibling: it has no binder image, so its
    // activation preparation vetoes before any acquisition and the
    // first owner's refresh carries the passes below.
    let second_child = scene.spawn_second_child("ready-b");
    let second_pid = second_child.id();
    scene.extra_children.push(second_child);
    scene.rewrite_membership(&[first_pid, second_pid]);
    let (completion, _, _) = scene.commit_observed_pass(None, second_pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(completion.admitted, 1, "the sibling is admitted");
    assert_eq!(
        acquired.borrow().calls(),
        10,
        "the first owner refreshed on the admission pass"
    );
    let epochs = scene
        .coordinator
        .engine
        .inventory_owner_epochs(owner)
        .unwrap();
    assert_eq!((epochs.requested, epochs.serviced), (1, 1));

    // Incomplete pass: the owner keeps its permit while the sibling
    // migrates out during provider retention.
    let (completion, _, _) =
        scene.commit_observed_pass(None, first_pid, PassAction::RetainOnly(first_pid));
    assert!(matches!(
        completion.outcome,
        ScopedCollectionOutcome::Incomplete(_)
    ));
    assert_eq!(scene.coordinator.owner_of(scene.caller), Some(owner));
    assert_eq!(
        acquired.borrow().calls(),
        15,
        "the refresh prepared before the fence refused"
    );
    let epochs = scene
        .coordinator
        .engine
        .inventory_owner_epochs(owner)
        .unwrap();
    assert_eq!(
        (epochs.requested, epochs.serviced),
        (2, 1),
        "the abandoned request stays pending"
    );
    assert_eq!(staged_counts(&scene), (1, 0, 0), "flag and lease released");
    assert!(
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .all(|gap| gap.subject != REFRESH_REFUSED_SUBJECT),
        "the fence abandon is silent"
    );
    assert_no_suspended_gap(&scene);

    // Landing pass over the retained membership: refresh commits.
    let completion = scene.commit_membership_pass_for(None, first_pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(acquired.borrow().calls(), 20);
    let epochs = scene
        .coordinator
        .engine
        .inventory_owner_epochs(owner)
        .unwrap();
    assert_eq!(
        (epochs.requested, epochs.serviced),
        (3, 3),
        "the landing pass services the pending refresh"
    );
    assert_eq!(staged_counts(&scene), (1, 0, 0));
}

#[test]
fn cgroup_native_owner_gap_reasons_carry_no_ticket_or_image_values() {
    // Privacy: across the standing, refusal, and suspend
    // disclosures one scene emits, reasons carry no scripted ticket
    // (41), cookie, or image values, and every gap's field shape
    // matches its subject's contract exactly.
    let mut scene = ScopedNativeScene::new();
    let _acquired = scene.set_scripted_acquisition(&[
        (1, 41, 1),
        (2, 41, 1),
        (3, 41, 1),
        (4, 41, 1),
        (5, 41, 1),
        (6, 41, 2),
        (7, 41, 2),
    ]);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let pid = scene.child_id();
    let (completion, _, _) = scene.commit_observed_pass(None, pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);

    let designed = [
        UNAVAILABLE_SUBJECT,
        REFRESH_REFUSED_SUBJECT,
        SUSPENDED_SUBJECT,
        "native owner activation refused",
        "engine tail revision failed",
    ];
    let gaps = scene.coordinator.registry().gaps();
    for subject in [
        UNAVAILABLE_SUBJECT,
        REFRESH_REFUSED_SUBJECT,
        SUSPENDED_SUBJECT,
    ] {
        assert!(
            gaps.iter().any(|gap| gap.subject == subject),
            "the scene emitted {subject}"
        );
    }
    for gap in gaps
        .iter()
        .filter(|gap| designed.contains(&gap.subject.as_str()))
    {
        assert!(
            !gap.reason.contains("41") && !gap.reason.contains("ticket"),
            "gap reason leaks scripted image values: {} / {}",
            gap.subject,
            gap.reason
        );
        if gap.subject == UNAVAILABLE_SUBJECT || gap.subject == "engine tail revision failed" {
            assert_eq!(
                (gap.caller, gap.module, gap.pid, gap.budget),
                (None, None, None, None),
                "{} names nothing",
                gap.subject
            );
        } else {
            assert!(
                gap.caller.is_some() && gap.pid.is_some(),
                "{} names its caller and pid",
                gap.subject
            );
            assert_eq!(
                (gap.module, gap.budget),
                (None, None),
                "{} names no module or budget",
                gap.subject
            );
        }
    }
}

#[test]
fn cgroup_native_owner_suspends_absent_member_and_keeps_other_owner() {
    // Suspend on absence: both members activate, then a complete
    // pass over membership without the first member cancels its
    // authority back to scan-pinned, releases its owner with the
    // exact suspended gap, and keeps the second owner's facts (the
    // second owner refreshes on that same pass).
    let mut scene = ScopedNativeScene::new();
    let provider = scene.dir.path().join("scoped-provider.so");
    let second_child = scene.spawn_second_child("ready-b");
    let (second_caller, second_pid, _) = scene.admit_and_settle_second_member(second_child, 42, 11);
    let first_pid = scene.child_id();
    let first_caller = scene.caller;
    let (early_ticket, late_ticket) = if first_pid < second_pid {
        (41, 42)
    } else {
        (42, 41)
    };
    let mut script = Vec::new();
    let mut generation = 1u64;
    for ticket in [early_ticket, late_ticket, late_ticket, 42] {
        for _ in 0..5 {
            script.push((generation, ticket, 1));
            generation += 1;
        }
    }
    let acquired = scene.set_scripted_acquisition(&script);
    let (early_caller, early_pid) = if first_pid < second_pid {
        (first_caller, first_pid)
    } else {
        (second_caller, second_pid)
    };
    let (late_caller, late_pid) = if first_pid < second_pid {
        (second_caller, second_pid)
    } else {
        (first_caller, first_pid)
    };
    let (completion, _, _) =
        scene.commit_observed_pass(Some(early_caller), early_pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let (completion, _, _) =
        scene.commit_observed_pass(Some(late_caller), late_pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let first_owner = scene
        .coordinator
        .owner_of(first_caller)
        .expect("first active");
    let second_owner = scene
        .coordinator
        .owner_of(second_caller)
        .expect("second active");
    assert_eq!(acquired.borrow().calls(), 15);
    assert_eq!(staged_counts(&scene), (2, 0, 0));

    scene.rewrite_membership(&[second_pid]);
    let completion = scene.commit_membership_pass_for(None, second_pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(
        scene.coordinator.owner_of(first_caller),
        None,
        "the absent member's owner releases"
    );
    assert_suspended_gap(&scene, first_caller, first_pid, SUSPENDED_ABSENT_REASON);
    assert_eq!(
        scene
            .coordinator
            .adapter()
            .record(first_caller)
            .unwrap()
            .authority,
        ImageAuthority::ScanPinned,
        "the migrated-out caller falls back to scan-pinned"
    );
    assert_eq!(
        scene.coordinator.owner_of(second_caller),
        Some(second_owner),
        "the resident owner is untouched"
    );
    assert_eq!(
        scene.engine_module_views_for(&provider),
        BTreeSet::from([second_owner.0]),
        "only the resident owner's facts remain"
    );
    assert!(
        scene
            .engine_module_facts()
            .iter()
            .all(|(view, _)| *view != first_owner.0),
        "the suspended owner retains no facts"
    );
    assert_eq!(staged_counts(&scene), (1, 0, 0), "capacity returns");
    assert_eq!(
        acquired.borrow().calls(),
        20,
        "the resident owner refreshed on the suspend pass"
    );
}

#[test]
fn cgroup_native_owner_suspends_retired_member_and_keeps_history() {
    // Suspend on death: the activated child dies and a successor
    // generation is admitted in a complete pass; the dead caller's
    // owner releases with the retired suspended gap while its
    // settled witness row stays bound for history.
    let mut scene = ScopedNativeScene::new();
    let script: Vec<_> = (1..=5).map(|generation| (generation, 41, 1)).collect();
    let acquired = scene.set_scripted_acquisition(&script);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert!(scene.coordinator.owner_of(scene.caller).is_some());
    assert_eq!(staged_counts(&scene), (1, 0, 0));

    let dead_pid = scene.kill_child();
    let successor = scene.spawn_second_child("ready-b");
    let successor_pid = successor.id();
    scene.child = Some(successor);
    scene.rewrite_membership(&[successor_pid]);
    let completion = scene.commit_membership_pass_for(None, successor_pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(completion.admitted, 1);
    assert!(
        scene
            .coordinator
            .adapter()
            .record(scene.caller)
            .unwrap()
            .retired,
        "the dead generation retires"
    );
    assert_eq!(scene.coordinator.owner_of(scene.caller), None);
    assert_suspended_gap(&scene, scene.caller, dead_pid, SUSPENDED_RETIRED_REASON);
    assert_eq!(
        scene.coordinator.registry().witness_census().bound,
        1,
        "the settled row stays bound for history"
    );
    assert_eq!(staged_counts(&scene), (0, 0, 0), "capacity returns");
    assert_eq!(acquired.borrow().calls(), 5, "suspend acquires nothing");
    let successor_caller = scene
        .coordinator
        .adapter()
        .live_id(successor_pid)
        .expect("the successor is admitted");
    assert_eq!(scene.coordinator.owner_of(successor_caller), None);
}

#[test]
fn cgroup_native_owner_incomplete_pass_never_suspends() {
    // A failed collection proves no absence: the member migrates
    // out mid-commit, the transaction is incomplete, and the owner
    // stands unsuspended even though its refresh prepared and was
    // refused for want of a permit.
    let mut scene = ScopedNativeScene::new();
    let script: Vec<_> = (1..=10).map(|generation| (generation, 41, 1)).collect();
    let acquired = scene.set_scripted_acquisition(&script);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let owner = scene.coordinator.owner_of(scene.caller).expect("active");

    let pid = scene.child_id();
    let (completion, _, _) = scene.commit_observed_pass(None, pid, PassAction::MigrateOut);
    assert!(matches!(
        completion.outcome,
        ScopedCollectionOutcome::Incomplete(_)
    ));
    assert_eq!(
        acquired.borrow().calls(),
        10,
        "the refresh reached the suspend decision point"
    );
    assert_eq!(
        scene.coordinator.owner_of(scene.caller),
        Some(owner),
        "an incomplete pass retains the owner"
    );
    assert_no_suspended_gap(&scene);
    assert_eq!(staged_counts(&scene), (1, 0, 0));
}

#[test]
fn cgroup_native_owner_migration_back_in_reactivates_fresh() {
    // Migration out suspends to scan-pinned; migration back in is
    // an ordinary fresh activation: a new owner id, exact authority
    // re-proved through scripted acquisition, and no reuse of the
    // released owner's state.
    let mut scene = ScopedNativeScene::new();
    let script: Vec<_> = (1..=10).map(|generation| (generation, 41, 1)).collect();
    let acquired = scene.set_scripted_acquisition(&script);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let first_owner = scene.coordinator.owner_of(scene.caller).expect("active");
    let pid = scene.child_id();

    scene.rewrite_membership(&[]);
    let completion = scene.commit_rewritten_membership_pass();
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(scene.coordinator.owner_of(scene.caller), None);
    assert_suspended_gap(&scene, scene.caller, pid, SUSPENDED_ABSENT_REASON);
    assert_eq!(
        scene
            .coordinator
            .adapter()
            .record(scene.caller)
            .unwrap()
            .authority,
        ImageAuthority::ScanPinned
    );
    assert_eq!(staged_counts(&scene), (0, 0, 0));

    scene.rewrite_membership(&[pid]);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let second_owner = scene
        .coordinator
        .owner_of(scene.caller)
        .expect("migration back in reactivates");
    assert_ne!(
        second_owner, first_owner,
        "reactivation mints a fresh owner id"
    );
    assert!(matches!(
        scene
            .coordinator
            .adapter()
            .record(scene.caller)
            .unwrap()
            .authority,
        ImageAuthority::NativeExact { .. }
    ));
    let epochs = scene
        .coordinator
        .engine
        .inventory_owner_epochs(second_owner)
        .unwrap();
    assert_eq!(
        epochs.image_state,
        super::super::inventory::ImageCheck::Exact
    );
    assert_eq!((epochs.requested, epochs.serviced), (0, 0));
    assert_eq!(acquired.borrow().calls(), 10);
    assert_eq!(staged_counts(&scene), (1, 0, 0));
}

#[test]
fn cgroup_native_owner_suspend_cycles_conserve_capacity() {
    // Repeated activate/suspend cycles return owner, reservation,
    // and lease counts to baseline every cycle, and a fresh
    // activation still succeeds afterwards with live pin claims:
    // suspend leaks no retained capacity.
    let mut scene = ScopedNativeScene::new();
    assert_eq!(staged_counts(&scene), (0, 0, 0), "baseline");
    let script: Vec<_> = (1..=20).map(|generation| (generation, 41, 1)).collect();
    let acquired = scene.set_scripted_acquisition(&script);
    let pid = scene.child_id();

    for cycle in 0..3 {
        let completion = scene.commit_membership_pass(false);
        assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
        assert!(
            scene.coordinator.owner_of(scene.caller).is_some(),
            "cycle {cycle}: activation succeeds"
        );
        assert_eq!(staged_counts(&scene), (1, 0, 0), "cycle {cycle}: one owner");
        scene.rewrite_membership(&[]);
        let completion = scene.commit_rewritten_membership_pass();
        assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
        assert_eq!(
            scene.coordinator.owner_of(scene.caller),
            None,
            "cycle {cycle}: suspend releases"
        );
        assert_eq!(
            staged_counts(&scene),
            (0, 0, 0),
            "cycle {cycle}: counts return to baseline"
        );
        scene.rewrite_membership(&[pid]);
    }

    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let owner = scene
        .coordinator
        .owner_of(scene.caller)
        .expect("activation still succeeds after the cycles");
    let claims = scene
        .coordinator
        .engine
        .pinned
        .view_claims(owner)
        .expect("the fresh owner retains pin claims");
    assert!(
        !claims.pins.is_empty() || !claims.tables.is_empty() || !claims.targets.is_empty(),
        "claim capacity is conserved"
    );
    assert_eq!(acquired.borrow().calls(), 20);
    assert_eq!(staged_counts(&scene), (1, 0, 0));
}

/// The shared late-loss disposition: the refresh refused by name
/// for `refusal_needle`, then the owner suspended in the same
/// complete pass with the lost-member reason — authority back
/// to scan-pinned, flag/lease/capacity released, the settled
/// witness history kept.
fn assert_late_permit_loss_suspended(scene: &ScopedNativeScene, pid: u32, refusal_needle: &str) {
    assert!(
        scene.coordinator.registry().gaps().iter().any(|gap| {
            gap.subject == REFRESH_REFUSED_SUBJECT
                && gap.caller == Some(scene.caller)
                && gap.pid == Some(pid)
                && gap.module.is_none()
                && gap.budget.is_none()
                && gap.reason.contains(refusal_needle)
        }),
        "the late refresh refusal names its stage: {:?}",
        scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        scene.coordinator.owner_of(scene.caller),
        None,
        "the lost member's owner releases in the same pass"
    );
    assert_suspended_gap(scene, scene.caller, pid, SUSPENDED_LOST_REASON);
    assert_eq!(
        scene
            .coordinator
            .adapter()
            .record(scene.caller)
            .unwrap()
            .authority,
        ImageAuthority::ScanPinned,
        "native authority cancels back to scan-pinned"
    );
    assert!(
        !scene.coordinator.engine.scoped_refresh_in_progress(),
        "no refresh candidate flag survives"
    );
    assert_eq!(
        staged_counts(scene),
        (0, 0, 0),
        "owner, reservation and lease capacity return"
    );
    assert_eq!(
        scene.coordinator.registry().witness_census().bound,
        1,
        "the settled row stays bound for history"
    );
}

#[test]
fn cgroup_native_owner_refresh_permit_loss_after_admission_suspends() {
    // The member dies between its admission permit and the staged
    // refresh's later permit poll: the second poll grants nothing
    // while the transaction stays complete, so the pass must
    // withdraw the caller's earlier admission standing and
    // suspend its owner in the same pass — refused and suspended
    // gaps are both honest. The incomplete-transaction controls
    // (migration/incomplete twins above) keep the opposite pin:
    // a failed collection proves no absence and retains the owner.
    let mut scene = ScopedNativeScene::new();
    let script: Vec<_> = (1..=10).map(|generation| (generation, 41, 1)).collect();
    let acquired = scene.set_scripted_acquisition(&script);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert!(
        scene.coordinator.owner_of(scene.caller).is_some(),
        "the stable member activates"
    );
    assert_eq!(acquired.borrow().calls(), 5);

    let pid = scene.child_id();
    let completion = scene.commit_gated_pass(pid, CollectionControl::new(None), move |phase| {
        if phase == super::scoped_commit_gate_test::Phase::GateSampled {
            kill_and_reap_owned_child(pid);
        }
    });
    assert_eq!(
        completion.outcome,
        ScopedCollectionOutcome::Complete,
        "the late death alone does not incomplete the transaction"
    );
    assert_eq!(
        acquired.borrow().calls(),
        10,
        "the refresh fully prepared before the gate"
    );
    assert_late_permit_loss_suspended(&scene, pid, "final-sample permit was not granted");
}

#[test]
fn cgroup_native_owner_refresh_proof_loss_after_admission_suspends() {
    // The refresh permit itself is granted, then the member dies
    // before the permit proof re-checks liveness: proof
    // validation refuses after a granted permit, in a still
    // complete transaction, so the owner suspends in the same
    // pass as the refusal.
    let mut scene = ScopedNativeScene::new();
    let script: Vec<_> = (1..=10).map(|generation| (generation, 41, 1)).collect();
    let acquired = scene.set_scripted_acquisition(&script);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert!(
        scene.coordinator.owner_of(scene.caller).is_some(),
        "the stable member activates"
    );
    assert_eq!(acquired.borrow().calls(), 5);

    let pid = scene.child_id();
    let completion = scene.commit_gated_pass(pid, CollectionControl::new(None), move |phase| {
        if phase == super::scoped_commit_gate_test::Phase::RefreshPermitPolled {
            kill_and_reap_owned_child(pid);
        }
    });
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(acquired.borrow().calls(), 10);
    assert_late_permit_loss_suspended(&scene, pid, "does not match the final-sample permit");
}

#[test]
fn cgroup_native_owner_refresh_commit_liveness_loss_suspends() {
    // The proof validates, then the member dies before the
    // engine commit re-checks the retained view's liveness: the
    // commit refuses on liveness in a still complete
    // transaction, so the owner suspends in the same pass —
    // distinguished from unrelated commit failures, which keep
    // the owner, and from a proven image change, which suspends
    // with the exec reason (twins above).
    let mut scene = ScopedNativeScene::new();
    let script: Vec<_> = (1..=10).map(|generation| (generation, 41, 1)).collect();
    let acquired = scene.set_scripted_acquisition(&script);
    let completion = scene.commit_membership_pass(false);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert!(
        scene.coordinator.owner_of(scene.caller).is_some(),
        "the stable member activates"
    );
    assert_eq!(acquired.borrow().calls(), 5);

    let pid = scene.child_id();
    let completion = scene.commit_gated_pass(pid, CollectionControl::new(None), move |phase| {
        if phase == super::scoped_commit_gate_test::Phase::RefreshProofValidated {
            kill_and_reap_owned_child(pid);
        }
    });
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    assert_eq!(acquired.borrow().calls(), 10);
    assert_late_permit_loss_suspended(&scene, pid, "liveness or pid changed at refresh commit");
}

#[test]
fn cgroup_native_owner_cancellation_after_gate_suspends_nobody() {
    // Cancellation latches after the transaction outcome was
    // sampled complete but before teardown: the suspend decision
    // must poll the current outcome, not the pre-loop sample, so
    // the absent member's owner stands with its native
    // authority, the resident owner stands with its refresh
    // state cleared, and the pass reports the cancellation. The
    // two-owner suspend twin above keeps the successful
    // teardown control on the same scene shape.
    let mut scene = ScopedNativeScene::new();
    let second_child = scene.spawn_second_child("ready-b");
    let (second_caller, second_pid, _) = scene.admit_and_settle_second_member(second_child, 42, 11);
    let first_pid = scene.child_id();
    let first_caller = scene.caller;
    let (early_ticket, late_ticket) = if first_pid < second_pid {
        (41, 42)
    } else {
        (42, 41)
    };
    let mut script = Vec::new();
    let mut generation = 1u64;
    for ticket in [early_ticket, late_ticket, late_ticket, 42] {
        for _ in 0..5 {
            script.push((generation, ticket, 1));
            generation += 1;
        }
    }
    let acquired = scene.set_scripted_acquisition(&script);
    let (early_caller, early_pid) = if first_pid < second_pid {
        (first_caller, first_pid)
    } else {
        (second_caller, second_pid)
    };
    let (late_caller, late_pid) = if first_pid < second_pid {
        (second_caller, second_pid)
    } else {
        (first_caller, first_pid)
    };
    let (completion, _, _) =
        scene.commit_observed_pass(Some(early_caller), early_pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let (completion, _, _) =
        scene.commit_observed_pass(Some(late_caller), late_pid, PassAction::Stable);
    assert_eq!(completion.outcome, ScopedCollectionOutcome::Complete);
    let first_owner = scene
        .coordinator
        .owner_of(first_caller)
        .expect("first active");
    let second_owner = scene
        .coordinator
        .owner_of(second_caller)
        .expect("second active");
    assert_eq!(acquired.borrow().calls(), 15);
    assert_eq!(staged_counts(&scene), (2, 0, 0));

    scene.rewrite_membership(&[second_pid]);
    let control = CollectionControl::new(None);
    let stop = control.clone();
    let completion = scene.commit_gated_pass(second_pid, control, move |phase| {
        if phase == super::scoped_commit_gate_test::Phase::GateSampled {
            stop.cancel();
        }
    });
    assert_eq!(
        completion.outcome,
        ScopedCollectionOutcome::Cancelled(
            crate::scope::inventory_cgroup::CollectionStop::OperatorStop
        )
    );
    assert_eq!(
        acquired.borrow().calls(),
        20,
        "the resident refresh prepared before the gate"
    );
    assert_eq!(
        scene.coordinator.owner_of(first_caller),
        Some(first_owner),
        "a cancelled pass suspends nobody: the absent owner stands"
    );
    assert_eq!(
        scene.coordinator.owner_of(second_caller),
        Some(second_owner),
        "the resident owner stands"
    );
    assert!(
        matches!(
            scene
                .coordinator
                .adapter()
                .record(first_caller)
                .unwrap()
                .authority,
            ImageAuthority::NativeExact { .. }
        ),
        "native authority stands unsuspended"
    );
    assert_no_suspended_gap(&scene);
    assert!(
        !scene.coordinator.engine.scoped_refresh_in_progress(),
        "refresh state cleared"
    );
    assert_eq!(
        staged_counts(&scene),
        (2, 0, 0),
        "both owners retain their capacity"
    );
}
