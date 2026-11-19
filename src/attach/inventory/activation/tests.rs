//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Behavioral contracts for the production Inventory activation helpers.
//! Only kernel link/map operations are replaced; target pinning uses real files.

use super::*;

#[path = "exit_retention_tests.rs"]
mod exit_retention;
use crate::discovery::identity::pin_scanned_view_objects;
use crate::discovery::scan::{CaptureWorkBudget, ScannedModule};
use crate::plan::{AdmissionPolicy, AttachPlan, Slot};
use crate::process::{ProcessView, ProcessViewId};
use p11scope_ebpf_common::SlotSemantics;
use p11scope_manifest::identity::{inspect_file, mapping_file_key, open_object};
use p11scope_manifest::maps::{Device, ObjectKey};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[path = "retirement_concurrency_tests.rs"]
mod bounded_concurrency;

fn budget(n: u32) -> InventoryBudget {
    InventoryBudget::new(u64::from(n), u64::from(n) * 8).unwrap()
}

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    pins: PinnedObjects,
    object: PinnedObjectId,
    offset: u64,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("owned-provider.so");
        std::fs::copy("/bin/sh", &path).unwrap();
        let file = open_object(&path).unwrap();
        let mapping = mapping_file_key(&file).unwrap();
        let inspected = inspect_file(&file).unwrap();
        let &(offset, end) = inspected
            .executable_ranges
            .iter()
            .find(|&&(start, end)| end - start >= 1024)
            .expect("owned ELF has a bounded executable fixture range");
        assert!(end > offset + 576);
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let module = ScannedModule {
            key_is_identity: false,
            module_hint: None,
            mapped_identity: None,
            double_loaded: false,
            same_file_loads: 1,
            pre_copy_up: None,
            view: view.id(),
            mount_namespace: view.mount_namespace(),
            key: ObjectKey {
                device: Device {
                    major: mapping.device_major,
                    minor: mapping.device_minor,
                },
                inode: mapping.inode,
            },
            path: path.display().to_string(),
            tables_scan_finished: false,
            decoder_abi: None,
            exports: vec![],
            tables: vec![],
            interfaces: vec![],
        };
        let (pins, skipped) =
            pin_scanned_view_objects(&view, &[module], &mut CaptureWorkBudget::default()).unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        let object = pins.pinned().next().unwrap().id;
        Self {
            _directory: directory,
            path,
            pins,
            object,
            offset,
        }
    }

    fn plan(&self, count: u32, capacity: u32) -> AttachPlan {
        let slots = (0..count)
            .map(|id| Slot {
                index: id,
                descriptor_index: 0,
                object: self.object,
                object_path: self.path.display().to_string(),
                file_offset: self.offset + u64::from(id),
                names: vec![format!("owned_{id}")],
                aliased: false,
                semantics: SlotSemantics::COUNT_ONLY,
                semantic_authorized: false,
                semantic_ambiguous: false,
                fork_safe: false,
                module_ids: vec![],
            })
            .collect();
        AttachPlan::from_slots_with_policy(slots, AdmissionPolicy::Inventory(budget(capacity)))
            .unwrap()
    }

    fn targets(&self, count: u32, capacity: u32) -> InventoryTargets {
        InventoryTargets::from_plan(&self.plan(count, capacity), &self.pins).unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Request {
    Lifecycle {
        program: String,
        tracepoint: String,
    },
    Entry {
        program: String,
        path: PathBuf,
        offset: u64,
        cookie: u64,
    },
    Return {
        program: String,
        path: PathBuf,
        offset: u64,
        cookie: u64,
    },
}

#[derive(Default)]
struct Observed {
    requests: Vec<Request>,
    detach_attempts: Vec<usize>,
    live: BTreeSet<usize>,
    dropped: Vec<usize>,
}

struct TestLink {
    ordinal: usize,
    state: Arc<Mutex<Observed>>,
}

impl Drop for TestLink {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap();
        state.live.remove(&self.ordinal);
        state.dropped.push(self.ordinal);
    }
}

#[derive(Default, Clone)]
struct LinkIo {
    state: Arc<Mutex<Observed>>,
    fail_attach: Option<usize>,
    fail_detach: BTreeSet<usize>,
    fail_custody: Option<usize>,
    mutate_after_attach: Option<(usize, PathBuf)>,
}

impl InventoryLinkIo for LinkIo {
    type Link = TestLink;

    fn publish_endpoint(&mut self, _endpoint: u32, _object: PinnedObjectId) -> Result<()> {
        Ok(())
    }

    fn attach(&mut self, request: InventoryAttachRequest<'_>) -> anyhow::Result<Self::Link> {
        let request = match request {
            InventoryAttachRequest::Lifecycle {
                program,
                tracepoint,
            } => Request::Lifecycle {
                program: program.into(),
                tracepoint: tracepoint.into(),
            },
            InventoryAttachRequest::Entry {
                program,
                path,
                file_offset,
                cookie,
            } => Request::Entry {
                program: program.into(),
                path: path.into(),
                offset: file_offset,
                cookie,
            },
            InventoryAttachRequest::Return {
                program,
                path,
                file_offset,
                cookie,
            } => Request::Return {
                program: program.into(),
                path: path.into(),
                offset: file_offset,
                cookie,
            },
        };
        let ordinal = self.state.lock().unwrap().requests.len();
        self.state.lock().unwrap().requests.push(request);
        if self.fail_attach == Some(ordinal) {
            anyhow::bail!("original attach failure {ordinal}");
        }
        self.state.lock().unwrap().live.insert(ordinal);
        if let Some((when, path)) = &self.mutate_after_attach
            && *when == ordinal
        {
            std::fs::OpenOptions::new()
                .append(true)
                .open(path)?
                .write_all(&[0])?;
        }
        Ok(TestLink {
            ordinal,
            state: self.state.clone(),
        })
    }

    fn detach(&mut self, link: &mut Self::Link) -> anyhow::Result<()> {
        self.state
            .lock()
            .unwrap()
            .detach_attempts
            .push(link.ordinal);
        if self.fail_detach.contains(&link.ordinal) {
            anyhow::bail!("uncertain detach {}", link.ordinal);
        }
        self.state.lock().unwrap().live.remove(&link.ordinal);
        Ok(())
    }

    fn attachment_error(&self, link: &Self::Link) -> Option<String> {
        (self.fail_custody == Some(link.ordinal)).then(|| "post-acquisition custody failure".into())
    }
}

/// Replaces only the map-publication/link IO boundary. The real attach
/// transaction must order all bindings before even its lifecycle producers.
#[derive(Default)]
struct CallerLinkIo {
    inner: LinkIo,
    committed: Vec<(u32, PinnedObjectId)>,
    publication_failure: Option<u32>,
    published_at_first_attach: Option<usize>,
}

impl InventoryLinkIo for CallerLinkIo {
    type Link = TestLink;

    fn publish_endpoint(&mut self, endpoint: u32, object: PinnedObjectId) -> Result<()> {
        if self.publication_failure == Some(endpoint) {
            bail!("owned endpoint {endpoint} publication/readback failure");
        }
        self.committed.push((endpoint, object));
        Ok(())
    }

    fn attach(&mut self, request: InventoryAttachRequest<'_>) -> Result<Self::Link> {
        self.published_at_first_attach
            .get_or_insert(self.committed.len());
        self.inner.attach(request)
    }

    fn detach(&mut self, link: &mut Self::Link) -> Result<()> {
        self.inner.detach(link)
    }

    fn attachment_error(&self, link: &Self::Link) -> Option<String> {
        self.inner.attachment_error(link)
    }
}

#[test]
fn caller_activation_publishes_all_physical_bindings_before_first_lifecycle_producer() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.object,
        PinnedObjectId(0),
        "object zero is a valid physical owner"
    );
    let targets = fixture.targets(2, 3);
    let mut io = CallerLinkIo::default();
    let links = attach_inventory_with(&mut io, &targets).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        io.committed,
        [(0, PinnedObjectId(0)), (1, PinnedObjectId(0))],
        "caller endpoint bindings were not published"
    );
    assert_eq!(
        io.published_at_first_attach,
        Some(2),
        "a producer preceded endpoint publication"
    );
    assert_eq!(links.len(), 4);
    drop(links);
    assert!(io.inner.state.lock().unwrap().live.is_empty());
}

#[test]
fn caller_activation_publication_failure_keeps_prior_binding_and_attaches_nothing() {
    let fixture = Fixture::new();
    let targets = fixture.targets(2, 3);
    let mut io = CallerLinkIo {
        publication_failure: Some(1),
        ..Default::default()
    };
    let failure = attach_inventory_with(&mut io, &targets)
        .err()
        .expect("caller publication failure must prevent every producer");
    assert!(
        format!("{:#}", failure.error).contains("owned endpoint 1 publication/readback failure")
    );
    assert_eq!(io.committed, [(0, fixture.object)]);
    assert!(failure.links.is_empty());
    assert_eq!(io.published_at_first_attach, None);
    assert!(io.inner.state.lock().unwrap().requests.is_empty());
    assert_eq!(targets.allocated, [0, 1], "failed IDs stay allocated");
}

#[test]
fn caller_activation_later_attach_failure_keeps_bindings_and_existing_retirement_custody() {
    let fixture = Fixture::new();
    let targets = fixture.targets(2, 3);
    let mut io = CallerLinkIo {
        inner: LinkIo {
            fail_attach: Some(3),
            ..Default::default()
        },
        ..Default::default()
    };
    let failure = attach_inventory_with(&mut io, &targets)
        .err()
        .expect("injected entry attach failure");
    assert_eq!(io.committed, [(0, fixture.object), (1, fixture.object)]);
    assert_eq!(io.published_at_first_attach, Some(2));
    assert_eq!(targets.allocated, [0, 1]);
    assert_eq!(
        failure.links.len(),
        3,
        "all acquired handles stay owned by the failure"
    );
    let failure = finish_failed_transaction(&io.inner, failure);
    assert!(format!("{:#}", failure.error).contains("original attach failure 3"));
    assert_eq!(failure.cleanup.closed, 3);
    assert!(failure.links.is_empty());
    assert_eq!(
        io.committed,
        [(0, fixture.object), (1, fixture.object)],
        "retirement must not clear metadata"
    );
    assert!(io.inner.state.lock().unwrap().live.is_empty());
}

#[test]
fn caller_activation_leaves_inactive_id_allocated_without_publishing_or_reusing_it() {
    let fixture = Fixture::new();
    let mut plan = fixture.plan(3, 3);
    plan.deactivate(1);
    let targets = InventoryTargets::from_plan(&plan, &fixture.pins).unwrap();
    let mut io = CallerLinkIo::default();
    let links = attach_inventory_with(&mut io, &targets).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(targets.allocated, [0, 1, 2]);
    assert_eq!(io.committed, [(0, fixture.object), (2, fixture.object)]);
    assert_eq!(io.published_at_first_attach, Some(2));
    assert_eq!(links.len(), 4);
    drop(links);
    assert!(io.inner.state.lock().unwrap().live.is_empty());
}

#[test]
fn caller_activation_changed_pin_prevents_publication_and_attachment() {
    let fixture = Fixture::new();
    let targets = fixture.targets(2, 3);
    std::fs::OpenOptions::new()
        .append(true)
        .open(&fixture.path)
        .unwrap()
        .write_all(&[0])
        .unwrap();
    let mut io = CallerLinkIo::default();
    let failure = attach_inventory_with(&mut io, &targets)
        .err()
        .expect("changed pin was accepted");
    assert!(format!("{:#}", failure.error).contains("changed"));
    assert!(io.committed.is_empty());
    assert!(failure.links.is_empty());
    assert!(io.inner.state.lock().unwrap().requests.is_empty());
}

fn finish_failed_transaction(
    io: &LinkIo,
    mut failure: InventoryAttachFailure<TestLink>,
) -> InventoryAttachFailure<TestLink> {
    let links = std::mem::take(&mut failure.links)
        .into_iter()
        .map(|link| RetirementLink {
            target: link.target,
            handle: Some(link.handle),
            quarantine: None,
            _leases: Arc::default(),
        })
        .collect();
    let mut io = io.clone();
    let mut job = RetirementJob::start(
        RetirementWork::new(links, vec![]),
        serial_fixture_close(move |link| io.detach(link)),
    )
    .unwrap_or_else(|error| panic!("failed rollback worker: {}", error.error));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(mut work) = job.poll(deadline).unwrap() {
            let (receipt, links) = work.take_result();
            failure.cleanup = receipt;
            failure.links = links
                .into_iter()
                .filter_map(|link| {
                    link.handle.map(|handle| InventoryLinked {
                        target: link.target,
                        handle,
                    })
                })
                .collect();
            return failure;
        }
        assert!(Instant::now() < deadline, "rollback worker deadline");
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn inventory_activation_preserves_exact_high_id_entry_cookies_and_two_lifecycle_roots() {
    let fixture = Fixture::new();
    let targets = fixture.targets(576, 576);
    validate_activation(
        &Scope::System,
        AttachBackend::Singles,
        budget(576),
        &targets,
    )
    .unwrap();
    let mut io = LinkIo::default();
    let links = attach_inventory_with(&mut io, &targets).unwrap_or_else(|error| panic!("{error}"));
    let state = io.state.lock().unwrap();
    assert_eq!(state.requests.len(), 578);
    assert_eq!(
        state.requests[0],
        Request::Lifecycle {
            program: "sched_process_exec".into(),
            tracepoint: "sched_process_exec".into(),
        }
    );
    assert_eq!(
        state.requests[1],
        Request::Lifecycle {
            program: "sched_process_exit".into(),
            tracepoint: "sched_process_exit".into(),
        }
    );
    let path = fixture.pins.attach_path_for(fixture.object).unwrap();
    for (id, request) in state.requests[2..].iter().enumerate() {
        assert_eq!(
            *request,
            Request::Entry {
                program: "p11_usage_entry_lp64".into(),
                path: path.clone(),
                offset: fixture.offset + id as u64,
                cookie: 0x5055_5347_0000_0000 | id as u64,
            }
        );
    }
    assert_eq!(state.live.len(), 578);
    drop(state);
    drop(links);
    assert!(io.state.lock().unwrap().live.is_empty());
}

#[test]
fn inventory_activation_refuses_pid_multi_and_different_budget_before_link_io() {
    let fixture = Fixture::new();
    let targets = fixture.targets(2, 576);
    for (scope, backend, configured, expected) in [
        (
            Scope::Pid(std::process::id()),
            AttachBackend::Singles,
            budget(576),
            "generation",
        ),
        (Scope::System, AttachBackend::Multi, budget(576), "Singles"),
        (Scope::System, AttachBackend::Singles, budget(577), "budget"),
    ] {
        let error = validate_activation(&scope, backend, configured, &targets).unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
    }
}

#[test]
fn inventory_targets_reject_detailed_missing_pins_and_mutated_ids_or_descriptors() {
    let fixture = Fixture::new();
    let original = fixture.plan(2, 576);
    let detailed = AttachPlan::from_slots(original.slots.clone());
    assert!(InventoryTargets::from_plan(&detailed, &fixture.pins).is_err());
    assert!(InventoryTargets::from_plan(&original, &PinnedObjects::empty()).is_err());
    for field in 0..5 {
        let mut plan = original.clone();
        match field {
            0 => plan.slots[1].index = 576,
            1 => plan.slots[1].descriptor_index = 1,
            2 => plan.slots[1].file_offset = plan.slots[0].file_offset,
            3 => plan.slots[1].semantic_authorized = true,
            // Keep the public slots unique and in range while invalidating
            // the private exact-target index retained by AttachPlan.
            4 => plan.slots[1].file_offset += 17,
            _ => unreachable!(),
        }
        assert!(
            InventoryTargets::from_plan(&plan, &fixture.pins).is_err(),
            "field {field}"
        );
    }
}

#[test]
fn inventory_activation_rolls_back_each_failed_stage_and_preserves_original_error() {
    let fixture = Fixture::new();
    for failed in 0..5 {
        let targets = fixture.targets(3, 576);
        let mut io = LinkIo {
            fail_attach: Some(failed),
            ..Default::default()
        };
        let failure = match attach_inventory_with(&mut io, &targets) {
            Ok(_) => panic!("stage {failed} unexpectedly succeeded"),
            Err(failure) => finish_failed_transaction(&io, failure),
        };
        assert!(
            format!("{:#}", failure.error).contains(&format!("original attach failure {failed}"))
        );
        assert_eq!(io.state.lock().unwrap().requests.len(), failed + 1);
        assert!(io.state.lock().unwrap().live.is_empty());
        assert_eq!(failure.cleanup.closed, failed);
        assert!(failure.cleanup.failures.is_empty());
        assert!(failure.links.is_empty());
    }
}

#[test]
fn inventory_failed_rollback_retains_uncertain_handle_and_attempts_remaining_cleanup() {
    let fixture = Fixture::new();
    let targets = fixture.targets(3, 576);
    let mut io = LinkIo {
        fail_attach: Some(4),
        fail_detach: BTreeSet::from([2]),
        ..Default::default()
    };
    let failure = match attach_inventory_with(&mut io, &targets) {
        Ok(_) => panic!("failed activation unexpectedly succeeded"),
        Err(failure) => finish_failed_transaction(&io, failure),
    };
    assert!(format!("{:#}", failure.error).contains("original attach failure 4"));
    let attempts = io.state.lock().unwrap().detach_attempts.clone();
    assert_eq!(attempts.len(), 4);
    assert_eq!(
        attempts[..2].iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([2, 3])
    );
    assert_eq!(
        attempts[2..].iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([0, 1])
    );
    assert_eq!(io.state.lock().unwrap().live, BTreeSet::from([2]));
    assert_eq!(failure.cleanup.closed, 3);
    assert_eq!(failure.cleanup.failures.len(), 1);
    assert_eq!(failure.links.len(), 1);
    assert!(!io.state.lock().unwrap().dropped.contains(&2));
    drop(failure);
    assert!(io.state.lock().unwrap().live.is_empty());
}

#[test]
fn inventory_post_acquisition_failure_keeps_its_handle_and_original_error() {
    let fixture = Fixture::new();
    for ordinal in [0, 2] {
        let targets = fixture.targets(2, 576);
        let mut io = LinkIo {
            fail_custody: Some(ordinal),
            fail_detach: BTreeSet::from([ordinal]),
            ..Default::default()
        };
        let failure = match attach_inventory_with(&mut io, &targets) {
            Ok(_) => panic!("custody failure was reported as successful activation"),
            Err(failure) => finish_failed_transaction(&io, failure),
        };
        assert!(format!("{:#}", failure.error).contains("post-acquisition custody failure"));
        assert_eq!(failure.cleanup.attempted, ordinal + 1);
        assert_eq!(failure.cleanup.closed, ordinal);
        assert_eq!(failure.cleanup.failures.len(), 1);
        assert_eq!(failure.links.len(), 1);
        assert_eq!(io.state.lock().unwrap().live, BTreeSet::from([ordinal]));
        assert!(!io.state.lock().unwrap().dropped.contains(&ordinal));
    }
}

#[test]
fn inventory_private_target_abi_or_id_drift_is_refused_before_any_root_link() {
    let fixture = Fixture::new();
    for abi_drift in [false, true] {
        let mut targets = fixture.targets(1, 576);
        if abi_drift {
            targets.entries[0].abi = ElfAbi::Ilp32;
        } else {
            targets.entries[0].id = 576;
        }
        let mut io = LinkIo::default();
        let failure = match attach_inventory_with(&mut io, &targets) {
            Ok(_) => panic!("altered immutable target activated"),
            Err(failure) => finish_failed_transaction(&io, failure),
        };
        let expected = if abi_drift { "ABI" } else { "exceeds N" };
        assert!(format!("{:#}", failure.error).contains(expected));
        assert!(io.state.lock().unwrap().requests.is_empty());
        assert_eq!(failure.cleanup.attempted, 0);
    }
}

/// Keymeta Task 7 stop scrub (spec §17.4): the retirement poll
/// drives the INFO_START scrub as explicit bounded steps with
/// progress carried across polls — never an unbounded sweep in one
/// poll — and refuses to scrub while links are retained (probes
/// still mutating), transferring with teardown explicitly unproven
/// instead.
#[test]
fn stop_scrub_is_bounded_resumable_and_refuses_retained_links() {
    let source = std::fs::read_to_string("src/attach/inventory/activation.rs")
        .expect("read activation source");
    assert!(
        source.contains("scrub: InfoScrubPhase"),
        "RetiringInventory carries scrub progress across polls"
    );
    assert!(
        source.contains("scrub_info_start_step"),
        "the scrub runs as bounded steps"
    );
    let lines: Vec<&str> = source.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.contains("pub(super) fn try_finish"))
        .expect("try_finish exists");
    let body = lines[start..(start + 80).min(lines.len())].join("\n");
    assert!(
        body.contains("failures.is_empty()"),
        "try_finish refuses to scrub while links are retained"
    );
}

#[test]
fn inventory_full_stop_closes_entries_before_lifecycle_and_retains_uncertainty() {
    let fixture = Fixture::new();
    let targets = fixture.targets(3, 576);
    let mut io = LinkIo::default();
    let mut links =
        attach_inventory_with(&mut io, &targets).unwrap_or_else(|error| panic!("{error}"));
    io.fail_detach.insert(3);
    let receipt = stop_inventory_links_with(&mut io, &mut links);
    assert_eq!(io.state.lock().unwrap().detach_attempts, [4, 3, 2, 1, 0]);
    assert_eq!(receipt.closed, 4);
    assert_eq!(receipt.failures.len(), 1);
    assert_eq!(links.len(), 1);
    assert!(!receipt.callback_quiescence_proven);
    assert_eq!(io.state.lock().unwrap().live, BTreeSet::from([3]));
}

#[test]
fn inventory_pin_drift_before_or_during_attach_refuses_success_and_cleans_links() {
    for during in [false, true] {
        let fixture = Fixture::new();
        let targets = fixture.targets(2, 576);
        let mut io = LinkIo::default();
        if during {
            io.mutate_after_attach = Some((2, fixture.path.clone()));
        } else {
            std::fs::OpenOptions::new()
                .append(true)
                .open(&fixture.path)
                .unwrap()
                .write_all(&[0])
                .unwrap();
        }
        let failure = match attach_inventory_with(&mut io, &targets) {
            Ok(_) => panic!("changed provider unexpectedly attached"),
            Err(failure) => finish_failed_transaction(&io, failure),
        };
        assert!(format!("{:#}", failure.error).contains("changed"));
        assert!(targets.provider_changed());
        assert!(io.state.lock().unwrap().live.is_empty());
        if !during {
            assert!(io.state.lock().unwrap().requests.is_empty());
        }
    }
}

#[test]
fn inventory_targets_keep_exact_inode_after_original_pins_drop_and_path_replacement() {
    let mut fixture = Fixture::new();
    let targets = fixture.targets(1, 576);
    let retained_path = fixture.pins.attach_path_for(fixture.object).unwrap();
    let original = std::fs::metadata(&retained_path).unwrap();
    fixture.pins = PinnedObjects::empty();
    let moved = fixture.path.with_extension("retired");
    std::fs::rename(&fixture.path, &moved).unwrap();
    std::fs::copy("/bin/sh", &fixture.path).unwrap();
    let retained = std::fs::metadata(&retained_path).unwrap();
    assert_eq!(
        (retained.dev(), retained.ino()),
        (original.dev(), original.ino())
    );
    assert_ne!(
        std::fs::metadata(&fixture.path).unwrap().ino(),
        retained.ino()
    );
    // Rename may change ctime. Retention is independent of a later mutation refusal.
    assert_eq!(targets.pins.len(), 1);
    drop(targets);
    // Other parallel tests may immediately reuse the closed descriptor number.
    if let Ok(reused) = std::fs::metadata(retained_path) {
        assert_ne!(
            (reused.dev(), reused.ino()),
            (original.dev(), original.ino())
        );
    }
}

fn read_window(cells: usize) -> InventoryReadWindow {
    InventoryReadWindow::new(cells, Instant::now() + Duration::from_secs(5)).unwrap()
}

#[test]
fn inventory_usage_reads_only_allocated_cells_with_fair_cursor_and_monotonic_positives() {
    let mut history = InventoryUsageHistory::new(vec![0, 512, 575]);
    let values = BTreeMap::from([(0, 0), (512, 1), (575, 1)]);
    let mut reads = vec![];
    let first = history.read_with(read_window(2), |id| {
        reads.push(id);
        Ok(values[&id])
    });
    assert_eq!(reads, [0, 512]);
    assert_eq!(first.newly_positive, [512]);
    assert_eq!(first.cells_read, 2);
    assert_eq!(first.positive_count, 1);
    let second = history.read_with(read_window(2), |id| {
        reads.push(id);
        Ok(values[&id])
    });
    assert_eq!(reads, [0, 512, 575, 0]);
    assert_eq!(second.newly_positive, [575]);
    assert_eq!(second.positive_count, 2);
    let third = history.read_with(read_window(20), |_| Ok(0));
    assert_eq!(
        third.cells_read, 3,
        "one window cannot spin over the same allocated cell"
    );
    assert!(third.newly_positive.is_empty());
    assert_eq!(third.positive_count, 2);
    assert!(history.is_positive(512));
    assert!(history.is_positive(575));
    assert!(!history.is_positive(0));
}

#[test]
fn inventory_usage_deadline_and_integrity_failures_preserve_prior_positive_evidence() {
    let mut history = InventoryUsageHistory::new(vec![0, 575]);
    let first = history.read_with(read_window(2), |id| Ok(if id == 0 { 1 } else { 7 }));
    assert_eq!(first.newly_positive, [0]);
    assert_eq!(first.integrity_failures, [575]);
    assert!(!history.is_positive(575));
    let second = history.read_with(read_window(2), |id| {
        if id == 575 {
            anyhow::bail!("owned map read failure");
        }
        Ok(0)
    });
    assert_eq!(second.read_failures.len(), 1);
    assert_eq!(second.positive_count, 1);
    let expired = InventoryReadWindow::new(2, Instant::now() - Duration::from_secs(1)).unwrap();
    let third = history.read_with(expired, |_| panic!("expired window performed map IO"));
    assert_eq!(third.cells_read, 0);
    assert!(third.deadline_reached);
    assert_eq!(third.positive_count, 1);
    assert!(InventoryReadWindow::new(0, Instant::now()).is_err());
}

// This gate replaces only a blocking kernel close. Its release is caused by
// consuming a valid record through the real DiscoveryDrain decoder. In the RED
// baseline the production synchronous stop cannot service that reader, so the
// close reports its bounded rescue as an error instead of hanging the test.
struct HeldCloseIo {
    release: std::sync::mpsc::Receiver<()>,
    entered: std::sync::Arc<std::sync::atomic::AtomicBool>,
    serviced: std::sync::Arc<std::sync::atomic::AtomicBool>,
    attempts: std::sync::Arc<std::sync::Mutex<Vec<u32>>>,
}

impl InventoryLinkIo for HeldCloseIo {
    type Link = u32;

    fn publish_endpoint(&mut self, _endpoint: u32, _object: PinnedObjectId) -> Result<()> {
        bail!("retirement regression must not publish endpoints")
    }

    fn attach(&mut self, _request: InventoryAttachRequest<'_>) -> Result<Self::Link> {
        bail!("retirement regression must not attach")
    }

    fn detach(&mut self, link: &mut Self::Link) -> Result<()> {
        self.attempts.lock().unwrap().push(*link);
        if *link == 575 {
            self.entered
                .store(true, std::sync::atomic::Ordering::SeqCst);
            self.release
                .recv_timeout(Duration::from_secs(2))
                .context("close rescue: discovery was not serviced while cleanup blocked")?;
            ensure!(self.serviced.load(std::sync::atomic::Ordering::SeqCst));
        }
        Ok(())
    }
}

fn drive_candidate_retirement(
    mut io: HeldCloseIo,
    links: Vec<InventoryLinked<u32>>,
    mut service: impl FnMut(),
) -> InventoryCleanupReceipt {
    let work = RetirementWork::new(
        links
            .into_iter()
            .map(|link| RetirementLink {
                target: link.target,
                handle: Some(link.handle),
                quarantine: None,
                _leases: Arc::default(),
            })
            .collect(),
        vec![],
    );
    let mut job = RetirementJob::start(work, serial_fixture_close(move |link| io.detach(link)))
        .unwrap_or_else(|failure| panic!("worker start: {}", failure.error));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        service();
        if let Some(mut work) = job.poll(deadline).unwrap() {
            return work.take_result().0;
        }
        assert!(Instant::now() < deadline, "retirement controller deadline");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn blocked_close_discovery_oracle(candidate: bool) -> (InventoryCleanupReceipt, Vec<u32>) {
    use crate::events::{DiscoveryDrain, ScriptedRecords};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, mpsc};

    // SAFETY: DiscoveryRecord contains only integer fields; this is the same
    // fixed, zero-reserved lifecycle wire shape emitted by the real producer.
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = p11scope_ebpf_common::DISCOVERY_KIND_LEADER_EXIT;
    record.pid_tgid = 0x5151u64 << 32;
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&record as *const DiscoveryRecord).cast::<u8>(),
            std::mem::size_of::<DiscoveryRecord>(),
        )
        .to_vec()
    };
    let mut drain = DiscoveryDrain::over(ScriptedRecords::records([bytes], 1));
    let serviced = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let (release, receiver) = mpsc::sync_channel(1);
    let mut io = HeldCloseIo {
        release: receiver,
        entered: entered.clone(),
        serviced: serviced.clone(),
        attempts: attempts.clone(),
    };
    let mut links = vec![
        InventoryLinked {
            target: InventoryLinkIdentity::Lifecycle("sched_process_exec"),
            handle: 0,
        },
        InventoryLinked {
            target: InventoryLinkIdentity::Lifecycle("sched_process_exit"),
            handle: 1,
        },
        InventoryLinked {
            target: InventoryLinkIdentity::Entry(575),
            handle: 575,
        },
    ];
    let mut service = || {
        if !entered.load(Ordering::SeqCst) || serviced.load(Ordering::SeqCst) {
            return;
        }
        let Some(DiscoveryItem::Record(observed)) = drain.dequeue() else {
            panic!("valid independent lifecycle record was not consumed");
        };
        assert_eq!(
            observed.kind,
            p11scope_ebpf_common::DISCOVERY_KIND_LEADER_EXIT
        );
        assert_eq!(observed.pid_tgid, 0x5151u64 << 32);
        serviced.store(true, Ordering::SeqCst);
        // The baseline receiver remains owned even after its bounded rescue.
        // A fixed controller may already have returned its completed close IO.
        let _ = release.send(());
    };
    let receipt = if candidate {
        drive_candidate_retirement(io, links, &mut service)
    } else {
        let receipt = stop_inventory_links_with(&mut io, &mut links);
        service();
        receipt
    };
    assert!(serviced.load(Ordering::SeqCst));
    assert_eq!(drain.source().remaining(), 0);
    let observed = attempts.lock().unwrap().clone();
    (receipt, observed)
}

#[test]
fn inventory_retirement_services_discovery_while_close_is_blocked() {
    let (receipt, attempts) = blocked_close_discovery_oracle(true);
    assert!(
        receipt.failures.is_empty(),
        "retirement blocked the sole discovery consumer: {receipt:?}"
    );
    assert_eq!(receipt.closed, 3);
    assert_eq!(attempts.first(), Some(&575));
    assert_eq!(attempts.len(), 3);
    assert_eq!(
        attempts[1..].iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([0, 1])
    );
    assert!(!receipt.callback_quiescence_proven);
}

#[test]
fn inventory_synchronous_retirement_negative_control_starves_discovery() {
    let (receipt, attempts) = blocked_close_discovery_oracle(false);
    assert_eq!(receipt.failures.len(), 1);
    assert_eq!(
        receipt.failures[0].target,
        InventoryLinkIdentity::Entry(575)
    );
    assert!(
        receipt.failures[0]
            .error
            .to_string()
            .contains("close rescue")
    );
    assert_eq!(receipt.closed, 2);
    assert_eq!(attempts, [575, 1, 0]);
    assert!(!receipt.callback_quiescence_proven);
}

// Existing mutable mock I/O keeps its old serialized leaf behavior.
// New scheduling/custody controls call the concurrent production path directly.
fn serial_fixture_close<L>(
    closer: impl FnMut(&mut L) -> Result<()> + Send,
) -> impl Fn(&mut L) -> Result<()> + Send + Sync {
    let closer = Mutex::new(closer);
    move |link| closer.lock().unwrap_or_else(|error| error.into_inner())(link)
}

fn retirement_links<L>(
    handles: impl IntoIterator<Item = (InventoryLinkIdentity, L)>,
) -> Vec<RetirementLink<L>> {
    handles
        .into_iter()
        .map(|(target, handle)| RetirementLink {
            target,
            handle: Some(handle),
            quarantine: None,
            _leases: Arc::default(),
        })
        .collect()
}

fn collect_job<L: Send + 'static>(job: &mut RetirementJob<L>) -> RetirementWork<L> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(work) = job.poll(deadline).unwrap() {
            return work;
        }
        assert!(Instant::now() < deadline, "owned worker did not complete");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn lifecycle_bytes(pid: u32) -> Vec<u8> {
    // SAFETY: repr(C) integer-only wire record, including zeroed reserved bytes.
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = p11scope_ebpf_common::DISCOVERY_KIND_LEADER_EXIT;
    record.pid_tgid = u64::from(pid) << 32;
    unsafe {
        std::slice::from_raw_parts(
            (&record as *const DiscoveryRecord).cast::<u8>(),
            std::mem::size_of::<DiscoveryRecord>(),
        )
        .to_vec()
    }
}

#[test]
fn inventory_retirement_actual_fd_payload_is_send_without_sharing_target_cells() {
    fn assert_send<T: Send>() {}
    assert_send::<RetirementWork<Vec<InventoryFd>>>();
    assert_send::<Arc<std::fs::File>>();
}

#[test]
fn inventory_retirement_expired_poll_keeps_job_pin_reader_and_positive_history() {
    use crate::events::{DiscoveryDrain, ScriptedRecords};
    use std::sync::mpsc;
    let fixture = Fixture::new();
    let targets = fixture.targets(1, 576);
    let lease = targets.pins.values().next().unwrap().retirement_lease();
    let inode = lease.metadata().unwrap().ino();
    let weak = Arc::downgrade(&lease);
    let attempts = Arc::new(Mutex::new(vec![]));
    let observed = attempts.clone();
    let (entered, entered_rx) = mpsc::sync_channel(1);
    let (release, release_rx) = mpsc::sync_channel(1);
    let work = RetirementWork::new(
        retirement_links([
            (InventoryLinkIdentity::Lifecycle("sched_process_exec"), 0),
            (InventoryLinkIdentity::Lifecycle("sched_process_exit"), 1),
            (InventoryLinkIdentity::Entry(575), 575),
        ]),
        vec![lease],
    );
    let mut job = RetirementJob::start(
        work,
        serial_fixture_close(move |id| {
            observed.lock().unwrap().push(*id);
            if *id == 575 {
                entered.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5))?;
            }
            Ok(())
        }),
    )
    .unwrap_or_else(|failure| panic!("{}", failure.error));
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    drop(targets);
    drop(fixture);
    assert_eq!(weak.upgrade().unwrap().metadata().unwrap().ino(), inode);
    assert!(job.poll(Instant::now()).unwrap().is_none());
    assert!(
        job.poll(Instant::now() + Duration::from_millis(10))
            .unwrap()
            .is_none()
    );
    assert_eq!(*attempts.lock().unwrap(), [575]);
    let mut history = InventoryUsageHistory::new(vec![575]);
    assert_eq!(
        history.read_with(read_window(1), |_| Ok(1)).positive_count,
        1
    );
    assert_eq!(
        history.read_with(read_window(1), |_| Ok(0)).positive_count,
        1
    );
    let mut reader = DiscoveryDrain::over(ScriptedRecords::records([lifecycle_bytes(0x5252)], 1));
    let service = service_inventory_discovery_with(
        1,
        Instant::now() + Duration::from_secs(1),
        || match reader.dequeue() {
            Some(DiscoveryItem::Record(record)) => Ok(Some(record)),
            _ => bail!("expected retained valid reader"),
        },
        |record| {
            ensure!(record.pid_tgid == 0x5252u64 << 32);
            release.send(())?;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(service.dispatched, 1);
    let work = collect_job(&mut job);
    let attempts = attempts.lock().unwrap().clone();
    assert_eq!(attempts.first(), Some(&575));
    assert_eq!(attempts.len(), 3);
    assert_eq!(
        attempts[1..].iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([0, 1])
    );
    assert_eq!(work.receipt.closed, 3);
    assert!(work.receipt.failures.is_empty());
    assert!(weak.upgrade().is_some());
    drop(work);
    assert!(weak.upgrade().is_none());
}

#[test]
fn inventory_retirement_close_panic_and_failure_keep_handles_and_attempt_roots_last() {
    let fixture = Fixture::new();
    let targets = fixture.targets(3, 576);
    let mut io = LinkIo {
        fail_attach: Some(4),
        ..Default::default()
    };
    let mut failure = match attach_inventory_with(&mut io, &targets) {
        Ok(_) => panic!("expected original attach failure"),
        Err(failure) => failure,
    };
    let links = std::mem::take(&mut failure.links);
    let observed = io.state.clone();
    let mut job = RetirementJob::start(
        RetirementWork::new(
            retirement_links(links.into_iter().map(|link| (link.target, link.handle))),
            vec![],
        ),
        serial_fixture_close(move |link: &mut TestLink| {
            observed.lock().unwrap().detach_attempts.push(link.ordinal);
            match link.ordinal {
                3 => panic!("owned injected close panic"),
                2 => bail!("owned injected close failure"),
                _ => Ok(()),
            }
        }),
    )
    .unwrap_or_else(|failure| panic!("{}", failure.error));
    let work = collect_job(&mut job);
    assert!(format!("{:#}", failure.error).contains("original attach failure 4"));
    let attempts = io.state.lock().unwrap().detach_attempts.clone();
    assert_eq!(attempts.len(), 4);
    assert_eq!(
        attempts[..2].iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([2, 3])
    );
    assert_eq!(
        attempts[2..].iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([0, 1])
    );
    assert_eq!(work.receipt.attempted, 4);
    assert_eq!(work.receipt.closed, 2);
    assert_eq!(work.receipt.failures.len(), 2);
    let panic_failure = work
        .receipt
        .failures
        .iter()
        .find(|failure| failure.target == InventoryLinkIdentity::Entry(1))
        .unwrap();
    assert!(
        panic_failure
            .error
            .to_string()
            .contains("owned injected close panic")
    );
    assert!(
        work.receipt
            .failures
            .iter()
            .any(|failure| failure.target == InventoryLinkIdentity::Entry(0))
    );
    assert_eq!(io.state.lock().unwrap().live, BTreeSet::from([2, 3]));
    assert_eq!(
        work.links
            .iter()
            .filter(|link| link.handle.is_some())
            .count(),
        2
    );
    drop(work);
    assert!(io.state.lock().unwrap().live.is_empty());
}

#[test]
fn inventory_retirement_spawn_and_transfer_failure_recover_owned_unattempted_work() {
    for transfer_failure in [false, true] {
        let fixture = Fixture::new();
        let targets = fixture.targets(1, 576);
        let mut io = LinkIo::default();
        let links =
            attach_inventory_with(&mut io, &targets).unwrap_or_else(|error| panic!("{error}"));
        let mut close_io = io.clone();
        let result = RetirementJob::start_with(
            RetirementWork::new(
                retirement_links(links.into_iter().map(|link| (link.target, link.handle))),
                vec![],
            ),
            serial_fixture_close(move |link| close_io.detach(link)),
            |task| {
                // Closing the receiver before transfer deterministically makes
                // send return its original owned payload to the controller.
                drop(task);
                if transfer_failure {
                    std::thread::Builder::new().spawn(|| None)
                } else {
                    Err(std::io::Error::other("owned spawn failure"))
                }
            },
        );
        let failure = match result {
            Ok(_) => panic!("injected launch failure unexpectedly succeeded"),
            Err(failure) => failure,
        };
        assert_eq!(failure.work.links.len(), 3);
        assert_eq!(failure.work.receipt.attempted, 0);
        assert!(io.state.lock().unwrap().detach_attempts.is_empty());
        assert_eq!(io.state.lock().unwrap().live, BTreeSet::from([0, 1, 2]));
        assert_eq!(failure.empty_worker.is_some(), transfer_failure);
        if let Some(worker) = failure.empty_worker {
            assert!(worker.join().unwrap().is_none());
        }
        drop(failure.work);
        assert_eq!(io.state.lock().unwrap().dropped, [2, 1, 0]);
    }
}

#[test]
fn inventory_retirement_unexpected_worker_panic_cannot_manufacture_success() {
    let fixture = Fixture::new();
    let targets = fixture.targets(1, 576);
    let mut io = LinkIo::default();
    let links = attach_inventory_with(&mut io, &targets).unwrap_or_else(|error| panic!("{error}"));
    let observed = io.state.clone();
    let work = RetirementWork::new(
        retirement_links(links.into_iter().map(|link| (link.target, link.handle))),
        vec![targets.pins.values().next().unwrap().retirement_lease()],
    );
    let job = RetirementJob::start_with(
        work,
        serial_fixture_close(move |link: &mut TestLink| {
            observed.lock().unwrap().detach_attempts.push(link.ordinal);
            bail!("retained before outer unwind");
        }),
        |task| {
            std::thread::Builder::new().spawn(move || {
                let _owned = task();
                // Outside the per-close catch, so the ordered resource guard
                // must reclaim custody and the controller must return failure.
                panic!("owned unexpected worker panic");
            })
        },
    )
    .unwrap_or_else(|failure| panic!("{}", failure.error));
    let evidence = RetirementFallbackEvidence::default();
    let error = match abandon_and_reclaim_with(job, &evidence, || None) {
        Ok(_) => panic!("unexpected worker panic reported successful completion"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("panicked outside close handling")
    );
    let attempts = io.state.lock().unwrap().detach_attempts.clone();
    assert_eq!(attempts.first(), Some(&2));
    assert_eq!(attempts.len(), 3);
    assert_eq!(
        attempts[1..].iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([0, 1])
    );
    assert_eq!(io.state.lock().unwrap().dropped, [2, 1, 0]);
    assert!(io.state.lock().unwrap().live.is_empty());
    assert!(evidence.snapshot().abandoned);
    assert_eq!(evidence.snapshot().worker_failures, 1);
}

#[test]
fn inventory_retirement_guard_keeps_file_lease_through_ordered_handle_drops() {
    struct GuardedLink {
        id: u32,
        pin: std::sync::Weak<std::fs::File>,
        dropped: Arc<Mutex<Vec<u32>>>,
    }
    impl Drop for GuardedLink {
        fn drop(&mut self) {
            assert!(self.pin.upgrade().unwrap().metadata().is_ok());
            self.dropped.lock().unwrap().push(self.id);
        }
    }
    let file = Arc::new(tempfile::tempfile().unwrap());
    let weak = Arc::downgrade(&file);
    let dropped = Arc::new(Mutex::new(vec![]));
    // Deliberately intermixed roots: the unwind guard must classify them.
    let work = RetirementWork::new(
        retirement_links(
            [
                (InventoryLinkIdentity::Entry(2), 2),
                (InventoryLinkIdentity::Lifecycle("sched_process_exec"), 0),
                (InventoryLinkIdentity::Entry(3), 3),
                (InventoryLinkIdentity::Lifecycle("sched_process_exit"), 1),
            ]
            .map(|(target, id)| {
                (
                    target,
                    GuardedLink {
                        id,
                        pin: weak.clone(),
                        dropped: dropped.clone(),
                    },
                )
            }),
        ),
        vec![file],
    );
    drop(work);
    assert_eq!(*dropped.lock().unwrap(), [3, 2, 1, 0]);
    assert!(weak.upgrade().is_none());
}

#[test]
fn inventory_abandoned_retirement_pumps_real_decoder_and_retains_discard_evidence() {
    use crate::events::{DiscoveryDrain, ScriptedRecords};
    use std::sync::mpsc;
    let (entered, entered_rx) = mpsc::sync_channel(1);
    let (release, release_rx) = mpsc::sync_channel(1);
    let evidence = RetirementFallbackEvidence::default();
    let retained_evidence = evidence.clone();
    let job = RetirementJob::start(
        RetirementWork::new(
            retirement_links([(InventoryLinkIdentity::Entry(575), 575)]),
            vec![],
        ),
        serial_fixture_close(move |_| {
            entered.send(())?;
            release_rx.recv_timeout(Duration::from_secs(5))?;
            Ok(())
        }),
    )
    .unwrap_or_else(|failure| panic!("{}", failure.error));
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let mut reader = DiscoveryDrain::over(ScriptedRecords::records(
        [vec![0], lifecycle_bytes(0x5353)],
        2,
    ));
    let work = abandon_and_reclaim_with(job, &evidence, || {
        assert!(
            retained_evidence.snapshot().abandoned,
            "marker precedes dequeue"
        );
        let item = reader.dequeue();
        if let Some(DiscoveryItem::Record(record)) = &item {
            assert_eq!(record.pid_tgid, 0x5353u64 << 32);
            release.send(()).unwrap();
        }
        item
    })
    .unwrap();
    assert_eq!(work.receipt.closed, 1);
    assert!(work.receipt.failures.is_empty());
    drop(evidence);
    assert_eq!(
        retained_evidence.snapshot(),
        retirement::RetirementFallbackSnapshot {
            abandoned: true,
            records: 1,
            malformed: 1,
            worker_failures: 0,
        }
    );
}

#[test]
fn inventory_discovery_service_preserves_consumer_failure_and_enforces_both_bounds() {
    use crate::events::{DiscoveryDrain, ScriptedRecords};
    let mut reader =
        DiscoveryDrain::over(ScriptedRecords::records((1..=4).map(lifecycle_bytes), 4));
    let mut delivered = vec![];
    let mut dequeue = || match reader.dequeue() {
        Some(DiscoveryItem::Record(record)) => Ok(Some(record)),
        Some(DiscoveryItem::Malformed) => bail!("unexpected malformed fixture"),
        None => Ok(None),
    };
    let first = service_inventory_discovery_with(
        1,
        Instant::now() + Duration::from_secs(1),
        &mut dequeue,
        |record| {
            delivered.push(record.pid_tgid);
            Ok(())
        },
    )
    .unwrap();
    assert!(first.record_bound_reached);
    assert_eq!(first.dispatched, 1);
    let expired = service_inventory_discovery_with(10, Instant::now(), &mut dequeue, |_| {
        panic!("expired dispatch")
    })
    .unwrap();
    assert!(expired.deadline_reached);
    assert_eq!(expired.dispatched, 0);
    let failure = service_inventory_discovery_with(
        10,
        Instant::now() + Duration::from_secs(1),
        &mut dequeue,
        |record| {
            if record.pid_tgid == 3u64 << 32 {
                bail!("owned consumer error");
            }
            delivered.push(record.pid_tgid);
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(failure.dispatched, 1);
    assert_eq!(failure.record.unwrap().pid_tgid, 3u64 << 32);
    assert!(failure.error.to_string().contains("owned consumer error"));
    assert_eq!(delivered, [1u64 << 32, 2u64 << 32]);
    assert_eq!(reader.source().remaining(), 1, "no read ahead after error");
    assert!(
        service_inventory_discovery_with(
            0,
            Instant::now(),
            || panic!("zero-bound read"),
            |_| Ok(())
        )
        .is_err()
    );
}

/// In-memory INFO_START stand-in for the scrub stepper: counts map
/// operations (budget pin), mirrors the zero-verify-remove sequence
/// and injects a fault on one operation.
#[cfg(not(feature = "stub-object-attributes"))]
struct FakeScrubTable {
    rows: BTreeMap<[u8; 16], [u8; 32]>,
    capacity: u32,
    ops: u64,
    fail_on_op: Option<u64>,
    fail_on_substep: Option<&'static str>,
    /// Keys an in-flight return removes between the fake's zero and
    /// verify: the verify observes the disappearance.
    remove_on_verify: BTreeSet<[u8; 16]>,
}

#[cfg(not(feature = "stub-object-attributes"))]
impl FakeScrubTable {
    fn full(rows: u16, capacity: u32) -> Self {
        let mut table = Self {
            rows: BTreeMap::new(),
            capacity,
            ops: 0,
            fail_on_op: None,
            fail_on_substep: None,
            remove_on_verify: BTreeSet::new(),
        };
        for row in 0..rows {
            let mut key = [0u8; 16];
            key[..2].copy_from_slice(&row.to_le_bytes());
            table.rows.insert(key, [0xa5; 32]);
        }
        table
    }

    fn tick(&mut self, what: &str) -> Result<()> {
        self.ops = self.ops.saturating_add(1);
        if self.fail_on_op == Some(self.ops) {
            anyhow::bail!("injected scrub fault at {what} op {}", self.ops);
        }
        if self.fail_on_substep == Some(what) {
            anyhow::bail!("injected persistent scrub fault at {what}");
        }
        Ok(())
    }

    fn tick_row(&mut self, what: &str) -> Result<(), ScrubRowError> {
        self.tick(what).map_err(ScrubRowError::Failed)
    }
}

#[cfg(not(feature = "stub-object-attributes"))]
impl InfoScrubTable for FakeScrubTable {
    fn capacity(&self) -> u32 {
        self.capacity
    }

    fn first_key(&mut self) -> Result<Option<[u8; 16]>> {
        self.tick("enumerate")?;
        Ok(self.rows.keys().next().copied())
    }

    fn zero_row(&mut self, key: &[u8; 16]) -> Result<(), ScrubRowError> {
        self.tick_row("zero")?;
        // BPF_EXIST, like the kernel: a missing row refuses instead
        // of manufacturing an owner.
        if !self.rows.contains_key(key) {
            return Err(ScrubRowError::Missing);
        }
        self.rows.insert(*key, [0; 32]);
        Ok(())
    }

    fn verify_row_zero(&mut self, key: &[u8; 16]) -> Result<(), ScrubRowError> {
        self.tick_row("verify")?;
        if self.remove_on_verify.remove(key) {
            self.rows.remove(key);
        }
        if !self.rows.contains_key(key) {
            return Err(ScrubRowError::Missing);
        }
        if self.rows.get(key) != Some(&[0; 32]) {
            return Err(ScrubRowError::Failed(anyhow::anyhow!(
                "stopped INFO_START zero readback differs"
            )));
        }
        Ok(())
    }

    fn remove_row(&mut self, key: &[u8; 16]) -> Result<(), ScrubRowError> {
        self.tick_row("remove")?;
        if self.rows.remove(key).is_none() {
            return Err(ScrubRowError::Missing);
        }
        Ok(())
    }
}

#[cfg(not(feature = "stub-object-attributes"))]
fn generous_budget() -> ScrubBudget<fn() -> Instant> {
    ScrubBudget::per_poll(Instant::now() + Duration::from_secs(60), Instant::now)
}

/// Keymeta Task 7 stop scrub (spec §17.4): a full 1024-row stash
/// clears in bounded 64-row steps within the map-I/O budget, and
/// the table observes empty exactly once at the end.
#[cfg(not(feature = "stub-object-attributes"))]
#[test]
fn scrub_step_clears_a_full_map_within_budget() {
    let mut table = FakeScrubTable::full(1024, 1024);
    let mut progress = 0u64;
    let mut steps = 0u32;
    loop {
        steps += 1;
        match scrub_info_start_step(&mut table, &mut progress, &mut None, &mut generous_budget())
            .expect("a healthy scrub never errors")
        {
            InfoScrubOutcome::Complete => break,
            InfoScrubOutcome::Pending => {}
            InfoScrubOutcome::Saturated => panic!("a quiet table never saturates"),
        }
        assert!(steps <= 17, "bounded steps");
    }
    assert_eq!(steps, 16, "1024 rows clear in sixteen 64-row steps");
    assert_eq!(progress, 1024);
    assert!(table.rows.is_empty());
    // Four map operations per row (enumerate, zero, verify, remove)
    // plus one emptiness observation per step: 1024×4 + 16.
    assert_eq!(table.ops, 4112);
    assert!(table.ops <= 5000, "full-map budget holds");
}

/// Keymeta Task 7 stop scrub (spec §17.4): a batch spent with rows
/// remaining yields `Pending` with progress carried; the next step
/// resumes where it left off and completes.
#[cfg(not(feature = "stub-object-attributes"))]
#[test]
fn scrub_step_yields_and_resumes_with_progress() {
    let mut table = FakeScrubTable::full(100, 1024);
    let mut progress = 0u64;
    assert_eq!(
        scrub_info_start_step(&mut table, &mut progress, &mut None, &mut generous_budget())
            .unwrap(),
        InfoScrubOutcome::Pending
    );
    assert_eq!(progress, 64);
    assert_eq!(table.rows.len(), 36);
    assert_eq!(
        scrub_info_start_step(&mut table, &mut progress, &mut None, &mut generous_budget())
            .unwrap(),
        InfoScrubOutcome::Complete
    );
    assert_eq!(progress, 100);
    assert!(table.rows.is_empty());
}

/// Keymeta Task 7 stop scrub (spec §17.4): a failed map operation
/// surfaces its concrete cause with progress preserved; clearing
/// the fault resumes to completion without redoing cleared rows.
#[cfg(not(feature = "stub-object-attributes"))]
#[test]
fn scrub_step_carries_concrete_failures_and_resumes() {
    let mut table = FakeScrubTable::full(10, 1024);
    table.fail_on_op = Some(7);
    let mut progress = 0u64;
    let error = scrub_info_start_step(&mut table, &mut progress, &mut None, &mut generous_budget())
        .unwrap_err();
    assert!(
        error.to_string().contains("injected scrub fault"),
        "concrete cause survives: {error:#}"
    );
    // Ops 1–4 clear row one (enumerate, zero, verify, remove); ops
    // 5–6 enumerate and zero row two; op 7 fails the verify.
    assert_eq!(progress, 1, "cleared rows stay cleared");
    assert_eq!(table.rows.len(), 9);
    table.fail_on_op = None;
    assert_eq!(
        scrub_info_start_step(&mut table, &mut progress, &mut None, &mut generous_budget())
            .unwrap(),
        InfoScrubOutcome::Complete
    );
    assert_eq!(progress, 10);
    assert!(table.rows.is_empty());
}

/// Keymeta Task 7 stop scrub (spec §17.4): clearing a full capacity
/// without emptying saturates instead of spinning — concurrent
/// inserts or an unremovable row retry from reset progress.
#[cfg(not(feature = "stub-object-attributes"))]
#[test]
fn scrub_step_saturates_past_capacity() {
    let mut table = FakeScrubTable::full(6, 4);
    let mut progress = 0u64;
    assert_eq!(
        scrub_info_start_step(&mut table, &mut progress, &mut None, &mut generous_budget())
            .unwrap(),
        InfoScrubOutcome::Saturated
    );
    assert_eq!(progress, 4);
    assert_eq!(table.rows.len(), 2);
}

/// Keymeta Task 7 stop scrub (spec §17.4, INV-2): the step spends
/// its native-operation allowance operation by operation — a short
/// allowance yields mid-row with the pending key and substep kept,
/// and the resume completes the row without redoing finished
/// substeps.
#[cfg(not(feature = "stub-object-attributes"))]
#[test]
fn scrub_step_yields_mid_row_on_a_short_allowance_and_resumes() {
    let mut table = FakeScrubTable::full(4, 1024);
    let mut progress = 0u64;
    let mut pending = None;
    // Six operations: row one (enumerate, zero, verify, remove) plus
    // the row-two enumeration and zero. The step yields with the
    // row-two verify pending instead of starting work it cannot pay.
    let mut budget = ScrubBudget {
        ops_remaining: 6,
        deadline: Instant::now() + Duration::from_secs(60),
        now: Instant::now,
    };
    assert_eq!(
        scrub_info_start_step(&mut table, &mut progress, &mut pending, &mut budget).unwrap(),
        InfoScrubOutcome::Pending
    );
    assert_eq!(progress, 1, "one row cleared");
    assert_eq!(table.ops, 6, "no operation starts without allowance");
    let mut key = [0u8; 16];
    key[..2].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(
        table.rows.get(&key),
        Some(&[0; 32]),
        "row two stays zeroed-but-present across the yield"
    );
    // The resume finishes row two (verify, remove), clears rows
    // three and four, and observes empty: 11 more operations, 17 in
    // all — exactly one pass with no redone zero.
    assert_eq!(
        scrub_info_start_step(
            &mut table,
            &mut progress,
            &mut pending,
            &mut generous_budget()
        )
        .unwrap(),
        InfoScrubOutcome::Complete
    );
    assert_eq!(progress, 4);
    assert!(table.rows.is_empty());
    assert_eq!(table.ops, 17, "the resume redoes no finished substep");
}

/// Keymeta Task 7 stop scrub (spec §17.4, INV-2): an expired budget
/// starts zero native calls — the step yields before its first map
/// operation.
#[cfg(not(feature = "stub-object-attributes"))]
#[test]
fn scrub_step_spends_nothing_once_expired() {
    let mut table = FakeScrubTable::full(4, 1024);
    let mut progress = 0u64;
    let mut budget = ScrubBudget {
        ops_remaining: INFO_SCRUB_OPS_PER_POLL,
        deadline: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
        now: Instant::now,
    };
    assert_eq!(
        scrub_info_start_step(&mut table, &mut progress, &mut None, &mut budget).unwrap(),
        InfoScrubOutcome::Pending
    );
    assert_eq!(table.ops, 0, "an expired step runs zero native calls");
    assert_eq!(progress, 0);
    assert_eq!(table.rows.len(), 4);
}

/// Keymeta Task 7 stop scrub (spec §17.4, INV-2): a deadline that
/// passes mid-step stops new operations at once — the step yields
/// with the pending substep kept and resumes to completion.
#[cfg(not(feature = "stub-object-attributes"))]
#[test]
fn scrub_step_stops_starting_operations_when_the_deadline_passes() {
    let mut table = FakeScrubTable::full(4, 1024);
    let mut progress = 0u64;
    let mut pending = None;
    let deadline = Instant::now() + Duration::from_secs(60);
    let before = deadline.checked_sub(Duration::from_secs(30)).unwrap();
    let after = deadline.checked_add(Duration::from_secs(1)).unwrap();
    // The clock reads healthy for the entry check plus three
    // operations, then passes the deadline for good.
    let calls = std::cell::Cell::new(0u32);
    let mut budget = ScrubBudget {
        ops_remaining: INFO_SCRUB_OPS_PER_POLL,
        deadline,
        now: || {
            calls.set(calls.get() + 1);
            if calls.get() <= 4 { before } else { after }
        },
    };
    assert_eq!(
        scrub_info_start_step(&mut table, &mut progress, &mut pending, &mut budget).unwrap(),
        InfoScrubOutcome::Pending
    );
    assert_eq!(table.ops, 3, "enumerate, zero, verify — then nothing new");
    assert_eq!(progress, 0, "the interrupted row clears on resume");
    assert_eq!(
        scrub_info_start_step(
            &mut table,
            &mut progress,
            &mut pending,
            &mut generous_budget()
        )
        .unwrap(),
        InfoScrubOutcome::Complete
    );
    assert_eq!(progress, 4);
    assert!(table.rows.is_empty());
    assert_eq!(table.ops, 17, "one pass with no redone substep");
}

/// Keymeta Task 7 stop scrub (spec §17.4, INV-2): the per-poll map
/// validation reads the map shape once and charges that read to the
/// same native-operation allowance as the table calls — the shape
/// is owned and unchanged, so one metadata read proves it.
#[cfg(not(feature = "stub-object-attributes"))]
#[test]
fn scrub_poll_validates_the_map_once_against_the_allowance() {
    use std::cell::Cell;
    let fetches = Cell::new(0u64);
    let mut fetch = || {
        fetches.set(fetches.get() + 1);
        Ok(crate::attach::map_metadata(
            aya::maps::MapType::Hash,
            16,
            32,
            1024,
            0,
        ))
    };
    let mut budget = generous_budget();
    let capacity = scrub_table_capacity_with(&mut fetch, &mut budget)
        .expect("a healthy shape validates")
        .expect("a generous budget fetches");
    assert_eq!(capacity, 1024, "the map's own capacity carries");
    assert_eq!(fetches.get(), 1, "one metadata read per poll");
    assert_eq!(
        budget.ops_remaining,
        INFO_SCRUB_OPS_PER_POLL - 1,
        "the metadata read charges to the poll allowance"
    );
    // An expired budget fetches nothing: zero native calls.
    let mut expired = ScrubBudget {
        ops_remaining: INFO_SCRUB_OPS_PER_POLL,
        deadline: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
        now: Instant::now,
    };
    let before = fetches.get();
    assert_eq!(
        scrub_table_capacity_with(&mut fetch, &mut expired).unwrap(),
        None,
        "an expired poll skips validation"
    );
    assert_eq!(
        fetches.get(),
        before,
        "zero metadata reads past the deadline"
    );
    // A wrong shape refuses without spending table work.
    let mut wrong = || {
        Ok(crate::attach::map_metadata(
            aya::maps::MapType::Array,
            16,
            32,
            1024,
            0,
        ))
    };
    assert!(
        scrub_table_capacity_with(&mut wrong, &mut generous_budget()).is_err(),
        "a mistyped map refuses"
    );
}

/// Keymeta Task 7 stop scrub (spec §17.4, INV-2): a poll that
/// resumes at Remove still clears at most a 64-row batch — the
/// resumed removal consumes its row slot instead of clearing 65.
#[cfg(not(feature = "stub-object-attributes"))]
#[test]
fn scrub_poll_resumed_at_remove_counts_against_the_row_batch() {
    let mut table = FakeScrubTable::full(70, 1024);
    let mut progress = 0u64;
    let mut pending = None;
    // Three operations: row one enumerated, zeroed and verified,
    // with its removal pending.
    let mut short = ScrubBudget {
        ops_remaining: 3,
        deadline: Instant::now() + Duration::from_secs(60),
        now: Instant::now,
    };
    assert_eq!(
        scrub_info_start_step(&mut table, &mut progress, &mut pending, &mut short).unwrap(),
        InfoScrubOutcome::Pending
    );
    assert_eq!(progress, 0, "the interrupted row clears on resume");
    assert_eq!(
        pending,
        Some(PendingScrubRow {
            key: {
                let mut key = [0u8; 16];
                key[..2].copy_from_slice(&0u16.to_le_bytes());
                key
            },
            next: ScrubSubstep::Remove,
        }),
        "the removal pends"
    );
    // The resume removes row one plus at most 63 fresh rows: 64
    // rows for the poll, with rows remaining afterwards.
    assert_eq!(
        scrub_info_start_step(
            &mut table,
            &mut progress,
            &mut pending,
            &mut generous_budget()
        )
        .unwrap(),
        InfoScrubOutcome::Pending
    );
    assert_eq!(progress, 64, "one poll clears one 64-row batch");
    assert_eq!(table.rows.len(), 6, "six rows wait for the next poll");
}

/// Keymeta Task 7 stop window (spec §17.4): the evidence group
/// read gates each of its five cell lookups on the quantum
/// deadline — a clock already past the window yields before the
/// first cell, and a deadline crossed inside the first cell starts
/// no further cell. A failed cell ends the group with its cause
/// and starts no later cell; a healthy group reads all five cells
/// in index order.
#[test]
fn evidence_group_read_gates_each_cell_on_the_quantum_deadline() {
    use p11scope_ebpf_common::{
        INFO_EVIDENCE_INSERT_FAILURES, INFO_EVIDENCE_NESTED_OVERWRITES, INFO_EVIDENCE_RING_LOSS,
        INFO_EVIDENCE_STASH_MISMATCHES, INFO_EVIDENCE_UNMATCHED_RETURNS,
    };
    use std::cell::RefCell;
    let order = [
        INFO_EVIDENCE_INSERT_FAILURES,
        INFO_EVIDENCE_UNMATCHED_RETURNS,
        INFO_EVIDENCE_NESTED_OVERWRITES,
        INFO_EVIDENCE_STASH_MISMATCHES,
        INFO_EVIDENCE_RING_LOSS,
    ];
    // An already-expired window yields with zero cell starts.
    let starts = RefCell::new(Vec::new());
    let mut now = || Instant::now() + Duration::from_secs(60);
    let expired = Instant::now();
    assert!(
        matches!(
            read_evidence_cells(expired, &mut now, |index| {
                starts.borrow_mut().push(index);
                Ok(1u64)
            }),
            InfoEvidenceRead::Yielded
        ),
        "an expired window yields before the first cell"
    );
    assert!(
        starts.borrow().is_empty(),
        "no cell starts at or past the deadline: {:?}",
        starts.borrow()
    );
    // A deadline crossed inside the first cell starts no further
    // cell: the clock reads inside the window once, then past it.
    let starts = RefCell::new(Vec::new());
    let reads = std::cell::Cell::new(0u32);
    let start = Instant::now();
    let deadline = start + Duration::from_secs(60);
    let mut now = || {
        reads.set(reads.get() + 1);
        if reads.get() == 1 { start } else { deadline }
    };
    assert!(
        matches!(
            read_evidence_cells(deadline, &mut now, |index| {
                starts.borrow_mut().push(index);
                Ok(7u64)
            }),
            InfoEvidenceRead::Yielded
        ),
        "the mid-group crossing yields with no partial sample"
    );
    assert_eq!(
        *starts.borrow(),
        [INFO_EVIDENCE_INSERT_FAILURES],
        "only the first cell starts: {:?}",
        starts.borrow()
    );
    // A healthy group reads all five cells in index order.
    let starts = RefCell::new(Vec::new());
    let mut now = || start;
    let read = read_evidence_cells(deadline, &mut now, |index| {
        starts.borrow_mut().push(index);
        Ok(u64::from(index) + 1)
    });
    let InfoEvidenceRead::Done(Ok(cells)) = read else {
        panic!("a healthy group reads all five cells");
    };
    assert_eq!(
        *starts.borrow(),
        order,
        "cells read in index order: {:?}",
        starts.borrow()
    );
    assert_eq!(cells, [1, 2, 3, 4, 5]);
    // A failed cell ends the group with its cause: later cells
    // never start.
    let starts = RefCell::new(Vec::new());
    let mut now = || start;
    let read = read_evidence_cells(deadline, &mut now, |index| {
        starts.borrow_mut().push(index);
        if index == INFO_EVIDENCE_UNMATCHED_RETURNS {
            return Err("cells broke".to_string());
        }
        Ok(0u64)
    });
    let InfoEvidenceRead::Done(Err(error)) = read else {
        panic!("a failed cell ends the group with its cause");
    };
    assert_eq!(error, "cells broke");
    assert_eq!(
        *starts.borrow(),
        [
            INFO_EVIDENCE_INSERT_FAILURES,
            INFO_EVIDENCE_UNMATCHED_RETURNS
        ],
        "no cell starts past the failure: {:?}",
        starts.borrow()
    );
}

/// Keymeta Task 7 stop scrub (spec §17.4, INV-2): one poll spends
/// at most 257 native operations all-in — one metadata read plus
/// the 64-row table batch — and the terminal emptiness observation
/// waits for the next poll when the allowance is spent.
#[cfg(not(feature = "stub-object-attributes"))]
#[test]
fn scrub_poll_spends_at_most_257_native_operations_all_in() {
    use std::cell::Cell;
    let fetches = Cell::new(0u64);
    let mut fetch = || {
        fetches.set(fetches.get() + 1);
        Ok(crate::attach::map_metadata(
            aya::maps::MapType::Hash,
            16,
            32,
            1024,
            0,
        ))
    };
    let mut table = FakeScrubTable::full(64, 1024);
    let mut progress = 0u64;
    let mut pending = None;
    let mut budget = generous_budget();
    let capacity = scrub_table_capacity_with(&mut fetch, &mut budget)
        .expect("a healthy shape validates")
        .expect("a generous budget fetches");
    assert_eq!(capacity, 1024);
    let outcome =
        scrub_info_start_step(&mut table, &mut progress, &mut pending, &mut budget).unwrap();
    assert_eq!(
        fetches.get() + table.ops,
        INFO_SCRUB_OPS_PER_POLL,
        "one metadata read plus the 64-row table batch, nothing more"
    );
    assert_eq!(progress, 64, "the full batch cleared");
    assert_eq!(
        outcome,
        InfoScrubOutcome::Pending,
        "the spent allowance defers the emptiness observation"
    );
    // The next poll validates again and observes the empty table.
    let ops_before = table.ops;
    let mut budget = generous_budget();
    let capacity = scrub_table_capacity_with(&mut fetch, &mut budget)
        .expect("a healthy shape validates")
        .expect("a generous budget fetches");
    assert_eq!(capacity, 1024);
    let outcome =
        scrub_info_start_step(&mut table, &mut progress, &mut pending, &mut budget).unwrap();
    assert_eq!(outcome, InfoScrubOutcome::Complete);
    assert_eq!(
        table.ops - ops_before,
        1,
        "one terminal emptiness observation"
    );
}

/// Keymeta Task 7 stop scrub (spec §17.4): a row an in-flight
/// return removed between polls never strands the scrub at its
/// stale key — the absence clears the cursor, counts the resolved
/// row, and the step re-enumerates (charged) to a fresh empty-map
/// observation before completing.
#[cfg(not(feature = "stub-object-attributes"))]
#[test]
fn scrub_step_disappeared_row_clears_the_cursor_and_reenumerates() {
    let mut table = FakeScrubTable::full(1, 1024);
    let mut key = [0u8; 16];
    key[..2].copy_from_slice(&0u16.to_le_bytes());
    // The return removes the row after the enumeration pinned it:
    // the resumed removal observes the absence.
    let mut progress = 0u64;
    let mut pending = Some(PendingScrubRow {
        key,
        next: ScrubSubstep::Remove,
    });
    table.rows.remove(&key);
    assert_eq!(
        scrub_info_start_step(
            &mut table,
            &mut progress,
            &mut pending,
            &mut generous_budget()
        )
        .unwrap(),
        InfoScrubOutcome::Complete,
        "a disappeared row completes on a fresh empty observation"
    );
    assert_eq!(progress, 1, "the resolved row counts");
    assert_eq!(pending, None, "the stale cursor clears");
    assert_eq!(
        table.ops, 2,
        "the failed removal plus the charged re-enumeration"
    );
}

/// Keymeta Task 7 stop scrub (spec §17.4): a row disappearing
/// mid-step — between its zero and its verify — resolves the same
/// way, while a concrete non-absence failure still retries with
/// the cursor kept.
#[cfg(not(feature = "stub-object-attributes"))]
#[test]
fn scrub_step_row_disappearing_mid_step_resolves_and_non_absence_retries() {
    let mut table = FakeScrubTable::full(1, 1024);
    let mut key = [0u8; 16];
    key[..2].copy_from_slice(&0u16.to_le_bytes());
    table.remove_on_verify.insert(key);
    let mut progress = 0u64;
    assert_eq!(
        scrub_info_start_step(&mut table, &mut progress, &mut None, &mut generous_budget())
            .unwrap(),
        InfoScrubOutcome::Complete,
        "a mid-step disappearance completes on re-enumeration"
    );
    assert_eq!(progress, 1, "the resolved row counts");
    assert_eq!(
        table.ops, 4,
        "enumerate, zero, the observing verify, re-enumeration"
    );
    // A concrete failure is not an absence: it retries with the
    // pending substep kept.
    let mut table = FakeScrubTable::full(1, 1024);
    table.fail_on_substep = Some("verify");
    let mut progress = 0u64;
    let mut pending = None;
    let error = scrub_info_start_step(
        &mut table,
        &mut progress,
        &mut pending,
        &mut generous_budget(),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("persistent scrub fault"),
        "concrete failures stay reportable: {error:#}"
    );
    assert_eq!(
        pending,
        Some(PendingScrubRow {
            key,
            next: ScrubSubstep::Verify,
        }),
        "concrete failures keep the cursor for retry"
    );
    assert_eq!(progress, 0, "nothing resolves on failure");
}

/// Keymeta Task 7 stop scrub (spec §17.4): retained links refuse the
/// scrub outright — the step never runs — and transfer with teardown
/// explicitly unproven.
#[cfg(not(feature = "stub-object-attributes"))]
#[test]
fn scrub_phase_refuses_retained_links() {
    let mut phase = InfoScrubPhase::default();
    let mut stepped = false;
    assert_eq!(
        phase.poll(true, |_, _| {
            stepped = true;
            Ok(InfoScrubOutcome::Complete)
        }),
        InfoScrubDirective::Transfer { unproven: true }
    );
    assert!(!stepped, "refused scrubs run no map operations");
    assert_eq!(
        phase.error.as_deref(),
        Some("scrub refused: links retained")
    );
}

/// Keymeta Task 7 stop scrub (spec §17.4): the phase lifecycle —
/// pending work retries with progress kept, concrete failures retry
/// with the failure carried, saturation resets progress and retries,
/// and completion transfers clean, clearing transient errors.
#[cfg(not(feature = "stub-object-attributes"))]
#[test]
fn scrub_phase_drives_pending_errors_and_saturation() {
    let mut phase = InfoScrubPhase::default();
    assert_eq!(
        phase.poll(false, |cleared, _| {
            *cleared = 64;
            Ok(InfoScrubOutcome::Pending)
        }),
        InfoScrubDirective::Retry
    );
    assert_eq!(phase.cleared, 64, "pending keeps progress");
    assert_eq!(
        phase.poll(false, |_, _| Err("cells broke".into())),
        InfoScrubDirective::Retry
    );
    assert_eq!(phase.error.as_deref(), Some("cells broke"));
    assert_eq!(phase.cleared, 64, "errors keep progress");
    assert_eq!(
        phase.poll(false, |_, _| Ok(InfoScrubOutcome::Saturated)),
        InfoScrubDirective::Retry
    );
    assert_eq!(phase.cleared, 0, "saturation resets progress");
    assert_eq!(
        phase.poll(false, |_, _| Ok(InfoScrubOutcome::Complete)),
        InfoScrubDirective::Transfer { unproven: false }
    );
    assert!(phase.error.is_none(), "completion clears transient errors");
}

/// Keymeta Task 7 teardown reporting (spec §17.4): a persistent
/// zero-substep failure retries with its concrete error carried,
/// and the timeout classifies it beside the detach outcome —
/// never a bare "probes did not detach".
#[cfg(not(feature = "stub-object-attributes"))]
#[test]
fn persistent_zero_failure_reports_its_concrete_error_on_timeout() {
    use crate::inventory_capture::{Retirement, classify_retirement};
    let mut table = FakeScrubTable::full(2, 1024);
    table.fail_on_substep = Some("zero");
    let mut phase = InfoScrubPhase::default();
    for poll in 1..=2u32 {
        assert_eq!(
            phase.poll(false, |cleared, pending| {
                scrub_info_start_step(&mut table, cleared, pending, &mut generous_budget())
                    .map_err(|error| format!("{error:#}"))
            }),
            InfoScrubDirective::Retry,
            "poll {poll}: a failing zero retries"
        );
        let InfoTeardown::Failed { error } = phase.status() else {
            panic!("poll {poll}: the status carries the failure");
        };
        assert!(
            error.contains("zero"),
            "poll {poll}: the concrete zero error survives: {error}"
        );
        let Retirement::Unsettled(reason) = classify_retirement(
            true,
            false,
            None,
            None,
            &InfoTeardown::Failed {
                error: error.clone(),
            },
            Duration::from_millis(300),
        ) else {
            panic!("poll {poll}: a timed-out retirement reads unsettled");
        };
        assert!(
            reason.contains("probes detached"),
            "poll {poll}: completed detach reads as completed: {reason}"
        );
        assert!(
            !reason.contains("did not detach"),
            "poll {poll}: no detach timeout past completed detach: {reason}"
        );
        assert!(
            reason.contains(&error),
            "poll {poll}: the concrete error crosses the timeout: {reason}"
        );
    }
}

/// Keymeta Task 7 teardown reporting (spec §17.4): a persistent
/// read-back failure reports end to end like the zero twin.
#[cfg(not(feature = "stub-object-attributes"))]
#[test]
fn persistent_readback_failure_reports_its_concrete_error_on_timeout() {
    use crate::inventory_capture::{Retirement, classify_retirement};
    let mut table = FakeScrubTable::full(2, 1024);
    table.fail_on_substep = Some("verify");
    let mut phase = InfoScrubPhase::default();
    for poll in 1..=2u32 {
        assert_eq!(
            phase.poll(false, |cleared, pending| {
                scrub_info_start_step(&mut table, cleared, pending, &mut generous_budget())
                    .map_err(|error| format!("{error:#}"))
            }),
            InfoScrubDirective::Retry,
            "poll {poll}: a failing read-back retries"
        );
        let InfoTeardown::Failed { error } = phase.status() else {
            panic!("poll {poll}: the status carries the failure");
        };
        assert!(
            error.contains("verify"),
            "poll {poll}: the concrete read-back error survives: {error}"
        );
        let Retirement::Unsettled(reason) = classify_retirement(
            true,
            false,
            None,
            None,
            &InfoTeardown::Failed {
                error: error.clone(),
            },
            Duration::from_millis(300),
        ) else {
            panic!("poll {poll}: a timed-out retirement reads unsettled");
        };
        assert!(
            reason.contains(&error),
            "poll {poll}: the concrete error crosses the timeout: {reason}"
        );
    }
}

/// Keymeta Task 7 teardown reporting (spec §17.4): a persistent
/// remove-substep failure reports end to end like the zero twin.
#[cfg(not(feature = "stub-object-attributes"))]
#[test]
fn persistent_remove_failure_reports_its_concrete_error_on_timeout() {
    use crate::inventory_capture::{Retirement, classify_retirement};
    let mut table = FakeScrubTable::full(2, 1024);
    table.fail_on_substep = Some("remove");
    let mut phase = InfoScrubPhase::default();
    for poll in 1..=2u32 {
        assert_eq!(
            phase.poll(false, |cleared, pending| {
                scrub_info_start_step(&mut table, cleared, pending, &mut generous_budget())
                    .map_err(|error| format!("{error:#}"))
            }),
            InfoScrubDirective::Retry,
            "poll {poll}: a failing remove retries"
        );
        let InfoTeardown::Failed { error } = phase.status() else {
            panic!("poll {poll}: the status carries the failure");
        };
        assert!(
            error.contains("remove"),
            "poll {poll}: the concrete remove error survives: {error}"
        );
        let Retirement::Unsettled(reason) = classify_retirement(
            true,
            false,
            None,
            None,
            &InfoTeardown::Failed {
                error: error.clone(),
            },
            Duration::from_millis(300),
        ) else {
            panic!("poll {poll}: a timed-out retirement reads unsettled");
        };
        assert!(
            reason.contains(&error),
            "poll {poll}: the concrete error crosses the timeout: {reason}"
        );
    }
}
