//! SPDX-License-Identifier: GPL-3.0-or-later
//! Pass-local custody controls. Scripted verdicts do not claim live BPF proof.

use super::super::identity::FileIdentity;
use super::*;
use crate::attach::identity_iter::{
    ANCHOR_DUP, ANCHOR_OK, KIND_ANCHOR, KIND_END, RECORD_MAGIC, RECORD_VERSION,
};
use std::cell::{Cell, RefCell};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::rc::Rc;

fn opened(dir: &std::path::Path, name: &str) -> (File, ExaminedObject) {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(dir.join(name))
        .unwrap();
    file.set_len(4096).unwrap();
    file.write_at(b"original", 0).unwrap();
    let meta = file.metadata().unwrap();
    let identity = FileIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
    };
    let key = ObjectKey {
        device: p11scope_manifest::maps::Device {
            major: libc::major(meta.dev()) as u64,
            minor: libc::minor(meta.dev()) as u64,
        },
        inode: meta.ino(),
    };
    (
        file,
        ExaminedObject {
            key,
            identity,
            key_is_identity: false,
        },
    )
}

fn custody(cap: usize, callers: BTreeMap<ObjectKey, usize>) -> ExaminedCustody {
    ExaminedCustody::new(
        ReservationOwner::for_examined(SegmentPolicy::from_headroom(64, 0, 0), cap),
        callers,
    )
}

fn fixture_session() -> IdentitySession {
    IdentitySession {
        object: SessionObject::Fixture {
            _object: tempfile::tempfile().unwrap(),
            anchor: anchor_stream(&[(0, ANCHOR_OK, 0)]),
            target: b"fixture target bytes".to_vec(),
            config: None,
            fail_config: false,
            reads: Cell::new(0),
        },
        scope: crate::attach::identity_iter::ScopeBitmap::default(),
        generation: 0,
        token: Arc::new(()),
        binding: None,
    }
}

fn owner_counterexample(case: usize) {
    let dir = tempfile::tempdir().unwrap();
    let pins = PinnedObjects::empty();
    let prepare = |name: &str| {
        let (file, examined) = opened(dir.path(), name);
        let mut custody = custody(1, BTreeMap::new());
        let scan = custody.begin_scan();
        assert!(custody.offer_for_test(scan, examined, file));
        AnchorPass::prepare(&pins, [], custody)
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut session = fixture_session();
    session.replace_scope(&[std::process::id()]).unwrap();
    let mut pass = prepare("first.so");
    match case {
        0 => {} // An uninstalled arena never authorizes a target run.
        1 => {
            pass = session.install_unowned_for_test(pass, 1, deadline).unwrap();
            let mut foreign = fixture_session();
            foreign.replace_scope(&[std::process::id()]).unwrap();
            session = foreign;
        }
        2 => {
            pass = session.install_unowned_for_test(pass, 1, deadline).unwrap();
            if let SessionObject::Fixture { anchor, .. } = &mut session.object {
                for record in anchor.as_chunks_mut::<32>().0 {
                    record[28..32].copy_from_slice(&2u32.to_le_bytes());
                }
            }
            let other = session
                .install_unowned_for_test(prepare("second.so"), 2, deadline)
                .unwrap();
            drop(other);
        }
        3 => {
            let installed = session.install_unowned_for_test(pass, 1, deadline).unwrap();
            let address = installed.arena.as_ref().unwrap().base();
            drop(installed);
            assert!(!mapped(address));
            pass = prepare("second.so");
        }
        _ => {
            if let SessionObject::Fixture { fail_config, .. } = &mut session.object {
                *fail_config = true;
            }
            assert!(session.install_unowned_for_test(pass, 1, deadline).is_err());
            pass = prepare("second.so");
        }
    }
    let before = match &session.object {
        SessionObject::Fixture { reads, .. } => reads.get(),
        _ => unreachable!(),
    };
    assert!(
        pass.read_run(&session, RunKind::Target, None, deadline, 128)
            .is_err(),
        "case {case}: a pass read another or absent installation"
    );
    let after = match &session.object {
        SessionObject::Fixture { reads, .. } => reads.get(),
        _ => unreachable!(),
    };
    assert_eq!(before, after, "refused ownership performed iterator I/O");
}

#[test]
fn d3b_uninstalled_pass_cannot_read_ready_session() {
    owner_counterexample(0);
}
#[test]
fn d3b_foreign_session_cannot_read_installed_pass() {
    owner_counterexample(1);
}
#[test]
fn d3b_superseded_installation_cannot_read_old_pass() {
    owner_counterexample(2);
}
#[test]
fn d3b_released_installation_cannot_read_new_pass() {
    owner_counterexample(3);
}
#[test]
fn d3b_failed_installation_cannot_authorize_next_pass() {
    owner_counterexample(4);
}

#[test]
fn d3b_owned_installation_reads_only_while_custody_is_live() {
    let dir = tempfile::tempdir().unwrap();
    let (file, examined) = opened(dir.path(), "held.so");
    let held_fd = FdToken::of(&file);
    let mut custody = custody(1, BTreeMap::new());
    let scan = custody.begin_scan();
    assert!(custody.offer_for_test(scan, examined, file));
    let pins = PinnedObjects::empty();
    let pass = AnchorPass::prepare(&pins, [], custody);
    let mut session = fixture_session();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut installed = session.install_anchors(pass, 1, deadline).unwrap();
    assert!(fd_open(held_fd));
    assert_eq!(
        installed.read_target(None, deadline, 128).unwrap(),
        b"fixture target bytes"
    );
    assert!(installed.read_target(None, deadline, 1).is_err());
    assert!(
        fd_open(held_fd),
        "failed target released custody before guard drop"
    );
    drop(installed);
    assert!(!fd_open(held_fd));
    assert!(session.binding.is_none());
    assert!(!session.scope.ready());
}

fn mapped(address: u64) -> bool {
    let mut residency = 0u8;
    // SAFETY: mincore observes one aligned page and does not dereference it.
    unsafe { libc::mincore(address as *mut libc::c_void, 4096, &mut residency) == 0 }
}

#[test]
fn d3b_pinned_files_precede_examined_and_are_borrowed_without_reopening() {
    let dir = tempfile::tempdir().unwrap();
    let (file, admitted) = opened(dir.path(), "admitted.so");
    drop(file);
    let pins = super::super::identity::test_fixture::real_scan_pin(
        &dir.path().join("admitted.so"),
        None,
        1,
        "fixture",
    );
    let id = pins.pinned().next().unwrap().id;
    let admitted_file = pins.file_for(id).unwrap();
    let mut custody = custody(2, BTreeMap::new());
    let mut examined_keys = Vec::new();
    for name in ["one.so", "two.so"] {
        let (file, examined) = opened(dir.path(), name);
        examined_keys.push(examined.key);
        let scan = custody.begin_scan();
        assert!(custody.offer_for_test(scan, examined, file));
    }
    std::fs::remove_file(dir.path().join("admitted.so")).unwrap();
    let pass = AnchorPass::prepare_limits(&pins, [(admitted.key, id)], custody, 2, 2);
    assert_eq!(pass.candidates.len(), 2);
    assert!(std::ptr::eq(pass.candidates[0].file.file(), admitted_file));
    assert_eq!(pass.candidates[0].slot, Slot(0));
    let loser = *examined_keys.iter().max().unwrap();
    assert_eq!(pass.fallback[&loser], AnchorDeny::AnchorCap);
    let arena = pass.arena.as_ref().unwrap();
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let entries = p11scope_manifest::maps::parse_maps(maps.as_bytes()).unwrap();
    let anchor = entries
        .iter()
        .find(|entry| entry.start == arena.slot_page(0).unwrap())
        .unwrap();
    assert_eq!(anchor.file_offset, 0);
    assert_eq!(&anchor.permissions[..3], b"r--");
    assert_eq!((EXAMINED_ANCHOR_CAP, TOTAL_ANCHOR_CAP), (512, 1024));
    drop(pass);
    assert!(
        admitted_file.metadata().is_ok(),
        "anchor owner closed a borrowed admitted File"
    );
}

#[test]
fn d3b_offer_census_is_bounded_sticky_and_sees_admitted_growth() {
    let dir = tempfile::tempdir().unwrap();
    let mut custody = custody(2, BTreeMap::new());
    let owner = custody.owner.clone();
    let (file, examined) = opened(dir.path(), "first.so");
    let fd = FdToken::of(&file);
    let scan = custody.begin_scan();
    assert!(
        custody.offer_with_census(scan, examined, file, || Ok(SegmentPolicy::from_headroom(
            3, 0, 0
        )))
    );
    let (file, other) = opened(dir.path(), "other.so");
    assert!(
        !custody.offer_with_census(scan, other, file, || Ok(SegmentPolicy::from_headroom(
            2, 0, 0
        ))),
        "admitted growth consumed the immediate envelope"
    );
    assert!(
        fd_open(fd),
        "ordinary low headroom discarded earlier complete custody"
    );
    let (file, failed) = opened(dir.path(), "failed.so");
    assert!(!custody.offer_with_census(scan, failed, file, || Err(
        "injected read/entry/deadline failure".into()
    )));
    assert!(!fd_open(fd));
    assert_eq!(owner.examined_for_test().0, 0);
    let (file, later) = opened(dir.path(), "later.so");
    assert!(!custody.offer_with_census(scan, later, file, || panic!("census failure was retried")));
    let pins = PinnedObjects::empty();
    let pass = AnchorPass::prepare(&pins, [], custody);
    assert!(pass.candidates.is_empty());
    for key in [examined.key, other.key, failed.key, later.key] {
        assert_eq!(pass.fallback[&key], AnchorDeny::FdHeadroom);
    }
}

#[test]
fn d3b_cap_losing_offer_does_not_enumerate_fds() {
    let dir = tempfile::tempdir().unwrap();
    let (file, examined) = opened(dir.path(), "first.so");
    let mut custody = custody(1, BTreeMap::new());
    let scan = custody.begin_scan();
    assert!(custody.offer_for_test(scan, examined, file));
    let (file, _) = opened(dir.path(), "other.so");
    assert!(!custody.offer_with_census(scan, examined, file, || panic!(
        "cap-losing offer enumerated FDs"
    )));
}

#[derive(Clone, Copy)]
struct FdToken {
    raw: i32,
    dev: u64,
    ino: u64,
}
impl FdToken {
    fn of(file: &File) -> Self {
        let meta = file.metadata().unwrap();
        Self {
            raw: file.as_raw_fd(),
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }
}
fn fd_open(fd: FdToken) -> bool {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat initializes stat on success; no descriptor ownership changes.
    if unsafe { libc::fstat(fd.raw, stat.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: successful fstat initialized stat.
    let stat = unsafe { stat.assume_init() };
    // This is an FD-reuse guard for our unique real fixture files, not a
    // physical-identity attribution proof based on inode metadata.
    stat.st_dev == fd.dev && stat.st_ino == fd.ino
}

fn anchor_stream(outcomes: &[(u32, u32, u64)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for &(slot, outcome, root) in outcomes {
        let mut record = [0u8; 32];
        record[..2].copy_from_slice(&RECORD_MAGIC.to_le_bytes());
        record[2] = RECORD_VERSION;
        record[3] = KIND_ANCHOR;
        record[4..8].copy_from_slice(&slot.to_le_bytes());
        record[8..16].copy_from_slice(&root.to_le_bytes());
        record[24..28].copy_from_slice(&outcome.to_le_bytes());
        record[28..32].copy_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&record);
    }
    let mut end = [0u8; 32];
    end[..2].copy_from_slice(&RECORD_MAGIC.to_le_bytes());
    end[2] = RECORD_VERSION;
    end[3] = KIND_END;
    end[28..32].copy_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&end);
    bytes
}

#[test]
fn d3b_custody_retains_exact_open_file_after_replace_or_unlink() {
    for unlink in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("examined.so");
        let (file, examined) = opened(dir.path(), "examined.so");
        let fd = FdToken::of(&file);
        let mut custody = custody(2, BTreeMap::new());
        let scan = custody.begin_scan();
        assert!(custody.offer_for_test(scan, examined, file));
        if unlink {
            std::fs::remove_file(&path).unwrap();
        } else {
            std::fs::rename(&path, dir.path().join("replaced.so")).unwrap();
            std::fs::write(&path, b"replacement").unwrap();
        }
        let held = &custody.candidates[0];
        assert_eq!(
            held.file.as_raw_fd(),
            fd.raw,
            "custody reconstructed a pathname"
        );
        assert_eq!(held.file.metadata().unwrap().ino(), examined.identity.ino);
        let mut bytes = [0; 8];
        held.file.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"original");
        drop(custody);
        assert!(!fd_open(fd), "the exact retained file outlived custody");
    }
}

#[test]
fn d3b_equal_metadata_never_deduplicates_distinct_open_files() {
    let dir = tempfile::tempdir().unwrap();
    let (first, examined) = opened(dir.path(), "first.so");
    let (second, actual_second) = opened(dir.path(), "second.so");
    assert_ne!(
        examined.identity, actual_second.identity,
        "real fixture files are distinct"
    );
    // Script equal metadata only to test the custody policy. This is not a
    // demonstrated filesystem collision or a kernel physical-identity proof.
    let mut custody = custody(2, BTreeMap::new());
    let scan = custody.begin_scan();
    assert!(custody.offer_for_test(scan, examined, first));
    assert!(custody.offer_for_test(scan, examined, second));
    assert_eq!(custody.candidates.len(), 2);
    let pins = PinnedObjects::empty();
    let mut pass = AnchorPass::prepare(&pins, [], custody);
    assert_eq!(pass.candidates.len(), 2);
    pass.accept_anchor_run(&anchor_stream(&[(0, ANCHOR_OK, 0), (1, ANCHOR_OK, 0)]), 1)
        .unwrap();
    assert_eq!(
        pass.expected[&examined.key],
        BTreeSet::from([Slot(0), Slot(1)])
    );
    // Only a valid DUP outcome is allowed to collapse the slot expectations.
    pass.accept_anchor_run(&anchor_stream(&[(0, ANCHOR_OK, 0), (1, ANCHOR_DUP, 0)]), 1)
        .unwrap();
    assert_eq!(pass.expected[&examined.key], BTreeSet::from([Slot(0)]));
    assert!(
        pass.accept_anchor_run(&anchor_stream(&[(0, ANCHOR_DUP, 1), (1, ANCHOR_DUP, 0)]), 1)
            .is_err()
    );
    assert!(
        pass.expected.is_empty(),
        "invalid aliases retained previous expectations"
    );
}

#[test]
fn d3b_global_overflow_ranking_is_deterministic() {
    let dir = tempfile::tempdir().unwrap();
    let opened: Vec<_> = (0..6)
        .map(|i| opened(dir.path(), &format!("{i}.so")))
        .collect();
    let mut ranks = BTreeMap::new();
    for (i, (_, object)) in opened.iter().enumerate() {
        ranks.insert(object.key, i / 2);
    }
    let mut expected: Vec<_> = ranks.keys().copied().collect();
    expected.sort_by_key(|key| (std::cmp::Reverse(ranks[key]), *key));
    let mut custody = custody(2, ranks);
    let owner = custody.owner.clone();
    for (file, object) in opened {
        let scan = custody.begin_scan();
        custody.offer_for_test(scan, object, file);
    }
    let mut actual: Vec<_> = custody
        .candidates
        .iter()
        .map(|held| held.examined.key)
        .collect();
    actual.sort_unstable();
    let mut wanted = expected[..2].to_vec();
    wanted.sort_unstable();
    assert_eq!(actual, wanted, "global cap or rank multiplied per member");
    assert_eq!(owner.examined_for_test(), (2, 2));
    let pins = PinnedObjects::empty();
    let pass = AnchorPass::prepare(&pins, [], custody);
    assert_eq!(pass.candidates.len(), 2);
    assert_eq!(
        pass.fallback.keys().copied().collect::<BTreeSet<_>>(),
        expected[2..].iter().copied().collect()
    );
    drop(pass);
    assert_eq!(owner.examined_for_test().0, 0);
}

#[test]
fn d3b_missing_one_candidate_forces_whole_key_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let (first, examined) = opened(dir.path(), "first.so");
    let (second, _) = opened(dir.path(), "second.so");
    let mut custody = custody(1, BTreeMap::new());
    let scan = custody.begin_scan();
    assert!(custody.offer_for_test(scan, examined, first));
    assert!(!custody.offer_for_test(scan, examined, second));
    let pins = PinnedObjects::empty();
    let mut pass = AnchorPass::prepare(&pins, [], custody);
    pass.accept_anchor_run(&anchor_stream(&[(0, ANCHOR_OK, 0)]), 1)
        .unwrap();
    assert!(!pass.expected.contains_key(&examined.key));
    assert_eq!(pass.fallback[&examined.key], AnchorDeny::AnchorCap);
}

#[test]
fn d3b_invalid_scan_and_census_failure_close_owned_files() {
    let dir = tempfile::tempdir().unwrap();
    let mut custody = custody(2, BTreeMap::new());
    let owner = custody.owner.clone();
    let (first, examined) = opened(dir.path(), "first.so");
    let first_fd = FdToken::of(&first);
    let one = custody.begin_scan();
    assert!(custody.offer_for_test(one, examined, first));
    let (second, examined) = opened(dir.path(), "second.so");
    let second_fd = FdToken::of(&second);
    let two = custody.begin_scan();
    assert!(custody.offer_for_test(two, examined, second));
    custody.discard_scan(one);
    assert!(!fd_open(first_fd));
    assert!(fd_open(second_fd));
    assert_eq!(owner.examined_for_test().0, 1);
    let transient = owner.immediate().transient().unwrap();
    assert!(
        custody
            .reconcile(SegmentPolicy::from_headroom(6, 1, 1))
            .is_err()
    );
    assert!(!fd_open(second_fd));
    assert_eq!(owner.examined_for_test().0, 0);
    drop(transient);
    assert_eq!(owner.state_for_test().0, [0; 4]);
}

#[test]
fn d3b_empty_files_never_gain_an_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let (file, examined) = opened(dir.path(), "empty.so");
    file.set_len(0).unwrap();
    let mut custody = custody(1, BTreeMap::new());
    let scan = custody.begin_scan();
    assert!(custody.offer_for_test(scan, examined, file));
    let pins = PinnedObjects::empty();
    let pass = AnchorPass::prepare(&pins, [], custody);
    assert!(pass.candidates.is_empty());
    assert_eq!(pass.fallback[&examined.key], AnchorDeny::AnchorNotInstalled);
}

#[test]
fn d3b_run_closes_before_anchor_and_file_release_on_success_or_error() {
    for error in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (file, examined) = opened(dir.path(), "retained.so");
        let file_fd = FdToken::of(&file);
        let mut custody = custody(1, BTreeMap::new());
        let scan = custody.begin_scan();
        assert!(custody.offer_for_test(scan, examined, file));
        let pins = PinnedObjects::empty();
        let mut pass = AnchorPass::prepare(&pins, [], custody);
        assert!(pass.arena.is_some());
        let arena_address = pass.arena.as_ref().unwrap().base();
        let events = Rc::new(RefCell::new(Vec::new()));
        let arena_events = events.clone();
        pass.after_arena = Some(DropObserver(Some(Box::new(move || {
            assert!(
                !mapped(arena_address),
                "arena stayed mapped when files began to release"
            );
            assert!(
                fd_open(file_fd),
                "examined File closed before its anchor arena"
            );
            arena_events.borrow_mut().push("arena");
        }))));
        let file_events = events.clone();
        pass.after_files = Some(DropObserver(Some(Box::new(move || {
            assert!(!fd_open(file_fd), "examined File leaked after owner drop");
            file_events.borrow_mut().push("file");
        }))));
        let run = tempfile::tempfile().unwrap();
        run.write_at(&anchor_stream(&[(0, ANCHOR_OK, 0)]), 0)
            .unwrap();
        let run_fd = FdToken::of(&run);
        let link = tempfile::tempfile().unwrap();
        let link_fd = FdToken::of(&link);
        let deadline = std::time::Instant::now()
            + if error {
                std::time::Duration::ZERO
            } else {
                std::time::Duration::from_secs(10)
            };
        let result = pass.read_fixture_run(run.into(), link.into(), deadline, 128);
        assert_eq!(result.is_err(), error);
        assert!(!fd_open(run_fd), "iterator remained live after consumption");
        assert!(!fd_open(link_fd), "link remained live after consumption");
        assert!(mapped(arena_address));
        assert!(fd_open(file_fd));
        events.borrow_mut().push("iterator");
        if let Ok(bytes) = result {
            pass.accept_anchor_run(&bytes, 1).unwrap();
        }
        drop(pass);
        assert!(!fd_open(file_fd));
        assert_eq!(&*events.borrow(), &["iterator", "arena", "file"]);
    }
}

#[test]
fn d3b_partial_anchor_install_and_failed_target_close_all_custody() {
    let dir = tempfile::tempdir().unwrap();
    let mut custody = custody(2, BTreeMap::new());
    let owner = custody.owner.clone();
    let mut fds = Vec::new();
    for name in ["one.so", "two.so"] {
        let (file, examined) = opened(dir.path(), name);
        fds.push(FdToken::of(&file));
        let scan = custody.begin_scan();
        assert!(custody.offer_for_test(scan, examined, file));
    }
    let pins = PinnedObjects::empty();
    let pass = AnchorPass::prepare(&pins, [], custody);
    let address = pass.arena.as_ref().unwrap().base();
    let mut session = fixture_session();
    if let SessionObject::Fixture { target, .. } = &mut session.object {
        *target = vec![1; 64];
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut installed = session.install_anchors(pass, 1, deadline).unwrap();
    assert_eq!(
        installed.pass.as_ref().unwrap().expected.len(),
        1,
        "partial installation invented the absent anchor"
    );
    assert_eq!(installed.pass.as_ref().unwrap().fallback.len(), 1);
    assert!(fds.iter().all(|fd| fd_open(*fd)));
    // The scripted session uses actual owned FDs and the production consume
    // primitive; this is an over-limit read, not a live BPF verdict.
    let result = installed.read_target(None, deadline, 32);
    assert!(result.is_err());
    assert!(mapped(address) && fds.iter().all(|fd| fd_open(*fd)));
    drop(installed);
    assert!(!mapped(address));
    assert!(fds.iter().all(|fd| !fd_open(*fd)));
    assert_eq!(owner.examined_for_test().0, 0);
    assert!(session.binding.is_none() && !session.scope.ready());
}

struct LoadedFixture {
    id: usize,
    generation: u64,
    scope: BTreeSet<u32>,
    slots: Vec<u32>,
    file: File,
    events: Rc<RefCell<Vec<(usize, &'static str)>>>,
}
impl Drop for LoadedFixture {
    fn drop(&mut self) {
        self.events.borrow_mut().push((self.id, "drop"));
    }
}

#[test]
fn d3b_probe_owner_drops_before_fresh_production_load() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let loads = Cell::new(0);
    let probe_fd = Cell::new(None);
    let production = probe_then_fresh(
        || {
            let id = loads.get();
            if id > 0 {
                assert!(
                    !fd_open(probe_fd.get().unwrap()),
                    "probe FD overlaps production load"
                );
            }
            loads.set(id + 1);
            events.borrow_mut().push((id, "load"));
            Ok::<_, &'static str>(LoadedFixture {
                id,
                generation: 0,
                scope: BTreeSet::new(),
                slots: Vec::new(),
                file: tempfile::tempfile().unwrap(),
                events: events.clone(),
            })
        },
        |probe| {
            probe_fd.set(Some(FdToken::of(&probe.file)));
            probe.generation = 42;
            probe.scope.insert(123);
            probe.slots.push(7);
            events.borrow_mut().push((probe.id, "probe"));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(loads.get(), 2, "probe state reused as production state");
    assert_eq!(production.generation, 0);
    assert!(production.scope.is_empty() && production.slots.is_empty());
    assert_eq!(
        &*events.borrow(),
        &[(0, "load"), (0, "probe"), (0, "drop"), (1, "load")]
    );
}

#[test]
fn d3b_failed_probe_never_loads_production_state() {
    let loads = Cell::new(0);
    let fd = Cell::new(None);
    let result = probe_then_fresh(
        || {
            loads.set(loads.get() + 1);
            Ok::<_, &'static str>(tempfile::tempfile().unwrap())
        },
        |probe| {
            fd.set(Some(FdToken::of(probe)));
            Err("failed probe")
        },
    );
    assert!(result.is_err());
    assert_eq!(loads.get(), 1);
    assert!(!fd_open(fd.get().unwrap()));
}

#[test]
fn d3b_probe_report_requires_every_functional_outcome() {
    use crate::attach::identity_iter::{AnchorOutcome, FunctionalProbeReport, TargetVerdict};
    let report = FunctionalProbeReport {
        child_pid: 17,
        anchor_outcomes: vec![(0, AnchorOutcome::Ok), (1, AnchorOutcome::Ok)],
        hardlink_verdict: TargetVerdict::Slot(0),
        second_verdict: TargetVerdict::Slot(1),
        copy_verdict: TargetVerdict::Unmatched,
        child_record_count: 3,
        child_unmatched_count: 1,
        pids_seen: vec![17],
        demoted_pids: vec![],
        stale_unmatched: true,
    };
    assert!(probe_succeeded(&report));
    for failure in 0..7 {
        let mut report = report.clone();
        match failure {
            0 => report.anchor_outcomes[1].1 = AnchorOutcome::Full,
            1 => report.hardlink_verdict = TargetVerdict::Unmatched,
            2 => report.second_verdict = TargetVerdict::Slot(0),
            3 => report.copy_verdict = TargetVerdict::Slot(0),
            4 => report.pids_seen.push(18),
            5 => report.demoted_pids.push(17),
            _ => report.stale_unmatched = false,
        }
        assert!(
            !probe_succeeded(&report),
            "probe outcome {failure} was not required"
        );
    }
}
