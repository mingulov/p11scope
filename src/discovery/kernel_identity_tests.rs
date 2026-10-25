//! SPDX-License-Identifier: GPL-3.0-or-later
//! Pass-local custody controls. Scripted verdicts do not claim live BPF proof.

use super::super::identity::FileIdentity;
use super::*;
use crate::attach::identity_iter::{
    ANCHOR_DUP, ANCHOR_OK, KIND_ANCHOR, KIND_END, RECORD_MAGIC, RECORD_VERSION,
};
use p11scope_manifest::maps::MapEntry;
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
            target_steps: RefCell::new(std::collections::VecDeque::new()),
            target_trace: Arc::new(std::sync::Mutex::new(FixtureRunTrace::default())),
            scope_words: RefCell::new(BTreeMap::new()),
        },
        scope: crate::attach::identity_iter::ScopeBitmap::default(),
        generation: 0,
        token: Arc::new(()),
        binding: None,
        sticky: None,
        consecutive_deadlines: 0,
        fallback: KernelFallbackLedger::default(),
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
            let mapping = anchor_mapping(installed.arena.as_ref().unwrap().base());
            drop(installed);
            assert!(!anchor_mapping_held(&mapping));
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

fn anchor_mapping(address: u64) -> MapEntry {
    let maps = std::fs::read("/proc/self/maps").unwrap();
    let entry = p11scope_manifest::maps::parse_maps(&maps)
        .unwrap()
        .into_iter()
        .find(|entry| entry.start <= address && address < entry.end)
        .expect("the live anchor has a mapping");
    assert_ne!(entry.inode, 0, "the anchor maps the retained fixture file");
    entry
}

fn anchor_mapping_held(mapping: &MapEntry) -> bool {
    // The unique fixture remains named, so its inode cannot be recycled while
    // this observation runs. Compare its actual maps key and path; unrelated
    // tests may already have reused the numeric address after arena drop.
    // This is teardown evidence only, never physical-identity or pass authority.
    let maps = std::fs::read("/proc/self/maps").unwrap();
    p11scope_manifest::maps::parse_maps(&maps)
        .unwrap()
        .iter()
        .any(|entry| {
            entry.start < mapping.end
                && mapping.start < entry.end
                && ObjectKey::of(entry) == ObjectKey::of(mapping)
                && entry.raw_path == mapping.raw_path
        })
}

#[test]
fn d3b_reused_anchor_address_cannot_authorize_uninstalled_or_stale_pass() {
    const CHILD: &str = "P11SCOPE_D3B_ANCHOR_REUSE_CHILD";
    const COMPLETED: &str = "P11SCOPE_D3B_ANCHOR_REUSE_REFUSALS_COMPLETED";
    if std::env::var_os(CHILD).is_none() {
        // Keep deliberate address reuse out of other tests' address space.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "discovery::kernel_identity::tests::d3b_reused_anchor_address_cannot_authorize_uninstalled_or_stale_pass",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "anchor reuse child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line == COMPLETED),
            "anchor reuse child did not complete its refusal assertions:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        return;
    }

    struct ReusedAddress {
        base: *mut libc::c_void,
        len: usize,
    }
    impl Drop for ReusedAddress {
        fn drop(&mut self) {
            // SAFETY: this guard owns exactly the successful mapping below.
            unsafe { libc::munmap(self.base, self.len) };
        }
    }

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
    let installed = session
        .install_unowned_for_test(prepare("released.so"), 1, deadline)
        .unwrap();
    let arena = installed.arena.as_ref().unwrap();
    let address = arena.base();
    let len = arena.len() as usize;
    let mapping = anchor_mapping(address);
    let stale = installed.binding.as_ref().unwrap().clone();
    drop(installed);
    // SAFETY: NOREPLACE claims only an unmapped range. A racing allocation
    // makes the test refuse, never overwrite somebody else's mapping.
    let base = unsafe {
        libc::mmap(
            address as *mut libc::c_void,
            len,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    assert_ne!(
        base,
        libc::MAP_FAILED,
        "{}",
        std::io::Error::last_os_error()
    );
    let reused = ReusedAddress { base, len };
    assert_eq!(reused.base.addr() as u64, address);
    assert!(
        mapped(address),
        "a different VMA now occupies the old address"
    );
    assert!(
        !anchor_mapping_held(&mapping),
        "address reuse must not revive the released fixture mapping"
    );

    let mut pass = prepare("uninstalled.so");
    assert_ne!(pass.arena.as_ref().unwrap().base(), address);
    assert!(session.scope.ready() && session.binding.is_some());
    let read_count = || match &session.object {
        SessionObject::Fixture { reads, .. } => reads.get(),
        _ => unreachable!(),
    };
    let before = read_count();
    for binding in [None, Some(stale)] {
        pass.binding = binding;
        assert!(
            pass.read_run(&session, RunKind::Target, None, deadline, 128)
                .is_err(),
            "an occupied old address authorized an uninstalled or stale pass"
        );
        assert_eq!(before, read_count(), "refusal performed iterator I/O");
    }
    println!("\n{COMPLETED}");
}

#[test]
fn capture_watched_admitted_aliases_never_reserve_an_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let (file, examined) = opened(dir.path(), "watched.so");
    drop(file);
    let pins = super::super::identity::test_fixture::real_scan_pin(
        &dir.path().join("watched.so"),
        None,
        1,
        "watched",
    );
    let id = pins.pinned().next().unwrap().id;
    let target = pins.retain_inventory_target(id).unwrap();
    let exclusions = KernelAnchorExclusions::from_targets([&target, &target]);
    assert_eq!(exclusions.files.len(), 1);
    assert!(Arc::ptr_eq(
        exclusions.files.values().next().unwrap(),
        &target.retirement_lease()
    ));
    let alias = ObjectKey {
        inode: examined.key.inode + 1,
        ..examined.key
    };
    let pass = AnchorPass::prepare_excluding(
        &pins,
        [(examined.key, id), (alias, id)],
        custody(0, BTreeMap::new()),
        &exclusions,
    );
    assert!(
        pass.arena.is_none(),
        "watched aliases created an observer mmap"
    );
    assert!(pass.candidates.is_empty());
    assert!(pass.expected_matches.is_empty());
}

#[test]
fn capture_watched_examined_file_alias_never_reserves_an_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let (file, mut examined) = opened(dir.path(), "watched.so");
    let pins = super::super::identity::test_fixture::real_scan_pin(
        &dir.path().join("watched.so"),
        None,
        1,
        "watched",
    );
    let id = pins.pinned().next().unwrap().id;
    let target = pins.retain_inventory_target(id).unwrap();
    let exclusions = KernelAnchorExclusions::from_targets([&target]);
    // Script only a differently exposed maps key. The actual opened file
    // remains the same retained inode, including when its metadata changes.
    examined.key.inode += 1;
    file.set_len(8192).unwrap();
    assert!(!target.check_unchanged().unwrap());
    let exclusions_after_change = KernelAnchorExclusions::from_targets([&target]);
    for exclusions in [&exclusions, &exclusions_after_change] {
        let mut held = custody(1, BTreeMap::new());
        let scan = held.begin_scan();
        assert!(held.offer_for_test(scan, examined, file.try_clone().unwrap()));
        let pass = AnchorPass::prepare_excluding(&pins, [], held, exclusions);
        assert!(
            pass.arena.is_none(),
            "examined alias mapped a watched inode"
        );
        assert!(pass.candidates.is_empty());
        assert!(pass.expected_examined.is_empty());
    }
}

#[test]
fn capture_watched_key_collision_only_excludes_acceleration() {
    let dir = tempfile::tempdir().unwrap();
    let (watched_file, watched) = opened(dir.path(), "watched.so");
    drop(watched_file);
    let pins = super::super::identity::test_fixture::real_scan_pin(
        &dir.path().join("watched.so"),
        None,
        1,
        "watched",
    );
    let target = pins
        .retain_inventory_target(pins.pinned().next().unwrap().id)
        .unwrap();
    let exclusions = KernelAnchorExclusions::from_targets([&target]);
    let (foreign_file, mut foreign) = opened(dir.path(), "foreign.so");
    assert_ne!(foreign.identity, watched.identity);
    foreign.key = watched.key;
    let (unrelated_file, unrelated) = opened(dir.path(), "unrelated.so");
    let mut held = custody(2, BTreeMap::new());
    let scan = held.begin_scan();
    assert!(held.offer_for_test(scan, foreign, foreign_file));
    assert!(held.offer_for_test(scan, unrelated, unrelated_file));
    let pass = AnchorPass::prepare_excluding(&pins, [], held, &exclusions);
    assert_eq!(pass.candidates.len(), 1);
    assert_eq!(pass.candidates[0].keys, BTreeSet::from([unrelated.key]));
    let mut session = fixture_session();
    let installed = session
        .install_anchors(
            pass,
            1,
            std::time::Instant::now() + std::time::Duration::from_secs(10),
        )
        .unwrap();
    let pass = installed.pass.as_ref().unwrap();
    assert_eq!(
        pass.expected_examined[&unrelated.key],
        BTreeSet::from([Slot(0)])
    );
    assert!(!pass.expected_examined.contains_key(&watched.key));
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
    let pass = AnchorPass::prepare_limits(
        &pins,
        [(admitted.key, id)],
        custody,
        2,
        2,
        &KernelAnchorExclusions::default(),
    );
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
pub(super) struct FdToken {
    raw: i32,
    dev: u64,
    ino: u64,
}
impl FdToken {
    pub(super) fn of(file: &File) -> Self {
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

pub(super) struct ClosedFdEvidence {
    _original: FdToken,
    _path: tempfile::TempPath,
    closed: bool,
}
impl ClosedFdEvidence {
    pub(super) fn capture(original: FdToken, path: tempfile::TempPath) -> Self {
        // The named entry keeps this inode allocated while we check the
        // original descriptor. It retains no additional descriptor.
        let closed = !fd_open(original);
        assert!(closed, "original fixture FD remains open after consumption");
        Self {
            _original: original,
            _path: path,
            closed,
        }
    }

    pub(super) fn was_closed(&self) -> bool {
        // A later descriptor can reuse this number, including another OFD
        // of the same inode. Preserve the physical check made at consumption.
        self.closed
    }
}

#[test]
fn d3c_fd_close_snapshot_survives_rebound_same_inode() {
    const CHILD: &str = "P11SCOPE_D3C_FD_CLOSE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // Isolate dup2 from other tests' descriptor allocation. The child
        // runs this exact cell with one harness thread and owns its FDs.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "discovery::kernel_identity::tests::d3c_fd_close_snapshot_survives_rebound_same_inode",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "FD close child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    use std::io::{Seek as _, SeekFrom};
    use std::os::fd::{FromRawFd as _, OwnedFd};

    let (mut original, path) = tempfile::NamedTempFile::new().unwrap().into_parts();
    let mut independent = File::open(&path).unwrap();
    original.seek(SeekFrom::Start(13)).unwrap();
    independent.seek(SeekFrom::Start(29)).unwrap();
    assert_eq!(original.stream_position().unwrap(), 13);
    assert_eq!(independent.stream_position().unwrap(), 29);
    let token = FdToken::of(&original);
    let other = FdToken::of(&independent);
    assert_ne!(token.raw, other.raw);
    assert_eq!((token.dev, token.ino), (other.dev, other.ino));
    drop(original);
    let closed = ClosedFdEvidence::capture(token, path);
    assert!(closed.was_closed());

    // SAFETY: this single-test child has closed token.raw and owns the
    // independent source FD. dup2 installs a newly owned destination FD.
    let rebound = unsafe { libc::dup2(independent.as_raw_fd(), token.raw) };
    assert_eq!(rebound, token.raw);
    // SAFETY: successful dup2 returned this unique owned destination FD.
    let mut rebound = File::from(unsafe { OwnedFd::from_raw_fd(rebound) });
    assert_eq!(rebound.stream_position().unwrap(), 29);
    assert!(
        fd_open(token),
        "rebind did not reproduce the old oracle match"
    );
    assert!(
        closed.was_closed(),
        "late FD reuse erased the original close observation"
    );
}

#[test]
#[should_panic(expected = "original fixture FD remains open after consumption")]
fn d3c_fd_close_snapshot_rejects_live_original() {
    let (original, path) = tempfile::NamedTempFile::new().unwrap().into_parts();
    ClosedFdEvidence::capture(FdToken::of(&original), path);
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
        let arena_mapping = anchor_mapping(arena_address);
        let events = Rc::new(RefCell::new(Vec::new()));
        let arena_events = events.clone();
        pass.after_arena = Some(DropObserver(Some(Box::new(move || {
            assert!(
                !anchor_mapping_held(&arena_mapping),
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
    let arena_mapping = anchor_mapping(address);
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
    assert!(!anchor_mapping_held(&arena_mapping));
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

// These cells exercise the dormant production adapter, shared charged
// preparation and live finish. Target bytes script a kernel response; the
// fixture's actual held Files and owned run FDs do not prove a live BPF join.
const ADAPTER_PID: u32 = 4100;
const ADAPTER_RANGES: [(u64, u64); 2] = [(0x1000, 0x2000), (0x3000, 0x4000)];

fn target_stream(records: &[(u32, (u64, u64), u32)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for &(pid, (start, end), verdict) in records {
        let mut record = [0u8; 32];
        record[..2].copy_from_slice(&RECORD_MAGIC.to_le_bytes());
        record[2] = RECORD_VERSION;
        record[3] = crate::attach::identity_iter::KIND_VMA;
        record[4..8].copy_from_slice(&pid.to_le_bytes());
        record[8..16].copy_from_slice(&start.to_le_bytes());
        record[16..24].copy_from_slice(&end.to_le_bytes());
        record[24..28].copy_from_slice(&verdict.to_le_bytes());
        record[28..32].copy_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&record);
    }
    bytes.extend_from_slice(&anchor_stream(&[]));
    bytes
}

fn complete_target() -> Vec<u8> {
    target_stream(&ADAPTER_RANGES.map(|range| (ADAPTER_PID, range, 0)))
}

#[derive(Default)]
struct AdapterCell {
    target: Vec<u8>,
    alias: bool,
    distinct_examined_same_key: bool,
    ranges: Option<Vec<(u64, u64)>>,
    page_offset: bool,
    exec_changed: bool,
    pid_changed: bool,
    capture_watched: bool,
    foreign_identity: bool,
}

#[derive(Default)]
struct AdapterTrace {
    opens: usize,
    closes: usize,
    reads: Vec<(u32, u64, u64)>,
    events: Vec<&'static str>,
    pin: Option<FdToken>,
    pin_closed: Option<ClosedFdEvidence>,
}

struct AdapterPin {
    file: Option<(File, tempfile::TempPath)>,
    trace: Rc<RefCell<AdapterTrace>>,
}
impl Drop for AdapterPin {
    fn drop(&mut self) {
        let (file, path) = self
            .file
            .take()
            .expect("fixture pin owns its original File");
        let token = FdToken::of(&file);
        assert!(fd_open(token));
        drop(file);
        let closed = ClosedFdEvidence::capture(token, path);
        let mut trace = self.trace.borrow_mut();
        trace.pin_closed = Some(closed);
        trace.closes += 1;
        trace.events.push("close-pin");
    }
}

struct AdapterIo {
    entries: Vec<p11scope_manifest::maps::MapEntry>,
    identity: FileIdentity,
    trace: Rc<RefCell<AdapterTrace>>,
    exe_reads: Cell<usize>,
    exec_changed: bool,
    pid_changed: bool,
}
impl ConfirmIo for AdapterIo {
    type Pin = AdapterPin;
    fn open(&mut self, pid: u32) -> Result<Self::Pin, String> {
        assert_eq!(pid, ADAPTER_PID);
        let (file, path) = tempfile::NamedTempFile::new().unwrap().into_parts();
        let mut trace = self.trace.borrow_mut();
        trace.opens += 1;
        trace.events.push("pin");
        trace.pin = Some(FdToken::of(&file));
        drop(trace);
        Ok(AdapterPin {
            file: Some((file, path)),
            trace: self.trace.clone(),
        })
    }
    fn mapped_file(&mut self, pid: u32, start: u64, end: u64) -> Result<FileIdentity, String> {
        let mut trace = self.trace.borrow_mut();
        assert!(
            fd_open(trace.pin.unwrap()),
            "fallback lost its original process pin"
        );
        trace.reads.push((pid, start, end));
        trace.events.push("map-files");
        Ok(self.identity)
    }
    fn start_time(&self, pin: &Self::Pin) -> Option<u64> {
        assert!(fd_open(FdToken::of(&pin.file.as_ref().unwrap().0)));
        self.trace.borrow_mut().events.push("start-time");
        Some(42)
    }
    fn still_the_same(&self, pin: &Self::Pin) -> bool {
        assert!(fd_open(FdToken::of(&pin.file.as_ref().unwrap().0)));
        self.trace.borrow_mut().events.push("generation");
        !self.pid_changed
    }
    fn exe(&self, _: u32) -> Option<crate::discovery::caller_registry::ExeIdentity> {
        let reads = self.exe_reads.get();
        self.exe_reads.set(reads + 1);
        self.trace.borrow_mut().events.push(if reads == 0 {
            "exe-before"
        } else {
            "exe-after"
        });
        Some(crate::discovery::caller_registry::ExeIdentity {
            dev: 1,
            ino: if reads > 0 && self.exec_changed { 3 } else { 2 },
            mtime_secs: 0,
            mtime_nanos: 0,
            path: Some("fixture-executable".into()),
        })
    }
    fn maps(
        &mut self,
        _: u32,
        _: &mut crate::discovery::scan::CaptureWorkBudget,
    ) -> Result<Vec<p11scope_manifest::maps::MapEntry>, String> {
        self.trace.borrow_mut().events.push("maps");
        Ok(self.entries.clone())
    }
    fn gone(&self, _: u32) -> bool {
        false
    }
}

struct AdapterChecks(FileIdentity);
impl super::super::sweep_attribution::ObjectChecks for AdapterChecks {
    fn nonunique_inodes(&self, _: PinnedObjectId) -> Result<Option<&'static str>, String> {
        Ok(None)
    }
    fn unchanged(&self, _: PinnedObjectId) -> Result<bool, String> {
        Ok(true)
    }
    fn mapped_identity(
        &self,
        _: PinnedObjectId,
    ) -> Result<super::super::identity::MappedFile, String> {
        Ok(super::super::identity::MappedFile {
            identity: self.0,
            fs_magic: None,
        })
    }
}

struct AdapterObservation {
    out: super::super::sweep_attribution::SweepAttribution,
    trace: Rc<RefCell<AdapterTrace>>,
    target_reads: usize,
    charges: u64,
    fallback_reason: Option<KernelFallbackReason>,
}

fn adapter_cell(cell: AdapterCell) -> AdapterObservation {
    let dir = tempfile::tempdir().unwrap();
    let (file, examined) = opened(dir.path(), "provider.so");
    drop(file);
    let pins = super::super::identity::test_fixture::real_scan_pin(
        &dir.path().join("provider.so"),
        None,
        1,
        "scripted-adapter-fixture",
    );
    let id = pins.pinned().next().unwrap().id;
    let owner = ReservationOwner::for_examined(SegmentPolicy::from_headroom(16, 0, 0), 1);
    let mut custody = ExaminedCustody::new(owner.clone(), BTreeMap::new());
    if cell.alias {
        let file = File::open(dir.path().join("provider.so")).unwrap();
        let scan = custody.begin_scan();
        assert!(custody.offer_for_test(scan, examined, file));
    }
    if cell.distinct_examined_same_key {
        let (file, mut distinct) = opened(dir.path(), "distinct.so");
        assert_ne!(distinct.identity, examined.identity);
        // Script only the mapped-key collision. These remain two independently
        // opened actual Files; this is not a claim of a live kernel collision.
        distinct.key = examined.key;
        let scan = custody.begin_scan();
        assert!(custody.offer_for_test(scan, distinct, file));
    }
    let exclusions = if cell.capture_watched {
        let target = pins.retain_inventory_target(id).unwrap();
        let (file, unrelated) = opened(dir.path(), "unrelated-anchor.so");
        let scan = custody.begin_scan();
        assert!(custody.offer_for_test(scan, unrelated, file));
        KernelAnchorExclusions::from_targets([&target])
    } else {
        KernelAnchorExclusions::default()
    };
    let pass = AnchorPass::prepare_excluding(&pins, [(examined.key, id)], custody, &exclusions);
    let mut session = fixture_session();
    if let SessionObject::Fixture { anchor, target, .. } = &mut session.object {
        *target = cell.target;
        if cell.alias {
            *anchor = anchor_stream(&[(0, ANCHOR_OK, 0), (1, ANCHOR_DUP, 0)]);
        } else if cell.distinct_examined_same_key {
            *anchor = anchor_stream(&[(0, ANCHOR_OK, 0), (1, ANCHOR_OK, 0)]);
        }
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut installed = session.install_anchors(pass, 1, deadline).unwrap();
    if !cell.capture_watched {
        assert!(installed.pass.as_ref().unwrap().expected[&examined.key].contains(&Slot(0)));
    }
    let entries: Vec<_> = cell
        .ranges
        .unwrap_or_else(|| ADAPTER_RANGES.to_vec())
        .into_iter()
        .map(|(start, end)| p11scope_manifest::maps::MapEntry {
            start,
            end,
            permissions: *b"r-xp",
            file_offset: if cell.page_offset { 4096 } else { 0 },
            device: examined.key.device,
            inode: examined.key.inode,
            raw_path: Some(b"/fixture/provider.so".to_vec()),
        })
        .collect();
    let foreign_file = cell
        .foreign_identity
        .then(|| opened(dir.path(), "foreign-mapped.so"));
    let trace = Rc::new(RefCell::new(AdapterTrace::default()));
    let io = AdapterIo {
        entries: entries.clone(),
        identity: foreign_file
            .as_ref()
            .map_or(examined.identity, |(_, foreign)| foreign.identity),
        trace: trace.clone(),
        exe_reads: Cell::new(0),
        exec_changed: cell.exec_changed,
        pid_changed: cell.pid_changed,
    };
    let (mut index, refused) = KnownKeyIndex::build(
        [(examined.key, Some(id))],
        &BTreeMap::from([(examined.key, id)]),
        [],
        &AdapterChecks(examined.identity),
    );
    assert!(refused.is_empty());
    let mut budget = crate::discovery::scan::CaptureWorkBudget::default();
    let mut probe = KernelMemberProbe::new(&mut installed, io, deadline);
    probe.install_expectations(&mut index).unwrap();
    let out = super::super::sweep_attribution::attribute_unselected(
        &[(ADAPTER_PID, entries)],
        &BTreeSet::new(),
        &BTreeSet::new(),
        &index,
        &mut probe,
        &mut budget,
    );
    drop(probe);
    let target_reads = match &installed.session.object {
        SessionObject::Fixture { reads, .. } => reads.get() - 1,
        _ => unreachable!(),
    };
    let charges = budget.work_units_count();
    assert_eq!(owner.state_for_test().0, [0; 4]);
    let trace_state = trace.borrow();
    assert_eq!((trace_state.opens, trace_state.closes), (1, 1));
    assert!(trace_state.pin_closed.as_ref().unwrap().was_closed());
    assert_eq!(&trace_state.events[..3], &["pin", "exe-before", "maps"]);
    drop(trace_state);
    drop(installed);
    let fallback_reason = session.fallback_totals().first_reason;
    AdapterObservation {
        out,
        trace,
        target_reads,
        charges,
        fallback_reason,
    }
}

#[test]
fn capture_watched_anchor_fallback_keeps_same_pin_and_userspace_truth() {
    for exec_changed in [false, true] {
        let observation = adapter_cell(AdapterCell {
            capture_watched: true,
            exec_changed,
            target: complete_target(),
            ..Default::default()
        });
        assert_eq!(
            observation.target_reads, 0,
            "watched request reached a kernel target run"
        );
        assert_eq!(observation.charges, 2);
        assert_eq!(
            observation.trace.borrow().reads,
            ADAPTER_RANGES.map(|(start, end)| (ADAPTER_PID, start, end))
        );
        assert_eq!(observation.out.members.len(), usize::from(!exec_changed));
        assert_eq!(
            observation.fallback_reason,
            Some(KernelFallbackReason::AnchorNotInstalled)
        );
    }
}

#[test]
fn capture_watched_fallback_rejects_foreign_map_files_identity() {
    let observation = adapter_cell(AdapterCell {
        capture_watched: true,
        foreign_identity: true,
        target: complete_target(),
        ..Default::default()
    });
    assert_eq!(observation.target_reads, 0);
    assert_eq!(observation.charges, 2);
    assert_eq!(
        observation.trace.borrow().reads,
        ADAPTER_RANGES.map(|(start, end)| (ADAPTER_PID, start, end))
    );
    assert!(
        observation.out.members.is_empty(),
        "coarse exclusion became an identity proof"
    );
    assert_eq!(
        observation.fallback_reason,
        Some(KernelFallbackReason::AnchorNotInstalled)
    );
}

fn assert_adapter_attempt(observation: &AdapterObservation, fallback: bool) {
    assert_eq!(
        observation.charges, 2,
        "fallback charged the logical ranges again"
    );
    assert_eq!(
        observation.target_reads, 1,
        "actual adapter did not consume its target run"
    );
    let reads = observation.trace.borrow().reads.clone();
    let expected = if fallback {
        ADAPTER_RANGES
            .map(|(start, end)| (ADAPTER_PID, start, end))
            .to_vec()
    } else {
        Vec::new()
    };
    assert_eq!(
        reads, expected,
        "kernel evidence retried or reopened userspace proof"
    );
}

#[derive(Default)]
struct EligibilityVisits {
    count: usize,
    expire_after: Option<usize>,
}

thread_local! {
    static ELIGIBILITY_VISITS: RefCell<Option<EligibilityVisits>> = const { RefCell::new(None) };
}

// Counts actual MapEntry visits in production eligibility preparation. The
// injected expiry uses the existing budget deadline, not a separate fake stop.
pub(super) fn note_eligibility_visit(budget: &mut crate::discovery::scan::CaptureWorkBudget) {
    ELIGIBILITY_VISITS.with(|visits| {
        let mut visits = visits.borrow_mut();
        if let Some(visits) = visits.as_mut() {
            visits.count += 1;
            if visits.expire_after == Some(visits.count) {
                budget.set_deadline(Some(0));
            }
        }
    });
}

fn measured_eligibility(
    cell: AdapterCell,
    expire_after: Option<usize>,
) -> (AdapterObservation, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ELIGIBILITY_VISITS.with(|visits| *visits.borrow_mut() = None);
        }
    }
    ELIGIBILITY_VISITS.with(|visits| {
        assert!(visits.borrow().is_none());
        *visits.borrow_mut() = Some(EligibilityVisits {
            count: 0,
            expire_after,
        });
    });
    let reset = Reset;
    let observation = adapter_cell(cell);
    let count = ELIGIBILITY_VISITS.with(|visits| visits.borrow().as_ref().unwrap().count);
    drop(reset);
    (observation, count)
}

#[test]
fn d3c_matched_key_rejects_distinct_examined_file_under_same_key() {
    let admitted = adapter_cell(AdapterCell {
        target: complete_target(),
        distinct_examined_same_key: true,
        ..Default::default()
    });
    assert_eq!(
        admitted.out.members.len(),
        1,
        "admitted A lost its own anchor"
    );
    assert_adapter_attempt(&admitted, false);
    let distinct = adapter_cell(AdapterCell {
        target: target_stream(&ADAPTER_RANGES.map(|range| (ADAPTER_PID, range, 1))),
        distinct_examined_same_key: true,
        ..Default::default()
    });
    assert!(
        distinct.out.members.is_empty(),
        "examined B's slot was accepted as admitted provider A"
    );
    assert_eq!(
        distinct.out.losses,
        BTreeMap::from([(
            super::super::sweep_attribution::AttributionLoss::IdentityMismatch,
            1
        )])
    );
    assert_adapter_attempt(&distinct, false);
}

#[test]
fn d3c_validated_alias_keeps_admitted_object_positive() {
    let observation = adapter_cell(AdapterCell {
        target: complete_target(),
        alias: true,
        ..Default::default()
    });
    assert_eq!(observation.out.members.len(), 1);
    assert!(observation.out.losses.is_empty());
    assert_adapter_attempt(&observation, false);
}

fn large_adapter_cell() -> AdapterCell {
    let ranges: Vec<_> = (0..2048)
        .map(|n| (0x1000 + n * 0x2000, 0x2000 + n * 0x2000))
        .collect();
    AdapterCell {
        target: target_stream(
            &ranges
                .iter()
                .map(|&range| (ADAPTER_PID, range, 0))
                .collect::<Vec<_>>(),
        ),
        ranges: Some(ranges),
        ..Default::default()
    }
}

#[test]
fn d3c_large_ranges_use_bounded_eligibility_work() {
    let (observation, visits) = measured_eligibility(large_adapter_cell(), None);
    assert_eq!(
        observation.out.members.len(),
        1,
        "large exact-range proof failed"
    );
    assert!(observation.out.losses.is_empty());
    assert_eq!(observation.target_reads, 1);
    assert_eq!(observation.charges, 2048);
    assert!(observation.trace.borrow().reads.is_empty());
    assert!(
        visits <= 4096,
        "eligibility visited {visits} entries for 2048 exact ranges"
    );
}

#[test]
fn d3c_eligibility_honors_injected_deadline_before_unbounded_work() {
    let (observation, visits) = measured_eligibility(large_adapter_cell(), Some(16));
    assert!(observation.out.members.is_empty());
    assert_eq!(observation.target_reads, 0);
    assert!(observation.trace.borrow().reads.is_empty());
    assert_eq!(observation.charges, 2048);
    assert_eq!(
        observation.out.losses,
        BTreeMap::from([(super::super::sweep_attribution::AttributionLoss::Budget, 1)])
    );
    assert!(
        visits <= 64,
        "deadline expired at visit 16 but eligibility continued through {visits} entries"
    );
}

#[test]
fn d3c_complete_slots_and_validated_alias_match_all_ranges() {
    for alias in [false, true] {
        let observation = adapter_cell(AdapterCell {
            target: complete_target(),
            alias,
            ..Default::default()
        });
        assert_eq!(
            observation
                .out
                .members
                .iter()
                .map(|member| member.pid)
                .collect::<Vec<_>>(),
            [ADAPTER_PID]
        );
        assert!(observation.out.losses.is_empty());
        assert_adapter_attempt(&observation, false);
    }
}

#[test]
fn d3c_valid_none_is_negative_without_userspace_retry() {
    let observation = adapter_cell(AdapterCell {
        target: target_stream(&[
            (ADAPTER_PID, ADAPTER_RANGES[0], 0),
            (
                ADAPTER_PID,
                ADAPTER_RANGES[1],
                crate::attach::identity_iter::VERDICT_NONE,
            ),
        ]),
        ..Default::default()
    });
    assert!(
        observation.out.members.is_empty(),
        "NONE became a userspace-positive edge"
    );
    assert_eq!(
        observation.out.losses,
        BTreeMap::from([(
            super::super::sweep_attribution::AttributionLoss::IdentityMismatch,
            1
        )])
    );
    assert_adapter_attempt(&observation, false);
}

#[test]
fn d3c_page_offset_keeps_file_identity_but_join_requires_exact_range() {
    let exact = adapter_cell(AdapterCell {
        target: complete_target(),
        page_offset: true,
        ..Default::default()
    });
    assert_eq!(exact.out.members.len(), 1);
    assert_adapter_attempt(&exact, false);
    let shifted = adapter_cell(AdapterCell {
        target: target_stream(&[
            (ADAPTER_PID, (0x2000, 0x3000), 0),
            (ADAPTER_PID, ADAPTER_RANGES[1], 0),
        ]),
        page_offset: true,
        ..Default::default()
    });
    assert!(
        shifted.out.members.is_empty(),
        "an adjacent range answered the requested range"
    );
    assert_eq!(
        shifted.out.losses,
        BTreeMap::from([(
            super::super::sweep_attribution::AttributionLoss::MappingChanged,
            1
        )])
    );
    assert_adapter_attempt(&shifted, false);
}

#[test]
fn d3c_present_pid_missing_range_is_mapping_changed() {
    let observation = adapter_cell(AdapterCell {
        target: target_stream(&[(ADAPTER_PID, ADAPTER_RANGES[0], 0)]),
        ..Default::default()
    });
    assert!(
        observation.out.members.is_empty(),
        "one proved range admitted an incomplete group"
    );
    assert_eq!(
        observation.out.losses,
        BTreeMap::from([(
            super::super::sweep_attribution::AttributionLoss::MappingChanged,
            1
        )])
    );
    assert_adapter_attempt(&observation, false);
}

#[test]
fn d3c_unvisited_pid_uses_same_prepared_pin_without_recharge() {
    let observation = adapter_cell(AdapterCell {
        target: target_stream(&[]),
        ..Default::default()
    });
    assert_eq!(
        observation.out.members.len(),
        1,
        "unvisited PID silently disappeared"
    );
    assert_adapter_attempt(&observation, true);
}

#[test]
fn d3c_conflicting_duplicate_falls_back_with_same_prepared_pin() {
    let observation = adapter_cell(AdapterCell {
        target: target_stream(&[
            (ADAPTER_PID, ADAPTER_RANGES[0], 0),
            (
                ADAPTER_PID,
                ADAPTER_RANGES[0],
                crate::attach::identity_iter::VERDICT_NONE,
            ),
            (ADAPTER_PID, ADAPTER_RANGES[1], 0),
        ]),
        ..Default::default()
    });
    assert_eq!(observation.out.members.len(), 1);
    assert_adapter_attempt(&observation, true);
}

#[test]
fn d3c_malformed_or_truncated_run_discards_all_partial_verdicts() {
    for kind in 0..3 {
        let mut target = target_stream(&[
            (
                ADAPTER_PID,
                ADAPTER_RANGES[0],
                crate::attach::identity_iter::VERDICT_NONE,
            ),
            (ADAPTER_PID, ADAPTER_RANGES[1], 0),
        ]);
        match kind {
            0 => target[0] = 0,
            1 => {
                target.truncate(target.len() - 32);
            }
            _ => {
                target.pop();
            }
        }
        let observation = adapter_cell(AdapterCell {
            target,
            ..Default::default()
        });
        assert_eq!(
            observation.out.members.len(),
            1,
            "partial negative survived invalid whole run"
        );
        assert_adapter_attempt(&observation, true);
    }
}

#[test]
fn d3c_kernel_verdict_cannot_bypass_final_exec_or_pid_generation_checks() {
    for pid_changed in [false, true] {
        let observation = adapter_cell(AdapterCell {
            target: complete_target(),
            exec_changed: !pid_changed,
            pid_changed,
            ..Default::default()
        });
        assert!(observation.out.members.is_empty());
        let loss = if pid_changed {
            super::super::sweep_attribution::AttributionLoss::GenerationChanged
        } else {
            super::super::sweep_attribution::AttributionLoss::ExecChanged
        };
        assert_eq!(observation.out.losses, BTreeMap::from([(loss, 1)]));
        assert_adapter_attempt(&observation, false);
    }
}

#[test]
fn d3c_successive_pass_same_slot_different_file_clears_old_kernel_authority() {
    for second_has_anchor in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (first, old) = opened(dir.path(), "old-provider.so");
        drop(first);
        let pins = super::super::identity::test_fixture::real_scan_pin(
            &dir.path().join("old-provider.so"),
            None,
            1,
            "old-adapter-fixture",
        );
        let id = pins.pinned().next().unwrap().id;
        let (second, new) = opened(dir.path(), "new-provider.so");
        let (third, missing) = opened(dir.path(), "uninstalled-provider.so");
        assert_ne!(
            old.identity, new.identity,
            "successive slots must name distinct real Files"
        );
        let (mut index, refused) = KnownKeyIndex::build(
            [(old.key, Some(id))],
            &BTreeMap::from([(old.key, id)]),
            [new, missing],
            &AdapterChecks(old.identity),
        );
        assert!(refused.is_empty());
        let mut session = fixture_session();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let pass = AnchorPass::prepare(&pins, [(old.key, id)], custody(0, BTreeMap::new()));
        {
            let mut installed = session.install_anchors(pass, 1, deadline).unwrap();
            let mut probe = KernelMemberProbe::new(
                &mut installed,
                AdapterIo {
                    entries: Vec::new(),
                    identity: old.identity,
                    trace: Rc::new(RefCell::new(AdapterTrace::default())),
                    exe_reads: Cell::new(0),
                    exec_changed: false,
                    pid_changed: false,
                },
                deadline,
            );
            probe.install_expectations(&mut index).unwrap();
            assert_eq!(
                index.kernel_slots_for_test(old.key),
                Some(&BTreeSet::from([Slot(0)]))
            );
        }
        // The same loaded Session gets a distinct pass/generation. Slot zero
        // now belongs to another actual File; partial and no-anchor outcomes
        // must both retire every prior numeric expectation in the reused index.
        let mut held = custody(2, BTreeMap::from([(new.key, 1)]));
        let scan = held.begin_scan();
        assert!(held.offer_for_test(scan, new, second));
        assert!(held.offer_for_test(scan, missing, third));
        let pass = AnchorPass::prepare(&pins, [], held);
        assert!(pass.candidates[0].keys.contains(&new.key));
        if let SessionObject::Fixture {
            anchor,
            target,
            reads,
            ..
        } = &mut session.object
        {
            *anchor = anchor_stream(&[
                (
                    0,
                    if second_has_anchor {
                        ANCHOR_OK
                    } else {
                        crate::attach::identity_iter::ANCHOR_BAD_SHAPE
                    },
                    0,
                ),
                (1, crate::attach::identity_iter::ANCHOR_BAD_SHAPE, 0),
            ]);
            *target = complete_target();
            for record in anchor
                .as_chunks_mut::<32>()
                .0
                .iter_mut()
                .chain(target.as_chunks_mut::<32>().0)
            {
                record[28..32].copy_from_slice(&2u32.to_le_bytes());
            }
            reads.set(0);
        }
        let mut installed = session.install_anchors(pass, 2, deadline).unwrap();
        let entries: Vec<_> = ADAPTER_RANGES
            .into_iter()
            .map(|(start, end)| p11scope_manifest::maps::MapEntry {
                start,
                end,
                file_offset: 0,
                permissions: *b"r-xp",
                device: old.key.device,
                inode: old.key.inode,
                raw_path: Some(b"/fixture/old-provider.so".to_vec()),
            })
            .collect();
        let trace = Rc::new(RefCell::new(AdapterTrace::default()));
        let io = AdapterIo {
            entries: entries.clone(),
            identity: old.identity,
            trace: trace.clone(),
            exe_reads: Cell::new(0),
            exec_changed: false,
            pid_changed: false,
        };
        let mut probe = KernelMemberProbe::new(&mut installed, io, deadline);
        probe.install_expectations(&mut index).unwrap();
        assert!(
            index.kernel_slots_for_test(old.key).is_none(),
            "released pass left independent scalar slot authority"
        );
        assert_eq!(
            index.kernel_slots_for_test(new.key).is_some(),
            second_has_anchor
        );
        let mut budget = crate::discovery::scan::CaptureWorkBudget::default();
        let out = super::super::sweep_attribution::attribute_unselected(
            &[(ADAPTER_PID, entries)],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &index,
            &mut probe,
            &mut budget,
        );
        drop(probe);
        assert_eq!(
            out.members.len(),
            1,
            "unanchored prior key must use ordinary same-pin proof"
        );
        assert_eq!(
            trace.borrow().reads,
            ADAPTER_RANGES.map(|(start, end)| (ADAPTER_PID, start, end))
        );
        assert_eq!(budget.work_units_count(), 2);
        if let SessionObject::Fixture { reads, .. } = &installed.session.object {
            assert_eq!(
                reads.get(),
                1,
                "a new file's same-numbered slot proved an old key"
            );
        }
    }
}

#[derive(Default)]
struct SegmentEvents {
    pins: BTreeMap<u32, FdToken>,
    pin_fds: BTreeMap<u32, i32>,
    opens: Vec<u32>,
    closes: Vec<u32>,
    maps: Vec<u32>,
    fallback: Vec<(u32, u64, u64)>,
    fallback_after_runs: Vec<usize>,
    finishes: Vec<u32>,
}

struct SegmentPin {
    pid: u32,
    file: File,
    events: Arc<std::sync::Mutex<SegmentEvents>>,
}
impl Drop for SegmentPin {
    fn drop(&mut self) {
        let mut events = self.events.lock().unwrap();
        assert!(fd_open(FdToken::of(&self.file)));
        assert!(events.pins.remove(&self.pid).is_some());
        events.closes.push(self.pid);
    }
}

struct SegmentIo<'w> {
    world: &'w BTreeMap<u32, Vec<p11scope_manifest::maps::MapEntry>>,
    identities: &'w BTreeMap<ObjectKey, FileIdentity>,
    events: Arc<std::sync::Mutex<SegmentEvents>>,
    runs: Arc<std::sync::Mutex<FixtureRunTrace>>,
    owner: ReservationOwner,
    exe_reads: Cell<usize>,
    /// Immediate-envelope occupancy already held when this handle was made
    /// (a resource test's deliberate occupant). Fallback must add none.
    imm_base: usize,
}
impl ConfirmIo for SegmentIo<'_> {
    type Pin = SegmentPin;
    fn open(&mut self, pid: u32) -> Result<Self::Pin, String> {
        // This is an actual owned self-pidfd, while the target PID/maps are
        // scripted. The test proves custody/order, not a live target identity.
        let file =
            File::from(crate::attach::identity_iter::open_pidfd(std::process::id()).unwrap());
        let mut events = self.events.lock().unwrap();
        assert!(events.pins.insert(pid, FdToken::of(&file)).is_none());
        events.pin_fds.insert(pid, file.as_raw_fd());
        events.opens.push(pid);
        Ok(SegmentPin {
            pid,
            file,
            events: self.events.clone(),
        })
    }
    fn borrowed_pidfd<'a>(&self, pin: &'a Self::Pin) -> Option<std::os::fd::BorrowedFd<'a>> {
        Some(pin.file.as_fd())
    }
    fn mapped_file(&mut self, pid: u32, start: u64, end: u64) -> Result<FileIdentity, String> {
        let runs = self.runs.lock().unwrap();
        assert!(
            runs.all_concrete_runs_closed(),
            "userspace worker started before an iterator/link closed"
        );
        assert_eq!(
            self.owner.state_for_test().0[3],
            self.imm_base,
            "iterator envelope remained leased during fallback"
        );
        let mut events = self.events.lock().unwrap();
        assert!(
            fd_open(events.pins[&pid]),
            "fallback lost its original prepared pin"
        );
        events.fallback.push((pid, start, end));
        events.fallback_after_runs.push(runs.scopes.len());
        let entry = self.world[&pid]
            .iter()
            .find(|entry| (entry.start, entry.end) == (start, end))
            .unwrap();
        Ok(self.identities[&ObjectKey::of(entry)])
    }
    fn start_time(&self, pin: &Self::Pin) -> Option<u64> {
        assert!(fd_open(FdToken::of(&pin.file)));
        Some(u64::from(pin.pid))
    }
    fn still_the_same(&self, pin: &Self::Pin) -> bool {
        fd_open(FdToken::of(&pin.file))
    }
    fn exe(&self, pid: u32) -> Option<crate::discovery::caller_registry::ExeIdentity> {
        if self.exe_reads.get() > 0 {
            self.events.lock().unwrap().finishes.push(pid);
        }
        self.exe_reads.set(self.exe_reads.get() + 1);
        Some(crate::discovery::caller_registry::ExeIdentity {
            dev: 1,
            ino: u64::from(pid),
            mtime_secs: 0,
            mtime_nanos: 0,
            path: None,
        })
    }
    fn maps(
        &mut self,
        pid: u32,
        budget: &mut crate::discovery::scan::CaptureWorkBudget,
    ) -> Result<Vec<p11scope_manifest::maps::MapEntry>, String> {
        let file =
            <Self as super::super::confirm_shards::ShardableIo>::open_maps(self, pid).unwrap();
        crate::discovery::scan::read_maps_or_refuse(file, budget, crate::attach::monotonic_ns)
    }
    fn gone(&self, _: u32) -> bool {
        false
    }
}
impl super::super::confirm_shards::ShardableIo for SegmentIo<'_> {
    type Maps = std::io::Cursor<Vec<u8>>;
    fn open_maps(&mut self, pid: u32) -> std::io::Result<Self::Maps> {
        self.events.lock().unwrap().maps.push(pid);
        let text: String = self.world[&pid]
            .iter()
            .map(|entry| {
                format!(
                    "{:x}-{:x} r-xp 00000000 {:02x}:{:02x} {} /fixture/provider.so\n",
                    entry.start, entry.end, entry.device.major, entry.device.minor, entry.inode
                )
            })
            .collect();
        Ok(std::io::Cursor::new(text.into_bytes()))
    }
    fn maps_now(&self) -> Option<u64> {
        crate::attach::monotonic_ns()
    }
}

#[test]
#[should_panic(expected = "userspace worker started before an iterator/link closed")]
fn d3c_fallback_rejects_unclosed_concrete_run() {
    let (iterator, _iterator_path) = tempfile::NamedTempFile::new().unwrap().into_parts();
    let (link, _link_path) = tempfile::NamedTempFile::new().unwrap().into_parts();
    assert!(fd_open(FdToken::of(&iterator)));
    assert!(fd_open(FdToken::of(&link)));
    let world = BTreeMap::new();
    let identities = BTreeMap::new();
    let mut io = SegmentIo {
        world: &world,
        identities: &identities,
        events: Arc::new(std::sync::Mutex::new(SegmentEvents::default())),
        runs: Arc::new(std::sync::Mutex::new(FixtureRunTrace {
            concrete_runs: 1,
            ..Default::default()
        })),
        owner: ReservationOwner::for_examined(SegmentPolicy::from_headroom(16, 0, 0), 0),
        exe_reads: Cell::new(0),
        imm_base: 0,
    };
    io.mapped_file(1, 0x1000, 0x2000).unwrap();
}

fn segment_range(key_number: usize) -> (u64, u64) {
    let start = 0x1000 + key_number as u64 * 0x2000;
    (start, start + 0x1000)
}
fn segment_target(pids: &[u32], verdict: u32) -> Vec<u8> {
    target_stream(
        &pids
            .iter()
            .map(|&pid| (pid, segment_range(0), verdict))
            .collect::<Vec<_>>(),
    )
}

struct SegmentObservation {
    out: super::super::sweep_attribution::SweepAttribution,
    events: Arc<std::sync::Mutex<SegmentEvents>>,
    runs: Arc<std::sync::Mutex<FixtureRunTrace>>,
    charges: u64,
    remaining_steps: usize,
    attempts: u32,
    failed_target: Option<RunFailure>,
    fallback: KernelFallbackTotals,
}

fn segment_cell(
    pids: &[(u32, Vec<usize>)],
    headroom: usize,
    steps: Vec<FixtureTarget>,
) -> SegmentObservation {
    segment_cell_with_deadline(pids, headroom, steps, None, None)
}

struct ExpireAfterPositive<'h, H> {
    hook: &'h mut H,
    calls: usize,
    expire_on: Option<usize>,
}
impl<H: SegmentProof> SegmentProof for ExpireAfterPositive<'_, H> {
    fn prove<'r>(
        &'r mut self,
        batch: &AcceptedBatch<'_>,
        budget: &mut crate::discovery::scan::CaptureWorkBudget,
        resources: &IoResources,
    ) -> ProofDecision<'r> {
        self.calls += 1;
        let expire = self.expire_on == Some(self.calls);
        let decision = self.hook.prove(batch, budget, resources);
        if expire {
            let answer = decision
                .answer(batch, 0)
                .expect("deadline injection lacked a genuine kernel answer");
            assert!(!answer.is_empty());
            assert!(answer.values().all(|proof| matches!(
                proof,
                super::super::sweep_attribution::RangeProof::Kernel(Slot(0))
            )));
            budget.set_deadline(Some(0));
        }
        decision
    }
}

fn segment_cell_with_deadline(
    pids: &[(u32, Vec<usize>)],
    headroom: usize,
    steps: Vec<FixtureTarget>,
    expire_on: Option<usize>,
    threshold: Option<usize>,
) -> SegmentObservation {
    let dir = tempfile::tempdir().unwrap();
    let (file, provider) = opened(dir.path(), "provider.so");
    drop(file);
    let pins = super::super::identity::test_fixture::real_scan_pin(
        &dir.path().join("provider.so"),
        None,
        1,
        "segment-custody-fixture",
    );
    let id = pins.pinned().next().unwrap().id;
    let (held, examined) = opened(dir.path(), "examined.so");
    let held_fd = FdToken::of(&held);
    let (missing_file, missing) = opened(dir.path(), "not-held.so");
    drop(missing_file);
    let facts = [provider, examined, missing];
    let world: BTreeMap<_, Vec<_>> = pids
        .iter()
        .map(|(pid, keys)| {
            (
                *pid,
                keys.iter()
                    .map(|&number| {
                        let (start, end) = segment_range(number);
                        p11scope_manifest::maps::MapEntry {
                            start,
                            end,
                            permissions: *b"r-xp",
                            file_offset: 0,
                            device: facts[number].key.device,
                            inode: facts[number].key.inode,
                            raw_path: Some(b"/fixture/provider.so".to_vec()),
                        }
                    })
                    .collect(),
            )
        })
        .collect();
    let identities = facts
        .into_iter()
        .map(|fact| (fact.key, fact.identity))
        .collect();
    let sweep: Vec<_> = world
        .iter()
        .map(|(&pid, entries)| (pid, entries.clone()))
        .collect();
    let policy = SegmentPolicy::from_headroom(headroom, 2, pids.len());
    let owner = ReservationOwner::for_examined(SegmentPolicy::from_headroom(16, 0, 0), 1);
    let mut custody = ExaminedCustody::new(owner.clone(), BTreeMap::new());
    let scan = custody.begin_scan();
    assert!(custody.offer_for_test(scan, examined, held));
    let mut session = fixture_session();
    let runs = if let SessionObject::Fixture {
        anchor,
        target_steps,
        target_trace,
        ..
    } = &mut session.object
    {
        *anchor = anchor_stream(&[(0, ANCHOR_OK, 0), (1, ANCHOR_OK, 0)]);
        *target_steps.borrow_mut() = steps.into();
        target_trace.clone()
    } else {
        unreachable!()
    };
    // The deterministic second census counts existing custody/session files
    // already; the original owner supplies the driver's new reservations.
    custody.reconcile(policy).unwrap();
    let pass = AnchorPass::prepare(&pins, [(provider.key, id)], custody);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut installed = session.install_anchors(pass, 1, deadline).unwrap();
    let (mut index, refused) = KnownKeyIndex::build(
        [(provider.key, Some(id))],
        &BTreeMap::from([(provider.key, id)]),
        [examined, missing],
        &AdapterChecks(provider.identity),
    );
    assert!(refused.is_empty());
    let events = Arc::new(std::sync::Mutex::new(SegmentEvents::default()));
    let make_io = || SegmentIo {
        world: &world,
        identities: &identities,
        events: events.clone(),
        runs: runs.clone(),
        owner: owner.clone(),
        exe_reads: Cell::new(0),
        imm_base: owner.state_for_test().0[3],
    };
    let mut probe = KernelMemberProbe::new(&mut installed, make_io(), deadline);
    if let Some(threshold) = threshold {
        probe = probe.with_auto_threshold(threshold);
    }
    probe.install_expectations(&mut index).unwrap();
    let mut budget = crate::discovery::scan::CaptureWorkBudget::default();
    let mut hook = ExpireAfterPositive {
        hook: probe.segment_proof(),
        calls: 0,
        expire_on,
    };
    let out = super::super::confirm_shards::attribute_unselected_with_segment_proof(
        &sweep,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &index,
        &mut budget,
        policy,
        &owner,
        2,
        &make_io,
        &mut hook,
    );
    drop(probe);
    assert!(fd_open(held_fd));
    assert_eq!(owner.state_for_test().0, [0; 4]);
    let state = events.lock().unwrap();
    assert!(state.pins.is_empty());
    for (pid, _) in pids {
        assert_eq!(
            state.opens.iter().filter(|&&opened| opened == *pid).count(),
            1
        );
        assert_eq!(
            state
                .closes
                .iter()
                .filter(|&&closed| closed == *pid)
                .count(),
            1
        );
        assert_eq!(
            state.maps.iter().filter(|&&mapped| mapped == *pid).count(),
            1
        );
    }
    drop(state);
    let charges = budget.work_units_count();
    let remaining_steps = match &installed.session.object {
        SessionObject::Fixture { target_steps, .. } => target_steps.borrow().len(),
        _ => unreachable!(),
    };
    let attempts = installed.target_attempts;
    let failed_target = installed.failed_target;
    drop(installed);
    assert!(!fd_open(held_fd));
    assert_eq!(owner.examined_for_test().0, 0);
    // The guard drop rolls the pass into the session ledger, so the totals
    // below include this cell's complete pass.
    let fallback = session.fallback.totals();
    SegmentObservation {
        out,
        events,
        runs,
        charges,
        remaining_steps,
        attempts,
        failed_target,
        fallback,
    }
}

#[test]
fn d3c_segments_keep_finished_prefix_and_fallback_inside_original_pins() {
    for failure in 0..3 {
        let bad = match failure {
            0 => {
                let mut bytes = segment_target(&[5101], 0);
                bytes[0] = 0;
                FixtureTarget::Bytes(bytes)
            }
            1 => FixtureTarget::Deadline(segment_target(&[5101], 0)),
            _ => FixtureTarget::Failure(RunFailure::AttachOrRead),
        };
        let observation = segment_cell(
            &[(5100, vec![0]), (5101, vec![0]), (5102, vec![0])],
            6,
            vec![
                FixtureTarget::Bytes(segment_target(&[5100], 0)),
                bad,
                FixtureTarget::Bytes(segment_target(
                    &[5102],
                    crate::attach::identity_iter::VERDICT_NONE,
                )),
            ],
        );
        assert_eq!(
            observation
                .out
                .members
                .iter()
                .map(|member| member.pid)
                .collect::<Vec<_>>(),
            [5100, 5101, 5102]
        );
        assert!(observation.out.losses.is_empty());
        assert_eq!(
            observation.charges, 3,
            "logical ranges were recharged across fallback"
        );
        assert_eq!(
            observation.runs.lock().unwrap().scopes.len(),
            2,
            "accepted driver did not use kernel segments or retried after failure"
        );
        assert_eq!(
            observation.remaining_steps, 1,
            "rest-pass demotion consumed the third-run NONE sentinel"
        );
        assert_eq!(
            observation.events.lock().unwrap().fallback,
            [
                (5101, segment_range(0).0, segment_range(0).1),
                (5102, segment_range(0).0, segment_range(0).1),
            ],
            "a completed earlier PID was reread or current same-pin fallback was lost"
        );
    }
}

#[test]
fn d3c_segments_replace_scope_between_accepted_batches() {
    let observation = segment_cell(
        &[(6100, vec![0]), (6200, vec![0]), (8000, vec![0])],
        7,
        vec![
            FixtureTarget::Bytes(segment_target(&[6100, 6200], 0)),
            FixtureTarget::Bytes(segment_target(&[8000], 0)),
        ],
    );
    assert_eq!(observation.out.members.len(), 3);
    assert_eq!(observation.charges, 3);
    assert_eq!(
        observation.runs.lock().unwrap().scopes,
        [BTreeSet::from([6100, 6200]), BTreeSet::from([8000])],
        "scope retained prior target/observer bitmap bits"
    );
    assert!(observation.events.lock().unwrap().fallback.is_empty());
}

#[test]
fn d3c_segments_mixed_missing_anchor_keeps_none_and_positive() {
    let observation = segment_cell(
        &[(7100, vec![0, 2]), (7101, vec![0]), (7102, vec![0])],
        16,
        vec![FixtureTarget::Bytes(target_stream(&[
            (
                7101,
                segment_range(0),
                crate::attach::identity_iter::VERDICT_NONE,
            ),
            (7102, segment_range(0), 0),
        ]))],
    );
    assert_eq!(
        observation
            .out
            .members
            .iter()
            .map(|member| member.pid)
            .collect::<Vec<_>>(),
        [7100, 7102],
        "a valid kernel NONE was retried into a userspace positive"
    );
    assert_eq!(
        observation.out.losses,
        BTreeMap::from([(
            super::super::sweep_attribution::AttributionLoss::IdentityMismatch,
            1
        )])
    );
    assert_eq!(
        observation.runs.lock().unwrap().scopes,
        [BTreeSet::from([7101, 7102])]
    );
    assert_eq!(observation.charges, 4);
    assert_eq!(
        observation.events.lock().unwrap().fallback,
        [
            (7100, segment_range(0).0, segment_range(0).1),
            (7100, segment_range(2).0, segment_range(2).1),
        ]
    );
}

#[test]
fn d3c_segments_iterator_fds_close_before_fallback_workers() {
    let mut invalid = segment_target(&[8100, 8101], 0);
    invalid[0] = 0;
    let observation = segment_cell(
        &[(8100, vec![0]), (8101, vec![0])],
        16,
        vec![FixtureTarget::Bytes(invalid)],
    );
    assert_eq!(observation.out.members.len(), 2);
    assert_eq!(observation.charges, 2);
    let trace = observation.runs.lock().unwrap();
    assert_eq!(
        trace.closed.len(),
        1,
        "no concrete iterator/link was consumed before fallback"
    );
    assert!(trace.all_concrete_runs_closed());
    assert_eq!(
        observation.events.lock().unwrap().fallback_after_runs,
        [1, 1]
    );
}

#[test]
fn d3c_segments_postproof_capture_deadline_discards_current_positive() {
    let observation = segment_cell_with_deadline(
        &[(9100, vec![0]), (9101, vec![0])],
        6,
        vec![
            FixtureTarget::Bytes(segment_target(&[9100], 0)),
            FixtureTarget::Bytes(segment_target(&[9101], 0)),
        ],
        Some(2),
        None,
    );
    assert_eq!(
        observation.runs.lock().unwrap().scopes,
        [BTreeSet::from([9100]), BTreeSet::from([9101])]
    );
    assert_eq!(
        observation.charges, 2,
        "deadline changed already committed logical charges"
    );
    assert_eq!(
        observation
            .out
            .members
            .iter()
            .map(|member| member.pid)
            .collect::<Vec<_>>(),
        [9100],
        "a stopped current segment published its not-yet-finished positive"
    );
    assert_eq!(
        observation.out.losses,
        BTreeMap::from([(super::super::sweep_attribution::AttributionLoss::Budget, 1)])
    );
    let events = observation.events.lock().unwrap();
    assert_eq!(
        events.finishes,
        [9100],
        "current segment ran final live checks after its observed stop"
    );
    assert!(
        events.fallback.is_empty(),
        "a stopped current segment started fallback I/O"
    );
}

fn ledger_key(inode: u64) -> ObjectKey {
    ObjectKey {
        device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
        inode,
    }
}

#[test]
fn d3c_fallback_counts_distinct_passes_pids_keys() {
    let (key_a, key_b) = (ledger_key(11), ledger_key(12));
    let mut ledger = KernelFallbackLedger::default();
    ledger.begin_pass();
    ledger.note_fallback(100, [key_a, key_b], KernelFallbackReason::StreamInvalid);
    ledger.note_fallback(100, [key_a], KernelFallbackReason::Deadline);
    ledger.note_fallback(101, [key_b], KernelFallbackReason::Deadline);
    ledger.end_pass();
    assert_eq!(
        ledger.totals(),
        KernelFallbackTotals {
            passes: 1,
            pids: 2,
            keys: 2,
            first_reason: Some(KernelFallbackReason::StreamInvalid),
        }
    );
    // A pass with no fallback requests adds zero at every unit.
    ledger.begin_pass();
    ledger.end_pass();
    assert_eq!(ledger.totals().passes, 1);
    assert_eq!((ledger.totals().pids, ledger.totals().keys), (2, 2));
    // A later pass sums its own distinct units and keeps the first reason.
    ledger.begin_pass();
    ledger.note_fallback(100, [key_a], KernelFallbackReason::BelowThreshold);
    ledger.end_pass();
    assert_eq!(
        ledger.totals(),
        KernelFallbackTotals {
            passes: 2,
            pids: 3,
            keys: 3,
            first_reason: Some(KernelFallbackReason::StreamInvalid),
        }
    );

    // Integration: a positive first segment is retained while the second
    // segment's actual affected requests count once at their own units.
    let mut bad = segment_target(&[5702], 0);
    bad[0] = 0;
    let observation = segment_cell(
        &[(5701, vec![0]), (5702, vec![0])],
        6,
        vec![
            FixtureTarget::Bytes(segment_target(&[5701], 0)),
            FixtureTarget::Bytes(bad),
        ],
    );
    assert_eq!(
        observation
            .out
            .members
            .iter()
            .map(|member| member.pid)
            .collect::<Vec<_>>(),
        [5701, 5702]
    );
    assert_eq!(observation.charges, 2);
    assert_eq!(
        observation.events.lock().unwrap().fallback,
        [(5702, segment_range(0).0, segment_range(0).1)],
        "the finished positive was reread or the fallback was lost"
    );
    assert_eq!(
        observation.fallback,
        KernelFallbackTotals {
            passes: 1,
            pids: 1,
            keys: 1,
            first_reason: Some(KernelFallbackReason::StreamInvalid),
        }
    );
}

#[test]
fn d3c_proof_selection_threshold_and_labels() {
    assert_eq!(AUTO_KERNEL_PROOF_PID_THRESHOLD, 2_400);
    assert!(matches!(
        select_proof_run(2_400, Some(AUTO_KERNEL_PROOF_PID_THRESHOLD)),
        SegmentSelection::Kernel
    ));
    assert!(matches!(
        select_proof_run(2_399, Some(AUTO_KERNEL_PROOF_PID_THRESHOLD)),
        SegmentSelection::Userspace(KernelFallbackReason::BelowThreshold)
    ));
    // Forced kernel bypasses the cost threshold only; resources and run caps
    // are still enforced where the run is attempted.
    assert!(matches!(
        select_proof_run(1, None),
        SegmentSelection::Kernel
    ));
    for (reason, label, detail) in [
        (
            KernelFallbackReason::BelowThreshold,
            "below_threshold",
            None,
        ),
        (KernelFallbackReason::FdHeadroom, "fd_headroom", None),
        (
            KernelFallbackReason::TargetLimit,
            "fd_headroom",
            Some("target_run_limit"),
        ),
        (
            KernelFallbackReason::AnchorNotInstalled,
            "anchor_not_installed",
            None,
        ),
        (KernelFallbackReason::Scope, "scope_unavailable", None),
        (KernelFallbackReason::Deadline, "deadline", None),
        (KernelFallbackReason::Clock, "clock_unavailable", None),
        (KernelFallbackReason::StreamInvalid, "stream_invalid", None),
        (
            KernelFallbackReason::TargetUnavailable,
            "target_unavailable",
            None,
        ),
        (KernelFallbackReason::Unvisited, "unvisited", None),
        (
            KernelFallbackReason::ConflictingDuplicate,
            "conflicting_duplicate",
            None,
        ),
    ] {
        assert_eq!(reason.label(), label);
        assert_eq!(reason.detail(), detail);
    }
}

fn set_stream_gen(bytes: &mut [u8], generation: u64) {
    for record in bytes.as_chunks_mut::<32>().0 {
        record[28..32].copy_from_slice(&(generation as u32).to_le_bytes());
    }
}

fn gen_target(generation: u64, records: &[(u32, (u64, u64), u32)]) -> Vec<u8> {
    let mut bytes = target_stream(records);
    set_stream_gen(&mut bytes, generation);
    bytes
}

/// A reusable provider/examined world for multi-pass session cells. Each
/// pass opens its own examined hold; pins stay borrowed across passes.
struct D3cWorld {
    dir: tempfile::TempDir,
    pins: PinnedObjects,
    provider_id: PinnedObjectId,
    provider: ExaminedObject,
    examined: ExaminedObject,
}

fn d3c_world() -> D3cWorld {
    let dir = tempfile::tempdir().unwrap();
    let (file, provider) = opened(dir.path(), "provider.so");
    drop(file);
    let pins = super::super::identity::test_fixture::real_scan_pin(
        &dir.path().join("provider.so"),
        None,
        1,
        "d3c-world-fixture",
    );
    let provider_id = pins.pinned().next().unwrap().id;
    let (held, examined) = opened(dir.path(), "examined.so");
    drop(held);
    D3cWorld {
        dir,
        pins,
        provider_id,
        provider,
        examined,
    }
}

fn d3c_policy(headroom: usize, candidates: usize) -> SegmentPolicy {
    SegmentPolicy::from_headroom(headroom, 2, candidates)
}

struct D3cPass {
    owner: ReservationOwner,
    runs: Arc<std::sync::Mutex<FixtureRunTrace>>,
}

/// Install one pass on a shared session: per-pass custody, owner and anchor
/// bytes at `generation`, with scripted target steps for this pass only.
#[allow(clippy::too_many_arguments)]
fn d3c_install<'s, 'p>(
    world: &'p D3cWorld,
    session: &'s mut IdentitySession,
    generation: u64,
    headroom: usize,
    candidates: usize,
    anchor: &[(u32, u32, u64)],
    mut steps: Vec<FixtureTarget>,
    deadline: std::time::Instant,
) -> (InstalledAnchorPass<'s, 'p>, D3cPass) {
    for step in &mut steps {
        match step {
            FixtureTarget::Bytes(bytes) | FixtureTarget::Deadline(bytes) => {
                set_stream_gen(bytes, generation);
            }
            FixtureTarget::Failure(_) => {}
        }
    }
    let mut anchor_bytes = anchor_stream(anchor);
    set_stream_gen(&mut anchor_bytes, generation);
    let runs = if let SessionObject::Fixture {
        anchor,
        target_steps,
        target_trace,
        ..
    } = &mut session.object
    {
        *anchor = anchor_bytes;
        *target_steps.borrow_mut() = steps.into();
        target_trace.clone()
    } else {
        unreachable!()
    };
    let owner = ReservationOwner::for_examined(SegmentPolicy::from_headroom(16, 0, 0), 1);
    let mut custody = ExaminedCustody::new(owner.clone(), BTreeMap::new());
    let scan = custody.begin_scan();
    let held = File::open(world.dir.path().join("examined.so")).unwrap();
    assert!(custody.offer_for_test(scan, world.examined, held));
    custody.reconcile(d3c_policy(headroom, candidates)).unwrap();
    let pass = AnchorPass::prepare(
        &world.pins,
        [(world.provider.key, world.provider_id)],
        custody,
    );
    let installed = session.install_anchors(pass, generation, deadline).unwrap();
    (installed, D3cPass { owner, runs })
}

fn d3c_world_map(
    world: &D3cWorld,
    pids: &[(u32, Vec<usize>)],
) -> (
    BTreeMap<u32, Vec<p11scope_manifest::maps::MapEntry>>,
    BTreeMap<ObjectKey, super::super::identity::FileIdentity>,
) {
    let facts = [world.provider, world.examined];
    let entries = |number: usize| {
        let (start, end) = segment_range(number);
        p11scope_manifest::maps::MapEntry {
            start,
            end,
            permissions: *b"r-xp",
            file_offset: 0,
            device: facts[number].key.device,
            inode: facts[number].key.inode,
            raw_path: Some(b"/fixture/provider.so".to_vec()),
        }
    };
    let world_map = pids
        .iter()
        .map(|(pid, keys)| (*pid, keys.iter().map(|&number| entries(number)).collect()))
        .collect();
    let identities = facts
        .into_iter()
        .map(|fact| (fact.key, fact.identity))
        .collect();
    (world_map, identities)
}

fn d3c_index(
    world: &D3cWorld,
) -> (
    KnownKeyIndex,
    Vec<super::super::sweep_attribution::RefusedObject>,
) {
    KnownKeyIndex::build(
        [(world.provider.key, Some(world.provider_id))],
        &BTreeMap::from([(world.provider.key, world.provider_id)]),
        [world.examined],
        &AdapterChecks(world.provider.identity),
    )
}

thread_local! {
    static POST_PARSE_EXPIRE: Cell<bool> = const { Cell::new(false) };
}

/// Arm one deterministic cooperative-deadline crossing right after the next
/// successful target parse. The capture budget stays live, so the discard
/// must fall back inside the original pins rather than stop the segment.
pub(super) fn arm_post_parse_expiry() {
    POST_PARSE_EXPIRE.set(true);
}

pub(super) fn maybe_cross_work_deadline(work: &mut TargetWorkDeadline) {
    if POST_PARSE_EXPIRE.take() {
        work.deadline = std::time::Instant::now() - std::time::Duration::from_millis(1);
    }
}

thread_local! {
    static PRE_MEMBER_CHECK_EXPIRE: Cell<bool> = const { Cell::new(false) };
}

/// Arm one deterministic cooperative-deadline crossing just before the
/// post-write member `work.check`. The install-time and eligibility
/// checks already passed, so only that site observes the crossing.
pub(super) fn arm_pre_member_check_expiry() {
    PRE_MEMBER_CHECK_EXPIRE.set(true);
}

pub(super) fn maybe_expire_pre_member_check(work: &mut TargetWorkDeadline) {
    if PRE_MEMBER_CHECK_EXPIRE.take() {
        work.deadline = std::time::Instant::now() - std::time::Duration::from_millis(1);
    }
}

/// One direct promotion packet: shared charged preparation on the original
/// pin, then the kernel hook, then live finish. The hook is the installed
/// probe's; the packet I/O is a fresh handle on the shared world/events.
#[allow(clippy::too_many_arguments)]
fn d3c_packet_with(
    hook: &mut impl SegmentProof,
    world_map: &BTreeMap<u32, Vec<p11scope_manifest::maps::MapEntry>>,
    identities: &BTreeMap<ObjectKey, super::super::identity::FileIdentity>,
    events: &Arc<std::sync::Mutex<SegmentEvents>>,
    runs: &Arc<std::sync::Mutex<FixtureRunTrace>>,
    owner: &ReservationOwner,
    resources: &IoResources,
    prove_set: &BTreeSet<ObjectKey>,
    pid: u32,
    budget: &mut CaptureWorkBudget,
) -> Confirmation {
    let mut segio = SegmentIo {
        world: world_map,
        identities,
        events: events.clone(),
        runs: runs.clone(),
        owner: owner.clone(),
        exe_reads: Cell::new(0),
        imm_base: owner.state_for_test().0[3],
    };
    let prepared = super::super::sweep_attribution::prepare_confirmation(
        &mut segio,
        pid,
        prove_set,
        budget,
        Some(resources),
    )
    .unwrap();
    super::super::confirm_shards::prove_and_finish_prepared(
        &mut segio, pid, prepared, hook, resources, budget,
    )
}

#[allow(clippy::too_many_arguments)]
fn d3c_packet(
    hook: &mut impl SegmentProof,
    world_map: &BTreeMap<u32, Vec<p11scope_manifest::maps::MapEntry>>,
    identities: &BTreeMap<ObjectKey, super::super::identity::FileIdentity>,
    events: &Arc<std::sync::Mutex<SegmentEvents>>,
    runs: &Arc<std::sync::Mutex<FixtureRunTrace>>,
    owner: &ReservationOwner,
    prove_set: &BTreeSet<ObjectKey>,
    pid: u32,
    budget: &mut CaptureWorkBudget,
) -> Confirmation {
    let resources = owner.batch();
    d3c_packet_with(
        hook, world_map, identities, events, runs, owner, &resources, prove_set, pid, budget,
    )
}

fn confirmed_mapped(confirmation: &Confirmation) -> &MappedIdentities {
    match confirmation {
        Confirmation::Confirmed(read) => &read.mapped,
        other => panic!("expected a confirmed read, got {other:?}"),
    }
}

fn assert_kernel_slot(confirmation: &Confirmation, slot: Slot) {
    let mapped = confirmed_mapped(confirmation);
    assert!(!mapped.is_empty(), "kernel proof answered no range");
    assert!(
        mapped
            .values()
            .all(|proof| *proof == super::super::sweep_attribution::RangeProof::Kernel(slot)),
        "a promotion packet did not prove every range by kernel: {mapped:?}"
    );
}

fn assert_userspace_mapped(confirmation: &Confirmation) {
    let mapped = confirmed_mapped(confirmation);
    assert!(!mapped.is_empty(), "fallback answered no range");
    assert!(
        mapped.values().all(|proof| matches!(
            proof,
            super::super::sweep_attribution::RangeProof::MapFiles(_)
        )),
        "fallback reused kernel evidence: {mapped:?}"
    );
}

#[test]
fn d3c_three_target_attempts_include_phase_d() {
    // Mixed shapes on one guard: two whole-system segments, then two
    // per-PID promotion packets. The fourth request falls back inside its
    // original pin; the cap reason is the run-limit detail.
    let world = d3c_world();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut session = fixture_session();
    let (world_map, identities) = d3c_world_map(
        &world,
        &[
            (5100, vec![0]),
            (5101, vec![0]),
            (5102, vec![0]),
            (5103, vec![0]),
        ],
    );
    let events = Arc::new(std::sync::Mutex::new(SegmentEvents::default()));
    let (mut installed, pass) = d3c_install(
        &world,
        &mut session,
        1,
        6,
        4,
        &[(0, ANCHOR_OK, 0), (1, ANCHOR_OK, 0)],
        vec![
            FixtureTarget::Bytes(gen_target(1, &[(5100, segment_range(0), 0)])),
            FixtureTarget::Bytes(gen_target(1, &[(5101, segment_range(0), 0)])),
            FixtureTarget::Bytes(gen_target(1, &[(5102, segment_range(0), 0)])),
        ],
        deadline,
    );
    let (mut index, refused) = d3c_index(&world);
    assert!(refused.is_empty());
    let prove_set = index.map_files_keys();
    let make_seg = || SegmentIo {
        world: &world_map,
        identities: &identities,
        events: events.clone(),
        runs: pass.runs.clone(),
        owner: pass.owner.clone(),
        exe_reads: Cell::new(0),
        imm_base: pass.owner.state_for_test().0[3],
    };
    let mut budget = CaptureWorkBudget::default();
    let mut probe = KernelMemberProbe::new(&mut installed, make_seg(), deadline);
    probe.install_expectations(&mut index).unwrap();
    let sweep: Vec<(u32, Vec<p11scope_manifest::maps::MapEntry>)> = [
        (5100, world_map[&5100].clone()),
        (5101, world_map[&5101].clone()),
    ]
    .to_vec();
    let out = super::super::confirm_shards::attribute_unselected_with_segment_proof(
        &sweep,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &index,
        &mut budget,
        d3c_policy(6, 4),
        &pass.owner,
        2,
        &make_seg,
        probe.segment_proof(),
    );
    assert_eq!(
        out.members
            .iter()
            .map(|member| member.pid)
            .collect::<Vec<_>>(),
        [5100, 5101]
    );
    let third = d3c_packet(
        probe.segment_proof(),
        &world_map,
        &identities,
        &events,
        &pass.runs,
        &pass.owner,
        &prove_set,
        5102,
        &mut budget,
    );
    assert_kernel_slot(&third, Slot(0));
    let fourth = d3c_packet(
        probe.segment_proof(),
        &world_map,
        &identities,
        &events,
        &pass.runs,
        &pass.owner,
        &prove_set,
        5103,
        &mut budget,
    );
    assert_userspace_mapped(&fourth);
    assert_eq!(budget.work_units_count(), 4);
    let pin5100 = events.lock().unwrap().pin_fds[&5100];
    let pin5101 = events.lock().unwrap().pin_fds[&5101];
    let pin5102 = events.lock().unwrap().pin_fds[&5102];
    let trace = pass.runs.lock().unwrap();
    assert_eq!(trace.scopes.len(), 3, "a fourth target run was attempted");
    assert_eq!(
        trace.pidfds,
        [Some(pin5100), Some(pin5101), Some(pin5102)],
        "a counted run did not borrow its original pin"
    );
    drop(trace);
    drop(probe);
    assert_eq!(installed.target_attempts, 3);
    assert_eq!(installed.failed_target, None);
    drop(installed);
    assert_eq!(
        events.lock().unwrap().fallback,
        [(5103, segment_range(0).0, segment_range(0).1)],
        "the capped request did not fall back inside its original pin"
    );
    assert_eq!(
        session.fallback.totals(),
        KernelFallbackTotals {
            passes: 1,
            pids: 1,
            keys: 1,
            first_reason: Some(KernelFallbackReason::TargetLimit),
        }
    );

    // Four uniform segments: the fourth falls back, its step stays queued.
    let uniform = segment_cell(
        &[
            (5110, vec![0]),
            (5111, vec![0]),
            (5112, vec![0]),
            (5113, vec![0]),
        ],
        6,
        vec![
            FixtureTarget::Bytes(segment_target(&[5110], 0)),
            FixtureTarget::Bytes(segment_target(&[5111], 0)),
            FixtureTarget::Bytes(segment_target(&[5112], 0)),
            FixtureTarget::Bytes(segment_target(&[5113], 0)),
        ],
    );
    assert_eq!(uniform.attempts, 3);
    assert_eq!(uniform.runs.lock().unwrap().scopes.len(), 3);
    assert_eq!(uniform.remaining_steps, 1);
    assert_eq!(uniform.out.members.len(), 4);
    assert_eq!(uniform.charges, 4);
    assert_eq!(
        uniform.events.lock().unwrap().fallback,
        [(5113, segment_range(0).0, segment_range(0).1)]
    );
    assert_eq!(
        uniform.fallback,
        KernelFallbackTotals {
            passes: 1,
            pids: 1,
            keys: 1,
            first_reason: Some(KernelFallbackReason::TargetLimit),
        }
    );

    // A failed run consumes an attempt too, then demotes the rest of the pass.
    let mut bad = segment_target(&[5121], 0);
    bad[0] = 0;
    let failed = segment_cell(
        &[(5120, vec![0]), (5121, vec![0]), (5122, vec![0])],
        6,
        vec![
            FixtureTarget::Bytes(segment_target(&[5120], 0)),
            FixtureTarget::Bytes(bad),
            FixtureTarget::Bytes(segment_target(&[5122], 0)),
        ],
    );
    assert_eq!(failed.attempts, 2);
    assert_eq!(failed.failed_target, Some(RunFailure::StreamInvalid));
    assert_eq!(failed.runs.lock().unwrap().scopes.len(), 2);
    assert_eq!(failed.remaining_steps, 1);
    assert_eq!(failed.out.members.len(), 3);
    assert_eq!(failed.charges, 3);
}

#[test]
fn d3c_phase_d_borrows_original_pidfd() {
    // A promotion for a PID that cannot be reopened numerically must still
    // prove by kernel on the original retained pidfd.
    const BOGUS: u32 = 4_000_000;
    assert!(crate::attach::identity_iter::scope_word_bit(BOGUS).is_some());
    assert!(
        crate::attach::identity_iter::open_pidfd(BOGUS).is_err(),
        "the bogus promotion PID exists; this cell proves nothing"
    );
    let world = d3c_world();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut session = fixture_session();
    let (world_map, identities) = d3c_world_map(
        &world,
        &[(BOGUS, vec![0]), (5301, vec![0]), (5302, vec![0])],
    );
    let events = Arc::new(std::sync::Mutex::new(SegmentEvents::default()));
    let (mut installed, pass) = d3c_install(
        &world,
        &mut session,
        1,
        16,
        1,
        &[(0, ANCHOR_OK, 0), (1, ANCHOR_OK, 0)],
        vec![FixtureTarget::Bytes(gen_target(
            1,
            &[(BOGUS, segment_range(0), 0)],
        ))],
        deadline,
    );
    let (mut index, refused) = d3c_index(&world);
    assert!(refused.is_empty());
    let prove_set = index.map_files_keys();
    let mut budget = CaptureWorkBudget::default();
    let mut probe = KernelMemberProbe::new(
        &mut installed,
        SegmentIo {
            world: &world_map,
            identities: &identities,
            events: events.clone(),
            runs: pass.runs.clone(),
            owner: pass.owner.clone(),
            exe_reads: Cell::new(0),
            imm_base: pass.owner.state_for_test().0[3],
        },
        deadline,
    );
    probe.install_expectations(&mut index).unwrap();
    let promoted = d3c_packet(
        probe.segment_proof(),
        &world_map,
        &identities,
        &events,
        &pass.runs,
        &pass.owner,
        &prove_set,
        BOGUS,
        &mut budget,
    );
    assert_kernel_slot(&promoted, Slot(0));
    assert_eq!(budget.work_units_count(), 1);
    assert!(
        events.lock().unwrap().fallback.is_empty(),
        "the borrowed-fd promotion fell back to userspace"
    );
    let bogus_pin = events.lock().unwrap().pin_fds[&BOGUS];
    assert_eq!(
        pass.runs.lock().unwrap().pidfds,
        [Some(bogus_pin)],
        "the promotion did not run on its original retained pidfd"
    );
    drop(probe);
    assert_eq!(installed.target_attempts, 1);
    drop(installed);

    // The shared reservation guard refuses a foreign owner without any run.
    let (mut installed, pass) = d3c_install(
        &world,
        &mut session,
        2,
        16,
        1,
        &[(0, ANCHOR_OK, 0), (1, ANCHOR_OK, 0)],
        vec![FixtureTarget::Bytes(gen_target(
            2,
            &[(5301, segment_range(0), 0)],
        ))],
        deadline,
    );
    let runs_before = pass.runs.lock().unwrap().scopes.len();
    let (mut index, _) = d3c_index(&world);
    let prove_set = index.map_files_keys();
    let mut budget = CaptureWorkBudget::default();
    let mut probe = KernelMemberProbe::new(
        &mut installed,
        SegmentIo {
            world: &world_map,
            identities: &identities,
            events: events.clone(),
            runs: pass.runs.clone(),
            owner: pass.owner.clone(),
            exe_reads: Cell::new(0),
            imm_base: pass.owner.state_for_test().0[3],
        },
        deadline,
    );
    probe.install_expectations(&mut index).unwrap();
    let foreign = ReservationOwner::new(SegmentPolicy::from_headroom(16, 2, 1));
    let foreign_resources = foreign.batch();
    let refused = d3c_packet_with(
        probe.segment_proof(),
        &world_map,
        &identities,
        &events,
        &pass.runs,
        &pass.owner,
        &foreign_resources,
        &prove_set,
        5301,
        &mut budget,
    );
    assert_userspace_mapped(&refused);
    assert_eq!(
        pass.runs.lock().unwrap().scopes.len(),
        runs_before,
        "a foreign reservation reached the target iterator"
    );
    drop(probe);
    assert_eq!(installed.target_attempts, 0);
    drop(installed);

    // The pass guard refuses a released installation without any run.
    let (mut installed, pass) = d3c_install(
        &world,
        &mut session,
        3,
        16,
        1,
        &[(0, ANCHOR_OK, 0), (1, ANCHOR_OK, 0)],
        vec![FixtureTarget::Bytes(gen_target(
            3,
            &[(5302, segment_range(0), 0)],
        ))],
        deadline,
    );
    installed.session.binding = None;
    let runs_before = pass.runs.lock().unwrap().scopes.len();
    let (mut index, _) = d3c_index(&world);
    let prove_set = index.map_files_keys();
    let mut budget = CaptureWorkBudget::default();
    let mut probe = KernelMemberProbe::new(
        &mut installed,
        SegmentIo {
            world: &world_map,
            identities: &identities,
            events: events.clone(),
            runs: pass.runs.clone(),
            owner: pass.owner.clone(),
            exe_reads: Cell::new(0),
            imm_base: pass.owner.state_for_test().0[3],
        },
        deadline,
    );
    probe.install_expectations(&mut index).unwrap();
    let unowned = d3c_packet(
        probe.segment_proof(),
        &world_map,
        &identities,
        &events,
        &pass.runs,
        &pass.owner,
        &prove_set,
        5302,
        &mut budget,
    );
    assert_userspace_mapped(&unowned);
    assert_eq!(
        pass.runs.lock().unwrap().scopes.len(),
        runs_before,
        "a released installation reached the target iterator"
    );
    drop(probe);
    assert_eq!(installed.target_attempts, 0);
    drop(installed);
}

#[test]
fn d3c_wrong_batch_or_pass_cannot_reuse_verdict() {
    // Batch 2 must not serve batch 1's verdicts: its PID is unvisited, so
    // it falls back inside its own pin while batch 1 stays kernel-positive.
    let batches = segment_cell(
        &[(5501, vec![0]), (5502, vec![0])],
        6,
        vec![
            FixtureTarget::Bytes(segment_target(&[5501], 0)),
            FixtureTarget::Bytes(target_stream(&[])),
        ],
    );
    assert_eq!(
        batches
            .out
            .members
            .iter()
            .map(|member| member.pid)
            .collect::<Vec<_>>(),
        [5501, 5502]
    );
    assert_eq!(batches.charges, 2);
    assert_eq!(batches.attempts, 2);
    assert_eq!(batches.runs.lock().unwrap().scopes.len(), 2);
    assert_eq!(
        batches.events.lock().unwrap().fallback,
        [(5502, segment_range(0).0, segment_range(0).1)],
        "the second batch reused the first batch's verdicts"
    );
    assert_eq!(
        batches.fallback,
        KernelFallbackTotals {
            passes: 1,
            pids: 1,
            keys: 1,
            first_reason: Some(KernelFallbackReason::Unvisited),
        }
    );

    // A new pass with a new installation cannot serve the old verdicts: its
    // slot is uninstalled, so it falls back without running at all.
    let world = d3c_world();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut session = fixture_session();
    let (world_map, identities) = d3c_world_map(&world, &[(5601, vec![0]), (5602, vec![0])]);
    let events = Arc::new(std::sync::Mutex::new(SegmentEvents::default()));
    let (mut installed, pass) = d3c_install(
        &world,
        &mut session,
        1,
        16,
        1,
        &[(0, ANCHOR_OK, 0), (1, ANCHOR_OK, 0)],
        vec![FixtureTarget::Bytes(gen_target(
            1,
            &[(5601, segment_range(0), 0)],
        ))],
        deadline,
    );
    let (mut index, _) = d3c_index(&world);
    let prove_set = index.map_files_keys();
    let mut budget = CaptureWorkBudget::default();
    let mut probe = KernelMemberProbe::new(
        &mut installed,
        SegmentIo {
            world: &world_map,
            identities: &identities,
            events: events.clone(),
            runs: pass.runs.clone(),
            owner: pass.owner.clone(),
            exe_reads: Cell::new(0),
            imm_base: pass.owner.state_for_test().0[3],
        },
        deadline,
    );
    probe.install_expectations(&mut index).unwrap();
    let first = d3c_packet(
        probe.segment_proof(),
        &world_map,
        &identities,
        &events,
        &pass.runs,
        &pass.owner,
        &prove_set,
        5601,
        &mut budget,
    );
    assert_kernel_slot(&first, Slot(0));
    drop(probe);
    drop(installed);
    let bad_shape = crate::attach::identity_iter::ANCHOR_BAD_SHAPE;
    let (mut installed, pass) = d3c_install(
        &world,
        &mut session,
        2,
        16,
        1,
        &[(0, bad_shape, 0), (1, bad_shape, 0)],
        vec![FixtureTarget::Bytes(gen_target(
            2,
            &[(5602, segment_range(0), 0)],
        ))],
        deadline,
    );
    let runs_before = pass.runs.lock().unwrap().scopes.len();
    let (mut index, _) = d3c_index(&world);
    let prove_set = index.map_files_keys();
    let mut budget = CaptureWorkBudget::default();
    let mut probe = KernelMemberProbe::new(
        &mut installed,
        SegmentIo {
            world: &world_map,
            identities: &identities,
            events: events.clone(),
            runs: pass.runs.clone(),
            owner: pass.owner.clone(),
            exe_reads: Cell::new(0),
            imm_base: pass.owner.state_for_test().0[3],
        },
        deadline,
    );
    probe.install_expectations(&mut index).unwrap();
    let second = d3c_packet(
        probe.segment_proof(),
        &world_map,
        &identities,
        &events,
        &pass.runs,
        &pass.owner,
        &prove_set,
        5602,
        &mut budget,
    );
    assert_userspace_mapped(&second);
    assert_eq!(
        pass.runs.lock().unwrap().scopes.len(),
        runs_before,
        "the new pass served the old installation's verdicts"
    );
    drop(probe);
    assert_eq!(installed.target_attempts, 0);
    drop(installed);
    assert_eq!(
        session.fallback.totals(),
        KernelFallbackTotals {
            passes: 1,
            pids: 1,
            keys: 1,
            first_reason: Some(KernelFallbackReason::AnchorNotInstalled),
        }
    );
}

#[test]
fn d3c_invalid_stream_sticks_across_passes() {
    let world = d3c_world();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut session = fixture_session();
    let (world_map, identities) = d3c_world_map(&world, &[(5201, vec![0]), (5202, vec![0])]);
    let events = Arc::new(std::sync::Mutex::new(SegmentEvents::default()));
    let mut bad = gen_target(1, &[(5201, segment_range(0), 0)]);
    bad[0] = 0;
    let (mut installed, pass) = d3c_install(
        &world,
        &mut session,
        1,
        16,
        1,
        &[(0, ANCHOR_OK, 0), (1, ANCHOR_OK, 0)],
        vec![FixtureTarget::Bytes(bad)],
        deadline,
    );
    let runs = pass.runs.clone();
    let (mut index, _) = d3c_index(&world);
    let prove_set = index.map_files_keys();
    let mut budget = CaptureWorkBudget::default();
    let mut probe = KernelMemberProbe::new(
        &mut installed,
        SegmentIo {
            world: &world_map,
            identities: &identities,
            events: events.clone(),
            runs: runs.clone(),
            owner: pass.owner.clone(),
            exe_reads: Cell::new(0),
            imm_base: pass.owner.state_for_test().0[3],
        },
        deadline,
    );
    probe.install_expectations(&mut index).unwrap();
    let poisoned = d3c_packet(
        probe.segment_proof(),
        &world_map,
        &identities,
        &events,
        &runs,
        &pass.owner,
        &prove_set,
        5201,
        &mut budget,
    );
    assert_userspace_mapped(&poisoned);
    assert_eq!(budget.work_units_count(), 1);
    drop(probe);
    assert_eq!(installed.failed_target, Some(RunFailure::StreamInvalid));
    assert_eq!(installed.target_attempts, 1);
    drop(installed);
    assert_eq!(session.sticky, Some(KernelSticky::StreamInvalid));

    // The next pass installs cleanly and offers valid bytes, but the sticky
    // session failure refuses every target run.
    let (mut installed, pass) = d3c_install(
        &world,
        &mut session,
        2,
        16,
        1,
        &[(0, ANCHOR_OK, 0), (1, ANCHOR_OK, 0)],
        vec![FixtureTarget::Bytes(gen_target(
            2,
            &[(5202, segment_range(0), 0)],
        ))],
        deadline,
    );
    let (mut index, _) = d3c_index(&world);
    let prove_set = index.map_files_keys();
    let mut budget = CaptureWorkBudget::default();
    let mut probe = KernelMemberProbe::new(
        &mut installed,
        SegmentIo {
            world: &world_map,
            identities: &identities,
            events: events.clone(),
            runs: runs.clone(),
            owner: pass.owner.clone(),
            exe_reads: Cell::new(0),
            imm_base: pass.owner.state_for_test().0[3],
        },
        deadline,
    );
    probe.install_expectations(&mut index).unwrap();
    let stuck = d3c_packet(
        probe.segment_proof(),
        &world_map,
        &identities,
        &events,
        &runs,
        &pass.owner,
        &prove_set,
        5202,
        &mut budget,
    );
    assert_userspace_mapped(&stuck);
    assert_eq!(budget.work_units_count(), 1);
    drop(probe);
    assert_eq!(installed.target_attempts, 0);
    drop(installed);
    assert_eq!(
        runs.lock().unwrap().scopes.len(),
        1,
        "a sticky invalid stream attempted another target run"
    );
    assert_eq!(
        events.lock().unwrap().fallback.len(),
        2,
        "sticky fallback did not stay inside the original pins"
    );
    assert_eq!(
        session.fallback.totals(),
        KernelFallbackTotals {
            passes: 2,
            pids: 2,
            keys: 2,
            first_reason: Some(KernelFallbackReason::StreamInvalid),
        }
    );
}

#[test]
fn d3c_three_attempted_deadlines_become_sticky() {
    let world = d3c_world();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut session = fixture_session();
    let pids: Vec<(u32, Vec<usize>)> = (0..4).map(|i| (5210 + i, vec![0])).collect();
    let (world_map, identities) = d3c_world_map(&world, &pids);
    let events = Arc::new(std::sync::Mutex::new(SegmentEvents::default()));
    let mut runs_seen = 0usize;
    for (pass_no, pid) in [5210, 5211, 5212].into_iter().enumerate() {
        let generation = pass_no as u64 + 1;
        let (mut installed, pass) = d3c_install(
            &world,
            &mut session,
            generation,
            16,
            1,
            &[(0, ANCHOR_OK, 0), (1, ANCHOR_OK, 0)],
            vec![FixtureTarget::Deadline(gen_target(
                generation,
                &[(pid, segment_range(0), 0)],
            ))],
            deadline,
        );
        let (mut index, _) = d3c_index(&world);
        let prove_set = index.map_files_keys();
        let mut budget = CaptureWorkBudget::default();
        let mut probe = KernelMemberProbe::new(
            &mut installed,
            SegmentIo {
                world: &world_map,
                identities: &identities,
                events: events.clone(),
                runs: pass.runs.clone(),
                owner: pass.owner.clone(),
                exe_reads: Cell::new(0),
                imm_base: pass.owner.state_for_test().0[3],
            },
            deadline,
        );
        probe.install_expectations(&mut index).unwrap();
        let late = d3c_packet(
            probe.segment_proof(),
            &world_map,
            &identities,
            &events,
            &pass.runs,
            &pass.owner,
            &prove_set,
            pid,
            &mut budget,
        );
        runs_seen = pass.runs.lock().unwrap().scopes.len();
        assert_userspace_mapped(&late);
        assert_eq!(budget.work_units_count(), 1);
        drop(probe);
        assert_eq!(installed.failed_target, Some(RunFailure::Deadline));
        assert_eq!(installed.target_attempts, 1);
        drop(installed);
        assert_eq!(session.consecutive_deadlines, generation as u32);
    }
    assert_eq!(
        session.sticky,
        Some(KernelSticky::Deadlines),
        "three consecutive attempted deadlines did not stick"
    );
    assert_eq!(runs_seen, 3);

    // The fourth pass offers valid bytes but must not run.
    let (mut installed, pass) = d3c_install(
        &world,
        &mut session,
        4,
        16,
        1,
        &[(0, ANCHOR_OK, 0), (1, ANCHOR_OK, 0)],
        vec![FixtureTarget::Bytes(gen_target(
            4,
            &[(5213, segment_range(0), 0)],
        ))],
        deadline,
    );
    let (mut index, _) = d3c_index(&world);
    let prove_set = index.map_files_keys();
    let mut budget = CaptureWorkBudget::default();
    let mut probe = KernelMemberProbe::new(
        &mut installed,
        SegmentIo {
            world: &world_map,
            identities: &identities,
            events: events.clone(),
            runs: pass.runs.clone(),
            owner: pass.owner.clone(),
            exe_reads: Cell::new(0),
            imm_base: pass.owner.state_for_test().0[3],
        },
        deadline,
    );
    probe.install_expectations(&mut index).unwrap();
    let stuck = d3c_packet(
        probe.segment_proof(),
        &world_map,
        &identities,
        &events,
        &pass.runs,
        &pass.owner,
        &prove_set,
        5213,
        &mut budget,
    );
    assert_userspace_mapped(&stuck);
    drop(probe);
    assert_eq!(installed.target_attempts, 0);
    drop(installed);
    assert_eq!(
        pass.runs.lock().unwrap().scopes.len(),
        3,
        "the deadline-stuck session attempted another target run"
    );
    assert_eq!(
        session.fallback.totals(),
        KernelFallbackTotals {
            passes: 4,
            pids: 4,
            keys: 4,
            first_reason: Some(KernelFallbackReason::Deadline),
        }
    );
}

#[test]
fn d3c_no_attempt_preserves_deadline_streak() {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Packet {
        Threshold,
        Foreign,
        Expired,
        Deadline,
        Valid,
    }
    // Streak after each pass: no-attempt cases neither create a streak from
    // zero nor reset an existing one; only attempted runs move it.
    let plan: [(u32, Packet, u32, usize); 8] = [
        (5401, Packet::Threshold, 0, 0),
        (5402, Packet::Deadline, 1, 1),
        (5403, Packet::Threshold, 1, 0),
        (5404, Packet::Foreign, 1, 0),
        (5405, Packet::Expired, 1, 0),
        (5406, Packet::Deadline, 2, 1),
        (5407, Packet::Deadline, 3, 1),
        (5408, Packet::Valid, 3, 0),
    ];
    let world = d3c_world();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut session = fixture_session();
    let pids: Vec<(u32, Vec<usize>)> = plan.iter().map(|(pid, _, _, _)| (*pid, vec![0])).collect();
    let (world_map, identities) = d3c_world_map(&world, &pids);
    let events = Arc::new(std::sync::Mutex::new(SegmentEvents::default()));
    for (i, (pid, kind, streak, new_runs)) in plan.into_iter().enumerate() {
        let generation = i as u64 + 1;
        let step = match kind {
            Packet::Deadline => {
                FixtureTarget::Deadline(gen_target(generation, &[(pid, segment_range(0), 0)]))
            }
            _ => FixtureTarget::Bytes(gen_target(generation, &[(pid, segment_range(0), 0)])),
        };
        let (mut installed, pass) = d3c_install(
            &world,
            &mut session,
            generation,
            16,
            1,
            &[(0, ANCHOR_OK, 0), (1, ANCHOR_OK, 0)],
            vec![step],
            deadline,
        );
        let runs_before = pass.runs.lock().unwrap().scopes.len();
        let (mut index, _) = d3c_index(&world);
        let prove_set = index.map_files_keys();
        let mut budget = CaptureWorkBudget::default();
        let mut probe = KernelMemberProbe::new(
            &mut installed,
            SegmentIo {
                world: &world_map,
                identities: &identities,
                events: events.clone(),
                runs: pass.runs.clone(),
                owner: pass.owner.clone(),
                exe_reads: Cell::new(0),
                imm_base: pass.owner.state_for_test().0[3],
            },
            deadline,
        );
        if kind == Packet::Threshold {
            probe = probe.with_auto_threshold(usize::MAX);
        }
        probe.install_expectations(&mut index).unwrap();
        match kind {
            Packet::Foreign => {
                let foreign = ReservationOwner::new(SegmentPolicy::from_headroom(16, 2, 1));
                let foreign_resources = foreign.batch();
                let refused = d3c_packet_with(
                    probe.segment_proof(),
                    &world_map,
                    &identities,
                    &events,
                    &pass.runs,
                    &pass.owner,
                    &foreign_resources,
                    &prove_set,
                    pid,
                    &mut budget,
                );
                assert_userspace_mapped(&refused);
            }
            Packet::Expired => {
                let mut segio = SegmentIo {
                    world: &world_map,
                    identities: &identities,
                    events: events.clone(),
                    runs: pass.runs.clone(),
                    owner: pass.owner.clone(),
                    exe_reads: Cell::new(0),
                    imm_base: pass.owner.state_for_test().0[3],
                };
                let resources = pass.owner.batch();
                let prepared = super::super::sweep_attribution::prepare_confirmation(
                    &mut segio,
                    pid,
                    &prove_set,
                    &mut budget,
                    Some(&resources),
                )
                .unwrap();
                budget.set_deadline(Some(0));
                let stopped = super::super::confirm_shards::prove_and_finish_prepared(
                    &mut segio,
                    pid,
                    prepared,
                    probe.segment_proof(),
                    &resources,
                    &mut budget,
                );
                assert!(
                    matches!(
                        stopped,
                        Confirmation::Lost(
                            super::super::sweep_attribution::AttributionLoss::Budget,
                            _
                        )
                    ),
                    "an already expired deadline attempted proof: {stopped:?}"
                );
                assert_eq!(budget.work_units_count(), 1);
            }
            _ => {
                let out = d3c_packet(
                    probe.segment_proof(),
                    &world_map,
                    &identities,
                    &events,
                    &pass.runs,
                    &pass.owner,
                    &prove_set,
                    pid,
                    &mut budget,
                );
                assert_userspace_mapped(&out);
                assert_eq!(budget.work_units_count(), 1);
            }
        }
        assert_eq!(
            pass.runs.lock().unwrap().scopes.len() - runs_before,
            new_runs,
            "pass {generation} attempted an unexpected run count"
        );
        drop(probe);
        drop(installed);
        assert_eq!(
            session.consecutive_deadlines, streak,
            "pass {generation} moved the deadline streak unexpectedly"
        );
    }
    assert_eq!(session.sticky, Some(KernelSticky::Deadlines));
    assert_eq!(
        session.fallback.totals(),
        KernelFallbackTotals {
            passes: 8,
            pids: 8,
            keys: 8,
            first_reason: Some(KernelFallbackReason::BelowThreshold),
        }
    );
}

#[test]
fn d3c_postparse_deadline_discards_complete_run() {
    // The first segment parses a complete valid run, then the cooperative
    // deadline crosses before any PID finishes: the entire run is discarded
    // and both segments fall back inside their original pins.
    arm_post_parse_expiry();
    let observation = segment_cell(
        &[(9200, vec![0]), (9201, vec![0])],
        6,
        vec![
            FixtureTarget::Bytes(segment_target(&[9200], 0)),
            FixtureTarget::Bytes(segment_target(&[9201], 0)),
        ],
    );
    assert_eq!(observation.attempts, 1);
    assert_eq!(observation.failed_target, Some(RunFailure::Deadline));
    assert_eq!(
        observation.runs.lock().unwrap().scopes.len(),
        1,
        "the demoted pass retried after a post-parse deadline"
    );
    assert_eq!(observation.remaining_steps, 1);
    assert_eq!(
        observation
            .out
            .members
            .iter()
            .map(|member| member.pid)
            .collect::<Vec<_>>(),
        [9200, 9201]
    );
    assert!(observation.out.losses.is_empty());
    assert_eq!(observation.charges, 2);
    assert_eq!(
        observation.events.lock().unwrap().fallback,
        [
            (9200, segment_range(0).0, segment_range(0).1),
            (9201, segment_range(0).0, segment_range(0).1),
        ],
        "a parsed-but-unfinished run kept partial kernel answers"
    );
    assert_eq!(
        observation.fallback,
        KernelFallbackTotals {
            passes: 1,
            pids: 2,
            keys: 1,
            first_reason: Some(KernelFallbackReason::Deadline),
        }
    );
}

#[test]
fn d3c_auto_below_threshold_skips_run_with_actual_fallback() {
    // More total proof PIDs than the injected threshold, but every
    // resource-bounded segment is sub-threshold: auto attempts no
    // production kernel run and discloses actual userspace fallback.
    let observation = segment_cell_with_deadline(
        &[(6101, vec![0]), (6102, vec![0]), (6103, vec![0])],
        6,
        vec![
            FixtureTarget::Bytes(segment_target(&[6101], 0)),
            FixtureTarget::Bytes(segment_target(&[6102], 0)),
            FixtureTarget::Bytes(segment_target(&[6103], 0)),
        ],
        None,
        Some(2),
    );
    assert_eq!(observation.attempts, 0);
    assert_eq!(observation.failed_target, None);
    assert!(
        observation.runs.lock().unwrap().scopes.is_empty(),
        "a sub-threshold segment attempted a kernel target run"
    );
    assert_eq!(observation.remaining_steps, 3);
    assert_eq!(
        observation
            .out
            .members
            .iter()
            .map(|member| member.pid)
            .collect::<Vec<_>>(),
        [6101, 6102, 6103]
    );
    assert_eq!(observation.charges, 3);
    assert_eq!(
        observation.events.lock().unwrap().fallback,
        [
            (6101, segment_range(0).0, segment_range(0).1),
            (6102, segment_range(0).0, segment_range(0).1),
            (6103, segment_range(0).0, segment_range(0).1),
        ]
    );
    assert_eq!(
        observation.fallback,
        KernelFallbackTotals {
            passes: 1,
            pids: 3,
            keys: 1,
            first_reason: Some(KernelFallbackReason::BelowThreshold),
        }
    );
}

#[test]
fn d3c_forced_kernel_obeys_resource_and_run_caps() {
    // Forced shape (no cost gate) with no iterator headroom: the run is
    // refused before I/O and falls back inside the original pin.
    let world = d3c_world();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut session = fixture_session();
    let (world_map, identities) = d3c_world_map(&world, &[(6201, vec![0])]);
    let events = Arc::new(std::sync::Mutex::new(SegmentEvents::default()));
    let (mut installed, pass) = d3c_install(
        &world,
        &mut session,
        1,
        16,
        1,
        &[(0, ANCHOR_OK, 0), (1, ANCHOR_OK, 0)],
        vec![FixtureTarget::Bytes(gen_target(
            1,
            &[(6201, segment_range(0), 0)],
        ))],
        deadline,
    );
    let (mut index, _) = d3c_index(&world);
    let prove_set = index.map_files_keys();
    let mut budget = CaptureWorkBudget::default();
    let mut probe = KernelMemberProbe::new(
        &mut installed,
        SegmentIo {
            world: &world_map,
            identities: &identities,
            events: events.clone(),
            runs: pass.runs.clone(),
            owner: pass.owner.clone(),
            exe_reads: Cell::new(0),
            imm_base: pass.owner.state_for_test().0[3],
        },
        deadline,
    );
    probe.install_expectations(&mut index).unwrap();
    let held = pass.owner.immediate().transient().unwrap();
    let refused = d3c_packet(
        probe.segment_proof(),
        &world_map,
        &identities,
        &events,
        &pass.runs,
        &pass.owner,
        &prove_set,
        6201,
        &mut budget,
    );
    drop(held);
    assert_userspace_mapped(&refused);
    assert_eq!(budget.work_units_count(), 1);
    assert!(
        pass.runs.lock().unwrap().scopes.is_empty(),
        "an over-headroom run reached the target iterator"
    );
    drop(probe);
    assert_eq!(installed.target_attempts, 0);
    assert_eq!(installed.failed_target, None);
    drop(installed);
    assert_eq!(session.consecutive_deadlines, 0);
    assert_eq!(
        events.lock().unwrap().fallback,
        [(6201, segment_range(0).0, segment_range(0).1)]
    );
    assert_eq!(
        session.fallback.totals(),
        KernelFallbackTotals {
            passes: 1,
            pids: 1,
            keys: 1,
            first_reason: Some(KernelFallbackReason::FdHeadroom),
        }
    );
}

#[test]
fn d3c_generation_rollover_refuses_reuse() {
    let world = d3c_world();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut session = fixture_session();
    let ok = [(0, ANCHOR_OK, 0), (1, ANCHOR_OK, 0)];
    let (installed, _) = d3c_install(&world, &mut session, 1, 16, 1, &ok, vec![], deadline);
    drop(installed);
    assert_eq!(session.generation, 1);
    // A reused, rolled-over, or record-ambiguous generation is refused, and
    // the refusal leaves the session usable for the next generation.
    for bad in [1, u64::from(u32::MAX), u64::MAX] {
        let owner = ReservationOwner::for_examined(SegmentPolicy::from_headroom(16, 0, 0), 1);
        let mut custody = ExaminedCustody::new(owner, BTreeMap::new());
        let scan = custody.begin_scan();
        let held = File::open(world.dir.path().join("examined.so")).unwrap();
        assert!(custody.offer_for_test(scan, world.examined, held));
        custody.reconcile(d3c_policy(16, 1)).unwrap();
        let pass = AnchorPass::prepare(
            &world.pins,
            [(world.provider.key, world.provider_id)],
            custody,
        );
        assert!(
            session.install_anchors(pass, bad, deadline).is_err(),
            "generation {bad} was accepted"
        );
        assert_eq!(session.generation, 1);
        assert!(session.binding.is_none());
    }
    let (installed, _) = d3c_install(&world, &mut session, 2, 16, 1, &ok, vec![], deadline);
    drop(installed);
    assert_eq!(session.generation, 2);
}

// ---- Member-run (TID) cells ----

use super::super::retained_member::RetainedGroupMember;
use super::super::sweep_attribution::AttributionLoss;
use crate::process::PidPin;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A live `sleep` child: real custody for member mints. The tests mint a
/// leader-as-member on the child, so every member prove runs against a
/// genuinely live (tgid, tid) pair without raw-clone fixtures.
struct SleepChild {
    child: std::process::Child,
}

impl SleepChild {
    fn spawn() -> Self {
        let child = std::process::Command::new("sleep")
            .arg("30")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("sleep spawns");
        Self { child }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for SleepChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Fake pin for member cells (no FD; custody lives in the member).
struct MemberPin;

/// `ConfirmIo` serving canned entries, with an optional REAL member mint.
/// The mint path exercises genuine custody (tgkill, pidfd, birth
/// brackets) on the live child; the kernel side stays scripted.
struct MemberIo {
    entries: Vec<MapEntry>,
    identity: FileIdentity,
    exe: super::super::caller_registry::ExeIdentity,
    mint: bool,
    member_owner: ReservationOwner,
    stashed: Option<RetainedGroupMember>,
    minter: Option<Arc<PidPin>>,
    fallback_reads: Rc<RefCell<Vec<(u32, u64, u64)>>>,
}

impl MemberIo {
    fn canned(
        entries: Vec<MapEntry>,
        identity: FileIdentity,
        mint: bool,
        fallback_reads: Rc<RefCell<Vec<(u32, u64, u64)>>>,
    ) -> Self {
        Self {
            entries,
            identity,
            exe: super::super::caller_registry::ExeIdentity {
                dev: 1,
                ino: 2,
                mtime_secs: 0,
                mtime_nanos: 0,
                path: Some("member-fixture".into()),
            },
            mint,
            member_owner: ReservationOwner::new(SegmentPolicy::from_headroom(64, 1, 1)),
            stashed: None,
            minter: None,
            fallback_reads,
        }
    }
}

impl super::super::sweep_attribution::ConfirmIo for MemberIo {
    type Pin = MemberPin;

    fn open(&mut self, _: u32) -> Result<Self::Pin, String> {
        Ok(MemberPin)
    }

    fn mapped_file(&mut self, pid: u32, start: u64, end: u64) -> Result<FileIdentity, String> {
        self.fallback_reads.borrow_mut().push((pid, start, end));
        // A leader-path read for a zombie pid fails like the real kernel
        // (ESRCH): only the member path serves it. Live pids keep the
        // canned identity, so the existing twins are unchanged.
        if self.stashed.is_none() && crate::process::process_is_zombie(pid) {
            return Err(std::io::Error::from_raw_os_error(libc::ESRCH).to_string());
        }
        Ok(self.identity)
    }

    fn start_time(&self, _: &Self::Pin) -> Option<u64> {
        Some(42)
    }

    fn still_the_same(&self, _: &Self::Pin) -> bool {
        true
    }

    fn exe(&self, _: u32) -> Option<super::super::caller_registry::ExeIdentity> {
        // Member-preferring, like the production routing: a stashed
        // member serves its real exe so prepare and finish agree.
        if let Some(member) = &self.stashed {
            return member.read_exe_identity();
        }
        Some(self.exe.clone())
    }

    fn maps(
        &mut self,
        _: u32,
        _: &mut crate::discovery::scan::CaptureWorkBudget,
    ) -> Result<Vec<MapEntry>, String> {
        Ok(self.entries.clone())
    }

    fn gone(&self, _: u32) -> bool {
        false
    }

    fn mint_member(
        &mut self,
        pid: u32,
        budget: &mut crate::discovery::scan::CaptureWorkBudget,
    ) -> Result<(), super::super::sweep_attribution::Confirmation> {
        use super::super::sweep_attribution::Confirmation;
        self.stashed = None;
        self.minter = None;
        if !self.mint {
            return Ok(());
        }
        let original =
            Arc::new(PidPin::open(pid).map_err(|error| {
                Confirmation::Lost(AttributionLoss::MapFilesUnavailable, error)
            })?);
        let deadline = Instant::now() + Duration::from_secs(10);
        match RetainedGroupMember::acquire(&original, pid, &self.member_owner, budget, deadline) {
            Ok(member) => {
                self.stashed = Some(member);
                self.minter = Some(original);
                Ok(())
            }
            Err(error) => Err(Confirmation::Lost(
                AttributionLoss::MapFilesUnavailable,
                error,
            )),
        }
    }

    fn take_member(&mut self) -> Option<RetainedGroupMember> {
        self.stashed.take()
    }

    fn return_member(&mut self, _pid: u32, member: Option<RetainedGroupMember>) {
        self.stashed = member;
    }
}

/// One scripted member-run outcome, in run order.
#[derive(Clone, Copy)]
enum MemberOutcome {
    /// The run emits Slot(0) verdicts for every requested range.
    Slot,
    /// The run fails before any byte (demotes later segments).
    Failure(RunFailure),
    /// The prove consumes no scripted step: a pre-read refusal skips
    /// the run entirely. Later `Slot` steps still key by their own
    /// prove position, so the following prove reads its own records.
    NoRead,
}

/// Drives member-cell proves against a fixture session. Singleton
/// requests each run one `prove_and_finish_prepared` (with finish);
/// `multi` runs one direct `prove` over all requests (no finish) so
/// per-request answers stay observable.
struct MemberCellSpec {
    mint: Vec<bool>,
    outcomes: Vec<MemberOutcome>,
    threshold: Option<usize>,
    fail_config: bool,
    multi: bool,
}

struct MemberObservation {
    confirmations: Vec<super::super::sweep_attribution::Confirmation>,
    answers: Vec<Option<MappedIdentities>>,
    pids: Vec<u32>,
    attempts: u32,
    failed_target: Option<RunFailure>,
    fallback: KernelFallbackTotals,
    tids: Vec<Option<(u32, u32)>>,
    pidfds: Vec<Option<i32>>,
    scopes: Vec<BTreeSet<u32>>,
    config_writes: Vec<crate::attach::identity_iter::IdentityConfig>,
    per_pid: BTreeMap<u32, KernelFallbackReason>,
    binding_valid: bool,
    fallback_reads: Vec<(u32, u64, u64)>,
}

fn member_cell(spec: MemberCellSpec) -> MemberObservation {
    assert_eq!(spec.mint.len(), spec.outcomes.len());
    let dir = tempfile::tempdir().unwrap();
    let (file, provider) = opened(dir.path(), "provider.so");
    drop(file);
    let pins = super::super::identity::test_fixture::real_scan_pin(
        &dir.path().join("provider.so"),
        None,
        1,
        "member-custody-fixture",
    );
    let id = pins.pinned().next().unwrap().id;
    let (held, examined) = opened(dir.path(), "examined.so");
    let children: Vec<SleepChild> = spec.mint.iter().map(|_| SleepChild::spawn()).collect();
    let pids: Vec<u32> = children.iter().map(SleepChild::pid).collect();
    let ranges: Vec<(u64, u64)> = pids
        .iter()
        .enumerate()
        .map(|(position, _)| segment_range(position))
        .collect();
    // Scripted target bytes per request: Slot verdicts keyed by the real
    // child pid (the member run emits the TGID), or a scripted failure.
    let steps: Vec<FixtureTarget> = spec
        .outcomes
        .iter()
        .enumerate()
        .filter_map(|(position, outcome)| match outcome {
            MemberOutcome::Slot => Some(FixtureTarget::Bytes(target_stream(&[(
                pids[position],
                ranges[position],
                0,
            )]))),
            MemberOutcome::Failure(reason) => Some(FixtureTarget::Failure(*reason)),
            MemberOutcome::NoRead => None,
        })
        .collect();
    let entries: Vec<Vec<MapEntry>> = pids
        .iter()
        .enumerate()
        .map(|(position, _)| {
            vec![MapEntry {
                start: ranges[position].0,
                end: ranges[position].1,
                permissions: *b"r-xp",
                file_offset: 0,
                device: provider.key.device,
                inode: provider.key.inode,
                raw_path: Some(b"/fixture/provider.so".to_vec()),
            }]
        })
        .collect();
    // The multi prove runs once over all requests: merge every
    // request's records into one scripted run.
    let multi_steps = vec![FixtureTarget::Bytes(target_stream(
        &spec
            .mint
            .iter()
            .enumerate()
            .filter(|(_, mint)| !**mint)
            .map(|(position, _)| (pids[position], ranges[position], 0))
            .collect::<Vec<_>>(),
    ))];
    let owner = ReservationOwner::for_examined(SegmentPolicy::from_headroom(16, 0, 0), 1);
    let mut custody = ExaminedCustody::new(owner.clone(), BTreeMap::new());
    let scan = custody.begin_scan();
    assert!(custody.offer_for_test(scan, examined, held));
    let mut session = fixture_session();
    let runs = if let SessionObject::Fixture {
        anchor,
        target_steps,
        target_trace,
        ..
    } = &mut session.object
    {
        *anchor = anchor_stream(&[(0, ANCHOR_OK, 0), (1, ANCHOR_OK, 0)]);
        *target_steps.borrow_mut() = if spec.multi { multi_steps } else { steps }.into();
        target_trace.clone()
    } else {
        unreachable!()
    };
    custody
        .reconcile(SegmentPolicy::from_headroom(64, 2, spec.mint.len()))
        .unwrap();
    let pass = AnchorPass::prepare(&pins, [(provider.key, id)], custody);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut installed = session.install_anchors(pass, 1, deadline).unwrap();
    // Config failure starts after installation: the install itself
    // must succeed so the proves exercise the member path.
    if spec.fail_config {
        if let SessionObject::Fixture { fail_config, .. } = &mut installed.session.object {
            *fail_config = true;
        } else {
            unreachable!()
        }
    }
    let (mut index, refused) = KnownKeyIndex::build(
        [(provider.key, Some(id))],
        &BTreeMap::from([(provider.key, id)]),
        [examined],
        &AdapterChecks(provider.identity),
    );
    assert!(refused.is_empty());
    let mut probe = KernelMemberProbe::new(
        &mut installed,
        MemberIo::canned(
            vec![],
            provider.identity,
            false,
            Rc::new(RefCell::new(vec![])),
        ),
        deadline,
    );
    if let Some(threshold) = spec.threshold {
        probe = probe.with_auto_threshold(threshold);
    }
    probe.install_expectations(&mut index).unwrap();
    let mut budget = crate::discovery::scan::CaptureWorkBudget::default();
    let fallback_reads = Rc::new(RefCell::new(Vec::new()));
    let resources = owner.batch();
    let prove_set = BTreeSet::from([provider.key]);
    let mut confirmations = Vec::new();
    let mut answers = Vec::new();
    if spec.multi {
        use super::super::confirm_shards::SegmentProof as _;
        use super::super::confirm_shards::accepted_batch_for_test;
        let mut ios: Vec<MemberIo> = spec
            .mint
            .iter()
            .enumerate()
            .map(|(position, mint)| {
                MemberIo::canned(
                    entries[position].clone(),
                    provider.identity,
                    *mint,
                    fallback_reads.clone(),
                )
            })
            .collect();
        let mut plans = Vec::new();
        for (position, io) in ios.iter_mut().enumerate() {
            let prepared = super::super::sweep_attribution::prepare_confirmation(
                io,
                pids[position],
                &prove_set,
                &mut budget,
                Some(&resources),
            )
            .expect("member request prepares");
            plans.push((pids[position], prepared));
        }
        let batch = accepted_batch_for_test(&plans);
        let decision = probe.segment_proof().prove(&batch, &mut budget, &resources);
        for position in 0..plans.len() {
            answers.push(decision.answer(&batch, position).cloned());
        }
        drop(batch);
        // Emulate the segment driver for unanswered requests: prove by
        // userspace exactly as `prove_and_finish_prepared` would.
        for (position, answer) in answers.iter().enumerate() {
            if answer.is_none() {
                let mapped = super::super::sweep_attribution::read_ranges_reserved(
                    &mut ios[position],
                    pids[position],
                    &plans[position].1.ranges,
                    Some(&resources),
                );
                assert!(
                    mapped.values().all(|proof| matches!(
                        proof,
                        super::super::sweep_attribution::RangeProof::MapFiles(_)
                    )),
                    "unanswered request proves by userspace: {mapped:?}"
                );
            }
        }
        drop(plans);
        drop(ios);
    } else {
        for (position, mint) in spec.mint.iter().enumerate() {
            let mut io = MemberIo::canned(
                entries[position].clone(),
                provider.identity,
                *mint,
                fallback_reads.clone(),
            );
            let prepared = super::super::sweep_attribution::prepare_confirmation(
                &mut io,
                pids[position],
                &prove_set,
                &mut budget,
                Some(&resources),
            )
            .expect("member request prepares");
            confirmations.push(super::super::confirm_shards::prove_and_finish_prepared(
                &mut io,
                pids[position],
                prepared,
                probe.segment_proof(),
                &resources,
                &mut budget,
            ));
        }
    }
    let attempts = installed.target_attempts;
    let failed_target = installed.failed_target;
    let binding_valid = installed.session.binding.is_some();
    let per_pid = installed
        .session
        .fallback
        .current
        .as_ref()
        .map(|pass| pass.per_pid.clone())
        .unwrap_or_default();
    drop(installed);
    let fallback = session.fallback_totals();
    let trace = runs.lock().unwrap();
    let observation = MemberObservation {
        confirmations,
        answers,
        pids,
        attempts,
        failed_target,
        fallback,
        tids: trace.tids.clone(),
        pidfds: trace.pidfds.clone(),
        scopes: trace.scopes.clone(),
        config_writes: trace.config_writes.clone(),
        per_pid,
        binding_valid,
        fallback_reads: fallback_reads.borrow().clone(),
    };
    drop(children);
    observation
}

#[test]
fn tid_run_encoding_uses_tid_only() {
    let out = member_cell(MemberCellSpec {
        mint: vec![true],
        outcomes: vec![MemberOutcome::Slot],
        threshold: None,
        fail_config: false,
        multi: false,
    });
    assert_eq!(out.confirmations.len(), 1);
    assert_kernel_slot(&out.confirmations[0], Slot(0));
    // The run carried the member's (tgid, tid) with no pidfd and no
    // scope write: TID selection only.
    assert_eq!(out.tids.len(), 1);
    let (tgid, tid) = out.tids[0].expect("member run records its target");
    assert_eq!(tgid, tid, "leader-as-member fixture");
    assert_eq!(out.pidfds, [None]);
    // The run executed under the stale install scope (the observer),
    // never a replaced batch scope: member runs write no scope.
    assert_eq!(out.scopes, [BTreeSet::from([std::process::id()])]);
    assert_ne!(out.pids[0], std::process::id());
    assert_eq!(out.attempts, 1);
    assert!(out.failed_target.is_none());
    // Exactly one config write plus its reset: install, target, zeroed.
    assert_eq!(out.config_writes.len(), 3);
    let install = &out.config_writes[0];
    assert_eq!((install.target_tgid, install.target_tid), (0, 0));
    let target = &out.config_writes[1];
    assert_eq!(target.generation, 1);
    assert_eq!((target.target_tgid, target.target_tid), (tgid, tid));
    assert_eq!(target.observer_tgid, std::process::id());
    let reset = &out.config_writes[2];
    assert_eq!((reset.target_tgid, reset.target_tid), (0, 0));
    assert!(out.fallback.passes == 0 && out.fallback.pids == 0 && out.fallback.keys == 0);
    assert!(out.fallback.first_reason.is_none());
    assert!(out.fallback_reads.is_empty(), "no userspace proof reads");
}

#[test]
fn tid_run_zeroes_target_fields_on_other_runs() {
    let out = member_cell(MemberCellSpec {
        mint: vec![false, true, false],
        outcomes: vec![
            MemberOutcome::Slot,
            MemberOutcome::Slot,
            MemberOutcome::Slot,
        ],
        threshold: None,
        fail_config: false,
        multi: false,
    });
    assert_eq!(out.confirmations.len(), 3);
    for confirmation in &out.confirmations {
        assert_kernel_slot(confirmation, Slot(0));
    }
    // Only the member run selected by TID; the ordinary runs wrote
    // scope instead and never touched the target fields.
    assert_eq!(out.tids.len(), 3);
    assert!(out.tids[0].is_none() && out.tids[2].is_none());
    assert!(out.tids[1].is_some());
    assert_eq!(out.pidfds, [None, None, None]);
    // Ordinary runs replace the scope; the member run in the middle
    // executed under the stale first scope and replaced nothing.
    assert_eq!(
        out.scopes,
        [
            BTreeSet::from([out.pids[0]]),
            BTreeSet::from([out.pids[0]]),
            BTreeSet::from([out.pids[2]]),
        ]
    );
    assert_eq!(out.config_writes.len(), 3, "ordinaries add no config write");
    for (position, config) in out.config_writes.iter().enumerate() {
        if position == 1 {
            assert_ne!(
                (config.target_tgid, config.target_tid),
                (0, 0),
                "the member write names its target"
            );
        } else {
            assert_eq!((config.target_tgid, config.target_tid), (0, 0));
        }
    }
    assert_eq!(out.attempts, 3);
}

#[test]
fn zombie_request_in_batch_is_named_zombie_batch_fallback() {
    let out = member_cell(MemberCellSpec {
        mint: vec![true, false],
        outcomes: vec![MemberOutcome::Slot, MemberOutcome::Slot],
        threshold: None,
        fail_config: false,
        multi: true,
    });
    assert_eq!(out.answers.len(), 2);
    // The zombie-group request cannot run inside a shared batch: it
    // answers nothing and falls back under its own name, while the
    // ordinary request still proves by kernel.
    assert!(
        out.answers[0].is_none(),
        "zombie request answers nothing in a shared batch"
    );
    let ordinary = out.answers[1].as_ref().expect("ordinary request proves");
    assert!(
        ordinary.values().all(|proof| {
            *proof == super::super::sweep_attribution::RangeProof::Kernel(Slot(0))
        }),
        "ordinary request still proves by kernel: {ordinary:?}"
    );
    assert_eq!(out.tids, [None], "the shared run is not a TID run");
    assert_eq!(out.attempts, 1);
    // The name stays in the oracle: per-request ZombieBatch with its
    // label, while the surfaced first reason never carries it.
    let (zombie_pid, _) = out
        .per_pid
        .iter()
        .find(|(_, reason)| **reason == KernelFallbackReason::ZombieBatch)
        .expect("zombie request named in the oracle");
    assert_eq!(KernelFallbackReason::ZombieBatch.label(), "zombie_batch");
    assert!(
        out.fallback_reads
            .iter()
            .any(|(pid, _, _)| pid == zombie_pid),
        "zombie request falls back to userspace proof"
    );
    assert_eq!(out.fallback.passes, 1);
    assert_eq!(out.fallback.pids, 1);
    assert_eq!(out.fallback.keys, 1);
    assert_ne!(
        out.fallback.first_reason,
        Some(KernelFallbackReason::ZombieBatch),
        "zombie_batch never surfaces: {:?}",
        out.fallback.first_reason
    );
}

#[test]
fn auto_single_member_run_is_below_threshold() {
    let out = member_cell(MemberCellSpec {
        mint: vec![true],
        outcomes: vec![MemberOutcome::Slot],
        threshold: Some(2_400),
        fail_config: false,
        multi: false,
    });
    // A single member run never clears the auto gate: no run, no
    // target write, userspace proof under the threshold name.
    assert_eq!(
        out.fallback.first_reason,
        Some(KernelFallbackReason::BelowThreshold)
    );
    assert_eq!(
        KernelFallbackReason::BelowThreshold.label(),
        "below_threshold"
    );
    assert_eq!(out.attempts, 0);
    assert!(out.tids.is_empty(), "no run was attempted");
    assert_eq!(out.config_writes.len(), 1, "install only");
    assert_eq!(
        (
            out.config_writes[0].target_tgid,
            out.config_writes[0].target_tid
        ),
        (0, 0)
    );
    assert_eq!(out.confirmations.len(), 1);
    assert_userspace_mapped(&out.confirmations[0]);
    assert!(
        !out.fallback_reads.is_empty(),
        "userspace proved the ranges"
    );
}

#[test]
fn forced_kernel_member_run_is_positive() {
    let out = member_cell(MemberCellSpec {
        mint: vec![true],
        outcomes: vec![MemberOutcome::Slot],
        threshold: None,
        fail_config: false,
        multi: false,
    });
    assert_eq!(out.confirmations.len(), 1);
    assert_kernel_slot(&out.confirmations[0], Slot(0));
    assert_eq!(out.attempts, 1);
    assert!(out.failed_target.is_none());
    assert!(out.per_pid.is_empty(), "no per-request fallback");
    assert!(out.fallback.passes == 0 && out.fallback.pids == 0 && out.fallback.keys == 0);
    assert!(out.fallback.first_reason.is_none());
    assert_eq!(out.tids.len(), 1);
    assert!(out.tids[0].is_some());
    assert!(out.fallback_reads.is_empty(), "no userspace proof reads");
}

#[test]
fn member_run_attempt_cap_counts_target_runs() {
    // Three member runs reach the cap; the fourth falls back under the
    // attempt name without attempting.
    let capped = member_cell(MemberCellSpec {
        mint: vec![true, true, true, true],
        outcomes: vec![
            MemberOutcome::Slot,
            MemberOutcome::Slot,
            MemberOutcome::Slot,
            MemberOutcome::Slot,
        ],
        threshold: None,
        fail_config: false,
        multi: false,
    });
    assert_eq!(capped.confirmations.len(), 4);
    for confirmation in &capped.confirmations[..3] {
        assert_kernel_slot(confirmation, Slot(0));
    }
    assert_userspace_mapped(&capped.confirmations[3]);
    assert_eq!(capped.attempts, 3);
    assert!(capped.failed_target.is_none(), "the cap is not a failure");
    assert_eq!(capped.tids.len(), 3, "the fourth run never attempted");
    assert_eq!(
        capped.fallback.first_reason,
        Some(KernelFallbackReason::TargetLimit)
    );
    assert_eq!(KernelFallbackReason::TargetLimit.label(), "fd_headroom");
    assert_eq!(
        KernelFallbackReason::TargetLimit.detail(),
        Some("target_run_limit")
    );
    // A failed member attempt demotes later segments instead.
    let demoted = member_cell(MemberCellSpec {
        mint: vec![true, true, true],
        outcomes: vec![
            MemberOutcome::Slot,
            MemberOutcome::Failure(RunFailure::AttachOrRead),
            MemberOutcome::Slot,
        ],
        threshold: None,
        fail_config: false,
        multi: false,
    });
    assert_kernel_slot(&demoted.confirmations[0], Slot(0));
    assert_userspace_mapped(&demoted.confirmations[1]);
    assert_userspace_mapped(&demoted.confirmations[2]);
    assert_eq!(demoted.attempts, 2);
    assert_eq!(demoted.failed_target, Some(RunFailure::AttachOrRead));
    assert_eq!(demoted.tids.len(), 2, "the demoted run never attempted");
    assert_eq!(
        demoted.fallback.first_reason,
        Some(KernelFallbackReason::TargetUnavailable)
    );
}

#[test]
fn failed_config_write_invalidates_binding() {
    let out = member_cell(MemberCellSpec {
        mint: vec![true, false],
        outcomes: vec![MemberOutcome::Slot, MemberOutcome::Slot],
        threshold: None,
        fail_config: true,
        multi: false,
    });
    // The failed target write invalidates the binding: both the member
    // prove and the later ordinary prove fall back, with no attempts.
    assert_eq!(out.confirmations.len(), 2);
    for confirmation in &out.confirmations {
        assert_userspace_mapped(confirmation);
    }
    assert_eq!(out.fallback.first_reason, Some(KernelFallbackReason::Scope));
    assert!(!out.binding_valid, "binding invalidated");
    assert_eq!(out.attempts, 0);
    assert!(out.tids.is_empty(), "no run was attempted");
    assert_eq!(
        out.config_writes.len(),
        2,
        "install plus the failed target write"
    );
    assert_ne!(
        (
            out.config_writes[1].target_tgid,
            out.config_writes[1].target_tid
        ),
        (0, 0),
        "the failed write named its target"
    );
}

#[test]
fn fd_headroom_member_refusal_resets_target_before_ordinary_run() {
    let out = member_cell(MemberCellSpec {
        mint: vec![true, false],
        outcomes: vec![
            MemberOutcome::Failure(RunFailure::FdHeadroom),
            MemberOutcome::Slot,
        ],
        threshold: None,
        fail_config: false,
        multi: false,
    });
    assert_eq!(out.confirmations.len(), 2);
    // The refused member run falls back without attempting; the
    // ordinary run still proves by kernel.
    assert_userspace_mapped(&out.confirmations[0]);
    assert_kernel_slot(&out.confirmations[1], Slot(0));
    assert_eq!(out.attempts, 1, "the refusal is not an attempt");
    assert!(out.failed_target.is_none(), "no demotion");
    assert_eq!(out.tids.len(), 2);
    let (tgid, tid) = out.tids[0].expect("the member run selected by TID");
    assert!(out.tids[1].is_none(), "the ordinary run selects by scope");
    // The member write named its target, so the reset below pins a
    // real installed target rather than a vacuous zero.
    assert!(
        out.config_writes.len() >= 2,
        "install plus the member target write"
    );
    assert_eq!(
        (
            out.config_writes[1].target_tgid,
            out.config_writes[1].target_tid
        ),
        (tgid, tid),
        "the member write named its target"
    );
    // The refusal reset the target before the ordinary run: the
    // trailing write zeroes it, so the ordinary run executes under
    // no member target. Ordinaries add no config write, so the reset
    // precedes the ordinary run.
    let last = out.config_writes.last().expect("the install wrote");
    assert_eq!(
        (last.target_tgid, last.target_tid),
        (0, 0),
        "the trailing config write zeroes the member target"
    );
    assert_eq!(
        out.config_writes.len(),
        3,
        "install, member target, then the refusal reset"
    );
}

/// A member-carrying preparation whose member re-proof refuses while
/// the IO exe answers the same identity is NOT confirmed. The member
/// is the only exe authority when one is carried: after a same-binary
/// nonleader exec the survivor's TID is released (re-proof refuses)
/// while the TGID exe serves the same binary, and falling back to it
/// would confirm on pre-exec proofs.
#[test]
fn refused_member_exe_with_matching_io_exe_is_not_confirmed() {
    use super::super::sweep_attribution::{finish_confirmation, prepare_confirmation};
    let child = SleepChild::spawn();
    let pid = child.pid();
    let mut budget = crate::discovery::scan::CaptureWorkBudget::default();
    let mut io = MemberIo::canned(
        vec![],
        FileIdentity { dev: 1, ino: 2 },
        true,
        Rc::new(RefCell::new(vec![])),
    );
    let prepared = prepare_confirmation(&mut io, pid, &BTreeSet::new(), &mut budget, None)
        .expect("member request prepares");
    assert!(
        prepared.member.is_some(),
        "the preparation carries its member"
    );
    let before = prepared.before.clone();
    // The survivor dies; the member re-proof now refuses.
    drop(child);
    assert!(
        prepared
            .member
            .as_ref()
            .expect("member")
            .read_exe_identity()
            .is_none(),
        "a dead member has no exe"
    );
    // The TGID exe answers the same identity (a live new leader after
    // de_thread serves the same binary): the fallback must not confirm.
    io.exe = before.clone();
    let confirmation = finish_confirmation(
        &io,
        pid,
        prepared,
        MappedIdentities::new(),
        None,
        &mut budget,
    );
    assert!(
        !matches!(confirmation, Confirmation::Confirmed(_)),
        "a refused member exe never confirms, even when the TGID exe agrees: {confirmation:?}"
    );
}

/// A healthy member still confirms at the finish: the member-only exe
/// authority agrees with the preparation read.
#[test]
fn healthy_member_exe_confirms_at_finish() {
    use super::super::sweep_attribution::{finish_confirmation, prepare_confirmation};
    let child = SleepChild::spawn();
    let pid = child.pid();
    let mut budget = crate::discovery::scan::CaptureWorkBudget::default();
    let mut io = MemberIo::canned(
        vec![],
        FileIdentity { dev: 1, ino: 2 },
        true,
        Rc::new(RefCell::new(vec![])),
    );
    let prepared = prepare_confirmation(&mut io, pid, &BTreeSet::new(), &mut budget, None)
        .expect("member request prepares");
    assert!(
        prepared.member.is_some(),
        "the preparation carries its member"
    );
    let confirmation = finish_confirmation(
        &io,
        pid,
        prepared,
        MappedIdentities::new(),
        None,
        &mut budget,
    );
    assert!(
        matches!(confirmation, Confirmation::Confirmed(_)),
        "a healthy member confirms: {confirmation:?}"
    );
    drop(child);
}

/// The `work.check` refusal right after the member-target write resets
/// the target before refusing: the trailing config write zeroes it, so
/// the following ordinary run executes under no member target. Mirrors
/// the FdHeadroom-arm twin; the hook expires the work deadline
/// deterministically between the eligibility check and this one.
#[test]
fn work_check_member_refusal_resets_target_before_ordinary_run() {
    arm_pre_member_check_expiry();
    let out = member_cell(MemberCellSpec {
        mint: vec![true, false],
        outcomes: vec![MemberOutcome::NoRead, MemberOutcome::Slot],
        threshold: None,
        fail_config: false,
        multi: false,
    });
    assert_eq!(out.confirmations.len(), 2);
    // The refused member run falls back without attempting; the
    // ordinary run still proves by kernel.
    assert_userspace_mapped(&out.confirmations[0]);
    assert_kernel_slot(&out.confirmations[1], Slot(0));
    assert_eq!(out.attempts, 1, "the refusal is not an attempt");
    assert!(out.failed_target.is_none(), "no demotion");
    assert_eq!(out.tids.len(), 1, "the refused run never selected");
    assert!(out.tids[0].is_none(), "the ordinary run selects by scope");
    // The member write named its target, so the reset below pins a
    // real installed target rather than a vacuous zero.
    assert!(
        out.config_writes.len() >= 2,
        "install plus the member target write"
    );
    assert_eq!(
        (
            out.config_writes[1].target_tgid,
            out.config_writes[1].target_tid
        ),
        (out.pids[0], out.pids[0]),
        "the member write named its target"
    );
    // The refusal reset the target before the ordinary run: the
    // trailing write zeroes it, so the ordinary run executes under
    // no member target. Ordinaries add no config write, so the reset
    // precedes the ordinary run.
    let last = out.config_writes.last().expect("the install wrote");
    assert_eq!(
        (last.target_tgid, last.target_tid),
        (0, 0),
        "the trailing config write zeroes the member target"
    );
    assert_eq!(
        out.config_writes.len(),
        3,
        "install, member target, then the refusal reset"
    );
    assert_eq!(
        out.fallback.first_reason,
        Some(KernelFallbackReason::Deadline),
        "the refusal names its site: {:?}",
        out.fallback.first_reason
    );
}
