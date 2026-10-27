//! SPDX-License-Identifier: GPL-3.0-or-later
//! D4 population cells: the kernel-positive identity population never
//! counts a provider the capture itself watches. One mixed Btrfs
//! population (a watched and an unwatched provider, each with a live
//! executable caller) runs under the forced kernel backend: the watched
//! anchor is refused as `CaptureWatched` and keeps its edge only through
//! the userspace fallback, while the unwatched provider is a kernel
//! positive with a nonzero target run. Exact edges on both backends.

use super::*;
use std::time::{Duration, Instant};

/// Userspace attribution of one population PID through the production
/// probe. Mirrors `attribute_pid` for pids without a `SwapChild` handle.
fn d4_population_attribute_pid(
    pid: u32,
    snapshot: Vec<MapEntry>,
    index: &KnownKeyIndex,
) -> SweepAttribution {
    attribute_unselected(
        &[(pid, snapshot)],
        &BTreeSet::new(),
        &BTreeSet::new(),
        index,
        &mut OsMemberProbe::default(),
        &mut CaptureWorkBudget::default(),
    )
}

/// Kernel-positive population with active-capture anchor exclusion: two
/// distinct Btrfs providers, one watched by the capture, one not, each
/// with a live executable caller. Under the forced kernel backend the
/// watched anchor is refused (`CaptureWatched`) and its caller keeps its
/// edge only through the `AnchorNotInstalled` userspace fallback (zero
/// kernel target runs for that key, userspace range proofs), while the
/// unwatched caller is a kernel positive (nonzero target runs, zero
/// userspace reads, no fallback). Both backends agree on the exact
/// population edges.
#[test]
#[ignore = "root Btrfs disk TMPDIR plus eligible BTF/task_vma identity; kernel-positive population excludes watched anchors"]
fn privileged_d4_kernel_positive_population_excludes_anchors() {
    use crate::discovery::identity::{PinnedObjects, test_fixture::real_scan_pin};
    use crate::discovery::kernel_identity::{
        AnchorDeny, IdentitySession, KernelAnchorExclusions, KernelFallbackReason,
    };
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt as _;
    use std::sync::{Arc, Mutex};

    crate::attach::identity_iter::ensure_kernel_identity_btf()
        .expect("required kernel identity capability; refusal cannot qualify");
    let btf = aya::Btf::from_sys_fs().expect("readable host BTF");
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path();
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let c_parent = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid path and writable statfs buffer, read only on success.
    assert_eq!(
        unsafe { libc::statfs(c_parent.as_ptr(), stat.as_mut_ptr()) },
        0
    );
    // SAFETY: initialized by the successful statfs above.
    #[allow(clippy::unnecessary_cast)]
    let magic = unsafe { stat.assume_init().f_type } as u64 & 0xffff_ffff;
    assert_eq!(magic, 0x9123_683e, "actual fixture TMPDIR must be Btrfs");

    // Two distinct providers: different bytes and different inodes, so
    // their maps keys differ and no lexical collision is involved. The
    // watched file is the capture's own anchor; the unwatched file is
    // the kernel-positive control.
    let watched_path = parent.join("libwatched.so");
    let plain_path = parent.join("libplain.so");
    std::fs::write(&watched_path, vec![0xa5u8; 8192]).unwrap();
    std::fs::write(&plain_path, vec![0x5cu8; 8192]).unwrap();
    let watched_file = std::fs::File::open(&watched_path).unwrap();
    let plain_file = std::fs::File::open(&plain_path).unwrap();
    let watched_meta = watched_file.metadata().unwrap();
    let plain_meta = plain_file.metadata().unwrap();
    assert_ne!(
        (watched_meta.dev(), watched_meta.ino()),
        (plain_meta.dev(), plain_meta.ino()),
        "population providers share one physical identity"
    );

    let watched_caller = SwapChild::spawn(&watched_path);
    let plain_caller = SwapChild::spawn(&plain_path);
    let watched_snapshot = watched_caller.maps();
    let plain_snapshot = plain_caller.maps();
    fn line_at(snapshot: &[MapEntry], address: u64) -> &MapEntry {
        snapshot
            .iter()
            .find(|entry| entry.start == address)
            .expect("independent live mapping")
    }
    let watched_text = line_at(&watched_snapshot, watched_caller.address);
    let plain_text = line_at(&plain_snapshot, plain_caller.address);
    assert_eq!(watched_text.permissions, *b"r-xp");
    assert_eq!(plain_text.permissions, *b"r-xp");
    let watched_key = ObjectKey::of(watched_text);
    let plain_key = ObjectKey::of(plain_text);
    assert_ne!(
        watched_key, plain_key,
        "population providers collide on one maps key"
    );

    let watched_digest =
        p11scope_manifest::identity::hex(&Sha256::digest(std::fs::read(&watched_path).unwrap()));
    let plain_digest =
        p11scope_manifest::identity::hex(&Sha256::digest(std::fs::read(&plain_path).unwrap()));
    let mut pins: PinnedObjects =
        real_scan_pin(&watched_path, Some(watched_key), 0, &watched_digest);
    let skipped = pins.absorb(real_scan_pin(
        &plain_path,
        Some(plain_key),
        0,
        &plain_digest,
    ));
    assert!(skipped.is_empty(), "{skipped:?}");
    let mut watched_id = None;
    let mut plain_id = None;
    for summary in pins.pinned() {
        if summary.key == watched_key {
            watched_id = Some(summary.id);
        } else if summary.key == plain_key {
            plain_id = Some(summary.id);
        }
    }
    let (watched_id, plain_id) = (
        watched_id.expect("watched pin retained"),
        plain_id.expect("plain pin retained"),
    );
    assert_ne!(watched_id, plain_id, "population pins share one object");

    // The capture watches the watched provider: its retained target
    // excludes the anchor by key and by held file.
    let watched_target = pins.retain_inventory_target(watched_id).unwrap();
    let exclusions = KernelAnchorExclusions::from_targets([&watched_target]);

    let (userspace_index, refused) = KnownKeyIndex::build(
        [(watched_key, Some(watched_id)), (plain_key, Some(plain_id))],
        &BTreeMap::from([(watched_key, watched_id), (plain_key, plain_id)]),
        [],
        &pins,
    );
    assert!(refused.is_empty(), "{refused:?}");
    assert!(
        userspace_index.map_files_keys().contains(&watched_key),
        "Btrfs watched key must require per-range proof"
    );
    assert!(
        userspace_index.map_files_keys().contains(&plain_key),
        "Btrfs plain key must require per-range proof"
    );

    // Userspace baseline: both callers keep their exact edges.
    let userspace_watched = d4_population_attribute_pid(
        watched_caller.pid as u32,
        watched_snapshot.clone(),
        &userspace_index,
    );
    let userspace_plain = d4_population_attribute_pid(
        plain_caller.pid as u32,
        plain_snapshot.clone(),
        &userspace_index,
    );
    for (name, out, pid, key, object) in [
        (
            "userspace watched",
            &userspace_watched,
            watched_caller.pid as u32,
            watched_key,
            watched_id,
        ),
        (
            "userspace plain",
            &userspace_plain,
            plain_caller.pid as u32,
            plain_key,
            plain_id,
        ),
    ] {
        assert_eq!(
            out.members
                .iter()
                .map(|member| member.pid)
                .collect::<Vec<_>>(),
            [pid],
            "{name}: exact caller"
        );
        assert_eq!(
            out.members[0]
                .objects
                .iter()
                .map(|matched| (matched.key, matched.object))
                .collect::<Vec<_>>(),
            [(key, object)],
            "{name}: exact held-provider edge"
        );
        assert!(out.losses.is_empty(), "{name}: {:?}", out.member_losses);
        assert_eq!(out.probed, 1, "{name}: nonempty executable proof demand");
    }

    // Kernel legs under the forced backend (no auto cost gate): the
    // watched pass refuses its anchor, the plain pass installs it.
    let probe_dir = tempfile::tempdir().unwrap();
    let mut session = IdentitySession::probe_and_load(&btf, probe_dir.path())
        .expect("actual strict-loaded kernel session; no refused/fallback positive");

    // Watched leg: one unrelated examined anchor keeps the install
    // alive so the watched key's proof-level fallback is observable;
    // without it the empty arena refuses installation before any proof.
    let kernel_watched = {
        use crate::discovery::kernel_identity::{AnchorPass, ExaminedCustody, KernelMemberProbe};
        let (mut index, refused) = KnownKeyIndex::build(
            [(watched_key, Some(watched_id)), (plain_key, Some(plain_id))],
            &BTreeMap::from([(watched_key, watched_id), (plain_key, plain_id)]),
            [],
            &pins,
        );
        assert!(refused.is_empty(), "{refused:?}");
        let owner = ReservationOwner::for_examined(
            SegmentPolicy::try_snapshot(0, 0).expect("actual FD census"),
            1,
        );
        let mut custody = ExaminedCustody::new(owner, BTreeMap::new());
        let unrelated_path = parent.join("libunrelated.so");
        std::fs::write(&unrelated_path, vec![0x3cu8; 8192]).unwrap();
        let unrelated_file = std::fs::File::open(&unrelated_path).unwrap();
        let unrelated_meta = unrelated_file.metadata().unwrap();
        let unrelated_key = ObjectKey {
            device: watched_key.device,
            inode: unrelated_meta.ino(),
        };
        assert_ne!(unrelated_key, watched_key);
        assert_ne!(unrelated_key, plain_key);
        let scan = custody.begin_scan();
        assert!(
            custody.offer_for_test(
                scan,
                crate::discovery::identity::ExaminedObject {
                    key: unrelated_key,
                    identity: crate::discovery::identity::FileIdentity {
                        dev: unrelated_meta.dev(),
                        ino: unrelated_meta.ino(),
                    },
                    key_is_identity: false,
                },
                unrelated_file,
            ),
            "unrelated examined anchor offers"
        );
        custody
            .reconcile(SegmentPolicy::try_snapshot(1, 1).expect("actual confirmation FD census"))
            .expect("shared physical reservation owner");
        let pass =
            AnchorPass::prepare_excluding(&pins, [(watched_key, watched_id)], custody, &exclusions);
        assert_eq!(
            pass.fallback.get(&watched_key),
            Some(&AnchorDeny::CaptureWatched),
            "watched anchor lacks its CaptureWatched refusal: {:?}",
            pass.fallback
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut installed = session
            .install_anchors(pass, 1, deadline)
            .expect("install watched-excluded anchors");
        let trace = Arc::new(Mutex::new(ProofTrace::default()));
        let bpf_before = crate::attach::identity_iter::test_bpf_call_count();
        let out = {
            let mut probe = KernelMemberProbe::new(
                &mut installed,
                OsConfirmIo::with_pool(None).observing(trace.clone()),
                deadline,
            );
            probe
                .install_expectations(&mut index)
                .expect("watched-excluded expectations install");
            assert!(
                !index
                    .match_slots
                    .get(&watched_key)
                    .is_some_and(|slots| !slots.is_empty()),
                "watched key gained kernel slots"
            );
            let mut budget = CaptureWorkBudget::default();
            assert!(
                !budget.has_collection_work(),
                "exercise actual kernel proof, not scoped fallback"
            );
            attribute_unselected(
                &[(watched_caller.pid as u32, watched_snapshot.clone())],
                &BTreeSet::new(),
                &BTreeSet::new(),
                &index,
                &mut probe,
                &mut budget,
            )
        };
        let bpf_delta = crate::attach::identity_iter::test_bpf_call_count() - bpf_before;
        let reads = trace.lock().unwrap().reads.clone();
        drop(installed);
        let fallback = session.fallback_totals();
        (out, reads, bpf_delta, fallback)
    };
    let (kernel_watched_out, watched_reads, watched_bpf, watched_fallback) = kernel_watched;
    assert_eq!(
        kernel_watched_out
            .members
            .iter()
            .map(|member| member.pid)
            .collect::<Vec<_>>(),
        [watched_caller.pid as u32],
        "kernel watched: exact caller through the userspace fallback"
    );
    assert_eq!(
        kernel_watched_out.members[0]
            .objects
            .iter()
            .map(|matched| (matched.key, matched.object))
            .collect::<Vec<_>>(),
        [(watched_key, watched_id)],
        "kernel watched: exact held-provider edge through the fallback"
    );
    assert!(
        kernel_watched_out.losses.is_empty(),
        "kernel watched: {:?}",
        kernel_watched_out.member_losses
    );
    assert_eq!(
        kernel_watched_out.probed, 1,
        "kernel watched: nonempty executable proof demand"
    );
    assert_eq!(
        kernel_watched_out.members, userspace_watched.members,
        "watched: exact backend members"
    );
    assert_eq!(
        kernel_watched_out.losses, userspace_watched.losses,
        "watched: same loss classifications"
    );
    assert!(
        !watched_reads.is_empty(),
        "watched kernel leg proved without userspace range reads"
    );
    assert_eq!(
        watched_bpf, 0,
        "watched leg ran {watched_bpf} bpf() calls: a target ran"
    );
    assert_eq!(
        watched_fallback,
        crate::discovery::kernel_identity::KernelFallbackTotals {
            passes: 1,
            pids: 1,
            keys: 1,
            first_reason: Some(KernelFallbackReason::AnchorNotInstalled),
        },
        "watched leg misclassified: {watched_fallback:?}"
    );

    // Plain leg: a kernel positive with a nonzero target run.
    let kernel_plain = {
        use crate::discovery::kernel_identity::{AnchorPass, ExaminedCustody, KernelMemberProbe};
        let (mut index, refused) = KnownKeyIndex::build(
            [(watched_key, Some(watched_id)), (plain_key, Some(plain_id))],
            &BTreeMap::from([(watched_key, watched_id), (plain_key, plain_id)]),
            [],
            &pins,
        );
        assert!(refused.is_empty(), "{refused:?}");
        let owner = ReservationOwner::for_examined(
            SegmentPolicy::try_snapshot(0, 0).expect("actual FD census"),
            0,
        );
        let mut custody = ExaminedCustody::new(owner, BTreeMap::new());
        custody
            .reconcile(SegmentPolicy::try_snapshot(1, 1).expect("actual confirmation FD census"))
            .expect("shared physical reservation owner");
        let pass =
            AnchorPass::prepare_excluding(&pins, [(plain_key, plain_id)], custody, &exclusions);
        assert!(
            pass.fallback.is_empty(),
            "plain provider refused: {:?}",
            pass.fallback
        );
        assert!(
            !pass.only_capture_excluded(),
            "plain pass claims capture exclusion"
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut installed = session
            .install_anchors(pass, 2, deadline)
            .expect("install plain anchors");
        let trace = Arc::new(Mutex::new(ProofTrace::default()));
        let bpf_before = crate::attach::identity_iter::test_bpf_call_count();
        let out = {
            let mut probe = KernelMemberProbe::new(
                &mut installed,
                OsConfirmIo::with_pool(None).observing(trace.clone()),
                deadline,
            );
            probe
                .install_expectations(&mut index)
                .expect("actual validated anchor expectations");
            assert!(
                index
                    .match_slots
                    .get(&plain_key)
                    .is_some_and(|slots| !slots.is_empty()),
                "the held plain provider has no validated actual kernel slot"
            );
            let mut budget = CaptureWorkBudget::default();
            assert!(
                !budget.has_collection_work(),
                "exercise actual kernel proof, not scoped fallback"
            );
            attribute_unselected(
                &[(plain_caller.pid as u32, plain_snapshot.clone())],
                &BTreeSet::new(),
                &BTreeSet::new(),
                &index,
                &mut probe,
                &mut budget,
            )
        };
        let bpf_delta = crate::attach::identity_iter::test_bpf_call_count() - bpf_before;
        let reads = trace.lock().unwrap().reads.clone();
        drop(installed);
        let fallback = session.fallback_totals();
        (out, reads, bpf_delta, fallback)
    };
    let (kernel_plain_out, plain_reads, plain_bpf, plain_fallback) = kernel_plain;
    assert_eq!(
        kernel_plain_out
            .members
            .iter()
            .map(|member| member.pid)
            .collect::<Vec<_>>(),
        [plain_caller.pid as u32],
        "kernel plain: exact caller"
    );
    assert_eq!(
        kernel_plain_out.members[0]
            .objects
            .iter()
            .map(|matched| (matched.key, matched.object))
            .collect::<Vec<_>>(),
        [(plain_key, plain_id)],
        "kernel plain: exact held-provider edge"
    );
    assert!(
        kernel_plain_out.losses.is_empty(),
        "kernel plain: {:?}",
        kernel_plain_out.member_losses
    );
    assert_eq!(
        kernel_plain_out.probed, 1,
        "kernel plain: nonempty executable proof demand"
    );
    assert_eq!(
        kernel_plain_out.members, userspace_plain.members,
        "plain: exact backend members"
    );
    assert_eq!(
        kernel_plain_out.losses, userspace_plain.losses,
        "plain: same loss classifications"
    );
    assert!(
        plain_reads.is_empty(),
        "the required kernel leg performed userspace range-proof reads: {plain_reads:?}"
    );
    assert!(
        plain_bpf > 0,
        "plain leg ran zero bpf() calls: no target ran"
    );
    // The session ledger still carries only the watched fallback: the
    // plain pass added zero at every unit.
    assert_eq!(
        plain_fallback, watched_fallback,
        "plain pass disclosed fallback: {plain_fallback:?} vs {watched_fallback:?}"
    );

    eprintln!(
        "D4_POPULATION watched={} plain={} userspace=1/1 kernel=1/1 \
         watched_fallback=anchor_not_installed watched_bpf=0 plain_bpf={plain_bpf}",
        watched_caller.pid, plain_caller.pid
    );
    drop((watched_caller, plain_caller));
    drop((session, pins, watched_file, plain_file));
    std::fs::remove_file(&watched_path).unwrap();
    std::fs::remove_file(&plain_path).unwrap();
    std::fs::remove_file(parent.join("libunrelated.so")).unwrap();
}
