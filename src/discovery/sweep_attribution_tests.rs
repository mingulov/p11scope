//! SPDX-License-Identifier: GPL-3.0-or-later
//! C1b pure-core tests: more processes than the deep-scan cap, many
//! identical callers, and every confirmation and identity hazard.

use super::*;
use crate::discovery::engine::select_deep_scan_candidates;
use p11scope_manifest::maps::Device;
use std::cell::RefCell;
use std::collections::HashMap;

const PROVIDER: u64 = 7_001;
const LIBC: u64 = 7_002;

fn key(inode: u64) -> ObjectKey {
    ObjectKey {
        device: Device { major: 8, minor: 1 },
        inode,
    }
}

fn mapping(start: u64, perms: &[u8; 4], inode: u64, path: &str) -> MapEntry {
    MapEntry {
        start,
        end: start + 0x1000,
        file_offset: 0,
        permissions: *perms,
        device: Device { major: 8, minor: 1 },
        inode,
        raw_path: Some(path.as_bytes().to_vec()),
    }
}

/// One object's loader mappings: a read-only header and the text segment.
fn object(base: u64, inode: u64, path: &str) -> Vec<MapEntry> {
    let mut text = mapping(base + 0x1000, b"r-xp", inode, path);
    text.file_offset = 0x1000;
    vec![mapping(base, b"r--p", inode, path), text]
}

fn provider_caller() -> Vec<MapEntry> {
    let mut entries = object(0x1000_0000, PROVIDER, "/usr/lib/softhsm/libsofthsm2.so");
    entries.extend(object(0x2000_0000, LIBC, "/usr/lib/libc.so.6"));
    entries
}

fn idle(unique: Option<u64>) -> Vec<MapEntry> {
    let mut entries = object(0x2000_0000, LIBC, "/usr/lib/libc.so.6");
    if let Some(inode) = unique {
        entries.extend(object(
            0x3000_0000,
            inode,
            &format!("/usr/lib/libu{inode}.so"),
        ));
    }
    entries
}

fn exe() -> ExeIdentity {
    ExeIdentity {
        dev: 1,
        ino: 100,
        mtime_secs: 10,
        mtime_nanos: 0,
        path: Some("/usr/bin/caller".into()),
    }
}

/// Every object passes both checks unless scripted otherwise.
#[derive(Default)]
struct Checks {
    nonunique: BTreeMap<PinnedObjectId, &'static str>,
    changed: BTreeSet<PinnedObjectId>,
    checked: RefCell<Vec<PinnedObjectId>>,
}

impl ObjectChecks for Checks {
    fn nonunique_inodes(&self, object: PinnedObjectId) -> Result<Option<&'static str>, String> {
        Ok(self.nonunique.get(&object).copied())
    }

    fn unchanged(&self, object: PinnedObjectId) -> Result<bool, String> {
        self.checked.borrow_mut().push(object);
        Ok(!self.changed.contains(&object))
    }
}

/// Scripted confirmations: by default each pid confirms its phase-1
/// snapshot under one start time; overrides script the hazards.
struct Probe {
    snapshots: HashMap<u32, Vec<MapEntry>>,
    overrides: HashMap<u32, Confirmation>,
    calls: Vec<u32>,
}

impl Probe {
    fn over(sweep: &[(u32, Vec<MapEntry>)]) -> Self {
        Self {
            snapshots: sweep.iter().cloned().collect(),
            overrides: HashMap::new(),
            calls: Vec::new(),
        }
    }
}

impl MemberProbe for Probe {
    fn confirm(&mut self, pid: u32, _: &mut CaptureWorkBudget) -> Confirmation {
        self.calls.push(pid);
        if let Some(scripted) = self.overrides.get(&pid) {
            return scripted.clone();
        }
        Confirmation::Confirmed(ConfirmedRead {
            start_time: 5_000 + u64::from(pid),
            exe: exe(),
            entries: self.snapshots.get(&pid).cloned().unwrap_or_default(),
        })
    }
}

const OBJECT: PinnedObjectId = PinnedObjectId(3);

/// The index a deep scan of one provider caller builds: the provider key
/// bound to `OBJECT` and libc examined without a module.
fn provider_index(checks: &Checks) -> KnownKeyIndex {
    let rep = provider_caller();
    let match_keys = BTreeMap::from([(key(PROVIDER), OBJECT)]);
    KnownKeyIndex::build([(key(PROVIDER), Some(OBJECT))], &match_keys, &rep, checks).0
}

fn run(
    sweep: &[(u32, Vec<MapEntry>)],
    selected: &BTreeSet<u32>,
    index: &KnownKeyIndex,
    probe: &mut Probe,
) -> SweepAttribution {
    attribute_unselected(
        sweep,
        &BTreeSet::new(),
        selected,
        index,
        probe,
        &mut CaptureWorkBudget::default(),
    )
}

#[test]
fn cap_448_with_300_identical_callers_attributes_all_300() {
    // 448 processes over a 256 cap: 300 identical SoftHSM2 callers and 148
    // idle processes each with one unique library.
    let mut sweep: Vec<(u32, Vec<MapEntry>)> = (0..300)
        .map(|index| (10_000 + index, provider_caller()))
        .collect();
    sweep.extend((0..148).map(|index| (20_000 + index, idle(Some(90_000 + u64::from(index))))));
    assert_eq!(sweep.len(), 448);
    let selected: BTreeSet<u32> = select_deep_scan_candidates(&sweep, 256)
        .into_iter()
        .collect();
    // One representative per provider group: the 300 callers send one.
    let reps: Vec<u32> = selected
        .iter()
        .copied()
        .filter(|pid| (10_000..10_300).contains(pid))
        .collect();
    assert_eq!(reps, vec![10_000], "one deep-scanned representative");
    // The deep scans examined every selected snapshot completely.
    let examined: Vec<&MapEntry> = sweep
        .iter()
        .filter(|(pid, _)| selected.contains(pid))
        .flat_map(|(_, entries)| entries)
        .collect();
    let checks = Checks::default();
    let match_keys = BTreeMap::from([(key(PROVIDER), OBJECT)]);
    let (index, refused) = KnownKeyIndex::build(
        [(key(PROVIDER), Some(OBJECT))],
        &match_keys,
        examined,
        &checks,
    );
    assert!(refused.is_empty());
    let mut probe = Probe::over(&sweep);
    let attribution = run(&sweep, &selected, &index, &mut probe);
    let mut attributed: BTreeSet<u32> = attribution.members.iter().map(|m| m.pid).collect();
    attributed.extend(reps);
    assert_eq!(
        attributed,
        (10_000..10_300).collect::<BTreeSet<u32>>(),
        "every identical caller is attributed: the deep-scanned one plus 299 by maps"
    );
    for member in &attribution.members {
        assert_eq!(member.objects.len(), 1, "{member:?}");
        assert_eq!(member.objects[0].object, OBJECT);
        assert_eq!(member.objects[0].key, key(PROVIDER));
        assert_eq!(member.objects[0].path, "/usr/lib/softhsm/libsofthsm2.so");
        assert_eq!(member.start_time, 5_000 + u64::from(member.pid));
        assert_eq!(member.unexamined, 0);
    }
    assert!(
        attribution.unexamined.is_empty(),
        "{:?}",
        attribution.unexamined
    );
    assert!(attribution.losses.is_empty(), "{:?}", attribution.losses);
    // Only phase-1 matches are confirmed: idle processes are never probed.
    assert_eq!(attribution.probed, 299);
    assert!(probe.calls.iter().all(|pid| (10_001..10_300).contains(pid)));
}

#[test]
fn groups_past_the_cap_leave_unexamined_keys_and_no_match() {
    // Cap 64: the 148 rarer unique-library groups fill the deep-scan slots,
    // so the provider group sends no representative and nothing is pinned.
    let mut sweep: Vec<(u32, Vec<MapEntry>)> = (0..300)
        .map(|index| (10_000 + index, provider_caller()))
        .collect();
    sweep.extend((0..148).map(|index| (20_000 + index, idle(Some(90_000 + u64::from(index))))));
    let selected: BTreeSet<u32> = select_deep_scan_candidates(&sweep, 64)
        .into_iter()
        .collect();
    assert!(!selected.contains(&10_000));
    let examined: Vec<&MapEntry> = sweep
        .iter()
        .filter(|(pid, _)| selected.contains(pid))
        .flat_map(|(_, entries)| entries)
        .collect();
    let checks = Checks::default();
    let (index, _) = KnownKeyIndex::build([], &BTreeMap::new(), examined, &checks);
    let mut probe = Probe::over(&sweep);
    let attribution = run(&sweep, &selected, &index, &mut probe);
    assert!(attribution.members.is_empty());
    assert_eq!(
        attribution.probed, 0,
        "no phase-1 match, no confirmation read"
    );
    // Every provider caller maps one unexamined key (the provider); every
    // unselected unique-library process maps its own unexamined library.
    let unselected_idle = 148 - selected.len();
    assert_eq!(attribution.unexamined.len(), 300 + unselected_idle);
    assert!(attribution.unexamined.values().all(|count| *count == 1));
    // Distinct objects: the provider plus each unselected unique library.
    assert_eq!(attribution.unexamined_keys(), 1 + unselected_idle);
}

#[test]
fn a_matched_member_still_counts_keys_no_deep_scan_examined() {
    let checks = Checks::default();
    let index = provider_index(&checks);
    let mut extra = provider_caller();
    extra.extend(object(0x4000_0000, 88, "/opt/unknown/libother.so"));
    let sweep = vec![(10_001, extra)];
    let mut probe = Probe::over(&sweep);
    let attribution = run(&sweep, &BTreeSet::new(), &index, &mut probe);
    assert_eq!(attribution.members.len(), 1);
    assert_eq!(attribution.members[0].unexamined, 1);
    assert_eq!(attribution.unexamined, BTreeMap::from([(10_001, 1)]));
}

#[test]
fn index_keys_only_one_pinned_non_rejected_object_bound_this_pass() {
    let checks = Checks::default();
    let match_keys = BTreeMap::from([
        (key(1), PinnedObjectId(1)),
        (key(4), PinnedObjectId(4)),
        (key(5), PinnedObjectId(5)),
    ]);
    let examined = object(0x5000_0000, 9, "/usr/lib/libexamined.so");
    let (index, _) = KnownKeyIndex::build(
        [
            (key(1), Some(PinnedObjectId(1))),
            // No comparable pin (an unbound module).
            (key(2), None),
            // Bound, but not a sweep-matching key (rejected, collapsed, or
            // an alias): the aggregate refused it.
            (key(3), Some(PinnedObjectId(3))),
            // Bound to one ID by one view and another by a second view.
            (key(4), Some(PinnedObjectId(4))),
            (key(4), Some(PinnedObjectId(6))),
            // Bound by one view, unbound by another.
            (key(5), Some(PinnedObjectId(5))),
            (key(5), None),
        ],
        &match_keys,
        &examined,
        &checks,
    );
    assert_eq!(index.classify(key(1)), KeyClass::Match(PinnedObjectId(1)));
    for rejected in [2, 3, 4, 5] {
        assert_eq!(
            index.classify(key(rejected)),
            KeyClass::Ineligible(AttributionLoss::KeyRejected),
            "key {rejected}"
        );
    }
    assert_eq!(index.classify(key(9)), KeyClass::Examined);
    assert_eq!(index.classify(key(10)), KeyClass::Unexamined);
}

#[test]
fn nonunique_inode_filesystems_refuse_sweep_matching_with_a_named_object() {
    let checks = Checks {
        nonunique: BTreeMap::from([(OBJECT, "fuse")]),
        ..Checks::default()
    };
    let match_keys = BTreeMap::from([(key(PROVIDER), OBJECT)]);
    let (index, refused) =
        KnownKeyIndex::build([(key(PROVIDER), Some(OBJECT))], &match_keys, &[], &checks);
    assert_eq!(
        refused,
        vec![RefusedObject {
            object: OBJECT,
            key: key(PROVIDER),
            filesystem: "fuse",
        }]
    );
    let sweep = vec![(10_001, provider_caller())];
    let mut probe = Probe::over(&sweep);
    let attribution = run(&sweep, &BTreeSet::new(), &index, &mut probe);
    assert!(attribution.members.is_empty());
    assert_eq!(
        attribution.losses,
        BTreeMap::from([(AttributionLoss::InodeNotUnique, 1)])
    );
    assert_eq!(probe.calls, Vec::<u32>::new());
}

#[test]
fn ineligible_keys_are_counted_losses_never_matches() {
    let checks = Checks::default();
    let (index, _) = KnownKeyIndex::build(
        [(key(PROVIDER), Some(OBJECT))],
        &BTreeMap::new(),
        &provider_caller(),
        &checks,
    );
    let sweep = vec![(10_001, provider_caller()), (10_002, provider_caller())];
    let mut probe = Probe::over(&sweep);
    let attribution = run(&sweep, &BTreeSet::new(), &index, &mut probe);
    assert!(attribution.members.is_empty());
    assert_eq!(
        attribution.losses,
        BTreeMap::from([(AttributionLoss::KeyRejected, 2)])
    );
    assert_eq!(
        attribution
            .member_losses
            .get(&10_001)
            .map(|(loss, _)| *loss),
        Some(AttributionLoss::KeyRejected)
    );
}

#[test]
fn the_confirmation_snapshot_attributes_never_the_phase_one_snapshot() {
    let checks = Checks::default();
    let index = provider_index(&checks);
    let sweep = vec![
        (10_001, provider_caller()),
        (10_002, provider_caller()),
        (10_003, provider_caller()),
    ];
    let mut probe = Probe::over(&sweep);
    // 10_001 unloaded the provider before its confirmation read.
    probe.snapshots.insert(10_001, idle(None));
    // 10_002's generation turned over between the reads.
    probe.overrides.insert(
        10_002,
        Confirmation::Lost(AttributionLoss::GenerationChanged, "reused".into()),
    );
    let attribution = run(&sweep, &BTreeSet::new(), &index, &mut probe);
    let pids: Vec<u32> = attribution.members.iter().map(|m| m.pid).collect();
    assert_eq!(pids, vec![10_003]);
    assert_eq!(
        attribution.losses,
        BTreeMap::from([(AttributionLoss::GenerationChanged, 1)])
    );
    assert!(
        !attribution.member_losses.contains_key(&10_001),
        "an unload before the confirmation is not a loss"
    );
    assert_eq!(attribution.probed, 3);
}

#[test]
fn an_exit_before_confirmation_is_silent_not_a_loss() {
    let checks = Checks::default();
    let index = provider_index(&checks);
    let sweep = vec![(10_001, provider_caller())];
    let mut probe = Probe::over(&sweep);
    probe.overrides.insert(10_001, Confirmation::Exited);
    let attribution = run(&sweep, &BTreeSet::new(), &index, &mut probe);
    assert!(attribution.members.is_empty());
    assert!(attribution.losses.is_empty());
    assert_eq!(attribution.exited, BTreeSet::from([10_001]));
}

#[test]
fn deleted_mappings_never_match_and_are_named_losses() {
    let checks = Checks::default();
    let index = provider_index(&checks);
    let deleted: Vec<MapEntry> = object(
        0x1000_0000,
        PROVIDER,
        "/usr/lib/softhsm/libsofthsm2.so (deleted)",
    )
    .into_iter()
    .chain(object(0x2000_0000, LIBC, "/usr/lib/libc.so.6"))
    .collect();
    // Phase 1 already shows the deletion: no confirmation is needed.
    let sweep = vec![(10_001, deleted.clone()), (10_002, provider_caller())];
    let mut probe = Probe::over(&sweep);
    // 10_002's object is replaced between phase 1 and its confirmation.
    probe.snapshots.insert(10_002, deleted);
    let attribution = run(&sweep, &BTreeSet::new(), &index, &mut probe);
    assert!(attribution.members.is_empty(), "{:?}", attribution.members);
    assert_eq!(
        attribution.losses,
        BTreeMap::from([(AttributionLoss::DeletedMapping, 2)])
    );
}

#[test]
fn matching_is_by_device_and_inode_never_by_path() {
    let checks = Checks::default();
    let index = provider_index(&checks);
    // Same path, another inode: a different file.
    let mut copy = object(
        0x1000_0000,
        PROVIDER + 100,
        "/usr/lib/softhsm/libsofthsm2.so",
    );
    copy.extend(object(0x2000_0000, LIBC, "/usr/lib/libc.so.6"));
    // Same device and inode under another path: a bind mount of the file.
    let mut bound = object(0x1000_0000, PROVIDER, "/srv/container/lib/libsofthsm2.so");
    bound.extend(object(0x2000_0000, LIBC, "/usr/lib/libc.so.6"));
    let sweep = vec![(10_001, copy), (10_002, bound)];
    let mut probe = Probe::over(&sweep);
    let attribution = run(&sweep, &BTreeSet::new(), &index, &mut probe);
    let pids: Vec<u32> = attribution.members.iter().map(|m| m.pid).collect();
    assert_eq!(pids, vec![10_002]);
    assert_eq!(
        attribution.members[0].objects[0].path,
        "/srv/container/lib/libsofthsm2.so"
    );
    assert_eq!(attribution.unexamined, BTreeMap::from([(10_001, 1)]));
}

#[test]
fn a_deep_scanned_pid_is_never_also_matched() {
    let checks = Checks::default();
    let index = provider_index(&checks);
    let sweep = vec![(10_000, provider_caller()), (10_001, provider_caller())];
    let mut probe = Probe::over(&sweep);
    let attribution = run(&sweep, &BTreeSet::from([10_000]), &index, &mut probe);
    let pids: Vec<u32> = attribution.members.iter().map(|m| m.pid).collect();
    assert_eq!(pids, vec![10_001]);
    assert_eq!(probe.calls, vec![10_001]);
}

#[test]
fn unavailable_snapshots_are_counted_never_matched() {
    let checks = Checks::default();
    let index = provider_index(&checks);
    let sweep = vec![(10_001, Vec::new()), (10_002, provider_caller())];
    let mut probe = Probe::over(&sweep);
    let attribution = attribute_unselected(
        &sweep,
        &BTreeSet::from([10_001]),
        &BTreeSet::new(),
        &index,
        &mut probe,
        &mut CaptureWorkBudget::default(),
    );
    assert_eq!(attribution.unavailable, 1);
    assert_eq!(attribution.members.len(), 1);
}

#[test]
fn double_load_evidence_comes_from_the_confirmed_entries() {
    let checks = Checks::default();
    let index = provider_index(&checks);
    let mut doubled = provider_caller();
    // A second load of the provider's text at another address.
    let mut second = mapping(
        0x6000_1000,
        b"r-xp",
        PROVIDER,
        "/usr/lib/softhsm/libsofthsm2.so",
    );
    second.file_offset = 0x1000;
    doubled.push(second);
    let sweep = vec![(10_001, provider_caller()), (10_002, doubled)];
    let mut probe = Probe::over(&sweep);
    let attribution = run(&sweep, &BTreeSet::new(), &index, &mut probe);
    let flags: Vec<(u32, bool)> = attribution
        .members
        .iter()
        .map(|member| (member.pid, member.objects[0].double_loaded))
        .collect();
    assert_eq!(flags, vec![(10_001, false), (10_002, true)]);
}

#[test]
fn changed_objects_drop_their_sweep_attributions_once_checked() {
    let checks = Checks::default();
    let match_keys = BTreeMap::from([(key(PROVIDER), OBJECT), (key(77), PinnedObjectId(4))]);
    let (index, _) = KnownKeyIndex::build(
        [
            (key(PROVIDER), Some(OBJECT)),
            (key(77), Some(PinnedObjectId(4))),
        ],
        &match_keys,
        &[],
        &checks,
    );
    let mut both = provider_caller();
    both.extend(object(0x7000_0000, 77, "/usr/lib/libp11kit.so"));
    let sweep = vec![
        (10_001, provider_caller()),
        (10_002, both),
        (10_003, provider_caller()),
    ];
    let mut probe = Probe::over(&sweep);
    let mut attribution = run(&sweep, &BTreeSet::new(), &index, &mut probe);
    assert_eq!(attribution.members.len(), 3);
    let changed = Checks {
        changed: BTreeSet::from([OBJECT]),
        ..Checks::default()
    };
    let dropped = retain_unchanged(&mut attribution, &changed);
    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0].0, OBJECT);
    // Each object is checked exactly once, however many members map it.
    let mut checked = changed.checked.borrow().clone();
    checked.sort();
    assert_eq!(checked, vec![OBJECT, PinnedObjectId(4)]);
    let kept: Vec<(u32, Vec<PinnedObjectId>)> = attribution
        .members
        .iter()
        .map(|member| {
            (
                member.pid,
                member.objects.iter().map(|o| o.object).collect(),
            )
        })
        .collect();
    assert_eq!(kept, vec![(10_002, vec![PinnedObjectId(4)])]);
    // Every lost (pid, object) attribution counts, including 10_002's,
    // which keeps its other object.
    assert_eq!(
        attribution.losses,
        BTreeMap::from([(AttributionLoss::ObjectChanged, 3)])
    );
}

/// Scripted OS reads for the confirmation decision order.
#[derive(Clone)]
struct Io {
    open: Result<u64, String>,
    start_time: Option<u64>,
    same: bool,
    exes: RefCell<Vec<Option<ExeIdentity>>>,
    maps: Result<Vec<MapEntry>, String>,
    gone: bool,
}

impl Io {
    fn healthy() -> Self {
        Self {
            open: Ok(1),
            start_time: Some(4_242),
            same: true,
            exes: RefCell::new(vec![Some(exe()), Some(exe())]),
            maps: Ok(provider_caller()),
            gone: false,
        }
    }
}

impl ConfirmIo for Io {
    type Pin = u64;

    fn open(&mut self, _: u32) -> Result<u64, String> {
        self.open.clone()
    }

    fn start_time(&self, _: &u64) -> Option<u64> {
        self.start_time
    }

    fn still_the_same(&self, _: &u64) -> bool {
        self.same
    }

    fn exe(&self, _: u32) -> Option<ExeIdentity> {
        let mut exes = self.exes.borrow_mut();
        if exes.is_empty() {
            None
        } else {
            exes.remove(0)
        }
    }

    fn maps(&mut self, _: u32, _: &mut CaptureWorkBudget) -> Result<Vec<MapEntry>, String> {
        self.maps.clone()
    }

    fn gone(&self, _: u32) -> bool {
        self.gone
    }
}

fn confirm(mut io: Io) -> Confirmation {
    confirm_with(&mut io, 10_001, &mut CaptureWorkBudget::default())
}

#[test]
fn confirmation_requires_the_pin_to_hold_and_the_exe_to_stay() {
    assert_eq!(
        confirm(Io::healthy()),
        Confirmation::Confirmed(ConfirmedRead {
            start_time: 4_242,
            exe: exe(),
            entries: provider_caller(),
        })
    );
    // The pin no longer names the generation (and the pid is not gone).
    let turned = Io {
        same: false,
        ..Io::healthy()
    };
    assert!(matches!(
        confirm(turned),
        Confirmation::Lost(AttributionLoss::GenerationChanged, _)
    ));
    // An exec between the two exe reads.
    let mut other = exe();
    other.ino = 101;
    let exec = Io {
        exes: RefCell::new(vec![Some(exe()), Some(other)]),
        ..Io::healthy()
    };
    assert!(matches!(
        confirm(exec),
        Confirmation::Lost(AttributionLoss::ExecChanged, _)
    ));
    // No start time: the generation cannot be joined later.
    let unproven = Io {
        start_time: None,
        ..Io::healthy()
    };
    assert!(matches!(
        confirm(unproven),
        Confirmation::Lost(AttributionLoss::ConfirmUnreadable, _)
    ));
    // A capture ceiling on the maps re-read is a budget loss.
    let ceiling = Io {
        maps: Err(IO_CEILING_REASON.into()),
        ..Io::healthy()
    };
    assert!(matches!(
        confirm(ceiling),
        Confirmation::Lost(AttributionLoss::Budget, _)
    ));
    // Unreadable maps of a live process.
    let unreadable = Io {
        maps: Err("Permission denied (os error 13)".into()),
        ..Io::healthy()
    };
    assert!(matches!(
        confirm(unreadable),
        Confirmation::Lost(AttributionLoss::ConfirmUnreadable, _)
    ));
    // Unreadable exe of a live process.
    let blind = Io {
        exes: RefCell::new(vec![None, None]),
        ..Io::healthy()
    };
    assert!(matches!(
        confirm(blind),
        Confirmation::Lost(AttributionLoss::ConfirmUnreadable, _)
    ));
}

#[test]
fn a_gone_process_is_an_exit_at_every_step() {
    for io in [
        Io {
            open: Err("no such process".into()),
            gone: true,
            ..Io::healthy()
        },
        Io {
            exes: RefCell::new(vec![None]),
            gone: true,
            ..Io::healthy()
        },
        Io {
            maps: Err("No such process (os error 3)".into()),
            gone: true,
            ..Io::healthy()
        },
        Io {
            same: false,
            gone: true,
            ..Io::healthy()
        },
    ] {
        assert_eq!(confirm(io), Confirmation::Exited);
    }
}

#[test]
fn loss_labels_are_stable_and_distinct() {
    let labels: BTreeSet<&str> = AttributionLoss::ALL
        .iter()
        .map(|loss| loss.label())
        .collect();
    assert_eq!(labels.len(), AttributionLoss::ALL.len());
    assert!(labels.contains("deleted_mapping"));
    assert!(labels.contains("inode_not_unique"));
}
