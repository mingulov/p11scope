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

/// The `vm_file` identity scripted `map_files` reads return by default: one
/// file per inode on a subvolume-style device (never the maps device, as
/// on btrfs).
fn vm_file(inode: u64) -> FileIdentity {
    FileIdentity {
        dev: 37,
        ino: inode,
    }
}

/// The objects a deep scan of `entries` examined: every provider
/// candidate, with its self-mapped `vm_file` identity.
fn examined_of<'a>(entries: impl IntoIterator<Item = &'a MapEntry>) -> Vec<ExaminedObject> {
    entries
        .into_iter()
        .filter(|entry| is_provider_mapping(entry))
        .map(|entry| ExaminedObject {
            key: ObjectKey::of(entry),
            identity: vm_file(entry.inode),
            key_is_identity: false,
        })
        .collect()
}

/// Every object passes every check unless scripted otherwise. The held
/// object's self-mapped identity defaults to the provider's `vm_file`;
/// `identities` overrides it (an `Err` is an unreadable `map_files`).
#[derive(Default)]
struct Checks {
    nonunique: BTreeMap<PinnedObjectId, &'static str>,
    changed: BTreeSet<PinnedObjectId>,
    checked: RefCell<Vec<PinnedObjectId>>,
    identities: BTreeMap<PinnedObjectId, Result<FileIdentity, String>>,
    /// The filesystem magic of an object's self-mapping (default: none
    /// read, so every key keeps the per-range proof).
    fs_magic: BTreeMap<PinnedObjectId, u64>,
}

impl ObjectChecks for Checks {
    fn nonunique_inodes(&self, object: PinnedObjectId) -> Result<Option<&'static str>, String> {
        Ok(self.nonunique.get(&object).copied())
    }

    fn unchanged(&self, object: PinnedObjectId) -> Result<bool, String> {
        self.checked.borrow_mut().push(object);
        Ok(!self.changed.contains(&object))
    }

    fn mapped_identity(&self, object: PinnedObjectId) -> Result<MappedFile, String> {
        let identity = self
            .identities
            .get(&object)
            .cloned()
            .unwrap_or(Ok(vm_file(PROVIDER)))?;
        Ok(MappedFile {
            identity,
            fs_magic: self.fs_magic.get(&object).copied(),
        })
    }
}

/// Scripted confirmations: by default each pid confirms its phase-1
/// snapshot under one start time; overrides script the hazards.
struct Probe {
    snapshots: HashMap<u32, Vec<MapEntry>>,
    overrides: HashMap<u32, Confirmation>,
    calls: Vec<u32>,
    /// `map_files` overrides by pid, served to both `confirm` (for the
    /// requested keys) and `stat_ranges`. Any other range reads its entry's
    /// default `vm_file`; `denied` makes every read of a pid EPERM.
    mapped: HashMap<u32, MappedIdentities>,
    denied: BTreeSet<u32>,
    stat_calls: Vec<u32>,
}

impl Probe {
    fn over(sweep: &[(u32, Vec<MapEntry>)]) -> Self {
        Self {
            snapshots: sweep.iter().cloned().collect(),
            overrides: HashMap::new(),
            calls: Vec::new(),
            mapped: HashMap::new(),
            denied: BTreeSet::new(),
            stat_calls: Vec::new(),
        }
    }
}

impl Probe {
    fn identities(
        &self,
        pid: u32,
        ranges: impl IntoIterator<Item = (u64, u64)>,
    ) -> MappedIdentities {
        let known = self.mapped.get(&pid);
        let entries = self.snapshots.get(&pid);
        ranges
            .into_iter()
            .map(|range| {
                if self.denied.contains(&pid) {
                    return (range, Err("Operation not permitted (os error 1)".into()));
                }
                let found = known
                    .and_then(|mapped| mapped.get(&range))
                    .cloned()
                    .unwrap_or_else(|| {
                        entries
                            .and_then(|entries| {
                                entries
                                    .iter()
                                    .find(|entry| (entry.start, entry.end) == range)
                            })
                            .map(|entry| vm_file(entry.inode))
                            .ok_or_else(|| "No such file or directory (os error 2)".into())
                    });
                (range, found)
            })
            .collect()
    }
}

impl MemberProbe for Probe {
    fn confirm(
        &mut self,
        pid: u32,
        prove: &BTreeSet<ObjectKey>,
        _: &mut CaptureWorkBudget,
    ) -> Confirmation {
        self.calls.push(pid);
        if let Some(scripted) = self.overrides.get(&pid) {
            return scripted.clone();
        }
        let entries = self.snapshots.get(&pid).cloned().unwrap_or_default();
        let mapped = self.identities(
            pid,
            entries
                .iter()
                .filter(|entry| is_provider_mapping(entry) && prove.contains(&ObjectKey::of(entry)))
                .map(|entry| (entry.start, entry.end)),
        );
        Confirmation::Confirmed(ConfirmedRead {
            start_time: 5_000 + u64::from(pid),
            exe: exe(),
            entries,
            mapped,
        })
    }

    fn stat_ranges(
        &mut self,
        pid: u32,
        ranges: &[(u64, u64)],
        _: &mut CaptureWorkBudget,
    ) -> MappedIdentities {
        self.stat_calls.push(pid);
        self.identities(pid, ranges.iter().copied())
    }
}

const OBJECT: PinnedObjectId = PinnedObjectId(3);

/// The index a deep scan of one provider caller builds: the provider key
/// bound to `OBJECT` and libc examined without a module.
fn provider_index(checks: &Checks) -> KnownKeyIndex {
    let rep = provider_caller();
    let match_keys = BTreeMap::from([(key(PROVIDER), OBJECT)]);
    KnownKeyIndex::build(
        [(key(PROVIDER), Some(OBJECT))],
        &match_keys,
        examined_of(&rep),
        checks,
    )
    .0
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
        examined_of(examined),
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
    let (index, _) = KnownKeyIndex::build([], &BTreeMap::new(), examined_of(examined), &checks);
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
        examined_of(&examined),
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
        KnownKeyIndex::build([(key(PROVIDER), Some(OBJECT))], &match_keys, [], &checks);
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
        examined_of(&provider_caller()),
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
    let checks = Checks {
        identities: BTreeMap::from([(PinnedObjectId(4), Ok(vm_file(77)))]),
        ..Checks::default()
    };
    let match_keys = BTreeMap::from([(key(PROVIDER), OBJECT), (key(77), PinnedObjectId(4))]);
    let (index, _) = KnownKeyIndex::build(
        [
            (key(PROVIDER), Some(OBJECT)),
            (key(77), Some(PinnedObjectId(4))),
        ],
        &match_keys,
        [],
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
    /// `map_files` identity by range start.
    mapped: BTreeMap<u64, Result<FileIdentity, String>>,
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
            mapped: BTreeMap::new(),
        }
    }
}

impl ConfirmIo for Io {
    type Pin = u64;

    fn mapped_file(&self, _: u32, start: u64, _: u64) -> Result<FileIdentity, String> {
        self.mapped
            .get(&start)
            .cloned()
            .unwrap_or_else(|| Err("Operation not permitted (os error 1)".into()))
    }

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
    confirm_with(
        &mut io,
        10_001,
        &BTreeSet::new(),
        &mut CaptureWorkBudget::default(),
    )
}

#[test]
fn confirmation_requires_the_pin_to_hold_and_the_exe_to_stay() {
    assert_eq!(
        confirm(Io::healthy()),
        Confirmation::Confirmed(ConfirmedRead {
            start_time: 4_242,
            exe: exe(),
            entries: provider_caller(),
            mapped: MappedIdentities::new(),
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

// ---- Review fix (Critical 1): a maps key is not one file ----

/// The `map_files` identities of every provider range of `entries` with
/// `inode`, all reading `identity`.
fn ranges_reading(entries: &[MapEntry], inode: u64, identity: FileIdentity) -> MappedIdentities {
    entries
        .iter()
        .filter(|entry| entry.inode == inode)
        .map(|entry| ((entry.start, entry.end), Ok(identity)))
        .collect()
}

/// btrfs: maps renders one device for every subvolume and inode numbers
/// repeat across subvolumes, so another subvolume's file can carry the
/// provider's exact maps key. Its `vm_file` is another file: never a match.
#[test]
fn a_colliding_maps_key_naming_another_file_is_an_identity_mismatch() {
    let checks = Checks::default();
    let index = provider_index(&checks);
    let sweep = vec![(10_001, provider_caller()), (10_002, provider_caller())];
    let mut probe = Probe::over(&sweep);
    // Same maps key (8:1, PROVIDER); another subvolume's file.
    let other_subvolume = FileIdentity {
        dev: 47,
        ino: PROVIDER,
    };
    probe.mapped.insert(
        10_001,
        ranges_reading(&provider_caller(), PROVIDER, other_subvolume),
    );
    let attribution = run(&sweep, &BTreeSet::new(), &index, &mut probe);
    let pids: Vec<u32> = attribution.members.iter().map(|m| m.pid).collect();
    assert_eq!(pids, vec![10_002], "only the real caller is attributed");
    assert_eq!(
        attribution.losses,
        BTreeMap::from([(AttributionLoss::IdentityMismatch, 1)])
    );
    let (loss, detail) = &attribution.member_losses[&10_001];
    assert_eq!(*loss, AttributionLoss::IdentityMismatch);
    assert!(detail.contains("maps key collision"), "{detail}");
}

/// One range of the group being another file is enough to refuse: the
/// whole group shares one key, so every range must be the held file.
#[test]
fn every_range_of_a_matched_group_must_be_the_held_file() {
    let checks = Checks::default();
    let index = provider_index(&checks);
    let sweep = vec![(10_001, provider_caller())];
    let mut probe = Probe::over(&sweep);
    let text = provider_caller()
        .into_iter()
        .find(|entry| entry.inode == PROVIDER && entry.permissions[2] == b'x')
        .unwrap();
    probe.mapped.insert(
        10_001,
        MappedIdentities::from([(
            (text.start, text.end),
            Ok(FileIdentity {
                dev: 47,
                ino: PROVIDER,
            }),
        )]),
    );
    let attribution = run(&sweep, &BTreeSet::new(), &index, &mut probe);
    assert!(attribution.members.is_empty());
    assert_eq!(
        attribution.losses,
        BTreeMap::from([(AttributionLoss::IdentityMismatch, 1)])
    );
}

/// Pre-6.8 overlayfs installs the BACKING file in the VMA: the target's
/// `map_files` names the backing file (here 0:21 inode 712355) while an fd
/// opened through the overlay path would `fstat` as the overlay file
/// (0:43). The pinned side is the held fd's own self-mapping, which the
/// same kernel path also backs with the backing file — like for like, so
/// the healthy container caller is attributed. `fstat` is never consulted.
#[test]
fn a_pre_6_8_overlay_caller_matches_the_self_mapped_backing_file() {
    let backing = FileIdentity {
        dev: 0x15,
        ino: 712_355,
    };
    let checks = Checks {
        identities: BTreeMap::from([(OBJECT, Ok(backing))]),
        ..Checks::default()
    };
    let index = provider_index(&checks);
    let sweep = vec![(10_001, provider_caller())];
    let mut probe = Probe::over(&sweep);
    probe.mapped.insert(
        10_001,
        ranges_reading(&provider_caller(), PROVIDER, backing),
    );
    let attribution = run(&sweep, &BTreeSet::new(), &index, &mut probe);
    let pids: Vec<u32> = attribution.members.iter().map(|m| m.pid).collect();
    assert_eq!(pids, vec![10_001]);
    assert!(attribution.losses.is_empty(), "{:?}", attribution.losses);
}

/// Without `CAP_SYS_ADMIN`/`CAP_CHECKPOINT_RESTORE` nothing is proven:
/// an unreadable target range, or an unreadable held self-mapping, is a
/// named `map_files_unavailable` loss — never a match by key alone.
#[test]
fn unreadable_map_files_fail_closed_on_either_side() {
    let checks = Checks::default();
    let index = provider_index(&checks);
    let sweep = vec![(10_001, provider_caller()), (10_002, provider_caller())];
    let mut probe = Probe::over(&sweep);
    probe.denied.insert(10_001);
    let attribution = run(&sweep, &BTreeSet::new(), &index, &mut probe);
    let pids: Vec<u32> = attribution.members.iter().map(|m| m.pid).collect();
    assert_eq!(pids, vec![10_002]);
    assert_eq!(
        attribution.losses,
        BTreeMap::from([(AttributionLoss::MapFilesUnavailable, 1)])
    );

    let unreadable = Checks {
        identities: BTreeMap::from([(OBJECT, Err("Operation not permitted".into()))]),
        ..Checks::default()
    };
    let index = provider_index(&unreadable);
    assert_eq!(
        index.classify(key(PROVIDER)),
        KeyClass::Ineligible(AttributionLoss::MapFilesUnavailable)
    );
    let mut probe = Probe::over(&sweep);
    let attribution = run(&sweep, &BTreeSet::new(), &index, &mut probe);
    assert!(attribution.members.is_empty());
    assert_eq!(
        attribution.losses,
        BTreeMap::from([(AttributionLoss::MapFilesUnavailable, 2)])
    );
    assert_eq!(probe.calls, Vec::<u32>::new(), "nothing to confirm");
}

/// An examined key counts as examined in another process only when every
/// one of its ranges is a file a deep scan examined under that key.
#[test]
fn an_examined_key_counts_only_when_its_ranges_are_an_examined_file() {
    let checks = Checks::default();
    let index = provider_index(&checks);
    let sweep = vec![
        (20_001, idle(None)),
        (20_002, idle(None)),
        (20_003, idle(None)),
    ];
    let mut probe = Probe::over(&sweep);
    // 20_002: another subvolume's file under libc's key; 20_003: no
    // privilege. 20_001 reads the examined libc file.
    probe.mapped.insert(
        20_002,
        ranges_reading(&idle(None), LIBC, FileIdentity { dev: 47, ino: LIBC }),
    );
    probe.denied.insert(20_003);
    let attribution = run(&sweep, &BTreeSet::new(), &index, &mut probe);
    assert_eq!(
        attribution.unexamined,
        BTreeMap::from([(20_002, 1), (20_003, 1)])
    );
    assert_eq!(attribution.unexamined_keys(), 1);
    assert!(attribution.losses.is_empty(), "unexamined is not a loss");
    assert_eq!(
        probe.calls,
        Vec::<u32>::new(),
        "no pin for examined-only proofs"
    );
    assert_eq!(probe.stat_calls, vec![20_001, 20_002, 20_003]);
}

/// The confirmation reads `map_files` only for the requested keys, inside
/// the pin: a generation change after those reads still loses the member.
#[test]
fn the_confirmation_reads_map_files_for_requested_keys_inside_the_pin() {
    let provider_ranges: Vec<(u64, u64)> = provider_caller()
        .iter()
        .filter(|entry| entry.inode == PROVIDER)
        .map(|entry| (entry.start, entry.end))
        .collect();
    let mut io = Io::healthy();
    for (start, _) in &provider_ranges {
        io.mapped.insert(*start, Ok(vm_file(PROVIDER)));
    }
    let prove = BTreeSet::from([key(PROVIDER)]);
    let Confirmation::Confirmed(read) =
        confirm_with(&mut io, 10_001, &prove, &mut CaptureWorkBudget::default())
    else {
        panic!("a healthy confirmation");
    };
    let read_ranges: Vec<(u64, u64)> = read.mapped.keys().copied().collect();
    assert_eq!(read_ranges, provider_ranges, "libc was not requested");
    assert!(
        read.mapped
            .values()
            .all(|identity| identity == &Ok(vm_file(PROVIDER)))
    );

    let mut turned = Io {
        same: false,
        ..Io::healthy()
    };
    assert!(matches!(
        confirm_with(
            &mut turned,
            10_001,
            &prove,
            &mut CaptureWorkBudget::default()
        ),
        Confirmation::Lost(AttributionLoss::GenerationChanged, _)
    ));
}

/// A deep-scanned representative maps the provider at its path; another
/// process maps a different file at that same path. Only `(device,
/// inode)` and the `vm_file` proof decide: the copy stays unexamined.
#[test]
fn a_same_path_different_file_never_matches_beside_a_deep_scanned_rep() {
    let checks = Checks::default();
    let index = provider_index(&checks);
    let mut copy = object(
        0x1000_0000,
        PROVIDER + 100,
        "/usr/lib/softhsm/libsofthsm2.so",
    );
    copy.extend(object(0x2000_0000, LIBC, "/usr/lib/libc.so.6"));
    let sweep = vec![(10_000, provider_caller()), (10_001, copy)];
    let mut probe = Probe::over(&sweep);
    let attribution = run(&sweep, &BTreeSet::from([10_000]), &index, &mut probe);
    assert!(attribution.members.is_empty(), "{:?}", attribution.members);
    assert!(attribution.losses.is_empty(), "{:?}", attribution.losses);
    assert_eq!(attribution.unexamined, BTreeMap::from([(10_001, 1)]));
}

/// The maps key `8:1` as a `stat` device.
fn key_device_identity(inode: u64) -> FileIdentity {
    FileIdentity {
        dev: libc::makedev(8, 1),
        ino: inode,
    }
}

const EXT4_MAGIC: u64 = 0xef53;
/// tmpfs, btrfs, overlayfs, bcachefs, FUSE, NFS: never on the allowlist.
const ALWAYS_PROVE_MAGICS: [u64; 6] = [
    0x0102_1994,
    0x9123_683e,
    0x794c_7630,
    0xca45_1a4e,
    0x6573_5546,
    0x6969,
];

/// DR-C1b-3: a matched key that is its held file's identity on an
/// allowlisted filesystem skips the per-range `map_files` stat (here every
/// stat would be EPERM); the same identity on tmpfs, btrfs, overlayfs,
/// bcachefs, FUSE or NFS always proves and so fails closed.
#[test]
fn an_identity_key_skips_the_range_proof_only_on_an_allowlisted_filesystem() {
    let sweep = vec![(10_001, provider_caller())];
    let checks_on = |magic| Checks {
        identities: BTreeMap::from([(OBJECT, Ok(key_device_identity(PROVIDER)))]),
        fs_magic: BTreeMap::from([(OBJECT, magic)]),
        ..Checks::default()
    };

    let index = provider_index(&checks_on(EXT4_MAGIC));
    assert_eq!(index.map_files_keys(), BTreeSet::from([key(LIBC)]));
    let mut probe = Probe::over(&sweep);
    probe.denied.insert(10_001);
    let attribution = run(&sweep, &BTreeSet::new(), &index, &mut probe);
    let pids: Vec<u32> = attribution.members.iter().map(|m| m.pid).collect();
    assert_eq!(pids, vec![10_001]);
    assert!(attribution.losses.is_empty(), "{:?}", attribution.losses);

    for magic in ALWAYS_PROVE_MAGICS {
        let index = provider_index(&checks_on(magic));
        assert_eq!(
            index.map_files_keys(),
            BTreeSet::from([key(PROVIDER), key(LIBC)]),
            "{magic:#x}"
        );
        let mut probe = Probe::over(&sweep);
        probe.denied.insert(10_001);
        let attribution = run(&sweep, &BTreeSet::new(), &index, &mut probe);
        assert!(attribution.members.is_empty(), "{magic:#x}");
        assert_eq!(
            attribution.losses,
            BTreeMap::from([(AttributionLoss::MapFilesUnavailable, 1)]),
            "{magic:#x}"
        );
    }

    // On ext4 but the identity is not the key (btrfs-style anon device):
    // still proves.
    let other = Checks {
        fs_magic: BTreeMap::from([(OBJECT, EXT4_MAGIC)]),
        ..Checks::default()
    };
    let index = provider_index(&other);
    assert!(index.map_files_keys().contains(&key(PROVIDER)));
}

/// An examined key that is its file's identity on an allowlisted
/// filesystem counts as examined without a stat; any other examined key
/// still needs every range to stat to an examined file.
#[test]
fn an_examined_identity_key_needs_no_stat() {
    let sweep = vec![(20_001, idle(None))];
    let build = |key_is_identity| {
        KnownKeyIndex::build(
            [(key(PROVIDER), Some(OBJECT))],
            &BTreeMap::from([(key(PROVIDER), OBJECT)]),
            [ExaminedObject {
                key: key(LIBC),
                identity: key_device_identity(LIBC),
                key_is_identity,
            }],
            &Checks::default(),
        )
        .0
    };

    let mut probe = Probe::over(&sweep);
    probe.denied.insert(20_001);
    let attribution = run(&sweep, &BTreeSet::new(), &build(true), &mut probe);
    assert!(
        attribution.unexamined.is_empty(),
        "{:?}",
        attribution.unexamined
    );
    assert_eq!(
        probe.stat_calls,
        Vec::<u32>::new(),
        "no stat for an identity key"
    );

    let mut probe = Probe::over(&sweep);
    probe.denied.insert(20_001);
    let attribution = run(&sweep, &BTreeSet::new(), &build(false), &mut probe);
    assert_eq!(attribution.unexamined, BTreeMap::from([(20_001, 1)]));
    assert_eq!(probe.stat_calls, vec![20_001]);
}
