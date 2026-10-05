//! SPDX-License-Identifier: GPL-3.0-or-later
//! C1b pure-core tests: more processes than the deep-scan cap, many
//! identical callers, and every confirmation and identity hazard.

use super::*;
use crate::discovery::engine::select_deep_scan_candidates;
use crate::discovery::proof_stats::{MAX_PROOF_STAT_THREADS, MIN_PARALLEL_BATCH};
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
    /// Every range `stat_ranges` was asked for, in order.
    statted: Vec<(u32, (u64, u64))>,
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
            statted: Vec::new(),
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
        // The production range selection (A6: caller ranges only), so the
        // scripted confirmation reads exactly what `confirm_with` would.
        let mapped = self.identities(pid, proof_ranges(&entries, prove));
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
        self.statted
            .extend(ranges.iter().map(|range| (pid, *range)));
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

    fn mapped_file(&mut self, _: u32, start: u64, _: u64) -> Result<FileIdentity, String> {
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
/// A6: only the requested keys' executable ranges are read (the provider's
/// text; its `r--` header is never statted).
#[test]
fn the_confirmation_reads_map_files_for_requested_keys_inside_the_pin() {
    let provider_ranges: Vec<(u64, u64)> = provider_caller()
        .iter()
        .filter(|entry| entry.inode == PROVIDER && entry.permissions[2] == b'x')
        .map(|entry| (entry.start, entry.end))
        .collect();
    assert_eq!(provider_ranges, vec![(0x1000_1000, 0x1000_2000)]);
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
    assert_eq!(
        read_ranges, provider_ranges,
        "libc was not requested; the provider's header is not executable"
    );
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

/// [`Io`] that records the order of the confirmation's OS calls and can
/// kill the pin while the proof reads run (`still_the_same` is false once
/// any `map_files` read has happened).
struct OrderedIo {
    io: Io,
    calls: RefCell<Vec<&'static str>>,
    pin_dies_during_reads: bool,
}

impl OrderedIo {
    fn new(pin_dies_during_reads: bool) -> Self {
        let mut io = Io::healthy();
        for entry in provider_caller()
            .iter()
            .filter(|entry| entry.inode == PROVIDER)
        {
            io.mapped.insert(entry.start, Ok(vm_file(PROVIDER)));
        }
        Self {
            io,
            calls: RefCell::new(Vec::new()),
            pin_dies_during_reads,
        }
    }

    fn record(&self, call: &'static str) {
        self.calls.borrow_mut().push(call);
    }

    fn read(&self) -> bool {
        self.calls.borrow().contains(&"mapped_files")
    }
}

impl ConfirmIo for OrderedIo {
    type Pin = u64;

    fn mapped_file(&mut self, pid: u32, start: u64, end: u64) -> Result<FileIdentity, String> {
        self.io.mapped_file(pid, start, end)
    }

    fn mapped_files(
        &mut self,
        pid: u32,
        ranges: &[(u64, u64)],
    ) -> Vec<Result<FileIdentity, String>> {
        self.record("mapped_files");
        self.io.mapped_files(pid, ranges)
    }

    fn open(&mut self, pid: u32) -> Result<u64, String> {
        self.record("open");
        self.io.open(pid)
    }

    fn start_time(&self, pin: &u64) -> Option<u64> {
        self.io.start_time(pin)
    }

    fn still_the_same(&self, pin: &u64) -> bool {
        self.record("still_the_same");
        self.io.still_the_same(pin) && !(self.pin_dies_during_reads && self.read())
    }

    fn exe(&self, pid: u32) -> Option<ExeIdentity> {
        self.record("exe");
        self.io.exe(pid)
    }

    fn maps(&mut self, pid: u32, budget: &mut CaptureWorkBudget) -> Result<Vec<MapEntry>, String> {
        self.record("maps");
        self.io.maps(pid, budget)
    }

    fn gone(&self, pid: u32) -> bool {
        self.io.gone(pid)
    }
}

/// R1 (C5.6 re-check): the `map_files` proof reads happen inside the pin
/// bracket — after the pidfd opens and the maps are read, before the exe
/// re-read and the one `still_the_same` check that closes the bracket.
/// Reading them after that check would prove a mapping of a generation
/// the pin no longer vouches for.
#[test]
fn the_proof_reads_happen_before_the_pin_is_checked() {
    let prove = BTreeSet::from([key(PROVIDER)]);
    let mut io = OrderedIo::new(false);
    assert!(matches!(
        confirm_with(&mut io, 10_001, &prove, &mut CaptureWorkBudget::default()),
        Confirmation::Confirmed(_)
    ));
    assert_eq!(
        *io.calls.borrow(),
        [
            "open",
            "exe",
            "maps",
            "mapped_files",
            "exe",
            "still_the_same"
        ]
    );
}

/// R1: a pin that dies while the proofs are read loses the confirmation
/// (the reads may be of the next generation's mappings); it is never
/// confirmed.
#[test]
fn a_pin_that_dies_during_the_proof_reads_loses_the_confirmation() {
    let prove = BTreeSet::from([key(PROVIDER)]);
    let mut io = OrderedIo::new(true);
    assert!(matches!(
        confirm_with(&mut io, 10_001, &prove, &mut CaptureWorkBudget::default()),
        Confirmation::Lost(AttributionLoss::GenerationChanged, _)
    ));
    assert!(io.read(), "the proofs were read");
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

// ---- C5.6 (DR-C1b-3) and its review fixes (R-C56-1) ----

/// Two fresh btrfs subvolumes under `parent` (`BTRFS_IOC_SUBVOL_CREATE`).
fn create_subvolume(parent: &std::path::Path, name: &str) {
    use std::os::fd::AsRawFd as _;
    #[repr(C)]
    struct VolArgs {
        fd: i64,
        name: [u8; 4088],
    }
    const BTRFS_IOC_SUBVOL_CREATE: libc::c_ulong = 0x5000_940e;
    let dir = std::fs::File::open(parent).unwrap();
    let mut args = VolArgs {
        fd: 0,
        name: [0; 4088],
    };
    args.name[..name.len()].copy_from_slice(name.as_bytes());
    // SAFETY: a valid directory fd and a NUL-terminated name in a
    // correctly sized btrfs_ioctl_vol_args.
    let rc = unsafe { libc::ioctl(dir.as_raw_fd(), BTRFS_IOC_SUBVOL_CREATE, &args) };
    assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
}

/// A forked, quiescent target: it maps each requested file (one page,
/// read-only, executable when asked) and reports the addresses; on `s` it
/// unmaps the first page and maps that path again at the same address with
/// the same protection (whatever file the path names now), then
/// acknowledges. A6: a caller is a process with an executable mapping, so
/// [`Self::spawn`] maps `r-x`; [`Self::spawn_with`] can add data-only
/// (`r--`) mappings.
struct SwapChild {
    pid: libc::pid_t,
    command: std::os::fd::OwnedFd,
    reply: std::os::fd::OwnedFd,
    address: u64,
    addresses: Vec<u64>,
}

impl SwapChild {
    /// One executable mapping of `path`, as a loaded library's text.
    fn spawn(path: &std::path::Path) -> Self {
        Self::spawn_with(&[(path, true)])
    }

    /// One page of each `(path, executable)`, in order.
    fn spawn_with(mappings: &[(&std::path::Path, bool)]) -> Self {
        use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
        assert!(!mappings.is_empty());
        let plan: Vec<(std::ffi::CString, libc::c_int)> = mappings
            .iter()
            .map(|(path, exec)| {
                let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                let prot = if *exec {
                    libc::PROT_READ | libc::PROT_EXEC
                } else {
                    libc::PROT_READ
                };
                (c_path, prot)
            })
            .collect();
        let (mut down, mut up) = ([0; 2], [0; 2]);
        // SAFETY: two valid two-element arrays for pipe2.
        assert_eq!(
            unsafe { libc::pipe2(down.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        assert_eq!(unsafe { libc::pipe2(up.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: the child only makes raw syscalls on preallocated
        // buffers and leaves through `_exit`.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // SAFETY: raw syscalls on valid fds and the preallocated paths.
            unsafe {
                let map =
                    |at: *mut libc::c_void,
                     flags,
                     (c_path, prot): &(std::ffi::CString, libc::c_int)| {
                        let fd = libc::open(c_path.as_ptr(), libc::O_RDONLY);
                        let base = libc::mmap(at, 4096, *prot, libc::MAP_PRIVATE | flags, fd, 0);
                        libc::close(fd);
                        base
                    };
                let mut first = std::ptr::null_mut();
                for (index, request) in plan.iter().enumerate() {
                    let base = map(std::ptr::null_mut(), 0, request);
                    if index == 0 {
                        first = base;
                    }
                    let address = (base as u64).to_ne_bytes();
                    libc::write(up[1], address.as_ptr().cast(), 8);
                }
                let mut byte = 0u8;
                while libc::read(down[0], (&raw mut byte).cast(), 1) == 1 && byte == b's' {
                    libc::munmap(first, 4096);
                    let again = map(first, libc::MAP_FIXED_NOREPLACE, &plan[0]);
                    let ok = [u8::from(again == first)];
                    libc::write(up[1], ok.as_ptr().cast(), 1);
                }
                libc::_exit(0);
            }
        }
        // SAFETY: the parent owns its pipe ends; the child's are closed.
        let (command, reply) = unsafe {
            libc::close(down[0]);
            libc::close(up[1]);
            (OwnedFd::from_raw_fd(down[1]), OwnedFd::from_raw_fd(up[0]))
        };
        let addresses: Vec<u64> = (0..plan.len())
            .map(|_| {
                let mut address = [0u8; 8];
                // SAFETY: reading 8 bytes into a valid buffer.
                assert_eq!(
                    unsafe { libc::read(reply.as_raw_fd(), address.as_mut_ptr().cast(), 8) },
                    8
                );
                let address = u64::from_ne_bytes(address);
                assert_ne!(address, libc::MAP_FAILED as u64, "the child's mmap failed");
                address
            })
            .collect();
        Self {
            pid,
            command,
            reply,
            address: addresses[0],
            addresses,
        }
    }

    fn remap(&self) {
        use std::os::fd::AsRawFd as _;
        let mut ok = 0u8;
        // SAFETY: one-byte writes and reads on owned pipe ends.
        unsafe {
            assert_eq!(
                libc::write(self.command.as_raw_fd(), b"s".as_ptr().cast(), 1),
                1
            );
            assert_eq!(
                libc::read(self.reply.as_raw_fd(), (&raw mut ok).cast(), 1),
                1
            );
        }
        assert_eq!(ok, 1, "the child mapped the page again at the same address");
    }

    fn maps(&self) -> Vec<MapEntry> {
        let file = std::fs::File::open(format!("/proc/{}/maps", self.pid)).unwrap();
        crate::discovery::scan::read_maps_or_refuse(
            file,
            &mut CaptureWorkBudget::default(),
            crate::attach::monotonic_ns,
        )
        .unwrap()
    }
}

impl Drop for SwapChild {
    fn drop(&mut self) {
        // SAFETY: our own child; reaped here.
        unsafe {
            libc::kill(self.pid, libc::SIGKILL);
            libc::waitpid(self.pid, std::ptr::null_mut(), 0);
        }
    }
}

/// A synthetic index binding the child's mapping key `key` to `OBJECT`,
/// as a deep scan that pinned a file under that key would: `identity` is
/// the pinned file's self-mapped identity; `magic` its filesystem.
fn index_binding(key: ObjectKey, identity: FileIdentity, magic: Option<u64>) -> KnownKeyIndex {
    let checks = Checks {
        identities: BTreeMap::from([(OBJECT, Ok(identity))]),
        fs_magic: magic
            .map(|magic| BTreeMap::from([(OBJECT, magic)]))
            .unwrap_or_default(),
        ..Checks::default()
    };
    KnownKeyIndex::build(
        [(key, Some(OBJECT))],
        &BTreeMap::from([(key, OBJECT)]),
        [],
        &checks,
    )
    .0
}

fn attribute_child(
    child: &SwapChild,
    snapshot: Vec<MapEntry>,
    index: &KnownKeyIndex,
) -> SweepAttribution {
    attribute_unselected(
        &[(child.pid as u32, snapshot)],
        &BTreeSet::new(),
        &BTreeSet::new(),
        index,
        &mut OsMemberProbe::default(),
        &mut CaptureWorkBudget::default(),
    )
}

/// Root on a btrfs TMPDIR, through the production probe: a process's
/// page is swapped (munmap, then mmap at the same address) for another
/// subvolume's file reached through the same path. Its maps render byte
/// for byte the same, so only a fresh `map_files` proof can tell: the
/// edge it had before the swap becomes an identity mismatch after it.
/// Guards against any proof ever being reused across an identical line.
#[test]
#[ignore = "root (map_files) on a btrfs TMPDIR: creates two subvolumes there"]
fn privileged_a_file_swapped_behind_an_identical_line_is_proved_as_the_new_file() {
    use std::os::unix::fs::MetadataExt as _;
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path();
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let c_parent = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid path and buffer, read only on success.
    assert_eq!(
        unsafe { libc::statfs(c_parent.as_ptr(), stat.as_mut_ptr()) },
        0
    );
    // SAFETY: initialized by the successful statfs.
    let magic = (unsafe { stat.assume_init().f_type }) as u64 & 0xffff_ffff;
    assert_eq!(magic, 0x9123_683e, "TMPDIR must be on btrfs");
    create_subvolume(parent, "s");
    create_subvolume(parent, "t");
    let path = parent.join("s/libswap.so");
    std::fs::write(&path, vec![0xa5u8; 8192]).unwrap();
    std::fs::write(parent.join("t/libswap.so"), vec![0x5au8; 8192]).unwrap();
    let (a, b) = (
        std::fs::metadata(&path).unwrap(),
        std::fs::metadata(parent.join("t/libswap.so")).unwrap(),
    );
    assert_eq!(a.ino(), b.ino(), "fresh subvolumes repeat inode numbers");
    assert_ne!(a.dev(), b.dev());
    let held_a =
        crate::discovery::identity::self_mapped_identity(&std::fs::File::open(&path).unwrap())
            .expect("map_files is readable as root");

    let child = SwapChild::spawn(&path);
    let range = (child.address, child.address + 4096);
    let before = child.maps();
    let line = before
        .iter()
        .find(|entry| (entry.start, entry.end) == range)
        .expect("the child's mapping")
        .clone();
    let index = index_binding(ObjectKey::of(&line), held_a, None);
    let first = attribute_child(&child, before.clone(), &index);
    let pids: Vec<u32> = first.members.iter().map(|member| member.pid).collect();
    assert_eq!(pids, vec![child.pid as u32], "{:?}", first.member_losses);

    std::fs::rename(parent.join("s"), parent.join("s.old")).unwrap();
    std::fs::rename(parent.join("t"), parent.join("s")).unwrap();
    child.remap();
    let after = child.maps();
    assert_eq!(after, before, "the swapped mapping renders the same maps");
    let second = attribute_child(&child, after, &index);
    assert!(second.members.is_empty(), "{:?}", second.members);
    assert_eq!(
        second.losses.get(&AttributionLoss::IdentityMismatch),
        Some(&1),
        "{:?}",
        second.member_losses
    );
    drop(child);
    std::fs::remove_file(parent.join("s/libswap.so")).unwrap();
    std::fs::remove_file(parent.join("s.old/libswap.so")).unwrap();
    std::fs::remove_dir(parent.join("s")).unwrap();
    std::fs::remove_dir(parent.join("s.old")).unwrap();
}

/// A private ext4 filesystem on a loop device under a temporary directory,
/// unmounted (lazily if busy) and deleted on drop.
struct Ext4Loop {
    _dir: tempfile::TempDir,
    mount: std::path::PathBuf,
}

impl Ext4Loop {
    fn new() -> Self {
        let run = |program: &str, args: &[&std::ffi::OsStr]| {
            let status = std::process::Command::new(program)
                .args(args)
                .status()
                .unwrap_or_else(|error| panic!("{program} is required: {error}"));
            assert!(status.success(), "{program} {args:?}: {status}");
        };
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("ext4.img");
        std::fs::File::create(&image)
            .unwrap()
            .set_len(64 << 20)
            .unwrap();
        let mount = dir.path().join("mnt");
        std::fs::create_dir(&mount).unwrap();
        run(
            "mkfs.ext4",
            &["-q".as_ref(), "-F".as_ref(), image.as_os_str()],
        );
        run(
            "mount",
            &[
                "-o".as_ref(),
                "loop".as_ref(),
                image.as_os_str(),
                mount.as_os_str(),
            ],
        );
        Self { _dir: dir, mount }
    }
}

impl Drop for Ext4Loop {
    fn drop(&mut self) {
        let unmounted = std::process::Command::new("umount")
            .arg(&self.mount)
            .status()
            .is_ok_and(|status| status.success());
        if !unmounted {
            let _ = std::process::Command::new("umount")
                .arg("-l")
                .arg(&self.mount)
                .status();
        }
    }
}

/// R-C56-1 (review H1), root with a loop-mounted ext4: a caller maps a
/// file whose maps key is its identity (ext4); after the sweep read it
/// unmaps the file, the file is freed, and ext4 gives its inode number to
/// another file at once — the key the stale sweep line carries now names
/// a file the caller never mapped. With an index binding that key (as a
/// deep scan pinning the new file would), the confirmation re-reads maps
/// inside the pin and attributes nothing. A cross-pass cache that let the
/// sweep line stand in for that re-read attributed the caller.
#[test]
#[ignore = "root: mounts a loop ext4 image (mkfs.ext4, mount, umount)"]
fn privileged_an_unmapped_file_whose_inode_is_reused_is_never_attributed_on_ext4() {
    use std::os::unix::fs::MetadataExt as _;
    let ext4 = Ext4Loop::new();
    let path = ext4.mount.join("libprobe.so");
    std::fs::write(&path, vec![0xa5u8; 8192]).unwrap();
    let f1 = std::fs::metadata(&path).unwrap();
    let child = SwapChild::spawn(&path);
    let range = (child.address, child.address + 4096);
    let sweep = child.maps();
    let line = sweep
        .iter()
        .find(|entry| (entry.start, entry.end) == range)
        .expect("the child's mapping")
        .clone();
    assert_eq!(line.inode, f1.ino());
    let key_k = ObjectKey::of(&line);
    let index = index_binding(
        key_k,
        FileIdentity {
            dev: libc::makedev(key_k.device.major as u32, key_k.device.minor as u32),
            ino: key_k.inode,
        },
        Some(0xef53),
    );
    assert!(
        !index.map_files_keys().contains(&key_k),
        "an identity key: no per-range proof"
    );

    // After the sweep read: the path is replaced (F2), the child maps it
    // again (freeing F1), and a new file F3 takes F1's inode number.
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, vec![0x5au8; 8192]).unwrap();
    child.remap();
    let f3_path = ext4.mount.join("libother.so");
    std::fs::write(&f3_path, vec![0x33u8; 8192]).unwrap();
    assert_eq!(
        std::fs::metadata(&f3_path).unwrap().ino(),
        f1.ino(),
        "ext4 reused the freed inode number"
    );
    assert!(
        !child
            .maps()
            .iter()
            .any(|entry| ObjectKey::of(entry) == key_k),
        "the child no longer maps key K"
    );

    let attribution = attribute_child(&child, sweep, &index);
    assert_eq!(attribution.probed, 1, "the stale match was confirmed");
    assert!(
        attribution.members.is_empty(),
        "attributed to a file it never mapped: {:?}",
        attribution.members
    );
    drop(child);
}

/// A held `map_files` directory is the given process's, never the
/// observer's own (unprivileged: the directory's procfs inode; as root
/// also the followed identity of the child's mapping).
#[test]
fn a_held_map_files_directory_is_the_given_processes() {
    use std::os::unix::fs::MetadataExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("libchild.so");
    std::fs::write(&path, vec![0x11u8; 8192]).unwrap();
    let child = SwapChild::spawn(&path);
    let held = MapFilesDir::open(child.pid as u32).expect("the child's map_files opens");
    let ino = held.directory_metadata().unwrap().ino();
    let by_path = std::fs::metadata(format!("/proc/{}/map_files", child.pid)).unwrap();
    let own = std::fs::metadata("/proc/self/map_files").unwrap();
    assert_eq!(ino, by_path.ino(), "the child's directory");
    assert_ne!(ino, own.ino(), "never the observer's own");
    let range = (child.address, child.address + 4096);
    match (
        held.identity(range.0, range.1),
        crate::discovery::identity::map_files_identity(child.pid as u32, range.0, range.1),
    ) {
        (Ok(by_dir), Ok(by_path)) => {
            assert_eq!(by_dir, by_path);
            assert_eq!(by_dir.ino, std::fs::metadata(&path).unwrap().ino());
        }
        (Err(by_dir), Err(by_path)) => assert_eq!(by_dir.raw_os_error(), by_path.raw_os_error()),
        (by_dir, by_path) => panic!("the two reads disagree: {by_dir:?} vs {by_path:?}"),
    }
    // Every range of the child (plus one that is not a mapping), read on
    // the proof-stat pool and on one thread through the production
    // source: the same results in the same order (EPERM unprivileged).
    let mut ranges: Vec<(u64, u64)> = child
        .maps()
        .iter()
        .map(|entry| (entry.start, entry.end))
        .collect();
    ranges.push((range.0, range.1 + 4096));
    let source = Arc::new(HeldMapFiles(held));
    let serial: Vec<_> = ranges.iter().map(|&(s, e)| source.stat(s, e)).collect();
    for threads in 1..=MAX_PROOF_STAT_THREADS {
        ProofStatPool::scoped(threads, |pool| {
            assert_eq!(
                crate::discovery::proof_stats::stat_batch(pool, source.clone(), &ranges),
                serial,
                "threads {threads}"
            );
        });
    }
}

/// `ENOENT` (no mapping, or no process, at the range now) is
/// [`RANGE_NOT_MAPPED`]; a missing privilege never is.
#[test]
fn only_enoent_reads_as_a_range_no_longer_mapped() {
    assert_eq!(
        map_files_error(std::io::Error::from_raw_os_error(libc::ENOENT)),
        RANGE_NOT_MAPPED
    );
    for errno in [libc::EPERM, libc::EACCES, libc::ESRCH] {
        assert_ne!(
            map_files_error(std::io::Error::from_raw_os_error(errno)),
            RANGE_NOT_MAPPED
        );
    }
    // The production probe on a process that has exited.
    let mut io = OsConfirmIo::default();
    let gone = {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    };
    assert_eq!(
        io.mapped_file(gone, 0x1000, 0x2000),
        Err(RANGE_NOT_MAPPED.to_string())
    );
}

/// Review L4: an examined range that is no longer one mapping when an
/// unmatched process's ranges are statted (unloaded, remapped or exited
/// since the sweep) is never counted unexamined: the pid is confirmed,
/// and its re-read decides — an unloaded key is simply gone.
#[test]
fn a_range_unmapped_after_the_sweep_is_confirmed_never_counted_unexamined() {
    let checks = Checks::default();
    let index = provider_index(&checks);
    let sweep = vec![(10_000, provider_caller()), (20_001, idle(None))];
    // A6: libc's text, its one proved range (the `r--` header is not read).
    let libc_range = (0x2000_1000, 0x2000_2000);

    // Unloaded since the sweep: the re-read no longer maps libc.
    let mut probe = Probe::over(&sweep);
    probe.mapped.insert(
        20_001,
        MappedIdentities::from([(libc_range, Err(RANGE_NOT_MAPPED.into()))]),
    );
    probe.snapshots.insert(20_001, Vec::new());
    let attribution = run(&sweep, &BTreeSet::from([10_000]), &index, &mut probe);
    assert_eq!(probe.calls, vec![20_001], "escalated to a confirmation");
    assert!(
        attribution.unexamined.is_empty(),
        "{:?}",
        attribution.unexamined
    );
    assert!(attribution.losses.is_empty(), "{:?}", attribution.losses);

    // Exited since the sweep: an exit, never a loss or a coverage gap.
    let mut probe = Probe::over(&sweep);
    probe.mapped.insert(
        20_001,
        MappedIdentities::from([(libc_range, Err(RANGE_NOT_MAPPED.into()))]),
    );
    probe.overrides.insert(20_001, Confirmation::Exited);
    let attribution = run(&sweep, &BTreeSet::from([10_000]), &index, &mut probe);
    assert_eq!(attribution.exited, BTreeSet::from([20_001]));
    assert!(
        attribution.unexamined.is_empty(),
        "{:?}",
        attribution.unexamined
    );

    // A privilege refusal is not a stale range: no confirmation, and the
    // unproven key stays unexamined, as before.
    let mut probe = Probe::over(&sweep);
    probe.denied.insert(20_001);
    let attribution = run(&sweep, &BTreeSet::from([10_000]), &index, &mut probe);
    assert!(probe.calls.is_empty());
    assert_eq!(attribution.unexamined, BTreeMap::from([(20_001, 1)]));
}

/// Review L4, inside the pin: a confirmed range (matched or examined) that
/// is no longer one mapping when its `map_files` entry is read is a
/// `mapping_changed` loss, never `map_files_unavailable` (which says the
/// privilege is missing) and never an unexamined key.
#[test]
fn a_range_gone_inside_the_pin_is_a_mapping_changed_loss() {
    let checks = Checks::default();
    let index = provider_index(&checks);
    let sweep = vec![(10_000, provider_caller()), (10_001, provider_caller())];
    // A6: the provider's and libc's text, their proved ranges.
    for range in [(0x1000_1000, 0x1000_2000), (0x2000_1000, 0x2000_2000)] {
        let mut probe = Probe::over(&sweep);
        probe.mapped.insert(
            10_001,
            MappedIdentities::from([(range, Err(RANGE_NOT_MAPPED.into()))]),
        );
        let attribution = run(&sweep, &BTreeSet::from([10_000]), &index, &mut probe);
        assert_eq!(
            attribution.losses,
            BTreeMap::from([(AttributionLoss::MappingChanged, 1)]),
            "{range:x?}"
        );
        assert!(attribution.unexamined.is_empty(), "{range:x?}");
    }
    // A6: the same fault on the non-executable headers is never read.
    let mut probe = Probe::over(&sweep);
    probe.mapped.insert(
        10_001,
        MappedIdentities::from([
            ((0x1000_0000, 0x1000_1000), Err(RANGE_NOT_MAPPED.into())),
            ((0x2000_0000, 0x2000_1000), Err(RANGE_NOT_MAPPED.into())),
        ]),
    );
    let attribution = run(&sweep, &BTreeSet::from([10_000]), &index, &mut probe);
    assert!(attribution.losses.is_empty(), "{:?}", attribution.losses);
    let pids: Vec<u32> = attribution.members.iter().map(|m| m.pid).collect();
    assert_eq!(pids, vec![10_001]);
}

// ---- C5.6 owner ruling: proof stats on a bounded pool ----

/// A deterministic stat seam for one process: each range reads its
/// entry's `vm_file`, unless scripted as a fault (a stale range, a
/// refusal, or another file).
struct SeamStat {
    files: BTreeMap<(u64, u64), FileIdentity>,
    faults: BTreeMap<(u64, u64), Result<FileIdentity, String>>,
}

impl SeamStat {
    fn over(
        entries: &[MapEntry],
        faults: BTreeMap<(u64, u64), Result<FileIdentity, String>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            files: entries
                .iter()
                .map(|entry| ((entry.start, entry.end), vm_file(entry.inode)))
                .collect(),
            faults,
        })
    }
}

impl RangeStat for SeamStat {
    fn stat(&self, start: u64, end: u64) -> Result<FileIdentity, String> {
        // Jitter, so workers finish out of order.
        if (start >> 12).is_multiple_of(3) {
            std::thread::yield_now();
        }
        if let Some(fault) = self.faults.get(&(start, end)) {
            return fault.clone();
        }
        self.files
            .get(&(start, end))
            .copied()
            .ok_or_else(|| RANGE_NOT_MAPPED.to_string())
    }
}

/// Scripted confirmation reads whose proof reads go through the pool (or
/// one thread) over a [`SeamStat`].
struct PoolIo<'p> {
    base: Io,
    pool: Option<&'p ProofStatPool>,
    source: Arc<SeamStat>,
}

impl ConfirmIo for PoolIo<'_> {
    type Pin = u64;

    fn mapped_file(&mut self, _: u32, start: u64, end: u64) -> Result<FileIdentity, String> {
        self.source.stat(start, end)
    }

    fn mapped_files(&mut self, _: u32, ranges: &[(u64, u64)]) -> Vec<Result<FileIdentity, String>> {
        crate::discovery::proof_stats::stat_batch(self.pool, self.source.clone(), ranges)
    }

    fn open(&mut self, pid: u32) -> Result<u64, String> {
        self.base.open(pid)
    }

    fn start_time(&self, pin: &u64) -> Option<u64> {
        self.base.start_time(pin)
    }

    fn still_the_same(&self, pin: &u64) -> bool {
        self.base.still_the_same(pin)
    }

    fn exe(&self, pid: u32) -> Option<ExeIdentity> {
        self.base.exe(pid)
    }

    fn maps(&mut self, pid: u32, budget: &mut CaptureWorkBudget) -> Result<Vec<MapEntry>, String> {
        self.base.maps(pid, budget)
    }

    fn gone(&self, pid: u32) -> bool {
        self.base.gone(pid)
    }
}

/// Enough wide libs that the proof batches of both `wide(true)` (130
/// executable ranges of 260 entries) and `wide(false)` (129 of 258) reach
/// the pool: the pooled-equivalence tests below are vacuous unless the pool
/// engages. A6: only executable ranges are proved, so this doubled from 64
/// (whose 66 and 65 proof ranges now stay under `MIN_PARALLEL_BATCH`).
const WIDE_LIBS: u64 = 128;

/// The executable (proved) ranges of `entries`, in maps order.
fn exec_ranges(entries: &[MapEntry]) -> Vec<(u64, u64)> {
    entries
        .iter()
        .filter(|entry| entry.permissions[2] == b'x')
        .map(|entry| (entry.start, entry.end))
        .collect()
}

/// A caller (or, without the provider, an idle process) mapping enough
/// candidate ranges for its proof batch to reach the pool.
fn wide(provider: bool) -> Vec<MapEntry> {
    let mut entries = if provider {
        provider_caller()
    } else {
        idle(None)
    };
    for lib in 0..WIDE_LIBS {
        entries.extend(object(
            0x3000_0000 + lib * 0x10_0000,
            8_000 + lib,
            &format!("/usr/lib/libw{lib}.so"),
        ));
    }
    assert!(exec_ranges(&entries).len() >= MIN_PARALLEL_BATCH);
    entries
}

/// Faults by range for one pid, a deterministic function of the pid, on
/// the proved (executable) ranges: a stale provider text range, a refused
/// one, another file at it (an identity mismatch), a refused libc text
/// range, another file at a wide lib's text range (an examined key that is
/// then unexamined). On a pid with several, the first listed wins. A6
/// moved the libc refusal and the mismatch from the `r--` headers (no
/// longer read) to the text ranges; the header faults stay, so they also
/// show a non-executable range is never read.
fn faults_of(pid: u32) -> BTreeMap<(u64, u64), Result<FileIdentity, String>> {
    let mut faults = BTreeMap::new();
    let text = (0x1000_1000, 0x1000_2000);
    let refused = || Err("Operation not permitted (os error 1)".to_string());
    if pid.is_multiple_of(7) {
        faults.insert(text, Err(RANGE_NOT_MAPPED.to_string()));
    }
    if pid.is_multiple_of(11) {
        faults.entry(text).or_insert_with(refused);
    }
    if pid.is_multiple_of(13) {
        faults.entry(text).or_insert(Ok(vm_file(9_999)));
        faults.insert((0x1000_0000, 0x1000_1000), Ok(vm_file(9_999)));
    }
    if pid.is_multiple_of(19) {
        faults.insert((0x2000_1000, 0x2000_2000), refused());
        faults.insert((0x2000_0000, 0x2000_1000), refused());
    }
    if pid.is_multiple_of(17) {
        faults.insert((0x3010_1000, 0x3010_2000), Ok(vm_file(9_998)));
    }
    faults
}

/// One confirmation and one unpinned batch through the production
/// `confirm_with` and `stat_unpinned`, on any pool: the same results, the
/// same losses with the same causes, and a work ceiling that stops at the
/// same range — for every pool size, 1 (no workers) included.
#[test]
fn the_pool_confirms_and_stats_exactly_like_one_thread() {
    let entries = wide(true);
    let prove: BTreeSet<ObjectKey> = entries.iter().map(ObjectKey::of).collect();
    // What attribution hands the unpinned path: executable ranges only.
    let ranges = exec_ranges(&entries);
    let run = |pool: Option<&ProofStatPool>, ceiling: u64| {
        let source = SeamStat::over(&entries, faults_of(7 * 11 * 13));
        let mut io = PoolIo {
            base: Io {
                maps: Ok(entries.clone()),
                ..Io::healthy()
            },
            pool,
            source,
        };
        let confirmed = confirm_with(
            &mut io,
            10_001,
            &prove,
            &mut CaptureWorkBudget::with_work_ceiling(ceiling),
        );
        let unpinned = stat_unpinned(
            &mut io,
            10_001,
            &ranges,
            &mut CaptureWorkBudget::with_work_ceiling(ceiling),
        );
        (confirmed, unpinned)
    };
    // A6: a confirmation charges one unit per executable range only.
    let full = ranges.len() as u64;
    assert_eq!(full, 130);
    for ceiling in [0, 1, 5, 9, 15, full - 1, full, 1_000] {
        let serial = run(None, ceiling);
        if ceiling >= full {
            assert!(matches!(serial.0, Confirmation::Confirmed(_)));
        } else {
            assert!(matches!(
                serial.0,
                Confirmation::Lost(AttributionLoss::Budget, _)
            ));
        }
        assert_eq!(serial.1.len() as u64, ceiling.min(full));
        for threads in 1..=MAX_PROOF_STAT_THREADS {
            ProofStatPool::scoped(threads, |pool| {
                assert_eq!(
                    run(pool, ceiling),
                    serial,
                    "threads {threads} ceiling {ceiling}"
                );
            });
        }
    }
}

/// The production probe's shape over the seam: confirmations through
/// `confirm_with`, unpinned batches through `stat_unpinned`.
struct PooledProbe<'p> {
    pool: Option<&'p ProofStatPool>,
    snapshots: HashMap<u32, Vec<MapEntry>>,
}

impl PooledProbe<'_> {
    fn io(&self, pid: u32) -> PoolIo<'_> {
        let entries = self.snapshots.get(&pid).cloned().unwrap_or_default();
        PoolIo {
            source: SeamStat::over(&entries, faults_of(pid)),
            base: Io {
                maps: Ok(entries),
                ..Io::healthy()
            },
            pool: self.pool,
        }
    }
}

impl MemberProbe for PooledProbe<'_> {
    fn confirm(
        &mut self,
        pid: u32,
        prove: &BTreeSet<ObjectKey>,
        budget: &mut CaptureWorkBudget,
    ) -> Confirmation {
        confirm_with(&mut self.io(pid), pid, prove, budget)
    }

    fn stat_ranges(
        &mut self,
        pid: u32,
        ranges: &[(u64, u64)],
        budget: &mut CaptureWorkBudget,
    ) -> MappedIdentities {
        stat_unpinned(&mut self.io(pid), pid, ranges, budget)
    }
}

/// Over the 448 shape with faults spread across pids (stale ranges that
/// escalate or become `mapping_changed`, refusals, identity mismatches),
/// and a shared work ceiling that runs out part-way: every pool size
/// attributes exactly what one thread does.
#[test]
fn a_pooled_pass_attributes_exactly_like_a_serial_one() {
    let mut sweep: Vec<(u32, Vec<MapEntry>)> = (0..300)
        .map(|offset| (10_000 + offset, wide(true)))
        .collect();
    sweep.extend((0..148).map(|offset| (20_000 + offset, wide(false))));
    let selected = BTreeSet::from([10_000, 20_000]);
    let checks = Checks::default();
    let rep = wide(true);
    let index = KnownKeyIndex::build(
        [(key(PROVIDER), Some(OBJECT))],
        &BTreeMap::from([(key(PROVIDER), OBJECT)]),
        examined_of(&rep),
        &checks,
    )
    .0;
    let pass = |pool: Option<&ProofStatPool>, ceiling: u64| {
        let mut probe = PooledProbe {
            pool,
            snapshots: sweep.iter().cloned().collect(),
        };
        attribute_unselected(
            &sweep,
            &BTreeSet::new(),
            &selected,
            &index,
            &mut probe,
            &mut CaptureWorkBudget::with_work_ceiling(ceiling),
        )
    };
    for ceiling in [3_000, u64::MAX] {
        let serial = pass(None, ceiling);
        assert!(!serial.unexamined.is_empty());
        assert!(serial.losses.contains_key(&AttributionLoss::MappingChanged));
        assert!(
            serial
                .losses
                .contains_key(&AttributionLoss::IdentityMismatch)
        );
        assert!(
            serial
                .losses
                .contains_key(&AttributionLoss::MapFilesUnavailable)
        );
        if ceiling != u64::MAX {
            assert!(serial.losses.contains_key(&AttributionLoss::Budget));
        }
        for threads in 1..=MAX_PROOF_STAT_THREADS {
            ProofStatPool::scoped(threads, |pool| {
                assert_eq!(
                    pass(pool, ceiling),
                    serial,
                    "threads {threads} ceiling {ceiling}"
                );
            });
        }
    }
}

// ---- A6 (owner ruling 2026-10-05): exec-only proof ranges ----

/// One object's five loader mappings, as a typical shared library maps
/// them: the `r--` header, the `r-x` text, `r--` rodata, the `r--` RELRO
/// and the `rw-` data. Only the text is executable.
fn lib5(base: u64, inode: u64, path: &str) -> Vec<MapEntry> {
    [b"r--p", b"r-xp", b"r--p", b"r--p", b"rw-p"]
        .iter()
        .enumerate()
        .map(|(index, perms)| {
            let offset = index as u64 * 0x1000;
            let mut entry = mapping(base + offset, perms, inode, path);
            entry.file_offset = offset;
            entry
        })
        .collect()
}

/// [`lib5`] without its text: what a process that maps the file without
/// executing it (a scanner `mmap`-ing it read-only) shows.
fn data_only(base: u64, inode: u64, path: &str) -> Vec<MapEntry> {
    lib5(base, inode, path)
        .into_iter()
        .filter(|entry| entry.permissions[2] != b'x')
        .collect()
}

const PROVIDER_PATH: &str = "/usr/lib/softhsm/libsofthsm2.so";
const PROVIDER_TEXT: (u64, u64) = (0x1000_1000, 0x1000_2000);
const LIBC_TEXT: (u64, u64) = (0x2000_1000, 0x2000_2000);

/// A `dlopen` caller of the provider: provider and libc, five ranges each.
fn caller5() -> Vec<MapEntry> {
    let mut entries = lib5(0x1000_0000, PROVIDER, PROVIDER_PATH);
    entries.extend(lib5(0x2000_0000, LIBC, "/usr/lib/libc.so.6"));
    entries
}

/// Production confirmation reads (`confirm_with`, `stat_unpinned`) over a
/// scripted snapshot, recording every `map_files` read. A range reads its
/// entry's default `vm_file` unless `faults` scripts it.
struct CountingIo<'r> {
    base: Io,
    pid: u32,
    entries: Vec<MapEntry>,
    faults: MappedIdentities,
    reads: &'r RefCell<Vec<(u32, (u64, u64))>>,
}

impl ConfirmIo for CountingIo<'_> {
    type Pin = u64;

    fn mapped_file(&mut self, pid: u32, start: u64, end: u64) -> Result<FileIdentity, String> {
        self.reads.borrow_mut().push((pid, (start, end)));
        if let Some(fault) = self.faults.get(&(start, end)) {
            return fault.clone();
        }
        self.entries
            .iter()
            .find(|entry| (entry.start, entry.end) == (start, end))
            .map(|entry| vm_file(entry.inode))
            .ok_or_else(|| RANGE_NOT_MAPPED.to_string())
    }

    fn open(&mut self, _: u32) -> Result<u64, String> {
        Ok(u64::from(self.pid))
    }

    fn start_time(&self, _: &u64) -> Option<u64> {
        Some(5_000 + u64::from(self.pid))
    }

    fn still_the_same(&self, pin: &u64) -> bool {
        self.base.still_the_same(pin)
    }

    fn exe(&self, pid: u32) -> Option<ExeIdentity> {
        self.base.exe(pid)
    }

    fn maps(&mut self, _: u32, _: &mut CaptureWorkBudget) -> Result<Vec<MapEntry>, String> {
        Ok(self.entries.clone())
    }

    fn gone(&self, pid: u32) -> bool {
        self.base.gone(pid)
    }
}

/// The production probe's shape over [`CountingIo`].
struct CountingProbe {
    snapshots: HashMap<u32, Vec<MapEntry>>,
    faults: HashMap<u32, MappedIdentities>,
    reads: RefCell<Vec<(u32, (u64, u64))>>,
}

impl CountingProbe {
    fn over(sweep: &[(u32, Vec<MapEntry>)]) -> Self {
        Self {
            snapshots: sweep.iter().cloned().collect(),
            faults: HashMap::new(),
            reads: RefCell::new(Vec::new()),
        }
    }

    fn io(&self, pid: u32) -> CountingIo<'_> {
        CountingIo {
            base: Io::healthy(),
            pid,
            entries: self.snapshots.get(&pid).cloned().unwrap_or_default(),
            faults: self.faults.get(&pid).cloned().unwrap_or_default(),
            reads: &self.reads,
        }
    }

    fn reads_of(&self, pid: u32) -> Vec<(u64, u64)> {
        self.reads
            .borrow()
            .iter()
            .filter(|(read, _)| *read == pid)
            .map(|(_, range)| *range)
            .collect()
    }
}

impl MemberProbe for CountingProbe {
    fn confirm(
        &mut self,
        pid: u32,
        prove: &BTreeSet<ObjectKey>,
        budget: &mut CaptureWorkBudget,
    ) -> Confirmation {
        confirm_with(&mut self.io(pid), pid, prove, budget)
    }

    fn stat_ranges(
        &mut self,
        pid: u32,
        ranges: &[(u64, u64)],
        budget: &mut CaptureWorkBudget,
    ) -> MappedIdentities {
        stat_unpinned(&mut self.io(pid), pid, ranges, budget)
    }
}

/// The index a deep scan of the `caller5` representative builds: the
/// provider bound to `OBJECT`, libc examined without a module.
fn caller5_index() -> KnownKeyIndex {
    KnownKeyIndex::build(
        [(key(PROVIDER), Some(OBJECT))],
        &BTreeMap::from([(key(PROVIDER), OBJECT)]),
        examined_of(&caller5()),
        &Checks::default(),
    )
    .0
}

fn run_counting(
    sweep: &[(u32, Vec<MapEntry>)],
    probe: &mut CountingProbe,
) -> (SweepAttribution, u64) {
    let mut budget = CaptureWorkBudget::default();
    let attribution = attribute_unselected(
        sweep,
        &BTreeSet::new(),
        &BTreeSet::from([10_000]),
        &caller5_index(),
        probe,
        &mut budget,
    );
    (attribution, budget.work_units_count())
}

/// The ruling's first consequence: a process that maps the provider only
/// without `x` (a scanner reading the file) is not its caller. Nothing is
/// confirmed or proved for it, and it is neither a loss nor a coverage gap
/// — also for an unknown library and a known-but-ineligible key it maps
/// data-only. Only libc's text (an examined key) is statted.
#[test]
fn a_data_only_mapper_of_the_provider_is_never_attributed() {
    const REJECTED: u64 = 55;
    let mut scanner = data_only(0x1000_0000, PROVIDER, PROVIDER_PATH);
    scanner.extend(lib5(0x2000_0000, LIBC, "/usr/lib/libc.so.6"));
    scanner.extend(data_only(0x4000_0000, 88, "/opt/unknown/libother.so"));
    scanner.extend(data_only(
        0x5000_0000,
        REJECTED,
        "/opt/vendor/librejected.so",
    ));
    let sweep = vec![(10_000, caller5()), (10_001, scanner)];
    let index = KnownKeyIndex::build(
        [(key(PROVIDER), Some(OBJECT)), (key(REJECTED), None)],
        &BTreeMap::from([(key(PROVIDER), OBJECT)]),
        examined_of(&caller5()),
        &Checks::default(),
    )
    .0;
    assert_eq!(
        index.classify(key(REJECTED)),
        KeyClass::Ineligible(AttributionLoss::KeyRejected)
    );
    let mut probe = Probe::over(&sweep);
    let attribution = run(&sweep, &BTreeSet::from([10_000]), &index, &mut probe);
    assert!(attribution.members.is_empty(), "{:?}", attribution.members);
    assert!(attribution.losses.is_empty(), "{:?}", attribution.losses);
    assert!(
        attribution.unexamined.is_empty(),
        "{:?}",
        attribution.unexamined
    );
    assert_eq!(attribution.probed, 0, "no confirmation read");
    assert!(probe.calls.is_empty());
    assert_eq!(probe.statted, vec![(10_001, LIBC_TEXT)]);
}

/// A normal `dlopen` caller is attributed, and its confirmation proves
/// exactly the executable ranges of the keys that need proof: the
/// provider's text and libc's text, never their eight other ranges.
#[test]
fn a_dlopen_caller_is_attributed_by_proving_its_executable_ranges_only() {
    let sweep = vec![(10_000, caller5()), (10_001, caller5())];
    let mut probe = CountingProbe::over(&sweep);
    let (attribution, charged) = run_counting(&sweep, &mut probe);
    let pids: Vec<u32> = attribution.members.iter().map(|m| m.pid).collect();
    assert_eq!(pids, vec![10_001], "{:?}", attribution.member_losses);
    let object = &attribution.members[0].objects[0];
    assert_eq!((object.key, object.object), (key(PROVIDER), OBJECT));
    assert_eq!(object.path, PROVIDER_PATH);
    assert!(!object.double_loaded);
    assert!(attribution.losses.is_empty(), "{:?}", attribution.losses);
    assert!(attribution.unexamined.is_empty());
    assert_eq!(probe.reads_of(10_001), vec![PROVIDER_TEXT, LIBC_TEXT]);
    assert_eq!(charged, 2, "one work unit per proved range");
}

/// The ruling's second consequence: a maps-key collision (btrfs) on a
/// non-executable range of the key no longer costs the edge when the
/// executable range is the held file — whether the colliding identity is
/// never read (the production path) or is in hand anyway.
#[test]
fn a_collision_on_a_data_range_does_not_cost_an_exec_proven_edge() {
    let other_subvolume = Ok(FileIdentity {
        dev: 47,
        ino: PROVIDER,
    });
    let data: Vec<(u64, u64)> = data_only(0x1000_0000, PROVIDER, PROVIDER_PATH)
        .iter()
        .map(|entry| (entry.start, entry.end))
        .collect();
    let collided: MappedIdentities = data
        .iter()
        .map(|range| (*range, other_subvolume.clone()))
        .collect();

    let sweep = vec![(10_000, caller5()), (10_001, caller5())];
    let mut probe = CountingProbe::over(&sweep);
    probe.faults.insert(10_001, collided.clone());
    let (attribution, _) = run_counting(&sweep, &mut probe);
    let pids: Vec<u32> = attribution.members.iter().map(|m| m.pid).collect();
    assert_eq!(pids, vec![10_001], "{:?}", attribution.member_losses);
    assert!(attribution.losses.is_empty(), "{:?}", attribution.losses);
    assert!(
        probe
            .reads_of(10_001)
            .iter()
            .all(|range| !data.contains(range)),
        "a data range is never read"
    );

    // The confirmation hands over the colliding data-range identities too:
    // the match still proves only its executable range.
    let mut mapped = collided;
    mapped.insert(PROVIDER_TEXT, Ok(vm_file(PROVIDER)));
    mapped.insert(LIBC_TEXT, Ok(vm_file(LIBC)));
    let mut scripted = Probe::over(&sweep);
    scripted.overrides.insert(
        10_001,
        Confirmation::Confirmed(ConfirmedRead {
            start_time: 5_001,
            exe: exe(),
            entries: caller5(),
            mapped,
        }),
    );
    let attribution = run(
        &sweep,
        &BTreeSet::from([10_000]),
        &caller5_index(),
        &mut scripted,
    );
    let pids: Vec<u32> = attribution.members.iter().map(|m| m.pid).collect();
    assert_eq!(pids, vec![10_001], "{:?}", attribution.member_losses);
}

/// The executable range is still proved like for like: when it fails, the
/// caller is not attributed, with that range's own reason.
#[test]
fn an_exec_range_that_fails_its_proof_is_not_attributed_with_its_reason() {
    let cases = [
        (
            Ok(FileIdentity {
                dev: 47,
                ino: PROVIDER,
            }),
            AttributionLoss::IdentityMismatch,
            "the range 10001000-10002000 maps another file",
        ),
        (
            Err(RANGE_NOT_MAPPED.to_string()),
            AttributionLoss::MappingChanged,
            "the range 10001000-10002000 was no longer one mapping",
        ),
        (
            Err("Operation not permitted (os error 1)".to_string()),
            AttributionLoss::MapFilesUnavailable,
            "the map_files identity of 10001000-10002000 could not be read",
        ),
    ];
    for (fault, loss, reason) in cases {
        let sweep = vec![(10_000, caller5()), (10_001, caller5())];
        let mut probe = CountingProbe::over(&sweep);
        probe
            .faults
            .insert(10_001, MappedIdentities::from([(PROVIDER_TEXT, fault)]));
        let (attribution, _) = run_counting(&sweep, &mut probe);
        assert!(attribution.members.is_empty(), "{loss:?}");
        assert_eq!(attribution.losses, BTreeMap::from([(loss, 1)]));
        let (first, detail) = &attribution.member_losses[&10_001];
        assert_eq!(*first, loss);
        assert!(detail.contains(reason), "{detail}");
    }
}

/// A key with several executable ranges (a split or second text mapping):
/// every one must prove; one failing costs the edge.
#[test]
fn every_executable_range_of_a_key_must_prove() {
    let second_text = (0x1000_5000, 0x1000_6000);
    let mut split = caller5();
    let mut extra = mapping(second_text.0, b"r-xp", PROVIDER, PROVIDER_PATH);
    extra.file_offset = 0x5000;
    split.push(extra);
    let sweep = vec![(10_000, caller5()), (10_001, split)];

    let mut probe = CountingProbe::over(&sweep);
    let (attribution, _) = run_counting(&sweep, &mut probe);
    let pids: Vec<u32> = attribution.members.iter().map(|m| m.pid).collect();
    assert_eq!(pids, vec![10_001], "{:?}", attribution.member_losses);
    assert_eq!(
        probe.reads_of(10_001),
        vec![PROVIDER_TEXT, LIBC_TEXT, second_text]
    );

    let mut probe = CountingProbe::over(&sweep);
    probe.faults.insert(
        10_001,
        MappedIdentities::from([(second_text, Ok(vm_file(9_999)))]),
    );
    let (attribution, _) = run_counting(&sweep, &mut probe);
    assert!(attribution.members.is_empty());
    assert_eq!(
        attribution.losses,
        BTreeMap::from([(AttributionLoss::IdentityMismatch, 1)])
    );
    let (_, detail) = &attribution.member_losses[&10_001];
    assert!(detail.contains("10005000-10006000"), "{detail}");
}

/// The proof count, exactly, for libraries of five ranges (one
/// executable): ten callers prove the provider's and libc's text (2 each),
/// five idle processes prove libc's text unpinned (1 each), and a scanner
/// mapping the provider data-only proves only libc's text (1) and is never
/// confirmed. 26 `map_files` reads and 26 work units, where proving every
/// range read 10 × 10 + 5 × 5 + (4 + 5) = 134.
#[test]
fn proof_count_for_five_range_libraries_is_one_per_executable_range() {
    let mut sweep: Vec<(u32, Vec<MapEntry>)> =
        (10_000..=10_010).map(|pid| (pid, caller5())).collect();
    sweep.extend((20_001..=20_005).map(|pid| (pid, lib5(0x2000_0000, LIBC, "/usr/lib/libc.so.6"))));
    let mut scanner = data_only(0x1000_0000, PROVIDER, PROVIDER_PATH);
    scanner.extend(lib5(0x2000_0000, LIBC, "/usr/lib/libc.so.6"));
    sweep.push((30_001, scanner));

    let mut probe = CountingProbe::over(&sweep);
    let (attribution, charged) = run_counting(&sweep, &mut probe);
    let pids: Vec<u32> = attribution.members.iter().map(|m| m.pid).collect();
    assert_eq!(pids, (10_001..=10_010).collect::<Vec<u32>>());
    assert_eq!(attribution.probed, 10, "the scanner is never confirmed");
    assert!(attribution.losses.is_empty(), "{:?}", attribution.losses);
    assert!(attribution.unexamined.is_empty());
    let reads = probe.reads.borrow().len();
    assert_eq!(reads, 26, "{:?}", probe.reads.borrow());
    assert_eq!(charged, 26);
    assert_eq!(probe.reads_of(30_001), vec![LIBC_TEXT]);
    for pid in 20_001..=20_005 {
        assert_eq!(probe.reads_of(pid), vec![LIBC_TEXT]);
    }
}

/// A real process (unprivileged): one page of a `.so` mapped read-only is
/// never confirmed or proved, even with an index binding its exact key.
#[test]
fn a_real_data_only_mapping_is_never_confirmed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("libdataonly.so");
    std::fs::write(&path, vec![0x22u8; 8192]).unwrap();
    let child = SwapChild::spawn_with(&[(&path, false)]);
    let snapshot = child.maps();
    let line = snapshot
        .iter()
        .find(|entry| entry.start == child.address)
        .expect("the child's mapping")
        .clone();
    assert_eq!(&line.permissions, b"r--p");
    let index = index_binding(ObjectKey::of(&line), vm_file(line.inode), None);
    let attribution = attribute_child(&child, snapshot, &index);
    assert!(attribution.members.is_empty(), "{:?}", attribution.members);
    assert!(attribution.losses.is_empty(), "{:?}", attribution.losses);
    assert_eq!(attribution.probed, 0);
}

/// A real process: an executable mapping of the same kind of file is
/// confirmed and its range proved — attributed as root (`map_files`
/// readable), a `map_files_unavailable` loss otherwise (fail closed).
#[test]
fn a_real_executable_mapping_is_confirmed_and_proved() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("libexec.so");
    std::fs::write(&path, vec![0x33u8; 8192]).unwrap();
    let child = SwapChild::spawn(&path);
    let snapshot = child.maps();
    let line = snapshot
        .iter()
        .find(|entry| entry.start == child.address)
        .expect("the child's mapping")
        .clone();
    assert_eq!(&line.permissions, b"r-xp");
    let held =
        crate::discovery::identity::self_mapped_identity(&std::fs::File::open(&path).unwrap());
    let index = index_binding(
        ObjectKey::of(&line),
        held.clone().unwrap_or(vm_file(line.inode)),
        None,
    );
    let attribution = attribute_child(&child, snapshot, &index);
    assert_eq!(attribution.probed, 1, "confirmed");
    if held.is_ok() {
        let pids: Vec<u32> = attribution.members.iter().map(|m| m.pid).collect();
        assert_eq!(
            pids,
            vec![child.pid as u32],
            "{:?}",
            attribution.member_losses
        );
    } else {
        assert!(attribution.members.is_empty());
        assert_eq!(
            attribution.losses,
            BTreeMap::from([(AttributionLoss::MapFilesUnavailable, 1)])
        );
    }
}

/// Root on a btrfs TMPDIR, through the production probe: two subvolumes'
/// files share a maps key. A caller maps the held file executable and the
/// other one read-only under the same key: the data range is not a caller
/// range, so the edge stands on its proven text. Swapping the roles (the
/// other file executable) is an identity mismatch, and a process mapping
/// the held file only read-only is not a caller at all.
#[test]
#[ignore = "root (map_files) on a btrfs TMPDIR: creates two subvolumes there"]
fn privileged_a_btrfs_collision_on_a_data_range_keeps_the_exec_proven_edge() {
    use std::os::unix::fs::MetadataExt as _;
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path();
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let c_parent = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid path and buffer, read only on success.
    assert_eq!(
        unsafe { libc::statfs(c_parent.as_ptr(), stat.as_mut_ptr()) },
        0
    );
    // SAFETY: initialized by the successful statfs.
    let magic = (unsafe { stat.assume_init().f_type }) as u64 & 0xffff_ffff;
    assert_eq!(magic, 0x9123_683e, "TMPDIR must be on btrfs");
    create_subvolume(parent, "s");
    create_subvolume(parent, "t");
    let held_path = parent.join("s/libcollide.so");
    let other_path = parent.join("t/libcollide.so");
    std::fs::write(&held_path, vec![0xa5u8; 8192]).unwrap();
    std::fs::write(&other_path, vec![0x5au8; 8192]).unwrap();
    let (a, b) = (
        std::fs::metadata(&held_path).unwrap(),
        std::fs::metadata(&other_path).unwrap(),
    );
    assert_eq!(a.ino(), b.ino(), "fresh subvolumes repeat inode numbers");
    assert_ne!(a.dev(), b.dev());
    let held =
        crate::discovery::identity::self_mapped_identity(&std::fs::File::open(&held_path).unwrap())
            .expect("map_files is readable as root");

    let line_at = |child: &SwapChild, address: u64| {
        child
            .maps()
            .into_iter()
            .find(|entry| entry.start == address)
            .expect("the child's mapping")
    };
    // The held file's text plus the other file read-only, one maps key.
    let caller = SwapChild::spawn_with(&[(&held_path, true), (&other_path, false)]);
    let (text, data) = (
        line_at(&caller, caller.addresses[0]),
        line_at(&caller, caller.addresses[1]),
    );
    assert_eq!(&text.permissions, b"r-xp");
    assert_eq!(&data.permissions, b"r--p");
    assert_eq!(
        ObjectKey::of(&text),
        ObjectKey::of(&data),
        "both files render one maps key"
    );
    let index = index_binding(ObjectKey::of(&text), held, None);
    let attribution = attribute_child(&caller, caller.maps(), &index);
    let pids: Vec<u32> = attribution.members.iter().map(|m| m.pid).collect();
    assert_eq!(
        pids,
        vec![caller.pid as u32],
        "{:?}",
        attribution.member_losses
    );
    assert!(attribution.losses.is_empty(), "{:?}", attribution.losses);

    // The other file executable, the held one read-only: a mismatch.
    let swapped = SwapChild::spawn_with(&[(&other_path, true), (&held_path, false)]);
    let attribution = attribute_child(&swapped, swapped.maps(), &index);
    assert!(attribution.members.is_empty(), "{:?}", attribution.members);
    assert_eq!(
        attribution.losses,
        BTreeMap::from([(AttributionLoss::IdentityMismatch, 1)])
    );

    // The held file read-only only: not a caller, nothing proved.
    let reader = SwapChild::spawn_with(&[(&held_path, false)]);
    let attribution = attribute_child(&reader, reader.maps(), &index);
    assert!(attribution.members.is_empty(), "{:?}", attribution.members);
    assert!(attribution.losses.is_empty(), "{:?}", attribution.losses);
    assert_eq!(attribution.probed, 0);

    drop((caller, swapped, reader));
    std::fs::remove_file(&held_path).unwrap();
    std::fs::remove_file(&other_path).unwrap();
    std::fs::remove_dir(parent.join("s")).unwrap();
    std::fs::remove_dir(parent.join("t")).unwrap();
}

/// Root with a loop-mounted ext4: there a held file's maps key is its
/// identity, so no per-range stat runs at all. Before A6 a process that
/// mapped the file only read-only was attributed on the key alone; now
/// only the executable mapper is.
#[test]
#[ignore = "root: mounts a loop ext4 image (mkfs.ext4, mount, umount)"]
fn privileged_a_data_only_mapper_of_an_identity_key_is_never_attributed_on_ext4() {
    let ext4 = Ext4Loop::new();
    let path = ext4.mount.join("libidentity.so");
    std::fs::write(&path, vec![0x44u8; 8192]).unwrap();
    let caller = SwapChild::spawn(&path);
    let reader = SwapChild::spawn_with(&[(&path, false)]);
    let line = caller
        .maps()
        .into_iter()
        .find(|entry| entry.start == caller.address)
        .expect("the caller's mapping");
    let key_k = ObjectKey::of(&line);
    let index = index_binding(
        key_k,
        FileIdentity {
            dev: libc::makedev(key_k.device.major as u32, key_k.device.minor as u32),
            ino: key_k.inode,
        },
        Some(0xef53),
    );
    assert!(
        !index.map_files_keys().contains(&key_k),
        "an identity key: no per-range proof"
    );
    let attributed = attribute_child(&caller, caller.maps(), &index);
    let pids: Vec<u32> = attributed.members.iter().map(|m| m.pid).collect();
    assert_eq!(
        pids,
        vec![caller.pid as u32],
        "{:?}",
        attributed.member_losses
    );

    let read_only = attribute_child(&reader, reader.maps(), &index);
    assert!(read_only.members.is_empty(), "{:?}", read_only.members);
    assert!(read_only.losses.is_empty(), "{:?}", read_only.losses);
    assert_eq!(read_only.probed, 0);
    drop((caller, reader));
}
