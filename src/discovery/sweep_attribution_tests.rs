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

/// The objects a deep scan of `entries` examined: every caller range's
/// object (as production builds them from caller groups), with its
/// self-mapped `vm_file` identity.
fn examined_of<'a>(entries: impl IntoIterator<Item = &'a MapEntry>) -> Vec<ExaminedObject> {
    entries
        .into_iter()
        .filter(|entry| is_caller_range(entry))
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
                    return (
                        range,
                        RangeProof::Unavailable("Operation not permitted (os error 1)".into()),
                    );
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
                            .map(|entry| RangeProof::MapFiles(vm_file(entry.inode)))
                            .unwrap_or_else(|| {
                                RangeProof::Unavailable(
                                    "No such file or directory (os error 2)".into(),
                                )
                            })
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
        .map(|entry| ((entry.start, entry.end), RangeProof::MapFiles(identity)))
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
            RangeProof::MapFiles(FileIdentity {
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
            .all(|identity| identity == &RangeProof::MapFiles(vm_file(PROVIDER)))
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
    // musl `ioctl` takes a c_int request, glibc a c_ulong one; the
    // number fits both.
    #[cfg(target_env = "musl")]
    const BTRFS_IOC_SUBVOL_CREATE: libc::c_int = 0x5000_940e;
    #[cfg(not(target_env = "musl"))]
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

#[derive(Debug, PartialEq, Eq)]
struct BindSetupError {
    stage: &'static str,
    errno: i32,
}

/// Child-local reply: stage, errno, address, actual opened-file dev and ino.
/// All words are initialized integers; this is private to one fork's pipe.
fn decode_bind_ready(words: [u64; 5]) -> Result<(u64, FileIdentity), BindSetupError> {
    let protocol = || BindSetupError {
        stage: "reply",
        errno: libc::EPROTO,
    };
    if words[0] != 0 {
        let stage = match words[0] {
            1 => "unshare",
            2 => "make-private",
            3 => "bind",
            4 => "open-alias",
            5 => "stat-alias",
            6 => "stat-held-source",
            7 => "source-identity",
            8 => "mmap",
            9 => "stat-child-namespace",
            10 => "namespace-unchanged",
            _ => return Err(protocol()),
        };
        let errno = i32::try_from(words[1])
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(protocol)?;
        return Err(BindSetupError { stage, errno });
    }
    if words[1] != 0 || words[2] == 0 || words[2].checked_add(4096).is_none() || words[4] == 0 {
        return Err(protocol());
    }
    Ok((
        words[2],
        FileIdentity {
            dev: words[3],
            ino: words[4],
        },
    ))
}

fn read_bind_ready(fd: std::os::fd::BorrowedFd<'_>) -> Result<(u64, FileIdentity), BindSetupError> {
    use std::os::fd::AsRawFd as _;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut bytes = [0u8; 40];
    let mut have = 0;
    while have < bytes.len() {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(BindSetupError {
                stage: "ready-deadline",
                errno: libc::ETIMEDOUT,
            });
        }
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd, followed by a read into the owned buffer.
        let ready = unsafe { libc::poll(&raw mut poll, 1, remaining.as_millis().max(1) as i32) };
        if ready < 0 {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if errno == libc::EINTR {
                continue;
            }
            return Err(BindSetupError {
                stage: "ready-poll",
                errno,
            });
        }
        if ready == 0 {
            continue;
        }
        // SAFETY: the remaining slice is writable and the polled descriptor is live.
        let got = unsafe {
            libc::read(
                fd.as_raw_fd(),
                bytes[have..].as_mut_ptr().cast(),
                bytes.len() - have,
            )
        };
        if got <= 0 {
            let errno = if got == 0 {
                libc::EPIPE
            } else {
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            };
            if errno == libc::EINTR {
                continue;
            }
            return Err(BindSetupError {
                stage: "ready-read",
                errno,
            });
        }
        have += got as usize;
    }
    decode_bind_ready(std::array::from_fn(|index| {
        u64::from_ne_bytes(bytes[index * 8..(index + 1) * 8].try_into().unwrap())
    }))
}

fn reap_owned_swap_child(pid: libc::pid_t) {
    // SAFETY: this PID is an owned, unreaped fork child, including startup failures.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        loop {
            if libc::waitpid(pid, std::ptr::null_mut(), 0) >= 0 {
                break;
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }
    }
}

struct PendingBindChild(Option<libc::pid_t>);

impl Drop for PendingBindChild {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            reap_owned_swap_child(pid);
        }
    }
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

    /// One child-private bind mount and mapping. The parent never enters the
    /// namespace or mounts anything. Setup errors are returned, never a skip.
    fn spawn_private_bind(
        source: &std::path::Path,
        held_source: &std::fs::File,
        alias: &std::path::Path,
        executable: bool,
    ) -> Result<(Self, FileIdentity), BindSetupError> {
        use std::os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _, OwnedFd};
        use std::os::unix::fs::MetadataExt as _;
        let path = |path: &std::path::Path| {
            std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
                BindSetupError {
                    stage: "path",
                    errno: libc::EINVAL,
                }
            })
        };
        let source = path(source)?;
        let alias = path(alias)?;
        let parent_namespace =
            std::fs::metadata("/proc/self/ns/mnt").map_err(|error| BindSetupError {
                stage: "stat-parent-namespace",
                errno: error.raw_os_error().unwrap_or(libc::EIO),
            })?;
        let parent_namespace = (parent_namespace.dev(), parent_namespace.ino());
        let pipe = || -> Result<(OwnedFd, OwnedFd), BindSetupError> {
            let mut fds = [0; 2];
            // SAFETY: pipe2 initializes two new owned descriptors on success.
            if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
                return Err(BindSetupError {
                    stage: "pipe",
                    errno: std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EIO),
                });
            }
            // SAFETY: successful pipe2 returned two new, independently owned fds.
            Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
        };
        let (down_read, down_write) = pipe()?;
        let (up_read, up_write) = pipe()?;
        let protection = libc::PROT_READ | if executable { libc::PROT_EXEC } else { 0 };
        // SAFETY: child uses only raw syscalls, fixed stack buffers and paths
        // allocated before fork; it never returns into the Rust test harness.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(BindSetupError {
                stage: "fork",
                errno: std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO),
            });
        }
        if pid == 0 {
            // SAFETY: syscall arguments refer to inherited live fds/paths or
            // initialized stack buffers. Every error reports and calls _exit.
            unsafe {
                libc::close(down_write.as_raw_fd());
                libc::close(up_read.as_raw_fd());
                let report = |words: [u64; 5]| {
                    let mut sent = 0;
                    while sent < 40 {
                        let got = libc::write(
                            up_write.as_raw_fd(),
                            words.as_ptr().cast::<u8>().add(sent).cast(),
                            40 - sent,
                        );
                        if got < 0 && *libc::__errno_location() == libc::EINTR {
                            continue;
                        }
                        if got <= 0 {
                            libc::_exit(99);
                        }
                        sent += got as usize;
                    }
                };
                let fail = |stage: u64, errno: i32| -> ! {
                    report([stage, errno as u64, 0, 0, 0]);
                    libc::_exit(100 + stage as i32);
                };
                if libc::syscall(libc::SYS_unshare, libc::CLONE_NEWNS) != 0 {
                    fail(1, *libc::__errno_location());
                }
                let mut namespace = std::mem::MaybeUninit::<libc::stat>::uninit();
                if libc::stat(c"/proc/self/ns/mnt".as_ptr(), namespace.as_mut_ptr()) != 0 {
                    fail(9, *libc::__errno_location());
                }
                let namespace = namespace.assume_init();
                if (namespace.st_dev, namespace.st_ino) == parent_namespace {
                    fail(10, libc::EXDEV);
                }
                if libc::syscall(
                    libc::SYS_mount,
                    std::ptr::null::<libc::c_char>(),
                    c"/".as_ptr(),
                    std::ptr::null::<libc::c_char>(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null::<libc::c_void>(),
                ) != 0
                {
                    fail(2, *libc::__errno_location());
                }
                // Resolve this owned source in the new namespace. An inherited
                // /proc/self/fd source still belongs to the parent's mount tree.
                if libc::syscall(
                    libc::SYS_mount,
                    source.as_ptr(),
                    alias.as_ptr(),
                    std::ptr::null::<libc::c_char>(),
                    libc::MS_BIND,
                    std::ptr::null::<libc::c_void>(),
                ) != 0
                {
                    fail(3, *libc::__errno_location());
                }
                let fd = libc::open(
                    alias.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                );
                if fd < 0 {
                    fail(4, *libc::__errno_location());
                }
                let mut mapped = std::mem::MaybeUninit::<libc::stat>::uninit();
                let mut held = std::mem::MaybeUninit::<libc::stat>::uninit();
                if libc::fstat(fd, mapped.as_mut_ptr()) != 0 {
                    fail(5, *libc::__errno_location());
                }
                if libc::fstat(held_source.as_raw_fd(), held.as_mut_ptr()) != 0 {
                    fail(6, *libc::__errno_location());
                }
                let (mapped, held) = (mapped.assume_init(), held.assume_init());
                if (mapped.st_dev, mapped.st_ino) != (held.st_dev, held.st_ino) {
                    fail(7, libc::EXDEV);
                }
                let first = libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    protection,
                    libc::MAP_PRIVATE,
                    fd,
                    0,
                );
                let map_errno = *libc::__errno_location();
                libc::close(fd);
                if first == libc::MAP_FAILED {
                    fail(8, map_errno);
                }
                report([0, 0, first as u64, mapped.st_dev, mapped.st_ino]);
                let mut command = 0u8;
                loop {
                    let got = libc::read(down_read.as_raw_fd(), (&raw mut command).cast(), 1);
                    if got < 0 && *libc::__errno_location() == libc::EINTR {
                        continue;
                    }
                    if got != 1 || command != b's' {
                        break;
                    }
                    libc::munmap(first, 4096);
                    let fd = libc::open(alias.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                    let again = libc::mmap(
                        first,
                        4096,
                        protection,
                        libc::MAP_PRIVATE | libc::MAP_FIXED_NOREPLACE,
                        fd,
                        0,
                    );
                    libc::close(fd);
                    let ok = u8::from(again == first);
                    if libc::write(up_write.as_raw_fd(), (&raw const ok).cast(), 1) != 1 {
                        break;
                    }
                }
                libc::_exit(0);
            }
        }
        let mut pending = PendingBindChild(Some(pid));
        drop((down_read, up_write));
        let (address, identity) = read_bind_ready(up_read.as_fd())?;
        let child = Self {
            pid,
            command: down_write,
            reply: up_read,
            address,
            addresses: vec![address],
        };
        pending.0 = None;
        Ok((child, identity))
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
        reap_owned_swap_child(self.pid);
    }
}

#[test]
fn d4_bind_startup_reply_requires_success_and_a_valid_mapping() {
    let healthy = [0, 0, 0x1000, 37, 123];
    let expected = (0x1000, FileIdentity { dev: 37, ino: 123 });
    assert_eq!(decode_bind_ready(healthy), Ok(expected));
    assert_eq!(
        decode_bind_ready([1, libc::EPERM as u64, 0, 0, 0]),
        Err(BindSetupError {
            stage: "unshare",
            errno: libc::EPERM
        })
    );
    assert_eq!(
        decode_bind_ready([3, libc::EACCES as u64, 0, 0, 0]),
        Err(BindSetupError {
            stage: "bind",
            errno: libc::EACCES
        })
    );
    assert_eq!(
        decode_bind_ready([7, libc::EXDEV as u64, 0, 0, 0]),
        Err(BindSetupError {
            stage: "source-identity",
            errno: libc::EXDEV
        })
    );
    for invalid in [
        [0, 1, 0x1000, 37, 123],
        [0, 0, 0, 37, 123],
        [0, 0, u64::MAX, 37, 123],
        [0, 0, 0x1000, 37, 0],
        [11, 1, 0, 0, 0],
    ] {
        assert!(decode_bind_ready(invalid).is_err());
        assert_eq!(decode_bind_ready(healthy), Ok(expected));
    }
}

#[test]
fn d4_bind_startup_eof_reaps_the_owned_child() {
    use std::os::fd::{AsFd as _, FromRawFd as _, OwnedFd};
    let mut fds = [0; 2];
    // SAFETY: pipe2 writes two newly owned descriptors into the live array.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: successful pipe2 returned both fds, each adopted once.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // SAFETY: the child only closes raw fds and exits without entering Rust.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // SAFETY: only inherited descriptors and _exit in the fork child.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
            libc::_exit(0);
        }
    }
    let pending = PendingBindChild(Some(pid));
    drop(write);
    assert_eq!(
        read_bind_ready(read.as_fd()),
        Err(BindSetupError {
            stage: "ready-read",
            errno: libc::EPIPE
        })
    );
    drop(pending);
    // SAFETY: querying only this test's PID; the guard must already have reaped it.
    assert_eq!(
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

fn d4_private_bind_mount(mountinfo: &str, alias: &std::path::Path) -> Result<(), &'static str> {
    let escaped = alias
        .to_str()
        .ok_or("non-UTF8 fixture path")?
        .replace('\\', "\\134")
        .replace(' ', "\\040")
        .replace('\t', "\\011")
        .replace('\n', "\\012");
    let mut found = false;
    for line in mountinfo.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.get(4) != Some(&escaped.as_str()) {
            continue;
        }
        if found {
            return Err("duplicate alias mount");
        }
        let separator = fields
            .iter()
            .position(|field| *field == "-")
            .ok_or("malformed alias mount")?;
        if separator < 6 || fields.get(separator + 1) != Some(&"btrfs") {
            return Err("alias is not a Btrfs mount");
        }
        if fields[6..separator].iter().any(|field| {
            field.starts_with("shared:")
                || field.starts_with("master:")
                || field.starts_with("propagate_from:")
        }) {
            return Err("alias mount propagates");
        }
        found = true;
    }
    if found { Ok(()) } else { Err("no alias mount") }
}

#[test]
fn d4_bind_mountinfo_requires_one_private_btrfs_alias() {
    let alias = std::path::Path::new("/owned/libalias.so");
    let healthy =
        "72 25 0:47 /owned/liboriginal.so /owned/libalias.so rw - btrfs /dev/fixture rw\n";
    assert_eq!(d4_private_bind_mount(healthy, alias), Ok(()));
    for bad in [
        healthy.replace(" rw -", " rw shared:1 -"),
        healthy.replace(" rw -", " rw master:1 -"),
        healthy.replace("btrfs", "tmpfs"),
        healthy.replace("/owned/libalias.so", "/other/libalias.so"),
        format!("{healthy}{healthy}"),
    ] {
        assert!(d4_private_bind_mount(&bad, alias).is_err());
        assert_eq!(d4_private_bind_mount(healthy, alias), Ok(()));
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
    attribute_pid(child.pid as u32, snapshot, index)
}

fn attribute_pid(pid: u32, snapshot: Vec<MapEntry>, index: &KnownKeyIndex) -> SweepAttribution {
    attribute_unselected(
        &[(pid, snapshot)],
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
    // `f_type` is signed on glibc and unsigned on musl; the magic fits both.
    #[allow(clippy::unnecessary_cast)]
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
    let source = Arc::new(HeldMapFiles {
        dir: Some(held),
        lease: None,
        closed: DropFence::default(),
        observer: None,
    });
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
        MappedIdentities::from([(libc_range, RangeProof::NotMapped)]),
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
        MappedIdentities::from([(libc_range, RangeProof::NotMapped)]),
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
            MappedIdentities::from([(range, RangeProof::NotMapped)]),
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
            ((0x1000_0000, 0x1000_1000), RangeProof::NotMapped),
            ((0x2000_0000, 0x2000_1000), RangeProof::NotMapped),
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
            return match fault {
                RangeProof::MapFiles(identity) => Ok(*identity),
                RangeProof::NotMapped => Err(RANGE_NOT_MAPPED.into()),
                RangeProof::Unavailable(error) => Err(error.clone()),
                _ => panic!("the OS seam emits no kernel evidence"),
            };
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
    let other_subvolume = RangeProof::MapFiles(FileIdentity {
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
    mapped.insert(PROVIDER_TEXT, RangeProof::MapFiles(vm_file(PROVIDER)));
    mapped.insert(LIBC_TEXT, RangeProof::MapFiles(vm_file(LIBC)));
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
        probe.faults.insert(
            10_001,
            MappedIdentities::from([(PROVIDER_TEXT, RangeProof::from(fault))]),
        );
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
        MappedIdentities::from([(second_text, RangeProof::MapFiles(vm_file(9_999)))]),
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
    // `f_type` is signed on glibc and unsigned on musl; the magic fits both.
    #[allow(clippy::unnecessary_cast)]
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

fn d4_kernel_collision_attribution(
    child: &SwapChild,
    snapshot: Vec<MapEntry>,
    pins: &crate::discovery::identity::PinnedObjects,
    object: PinnedObjectId,
    key: ObjectKey,
    session: &mut crate::discovery::kernel_identity::IdentitySession,
    generation: u64,
) -> SweepAttribution {
    d4_kernel_attribution_for_pid(
        child.pid as u32,
        snapshot,
        pins,
        object,
        key,
        session,
        generation,
    )
}

fn d4_kernel_attribution_for_pid(
    pid: u32,
    snapshot: Vec<MapEntry>,
    pins: &crate::discovery::identity::PinnedObjects,
    object: PinnedObjectId,
    key: ObjectKey,
    session: &mut crate::discovery::kernel_identity::IdentitySession,
    generation: u64,
) -> SweepAttribution {
    use crate::discovery::kernel_identity::{AnchorPass, ExaminedCustody, KernelMemberProbe};
    use std::sync::{Arc, Mutex};

    let (mut index, refused) = KnownKeyIndex::build(
        [(key, Some(object))],
        &BTreeMap::from([(key, object)]),
        [],
        pins,
    );
    assert!(refused.is_empty(), "{refused:?}");
    assert!(
        index.map_files_keys().contains(&key),
        "Btrfs collision must require actual per-range proof"
    );
    let owner = ReservationOwner::for_examined(
        SegmentPolicy::try_snapshot(0, 0).expect("actual FD census"),
        0,
    );
    let mut custody = ExaminedCustody::new(owner, BTreeMap::new());
    custody
        .reconcile(SegmentPolicy::try_snapshot(1, 1).expect("actual confirmation FD census"))
        .expect("shared physical reservation owner");
    let pass = AnchorPass::prepare(pins, [(key, object)], custody);
    assert!(pass.fallback.is_empty(), "{:?}", pass.fallback);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut installed = session
        .install_anchors(pass, generation, deadline)
        .expect("install actual held-file anchors");
    let trace = Arc::new(Mutex::new(ProofTrace::default()));
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
                .get(&key)
                .is_some_and(|slots| !slots.is_empty()),
            "the held provider has no validated actual kernel slot"
        );
        let mut budget = CaptureWorkBudget::default();
        assert!(
            !budget.has_collection_work(),
            "exercise actual kernel proof, not scoped fallback"
        );
        attribute_unselected(
            &[(pid, snapshot)],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &index,
            &mut probe,
            &mut budget,
        )
    };
    drop(installed);
    let fallback = session.fallback_totals();
    assert_eq!(fallback.passes, 0, "{fallback:?}");
    assert_eq!(fallback.pids, 0, "{fallback:?}");
    assert_eq!(fallback.keys, 0, "{fallback:?}");
    assert!(fallback.first_reason.is_none(), "{fallback:?}");
    assert!(
        trace.lock().unwrap().reads.is_empty(),
        "the required kernel leg performed userspace range-proof reads"
    );
    out
}

/// Actual identity-substrate parity on one live population: two equal-byte
/// files in separate Btrfs subvolumes have one lexical maps key but different
/// physical identities. No gcc, source files or external provider are needed
/// at runtime: the real identity object is embedded in this libtest.
/// Same-line remapping and the complete five D4 rows remain separate gates.
#[test]
#[ignore = "root Btrfs disk TMPDIR plus eligible BTF/task_vma identity; actual kernel/userspace parity"]
fn privileged_d4_btrfs_subvolume_collision_backend_parity() {
    use crate::discovery::identity::{PinnedObjects, test_fixture::real_scan_pin};
    use crate::discovery::kernel_identity::IdentitySession;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt as _;

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
    // `f_type` is signed on glibc and unsigned on musl; the magic fits both.
    #[allow(clippy::unnecessary_cast)]
    let magic = unsafe { stat.assume_init().f_type } as u64 & 0xffff_ffff;
    assert_eq!(magic, 0x9123_683e, "actual fixture TMPDIR must be Btrfs");
    create_subvolume(parent, "a");
    create_subvolume(parent, "b");
    let a_path = parent.join("a/libcollision.so");
    let b_path = parent.join("b/libcollision.so");
    std::fs::write(&a_path, vec![0xa5u8; 8192]).unwrap();
    std::fs::copy(&a_path, &b_path).unwrap();
    let a_file = std::fs::File::open(&a_path).unwrap();
    let b_file = std::fs::File::open(&b_path).unwrap();
    let a = a_file.metadata().unwrap();
    let b = b_file.metadata().unwrap();
    assert_eq!(
        std::fs::read(&a_path).unwrap(),
        std::fs::read(&b_path).unwrap()
    );
    assert_eq!(
        a.ino(),
        b.ino(),
        "fresh subvolume files share the inode number"
    );
    assert_ne!(
        (a.dev(), a.ino()),
        (b.dev(), b.ino()),
        "full physical IDs must differ"
    );

    let caller = SwapChild::spawn_with(&[(&a_path, true), (&b_path, false)]);
    let wrong = SwapChild::spawn_with(&[(&b_path, true), (&a_path, false)]);
    let reader = SwapChild::spawn_with(&[(&a_path, false)]);
    let snapshots = [caller.maps(), wrong.maps(), reader.maps()];
    fn line_at(snapshot: &[MapEntry], address: u64) -> &MapEntry {
        snapshot
            .iter()
            .find(|entry| entry.start == address)
            .expect("independent live mapping")
    }
    let a_text = line_at(&snapshots[0], caller.addresses[0]);
    let b_data = line_at(&snapshots[0], caller.addresses[1]);
    let b_text = line_at(&snapshots[1], wrong.addresses[0]);
    let a_data = line_at(&snapshots[1], wrong.addresses[1]);
    let reader_data = line_at(&snapshots[2], reader.address);
    assert_eq!(a_text.permissions, *b"r-xp");
    assert_eq!(b_text.permissions, *b"r-xp");
    for data in [b_data, a_data, reader_data] {
        assert_eq!(data.permissions, *b"r--p");
    }
    let key = ObjectKey::of(a_text);
    for entry in [b_data, b_text, a_data, reader_data] {
        assert_eq!(
            ObjectKey::of(entry),
            key,
            "actual lexical collision, not scripted keys"
        );
    }
    let digest = p11scope_manifest::identity::hex(&Sha256::digest(std::fs::read(&a_path).unwrap()));
    let pins: PinnedObjects = real_scan_pin(&a_path, Some(key), 0, &digest);
    let object = pins.pinned().next().expect("actual held-file pin").id;
    let (userspace_index, refused) = KnownKeyIndex::build(
        [(key, Some(object))],
        &BTreeMap::from([(key, object)]),
        [],
        &pins,
    );
    assert!(refused.is_empty(), "{refused:?}");
    assert!(userspace_index.map_files_keys().contains(&key));
    let probe_dir = tempfile::tempdir().unwrap();
    let mut session = IdentitySession::probe_and_load(&btf, probe_dir.path())
        .expect("actual strict-loaded kernel session; no refused/fallback positive");
    for (position, child) in [&caller, &wrong, &reader].into_iter().enumerate() {
        let userspace = attribute_child(child, snapshots[position].clone(), &userspace_index);
        let kernel = d4_kernel_collision_attribution(
            child,
            snapshots[position].clone(),
            &pins,
            object,
            key,
            &mut session,
            position as u64 + 1,
        );
        assert_eq!(
            userspace.members, kernel.members,
            "exact same-population backend members"
        );
        assert_eq!(
            userspace.losses, kernel.losses,
            "same actual loss classifications"
        );
        for (backend, out) in [("userspace", userspace), ("kernel", kernel)] {
            let members: Vec<_> = out.members.iter().map(|member| member.pid).collect();
            match position {
                0 => {
                    assert_eq!(
                        members,
                        [caller.pid as u32],
                        "{backend} exact healthy caller"
                    );
                    assert_eq!(
                        out.members[0]
                            .objects
                            .iter()
                            .map(|matched| (matched.key, matched.object))
                            .collect::<Vec<_>>(),
                        [(key, object)],
                        "{backend} exact held original-provider edge"
                    );
                    assert!(out.losses.is_empty(), "{backend}: {:?}", out.member_losses);
                    assert_eq!(out.probed, 1, "{backend} nonempty executable proof demand");
                }
                1 => {
                    assert!(
                        members.is_empty(),
                        "{backend} attributed the distinct equal-byte file"
                    );
                    assert_eq!(
                        out.losses,
                        BTreeMap::from([(AttributionLoss::IdentityMismatch, 1)])
                    );
                    assert_eq!(out.probed, 1, "{backend} real negative proof demand");
                }
                2 => {
                    assert!(
                        members.is_empty(),
                        "{backend} attributed a data-only mapping"
                    );
                    assert!(out.losses.is_empty(), "{backend}: {:?}", out.member_losses);
                    assert_eq!(
                        out.probed, 0,
                        "{backend} data-only input costs no executable proof"
                    );
                }
                _ => unreachable!(),
            }
        }
    }
    eprintln!(
        "D4_BTRFS_COLLISION callers={}/{}/{} userspace=1/0/0 kernel=1/0/0 \
         equal_bytes=true lexical_collision=true fallback=none",
        caller.pid, wrong.pid, reader.pid
    );
    drop((caller, wrong, reader));
    drop((session, pins, a_file, b_file));
    std::fs::remove_file(&a_path).unwrap();
    std::fs::remove_file(&b_path).unwrap();
    std::fs::remove_dir(parent.join("a")).unwrap();
    std::fs::remove_dir(parent.join("b")).unwrap();
}

/// One child remaps an equal-byte, physically different Btrfs file at the
/// same address and path, leaving its full maps bytes unchanged. Both actual
/// backends must discard the old provider's edge and accept a fresh pin of
/// the current provider. Each kernel leg installs a fresh real generation
/// and validated slots; no fallback or userspace range proof may qualify.
/// This is scan identity parity, not native calls or whole-row D4 readiness.
#[test]
#[ignore = "root Btrfs disk TMPDIR plus eligible BTF/task_vma identity; actual same-line remap parity"]
fn privileged_d4_btrfs_same_line_remap_backend_parity() {
    use crate::discovery::identity::{
        PinnedObjects, map_files_identity, test_fixture::real_scan_pin,
    };
    use crate::discovery::kernel_identity::IdentitySession;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::{FileExt as _, MetadataExt as _};

    fn file_identity(file: &std::fs::File) -> FileIdentity {
        let metadata = file.metadata().unwrap();
        FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }

    fn assert_pair(
        phase: &str,
        child: &SwapChild,
        expected: Option<(ObjectKey, PinnedObjectId)>,
        userspace: SweepAttribution,
        kernel: SweepAttribution,
    ) {
        for (backend, out) in [("userspace", &userspace), ("kernel", &kernel)] {
            assert_eq!(out.probed, 1, "{phase} {backend}: actual executable demand");
            if let Some(edge) = expected {
                assert_eq!(
                    out.members
                        .iter()
                        .map(|member| member.pid)
                        .collect::<Vec<_>>(),
                    [child.pid as u32],
                    "{phase} {backend}: {:?}",
                    out.member_losses
                );
                assert_eq!(
                    out.members[0]
                        .objects
                        .iter()
                        .map(|matched| (matched.key, matched.object))
                        .collect::<Vec<_>>(),
                    [edge],
                    "{phase} {backend}: exact held-provider edge"
                );
                assert!(
                    out.losses.is_empty(),
                    "{phase} {backend}: {:?}",
                    out.member_losses
                );
            } else {
                assert!(
                    out.members.is_empty(),
                    "{phase} {backend}: {:?}",
                    out.members
                );
                assert_eq!(
                    out.losses,
                    BTreeMap::from([(AttributionLoss::IdentityMismatch, 1)]),
                    "{phase} {backend}: {:?}",
                    out.member_losses
                );
            }
        }
        assert_eq!(
            userspace.members, kernel.members,
            "{phase}: exact backend members"
        );
        assert_eq!(
            userspace.losses, kernel.losses,
            "{phase}: actual loss classifications"
        );
    }

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
    // `f_type` is signed on glibc and unsigned on musl; the magic fits both.
    #[allow(clippy::unnecessary_cast)]
    let magic = unsafe { stat.assume_init().f_type } as u64 & 0xffff_ffff;
    assert_eq!(magic, 0x9123_683e, "actual fixture TMPDIR must be Btrfs");
    create_subvolume(parent, "a");
    create_subvolume(parent, "b");
    let path = parent.join("a/libswap.so");
    let replacement_path = parent.join("b/libswap.so");
    let bytes = vec![0xa5u8; 8192];
    std::fs::write(&path, &bytes).unwrap();
    std::fs::copy(&path, &replacement_path).unwrap();
    let a_file = std::fs::File::open(&path).unwrap();
    let b_file = std::fs::File::open(&replacement_path).unwrap();
    let a_identity = file_identity(&a_file);
    let b_identity = file_identity(&b_file);
    assert_eq!(
        a_identity.ino, b_identity.ino,
        "fresh subvolumes repeat inode numbers"
    );
    assert_ne!(
        a_identity, b_identity,
        "the held physical files must differ"
    );
    for file in [&a_file, &b_file] {
        let mut held_bytes = vec![0; bytes.len()];
        file.read_exact_at(&mut held_bytes, 0).unwrap();
        assert_eq!(
            held_bytes, bytes,
            "equal bytes verified through each held FD"
        );
    }

    let child = SwapChild::spawn(&path);
    let range = (child.address, child.address + 4096);
    let maps_path = format!("/proc/{}/maps", child.pid);
    let before_bytes = std::fs::read(&maps_path).unwrap();
    let before = child.maps();
    let line = before
        .iter()
        .find(|entry| (entry.start, entry.end) == range)
        .expect("the child's actual executable mapping");
    assert_eq!(line.permissions, *b"r-xp");
    let key = ObjectKey::of(line);
    // Independent fixture truth, outside the required kernel leg: these
    // identities come from file metadata, never the lexical maps device.
    let before_identity = map_files_identity(child.pid as u32, range.0, range.1).unwrap();
    assert_eq!(before_identity, a_identity);
    let digest = p11scope_manifest::identity::hex(&Sha256::digest(&bytes));
    let a_pins: PinnedObjects = real_scan_pin(&path, Some(key), 0, &digest);
    let a_object = a_pins.pinned().next().expect("actual old-provider pin").id;
    assert_eq!(
        file_identity(a_pins.file_for(a_object).unwrap()),
        a_identity
    );
    let (a_index, refused) = KnownKeyIndex::build(
        [(key, Some(a_object))],
        &BTreeMap::from([(key, a_object)]),
        [],
        &a_pins,
    );
    assert!(refused.is_empty(), "{refused:?}");
    assert!(a_index.map_files_keys().contains(&key));
    let probe_dir = tempfile::tempdir().unwrap();
    let mut session = IdentitySession::probe_and_load(&btf, probe_dir.path())
        .expect("actual strict-loaded kernel session; no refused/fallback positive");
    assert_pair(
        "before: held A",
        &child,
        Some((key, a_object)),
        attribute_child(&child, before.clone(), &a_index),
        d4_kernel_collision_attribution(
            &child,
            before.clone(),
            &a_pins,
            a_object,
            key,
            &mut session,
            1,
        ),
    );

    std::fs::rename(parent.join("a"), parent.join("a.old")).unwrap();
    std::fs::rename(parent.join("b"), parent.join("a")).unwrap();
    child.remap();
    let after = child.maps();
    assert_eq!(
        std::fs::read(&maps_path).unwrap(),
        before_bytes,
        "full maps bytes stay identical"
    );
    assert_eq!(
        after, before,
        "same ranges, offsets, permissions, keys and paths"
    );
    let after_identity = map_files_identity(child.pid as u32, range.0, range.1).unwrap();
    assert_eq!(after_identity, b_identity, "the live mapping now holds B");
    assert_ne!(
        after_identity, before_identity,
        "the physical file actually changed"
    );
    assert_pair(
        "after: held A must mismatch",
        &child,
        None,
        attribute_child(&child, after.clone(), &a_index),
        d4_kernel_collision_attribution(
            &child,
            after.clone(),
            &a_pins,
            a_object,
            key,
            &mut session,
            2,
        ),
    );

    let b_pins: PinnedObjects = real_scan_pin(&path, Some(key), 0, &digest);
    let b_object = b_pins
        .pinned()
        .next()
        .expect("actual current-provider pin")
        .id;
    assert_eq!(
        file_identity(b_pins.file_for(b_object).unwrap()),
        b_identity
    );
    let (b_index, refused) = KnownKeyIndex::build(
        [(key, Some(b_object))],
        &BTreeMap::from([(key, b_object)]),
        [],
        &b_pins,
    );
    assert!(refused.is_empty(), "{refused:?}");
    assert!(b_index.map_files_keys().contains(&key));
    assert_pair(
        "after: fresh held B",
        &child,
        Some((key, b_object)),
        attribute_child(&child, after.clone(), &b_index),
        d4_kernel_collision_attribution(&child, after, &b_pins, b_object, key, &mut session, 3),
    );
    for (file, expected) in [(&a_file, a_identity), (&b_file, b_identity)] {
        assert_eq!(
            file_identity(file),
            expected,
            "held physical files remain unchanged"
        );
        assert_eq!(file.metadata().unwrap().len(), bytes.len() as u64);
        let mut held_bytes = vec![0; bytes.len()];
        file.read_exact_at(&mut held_bytes, 0).unwrap();
        assert_eq!(held_bytes, bytes);
    }
    eprintln!(
        "D4_BTRFS_SAME_LINE caller={} userspace=1/0/1 kernel=1/0/1 \
         equal_bytes=true identical_maps=true changed_file=true generations=1/2/3 fallback=none",
        child.pid
    );
    drop(child);
    drop((session, a_pins, b_pins, a_file, b_file));
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(parent.join("a.old/libswap.so")).unwrap();
    std::fs::remove_dir(parent.join("a")).unwrap();
    std::fs::remove_dir(parent.join("a.old")).unwrap();
}

/// A real executable mapping survives unlink with the held file's identity
/// and bytes intact. Both actual backends first prove its edge, then the
/// production deleted-path filter must name DeletedMapping without another
/// confirmation or executable proof. Keep the validated pre-unlink anchor
/// pass alive: unlink may change ctime, so this does not invent a current pin
/// or bypass an unchanged-file guard. Whole D4 rows remain separate gates.
#[test]
#[ignore = "root Btrfs disk TMPDIR plus eligible BTF/task_vma identity; actual deleted-mapping parity"]
fn privileged_d4_btrfs_deleted_mapping_backend_parity() {
    use crate::discovery::identity::{PinnedObjects, test_fixture::real_scan_pin};
    use crate::discovery::kernel_identity::{
        AnchorPass, ExaminedCustody, IdentitySession, KernelMemberProbe,
    };
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::{FileExt as _, MetadataExt as _};
    use std::sync::{Arc, Mutex};

    // The production OsMemberProbe's delegation, retaining an observable
    // actual OsConfirmIo so zero post-unlink proof reads are checkable.
    struct UserspaceProbe<'p>(OsConfirmIo<'p>);

    impl MemberProbe for UserspaceProbe<'_> {
        fn confirm(
            &mut self,
            pid: u32,
            prove: &BTreeSet<ObjectKey>,
            budget: &mut CaptureWorkBudget,
        ) -> Confirmation {
            confirm_with(&mut self.0, pid, prove, budget)
        }

        fn stat_ranges(
            &mut self,
            pid: u32,
            ranges: &[(u64, u64)],
            budget: &mut CaptureWorkBudget,
        ) -> MappedIdentities {
            stat_unpinned(&mut self.0, pid, ranges, budget)
        }
    }

    fn attribute(
        child: &SwapChild,
        snapshot: Vec<MapEntry>,
        index: &KnownKeyIndex,
        probe: &mut dyn MemberProbe,
    ) -> (SweepAttribution, u64) {
        let mut budget = CaptureWorkBudget::default();
        assert!(
            !budget.has_collection_work(),
            "actual kernel path, no scoped fallback"
        );
        let out = attribute_unselected(
            &[(child.pid as u32, snapshot)],
            &BTreeSet::new(),
            &BTreeSet::new(),
            index,
            probe,
            &mut budget,
        );
        (out, budget.work_units_count())
    }

    crate::attach::identity_iter::ensure_kernel_identity_btf()
        .expect("required kernel identity capability; refusal cannot qualify");
    let btf = aya::Btf::from_sys_fs().expect("readable host BTF");
    let dir = tempfile::tempdir().unwrap();
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let c_parent = std::ffi::CString::new(dir.path().as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid path and writable statfs buffer, read only on success.
    assert_eq!(
        unsafe { libc::statfs(c_parent.as_ptr(), stat.as_mut_ptr()) },
        0
    );
    // SAFETY: initialized by the successful statfs above.
    // `f_type` is signed on glibc and unsigned on musl; the magic fits both.
    #[allow(clippy::unnecessary_cast)]
    let magic = unsafe { stat.assume_init().f_type } as u64 & 0xffff_ffff;
    assert_eq!(magic, 0x9123_683e, "actual fixture TMPDIR must be Btrfs");
    let path = dir.path().join("libdeleted.so");
    let bytes = vec![0x5au8; 8192];
    std::fs::write(&path, &bytes).unwrap();
    let held_file = std::fs::File::open(&path).unwrap();
    let held = held_file.metadata().unwrap();
    let physical_id = (held.dev(), held.ino());
    let mut held_bytes = vec![0; bytes.len()];
    held_file.read_exact_at(&mut held_bytes, 0).unwrap();
    assert_eq!(held_bytes, bytes);

    let child = SwapChild::spawn(&path);
    let range = (child.address, child.address + 4096);
    let before = child.maps();
    let position = before
        .iter()
        .position(|entry| (entry.start, entry.end) == range)
        .expect("the child's actual executable mapping");
    assert_eq!(before[position].permissions, *b"r-xp");
    let key = ObjectKey::of(&before[position]);
    let digest = p11scope_manifest::identity::hex(&Sha256::digest(&bytes));
    let pins: PinnedObjects = real_scan_pin(&path, Some(key), 0, &digest);
    let object = pins
        .pinned()
        .next()
        .expect("actual pre-unlink held-file pin")
        .id;
    let pinned = pins.file_for(object).unwrap().metadata().unwrap();
    assert_eq!((pinned.dev(), pinned.ino()), physical_id);
    let (userspace_index, refused) = KnownKeyIndex::build(
        [(key, Some(object))],
        &BTreeMap::from([(key, object)]),
        [],
        &pins,
    );
    assert!(refused.is_empty(), "{refused:?}");
    assert!(userspace_index.map_files_keys().contains(&key));
    let mut kernel_index = userspace_index.clone();
    let probe_dir = tempfile::tempdir().unwrap();
    let mut session = IdentitySession::probe_and_load(&btf, probe_dir.path())
        .expect("actual strict-loaded kernel session; no refused/fallback positive");
    let owner = ReservationOwner::for_examined(
        SegmentPolicy::try_snapshot(0, 0).expect("actual FD census"),
        0,
    );
    let mut custody = ExaminedCustody::new(owner, BTreeMap::new());
    custody
        .reconcile(SegmentPolicy::try_snapshot(1, 1).expect("actual confirmation FD census"))
        .expect("shared physical reservation owner");
    let pass = AnchorPass::prepare(&pins, [(key, object)], custody);
    assert!(pass.fallback.is_empty(), "{:?}", pass.fallback);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut installed = session
        .install_anchors(pass, 1, deadline)
        .expect("install actual pre-unlink held-file anchors");
    let userspace_trace = Arc::new(Mutex::new(ProofTrace::default()));
    let kernel_trace = Arc::new(Mutex::new(ProofTrace::default()));
    let mut userspace_probe =
        UserspaceProbe(OsConfirmIo::with_pool(None).observing(userspace_trace.clone()));
    let mut kernel_probe = KernelMemberProbe::new(
        &mut installed,
        OsConfirmIo::with_pool(None).observing(kernel_trace.clone()),
        deadline,
    );
    kernel_probe
        .install_expectations(&mut kernel_index)
        .expect("actual validated pre-unlink anchor expectations");
    assert!(
        kernel_index
            .match_slots
            .get(&key)
            .is_some_and(|slots| !slots.is_empty()),
        "the held provider has no validated actual kernel slot"
    );
    let (userspace_before, _) = attribute(
        &child,
        before.clone(),
        &userspace_index,
        &mut userspace_probe,
    );
    let (kernel_before, _) = attribute(&child, before.clone(), &kernel_index, &mut kernel_probe);
    for (backend, out) in [("userspace", &userspace_before), ("kernel", &kernel_before)] {
        assert_eq!(
            out.members
                .iter()
                .map(|member| member.pid)
                .collect::<Vec<_>>(),
            [child.pid as u32],
            "{backend}: {:?}",
            out.member_losses
        );
        assert_eq!(
            out.members[0]
                .objects
                .iter()
                .map(|matched| (matched.key, matched.object))
                .collect::<Vec<_>>(),
            [(key, object)],
            "{backend}: exact pre-unlink provider edge"
        );
        assert!(out.losses.is_empty(), "{backend}: {:?}", out.member_losses);
        assert_eq!(
            out.probed, 1,
            "{backend}: nonempty pre-unlink executable demand"
        );
    }
    assert_eq!(userspace_before.members, kernel_before.members);
    {
        let mut trace = userspace_trace.lock().unwrap();
        assert_eq!(
            trace.reads.len(),
            1,
            "positive twin observes an actual userspace proof read"
        );
        let (pid, start, end, _, _) = &trace.reads[0];
        assert_eq!((*pid, *start, *end), (child.pid as u32, range.0, range.1));
        trace.reads.clear();
    }
    assert!(
        kernel_trace.lock().unwrap().reads.is_empty(),
        "required kernel positive used userspace proof reads"
    );

    // Preserve the same live VMA and validated installation across unlink;
    // only the production path-eligibility fact changes for this observation.
    std::fs::remove_file(&path).unwrap();
    assert!(!path.exists(), "the owned pathname really was unlinked");
    let after = child.maps();
    let mut expected = before;
    expected[position]
        .raw_path
        .as_mut()
        .expect("the mapped pathname")
        .extend_from_slice(b" (deleted)");
    assert_eq!(
        after, expected,
        "same live mapping except the actual deleted-path flag"
    );
    assert!(
        is_caller_range(&after[position]),
        "the executable caller population is nonempty"
    );
    let held_after = held_file.metadata().unwrap();
    assert_eq!((held_after.dev(), held_after.ino()), physical_id);
    assert_eq!(
        held_after.nlink(),
        0,
        "the live held file has no remaining pathname"
    );
    assert_eq!(held_after.len(), bytes.len() as u64);
    held_file.read_exact_at(&mut held_bytes, 0).unwrap();
    assert_eq!(
        held_bytes, bytes,
        "unlink preserved the independently held file's bytes"
    );

    let (userspace_after, userspace_work) = attribute(
        &child,
        after.clone(),
        &userspace_index,
        &mut userspace_probe,
    );
    let (kernel_after, kernel_work) = attribute(&child, after, &kernel_index, &mut kernel_probe);
    for (backend, out, work) in [
        ("userspace", &userspace_after, userspace_work),
        ("kernel", &kernel_after, kernel_work),
    ] {
        assert!(out.members.is_empty(), "{backend}: {:?}", out.members);
        assert_eq!(
            out.losses,
            BTreeMap::from([(AttributionLoss::DeletedMapping, 1)]),
            "{backend}: {:?}",
            out.member_losses
        );
        assert_eq!(
            out.member_losses
                .get(&(child.pid as u32))
                .map(|(loss, _)| *loss),
            Some(AttributionLoss::DeletedMapping)
        );
        assert_eq!(
            out.probed, 0,
            "{backend}: deleted mapping needs no confirmation"
        );
        assert_eq!(
            work, 0,
            "{backend}: deleted mapping needs no executable proof work"
        );
        assert_eq!(out.unavailable, 0);
        assert!(
            out.exited.is_empty(),
            "{backend}: the mapped child is still alive"
        );
    }
    assert_eq!(userspace_after.losses, kernel_after.losses);
    assert!(
        userspace_trace.lock().unwrap().reads.is_empty(),
        "deleted userspace leg read a map_files proof"
    );
    assert!(
        kernel_trace.lock().unwrap().reads.is_empty(),
        "deleted kernel leg read a userspace proof"
    );
    drop((userspace_probe, kernel_probe));
    drop(installed);
    let fallback = session.fallback_totals();
    assert_eq!(fallback.passes, 0, "{fallback:?}");
    assert_eq!(fallback.pids, 0, "{fallback:?}");
    assert_eq!(fallback.keys, 0, "{fallback:?}");
    assert!(fallback.first_reason.is_none(), "{fallback:?}");
    eprintln!(
        "D4_BTRFS_DELETED caller={} userspace=1/0 kernel=1/0 deleted_mapping=1/1 \
         after_probed=0/0 after_proof_reads=0/0 held_file_stable=true generation=1 fallback=none",
        child.pid
    );
    drop(child);
    drop((session, pins, held_file));
    probe_dir
        .close()
        .expect("remove owned kernel probe directory");
    dir.close()
        .expect("remove owned unlinked-file fixture directory");
}

/// A hardlink's executable mapping attributes to a pin opened through the
/// original name, using both actual backends over the same live population.
/// An equal-byte copy has its own unexamined key, and an alias mapped only
/// as data has no executable proof demand. Create all names before pinning
/// so the hardlink's ctime change is not confused with identity rejection.
/// This qualifies alias attribution only; whole D4 rows remain separate.
#[test]
#[ignore = "root Btrfs disk TMPDIR plus eligible BTF/task_vma identity; actual hardlink alias parity"]
fn privileged_d4_btrfs_hardlink_alias_backend_parity() {
    use crate::discovery::identity::{PinnedObjects, test_fixture::real_scan_pin};
    use crate::discovery::kernel_identity::IdentitySession;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::{FileExt as _, MetadataExt as _};

    crate::attach::identity_iter::ensure_kernel_identity_btf()
        .expect("required kernel identity capability; refusal cannot qualify");
    let btf = aya::Btf::from_sys_fs().expect("readable host BTF");
    let dir = tempfile::tempdir().unwrap();
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let c_parent = std::ffi::CString::new(dir.path().as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid path and writable statfs buffer, read only on success.
    assert_eq!(
        unsafe { libc::statfs(c_parent.as_ptr(), stat.as_mut_ptr()) },
        0
    );
    // SAFETY: initialized by the successful statfs above.
    // `f_type` is signed on glibc and unsigned on musl; the magic fits both.
    #[allow(clippy::unnecessary_cast)]
    let magic = unsafe { stat.assume_init().f_type } as u64 & 0xffff_ffff;
    assert_eq!(magic, 0x9123_683e, "actual fixture TMPDIR must be Btrfs");
    let original_path = dir.path().join("liboriginal.so");
    let alias_path = dir.path().join("libalias.so");
    let copy_path = dir.path().join("libcopy.so");
    let bytes = vec![0xa5u8; 8192];
    std::fs::write(&original_path, &bytes).unwrap();
    std::fs::hard_link(&original_path, &alias_path).unwrap();
    std::fs::copy(&original_path, &copy_path).unwrap();
    let original_file = std::fs::File::open(&original_path).unwrap();
    let alias_file = std::fs::File::open(&alias_path).unwrap();
    let copy_file = std::fs::File::open(&copy_path).unwrap();
    let original = original_file.metadata().unwrap();
    let alias = alias_file.metadata().unwrap();
    let copy = copy_file.metadata().unwrap();
    let original_id = (original.dev(), original.ino());
    let alias_id = (alias.dev(), alias.ino());
    let copy_id = (copy.dev(), copy.ino());
    assert_eq!(alias_id, original_id, "actual hardlink physical identity");
    assert_eq!(original.nlink(), 2);
    assert_eq!(alias.nlink(), 2);
    assert_ne!(
        copy_id, original_id,
        "the equal-byte copy is a different held file"
    );
    for file in [&original_file, &alias_file, &copy_file] {
        let mut held_bytes = vec![0; bytes.len()];
        file.read_exact_at(&mut held_bytes, 0).unwrap();
        assert_eq!(held_bytes, bytes, "contents checked through each held FD");
    }

    let caller = SwapChild::spawn(&alias_path);
    let copied = SwapChild::spawn(&copy_path);
    let reader = SwapChild::spawn_with(&[(&alias_path, false)]);
    let snapshots = [caller.maps(), copied.maps(), reader.maps()];
    let line_at = |position: usize, child: &SwapChild| {
        snapshots[position]
            .iter()
            .find(|entry| (entry.start, entry.end) == (child.address, child.address + 4096))
            .expect("independent actual mapping")
    };
    let alias_text = line_at(0, &caller);
    let copy_text = line_at(1, &copied);
    let alias_data = line_at(2, &reader);
    assert_eq!(alias_text.permissions, *b"r-xp");
    assert_eq!(copy_text.permissions, *b"r-xp");
    assert_eq!(alias_data.permissions, *b"r--p");
    for entry in [alias_text, alias_data] {
        assert_eq!(
            entry.raw_path.as_deref(),
            Some(alias_path.as_os_str().as_encoded_bytes())
        );
    }
    assert_eq!(
        copy_text.raw_path.as_deref(),
        Some(copy_path.as_os_str().as_encoded_bytes())
    );
    let key = ObjectKey::of(alias_text);
    let copy_key = ObjectKey::of(copy_text);
    assert_eq!(ObjectKey::of(alias_data), key);
    assert_ne!(
        copy_key, key,
        "the actual copy has its own lexical maps key"
    );
    let digest = p11scope_manifest::identity::hex(&Sha256::digest(&bytes));
    let pins: PinnedObjects = real_scan_pin(&original_path, Some(key), 0, &digest);
    let pin = pins
        .pinned()
        .next()
        .expect("actual pin opened through the original name");
    let object = pin.id;
    assert_eq!(pin.path, original_path.to_str().unwrap());
    let pinned = pins.file_for(object).unwrap().metadata().unwrap();
    assert_eq!((pinned.dev(), pinned.ino()), original_id);
    let (userspace_index, refused) = KnownKeyIndex::build(
        [(key, Some(object))],
        &BTreeMap::from([(key, object)]),
        [],
        &pins,
    );
    assert!(refused.is_empty(), "{refused:?}");
    let proof_keys = userspace_index.map_files_keys();
    assert!(proof_keys.contains(&key));
    assert_eq!(userspace_index.classify(copy_key), KeyClass::Unexamined);
    assert_eq!(
        proof_ranges(&snapshots[0], &proof_keys),
        [(caller.address, caller.address + 4096)]
    );
    for snapshot in &snapshots[1..] {
        assert!(
            proof_ranges(snapshot, &proof_keys).is_empty(),
            "copy and data-only mappings have no provider proof demand"
        );
    }
    let probe_dir = tempfile::tempdir().unwrap();
    let mut session = IdentitySession::probe_and_load(&btf, probe_dir.path())
        .expect("actual strict-loaded kernel session; no refused/fallback positive");
    for (position, child) in [&caller, &copied, &reader].into_iter().enumerate() {
        let userspace = attribute_child(child, snapshots[position].clone(), &userspace_index);
        let kernel = d4_kernel_collision_attribution(
            child,
            snapshots[position].clone(),
            &pins,
            object,
            key,
            &mut session,
            position as u64 + 1,
        );
        for (backend, out) in [("userspace", &userspace), ("kernel", &kernel)] {
            assert!(out.losses.is_empty(), "{backend}: {:?}", out.member_losses);
            assert_eq!(out.unavailable, 0);
            assert!(out.exited.is_empty(), "{backend}: an owned child exited");
            if position == 0 {
                assert_eq!(
                    out.members
                        .iter()
                        .map(|member| member.pid)
                        .collect::<Vec<_>>(),
                    [caller.pid as u32],
                    "{backend}: exact alias caller"
                );
                assert_eq!(
                    out.members[0]
                        .objects
                        .iter()
                        .map(|matched| (matched.key, matched.object, matched.path.as_str()))
                        .collect::<Vec<_>>(),
                    [(key, object, alias_path.to_str().unwrap())],
                    "{backend}: the original pin is reached through the real alias path"
                );
                assert_eq!(
                    out.probed, 1,
                    "{backend}: nonempty alias executable proof demand"
                );
            } else {
                assert!(out.members.is_empty(), "{backend}: {:?}", out.members);
                assert_eq!(
                    out.probed, 0,
                    "{backend}: no executable proof for a copy's unknown key or a data-only alias"
                );
                if position == 1 {
                    assert!(
                        out.unexamined_objects.contains(&copy_key),
                        "{backend}: the copy remains honestly unexamined"
                    );
                    assert!(
                        out.unexamined
                            .get(&(copied.pid as u32))
                            .is_some_and(|count| *count > 0)
                    );
                } else {
                    assert!(
                        !out.unexamined_objects.contains(&key),
                        "{backend}: data-only alias is not an unexamined caller"
                    );
                }
            }
        }
        assert_eq!(
            userspace.members, kernel.members,
            "exact independently checked backend members"
        );
        assert_eq!(userspace.losses, kernel.losses);
        assert_eq!(userspace.unexamined_objects, kernel.unexamined_objects);
        assert_eq!(userspace.unexamined, kernel.unexamined);
    }
    assert!(
        pins.object_unchanged(object)
            .expect("recheck the actual pin"),
        "all hardlinks were created before pinning"
    );
    for (file, expected) in [
        (&original_file, original_id),
        (&alias_file, alias_id),
        (&copy_file, copy_id),
    ] {
        let metadata = file.metadata().unwrap();
        assert_eq!((metadata.dev(), metadata.ino()), expected);
        assert_eq!(metadata.len(), bytes.len() as u64);
        let mut held_bytes = vec![0; bytes.len()];
        file.read_exact_at(&mut held_bytes, 0).unwrap();
        assert_eq!(held_bytes, bytes, "held physical files remain unchanged");
    }
    eprintln!(
        "D4_BTRFS_HARDLINK callers={}/{}/{} userspace=1/0/0 kernel=1/0/0 \
         same_file_alias=true equal_bytes_copy=true copy=unexamined generations=1/2/3 fallback=none",
        caller.pid, copied.pid, reader.pid
    );
    drop((caller, copied, reader));
    drop((session, pins, original_file, alias_file, copy_file));
    probe_dir
        .close()
        .expect("remove owned kernel probe directory");
    dir.close()
        .expect("remove owned hardlink fixture directory and files");
}

/// The same alias pathname names A in child-private bind namespaces and an
/// equal-byte, physically different B in the observer's namespace. Actual
/// attribution must follow the live mapping and held A pin on both backends;
/// opening that pathname in the observer would reach the wrong file.
/// This is one bind substrate control, not whole-row D4 qualification.
#[test]
#[ignore = "root Btrfs disk TMPDIR, private mount namespaces and eligible BTF/task_vma identity; actual bind alias parity"]
fn privileged_d4_btrfs_bind_alias_backend_parity() {
    use crate::discovery::identity::{
        PinnedObjects, map_files_identity, test_fixture::real_scan_pin,
    };
    use crate::discovery::kernel_identity::IdentitySession;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::{FileExt as _, MetadataExt as _};

    let namespace_id = |pid: u32| {
        let metadata = std::fs::metadata(format!("/proc/{pid}/ns/mnt")).unwrap();
        (metadata.dev(), metadata.ino())
    };
    crate::attach::identity_iter::ensure_kernel_identity_btf()
        .expect("required kernel identity capability; refusal cannot qualify");
    let btf = aya::Btf::from_sys_fs().expect("readable host BTF");
    let dir = tempfile::tempdir().unwrap();
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let c_parent = std::ffi::CString::new(dir.path().as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid path and writable statfs buffer, read only on success.
    assert_eq!(
        unsafe { libc::statfs(c_parent.as_ptr(), stat.as_mut_ptr()) },
        0
    );
    // SAFETY: initialized by successful statfs above.
    // `f_type` is signed on glibc and unsigned on musl; the magic fits both.
    #[allow(clippy::unnecessary_cast)]
    let magic = unsafe { stat.assume_init().f_type } as u64 & 0xffff_ffff;
    assert_eq!(magic, 0x9123_683e, "actual fixture TMPDIR must be Btrfs");
    let original_path = dir.path().join("liboriginal.so");
    let alias_path = dir.path().join("libalias.so");
    let bytes = vec![0x5au8; 8192];
    std::fs::write(&original_path, &bytes).unwrap();
    std::fs::copy(&original_path, &alias_path).unwrap();
    let a_file = std::fs::File::open(&original_path).unwrap();
    let b_file = std::fs::File::open(&alias_path).unwrap();
    let a = a_file.metadata().unwrap();
    let b = b_file.metadata().unwrap();
    let a_identity = FileIdentity {
        dev: a.dev(),
        ino: a.ino(),
    };
    let b_identity = FileIdentity {
        dev: b.dev(),
        ino: b.ino(),
    };
    assert_ne!(
        a_identity, b_identity,
        "parent alias is an actual different physical file"
    );
    for file in [&a_file, &b_file] {
        let mut held_bytes = vec![0; bytes.len()];
        file.read_exact_at(&mut held_bytes, 0).unwrap();
        assert_eq!(
            held_bytes, bytes,
            "equal bytes independently read from held FDs"
        );
    }
    let parent_namespace = namespace_id(std::process::id());
    let parent_mounts = std::fs::read("/proc/self/mountinfo").unwrap();
    let parent_unchanged = || {
        assert_eq!(namespace_id(std::process::id()), parent_namespace);
        assert_eq!(
            std::fs::read("/proc/self/mountinfo").unwrap(),
            parent_mounts,
            "parent mount tree and propagation remain unchanged"
        );
        let current = std::fs::metadata(&alias_path).unwrap();
        assert_eq!(
            (current.dev(), current.ino()),
            (b_identity.dev, b_identity.ino),
            "the parent alias still opens B"
        );
    };
    let (caller, caller_identity) =
        SwapChild::spawn_private_bind(&original_path, &a_file, &alias_path, true)
            .expect("required private bind setup; namespace/mount refusal cannot qualify");
    parent_unchanged();
    let copied = SwapChild::spawn(&alias_path);
    let (reader, reader_identity) =
        SwapChild::spawn_private_bind(&original_path, &a_file, &alias_path, false)
            .expect("required data-only private bind setup; refusal cannot qualify");
    parent_unchanged();
    assert_eq!(caller_identity, a_identity, "mmap used an FD of held A");
    assert_eq!(
        reader_identity, a_identity,
        "data mapping used an FD of held A"
    );
    assert_ne!(namespace_id(caller.pid as u32), parent_namespace);
    assert_ne!(namespace_id(reader.pid as u32), parent_namespace);
    assert_ne!(
        namespace_id(caller.pid as u32),
        namespace_id(reader.pid as u32)
    );
    assert_eq!(namespace_id(copied.pid as u32), parent_namespace);
    for child in [&caller, &reader] {
        let mountinfo = std::fs::read_to_string(format!("/proc/{}/mountinfo", child.pid)).unwrap();
        d4_private_bind_mount(&mountinfo, &alias_path)
            .expect("actual private Btrfs alias mount in the child's namespace");
    }
    let snapshots = [caller.maps(), copied.maps(), reader.maps()];
    let line_at = |position: usize, child: &SwapChild| {
        snapshots[position]
            .iter()
            .find(|entry| (entry.start, entry.end) == (child.address, child.address + 4096))
            .expect("the actual live mapping")
    };
    let bound_text = line_at(0, &caller);
    let copy_text = line_at(1, &copied);
    let bound_data = line_at(2, &reader);
    assert_eq!(bound_text.permissions, *b"r-xp");
    assert_eq!(copy_text.permissions, *b"r-xp");
    assert_eq!(bound_data.permissions, *b"r--p");
    for entry in [bound_text, copy_text, bound_data] {
        assert_eq!(
            entry.raw_path.as_deref(),
            Some(alias_path.as_os_str().as_encoded_bytes()),
            "the same actual maps pathname denotes different files by namespace"
        );
    }
    // Independent fixture truth, outside the required kernel legs. File
    // metadata is never compared with the lexical maps device domain.
    for (child, expected) in [
        (&caller, a_identity),
        (&copied, b_identity),
        (&reader, a_identity),
    ] {
        assert_eq!(
            map_files_identity(child.pid as u32, child.address, child.address + 4096).unwrap(),
            expected
        );
    }
    let key = ObjectKey::of(bound_text);
    let copy_key = ObjectKey::of(copy_text);
    assert_eq!(ObjectKey::of(bound_data), key);
    assert_ne!(copy_key, key);
    let digest = p11scope_manifest::identity::hex(&Sha256::digest(&bytes));
    let pins: PinnedObjects = real_scan_pin(&original_path, Some(key), 0, &digest);
    let pin = pins.pinned().next().expect("actual original-file pin");
    let object = pin.id;
    assert_eq!(pin.path, original_path.to_str().unwrap());
    let pinned = pins.file_for(object).unwrap().metadata().unwrap();
    assert_eq!(
        (pinned.dev(), pinned.ino()),
        (a_identity.dev, a_identity.ino)
    );
    let (userspace_index, refused) = KnownKeyIndex::build(
        [(key, Some(object))],
        &BTreeMap::from([(key, object)]),
        [],
        &pins,
    );
    assert!(refused.is_empty(), "{refused:?}");
    assert_eq!(userspace_index.classify(copy_key), KeyClass::Unexamined);
    let proof_keys = userspace_index.map_files_keys();
    assert!(proof_keys.contains(&key));
    assert_eq!(
        proof_ranges(&snapshots[0], &proof_keys),
        [(caller.address, caller.address + 4096)]
    );
    for snapshot in &snapshots[1..] {
        assert!(proof_ranges(snapshot, &proof_keys).is_empty());
    }
    let probe_dir = tempfile::tempdir().unwrap();
    let mut session = IdentitySession::probe_and_load(&btf, probe_dir.path())
        .expect("actual strict-loaded kernel session; no refused/fallback positive");
    for (position, child) in [&caller, &copied, &reader].into_iter().enumerate() {
        let userspace = attribute_child(child, snapshots[position].clone(), &userspace_index);
        let kernel = d4_kernel_collision_attribution(
            child,
            snapshots[position].clone(),
            &pins,
            object,
            key,
            &mut session,
            position as u64 + 1,
        );
        for (backend, out) in [("userspace", &userspace), ("kernel", &kernel)] {
            assert!(out.losses.is_empty(), "{backend}: {:?}", out.member_losses);
            assert_eq!(out.unavailable, 0);
            assert!(out.exited.is_empty());
            if position == 0 {
                assert_eq!(
                    out.members
                        .iter()
                        .map(|member| member.pid)
                        .collect::<Vec<_>>(),
                    [caller.pid as u32]
                );
                assert_eq!(
                    out.members[0]
                        .objects
                        .iter()
                        .map(|matched| (matched.key, matched.object, matched.path.as_str()))
                        .collect::<Vec<_>>(),
                    [(key, object, alias_path.to_str().unwrap())],
                    "{backend}: bind alias attributes held A despite parent pathname B"
                );
                assert_eq!(
                    out.probed, 1,
                    "{backend}: actual executable positive demand"
                );
            } else {
                assert!(out.members.is_empty(), "{backend}: {:?}", out.members);
                assert_eq!(
                    out.probed, 0,
                    "{backend}: unknown copy/data-only alias needs no provider proof"
                );
                if position == 1 {
                    assert!(
                        out.unexamined_objects.contains(&copy_key),
                        "{backend}: the same-path parent copy remains unexamined"
                    );
                    assert!(
                        out.unexamined
                            .get(&(copied.pid as u32))
                            .is_some_and(|count| *count > 0)
                    );
                } else {
                    assert!(!out.unexamined_objects.contains(&key));
                }
            }
        }
        assert_eq!(userspace.members, kernel.members);
        assert_eq!(userspace.losses, kernel.losses);
        assert_eq!(userspace.unexamined_objects, kernel.unexamined_objects);
        assert_eq!(userspace.unexamined, kernel.unexamined);
        parent_unchanged();
    }
    assert!(
        pins.object_unchanged(object)
            .expect("actual pin remains unchanged")
    );
    for (file, expected) in [(&a_file, a_identity), (&b_file, b_identity)] {
        let metadata = file.metadata().unwrap();
        assert_eq!(
            (metadata.dev(), metadata.ino()),
            (expected.dev, expected.ino)
        );
        assert_eq!(metadata.len(), bytes.len() as u64);
        let mut held_bytes = vec![0; bytes.len()];
        file.read_exact_at(&mut held_bytes, 0).unwrap();
        assert_eq!(held_bytes, bytes);
    }
    eprintln!(
        "D4_BTRFS_BIND callers={}/{}/{} userspace=1/0/0 kernel=1/0/0 parent_alias=B child_alias=A private_namespaces=true parent_mounts_unchanged=true generations=1/2/3 fallback=none",
        caller.pid, copied.pid, reader.pid
    );
    // No retained namespace/root/map_files handles remain. Reaping the
    // children releases their private namespaces and bind mounts; the
    // parent never performs setns or an unmount.
    drop((session, pins));
    drop((caller, copied, reader));
    parent_unchanged();
    drop((a_file, b_file));
    probe_dir
        .close()
        .expect("remove owned kernel probe directory");
    dir.close()
        .expect("remove owned bind fixture files and directory");
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct D4ThreadReady {
    token: String,
    tgid: u32,
    tid: u32,
    fd: i32,
    start: u64,
    end: u64,
    dev: u64,
    ino: u64,
}

fn d4_validate_thread_ready(
    ready: &D4ThreadReady,
    pid: u32,
    token: &str,
) -> Result<(), &'static str> {
    if ready.token != token || ready.tgid != pid || pid == 0 {
        return Err("wrong helper process or token");
    }
    if ready.tid == 0 || ready.tid == pid {
        return Err("mapping did not come from a nonleader");
    }
    if ready.fd < 3
        || ready.start == 0
        || ready.start.checked_add(4096) != Some(ready.end)
        || ready.ino == 0
    {
        return Err("invalid opened-file mapping reply");
    }
    Ok(())
}

fn d4_write_thread_ready(
    stream: &mut std::os::unix::net::UnixStream,
    ready: &D4ThreadReady,
) -> std::io::Result<()> {
    use std::io::Write as _;
    let bytes = serde_json::to_vec(ready).map_err(std::io::Error::other)?;
    if bytes.is_empty() || bytes.len() > 1024 {
        return Err(std::io::Error::other("thread READY exceeds its bound"));
    }
    stream.write_all(&(bytes.len() as u32).to_ne_bytes())?;
    stream.write_all(&bytes)
}

fn d4_read_thread_ready(
    stream: &mut std::os::unix::net::UnixStream,
) -> std::io::Result<D4ThreadReady> {
    use std::io::Read as _;
    let mut size = [0; 4];
    stream.read_exact(&mut size)?;
    let size = u32::from_ne_bytes(size) as usize;
    if size == 0 || size > 1024 {
        return Err(std::io::Error::other("invalid thread READY length"));
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(std::io::Error::other)
}

fn d4_thread_fd_identity(path: &std::path::Path) -> std::io::Result<Option<FileIdentity>> {
    use std::os::unix::fs::MetadataExt as _;
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some(FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn d4_check_thread_file_table(
    private: bool,
    worker: FileIdentity,
    leader: Option<FileIdentity>,
) -> Result<(), &'static str> {
    if private == (leader == Some(worker)) {
        return Err("actual leader/worker FD evidence disagrees with the requested table state");
    }
    Ok(())
}

struct D4ThreadChild {
    child: std::process::Child,
    channel: std::os::unix::net::UnixStream,
    reaped: bool,
}

impl D4ThreadChild {
    fn spawn(path: &std::path::Path, private: bool, token: &str) -> (Self, D4ThreadReady) {
        use std::os::fd::OwnedFd;
        use std::process::{Command, Stdio};
        let (channel, helper) = std::os::unix::net::UnixStream::pair().unwrap();
        channel
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        channel
            .set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        helper
            .set_read_timeout(Some(std::time::Duration::from_secs(60)))
            .unwrap();
        helper
            .set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "discovery::sweep_attribution::tests::d4_thread_mapping_helper",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("P11SCOPE_D4_THREAD_PATH", path)
            .env(
                "P11SCOPE_D4_THREAD_MODE",
                if private { "private" } else { "shared" },
            )
            .env("P11SCOPE_D4_THREAD_TOKEN", token)
            .stdin(Stdio::from(OwnedFd::from(helper)))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("fresh exec of the matching libtest helper");
        // Own the process before any fallible READY I/O or validation.
        let mut owned = Self {
            child,
            channel,
            reaped: false,
        };
        let ready = d4_read_thread_ready(&mut owned.channel)
            .expect("required actual thread READY; helper refusal cannot qualify");
        d4_validate_thread_ready(&ready, owned.child.id(), token)
            .expect("owned helper and actual nonleader mapping");
        (owned, ready)
    }

    fn maps(&self) -> Vec<MapEntry> {
        crate::discovery::scan::read_maps_or_refuse(
            std::fs::File::open(format!("/proc/{}/maps", self.child.id())).unwrap(),
            &mut CaptureWorkBudget::default(),
            crate::attach::monotonic_ns,
        )
        .unwrap()
    }

    fn verify_worker(&self, ready: &D4ThreadReady, expected: FileIdentity, private: bool) -> u64 {
        let pid = self.child.id();
        assert_eq!(ready.tgid, pid);
        let start_time = crate::process::process_start_time(pid).expect("owned helper is alive");
        assert!(
            !crate::process::process_is_zombie(pid),
            "the leader must remain live"
        );
        for tid in [pid, ready.tid] {
            let status = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/status"))
                .expect("actual live leader and worker status");
            let field = |name: &str| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix(name))
                    .expect("actual task status identity field")
                    .trim()
                    .parse::<u32>()
                    .unwrap()
            };
            assert_eq!(field("Tgid:"), pid);
            assert_eq!(field("Pid:"), tid);
        }
        let worker = d4_thread_fd_identity(std::path::Path::new(&format!(
            "/proc/{pid}/task/{}/fd/{}",
            ready.tid, ready.fd
        )))
        .expect("inspect actual worker FD")
        .expect("worker must hold its opened file");
        assert_eq!(
            worker,
            FileIdentity {
                dev: ready.dev,
                ino: ready.ino
            }
        );
        assert_eq!(
            worker, expected,
            "worker FD must name the independently held file"
        );
        let leader = d4_thread_fd_identity(std::path::Path::new(&format!(
            "/proc/{pid}/fd/{}",
            ready.fd
        )))
        .expect("inspect leader same-number FD; only absence is acceptable refusal");
        d4_check_thread_file_table(private, worker, leader)
            .expect("independent leader/worker FD-table evidence");
        start_time
    }

    fn finish(mut self) {
        use std::io::Write as _;
        self.channel
            .write_all(b"Q")
            .expect("release the exact held worker");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.reaped = true;
                    assert!(status.success(), "thread helper failed: {status}");
                    return;
                }
                Ok(None) => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "thread helper did not exit after release"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => panic!("cannot reap the owned thread helper: {error}"),
            }
        }
    }
}

impl Drop for D4ThreadChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let _ = self.child.kill();
        loop {
            match self.child.wait() {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                _ => break,
            }
        }
    }
}

/// Private entrypoint, never a standalone qualification. Rust worker creation
/// happens only after exec; CLONE_FILES is unshared only in that owned worker.
#[test]
#[ignore = "private D4 thread fixture entrypoint; invoked only by its owning parity test with an owned socket/configuration"]
fn d4_thread_mapping_helper() {
    use std::io::Read as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::fs::MetadataExt as _;
    let path = std::env::var_os("P11SCOPE_D4_THREAD_PATH").expect("owned helper source path");
    let token = std::env::var("P11SCOPE_D4_THREAD_TOKEN").expect("owning fixture token");
    assert!(!token.is_empty());
    let private = match std::env::var("P11SCOPE_D4_THREAD_MODE").as_deref() {
        Ok("private") => true,
        Ok("shared") => false,
        _ => panic!("owning fixture must select the actual FD-table mode"),
    };
    // SAFETY: duplicate only the stdin socket supplied by the owning fixture.
    let raw = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3) };
    assert!(raw >= 0, "duplicate the owned helper channel");
    // SAFETY: fcntl returned a new fd, adopted once as this socket's owner.
    let socket = std::os::unix::net::UnixStream::from(unsafe { OwnedFd::from_raw_fd(raw) });
    socket
        .peer_addr()
        .expect("owning fixture must supply a connected Unix socket as stdin");
    std::thread::spawn(move || {
        let mut socket = socket;
        let tgid = std::process::id();
        // SAFETY: gettid has no arguments and identifies this actual worker.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
        assert_ne!(tgid, tid, "the mapping worker must be a nonleader");
        if private {
            // SAFETY: only this fresh-exec worker's FD table is detached.
            let status = unsafe { libc::syscall(libc::SYS_unshare, libc::CLONE_FILES) };
            assert_eq!(
                status,
                0,
                "required private FD table refused: {}",
                std::io::Error::last_os_error()
            );
        }
        // Open AFTER unshare: the leader's corresponding descriptor must not
        // acquire this file in private mode. Keep the worker FD through proof.
        let file = std::fs::File::open(path).expect("open the worker's actual source");
        let metadata = file.metadata().unwrap();
        // SAFETY: one read/execute private page from the actual live file fd.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(address, libc::MAP_FAILED, "worker mmap failed");
        struct Mapping(*mut libc::c_void);
        impl Drop for Mapping {
            fn drop(&mut self) {
                // SAFETY: this worker exclusively owns the one-page mapping.
                unsafe {
                    libc::munmap(self.0, 4096);
                }
            }
        }
        let mapping = Mapping(address);
        let ready = D4ThreadReady {
            token,
            tgid,
            tid,
            fd: file.as_raw_fd(),
            start: address as u64,
            end: address as u64 + 4096,
            dev: metadata.dev(),
            ino: metadata.ino(),
        };
        d4_write_thread_ready(&mut socket, &ready).expect("report actual worker FD/VMA identity");
        let mut command = [0];
        socket
            .read_exact(&mut command)
            .expect("owning fixture must release its held worker");
        assert_eq!(command, *b"Q");
        drop(mapping);
        drop(file);
    })
    .join()
    .expect("owned mapping worker must finish successfully");
}

#[test]
fn d4_thread_ready_protocol_rejects_wrong_process_thread_and_ranges() {
    use std::io::Write as _;
    let healthy = D4ThreadReady {
        token: "owned".into(),
        tgid: 101,
        tid: 102,
        fd: 4,
        start: 0x1000,
        end: 0x2000,
        dev: 37,
        ino: 123,
    };
    assert_eq!(d4_validate_thread_ready(&healthy, 101, "owned"), Ok(()));
    let (mut writer, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
    d4_write_thread_ready(&mut writer, &healthy).unwrap();
    let read = d4_read_thread_ready(&mut reader).unwrap();
    assert_eq!(
        read, healthy,
        "actual READY frame retains every reported field"
    );
    assert_eq!(d4_validate_thread_ready(&read, 101, "owned"), Ok(()));
    let mut invalid = Vec::new();
    let mut bad = healthy.clone();
    bad.token = "foreign".into();
    invalid.push(bad);
    let mut bad = healthy.clone();
    bad.tgid = 103;
    invalid.push(bad);
    let mut bad = healthy.clone();
    bad.tid = 101;
    invalid.push(bad);
    let mut bad = healthy.clone();
    bad.tid = 0;
    invalid.push(bad);
    let mut bad = healthy.clone();
    bad.fd = 0;
    invalid.push(bad);
    let mut bad = healthy.clone();
    bad.end += 1;
    invalid.push(bad);
    let mut bad = healthy.clone();
    bad.start = u64::MAX;
    invalid.push(bad);
    let mut bad = healthy.clone();
    bad.ino = 0;
    invalid.push(bad);
    for bad in invalid {
        assert!(d4_validate_thread_ready(&bad, 101, "owned").is_err());
        assert_eq!(d4_validate_thread_ready(&healthy, 101, "owned"), Ok(()));
    }
    writer.write_all(&1025u32.to_ne_bytes()).unwrap();
    assert!(
        d4_read_thread_ready(&mut reader).is_err(),
        "oversize frame refused before any payload read"
    );
}

#[test]
fn d4_thread_file_table_oracle_requires_actual_shared_or_private_evidence() {
    let a = FileIdentity { dev: 37, ino: 123 };
    let b = FileIdentity { dev: 38, ino: 123 };
    assert_eq!(d4_check_thread_file_table(false, a, Some(a)), Ok(()));
    for other in [None, Some(b)] {
        assert!(d4_check_thread_file_table(false, a, other).is_err());
        assert_eq!(d4_check_thread_file_table(true, a, other), Ok(()));
        assert_eq!(d4_check_thread_file_table(false, a, Some(a)), Ok(()));
    }
    assert!(d4_check_thread_file_table(true, a, Some(a)).is_err());
    assert_eq!(d4_check_thread_file_table(true, a, Some(b)), Ok(()));
}

/// A live nonleader maps A with either the shared or its own private FD
/// table; the live leader's TGID must attribute A on both actual backends.
/// A third private-table worker maps an equal-byte Btrfs-key collision B,
/// which must be a real identity mismatch. This observes private files
/// after unshare; literal clone birth, zombie leaders, active capture and
/// native provider calls remain separate obligations.
#[test]
#[ignore = "root Btrfs disk TMPDIR, worker CLONE_FILES unshare and eligible BTF/task_vma identity; actual live-thread parity"]
fn privileged_d4_btrfs_live_thread_private_files_backend_parity() {
    use crate::discovery::identity::{
        PinnedObjects, map_files_identity, test_fixture::real_scan_pin,
    };
    use crate::discovery::kernel_identity::IdentitySession;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::{FileExt as _, MetadataExt as _};

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
    let magic = unsafe { stat.assume_init().f_type } as u64 & 0xffff_ffff;
    assert_eq!(magic, 0x9123_683e, "actual fixture TMPDIR must be Btrfs");
    create_subvolume(parent, "a");
    create_subvolume(parent, "b");
    let a_path = parent.join("a/libthread.so");
    let b_path = parent.join("b/libthread.so");
    let bytes = vec![0xa5u8; 8192];
    std::fs::write(&a_path, &bytes).unwrap();
    std::fs::copy(&a_path, &b_path).unwrap();
    let a_file = std::fs::File::open(&a_path).unwrap();
    let b_file = std::fs::File::open(&b_path).unwrap();
    let identity = |file: &std::fs::File| {
        let metadata = file.metadata().unwrap();
        FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    };
    let a = identity(&a_file);
    let b = identity(&b_file);
    assert_eq!(
        a.ino, b.ino,
        "fresh subvolume files must share an inode number"
    );
    assert_ne!(
        a, b,
        "the collision files must have different physical identities"
    );
    for file in [&a_file, &b_file] {
        let mut held_bytes = vec![0; bytes.len()];
        file.read_exact_at(&mut held_bytes, 0).unwrap();
        assert_eq!(held_bytes, bytes, "actual held equal-byte input");
    }

    let (shared, shared_ready) = D4ThreadChild::spawn(&a_path, false, "owned-shared-a");
    let (private, private_ready) = D4ThreadChild::spawn(&a_path, true, "owned-private-a");
    let (wrong, wrong_ready) = D4ThreadChild::spawn(&b_path, true, "owned-private-b");
    let children = [&shared, &private, &wrong];
    let ready = [&shared_ready, &private_ready, &wrong_ready];
    let expected_files = [a, a, b];
    let paths = [&a_path, &a_path, &b_path];
    let start_times: Vec<_> = children
        .iter()
        .enumerate()
        .map(|(position, child)| {
            child.verify_worker(ready[position], expected_files[position], position != 0)
        })
        .collect();
    for report in ready {
        eprintln!(
            "D4_THREAD_WORKER caller={} tid={} fd={} range={:x}-{:x} file={}:{}",
            report.tgid, report.tid, report.fd, report.start, report.end, report.dev, report.ino
        );
    }
    let snapshots = [shared.maps(), private.maps(), wrong.maps()];
    let mut fixture_lines = Vec::new();
    for (position, snapshot) in snapshots.iter().enumerate() {
        let report = ready[position];
        let line = snapshot
            .iter()
            .find(|entry| (entry.start, entry.end) == (report.start, report.end))
            .expect("the actual worker's exact live VMA");
        assert_eq!(line.permissions, *b"r-xp");
        assert_eq!(line.file_offset, 0);
        assert_eq!(
            line.raw_path.as_deref(),
            Some(paths[position].as_os_str().as_encoded_bytes())
        );
        assert!(
            is_caller_range(line),
            "each real worker has executable proof demand"
        );
        assert_eq!(
            map_files_identity(report.tgid, line.start, line.end)
                .expect("independent live vm_file identity"),
            expected_files[position]
        );
        fixture_lines.push(line.clone());
    }
    let key = ObjectKey::of(&fixture_lines[0]);
    for line in &fixture_lines {
        assert_eq!(ObjectKey::of(line), key, "actual Btrfs maps-key collision");
    }
    let digest = p11scope_manifest::identity::hex(&Sha256::digest(&bytes));
    let pins: PinnedObjects = real_scan_pin(&a_path, Some(key), 0, &digest);
    let object = pins.pinned().next().expect("actual held A pin").id;
    assert_eq!(identity(pins.file_for(object).unwrap()), a);
    let (index, refused) = KnownKeyIndex::build(
        [(key, Some(object))],
        &BTreeMap::from([(key, object)]),
        [],
        &pins,
    );
    assert!(refused.is_empty(), "{refused:?}");
    let proof_keys = index.map_files_keys();
    assert!(proof_keys.contains(&key));
    for (position, snapshot) in snapshots.iter().enumerate() {
        assert_eq!(
            proof_ranges(snapshot, &proof_keys),
            [(ready[position].start, ready[position].end)],
            "one exact real worker VMA must require identity proof"
        );
        assert_eq!(
            snapshot
                .iter()
                .filter(|entry| ObjectKey::of(entry) == key)
                .cloned()
                .collect::<Vec<_>>(),
            [fixture_lines[position].clone()],
            "no additional fixture-key mapping may hide the population"
        );
    }
    let probe_dir = tempfile::tempdir().unwrap();
    let mut session = IdentitySession::probe_and_load(&btf, probe_dir.path())
        .expect("actual strict-loaded kernel session; no refused/fallback positive");
    for (position, child) in children.iter().enumerate() {
        let pid = child.child.id();
        let userspace = attribute_pid(pid, snapshots[position].clone(), &index);
        let kernel = d4_kernel_attribution_for_pid(
            pid,
            snapshots[position].clone(),
            &pins,
            object,
            key,
            &mut session,
            position as u64 + 1,
        );
        for (backend, out) in [("userspace", &userspace), ("kernel", &kernel)] {
            assert_eq!(
                out.probed, 1,
                "{backend}: nonvacuous actual executable proof demand"
            );
            assert_eq!(out.unavailable, 0);
            assert!(
                out.exited.is_empty(),
                "{backend}: the owned leader/worker must remain live"
            );
            if position < 2 {
                assert_eq!(
                    out.members
                        .iter()
                        .map(|member| member.pid)
                        .collect::<Vec<_>>(),
                    [pid],
                    "{backend}: the live leader TGID owns the worker's executable mapping"
                );
                assert_eq!(out.members[0].start_time, start_times[position]);
                assert_eq!(
                    out.members[0]
                        .objects
                        .iter()
                        .map(|matched| (matched.key, matched.object, matched.path.as_str()))
                        .collect::<Vec<_>>(),
                    [(key, object, a_path.to_str().unwrap())],
                    "{backend}: exact held-A edge"
                );
                assert!(out.losses.is_empty(), "{backend}: {:?}", out.member_losses);
            } else {
                assert!(
                    out.members.is_empty(),
                    "{backend}: the equal-byte private B is not A"
                );
                assert_eq!(
                    out.losses,
                    BTreeMap::from([(AttributionLoss::IdentityMismatch, 1)]),
                    "{backend}: actual physical-file mismatch"
                );
                assert_eq!(
                    out.member_losses.get(&pid).map(|(loss, _)| *loss),
                    Some(AttributionLoss::IdentityMismatch)
                );
            }
        }
        assert_eq!(
            userspace.members, kernel.members,
            "independently checked backend edges"
        );
        assert_eq!(userspace.losses, kernel.losses);
        assert_eq!(
            child.verify_worker(ready[position], expected_files[position], position != 0),
            start_times[position]
        );
        let after = child.maps();
        assert_eq!(
            after
                .iter()
                .filter(|entry| ObjectKey::of(entry) == key)
                .cloned()
                .collect::<Vec<_>>(),
            [fixture_lines[position].clone()],
            "the actual held worker VMA remains stable"
        );
    }
    assert!(
        pins.object_unchanged(object)
            .expect("recheck actual held A anchor")
    );
    for (file, expected) in [(&a_file, a), (&b_file, b)] {
        assert_eq!(identity(file), expected);
        assert_eq!(file.metadata().unwrap().len(), bytes.len() as u64);
        let mut held_bytes = vec![0; bytes.len()];
        file.read_exact_at(&mut held_bytes, 0).unwrap();
        assert_eq!(
            held_bytes, bytes,
            "both held physical files remain unchanged"
        );
    }
    let pids = [shared.child.id(), private.child.id(), wrong.child.id()];
    eprintln!(
        "D4_BTRFS_THREAD callers={}/{}/{} workers={}/{}/{} userspace=1/1/0 kernel=1/1/0 fd_tables=shared/private/private generations=1/2/3 fallback=none",
        pids[0], pids[1], pids[2], shared_ready.tid, private_ready.tid, wrong_ready.tid
    );
    drop((session, pins));
    shared.finish();
    private.finish();
    wrong.finish();
    for pid in pids {
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "owned helper must be reaped"
        );
    }
    drop((a_file, b_file));
    std::fs::remove_file(&a_path).unwrap();
    std::fs::remove_file(&b_path).unwrap();
    std::fs::remove_dir(parent.join("a")).unwrap();
    std::fs::remove_dir(parent.join("b")).unwrap();
    probe_dir
        .close()
        .expect("remove owned kernel probe directory");
    dir.close()
        .expect("remove owned Btrfs thread fixture directory");
}

const D4_CLONE_WITHOUT_FILES_FLAGS: libc::c_int = libc::CLONE_VM
    | libc::CLONE_SIGHAND
    | libc::CLONE_THREAD
    | libc::CLONE_PARENT_SETTID
    | libc::CLONE_CHILD_CLEARTID;
const D4_CLONE_WORKER_MAGIC: u64 = 0xd4c1_0001;
const D4_CLONE_WORKER_REPLY_LEN: usize = 8 * 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct D4CloneBirth {
    returned_tid: u32,
    parent_tid: u32,
    flags: u32,
}

fn d4_clone_without_files_flags(flags: u32) -> Result<(), &'static str> {
    if flags & libc::CLONE_FILES as u32 != 0 {
        return Err("the thread must be born without CLONE_FILES");
    }
    if flags != D4_CLONE_WITHOUT_FILES_FLAGS as u32 {
        return Err("require VM/SIGHAND/THREAD and the two actual kernel TID operations only");
    }
    Ok(())
}

fn d4_decode_clone_worker_reply(
    bytes: &[u8],
    tgid: u32,
    tid: u32,
    token: &str,
) -> Result<D4ThreadReady, &'static str> {
    if bytes.len() != D4_CLONE_WORKER_REPLY_LEN {
        return Err("wrong raw worker reply size");
    }
    let words: [u64; 8] = std::array::from_fn(|index| {
        u64::from_ne_bytes(bytes[index * 8..(index + 1) * 8].try_into().unwrap())
    });
    if words[0] != D4_CLONE_WORKER_MAGIC
        || words[1] != u64::from(tgid)
        || words[2] != u64::from(tid)
    {
        return Err("raw worker is not the actual cloned task");
    }
    let ready = D4ThreadReady {
        token: token.into(),
        tgid,
        tid,
        fd: i32::try_from(words[3]).map_err(|_| "raw worker fd overflow")?,
        start: words[4],
        end: words[5],
        dev: words[6],
        ino: words[7],
    };
    d4_validate_thread_ready(&ready, tgid, token)?;
    Ok(ready)
}

fn d4_decode_clone_birth(
    bytes: &[u8],
    ready: &D4ThreadReady,
) -> Result<D4CloneBirth, &'static str> {
    if bytes.len() != 12 {
        return Err("wrong clone birth reply size");
    }
    let birth = D4CloneBirth {
        returned_tid: u32::from_ne_bytes(bytes[..4].try_into().unwrap()),
        parent_tid: u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
        flags: u32::from_ne_bytes(bytes[8..12].try_into().unwrap()),
    };
    d4_clone_without_files_flags(birth.flags)?;
    if birth.returned_tid == 0
        || birth.returned_tid != ready.tid
        || birth.parent_tid != birth.returned_tid
    {
        return Err("clone return, parent-written TID and live worker reply must agree");
    }
    Ok(birth)
}

fn d4_write_clone_birth(
    stream: &mut std::os::unix::net::UnixStream,
    birth: D4CloneBirth,
) -> std::io::Result<()> {
    use std::io::Write as _;
    for word in [birth.returned_tid, birth.parent_tid, birth.flags] {
        stream.write_all(&word.to_ne_bytes())?;
    }
    Ok(())
}

impl D4ThreadChild {
    fn spawn_clone_without_files(
        path: &std::path::Path,
        token: &str,
    ) -> (Self, D4ThreadReady, D4CloneBirth) {
        use std::io::Read as _;
        use std::os::fd::OwnedFd;
        use std::process::{Command, Stdio};
        let (channel, helper) = std::os::unix::net::UnixStream::pair().unwrap();
        channel
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        channel
            .set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        helper
            .set_read_timeout(Some(std::time::Duration::from_secs(60)))
            .unwrap();
        helper
            .set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "discovery::sweep_attribution::tests::d4_clone_without_files_mapping_helper",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("P11SCOPE_D4_CLONE_PATH", path)
            .env("P11SCOPE_D4_CLONE_TOKEN", token)
            .stdin(Stdio::from(OwnedFd::from(helper)))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("fresh exec of the matching literal-clone libtest helper");
        let mut owned = Self {
            child,
            channel,
            reaped: false,
        };
        let ready = d4_read_thread_ready(&mut owned.channel)
            .expect("required actual clone worker READY; refusal cannot qualify");
        d4_validate_thread_ready(&ready, owned.child.id(), token)
            .expect("actual owned nonleader mapping");
        let mut bytes = [0; 12];
        owned
            .channel
            .read_exact(&mut bytes)
            .expect("actual clone return and parent-written TID");
        let birth =
            d4_decode_clone_birth(&bytes, &ready).expect("literal private-files thread birth");
        (owned, ready, birth)
    }
}

#[test]
fn d4_clone_without_files_flags_reject_shared_files_or_nonthreads() {
    let healthy = (libc::CLONE_VM
        | libc::CLONE_SIGHAND
        | libc::CLONE_THREAD
        | libc::CLONE_PARENT_SETTID
        | libc::CLONE_CHILD_CLEARTID) as u32;
    assert_eq!(d4_clone_without_files_flags(healthy), Ok(()));
    for bad in [
        healthy | libc::CLONE_FILES as u32,
        healthy & !(libc::CLONE_VM as u32),
        healthy & !(libc::CLONE_SIGHAND as u32),
        healthy & !(libc::CLONE_THREAD as u32),
        healthy & !(libc::CLONE_PARENT_SETTID as u32),
        healthy & !(libc::CLONE_CHILD_CLEARTID as u32),
        healthy | libc::CLONE_SETTLS as u32,
    ] {
        assert!(d4_clone_without_files_flags(bad).is_err());
        assert_eq!(d4_clone_without_files_flags(healthy), Ok(()));
    }
}

#[test]
fn d4_clone_without_files_reply_rejects_wrong_tid_and_malformed_frames() {
    let words = [D4_CLONE_WORKER_MAGIC, 101, 102, 4, 0x1000, 0x2000, 37, 123];
    let encode = |words: &[u64]| {
        words
            .iter()
            .flat_map(|word| word.to_ne_bytes())
            .collect::<Vec<_>>()
    };
    let bytes = encode(&words);
    let healthy = d4_decode_clone_worker_reply(&bytes, 101, 102, "owned").unwrap();
    assert_eq!(
        (
            healthy.tgid,
            healthy.tid,
            healthy.fd,
            healthy.start,
            healthy.end,
            healthy.dev,
            healthy.ino
        ),
        (101, 102, 4, 0x1000, 0x2000, 37, 123)
    );
    for bad in [
        &bytes[..bytes.len() - 1],
        &[0; D4_CLONE_WORKER_REPLY_LEN + 1][..],
    ] {
        assert!(d4_decode_clone_worker_reply(bad, 101, 102, "owned").is_err());
    }
    for (position, value) in [
        (0, 0),
        (1, 103),
        (2, 103),
        (3, u64::MAX),
        (5, 0x2001),
        (7, 0),
    ] {
        let mut bad = words;
        bad[position] = value;
        assert!(d4_decode_clone_worker_reply(&encode(&bad), 101, 102, "owned").is_err());
        assert_eq!(
            d4_decode_clone_worker_reply(&bytes, 101, 102, "owned"),
            Ok(healthy.clone())
        );
    }
    let birth = D4CloneBirth {
        returned_tid: 102,
        parent_tid: 102,
        flags: D4_CLONE_WITHOUT_FILES_FLAGS as u32,
    };
    let (mut writer, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
    d4_write_thread_ready(&mut writer, &healthy).unwrap();
    d4_write_clone_birth(&mut writer, birth).unwrap();
    let ready = d4_read_thread_ready(&mut reader).unwrap();
    use std::io::Read as _;
    let mut birth_bytes = [0; 12];
    reader.read_exact(&mut birth_bytes).unwrap();
    assert_eq!(d4_decode_clone_birth(&birth_bytes, &ready), Ok(birth));
    for bad in [
        D4CloneBirth {
            returned_tid: 0,
            ..birth
        },
        D4CloneBirth {
            returned_tid: 103,
            ..birth
        },
        D4CloneBirth {
            parent_tid: 103,
            ..birth
        },
        D4CloneBirth {
            flags: birth.flags | libc::CLONE_FILES as u32,
            ..birth
        },
    ] {
        let bytes: Vec<_> = [bad.returned_tid, bad.parent_tid, bad.flags]
            .into_iter()
            .flat_map(u32::to_ne_bytes)
            .collect();
        assert!(d4_decode_clone_birth(&bytes, &healthy).is_err());
        assert_eq!(d4_decode_clone_birth(&birth_bytes, &healthy), Ok(birth));
    }
    assert!(d4_decode_clone_birth(&birth_bytes[..11], &healthy).is_err());
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[repr(C)]
struct D4RawCloneArgs {
    path: *const libc::c_char,
    channel: libc::c_int,
    unused_channel: libc::c_int,
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
const D4_CLONE_WORKER_WIRE_OFFSET: usize = (std::mem::size_of::<libc::stat>() + 15) & !15;
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
const D4_CLONE_WORKER_FRAME_SIZE: usize =
    (D4_CLONE_WORKER_WIRE_OFFSET + D4_CLONE_WORKER_REPLY_LEN + 1 + 15) & !15;

/// The complete newborn path is assembly: no libc syscall errno writes,
/// inherited TLS, Rust prologue, allocation, panic or unwinding. The glibc
/// clone trampoline supplies RDI and an independent stack. We never return,
/// so callee-saved registers need not be restored to that trampoline.
/// Both success and failure use SYS_exit for THIS THREAD, never exit_group.
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[unsafe(naked)]
extern "C" fn d4_clone_without_files_worker(_context: *mut libc::c_void) -> libc::c_int {
    core::arch::naked_asm!(
        "sub rsp, {frame}",
        "mov rbx, rdi",
        "mov r12d, dword ptr [rbx + {args_channel}]",
        // This endpoint belongs to the normal parent. Its newborn copy
        // must close, or EOF would depend on a peer held by the worker.
        "mov edi, dword ptr [rbx + {args_unused}]",
        "mov eax, {sys_close}",
        "syscall",
        "test rax, rax",
        "jnz 9f",
        "mov eax, {magic}",
        "mov qword ptr [rsp + {wire}], rax",
        "mov eax, {sys_getpid}",
        "syscall",
        "mov qword ptr [rsp + {wire} + 8], rax",
        "mov eax, {sys_gettid}",
        "syscall",
        "mov qword ptr [rsp + {wire} + 16], rax",
        // Open only AFTER the literal private-files birth, with no unshare.
        "mov eax, {sys_openat}",
        "mov rdi, {at_fdcwd}",
        "mov rsi, qword ptr [rbx + {args_path}]",
        "mov edx, {open_flags}",
        "xor r10d, r10d",
        "syscall",
        "test rax, rax",
        "js 9f",
        "mov r13, rax",
        "mov qword ptr [rsp + {wire} + 24], rax",
        "mov eax, {sys_fstat}",
        "mov edi, r13d",
        "mov rsi, rsp",
        "syscall",
        "test rax, rax",
        "jnz 9f",
        "mov rax, qword ptr [rsp + {stat_dev}]",
        "mov qword ptr [rsp + {wire} + 48], rax",
        "mov rax, qword ptr [rsp + {stat_ino}]",
        "mov qword ptr [rsp + {wire} + 56], rax",
        "mov eax, {sys_mmap}",
        "xor edi, edi",
        "mov esi, 4096",
        "mov edx, {prot}",
        "mov r10d, {map_private}",
        "mov r8, r13",
        "xor r9d, r9d",
        "syscall",
        "test rax, rax",
        "js 9f",
        "mov r14, rax",
        "mov qword ptr [rsp + {wire} + 32], rax",
        "add rax, 4096",
        "mov qword ptr [rsp + {wire} + 40], rax",
        // The bounded native-endian reply comes only from actual syscalls.
        "lea rbp, [rsp + {wire}]",
        "mov r15d, {reply_len}",
        "2:",
        "mov eax, {sys_write}",
        "mov edi, r12d",
        "mov rsi, rbp",
        "mov rdx, r15",
        "syscall",
        "cmp rax, -{eintr}",
        "je 2b",
        "test rax, rax",
        "jle 9f",
        "cmp rax, r15",
        "ja 9f",
        "add rbp, rax",
        "sub r15, rax",
        "jnz 2b",
        "3:",
        "mov eax, {sys_read}",
        "mov edi, r12d",
        "lea rsi, [rsp + {wire} + {reply_len}]",
        "mov edx, 1",
        "syscall",
        "cmp rax, -{eintr}",
        "je 3b",
        "cmp rax, 1",
        "jne 9f",
        "cmp byte ptr [rsp + {wire} + {reply_len}], 81",
        "jne 9f",
        "mov eax, {sys_munmap}",
        "mov rdi, r14",
        "mov esi, 4096",
        "syscall",
        "test rax, rax",
        "jnz 9f",
        "mov eax, {sys_close}",
        "mov edi, r13d",
        "syscall",
        "test rax, rax",
        "jnz 9f",
        // ACK follows successful VMA removal and source-FD close. The
        // normal parent still must join kernel clear-TID before freeing.
        "mov byte ptr [rsp + {wire} + {reply_len}], 68",
        "4:",
        "mov eax, {sys_write}",
        "mov edi, r12d",
        "lea rsi, [rsp + {wire} + {reply_len}]",
        "mov edx, 1",
        "syscall",
        "cmp rax, -{eintr}",
        "je 4b",
        "cmp rax, 1",
        "jne 9f",
        "xor edi, edi",
        "mov eax, {sys_exit}",
        "syscall",
        "ud2",
        "9:",
        "mov edi, 91",
        "mov eax, {sys_exit}",
        "syscall",
        "ud2",
        frame = const D4_CLONE_WORKER_FRAME_SIZE,
        wire = const D4_CLONE_WORKER_WIRE_OFFSET,
        reply_len = const D4_CLONE_WORKER_REPLY_LEN,
        args_path = const std::mem::offset_of!(D4RawCloneArgs, path),
        args_channel = const std::mem::offset_of!(D4RawCloneArgs, channel),
        args_unused = const std::mem::offset_of!(D4RawCloneArgs, unused_channel),
        stat_dev = const std::mem::offset_of!(libc::stat, st_dev),
        stat_ino = const std::mem::offset_of!(libc::stat, st_ino),
        magic = const D4_CLONE_WORKER_MAGIC,
        eintr = const libc::EINTR,
        at_fdcwd = const libc::AT_FDCWD,
        open_flags = const libc::O_RDONLY | libc::O_CLOEXEC,
        prot = const libc::PROT_READ | libc::PROT_EXEC,
        map_private = const libc::MAP_PRIVATE,
        sys_close = const libc::SYS_close,
        sys_getpid = const libc::SYS_getpid,
        sys_gettid = const libc::SYS_gettid,
        sys_openat = const libc::SYS_openat,
        sys_fstat = const libc::SYS_fstat,
        sys_mmap = const libc::SYS_mmap,
        sys_write = const libc::SYS_write,
        sys_read = const libc::SYS_read,
        sys_munmap = const libc::SYS_munmap,
        sys_exit = const libc::SYS_exit,
    );
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
struct D4RawCloneGuard {
    stack: *mut libc::c_void,
    stack_len: usize,
    // Published allocations stay raw while the newborn can access them;
    // moving this guard never reclaims or retags a Box over its live args.
    args: *mut D4RawCloneArgs,
    path: *mut libc::c_char,
    channel: std::os::unix::net::UnixStream,
    child_tid: *mut std::sync::atomic::AtomicI32,
    worker_tid: libc::c_int,
    joined: bool,
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
impl D4RawCloneGuard {
    fn spawn(path: std::ffi::CString) -> (Self, D4CloneBirth) {
        use std::os::fd::AsRawFd as _;
        use std::sync::atomic::{AtomicI32, Ordering};
        let (channel, worker) = std::os::unix::net::UnixStream::pair().unwrap();
        channel
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        channel
            .set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        worker
            .set_read_timeout(Some(std::time::Duration::from_secs(60)))
            .unwrap();
        worker
            .set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        // SAFETY: this is the normal post-exec parent, with ordinary TLS.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(page > 0);
        let page = page as usize;
        let stack_size = 1024 * 1024;
        let stack_len = stack_size + 2 * page;
        // SAFETY: an owned anonymous allocation, initially all guard pages.
        let stack = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                stack_len,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(stack, libc::MAP_FAILED, "owned raw-worker stack");
        let path = path.into_raw();
        let args = Box::into_raw(Box::new(D4RawCloneArgs {
            path,
            channel: worker.as_raw_fd(),
            unused_channel: channel.as_raw_fd(),
        }));
        let mut owned = Self {
            stack,
            stack_len,
            args,
            path,
            channel,
            child_tid: Box::into_raw(Box::new(AtomicI32::new(-1))),
            worker_tid: 0,
            joined: false,
        };
        // SAFETY: only the middle of this owned allocation becomes writable;
        // the leading/trailing pages remain guards through kernel join.
        let stack_start = unsafe { stack.cast::<u8>().add(page) };
        assert_eq!(
            unsafe {
                libc::mprotect(
                    stack_start.cast(),
                    stack_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            },
            0
        );
        d4_clone_without_files_flags(D4_CLONE_WITHOUT_FILES_FLAGS as u32).unwrap();
        let tid_address = owned.tid_word().as_ptr();
        // SAFETY: normal-parent glibc trampoline; the callback is a complete
        // syscall-only leaf on its separate stack. All pointed-to storage and
        // both IPC endpoints remain owned until kernel clear-TID is acquired.
        let tid = unsafe {
            libc::clone(
                d4_clone_without_files_worker,
                stack_start.add(stack_size).cast(),
                D4_CLONE_WITHOUT_FILES_FLAGS,
                owned.args.cast(),
                tid_address,
                std::ptr::null_mut::<libc::c_void>(),
                tid_address,
            )
        };
        // Establish the fatal-on-unwind guard before any assertion or I/O.
        owned.worker_tid = tid;
        assert!(
            tid > 0,
            "required literal clone failed: {}",
            std::io::Error::last_os_error()
        );
        let parent_tid = owned.tid_word().load(Ordering::Acquire);
        assert_eq!(parent_tid, tid, "actual CLONE_PARENT_SETTID write");
        // Parent and worker have separate FD tables. Closing this parent's
        // copy cannot close the raw worker's peer; it makes worker EOF honest.
        drop(worker);
        (
            owned,
            D4CloneBirth {
                returned_tid: tid as u32,
                parent_tid: parent_tid as u32,
                flags: D4_CLONE_WITHOUT_FILES_FLAGS as u32,
            },
        )
    }

    fn tid_word(&self) -> &std::sync::atomic::AtomicI32 {
        // SAFETY: this guard owns the naturally aligned allocation until
        // Drop after join. Only the kernel writes it after its initial -1.
        unsafe { &*self.child_tid }
    }

    fn ready(&mut self, token: &str) -> D4ThreadReady {
        use std::io::Read as _;
        let mut bytes = [0; D4_CLONE_WORKER_REPLY_LEN];
        self.channel
            .read_exact(&mut bytes)
            .expect("actual syscall-only worker reply");
        d4_decode_clone_worker_reply(&bytes, std::process::id(), self.worker_tid as u32, token)
            .expect("actual worker matches clone return and opened-file VMA")
    }

    fn finish(mut self) {
        use std::io::{Read as _, Write as _};
        use std::sync::atomic::Ordering;
        self.channel
            .write_all(b"Q")
            .expect("release the actual raw worker");
        let mut ack = [0];
        self.channel
            .read_exact(&mut ack)
            .expect("raw worker cleanup ACK");
        assert_eq!(ack, *b"D", "raw worker removed its VMA and closed its file");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut waits = 0;
        loop {
            let observed = self.tid_word().load(Ordering::Acquire);
            if observed == 0 {
                self.joined = true;
                break;
            }
            assert_eq!(
                observed, self.worker_tid,
                "only the kernel may clear child-TID"
            );
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .expect("raw worker kernel join exceeded its deadline");
            let timeout = libc::timespec {
                tv_sec: remaining.as_secs() as libc::time_t,
                tv_nsec: remaining.subsec_nanos() as libc::c_long,
            };
            // SAFETY: the naturally aligned boxed TID word and timeout stay
            // live. clear_child_tid wakes FUTEX_WAIT, NOT FUTEX_WAIT_PRIVATE.
            // This libc call is on the normal parent, never the raw child.
            let status = unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    self.tid_word().as_ptr(),
                    libc::FUTEX_WAIT,
                    observed,
                    &timeout,
                    std::ptr::null::<u32>(),
                    0,
                )
            };
            waits += 1;
            if status < 0 {
                let error = std::io::Error::last_os_error();
                assert!(
                    matches!(
                        error.raw_os_error(),
                        Some(libc::EINTR | libc::EAGAIN | libc::ETIMEDOUT)
                    ),
                    "kernel clear-TID join failed: {error}"
                );
            }
        }
        assert_eq!(self.tid_word().load(Ordering::Acquire), 0);
        // SAFETY: kernel clear-TID was acquired; no newborn user code can
        // access this stack, args, path or IPC after this point.
        assert_eq!(
            unsafe { libc::munmap(self.stack, self.stack_len) },
            0,
            "release joined raw-worker stack"
        );
        self.stack = std::ptr::null_mut();
        eprintln!(
            "D4_CLONE_JOIN caller={} worker={} clear_tid=0 shared_futex_waits={waits}",
            std::process::id(),
            self.worker_tid
        );
    }
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
impl Drop for D4RawCloneGuard {
    fn drop(&mut self) {
        if self.worker_tid > 0 && !self.joined {
            // A normal-parent failure must not unwind/free memory a raw
            // worker could still use. Terminate this OWNED helper process;
            // the outer D4ThreadChild guard reaps it. The child never uses
            // this path, and its normal exit above is strictly thread-only.
            unsafe { libc::_exit(104) };
        }
        if !self.stack.is_null() {
            // SAFETY: no worker was created, or kernel join already completed.
            unsafe {
                libc::munmap(self.stack, self.stack_len);
            }
        }
        // SAFETY: the fatal branch prevents reclamation with a live raw
        // child. Each allocation was published once and is reclaimed once;
        // the newborn never changes the owned CString's bytes or length.
        unsafe {
            drop(Box::from_raw(self.args));
            drop(std::ffi::CString::from_raw(self.path));
            drop(Box::from_raw(self.child_tid));
        }
    }
}

/// Private re-exec entrypoint. Missing owned configuration fails, never skips.
#[test]
#[ignore = "private D4 literal-clone fixture entrypoint; requires its owning parity test socket/configuration"]
fn d4_clone_without_files_mapping_helper() {
    #[cfg(not(all(target_arch = "x86_64", target_pointer_width = "64")))]
    panic!("the actual literal-clone fixture requires the x86-64 LP64 syscall ABI");
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    {
        use std::io::Read as _;
        use std::os::fd::{FromRawFd as _, OwnedFd};
        let path = std::env::var_os("P11SCOPE_D4_CLONE_PATH").expect("owned literal-clone source");
        let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let token = std::env::var("P11SCOPE_D4_CLONE_TOKEN").expect("owning literal-clone token");
        assert!(!token.is_empty());
        // SAFETY: only this fresh-exec normal parent's supplied stdin socket.
        let raw = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3) };
        assert!(raw >= 0);
        // SAFETY: the fresh duplicate is adopted exactly once.
        let mut socket = std::os::unix::net::UnixStream::from(unsafe { OwnedFd::from_raw_fd(raw) });
        socket
            .peer_addr()
            .expect("owning fixture must supply its connected Unix socket");
        let (mut worker, birth) = D4RawCloneGuard::spawn(path);
        let ready = worker.ready(&token);
        d4_write_thread_ready(&mut socket, &ready)
            .expect("relay actual raw-worker FD/VMA identity");
        d4_write_clone_birth(&mut socket, birth)
            .expect("report actual clone return and parent-written TID");
        let mut command = [0];
        socket
            .read_exact(&mut command)
            .expect("owning fixture must release its raw worker");
        assert_eq!(command, *b"Q");
        worker.finish();
    }
}

/// A literal CLONE_THREAD birth omits CLONE_FILES, rather than detaching
/// files after std-thread birth. The actual live TGID must attribute A,
/// and refuse physically different B despite its identical Btrfs maps key.
/// Zombie leaders, active capture and native calls remain separate gates;
/// the current zombie refusal does not satisfy that selected D4 population.
#[test]
#[ignore = "root x86-64 LP64 Btrfs disk TMPDIR, literal private-files clone and eligible BTF/task_vma identity; actual backend parity"]
fn privileged_d4_btrfs_clone_without_files_backend_parity() {
    use crate::discovery::identity::{
        PinnedObjects, map_files_identity, test_fixture::real_scan_pin,
    };
    use crate::discovery::kernel_identity::IdentitySession;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::{FileExt as _, MetadataExt as _};

    assert!(
        cfg!(all(target_arch = "x86_64", target_pointer_width = "64")),
        "the required actual raw worker uses the x86-64 LP64 syscall ABI"
    );
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
    let magic = unsafe { stat.assume_init().f_type } as u64 & 0xffff_ffff;
    assert_eq!(magic, 0x9123_683e, "actual fixture TMPDIR must be Btrfs");
    create_subvolume(parent, "a");
    create_subvolume(parent, "b");
    let a_path = parent.join("a/libclone.so");
    let b_path = parent.join("b/libclone.so");
    let bytes = vec![0xa5u8; 8192];
    std::fs::write(&a_path, &bytes).unwrap();
    std::fs::copy(&a_path, &b_path).unwrap();
    let a_file = std::fs::File::open(&a_path).unwrap();
    let b_file = std::fs::File::open(&b_path).unwrap();
    let identity = |file: &std::fs::File| {
        let metadata = file.metadata().unwrap();
        FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    };
    let a = identity(&a_file);
    let b = identity(&b_file);
    assert_eq!(
        a.ino, b.ino,
        "fresh subvolume files must share an inode number"
    );
    assert_ne!(
        a, b,
        "the equal-byte collision must name different physical files"
    );
    for file in [&a_file, &b_file] {
        let mut held_bytes = vec![0; bytes.len()];
        file.read_exact_at(&mut held_bytes, 0).unwrap();
        assert_eq!(
            held_bytes, bytes,
            "each actual held input has the same bytes"
        );
    }

    let (caller, caller_ready, caller_birth) =
        D4ThreadChild::spawn_clone_without_files(&a_path, "owned-clone-a");
    let (wrong, wrong_ready, wrong_birth) =
        D4ThreadChild::spawn_clone_without_files(&b_path, "owned-clone-b");
    let children = [&caller, &wrong];
    let ready = [&caller_ready, &wrong_ready];
    let birth = [caller_birth, wrong_birth];
    let expected_files = [a, b];
    let paths = [&a_path, &b_path];
    let mut start_times = Vec::new();
    for (position, child) in children.iter().enumerate() {
        let report = ready[position];
        assert_eq!(birth[position].flags, D4_CLONE_WITHOUT_FILES_FLAGS as u32);
        assert_eq!(birth[position].returned_tid, report.tid);
        assert_eq!(birth[position].parent_tid, report.tid);
        start_times.push(child.verify_worker(report, expected_files[position], true));
        eprintln!(
            "D4_CLONE_WORKER caller={} tid={} clone_return={} parent_tid={} flags={:#x} fd={} range={:x}-{:x} file={}:{}",
            report.tgid,
            report.tid,
            birth[position].returned_tid,
            birth[position].parent_tid,
            birth[position].flags,
            report.fd,
            report.start,
            report.end,
            report.dev,
            report.ino
        );
    }
    let snapshots = [caller.maps(), wrong.maps()];
    let mut fixture_lines = Vec::new();
    for (position, snapshot) in snapshots.iter().enumerate() {
        let report = ready[position];
        let line = snapshot
            .iter()
            .find(|entry| (entry.start, entry.end) == (report.start, report.end))
            .expect("the actual literal-clone worker's exact VMA");
        assert_eq!(line.permissions, *b"r-xp");
        assert_eq!(line.file_offset, 0);
        assert_eq!(
            line.raw_path.as_deref(),
            Some(paths[position].as_os_str().as_encoded_bytes())
        );
        assert!(
            is_caller_range(line),
            "both actual workers require executable proof"
        );
        assert_eq!(
            map_files_identity(report.tgid, line.start, line.end)
                .expect("independent actual vm_file identity"),
            expected_files[position]
        );
        fixture_lines.push(line.clone());
    }
    let key = ObjectKey::of(&fixture_lines[0]);
    assert_eq!(
        ObjectKey::of(&fixture_lines[1]),
        key,
        "actual Btrfs maps-key collision"
    );
    let digest = p11scope_manifest::identity::hex(&Sha256::digest(&bytes));
    let pins: PinnedObjects = real_scan_pin(&a_path, Some(key), 0, &digest);
    let object = pins.pinned().next().expect("actual held A pin").id;
    assert_eq!(identity(pins.file_for(object).unwrap()), a);
    let (index, refused) = KnownKeyIndex::build(
        [(key, Some(object))],
        &BTreeMap::from([(key, object)]),
        [],
        &pins,
    );
    assert!(refused.is_empty(), "{refused:?}");
    let proof_keys = index.map_files_keys();
    assert!(proof_keys.contains(&key));
    for (position, snapshot) in snapshots.iter().enumerate() {
        assert_eq!(
            proof_ranges(snapshot, &proof_keys),
            [(ready[position].start, ready[position].end)],
            "one exact real worker VMA must require identity proof"
        );
        assert_eq!(
            snapshot
                .iter()
                .filter(|entry| ObjectKey::of(entry) == key)
                .cloned()
                .collect::<Vec<_>>(),
            [fixture_lines[position].clone()],
            "the entire fixture-key population is known"
        );
    }
    let probe_dir = tempfile::tempdir().unwrap();
    let mut session = IdentitySession::probe_and_load(&btf, probe_dir.path())
        .expect("actual strict-loaded kernel session; no refused/fallback positive");
    for (position, child) in children.iter().enumerate() {
        let pid = child.child.id();
        let userspace = attribute_pid(pid, snapshots[position].clone(), &index);
        let kernel = d4_kernel_attribution_for_pid(
            pid,
            snapshots[position].clone(),
            &pins,
            object,
            key,
            &mut session,
            position as u64 + 1,
        );
        for (backend, out) in [("userspace", &userspace), ("kernel", &kernel)] {
            assert_eq!(out.probed, 1, "{backend}: actual executable proof demand");
            assert_eq!(out.unavailable, 0);
            assert!(
                out.exited.is_empty(),
                "{backend}: the owned TGID and worker remain live"
            );
            if position == 0 {
                assert_eq!(
                    out.members
                        .iter()
                        .map(|member| member.pid)
                        .collect::<Vec<_>>(),
                    [pid],
                    "{backend}: exact live TGID owns the raw worker's mapping"
                );
                assert_eq!(out.members[0].start_time, start_times[position]);
                assert_eq!(
                    out.members[0]
                        .objects
                        .iter()
                        .map(|matched| (matched.key, matched.object, matched.path.as_str()))
                        .collect::<Vec<_>>(),
                    [(key, object, a_path.to_str().unwrap())],
                    "{backend}: exact held-A edge"
                );
                assert!(out.losses.is_empty(), "{backend}: {:?}", out.member_losses);
            } else {
                assert!(
                    out.members.is_empty(),
                    "{backend}: equal bytes and maps key cannot make B into A"
                );
                assert_eq!(
                    out.losses,
                    BTreeMap::from([(AttributionLoss::IdentityMismatch, 1)]),
                    "{backend}: actual different-file negative"
                );
                assert_eq!(
                    out.member_losses.get(&pid).map(|(loss, _)| *loss),
                    Some(AttributionLoss::IdentityMismatch)
                );
            }
        }
        assert_eq!(
            userspace.members, kernel.members,
            "independently checked backend edges"
        );
        assert_eq!(userspace.losses, kernel.losses);
        assert_eq!(
            child.verify_worker(ready[position], expected_files[position], true),
            start_times[position]
        );
        assert_eq!(
            child
                .maps()
                .into_iter()
                .filter(|entry| ObjectKey::of(entry) == key)
                .collect::<Vec<_>>(),
            [fixture_lines[position].clone()],
            "actual raw-worker VMA remains held through both proofs"
        );
    }
    assert!(
        pins.object_unchanged(object)
            .expect("recheck the real held A anchor")
    );
    for (file, expected) in [(&a_file, a), (&b_file, b)] {
        assert_eq!(identity(file), expected);
        assert_eq!(file.metadata().unwrap().len(), bytes.len() as u64);
        let mut held_bytes = vec![0; bytes.len()];
        file.read_exact_at(&mut held_bytes, 0).unwrap();
        assert_eq!(
            held_bytes, bytes,
            "both held physical files remain unchanged"
        );
    }
    let pids = [caller.child.id(), wrong.child.id()];
    let tids = [caller_ready.tid, wrong_ready.tid];
    drop((session, pins));
    caller.finish();
    wrong.finish();
    for (pid, tid) in pids.into_iter().zip(tids) {
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "owned helper is reaped"
        );
        assert!(
            !std::path::Path::new(&format!("/proc/{tid}")).exists(),
            "owned raw thread is gone"
        );
    }
    eprintln!(
        "D4_BTRFS_CLONE callers={}/{} workers={}/{} userspace=1/0 kernel=1/0 files_private_at_birth=true generations=1/2 fallback=none joined_and_reaped=true",
        pids[0], pids[1], tids[0], tids[1]
    );
    drop((a_file, b_file));
    std::fs::remove_file(&a_path).unwrap();
    std::fs::remove_file(&b_path).unwrap();
    std::fs::remove_dir(parent.join("a")).unwrap();
    std::fs::remove_dir(parent.join("b")).unwrap();
    probe_dir
        .close()
        .expect("remove owned kernel probe directory");
    dir.close()
        .expect("remove owned Btrfs literal-clone fixture directory");
}

const D4_ZOMBIE_MAGIC: u64 = 0xd401_0001;
const D4_ZOMBIE_REPLY_LEN: usize = 11 * 8;

#[derive(Debug, Clone, PartialEq, Eq)]
struct D4ZombieReady {
    mapping: D4ThreadReady,
    creator: u32,
    returned_tid: u32,
    parent_tid: u32,
}

fn d4_zombie_reply(bytes: &[u8], pid: u32) -> Result<D4ZombieReady, &'static str> {
    if bytes.len() != D4_ZOMBIE_REPLY_LEN {
        return Err("fixture: wrong zombie READY length");
    }
    let words: [u64; 11] = std::array::from_fn(|index| {
        u64::from_ne_bytes(bytes[index * 8..(index + 1) * 8].try_into().unwrap())
    });
    if words[0] != D4_ZOMBIE_MAGIC || words[1] != u64::from(pid) {
        return Err("fixture: foreign zombie helper");
    }
    let tid = u32::try_from(words[2]).map_err(|_| "fixture: worker TID overflow")?;
    let mapping = D4ThreadReady {
        token: "owned-zombie".into(),
        tgid: pid,
        tid,
        fd: i32::try_from(words[3]).map_err(|_| "fixture: FD overflow")?,
        start: words[4],
        end: words[5],
        dev: words[6],
        ino: words[7],
    };
    d4_validate_thread_ready(&mapping, pid, "owned-zombie")?;
    let ready = D4ZombieReady {
        mapping,
        creator: u32::try_from(words[8]).map_err(|_| "fixture: creator overflow")?,
        returned_tid: u32::try_from(words[9]).map_err(|_| "fixture: clone return overflow")?,
        parent_tid: u32::try_from(words[10]).map_err(|_| "fixture: parent TID overflow")?,
    };
    if ready.creator == 0
        || ready.creator == pid
        || ready.creator == tid
        || ready.returned_tid != tid
        || ready.parent_tid != tid
    {
        return Err("fixture: actual creator/clone/parent/worker TIDs disagree");
    }
    Ok(ready)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct D4ZombieTask {
    tid: u32,
    state: u8,
    birth: u64,
}

fn d4_zombie_stat(text: &str) -> Result<D4ZombieTask, &'static str> {
    let end = text.rfind(')').ok_or("fixture: malformed task comm")?;
    let tid = text
        .split_whitespace()
        .next()
        .ok_or("fixture: missing TID")?
        .parse::<u32>()
        .map_err(|_| "fixture: invalid TID")?;
    let fields: Vec<_> = text[end + 1..].split_whitespace().collect();
    let state = fields
        .first()
        .filter(|value| value.len() == 1)
        .ok_or("fixture: missing task state")?
        .as_bytes()[0];
    let birth = fields
        .get(19)
        .ok_or("fixture: missing task birth")?
        .parse::<u64>()
        .map_err(|_| "fixture: invalid task birth")?;
    if tid == 0 || birth == 0 {
        return Err("fixture: zero task identity");
    }
    Ok(D4ZombieTask { tid, state, birth })
}

fn d4_zombie_task_set(
    tasks: &[D4ZombieTask],
    ready: &D4ZombieReady,
    zombie: bool,
) -> Result<(), &'static str> {
    let live = |state| matches!(state, b'R' | b'S' | b'D');
    let mut expected = BTreeSet::from([ready.mapping.tgid, ready.mapping.tid]);
    if !zombie {
        expected.insert(ready.creator);
    }
    let actual: BTreeSet<_> = tasks.iter().map(|task| task.tid).collect();
    if actual != expected || actual.len() != tasks.len() {
        return Err("fixture: extra, missing or duplicate helper task");
    }
    for task in tasks {
        if zombie && task.tid == ready.mapping.tgid {
            if task.state != b'Z' {
                return Err("fixture: leader is not a zombie");
            }
        } else if !live(task.state) {
            return Err("fixture: expected live worker/controller");
        }
    }
    Ok(())
}

#[test]
fn d4_zombie_single_survivor_protocol_rejects_extra_members() {
    let words = [
        D4_ZOMBIE_MAGIC,
        101,
        103,
        4,
        0x1000,
        0x2000,
        37,
        123,
        102,
        103,
        103,
    ];
    let encode = |words: &[u64]| {
        words
            .iter()
            .flat_map(|word| word.to_ne_bytes())
            .collect::<Vec<_>>()
    };
    let bytes = encode(&words);
    let ready = d4_zombie_reply(&bytes, 101).unwrap();
    let before = [
        D4ZombieTask {
            tid: 101,
            state: b'S',
            birth: 1,
        },
        D4ZombieTask {
            tid: 102,
            state: b'S',
            birth: 2,
        },
        D4ZombieTask {
            tid: 103,
            state: b'S',
            birth: 3,
        },
    ];
    let after = [
        D4ZombieTask {
            state: b'Z',
            ..before[0]
        },
        before[2],
    ];
    assert_eq!(d4_zombie_task_set(&before, &ready, false), Ok(()));
    assert_eq!(d4_zombie_task_set(&after, &ready, true), Ok(()));
    for bad in [
        vec![after[0]],
        vec![after[0], after[1], before[1]],
        vec![after[0], after[1], after[1]],
        vec![before[0], after[1]],
        vec![
            after[0],
            D4ZombieTask {
                state: b'Z',
                ..after[1]
            },
        ],
    ] {
        assert!(d4_zombie_task_set(&bad, &ready, true).is_err());
        assert_eq!(d4_zombie_task_set(&after, &ready, true), Ok(()));
    }
    assert!(d4_zombie_reply(&bytes[..bytes.len() - 1], 101).is_err());
    for (index, value) in [
        (0, 0),
        (1, 104),
        (8, 101),
        (8, 103),
        (9, 104),
        (10, 104),
        (5, 0x2001),
    ] {
        let mut bad = words;
        bad[index] = value;
        assert!(d4_zombie_reply(&encode(&bad), 101).is_err());
        assert_eq!(d4_zombie_reply(&bytes, 101), Ok(ready.clone()));
    }
    let stat = "103 (owned worker) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 3";
    assert_eq!(d4_zombie_stat(stat), Ok(before[2]));
    assert!(d4_zombie_stat("103 (bad) S").is_err());
}

struct D4ZombieChild {
    owned: D4ThreadChild,
}

impl D4ZombieChild {
    fn spawn(path: &std::path::Path) -> (Self, D4ZombieReady) {
        use std::io::Read as _;
        use std::os::fd::OwnedFd;
        use std::process::{Command, Stdio};
        let (channel, helper) = std::os::unix::net::UnixStream::pair().unwrap();
        for socket in [&channel, &helper] {
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
        }
        helper
            .set_read_timeout(Some(std::time::Duration::from_secs(60)))
            .unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "discovery::sweep_attribution::tests::d4_zombie_single_survivor_mapping_helper",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("P11SCOPE_D4_ZOMBIE_PATH", path)
            .stdin(Stdio::from(OwnedFd::from(helper)))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("fixture: matching zombie helper re-exec");
        let mut owned = Self {
            owned: D4ThreadChild {
                child,
                channel,
                reaped: false,
            },
        };
        let mut bytes = [0; D4_ZOMBIE_REPLY_LEN];
        owned
            .owned
            .channel
            .read_exact(&mut bytes)
            .expect("fixture: actual raw zombie READY");
        let ready = d4_zombie_reply(&bytes, owned.owned.child.id())
            .expect("fixture: owned raw worker identity");
        (owned, ready)
    }

    fn zombify(&mut self) {
        use std::io::{Read as _, Write as _};
        self.owned
            .channel
            .write_all(b"Z")
            .expect("fixture: retire leader/controller");
        let mut ack = [0];
        self.owned
            .channel
            .read_exact(&mut ack)
            .expect("fixture: raw retirement ACK");
        assert_eq!(ack, *b"Z", "fixture: retirement protocol");
    }

    fn finish(mut self) -> Result<(), String> {
        use std::io::{Read as _, Write as _};
        self.owned
            .channel
            .write_all(b"Q")
            .map_err(|e| format!("fixture: release failed: {e}"))?;
        let mut ack = [0];
        self.owned
            .channel
            .read_exact(&mut ack)
            .map_err(|e| format!("fixture: cleanup ACK: {e}"))?;
        if ack != *b"D" {
            return Err("fixture: wrong cleanup ACK".into());
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match self.owned.child.try_wait() {
                Ok(Some(status)) => {
                    self.owned.reaped = true;
                    return if status.success() {
                        Ok(())
                    } else {
                        Err(format!("fixture: helper exit {status}"))
                    };
                }
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(2))
                }
                Ok(None) => return Err("fixture: normal whole-group reap timed out".into()),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(format!("fixture: reap failed: {e}")),
            }
        }
    }
}

fn d4_zombie_open_at(
    directory: &std::os::fd::OwnedFd,
    name: &std::ffi::CStr,
) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    // SAFETY: held fixture directory and internally selected relative name.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: new descriptor, adopted once.
        Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
    }
}

/// Test observation only: no production member authority or selector is minted.
/// All post-exit reads are relative to directories opened while the leader lives.
struct D4ZombieObservation {
    original: std::sync::Arc<crate::process::PidPin>,
    leader: std::os::fd::OwnedFd,
    tasks: std::os::fd::OwnedFd,
    member: std::os::fd::OwnedFd,
    member_birth: u64,
    full_member: Option<std::os::fd::OwnedFd>,
}

impl D4ZombieObservation {
    fn acquire(ready: &D4ZombieReady) -> Self {
        use std::os::unix::fs::OpenOptionsExt as _;
        let original =
            std::sync::Arc::new(crate::process::PidPin::open(ready.mapping.tgid).unwrap());
        original
            .pidfd()
            .expect("fixture: original group pidfd required");
        original
            .start_time()
            .expect("fixture: original birth required");
        assert_eq!(original.original_exited(), Ok(false));
        let leader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(format!("/proc/{}", ready.mapping.tgid))
            .unwrap()
            .into();
        let tasks = d4_zombie_open_at(&leader, c"task").unwrap();
        let name = std::ffi::CString::new(ready.mapping.tid.to_string()).unwrap();
        let member = d4_zombie_open_at(&tasks, &name).unwrap();
        let mut result = Self {
            original,
            leader,
            tasks,
            member,
            member_birth: 0,
            full_member: None,
        };
        result.member_birth = result.stat(&result.member).unwrap().birth;
        // The nested task directory proves original-group membership but
        // uses tid_base_stuff, which lacks map_files. A direct /proc/TID
        // directory uses tgid_base_stuff even for a nonleader. Its numeric
        // path is only a candidate lookup, never independent authority.
        // Acquire it while the owned raw worker cannot exec/exit before Q,
        // bracketed by validation of the original group and held member.
        result.validate(ready);
        assert!(
            matches!(
                result.stat(&result.leader).unwrap().state,
                b'R' | b'S' | b'D'
            ),
            "fixture: full member view must be acquired before leader retirement"
        );
        let candidate = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(format!("/proc/{}", ready.mapping.tid))
            .expect("fixture: pre-exit candidate full member directory");
        result.validate(ready);
        assert!(
            matches!(
                result.stat(&result.leader).unwrap().state,
                b'R' | b'S' | b'D'
            ),
            "fixture: leader retired during full-view acquisition"
        );
        result.full_member = Some(candidate.into());
        result.validate(ready);
        // Relative task/<TGID> traverses proc_task_lookup's actual
        // same_thread_group gate from the candidate's retained task.
        // Bind that round trip to the still-held original leader/birth.
        let candidate_tasks = d4_zombie_open_at(result.full_member(), c"task")
            .expect("fixture: full member view task directory");
        let leader_name = std::ffi::CString::new(ready.mapping.tgid.to_string()).unwrap();
        let same_group_leader = d4_zombie_open_at(&candidate_tasks, &leader_name)
            .expect("fixture: full-view task/original-TGID same-group round trip");
        let round_trip = result.stat(&same_group_leader).unwrap();
        let original_leader = result.stat(&result.leader).unwrap();
        assert_eq!(
            (round_trip.tid, round_trip.birth),
            (original_leader.tid, original_leader.birth),
            "fixture: full-view original leader binding"
        );
        assert_eq!(
            (round_trip.tid, Some(round_trip.birth)),
            (ready.mapping.tgid, result.original.start_time())
        );
        result.validate(ready);
        result
    }

    fn full_member(&self) -> &std::os::fd::OwnedFd {
        self.full_member
            .as_ref()
            .expect("fixture: validated pre-exit full member view required")
    }

    fn stat(&self, dir: &std::os::fd::OwnedFd) -> std::io::Result<D4ZombieTask> {
        use std::io::Read as _;
        let file = std::fs::File::from(d4_zombie_open_at(dir, c"stat")?);
        let mut text = String::new();
        file.take(65536).read_to_string(&mut text)?;
        if text.len() >= 65536 {
            return Err(std::io::Error::other("fixture: oversized stat"));
        }
        d4_zombie_stat(&text).map_err(std::io::Error::other)
    }

    fn tasks(&self) -> std::io::Result<Vec<D4ZombieTask>> {
        use std::os::fd::AsRawFd as _;
        // This fd alias is the retained directory, never a fresh /proc/TGID walk.
        let mut tasks = Vec::new();
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", self.tasks.as_raw_fd()))? {
            let name = entry?.file_name();
            let name =
                std::ffi::CString::new(name.as_encoded_bytes()).map_err(std::io::Error::other)?;
            tasks.push(self.stat(&d4_zombie_open_at(&self.tasks, &name)?)?);
        }
        tasks.sort_by_key(|task| task.tid);
        Ok(tasks)
    }

    fn status(&self, directory: &std::os::fd::OwnedFd) -> String {
        use std::io::Read as _;
        let mut text = String::new();
        std::fs::File::from(
            d4_zombie_open_at(directory, c"status").expect("fixture: retained task status"),
        )
        .take(65536)
        .read_to_string(&mut text)
        .unwrap();
        assert!(text.len() < 65536, "fixture: oversized task status");
        text
    }

    fn retirement_ready(&self, ready: &D4ZombieReady) {
        let name = std::ffi::CString::new(ready.creator.to_string()).unwrap();
        let creator =
            d4_zombie_open_at(&self.tasks, &name).expect("fixture: actual creator directory");
        for directory in [&self.leader, &creator] {
            let status = self.status(directory);
            let mask = status
                .lines()
                .find_map(|line| line.strip_prefix("SigBlk:"))
                .expect("fixture: actual retirement signal mask")
                .trim();
            let mask = u64::from_str_radix(mask, 16).unwrap();
            assert_eq!(
                mask & (1 << (libc::SIGUSR1 - 1)),
                0,
                "fixture: targeted retirement signal must be unblocked"
            );
        }
    }

    fn validate(&self, ready: &D4ZombieReady) {
        assert_eq!(
            self.original.original_exited(),
            Ok(false),
            "fixture: whole group must live"
        );
        assert!(self.original.still_the_same());
        let leader = self
            .stat(&self.leader)
            .expect("fixture: retained original leader stat");
        assert_eq!(
            (leader.tid, Some(leader.birth)),
            (ready.mapping.tgid, self.original.start_time())
        );
        // Both descriptors pin the original task's struct pid. Neither is
        // reopened after retirement, so member death/exec PID exchange
        // cannot substitute a fresh task by its equal numeric TID.
        for directory in std::iter::once(&self.member).chain(self.full_member.iter()) {
            let member = self
                .stat(directory)
                .expect("fixture: retained live member stat");
            assert_eq!(
                (member.tid, member.birth),
                (ready.mapping.tid, self.member_birth)
            );
            assert!(
                matches!(member.state, b'R' | b'S' | b'D'),
                "fixture: retained member must stay live"
            );
            let status = self.status(directory);
            for (field, expected) in [("Tgid:", ready.mapping.tgid), ("Pid:", ready.mapping.tid)] {
                let actual = status
                    .lines()
                    .find_map(|line| line.strip_prefix(field))
                    .expect("fixture: actual member status identity")
                    .trim()
                    .parse::<u32>()
                    .unwrap();
                assert_eq!(actual, expected, "fixture: actual member {field}");
            }
        }
    }

    fn maps(&self, ready: &D4ZombieReady) -> Vec<MapEntry> {
        self.validate(ready);
        let snapshot = crate::discovery::scan::read_maps_or_refuse(
            std::fs::File::from(
                d4_zombie_open_at(self.full_member(), c"maps")
                    .expect("fixture: retained full member maps"),
            ),
            &mut CaptureWorkBudget::default(),
            crate::attach::monotonic_ns,
        )
        .expect("fixture: fresh full member maps");
        self.validate(ready);
        snapshot
    }

    fn identity(&self, ready: &D4ZombieReady, name: &str) -> FileIdentity {
        use std::os::fd::AsRawFd as _;
        self.validate(ready);
        let name = std::ffi::CString::new(name).unwrap();
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: live retained directory, internal fd/range name; follow its
        // proc link to obtain actual vm_file/open-file metadata, not a pathname.
        assert_eq!(
            unsafe {
                libc::fstatat(
                    self.full_member().as_raw_fd(),
                    name.as_ptr(),
                    stat.as_mut_ptr(),
                    0,
                )
            },
            0,
            "fixture: retained full member identity {:?}: {}",
            name,
            std::io::Error::last_os_error()
        );
        // SAFETY: successful fstatat initialized stat.
        let stat = unsafe { stat.assume_init() };
        self.validate(ready);
        FileIdentity {
            dev: stat.st_dev,
            ino: stat.st_ino,
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[repr(C)]
struct D4ZombieRawArgs {
    path: *const libc::c_char,
    channel: libc::c_int,
    creator: libc::c_int,
    parent_tid: *mut std::sync::atomic::AtomicI32,
    returned_tid: std::sync::atomic::AtomicI32,
    start: std::sync::atomic::AtomicU32,
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
const D4_ZOMBIE_FRAME_SIZE: usize =
    (D4_CLONE_WORKER_WIRE_OFFSET + D4_ZOMBIE_REPLY_LEN + 1 + 15) & !15;

/// Only the owned helper installs this handler. A targeted signal retires
/// one thread without running Rust destructors or terminating the group.
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[unsafe(naked)]
extern "C" fn d4_zombie_thread_exit(_signal: libc::c_int) {
    core::arch::naked_asm!(
        "xor edi, edi",
        "mov eax, {sys_exit}",
        "syscall",
        "ud2",
        sys_exit = const libc::SYS_exit,
    );
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[unsafe(naked)]
extern "C" fn d4_zombie_creator_park() -> ! {
    core::arch::naked_asm!(
        "2:",
        "mov eax, {sys_pause}",
        "syscall",
        "jmp 2b",
        sys_pause = const libc::SYS_pause,
    );
}

/// Separate from the qualified clone worker: this leaf owns the external
/// protocol after retiring BOTH the TGID leader and libtest controller.
/// No Rust/libc/TLS, allocator, unwinding, or exit_group runs in this path.
/// Published storage is never reclaimed while any group member lives.
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[unsafe(naked)]
extern "C" fn d4_zombie_single_survivor_worker(_context: *mut libc::c_void) -> libc::c_int {
    core::arch::naked_asm!(
        "sub rsp, {frame}",
        "mov rbx, rdi",
        "mov r12d, dword ptr [rbx + {args_channel}]",
        // Release/acquire publication on x86-64: no child reads the return
        // or parent-written TID before the normal creator opens this gate.
        "2:",
        "cmp dword ptr [rbx + {args_start}], 1",
        "je 3f",
        "pause",
        "jmp 2b",
        "3:",
        "mov eax, {magic}",
        "mov qword ptr [rsp + {wire}], rax",
        "mov eax, {sys_getpid}",
        "syscall",
        "mov qword ptr [rsp + {wire} + 8], rax",
        "mov eax, {sys_gettid}",
        "syscall",
        "mov qword ptr [rsp + {wire} + 16], rax",
        "mov eax, dword ptr [rbx + {args_creator}]",
        "mov qword ptr [rsp + {wire} + 64], rax",
        "mov eax, dword ptr [rbx + {args_returned}]",
        "mov qword ptr [rsp + {wire} + 72], rax",
        "mov rax, qword ptr [rbx + {args_parent}]",
        "mov eax, dword ptr [rax]",
        "mov qword ptr [rsp + {wire} + 80], rax",
        "mov eax, {sys_openat}",
        "mov rdi, {at_fdcwd}",
        "mov rsi, qword ptr [rbx + {args_path}]",
        "mov edx, {open_flags}",
        "xor r10d, r10d",
        "syscall",
        "test rax, rax",
        "js 9f",
        "mov r13, rax",
        "mov qword ptr [rsp + {wire} + 24], rax",
        "mov eax, {sys_fstat}",
        "mov edi, r13d",
        "mov rsi, rsp",
        "syscall",
        "test rax, rax",
        "jnz 9f",
        "mov rax, qword ptr [rsp + {stat_dev}]",
        "mov qword ptr [rsp + {wire} + 48], rax",
        "mov rax, qword ptr [rsp + {stat_ino}]",
        "mov qword ptr [rsp + {wire} + 56], rax",
        "mov eax, {sys_mmap}",
        "xor edi, edi",
        "mov esi, 4096",
        "mov edx, {prot}",
        "mov r10d, {map_private}",
        "mov r8, r13",
        "xor r9d, r9d",
        "syscall",
        "test rax, rax",
        "js 9f",
        "mov r14, rax",
        "mov qword ptr [rsp + {wire} + 32], rax",
        "add rax, 4096",
        "mov qword ptr [rsp + {wire} + 40], rax",
        "lea rbp, [rsp + {wire}]",
        "mov r15d, {reply_len}",
        "4:",
        "mov eax, {sys_write}",
        "mov edi, r12d",
        "mov rsi, rbp",
        "mov rdx, r15",
        "syscall",
        "cmp rax, -{eintr}",
        "je 4b",
        "test rax, rax",
        "jle 9f",
        "cmp rax, r15",
        "ja 9f",
        "add rbp, rax",
        "sub r15, rax",
        "jnz 4b",
        // R15 is now zero: no normal helper threads have retired yet.
        "5:",
        "mov eax, {sys_read}",
        "mov edi, r12d",
        "lea rsi, [rsp + {wire} + {reply_len}]",
        "mov edx, 1",
        "syscall",
        "cmp rax, -{eintr}",
        "je 5b",
        "cmp rax, 1",
        "jne 9f",
        "cmp byte ptr [rsp + {wire} + {reply_len}], 90",
        "je 6f",
        "cmp byte ptr [rsp + {wire} + {reply_len}], 81",
        "jne 9f",
        "6:",
        "test r15d, r15d",
        "jnz 7f",
        // These are actual kernel TGID/creator TIDs from this owned group.
        "mov eax, {sys_tgkill}",
        "mov edi, dword ptr [rsp + {wire} + 8]",
        "mov esi, edi",
        "mov edx, {retire_signal}",
        "syscall",
        "test rax, rax",
        "jnz 9f",
        "mov eax, {sys_tgkill}",
        "mov edi, dword ptr [rsp + {wire} + 8]",
        "mov esi, dword ptr [rbx + {args_creator}]",
        "mov edx, {retire_signal}",
        "syscall",
        "test rax, rax",
        "jnz 9f",
        "mov r15d, 1",
        "7:",
        "cmp byte ptr [rsp + {wire} + {reply_len}], 90",
        "je 8f",
        "mov eax, {sys_munmap}",
        "mov rdi, r14",
        "mov esi, 4096",
        "syscall",
        "test rax, rax",
        "jnz 9f",
        "mov eax, {sys_close}",
        "mov edi, r13d",
        "syscall",
        "test rax, rax",
        "jnz 9f",
        "mov byte ptr [rsp + {wire} + {reply_len}], 68",
        "8:",
        "mov eax, {sys_write}",
        "mov edi, r12d",
        "lea rsi, [rsp + {wire} + {reply_len}]",
        "mov edx, 1",
        "syscall",
        "cmp rax, -{eintr}",
        "je 8b",
        "cmp rax, 1",
        "jne 9f",
        "cmp byte ptr [rsp + {wire} + {reply_len}], 90",
        "je 5b",
        "xor edi, edi",
        "mov eax, {sys_exit}",
        "syscall",
        "ud2",
        "9:",
        "mov edi, 91",
        "mov eax, {sys_exit}",
        "syscall",
        "ud2",
        frame = const D4_ZOMBIE_FRAME_SIZE,
        wire = const D4_CLONE_WORKER_WIRE_OFFSET,
        reply_len = const D4_ZOMBIE_REPLY_LEN,
        args_path = const std::mem::offset_of!(D4ZombieRawArgs, path),
        args_channel = const std::mem::offset_of!(D4ZombieRawArgs, channel),
        args_creator = const std::mem::offset_of!(D4ZombieRawArgs, creator),
        args_parent = const std::mem::offset_of!(D4ZombieRawArgs, parent_tid),
        args_returned = const std::mem::offset_of!(D4ZombieRawArgs, returned_tid),
        args_start = const std::mem::offset_of!(D4ZombieRawArgs, start),
        stat_dev = const std::mem::offset_of!(libc::stat, st_dev),
        stat_ino = const std::mem::offset_of!(libc::stat, st_ino),
        magic = const D4_ZOMBIE_MAGIC,
        eintr = const libc::EINTR,
        at_fdcwd = const libc::AT_FDCWD,
        open_flags = const libc::O_RDONLY | libc::O_CLOEXEC,
        prot = const libc::PROT_READ | libc::PROT_EXEC,
        map_private = const libc::MAP_PRIVATE,
        retire_signal = const libc::SIGUSR1,
        sys_getpid = const libc::SYS_getpid,
        sys_gettid = const libc::SYS_gettid,
        sys_openat = const libc::SYS_openat,
        sys_fstat = const libc::SYS_fstat,
        sys_mmap = const libc::SYS_mmap,
        sys_write = const libc::SYS_write,
        sys_read = const libc::SYS_read,
        sys_tgkill = const libc::SYS_tgkill,
        sys_munmap = const libc::SYS_munmap,
        sys_close = const libc::SYS_close,
        sys_exit = const libc::SYS_exit,
    );
}

/// Once published, these allocations are never reclaimed in this helper.
/// The creator and leader exit without unwinding. The shared mm keeps the
/// storage live through the last worker's exit; the outer owned process
/// guard then reaps the whole group before claiming cleanup.
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
struct D4ZombieRawStorage {
    stack: *mut libc::c_void,
    stack_len: usize,
    path: *mut libc::c_char,
    args: *mut D4ZombieRawArgs,
    tid: *mut std::sync::atomic::AtomicI32,
    worker: libc::c_int,
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
impl D4ZombieRawStorage {
    fn publish(path: std::ffi::CString, channel: libc::c_int) -> ! {
        use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
        // SAFETY: all libc/TLS use is confined to the normal creator.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(page > 0);
        let page = page as usize;
        let stack_size = 1024 * 1024;
        let stack_len = stack_size + 2 * page;
        let stack = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                stack_len,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(
            stack,
            libc::MAP_FAILED,
            "fixture: owned zombie-worker stack"
        );
        let path = path.into_raw();
        let tid = Box::into_raw(Box::new(AtomicI32::new(-1)));
        let args = Box::into_raw(Box::new(D4ZombieRawArgs {
            path,
            channel,
            creator: unsafe { libc::syscall(libc::SYS_gettid) } as libc::c_int,
            parent_tid: tid,
            returned_tid: AtomicI32::new(-1),
            start: AtomicU32::new(0),
        }));
        let mut owned = Self {
            stack,
            stack_len,
            path,
            args,
            tid,
            worker: 0,
        };
        // SAFETY: only the middle of this owned mapping becomes writable.
        let stack_start = unsafe { stack.cast::<u8>().add(page) };
        assert_eq!(
            unsafe {
                libc::mprotect(
                    stack_start.cast(),
                    stack_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            },
            0
        );
        // SAFETY: ordinary-parent trampoline; the callback is entirely raw
        // assembly. The newborn cannot pass its start gate until publication.
        owned.worker = unsafe {
            libc::clone(
                d4_zombie_single_survivor_worker,
                stack_start.add(stack_size).cast(),
                D4_CLONE_WITHOUT_FILES_FLAGS,
                args.cast(),
                (*tid).as_ptr(),
                std::ptr::null_mut::<libc::c_void>(),
                (*tid).as_ptr(),
            )
        };
        assert!(
            owned.worker > 0,
            "fixture: literal zombie-worker clone: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            unsafe { (*tid).load(Ordering::Acquire) },
            owned.worker,
            "fixture: kernel parent-TID write"
        );
        // SAFETY: these raw allocations were published once, stay live to
        // whole-group exit, and are only accessed atomically after clone.
        unsafe {
            (*args).returned_tid.store(owned.worker, Ordering::Relaxed);
            (*args).start.store(1, Ordering::Release);
        }
        std::mem::forget(owned);
        d4_zombie_creator_park()
    }
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
impl Drop for D4ZombieRawStorage {
    fn drop(&mut self) {
        if self.worker > 0 {
            // A failure must terminate this owned helper before any live
            // newborn's stack/context/path can unwind or be reclaimed.
            unsafe { libc::_exit(105) };
        }
        // SAFETY: clone did not create a worker. Successful publication
        // forgets this guard and relies on outer whole-group reap instead.
        unsafe {
            libc::munmap(self.stack, self.stack_len);
            drop(std::ffi::CString::from_raw(self.path));
            drop(Box::from_raw(self.args));
            drop(Box::from_raw(self.tid));
        }
    }
}

/// Private helper never completes as a standalone libtest qualification.
/// It needs its owning socket/path; normal completion comes from the last
/// raw worker's SYS_exit after the original leader/controller have retired.
#[test]
#[ignore = "private D4 zombie fixture entrypoint; requires owning socket and source configuration"]
fn d4_zombie_single_survivor_mapping_helper() {
    #[cfg(not(all(target_arch = "x86_64", target_pointer_width = "64")))]
    panic!("the actual zombie fixture requires the x86-64 LP64 syscall ABI");
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    {
        use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
        let path =
            std::env::var_os("P11SCOPE_D4_ZOMBIE_PATH").expect("fixture: owned zombie source");
        let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: fresh-exec helper only; stdin must be its owning Unix socket.
        let raw = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3) };
        assert!(raw >= 0);
        let socket = std::os::unix::net::UnixStream::from(unsafe { OwnedFd::from_raw_fd(raw) });
        socket
            .peer_addr()
            .expect("fixture: connected owning socket required");
        // SAFETY: only the owned fresh helper changes its process-wide
        // disposition. The naked handler does a thread-only syscall exit.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = d4_zombie_thread_exit as *const () as usize;
        assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()) },
            0
        );
        // No return or Rust cleanup after publication; the socket and all
        // raw allocations remain live until the outer process guard reaps.
        D4ZombieRawStorage::publish(path, socket.as_raw_fd());
    }
}

/// Existing-API required-positive regression, NOT a qualified zombie port.
/// The post-exit semantic assertions deliberately remain required positives:
/// today's zombie/leader-only refusals do not satisfy the selected population.
/// Both real backends are attempted and the owned helper is normally reaped
/// BEFORE those assertions, even when either backend panics internally.
#[test]
#[ignore = "root x86-64 LP64 Btrfs disk TMPDIR and eligible BTF/task_vma; required zombie-leader positive baseline"]
fn privileged_d4_btrfs_zombie_leader_single_survivor_backend_parity() {
    use crate::discovery::identity::{PinnedObjects, test_fixture::real_scan_pin};
    use crate::discovery::kernel_identity::IdentitySession;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::{FileExt as _, MetadataExt as _};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    assert!(
        cfg!(all(target_arch = "x86_64", target_pointer_width = "64")),
        "fixture: actual zombie survivor requires x86-64 LP64"
    );
    crate::attach::identity_iter::ensure_kernel_identity_btf()
        .expect("fixture: required kernel identity capability; refusal cannot qualify");
    let btf = aya::Btf::from_sys_fs().expect("fixture: readable host BTF");
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path();
    let raw_parent = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes()).unwrap();
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: valid owned directory name and output buffer.
    assert_eq!(
        unsafe { libc::statfs(raw_parent.as_ptr(), stat.as_mut_ptr()) },
        0
    );
    // SAFETY: successful statfs initialized the output.
    assert_eq!(
        unsafe { stat.assume_init().f_type } as u64 & 0xffff_ffff,
        0x9123_683e,
        "fixture: actual disk TMPDIR must be Btrfs"
    );
    create_subvolume(parent, "a");
    let path = parent.join("a/libzombie.so");
    let bytes = vec![0x5cu8; 8192];
    std::fs::write(&path, &bytes).unwrap();
    let held = std::fs::File::open(&path).unwrap();
    let identity = |file: &std::fs::File| {
        let metadata = file.metadata().unwrap();
        FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    };
    let physical = identity(&held);
    let (mut child, ready) = D4ZombieChild::spawn(&path);
    let observation = D4ZombieObservation::acquire(&ready);
    let original_birth = observation
        .original
        .start_time()
        .expect("fixture: retained original birth");
    let pid = ready.mapping.tgid;
    let worker = ready.mapping.tid;
    let creator = ready.creator;
    let digest = p11scope_manifest::identity::hex(&Sha256::digest(&bytes));
    let before_maps = observation.maps(&ready);
    let before_line = before_maps
        .iter()
        .find(|entry| (entry.start, entry.end) == (ready.mapping.start, ready.mapping.end))
        .expect("fixture: actual worker executable VMA")
        .clone();
    let key = ObjectKey::of(&before_line);
    let pins: PinnedObjects = real_scan_pin(&path, Some(key), 0, &digest);
    let object = pins.pinned().next().expect("fixture: actual held-A pin").id;
    let (index, refused) = KnownKeyIndex::build(
        [(key, Some(object))],
        &BTreeMap::from([(key, object)]),
        [],
        &pins,
    );
    assert!(refused.is_empty(), "fixture: {refused:?}");
    assert!(
        index.map_files_keys().contains(&key),
        "fixture: actual Btrfs range proof required"
    );
    let probe_dir = tempfile::tempdir().unwrap();
    let mut session = IdentitySession::probe_and_load(&btf, probe_dir.path())
        .expect("fixture: actual strict kernel session; no fallback positive");

    // Fixture checks are separate from the required attribution positives.
    // Catch them too so a failed observation can still release the owned
    // group normally. Q retires the controller even if Z was never sent.
    let outcomes = catch_unwind(AssertUnwindSafe(|| {
        d4_zombie_task_set(
            &observation.tasks().expect("fixture: before task set"),
            &ready,
            false,
        )
        .expect("fixture: exactly leader/controller/raw worker before exit");
        observation.retirement_ready(&ready);
        let verify_mapping = |snapshot: &[MapEntry]| {
            observation.validate(&ready);
            assert_eq!(
                (ready.mapping.dev, ready.mapping.ino),
                (physical.dev, physical.ino),
                "fixture: actual worker fstat matches held file"
            );
            assert_eq!(
                observation.identity(&ready, &format!("fd/{}", ready.mapping.fd)),
                physical,
                "fixture: actual live-member FD names held A"
            );
            assert_eq!(
                observation.identity(
                    &ready,
                    &format!(
                        "map_files/{:x}-{:x}",
                        ready.mapping.start, ready.mapping.end
                    )
                ),
                physical,
                "fixture: actual live-member vm_file names held A"
            );
            let lines: Vec<_> = snapshot
                .iter()
                .filter(|entry| ObjectKey::of(entry) == key)
                .collect();
            assert_eq!(
                lines,
                [&before_line],
                "fixture: exact held VMA remains unchanged"
            );
            assert_eq!(before_line.permissions, *b"r-xp");
            assert_eq!(before_line.file_offset, 0);
            assert_eq!(
                before_line.raw_path.as_deref(),
                Some(path.as_os_str().as_encoded_bytes())
            );
            assert!(is_caller_range(&before_line));
            assert_eq!(
                proof_ranges(snapshot, &index.map_files_keys()),
                [(ready.mapping.start, ready.mapping.end)],
                "fixture: one exact actual proof range"
            );
            assert_eq!(identity(&held), physical);
            assert_eq!(identity(pins.file_for(object).unwrap()), physical);
            assert!(
                pins.object_unchanged(object)
                    .expect("fixture: actual held anchor unchanged")
            );
            let mut actual_bytes = vec![0; bytes.len()];
            held.read_exact_at(&mut actual_bytes, 0).unwrap();
            assert_eq!(actual_bytes, bytes, "fixture: held A bytes remain stable");
        };
        verify_mapping(&before_maps);
        let before_userspace = catch_unwind(AssertUnwindSafe(|| {
            attribute_pid(pid, before_maps.clone(), &index)
        }));
        let before_kernel = catch_unwind(AssertUnwindSafe(|| {
            d4_kernel_attribution_for_pid(
                pid,
                before_maps.clone(),
                &pins,
                object,
                key,
                &mut session,
                1,
            )
        }));
        child.zombify();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let after_tasks = loop {
            match observation.tasks() {
                Ok(tasks) if d4_zombie_task_set(&tasks, &ready, true).is_ok() => break tasks,
                Ok(tasks) => assert!(
                    std::time::Instant::now() < deadline,
                    "fixture: retirement never reached exactly one live survivor: {tasks:?}"
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "fixture: retiring controller enumeration did not settle: {error}"
                    );
                }
                Err(error) => panic!("fixture: retained task enumeration failed: {error}"),
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        };
        // The retained MEMBER's maps are opened anew AFTER the zombie
        // barrier. No leader maps path or saved snapshot substitutes for it.
        let after_maps = observation.maps(&ready);
        verify_mapping(&after_maps);
        eprintln!(
            "D4_ZOMBIE_TRUTH caller={pid} worker={worker} retired_controller={creator} tasks={after_tasks:?} original_birth={original_birth:?} group_pidfd_ready=false fd={} range={:x}-{:x} file={}:{} clone_return={} parent_tid={}",
            ready.mapping.fd,
            ready.mapping.start,
            ready.mapping.end,
            physical.dev,
            physical.ino,
            ready.returned_tid,
            ready.parent_tid
        );
        let after_userspace = catch_unwind(AssertUnwindSafe(|| {
            attribute_pid(pid, after_maps.clone(), &index)
        }));
        let after_kernel = catch_unwind(AssertUnwindSafe(|| {
            d4_kernel_attribution_for_pid(pid, after_maps, &pins, object, key, &mut session, 2)
        }));
        // Both backend calls above have happened before any positive check.
        verify_mapping(&observation.maps(&ready));
        d4_zombie_task_set(
            &observation
                .tasks()
                .expect("fixture: final retained task set"),
            &ready,
            true,
        )
        .expect("fixture: sole survivor stays live through both proofs");
        (
            before_userspace,
            before_kernel,
            after_userspace,
            after_kernel,
        )
    }));
    let cleanup = child.finish();
    // On a fixture failure the owned guard also kills/reaps, but that is
    // distinct from this normal release/reap required by semantic baseline.
    cleanup.expect("fixture: normal whole-group release/reap required before semantic assertions");
    assert_eq!(
        observation.original.original_exited(),
        Ok(true),
        "fixture: original group exited"
    );
    assert!(!observation.original.still_the_same());
    for id in [pid, worker, creator] {
        assert!(
            !std::path::Path::new(&format!("/proc/{id}")).exists(),
            "fixture: owned task {id} gone"
        );
    }
    drop((observation, session, pins, held));
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(parent.join("a")).unwrap();
    probe_dir
        .close()
        .expect("fixture: remove owned kernel probe directory");
    dir.close()
        .expect("fixture: remove owned Btrfs zombie directory");
    eprintln!(
        "D4_ZOMBIE_CLEANUP caller={pid} worker={worker} controller={creator} normal_release=true whole_group_reaped=true owned_files_removed=true"
    );
    let (before_userspace, before_kernel, after_userspace, after_kernel) =
        outcomes.unwrap_or_else(|failure| std::panic::resume_unwind(failure));
    for (label, result) in [
        ("before/userspace", &before_userspace),
        ("before/kernel", &before_kernel),
        ("zombie/userspace", &after_userspace),
        ("zombie/kernel", &after_kernel),
    ] {
        match result {
            Ok(out) => eprintln!(
                "D4_ZOMBIE_RESULT {label} members={} probed={} unavailable={} exited={:?} losses={:?}",
                out.members.len(),
                out.probed,
                out.unavailable,
                out.exited,
                out.losses
            ),
            Err(_) => eprintln!("D4_ZOMBIE_RESULT {label} backend_panicked=true"),
        }
    }
    let before_userspace = before_userspace.expect("fixture/backend: before userspace panic");
    let before_kernel = before_kernel.expect("fixture/backend: before kernel panic");
    let after_userspace = after_userspace.expect("fixture/backend: zombie userspace panic");
    let after_kernel = after_kernel.expect("fixture/backend: zombie kernel panic");
    for (phase, userspace, kernel) in [
        ("leader live", &before_userspace, &before_kernel),
        (
            "leader zombie / sole live worker",
            &after_userspace,
            &after_kernel,
        ),
    ] {
        for (backend, out) in [("userspace", userspace), ("kernel", kernel)] {
            assert_eq!(
                out.members
                    .iter()
                    .map(|member| member.pid)
                    .collect::<Vec<_>>(),
                [pid],
                "required positive: {phase}/{backend} must attribute original TGID's held A; current refusal is a regression, not qualification"
            );
            assert_eq!(out.members[0].start_time, original_birth);
            assert_eq!(
                out.members[0]
                    .objects
                    .iter()
                    .map(|matched| (matched.key, matched.object, matched.path.as_str()))
                    .collect::<Vec<_>>(),
                [(key, object, path.to_str().unwrap())]
            );
            assert_eq!(out.probed, 1);
            assert_eq!(out.unavailable, 0);
            assert!(
                out.exited.is_empty(),
                "required live group: {phase}/{backend}"
            );
            assert!(out.losses.is_empty(), "{phase}/{backend}: {:?}", out.losses);
        }
        assert_eq!(
            userspace.members, kernel.members,
            "independently required {phase} edges"
        );
    }
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

#[test]
fn a_caller_range_is_any_executable_shared_object_mapping() {
    for perms in [b"r-xp", b"--xp", b"rwxp", b"r-xs"] {
        assert!(
            is_caller_range(&mapping(0x1000, perms, PROVIDER, "/usr/lib/p.so")),
            "{} must be a caller range",
            String::from_utf8_lossy(perms)
        );
    }
    for perms in [b"r--p", b"rw-p", b"---p", b"r--s"] {
        assert!(
            !is_caller_range(&mapping(0x1000, perms, PROVIDER, "/usr/lib/p.so")),
            "{} must not be a caller range",
            String::from_utf8_lossy(perms)
        );
    }
    assert!(
        !is_caller_range(&mapping(0x1000, b"r-xp", PROVIDER, "/usr/bin/tool")),
        "an executable non-shared-object mapping is not a provider caller range"
    );
}

// The production confirmation functions run against normally returning proof
// reads. This fixture cancels after the first read, with another range/member
// queued; it does not claim to interrupt an in-flight kernel operation.
struct CgroupProofProbe {
    inner: CountingProbe,
    control: crate::scope::inventory_cgroup::CollectionControl,
    cancel_first: bool,
    opens: RefCell<Vec<u32>>,
}
struct CgroupProofIo<'a> {
    inner: CountingIo<'a>,
    control: &'a crate::scope::inventory_cgroup::CollectionControl,
    cancel_first: bool,
    opens: &'a RefCell<Vec<u32>>,
}
impl CgroupProofProbe {
    fn new(sweep: &[(u32, Vec<MapEntry>)], cancel_first: bool) -> Self {
        Self {
            inner: CountingProbe::over(sweep),
            control: crate::scope::inventory_cgroup::CollectionControl::new(None),
            cancel_first,
            opens: RefCell::new(Vec::new()),
        }
    }
    fn io(&self, pid: u32) -> CgroupProofIo<'_> {
        CgroupProofIo {
            inner: self.inner.io(pid),
            control: &self.control,
            cancel_first: self.cancel_first,
            opens: &self.opens,
        }
    }
    fn budget(&self) -> CaptureWorkBudget {
        let control = self.control.clone();
        let mut budget = CaptureWorkBudget::default();
        budget.set_collection_work(crate::discovery::scan::CollectionWork::new(move |_| {
            control.check().is_ok()
        }));
        budget
    }
}
impl ConfirmIo for CgroupProofIo<'_> {
    type Pin = u64;
    fn mapped_file(&mut self, pid: u32, start: u64, end: u64) -> Result<FileIdentity, String> {
        let answer = self.inner.mapped_file(pid, start, end);
        if self.cancel_first && self.inner.reads.borrow().len() == 1 {
            self.control.cancel();
        }
        answer
    }
    fn open(&mut self, pid: u32) -> Result<u64, String> {
        self.opens.borrow_mut().push(pid);
        self.inner.open(pid)
    }
    fn start_time(&self, pin: &u64) -> Option<u64> {
        self.inner.start_time(pin)
    }
    fn still_the_same(&self, pin: &u64) -> bool {
        self.inner.still_the_same(pin)
    }
    fn exe(&self, pid: u32) -> Option<ExeIdentity> {
        self.inner.exe(pid)
    }
    fn maps(&mut self, pid: u32, budget: &mut CaptureWorkBudget) -> Result<Vec<MapEntry>, String> {
        self.inner.maps(pid, budget)
    }
    fn gone(&self, pid: u32) -> bool {
        self.inner.gone(pid)
    }
}
impl MemberProbe for CgroupProofProbe {
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

#[test]
fn cgroup_review_confirmation_stop_prevents_next_range_and_member() {
    let sweep = vec![(10_001, caller5()), (10_002, caller5())];
    let index = caller5_index();
    assert_eq!(
        proof_ranges(&caller5(), &index.map_files_keys()).len(),
        2,
        "the fixture has two independent proof ranges"
    );
    let mut probe = CgroupProofProbe::new(&sweep, true);
    let mut budget = probe.budget();
    let attribution = attribute_unselected(
        &sweep,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &index,
        &mut probe,
        &mut budget,
    );
    assert_eq!(
        probe.inner.reads.borrow().len(),
        1,
        "a returning first proof read cancels before the next range"
    );
    assert_eq!(
        *probe.opens.borrow(),
        vec![10_001],
        "the next member cannot open a generation after cancellation"
    );
    assert!(attribution.members.is_empty());
    assert!(budget.stopped_reason().is_some());
}

#[test]
fn cgroup_review_unpinned_stop_prevents_next_range() {
    let sweep = vec![(10_001, caller5())];
    let probe = CgroupProofProbe::new(&sweep, true);
    let mut budget = probe.budget();
    let answers = stat_unpinned(
        &mut probe.io(10_001),
        10_001,
        &[PROVIDER_TEXT, LIBC_TEXT],
        &mut budget,
    );
    assert_eq!(
        probe.inner.reads.borrow().len(),
        1,
        "precharged ranges cannot drain after cancellation"
    );
    assert_eq!(answers.len(), 1, "the unread suffix remains unproven");
    assert!(budget.stopped_reason().is_some());
}

#[test]
fn cgroup_review_confirmation_without_stop_preserves_both_members() {
    let sweep = vec![(10_001, caller5()), (10_002, caller5())];
    let mut probe = CgroupProofProbe::new(&sweep, false);
    let mut budget = probe.budget();
    let attribution = attribute_unselected(
        &sweep,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &caller5_index(),
        &mut probe,
        &mut budget,
    );
    assert_eq!(probe.inner.reads.borrow().len(), 4);
    assert_eq!(*probe.opens.borrow(), vec![10_001, 10_002]);
    assert_eq!(attribution.members.len(), 2);
    assert!(budget.stopped_reason().is_none());
}

/// Reconciliation must keep each normally returning operation behind the
/// scoped collector's cancellation fence, including the live finish checks.
struct CgroupOrderedIo {
    inner: OrderedIo,
    control: crate::scope::inventory_cgroup::CollectionControl,
    stop_after: &'static str,
}

impl CgroupOrderedIo {
    fn returned(&self, operation: &str) {
        if operation == self.stop_after {
            self.control.cancel();
        }
    }
}

impl ConfirmIo for CgroupOrderedIo {
    type Pin = u64;

    fn mapped_file(&mut self, pid: u32, start: u64, end: u64) -> Result<FileIdentity, String> {
        self.mapped_files(pid, &[(start, end)]).remove(0)
    }

    fn mapped_files(
        &mut self,
        pid: u32,
        ranges: &[(u64, u64)],
    ) -> Vec<Result<FileIdentity, String>> {
        let answer = self.inner.mapped_files(pid, ranges);
        self.returned("proof");
        answer
    }

    fn open(&mut self, pid: u32) -> Result<Self::Pin, String> {
        let answer = self.inner.open(pid);
        self.returned("open");
        answer
    }

    fn start_time(&self, pin: &Self::Pin) -> Option<u64> {
        self.inner.record("start_time");
        self.inner.start_time(pin)
    }

    fn still_the_same(&self, pin: &Self::Pin) -> bool {
        let answer = self.inner.still_the_same(pin);
        self.returned("same");
        answer
    }

    fn exe(&self, pid: u32) -> Option<ExeIdentity> {
        let finishing = self.inner.read();
        let answer = self.inner.exe(pid);
        self.returned(if finishing { "after" } else { "before" });
        answer
    }

    fn maps(&mut self, pid: u32, budget: &mut CaptureWorkBudget) -> Result<Vec<MapEntry>, String> {
        let answer = self.inner.maps(pid, budget);
        self.returned("maps");
        answer
    }

    fn gone(&self, pid: u32) -> bool {
        self.inner.gone(pid)
    }
}

#[test]
fn d3a_cgroup_stop_checks_each_confirmation_boundary() {
    let order = [
        "open",
        "exe",
        "maps",
        "mapped_files",
        "exe",
        "still_the_same",
    ];
    for (stop_after, completed) in [
        ("already_stopped", 0),
        ("open", 1),
        ("before", 2),
        ("maps", 3),
        ("proof", 4),
        ("after", 5),
        ("same", 6),
    ] {
        let control = crate::scope::inventory_cgroup::CollectionControl::new(None);
        let checked = control.clone();
        let mut budget = CaptureWorkBudget::default();
        budget.set_collection_work(crate::discovery::scan::CollectionWork::new(move |_| {
            checked.check().is_ok()
        }));
        if completed == 0 {
            control.cancel();
        }
        let mut io = CgroupOrderedIo {
            inner: OrderedIo::new(false),
            control,
            stop_after,
        };
        let policy = SegmentPolicy::from_headroom(3, 4, 1);
        let owner = ReservationOwner::new(policy);
        let resources = owner.immediate();
        let confirmation = confirm_with_resources(
            &mut io,
            10_001,
            &BTreeSet::from([key(PROVIDER)]),
            &mut budget,
            Some(&resources),
        );
        assert!(
            matches!(confirmation, Confirmation::Lost(AttributionLoss::Budget, _)),
            "stop after {stop_after} published a completed confirmation: {confirmation:?}"
        );
        assert_eq!(
            &*io.inner.calls.borrow(),
            &order[..completed],
            "{stop_after}"
        );
        assert!(budget.stopped_reason().is_some(), "{stop_after}");
        assert_eq!(owner.state_for_test().0, [0; 4], "{stop_after}");
    }
}

/// A zero-request proof must not create a directory FD or depend on access to
/// a process that the operation never needs to inspect.
#[test]
fn d3a_empty_proof_does_not_open_a_directory() {
    let mut io = OsConfirmIo::default();
    assert!(io.mapped_files(std::process::id(), &[]).is_empty());
    assert!(
        io.map_files.is_none(),
        "an empty proof retained an unnecessary directory"
    );
}

/// Catches treating unsupported/missing kernel evidence as a positive, using
/// a numeric file identity as a slot, or accepting only one text range.
#[test]
fn d3a_kernel_proofs_require_complete_slot_expectations() {
    let checks = Checks::default();
    let mut index = provider_index(&checks);
    let mut entries = provider_caller();
    entries.push(mapping(
        0x1000_3000,
        b"r-xp",
        PROVIDER,
        "/usr/lib/softhsm/libsofthsm2.so",
    ));
    let sweep = vec![(10_001, entries.clone())];
    let first = (0x1000_1000, 0x1000_2000);
    let second = (0x1000_3000, 0x1000_4000);
    let libc = (0x2000_1000, 0x2000_2000);
    index
        .set_kernel_slots(key(PROVIDER), BTreeSet::from([Slot(1), Slot(2)]))
        .unwrap();
    index
        .set_kernel_slots(key(LIBC), BTreeSet::from([Slot(3), Slot(4)]))
        .unwrap();
    for (proof, loss) in [
        (
            RangeProof::Kernel(Slot(99)),
            Some(AttributionLoss::IdentityMismatch),
        ),
        (
            RangeProof::KernelNone,
            Some(AttributionLoss::IdentityMismatch),
        ),
        (RangeProof::NotMapped, Some(AttributionLoss::MappingChanged)),
        (
            RangeProof::Unavailable("unvisited requested range".into()),
            Some(AttributionLoss::MapFilesUnavailable),
        ),
        (RangeProof::Kernel(Slot(2)), None),
    ] {
        let mut probe = Probe::over(&sweep);
        probe.mapped.insert(
            10_001,
            MappedIdentities::from([
                (first, RangeProof::Kernel(Slot(1))),
                (second, proof),
                (libc, RangeProof::Kernel(Slot(4))),
            ]),
        );
        let out = run(&sweep, &BTreeSet::new(), &index, &mut probe);
        assert!(
            out.unexamined.is_empty(),
            "validated examined alias must remain examined"
        );
        match loss {
            Some(loss) => {
                assert!(out.members.is_empty());
                assert_eq!(out.member_losses[&10_001].0, loss);
                if loss == AttributionLoss::IdentityMismatch {
                    assert!(!out.member_losses[&10_001].1.contains("st_dev"));
                    assert!(!out.member_losses[&10_001].1.contains("st_ino"));
                }
            }
            None => {
                assert_eq!(
                    out.members
                        .iter()
                        .map(|member| member.pid)
                        .collect::<Vec<_>>(),
                    [10_001]
                );
                assert!(out.losses.is_empty());
            }
        }
    }
    index
        .set_kernel_slots(key(PROVIDER), BTreeSet::new())
        .unwrap();
    let mut probe = Probe::over(&sweep);
    probe.mapped.insert(
        10_001,
        MappedIdentities::from([
            (first, RangeProof::Kernel(Slot(1))),
            (second, RangeProof::Kernel(Slot(1))),
            (libc, RangeProof::Kernel(Slot(4))),
        ]),
    );
    let out = run(&sweep, &BTreeSet::new(), &index, &mut probe);
    assert!(out.members.is_empty());
    assert_eq!(
        out.member_losses[&10_001].0,
        AttributionLoss::IdentityMismatch
    );
}

#[test]
fn d3a_global_reservations_enforce_each_envelope() {
    for (headroom, workers, retained) in [
        (0, 0, 0),
        (3, 0, 0),
        (4, 0, 0),
        (5, 0, 0),
        (6, 1, 1),
        (9, 2, 2),
        (12, 3, 3),
        (64, 4, 53),
    ] {
        let policy = SegmentPolicy::from_headroom(headroom, 4, 100);
        assert_eq!((policy.workers, policy.retained), (workers, retained));
        let owner = ReservationOwner::new(policy);
        let batch = owner.batch();
        let pins: Vec<_> = (0..retained).map(|_| batch.pin().unwrap()).collect();
        assert!(batch.pin().is_err());
        let workers: Vec<_> = (0..workers).map(|_| batch.transient().unwrap()).collect();
        assert!(batch.transient().is_err());
        let immediate = owner.immediate();
        let immediate_pin = immediate.pin();
        let immediate_io = immediate.transient();
        if headroom >= 3 {
            assert!(immediate_pin.is_ok());
            assert!(immediate_io.is_ok());
        } else {
            assert!(immediate_pin.is_err());
            assert!(immediate_io.is_err());
        }
        assert!(immediate.pin().is_err());
        assert!(immediate.transient().is_err());
        assert!(owner.state_for_test().2 <= headroom);
        assert!(owner.state_for_test().3 <= headroom);
        drop((pins, workers, immediate_pin, immediate_io));
        assert_eq!(owner.state_for_test().0, [0; 4]);
    }
    let policy = SegmentPolicy::from_headroom(usize::MAX, usize::MAX, 2);
    assert_eq!((policy.workers, policy.retained), (2, 2));
    assert_eq!(ReservationOwner::new(policy).state_for_test().3, 9);
}

#[test]
fn d3b_examined_holds_use_one_global_allowance() {
    let policy = SegmentPolicy::from_headroom(10, 0, 0);
    let owner = ReservationOwner::for_examined(policy, 2);
    assert_eq!(owner.examined_capacity(), 2);
    let first = owner.examined().unwrap();
    let first_file = std::fs::File::open("/dev/null").unwrap();
    let sibling = owner.clone();
    let second = sibling.examined().unwrap();
    let second_file = std::fs::File::open("/dev/null").unwrap();
    assert!(owner.examined().is_err(), "cap multiplied by owner clones");
    let immediate = owner.immediate();
    let pin = immediate.pin().unwrap();
    let io = immediate.transient().unwrap();
    assert_eq!(owner.examined_for_test(), (2, 2));
    assert!(owner.state_for_test().2 <= policy.headroom);
    drop((first_file, second_file));
    drop((first, second, pin, io));
    assert_eq!(owner.examined_for_test().0, 0);
    assert_eq!(owner.state_for_test().0, [0; 4]);
}

#[test]
fn d3b_strict_census_never_accepts_a_partial_count() {
    let entries = || [Ok::<_, ()>(()), Ok(()), Ok(())].into_iter();
    // Three FDs include the census itself; held/admitted/current scan FDs
    // would be among the other two, never subtracted a second time.
    assert_eq!(census_allowance(100, entries(), 4, || true).unwrap(), 34);
    assert_eq!(census_allowance(64, entries(), 4, || true).unwrap(), 0);
    assert_eq!(
        census_allowance(100, entries(), 3, || true).unwrap_err(),
        FD_CENSUS_REASON
    );
    assert_eq!(
        census_allowance(100, [Ok(()), Err(())].into_iter(), 4, || true).unwrap_err(),
        FD_CENSUS_REASON
    );
    let polls = std::cell::Cell::new(0);
    assert!(
        census_allowance(100, entries(), 4, || {
            polls.set(polls.get() + 1);
            polls.get() < 4
        })
        .is_err(),
        "late census accepted its partial count"
    );
    assert!(
        census_allowance(100, entries(), 4, || false).is_err(),
        "clock refusal was ignored"
    );
    assert!(census_allowance(100, std::iter::empty::<Result<(), ()>>(), 4, || true).is_err());
    // Exercise the real unprivileged directory/syscall path too. Headroom
    // is environment dependent, so its numeric value is not an oracle.
    match SegmentPolicy::try_snapshot(0, 0) {
        Ok(live) => assert_eq!((live.workers, live.retained), (0, 0)),
        Err(reason) => assert_eq!(reason, FD_CENSUS_REASON),
    }
}

#[test]
fn d3b_census_reconciliation_requires_quiescence_and_counts_holds_once() {
    let owner = ReservationOwner::for_examined(SegmentPolicy::from_headroom(10, 0, 0), 2);
    let hold = owner.examined().unwrap();
    let held_file = std::fs::File::open("/dev/null").unwrap();
    let immediate = owner.immediate();
    let pin = immediate.pin().unwrap();
    let fresh = SegmentPolicy::from_headroom(6, 1, 1);
    assert!(
        owner.reconcile(fresh).is_err(),
        "live confirmation pin rebased"
    );
    drop(pin);
    let worker = immediate.transient().unwrap();
    assert!(
        owner.reconcile(fresh).is_err(),
        "live transient worker rebased"
    );
    drop(worker);
    owner.reconcile(fresh).unwrap();
    assert!(
        owner.examined().is_err(),
        "new custody after the census boundary"
    );
    let batch = owner.batch();
    let pin = batch.pin().unwrap();
    let transient = batch.transient().unwrap();
    let immediate_pin = immediate.pin().unwrap();
    let immediate_io = immediate.transient().unwrap();
    assert_eq!(owner.state_for_test().0, [1, 2, 1, 2]);
    assert_eq!(owner.examined_for_test().0, 1);
    drop((pin, transient, immediate_pin, immediate_io));
    drop(held_file);
    drop(hold);
    assert_eq!(owner.state_for_test().0, [0; 4]);
    assert_eq!(owner.examined_for_test().0, 0);
}

/// A delivered reply does not release the worker's source Arc. The observer
/// owns no source, and the next immediate operation awaits real destruction.
#[test]
fn d3a_directory_final_drop_fences_immediate_reuse() {
    let policy = SegmentPolicy::from_headroom(3, 4, 2);
    let owner = ReservationOwner::new(policy);
    let resources = owner.immediate();
    let lease = resources.transient().unwrap();
    let held = Arc::new(HeldMapFiles {
        dir: Some(MapFilesDir::open(std::process::id()).unwrap()),
        lease: Some(lease),
        closed: DropFence::default(),
        observer: None,
    });
    let weak = Arc::downgrade(&held);
    let observer = held.closed.clone(); // no source Arc in the observer
    let delivered = std::sync::Barrier::new(2);
    let release = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let worker_source = held.clone();
        scope.spawn(|| {
            delivered.wait(); // analogous to proof result delivery
            release.wait();
            drop(worker_source);
        });
        drop(held);
        delivered.wait();
        assert!(
            weak.upgrade()
                .unwrap()
                .dir
                .as_ref()
                .unwrap()
                .directory_metadata()
                .is_ok()
        );
        assert_eq!(owner.state_for_test().0, [0, 0, 0, 2]);
        assert!(resources.transient().is_err());
        assert!(!*observer.0.0.lock().unwrap());
        release.wait();
        observer.wait();
        assert!(weak.upgrade().is_none());
        assert_eq!(owner.state_for_test().0, [0; 4]);
        let next = resources.transient().unwrap();
        drop(next);
    });
    assert_eq!(owner.state_for_test().0, [0; 4]);
}

#[path = "d4_ext4_cells.rs"]
mod d4_ext4_cells;
#[path = "d4_overlay_cells.rs"]
mod d4_overlay_cells;
#[path = "d4_population_cells.rs"]
mod d4_population_cells;
#[path = "d4_zombie_cells.rs"]
mod d4_zombie_cells;
