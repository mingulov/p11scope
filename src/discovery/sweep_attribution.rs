//! SPDX-License-Identifier: GPL-3.0-or-later
//! C1b: attribute callers independently of the deep-scan cap.
//!
//! Over `--max-scan-pids`, discovery deep-scans one representative per
//! provider group. Every other process used to be dropped. This module
//! attributes those unselected processes to provider objects a deep scan
//! already pinned this pass, using only their phase-1 maps snapshot and a
//! confirmation read — never a decode, a digest, or a new identity:
//!
//! - A key matches only by exact `(device, inode)` equality with a key a
//!   deep scan bound, this pass, to exactly one pinned, non-rejected
//!   object (`PinnedObjects::sweep_match_keys`). Overlay-collapsed and
//!   alias keys never match; neither does a key on a filesystem whose
//!   inode numbers are not unique (FUSE, network filesystems).
//! - Each phase-1 match is confirmed while the aggregate pins (and their
//!   fds) are held: a pidfd/start-time pin, the exe identity read before
//!   and after, a maps re-read, and `still_the_same()`. Only the
//!   confirmation snapshot attributes.
//! - A maps key is not one file (btrfs renders one device for every
//!   subvolume while inode numbers repeat across them), and `fstat` of the
//!   held fd is not comparable with maps (btrfs anon devices; pre-6.8
//!   overlayfs installs the backing file in the VMA). So every matched
//!   range must have the same kernel `vm_file` as the held object, both
//!   read through `map_files` — the target's range, read while the pin
//!   holds, and a self-mapping of the held fd (see
//!   `identity::FileIdentity` for why each side uses what). A different
//!   file is an `identity_mismatch` loss; an unprovable one (no
//!   `CAP_SYS_ADMIN`/`CAP_CHECKPOINT_RESTORE`) a `map_files_unavailable`
//!   loss. "Examined" keys need the same proof to count as examined.
//! - Only executable ranges make a caller (owner ruling A6, exec-only
//!   proof ranges): a key's non-executable ranges are neither proved nor
//!   counted, for matched and examined keys alike, so a process that maps
//!   a provider only without `x` (a scanner reading the file, `ld.so`'s
//!   first `r--` mapping) is not a caller and costs no proof. Every range
//!   selection goes through [`is_caller_range`].
//! - ` (deleted)` (and otherwise unusable) mapping paths never match.
//! - After the confirmations, each matched object is rechecked once
//!   (`object_unchanged`); a changed object drops its sweep attributions.
//!
//! Every loss is explicit and counted by category; nothing is silent. The
//! module is pure over its inputs: `/proc` access goes through
//! [`MemberProbe`], so the decisions are unit-testable.
//!
//! Privacy (allowlist-v1, "filesystem mapping names/metadata"): this reads
//! only maps, a pidfd, the start time, exe metadata, and the
//! `(st_dev, st_ino)` of mapped provider-candidate ranges — metadata, never
//! file contents. Paths come only from matched provider mappings.

use crate::discovery::caller_registry::ExeIdentity;
use crate::discovery::engine::is_provider_mapping;
use crate::discovery::identity::{
    ExaminedObject, FileIdentity, MapFilesDir, MappedFile, PinnedObjectId,
};
use crate::discovery::proof_stats::{ProofStatPool, RangeStat, stat_batch};
use crate::discovery::scan::{
    CaptureWorkBudget, IO_CEILING_REASON, MAPS_CEILING_REASON, MAPS_ENTRY_CEILING_REASON,
    SCAN_CLOCK_REASON, SCAN_DEADLINE_REASON, WORK_CEILING_REASON, duplicate_exec_coverage,
};
use p11scope_manifest::maps::{MapEntry, MappedPath, ObjectKey, mapped_path};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Why one unselected process mapping a known provider object was not
/// attributed to it. Counted per category at scope level; the per-pid
/// reason goes to the process table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AttributionLoss {
    /// The pidfd/start-time pin stopped naming the generation (exit and
    /// reuse, or a turnover the confirmation could not prove).
    GenerationChanged,
    /// The exe identity changed across the confirmation read (an exec), or
    /// no longer equals the caller incarnation reconcile admitted.
    ExecChanged,
    /// The pin, exe identity, start time, or maps could not be read.
    ConfirmUnreadable,
    /// The confirmed mapping of the known object reads ` (deleted)`.
    DeletedMapping,
    /// The matched object's pin changed (`(ino, size, ctime)`) after the
    /// confirmation reads.
    ObjectChanged,
    /// The key is known from a deep scan but names no single, comparable,
    /// non-rejected pinned object (a rejected or unbound key, an overlay
    /// collapse, an alias, or an unusable pathname).
    KeyRejected,
    /// The object lives on a filesystem whose inode numbers are not unique
    /// per device (FUSE, network filesystems): a maps key cannot name it.
    InodeNotUnique,
    /// The confirmation read hit a capture work, I/O, or deadline ceiling.
    Budget,
    /// The key matched, but a mapped range at it is another file (a maps
    /// key collision: btrfs subvolumes, overlayfs).
    IdentityMismatch,
    /// The key needs the `map_files` proof and it could not be read (no
    /// `CAP_SYS_ADMIN`/`CAP_CHECKPOINT_RESTORE`).
    MapFilesUnavailable,
    /// A range confirmed inside the pin was no longer one mapping when its
    /// `map_files` entry was read (unmapped or remapped during the
    /// confirmation): the proof is impossible this pass, not unprivileged.
    MappingChanged,
}

impl AttributionLoss {
    pub(crate) const ALL: [AttributionLoss; 11] = [
        Self::GenerationChanged,
        Self::ExecChanged,
        Self::ConfirmUnreadable,
        Self::DeletedMapping,
        Self::ObjectChanged,
        Self::KeyRejected,
        Self::InodeNotUnique,
        Self::Budget,
        Self::IdentityMismatch,
        Self::MapFilesUnavailable,
        Self::MappingChanged,
    ];

    /// Stable category label (`scan.attribution_losses` keys).
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::GenerationChanged => "generation_changed",
            Self::ExecChanged => "exec_changed",
            Self::ConfirmUnreadable => "confirm_unreadable",
            Self::DeletedMapping => "deleted_mapping",
            Self::ObjectChanged => "object_changed",
            Self::KeyRejected => "key_rejected",
            Self::InodeNotUnique => "inode_not_unique",
            Self::Budget => "budget",
            Self::IdentityMismatch => "identity_mismatch",
            Self::MapFilesUnavailable => "map_files_unavailable",
            Self::MappingChanged => "mapping_changed",
        }
    }
}

/// How one provider-candidate key of an unselected process classifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyClass {
    /// Bound this pass to exactly one pinned object: attributable.
    Match(PinnedObjectId),
    /// A deep scan saw a module here, but the key cannot attribute.
    Ineligible(AttributionLoss),
    /// A complete deep scan mapped this key and found no module in it.
    Examined,
    /// No deep scan examined this key this pass.
    Unexamined,
}

/// One object a deep scan refused for sweep matching on a filesystem
/// without unique inode numbers: the named gap's facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefusedObject {
    pub object: PinnedObjectId,
    pub key: ObjectKey,
    pub filesystem: &'static str,
}

/// What the index needs to ask of a pinned object. `PinnedObjects`
/// answers in production; tests script it.
pub(crate) trait ObjectChecks {
    /// `Some(filesystem)` for a filesystem without unique inode numbers.
    fn nonunique_inodes(&self, object: PinnedObjectId) -> Result<Option<&'static str>, String>;
    /// `Ok(true)` while the object still matches its pin.
    fn unchanged(&self, object: PinnedObjectId) -> Result<bool, String>;
    /// The held object's self-mapped `vm_file`: its identity is what
    /// another process's `map_files` range must equal before a maps key
    /// stands for it, unless the key is that identity on an allowlisted
    /// filesystem ([`MappedFile::key_is_identity`]).
    fn mapped_identity(&self, object: PinnedObjectId) -> Result<MappedFile, String>;
}

impl ObjectChecks for crate::discovery::identity::PinnedObjects {
    fn nonunique_inodes(&self, object: PinnedObjectId) -> Result<Option<&'static str>, String> {
        self.nonunique_inode_filesystem(object)
    }

    fn unchanged(&self, object: PinnedObjectId) -> Result<bool, String> {
        self.object_unchanged(object)
    }

    fn mapped_identity(&self, object: PinnedObjectId) -> Result<MappedFile, String> {
        self.object_mapped_identity(object)
    }
}

/// This pass's attributable keys: exact maps keys a deep scan bound to one
/// pinned object (with that object's `vm_file` identity), the keys
/// a deep scan saw as modules that cannot attribute, and the
/// provider-candidate keys complete deep scans opened and found to export
/// nothing wanted. Built once per pass from this pass's deep scans only —
/// there is no cross-pass state.
#[derive(Debug, Clone, Default)]
pub(crate) struct KnownKeyIndex {
    by_key: BTreeMap<ObjectKey, (PinnedObjectId, FileIdentity)>,
    ineligible: BTreeMap<ObjectKey, AttributionLoss>,
    /// Examined keys with every `vm_file` identity a deep scan examined
    /// under them (a key may name several files).
    examined: BTreeMap<ObjectKey, BTreeSet<FileIdentity>>,
    /// Matchable or examined keys that are their file's identity on an
    /// allowlisted filesystem: any range under them is that file, so they
    /// skip the per-range `map_files` stat (DR-C1b-3).
    identity_keys: BTreeSet<ObjectKey>,
}

impl KnownKeyIndex {
    /// `modules`: every deep-scanned module's maps key with the pinned
    /// object it bound to (`None`: no comparable pin). `match_keys`: the
    /// aggregate's `sweep_match_keys`. `examined`: the objects complete
    /// deep scans examined, from their own scan reads. Returns the index
    /// plus the objects refused on filesystems without unique inode
    /// numbers.
    pub(crate) fn build(
        modules: impl IntoIterator<Item = (ObjectKey, Option<PinnedObjectId>)>,
        match_keys: &BTreeMap<ObjectKey, PinnedObjectId>,
        examined: impl IntoIterator<Item = ExaminedObject>,
        checks: &dyn ObjectChecks,
    ) -> (Self, Vec<RefusedObject>) {
        let mut bound: BTreeMap<ObjectKey, BTreeSet<Option<PinnedObjectId>>> = BTreeMap::new();
        for (key, object) in modules {
            bound.entry(key).or_default().insert(object);
        }
        let mut index = Self::default();
        let mut refused = Vec::new();
        for (key, objects) in &bound {
            let single = match_keys
                .get(key)
                .copied()
                .filter(|object| objects.len() == 1 && objects.first() == Some(&Some(*object)));
            let Some(object) = single else {
                index.ineligible.insert(*key, AttributionLoss::KeyRejected);
                continue;
            };
            match checks.nonunique_inodes(object) {
                Ok(None) => {}
                Ok(Some(filesystem)) => {
                    index
                        .ineligible
                        .insert(*key, AttributionLoss::InodeNotUnique);
                    refused.push(RefusedObject {
                        object,
                        key: *key,
                        filesystem,
                    });
                    continue;
                }
                // Unclassifiable: fail closed, never match by key alone.
                Err(_) => {
                    index.ineligible.insert(*key, AttributionLoss::KeyRejected);
                    continue;
                }
            }
            match checks.mapped_identity(object) {
                Ok(mapped) => {
                    if mapped.key_is_identity(*key) {
                        index.identity_keys.insert(*key);
                    }
                    index.by_key.insert(*key, (object, mapped.identity));
                }
                // No privilege to read map_files: nothing can be proven.
                Err(_) => {
                    index
                        .ineligible
                        .insert(*key, AttributionLoss::MapFilesUnavailable);
                }
            }
        }
        for object in examined {
            if bound.contains_key(&object.key) {
                continue;
            }
            if object.key_is_identity {
                index.identity_keys.insert(object.key);
            }
            index
                .examined
                .entry(object.key)
                .or_default()
                .insert(object.identity);
        }
        (index, refused)
    }

    pub(crate) fn classify(&self, key: ObjectKey) -> KeyClass {
        if let Some((object, _)) = self.by_key.get(&key) {
            KeyClass::Match(*object)
        } else if let Some(loss) = self.ineligible.get(&key) {
            KeyClass::Ineligible(*loss)
        } else if self.examined.contains_key(&key) {
            KeyClass::Examined
        } else {
            KeyClass::Unexamined
        }
    }

    /// The keys whose ranges need the `map_files` proof in another
    /// process: every matchable and every examined key that is not its
    /// file's identity.
    pub(crate) fn map_files_keys(&self) -> BTreeSet<ObjectKey> {
        self.by_key
            .keys()
            .chain(self.examined.keys())
            .filter(|key| !self.identity_keys.contains(key))
            .copied()
            .collect()
    }

    /// Whether any range under `key` is its file without a per-range stat.
    fn key_is_identity(&self, key: ObjectKey) -> bool {
        self.identity_keys.contains(&key)
    }

    fn match_identity(&self, key: ObjectKey) -> Option<FileIdentity> {
        self.by_key.get(&key).map(|(_, identity)| *identity)
    }

    fn examined_identities(&self, key: ObjectKey) -> Option<&BTreeSet<FileIdentity>> {
        self.examined.get(&key)
    }
}

/// `map_files` identities read for the mapped ranges that needed them,
/// keyed by `(start, end)`.
pub(crate) type MappedIdentities = BTreeMap<(u64, u64), Result<FileIdentity, String>>;

/// A confirmation read that held: the generation the pin proved and the
/// maps snapshot read while it held, between two equal exe reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfirmedRead {
    pub start_time: u64,
    pub exe: ExeIdentity,
    pub entries: Vec<MapEntry>,
    /// The `map_files` identity of every confirmed caller range
    /// ([`is_caller_range`]) whose key needs that proof, read while the pin
    /// held.
    pub mapped: MappedIdentities,
}

/// What one confirmation concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Confirmation {
    Confirmed(ConfirmedRead),
    /// The process is provably gone: an ordinary exit, never a loss.
    Exited,
    Lost(AttributionLoss, String),
}

/// The `/proc` side of the confirmation, behind a seam.
pub(crate) trait MemberProbe {
    /// Confirm `pid`, statting the `map_files` entry of every confirmed
    /// caller range ([`proof_ranges`]) whose key is in `prove`.
    fn confirm(
        &mut self,
        pid: u32,
        prove: &BTreeSet<ObjectKey>,
        budget: &mut CaptureWorkBudget,
    ) -> Confirmation;
    /// The `map_files` identities of `ranges` for a process with no match
    /// to confirm: only examined keys are being proven, so no pin is
    /// needed — a range that does not stat to an examined identity counts
    /// as unexamined.
    fn stat_ranges(
        &mut self,
        pid: u32,
        ranges: &[(u64, u64)],
        budget: &mut CaptureWorkBudget,
    ) -> MappedIdentities;
}

/// One object an unselected process was attributed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MatchedObject {
    pub key: ObjectKey,
    pub object: PinnedObjectId,
    /// The confirmed mapping's pathname as the target renders it (lossy
    /// UTF-8; control-escaped wherever text is rendered).
    pub path: String,
    /// `duplicate_exec_coverage` over the confirmed entries of this key:
    /// parity with the deep scan's double-load evidence.
    pub double_loaded: bool,
}

/// One unselected process attributed by exact maps identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SweptMember {
    pub pid: u32,
    pub start_time: u64,
    pub exe: ExeIdentity,
    pub objects: Vec<MatchedObject>,
    /// Caller keys (keys with a caller range) in the confirmation snapshot
    /// no deep scan examined this pass.
    pub unexamined: usize,
}

/// One pass's sweep attribution over the unselected processes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SweepAttribution {
    pub members: Vec<SweptMember>,
    /// Per unselected pid (matched or not): caller keys no deep scan
    /// examined this pass. Only nonzero counts are kept.
    pub unexamined: BTreeMap<u32, usize>,
    /// The distinct caller keys behind `unexamined`.
    pub unexamined_objects: BTreeSet<ObjectKey>,
    /// Unselected pids whose phase-1 snapshot was unavailable.
    pub unavailable: usize,
    /// Losses by category: each pid counts once per category.
    pub losses: BTreeMap<AttributionLoss, usize>,
    /// The per-pid reason (first loss) for the process table.
    pub member_losses: BTreeMap<u32, (AttributionLoss, String)>,
    /// Unselected pids that exited before their confirmation.
    pub exited: BTreeSet<u32>,
    /// Confirmation reads attempted.
    pub probed: usize,
}

impl SweepAttribution {
    /// Distinct provider-candidate keys no deep scan examined (the capped
    /// record's `k`).
    pub(crate) fn unexamined_keys(&self) -> usize {
        self.unexamined_objects.len()
    }

    fn note_unexamined(&mut self, pid: u32, keys: &BTreeSet<ObjectKey>) {
        if !keys.is_empty() {
            self.unexamined.insert(pid, keys.len());
            self.unexamined_objects.extend(keys.iter().copied());
        }
    }

    /// Count one loss: a pid counts once per category, and its first loss
    /// is the process-table reason.
    fn note_loss(
        &mut self,
        pid: u32,
        loss: AttributionLoss,
        detail: String,
        seen: &mut BTreeSet<AttributionLoss>,
    ) {
        if seen.insert(loss) {
            *self.losses.entry(loss).or_default() += 1;
        }
        self.member_losses.entry(pid).or_insert((loss, detail));
    }
}

/// How one snapshot's provider-candidate keys classify against the index.
#[derive(Default)]
struct Classified<'a> {
    matches: Vec<(ObjectKey, PinnedObjectId, Vec<&'a MapEntry>)>,
    ineligible: Vec<(ObjectKey, AttributionLoss)>,
    unexamined: BTreeSet<ObjectKey>,
    /// Examined keys whose ranges still need the `map_files` proof.
    examined_pending: Vec<(ObjectKey, Vec<&'a MapEntry>)>,
}

impl Classified<'_> {
    /// The ranges of pending examined keys that need a stat, for an
    /// unpinned stat.
    fn pending_ranges(&self, index: &KnownKeyIndex) -> Vec<(u64, u64)> {
        self.examined_pending
            .iter()
            .filter(|(key, _)| !index.key_is_identity(*key))
            .flat_map(|(_, group)| group.iter().map(|entry| (entry.start, entry.end)))
            .collect()
    }

    /// Settle the pending examined keys against `mapped`: a key whose
    /// every caller range ([`is_caller_range`]: its groups hold no other)
    /// stats to an identity a deep scan examined is examined;
    /// a key with a range that is no longer one mapping
    /// ([`RANGE_NOT_MAPPED`]) is returned (its mapping changed since the
    /// maps read: not a coverage gap); any other becomes unexamined.
    fn settle_examined(
        &mut self,
        index: &KnownKeyIndex,
        mapped: &MappedIdentities,
    ) -> BTreeSet<ObjectKey> {
        let mut changed = BTreeSet::new();
        for (key, group) in std::mem::take(&mut self.examined_pending) {
            let proven = index.key_is_identity(key)
                || index.examined_identities(key).is_some_and(|files| {
                    group.iter().all(|entry| {
                        matches!(
                            mapped.get(&(entry.start, entry.end)),
                            Some(Ok(identity)) if files.contains(identity)
                        )
                    })
                });
            if proven {
                continue;
            }
            if group.iter().any(|entry| {
                matches!(
                    mapped.get(&(entry.start, entry.end)),
                    Some(Err(error)) if error == RANGE_NOT_MAPPED
                )
            }) {
                changed.insert(key);
            } else {
                self.unexamined.insert(key);
            }
        }
        changed
    }

    /// Whether any pending examined range read [`RANGE_NOT_MAPPED`].
    fn pending_changed(&self, mapped: &MappedIdentities) -> bool {
        self.examined_pending.iter().any(|(_, group)| {
            group.iter().any(|entry| {
                matches!(
                    mapped.get(&(entry.start, entry.end)),
                    Some(Err(error)) if error == RANGE_NOT_MAPPED
                )
            })
        })
    }
}

fn classify_snapshot<'a>(index: &KnownKeyIndex, entries: &'a [MapEntry]) -> Classified<'a> {
    let mut classified = Classified::default();
    for (key, group) in provider_groups(entries) {
        match index.classify(key) {
            KeyClass::Match(object) => classified.matches.push((key, object, group)),
            KeyClass::Ineligible(loss) => classified.ineligible.push((key, loss)),
            KeyClass::Examined => classified.examined_pending.push((key, group)),
            KeyClass::Unexamined => {
                classified.unexamined.insert(key);
            }
        }
    }
    classified
}

/// Whether every range of a matched group (its caller ranges: see
/// [`is_caller_range`]) is the held object's file.
fn prove_match(
    expected: FileIdentity,
    group: &[&MapEntry],
    mapped: &MappedIdentities,
) -> Result<(), (AttributionLoss, String)> {
    for entry in group {
        match mapped.get(&(entry.start, entry.end)) {
            Some(Ok(identity)) if *identity == expected => {}
            Some(Ok(identity)) => {
                return Err((
                    AttributionLoss::IdentityMismatch,
                    format!(
                        "the range {:x}-{:x} maps another file (st_dev {} st_ino {}, the \
                         pinned object is st_dev {} st_ino {}): a maps key collision",
                        entry.start,
                        entry.end,
                        identity.dev,
                        identity.ino,
                        expected.dev,
                        expected.ino
                    ),
                ));
            }
            Some(Err(error)) if error == RANGE_NOT_MAPPED => {
                return Err((
                    AttributionLoss::MappingChanged,
                    format!(
                        "the range {:x}-{:x} was no longer one mapping when its map_files \
                         entry was read",
                        entry.start, entry.end
                    ),
                ));
            }
            Some(Err(error)) => {
                return Err((
                    AttributionLoss::MapFilesUnavailable,
                    format!(
                        "the map_files identity of {:x}-{:x} could not be read: {error}",
                        entry.start, entry.end
                    ),
                ));
            }
            None => {
                return Err((
                    AttributionLoss::MapFilesUnavailable,
                    format!(
                        "the map_files identity of {:x}-{:x} was not read",
                        entry.start, entry.end
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn key_detail(key: ObjectKey) -> String {
    format!(
        "device {}:{} inode {}",
        key.device.major, key.device.minor, key.inode
    )
}

/// Attribute every unselected, swept process to this pass's pinned
/// objects. `sweep` is the phase-1 snapshot per pid (`unavailable` pids
/// carry an empty one); `selected` pids were deep-scanned and are never
/// attributed here.
pub(crate) fn attribute_unselected(
    sweep: &[(u32, Vec<MapEntry>)],
    unavailable: &BTreeSet<u32>,
    selected: &BTreeSet<u32>,
    index: &KnownKeyIndex,
    probe: &mut dyn MemberProbe,
    budget: &mut CaptureWorkBudget,
) -> SweepAttribution {
    let mut out = SweepAttribution::default();
    let prove = index.map_files_keys();
    for (pid, phase_one) in sweep {
        let pid = *pid;
        if selected.contains(&pid) {
            continue;
        }
        if unavailable.contains(&pid) {
            out.unavailable += 1;
            continue;
        }
        let mut seen = BTreeSet::new();
        let mut first = classify_snapshot(index, phase_one);
        // Ineligible known keys are attribution losses either way: the
        // process maps a provider object it cannot be attributed to.
        let note_ineligible =
            |out: &mut SweepAttribution,
             seen: &mut BTreeSet<AttributionLoss>,
             ineligible: &[(ObjectKey, AttributionLoss)]| {
                for (key, loss) in ineligible {
                    out.note_loss(
                        pid,
                        *loss,
                        format!(
                            "maps a known provider object ({}) that cannot be matched: {}",
                            key_detail(*key),
                            loss.label()
                        ),
                        seen,
                    );
                }
            };
        // Usable phase-1 matches decide whether a confirmation is worth a
        // read. Without one, the phase-1 facts are the verdict: an unusable
        // (deleted) known mapping and any ineligible known key are named
        // losses, and unexamined keys are counted.
        let unusable: Vec<(ObjectKey, AttributionLoss)> = first
            .matches
            .iter()
            .filter_map(|(key, _, group)| usable_path(group).err().map(|loss| (*key, loss)))
            .collect();
        // No pin is needed to prove examined keys: a range that does not
        // stat to an examined identity only counts as unexamined. But a
        // range that is no longer one mapping means the snapshot is stale
        // (an unload, a remap or an exit since the sweep): only a re-read
        // can say which, so such a pid is confirmed like a match.
        let mut mapped = MappedIdentities::new();
        if unusable.len() == first.matches.len() {
            let ranges = first.pending_ranges(index);
            if !ranges.is_empty() {
                mapped = probe.stat_ranges(pid, &ranges, budget);
            }
        }
        if unusable.len() == first.matches.len() && !first.pending_changed(&mapped) {
            for (key, loss) in &unusable {
                out.note_loss(
                    pid,
                    *loss,
                    format!(
                        "the mapping of {} is unusable for matching: {}",
                        key_detail(*key),
                        loss.label()
                    ),
                    &mut seen,
                );
            }
            note_ineligible(&mut out, &mut seen, &first.ineligible);
            first.settle_examined(index, &mapped);
            out.note_unexamined(pid, &first.unexamined);
            continue;
        }
        out.probed += 1;
        let read = match probe.confirm(pid, &prove, budget) {
            Confirmation::Confirmed(read) => read,
            Confirmation::Exited => {
                out.exited.insert(pid);
                continue;
            }
            Confirmation::Lost(loss, detail) => {
                out.note_loss(pid, loss, detail, &mut seen);
                // Nothing was proven: pending examined keys are unexamined.
                first.settle_examined(index, &MappedIdentities::new());
                out.note_unexamined(pid, &first.unexamined);
                continue;
            }
        };
        let mut confirmed = classify_snapshot(index, &read.entries);
        for key in confirmed.settle_examined(index, &read.mapped) {
            out.note_loss(
                pid,
                AttributionLoss::MappingChanged,
                format!(
                    "a confirmed range of {} was no longer one mapping when its map_files \
                     entry was read",
                    key_detail(key)
                ),
                &mut seen,
            );
        }
        note_ineligible(&mut out, &mut seen, &confirmed.ineligible);
        let mut objects = Vec::new();
        for (key, object, group) in &confirmed.matches {
            let proven = match index.match_identity(*key) {
                Some(_) if index.key_is_identity(*key) => Ok(()),
                Some(expected) => prove_match(expected, group, &read.mapped),
                None => Err((
                    AttributionLoss::KeyRejected,
                    "the key lost its proof".into(),
                )),
            };
            if let Err((loss, detail)) = proven {
                out.note_loss(
                    pid,
                    loss,
                    format!("{}: {detail}", key_detail(*key)),
                    &mut seen,
                );
                continue;
            }
            match usable_path(group) {
                Ok(path) => objects.push(MatchedObject {
                    key: *key,
                    object: *object,
                    path,
                    double_loaded: duplicate_exec_coverage(group),
                }),
                Err(loss) => out.note_loss(
                    pid,
                    loss,
                    format!(
                        "the confirmed mapping of {} is unusable for matching: {}",
                        key_detail(*key),
                        loss.label()
                    ),
                    &mut seen,
                ),
            }
        }
        out.note_unexamined(pid, &confirmed.unexamined);
        if objects.is_empty() {
            // Unloaded before the confirmation (no loss), or every known
            // mapping was unusable (already counted above).
            continue;
        }
        out.members.push(SweptMember {
            pid,
            start_time: read.start_time,
            exe: read.exe,
            objects,
            unexamined: confirmed.unexamined.len(),
        });
    }
    out
}

/// Recheck every matched object once, after every confirmation read: a
/// changed (or unverifiable) object drops its sweep attributions, and a
/// member left with none becomes an `object_changed` loss. Returns the
/// dropped objects with the reason, for their gaps.
pub(crate) fn retain_unchanged(
    attribution: &mut SweepAttribution,
    checks: &dyn ObjectChecks,
) -> Vec<(PinnedObjectId, String)> {
    let objects: BTreeSet<PinnedObjectId> = attribution
        .members
        .iter()
        .flat_map(|member| member.objects.iter().map(|object| object.object))
        .collect();
    let mut dropped = Vec::new();
    for object in objects {
        match checks.unchanged(object) {
            Ok(true) => {}
            Ok(false) => dropped.push((
                object,
                "the pinned object changed after the confirmation reads".to_string(),
            )),
            Err(error) => dropped.push((
                object,
                format!("the pinned object could not be rechecked: {error}"),
            )),
        }
    }
    if dropped.is_empty() {
        return dropped;
    }
    let gone: BTreeSet<PinnedObjectId> = dropped.iter().map(|(object, _)| *object).collect();
    let members = std::mem::take(&mut attribution.members);
    for mut member in members {
        let before = member.objects.len();
        member
            .objects
            .retain(|object| !gone.contains(&object.object));
        if member.objects.len() < before {
            let mut seen: BTreeSet<AttributionLoss> = attribution
                .member_losses
                .get(&member.pid)
                .map(|(loss, _)| *loss)
                .into_iter()
                .collect();
            attribution.note_loss(
                member.pid,
                AttributionLoss::ObjectChanged,
                "a matched provider object changed after its confirmation".into(),
                &mut seen,
            );
        }
        if !member.objects.is_empty() {
            attribution.members.push(member);
        }
    }
    dropped
}

/// Whether `entry` is a range that makes its process a caller of the
/// object at its key, and so the only kind of range a key must prove
/// (owner ruling A6, 2026-10-05: exec-only proof ranges): a file-backed
/// provider-candidate mapping with the `x` permission. A key's
/// non-executable ranges are neither proved nor counted — not for a
/// matched key (attribution), not for an examined key (coverage) — so a
/// process mapping a provider only without `x` is not its caller, and a
/// maps-key collision on a data range cannot cost an edge whose executable
/// ranges are the held file.
///
/// This is the one rule for which ranges a key brings: phase-1 and
/// confirmed classification ([`provider_groups`]) and the confirmation's
/// proof reads ([`proof_ranges`]) both use it, and any other identity
/// backend must take its range set from the same place (I7).
pub(crate) fn is_caller_range(entry: &MapEntry) -> bool {
    is_provider_mapping(entry) && entry.permissions[2] == b'x'
}

/// The caller ranges ([`is_caller_range`]) of one snapshot by key, each key
/// once, with its entries in maps order (for the proof, double-load
/// evidence and the path). A key with no caller range has no group.
fn provider_groups(entries: &[MapEntry]) -> BTreeMap<ObjectKey, Vec<&MapEntry>> {
    let mut groups: BTreeMap<ObjectKey, Vec<&MapEntry>> = BTreeMap::new();
    for entry in entries.iter().filter(|entry| is_caller_range(entry)) {
        groups.entry(ObjectKey::of(entry)).or_default().push(entry);
    }
    groups
}

/// The ranges whose `map_files` identity a confirmation reads: every
/// caller range ([`is_caller_range`]) under a key in `prove`, each once,
/// in maps order (the order the work budget is charged in).
pub(crate) fn proof_ranges(entries: &[MapEntry], prove: &BTreeSet<ObjectKey>) -> Vec<(u64, u64)> {
    let mut seen = BTreeSet::new();
    entries
        .iter()
        .filter(|entry| is_caller_range(entry) && prove.contains(&ObjectKey::of(entry)))
        .map(|entry| (entry.start, entry.end))
        .filter(|range| seen.insert(*range))
        .collect()
}

/// Whether a group's pathname can attribute: every caller range of the
/// object must carry a usable path. `Err(DeletedMapping)` for ` (deleted)`,
/// `Err(KeyRejected)` for any other unusable spelling.
fn usable_path(group: &[&MapEntry]) -> Result<String, AttributionLoss> {
    let mut path = None;
    for entry in group {
        let Some(raw) = entry.raw_path.as_deref() else {
            return Err(AttributionLoss::KeyRejected);
        };
        match mapped_path(raw) {
            MappedPath::Usable(usable) => {
                path.get_or_insert_with(|| usable.display().to_string());
            }
            MappedPath::Unusable { reason } if reason == "deleted mapping" => {
                return Err(AttributionLoss::DeletedMapping);
            }
            MappedPath::Unusable { .. } => return Err(AttributionLoss::KeyRejected),
        }
    }
    path.ok_or(AttributionLoss::KeyRejected)
}

/// Whether a maps-read refusal is a capture ceiling or deadline (a
/// `budget` loss) rather than an unreadable process.
pub(crate) fn budget_refusal(reason: &str) -> bool {
    [
        IO_CEILING_REASON,
        WORK_CEILING_REASON,
        SCAN_DEADLINE_REASON,
        SCAN_CLOCK_REASON,
        MAPS_CEILING_REASON,
        MAPS_ENTRY_CEILING_REASON,
    ]
    .contains(&reason)
}

/// The OS operations one confirmation needs, behind a seam so the
/// decision order is unit-testable.
pub(crate) trait ConfirmIo {
    type Pin;
    /// The `map_files` identity of `[start, end)` in `pid`; `Err` equal to
    /// [`RANGE_NOT_MAPPED`] when no mapping (or no process) is there now.
    fn mapped_file(&mut self, pid: u32, start: u64, end: u64) -> Result<FileIdentity, String>;
    /// [`Self::mapped_file`] of every range, in order (one result per
    /// range). Production reads them on the proof-stat pool.
    fn mapped_files(
        &mut self,
        pid: u32,
        ranges: &[(u64, u64)],
    ) -> Vec<Result<FileIdentity, String>> {
        ranges
            .iter()
            .map(|&(start, end)| self.mapped_file(pid, start, end))
            .collect()
    }
    fn open(&mut self, pid: u32) -> Result<Self::Pin, String>;
    fn start_time(&self, pin: &Self::Pin) -> Option<u64>;
    fn still_the_same(&self, pin: &Self::Pin) -> bool;
    fn exe(&self, pid: u32) -> Option<ExeIdentity>;
    fn maps(&mut self, pid: u32, budget: &mut CaptureWorkBudget) -> Result<Vec<MapEntry>, String>;
    fn gone(&self, pid: u32) -> bool;
}

/// The proof reads of `ranges` keyed by range. A range whose result is
/// missing (never expected) is left out, which every consumer reads as
/// unproven: fail closed.
fn read_ranges<Io: ConfirmIo>(io: &mut Io, pid: u32, ranges: &[(u64, u64)]) -> MappedIdentities {
    ranges
        .iter()
        .copied()
        .zip(io.mapped_files(pid, ranges))
        .collect()
}

/// The unpinned proof reads of `ranges` (each once): charged in order
/// first; out of budget, the rest stay unproven (unexamined), exactly as
/// reading one at a time would leave them.
pub(crate) fn stat_unpinned<Io: ConfirmIo>(
    io: &mut Io,
    pid: u32,
    ranges: &[(u64, u64)],
    budget: &mut CaptureWorkBudget,
) -> MappedIdentities {
    let mut charged = Vec::new();
    let mut seen = BTreeSet::new();
    for &range in ranges {
        if !seen.insert(range) {
            continue;
        }
        if budget.spend(1).is_err() {
            break;
        }
        charged.push(range);
    }
    read_ranges(io, pid, &charged)
}

/// One confirmation: pin, exe, maps re-read, exe again, then the pin must
/// still hold and both exe reads agree. Only then does the snapshot count.
pub(crate) fn confirm_with<Io: ConfirmIo>(
    io: &mut Io,
    pid: u32,
    prove: &BTreeSet<ObjectKey>,
    budget: &mut CaptureWorkBudget,
) -> Confirmation {
    let lost = |io: &Io, loss: AttributionLoss, detail: String| {
        if io.gone(pid) {
            Confirmation::Exited
        } else {
            Confirmation::Lost(loss, detail)
        }
    };
    let pin = match io.open(pid) {
        Ok(pin) => pin,
        Err(error) => return lost(io, AttributionLoss::ConfirmUnreadable, error),
    };
    let Some(before) = io.exe(pid) else {
        return lost(
            io,
            AttributionLoss::ConfirmUnreadable,
            "the exe identity could not be read".into(),
        );
    };
    let entries = match io.maps(pid, budget) {
        Ok(entries) => entries,
        Err(reason) if budget_refusal(&reason) => {
            return Confirmation::Lost(AttributionLoss::Budget, reason);
        }
        Err(reason) => return lost(io, AttributionLoss::ConfirmUnreadable, reason),
    };
    // The map_files proof is read while the pin holds; `still_the_same`
    // below proves it was this generation's mapping.
    // Every range is charged first, in order, exactly as one read at a
    // time would charge it; only then are the charged ranges read (on the
    // proof-stat pool when there is one), so a ceiling stops at the same
    // range and never yields a partial proof.
    let ranges = proof_ranges(&entries, prove);
    for _ in &ranges {
        if let Err(reason) = budget.spend(1) {
            return Confirmation::Lost(AttributionLoss::Budget, reason.to_string());
        }
    }
    let mapped = read_ranges(io, pid, &ranges);
    let after = io.exe(pid);
    if !io.still_the_same(&pin) {
        return lost(
            io,
            AttributionLoss::GenerationChanged,
            "the process generation changed during the confirmation read".into(),
        );
    }
    match after {
        Some(after) if after == before => {}
        Some(_) => {
            return Confirmation::Lost(
                AttributionLoss::ExecChanged,
                "the exe identity changed during the confirmation read (exec)".into(),
            );
        }
        None => {
            return lost(
                io,
                AttributionLoss::ConfirmUnreadable,
                "the exe identity could not be re-read".into(),
            );
        }
    }
    let Some(start_time) = io.start_time(&pin) else {
        return Confirmation::Lost(
            AttributionLoss::ConfirmUnreadable,
            "the start time is unreadable; the generation cannot be joined".into(),
        );
    };
    Confirmation::Confirmed(ConfirmedRead {
        start_time,
        exe: before,
        entries,
        mapped,
    })
}

/// The `map_files` error that means "no mapping is at this range now":
/// `ENOENT` from the entry (unmapped, or split or merged by a remap since
/// the maps read) or from the directory (the process is gone). Never a
/// missing privilege, which is `EPERM`/`EACCES`.
pub(crate) const RANGE_NOT_MAPPED: &str = "no mapping is at this range now (ENOENT: unmapped or remapped since the maps read, or the \
     process exited)";

fn map_files_error(error: std::io::Error) -> String {
    if error.raw_os_error() == Some(libc::ENOENT) {
        RANGE_NOT_MAPPED.to_string()
    } else {
        error.to_string()
    }
}

/// Production confirmation: `PidPin` (pidfd plus start time), the exe
/// metadata the caller adapter reads, a budget-charged maps re-read, and
/// `map_files` stats relative to one `/proc/<pid>/map_files` directory
/// (DR-C1b-3), opened at the first range and dropped with this value, so
/// it is never held past the confirmation or stat batch that opened it.
#[derive(Default)]
pub(crate) struct OsConfirmIo<'p> {
    map_files: Option<(u32, Result<Arc<HeldMapFiles>, String>)>,
    /// The collection's proof-stat pool (`None`: read on this thread).
    pool: Option<&'p ProofStatPool>,
}

/// A held `map_files` directory as a pool-shareable proof source, with
/// `ENOENT` read as [`RANGE_NOT_MAPPED`].
struct HeldMapFiles(MapFilesDir);

impl RangeStat for HeldMapFiles {
    fn stat(&self, start: u64, end: u64) -> Result<FileIdentity, String> {
        self.0.identity(start, end).map_err(map_files_error)
    }
}

impl OsConfirmIo<'_> {
    /// The directory of `pid`, opened at its first range.
    fn held(&mut self, pid: u32) -> Result<Arc<HeldMapFiles>, String> {
        if self.map_files.as_ref().is_none_or(|(held, _)| *held != pid) {
            let dir = MapFilesDir::open(pid)
                .map(|dir| Arc::new(HeldMapFiles(dir)))
                .map_err(map_files_error);
            self.map_files = Some((pid, dir));
        }
        match self.map_files.as_ref().map(|(_, dir)| dir) {
            Some(dir) => dir.clone(),
            None => Err("the map_files directory was not opened".into()),
        }
    }
}

impl ConfirmIo for OsConfirmIo<'_> {
    type Pin = crate::process::PidPin;

    fn mapped_file(&mut self, pid: u32, start: u64, end: u64) -> Result<FileIdentity, String> {
        self.held(pid)?.stat(start, end)
    }

    fn mapped_files(
        &mut self,
        pid: u32,
        ranges: &[(u64, u64)],
    ) -> Vec<Result<FileIdentity, String>> {
        match self.held(pid) {
            Ok(dir) => stat_batch(self.pool, dir, ranges),
            Err(error) => vec![Err(error); ranges.len()],
        }
    }

    fn open(&mut self, pid: u32) -> Result<Self::Pin, String> {
        crate::process::PidPin::open(pid)
    }

    fn start_time(&self, pin: &Self::Pin) -> Option<u64> {
        pin.start_time()
    }

    fn still_the_same(&self, pin: &Self::Pin) -> bool {
        pin.still_the_same()
    }

    fn exe(&self, pid: u32) -> Option<ExeIdentity> {
        crate::discovery::caller_registry::read_exe_identity(pid)
    }

    fn maps(&mut self, pid: u32, budget: &mut CaptureWorkBudget) -> Result<Vec<MapEntry>, String> {
        let file = std::fs::File::open(format!("/proc/{pid}/maps")).map_err(|e| e.to_string())?;
        crate::discovery::scan::read_maps_or_refuse(file, budget, crate::attach::monotonic_ns)
    }

    fn gone(&self, pid: u32) -> bool {
        crate::process::generation_gone(pid) || crate::process::process_is_zombie(pid)
    }
}

/// The production probe: proof stats on the collection's pool, if any.
#[derive(Default)]
pub(crate) struct OsMemberProbe<'p> {
    pub pool: Option<&'p ProofStatPool>,
}

impl MemberProbe for OsMemberProbe<'_> {
    fn confirm(
        &mut self,
        pid: u32,
        prove: &BTreeSet<ObjectKey>,
        budget: &mut CaptureWorkBudget,
    ) -> Confirmation {
        let mut io = OsConfirmIo {
            map_files: None,
            pool: self.pool,
        };
        confirm_with(&mut io, pid, prove, budget)
    }

    fn stat_ranges(
        &mut self,
        pid: u32,
        ranges: &[(u64, u64)],
        budget: &mut CaptureWorkBudget,
    ) -> MappedIdentities {
        let mut io = OsConfirmIo {
            map_files: None,
            pool: self.pool,
        };
        stat_unpinned(&mut io, pid, ranges, budget)
    }
}

#[cfg(test)]
#[path = "sweep_attribution_tests.rs"]
mod tests;
