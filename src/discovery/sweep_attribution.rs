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
//!   confirmation snapshot attributes. A held fd keeps the inode and its
//!   superblock allocated, so the confirmed `(device, inode)` cannot name
//!   another file.
//! - ` (deleted)` (and otherwise unusable) mapping paths never match.
//! - After the confirmations, each matched object is rechecked once
//!   (`object_unchanged`); a changed object drops its sweep attributions.
//!
//! Every loss is explicit and counted by category; nothing is silent. The
//! module is pure over its inputs: `/proc` access goes through
//! [`MemberProbe`], so the decisions are unit-testable.
//!
//! Privacy (allowlist-v1, "filesystem mapping names/metadata"): this reads
//! only maps, a pidfd, the start time, and exe metadata — the facts the
//! caller adapter already reads. Paths come only from matched provider
//! mappings.

use crate::discovery::caller_registry::ExeIdentity;
use crate::discovery::engine::is_provider_mapping;
use crate::discovery::identity::PinnedObjectId;
use crate::discovery::scan::{
    CaptureWorkBudget, IO_CEILING_REASON, MAPS_CEILING_REASON, MAPS_ENTRY_CEILING_REASON,
    SCAN_CLOCK_REASON, SCAN_DEADLINE_REASON, WORK_CEILING_REASON, duplicate_exec_coverage,
};
use p11scope_manifest::maps::{MapEntry, MappedPath, ObjectKey, mapped_path};
use std::collections::{BTreeMap, BTreeSet};

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
}

impl AttributionLoss {
    pub(crate) const ALL: [AttributionLoss; 8] = [
        Self::GenerationChanged,
        Self::ExecChanged,
        Self::ConfirmUnreadable,
        Self::DeletedMapping,
        Self::ObjectChanged,
        Self::KeyRejected,
        Self::InodeNotUnique,
        Self::Budget,
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
}

impl ObjectChecks for crate::discovery::identity::PinnedObjects {
    fn nonunique_inodes(&self, object: PinnedObjectId) -> Result<Option<&'static str>, String> {
        self.nonunique_inode_filesystem(object)
    }

    fn unchanged(&self, object: PinnedObjectId) -> Result<bool, String> {
        self.object_unchanged(object)
    }
}

/// This pass's attributable keys: exact maps keys a deep scan bound to one
/// pinned object, the keys a deep scan saw as modules that cannot
/// attribute, and the provider-candidate keys complete deep scans
/// examined without finding a module. Built once per pass from this
/// pass's deep scans only — there is no cross-pass state.
#[derive(Debug, Clone, Default)]
pub(crate) struct KnownKeyIndex {
    by_key: BTreeMap<ObjectKey, PinnedObjectId>,
    ineligible: BTreeMap<ObjectKey, AttributionLoss>,
    examined: BTreeSet<ObjectKey>,
}

impl KnownKeyIndex {
    /// `modules`: every deep-scanned module's maps key with the pinned
    /// object it bound to (`None`: no comparable pin). `match_keys`: the
    /// aggregate's `sweep_match_keys`. `examined`: the phase-1 entries of
    /// deep-scanned members whose scan completed. Returns the index plus
    /// the objects refused on filesystems without unique inode numbers.
    pub(crate) fn build<'a>(
        modules: impl IntoIterator<Item = (ObjectKey, Option<PinnedObjectId>)>,
        match_keys: &BTreeMap<ObjectKey, PinnedObjectId>,
        examined: impl IntoIterator<Item = &'a MapEntry>,
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
                Ok(None) => {
                    index.by_key.insert(*key, object);
                }
                Ok(Some(filesystem)) => {
                    index
                        .ineligible
                        .insert(*key, AttributionLoss::InodeNotUnique);
                    refused.push(RefusedObject {
                        object,
                        key: *key,
                        filesystem,
                    });
                }
                // Unclassifiable: fail closed, never match by key alone.
                Err(_) => {
                    index.ineligible.insert(*key, AttributionLoss::KeyRejected);
                }
            }
        }
        index.examined = examined
            .into_iter()
            .filter(|entry| is_provider_mapping(entry))
            .map(ObjectKey::of)
            .filter(|key| !bound.contains_key(key))
            .collect();
        (index, refused)
    }

    pub(crate) fn classify(&self, key: ObjectKey) -> KeyClass {
        if let Some(object) = self.by_key.get(&key) {
            KeyClass::Match(*object)
        } else if let Some(loss) = self.ineligible.get(&key) {
            KeyClass::Ineligible(*loss)
        } else if self.examined.contains(&key) {
            KeyClass::Examined
        } else {
            KeyClass::Unexamined
        }
    }
}

/// A confirmation read that held: the generation the pin proved and the
/// maps snapshot read while it held, between two equal exe reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfirmedRead {
    pub start_time: u64,
    pub exe: ExeIdentity,
    pub entries: Vec<MapEntry>,
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
    fn confirm(&mut self, pid: u32, budget: &mut CaptureWorkBudget) -> Confirmation;
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
    /// Provider-candidate keys in the confirmation snapshot no deep scan
    /// examined this pass.
    pub unexamined: usize,
}

/// One pass's sweep attribution over the unselected processes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SweepAttribution {
    pub members: Vec<SweptMember>,
    /// Per unselected pid (matched or not): provider-candidate keys no
    /// deep scan examined this pass. Only nonzero counts are kept.
    pub unexamined: BTreeMap<u32, usize>,
    /// The distinct provider-candidate keys behind `unexamined`.
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
}

fn classify_snapshot<'a>(index: &KnownKeyIndex, entries: &'a [MapEntry]) -> Classified<'a> {
    let mut classified = Classified::default();
    for (key, group) in provider_groups(entries) {
        match index.classify(key) {
            KeyClass::Match(object) => classified.matches.push((key, object, group)),
            KeyClass::Ineligible(loss) => classified.ineligible.push((key, loss)),
            KeyClass::Examined => {}
            KeyClass::Unexamined => {
                classified.unexamined.insert(key);
            }
        }
    }
    classified
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
        let first = classify_snapshot(index, phase_one);
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
        if unusable.len() == first.matches.len() {
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
            out.note_unexamined(pid, &first.unexamined);
            continue;
        }
        out.probed += 1;
        let read = match probe.confirm(pid, budget) {
            Confirmation::Confirmed(read) => read,
            Confirmation::Exited => {
                out.exited.insert(pid);
                continue;
            }
            Confirmation::Lost(loss, detail) => {
                out.note_loss(pid, loss, detail, &mut seen);
                out.note_unexamined(pid, &first.unexamined);
                continue;
            }
        };
        let confirmed = classify_snapshot(index, &read.entries);
        note_ineligible(&mut out, &mut seen, &confirmed.ineligible);
        let mut objects = Vec::new();
        for (key, object, group) in &confirmed.matches {
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

/// The provider-candidate keys of one snapshot, each once, with its
/// entries (for double-load evidence and the path).
fn provider_groups(entries: &[MapEntry]) -> BTreeMap<ObjectKey, Vec<&MapEntry>> {
    let mut groups: BTreeMap<ObjectKey, Vec<&MapEntry>> = BTreeMap::new();
    for entry in entries.iter().filter(|entry| is_provider_mapping(entry)) {
        groups.entry(ObjectKey::of(entry)).or_default().push(entry);
    }
    groups
}

/// Whether a group's pathname can attribute: every mapping of the object
/// must carry a usable path. `Err(DeletedMapping)` for ` (deleted)`,
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
    fn open(&mut self, pid: u32) -> Result<Self::Pin, String>;
    fn start_time(&self, pin: &Self::Pin) -> Option<u64>;
    fn still_the_same(&self, pin: &Self::Pin) -> bool;
    fn exe(&self, pid: u32) -> Option<ExeIdentity>;
    fn maps(&mut self, pid: u32, budget: &mut CaptureWorkBudget) -> Result<Vec<MapEntry>, String>;
    fn gone(&self, pid: u32) -> bool;
}

/// One confirmation: pin, exe, maps re-read, exe again, then the pin must
/// still hold and both exe reads agree. Only then does the snapshot count.
pub(crate) fn confirm_with<Io: ConfirmIo>(
    io: &mut Io,
    pid: u32,
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
    })
}

/// Production confirmation: `PidPin` (pidfd plus start time), the exe
/// metadata the caller adapter reads, and a budget-charged maps re-read.
pub(crate) struct OsConfirmIo;

impl ConfirmIo for OsConfirmIo {
    type Pin = crate::process::PidPin;

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

/// The production probe.
pub(crate) struct OsMemberProbe;

impl MemberProbe for OsMemberProbe {
    fn confirm(&mut self, pid: u32, budget: &mut CaptureWorkBudget) -> Confirmation {
        confirm_with(&mut OsConfirmIo, pid, budget)
    }
}

#[cfg(test)]
#[path = "sweep_attribution_tests.rs"]
mod tests;
