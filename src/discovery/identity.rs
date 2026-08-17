//! Pins objects — manifest-recorded or scan-discovered — to their current identity
//! without holding read leases. `check_unchanged` gives cheap, best-effort change
//! detection via `(ino, size, ctime)`; it is not a security boundary — the leased,
//! provenance-checked verification path it replaces was removed by
//! Productization Slice 1a (formerly `src/verify.rs`, restorable from history).

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{AsRawFd as _, RawFd};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Component, Path, PathBuf};

use p11scope_manifest::identity::{
    IdentityKind, MappingFileKey, ObjectIdentity, inspect_file, inspect_file_with_reader,
    mapping_file_key, mapping_file_key_in_mountinfo, open_object,
};
use p11scope_manifest::manifest::{Manifest, Resolution};
use p11scope_manifest::maps::{Device, ObjectKey};

use crate::discovery::scan::{CaptureWorkBudget, IO_CEILING_REASON, ScannedModule, Skipped};
use crate::manifest_input::{MAX_TOTAL_OBJECT_BYTES, validate_structure};
use crate::process::{MountNamespaceId, ProcessView, ProcessViewId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Pin {
    ino: u64,
    size: u64,
    ctime: (i64, i64),
}

fn pin_of(file: &std::fs::File) -> Result<Pin, String> {
    let md = file
        .metadata()
        .map_err(|error| format!("fstat failed: {error}"))?;
    Ok(Pin {
        ino: md.ino(),
        size: md.len(),
        ctime: (md.ctime(), md.ctime_nsec()),
    })
}

/// Capture-local opened-object identity. It has no stable or serialized meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PinnedObjectId(pub u32);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RawObjectInstance {
    mount_namespace: Option<MountNamespaceId>,
    key: ObjectKey,
    path: String,
}

impl RawObjectInstance {
    fn scanned(module: &ScannedModule, key: ObjectKey, path: &str) -> Option<Self> {
        Some(Self {
            mount_namespace: Some(module.mount_namespace),
            key,
            path: normalize_target_path(path)?,
        })
    }

    fn manifest(key: ObjectKey, path: String) -> Option<Self> {
        Some(Self {
            mount_namespace: None,
            key,
            path: normalize_target_path(&path)?,
        })
    }
}

fn normalize_target_path(path: &str) -> Option<String> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return None;
    }
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(component) => normalized.push(component),
            Component::Prefix(_) => return None,
        }
    }
    normalized.to_str().map(str::to_string)
}

#[derive(Debug)]
struct Entry {
    raw: RawObjectInstance,
    mapping: MappingFileKey,
    file: std::fs::File,
    pin: Pin,
    path: String,
    sha256: String,
    build_id: Option<String>,
    /// Whether this object was opened through overlayfs. This narrows the collapse
    /// heuristic but does not prove that another overlay instance resolves to the
    /// same underlying kernel inode.
    overlay: bool,
}

/// `OVERLAYFS_SUPER_MAGIC`. `ovl_statfs` reports the underlying filesystem's numbers
/// but overrides `f_type` with the overlay's own magic, so this answers "was this file
/// reached *through* an overlay mount", which is the question, and not "what is it
/// ultimately stored on".
const OVERLAYFS_SUPER_MAGIC: u64 = 0x794c_7630;

fn on_overlayfs(fd: RawFd) -> Result<bool, String> {
    let mut buf = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `fstatfs` fills `buf` for a valid fd and is only read on success.
    if unsafe { libc::fstatfs(fd, buf.as_mut_ptr()) } != 0 {
        return Err(format!(
            "fstatfs failed while classifying overlayfs: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the successful `fstatfs` above initialized `buf`.
    Ok(unsafe { buf.assume_init().f_type as u64 == OVERLAYFS_SUPER_MAGIC })
}

impl Entry {
    fn new(
        file: std::fs::File,
        pin: Pin,
        path: String,
        identity: &ObjectIdentity,
        raw: RawObjectInstance,
        mapping: MappingFileKey,
    ) -> Result<Self, String> {
        Ok(Self {
            overlay: on_overlayfs(file.as_raw_fd())?,
            raw,
            mapping,
            file,
            pin,
            path,
            // `inspect_file` always records a whole-file digest.
            sha256: identity.sha256.clone().unwrap_or_default(),
            build_id: match identity.kind {
                IdentityKind::GnuBuildId => identity.value.clone(),
                _ => None,
            },
        })
    }
}

/// What a pinned object is, for the `discovery[]` report.
#[derive(Debug, Clone, Copy)]
pub struct PinnedSummary<'a> {
    pub id: PinnedObjectId,
    pub key: ObjectKey,
    /// For scan-sourced objects this is the *target's* path: it is namespace-relative
    /// and the observer cannot open it. Attach through `attach_path_for` instead.
    pub path: &'a str,
    pub sha256: &'a str,
    pub build_id: Option<&'a str>,
    /// Always "mountinfo": incomparable identities are refused rather than downgraded.
    pub identity_source: &'static str,
    /// Reserved for bounded diagnostic context; ordinary comparable pins have none.
    pub note: Option<&'a str>,
}

/// Claims retained per accepted process view. Vectors deliberately preserve duplicate
/// claims: two tables or views may rely on the same pin/target independently.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ViewClaims {
    pub tables: Vec<PinnedObjectId>,
    pub targets: Vec<(PinnedObjectId, u64)>,
    pub pins: Vec<PinnedObjectId>,
}

impl ViewClaims {
    fn remap(&mut self, ids: &BTreeMap<PinnedObjectId, PinnedObjectId>) {
        for id in self.tables.iter_mut().chain(&mut self.pins) {
            if let Some(mapped) = ids.get(id) {
                *id = *mapped;
            }
        }
        for (id, _) in &mut self.targets {
            if let Some(mapped) = ids.get(id) {
                *id = *mapped;
            }
        }
    }

    fn remove(&mut self, ids: &BTreeSet<PinnedObjectId>) {
        self.tables.retain(|id| !ids.contains(id));
        self.targets.retain(|(id, _)| !ids.contains(id));
        self.pins.retain(|id| !ids.contains(id));
    }
}

/// A scanned process view after every raw object reference was reconciled to an opened,
/// comparable, hashed capture-local object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciledModule {
    pub scanned: ScannedModule,
    pub object: PinnedObjectId,
    /// Parallel to `scanned.tables[*].entries`.
    pub entry_objects: Vec<Vec<PinnedObjectId>>,
}

/// Every object opened, identity-matched, hashed, and pinned by a capture-local ID.
/// Raw mapping keys remain lookup inputs until reconciliation, never attach identity.
/// No read leases are held:
/// `check_unchanged` is a cheap, best-effort check, not a guarantee that the bytes
/// cannot change between the check and Aya's attach.
#[derive(Debug)]
pub struct PinnedObjects {
    by_id: BTreeMap<PinnedObjectId, Entry>,
    raw_to_id: BTreeMap<RawObjectInstance, PinnedObjectId>,
    rejected_keys: BTreeSet<ObjectKey>,
    ambiguous_keys: BTreeSet<ObjectKey>,
    ambiguity_published: BTreeSet<ObjectKey>,
    ownership: BTreeMap<ProcessViewId, ViewClaims>,
    next_id: u32,
    /// Latched by `check_unchanged` the first time any pin differs.
    changed: std::cell::Cell<bool>,
}

impl PinnedObjects {
    /// An empty set: no objects pinned. For rendering tests that have no live
    /// process to pin objects from.
    pub fn empty() -> Self {
        Self {
            by_id: BTreeMap::new(),
            raw_to_id: BTreeMap::new(),
            rejected_keys: BTreeSet::new(),
            ambiguous_keys: BTreeSet::new(),
            ambiguity_published: BTreeSet::new(),
            ownership: BTreeMap::new(),
            next_id: 0,
            changed: std::cell::Cell::new(false),
        }
    }

    /// Folds another pin set into this capture. Exact comparable identities merge;
    /// an equal raw `ObjectKey` with any unequal full identity rejects the whole group.
    pub fn absorb(&mut self, other: PinnedObjects) -> Vec<Skipped> {
        let mut entries = other.by_id;
        let mut raws: BTreeMap<PinnedObjectId, Vec<RawObjectInstance>> = BTreeMap::new();
        for (raw, id) in other.raw_to_id {
            raws.entry(id).or_default().push(raw);
        }
        let mut skipped = Vec::new();
        let mut id_map = BTreeMap::new();
        for (old_id, mut instances) in raws {
            let Some(mut entry) = entries.remove(&old_id) else {
                continue;
            };
            let raw = instances.remove(0);
            entry.raw = raw.clone();
            let id = self.insert_entry(entry, &mut skipped);
            if let Some(id) = id {
                id_map.insert(old_id, id);
                for raw in instances {
                    self.raw_to_id.insert(raw, id);
                }
            }
        }
        for key in other.rejected_keys {
            self.reject_observation(key);
        }
        self.ambiguous_keys.extend(other.ambiguous_keys);
        self.ambiguity_published.extend(other.ambiguity_published);
        for (view, claims) in other.ownership {
            let ours = self.ownership.entry(view).or_default();
            ours.tables.extend(
                claims
                    .tables
                    .into_iter()
                    .filter_map(|id| id_map.get(&id).copied())
                    .filter(|id| self.by_id.contains_key(id)),
            );
            ours.targets
                .extend(claims.targets.into_iter().filter_map(|(id, offset)| {
                    let id = id_map.get(&id).copied()?;
                    self.by_id.contains_key(&id).then_some((id, offset))
                }));
            ours.pins.extend(
                claims
                    .pins
                    .into_iter()
                    .filter_map(|id| id_map.get(&id).copied())
                    .filter(|id| self.by_id.contains_key(id)),
            );
        }
        self.changed.set(self.changed.get() || other.changed.get());
        self.publish_ambiguities(&mut skipped);
        skipped
    }

    /// The path Aya reopens for this object: an fd this capture holds, never a name
    /// resolved again through a namespace that may not mean the same file.
    pub fn attach_path_for(&self, id: PinnedObjectId) -> Result<PathBuf, String> {
        self.by_id
            .get(&id)
            .map(|entry| PathBuf::from(format!("/proc/self/fd/{}", entry.file.as_raw_fd())))
            .ok_or_else(|| format!("object {id:?} was not pinned"))
    }

    /// Every pinned object, for `discovery[]`.
    pub fn pinned(&self) -> impl Iterator<Item = PinnedSummary<'_>> {
        self.by_id.iter().map(|(id, entry)| PinnedSummary {
            id: *id,
            key: entry.raw.key,
            path: &entry.path,
            sha256: &entry.sha256,
            build_id: entry.build_id.as_deref(),
            identity_source: "mountinfo",
            note: None,
        })
    }

    pub fn view_claims(&self, view: ProcessViewId) -> Option<&ViewClaims> {
        self.ownership.get(&view)
    }

    /// Retires one accepted process generation without disturbing another view or a
    /// manifest that still owns the same opened object. Returns the exact claims that
    /// were removed so the caller can rebuild its plan from the remaining modules.
    pub fn remove_view(&mut self, view: ProcessViewId) -> Option<ViewClaims> {
        let removed = self.ownership.remove(&view)?;
        let candidates: BTreeSet<_> = removed
            .tables
            .iter()
            .chain(removed.targets.iter().map(|(id, _)| id))
            .chain(&removed.pins)
            .copied()
            .collect();
        let retained: BTreeSet<_> = self
            .ownership
            .values()
            .flat_map(|claims| {
                claims
                    .tables
                    .iter()
                    .chain(claims.targets.iter().map(|(id, _)| id))
                    .chain(&claims.pins)
            })
            .copied()
            .chain(
                self.raw_to_id
                    .iter()
                    .filter_map(|(raw, id)| raw.mount_namespace.is_none().then_some(*id)),
            )
            .collect();
        let unowned: BTreeSet<_> = candidates.difference(&retained).copied().collect();
        self.by_id.retain(|id, _| !unowned.contains(id));
        self.raw_to_id.retain(|_, id| !unowned.contains(id));
        Some(removed)
    }

    /// The one pin opened for a manifest object before it is absorbed into the
    /// capture set. Used only to compare that opened object with scan-owned pins.
    pub fn id_for_path(&self, path: &str) -> Option<PinnedObjectId> {
        let path = normalize_target_path(path)?;
        let mut ids = self.raw_to_id.iter().filter_map(|(raw, id)| {
            (raw.mount_namespace.is_none() && raw.path == path).then_some(*id)
        });
        let first = ids.next()?;
        ids.next().is_none().then_some(first)
    }

    /// Resolves a manifest record only through the exact raw instance established
    /// when that record's path was opened. A bare raw key is never enough.
    pub fn id_for_manifest(&self, key: ObjectKey, path: &str) -> Option<PinnedObjectId> {
        self.raw_to_id
            .get(&RawObjectInstance::manifest(key, path.to_string())?)
            .copied()
    }

    /// Exact ordinary-file equality between two already opened, hashed pin sets.
    pub fn exactly_matches(
        &self,
        id: PinnedObjectId,
        other: &Self,
        other_id: PinnedObjectId,
    ) -> bool {
        self.by_id
            .get(&id)
            .zip(other.by_id.get(&other_id))
            .is_some_and(|(left, right)| ordinary_identity_equal(left, right))
    }

    /// Exact equality for target sets whose IDs belong to separate pin stores.
    /// Numeric IDs are never compared across stores; the ordered key is the same
    /// complete opened-file identity used by `exactly_matches`, plus the offset.
    pub fn exactly_same_targets(
        &self,
        targets: &BTreeSet<(PinnedObjectId, u64)>,
        other: &Self,
        other_targets: &BTreeSet<(PinnedObjectId, u64)>,
    ) -> bool {
        let keys = |pinned: &Self, targets: &BTreeSet<(PinnedObjectId, u64)>| {
            let keys: Option<BTreeSet<_>> = targets
                .iter()
                .map(|(id, offset)| {
                    let entry = pinned.by_id.get(id)?;
                    (!entry.sha256.is_empty())
                        .then(|| (entry.mapping, entry.pin, entry.sha256.clone(), *offset))
                })
                .collect();
            keys.filter(|keys| keys.len() == targets.len())
        };
        keys(self, targets)
            .zip(keys(other, other_targets))
            .is_some_and(|(ours, theirs)| ours == theirs)
    }

    pub fn id_for_scanned(
        &self,
        module: &ScannedModule,
        key: ObjectKey,
        path: &str,
    ) -> Option<PinnedObjectId> {
        self.raw_to_id
            .get(&RawObjectInstance::scanned(module, key, path)?)
            .copied()
    }

    pub fn summary(&self, id: PinnedObjectId) -> Option<PinnedSummary<'_>> {
        let entry = self.by_id.get(&id)?;
        Some(PinnedSummary {
            id,
            key: entry.raw.key,
            path: &entry.path,
            sha256: &entry.sha256,
            build_id: entry.build_id.as_deref(),
            identity_source: "mountinfo",
            note: None,
        })
    }

    /// `Ok(true)` when every pinned object still has the `(ino, size, ctime)` seen
    /// at pinning; `Ok(false)` when any changed (sticky: once seen, every later
    /// call is `Ok(false)` without re-checking); `Err` only when `fstat` itself fails.
    pub fn check_unchanged(&self) -> Result<bool, String> {
        if self.changed.get() {
            return Ok(false);
        }
        for entry in self.by_id.values() {
            if pin_of(&entry.file).map_err(|e| format!("{}: {e}", entry.path))? != entry.pin {
                self.changed.set(true);
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether any `check_unchanged` so far saw a pinned object change.
    pub fn provider_changed(&self) -> bool {
        self.changed.get()
    }

    fn insert_entry(&mut self, entry: Entry, skipped: &mut Vec<Skipped>) -> Option<PinnedObjectId> {
        let key = entry.raw.key;
        if self.rejected_keys.contains(&key) {
            self.ambiguous_keys.insert(key);
            return None;
        }
        let same_key: Vec<PinnedObjectId> = self
            .by_id
            .iter()
            .filter_map(|(id, known)| (known.raw.key == key).then_some(*id))
            .collect();
        if let Some(id) = same_key
            .iter()
            .copied()
            .find(|id| ordinary_identity_equal(&self.by_id[id], &entry))
        {
            self.raw_to_id.insert(entry.raw, id);
            return Some(id);
        }
        if let Some(id) = same_key
            .iter()
            .copied()
            .find(|id| overlay_identity_equal(&self.by_id[id], &entry))
        {
            skipped.push(overlay_uncertainty(&entry, &self.by_id[&id]));
            self.raw_to_id.insert(entry.raw, id);
            return Some(id);
        }
        if !same_key.is_empty() {
            self.reject_key(key);
            return None;
        }
        let id = PinnedObjectId(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("capture object id overflow");
        self.raw_to_id.insert(entry.raw.clone(), id);
        self.by_id.insert(id, entry);
        Some(id)
    }

    fn reject_key(&mut self, key: ObjectKey) {
        self.rejected_keys.insert(key);
        let ids: BTreeSet<PinnedObjectId> = self
            .by_id
            .iter()
            .filter_map(|(id, entry)| (entry.raw.key == key).then_some(*id))
            .collect();
        self.by_id.retain(|id, _| !ids.contains(id));
        self.raw_to_id
            .retain(|raw, id| raw.key != key && !ids.contains(id));
        for claims in self.ownership.values_mut() {
            claims.remove(&ids);
        }
        if !ids.is_empty() {
            self.ambiguous_keys.insert(key);
        }
    }

    /// Records another member of a group that is already known only as rejected.
    /// The first unavailable observation establishes fail-closed state; the second
    /// establishes the finite collision-group ambiguity, once per raw key.
    fn reject_observation(&mut self, key: ObjectKey) {
        let repeated = self.rejected_keys.contains(&key);
        self.reject_key(key);
        if repeated {
            self.ambiguous_keys.insert(key);
        }
    }

    fn publish_ambiguities(&mut self, skipped: &mut Vec<Skipped>) {
        for key in self
            .ambiguous_keys
            .difference(&self.ambiguity_published)
            .copied()
            .collect::<Vec<_>>()
        {
            self.ambiguity_published.insert(key);
            skipped.push(ambiguous_identity_skip());
        }
    }
}

fn ambiguous_identity_skip() -> Skipped {
    Skipped {
        subject: "discovery subject".into(),
        reason: "physical identity is ambiguous: equal mapping keys had unequal or unavailable full opened-file identities; the collision group was not attached".into(),
    }
}

fn ordinary_identity_equal(left: &Entry, right: &Entry) -> bool {
    left.mapping == right.mapping
        && left.pin == right.pin
        && !left.sha256.is_empty()
        && left.sha256 == right.sha256
}

fn overlay_identity_equal(left: &Entry, right: &Entry) -> bool {
    left.overlay
        && right.overlay
        && left.pin == right.pin
        && !left.sha256.is_empty()
        && left.sha256 == right.sha256
}

fn overlay_uncertainty(entry: &Entry, kept: &Entry) -> Skipped {
    Skipped {
        subject: format!("{} ({:?})", entry.path, entry.raw.key),
        reason: format!(
            "mapping {:?} was collapsed onto {:?} by the overlayfs + inode metadata + \
             SHA-256 heuristic, which cannot prove physical identity across overlay \
             instances; calls through a distinct byte-identical instance would not be probed",
            entry.raw.key, kept.raw.key,
        ),
    }
}

/// The complete comparable mapping identity of an opened fd. `mapping_file_key`
/// resolves fdinfo's mount ID through mountinfo, so btrfs subvolumes and overlay are
/// compared in the same representation `/proc/<pid>/maps` uses. Missing mount data is
/// incomparable and fails closed; `st_dev` is never substituted.
fn identity_of(file: &std::fs::File) -> Result<MappingFileKey, String> {
    mapping_file_key(file).map_err(|error| format!("mapping identity unavailable: {error}"))
}

fn identity_of_in_mountinfo(
    file: &std::fs::File,
    mountinfo: &str,
) -> Result<MappingFileKey, String> {
    mapping_file_key_in_mountinfo(file, mountinfo)
        .map_err(|error| format!("mapping identity unavailable: {error}"))
}

fn object_key(mapping: MappingFileKey) -> ObjectKey {
    ObjectKey {
        device: Device {
            major: mapping.device_major,
            minor: mapping.device_minor,
        },
        inode: mapping.inode,
    }
}

/// Structural validation + open + size cap + identity match + executable-offset check.
/// Opens, identifies, and pins every object. Errors are aggregated so an
/// operator sees every stale or malformed target in one run.
pub fn pin_manifest_objects(m: &Manifest) -> Result<PinnedObjects, Vec<String>> {
    let mut problems = validate_structure(m);
    if !problems.is_empty() {
        return Err(problems);
    }

    let mut pinned = Vec::new();
    let mut total_object_bytes = 0u64;
    for object in &m.objects {
        if !object.identity.reusable {
            problems.push(format!(
                "{}: manifest identity is not reusable ({})",
                object.path,
                object
                    .identity
                    .note
                    .as_deref()
                    .unwrap_or("no identity recorded")
            ));
            continue;
        }
        let file = match open_object(Path::new(&object.path)) {
            Ok(file) => file,
            Err(error) => {
                problems.push(format!(
                    "{}: cannot open the file now ({error})",
                    object.path
                ));
                continue;
            }
        };
        let pin = match pin_of(&file) {
            Ok(pin) => pin,
            Err(error) => {
                problems.push(format!("{}: {error}", object.path));
                continue;
            }
        };
        let len = pin.size;
        let Some(total) = total_object_bytes.checked_add(len) else {
            problems.push("total object size overflowed u64".into());
            continue;
        };
        if total > MAX_TOTAL_OBJECT_BYTES {
            problems.push(format!(
                "manifest objects total more than the {MAX_TOTAL_OBJECT_BYTES}-byte limit"
            ));
            continue;
        }
        total_object_bytes = total;
        pinned.push((object, file, pin));
    }
    if !problems.is_empty() {
        return Err(problems);
    }

    let mut opened = BTreeMap::new();
    for (object, file, pin) in pinned {
        let inspected = match inspect_file(&file) {
            Ok(inspected) => inspected,
            Err(error) => {
                problems.push(format!(
                    "{}: cannot identify the file now ({error})",
                    object.path
                ));
                continue;
            }
        };
        // The pin was taken before the bytes were hashed; a write that lands
        // during the hash must not become the baseline the capture trusts.
        match pin_of(&file) {
            Ok(after) if after == pin => {}
            Ok(_) => {
                problems.push(format!(
                    "{}: file changed while it was being identified — retry",
                    object.path
                ));
                continue;
            }
            Err(error) => {
                problems.push(format!("{}: {error}", object.path));
                continue;
            }
        }
        if inspected.identity.kind != object.identity.kind
            || inspected.identity.value != object.identity.value
            || inspected.identity.sha256 != object.identity.sha256
        {
            problems.push(format!(
                "{}: identity changed since discovery (manifest {:?} {} sha256 {}, current {:?} {} sha256 {}) — re-run `p11scope-discover`",
                object.path,
                object.identity.kind,
                object.identity.value.as_deref().unwrap_or("-"),
                object.identity.sha256.as_deref().unwrap_or("-"),
                inspected.identity.kind,
                inspected.identity.value.as_deref().unwrap_or("-"),
                inspected.identity.sha256.as_deref().unwrap_or("-"),
            ));
            continue;
        }
        opened.insert(object.id, (object.path.clone(), file, inspected, pin));
    }

    for surface in &m.surfaces {
        for function in &surface.functions {
            let Resolution::Resolved {
                object,
                file_offset,
            } = function.resolution
            else {
                continue;
            };
            if let Some((path, _, inspected, _)) = opened.get(&object)
                && !inspected.contains_executable_offset(file_offset)
            {
                problems.push(format!(
                    "{}: {}+{file_offset:#x} is outside every executable ELF segment",
                    function.name, path
                ));
            }
        }
    }

    if !problems.is_empty() {
        return Err(problems);
    }
    let mut result = PinnedObjects::empty();
    for (path, file, inspected, pin) in opened.into_values() {
        let mapping = match identity_of(&file) {
            Ok(found) => found,
            Err(error) => {
                problems.push(format!("{path}: {error}"));
                continue;
            }
        };
        let key = object_key(mapping);
        let Some(raw) = RawObjectInstance::manifest(key, path.clone()) else {
            problems.push(format!("{path}: object path cannot be normalized"));
            continue;
        };
        let entry = match Entry::new(file, pin, path.clone(), &inspected.identity, raw, mapping) {
            Ok(entry) => entry,
            Err(error) => {
                problems.push(format!("{path}: {error}"));
                continue;
            }
        };
        let mut skipped = Vec::new();
        if result.insert_entry(entry, &mut skipped).is_none() {
            problems.extend(
                skipped
                    .into_iter()
                    .map(|skip| format!("{path}: {}", skip.reason)),
            );
        }
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    Ok(result)
}

/// Opens, identity-checks, hashes once and pins every object the scan named. Objects
/// that cannot be pinned are returned as `Skipped`, never as errors: one unusable
/// dependency must not lose the whole capture (spec §4.10). `Err` is reserved for the
/// case that makes the whole result meaningless — the target exiting, after which a
/// report could be claiming objects pinned from a recycled pid.
///
/// `limits` are the scan's own byte caps and bind here too: hashing reads each object
/// whole, and the object set comes from the target's mappings, so an unbounded pin
/// would let a target turn a bounded memory scan into unbounded reads on the observer.
pub fn pin_scanned_objects(
    pid: u32,
    modules: &[ScannedModule],
    budget: &mut CaptureWorkBudget,
) -> Result<(PinnedObjects, Vec<Skipped>), String> {
    let id = modules
        .first()
        .map_or(ProcessViewId(0), |module| module.view);
    let view = ProcessView::open(id, pid)?;
    let (local, mut skipped) = pin_scanned_view_objects(&view, modules, budget)?;
    let mut aggregate = PinnedObjects::empty();
    skipped.extend(aggregate.absorb(local));
    Ok((aggregate, skipped))
}

pub fn pin_scanned_view_objects(
    view: &ProcessView,
    modules: &[ScannedModule],
    budget: &mut CaptureWorkBudget,
) -> Result<(PinnedObjects, Vec<Skipped>), String> {
    // Both the table-owning modules and every object a table entry points into: an
    // entry may land in a dependency the module itself only forwards to.
    let mut wanted = BTreeSet::new();
    let mut skipped = Vec::new();
    for module in modules {
        if module.view != view.id() || module.mount_namespace != view.mount_namespace() {
            return Err("scan result belongs to a different process view".into());
        }
        match RawObjectInstance::scanned(module, module.key, &module.path) {
            Some(raw) => {
                wanted.insert(raw);
            }
            None => skipped.push(Skipped {
                subject: module.path.clone(),
                reason: "target path cannot be normalized; object was not pinned".into(),
            }),
        }
        for entry in module.tables.iter().flat_map(|table| &table.entries) {
            match RawObjectInstance::scanned(module, entry.object, &entry.object_path) {
                Some(raw) => {
                    wanted.insert(raw);
                }
                None => skipped.push(Skipped {
                    subject: entry.name.to_string(),
                    reason: "target path cannot be normalized; entry was not pinned".into(),
                }),
            }
        }
    }

    let exited = || "process generation exited during discovery".to_string();
    let mut pinned = PinnedObjects::empty();
    if wanted.is_empty() {
        if !view.still_the_same() {
            return Err(exited());
        }
        return Ok((pinned, skipped));
    }
    for raw in wanted {
        // Opening through /proc/<pid>/root is a per-pid action (spec §4.5).
        if !view.still_the_same() {
            return Err(exited());
        }
        let candidate = pin_scanned_object(view, raw.clone(), budget);
        record_scanned_candidate(&mut pinned, raw, candidate, &mut skipped);
    }
    if !view.still_the_same() {
        return Err(exited());
    }
    Ok((pinned, skipped))
}

fn record_scanned_candidate(
    pinned: &mut PinnedObjects,
    raw: RawObjectInstance,
    candidate: Result<Entry, String>,
    skipped: &mut Vec<Skipped>,
) {
    match candidate {
        Ok(entry) => {
            pinned.insert_entry(entry, skipped);
        }
        Err(reason) => {
            // A missing mapping identity or digest makes every equal raw-key
            // observation incomparable. Remember the failed member so a candidate
            // from another process view cannot become receiver-wins authority.
            pinned.reject_observation(raw.key);
            skipped.push(Skipped {
                subject: raw.path,
                reason,
            });
        }
    }
}

/// Resolves every process-view-local mapping reference to a capture-local opened
/// object. Ordinary identities merge only when their complete mapping identity,
/// pin metadata, and digest agree. The one pre-existing exception is the bounded
/// overlayfs heuristic, which preserves all process views and publishes uncertainty.
pub fn reconcile_scanned_modules(
    modules: &[ScannedModule],
    pinned: &mut PinnedObjects,
) -> (Vec<ReconciledModule>, usize, Vec<Skipped>) {
    let mut first: BTreeMap<(Pin, &str), PinnedObjectId> = BTreeMap::new();
    let mut canonical: BTreeMap<PinnedObjectId, PinnedObjectId> = BTreeMap::new();
    let mut lost = Vec::new();
    for (id, entry) in &pinned.by_id {
        if entry.sha256.is_empty() || !entry.overlay {
            continue;
        }
        match first.entry((entry.pin, entry.sha256.as_str())) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(*id);
            }
            std::collections::btree_map::Entry::Occupied(kept) => {
                let kept = *kept.get();
                canonical.insert(*id, kept);
                lost.push(overlay_uncertainty(entry, &pinned.by_id[&kept]));
            }
        }
    }
    for id in pinned.raw_to_id.values_mut() {
        if let Some(kept) = canonical.get(id) {
            *id = *kept;
        }
    }
    for claims in pinned.ownership.values_mut() {
        claims.remap(&canonical);
    }
    for id in canonical.keys() {
        pinned.by_id.remove(id);
    }

    let mut reconciled = Vec::new();
    for module in modules {
        let Some(object) = pinned.id_for_scanned(module, module.key, &module.path) else {
            lost.push(Skipped {
                subject: module.path.clone(),
                reason: "module has no comparable pinned identity; it was not attached".into(),
            });
            continue;
        };
        let mut scanned = module.clone();
        let mut entry_objects = Vec::with_capacity(scanned.tables.len());
        for table in &mut scanned.tables {
            let mut ids = Vec::with_capacity(table.entries.len());
            let mut kept = Vec::with_capacity(table.entries.len());
            for entry in std::mem::take(&mut table.entries) {
                match pinned.id_for_scanned(module, entry.object, &entry.object_path) {
                    Some(id) => {
                        ids.push(id);
                        kept.push(entry);
                    }
                    None => {
                        let skip = Skipped {
                            subject: entry.name.to_string(),
                            reason: format!(
                                "{} could not be reconciled to a comparable pinned object; entry was not attached",
                                entry.object_path
                            ),
                        };
                        table.unpinned.push(skip.clone());
                        lost.push(skip);
                    }
                }
            }
            table.entries = kept;
            entry_objects.push(ids);
        }
        let claims = pinned.ownership.entry(module.view).or_default();
        claims
            .tables
            .extend(std::iter::repeat_n(object, scanned.tables.len()));
        claims.pins.push(object);
        for (table, ids) in scanned.tables.iter().zip(&entry_objects) {
            for (entry, id) in table.entries.iter().zip(ids) {
                claims.targets.push((*id, entry.file_offset));
                claims.pins.push(*id);
            }
        }
        reconciled.push(ReconciledModule {
            scanned,
            object,
            entry_objects,
        });
    }
    (reconciled, canonical.len(), lost)
}

fn pin_scanned_object(
    view: &ProcessView,
    raw: RawObjectInstance,
    budget: &mut CaptureWorkBudget,
) -> Result<Entry, String> {
    // The target's own filesystem view: a container's object is never copied out.
    let (file, mountinfo) = view.open_then_mountinfo(|| {
        open_object(Path::new(&format!("/proc/{}/root{}", view.pid(), raw.path)))
    })?;
    let found = identity_of_in_mountinfo(&file, &mountinfo)?;
    if object_key(found) != raw.key {
        return Err(format!(
            "identity_mismatch: the mapping is {:?} but {} now opens as {:?} \
             (compared via mountinfo)",
            raw.key,
            raw.path,
            object_key(found),
        ));
    }
    let before = pin_of(&file)?;
    // The per-file rule can be decided from metadata. Aggregate admission happens
    // incrementally at the reader below, and a partial digest is never trusted.
    if before.size > budget.limits().per_object_bytes {
        let limits = budget.limits();
        return Err(format!(
            "too_large ({} bytes; per-object cap is {})",
            before.size, limits.per_object_bytes,
        ));
    }
    let mut operation_bytes = 0u64;
    let inspected = inspect_file_with_reader(&file, |file, bytes, offset| {
        let allowed = budget.allowed_io(operation_bytes, bytes.len());
        if allowed == 0 {
            return Err(std::io::Error::other(IO_CEILING_REASON));
        }
        let read = file.read_at(&mut bytes[..allowed], offset)?;
        budget.record_io(read);
        operation_bytes += read as u64;
        Ok(read)
    })?;
    // The pin was taken before the bytes were hashed; a write that lands during the
    // hash must not become the baseline the capture trusts.
    if pin_of(&file)? != before {
        return Err("file changed while it was being identified — retry".into());
    }
    Entry::new(
        file,
        before,
        raw.path.clone(),
        &inspected.identity,
        raw,
        found,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::scan::{ScannedEntry, ScannedTable};

    const SHA: &str = "b4e608e4";
    /// The inode and the two overlay device numbers a two-container docker run
    /// really produced (`102:56317450` and `104:56317450`).
    const INODE: u64 = 56_317_450;
    const PATH: &str = "/usr/lib/softhsm/libsofthsm2.so";

    fn overlay(minor: u64) -> ObjectKey {
        ObjectKey {
            device: Device { major: 0, minor },
            inode: INODE,
        }
    }

    fn module(key: ObjectKey) -> ScannedModule {
        ScannedModule {
            view: ProcessViewId(key.device.minor as u32),
            mount_namespace: MountNamespaceId {
                device: 1,
                inode: key.device.minor,
            },
            key,
            path: PATH.into(),
            exports: vec!["C_GetFunctionList".into()],
            tables: vec![ScannedTable {
                version: (2, 40),
                walk: "full",
                entries: vec![ScannedEntry {
                    name: "C_Initialize",
                    object: key,
                    object_path: PATH.into(),
                    file_offset: 0x1000,
                }],
                null_entries: vec![],
                unpinned: vec![],
                address: 0x7000,
            }],
            interfaces: vec![],
        }
    }

    /// A pin set as `pin_scanned_objects` builds it, but written out directly: the
    /// two mappings this is about live in two mount namespaces, so reaching this
    /// state through the real scan needs two containers. Each entry is
    /// `(key, sha256, ctime)`; the pin's inode is the key's, as a real pin's always is.
    fn pin_set(entries: &[(ObjectKey, &str, i64)], overlay: bool) -> PinnedObjects {
        let mut result = PinnedObjects::empty();
        for (key, sha, ctime) in entries {
            let raw = RawObjectInstance {
                mount_namespace: Some(MountNamespaceId {
                    device: 1,
                    inode: key.device.minor,
                }),
                key: *key,
                path: PATH.into(),
            };
            let mapping = MappingFileKey {
                mount_id: key.device.minor + 1,
                device_major: key.device.major,
                device_minor: key.device.minor,
                inode: key.inode,
            };
            let entry = Entry {
                raw,
                mapping,
                file: std::fs::File::open("/dev/null").unwrap(),
                pin: Pin {
                    ino: key.inode,
                    size: 4096,
                    ctime: (*ctime, 7),
                },
                path: PATH.into(),
                sha256: (*sha).into(),
                build_id: None,
                overlay,
            };
            result.insert_entry(entry, &mut Vec::new());
        }
        result
    }

    /// Objects opened through a container's overlay mount — the shape this is about.
    fn pins(entries: &[(ObjectKey, &str, i64)]) -> PinnedObjects {
        pin_set(entries, true)
    }

    /// The same objects, opened on a real filesystem rather than through an overlay.
    fn image_pins(entries: &[(ObjectKey, &str, i64)]) -> PinnedObjects {
        pin_set(entries, false)
    }

    fn unavailable_pins(key: ObjectKey, views: &[u64]) -> (PinnedObjects, Vec<Skipped>) {
        let mut raw = image_pins(&[(key, "aaaaaaaa", 1)])
            .by_id
            .pop_first()
            .unwrap()
            .1
            .raw;
        let mut pins = PinnedObjects::empty();
        let mut skipped = Vec::new();
        for view in views {
            raw.mount_namespace = Some(MountNamespaceId {
                device: 1,
                inode: *view,
            });
            record_scanned_candidate(
                &mut pins,
                raw.clone(),
                Err(format!("/private/view-{view}.so: unavailable")),
                &mut skipped,
            );
        }
        (pins, skipped)
    }

    fn ambiguity_count(skipped: &[Skipped]) -> usize {
        skipped
            .iter()
            .filter(|skip| skip.reason.contains("physical identity is ambiguous"))
            .count()
    }

    #[test]
    fn fstatfs_failure_is_an_error_not_non_overlay() {
        let error = on_overlayfs(-1).expect_err("an invalid fd must not mean non-overlay");
        assert!(error.contains("fstatfs failed"), "{error}");
    }

    #[test]
    fn raw_grouping_normalizes_path_aliases_but_keeps_mount_namespaces_distinct() {
        let key = overlay(102);
        let mut plain = module(key);
        plain.path = "/usr/lib/softhsm/libsofthsm2.so".into();
        let mut alias = plain.clone();
        alias.path = "/usr/lib/./softhsm/../softhsm/libsofthsm2.so".into();
        assert_eq!(
            RawObjectInstance::scanned(&plain, key, &plain.path),
            RawObjectInstance::scanned(&alias, key, &alias.path)
        );

        alias.mount_namespace.inode += 1;
        assert_ne!(
            RawObjectInstance::scanned(&plain, key, &plain.path),
            RawObjectInstance::scanned(&alias, key, &alias.path)
        );
    }

    #[test]
    fn absorbing_incomparable_same_key_candidates_rejects_the_collision_group() {
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: INODE,
        };
        let mut first = image_pins(&[(key, "aaaaaaaa", 1)]);
        let mut second = image_pins(&[(key, "aaaaaaaa", 1)]);
        second.by_id.values_mut().next().unwrap().mapping.mount_id += 1;

        let skipped = first.absorb(second);

        assert_eq!(
            first.pinned().count(),
            0,
            "receiver-wins would let one incomparable fd lend its offsets to the other view"
        );
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert!(skipped[0].reason.contains("physical identity is ambiguous"));
    }

    #[test]
    fn an_unavailable_identity_rejects_its_whole_raw_key_group() {
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: INODE,
        };
        for unavailable_first in [false, true] {
            let mut source = image_pins(&[(key, "aaaaaaaa", 1)]);
            let entry = source.by_id.pop_first().unwrap().1;
            let raw = entry.raw.clone();
            let mut pinned = PinnedObjects::empty();
            let mut skipped = Vec::new();
            if unavailable_first {
                record_scanned_candidate(
                    &mut pinned,
                    raw.clone(),
                    Err("mapping identity unavailable".into()),
                    &mut skipped,
                );
            }
            record_scanned_candidate(&mut pinned, raw.clone(), Ok(entry), &mut skipped);
            if !unavailable_first {
                record_scanned_candidate(
                    &mut pinned,
                    raw,
                    Err("mapping identity unavailable".into()),
                    &mut skipped,
                );
            }
            assert_eq!(
                pinned.pinned().count(),
                0,
                "an unavailable group member left an attachable candidate"
            );
            let mut aggregate = PinnedObjects::empty();
            skipped.extend(aggregate.absorb(pinned));
            assert_eq!(aggregate.pinned().count(), 0);
            assert!(
                skipped
                    .iter()
                    .any(|skip| skip.reason.contains("physical identity is ambiguous")),
                "the rejected collision group needs bounded ambiguity evidence: {skipped:?}"
            );
        }
    }

    #[test]
    fn two_unavailable_same_key_observations_emit_one_bounded_ambiguity() {
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: INODE,
        };
        let raw = image_pins(&[(key, "aaaaaaaa", 1)])
            .by_id
            .pop_first()
            .unwrap()
            .1
            .raw;
        let mut aggregate = PinnedObjects::empty();
        let mut skipped = Vec::new();
        for view in 1..=2 {
            let mut pins = PinnedObjects::empty();
            let mut raw = raw.clone();
            raw.mount_namespace = Some(MountNamespaceId {
                device: 1,
                inode: view,
            });
            record_scanned_candidate(
                &mut pins,
                raw,
                Err(format!(
                    "/private/view-{view}.so: ROUND1_UNAVAILABLE_ERROR_{view}"
                )),
                &mut skipped,
            );
            skipped.extend(aggregate.absorb(pins));
        }

        assert_eq!(aggregate.pinned().count(), 0);
        let ambiguity: Vec<_> = skipped
            .iter()
            .filter(|skip| skip.reason.contains("physical identity is ambiguous"))
            .collect();
        assert_eq!(
            ambiguity.len(),
            1,
            "the second unavailable member must emit exactly one collision category: {skipped:?}"
        );
        let public = crate::render::capture_skipped_out(ambiguity[0]);
        let rendered = serde_json::to_string(&public).unwrap();
        assert_eq!(
            public.reason,
            "physical identity is ambiguous; the collision group was not attached"
        );
        for private in ["/private/", "ROUND1_UNAVAILABLE_ERROR", "view-1", "view-2"] {
            assert!(!rendered.contains(private), "leaked {private}: {rendered}");
        }
    }

    #[test]
    fn aggregate_rejection_plus_a_later_local_collision_publishes_once() {
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: INODE,
        };
        let mut aggregate = PinnedObjects::empty();
        let mut skipped = Vec::new();

        let (first, first_skips) = unavailable_pins(key, &[1]);
        skipped.extend(first_skips);
        skipped.extend(aggregate.absorb(first));
        assert_eq!(aggregate.pinned().count(), 0);
        assert_eq!(ambiguity_count(&skipped), 0);

        let (later, later_skips) = unavailable_pins(key, &[2, 3]);
        skipped.extend(later_skips);
        skipped.extend(aggregate.absorb(later));

        assert_eq!(aggregate.pinned().count(), 0);
        assert_eq!(
            ambiguity_count(&skipped),
            1,
            "a local collision must not publish separately from the aggregate: {skipped:?}"
        );
    }

    #[test]
    fn separate_later_view_collisions_publish_once_for_the_capture() {
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: INODE,
        };
        let mut aggregate = PinnedObjects::empty();
        let mut skipped = Vec::new();

        for views in [[10, 11], [20, 21]] {
            let (local, local_skips) = unavailable_pins(key, &views);
            skipped.extend(local_skips);
            skipped.extend(aggregate.absorb(local));
        }

        assert_eq!(aggregate.pinned().count(), 0);
        assert_eq!(
            ambiguity_count(&skipped),
            1,
            "each per-view set must not publish the capture-wide category: {skipped:?}"
        );
    }

    #[test]
    fn distinct_unavailable_collision_keys_each_publish_once() {
        let first = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: INODE,
        };
        let second = ObjectKey {
            device: Device { major: 8, minor: 2 },
            inode: INODE + 1,
        };
        let mut aggregate = PinnedObjects::empty();
        let mut skipped = Vec::new();
        for (key, views) in [(first, [1, 2]), (second, [3, 4])] {
            let (local, local_skips) = unavailable_pins(key, &views);
            skipped.extend(local_skips);
            skipped.extend(aggregate.absorb(local));
        }

        assert_eq!(ambiguity_count(&skipped), 2, "{skipped:?}");
    }

    #[test]
    fn same_raw_key_overlay_candidates_keep_the_explicit_partial_exception() {
        let key = ObjectKey {
            device: Device {
                major: 0,
                minor: 102,
            },
            inode: INODE,
        };
        let mut first = pins(&[(key, SHA, 1)]);
        let mut second = pins(&[(key, SHA, 1)]);
        second.by_id.values_mut().next().unwrap().mapping.mount_id += 1;

        let skipped = first.absorb(second);

        assert_eq!(first.pinned().count(), 1, "the overlay exception regressed");
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert!(
            skipped[0]
                .reason
                .contains("cannot prove physical identity across overlay instances"),
            "{skipped:?}"
        );
    }

    #[test]
    fn absorbing_reconciled_view_claims_remaps_their_capture_local_ids() {
        let real = |minor| ObjectKey {
            device: Device { major: 8, minor },
            inode: INODE + minor,
        };
        let first_module = module(real(1));
        let mut first = image_pins(&[(real(1), "aaaaaaaa", 1)]);
        reconcile_scanned_modules(std::slice::from_ref(&first_module), &mut first);

        let incoming_module = module(real(17));
        let mut incoming = image_pins(&[(real(17), "bbbbbbbb", 2)]);
        reconcile_scanned_modules(std::slice::from_ref(&incoming_module), &mut incoming);
        first.absorb(incoming);

        let incoming_id = first
            .pinned()
            .find(|pin| pin.key == real(17))
            .expect("incoming pin survives")
            .id;
        assert_eq!(
            first
                .view_claims(ProcessViewId(17))
                .expect("incoming view claims survive")
                .pins,
            vec![incoming_id, incoming_id],
            "ownership kept the incoming set's pre-absorb ID"
        );
    }

    #[test]
    fn rejecting_a_late_collision_removes_stale_view_claims() {
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: INODE,
        };
        let first_module = module(key);
        let mut first = image_pins(&[(key, "aaaaaaaa", 1)]);
        reconcile_scanned_modules(std::slice::from_ref(&first_module), &mut first);

        let mut collision = image_pins(&[(key, "aaaaaaaa", 1)]);
        collision
            .by_id
            .values_mut()
            .next()
            .unwrap()
            .mapping
            .mount_id += 1;
        first.absorb(collision);

        let claims = first
            .view_claims(first_module.view)
            .expect("the accepted view remains represented");
        assert!(claims.tables.is_empty(), "stale table IDs: {claims:?}");
        assert!(claims.targets.is_empty(), "stale target IDs: {claims:?}");
        assert!(claims.pins.is_empty(), "stale pin IDs: {claims:?}");
    }

    #[test]
    fn overlay_canonicalization_remaps_existing_view_claims() {
        let a = module(overlay(102));
        let mut pinned = pins(&[(overlay(102), SHA, 1)]);
        reconcile_scanned_modules(std::slice::from_ref(&a), &mut pinned);

        let b = module(overlay(104));
        let mut incoming = pins(&[(overlay(104), SHA, 1)]);
        reconcile_scanned_modules(std::slice::from_ref(&b), &mut incoming);
        pinned.absorb(incoming);

        let modules = [a, b];
        reconcile_scanned_modules(&modules, &mut pinned);
        for module in modules {
            let claims = pinned.view_claims(module.view).expect("view claims");
            assert!(
                claims
                    .tables
                    .iter()
                    .chain(claims.targets.iter().map(|(id, _)| id))
                    .chain(&claims.pins)
                    .all(|id| pinned.by_id.contains_key(id)),
                "view {:?} retained a removed pre-collapse ID: {claims:?}",
                module.view
            );
        }
    }

    /// Models the measured common case: two containers from one image layer expose
    /// matching overlay metadata under different anonymous devices. Two slots caused
    /// doubled counts in the live lane; one slot restores its exact count oracle, but
    /// the unit predicate cannot prove physical identity and must publish uncertainty.
    #[test]
    fn common_shared_overlay_layer_is_one_module_and_one_slot_with_uncertainty() {
        let modules = vec![module(overlay(104)), module(overlay(102))];
        let mut pinned = pins(&[(overlay(104), SHA, 1), (overlay(102), SHA, 1)]);

        let (modules, collapsed, uncertainty) = reconcile_scanned_modules(&modules, &mut pinned);
        assert_eq!(collapsed, 1);
        assert_eq!(uncertainty.len(), 1, "{uncertainty:?}");
        assert!(uncertainty[0].subject.starts_with(PATH), "{uncertainty:?}");
        assert!(
            uncertainty[0]
                .reason
                .contains("cannot prove physical identity"),
            "{uncertainty:?}"
        );
        let plan = crate::plan::build_from_reconciled_modules(&modules);
        assert_eq!(plan.slots.len(), 1, "{:?}", plan.slots);
        assert_eq!(plan.modules.len(), 1, "{:?}", plan.modules);
        // One module reached by two mounts is not two modules claiming one target:
        // the slot keeps its semantics and the capture stays attributed.
        assert_eq!(plan.slots[0].module_ids.len(), 1);
        assert!(!plan.slots[0].semantic_ambiguous);
        assert_eq!(plan.module_ambiguous, 0);
        assert_eq!(
            plan.entries_seen, 1,
            "duplicate view claims stay in ownership, not public table cardinality"
        );
        assert_eq!(plan.modules[0].tables.len(), 1);
        assert_eq!(plan.surfaces.len(), 1);
        // Every plan reference is a capture-local pin ID; attach has no raw-key or
        // pathname fallback.
        assert!(pinned.attach_path_for(plan.slots[0].object).is_ok());
        assert!(pinned.attach_path_for(plan.modules[0].object).is_ok());
        assert_eq!(
            pinned
                .view_claims(ProcessViewId(102))
                .expect("first view")
                .targets
                .len(),
            1
        );
        assert_eq!(
            pinned
                .view_claims(ProcessViewId(104))
                .expect("second view")
                .targets
                .len(),
            1
        );
    }

    /// Two mounts of two byte-identical filesystem images (squashfs, erofs, iso, a
    /// loop-mounted ext4) are two superblocks — two devices — holding two genuinely
    /// distinct kernel inodes that carry the image's inode number, size and ctime
    /// *verbatim*. Every content conjunct is satisfied by construction rather than by
    /// coincidence, so nothing about the bytes can separate them; a uprobe on one does
    /// not fire for the other, and merging them silently drops the second mount's calls.
    /// Non-overlay classification excludes this direct-image case. It does not make
    /// the inverse claim: overlay classification still cannot prove identity.
    #[test]
    fn two_mounts_of_one_filesystem_image_are_not_merged() {
        let image = |minor| ObjectKey {
            device: Device { major: 7, minor },
            inode: INODE,
        };
        let modules = vec![module(image(0)), module(image(1))];
        let mut pinned = image_pins(&[(image(0), SHA, 1), (image(1), SHA, 1)]);

        let (modules, collapsed, lost) = reconcile_scanned_modules(&modules, &mut pinned);
        assert_eq!((collapsed, lost), (0, vec![]));
        let plan = crate::plan::build_from_reconciled_modules(&modules);
        assert_eq!(plan.slots.len(), 2, "{:?}", plan.slots);
        assert_eq!(plan.modules.len(), 2, "{:?}", plan.modules);
    }

    /// The dangerous direction. Inode numbers are unique only per filesystem, so two
    /// genuinely different providers on two real devices can share one — and merging
    /// them would be a worse defect than the double-counting above.
    #[test]
    fn two_different_files_sharing_an_inode_number_are_never_merged() {
        let real = |minor| ObjectKey {
            device: Device { major: 8, minor },
            inode: INODE,
        };
        for mut pins in [
            // Same inode number, different bytes: two providers, two modules.
            pins(&[(real(1), SHA, 1), (real(17), "0badc0de", 1)]),
            // Same inode number and the same bytes, but not the same inode: two
            // copies of one build, each its own file and its own attach target.
            pins(&[(real(1), SHA, 1), (real(17), SHA, 2)]),
            // Nothing hashed either one, so nothing identifies them.
            pins(&[(real(1), "", 1), (real(17), "", 1)]),
        ] {
            let modules = vec![module(real(1)), module(real(17))];
            let (modules, collapsed, lost) = reconcile_scanned_modules(&modules, &mut pins);
            assert_eq!((collapsed, lost), (0, vec![]));
            let plan = crate::plan::build_from_reconciled_modules(&modules);
            assert_eq!(plan.modules.len(), 2, "{:?}", plan.modules);
            assert_eq!(plan.slots.len(), 2, "{:?}", plan.slots);
        }
    }

    /// Two *different* providers — different digests, so never merged — in two
    /// containers, both forwarding into one shared dependency. The dependency is one
    /// target with the measured shared-overlay shape. It becomes one slot claimed by
    /// two modules, with explicit collapse uncertainty: Task 8's rule must still hold.
    /// Without rewriting *entry* objects this is two slots and `module_ambiguous` reads
    /// 0 — the ambiguity would vanish rather than be reported.
    #[test]
    fn one_dependency_reached_through_two_mounts_is_one_ambiguous_slot() {
        const DEP: u64 = 56_317_999;
        let dep = |minor| ObjectKey {
            device: Device { major: 0, minor },
            inode: DEP,
        };
        let forwarding = |device_minor, dependency| {
            let mut module = module(overlay(device_minor));
            module.tables[0].entries[0].object = dependency;
            module
        };
        let modules = vec![forwarding(102, dep(102)), forwarding(104, dep(104))];
        let mut pinned = pins(&[
            // The two providers happen to share an inode number too: only their
            // digests separate them, and that is enough.
            (overlay(102), "aaaaaaaa", 1),
            (overlay(104), "bbbbbbbb", 1),
            (dep(102), "dddddddd", 1),
            (dep(104), "dddddddd", 1),
        ]);

        let (modules, collapsed, uncertainty) = reconcile_scanned_modules(&modules, &mut pinned);
        assert_eq!(collapsed, 1);
        assert_eq!(uncertainty.len(), 1, "{uncertainty:?}");
        let plan = crate::plan::build_from_reconciled_modules(&modules);
        assert_eq!(plan.modules.len(), 2, "{:?}", plan.modules);
        assert_eq!(plan.slots.len(), 1, "{:?}", plan.slots);
        assert_eq!(plan.slots[0].module_ids.len(), 2);
        assert!(plan.slots[0].semantic_ambiguous);
        assert_eq!(
            plan.slots[0].semantics,
            p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
        );
        assert_eq!(plan.module_ambiguous, 1);
    }

    /// The mapping that decoded nothing — its process's `/proc/<pid>/mem` was
    /// unreadable, or it was over the scan's byte caps — must not shadow the one
    /// that read the tables just because it was scanned first. Its emptiness is not
    /// a loss of its own: the object skip that caused it is already published.
    #[test]
    fn the_mapping_that_decoded_the_tables_is_the_one_kept() {
        let mut empty = module(overlay(104));
        empty.tables.clear();
        let modules = vec![empty, module(overlay(102))];
        let mut pinned = pins(&[(overlay(104), SHA, 1), (overlay(102), SHA, 1)]);

        let (modules, collapsed, uncertainty) = reconcile_scanned_modules(&modules, &mut pinned);
        assert_eq!(collapsed, 1);
        assert_eq!(uncertainty.len(), 1, "{uncertainty:?}");
        assert_eq!(modules.len(), 2, "both process views are retained");
        assert_eq!(
            crate::plan::build_from_reconciled_modules(&modules)
                .slots
                .len(),
            1
        );
    }

    /// Function tables are read from *per-process* memory, so two overlay candidates
    /// can decode different targets — a table patched in memory in one container, or a
    /// dependency mapped in only one mount namespace. Both views' targets must survive.
    #[test]
    fn all_process_views_overlay_target_union_is_retained() {
        let mut patched = module(overlay(104));
        let mut extra = patched.tables[0].entries[0].clone();
        extra.name = "C_Sign";
        extra.file_offset = 0x9000;
        patched.tables[0].entries.push(extra);
        let modules = vec![module(overlay(102)), patched];
        let mut pinned = pins(&[(overlay(102), SHA, 1), (overlay(104), SHA, 1)]);

        let (modules, collapsed, lost) = reconcile_scanned_modules(&modules, &mut pinned);
        assert_eq!(collapsed, 1);
        // Both views survive, so the only record is the unavoidable physical-
        // identity uncertainty; neither view's target is lost.
        assert_eq!(lost.len(), 1, "{lost:?}");
        assert!(lost[0].reason.contains("cannot prove physical identity"));
        let plan = crate::plan::build_from_reconciled_modules(&modules);
        assert_eq!(plan.slots.len(), 2);
        assert_eq!(
            plan.entries_seen, 2,
            "the shared entry is one record and the patched target extends its union"
        );

        // Reversed: the mapping that wins on count is missing a target the other had.
        let mut a = module(overlay(102));
        a.tables[0].entries[0].file_offset = 0x1000;
        let mut b = module(overlay(104));
        b.tables[0].entries[0].file_offset = 0x2000;
        b.tables[0].entries.push(ScannedEntry {
            name: "C_Sign",
            object: overlay(104),
            object_path: PATH.into(),
            file_offset: 0x3000,
        });
        let modules = vec![a, b];
        let mut pinned = pins(&[(overlay(102), SHA, 1), (overlay(104), SHA, 1)]);
        let (modules, _, lost) = reconcile_scanned_modules(&modules, &mut pinned);
        assert_eq!(lost.len(), 1, "only overlay uncertainty remains: {lost:?}");
        assert_eq!(
            crate::plan::build_from_reconciled_modules(&modules)
                .slots
                .len(),
            3,
            "the union of both process views must be attached"
        );
    }

    #[test]
    fn overlay_target_union_is_order_independent() {
        let mut existing = module(overlay(102));
        let mut extra = existing.tables[0].entries[0].clone();
        extra.name = "C_Sign";
        extra.file_offset = 0x3000;
        existing.tables[0].entries.push(extra);

        let mut incoming = module(overlay(104));
        incoming.tables[0].entries[0].file_offset = 0x2000;
        let modules = vec![existing, incoming];
        let mut pinned = pins(&[(overlay(102), SHA, 1), (overlay(104), SHA, 1)]);

        let (modules, _, lost) = reconcile_scanned_modules(&modules, &mut pinned);
        assert_eq!(lost.len(), 1, "only overlay uncertainty remains: {lost:?}");
        assert_eq!(
            crate::plan::build_from_reconciled_modules(&modules)
                .slots
                .len(),
            3
        );
    }
}
