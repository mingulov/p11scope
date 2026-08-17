//! Pins objects — manifest-recorded or scan-discovered — to their current identity
//! without holding read leases. `check_unchanged` gives cheap, best-effort change
//! detection via `(ino, size, ctime)`; it is not a security boundary — the leased,
//! provenance-checked verification path it replaces was removed by
//! Productization Slice 1a (formerly `src/verify.rs`, restorable from history).

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{AsRawFd as _, RawFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use p11scope_manifest::identity::{
    IdentityKind, ObjectIdentity, inspect_file, mapping_file_key, open_object,
};
use p11scope_manifest::manifest::{Manifest, Resolution};
use p11scope_manifest::maps::{Device, ObjectKey};

use crate::discovery::scan::{ScanLimits, ScannedModule, Skipped};
use crate::manifest_input::{MAX_TOTAL_OBJECT_BYTES, validate_structure};
use crate::process::PidPin;

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

/// How an object's `(device, inode)` was determined, and therefore how much of it can
/// be compared with what `/proc/<pid>/maps` reported. A typed distinction on purpose:
/// this is the strength of the retargeting check, and a stray string must not be able
/// to downgrade it silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentitySource {
    /// fdinfo + mountinfo resolved the mount's device — the whole key is comparable.
    Mountinfo,
    /// The mountinfo lookup failed, and `st_dev` is *not* the device maps renders
    /// (btrfs subvolumes, overlay), so only the inode is comparable.
    Stat,
}

impl IdentitySource {
    fn label(self) -> &'static str {
        match self {
            Self::Mountinfo => "mountinfo",
            Self::Stat => "stat",
        }
    }

    /// Whether the opened file is the object the mapping named.
    fn confirms(self, found: ObjectKey, expected: ObjectKey) -> bool {
        found.inode == expected.inode
            && match self {
                Self::Mountinfo => found.device == expected.device,
                Self::Stat => true,
            }
    }
}

struct FoundIdentity {
    key: ObjectKey,
    source: IdentitySource,
    /// Why the mountinfo lookup was unavailable, when it was. Four of its five failures
    /// mean the observer's own `/proc` is broken rather than "the target is a
    /// container", so the downgrade is recorded instead of inferred.
    note: Option<String>,
}

#[derive(Debug)]
struct Entry {
    file: std::fs::File,
    pin: Pin,
    path: String,
    sha256: String,
    build_id: Option<String>,
    identity_source: &'static str,
    note: Option<String>,
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
        found: FoundIdentity,
    ) -> Result<Self, String> {
        Ok(Self {
            overlay: on_overlayfs(file.as_raw_fd())?,
            file,
            pin,
            path,
            // `inspect_file` always records a whole-file digest.
            sha256: identity.sha256.clone().unwrap_or_default(),
            build_id: match identity.kind {
                IdentityKind::GnuBuildId => identity.value.clone(),
                _ => None,
            },
            identity_source: found.source.label(),
            note: found.note,
        })
    }
}

/// What a pinned object is, for the `discovery[]` report.
#[derive(Debug, Clone, Copy)]
pub struct PinnedSummary<'a> {
    pub key: ObjectKey,
    /// For scan-sourced objects this is the *target's* path: it is namespace-relative
    /// and the observer cannot open it. Attach through `attach_path_for` instead.
    pub path: &'a str,
    pub sha256: &'a str,
    pub build_id: Option<&'a str>,
    /// "mountinfo" or "stat" — how the mapping identity was confirmed.
    pub identity_source: &'static str,
    /// Why `identity_source` is "stat" rather than "mountinfo".
    pub note: Option<&'a str>,
}

/// Every object opened, identity-matched, and pinned by `(ino, size, ctime)`, keyed
/// by the `(device, inode)` a mapping of it shows. No read leases are held:
/// `check_unchanged` is a cheap, best-effort check, not a guarantee that the bytes
/// cannot change between the check and Aya's attach.
#[derive(Debug)]
pub struct PinnedObjects {
    /// Keyed by identity alone. There is deliberately no path index: a pathname is
    /// not an identity — the target's `/proc/<pid>/maps` path names a different file
    /// in the observer's namespace, and a manifest's recorded path resolves to
    /// whatever lives there now. Callers resolve by the key of an object this
    /// capture pinned, which `main.rs` guarantees every plan slot carries.
    by_key: BTreeMap<ObjectKey, Entry>,
    /// Latched by `check_unchanged` the first time any pin differs.
    changed: std::cell::Cell<bool>,
}

impl PinnedObjects {
    /// An empty set: no objects pinned. For rendering tests that have no live
    /// process to pin objects from.
    pub fn empty() -> Self {
        Self {
            by_key: BTreeMap::new(),
            changed: std::cell::Cell::new(false),
        }
    }

    /// Folds another pin set into this one. A capture pins what the scan found and
    /// what every `--manifest` names, but `Session::start` takes exactly one set.
    /// The receiver wins a duplicate key: the scan opens objects through the
    /// target's own `/proc/<pid>/root` view, which is the file the probe attaches
    /// into even when the observer's namespace spells the path differently.
    pub fn absorb(&mut self, other: PinnedObjects) {
        for (key, entry) in other.by_key {
            self.by_key.entry(key).or_insert(entry);
        }
        self.changed.set(self.changed.get() || other.changed.get());
    }

    /// The path Aya reopens for this object: an fd this capture holds, never a name
    /// resolved again through a namespace that may not mean the same file.
    pub fn attach_path_for(&self, key: ObjectKey) -> Result<PathBuf, String> {
        self.by_key
            .get(&key)
            .map(|entry| PathBuf::from(format!("/proc/self/fd/{}", entry.file.as_raw_fd())))
            .ok_or_else(|| format!("object {key:?} was not pinned"))
    }

    /// Every pinned object, for `discovery[]`.
    pub fn pinned(&self) -> impl Iterator<Item = PinnedSummary<'_>> {
        self.by_key.iter().map(|(key, entry)| PinnedSummary {
            key: *key,
            path: &entry.path,
            sha256: &entry.sha256,
            build_id: entry.build_id.as_deref(),
            identity_source: entry.identity_source,
            note: entry.note.as_deref(),
        })
    }

    /// `Ok(true)` when every pinned object still has the `(ino, size, ctime)` seen
    /// at pinning; `Ok(false)` when any changed (sticky: once seen, every later
    /// call is `Ok(false)` without re-checking); `Err` only when `fstat` itself fails.
    pub fn check_unchanged(&self) -> Result<bool, String> {
        if self.changed.get() {
            return Ok(false);
        }
        for entry in self.by_key.values() {
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
}

/// The `(device, inode)` a mapping of this fd would show, and how it was determined.
/// `mapping_file_key` renders the device the way `/proc/<pid>/maps` does (fdinfo +
/// mountinfo, so btrfs subvolumes and overlay agree). When the fd's mount is missing
/// from the observer's own table — plausible for a container — `st_dev` is *not* that
/// device, so `"stat"` records that only the inode is comparable.
fn identity_of(file: &std::fs::File) -> Result<FoundIdentity, String> {
    let note = match mapping_file_key(file) {
        Ok(key) => {
            return Ok(FoundIdentity {
                key: ObjectKey {
                    device: Device {
                        major: key.device_major,
                        minor: key.device_minor,
                    },
                    inode: key.inode,
                },
                source: IdentitySource::Mountinfo,
                note: None,
            });
        }
        Err(error) => format!("mountinfo device unavailable ({error}); inode compared alone"),
    };
    let metadata = file
        .metadata()
        .map_err(|error| format!("fstat failed: {error}"))?;
    Ok(FoundIdentity {
        key: ObjectKey {
            device: Device {
                major: libc::major(metadata.dev()).into(),
                minor: libc::minor(metadata.dev()).into(),
            },
            inode: metadata.ino(),
        },
        source: IdentitySource::Stat,
        note: Some(note),
    })
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
    let mut by_key = BTreeMap::new();
    for (path, file, inspected, pin) in opened.into_values() {
        let found = match identity_of(&file) {
            Ok(found) => found,
            Err(error) => {
                problems.push(format!("{path}: {error}"));
                continue;
            }
        };
        let key = found.key;
        let entry = match Entry::new(file, pin, path.clone(), &inspected.identity, found) {
            Ok(entry) => entry,
            Err(error) => {
                problems.push(format!("{path}: {error}"));
                continue;
            }
        };
        if let Some(previous) = by_key.insert(key, entry) {
            problems.push(format!(
                "{path} and {} are the same object ({key:?}); refusing an ambiguous pin",
                previous.path
            ));
        }
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    Ok(PinnedObjects {
        by_key,
        changed: std::cell::Cell::new(false),
    })
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
    limits: ScanLimits,
) -> Result<(PinnedObjects, Vec<Skipped>), String> {
    let pin = PidPin::open(pid)?;
    // Both the table-owning modules and every object a table entry points into: an
    // entry may land in a dependency the module itself only forwards to.
    let mut wanted: BTreeMap<ObjectKey, &str> = BTreeMap::new();
    for module in modules {
        wanted.entry(module.key).or_insert(&module.path);
        for entry in module.tables.iter().flat_map(|table| &table.entries) {
            wanted.entry(entry.object).or_insert(&entry.object_path);
        }
    }

    let exited = || format!("pid {pid} exited during discovery");
    let mut by_key = BTreeMap::new();
    let mut skipped = Vec::new();
    let mut total_bytes = 0u64;
    for (key, path) in wanted {
        // Opening through /proc/<pid>/root is a per-pid action (spec §4.5).
        if !pin.still_the_same() {
            return Err(exited());
        }
        match pin_scanned_object(pid, key, path, limits, &mut total_bytes) {
            Ok(entry) => {
                by_key.insert(key, entry);
            }
            Err(reason) => skipped.push(Skipped {
                subject: path.to_string(),
                reason,
            }),
        }
    }
    if !pin.still_the_same() {
        return Err(exited());
    }
    Ok((
        PinnedObjects {
            by_key,
            changed: std::cell::Cell::new(false),
        },
        skipped,
    ))
}

/// Heuristically collapses likely shared overlay mappings onto one pinned key and
/// drops duplicate module views. Returns how many keys were collapsed plus published
/// uncertainty/loss evidence; every collapse is uncertain because overlayfs, inode
/// metadata and identical bytes do not prove physical identity across overlay instances.
///
/// `ObjectKey` is `(device, inode)`, and that pair identifies a *mapping*, not a
/// file: `/proc/<pid>/maps` renders `i_sb->s_dev`, the superblock the mapping was
/// reached through, and an overlay mount reports the *underlying* inode's number under
/// its own anonymous superblock device. Two containers started from one image
/// therefore show one file as `[0,102]:56317450` and
/// `[0,104]:56317450` — two keys, two modules, two slots. A uprobe is registered per
/// `(inode, offset)`, so both slots are two registrations on *one* point: both fire
/// for every call from either container, every count doubles, and nothing in the
/// document says so (neither slot is shared by two modules, so `module_ambiguous`
/// stays 0 and every entry reads as attributed). N pods from one image inflate N×,
/// which is the ordinary Kubernetes shape, so this is not an edge case.
///
/// Candidates must both be opened through overlayfs and have equal inode number, size,
/// ctime and whole-file SHA-256, with only the mapping device differing. The device is
/// deliberately not compared because the common Kubernetes shared-layer case exposes
/// one provider under a different anonymous overlay device per container.
///
/// This remains a heuristic: two independent overlay instances over byte-identical
/// filesystem images can satisfy every predicate while resolving to distinct kernel
/// inodes. Collapsing them would under-count one instance, so each rewrite is published
/// through `Skipped` and forces `PARTIAL`. That makes the uncertainty explicit while
/// retaining one-slot counting for the measured shared-image-layer case.
///
/// Two shapes deliberately do **not** merge:
///  - one process reaching the file through an overlay and another reaching the same
///    file directly (an overlay whose lowerdir is the very path the other maps). No
///    container runtime builds that; a hand-rolled `mount -t overlay` could.
///  - an overlay with `xino` disabled that numbers inodes from its own pool instead of
///    passing the underlying inode's number through: `Pin.ino` then differs and nothing
///    here fires.
///
/// A target two *different* modules both publish is a different thing entirely and
/// is untouched here: those have different digests, so they keep their own keys, and
/// `plan::merge` still gives that shared target one slot marked ambiguous and
/// COUNT_ONLY.
///
/// Call this *after* `drop_unpinned_entries`, so the election below counts targets that
/// can actually be attached rather than merely decoded.
pub fn collapse_overlay_mappings(
    modules: &mut Vec<ScannedModule>,
    pinned: &PinnedObjects,
) -> (usize, Vec<Skipped>) {
    let mut first: BTreeMap<(Pin, &str), ObjectKey> = BTreeMap::new();
    let mut canonical: BTreeMap<ObjectKey, ObjectKey> = BTreeMap::new();
    let mut lost = Vec::new();
    for (key, entry) in &pinned.by_key {
        // An object nothing hashed has no content to be identified by, and one not
        // reached through an overlay has no reason to show two devices: absence of
        // evidence is never evidence of sameness.
        if entry.sha256.is_empty() || !entry.overlay {
            continue;
        }
        match first.entry((entry.pin, entry.sha256.as_str())) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(*key);
            }
            std::collections::btree_map::Entry::Occupied(kept) => {
                let kept = *kept.get();
                canonical.insert(*key, kept);
                lost.push(Skipped {
                    subject: format!("{} ({key:?})", entry.path),
                    reason: format!(
                        "mapping {key:?} was collapsed onto {kept:?} by the overlayfs + \
                         inode metadata + SHA-256 heuristic, which cannot prove physical \
                         identity across overlay instances; calls through a distinct \
                         byte-identical instance would not be probed"
                    ),
                });
            }
        }
    }
    if canonical.is_empty() {
        return (0, lost);
    }
    for module in modules.iter_mut() {
        // A table entry may land in a dependency rather than in the module that
        // published it, and that dependency is shared through the same mounts.
        for entry in module
            .tables
            .iter_mut()
            .flat_map(|table| &mut table.entries)
        {
            if let Some(key) = canonical.get(&entry.object) {
                entry.object = *key;
            }
        }
    }
    // Keep one module per heuristic group. This is the shape that avoids duplicate
    // registrations in the measured shared-layer case; the uncertainty above records
    // that a distinct overlay instance could instead be omitted. The candidate with
    // the most attachable targets wins — one process's
    // `/proc/<pid>/mem` can be unreadable, or over the scan's byte caps, while another
    // matching mapping was read in full, and an empty module must not shadow the one
    // with targets to attach.
    //
    // Tables are read from *per-process* memory, so the loser can legitimately hold
    // targets the winner does not: an in-memory patch applied in one container, or a
    // dependency mapped only in one mount namespace. Those cannot be attached and are
    // reported as skipped rather than dropped — a loss with no record is exactly the
    // silence this whole task is about.
    let targets = |module: &ScannedModule| -> BTreeSet<(ObjectKey, u64)> {
        module
            .tables
            .iter()
            .flat_map(|table| &table.entries)
            .map(|entry| (entry.object, entry.file_offset))
            .collect()
    };
    let mut kept: Vec<(ScannedModule, ObjectKey)> = Vec::new();
    for mut module in std::mem::take(modules) {
        let original_key = module.key;
        module.key = canonical
            .get(&original_key)
            .copied()
            .unwrap_or(original_key);
        let Some(position) = kept.iter().position(|(known, _)| known.key == module.key) else {
            kept.push((module, original_key));
            continue;
        };
        let (here, there) = (targets(&module), targets(&kept[position].0));
        let wins = here.len() > there.len();
        let missing = if wins {
            there.difference(&here).count()
        } else {
            here.difference(&there).count()
        };
        if missing > 0 {
            let discarded = if wins {
                (&kept[position].0.path, kept[position].1)
            } else {
                (&module.path, original_key)
            };
            lost.push(Skipped {
                subject: format!("{} ({:?})", discarded.0, discarded.1),
                reason: format!(
                    "the attached mapping does not publish {missing} target(s) the \
                     discarded mapping decoded; those are not probed — the two \
                     processes' function tables differ (a table patched in memory, or \
                     a dependency mapped in only one mount namespace)"
                ),
            });
        }
        if wins {
            kept[position] = (module, original_key);
        }
    }
    *modules = kept.into_iter().map(|(module, _)| module).collect();
    (canonical.len(), lost)
}

fn pin_scanned_object(
    pid: u32,
    key: ObjectKey,
    path: &str,
    limits: ScanLimits,
    total_bytes: &mut u64,
) -> Result<Entry, String> {
    // The target's own filesystem view: a container's object is never copied out.
    let file = open_object(Path::new(&format!("/proc/{pid}/root{path}")))?;
    let found = identity_of(&file)?;
    if !found.source.confirms(found.key, key) {
        return Err(format!(
            "identity_mismatch: the mapping is {key:?} but {path} now opens as {:?} \
             (compared via {})",
            found.key,
            found.source.label(),
        ));
    }
    let before = pin_of(&file)?;
    // Checked before the hash, which reads the object whole. Over budget is a skip,
    // never a partial digest.
    match total_bytes.checked_add(before.size) {
        Some(running)
            if before.size <= limits.per_object_bytes && running <= limits.total_bytes =>
        {
            *total_bytes = running
        }
        _ => {
            return Err(format!(
                "too_large ({} bytes; caps are {} per object and {} per capture, \
                 {total_bytes} already pinned)",
                before.size, limits.per_object_bytes, limits.total_bytes
            ));
        }
    }
    let inspected = inspect_file(&file)?;
    // The pin was taken before the bytes were hashed; a write that lands during the
    // hash must not become the baseline the capture trusts.
    if pin_of(&file)? != before {
        return Err("file changed while it was being identified — retry".into());
    }
    Entry::new(file, before, path.to_string(), &inspected.identity, found)
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
        PinnedObjects {
            by_key: entries
                .iter()
                .map(|(key, sha, ctime)| {
                    (
                        *key,
                        Entry {
                            file: std::fs::File::open("/dev/null").unwrap(),
                            pin: Pin {
                                ino: key.inode,
                                size: 4096,
                                ctime: (*ctime, 7),
                            },
                            path: PATH.into(),
                            sha256: (*sha).into(),
                            build_id: None,
                            identity_source: IdentitySource::Stat.label(),
                            note: None,
                            overlay,
                        },
                    )
                })
                .collect(),
            changed: std::cell::Cell::new(false),
        }
    }

    /// Objects opened through a container's overlay mount — the shape this is about.
    fn pins(entries: &[(ObjectKey, &str, i64)]) -> PinnedObjects {
        pin_set(entries, true)
    }

    /// The same objects, opened on a real filesystem rather than through an overlay.
    fn image_pins(entries: &[(ObjectKey, &str, i64)]) -> PinnedObjects {
        pin_set(entries, false)
    }

    #[test]
    fn fstatfs_failure_is_an_error_not_non_overlay() {
        let error = on_overlayfs(-1).expect_err("an invalid fd must not mean non-overlay");
        assert!(error.contains("fstatfs failed"), "{error}");
    }

    /// Models the measured common case: two containers from one image layer expose
    /// matching overlay metadata under different anonymous devices. Two slots caused
    /// doubled counts in the live lane; one slot restores its exact count oracle, but
    /// the unit predicate cannot prove physical identity and must publish uncertainty.
    #[test]
    fn common_shared_overlay_layer_is_one_module_and_one_slot_with_uncertainty() {
        let mut modules = vec![module(overlay(104)), module(overlay(102))];
        let pinned = pins(&[(overlay(104), SHA, 1), (overlay(102), SHA, 1)]);

        let (collapsed, uncertainty) = collapse_overlay_mappings(&mut modules, &pinned);
        assert_eq!(collapsed, 1);
        assert_eq!(uncertainty.len(), 1, "{uncertainty:?}");
        assert!(
            uncertainty[0].subject.starts_with(PATH)
                && uncertainty[0].subject.contains("minor: 104"),
            "{uncertainty:?}"
        );
        assert!(
            uncertainty[0]
                .reason
                .contains("cannot prove physical identity"),
            "{uncertainty:?}"
        );
        let plan = crate::plan::build_from_modules(&modules);
        assert_eq!(plan.slots.len(), 1, "{:?}", plan.slots);
        assert_eq!(plan.modules.len(), 1, "{:?}", plan.modules);
        // One module reached by two mounts is not two modules claiming one target:
        // the slot keeps its semantics and the capture stays attributed.
        assert_eq!(plan.slots[0].module_ids.len(), 1);
        assert!(!plan.slots[0].semantic_ambiguous);
        assert_eq!(plan.module_ambiguous, 0);
        assert_eq!(
            plan.entries_seen, 1,
            "one collapsed mapping published one table"
        );
        // Every plan key is still one this capture pinned — `Session::start`
        // resolves by key alone and has no fallback.
        assert!(pinned.attach_path_for(plan.slots[0].object).is_ok());
        assert!(pinned.attach_path_for(plan.modules[0].key).is_ok());
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
        let mut modules = vec![module(image(0)), module(image(1))];
        let pinned = image_pins(&[(image(0), SHA, 1), (image(1), SHA, 1)]);

        assert_eq!(
            collapse_overlay_mappings(&mut modules, &pinned),
            (0, vec![])
        );
        let plan = crate::plan::build_from_modules(&modules);
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
        for pins in [
            // Same inode number, different bytes: two providers, two modules.
            pins(&[(real(1), SHA, 1), (real(17), "0badc0de", 1)]),
            // Same inode number and the same bytes, but not the same inode: two
            // copies of one build, each its own file and its own attach target.
            pins(&[(real(1), SHA, 1), (real(17), SHA, 2)]),
            // Nothing hashed either one, so nothing identifies them.
            pins(&[(real(1), "", 1), (real(17), "", 1)]),
        ] {
            let mut modules = vec![module(real(1)), module(real(17))];
            assert_eq!(collapse_overlay_mappings(&mut modules, &pins), (0, vec![]));
            let plan = crate::plan::build_from_modules(&modules);
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
        let mut modules = vec![forwarding(102, dep(102)), forwarding(104, dep(104))];
        let pinned = pins(&[
            // The two providers happen to share an inode number too: only their
            // digests separate them, and that is enough.
            (overlay(102), "aaaaaaaa", 1),
            (overlay(104), "bbbbbbbb", 1),
            (dep(102), "dddddddd", 1),
            (dep(104), "dddddddd", 1),
        ]);

        let (collapsed, uncertainty) = collapse_overlay_mappings(&mut modules, &pinned);
        assert_eq!(collapsed, 1);
        assert_eq!(uncertainty.len(), 1, "{uncertainty:?}");
        let plan = crate::plan::build_from_modules(&modules);
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
        let mut modules = vec![empty, module(overlay(102))];
        let pinned = pins(&[(overlay(104), SHA, 1), (overlay(102), SHA, 1)]);

        let (collapsed, uncertainty) = collapse_overlay_mappings(&mut modules, &pinned);
        assert_eq!(collapsed, 1);
        assert_eq!(uncertainty.len(), 1, "{uncertainty:?}");
        assert_eq!(modules.len(), 1);
        assert_eq!(crate::plan::build_from_modules(&modules).slots.len(), 1);
    }

    /// Function tables are read from *per-process* memory, so two collapse candidates
    /// can decode different targets — a table patched in memory in one container, or a
    /// dependency mapped in only one mount namespace. The discarded mapping's targets
    /// are a separate concrete loss from the physical-identity uncertainty.
    #[test]
    fn targets_only_the_discarded_mapping_decoded_are_reported_not_dropped() {
        let mut patched = module(overlay(104));
        let mut extra = patched.tables[0].entries[0].clone();
        extra.name = "C_Sign";
        extra.file_offset = 0x9000;
        patched.tables[0].entries.push(extra);
        let mut modules = vec![module(overlay(102)), patched];
        let pinned = pins(&[(overlay(102), SHA, 1), (overlay(104), SHA, 1)]);

        let (collapsed, lost) = collapse_overlay_mappings(&mut modules, &pinned);
        assert_eq!(collapsed, 1);
        // The richer mapping wins, so the only record is the unavoidable physical-
        // identity uncertainty, not target loss.
        assert_eq!(lost.len(), 1, "{lost:?}");
        assert!(lost[0].reason.contains("cannot prove physical identity"));
        assert_eq!(crate::plan::build_from_modules(&modules).slots.len(), 2);

        // Reversed: the mapping that wins on count is missing a target the other had.
        let mut a = module(overlay(102));
        a.path = "/discarded/libsofthsm2.so".into();
        a.tables[0].entries[0].file_offset = 0x1000;
        let mut b = module(overlay(104));
        b.path = "/attached/libsofthsm2.so".into();
        b.tables[0].entries[0].file_offset = 0x2000;
        b.tables[0].entries.push(ScannedEntry {
            name: "C_Sign",
            object: overlay(104),
            object_path: PATH.into(),
            file_offset: 0x3000,
        });
        let mut modules = vec![a, b];
        let (_, lost) = collapse_overlay_mappings(&mut modules, &pinned);
        let target_loss: Vec<_> = lost
            .iter()
            .filter(|skip| skip.reason.contains("1 target(s)"))
            .collect();
        assert_eq!(target_loss.len(), 1, "{lost:?}");
        assert!(
            target_loss[0]
                .subject
                .starts_with("/discarded/libsofthsm2.so")
                && target_loss[0].subject.contains("minor: 102"),
            "{target_loss:?}"
        );
        assert!(
            target_loss[0].reason.contains("not probed"),
            "{target_loss:?}"
        );
    }

    #[test]
    fn target_loss_names_discarded_incoming_mapping_when_existing_wins() {
        let mut existing = module(overlay(102));
        existing.path = "/attached/libsofthsm2.so".into();
        let mut extra = existing.tables[0].entries[0].clone();
        extra.name = "C_Sign";
        extra.file_offset = 0x3000;
        existing.tables[0].entries.push(extra);

        let mut incoming = module(overlay(104));
        incoming.path = "/discarded/libsofthsm2.so".into();
        incoming.tables[0].entries[0].file_offset = 0x2000;
        let mut modules = vec![existing, incoming];
        let pinned = pins(&[(overlay(102), SHA, 1), (overlay(104), SHA, 1)]);

        let (_, lost) = collapse_overlay_mappings(&mut modules, &pinned);
        let target_loss: Vec<_> = lost
            .iter()
            .filter(|skip| skip.reason.contains("1 target(s)"))
            .collect();
        assert_eq!(target_loss.len(), 1, "{lost:?}");
        assert!(
            target_loss[0]
                .subject
                .starts_with("/discarded/libsofthsm2.so")
                && target_loss[0].subject.contains("minor: 104"),
            "{target_loss:?}"
        );
    }
}
