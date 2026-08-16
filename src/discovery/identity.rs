//! Pins objects — manifest-recorded or scan-discovered — to their current identity
//! without holding read leases. `check_unchanged` gives cheap, best-effort change
//! detection via `(ino, size, ctime)`; it is not a security boundary — the leased,
//! provenance-checked verification path it replaces was removed by
//! Productization Slice 1a (formerly `src/verify.rs`, restorable from history).

use std::collections::BTreeMap;
use std::os::fd::AsRawFd as _;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

impl Entry {
    fn new(
        file: std::fs::File,
        pin: Pin,
        path: String,
        identity: &ObjectIdentity,
        found: FoundIdentity,
    ) -> Self {
        Self {
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
        }
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
    by_key: BTreeMap<ObjectKey, Entry>,
    /// Manifest paths → key, so `attach_path(&str)` keeps working. Scan-sourced
    /// objects are not listed here: their paths are the *target's*, which two
    /// processes in different mount namespaces can spell identically.
    by_path: BTreeMap<String, ObjectKey>,
    /// Latched by `check_unchanged` the first time any pin differs.
    changed: std::cell::Cell<bool>,
}

impl PinnedObjects {
    /// An empty set: no objects pinned. For rendering tests that have no live
    /// process to pin objects from.
    pub fn empty() -> Self {
        Self {
            by_key: BTreeMap::new(),
            by_path: BTreeMap::new(),
            changed: std::cell::Cell::new(false),
        }
    }

    /// Path Aya may reopen without re-resolving the untrusted manifest path.
    pub fn attach_path(&self, original: &str) -> Result<PathBuf, String> {
        let key = *self
            .by_path
            .get(original)
            .ok_or_else(|| format!("object path {original:?} was not pinned"))?;
        self.attach_path_for(key)
    }

    /// Attach path for an object discovered by the scan.
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
    let mut by_path = BTreeMap::new();
    for (path, file, inspected, pin) in opened.into_values() {
        let found = match identity_of(&file) {
            Ok(found) => found,
            Err(error) => {
                problems.push(format!("{path}: {error}"));
                continue;
            }
        };
        let key = found.key;
        by_path.insert(path.clone(), key);
        if let Some(previous) = by_key.insert(
            key,
            Entry::new(file, pin, path.clone(), &inspected.identity, found),
        ) {
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
        by_path,
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
            by_path: BTreeMap::new(),
            changed: std::cell::Cell::new(false),
        },
        skipped,
    ))
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
    Ok(Entry::new(
        file,
        before,
        path.to_string(),
        &inspected.identity,
        found,
    ))
}
