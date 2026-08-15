//! Pins manifest-recorded objects to their current identity without holding read
//! leases. `check_unchanged` gives cheap, best-effort change detection via
//! `(ino, size, ctime)`; it is not a security boundary — see `src/verify.rs` for
//! that (the leased, provenance-checked path this module will replace).

use std::collections::BTreeMap;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use p11scope_manifest::identity::{ObjectIdentity, inspect_file, open_object};
use p11scope_manifest::manifest::{Manifest, Resolution};

use crate::manifest_input::{MAX_TOTAL_OBJECT_BYTES, validate_structure};

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

/// Every manifest object opened, identity-matched, and pinned by `(ino, size, ctime)`.
/// No read leases are held: `check_unchanged` is a cheap, best-effort check, not a
/// guarantee that the bytes cannot change between the check and Aya's attach.
#[derive(Debug)]
pub struct PinnedObjects {
    files: BTreeMap<String, std::fs::File>,
    identities: BTreeMap<String, ObjectIdentity>,
    pins: BTreeMap<String, Pin>,
}

impl PinnedObjects {
    /// Path Aya may reopen without re-resolving the untrusted manifest path.
    pub fn attach_path(&self, original: &str) -> Result<PathBuf, String> {
        self.files
            .get(original)
            .map(|file| PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())))
            .ok_or_else(|| format!("object path {original:?} was not pinned"))
    }

    /// `Ok(true)` when every pinned object still has the `(ino, size, ctime)` seen
    /// at pinning; `Ok(false)` when any changed; `Err` only when `fstat` itself fails.
    pub fn check_unchanged(&self) -> Result<bool, String> {
        for (path, file) in &self.files {
            if pin_of(file).map_err(|e| format!("{path}: {e}"))? != self.pins[path] {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// (path, identity) of every pinned object, for `capture.module` rendering.
    pub fn identities(&self) -> impl Iterator<Item = (&str, &ObjectIdentity)> {
        self.identities.iter().map(|(p, i)| (p.as_str(), i))
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
        let len = match file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                problems.push(format!("{}: metadata failed ({error})", object.path));
                continue;
            }
        };
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
        pinned.push((object, file));
    }
    if !problems.is_empty() {
        return Err(problems);
    }

    let mut opened = BTreeMap::new();
    for (object, file) in pinned {
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
        opened.insert(object.id, (object.path.clone(), file, inspected));
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
            if let Some((path, _, inspected)) = opened.get(&object)
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
    let mut files = BTreeMap::new();
    let mut identities = BTreeMap::new();
    let mut pins = BTreeMap::new();
    for (path, file, inspected) in opened.into_values() {
        let pin = pin_of(&file).map_err(|e| vec![format!("{path}: {e}")])?;
        pins.insert(path.clone(), pin);
        identities.insert(path.clone(), inspected.identity);
        files.insert(path, file);
    }
    Ok(PinnedObjects {
        files,
        identities,
        pins,
    })
}
