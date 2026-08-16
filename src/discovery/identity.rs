//! Pins manifest-recorded objects to their current identity without holding read
//! leases. `check_unchanged` gives cheap, best-effort change detection via
//! `(ino, size, ctime)`; it is not a security boundary — the leased,
//! provenance-checked verification path it replaces was removed by
//! Productization Slice 1a (formerly `src/verify.rs`, restorable from history).

use std::collections::BTreeMap;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use p11scope_manifest::identity::{inspect_file, open_object};
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
    pins: BTreeMap<String, Pin>,
    /// Latched by `check_unchanged` the first time any pin differs.
    changed: std::cell::Cell<bool>,
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
    /// at pinning; `Ok(false)` when any changed (sticky: once seen, every later
    /// call is `Ok(false)` without re-checking); `Err` only when `fstat` itself fails.
    pub fn check_unchanged(&self) -> Result<bool, String> {
        if self.changed.get() {
            return Ok(false);
        }
        for (path, file) in &self.files {
            if pin_of(file).map_err(|e| format!("{path}: {e}"))? != self.pins[path] {
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
    let mut files = BTreeMap::new();
    let mut pins = BTreeMap::new();
    for (path, file, _, pin) in opened.into_values() {
        pins.insert(path.clone(), pin);
        files.insert(path, file);
    }
    Ok(PinnedObjects {
        files,
        pins,
        changed: std::cell::Cell::new(false),
    })
}
