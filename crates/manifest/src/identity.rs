//! Per-object identity for manifest-reuse decisions. A manifest may only be
//! reused against a file whose identity matches (Gate G1: reuse refused on
//! content mismatch). Whole-file SHA-256 is authoritative; a GNU build ID is
//! retained as producer-supplied evidence. Non-ELF/unreadable input is
//! explicitly not reusable.

#[cfg(feature = "identify")]
use object::{BinaryFormat, Object as _, ObjectSegment as _};
use serde::{Deserialize, Serialize};
#[cfg(feature = "identify")]
use sha2::{Digest as _, Sha256};
#[cfg(feature = "identify")]
use std::os::fd::AsRawFd as _;
#[cfg(feature = "identify")]
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
#[cfg(feature = "identify")]
use std::path::Path;

#[cfg(feature = "identify")]
pub const MAX_OBJECT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    GnuBuildId,
    Sha256,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectIdentity {
    pub kind: IdentityKind,
    /// Hex digest; `None` only when `kind == Unavailable`.
    pub value: Option<String>,
    /// Whole-file cryptographic identity used for authorization. GNU build IDs
    /// remain useful evidence but are producer-chosen and cannot authenticate
    /// a byte-identical safe copy on their own.
    pub sha256: Option<String>,
    /// Whether a manifest may be reused against a file with this identity.
    pub reusable: bool,
    pub note: Option<String>,
}

#[cfg(feature = "identify")]
pub fn identify(path: &Path) -> ObjectIdentity {
    match open_object(path).and_then(|file| inspect_file(&file)) {
        Ok(inspected) => inspected.identity,
        Err(note) => unavailable(note),
    }
}

#[cfg(feature = "identify")]
pub struct InspectedObject {
    pub identity: ObjectIdentity,
    pub executable_ranges: Vec<(u64, u64)>,
}

#[cfg(feature = "identify")]
impl InspectedObject {
    pub fn contains_executable_offset(&self, offset: u64) -> bool {
        self.executable_ranges
            .iter()
            .any(|(start, end)| *start <= offset && offset < *end)
    }
}

#[cfg(feature = "identify")]
pub fn open_object(path: &Path) -> Result<std::fs::File, String> {
    let file = open_regular(path)?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?;
    if metadata.len() > MAX_OBJECT_BYTES {
        return Err(format!(
            "object is {} bytes; limit is {MAX_OBJECT_BYTES}",
            metadata.len()
        ));
    }
    Ok(file)
}

/// Pins the pathname without invoking device/FIFO open semantics, verifies
/// the pinned inode is regular, then obtains a readable descriptor for that
/// same inode. Normal provider symlinks remain supported safely.
#[cfg(feature = "identify")]
pub fn open_regular(path: &Path) -> Result<std::fs::File, String> {
    let pinned = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("open failed: {error}"))?;
    let metadata = pinned
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("not a regular file".into());
    }
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
        .map_err(|error| format!("opening pinned regular file failed: {error}"))
}

#[cfg(feature = "identify")]
pub fn inspect_file(file: &std::fs::File) -> Result<InspectedObject, String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("not a regular file".into());
    }
    let len = metadata.len();
    if len > MAX_OBJECT_BYTES {
        return Err(format!(
            "object is {len} bytes; limit is {MAX_OBJECT_BYTES}"
        ));
    }
    let len: usize = len
        .try_into()
        .map_err(|_| "object length does not fit usize")?;
    let mut data = vec![0u8; len];
    let mut done = 0;
    while done < data.len() {
        let read = file
            .read_at(&mut data[done..], done as u64)
            .map_err(|error| format!("read failed: {error}"))?;
        if read == 0 {
            return Err(format!("short read: {done} of {} bytes", data.len()));
        }
        done += read;
    }

    let object = object::File::parse(&*data)
        .map_err(|error| format!("not parseable as an object file: {error}"))?;
    if object.format() != BinaryFormat::Elf {
        return Err(format!("not an ELF object ({:?})", object.format()));
    }
    let sha256 = hex(&Sha256::digest(&data));
    let mut note = None;
    // object reads the build-id from PT_NOTE program headers too, so a
    // stripped section table does not lose it (review finding, 2026-08-11).
    let identity = match object.build_id() {
        Ok(Some(id)) => ObjectIdentity {
            kind: IdentityKind::GnuBuildId,
            value: Some(hex(id)),
            sha256: Some(sha256.clone()),
            reusable: true,
            note: None,
        },
        Ok(None) => ObjectIdentity {
            kind: IdentityKind::Sha256,
            value: Some(sha256.clone()),
            sha256: Some(sha256.clone()),
            reusable: true,
            note,
        },
        Err(error) => {
            note = Some(format!("build-id read failed: {error}"));
            ObjectIdentity {
                kind: IdentityKind::Sha256,
                value: Some(sha256.clone()),
                sha256: Some(sha256),
                reusable: true,
                note,
            }
        }
    };
    let executable_ranges = object
        .segments()
        .filter(|segment| segment.permissions().executable())
        .filter_map(|segment| {
            let (start, size) = segment.file_range();
            start.checked_add(size).map(|end| (start, end))
        })
        .collect();
    Ok(InspectedObject {
        identity,
        executable_ranges,
    })
}

#[cfg(feature = "identify")]
fn unavailable(note: String) -> ObjectIdentity {
    ObjectIdentity {
        kind: IdentityKind::Unavailable,
        value: None,
        sha256: None,
        reusable: false,
        note: Some(note),
    }
}

#[cfg(feature = "identify")]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
