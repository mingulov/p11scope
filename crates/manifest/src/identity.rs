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

#[cfg(feature = "identify")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MappingFileKey {
    /// The fd's mount identity from `/proc/self/fdinfo`. Zero only for lexical
    /// map-derived values that have no opened fd and are therefore not comparable.
    pub mount_id: u64,
    pub device_major: u64,
    pub device_minor: u64,
    pub inode: u64,
}

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

/// Returns the device/inode tuple rendered for this fd's mappings in
/// `/proc/*/maps`. On filesystems such as btrfs, `st_dev` can be an anonymous
/// subvolume device while maps reports the containing mount's device.
#[cfg(feature = "identify")]
pub fn mapping_file_key(file: &std::fs::File) -> Result<MappingFileKey, String> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("reading mount table failed: {error}"))?;
    mapping_file_key_in_mountinfo(file, &mountinfo)
}

/// Resolves an opened fd's mount ID in the mount table of the process view
/// through which it was opened. Mount IDs name mounts, not global devices, so a
/// foreign `/proc/<pid>/root` fd must not be resolved through the observer's table.
#[cfg(feature = "identify")]
pub fn mapping_file_key_in_mountinfo(
    file: &std::fs::File,
    mountinfo: &str,
) -> Result<MappingFileKey, String> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?;
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))
        .map_err(|error| format!("reading fd mount identity failed: {error}"))?;
    let mount_id = fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:\t"))
        .ok_or_else(|| "fd mount identity is missing".to_string())?;
    let parsed_mount_id = mount_id
        .parse()
        .map_err(|_| format!("invalid fd mount identity {mount_id:?}"))?;
    let device = mountinfo
        .lines()
        .find_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            (fields.next()? == mount_id)
                .then(|| fields.nth(1))
                .flatten()
        })
        .ok_or_else(|| format!("fd mount {mount_id} is missing from the mount table"))?;
    let (major, minor) = device
        .split_once(':')
        .ok_or_else(|| format!("invalid mount device {device:?}"))?;
    Ok(MappingFileKey {
        mount_id: parsed_mount_id,
        device_major: major
            .parse()
            .map_err(|_| format!("invalid mount device {device:?}"))?,
        device_minor: minor
            .parse()
            .map_err(|_| format!("invalid mount device {device:?}"))?,
        inode: metadata.ino(),
    })
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
    inspect_file_with_reader(file, |file, bytes, offset| file.read_at(bytes, offset))
}

/// Inspect one object while letting a caller enforce accounting at each actual read.
#[cfg(feature = "identify")]
pub fn inspect_file_with_reader(
    file: &std::fs::File,
    reader: impl FnMut(&std::fs::File, &mut [u8], u64) -> std::io::Result<usize>,
) -> Result<InspectedObject, String> {
    let data = read_object_bytes_with(file, reader)?;
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
pub(crate) fn read_object_bytes(file: &std::fs::File) -> Result<Vec<u8>, String> {
    read_object_bytes_with(file, |file, bytes, offset| file.read_at(bytes, offset))
}

#[cfg(feature = "identify")]
fn read_object_bytes_with(
    file: &std::fs::File,
    mut reader: impl FnMut(&std::fs::File, &mut [u8], u64) -> std::io::Result<usize>,
) -> Result<Vec<u8>, String> {
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
    let mut data = Vec::with_capacity(len.min(1024 * 1024));
    while data.len() < len {
        let done = data.len();
        let want = (len - done).min(1024 * 1024);
        data.resize(done + want, 0);
        let read = match reader(file, &mut data[done..], done as u64) {
            Ok(read) => read,
            Err(error) => {
                data.truncate(done);
                return Err(format!("read failed: {error}"));
            }
        };
        if read == 0 {
            data.truncate(done);
            return Err(format!("short read: {done} of {len} bytes"));
        }
        data.truncate(done + read);
    }
    Ok(data)
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

#[cfg(all(test, feature = "identify"))]
mod tests {
    use super::*;

    #[test]
    fn retained_process_view_mount_table_controls_the_mapping_device() {
        let file = open_object(Path::new("/bin/sh")).unwrap();
        let observer = mapping_file_key(&file).unwrap();
        let target_major = observer.device_major.saturating_add(1);
        let target_minor = observer.device_minor.saturating_add(1);
        let target_mountinfo = format!(
            "{} 1 {target_major}:{target_minor} / /target rw - ext4 /dev/target rw\n",
            observer.mount_id
        );

        let found = mapping_file_key_in_mountinfo(&file, &target_mountinfo).unwrap();
        assert_eq!(found.mount_id, observer.mount_id);
        assert_eq!(
            (found.device_major, found.device_minor),
            (target_major, target_minor),
            "an fd opened through a retained process view must resolve in that view's mount table"
        );
        assert_eq!(found.inode, observer.inode, "inode still comes from fstat");
        let error =
            mapping_file_key_in_mountinfo(&file, "999999 1 8:1 / /other rw - ext4 /dev/other rw\n")
                .expect_err("an absent view-local mount ID must remain incomparable");
        assert!(error.contains("is missing from the mount table"), "{error}");
    }
}
