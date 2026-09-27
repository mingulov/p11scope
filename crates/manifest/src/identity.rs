//! SPDX-License-Identifier: GPL-3.0-or-later
//! Per-object identity for manifest-reuse decisions. A manifest may only be
//! reused against a file whose identity matches (Gate G1: reuse refused on
//! content mismatch). Whole-file SHA-256 is authoritative; a GNU build ID is
//! retained as producer-supplied evidence. Non-ELF/unreadable input is
//! explicitly not reusable.

#[cfg(feature = "identify")]
use object::{Object as _, ObjectSegment as _};
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
use crate::elf::{ElfAbi, classified_object, exports_matching_in_object};
#[cfg(feature = "identify")]
use crate::maps::{Device, ObjectKey};

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedObject {
    pub identity: ObjectIdentity,
    pub executable_ranges: Vec<(u64, u64)>,
    pub abi: ElfAbi,
    /// `.dynsym` definitions of the names the caller asked for, as
    /// `(name, file offset)` in dynsym order — the same walk and the same
    /// definition rule (`is_definition`, which excludes `STT_GNU_IFUNC`) as
    /// [`crate::elf::exports_matching`]. Read from the bytes already hashed,
    /// so it costs no I/O. Empty when nothing was asked for.
    pub exports: Vec<(String, u64)>,
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

/// True when `error` is the missing-mount-id failure from
/// [`mapping_file_key_in_mountinfo`] — the only resolution failure a
/// mount-table re-read can heal (mount churn races the first read). Matches
/// the wrapped form too (`mapping identity unavailable: ...`); no other
/// constructor emits the substring.
#[cfg(feature = "identify")]
pub fn is_missing_mount_id_error(error: &str) -> bool {
    error.contains("is missing from the mount table")
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
    inspect_file_with_reader_exporting(file, reader, &[])
}

/// [`inspect_file_with_reader`] that also records the `.dynsym` definitions
/// of `wanted` (see [`InspectedObject::exports`]) from the same bytes.
#[cfg(feature = "identify")]
pub fn inspect_file_with_reader_exporting(
    file: &std::fs::File,
    reader: impl FnMut(&std::fs::File, &mut [u8], u64) -> std::io::Result<usize>,
    wanted: &[&str],
) -> Result<InspectedObject, String> {
    let data = read_object_bytes_with(file, reader)?;
    let (object, abi) = classified_object(&data)?;
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
    let exports = if wanted.is_empty() {
        Vec::new()
    } else {
        exports_matching_in_object(&object, wanted)
    };
    Ok(InspectedObject {
        identity,
        executable_ranges,
        abi,
        exports,
    })
}

#[cfg(feature = "identify")]
pub(crate) fn read_object_bytes(file: &std::fs::File) -> Result<Vec<u8>, String> {
    read_object_bytes_with(file, |file, bytes, offset| file.read_at(bytes, offset))
}

#[cfg(feature = "identify")]
pub(crate) fn read_object_bytes_with(
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

/// The pre-6.8 overlayfs maps-identity split, and its exact fallback.
///
/// Before 6.8, overlayfs installs the real (backing) file in the VMA, so
/// `/proc/<pid>/maps` prints the backing `s_dev:i_ino` while the opened fd —
/// resolved through mountinfo — names the overlay device. Both name the same
/// physical file, yet every maps-key-vs-opened-fd comparison refuses it.
/// Since 6.8 maps prints the overlay identity and the keys agree.
///
/// The self-mapping identity probe closes the split without weakening the
/// proof: when the keys differ and the fd is on overlayfs, mmap one page of
/// the already-opened fd (`PROT_READ`, `MAP_PRIVATE`, never `PROT_EXEC`),
/// read this process's own `/proc/self/maps` line for that address, and
/// accept iff the kernel-rendered `(device, inode)` exactly equals the
/// target's maps key. The same kernel code produces both lines, so the
/// accept is exact physical identity, not a heuristic. Every other outcome —
/// non-overlay, unmappable, probe failure, mismatch — refuses exactly as
/// before, with the caller's own message unchanged.
///
/// One implementation serves the observer and `p11scope-discover`: the trait
/// and seam, the real mmap probe, and the bounded maps reader with its
/// parser all live here. Budget accounting is the caller's: the observer
/// passes a thin adapter over `CaptureWorkBudget` (identical charging), the
/// helper passes [`UnboundedProbeBudget`].
#[cfg(feature = "identify")]
pub const OVERLAYFS_SUPER_MAGIC: u64 = 0x794c_7630;

/// The accounting surface the probe's `/proc/self/maps` read charges. The
/// observer adapts `CaptureWorkBudget` 1:1 (deadline, per-chunk and per-line
/// units, bytes); the helper has no budget and passes
/// [`UnboundedProbeBudget`]. The 1 MiB single-line cap and stop-at-match
/// bound apply in both.
#[cfg(feature = "identify")]
pub trait ProbeBudget {
    /// True when the caller is already stopped (deadline or ceiling).
    fn probe_expired(&mut self) -> bool;
    /// Bytes the read may take this chunk, honouring the caller's ceilings.
    fn probe_allowed_io(&mut self, operation_bytes: u64, wanted: usize) -> usize;
    /// Spend one work unit; false refuses (exhausted).
    fn probe_spend(&mut self) -> bool;
    /// Record bytes actually read.
    fn probe_record_io(&mut self, bytes: usize);
}

/// [`ProbeBudget`] for callers without a capture budget: never expires,
/// always allows, always spends, records nothing. The probe's own bounds
/// (stop at the mapping's line, 1 MiB single-line cap, fail closed) still
/// apply.
#[cfg(feature = "identify")]
pub struct UnboundedProbeBudget;

#[cfg(feature = "identify")]
impl ProbeBudget for UnboundedProbeBudget {
    fn probe_expired(&mut self) -> bool {
        false
    }

    fn probe_allowed_io(&mut self, _operation_bytes: u64, wanted: usize) -> usize {
        wanted
    }

    fn probe_spend(&mut self) -> bool {
        true
    }

    fn probe_record_io(&mut self, _bytes: usize) {}
}

#[cfg(feature = "identify")]
pub trait SelfMappingProbe {
    /// Whether `file` was reached through an overlay mount (`fstatfs` magic).
    fn fd_is_on_overlayfs(&self, file: &std::fs::File) -> bool;
    /// How the kernel renders `file` in `/proc` maps: one private read-only
    /// page of the fd, then its own maps line. `None` is inconclusive and
    /// always refuses. The read is charged to `budget` and stops at the
    /// mapping's line.
    fn kernel_maps_key(
        &self,
        file: &std::fs::File,
        budget: &mut dyn ProbeBudget,
    ) -> Option<ObjectKey>;
}

/// [`SelfMappingProbe`] against the live kernel.
#[cfg(feature = "identify")]
pub struct KernelSelfMappingProbe;

#[cfg(feature = "identify")]
impl SelfMappingProbe for KernelSelfMappingProbe {
    fn fd_is_on_overlayfs(&self, file: &std::fs::File) -> bool {
        fd_is_on_overlayfs(file)
    }

    fn kernel_maps_key(
        &self,
        file: &std::fs::File,
        budget: &mut dyn ProbeBudget,
    ) -> Option<ObjectKey> {
        kernel_maps_key_for(file, budget)
    }
}

/// `ovl_statfs` reports the underlying filesystem's numbers but overrides
/// `f_type` with the overlay's own magic, so this answers "was this file
/// reached *through* an overlay mount", which is the question, and not "what
/// is it ultimately stored on". Fail-closed: an `fstatfs` error is not
/// overlay.
#[cfg(feature = "identify")]
pub fn fd_is_on_overlayfs(file: &std::fs::File) -> bool {
    let mut buf = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `fstatfs` fills `buf` for a valid fd and is only read on success.
    if unsafe { libc::fstatfs(file.as_raw_fd(), buf.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: the successful `fstatfs` above initialized `buf`.
    unsafe { buf.assume_init().f_type as u64 == OVERLAYFS_SUPER_MAGIC }
}

#[cfg(feature = "identify")]
pub fn has_mappable_bytes(file: &std::fs::File) -> bool {
    file.metadata().is_ok_and(|metadata| metadata.len() != 0)
}

/// The kernel-rendered maps key for one opened fd: mmap one page
/// (`PROT_READ`, `MAP_PRIVATE`, never `PROT_EXEC`) and read this process's
/// own maps line for that address. `None` is inconclusive and always
/// refuses.
#[cfg(feature = "identify")]
pub fn kernel_maps_key_for(
    file: &std::fs::File,
    budget: &mut dyn ProbeBudget,
) -> Option<ObjectKey> {
    if !has_mappable_bytes(file) {
        return None;
    }
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let len = usize::try_from(page).unwrap_or(4096).max(1);
    // SAFETY: one private read-only page of a borrowed valid fd at
    // offset 0; never PROT_EXEC; unmapped by the guard below.
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return None;
    }
    let _mapping = MappedProbe { base, len };
    read_self_maps_key_for(base as u64, budget)
}

/// One private read-only page of an already-opened fd, unmapped on drop —
/// including every error path out of the probe.
#[cfg(feature = "identify")]
struct MappedProbe {
    base: *mut libc::c_void,
    len: usize,
}

#[cfg(feature = "identify")]
impl Drop for MappedProbe {
    fn drop(&mut self) {
        // SAFETY: the probe mapped exactly this range with mmap, owns it
        // exclusively, and Drop runs once.
        unsafe {
            libc::munmap(self.base, self.len);
        }
    }
}

/// The kernel-rendered key for the mapping containing `addr` in this
/// process's own maps. Charged through `budget` (one unit per chunk and per
/// line, bytes recorded) and stops at the mapping's line.
#[cfg(feature = "identify")]
pub fn read_self_maps_key_for(addr: u64, budget: &mut dyn ProbeBudget) -> Option<ObjectKey> {
    use std::io::Read as _;
    let mut reader = std::fs::File::open("/proc/self/maps").ok()?;
    let mut operation_bytes = 0u64;
    let mut pending = Vec::new();
    let mut chunk = vec![0u8; 4096];
    loop {
        if budget.probe_expired() {
            return None;
        }
        let allowed = budget.probe_allowed_io(operation_bytes, chunk.len());
        if allowed == 0 {
            return None;
        }
        if !budget.probe_spend() {
            return None;
        }
        let read = match reader.read(&mut chunk[..allowed]) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        };
        budget.probe_record_io(read);
        operation_bytes = operation_bytes.saturating_add(read as u64);
        if read == 0 {
            if pending.is_empty() {
                return None;
            }
            return parse_probed_maps_line(&pending, addr).ok().flatten();
        }
        pending.extend_from_slice(&chunk[..read]);
        while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            if !budget.probe_spend() {
                return None;
            }
            match parse_probed_maps_line(&line[..line.len() - 1], addr) {
                Ok(Some(key)) => return Some(key),
                Ok(None) => {}
                Err(()) => return None,
            }
        }
        // A real maps line is hundreds of bytes; a megabyte without a
        // newline is not one. Fail closed instead of buffering on.
        if pending.len() > 1024 * 1024 {
            return None;
        }
    }
}

/// Whether one opened fd may stand for a maps identity: equal keys accept
/// without consulting the probe; a split identity accepts only when the
/// kernel renders this exact fd at the maps key.
#[cfg(feature = "identify")]
pub fn opened_file_matches_maps(
    file: &std::fs::File,
    fd_key: ObjectKey,
    maps_key: ObjectKey,
    budget: &mut dyn ProbeBudget,
    probe: &impl SelfMappingProbe,
) -> bool {
    if fd_key == maps_key {
        return true;
    }
    if !probe.fd_is_on_overlayfs(file) {
        return false;
    }
    if !has_mappable_bytes(file) {
        return false;
    }
    probe
        .kernel_maps_key(file, budget)
        .is_some_and(|probed| probed == maps_key)
}

/// The maps key to retry a snapshot with when an overlay fd's own key found
/// no mapping: `None` unless the kernel renders this exact fd at a
/// *different* key, so a pointless same-key retry never runs.
#[cfg(feature = "identify")]
pub fn self_mapped_fallback_key(
    file: &std::fs::File,
    fd_key: ObjectKey,
    budget: &mut dyn ProbeBudget,
    probe: &impl SelfMappingProbe,
) -> Option<ObjectKey> {
    if !probe.fd_is_on_overlayfs(file) {
        return None;
    }
    if !has_mappable_bytes(file) {
        return None;
    }
    let probed = probe.kernel_maps_key(file, budget)?;
    (probed != fd_key).then_some(probed)
}

#[cfg(feature = "identify")]
fn split_field(field: &[u8], separator: u8) -> Option<(&[u8], &[u8])> {
    let position = field.iter().position(|byte| *byte == separator)?;
    Some((&field[..position], &field[position + 1..]))
}

#[cfg(feature = "identify")]
fn parse_hex_field(field: &[u8]) -> Option<u64> {
    if field.is_empty() || !field.iter().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    std::str::from_utf8(field)
        .ok()
        .and_then(|text| u64::from_str_radix(text, 16).ok())
}

#[cfg(feature = "identify")]
fn parse_decimal_field(field: &[u8]) -> Option<u64> {
    if field.is_empty() || !field.iter().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    // The digit pre-check above already rejected `+`, which `parse` accepts.
    std::str::from_utf8(field)
        .ok()
        .and_then(|text| text.parse().ok())
}

/// Parse one `/proc/self/maps` line for the self-mapping probe: `Ok(Some)`
/// when the line's range contains `addr`, `Ok(None)` for any other
/// well-formed line, `Err(())` when the line is malformed. Malformed fails
/// closed — an unparseable line could be the mapping's own. Private: only
/// the probe's own reader consults it.
#[cfg(feature = "identify")]
fn parse_probed_maps_line(line: &[u8], addr: u64) -> Result<Option<ObjectKey>, ()> {
    // <start>-<end> <perms> <offset> <major:minor hex> <inode decimal> [path]
    let mut fields = line
        .split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty());
    let range = fields.next().ok_or(())?;
    fields.next().ok_or(())?;
    fields.next().ok_or(())?;
    let device = fields.next().ok_or(())?;
    let inode = fields.next().ok_or(())?;
    let (start, end) = split_field(range, b'-').ok_or(())?;
    let (major, minor) = split_field(device, b':').ok_or(())?;
    let start = parse_hex_field(start).ok_or(())?;
    let end = parse_hex_field(end).ok_or(())?;
    if start >= end {
        return Err(());
    }
    let major = parse_hex_field(major).ok_or(())?;
    let minor = parse_hex_field(minor).ok_or(())?;
    let inode = parse_decimal_field(inode).ok_or(())?;
    if start <= addr && addr < end {
        Ok(Some(ObjectKey {
            device: Device { major, minor },
            inode,
        }))
    } else {
        Ok(None)
    }
}

#[cfg(all(test, feature = "identify"))]
mod tests {
    use super::*;
    use std::cell::Cell;

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

    #[test]
    fn the_missing_mount_classifier_matches_only_the_missing_mount_error() {
        let file = open_object(Path::new("/bin/sh")).unwrap();
        let missing =
            mapping_file_key_in_mountinfo(&file, "999999 1 8:1 / /other rw - ext4 /dev/other rw\n")
                .expect_err("fixture table lacks the fd's mount");
        assert!(is_missing_mount_id_error(&missing));
        assert!(is_missing_mount_id_error(&format!(
            "mapping identity unavailable: {missing}"
        )));
        for other in [
            "metadata failed: stale",
            "reading fd mount identity failed: stale",
            "fd mount identity is missing",
            "invalid fd mount identity \"x\"",
            "invalid mount device \"8\"",
        ] {
            assert!(!is_missing_mount_id_error(other), "{other}");
        }
    }

    #[test]
    fn an_early_zero_read_is_rejected_as_a_short_read() {
        let file = open_object(Path::new("/bin/sh")).unwrap();
        let len = file.metadata().unwrap().len();
        let calls = Cell::new(0);
        let result = read_object_bytes_with(&file, |_, bytes, _| {
            let call = calls.get();
            calls.set(call + 1);
            if call == 0 { Ok(0) } else { Ok(bytes.len()) }
        });

        assert_eq!(calls.get(), 1, "the short-read guard stops before a retry");
        let expected = format!("short read: 0 of {len} bytes");
        assert!(
            matches!(&result, Err(error) if error == &expected),
            "expected {expected:?}, got {}",
            match &result {
                Ok(bytes) => format!("Ok({} bytes)", bytes.len()),
                Err(error) => format!("Err({error})"),
            }
        );
    }

    /// A scripted self-mapping probe: `overlay` answers the overlayfs
    /// question and `key` answers the kernel-rendered maps key, counting both
    /// consultations. Real overlayfs is unmountable without privileges, so
    /// unit tests script the kernel side of the split.
    struct FakeSelfMappingProbe {
        overlay: bool,
        key: Option<ObjectKey>,
        overlay_checks: Cell<usize>,
        probes: Cell<usize>,
    }

    impl FakeSelfMappingProbe {
        fn new(overlay: bool, key: Option<ObjectKey>) -> Self {
            Self {
                overlay,
                key,
                overlay_checks: Cell::new(0),
                probes: Cell::new(0),
            }
        }
    }

    impl SelfMappingProbe for FakeSelfMappingProbe {
        fn fd_is_on_overlayfs(&self, _file: &std::fs::File) -> bool {
            self.overlay_checks.set(self.overlay_checks.get() + 1);
            self.overlay
        }

        fn kernel_maps_key(
            &self,
            _file: &std::fs::File,
            _budget: &mut dyn ProbeBudget,
        ) -> Option<ObjectKey> {
            self.probes.set(self.probes.get() + 1);
            self.key
        }
    }

    /// The inode a two-container docker run really produced for one shared
    /// image-layer object.
    const INODE: u64 = 56_317_450;

    fn overlay(minor: u64) -> ObjectKey {
        ObjectKey {
            device: Device { major: 0, minor },
            inode: INODE,
        }
    }

    /// The backing identity a pre-6.8 kernel prints for an overlay mapping:
    /// `00:15` is 0:21, the measured 6.1 rendering of the `overlay(41)` fd.
    fn backing_key() -> ObjectKey {
        ObjectKey {
            device: Device {
                major: 0,
                minor: 21,
            },
            inode: INODE,
        }
    }

    /// A real file on a real filesystem for probe fixtures. Uses the process
    /// temp dir so the repo's `TMPDIR` lane override applies.
    fn probe_tempfile(name: &str) -> (std::path::PathBuf, std::fs::File) {
        let dir = std::env::temp_dir().join(format!(
            "p11scope-manifest-probe-{}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("probed.so");
        std::fs::write(&path, "p11scope-self-mapping-probe:page-one").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        (dir, file)
    }

    struct CountingBudget {
        spends: usize,
        recorded: u64,
    }

    impl ProbeBudget for CountingBudget {
        fn probe_expired(&mut self) -> bool {
            false
        }

        fn probe_allowed_io(&mut self, _operation_bytes: u64, wanted: usize) -> usize {
            wanted
        }

        fn probe_spend(&mut self) -> bool {
            self.spends += 1;
            true
        }

        fn probe_record_io(&mut self, bytes: usize) {
            self.recorded += bytes as u64;
        }
    }

    struct RefusingBudget;

    impl ProbeBudget for RefusingBudget {
        fn probe_expired(&mut self) -> bool {
            false
        }

        fn probe_allowed_io(&mut self, _operation_bytes: u64, _wanted: usize) -> usize {
            0
        }

        fn probe_spend(&mut self) -> bool {
            false
        }

        fn probe_record_io(&mut self, _bytes: usize) {}
    }

    #[test]
    fn equal_fd_and_maps_keys_accept_without_consulting_the_probe() {
        let (_dir, file) = probe_tempfile("equal");
        let probe = FakeSelfMappingProbe::new(true, None);
        let mut budget = UnboundedProbeBudget;
        assert!(opened_file_matches_maps(
            &file,
            overlay(41),
            overlay(41),
            &mut budget,
            &probe,
        ));
        assert_eq!(probe.overlay_checks.get(), 0);
        assert_eq!(probe.probes.get(), 0);
    }

    #[test]
    fn overlay_probe_match_accepts_a_split_identity() {
        let (_dir, file) = probe_tempfile("match");
        let probe = FakeSelfMappingProbe::new(true, Some(backing_key()));
        let mut budget = UnboundedProbeBudget;
        assert!(opened_file_matches_maps(
            &file,
            overlay(41),
            backing_key(),
            &mut budget,
            &probe,
        ));
        assert_eq!(probe.probes.get(), 1);
    }

    #[test]
    fn overlay_probe_mismatch_refuses() {
        let (_dir, file) = probe_tempfile("mismatch");
        let probe = FakeSelfMappingProbe::new(true, Some(overlay(43)));
        let mut budget = UnboundedProbeBudget;
        assert!(!opened_file_matches_maps(
            &file,
            overlay(41),
            backing_key(),
            &mut budget,
            &probe,
        ));
    }

    #[test]
    fn non_overlay_mismatch_refuses_without_probing() {
        let (_dir, file) = probe_tempfile("non-overlay");
        let probe = FakeSelfMappingProbe::new(false, Some(backing_key()));
        let mut budget = UnboundedProbeBudget;
        assert!(!opened_file_matches_maps(
            &file,
            overlay(41),
            backing_key(),
            &mut budget,
            &probe,
        ));
        assert_eq!(probe.overlay_checks.get(), 1);
        assert_eq!(probe.probes.get(), 0);
    }

    #[test]
    fn inconclusive_probe_refuses() {
        let (_dir, file) = probe_tempfile("inconclusive");
        let probe = FakeSelfMappingProbe::new(true, None);
        let mut budget = UnboundedProbeBudget;
        assert!(!opened_file_matches_maps(
            &file,
            overlay(41),
            backing_key(),
            &mut budget,
            &probe,
        ));
    }

    #[test]
    fn overlay_probe_skips_unmappable_files_without_probing() {
        let dir = std::env::temp_dir().join(format!(
            "p11scope-manifest-probe-{}-empty",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.so");
        std::fs::write(&path, b"").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let probe = FakeSelfMappingProbe::new(true, Some(backing_key()));
        let mut budget = UnboundedProbeBudget;
        assert!(!opened_file_matches_maps(
            &file,
            overlay(41),
            backing_key(),
            &mut budget,
            &probe,
        ));
        assert_eq!(probe.probes.get(), 0);
    }

    #[test]
    fn self_mapped_fallback_key_returns_a_differing_probed_key() {
        let (_dir, file) = probe_tempfile("fallback");
        let probe = FakeSelfMappingProbe::new(true, Some(backing_key()));
        let mut budget = UnboundedProbeBudget;
        assert_eq!(
            self_mapped_fallback_key(&file, overlay(41), &mut budget, &probe),
            Some(backing_key())
        );
    }

    #[test]
    fn self_mapped_fallback_key_stays_none_without_a_retry_worth_making() {
        let (_dir, file) = probe_tempfile("fallback-none");
        let mut budget = UnboundedProbeBudget;
        let refused = FakeSelfMappingProbe::new(false, Some(backing_key()));
        assert_eq!(
            self_mapped_fallback_key(&file, overlay(41), &mut budget, &refused),
            None
        );
        assert_eq!(refused.probes.get(), 0);
        let inconclusive = FakeSelfMappingProbe::new(true, None);
        assert_eq!(
            self_mapped_fallback_key(&file, overlay(41), &mut budget, &inconclusive),
            None
        );
        let same = FakeSelfMappingProbe::new(true, Some(overlay(41)));
        assert_eq!(
            self_mapped_fallback_key(&file, overlay(41), &mut budget, &same),
            None,
            "a probe that repeats the fd key must not trigger a same-key retry"
        );
    }

    #[test]
    fn probed_maps_line_parses_hex_devices_and_decimal_inodes() {
        // The measured 6.1 rendering: backing device 00:15, inode 712355.
        let line = b"7fb053667000-7fb05367c000 r--p 00000000 00:15 712355 \
                     /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so";
        assert_eq!(
            parse_probed_maps_line(line, 0x7fb053667000),
            Ok(Some(ObjectKey {
                device: Device {
                    major: 0,
                    minor: 21
                },
                inode: 712355,
            }))
        );
        let upper = b"1000-2000 r--p 00000000 0A:fF 42 /lib/x.so";
        assert_eq!(
            parse_probed_maps_line(upper, 0x1000),
            Ok(Some(ObjectKey {
                device: Device {
                    major: 10,
                    minor: 255,
                },
                inode: 42,
            }))
        );
    }

    #[test]
    fn probed_maps_line_matches_only_its_own_range() {
        let line = b"1000-2000 r--p 00000000 00:15 7 /lib/x.so";
        let key = ObjectKey {
            device: Device {
                major: 0,
                minor: 21,
            },
            inode: 7,
        };
        assert_eq!(parse_probed_maps_line(line, 0x1000), Ok(Some(key)));
        assert_eq!(parse_probed_maps_line(line, 0x1fff), Ok(Some(key)));
        assert_eq!(parse_probed_maps_line(line, 0x2000), Ok(None));
        assert_eq!(parse_probed_maps_line(line, 0x0fff), Ok(None));
        assert_eq!(parse_probed_maps_line(line, 0x3000), Ok(None));
    }

    #[test]
    fn malformed_probed_maps_lines_fail_closed() {
        for line in [
            b"".as_slice(),
            b"1000-2000 r--p 00000000".as_slice(),
            b"1000-2000 r--p 00000000 00:15".as_slice(),
            b"1000_2000 r--p 00000000 00:15 7".as_slice(),
            b"zz-2000 r--p 00000000 00:15 7".as_slice(),
            b"2000-1000 r--p 00000000 00:15 7".as_slice(),
            b"1000-1000 r--p 00000000 00:15 7".as_slice(),
            b"1000-2000 r--p 00000000 0015 7".as_slice(),
            b"1000-2000 r--p 00000000 00:zz 7".as_slice(),
            b"1000-2000 r--p 00000000 00:15 xx".as_slice(),
            b"1000-2000 r--p 00000000 00:15 0x10".as_slice(),
            b"1000-2000 r--p 00000000 00:15 18446744073709551616".as_slice(),
        ] {
            assert_eq!(parse_probed_maps_line(line, 0x1000), Err(()), "{}", {
                String::from_utf8_lossy(line).into_owned()
            });
        }
    }

    /// Independent oracle for the real probe: map the file here and read the
    /// kernel's own maps line for that address with a deliberately minimal
    /// parse, so the probe's read path and parser are both checked. Compared
    /// against the maps rendering, never fstat: on btrfs the same file's
    /// st_dev (anonymous subvolume device, observed 0:37) differs from its
    /// maps s_dev (observed 00:23) — the reason retained identity resolves
    /// through mountinfo.
    fn maps_key_for_fresh_mapping(file: &std::fs::File) -> ObjectKey {
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(addr, libc::MAP_FAILED, "the oracle mapping must succeed");
        let addr = addr as u64;
        let text = std::fs::read_to_string("/proc/self/maps").unwrap();
        let mut found = None;
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            let range = fields.next().unwrap();
            let (start, end) = range.split_once('-').unwrap();
            let (start, end) = (
                u64::from_str_radix(start, 16).unwrap(),
                u64::from_str_radix(end, 16).unwrap(),
            );
            if start <= addr && addr < end {
                let device = fields.nth(2).unwrap();
                let inode: u64 = fields.next().unwrap().parse().unwrap();
                let (major, minor) = device.split_once(':').unwrap();
                found = Some(ObjectKey {
                    device: Device {
                        major: u64::from_str_radix(major, 16).unwrap(),
                        minor: u64::from_str_radix(minor, 16).unwrap(),
                    },
                    inode,
                });
                break;
            }
        }
        assert_eq!(unsafe { libc::munmap(addr as *mut libc::c_void, 4096) }, 0);
        found.expect("the fresh mapping has a maps line")
    }

    #[test]
    fn real_probe_reports_the_key_maps_shows_for_a_plain_mapping() {
        let (_dir, file) = probe_tempfile("real");
        let mut budget = CountingBudget {
            spends: 0,
            recorded: 0,
        };
        let probed = KernelSelfMappingProbe
            .kernel_maps_key(&file, &mut budget)
            .expect("a plain temp file probes");
        assert!(
            budget.spends > 0 && budget.recorded > 0,
            "the probe's /proc/self/maps read is charged through the budget"
        );
        assert_eq!(probed, maps_key_for_fresh_mapping(&file));
        assert_eq!(
            probed.inode,
            {
                use std::os::unix::fs::MetadataExt as _;
                file.metadata().unwrap().ino()
            },
            "the same file keeps its inode in both renderings"
        );
    }

    #[test]
    fn real_probe_refuses_an_empty_file() {
        let dir = std::env::temp_dir().join(format!(
            "p11scope-manifest-probe-{}-real-empty",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.so");
        std::fs::write(&path, b"").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let mut budget = UnboundedProbeBudget;
        assert_eq!(
            KernelSelfMappingProbe.kernel_maps_key(&file, &mut budget),
            None
        );
    }

    #[test]
    fn real_probe_refuses_an_unmappable_fd() {
        let (dir, _) = probe_tempfile("real-opath");
        // O_PATH fds cannot back a mapping, so mmap fails and the probe is
        // inconclusive rather than wrong.
        let unmappable = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(dir.join("probed.so"))
            .unwrap();
        let mut budget = UnboundedProbeBudget;
        assert_eq!(
            KernelSelfMappingProbe.kernel_maps_key(&unmappable, &mut budget),
            None
        );
    }

    #[test]
    fn real_probe_refuses_when_the_budget_is_exhausted() {
        let (_dir, file) = probe_tempfile("real-refused");
        let mut budget = RefusingBudget;
        assert_eq!(
            KernelSelfMappingProbe.kernel_maps_key(&file, &mut budget),
            None
        );
    }
}
