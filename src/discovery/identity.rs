//! SPDX-License-Identifier: GPL-3.0-or-later
//! Pins objects — manifest-recorded or scan-discovered — to their current identity
//! without holding read leases. `check_unchanged` gives cheap, best-effort change
//! detection via `(ino, size, ctime)`; it is not a security boundary — the leased,
//! provenance-checked verification path it replaces was removed by
//! Productization Slice 1a (formerly `src/verify.rs`, restorable from history).
//!
//! Mount-table churn tolerance: view-local identity resolution re-reads the
//! view's `/proc/<pid>/mountinfo` exactly once when the fd's mount row is
//! missing from the first read, then re-resolves in the fresh table. Any other
//! resolution failure — or a mount still missing after the re-read — fails
//! with today's error text unchanged, so the retry only ever converts churn
//! flakes into successes and never masks a genuine failure.

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{AsRawFd as _, RawFd};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use p11scope_manifest::elf::ElfAbi;
use p11scope_manifest::identity::{
    IdentityKind, InspectedObject, MappingFileKey, inspect_file_with_reader_exporting,
    is_missing_mount_id_error, mapping_file_key, mapping_file_key_in_mountinfo, open_object,
    open_regular,
};
use p11scope_manifest::manifest::{Manifest, Resolution};
use p11scope_manifest::maps::{Device, ObjectKey};

use crate::discovery::scan::{
    CaptureWorkBudget, IO_CEILING_REASON, InspectedFileKey, ScannedModule, Skipped, read_mountinfo,
    standard_function_names,
};
use crate::manifest_input::{MAX_TOTAL_OBJECT_BYTES, validate_structure};
use crate::process::{MountNamespaceId, MountTableCache, ProcessView, ProcessViewId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Pin {
    ino: u64,
    size: u64,
    ctime: (i64, i64),
}

pub(crate) fn pin_of(file: &std::fs::File) -> Result<Pin, String> {
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

/// Path spelling is only part of a validated manifest-to-scan relation, never
/// attach identity. Exposed so the orchestrator uses the same normalization as
/// the raw aliases that resolve to `PinnedObjectId`.
pub fn target_paths_equal(left: &str, right: &str) -> bool {
    normalize_target_path(left)
        .zip(normalize_target_path(right))
        .is_some_and(|(left, right)| left == right)
}

#[derive(Debug, Clone)]
struct Entry {
    raw: RawObjectInstance,
    mapping: MappingFileKey,
    file: Arc<std::fs::File>,
    pin: Pin,
    path: String,
    sha256: String,
    build_id: Option<String>,
    abi: ElfAbi,
    /// The object's own `.dynsym` definitions of standard PKCS#11 function
    /// names, `(name, file offset)`, read from the bytes that were hashed.
    /// Export linkage's witness (`scan::export_agreement`); file-derived, so
    /// every entry for one digest carries the same list.
    exports: Arc<[(String, u64)]>,
    /// Whether this object was opened through overlayfs. This narrows the collapse
    /// heuristic but does not prove that another overlay instance resolves to the
    /// same underlying kernel inode.
    overlay: bool,
    /// Sticky: another mapping was folded onto this entry by the overlayfs
    /// heuristic (same-key alias or cross-key canonicalization). Such an
    /// entry stands for more than one proven kernel file, so its raw key is
    /// never a sweep-matching key (`sweep_match_keys`).
    collapsed: bool,
}

/// The exact, bounded pin subset retained by private Inventory activation.
/// Cloning one entry preserves its complete canonical identity and opened file;
/// it does not clone discovery ownership graphs or reopen a pathname.
#[derive(Debug)]
pub(crate) struct RetainedInventoryTarget {
    entry: Entry,
    changed: std::cell::Cell<bool>,
}

impl RetainedInventoryTarget {
    /// A second owner of this retained object: the same opened file (one
    /// shared `Arc`, no reopen, no new descriptor), the same canonical
    /// identity, and the sticky changed evidence observed so far. The
    /// capture facade holds these so its links never borrow the attach set.
    pub(crate) fn share(&self) -> Self {
        Self {
            entry: self.entry.clone(),
            changed: std::cell::Cell::new(self.changed.get()),
        }
    }

    pub(crate) fn retirement_lease(&self) -> Arc<std::fs::File> {
        // The retirement worker needs only custody of the already-open file.
        // Identity and sticky mutation checks stay with the main target owner.
        self.entry.file.clone()
    }

    pub(crate) fn abi(&self) -> ElfAbi {
        self.entry.abi
    }

    pub(crate) fn attach_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.entry.file.as_raw_fd()))
    }

    /// Same best-effort metadata check as `PinnedObjects`, with independent
    /// sticky evidence after the discovery owner has released its copy.
    pub(crate) fn check_unchanged(&self) -> Result<bool, String> {
        if self.changed.get() {
            return Ok(false);
        }
        let unchanged = pin_of(&self.entry.file)? == self.entry.pin;
        if !unchanged {
            self.changed.set(true);
        }
        Ok(unchanged)
    }

    /// The raw mapping key this object was first retained under.
    pub(crate) fn object_key(&self) -> ObjectKey {
        self.entry.raw.key
    }

    /// The retained pathname, for messages only.
    #[cfg(test)]
    pub(crate) fn path(&self) -> &str {
        &self.entry.path
    }

    pub(crate) fn content_key(&self) -> PinnedContentKey {
        PinnedContentKey {
            pin: self.entry.pin,
            sha256: self.entry.sha256.clone(),
        }
    }

    /// Whether `id` in a later, separately built pin store is this retained
    /// object: equal non-empty digest, equal pin, and either the same opened
    /// mapping or the same kernel file behind both fds. Numeric IDs and raw
    /// keys are never compared; an fstat pair runs only when the mappings
    /// differ (one file seen through two mounts).
    pub(crate) fn same_object_as(&self, pins: &PinnedObjects, id: PinnedObjectId) -> bool {
        pins.by_id.get(&id).is_some_and(|current| {
            !self.entry.sha256.is_empty()
                && self.entry.sha256 == current.sha256
                && self.entry.pin == current.pin
                && (self.entry.mapping == current.mapping
                    || same_kernel_file(&self.entry.file, &current.file))
        })
    }

    /// Whether `id`'s opened file is the kernel file this object retains
    /// (an fstat pair on the two fds), whatever its pin or digest says. An
    /// in-place rewrite keeps the kernel file; a raw maps key reused for
    /// another file (an anonymous overlay device recycled after a container
    /// exits) does not.
    pub(crate) fn same_kernel_file_as(&self, pins: &PinnedObjects, id: PinnedObjectId) -> bool {
        pins.by_id
            .get(&id)
            .is_some_and(|current| same_kernel_file(&self.entry.file, &current.file))
    }
}

/// The content half of one opened identity — the pin taken at open plus the
/// whole-file digest. Two openings of one physical file agree on it, so it
/// narrows a cross-store lookup; it never proves sameness on its own.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PinnedContentKey {
    pin: Pin,
    sha256: String,
}

/// Capture-private ownership key for causal timing. Numeric pin/module IDs and
/// path spellings are intentionally absent: this is the same complete opened
/// identity used by ordinary pin reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PinnedTimingKey {
    mapping: MappingFileKey,
    pin: Pin,
    sha256: String,
}

/// `ovl_statfs` reports the underlying filesystem's numbers but overrides
/// `f_type` with the overlay's own magic, so this answers "was this file
/// reached *through* an overlay mount", which is the question, and not "what
/// is it ultimately stored on". Unlike the probe's fail-closed check, entry
/// construction reports an `fstatfs` failure instead of guessing.
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
    Ok(unsafe {
        buf.assume_init().f_type as u64 == p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC
    })
}

/// Filesystems whose inode numbers do not name one file per device: FUSE
/// (the daemon chooses them) and network filesystems (server-assigned,
/// possibly folded). C1b never matches a maps `(device, inode)` key there.
const NONUNIQUE_INODE_FILESYSTEMS: [(u64, &str); 9] = [
    (0x6573_5546, "fuse"),
    (0x6969, "nfs"),
    (0x517b, "smb"),
    (0xff53_4d42, "cifs"),
    (0xfe53_4d42, "smb2"),
    (0x0102_1997, "9p"),
    (0x00c3_6400, "ceph"),
    (0x5346_414f, "afs"),
    (0x7375_7245, "coda"),
];

/// The named filesystem kind for an `f_type` with non-unique inodes, or
/// `None`. Pure so the table is unit-testable without such a mount.
pub(crate) fn nonunique_inode_kind(f_type: u64) -> Option<&'static str> {
    NONUNIQUE_INODE_FILESYSTEMS
        .iter()
        .find_map(|(magic, name)| (*magic == f_type).then_some(*name))
}

fn filesystem_without_unique_inodes(fd: RawFd) -> Result<Option<&'static str>, String> {
    let mut buf = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `fstatfs` fills `buf` for a valid fd and is only read on success.
    if unsafe { libc::fstatfs(fd, buf.as_mut_ptr()) } != 0 {
        return Err(format!(
            "fstatfs failed while classifying inode uniqueness: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the successful `fstatfs` above initialized `buf`. `f_type` is
    // signed on some ABIs; the magic numbers are 32-bit values.
    let f_type = unsafe { buf.assume_init().f_type } as u64 & 0xffff_ffff;
    Ok(nonunique_inode_kind(f_type))
}

/// The identity of the file the kernel installed in one mapping (the VMA's
/// `vm_file`), read by following `/proc/<pid>/map_files/<start>-<end>`:
/// `(st_dev, st_ino)` of exactly that file.
///
/// Which identity each side of a C1b comparison uses, and why — this is
/// the fourth time this project has had to get it right:
///
/// - A maps key `(device, inode)` is NOT one file. Maps renders
///   `i_sb->s_dev`: on btrfs one device for every subvolume, while inode
///   numbers repeat across subvolumes (observed here: two unrelated files
///   both rendered `00:23 45598`).
/// - `fstat` of an opened fd is NOT comparable with maps either (1786658:
///   btrfs `st_dev` is the subvolume's anonymous device, 0:37, never the
///   maps device). And since 4.19 (stacked file operations) overlayfs
///   `mmap` installs the BACKING file in the VMA (`ovl_mmap` ->
///   `backing_file_mmap` -> `vma_set_file(realfile)`); what changed around
///   6.8 is only what procfs renders for it. Before, maps and `map_files`
///   show the backing file itself (observed on 6.1 and 6.6, 5498046); from
///   then on they render the user-visible overlay file (`file_user_inode`
///   in `show_map_vma`, `file_user_path` in `map_files_get_link`; read in
///   the 6.17 source). An fd opened through the overlay path `fstat`s as
///   the overlay file, so comparing `map_files` against `fstat` would
///   refuse every pre-6.8 container.
/// - So both sides use the kernel's own `vm_file`: the candidate side
///   stats the target's `map_files` range; the pinned side mmaps the held
///   fd itself (one private read-only page, like `KernelSelfMappingProbe`)
///   and stats `/proc/self/map_files` for that mapping. The same kernel
///   path installs both VMAs and the same procfs code renders both
///   (overlay or not, before or after 6.8), so equal identities are the
///   same kernel file: on btrfs the subvolume's `(anon dev, ino)`, unique;
///   on pre-6.8 overlay both render the backing file; on 6.8+ overlay both
///   render the overlay file of the same backing file.
/// - Following a `map_files` link needs `CAP_SYS_ADMIN` or
///   `CAP_CHECKPOINT_RESTORE` in the initial user namespace (`EPERM`
///   otherwise), for `/proc/self` too. Without it nothing is proven and
///   C1b fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
}

/// A provider-candidate object a complete deep scan opened, identified,
/// and found to export no wanted symbol: examined, not a provider. Carries
/// the held fd's `vm_file` identity (see [`FileIdentity`]); an object
/// whose identity could not be read is not recorded as examined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ExaminedObject {
    pub key: ObjectKey,
    pub identity: FileIdentity,
    /// [`MappedFile::key_is_identity`] for `key`: any range under the key
    /// is this file, with no per-range `map_files` stat.
    pub key_is_identity: bool,
}

/// The actual scanner-opened file; its physical lease returns after the file
/// closes. Equal metadata never makes two instances of this type one file.
pub(crate) struct HeldExaminedObject {
    pub scan: u64,
    pub ordinal: u64,
    pub examined: ExaminedObject,
    pub file: std::fs::File,
    pub _lease: crate::discovery::sweep_attribution::FdLease,
}

/// Filesystems on which a maps key is one file: one superblock renders one
/// device in maps and `stat` alike, and no two simultaneously live inodes
/// of the superblock share an inode number. A positive allowlist; the
/// question for each entry is "can two live inodes in one superblock
/// share a number?":
///
/// - ext2/3/4: the number is the inode's slot in the on-disk inode table.
///   A slot is freed only when the last reference to the inode (a mapping
///   holds one) is dropped, so a mapped file's number is not reused.
/// - XFS: the number encodes the inode's on-disk location (AG, block,
///   offset), also with `inode32`; freed only as for ext4.
/// - squashfs: read-only; numbers are fixed in the image by mksquashfs.
/// - EROFS: read-only; the number is the on-disk nid (on 64-bit `ino_t`
///   it is not folded; this project is x86-64-first).
///
/// Absent, so always proving per range: tmpfs (without `inode64`, the
/// default, numbers come from a wrapping 32-bit counter — global
/// `get_next_ino` before 5.9, per superblock after — so after ~4G
/// allocations a new file can take a live file's number), btrfs (one maps
/// device for every subvolume), overlayfs as rendered from 6.8 on,
/// bcachefs, FUSE and network filesystems.
///
/// The device half: a matched key is checked against an object whose fd
/// this pass holds, and the held fd keeps its superblock alive, so its
/// device (a block device, or an anonymous one) cannot be released and
/// reused by another superblock meanwhile; at any instant one live
/// superblock owns a device. An examined object is not held after its
/// scan, so an unmount and device reuse (e.g. a loop device re-attached
/// to another image) could make its key name another file: that is the
/// accepted unpinned-examined-identity race, which can only change the
/// `complete` bit, never an edge.
pub(crate) const KEY_IS_IDENTITY_FILESYSTEMS: &[(u64, &str)] = &[
    (0xef53, "ext2/ext3/ext4"),
    (0x5846_5342, "xfs"),
    (0x7371_7368, "squashfs"),
    (0xe0f5_e1e2, "erofs"),
];

/// A held fd's self-mapped `vm_file`: its identity and the filesystem
/// magic of the same `map_files` entry (`statfs`, `None` if unreadable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappedFile {
    pub identity: FileIdentity,
    pub fs_magic: Option<u64>,
}

impl MappedFile {
    /// Whether the maps key `key` is this file's identity, so a range
    /// rendered under it in any process is this file: the identity equals
    /// `(makedev(key.device), key.inode)` AND the filesystem is on
    /// [`KEY_IS_IDENTITY_FILESYSTEMS`]. Either failing keeps the per-range
    /// `map_files` proof.
    pub(crate) fn key_is_identity(&self, key: ObjectKey) -> bool {
        let (Ok(major), Ok(minor)) = (
            u32::try_from(key.device.major),
            u32::try_from(key.device.minor),
        ) else {
            return false;
        };
        let device = libc::makedev(major, minor);
        self.identity
            == (FileIdentity {
                dev: device,
                ino: key.inode,
            })
            && self.fs_magic.is_some_and(|magic| {
                KEY_IS_IDENTITY_FILESYSTEMS
                    .iter()
                    .any(|(allowed, _)| *allowed == magic)
            })
    }
}

/// The `vm_file` identity of `[start, end)` in `pid` (see
/// [`FileIdentity`]). Metadata only: nothing is opened or read.
pub(crate) fn map_files_identity(pid: u32, start: u64, end: u64) -> std::io::Result<FileIdentity> {
    map_files_entry_identity(&format!("/proc/{pid}/map_files/{start:x}-{end:x}"))
}

/// One process's `/proc/<pid>/map_files` directory, held open so each
/// range is one `fstatat` relative to it instead of a full `/proc` path
/// walk (DR-C1b-3). The same entry, followed the same way, as
/// [`map_files_identity`]: like for like. The directory names the process
/// it was opened for; after an exit its lookups fail and never reach a
/// process that reuses the pid.
pub(crate) struct MapFilesDir {
    dir: std::fs::File,
}

impl MapFilesDir {
    pub(crate) fn open(pid: u32) -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(format!("/proc/{pid}/map_files"))
            .map(|dir| Self { dir })
    }

    /// The held directory's own metadata: which process's directory it is.
    #[cfg(test)]
    pub(crate) fn directory_metadata(&self) -> std::io::Result<std::fs::Metadata> {
        self.dir.metadata()
    }

    /// The `vm_file` identity of `[start, end)`: [`map_files_identity`]
    /// relative to the held directory (the entry is followed, as `stat`
    /// follows it).
    pub(crate) fn identity(&self, start: u64, end: u64) -> std::io::Result<FileIdentity> {
        let mut name = [0u8; MAP_FILES_NAME_LEN];
        write_map_files_name(start, end, &mut name);
        let mut buf = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: a valid directory fd, a writable stat buffer read only on
        // success, and `name`, which holds `{hex}-{hex}` plus its NUL
        // terminator with no interior NUL, so its pointer is a valid
        // NUL-terminated relative name for the call.
        if unsafe {
            libc::fstatat(
                self.dir.as_raw_fd(),
                name.as_ptr() as *const libc::c_char,
                buf.as_mut_ptr(),
                0,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: initialized by the successful `fstatat`.
        let stat = unsafe { buf.assume_init() };
        Ok(FileIdentity {
            dev: stat.st_dev,
            ino: stat.st_ino,
        })
    }
}

/// `{start:x}-{end:x}` plus the NUL terminator: 16 hex digits per bound.
const MAP_FILES_NAME_LEN: usize = 16 + 1 + 16 + 1;

/// Render `{start:x}-{end:x}` into `out` — exactly what `format!` would
/// produce, without the per-range allocation — and NUL-terminate it.
/// Returns the name length without the terminator.
fn write_map_files_name(start: u64, end: u64, out: &mut [u8; MAP_FILES_NAME_LEN]) -> usize {
    fn write_hex(value: u64, out: &mut [u8], mut index: usize) -> usize {
        let digits = if value == 0 {
            1
        } else {
            u32::div_ceil(u64::BITS - value.leading_zeros(), 4) as usize
        };
        for shift in (0..digits).rev() {
            let digit = ((value >> (4 * shift)) & 0xf) as u8;
            out[index] = if digit < 10 {
                b'0' + digit
            } else {
                b'a' + digit - 10
            };
            index += 1;
        }
        index
    }

    let mut len = write_hex(start, out, 0);
    out[len] = b'-';
    len = write_hex(end, out, len + 1);
    out[len] = 0;
    len
}

fn map_files_entry_identity(entry: &str) -> std::io::Result<FileIdentity> {
    let metadata = std::fs::metadata(entry)?;
    Ok(FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}

/// [`map_files_entry_identity`] plus the filesystem magic of the same
/// entry, read with `statfs` (which follows the link like `stat`).
fn map_files_entry_file(entry: &str) -> std::io::Result<MappedFile> {
    let identity = map_files_entry_identity(entry)?;
    let fs_magic = std::ffi::CString::new(entry).ok().and_then(|path| {
        let mut buf = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: `statfs` fills `buf` for a valid C path; read only on success.
        (unsafe { libc::statfs(path.as_ptr(), buf.as_mut_ptr()) } == 0).then(|| {
            // SAFETY: initialized by the successful `statfs`. `f_type` is
            // signed on some ABIs; the magic numbers are 32-bit values.
            (unsafe { buf.assume_init().f_type }) as u64 & 0xffff_ffff
        })
    });
    Ok(MappedFile { identity, fs_magic })
}

/// The `vm_file` identity of a held fd: mmap one page (`PROT_READ`,
/// `MAP_PRIVATE`, never `PROT_EXEC`, unmapped on every path) and stat this
/// process's own `map_files` entry for it. Like-for-like with
/// [`map_files_identity`] of a target that maps the same file.
pub(crate) fn self_mapped_identity(file: &std::fs::File) -> Result<FileIdentity, String> {
    self_mapped_file(file).map(|mapped| mapped.identity)
}

/// [`self_mapped_identity`] plus the filesystem magic of the same
/// `/proc/self/map_files` entry, read while the self-mapping exists.
pub(crate) fn self_mapped_file(file: &std::fs::File) -> Result<MappedFile, String> {
    if file.metadata().map_err(|e| e.to_string())?.len() == 0 {
        return Err("an empty file cannot be mapped".into());
    }
    // SAFETY: sysconf has no preconditions.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let len = usize::try_from(page).unwrap_or(4096).max(1);
    // SAFETY: one private read-only page of a borrowed valid fd at offset
    // 0; never PROT_EXEC; unmapped by the guard below.
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
        return Err(format!(
            "mapping the held object failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let _mapping = SelfMapping { base, len };
    let start = base as u64;
    let end = start + len as u64;
    match map_files_entry_file(&format!("/proc/self/map_files/{start:x}-{end:x}")) {
        Ok(mapped) => Ok(mapped),
        // The kernel merged the page into a neighbouring VMA: find the
        // VMA that contains it and stat that entry instead.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let maps = std::fs::read_to_string("/proc/self/maps").map_err(|e| e.to_string())?;
            let range = maps
                .lines()
                .filter_map(|line| line.split_ascii_whitespace().next())
                .find(|range| {
                    range.split_once('-').is_some_and(|(low, high)| {
                        u64::from_str_radix(low, 16).is_ok_and(|low| low <= start)
                            && u64::from_str_radix(high, 16).is_ok_and(|high| end <= high)
                    })
                })
                .ok_or("the held object's self-mapping was not found")?;
            map_files_entry_file(&format!("/proc/self/map_files/{range}"))
                .map_err(|e| format!("map_files of the held object: {e}"))
        }
        Err(error) => Err(format!("map_files of the held object: {error}")),
    }
}

/// The pin reopens the scanned object by path, and on btrfs a path swapped
/// between the scan and the pin to another subvolume's file with the same
/// inode number keeps the maps key. When both `vm_file` identities were
/// readable they must be equal; an unreadable pin side keeps the key check
/// as the proof, exactly as before.
fn check_same_scanned_file(
    scanned: FileIdentity,
    pinned: Result<FileIdentity, String>,
) -> Result<(), String> {
    match pinned {
        Ok(pinned) if pinned != scanned => Err(format!(
            "identity_mismatch: the pinned file (st_dev {} st_ino {}) is not the file the scan \
             read (st_dev {} st_ino {})",
            pinned.dev, pinned.ino, scanned.dev, scanned.ino
        )),
        _ => Ok(()),
    }
}

/// One private read-only page of a held fd, unmapped on drop.
struct SelfMapping {
    base: *mut libc::c_void,
    len: usize,
}

impl Drop for SelfMapping {
    fn drop(&mut self) {
        // SAFETY: exactly this range was mapped with mmap, is owned here
        // exclusively, and Drop runs once.
        unsafe {
            libc::munmap(self.base, self.len);
        }
    }
}

impl Entry {
    fn new(
        file: std::fs::File,
        pin: Pin,
        path: String,
        inspected: &InspectedObject,
        raw: RawObjectInstance,
        mapping: MappingFileKey,
    ) -> Result<Self, String> {
        Ok(Self {
            overlay: on_overlayfs(file.as_raw_fd())?,
            collapsed: false,
            raw,
            mapping,
            file: Arc::new(file),
            pin,
            path,
            // `inspect_file` always records a whole-file digest.
            sha256: inspected.identity.sha256.clone().unwrap_or_default(),
            build_id: match inspected.identity.kind {
                IdentityKind::GnuBuildId => inspected.identity.value.clone(),
                _ => None,
            },
            abi: inspected.abi,
            exports: inspected.exports.clone().into(),
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
    /// The module object's own standard-name `.dynsym` definitions, from its
    /// pinned inspection: the export-linkage witness for its tables.
    pub exports: Arc<[(String, u64)]>,
}

/// Every object opened, identity-matched, hashed, and pinned by a capture-local ID.
/// Raw mapping keys remain lookup inputs until reconciliation, never attach identity.
/// No read leases are held:
/// `check_unchanged` is a cheap, best-effort check, not a guarantee that the bytes
/// cannot change between the check and Aya's attach.
#[derive(Debug, Clone)]
pub struct PinnedObjects {
    by_id: BTreeMap<PinnedObjectId, Entry>,
    raw_to_id: BTreeMap<RawObjectInstance, PinnedObjectId>,
    rejected_keys: BTreeSet<ObjectKey>,
    ambiguous_keys: BTreeSet<ObjectKey>,
    ambiguity_published: BTreeSet<ObjectKey>,
    ownership: BTreeMap<ProcessViewId, ViewClaims>,
    raw_ownership: BTreeMap<ProcessViewId, BTreeSet<RawObjectInstance>>,
    next_id: u32,
    /// Sticky proof loss from either accepted scan-only overlay heuristic.
    overlay_uncertain: bool,
    /// Latched by `check_unchanged` the first time any pin differs.
    changed: std::cell::Cell<bool>,
    /// Membership revision (B2): bumped on every pin-set membership change
    /// (inserts, removals, absorbs, replaces, binds). The run loop's
    /// pin-sweep gate compares it across ticks; a missed bump only delays
    /// the live display (the frame backstop and the terminal sweep carry
    /// correctness), so bumps are conservative, never exact.
    revision: u64,
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
            raw_ownership: BTreeMap::new(),
            next_id: 0,
            overlay_uncertain: false,
            changed: std::cell::Cell::new(false),
            revision: 0,
        }
    }

    /// The current membership revision for the pin-sweep gate.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    fn bump_revision(&mut self) {
        self.revision = self.revision.saturating_add(1);
    }

    /// Folds another pin set into this capture. Exact comparable identities merge;
    /// an equal raw `ObjectKey` with any unequal full identity rejects the whole group.
    pub fn absorb(&mut self, other: PinnedObjects) -> Vec<Skipped> {
        self.bump_revision();
        let other_overlay_uncertain = other.overlay_uncertain;
        let other_raw_ownership = other.raw_ownership;
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
            let incoming_scan_only = instances.iter().all(|raw| raw.mount_namespace.is_some());
            let raw = instances.remove(0);
            entry.raw = raw.clone();
            let id = self.insert_entry_with_aliases(entry, incoming_scan_only, &mut skipped);
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
        for (view, raws) in other_raw_ownership {
            self.raw_ownership.entry(view).or_default().extend(
                raws.into_iter()
                    .filter(|raw| self.raw_to_id.contains_key(raw)),
            );
        }
        self.changed.set(self.changed.get() || other.changed.get());
        self.overlay_uncertain |= other_overlay_uncertain;
        self.publish_ambiguities(&mut skipped);
        skipped
    }

    pub(crate) fn has_overlay_uncertainty(&self) -> bool {
        self.overlay_uncertain
    }

    /// A loader-only absorption may add its pin and scan ownership, but every
    /// retained provider input must still name the same held File and facts.
    /// This compares stored state only; attachment keeps its ordinary metadata
    /// and generation revalidation, rather than replacing them with this proof.
    pub(crate) fn preserves_provider_inputs_for_loader(
        &self,
        candidate: &Self,
        loader: PinnedObjectId,
    ) -> bool {
        if self.changed.get()
            || candidate.changed.get()
            || self.overlay_uncertain
            || candidate.overlay_uncertain
            || self.rejected_keys != candidate.rejected_keys
            || self.ambiguous_keys != candidate.ambiguous_keys
            || self.ambiguity_published != candidate.ambiguity_published
            || !candidate.by_id.contains_key(&loader)
            || candidate
                .by_id
                .keys()
                .any(|id| !self.by_id.contains_key(id) && *id != loader)
        {
            return false;
        }
        for (id, old) in &self.by_id {
            let Some(new) = candidate.by_id.get(id) else {
                return false;
            };
            if !Arc::ptr_eq(&old.file, &new.file)
                || old.raw != new.raw
                || old.mapping != new.mapping
                || old.pin != new.pin
                || old.path != new.path
                || old.sha256 != new.sha256
                || old.build_id != new.build_id
                || old.abi != new.abi
                || old.exports != new.exports
                || old.overlay != new.overlay
                || old.collapsed != new.collapsed
            {
                return false;
            }
        }
        if self
            .raw_to_id
            .iter()
            .any(|(raw, id)| candidate.raw_to_id.get(raw) != Some(id))
            || candidate.raw_to_id.iter().any(|(raw, id)| {
                !self.raw_to_id.contains_key(raw)
                    && (*id != loader || raw.mount_namespace.is_none())
            })
            || (self.by_id.contains_key(&loader)
                && self.sources(loader) != candidate.sources(loader))
        {
            return false;
        }
        for (view, old) in &self.ownership {
            let Some(new) = candidate.ownership.get(view) else {
                return false;
            };
            if old.tables != new.tables
                || old.targets != new.targets
                || !new.pins.starts_with(&old.pins)
                || new.pins[old.pins.len()..].iter().any(|id| *id != loader)
            {
                return false;
            }
        }
        if candidate.ownership.iter().any(|(view, claims)| {
            !self.ownership.contains_key(view)
                && (!claims.tables.is_empty()
                    || !claims.targets.is_empty()
                    || claims.pins.iter().any(|id| *id != loader))
        }) {
            return false;
        }
        for (view, old) in &self.raw_ownership {
            if candidate
                .raw_ownership
                .get(view)
                .is_none_or(|new| !old.is_subset(new))
            {
                return false;
            }
        }
        candidate.raw_ownership.iter().all(|(view, raws)| {
            raws.iter().all(|raw| {
                self.raw_ownership
                    .get(view)
                    .is_some_and(|old| old.contains(raw))
                    || (raw.mount_namespace.is_some()
                        && candidate.raw_to_id.get(raw) == Some(&loader))
            })
        })
    }

    pub(crate) fn newly_rejected_keys(&self, committed: &Self) -> BTreeSet<ObjectKey> {
        self.rejected_keys
            .difference(&committed.rejected_keys)
            .copied()
            .collect()
    }

    pub(crate) fn reapply_rejected_keys(&mut self, keys: &BTreeSet<ObjectKey>) -> Vec<Skipped> {
        for key in keys {
            self.reject_observation(*key);
        }
        let mut skipped = Vec::new();
        self.publish_ambiguities(&mut skipped);
        skipped
    }

    /// Builds disposable capture-local identity state from pristine per-view pins.
    /// Cloning shares the already-opened files through `Arc`; it neither reopens nor
    /// duplicates an fd, and destructive collision handling cannot alter a source.
    pub fn aggregate_views<'a>(views: impl IntoIterator<Item = &'a Self>) -> (Self, Vec<Skipped>) {
        let mut aggregate = Self::empty();
        let mut skipped = Vec::new();
        for view in views {
            skipped.extend(aggregate.absorb(view.clone()));
        }
        (aggregate, skipped)
    }

    /// The path Aya reopens for this object: an fd this capture holds, never a name
    /// resolved again through a namespace that may not mean the same file.
    pub fn attach_path_for(&self, id: PinnedObjectId) -> Result<PathBuf, String> {
        self.by_id
            .get(&id)
            .map(|entry| PathBuf::from(format!("/proc/self/fd/{}", entry.file.as_raw_fd())))
            .ok_or_else(|| format!("object {id:?} was not pinned"))
    }

    /// Borrows the already-opened object behind a canonical capture-local ID.
    /// Live discovery uses this for ELF facts without reopening a pathname or
    /// recomputing the pin's identity digest.
    pub(crate) fn file_for(&self, id: PinnedObjectId) -> Option<&std::fs::File> {
        self.by_id.get(&id).map(|entry| entry.file.as_ref())
    }

    /// Every maps-visible key this capture-local object is retained under
    /// (scan aliases included), sorted and deduplicated. Task 3 Stage A
    /// selects the object's ranges in `/proc/PID/maps` by these.
    pub(crate) fn raw_keys_for(&self, id: PinnedObjectId) -> Vec<ObjectKey> {
        let mut keys: Vec<ObjectKey> = self
            .raw_to_id
            .iter()
            .filter(|(_, owner)| **owner == id)
            .map(|(raw, _)| raw.key)
            .collect();
        if let Some(entry) = self.by_id.get(&id) {
            keys.push(entry.raw.key);
        }
        keys.sort();
        keys.dedup();
        keys
    }

    pub(crate) fn abi_for(&self, id: PinnedObjectId) -> Option<ElfAbi> {
        self.by_id.get(&id).map(|entry| entry.abi)
    }

    /// The pinned object's standard-name `.dynsym` definitions; empty when
    /// the object is not pinned here.
    pub(crate) fn exports_for(&self, id: PinnedObjectId) -> Arc<[(String, u64)]> {
        self.by_id
            .get(&id)
            .map_or_else(|| Arc::from(Vec::new()), |entry| entry.exports.clone())
    }

    /// The content lookup key of a pinned object; `None` when it is not
    /// pinned here or carries no digest (never comparable).
    pub(crate) fn content_key(&self, id: PinnedObjectId) -> Option<PinnedContentKey> {
        let entry = self.by_id.get(&id)?;
        (!entry.sha256.is_empty()).then(|| PinnedContentKey {
            pin: entry.pin,
            sha256: entry.sha256.clone(),
        })
    }

    pub(crate) fn retain_inventory_target(
        &self,
        id: PinnedObjectId,
    ) -> Result<RetainedInventoryTarget, String> {
        if self.provider_changed() {
            return Err("provider changed before Inventory target retention".into());
        }
        let entry = self
            .by_id
            .get(&id)
            .ok_or_else(|| format!("Inventory object {id:?} was not pinned"))?
            .clone();
        let retained = RetainedInventoryTarget {
            entry,
            changed: std::cell::Cell::new(false),
        };
        if !retained.check_unchanged()? {
            return Err(format!("Inventory object {id:?} changed before retention"));
        }
        Ok(retained)
    }

    /// Replaces the raw ownership for one retained process generation while
    /// keeping exact canonical entries available for ID reuse. The incoming
    /// pin set was built through the same `ProcessView`; unequal full identity
    /// for an equal raw key therefore follows the ordinary collision path.
    pub(crate) fn replace_view_pins(
        &mut self,
        view: ProcessViewId,
        incoming: PinnedObjects,
        preserve: &[PinnedObjectId],
    ) -> Vec<Skipped> {
        self.bump_revision();
        self.ownership.remove(&view);
        let preserved: BTreeSet<_> = preserve.iter().copied().collect();
        let preserved_raws: BTreeSet<_> = self
            .raw_ownership
            .remove(&view)
            .unwrap_or_default()
            .into_iter()
            .filter(|raw| {
                self.raw_to_id
                    .get(raw)
                    .is_some_and(|id| preserved.contains(id))
            })
            .collect();
        let skipped = self.absorb(incoming);
        let preserved_raws: BTreeSet<_> = preserved_raws
            .into_iter()
            .filter(|raw| {
                self.raw_to_id
                    .get(raw)
                    .is_some_and(|id| preserved.contains(id))
            })
            .collect();
        if !preserved_raws.is_empty() {
            self.raw_ownership
                .entry(view)
                .or_default()
                .extend(preserved_raws);
            self.ownership
                .entry(view)
                .or_default()
                .pins
                .extend(preserved.iter().filter(|id| self.by_id.contains_key(id)));
        }

        let retained_raws: BTreeSet<_> = self
            .raw_ownership
            .values()
            .flatten()
            .cloned()
            .chain(
                self.raw_to_id
                    .keys()
                    .filter(|raw| raw.mount_namespace.is_none())
                    .cloned(),
            )
            .collect();
        self.raw_to_id.retain(|raw, _| retained_raws.contains(raw));
        let retained_ids: BTreeSet<_> = self.raw_to_id.values().copied().collect();
        let dropped: BTreeSet<_> = self
            .by_id
            .keys()
            .copied()
            .filter(|id| !retained_ids.contains(id))
            .collect();
        self.by_id.retain(|id, _| retained_ids.contains(id));
        // Dropping entries must not strand their claimants: scrub ownership
        // claims and owned raws for the dropped ids, mirroring remove_view.
        // A no-op whenever raw ownership is complete, as production scans
        // always attach it at pin time.
        if !dropped.is_empty() {
            for claims in self.ownership.values_mut() {
                claims.remove(&dropped);
            }
            for raws in self.raw_ownership.values_mut() {
                raws.retain(|raw| self.raw_to_id.contains_key(raw));
            }
        }
        skipped
    }

    /// Clears plan-derived table/target claims before the canonical raw module
    /// set is rebound. Opened pin ownership remains intact.
    pub(crate) fn reset_derived_claims(&mut self) {
        for claims in self.ownership.values_mut() {
            claims.tables.clear();
            claims.targets.clear();
        }
    }

    /// Restores the scan-owned pin layer before Inventory rebinds every retained
    /// module. Rebinding appends independent module/entry pin references; keeping
    /// the previous binding's pins would charge untouched owners repeatedly.
    /// Each retained raw alias keeps its own pin reference, even when several
    /// aliases resolve to the same physical object. Object IDs, aliases, and
    /// opened-file custody remain unchanged.
    pub(crate) fn reset_scan_pin_claims(&mut self) {
        for (view, claims) in &mut self.ownership {
            claims.pins = self
                .raw_ownership
                .get(view)
                .into_iter()
                .flatten()
                .filter_map(|raw| self.raw_to_id.get(raw).copied())
                .filter(|id| self.by_id.contains_key(id))
                .collect();
        }
    }

    pub(crate) fn rejects(&self, key: ObjectKey) -> bool {
        self.rejected_keys.contains(&key)
    }

    /// The raw maps keys that name exactly one opened object, for C1b sweep
    /// matching: a key qualifies only when it is not rejected, every scan
    /// alias filed under it resolves to one capture-local ID, that ID carries
    /// a digest, files no alias under any other key, and was never folded
    /// onto by the overlayfs heuristic. Overlay-collapsed and cross-key alias
    /// keys therefore never qualify: they stand for more than one proven
    /// kernel file. Manifest aliases are ignored (they never come from maps).
    pub(crate) fn sweep_match_keys(&self) -> BTreeMap<ObjectKey, PinnedObjectId> {
        let mut ids_by_key: BTreeMap<ObjectKey, BTreeSet<PinnedObjectId>> = BTreeMap::new();
        let mut keys_by_id: BTreeMap<PinnedObjectId, BTreeSet<ObjectKey>> = BTreeMap::new();
        for (raw, id) in &self.raw_to_id {
            if raw.mount_namespace.is_none() {
                continue;
            }
            ids_by_key.entry(raw.key).or_default().insert(*id);
            keys_by_id.entry(*id).or_default().insert(raw.key);
        }
        ids_by_key
            .into_iter()
            .filter_map(|(key, ids)| {
                let mut ids = ids.into_iter();
                let id = ids.next()?;
                if ids.next().is_some() || self.rejected_keys.contains(&key) {
                    return None;
                }
                let entry = self.by_id.get(&id)?;
                let single_key = keys_by_id
                    .get(&id)
                    .is_some_and(|keys| keys.len() == 1 && keys.contains(&key));
                (single_key && !entry.collapsed && !entry.sha256.is_empty() && entry.raw.key == key)
                    .then_some((key, id))
            })
            .collect()
    }

    /// Per-object `(ino, size, ctime)` recheck for C1b's confirmation step:
    /// `Ok(true)` while this one object still matches its pin. Unlike
    /// `check_unchanged` it neither latches nor answers for the whole set,
    /// so one changed object drops only its own sweep attributions.
    pub(crate) fn object_unchanged(&self, id: PinnedObjectId) -> Result<bool, String> {
        let entry = self
            .by_id
            .get(&id)
            .ok_or_else(|| format!("object {id:?} was not pinned"))?;
        pin_of(&entry.file)
            .map(|pin| pin == entry.pin)
            .map_err(|error| format!("{}: {error}", entry.path))
    }

    /// `Some(filesystem)` when the pinned object lives on a filesystem whose
    /// inode numbers are not unique per device (FUSE, network filesystems):
    /// there a maps `(device, inode)` cannot name one file, so C1b refuses
    /// sweep matching for it. `Err` only when `fstatfs` itself fails.
    pub(crate) fn nonunique_inode_filesystem(
        &self,
        id: PinnedObjectId,
    ) -> Result<Option<&'static str>, String> {
        let entry = self
            .by_id
            .get(&id)
            .ok_or_else(|| format!("object {id:?} was not pinned"))?;
        filesystem_without_unique_inodes(entry.file.as_raw_fd())
    }

    /// The held object's `vm_file` identity ([`self_mapped_identity`]):
    /// what another process's `map_files` range must equal before a maps
    /// key may stand for this object there (C1b sweep matching).
    pub(crate) fn object_mapped_identity(&self, id: PinnedObjectId) -> Result<MappedFile, String> {
        let entry = self
            .by_id
            .get(&id)
            .ok_or_else(|| format!("object {id:?} was not pinned"))?;
        self_mapped_file(&entry.file)
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

    /// Canonical, finite source ownership for one opened capture-local object.
    /// Raw aliases remain private; output only needs to distinguish scan and
    /// optional-manifest authority.
    pub fn sources(&self, id: PinnedObjectId) -> Vec<&'static str> {
        let mut scan = false;
        let mut manifest = false;
        for (raw, observed) in &self.raw_to_id {
            if *observed != id {
                continue;
            }
            if raw.mount_namespace.is_some() {
                scan = true;
            } else {
                manifest = true;
            }
        }
        [scan.then_some("scan"), manifest.then_some("manifest")]
            .into_iter()
            .flatten()
            .collect()
    }

    pub fn view_claims(&self, view: ProcessViewId) -> Option<&ViewClaims> {
        self.ownership.get(&view)
    }

    /// Retires one accepted process generation without disturbing another view or a
    /// manifest that still owns the same opened object. Returns the exact claims that
    /// were removed so the caller can rebuild its plan from the remaining modules.
    pub fn remove_view(&mut self, view: ProcessViewId) -> Option<ViewClaims> {
        let removed = self.ownership.remove(&view)?;
        self.bump_revision();
        let removed_raws = self.raw_ownership.remove(&view).unwrap_or_default();
        let retained_raws: BTreeSet<_> = self
            .raw_ownership
            .values()
            .flatten()
            .cloned()
            .chain(
                self.raw_to_id
                    .keys()
                    .filter(|raw| raw.mount_namespace.is_none())
                    .cloned(),
            )
            .collect();
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
        self.raw_to_id.retain(|raw, id| {
            !unowned.contains(id) && (!removed_raws.contains(raw) || retained_raws.contains(raw))
        });
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

    /// Re-files one manifest alias split by pre-6.8 overlayfs onto its scan pin.
    ///
    /// On mainline kernels before 6.8 the helper records the maps/backing key
    /// while this capture pins the opened fd under the overlay key, and
    /// retargeting rewrites the record to the scan pin's backing key — so the
    /// exact join misses: neither the scan alias (wrong namespace) nor the
    /// manifest alias (wrong key) matches the recorded identity. The alias is
    /// re-filed onto the scan pin if and only if the halves prove to be one
    /// physical file: the manifest pin's retained fd must render exactly the
    /// recorded key through the shared self-mapping probe (never inode-only),
    /// and exactly one scan pin must carry the recorded key with the same
    /// complete opened-file identity. Every downstream exact join — plan
    /// lowering, the engine merge, per-function targets — then resolves one
    /// provider, with the scan pin's maps key canonical for the report and
    /// its retained fd canonical for attach, exactly as on >= 6.8. Any
    /// ambiguity, any probe refusal, or an already-exact alias leaves the
    /// pins untouched, so a >= 6.8 capture never consults the probe here.
    pub(crate) fn refile_split_manifest_alias(
        &mut self,
        recorded: ObjectKey,
        path: &str,
        budget: &mut CaptureWorkBudget,
        probe: &impl SelfMappingProbe,
    ) {
        if self.id_for_manifest(recorded, path).is_some() {
            return;
        }
        let Some(normalized) = normalize_target_path(path) else {
            return;
        };
        // The one manifest pin filed for this path, under its fd key. More
        // than one is a genuine change during discovery, not a split.
        let mut manifest_aliases = self
            .raw_to_id
            .iter()
            .filter(|(raw, _)| raw.mount_namespace.is_none() && raw.path == normalized);
        let Some((manifest_raw, manifest_id)) = manifest_aliases.next() else {
            return;
        };
        if manifest_aliases.next().is_some() {
            return;
        }
        let manifest_raw = manifest_raw.clone();
        let manifest_id = *manifest_id;
        let Some(manifest_entry) = self.by_id.get(&manifest_id) else {
            return;
        };
        // The manifest pin must own its entry alone; otherwise retiring it
        // would strand another record's alias.
        if self
            .raw_to_id
            .values()
            .filter(|id| **id == manifest_id)
            .count()
            != 1
        {
            return;
        }
        // The split, proved exactly as the scan path proves it: this opened fd
        // may stand for the recorded maps identity only when the kernel
        // renders it exactly there.
        let fd_key = object_key(manifest_entry.mapping);
        if !opened_file_matches_maps(&manifest_entry.file, fd_key, recorded, budget, probe) {
            return;
        }
        // The scan pin retargeting chose for this record: the recorded key,
        // the same opened file. Same-key same-file pins merge at absorb, so
        // more than one match is ambiguity, never identity.
        let mut scans = BTreeSet::new();
        for (raw, id) in &self.raw_to_id {
            if raw.mount_namespace.is_none() || raw.key != recorded {
                continue;
            }
            if self.exactly_matches(*id, self, manifest_id) {
                scans.insert(*id);
            }
        }
        if scans.len() != 1 {
            return;
        }
        let scan_id = *scans.first().unwrap();
        if !self.by_id.contains_key(&scan_id) {
            return;
        }
        self.raw_to_id.remove(&manifest_raw);
        let referenced = self.raw_to_id.values().any(|id| *id == manifest_id)
            || self.ownership.values().any(|claims| {
                claims.tables.contains(&manifest_id)
                    || claims.pins.contains(&manifest_id)
                    || claims.targets.iter().any(|(id, _)| *id == manifest_id)
            });
        if !referenced {
            self.by_id.remove(&manifest_id);
            self.bump_revision();
        }
        self.raw_to_id.insert(
            RawObjectInstance {
                mount_namespace: None,
                key: recorded,
                path: normalized,
            },
            scan_id,
        );
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

    pub(crate) fn owned_timing_key(&self, id: PinnedObjectId) -> Option<PinnedTimingKey> {
        let entry = self.by_id.get(&id)?;
        (!entry.sha256.is_empty()).then(|| PinnedTimingKey {
            mapping: entry.mapping,
            pin: entry.pin,
            sha256: entry.sha256.clone(),
        })
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
        let incoming_scan_only = entry.raw.mount_namespace.is_some();
        self.insert_entry_with_aliases(entry, incoming_scan_only, skipped)
    }

    fn insert_entry_with_aliases(
        &mut self,
        entry: Entry,
        incoming_scan_only: bool,
        skipped: &mut Vec<Skipped>,
    ) -> Option<PinnedObjectId> {
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
            if entry.collapsed
                && let Some(kept) = self.by_id.get_mut(&id)
            {
                kept.collapsed = true;
            }
            self.raw_to_id.insert(entry.raw, id);
            return Some(id);
        }
        if incoming_scan_only
            && let Some(id) = same_key.iter().copied().find(|id| {
                self.aliases_are_scan_only(*id) && overlay_identity_equal(&self.by_id[id], &entry)
            })
        {
            skipped.push(overlay_uncertainty(&entry, &self.by_id[&id]));
            self.overlay_uncertain = true;
            if let Some(kept) = self.by_id.get_mut(&id) {
                kept.collapsed = true;
            }
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
        #[cfg(test)]
        crate::first_use_probe::known(&entry.file, &entry.sha256);
        self.raw_to_id.insert(entry.raw.clone(), id);
        self.by_id.insert(id, entry);
        self.bump_revision();
        Some(id)
    }

    fn aliases_are_scan_only(&self, id: PinnedObjectId) -> bool {
        let mut aliases = self
            .raw_to_id
            .iter()
            .filter_map(|(raw, observed)| (*observed == id).then_some(raw));
        aliases
            .next()
            .is_some_and(|raw| raw.mount_namespace.is_some())
            && aliases.all(|raw| raw.mount_namespace.is_some())
    }

    fn reject_key(&mut self, key: ObjectKey) {
        self.bump_revision();
        self.rejected_keys.insert(key);
        let ids: BTreeSet<PinnedObjectId> = self
            .by_id
            .iter()
            .filter_map(|(id, entry)| (entry.raw.key == key).then_some(*id))
            .collect();
        self.by_id.retain(|id, _| !ids.contains(id));
        self.raw_to_id
            .retain(|raw, id| raw.key != key && !ids.contains(id));
        for raws in self.raw_ownership.values_mut() {
            raws.retain(|raw| raw.key != key);
        }
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
    if left.mapping == right.mapping
        && left.pin == right.pin
        && !left.sha256.is_empty()
        && left.sha256 == right.sha256
    {
        return true;
    }
    same_open_file(left, right)
}

/// Same-open-file escape (cgroup-256 D): the same provider file observed
/// through two mount namespaces (a container bind-mounting the host's provider)
/// carries a different `mount_id` per mount table while remaining one attach
/// target. Merge only on proof — same key, equal pin, equal non-empty digest,
/// and equal fstat `(st_dev, st_ino)` on the two retained fds. `mount_id` is
/// not consulted here; anything unproven fails closed.
fn same_open_file(left: &Entry, right: &Entry) -> bool {
    left.raw.key == right.raw.key
        && left.pin == right.pin
        && !left.sha256.is_empty()
        && left.sha256 == right.sha256
        && same_kernel_file(&left.file, &right.file)
}

fn same_kernel_file(left: &std::fs::File, right: &std::fs::File) -> bool {
    match (left.metadata(), right.metadata()) {
        (Ok(left), Ok(right)) => left.dev() == right.dev() && left.ino() == right.ino(),
        _ => false,
    }
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

/// Resolves `file` in this view's mount table, re-reading the table once when
/// the fd's mount row is missing (mount-table churn races the first read).
/// The fd stays open across the retry, so its mount cannot be detached
/// underneath the re-resolution, and the re-read runs under the same retained
/// view checks as the first read. The retry is purely opportunistic: success
/// returns the key, while persistent absence — or a failed re-read — returns
/// today's error text unchanged. No other error retries.
#[cfg(test)]
fn identity_of_in_mountinfo_with_reread(
    file: &std::fs::File,
    mountinfo: &str,
    reread: impl FnOnce() -> Result<String, String>,
) -> Result<MappingFileKey, String> {
    reread_on_missing_mount(identity_of_in_mountinfo(file, mountinfo), file, reread)
}

/// The retry half of the rule above, given the first resolution's result.
fn reread_on_missing_mount(
    first: Result<MappingFileKey, String>,
    file: &std::fs::File,
    reread: impl FnOnce() -> Result<String, String>,
) -> Result<MappingFileKey, String> {
    match first {
        Err(error) if is_missing_mount_id_error(&error) => match reread() {
            Ok(fresh) => identity_of_in_mountinfo(file, &fresh),
            Err(_) => Err(error),
        },
        outcome => outcome,
    }
}

/// The `/proc/<pid>/maps`-comparable identity of one object reached through a
/// retained process view. Live loader arming finds the executable and its
/// PT_INTERP by matching this against `ObjectKey::of(mapping)`, so it has to be
/// the representation maps itself renders: `st_dev` is the btrfs subvolume's
/// anonymous device and never equals the mount device in maps, which leaves the
/// loader unbindable on such a rootfs.
pub fn open_view_object(
    view: &ProcessView,
    path: &Path,
    budget: &mut CaptureWorkBudget,
) -> Result<(std::fs::File, ObjectKey), String> {
    open_view_object_cached(view, path, &mut MountTableCache::default(), budget)
}

/// [`open_view_object`] over a mount table `mounts` reads once per view.
pub(crate) fn open_view_object_cached(
    view: &ProcessView,
    path: &Path,
    mounts: &mut MountTableCache,
    budget: &mut CaptureWorkBudget,
) -> Result<(std::fs::File, ObjectKey), String> {
    let (file, mountinfo) =
        view.open_then_cached_mountinfo(|| open_regular(path), mounts, budget)?;
    let first = identity_of_in_mountinfo(&file, mountinfo);
    let key = object_key(identity_in_cached_table(
        view, &file, first, mounts, budget,
    )?);
    Ok((file, key))
}

pub fn view_object_key(
    view: &ProcessView,
    path: &Path,
    budget: &mut CaptureWorkBudget,
) -> Result<ObjectKey, String> {
    Ok(open_view_object(view, path, budget)?.1)
}

pub(crate) fn view_object_key_cached(
    view: &ProcessView,
    path: &Path,
    mounts: &mut MountTableCache,
    budget: &mut CaptureWorkBudget,
) -> Result<ObjectKey, String> {
    Ok(open_view_object_cached(view, path, mounts, budget)?.1)
}

/// The cached-table form of the rule above: a missing mount row still forces
/// exactly one fresh read of the table, under the same retained view checks.
fn identity_in_cached_table(
    view: &ProcessView,
    file: &std::fs::File,
    first: Result<MappingFileKey, String>,
    mounts: &mut MountTableCache,
    budget: &mut CaptureWorkBudget,
) -> Result<MappingFileKey, String> {
    reread_on_missing_mount(first, file, || {
        mounts.invalidate();
        Ok(view
            .open_then_cached_mountinfo(|| Ok(()), mounts, budget)?
            .1
            .to_owned())
    })
}

/// The same identity for a descriptor already retained across a pre-exec
/// barrier, which must not be reopened by path.
pub fn retained_object_key(
    view: &ProcessView,
    file: &std::fs::File,
    budget: &mut CaptureWorkBudget,
) -> Result<ObjectKey, String> {
    retained_object_key_cached(view, file, &mut MountTableCache::default(), budget)
}

/// Maps identity for the retained interpreter before the owned child maps it.
/// On pre-6.8 overlayfs the mountinfo/fd key can differ from the key the
/// kernel later reports for the loader hook. Ask the existing bounded,
/// read-only self-mapping probe about this exact retained descriptor once;
/// an inconclusive overlay probe cannot authorize the future mapping.
pub(crate) fn preexec_object_key(
    view: &ProcessView,
    file: &std::fs::File,
    budget: &mut CaptureWorkBudget,
) -> Result<ObjectKey, String> {
    preexec_object_key_with(view, file, budget, &KernelSelfMappingProbe)
}

fn preexec_object_key_with(
    view: &ProcessView,
    file: &std::fs::File,
    budget: &mut CaptureWorkBudget,
    probe: &impl SelfMappingProbe,
) -> Result<ObjectKey, String> {
    let fd_key = retained_object_key(view, file, budget)?;
    if !probe.fd_is_on_overlayfs(file) {
        return Ok(fd_key);
    }
    probe
        .kernel_maps_key(file, &mut BudgetAdapter(budget))
        .ok_or_else(|| "the retained pre-exec interpreter maps identity was unavailable".into())
}

/// [`retained_object_key`] over a mount table `mounts` reads once per view.
pub(crate) fn retained_object_key_cached(
    view: &ProcessView,
    file: &std::fs::File,
    mounts: &mut MountTableCache,
    budget: &mut CaptureWorkBudget,
) -> Result<ObjectKey, String> {
    let ((), mountinfo) = view.open_then_cached_mountinfo(|| Ok(()), mounts, budget)?;
    let first = identity_of_in_mountinfo(file, mountinfo);
    Ok(object_key(identity_in_cached_table(
        view, file, first, mounts, budget,
    )?))
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

/// The pre-6.8 overlayfs maps-identity split, and its exact fallback.
///
/// The one shared implementation lives in `p11scope_manifest::identity`
/// (trait and seam, real mmap probe, bounded `/proc/self/maps` reader with
/// its parser); the observer and `p11scope-discover` both use it. This
/// module keeps only a thin budget-charging adapter so the observer's
/// `CaptureWorkBudget` accounting stays exactly as it was: the adapter
/// delegates 1:1 — deadline poll, per-chunk and per-line work units, bytes
/// recorded — in the same order the inlined probe used, and every refusal
/// keeps its byte-identical message.
pub(crate) use p11scope_manifest::identity::{KernelSelfMappingProbe, SelfMappingProbe};

/// Adapts the capture budget to the shared probe's accounting surface.
/// Each method is the same call the inlined probe made, so charging is
/// identical; the helper passes an unbounded budget instead.
struct BudgetAdapter<'a>(&'a mut CaptureWorkBudget);

impl p11scope_manifest::identity::ProbeBudget for BudgetAdapter<'_> {
    fn probe_expired(&mut self) -> bool {
        self.0.check_deadline_now().is_some()
    }

    fn probe_allowed_io(&mut self, operation_bytes: u64, wanted: usize) -> usize {
        self.0.allowed_io(operation_bytes, wanted)
    }

    fn probe_spend(&mut self) -> bool {
        self.0.spend(1).is_ok()
    }

    fn probe_record_io(&mut self, bytes: usize) {
        self.0.record_io(bytes)
    }
}

/// Whether one opened fd may stand for a maps identity: equal keys accept
/// without consulting the probe; a split identity accepts only when the
/// kernel renders this exact fd at the maps key.
pub(crate) fn opened_file_matches_maps(
    file: &std::fs::File,
    fd_key: ObjectKey,
    maps_key: ObjectKey,
    budget: &mut CaptureWorkBudget,
    probe: &impl SelfMappingProbe,
) -> bool {
    p11scope_manifest::identity::opened_file_matches_maps(
        file,
        fd_key,
        maps_key,
        &mut BudgetAdapter(budget),
        probe,
    )
}

/// The maps key to retry a snapshot with when an overlay fd's own key found
/// no mapping: `None` unless the kernel renders this exact fd at a
/// *different* key, so a pointless same-key retry never runs.
pub(crate) fn self_mapped_fallback_key(
    file: &std::fs::File,
    fd_key: ObjectKey,
    budget: &mut CaptureWorkBudget,
    probe: &impl SelfMappingProbe,
) -> Option<ObjectKey> {
    p11scope_manifest::identity::self_mapped_fallback_key(
        file,
        fd_key,
        &mut BudgetAdapter(budget),
        probe,
    )
}

/// Structural validation + open + size cap + identity match + executable-offset check.
/// Opens, identifies, and pins every object. Errors are aggregated so an
/// operator sees every stale or malformed target in one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestStaleReason {
    OpenStale,
    IdentityMismatch,
}

impl ManifestStaleReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::OpenStale => "open_stale",
            Self::IdentityMismatch => "identity_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleManifestObject {
    pub object: u32,
    pub path: String,
    pub reason: ManifestStaleReason,
    diagnostic: String,
}

impl StaleManifestObject {
    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
}

#[derive(Debug, Clone)]
pub struct ManifestPinning {
    pub pins: PinnedObjects,
    pub stale: Vec<StaleManifestObject>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestPinError {
    Invalid(Vec<String>),
    Fatal(Vec<String>),
}

impl ManifestPinError {
    pub fn problems(&self) -> &[String] {
        match self {
            Self::Invalid(problems) | Self::Fatal(problems) => problems,
        }
    }
}

fn classify_locator_error(kind: std::io::ErrorKind) -> Option<ManifestStaleReason> {
    (kind == std::io::ErrorKind::NotFound).then_some(ManifestStaleReason::OpenStale)
}

fn has_proc_root_component(path: &Path) -> bool {
    let mut stack = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                stack.pop();
            }
            Component::Normal(component) => {
                let process_root = stack.len() == 2 && stack[0] == "proc" && component == "root";
                let task_root = stack.len() == 4
                    && stack[0] == "proc"
                    && stack[2] == "task"
                    && component == "root";
                if process_root || task_root {
                    return true;
                }
                stack.push(component);
            }
            Component::Prefix(_) => return false,
        }
    }
    false
}

fn retained_view_for_manifest_locator<'a>(
    path: &str,
    views: &'a [ProcessView],
) -> Result<Option<&'a ProcessView>, String> {
    let canonical = || {
        format!(
            "{path}: proc-root manifest locators must use canonical /proc/<pid>/root/<path> spelling"
        )
    };
    let raw_proc_root = has_proc_root_component(Path::new(path));
    let Some(normalized) = normalize_target_path(path) else {
        return Ok(None);
    };
    if raw_proc_root && path != normalized {
        return Err(canonical());
    }
    let Some(proc_path) = normalized.strip_prefix("/proc/") else {
        return if raw_proc_root {
            Err(canonical())
        } else {
            Ok(None)
        };
    };
    let components: Vec<_> = proc_path.split('/').collect();
    let Some(root) = components.iter().position(|component| *component == "root") else {
        return if raw_proc_root {
            Err(canonical())
        } else {
            Ok(None)
        };
    };
    if path != normalized || root != 1 || components.len() < 3 {
        return Err(canonical());
    }
    let pid = components[0].parse::<u32>().map_err(|_| canonical())?;
    if pid == 0 || components[0] != pid.to_string() {
        return Err(canonical());
    }
    if components[2..].iter().any(|component| component.is_empty())
        || components.get(2) == Some(&"proc")
    {
        return Err(canonical());
    }
    let mut matching = views.iter().filter(|view| view.pid() == pid);
    let Some(view) = matching.next() else {
        return Err(format!(
            "{path}: no exact retained process view exists for pid {pid}"
        ));
    };
    if matching.next().is_some() {
        return Err(format!(
            "{path}: more than one retained process view exists for pid {pid}"
        ));
    }
    Ok(Some(view))
}

enum ManifestLocatorOpen {
    Opened(std::fs::File),
    Stale,
    Fatal(String),
}

fn open_manifest_locator(path: &Path) -> ManifestLocatorOpen {
    match path.try_exists() {
        Ok(true) => {}
        Ok(false) => return ManifestLocatorOpen::Stale,
        Err(error) => {
            if classify_locator_error(error.kind()).is_some() {
                return ManifestLocatorOpen::Stale;
            }
            return ManifestLocatorOpen::Fatal(format!(
                "{}: cannot inspect the file locator now ({error})",
                path.display()
            ));
        }
    }
    match open_object(path) {
        Ok(file) => ManifestLocatorOpen::Opened(file),
        Err(error) => ManifestLocatorOpen::Fatal(format!(
            "{}: cannot open the file now ({error})",
            path.display()
        )),
    }
}

fn identity_of_manifest(
    file: &std::fs::File,
    retained_mountinfo: Option<&str>,
) -> Result<MappingFileKey, String> {
    match retained_mountinfo {
        Some(mountinfo) => identity_of_in_mountinfo(file, mountinfo),
        None => identity_of(file),
    }
}

/// Classifies only a locator that no longer resolves as deferred staleness. Every
/// opened object's remaining checks are fatal except an exact recorded-identity
/// mismatch; the caller may ignore either stale class only after a scan-opened
/// replacement is proven.
pub fn pin_manifest_objects_deferred(m: &Manifest) -> Result<ManifestPinning, ManifestPinError> {
    let mut budget = CaptureWorkBudget::default();
    pin_manifest_objects_deferred_in_views_with_budget(m, &[], &mut budget)
}

/// Pins manifest objects, binding canonical `/proc/<pid>/root/...` locators to the
/// exact process generation already retained from capture scope. Ordinary host
/// paths continue to resolve in the observer's filesystem view.
pub fn pin_manifest_objects_deferred_in_views(
    m: &Manifest,
    views: &[ProcessView],
) -> Result<ManifestPinning, ManifestPinError> {
    let mut budget = CaptureWorkBudget::default();
    pin_manifest_objects_deferred_in_views_with_budget(m, views, &mut budget)
}

pub fn pin_manifest_objects_deferred_in_views_with_budget(
    m: &Manifest,
    views: &[ProcessView],
    budget: &mut CaptureWorkBudget,
) -> Result<ManifestPinning, ManifestPinError> {
    let structural = validate_structure(m);
    if !structural.is_empty() {
        return Err(ManifestPinError::Invalid(structural));
    }

    let mut problems = Vec::new();
    let mut stale = Vec::new();
    let mut pinned = Vec::new();
    let mut total_object_bytes = 0u64;
    for object in &m.objects {
        let path = Path::new(&object.path);
        let retained = match retained_view_for_manifest_locator(&object.path, views) {
            Ok(retained) => retained,
            Err(binding_error) => {
                // Preserve the actionable permission diagnostic for an inaccessible
                // locator, but never open or accept an unbound proc-root object.
                match path.try_exists() {
                    Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                        problems.push(format!(
                            "{}: cannot inspect the file locator now ({error})",
                            object.path
                        ));
                    }
                    _ => problems.push(binding_error),
                }
                continue;
            }
        };
        let (opened, mountinfo) = match retained {
            Some(view) => {
                match view
                    .open_then_mountinfo(|| Ok::<_, String>(open_manifest_locator(path)), budget)
                {
                    Ok((opened, mountinfo)) => (opened, Some(mountinfo)),
                    Err(error) => {
                        problems.push(format!("{}: {error}", object.path));
                        continue;
                    }
                }
            }
            None => (open_manifest_locator(path), None),
        };
        let file = match opened {
            ManifestLocatorOpen::Opened(file) => file,
            ManifestLocatorOpen::Stale => {
                stale.push(StaleManifestObject {
                    object: object.id,
                    path: object.path.clone(),
                    reason: ManifestStaleReason::OpenStale,
                    diagnostic: format!(
                        "{}: the manifest object locator no longer resolves",
                        object.path
                    ),
                });
                continue;
            }
            ManifestLocatorOpen::Fatal(error) => {
                problems.push(error);
                continue;
            }
        };
        let mountinfo = match mountinfo {
            Some(mountinfo) => Some(mountinfo),
            None => {
                let table = match std::fs::File::open("/proc/self/mountinfo")
                    .map_err(|error| format!("cannot open observer mount table: {error}"))
                    .and_then(|table| read_mountinfo(table, budget))
                {
                    Ok(table) => table,
                    Err(error) => {
                        problems.push(format!("{}: {error}", object.path));
                        continue;
                    }
                };
                Some(table)
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
        pinned.push((object, file, pin, mountinfo));
    }
    if !problems.is_empty() {
        return Err(ManifestPinError::Fatal(problems));
    }

    let mut opened = BTreeMap::new();
    for (object, file, pin, mountinfo) in pinned {
        let inspected = match inspect_file_with_reader_exporting(
            &file,
            |file, bytes, offset| file.read_at(bytes, offset),
            &standard_function_names(),
        ) {
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
        let mut offsets_valid = true;
        let surface_functions = m.surfaces.iter().flat_map(|surface| &surface.functions);
        let selection_functions = m
            .selection_evidence
            .tables
            .iter()
            .flat_map(|table| &table.functions);
        for function in surface_functions.chain(selection_functions) {
            let Resolution::Resolved {
                object: target,
                file_offset,
            } = function.resolution
            else {
                continue;
            };
            if target == object.id && !inspected.contains_executable_offset(file_offset) {
                problems.push(format!(
                    "{}: {}+{file_offset:#x} is outside every executable ELF segment",
                    function.name, object.path
                ));
                offsets_valid = false;
            }
        }
        if !offsets_valid {
            continue;
        }
        let mapping = match identity_of_manifest(&file, mountinfo.as_deref()) {
            Ok(mapping) => mapping,
            Err(error) => {
                problems.push(format!("{}: {error}", object.path));
                continue;
            }
        };
        let key = object_key(mapping);
        let Some(raw) = RawObjectInstance::manifest(key, object.path.clone()) else {
            problems.push(format!("{}: object path cannot be normalized", object.path));
            continue;
        };
        let entry = match Entry::new(file, pin, object.path.clone(), &inspected, raw, mapping) {
            Ok(entry) => entry,
            Err(error) => {
                problems.push(format!("{}: {error}", object.path));
                continue;
            }
        };
        if inspected.identity.kind != object.identity.kind
            || inspected.identity.value != object.identity.value
            || inspected.identity.sha256 != object.identity.sha256
        {
            stale.push(StaleManifestObject {
                object: object.id,
                path: object.path.clone(),
                reason: ManifestStaleReason::IdentityMismatch,
                diagnostic: format!(
                    "{}: identity changed since discovery (manifest {:?} {} sha256 {}, current {:?} {} sha256 {}) — re-run `p11scope-discover`",
                    object.path,
                    object.identity.kind,
                    object.identity.value.as_deref().unwrap_or("-"),
                    object.identity.sha256.as_deref().unwrap_or("-"),
                    inspected.identity.kind,
                    inspected.identity.value.as_deref().unwrap_or("-"),
                    inspected.identity.sha256.as_deref().unwrap_or("-"),
                ),
            });
            drop(entry);
            continue;
        }
        opened.insert(object.id, (entry, inspected));
    }

    if !problems.is_empty() {
        return Err(ManifestPinError::Fatal(problems));
    }
    let mut result = PinnedObjects::empty();
    for (entry, _) in opened.into_values() {
        let path = entry.path.clone();
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
        return Err(ManifestPinError::Fatal(problems));
    }
    Ok(ManifestPinning {
        pins: result,
        stale,
    })
}

/// Strict compatibility API for callers that have no scan fallback context.
pub fn pin_manifest_objects(m: &Manifest) -> Result<PinnedObjects, Vec<String>> {
    match pin_manifest_objects_deferred(m) {
        Ok(result) if result.stale.is_empty() => Ok(result.pins),
        Ok(result) => Err(result
            .stale
            .into_iter()
            .map(|stale| stale.diagnostic)
            .collect()),
        Err(error) => Err(error.problems().to_vec()),
    }
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
    pin_scanned_view_objects_with(view, modules, budget, &self_mapped_identity)
}

/// Reads a pinned fd's `vm_file` identity ([`self_mapped_identity`]).
type ReadPinnedIdentity<'a> = &'a dyn Fn(&std::fs::File) -> Result<FileIdentity, String>;

/// [`pin_scanned_view_objects`] with the pinned fd's `vm_file` identity
/// read through `pinned_identity` (a seam: following `map_files` needs
/// privilege, so tests script it).
fn pin_scanned_view_objects_with(
    view: &ProcessView,
    modules: &[ScannedModule],
    budget: &mut CaptureWorkBudget,
    pinned_identity: ReadPinnedIdentity<'_>,
) -> Result<(PinnedObjects, Vec<Skipped>), String> {
    // Both the table-owning modules and every object a table entry points into: an
    // entry may land in a dependency the module itself only forwards to.
    let mut wanted = BTreeSet::new();
    // The `vm_file` identity each module's own scan read, where readable:
    // the pin must reopen exactly that file.
    let mut scanned_files: BTreeMap<RawObjectInstance, FileIdentity> = BTreeMap::new();
    let mut skipped = Vec::new();
    for module in modules {
        if module.view != view.id() || module.mount_namespace != view.mount_namespace() {
            return Err("scan result belongs to a different process view".into());
        }
        match RawObjectInstance::scanned(module, module.key, &module.path) {
            Some(raw) => {
                if let Some(identity) = module.mapped_identity {
                    scanned_files.insert(raw.clone(), identity);
                }
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
    // One mount-table read serves every object pinned here (H-3).
    let mut mounts = MountTableCache::default();
    for raw in wanted {
        // Opening through /proc/<pid>/root is a per-pid action (spec §4.5).
        if !view.still_the_same() {
            return Err(exited());
        }
        let scanned = scanned_files.get(&raw).copied();
        let candidate = pin_scanned_object(
            view,
            raw.clone(),
            scanned.map(|scanned| (scanned, pinned_identity)),
            &mut mounts,
            budget,
        );
        record_scanned_candidate(&mut pinned, view.id(), raw, candidate, &mut skipped);
    }
    if !view.still_the_same() {
        return Err(exited());
    }
    Ok((pinned, skipped))
}

fn record_scanned_candidate(
    pinned: &mut PinnedObjects,
    view: ProcessViewId,
    raw: RawObjectInstance,
    candidate: Result<Entry, String>,
    skipped: &mut Vec<Skipped>,
) {
    match candidate {
        Ok(entry) => {
            if let Some(id) = pinned.insert_entry(entry, skipped) {
                pinned.ownership.entry(view).or_default().pins.push(id);
                pinned.raw_ownership.entry(view).or_default().insert(raw);
            }
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

/// Collapses only scan-owned overlay aliases that have matching pinned metadata and
/// digests. Manifest aliases remain exact inputs: the overlay heuristic never gives
/// them a scan peer's capture-local identity.
pub fn canonicalize_scanned_overlays(pinned: &mut PinnedObjects) -> (usize, Vec<Skipped>) {
    let mut first: BTreeMap<(Pin, &str), PinnedObjectId> = BTreeMap::new();
    let mut canonical: BTreeMap<PinnedObjectId, PinnedObjectId> = BTreeMap::new();
    let mut lost = Vec::new();
    for (id, entry) in &pinned.by_id {
        if entry.sha256.is_empty() || !entry.overlay || !pinned.aliases_are_scan_only(*id) {
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
    for (id, kept) in &canonical {
        pinned.by_id.remove(id);
        if let Some(kept) = pinned.by_id.get_mut(kept) {
            kept.collapsed = true;
        }
    }
    if !canonical.is_empty() {
        pinned.bump_revision();
    }
    pinned.overlay_uncertain |= !canonical.is_empty();
    (canonical.len(), lost)
}

/// Resolves every process-view-local mapping reference to its final capture-local
/// opened identity. It does not apply overlay heuristics, so callers can bind after
/// manifest absorption without moving manifest authority between scan peers.
pub fn bind_scanned_modules(
    modules: &[ScannedModule],
    pinned: &mut PinnedObjects,
) -> (Vec<ReconciledModule>, Vec<Skipped>) {
    let mut reconciled = Vec::new();
    let mut lost = Vec::new();
    for module in modules {
        let Some(object) = pinned.id_for_scanned(module, module.key, &module.path) else {
            lost.push(Skipped {
                subject: module.path.clone(),
                reason: "module has no comparable pinned identity; it was not attached".into(),
            });
            continue;
        };
        if module.decoder_abi.is_some_and(|decoded| {
            pinned
                .abi_for(object)
                .is_none_or(|inspected| inspected != decoded)
        }) {
            lost.push(Skipped {
                subject: module.path.clone(),
                reason: "module decoder ABI disagrees with its retained pinned identity; its tables were not attached"
                    .into(),
            });
            continue;
        }
        let mut scanned = module.clone();
        let mut entry_objects = Vec::with_capacity(scanned.tables.len());
        for table in &mut scanned.tables {
            let mut ids = Vec::with_capacity(table.entries.len());
            let mut kept = Vec::with_capacity(table.entries.len());
            for entry in std::mem::take(&mut table.entries) {
                match pinned.id_for_scanned(module, entry.object, &entry.object_path) {
                    Some(id)
                        if matches!(
                            (pinned.abi_for(id), pinned.abi_for(object)),
                            (Some(target), Some(provider)) if target == provider
                        ) =>
                    {
                        ids.push(id);
                        kept.push(entry);
                    }
                    candidate => {
                        let skip = Skipped {
                            subject: entry.name.to_string(),
                            reason: if candidate.is_some() {
                                format!(
                                    "{} has a different target ABI from its provider; entry was not attached",
                                    entry.object_path
                                )
                            } else {
                                format!(
                                    "{} could not be reconciled to a comparable pinned object; entry was not attached",
                                    entry.object_path
                                )
                            },
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
            exports: pinned.exports_for(object),
        });
    }
    (reconciled, lost)
}

/// Resolves every process-view-local mapping reference to a capture-local opened
/// object. Ordinary identities merge only when their complete mapping identity,
/// pin metadata, and digest agree. The bounded overlayfs heuristic is scan-only and
/// preserves all process views while publishing uncertainty.
pub fn reconcile_scanned_modules(
    modules: &[ScannedModule],
    pinned: &mut PinnedObjects,
) -> (Vec<ReconciledModule>, usize, Vec<Skipped>) {
    let (collapsed, mut lost) = canonicalize_scanned_overlays(pinned);
    let (reconciled, binding_lost) = bind_scanned_modules(modules, pinned);
    lost.extend(binding_lost);
    (reconciled, collapsed, lost)
}

fn pin_scanned_object(
    view: &ProcessView,
    raw: RawObjectInstance,
    scanned: Option<(FileIdentity, ReadPinnedIdentity<'_>)>,
    mounts: &mut MountTableCache,
    budget: &mut CaptureWorkBudget,
) -> Result<Entry, String> {
    // The target's own filesystem view: a container's object is never copied out.
    let (file, mountinfo) = view.open_then_cached_mountinfo(
        || open_object(Path::new(&format!("/proc/{}/root{}", view.pid(), raw.path))),
        mounts,
        budget,
    )?;
    let first = identity_of_in_mountinfo(&file, mountinfo);
    let found = identity_in_cached_table(view, &file, first, mounts, budget)?;
    // On pre-6.8 kernels an overlayfs fd and its mappings legitimately carry
    // different keys (overlay vs backing device); the self-mapping probe
    // asks the kernel how it renders this exact fd before refusing.
    if !opened_file_matches_maps(
        &file,
        object_key(found),
        raw.key,
        budget,
        &KernelSelfMappingProbe,
    ) {
        return Err(format!(
            "identity_mismatch: the mapping is {:?} but {} now opens as {:?} \
             (compared via mountinfo)",
            raw.key,
            raw.path,
            object_key(found),
        ));
    }
    if let Some((scanned, pinned_identity)) = scanned {
        check_same_scanned_file(scanned, pinned_identity(&file))?;
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
    #[cfg(test)]
    tests::run_before_hash_test_hook();
    // A repeat pin of the unchanged file reuses the cached inspection with zero
    // reads. The key's (device, inode) is the mountinfo-validated identity above.
    let validated = object_key(found);
    let cache_key = InspectedFileKey {
        device: validated.device,
        inode: validated.inode,
        pin: before,
    };
    if let Some(inspected) = budget.inspected_file(&cache_key) {
        // Nothing was read for this hit, but the file may have changed since
        // `before`; only the still-unchanged file may reuse the cached value.
        if pin_of(&file)? == before {
            return Entry::new(file, before, raw.path.clone(), &inspected, raw, found);
        }
    }
    let mut operation_bytes = 0u64;
    let inspected = inspect_file_with_reader_exporting(
        &file,
        |file, bytes, offset| {
            if let Some(reason) = budget.check_deadline_now() {
                return Err(std::io::Error::other(reason));
            }
            let allowed = budget.allowed_io(operation_bytes, bytes.len());
            if allowed == 0 {
                return Err(std::io::Error::other(IO_CEILING_REASON));
            }
            let read = file.read_at(&mut bytes[..allowed], offset)?;
            budget.record_io(read);
            operation_bytes = operation_bytes.saturating_add(read as u64);
            Ok(read)
        },
        &standard_function_names(),
    )?;
    // The pin was taken before the bytes were hashed; a write that lands during the
    // hash must not become the baseline the capture trusts.
    if pin_of(&file)? != before {
        return Err("file changed while it was being identified — retry".into());
    }
    // Only the stable read lands here: a file that changed mid-read is never cached.
    budget.note_inspected_file(cache_key, inspected.clone());
    Entry::new(file, before, raw.path.clone(), &inspected, raw, found)
}

#[cfg(test)]
pub(crate) mod test_fixture {
    use super::*;
    use crate::discovery::scan::{ScannedEntry, ScannedTable};

    pub(crate) const SHA: &str = "b4e608e4";
    /// The inode and the two overlay device numbers a two-container docker run
    /// really produced (`102:56317450` and `104:56317450`).
    pub(crate) const INODE: u64 = 56_317_450;
    pub(crate) const PATH: &str = "/usr/lib/softhsm/libsofthsm2.so";

    pub(crate) fn overlay(minor: u64) -> ObjectKey {
        ObjectKey {
            device: Device { major: 0, minor },
            inode: INODE,
        }
    }

    pub(crate) fn module(key: ObjectKey) -> ScannedModule {
        ScannedModule {
            mapped_identity: None,
            double_loaded: false,
            view: ProcessViewId(key.device.minor as u32),
            mount_namespace: MountNamespaceId {
                device: 1,
                inode: key.device.minor,
            },
            key,
            path: PATH.into(),
            decoder_abi: Some(ElfAbi::Lp64),
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
                file_offset: Some(0),
                live_return: false,
                manifest_supported: false,
            }],
            interfaces: vec![],
        }
    }

    /// A pin set as `pin_scanned_objects` builds it, but written out directly: the
    /// two mappings this is about live in two mount namespaces, so reaching this
    /// state through the real scan needs two containers. Each entry is
    /// `(key, sha256, ctime)`; the pin's inode is the key's, as a real pin's always is.
    pub(crate) fn pin_set(entries: &[(ObjectKey, &str, i64)], overlay: bool) -> PinnedObjects {
        let mut result = PinnedObjects::empty();
        for (key, sha, ctime) in entries {
            let mut pins = view_pin(&module(*key), key.device.minor + 1, sha, *ctime, overlay);
            let entry = pins.by_id.pop_first().unwrap().1;
            result.insert_entry(entry, &mut Vec::new());
        }
        result
    }

    /// A scan pin over a real file: the pin and the mapping's device and
    /// inode come from the opened file itself, so retention,
    /// `check_unchanged` and the same-kernel-file proof behave as for a real
    /// scan pin. `key` overrides the raw maps key (one file seen through an
    /// overlay view); `sha256` is the digest the caller asserts for the bytes.
    pub(crate) fn real_scan_pin(
        path: &Path,
        key: Option<ObjectKey>,
        mount_id: u64,
        sha256: &str,
    ) -> PinnedObjects {
        let file = std::fs::File::open(path).unwrap();
        let metadata = file.metadata().unwrap();
        let fd_key = ObjectKey {
            device: Device {
                major: u64::from(libc::major(metadata.dev())),
                minor: u64::from(libc::minor(metadata.dev())),
            },
            inode: metadata.ino(),
        };
        let key = key.unwrap_or(fd_key);
        let path = path.to_str().unwrap();
        let raw = RawObjectInstance::scanned(&module(key), key, path).unwrap();
        let entry = Entry {
            mapping: MappingFileKey {
                mount_id,
                device_major: fd_key.device.major,
                device_minor: fd_key.device.minor,
                inode: fd_key.inode,
            },
            raw,
            pin: pin_of(&file).unwrap(),
            file: Arc::new(file),
            path: path.into(),
            sha256: sha256.into(),
            build_id: None,
            abi: ElfAbi::Lp64,
            exports: Arc::from(Vec::new()),
            overlay: false,
            collapsed: false,
        };
        let mut pins = PinnedObjects::empty();
        pins.insert_entry(entry, &mut Vec::new());
        pins
    }

    /// Objects opened through a container's overlay mount — the shape this is about.
    pub(crate) fn pins(entries: &[(ObjectKey, &str, i64)]) -> PinnedObjects {
        pin_set(entries, true)
    }

    pub(crate) fn view_pin(
        module: &ScannedModule,
        mapping_mount_id: u64,
        sha256: &str,
        ctime: i64,
        overlay: bool,
    ) -> PinnedObjects {
        let raw = RawObjectInstance::scanned(module, module.key, &module.path).unwrap();
        let entry = Entry {
            mapping: MappingFileKey {
                mount_id: mapping_mount_id,
                device_major: module.key.device.major,
                device_minor: module.key.device.minor,
                inode: module.key.inode,
            },
            raw,
            file: Arc::new(std::fs::File::open("/dev/null").unwrap()),
            pin: Pin {
                ino: module.key.inode,
                size: 4096,
                ctime: (ctime, 7),
            },
            path: module.path.clone(),
            sha256: sha256.into(),
            build_id: None,
            abi: ElfAbi::Lp64,
            exports: Arc::from(Vec::new()),
            overlay,
            collapsed: false,
        };
        let mut pins = PinnedObjects::empty();
        pins.insert_entry(entry, &mut Vec::new());
        pins
    }

    /// A real file on a real filesystem for backing fixtures. Each name is a
    /// distinct kernel file; every file carries identical bytes (the
    /// btrfs-clone shape), so only the kernel file separates same-key fixtures.
    pub(crate) fn backing_file(dir: &tempfile::TempDir, name: &str) -> Arc<std::fs::File> {
        let path = dir.path().join(name);
        std::fs::write(&path, "p11scope-fixture:shared-provider-bytes").unwrap();
        Arc::new(std::fs::File::open(&path).unwrap())
    }

    /// Re-backs every entry in `pins` with `file`, keeping the forged
    /// pin/mapping/sha. Fixtures sharing `/dev/null` are one kernel file; tests
    /// forging a genuine collision or a distinct overlay instance must re-back
    /// with distinct real files instead.
    pub(crate) fn reback(pins: &mut PinnedObjects, file: &Arc<std::fs::File>) {
        for entry in pins.by_id.values_mut() {
            entry.file = Arc::clone(file);
        }
    }

    /// The mount both halves of a forged pre-6.8 split resolve in: the scan
    /// pin and the manifest pin are one file in one mount namespace, so their
    /// mappings agree exactly.
    const SPLIT_MOUNT_ID: u64 = 7;

    /// A scan pin for a pre-6.8 overlayfs split: filed under the maps/backing
    /// key while the opened fd resolves to the overlay key — the shape
    /// `pin_scanned_object` accepts via the self-mapping probe.
    pub(crate) fn split_scan_pin(
        maps_key: ObjectKey,
        fd_key: ObjectKey,
        sha256: &str,
        ctime: i64,
    ) -> PinnedObjects {
        let modelled = module(maps_key);
        let raw = RawObjectInstance::scanned(&modelled, modelled.key, &modelled.path).unwrap();
        let entry = Entry {
            mapping: MappingFileKey {
                mount_id: SPLIT_MOUNT_ID,
                device_major: fd_key.device.major,
                device_minor: fd_key.device.minor,
                inode: fd_key.inode,
            },
            raw,
            file: Arc::new(std::fs::File::open("/dev/null").unwrap()),
            pin: Pin {
                ino: INODE,
                size: 4096,
                ctime: (ctime, 7),
            },
            path: modelled.path.clone(),
            sha256: sha256.into(),
            build_id: None,
            abi: ElfAbi::Lp64,
            exports: Arc::from(Vec::new()),
            overlay: true,
            collapsed: false,
        };
        let mut pins = PinnedObjects::empty();
        pins.insert_entry(entry, &mut Vec::new());
        pins
    }

    /// A manifest pin as `pin_manifest_objects` files it: under the opened
    /// fd's key, with the same mapping, pin and digest as its scan pin.
    pub(crate) fn manifest_pin(fd_key: ObjectKey, sha256: &str, ctime: i64) -> PinnedObjects {
        let raw = RawObjectInstance::manifest(fd_key, PATH.to_string()).unwrap();
        let entry = Entry {
            mapping: MappingFileKey {
                mount_id: SPLIT_MOUNT_ID,
                device_major: fd_key.device.major,
                device_minor: fd_key.device.minor,
                inode: fd_key.inode,
            },
            raw,
            file: Arc::new(std::fs::File::open("/dev/null").unwrap()),
            pin: Pin {
                ino: INODE,
                size: 4096,
                ctime: (ctime, 7),
            },
            path: PATH.into(),
            sha256: sha256.into(),
            build_id: None,
            abi: ElfAbi::Lp64,
            exports: Arc::from(Vec::new()),
            overlay: true,
            collapsed: false,
        };
        let mut pins = PinnedObjects::empty();
        pins.insert_entry(entry, &mut Vec::new());
        pins
    }

    /// A scripted self-mapping probe: `overlay` answers the overlayfs
    /// question and `key` answers the kernel-rendered maps key, counting both
    /// consultations. Real overlayfs is unmountable without privileges, so
    /// unit tests script the kernel side of the split.
    pub(crate) struct FakeSelfMappingProbe {
        pub(crate) overlay: bool,
        pub(crate) key: Option<ObjectKey>,
        pub(crate) overlay_checks: std::cell::Cell<usize>,
        pub(crate) probes: std::cell::Cell<usize>,
    }

    impl FakeSelfMappingProbe {
        pub(crate) fn new(overlay: bool, key: Option<ObjectKey>) -> Self {
            Self {
                overlay,
                key,
                overlay_checks: std::cell::Cell::new(0),
                probes: std::cell::Cell::new(0),
            }
        }
    }

    impl super::SelfMappingProbe for FakeSelfMappingProbe {
        fn fd_is_on_overlayfs(&self, _file: &std::fs::File) -> bool {
            self.overlay_checks.set(self.overlay_checks.get() + 1);
            self.overlay
        }

        fn kernel_maps_key(
            &self,
            _file: &std::fs::File,
            _budget: &mut dyn p11scope_manifest::identity::ProbeBudget,
        ) -> Option<ObjectKey> {
            self.probes.set(self.probes.get() + 1);
            self.key
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_fixture::{
        FakeSelfMappingProbe, INODE, PATH, SHA, backing_file, module, overlay, pin_set, pins,
        reback, view_pin,
    };
    use super::*;
    use crate::discovery::scan::ScannedEntry;
    use p11scope_manifest::identity::{IdentityKind, ObjectIdentity};
    use p11scope_manifest::manifest::{
        Acquisition, FunctionRecord, ObjectRecord, ProvenanceObject, SurfaceRecord, SurfaceSource,
        Version, WalkOutcome,
    };
    use std::cell::RefCell;

    thread_local! {
        static BEFORE_HASH_HOOK: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    }

    struct BeforeHashHookGuard;

    impl BeforeHashHookGuard {
        fn install(hook: impl FnOnce() + 'static) -> Self {
            BEFORE_HASH_HOOK.with(|slot| {
                assert!(slot.borrow_mut().replace(Box::new(hook)).is_none());
            });
            Self
        }
    }

    impl Drop for BeforeHashHookGuard {
        fn drop(&mut self) {
            BEFORE_HASH_HOOK.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }

    pub(super) fn run_before_hash_test_hook() {
        let hook = BEFORE_HASH_HOOK.with(|slot| slot.borrow_mut().take());
        if let Some(hook) = hook {
            hook();
        }
    }

    fn set_pin_abi(pins: &mut PinnedObjects, key: ObjectKey, abi: ElfAbi) {
        let entry = pins
            .by_id
            .values_mut()
            .find(|entry| entry.raw.key == key)
            .expect("fixture pin");
        entry.abi = abi;
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

    fn probe_tempfile() -> (tempfile::TempDir, std::fs::File) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probed.so");
        std::fs::write(&path, "p11scope-self-mapping-probe:page-one").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        (dir, file)
    }

    #[test]
    fn equal_fd_and_maps_keys_accept_without_consulting_the_probe() {
        let (_dir, file) = probe_tempfile();
        let probe = FakeSelfMappingProbe::new(true, None);
        let mut budget = CaptureWorkBudget::default();
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
        let (_dir, file) = probe_tempfile();
        let probe = FakeSelfMappingProbe::new(true, Some(backing_key()));
        let mut budget = CaptureWorkBudget::default();
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
        let (_dir, file) = probe_tempfile();
        let probe = FakeSelfMappingProbe::new(true, Some(overlay(43)));
        let mut budget = CaptureWorkBudget::default();
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
        let (_dir, file) = probe_tempfile();
        let probe = FakeSelfMappingProbe::new(false, Some(backing_key()));
        let mut budget = CaptureWorkBudget::default();
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
        let (_dir, file) = probe_tempfile();
        let probe = FakeSelfMappingProbe::new(true, None);
        let mut budget = CaptureWorkBudget::default();
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
        let empty = tempfile::NamedTempFile::new().unwrap();
        let file = std::fs::File::open(empty.path()).unwrap();
        let probe = FakeSelfMappingProbe::new(true, Some(backing_key()));
        let mut budget = CaptureWorkBudget::default();
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
        let (_dir, file) = probe_tempfile();
        let probe = FakeSelfMappingProbe::new(true, Some(backing_key()));
        let mut budget = CaptureWorkBudget::default();
        assert_eq!(
            self_mapped_fallback_key(&file, overlay(41), &mut budget, &probe),
            Some(backing_key())
        );
    }

    #[test]
    fn self_mapped_fallback_key_stays_none_without_a_retry_worth_making() {
        let (_dir, file) = probe_tempfile();
        let mut budget = CaptureWorkBudget::default();
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

    // The maps-line parser tests moved with the parser to
    // `p11scope_manifest::identity`; the adapter below is covered through
    // the real-probe tests against the shared kernel probe.

    /// Independent oracle for the real probe: map the file here and read the
    /// kernel's own maps line for that address with a deliberately minimal
    /// parse, so the probe's read path and parser are both checked. Compared
    /// against the maps rendering, never fstat: on btrfs the same file's
    /// st_dev (anonymous subvolume device, observed 0:37) differs from its
    /// maps s_dev (observed 00:23) — the reason retained identity resolves
    /// through mountinfo.
    fn maps_key_for_fresh_mapping(file: &std::fs::File) -> ObjectKey {
        use std::os::fd::AsRawFd as _;
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
        let (_dir, file) = probe_tempfile();
        let mut budget = CaptureWorkBudget::default();
        let io_before = budget.attempted_io_bytes();
        let probed = KernelSelfMappingProbe
            .kernel_maps_key(&file, &mut super::BudgetAdapter(&mut budget))
            .expect("a plain temp file probes");
        assert!(
            budget.attempted_io_bytes() > io_before,
            "the probe's /proc/self/maps read is charged to the capture budget"
        );
        assert_eq!(probed, maps_key_for_fresh_mapping(&file));
        assert_eq!(
            probed.inode,
            file.metadata().unwrap().ino(),
            "the same file keeps its inode in both renderings"
        );
    }

    /// A retained pre-exec interpreter has no target mapping to compare yet.
    /// On old overlayfs kernels its fd key must not become the live hook key.
    #[test]
    fn preexec_loader_key_uses_the_exact_kernel_maps_identity_on_overlay() {
        let (_dir, file) = probe_tempfile();
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let maps_key = ObjectKey {
            device: Device {
                major: 0,
                minor: 21,
            },
            inode: 712_355,
        };
        let probe = FakeSelfMappingProbe::new(true, Some(maps_key));
        let mut budget = CaptureWorkBudget::default();
        assert_eq!(
            preexec_object_key_with(&view, &file, &mut budget, &probe).unwrap(),
            maps_key,
            "the live loader record will name the maps identity, not the overlay fd device"
        );
    }

    #[test]
    fn preexec_loader_key_refuses_an_inconclusive_overlay_probe() {
        let (_dir, file) = probe_tempfile();
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let probe = FakeSelfMappingProbe::new(true, None);
        assert!(
            preexec_object_key_with(&view, &file, &mut CaptureWorkBudget::default(), &probe)
                .is_err(),
            "an unproven fd identity cannot authorize a future mapped loader"
        );
    }

    #[test]
    fn preexec_loader_key_keeps_the_mount_identity_off_overlayfs() {
        let (_dir, file) = probe_tempfile();
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let probe = FakeSelfMappingProbe::new(false, None);
        let mut budget = CaptureWorkBudget::default();
        let fd_key = retained_object_key(&view, &file, &mut budget).unwrap();
        assert_eq!(
            preexec_object_key_with(&view, &file, &mut budget, &probe).unwrap(),
            fd_key
        );
        assert_eq!(probe.probes.get(), 0, "ordinary mounts need no extra probe");
    }

    #[test]
    fn preexec_loader_key_refuses_an_exhausted_capture_budget() {
        let (_dir, file) = probe_tempfile();
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let mut budget = CaptureWorkBudget::default();
        assert!(!budget.charge(u64::MAX));
        assert!(preexec_object_key(&view, &file, &mut budget).is_err());
    }

    #[test]
    fn real_probe_refuses_an_empty_file() {
        let empty = tempfile::NamedTempFile::new().unwrap();
        let file = std::fs::File::open(empty.path()).unwrap();
        let mut budget = CaptureWorkBudget::default();
        assert_eq!(
            KernelSelfMappingProbe.kernel_maps_key(&file, &mut super::BudgetAdapter(&mut budget)),
            None
        );
    }

    #[test]
    fn real_probe_refuses_an_unmappable_fd() {
        use std::os::unix::fs::OpenOptionsExt as _;
        let (dir, _) = probe_tempfile();
        // O_PATH fds cannot back a mapping, so mmap fails and the probe is
        // inconclusive rather than wrong.
        let unmappable = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(dir.path().join("probed.so"))
            .unwrap();
        let mut budget = CaptureWorkBudget::default();
        assert_eq!(
            KernelSelfMappingProbe
                .kernel_maps_key(&unmappable, &mut super::BudgetAdapter(&mut budget)),
            None
        );
    }

    #[test]
    fn real_probe_refuses_when_the_budget_is_exhausted() {
        let (_dir, file) = probe_tempfile();
        let mut budget = CaptureWorkBudget::default();
        assert!(!budget.charge(u64::MAX), "the ceiling must be sticky");
        assert_eq!(
            KernelSelfMappingProbe.kernel_maps_key(&file, &mut super::BudgetAdapter(&mut budget)),
            None
        );
    }

    /// H-3: one cache reads a view's mount table once and serves every later
    /// identity from it, giving the same keys as a fresh read each time. A
    /// table the kernel reports changed is read again; another view reads its
    /// own.
    #[test]
    fn a_cached_mount_table_is_read_once_and_again_after_a_change() {
        let witness = crate::process::MountChangeWitness::new();
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let files: Vec<_> = ["/proc/self/exe", "/bin/sh", "/proc/self/status"]
            .iter()
            .map(|path| std::fs::File::open(path).unwrap())
            .collect();
        let mut budget = CaptureWorkBudget::default();
        let fresh: Vec<_> = files
            .iter()
            .map(|file| retained_object_key(&view, file, &mut budget).unwrap())
            .collect();

        let mut unchanged = MountTableCache::default();
        let before = crate::process::mountinfo_reads_for_test();
        let cached: Vec<_> = files
            .iter()
            .map(|file| {
                retained_object_key_cached(&view, file, &mut unchanged, &mut budget).unwrap()
            })
            .collect();
        assert_eq!(cached, fresh);
        let unchanged_reads = crate::process::mountinfo_reads_for_test() - before;

        let mut changing = MountTableCache::with_change_detector_for_test(|_| true);
        let before = crate::process::mountinfo_reads_for_test();
        for (file, key) in files.iter().zip(&fresh) {
            assert_eq!(
                retained_object_key_cached(&view, file, &mut changing, &mut budget).unwrap(),
                *key
            );
        }
        assert_eq!(crate::process::mountinfo_reads_for_test() - before, 3);

        let other = ProcessView::open(ProcessViewId(1), std::process::id()).unwrap();
        let before = crate::process::mountinfo_reads_for_test();
        retained_object_key_cached(&other, &files[0], &mut unchanged, &mut budget).unwrap();
        retained_object_key_cached(&other, &files[1], &mut unchanged, &mut budget).unwrap();
        let other_reads = crate::process::mountinfo_reads_for_test() - before;
        // A mount change elsewhere on the host must be read again; only an
        // unchanged table has to be read exactly once per view.
        if !witness.changed() {
            assert_eq!(unchanged_reads, 1, "one read serves every identity");
            assert_eq!(other_reads, 1, "another view reads its own table, once");
        }
    }

    #[test]
    fn open_view_object_refuses_an_identity_matching_mountinfo_prefix() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let full = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        let (path, prefix) = [temporary.path(), Path::new("/proc/self/status")]
            .into_iter()
            .find_map(|path| {
                let file = open_regular(path).ok()?;
                let mut prefix = String::new();
                for line in full.lines() {
                    prefix.push_str(line);
                    prefix.push('\n');
                    if identity_of_in_mountinfo(&file, &prefix).is_ok() {
                        return (prefix.len() < full.len()).then_some((path, prefix));
                    }
                }
                None
            })
            .expect("a controlled regular file must have a matching non-final mount row");
        let file = open_regular(path).unwrap();
        assert!(
            identity_of_in_mountinfo(&file, &prefix).is_ok(),
            "the prefix contains this opened fd's matching mount ID"
        );
        assert!(
            !full[prefix.len()..].is_empty(),
            "a table suffix must exist"
        );

        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let mut budget = CaptureWorkBudget::new(crate::discovery::scan::ScanLimits {
            per_object_bytes: u64::try_from(prefix.len()).unwrap(),
            total_bytes: u64::try_from(prefix.len() + 1).unwrap(),
        });
        let error = open_view_object(&view, path, &mut budget)
            .expect_err("the real identity caller must return no key from an incomplete table");
        assert!(error.contains("mountinfo byte ceiling"), "{error}");

        let (opened, key) = open_view_object(&view, path, &mut CaptureWorkBudget::default())
            .expect("the same caller accepts the EOF-proven complete table");
        assert_eq!(key, object_key(identity_of(&opened).unwrap()));
    }

    #[test]
    fn a_missing_mount_id_re_reads_the_table_once_before_failing() {
        let file = open_regular(Path::new("/bin/sh")).unwrap();
        let observer = mapping_file_key(&file).unwrap();
        // A table that names every mount except this fd's own: the resolver
        // reports the mount missing, exactly as under mount-table churn.
        assert_ne!(
            observer.mount_id, 999999,
            "fixture assumes the fd's mount row is absent from the stale table"
        );
        let stale = "999999 1 8:1 / /other rw - ext4 /dev/other rw\n";
        let fresh = format!(
            "{} 1 9:9 / /target rw - ext4 /dev/target rw\n",
            observer.mount_id
        );
        let rereads = RefCell::new(0usize);
        let found = identity_of_in_mountinfo_with_reread(&file, stale, || {
            *rereads.borrow_mut() += 1;
            Ok(fresh.clone())
        })
        .expect("one re-read must heal a churned mount row");
        assert_eq!(*rereads.borrow(), 1, "the table is re-read exactly once");
        assert_eq!(found.mount_id, observer.mount_id);
        assert_eq!(
            (found.device_major, found.device_minor),
            (9, 9),
            "the key must resolve in the re-read table, not the stale one"
        );
        assert_eq!(found.inode, observer.inode, "inode still comes from fstat");
    }

    #[test]
    fn a_persistently_missing_mount_id_keeps_todays_error() {
        let file = open_regular(Path::new("/bin/sh")).unwrap();
        let observer = mapping_file_key(&file).unwrap();
        assert_ne!(
            observer.mount_id, 999999,
            "fixture assumes the fd's mount row is absent from the stale table"
        );
        let stale = "999999 1 8:1 / /other rw - ext4 /dev/other rw\n";
        let rereads = RefCell::new(0usize);
        let error = identity_of_in_mountinfo_with_reread(&file, stale, || {
            *rereads.borrow_mut() += 1;
            Ok(stale.to_string())
        })
        .expect_err("a mount missing from both reads must still fail");
        assert_eq!(*rereads.borrow(), 1, "the table is re-read exactly once");
        assert_eq!(
            error,
            format!(
                "mapping identity unavailable: fd mount {} is missing from the mount table",
                observer.mount_id
            ),
            "persistent absence keeps today's error text byte-for-byte"
        );
    }

    #[test]
    fn failed_re_read_keeps_the_first_error() {
        let file = open_regular(Path::new("/bin/sh")).unwrap();
        let observer = mapping_file_key(&file).unwrap();
        assert_ne!(
            observer.mount_id, 999999,
            "fixture assumes the fd's mount row is absent from the stale table"
        );
        let stale = "999999 1 8:1 / /other rw - ext4 /dev/other rw\n";
        let rereads = RefCell::new(0usize);
        let error = identity_of_in_mountinfo_with_reread(&file, stale, || {
            *rereads.borrow_mut() += 1;
            Err("stale".into())
        })
        .expect_err("a failed re-read must keep the first missing-mount error");
        assert_eq!(*rereads.borrow(), 1, "the table is re-read exactly once");
        assert_eq!(
            error,
            format!(
                "mapping identity unavailable: fd mount {} is missing from the mount table",
                observer.mount_id
            ),
            "a failed re-read keeps the first error text byte-for-byte"
        );
    }

    #[test]
    fn other_resolution_errors_do_not_re_read_the_table() {
        let file = open_regular(Path::new("/bin/sh")).unwrap();
        let observer = mapping_file_key(&file).unwrap();
        // The mount row is present but corrupt: no re-read can heal it.
        let corrupt = format!(
            "{} 1 not-a-device / /target rw - ext4 /dev/target rw\n",
            observer.mount_id
        );
        let rereads = RefCell::new(0usize);
        let error = identity_of_in_mountinfo_with_reread(&file, &corrupt, || {
            *rereads.borrow_mut() += 1;
            Ok(corrupt.clone())
        })
        .expect_err("an invalid mount device must still fail");
        assert_eq!(*rereads.borrow(), 0, "only a missing mount id retries");
        assert!(
            error.contains("invalid mount device"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_scan_object_changed_after_pinning_is_not_accepted() {
        use crate::discovery::scan::ScannedModule;
        use std::io::Write as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("changed-after-pin.so");
        std::fs::copy("/bin/sh", &path).unwrap();
        let file = open_object(&path).unwrap();
        let mapping = mapping_file_key(&file).unwrap();
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let module = ScannedModule {
            mapped_identity: None,
            double_loaded: false,
            view: view.id(),
            mount_namespace: view.mount_namespace(),
            key: ObjectKey {
                device: Device {
                    major: mapping.device_major,
                    minor: mapping.device_minor,
                },
                inode: mapping.inode,
            },
            path: path.display().to_string(),
            decoder_abi: None,
            exports: Vec::new(),
            tables: Vec::new(),
            interfaces: Vec::new(),
        };
        let changed_path = path.clone();
        let _hook = BeforeHashHookGuard::install(move || {
            let mut changed = std::fs::OpenOptions::new()
                .append(true)
                .open(changed_path)
                .unwrap();
            changed.write_all(&[0]).unwrap();
        });

        let (pinned, skipped) = pin_scanned_view_objects(
            &view,
            std::slice::from_ref(&module),
            &mut CaptureWorkBudget::default(),
        )
        .unwrap();

        assert_eq!(pinned.pinned().count(), 0, "a changed hash has no pin");
        assert_eq!(skipped.len(), 1, "the changed object is reported once");
        assert_eq!(
            skipped[0].reason,
            "file changed while it was being identified — retry"
        );
    }

    #[test]
    fn identical_file_bytes_are_read_once_per_capture() {
        use crate::discovery::scan::ScannedModule;
        use std::io::Write as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cached-read.so");
        std::fs::copy("/bin/sh", &path).unwrap();
        let file = open_object(&path).unwrap();
        let file_len = file.metadata().unwrap().len();
        assert!(file_len > 0, "the fixture must have bytes worth caching");
        let mapping = mapping_file_key(&file).unwrap();
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let module = ScannedModule {
            mapped_identity: None,
            double_loaded: false,
            view: view.id(),
            mount_namespace: view.mount_namespace(),
            key: ObjectKey {
                device: Device {
                    major: mapping.device_major,
                    minor: mapping.device_minor,
                },
                inode: mapping.inode,
            },
            path: path.display().to_string(),
            decoder_abi: None,
            exports: Vec::new(),
            tables: Vec::new(),
            interfaces: Vec::new(),
        };
        let mut budget = CaptureWorkBudget::default();

        // First pin reads the whole file (plus the mount table).
        let (pinned, skipped) =
            pin_scanned_view_objects(&view, std::slice::from_ref(&module), &mut budget).unwrap();
        assert_eq!(pinned.pinned().count(), 1);
        assert!(skipped.is_empty());
        let charged_first = budget.attempted_io_bytes();
        assert!(
            charged_first >= file_len,
            "first pin charges the file read: {charged_first} >= {file_len}"
        );

        // Repeat pin of the unchanged file: mount-table bytes only, no file re-read.
        let (pinned, skipped) =
            pin_scanned_view_objects(&view, std::slice::from_ref(&module), &mut budget).unwrap();
        assert_eq!(pinned.pinned().count(), 1);
        assert!(skipped.is_empty());
        let charged_second = budget.attempted_io_bytes() - charged_first;
        assert!(
            charged_second < file_len,
            "repeat pin must not re-read {file_len} file bytes (charged {charged_second})"
        );

        // A changed file (new size pin) is read and charged again.
        let mut changed = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        changed.write_all(&[0]).unwrap();
        drop(changed);
        let new_len = std::fs::metadata(&path).unwrap().len();
        assert_eq!(new_len, file_len + 1);
        let (pinned, skipped) =
            pin_scanned_view_objects(&view, std::slice::from_ref(&module), &mut budget).unwrap();
        assert_eq!(pinned.pinned().count(), 1);
        assert!(skipped.is_empty());
        let charged_third = budget.attempted_io_bytes() - charged_first - charged_second;
        assert!(
            charged_third >= new_len,
            "changed file is read again: {charged_third} >= {new_len}"
        );
    }

    #[test]
    fn same_size_content_rewrite_rotates_the_pin_and_rereads() {
        use crate::discovery::scan::ScannedModule;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("same-size.so");
        std::fs::copy("/bin/sh", &path).unwrap();
        let file = open_object(&path).unwrap();
        let file_len = file.metadata().unwrap().len();
        assert!(file_len > 0, "the fixture must have bytes worth caching");
        let mapping = mapping_file_key(&file).unwrap();
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let module = ScannedModule {
            mapped_identity: None,
            double_loaded: false,
            view: view.id(),
            mount_namespace: view.mount_namespace(),
            key: ObjectKey {
                device: Device {
                    major: mapping.device_major,
                    minor: mapping.device_minor,
                },
                inode: mapping.inode,
            },
            path: path.display().to_string(),
            decoder_abi: None,
            exports: Vec::new(),
            tables: Vec::new(),
            interfaces: Vec::new(),
        };
        let mut budget = CaptureWorkBudget::default();

        let (pinned, skipped) =
            pin_scanned_view_objects(&view, std::slice::from_ref(&module), &mut budget).unwrap();
        assert_eq!(pinned.pinned().count(), 1);
        assert!(skipped.is_empty());
        let charged_first = budget.attempted_io_bytes();
        let old_pin = pin_of(&open_object(&path).unwrap()).unwrap();

        // Rewrite the content without changing the size: the pin must rotate
        // on ctime alone. The loop only absorbs coarse-timestamp filesystems;
        // a pin that ignored ctime would never rotate and still fail below.
        let mut bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() > 1024, "the fixture must cover both edits");
        let mut new_pin = None;
        for _ in 0..500 {
            bytes[64] = bytes[64].wrapping_add(1);
            bytes[1024] = bytes[1024].wrapping_add(1);
            std::fs::write(&path, &bytes).unwrap();
            let candidate = pin_of(&open_object(&path).unwrap()).unwrap();
            assert_eq!(candidate.size, file_len, "the rewrite keeps the size");
            if candidate != old_pin {
                new_pin = Some(candidate);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let new_pin = new_pin.expect("the same-size rewrite rotates the pin");
        assert_ne!(new_pin, old_pin);

        // The rescan accepts the rotated file and charges the re-read.
        let (pinned, skipped) =
            pin_scanned_view_objects(&view, std::slice::from_ref(&module), &mut budget).unwrap();
        assert_eq!(pinned.pinned().count(), 1);
        assert!(skipped.is_empty());
        let charged_second = budget.attempted_io_bytes() - charged_first;
        assert!(
            charged_second >= file_len,
            "rotated file is read again: {charged_second} >= {file_len}"
        );
    }

    #[test]
    fn decoder_abi_mismatch_refuses_the_module_before_ownership() {
        let key = overlay(210);
        let mut scanned = module(key);
        scanned.decoder_abi = Some(ElfAbi::Ilp32);
        let mut pinned = view_pin(&scanned, 1, SHA, 1, false);

        let (bound, skipped) = bind_scanned_modules(&[scanned.clone()], &mut pinned);

        assert!(bound.is_empty());
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].subject, scanned.path);
        assert!(skipped[0].reason.contains("decoder ABI disagrees"));
        assert!(pinned.ownership.is_empty(), "a refused decode owns nothing");
    }

    #[test]
    fn matching_ilp32_decoder_abi_binds_but_a_lp64_dependency_does_not() {
        let provider = overlay(211);
        let dependency = ObjectKey {
            inode: provider.inode + 1,
            ..provider
        };
        let mut scanned = module(provider);
        scanned.decoder_abi = Some(ElfAbi::Ilp32);
        scanned.tables[0].entries[0].object = dependency;

        let mut pinned = view_pin(&scanned, 1, SHA, 1, false);
        set_pin_abi(&mut pinned, provider, ElfAbi::Ilp32);
        let mut dependency_module = scanned.clone();
        dependency_module.key = dependency;
        let dependency_pins = view_pin(&dependency_module, 2, SHA, 1, false);
        assert!(pinned.absorb(dependency_pins).is_empty());

        set_pin_abi(&mut pinned, dependency, ElfAbi::Ilp32);
        let mut matching = pinned.clone();
        let (bound, skipped) = bind_scanned_modules(&[scanned.clone()], &mut matching);
        assert!(skipped.is_empty());
        assert_eq!(bound.len(), 1);
        assert_eq!(bound[0].scanned.tables[0].entries.len(), 1);
        assert_eq!(bound[0].entry_objects[0].len(), 1);
        let ownership = matching.ownership.values().next().unwrap();
        assert_eq!(ownership.tables.len(), 1);
        assert_eq!(ownership.targets.len(), 1);

        set_pin_abi(&mut pinned, dependency, ElfAbi::Lp64);
        let (bound, skipped) = bind_scanned_modules(&[scanned], &mut pinned);

        assert_eq!(bound.len(), 1, "matching ILP32 provider is retained");
        assert!(bound[0].scanned.tables[0].entries.is_empty());
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].reason.contains("different target ABI"));
        assert_eq!(pinned.ownership.values().next().unwrap().tables.len(), 1);
        assert!(pinned.ownership.values().next().unwrap().targets.is_empty());
    }

    #[test]
    fn retained_view_object_open_rejects_a_fifo_without_data_open() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;

        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("interpreter");
        let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();

        let error = open_view_object(&view, &fifo, &mut CaptureWorkBudget::default())
            .expect_err("a FIFO is not a loader object");
        assert!(error.contains("not a regular file"), "{error}");
    }

    /// The same objects, opened on a real filesystem rather than through an overlay.
    fn image_pins(entries: &[(ObjectKey, &str, i64)]) -> PinnedObjects {
        pin_set(entries, false)
    }

    fn manifest_pins(key: ObjectKey, sha256: &str, ctime: i64) -> PinnedObjects {
        let mut pins = pin_set(&[(key, sha256, ctime)], true);
        let (raw, id) = pins.raw_to_id.pop_first().expect("one scan raw alias");
        assert!(raw.mount_namespace.is_some());
        let raw = RawObjectInstance::manifest(key, PATH.into()).expect("absolute manifest path");
        pins.by_id.get_mut(&id).expect("entry for raw alias").raw = raw.clone();
        pins.raw_to_id.insert(raw, id);
        pins
    }

    fn manifest_for(key: ObjectKey) -> Manifest {
        let identity = ObjectIdentity {
            kind: IdentityKind::GnuBuildId,
            value: Some("fixture".into()),
            sha256: Some(SHA.repeat(8)),
            reusable: true,
            note: None,
        };
        Manifest {
            schema: "test".into(),
            module_path: PATH.into(),
            objects: vec![ObjectRecord {
                id: 0,
                path: PATH.into(),
                identity: identity.clone(),
            }],
            provenance_objects: vec![ProvenanceObject {
                path: PATH.into(),
                device_major: key.device.major,
                device_minor: key.device.minor,
                inode: key.inode,
                identity,
            }],
            interface_list: Acquisition::Absent,
            surfaces: vec![SurfaceRecord {
                source: SurfaceSource::LegacyFunctionList,
                acquisition: Acquisition::Ok,
                version: Some(Version {
                    major: 2,
                    minor: 40,
                }),
                walk: WalkOutcome::Full,
                functions: vec![FunctionRecord {
                    name: "C_Initialize".into(),
                    resolution: Resolution::Resolved {
                        object: 0,
                        file_offset: 0x1000,
                    },
                }],
            }],
            vendor_interfaces: vec![],
            alias_groups: vec![],
            selection_evidence: Default::default(),
        }
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
                ProcessViewId(*view as u32),
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
    fn only_not_found_is_a_deferred_open_staleness() {
        assert_eq!(
            classify_locator_error(std::io::ErrorKind::NotFound),
            Some(ManifestStaleReason::OpenStale)
        );
        for fatal in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::InvalidData,
            std::io::ErrorKind::OutOfMemory,
            std::io::ErrorKind::Other,
        ] {
            assert_eq!(classify_locator_error(fatal), None, "{fatal:?}");
        }
    }

    #[test]
    fn retained_mount_table_controls_manifest_mapping_identity() {
        let file = open_object(Path::new("/bin/sh")).unwrap();
        let observer = identity_of_manifest(&file, None).unwrap();
        let target_major = observer.device_major.saturating_add(1);
        let target_minor = observer.device_minor.saturating_add(1);
        let target_mountinfo = format!(
            "{} 1 {target_major}:{target_minor} / /target rw - ext4 /dev/target rw\n",
            observer.mount_id
        );

        let retained = identity_of_manifest(&file, Some(&target_mountinfo)).unwrap();
        assert_eq!(retained.mount_id, observer.mount_id);
        assert_eq!(
            (retained.device_major, retained.device_minor),
            (target_major, target_minor),
            "manifest identity must use the retained view table, not observer mountinfo"
        );
        assert_eq!(retained.inode, observer.inode);
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
    fn absorbing_same_open_file_once_rejected_as_incomparable_merges() {
        // Both fixtures open /dev/null: one kernel file seen through two mount
        // tables is the cross-namespace shape, so it merges. The genuine
        // collision assertions this test used to carry moved to
        // absorbing_same_key_distinct_files_still_rejects_the_collision_group.
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: INODE,
        };
        let mut first = image_pins(&[(key, "aaaaaaaa", 1)]);
        let mut second = image_pins(&[(key, "aaaaaaaa", 1)]);
        second.by_id.values_mut().next().unwrap().mapping.mount_id += 1;

        let skipped = first.absorb(second);

        assert_eq!(first.pinned().count(), 1, "{skipped:?}");
        assert!(skipped.is_empty(), "{skipped:?}");
    }

    #[test]
    fn absorbing_same_open_file_across_mount_namespaces_merges() {
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: INODE,
        };
        let dir = tempfile::tempdir().unwrap();
        // Two mount tables, one kernel file: each view opened the same path.
        let first_file = backing_file(&dir, "provider.so");
        let second_file = Arc::new(std::fs::File::open(dir.path().join("provider.so")).unwrap());
        let mut first = image_pins(&[(key, "aaaaaaaa", 1)]);
        reback(&mut first, &first_file);
        let mut second = image_pins(&[(key, "aaaaaaaa", 1)]);
        reback(&mut second, &second_file);
        second.by_id.values_mut().next().unwrap().mapping.mount_id += 1;

        let skipped = first.absorb(second);

        assert_eq!(first.pinned().count(), 1, "{skipped:?}");
        assert!(skipped.is_empty(), "{skipped:?}");
    }

    #[test]
    fn absorbing_same_key_distinct_files_still_rejects_the_collision_group() {
        // The btrfs-clone shape: identical bytes, forged same key, equal
        // pin+sha — but two kernel files, so the collision group still rejects.
        // (Reject assertions moved here from the rewritten merge test above.)
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: INODE,
        };
        let dir = tempfile::tempdir().unwrap();
        let mut first = image_pins(&[(key, "aaaaaaaa", 1)]);
        reback(&mut first, &backing_file(&dir, "first.so"));
        let committed = first.clone();
        let mut second = image_pins(&[(key, "aaaaaaaa", 1)]);
        reback(&mut second, &backing_file(&dir, "second.so"));
        second.by_id.values_mut().next().unwrap().mapping.mount_id += 1;

        let skipped = first.absorb(second);

        assert_eq!(
            first.pinned().count(),
            0,
            "receiver-wins would let one incomparable fd lend its offsets to the other view"
        );
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert!(skipped[0].reason.contains("physical identity is ambiguous"));

        let rejected = first.newly_rejected_keys(&committed);
        assert_eq!(rejected, [key].into_iter().collect());
        let mut replay = committed;
        let replay_skips = replay.reapply_rejected_keys(&rejected);
        assert!(replay.rejects(key));
        assert_eq!(replay.pinned().count(), 0);
        assert_eq!(ambiguity_count(&replay_skips), 1, "{replay_skips:?}");
    }

    #[test]
    fn absorbing_same_key_unavailable_digest_still_rejects() {
        // One kernel file both sides — but one side never hashed, so the bytes
        // are unproven and the group still rejects.
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: INODE,
        };
        let dir = tempfile::tempdir().unwrap();
        let file = backing_file(&dir, "provider.so");
        let mut first = image_pins(&[(key, "aaaaaaaa", 1)]);
        reback(&mut first, &file);
        let mut second = image_pins(&[(key, "", 1)]);
        reback(&mut second, &file);
        second.by_id.values_mut().next().unwrap().mapping.mount_id += 1;

        let skipped = first.absorb(second);

        assert_eq!(first.pinned().count(), 0);
        assert_eq!(ambiguity_count(&skipped), 1, "{skipped:?}");
    }

    #[test]
    fn owned_timing_key_matches_only_the_full_opened_identity() {
        let first_key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: INODE,
        };
        let other_key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: INODE + 1,
        };
        let first = image_pins(&[(first_key, "aaaaaaaa", 1)]);
        let mut shifted = image_pins(&[(other_key, "bbbbbbbb", 2)]);
        assert!(
            shifted
                .absorb(image_pins(&[(first_key, "aaaaaaaa", 1)]))
                .is_empty()
        );
        let changed = image_pins(&[(first_key, "cccccccc", 1)]);

        let first_id = first.pinned().next().unwrap().id;
        let shifted_id = shifted
            .pinned()
            .find(|pin| pin.key == first_key)
            .unwrap()
            .id;
        let changed_id = changed.pinned().next().unwrap().id;

        assert_ne!(
            first_id, shifted_id,
            "the fixture uses different allocators"
        );
        assert_eq!(
            first.owned_timing_key(first_id),
            shifted.owned_timing_key(shifted_id),
            "capture-local numeric IDs do not define timing ownership"
        );
        assert_ne!(
            first.owned_timing_key(first_id),
            changed.owned_timing_key(changed_id),
            "an unequal full opened identity cannot inherit timing"
        );
    }

    #[test]
    fn fresh_view_aggregation_restores_the_stable_original_pin_in_both_orders() {
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: INODE,
        };
        let mut stable_module = module(key);
        stable_module.view = ProcessViewId(1);
        stable_module.mount_namespace.inode = 1;
        let mut stale_module = stable_module.clone();
        stale_module.view = ProcessViewId(2);
        stale_module.mount_namespace.inode = 2;
        // A stale view disagreeing on one key is a genuine collision: two files.
        let dir = tempfile::tempdir().unwrap();
        let mut stable = view_pin(&stable_module, 11, "aaaaaaaa", 1, false);
        reback(&mut stable, &backing_file(&dir, "stable.so"));
        let mut stale = view_pin(&stale_module, 12, "aaaaaaaa", 1, false);
        reback(&mut stale, &backing_file(&dir, "stale.so"));
        let original = stable
            .attach_path_for(stable.pinned().next().unwrap().id)
            .unwrap();

        for sources in [vec![&stable, &stale], vec![&stale, &stable]] {
            let (rejected, skipped) = PinnedObjects::aggregate_views(sources);
            assert_eq!(rejected.pinned().count(), 0);
            assert_eq!(ambiguity_count(&skipped), 1, "{skipped:?}");
        }

        let (mut rebuilt, skipped) = PinnedObjects::aggregate_views([&stable]);
        assert!(skipped.is_empty(), "{skipped:?}");
        let (modules, collapsed, lost) =
            reconcile_scanned_modules(std::slice::from_ref(&stable_module), &mut rebuilt);
        assert_eq!((collapsed, lost.len()), (0, 0), "{lost:?}");
        let plan = crate::plan::build_from_reconciled_modules(&modules);
        assert_eq!(plan.slots.len(), 1);
        assert_eq!(
            rebuilt.attach_path_for(plan.slots[0].object).unwrap(),
            original,
            "the retry must reuse the originally opened stable fd"
        );
        assert!(
            rebuilt
                .id_for_scanned(&stable_module, stable_module.key, &stable_module.path)
                .is_some(),
            "the stable raw alias must be rebuilt"
        );
    }

    #[test]
    fn fresh_view_aggregation_recomputes_collision_evidence_from_survivors() {
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: INODE,
        };
        let source = |view, mapping_mount_id| {
            let mut module = module(key);
            module.view = ProcessViewId(view);
            module.mount_namespace.inode = u64::from(view);
            view_pin(&module, mapping_mount_id, "aaaaaaaa", 1, false)
        };
        // Views colliding on one key are genuinely distinct files.
        let dir = tempfile::tempdir().unwrap();
        let mut stable = source(1, 11);
        reback(&mut stable, &backing_file(&dir, "stable.so"));
        let mut stale = source(2, 12);
        reback(&mut stale, &backing_file(&dir, "stale.so"));
        let mut remaining_collision = source(3, 13);
        reback(
            &mut remaining_collision,
            &backing_file(&dir, "remaining.so"),
        );

        let (_, initial) = PinnedObjects::aggregate_views([&stable, &stale]);
        assert_eq!(ambiguity_count(&initial), 1, "{initial:?}");

        let (restored, after_retirement) = PinnedObjects::aggregate_views([&stable]);
        assert_eq!(restored.pinned().count(), 1);
        assert_eq!(
            ambiguity_count(&after_retirement),
            0,
            "stale-view-caused collision evidence leaked into the retry"
        );

        let (still_rejected, remaining) =
            PinnedObjects::aggregate_views([&stable, &remaining_collision]);
        assert_eq!(still_rejected.pinned().count(), 0);
        assert_eq!(
            ambiguity_count(&remaining),
            1,
            "a collision between retained views must remain PARTIAL"
        );
    }

    #[test]
    fn fresh_view_aggregation_drops_retired_overlay_uncertainty_and_keeps_one_slot() {
        let stable_module = module(overlay(102));
        let stale_module = module(overlay(104));
        let stable = view_pin(&stable_module, 103, SHA, 1, true);
        let stale = view_pin(&stale_module, 105, SHA, 1, true);

        let (mut initial, mut initial_lost) = PinnedObjects::aggregate_views([&stable, &stale]);
        let (modules, collapsed, lost) =
            reconcile_scanned_modules(&[stable_module.clone(), stale_module], &mut initial);
        initial_lost.extend(lost);
        assert_eq!(collapsed, 1);
        assert_eq!(
            crate::plan::build_from_reconciled_modules(&modules)
                .slots
                .len(),
            1
        );
        assert!(
            initial_lost
                .iter()
                .any(|skip| skip.reason.contains("cannot prove physical identity")),
            "{initial_lost:?}"
        );

        let (mut rebuilt, mut after_retirement) = PinnedObjects::aggregate_views([&stable]);
        let (modules, collapsed, lost) = reconcile_scanned_modules(&[stable_module], &mut rebuilt);
        after_retirement.extend(lost);
        assert_eq!(collapsed, 0);
        assert_eq!(
            crate::plan::build_from_reconciled_modules(&modules)
                .slots
                .len(),
            1
        );
        assert!(
            after_retirement
                .iter()
                .all(|skip| !skip.reason.contains("cannot prove physical identity")),
            "retired overlay uncertainty leaked into the retry: {after_retirement:?}"
        );
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
                    ProcessViewId(0),
                    raw.clone(),
                    Err("mapping identity unavailable".into()),
                    &mut skipped,
                );
            }
            record_scanned_candidate(
                &mut pinned,
                ProcessViewId(0),
                raw.clone(),
                Ok(entry),
                &mut skipped,
            );
            if !unavailable_first {
                record_scanned_candidate(
                    &mut pinned,
                    ProcessViewId(0),
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
                ProcessViewId(view as u32),
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
        // Two overlay instances are two files; one file would take the
        // same-open-file path instead of the overlay exception below.
        let dir = tempfile::tempdir().unwrap();
        let mut first = pins(&[(key, SHA, 1)]);
        reback(&mut first, &backing_file(&dir, "first.so"));
        let mut second = pins(&[(key, SHA, 1)]);
        reback(&mut second, &backing_file(&dir, "second.so"));
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
    fn manifest_attestation_cannot_cross_a_scan_only_overlay_collapse() {
        let a = module(overlay(102));
        let b = module(overlay(104));
        let mut pinned = pins(&[(a.key, SHA, 1), (b.key, SHA, 1)]);

        let (_, collapsed, initial_uncertainty) =
            reconcile_scanned_modules(&[a.clone(), b.clone()], &mut pinned);
        assert_eq!(collapsed, 1);
        assert_eq!(initial_uncertainty.len(), 1, "{initial_uncertainty:?}");

        assert!(pinned.absorb(manifest_pins(b.key, SHA, 1)).is_empty());
        let (scanned, _, _) = reconcile_scanned_modules(&[a.clone(), b.clone()], &mut pinned);
        let scan_id = pinned
            .id_for_scanned(&a, a.key, &a.path)
            .expect("canonical scan pin");
        let manifest_id = pinned
            .id_for_manifest(b.key, PATH)
            .expect("exact manifest pin");
        let plan = crate::plan::build_from_sources(&scanned, &[manifest_for(b.key)], &pinned);
        let scan_slot = plan
            .slots
            .iter()
            .find(|slot| slot.object == scan_id)
            .expect("scan overlay slot");

        assert!(
            !scan_slot.semantic_authorized,
            "an exact manifest for overlay B must not authorize uncertain scan peer A"
        );
        assert_eq!(
            scan_slot.semantics,
            p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
        );
        let manifest_slot = plan
            .slots
            .iter()
            .find(|slot| slot.object == manifest_id)
            .expect("manifest B remains a distinct pinned object");
        assert!(manifest_slot.semantic_authorized);
        assert_ne!(scan_id, manifest_id);
    }

    #[test]
    fn same_raw_key_overlay_exception_never_crosses_sources_in_either_absorb_order() {
        let key = overlay(102);
        // Two sources observing one key through different tables are two files;
        // one file would merge instead of exercising the cross-source reject.
        let dir = tempfile::tempdir().unwrap();
        let scan_file = backing_file(&dir, "scan.so");
        let manifest_file = backing_file(&dir, "manifest.so");
        for manifest_first in [false, true] {
            let mut scan = pins(&[(key, SHA, 1)]);
            reback(&mut scan, &scan_file);
            let mut manifest = manifest_pins(key, SHA, 1);
            reback(&mut manifest, &manifest_file);
            manifest
                .by_id
                .values_mut()
                .next()
                .expect("manifest entry")
                .mapping
                .mount_id += 1;
            let (mut first, second) = if manifest_first {
                (manifest, scan)
            } else {
                (scan, manifest)
            };

            let skipped = first.absorb(second);

            assert_eq!(
                first.pinned().count(),
                0,
                "cross-source overlay fallback must reject the same raw key ({manifest_first})"
            );
            assert_eq!(ambiguity_count(&skipped), 1, "{skipped:?}");
        }
    }

    #[test]
    fn overlay_merge_rejects_a_scan_peer_when_the_candidate_has_a_manifest_alias() {
        let key = overlay(102);
        // The peer from another mount table is another file; the same file
        // would merge instead of exercising the mixed-group reject.
        let dir = tempfile::tempdir().unwrap();
        let mut pinned = pins(&[(key, SHA, 1)]);
        reback(&mut pinned, &backing_file(&dir, "candidate.so"));
        assert!(pinned.absorb(manifest_pins(key, SHA, 1)).is_empty());
        let id = pinned
            .id_for_scanned(&module(key), key, PATH)
            .expect("exact scan alias");
        assert_eq!(pinned.sources(id), ["scan", "manifest"]);

        let mut peer = pins(&[(key, SHA, 1)]);
        reback(&mut peer, &backing_file(&dir, "peer.so"));
        peer.by_id
            .values_mut()
            .next()
            .expect("scan peer")
            .mapping
            .mount_id += 1;
        let skipped = pinned.absorb(peer);

        assert_eq!(
            pinned.pinned().count(),
            0,
            "a mixed candidate group must not receive another scan peer through overlay equality"
        );
        assert_eq!(ambiguity_count(&skipped), 1, "{skipped:?}");
    }

    #[test]
    fn overlay_merge_rejects_a_mixed_incoming_group() {
        let key = overlay(102);
        // The incoming group observes the key through another table: another
        // file than the receiver's, so the join must reject.
        let dir = tempfile::tempdir().unwrap();
        let mut receiver = pins(&[(key, SHA, 1)]);
        reback(&mut receiver, &backing_file(&dir, "receiver.so"));
        let mut incoming = pins(&[(key, SHA, 1)]);
        let incoming_file = backing_file(&dir, "incoming.so");
        reback(&mut incoming, &incoming_file);
        incoming
            .by_id
            .values_mut()
            .next()
            .expect("incoming scan pin")
            .mapping
            .mount_id += 1;
        let mut incoming_manifest = manifest_pins(key, SHA, 1);
        reback(&mut incoming_manifest, &incoming_file);
        incoming_manifest
            .by_id
            .values_mut()
            .next()
            .expect("incoming manifest pin")
            .mapping
            .mount_id += 1;
        assert!(incoming.absorb(incoming_manifest).is_empty());
        let id = incoming
            .id_for_scanned(&module(key), key, PATH)
            .expect("incoming scan alias");
        assert_eq!(incoming.sources(id), ["scan", "manifest"]);

        let skipped = receiver.absorb(incoming);

        assert_eq!(
            receiver.pinned().count(),
            0,
            "a mixed incoming group must not use overlay equality to join a scan-only peer"
        );
        assert_eq!(ambiguity_count(&skipped), 1, "{skipped:?}");
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
        // A late collision is a genuinely different file disagreeing on one key.
        let dir = tempfile::tempdir().unwrap();
        let mut first = image_pins(&[(key, "aaaaaaaa", 1)]);
        reback(&mut first, &backing_file(&dir, "first.so"));
        reconcile_scanned_modules(std::slice::from_ref(&first_module), &mut first);

        let mut collision = image_pins(&[(key, "aaaaaaaa", 1)]);
        reback(&mut collision, &backing_file(&dir, "collision.so"));
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

    /// Fixture pins bypass `record_scanned_candidate`, which attaches raw
    /// ownership at pin time in production. Restore the production shape so
    /// the cycle below exercises states real scans can reach.
    fn own_all_raws(pins: &mut PinnedObjects) {
        let raws: Vec<_> = pins.raw_to_id.keys().cloned().collect();
        for raw in raws {
            // Fixture keys encode their view in device.minor (see module()).
            pins.raw_ownership
                .entry(ProcessViewId(raw.key.device.minor as u32))
                .or_default()
                .insert(raw);
        }
    }

    fn assert_pins_consistent(step: &str, pins: &PinnedObjects) {
        let by_id: BTreeSet<_> = pins.by_id.keys().copied().collect();
        let mut claimed = BTreeSet::new();
        for claims in pins.ownership.values() {
            claimed.extend(claims.tables.iter().copied());
            claimed.extend(claims.targets.iter().map(|(id, _)| *id));
            claimed.extend(claims.pins.iter().copied());
        }
        for id in &claimed {
            assert!(
                by_id.contains(id),
                "[{step}] claimed id {id:?} missing from by_id"
            );
        }
        for (raw, id) in &pins.raw_to_id {
            assert!(
                by_id.contains(id),
                "raw {raw:?} maps to an id missing from by_id: {id:?}"
            );
        }
        for raws in pins.raw_ownership.values() {
            for raw in raws {
                assert!(
                    pins.raw_to_id.contains_key(raw),
                    "owned raw {raw:?} missing from raw_to_id"
                );
            }
        }
        let manifest_backed: BTreeSet<_> = pins
            .raw_to_id
            .iter()
            .filter_map(|(raw, id)| raw.mount_namespace.is_none().then_some(*id))
            .collect();
        for id in by_id {
            assert!(
                claimed.contains(&id) || manifest_backed.contains(&id),
                "by_id id {id:?} is neither claimed nor manifest-backed"
            );
        }
    }

    /// MED-4: `replace_view_pins` retains `by_id` by surviving raws, so any
    /// raw-ownership gap would strand dangling claim ids (and stale owned
    /// raws). Production scans always attach raw ownership at pin time, but
    /// the replace path must not trust that: it scrubs both maps for ids its
    /// retain drops, mirroring `remove_view`.
    #[test]
    fn replace_absorb_remove_cycles_keep_claims_and_pins_consistent() {
        let real = |minor| ObjectKey {
            device: Device { major: 8, minor },
            inode: INODE + minor,
        };
        let first_module = module(real(1));
        let mut pins = image_pins(&[(real(1), "aaaaaaaa", 1)]);
        reconcile_scanned_modules(std::slice::from_ref(&first_module), &mut pins);
        own_all_raws(&mut pins);
        assert_pins_consistent("reconcile", &pins);

        let second_module = module(real(17));
        let mut incoming = image_pins(&[(real(17), "bbbbbbbb", 2)]);
        reconcile_scanned_modules(std::slice::from_ref(&second_module), &mut incoming);
        own_all_raws(&mut incoming);
        pins.absorb(incoming);
        assert_pins_consistent("absorb", &pins);

        let mut rescan = image_pins(&[(real(1), "aaaaaaaa", 1)]);
        reconcile_scanned_modules(std::slice::from_ref(&first_module), &mut rescan);
        own_all_raws(&mut rescan);
        pins.replace_view_pins(first_module.view, rescan, &[]);
        assert_pins_consistent("replace", &pins);

        // The gap shape: raw ownership lost while claims survive (never from
        // production scans, but the replace path must survive it anyway).
        // View 17 keeps its claims while its id loses every owned raw.
        pins.raw_ownership.clear();
        pins.replace_view_pins(first_module.view, PinnedObjects::empty(), &[]);
        assert_pins_consistent("replace-after-gap", &pins);
        assert!(
            pins.by_id.is_empty() && pins.raw_to_id.is_empty(),
            "unowned pins are collected, not stranded"
        );

        pins.remove_view(second_module.view);
        assert_pins_consistent("remove", &pins);
    }

    /// C1b: only a key naming exactly one proven opened object may match a
    /// sweep. Collapsed overlay instances, same-key heuristic aliases, and
    /// rejected keys never do; one file seen through two mounts does.
    #[test]
    fn sweep_match_keys_name_exactly_one_proven_object() {
        let plain = pin_set(&[(overlay(1), SHA, 1)], false);
        let keys: Vec<ObjectKey> = plain.sweep_match_keys().into_keys().collect();
        assert_eq!(keys, vec![overlay(1)]);

        // Two overlay instances collapsed by the heuristic: neither key.
        let mut collapsed = pins(&[
            (overlay(1), SHA, 1),
            (overlay(2), SHA, 1),
            (overlay(3), "cc", 9),
        ]);
        let (count, _) = canonicalize_scanned_overlays(&mut collapsed);
        assert_eq!(count, 1);
        let keys: Vec<ObjectKey> = collapsed.sweep_match_keys().into_keys().collect();
        assert_eq!(
            keys,
            vec![overlay(3)],
            "only the uncollapsed instance matches"
        );

        let key = overlay(1);
        let view = |id: u32, mount: u64, overlay: bool| {
            let mut scanned = module(key);
            scanned.view = ProcessViewId(id);
            scanned.mount_namespace.inode = u64::from(id) + 100;
            view_pin(&scanned, mount, SHA, 1, overlay)
        };
        let dir = tempfile::tempdir().unwrap();

        // One kernel file through two mounts: the same-open-file proof.
        let shared = backing_file(&dir, "shared.so");
        let mut first = view(1, 11, false);
        reback(&mut first, &shared);
        let mut second = view(2, 12, false);
        reback(&mut second, &shared);
        let (merged, skipped) = PinnedObjects::aggregate_views([&first, &second]);
        assert!(skipped.is_empty(), "{skipped:?}");
        assert_eq!(merged.sweep_match_keys().len(), 1);

        // Two kernel files under one key on overlay: the heuristic alias.
        let mut left = view(3, 13, true);
        reback(&mut left, &backing_file(&dir, "left.so"));
        let mut right = view(4, 14, true);
        reback(&mut right, &backing_file(&dir, "right.so"));
        let (aliased, _) = PinnedObjects::aggregate_views([&left, &right]);
        assert_eq!(aliased.pinned().count(), 1, "the heuristic merged them");
        assert!(aliased.sweep_match_keys().is_empty());

        // Two kernel files under one key off overlay: rejected.
        let mut one = view(5, 15, false);
        reback(&mut one, &backing_file(&dir, "one.so"));
        let mut two = view(6, 16, false);
        reback(&mut two, &backing_file(&dir, "two.so"));
        let (rejected, _) = PinnedObjects::aggregate_views([&one, &two]);
        assert!(rejected.rejects(key));
        assert!(rejected.sweep_match_keys().is_empty());
    }

    /// C1b defense in depth: `reject_key` drops a rejected key's raw
    /// aliases and insertion never files one key under two objects, so
    /// these states are unreachable through the public API today. The
    /// sweep-match filter must still fail closed on each of them by
    /// itself, never relying on those invariants.
    #[test]
    fn sweep_match_keys_fail_closed_on_states_the_invariants_forbid() {
        let id_of = |pins: &PinnedObjects, key: ObjectKey| {
            pins.raw_to_id
                .iter()
                .find_map(|(raw, id)| (raw.key == key).then_some(*id))
                .expect("a raw alias under the key")
        };
        let alias_raw = |pins: &PinnedObjects, key: ObjectKey| {
            let (raw, _) = pins.raw_to_id.first_key_value().expect("one scan raw");
            RawObjectInstance { key, ..raw.clone() }
        };

        // One key filed under two objects.
        let mut two_objects = pin_set(&[(overlay(1), SHA, 1), (overlay(2), "bb", 2)], false);
        assert_eq!(two_objects.sweep_match_keys().len(), 2);
        let other = id_of(&two_objects, overlay(2));
        let raw = alias_raw(&two_objects, overlay(1));
        let raw = RawObjectInstance {
            path: format!("{}.second", raw.path),
            ..raw
        };
        two_objects.raw_to_id.insert(raw, other);
        // overlay(2)'s object is now filed under two keys as well.
        assert!(
            two_objects.sweep_match_keys().is_empty(),
            "a key naming two objects never matches"
        );

        // One object filed under a second key (not collapsed): neither key.
        let mut aliased = pin_set(&[(overlay(1), SHA, 1)], false);
        let id = id_of(&aliased, overlay(1));
        let raw = alias_raw(&aliased, overlay(5));
        aliased.raw_to_id.insert(raw, id);
        assert!(
            aliased.sweep_match_keys().is_empty(),
            "an object aliased under another key matches under neither"
        );

        // A rejected key whose raw alias was (wrongly) left behind.
        let mut rejected = pin_set(&[(overlay(1), SHA, 1)], false);
        rejected.rejected_keys.insert(overlay(1));
        assert!(
            rejected.sweep_match_keys().is_empty(),
            "a rejected key never matches"
        );
    }

    /// The held side of the C1b comparison is the kernel's `vm_file` of a
    /// self-mapping, never `fstat`: with the privilege it equals the
    /// `map_files` identity of any other mapping of the same file (on
    /// btrfs `fstat` agrees too; on pre-6.8 overlayfs it would not, which
    /// is why it is not used); without it, both sides fail closed.
    #[test]
    fn a_key_is_its_files_identity_only_on_an_allowlisted_filesystem() {
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: 42,
        };
        let on = |identity, fs_magic| MappedFile { identity, fs_magic }.key_is_identity(key);
        let same = FileIdentity {
            dev: libc::makedev(8, 1),
            ino: 42,
        };
        // ext2/3/4, XFS, squashfs, EROFS: exactly the allowlist.
        for magic in [0xef53, 0x5846_5342, 0x7371_7368, 0xe0f5_e1e2] {
            assert!(on(same, Some(magic)), "{magic:#x}");
        }
        assert_eq!(KEY_IS_IDENTITY_FILESYSTEMS.len(), 4);
        // tmpfs (wrapping 32-bit inode numbers without inode64), btrfs,
        // overlayfs, bcachefs, FUSE, NFS, an unknown and an unread magic
        // always prove per range.
        for magic in [
            Some(0x0102_1994),
            Some(0x9123_683e),
            Some(0x794c_7630),
            Some(0xca45_1a4e),
            Some(0x6573_5546),
            Some(0x6969),
            Some(0x1234_5678),
            None,
        ] {
            assert!(!on(same, magic), "{magic:?}");
        }
        // The identity must be the key: another device or inode proves.
        assert!(!on(FileIdentity { dev: 37, ino: 42 }, Some(0xef53)));
        assert!(!on(
            FileIdentity {
                dev: libc::makedev(8, 1),
                ino: 43
            },
            Some(0xef53)
        ));
    }

    #[test]
    fn the_pin_refuses_a_reopened_file_that_is_not_the_one_the_scan_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("libpinned.so");
        std::fs::copy("/bin/sh", &path).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let mapping = mapping_file_key(&file).unwrap();
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let read = FileIdentity { dev: 37, ino: 9 };
        let module = |mapped_identity| ScannedModule {
            mapped_identity,
            double_loaded: false,
            view: view.id(),
            mount_namespace: view.mount_namespace(),
            key: ObjectKey {
                device: Device {
                    major: mapping.device_major,
                    minor: mapping.device_minor,
                },
                inode: mapping.inode,
            },
            path: path.display().to_string(),
            decoder_abi: None,
            exports: Vec::new(),
            tables: Vec::new(),
            interfaces: Vec::new(),
        };
        let pin = |module: ScannedModule, pinned: Result<FileIdentity, String>| {
            let mut budget = CaptureWorkBudget::default();
            let (objects, skipped) = pin_scanned_view_objects_with(
                &view,
                std::slice::from_ref(&module),
                &mut budget,
                &|_| pinned.clone(),
            )
            .unwrap();
            (objects.pinned().count(), skipped)
        };

        // Same maps key, but the path now resolves to another subvolume's
        // file (btrfs): refused, never pinned as the scanned object.
        let (count, skipped) = pin(module(Some(read)), Ok(FileIdentity { dev: 47, ino: 9 }));
        assert_eq!(count, 0);
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert!(
            skipped[0].reason.contains("identity_mismatch"),
            "{skipped:?}"
        );
        // The file the scan read: pinned.
        let (count, skipped) = pin(module(Some(read)), Ok(read));
        assert_eq!((count, skipped.len()), (1, 0), "{skipped:?}");
        // An unreadable pin side keeps the key check as the proof.
        let (count, skipped) = pin(module(Some(read)), Err("EPERM".into()));
        assert_eq!((count, skipped.len()), (1, 0), "{skipped:?}");
        // No scanned identity (map_files unreadable at scan time): key only.
        let (count, skipped) = pin(module(None), Ok(FileIdentity { dev: 47, ino: 9 }));
        assert_eq!((count, skipped.len()), (1, 0), "{skipped:?}");
    }

    /// DR-C1b-3: a stat relative to the held `map_files` directory reads
    /// exactly what the full-path stat reads — the followed `vm_file`'s
    /// identity as root, the same `EPERM` unprivileged — and a range that
    /// is not one mapping is not found either way.
    #[test]
    fn a_held_map_files_directory_reads_what_the_path_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("libdirfd.so");
        std::fs::write(&path, vec![0x5au8; 8192]).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        // SAFETY: a private read-only page of a valid fd, unmapped below.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED);
        let _guard = SelfMapping { base, len: 4096 };
        let start = base as u64;
        let pid = std::process::id();
        let held = MapFilesDir::open(pid).expect("the own map_files directory opens");
        for (low, high) in [(start, start + 4096), (start, start + 8192)] {
            let by_path = map_files_identity(pid, low, high);
            let by_dir = held.identity(low, high);
            match (&by_path, &by_dir) {
                (Ok(path_identity), Ok(dir_identity)) => {
                    assert_eq!(path_identity, dir_identity);
                    assert_eq!(dir_identity.ino, file.metadata().unwrap().ino());
                }
                (Err(path_error), Err(dir_error)) => {
                    assert_eq!(path_error.raw_os_error(), dir_error.raw_os_error());
                    assert_ne!(dir_error.raw_os_error(), Some(libc::ENOSYS));
                }
                _ => panic!("the two reads disagree: {by_path:?} vs {by_dir:?}"),
            }
        }
    }

    /// The stack-rendered `map_files` entry name is exactly what
    /// `format!("{start:x}-{end:x}")` produces, NUL-terminated with no
    /// interior NUL: every hex width, realistic mapping bounds, the `u64`
    /// extremes, and a deterministic pseudo-random sweep.
    #[test]
    fn stack_map_files_names_match_format() {
        fn check(start: u64, end: u64) {
            let mut name = [0u8; MAP_FILES_NAME_LEN];
            let len = write_map_files_name(start, end, &mut name);
            let expected = format!("{start:x}-{end:x}");
            assert_eq!(&name[..len], expected.as_bytes(), "{start:x}-{end:x}");
            assert_eq!(name[len], 0, "missing NUL terminator");
            assert!(
                !name[..len].contains(&0),
                "interior NUL in {start:x}-{end:x}"
            );
            assert_eq!(
                std::ffi::CStr::from_bytes_with_nul(&name[..len + 1])
                    .unwrap()
                    .to_str()
                    .unwrap(),
                expected
            );
        }

        let mut edges = vec![
            0,
            1,
            9,
            10,
            15,
            16,
            17,
            255,
            256,
            4095,
            4096,
            0x400000,
            0x7f0000000000,
            0x7fffffffffff,
            u64::MAX - 1,
            u64::MAX,
        ];
        for width in 0..16u32 {
            let bound = 1u64 << (4 * width);
            edges.extend([bound.saturating_sub(1), bound]);
            if width < 15 {
                edges.push(bound + 1);
            }
        }
        for &start in &edges {
            for &end in &edges {
                check(start, end);
            }
        }
        let mut state = 0x1234_5678_9abc_def1u64;
        for _ in 0..20_000 {
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            check(next(), next());
        }
    }

    /// Heap allocations per 1,000 `map_files` entry names, `format!` +
    /// `CString` vs the stack writer (C7 A2 measurement; the counter is
    /// per thread, so this runs in the default suite; `--nocapture`
    /// prints the counts).
    #[test]
    fn map_files_name_allocation_count_per_thousand() {
        let (_, old_allocs, old_bytes) = crate::test_alloc::count_allocs_during(|| {
            for i in 0..1000u64 {
                let start = 0x7f00_0000_0000 + i * 0x1000;
                let name = std::ffi::CString::new(format!("{start:x}-{:x}", start + 0x1000))
                    .map_err(std::io::Error::other)
                    .unwrap();
                std::hint::black_box(name);
            }
        });
        let (_, stack_allocs, stack_bytes) = crate::test_alloc::count_allocs_during(|| {
            for i in 0..1000u64 {
                let start = 0x7f00_0000_0000 + i * 0x1000;
                let mut name = [0u8; MAP_FILES_NAME_LEN];
                let len = write_map_files_name(start, start + 0x1000, &mut name);
                std::hint::black_box((name, len));
            }
        });
        println!("format per 1000 names: {old_allocs} allocs, {old_bytes} bytes");
        println!("stack per 1000 names: {stack_allocs} allocs, {stack_bytes} bytes");
        assert!(
            old_allocs >= 1000,
            "format! + CString allocates per name: {old_allocs}"
        );
        assert_eq!(
            (stack_allocs, stack_bytes),
            (0, 0),
            "the stack writer must not allocate"
        );
    }

    /// Indicative wall time per `map_files` entry name, `format!` +
    /// `CString` vs the stack writer (a criterion-free loop, not a
    /// benchmark; run single-threaded:
    /// `test -- --ignored map_files_name_timing --test-threads=1 --nocapture`).
    #[test]
    #[ignore]
    fn map_files_name_timing_per_thousand() {
        use std::time::Instant;

        const ROUNDS: u64 = 100_000;
        let start = Instant::now();
        for i in 0..ROUNDS {
            let bound = 0x7f00_0000_0000 + i * 0x1000;
            let name = std::ffi::CString::new(format!("{bound:x}-{:x}", bound + 0x1000))
                .map_err(std::io::Error::other)
                .unwrap();
            std::hint::black_box(name);
        }
        let old = start.elapsed();
        let start = Instant::now();
        for i in 0..ROUNDS {
            let bound = 0x7f00_0000_0000 + i * 0x1000;
            let mut name = [0u8; MAP_FILES_NAME_LEN];
            let len = write_map_files_name(bound, bound + 0x1000, &mut name);
            std::hint::black_box((name, len));
        }
        let stack = start.elapsed();
        println!(
            "format per 1000 names: {:.1} ns/name",
            old.as_nanos() as f64 / ROUNDS as f64
        );
        println!(
            "stack per 1000 names: {:.1} ns/name",
            stack.as_nanos() as f64 / ROUNDS as f64
        );
    }

    #[test]
    fn the_held_side_is_the_self_mapped_vm_file_and_fails_closed_unprivileged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("libheld.so");
        std::fs::write(&path, vec![0x5au8; 8192]).unwrap();
        let held = std::fs::File::open(&path).unwrap();
        let empty_path = dir.path().join("empty.so");
        std::fs::write(&empty_path, b"").unwrap();
        assert!(self_mapped_identity(&std::fs::File::open(&empty_path).unwrap()).is_err());
        // An independent mapping of the same file, as a target would hold.
        let other = std::fs::File::open(&path).unwrap();
        // SAFETY: a private read-only page of a valid fd, unmapped below.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                other.as_raw_fd(),
                4096,
            )
        };
        assert_ne!(base, libc::MAP_FAILED);
        let _guard = SelfMapping { base, len: 4096 };
        let start = base as u64;
        let target = map_files_identity(std::process::id(), start, start + 4096);
        match self_mapped_identity(&held) {
            Ok(identity) => {
                assert_eq!(target.unwrap(), identity, "one file, one vm_file identity");
                let metadata = held.metadata().unwrap();
                assert_eq!(identity.ino, metadata.ino());
                // The same entry's statfs is the held file's filesystem.
                let mut buf = std::mem::MaybeUninit::<libc::statfs>::uninit();
                // SAFETY: a valid fd; `buf` is read only on success.
                assert_eq!(
                    unsafe { libc::fstatfs(held.as_raw_fd(), buf.as_mut_ptr()) },
                    0
                );
                // SAFETY: initialized by the successful `fstatfs`.
                let magic = (unsafe { buf.assume_init().f_type }) as u64 & 0xffff_ffff;
                assert_eq!(self_mapped_file(&held).unwrap().fs_magic, Some(magic));
            }
            Err(error) => {
                // Unprivileged: following map_files is EPERM on both sides.
                assert!(error.contains("Operation not permitted"), "{error}");
                assert_eq!(
                    target.unwrap_err().raw_os_error(),
                    Some(libc::EPERM),
                    "the target side fails closed the same way"
                );
            }
        }
    }

    #[test]
    fn object_checks_are_per_object_and_name_nonunique_inode_filesystems() {
        assert_eq!(nonunique_inode_kind(0x6573_5546), Some("fuse"));
        assert_eq!(nonunique_inode_kind(0x6969), Some("nfs"));
        assert_eq!(nonunique_inode_kind(0xef53), None, "ext4 inodes are unique");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.so");
        std::fs::write(&path, b"provider bytes").unwrap();
        let pinned = super::test_fixture::real_scan_pin(&path, None, 1, SHA);
        let id = pinned.pinned().next().unwrap().id;
        assert_eq!(pinned.object_unchanged(id), Ok(true));
        assert_eq!(pinned.nonunique_inode_filesystem(id), Ok(None));
        std::fs::write(&path, b"replaced provider bytes").unwrap();
        assert_eq!(pinned.object_unchanged(id), Ok(false));
        assert!(
            !pinned.provider_changed(),
            "the per-object check does not latch the whole set"
        );
        assert!(pinned.object_unchanged(PinnedObjectId(999)).is_err());
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
        // Task 1.3: the unlinked table's ordinal label is gated to `unknown`,
        // and an unnamed slot cannot resolve one descriptor.
        assert_eq!(plan.slots[0].names, ["unknown"]);
        assert!(plan.slots[0].semantic_ambiguous);
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

    /// B2: the pin-sweep gate's watermark. Membership mutations advance
    /// the revision; no-op removals do not; a sweep over an unchanged
    /// revision is a provable skip (counter, not timing).
    #[test]
    fn pin_revision_advances_on_membership_change_only() {
        let mut pins = PinnedObjects::empty();
        assert_eq!(pins.revision(), 0);
        // A merge ran: conservative bump even for an empty donor.
        let _ = pins.absorb(PinnedObjects::empty());
        assert_eq!(pins.revision(), 1);
        // A replace bumps twice (the replace plus the incoming merge).
        let _ = pins.replace_view_pins(ProcessViewId(3), PinnedObjects::empty(), &[]);
        assert_eq!(pins.revision(), 3);
        // Removing a view that was never there changes nothing.
        assert!(pins.remove_view(ProcessViewId(9)).is_none());
        assert_eq!(pins.revision(), 3);
        // The gate counts the skip; the next sweep needs a new revision.
        let mut gate = crate::timing::PinSweepGate::new();
        assert!(gate.should_sweep(pins.revision(), false));
        assert!(!gate.should_sweep(pins.revision(), false));
        assert_eq!((gate.sweeps(), gate.skips()), (1, 1));
        let _ = pins.absorb(PinnedObjects::empty());
        assert!(gate.should_sweep(pins.revision(), false));
        assert_eq!((gate.sweeps(), gate.skips()), (2, 1));
    }
}
